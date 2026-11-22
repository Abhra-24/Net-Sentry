const form = document.querySelector('#scan-form');
const targetInput = document.querySelector('#target');
const fullScanInput = document.querySelector('#full-scan');
const useAiInput = document.querySelector('#use-ai');
const aiOptinNote = document.querySelector('#ai-optin-note');
const scanButton = document.querySelector('#scan-button');
const errorBox = document.querySelector('#form-error');
const progress = document.querySelector('#progress');
const progressTitle = document.querySelector('#progress-title');
const progressDetail = document.querySelector('#progress-detail');
const results = document.querySelector('#results');
let activeJob = null;

document.querySelector('#print-report').addEventListener('click', () => window.print());
form.addEventListener('submit', startScan);
fullScanInput.addEventListener('change', () => setScanButtonLabel(false));
loadHealth();

async function loadHealth() {
  const dot = document.querySelector('#health-dot');
  const label = document.querySelector('#health-label');
  try {
    const response = await fetch('/api/health');
    if (!response.ok) throw new Error('Scanner is unavailable');
    const health = await response.json();
    dot.classList.add('ready');
    label.textContent = `Scanner ready · ${health.scanner}`;
    if (health.ai_configured) {
      useAiInput.dataset.configured = 'true';
      useAiInput.disabled = false;
      aiOptinNote.textContent = 'Optional. Sends the target IP and observed service details to Groq.';
    } else {
      useAiInput.dataset.configured = '';
      useAiInput.disabled = true;
      aiOptinNote.textContent = 'Optional AI is not configured. The local scan and report work without it.';
    }
  } catch {
    dot.classList.add('error');
    label.textContent = 'Scanner unavailable';
    useAiInput.dataset.configured = '';
    useAiInput.disabled = true;
    aiOptinNote.textContent = 'Start the NetSentry server to enable scanning.';
  }
}

async function startScan(event) {
  event.preventDefault();
  if (activeJob) return;
  activeJob = 'starting';
  errorBox.textContent = '';
  results.hidden = true;
  setBusy(true);
  const fullScan = fullScanInput.checked;
  showProgress(fullScan ? 'Starting full scan…' : 'Starting quick scan…', fullScan ? 'Checking TCP ports 1–65,535.' : 'Checking common TCP ports and popular high ports.');
  try {
    const response = await fetch('/api/scans', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target: targetInput.value.trim(), use_ai: useAiInput.checked, full_scan: fullScan}),
    });
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || 'Could not start the scan.');
    activeJob = job.id;
    showProgress('Scanning device…', fullScan ? 'Checking all TCP ports 1–65,535. This can take about a minute.' : 'Quickly checking common TCP ports.');
    await poll(job.id);
  } catch (error) {
    errorBox.textContent = error.message || 'The scan could not be completed.';
    progress.hidden = true;
  } finally {
    activeJob = null;
    setBusy(false);
  }
}

function setBusy(busy) {
  scanButton.disabled = busy;
  setScanButtonLabel(busy);
  targetInput.disabled = busy;
  fullScanInput.disabled = busy;
  useAiInput.disabled = busy || !useAiInput.dataset.configured;
}

function setScanButtonLabel(busy) {
  scanButton.querySelector('span:first-child').textContent = busy ? 'Scanning…' : fullScanInput.checked ? 'Run full scan' : 'Run quick scan';
}

function showProgress(title, detail) {
  progressTitle.textContent = title;
  progressDetail.textContent = detail;
  progress.hidden = false;
}

async function poll(id) {
  const deadline = Date.now() + 330_000;
  while (Date.now() < deadline) {
    await pause(1000);
    const response = await fetch(`/api/scans/${encodeURIComponent(id)}`);
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || 'Could not read the scan report.');
    if (job.status === 'complete') {
      progress.hidden = true;
      render(job);
      return;
    }
    if (job.status === 'error') throw new Error(job.error || 'The scan could not be completed.');
    if (job.status === 'queued') showProgress('Starting scan…', 'Waiting for the local scanner.');
  }
  throw new Error('This scan took longer than expected. Check the target and try again.');
}

function pause(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function render(job) {
  const report = job.report;
  const riskCard = document.querySelector('.risk-card');
  riskCard.dataset.risk = report.level;
  document.querySelector('#risk-level').textContent = capitalize(report.level);
  document.querySelector('#risk-score').textContent = `Exposure index ${report.score} / 99`;
  document.querySelector('#open-count').textContent = job.ports.length;

  const ml = report.ml;
  document.querySelector('#ml-signal').textContent = `${capitalize(ml.signal)} signal`;
  document.querySelector('#ml-score').textContent = `Model score: ${ml.score}/100 · not a probability`;
  renderMl(ml);
  document.querySelector('#report-meta').textContent = `${job.target} · ${report.scan_scope} · ${job.engine} · ${formatTime(job.finished_at)}`;

  renderAnalysis(report.analysis);
  renderFindings(report.findings);
  renderPorts(job.ports, report.findings);
  window.currentReport = {target: job.target, scanned_at: job.finished_at, scan_scope: report.scan_scope, engine: job.engine, risk_score: report.score, risk_level: report.level, ml_triage: ml, findings: report.findings, analysis: report.analysis, open_ports: job.ports};
  results.hidden = false;
}

function renderMl(model) {
  document.querySelector('#ml-result-badge').textContent = `${capitalize(model.signal)} signal · ${model.score}/100`;
  document.querySelector('#ml-summary').textContent = `${model.name}: ${model.summary}`;
  document.querySelector('#ml-training-note').textContent = model.training_note;
  document.querySelector('#ml-caveat').textContent = model.caveat;
  const score = Math.max(0, Math.min(100, Number(model.score) || 0));
  document.querySelector('#ml-flow-score').textContent = `${score}/100`;
  document.querySelector('#ml-flow-signal').textContent = `${capitalize(model.signal)} review signal · not a probability`;
  document.querySelector('#ml-meter-value').textContent = `${score} / 100`;
  document.querySelector('#ml-score-fill').style.width = `${score}%`;
  const meter = document.querySelector('#ml-score-track');
  meter.setAttribute('aria-valuenow', String(score));
  meter.setAttribute('aria-valuetext', `${score} out of 100; a review score, not a probability`);
  const grid = document.querySelector('#ml-feature-grid');
  grid.replaceChildren();
  for (const item of model.feature_effects || []) {
    const card = make('article', 'ml-feature');
    const heading = make('div', 'ml-feature-heading');
    heading.append(make('strong', '', item.label));
    heading.append(make('b', 'ml-feature-value', String(item.value)));
    card.append(heading);
    card.append(make('p', 'ml-feature-description', item.description));
    card.append(make('p', 'ml-reference', `This scan: ${item.value} · Example average: ${item.reference_value}`));
    const scale = Math.max(Number(item.value) || 0, Number(item.reference_value) || 0, 1);
    card.append(makeComparisonRow('This scan', item.value, scale));
    card.append(makeComparisonRow('Example average', item.reference_value, scale));
    const influence = item.influence === 'raises'
      ? 'Compared with its example average, this value pushes the score higher.'
      : item.influence === 'lowers'
        ? 'Compared with its example average, this value pushes the score lower.'
        : 'This value is close to its example average, so it has little effect.';
    card.append(make('span', 'ml-influence', influence));
    grid.append(card);
  }
}

function makeComparisonRow(label, value, scale) {
  const row = make('div', 'ml-compare-row');
  row.append(make('span', 'ml-compare-label', label));
  const track = make('span', 'ml-compare-track');
  track.setAttribute('aria-hidden', 'true');
  const fill = make('span', 'ml-compare-fill');
  fill.style.width = `${Math.max(0, Math.min(100, (Number(value) || 0) / scale * 100))}%`;
  track.append(fill);
  row.append(track);
  row.append(make('b', 'ml-compare-value', String(value)));
  return row;
}

function renderAnalysis(analysis) {
  const cloudAi = analysis.provider === 'Groq' && analysis.status === 'complete';
  document.querySelector('#analysis-title').textContent = cloudAi ? 'AI analyst report' : 'Local analyst report';
  document.querySelector('#analysis-status').textContent = cloudAi ? 'AI ANALYSIS' : 'LOCAL REPORT';
  document.querySelector('#analysis-summary').textContent = analysis.summary || analysis.message || 'No analysis summary was returned.';
  replaceList('#analysis-reasoning', analysis.reasoning, 'No additional reasoning returned.');
  replaceList('#analysis-actions', analysis.priority_actions, 'No follow-up actions returned.');
  const caveats = Array.isArray(analysis.caveats) ? [...analysis.caveats] : [];
  if (analysis.ai_message) caveats.push(analysis.ai_message);
  document.querySelector('#analysis-caveats').textContent = caveats.join(' ');
}

function renderFindings(findings) {
  const list = document.querySelector('#findings-list');
  list.replaceChildren();
  for (const item of findings) {
    const row = make('div', 'finding');
    row.append(make('span', `severity ${item.severity}`, item.severity));
    const body = make('div');
    body.append(make('div', 'finding-title', item.title));
    body.append(make('div', 'finding-detail', item.detail));
    row.append(body);
    list.append(row);
  }
}

function renderPorts(ports, findings) {
  document.querySelector('#table-meta').textContent = `${ports.length} service${ports.length === 1 ? '' : 's'}`;
  const table = document.querySelector('#ports-table');
  table.replaceChildren();
  if (!ports.length) {
    const row = make('tr');
    const cell = make('td', 'empty-cell', 'No open TCP ports were detected.');
    cell.colSpan = 3;
    row.append(cell);
    table.append(row);
    return;
  }
  for (const item of ports) {
    const finding = findings.find(entry => entry.port === item.port);
    const priority = finding?.severity || 'low';
    const row = make('tr');
    row.append(make('td', 'port', `${item.port}/tcp`));
    row.append(make('td', '', item.service));
    row.append(make('td', `priority ${priority}`, priority === 'low' ? 'Routine review' : `${capitalize(priority)} priority`));
    table.append(row);
  }
}

function replaceList(selector, items, emptyText) {
  const list = document.querySelector(selector);
  list.replaceChildren();
  const entries = Array.isArray(items) && items.length ? items : [emptyText];
  for (const item of entries) list.append(make('li', '', String(item)));
}

function make(tag, className = '', text = '') {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text) element.textContent = text;
  return element;
}

function capitalize(value) { return String(value || '').replace(/^./, character => character.toUpperCase()); }
function formatTime(value) {
  if (!value) return 'Time unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
}

