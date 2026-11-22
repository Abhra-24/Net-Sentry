# NetSentry

NetSentry is a small dashboard for checking a device on your local network. Enter its private IPv4 or IPv6 address for a quick scan of common TCP ports or select the full scan to check ports 1–65,535. The report includes an exposure score, ML-assisted triage, and suggested next steps.

## Start the dashboard

1. Install Python 3.10 or newer.
2. From this folder, start NetSentry:

   ```powershell
   python backend/app.py
   ```

3. Open [http://127.0.0.1:8080](http://127.0.0.1:8080) and enter the device's IP address.

Nmap is optional. When installed, the quick scan uses Nmap to check common TCP service ports and popular high ports. Select **Scan all 65,535 TCP ports** for a wider sweep using the built-in scanner; this can take about a minute. Version probes are skipped to keep scans quick. The dashboard and local report do not require an API key.

## Optional AI explanation

The local report always works. To enable the optional Groq AI explanation, put an API key in the project-root `.env` file:

```text
GROQ_API_KEY=your-key
```

Then restart NetSentry and select **Add AI explanation** before scanning. When selected, the target IP and observed service details are sent to Groq. The API key stays on the backend and is never sent to the browser.

## What the report means
   
- Scans are limited to private and local-network IP addresses.
- The built-in fallback checks TCP ports only. UDP, application behavior, login security, and confirmed CVEs are outside its scope.
- Open ports and the exposure score are review signals, not proof that a vulnerability exists.
- ML triage is a lightweight standard-library logistic-regression baseline trained from a small embedded example set. It helps prioritize review and is not a calibrated chance of compromise.
- Results are kept in memory for up to one hour. Download or print a report before closing the app if you need to keep it.

Only scan devices you own or have permission to assess.
