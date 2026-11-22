# NetSentry Project Theory

## 1. Introduction and Problem Statement

Devices on a local network often expose services through open TCP ports. Users may not know which services are reachable or which ones deserve attention. NetSentry provides a local dashboard that checks an authorized private-network device, summarizes the observed services, assigns a transparent exposure index, and gives practical follow-up actions.

## 2. Existing Research and Literature Review

Network reconnaissance tools commonly identify reachable ports and services. Rule-based risk scoring is useful for explaining why a finding is prioritized, while machine-learning triage can help sort larger result sets. Existing scanners may be powerful but can be difficult for beginners to interpret. NetSentry combines a bounded TCP scan with a plain-language report so the output can be understood by a non-specialist.

## 3. Research Gap

Many scanning tools report technical port output without explaining the meaning or limits of that output. Other systems may present a risk score without showing how it was produced. NetSentry addresses this gap by showing the observed evidence, the local scoring rules, the four model inputs, and a glossary. It also states that an open port is a review signal rather than proof of a vulnerability.

## 4. Research Objectives

- Build a local web dashboard for authorized private-network checks.
- Detect reachable TCP services using a quick common-port scan or a full TCP-port scan.
- Convert results into an explainable exposure index and prioritized findings.
- Add a lightweight local model that supports review prioritization.
- Present technical terms and limitations in plain language.
- Produce a printable PDF report for each completed scan.

## 5. Proposed Methodology / Research Plan

The user enters a private IPv4 or IPv6 address. The backend validates the address, starts a background scan, and returns a scan identifier. Nmap is used for a quick scan when available. Otherwise, or for a full scan, the backend uses concurrent Python TCP connection attempts. Open ports are mapped to recognized services and local exposure weights.

The model receives four features: total open TCP ports, higher-signal ports, legacy or administration ports, and recognized SSH or HTTPS entry points. It standardizes those values and applies a small logistic-regression model. The dashboard shows the resulting review score together with the feature values and their direction of influence.

## 6. Dataset and Synthetic Data

The repository includes `data/synthetic_scan_profiles.csv`. This is fabricated demonstration data created for the project’s model workflow; it is not collected from real devices and must not be presented as real-world measurements. Each row represents a synthetic scan profile with the same four feature types used by the model and a simple higher-exposure label. The backend loads this CSV at startup and falls back to a small embedded baseline if the file is unavailable.

The dataset is intentionally small and transparent. It demonstrates dataset loading, feature preparation, model training, and prediction without claiming statistical validity. A future research version should replace it with a consented, documented, anonymized dataset and evaluate the model with a separate test set.

## 7. Preliminary Results

The current prototype can complete quick scans of common TCP ports and full scans of ports 1–65,535. It produces an exposure level, open-service inventory, prioritized findings, model review score, plain-language explanation, and printable PDF report. These are preliminary engineering results. They do not establish that the model detects vulnerabilities or predicts compromise.

## 8. Roles and Responsibilities of Individual Team Members

Use the following roles as a template and replace the names with the actual team members:

- **Backend and scanning:** implement target validation, Nmap integration, the built-in TCP scanner, job handling, and report generation.
- **Dataset and ML:** document the synthetic dataset, prepare features, maintain the local logistic-regression baseline, and describe its limitations.
- **Frontend and UX:** build the dashboard, plain-language labels, result cards, glossary, and PDF-print layout.
- **Research and documentation:** prepare the literature review, research gap, objectives, methodology, preliminary results, and final user documentation.
