# Threat Intelligence Correlation Engine

A Python-based **Threat Intelligence Enrichment & Correlation Engine** that simulates real-world **Security Operations Center (SOC)** workflows.  
The system ingests security alerts, enriches Indicators of Compromise (IOCs), correlates MITRE ATT&CK techniques, integrates dark web intelligence, and produces risk-based alert prioritization with a visual SOC dashboard.

---

## Why This Project Matters

SOC teams are overwhelmed with alerts.  
This project demonstrates how **raw security events can be transformed into actionable intelligence** using enrichment, correlation, and risk scoring — the same concepts used by modern SOC and Threat Intelligence teams.

---

## Key Capabilities

- **IOC Extraction**  
  Extracts IPs, domains, and file hashes from security alerts.

- **Threat Intelligence Enrichment**  
  Matches IOCs against simulated threat feeds to determine malicious context.

- **MITRE ATT&CK Correlation**  
  Maps observed activity to ATT&CK tactics and techniques to identify attack patterns.

- **Dark Web Intelligence Fusion**  
  Correlates underground forum intelligence to escalate alert severity and confirm attacker intent.

- **Risk Scoring & Prioritization**  
  Assigns SOC-style risk scores (0–100) and priorities (LOW → CRITICAL).

- **SOC Dashboard (Streamlit)**  
  Visual dashboard for alert triage, MITRE visibility, and dark web context.

---

## High-Level Architecture

```

Security Alert (JSON)
↓
IOC Extraction
↓
Threat Intelligence Enrichment
↓
MITRE ATT&CK Correlation
↓
Dark Web Intelligence Fusion
↓
Risk Scoring & Prioritization
↓
SOC Dashboard

```

---

## Project Structure

```

threat-intel-correlation-engine/
│
├── main.py
│
├── data/
│   ├── sample_alerts.json
│   └── threat_feeds.json
│
├── enrichment/
│   ├── ioc_extractor.py
│   └── intel_enricher.py
│
├── correlation/
│   ├── mitre_correlator.py
│   └── risk_scorer.py
│
├── darkweb/
│   ├── darkweb_feed.json
│   └── darkweb_ingestor.py
│
├── dashboard/
│   └── soc_dashboard.py
│
├── output/
│   └── enriched_results.json
│
└── README.md

````

---

## How to Run

### Install Dependencies
```bash
pip install streamlit pandas
````

### Run the Correlation Engine

```bash
python3 main.py
```

This generates:

```
output/enriched_results.json
```

### Launch the SOC Dashboard

```bash
streamlit run dashboard/soc_dashboard.py
```

Access at:

```
http://localhost:8501
```

---

## What the Output Shows

* **Risk Score:** 0–100
* **Priority:** LOW / MEDIUM / HIGH / CRITICAL
* **MITRE Techniques:** e.g., T1078, T1566, T1204
* **Dark Web Context:** Phishing kits, credential sales, attacker intent

---

## Technologies & Concepts Used

* Python
* Threat Intelligence Enrichment
* SOC Alert Triage
* MITRE ATT&CK Framework
* Dark Web Monitoring Concepts
* Risk-Based Prioritization
* Streamlit Dashboarding

---

## Future Enhancements

* Live threat intelligence API integrations
* Time-based alert correlation
* SIEM ingestion (Splunk / Elastic format)
* Dockerized deployment
* Executive & GRC-style risk summaries

---

## Author

**Twisha Sharma**
Cybersecurity | Threat Intelligence | SOC Analytics

```

---
