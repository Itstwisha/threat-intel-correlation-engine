# Threat Intelligence Correlation Engine

A Python-based **Threat Intelligence Enrichment & Correlation Engine** that simulates real-world SOC workflows by ingesting security alerts, enriching Indicators of Compromise (IOCs), correlating MITRE ATT&CK techniques, integrating dark web intelligence, and producing risk-based alert prioritization with a visual SOC dashboard.

---

## Project Overview

Security teams often receive thousands of alerts daily. This project demonstrates how raw alerts can be transformed into **actionable intelligence** using enrichment, correlation, and risk scoring the same concepts used in modern SOC and Threat Intelligence teams.

---

## Key Features

-  **IOC Extraction** – Parses alerts to extract IPs, domains, and file hashes  
-  **Threat Intelligence Enrichment** – Matches IOCs against simulated threat feeds  
-  **MITRE ATT&CK Correlation** – Maps activity to tactics and techniques  
-  **Dark Web Intelligence Fusion** – Escalates alerts when underground chatter is detected  
-  **Risk Scoring & Prioritization** – Assigns SOC-style severity and priority  
-  **SOC Dashboard (Streamlit)** – Visualizes alerts, MITRE data, and dark web context  

---

## Architecture

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
Risk Scoring & Priority
↓
SOC Dashboard

yaml
Copy code

---

## Project Structure

threat-intel-correlation-engine/
│
├── main.py
├── data/
│ ├── sample_alerts.json
│ └── threat_feeds.json
│
├── enrichment/
│ ├── ioc_extractor.py
│ └── intel_enricher.py
│
├── correlation/
│ ├── mitre_correlator.py
│ └── risk_scorer.py
│
├── darkweb/
│ ├── darkweb_feed.json
│ └── darkweb_ingestor.py
│
├── dashboard/
│ └── soc_dashboard.py
│
└── output/

yaml
Copy code

---

## How to Run

### Install dependencies
```bash
pip install streamlit pandas
Run the engine
bash
Copy code
python3 main.py
This generates:

bash
Copy code
output/enriched_results.json
Launch SOC Dashboard
bash
Copy code
streamlit run dashboard/soc_dashboard.py
Dashboard opens at:

arduino
Copy code
http://localhost:8501
Sample Output
Risk Score: 0–100

Priority: LOW / MEDIUM / HIGH / CRITICAL

MITRE Techniques: T1078, T1566, T1204

Dark Web Context: Credential sales, phishing kits, attacker intent

Skills Demonstrated
Threat Intelligence Analysis

SOC Alert Triage & Prioritization

MITRE ATT&CK Framework

Dark Web Monitoring Concepts

Python Automation

Security Analytics & Visualization

 Future Enhancements
Live threat intelligence APIs

Time-based alert correlation

SIEM integration

Dockerized deployment

Executive/GRC risk summaries

Author
Twisha Sharma
Cybersecurity | Threat Intelligence | SOC Analytics


---
