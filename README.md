# 🛡️ Virtual SOC Lab

> A production-style Virtual Security Operations Center (SOC) Lab combining security monitoring, SIEM analysis, network reconnaissance, packet analysis, threat intelligence, automated detection, and MITRE ATT&CK mapping.

![Virtual SOC Lab](https://img.shields.io/badge/Project-Virtual%20SOC%20Lab-00d4ff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Flask](https://img.shields.io/badge/Flask-REST%20API-000000?style=for-the-badge&logo=flask&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-SIEM-000000?style=for-the-badge&logo=splunk&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-EF3B2D?style=for-the-badge)

---

## 📌 Overview

**Virtual SOC Lab** is an end-to-end cybersecurity project designed to simulate the workflow of a Security Operations Center.

The project demonstrates how security telemetry can be collected, analyzed, detected, investigated, mapped to MITRE ATT&CK techniques, and presented through a modern SOC dashboard.

The lab combines:

- 🔐 Authentication monitoring
- 🌐 Network traffic analysis
- 🔎 Nmap reconnaissance
- 📡 Wireshark packet analysis
- 📊 Splunk SIEM investigation
- 🤖 Python-based detection scripts
- 🧠 Threat intelligence lookup
- 🎯 MITRE ATT&CK mapping
- ⚡ Flask REST API
- 🖥️ React SOC dashboard

---

# 🏗️ Architecture

```text
                    ┌──────────────────┐
                    │      Kali Linux  │
                    │  Security Testing │
                    └────────┬─────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
          ┌─────────────┐         ┌─────────────┐
          │    Nmap     │         │  Wireshark  │
          │ Recon Scan  │         │ Packet Cap. │
          └──────┬──────┘         └──────┬──────┘
                 │                       │
                 └───────────┬───────────┘
                             ▼
                    ┌──────────────────┐
                    │ Security Evidence│
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Python Detection  │
                    │     Scripts       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Synthetic Logs   │
                    │ Auth / Web / Net │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  Splunk SIEM     │
                    │ SPL Investigation│
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Flask REST API   │
                    │ Threat Intel     │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ React SOC        │
                    │ Dashboard        │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   SOC Interface  │
                    │ Alerts / Intel   │
                    └──────────────────┘
```

---

# 🚀 Key Features

## 🔐 Authentication Monitoring

The lab generates and analyzes authentication events to identify suspicious login behavior.

Example detection:

```text
Multiple failed login attempts
Source IP: 192.168.56.10
Failed Attempts: 5
Severity: HIGH
Alert Type: BRUTE_FORCE
```

Detection logic is implemented using Python and Splunk SPL.

---

## 🌐 Web Security Monitoring

HTTP security events are analyzed to identify suspicious web access.

Example:

```text
Source IP: 192.168.56.30
Path: /admin
Status: 403
Severity: MEDIUM
Alert Type: HTTP_403
```

---

## 🔎 Network Reconnaissance

Nmap is used to perform service discovery and identify exposed services.

Example scan:

```text
Target: 10.0.3.2

135/tcp   msrpc
445/tcp   microsoft-ds
8090/tcp  tcpwrapped
```

The scan results are stored as investigation evidence inside the project.

---

## 📡 Packet Analysis

Wireshark is used to capture and inspect network traffic.

The lab includes an ICMP packet capture generated during controlled connectivity testing.

Example:

```text
Protocol: ICMP
Interface: eth1
Packets Captured: 25
Packets Displayed: 20
Packets Dropped: 0
```

---

# 📊 SIEM Investigation

Splunk is used as the SIEM layer for centralized log analysis.

The following log sources are ingested:

```text
auth.log
web.log
network.log
alerts.log
```

Configured logical sources:

```text
soc_auth
soc_web
soc_network
soc_alerts
```

---

# 🔍 Detection Queries

## Brute Force Detection

```spl
index=* sourcetype=soc_auth event=LOGIN_FAILURE
| stats count as failed_attempts by src_ip
| where failed_attempts >= 5
| eval severity="HIGH"
| eval alert_type="BRUTE_FORCE"
| table src_ip failed_attempts severity alert_type
```

Expected result:

```text
src_ip          failed_attempts    severity    alert_type
192.168.56.10   5                  HIGH        BRUTE_FORCE
```

---

## HTTP 403 Detection

```spl
index=* sourcetype=soc_web status=403
| stats count as events by src_ip path
| eval severity="MEDIUM"
| eval alert_type="HTTP_403"
| table src_ip path events severity alert_type
```

Expected result:

```text
src_ip          path      events    severity    alert_type
192.168.56.30   /admin    1         MEDIUM      HTTP_403
```

---

## Network Event Analysis

```spl
index=* sourcetype=soc_network
| stats count by event
| sort - count
```

This query provides a summary of network telemetry such as:

```text
TCP_CONNECTION
DNS_QUERY
```

---

## Alert Summary

```spl
index=* sourcetype=soc_alerts
| stats count by alert_type severity src_ip
| sort - count
```

---

# 🧠 MITRE ATT&CK

Detected activities are mapped to relevant MITRE ATT&CK techniques to provide an adversary-behavior perspective.

The project includes an ATT&CK mapping document:

```text
mitre/attack_mapping.md
```

The mapping connects observed security behavior with corresponding attack techniques and investigation context.

---

# 🖥️ SOC Dashboard

The project includes a modern React-based SOC dashboard.

### Dashboard sections

- Overview
- Security Alerts
- Authentication
- Network Activity
- Reconnaissance
- Packet Analysis
- MITRE ATT&CK
- Investigation Report

The dashboard provides:

- Threat statistics
- Alert severity visualization
- Authentication activity
- Network telemetry
- Reconnaissance results
- Packet analysis evidence
- MITRE ATT&CK mapping
- Investigation workflow
- Threat intelligence lookup

---

# 🧠 Threat Intelligence

The dashboard supports threat intelligence lookup through the backend API.

Supported target types include:

```text
IP Address
Domain
URL
```

The backend communicates with the VirusTotal API for threat intelligence analysis.

Example:

```text
Target: 8.8.8.8

Type: IP
Risk: LOW
Malicious: 0
Suspicious: 0
Harmless: 52
Undetected: 37
```

> Threat intelligence results depend on the external intelligence provider and should be interpreted as investigation evidence rather than standalone proof of compromise.

---

# ⚙️ Technology Stack

| Layer               | Technology        |
| ------------------- | ----------------- |
| Security Testing    | Kali Linux        |
| Reconnaissance      | Nmap              |
| Packet Analysis     | Wireshark         |
| SIEM                | Splunk Enterprise |
| Detection           | Python            |
| Backend             | Flask             |
| Frontend            | React + Vite      |
| Charts              | Recharts          |
| Icons               | Lucide React      |
| Threat Intelligence | VirusTotal API    |
| Attack Framework    | MITRE ATT&CK      |
| Version Control     | Git + GitHub      |

---

# 📁 Project Structure

```text
Virtual-SOC-Lab/
│
├── backend/
│   ├── app.py
│   ├── .env
│   └── venv/
│
├── data/
│   ├── auth_logs/
│   │   └── auth.log
│   ├── web_logs/
│   │   └── web.log
│   ├── network_logs/
│   │   └── network.log
│   └── alerts.log
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── mitre/
│   └── attack_mapping.md
│
├── nmap/
│   └── nmap_scan.txt
│
├── reports/
│   └── investigation_report.md
│
├── screenshots/
│
├── scripts/
│   ├── generate_logs.py
│   ├── detect_events.py
│   └── generate_alerts.py
│
├── splunk/
│   ├── README.md
│   └── queries.md
│
├── wireshark/
│   └── virtual_soc_icmp_capture.pcapng
│
├── .gitignore
└── README.md
```

---

# 🧪 Investigation Workflow

The project follows a simplified SOC investigation lifecycle:

```text
1. Generate / Collect Security Telemetry
                ↓
2. Normalize Security Logs
                ↓
3. Detect Suspicious Events
                ↓
4. Ingest Logs into Splunk
                ↓
5. Investigate using SPL
                ↓
6. Generate Security Alerts
                ↓
7. Perform Reconnaissance Analysis
                ↓
8. Analyze Network Packets
                ↓
9. Map Activity to MITRE ATT&CK
                ↓
10. Enrich Indicators using Threat Intelligence
                ↓
11. Present Findings in SOC Dashboard
                ↓
12. Document Investigation
```

---

# 🔬 Evidence Collected

The lab contains practical cybersecurity evidence including:

### Nmap

```text
nmap/nmap_scan.txt
```

Service discovery results from controlled network reconnaissance.

### Wireshark

```text
wireshark/virtual_soc_icmp_capture.pcapng
```

Packet capture generated during controlled ICMP traffic testing.

### Splunk

Splunk queries and dashboard configuration are documented inside:

```text
splunk/
```

### Investigation Report

```text
reports/investigation_report.md
```

Contains the investigation workflow, observations, and security findings.

---

# 🔧 Local Setup

## 1. Clone the repository

```bash
git clone https://github.com/AnmolCEO123/Virtual-SOC-Lab.git
cd Virtual-SOC-Lab
```

---

# 🐍 Backend Setup

Move into the backend directory:

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install flask flask-cors requests python-dotenv
```

Create a `.env` file:

```env
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY
```

Start the backend:

```bash
python app.py
```

The API will run locally on:

```text
http://127.0.0.1:5000
```

Health check:

```text
/api/health
```

Threat intelligence endpoint:

```text
/api/analyze?target=8.8.8.8
```

---

# ⚛️ Frontend Setup

Open another terminal.

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

The frontend will normally be available at:

```text
http://localhost:5173
```

---

# 📊 Splunk Setup

Install Splunk Enterprise separately.

Import the following security logs:

```text
data/auth_logs/auth.log
data/web_logs/web.log
data/network_logs/network.log
data/alerts.log
```

Use the documented sourcetypes:

```text
soc_auth
soc_web
soc_network
soc_alerts
```

The Splunk dashboard can then be used to visualize:

- Security alerts
- Failed login attempts
- Network events
- DNS queries
- HTTP 403 events

---

# 🔐 Security Considerations

This project is designed for **controlled lab and educational use**.

All reconnaissance and traffic-generation activities should be performed only against systems and networks that you own or have explicit authorization to test.

The project does not provide unauthorized access to third-party systems.

API credentials and secrets should never be committed to GitHub.

The backend `.env` file is intentionally excluded from version control.

---

# 🎯 Learning Objectives

This project demonstrates practical understanding of:

- SOC operations
- SIEM concepts
- Log analysis
- Security event detection
- Incident investigation
- Network reconnaissance
- Packet analysis
- Threat intelligence
- MITRE ATT&CK
- Python automation
- REST APIs
- React dashboards
- Security monitoring workflows

---

# 📈 Future Improvements

Planned enhancements include:

- Real-time log streaming
- Automated alert correlation
- More detection rules
- Authentication anomaly detection
- IOC enrichment
- Additional MITRE ATT&CK mappings
- Automated incident scoring
- Email / notification integration
- Persistent investigation cases
- Production deployment
- Role-based SOC analyst access

---

# 👨‍💻 Author

**Anmol Kumar**

B.Tech Computer Science Engineering  
Kashi Institute of Technology, Varanasi

### Areas of Interest

- Cybersecurity
- Security Operations Center
- SIEM
- Threat Detection
- Network Security
- Web Development
- Security Automation

---

# ⭐ Project

If you find this project useful for learning SOC operations, cybersecurity monitoring, or SIEM workflows, consider giving the repository a star.

---

## ⚠️ Disclaimer

This project is intended for educational, research, and authorized security-testing purposes only.

The author is not responsible for misuse of the techniques, tools, or information contained in this repository.
