# 🛡️ Virtual SOC Lab

A full-stack Security Operations Center (SOC) simulation and defensive security investigation platform that combines security telemetry, automated detection, SIEM analysis, threat intelligence, reconnaissance, packet analysis, and a modern SOC dashboard.

The project demonstrates an end-to-end defensive security workflow from raw security evidence to detection, investigation, correlation, and visualization.

---

## 🚀 Project Overview

Virtual SOC Lab is designed to simulate the workflow of a real-world Security Operations Center.

The platform collects and analyzes security evidence from an authorized laboratory environment and presents the results through a centralized web dashboard.

The project combines:

- Authentication security monitoring
- Network security telemetry
- Web security events
- Automated Python detection
- Splunk SIEM analysis
- Nmap reconnaissance
- Wireshark packet analysis
- MITRE ATT&CK mapping
- VirusTotal threat intelligence
- Flask REST API
- React-based SOC dashboard

---

## 🎯 Objectives

The main objectives of this project are:

1. Simulate a real SOC monitoring environment.
2. Generate and analyze security telemetry.
3. Detect suspicious authentication and web activity.
4. Perform authorized network reconnaissance.
5. Capture and analyze network packets.
6. Correlate security events using Splunk.
7. Map detected activity to MITRE ATT&CK techniques.
8. Integrate external threat intelligence.
9. Provide a centralized analyst-friendly dashboard.
10. Demonstrate an end-to-end defensive security investigation workflow.

---

## 🏗️ System Architecture

```text
                    ┌──────────────────┐
                    │   Kali Linux     │
                    │ Authorized Lab   │
                    └────────┬─────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
          ┌─────▼─────┐             ┌────▼──────┐
          │    Nmap   │             │ Wireshark │
          │ Recon      │             │ Packets   │
          └─────┬─────┘             └────┬──────┘
                │                         │
                └──────────┬──────────────┘
                           │
                    Security Evidence
                           │
                 ┌─────────▼─────────┐
                 │ Python Detection  │
                 │     Engine        │
                 └─────────┬─────────┘
                           │
                    Synthetic Logs
                           │
                    ┌──────▼──────┐
                    │   Splunk    │
                    │     SIEM    │
                    └──────┬──────┘
                           │
                     SPL Detection
                           │
                    ┌──────▼──────┐
                    │ Flask REST  │
                    │     API     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │    React    │
                    │ SOC Dashboard│
                    └──────┬──────┘
                           │
                    Analyst Interface
                           │
                    Live Threat Intel
                           │
                    ┌──────▼──────┐
                    │ VirusTotal  │
                    └─────────────┘
```
