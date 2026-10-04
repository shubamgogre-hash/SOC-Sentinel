# SOC Sentinel — Intelligent Attack Detection & Investigation Platform

SOC Sentinel is a portfolio cybersecurity project that demonstrates how security events can be collected, detected, correlated, investigated, and visualized using a SIEM-based workflow.

The project combines **Splunk, Linux security logs, Python automation, Git/GitHub, and MITRE ATT&CK mapping** to simulate a small Security Operations Center (SOC) investigation workflow.

---

## 🎯 Project Objective

The primary objective of SOC Sentinel is to move beyond detecting individual security events and instead correlate multiple related events into meaningful **Attack Stories**.

The project demonstrates the workflow:

Linux Security Logs  
↓  
Splunk / SIEM  
↓  
Detection Rules  
↓  
Security Events  
↓  
Python Correlation Engine  
↓  
Attack Story  
↓  
Investigation  
↓  
MITRE ATT&CK Mapping  
↓  
SOC Dashboard

---

## 🏗️ Architecture

```text
┌──────────────────────┐
│   Linux Security     │
│        Logs          │
│   /var/log/auth.log  │
│   /var/log/syslog    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│       Splunk         │
│        SIEM          │
│                      │
│ • Log Ingestion      │
│ • SPL Detection      │
│ • Correlation        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Python Correlation   │
│       Engine         │
│                      │
│ • Event Parsing      │
│ • Correlation        │
│ • Attack Stories     │
│ • Incident Creation  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Incident Data        │
│ JSON / CSV           │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   SOC Dashboard      │
│                      │
│ • Severity           │
│ • Timeline            │
│ • MITRE Techniques   │
│ • Attack Stories     │
│ • Investigation      │
└──────────────────────┘
