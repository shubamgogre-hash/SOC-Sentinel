 🛡️ SOC Sientinel

 Intelligent Attack Detection & Investigation Platform

SOC Sentinel is a practical Security Operations Center (SOC) project designed to simulate how security events can be collected, detected, correlated, investigated, and presented as an attack story.

The project uses Splunk as the SIEM layer and will progressively integrate Linux security logs, detection rules, correlation logic, Python automation, MITRE ATT&CK mapping, and a SOC dashboard.

---

 🎯 Project Objective

The goal of SOC Sentinel is to build an end-to-end security monitoring and investigation workflow:

Linux/Windows Security Events
        ↓
       SIEM
        ↓
Detection Rules
        ↓
Event Correlation
        ↓
Attack Story
        ↓
Investigation
        ↓
MITRE ATT&CK Mapping
        ↓
SOC Dashboard & Report

---

 🧩 Core Components

- Security event collection
- SIEM-based monitoring
- Failed-login detection
- Suspicious activity detection
- User/IP correlation
- Authentication correlation
- Attack timeline generation
- Attack Story creation
- Investigation status
- MITRE ATT&CK mapping
- Python-based automation
- SOC dashboard
- Investigation reporting

---

 📊 Current Progress

 Days 1–4 — Completed

- SOC and SIEM fundamentals
- Splunk fundamentals
- SPL fundamentals
- `makeresults`
- `eval`
- `table`
- `search`
- `stats`
- `sort`
- `append`
- `strptime`
- `_time` handling
- Failed-login detection
- Threshold-based suspicious activity detection
- User/IP correlation
- Failed → successful authentication correlation
- Event timelines
- Attack Story ID generation
- Attack stages
- Investigation status
- Basic MITRE ATT&CK mapping

 Current Stage

**Project Day 5 — Real Linux Logs & GitHub Integration**

Next development focus:

1. Ingest real Linux security logs into Splunk
2. Build real detection rules
3. Improve event correlation
4. Develop Python investigation/automation components
5. Expand MITRE ATT&CK mapping
6. Generate attack timelines
7. Build SOC dashboard
8. Test realistic attack scenarios
9. Complete GitHub documentation
10. Prepare final demonstration and interview explanation

---

 🔍 Example Attack Story

A simulated attack sequence currently used for correlation testing:

```text
Failed Login
     ↓
Failed Login
     ↓
Successful Login
     ↓
PowerShell Activity
     ↓
Attack Story
