# SOC Sentinel — Intelligent Attack Detection & Investigation Platform

SOC Sentinel is a portfolio cybersecurity project that demonstrates a small-scale **Security Operations Center (SOC) investigation workflow** using Linux security logs, Splunk SIEM, Python-based event correlation, incident generation, and MITRE ATT&CK mapping.

The project focuses on transforming individual security events into meaningful **Attack Stories** that can be investigated and visualized through a SOC dashboard.

---

## 🎯 Project Objective

The primary objective of SOC Sentinel is to demonstrate how a SOC analyst can:

- Collect and monitor security events
- Detect suspicious authentication and system activity
- Correlate multiple related events
- Build attack stories from event sequences
- Generate structured security incidents
- Map suspicious activity to MITRE ATT&CK techniques
- Visualize incident information through a SOC dashboard

The overall workflow is:

```text
Linux Security Logs
        ↓
Splunk / SIEM
        ↓
Detection & Correlation
        ↓
Python Correlation Engine
        ↓
Attack Story
        ↓
Incident Creation
        ↓
MITRE ATT&CK Mapping
        ↓
SOC Dashboard
```

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
│ • Timeline           │
│ • MITRE Techniques   │
│ • Attack Stories     │
│ • Investigation      │
└──────────────────────┘
```

---

## 🔍 Key Features

### 1. Linux Security Log Monitoring

SOC Sentinel uses Linux security and system logs as the source of security events.

Example log sources:

```text
/var/log/auth.log
/var/log/syslog
```

These logs can contain authentication activity, privileged operations, system events, and other security-relevant information.

---

### 2. Splunk SIEM Integration

Splunk is used as the SIEM layer for:

- Log ingestion
- Security event searching
- SPL-based detection
- Event filtering
- Event correlation
- Investigation

Example Splunk workflow:

```text
Raw Security Events
        ↓
SPL Search
        ↓
Suspicious Activity
        ↓
Correlation
        ↓
Investigation Candidate
```

---

### 3. Authentication Attack Detection

SOC Sentinel demonstrates correlation of multiple authentication failures followed by a successful login.

Example attack pattern:

```text
FAILED LOGIN
      ↓
FAILED LOGIN
      ↓
FAILED LOGIN
      ↓
SUCCESSFUL LOGIN
```

The correlation engine generates an investigation candidate when the sequence occurs within the configured correlation window.

Example:

```text
Incident ID:
SIM-AUTH-20261003140000

Severity:
High

Status:
INVESTIGATE

Failed Attempts:
3

Source IP:
10.10.10.50

Target User:
shubam

MITRE Candidate:
T1110 — Brute Force
```

---

### 4. Privileged Account Attack Story

SOC Sentinel also demonstrates correlation of privileged account activity into a multi-stage attack story.

Example sequence:

```text
ROOT LOGIN
     ↓
PASSWORD CHANGE
     ↓
COMMAND EXECUTION
```

Example generated incident:

```text
Incident ID:
SIM-20261003130000

Severity:
High

Status:
INVESTIGATE

Attack Story:
ROOT_LOGIN → PASSWORD_CHANGE → COMMAND_EXECUTION

Duration:
120 seconds

Command:
whoami

MITRE Candidate:
T1078 — Valid Accounts
```

---

## 🐍 Python Correlation Engine

The Python correlation engine is responsible for converting related security events into structured incidents.

Main responsibilities:

```text
Event Parsing
     ↓
Event Correlation
     ↓
Attack Story Detection
     ↓
Severity Assignment
     ↓
MITRE Technique Candidate
     ↓
Incident Creation
```

The generated incident information is stored in:

```text
python/incidents.json
python/incidents.csv
```

The engine is implemented in:

```text
python/correlation_engine.py
```

---

## 🛡️ Attack Story Concept

Instead of treating every event independently, SOC Sentinel combines related events into a single investigation story.

For example:

```text
Failed Login
     ↓
Failed Login
     ↓
Failed Login
     ↓
Successful Login
```

is treated as a correlated authentication attack candidate rather than four unrelated events.

Similarly:

```text
Root Login
     ↓
Password Change
     ↓
Command Execution
```

is represented as a privileged account activity attack story.

This approach demonstrates a simplified version of how SOC analysts investigate **event sequences and attack behavior** rather than isolated log entries.

---

## 🎯 MITRE ATT&CK Mapping

SOC Sentinel associates detected attack patterns with candidate MITRE ATT&CK techniques.

Current examples include:

| Attack Pattern | MITRE Technique |
|---|---|
| Multiple authentication failures followed by successful login | T1110 — Brute Force |
| Valid account / privileged account activity | T1078 — Valid Accounts |

The mapping is treated as an **investigation candidate**, not definitive proof that an attack occurred.

---

## 📊 SOC Dashboard

The project includes a Splunk-based SOC dashboard designed to provide an analyst-oriented view of incident information.

Dashboard areas include:

- Incident severity
- Investigation status
- Attack stories
- MITRE ATT&CK techniques
- Incident timeline
- Total incidents
- High-severity incidents

The dashboard is intended to provide a centralized view of correlated security activity.

---

## 📁 Project Structure

```text
SOC-Sentinel/
│
├── dashboard/
│   └── .gitkeep
│
├── docs/
│   └── .gitkeep
│
├── python/
│   ├── correlation_engine.py
│   ├── incidents.json
│   ├── incidents.csv
│   ├── simulated_attack.log
│   └── simulated_auth_attack.log
│
├── sample-data/
│   └── .gitkeep
│
├── screenshots/
│   └── .gitkeep
│
├── splunk/
│   └── .gitkeep
│
├── .gitignore
└── README.md
```

---

## ⚙️ Running the Python Correlation Engine

From the project directory:

```bash
cd ~/SOC-Sentinel/python
python3 correlation_engine.py
```

The engine processes the simulated security scenarios and generates structured incident data.

Generated files:

```text
incidents.json
incidents.csv
```

---

## 🔎 Splunk Investigation

Splunk can be used to search and investigate the ingested Linux security events.

Example searches can be used to:

- Identify authentication failures
- Identify successful authentication
- Investigate suspicious users
- Investigate source IP addresses
- Correlate events within a time window
- Build attack timelines

Example event correlation concept:

```text
Multiple Failed Logins
        +
Successful Login
        ↓
Authentication Attack Candidate
```

---

## 🧪 Simulated Laboratory Environment

SOC Sentinel uses simulated attack scenarios for controlled testing and demonstration.

The generated incidents are **not evidence of real-world compromise**.

The project is designed for:

- SOC learning
- SIEM practice
- Detection engineering practice
- Incident investigation
- Portfolio demonstration
- Interview preparation

---

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Linux / WSL | Security log environment |
| Splunk Enterprise | SIEM and investigation |
| SPL | Detection and event analysis |
| Python | Event correlation and automation |
| JSON | Structured incident output |
| CSV | Incident data export |
| Git | Version control |
| GitHub | Project repository |
| MITRE ATT&CK | Attack technique mapping |

---

## 🧠 Skills Demonstrated

This project demonstrates practical experience with:

- SOC monitoring
- SIEM concepts
- Splunk
- SPL
- Linux security logs
- Authentication event analysis
- Event correlation
- Attack story construction
- Incident creation
- MITRE ATT&CK mapping
- Python automation
- JSON / CSV data handling
- Git and GitHub
- Security investigation workflows

---

## 🚀 Future Enhancements

Possible future improvements include:

- Windows Event Log integration
- Additional authentication detections
- Automated alert prioritization
- Expanded MITRE ATT&CK mapping
- More realistic attack simulations
- Automated response actions
- Additional SOC dashboard visualizations
- Integration with other SIEM platforms

---

## ⚠️ Disclaimer

SOC Sentinel is an educational cybersecurity project developed in a controlled laboratory environment.

The attack scenarios and incidents generated by the project are simulated for detection, correlation, investigation, and visualization purposes.

They should not be interpreted as evidence of an actual security compromise.

---

## 👨‍💻 Project

**SOC Sentinel — Intelligent Attack Detection & Investigation Platform**

Built as a hands-on cybersecurity/SOC learning and portfolio project using Linux, Splunk, Python, Git, and MITRE ATT&CK.
