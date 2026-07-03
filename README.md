# 🛡️ SentinelMind

### Turning Security Noise into Actionable Intelligence

![Built with IBM Bob](https://img.shields.io/badge/Built%20with-IBM%20Bob-0f62fe?style=flat-square&logo=ibm&logoColor=white)
![Wildcard Challenge](https://img.shields.io/badge/AI%20Builders%20Challenge-Wildcard-7c3aed?style=flat-square)
![MVP Complete](https://img.shields.io/badge/Status-MVP%20Complete-22c55e?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)

> Submitted to the **AI Builders Challenge with IBM Bob** — *Wildcard Challenge: Build Intelligent Systems for the Future of Work*

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Solution Overview](#-solution-overview)
- [Demo](#-demo)
- [AI Approach & Architecture](#-ai-approach--architecture)
- [How IBM Bob Was Used](#-how-ibm-bob-was-used)
- [Tech Stack](#-tech-stack)
- [Selected Challenge](#-selected-challenge)
- [Installation & Setup](#-installation--setup)
- [Sample Detection Output](#-sample-detection-output)
- [Future Enhancements](#-future-enhancements)
- [Team](#-team)

---

## 🚨 Problem Statement

Security Operations Centre (SOC) analysts are drowning.

A mid-sized enterprise generates **tens of thousands of security alerts every single day**. The average analyst must triage hundreds of events per shift — most of which are false positives. This creates a cascade of compounding problems:

| Problem | Impact |
|---|---|
| **Alert fatigue** | Analysts become desensitised, missing real threats buried in noise |
| **High false-positive rates** | Industry average exceeds 40%; analysts waste hours chasing ghosts |
| **Burnout & attrition** | SOC is one of the highest-turnover roles in tech |
| **Communication gap** | Technical findings don't translate to business stakeholders — CISOs and managers can't act on raw log data |
| **Slow mean-time-to-respond** | Without prioritisation, critical threats sit unaddressed for hours |

The core issue isn't a lack of data — it's a lack of **intelligible, prioritised, actionable** data. Analysts need a system that can cut through the noise, explain what is happening in plain English, and tell them exactly what to do next.

---

## 💡 Solution Overview

**SentinelMind** is an AI-powered security log analysis and decision-support platform that transforms raw event logs into clear, prioritised, human-readable threat intelligence.

### What It Does

**1. Ingests & parses security logs**
Loads structured event logs (timestamp, username, source IP, event type, status) and normalises them for analysis.

**2. Detects threats using rule-based intelligence**
Three core detection engines identify the most common and dangerous attack patterns seen in real-world environments:

- 🔴 **Brute Force** — multiple failed login attempts from the same IP, followed by a successful authentication
- 🟡 **Off-Hours Access** — login, privilege escalation, or sensitive data access occurring between midnight and 06:00
- 🔴 **Privilege Escalation + Data Access** — an account elevating its own permissions then immediately accessing sensitive data — the classic lateral movement / exfiltration pattern

**3. Scores risk 0–100**
Every detected threat receives a numeric risk score based on severity indicators (attempt volume, time of day, event chaining), enabling instant prioritisation without manual triage.

**4. Generates dual explanations**
This is the core differentiator. For each threat, SentinelMind writes two versions of the same explanation:
- **Technical View** — precise, log-referenced language for SOC analysts
- **Simple View** — plain-English narrative for managers, executives, and non-technical stakeholders

**5. Maps to MITRE ATT&CK**
Every alert is tagged with the relevant MITRE ATT&CK technique (e.g. T1110 Brute Force, T1068 Privilege Escalation), giving analysts immediate context within the industry-standard threat taxonomy.

**6. Tells the "Attack Story"**
Clicking any username opens a chronological timeline modal that reconstructs the full sequence of an attacker's movements — from first probe to privilege escalation to data exfiltration — in one readable view.

**7. Recommends remediation actions**
Each alert includes a specific, actionable recommendation (e.g. "Reset credentials, block source IP, enable MFA") so analysts spend time acting rather than deliberating.

---

## 🎬 Demo

### Video Walkthrough

> 📹 **[Watch the demo video](https://youtu.be/Yfm5iqI5Q5k)**

---

## 🏗️ AI Approach & Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SentinelMind                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Raw Log Data          Detection Engine        REST API         │
│  (CSV / SIEM)   ──►   (Rule-based threat  ──► (FastAPI)        │
│                         pattern matching)      Port 8000        │
│                                │                    │            │
│                                ▼                    ▼            │
│                       Explanation Generator    SOC Dashboard    │
│                       ├─ Technical text        ├─ Alert cards   │
│                       ├─ Plain-English text    ├─ Risk scores   │
│                       ├─ MITRE ATT&CK tag      ├─ View toggle   │
│                       └─ Remediation action    └─ Timeline      │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Detection Rules

| Rule | Trigger Condition | Risk Score | Severity | MITRE Technique |
|---|---|---|---|---|
| **Brute Force** | 3+ failed logins from the same source IP, followed by a successful login | 75 – 95 | High | T1110 — Brute Force |
| **Privilege Escalation + Data Access** | `privilege_escalation` event followed by `access_sensitive_data` for the same user/IP | 90 | High | T1068 — Exploitation for Privilege Escalation |
| **Off-Hours Access** | Suspicious events (login, privilege escalation, sensitive data access) between 00:00–05:59; score elevated to 75 when privilege escalation is also present | 55 – 75 | Medium / High | T1078 — Valid Accounts |

### Risk Score Model

```
Brute Force:  base 60 + (5 × failed_attempt_count), capped at 95
Priv-Esc:     fixed 90
Off-Hours:    55 (activity only)  |  75 (+ privilege escalation)

Severity thresholds:
  ≥ 70  →  High
  ≥ 40  →  Medium
  < 40  →  Low
```

---

## 🤖 How IBM Bob Was Used

IBM Bob was the primary development tool for this entire project — not as an autocomplete assistant, but as an **autonomous engineering collaborator** working through the full build lifecycle.

### Backend — FastAPI + Detection Engine

Bob was given a single detailed specification and built the entire [`backend/main.py`](backend/main.py) from scratch — including:

- `load_logs()` — CSV ingestion and data normalisation with pandas
- `detect_threats()` — three independent, chained detection passes with scoring logic
- `generate_explanation()` — dual-narrative explanation generator with MITRE mapping
- All three API routes (`/alerts`, `/alerts/{username}`, `/stats`) with correct HTTP semantics
- CORS middleware configured for frontend access

Bob then **wrote its own validation tests** and ran them, fixing a Windows console encoding edge case before reporting success — demonstrating a genuine test → debug → verify loop without human intervention.

### Frontend — SOC Dashboard

Bob built the complete [`frontend/index.html`](frontend/index.html) from a detailed feature specification, producing a professional dark-theme SOC dashboard with:

- Parallel `fetch()` calls to `/stats` and `/alerts` on load
- Animated risk score progress bars
- Collapsible alert cards with XSS-safe rendering
- Technical/Simple view toggle using `<template>` elements (no re-render)
- Severity filter pills
- A full attack-story timeline modal with colour-coded event nodes
- Error and loading states with actionable recovery messages

### Agentic Workflow

Bob's structured workflow — **explore → create → validate** — drove the entire session:

1. **Explored** the existing workspace to understand file structure and existing stubs
2. **Created** each file with complete, production-quality content
3. **Validated** by running the code, reading actual output, and self-correcting

No scaffolding was used. Every line of application code was generated and verified by Bob.

---

## 🧰 Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend runtime** | Python 3.11 | Core application language |
| **API framework** | FastAPI 0.111 | REST API with automatic OpenAPI docs |
| **Data processing** | Pandas 2.2 | Log ingestion, grouping, and analysis |
| **API server** | Uvicorn 0.30 | ASGI server for FastAPI |
| **Frontend** | HTML5 / CSS3 / Vanilla JS | Zero-dependency SOC dashboard |
| **AI dev tool** | IBM Bob | Full-stack code generation & validation |
| **Threat intelligence** | MITRE ATT&CK | Industry-standard technique taxonomy |

---

## 🎯 Selected Challenge

### Wildcard — Build Intelligent Systems for the Future of Work

SentinelMind directly addresses the challenge theme: **using AI to augment human work, not replace it**.

Security analysts are knowledge workers under extreme cognitive load. SentinelMind acts as an **AI co-worker** — one that never sleeps, never suffers alert fatigue, and translates complex technical signals into language every stakeholder can understand and act on.

The "future of work" in security isn't about automating analysts out of existence. It's about giving them a system that handles the **classification, prioritisation, explanation, and escalation guidance** — so they can focus on the high-judgement decisions that genuinely require a human.

The dual Technical/Simple View feature embodies this philosophy: the same intelligence, expressed in the right language for the right person, at the right moment.

---

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.10 or higher
- A modern web browser (Chrome, Firefox, Edge, Safari)

### 1. Clone the repository

```bash
git clone https://github.com/sanasimran1403-jpg/sentinelmind.git
cd sentinelmind
```

### 2. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

`requirements.txt` includes:
```
fastapi==0.111.0
uvicorn==0.30.1
pandas==2.2.2
python-multipart==0.0.9
```

### 3. Start the backend API

```bash
# From the backend/ directory
python main.py

# Or with hot-reload for development
uvicorn main:app --reload
```

The API will be available at **`http://localhost:8000`**.

Interactive API documentation: **`http://localhost:8000/docs`**

### 4. Open the dashboard

```bash
# No build step required — open directly in your browser
open frontend/index.html          # macOS
start frontend/index.html         # Windows
xdg-open frontend/index.html      # Linux
```

> **Note:** Both the backend server and the frontend page must be running simultaneously. The dashboard fetches all data from `localhost:8000` on page load.

---

## 📊 Sample Detection Output

With the included `data/sample_logs.csv`, SentinelMind detects **10 threats across 29 events**:

```
Score  Severity  Threat Type                              User
─────────────────────────────────────────────────────────────────
  90   High      Privilege Escalation + Data Access       maria.garcia
  90   High      Privilege Escalation + Data Access       svc_backup
  90   High      Privilege Escalation + Data Access       unknown_user
  80   High      Brute Force Attack                       unknown_user
  75   High      Brute Force Attack                       john.smith
  75   High      Off-Hours Access                         maria.garcia
  75   High      Off-Hours Access                         svc_backup
  75   High      Off-Hours Access                         unknown_user
  55   Medium    Off-Hours Access                         david.lee
  55   Medium    Off-Hours Access                         john.smith
```

The `unknown_user` account — attacking from `45.33.12.88` at 02:14 — is the most dangerous actor in this dataset, triggering all three detection rules in a single session:
1. 4 failed logins → successful login (Brute Force, score 80)
2. Privilege escalation → sensitive data access (score 90)
3. All activity between 02:14–02:16, well outside business hours (score 75)

---

## 🔮 Future Enhancements

| Enhancement | Description |
|---|---|
| **Real-time SIEM integration** | Connect directly to Splunk, Microsoft Sentinel, or Elastic SIEM via API/webhook for live streaming alerts |
| **ML-based anomaly detection** | Replace rule-based thresholds with learned baselines — flag deviations from a user's normal behaviour profile |
| **IBM watsonx / Granite integration** | Use IBM's foundation models to generate richer, context-aware natural-language explanations and incident reports |
| **Multi-analyst collaboration** | Allow SOC teams to annotate, assign, escalate, and resolve alerts with a full audit trail |
| **Threat intelligence enrichment** | Auto-enrich source IPs against threat feeds (AbuseIPDB, VirusTotal) to confirm known-bad actors |
| **Executive reporting** | One-click PDF/email report generation with board-level summaries of the security posture |
| **False positive feedback loop** | Analysts mark false positives; the system learns and adjusts scoring weights over time |

---

## 👤 Team

| Name | University / Organisation | Role |
|---|---|---|
| Sana Simrann | St. Paul's Degree & PG College, Osmania University | Full-Stack Developer & AI Architect |

---

## 📄 License

This project was built for the **AI Builders Challenge with IBM Bob** (Wildcard Challenge).

---

<div align="center">

Built with ❤️ and **IBM Bob** &nbsp;·&nbsp; AI Builders Challenge &nbsp;·&nbsp; Wildcard Challenge

*Turning Security Noise into Actionable Intelligence*

</div>