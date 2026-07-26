<div align="center">

# 🛡️ Vistra

### Hybrid Ransomware Detection & Prevention Framework for Linux

*A two-layer security framework combining static malware scanning with real-time kernel behavioural monitoring to detect and mitigate ransomware before large-scale encryption occurs.*

![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![Language](https://img.shields.io/badge/C++-17-blue)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![eBPF](https://img.shields.io/badge/eBPF-Kernel-red)
![YARA](https://img.shields.io/badge/YARA-Signature-green)
![Status](https://img.shields.io/badge/Status-Research-orange)

</div>

---

## Overview

Vistra is a **hybrid anti-ransomware framework** designed for Linux systems.

Unlike traditional antivirus software that relies solely on malware signatures, Vistra combines **signature-based detection** with **real-time behavioural analysis** to identify both known ransomware samples and previously unseen attacks.

The framework continuously monitors file-system activity using **eBPF**, analyses suspicious process behaviour, and automatically generates security alerts while providing options to quarantine or remove malicious files.

---

# Architecture

```text
                     +------------------------+
                     |      User / Client     |
                     +-----------+------------+
                                 |
                                 |
                     WebSocket Communication
                                 |
                 +---------------v---------------+
                 |        FastAPI Backend        |
                 +---------------+---------------+
                                 |
        --------------------------------------------------
        |                                                |
        |                                                |
+-------v--------+                            +----------v---------+
| Layer 1 Agent  |                            | Layer 2 Behaviour  |
| Static Scanner |                            | Detection Engine   |
+-------+--------+                            +----------+---------+
        |                                              |
        |                                              |
   C++ Scanner                                   eBPF Kernel Hooks
        |                                              |
   YARA Rules                             File Writes / Rename /
        |                                Delete / Truncate Events
        |                                              |
        +----------------------+-----------------------+
                               |
                        Threat Detection
                               |
                  Alert / Quarantine / Delete
```

---

# Features

### Static Detection

- Signature-based malware scanning
- YARA rule engine
- Detects known ransomware samples
- Identifies suspicious executable files
- Automated scan reporting

### Behavioural Detection

- Real-time kernel monitoring using eBPF
- Process profiling
- Burst activity detection
- Mass file rename detection
- Mass deletion detection
- High-volume write detection
- Suspicious execution path detection

### Incident Response

- Alert generation
- File quarantine
- File deletion
- Restore quarantined files
- Detection logs

---

# Detection Pipeline

## Layer 1 – Static Analysis

The Layer 1 agent performs signature-based scanning using a custom C++ scanner integrated with **YARA**.

The scanner searches files for ransomware indicators including:

- Known malware signatures
- ELF executable patterns
- Ransom notes
- Encryption behaviour
- TOR payment references
- Suspicious Python ransomware scripts

If a malicious file is detected, the backend can:

- quarantine the file
- delete the file
- notify the dashboard

---

## Layer 2 – Behavioural Analysis

Layer 2 continuously observes kernel events using **eBPF**.

Instead of looking for signatures, it analyses process behaviour by tracking:

- file writes
- file renames
- file deletions
- process execution
- syscall frequency
- write volume

Every process receives a **risk score** based on its behaviour.

Example factors include:

| Behaviour | Risk |
|-----------|------|
| Mass rename operations | High |
| Large write volume | Medium |
| Burst syscall activity | Medium |
| Running from `/tmp` | Medium |
| Mass file deletion | High |

When the risk threshold is exceeded, Vistra generates a security alert.

---

# Project Structure

```
Vistra
│
├── Agents/
│   ├── agent.py
│   ├── scanner.cpp
│   ├── scanner
│   └── Yara/
│
├── Layer2/
│   ├── eBPFAgent.bpf.c
│   ├── monitor.c
│   ├── BehavioralEngine/
│   │      └── layer2.py
│   └── run.sh
│
├── Files/
│
├── Tests/
│
├── alerts/
│
└── README.md
```

---

# Technologies

| Technology | Purpose |
|------------|----------|
| C++ | Static malware scanner |
| Python | Agent orchestration |
| FastAPI | Backend communication |
| WebSockets | Agent communication |
| eBPF | Kernel event monitoring |
| YARA | Signature detection |
| Linux | Target platform |

---

# Alert Generation

When suspicious activity is detected, Vistra generates structured JSON alerts containing:

- Process information
- Risk score
- Detection timestamp
- Behaviour summary
- Process runtime
- File activity

These alerts can later be integrated into SIEM platforms or monitoring dashboards.

---

# Sample Detection Workflow

```
User starts scan
        │
        ▼
C++ Scanner
        │
        ▼
YARA Rules
        │
        ▼
Known Malware?
        │
 ┌──────┴────────┐
 │               │
Yes             No
 │               │
 ▼               ▼
Quarantine    Behaviour Monitor
                    │
                    ▼
             eBPF Kernel Events
                    │
                    ▼
             Risk Score Engine
                    │
                    ▼
          Threshold Exceeded?
                    │
          ┌─────────┴─────────┐
          │                   │
         Yes                 No
          │                   │
          ▼                   ▼
     Generate Alert      Continue Monitoring
```

---

# Research Focus

Vistra explores a hybrid approach to ransomware detection by combining:

- Signature-based malware identification
- Behaviour-based anomaly detection
- Kernel-level monitoring
- Automated response mechanisms

This approach enables detection of both **known ransomware families** and **previously unseen behavioural variants**.

---

# Contributors

- [Krishnan E](https://github.com/krishnanx)
- [Sreyavenkat](https://github.com/Sreyavenkat)

---

# License

This project was developed for academic and research purposes.

---
