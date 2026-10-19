# AI-Augmented Cyber Attack Investigation Platform

[![CI Threat Triage](https://github.com/OWNER/REPO/actions/workflows/malware-scan.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/malware-scan.yml)
[![Platform](https://img.shields.io/badge/Platform-Docker%20%7C%20macOS%20ARM64-blue.svg)](https://www.docker.com/)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20Engine-orange.svg)](https://wazuh.com/)
[![Local AI](https://img.shields.io/badge/Inference-Ollama%20(Llama--3.2)-green.svg)](https://ollama.com/)

An end-to-end, multi-stage cybersecurity investigation platform and automated threat triage engine. This platform simulates a full-spectrum cyber kill chain in an isolated software-defined environment, captures raw ground-truth telemetry, performs deep-packet and host forensic analysis, and correlates all findings using a locally hosted LLM to produce MITRE ATT&CK-aligned incident response reports in seconds.

---

## 🎯 Problem Statement & Architecture

In modern Security Operations Centers (SOCs), digital evidence is fragmented across isolated silos:

- **Network Engineers** analyze packet captures (`.pcap`) and TCP streams.
- **Malware Analysts** dissect binary strings, hashes, and behavioral capabilities.
- **SIEM Engineers** triage syslog events and detection rule matches.
- **Forensic Investigators** reconstruct chronological incident timelines.

Cross-correlating these sources manually requires 2 to 4 hours per incident. This project automates that workflow. By combining containerized simulation, forensic parsers, and a local Large Language Model via LangChain, multi-source evidence is synthesized into a standardized, actionable incident report in under 45 seconds—with zero cloud egress and zero API cost.

### Architecture Overview

```text
                ┌────────────────────────────────────────────────────────┐
                │               ISOLATED DOCKER BRIDGE                   │
                │               lab-net (172.20.0.0/24)                  │
                │                                                        │
                │   ┌──────────────────┐          ┌──────────────────┐   │
                │   │  kali-attacker   │          │  ubuntu-victim   │   │
                │   │   172.20.0.10    │          │   172.20.0.20    │   │
                │   └─────────┬────────┘          └────────┬─────────┘   │
                └─────────────┼────────────────────────────┼─────────────┘
                              │                            │
                              ▼                            ▼
                   Recon / C2 / Exfiltration        tcpdump Wiretap
                              │                            │
                              └──────────────┬─────────────┘
                                             │
                                             ▼
                ┌────────────────────────────────────────────────────────┐
                │            PERSISTENT HOST EVIDENCE VOLUME             │
                │                     ./evidence                         │
                │  ├── full_attack.pcap      ├── wazuh_alerts.json       │
                │  ├── sys_update.py         ├── attack_timeline.json    │
                │  ├── carved_exfil.txt      └── malware_report.json     │
                └────────────────────────────┬───────────────────────────┘
                                             │
                                             ▼
                ┌────────────────────────────────────────────────────────┐
                │             LOCAL AI CORRELATION PIPELINE              │
                │           MacBook Air M1 (macOS Apple Silicon)         │
                │                                                        │
                │   scripts/evidence_loader.py (Multi-Source Aggregator) │
                │                     │                                  │
                │                     ▼                                  │
                │   scripts/ai_analyst.py (LangChain Orchestration)      │
                │                     │                                  │
                │                     ▼                                  │
                │   Ollama: Meta Llama 3.2 3B (Offline Local Inference)  │
                │                     │                                  │
                │                     ▼                                  │
                │         evidence/incident_report.md                    │
                └────────────────────────────────────────────────────────┘
```

---

## ⚡ The 8 GB RAM Survival Strategy

Running enterprise security tooling (Kali, vulnerable endpoints, Wazuh SIEM, Wireshark, and LLMs) on an 8 GB RAM MacBook Air M1 typically risks swap thrashing and system freezing.

This platform uses a strict **Phase-Decoupled Workflow**:

1. **Simulation Phase (~300 MB RAM):** Lightweight Kali and Ubuntu containers execute the intrusion, stream raw frames to a host volume via `tcpdump`, and immediately terminate.
2. **Forensics & SIEM Phase (~150 MB RAM):** Native Python engines evaluate extracted syslog telemetry against custom Wazuh XML rules and calculate YARA signatures.
3. **AI Analyst Phase (~2.5 GB RAM):** Meta's Llama 3.2 (3B) operates locally via Ollama, consuming approximately 2.5 GB of unified memory while leaving additional memory available for macOS system stability.

---

## ⚔️ The Intrusion Lifecycle: Operation RedBridge

| Stage | Action / Vector | Tooling | MITRE ATT&CK Mapping |
|---|---|---|---|
| **1. Reconnaissance** | TCP SYN half-open stealth port sweep against ports 21, 23, 80, 3306 | `nmap -sS` | **T1046** (Network Service Scanning) |
| **2. Masquerading** | Payload disguised as a legitimate system maintenance script (`sys_update.py`) | Python | **T1036.005** (Masquerading: Match Legitimate Name) |
| **3. Command & Control** | Interactive reverse shell connection initiated to attacker listening on port 4444 | Raw TCP Socket | **T1095** (Non-Application Layer Protocol) |
| **4. Discovery & Dumping** | Automated execution of `whoami`, `id`, `uname -a`, and inspection of `/etc/passwd` | Bash / Coreutils | **T1003** (OS Credential Dumping) |
| **5. Persistence** | Automated cron backdoor injected into `/etc/crontab`, scheduled every 5 minutes | `crontab` | **T1053.003** (Scheduled Task/Job: Cron) |
| **6. Exfiltration** | Linux user account database piped outward over raw TCP port 5555 | `netcat` | **T1041** (Exfiltration Over C2 Channel) |

---

## 🔍 Forensic Analysis & Deliverables

### 1. Network Packet Carving (`evidence/full_attack.pcap`)

- Dissected **29,135 raw Ethernet frames** using `tshark` and Wireshark.
- Reconstructed TCP Stream Index `0` to audit the interactive reverse shell session.
- Extracted TCP Stream Index `394` to carve the stolen user database (`evidence/carved_exfil.txt`) directly from packet data.

### 2. Static Malware Analysis & Signature Engineering

Cryptographic fingerprints:

- **MD5:** `2da4b2944d71927e1a981d7c5fd3cda7`
- **SHA-1:** `dfee4cf87844f9b21e199bb68df6198574db19ea`
- **SHA-256:** `4d084f83182bbd830ad4aa703e1b718d5bc805a3ec6860ad74e9ff107b0f0195`

Engineered detection signatures in `rules/malware_rules.yar` to identify socket instantiation, process spawning, and scheduled task modifications.

### 3. SIEM Detection Engineering & Visibility Gap Analysis

- Authored four custom Wazuh XML rules (`rules/local_rules.xml`) covering levels 9 through 13.
- Identified critical detection gaps: demonstrated that standard host syslog engines may fail to alert on internal TCP SYN sweeps, validating the need for unified network-to-host correlation.

---

## 🤖 Local AI Analyst Engine

The AI Analyst (`scripts/ai_analyst.py`) normalizes all telemetry into a structured, multi-source case file and queries Ollama locally with `temperature=0.1` to reduce output variability and encourage consistent incident analysis.

### Sample AI-Generated Incident Report Output

```markdown
# Incident Investigation & Threat Intelligence Report: Operation RedBridge

## 1. Executive Summary

Operation RedBridge involved a targeted intrusion against an enterprise Linux server, resulting in unauthorized access and the exfiltration of sensitive system data. The adversary utilized half-open network scanning, process masquerading, and an unencrypted reverse TCP channel before establishing cron-based persistence. Malicious artifacts were identified during the investigation.

## 2. MITRE ATT&CK Matrix Alignment

| Phase | Technique ID | Technique Name | Evidence & Artifact Reference |
|---|---|---|---|
| 1 | T1046 | Network Service Scanning | PCAP: SYN port sweep from 172.20.0.10 to 172.20.0.20 |
| 2 | T1036.005 | Masquerading | Static Malware Analysis: Execution of sys_update.py |
| 3 | T1095 | Non-Application Layer Protocol | SIEM Alert (Rule 100001) + PCAP: Traffic to port 4444/TCP |
| 4 | T1003 | OS Credential Dumping | SIEM Alert (Rule 100003): Access to /etc/passwd |
| 5 | T1053.003 | Scheduled Task/Job: Cron | SIEM Alert (Rule 100002) + YARA: Scheduled backdoor |
| 6 | T1041 | Exfiltration Over C2 Channel | Carved Stream 394: Data transfer over port 5555 |
```

---

## 🚀 Reproduction & Setup Guide

### Prerequisites

- macOS Apple Silicon (M1/M2/M3) or Linux x86_64
- Docker Desktop
- Python 3.12+
- Ollama with the `llama3.2` model
- YARA and Wireshark

### Step 1: Clone the Repository & Build the Lab Range

Replace `OWNER` and `REPO` with your actual GitHub username or organization and repository name.

```bash
git clone https://github.com/OWNER/REPO.git
cd cyber-investigation-platform
docker compose up -d --build
```

### Step 2: Set Up the Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Download the Local LLM

```bash
ollama pull llama3.2
```

Ensure the Ollama service is running before starting the AI analysis stage.

### Step 4: Run the Investigation Pipeline

```bash
python3 scripts/parse_network.py
python3 scripts/analyze_malware.py
python3 scripts/ingest_siem.py
python3 scripts/build_timeline.py
python3 scripts/ai_analyst.py
```

Run these scripts in the appropriate order and ensure the required evidence files exist. If your implementation uses different script names or dependencies, update the commands to match your repository.

---

## 📁 Repository Structure

```text
cyber-investigation-platform/
├── .github/
│   └── workflows/
│       └── malware-scan.yml      # CI/CD automated YARA triage pipeline
├── Dockerfile.attacker           # Custom Kali Linux attack image
├── Dockerfile.victim             # Custom Ubuntu 22.04 target image
├── docker-compose.yml            # Isolated lab-net container range
├── rules/
│   ├── malware_rules.yar         # YARA detection rules
│   └── local_rules.xml           # Custom Wazuh XML SIEM rules
├── scripts/
│   ├── parse_network.py          # Network PCAP packet parser
│   ├── analyze_malware.py        # Static malware analyzer and hash extractor
│   ├── ingest_siem.py            # SIEM rule evaluation engine
│   ├── build_timeline.py         # Chronological correlation engine
│   ├── evidence_loader.py        # Multi-source case file aggregator
│   └── ai_analyst.py             # LangChain + Ollama analysis engine
├── evidence/
│   ├── full_attack.pcap          # Raw packet capture
│   ├── sys_update.py             # Captured test artifact
│   ├── carved_exfil.txt          # Reconstructed data transfer payload
│   ├── network_forensics.json    # Structured network IOC dataset
│   ├── malware_report.json       # Structured malware analysis report
│   ├── wazuh_alerts.json         # Normalized SIEM alerts
│   ├── attack_timeline.json      # Machine-readable attack sequence
│   ├── timeline.txt              # Formatted incident timeline
│   └── incident_report.md        # Generated incident report
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🛡️ License & Responsible Use

This project was developed for authorized educational research, defensive security engineering, and digital forensics training.

All penetration testing and exploitation techniques are intended to run exclusively within an isolated, private lab network (`172.20.0.0/24`). Do not deploy the simulated attack components against systems or networks without explicit authorization.

**Note:** Reported performance metrics, RAM usage, packet counts, hashes, detection results, and ATT&CK mappings should be verified against the actual implementation and collected evidence before presenting them as measured results. Replace placeholder repository links and adjust the documented file structure and commands to match the contents of your GitHub repository.
