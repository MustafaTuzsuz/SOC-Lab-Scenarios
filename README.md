# 🔎 SOC Lab Scenarios — Incident Detection & Response

> Hands-on Security Operations Centre (SOC) lab scenarios covering 
> threat detection, network traffic analysis, and incident response.
> Built using real tools: Wireshark, Nmap, and Linux CLI.

---

## 📋 Overview

This repository documents real SOC analyst workflows applied in a 
controlled lab environment. Each scenario follows the standard 
incident response lifecycle: Detect → Analyse → Contain → Eradicate → Recover → Document

---

## 📁 Repository Structure

soc-lab-scenarios/
├── scenario-01-port-scan/
│   ├── README.md              # Full walkthrough
│   ├── analysis-notes.md      # Findings and IOCs
│   └── wireshark-filters.md   # Filters used
├── scenario-02-brute-force/
│   ├── README.md
│   ├── analysis-notes.md
│   └── log-samples.md
├── scenario-03-traffic-analysis/
│   ├── README.md
│   └── wireshark-filters.md
├── tools-and-references/
│   ├── wireshark-cheatsheet.md
│   └── incident-response-checklist.md
└── README.md

---

## 🛡️ Scenarios

| # | Scenario | Technique | Tools |
|---|---|---|---|
| 01 | Port Scan Detection | Reconnaissance | Wireshark, Nmap |
| 02 | SSH Brute Force Detection | Credential Attack | Linux logs, Wireshark |
| 03 | Anomalous Traffic Analysis | Exfiltration/C2 | Wireshark |

---

## 🧰 Tools Used

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat&logo=wireshark&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Nmap](https://img.shields.io/badge/Nmap-214a7e?style=flat&logoColor=white)

| Tool | Purpose |
|---|---|
| Wireshark | Packet capture and traffic analysis |
| Nmap | Network scanning and reconnaissance |
| Linux CLI | Log analysis and system investigation |
| grep / awk | Log parsing and pattern matching |

---

## 📚 Incident Response Methodology

Each scenario follows this workflow:

1. **Detection** — identify suspicious activity
2. **Analysis** — investigate scope and impact
3. **Containment** — isolate affected systems
4. **Eradication** — remove threat
5. **Recovery** — restore normal operations
6. **Documentation** — record findings and IOCs

---

## 👤 Author

**Mustafa Talha Tuzsuz**  
Junior Cybersecurity & Cloud Engineer — Dublin, Ireland  
[LinkedIn](https://linkedin.com/in/tuzsuz) • [Email](mailto:tuzsuz@pm.me)

> ✅ Stamp 4 Visa | Full work authorisation | Available immediately
