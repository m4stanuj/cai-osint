<div align="center">

# 🛡️ CAI-OSINT — Autonomous Cyber Reconnaissance Framework

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![CI](https://github.com/m4stanuj/cai-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/m4stanuj/cai-osint/actions)
[![Release](https://img.shields.io/github/v/release/m4stanuj/cai-osint?style=flat-square&color=FF0055)](https://github.com/m4stanuj/cai-osint/releases)
[![Stars](https://img.shields.io/github/stars/m4stanuj/cai-osint?style=flat-square&color=yellow)](https://github.com/m4stanuj/cai-osint/stargazers)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CEH](https://img.shields.io/badge/CEH-Aligned-red?style=flat-square)]()

**An AI-driven OSINT and penetration testing automation framework. From target to report — fully autonomous.**

> ⚠️ **Ethical Use Only.** This tool is designed for authorized penetration testing and security research. Always obtain explicit written permission before testing any system.

[Features](#features) · [Architecture](#architecture) · [Workflow](#workflow) · [Tools](#integrated-tools) · [Reports](#reporting)

</div>

---

## 🔍 What is CAI-OSINT?

CAI-OSINT combines a **CEH-aligned offensive security methodology** with LLM-driven intelligence gathering. It automates the full penetration testing lifecycle: reconnaissance → enumeration → vulnerability scanning → exploitation guidance → professional report generation.

Built as an MCP layer inside M4STCLAW v3, it operates as an **autonomous security analyst** — you give it a target domain, it returns a comprehensive vulnerability assessment.

## ✨ Features

### 🌐 Passive Reconnaissance
- **Shodan** API integration — automated exposure mapping
- **Subfinder** — subdomain enumeration across 50+ sources
- **WHOIS** & DNS intelligence gathering
- Social engineering target profiling

### 🔬 Active Enumeration
- **Nmap** — intelligent port scanning with OS detection
- **Service fingerprinting** — identify software versions
- Banner grabbing and HTTP header analysis

### 💉 Vulnerability Assessment
- **Nuclei** — 8,000+ CVE template scanning
- **CVE database** lookups via NIST NVD API
- Severity scoring (CVSS v3)
- False positive filtering via AI analysis

### 🤖 AI-Powered Analysis
- **DeepSeek-R1** for reasoning over scan output
- Automated attack surface prioritization
- Exploitation path suggestion (ethical guidance)
- Natural language query interface

### 📋 Report Generation
- Auto-generated **Markdown + PDF** reports
- Executive summary + technical detail sections
- Remediation recommendations
- OWASP/CVE cross-referencing

## 🏗️ Architecture

```
Target Input
     │
     ▼
┌────────────────────┐
│  Passive Recon     │ ◄── Shodan + Subfinder + WHOIS
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Active Enum       │ ◄── Nmap + Banner Grab
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Vuln Scan         │ ◄── Nuclei + CVE Lookup
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  AI Analysis       │ ◄── DeepSeek-R1 reasoning
│  (DeepSeek-R1)     │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  Report Generator  │ ◄── Auto MD/PDF output
└────────────────────┘
```

## 🔧 Integrated Tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| **Nmap** | Port scanning, OS detect | Python subprocess + AI parsing |
| **Nuclei** | CVE template scanning | Async execution + result filtering |
| **Shodan** | Passive exposure analysis | REST API via Python SDK |
| **Subfinder** | Subdomain enumeration | CLI wrapper with JSON output |
| **DeepSeek-R1** | Intelligence reasoning | OpenRouter API |

## 📊 Sample Workflow

```bash
# Initialize a pentest session
python pentest.py --target example.com --mode full

# Output:
# [RECON]   Shodan: 3 exposed services found
# [ENUM]    Nmap: 12 open ports (80, 443, 22, 8080...)
# [SCAN]    Nuclei: 2 critical CVEs detected (CVE-2024-XXXX)
# [AI]      DeepSeek-R1 analyzing attack surface...
# [REPORT]  Generated: ./reports/example.com_2026-04-19.md
```

## ⚖️ Legal & Ethics

This tool is built for:
- ✅ CTF (Capture The Flag) competitions
- ✅ Authorized bug bounty programs
- ✅ Penetration testing with written permission
- ✅ Your own infrastructure security auditing
- ❌ Unauthorized access to any system

---

<div align="center">
  <sub>Part of the <a href="https://github.com/m4stanuj">M4STCLAW ecosystem</a> · CEH methodology aligned · Built for ethical security research</sub>
</div>
