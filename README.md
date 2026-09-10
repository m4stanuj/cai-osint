# 🛡️ cai-osint

> **Autonomous AI OSINT & Security Assessment Engine via Model Context Protocol (MCP)**  
> Autonomous reconnaissance, SSL/TLS posture auditing, HTTP security headers analysis, open service triage, and executive vulnerability reporting for AI agents (Cursor, Windsurf, Claude Desktop).

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Enabled-purple.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/m4stanuj/cai-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/m4stanuj/cai-osint/actions)

---

## 💥 The Problem
Security analysts and bug bounty hunters waste hours manually jumping between `whois`, `dig`, `nmap`, and SSL certificate inspectors, and then even longer formatting markdown tables into client-ready executive reports.

Existing security MCP tools are mostly raw command wrappers that trigger agent hallucinations or get IP-blocked.

---

## 🚀 The Solution: `cai-osint`
`cai-osint` provides high-level **agentic workflows** directly to your AI assistant:

```
┌───────────────────────────────────────────────────────────┐
│                    AI Agent (Cursor/Claude)                │
│                "Audit the security of example.com"        │
└────────────────────────┬──────────────────────────────────┘
                         │ MCP Tool Call
┌────────────────────────▼──────────────────────────────────┐
│                    cai-osint FastMCP Server                │
├───────────────────────────────────────────────────────────┤
│  [1] Passive Recon     DNS, CDN, SPF/DMARC resolution    │
│  [2] TLS Audit         Certificate validity & expiry      │
│  [3] Port Scan         Rate-limited banner grabbing       │
│  [4] Header Analysis   HSTS, CSP, X-Frame-Options        │
│  [5] Posture Score     CVSS-aligned risk assessment       │
│  [6] Report Gen        Markdown executive report          │
└────────────────────────┬──────────────────────────────────┘
                         │
                  ┌──────▼──────┐
                  │  audit_     │
                  │  report.md  │
                  └─────────────┘
```

---

## ✨ Features

| Feature | Description |
|:---|:---|
| 🔍 **Passive Recon** | DNS hierarchies, CDN endpoints, SPF/DMARC mail safety |
| 🔐 **TLS Audit** | SSL certificate validity, issuer, expiry countdown |
| 📡 **Port Scanning** | Rate-limited (max 5 concurrent) banner grabbing on 11 standard ports |
| 🔒 **Security Headers** | Checks 7 critical HTTP headers (HSTS, CSP, X-Frame-Options, etc.) |
| 📊 **Risk Scoring** | CVSS-aligned 1.0-10.0 score with SECURE/NEEDS ATTENTION/VULNERABLE posture |
| 📝 **Executive Reports** | Auto-generated Markdown reports with findings & remediation checklist |

---

## 🛠️ MCP Tool Reference

| Tool | Description | Input |
|:---|:---|:---|
| `osint_passive_recon` | DNS + SSL reconnaissance on target | `target: str` |
| `audit_ports_services` | Scan exposed ports with banner grabbing | `target: str, ports: list[int]` |
| `run_full_autonomous_audit` | End-to-end audit with executive report | `target: str` |

---

## 📦 Installation & Integration

### With OpenWork (Recommended)
Add `cai-osint` to your `openwork.json` and sync across all IDEs:
```json
{
  "mcpServers": {
    "cai-osint": {
      "command": "python",
      "args": ["-m", "server"],
      "cwd": "path/to/cai-osint"
    }
  }
}
```
Then run:
```bash
npx @m4stanuj/openwork sync
```

### Manual Usage
```bash
# Clone the repository
git clone https://github.com/m4stanuj/cai-osint.git
cd cai-osint
pip install -r requirements.txt

# Run the live terminal demo
python demo_runner.py scanme.nmap.org

# Start the FastMCP server for IDEs
python server.py
```

---

## 💻 Visual Terminal Demo
Open `demo/demo_player.html` in your browser for a live 30-second animated simulation of the agent audit sequence.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and ethical scanning guidelines.

---

## 👤 Author & License
Crafted with 🛡️ by **Anuj ([@m4stanuj](https://github.com/m4stanuj))**  
Distributed under the **MIT License**.
