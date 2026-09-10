# 🛡️ cai-osint

> **Autonomous AI OSINT & Security Assessment Engine via Model Context Protocol (MCP)**  
> Autonomous reconnaissance, SSL/TLS posture auditing, open service triage, and executive vulnerability reporting for AI agents (Cursor, Windsurf, Claude Desktop).

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Enabled-purple.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 💥 The Problem
Security analysts and bug bounty hunters waste hours manually jumping between `whois`, `dig`, `nmap`, and SSL certificate inspectors, and then even longer formatting markdown tables into client-ready executive reports.

Existing security MCP tools are mostly raw command wrappers that trigger agent hallucinations or get IP-blocked.

---

## 🚀 The Solution: `cai-osint`
`cai-osint` provides high-level **agentic workflows** directly to your AI assistant:
1. **Passive Reconnaissance:** Resolves DNS hierarchies, CDN endpoints, and SPF/DMARC mail safety.
2. **TLS & Cipher Audit:** Validates SSL/TLS certificates, expiry dates, and cipher suites on port 443.
3. **Safe Perimeter Probe:** Probes standard service ports with banner grabbing and strict timeout handling.
4. **Autonomous Executive Reporting:** Generates a structured CVSS-aligned security score, vulnerability breakdown, and remediation checklist in Markdown and HTML.

---

## 🛠️ Installation & Integration

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

# Run the live terminal demo
python demo_runner.py scanme.nmap.org

# Start the FastMCP server for IDEs
python server.py
```

---

## 💻 Visual Terminal Demo
Open `demo/demo_player.html` in your browser for a live 30-second animated simulation of the agent audit sequence.

---

## 👤 Author & License
Crafted with 🛡️ by **Anuj ([@m4stanuj](https://github.com/m4stanuj))**  
Distributed under the **MIT License**.
