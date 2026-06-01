# M4ST Defensive OSINT Workflow

Authorized OSINT and defensive security workflow by Mast Anuj.

This project helps collect public evidence, map exposed services, organize findings, and generate reports for owned or explicitly approved targets.

## What It Does

- public-domain and infrastructure discovery
- subdomain and service enumeration
- Nmap-assisted port checks for approved targets
- Shodan-assisted exposure review
- Nuclei-assisted template checks where authorized
- CVE and remediation notes
- Markdown report generation
- false-positive review support

## Workflow

```text
approved target -> public evidence -> scoped checks -> finding review -> report -> remediation notes
```

## Tools

| Tool | Purpose |
|---|---|
| Nmap | port and service checks for approved targets |
| Shodan | public exposure review |
| Nuclei | template-based checks where authorized |
| Subfinder | subdomain discovery |
| CVE sources | vulnerability reference lookup |

## Legal And Ethical Boundary

Use only for:

- your own systems
- written-permission assessments
- CTF/lab environments
- authorized bug bounty scope
- defensive research

Do not use this project for unauthorized scanning, exploitation, stealth, credential abuse, malware, or bypassing protections.

## M4ST Fit

This is part of the M4ST local-first operator ecosystem and should stay scoped, logged, evidence-based, and human-approved for sensitive steps.
