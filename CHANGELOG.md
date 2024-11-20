# Changelog

All notable changes to CAI-OSINT are documented here.

## [2.1.0] — 2026-04-10

### Added
- **AI-powered false positive filtering** — DeepSeek-R1 analyzes Nuclei results to reduce noise by ~60%
- Automated attack surface prioritization with CVSS v3 scoring
- PDF report generation with executive summary section

### Fixed
- Subfinder timing out on domains with >500 subdomains
- Nmap OS detection failing on hardened firewalls

## [2.0.0] — 2026-01-20

### Added
- **Full MCP integration** — operates as native M4STCLAW pentest server
- Session-based workflow: `session_start → recon → enum → vuln → report → session_end`
- Cross-session memory — findings persist and correlate across engagements
- Nuclei template auto-update from ProjectDiscovery feed

### Changed
- Migrated from standalone script to MCP server architecture
- Replaced manual OSINT workflow with autonomous pipeline

### Breaking Changes
- CLI interface removed — now operates via MCP tool calls
- Output format changed from JSON to structured Markdown

## [1.3.0] — 2025-09-12

### Added
- Shodan API integration for passive reconnaissance
- CVE database lookups via NIST NVD API
- WHOIS and DNS intelligence gathering

## [1.2.0] — 2025-06-01

### Added
- Nuclei integration with 8,000+ CVE templates
- Service fingerprinting and banner grabbing
- Severity scoring with color-coded output

## [1.1.0] — 2025-03-15

### Added
- Nmap integration with intelligent port scanning
- OS detection and service version enumeration
- Scan profile presets (quick, vuln, full, udp)

## [1.0.0] — 2024-11-20

### Added
- Initial release — basic OSINT reconnaissance tool
- Subfinder integration for subdomain enumeration
- Manual target profiling workflow
