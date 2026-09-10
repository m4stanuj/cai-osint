import os
import json
import sys
from mcp.server.fastmcp import FastMCP
from app.recon import OSINTReconEngine
from app.report import generate_markdown_report

# Initialize FastMCP Server
mcp = FastMCP("cai-osint")
engine = OSINTReconEngine(timeout=3.0)

@mcp.tool()
def osint_passive_recon(target: str) -> str:
    """
    Perform passive OSINT reconnaissance on a target domain/IP.
    Collects DNS A/MX/aliases and SSL/TLS certificate validity.
    """
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
    dns_res = engine.resolve_dns_and_host(clean_target)
    ssl_res = engine.inspect_ssl_tls(clean_target)
    return json.dumps({
        "target": clean_target,
        "dns": dns_res,
        "ssl": ssl_res
    }, indent=2)

@mcp.tool()
def audit_ports_services(target: str, ports: list[int] = None) -> str:
    """
    Safely audit exposed perimeter ports and grab service banners.
    Identifies risky services like exposed databases or unencrypted protocols.
    """
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
    services = engine.probe_services(clean_target, ports)
    return json.dumps({
        "target": clean_target,
        "open_services": services
    }, indent=2)

@mcp.tool()
def run_full_autonomous_audit(target: str) -> str:
    """
    Run an end-to-end autonomous OSINT and perimeter security audit.
    Generates an executive risk score and complete markdown vulnerability report.
    """
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
    dns_res = engine.resolve_dns_and_host(clean_target)
    ssl_res = engine.inspect_ssl_tls(clean_target)
    services = engine.probe_services(clean_target)
    posture = engine.evaluate_posture(clean_target, dns_res, ssl_res, services)

    # Generate Markdown report
    report_file = os.path.join(os.path.dirname(__file__), "reports", f"audit_{clean_target.replace('.', '_')}.md")
    report_md = generate_markdown_report(posture, report_file)

    return json.dumps({
        "target": clean_target,
        "security_score": posture["security_score"],
        "posture": posture["posture"],
        "findings_count": len(posture["findings"]),
        "report_saved_to": report_file,
        "report_preview": report_md[:600] + "\n...[Report truncated for preview]..."
    }, indent=2)

if __name__ == "__main__":
    mcp.run()
