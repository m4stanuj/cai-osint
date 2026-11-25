import json
import os

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from mcp.server.mcpserver import MCPServer as FastMCP
    except (ImportError, ModuleNotFoundError):
        from mcp.server import FastMCP

from app.recon import OSINTReconEngine
from app.report import generate_markdown_report

mcp = FastMCP("cai-osint")
engine = OSINTReconEngine(timeout=3.0)


def clean_host(target: str) -> str:
    """Normalize URL/host string into a bare hostname."""
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
        .strip()
        .lower()
    )


def is_target_authorized(host: str, authorized: bool = False) -> tuple[bool, str]:
    """
    Enforce explicit target scope verification before running active network probes.
    Allows localhost/127.0.0.1, targets listed in CAI_AUTHORIZED_TARGETS, or explicit
    `authorized=True` attestation.
    """
    if not host:
        return False, "Empty target host."
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True, "local-loopback"
    allowlist_raw = os.environ.get("CAI_AUTHORIZED_TARGETS", "")
    allowlist = {t.strip().lower() for t in allowlist_raw.split(",") if t.strip()}
    if host in allowlist or any(host.endswith(f".{dom}") for dom in allowlist):
        return True, "env-allowlist"
    if authorized:
        return True, "explicit-attestation"
    return (
        False,
        (
            f"Blocked active probe against '{host}'. Add '{host}' to CAI_AUTHORIZED_TARGETS "
            "or pass authorized=True confirming written scan permission."
        ),
    )


@mcp.tool()
def osint_passive_recon(target: str) -> str:
    """
    Perform passive OSINT reconnaissance on a target domain/IP.
    Collects DNS A/MX/aliases and SSL/TLS certificate validity.
    """
    host = clean_host(target)
    dns_res = engine.resolve_dns_and_host(host)
    ssl_res = engine.inspect_ssl_tls(host)
    return json.dumps({"target": host, "dns": dns_res, "ssl": ssl_res}, indent=2)


@mcp.tool()
def audit_ports_services(
    target: str, ports: list[int] | None = None, authorized: bool = False
) -> str:
    """
    Safely audit exposed perimeter ports and grab service banners after scope check.
    """
    host = clean_host(target)
    ok, reason = is_target_authorized(host, authorized=authorized)
    if not ok:
        return json.dumps({"error": "SCOPE_DENIED", "detail": reason}, indent=2)
    services = engine.probe_services(host, ports)
    return json.dumps(
        {"target": host, "scope": reason, "open_services": services}, indent=2
    )


@mcp.tool()
def run_full_autonomous_audit(target: str, authorized: bool = False) -> str:
    """
    Run an end-to-end scope-checked OSINT and perimeter security audit.
    Generates an executive risk score and complete markdown vulnerability report.
    """
    host = clean_host(target)
    ok, reason = is_target_authorized(host, authorized=authorized)
    if not ok:
        return json.dumps({"error": "SCOPE_DENIED", "detail": reason}, indent=2)

    dns_res = engine.resolve_dns_and_host(host)
    ssl_res = engine.inspect_ssl_tls(host)
    services = engine.probe_services(host)
    headers_res = engine.check_security_headers(host)
    posture = engine.evaluate_posture(host, dns_res, ssl_res, services, headers_res)

    report_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, f"audit_{host.replace('.', '_')}.md")
    report_md = generate_markdown_report(posture, report_file)

    return json.dumps(
        {
            "target": host,
            "scope": reason,
            "security_score": posture["security_score"],
            "posture": posture["posture"],
            "findings_count": len(posture["findings"]),
            "report_saved_to": report_file,
            "report_preview": report_md[:600] + "\n...[Report truncated for preview]...",
        },
        indent=2,
    )


if __name__ == "__main__":
    mcp.run()
