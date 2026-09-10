import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app.recon import OSINTReconEngine
from app.report import generate_markdown_report

def run_demo(target: str = "scanme.nmap.org"):
    print("""
\x1b[36m\x1b[1m
  ██████╗ █████╗ ██╗     ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔════╝██╔══██╗██║    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██║     ███████║██║    ██║   ██║███████╗██║██╔██╗ ██║   ██║   
 ██║     ██╔══██║██║    ██║   ██║╚════██║██║██║╚██╗██║   ██║   
 ╚██████╗██║  ██║██║    ╚██████╔╝███████║██║██║ ╚████║   ██║   
  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
\x1b[0m\x1b[90m  Autonomous AI OSINT & Security Assessment Engine via MCP\x1b[0m
\x1b[90m  ─────────────────────────────────────────────────────────────\x1b[0m
""")
    engine = OSINTReconEngine(timeout=2.5)

    print(f"\x1b[33m[1/4] 🔍 Initializing Passive OSINT on Target: \x1b[1m{target}\x1b[0m...")
    time.sleep(0.5)
    dns_data = engine.resolve_dns_and_host(target)
    print(f"      ✔ Hostname: {dns_data.get('hostname')}")
    print(f"      ✔ Resolved IPs: {', '.join(dns_data.get('ip_addresses', []))}")

    print(f"\n\x1b[33m[2/4] 🔐 Inspecting SSL/TLS Encryption & Certificates...\x1b[0m")
    time.sleep(0.5)
    ssl_data = engine.inspect_ssl_tls(target, 443)
    if ssl_data.get("has_ssl"):
        print(f"      ✔ Issuer: {ssl_data.get('issuer')}")
        print(f"      ✔ Valid Until: {ssl_data.get('valid_until')} ({ssl_data.get('days_remaining')} days left)")
    else:
        print(f"      ⚠ No SSL/TLS detected on port 443.")

    print(f"\n\x1b[33m[3/5] 📡 Scanning Exposed Perimeter Services & Ports...\x1b[0m")
    time.sleep(0.5)
    # Quick probe on standard audit ports
    open_ports = engine.probe_services(target, ports=[21, 22, 25, 80, 443, 3306, 8080])
    for p in open_ports:
        print(f"      ✔ Open Port \x1b[32m{p['port']}\x1b[0m ({p['service']}) -> {p['banner']}")

    print(f"\n\x1b[33m[4/5] 🔒 Analyzing HTTP Security Headers...\x1b[0m")
    time.sleep(0.3)
    headers_data = engine.check_security_headers(target)
    if headers_data.get("checked"):
        present = headers_data.get("present", {})
        missing = headers_data.get("missing", [])
        for label in present:
            print(f"      ✔ {label}: Present")
        for label in missing:
            print(f"      ⚠ {label}: \x1b[33mMissing\x1b[0m")
    else:
        print(f"      ⚠ Could not check security headers.")

    print(f"\n\x1b[33m[5/5] 🧠 Synthesizing Posture & Generating Executive Audit Report...\x1b[0m")
    time.sleep(0.5)
    posture = engine.evaluate_posture(target, dns_data, ssl_data, open_ports, headers_data)

    report_path = os.path.join(os.path.dirname(__file__), "reports", f"audit_{target.replace('.', '_')}.md")
    generate_markdown_report(posture, report_path)

    score = posture['security_score']
    color = "\x1b[32m" if score >= 8.0 else "\x1b[33m" if score >= 6.0 else "\x1b[31m"
    print(f"\n\x1b[1m═══════════════════════════════════════════════════════════\x1b[0m")
    print(f"  TARGET: \x1b[1m{target}\x1b[0m")
    print(f"  OVERALL POSTURE: {color}\x1b[1m{posture['posture']}\x1b[0m")
    print(f"  SECURITY SCORE:  {color}\x1b[1m{score} / 10.0\x1b[0m")
    print(f"  FINDINGS COUNT:  {len(posture['findings'])} issues identified")
    print(f"  EXECUTIVE REPORT SAVED: \x1b[36m{report_path}\x1b[0m")
    print(f"\x1b[1m═══════════════════════════════════════════════════════════\x1b[0m\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    run_demo(target)
