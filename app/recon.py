import socket
import ssl
import time
import http.client
from datetime import datetime, timezone
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

COMMON_AUDIT_PORTS = [21, 22, 25, 53, 80, 443, 3306, 5432, 6379, 8080, 8443]

class OSINTReconEngine:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def resolve_dns_and_host(self, target: str) -> Dict[str, Any]:
        result = {
            "target": target,
            "ip_addresses": [],
            "hostname": "",
            "aliases": []
        }
        try:
            name, aliases, ip_list = socket.gethostbyname_ex(target)
            result["hostname"] = name
            result["aliases"] = aliases
            result["ip_addresses"] = ip_list
        except Exception as e:
            result["error"] = str(e)
        return result

    def inspect_ssl_tls(self, target: str, port: int = 443) -> Dict[str, Any]:
        cert_info = {
            "has_ssl": False,
            "issuer": {},
            "subject": {},
            "valid_from": None,
            "valid_until": None,
            "days_remaining": 0,
            "expired": False
        }
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cert_info["has_ssl"] = True

                    # Extract Issuer
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    cert_info["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

                    # Dates
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        cert_info["valid_until"] = exp_date.isoformat()
                        days_left = (exp_date - datetime.now(timezone.utc).replace(tzinfo=None)).days
                        cert_info["days_remaining"] = days_left
                        cert_info["expired"] = days_left <= 0
        except Exception as e:
            cert_info["error"] = str(e)
        return cert_info

    def probe_services(self, target: str, ports: List[int] = None, max_concurrent: int = 5) -> List[Dict[str, Any]]:
        target_ports = ports or COMMON_AUDIT_PORTS
        open_services = []

        def _probe_single_port(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                code = s.connect_ex((target, port))
                if code == 0:
                    banner = ""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(256).decode("utf-8", errors="ignore").strip().split("\n")[0]
                    except Exception:
                        pass
                    service_name = socket.getservbyport(port) if port <= 1024 else f"custom-{port}"
                    return {
                        "port": port,
                        "state": "open",
                        "service": service_name,
                        "banner": banner or "Banner suppressed"
                    }
            except Exception:
                pass
            finally:
                s.close()
            return None

        # Rate-limited concurrent scanning (max 5 connections at once)
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            results = executor.map(_probe_single_port, target_ports)
            for r in results:
                if r is not None:
                    open_services.append(r)

        return open_services

    def check_security_headers(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP response headers for security best practices."""
        EXPECTED_HEADERS = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "X-XSS-Protection": "XSS Filter",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy"
        }

        result = {
            "checked": False,
            "present": {},
            "missing": [],
            "score": 0
        }

        try:
            conn = http.client.HTTPSConnection(target, timeout=self.timeout)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()

            result["checked"] = True
            present_count = 0

            for header, label in EXPECTED_HEADERS.items():
                header_lower = header.lower()
                if header_lower in headers:
                    result["present"][label] = headers[header_lower]
                    present_count += 1
                else:
                    result["missing"].append(label)

            result["score"] = round(present_count / len(EXPECTED_HEADERS) * 10, 1)

        except Exception as e:
            result["error"] = str(e)

        return result

    def evaluate_posture(self, target: str, dns_data: dict, ssl_data: dict, open_ports: list, headers_data: dict = None) -> Dict[str, Any]:
        findings = []
        score = 9.8  # Start pristine, deduct for issues

        # Check SSL
        if not ssl_data.get("has_ssl"):
            findings.append({
                "severity": "HIGH",
                "title": "Missing SSL/TLS Certificate",
                "desc": "Port 443 is unreachable or not using valid TLS encryption.",
                "remediation": "Deploy a valid TLS certificate using Let's Encrypt or Cloudflare."
            })
            score -= 3.0
        elif ssl_data.get("expired"):
            findings.append({
                "severity": "CRITICAL",
                "title": "Expired SSL/TLS Certificate",
                "desc": f"The certificate has expired, exposing users to MITM risks.",
                "remediation": "Renew and rebind the TLS certificate immediately."
            })
            score -= 4.0
        elif ssl_data.get("days_remaining", 100) < 14:
            findings.append({
                "severity": "MEDIUM",
                "title": "Certificate Expiring Soon",
                "desc": f"Certificate expires in {ssl_data.get('days_remaining')} days.",
                "remediation": "Trigger automated ACME cert renewal."
            })
            score -= 1.0

        # Check dangerous open ports
        risky_ports = {
            21: ("HIGH", "Exposed FTP Service", "Unencrypted file transfer service exposed to internet."),
            23: ("CRITICAL", "Exposed Telnet Service", "Plaintext remote administration exposed."),
            3306: ("HIGH", "Public MySQL Database", "Direct database port exposed to public internet."),
            5432: ("HIGH", "Public PostgreSQL Database", "Direct database port exposed to public internet."),
            6379: ("CRITICAL", "Public Redis Cache", "Redis instance exposed without firewall boundary.")
        }

        for p in open_ports:
            port_num = p["port"]
            if port_num in risky_ports:
                sev, title, desc = risky_ports[port_num]
                findings.append({
                    "severity": sev,
                    "title": title,
                    "desc": f"{desc} (Port {port_num})",
                    "remediation": f"Block port {port_num} via Security Group / UFW firewall."
                })
                score -= 2.5

        # Check HTTP Security Headers
        if headers_data and headers_data.get("checked"):
            missing_headers = headers_data.get("missing", [])
            critical_missing = [h for h in missing_headers if h in ["HSTS", "CSP", "Clickjacking Protection"]]
            if len(critical_missing) > 0:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Missing Critical Security Headers",
                    "desc": f"Missing: {', '.join(critical_missing)}. These headers protect against common web attacks.",
                    "remediation": "Configure web server to send Strict-Transport-Security, Content-Security-Policy, and X-Frame-Options headers."
                })
                score -= min(1.5, len(critical_missing) * 0.5)
            if len(missing_headers) > 4:
                findings.append({
                    "severity": "LOW",
                    "title": "Weak HTTP Security Header Coverage",
                    "desc": f"Only {7 - len(missing_headers)}/7 recommended security headers are present.",
                    "remediation": "Review OWASP Secure Headers Project for recommended header configuration."
                })
                score -= 0.5

        final_score = max(1.0, min(10.0, round(score, 1)))
        posture = "SECURE" if final_score >= 8.5 else "NEEDS ATTENTION" if final_score >= 6.0 else "VULNERABLE"

        return {
            "target": target,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "security_score": final_score,
            "posture": posture,
            "findings": findings,
            "open_services": open_ports,
            "dns_summary": dns_data,
            "ssl_summary": ssl_data,
            "security_headers": headers_data or {}
        }
