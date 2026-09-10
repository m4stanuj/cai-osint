import socket
import ssl
import time
from datetime import datetime
from typing import Dict, Any, List

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
                        days_left = (exp_date - datetime.utcnow()).days
                        cert_info["days_remaining"] = days_left
                        cert_info["expired"] = days_left <= 0
        except Exception as e:
            cert_info["error"] = str(e)
        return cert_info

    def probe_services(self, target: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        target_ports = ports or COMMON_AUDIT_PORTS
        open_services = []

        for port in target_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                code = s.connect_ex((target, port))
                if code == 0:
                    # Attempt banner grab
                    banner = ""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(256).decode("utf-8", errors="ignore").strip().split("\n")[0]
                    except Exception:
                        pass

                    service_name = socket.getservbyport(port) if port <= 1024 else f"custom-{port}"
                    open_services.append({
                        "port": port,
                        "state": "open",
                        "service": service_name,
                        "banner": banner or "Banner suppressed"
                    })
            except Exception:
                pass
            finally:
                s.close()
        return open_services

    def evaluate_posture(self, target: str, dns_data: dict, ssl_data: dict, open_ports: list) -> Dict[str, Any]:
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

        final_score = max(1.0, min(10.0, round(score, 1)))
        posture = "SECURE" if final_score >= 8.5 else "NEEDS ATTENTION" if final_score >= 6.0 else "VULNERABLE"

        return {
            "target": target,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "security_score": final_score,
            "posture": posture,
            "findings": findings,
            "open_services": open_ports,
            "dns_summary": dns_data,
            "ssl_summary": ssl_data
        }
