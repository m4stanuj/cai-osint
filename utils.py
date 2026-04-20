"""
CAI-OSINT Utilities
Common helper functions used across the framework.
"""
import json
import os
from datetime import datetime


def sanitize_target(target: str) -> str:
    """Strip protocol and trailing slashes from target."""
    target = target.strip()
    for prefix in ("https://", "http://", "ftp://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.rstrip("/")


def generate_report_filename(target: str, scan_type: str = "full") -> str:
    """Generate timestamped report filename."""
    safe_target = target.replace(".", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"cai_report_{safe_target}_{scan_type}_{timestamp}.md"


def severity_color(severity: str) -> str:
    """Return ANSI color code for severity level."""
    colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[96m",       # Cyan
        "INFO": "\033[90m",      # Gray
    }
    return colors.get(severity.upper(), "\033[0m")


def load_previous_findings(target: str, findings_dir: str = "./findings") -> list:
    """Load previous scan findings for correlation."""
    safe_target = target.replace(".", "_")
    findings_path = os.path.join(findings_dir, f"{safe_target}.json")
    if os.path.exists(findings_path):
        with open(findings_path, "r") as f:
            return json.load(f)
    return []


def save_findings(target: str, findings: list, findings_dir: str = "./findings"):
    """Persist scan findings for cross-session correlation."""
    os.makedirs(findings_dir, exist_ok=True)
    safe_target = target.replace(".", "_")
    findings_path = os.path.join(findings_dir, f"{safe_target}.json")
    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)
