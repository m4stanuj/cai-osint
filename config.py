"""
CAI-OSINT Configuration
"""
import os

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "nmap_flags": "-sV -T4 --top-ports 100",
        "nuclei_severity": "critical,high",
        "timeout": 120,
    },
    "standard": {
        "nmap_flags": "-sV -sC -T3 -p-",
        "nuclei_severity": "critical,high,medium",
        "timeout": 600,
    },
    "full": {
        "nmap_flags": "-sV -sC -A -T3 -p-",
        "nuclei_severity": "critical,high,medium,low",
        "timeout": 1800,
    },
    "stealth": {
        "nmap_flags": "-sS -T2 --top-ports 1000 --randomize-hosts",
        "nuclei_severity": "critical,high",
        "timeout": 900,
    },
}

# Report settings
REPORT_DIR = os.getenv("CAI_REPORT_DIR", "./reports")
REPORT_FORMAT = os.getenv("CAI_REPORT_FORMAT", "markdown")  # markdown | pdf | json

# AI Analysis
AI_MODEL = os.getenv("CAI_AI_MODEL", "deepseek-reasoner")
AI_PROVIDER = os.getenv("CAI_AI_PROVIDER", "deepseek")
FALSE_POSITIVE_THRESHOLD = 0.75  # Confidence below this = likely false positive

# Tool paths (auto-detect)
NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
NUCLEI_PATH = os.getenv("NUCLEI_PATH", "nuclei")
SUBFINDER_PATH = os.getenv("SUBFINDER_PATH", "subfinder")
