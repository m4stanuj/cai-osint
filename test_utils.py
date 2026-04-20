"""
Tests for CAI-OSINT utilities
"""
from utils import sanitize_target, generate_report_filename, severity_color


def test_sanitize_target_strips_protocol():
    assert sanitize_target("https://example.com") == "example.com"
    assert sanitize_target("http://example.com/") == "example.com"
    assert sanitize_target("ftp://files.example.com/") == "files.example.com"


def test_sanitize_target_preserves_plain():
    assert sanitize_target("192.168.1.1") == "192.168.1.1"
    assert sanitize_target("example.com") == "example.com"


def test_report_filename_format():
    filename = generate_report_filename("example.com", "quick")
    assert filename.startswith("cai_report_example_com_quick_")
    assert filename.endswith(".md")


def test_severity_colors():
    assert severity_color("CRITICAL") == "\033[91m"
    assert severity_color("HIGH") == "\033[93m"
    assert severity_color("INFO") == "\033[90m"
    assert severity_color("UNKNOWN") == "\033[0m"
