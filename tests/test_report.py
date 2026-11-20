from app.report import generate_markdown_report


def test_empty_report_does_not_claim_security_or_port_coverage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = generate_markdown_report({}, "assessment.md")
    assert (tmp_path / "assessment.md").read_text(encoding="utf-8") == report
    assert "Coverage may be incomplete" in report
    assert "No service observations supplied" in report
    assert "Security Score:** Not provided" in report


def test_report_preserves_severity_and_contains_untrusted_text():
    report = generate_markdown_report({
        "target": "fixture.invalid",
        "security_score": 6,
        "findings": [{"severity": "LOW", "title": "Fixture <tag>\n# heading"}],
        "open_services": [{"port": 443, "state": "open", "service": "https", "banner": "fixture | banner"}],
    })
    assert "LOW - Fixture &lt;tag&gt;" in report
    assert "6 / 10.0" in report
    assert r"fixture \| banner" in report
    assert "\n# heading" not in report
