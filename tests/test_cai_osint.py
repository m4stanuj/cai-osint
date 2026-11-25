"""Unit tests for cai-osint scope guard and host normalization."""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server import audit_ports_services, clean_host, is_target_authorized


def test_clean_host_normalization():
    assert clean_host("https://Example.com:8443/path") == "example.com"
    assert clean_host("http://sub.domain.org/") == "sub.domain.org"


def test_scope_guard_blocks_unlisted_external_targets():
    os.environ.pop("CAI_AUTHORIZED_TARGETS", None)
    ok, _ = is_target_authorized("example.com", authorized=False)
    assert ok is False
    payload = json.loads(audit_ports_services("https://example.com"))
    assert payload["error"] == "SCOPE_DENIED"


def test_scope_guard_allows_loopback_and_allowlist(monkeypatch):
    ok_local, reason = is_target_authorized("127.0.0.1")
    assert ok_local is True
    assert reason == "local-loopback"

    monkeypatch.setenv("CAI_AUTHORIZED_TARGETS", "internal.corp")
    ok_sub, reason_sub = is_target_authorized("api.internal.corp")
    assert ok_sub is True
    assert reason_sub == "env-allowlist"
