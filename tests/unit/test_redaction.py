from cyberguard.core.redaction import redact


def test_redacts_sensitive_keys_and_values():
    result = redact({"token": "abc", "message": "password=hunter2", "nested": {"ok": "value"}})
    assert result["token"] == "[REDACTED]"
    assert "hunter2" not in result["message"]
    assert result["nested"]["ok"] == "value"
