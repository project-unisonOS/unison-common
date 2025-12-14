from unison_common.redaction import redact_obj, redact_text


def test_redact_text_redacts_bearer_and_jwt_and_email():
    assert redact_text("Bearer abc.def.ghi") == "[REDACTED]"
    assert redact_text("token abc.def.ghi") == "[REDACTED]"
    assert redact_text("email me at user@example.com") == "email me at [REDACTED_EMAIL]"


def test_redact_obj_redacts_sensitive_keys_recursively():
    out = redact_obj(
        {
            "authorization": "Bearer xyz",
            "nested": {"api_key": "secret", "email": "user@example.com"},
            "ok": True,
        }
    )
    assert out["authorization"] == "[REDACTED]"
    assert out["nested"]["api_key"] == "[REDACTED]"
    assert out["nested"]["email"] == "[REDACTED_EMAIL]"
    assert out["ok"] is True

