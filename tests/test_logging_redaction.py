import json
import logging
import pytest
from unison_common.logging import log_json, configure_logging


def get_last_log_json(caplog):
    for rec in reversed(caplog.records):
        try:
            return json.loads(rec.getMessage())
        except Exception:
            continue
    return {}


def test_redacts_sensitive_keys_and_values(caplog):
    caplog.set_level(logging.INFO)
    configure_logging("test")

    log_json(logging.INFO, "evt", 
             authorization="Bearer xyz.abc.def",
             api_key="secretkey",
             nested={"password": "123", "email": "user@example.com"},
             email="another@example.com",
             msg="token bearer ABC.D.E")

    payload = get_last_log_json(caplog)
    assert payload["authorization"] == "[REDACTED]"
    assert payload["api_key"] == "[REDACTED]"
    assert payload["nested"]["password"] == "[REDACTED]"
    assert payload["nested"]["email"] == "[REDACTED_EMAIL]"
    assert payload["email"] == "[REDACTED_EMAIL]"
    assert payload["msg"] == "[REDACTED]"
