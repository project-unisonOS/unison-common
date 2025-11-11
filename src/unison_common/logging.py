import logging
import json
from opentelemetry import trace
import re


def configure_logging(name: str):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    return logger


def _get_trace_fields() -> dict:
    """Extract standard trace fields from current OpenTelemetry span."""
    fields = {}
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx and ctx.is_valid:
            trace_id_hex = format(ctx.trace_id, '032x')
            span_id_hex = format(ctx.span_id, '016x')
            trace_flags = format(ctx.trace_flags, '02x')

            # Standardized fields
            fields.setdefault("request_id", trace_id_hex)
            fields.setdefault("trace_id", trace_id_hex)
            fields.setdefault("span_id", span_id_hex)
            fields.setdefault("traceparent", f"00-{trace_id_hex}-{span_id_hex}-{trace_flags}")
    except Exception:
        # Best-effort enrichment; ignore errors
        pass
    return fields


def log_json(level: int, event: str, **kwargs):
    # Auto-enrich with trace fields unless explicitly provided
    trace_fields = _get_trace_fields()
    for k, v in trace_fields.items():
        kwargs.setdefault(k, v)
    def _scrub_value(v):
        if isinstance(v, str):
            if re.search(r"bearer\s+[A-Za-z0-9._\-]+", v, re.IGNORECASE):
                return "[REDACTED]"
            if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", v):
                return "[REDACTED_EMAIL]"
        return v
    SENSITIVE_KEYS = {
        "authorization",
        "proxy-authorization",
        "api_key",
        "apikey",
        "api-key",
        "password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "set-cookie",
        "cookie",
    }
    def _scrub(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                key_lower = str(k).lower()
                if key_lower in SENSITIVE_KEYS:
                    out[k] = "[REDACTED]"
                else:
                    out[k] = _scrub(v)
            return out
        elif isinstance(obj, list):
            return [_scrub(i) for i in obj]
        else:
            return _scrub_value(obj)
    payload = _scrub({"event": event, **kwargs})
    logging.log(level, json.dumps(payload))
