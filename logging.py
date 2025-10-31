"""
Shared JSON logging utilities for Unison services.
Ensures consistent schema: ts, service, message, event_id?, level?, extra fields.
"""
import json
import logging
import time
from typing import Any

def log_json(logger: logging.Logger, level: int, message: str, service: str, event_id: str | None = None, **fields: Any) -> None:
    """
    Emit a structured JSON log line.
    - ts: epoch seconds
    - service: service name
    - message: free-form message
    - event_id: optional correlation ID
    - level: string name of level
    - any additional fields are merged at top level
    """
    record = {
        "ts": time.time(),
        "service": service,
        "message": message,
        "level": logging.getLevelName(level),
    }
    if event_id is not None:
        record["event_id"] = event_id
    record.update(fields)
    logger.log(level, json.dumps(record, separators=(",", ":")))

def configure_logging(service_name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Configure a logger with JSON formatting.
    Returns a logger instance ready for log_json calls.
    """
    logger = logging.getLogger(service_name)
    if not logger.handlers:
        logging.basicConfig(level=level)
    return logger
