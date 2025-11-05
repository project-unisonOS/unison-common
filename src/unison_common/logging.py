import logging
import json


def configure_logging(name: str):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    return logger


def log_json(level: int, event: str, **kwargs):
    payload = {"event": event, **kwargs}
    logging.log(level, json.dumps(payload))
