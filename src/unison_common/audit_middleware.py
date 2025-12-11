"""
Audit/logging middleware for FastAPI services.
Emits minimal structured logs and redacts sensitive headers.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Iterable, Mapping

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from unison_common.logging import log_json

REDACT_HEADERS = {"authorization", "cookie", "x-api-key"}


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, service_name: str, allow_client_ip: bool = False):
        super().__init__(app)
        self.service_name = service_name
        self.allow_client_ip = allow_client_ip
        self.logger = logging.getLogger(service_name)

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id")
        headers = _filter_headers(request.headers)
        client_ip = request.client.host if (self.allow_client_ip and request.client) else None
        start = datetime.utcnow()
        try:
            response: Response = await call_next(request)
            status = response.status_code
            outcome = "success" if status < 400 else "error"
        except Exception as exc:  # pragma: no cover
            status = 500
            outcome = "error"
            response = Response(status_code=500)
            log_json(
                self.logger,
                logging.ERROR,
                "request failed",
                service=self.service_name,
                event="http.request",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status=status,
                outcome=outcome,
                client_ip=client_ip,
                headers=headers,
                error=str(exc),
                ts=start.isoformat() + "Z",
            )
            raise

        log_json(
            self.logger,
            logging.INFO,
            "request completed",
            service=self.service_name,
            event="http.request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=status,
            outcome=outcome,
            client_ip=client_ip,
            headers=headers,
            ts=start.isoformat() + "Z",
        )
        return response


def _filter_headers(headers: Mapping[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in REDACT_HEADERS:
            continue
        clean[k] = v
    return clean
