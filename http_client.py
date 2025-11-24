"""
Shared HTTP client with retry/backoff for inter-service calls.
"""
import time
import random
import httpx
from typing import Any, Dict, Tuple, Optional
from unison_common.baton import get_current_baton

def http_post_json_with_retry(
    host: str,
    port: str,
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    timeout: float = 2.0,
) -> Tuple[bool, int, dict | None]:
    """
    POST JSON with exponential backoff and jitter.
    Returns (ok, status_code, parsed_json_body_or_None)
    """
    url = f"http://{host}:{port}{path}"
    merged_headers = {"Accept": "application/json"}
    baton = get_current_baton()
    if baton:
        merged_headers["X-Context-Baton"] = baton
    if headers:
        merged_headers.update(headers)
    attempt = 0
    last_exception: Exception | None = None
    while attempt <= max_retries:
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=payload, headers=merged_headers)
            parsed = None
            try:
                parsed = resp.json()
            except Exception:
                parsed = None
            return (resp.status_code >= 200 and resp.status_code < 300, resp.status_code, parsed)
        except Exception as e:
            last_exception = e
            if attempt == max_retries:
                break
            # exponential backoff with jitter
            delay = min(base_delay * (2 ** attempt) + random.uniform(0, 0.1), max_delay)
            time.sleep(delay)
            attempt += 1
    return (False, 0, None)

def http_get_json_with_retry(
    host: str,
    port: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    timeout: float = 2.0,
) -> Tuple[bool, int, dict | None]:
    """
    GET JSON with exponential backoff and jitter.
    Returns (ok, status_code, parsed_json_body_or_None)
    """
    url = f"http://{host}:{port}{path}"
    merged_headers = {"Accept": "application/json"}
    baton = get_current_baton()
    if baton:
        merged_headers["X-Context-Baton"] = baton
    if headers:
        merged_headers.update(headers)
    attempt = 0
    last_exception: Exception | None = None
    while attempt <= max_retries:
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url, headers=merged_headers)
            parsed = None
            try:
                parsed = resp.json()
            except Exception:
                parsed = None
            return (resp.status_code >= 200 and resp.status_code < 300, resp.status_code, parsed)
        except Exception as e:
            last_exception = e
            if attempt == max_retries:
                break
            delay = min(base_delay * (2 ** attempt) + random.uniform(0, 0.1), max_delay)
            time.sleep(delay)
            attempt += 1
    return (False, 0, None)

def http_put_json_with_retry(
    host: str,
    port: str,
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    timeout: float = 2.0,
) -> Tuple[bool, int, dict | None]:
    """
    PUT JSON with exponential backoff and jitter.
    Returns (ok, status_code, parsed_json_body_or_None)
    """
    url = f"http://{host}:{port}{path}"
    merged_headers = {"Accept": "application/json"}
    baton = get_current_baton()
    if baton:
        merged_headers["X-Context-Baton"] = baton
    if headers:
        merged_headers.update(headers)
    attempt = 0
    last_exception: Exception | None = None
    while attempt <= max_retries:
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.put(url, json=payload, headers=merged_headers)
            parsed = None
            try:
                parsed = resp.json()
            except Exception:
                parsed = None
            return (resp.status_code >= 200 and resp.status_code < 300, resp.status_code, parsed)
        except Exception as e:
            last_exception = e
            if attempt == max_retries:
                break
            delay = min(base_delay * (2 ** attempt) + random.uniform(0, 0.1), max_delay)
            time.sleep(delay)
            attempt += 1
    return (False, 0, None)
