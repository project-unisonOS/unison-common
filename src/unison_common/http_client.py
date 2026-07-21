from typing import Dict, Tuple, Optional
import httpx
import os
import time
import logging
import random
import threading

JsonDict = dict

logger = logging.getLogger(__name__)

# Import tracing as a module so the optional fallback has one stable type.
try:
    from . import tracing as _tracing
except ImportError:
    _tracing = None  # type: ignore[assignment]

TRACING_AVAILABLE = _tracing is not None


_CLIENT_POOL: dict[tuple[str, float], httpx.Client] = {}
_CLIENT_POOL_LOCK = threading.Lock()


def _pool_enabled() -> bool:
    return os.getenv("UNISON_HTTP_CLIENT_POOL", "true").lower() in {"1", "true", "yes", "on"}


def _get_pooled_client(base_url: str, timeout: float) -> httpx.Client:
    """
    Return a reusable sync httpx.Client for a base URL.

    This reduces per-request connection setup overhead (DNS/TCP/TLS) and improves
    latency/throughput under load.
    """
    key = (base_url, float(timeout))
    with _CLIENT_POOL_LOCK:
        existing = _CLIENT_POOL.get(key)
        if existing is not None:
            return existing
        client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=100, keepalive_expiry=30.0),
            headers={"Connection": "keep-alive"},
        )
        _CLIENT_POOL[key] = client
        return client


def _inject_tracing_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Inject tracing headers into request headers"""
    if not headers:
        headers = {}
    # httpx requires header values to be non-None strings/bytes.
    headers = {k: str(v) for k, v in headers.items() if v is not None}
    
    if TRACING_AVAILABLE:
        assert _tracing is not None
        tracer = _tracing.get_tracer()
        if tracer:
            injected = tracer.inject_headers(headers)
            if isinstance(injected, dict):
                headers = injected
    
    return {k: str(v) for k, v in headers.items() if v is not None}


def _request_with_retry(
    method: str,
    host: str,
    port: str,
    path: str,
    payload: Optional[JsonDict] = None,
    headers: Optional[Dict[str, str]] = None,
    *,
    max_retries: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    timeout: float = 2.0,
    retry_on_status: Tuple[int, ...] = (500, 502, 503, 504),
    retry_on_exceptions: Tuple[type[BaseException], ...] = (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError),
) -> Tuple[bool, int, Optional[JsonDict]]:
    url = f"http://{host}:{port}{path}"
    base_url = f"http://{host}:{port}"
    attempt = 0
    last_status = 0
    last_body: Optional[JsonDict] = None
    start_time = time.time()
    
    # Inject tracing headers (preserved across retries)
    headers = _inject_tracing_headers(headers)
    
    # Log request attempt with tracing
    logger.info(f"HTTP {method} {url} attempt {attempt + 1}")
    
    while attempt <= max_retries:
        try:
            request_start = time.time()
            if _pool_enabled():
                client = _get_pooled_client(base_url, timeout=timeout)
                if method == "GET":
                    r = client.get(path, headers=headers)
                elif method == "POST":
                    r = client.post(path, headers=headers, json=payload)
                elif method == "PUT":
                    r = client.put(path, headers=headers, json=payload)
                else:
                    raise ValueError(f"Unsupported method: {method}")
            else:
                with httpx.Client(timeout=timeout) as client:
                    if method == "GET":
                        r = client.get(url, headers=headers)
                    elif method == "POST":
                        r = client.post(url, headers=headers, json=payload)
                    elif method == "PUT":
                        r = client.put(url, headers=headers, json=payload)
                    else:
                        raise ValueError(f"Unsupported method: {method}")
            
            request_duration = (time.time() - request_start) * 1000  # Convert to ms
            
            last_status = r.status_code
            try:
                last_body = r.json()
            except Exception:
                last_body = None
            
            # Trace the HTTP request
            if TRACING_AVAILABLE:
                assert _tracing is not None
                _tracing.trace_http_request(method, url, r.status_code, request_duration, headers)
                
                # Trace service call
                service_name = f"{host}:{port}"
                operation = f"{method} {path}"
                success = 200 <= r.status_code < 300
                error = None if success else f"HTTP {r.status_code}"
                _tracing.trace_service_call(service_name, operation, request_duration, success, error)
            
            if 200 <= r.status_code < 300:
                total_duration = (time.time() - start_time) * 1000
                logger.info(f"HTTP {method} {url} success in {total_duration:.2f}ms")
                return True, r.status_code, last_body
            # Non-2xx: decide if retryable
            if r.status_code not in retry_on_status:
                break

        except retry_on_exceptions as e:
            request_duration = (time.time() - request_start) * 1000
            logger.warning(f"HTTP {method} {url} attempt {attempt + 1} failed: {e}")
            
            # Trace failed request
            if TRACING_AVAILABLE:
                assert _tracing is not None
                _tracing.trace_http_request(method, url, 0, request_duration, headers)
                _tracing.trace_service_call(f"{host}:{port}", f"{method} {path}", request_duration, False, str(e))
        except Exception as e:
            # Non-retryable exception
            logger.error(f"HTTP {method} {url} non-retryable error: {e}")
            break
        
        if attempt == max_retries:
            break
        
        # Exponential backoff with jitter
        backoff = base_delay * (2 ** attempt)
        sleep_for = min(max_delay, backoff + random.uniform(0, base_delay))
        time.sleep(sleep_for)
        attempt += 1
    
    total_duration = (time.time() - start_time) * 1000
    logger.error(f"HTTP {method} {url} failed after {attempt} attempts in {total_duration:.2f}ms")
    return False, last_status, last_body


def http_get_json_with_retry(host: str, port: str, path: str, *, headers: Optional[Dict[str, str]] = None,
                              max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 2.0,
                              timeout: float = 2.0) -> Tuple[bool, int, Optional[JsonDict]]:
    return _request_with_retry('GET', host, port, path, None, headers, max_retries=max_retries,
                               base_delay=base_delay, max_delay=max_delay, timeout=timeout)


def http_post_json_with_retry(host: str, port: str, path: str, payload: JsonDict, *, headers: Optional[Dict[str, str]] = None,
                               max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 2.0,
                               timeout: float = 2.0) -> Tuple[bool, int, Optional[JsonDict]]:
    return _request_with_retry('POST', host, port, path, payload, headers, max_retries=max_retries,
                               base_delay=base_delay, max_delay=max_delay, timeout=timeout)


def http_put_json_with_retry(host: str, port: str, path: str, payload: JsonDict, *, headers: Optional[Dict[str, str]] = None,
                              max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 2.0,
                              timeout: float = 2.0) -> Tuple[bool, int, Optional[JsonDict]]:
    return _request_with_retry('PUT', host, port, path, payload, headers, max_retries=max_retries,
                               base_delay=base_delay, max_delay=max_delay, timeout=timeout)
