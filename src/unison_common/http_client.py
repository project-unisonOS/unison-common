from typing import Dict, Tuple, Optional
import httpx
import time
import logging

JsonDict = dict

logger = logging.getLogger(__name__)

# Import tracing functions with fallback for when not available
try:
    from .tracing import get_tracer, trace_http_request, trace_service_call
    TRACING_AVAILABLE = True
except ImportError:
    TRACING_AVAILABLE = False
    
    def get_tracer():
        return None
    
    def trace_http_request(*args, **kwargs):
        pass
    
    def trace_service_call(*args, **kwargs):
        pass


def _inject_tracing_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Inject tracing headers into request headers"""
    if not headers:
        headers = {}
    
    if TRACING_AVAILABLE:
        tracer = get_tracer()
        if tracer:
            return tracer.inject_headers(headers)
    
    return headers


def _request_with_retry(method: str, host: str, port: str, path: str, payload: Optional[JsonDict] = None,
                         headers: Optional[Dict[str, str]] = None, *,
                         max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 2.0,
                         timeout: float = 2.0) -> Tuple[bool, int, Optional[JsonDict]]:
    url = f"http://{host}:{port}{path}"
    attempt = 0
    last_status = 0
    last_body: Optional[JsonDict] = None
    start_time = time.time()
    
    # Inject tracing headers
    headers = _inject_tracing_headers(headers)
    
    # Log request attempt with tracing
    logger.info(f"HTTP {method} {url} attempt {attempt + 1}")
    
    while attempt <= max_retries:
        try:
            request_start = time.time()
            with httpx.Client(timeout=timeout) as client:
                if method == 'GET':
                    r = client.get(url, headers=headers)
                elif method == 'POST':
                    r = client.post(url, headers=headers, json=payload)
                elif method == 'PUT':
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
                trace_http_request(method, url, r.status_code, request_duration, headers)
                
                # Trace service call
                service_name = f"{host}:{port}"
                operation = f"{method} {path}"
                success = 200 <= r.status_code < 300
                error = None if success else f"HTTP {r.status_code}"
                trace_service_call(service_name, operation, request_duration, success, error)
            
            if 200 <= r.status_code < 300:
                total_duration = (time.time() - start_time) * 1000
                logger.info(f"HTTP {method} {url} success in {total_duration:.2f}ms")
                return True, r.status_code, last_body
                
        except Exception as e:
            request_duration = (time.time() - request_start) * 1000
            logger.warning(f"HTTP {method} {url} attempt {attempt + 1} failed: {e}")
            
            # Trace failed request
            if TRACING_AVAILABLE:
                trace_http_request(method, url, 0, request_duration, headers)
                trace_service_call(f"{host}:{port}", f"{method} {path}", request_duration, False, str(e))
        
        if attempt == max_retries:
            break
        
        sleep_for = min(max_delay, base_delay * (2 ** attempt))
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
