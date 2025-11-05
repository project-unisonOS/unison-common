from typing import Dict, Tuple, Optional
import httpx
import time

JsonDict = dict


def _request_with_retry(method: str, host: str, port: str, path: str, payload: Optional[JsonDict] = None,
                         headers: Optional[Dict[str, str]] = None, *,
                         max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 2.0,
                         timeout: float = 2.0) -> Tuple[bool, int, Optional[JsonDict]]:
    url = f"http://{host}:{port}{path}"
    attempt = 0
    last_status = 0
    last_body: Optional[JsonDict] = None
    while attempt <= max_retries:
        try:
            with httpx.Client(timeout=timeout) as client:
                if method == 'GET':
                    r = client.get(url, headers=headers)
                elif method == 'POST':
                    r = client.post(url, headers=headers, json=payload)
                elif method == 'PUT':
                    r = client.put(url, headers=headers, json=payload)
                else:
                    raise ValueError(f"Unsupported method: {method}")
            last_status = r.status_code
            try:
                last_body = r.json()
            except Exception:
                last_body = None
            if 200 <= r.status_code < 300:
                return True, r.status_code, last_body
        except Exception:
            # network error; will retry
            pass
        if attempt == max_retries:
            break
        sleep_for = min(max_delay, base_delay * (2 ** attempt))
        time.sleep(sleep_for)
        attempt += 1
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
