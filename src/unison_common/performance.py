"""
Performance optimization utilities for Unison platform (M5.4)

Includes:
- HTTP connection pooling
- Redis connection pooling
- Response caching
- Rate limiting
"""

import asyncio
import time
import httpx
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# HTTP Connection Pooling (M5.4)
# ============================================================================

class HTTPConnectionPool:
    """
    Singleton HTTP connection pool for reusing connections.
    Significantly improves performance by avoiding connection overhead.
    """
    _instance = None
    _client: Optional[httpx.AsyncClient] = None
    _sync_client: Optional[httpx.Client] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            # Configure connection pool limits
            limits = httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30.0
            )
            
            # Async client for async operations
            self._client = httpx.AsyncClient(
                limits=limits,
                timeout=httpx.Timeout(10.0, connect=5.0),
                http2=True  # Enable HTTP/2 for better performance
            )
            
            # Sync client for synchronous operations
            self._sync_client = httpx.Client(
                limits=limits,
                timeout=httpx.Timeout(10.0, connect=5.0),
                http2=True
            )
            
            logger.info("HTTP connection pool initialized (max_connections=100)")
    
    @property
    def async_client(self) -> httpx.AsyncClient:
        """Get async HTTP client"""
        if self._client is None:
            self.__init__()
        return self._client
    
    @property
    def sync_client(self) -> httpx.Client:
        """Get sync HTTP client"""
        if self._sync_client is None:
            self.__init__()
        return self._sync_client
    
    async def close(self):
        """Close all connections"""
        if self._client:
            await self._client.aclose()
        if self._sync_client:
            self._sync_client.close()
        logger.info("HTTP connection pool closed")


# Global connection pool instance
_http_pool = HTTPConnectionPool()


def get_http_client() -> httpx.AsyncClient:
    """Get the global async HTTP client with connection pooling"""
    return _http_pool.async_client


def get_sync_http_client() -> httpx.Client:
    """Get the global sync HTTP client with connection pooling"""
    return _http_pool.sync_client


# ============================================================================
# Response Caching (M5.4)
# ============================================================================

class ResponseCache:
    """
    In-memory response cache with TTL support.
    Reduces load on downstream services by caching responses.
    """
    
    def __init__(self, default_ttl: int = 300):
        """
        Initialize cache
        
        Args:
            default_ttl: Default time-to-live in seconds (default: 5 minutes)
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        if key not in self._cache:
            self._misses += 1
            return None
        
        entry = self._cache[key]
        
        # Check if expired
        if datetime.now() > entry["expires_at"]:
            del self._cache[key]
            self._misses += 1
            return None
        
        self._hits += 1
        logger.debug(f"Cache hit: {key}")
        return entry["value"]
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        ttl = ttl if ttl is not None else self._default_ttl
        
        self._cache[key] = {
            "value": value,
            "expires_at": datetime.now() + timedelta(seconds=ttl),
            "created_at": datetime.now()
        }
        
        logger.debug(f"Cache set: {key} (TTL: {ttl}s)")
    
    def delete(self, key: str):
        """Delete key from cache"""
        if key in self._cache:
            del self._cache[key]
            logger.debug(f"Cache delete: {key}")
    
    def clear(self):
        """Clear all cache entries"""
        count = len(self._cache)
        self._cache.clear()
        self._hits = 0
        self._misses = 0
        logger.info(f"Cache cleared ({count} entries)")
    
    def cleanup_expired(self):
        """Remove expired entries from cache"""
        now = datetime.now()
        expired_keys = [
            key for key, entry in self._cache.items()
            if now > entry["expires_at"]
        ]
        
        for key in expired_keys:
            del self._cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self._hits + self._misses
        hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "entries": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(hit_rate, 2),
            "total_requests": total_requests
        }


# Global cache instances
_auth_cache = ResponseCache(default_ttl=300)  # 5 minutes
_policy_cache = ResponseCache(default_ttl=60)  # 1 minute


def get_auth_cache() -> ResponseCache:
    """Get the global auth response cache"""
    return _auth_cache


def get_policy_cache() -> ResponseCache:
    """Get the global policy response cache"""
    return _policy_cache


# ============================================================================
# Caching Decorators (M5.4)
# ============================================================================

def cached(cache: ResponseCache, ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    """
    Decorator to cache function results
    
    Args:
        cache: Cache instance to use
        ttl: Time-to-live in seconds
        key_func: Function to generate cache key from args/kwargs
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get from cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call function and cache result
            result = await func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get from cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            
            return result
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# ============================================================================
# Rate Limiting (M5.4)
# ============================================================================

class RateLimiter:
    """
    Token bucket rate limiter for API endpoints.
    Prevents abuse and ensures fair resource usage.
    """
    
    def __init__(self, rate: int, per: int):
        """
        Initialize rate limiter
        
        Args:
            rate: Number of requests allowed
            per: Time period in seconds
        """
        self.rate = rate
        self.per = per
        self._buckets: Dict[str, Dict[str, Any]] = {}
    
    def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed
        
        Args:
            key: Identifier for rate limiting (e.g., user_id, IP)
            
        Returns:
            True if request is allowed, False otherwise
        """
        now = time.time()
        
        # Initialize bucket if not exists
        if key not in self._buckets:
            self._buckets[key] = {
                "tokens": self.rate,
                "last_update": now
            }
        
        bucket = self._buckets[key]
        
        # Refill tokens based on time elapsed
        time_passed = now - bucket["last_update"]
        tokens_to_add = time_passed * (self.rate / self.per)
        bucket["tokens"] = min(self.rate, bucket["tokens"] + tokens_to_add)
        bucket["last_update"] = now
        
        # Check if request is allowed
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        
        logger.warning(f"Rate limit exceeded for key: {key}")
        return False
    
    def reset(self, key: str):
        """Reset rate limit for a key"""
        if key in self._buckets:
            del self._buckets[key]
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests for a key"""
        if key not in self._buckets:
            return self.rate
        return int(self._buckets[key]["tokens"])


# Global rate limiters
_user_rate_limiter = RateLimiter(rate=100, per=60)  # 100 requests per minute
_endpoint_rate_limiter = RateLimiter(rate=1000, per=60)  # 1000 requests per minute per endpoint


def get_user_rate_limiter() -> RateLimiter:
    """Get the global user rate limiter"""
    return _user_rate_limiter


def get_endpoint_rate_limiter() -> RateLimiter:
    """Get the global endpoint rate limiter"""
    return _endpoint_rate_limiter


# ============================================================================
# Performance Monitoring (M5.4)
# ============================================================================

class PerformanceMonitor:
    """Track performance metrics for optimization"""
    
    def __init__(self):
        self._metrics: Dict[str, list] = {}
    
    def record(self, metric_name: str, value: float):
        """Record a performance metric"""
        if metric_name not in self._metrics:
            self._metrics[metric_name] = []
        
        self._metrics[metric_name].append({
            "value": value,
            "timestamp": datetime.now()
        })
        
        # Keep only last 1000 entries per metric
        if len(self._metrics[metric_name]) > 1000:
            self._metrics[metric_name] = self._metrics[metric_name][-1000:]
    
    def get_stats(self, metric_name: str) -> Dict[str, float]:
        """Get statistics for a metric"""
        if metric_name not in self._metrics or not self._metrics[metric_name]:
            return {}
        
        values = [m["value"] for m in self._metrics[metric_name]]
        values.sort()
        
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "p50": values[len(values) // 2],
            "p95": values[int(len(values) * 0.95)],
            "p99": values[int(len(values) * 0.99)]
        }
    
    def get_all_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all metrics"""
        return {
            metric_name: self.get_stats(metric_name)
            for metric_name in self._metrics.keys()
        }


# Global performance monitor
_perf_monitor = PerformanceMonitor()


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor"""
    return _perf_monitor
