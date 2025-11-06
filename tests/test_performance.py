"""
Unit tests for performance optimization utilities (M5.4)
"""

import pytest
import time
from datetime import datetime, timedelta

from unison_common.performance import (
    HTTPConnectionPool,
    get_http_client,
    get_sync_http_client,
    ResponseCache,
    get_auth_cache,
    get_policy_cache,
    RateLimiter,
    get_user_rate_limiter,
    get_endpoint_rate_limiter,
    PerformanceMonitor,
    get_performance_monitor,
)


class TestHTTPConnectionPool:
    """Tests for HTTP connection pooling"""
    
    def test_singleton_pattern(self):
        """Test that HTTPConnectionPool is a singleton"""
        pool1 = HTTPConnectionPool()
        pool2 = HTTPConnectionPool()
        
        assert pool1 is pool2
    
    def test_async_client_available(self):
        """Test that async client is available"""
        pool = HTTPConnectionPool()
        client = pool.async_client
        
        assert client is not None
        assert hasattr(client, 'get')
        assert hasattr(client, 'post')
    
    def test_sync_client_available(self):
        """Test that sync client is available"""
        pool = HTTPConnectionPool()
        client = pool.sync_client
        
        assert client is not None
        assert hasattr(client, 'get')
        assert hasattr(client, 'post')
    
    def test_get_http_client(self):
        """Test global async client getter"""
        client = get_http_client()
        
        assert client is not None
        # Should return same instance
        assert client is get_http_client()
    
    def test_get_sync_http_client(self):
        """Test global sync client getter"""
        client = get_sync_http_client()
        
        assert client is not None
        # Should return same instance
        assert client is get_sync_http_client()


class TestResponseCache:
    """Tests for response caching"""
    
    @pytest.fixture
    def cache(self):
        """Create a fresh cache for each test"""
        return ResponseCache(default_ttl=60)
    
    def test_set_and_get(self, cache):
        """Test basic set and get operations"""
        cache.set("key1", "value1")
        
        result = cache.get("key1")
        assert result == "value1"
    
    def test_get_nonexistent_key(self, cache):
        """Test getting a non-existent key"""
        result = cache.get("nonexistent")
        
        assert result is None
    
    def test_cache_expiration(self, cache):
        """Test that cache entries expire"""
        cache.set("key1", "value1", ttl=1)  # 1 second TTL
        
        # Should be available immediately
        assert cache.get("key1") == "value1"
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        assert cache.get("key1") is None
    
    def test_cache_overwrite(self, cache):
        """Test overwriting cache entries"""
        cache.set("key1", "value1")
        cache.set("key1", "value2")
        
        result = cache.get("key1")
        assert result == "value2"
    
    def test_delete(self, cache):
        """Test deleting cache entries"""
        cache.set("key1", "value1")
        cache.delete("key1")
        
        result = cache.get("key1")
        assert result is None
    
    def test_clear(self, cache):
        """Test clearing all cache entries"""
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        
        cache.clear()
        
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.get("key3") is None
    
    def test_cleanup_expired(self, cache):
        """Test cleanup of expired entries"""
        cache.set("key1", "value1", ttl=1)
        cache.set("key2", "value2", ttl=10)
        
        # Wait for first key to expire
        time.sleep(1.1)
        
        cache.cleanup_expired()
        
        # key1 should be gone, key2 should remain
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
    
    def test_cache_statistics(self, cache):
        """Test cache statistics tracking"""
        # Generate some hits and misses
        cache.set("key1", "value1")
        
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("key2")  # Miss
        
        stats = cache.get_stats()
        
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["total_requests"] == 3
        assert stats["hit_rate"] == pytest.approx(66.67, rel=0.1)
    
    def test_get_auth_cache(self):
        """Test global auth cache getter"""
        cache = get_auth_cache()
        
        assert cache is not None
        assert isinstance(cache, ResponseCache)
    
    def test_get_policy_cache(self):
        """Test global policy cache getter"""
        cache = get_policy_cache()
        
        assert cache is not None
        assert isinstance(cache, ResponseCache)


class TestRateLimiter:
    """Tests for rate limiting"""
    
    @pytest.fixture
    def limiter(self):
        """Create a rate limiter for testing"""
        return RateLimiter(rate=10, per=60)  # 10 requests per 60 seconds
    
    def test_initial_requests_allowed(self, limiter):
        """Test that initial requests are allowed"""
        for i in range(10):
            assert limiter.is_allowed("user1") is True
    
    def test_rate_limit_exceeded(self, limiter):
        """Test that requests are blocked after limit"""
        # Use up all tokens
        for i in range(10):
            limiter.is_allowed("user1")
        
        # Next request should be blocked
        assert limiter.is_allowed("user1") is False
    
    def test_different_keys_independent(self, limiter):
        """Test that different keys have independent limits"""
        # Use up tokens for user1
        for i in range(10):
            limiter.is_allowed("user1")
        
        # user2 should still be allowed
        assert limiter.is_allowed("user2") is True
    
    def test_token_refill(self, limiter):
        """Test that tokens refill over time"""
        # Use up all tokens
        for i in range(10):
            limiter.is_allowed("user1")
        
        # Should be blocked
        assert limiter.is_allowed("user1") is False
        
        # Wait for some tokens to refill (10 req/60s = 1 req/6s)
        time.sleep(6.5)
        
        # Should have at least 1 token now
        assert limiter.is_allowed("user1") is True
    
    def test_reset(self, limiter):
        """Test resetting rate limit for a key"""
        # Use up tokens
        for i in range(10):
            limiter.is_allowed("user1")
        
        # Reset
        limiter.reset("user1")
        
        # Should be allowed again
        assert limiter.is_allowed("user1") is True
    
    def test_get_remaining(self, limiter):
        """Test getting remaining requests"""
        # Initially should have full rate
        assert limiter.get_remaining("new_user") == 10
        
        # Use some tokens
        limiter.is_allowed("new_user")
        limiter.is_allowed("new_user")
        
        # Should have fewer remaining
        remaining = limiter.get_remaining("new_user")
        assert remaining < 10
        assert remaining >= 0
    
    def test_get_user_rate_limiter(self):
        """Test global user rate limiter getter"""
        limiter = get_user_rate_limiter()
        
        assert limiter is not None
        assert isinstance(limiter, RateLimiter)
        assert limiter.rate == 100
        assert limiter.per == 60
    
    def test_get_endpoint_rate_limiter(self):
        """Test global endpoint rate limiter getter"""
        limiter = get_endpoint_rate_limiter()
        
        assert limiter is not None
        assert isinstance(limiter, RateLimiter)
        assert limiter.rate == 1000
        assert limiter.per == 60


class TestPerformanceMonitor:
    """Tests for performance monitoring"""
    
    @pytest.fixture
    def monitor(self):
        """Create a fresh performance monitor"""
        return PerformanceMonitor()
    
    def test_record_metric(self, monitor):
        """Test recording a metric"""
        monitor.record("test_metric", 100.5)
        
        stats = monitor.get_stats("test_metric")
        
        assert stats["count"] == 1
        assert stats["min"] == 100.5
        assert stats["max"] == 100.5
        assert stats["avg"] == 100.5
    
    def test_multiple_recordings(self, monitor):
        """Test recording multiple values"""
        values = [10, 20, 30, 40, 50]
        for val in values:
            monitor.record("test_metric", val)
        
        stats = monitor.get_stats("test_metric")
        
        assert stats["count"] == 5
        assert stats["min"] == 10
        assert stats["max"] == 50
        assert stats["avg"] == 30
    
    def test_percentiles(self, monitor):
        """Test percentile calculations"""
        # Record 100 values
        for i in range(100):
            monitor.record("test_metric", i)
        
        stats = monitor.get_stats("test_metric")
        
        # p50 should be around 50
        assert 45 <= stats["p50"] <= 55
        
        # p95 should be around 95
        assert 90 <= stats["p95"] <= 99
        
        # p99 should be around 99
        assert 95 <= stats["p99"] <= 99
    
    def test_max_entries_limit(self, monitor):
        """Test that only last 1000 entries are kept"""
        # Record 1500 values
        for i in range(1500):
            monitor.record("test_metric", i)
        
        stats = monitor.get_stats("test_metric")
        
        # Should only have 1000 entries
        assert stats["count"] == 1000
        
        # Min should be 500 (first 500 were dropped)
        assert stats["min"] >= 500
    
    def test_get_all_stats(self, monitor):
        """Test getting statistics for all metrics"""
        monitor.record("metric1", 10)
        monitor.record("metric2", 20)
        monitor.record("metric3", 30)
        
        all_stats = monitor.get_all_stats()
        
        assert "metric1" in all_stats
        assert "metric2" in all_stats
        assert "metric3" in all_stats
    
    def test_nonexistent_metric(self, monitor):
        """Test getting stats for non-existent metric"""
        stats = monitor.get_stats("nonexistent")
        
        assert stats == {}
    
    def test_get_performance_monitor(self):
        """Test global performance monitor getter"""
        monitor = get_performance_monitor()
        
        assert monitor is not None
        assert isinstance(monitor, PerformanceMonitor)


class TestCacheIntegration:
    """Integration tests for caching"""
    
    def test_cache_reduces_calls(self):
        """Test that caching reduces function calls"""
        cache = ResponseCache(default_ttl=60)
        call_count = 0
        
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2
        
        # First call
        cache_key = "test:1"
        result = cache.get(cache_key)
        if result is None:
            result = expensive_function(1)
            cache.set(cache_key, result)
        
        assert call_count == 1
        assert result == 2
        
        # Second call (should use cache)
        result = cache.get(cache_key)
        if result is None:
            result = expensive_function(1)
            cache.set(cache_key, result)
        
        assert call_count == 1  # Still 1, not 2
        assert result == 2


class TestRateLimitingIntegration:
    """Integration tests for rate limiting"""
    
    def test_rate_limiter_prevents_abuse(self):
        """Test that rate limiter prevents request abuse"""
        limiter = RateLimiter(rate=5, per=10)  # 5 requests per 10 seconds
        
        allowed_count = 0
        blocked_count = 0
        
        # Try to make 10 requests
        for i in range(10):
            if limiter.is_allowed("abusive_user"):
                allowed_count += 1
            else:
                blocked_count += 1
        
        # Should allow 5, block 5
        assert allowed_count == 5
        assert blocked_count == 5
