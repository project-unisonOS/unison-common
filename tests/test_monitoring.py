"""
Unit tests for production monitoring utilities (M5.5)
"""

import pytest
import time
from datetime import datetime

from unison_common.monitoring import (
    PrometheusMetrics,
    get_prometheus_metrics,
    HealthCheck,
    HealthStatus,
    initialize_health_check,
    get_health_check,
    log_metric,
    log_event,
    log_error,
)


class TestPrometheusMetrics:
    """Tests for Prometheus metrics"""
    
    @pytest.fixture
    def metrics(self):
        """Create a fresh metrics instance"""
        return PrometheusMetrics()
    
    def test_counter_increment(self, metrics):
        """Test counter increment"""
        metrics.counter_inc("test_counter")
        metrics.counter_inc("test_counter")
        metrics.counter_inc("test_counter", value=3.0)
        
        metrics_dict = metrics.get_metrics_dict()
        assert metrics_dict["counters"]["test_counter"] == 5.0
    
    def test_counter_with_labels(self, metrics):
        """Test counter with labels"""
        metrics.counter_inc("http_requests", labels={"method": "GET", "status": "200"})
        metrics.counter_inc("http_requests", labels={"method": "POST", "status": "201"})
        
        metrics_dict = metrics.get_metrics_dict()
        assert 'http_requests{method="GET",status="200"}' in metrics_dict["counters"]
        assert 'http_requests{method="POST",status="201"}' in metrics_dict["counters"]
    
    def test_gauge_set(self, metrics):
        """Test gauge set"""
        metrics.gauge_set("memory_usage", 1024.5)
        metrics.gauge_set("memory_usage", 2048.0)
        
        metrics_dict = metrics.get_metrics_dict()
        assert metrics_dict["gauges"]["memory_usage"] == 2048.0
    
    def test_gauge_with_labels(self, metrics):
        """Test gauge with labels"""
        metrics.gauge_set("cpu_usage", 45.5, labels={"core": "0"})
        metrics.gauge_set("cpu_usage", 67.2, labels={"core": "1"})
        
        metrics_dict = metrics.get_metrics_dict()
        assert 'cpu_usage{core="0"}' in metrics_dict["gauges"]
        assert 'cpu_usage{core="1"}' in metrics_dict["gauges"]
    
    def test_histogram_observe(self, metrics):
        """Test histogram observation"""
        values = [0.1, 0.2, 0.5, 1.0, 2.0]
        for val in values:
            metrics.histogram_observe("request_duration", val)
        
        metrics_dict = metrics.get_metrics_dict()
        assert metrics_dict["histograms"]["request_duration"]["count"] == 5
        assert metrics_dict["histograms"]["request_duration"]["sum"] == sum(values)
    
    def test_summary_observe(self, metrics):
        """Test summary observation"""
        values = [10, 20, 30, 40, 50]
        for val in values:
            metrics.summary_observe("response_size", val)
        
        metrics_dict = metrics.get_metrics_dict()
        assert metrics_dict["summaries"]["response_size"]["count"] == 5
        assert metrics_dict["summaries"]["response_size"]["sum"] == sum(values)
    
    def test_set_help_text(self, metrics):
        """Test setting help text for metrics"""
        metrics.set_help("test_metric", "This is a test metric")
        
        # Help text should be stored
        assert "test_metric" in metrics._help_text
        assert metrics._help_text["test_metric"] == "This is a test metric"
    
    def test_export_text_format(self, metrics):
        """Test Prometheus text format export"""
        metrics.set_help("test_counter", "Test counter metric")
        metrics.counter_inc("test_counter", value=5.0)
        metrics.gauge_set("test_gauge", 42.0)
        
        export = metrics.export_text()
        
        # Should contain HELP and TYPE comments
        assert "# HELP test_counter Test counter metric" in export
        assert "# TYPE test_counter counter" in export
        
        # Should contain metric values
        assert "test_counter 5.0" in export
        assert "test_gauge 42.0" in export
    
    def test_export_histogram_buckets(self, metrics):
        """Test histogram bucket export"""
        metrics.histogram_observe("latency", 0.05)
        metrics.histogram_observe("latency", 0.15)
        metrics.histogram_observe("latency", 0.5)
        
        export = metrics.export_text()
        
        # Should contain bucket counts
        assert 'le="0.1"' in export
        assert 'le="0.25"' in export
        assert 'le="+Inf"' in export
        
        # Should contain sum and count
        assert "latency_sum" in export
        assert "latency_count" in export
    
    def test_get_prometheus_metrics(self):
        """Test global Prometheus metrics getter"""
        metrics = get_prometheus_metrics()
        
        assert metrics is not None
        assert isinstance(metrics, PrometheusMetrics)
        
        # Should return same instance
        assert metrics is get_prometheus_metrics()


class TestHealthCheck:
    """Tests for health check system"""
    
    @pytest.fixture
    def health_check(self):
        """Create a fresh health check instance"""
        return HealthCheck("test-service")
    
    def test_register_check(self, health_check):
        """Test registering a health check"""
        def dummy_check():
            return HealthStatus.HEALTHY, {"status": "ok"}
        
        health_check.register_check("dummy", dummy_check)
        
        assert "dummy" in health_check._checks
    
    def test_run_checks_all_healthy(self, health_check):
        """Test running checks when all are healthy"""
        def check1():
            return HealthStatus.HEALTHY, {"db": "connected"}
        
        def check2():
            return HealthStatus.HEALTHY, {"cache": "connected"}
        
        health_check.register_check("database", check1)
        health_check.register_check("cache", check2)
        
        results = health_check.run_checks()
        
        assert results["status"] == HealthStatus.HEALTHY.value
        assert results["service"] == "test-service"
        assert "database" in results["checks"]
        assert "cache" in results["checks"]
        assert results["checks"]["database"]["status"] == HealthStatus.HEALTHY.value
    
    def test_run_checks_degraded(self, health_check):
        """Test running checks with degraded status"""
        def check1():
            return HealthStatus.HEALTHY, {"status": "ok"}
        
        def check2():
            return HealthStatus.DEGRADED, {"status": "slow"}
        
        health_check.register_check("service1", check1)
        health_check.register_check("service2", check2)
        
        results = health_check.run_checks()
        
        # Overall status should be degraded
        assert results["status"] == HealthStatus.DEGRADED.value
    
    def test_run_checks_unhealthy(self, health_check):
        """Test running checks with unhealthy status"""
        def check1():
            return HealthStatus.HEALTHY, {"status": "ok"}
        
        def check2():
            return HealthStatus.UNHEALTHY, {"error": "connection failed"}
        
        health_check.register_check("service1", check1)
        health_check.register_check("service2", check2)
        
        results = health_check.run_checks()
        
        # Overall status should be unhealthy
        assert results["status"] == HealthStatus.UNHEALTHY.value
    
    def test_run_checks_with_exception(self, health_check):
        """Test running checks when a check raises exception"""
        def failing_check():
            raise Exception("Check failed")
        
        health_check.register_check("failing", failing_check)
        
        results = health_check.run_checks()
        
        # Should mark as unhealthy
        assert results["status"] == HealthStatus.UNHEALTHY.value
        assert results["checks"]["failing"]["status"] == HealthStatus.UNHEALTHY.value
        assert "error" in results["checks"]["failing"]["details"]
    
    def test_check_duration_tracking(self, health_check):
        """Test that check duration is tracked"""
        def slow_check():
            time.sleep(0.1)
            return HealthStatus.HEALTHY, {"status": "ok"}
        
        health_check.register_check("slow", slow_check)
        
        results = health_check.run_checks()
        
        # Should have duration
        assert "duration_ms" in results["checks"]["slow"]
        assert results["checks"]["slow"]["duration_ms"] > 50  # At least 50ms
    
    def test_uptime_tracking(self, health_check):
        """Test that uptime is tracked"""
        time.sleep(0.1)
        
        results = health_check.run_checks()
        
        assert "uptime_seconds" in results
        assert results["uptime_seconds"] > 0
    
    def test_get_last_results(self, health_check):
        """Test getting last results without re-running"""
        def check():
            return HealthStatus.HEALTHY, {"status": "ok"}
        
        health_check.register_check("test", check)
        
        # Run checks
        results1 = health_check.run_checks()
        
        # Get last results
        results2 = health_check.get_last_results()
        
        # Should have same check results
        assert results2 == results1["checks"]
    
    def test_initialize_health_check(self):
        """Test initializing global health check"""
        health_check = initialize_health_check("my-service")
        
        assert health_check is not None
        assert health_check.service_name == "my-service"
        
        # Should be retrievable
        assert get_health_check() is health_check


class TestStructuredLogging:
    """Tests for structured logging helpers"""
    
    def test_log_metric(self, caplog):
        """Test logging a metric"""
        with caplog.at_level("INFO"):
            log_metric("request_count", 42, endpoint="/api/test")
        
        # Should log the metric
        assert "METRIC: request_count=42" in caplog.text
    
    def test_log_event(self, caplog):
        """Test logging an event"""
        with caplog.at_level("INFO"):
            log_event("user_login", user_id="123", ip="192.168.1.1")
        
        # Should log the event
        assert "EVENT: user_login" in caplog.text
    
    def test_log_error_without_exception(self, caplog):
        """Test logging an error without exception"""
        with caplog.at_level("ERROR"):
            log_error("Something went wrong", user_id="123")
        
        # Should log the error
        assert "ERROR: Something went wrong" in caplog.text
    
    def test_log_error_with_exception(self, caplog):
        """Test logging an error with exception"""
        try:
            raise ValueError("Test error")
        except ValueError as e:
            with caplog.at_level("ERROR"):
                log_error("An error occurred", error=e)
        
        # Should log the error
        assert "ERROR: An error occurred" in caplog.text


class TestPrometheusIntegration:
    """Integration tests for Prometheus metrics"""
    
    def test_counter_workflow(self):
        """Test complete counter workflow"""
        metrics = PrometheusMetrics()
        
        # Simulate HTTP requests
        metrics.counter_inc("http_requests_total", labels={"method": "GET", "status": "200"})
        metrics.counter_inc("http_requests_total", labels={"method": "GET", "status": "200"})
        metrics.counter_inc("http_requests_total", labels={"method": "POST", "status": "201"})
        
        # Export and verify
        export = metrics.export_text()
        
        assert "http_requests_total" in export
        assert 'method="GET"' in export
        assert 'status="200"' in export
    
    def test_histogram_workflow(self):
        """Test complete histogram workflow"""
        metrics = PrometheusMetrics()
        metrics.set_help("http_request_duration_seconds", "HTTP request duration in seconds")
        
        # Simulate request durations
        durations = [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
        for duration in durations:
            metrics.histogram_observe("http_request_duration_seconds", duration)
        
        # Export and verify
        export = metrics.export_text()
        
        assert "# HELP http_request_duration_seconds" in export
        assert "# TYPE http_request_duration_seconds histogram" in export
        assert "http_request_duration_seconds_sum" in export
        assert "http_request_duration_seconds_count 7" in export


class TestHealthCheckIntegration:
    """Integration tests for health check system"""
    
    def test_multi_dependency_health_check(self):
        """Test health check with multiple dependencies"""
        health_check = HealthCheck("api-service")
        
        # Register multiple checks
        def db_check():
            return HealthStatus.HEALTHY, {"latency_ms": 5}
        
        def cache_check():
            return HealthStatus.HEALTHY, {"hit_rate": 0.85}
        
        def external_api_check():
            return HealthStatus.DEGRADED, {"latency_ms": 500, "reason": "slow"}
        
        health_check.register_check("database", db_check)
        health_check.register_check("cache", cache_check)
        health_check.register_check("external_api", external_api_check)
        
        results = health_check.run_checks()
        
        # Overall should be degraded (worst status)
        assert results["status"] == HealthStatus.DEGRADED.value
        
        # All checks should be present
        assert len(results["checks"]) == 3
        assert results["checks"]["database"]["status"] == HealthStatus.HEALTHY.value
        assert results["checks"]["external_api"]["status"] == HealthStatus.DEGRADED.value
    
    def test_health_check_recovery(self):
        """Test health check status recovery"""
        health_check = HealthCheck("test-service")
        
        # Initially unhealthy
        unhealthy_state = {"is_healthy": False}
        
        def dynamic_check():
            if unhealthy_state["is_healthy"]:
                return HealthStatus.HEALTHY, {"status": "recovered"}
            else:
                return HealthStatus.UNHEALTHY, {"status": "down"}
        
        health_check.register_check("dynamic", dynamic_check)
        
        # First check - unhealthy
        results1 = health_check.run_checks()
        assert results1["status"] == HealthStatus.UNHEALTHY.value
        
        # Recover
        unhealthy_state["is_healthy"] = True
        
        # Second check - healthy
        results2 = health_check.run_checks()
        assert results2["status"] == HealthStatus.HEALTHY.value


class TestMetricsExportFormat:
    """Tests for Prometheus export format compliance"""
    
    def test_export_format_structure(self):
        """Test that export format follows Prometheus spec"""
        metrics = PrometheusMetrics()
        metrics.set_help("test_metric", "A test metric")
        metrics.counter_inc("test_metric", value=42)
        
        export = metrics.export_text()
        lines = export.strip().split("\n")
        
        # Should have HELP, TYPE, and value lines
        assert any("# HELP" in line for line in lines)
        assert any("# TYPE" in line for line in lines)
        assert any("test_metric 42" in line for line in lines)
    
    def test_label_format(self):
        """Test that labels are formatted correctly"""
        metrics = PrometheusMetrics()
        metrics.counter_inc("test", labels={"label1": "value1", "label2": "value2"})
        
        export = metrics.export_text()
        
        # Labels should be sorted and quoted
        assert 'test{label1="value1",label2="value2"}' in export
