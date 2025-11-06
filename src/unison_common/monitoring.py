"""
Production monitoring utilities for Unison platform (M5.5)

Includes:
- Prometheus metrics
- Enhanced health checks
- Structured logging helpers
"""

import time
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Prometheus Metrics (M5.5)
# ============================================================================

class MetricType(Enum):
    """Metric types for Prometheus"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class PrometheusMetrics:
    """
    Prometheus-compatible metrics collector.
    Exports metrics in Prometheus text format.
    """
    
    def __init__(self):
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._summaries: Dict[str, List[float]] = {}
        self._help_text: Dict[str, str] = {}
        self._metric_types: Dict[str, MetricType] = {}
    
    def counter_inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """
        Increment a counter metric
        
        Args:
            name: Metric name
            value: Increment value (default: 1.0)
            labels: Optional labels dict
        """
        metric_key = self._format_metric_key(name, labels)
        self._counters[metric_key] = self._counters.get(metric_key, 0) + value
        self._metric_types[name] = MetricType.COUNTER
    
    def gauge_set(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Set a gauge metric value
        
        Args:
            name: Metric name
            value: Gauge value
            labels: Optional labels dict
        """
        metric_key = self._format_metric_key(name, labels)
        self._gauges[metric_key] = value
        self._metric_types[name] = MetricType.GAUGE
    
    def histogram_observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Observe a value for histogram
        
        Args:
            name: Metric name
            value: Observed value
            labels: Optional labels dict
        """
        metric_key = self._format_metric_key(name, labels)
        if metric_key not in self._histograms:
            self._histograms[metric_key] = []
        self._histograms[metric_key].append(value)
        self._metric_types[name] = MetricType.HISTOGRAM
    
    def summary_observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Observe a value for summary
        
        Args:
            name: Metric name
            value: Observed value
            labels: Optional labels dict
        """
        metric_key = self._format_metric_key(name, labels)
        if metric_key not in self._summaries:
            self._summaries[metric_key] = []
        self._summaries[metric_key].append(value)
        self._metric_types[name] = MetricType.SUMMARY
    
    def set_help(self, name: str, help_text: str):
        """Set help text for a metric"""
        self._help_text[name] = help_text
    
    def _format_metric_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        """Format metric key with labels"""
        if not labels:
            return name
        
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def _parse_metric_key(self, metric_key: str) -> tuple:
        """Parse metric key into name and labels"""
        if "{" not in metric_key:
            return metric_key, {}
        
        name = metric_key.split("{")[0]
        labels_str = metric_key.split("{")[1].rstrip("}")
        
        labels = {}
        if labels_str:
            for pair in labels_str.split(","):
                k, v = pair.split("=")
                labels[k] = v.strip('"')
        
        return name, labels
    
    def export_text(self) -> str:
        """
        Export metrics in Prometheus text format
        
        Returns:
            Prometheus-formatted metrics string
        """
        lines = []
        
        # Export counters
        for metric_key, value in self._counters.items():
            name, labels = self._parse_metric_key(metric_key)
            
            if name in self._help_text and metric_key == name:
                lines.append(f"# HELP {name} {self._help_text[name]}")
                lines.append(f"# TYPE {name} counter")
            
            lines.append(f"{metric_key} {value}")
        
        # Export gauges
        for metric_key, value in self._gauges.items():
            name, labels = self._parse_metric_key(metric_key)
            
            if name in self._help_text and metric_key == name:
                lines.append(f"# HELP {name} {self._help_text[name]}")
                lines.append(f"# TYPE {name} gauge")
            
            lines.append(f"{metric_key} {value}")
        
        # Export histograms
        for metric_key, values in self._histograms.items():
            name, labels = self._parse_metric_key(metric_key)
            
            if name in self._help_text and metric_key == name:
                lines.append(f"# HELP {name} {self._help_text[name]}")
                lines.append(f"# TYPE {name} histogram")
            
            # Calculate histogram buckets
            values_sorted = sorted(values)
            buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
            
            for bucket in buckets:
                count = sum(1 for v in values_sorted if v <= bucket)
                bucket_key = metric_key.replace("}", f',le="{bucket}"}') if labels else f'{name}{{le="{bucket}"}}'
                lines.append(f"{bucket_key} {count}")
            
            # Add +Inf bucket
            inf_key = metric_key.replace("}", ',le="+Inf"}') if labels else f'{name}{{le="+Inf"}}'
            lines.append(f"{inf_key} {len(values)}")
            
            # Add sum and count
            sum_key = f"{name}_sum" + (f"{{{','.join(f'{k}=\"{v}\"' for k, v in labels.items())}}}" if labels else "")
            count_key = f"{name}_count" + (f"{{{','.join(f'{k}=\"{v}\"' for k, v in labels.items())}}}" if labels else "")
            lines.append(f"{sum_key} {sum(values)}")
            lines.append(f"{count_key} {len(values)}")
        
        return "\n".join(lines) + "\n"
    
    def get_metrics_dict(self) -> Dict[str, Any]:
        """Get metrics as dictionary"""
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {k: {"count": len(v), "sum": sum(v)} for k, v in self._histograms.items()},
            "summaries": {k: {"count": len(v), "sum": sum(v)} for k, v in self._summaries.items()}
        }


# Global Prometheus metrics instance
_prometheus_metrics = PrometheusMetrics()


def get_prometheus_metrics() -> PrometheusMetrics:
    """Get the global Prometheus metrics instance"""
    return _prometheus_metrics


# ============================================================================
# Health Check System (M5.5)
# ============================================================================

class HealthStatus(Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck:
    """
    Enhanced health check system with dependency tracking
    """
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self._checks: Dict[str, Callable] = {}
        self._last_results: Dict[str, Dict[str, Any]] = {}
        self._start_time = time.time()
    
    def register_check(self, name: str, check_func: Callable):
        """
        Register a health check function
        
        Args:
            name: Check name
            check_func: Function that returns (status, details)
        """
        self._checks[name] = check_func
        logger.info(f"Registered health check: {name}")
    
    def run_checks(self) -> Dict[str, Any]:
        """
        Run all health checks
        
        Returns:
            Health check results with overall status
        """
        results = {}
        overall_status = HealthStatus.HEALTHY
        
        for name, check_func in self._checks.items():
            try:
                start = time.time()
                status, details = check_func()
                duration = (time.time() - start) * 1000
                
                results[name] = {
                    "status": status.value if isinstance(status, HealthStatus) else status,
                    "details": details,
                    "duration_ms": round(duration, 2),
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Update overall status
                if status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
                    
            except Exception as e:
                logger.error(f"Health check '{name}' failed: {e}")
                results[name] = {
                    "status": HealthStatus.UNHEALTHY.value,
                    "details": {"error": str(e)},
                    "timestamp": datetime.utcnow().isoformat()
                }
                overall_status = HealthStatus.UNHEALTHY
        
        self._last_results = results
        
        return {
            "service": self.service_name,
            "status": overall_status.value,
            "uptime_seconds": round(time.time() - self._start_time, 2),
            "checks": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_last_results(self) -> Dict[str, Any]:
        """Get last health check results without re-running"""
        return self._last_results


# Global health check instance
_health_check: Optional[HealthCheck] = None


def initialize_health_check(service_name: str) -> HealthCheck:
    """Initialize the global health check system"""
    global _health_check
    _health_check = HealthCheck(service_name)
    return _health_check


def get_health_check() -> Optional[HealthCheck]:
    """Get the global health check instance"""
    return _health_check


# ============================================================================
# Structured Logging Helpers (M5.5)
# ============================================================================

def log_metric(metric_name: str, value: float, **context):
    """
    Log a metric with structured context
    
    Args:
        metric_name: Name of the metric
        value: Metric value
        **context: Additional context fields
    """
    logger.info(
        f"METRIC: {metric_name}={value}",
        extra={
            "metric_name": metric_name,
            "metric_value": value,
            "event_type": "metric",
            **context
        }
    )


def log_event(event_name: str, **context):
    """
    Log a structured event
    
    Args:
        event_name: Name of the event
        **context: Event context fields
    """
    logger.info(
        f"EVENT: {event_name}",
        extra={
            "event_name": event_name,
            "event_type": "event",
            **context
        }
    )


def log_error(error_message: str, error: Optional[Exception] = None, **context):
    """
    Log a structured error
    
    Args:
        error_message: Error message
        error: Optional exception object
        **context: Error context fields
    """
    logger.error(
        f"ERROR: {error_message}",
        extra={
            "error_message": error_message,
            "error_type": type(error).__name__ if error else None,
            "error_details": str(error) if error else None,
            "event_type": "error",
            **context
        },
        exc_info=error is not None
    )
