"""
Simple test to verify tracing tests work in CI/CD
"""

import os
import sys

# Add the src directory to Python path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_tracing_imports():
    """Test that all tracing modules can be imported"""
    try:
        from unison_common.tracing import (
            TracingConfig,
            TraceContext,
            DistributedTracer,
            get_tracer,
            initialize_tracing
        )
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import tracing modules: {e}")

def test_tracing_config():
    """Test basic tracing configuration"""
    from unison_common.tracing import TracingConfig
    
    config = TracingConfig()
    assert config.service_name == "unison-service"
    assert config.enabled == True

def test_trace_context():
    """Test trace context creation"""
    from unison_common.tracing import TraceContext
    
    context = TraceContext()
    assert context.trace_id is not None
    assert context.span_id is not None
    assert context.baggage == {}

def test_disabled_tracer():
    """Test disabled tracer functionality"""
    from unison_common.tracing import TracingConfig, DistributedTracer
    
    config = TracingConfig()
    config.enabled = False
    config.jaeger_endpoint = None
    config.otlp_endpoint = None
    
    tracer = DistributedTracer(config)
    assert tracer.config.enabled == False
    
    # Test basic operations don't crash
    context = tracer.create_trace_context()
    assert context.trace_id is not None
    
    headers = tracer.inject_headers()
    assert "X-Request-Id" in headers

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
