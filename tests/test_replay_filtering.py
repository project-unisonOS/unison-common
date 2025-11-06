"""
Unit tests for replay trace filtering (M5.3)
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock

from unison_common.replay_store import (
    ReplayConfig,
    MemoryReplayStore,
    StoredEnvelope,
)


@pytest.fixture
def replay_store():
    """Create a replay store with test data"""
    config = ReplayConfig()
    store = MemoryReplayStore(config)
    
    # Add test envelopes
    base_time = datetime.utcnow()
    
    # Trace 1: Success, user1, echo intent
    store.store_envelope(StoredEnvelope(
        envelope_id="env1",
        trace_id="trace1",
        correlation_id="corr1",
        envelope_data={"intent": "echo", "payload": {"message": "test1"}},
        timestamp=base_time - timedelta(hours=2),
        event_type="ingest_request",
        source="orchestrator",
        user_id="user1",
        processing_time_ms=50.0,
        status_code=200,
        error_message=None
    ))
    
    # Trace 2: Error, user1, echo intent
    store.store_envelope(StoredEnvelope(
        envelope_id="env2",
        trace_id="trace2",
        correlation_id="corr2",
        envelope_data={"intent": "echo", "payload": {"message": "test2"}},
        timestamp=base_time - timedelta(hours=1),
        event_type="ingest_request",
        source="orchestrator",
        user_id="user1",
        processing_time_ms=None,
        status_code=500,
        error_message="Test error"
    ))
    
    # Trace 3: Success, user2, summarize intent
    store.store_envelope(StoredEnvelope(
        envelope_id="env3",
        trace_id="trace3",
        correlation_id="corr3",
        envelope_data={"intent": "summarize", "payload": {"doc": "test"}},
        timestamp=base_time - timedelta(minutes=30),
        event_type="ingest_request",
        source="orchestrator",
        user_id="user2",
        processing_time_ms=100.0,
        status_code=200,
        error_message=None
    ))
    
    # Trace 4: Success, user2, echo intent (recent)
    store.store_envelope(StoredEnvelope(
        envelope_id="env4",
        trace_id="trace4",
        correlation_id="corr4",
        envelope_data={"intent": "echo", "payload": {"message": "test4"}},
        timestamp=base_time,
        event_type="ingest_request",
        source="orchestrator",
        user_id="user2",
        processing_time_ms=75.0,
        status_code=200,
        error_message=None
    ))
    
    return store


class TestTraceFiltering:
    """Tests for trace filtering functionality"""
    
    def test_filter_by_user_id(self, replay_store):
        """Test filtering traces by user ID"""
        # Filter for user1
        traces, total = replay_store.filter_traces(user_id="user1")
        
        assert total == 2
        assert "trace1" in traces
        assert "trace2" in traces
        assert "trace3" not in traces
        assert "trace4" not in traces
    
    def test_filter_by_status_success(self, replay_store):
        """Test filtering traces by success status"""
        traces, total = replay_store.filter_traces(status="success")
        
        assert total == 3
        assert "trace1" in traces
        assert "trace3" in traces
        assert "trace4" in traces
        assert "trace2" not in traces  # Has error
    
    def test_filter_by_status_error(self, replay_store):
        """Test filtering traces by error status"""
        traces, total = replay_store.filter_traces(status="error")
        
        assert total == 1
        assert "trace2" in traces
        assert "trace1" not in traces
    
    def test_filter_by_intent(self, replay_store):
        """Test filtering traces by intent type"""
        traces, total = replay_store.filter_traces(intent="echo")
        
        assert total == 3
        assert "trace1" in traces
        assert "trace2" in traces
        assert "trace4" in traces
        assert "trace3" not in traces  # Summarize intent
    
    def test_filter_by_date_range(self, replay_store):
        """Test filtering traces by date range"""
        base_time = datetime.utcnow()
        start_date = base_time - timedelta(hours=1, minutes=30)
        end_date = base_time
        
        traces, total = replay_store.filter_traces(
            start_date=start_date,
            end_date=end_date
        )
        
        # Should include trace2 (1h ago), trace3 (30m ago), trace4 (now)
        # Should exclude trace1 (2h ago)
        assert total == 3
        assert "trace2" in traces
        assert "trace3" in traces
        assert "trace4" in traces
        assert "trace1" not in traces
    
    def test_filter_combined(self, replay_store):
        """Test filtering with multiple criteria"""
        traces, total = replay_store.filter_traces(
            user_id="user2",
            intent="echo",
            status="success"
        )
        
        # Only trace4 matches all criteria
        assert total == 1
        assert "trace4" in traces
    
    def test_filter_pagination(self, replay_store):
        """Test pagination of filtered results"""
        # Get first 2 results
        traces_page1, total = replay_store.filter_traces(limit=2, offset=0)
        assert len(traces_page1) == 2
        assert total == 4
        
        # Get next 2 results
        traces_page2, total = replay_store.filter_traces(limit=2, offset=2)
        assert len(traces_page2) == 2
        assert total == 4
        
        # No overlap
        assert not set(traces_page1).intersection(set(traces_page2))
    
    def test_filter_no_results(self, replay_store):
        """Test filtering with no matching results"""
        traces, total = replay_store.filter_traces(user_id="nonexistent")
        
        assert total == 0
        assert len(traces) == 0
    
    def test_filter_sorting(self, replay_store):
        """Test that results are sorted by timestamp (most recent first)"""
        traces, total = replay_store.filter_traces()
        
        # Should be sorted: trace4 (now), trace3 (30m), trace2 (1h), trace1 (2h)
        assert traces[0] == "trace4"
        assert traces[-1] == "trace1"
    
    def test_filter_empty_store(self):
        """Test filtering on empty store"""
        config = ReplayConfig()
        empty_store = MemoryReplayStore(config)
        
        traces, total = empty_store.filter_traces()
        
        assert total == 0
        assert len(traces) == 0


class TestTraceDeletion:
    """Tests for trace deletion functionality"""
    
    def test_delete_existing_trace(self, replay_store):
        """Test deleting an existing trace"""
        # Verify trace exists
        assert "trace1" in replay_store.get_trace_ids()
        
        # Delete it
        success = replay_store.delete_trace("trace1")
        
        assert success is True
        assert "trace1" not in replay_store.get_trace_ids()
    
    def test_delete_nonexistent_trace(self, replay_store):
        """Test deleting a non-existent trace"""
        success = replay_store.delete_trace("nonexistent")
        
        assert success is False
    
    def test_delete_removes_from_correlation_index(self, replay_store):
        """Test that deletion removes trace from correlation index"""
        # Get envelopes by correlation before deletion
        envelopes_before = replay_store.get_envelopes_by_correlation("corr1")
        assert len(envelopes_before) > 0
        
        # Delete the trace
        replay_store.delete_trace("trace1")
        
        # Correlation should no longer return results
        envelopes_after = replay_store.get_envelopes_by_correlation("corr1")
        assert len(envelopes_after) == 0


class TestStatistics:
    """Tests for replay statistics"""
    
    def test_basic_statistics(self, replay_store):
        """Test basic statistics calculation"""
        stats = replay_store.get_statistics()
        
        assert stats["total_envelopes"] == 4
        assert stats["total_traces"] == 4
        assert stats["store_type"] == "MemoryReplayStore"
    
    def test_statistics_after_deletion(self, replay_store):
        """Test statistics after deleting traces"""
        # Delete one trace
        replay_store.delete_trace("trace1")
        
        stats = replay_store.get_statistics()
        
        assert stats["total_envelopes"] == 3
        assert stats["total_traces"] == 3
    
    def test_statistics_empty_store(self):
        """Test statistics on empty store"""
        config = ReplayConfig()
        empty_store = MemoryReplayStore(config)
        
        stats = empty_store.get_statistics()
        
        assert stats["total_envelopes"] == 0
        assert stats["total_traces"] == 0


class TestExportData:
    """Tests for data export preparation"""
    
    def test_envelope_to_dict(self, replay_store):
        """Test converting envelope to dictionary"""
        envelopes = replay_store.get_envelopes_by_trace("trace1")
        assert len(envelopes) > 0
        
        envelope_dict = envelopes[0].to_dict()
        
        # Verify all fields are present
        assert "envelope_id" in envelope_dict
        assert "trace_id" in envelope_dict
        assert "correlation_id" in envelope_dict
        assert "timestamp" in envelope_dict
        assert "event_type" in envelope_dict
        assert "envelope_data" in envelope_dict
        
        # Verify timestamp is ISO string
        assert isinstance(envelope_dict["timestamp"], str)
    
    def test_get_all_trace_envelopes(self, replay_store):
        """Test getting all envelopes for export"""
        envelopes = replay_store.get_envelopes_by_trace("trace1")
        
        assert len(envelopes) > 0
        assert all(env.trace_id == "trace1" for env in envelopes)
