"""
Event replay store for storing and retrieving event envelopes

This module provides comprehensive event replay functionality to store
event envelopes by trace_id and replay them for debugging and auditing.
"""

import json
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class StoredEnvelope:
    """Stored event envelope with metadata"""
    envelope_id: str
    trace_id: str
    correlation_id: str
    envelope_data: Dict[str, Any]
    timestamp: datetime
    event_type: str
    source: str
    user_id: Optional[str] = None
    processing_time_ms: Optional[float] = None
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        # Convert datetime to ISO string
        data['timestamp'] = self.timestamp.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StoredEnvelope':
        """Create from dictionary from storage"""
        # Convert ISO string back to datetime
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


@dataclass
class ReplaySession:
    """Replay session metadata"""
    session_id: str
    trace_id: str
    created_at: datetime
    created_by: str
    status: str  # "created", "running", "completed", "failed"
    total_envelopes: int
    replayed_envelopes: int
    failed_envelopes: int
    errors: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReplaySession':
        """Create from dictionary from storage"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)


class ReplayConfig:
    """Configuration for event replay system"""
    
    def __init__(self):
        self.default_retention_days = 30  # Days to keep stored envelopes
        self.max_envelopes_per_trace = 1000  # Maximum envelopes per trace
        self.max_session_duration_hours = 24  # Maximum replay session duration
        self.cleanup_interval_hours = 6  # Cleanup interval
        self.max_stored_envelopes = 100000  # Maximum total stored envelopes
        self.compression_enabled = True  # Enable data compression
        self.index_by_correlation_id = True  # Index by correlation ID for faster lookups


class MemoryReplayStore:
    """In-memory store for event envelopes"""
    
    def __init__(self, config: ReplayConfig):
        self.config = config
        self._envelopes: Dict[str, List[StoredEnvelope]] = {}  # trace_id -> envelopes
        self._correlation_index: Dict[str, List[str]] = {}  # correlation_id -> trace_ids
        self._sessions: Dict[str, ReplaySession] = {}  # session_id -> session
        self._last_cleanup = time.time()
    
    def store_envelope(self, envelope: StoredEnvelope) -> bool:
        """Store an event envelope"""
        try:
            # Check if trace exists
            if envelope.trace_id not in self._envelopes:
                self._envelopes[envelope.trace_id] = []
            
            # Check envelope limit per trace
            if len(self._envelopes[envelope.trace_id]) >= self.config.max_envelopes_per_trace:
                logger.warning(f"Trace {envelope.trace_id} has reached maximum envelope limit")
                return False
            
            # Store envelope
            self._envelopes[envelope.trace_id].append(envelope)
            
            # Update correlation index
            if self.config.index_by_correlation_id and envelope.correlation_id:
                if envelope.correlation_id not in self._correlation_index:
                    self._correlation_index[envelope.correlation_id] = []
                if envelope.trace_id not in self._correlation_index[envelope.correlation_id]:
                    self._correlation_index[envelope.correlation_id].append(envelope.trace_id)
            
            # Cleanup if needed
            self._cleanup_if_needed()
            
            logger.info(f"Stored envelope {envelope.envelope_id} for trace {envelope.trace_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing envelope: {e}")
            return False
    
    def get_envelopes_by_trace(self, trace_id: str) -> List[StoredEnvelope]:
        """Get all envelopes for a trace ID"""
        self._cleanup_if_needed()
        return self._envelopes.get(trace_id, [])
    
    def get_envelopes_by_correlation(self, correlation_id: str) -> List[StoredEnvelope]:
        """Get all envelopes for a correlation ID"""
        self._cleanup_if_needed()
        
        if not self.config.index_by_correlation_id or correlation_id not in self._correlation_index:
            return []
        
        envelopes = []
        for trace_id in self._correlation_index[correlation_id]:
            envelopes.extend(self._envelopes.get(trace_id, []))
        
        # Sort by timestamp
        envelopes.sort(key=lambda x: x.timestamp)
        return envelopes
    
    def create_replay_session(self, trace_id: str, created_by: str) -> ReplaySession:
        """Create a new replay session"""
        session_id = str(uuid.uuid4())
        envelopes = self.get_envelopes_by_trace(trace_id)
        
        session = ReplaySession(
            session_id=session_id,
            trace_id=trace_id,
            created_at=now_utc(),
            created_by=created_by,
            status="created",
            total_envelopes=len(envelopes),
            replayed_envelopes=0,
            failed_envelopes=0,
            errors=[]
        )
        
        self._sessions[session_id] = session
        logger.info(f"Created replay session {session_id} for trace {trace_id}")
        return session
    
    def get_replay_session(self, session_id: str) -> Optional[ReplaySession]:
        """Get a replay session"""
        return self._sessions.get(session_id)
    
    def update_replay_session(self, session_id: str, **updates) -> bool:
        """Update a replay session"""
        if session_id not in self._sessions:
            return False
        
        session = self._sessions[session_id]
        for key, value in updates.items():
            if hasattr(session, key):
                setattr(session, key, value)
        
        return True
    
    def delete_trace(self, trace_id: str) -> bool:
        """Delete all envelopes for a trace"""
        if trace_id in self._envelopes:
            # Remove from correlation index
            for envelope in self._envelopes[trace_id]:
                if (envelope.correlation_id and 
                    envelope.correlation_id in self._correlation_index):
                    if trace_id in self._correlation_index[envelope.correlation_id]:
                        self._correlation_index[envelope.correlation_id].remove(trace_id)
                    if not self._correlation_index[envelope.correlation_id]:
                        del self._correlation_index[envelope.correlation_id]
            
            del self._envelopes[trace_id]
            logger.info(f"Deleted trace {trace_id}")
            return True
        return False
    
    def get_trace_ids(self) -> List[str]:
        """Get all stored trace IDs"""
        return list(self._envelopes.keys())
    
    def filter_traces(
        self,
        user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        status: Optional[str] = None,
        intent: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[str], int]:
        """
        Filter traces by various criteria (M5.3)
        
        Args:
            user_id: Filter by user ID
            start_date: Filter by start date (inclusive)
            end_date: Filter by end date (inclusive)
            status: Filter by status ("success", "error")
            intent: Filter by intent type
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            Tuple of (filtered_trace_ids, total_count)
        """
        filtered_traces = []
        
        for trace_id, envelopes in self._envelopes.items():
            if not envelopes:
                continue
            
            # Get first envelope for metadata
            first_envelope = envelopes[0]
            
            # Filter by user_id
            if user_id and first_envelope.user_id != user_id:
                continue
            
            # Filter by date range
            if start_date and first_envelope.timestamp < start_date:
                continue
            if end_date and first_envelope.timestamp > end_date:
                continue
            
            # Filter by status (check if any envelope has error)
            if status:
                has_error = any(e.error_message for e in envelopes)
                if status == "error" and not has_error:
                    continue
                if status == "success" and has_error:
                    continue
            
            # Filter by intent (check envelope data)
            if intent:
                intent_match = any(
                    e.envelope_data.get("intent") == intent 
                    for e in envelopes
                )
                if not intent_match:
                    continue
            
            filtered_traces.append(trace_id)
        
        # Sort by timestamp (most recent first)
        filtered_traces.sort(
            key=lambda tid: self._envelopes[tid][0].timestamp,
            reverse=True
        )
        
        total_count = len(filtered_traces)
        
        # Apply pagination
        paginated_traces = filtered_traces[offset:offset + limit]
        
        return paginated_traces, total_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get replay store statistics"""
        total_envelopes = sum(len(envelopes) for envelopes in self._envelopes.values())
        total_traces = len(self._envelopes)
        active_sessions = len([s for s in self._sessions.values() if s.status in ["created", "running"]])
        
        return {
            "total_envelopes": total_envelopes,
            "total_traces": total_traces,
            "active_sessions": active_sessions,
            "correlation_index_size": len(self._correlation_index),
            "store_type": "MemoryReplayStore"
        }
    
    def _cleanup_if_needed(self):
        """Clean up expired data if needed"""
        now = time.time()
        if now - self._last_cleanup < self.config.cleanup_interval_hours * 3600:
            return
        
        cutoff_time = now_utc() - timedelta(days=self.config.default_retention_days)
        removed_traces = []
        
        for trace_id, envelopes in self._envelopes.items():
            # Remove expired envelopes
            valid_envelopes = [e for e in envelopes if e.timestamp > cutoff_time]
            if len(valid_envelopes) != len(envelopes):
                self._envelopes[trace_id] = valid_envelopes
                if not valid_envelopes:
                    removed_traces.append(trace_id)
        
        # Remove empty traces
        for trace_id in removed_traces:
            del self._envelopes[trace_id]
        
        # Clean up old sessions
        session_cutoff = now_utc() - timedelta(hours=self.config.max_session_duration_hours)
        expired_sessions = [
            session_id for session_id, session in self._sessions.items()
            if session.created_at < session_cutoff
        ]
        
        for session_id in expired_sessions:
            del self._sessions[session_id]
        
        # Check total envelope limit
        total_envelopes = sum(len(envelopes) for envelopes in self._envelopes.values())
        if total_envelopes > self.config.max_stored_envelopes:
            self._cleanup_oldest_traces()
        
        self._last_cleanup = now
        logger.info(f"Cleanup completed: removed {len(removed_traces)} traces, {len(expired_sessions)} sessions")
    
    def _cleanup_oldest_traces(self):
        """Clean up oldest traces when at capacity"""
        if not self._envelopes:
            return
        
        # Sort traces by oldest envelope timestamp
        trace_ages = []
        for trace_id, envelopes in self._envelopes.items():
            if envelopes:
                oldest_timestamp = min(e.timestamp for e in envelopes)
                trace_ages.append((oldest_timestamp, trace_id))
        
        trace_ages.sort()
        
        # Remove oldest traces until under limit
        target_removal = max(1, len(self._envelopes) // 10)  # Remove 10% of traces
        
        for i in range(min(target_removal, len(trace_ages))):
            _, trace_id = trace_ages[i]
            self.delete_trace(trace_id)


class ReplayManager:
    """Main replay manager for event replay functionality"""
    
    def __init__(self, config: Optional[ReplayConfig] = None, store=None):
        self.config = config or ReplayConfig()
        self.store = store or MemoryReplayStore(self.config)
    
    def store_event_envelope(self, envelope_data: Dict[str, Any], trace_id: str,
                           correlation_id: str, event_type: str, source: str,
                           user_id: Optional[str] = None, processing_time_ms: Optional[float] = None,
                           status_code: Optional[int] = None, error_message: Optional[str] = None) -> bool:
        """Store an event envelope"""
        envelope = StoredEnvelope(
            envelope_id=str(uuid.uuid4()),
            trace_id=trace_id,
            correlation_id=correlation_id,
            envelope_data=envelope_data,
            timestamp=now_utc(),
            event_type=event_type,
            source=source,
            user_id=user_id,
            processing_time_ms=processing_time_ms,
            status_code=status_code,
            error_message=error_message
        )
        
        return self.store.store_envelope(envelope)
    
    def replay_trace(self, trace_id: str, created_by: str) -> ReplaySession:
        """Start replaying a trace"""
        session = self.store.create_replay_session(trace_id, created_by)
        
        # Update session status to running
        self.store.update_replay_session(session.session_id, status="running")
        
        try:
            envelopes = self.store.get_envelopes_by_trace(trace_id)
            replayed_count = 0
            failed_count = 0
            errors = []
            
            for envelope in envelopes:
                try:
                    # Here you would replay the envelope to the appropriate service
                    # For now, we'll just count it as successfully replayed
                    replayed_count += 1
                    logger.debug(f"Replayed envelope {envelope.envelope_id}")
                    
                except Exception as e:
                    failed_count += 1
                    error_msg = f"Failed to replay envelope {envelope.envelope_id}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            
            # Update session with results
            status = "completed" if failed_count == 0 else "failed"
            self.store.update_replay_session(
                session.session_id,
                status=status,
                replayed_envelopes=replayed_count,
                failed_envelopes=failed_count,
                errors=errors
            )
            
            logger.info(f"Replay session {session.session_id} completed: {replayed_count} replayed, {failed_count} failed")
            
        except Exception as e:
            # Update session with error
            self.store.update_replay_session(
                session.session_id,
                status="failed",
                errors=[f"Replay session failed: {str(e)}"]
            )
            logger.error(f"Replay session {session.session_id} failed: {e}")
        
        return self.store.get_replay_session(session.session_id)
    
    def get_replay_history(self, trace_id: str) -> List[Dict[str, Any]]:
        """Get replay history for a trace"""
        envelopes = self.store.get_envelopes_by_trace(trace_id)
        
        history = []
        for envelope in envelopes:
            history.append({
                "envelope_id": envelope.envelope_id,
                "timestamp": envelope.timestamp.isoformat(),
                "event_type": envelope.event_type,
                "source": envelope.source,
                "user_id": envelope.user_id,
                "processing_time_ms": envelope.processing_time_ms,
                "status_code": envelope.status_code,
                "error_message": envelope.error_message,
                "envelope_data": envelope.envelope_data
            })
        
        return history
    
    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of a trace"""
        envelopes = self.store.get_envelopes_by_trace(trace_id)
        
        if not envelopes:
            return {"trace_id": trace_id, "found": False}
        
        # Calculate summary statistics
        start_time = min(e.timestamp for e in envelopes)
        end_time = max(e.timestamp for e in envelopes)
        total_processing_time = sum(e.processing_time_ms or 0 for e in envelopes)
        
        event_types = {}
        sources = {}
        status_codes = {}
        
        for envelope in envelopes:
            event_types[envelope.event_type] = event_types.get(envelope.event_type, 0) + 1
            sources[envelope.source] = sources.get(envelope.source, 0) + 1
            if envelope.status_code:
                status_codes[envelope.status_code] = status_codes.get(envelope.status_code, 0) + 1
        
        return {
            "trace_id": trace_id,
            "found": True,
            "correlation_id": envelopes[0].correlation_id,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "total_envelopes": len(envelopes),
            "total_processing_time_ms": total_processing_time,
            "event_types": event_types,
            "sources": sources,
            "status_codes": status_codes,
            "user_id": envelopes[0].user_id
        }
    
    def delete_trace(self, trace_id: str) -> bool:
        """Delete a trace and all its envelopes"""
        return self.store.delete_trace(trace_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get replay system statistics"""
        stats = self.store.get_statistics()
        stats.update({
            "config": {
                "default_retention_days": self.config.default_retention_days,
                "max_envelopes_per_trace": self.config.max_envelopes_per_trace,
                "max_stored_envelopes": self.config.max_stored_envelopes,
                "compression_enabled": self.config.compression_enabled
            }
        })
        return stats


# Global instance for easy access
_default_manager: Optional[ReplayManager] = None


def get_replay_manager() -> ReplayManager:
    """Get the default replay manager"""
    global _default_manager
    if _default_manager is None:
        _default_manager = ReplayManager()
    return _default_manager


def initialize_replay(config: Optional[ReplayConfig] = None, store=None):
    """Initialize the global replay manager"""
    global _default_manager
    _default_manager = ReplayManager(config, store)
from .datetime_utils import now_utc, isoformat_utc
