"""
Event replay endpoints for the orchestrator

This module provides FastAPI endpoints for event replay functionality,
including replay history, session management, and trace operations.
"""

from typing import Dict, Any, List, Optional
from fastapi import HTTPException, Depends, Query
from fastapi.responses import JSONResponse
import logging

from .replay_store import (
    ReplayManager,
    ReplaySession,
    get_replay_manager,
    initialize_replay,
    ReplayConfig
)
from .auth import verify_token, require_admin

logger = logging.getLogger(__name__)


async def replay_trace_by_id(
    trace_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Replay all events for a specific trace ID"""
    
    if not trace_id or not trace_id.strip():
        raise HTTPException(
            status_code=400,
            detail="trace_id is required and cannot be empty"
        )
    
    replay_manager = get_replay_manager()
    
    # Check if trace exists
    trace_summary = replay_manager.get_trace_summary(trace_id.strip())
    if not trace_summary.get("found", False):
        raise HTTPException(
            status_code=404,
            detail=f"No trace found with ID: {trace_id.strip()}"
        )
    
    try:
        # Start replay session
        session = replay_manager.replay_trace(trace_id.strip(), current_user.get("username"))
        
        return {
            "session_id": session.session_id,
            "trace_id": session.trace_id,
            "status": session.status,
            "created_at": session.created_at.isoformat(),
            "created_by": session.created_by,
            "total_envelopes": session.total_envelopes,
            "replayed_envelopes": session.replayed_envelopes,
            "failed_envelopes": session.failed_envelopes,
            "errors": session.errors,
            "trace_summary": trace_summary
        }
        
    except Exception as e:
        logger.error(f"Error replaying trace {trace_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to replay trace: {str(e)}"
        )


async def get_replay_history(
    trace_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Get the replay history for a specific trace ID"""
    
    if not trace_id or not trace_id.strip():
        raise HTTPException(
            status_code=400,
            detail="trace_id is required and cannot be empty"
        )
    
    replay_manager = get_replay_manager()
    
    try:
        # Get trace summary
        trace_summary = replay_manager.get_trace_summary(trace_id.strip())
        if not trace_summary.get("found", False):
            raise HTTPException(
                status_code=404,
                detail=f"No trace found with ID: {trace_id.strip()}"
            )
        
        # Get replay history
        history = replay_manager.get_replay_history(trace_id.strip())
        
        return {
            "trace_id": trace_id.strip(),
            "trace_summary": trace_summary,
            "envelopes": history,
            "total_envelopes": len(history)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting replay history for trace {trace_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get replay history: {str(e)}"
        )


async def get_trace_summary(
    trace_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Get summary information for a specific trace"""
    
    if not trace_id or not trace_id.strip():
        raise HTTPException(
            status_code=400,
            detail="trace_id is required and cannot be empty"
        )
    
    replay_manager = get_replay_manager()
    
    try:
        summary = replay_manager.get_trace_summary(trace_id.strip())
        
        if not summary.get("found", False):
            raise HTTPException(
                status_code=404,
                detail=f"No trace found with ID: {trace_id.strip()}"
            )
        
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting trace summary for {trace_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get trace summary: {str(e)}"
        )


async def list_traces(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of traces to return"),
    offset: int = Query(0, ge=0, description="Number of traces to skip"),
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """List all stored traces with pagination"""
    
    replay_manager = get_replay_manager()
    
    try:
        # Get all trace IDs
        trace_ids = replay_manager.store.get_trace_ids()
        
        # Apply pagination
        total_traces = len(trace_ids)
        paginated_ids = trace_ids[offset:offset + limit]
        
        # Get summaries for each trace
        traces = []
        for trace_id in paginated_ids:
            summary = replay_manager.get_trace_summary(trace_id)
            if summary.get("found", False):
                traces.append(summary)
        
        # Sort by start time (newest first)
        traces.sort(key=lambda x: x.get("start_time", ""), reverse=True)
        
        return {
            "traces": traces,
            "pagination": {
                "total": total_traces,
                "limit": limit,
                "offset": offset,
                "has_more": offset + limit < total_traces
            }
        }
        
    except Exception as e:
        logger.error(f"Error listing traces: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list traces: {str(e)}"
        )


async def delete_trace(
    trace_id: str,
    current_user: Dict[str, Any] = Depends(require_admin)
) -> Dict[str, Any]:
    """Delete a trace and all its envelopes (admin only)"""
    
    if not trace_id or not trace_id.strip():
        raise HTTPException(
            status_code=400,
            detail="trace_id is required and cannot be empty"
        )
    
    replay_manager = get_replay_manager()
    
    try:
        # Check if trace exists
        trace_summary = replay_manager.get_trace_summary(trace_id.strip())
        if not trace_summary.get("found", False):
            raise HTTPException(
                status_code=404,
                detail=f"No trace found with ID: {trace_id.strip()}"
            )
        
        # Delete the trace
        success = replay_manager.delete_trace(trace_id.strip())
        
        if success:
            logger.info(f"Trace {trace_id.strip()} deleted by user {current_user.get('username')}")
            return {
                "trace_id": trace_id.strip(),
                "deleted": True,
                "deleted_by": current_user.get("username"),
                "message": "Trace and all associated envelopes have been deleted"
            }
        else:
            raise HTTPException(
                status_code=500,
                detail="Failed to delete trace"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting trace {trace_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete trace: {str(e)}"
        )


async def get_replay_statistics(
    current_user: Dict[str, Any] = Depends(require_admin)
) -> Dict[str, Any]:
    """Get replay system statistics (admin only)"""
    
    replay_manager = get_replay_manager()
    
    try:
        stats = replay_manager.get_statistics()
        
        return {
            "replay_system": stats,
            "requested_by": current_user.get("username"),
            "timestamp": replay_manager.store._last_cleanup
        }
        
    except Exception as e:
        logger.error(f"Error getting replay statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get replay statistics: {str(e)}"
        )


async def get_replay_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Get details of a specific replay session"""
    
    if not session_id or not session_id.strip():
        raise HTTPException(
            status_code=400,
            detail="session_id is required and cannot be empty"
        )
    
    replay_manager = get_replay_manager()
    
    try:
        session = replay_manager.store.get_replay_session(session_id.strip())
        
        if not session:
            raise HTTPException(
                status_code=404,
                detail=f"No replay session found with ID: {session_id.strip()}"
            )
        
        # Check if user has permission to view this session
        if (session.created_by != current_user.get("username") and 
            "admin" not in current_user.get("roles", [])):
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to view this replay session"
            )
        
        return {
            "session_id": session.session_id,
            "trace_id": session.trace_id,
            "created_at": session.created_at.isoformat(),
            "created_by": session.created_by,
            "status": session.status,
            "total_envelopes": session.total_envelopes,
            "replayed_envelopes": session.replayed_envelopes,
            "failed_envelopes": session.failed_envelopes,
            "errors": session.errors
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting replay session {session_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get replay session: {str(e)}"
        )


# Utility function to store envelopes during processing
def store_processing_envelope(envelope_data: Dict[str, Any], trace_id: str,
                             correlation_id: str, event_type: str, source: str,
                             user_id: Optional[str] = None, processing_time_ms: Optional[float] = None,
                             status_code: Optional[int] = None, error_message: Optional[str] = None) -> bool:
    """Store an envelope during processing"""
    try:
        replay_manager = get_replay_manager()
        return replay_manager.store_event_envelope(
            envelope_data=envelope_data,
            trace_id=trace_id,
            correlation_id=correlation_id,
            event_type=event_type,
            source=source,
            user_id=user_id,
            processing_time_ms=processing_time_ms,
            status_code=status_code,
            error_message=error_message
        )
    except Exception as e:
        logger.error(f"Error storing processing envelope: {e}")
        return False
