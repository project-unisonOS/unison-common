"""
Idempotency management for duplicate request prevention

This module provides comprehensive idempotency key management to ensure
that duplicate requests don't cause unintended side effects in distributed systems.
"""

import hashlib
import json
import time
import uuid
from typing import Dict, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import logging

from .datetime_utils import now_utc

logger = logging.getLogger(__name__)


@dataclass
class IdempotencyRecord:
    """Record of an idempotent request"""
    idempotency_key: str
    response_data: Optional[Dict[str, Any]]
    status_code: int
    created_at: datetime
    expires_at: datetime
    request_hash: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IdempotencyRecord':
        """Create from dictionary from storage"""
        # Convert ISO strings back to datetime objects
        data['created_at'] = ensure_utc(datetime.fromisoformat(data['created_at']))
        data['expires_at'] = ensure_utc(datetime.fromisoformat(data['expires_at']))
        return cls(**data)


def ensure_utc(value: datetime) -> datetime:
    """Attach UTC tzinfo when a datetime is naive."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class IdempotencyConfig:
    """Configuration for idempotency management"""
    
    def __init__(self):
        self.default_ttl_seconds = 24 * 60 * 60  # 24 hours
        self.max_ttl_seconds = 7 * 24 * 60 * 60   # 7 days
        self.cleanup_interval_seconds = 60 * 60   # 1 hour
        self.max_records = 10000  # Maximum records to keep in memory
        self.key_length = 36  # UUID length
        self.hash_request_body = True  # Whether to hash request body for additional safety


class MemoryIdempotencyStore:
    """In-memory store for idempotency records"""
    
    def __init__(self, config: IdempotencyConfig):
        self.config = config
        self._records: Dict[str, IdempotencyRecord] = {}
        self._last_cleanup = time.time()
    
    def get(self, key: str) -> Optional[IdempotencyRecord]:
        """Get an idempotency record"""
        self._cleanup_expired()
        record = self._records.get(key)
        
        now = now_utc()
        if record and ensure_utc(record.expires_at) > now:
            return record
        elif record:
            # Remove expired record
            del self._records[key]
            
        return None
    
    def put(self, record: IdempotencyRecord) -> bool:
        """Store an idempotency record"""
        self._cleanup_expired()
        
        # Check if we're at capacity
        if len(self._records) >= self.config.max_records:
            self._cleanup_oldest()
        
        self._records[record.idempotency_key] = record
        return True
    
    def delete(self, key: str) -> bool:
        """Delete an idempotency record"""
        if key in self._records:
            del self._records[key]
            return True
        return False
    
    def _cleanup_expired(self):
        """Clean up expired records"""
        now = now_utc()
        expired_keys = [
            key for key, record in self._records.items()
            if ensure_utc(record.expires_at) <= now
        ]
        
        for key in expired_keys:
            del self._records[key]
        
        self._last_cleanup = time.time()
    
    def _cleanup_oldest(self):
        """Clean up oldest records when at capacity"""
        if not self._records:
            return
        
        # Sort by creation time and remove oldest 10%
        sorted_records = sorted(
            self._records.items(),
            key=lambda x: x[1].created_at
        )
        
        # Remove oldest 10% of records
        to_remove = max(1, len(sorted_records) // 10)
        for key, _ in sorted_records[:to_remove]:
            del self._records[key]
    
    def clear(self):
        """Clear all records"""
        self._records.clear()
    
    def size(self) -> int:
        """Get current number of records"""
        self._cleanup_expired()
        return len(self._records)


class RedisIdempotencyStore:
    """Redis-based store for idempotency records"""
    
    def __init__(self, config: IdempotencyConfig, redis_client=None):
        self.config = config
        self.redis_client = redis_client
        self.key_prefix = "unison:idempotency:"
    
    def get(self, key: str) -> Optional[IdempotencyRecord]:
        """Get an idempotency record from Redis"""
        if not self.redis_client:
            logger.warning("Redis client not available, falling back to None")
            return None
        
        try:
            data = self.redis_client.get(f"{self.key_prefix}{key}")
            if data:
                record_data = json.loads(data)
                return IdempotencyRecord.from_dict(record_data)
        except Exception as e:
            logger.error(f"Error getting idempotency record from Redis: {e}")
        
        return None
    
    def put(self, record: IdempotencyRecord) -> bool:
        """Store an idempotency record in Redis"""
        if not self.redis_client:
            logger.warning("Redis client not available, cannot store record")
            return False
        
        try:
            key = f"{self.key_prefix}{record.idempotency_key}"
            data = json.dumps(record.to_dict())
            
            # Calculate TTL in seconds
            ttl_seconds = int((ensure_utc(record.expires_at) - now_utc()).total_seconds())
            ttl_seconds = max(1, ttl_seconds)  # Ensure at least 1 second TTL
            
            self.redis_client.setex(key, ttl_seconds, data)
            return True
        except Exception as e:
            logger.error(f"Error storing idempotency record in Redis: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete an idempotency record from Redis"""
        if not self.redis_client:
            return False
        
        try:
            return bool(self.redis_client.delete(f"{self.key_prefix}{key}"))
        except Exception as e:
            logger.error(f"Error deleting idempotency record from Redis: {e}")
            return False
    
    def clear(self):
        """Clear all idempotency records (use with caution)"""
        if not self.redis_client:
            return
        
        try:
            pattern = f"{self.key_prefix}*"
            keys = self.redis_client.keys(pattern)
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            logger.error(f"Error clearing idempotency records from Redis: {e}")


class IdempotencyManager:
    """Main idempotency manager"""
    
    def __init__(self, config: Optional[IdempotencyConfig] = None, store=None):
        self.config = config or IdempotencyConfig()
        self.store = store or MemoryIdempotencyStore(self.config)
    
    def generate_key(self) -> str:
        """Generate a new idempotency key"""
        return str(uuid.uuid4())
    
    def hash_request(self, method: str, url: str, body: Optional[Dict[str, Any]], 
                    user_id: Optional[str] = None) -> str:
        """Generate a hash from request components for additional safety"""
        if not self.config.hash_request_body:
            return ""
        
        # Create normalized request data
        request_data = {
            "method": method.upper(),
            "url": url.lower(),
            "user_id": user_id or ""
        }
        
        # Sort body keys for consistent hashing
        if body:
            sorted_body = json.dumps(body, sort_keys=True, separators=(',', ':'))
            request_data["body"] = sorted_body
        else:
            request_data["body"] = ""
        
        # Generate hash
        content = json.dumps(request_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(content.encode()).hexdigest()
    
    def check_idempotency(self, idempotency_key: str, method: str, url: str,
                         body: Optional[Dict[str, Any]] = None,
                         user_id: Optional[str] = None,
                         ttl_seconds: Optional[int] = None) -> Tuple[bool, Optional[IdempotencyRecord]]:
        """Check if a request is idempotent"""
        
        # Get existing record
        record = self.store.get(idempotency_key)
        
        if record:
            # Check if request hash matches (additional safety)
            if self.config.hash_request_body:
                current_hash = self.hash_request(method, url, body, user_id)
                if record.request_hash and current_hash != record.request_hash:
                    logger.warning(f"Idempotency key {idempotency_key} reused with different request")
                    # This could be a key collision or misuse
                    # For safety, we'll treat it as a new request
                    return False, None
            
            # Record exists and matches
            logger.info(f"Idempotent request detected: {idempotency_key}")
            return True, record
        
        # No existing record
        return False, None
    
    def create_record(self, idempotency_key: str, response_data: Optional[Dict[str, Any]],
                      status_code: int, method: str, url: str,
                      body: Optional[Dict[str, Any]] = None,
                      user_id: Optional[str] = None,
                      ttl_seconds: Optional[int] = None) -> IdempotencyRecord:
        """Create a new idempotency record"""
        
        # Set TTL
        if ttl_seconds is None:
            ttl_seconds = self.config.default_ttl_seconds
        ttl_seconds = min(ttl_seconds, self.config.max_ttl_seconds)
        
        # Create record
        now = now_utc()
        request_hash = None
        if self.config.hash_request_body:
            request_hash = self.hash_request(method, url, body, user_id)
        
        record = IdempotencyRecord(
            idempotency_key=idempotency_key,
            response_data=response_data,
            status_code=status_code,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            request_hash=request_hash,
            user_id=user_id,
            endpoint=url
        )
        
        # Store record
        self.store.put(record)
        
        logger.info(f"Created idempotency record: {idempotency_key} for user {user_id}")
        return record
    
    def invalidate_key(self, idempotency_key: str) -> bool:
        """Invalidate an idempotency key"""
        return self.store.delete(idempotency_key)
    
    def cleanup_expired(self):
        """Clean up expired records"""
        if hasattr(self.store, '_cleanup_expired'):
            self.store._cleanup_expired()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get idempotency statistics"""
        stats = {
            "store_type": type(self.store).__name__,
            "max_records": self.config.max_records,
            "default_ttl": self.config.default_ttl_seconds
        }
        
        if hasattr(self.store, 'size'):
            stats["current_records"] = self.store.size()
        
        return stats


# Global instance for easy access
_default_manager: Optional[IdempotencyManager] = None


def get_idempotency_manager() -> IdempotencyManager:
    """Get the default idempotency manager"""
    global _default_manager
    if _default_manager is None:
        _default_manager = IdempotencyManager()
    return _default_manager


def initialize_idempotency(config: Optional[IdempotencyConfig] = None, store=None):
    """Initialize the global idempotency manager"""
    global _default_manager
    _default_manager = IdempotencyManager(config, store)


def validate_idempotency_key(key: str) -> bool:
    """Validate an idempotency key format"""
    if not key:
        return False
    
    # Check if it's a valid UUID
    try:
        uuid.UUID(key)
        return True
    except ValueError:
        return False


def extract_idempotency_key(headers: Dict[str, str]) -> Optional[str]:
    """Extract idempotency key from headers (case-insensitive)."""
    if not headers:
        return None

    normalized = {name.lower(): value for name, value in headers.items()}

    for header_name in ("idempotency-key", "x-idempotency-key"):
        key = normalized.get(header_name)
        if key and validate_idempotency_key(key):
            return key

    return None
