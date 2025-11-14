"""
Storage Durability Module

Provides Write-Ahead Log (WAL), TTL, PII scrubbing, and crash recovery
for the context-graph service.
"""

import sqlite3
import logging
import os
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pathlib import Path
import threading

from .datetime_utils import now_utc, isoformat_utc

logger = logging.getLogger(__name__)


class DurabilityConfig:
    """Configuration for durability features"""
    
    # WAL settings
    WAL_ENABLED = os.getenv("DURABILITY_WAL_ENABLED", "true").lower() == "true"
    WAL_CHECKPOINT_INTERVAL = int(os.getenv("DURABILITY_WAL_CHECKPOINT", "1000"))
    WAL_SYNC_MODE = os.getenv("DURABILITY_WAL_SYNC", "NORMAL")  # FULL, NORMAL, OFF
    
    # TTL settings
    TTL_ENABLED = os.getenv("DURABILITY_TTL_ENABLED", "true").lower() == "true"
    TTL_DEFAULT_DAYS = int(os.getenv("DURABILITY_TTL_DAYS", "30"))
    TTL_CLEANUP_INTERVAL = int(os.getenv("DURABILITY_TTL_INTERVAL", "3600"))  # 1 hour
    
    # PII scrubbing
    PII_SCRUBBING_ENABLED = os.getenv("DURABILITY_PII_ENABLED", "true").lower() == "true"
    PII_SCRUBBING_AFTER_DAYS = int(os.getenv("DURABILITY_PII_AFTER_DAYS", "90"))
    PII_SCRUBBING_INTERVAL = int(os.getenv("DURABILITY_PII_INTERVAL", "86400"))  # 1 day
    
    # Recovery
    RECOVERY_ENABLED = os.getenv("DURABILITY_RECOVERY_ENABLED", "true").lower() == "true"
    RECOVERY_VERIFY_CHECKSUMS = os.getenv("DURABILITY_VERIFY_CHECKSUMS", "true").lower() == "true"


class DurabilityMetrics:
    """Metrics for durability features"""
    
    def __init__(self):
        self.wal_checkpoints = 0
        self.wal_checkpoint_duration_ms = 0.0
        self.ttl_records_deleted = 0
        self.ttl_cleanup_duration_ms = 0.0
        self.pii_records_scrubbed = 0
        self.pii_scrubbing_duration_ms = 0.0
        self.recovery_attempts = 0
        self.recovery_duration_ms = 0.0
        self.recovery_transactions_replayed = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            "wal_checkpoints": self.wal_checkpoints,
            "wal_checkpoint_duration_ms": self.wal_checkpoint_duration_ms,
            "ttl_records_deleted": self.ttl_records_deleted,
            "ttl_cleanup_duration_ms": self.ttl_cleanup_duration_ms,
            "pii_records_scrubbed": self.pii_records_scrubbed,
            "pii_scrubbing_duration_ms": self.pii_scrubbing_duration_ms,
            "recovery_attempts": self.recovery_attempts,
            "recovery_duration_ms": self.recovery_duration_ms,
            "recovery_transactions_replayed": self.recovery_transactions_replayed
        }


class WALManager:
    """Manages Write-Ahead Log for SQLite database"""
    
    def __init__(self, db_path: str, config: DurabilityConfig, metrics: DurabilityMetrics):
        self.db_path = db_path
        self.config = config
        self.metrics = metrics
        self._transaction_count = 0
        self._lock = threading.Lock()
    
    def enable_wal(self, conn: sqlite3.Connection) -> bool:
        """
        Enable WAL mode on database connection
        
        Args:
            conn: SQLite connection
            
        Returns:
            True if WAL enabled successfully
        """
        if not self.config.WAL_ENABLED:
            logger.info("WAL mode disabled by configuration")
            return False
        
        try:
            # Enable WAL mode
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            result = cursor.fetchone()
            
            if result and result[0] == 'wal':
                logger.info("✅ WAL mode enabled")
                
                # Configure WAL settings
                cursor.execute(f"PRAGMA synchronous={self.config.WAL_SYNC_MODE}")
                cursor.execute(f"PRAGMA wal_autocheckpoint={self.config.WAL_CHECKPOINT_INTERVAL}")
                
                # Get WAL info
                cursor.execute("PRAGMA wal_checkpoint(PASSIVE)")
                
                logger.info(f"WAL sync mode: {self.config.WAL_SYNC_MODE}")
                logger.info(f"WAL autocheckpoint: {self.config.WAL_CHECKPOINT_INTERVAL} transactions")
                
                return True
            else:
                logger.warning(f"Failed to enable WAL mode: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Error enabling WAL mode: {e}")
            return False
    
    def checkpoint(self, conn: sqlite3.Connection, mode: str = "PASSIVE") -> bool:
        """
        Perform WAL checkpoint
        
        Args:
            conn: SQLite connection
            mode: Checkpoint mode (PASSIVE, FULL, RESTART, TRUNCATE)
            
        Returns:
            True if checkpoint successful
        """
        if not self.config.WAL_ENABLED:
            return False
        
        try:
            start_time = time.time()
            
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA wal_checkpoint({mode})")
            result = cursor.fetchone()
            
            duration_ms = (time.time() - start_time) * 1000
            
            with self._lock:
                self.metrics.wal_checkpoints += 1
                self.metrics.wal_checkpoint_duration_ms = duration_ms
            
            if result:
                busy, log_size, checkpointed = result
                logger.info(f"WAL checkpoint ({mode}): busy={busy}, log_size={log_size}, checkpointed={checkpointed}, duration={duration_ms:.2f}ms")
                return busy == 0
            
            return True
            
        except Exception as e:
            logger.error(f"Error during WAL checkpoint: {e}")
            return False
    
    def get_wal_info(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Get WAL file information"""
        if not self.config.WAL_ENABLED:
            return {"enabled": False}
        
        try:
            wal_path = f"{self.db_path}-wal"
            wal_exists = os.path.exists(wal_path)
            wal_size = os.path.getsize(wal_path) if wal_exists else 0
            
            return {
                "enabled": True,
                "wal_exists": wal_exists,
                "wal_size_bytes": wal_size,
                "wal_path": wal_path,
                "transaction_count": self._transaction_count
            }
        except Exception as e:
            logger.error(f"Error getting WAL info: {e}")
            return {"enabled": True, "error": str(e)}
    
    def increment_transaction_count(self):
        """Increment transaction counter"""
        with self._lock:
            self._transaction_count += 1
    
    def cleanup_on_shutdown(self, conn: sqlite3.Connection):
        """Cleanup WAL on graceful shutdown"""
        if not self.config.WAL_ENABLED:
            return
        
        try:
            logger.info("Performing final WAL checkpoint before shutdown...")
            self.checkpoint(conn, mode="TRUNCATE")
            logger.info("✅ WAL cleanup complete")
        except Exception as e:
            logger.error(f"Error during WAL cleanup: {e}")


class TTLManager:
    """Manages Time-To-Live (TTL) for automatic data cleanup"""
    
    def __init__(self, db_path: str, config: DurabilityConfig, metrics: DurabilityMetrics):
        self.db_path = db_path
        self.config = config
        self.metrics = metrics
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
    
    def add_ttl_columns(self, conn: sqlite3.Connection) -> bool:
        """
        Add TTL columns to existing tables
        
        Args:
            conn: SQLite connection
            
        Returns:
            True if columns added successfully
        """
        if not self.config.TTL_ENABLED:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Check if expires_at column exists
            cursor.execute("PRAGMA table_info(event_traces)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'expires_at' not in columns:
                logger.info("Adding TTL columns to event_traces table...")
                cursor.execute("ALTER TABLE event_traces ADD COLUMN expires_at TEXT")
                
                # Create index for efficient cleanup
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_expires_at ON event_traces(expires_at)")
                
                # Set expires_at for existing records
                cursor.execute(f"""
                    UPDATE event_traces 
                    SET expires_at = datetime(created_at, '+{self.config.TTL_DEFAULT_DAYS} days')
                    WHERE expires_at IS NULL
                """)
                
                conn.commit()
                logger.info("✅ TTL columns added")
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding TTL columns: {e}")
            return False
    
    def calculate_expiry(self, days: Optional[int] = None) -> str:
        """
        Calculate expiry timestamp
        
        Args:
            days: Days until expiry (uses default if None)
            
        Returns:
            ISO format expiry timestamp
        """
        ttl_days = days or self.config.TTL_DEFAULT_DAYS
        expiry = now_utc() + timedelta(days=ttl_days)
        return expiry.isoformat()
    
    def cleanup_expired(self, conn: sqlite3.Connection) -> int:
        """
        Delete expired records
        
        Args:
            conn: SQLite connection
            
        Returns:
            Number of records deleted
        """
        if not self.config.TTL_ENABLED:
            return 0
        
        try:
            start_time = time.time()
            
            cursor = conn.cursor()
            
            # Delete expired records in batches
            now = isoformat_utc()
            
            cursor.execute("""
                DELETE FROM event_traces 
                WHERE expires_at IS NOT NULL 
                AND expires_at < ?
            """, (now,))
            
            deleted_count = cursor.rowcount
            
            conn.commit()
            
            duration_ms = (time.time() - start_time) * 1000
            
            with threading.Lock():
                self.metrics.ttl_records_deleted += deleted_count
                self.metrics.ttl_cleanup_duration_ms = duration_ms
            
            if deleted_count > 0:
                logger.info(f"🗑️  TTL cleanup: deleted {deleted_count} expired records ({duration_ms:.2f}ms)")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error during TTL cleanup: {e}")
            return 0
    
    def start_cleanup_job(self):
        """Start background cleanup job"""
        if not self.config.TTL_ENABLED:
            return
        
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            logger.warning("TTL cleanup job already running")
            return
        
        logger.info(f"Starting TTL cleanup job (interval: {self.config.TTL_CLEANUP_INTERVAL}s)")
        
        self._stop_cleanup.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_loop(self):
        """Background cleanup loop"""
        while not self._stop_cleanup.is_set():
            try:
                # Wait for interval or stop signal
                if self._stop_cleanup.wait(self.config.TTL_CLEANUP_INTERVAL):
                    break
                
                # Perform cleanup
                conn = sqlite3.connect(self.db_path)
                self.cleanup_expired(conn)
                conn.close()
                
            except Exception as e:
                logger.error(f"Error in TTL cleanup loop: {e}")
    
    def stop_cleanup_job(self):
        """Stop background cleanup job"""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            logger.info("Stopping TTL cleanup job...")
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=5)
            logger.info("✅ TTL cleanup job stopped")
    
    def get_ttl_stats(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Get TTL statistics"""
        if not self.config.TTL_ENABLED:
            return {"enabled": False}
        
        try:
            cursor = conn.cursor()
            
            # Count expired records
            now = isoformat_utc()
            cursor.execute("""
                SELECT COUNT(*) FROM event_traces 
                WHERE expires_at IS NOT NULL AND expires_at < ?
            """, (now,))
            expired_count = cursor.fetchone()[0]
            
            # Count records with TTL
            cursor.execute("SELECT COUNT(*) FROM event_traces WHERE expires_at IS NOT NULL")
            ttl_count = cursor.fetchone()[0]
            
            # Get oldest expiry
            cursor.execute("""
                SELECT MIN(expires_at) FROM event_traces 
                WHERE expires_at IS NOT NULL
            """)
            oldest_expiry = cursor.fetchone()[0]
            
            return {
                "enabled": True,
                "ttl_default_days": self.config.TTL_DEFAULT_DAYS,
                "cleanup_interval_seconds": self.config.TTL_CLEANUP_INTERVAL,
                "records_with_ttl": ttl_count,
                "expired_records": expired_count,
                "oldest_expiry": oldest_expiry,
                "cleanup_job_running": self._cleanup_thread and self._cleanup_thread.is_alive()
            }
            
        except Exception as e:
            logger.error(f"Error getting TTL stats: {e}")
            return {"enabled": True, "error": str(e)}


class PIIScrubber:
    """Manages PII scrubbing for privacy compliance"""
    
    def __init__(self, db_path: str, config: DurabilityConfig, metrics: DurabilityMetrics):
        self.db_path = db_path
        self.config = config
        self.metrics = metrics
        self._scrubbing_thread = None
        self._stop_scrubbing = threading.Event()
    
    def add_scrubbing_columns(self, conn: sqlite3.Connection) -> bool:
        """
        Add scrubbing tracking columns to tables
        
        Args:
            conn: SQLite connection
            
        Returns:
            True if columns added successfully
        """
        if not self.config.PII_SCRUBBING_ENABLED:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Check if scrubbed_at column exists
            cursor.execute("PRAGMA table_info(event_traces)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'scrubbed_at' not in columns:
                logger.info("Adding PII scrubbing columns to event_traces table...")
                cursor.execute("ALTER TABLE event_traces ADD COLUMN scrubbed_at TEXT")
                
                # Create index for efficient scrubbing queries
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scrubbed_at ON event_traces(scrubbed_at)")
                
                conn.commit()
                logger.info("✅ PII scrubbing columns added")
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding scrubbing columns: {e}")
            return False
    
    def hash_person_id(self, person_id: str) -> str:
        """
        Hash person_id for anonymization
        
        Args:
            person_id: Original person ID
            
        Returns:
            Hashed person ID
        """
        # Use SHA-256 hash
        hash_obj = hashlib.sha256(person_id.encode())
        return f"SCRUBBED_{hash_obj.hexdigest()[:16]}"
    
    def scrub_record(self, cursor: sqlite3.Cursor, trace_id: str) -> bool:
        """
        Scrub PII from a single record
        
        Args:
            cursor: Database cursor
            trace_id: Trace ID to scrub
            
        Returns:
            True if scrubbing successful
        """
        try:
            # Get current record
            cursor.execute("""
                SELECT person_id, event_data, context_snapshot 
                FROM event_traces 
                WHERE trace_id = ?
            """, (trace_id,))
            
            row = cursor.fetchone()
            if not row:
                return False
            
            person_id, event_data_str, context_snapshot_str = row
            
            # Hash person_id
            scrubbed_person_id = self.hash_person_id(person_id)
            
            # Parse and scrub event_data
            event_data = json.loads(event_data_str) if event_data_str else {}
            scrubbed_event_data = self._scrub_dict(event_data)
            
            # Parse and scrub context_snapshot
            context_snapshot = json.loads(context_snapshot_str) if context_snapshot_str else None
            scrubbed_context = self._scrub_dict(context_snapshot) if context_snapshot else None
            
            # Update record
            cursor.execute("""
                UPDATE event_traces 
                SET person_id = ?,
                    event_data = ?,
                    context_snapshot = ?,
                    scrubbed_at = ?
                WHERE trace_id = ?
            """, (
                scrubbed_person_id,
                json.dumps(scrubbed_event_data),
                json.dumps(scrubbed_context) if scrubbed_context else None,
                isoformat_utc(),
                trace_id
            ))
            
            return True
            
        except Exception as e:
            logger.error(f"Error scrubbing record {trace_id}: {e}")
            return False
    
    def _scrub_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scrub PII fields from dictionary
        
        Args:
            data: Dictionary to scrub
            
        Returns:
            Scrubbed dictionary
        """
        if not data:
            return data
        
        scrubbed = data.copy()
        
        # Fields to remove completely
        remove_fields = [
            'device_id', 'ip_address', 'mac_address',
            'email', 'phone', 'address', 'ssn',
            'credit_card', 'password', 'token'
        ]
        
        # Fields to generalize
        generalize_fields = {
            'location': self._generalize_location,
            'gps_coordinates': self._generalize_coordinates,
            'timestamp': self._generalize_timestamp
        }
        
        # Remove sensitive fields
        for field in remove_fields:
            if field in scrubbed:
                scrubbed[field] = None
        
        # Generalize fields
        for field, generalizer in generalize_fields.items():
            if field in scrubbed and scrubbed[field]:
                scrubbed[field] = generalizer(scrubbed[field])
        
        # Recursively scrub nested dictionaries
        for key, value in scrubbed.items():
            if isinstance(value, dict):
                scrubbed[key] = self._scrub_dict(value)
            elif isinstance(value, list):
                scrubbed[key] = [
                    self._scrub_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
        
        return scrubbed
    
    def _generalize_location(self, location: Any) -> str:
        """Generalize location to city level"""
        if isinstance(location, str):
            # Extract city if format is "City, State, Country"
            parts = location.split(',')
            return parts[0].strip() if parts else "LOCATION_SCRUBBED"
        return "LOCATION_SCRUBBED"
    
    def _generalize_coordinates(self, coords: Any) -> str:
        """Generalize GPS coordinates to approximate area"""
        if isinstance(coords, dict) and 'lat' in coords and 'lon' in coords:
            # Round to 1 decimal place (~11km precision)
            lat = round(float(coords['lat']), 1)
            lon = round(float(coords['lon']), 1)
            return f"~{lat},~{lon}"
        return "COORDS_SCRUBBED"
    
    def _generalize_timestamp(self, timestamp: Any) -> str:
        """Generalize timestamp to date only"""
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d')
            except:
                pass
        return "DATE_SCRUBBED"
    
    def scrub_old_records(self, conn: sqlite3.Connection, batch_size: int = 100) -> int:
        """
        Scrub PII from old records
        
        Args:
            conn: SQLite connection
            batch_size: Number of records to scrub per batch
            
        Returns:
            Number of records scrubbed
        """
        if not self.config.PII_SCRUBBING_ENABLED:
            return 0
        
        try:
            start_time = time.time()
            
            cursor = conn.cursor()
            
            # Find records older than scrubbing threshold that haven't been scrubbed
            cutoff_date = (
                now_utc() - timedelta(days=self.config.PII_SCRUBBING_AFTER_DAYS)
            ).isoformat()
            
            cursor.execute("""
                SELECT trace_id FROM event_traces 
                WHERE created_at < ? 
                AND scrubbed_at IS NULL
                LIMIT ?
            """, (cutoff_date, batch_size))
            
            trace_ids = [row[0] for row in cursor.fetchall()]
            
            scrubbed_count = 0
            for trace_id in trace_ids:
                if self.scrub_record(cursor, trace_id):
                    scrubbed_count += 1
            
            conn.commit()
            
            duration_ms = (time.time() - start_time) * 1000
            
            with threading.Lock():
                self.metrics.pii_records_scrubbed += scrubbed_count
                self.metrics.pii_scrubbing_duration_ms = duration_ms
            
            if scrubbed_count > 0:
                logger.info(f"🔒 PII scrubbing: scrubbed {scrubbed_count} records ({duration_ms:.2f}ms)")
            
            return scrubbed_count
            
        except Exception as e:
            logger.error(f"Error during PII scrubbing: {e}")
            return 0
    
    def start_scrubbing_job(self):
        """Start background scrubbing job"""
        if not self.config.PII_SCRUBBING_ENABLED:
            return
        
        if self._scrubbing_thread and self._scrubbing_thread.is_alive():
            logger.warning("PII scrubbing job already running")
            return
        
        logger.info(f"Starting PII scrubbing job (interval: {self.config.PII_SCRUBBING_INTERVAL}s)")
        
        self._stop_scrubbing.clear()
        self._scrubbing_thread = threading.Thread(target=self._scrubbing_loop, daemon=True)
        self._scrubbing_thread.start()
    
    def _scrubbing_loop(self):
        """Background scrubbing loop"""
        while not self._stop_scrubbing.is_set():
            try:
                # Wait for interval or stop signal
                if self._stop_scrubbing.wait(self.config.PII_SCRUBBING_INTERVAL):
                    break
                
                # Perform scrubbing
                conn = sqlite3.connect(self.db_path)
                self.scrub_old_records(conn)
                conn.close()
                
            except Exception as e:
                logger.error(f"Error in PII scrubbing loop: {e}")
    
    def stop_scrubbing_job(self):
        """Stop background scrubbing job"""
        if self._scrubbing_thread and self._scrubbing_thread.is_alive():
            logger.info("Stopping PII scrubbing job...")
            self._stop_scrubbing.set()
            self._scrubbing_thread.join(timeout=5)
            logger.info("✅ PII scrubbing job stopped")
    
    def get_scrubbing_stats(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Get PII scrubbing statistics"""
        if not self.config.PII_SCRUBBING_ENABLED:
            return {"enabled": False}
        
        try:
            cursor = conn.cursor()
            
            # Count scrubbed records
            cursor.execute("SELECT COUNT(*) FROM event_traces WHERE scrubbed_at IS NOT NULL")
            scrubbed_count = cursor.fetchone()[0]
            
            # Count records pending scrubbing
            cutoff_date = (
                now_utc() - timedelta(days=self.config.PII_SCRUBBING_AFTER_DAYS)
            ).isoformat()
            cursor.execute("""
                SELECT COUNT(*) FROM event_traces 
                WHERE created_at < ? AND scrubbed_at IS NULL
            """, (cutoff_date,))
            pending_count = cursor.fetchone()[0]
            
            # Get oldest scrubbed record
            cursor.execute("SELECT MIN(scrubbed_at) FROM event_traces WHERE scrubbed_at IS NOT NULL")
            oldest_scrubbed = cursor.fetchone()[0]
            
            return {
                "enabled": True,
                "scrubbing_after_days": self.config.PII_SCRUBBING_AFTER_DAYS,
                "scrubbing_interval_seconds": self.config.PII_SCRUBBING_INTERVAL,
                "records_scrubbed": scrubbed_count,
                "records_pending_scrubbing": pending_count,
                "oldest_scrubbed_at": oldest_scrubbed,
                "scrubbing_job_running": self._scrubbing_thread and self._scrubbing_thread.is_alive()
            }
            
        except Exception as e:
            logger.error(f"Error getting scrubbing stats: {e}")
            return {"enabled": True, "error": str(e)}


class RecoveryManager:
    """Manages crash recovery"""
    
    def __init__(self, db_path: str, config: DurabilityConfig, metrics: DurabilityMetrics):
        self.db_path = db_path
        self.config = config
        self.metrics = metrics
    
    def check_for_recovery(self) -> bool:
        """
        Check if recovery is needed (WAL file exists)
        
        Returns:
            True if recovery was performed
        """
        if not self.config.RECOVERY_ENABLED:
            return False
        
        wal_path = f"{self.db_path}-wal"
        
        if os.path.exists(wal_path):
            wal_size = os.path.getsize(wal_path)
            logger.warning(f"⚠️  WAL file found ({wal_size} bytes), recovery needed")
            return True
        
        return False
    
    def recover(self) -> bool:
        """
        Perform crash recovery
        
        Returns:
            True if recovery successful
        """
        if not self.config.RECOVERY_ENABLED:
            return False
        
        try:
            start_time = time.time()
            
            logger.info("🔄 Starting crash recovery...")
            
            # Connect to database (SQLite automatically replays WAL)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Verify database integrity
            if self.config.RECOVERY_VERIFY_CHECKSUMS:
                logger.info("Verifying database integrity...")
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()
                
                if result and result[0] != 'ok':
                    logger.error(f"❌ Database integrity check failed: {result}")
                    conn.close()
                    return False
                
                logger.info("✅ Database integrity verified")
            
            # Checkpoint WAL to apply all transactions
            logger.info("Checkpointing WAL...")
            cursor.execute("PRAGMA wal_checkpoint(FULL)")
            result = cursor.fetchone()
            
            if result:
                busy, log_size, checkpointed = result
                logger.info(f"WAL checkpoint: log_size={log_size}, checkpointed={checkpointed}")
                
                with threading.Lock():
                    self.metrics.recovery_transactions_replayed = checkpointed
            
            conn.close()
            
            duration_ms = (time.time() - start_time) * 1000
            
            with threading.Lock():
                self.metrics.recovery_attempts += 1
                self.metrics.recovery_duration_ms = duration_ms
            
            logger.info(f"✅ Recovery complete ({duration_ms:.2f}ms)")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Recovery failed: {e}")
            return False


class DurabilityManager:
    """Main durability manager coordinating all features"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.config = DurabilityConfig()
        self.metrics = DurabilityMetrics()
        
        self.wal_manager = WALManager(db_path, self.config, self.metrics)
        self.ttl_manager = TTLManager(db_path, self.config, self.metrics)
        self.pii_scrubber = PIIScrubber(db_path, self.config, self.metrics)
        self.recovery_manager = RecoveryManager(db_path, self.config, self.metrics)
    
    def initialize(self, conn: sqlite3.Connection) -> bool:
        """
        Initialize durability features
        
        Args:
            conn: SQLite connection
            
        Returns:
            True if initialization successful
        """
        try:
            # Check for crash recovery
            if self.recovery_manager.check_for_recovery():
                logger.info("Performing crash recovery...")
                if not self.recovery_manager.recover():
                    logger.error("Recovery failed, proceeding with caution")
            
            # Enable WAL mode
            if self.config.WAL_ENABLED:
                self.wal_manager.enable_wal(conn)
            
            # Add TTL columns
            if self.config.TTL_ENABLED:
                self.ttl_manager.add_ttl_columns(conn)
                # Start background cleanup job
                self.ttl_manager.start_cleanup_job()
            
            # Add PII scrubbing columns
            if self.config.PII_SCRUBBING_ENABLED:
                self.pii_scrubber.add_scrubbing_columns(conn)
                # Start background scrubbing job
                self.pii_scrubber.start_scrubbing_job()
            
            logger.info("✅ Durability features initialized")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing durability features: {e}")
            return False
    
    def on_transaction(self, conn: sqlite3.Connection):
        """Called after each transaction"""
        self.wal_manager.increment_transaction_count()
    
    def get_status(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        """Get durability status"""
        return {
            "config": {
                "wal_enabled": self.config.WAL_ENABLED,
                "ttl_enabled": self.config.TTL_ENABLED,
                "pii_scrubbing_enabled": self.config.PII_SCRUBBING_ENABLED,
                "recovery_enabled": self.config.RECOVERY_ENABLED
            },
            "wal": self.wal_manager.get_wal_info(conn),
            "ttl": self.ttl_manager.get_ttl_stats(conn),
            "pii_scrubbing": self.pii_scrubber.get_scrubbing_stats(conn),
            "metrics": self.metrics.to_dict()
        }
    
    def shutdown(self, conn: sqlite3.Connection):
        """Graceful shutdown"""
        logger.info("Shutting down durability manager...")
        
        # Stop TTL cleanup job
        if self.config.TTL_ENABLED:
            self.ttl_manager.stop_cleanup_job()
        
        # Stop PII scrubbing job
        if self.config.PII_SCRUBBING_ENABLED:
            self.pii_scrubber.stop_scrubbing_job()
        
        # Cleanup WAL
        self.wal_manager.cleanup_on_shutdown(conn)
        
        logger.info("✅ Durability manager shutdown complete")
