"""
Database Manager for Webcam Spyware Security
Handles SQLite database operations with encrypted logging
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path
import logging
from crypto_manager import CryptoManager
from utils import AppPaths

# Configure module logging
logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages all database operations for the application"""
    
    def __init__(self, db_path: str = None):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file. Defaults to database/app.db
        """
        if db_path is None:
            db_path = os.path.join(AppPaths.database_dir(), 'app.db')
        
        self.db_path = db_path
        self.connection = None
        # In frozen builds, pull the bundled DB + key into a persistent
        # location first so seeded demo data and encryption survive the run.
        AppPaths.seed_bundled_database()
        self._ensure_database_exists()
        self._initialize_schema()
        try:
            self._crypto = CryptoManager()
        except Exception as e:
            logger.error(f"Could not initialize log encryption, logs will be stored "
                        f"in plaintext until this is fixed: {e}")
            self._crypto = None
    
    def _ensure_database_exists(self):
        """Ensure database file and directory exist"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    def connect(self) -> sqlite3.Connection:
        """Establish database connection"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            logger.info(f"Database connection established: {self.db_path}")
            return self.connection
        except sqlite3.Error as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    def disconnect(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
    
    def execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """
        Execute a database query
        
        Args:
            query: SQL query string
            params: Query parameters
            
        Returns:
            Cursor object
        """
        if not self.connection:
            self.connect()
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            return cursor
        except sqlite3.Error as e:
            logger.error(f"Query execution failed: {e}\nQuery: {query}")
            raise
    
    def commit(self):
        """Commit transaction"""
        if self.connection:
            self.connection.commit()
    
    def rollback(self):
        """Rollback transaction"""
        if self.connection:
            self.connection.rollback()
    
    def _initialize_schema(self):
        """Initialize database schema"""
        self.connect()
        
        # Users table
        self.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'employee')),
                face_data BLOB,
                face_encoding TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        # Logs table (encrypted activity logging)
        self.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
                details TEXT,
                ip_address TEXT,
                machine_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)

        # One-time login codes emailed via SMTP (see email_manager.py)
        self.execute("""
            CREATE TABLE IF NOT EXISTS login_otp (
                otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        # Intruder Detection Logs
        self.execute("""
            CREATE TABLE IF NOT EXISTS intruder_logs (
                intruder_id INTEGER PRIMARY KEY AUTOINCREMENT,
                failed_attempts INTEGER DEFAULT 1,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                image_path TEXT,
                ip_address TEXT,
                machine_name TEXT,
                alert_sent BOOLEAN DEFAULT 0
            )
        """)
        
        # Policies table
        self.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT UNIQUE NOT NULL,
                description TEXT,
                policy_type TEXT DEFAULT 'allow' CHECK(policy_type IN ('allow', 'deny')),
                scope TEXT DEFAULT 'global' CHECK(scope IN ('global', 'user', 'application')),
                allowed_start_time TEXT,
                allowed_end_time TEXT,
                blocked_days TEXT,
                weekend_access BOOLEAN DEFAULT 0,
                organization TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Schedules table (automatic enable/disable)
        self.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                policy_id INTEGER,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('enable', 'disable')),
                recurrence TEXT CHECK(recurrence IN ('once', 'daily', 'weekly', 'monthly')),
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE SET NULL
            )
        """)
        
        # Settings table
        self.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                data_type TEXT CHECK(data_type IN ('string', 'integer', 'boolean', 'json')),
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Camera Access History
        self.execute("""
            CREATE TABLE IF NOT EXISTS camera_access (
                access_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('enabled', 'disabled', 'accessed')),
                status TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                duration_seconds INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        # Face Recognition Registry
        self.execute("""
            CREATE TABLE IF NOT EXISTS face_registry (
                face_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                encoding TEXT NOT NULL,
                image_path TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        # Sessions table (for tracking active sessions)
        self.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        self._migrate_schema()
        self.commit()
        logger.info("Database schema initialized successfully")

    def _migrate_schema(self):
        """Add missing columns to existing tables for upgrades"""
        try:
            cursor = self.execute("PRAGMA table_info(policies)")
            existing_cols = {row[1] for row in cursor.fetchall()}
            if 'policy_type' not in existing_cols:
                self.execute("ALTER TABLE policies ADD COLUMN policy_type TEXT DEFAULT 'allow'")
                logger.info("Added policy_type column to policies table")
            if 'scope' not in existing_cols:
                self.execute("ALTER TABLE policies ADD COLUMN scope TEXT DEFAULT 'global'")
                logger.info("Added scope column to policies table")

            cursor = self.execute("PRAGMA table_info(intruder_logs)")
            existing_cols = {row[1] for row in cursor.fetchall()}
            if 'video_path' not in existing_cols:
                self.execute("ALTER TABLE intruder_logs ADD COLUMN video_path TEXT")
                logger.info("Added video_path column to intruder_logs table")
            if 'reason' not in existing_cols:
                self.execute("ALTER TABLE intruder_logs ADD COLUMN reason TEXT")
                logger.info("Added reason column to intruder_logs table")
        except sqlite3.Error as e:
            logger.warning(f"Migration warning (may be expected): {e}")
    
    # ============ USER OPERATIONS ============
    
    def create_user(self, username: str, email: str, password_hash: str, 
                   role: str = 'employee') -> int:
        """Create a new user"""
        try:
            cursor = self.execute(
                """INSERT INTO users (username, email, password_hash, role) 
                   VALUES (?, ?, ?, ?)""",
                (username, email, password_hash, role)
            )
            self.commit()
            logger.info(f"User created: {username}")
            return cursor.lastrowid
        except sqlite3.IntegrityError as e:
            logger.error(f"User creation failed (duplicate): {e}")
            raise
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        cursor = self.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        cursor = self.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_users(self) -> List[Dict]:
        """Get all users"""
        cursor = self.execute("SELECT * FROM users ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    def update_user(self, user_id: int, **kwargs) -> bool:
        """Update user fields"""
        allowed_fields = {'password_hash', 'email', 'role', 'is_active', 'last_login', 'face_encoding'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not fields:
            return False
        
        fields['updated_at'] = datetime.now().isoformat()
        
        set_clause = ", ".join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [user_id]
        
        self.execute(f"UPDATE users SET {set_clause} WHERE user_id = ?", values)
        self.commit()
        logger.info(f"User {user_id} updated")
        return True
    
    def delete_user(self, user_id: int) -> bool:
        """Delete user (soft delete recommended in practice)"""
        self.execute("UPDATE users SET is_active = 0 WHERE user_id = ?", (user_id,))
        self.commit()
        logger.info(f"User {user_id} deactivated")
        return True
    
    # ============ LOG OPERATIONS ============
    # 'details' is encrypted at rest (AES/Fernet via CryptoManager) so that
    # opening database/app.db directly, outside the running application,
    # does not show readable log content. It is transparently decrypted
    # here for every reader below, so the rest of the app (View Logs,
    # reports, etc.) keeps working with plain strings as before.

    def add_log(self, user_id: int, username: str, action: str, 
               severity: str = 'info', details: str = None, 
               ip_address: str = None, machine_name: str = None) -> int:
        """Add activity log entry"""
        try:
            stored_details = details
            if details and self._crypto:
                try:
                    stored_details = self._crypto.encrypt_string(details)
                except Exception as e:
                    logger.error(f"Failed to encrypt log details, storing as plaintext: {e}")
            cursor = self.execute(
                """INSERT INTO logs (user_id, username, action, severity, details, ip_address, machine_name) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, username, action, severity, stored_details, ip_address, machine_name)
            )
            self.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Log creation failed: {e}")
            raise

    def _decrypt_log_row(self, row: Dict) -> Dict:
        """Decrypts a log row's 'details' field in place. Rows written
        before encryption was enabled (or that fail to decrypt for any
        reason) are left as-is rather than raising, so one bad/legacy row
        can't break the whole log view."""
        if row.get('details') and self._crypto:
            try:
                row['details'] = self._crypto.decrypt_string(row['details'])
            except Exception:
                pass  # legacy plaintext row, or corrupted - show as stored
        return row

    def get_logs_by_user(self, user_id: int, limit: int = 100) -> List[Dict]:
        """Get logs for a specific user"""
        cursor = self.execute(
            """SELECT * FROM logs WHERE user_id = ? 
               ORDER BY log_id DESC LIMIT ?""",
            (user_id, limit)
        )
        return [self._decrypt_log_row(dict(row)) for row in cursor.fetchall()]
    
    def get_all_logs(self, limit: int = 500) -> List[Dict]:
        """Get all logs"""
        cursor = self.execute(
            "SELECT * FROM logs ORDER BY log_id DESC LIMIT ?",
            (limit,)
        )
        return [self._decrypt_log_row(dict(row)) for row in cursor.fetchall()]
    
    def get_logs_by_severity(self, severity: str, limit: int = 100) -> List[Dict]:
        """Get logs by severity level"""
        cursor = self.execute(
            """SELECT * FROM logs WHERE severity = ? 
               ORDER BY log_id DESC LIMIT ?""",
            (severity, limit)
        )
        return [self._decrypt_log_row(dict(row)) for row in cursor.fetchall()]
    
    def get_logs_by_date_range(self, start_date: str, end_date: str) -> List[Dict]:
        """Get logs within date range"""
        cursor = self.execute(
            """SELECT * FROM logs WHERE timestamp BETWEEN ? AND ? 
               ORDER BY log_id DESC""",
            (start_date, end_date)
        )
        return [self._decrypt_log_row(dict(row)) for row in cursor.fetchall()]
    
    # ============ INTRUDER DETECTION ============
    
    def add_intruder_log(self, failed_attempts: int = 1, image_path: str = None,
                        ip_address: str = None, machine_name: str = None,
                        video_path: str = None, reason: str = None) -> int:
        """Log intruder detection event"""
        cursor = self.execute(
            """INSERT INTO intruder_logs
               (failed_attempts, image_path, ip_address, machine_name, video_path, reason)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (failed_attempts, image_path, ip_address, machine_name, video_path, reason)
        )
        self.commit()
        return cursor.lastrowid
    
    def get_intruder_logs(self, limit: int = 50) -> List[Dict]:
        """Get intruder detection logs.
        Ordered by intruder_id (strictly increasing) rather than
        last_attempt, since CURRENT_TIMESTAMP only has 1-second resolution
        and two events in the same second would otherwise tie/misorder -
        same class of bug as login_otp's ordering, found the same way."""
        cursor = self.execute(
            "SELECT * FROM intruder_logs ORDER BY intruder_id DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    # ============ LOGIN OTP OPERATIONS ============

    def create_login_otp(self, user_id: int, code_hash: str, expires_at: str) -> int:
        """Store a freshly generated one-time login code (hashed, never plaintext)"""
        cursor = self.execute(
            "INSERT INTO login_otp (user_id, code_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, code_hash, expires_at)
        )
        self.commit()
        return cursor.lastrowid

    def get_latest_login_otp(self, user_id: int):
        """Get the most recently issued OTP for this user.
        Ordered by otp_id (strictly increasing) rather than created_at,
        since CURRENT_TIMESTAMP only has 1-second resolution and two codes
        requested within the same second would otherwise tie."""
        cursor = self.execute(
            "SELECT * FROM login_otp WHERE user_id = ? ORDER BY otp_id DESC LIMIT 1",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def mark_login_otp_used(self, otp_id: int):
        self.execute("UPDATE login_otp SET used = 1 WHERE otp_id = ?", (otp_id,))
        self.commit()

    # ============ POLICY OPERATIONS ============
    
    def create_policy(self, policy_name: str, description: str = None,
                     policy_type: str = 'allow', scope: str = 'global',
                     is_active: bool = True, allowed_start_time: str = None,
                     allowed_end_time: str = None) -> int:
        """Create a new policy"""
        cursor = self.execute(
            """INSERT INTO policies (policy_name, description, policy_type, scope,
               is_active, allowed_start_time, allowed_end_time) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (policy_name, description, policy_type, scope,
             is_active, allowed_start_time, allowed_end_time)
        )
        self.commit()
        logger.info(f"Policy created: {policy_name}")
        return cursor.lastrowid
    
    def get_policy_by_id(self, policy_id: int) -> Optional[Dict]:
        """Get policy by ID"""
        cursor = self.execute(
            "SELECT * FROM policies WHERE policy_id = ? AND is_active = 1",
            (policy_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_policies(self) -> List[Dict]:
        """Get all active policies"""
        cursor = self.execute(
            "SELECT * FROM policies WHERE is_active = 1 ORDER BY created_at DESC"
        )
        return [dict(row) for row in cursor.fetchall()]
    
    def update_policy(self, policy_id: int, **kwargs) -> bool:
        """Update policy"""
        allowed_fields = {'description', 'policy_type', 'scope', 'allowed_start_time',
                         'allowed_end_time', 'blocked_days', 'weekend_access', 'is_active'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not fields:
            return False
        
        fields['updated_at'] = datetime.now().isoformat()
        set_clause = ", ".join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [policy_id]
        
        self.execute(f"UPDATE policies SET {set_clause} WHERE policy_id = ?", values)
        self.commit()
        return True
    
    def delete_policy(self, policy_id: int) -> bool:
        """Delete policy (soft delete)"""
        self.execute("UPDATE policies SET is_active = 0 WHERE policy_id = ?", (policy_id,))
        self.commit()
        logger.info(f"Policy {policy_id} deleted")
        return True
    
    # ============ SCHEDULE OPERATIONS ============
    
    def create_schedule(self, user_id: int, start_time: str, end_time: str,
                       action: str, recurrence: str = 'once', 
                       policy_id: int = None) -> int:
        """Create a schedule"""
        cursor = self.execute(
            """INSERT INTO schedules (user_id, policy_id, start_time, end_time, action, recurrence) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, policy_id, start_time, end_time, action, recurrence)
        )
        self.commit()
        return cursor.lastrowid
    
    def get_schedules_by_user(self, user_id: int) -> List[Dict]:
        """Get schedules for user"""
        cursor = self.execute(
            "SELECT * FROM schedules WHERE user_id = ? AND is_active = 1 ORDER BY start_time",
            (user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    def get_active_schedules(self) -> List[Dict]:
        """Get all active schedules"""
        cursor = self.execute(
            "SELECT * FROM schedules WHERE is_active = 1 ORDER BY start_time"
        )
        return [dict(row) for row in cursor.fetchall()]

    def update_schedule(self, schedule_id: int, **kwargs) -> bool:
        """Update schedule fields (start_time, end_time, action, recurrence, is_active)"""
        allowed_fields = {'start_time', 'end_time', 'action', 'recurrence', 'is_active', 'policy_id'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            return False

        set_clause = ", ".join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [schedule_id]

        self.execute(f"UPDATE schedules SET {set_clause} WHERE schedule_id = ?", values)
        self.commit()
        return True

    def delete_schedule(self, schedule_id: int) -> bool:
        """Permanently delete a schedule"""
        self.execute("DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,))
        self.commit()
        return True
    
    # ============ SETTINGS OPERATIONS ============
    
    def set_setting(self, key: str, value: str, data_type: str = 'string'):
        """Set or update a setting"""
        cursor = self.execute(
            "SELECT * FROM settings WHERE setting_key = ?",
            (key,)
        )
        
        if cursor.fetchone():
            self.execute(
                """UPDATE settings SET setting_value = ?, data_type = ?, updated_at = CURRENT_TIMESTAMP 
                   WHERE setting_key = ?""",
                (value, data_type, key)
            )
        else:
            self.execute(
                """INSERT INTO settings (setting_key, setting_value, data_type) 
                   VALUES (?, ?, ?)""",
                (key, value, data_type)
            )
        
        self.commit()
    
    def get_setting(self, key: str) -> Optional[str]:
        """Get a setting value"""
        cursor = self.execute(
            "SELECT setting_value FROM settings WHERE setting_key = ?",
            (key,)
        )
        row = cursor.fetchone()
        return row[0] if row else None
    
    def get_all_settings(self) -> Dict:
        """Get all settings"""
        cursor = self.execute("SELECT setting_key, setting_value FROM settings")
        return {row[0]: row[1] for row in cursor.fetchall()}
    
    # ============ CAMERA ACCESS ============
    
    def log_camera_access(self, user_id: int, action: str, status: str = None,
                         duration_seconds: int = None) -> int:
        """Log camera access event"""
        cursor = self.execute(
            """INSERT INTO camera_access (user_id, action, status, duration_seconds) 
               VALUES (?, ?, ?, ?)""",
            (user_id, action, status, duration_seconds)
        )
        self.commit()
        return cursor.lastrowid
    
    def get_camera_history(self, user_id: int, limit: int = 100) -> List[Dict]:
        """Get camera access history for user"""
        cursor = self.execute(
            """SELECT * FROM camera_access WHERE user_id = ? 
               ORDER BY timestamp DESC LIMIT ?""",
            (user_id, limit)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    # ============ FACE RECOGNITION ============
    
    def register_face(self, user_id: int, encoding: str, image_path: str = None) -> int:
        """Register face for user"""
        try:
            cursor = self.execute(
                """INSERT INTO face_registry (user_id, encoding, image_path) 
                   VALUES (?, ?, ?)""",
                (user_id, encoding, image_path)
            )
            self.commit()
            logger.info(f"Face registered for user {user_id}")
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            logger.warning(f"Face already exists for user {user_id}")
            self.update_face(user_id, encoding, image_path)
            return user_id
    
    def get_face_by_user(self, user_id: int) -> Optional[Dict]:
        """Get face registration for user"""
        cursor = self.execute(
            "SELECT * FROM face_registry WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def update_face(self, user_id: int, encoding: str, image_path: str = None) -> bool:
        """Update face registration"""
        self.execute(
            """UPDATE face_registry SET encoding = ?, image_path = ?, updated_at = CURRENT_TIMESTAMP 
               WHERE user_id = ?""",
            (encoding, image_path, user_id)
        )
        self.commit()
        return True
    
    # ============ SESSION MANAGEMENT ============
    
    def create_session(self, user_id: int, token: str, expires_at: str) -> int:
        """Create user session"""
        cursor = self.execute(
            """INSERT INTO sessions (user_id, token, expires_at) 
               VALUES (?, ?, ?)""",
            (user_id, token, expires_at)
        )
        self.commit()
        return cursor.lastrowid
    
    def get_session(self, token: str) -> Optional[Dict]:
        """Get session by token"""
        cursor = self.execute(
            "SELECT * FROM sessions WHERE token = ? AND is_active = 1",
            (token,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def invalidate_session(self, token: str) -> bool:
        """Invalidate session"""
        self.execute(
            "UPDATE sessions SET is_active = 0 WHERE token = ?",
            (token,)
        )
        self.commit()
        return True
    
    # ============ UTILITY OPERATIONS ============
    
    def backup_database(self, backup_path: str = None) -> str:
        """Create database backup"""
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(
                os.path.dirname(self.db_path), 
                f'backup_{timestamp}.db'
            )
        
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"Database backed up to {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise
    
    def restore_database(self, backup_path: str):
        """Restore database from backup"""
        try:
            if self.connection:
                self.disconnect()
            
            import shutil
            shutil.copy2(backup_path, self.db_path)
            self.connect()
            logger.info(f"Database restored from {backup_path}")
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            raise
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        stats = {}
        
        tables = ['users', 'logs', 'intruder_logs', 'policies', 'schedules', 'camera_access']
        for table in tables:
            cursor = self.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = cursor.fetchone()[0]
        
        return stats
    
    def __del__(self):
        """Cleanup on deletion"""
        self.disconnect()


# Example usage for testing
if __name__ == '__main__':
    # Setup basic logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize database
    db = DatabaseManager()
    
    # Test create user
    try:
        user_id = db.create_user('admin', 'admin@company.com', 'hashed_password', 'admin')
        print(f"Created user: {user_id}")
        
        # Test get user
        user = db.get_user_by_username('admin')
        print(f"Retrieved user: {user}")
        
        # Test add log
        log_id = db.add_log(user_id, 'admin', 'login', 'info', 'Admin login successful')
        print(f"Created log: {log_id}")
        
        # Test get stats
        stats = db.get_database_stats()
        print(f"Database stats: {stats}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.disconnect()
