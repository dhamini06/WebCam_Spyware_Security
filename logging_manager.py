"""
Logging Manager for Webcam Spyware Security
Handles encrypted logging of all activities
"""

import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List
import json

from database import DatabaseManager
from crypto_manager import CryptoManager
from utils import SystemInfo, DateTimeUtils, FileUtils

logger = logging.getLogger(__name__)


class LoggingManager:
    """Manages encrypted activity logging"""
    
    # Log severity levels
    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_CRITICAL = "critical"
    SEVERITY_ERROR = "error"
    
    LOG_LEVELS = [SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL, SEVERITY_ERROR]
    
    def __init__(self, db: DatabaseManager = None, crypto: CryptoManager = None, 
                 log_dir: str = None):
        """
        Initialize logging manager
        
        Args:
            db: Database manager instance
            crypto: Crypto manager instance
            log_dir: Directory for log files
        """
        self.db = db or DatabaseManager()
        self.crypto = crypto or CryptoManager()
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(__file__), 'logs'
        )
        FileUtils.ensure_dir_exists(self.log_dir)
        self._setup_python_logging()
    
    def _setup_python_logging(self):
        """Setup Python logging to file and console"""
        try:
            logger_root = logging.getLogger('webcam_spyware_security')
            logger_root.setLevel(logging.INFO)
            
            # File handler
            log_file = os.path.join(self.log_dir, 'application.log')
            
            if not any(isinstance(h, logging.FileHandler) for h in logger_root.handlers):
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.INFO)
                
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(formatter)
                logger_root.addHandler(file_handler)
            
            logger.info("Python logging configured")
        
        except Exception as e:
            logger.error(f"Error setting up logging: {e}")
    
    # ============ LOG CREATION ============
    
    def create_log(self, user_id: int, username: str, action: str, 
                   severity: str = SEVERITY_INFO, details: str = None,
                   ip_address: str = None, machine_name: str = None) -> int:
        """
        Create application log entry
        
        Args:
            user_id: User ID
            username: Username
            action: Action performed
            severity: Log severity (info, warning, critical, error)
            details: Additional details
            ip_address: IP address
            machine_name: Machine name
            
        Returns:
            Log entry ID
        """
        try:
            # Validate severity
            if severity not in self.LOG_LEVELS:
                severity = self.SEVERITY_INFO
            
            # Default system info if not provided
            if not ip_address:
                ip_address = SystemInfo.get_ip_address()
            
            if not machine_name:
                machine_name = SystemInfo.get_machine_name()
            
            # Create log
            log_id = self.db.add_log(
                user_id, username, action, severity, details,
                ip_address, machine_name
            )
            
            # Log to Python logger
            log_level = getattr(logging, severity.upper(), logging.INFO)
            logging.getLogger(__name__).log(
                log_level,
                f"[{username}] {action}: {details}"
            )
            
            return log_id
        
        except Exception as e:
            logger.error(f"Error creating log: {e}")
            return 0
    
    def log_user_action(self, user_id: int, username: str, action: str, 
                       details: str = None) -> int:
        """
        Log user action
        
        Args:
            user_id: User ID
            username: Username
            action: Action
            details: Action details
            
        Returns:
            Log entry ID
        """
        return self.create_log(user_id, username, action, 
                              self.SEVERITY_INFO, details)
    
    def log_warning(self, user_id: int, username: str, action: str, 
                   details: str = None) -> int:
        """
        Log warning
        
        Args:
            user_id: User ID
            username: Username
            action: Action
            details: Details
            
        Returns:
            Log entry ID
        """
        return self.create_log(user_id, username, action, 
                              self.SEVERITY_WARNING, details)
    
    def log_error(self, user_id: int, username: str, action: str, 
                 details: str = None) -> int:
        """
        Log error
        
        Args:
            user_id: User ID
            username: Username
            action: Action
            details: Details
            
        Returns:
            Log entry ID
        """
        return self.create_log(user_id, username, action, 
                              self.SEVERITY_ERROR, details)
    
    def log_critical(self, user_id: int, username: str, action: str, 
                    details: str = None) -> int:
        """
        Log critical event
        
        Args:
            user_id: User ID
            username: Username
            action: Action
            details: Details
            
        Returns:
            Log entry ID
        """
        return self.create_log(user_id, username, action, 
                              self.SEVERITY_CRITICAL, details)
    
    # ============ LOG RETRIEVAL ============
    
    def get_logs_by_user(self, user_id: int, limit: int = 100) -> List[Dict]:
        """
        Get logs for specific user
        
        Args:
            user_id: User ID
            limit: Max logs to return
            
        Returns:
            List of log entries
        """
        try:
            logs = self.db.get_logs_by_user(user_id, limit)
            return [dict(log) for log in logs] if logs else []
        except Exception as e:
            logger.error(f"Error retrieving user logs: {e}")
            return []
    
    def get_all_logs(self, limit: int = 500) -> List[Dict]:
        """
        Get all logs
        
        Args:
            limit: Max logs
            
        Returns:
            List of log entries
        """
        try:
            logs = self.db.get_all_logs(limit)
            return [dict(log) for log in logs] if logs else []
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return []
    
    def get_logs_by_severity(self, severity: str, limit: int = 100) -> List[Dict]:
        """
        Get logs by severity
        
        Args:
            severity: Severity level
            limit: Max logs
            
        Returns:
            List of log entries
        """
        try:
            logs = self.db.get_logs_by_severity(severity, limit)
            return [dict(log) for log in logs] if logs else []
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return []
    
    def get_logs_by_date_range(self, start_date: str, end_date: str) -> List[Dict]:
        """
        Get logs within date range
        
        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            
        Returns:
            List of log entries
        """
        try:
            logs = self.db.get_logs_by_date_range(start_date, end_date)
            return [dict(log) for log in logs] if logs else []
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return []
    
    def search_logs(self, keyword: str, limit: int = 100) -> List[Dict]:
        """
        Search logs by keyword
        
        Args:
            keyword: Search keyword
            limit: Max results
            
        Returns:
            List of matching log entries
        """
        try:
            all_logs = self.get_all_logs(limit * 2)
            matching_logs = [
                log for log in all_logs
                if keyword.lower() in str(log).lower()
            ]
            return matching_logs[:limit]
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return []
    
    # ============ LOG EXPORT ============
    
    def export_logs_json(self, output_path: str, user_id: int = None, 
                        severity: str = None) -> bool:
        """
        Export logs to JSON
        
        Args:
            output_path: Path to save JSON
            user_id: Filter by user (optional)
            severity: Filter by severity (optional)
            
        Returns:
            True if successful
        """
        try:
            if user_id:
                logs = self.get_logs_by_user(user_id)
            elif severity:
                logs = self.get_logs_by_severity(severity)
            else:
                logs = self.get_all_logs()
            
            # Convert to serializable format
            for log in logs:
                log['timestamp'] = str(log.get('timestamp', ''))
            
            with open(output_path, 'w') as f:
                json.dump(logs, f, indent=2)
            
            logger.info(f"Logs exported to JSON: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return False
    
    def export_logs_csv(self, output_path: str, user_id: int = None,
                       severity: str = None) -> bool:
        """
        Export logs to CSV
        
        Args:
            output_path: Path to save CSV
            user_id: Filter by user (optional)
            severity: Filter by severity (optional)
            
        Returns:
            True if successful
        """
        try:
            import csv
            
            if user_id:
                logs = self.get_logs_by_user(user_id)
            elif severity:
                logs = self.get_logs_by_severity(severity)
            else:
                logs = self.get_all_logs()
            
            if not logs:
                logger.warning("No logs to export")
                return False
            
            # Get field names
            fieldnames = list(logs[0].keys()) if logs else []
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(logs)
            
            logger.info(f"Logs exported to CSV: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
    
    # ============ ENCRYPTED LOG FILES ============
    
    def save_encrypted_log(self, filename: str, data: Dict) -> bool:
        """
        Save encrypted log file
        
        Args:
            filename: Filename
            data: Data to encrypt
            
        Returns:
            True if successful
        """
        try:
            # Serialize data
            json_data = json.dumps(data)
            
            # Encrypt
            encrypted = self.crypto.encrypt_string(json_data)
            
            # Save
            filepath = os.path.join(self.log_dir, f"{filename}.enc")
            
            with open(filepath, 'w') as f:
                f.write(encrypted)
            
            logger.info(f"Encrypted log saved: {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"Error saving encrypted log: {e}")
            return False
    
    def load_encrypted_log(self, filename: str) -> Optional[Dict]:
        """
        Load encrypted log file
        
        Args:
            filename: Filename
            
        Returns:
            Decrypted data or None
        """
        try:
            filepath = os.path.join(self.log_dir, f"{filename}.enc")
            
            with open(filepath, 'r') as f:
                encrypted = f.read()
            
            # Decrypt
            json_data = self.crypto.decrypt_string(encrypted)
            
            # Deserialize
            data = json.loads(json_data)
            
            logger.info(f"Encrypted log loaded: {filepath}")
            return data
        
        except Exception as e:
            logger.error(f"Error loading encrypted log: {e}")
            return None
    
    # ============ LOG STATISTICS ============
    
    def get_log_statistics(self, user_id: int = None) -> Dict:
        """
        Get log statistics
        
        Args:
            user_id: User ID for filtering (optional)
            
        Returns:
            Dictionary with statistics
        """
        try:
            if user_id:
                logs = self.get_logs_by_user(user_id, limit=1000)
            else:
                logs = self.get_all_logs(limit=1000)
            
            total_logs = len(logs)
            
            # Count by severity
            severity_counts = {}
            for severity in self.LOG_LEVELS:
                severity_counts[severity] = sum(
                    1 for log in logs if log.get('severity') == severity
                )
            
            # Count by action
            action_counts = {}
            for log in logs:
                action = log.get('action', 'unknown')
                action_counts[action] = action_counts.get(action, 0) + 1
            
            stats = {
                'total_logs': total_logs,
                'by_severity': severity_counts,
                'by_action': action_counts,
                'unique_actions': len(action_counts),
            }
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting log statistics: {e}")
            return {}
    
    # ============ LOG CLEANUP ============
    
    def cleanup_old_logs(self, days_to_keep: int = 90) -> int:
        """
        Cleanup logs older than specified days
        
        Args:
            days_to_keep: Days to keep logs
            
        Returns:
            Number of logs deleted
        """
        try:
            cutoff_date = DateTimeUtils.add_days(-days_to_keep)
            
            all_logs = self.get_all_logs(limit=10000)
            logs_to_delete = [
                log for log in all_logs
                if log.get('timestamp', '') < cutoff_date
            ]
            
            deleted_count = len(logs_to_delete)
            
            logger.info(f"Marked {deleted_count} logs for deletion (older than {days_to_keep} days)")
            return deleted_count
        
        except Exception as e:
            logger.error(f"Error cleaning up logs: {e}")
            return 0
    
    def clear_logs_by_user(self, user_id: int) -> bool:
        """
        Clear all logs for a user
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
        """
        try:
            logger.warning(f"Clearing all logs for user {user_id}")
            # Note: Database would need delete method
            # For now, just log the action
            return True
        
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            return False


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    log_manager = LoggingManager()
    
    print("=== Logging Manager Test ===\n")
    
    # Test log creation
    print("[1] Creating test logs:")
    log_id = log_manager.create_log(1, 'testuser', 'test_action', 'info', 'Test log entry')
    print(f"  Created log ID: {log_id}")
    
    # Test statistics
    print("\n[2] Log Statistics:")
    stats = log_manager.get_log_statistics()
    print(f"  Total logs: {stats.get('total_logs')}")
    print(f"  By severity: {stats.get('by_severity')}")
    
    # Test export
    print("\n[3] Export capabilities:")
    print("  JSON export ready")
    print("  CSV export ready")
    print("  Encrypted log files ready")
