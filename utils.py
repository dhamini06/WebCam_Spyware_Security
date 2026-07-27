"""
Utility functions for Webcam Spyware Security
"""

import socket
import platform
import os
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging
import subprocess

logger = logging.getLogger(__name__)


class SystemInfo:
    """Get system information"""
    
    @staticmethod
    def get_machine_name() -> str:
        """Get machine/computer name"""
        try:
            return socket.gethostname()
        except Exception as e:
            logger.error(f"Failed to get machine name: {e}")
            return "Unknown"
    
    @staticmethod
    def get_ip_address() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Failed to get IP: {e}")
            return "0.0.0.0"
    
    @staticmethod
    def get_os_version() -> str:
        """Get OS version"""
        try:
            return platform.platform()
        except Exception as e:
            logger.error(f"Failed to get OS version: {e}")
            return "Unknown"
    
    @staticmethod
    def get_python_version() -> str:
        """Get Python version"""
        return platform.python_version()


class DateTimeUtils:
    """Datetime utilities"""
    
    @staticmethod
    def get_current_timestamp() -> str:
        """Get current timestamp in ISO format"""
        return datetime.now().isoformat()
    
    @staticmethod
    def get_current_date() -> str:
        """Get current date as YYYY-MM-DD"""
        return datetime.now().strftime("%Y-%m-%d")
    
    @staticmethod
    def get_current_time() -> str:
        """Get current time as HH:MM:SS"""
        return datetime.now().strftime("%H:%M:%S")
    
    @staticmethod
    def parse_time(time_str: str) -> Optional[datetime]:
        """Parse time string"""
        try:
            return datetime.fromisoformat(time_str)
        except Exception as e:
            logger.error(f"Failed to parse time: {e}")
            return None
    
    @staticmethod
    def is_time_in_range(current_time: str, start_time: str, end_time: str) -> bool:
        """Check if current time is within range"""
        try:
            current = datetime.fromisoformat(current_time).time()
            start = datetime.fromisoformat(start_time).time()
            end = datetime.fromisoformat(end_time).time()
            
            if start <= end:
                return start <= current <= end
            else:  # Range crosses midnight
                return current >= start or current <= end
        except Exception as e:
            logger.error(f"Failed to check time range: {e}")
            return False
    
    @staticmethod
    def add_minutes(minutes: int) -> str:
        """Get future time by adding minutes"""
        future = datetime.now() + timedelta(minutes=minutes)
        return future.isoformat()
    
    @staticmethod
    def add_hours(hours: int) -> str:
        """Get future time by adding hours"""
        future = datetime.now() + timedelta(hours=hours)
        return future.isoformat()
    
    @staticmethod
    def add_days(days: int) -> str:
        """Get future time by adding days"""
        future = datetime.now() + timedelta(days=days)
        return future.isoformat()


class ValidationUtils:
    """Input validation utilities"""
    
    @staticmethod
    def is_valid_username(username: str) -> bool:
        """Validate username format"""
        if not username or len(username) < 3 or len(username) > 50:
            return False
        return username.isalnum() or '_' in username
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def is_valid_password(password: str) -> bool:
        """Validate password strength"""
        # Min 8 chars, at least one upper, one lower, one digit, one special
        import re
        if len(password) < 8:
            return False
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        return has_upper and has_lower and has_digit and has_special
    
    @staticmethod
    def is_valid_time_format(time_str: str) -> bool:
        """Validate HH:MM:SS format"""
        import re
        pattern = r'^([0-1][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
        return bool(re.match(pattern, time_str))
    
    @staticmethod
    def sanitize_input(user_input: str, max_length: int = 255) -> str:
        """Sanitize user input"""
        if not user_input:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(c for c in user_input if ord(c) >= 32 or c in '\t\n\r')
        
        # Limit length
        return sanitized[:max_length].strip()


class FileUtils:
    """File operation utilities"""
    
    @staticmethod
    def ensure_dir_exists(dir_path: str):
        """Ensure directory exists"""
        try:
            os.makedirs(dir_path, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create directory {dir_path}: {e}")
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"Failed to get file size: {e}")
            return 0
    
    @staticmethod
    def file_exists(file_path: str) -> bool:
        """Check if file exists"""
        return os.path.isfile(file_path)
    
    @staticmethod
    def dir_exists(dir_path: str) -> bool:
        """Check if directory exists"""
        return os.path.isdir(dir_path)
    
    @staticmethod
    def get_file_extension(file_path: str) -> str:
        """Get file extension"""
        return os.path.splitext(file_path)[1].lower()
    
    @staticmethod
    def read_json_file(file_path: str) -> Optional[Dict]:
        """Read JSON file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read JSON file: {e}")
            return None
    
    @staticmethod
    def write_json_file(file_path: str, data: Dict) -> bool:
        """Write JSON file"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to write JSON file: {e}")
            return False
    
    @staticmethod
    def delete_file(file_path: str) -> bool:
        """Delete file safely"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            return True
        except Exception as e:
            logger.error(f"Failed to delete file: {e}")
            return False
    
    @staticmethod
    def clear_directory(dir_path: str, pattern: str = None):
        """Clear directory contents"""
        try:
            if not os.path.exists(dir_path):
                return
            
            for filename in os.listdir(dir_path):
                if pattern and pattern not in filename:
                    continue
                
                filepath = os.path.join(dir_path, filename)
                if os.path.isfile(filepath):
                    os.remove(filepath)
        except Exception as e:
            logger.error(f"Failed to clear directory: {e}")


class ProcessUtils:
    """Process and command utilities"""
    
    @staticmethod
    def run_command(command: str) -> Optional[str]:
        """Run system command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return None
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with admin privileges"""
        try:
            import ctypes
            return ctypes.windll.shell.IsUserAnAdmin()
        except Exception as e:
            logger.error(f"Failed to check admin status: {e}")
            return False
    
    @staticmethod
    def request_admin_privileges():
        """Request admin privileges (Windows)"""
        try:
            import ctypes
            ctypes.windll.shell.ShellExecuteW(None, "runas", "python", __file__, None, 1)
        except Exception as e:
            logger.error(f"Failed to request admin privileges: {e}")


class ConfigUtils:
    """Configuration utilities"""
    
    _config: Dict[str, Any] = {}
    
    @classmethod
    def load_config(cls, config_file: str):
        """Load configuration from JSON file"""
        cls._config = FileUtils.read_json_file(config_file) or {}
    
    @classmethod
    def get_config(cls, key: str, default: Any = None) -> Any:
        """Get config value"""
        return cls._config.get(key, default)
    
    @classmethod
    def set_config(cls, key: str, value: Any):
        """Set config value"""
        cls._config[key] = value
    
    @classmethod
    def save_config(cls, config_file: str):
        """Save configuration to JSON file"""
        FileUtils.write_json_file(config_file, cls._config)


class LoggingUtils:
    """Logging utilities"""
    
    @staticmethod
    def setup_logging(log_file: str = None, level: str = 'INFO') -> logging.Logger:
        """Setup application logging"""
        logger = logging.getLogger('webcam_spyware_security')
        logger.setLevel(getattr(logging, level))
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(getattr(logging, level))
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                fh = logging.FileHandler(log_file)
                fh.setLevel(getattr(logging, level))
                fh.setFormatter(formatter)
                logger.addHandler(fh)
            except Exception as e:
                logger.error(f"Failed to setup file logging: {e}")
        
        return logger


if __name__ == '__main__':
    # Test utilities
    print("System Info:")
    print(f"  Machine: {SystemInfo.get_machine_name()}")
    print(f"  IP: {SystemInfo.get_ip_address()}")
    print(f"  OS: {SystemInfo.get_os_version()}")
    print(f"  Python: {SystemInfo.get_python_version()}")
    
    print("\nDateTime:")
    print(f"  Current: {DateTimeUtils.get_current_timestamp()}")
    print(f"  Date: {DateTimeUtils.get_current_date()}")
    print(f"  Time: {DateTimeUtils.get_current_time()}")
    
    print("\nValidation:")
    print(f"  Valid username 'admin': {ValidationUtils.is_valid_username('admin')}")
    print(f"  Valid email 'test@example.com': {ValidationUtils.is_valid_email('test@example.com')}")
    print(f"  Valid password 'Pass123!': {ValidationUtils.is_valid_password('Pass123!')}")
