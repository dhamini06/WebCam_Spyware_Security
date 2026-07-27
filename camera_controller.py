"""
Camera Controller for Webcam Spyware Security
High-level webcam management and control
"""

import logging
import subprocess
import os
from typing import Optional, Tuple, Dict, List
from datetime import datetime
import threading

from registry_manager import RegistryManager
from database import DatabaseManager
from utils import SystemInfo, DateTimeUtils

logger = logging.getLogger(__name__)


class CameraController:
    """Manages camera/webcam operations"""
    
    def __init__(self, db: DatabaseManager = None, registry: RegistryManager = None):
        """
        Initialize camera controller
        
        Args:
            db: Database manager instance
            registry: Registry manager instance
        """
        self.db = db or DatabaseManager()
        self.registry = registry or RegistryManager()
        self.camera_devices = []
        self.is_camera_enabled = None
        self.refresh_camera_devices()
    
    # ============ DEVICE DETECTION ============
    
    def refresh_camera_devices(self) -> int:
        """
        Refresh list of detected camera devices
        
        Returns:
            Number of cameras found
        """
        try:
            self.camera_devices = self.registry.find_camera_devices()
            logger.info(f"Detected {len(self.camera_devices)} camera device(s)")
            return len(self.camera_devices)
        except Exception as e:
            logger.error(f"Error refreshing camera devices: {e}")
            return 0
    
    def get_camera_devices(self) -> List[Dict]:
        """
        Get list of camera devices
        
        Returns:
            List of camera device dictionaries
        """
        return self.camera_devices.copy()
    
    def get_camera_count(self) -> int:
        """Get number of cameras"""
        return len(self.camera_devices)
    
    def has_camera(self) -> bool:
        """Check if camera exists"""
        return len(self.camera_devices) > 0
    
    # ============ CAMERA CONTROL ============
    
    def disable_all_cameras(self, user_id: int = None, username: str = None) -> Tuple[bool, str]:
        """Disable webcam via CapabilityAccessManager consent registry (Deny)"""
        if not self.registry.is_admin:
            msg = "Admin privileges required to disable cameras"
            logger.warning(msg)
            return False, msg
        
        try:
            success = self.registry.disable_camera_device()
            
            if success:
                if user_id and username:
                    self.db.add_log(
                        user_id, username, 'disable_all_cameras', 'info',
                        'Webcam disabled (consent set to Deny)',
                        SystemInfo.get_ip_address(),
                        SystemInfo.get_machine_name()
                    )
                
                self.is_camera_enabled = False
                logger.info("Webcam disabled via consent registry")
                return True, "Webcam disabled successfully (all apps blocked). A reboot may be required."
            else:
                return False, "Failed to disable webcam"
        
        except Exception as e:
            logger.error(f"Error disabling cameras: {e}")
            return False, "Failed to disable cameras"
    
    def enable_all_cameras(self, user_id: int = None, username: str = None) -> Tuple[bool, str]:
        """Enable webcam via CapabilityAccessManager consent registry (Allow)"""
        if not self.registry.is_admin:
            msg = "Admin privileges required to enable cameras"
            logger.warning(msg)
            return False, msg
        
        try:
            success = self.registry.enable_camera_device()
            
            if success:
                if user_id and username:
                    self.db.add_log(
                        user_id, username, 'enable_all_cameras', 'info',
                        'Webcam enabled (consent set to Allow)',
                        SystemInfo.get_ip_address(),
                        SystemInfo.get_machine_name()
                    )
                
                self.is_camera_enabled = True
                logger.info("Webcam enabled via consent registry")
                return True, "Webcam enabled successfully (all apps allowed). A reboot may be required."
            else:
                return False, "Failed to enable webcam"
        
        except Exception as e:
            logger.error(f"Error enabling cameras: {e}")
            return False, "Failed to enable cameras"
    
    def disable_specific_camera(self, device_id: str, user_id: int = None, 
                               username: str = None) -> Tuple[bool, str]:
        """
        Disable specific camera
        
        Args:
            device_id: Device ID to disable
            user_id: User ID for logging
            username: Username for logging
            
        Returns:
            Tuple (success: bool, message: str)
        """
        if not self.registry.is_admin:
            return False, "Admin privileges required"
        
        try:
            device = next((d for d in self.camera_devices 
                          if d['device_id'] == device_id), None)
            
            if not device:
                return False, f"Camera device not found: {device_id}"
            
            success = self.registry.disable_camera_device(device_id)
            
            if success:
                # Log action
                if user_id and username:
                    self.db.add_log(
                        user_id, username, 'disable_camera', 'info',
                        f'Disabled camera: {device["friendly_name"]}',
                        SystemInfo.get_ip_address(),
                        SystemInfo.get_machine_name()
                    )
                
                # Log camera access
                self.db.log_camera_access(user_id or 0, 'disabled')
            
            return success, f"Camera {'disabled' if success else 'disable failed'}"
        
        except Exception as e:
            logger.error(f"Error disabling camera: {e}")
            return False, "Failed to disable camera"
    
    def enable_specific_camera(self, device_id: str, user_id: int = None, 
                              username: str = None) -> Tuple[bool, str]:
        """
        Enable specific camera
        
        Args:
            device_id: Device ID to enable
            user_id: User ID for logging
            username: Username for logging
            
        Returns:
            Tuple (success: bool, message: str)
        """
        if not self.registry.is_admin:
            return False, "Admin privileges required"
        
        try:
            device = next((d for d in self.camera_devices 
                          if d['device_id'] == device_id), None)
            
            if not device:
                return False, f"Camera device not found: {device_id}"
            
            success = self.registry.enable_camera_device(device_id)
            
            if success:
                # Log action
                if user_id and username:
                    self.db.add_log(
                        user_id, username, 'enable_camera', 'info',
                        f'Enabled camera: {device["friendly_name"]}',
                        SystemInfo.get_ip_address(),
                        SystemInfo.get_machine_name()
                    )
                
                # Log camera access
                self.db.log_camera_access(user_id or 0, 'enabled')
            
            return success, f"Camera {'enabled' if success else 'enable failed'}"
        
        except Exception as e:
            logger.error(f"Error enabling camera: {e}")
            return False, "Failed to enable camera"
    
    # ============ STATUS OPERATIONS ============
    
    def get_camera_status(self, device_id: str = None) -> Dict[str, str]:
        """
        Get camera status
        
        Args:
            device_id: Specific device to check. If None, checks all.
            
        Returns:
            Dictionary with status info
        """
        try:
            if device_id:
                device = next((d for d in self.camera_devices 
                              if d['device_id'] == device_id), None)
                
                if not device:
                    return {"error": "Device not found"}
                
                status = self.registry.get_device_status(device_id)
                return {
                    "device_id": device_id,
                    "friendly_name": device['friendly_name'],
                    "status": status,
                    "enabled": status == "enabled",
                }
            
            else:
                # All cameras
                statuses = {}
                for device in self.camera_devices:
                    status = self.registry.get_device_status(device['device_id'])
                    statuses[device['device_id']] = {
                        "friendly_name": device['friendly_name'],
                        "status": status,
                    }
                
                all_enabled = all(s['status'] == 'enabled' 
                                 for s in statuses.values())
                
                return {
                    "total_cameras": len(self.camera_devices),
                    "all_enabled": all_enabled,
                    "devices": statuses,
                }
        
        except Exception as e:
            logger.error(f"Error getting camera status: {e}")
            return {"error": str(e)}
    
    def is_camera_accessible(self) -> bool:
        """Check if any camera is accessible"""
        try:
            status = self.get_camera_status()
            
            if "devices" in status:
                return any(d['status'] == 'enabled' 
                          for d in status["devices"].values())
            
            return False
        except Exception as e:
            logger.error(f"Error checking camera accessibility: {e}")
            return False
    
    # ============ POLICY OPERATIONS ============
    
    def apply_camera_policy(self, allow_camera: bool, user_id: int = None, 
                           username: str = None) -> Tuple[bool, str]:
        """
        Apply camera access policy
        
        Args:
            allow_camera: True to allow, False to deny
            user_id: User ID for logging
            username: Username for logging
            
        Returns:
            Tuple (success: bool, message: str)
        """
        if not self.registry.is_admin:
            return False, "Admin privileges required"
        
        try:
            success = self.registry.set_camera_policy(allow_camera)
            
            if success:
                action = "allowed" if allow_camera else "denied"
                
                # Log action
                if user_id and username:
                    self.db.add_log(
                        user_id, username, 'camera_policy_applied', 'info',
                        f'Camera access {action}',
                        SystemInfo.get_ip_address(),
                        SystemInfo.get_machine_name()
                    )
            
            return success, f"Camera policy {'applied' if success else 'failed'}"
        
        except Exception as e:
            logger.error(f"Error applying camera policy: {e}")
            return False, "Failed to apply policy"
    
    # ============ MONITORING ============
    
    def monitor_camera_access(self, user_id: int, duration_seconds: int = 3600) -> bool:
        """
        Monitor camera for unauthorized access
        
        Args:
            user_id: User ID to monitor
            duration_seconds: Duration to monitor in seconds
            
        Returns:
            True if monitoring started
        """
        try:
            # Start monitoring thread
            thread = threading.Thread(
                target=self._monitor_camera_thread,
                args=(user_id, duration_seconds),
                daemon=True
            )
            thread.start()
            
            logger.info(f"Camera monitoring started for user {user_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error starting camera monitoring: {e}")
            return False
    
    def _monitor_camera_thread(self, user_id: int, duration_seconds: int):
        """Monitor camera in background"""
        start_time = datetime.now()
        check_interval = 60  # Check every 60 seconds
        
        try:
            while (datetime.now() - start_time).total_seconds() < duration_seconds:
                # Check if camera was accessed
                # This is a placeholder - in production, use Windows event logs
                status = self.get_camera_status()
                
                if status.get("all_enabled"):
                    logger.warning(f"Camera active during monitoring for user {user_id}")
                
                threading.Event().wait(check_interval)
        
        except Exception as e:
            logger.error(f"Error in camera monitoring: {e}")
    
    # ============ LOGGING AND REPORTING ============
    
    def log_camera_action(self, user_id: int, username: str, action: str, 
                         status: str = None) -> int:
        """
        Log camera action
        
        Args:
            user_id: User ID
            username: Username
            action: Action performed (enable, disable, access)
            status: Status result
            
        Returns:
            Log entry ID
        """
        try:
            severity = "critical" if action == "access" else "info"
            
            log_id = self.db.add_log(
                user_id, username, f'camera_{action}', severity,
                f'Camera {action} - Status: {status}',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            return log_id
        
        except Exception as e:
            logger.error(f"Error logging camera action: {e}")
            return 0
    
    def get_camera_history(self, user_id: int, limit: int = 50) -> List[Dict]:
        """
        Get camera access history
        
        Args:
            user_id: User ID
            limit: Max records
            
        Returns:
            List of camera access records
        """
        try:
            return self.db.get_camera_history(user_id, limit)
        except Exception as e:
            logger.error(f"Error getting camera history: {e}")
            return []
    
    def get_camera_summary(self, user_id: int = None) -> Dict:
        """
        Get camera activity summary
        
        Args:
            user_id: User ID (optional)
            
        Returns:
            Dictionary with summary stats
        """
        try:
            db_stats = self.db.get_database_stats()
            
            summary = {
                "total_cameras": self.get_camera_count(),
                "cameras_enabled": sum(
                    1 for d in self.camera_devices
                    if self.registry.get_device_status(d['device_id']) == 'enabled'
                ),
                "camera_access_logs": db_stats.get('camera_access', 0),
                "admin_privileges": self.registry.is_admin,
            }
            
            return summary
        
        except Exception as e:
            logger.error(f"Error getting camera summary: {e}")
            return {}


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    controller = CameraController()
    
    print("=== Camera Controller Test ===\n")
    
    # Detect cameras
    print("[1] Camera Detection:")
    count = controller.refresh_camera_devices()
    print(f"  Detected: {count} camera(s)")
    
    devices = controller.get_camera_devices()
    for device in devices:
        print(f"    - {device['friendly_name']}")
    
    # Get status
    print("\n[2] Camera Status:")
    status = controller.get_camera_status()
    print(f"  Status: {status}")
    
    # Summary
    print("\n[3] Camera Summary:")
    summary = controller.get_camera_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")
    
    # Admin check
    print(f"\n[4] Admin Privileges: {'✅ Yes' if controller.registry.is_admin else '❌ No'}")
