"""
Registry Manager for Webcam Spyware Security
Handles Windows Registry operations for webcam control
"""

import winreg
import subprocess
import logging
from typing import Optional, Tuple, Dict, List
from enum import Enum
import ctypes

logger = logging.getLogger(__name__)


class CameraDriver(Enum):
    """Known camera driver registry paths"""
    INTEGRATED_CAMERA = "USB\\VID_"  # USB cameras
    WEBCAM_DRIVERS = "System\\CurrentControlSet\\Enum\\USB"
    DEVICE_CLASSES = "System\\CurrentControlSet\\Control\\DeviceClasses"


class RegistryManager:
    """Manages Windows Registry operations"""
    
    # Common registry paths for camera/webcam
    REGISTRY_PATHS = {
        "camera_devices": r"SYSTEM\CurrentControlSet\Enum\USB",
        "device_classes": r"SYSTEM\CurrentControlSet\Control\DeviceClasses",
        "services": r"SYSTEM\CurrentControlSet\Services",
        "camera_service": r"SYSTEM\CurrentControlSet\Services\usbhub",
        "imaging_devices": r"SYSTEM\CurrentControlSet\Enum\PCI",
        "video_devices": r"SYSTEM\CurrentControlSet\Enum\ACPI",
        "webcam_consent": r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
    }
    
    def __init__(self):
        """Initialize registry manager"""
        self.is_admin = self._check_admin_privileges()
        if not self.is_admin:
            logger.warning("Not running with admin privileges. Some operations may fail.")
    
    @staticmethod
    def _check_admin_privileges() -> bool:
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception as e:
            logger.error(f"Failed to check admin privileges: {e}")
            return False
    
    def request_admin_privileges(self) -> bool:
        """Request admin privileges (Windows UAC)"""
        if self.is_admin:
            return True
        
        try:
            logger.info("Requesting admin privileges...")
            # This would typically trigger UAC prompt
            # For now, just log it
            return False
        except Exception as e:
            logger.error(f"Failed to request admin privileges: {e}")
            return False
    
    # ============ REGISTRY READ OPERATIONS ============
    
    def get_registry_value(self, hive: int, path: str, value_name: str) -> Optional[any]:
        """
        Get registry value
        
        Args:
            hive: Registry hive (winreg.HKEY_LOCAL_MACHINE, etc.)
            path: Registry path
            value_name: Value name
            
        Returns:
            Registry value or None if not found
        """
        try:
            with winreg.OpenKey(hive, path, access=winreg.KEY_READ) as key:
                value, value_type = winreg.QueryValueEx(key, value_name)
                return value
        except FileNotFoundError:
            logger.warning(f"Registry path not found: {path}")
            return None
        except Exception as e:
            logger.error(f"Error reading registry: {e}")
            return None
    
    def list_registry_subkeys(self, hive: int, path: str) -> List[str]:
        """
        List subkeys in registry path
        
        Args:
            hive: Registry hive
            path: Registry path
            
        Returns:
            List of subkey names
        """
        try:
            subkeys = []
            with winreg.OpenKey(hive, path, access=winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                        subkeys.append(subkey_name)
                        index += 1
                    except OSError:
                        break
            return subkeys
        except Exception as e:
            logger.error(f"Error listing registry subkeys: {e}")
            return []
    
    def list_registry_values(self, hive: int, path: str) -> Dict[str, Tuple]:
        """
        List all values in registry path
        
        Args:
            hive: Registry hive
            path: Registry path
            
        Returns:
            Dictionary of value names and their data
        """
        try:
            values = {}
            with winreg.OpenKey(hive, path, access=winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, index)
                        values[value_name] = (value_data, value_type)
                        index += 1
                    except OSError:
                        break
            return values
        except Exception as e:
            logger.error(f"Error listing registry values: {e}")
            return {}
    
    # ============ REGISTRY WRITE OPERATIONS ============
    
    def set_registry_value(self, hive: int, path: str, value_name: str, 
                          value_data: any, value_type: int = winreg.REG_DWORD) -> bool:
        """
        Set registry value
        
        Args:
            hive: Registry hive
            path: Registry path
            value_name: Value name
            value_data: Value data
            value_type: Registry type (REG_DWORD, REG_SZ, etc.)
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to write to registry")
            return False
        
        try:
            with winreg.CreateKey(hive, path) as key:
                winreg.SetValueEx(key, value_name, 0, value_type, value_data)
                logger.info(f"Registry value set: {path}\\{value_name}")
                return True
        except Exception as e:
            logger.error(f"Error setting registry value: {e}")
            return False
    
    def delete_registry_value(self, hive: int, path: str, value_name: str) -> bool:
        """
        Delete registry value
        
        Args:
            hive: Registry hive
            path: Registry path
            value_name: Value name
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to delete registry values")
            return False
        
        try:
            with winreg.OpenKey(hive, path, access=winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, value_name)
                logger.info(f"Registry value deleted: {path}\\{value_name}")
                return True
        except FileNotFoundError:
            logger.warning(f"Registry value not found: {path}\\{value_name}")
            return False
        except Exception as e:
            logger.error(f"Error deleting registry value: {e}")
            return False
    
    # ============ CAMERA-SPECIFIC OPERATIONS ============
    
    def find_camera_devices(self) -> List[Dict[str, str]]:
        """
        Find all camera devices using WMI, registry, and OpenCV probing
        
        Returns:
            List of camera devices with details
        """
        cameras = []
        seen_ids = set()
        
        # Method 1: WMI query for camera devices (most reliable, gets real device IDs)
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-PnpDevice -Class Camera -Status OK -ErrorAction SilentlyContinue | "
                 "Select-Object InstanceId, FriendlyName, Status | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15, creationflags=0x08000000  # CREATE_NO_WINDOW
            )
            if result.stdout.strip():
                import json
                devices = json.loads(result.stdout.strip())
                if isinstance(devices, dict):
                    devices = [devices]
                for dev in devices:
                    dev_id = dev.get("InstanceId", "")
                    name = dev.get("FriendlyName", "Unknown Camera")
                    if dev_id and dev_id not in seen_ids:
                        cameras.append({
                            "device_id": dev_id,
                            "device_path": f"WMI\\{dev_id}",
                            "friendly_name": name,
                            "device_desc": f"WMI Camera - {dev.get('Status', 'OK')}",
                        })
                        seen_ids.add(dev_id)
        except Exception as e:
            logger.debug(f"WMI camera query: {e}")
        
        # Method 2: Also check Imaging Devices class
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-PnpDevice -Class 'Image' -Status OK -ErrorAction SilentlyContinue | "
                 "Select-Object InstanceId, FriendlyName, Status | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15, creationflags=0x08000000
            )
            if result.stdout.strip():
                import json
                devices = json.loads(result.stdout.strip())
                if isinstance(devices, dict):
                    devices = [devices]
                for dev in devices:
                    dev_id = dev.get("InstanceId", "")
                    name = dev.get("FriendlyName", "Unknown Camera")
                    if dev_id and dev_id not in seen_ids:
                        cameras.append({
                            "device_id": dev_id,
                            "device_path": f"WMI\\{dev_id}",
                            "friendly_name": name,
                            "device_desc": f"WMI Image Device - {dev.get('Status', 'OK')}",
                        })
                        seen_ids.add(dev_id)
        except Exception as e:
            logger.debug(f"WMI image device query: {e}")

        # Method 3: Registry search for imaging devices
        try:
            usb_path = self.REGISTRY_PATHS["camera_devices"]
            usb_devices = self.list_registry_subkeys(winreg.HKEY_LOCAL_MACHINE, usb_path)
            
            for device_id in usb_devices:
                device_path = f"{usb_path}\\{device_id}"
                device_info = self.list_registry_values(
                    winreg.HKEY_LOCAL_MACHINE, device_path
                )
                
                friendly_name = str(device_info.get("FriendlyName", ("Unknown", 0))[0])
                device_desc = str(device_info.get("DeviceDesc", ("", 0))[0])
                
                if any(keyword in device_desc.lower() 
                       for keyword in ["camera", "webcam", "imaging", "video"]):
                    cam_key = f"usb_{device_id}"
                    if cam_key not in seen_ids:
                        cameras.append({
                            "device_id": device_id,
                            "device_path": device_path,
                            "friendly_name": friendly_name,
                            "device_desc": device_desc,
                        })
                        seen_ids.add(cam_key)
        except Exception as e:
            logger.debug(f"Registry camera search: {e}")
        
        # If no cameras found via WMI/registry, fall back to OpenCV probing
        if not cameras:
            try:
                import cv2
                for idx in range(3):
                    cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
                    if cap.isOpened():
                        ret, frame = cap.read()
                        cap.release()
                        if ret and frame is not None and frame.shape[0] > 0 and frame.shape[1] > 0:
                            cam_id = f"opencv_{idx}"
                            if cam_id not in seen_ids:
                                cameras.append({
                                    "device_id": cam_id,
                                    "device_path": f"OpenCV Camera {idx}",
                                    "friendly_name": f"Camera {idx}",
                                    "device_desc": f"Detected via OpenCV (index {idx})",
                                    "opencv_index": idx,
                                })
                                seen_ids.add(cam_id)
            except ImportError:
                logger.warning("OpenCV not available for camera detection")
            except Exception as e:
                logger.warning(f"OpenCV camera probe failed: {e}")
        
        logger.info(f"Found {len(cameras)} camera device(s)")
        return cameras
    
    def disable_camera_device(self, device_id: str = None) -> bool:
        """
        Disable webcam via Windows CapabilityAccessManager consent registry.
        Sets webcam consent to 'Deny' — blocks all apps from accessing the camera.
        
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to disable camera")
            return False
        
        try:
            consent_path = self.REGISTRY_PATHS["webcam_consent"]
            success = self.set_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                consent_path,
                "Value",
                "Deny",
                winreg.REG_SZ
            )
            
            if success:
                logger.info("Webcam disabled (consent set to Deny)")
            else:
                logger.error("Failed to set webcam consent to Deny")
            
            return success
        
        except Exception as e:
            logger.error(f"Error disabling camera: {e}")
            return False
    
    def enable_camera_device(self, device_id: str = None) -> bool:
        """
        Enable webcam via Windows CapabilityAccessManager consent registry.
        Sets webcam consent to 'Allow' — allows apps to access the camera.
        
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to enable devices")
            return False
        
        try:
            consent_path = self.REGISTRY_PATHS["webcam_consent"]
            success = self.set_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                consent_path,
                "Value",
                "Allow",
                winreg.REG_SZ
            )
            
            if success:
                logger.info("Webcam enabled (consent set to Allow)")
            else:
                logger.error("Failed to set webcam consent to Allow")
            
            return success
        
        except Exception as e:
            logger.error(f"Error enabling camera: {e}")
            return False
    
    def get_device_status(self, device_id: str = None) -> Optional[str]:
        """
        Get webcam status from CapabilityAccessManager consent registry
        
        Returns:
            Status string ('enabled' or 'disabled')
        """
        try:
            consent_path = self.REGISTRY_PATHS["webcam_consent"]
            value = self.get_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                consent_path,
                "Value"
            )
            
            if isinstance(value, str):
                if value.lower() == "allow":
                    return "enabled"
                elif value.lower() == "deny":
                    return "disabled"
            
            return "enabled"  # Default
        except Exception as e:
            logger.error(f"Error getting device status: {e}")
            return "unknown"
    
    # ============ DRIVER OPERATIONS ============
    
    def disable_driver(self, driver_name: str) -> bool:
        """
        Disable device driver
        
        Args:
            driver_name: Driver name (e.g., 'usbhub')
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to disable drivers")
            return False
        
        try:
            driver_path = f"{self.REGISTRY_PATHS['services']}\\{driver_name}"
            
            # Set start type to disabled (4)
            success = self.set_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                driver_path,
                "Start",
                4,  # 4 = disabled
                winreg.REG_DWORD
            )
            
            if success:
                logger.info(f"Driver disabled: {driver_name}")
            
            return success
        
        except Exception as e:
            logger.error(f"Error disabling driver: {e}")
            return False
    
    def enable_driver(self, driver_name: str) -> bool:
        """
        Enable device driver
        
        Args:
            driver_name: Driver name
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to enable drivers")
            return False
        
        try:
            driver_path = f"{self.REGISTRY_PATHS['services']}\\{driver_name}"
            
            # Set start type to auto (2)
            success = self.set_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                driver_path,
                "Start",
                2,  # 2 = auto start
                winreg.REG_DWORD
            )
            
            if success:
                logger.info(f"Driver enabled: {driver_name}")
            
            return success
        
        except Exception as e:
            logger.error(f"Error enabling driver: {e}")
            return False
    
    # ============ POLICY OPERATIONS ============
    
    def set_camera_policy(self, allow_camera: bool) -> bool:
        """
        Set Windows camera access policy
        
        Args:
            allow_camera: True to allow, False to disable
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required to set policies")
            return False
        
        try:
            # Windows 10+ camera privacy policy
            policy_path = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
            
            value = "Allow" if allow_camera else "Deny"
            
            success = self.set_registry_value(
                winreg.HKEY_CURRENT_USER,
                policy_path,
                "Value",
                value,
                winreg.REG_SZ
            )
            
            if success:
                logger.info(f"Camera policy set: {value}")
            
            return success
        
        except Exception as e:
            logger.error(f"Error setting camera policy: {e}")
            return False
    
    def disable_usb_mass_storage(self) -> bool:
        """
        Disable USB mass storage (prevents webcam module from loading)
        
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required")
            return False
        
        try:
            # USBSTOR = USB Storage
            driver_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            
            # Set start to disabled (4)
            success = self.set_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                driver_path,
                "Start",
                4,
                winreg.REG_DWORD
            )
            
            if success:
                logger.info("USB mass storage disabled")
            
            return success
        
        except Exception as e:
            logger.error(f"Error disabling USB storage: {e}")
            return False
    
    def enable_usb_mass_storage(self) -> bool:
        """
        Enable USB mass storage
        
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required")
            return False
        
        try:
            driver_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
            
            # Set start to auto (2)
            success = self.set_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                driver_path,
                "Start",
                2,
                winreg.REG_DWORD
            )
            
            if success:
                logger.info("USB mass storage enabled")
            
            return success
        
        except Exception as e:
            logger.error(f"Error enabling USB storage: {e}")
            return False
    
    # ============ DEVICE MANAGER OPERATIONS ============
    
    def disable_device_via_devcon(self, device_id: str) -> bool:
        """
        Disable device using devcon utility
        
        Args:
            device_id: Device hardware ID
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required")
            return False
        
        try:
            # devcon is Windows Device Console utility
            cmd = f'devcon disable "{device_id}"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            if success:
                logger.info(f"Device disabled via devcon: {device_id}")
            else:
                logger.error(f"devcon failed: {result.stderr}")
            
            return success
        
        except Exception as e:
            logger.error(f"Error running devcon: {e}")
            return False
    
    def enable_device_via_devcon(self, device_id: str) -> bool:
        """
        Enable device using devcon utility
        
        Args:
            device_id: Device hardware ID
            
        Returns:
            True if successful
        """
        if not self.is_admin:
            logger.error("Admin privileges required")
            return False
        
        try:
            cmd = f'devcon enable "{device_id}"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0
            if success:
                logger.info(f"Device enabled via devcon: {device_id}")
            else:
                logger.error(f"devcon failed: {result.stderr}")
            
            return success
        
        except Exception as e:
            logger.error(f"Error running devcon: {e}")
            return False
    
    # ============ INFORMATION GATHERING ============
    
    def get_system_info(self) -> Dict[str, str]:
        """
        Get system information
        
        Returns:
            Dictionary with system info
        """
        try:
            info = {
                "admin_privileges": str(self.is_admin),
                "os_version": self.get_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    "CurrentVersion"
                ) or "Unknown",
                "product_name": self.get_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    "ProductName"
                ) or "Unknown",
            }
            return info
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    registry = RegistryManager()
    
    print("=== Registry Manager Test ===\n")
    
    # System info
    print("[1] System Information:")
    sys_info = registry.get_system_info()
    for key, value in sys_info.items():
        print(f"  {key}: {value}")
    
    # Find cameras
    print("\n[2] Finding Camera Devices:")
    cameras = registry.find_camera_devices()
    if cameras:
        for camera in cameras:
            print(f"  Device: {camera['friendly_name']}")
            print(f"    ID: {camera['device_id']}")
            print(f"    Status: {registry.get_device_status(camera['device_id'])}")
    else:
        print("  No cameras found")
    
    # Admin check
    print(f"\n[3] Admin Privileges: {'✅ Yes' if registry.is_admin else '❌ No'}")
