"""
Authentication Manager for Webcam Spyware Security
Handles user registration, login, password management, and session management
"""

import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
import logging

from database import DatabaseManager
from crypto_manager import CryptoManager
from utils import ValidationUtils, SystemInfo, DateTimeUtils

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Manages user authentication and authorization"""
    
    # Session token expiry time (in hours)
    SESSION_EXPIRY_HOURS = 24
    
    # Password expiry time (in days)
    PASSWORD_EXPIRY_DAYS = 90
    
    def __init__(self, db: DatabaseManager = None):
        """
        Initialize authentication manager
        
        Args:
            db: Database manager instance
        """
        self.db = db or DatabaseManager()
        self.crypto = CryptoManager()
        self.current_user: Optional[Dict] = None
        self.current_token: Optional[str] = None
    
    # ============ USER REGISTRATION ============
    
    def register_user(self, username: str, email: str, password: str, 
                     role: str = 'employee') -> Tuple[bool, str]:
        """
        Register a new user
        
        Args:
            username: Username (3-50 alphanumeric chars)
            email: Email address
            password: Password (min 8 chars, upper, lower, digit, special)
            role: User role ('admin' or 'employee')
            
        Returns:
            Tuple (success: bool, message: str)
        """
        # Validate inputs
        if not ValidationUtils.is_valid_username(username):
            return False, "Invalid username. Must be 3-50 characters, alphanumeric or underscore."
        
        if not ValidationUtils.is_valid_email(email):
            return False, "Invalid email format."
        
        if not ValidationUtils.is_valid_password(password):
            return False, (
                "Password must be at least 8 characters with uppercase, "
                "lowercase, digit, and special character."
            )
        
        if role not in ['admin', 'employee']:
            return False, "Invalid role. Must be 'admin' or 'employee'."
        
        # Check if user already exists
        existing_user = self.db.get_user_by_username(username)
        if existing_user:
            return False, "Username already exists."
        
        try:
            # Hash password
            password_hash = CryptoManager.hash_password(password)
            
            # Create user
            user_id = self.db.create_user(username, email, password_hash, role)
            
            # Log registration
            self.db.add_log(
                user_id, username, 'user_registered', 'info',
                f'User registered with role: {role}',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            logger.info(f"User registered successfully: {username}")
            return True, f"User '{username}' registered successfully."
        
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return False, "Registration failed. Please try again."
    
    # ============ USER LOGIN ============
    
    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[str]]:
        """
        Authenticate user and create session
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Tuple (success: bool, message: str, token: Optional[str])
        """
        try:
            # Get user
            user = self.db.get_user_by_username(username)
            
            if not user:
                # Log failed attempt
                self.db.add_intruder_log(
                    failed_attempts=1,
                    ip_address=SystemInfo.get_ip_address(),
                    machine_name=SystemInfo.get_machine_name()
                )
                logger.warning(f"Login failed: User not found - {username}")
                return False, "Invalid username or password.", None
            
            # Check if user is active
            if not user['is_active']:
                logger.warning(f"Login failed: User inactive - {username}")
                return False, "User account is inactive.", None
            
            # Verify password
            if not CryptoManager.verify_password(password, user['password_hash']):
                # Log failed attempt
                self.db.add_intruder_log(
                    failed_attempts=1,
                    ip_address=SystemInfo.get_ip_address(),
                    machine_name=SystemInfo.get_machine_name()
                )
                logger.warning(f"Login failed: Invalid password - {username}")
                return False, "Invalid username or password.", None
            
            # Create session token
            token = self._create_session_token(user['user_id'])
            
            # Update last login
            self.db.update_user(user['user_id'], last_login=DateTimeUtils.get_current_timestamp())
            
            # Log successful login
            self.db.add_log(
                user['user_id'], username, 'login', 'info',
                'User logged in successfully',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            # Store current user
            self.current_user = user
            self.current_token = token
            
            logger.info(f"User logged in successfully: {username}")
            return True, "Login successful.", token
        
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False, "Login failed. Please try again.", None
    
    def logout(self) -> Tuple[bool, str]:
        """
        Logout current user
        
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            if not self.current_user or not self.current_token:
                return False, "No active session."
            
            username = self.current_user['username']
            user_id = self.current_user['user_id']
            
            # Invalidate session
            self.db.invalidate_session(self.current_token)
            
            # Log logout
            self.db.add_log(
                user_id, username, 'logout', 'info',
                'User logged out',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            # Clear current user
            self.current_user = None
            self.current_token = None
            
            logger.info(f"User logged out: {username}")
            return True, "Logout successful."
        
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False, "Logout failed."
    
    # ============ PASSWORD MANAGEMENT ============
    
    def change_password(self, username: str, old_password: str, 
                       new_password: str) -> Tuple[bool, str]:
        """
        Change user password
        
        Args:
            username: Username
            old_password: Current password
            new_password: New password
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            # Get user
            user = self.db.get_user_by_username(username)
            if not user:
                return False, "User not found."
            
            # Verify old password
            if not CryptoManager.verify_password(old_password, user['password_hash']):
                self.db.add_log(
                    user['user_id'], username, 'password_change_failed', 'warning',
                    'Invalid old password',
                    SystemInfo.get_ip_address(),
                    SystemInfo.get_machine_name()
                )
                return False, "Invalid old password."
            
            # Validate new password
            if not ValidationUtils.is_valid_password(new_password):
                return False, (
                    "New password must be at least 8 characters with uppercase, "
                    "lowercase, digit, and special character."
                )
            
            # Prevent reusing old password
            if CryptoManager.verify_password(new_password, user['password_hash']):
                return False, "New password cannot be the same as old password."
            
            # Hash new password
            new_hash = CryptoManager.hash_password(new_password)
            
            # Update password
            self.db.update_user(user['user_id'], password_hash=new_hash)
            
            # Log password change
            self.db.add_log(
                user['user_id'], username, 'password_changed', 'info',
                'User password changed successfully',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            logger.info(f"Password changed for user: {username}")
            return True, "Password changed successfully."
        
        except Exception as e:
            logger.error(f"Password change error: {e}")
            return False, "Password change failed."
    
    def reset_password(self, email: str) -> Tuple[bool, str, Optional[str]]:
        """
        Initiate password reset (admin function)
        
        Args:
            email: User email
            
        Returns:
            Tuple (success: bool, message: str, reset_token: Optional[str])
        """
        try:
            # Find user by email
            all_users = self.db.get_all_users()
            user = next((u for u in all_users if u['email'] == email), None)
            
            if not user:
                # Don't reveal if email exists or not (security)
                return True, "If email exists, password reset instructions have been sent.", None
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            
            # In production, store this token with expiry and send via email
            # For now, we'll just return it
            
            # Log password reset request
            self.db.add_log(
                user['user_id'], user['username'], 'password_reset_requested', 'info',
                'Password reset requested',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            logger.info(f"Password reset initiated for: {user['username']}")
            return True, "Password reset instructions sent to email.", reset_token
        
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return False, "Password reset failed.", None
    
    def set_password(self, username: str, new_password: str, 
                    admin_id: int = None) -> Tuple[bool, str]:
        """
        Set password for user (admin function)
        
        Args:
            username: Username
            new_password: New password
            admin_id: Admin user ID for authorization
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            # Verify admin authorization
            if admin_id:
                admin = self.db.get_user_by_id(admin_id)
                if not admin or admin['role'] != 'admin':
                    return False, "Unauthorized. Admin privileges required."
            
            # Get user
            user = self.db.get_user_by_username(username)
            if not user:
                return False, "User not found."
            
            # Validate password
            if not ValidationUtils.is_valid_password(new_password):
                return False, "Password does not meet security requirements."
            
            # Hash and update
            password_hash = CryptoManager.hash_password(new_password)
            self.db.update_user(user['user_id'], password_hash=password_hash)
            
            # Log
            self.db.add_log(
                user['user_id'], username, 'password_reset', 'info',
                'Password reset by administrator',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            logger.info(f"Password reset for user: {username}")
            return True, "Password reset successfully."
        
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return False, "Password reset failed."
    
    # ============ SESSION MANAGEMENT ============
    
    def _create_session_token(self, user_id: int) -> str:
        """
        Create a session token for user
        
        Args:
            user_id: User ID
            
        Returns:
            Session token
        """
        token = str(uuid.uuid4())
        expires_at = DateTimeUtils.add_hours(self.SESSION_EXPIRY_HOURS)
        
        self.db.create_session(user_id, token, expires_at)
        return token
    
    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """
        Verify session token and get user
        
        Args:
            token: Session token
            
        Returns:
            Tuple (valid: bool, user: Optional[Dict])
        """
        try:
            session = self.db.get_session(token)
            
            if not session:
                return False, None
            
            # Check expiry
            expiry = session['expires_at']
            if datetime.fromisoformat(expiry) < datetime.now():
                self.db.invalidate_session(token)
                return False, None
            
            # Get user
            user = self.db.get_user_by_id(session['user_id'])
            return user is not None, user
        
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False, None
    
    def refresh_token(self, old_token: str) -> Tuple[bool, Optional[str]]:
        """
        Refresh session token
        
        Args:
            old_token: Current session token
            
        Returns:
            Tuple (success: bool, new_token: Optional[str])
        """
        try:
            valid, user = self.verify_token(old_token)
            
            if not valid or not user:
                return False, None
            
            # Invalidate old token
            self.db.invalidate_session(old_token)
            
            # Create new token
            new_token = self._create_session_token(user['user_id'])
            
            logger.info(f"Token refreshed for user: {user['username']}")
            return True, new_token
        
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return False, None
    
    # ============ ROLE-BASED ACCESS CONTROL ============
    
    def is_admin(self, user: Dict = None) -> bool:
        """
        Check if user is admin
        
        Args:
            user: User dict (defaults to current user)
            
        Returns:
            True if admin
        """
        user = user or self.current_user
        return user and user.get('role') == 'admin'
    
    def is_employee(self, user: Dict = None) -> bool:
        """
        Check if user is employee
        
        Args:
            user: User dict (defaults to current user)
            
        Returns:
            True if employee
        """
        user = user or self.current_user
        return user and user.get('role') == 'employee'
    
    def has_permission(self, permission: str, user: Dict = None) -> bool:
        """
        Check if user has specific permission
        
        Args:
            permission: Permission name
            user: User dict (defaults to current user)
            
        Returns:
            True if has permission
        """
        user = user or self.current_user
        
        if not user:
            return False
        
        # Admin has all permissions
        if user['role'] == 'admin':
            return True
        
        # Employee permissions
        employee_permissions = {
            'enable_webcam',
            'disable_webcam',
            'view_own_logs',
            'verify_face',
        }
        
        admin_permissions = {
            'create_user',
            'delete_user',
            'manage_policies',
            'view_all_logs',
            'generate_reports',
            'manage_settings',
        }
        
        if user['role'] == 'employee':
            return permission in employee_permissions
        
        return False
    
    # ============ USER MANAGEMENT ============
    
    def get_user_profile(self, user_id: int = None) -> Optional[Dict]:
        """
        Get user profile
        
        Args:
            user_id: User ID (defaults to current user)
            
        Returns:
            User dict without sensitive data
        """
        user_id = user_id or (self.current_user['user_id'] if self.current_user else None)
        
        if not user_id:
            return None
        
        user = self.db.get_user_by_id(user_id)
        
        if not user:
            return None
        
        # Remove sensitive data
        user.pop('password_hash', None)
        user.pop('face_data', None)
        
        return dict(user)
    
    def update_user_profile(self, user_id: int, email: str = None, 
                           face_encoding: str = None) -> Tuple[bool, str]:
        """
        Update user profile
        
        Args:
            user_id: User ID
            email: New email
            face_encoding: New face encoding
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            user = self.db.get_user_by_id(user_id)
            if not user:
                return False, "User not found."
            
            updates = {}
            
            if email:
                if not ValidationUtils.is_valid_email(email):
                    return False, "Invalid email format."
                updates['email'] = email
            
            if face_encoding:
                updates['face_encoding'] = face_encoding
            
            if updates:
                self.db.update_user(user_id, **updates)
                logger.info(f"User profile updated: {user['username']}")
            
            return True, "Profile updated successfully."
        
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            return False, "Profile update failed."
    
    def get_all_users(self, admin_id: int = None) -> Tuple[bool, list]:
        """
        Get all users (admin only)
        
        Args:
            admin_id: Admin user ID for authorization
            
        Returns:
            Tuple (success: bool, users: list)
        """
        try:
            admin = self.db.get_user_by_id(admin_id) if admin_id else self.current_user
            
            if not admin or admin['role'] != 'admin':
                return False, []
            
            users = self.db.get_all_users()
            
            # Remove sensitive data
            for user in users:
                user.pop('password_hash', None)
                user.pop('face_data', None)
            
            return True, users
        
        except Exception as e:
            logger.error(f"Get users error: {e}")
            return False, []
    
    def delete_user(self, user_id: int, admin_id: int = None) -> Tuple[bool, str]:
        """
        Delete user (admin only)
        
        Args:
            user_id: User ID to delete
            admin_id: Admin user ID for authorization
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            admin = self.db.get_user_by_id(admin_id) if admin_id else self.current_user
            
            if not admin or admin['role'] != 'admin':
                return False, "Unauthorized. Admin privileges required."
            
            user = self.db.get_user_by_id(user_id)
            if not user:
                return False, "User not found."
            
            # Soft delete
            self.db.delete_user(user_id)
            
            # Log
            self.db.add_log(
                admin['user_id'], admin['username'], 'user_deleted', 'warning',
                f'User deleted: {user["username"]}',
                SystemInfo.get_ip_address(),
                SystemInfo.get_machine_name()
            )
            
            logger.info(f"User deleted: {user['username']}")
            return True, "User deleted successfully."
        
        except Exception as e:
            logger.error(f"Delete user error: {e}")
            return False, "Delete failed."
    
    # ============ FACE RECOGNITION VERIFICATION ============
    
    def verify_face_required(self, user_id: int = None) -> bool:
        """
        Check if face verification is required for sensitive operations
        
        Args:
            user_id: User ID (defaults to current user)
            
        Returns:
            True if face verification required
        """
        user_id = user_id or (self.current_user['user_id'] if self.current_user else None)
        
        if not user_id:
            return False
        
        user = self.db.get_user_by_id(user_id)
        
        # Face verification required if face encoding exists
        return user and user.get('face_encoding') is not None
    
    def can_access_webcam(self, user_id: int = None) -> bool:
        """
        Check if user can access webcam
        
        Args:
            user_id: User ID (defaults to current user)
            
        Returns:
            True if user can access webcam
        """
        user_id = user_id or (self.current_user['user_id'] if self.current_user else None)
        
        if not user_id:
            return False
        
        user = self.db.get_user_by_id(user_id)
        
        if not user or not user['is_active']:
            return False
        
        # Employees can access webcam
        return user['role'] == 'employee' or user['role'] == 'admin'


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize
    auth = AuthenticationManager()
    
    # Test registration
    print("=== Registration ===")
    success, msg = auth.register_user('testuser', 'test@example.com', 'TestPass123!', 'employee')
    print(f"Register: {success} - {msg}")
    
    # Test login
    print("\n=== Login ===")
    success, msg, token = auth.login('testuser', 'TestPass123!')
    print(f"Login: {success} - {msg}")
    print(f"Token: {token[:20]}..." if token else "No token")
    
    # Test password change
    print("\n=== Password Change ===")
    success, msg = auth.change_password('testuser', 'TestPass123!', 'NewPass456!')
    print(f"Change Password: {success} - {msg}")
    
    # Test token verification
    if token:
        print("\n=== Token Verification ===")
        valid, user = auth.verify_token(token)
        print(f"Token valid: {valid}")
        if user:
            print(f"User: {user['username']}")
