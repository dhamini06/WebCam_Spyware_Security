"""
User Manager for Webcam Spyware Security
High-level user management operations
"""

from typing import Optional, Tuple, Dict, List
import logging

from database import DatabaseManager
from authentication import AuthenticationManager

logger = logging.getLogger(__name__)


class UserManager:
    """Manages user operations at a high level"""
    
    def __init__(self, auth: AuthenticationManager = None, db: DatabaseManager = None):
        """
        Initialize user manager
        
        Args:
            auth: Authentication manager instance
            db: Database manager instance
        """
        self.db = db or DatabaseManager()
        self.auth = auth or AuthenticationManager(self.db)
    
    # ============ USER CREATION ============
    
    def create_employee(self, username: str, email: str, password: str,
                       admin_id: int) -> Tuple[bool, str, Optional[int]]:
        """
        Create new employee (admin only)
        
        Args:
            username: Username
            email: Email
            password: Initial password
            admin_id: Admin user ID for authorization
            
        Returns:
            Tuple (success: bool, message: str, user_id: Optional[int])
        """
        # Verify admin authorization
        admin = self.db.get_user_by_id(admin_id)
        if not admin or admin['role'] != 'admin':
            return False, "Unauthorized. Admin privileges required.", None
        
        # Register user
        success, msg = self.auth.register_user(username, email, password, 'employee')
        
        if success:
            user = self.db.get_user_by_username(username)
            return True, msg, user['user_id']
        
        return False, msg, None
    
    def create_admin(self, username: str, email: str, password: str,
                    admin_id: int) -> Tuple[bool, str, Optional[int]]:
        """
        Create new admin (admin only)
        
        Args:
            username: Username
            email: Email
            password: Initial password
            admin_id: Admin user ID for authorization
            
        Returns:
            Tuple (success: bool, message: str, user_id: Optional[int])
        """
        # Verify admin authorization
        admin = self.db.get_user_by_id(admin_id)
        if not admin or admin['role'] != 'admin':
            return False, "Unauthorized. Admin privileges required.", None
        
        # Register user with admin role
        success, msg = self.auth.register_user(username, email, password, 'admin')
        
        if success:
            user = self.db.get_user_by_username(username)
            return True, msg, user['user_id']
        
        return False, msg, None
    
    # ============ USER LISTING ============
    
    def list_all_users(self, admin_id: int) -> Tuple[bool, List[Dict]]:
        """
        List all users (admin only)
        
        Args:
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, users: List[Dict])
        """
        return self.auth.get_all_users(admin_id)
    
    def list_employees(self, admin_id: int) -> Tuple[bool, List[Dict]]:
        """
        List all employees (admin only)
        
        Args:
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, employees: List[Dict])
        """
        success, users = self.auth.get_all_users(admin_id)
        
        if not success:
            return False, []
        
        employees = [u for u in users if u['role'] == 'employee']
        return True, employees
    
    def list_admins(self, admin_id: int) -> Tuple[bool, List[Dict]]:
        """
        List all admins (admin only)
        
        Args:
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, admins: List[Dict])
        """
        success, users = self.auth.get_all_users(admin_id)
        
        if not success:
            return False, []
        
        admins = [u for u in users if u['role'] == 'admin']
        return True, admins
    
    # ============ USER DETAILS ============
    
    def get_user_details(self, username: str, admin_id: int = None) -> Tuple[bool, Optional[Dict]]:
        """
        Get detailed user information (admin or user themselves)
        
        Args:
            username: Username
            admin_id: Admin user ID (optional)
            
        Returns:
            Tuple (success: bool, user_details: Optional[Dict])
        """
        try:
            user = self.db.get_user_by_username(username)
            
            if not user:
                return False, None
            
            # Check authorization
            if admin_id:
                admin = self.db.get_user_by_id(admin_id)
                if not admin or admin['role'] != 'admin':
                    return False, None
            
            # Remove sensitive data
            user_copy = dict(user)
            user_copy.pop('password_hash', None)
            user_copy.pop('face_data', None)
            
            return True, user_copy
        
        except Exception as e:
            logger.error(f"Get user details error: {e}")
            return False, None
    
    def get_user_activity(self, user_id: int, admin_id: int = None,
                         limit: int = 100) -> Tuple[bool, List[Dict]]:
        """
        Get user activity logs (admin or user themselves)
        
        Args:
            user_id: User ID
            admin_id: Admin user ID
            limit: Max logs to return
            
        Returns:
            Tuple (success: bool, logs: List[Dict])
        """
        try:
            # Check authorization
            if admin_id:
                admin = self.db.get_user_by_id(admin_id)
                if not admin or admin['role'] != 'admin':
                    return False, []
            
            logs = self.db.get_logs_by_user(user_id, limit)
            return True, logs
        
        except Exception as e:
            logger.error(f"Get user activity error: {e}")
            return False, []
    
    # ============ USER MODIFICATION ============
    
    def update_user_role(self, user_id: int, new_role: str,
                        admin_id: int) -> Tuple[bool, str]:
        """
        Update user role (admin only)
        
        Args:
            user_id: User ID to update
            new_role: New role ('admin' or 'employee')
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            # Verify admin authorization
            admin = self.db.get_user_by_id(admin_id)
            if not admin or admin['role'] != 'admin':
                return False, "Unauthorized. Admin privileges required."
            
            # Validate role
            if new_role not in ['admin', 'employee']:
                return False, "Invalid role."
            
            user = self.db.get_user_by_id(user_id)
            if not user:
                return False, "User not found."
            
            # Prevent last admin deletion
            if user['role'] == 'admin' and new_role == 'employee':
                admins = self.db.get_all_users()
                admin_count = sum(1 for u in admins if u['role'] == 'admin' and u['is_active'])
                
                if admin_count <= 1:
                    return False, "Cannot demote the last active admin."
            
            # Update role
            self.db.update_user(user_id, role=new_role)
            
            logger.info(f"User {user['username']} role updated to {new_role}")
            return True, f"Role updated to {new_role}."
        
        except Exception as e:
            logger.error(f"Update role error: {e}")
            return False, "Update failed."
    
    def activate_user(self, user_id: int, admin_id: int) -> Tuple[bool, str]:
        """
        Activate user (admin only)
        
        Args:
            user_id: User ID
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            # Verify admin
            admin = self.db.get_user_by_id(admin_id)
            if not admin or admin['role'] != 'admin':
                return False, "Unauthorized."
            
            user = self.db.get_user_by_id(user_id)
            if not user:
                return False, "User not found."
            
            self.db.update_user(user_id, is_active=True)
            logger.info(f"User activated: {user['username']}")
            return True, "User activated."
        
        except Exception as e:
            logger.error(f"Activate user error: {e}")
            return False, "Activation failed."
    
    def deactivate_user(self, user_id: int, admin_id: int) -> Tuple[bool, str]:
        """
        Deactivate user (admin only)
        
        Args:
            user_id: User ID
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, message: str)
        """
        try:
            # Verify admin
            admin = self.db.get_user_by_id(admin_id)
            if not admin or admin['role'] != 'admin':
                return False, "Unauthorized."
            
            user = self.db.get_user_by_id(user_id)
            if not user:
                return False, "User not found."
            
            self.db.update_user(user_id, is_active=False)
            logger.info(f"User deactivated: {user['username']}")
            return True, "User deactivated."
        
        except Exception as e:
            logger.error(f"Deactivate user error: {e}")
            return False, "Deactivation failed."
    
    # ============ USER DELETION ============
    
    def delete_user(self, user_id: int, admin_id: int) -> Tuple[bool, str]:
        """
        Delete user (admin only)
        
        Args:
            user_id: User ID to delete
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, message: str)
        """
        return self.auth.delete_user(user_id, admin_id)
    
    # ============ USER STATISTICS ============
    
    def get_user_statistics(self, admin_id: int) -> Tuple[bool, Optional[Dict]]:
        """
        Get user statistics (admin only)
        
        Args:
            admin_id: Admin user ID
            
        Returns:
            Tuple (success: bool, stats: Optional[Dict])
        """
        try:
            # Verify admin
            admin = self.db.get_user_by_id(admin_id)
            if not admin or admin['role'] != 'admin':
                return False, None
            
            users = self.db.get_all_users()
            
            stats = {
                'total_users': len(users),
                'active_users': sum(1 for u in users if u['is_active']),
                'inactive_users': sum(1 for u in users if not u['is_active']),
                'admins': sum(1 for u in users if u['role'] == 'admin'),
                'employees': sum(1 for u in users if u['role'] == 'employee'),
            }
            
            return True, stats
        
        except Exception as e:
            logger.error(f"Get statistics error: {e}")
            return False, None
    
    # ============ INTRUDER DETECTION ============
    
    def get_intruder_attempts(self, admin_id: int, limit: int = 50) -> Tuple[bool, List[Dict]]:
        """
        Get intruder detection logs (admin only)
        
        Args:
            admin_id: Admin user ID
            limit: Max records
            
        Returns:
            Tuple (success: bool, logs: List[Dict])
        """
        try:
            # Verify admin
            admin = self.db.get_user_by_id(admin_id)
            if not admin or admin['role'] != 'admin':
                return False, []
            
            logs = self.db.get_intruder_logs(limit)
            return True, logs
        
        except Exception as e:
            logger.error(f"Get intruder logs error: {e}")
            return False, []


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    db = DatabaseManager()
    auth = AuthenticationManager(db)
    user_manager = UserManager(auth, db)
    
    # Test: Create initial admin
    print("=== Creating Initial Admin ===")
    success, msg = auth.register_user('admin', 'admin@company.com', 'AdminPass123!', 'admin')
    print(f"Create admin: {success} - {msg}")
    
    # Get admin
    admin = db.get_user_by_username('admin')
    admin_id = admin['user_id']
    
    # Test: Create employee
    print("\n=== Creating Employee ===")
    success, msg, emp_id = user_manager.create_employee(
        'employee1', 'emp1@company.com', 'EmpPass123!', admin_id
    )
    print(f"Create employee: {success} - {msg}")
    
    # Test: List users
    print("\n=== Listing Users ===")
    success, users = user_manager.list_all_users(admin_id)
    print(f"List users: {success}")
    for user in users:
        print(f"  - {user['username']} ({user['role']})")
    
    # Test: Statistics
    print("\n=== User Statistics ===")
    success, stats = user_manager.get_user_statistics(admin_id)
    if success:
        print(f"Total users: {stats['total_users']}")
        print(f"Active users: {stats['active_users']}")
        print(f"Admins: {stats['admins']}")
        print(f"Employees: {stats['employees']}")
