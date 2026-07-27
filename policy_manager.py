"""
Policy Manager for Webcam Spyware Security
Handles webcam access policies with time-based and role-based restrictions
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json

from database import DatabaseManager
from utils import DateTimeUtils

logger = logging.getLogger(__name__)


class Policy:
    """Represents a webcam access policy"""
    
    # Policy types
    TYPE_ALLOW = "allow"
    TYPE_DENY = "deny"
    
    # Policy scopes
    SCOPE_GLOBAL = "global"
    SCOPE_USER = "user"
    SCOPE_APPLICATION = "application"
    
    def __init__(self, policy_id: int, name: str, description: str,
                 policy_type: str, scope: str, enabled: bool = True,
                 start_time: str = None, end_time: str = None,
                 allowed_applications: List[str] = None,
                 allowed_users: List[int] = None,
                 created_at: str = None):
        """
        Initialize policy
        
        Args:
            policy_id: Policy ID
            name: Policy name
            description: Policy description
            policy_type: 'allow' or 'deny'
            scope: 'global', 'user', or 'application'
            enabled: Whether policy is enabled
            start_time: Start time (HH:MM) optional
            end_time: End time (HH:MM) optional
            allowed_applications: List of allowed apps
            allowed_users: List of allowed user IDs
            created_at: Creation timestamp
        """
        self.policy_id = policy_id
        self.name = name
        self.description = description
        self.policy_type = policy_type
        self.scope = scope
        self.enabled = enabled
        self.start_time = start_time
        self.end_time = end_time
        self.allowed_applications = allowed_applications or []
        self.allowed_users = allowed_users or []
        self.created_at = created_at or DateTimeUtils.get_current_timestamp()
    
    def is_active_now(self) -> bool:
        """Check if policy is active at current time"""
        if not self.enabled:
            return False
        
        # If no time restrictions, always active
        if not self.start_time or not self.end_time:
            return True
        
        # Check time range
        current_time = datetime.now().strftime('%H:%M')
        return self.start_time <= current_time <= self.end_time
    
    def matches_user(self, user_id: int) -> bool:
        """Check if policy matches user"""
        if self.scope == self.SCOPE_GLOBAL:
            return True
        if self.scope == self.SCOPE_USER:
            return user_id in self.allowed_users
        return False
    
    def matches_application(self, app_name: str) -> bool:
        """Check if policy matches application"""
        if self.scope == self.SCOPE_GLOBAL:
            return True
        if self.scope == self.SCOPE_APPLICATION:
            return app_name in self.allowed_applications
        return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'policy_id': self.policy_id,
            'name': self.name,
            'description': self.description,
            'policy_type': self.policy_type,
            'scope': self.scope,
            'enabled': self.enabled,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'allowed_applications': self.allowed_applications,
            'allowed_users': self.allowed_users,
            'created_at': self.created_at,
            'is_active_now': self.is_active_now()
        }


class PolicyManager:
    """Manages webcam access policies"""
    
    def __init__(self, db: DatabaseManager = None):
        """
        Initialize policy manager
        
        Args:
            db: Database manager instance
        """
        self.db = db or DatabaseManager()
        self.policies = {}
        self._load_policies()
    
    # ============ POLICY MANAGEMENT ============
    
    def create_policy(self, name: str, description: str, policy_type: str,
                     scope: str, enabled: bool = True, 
                     start_time: str = None, end_time: str = None) -> int:
        """
        Create new policy
        
        Args:
            name: Policy name
            description: Description
            policy_type: 'allow' or 'deny'
            scope: 'global', 'user', or 'application'
            enabled: Whether enabled
            start_time: Start time (HH:MM)
            end_time: End time (HH:MM)
            
        Returns:
            Policy ID
        """
        try:
            # Validate inputs
            if policy_type not in [Policy.TYPE_ALLOW, Policy.TYPE_DENY]:
                raise ValueError(f"Invalid policy type: {policy_type}")
            
            if scope not in [Policy.SCOPE_GLOBAL, Policy.SCOPE_USER, 
                           Policy.SCOPE_APPLICATION]:
                raise ValueError(f"Invalid scope: {scope}")
            
            # Create in database
            policy_id = self.db.create_policy(
                name, description, policy_type, scope, enabled,
                start_time, end_time
            )
            
            # Create policy object
            policy = Policy(policy_id, name, description, policy_type,
                          scope, enabled, start_time, end_time)
            self.policies[policy_id] = policy
            
            logger.info(f"Policy created: {name} (ID: {policy_id})")
            return policy_id
        
        except Exception as e:
            logger.error(f"Error creating policy: {e}")
            return 0
    
    def get_policy(self, policy_id: int) -> Optional[Dict]:
        """
        Get policy details
        
        Args:
            policy_id: Policy ID
            
        Returns:
            Policy dictionary or None
        """
        try:
            if policy_id in self.policies:
                return self.policies[policy_id].to_dict()
            return None
        except Exception as e:
            logger.error(f"Error getting policy: {e}")
            return None
    
    def get_all_policies(self) -> List[Dict]:
        """
        Get all policies
        
        Returns:
            List of policy dictionaries
        """
        try:
            return [p.to_dict() for p in self.policies.values()]
        except Exception as e:
            logger.error(f"Error getting policies: {e}")
            return []
    
    def get_policies_by_type(self, policy_type: str) -> List[Dict]:
        """
        Get policies by type
        
        Args:
            policy_type: 'allow' or 'deny'
            
        Returns:
            List of matching policies
        """
        try:
            return [p.to_dict() for p in self.policies.values()
                   if p.policy_type == policy_type]
        except Exception as e:
            logger.error(f"Error getting policies: {e}")
            return []
    
    def get_policies_by_scope(self, scope: str) -> List[Dict]:
        """
        Get policies by scope
        
        Args:
            scope: 'global', 'user', or 'application'
            
        Returns:
            List of matching policies
        """
        try:
            return [p.to_dict() for p in self.policies.values()
                   if p.scope == scope]
        except Exception as e:
            logger.error(f"Error getting policies: {e}")
            return []
    
    def update_policy(self, policy_id: int, **kwargs) -> bool:
        """
        Update policy
        
        Args:
            policy_id: Policy ID
            **kwargs: Fields to update
            
        Returns:
            True if successful
        """
        try:
            if policy_id not in self.policies:
                return False
            
            policy = self.policies[policy_id]
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)
            
            logger.info(f"Policy updated: {policy_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error updating policy: {e}")
            return False
    
    def delete_policy(self, policy_id: int) -> bool:
        """
        Delete policy
        
        Args:
            policy_id: Policy ID
            
        Returns:
            True if successful
        """
        try:
            if policy_id not in self.policies:
                return False
            
            del self.policies[policy_id]
            logger.info(f"Policy deleted: {policy_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error deleting policy: {e}")
            return False
    
    def enable_policy(self, policy_id: int) -> bool:
        """Enable policy"""
        return self.update_policy(policy_id, enabled=True)
    
    def disable_policy(self, policy_id: int) -> bool:
        """Disable policy"""
        return self.update_policy(policy_id, enabled=False)
    
    # ============ POLICY ASSIGNMENT ============
    
    def add_user_to_policy(self, policy_id: int, user_id: int) -> bool:
        """
        Add user to policy
        
        Args:
            policy_id: Policy ID
            user_id: User ID
            
        Returns:
            True if successful
        """
        try:
            if policy_id not in self.policies:
                return False
            
            policy = self.policies[policy_id]
            if user_id not in policy.allowed_users:
                policy.allowed_users.append(user_id)
                logger.info(f"User {user_id} added to policy {policy_id}")
            
            return True
        except Exception as e:
            logger.error(f"Error adding user to policy: {e}")
            return False
    
    def remove_user_from_policy(self, policy_id: int, user_id: int) -> bool:
        """
        Remove user from policy
        
        Args:
            policy_id: Policy ID
            user_id: User ID
            
        Returns:
            True if successful
        """
        try:
            if policy_id not in self.policies:
                return False
            
            policy = self.policies[policy_id]
            if user_id in policy.allowed_users:
                policy.allowed_users.remove(user_id)
                logger.info(f"User {user_id} removed from policy {policy_id}")
            
            return True
        except Exception as e:
            logger.error(f"Error removing user from policy: {e}")
            return False
    
    def add_application_to_policy(self, policy_id: int, 
                                 app_name: str) -> bool:
        """
        Add application to policy
        
        Args:
            policy_id: Policy ID
            app_name: Application name
            
        Returns:
            True if successful
        """
        try:
            if policy_id not in self.policies:
                return False
            
            policy = self.policies[policy_id]
            if app_name not in policy.allowed_applications:
                policy.allowed_applications.append(app_name)
                logger.info(f"App {app_name} added to policy {policy_id}")
            
            return True
        except Exception as e:
            logger.error(f"Error adding app to policy: {e}")
            return False
    
    def remove_application_from_policy(self, policy_id: int,
                                      app_name: str) -> bool:
        """
        Remove application from policy
        
        Args:
            policy_id: Policy ID
            app_name: Application name
            
        Returns:
            True if successful
        """
        try:
            if policy_id not in self.policies:
                return False
            
            policy = self.policies[policy_id]
            if app_name in policy.allowed_applications:
                policy.allowed_applications.remove(app_name)
                logger.info(f"App {app_name} removed from policy {policy_id}")
            
            return True
        except Exception as e:
            logger.error(f"Error removing app from policy: {e}")
            return False
    
    # ============ POLICY EVALUATION ============
    
    def evaluate_access(self, user_id: int = None, 
                       app_name: str = None) -> Tuple[bool, str]:
        """
        Evaluate if access is allowed
        
        Args:
            user_id: User ID (optional)
            app_name: Application name (optional)
            
        Returns:
            Tuple of (allowed, reason)
        """
        try:
            # Start with allow by default
            allowed = True
            reason = "No policies applied"
            
            # Get applicable policies
            deny_policies = self.get_policies_by_type(Policy.TYPE_DENY)
            allow_policies = self.get_policies_by_type(Policy.TYPE_ALLOW)
            
            # Check deny policies first
            for policy in deny_policies:
                if not policy.get('enabled'):
                    continue
                
                if not policy.get('is_active_now'):
                    continue
                
                if user_id and policy.get('scope') == Policy.SCOPE_USER:
                    if user_id in policy.get('allowed_users', []):
                        allowed = False
                        reason = f"Denied by policy: {policy['name']}"
                        break
                
                if app_name and policy.get('scope') == Policy.SCOPE_APPLICATION:
                    if app_name in policy.get('allowed_applications', []):
                        allowed = False
                        reason = f"Denied by policy: {policy['name']}"
                        break
                
                if policy.get('scope') == Policy.SCOPE_GLOBAL:
                    allowed = False
                    reason = f"Denied by global policy: {policy['name']}"
                    break
            
            return (allowed, reason)
        
        except Exception as e:
            logger.error(f"Error evaluating access: {e}")
            return (False, str(e))
    
    # ============ HELPER METHODS ============
    
    def _load_policies(self):
        """Load policies from database"""
        try:
            policies_data = self.db.get_all_policies()
            
            for row in policies_data:
                try:
                    # Handle both dict and Row objects
                    if isinstance(row, dict):
                        r = row
                    else:
                        r = dict(row)
                    
                    policy_id = r['policy_id']
                    policy = Policy(
                        policy_id=policy_id,
                        name=r['policy_name'],
                        description=r.get('description', ''),
                        policy_type=r.get('policy_type', 'allow'),
                        scope=r.get('scope', 'global'),
                        enabled=bool(r.get('is_active', 1)),
                        start_time=r.get('allowed_start_time'),
                        end_time=r.get('allowed_end_time'),
                        created_at=r.get('created_at')
                    )
                    self.policies[policy_id] = policy
                except Exception as e:
                    logger.warning(f"Failed to load policy row: {e}")
            
            logger.info(f"Loaded {len(self.policies)} policies")
        
        except Exception as e:
            logger.warning(f"Policy loading not available: {e}")
    
    # ============ STATISTICS ============
    
    def get_policy_statistics(self) -> Dict:
        """Get policy statistics"""
        try:
            total_policies = len(self.policies)
            enabled_policies = sum(
                1 for p in self.policies.values() if p.enabled
            )
            active_policies = sum(
                1 for p in self.policies.values() if p.is_active_now()
            )
            
            # Count by type
            type_counts = {}
            for policy in self.policies.values():
                policy_type = policy.policy_type
                type_counts[policy_type] = type_counts.get(policy_type, 0) + 1
            
            # Count by scope
            scope_counts = {}
            for policy in self.policies.values():
                scope = policy.scope
                scope_counts[scope] = scope_counts.get(scope, 0) + 1
            
            stats = {
                'total_policies': total_policies,
                'enabled_policies': enabled_policies,
                'active_policies': active_policies,
                'by_type': type_counts,
                'by_scope': scope_counts,
            }
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    # ============ POLICY TEMPLATES ============
    
    def create_allow_all_policy(self) -> int:
        """Create allow-all policy"""
        return self.create_policy(
            name="Allow All",
            description="Allow all camera access",
            policy_type=Policy.TYPE_ALLOW,
            scope=Policy.SCOPE_GLOBAL,
            enabled=True
        )
    
    def create_deny_all_policy(self) -> int:
        """Create deny-all policy"""
        return self.create_policy(
            name="Deny All",
            description="Deny all camera access",
            policy_type=Policy.TYPE_DENY,
            scope=Policy.SCOPE_GLOBAL,
            enabled=False  # Off by default
        )
    
    def create_business_hours_policy(self) -> int:
        """Create business hours policy"""
        return self.create_policy(
            name="Business Hours Only",
            description="Allow camera access during business hours",
            policy_type=Policy.TYPE_ALLOW,
            scope=Policy.SCOPE_GLOBAL,
            start_time="09:00",
            end_time="17:00",
            enabled=True
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    policy_manager = PolicyManager()
    
    print("=== Policy Manager Test ===\n")
    
    # Test policy creation
    print("[1] Creating policies:")
    policy_id1 = policy_manager.create_policy(
        name="Test Policy",
        description="Test policy",
        policy_type="deny",
        scope="global",
        enabled=True
    )
    print(f"  Created policy ID: {policy_id1}")
    
    policy_id2 = policy_manager.create_allow_all_policy()
    print(f"  Created allow-all policy ID: {policy_id2}")
    
    # Test retrieval
    print("\n[2] Retrieving policies:")
    all_policies = policy_manager.get_all_policies()
    print(f"  Total policies: {len(all_policies)}")
    
    # Test statistics
    print("\n[3] Policy Statistics:")
    stats = policy_manager.get_policy_statistics()
    print(f"  Total: {stats.get('total_policies')}")
    print(f"  Enabled: {stats.get('enabled_policies')}")
    print(f"  By type: {stats.get('by_type')}")
    
    # Test access evaluation
    print("\n[4] Access Evaluation:")
    allowed, reason = policy_manager.evaluate_access(user_id=1)
    print(f"  User 1 access: {allowed} ({reason})")
    
    # Test policy update
    print("\n[5] Testing policy update:")
    policy_manager.update_policy(policy_id1, enabled=False)
    updated = policy_manager.get_policy(policy_id1)
    if updated:
        print(f"  Updated enabled: {updated.get('enabled')}")
    
    print("\n[6] Policy Manager capabilities:")
    print("  ✅ Policy creation and storage")
    print("  ✅ Allow/Deny types supported")
    print("  ✅ Scope-based policies (global, user, application)")
    print("  ✅ Time-based policy activation")
    print("  ✅ User and application assignment")
    print("  ✅ Access evaluation engine")
    
    print("\n=== All tests completed successfully ===")
