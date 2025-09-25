"""
Role-based access control and permission management for monty utility.
"""
import logging
from typing import Dict, List, Optional, Set
from functools import wraps
from flask import request, jsonify, g


logger = logging.getLogger(__name__)


class RBACManager:
    """Role-based access control manager."""
    
    def __init__(self):
        """Initialize RBAC manager with default role mappings."""
        self.role_permissions = {
            'cluster-admin': {
                'namespaces:create',
                'namespaces:read', 
                'namespaces:update',
                'namespaces:delete',
                'cluster:admin',
                'audit:read'
            },
            'namespace-admin': {
                'namespaces:create',
                'namespaces:read',
                'namespaces:update', 
                'namespaces:delete'
            },
            'namespace-edit': {
                'namespaces:read',
                'namespaces:update'
            },
            'namespace-view': {
                'namespaces:read'
            }
        }
        
        self.group_role_mappings = {
            'K8S-Admins': ['cluster-admin'],
            'K8S-Developers': ['namespace-admin'],
            'K8S-Operators': ['namespace-edit'],
            'K8S-Viewers': ['namespace-view']
        }
    
    def get_user_permissions(self, groups: List[str]) -> Set[str]:
        """
        Get all permissions for user based on their AD groups.
        
        Args:
            groups: List of user's Active Directory groups
            
        Returns:
            Set of permission strings
        """
        permissions = set()
        
        for group in groups:
            roles = self.group_role_mappings.get(group, [])
            for role in roles:
                role_perms = self.role_permissions.get(role, set())
                permissions.update(role_perms)
        
        return permissions
    
    def has_permission(self, user_groups: List[str], required_permission: str) -> bool:
        """
        Check if user has specific permission based on their groups.
        
        Args:
            user_groups: List of user's AD groups
            required_permission: Permission to check
            
        Returns:
            True if user has permission
        """
        user_permissions = self.get_user_permissions(user_groups)
        return required_permission in user_permissions or 'cluster:admin' in user_permissions
    
    def can_access_namespace(self, user_groups: List[str], namespace_name: str, 
                           operation: str) -> bool:
        """
        Check if user can perform operation on specific namespace.
        
        Args:
            user_groups: List of user's AD groups
            namespace_name: Target namespace name
            operation: Operation type (create, read, update, delete)
            
        Returns:
            True if access is allowed
        """
        required_permission = f"namespaces:{operation}"
        
        if not self.has_permission(user_groups, required_permission):
            return False
        
        
        return True
    
    def get_accessible_clusters(self, user_groups: List[str]) -> List[str]:
        """
        Get list of clusters user can access based on their groups.
        
        Args:
            user_groups: List of user's AD groups
            
        Returns:
            List of accessible cluster names
        """
        user_permissions = self.get_user_permissions(user_groups)
        namespace_permissions = [p for p in user_permissions if p.startswith('namespaces:')]
        
        if namespace_permissions or 'cluster:admin' in user_permissions:
            return ['production', 'development', 'staging']
        
        return []


def require_permission(permission: str):
    """
    Decorator to require specific permission for API endpoints.
    
    Args:
        permission: Required permission string
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user') or not g.current_user:
                return jsonify({'error': 'Authentication required'}), 401
            
            user_groups = g.current_user.get('groups', [])
            
            rbac_manager = RBACManager()
            if not rbac_manager.has_permission(user_groups, permission):
                logger.warning(f"Permission denied for user {g.current_user.get('username')} "
                             f"requesting {permission}")
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_permission': permission
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_namespace_access(operation: str):
    """
    Decorator to require namespace-specific access.
    
    Args:
        operation: Operation type (create, read, update, delete)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user') or not g.current_user:
                return jsonify({'error': 'Authentication required'}), 401
            
            namespace_name = kwargs.get('namespace_name')
            if not namespace_name and request.json:
                namespace_name = request.json.get('namespace_name')
            
            if not namespace_name:
                return jsonify({'error': 'Namespace name required'}), 400
            
            user_groups = g.current_user.get('groups', [])
            
            rbac_manager = RBACManager()
            if not rbac_manager.can_access_namespace(user_groups, namespace_name, operation):
                logger.warning(f"Namespace access denied for user {g.current_user.get('username')} "
                             f"on namespace {namespace_name} for operation {operation}")
                return jsonify({
                    'error': 'Insufficient permissions for namespace operation',
                    'namespace': namespace_name,
                    'operation': operation
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class PermissionChecker:
    """Utility class for checking permissions in various contexts."""
    
    def __init__(self, rbac_manager: RBACManager):
        self.rbac_manager = rbac_manager
    
    def check_cluster_access(self, user_groups: List[str], cluster_name: str) -> bool:
        """
        Check if user can access specific cluster.
        
        Args:
            user_groups: User's AD groups
            cluster_name: Target cluster name
            
        Returns:
            True if access is allowed
        """
        accessible_clusters = self.rbac_manager.get_accessible_clusters(user_groups)
        return cluster_name in accessible_clusters
    
    def filter_namespaces_by_access(self, user_groups: List[str], 
                                  namespaces: List[Dict]) -> List[Dict]:
        """
        Filter namespace list based on user's access permissions.
        
        Args:
            user_groups: User's AD groups
            namespaces: List of namespace dictionaries
            
        Returns:
            Filtered list of accessible namespaces
        """
        accessible_namespaces = []
        
        for namespace in namespaces:
            namespace_name = namespace.get('namespace_name', '')
            if self.rbac_manager.can_access_namespace(user_groups, namespace_name, 'read'):
                accessible_namespaces.append(namespace)
        
        return accessible_namespaces
    
    def get_user_role_summary(self, user_groups: List[str]) -> Dict:
        """
        Get summary of user's roles and permissions.
        
        Args:
            user_groups: User's AD groups
            
        Returns:
            Dictionary with role and permission summary
        """
        permissions = self.rbac_manager.get_user_permissions(user_groups)
        accessible_clusters = self.rbac_manager.get_accessible_clusters(user_groups)
        
        primary_role = 'namespace-view'  # Default
        if 'cluster:admin' in permissions:
            primary_role = 'cluster-admin'
        elif 'namespaces:delete' in permissions:
            primary_role = 'namespace-admin'
        elif 'namespaces:update' in permissions:
            primary_role = 'namespace-edit'
        
        return {
            'primary_role': primary_role,
            'permissions': list(permissions),
            'accessible_clusters': accessible_clusters,
            'ad_groups': user_groups
        }
