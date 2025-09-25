"""
JWT token management for monty utility.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any, List
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


logger = logging.getLogger(__name__)


class JWTHandler:
    """JWT token creation and validation handler."""
    
    def __init__(self, secret_key: Optional[str] = None, 
                 algorithm: str = 'HS256',
                 token_expiry_hours: int = 8,
                 issuer: str = 'monty-k8s-utility'):
        """
        Initialize JWT handler.
        
        Args:
            secret_key: Secret key for signing tokens (generated if None)
            algorithm: JWT signing algorithm
            token_expiry_hours: Token expiration time in hours
            issuer: Token issuer identifier
        """
        self.algorithm = algorithm
        self.token_expiry_hours = token_expiry_hours
        self.issuer = issuer
        
        if secret_key:
            self.secret_key = secret_key
        else:
            self.secret_key = self._generate_secret_key()
            logger.warning("Generated new JWT secret key. Tokens will be invalid after restart.")
    
    def create_token(self, user_info: Dict[str, Any], groups: Optional[List[str]] = None) -> str:
        """
        Create JWT token for authenticated user.
        
        Args:
            user_info: User information dictionary
            groups: List of user's AD groups
            
        Returns:
            JWT token string
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(hours=self.token_expiry_hours)
        
        payload = {
            'iss': self.issuer,
            'sub': user_info.get('username'),
            'iat': now,
            'exp': expiry,
            'user_info': {
                'username': user_info.get('username'),
                'display_name': user_info.get('display_name'),
                'email': user_info.get('email'),
                'department': user_info.get('department'),
                'title': user_info.get('title')
            },
            'groups': groups or [],
            'permissions': self._calculate_permissions(groups or [])
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.info(f"Created JWT token for user: {user_info.get('username')}")
        return token
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate and decode JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                issuer=self.issuer
            )
            
            exp = payload.get('exp')
            if exp and datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc):
                logger.warning("JWT token has expired")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"Error validating JWT token: {e}")
            return None
    
    def refresh_token(self, token: str) -> Optional[str]:
        """
        Refresh JWT token if it's still valid but close to expiry.
        
        Args:
            token: Current JWT token
            
        Returns:
            New JWT token or None if refresh failed
        """
        payload = self.validate_token(token)
        if not payload:
            return None
        
        exp = payload.get('exp')
        if exp:
            expiry_time = datetime.fromtimestamp(exp, timezone.utc)
            refresh_threshold = expiry_time - timedelta(hours=2)
            
            if datetime.now(timezone.utc) < refresh_threshold:
                return token
        
        user_info = payload.get('user_info', {})
        groups = payload.get('groups', [])
        
        return self.create_token(user_info, groups)
    
    def _calculate_permissions(self, groups: list) -> list:
        """
        Calculate user permissions based on AD groups.
        
        Args:
            groups: List of user's AD groups
            
        Returns:
            List of permission strings
        """
        permissions = []
        
        group_permissions = {
            'K8S-Admins': [
                'namespaces:create',
                'namespaces:read',
                'namespaces:update',
                'namespaces:delete',
                'cluster:admin'
            ],
            'K8S-Developers': [
                'namespaces:create',
                'namespaces:read',
                'namespaces:update',
                'namespaces:delete'
            ],
            'K8S-Operators': [
                'namespaces:read',
                'namespaces:update'
            ],
            'K8S-Viewers': [
                'namespaces:read'
            ]
        }
        
        for group in groups:
            if group in group_permissions:
                permissions.extend(group_permissions[group])
        
        return list(set(permissions))
    
    def _generate_secret_key(self) -> str:
        """
        Generate a new secret key for JWT signing.
        
        Returns:
            Base64 encoded secret key
        """
        import secrets
        import base64
        
        key_bytes = secrets.token_bytes(32)
        return base64.b64encode(key_bytes).decode('utf-8')
    
    def get_user_permissions(self, token: str) -> list:
        """
        Extract user permissions from JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            List of permission strings
        """
        payload = self.validate_token(token)
        if payload:
            return payload.get('permissions', [])
        return []
    
    def has_permission(self, token: str, required_permission: str) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            token: JWT token string
            required_permission: Permission to check (e.g., 'namespaces:create')
            
        Returns:
            True if user has permission
        """
        permissions = self.get_user_permissions(token)
        return required_permission in permissions or 'cluster:admin' in permissions
