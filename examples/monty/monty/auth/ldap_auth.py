"""
Active Directory LDAP authentication module for monty utility.
"""
import logging
from typing import Dict, List, Optional, Tuple
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException


logger = logging.getLogger(__name__)


class ActiveDirectoryAuth:
    """Active Directory authentication handler."""
    
    def __init__(self, server_url: str, domain: str, base_dn: str, 
                 user_search_base: Optional[str] = None,
                 group_search_base: Optional[str] = None,
                 use_ssl: bool = False,
                 ca_cert_path: Optional[str] = None,
                 timeout: int = 30):
        """
        Initialize Active Directory authentication.
        
        Args:
            server_url: LDAP server URL (e.g., 'ldap://ad-server.company.com')
            domain: AD domain name (e.g., 'COMPANY')
            base_dn: Base distinguished name (e.g., 'DC=company,DC=com')
            user_search_base: User search base DN
            group_search_base: Group search base DN
            use_ssl: Whether to use LDAPS
            ca_cert_path: Path to CA certificate for SSL
            timeout: Connection timeout in seconds
        """
        self.server_url = server_url
        self.domain = domain
        self.base_dn = base_dn
        self.user_search_base = user_search_base or f"OU=Users,{base_dn}"
        self.group_search_base = group_search_base or f"OU=Groups,{base_dn}"
        self.use_ssl = use_ssl
        self.ca_cert_path = ca_cert_path
        self.timeout = timeout
        
        self.server = Server(
            server_url,
            get_info=ALL,
            use_ssl=use_ssl,
            connect_timeout=timeout
        )
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """
        Authenticate user against Active Directory.
        
        Args:
            username: Username (without domain)
            password: User password
            
        Returns:
            Tuple of (success, user_info_dict)
        """
        try:
            ad_username = f"{self.domain}\\{username}"
            
            conn = Connection(
                self.server,
                user=ad_username,
                password=password,
                authentication=NTLM,
                auto_bind=True,
                raise_exceptions=True
            )
            
            user_info = self._get_user_info(conn, username)
            conn.unbind()
            
            logger.info(f"Successfully authenticated user: {username}")
            return True, user_info
            
        except LDAPException as e:
            logger.warning(f"Authentication failed for user {username}: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Unexpected error during authentication for {username}: {e}")
            return False, None
    
    def get_user_groups(self, username: str, admin_username: str, admin_password: str) -> List[str]:
        """
        Get user's Active Directory groups using admin credentials.
        
        Args:
            username: Target username
            admin_username: Admin username for LDAP queries
            admin_password: Admin password
            
        Returns:
            List of group names
        """
        try:
            admin_user = f"{self.domain}\\{admin_username}"
            conn = Connection(
                self.server,
                user=admin_user,
                password=admin_password,
                authentication=NTLM,
                auto_bind=True,
                raise_exceptions=True
            )
            
            user_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
            conn.search(
                search_base=self.user_search_base,
                search_filter=user_filter,
                search_scope=SUBTREE,
                attributes=['memberOf', 'distinguishedName']
            )
            
            if not conn.entries:
                logger.warning(f"User {username} not found in AD")
                conn.unbind()
                return []
            
            user_entry = conn.entries[0]
            member_of = user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else []
            
            groups = []
            for group_dn in member_of:
                if group_dn.startswith('CN='):
                    group_name = group_dn.split(',')[0][3:]  # Remove "CN="
                    groups.append(group_name)
            
            conn.unbind()
            logger.info(f"Retrieved {len(groups)} groups for user {username}")
            return groups
            
        except LDAPException as e:
            logger.error(f"Failed to get groups for user {username}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting groups for {username}: {e}")
            return []
    
    def _get_user_info(self, conn: Connection, username: str) -> Dict:
        """
        Get detailed user information from Active Directory.
        
        Args:
            conn: Active LDAP connection
            username: Username to query
            
        Returns:
            Dictionary with user information
        """
        try:
            user_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
            conn.search(
                search_base=self.user_search_base,
                search_filter=user_filter,
                search_scope=SUBTREE,
                attributes=['displayName', 'mail', 'department', 'title', 'memberOf']
            )
            
            if not conn.entries:
                return {'username': username}
            
            user_entry = conn.entries[0]
            
            return {
                'username': username,
                'display_name': str(user_entry.displayName) if hasattr(user_entry, 'displayName') else username,
                'email': str(user_entry.mail) if hasattr(user_entry, 'mail') else None,
                'department': str(user_entry.department) if hasattr(user_entry, 'department') else None,
                'title': str(user_entry.title) if hasattr(user_entry, 'title') else None,
                'groups': [dn.split(',')[0][3:] for dn in (user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else [])]
            }
            
        except Exception as e:
            logger.error(f"Error getting user info for {username}: {e}")
            return {'username': username}
    
    def validate_connection(self) -> bool:
        """
        Validate connection to Active Directory server.
        
        Returns:
            True if connection is successful
        """
        try:
            conn = Connection(self.server, auto_bind=True)
            conn.unbind()
            return True
        except Exception as e:
            logger.error(f"Failed to connect to AD server: {e}")
            return False
