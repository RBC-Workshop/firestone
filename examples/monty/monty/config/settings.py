"""
Configuration management for monty utility.
"""
import os
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ClusterConfig:
    """Configuration for a single Kubernetes cluster."""
    name: str
    endpoint: str
    ca_cert_path: Optional[str] = None
    service_account_token_path: Optional[str] = None
    kubeconfig_path: Optional[str] = None
    verify_ssl: bool = True
    default_namespace: str = "default"


@dataclass
class MontyConfig:
    """Main configuration class for monty utility."""
    
    ad_server_url: str = "ldap://localhost:389"
    ad_domain: str = "COMPANY"
    ad_base_dn: str = "DC=company,DC=com"
    ad_user_search_base: Optional[str] = None
    ad_group_search_base: Optional[str] = None
    ad_use_ssl: bool = False
    ad_ca_cert_path: Optional[str] = None
    ad_timeout: int = 30
    ad_admin_username: str = ""
    ad_admin_password: str = ""
    
    jwt_secret_key: str = ""
    jwt_expiry_hours: int = 8
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "monty-k8s-utility"
    
    api_host: str = "0.0.0.0"
    api_port: int = 5000
    debug_mode: bool = False
    
    audit_enabled: bool = True
    audit_log_file: str = "/var/log/monty/audit.log"
    audit_syslog_server: Optional[str] = None
    
    cluster_configs: List[ClusterConfig] = field(default_factory=list)
    
    default_output_format: str = "table"
    config_file_path: str = "~/.monty/config.yaml"
    
    def __post_init__(self):
        """Post-initialization processing."""
        if not self.ad_user_search_base:
            self.ad_user_search_base = f"OU=Users,{self.ad_base_dn}"
        if not self.ad_group_search_base:
            self.ad_group_search_base = f"OU=Groups,{self.ad_base_dn}"
        
        if not self.jwt_secret_key:
            self.jwt_secret_key = self._generate_secret_key()
        
        self._load_from_file()
        
        self._load_from_env()
    
    def _generate_secret_key(self) -> str:
        """Generate a random JWT secret key."""
        import secrets
        import base64
        key_bytes = secrets.token_bytes(32)
        return base64.b64encode(key_bytes).decode('utf-8')
    
    def _load_from_file(self):
        """Load configuration from YAML file."""
        config_path = Path(self.config_file_path).expanduser()
        
        if not config_path.exists():
            return
        
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if not config_data:
                return
            
            if 'active_directory' in config_data:
                ad_config = config_data['active_directory']
                self.ad_server_url = ad_config.get('server', self.ad_server_url)
                self.ad_domain = ad_config.get('domain', self.ad_domain)
                self.ad_base_dn = ad_config.get('base_dn', self.ad_base_dn)
                self.ad_user_search_base = ad_config.get('user_search_base', self.ad_user_search_base)
                self.ad_group_search_base = ad_config.get('group_search_base', self.ad_group_search_base)
                self.ad_use_ssl = ad_config.get('use_ssl', self.ad_use_ssl)
                self.ad_ca_cert_path = ad_config.get('ca_cert_path', self.ad_ca_cert_path)
                self.ad_timeout = ad_config.get('timeout', self.ad_timeout)
                self.ad_admin_username = ad_config.get('admin_username', self.ad_admin_username)
                self.ad_admin_password = ad_config.get('admin_password', self.ad_admin_password)
            
            if 'jwt' in config_data:
                jwt_config = config_data['jwt']
                self.jwt_secret_key = jwt_config.get('secret_key', self.jwt_secret_key)
                self.jwt_expiry_hours = jwt_config.get('expiry_hours', self.jwt_expiry_hours)
                self.jwt_algorithm = jwt_config.get('algorithm', self.jwt_algorithm)
                self.jwt_issuer = jwt_config.get('issuer', self.jwt_issuer)
            
            if 'api' in config_data:
                api_config = config_data['api']
                self.api_host = api_config.get('host', self.api_host)
                self.api_port = api_config.get('port', self.api_port)
                self.debug_mode = api_config.get('debug', self.debug_mode)
            
            if 'audit' in config_data:
                audit_config = config_data['audit']
                self.audit_enabled = audit_config.get('enabled', self.audit_enabled)
                self.audit_log_file = audit_config.get('log_file', self.audit_log_file)
                self.audit_syslog_server = audit_config.get('syslog_server', self.audit_syslog_server)
            
            if 'clusters' in config_data:
                self.cluster_configs = []
                for cluster_data in config_data['clusters']:
                    cluster_config = ClusterConfig(
                        name=cluster_data['name'],
                        endpoint=cluster_data['endpoint'],
                        ca_cert_path=cluster_data.get('ca_cert_path'),
                        service_account_token_path=cluster_data.get('service_account_token_path'),
                        kubeconfig_path=cluster_data.get('kubeconfig_path'),
                        verify_ssl=cluster_data.get('verify_ssl', True),
                        default_namespace=cluster_data.get('default_namespace', 'default')
                    )
                    self.cluster_configs.append(cluster_config)
            
            if 'cli' in config_data:
                cli_config = config_data['cli']
                self.default_output_format = cli_config.get('default_output_format', self.default_output_format)
                
        except Exception as e:
            print(f"Warning: Failed to load configuration from {config_path}: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        self.ad_server_url = os.getenv('MONTY_AD_SERVER_URL', self.ad_server_url)
        self.ad_domain = os.getenv('MONTY_AD_DOMAIN', self.ad_domain)
        self.ad_base_dn = os.getenv('MONTY_AD_BASE_DN', self.ad_base_dn)
        self.ad_user_search_base = os.getenv('MONTY_AD_USER_SEARCH_BASE', self.ad_user_search_base)
        self.ad_group_search_base = os.getenv('MONTY_AD_GROUP_SEARCH_BASE', self.ad_group_search_base)
        self.ad_use_ssl = os.getenv('MONTY_AD_USE_SSL', str(self.ad_use_ssl)).lower() == 'true'
        self.ad_ca_cert_path = os.getenv('MONTY_AD_CA_CERT_PATH', self.ad_ca_cert_path)
        self.ad_timeout = int(os.getenv('MONTY_AD_TIMEOUT', str(self.ad_timeout)))
        self.ad_admin_username = os.getenv('MONTY_AD_ADMIN_USERNAME', self.ad_admin_username)
        self.ad_admin_password = os.getenv('MONTY_AD_ADMIN_PASSWORD', self.ad_admin_password)
        
        self.jwt_secret_key = os.getenv('MONTY_JWT_SECRET_KEY', self.jwt_secret_key)
        self.jwt_expiry_hours = int(os.getenv('MONTY_JWT_EXPIRY_HOURS', str(self.jwt_expiry_hours)))
        self.jwt_algorithm = os.getenv('MONTY_JWT_ALGORITHM', self.jwt_algorithm)
        self.jwt_issuer = os.getenv('MONTY_JWT_ISSUER', self.jwt_issuer)
        
        self.api_host = os.getenv('MONTY_API_HOST', self.api_host)
        self.api_port = int(os.getenv('MONTY_API_PORT', str(self.api_port)))
        self.debug_mode = os.getenv('MONTY_DEBUG_MODE', str(self.debug_mode)).lower() == 'true'
        
        self.audit_enabled = os.getenv('MONTY_AUDIT_ENABLED', str(self.audit_enabled)).lower() == 'true'
        self.audit_log_file = os.getenv('MONTY_AUDIT_LOG_FILE', self.audit_log_file)
        self.audit_syslog_server = os.getenv('MONTY_AUDIT_SYSLOG_SERVER', self.audit_syslog_server)
        
        self.default_output_format = os.getenv('MONTY_DEFAULT_OUTPUT_FORMAT', self.default_output_format)
        self.config_file_path = os.getenv('MONTY_CONFIG_FILE', self.config_file_path)
    
    def save_to_file(self, file_path: Optional[str] = None):
        """
        Save configuration to YAML file.
        
        Args:
            file_path: Path to save configuration file (defaults to config_file_path)
        """
        if not file_path:
            file_path = self.config_file_path
        
        config_path = Path(file_path).expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        config_data = {
            'active_directory': {
                'server': self.ad_server_url,
                'domain': self.ad_domain,
                'base_dn': self.ad_base_dn,
                'user_search_base': self.ad_user_search_base,
                'group_search_base': self.ad_group_search_base,
                'use_ssl': self.ad_use_ssl,
                'ca_cert_path': self.ad_ca_cert_path,
                'timeout': self.ad_timeout,
                'admin_username': self.ad_admin_username,
                'admin_password': '***REDACTED***'  # Don't save password
            },
            'jwt': {
                'secret_key': '***REDACTED***',  # Don't save secret key
                'expiry_hours': self.jwt_expiry_hours,
                'algorithm': self.jwt_algorithm,
                'issuer': self.jwt_issuer
            },
            'api': {
                'host': self.api_host,
                'port': self.api_port,
                'debug': self.debug_mode
            },
            'audit': {
                'enabled': self.audit_enabled,
                'log_file': self.audit_log_file,
                'syslog_server': self.audit_syslog_server
            },
            'clusters': [
                {
                    'name': cluster.name,
                    'endpoint': cluster.endpoint,
                    'ca_cert_path': cluster.ca_cert_path,
                    'service_account_token_path': cluster.service_account_token_path,
                    'kubeconfig_path': cluster.kubeconfig_path,
                    'verify_ssl': cluster.verify_ssl,
                    'default_namespace': cluster.default_namespace
                }
                for cluster in self.cluster_configs
            ],
            'cli': {
                'default_output_format': self.default_output_format
            }
        }
        
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
    
    def validate(self) -> List[str]:
        """
        Validate configuration and return list of validation errors.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not self.ad_server_url:
            errors.append("Active Directory server URL is required")
        if not self.ad_domain:
            errors.append("Active Directory domain is required")
        if not self.ad_base_dn:
            errors.append("Active Directory base DN is required")
        
        if not self.jwt_secret_key:
            errors.append("JWT secret key is required")
        if self.jwt_expiry_hours <= 0:
            errors.append("JWT expiry hours must be positive")
        
        if self.api_port <= 0 or self.api_port > 65535:
            errors.append("API port must be between 1 and 65535")
        
        if not self.cluster_configs:
            errors.append("At least one cluster configuration is required")
        
        for i, cluster in enumerate(self.cluster_configs):
            if not cluster.name:
                errors.append(f"Cluster {i+1}: name is required")
            if not cluster.endpoint:
                errors.append(f"Cluster {i+1}: endpoint is required")
            if not cluster.ca_cert_path and not cluster.kubeconfig_path and not cluster.service_account_token_path:
                errors.append(f"Cluster {i+1}: authentication method required (ca_cert_path, kubeconfig_path, or service_account_token_path)")
        
        return errors
    
    def get_cluster_config(self, cluster_name: str) -> Optional[ClusterConfig]:
        """
        Get configuration for specific cluster.
        
        Args:
            cluster_name: Name of the cluster
            
        Returns:
            ClusterConfig object or None if not found
        """
        for cluster in self.cluster_configs:
            if cluster.name == cluster_name:
                return cluster
        return None
    
    def add_cluster_config(self, cluster_config: ClusterConfig):
        """
        Add cluster configuration.
        
        Args:
            cluster_config: ClusterConfig object to add
        """
        self.cluster_configs = [c for c in self.cluster_configs if c.name != cluster_config.name]
        self.cluster_configs.append(cluster_config)
    
    def remove_cluster_config(self, cluster_name: str) -> bool:
        """
        Remove cluster configuration.
        
        Args:
            cluster_name: Name of cluster to remove
            
        Returns:
            True if cluster was removed
        """
        original_count = len(self.cluster_configs)
        self.cluster_configs = [c for c in self.cluster_configs if c.name != cluster_name]
        return len(self.cluster_configs) < original_count


def load_config(config_file: Optional[str] = None) -> MontyConfig:
    """
    Load monty configuration from file and environment.
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        MontyConfig object
    """
    config = MontyConfig()
    
    if config_file:
        config.config_file_path = config_file
        config._load_from_file()
    
    return config


def create_example_config(file_path: str):
    """
    Create an example configuration file.
    
    Args:
        file_path: Path where to create the example config
    """
    example_config = MontyConfig()
    
    example_config.cluster_configs = [
        ClusterConfig(
            name="production",
            endpoint="https://prod-k8s.company.com:6443",
            ca_cert_path="/etc/monty/certs/prod-ca.crt",
            service_account_token_path="/etc/monty/tokens/prod-token",
            verify_ssl=True
        ),
        ClusterConfig(
            name="development",
            endpoint="https://dev-k8s.company.com:6443",
            ca_cert_path="/etc/monty/certs/dev-ca.crt",
            service_account_token_path="/etc/monty/tokens/dev-token",
            verify_ssl=True
        )
    ]
    
    example_config.ad_server_url = "ldap://ad-server.company.com"
    example_config.ad_domain = "COMPANY"
    example_config.ad_base_dn = "DC=company,DC=com"
    example_config.audit_log_file = "/var/log/monty/audit.log"
    example_config.audit_syslog_server = "syslog.company.com:514"
    
    example_config.save_to_file(file_path)
