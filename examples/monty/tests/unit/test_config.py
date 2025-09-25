"""
Unit tests for configuration management.
"""
import pytest
import tempfile
import os
from pathlib import Path
from monty.config.settings import MontyConfig, ClusterConfig, load_config


def test_monty_config_defaults():
    """Test MontyConfig with default values."""
    config = MontyConfig()
    
    assert config.ad_server_url == "ldap://localhost:389"
    assert config.ad_domain == "COMPANY"
    assert config.ad_base_dn == "DC=company,DC=com"
    assert config.jwt_expiry_hours == 8
    assert config.api_port == 5000
    assert config.audit_enabled is True


def test_cluster_config():
    """Test ClusterConfig creation."""
    cluster = ClusterConfig(
        name="test-cluster",
        endpoint="https://test.example.com:6443",
        ca_cert_path="/path/to/ca.crt"
    )
    
    assert cluster.name == "test-cluster"
    assert cluster.endpoint == "https://test.example.com:6443"
    assert cluster.ca_cert_path == "/path/to/ca.crt"
    assert cluster.verify_ssl is True
    assert cluster.default_namespace == "default"


def test_config_validation():
    """Test configuration validation."""
    config = MontyConfig()
    
    config.cluster_configs = [
        ClusterConfig(
            name="test",
            endpoint="https://test.com:6443",
            ca_cert_path="/path/to/ca.crt"
        )
    ]
    
    errors = config.validate()
    assert len(errors) == 0


def test_config_validation_errors():
    """Test configuration validation with errors."""
    config = MontyConfig()
    config.ad_server_url = ""
    config.ad_domain = ""
    config.ad_base_dn = ""
    config.jwt_secret_key = ""
    config.api_port = 0
    config.cluster_configs = []
    
    errors = config.validate()
    assert len(errors) > 0
    assert any("Active Directory server URL" in error for error in errors)
    assert any("domain is required" in error for error in errors)
    assert any("base DN is required" in error for error in errors)
    assert any("JWT secret key" in error for error in errors)
    assert any("API port" in error for error in errors)
    assert any("cluster configuration" in error for error in errors)


def test_add_remove_cluster_config():
    """Test adding and removing cluster configurations."""
    config = MontyConfig()
    
    cluster1 = ClusterConfig(name="cluster1", endpoint="https://cluster1.com:6443")
    cluster2 = ClusterConfig(name="cluster2", endpoint="https://cluster2.com:6443")
    
    config.add_cluster_config(cluster1)
    config.add_cluster_config(cluster2)
    
    assert len(config.cluster_configs) == 2
    assert config.get_cluster_config("cluster1") is not None
    assert config.get_cluster_config("cluster2") is not None
    
    removed = config.remove_cluster_config("cluster1")
    assert removed is True
    assert len(config.cluster_configs) == 1
    assert config.get_cluster_config("cluster1") is None
    assert config.get_cluster_config("cluster2") is not None
    
    removed = config.remove_cluster_config("nonexistent")
    assert removed is False


def test_config_from_yaml():
    """Test loading configuration from YAML file."""
    yaml_content = """
active_directory:
  server: "ldap://test-ad.com"
  domain: "TESTDOMAIN"
  base_dn: "DC=test,DC=com"

jwt:
  expiry_hours: 12

api:
  port: 8080

clusters:
  - name: "test-cluster"
    endpoint: "https://test-k8s.com:6443"
    ca_cert_path: "/test/ca.crt"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        temp_file = f.name
    
    try:
        config = MontyConfig()
        config.config_file_path = temp_file
        config._load_from_file()
        
        assert config.ad_server_url == "ldap://test-ad.com"
        assert config.ad_domain == "TESTDOMAIN"
        assert config.ad_base_dn == "DC=test,DC=com"
        assert config.jwt_expiry_hours == 12
        assert config.api_port == 8080
        assert len(config.cluster_configs) == 1
        assert config.cluster_configs[0].name == "test-cluster"
        
    finally:
        os.unlink(temp_file)


def test_config_from_env():
    """Test loading configuration from environment variables."""
    env_vars = {
        'MONTY_AD_SERVER_URL': 'ldap://env-ad.com',
        'MONTY_AD_DOMAIN': 'ENVDOMAIN',
        'MONTY_JWT_EXPIRY_HOURS': '24',
        'MONTY_API_PORT': '9000',
        'MONTY_AUDIT_ENABLED': 'false'
    }
    
    for key, value in env_vars.items():
        os.environ[key] = value
    
    try:
        config = MontyConfig()
        config._load_from_env()
        
        assert config.ad_server_url == 'ldap://env-ad.com'
        assert config.ad_domain == 'ENVDOMAIN'
        assert config.jwt_expiry_hours == 24
        assert config.api_port == 9000
        assert config.audit_enabled is False
        
    finally:
        for key in env_vars:
            if key in os.environ:
                del os.environ[key]
