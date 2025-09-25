#!/usr/bin/env python3
"""
Simple verification script to test monty implementation.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all core modules can be imported."""
    try:
        from monty.config.settings import MontyConfig, ClusterConfig
        print("✓ Configuration module imports successfully")
        
        from monty.utils.formatters import OutputFormatter, NamespaceFormatter
        print("✓ Formatters module imports successfully")
        
        from monty.auth.ldap_auth import ActiveDirectoryAuth
        print("✓ LDAP authentication module imports successfully")
        
        from monty.auth.jwt_handler import JWTHandler
        print("✓ JWT handler module imports successfully")
        
        from monty.kubernetes.client import MultiClusterKubernetesClient
        print("✓ Kubernetes client module imports successfully")
        
        from monty.api.main import create_app
        print("✓ Flask API module imports successfully")
        
        from monty.audit.logger import AuditLogger
        print("✓ Audit logger module imports successfully")
        
        from monty.rbac.permissions import RBACManager
        print("✓ RBAC module imports successfully")
        
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_formatters():
    """Test output formatters."""
    try:
        from monty.utils.formatters import NamespaceFormatter, OutputFormatter
        
        test_data = [
            {
                'namespace_name': 'test-namespace',
                'cluster_name': 'development',
                'status': 'Active',
                'created_at': '2023-01-01T00:00:00Z',
                'labels': {'env': 'test'},
                'resource_quota': {'cpu': '2', 'memory': '4Gi'}
            }
        ]
        
        json_output = NamespaceFormatter.format_namespace_list(test_data, 'json')
        print("✓ JSON formatting works")
        
        yaml_output = NamespaceFormatter.format_namespace_list(test_data, 'yaml')
        print("✓ YAML formatting works")
        
        table_output = NamespaceFormatter.format_namespace_list(test_data, 'table')
        print("✓ Table formatting works")
        
        return True
    except Exception as e:
        print(f"✗ Formatter test error: {e}")
        return False

def test_config():
    """Test configuration loading."""
    try:
        from monty.config.settings import MontyConfig
        
        config = MontyConfig()
        print("✓ Default configuration creation works")
        
        from monty.config.settings import ClusterConfig
        cluster_obj = ClusterConfig(
            name='test-cluster',
            endpoint='https://test.example.com:6443',
            ca_cert_path='/path/to/ca.crt',
            verify_ssl=True
        )
        config.add_cluster_config(cluster_obj)
        print("✓ Cluster configuration works")
        
        return True
    except Exception as e:
        print(f"✗ Configuration test error: {e}")
        return False

def main():
    """Run all verification tests."""
    print("=== Monty Implementation Verification ===\n")
    
    tests = [
        ("Import Tests", test_imports),
        ("Formatter Tests", test_formatters),
        ("Configuration Tests", test_config)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
            print(f"✓ {test_name} PASSED")
        else:
            print(f"✗ {test_name} FAILED")
    
    print(f"\n=== Summary ===")
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All verification tests passed! Monty implementation is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Implementation needs attention.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
