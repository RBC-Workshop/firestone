"""
Flask REST API backend for monty utility with Active Directory authentication.
"""
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monty.auth.ldap_auth import ActiveDirectoryAuth
from monty.auth.jwt_handler import JWTHandler
from monty.rbac.permissions import RBACManager, require_permission, require_namespace_access
from monty.kubernetes.client import MultiClusterKubernetesClient, KubernetesClientError
from monty.audit.logger import AuditLogger
from monty.config.settings import MontyConfig


logger = logging.getLogger(__name__)


def create_app(config: Optional[MontyConfig] = None) -> Flask:
    """
    Create and configure Flask application.
    
    Args:
        config: Monty configuration object
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    if not config:
        config = MontyConfig()
    
    app.config['JWT_SECRET_KEY'] = config.jwt_secret_key
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.jwt_expiry_hours * 3600
    
    CORS(app)
    jwt_manager = JWTManager(app)
    
    ad_auth = ActiveDirectoryAuth(
        server_url=config.ad_server_url,
        domain=config.ad_domain,
        base_dn=config.ad_base_dn,
        user_search_base=config.ad_user_search_base,
        group_search_base=config.ad_group_search_base,
        use_ssl=config.ad_use_ssl,
        ca_cert_path=config.ad_ca_cert_path,
        timeout=config.ad_timeout
    )
    
    jwt_handler = JWTHandler(
        secret_key=config.jwt_secret_key,
        token_expiry_hours=config.jwt_expiry_hours,
        issuer='monty-k8s-utility'
    )
    
    rbac_manager = RBACManager()
    
    k8s_client = MultiClusterKubernetesClient(config.cluster_configs)
    
    audit_logger = AuditLogger(
        log_file=config.audit_log_file,
        syslog_server=config.audit_syslog_server,
        enabled=config.audit_enabled
    )
    
    app.ad_auth = ad_auth
    app.jwt_handler = jwt_handler
    app.rbac_manager = rbac_manager
    app.k8s_client = k8s_client
    app.audit_logger = audit_logger
    app.config_obj = config
    
    @jwt_manager.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        return False
    
    @app.before_request
    def before_request():
        """Set up request context."""
        g.start_time = datetime.utcnow()
        g.current_user = None
        
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            payload = app.jwt_handler.validate_token(token)
            if payload:
                g.current_user = payload
    
    @app.after_request
    def after_request(response):
        """Log request for audit trail."""
        if hasattr(g, 'start_time'):
            duration = (datetime.utcnow() - g.start_time).total_seconds()
            
            audit_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'duration_seconds': duration,
                'user_agent': request.headers.get('User-Agent'),
                'remote_addr': request.remote_addr,
                'user': g.current_user.get('user_info', {}).get('username') if g.current_user else None,
                'user_groups': g.current_user.get('groups', []) if g.current_user else [],
                'request_data': request.get_json() if request.is_json else None
            }
            
            app.audit_logger.log_request(audit_data)
        
        return response
    
    @app.route('/api/v1/auth/login', methods=['POST'])
    def login():
        """Authenticate user with Active Directory."""
        try:
            data = request.get_json()
            if not data or not data.get('username') or not data.get('password'):
                return jsonify({'error': 'Username and password required'}), 400
            
            username = data['username']
            password = data['password']
            
            success, user_info = app.ad_auth.authenticate(username, password)
            if not success:
                app.audit_logger.log_auth_failure(username, request.remote_addr)
                return jsonify({'error': 'Invalid credentials'}), 401
            
            groups = app.ad_auth.get_user_groups(
                username,
                app.config_obj.ad_admin_username,
                app.config_obj.ad_admin_password
            )
            
            token = app.jwt_handler.create_token(user_info, groups)
            
            permissions_summary = app.rbac_manager.get_user_permissions(groups)
            
            app.audit_logger.log_auth_success(username, request.remote_addr, groups)
            
            return jsonify({
                'access_token': token,
                'token_type': 'Bearer',
                'expires_in': app.config_obj.jwt_expiry_hours * 3600,
                'user_info': user_info,
                'groups': groups,
                'permissions': list(permissions_summary)
            })
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Authentication failed'}), 500
    
    @app.route('/api/v1/auth/refresh', methods=['POST'])
    @jwt_required()
    def refresh_token():
        """Refresh JWT token."""
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Invalid token format'}), 400
            
            current_token = auth_header[7:]
            new_token = app.jwt_handler.refresh_token(current_token)
            
            if not new_token:
                return jsonify({'error': 'Token refresh failed'}), 401
            
            return jsonify({
                'access_token': new_token,
                'token_type': 'Bearer',
                'expires_in': app.config_obj.jwt_expiry_hours * 3600
            })
            
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return jsonify({'error': 'Token refresh failed'}), 500
    
    @app.route('/api/v1/auth/user', methods=['GET'])
    @jwt_required()
    def get_user_info():
        """Get current user information."""
        if not g.current_user:
            return jsonify({'error': 'User not found'}), 404
        
        user_groups = g.current_user.get('groups', [])
        permissions_summary = app.rbac_manager.get_user_permissions(user_groups)
        
        return jsonify({
            'user_info': g.current_user.get('user_info', {}),
            'groups': user_groups,
            'permissions': list(permissions_summary),
            'accessible_clusters': app.rbac_manager.get_accessible_clusters(user_groups)
        })
    
    @app.route('/api/v1/namespaces', methods=['GET'])
    @require_permission('namespaces:read')
    def list_namespaces():
        """List Kubernetes namespaces."""
        try:
            cluster_name = request.args.get('cluster')
            if not cluster_name:
                return jsonify({'error': 'cluster parameter required'}), 400
            
            user_groups = g.current_user.get('groups', [])
            accessible_clusters = app.rbac_manager.get_accessible_clusters(user_groups)
            if cluster_name not in accessible_clusters:
                return jsonify({'error': f'Access denied to cluster: {cluster_name}'}), 403
            
            limit = request.args.get('limit', type=int)
            offset = request.args.get('offset', type=int)
            label_selector = request.args.get('label_selector')
            
            namespaces = app.k8s_client.list_namespaces(
                cluster_name=cluster_name,
                label_selector=label_selector,
                limit=limit,
                offset=offset
            )
            
            from monty.rbac.permissions import PermissionChecker
            permission_checker = PermissionChecker(app.rbac_manager)
            accessible_namespaces = permission_checker.filter_namespaces_by_access(
                user_groups, namespaces
            )
            
            app.audit_logger.log_namespace_operation(
                'list', cluster_name, None, g.current_user.get('user_info', {}).get('username'),
                success=True, count=len(accessible_namespaces)
            )
            
            return jsonify(accessible_namespaces)
            
        except KubernetesClientError as e:
            app.audit_logger.log_namespace_operation(
                'list', cluster_name, None, g.current_user.get('user_info', {}).get('username'),
                success=False, error=str(e)
            )
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"List namespaces error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/v1/namespaces', methods=['POST'])
    @require_namespace_access('create')
    def create_namespace():
        """Create Kubernetes namespace."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body required'}), 400
            
            cluster_name = request.args.get('cluster')
            if not cluster_name:
                return jsonify({'error': 'cluster parameter required'}), 400
            
            if not data.get('namespace_name'):
                return jsonify({'error': 'namespace_name required'}), 400
            
            data['cluster_name'] = cluster_name
            
            data['created_by'] = g.current_user.get('user_info', {}).get('username')
            if not data.get('annotations'):
                data['annotations'] = {}
            data['annotations']['created-by'] = data['created_by']
            data['annotations']['created-at'] = datetime.utcnow().isoformat()
            
            namespace = app.k8s_client.create_namespace(cluster_name, data)
            
            app.audit_logger.log_namespace_operation(
                'create', cluster_name, data['namespace_name'],
                g.current_user.get('user_info', {}).get('username'),
                success=True, data=data
            )
            
            return jsonify(namespace), 201
            
        except KubernetesClientError as e:
            app.audit_logger.log_namespace_operation(
                'create', cluster_name, data.get('namespace_name'),
                g.current_user.get('user_info', {}).get('username'),
                success=False, error=str(e)
            )
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Create namespace error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/v1/namespaces/<namespace_name>', methods=['GET'])
    @require_namespace_access('read')
    def get_namespace(namespace_name: str):
        """Get specific Kubernetes namespace."""
        try:
            cluster_name = request.args.get('cluster')
            if not cluster_name:
                return jsonify({'error': 'cluster parameter required'}), 400
            
            namespace = app.k8s_client.get_namespace(cluster_name, namespace_name)
            
            app.audit_logger.log_namespace_operation(
                'read', cluster_name, namespace_name,
                g.current_user.get('user_info', {}).get('username'),
                success=True
            )
            
            return jsonify(namespace)
            
        except KubernetesClientError as e:
            app.audit_logger.log_namespace_operation(
                'read', cluster_name, namespace_name,
                g.current_user.get('user_info', {}).get('username'),
                success=False, error=str(e)
            )
            if 'not found' in str(e).lower():
                return jsonify({'error': str(e)}), 404
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Get namespace error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/v1/namespaces/<namespace_name>', methods=['PUT'])
    @require_namespace_access('update')
    def update_namespace(namespace_name: str):
        """Update Kubernetes namespace."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body required'}), 400
            
            cluster_name = request.args.get('cluster')
            if not cluster_name:
                return jsonify({'error': 'cluster parameter required'}), 400
            
            if not data.get('annotations'):
                data['annotations'] = {}
            data['annotations']['updated-by'] = g.current_user.get('user_info', {}).get('username')
            data['annotations']['updated-at'] = datetime.utcnow().isoformat()
            
            namespace = app.k8s_client.update_namespace(cluster_name, namespace_name, data)
            
            app.audit_logger.log_namespace_operation(
                'update', cluster_name, namespace_name,
                g.current_user.get('user_info', {}).get('username'),
                success=True, data=data
            )
            
            return jsonify(namespace)
            
        except KubernetesClientError as e:
            app.audit_logger.log_namespace_operation(
                'update', cluster_name, namespace_name,
                g.current_user.get('user_info', {}).get('username'),
                success=False, error=str(e)
            )
            if 'not found' in str(e).lower():
                return jsonify({'error': str(e)}), 404
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Update namespace error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/v1/namespaces/<namespace_name>', methods=['DELETE'])
    @require_namespace_access('delete')
    def delete_namespace(namespace_name: str):
        """Delete Kubernetes namespace."""
        try:
            cluster_name = request.args.get('cluster')
            if not cluster_name:
                return jsonify({'error': 'cluster parameter required'}), 400
            
            success = app.k8s_client.delete_namespace(cluster_name, namespace_name)
            
            app.audit_logger.log_namespace_operation(
                'delete', cluster_name, namespace_name,
                g.current_user.get('user_info', {}).get('username'),
                success=success
            )
            
            return '', 204
            
        except KubernetesClientError as e:
            app.audit_logger.log_namespace_operation(
                'delete', cluster_name, namespace_name,
                g.current_user.get('user_info', {}).get('username'),
                success=False, error=str(e)
            )
            if 'not found' in str(e).lower():
                return jsonify({'error': str(e)}), 404
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Delete namespace error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/v1/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        })
    
    @app.route('/api/v1/health/clusters', methods=['GET'])
    @require_permission('namespaces:read')
    def cluster_health_check():
        """Check health of all configured clusters."""
        cluster_health = {}
        
        for cluster_name in app.k8s_client.get_available_clusters():
            cluster_health[cluster_name] = app.k8s_client.health_check(cluster_name)
        
        return jsonify({
            'clusters': cluster_health,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    return app


def run_server():
    """Run the Flask development server."""
    config = MontyConfig()
    app = create_app(config)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Starting Monty Kubernetes API server")
    app.run(
        host=config.api_host,
        port=config.api_port,
        debug=config.debug_mode
    )


if __name__ == '__main__':
    run_server()
