"""
Main CLI entry point for monty utility.
"""
import os
import sys
import click
import logging
from typing import Optional, Dict, Any
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monty.config.settings import MontyConfig, load_config
from monty.auth.ldap_auth import ActiveDirectoryAuth
from monty.auth.jwt_handler import JWTHandler
from monty.kubernetes.client import MultiClusterKubernetesClient, KubernetesClientError
from monty.utils.formatters import NamespaceFormatter, OutputFormatter, ErrorFormatter
from monty.audit.logger import AuditLogger


config: Optional[MontyConfig] = None
jwt_handler: Optional[JWTHandler] = None
k8s_client: Optional[MultiClusterKubernetesClient] = None
audit_logger: Optional[AuditLogger] = None


def init_config(config_file: Optional[str] = None):
    """Initialize global configuration and clients."""
    global config, jwt_handler, k8s_client, audit_logger
    
    config = load_config(config_file)
    
    if not config:
        raise RuntimeError("Failed to load configuration")
    
    jwt_handler = JWTHandler(
        secret_key=config.jwt_secret_key,
        token_expiry_hours=config.jwt_expiry_hours,
        issuer=config.jwt_issuer
    )
    
    k8s_client = MultiClusterKubernetesClient(config.cluster_configs)
    
    audit_logger = AuditLogger(
        log_file=config.audit_log_file,
        syslog_server=config.audit_syslog_server,
        enabled=config.audit_enabled
    )


def get_stored_token() -> Optional[str]:
    """Get stored JWT token from file."""
    token_file = Path.home() / '.monty' / 'token'
    if token_file.exists():
        try:
            return token_file.read_text().strip()
        except Exception:
            return None
    return None


def store_token(token: str):
    """Store JWT token to file."""
    token_dir = Path.home() / '.monty'
    token_dir.mkdir(exist_ok=True)
    token_file = token_dir / 'token'
    token_file.write_text(token)
    token_file.chmod(0o600)  # Secure permissions


def clear_token():
    """Clear stored JWT token."""
    token_file = Path.home() / '.monty' / 'token'
    if token_file.exists():
        token_file.unlink()


def validate_token(token: str) -> Optional[Dict[str, Any]]:
    """Validate JWT token and return payload."""
    if not jwt_handler:
        return None
    return jwt_handler.validate_token(token)


@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--output', '-o', default='table', 
              type=click.Choice(['json', 'yaml', 'table']),
              help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, config_file, output, verbose):
    """Monty - Kubernetes utility with Active Directory authentication."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    init_config(config_file)
    
    ctx.ensure_object(dict)
    ctx.obj['output_format'] = output
    ctx.obj['verbose'] = verbose


@cli.group()
@click.pass_context
def auth(ctx):
    """Authentication commands."""
    pass


@auth.command()
@click.option('--username', '-u', prompt=True, help='Active Directory username')
@click.option('--password', '-p', prompt=True, hide_input=True, help='Password')
@click.pass_context
def login(ctx, username, password):
    """Login with Active Directory credentials."""
    try:
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
        
        success, user_info = ad_auth.authenticate(username, password)
        if not success:
            click.echo("Authentication failed: Invalid credentials", err=True)
            audit_logger.log_auth_failure(username, 'cli')
            sys.exit(1)
        
        groups = ad_auth.get_user_groups(
            username,
            config.ad_admin_username,
            config.ad_admin_password
        )
        
        token = jwt_handler.create_token(user_info, groups)
        
        store_token(token)
        
        audit_logger.log_auth_success(username, 'cli', groups)
        
        click.echo(f"Successfully authenticated as {user_info.get('display_name', username)}")
        if ctx.obj['verbose']:
            click.echo(f"Groups: {', '.join(groups)}")
        
    except Exception as e:
        click.echo(f"Login failed: {e}", err=True)
        sys.exit(1)


@auth.command()
def logout():
    """Logout and clear stored credentials."""
    clear_token()
    click.echo("Successfully logged out")


@auth.command()
@click.pass_context
def status(ctx):
    """Show authentication status."""
    token = get_stored_token()
    if not token:
        click.echo("Not authenticated")
        return
    
    payload = validate_token(token)
    if not payload:
        click.echo("Authentication expired")
        clear_token()
        return
    
    user_info = payload.get('user_info', {})
    groups = payload.get('groups', [])
    permissions = payload.get('permissions', [])
    
    status_data = {
        'authenticated': True,
        'username': user_info.get('username'),
        'display_name': user_info.get('display_name'),
        'email': user_info.get('email'),
        'groups': groups,
        'permissions': permissions,
        'expires': payload.get('exp')
    }
    
    output_format = ctx.obj['output_format']
    click.echo(OutputFormatter.format_output(status_data, output_format))


@cli.group()
@click.pass_context
def namespace(ctx):
    """Kubernetes namespace operations."""
    token = get_stored_token()
    if not token:
        click.echo("Authentication required. Run 'monty auth login' first.", err=True)
        sys.exit(1)
    
    payload = validate_token(token)
    if not payload:
        click.echo("Authentication expired. Please login again.", err=True)
        clear_token()
        sys.exit(1)
    
    ctx.obj['token_payload'] = payload


@namespace.command('list')
@click.option('--cluster', '-c', required=True, help='Kubernetes cluster name')
@click.option('--label-selector', '-l', help='Label selector for filtering')
@click.option('--limit', type=int, help='Limit number of results')
@click.option('--offset', type=int, help='Offset for pagination')
@click.pass_context
def list_namespaces(ctx, cluster, label_selector, limit, offset):
    """List Kubernetes namespaces."""
    try:
        payload = ctx.obj['token_payload']
        user_groups = payload.get('groups', [])
        
        from monty.rbac.permissions import RBACManager
        rbac_manager = RBACManager()
        accessible_clusters = rbac_manager.get_accessible_clusters(user_groups)
        
        if cluster not in accessible_clusters:
            click.echo(f"Access denied to cluster: {cluster}", err=True)
            sys.exit(1)
        
        namespaces = k8s_client.list_namespaces(
            cluster_name=cluster,
            label_selector=label_selector,
            limit=limit,
            offset=offset
        )
        
        from monty.rbac.permissions import PermissionChecker
        permission_checker = PermissionChecker(rbac_manager)
        accessible_namespaces = permission_checker.filter_namespaces_by_access(
            user_groups, namespaces
        )
        
        output_format = ctx.obj['output_format']
        formatted_output = NamespaceFormatter.format_namespace_list(
            accessible_namespaces, output_format
        )
        click.echo(formatted_output)
        
        username = payload.get('user_info', {}).get('username')
        audit_logger.log_namespace_operation(
            'list', cluster, None, username, True, count=len(accessible_namespaces)
        )
        
    except KubernetesClientError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@namespace.command('get')
@click.argument('name')
@click.option('--cluster', '-c', required=True, help='Kubernetes cluster name')
@click.pass_context
def get_namespace(ctx, name, cluster):
    """Get specific Kubernetes namespace."""
    try:
        payload = ctx.obj['token_payload']
        user_groups = payload.get('groups', [])
        
        from monty.rbac.permissions import RBACManager
        rbac_manager = RBACManager()
        
        if not rbac_manager.can_access_namespace(user_groups, name, 'read'):
            click.echo(f"Access denied to namespace: {name}", err=True)
            sys.exit(1)
        
        namespace = k8s_client.get_namespace(cluster, name)
        
        output_format = ctx.obj['output_format']
        formatted_output = NamespaceFormatter.format_namespace_detail(
            namespace, output_format
        )
        click.echo(formatted_output)
        
        username = payload.get('user_info', {}).get('username')
        audit_logger.log_namespace_operation(
            'read', cluster, name, username, True
        )
        
    except KubernetesClientError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@namespace.command('create')
@click.argument('name')
@click.option('--cluster', '-c', required=True, help='Kubernetes cluster name')
@click.option('--labels', '-l', help='Labels as key=value pairs (comma-separated)')
@click.option('--annotations', '-a', help='Annotations as key=value pairs (comma-separated)')
@click.option('--cpu-limit', help='CPU limit (e.g., 2000m)')
@click.option('--memory-limit', help='Memory limit (e.g., 4Gi)')
@click.option('--storage-limit', help='Storage limit (e.g., 10Gi)')
@click.option('--pod-limit', type=int, help='Pod limit')
@click.pass_context
def create_namespace(ctx, name, cluster, labels, annotations, cpu_limit, 
                    memory_limit, storage_limit, pod_limit):
    """Create Kubernetes namespace."""
    try:
        payload = ctx.obj['token_payload']
        user_groups = payload.get('groups', [])
        
        from monty.rbac.permissions import RBACManager
        rbac_manager = RBACManager()
        
        if not rbac_manager.can_access_namespace(user_groups, name, 'create'):
            click.echo(f"Access denied to create namespace: {name}", err=True)
            sys.exit(1)
        
        parsed_labels = {}
        if labels:
            for label in labels.split(','):
                key, value = label.split('=', 1)
                parsed_labels[key.strip()] = value.strip()
        
        parsed_annotations = {}
        if annotations:
            for annotation in annotations.split(','):
                key, value = annotation.split('=', 1)
                parsed_annotations[key.strip()] = value.strip()
        
        resource_quota = {}
        if cpu_limit:
            resource_quota['cpu_limit'] = cpu_limit
        if memory_limit:
            resource_quota['memory_limit'] = memory_limit
        if storage_limit:
            resource_quota['storage_limit'] = storage_limit
        if pod_limit:
            resource_quota['pod_limit'] = pod_limit
        
        namespace_data = {
            'namespace_name': name,
            'cluster_name': cluster,
            'labels': parsed_labels,
            'annotations': parsed_annotations
        }
        
        if resource_quota:
            namespace_data['resource_quota'] = resource_quota
        
        namespace = k8s_client.create_namespace(cluster, namespace_data)
        
        output_format = ctx.obj['output_format']
        formatted_output = NamespaceFormatter.format_namespace_detail(
            namespace, output_format
        )
        click.echo(formatted_output)
        
        username = payload.get('user_info', {}).get('username')
        audit_logger.log_namespace_operation(
            'create', cluster, name, username, True, data=namespace_data
        )
        
    except KubernetesClientError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@namespace.command('update')
@click.argument('name')
@click.option('--cluster', '-c', required=True, help='Kubernetes cluster name')
@click.option('--labels', '-l', help='Labels as key=value pairs (comma-separated)')
@click.option('--annotations', '-a', help='Annotations as key=value pairs (comma-separated)')
@click.option('--cpu-limit', help='CPU limit (e.g., 2000m)')
@click.option('--memory-limit', help='Memory limit (e.g., 4Gi)')
@click.option('--storage-limit', help='Storage limit (e.g., 10Gi)')
@click.option('--pod-limit', type=int, help='Pod limit')
@click.pass_context
def update_namespace(ctx, name, cluster, labels, annotations, cpu_limit,
                    memory_limit, storage_limit, pod_limit):
    """Update Kubernetes namespace."""
    try:
        payload = ctx.obj['token_payload']
        user_groups = payload.get('groups', [])
        
        from monty.rbac.permissions import RBACManager
        rbac_manager = RBACManager()
        
        if not rbac_manager.can_access_namespace(user_groups, name, 'update'):
            click.echo(f"Access denied to update namespace: {name}", err=True)
            sys.exit(1)
        
        update_data = {}
        
        if labels:
            parsed_labels = {}
            for label in labels.split(','):
                key, value = label.split('=', 1)
                parsed_labels[key.strip()] = value.strip()
            update_data['labels'] = parsed_labels
        
        if annotations:
            parsed_annotations = {}
            for annotation in annotations.split(','):
                key, value = annotation.split('=', 1)
                parsed_annotations[key.strip()] = value.strip()
            update_data['annotations'] = parsed_annotations
        
        resource_quota = {}
        if cpu_limit:
            resource_quota['cpu_limit'] = cpu_limit
        if memory_limit:
            resource_quota['memory_limit'] = memory_limit
        if storage_limit:
            resource_quota['storage_limit'] = storage_limit
        if pod_limit:
            resource_quota['pod_limit'] = pod_limit
        
        if resource_quota:
            update_data['resource_quota'] = resource_quota
        
        if not update_data:
            click.echo("No updates specified", err=True)
            sys.exit(1)
        
        namespace = k8s_client.update_namespace(cluster, name, update_data)
        
        output_format = ctx.obj['output_format']
        formatted_output = NamespaceFormatter.format_namespace_detail(
            namespace, output_format
        )
        click.echo(formatted_output)
        
        username = payload.get('user_info', {}).get('username')
        audit_logger.log_namespace_operation(
            'update', cluster, name, username, True, data=update_data
        )
        
    except KubernetesClientError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@namespace.command('delete')
@click.argument('name')
@click.option('--cluster', '-c', required=True, help='Kubernetes cluster name')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def delete_namespace(ctx, name, cluster, yes):
    """Delete Kubernetes namespace."""
    try:
        payload = ctx.obj['token_payload']
        user_groups = payload.get('groups', [])
        
        from monty.rbac.permissions import RBACManager
        rbac_manager = RBACManager()
        
        if not rbac_manager.can_access_namespace(user_groups, name, 'delete'):
            click.echo(f"Access denied to delete namespace: {name}", err=True)
            sys.exit(1)
        
        if not yes:
            if not click.confirm(f"Are you sure you want to delete namespace '{name}' in cluster '{cluster}'?"):
                click.echo("Deletion cancelled")
                return
        
        success = k8s_client.delete_namespace(cluster, name)
        
        if success:
            click.echo(f"Namespace '{name}' deletion initiated")
        else:
            click.echo(f"Failed to delete namespace '{name}'", err=True)
            sys.exit(1)
        
        username = payload.get('user_info', {}).get('username')
        audit_logger.log_namespace_operation(
            'delete', cluster, name, username, success
        )
        
    except KubernetesClientError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def config_show(ctx):
    """Show current configuration."""
    output_format = ctx.obj['output_format']
    
    config_data = {
        'active_directory': {
            'server': config.ad_server_url,
            'domain': config.ad_domain,
            'base_dn': config.ad_base_dn,
            'use_ssl': config.ad_use_ssl,
            'timeout': config.ad_timeout
        },
        'api': {
            'host': config.api_host,
            'port': config.api_port,
            'debug': config.debug_mode
        },
        'audit': {
            'enabled': config.audit_enabled,
            'log_file': config.audit_log_file,
            'syslog_server': config.audit_syslog_server
        },
        'clusters': [
            {
                'name': cluster.name,
                'endpoint': cluster.endpoint,
                'verify_ssl': cluster.verify_ssl,
                'default_namespace': cluster.default_namespace
            }
            for cluster in config.cluster_configs
        ],
        'cli': {
            'default_output_format': config.default_output_format,
            'config_file_path': config.config_file_path
        }
    }
    
    click.echo(OutputFormatter.format_output(config_data, output_format))


@cli.command()
def version():
    """Show version information."""
    version_info = {
        'version': '1.0.0',
        'framework': 'firestone',
        'python_version': sys.version,
        'platform': sys.platform
    }
    
    click.echo(OutputFormatter.format_output(version_info, 'json'))


if __name__ == '__main__':
    cli()
