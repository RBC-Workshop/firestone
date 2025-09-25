"""
Comprehensive audit logging system for monty utility.
"""
import logging
import json
import socket
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class AuditLogger:
    """Comprehensive audit logger for compliance and security monitoring."""
    
    def __init__(self, log_file: Optional[str] = None, 
                 syslog_server: Optional[str] = None,
                 enabled: bool = True):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
            syslog_server: Syslog server address (host:port)
            enabled: Whether audit logging is enabled
        """
        self.enabled = enabled
        self.log_file = log_file
        self.syslog_server = syslog_server
        
        self.file_logger = None
        if log_file and enabled:
            self.file_logger = logging.getLogger('monty.audit.file')
            self.file_logger.setLevel(logging.INFO)
            
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter('%(message)s')
            file_handler.setFormatter(formatter)
            
            self.file_logger.addHandler(file_handler)
            self.file_logger.propagate = False
        
        self.syslog_socket = None
        if syslog_server and enabled:
            try:
                host, port = syslog_server.split(':')
                self.syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.syslog_host = host
                self.syslog_port = int(port)
            except Exception as e:
                logging.getLogger(__name__).warning(f"Failed to configure syslog: {e}")
                self.syslog_socket = None
    
    def _log_event(self, event_type: str, event_data: Dict[str, Any]):
        """
        Log audit event to all configured destinations.
        
        Args:
            event_type: Type of audit event
            event_data: Event data dictionary
        """
        if not self.enabled:
            return
        
        audit_record = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'application': 'monty-k8s-utility',
            'version': '1.0.0',
            **event_data
        }
        
        if self.file_logger:
            self.file_logger.info(json.dumps(audit_record))
        
        if self.syslog_socket:
            try:
                syslog_message = f"<134>monty: {json.dumps(audit_record)}"
                self.syslog_socket.sendto(
                    syslog_message.encode('utf-8'),
                    (self.syslog_host, self.syslog_port)
                )
            except Exception as e:
                logging.getLogger(__name__).warning(f"Failed to send syslog message: {e}")
    
    def log_auth_success(self, username: str, remote_addr: str, groups: list):
        """
        Log successful authentication event.
        
        Args:
            username: Authenticated username
            remote_addr: Client IP address
            groups: User's AD groups
        """
        self._log_event('authentication_success', {
            'username': username,
            'remote_addr': remote_addr,
            'groups': groups,
            'auth_method': 'active_directory'
        })
    
    def log_auth_failure(self, username: str, remote_addr: str, reason: str = 'invalid_credentials'):
        """
        Log failed authentication event.
        
        Args:
            username: Attempted username
            remote_addr: Client IP address
            reason: Failure reason
        """
        self._log_event('authentication_failure', {
            'username': username,
            'remote_addr': remote_addr,
            'reason': reason,
            'auth_method': 'active_directory'
        })
    
    def log_authorization_failure(self, username: str, resource: str, action: str, reason: str):
        """
        Log authorization failure event.
        
        Args:
            username: Username attempting action
            resource: Resource being accessed
            action: Action being attempted
            reason: Authorization failure reason
        """
        self._log_event('authorization_failure', {
            'username': username,
            'resource': resource,
            'action': action,
            'reason': reason
        })
    
    def log_namespace_operation(self, operation: str, cluster: str, namespace: Optional[str],
                              username: str, success: bool, **kwargs):
        """
        Log Kubernetes namespace operation.
        
        Args:
            operation: Operation type (create, read, update, delete, list)
            cluster: Target cluster name
            namespace: Target namespace name (if applicable)
            username: User performing operation
            success: Whether operation succeeded
            **kwargs: Additional operation data
        """
        event_data = {
            'username': username,
            'operation': operation,
            'cluster': cluster,
            'namespace': namespace,
            'success': success,
            'resource_type': 'kubernetes_namespace'
        }
        
        if 'error' in kwargs:
            event_data['error'] = kwargs['error']
        if 'data' in kwargs:
            event_data['operation_data'] = kwargs['data']
        if 'count' in kwargs:
            event_data['result_count'] = kwargs['count']
        
        self._log_event('namespace_operation', event_data)
    
    def log_request(self, request_data: Dict[str, Any]):
        """
        Log HTTP request for audit trail.
        
        Args:
            request_data: Request information dictionary
        """
        if not request_data.get('path', '').startswith('/api/'):
            return
        
        self._log_event('http_request', {
            'method': request_data.get('method'),
            'path': request_data.get('path'),
            'status_code': request_data.get('status_code'),
            'duration_seconds': request_data.get('duration_seconds'),
            'user_agent': request_data.get('user_agent'),
            'remote_addr': request_data.get('remote_addr'),
            'username': request_data.get('user'),
            'user_groups': request_data.get('user_groups', []),
            'request_size': len(json.dumps(request_data.get('request_data', {}))) if request_data.get('request_data') else 0
        })
    
    def log_configuration_change(self, username: str, component: str, change_type: str, 
                                old_value: Any = None, new_value: Any = None):
        """
        Log configuration change event.
        
        Args:
            username: User making the change
            component: Component being configured
            change_type: Type of change (create, update, delete)
            old_value: Previous value
            new_value: New value
        """
        self._log_event('configuration_change', {
            'username': username,
            'component': component,
            'change_type': change_type,
            'old_value': old_value,
            'new_value': new_value
        })
    
    def log_security_event(self, event_type: str, username: str, details: Dict[str, Any]):
        """
        Log security-related event.
        
        Args:
            event_type: Type of security event
            username: Associated username
            details: Event details
        """
        self._log_event('security_event', {
            'security_event_type': event_type,
            'username': username,
            **details
        })
    
    def log_system_event(self, event_type: str, component: str, details: Dict[str, Any]):
        """
        Log system-level event.
        
        Args:
            event_type: Type of system event
            component: System component
            details: Event details
        """
        self._log_event('system_event', {
            'system_event_type': event_type,
            'component': component,
            **details
        })
    
    def close(self):
        """Close audit logger and clean up resources."""
        if self.syslog_socket:
            self.syslog_socket.close()
        
        if self.file_logger:
            for handler in self.file_logger.handlers:
                handler.close()
                self.file_logger.removeHandler(handler)


class ComplianceAuditLogger(AuditLogger):
    """Extended audit logger with financial industry compliance features."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compliance_standards = ['SOX', 'PCI-DSS', 'GDPR']
    
    def log_data_access(self, username: str, data_type: str, operation: str, 
                       record_count: int = 0, sensitive: bool = False):
        """
        Log data access event for compliance.
        
        Args:
            username: User accessing data
            data_type: Type of data accessed
            operation: Operation performed
            record_count: Number of records accessed
            sensitive: Whether data is considered sensitive
        """
        self._log_event('data_access', {
            'username': username,
            'data_type': data_type,
            'operation': operation,
            'record_count': record_count,
            'sensitive_data': sensitive,
            'compliance_standards': self.compliance_standards
        })
    
    def log_privilege_escalation(self, username: str, from_role: str, to_role: str, 
                               authorized_by: str):
        """
        Log privilege escalation event.
        
        Args:
            username: User whose privileges changed
            from_role: Previous role
            to_role: New role
            authorized_by: Who authorized the change
        """
        self._log_event('privilege_escalation', {
            'username': username,
            'from_role': from_role,
            'to_role': to_role,
            'authorized_by': authorized_by,
            'compliance_standards': self.compliance_standards
        })
    
    def log_retention_event(self, data_type: str, action: str, retention_period: str,
                           record_count: int = 0):
        """
        Log data retention event.
        
        Args:
            data_type: Type of data
            action: Retention action (archive, delete, etc.)
            retention_period: Retention period applied
            record_count: Number of records affected
        """
        self._log_event('data_retention', {
            'data_type': data_type,
            'retention_action': action,
            'retention_period': retention_period,
            'record_count': record_count,
            'compliance_standards': self.compliance_standards
        })
