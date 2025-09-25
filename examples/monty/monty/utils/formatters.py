"""
Output formatting utilities for monty CLI and API.
"""
import json
import yaml
from typing import Any, Dict, List, Optional
from tabulate import tabulate
from datetime import datetime


class OutputFormatter:
    """Output formatter for different formats (JSON, YAML, table)."""
    
    @staticmethod
    def format_output(data: Any, output_format: str = 'json') -> str:
        """
        Format data according to specified output format.
        
        Args:
            data: Data to format
            output_format: Output format ('json', 'yaml', 'table')
            
        Returns:
            Formatted string
        """
        if output_format.lower() == 'json':
            return OutputFormatter.to_json(data)
        elif output_format.lower() == 'yaml':
            return OutputFormatter.to_yaml(data)
        elif output_format.lower() == 'table':
            return OutputFormatter.to_table(data)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    @staticmethod
    def to_json(data: Any, indent: int = 2) -> str:
        """
        Format data as JSON.
        
        Args:
            data: Data to format
            indent: JSON indentation
            
        Returns:
            JSON formatted string
        """
        return json.dumps(data, indent=indent, default=OutputFormatter._json_serializer)
    
    @staticmethod
    def to_yaml(data: Any) -> str:
        """
        Format data as YAML.
        
        Args:
            data: Data to format
            
        Returns:
            YAML formatted string
        """
        return yaml.dump(data, default_flow_style=False, indent=2)
    
    @staticmethod
    def to_table(data: Any, headers: Optional[List[str]] = None) -> str:
        """
        Format data as table.
        
        Args:
            data: Data to format (should be list of dicts or single dict)
            headers: Optional custom headers
            
        Returns:
            Table formatted string
        """
        if not data:
            return "No data to display"
        
        if isinstance(data, dict):
            data = [data]
        
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            return OutputFormatter._dict_list_to_table(data, headers)
        
        return str(data)
    
    @staticmethod
    def _dict_list_to_table(data: List[Dict], headers: Optional[List[str]] = None) -> str:
        """
        Convert list of dictionaries to table format.
        
        Args:
            data: List of dictionaries
            headers: Optional custom headers
            
        Returns:
            Table formatted string
        """
        if not data:
            return "No data to display"
        
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        if headers:
            table_headers = headers
        else:
            table_headers = sorted(all_keys)
        
        table_rows = []
        for item in data:
            row = []
            for header in table_headers:
                value = item.get(header, '')
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, default=OutputFormatter._json_serializer)
                elif isinstance(value, datetime):
                    value = value.isoformat()
                elif value is None:
                    value = ''
                row.append(str(value))
            table_rows.append(row)
        
        return tabulate(table_rows, headers=table_headers, tablefmt='grid')
    
    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        """
        JSON serializer for non-standard types.
        
        Args:
            obj: Object to serialize
            
        Returns:
            Serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)


class NamespaceFormatter(OutputFormatter):
    """Specialized formatter for Kubernetes namespace data."""
    
    @staticmethod
    def format_namespace_list(namespaces: List[Dict], output_format: str = 'table') -> str:
        """
        Format list of namespaces.
        
        Args:
            namespaces: List of namespace dictionaries
            output_format: Output format
            
        Returns:
            Formatted string
        """
        if output_format.lower() == 'table':
            headers = [
                'NAME',
                'CLUSTER',
                'STATUS',
                'CREATED',
                'LABELS',
                'RESOURCE_QUOTA'
            ]
            
            simplified_data = []
            for ns in namespaces:
                labels_str = ', '.join([f"{k}={v}" for k, v in ns.get('labels', {}).items()]) or 'none'
                quota = ns.get('resource_quota', {})
                quota_str = ', '.join([f"{k}={v}" for k, v in quota.items() if v]) or 'none'
                
                simplified_data.append({
                    'NAME': ns.get('namespace_name', ''),
                    'CLUSTER': ns.get('cluster_name', ''),
                    'STATUS': ns.get('status', ''),
                    'CREATED': ns.get('created_at', '').split('T')[0] if ns.get('created_at') else '',
                    'LABELS': labels_str,
                    'RESOURCE_QUOTA': quota_str
                })
            
            return OutputFormatter._dict_list_to_table(simplified_data, headers)
        else:
            return OutputFormatter.format_output(namespaces, output_format)
    
    @staticmethod
    def format_namespace_detail(namespace: Dict, output_format: str = 'yaml') -> str:
        """
        Format single namespace details.
        
        Args:
            namespace: Namespace dictionary
            output_format: Output format
            
        Returns:
            Formatted string
        """
        if output_format.lower() == 'table':
            details = []
            for key, value in namespace.items():
                if isinstance(value, (dict, list)):
                    value_str = json.dumps(value, indent=2, default=OutputFormatter._json_serializer)
                else:
                    value_str = str(value)
                details.append({'PROPERTY': key.upper(), 'VALUE': value_str})
            
            return OutputFormatter._dict_list_to_table(details, ['PROPERTY', 'VALUE'])
        else:
            return OutputFormatter.format_output(namespace, output_format)


class AuditFormatter(OutputFormatter):
    """Specialized formatter for audit log data."""
    
    @staticmethod
    def format_audit_logs(logs: List[Dict], output_format: str = 'table') -> str:
        """
        Format audit log entries.
        
        Args:
            logs: List of audit log dictionaries
            output_format: Output format
            
        Returns:
            Formatted string
        """
        if output_format.lower() == 'table':
            headers = [
                'TIMESTAMP',
                'USER',
                'EVENT_TYPE',
                'RESOURCE',
                'ACTION',
                'SUCCESS',
                'DETAILS'
            ]
            
            simplified_data = []
            for log in logs:
                details = log.get('details', {})
                details_str = json.dumps(details) if details else ''
                
                simplified_data.append({
                    'TIMESTAMP': log.get('timestamp', '').split('T')[0] if log.get('timestamp') else '',
                    'USER': log.get('username', ''),
                    'EVENT_TYPE': log.get('event_type', ''),
                    'RESOURCE': log.get('resource', ''),
                    'ACTION': log.get('action', ''),
                    'SUCCESS': str(log.get('success', '')),
                    'DETAILS': details_str[:50] + '...' if len(details_str) > 50 else details_str
                })
            
            return OutputFormatter._dict_list_to_table(simplified_data, headers)
        else:
            return OutputFormatter.format_output(logs, output_format)


class ErrorFormatter:
    """Formatter for error messages and responses."""
    
    @staticmethod
    def format_error(error_message: str, error_code: Optional[str] = None, 
                    details: Optional[Dict[str, Any]] = None, output_format: str = 'json') -> str:
        """
        Format error message.
        
        Args:
            error_message: Error message
            error_code: Optional error code
            details: Optional error details
            output_format: Output format
            
        Returns:
            Formatted error string
        """
        error_data: Dict[str, Any] = {
            'error': error_message,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if error_code:
            error_data['code'] = error_code
        
        if details:
            error_data['details'] = details
        
        return OutputFormatter.format_output(error_data, output_format)
    
    @staticmethod
    def format_validation_errors(errors: List[str], output_format: str = 'json') -> str:
        """
        Format validation errors.
        
        Args:
            errors: List of validation error messages
            output_format: Output format
            
        Returns:
            Formatted validation errors
        """
        error_data = {
            'validation_errors': errors,
            'error_count': len(errors),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return OutputFormatter.format_output(error_data, output_format)


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human-readable duration string
    """
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def format_bytes(bytes_value: float) -> str:
    """
    Format bytes in human-readable format.
    
    Args:
        bytes_value: Size in bytes
        
    Returns:
        Human-readable size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f}{unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f}PB"


def truncate_string(text: str, max_length: int = 50, suffix: str = '...') -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncating
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix
