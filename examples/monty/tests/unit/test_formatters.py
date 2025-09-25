"""
Unit tests for output formatters.
"""
import pytest
import json
import yaml
from monty.utils.formatters import (
    OutputFormatter, NamespaceFormatter, ErrorFormatter,
    format_duration, format_bytes, truncate_string
)


def test_output_formatter_json():
    """Test JSON formatting."""
    data = {"name": "test", "value": 123}
    result = OutputFormatter.to_json(data)
    
    parsed = json.loads(result)
    assert parsed["name"] == "test"
    assert parsed["value"] == 123


def test_output_formatter_yaml():
    """Test YAML formatting."""
    data = {"name": "test", "value": 123}
    result = OutputFormatter.to_yaml(data)
    
    parsed = yaml.safe_load(result)
    assert parsed["name"] == "test"
    assert parsed["value"] == 123


def test_output_formatter_table():
    """Test table formatting."""
    data = [
        {"name": "item1", "value": 123},
        {"name": "item2", "value": 456}
    ]
    result = OutputFormatter.to_table(data)
    
    assert "item1" in result
    assert "item2" in result
    assert "123" in result
    assert "456" in result


def test_output_formatter_table_single_dict():
    """Test table formatting with single dictionary."""
    data = {"name": "test", "value": 123}
    result = OutputFormatter.to_table(data)
    
    assert "test" in result
    assert "123" in result


def test_output_formatter_table_empty():
    """Test table formatting with empty data."""
    result = OutputFormatter.to_table([])
    assert result == "No data to display"


def test_namespace_formatter_list():
    """Test namespace list formatting."""
    namespaces = [
        {
            "namespace_name": "test-ns",
            "cluster_name": "prod",
            "status": "Active",
            "created_at": "2023-01-01T00:00:00Z",
            "labels": {"env": "prod"},
            "resource_quota": {"cpu_limit": "2000m"}
        }
    ]
    
    result = NamespaceFormatter.format_namespace_list(namespaces, "table")
    assert "test-ns" in result
    assert "prod" in result
    assert "Active" in result


def test_namespace_formatter_detail():
    """Test namespace detail formatting."""
    namespace = {
        "namespace_name": "test-ns",
        "cluster_name": "prod",
        "status": "Active",
        "labels": {"env": "prod"}
    }
    
    result = NamespaceFormatter.format_namespace_detail(namespace, "yaml")
    parsed = yaml.safe_load(result)
    assert parsed["namespace_name"] == "test-ns"
    assert parsed["cluster_name"] == "prod"


def test_error_formatter():
    """Test error formatting."""
    result = ErrorFormatter.format_error(
        "Test error",
        error_code="E001",
        details={"field": "value"},
        output_format="json"
    )
    
    parsed = json.loads(result)
    assert parsed["error"] == "Test error"
    assert parsed["code"] == "E001"
    assert parsed["details"]["field"] == "value"


def test_error_formatter_validation():
    """Test validation error formatting."""
    errors = ["Field is required", "Invalid format"]
    result = ErrorFormatter.format_validation_errors(errors, "json")
    
    parsed = json.loads(result)
    assert parsed["error_count"] == 2
    assert "Field is required" in parsed["validation_errors"]
    assert "Invalid format" in parsed["validation_errors"]


def test_format_duration():
    """Test duration formatting."""
    assert format_duration(0.5) == "500ms"
    assert format_duration(1.5) == "1.5s"
    assert format_duration(90) == "1.5m"
    assert format_duration(7200) == "2.0h"


def test_format_bytes():
    """Test bytes formatting."""
    assert format_bytes(512) == "512.0B"
    assert format_bytes(1536) == "1.5KB"
    assert format_bytes(1048576) == "1.0MB"
    assert format_bytes(1073741824) == "1.0GB"


def test_truncate_string():
    """Test string truncation."""
    text = "This is a very long string that should be truncated"
    result = truncate_string(text, 20)
    assert len(result) <= 20
    assert result.endswith("...")
    
    short_text = "Short"
    result = truncate_string(short_text, 20)
    assert result == "Short"
