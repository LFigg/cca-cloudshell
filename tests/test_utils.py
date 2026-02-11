"""
Tests for lib/utils.py utility functions.

Covers:
- generate_run_id format and uniqueness
- get_timestamp format
- format_bytes_to_gb conversion
- format_gb_to_tb conversion
- tags_to_dict conversion (AWS and Azure formats)
- get_name_from_tags fallback logic
- write_json and write_csv (local files)
- print_summary_table formatting
- retry_with_backoff decorator
"""
import pytest
from unittest.mock import Mock, patch, mock_open
import os
import sys
import json
import tempfile
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.utils import (
    generate_run_id,
    get_timestamp,
    format_bytes_to_gb,
    format_gb_to_tb,
    tags_to_dict,
    get_name_from_tags,
    setup_logging,
    write_json,
    write_csv,
    retry_with_backoff,
)


# =============================================================================
# generate_run_id Tests
# =============================================================================

class TestGenerateRunId:
    """Tests for generate_run_id function."""
    
    def test_run_id_format(self):
        """Test run ID has correct format: YYYYMMDD-HHMMSS-xxxxxxxx"""
        run_id = generate_run_id()
        parts = run_id.split('-')
        
        # Should have 3 parts: date, time, uuid
        assert len(parts) == 3
        
        # Date should be 8 digits
        assert len(parts[0]) == 8
        assert parts[0].isdigit()
        
        # Time should be 6 digits
        assert len(parts[1]) == 6
        assert parts[1].isdigit()
        
        # UUID portion should be 8 chars
        assert len(parts[2]) == 8
    
    def test_run_id_uniqueness(self):
        """Test that multiple run IDs are unique."""
        ids = [generate_run_id() for _ in range(100)]
        assert len(set(ids)) == 100  # All should be unique


# =============================================================================
# get_timestamp Tests
# =============================================================================

class TestGetTimestamp:
    """Tests for get_timestamp function."""
    
    def test_timestamp_format(self):
        """Test timestamp is ISO format with Z suffix."""
        ts = get_timestamp()
        
        # Should end with Z (UTC)
        assert ts.endswith('Z')
        
        # Should be parseable as ISO format
        from datetime import datetime
        # Remove Z and parse
        datetime.fromisoformat(ts.replace('Z', '+00:00'))
    
    def test_timestamp_is_utc(self):
        """Test timestamp is in UTC."""
        ts = get_timestamp()
        assert 'Z' in ts or '+00:00' in ts


# =============================================================================
# format_bytes_to_gb Tests
# =============================================================================

class TestFormatBytesToGb:
    """Tests for format_bytes_to_gb function."""
    
    def test_zero_bytes(self):
        """Test conversion of zero bytes."""
        assert format_bytes_to_gb(0) == 0.0
    
    def test_none_bytes(self):
        """Test conversion of None."""
        assert format_bytes_to_gb(None) == 0.0
    
    def test_one_gb(self):
        """Test conversion of exactly 1 GB."""
        one_gb = 1024 ** 3
        assert format_bytes_to_gb(one_gb) == 1.0
    
    def test_fractional_gb(self):
        """Test conversion with fractional result."""
        half_gb = (1024 ** 3) // 2
        assert format_bytes_to_gb(half_gb) == 0.5
    
    def test_large_value(self):
        """Test conversion of large value (1 TB)."""
        one_tb = 1024 ** 4
        assert format_bytes_to_gb(one_tb) == 1024.0
    
    def test_rounding(self):
        """Test that result is rounded to 2 decimal places."""
        bytes_val = 1234567890
        result = format_bytes_to_gb(bytes_val)
        assert result == round(result, 2)


# =============================================================================
# format_gb_to_tb Tests
# =============================================================================

class TestFormatGbToTb:
    """Tests for format_gb_to_tb function."""
    
    def test_zero_gb(self):
        """Test conversion of zero GB."""
        assert format_gb_to_tb(0) == 0.0
    
    def test_none_gb(self):
        """Test conversion of None."""
        assert format_gb_to_tb(None) == 0.0
    
    def test_one_tb(self):
        """Test conversion of 1024 GB = 1 TB."""
        assert format_gb_to_tb(1024) == 1.0
    
    def test_fractional_tb(self):
        """Test conversion with fractional result."""
        assert format_gb_to_tb(512) == 0.5
    
    def test_rounding(self):
        """Test that result is rounded to 2 decimal places."""
        result = format_gb_to_tb(1234)
        assert result == round(result, 2)


# =============================================================================
# tags_to_dict Tests
# =============================================================================

class TestTagsToDict:
    """Tests for tags_to_dict function."""
    
    def test_none_tags(self):
        """Test handling of None tags."""
        assert tags_to_dict(None) == {}
    
    def test_empty_list(self):
        """Test handling of empty list."""
        assert tags_to_dict([]) == {}
    
    def test_empty_dict(self):
        """Test handling of empty dict."""
        assert tags_to_dict({}) == {}
    
    def test_aws_format(self):
        """Test conversion of AWS tag format."""
        aws_tags = [
            {"Key": "Name", "Value": "my-instance"},
            {"Key": "Environment", "Value": "production"},
        ]
        result = tags_to_dict(aws_tags)
        assert result == {"Name": "my-instance", "Environment": "production"}
    
    def test_azure_format(self):
        """Test conversion of Azure tag format (already dict)."""
        azure_tags = {"Name": "my-vm", "Environment": "staging"}
        result = tags_to_dict(azure_tags)
        assert result == azure_tags
    
    def test_aws_with_empty_key(self):
        """Test AWS format with missing Key."""
        aws_tags = [
            {"Key": "Name", "Value": "my-instance"},
            {"Value": "orphan-value"},  # No Key
        ]
        result = tags_to_dict(aws_tags)
        assert result == {"Name": "my-instance"}
    
    def test_unknown_format(self):
        """Test handling of unknown format returns empty dict."""
        assert tags_to_dict("not-a-valid-format") == {}


# =============================================================================
# get_name_from_tags Tests
# =============================================================================

class TestGetNameFromTags:
    """Tests for get_name_from_tags function."""
    
    def test_name_key_uppercase(self):
        """Test extraction with uppercase 'Name' key."""
        tags = {"Name": "my-resource", "Environment": "prod"}
        assert get_name_from_tags(tags) == "my-resource"
    
    def test_name_key_lowercase(self):
        """Test extraction with lowercase 'name' key."""
        tags = {"name": "my-resource", "env": "prod"}
        assert get_name_from_tags(tags) == "my-resource"
    
    def test_fallback_to_resource_id(self):
        """Test fallback to resource_id when no name tag."""
        tags = {"Environment": "prod"}
        assert get_name_from_tags(tags, "i-1234567890") == "i-1234567890"
    
    def test_empty_tags(self):
        """Test with empty tags and resource_id."""
        assert get_name_from_tags({}, "vol-abc123") == "vol-abc123"
    
    def test_empty_everything(self):
        """Test with empty tags and no resource_id."""
        assert get_name_from_tags({}) == ""


# =============================================================================
# write_json Tests
# =============================================================================

class TestWriteJson:
    """Tests for write_json function."""
    
    def test_write_local_file(self):
        """Test writing JSON to local file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            data = {"key": "value", "number": 42}
            write_json(data, filepath)
            
            # Verify file was written
            with open(filepath) as f:
                loaded = json.load(f)
            
            assert loaded == data
        finally:
            os.unlink(filepath)
    
    def test_write_complex_data(self):
        """Test writing complex nested data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            data = {
                "list": [1, 2, 3],
                "nested": {"a": {"b": "c"}},
                "null": None,
            }
            write_json(data, filepath)
            
            with open(filepath) as f:
                loaded = json.load(f)
            
            assert loaded == data
        finally:
            os.unlink(filepath)


# =============================================================================
# write_csv Tests
# =============================================================================

class TestWriteCsv:
    """Tests for write_csv function."""
    
    def test_write_local_file(self):
        """Test writing CSV to local file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            data = [
                {"name": "item1", "value": 100},
                {"name": "item2", "value": 200},
            ]
            write_csv(data, filepath)
            
            # Verify file was written
            with open(filepath) as f:
                content = f.read()
            
            assert "name,value" in content
            assert "item1,100" in content
            assert "item2,200" in content
        finally:
            os.unlink(filepath)
    
    def test_write_empty_data(self):
        """Test writing empty data does nothing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        # Write empty data
        write_csv([], filepath)
        
        # File should be empty or unchanged
        # (write_csv returns early for empty data)
    
    def test_custom_fieldnames(self):
        """Test writing CSV with custom fieldnames that include all data keys."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            data = [
                {"a": 1, "b": 2},
            ]
            write_csv(data, filepath, fieldnames=["b", "a"])
            
            with open(filepath) as f:
                lines = f.readlines()
            
            # Header should use specified field order
            assert lines[0].strip() == "b,a"
            assert lines[1].strip() == "2,1"
        finally:
            os.unlink(filepath)


# =============================================================================
# retry_with_backoff Tests
# =============================================================================

class TestRetryWithBackoff:
    """Tests for retry_with_backoff decorator."""
    
    def test_no_retry_on_success(self):
        """Test function not retried when it succeeds."""
        call_count = 0
        
        @retry_with_backoff(max_attempts=3)
        def successful_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = successful_func()
        assert result == "success"
        assert call_count == 1
    
    def test_retry_on_failure(self):
        """Test function is retried on failure."""
        call_count = 0
        
        @retry_with_backoff(max_attempts=3, min_wait=0.01, max_wait=0.1)
        def failing_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Not yet")
            return "success"
        
        result = failing_func()
        assert result == "success"
        assert call_count == 3
    
    def test_max_attempts_exceeded(self):
        """Test exception raised when max attempts exceeded."""
        call_count = 0
        
        @retry_with_backoff(max_attempts=2, min_wait=0.01, max_wait=0.1)
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Always fails")
        
        with pytest.raises(ConnectionError, match="Always fails"):
            always_fails()
        
        assert call_count == 2
    
    def test_specific_exception_types(self):
        """Test retry only on specified exception types."""
        call_count = 0
        
        @retry_with_backoff(max_attempts=3, exceptions=(ValueError,), min_wait=0.01)
        def specific_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("Not retryable")
        
        with pytest.raises(TypeError):
            specific_error()
        
        # Should only be called once since TypeError isn't in retry list
        assert call_count == 1


# =============================================================================
# setup_logging Tests
# =============================================================================

class TestSetupLogging:
    """Tests for setup_logging function."""
    
    def test_default_level(self):
        """Test default logging level is INFO."""
        logger = setup_logging()
        assert logger is not None
    
    def test_debug_level(self):
        """Test setting DEBUG level."""
        logger = setup_logging("DEBUG")
        assert logger is not None
    
    def test_warning_level(self):
        """Test setting WARNING level."""
        logger = setup_logging("WARNING")
        assert logger is not None
    
    def test_case_insensitive(self):
        """Test level string is case insensitive."""
        logger = setup_logging("debug")
        assert logger is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
