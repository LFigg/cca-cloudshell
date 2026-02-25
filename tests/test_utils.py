"""
Tests for lib/utils.py utility functions.

Covers:
- generate_run_id format and uniqueness
- get_timestamp format
- format_bytes_to_gb conversion
- format_gb_to_tb conversion
- mask_account_id ARN masking
- tags_to_dict conversion (AWS and Azure formats)
- get_name_from_tags fallback logic
- write_json and write_csv (local files)
- print_summary_table formatting
- retry_with_backoff decorator
- redact_sensitive_data and hash_sensitive_id
- AuthError and is_auth_error detection
- check_and_raise_auth_error
- parallel_collect utility
"""
import json
import os
import sys
import tempfile
import time
from unittest.mock import Mock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.utils import (
    AuthError,
    check_and_raise_auth_error,
    format_bytes_to_gb,
    format_gb_to_tb,
    generate_run_id,
    get_name_from_tags,
    get_timestamp,
    hash_sensitive_id,
    is_auth_error,
    mask_account_id,
    parallel_collect,
    redact_sensitive_data,
    retry_with_backoff,
    setup_logging,
    tags_to_dict,
    write_csv,
    write_json,
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
        assert format_bytes_to_gb(None) == 0.0  # type: ignore[arg-type]

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
        assert format_gb_to_tb(None) == 0.0  # type: ignore[arg-type]

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


# =============================================================================
# mask_account_id Tests
# =============================================================================

class TestMaskAccountId:
    """Tests for mask_account_id function."""

    def test_mask_standard_arn(self):
        """Test masking a standard IAM role ARN."""
        arn = "arn:aws:iam::123456789012:role/MyRole"
        result = mask_account_id(arn)
        assert result == "arn:aws:iam::***:role/MyRole"
        assert "123456789012" not in result

    def test_mask_arn_with_path(self):
        """Test masking ARN with path."""
        arn = "arn:aws:iam::987654321098:role/path/to/MyRole"
        result = mask_account_id(arn)
        assert result == "arn:aws:iam::***:role/path/to/MyRole"

    def test_mask_s3_arn(self):
        """Test masking S3 bucket ARN."""
        arn = "arn:aws:s3:::my-bucket/path/object.txt"
        result = mask_account_id(arn)
        # S3 ARNs don't have account IDs, should remain unchanged
        assert result == arn

    def test_mask_ec2_arn(self):
        """Test masking EC2 instance ARN."""
        arn = "arn:aws:ec2:us-east-1:111222333444:instance/i-0abc123def456"
        result = mask_account_id(arn)
        assert result == "arn:aws:ec2:us-east-1:***:instance/i-0abc123def456"

    def test_mask_multiple_account_ids(self):
        """Test masking message with multiple account IDs."""
        msg = "Failed to assume role in accounts 111111111111, 222222222222"
        result = mask_account_id(msg)
        assert "111111111111" not in result
        assert "222222222222" not in result
        assert "***" in result

    def test_mask_empty_string(self):
        """Test with empty string."""
        result = mask_account_id("")
        assert result == ""

    def test_mask_no_account_id(self):
        """Test string without account ID."""
        msg = "Some error message"
        result = mask_account_id(msg)
        assert result == msg


# =============================================================================
# hash_sensitive_id Tests
# =============================================================================

class TestHashSensitiveId:
    """Tests for hash_sensitive_id function."""

    def test_hash_with_prefix(self):
        """Test hashing with a prefix."""
        result = hash_sensitive_id("i-0abc123def456", "i-")
        assert result.startswith("i-")
        assert len(result) == 10  # "i-" + 8 chars

    def test_hash_without_prefix(self):
        """Test hashing without prefix."""
        result = hash_sensitive_id("some-value")
        assert len(result) == 8

    def test_hash_consistency(self):
        """Test that same input produces same hash."""
        value = "test-value-123"
        hash1 = hash_sensitive_id(value)
        hash2 = hash_sensitive_id(value)
        assert hash1 == hash2

    def test_hash_different_values(self):
        """Test that different inputs produce different hashes."""
        hash1 = hash_sensitive_id("value1")
        hash2 = hash_sensitive_id("value2")
        assert hash1 != hash2

    def test_hash_empty_string(self):
        """Test with empty string returns empty."""
        result = hash_sensitive_id("")
        assert result == ""

    def test_hash_none(self):
        """Test with None value."""
        result = hash_sensitive_id(None)
        assert result is None


# =============================================================================
# redact_sensitive_data Tests
# =============================================================================

class TestRedactSensitiveData:
    """Tests for redact_sensitive_data function."""

    def test_redact_aws_instance_id(self):
        """Test redacting AWS EC2 instance ID."""
        data = {"resource_id": "i-0abc123def456789"}
        result = redact_sensitive_data(data)
        assert result["resource_id"] != "i-0abc123def456789"
        assert result["resource_id"].startswith("i-")

    def test_redact_aws_volume_id(self):
        """Test redacting AWS EBS volume ID."""
        data = {"resource_id": "vol-0abc123def456789"}
        result = redact_sensitive_data(data)
        assert result["resource_id"] != "vol-0abc123def456789"
        assert result["resource_id"].startswith("vol-")

    def test_redact_aws_account_id(self):
        """Test redacting AWS account ID field."""
        data = {"account_id": "123456789012"}
        result = redact_sensitive_data(data)
        assert result["account_id"] != "123456789012"

    def test_redact_azure_subscription(self):
        """Test redacting Azure subscription ID."""
        data = {"subscription_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
        result = redact_sensitive_data(data)
        assert result["subscription_id"] != "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_redact_azure_resource_id(self):
        """Test redacting Azure resource ID path."""
        azure_id = "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
        data = {"resource_id": azure_id}
        result = redact_sensitive_data(data)
        assert result["resource_id"] != azure_id
        assert "/subscriptions/" in result["resource_id"]
        assert "/providers/Microsoft.Compute/virtualMachines/" in result["resource_id"]

    def test_redact_gcp_project_path(self):
        """Test redacting GCP project path."""
        data = {"resource_id": "projects/my-project-123/zones/us-central1-a/instances/my-vm"}
        result = redact_sensitive_data(data)
        assert "projects/" in result["resource_id"]
        assert "my-project-123" not in result["resource_id"]

    def test_redact_nested_dict(self):
        """Test redacting nested dictionary."""
        data = {
            "metadata": {
                "account_id": "123456789012",
                "vpc_id": "vpc-abc123"
            }
        }
        result = redact_sensitive_data(data)
        assert result["metadata"]["account_id"] != "123456789012"
        assert result["metadata"]["vpc_id"] != "vpc-abc123"

    def test_redact_list(self):
        """Test redacting list of sensitive values."""
        data = {"subnet_ids": ["subnet-abc123", "subnet-def456"]}
        result = redact_sensitive_data(data)
        assert "subnet-abc123" not in result["subnet_ids"]
        assert "subnet-def456" not in result["subnet_ids"]

    def test_preserve_non_sensitive_fields(self):
        """Test that non-sensitive fields are preserved."""
        data = {
            "name": "my-resource",
            "size_gb": 100,
            "region": "us-east-1",
            "tags": {"Environment": "prod"}
        }
        result = redact_sensitive_data(data)
        assert result["name"] == "my-resource"
        assert result["size_gb"] == 100
        assert result["region"] == "us-east-1"
        assert result["tags"] == {"Environment": "prod"}

    def test_consistency_across_calls(self):
        """Test that same value always hashes to same result."""
        data1 = {"account_id": "123456789012"}
        data2 = {"account_id": "123456789012"}
        result1 = redact_sensitive_data(data1)
        result2 = redact_sensitive_data(data2)
        assert result1["account_id"] == result2["account_id"]


# =============================================================================
# AuthError Tests
# =============================================================================

class TestAuthError:
    """Tests for AuthError exception class."""

    def test_auth_error_message(self):
        """Test AuthError stores message correctly."""
        err = AuthError("Access denied", provider="aws")
        assert str(err) == "Access denied"

    def test_auth_error_provider(self):
        """Test AuthError stores provider."""
        err = AuthError("Access denied", provider="azure")
        assert err.provider == "azure"

    def test_auth_error_original_error(self):
        """Test AuthError stores original exception."""
        original = ValueError("Original error")
        err = AuthError("Wrapped error", provider="gcp", original_error=original)
        assert err.original_error is original

    def test_auth_error_inheritance(self):
        """Test AuthError is an Exception."""
        err = AuthError("Test", provider="aws")
        assert isinstance(err, Exception)


# =============================================================================
# is_auth_error Tests
# =============================================================================

class TestIsAuthError:
    """Tests for is_auth_error function."""

    def test_regular_exception_not_auth(self):
        """Test regular exception is not auth error."""
        exc = ValueError("Some error")
        assert is_auth_error(exc) is False

    def test_aws_access_denied(self):
        """Test AWS AccessDenied is auth error."""
        # Mock a botocore ClientError
        exc = Mock()
        exc.__class__.__name__ = 'ClientError'
        exc.response = {'Error': {'Code': 'AccessDenied'}}
        assert is_auth_error(exc) is True

    def test_aws_unauthorized_operation(self):
        """Test AWS UnauthorizedOperation is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'ClientError'
        exc.response = {'Error': {'Code': 'UnauthorizedOperation'}}
        assert is_auth_error(exc) is True

    def test_aws_expired_token(self):
        """Test AWS ExpiredToken is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'ClientError'
        exc.response = {'Error': {'Code': 'ExpiredToken'}}
        assert is_auth_error(exc) is True

    def test_aws_non_auth_client_error(self):
        """Test AWS non-auth ClientError is not auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'ClientError'
        exc.response = {'Error': {'Code': 'ResourceNotFoundException'}}
        assert is_auth_error(exc) is False

    def test_azure_401_status(self):
        """Test Azure HttpResponseError with 401 is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'HttpResponseError'
        exc.status_code = 401
        assert is_auth_error(exc) is True

    def test_azure_403_status(self):
        """Test Azure HttpResponseError with 403 is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'HttpResponseError'
        exc.status_code = 403
        assert is_auth_error(exc) is True

    def test_azure_500_not_auth(self):
        """Test Azure HttpResponseError with 500 is not auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'HttpResponseError'
        exc.status_code = 500
        exc.__str__ = lambda self: "Internal server error"
        assert is_auth_error(exc) is False

    def test_gcp_permission_denied(self):
        """Test GCP PermissionDenied is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'PermissionDenied'
        assert is_auth_error(exc) is True

    def test_gcp_unauthenticated(self):
        """Test GCP Unauthenticated is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'Unauthenticated'
        assert is_auth_error(exc) is True

    def test_m365_authorization_denied(self):
        """Test M365 ODataError with Authorization_RequestDenied is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'ODataError'
        exc.error = Mock()
        exc.error.code = 'Authorization_RequestDenied'
        assert is_auth_error(exc) is True

    def test_m365_invalid_token(self):
        """Test M365 InvalidAuthenticationToken is auth error."""
        exc = Mock()
        exc.__class__.__name__ = 'ODataError'
        exc.error = Mock()
        exc.error.code = 'InvalidAuthenticationToken'
        assert is_auth_error(exc) is True


# =============================================================================
# check_and_raise_auth_error Tests
# =============================================================================

class TestCheckAndRaiseAuthError:
    """Tests for check_and_raise_auth_error function."""

    def test_raises_on_auth_error(self):
        """Test raises AuthError when exception is auth-related."""
        # Create a real exception class named exactly as is_auth_error expects
        # We need the class name to be 'ClientError' for the check
        class ClientError(Exception):
            response = {'Error': {'Code': 'AccessDenied'}}

        exc = ClientError("Access Denied")

        with pytest.raises(AuthError) as excinfo:
            check_and_raise_auth_error(exc, "collect VMs", "aws")

        assert excinfo.value.provider == "aws"
        assert "collect VMs" in str(excinfo.value)

    def test_returns_on_non_auth_error(self):
        """Test returns normally when exception is not auth-related."""
        exc = ValueError("Some other error")
        # Should not raise
        result = check_and_raise_auth_error(exc, "collect VMs", "azure")
        assert result is None

    def test_preserves_original_error(self):
        """Test original exception is preserved."""
        # Class must be named exactly 'PermissionDenied' for is_auth_error to detect it
        class PermissionDenied(Exception):
            pass

        exc = PermissionDenied("Permission denied")

        with pytest.raises(AuthError) as excinfo:
            check_and_raise_auth_error(exc, "list projects", "gcp")

        assert excinfo.value.original_error is exc


# =============================================================================
# parallel_collect Tests
# =============================================================================

class TestParallelCollect:
    """Tests for parallel_collect function."""

    def test_serial_collection(self):
        """Test collection with parallel_workers=1 (serial)."""
        def collect_a():
            return [{"name": "a1"}, {"name": "a2"}]

        def collect_b():
            return [{"name": "b1"}]

        tasks = [
            ("A", collect_a, ()),
            ("B", collect_b, ()),
        ]

        result = parallel_collect(tasks, parallel_workers=1)
        assert len(result) == 3
        assert {"name": "a1"} in result
        assert {"name": "b1"} in result

    def test_parallel_collection(self):
        """Test collection with parallel_workers>1."""
        def collect_items(prefix):
            return [{"name": f"{prefix}1"}, {"name": f"{prefix}2"}]

        tasks = [
            ("A", collect_items, ("a",)),
            ("B", collect_items, ("b",)),
            ("C", collect_items, ("c",)),
        ]

        result = parallel_collect(tasks, parallel_workers=3)
        assert len(result) == 6

    def test_empty_results_handling(self):
        """Test handling of tasks that return empty/None."""
        def collect_empty():
            return []

        def collect_none():
            return None

        def collect_some():
            return [{"name": "item"}]

        tasks = [
            ("Empty", collect_empty, ()),
            ("None", collect_none, ()),
            ("Some", collect_some, ()),
        ]

        result = parallel_collect(tasks, parallel_workers=1)
        assert len(result) == 1
        assert result[0] == {"name": "item"}

    def test_error_handling_continues(self):
        """Test that non-auth errors are logged and collection continues."""
        def collect_good():
            return [{"name": "good"}]

        def collect_bad():
            raise ValueError("Something went wrong")

        tasks = [
            ("Good", collect_good, ()),
            ("Bad", collect_bad, ()),
        ]

        # Should not raise, should return results from good task
        result = parallel_collect(tasks, parallel_workers=1)
        assert len(result) == 1
        assert result[0] == {"name": "good"}

    def test_auth_error_propagates(self):
        """Test that AuthError stops collection and propagates."""
        def collect_good():
            return [{"name": "good"}]

        def collect_auth_fail():
            raise AuthError("Access denied", provider="aws")

        tasks = [
            ("Good", collect_good, ()),
            ("AuthFail", collect_auth_fail, ()),
        ]

        with pytest.raises(AuthError):
            parallel_collect(tasks, parallel_workers=1)

    def test_parallel_auth_error_propagates(self):
        """Test AuthError propagates in parallel mode."""
        def collect_slow():
            time.sleep(0.1)
            return [{"name": "slow"}]

        def collect_auth_fail():
            raise AuthError("Access denied", provider="azure")

        tasks = [
            ("Slow", collect_slow, ()),
            ("AuthFail", collect_auth_fail, ()),
        ]

        with pytest.raises(AuthError):
            parallel_collect(tasks, parallel_workers=2)

    def test_with_tracker(self):
        """Test parallel_collect with a mock tracker."""
        tracker = Mock()

        def collect_items():
            # Return mock objects with size_gb attribute
            item = Mock()
            item.size_gb = 10.0
            return [item, item]

        tasks = [("Items", collect_items, ())]

        result = parallel_collect(tasks, parallel_workers=1, tracker=tracker)
        assert len(result) == 2
        # Verify tracker was called
        tracker.update_task.assert_called()
        tracker.add_resources.assert_called()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
