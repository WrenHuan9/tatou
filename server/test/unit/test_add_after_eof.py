"""Unit tests for add_after_eof.py module."""

import base64
import json
import tempfile
from pathlib import Path

import pytest

from server.src.add_after_eof import AddAfterEOF
from server.src.watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError


class TestAddAfterEOF:
    """Test AddAfterEOF watermarking method."""
    
    def test_class_attributes(self):
        """Test class has correct attributes."""
        method = AddAfterEOF()
        assert method.name == "toy-eof"
        assert hasattr(method, '_MAGIC')
        assert hasattr(method, '_CONTEXT')
    
    def test_get_usage(self):
        """Test get_usage returns descriptive string."""
        usage = AddAfterEOF.get_usage()
        assert isinstance(usage, str)
        assert "toy method" in usage.lower()
        assert "eof" in usage.lower()
    
    def test_is_watermark_applicable_always_true(self, sample_pdf_file: Path):
        """Test is_watermark_applicable always returns True."""
        method = AddAfterEOF()
        assert method.is_watermark_applicable(sample_pdf_file) is True
        assert method.is_watermark_applicable(sample_pdf_file, position="any") is True
    
    def test_add_watermark_basic(self, sample_pdf_bytes: bytes):
        """Test basic watermark addition."""
        method = AddAfterEOF()
        secret = "test-secret"
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert len(result) > len(sample_pdf_bytes)
        assert result.startswith(b"%PDF-")
        assert method._MAGIC in result
    
    def test_add_watermark_with_position_ignored(self, sample_pdf_bytes: bytes):
        """Test position parameter is ignored."""
        method = AddAfterEOF()
        secret = "test-secret"
        key = "test-key"
        
        result1 = method.add_watermark(sample_pdf_bytes, secret, key)
        result2 = method.add_watermark(sample_pdf_bytes, secret, key, position="ignored")
        
        assert result1 == result2
    
    def test_add_watermark_deterministic(self, sample_pdf_bytes: bytes):
        """Test watermarking is deterministic."""
        method = AddAfterEOF()
        secret = "test-secret"
        key = "test-key"
        
        result1 = method.add_watermark(sample_pdf_bytes, secret, key)
        result2 = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert result1 == result2
    
    def test_add_watermark_empty_secret_raises_error(self, sample_pdf_bytes: bytes):
        """Test empty secret raises ValueError."""
        method = AddAfterEOF()
        
        with pytest.raises(ValueError, match="Secret must be a non-empty string"):
            method.add_watermark(sample_pdf_bytes, "", "key")
    
    def test_add_watermark_empty_key_raises_error(self, sample_pdf_bytes: bytes):
        """Test empty key raises ValueError."""
        method = AddAfterEOF()
        
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.add_watermark(sample_pdf_bytes, "secret", "")
    
    def test_add_watermark_none_key_raises_error(self, sample_pdf_bytes: bytes):
        """Test None key raises ValueError."""
        method = AddAfterEOF()
        
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.add_watermark(sample_pdf_bytes, "secret", None)  # type: ignore
    
    def test_read_secret_roundtrip(self, sample_pdf_bytes: bytes):
        """Test complete roundtrip: add then read watermark."""
        method = AddAfterEOF()
        secret = "test-secret-123"
        key = "test-key-456"
        
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_read_secret_unicode_roundtrip(self, sample_pdf_bytes: bytes):
        """Test roundtrip with Unicode characters."""
        method = AddAfterEOF()
        secret = "测试秘密 🔒"
        key = "测试密钥"
        
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_read_secret_no_watermark_raises_error(self, sample_pdf_bytes: bytes):
        """Test reading from non-watermarked PDF raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        with pytest.raises(SecretNotFoundError, match="No AddAfterEOF watermark found"):
            method.read_secret(sample_pdf_bytes, "any-key")
    
    def test_read_secret_wrong_key_raises_error(self, sample_pdf_bytes: bytes):
        """Test reading with wrong key raises InvalidKeyError."""
        method = AddAfterEOF()
        secret = "test-secret"
        correct_key = "correct-key"
        wrong_key = "wrong-key"
        
        watermarked = method.add_watermark(sample_pdf_bytes, secret, correct_key)
        
        with pytest.raises(InvalidKeyError, match="Provided key failed to authenticate"):
            method.read_secret(watermarked, wrong_key)
    
    def test_read_secret_empty_key_raises_error(self, sample_pdf_bytes: bytes):
        """Test reading with empty key raises ValueError."""
        method = AddAfterEOF()
        
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.read_secret(sample_pdf_bytes, "")
    
    def test_payload_structure(self, sample_pdf_bytes: bytes):
        """Test the internal payload structure is correct."""
        method = AddAfterEOF()
        secret = "test-secret"
        key = "test-key"
        
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Extract payload manually to verify structure
        magic_idx = watermarked.rfind(method._MAGIC)
        assert magic_idx != -1
        
        start = magic_idx + len(method._MAGIC)
        end = watermarked.find(b"\n", start)
        if end == -1:
            end = len(watermarked)
        
        payload_b64 = watermarked[start:end].strip()
        payload_json = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_json)
        
        assert payload["v"] == 1
        assert payload["alg"] == "HMAC-SHA256"
        assert "mac" in payload
        assert "secret" in payload
        
        # Verify secret is base64 encoded
        decoded_secret = base64.b64decode(payload["secret"]).decode("utf-8")
        assert decoded_secret == secret
    
    def test_mac_computation(self):
        """Test MAC computation is consistent."""
        method = AddAfterEOF()
        secret_bytes = b"test-secret"
        key = "test-key"
        
        mac1 = method._mac_hex(secret_bytes, key)
        mac2 = method._mac_hex(secret_bytes, key)
        
        assert mac1 == mac2
        assert isinstance(mac1, str)
        assert len(mac1) == 64  # SHA256 hex = 64 chars
    
    def test_mac_different_for_different_inputs(self):
        """Test MAC is different for different inputs."""
        method = AddAfterEOF()
        
        mac1 = method._mac_hex(b"secret1", "key")
        mac2 = method._mac_hex(b"secret2", "key")
        mac3 = method._mac_hex(b"secret1", "different-key")
        
        assert mac1 != mac2
        assert mac1 != mac3
        assert mac2 != mac3
    
    def test_build_payload_deterministic(self):
        """Test payload building is deterministic."""
        method = AddAfterEOF()
        secret = "test-secret"
        key = "test-key"
        
        payload1 = method._build_payload(secret, key)
        payload2 = method._build_payload(secret, key)
        
        assert payload1 == payload2
    
    def test_corrupted_payload_raises_error(self, sample_pdf_bytes: bytes):
        """Test corrupted payload raises SecretNotFoundError."""
        method = AddAfterEOF()
        secret = "test-secret"
        key = "test-key"
        
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Corrupt the payload
        magic_idx = watermarked.rfind(method._MAGIC)
        corrupted = watermarked[:magic_idx + len(method._MAGIC)] + b"corrupted-data\n"
        
        with pytest.raises(SecretNotFoundError, match="Malformed watermark payload"):
            method.read_secret(corrupted, key)
    
    def test_empty_payload_raises_error(self, sample_pdf_bytes: bytes):
        """Test empty payload raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create PDF with magic but empty payload
        watermarked = sample_pdf_bytes + method._MAGIC + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Found marker but empty payload"):
            method.read_secret(watermarked, "any-key")
    
    def test_unsupported_version_raises_error(self, sample_pdf_bytes: bytes):
        """Test unsupported version raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create payload with unsupported version
        payload = {"v": 2, "alg": "HMAC-SHA256", "mac": "fake", "secret": "fake"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Unsupported watermark version"):
            method.read_secret(watermarked, "any-key")
    
    def test_unsupported_mac_algorithm_raises_error(self, sample_pdf_bytes: bytes):
        """Test unsupported MAC algorithm raises WatermarkingError."""
        method = AddAfterEOF()
        
        # Create payload with unsupported MAC algorithm
        payload = {"v": 1, "alg": "HMAC-SHA512", "mac": "fake", "secret": "fake"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(WatermarkingError, match="Unsupported MAC algorithm: 'HMAC-SHA512'"):
            method.read_secret(watermarked, "any-key")
    
    def test_missing_mac_algorithm_raises_error(self, sample_pdf_bytes: bytes):
        """Test missing MAC algorithm raises WatermarkingError."""
        method = AddAfterEOF()
        
        # Create payload without MAC algorithm field
        payload = {"v": 1, "mac": "fake", "secret": "fake"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(WatermarkingError, match="Unsupported MAC algorithm: None"):
            method.read_secret(watermarked, "any-key")
    
    def test_missing_mac_field_raises_error(self, sample_pdf_bytes: bytes):
        """Test missing MAC field raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create payload without MAC field
        payload = {"v": 1, "alg": "HMAC-SHA256", "secret": "fake"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Invalid payload fields"):
            method.read_secret(watermarked, "any-key")
    
    def test_missing_secret_field_raises_error(self, sample_pdf_bytes: bytes):
        """Test missing secret field raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create payload without secret field
        payload = {"v": 1, "alg": "HMAC-SHA256", "mac": "fake"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Invalid payload fields"):
            method.read_secret(watermarked, "any-key")
    
    def test_invalid_base64_secret_raises_error(self, sample_pdf_bytes: bytes):
        """Test invalid base64 secret raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create payload with invalid base64 secret
        payload = {"v": 1, "alg": "HMAC-SHA256", "mac": "fake", "secret": "invalid-base64!@#$%"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Invalid payload fields"):
            method.read_secret(watermarked, "any-key")
    
    def test_non_string_mac_field_raises_error(self, sample_pdf_bytes: bytes):
        """Test non-string MAC field raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create payload with non-string MAC field
        payload = {"v": 1, "alg": "HMAC-SHA256", "mac": 12345, "secret": "fake"}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Invalid payload fields"):
            method.read_secret(watermarked, "any-key")
    
    def test_non_string_secret_field_raises_error(self, sample_pdf_bytes: bytes):
        """Test non-string secret field raises SecretNotFoundError."""
        method = AddAfterEOF()
        
        # Create payload with non-string secret field
        payload = {"v": 1, "alg": "HMAC-SHA256", "mac": "fake", "secret": 12345}
        payload_json = json.dumps(payload).encode()
        payload_b64 = base64.urlsafe_b64encode(payload_json)
        
        watermarked = sample_pdf_bytes + method._MAGIC + payload_b64 + b"\n"
        
        with pytest.raises(SecretNotFoundError, match="Invalid payload fields"):
            method.read_secret(watermarked, "any-key")
    
    def test_with_file_input(self, sample_pdf_file: Path):
        """Test method works with file input."""
        method = AddAfterEOF()
        secret = "file-test-secret"
        key = "file-test-key"
        
        watermarked = method.add_watermark(sample_pdf_file, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_pdf_without_trailing_newline(self):
        """Test watermarking PDF without trailing newline."""
        method = AddAfterEOF()
        pdf_without_newline = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj\n%%EOF"
        secret = "test-secret"
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_without_newline, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
