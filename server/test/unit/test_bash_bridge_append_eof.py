"""Unit tests for bash_bridge_append_eof.py module."""

import tempfile
from pathlib import Path
from io import BytesIO

import pytest

from server.src.bash_bridge_append_eof import BashBridgeAppendEOF
from server.src.watermarking_method import SecretNotFoundError, WatermarkingMethod


class TestBashBridgeAppendEOF:
    """Test BashBridgeAppendEOF watermarking method."""
    
    def test_class_attributes(self):
        """Test class has correct attributes."""
        method = BashBridgeAppendEOF()
        assert method.name == "bash-bridge-eof"
        assert BashBridgeAppendEOF.name == "bash-bridge-eof"
    
    def test_get_usage(self):
        """Test get_usage returns descriptive string."""
        usage = BashBridgeAppendEOF.get_usage()
        assert isinstance(usage, str)
        assert "toy method" in usage.lower()
        assert "eof" in usage.lower()
        assert "position and key are ignored" in usage.lower()
    
    def test_is_watermark_applicable_always_true(self, sample_pdf_file: Path, sample_pdf_bytes: bytes):
        """Test is_watermark_applicable always returns True.
        
        The position parameter is accepted for API compatibility but ignored.
        This method always returns True regardless of input.
        """
        method = BashBridgeAppendEOF()
        
        # Test with different PDF sources
        assert method.is_watermark_applicable(sample_pdf_file) is True
        assert method.is_watermark_applicable(sample_pdf_bytes) is True
        assert method.is_watermark_applicable(str(sample_pdf_file)) is True
        
        # Test with different position values (all ignored)
        assert method.is_watermark_applicable(sample_pdf_file, position="top-left") is True
        assert method.is_watermark_applicable(sample_pdf_file, position="bottom-right") is True
        assert method.is_watermark_applicable(sample_pdf_file, position="center") is True
        assert method.is_watermark_applicable(sample_pdf_file, position="invalid-position") is True
        assert method.is_watermark_applicable(sample_pdf_file, position="") is True
        assert method.is_watermark_applicable(sample_pdf_file, position=None) is True
        
        # Test with bytes and different positions
        assert method.is_watermark_applicable(sample_pdf_bytes, position="any") is True
        assert method.is_watermark_applicable(sample_pdf_bytes, position="🎯") is True
    
    def test_add_watermark_with_bytes(self, sample_pdf_bytes: bytes):
        """Test add_watermark with bytes input."""
        method = BashBridgeAppendEOF()
        secret = "test-secret-123"
        key = "test-key"  # This will be ignored
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert result.startswith(sample_pdf_bytes)
        assert result.endswith(secret.encode('utf-8'))
        assert len(result) == len(sample_pdf_bytes) + len(secret.encode('utf-8'))
    
    def test_add_watermark_with_file_path(self, sample_pdf_file: Path):
        """Test add_watermark with file path input."""
        method = BashBridgeAppendEOF()
        secret = "file-path-secret"
        key = "ignored-key"
        
        result = method.add_watermark(sample_pdf_file, secret, key)
        
        assert isinstance(result, bytes)
        assert result.endswith(secret.encode('utf-8'))
        # Should start with PDF header
        assert result.startswith(b"%PDF-")
    
    def test_add_watermark_with_string_path(self, sample_pdf_file: Path):
        """Test add_watermark with string path input."""
        method = BashBridgeAppendEOF()
        secret = "string-path-secret"
        key = "ignored-key"
        
        result = method.add_watermark(str(sample_pdf_file), secret, key)
        
        assert isinstance(result, bytes)
        assert result.endswith(secret.encode('utf-8'))
        assert result.startswith(b"%PDF-")
    
    def test_add_watermark_with_file_object(self, sample_pdf_bytes: bytes):
        """Test add_watermark with file-like object input."""
        method = BashBridgeAppendEOF()
        secret = "file-object-secret"
        key = "ignored-key"
        
        pdf_file = BytesIO(sample_pdf_bytes)
        result = method.add_watermark(pdf_file, secret, key)
        
        assert isinstance(result, bytes)
        assert result.endswith(secret.encode('utf-8'))
        assert result.startswith(b"%PDF-")
    
    def test_add_watermark_position_parameter_ignored(self, sample_pdf_bytes: bytes):
        """Test that position parameter is ignored in add_watermark method.
        
        The position parameter is accepted for API compatibility but completely ignored.
        """
        method = BashBridgeAppendEOF()
        secret = "position-test"
        key = "test-key"
        
        result1 = method.add_watermark(sample_pdf_bytes, secret, key)
        result2 = method.add_watermark(sample_pdf_bytes, secret, key, position="top-left")
        result3 = method.add_watermark(sample_pdf_bytes, secret, key, position="bottom-right")
        result4 = method.add_watermark(sample_pdf_bytes, secret, key, position="center")
        result5 = method.add_watermark(sample_pdf_bytes, secret, key, position="invalid-position")
        result6 = method.add_watermark(sample_pdf_bytes, secret, key, position="")
        result7 = method.add_watermark(sample_pdf_bytes, secret, key, position=None)
        
        # All results should be identical regardless of position value
        assert result1 == result2 == result3 == result4 == result5 == result6 == result7
        # All should just append the secret to the PDF
        assert all(result.endswith(secret.encode('utf-8')) for result in [result1, result2, result3, result4, result5, result6, result7])
    
    def test_add_watermark_key_parameter_ignored(self, sample_pdf_bytes: bytes):
        """Test that key parameter is ignored in add_watermark method.
        
        The key parameter is accepted for API compatibility but completely ignored.
        """
        method = BashBridgeAppendEOF()
        secret = "key-test"
        
        result1 = method.add_watermark(sample_pdf_bytes, secret, "key1")
        result2 = method.add_watermark(sample_pdf_bytes, secret, "key2")
        result3 = method.add_watermark(sample_pdf_bytes, secret, "completely-different-key")
        result4 = method.add_watermark(sample_pdf_bytes, secret, "")  # Empty key
        result5 = method.add_watermark(sample_pdf_bytes, secret, "🔑🗝️")  # Unicode key
        
        # All results should be identical regardless of key value
        assert result1 == result2 == result3 == result4 == result5
        # All should just append the secret to the PDF
        assert all(result.endswith(secret.encode('utf-8')) for result in [result1, result2, result3, result4, result5])
    
    def test_add_watermark_empty_secret(self, sample_pdf_bytes: bytes):
        """Test add_watermark with empty secret."""
        method = BashBridgeAppendEOF()
        secret = ""
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert result == sample_pdf_bytes  # Should be identical since empty secret
    
    def test_add_watermark_unicode_secret(self, sample_pdf_bytes: bytes):
        """Test add_watermark with unicode characters in secret."""
        method = BashBridgeAppendEOF()
        secret = "测试秘密🔒"
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert result.startswith(sample_pdf_bytes)
        assert result.endswith(secret.encode('utf-8'))
    
    def test_add_watermark_multiline_secret(self, sample_pdf_bytes: bytes):
        """Test add_watermark with multiline secret."""
        method = BashBridgeAppendEOF()
        secret = "line1\nline2\nline3"
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert result.startswith(sample_pdf_bytes)
        assert result.endswith(secret.encode('utf-8'))
    
    def test_read_secret_with_eof_marker_no_watermark(self, sample_pdf_bytes: bytes):
        """Test that read_secret returns empty string when %%EOF marker is found but no watermark exists."""
        method = BashBridgeAppendEOF()
        key = "test-key"
        
        # PDF with %%EOF marker but no watermark should raise SecretNotFoundError
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, key)
    
    def test_read_secret_with_watermarked_pdf(self, sample_pdf_bytes: bytes):
        """Test read_secret with watermarked PDF correctly extracts the secret."""
        method = BashBridgeAppendEOF()
        secret = "test-secret"
        key = "test-key"
        
        # First add a watermark
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Should be able to read the secret back
        result = method.read_secret(watermarked, key)
        assert result == secret
    
    def test_read_secret_with_file_path(self, sample_pdf_file: Path):
        """Test read_secret with file path input returns empty string when no watermark exists."""
        method = BashBridgeAppendEOF()
        key = "test-key"
        
        # File path with %%EOF marker but no watermark should raise SecretNotFoundError
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_file, key)
    
    def test_read_secret_with_string_path(self, sample_pdf_file: Path):
        """Test read_secret with string path input returns empty string when no watermark exists."""
        method = BashBridgeAppendEOF()
        key = "test-key"
        
        # String path with %%EOF marker but no watermark should raise SecretNotFoundError
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(str(sample_pdf_file), key)
    
    def test_read_secret_with_file_object(self, sample_pdf_bytes: bytes):
        """Test read_secret with file-like object input returns empty string when no watermark exists."""
        method = BashBridgeAppendEOF()
        key = "test-key"
        
        pdf_file = BytesIO(sample_pdf_bytes)
        # File object with %%EOF marker but no watermark should raise SecretNotFoundError
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(pdf_file, key)
    
    def test_read_secret_key_parameter_ignored(self, sample_pdf_bytes: bytes):
        """Test that key parameter is ignored in read_secret method.
        
        The key parameter is accepted for API compatibility but completely ignored.
        All key value reads should throw SecretNotFoundError since there's no secret data after EOF.
        """
        method = BashBridgeAppendEOF()
        
        # All should raise SecretNotFoundError regardless of key value since there's no secret data
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, "key1")
        
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, "key2")
        
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, "completely-different-key")
        
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, "")  # Empty key
        
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, "🔑🗝️")  # Unicode key
        
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(sample_pdf_bytes, "super-long-key-that-would-normally-matter")

    def test_pdf_without_eof_marker(self, pdf_without_eof: bytes):
        """Test behavior with PDF that doesn't contain %%EOF marker.
        
        When no %%EOF marker is found, the method should raise SecretNotFoundError.
        """
        method = BashBridgeAppendEOF()
        key = "test-key"
        
        # When rfind returns -1 (no %%EOF found), should raise SecretNotFoundError
        with pytest.raises(SecretNotFoundError, match="No BashBridgeAppendEOF watermark found"):
            method.read_secret(pdf_without_eof, "")
    
    def test_constants(self):
        """Test class constants are properly defined."""
        assert BashBridgeAppendEOF._EOF_MARKER == b'%%EOF'

    def test_method_inheritance(self):
        """Test that class properly inherits from WatermarkingMethod."""
        method = BashBridgeAppendEOF()
        assert isinstance(method, WatermarkingMethod)
    
    def test_add_watermark_large_secret(self, sample_pdf_bytes: bytes):
        """Test add_watermark with large secret."""
        method = BashBridgeAppendEOF()
        # Create a large secret (1MB)
        secret = "A" * (1024 * 1024)
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert len(result) == len(sample_pdf_bytes) + len(secret.encode('utf-8'))
        assert result.endswith(secret.encode('utf-8'))
    
    def test_add_watermark_special_characters(self, sample_pdf_bytes: bytes):
        """Test add_watermark with special characters in secret."""
        method = BashBridgeAppendEOF()
        secret = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert result.endswith(secret.encode('utf-8'))
    
    def test_integration_add_and_read_workflow(self, sample_pdf_bytes: bytes):
        """Test the complete workflow of adding and reading watermarks works correctly."""
        method = BashBridgeAppendEOF()
        secret = "integration-test-secret"
        key = "integration-key"
        
        # Step 1: Add watermark
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        assert isinstance(watermarked, bytes)
        assert watermarked.endswith(secret.encode('utf-8'))
        
        # Step 2: Read watermark back
        result = method.read_secret(watermarked, key)
        assert result == secret
    
    def test_multiple_watermarks(self, sample_pdf_bytes: bytes):
        """Test adding multiple watermarks sequentially."""
        method = BashBridgeAppendEOF()
        
        # Add first watermark
        watermarked1 = method.add_watermark(sample_pdf_bytes, "secret1", "key1")
        
        # Add second watermark to the already watermarked PDF
        watermarked2 = method.add_watermark(watermarked1, "secret2", "key2")
        
        # Should contain both secrets
        assert watermarked2.endswith(b"secret2")
        assert b"secret1" in watermarked2
        assert b"secret2" in watermarked2
    
    def test_edge_case_empty_pdf(self):
        """Test behavior with empty PDF data.
        
        Empty data is not valid PDF and should raise ValueError.
        """
        method = BashBridgeAppendEOF()
        empty_pdf = b""
        secret = "secret"
        key = "key"
        
        # Empty data should raise ValueError because it's not a valid PDF
        with pytest.raises(ValueError, match="Input does not look like a valid PDF"):
            method.add_watermark(empty_pdf, secret, key)
    
    def test_watermark_preservation(self, sample_pdf_bytes: bytes):
        """Test that original PDF content is preserved when adding watermark."""
        method = BashBridgeAppendEOF()
        secret = "preservation-test"
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Original content should be at the beginning
        assert result.startswith(sample_pdf_bytes)
        # New content should be at the end
        assert result[len(sample_pdf_bytes):] == secret.encode('utf-8')
    
    def test_method_name_in_all(self):
        """Test that the class is properly exported in __all__."""
        from server.src.bash_bridge_append_eof import __all__
        assert "BashBridgeAppendEOF" in __all__
    
    def test_read_secret_with_watermarked_file_path(self, sample_pdf_file: Path):
        """Test reading secret from watermarked PDF file."""
        method = BashBridgeAppendEOF()
        secret = "file-path-secret"
        key = "test-key"
        
        # Add watermark to file content
        original_content = sample_pdf_file.read_bytes()
        watermarked_content = method.add_watermark(original_content, secret, key)
        
        # Write watermarked content to a new file
        watermarked_file = sample_pdf_file.parent / "watermarked.pdf"
        watermarked_file.write_bytes(watermarked_content)
        
        # Read secret from the watermarked file
        result = method.read_secret(watermarked_file, key)
        assert result == secret
        
        # Cleanup
        watermarked_file.unlink()
    
    def test_read_secret_with_whitespace_in_secret(self, sample_pdf_bytes: bytes):
        """Test reading secret that contains whitespace characters."""
        method = BashBridgeAppendEOF()
        secret = "  secret with spaces  \n\t"
        key = "test-key"
        
        # Add watermark
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Read secret back (should be stripped)
        result = method.read_secret(watermarked, key)
        assert result == secret.strip()
    
    def test_read_secret_with_binary_data_in_secret(self, sample_pdf_bytes: bytes):
        """Test reading secret that contains binary-like data."""
        method = BashBridgeAppendEOF()
        # Secret with some binary-looking content
        secret = "binary\x00\x01\x02data"
        key = "test-key"
        
        # Add watermark
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Read secret back (binary data should be handled with errors='ignore')
        result = method.read_secret(watermarked, key)
        # The result may not be exactly the same due to encoding/decoding with errors='ignore'
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_add_watermark_preserves_pdf_structure(self, sample_pdf_bytes: bytes):
        """Test that adding watermark preserves the original PDF structure."""
        method = BashBridgeAppendEOF()
        secret = "structure-test"
        key = "test-key"
        
        # Add watermark
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Original PDF structure should be preserved
        assert watermarked.startswith(b"%PDF-1.4")
        assert b"%%EOF" in watermarked
        
        # The secret should be appended after the original content
        assert watermarked == sample_pdf_bytes + secret.encode('utf-8')
    
    def test_multiple_eof_markers_uses_last_one(self, sample_pdf_bytes: bytes):
        """Test that when multiple %%EOF markers exist, the last one is used."""
        method = BashBridgeAppendEOF()
        
        # Create PDF with multiple %%EOF markers
        pdf_with_multiple_eof = sample_pdf_bytes + b"\n%%EOF\nextra content after second EOF"
        
        # Read secret should extract everything after the LAST %%EOF
        result = method.read_secret(pdf_with_multiple_eof, "test-key")
        assert result == "extra content after second EOF"
    
    def test_read_secret_with_non_utf8_data(self, sample_pdf_bytes: bytes):
        """Test reading secret when non-UTF8 data exists after %%EOF."""
        method = BashBridgeAppendEOF()
        
        # Create PDF with non-UTF8 bytes after %%EOF
        non_utf8_data = b"\xff\xfe\x00invalid utf8 data"
        pdf_with_non_utf8 = sample_pdf_bytes + non_utf8_data
        
        # Should raise SecretNotFoundError since non-UTF8 data is not valid UTF-8
        with pytest.raises(SecretNotFoundError, match="Secret data contains invalid UTF-8"):
            method.read_secret(pdf_with_non_utf8, "test-key")

    def test_eof_marker_constant_is_correct(self):
        """Test that the EOF marker constant is correctly defined."""
        assert BashBridgeAppendEOF._EOF_MARKER == b'%%EOF'
        assert len(BashBridgeAppendEOF._EOF_MARKER) == 5
    
    def test_watermark_with_eof_in_secret(self, sample_pdf_bytes: bytes):
        """Test adding watermark where secret contains %%EOF."""
        method = BashBridgeAppendEOF()
        secret = "This secret contains %%EOF marker"
        key = "test-key"
        
        # Add watermark
        watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
        
        # Read secret back
        result = method.read_secret(watermarked, key)
        # The method finds the LAST %%EOF (from the original PDF) and reads everything after it
        # Since the secret contains %%EOF, only the text after the LAST %%EOF will be read
        # In this case, it will be "marker" (the part after "%%EOF" in the secret)
        assert "marker" in result
    
    def test_empty_pdf_with_eof_only(self):
        """Test behavior with minimal PDF containing only %%EOF."""
        method = BashBridgeAppendEOF()
        # Create a minimal valid PDF with just %%EOF
        minimal_pdf = b"%PDF-1.4\n%%EOF"
        
        # Should raise SecretNotFoundError since nothing is after %%EOF
        with pytest.raises(SecretNotFoundError, match="Found EOF marker but no secret data"):
            method.read_secret(minimal_pdf, "")
    
    def test_method_works_with_pathlib_path(self, sample_pdf_file: Path):
        """Test that method works correctly with pathlib.Path objects."""
        method = BashBridgeAppendEOF()
        secret = "pathlib-test"
        key = "test-key"
        
        # Should work with pathlib.Path for both add and read operations
        original_content = sample_pdf_file.read_bytes()
        watermarked_content = method.add_watermark(sample_pdf_file, secret, key)
        
        assert isinstance(watermarked_content, bytes)
        assert watermarked_content.endswith(secret.encode('utf-8'))
        assert watermarked_content.startswith(original_content)
    
    def test_read_secret_key_ignored_with_watermarked_pdf(self, sample_pdf_bytes: bytes):
        """Test that key parameter is ignored even when reading from watermarked PDFs.
        
        This demonstrates that the key used to add the watermark doesn't matter
        when reading it back - any key will work because the key is ignored.
        """
        method = BashBridgeAppendEOF()
        secret = "key-independence-test"
        original_key = "original-key-used-for-watermarking"
        
        # Add watermark with one key
        watermarked = method.add_watermark(sample_pdf_bytes, secret, original_key)
        
        # Read with completely different keys - should all return the same secret
        result1 = method.read_secret(watermarked, original_key)  # Same key as used for watermarking
        result2 = method.read_secret(watermarked, "different-key")  # Different key
        result3 = method.read_secret(watermarked, "")  # Empty key
        result4 = method.read_secret(watermarked, "🔐wrong-key🔐")  # Unicode key
        result5 = method.read_secret(watermarked, "completely-unrelated-key-12345")
        
        # All should return the same secret regardless of the key used
        assert result1 == result2 == result3 == result4 == result5 == secret
    
    def test_both_position_and_key_ignored_together(self, sample_pdf_bytes: bytes):
        """Test that both position and key parameters are ignored when used together."""
        method = BashBridgeAppendEOF()
        secret = "both-params-ignored"
        
        # Add watermarks with different combinations of position and key
        result1 = method.add_watermark(sample_pdf_bytes, secret, "key1", position="top-left")
        result2 = method.add_watermark(sample_pdf_bytes, secret, "key2", position="bottom-right")
        result3 = method.add_watermark(sample_pdf_bytes, secret, "key3", position="center")
        result4 = method.add_watermark(sample_pdf_bytes, secret, "", position="")
        result5 = method.add_watermark(sample_pdf_bytes, secret, "🔑", position="🎯")
        
        # All results should be identical
        assert result1 == result2 == result3 == result4 == result5
        assert all(result.endswith(secret.encode('utf-8')) for result in [result1, result2, result3, result4, result5])
        
        # Reading with different keys should also return the same result
        read1 = method.read_secret(result1, "any-key")
        read2 = method.read_secret(result2, "different-key")
        read3 = method.read_secret(result3, "")
        
        assert read1 == read2 == read3 == secret