"""Unit tests for toy_bridge_eof.py module - 100% coverage."""

import pytest

from toy_bridge_eof import ToyBridgeEOF


class TestToyBridgeEOF:
    """Test ToyBridgeEOF watermarking method."""
    
    def test_class_attributes(self):
        """Test class has correct attributes and inherits properly."""
        method = ToyBridgeEOF()
        # ToyBridgeEOF doesn't define a name attribute, so it should inherit the default
        assert hasattr(method, 'add_watermark')
        assert hasattr(method, 'read_secret')
        assert hasattr(method, 'is_watermark_applicable')
        assert hasattr(method, 'get_usage')
    
    def test_docstring(self):
        """Test class has proper docstring."""
        assert ToyBridgeEOF.__doc__ is not None
        assert ("EOF" in ToyBridgeEOF.__doc__ or "桥" in ToyBridgeEOF.__doc__ or 
                "bridge" in ToyBridgeEOF.__doc__)
    
    def test_get_usage(self):
        """Test get_usage returns descriptive string."""
        method = ToyBridgeEOF()
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert "bridge" in usage.lower()
        assert "eof" in usage.lower()
        assert "key" in usage.lower()
        assert "delimiter" in usage.lower()
    
    def test_is_watermark_applicable_always_true(self):
        """Test is_watermark_applicable always returns True."""
        method = ToyBridgeEOF()
        
        # Test with different inputs - should always return True
        assert method.is_watermark_applicable(b"any bytes") is True
        assert method.is_watermark_applicable(b"") is True
        assert method.is_watermark_applicable(b"%PDF-1.4") is True
        assert method.is_watermark_applicable(b"not a pdf") is True
    
    def test_is_watermark_applicable_with_kwargs(self):
        """Test is_watermark_applicable with additional kwargs."""
        method = ToyBridgeEOF()
        
        result = method.is_watermark_applicable(
            b"pdf_bytes",
            position="any",
            extra_param="ignored"
        )
        assert result is True
    
    def test_add_watermark_basic(self):
        """Test basic watermark addition."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\noriginal content\n%%EOF"
        secret = "test-secret"
        key = "test-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert len(result) > len(pdf_bytes)
        assert result.startswith(pdf_bytes)
        
        # Check that bridge and secret were added
        suffix = result[len(pdf_bytes):]
        expected_bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        expected_secret = secret.encode("utf-8")
        assert suffix == expected_bridge + expected_secret
    
    def test_add_watermark_bridge_format(self):
        """Test the exact format of the bridge."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "my-secret"
        key = "my-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        # Bridge format should be: "\n%%--{key}--%%\n"
        expected_bridge = b"\n%%--my-key--%%\n"
        expected_secret = b"my-secret"
        expected_suffix = expected_bridge + expected_secret
        
        assert result == pdf_bytes + expected_suffix
    
    def test_add_watermark_unicode_secret(self):
        """Test add_watermark with Unicode characters in secret."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "测试秘密 🔒"
        key = "test-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        # Unicode should be encoded as UTF-8
        expected_bridge = b"\n%%--test-key--%%\n"
        expected_secret = secret.encode("utf-8")
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_unicode_key(self):
        """Test add_watermark with Unicode characters in key."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        key = "测试密钥 🔑"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        # Unicode key should be encoded as UTF-8 in bridge
        expected_bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        expected_secret = b"test-secret"
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_empty_secret(self):
        """Test add_watermark with empty secret."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = ""
        key = "test-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_bridge = b"\n%%--test-key--%%\n"
        expected_secret = b""
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_empty_key(self):
        """Test add_watermark with empty key."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        key = ""
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_bridge = b"\n%%----%%\n"  # Empty key results in double dashes
        expected_secret = b"test-secret"
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_secret_with_newlines(self):
        """Test add_watermark with secret containing newlines."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "line1\nline2\nline3"
        key = "test-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_bridge = b"\n%%--test-key--%%\n"
        expected_secret = secret.encode("utf-8")
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_secret_with_special_chars(self):
        """Test add_watermark with secret containing special characters."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        key = "test-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_bridge = b"\n%%--test-key--%%\n"
        expected_secret = secret.encode("utf-8")
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_key_with_special_chars(self):
        """Test add_watermark with key containing special characters."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        key = "!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        expected_secret = b"test-secret"
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_add_watermark_with_kwargs(self):
        """Test add_watermark with additional kwargs."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        key = "test-key"
        
        result = method.add_watermark(
            pdf_bytes,
            secret,
            key,
            position="ignored",
            extra_param="also_ignored"
        )
        
        expected_bridge = b"\n%%--test-key--%%\n"
        expected_secret = b"test-secret"
        assert result == pdf_bytes + expected_bridge + expected_secret
    
    def test_read_secret_basic_found(self):
        """Test read_secret when secret is found."""
        method = ToyBridgeEOF()
        key = "test-key"
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        secret = "my-secret"
        
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_not_found(self):
        """Test read_secret when no secret is found."""
        method = ToyBridgeEOF()
        pdf_without_watermark = b"%PDF-1.4\ncontent without watermark"
        key = "any-key"
        
        result = method.read_secret(pdf_without_watermark, key)
        
        assert result == "No secret found with toy-bridge-eof method."
    
    def test_read_secret_wrong_key(self):
        """Test read_secret with wrong key."""
        method = ToyBridgeEOF()
        correct_key = "correct-key"
        wrong_key = "wrong-key"
        
        bridge = f"\n%%--{correct_key}--%%\n".encode("utf-8")
        secret = "my-secret"
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, wrong_key)
        
        assert result == "No secret found with toy-bridge-eof method."
    
    def test_read_secret_unicode_secret(self):
        """Test read_secret with Unicode characters in secret."""
        method = ToyBridgeEOF()
        key = "test-key"
        secret = "测试秘密 🔒"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_unicode_key(self):
        """Test read_secret with Unicode characters in key."""
        method = ToyBridgeEOF()
        key = "测试密钥 🔑"
        secret = "test-secret"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_empty_secret(self):
        """Test read_secret when secret is empty."""
        method = ToyBridgeEOF()
        key = "test-key"
        secret = ""
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_empty_key(self):
        """Test read_secret with empty key."""
        method = ToyBridgeEOF()
        key = ""
        secret = "test-secret"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")  # Results in "\n%%----%%\n"
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_secret_with_newlines(self):
        """Test read_secret with secret containing newlines."""
        method = ToyBridgeEOF()
        key = "test-key"
        secret = "line1\nline2\nline3"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_secret_with_special_chars(self):
        """Test read_secret with secret containing special characters."""
        method = ToyBridgeEOF()
        key = "test-key"
        secret = "!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_key_with_special_chars(self):
        """Test read_secret with key containing special characters."""
        method = ToyBridgeEOF()
        key = "!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        secret = "test-secret"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_watermark = b"%PDF-1.4\ncontent" + bridge + secret.encode("utf-8")
        
        result = method.read_secret(pdf_with_watermark, key)
        
        assert result == secret
    
    def test_read_secret_multiple_bridges_returns_last(self):
        """Test read_secret when multiple bridges exist, returns last one."""
        method = ToyBridgeEOF()
        key = "test-key"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_multiple = (
            b"%PDF-1.4\ncontent" +
            bridge + b"first-secret" +
            b"more content" +
            bridge + b"second-secret"
        )
        
        result = method.read_secret(pdf_with_multiple, key)
        
        # The split() method will split by bridge, and parts[-1] gets the last part
        assert result == "second-secret"
    
    def test_read_secret_bridge_in_middle_of_content(self):
        """Test read_secret when bridge appears in middle of content."""
        method = ToyBridgeEOF()
        key = "test-key"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_bridge = (
            b"%PDF-1.4\n" +
            b"before content" +
            bridge +
            b"secret-content\n" +
            b"after content"
        )
        
        result = method.read_secret(pdf_with_bridge, key)
        
        # Should return everything after the (last) bridge
        assert result == "secret-content\nafter content"
    
    def test_read_secret_bridge_at_beginning(self):
        """Test read_secret when bridge is at the beginning."""
        method = ToyBridgeEOF()
        key = "test-key"
        
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        pdf_with_bridge = bridge + b"secret-content"
        
        result = method.read_secret(pdf_with_bridge, key)
        
        assert result == "secret-content"
    
    def test_read_secret_partial_bridge_patterns(self):
        """Test read_secret with partial bridge patterns that shouldn't match."""
        method = ToyBridgeEOF()
        key = "test-key"
        
        # Missing newlines
        pdf1 = b"%PDF-1.4\n%%--test-key--%%secret"
        assert method.read_secret(pdf1, key) == "No secret found with toy-bridge-eof method."
        
        # Wrong delimiter format
        pdf2 = b"%PDF-1.4\n%--test-key--%\nsecret"
        assert method.read_secret(pdf2, key) == "No secret found with toy-bridge-eof method."
        
        # Missing dashes
        pdf3 = b"%PDF-1.4\n%%test-key%%\nsecret"
        assert method.read_secret(pdf3, key) == "No secret found with toy-bridge-eof method."
    
    def test_read_secret_with_decode_errors(self):
        """Test read_secret with bytes that can't be decoded."""
        method = ToyBridgeEOF()
        key = "test-key"
        
        # Create binary data with invalid UTF-8 sequence after bridge
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        invalid_utf8_secret = b"\xff\xfe\xfd"
        pdf_with_invalid = b"%PDF-1.4\ncontent" + bridge + invalid_utf8_secret
        
        result = method.read_secret(pdf_with_invalid, key)
        
        # The method uses "ignore" mode, so invalid bytes should be ignored
        # Should not raise an exception, but return a string (possibly empty or mangled)
        assert isinstance(result, str)
    
    def test_read_secret_split_behavior_verification(self):
        """Test the split behavior used in read_secret."""
        method = ToyBridgeEOF()
        key = "test-key"
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        
        # Test with no bridge - split should return single item
        pdf_no_bridge = b"%PDF-1.4\ncontent"
        parts = pdf_no_bridge.split(bridge)
        assert len(parts) == 1
        assert parts[0] == pdf_no_bridge
        
        result = method.read_secret(pdf_no_bridge, key)
        assert result == "No secret found with toy-bridge-eof method."
        
        # Test with one bridge - split should return two items
        pdf_one_bridge = b"%PDF-1.4\ncontent" + bridge + b"secret"
        parts = pdf_one_bridge.split(bridge)
        assert len(parts) == 2
        assert parts[-1] == b"secret"
        
        result = method.read_secret(pdf_one_bridge, key)
        assert result == "secret"
    
    def test_roundtrip_integration(self):
        """Test complete roundtrip: add watermark then read secret."""
        method = ToyBridgeEOF()
        original_pdf = b"%PDF-1.4\noriginal content\n%%EOF"
        secret = "roundtrip-secret"
        key = "roundtrip-key"
        
        # Add watermark
        watermarked = method.add_watermark(original_pdf, secret, key)
        
        # Read secret
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_roundtrip_with_unicode(self):
        """Test roundtrip with Unicode characters."""
        method = ToyBridgeEOF()
        original_pdf = b"%PDF-1.4\ncontent"
        secret = "测试秘密 🔒 with symbols !@#$%"
        key = "测试密钥 🔑"
        
        watermarked = method.add_watermark(original_pdf, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_roundtrip_with_empty_values(self):
        """Test roundtrip with empty secret and key."""
        method = ToyBridgeEOF()
        original_pdf = b"%PDF-1.4\ncontent"
        secret = ""
        key = ""
        
        watermarked = method.add_watermark(original_pdf, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_roundtrip_with_newlines_and_special_chars(self):
        """Test roundtrip with complex content."""
        method = ToyBridgeEOF()
        original_pdf = b"%PDF-1.4\ncontent"
        secret = "line1\nline2\nspecial: !@#$%^&*()"
        key = "complex-key-!@#"
        
        watermarked = method.add_watermark(original_pdf, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_deterministic_behavior(self):
        """Test that the method produces deterministic results."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "deterministic-test"
        key = "test-key"
        
        # Add watermark multiple times
        result1 = method.add_watermark(pdf_bytes, secret, key)
        result2 = method.add_watermark(pdf_bytes, secret, key)
        
        assert result1 == result2
        
        # Read secret multiple times
        extracted1 = method.read_secret(result1, key)
        extracted2 = method.read_secret(result1, key)
        
        assert extracted1 == extracted2 == secret
    
    def test_method_independence(self):
        """Test that different method instances behave identically."""
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        key = "test-key"
        
        method1 = ToyBridgeEOF()
        method2 = ToyBridgeEOF()
        
        # Both instances should produce identical results
        result1 = method1.add_watermark(pdf_bytes, secret, key)
        result2 = method2.add_watermark(pdf_bytes, secret, key)
        
        assert result1 == result2
        
        extracted1 = method1.read_secret(result1, key)
        extracted2 = method2.read_secret(result1, key)
        
        assert extracted1 == extracted2 == secret
    
    def test_large_secret(self):
        """Test with very large secret."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "x" * 10000  # Very large secret
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_large_key(self):
        """Test with very large key."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        key = "k" * 10000  # Very large key
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_large_pdf(self):
        """Test with large PDF content."""
        method = ToyBridgeEOF()
        large_content = b"content line\n" * 10000
        pdf_bytes = b"%PDF-1.4\n" + large_content + b"%%EOF"
        secret = "large-pdf-secret"
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_binary_pdf_content(self):
        """Test with PDF containing binary data."""
        method = ToyBridgeEOF()
        # PDF with some binary content
        binary_content = bytes(range(256))
        pdf_bytes = b"%PDF-1.4\n" + binary_content + b"\n%%EOF"
        secret = "binary-test"
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_bridge_collision_with_content(self):
        """Test when PDF content already contains similar bridge patterns."""
        method = ToyBridgeEOF()
        key = "test-key"
        secret = "real-secret"
        
        # PDF already contains a fake bridge pattern
        fake_bridge = b"\n%%--fake-key--%%\n"
        pdf_with_fake = b"%PDF-1.4\ncontent" + fake_bridge + b"fake-secret"
        
        # Add real watermark
        watermarked = method.add_watermark(pdf_with_fake, secret, key)
        
        # Should read the real secret, not the fake one
        extracted = method.read_secret(watermarked, key)
        assert extracted == secret
        
        # Reading with fake key should find the fake bridge and content after it
        fake_extracted = method.read_secret(watermarked, "fake-key")
        # The fake bridge splits the content, so we get everything after the fake bridge,
        # which includes the fake-secret AND the subsequent real watermark
        assert fake_extracted == "fake-secret\n%%--test-key--%%\nreal-secret"
    
    def test_bridge_encoding_edge_cases(self):
        """Test bridge encoding with various edge cases."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        
        # Test with key containing characters that need encoding
        special_keys = [
            "\n",          # Newline in key
            "\r\n",        # CRLF in key  
            "%%--%%",      # Bridge delimiters in key
            "测试\n密钥",    # Unicode with newline
        ]
        
        for key in special_keys:
            watermarked = method.add_watermark(pdf_bytes, secret, key)
            extracted = method.read_secret(watermarked, key)
            assert extracted == secret, f"Failed for key: {repr(key)}"
    
    def test_secret_encoding_edge_cases(self):
        """Test secret encoding with various edge cases."""
        method = ToyBridgeEOF()
        pdf_bytes = b"%PDF-1.4\ncontent"
        key = "test-key"
        
        # Test with secrets containing various characters
        special_secrets = [
            "\x00",        # Null byte
            "\r\n",        # CRLF
            "测试\n秘密",    # Unicode with newline
            bytes(range(128)).decode('latin1'),  # All ASCII chars
        ]
        
        for secret in special_secrets:
            watermarked = method.add_watermark(pdf_bytes, secret, key)
            extracted = method.read_secret(watermarked, key)
            assert extracted == secret, f"Failed for secret: {repr(secret)}"


# Coverage analysis:
# 
# ToyBridgeEOF class:
# ✓ __init__ (implicit through instantiation)
# ✓ Class docstring and attributes  
# ✓ add_watermark() - all parameters, Unicode, special chars, edge cases
# ✓ read_secret() - found/not found, wrong key, multiple bridges, edge cases
# ✓ is_watermark_applicable() - always returns True with any input
# ✓ get_usage() - return value verification
# ✓ Bridge format verification and encoding
# ✓ Split behavior and edge cases
# ✓ All code paths and branches covered
# ✓ Integration roundtrip tests
# ✓ Deterministic behavior verification
# ✓ Edge cases: empty values, large data, Unicode, special characters
# ✓ Binary content handling
# ✓ Error conditions and decode failures
# ✓ Bridge collision scenarios
# ✓ Encoding edge cases for both key and secret
# 
# This should achieve 100% code coverage for toy_bridge_eof.py
