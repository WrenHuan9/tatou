"""Unit tests for toy_comment.py module - 100% coverage."""

import re
from unittest.mock import patch

import pytest

from toy_comment import ToyComment


class TestToyComment:
    """Test ToyComment watermarking method."""
    
    def test_class_attributes(self):
        """Test class has correct attributes and inherits properly."""
        method = ToyComment()
        # ToyComment doesn't define a name attribute, so it should inherit the default
        assert hasattr(method, 'add_watermark')
        assert hasattr(method, 'read_secret')
        assert hasattr(method, 'is_watermark_applicable')
        assert hasattr(method, 'get_usage')
    
    def test_docstring(self):
        """Test class has proper docstring."""
        assert ToyComment.__doc__ is not None
        assert "PDF注释" in ToyComment.__doc__ or "注释对象" in ToyComment.__doc__
    
    def test_get_usage(self):
        """Test get_usage returns descriptive string."""
        method = ToyComment()
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert "comment" in usage.lower()
        assert "secret" in usage.lower()
        assert "pdf" in usage.lower()
    
    def test_is_watermark_applicable_always_true(self):
        """Test is_watermark_applicable always returns True."""
        method = ToyComment()
        
        # Test with different inputs - should always return True
        assert method.is_watermark_applicable(b"any bytes") is True
        assert method.is_watermark_applicable(b"") is True
        assert method.is_watermark_applicable(b"%PDF-1.4") is True
        assert method.is_watermark_applicable(b"not a pdf") is True
    
    def test_is_watermark_applicable_with_kwargs(self):
        """Test is_watermark_applicable with additional kwargs."""
        method = ToyComment()
        
        result = method.is_watermark_applicable(
            b"pdf_bytes",
            position="any",
            extra_param="ignored"
        )
        assert result is True
    
    def test_add_watermark_basic(self):
        """Test basic watermark addition."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\noriginal content\n%%EOF"
        secret = "test-secret"
        key = "test-key"  # Key is not used but should be accepted
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        assert len(result) > len(pdf_bytes)
        assert result.startswith(pdf_bytes)
        
        # Check that comment was added
        comment_part = result[len(pdf_bytes):]
        assert b"% TATOU_SECRET: test-secret" in comment_part
    
    def test_add_watermark_comment_format(self):
        """Test the exact format of the added comment."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "my-secret"
        key = "unused-key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        # Comment should be: "\n% TATOU_SECRET: {secret}\n"
        expected_comment = b"\n% TATOU_SECRET: my-secret\n"
        assert result.endswith(expected_comment)
        assert result == pdf_bytes + expected_comment
    
    def test_add_watermark_unicode_secret(self):
        """Test add_watermark with Unicode characters in secret."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "测试秘密 🔒"
        key = "key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        # Unicode should be encoded as UTF-8
        expected_comment = f"\n% TATOU_SECRET: {secret}\n".encode("utf-8")
        assert result.endswith(expected_comment)
    
    def test_add_watermark_empty_secret(self):
        """Test add_watermark with empty secret."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = ""
        key = "key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_comment = b"\n% TATOU_SECRET: \n"
        assert result.endswith(expected_comment)
    
    def test_add_watermark_secret_with_newlines(self):
        """Test add_watermark with secret containing newlines."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "line1\nline2\nline3"
        key = "key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        # Newlines should be preserved in the comment
        expected_comment = f"\n% TATOU_SECRET: {secret}\n".encode("utf-8")
        assert result.endswith(expected_comment)
    
    def test_add_watermark_secret_with_special_chars(self):
        """Test add_watermark with secret containing special characters."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        key = "key"
        
        result = method.add_watermark(pdf_bytes, secret, key)
        
        expected_comment = f"\n% TATOU_SECRET: {secret}\n".encode("utf-8")
        assert result.endswith(expected_comment)
    
    def test_add_watermark_with_kwargs(self):
        """Test add_watermark with additional kwargs."""
        method = ToyComment()
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
        
        expected_comment = b"\n% TATOU_SECRET: test-secret\n"
        assert result.endswith(expected_comment)
    
    def test_add_watermark_key_not_used(self):
        """Test that key parameter is not used (as documented in code)."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "test-secret"
        
        # Different keys should produce identical results
        result1 = method.add_watermark(pdf_bytes, secret, "key1")
        result2 = method.add_watermark(pdf_bytes, secret, "key2")
        result3 = method.add_watermark(pdf_bytes, secret, "")
        
        assert result1 == result2 == result3
    
    def test_read_secret_basic_found(self):
        """Test read_secret when secret is found."""
        method = ToyComment()
        pdf_with_comment = b"%PDF-1.4\ncontent\n% TATOU_SECRET: my-secret\n"
        key = "any-key"  # Key is not used
        
        result = method.read_secret(pdf_with_comment, key)
        
        assert result == "my-secret"
    
    def test_read_secret_not_found(self):
        """Test read_secret when no secret is found."""
        method = ToyComment()
        pdf_without_comment = b"%PDF-1.4\ncontent without watermark\n"
        key = "any-key"
        
        result = method.read_secret(pdf_without_comment, key)
        
        assert result == "No secret found with toy-comment method."
    
    def test_read_secret_unicode_secret(self):
        """Test read_secret with Unicode characters."""
        method = ToyComment()
        secret = "测试秘密 🔒"
        pdf_with_comment = f"%PDF-1.4\ncontent\n% TATOU_SECRET: {secret}\n".encode("utf-8")
        key = "any-key"
        
        result = method.read_secret(pdf_with_comment, key)
        
        assert result == secret
    
    def test_read_secret_empty_secret(self):
        """Test read_secret when secret is empty."""
        method = ToyComment()
        pdf_with_comment = b"%PDF-1.4\ncontent\n% TATOU_SECRET: \n"
        key = "any-key"
        
        result = method.read_secret(pdf_with_comment, key)
        
        assert result == ""
    
    def test_read_secret_secret_with_newlines(self):
        """Test read_secret with secret containing newlines."""
        method = ToyComment()
        secret = "line1\nline2"
        pdf_with_comment = f"%PDF-1.4\ncontent\n% TATOU_SECRET: {secret}\n".encode("utf-8")
        key = "any-key"
        
        result = method.read_secret(pdf_with_comment, key)
        
        # Only the first line should be captured by the regex
        assert result == "line1"
    
    def test_read_secret_secret_with_special_chars(self):
        """Test read_secret with secret containing special characters."""
        method = ToyComment()
        secret = "!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        pdf_with_comment = f"%PDF-1.4\ncontent\n% TATOU_SECRET: {secret}\n".encode("utf-8")
        key = "any-key"
        
        result = method.read_secret(pdf_with_comment, key)
        
        assert result == secret
    
    def test_read_secret_multiple_comments_returns_first(self):
        """Test read_secret when multiple comments exist, returns first one."""
        method = ToyComment()
        pdf_with_comments = (
            b"%PDF-1.4\ncontent\n"
            b"% TATOU_SECRET: first-secret\n"
            b"more content\n"
            b"% TATOU_SECRET: second-secret\n"
        )
        key = "any-key"
        
        result = method.read_secret(pdf_with_comments, key)
        
        assert result == "first-secret"
    
    def test_read_secret_comment_in_middle_of_pdf(self):
        """Test read_secret when comment is in the middle of PDF."""
        method = ToyComment()
        pdf_with_comment = (
            b"%PDF-1.4\n"
            b"some content\n"
            b"% TATOU_SECRET: middle-secret\n"
            b"more content\n"
            b"%%EOF"
        )
        key = "any-key"
        
        result = method.read_secret(pdf_with_comment, key)
        
        assert result == "middle-secret"
    
    def test_read_secret_comment_at_beginning(self):
        """Test read_secret when comment is at the beginning of PDF."""
        method = ToyComment()
        pdf_with_comment = (
            b"% TATOU_SECRET: beginning-secret\n"
            b"%PDF-1.4\n"
            b"content\n"
        )
        key = "any-key"
        
        result = method.read_secret(pdf_with_comment, key)
        
        assert result == "beginning-secret"
    
    def test_read_secret_partial_comment_pattern(self):
        """Test read_secret with partial comment patterns that shouldn't match."""
        method = ToyComment()
        
        # Missing colon
        pdf1 = b"%PDF-1.4\n% TATOU_SECRET no-colon\n"
        assert method.read_secret(pdf1, "key") == "No secret found with toy-comment method."
        
        # Missing TATOU_SECRET prefix
        pdf2 = b"%PDF-1.4\n% SECRET: secret\n"
        assert method.read_secret(pdf2, "key") == "No secret found with toy-comment method."
        
        # Missing % prefix
        pdf3 = b"%PDF-1.4\nTATOU_SECRET: secret\n"
        assert method.read_secret(pdf3, "key") == "No secret found with toy-comment method."
    
    def test_read_secret_with_decode_errors(self):
        """Test read_secret with bytes that can't be decoded."""
        method = ToyComment()
        
        # Create binary data with invalid UTF-8 sequence
        invalid_utf8 = b"%PDF-1.4\n% TATOU_SECRET: \xff\xfe\n"
        key = "any-key"
        
        result = method.read_secret(invalid_utf8, key)
        
        # The method uses "ignore" mode, so invalid bytes should be ignored
        # The regex should still match, but the invalid bytes will be ignored during decode
        assert "No secret found" not in result or result == ""
    
    def test_read_secret_regex_pattern_verification(self):
        """Test the exact regex pattern used in read_secret."""
        method = ToyComment()
        
        # Test the regex pattern directly
        test_data = b"some content\n% TATOU_SECRET: captured-secret\nmore content"
        
        # This should match the pattern used in the method
        match = re.search(rb"% TATOU_SECRET: (.*)\n", test_data)
        assert match is not None
        assert match.group(1) == b"captured-secret"
        
        # Test through the method
        result = method.read_secret(test_data, "key")
        assert result == "captured-secret"
    
    def test_read_secret_key_not_used(self):
        """Test that key parameter is not used in read_secret."""
        method = ToyComment()
        pdf_with_comment = b"%PDF-1.4\n% TATOU_SECRET: test-secret\n"
        
        # Different keys should produce identical results
        result1 = method.read_secret(pdf_with_comment, "key1")
        result2 = method.read_secret(pdf_with_comment, "key2")
        result3 = method.read_secret(pdf_with_comment, "")
        
        assert result1 == result2 == result3 == "test-secret"
    
    def test_roundtrip_integration(self):
        """Test complete roundtrip: add watermark then read secret."""
        method = ToyComment()
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
        method = ToyComment()
        original_pdf = b"%PDF-1.4\ncontent"
        secret = "测试秘密 🔒 with symbols !@#$%"
        key = "test-key"
        
        watermarked = method.add_watermark(original_pdf, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_roundtrip_with_empty_secret(self):
        """Test roundtrip with empty secret."""
        method = ToyComment()
        original_pdf = b"%PDF-1.4\ncontent"
        secret = ""
        key = "test-key"
        
        watermarked = method.add_watermark(original_pdf, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_deterministic_behavior(self):
        """Test that the method produces deterministic results."""
        method = ToyComment()
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
        
        method1 = ToyComment()
        method2 = ToyComment()
        
        # Both instances should produce identical results
        result1 = method1.add_watermark(pdf_bytes, secret, key)
        result2 = method2.add_watermark(pdf_bytes, secret, key)
        
        assert result1 == result2
        
        extracted1 = method1.read_secret(result1, key)
        extracted2 = method2.read_secret(result1, key)
        
        assert extracted1 == extracted2 == secret
    
    def test_large_secret(self):
        """Test with very large secret."""
        method = ToyComment()
        pdf_bytes = b"%PDF-1.4\ncontent"
        secret = "x" * 10000  # Very large secret
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_large_pdf(self):
        """Test with large PDF content."""
        method = ToyComment()
        large_content = b"content line\n" * 10000
        pdf_bytes = b"%PDF-1.4\n" + large_content + b"%%EOF"
        secret = "large-pdf-secret"
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_binary_pdf_content(self):
        """Test with PDF containing binary data."""
        method = ToyComment()
        # PDF with some binary content
        binary_content = bytes(range(256))
        pdf_bytes = b"%PDF-1.4\n" + binary_content + b"\n%%EOF"
        secret = "binary-test"
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_bytes, secret, key)
        extracted = method.read_secret(watermarked, key)
        
        assert extracted == secret
    
    def test_existing_comment_preservation(self):
        """Test that existing comments in PDF are preserved."""
        method = ToyComment()
        pdf_with_existing_comment = (
            b"%PDF-1.4\n"
            b"% This is an existing comment\n"
            b"content\n"
            b"% Another existing comment\n"
            b"%%EOF"
        )
        secret = "new-secret"
        key = "test-key"
        
        watermarked = method.add_watermark(pdf_with_existing_comment, secret, key)
        
        # Original comments should still be present
        assert b"% This is an existing comment" in watermarked
        assert b"% Another existing comment" in watermarked
        
        # New comment should be added
        assert b"% TATOU_SECRET: new-secret" in watermarked
        
        extracted = method.read_secret(watermarked, key)
        assert extracted == secret


# Coverage analysis:
# 
# ToyComment class:
# ✓ __init__ (implicit through instantiation)
# ✓ Class docstring and attributes
# ✓ add_watermark() - all parameters, edge cases, Unicode, special chars
# ✓ read_secret() - found/not found, regex patterns, decode errors
# ✓ is_watermark_applicable() - always returns True with any input
# ✓ get_usage() - return value verification
# ✓ Key parameter handling (documented as unused)
# ✓ All code paths and branches covered
# ✓ Integration roundtrip tests
# ✓ Deterministic behavior verification
# ✓ Edge cases: empty secret, large data, Unicode, special characters
# ✓ Regex pattern verification and edge cases
# ✓ Multiple comment handling
# ✓ Binary content handling
# ✓ Error conditions and decode failures
# 
# This should achieve 100% code coverage for toy_comment.py
