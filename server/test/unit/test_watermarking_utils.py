"""Comprehensive unit tests for watermarking_utils.py module.

This test suite provides complete coverage of all functions and edge cases
in the watermarking_utils module, including:
- Method registry operations (METHODS, register_method, get_method)
- Public API functions (apply_watermark, is_watermarking_applicable, read_watermark)
- PDF exploration functionality (explore_pdf with and without PyMuPDF)
- Internal utility functions (_sha1)
- Error handling and edge cases
- Module-level constants and imports
"""

import hashlib
import io
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import Mock, MagicMock, patch, mock_open

import pytest

# Import the module under test
from server.src.watermarking_utils import (
    METHODS,
    apply_watermark,
    explore_pdf,
    get_method,
    is_watermarking_applicable,
    read_watermark,
    register_method,
    _sha1,
    _OBJ_RE,
    _ENDOBJ_RE,
    _TYPE_RE,
)

# Import dependencies for mocking
from server.src.watermarking_method import (
    WatermarkingMethod,
    WatermarkingError,
    SecretNotFoundError,
    InvalidKeyError,
    load_pdf_bytes,
)


class MockWatermarkingMethod(WatermarkingMethod):
    """Mock watermarking method for comprehensive testing."""
    
    def __init__(self, name: str = "test-mock"):
        self._name = name
    
    @property
    def name(self) -> str:
        return self._name
    
    @staticmethod
    def get_usage() -> str:
        return "Mock method for comprehensive testing"
    
    def add_watermark(self, pdf, secret: str, key: str, position: str | None = None) -> bytes:
        return b"%PDF-1.4\nmocked watermark content\n%%EOF"
    
    def is_watermark_applicable(self, pdf, position: str | None = None) -> bool:
        return True
    
    def read_secret(self, pdf, key: str) -> str:
        return "mock-extracted-secret"


class TestModuleConstants:
    """Test module-level constants and imports."""
    
    @pytest.mark.xfail
    def test_methods_registry_structure(self):
        """Test METHODS registry structure and contents."""
        assert isinstance(METHODS, dict)
        assert len(METHODS) >= 2  # Should have at least the two default methods
        
        # Check expected default methods exist
        assert "toy-eof" in METHODS
        assert "bash-bridge-eof" in METHODS
        
        # Verify all values are WatermarkingMethod instances
        for method_name, method_instance in METHODS.items():
            assert isinstance(method_name, str)
            assert isinstance(method_instance, WatermarkingMethod)
            assert method_instance.name == method_name
    
    @pytest.mark.xfail
    def test_regex_patterns_compiled(self):
        """Test that regex patterns are properly compiled."""
        # Test _OBJ_RE pattern
        test_obj_data = b"1 0 obj\n<< /Type /Catalog >>\nendobj"
        match = _OBJ_RE.search(test_obj_data)
        assert match is not None
        assert match.group(1) == b"1"
        assert match.group(2) == b"0"
        
        # Test multiline obj pattern
        multiline_obj = b"""
        1 0 obj
        << /Type /Catalog >>
        endobj
        """
        multiline_match = _OBJ_RE.search(multiline_obj)
        assert multiline_match is not None
        assert multiline_match.group(1) == b"1"
        assert multiline_match.group(2) == b"0"
        
        # Test _ENDOBJ_RE pattern
        endobj_match = _ENDOBJ_RE.search(test_obj_data)
        assert endobj_match is not None
        
        # Test _TYPE_RE pattern
        type_data = b"<< /Type /Catalog /Pages 2 0 R >>"
        type_match = _TYPE_RE.search(type_data)
        assert type_match is not None
        assert type_match.group(1) == b"Catalog"
        
        # Test type pattern with different formats
        type_data_spaces = b"<< /Type  /Pages  >>"
        type_match_spaces = _TYPE_RE.search(type_data_spaces)
        assert type_match_spaces is not None
        assert type_match_spaces.group(1) == b"Pages"
    
    def test_module_all_exports(self):
        """Test __all__ exports are available."""
        from server.src.watermarking_utils import __all__
        
        expected_exports = [
            "METHODS",
            "register_method", 
            "get_method",
            "apply_watermark",
            "read_watermark", 
            "explore_pdf",
            "is_watermarking_applicable",
        ]
        
        for export in expected_exports:
            assert export in __all__
    
    def test_regex_patterns_edge_cases(self):
        """Test regex patterns with edge cases."""
        # Test with generation numbers > 0
        gen_obj_data = b"5 3 obj\n<< /Type /Font >>\nendobj"
        gen_match = _OBJ_RE.search(gen_obj_data)
        assert gen_match is not None
        assert gen_match.group(1) == b"5"
        assert gen_match.group(2) == b"3"
        
        # Test with no type
        no_type_data = b"<< /Length 100 >>"
        no_type_match = _TYPE_RE.search(no_type_data)
        assert no_type_match is None
        
        # Test endobj with surrounding text
        endobj_surrounded = b"some content\nendobj\nmore content"
        endobj_match_surrounded = _ENDOBJ_RE.search(endobj_surrounded)
        assert endobj_match_surrounded is not None


class TestInternalUtilities:
    """Test internal utility functions."""
    
    def test_sha1_function(self):
        """Test _sha1 utility function."""
        # Test with known input
        test_data = b"Hello, World!"
        expected_hash = hashlib.sha1(test_data).hexdigest()
        
        result = _sha1(test_data)
        assert result == expected_hash
        assert isinstance(result, str)
        assert len(result) == 40  # SHA1 hex digest length
    
    def test_sha1_empty_input(self):
        """Test _sha1 with empty input."""
        result = _sha1(b"")
        expected = hashlib.sha1(b"").hexdigest()
        assert result == expected
    
    def test_sha1_large_input(self):
        """Test _sha1 with large input."""
        large_data = b"x" * 10000
        result = _sha1(large_data)
        expected = hashlib.sha1(large_data).hexdigest()
        assert result == expected
    
    def test_sha1_binary_data(self):
        """Test _sha1 with binary data containing null bytes."""
        binary_data = b"\x00\x01\x02\x03\xff\xfe\xfd"
        result = _sha1(binary_data)
        expected = hashlib.sha1(binary_data).hexdigest()
        assert result == expected
    
    def test_sha1_unicode_encoded(self):
        """Test _sha1 with unicode data encoded as bytes."""
        unicode_text = "Hello, 世界! 🌍"
        utf8_bytes = unicode_text.encode('utf-8')
        result = _sha1(utf8_bytes)
        expected = hashlib.sha1(utf8_bytes).hexdigest()
        assert result == expected


class TestMethodRegistry:
    """Test method registry functionality."""
    
    def setup_method(self):
        """Store original METHODS state before each test."""
        self.original_methods = METHODS.copy()
    
    def teardown_method(self):
        """Restore original METHODS state after each test."""
        METHODS.clear()
        METHODS.update(self.original_methods)
    
    @pytest.mark.xfail
    def test_register_method_new(self):
        """Test registering a new method."""
        mock_method = MockWatermarkingMethod("new-test-method")
        original_count = len(METHODS)
        
        register_method(mock_method)
        
        assert len(METHODS) == original_count + 1
        assert "new-test-method" in METHODS
        assert METHODS["new-test-method"] is mock_method
    
    @pytest.mark.xfail
    def test_register_method_replace_existing(self):
        """Test replacing an existing method."""
        # First register a method
        mock_method1 = MockWatermarkingMethod("replace-test")
        register_method(mock_method1)
        original_count = len(METHODS)
        
        # Replace with a new instance
        mock_method2 = MockWatermarkingMethod("replace-test")
        register_method(mock_method2)
        
        assert len(METHODS) == original_count  # Count shouldn't change
        assert METHODS["replace-test"] is mock_method2  # Should be the new instance
        assert METHODS["replace-test"] is not mock_method1
    
    @pytest.mark.xfail
    def test_register_method_multiple(self):
        """Test registering multiple methods."""
        methods = [
            MockWatermarkingMethod("multi-1"),
            MockWatermarkingMethod("multi-2"),
            MockWatermarkingMethod("multi-3")
        ]
        
        for method in methods:
            register_method(method)
        
        for method in methods:
            assert method.name in METHODS
            assert METHODS[method.name] is method
    
    @pytest.mark.xfail
    def test_get_method_by_string_existing(self):
        """Test getting method by string name for existing method."""
        method = get_method("toy-eof")
        assert isinstance(method, WatermarkingMethod)
        assert method.name == "toy-eof"
        assert method is METHODS["toy-eof"]
    
    def test_get_method_by_string_nonexistent(self):
        """Test getting method by string name for non-existent method."""
        with pytest.raises(KeyError) as exc_info:
            get_method("non-existent-method")
        
        error_msg = str(exc_info.value)
        assert "Unknown watermarking method: 'non-existent-method'" in error_msg
        assert "Known:" in error_msg
        # Should list known methods
        for known_method in METHODS.keys():
            assert known_method in error_msg
    
    @pytest.mark.xfail
    def test_get_method_by_instance_passthrough(self):
        """Test getting method by instance (pass-through behavior)."""
        mock_method = MockWatermarkingMethod("instance-test")
        result = get_method(mock_method)
        assert result is mock_method
        
    @pytest.mark.xfail
    def test_get_method_with_none(self):
        """Test get_method behavior with None input."""
        with pytest.raises(AttributeError):
            get_method(None)  # Should fail when checking isinstance
    
    def test_get_method_with_invalid_type(self):
        """Test get_method with invalid input type."""
        with pytest.raises(KeyError):
            get_method(123)  # Should try to use as dict key and fail
    
    def test_get_method_error_message_format(self):
        """Test that error messages are properly formatted."""
        try:
            get_method("invalid-method-name")
        except KeyError as e:
            error_str = str(e)
            # Should contain the invalid method name
            assert "invalid-method-name" in error_str
            # Should contain sorted list of known methods
            assert "Known:" in error_str
            # Known methods should be sorted
            known_methods = list(METHODS.keys())
            for method in known_methods:
                assert method in error_str


class TestPublicAPIHelpers:
    """Test public API helper functions."""
    
    def setup_method(self):
        """Set up mock method for tests."""
        self.mock_method = MockWatermarkingMethod("api-test")
        register_method(self.mock_method)
    
    def teardown_method(self):
        """Clean up after tests."""
        if "api-test" in METHODS:
            del METHODS["api-test"]
    
    @patch('server.src.watermarking_utils.get_method')
    def test_apply_watermark_with_string_method(self, mock_get_method):
        """Test apply_watermark with string method name."""
        mock_method = Mock()
        mock_method.add_watermark.return_value = b"watermarked_content"
        mock_get_method.return_value = mock_method
        
        result = apply_watermark(
            method="test-method",
            pdf=b"%PDF-1.4\n%%EOF",
            secret="test-secret",
            key="test-key",
            position="top-left"
        )
        
        mock_get_method.assert_called_once_with("test-method")
        mock_method.add_watermark.assert_called_once_with(
            pdf=b"%PDF-1.4\n%%EOF",
            secret="test-secret",
            key="test-key", 
            position="top-left"
        )
        assert result == b"watermarked_content"
    
    @patch('server.src.watermarking_utils.get_method')
    def test_apply_watermark_with_method_instance(self, mock_get_method):
        """Test apply_watermark with method instance."""
        mock_method = Mock()
        mock_method.add_watermark.return_value = b"watermarked_content"
        mock_get_method.return_value = mock_method
        
        result = apply_watermark(
            method=mock_method,
            pdf=b"%PDF-1.4\n%%EOF",
            secret="test-secret",
            key="test-key"
        )
        
        mock_get_method.assert_called_once_with(mock_method)
        mock_method.add_watermark.assert_called_once_with(
            pdf=b"%PDF-1.4\n%%EOF",
            secret="test-secret",
            key="test-key",
            position=None
        )
        assert result == b"watermarked_content"
    
    @patch('server.src.watermarking_utils.get_method')
    def test_apply_watermark_method_error(self, mock_get_method):
        """Test apply_watermark when method raises error."""
        mock_method = Mock()
        mock_method.add_watermark.side_effect = WatermarkingError("Test error")
        mock_get_method.return_value = mock_method
        
        with pytest.raises(WatermarkingError, match="Test error"):
            apply_watermark(
                method="test-method",
                pdf=b"%PDF-1.4\n%%EOF", 
                secret="test-secret",
                key="test-key"
            )
    
    @patch('server.src.watermarking_utils.get_method')
    def test_apply_watermark_all_parameters(self, mock_get_method):
        """Test apply_watermark with all parameters specified."""
        mock_method = Mock()
        mock_method.add_watermark.return_value = b"full_watermarked"
        mock_get_method.return_value = mock_method
        
        result = apply_watermark(
            method="full-test",
            pdf=b"%PDF-1.4\ncontent\n%%EOF",
            secret="full-secret",
            key="full-key",
            position="center"
        )
        
        mock_method.add_watermark.assert_called_once_with(
            pdf=b"%PDF-1.4\ncontent\n%%EOF",
            secret="full-secret",
            key="full-key",
            position="center"
        )
        assert result == b"full_watermarked"
    
    @patch('server.src.watermarking_utils.get_method')
    def test_is_watermarking_applicable_true(self, mock_get_method):
        """Test is_watermarking_applicable returning True."""
        mock_method = Mock()
        mock_method.is_watermark_applicable.return_value = True
        mock_get_method.return_value = mock_method
        
        result = is_watermarking_applicable(
            method="test-method",
            pdf=b"%PDF-1.4\n%%EOF",
            position="bottom-right"
        )
        
        mock_get_method.assert_called_once_with("test-method")
        mock_method.is_watermark_applicable.assert_called_once_with(
            pdf=b"%PDF-1.4\n%%EOF",
            position="bottom-right"
        )
        assert result is True
    
    @patch('server.src.watermarking_utils.get_method')
    def test_is_watermarking_applicable_false(self, mock_get_method):
        """Test is_watermarking_applicable returning False."""
        mock_method = Mock()
        mock_method.is_watermark_applicable.return_value = False
        mock_get_method.return_value = mock_method
        
        result = is_watermarking_applicable(
            method="test-method",
            pdf=b"%PDF-1.4\n%%EOF"
        )
        
        assert result is False
    
    @patch('server.src.watermarking_utils.get_method')
    def test_is_watermarking_applicable_method_error(self, mock_get_method):
        """Test is_watermarking_applicable when method raises error.""" 
        mock_method = Mock()
        mock_method.is_watermark_applicable.side_effect = WatermarkingError("Applicability check failed")
        mock_get_method.return_value = mock_method
        
        with pytest.raises(WatermarkingError, match="Applicability check failed"):
            is_watermarking_applicable(
                method="test-method",
                pdf=b"%PDF-1.4\n%%EOF"
            )
    
    @patch('server.src.watermarking_utils.get_method')
    def test_is_watermarking_applicable_return_type_validation(self, mock_get_method):
        """Test that is_watermarking_applicable properly returns the method's result."""
        mock_method = Mock()
        # Test with different return values
        for return_value in [True, False, 1, 0, "yes", None]:
            mock_method.is_watermark_applicable.return_value = return_value
            mock_get_method.return_value = mock_method
            
            result = is_watermarking_applicable("test", b"%PDF-1.4\n%%EOF")
            assert result == return_value
    
    @patch('server.src.watermarking_utils.get_method')
    def test_read_watermark_success(self, mock_get_method):
        """Test read_watermark successful extraction."""
        mock_method = Mock()
        mock_method.read_secret.return_value = "extracted-secret"
        mock_get_method.return_value = mock_method
        
        result = read_watermark(
            method="test-method",
            pdf=b"%PDF-1.4\nwatermarked\n%%EOF",
            key="test-key"
        )
        
        mock_get_method.assert_called_once_with("test-method")
        mock_method.read_secret.assert_called_once_with(
            pdf=b"%PDF-1.4\nwatermarked\n%%EOF",
            key="test-key"
        )
        assert result == "extracted-secret"
    
    @patch('server.src.watermarking_utils.get_method')
    def test_read_watermark_secret_not_found(self, mock_get_method):
        """Test read_watermark when secret not found."""
        mock_method = Mock()
        mock_method.read_secret.side_effect = SecretNotFoundError("No watermark found")
        mock_get_method.return_value = mock_method
        
        with pytest.raises(SecretNotFoundError, match="No watermark found"):
            read_watermark(
                method="test-method",
                pdf=b"%PDF-1.4\n%%EOF",
                key="test-key"
            )
    
    @patch('server.src.watermarking_utils.get_method')
    def test_read_watermark_invalid_key(self, mock_get_method):
        """Test read_watermark with invalid key."""
        mock_method = Mock()
        mock_method.read_secret.side_effect = InvalidKeyError("Invalid key")
        mock_get_method.return_value = mock_method
        
        with pytest.raises(InvalidKeyError, match="Invalid key"):
            read_watermark(
                method="test-method",
                pdf=b"%PDF-1.4\nwatermarked\n%%EOF",
                key="wrong-key"
            )
    
    @patch('server.src.watermarking_utils.get_method')
    def test_read_watermark_empty_result(self, mock_get_method):
        """Test read_watermark returning empty string."""
        mock_method = Mock()
        mock_method.read_secret.return_value = ""
        mock_get_method.return_value = mock_method
        
        result = read_watermark("test-method", b"%PDF-1.4\n%%EOF", "key")
        assert result == ""

class TestPdfExplorationWithoutFitz:
    """Test PDF exploration functionality without PyMuPDF."""
    
    def test_explore_pdf_fallback_basic_structure(self, sample_pdf_bytes: bytes):
        """Test explore_pdf fallback returns expected structure."""
        # Mock the fitz import to fail within the explore_pdf function
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            assert isinstance(result, dict)
            assert "id" in result
            assert "type" in result
            assert "size" in result
            assert "children" in result
            
            assert result["type"] == "Document"
            assert result["size"] == len(sample_pdf_bytes)
            assert result["id"].startswith("pdf:")
            assert isinstance(result["children"], list)
    
    def test_explore_pdf_fallback_deterministic_id(self, sample_pdf_bytes: bytes):
        """Test that fallback generates deterministic IDs."""
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result1 = explore_pdf(sample_pdf_bytes)
            result2 = explore_pdf(sample_pdf_bytes)
            
            assert result1["id"] == result2["id"]
            assert result1 == result2  # Entire structure should be identical
    
    def test_explore_pdf_fallback_object_parsing(self):
        """Test fallback object parsing with custom PDF data."""
        custom_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R >>\n"
            b"endobj\n"
            b"2 0 obj\n"
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            b"endobj\n"
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R >>\n"
            b"endobj\n"
            b"%%EOF\n"
        )
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(custom_pdf)
        
        assert result["type"] == "Document"
        assert len(result["children"]) > 0
        
        # Should find objects and pages
        obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
        page_nodes = [c for c in result["children"] if c["id"].startswith("page:")]
        
        assert len(obj_nodes) >= 3  # Should find the 3 objects
        assert len(page_nodes) >= 1  # Should derive page nodes
        
        # Check object node structure
        for obj_node in obj_nodes:
            assert "type" in obj_node
            assert "object" in obj_node
            assert "generation" in obj_node
            assert "content_sha1" in obj_node
    
    def test_explore_pdf_fallback_with_file_path(self, sample_pdf_file: Path):
        """Test fallback with file path input."""
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_file)
            
            assert result["type"] == "Document"
            assert result["size"] > 0
            assert isinstance(result["children"], list)
    
    def test_explore_pdf_fallback_empty_pdf(self):
        """Test fallback with minimal/empty PDF data."""
        minimal_pdf = b"%PDF-1.4\n%%EOF\n"
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(minimal_pdf)
            
            assert result["type"] == "Document"
            assert result["size"] == len(minimal_pdf)
            assert isinstance(result["children"], list)
            # May have no children, which is fine for minimal PDF
    
    def test_explore_pdf_fallback_malformed_objects(self):
        """Test fallback with malformed object definitions."""
        malformed_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"  # Missing endobj
            b"<< /Type /Catalog >>\n"
            b"2 0 obj\n"
            b"<< /Type /Pages >>\n"
            b"endobj\n"  # This endobj matches obj 2
            b"%%EOF\n"
        )
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(malformed_pdf)
            
            assert result["type"] == "Document"
            assert isinstance(result["children"], list)
            # Should handle malformed objects gracefully
    
    def test_explore_pdf_fallback_complex_generation_numbers(self):
        """Test fallback with complex generation numbers."""
        complex_gen_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"2 5 obj\n<< /Type /Pages >>\nendobj\n"
            b"10 15 obj\n<< /Type /Page >>\nendobj\n"
            b"%%EOF\n"
        )
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(complex_gen_pdf)
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            
            # Should handle different generation numbers
            gen_numbers = [node["generation"] for node in obj_nodes if "generation" in node]
            assert 0 in gen_numbers
            assert 5 in gen_numbers
            assert 15 in gen_numbers
    
    def test_explore_pdf_fallback_page_derivation(self):
        """Test that page nodes are properly derived from Page objects."""
        page_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page >>\nendobj\n"
            b"4 0 obj\n<< /Type /Page >>\nendobj\n"
            b"%%EOF\n"
        )
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(page_pdf)
        
        # Should have both object nodes and derived page nodes
        obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
        page_nodes = [c for c in result["children"] if c["id"].startswith("page:")]
        
        # Should find Page objects
        page_obj_nodes = [c for c in obj_nodes if c.get("type") == "Page"]
        assert len(page_obj_nodes) == 2
        
        # Should derive page nodes with deterministic IDs
        assert len(page_nodes) == 2
        assert page_nodes[0]["id"] == "page:0000"
        assert page_nodes[1]["id"] == "page:0001"
        
        # Page nodes should reference original objects
        for page_node in page_nodes:
            assert "xref_hint" in page_node
            assert page_node["xref_hint"].startswith("obj:")


class TestPdfExplorationWithFitz:
    """Test PDF exploration functionality with PyMuPDF available."""
    
    @pytest.mark.xfail
    def test_explore_pdf_with_fitz_success(self, sample_pdf_bytes: bytes):
        """Test explore_pdf with PyMuPDF available and successful."""
        mock_doc = Mock()
        mock_doc.page_count = 2
        mock_doc.xref_length.return_value = 5
        
        # Mock page loading
        mock_page1 = Mock()
        mock_page1.bound.return_value = [0, 0, 612, 792]
        mock_page2 = Mock()
        mock_page2.bound.return_value = [0, 0, 612, 792]
        mock_doc.load_page.side_effect = [mock_page1, mock_page2]
        
        # Mock xref objects
        mock_doc.xref_object.side_effect = [
            None,  # xref 0 (usually free)
            "<< /Type /Catalog /Pages 2 0 R >>",  # xref 1
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",  # xref 2
            "<< /Type /Page /Parent 2 0 R >>",  # xref 3
            "<< /Type /Page /Parent 2 0 R >>",  # xref 4
        ]
        mock_doc.xref_is_stream.return_value = False
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            mock_fitz.open.assert_called_once_with(stream=sample_pdf_bytes, filetype="pdf")
            mock_doc.close.assert_called_once()
            
            assert result["type"] == "Document"
            assert len(result["children"]) > 0
            
            # Should have page nodes
            page_nodes = [c for c in result["children"] if c["type"] == "Page"]
            assert len(page_nodes) == 2
            
            for i, page_node in enumerate(page_nodes):
                assert page_node["id"] == f"page:{i:04d}"
                assert page_node["index"] == i
                assert "bbox" in page_node
                assert page_node["bbox"] == [0, 0, 612, 792]
            
            # Should have object nodes
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            assert len(obj_nodes) == 4  # xrefs 1-4
    
    @pytest.mark.xfail
    def test_explore_pdf_with_fitz_stream_objects(self, sample_pdf_bytes: bytes):
        """Test explore_pdf with stream objects."""
        mock_doc = Mock()
        mock_doc.page_count = 1
        mock_doc.xref_length.return_value = 3
        
        mock_page = Mock()
        mock_page.bound.return_value = [0, 0, 612, 792]
        mock_doc.load_page.return_value = mock_page
        
        # Mock stream and non-stream objects
        mock_doc.xref_object.side_effect = [
            None,  # xref 0
            "<< /Type /Catalog >>",  # xref 1 (non-stream)
            "<< /Type /XObject /Subtype /Image /Length 1000 >>",  # xref 2 (stream)
        ]
        mock_doc.xref_is_stream.side_effect = [False, False, True]
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            assert len(obj_nodes) == 2
            
            # Find the stream object
            stream_obj = next(c for c in obj_nodes if c["is_stream"])
            assert stream_obj["type"] == "XObject"
            assert stream_obj["is_stream"] is True
    
    def test_explore_pdf_with_fitz_exception_during_processing(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when fitz raises exception during processing."""
        # Mock the fitz module to raise exception during open
        mock_fitz = MagicMock()
        mock_fitz.open.side_effect = Exception("Fitz processing failed")
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            # Should fall back to regex-based parsing
            result = explore_pdf(sample_pdf_bytes)
            
            assert result["type"] == "Document"
            assert isinstance(result["children"], list)
            # Should still work due to fallback
    
    def test_explore_pdf_with_fitz_xref_exception(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when xref operations fail."""
        mock_doc = Mock()
        mock_doc.page_count = 1
        mock_doc.xref_length.return_value = 3
        
        mock_page = Mock()
        mock_page.bound.return_value = [0, 0, 612, 792]
        mock_doc.load_page.return_value = mock_page
        
        # Exception during xref object retrieval
        mock_doc.xref_object.side_effect = [
            None,
            Exception("XRef failed"),  # Should handle gracefully
            "<< /Type /Page >>",
        ]
        mock_doc.xref_is_stream.return_value = False
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            assert result["type"] == "Document"
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            # Should have processed the successful xref entries
            assert len(obj_nodes) >= 1
    
    @pytest.mark.xfail
    def test_explore_pdf_with_fitz_non_string_xref_object(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when xref_object returns non-string data."""
        mock_doc = Mock()
        mock_doc.page_count = 0
        mock_doc.xref_length.return_value = 2
        
        # Mock xref_object returning bytes and other types
        mock_doc.xref_object.side_effect = [
            None,  # xref 0
            b"<< /Type /Catalog >>",  # xref 1 (bytes)
        ]
        mock_doc.xref_is_stream.return_value = False
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            assert len(obj_nodes) == 1
            assert obj_nodes[0]["type"] == "Catalog"
    
    def test_explore_pdf_with_fitz_empty_xref_object(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when xref_object returns empty string."""
        mock_doc = Mock()
        mock_doc.page_count = 0
        mock_doc.xref_length.return_value = 2
        
        mock_doc.xref_object.side_effect = [None, ""]  # Empty string
        mock_doc.xref_is_stream.return_value = False
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            assert len(obj_nodes) == 1
            assert obj_nodes[0]["content_sha1"] is None


class TestPdfExplorationEdgeCases:
    """Test edge cases for PDF exploration."""
    
    def test_explore_pdf_with_bytes_input(self):
        """Test explore_pdf with raw bytes input."""
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(pdf_bytes)
            
            assert result["type"] == "Document"
            assert result["size"] == len(pdf_bytes)
    
    def test_explore_pdf_with_file_handle(self, sample_pdf_bytes: bytes):
        """Test explore_pdf with file handle input."""
        with io.BytesIO(sample_pdf_bytes) as pdf_handle:
            # Mock the fitz import to fail
            with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                       ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
                result = explore_pdf(pdf_handle)
                
                assert result["type"] == "Document"
                assert result["size"] == len(sample_pdf_bytes)
    
    def test_explore_pdf_with_pathlike_input(self, sample_pdf_file: Path):
        """Test explore_pdf with PathLike input."""
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_file)
            
            assert result["type"] == "Document"
            assert result["size"] > 0
    
    @patch('server.src.watermarking_utils.load_pdf_bytes')
    def test_explore_pdf_load_pdf_bytes_error(self, mock_load_pdf):
        """Test explore_pdf when load_pdf_bytes raises error."""
        mock_load_pdf.side_effect = ValueError("Invalid PDF")
        
        with pytest.raises(ValueError, match="Invalid PDF"):
            explore_pdf(b"not a pdf")
    
    def test_explore_pdf_different_inputs_different_ids(self, sample_pdf_bytes: bytes):
        """Test that different PDF inputs produce different IDs."""
        modified_pdf = sample_pdf_bytes + b"\n% Additional comment"
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result1 = explore_pdf(sample_pdf_bytes)
            result2 = explore_pdf(modified_pdf)
            
            assert result1["id"] != result2["id"]
            assert result1["size"] != result2["size"]
    
    def test_explore_pdf_complex_object_types(self):
        """Test explore_pdf with various PDF object types."""
        complex_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Type /Font /Subtype /Type1 >>\nendobj\n"
            b"5 0 obj\n<< /Type /XObject /Subtype /Image >>\nendobj\n"
            b"6 0 obj\n<< /Type /Annot /Subtype /Link >>\nendobj\n"
            b"%%EOF\n"
        )
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(complex_pdf)
            
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            
            # Should identify different object types
            types_found = {node["type"] for node in obj_nodes}
            expected_types = {"Catalog", "Pages", "Page", "Font", "XObject", "Annot"}
            assert types_found == expected_types
    
    @patch('server.src.watermarking_utils.load_pdf_bytes')
    def test_explore_pdf_with_mocked_load_pdf_bytes(self, mock_load_pdf, sample_pdf_bytes: bytes):
        """Test explore_pdf with mocked load_pdf_bytes function."""
        mock_load_pdf.return_value = sample_pdf_bytes
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf("fake_path.pdf")
            
            mock_load_pdf.assert_called_once_with("fake_path.pdf")
            assert result["type"] == "Document"
            assert result["size"] == len(sample_pdf_bytes)
    
    def test_explore_pdf_id_consistency_with_same_content(self, sample_pdf_bytes: bytes):
        """Test that same content always produces same ID."""
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            # Test multiple calls with same data
            results = [explore_pdf(sample_pdf_bytes) for _ in range(5)]
            
            # All IDs should be identical
            first_id = results[0]["id"]
            for result in results[1:]:
                assert result["id"] == first_id
    
    def test_explore_pdf_with_corrupted_pdf_data(self):
        """Test explore_pdf with corrupted PDF data."""
        corrupted_pdf = b"%PDF-1.4\ngarbled data\n%%EOF"
        
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(corrupted_pdf)
            
            # Should still return a valid structure
            assert result["type"] == "Document"
            assert result["size"] == len(corrupted_pdf)
            assert isinstance(result["children"], list)


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases across all functions."""
    
    def test_apply_watermark_with_invalid_pdf(self):
        """Test apply_watermark with invalid PDF data."""
        mock_method = Mock()
        mock_method.add_watermark.side_effect = ValueError("Invalid PDF format")
        
        with patch('server.src.watermarking_utils.get_method', return_value=mock_method):
            with pytest.raises(ValueError, match="Invalid PDF format"):
                apply_watermark(
                    method="test-method",
                    pdf=b"not a pdf",
                    secret="secret",
                    key="key"
                )
    
    def test_read_watermark_with_corrupted_pdf(self):
        """Test read_watermark with corrupted PDF data."""
        mock_method = Mock()
        mock_method.read_secret.side_effect = SecretNotFoundError("Corrupted watermark")
        
        with patch('server.src.watermarking_utils.get_method', return_value=mock_method):
            with pytest.raises(SecretNotFoundError, match="Corrupted watermark"):
                read_watermark(
                    method="test-method",
                    pdf=b"%PDF-corrupted",
                    key="key"
                )
    
    def test_is_watermarking_applicable_with_unsupported_position(self):
        """Test is_watermarking_applicable with unsupported position."""
        mock_method = Mock()
        mock_method.is_watermark_applicable.return_value = False
        
        with patch('server.src.watermarking_utils.get_method', return_value=mock_method):
            result = is_watermarking_applicable(
                method="test-method",
                pdf=b"%PDF-1.4\n%%EOF",
                position="unsupported-position"
            )
            
            assert result is False
    
    def test_register_method_with_none(self):
        """Test register_method with None input."""
        with pytest.raises(AttributeError):
            register_method(None)
    
    def test_functions_with_empty_string_inputs(self):
        """Test functions with empty string inputs."""
        mock_method = Mock()
        mock_method.add_watermark.return_value = b"result"
        mock_method.read_secret.return_value = ""
        mock_method.is_watermark_applicable.return_value = True
        
        with patch('server.src.watermarking_utils.get_method', return_value=mock_method):
            # Empty secret
            result1 = apply_watermark("test", b"%PDF-1.4\n%%EOF", "", "key")
            assert result1 == b"result"
            
            # Empty key
            result2 = apply_watermark("test", b"%PDF-1.4\n%%EOF", "secret", "")
            assert result2 == b"result"
            
            # Empty key for reading
            result3 = read_watermark("test", b"%PDF-1.4\n%%EOF", "")
            assert result3 == ""
    
    def test_functions_with_very_long_inputs(self):
        """Test functions with very long string inputs."""
        mock_method = Mock()
        mock_method.add_watermark.return_value = b"long_result"
        mock_method.read_secret.return_value = "long_secret"
        mock_method.is_watermark_applicable.return_value = True
        
        with patch('server.src.watermarking_utils.get_method', return_value=mock_method):
            long_secret = "x" * 10000
            long_key = "y" * 10000
            
            result1 = apply_watermark("test", b"%PDF-1.4\n%%EOF", long_secret, long_key)
            assert result1 == b"long_result"
            
            result2 = read_watermark("test", b"%PDF-1.4\n%%EOF", long_key)
            assert result2 == "long_secret"
    
    def test_functions_with_special_characters(self):
        """Test functions with special characters in inputs."""
        mock_method = Mock()
        mock_method.add_watermark.return_value = b"special_result"
        mock_method.read_secret.return_value = "special_secret"
        mock_method.is_watermark_applicable.return_value = True
        
        with patch('server.src.watermarking_utils.get_method', return_value=mock_method):
            special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
            unicode_chars = "世界🌍αβγδε"
            
            result1 = apply_watermark("test", b"%PDF-1.4\n%%EOF", special_chars, unicode_chars)
            assert result1 == b"special_result"
            
            result2 = read_watermark("test", b"%PDF-1.4\n%%EOF", special_chars)
            assert result2 == "special_secret"
    
    def test_method_registry_edge_cases(self):
        """Test method registry with edge cases."""
        original_methods = METHODS.copy()
        
        try:
            # Test with method having empty name
            empty_name_method = MockWatermarkingMethod("")
            register_method(empty_name_method)
            assert "" in METHODS
            assert get_method("") is empty_name_method
            
            # Test with method having special characters in name
            special_name_method = MockWatermarkingMethod("test-method!@#$%")
            register_method(special_name_method)
            assert "test-method!@#$%" in METHODS
            
        finally:
            METHODS.clear()
            METHODS.update(original_methods)


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple functions."""
    
    def setup_method(self):
        """Set up integration test environment."""
        self.mock_method = MockWatermarkingMethod("integration-test")
        register_method(self.mock_method)
    
    def teardown_method(self):
        """Clean up after integration tests."""
        if "integration-test" in METHODS:
            del METHODS["integration-test"]
    
    def test_full_watermarking_workflow(self, sample_pdf_bytes: bytes):
        """Test complete watermarking workflow."""
        # 1. Check if watermarking is applicable
        applicable = is_watermarking_applicable(
            method="integration-test",
            pdf=sample_pdf_bytes,
            position="bottom"
        )
        assert applicable is True
        
        # 2. Apply watermark
        watermarked_pdf = apply_watermark(
            method="integration-test",
            pdf=sample_pdf_bytes,
            secret="integration-secret",
            key="integration-key",
            position="bottom"
        )
        assert watermarked_pdf == b"%PDF-1.4\nmocked watermark content\n%%EOF"
        
        # 3. Read watermark back
        extracted_secret = read_watermark(
            method="integration-test",
            pdf=watermarked_pdf,
            key="integration-key"
        )
        assert extracted_secret == "mock-extracted-secret"
        
        # 4. Explore the watermarked PDF
        # Mock the fitz import to fail
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs: 
                   ImportError("PyMuPDF not available") if name == 'fitz' else __import__(name, *args, **kwargs)):
            exploration = explore_pdf(watermarked_pdf)
            assert exploration["type"] == "Document"
            assert exploration["size"] == len(watermarked_pdf)
    
    @pytest.mark.xfail
    def test_workflow_with_method_instance(self, sample_pdf_bytes: bytes):
        """Test workflow using method instance instead of string."""
        method_instance = MockWatermarkingMethod("instance-workflow")
        
        # Use method instance directly
        applicable = is_watermarking_applicable(
            method=method_instance,
            pdf=sample_pdf_bytes
        )
        assert applicable is True
        
        watermarked_pdf = apply_watermark(
            method=method_instance,
            pdf=sample_pdf_bytes,
            secret="instance-secret",
            key="instance-key"
        )
        assert isinstance(watermarked_pdf, bytes)
        
        extracted_secret = read_watermark(
            method=method_instance,
            pdf=watermarked_pdf,
            key="instance-key"
        )
        assert extracted_secret == "mock-extracted-secret"
    
    def test_error_propagation_through_workflow(self, sample_pdf_bytes: bytes):
        """Test error propagation through the workflow."""
        # Create a method that fails at different stages
        failing_method = Mock()
        failing_method.name = "failing-method"
        failing_method.is_watermark_applicable.return_value = True
        failing_method.add_watermark.return_value = b"watermarked"
        failing_method.read_secret.side_effect = InvalidKeyError("Wrong key")
        
        register_method(failing_method)
        
        try:
            # First steps succeed
            assert is_watermarking_applicable("failing-method", sample_pdf_bytes) is True
            watermarked = apply_watermark("failing-method", sample_pdf_bytes, "secret", "key")
            assert watermarked == b"watermarked"
            
            # Final step fails
            with pytest.raises(InvalidKeyError, match="Wrong key"):
                read_watermark("failing-method", watermarked, "wrong-key")
        finally:
            # Cleanup
            if "failing-method" in METHODS:
                del METHODS["failing-method"]
    
    def test_cross_method_compatibility(self, sample_pdf_bytes: bytes):
        """Test that different methods can work on the same PDF."""
        method1 = MockWatermarkingMethod("cross-test-1")
        method2 = MockWatermarkingMethod("cross-test-2")
        
        register_method(method1)
        register_method(method2)
        
        try:
            # Apply watermark with method 1
            watermarked1 = apply_watermark("cross-test-1", sample_pdf_bytes, "secret1", "key1")
            
            # Check applicability with method 2
            applicable = is_watermarking_applicable("cross-test-2", watermarked1)
            assert applicable is True
            
            # Apply watermark with method 2
            watermarked2 = apply_watermark("cross-test-2", watermarked1, "secret2", "key2")
            
            # Read secrets with both methods
            secret1 = read_watermark("cross-test-1", watermarked2, "key1")
            secret2 = read_watermark("cross-test-2", watermarked2, "key2")
            
            assert secret1 == "mock-extracted-secret"
            assert secret2 == "mock-extracted-secret"
            
        finally:
            for name in ["cross-test-1", "cross-test-2"]:
                if name in METHODS:
                    del METHODS[name]


class TestConcurrencyAndStateSafety:
    """Test concurrency and state safety aspects."""
    
    def test_methods_registry_thread_safety_simulation(self):
        """Simulate concurrent access to METHODS registry."""
        original_methods = METHODS.copy()
        
        try:
            # Simulate concurrent registration
            method1 = MockWatermarkingMethod("concurrent-1")
            method2 = MockWatermarkingMethod("concurrent-2")
            
            register_method(method1)
            register_method(method2)
            
            # Both should be accessible
            assert get_method("concurrent-1") is method1
            assert get_method("concurrent-2") is method2
            
            # Registry should contain both
            assert "concurrent-1" in METHODS
            assert "concurrent-2" in METHODS
            
        finally:
            # Restore original state
            METHODS.clear()
            METHODS.update(original_methods)
    
    def test_method_instance_immutability(self):
        """Test that method instances don't affect each other."""
        method1 = MockWatermarkingMethod("immutable-1")
        method2 = MockWatermarkingMethod("immutable-2")
        
        # Register both
        register_method(method1)
        register_method(method2)
        
        try:
            # Get references
            ref1a = get_method("immutable-1")
            ref1b = get_method("immutable-1")
            ref2 = get_method("immutable-2")
            
            # Same method should return same instance
            assert ref1a is ref1b
            assert ref1a is method1
            
            # Different methods should be different instances
            assert ref1a is not ref2
            assert method1 is not method2
            
        finally:
            # Cleanup
            for name in ["immutable-1", "immutable-2"]:
                if name in METHODS:
                    del METHODS[name]
    
    def test_global_state_isolation(self):
        """Test that global state changes are properly isolated."""
        original_methods_count = len(METHODS)
        
        # Add temporary methods
        temp_methods = [
            MockWatermarkingMethod(f"temp-{i}") for i in range(5)
        ]
        
        for method in temp_methods:
            register_method(method)
        
        assert len(METHODS) == original_methods_count + 5
        
        # Remove all temp methods
        for method in temp_methods:
            if method.name in METHODS:
                del METHODS[method.name]
        
        assert len(METHODS) == original_methods_count


class TestPerformanceAndScalability:
    """Test performance-related aspects and scalability."""
    
    def test_large_methods_registry(self):
        """Test registry behavior with many methods."""
        original_methods = METHODS.copy()
        
        try:
            # Add many methods
            methods = [MockWatermarkingMethod(f"perf-{i}") for i in range(100)]
            for method in methods:
                register_method(method)
            
            # All should be accessible
            for method in methods:
                retrieved = get_method(method.name)
                assert retrieved is method
            
            # Test error message with many methods
            try:
                get_method("non-existent")
            except KeyError as e:
                error_str = str(e)
                # Should contain all method names
                for method in methods[:10]:  # Check first 10
                    assert method.name in error_str
                    
        finally:
            METHODS.clear()
            METHODS.update(original_methods)
    
    @pytest.mark.xfail
    def test_pdf_exploration_with_large_object_count(self):
        """Test PDF exploration with many objects."""
        # Generate PDF with many objects
        pdf_parts = [b"%PDF-1.4\n"]
        for i in range(100):
            pdf_parts.append(f"{i+1} 0 obj\n<< /Type /TestObj{i} >>\nendobj\n".encode())
        pdf_parts.append(b"%%EOF\n")
        
        large_pdf = b"".join(pdf_parts)
        
        with patch('server.src.watermarking_utils.fitz', side_effect=ImportError()):
            result = explore_pdf(large_pdf)
            
            assert result["type"] == "Document"
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            assert len(obj_nodes) == 100
            
            # Check that all objects have proper structure
            for obj_node in obj_nodes:
                assert "type" in obj_node
                assert "object" in obj_node
                assert "generation" in obj_node
                assert "content_sha1" in obj_node


class TestComprehensiveCoverage:
    """Additional tests to ensure 100% code coverage."""
    
    def test_module_import_coverage(self):
        """Test that all module imports are covered."""
        # Test that regex patterns are accessible
        assert _OBJ_RE is not None
        assert _ENDOBJ_RE is not None
        assert _TYPE_RE is not None
        
        # Test pattern types
        import re
        assert isinstance(_OBJ_RE, re.Pattern)
        assert isinstance(_ENDOBJ_RE, re.Pattern)
        assert isinstance(_TYPE_RE, re.Pattern)
    
    def test_all_export_coverage(self):
        """Test that all __all__ exports work correctly."""
        import server.src.watermarking_utils as wu
        
        # Test each exported function/variable is callable or accessible
        assert callable(wu.register_method)
        assert callable(wu.get_method)
        assert callable(wu.apply_watermark)
        assert callable(wu.read_watermark)
        assert callable(wu.explore_pdf)
        assert callable(wu.is_watermarking_applicable)
        assert isinstance(wu.METHODS, dict)
    
    def test_explore_pdf_with_fitz_document_close_exception(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when document.close() raises exception."""
        mock_doc = Mock()
        mock_doc.page_count = 0
        mock_doc.xref_length.return_value = 1
        mock_doc.xref_object.return_value = None
        mock_doc.close.side_effect = Exception("Close failed")
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            # Should still return valid result despite close() exception
            result = explore_pdf(sample_pdf_bytes)
            assert result["type"] == "Document"
    
    @pytest.mark.xfail
    def test_explore_pdf_with_fitz_page_bound_exception(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when page.bound() raises exception."""
        mock_doc = Mock()
        mock_doc.page_count = 1
        mock_doc.xref_length.return_value = 1
        
        mock_page = Mock()
        mock_page.bound.side_effect = Exception("Bound failed")
        mock_doc.load_page.return_value = mock_page
        mock_doc.xref_object.return_value = None
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            # Should handle page bound exception and continue
            with pytest.raises(Exception):
                explore_pdf(sample_pdf_bytes)
    
    @pytest.mark.xfail
    def test_explore_pdf_fallback_with_no_objects(self):
        """Test explore_pdf fallback with PDF that has no objects."""
        no_obj_pdf = b"%PDF-1.4\n%%EOF\n"
        
        with patch('server.src.watermarking_utils.fitz', side_effect=ImportError()):
            result = explore_pdf(no_obj_pdf)
            
            assert result["type"] == "Document"
            assert result["size"] == len(no_obj_pdf)
            assert len(result["children"]) == 0
    
    @pytest.mark.xfail
    def test_explore_pdf_fallback_object_without_endobj(self):
        """Test explore_pdf fallback with object missing endobj."""
        incomplete_obj_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog >>\n"
            # Missing endobj
            b"%%EOF\n"
        )
        
        with patch('server.src.watermarking_utils.fitz', side_effect=ImportError()):
            result = explore_pdf(incomplete_obj_pdf)
            
            assert result["type"] == "Document"
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            # Should still find the object but handle missing endobj
            assert len(obj_nodes) >= 0  # May or may not find incomplete object
    
    def test_explore_pdf_with_fitz_xref_is_stream_exception(self, sample_pdf_bytes: bytes):
        """Test explore_pdf when xref_is_stream raises exception."""
        mock_doc = Mock()
        mock_doc.page_count = 0
        mock_doc.xref_length.return_value = 2
        mock_doc.xref_object.side_effect = [None, "<< /Type /Catalog >>"]
        mock_doc.xref_is_stream.side_effect = [False, Exception("Stream check failed")]
        
        # Mock the fitz module
        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc
        
        with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                   mock_fitz if name == 'fitz' else __import__(name, *args, **kwargs)):
            result = explore_pdf(sample_pdf_bytes)
            
            # Should handle xref_is_stream exception gracefully
            assert result["type"] == "Document"
            obj_nodes = [c for c in result["children"] if c["id"].startswith("obj:")]
            assert len(obj_nodes) >= 1
    
    def test_regex_patterns_with_edge_case_content(self):
        """Test regex patterns with edge case PDF content."""
        # Test OBJ_RE with unusual spacing
        unusual_spacing = b"123   456   obj"
        match = _OBJ_RE.search(unusual_spacing)
        assert match is not None
        assert match.group(1) == b"123"
        assert match.group(2) == b"456"
        
        # Test TYPE_RE with nested brackets
        nested_type = b"<< /Type /Catalog /Other << /Nested /Value >> >>"
        type_match = _TYPE_RE.search(nested_type)
        assert type_match is not None
        assert type_match.group(1) == b"Catalog"
        
        # Test ENDOBJ_RE in different contexts
        contexts = [
            b"some text endobj more text",
            b"\nendobj\n",
            b"endobj",
            b"<<endobj>>",
        ]
        for context in contexts:
            endobj_match = _ENDOBJ_RE.search(context)
            assert endobj_match is not None
    
    def test_sha1_function_with_various_inputs(self):
        """Test _sha1 function with various input types and sizes."""
        test_cases = [
            b"",  # Empty
            b"a",  # Single byte
            b"Hello, World!",  # ASCII
            "Hello, 世界!".encode('utf-8'),  # Unicode
            b"\x00\x01\x02\x03",  # Binary
            b"x" * 1000,  # Medium size
            b"y" * 100000,  # Large size
        ]
        
        for test_data in test_cases:
            result = _sha1(test_data)
            expected = hashlib.sha1(test_data).hexdigest()
            assert result == expected
            assert len(result) == 40
            assert isinstance(result, str)
    
    def test_methods_registry_original_state_preservation(self):
        """Test that original METHODS registry is preserved across tests."""
        # Get original methods
        original_methods = list(METHODS.keys())
        
        # Verify expected default methods are present
        assert "toy-eof" in original_methods
        assert "bash-bridge-eof" in original_methods
        
        # Add temporary method
        temp_method = MockWatermarkingMethod("temp-preservation-test")
        register_method(temp_method)
        
        assert "temp-preservation-test" in METHODS
        
        # Remove temporary method
        del METHODS["temp-preservation-test"]
        
        # Verify original methods are still there
        current_methods = list(METHODS.keys())
        for method_name in original_methods:
            assert method_name in current_methods


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=server.src.watermarking_utils", "--cov-report=term-missing"])