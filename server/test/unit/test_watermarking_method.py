"""Unit tests for watermarking_method.py module."""

import os
import tempfile
from pathlib import Path
from typing import IO

import pytest

from server.src.watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    is_pdf_bytes,
    load_pdf_bytes,
)


class TestPdfSourceHelpers:
    """Test helper functions for PDF source handling."""
    
    def test_is_pdf_bytes_valid(self):
        """Test is_pdf_bytes with valid PDF data."""
        valid_pdf = b"%PDF-1.4\nsome content"
        assert is_pdf_bytes(valid_pdf) is True
    
    def test_is_pdf_bytes_invalid(self):
        """Test is_pdf_bytes with invalid PDF data."""
        invalid_data = b"not a pdf"
        assert is_pdf_bytes(invalid_data) is False
    
    def test_is_pdf_bytes_empty(self):
        """Test is_pdf_bytes with empty data."""
        empty_data = b""
        assert is_pdf_bytes(empty_data) is False
    
    def test_load_pdf_bytes_from_bytes(self, sample_pdf_bytes: bytes):
        """Test loading PDF from bytes."""
        result = load_pdf_bytes(sample_pdf_bytes)
        assert result == sample_pdf_bytes
        assert isinstance(result, bytes)
    
    def test_load_pdf_bytes_from_bytearray(self, sample_pdf_bytes: bytes):
        """Test loading PDF from bytearray."""
        pdf_bytearray = bytearray(sample_pdf_bytes)
        result = load_pdf_bytes(pdf_bytearray)
        assert result == sample_pdf_bytes
        assert isinstance(result, bytes)
    
    def test_load_pdf_bytes_from_file_path(self, sample_pdf_file: Path):
        """Test loading PDF from file path."""
        result = load_pdf_bytes(str(sample_pdf_file))
        assert result.startswith(b"%PDF-")
        assert isinstance(result, bytes)
    
    def test_load_pdf_bytes_from_pathlike(self, sample_pdf_file: Path):
        """Test loading PDF from PathLike object."""
        result = load_pdf_bytes(sample_pdf_file)
        assert result.startswith(b"%PDF-")
        assert isinstance(result, bytes)
    
    def test_load_pdf_bytes_from_file_handle(self, sample_pdf_file: Path):
        """Test loading PDF from file handle."""
        with open(sample_pdf_file, "rb") as f:
            result = load_pdf_bytes(f)
        assert result.startswith(b"%PDF-")
        assert isinstance(result, bytes)
    
    def test_load_pdf_bytes_file_not_found(self):
        """Test loading PDF from non-existent file."""
        with pytest.raises(FileNotFoundError):
            load_pdf_bytes("nonexistent.pdf")
    
    def test_load_pdf_bytes_invalid_pdf(self):
        """Test loading invalid PDF data."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"not a pdf")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Input does not look like a valid PDF"):
                load_pdf_bytes(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_load_pdf_bytes_unsupported_type(self):
        """Test loading PDF from unsupported type."""
        with pytest.raises(TypeError, match="Unsupported PdfSource"):
            load_pdf_bytes(123)  # type: ignore


class TestWatermarkingErrors:
    """Test watermarking exception classes."""
    
    def test_watermarking_error_inheritance(self):
        """Test WatermarkingError is an Exception."""
        error = WatermarkingError("test")
        assert isinstance(error, Exception)
    
    def test_secret_not_found_error_inheritance(self):
        """Test SecretNotFoundError inherits from WatermarkingError."""
        error = SecretNotFoundError("test")
        assert isinstance(error, WatermarkingError)
        assert isinstance(error, Exception)
    
    def test_invalid_key_error_inheritance(self):
        """Test InvalidKeyError inherits from WatermarkingError."""
        error = InvalidKeyError("test")
        assert isinstance(error, WatermarkingError)
        assert isinstance(error, Exception)


class MockWatermarkingMethod(WatermarkingMethod):
    """Mock implementation for testing abstract base class."""
    
    name = "mock-method"
    
    @staticmethod
    def get_usage() -> str:
        return "Mock method for testing"
    
    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        return data + b"\n%%MOCK-WATERMARK:" + secret.encode() + b"\n"
    
    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        return True
    
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if b"%%MOCK-WATERMARK:" not in data:
            raise SecretNotFoundError("No mock watermark found")
        
        # Extract secret between markers
        start = data.find(b"%%MOCK-WATERMARK:") + len(b"%%MOCK-WATERMARK:")
        end = data.find(b"\n", start)
        if end == -1:
            end = len(data)
        
        return data[start:end].decode()


class TestWatermarkingMethod:
    """Test abstract WatermarkingMethod class."""
    
    def test_abstract_method_cannot_be_instantiated(self):
        """Test that abstract WatermarkingMethod cannot be instantiated."""
        with pytest.raises(TypeError):
            WatermarkingMethod()  # type: ignore
    
    def test_abstract_get_usage_raises_not_implemented(self):
        """Test that abstract get_usage() raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            WatermarkingMethod.get_usage()
    
    def test_abstract_add_watermark_raises_not_implemented(self, sample_pdf_file: Path):
        """Test that abstract add_watermark() raises NotImplementedError."""
        # Test the abstract method directly by calling super()
        class TestMethod(WatermarkingMethod):
            name = "test"
            
            @staticmethod
            def get_usage() -> str:
                return "test"
            
            def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
                return True
                
            def read_secret(self, pdf: PdfSource, key: str) -> str:
                return "test"
            
            def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
                # Call the abstract method to trigger NotImplementedError
                return super().add_watermark(pdf, secret, key, position)
        
        method = TestMethod()
        with pytest.raises(NotImplementedError):
            method.add_watermark(sample_pdf_file, "secret", "key")
    
    def test_abstract_is_watermark_applicable_raises_not_implemented(self, sample_pdf_file: Path):
        """Test that abstract is_watermark_applicable() raises NotImplementedError."""
        # Test the abstract method directly by calling super()
        class TestMethod(WatermarkingMethod):
            name = "test"
            
            @staticmethod
            def get_usage() -> str:
                return "test"
            
            def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
                return b"test"
                
            def read_secret(self, pdf: PdfSource, key: str) -> str:
                return "test"
            
            def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
                # Call the abstract method to trigger NotImplementedError
                return super().is_watermark_applicable(pdf, position)
        
        method = TestMethod()
        with pytest.raises(NotImplementedError):
            method.is_watermark_applicable(sample_pdf_file)
    
    def test_abstract_read_secret_raises_not_implemented(self, sample_pdf_file: Path):
        """Test that abstract read_secret() raises NotImplementedError."""
        # Test the abstract method directly by calling super()
        class TestMethod(WatermarkingMethod):
            name = "test"
            
            @staticmethod
            def get_usage() -> str:
                return "test"
            
            def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
                return b"test"
                
            def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
                return True
            
            def read_secret(self, pdf: PdfSource, key: str) -> str:
                # Call the abstract method to trigger NotImplementedError
                return super().read_secret(pdf, key)
        
        method = TestMethod()
        with pytest.raises(NotImplementedError):
            method.read_secret(sample_pdf_file, "key")
    
    def test_mock_implementation(self, sample_pdf_file: Path):
        """Test mock implementation works correctly."""
        method = MockWatermarkingMethod()
        secret = "test-secret"
        key = "test-key"
        
        # Test add_watermark
        watermarked = method.add_watermark(sample_pdf_file, secret, key)
        assert isinstance(watermarked, bytes)
        assert b"%%MOCK-WATERMARK:" in watermarked
        
        # Test is_watermark_applicable
        assert method.is_watermark_applicable(sample_pdf_file) is True
        
        # Test read_secret roundtrip
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(watermarked)
            temp_path = f.name
        
        try:
            extracted_secret = method.read_secret(temp_path, key)
            assert extracted_secret == secret
        finally:
            os.unlink(temp_path)
    
    def test_mock_read_secret_not_found(self, sample_pdf_file: Path):
        """Test read_secret raises SecretNotFoundError when no watermark present."""
        method = MockWatermarkingMethod()
        
        with pytest.raises(SecretNotFoundError, match="No mock watermark found"):
            method.read_secret(sample_pdf_file, "any-key")
    
    def test_get_usage(self):
        """Test get_usage returns string."""
        method = MockWatermarkingMethod()
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert len(usage) > 0
