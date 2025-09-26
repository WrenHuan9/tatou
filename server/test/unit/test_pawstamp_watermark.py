import hashlib
import io
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from PawStamp_watermark import TinyTextWatermark
from watermarking_method import load_pdf_bytes, WatermarkingError, SecretNotFoundError


class TestTinyTextWatermark:
    
    def test_class_attributes(self):
        method = TinyTextWatermark()
        assert method.name == "PawStamp Secure"
        assert hasattr(method, '_get_secure_secret')
    
    def test_get_usage(self):
        method = TinyTextWatermark()
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert "secret" in usage.lower()
        assert "tiny" in usage.lower() or "invisible" in usage.lower()
        assert "base64" in usage.lower()
    
    def test_get_secure_secret_basic(self):
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        result = method._get_secure_secret(secret, key)
        
        assert isinstance(result, str)
        assert len(result) == 16
        
        result2 = method._get_secure_secret(secret, key)
        assert result == result2
    
    def test_get_secure_secret_different_inputs(self):
        method = TinyTextWatermark()
        
        result1 = method._get_secure_secret("secret1", "key1")
        result2 = method._get_secure_secret("secret2", "key1")
        result3 = method._get_secure_secret("secret1", "key2")
        
        assert result1 != result2
        assert result1 != result3
        assert result2 != result3
    
    def test_get_secure_secret_hash_computation(self):
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        result = method._get_secure_secret(secret, key)
        
        expected_input = secret + key
        expected_hash = hashlib.sha1(expected_input.encode()).hexdigest()[:16]
        assert result == expected_hash
    
    def test_get_secure_secret_unicode(self):
        method = TinyTextWatermark()
        secret = "测试秘密"
        key = "测试密钥"
        
        result = method._get_secure_secret(secret, key)
        
        assert isinstance(result, str)
        assert len(result) == 16
    
    def test_get_secure_secret_empty_strings(self):
        method = TinyTextWatermark()
        
        result1 = method._get_secure_secret("", "")
        result2 = method._get_secure_secret("", "key")
        result3 = method._get_secure_secret("secret", "")
        
        assert isinstance(result1, str)
        assert isinstance(result2, str)
        assert isinstance(result3, str)
        assert len(result1) == len(result2) == len(result3) == 16
    
    def test_is_watermark_applicable_valid_pdf(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        result = method.is_watermark_applicable(sample_pdf_bytes)
        
        assert result is True
    
    def test_is_watermark_applicable_with_file_path(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
            tmp_file.write(sample_pdf_bytes)
            tmp_file.flush()
            
            result = method.is_watermark_applicable(tmp_file.name)
            
            assert result is True
            
            Path(tmp_file.name).unlink()
    
    def test_is_watermark_applicable_invalid_input(self):
        method = TinyTextWatermark()
        
        assert method.is_watermark_applicable(b"not a pdf") is False
        assert method.is_watermark_applicable(b"") is False
        assert method.is_watermark_applicable(b"random bytes") is False
    
    def test_is_watermark_applicable_load_pdf_bytes_exception(self):
        method = TinyTextWatermark()
        
        assert method.is_watermark_applicable("nonexistent_file.pdf") is False
    
    def test_is_watermark_applicable_with_kwargs(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        result = method.is_watermark_applicable(
            sample_pdf_bytes,
            position="bottom-right",
            extra_param="ignored"
        )
        
        assert result is True
    
    @patch('fitz.open')
    def test_add_watermark_basic(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.tobytes.return_value = b"%PDF-watermarked content"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        mock_fitz_open.assert_called_once()
        mock_page.insert_textbox.assert_called_once()
        
        args, kwargs = mock_page.insert_textbox.call_args
        textbox_rect, watermark_text = args[:2]
        
        # 现在期望Base64编码的秘密
        import base64
        expected_encoded_secret = base64.b64encode(secret.encode('utf-8')).decode('ascii')
        expected_text = f"TATOU_SECRET_START_{expected_encoded_secret}_END"
        assert watermark_text == expected_text
        
        assert kwargs['fontsize'] == 1
        assert kwargs['color'] == (0.9, 0.9, 0.9)
        assert kwargs['fontname'] == "helv"
    
    @patch('fitz.open')
    def test_add_watermark_with_position_parameter(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.tobytes.return_value = b"%PDF-watermarked content"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        result = method.add_watermark(sample_pdf_bytes, "secret", "key", position="top-left")
        
        assert isinstance(result, bytes)
        mock_page.insert_textbox.assert_called_once()
    
    @patch('fitz.open')
    def test_add_watermark_with_kwargs(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.tobytes.return_value = b"%PDF-watermarked content"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        result = method.add_watermark(
            sample_pdf_bytes, 
            "secret", 
            "key",
            position="center",
            extra_param="ignored"
        )
        
        assert isinstance(result, bytes)
        mock_page.insert_textbox.assert_called_once()
    
    @patch('fitz.open')
    def test_add_watermark_multiple_pages(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        
        mock_page1 = MagicMock()
        mock_page1.rect.width = 612
        mock_page1.rect.height = 792
        
        mock_page2 = MagicMock()
        mock_page2.rect.width = 612
        mock_page2.rect.height = 792
        
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page1, mock_page2]))
        mock_doc.tobytes.return_value = b"%PDF-multi-page watermarked"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        result = method.add_watermark(sample_pdf_bytes, "secret", "key")
        
        assert isinstance(result, bytes)
        mock_page1.insert_textbox.assert_called_once()
        mock_page2.insert_textbox.assert_called_once()
    
    @patch('fitz.open')
    def test_add_watermark_unicode_secret(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.tobytes.return_value = b"%PDF-unicode watermarked"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        secret = "测试秘密 🔒"
        key = "测试密钥"
        
        result = method.add_watermark(sample_pdf_bytes, secret, key)
        
        assert isinstance(result, bytes)
        mock_page.insert_textbox.assert_called_once()
        
        args, kwargs = mock_page.insert_textbox.call_args
        watermark_text = args[1]
        
        # 现在期望Base64编码的Unicode秘密
        import base64
        expected_encoded_secret = base64.b64encode(secret.encode('utf-8')).decode('ascii')
        expected_text = f"TATOU_SECRET_START_{expected_encoded_secret}_END"
        assert watermark_text == expected_text
    
    @patch('fitz.open')
    def test_add_watermark_with_file_path(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.tobytes.return_value = b"%PDF-watermarked content"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
            tmp_file.write(sample_pdf_bytes)
            tmp_file.flush()
            
            result = method.add_watermark(tmp_file.name, "secret", "key")
            
            assert isinstance(result, bytes)
            mock_page.insert_textbox.assert_called_once()
            
            Path(tmp_file.name).unlink()
    
    @patch('fitz.open')
    def test_add_watermark_with_file_object(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_doc.tobytes.return_value = b"%PDF-watermarked content"
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        pdf_file_obj = io.BytesIO(sample_pdf_bytes)
        
        result = method.add_watermark(pdf_file_obj, "secret", "key")
        
        assert result == b"%PDF-watermarked content"
    
    def test_add_watermark_load_pdf_bytes_exception(self):
        method = TinyTextWatermark()
        
        with patch('PawStamp_watermark.load_pdf_bytes', side_effect=ValueError("Invalid PDF")):
            with pytest.raises(ValueError, match="Invalid PDF"):
                method.add_watermark("invalid", "secret", "key")
    
    @patch('fitz.open')
    def test_add_watermark_fitz_exception(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_fitz_open.side_effect = Exception("Fitz error")
        method = TinyTextWatermark()
        
        with pytest.raises(Exception, match="Fitz error"):
            method.add_watermark(sample_pdf_bytes, "secret", "key")
    
    @patch('fitz.open')
    def test_read_secret_basic_found(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        # 现在使用Base64编码的秘密
        import base64
        encoded_secret = base64.b64encode(secret.encode('utf-8')).decode('ascii')
        watermark_text = f"Some content TATOU_SECRET_START_{encoded_secret}_END more content"
        mock_page.get_text.return_value = watermark_text
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        result = method.read_secret(sample_pdf_bytes, key)
        
        assert result == secret
    
    @patch('fitz.open')
    def test_read_secret_multiple_pages_found_on_second(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        
        mock_page1 = MagicMock()
        mock_page1.get_text.return_value = "No watermark here"
        
        mock_page2 = MagicMock()
        method = TinyTextWatermark()
        secret = "page2-secret"
        key = "page2-key"
        
        # 现在使用Base64编码的秘密
        import base64
        encoded_secret = base64.b64encode(secret.encode('utf-8')).decode('ascii')
        watermark_text = f"Content TATOU_SECRET_START_{encoded_secret}_END"
        mock_page2.get_text.return_value = watermark_text
        
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page1, mock_page2]))
        mock_fitz_open.return_value = mock_doc
        
        result = method.read_secret(sample_pdf_bytes, key)
        
        assert result == secret
    
    @patch('fitz.open')
    def test_read_secret_not_found(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.return_value = "No watermark in this content"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="No secret found with the PawStamp Secure method"):
            method.read_secret(sample_pdf_bytes, "any-key")
    
    @patch('fitz.open')
    def test_read_secret_start_tag_found_but_no_end_tag(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.return_value = "Content TATOU_SECRET_START_somehash but no end tag"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="No secret found with the PawStamp Secure method"):
            method.read_secret(sample_pdf_bytes, "key")
    
    @patch('fitz.open')
    def test_read_secret_empty_secret_between_tags(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        # 空字符串的Base64编码
        import base64
        empty_encoded = base64.b64encode("".encode('utf-8')).decode('ascii')
        mock_page.get_text.return_value = f"Content TATOU_SECRET_START_{empty_encoded}_END more content"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        result = method.read_secret(sample_pdf_bytes, "key")
        
        assert result == ""
    
    @patch('fitz.open')
    def test_read_secret_multiple_watermarks_returns_first(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        
        # 使用Base64编码的多个水印
        import base64
        first_encoded = base64.b64encode("first".encode('utf-8')).decode('ascii')
        second_encoded = base64.b64encode("second".encode('utf-8')).decode('ascii')
        content = f"TATOU_SECRET_START_{first_encoded}_END and TATOU_SECRET_START_{second_encoded}_END"
        mock_page.get_text.return_value = content
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        result = method.read_secret(sample_pdf_bytes, "key")
        
        assert result == "first"
    
    @patch('fitz.open')
    def test_read_secret_with_file_path(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        # 使用Base64编码
        import base64
        encoded_secret = base64.b64encode("testsecret".encode('utf-8')).decode('ascii')
        mock_page.get_text.return_value = f"TATOU_SECRET_START_{encoded_secret}_END"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
            tmp_file.write(sample_pdf_bytes)
            tmp_file.flush()
            
            result = method.read_secret(tmp_file.name, "any-key")
            
            assert result == "testsecret"
            
            Path(tmp_file.name).unlink()
    
    @patch('fitz.open')
    def test_read_secret_with_file_object(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_doc = MagicMock()
        mock_page = MagicMock()
        # 使用Base64编码
        import base64
        encoded_secret = base64.b64encode("testsecret".encode('utf-8')).decode('ascii')
        mock_page.get_text.return_value = f"TATOU_SECRET_START_{encoded_secret}_END"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        pdf_file_obj = io.BytesIO(sample_pdf_bytes)
        
        result = method.read_secret(pdf_file_obj, "any-key")
        
        assert result == "testsecret"
    
    def test_read_secret_load_pdf_bytes_exception(self):
        method = TinyTextWatermark()
        
        with patch('PawStamp_watermark.load_pdf_bytes', side_effect=ValueError("Invalid PDF")):
            with pytest.raises(ValueError, match="Invalid PDF"):
                method.read_secret("invalid", "key")
    
    @patch('fitz.open')
    def test_read_secret_fitz_exception(self, mock_fitz_open, sample_pdf_bytes: bytes):
        mock_fitz_open.side_effect = Exception("Fitz error")
        method = TinyTextWatermark()
        
        with pytest.raises(Exception, match="Fitz error"):
            method.read_secret(sample_pdf_bytes, "key")
    
    def test_remove_watermark_basic(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        result = method.remove_watermark(sample_pdf_bytes, "any-key")
        
        assert result == sample_pdf_bytes
    
    def test_remove_watermark_with_file_path(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
            tmp_file.write(sample_pdf_bytes)
            tmp_file.flush()
            
            result = method.remove_watermark(tmp_file.name, "any-key")
            
            assert result == sample_pdf_bytes
            
            Path(tmp_file.name).unlink()
    
    def test_remove_watermark_with_file_object(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        pdf_file_obj = io.BytesIO(sample_pdf_bytes)
        
        result = method.remove_watermark(pdf_file_obj, "any-key")
        
        assert result == sample_pdf_bytes
    
    def test_remove_watermark_with_kwargs(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        result = method.remove_watermark(
            sample_pdf_bytes,
            "any-key",
            position="ignored",
            extra_param="ignored"
        )
        
        assert result == sample_pdf_bytes
    
    def test_remove_watermark_load_pdf_bytes_exception(self):
        method = TinyTextWatermark()
        
        with patch('PawStamp_watermark.load_pdf_bytes', side_effect=ValueError("Invalid PDF")):
            with pytest.raises(ValueError, match="Invalid PDF"):
                method.remove_watermark("invalid", "key")
    
    @patch('fitz.open')
    def test_read_secret_invalid_base64_encoding(self, mock_fitz_open, sample_pdf_bytes: bytes):
        """Test read_secret with invalid Base64 encoding."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        # 使用无效的Base64编码
        mock_page.get_text.return_value = "TATOU_SECRET_START_invalid_base64!_END"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="Failed to decode secret"):
            method.read_secret(sample_pdf_bytes, "key")
    
    @patch('fitz.open')
    def test_read_secret_invalid_utf8_after_decode(self, mock_fitz_open, sample_pdf_bytes: bytes):
        """Test read_secret with valid Base64 but invalid UTF-8."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        # 使用有效的Base64但无效的UTF-8
        import base64
        invalid_utf8_bytes = b'\xff\xfe\xfd'  # 无效的UTF-8序列
        invalid_base64 = base64.b64encode(invalid_utf8_bytes).decode('ascii')
        mock_page.get_text.return_value = f"TATOU_SECRET_START_{invalid_base64}_END"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="Failed to decode secret"):
            method.read_secret(sample_pdf_bytes, "key")
    
    @patch('fitz.open')
    def test_read_secret_fitz_exception_during_processing(self, mock_fitz_open, sample_pdf_bytes: bytes):
        """Test read_secret when fitz raises an exception during processing."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.side_effect = Exception("Fitz processing error")
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="Error reading watermark"):
            method.read_secret(sample_pdf_bytes, "key")
    
    @patch('fitz.open')
    def test_add_watermark_fitz_exception_during_processing(self, mock_fitz_open, sample_pdf_bytes: bytes):
        """Test add_watermark when fitz raises an exception during processing."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_page.insert_textbox.side_effect = Exception("Fitz processing error")
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(Exception, match="Fitz processing error"):
            method.add_watermark(sample_pdf_bytes, "secret", "key")
    
    def test_add_watermark_zero_pages_returns_original(self, sample_pdf_bytes: bytes):
        """Test add_watermark with zero pages returns original PDF."""
        method = TinyTextWatermark()
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc = MagicMock()
            mock_doc.page_count = 0
            mock_fitz_open.return_value = mock_doc
            
            result = method.add_watermark(sample_pdf_bytes, "secret", "key")
            
            assert result == sample_pdf_bytes
            mock_doc.close.assert_called_once()
    
    def test_is_watermark_applicable_fitz_exception_returns_false(self, sample_pdf_bytes: bytes):
        """Test is_watermark_applicable when fitz raises an exception."""
        method = TinyTextWatermark()
        
        with patch('fitz.open', side_effect=Exception("Fitz error")):
            result = method.is_watermark_applicable(sample_pdf_bytes)
            assert result is False
    
    def test_is_watermark_applicable_load_pdf_bytes_exception_returns_false(self):
        """Test is_watermark_applicable when load_pdf_bytes raises an exception."""
        method = TinyTextWatermark()
        
        with patch('PawStamp_watermark.load_pdf_bytes', side_effect=Exception("Load error")):
            result = method.is_watermark_applicable("invalid")
            assert result is False
    
    def test_roundtrip_integration(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        secret = "integration-test-secret"
        key = "integration-test-key"
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc_add = MagicMock()
            mock_page_add = MagicMock()
            mock_page_add.rect.width = 612
            mock_page_add.rect.height = 792
            mock_doc_add.__iter__ = MagicMock(return_value=iter([mock_page_add]))
            
            # 现在使用Base64编码
            import base64
            encoded_secret = base64.b64encode(secret.encode('utf-8')).decode('ascii')
            watermark_text = f"TATOU_SECRET_START_{encoded_secret}_END"
            watermarked_content = f"PDF content {watermark_text}"
            mock_doc_add.tobytes.return_value = b"%PDF-1.4\n" + watermarked_content.encode()
            
            mock_doc_read = MagicMock()
            mock_page_read = MagicMock()
            mock_page_read.get_text.return_value = watermarked_content
            mock_doc_read.__iter__ = MagicMock(return_value=iter([mock_page_read]))
            
            mock_fitz_open.side_effect = [mock_doc_add, mock_doc_read]
            
            watermarked = method.add_watermark(sample_pdf_bytes, secret, key)
            
            extracted = method.read_secret(watermarked, key)
            
            assert extracted == secret
    
    def test_deterministic_behavior(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        secret = "deterministic-test"
        key = "deterministic-key"
        
        hash1 = method._get_secure_secret(secret, key)
        hash2 = method._get_secure_secret(secret, key)
        assert hash1 == hash2
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc = MagicMock()
            mock_page = MagicMock()
            mock_page.rect.width = 612
            mock_page.rect.height = 792
            mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
            mock_doc.tobytes.return_value = b"%PDF-deterministic"
            mock_fitz_open.return_value = mock_doc
            
            result1 = method.add_watermark(sample_pdf_bytes, secret, key)
            result2 = method.add_watermark(sample_pdf_bytes, secret, key)
            
            assert result1 == result2
    
    def test_edge_cases_large_page_size(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc = MagicMock()
            mock_page = MagicMock()
            mock_page.rect.width = 10000
            mock_page.rect.height = 10000
            mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
            mock_doc.tobytes.return_value = b"%PDF-large"
            mock_fitz_open.return_value = mock_doc
            
            result = method.add_watermark(sample_pdf_bytes, "secret", "key")
            
            assert isinstance(result, bytes)
            mock_page.insert_textbox.assert_called_once()
    
    def test_edge_cases_small_page_size(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc = MagicMock()
            mock_page = MagicMock()
            mock_page.rect.width = 50
            mock_page.rect.height = 50
            mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
            mock_doc.tobytes.return_value = b"%PDF-small"
            mock_fitz_open.return_value = mock_doc
            
            result = method.add_watermark(sample_pdf_bytes, "secret", "key")
            
            assert isinstance(result, bytes)
            mock_page.insert_textbox.assert_called_once()
    
    def test_edge_cases_zero_page_size(self, sample_pdf_bytes: bytes):
        method = TinyTextWatermark()
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc = MagicMock()
            mock_page = MagicMock()
            mock_page.rect.width = 0
            mock_page.rect.height = 0
            mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
            mock_doc.tobytes.return_value = b"%PDF-zero"
            mock_fitz_open.return_value = mock_doc
            
            result = method.add_watermark(sample_pdf_bytes, "secret", "key")
            
            assert isinstance(result, bytes)
            mock_page.insert_textbox.assert_called_once()
    
    def test_edge_cases_zero_page_count(self, sample_pdf_bytes: bytes):
        """Test add_watermark with a PDF that has zero pages."""
        method = TinyTextWatermark()
        
        with patch('fitz.open') as mock_fitz_open:
            mock_doc = MagicMock()
            mock_doc.page_count = 0  # 模拟零页面文档
            mock_fitz_open.return_value = mock_doc
            
            result = method.add_watermark(sample_pdf_bytes, "secret", "key")
            
            # 应该返回原始PDF字节，因为无法处理零页面文档
            assert result == sample_pdf_bytes
            mock_doc.close.assert_called_once()
            # tobytes 不应该被调用，因为文档没有页面
            mock_doc.tobytes.assert_not_called()

@pytest.fixture
def sample_pdf_bytes():
    return b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000120 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
202
%%EOF"""
