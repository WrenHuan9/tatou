import hashlib
import base64
import json
import hmac
from unittest.mock import MagicMock, patch
import pytest

from PawStamp_watermark import TinyTextWatermark
from watermarking_method import SecretNotFoundError, InvalidKeyError


# Valid PDF header for testing
VALID_PDF_HEADER = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000062 00000 n \n0000000140 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n181\n%%EOF"


class TestTinyTextWatermark:
    
    def test_class_attributes(self):
        """Test basic class attributes."""
        method = TinyTextWatermark()
        assert method.name == "PawStamp Secure"
        assert hasattr(method, '_get_secure_secret')
        assert hasattr(method, '_generate_hmac')
    
    def test_get_usage(self):
        """Test usage description."""
        method = TinyTextWatermark()
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert "secret" in usage.lower()
        assert "hmac" in usage.lower()
    
    def test_generate_hmac_basic(self):
        """Test HMAC generation."""
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        result = method._generate_hmac(secret, key)
        
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest length
        
        # Same input should produce same result
        result2 = method._generate_hmac(secret, key)
        assert result == result2
    
    def test_generate_hmac_different_inputs(self):
        """Test HMAC with different inputs produces different results."""
        method = TinyTextWatermark()
        
        result1 = method._generate_hmac("secret1", "key1")
        result2 = method._generate_hmac("secret2", "key1")
        result3 = method._generate_hmac("secret1", "key2")
        
        assert result1 != result2
        assert result1 != result3
        assert result2 != result3
    
    def test_generate_hmac_unicode(self):
        """Test HMAC with Unicode input."""
        method = TinyTextWatermark()
        secret = "测试秘密 🔒"
        key = "测试密钥"
        
        result = method._generate_hmac(secret, key)
        
        assert isinstance(result, str)
        assert len(result) == 64
    
    def test_generate_hmac_empty_strings(self):
        """Test HMAC with empty strings."""
        method = TinyTextWatermark()
        
        result1 = method._generate_hmac("", "")
        result2 = method._generate_hmac("", "key")
        result3 = method._generate_hmac("secret", "")
        
        assert isinstance(result1, str)
        assert isinstance(result2, str)
        assert isinstance(result3, str)
        assert len(result1) == len(result2) == len(result3) == 64
    
    def test_get_secure_secret(self):
        """Test _get_secure_secret method."""
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        result = method._get_secure_secret(secret, key)
        
        assert isinstance(result, str)
        assert len(result) == 16  # SHA1 hex digest truncated to 16 chars
        
        # Test consistency
        result2 = method._get_secure_secret(secret, key)
        assert result == result2
        
        # Test different inputs produce different results
        result3 = method._get_secure_secret("different-secret", key)
        result4 = method._get_secure_secret(secret, "different-key")
        assert result != result3
        assert result != result4
    
    @patch('PawStamp_watermark.fitz.open')
    def test_add_watermark_basic(self, mock_fitz_open):
        """Test basic watermark addition."""
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
        
        result = method.add_watermark(VALID_PDF_HEADER, secret, key)
        
        assert isinstance(result, bytes)
        mock_fitz_open.assert_called_once()
        mock_page.insert_textbox.assert_called_once()
        
        # Check watermark text format
        args, kwargs = mock_page.insert_textbox.call_args
        watermark_text = args[1]
        
        expected_hmac = method._generate_hmac(secret, key)
        expected_payload = {"secret": secret, "hmac": expected_hmac}
        expected_payload_json = json.dumps(expected_payload)
        expected_encoded_payload = base64.b64encode(expected_payload_json.encode('utf-8')).decode('ascii')
        expected_text = f"TATOU_SECRET_START_{expected_encoded_payload}_END"
        assert watermark_text == expected_text
        
        # Check textbox parameters
        assert kwargs['fontsize'] == 1
        assert kwargs['color'] == (0.9, 0.9, 0.9)
        assert kwargs['fontname'] == "helv"
    
    @patch('PawStamp_watermark.fitz.open')
    def test_add_watermark_zero_pages(self, mock_fitz_open):
        """Test watermark addition with zero pages."""
        mock_doc = MagicMock()
        mock_doc.page_count = 0
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        result = method.add_watermark(VALID_PDF_HEADER, "secret", "key")
        
        assert result == VALID_PDF_HEADER
        mock_doc.close.assert_called_once()
    
    @patch('PawStamp_watermark.fitz.open')
    def test_add_watermark_exception(self, mock_fitz_open):
        """Test watermark addition with exception."""
        mock_fitz_open.side_effect = Exception("Fitz error")
        method = TinyTextWatermark()
        
        with pytest.raises(Exception, match="Fitz error"):
            method.add_watermark(VALID_PDF_HEADER, "secret", "key")
    
    @patch('PawStamp_watermark.fitz.open')
    def test_add_watermark_exception_during_processing(self, mock_fitz_open):
        """Test watermark addition with exception during processing."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.rect.width = 612
        mock_page.rect.height = 792
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_page.insert_textbox.side_effect = Exception("Processing error")
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(Exception, match="Processing error"):
            method.add_watermark(VALID_PDF_HEADER, "secret", "key")
        
        # Verify doc.close() is called even when exception occurs
        mock_doc.close.assert_called_once()
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_success(self, mock_fitz_open):
        """Test successful secret reading."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        # Create valid watermark text
        hmac_signature = method._generate_hmac(secret, key)
        payload = {"secret": secret, "hmac": hmac_signature}
        payload_json = json.dumps(payload)
        encoded_payload = base64.b64encode(payload_json.encode('utf-8')).decode('ascii')
        watermark_text = f"Some content TATOU_SECRET_START_{encoded_payload}_END more content"
        mock_page.get_text.return_value = watermark_text
        
        result = method.read_secret(VALID_PDF_HEADER, key)
        
        assert result == secret
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_invalid_key(self, mock_fitz_open):
        """Test secret reading with invalid key."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        secret = "test-secret"
        correct_key = "correct-key"
        wrong_key = "wrong-key"
        
        # Create watermark with correct key
        hmac_signature = method._generate_hmac(secret, correct_key)
        payload = {"secret": secret, "hmac": hmac_signature}
        payload_json = json.dumps(payload)
        encoded_payload = base64.b64encode(payload_json.encode('utf-8')).decode('ascii')
        watermark_text = f"TATOU_SECRET_START_{encoded_payload}_END"
        mock_page.get_text.return_value = watermark_text
        
        # Try to read with wrong key
        with pytest.raises(SecretNotFoundError):
            method.read_secret(VALID_PDF_HEADER, wrong_key)
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_not_found(self, mock_fitz_open):
        """Test secret reading when no watermark found."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.return_value = "No watermark here"
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="No secret found with the PawStamp Secure method"):
            method.read_secret(VALID_PDF_HEADER, "key")
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_invalid_payload_format(self, mock_fitz_open):
        """Test secret reading with invalid payload format."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        # Invalid payload (missing hmac field)
        invalid_payload = {"secret": "test"}
        payload_json = json.dumps(invalid_payload)
        encoded_payload = base64.b64encode(payload_json.encode('utf-8')).decode('ascii')
        watermark_text = f"TATOU_SECRET_START_{encoded_payload}_END"
        mock_page.get_text.return_value = watermark_text
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="Invalid watermark payload format"):
            method.read_secret(VALID_PDF_HEADER, "key")
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_invalid_json(self, mock_fitz_open):
        """Test secret reading with invalid JSON."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        # Invalid JSON
        invalid_json = '{"secret": "test", "hmac": "invalid"'
        encoded_payload = base64.b64encode(invalid_json.encode('utf-8')).decode('ascii')
        watermark_text = f"TATOU_SECRET_START_{encoded_payload}_END"
        mock_page.get_text.return_value = watermark_text
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="Failed to decode watermark payload"):
            method.read_secret(VALID_PDF_HEADER, "key")
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_invalid_base64(self, mock_fitz_open):
        """Test secret reading with invalid Base64."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        # Invalid Base64
        watermark_text = "TATOU_SECRET_START_invalid_base64!_END"
        mock_page.get_text.return_value = watermark_text
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError):
            method.read_secret(VALID_PDF_HEADER, "key")
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_exception_during_processing(self, mock_fitz_open):
        """Test secret reading with exception during processing."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.side_effect = Exception("Processing error")
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        
        with pytest.raises(SecretNotFoundError, match="Error reading watermark"):
            method.read_secret(VALID_PDF_HEADER, "key")
    
    @patch('PawStamp_watermark.fitz.open')
    def test_read_secret_exception_during_payload_processing(self, mock_fitz_open):
        """Test secret reading with exception during payload processing."""
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.__iter__ = MagicMock(return_value=iter([mock_page]))
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        secret = "test-secret"
        key = "test-key"
        
        # Create valid watermark text
        hmac_signature = method._generate_hmac(secret, key)
        payload = {"secret": secret, "hmac": hmac_signature}
        payload_json = json.dumps(payload)
        encoded_payload = base64.b64encode(payload_json.encode('utf-8')).decode('ascii')
        watermark_text = f"TATOU_SECRET_START_{encoded_payload}_END"
        mock_page.get_text.return_value = watermark_text
        
        # Mock an exception during payload processing (e.g., in _generate_hmac)
        with patch.object(method, '_generate_hmac', side_effect=Exception("HMAC processing error")):
            with pytest.raises(SecretNotFoundError, match="Error processing watermark"):
                method.read_secret(VALID_PDF_HEADER, key)
    
    @patch('PawStamp_watermark.fitz.open')
    def test_is_watermark_applicable_valid_pdf(self, mock_fitz_open):
        """Test watermark applicability with valid PDF."""
        mock_doc = MagicMock()
        mock_doc.page_count = 1
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        result = method.is_watermark_applicable(VALID_PDF_HEADER)
        
        assert result is True
        mock_doc.close.assert_called_once()
    
    @patch('PawStamp_watermark.fitz.open')
    def test_is_watermark_applicable_zero_pages(self, mock_fitz_open):
        """Test watermark applicability with zero pages."""
        mock_doc = MagicMock()
        mock_doc.page_count = 0
        mock_fitz_open.return_value = mock_doc
        
        method = TinyTextWatermark()
        result = method.is_watermark_applicable(VALID_PDF_HEADER)
        
        assert result is False
        mock_doc.close.assert_called_once()
    
    @patch('PawStamp_watermark.fitz.open')
    def test_is_watermark_applicable_exception(self, mock_fitz_open):
        """Test watermark applicability with exception."""
        mock_fitz_open.side_effect = Exception("Fitz error")
        
        method = TinyTextWatermark()
        result = method.is_watermark_applicable(VALID_PDF_HEADER)
        
        assert result is False
    
    def test_remove_watermark(self):
        """Test watermark removal."""
        method = TinyTextWatermark()
        original_pdf = VALID_PDF_HEADER
        
        result = method.remove_watermark(original_pdf, "key")
        
        assert result == original_pdf
    
    @patch('PawStamp_watermark.fitz.open')
    def test_roundtrip_integration(self, mock_fitz_open):
        """Test complete add-read cycle."""
        method = TinyTextWatermark()
        secret = "integration-test-secret"
        key = "integration-test-key"
        
        # Mock add watermark
        mock_doc_add = MagicMock()
        mock_page_add = MagicMock()
        mock_page_add.rect.width = 612
        mock_page_add.rect.height = 792
        mock_doc_add.__iter__ = MagicMock(return_value=iter([mock_page_add]))
        
        # Create expected watermark content
        hmac_signature = method._generate_hmac(secret, key)
        payload = {"secret": secret, "hmac": hmac_signature}
        payload_json = json.dumps(payload)
        encoded_payload = base64.b64encode(payload_json.encode('utf-8')).decode('ascii')
        watermark_text = f"TATOU_SECRET_START_{encoded_payload}_END"
        watermarked_content = f"PDF content {watermark_text}"
        mock_doc_add.tobytes.return_value = b"%PDF-1.4\n" + watermarked_content.encode()
        
        # Mock read watermark
        mock_doc_read = MagicMock()
        mock_page_read = MagicMock()
        mock_page_read.get_text.return_value = watermarked_content
        mock_doc_read.__iter__ = MagicMock(return_value=iter([mock_page_read]))
        
        mock_fitz_open.side_effect = [mock_doc_add, mock_doc_read]
            
        # Test add watermark
        watermarked = method.add_watermark(VALID_PDF_HEADER, secret, key)
        assert isinstance(watermarked, bytes)
        
        # Test read watermark
        extracted = method.read_secret(watermarked, key)
        assert extracted == secret

