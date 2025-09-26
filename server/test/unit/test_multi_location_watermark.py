"""test_multi_location_watermark.py

Test suite for the advanced MultiLocationWatermark method that uses pikepdf.
"""

import pytest
import base64
import json
import re
from io import BytesIO

import pikepdf

from multi_location_watermark import MultiLocationWatermark
from watermarking_method import SecretNotFoundError, InvalidKeyError, WatermarkingError


class TestMultiLocationWatermarkAdvanced:
    """Test cases for the advanced MultiLocationWatermark method."""

    @pytest.fixture
    def method(self):
        """Create watermarking method instance."""
        return MultiLocationWatermark()

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a minimal, valid PDF for testing."""
        pdf_content = b"""%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>
endobj
4 0 obj
<</Length 44>>
stream
BT
/F1 12 Tf
100 700 Td
(Hello World from test!) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000057 00000 n 
0000000111 00000 n 
0000000196 00000 n 
trailer
<</Size 5/Root 1 0 R>>
startxref
248
%%EOF
"""
        pdf_path = tmp_path / "sample.pdf"
        pdf_path.write_bytes(pdf_content)
        return pdf_path

    @pytest.fixture
    def pdf_with_blank_page(self, tmp_path):
        """Creates a PDF with one content page and one blank (no-content) page."""
        pdf_path = tmp_path / "blank_page.pdf"
        with pikepdf.new() as pdf:
            # Add a page with content
            pdf.add_blank_page()
            page_with_content = pdf.pages[0]
            page_with_content.Contents = pikepdf.Stream(pdf, b"BT /F1 24 Tf 100 700 Td (First Page Content) Tj ET")

            # Add a blank page and remove its content stream key
            pdf.add_blank_page()
            page_without_content = pdf.pages[1]
            del page_without_content.Contents

            pdf.save(pdf_path)
        return pdf_path

    @pytest.fixture
    def pdf_without_pages(self, tmp_path):
        """Creates a valid PDF structure but with no pages."""
        pdf_path = tmp_path / "no_pages.pdf"
        # pikepdf.new() 创建一个只有 Catalog 的空 PDF，没有 /Pages 对象
        with pikepdf.new() as pdf:
            pdf.save(pdf_path)
        return pdf_path

    # --- Basic Functionality Tests ---

    def test_method_name(self, method):
        """Test method name is correct."""
        assert method.name == "multi-location-robust-advanced"

    def test_get_usage(self, method):
        """Test usage description."""
        usage = method.get_usage()
        assert isinstance(usage, str)
        assert "trailer" in usage.lower()
        assert "content streams" in usage.lower()
        assert "advanced" in usage.lower()

    def test_is_watermark_applicable(self, method, sample_pdf):
        """Test watermark applicability check."""
        assert method.is_watermark_applicable(sample_pdf) is True
        assert method.is_watermark_applicable(sample_pdf, position="test") is True

    def test_is_watermark_applicable_invalid_pdf(self, method):
        """Test applicability check with invalid PDF."""
        assert method.is_watermark_applicable(b"not a pdf") is False
        assert method.is_watermark_applicable(b"") is False

    def test_add_watermark_invalid_inputs(self, method, sample_pdf):
        """Test add_watermark with invalid inputs."""
        with pytest.raises(ValueError, match="Secret must be a non-empty string"):
            method.add_watermark(sample_pdf, "", "key")

        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.add_watermark(sample_pdf, "secret", "")

    def test_add_watermark_success(self, method, sample_pdf):
        """Test successful watermark addition across all three locations."""
        secret = "test-secret-123"
        key = "test-key-456"

        watermarked_pdf_bytes = method.add_watermark(sample_pdf, secret, key)

        # Check EOF marker presence
        assert method._MAGIC_PREFIX_EOF.encode() in watermarked_pdf_bytes

        # Use pikepdf to verify structured and compressed locations
        with pikepdf.open(BytesIO(watermarked_pdf_bytes)) as pdf:
            # Check trailer for our custom key
            assert pikepdf.Name(method._TRAILER_WM_KEY_STR) in pdf.trailer

            # Check content stream of the first page for our marker
            page = pdf.pages[0]
            content_stream = page.Contents.read_bytes()
            assert method._CONTENT_STREAM_MARKER in content_stream

    def test_roundtrip_consistency(self, method, sample_pdf):
        """Test that watermarking and extraction are consistent."""
        secret = "roundtrip-test-secret-advanced-@!#"
        key = "roundtrip-test-key"

        watermarked_pdf = method.add_watermark(sample_pdf, secret, key)
        extracted_secret = method.read_secret(watermarked_pdf, key)
        assert extracted_secret == secret

    def test_unicode_and_large_secret(self, method, sample_pdf):
        """Test watermarking with Unicode and large secrets."""
        secret = "测试秘密 🎯 中文" * 500  # Large and complex Unicode secret
        key = "unicode-key-for-advanced-test"

        watermarked_pdf = method.add_watermark(sample_pdf, secret, key)
        extracted_secret = method.read_secret(watermarked_pdf, key)
        assert extracted_secret == secret

    # --- Error Handling and Edge Case Tests ---

    def test_read_secret_empty_key(self, method, sample_pdf):
        """Test read_secret with empty key."""
        with pytest.raises(ValueError, match="Key must be a non-empty string"):
            method.read_secret(sample_pdf, "")

    def test_read_secret_wrong_key(self, method, sample_pdf):
        """Test that secret extraction fails with an incorrect key."""
        watermarked_pdf = method.add_watermark(sample_pdf, "secret", "correct-key")
        with pytest.raises(InvalidKeyError):
            method.read_secret(watermarked_pdf, "wrong-key")

    def test_read_secret_no_watermark(self, method, sample_pdf):
        """Test secret extraction from a non-watermarked PDF."""
        with pytest.raises(SecretNotFoundError):
            method.read_secret(sample_pdf, "any-key")

    def test_add_watermark_on_corrupt_pdf_raises_error(self, method):
        """Test that add_watermark raises WatermarkingError on corrupt PDF input."""
        corrupt_pdf_data = b"%PDF-1.4\n%This file is intentionally broken\n"
        with pytest.raises(WatermarkingError):
            method.add_watermark(corrupt_pdf_data, "secret", "key")

    def test_read_secret_all_locations_invalid_payload(self, method, sample_pdf):
        """Test reading when all watermarks are present but have corrupted payloads."""
        secret = "will-be-corrupted"
        key = "key"
        watermarked_pdf_bytes = method.add_watermark(sample_pdf, secret, key)

        # This payload is not valid Base64 and will fail to decode
        corrupted_payload = b"this-is-not-valid-base64-payload"

        # Replace all instances of the real payload with the corrupted one
        with pikepdf.open(BytesIO(watermarked_pdf_bytes)) as pdf:
            # Corrupt trailer
            trailer_key = pikepdf.Name(method._TRAILER_WM_KEY_STR)
            if trailer_key in pdf.trailer:
                pdf.trailer[trailer_key] = pikepdf.String(corrupted_payload.decode('ascii'))

            # Corrupt content stream
            page = pdf.pages[0]
            contents = page.Contents.read_bytes()
            new_contents = re.sub(method._CONTENT_STREAM_MARKER + b"[a-zA-Z0-9+/=_-]+", method._CONTENT_STREAM_MARKER + corrupted_payload, contents)
            page.Contents.write(new_contents)

            buffer = BytesIO()
            pdf.save(buffer)
            corrupted_internals_pdf = buffer.getvalue()

        # Corrupt EOF
        final_corrupted_pdf = re.sub(method._MAGIC_PREFIX_EOF.encode() + b' [^\\s]+', method._MAGIC_PREFIX_EOF.encode() + b' ' + corrupted_payload, corrupted_internals_pdf)

        with pytest.raises(SecretNotFoundError, match="No valid watermarks found"):
            method.read_secret(final_corrupted_pdf, key)

    def test_decrypt_payload_invalid_version(self, method):
        """Test _decrypt_payload with an unsupported payload version."""
        payload_dict = {
            "v": 99, "salt": "a", "iv": "b", "ciphertext": "c", "mac": "d"
        }
        payload_json = json.dumps(payload_dict).encode('utf-8')
        payload_b64 = base64.urlsafe_b64encode(payload_json).decode('ascii')

        with pytest.raises(SecretNotFoundError, match="Unsupported payload version"):
            method._decrypt_payload(payload_b64, "any-key")

    def test_read_secret_with_locations_removed(self, method, sample_pdf):
        """Test that the secret can be read if one or two locations are removed."""
        secret = "robustness-test"
        key = "robustness-key"

        watermarked_pdf_bytes = method.add_watermark(sample_pdf, secret, key)

        # SCENARIO 1: Remove trailer watermark, should read from stream or EOF
        with pikepdf.open(BytesIO(watermarked_pdf_bytes)) as pdf:
            del pdf.trailer[pikepdf.Name(method._TRAILER_WM_KEY_STR)]
            buffer = BytesIO()
            pdf.save(buffer)
            corrupted_pdf = buffer.getvalue()
        assert method.read_secret(corrupted_pdf, key) == secret

        # SCENARIO 2: Remove content stream watermark, should read from trailer or EOF
        with pikepdf.open(BytesIO(watermarked_pdf_bytes)) as pdf:
            page = pdf.pages[0]
            contents = page.Contents.read_bytes()
            corrupted_contents = re.sub(b"\\n" + method._CONTENT_STREAM_MARKER + b"[^\\n]*\\n", b"\\n", contents)
            page.Contents.write(corrupted_contents)
            buffer = BytesIO()
            pdf.save(buffer)
            corrupted_pdf = buffer.getvalue()
        assert method.read_secret(corrupted_pdf, key) == secret

        # SCENARIO 3: Remove EOF watermark, should read from trailer or stream
        corrupted_pdf = re.sub(b"\\n%" + method._MAGIC_PREFIX_EOF.encode() + b"[^\\n]*\\n", b"\\n", watermarked_pdf_bytes)
        assert method.read_secret(corrupted_pdf, key) == secret

    def test_read_secret_fallback_on_corrupt_pdf(self, method, sample_pdf):
        """
        Tests that read_secret can still find the EOF watermark even if the PDF
        is too corrupt for pikepdf to open.
        """
        secret = "fallback-secret"
        key = "fallback-key"

        # Create a normally watermarked PDF to get a valid EOF payload
        watermarked_pdf_bytes = method.add_watermark(sample_pdf, secret, key)

        # Extract just the EOF watermark line
        eof_watermark_line_match = re.search(b"(\\n%.*\\n%%EOF)", watermarked_pdf_bytes, re.DOTALL)
        assert eof_watermark_line_match is not None, "Could not find EOF watermark line"
        eof_watermark_part = eof_watermark_line_match.group(1)

        # Create a new, severely corrupted PDF that will fail pikepdf.open()
        corrupt_pdf_data = (
            b"%PDF-1.4\n"
            b"%This file is intentionally broken\n"
            b"1 0 obj << /Invalid >> endobj\n"
            b"startxref\n-1\n"
        ) + eof_watermark_part

        # Our method should gracefully handle the pikepdf error and fall back
        # to reading the EOF marker, successfully finding the secret.
        extracted_secret = method.read_secret(corrupt_pdf_data, key)
        assert extracted_secret == secret

    def test_embed_on_pdf_with_blank_page(self, method, pdf_with_blank_page):
        """Tests embedding on a PDF with a contentless page. (Covers lines 146-149)"""
        # This test passes if no exception is raised
        method.add_watermark(pdf_with_blank_page, "secret", "key")

    def test_extract_from_pdf_with_blank_page(self, method, pdf_with_blank_page):
        """Tests extraction from a PDF with a contentless page. (Covers lines 218-220)"""
        watermarked_pdf = method.add_watermark(pdf_with_blank_page, "secret", "key")
        assert method.read_secret(watermarked_pdf, "key") == "secret"

    def test_read_secret_metadata_wrong_type(self, method, sample_pdf):
        """Tests reading when metadata WM is not a string. (Covers line 199)"""
        secret = "robust-secret"
        key = "robust-key"
        watermarked_pdf_bytes = method.add_watermark(sample_pdf, secret, key)

        # Manually corrupt the trailer watermark to be the wrong type
        with pikepdf.open(BytesIO(watermarked_pdf_bytes)) as pdf:
            key_name = pikepdf.Name(method._TRAILER_WM_KEY_STR)
            pdf.trailer[key_name] = 12345

            buffer = BytesIO()
            pdf.save(buffer)
            corrupted_pdf = buffer.getvalue()

        # The secret should still be found in the other locations
        assert method.read_secret(corrupted_pdf, key) == secret

    def test_add_watermark_to_pdf_with_no_pages(self, method, pdf_without_pages):
        secret = "no-pages-test"
        key = "no-pages-key"

        watermarked_bytes = method.add_watermark(pdf_without_pages, secret, key)

        assert method._MAGIC_PREFIX_EOF.encode() in watermarked_bytes
        with pikepdf.open(BytesIO(watermarked_bytes)) as pdf:
            assert pikepdf.Name(method._TRAILER_WM_KEY_STR) in pdf.trailer
            assert not pdf.pages

        assert method.read_secret(watermarked_bytes, key) == secret

    # --- Helper Method Unit Tests ---

    def test_helper_embed_in_eof_trailer_no_eof(self, method):
        """Test the _embed_in_eof_trailer helper with data lacking an %%EOF marker."""
        invalid_file_data = b"%PDF-1.4\n1 0 obj <<>> endobj"
        payload = b"test-payload"

        # The method should not fail and simply return the original data
        result = method._embed_in_eof_trailer(invalid_file_data, payload)
        assert result == invalid_file_data