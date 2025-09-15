# tests/test_add_after_eof.py
import pytest

try:
    from server.src.watermarking_method import SecretNotFoundError, InvalidKeyError, WatermarkingError
except ImportError:
    class SecretNotFoundError(Exception): pass
    class InvalidKeyError(Exception): pass
    class WatermarkingError(Exception): pass

from server.src.add_after_eof import AddAfterEOF


@pytest.fixture
def watermark_method():
    return AddAfterEOF()

# --- 使用更真实的模拟PDF数据 ---
VALID_PDF_HEADER = b"%PDF-1.7\n"
FAKE_PDF_CONTENT = VALID_PDF_HEADER + b"1 0 obj<</Type/Catalog>>endobj\n%%EOF"


def test_get_usage(watermark_method):
    usage = watermark_method.get_usage()
    assert isinstance(usage, str)
    assert "appends a watermark" in usage

def test_is_watermark_applicable(watermark_method):
    assert watermark_method.is_watermark_applicable(FAKE_PDF_CONTENT) is True

# ---- 测试 add_watermark 方法 ----

def test_add_watermark_success(watermark_method):
    secret = "my-secret-message"
    key = "my-secret-key"
    watermarked_pdf = watermark_method.add_watermark(FAKE_PDF_CONTENT, secret, key)
    assert watermarked_pdf.startswith(FAKE_PDF_CONTENT)
    assert watermark_method._MAGIC in watermarked_pdf
    assert len(watermarked_pdf) > len(FAKE_PDF_CONTENT)

def test_add_watermark_handles_no_newline(watermark_method):
    pdf_without_newline = FAKE_PDF_CONTENT.strip()
    watermarked_pdf = watermark_method.add_watermark(pdf_without_newline, "secret", "key")
    assert b"%%EOF\n" + watermark_method._MAGIC in watermarked_pdf

def test_add_watermark_raises_error_on_empty_secret(watermark_method):
    with pytest.raises(ValueError, match="Secret must be a non-empty string"):
        watermark_method.add_watermark(FAKE_PDF_CONTENT, secret="", key="key")

def test_add_watermark_raises_error_on_empty_key(watermark_method):
    with pytest.raises(ValueError, match="Key must be a non-empty string"):
        watermark_method.add_watermark(FAKE_PDF_CONTENT, secret="secret", key="")


# ---- 测试 read_secret 方法 ----

def test_read_secret_success(watermark_method):
    secret = "top secret info 🤫"
    key = "correct-key"
    watermarked_pdf = watermark_method.add_watermark(FAKE_PDF_CONTENT, secret, key)
    extracted_secret = watermark_method.read_secret(watermarked_pdf, key)
    assert extracted_secret == secret

def test_read_secret_raises_error_with_wrong_key(watermark_method):
    watermarked_pdf = watermark_method.add_watermark(FAKE_PDF_CONTENT, "secret", "correct-key")
    with pytest.raises(InvalidKeyError, match="failed to authenticate the watermark"):
        watermark_method.read_secret(watermarked_pdf, "wrong-key")

def test_read_secret_raises_error_if_no_watermark(watermark_method):
    with pytest.raises(SecretNotFoundError, match="No AddAfterEOF watermark found"):
        watermark_method.read_secret(FAKE_PDF_CONTENT, "any-key")

# tests/test_add_after_eof.py
def test_read_secret_raises_error_if_payload_tampered(watermark_method):
    watermarked_pdf = watermark_method.add_watermark(FAKE_PDF_CONTENT, "secret", "key")
    tampered_pdf = watermarked_pdf + b"tampered"
    with pytest.raises(SecretNotFoundError, match="Extra data found after watermark payload, indicating tampering"):
        watermark_method.read_secret(tampered_pdf, "key")