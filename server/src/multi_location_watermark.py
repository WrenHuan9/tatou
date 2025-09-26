"""multi_location_watermark.py (Advanced Version)

Robust watermarking method that embeds watermarks in multiple locations,
including within compressed PDF content streams for high resistance to removal.

This method provides enhanced security and robustness by:
- Storing watermarks in three PDF locations (trailer, content streams, EOF comment)
- Hiding the watermark inside compressed streams, making it invisible to simple binary searches.
- Using strong encryption (AES-256-GCM) for watermark protection.
- Implementing redundancy to survive partial removal attempts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from io import BytesIO
from typing import IO, Final, TypeAlias, Union

import pikepdf

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    load_pdf_bytes,
    WatermarkingMethod
)

PdfSource: TypeAlias = Union[bytes, str, os.PathLike[str], IO[bytes]]


class MultiLocationWatermark(WatermarkingMethod):
    """
    Robust watermarking method using three storage locations, including
    compressed content streams for enhanced stealth and resilience.
    """
    name: Final[str] = "multi-location-robust-advanced"

    # Constants
    _MAGIC_PREFIX_EOF: Final[str] = "%%WM-EOF:v2"
    _TRAILER_WM_KEY_STR: Final[str] = "/GMNIWatermarkV2"
    _CONTENT_STREAM_MARKER: Final[bytes] = b"%%GMNI-WM-PAYLOAD:"
    _CONTEXT: Final[bytes] = b"wm:multi-location:v2:"
    _SALT_LENGTH: Final[int] = 16
    _IV_LENGTH: Final[int] = 12
    _TAG_LENGTH: Final[int] = 16

    @staticmethod
    def get_usage() -> str:
        return (
            "Advanced robust watermarking that embeds secrets in the PDF trailer, "
            "EOF comments, and inside compressed page content streams for high "
            "resistance to removal. Position parameter is ignored."
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        pdf_bytes = load_pdf_bytes(pdf)

        # Generate fresh crypto material for each watermarking operation
        salt = os.urandom(self._SALT_LENGTH)
        iv = os.urandom(self._IV_LENGTH)
        derived_key = self._derive_key(key.encode('utf-8'), salt)
        payload = self._create_encrypted_payload(secret, derived_key, salt, iv)

        try:
            # Use BytesIO to handle the PDF in memory
            pdf_stream = BytesIO(pdf_bytes)
            with pikepdf.open(pdf_stream) as pdf_obj:
                # Location 1: PDF Trailer (structured, robust)
                self._embed_in_metadata(pdf_obj, payload)

                # Location 2: Compressed Content Stream (stealthy, very robust)
                self._embed_in_content_stream(pdf_obj, payload)

                # Save the structurally modified PDF to a new memory buffer
                output_buffer = BytesIO()
                pdf_obj.save(output_buffer)
                modified_bytes = output_buffer.getvalue()

            # Location 3: EOF Comment (simple fallback)
            final_bytes = self._embed_in_eof_trailer(modified_bytes, payload)

            return final_bytes

        except pikepdf.PdfError as e:
            raise WatermarkingError(f"Failed to process PDF with pikepdf: {e}")

    def is_watermark_applicable(
            self,
            pdf: PdfSource,
            position: str | None = None,
    ) -> bool:
        """Check if watermarking is applicable to this PDF.

        This method is always applicable as it works with any PDF structure.
        """
        try:
            data = load_pdf_bytes(pdf)
            return len(data) > 0 and data.startswith(b"%PDF-") and b"%%EOF" in data
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        pdf_bytes = load_pdf_bytes(pdf)

        found_payloads = set()
        last_error = None

        try:
            pdf_stream = BytesIO(pdf_bytes)
            with pikepdf.open(pdf_stream) as pdf_obj:
                # Attempt to extract from all locations
                # Location 1: Content Stream
                payload_cs = self._extract_from_content_streams(pdf_obj)
                if payload_cs:
                    found_payloads.add(payload_cs)

                # Location 2: Metadata
                payload_meta = self._extract_from_metadata(pdf_obj)
                if payload_meta:
                    found_payloads.add(payload_meta)

        except pikepdf.PdfError:
            # If pikepdf fails, the PDF might be corrupt, but we can still try
            # the simple EOF method as a last resort.
            pass

        # Location 3: EOF (works even if PDF structure is slightly corrupt)
        payload_eof = self._extract_from_eof_trailer(pdf_bytes)
        if payload_eof:
            found_payloads.add(payload_eof)

        if not found_payloads:
            raise SecretNotFoundError("No watermarks found in any location")

        for payload in found_payloads:
            try:
                secret = self._decrypt_payload(payload.decode('ascii'), key)
                return secret
            except Exception as e:
                if isinstance(e, InvalidKeyError):
                    last_error = e
                elif not last_error:
                    last_error = e
                continue

        if isinstance(last_error, InvalidKeyError):
            raise last_error
        elif last_error:
            raise SecretNotFoundError(f"No valid watermarks found. Last error: {last_error}")

    # --- Embedding Methods ---

    def _embed_in_metadata(self, pdf_obj: pikepdf.Pdf, payload: bytes):
        """Embeds watermark in the PDF trailer using structured access."""
        key_name = pikepdf.Name(self._TRAILER_WM_KEY_STR)
        pdf_obj.trailer[key_name] = pikepdf.String(payload.decode('ascii'))

    def _embed_in_eof_trailer(self, data: bytes, payload: bytes) -> bytes:
        """Embeds watermark as a comment before the final %%EOF."""
        eof_marker = b'%%EOF'
        eof_pos = data.rfind(eof_marker)
        if eof_pos == -1:
            return data

        existing_wm_regex = re.compile(f"\\n% ?{self._MAGIC_PREFIX_EOF}[^\\n]*\\n".encode('utf-8'))
        data = existing_wm_regex.sub(b"\n", data)
        eof_pos = data.rfind(eof_marker)

        watermark_comment = f"\n%{self._MAGIC_PREFIX_EOF} {payload.decode('ascii')}\n".encode('utf-8')
        return data[:eof_pos] + watermark_comment + data[eof_pos:]

    def _embed_in_content_stream(self, pdf_obj: pikepdf.Pdf, payload: bytes):
        """Embeds watermark as a comment inside a page's compressed content stream."""
        if not pdf_obj.pages:
            return # No pages to watermark

        # Target the first page for simplicity
        page = pdf_obj.pages[0]

        try:
            # read_bytes() automatically handles decompression
            contents = page.Contents.read_bytes()

            # Remove old watermark to prevent duplicates
            existing_wm_regex = re.compile(b"\\n%% ?" + self._CONTENT_STREAM_MARKER + b"[^\\n]*\\n")
            contents = existing_wm_regex.sub(b"\n", contents)

            # Inject new watermark as a PDF comment, which is ignored by renderers
            watermark_injection = b"\n" + self._CONTENT_STREAM_MARKER + payload + b"\n"
            new_contents = contents + watermark_injection

            # write() automatically handles re-compression and length updates
            page.Contents.write(new_contents)
        except (KeyError, AttributeError, pikepdf.PdfError):
            # Some pages might not have a content stream, or it might be malformed. Skip them.
            pass

    # --- Extraction Methods ---

    def _extract_from_metadata(self, pdf_obj: pikepdf.Pdf) -> bytes | None:
        """Extracts watermark from the PDF trailer."""
        key_name = pikepdf.Name(self._TRAILER_WM_KEY_STR)
        payload = pdf_obj.trailer.get(key_name)
        if payload and isinstance(payload, pikepdf.String):
            return str(payload).encode('ascii')
        return None

    def _extract_from_eof_trailer(self, data: bytes) -> bytes | None:
        """Extracts watermark from the comment before %%EOF."""
        pattern = f"%{self._MAGIC_PREFIX_EOF}\\s*([^\\s]+)".encode('utf-8')
        match = re.search(pattern, data)
        if match:
            return match.group(1).strip()
        return None

    def _extract_from_content_streams(self, pdf_obj: pikepdf.Pdf) -> bytes | None:
        """Extracts watermark from page content streams."""
        pattern = re.compile(self._CONTENT_STREAM_MARKER + b"([a-zA-Z0-9+/=_-]+)")
        for page in pdf_obj.pages:
            try:
                contents = page.Contents.read_bytes()
                match = pattern.search(contents)
                if match:
                    return match.group(1)
            except (KeyError, AttributeError, pikepdf.PdfError):
                # Skip pages with no content or errors
                continue
        return None

    # --- Crypto Helper Methods ---

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
        )
        return kdf.derive(password)

    def _create_encrypted_payload(self, secret: str, key: bytes, salt: bytes, iv: bytes) -> bytes:
        secret_bytes = secret.encode('utf-8')
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, secret_bytes, None)
        payload_data = {
            "v": 2,
            "salt": base64.b64encode(salt).decode('ascii'),
            "iv": base64.b64encode(iv).decode('ascii'),
            "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        }
        payload_json = json.dumps(payload_data, separators=(',', ':')).encode('utf-8')
        mac = hmac.new(key, self._CONTEXT + payload_json, hashlib.sha256).hexdigest()
        payload_data["mac"] = mac
        final_payload = json.dumps(payload_data, separators=(',', ':')).encode('utf-8')
        return base64.urlsafe_b64encode(final_payload)

    def _decrypt_payload(self, payload: str, key: str) -> str:
        try:
            payload_json = base64.urlsafe_b64decode(payload)
            payload_data = json.loads(payload_json)

            if payload_data.get("v") != 2:
                raise SecretNotFoundError("Unsupported payload version")

            salt = base64.b64decode(payload_data["salt"])
            iv = base64.b64decode(payload_data["iv"])
            ciphertext = base64.b64decode(payload_data["ciphertext"])
            mac = payload_data["mac"]

            derived_key = self._derive_key(key.encode('utf-8'), salt)

            payload_for_mac = json.dumps({
                "v": payload_data["v"],
                "salt": payload_data["salt"],
                "iv": payload_data["iv"],
                "ciphertext": payload_data["ciphertext"],
            }, separators=(',', ':')).encode('utf-8')

            expected_mac = hmac.new(derived_key, self._CONTEXT + payload_for_mac, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, expected_mac):
                raise InvalidKeyError("HMAC verification failed (wrong key or corrupted data)")

            aesgcm = AESGCM(derived_key)
            secret_bytes = aesgcm.decrypt(iv, ciphertext, None)

            return secret_bytes.decode('utf-8')
        except InvalidKeyError:
            raise
        except Exception as e:
            raise SecretNotFoundError(f"Failed to decrypt payload: {e}")

__all__ = ["MultiLocationWatermark"]