import json
import base64
import hmac
import hashlib
from io import BytesIO
import pypdf

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)


class MetadataWatermark(WatermarkingMethod):
    """
    Embeds a watermark by adding a custom field to the PDF's metadata.
    This method is invisible and uses HMAC to verify the integrity and authenticity of the information.
    """
    name: str = "metadata"


    _CONTEXT: bytes = b"wm:metadata:v1:"

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        """Calculates the HMAC-SHA256 signature and returns it as a hex string."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def _build_payload(self, secret: str, key: str) -> str:
        """Builds a JSON payload containing the secret and signature, then Base64-encodes it."""
        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        json_payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(json_payload).decode("ascii")

    # --- Core interface implementation ---
    @staticmethod
    def get_usage() -> str:
        return "Embeds an invisible watermark in the PDF's metadata. The 'position' parameter is not used."

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        return True  # This method is applicable to all valid PDFs

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        """Adds the watermarked payload to the PDF metadata."""
        pdf_bytes = load_pdf_bytes(pdf)

        # 1. Create PdfReader and PdfWriter objects
        reader = pypdf.PdfReader(BytesIO(pdf_bytes))
        writer = pypdf.PdfWriter()

        # 2. Copy all pages and metadata from the original PDF
        writer.append_pages_from_reader(reader)

        # Check if metadata exists before copying
        if reader.metadata:
            writer.add_metadata(reader.metadata)

        # 3. Build the secure payload and add it to the metadata
        payload = self._build_payload(secret, key)
        writer.add_metadata({
            "/TatouSecret": payload
        })

        # 4. Write the modified PDF to an in-memory byte stream and return it
        buffer = BytesIO()
        writer.write(buffer)
        return buffer.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Reads and verifies the watermark from the PDF metadata."""
        pdf_bytes = load_pdf_bytes(pdf)

        try:
            reader = pypdf.PdfReader(BytesIO(pdf_bytes))
            metadata = reader.metadata

            # 1. Check if our custom field exists
            if metadata is None or "/TatouSecret" not in metadata:
                raise SecretNotFoundError("Watermark not found in metadata.")

            payload_b64 = metadata["/TatouSecret"]

            # 2. Decode and parse the payload
            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)

            # 3. Validate the payload format and version
            if not (isinstance(payload, dict) and payload.get("v") == 1):
                raise SecretNotFoundError("Unsupported watermark version or format.")

            # 4. Extract the secret and signature, and verify them
            mac_hex = str(payload["mac"])
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)

            expected_mac = self._mac_hex(secret_bytes, key)
            if not hmac.compare_digest(mac_hex, expected_mac):
                raise InvalidKeyError("Invalid key, cannot verify the watermark.")

            # 5. Verification passed, return the secret
            return secret_bytes.decode("utf-8")

        except (pypdf.errors.PdfReadError, TypeError, KeyError, ValueError) as exc:
            # Catch all possible parsing errors and treat them as watermark not found
            raise SecretNotFoundError("Error parsing the watermark payload.") from exc
