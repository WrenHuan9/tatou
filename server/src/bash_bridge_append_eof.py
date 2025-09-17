"""bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
from __future__ import annotations

import os
import subprocess
from typing import IO, Final, TypeAlias, Union

from watermarking_method import WatermarkingMethod, load_pdf_bytes, WatermarkingError, SecretNotFoundError

PdfSource: TypeAlias = Union[bytes, str, os.PathLike[str], IO[bytes]]


class BashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF."""

    name: Final[str] = "bash-bridge-eof"

    # Constants
    _EOF_MARKER: Final[bytes] = b'%%EOF'

    # ---------------------
    # Public API overrides
    # ---------------------

    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position and key are ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` and ``key`` parameters are accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        secret_bytes = secret.encode('utf-8')

        return data + secret_bytes

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret if present.
        Prints whatever there is after %EOF
        """
        data = load_pdf_bytes(pdf)
        last_eof_pos = data.rfind(self._EOF_MARKER)

        if last_eof_pos == -1:
            raise SecretNotFoundError("No BashBridgeAppendEOF watermark found")

        start_of_secret = last_eof_pos + len(self._EOF_MARKER)
        secret_bytes = data[start_of_secret:]

        return secret_bytes.strip().decode('utf-8', errors='ignore')


__all__ = ["BashBridgeAppendEOF"]
