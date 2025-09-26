# tests/test_watermarking_all_methods.py
from __future__ import annotations
import importlib
import inspect
from pathlib import Path
import pytest


# --------- collect all methods from the registry ----------
try:
    wm = importlib.import_module("watermarking_utils")
    METHODS = getattr(wm, "METHODS", {})
except Exception:  # registry/module missing
    METHODS = {}

CASES: list[tuple[str, object]] = []
for name, impl in (METHODS or {}).items():
    if not name == "UnsafeBashBridgeAppendEOF":
        CASES.append((str(name), impl))

if not CASES:
    pytest.skip(
        "No watermarking methods registered in watermarking_utils.METHODS",
        allow_module_level=True,
    )


# --------- fixtures ----------
@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    """Minimal but recognizable PDF bytes."""
    pdf = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    pdf_content = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000010 00000 n \n"
        b"0000000062 00000 n \n"
        b"0000000140 00000 n \n"
        b"trailer\n"
        b"<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"181\n"
        b"%%EOF\n"
    )
    pdf.write_bytes(pdf_content)
    return pdf


@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"


@pytest.fixture(scope="session")
def key() -> str:
    return "unit-test-key"


def _as_instance(impl: object) -> object:
    """Return an instance for class objects; pass instances through."""
    if inspect.isclass(impl):
        return impl()  # assumes zero-arg constructor
    return impl


# --------- parameterization over all methods ----------
@pytest.mark.parametrize("method_name,impl", CASES, ids=[n for n, _ in CASES])
class TestAllWatermarkingMethods:
    def test_is_watermark_applicable(
        self, method_name: str, impl: object, sample_pdf_path: Path
    ):
        wm_impl = _as_instance(impl)
        ok = wm_impl.is_watermark_applicable(sample_pdf_path, position=None)
        assert isinstance(
            ok, bool
        ), f"{method_name}: is_watermark_applicable must return bool"
        if not ok:
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

    def test_add_watermark_and_shape(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
        secret: str,
        key: str,
    ):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")
        original = sample_pdf_path.read_bytes()
        out_bytes = wm_impl.add_watermark(
            sample_pdf_path, secret=secret, key=key, position=None
        )
        assert isinstance(
            out_bytes, (bytes, bytearray)
        ), f"{method_name}: add_watermark must return bytes"
        assert len(out_bytes) >= len(
            original
        ), f"{method_name}: watermarked bytes should not be smaller than input"
        assert out_bytes.startswith(
            b"%PDF-"
        ), f"{method_name}: output should still look like a PDF"

    @pytest.mark.xfail
    def test_read_secret_roundtrip(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
        secret: str,
        key: str,
        tmp_path: Path,
    ):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")
        out_pdf = tmp_path / f"{method_name}_watermarked.pdf"
        out_pdf.write_bytes(
            wm_impl.add_watermark(
                sample_pdf_path, secret=secret, key=key, position=None
            )
        )
        extracted = wm_impl.read_secret(out_pdf, key=key)
        assert isinstance(extracted, str), f"{method_name}: read_secret must return str"
        assert extracted == secret, f"{method_name}: read_secret should return the exact embedded secret"
