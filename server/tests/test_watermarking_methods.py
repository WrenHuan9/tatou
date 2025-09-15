import pytest
from pathlib import Path
import io

# 导入需要测试的所有内容
from server.src.watermarking_method import (
    is_pdf_bytes,
    load_pdf_bytes,
    WatermarkingMethod,
    PdfSource,  # 导入类型别名用于测试
)


# --- 1. 测试 is_pdf_bytes 辅助函数 ---

class TestIsPdfBytes:
    """测试 is_pdf_bytes 函数。"""

    def test_is_pdf_bytes_true_for_valid_header(self):
        """测试：对于包含有效头部的字节串，应返回 True。"""
        assert is_pdf_bytes(b"%PDF-1.7\n%%EOF") is True

    def test_is_pdf_bytes_false_for_invalid_header(self):
        """测试：对于不包含有效头部的字节串，应返回 False。"""
        assert is_pdf_bytes(b"this is just a text file") is False

    def test_is_pdf_bytes_false_for_empty_bytes(self):
        """测试：对于空字节串，应返回 False。"""
        assert is_pdf_bytes(b"") is False


# --- 2. 测试 load_pdf_bytes 辅助函数 ---

class TestLoadPdfBytes:
    """全面测试 load_pdf_bytes 函数对不同输入源的处理能力。"""

    # 使用 fixture 提供一份标准的 PDF 内容，方便复用
    @pytest.fixture
    def pdf_content(self) -> bytes:
        return b"%PDF-1.4\n<dummy content>"

    def test_load_from_bytes(self, pdf_content: bytes):
        """测试：当输入已经是 bytes 时，应直接返回。"""
        assert load_pdf_bytes(pdf_content) == pdf_content

    def test_load_from_path(self, tmp_path: Path, pdf_content: bytes):
        """测试：当输入是 str 或 Path 对象时，应从文件读取内容。"""
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)

        # 测试 str 路径
        assert load_pdf_bytes(str(pdf_file)) == pdf_content
        # 测试 Path 对象
        assert load_pdf_bytes(pdf_file) == pdf_content

    def test_load_from_file_handle(self, tmp_path: Path, pdf_content: bytes):
        """测试：当输入是一个打开的二进制文件句柄时，应从中读取内容。"""
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)

        with open(pdf_file, "rb") as fh:
            assert load_pdf_bytes(fh) == pdf_content

    def test_load_from_bytesio(self, pdf_content: bytes):
        """测试：当输入是一个内存中的二进制流时，应从中读取内容。"""
        bytes_io_stream = io.BytesIO(pdf_content)
        assert load_pdf_bytes(bytes_io_stream) == pdf_content

    def test_raises_file_not_found_for_nonexistent_path(self):
        """测试：对于不存在的文件路径，应抛出 FileNotFoundError。"""
        with pytest.raises(FileNotFoundError):
            load_pdf_bytes("path/to/nonexistent/file.pdf")

    def test_raises_value_error_for_non_pdf_content(self):
        """测试：对于内容不是 PDF 的输入，应抛出 ValueError。"""
        non_pdf_content = b"this is not a pdf"
        with pytest.raises(ValueError, match="missing %PDF header"):
            load_pdf_bytes(non_pdf_content)

    def test_raises_type_error_for_unsupported_type(self):
        """测试：对于不支持的输入类型，应抛出 TypeError。"""
        with pytest.raises(TypeError, match="Unsupported PdfSource"):
            load_pdf_bytes(12345)  # 整数是无效输入


# --- 3. 测试 WatermarkingMethod 抽象基类 ---

class TestWatermarkingMethodABC:
    """测试 WatermarkingMethod 抽象基类（ABC）的契约是否有效。"""

    def test_cannot_instantiate_abc_directly(self):
        """测试：不能直接实例化抽象基类。"""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            WatermarkingMethod()

    def test_subclass_must_implement_all_abstract_methods(self):
        """测试：不完整的子类在实例化时会失败。"""

        # 这个子类故意不实现任何抽象方法
        class IncompleteMethod(WatermarkingMethod):
            pass

        with pytest.raises(TypeError):
            IncompleteMethod()

        # 这个子类只实现了一部分抽象方法
        class PartialMethod(WatermarkingMethod):
            def add_watermark(self, pdf, secret, key, position=None):
                return b""
            # 故意缺少 read_secret, get_usage, is_watermark_applicable

        with pytest.raises(TypeError):
            PartialMethod()

    def test_concrete_subclass_can_be_instantiated(self):
        """测试：完整实现了所有抽象方法的子类可以被成功实例化。"""

        class CompleteMethod(WatermarkingMethod):
            def get_usage(self) -> str:
                return "Usage"

            def add_watermark(self, pdf, secret, key, position=None):
                return b"%PDF-watermarked"

            def is_watermark_applicable(self, pdf, position=None) -> bool:
                return True

            def read_secret(self, pdf, key) -> str:
                return "secret"

        # 尝试实例化，不应该抛出任何错误
        try:
            instance = CompleteMethod()
            assert isinstance(instance, WatermarkingMethod)
        except TypeError:
            pytest.fail("A concrete subclass should be instantiable, but it failed.")