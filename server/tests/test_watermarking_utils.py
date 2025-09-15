import pytest
from unittest.mock import MagicMock

# 导入要测试的模块和相关类
from server.src import watermarking_utils
from server.src.watermarking_method import WatermarkingMethod


# --- 1. 测试注册表功能 ---

class TestRegistry:
    """测试方法注册表 (register_method, get_method)。"""

    # 创建一个虚拟的水印方法类用于测试
    class DummyMethod(WatermarkingMethod):
        name = "dummy-method"

        def get_usage(self): return "dummy"

        def add_watermark(self, pdf, secret, key, position=None): return b''

        def is_watermark_applicable(self, pdf, position=None): return True

        def read_secret(self, pdf, key): return "dummy"

    def test_get_method_by_name(self):
        """测试：可以通过字符串名称成功获取一个已注册的方法。"""
        # "toy-eof" 是默认注册的方法之一
        method = watermarking_utils.get_method("toy-eof")
        assert isinstance(method, WatermarkingMethod)
        assert method.name == "toy-eof"

    def test_get_method_passthrough(self):
        """测试：如果传入的已经是方法实例，应直接返回该实例。"""
        instance = self.DummyMethod()
        method = watermarking_utils.get_method(instance)
        assert method is instance

    def test_get_method_raises_key_error_for_unknown_name(self):
        """测试：请求一个未注册的方法名称时，应抛出 KeyError。"""
        with pytest.raises(KeyError, match="Unknown watermarking method"):
            watermarking_utils.get_method("nonexistent-method")

    def test_register_method(self):
        """测试：可以成功注册一个新方法，并能通过名称获取到它。"""
        instance = self.DummyMethod()

        # 1. 保存原始的 METHODS 字典
        original_methods = watermarking_utils.METHODS.copy()
        try:
            # 2. 在 try 块中执行测试逻辑
            watermarking_utils.register_method(instance)

            # 验证新方法已被注册
            retrieved_method = watermarking_utils.get_method("dummy-method")
            assert retrieved_method is instance
        finally:
            # 3. 在 finally 块中，无论测试成功还是失败，都确保恢复原始字典
            watermarking_utils.METHODS = original_methods


# --- 2. 测试公共 API 包装器 ---

class TestApiWrappers:
    """测试 apply_watermark, read_watermark 等包装函数。"""

    @pytest.fixture
    def mock_method(self, mocker) -> MagicMock:
        """创建一个 mock 的水印方法实例。"""
        mock = MagicMock(spec=WatermarkingMethod)
        mock.name = "mock-method"
        return mock

    def test_apply_watermark_delegates_correctly(self, mock_method, mocker):
        """测试：apply_watermark 应正确地将参数委托给底层方法。"""
        mocker.patch.object(watermarking_utils, 'get_method', return_value=mock_method)

        watermarking_utils.apply_watermark(
            method="mock-method",
            pdf=b'%PDF-test',
            secret="s",
            key="k",
            position="p"
        )

        # 断言底层方法被以完全相同的参数调用了一次
        mock_method.add_watermark.assert_called_once_with(
            pdf=b'%PDF-test', secret="s", key="k", position="p"
        )

    def test_read_watermark_delegates_correctly(self, mock_method, mocker):
        """测试：read_watermark 应正确地委托调用。"""
        mocker.patch.object(watermarking_utils, 'get_method', return_value=mock_method)

        watermarking_utils.read_watermark(
            method="mock-method", pdf=b'%PDF-test', key="k"
        )

        mock_method.read_secret.assert_called_once_with(pdf=b'%PDF-test', key="k")


# --- 3. 测试 PDF 解析功能 ---

class TestExplorePdf:
    """测试 explore_pdf 函数的两种路径：使用 fitz 和不使用 fitz。"""

    @pytest.fixture
    def sample_pdf_bytes(self) -> bytes:
        return b"%PDF-1.4\n1 0 obj\n<< /Type /Page >>\nendobj\n2 0 obj\n<</Type/Catalog>>\nendobj\n%%EOF"

    def test_explore_pdf_with_fitz_mocked(self, sample_pdf_bytes, mocker):
        """测试：当 fitz (PyMuPDF) 库可用时的解析路径。"""
        # 创建一个 mock 的 fitz 模块和文档对象
        mock_doc = MagicMock()
        mock_doc.page_count = 1
        mock_doc.xref_length.return_value = 3  # 模拟有2个对象 (xref 1 和 2)
        mock_doc.load_page.return_value.bound.return_value = (0, 0, 100, 100)  # bbox
        # 模拟 xref 查询
        mock_doc.xref_object.side_effect = ["<< /Type /Page >>", "<< /Type /Catalog >>"]
        mock_doc.xref_is_stream.return_value = False

        mock_fitz = MagicMock()
        mock_fitz.open.return_value = mock_doc

        # 关键: 注入 mock 的 fitz 模块，让 'import fitz' 成功
        mocker.patch.dict('sys.modules', {'fitz': mock_fitz})

        result = watermarking_utils.explore_pdf(sample_pdf_bytes)

        # 验证输出结构是否符合 fitz 路径的预期
        assert result['type'] == 'Document'
        assert len(result['children']) > 0

        child_types = [c['type'] for c in result['children']]
        assert 'Page' in child_types
        assert 'Catalog' in child_types

    def test_explore_pdf_fallback_parser(self, sample_pdf_bytes, mocker):
        """测试：当 fitz 库不可用时，回退到基于正则表达式的解析路径。"""
        # 关键: 让 'import fitz' 失败
        mocker.patch.dict('sys.modules', {'fitz': None})

        result = watermarking_utils.explore_pdf(sample_pdf_bytes)

        # 验证输出结构是否符合 fallback 路径的预期
        assert result['type'] == 'Document'
        assert len(result['children']) > 0

        # Fallback 解析器会找到 Page 类型的对象，并为它额外创建一个 page:id 节点
        child_ids = [c['id'] for c in result['children']]
        assert 'page:0000' in child_ids
        assert 'obj:000001:00000' in child_ids
        assert 'obj:000002:00000' in child_ids