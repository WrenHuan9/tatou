# server/test/unit/test_metadata_watermark.py

import unittest
from pathlib import Path
import pypdf  # 导入 pypdf 用于验证
from io import BytesIO

# 确保测试脚本可以找到 'src' 目录下的模块
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))

from watermarking_utils import apply_watermark, read_watermark
from watermarking_method import SecretNotFoundError, InvalidKeyError


class TestMetadataWatermark(unittest.TestCase):

    def setUp(self):
        """准备一个空白 PDF 和测试数据。"""
        self.secret_message = "这是一个元数据水印的秘密！"
        self.key = "my-metadata-key-123"
        self.wrong_key = "wrong-key-789"

        # 在内存中创建一个简单的 PDF
        writer = pypdf.PdfWriter()
        writer.add_blank_page(width=200, height=200)
        buffer = BytesIO()
        writer.write(buffer)
        self.original_pdf_bytes = buffer.getvalue()

    def test_full_lifecycle(self):
        """测试'metadata'方法的完整生命周期：添加、成功读取、失败读取。"""
        method_name = "metadata"

        # 1. 添加水印并验证
        watermarked_bytes = apply_watermark(
            method=method_name,
            pdf=self.original_pdf_bytes,
            secret=self.secret_message,
            key=self.key
        )

        # 验证方式：打开新生成的PDF，检查元数据中是否存在我们的字段
        reader = pypdf.PdfReader(BytesIO(watermarked_bytes))
        self.assertIn("/TatouSecret", reader.metadata)

        # 2. 使用正确的密钥成功读取
        retrieved_secret = read_watermark(
            method=method_name,
            pdf=watermarked_bytes,
            key=self.key
        )
        self.assertEqual(self.secret_message, retrieved_secret)

        # 3. 在原始文件上读取（应该失败，因为没有水印）
        with self.assertRaises(SecretNotFoundError):
            read_watermark(method=method_name, pdf=self.original_pdf_bytes, key=self.key)

        # 4. 使用错误的密钥读取（应该失败，因为签名验证不通过）
        with self.assertRaises(InvalidKeyError):
            read_watermark(method=method_name, pdf=watermarked_bytes, key=self.wrong_key)


if __name__ == '__main__':
    unittest.main()