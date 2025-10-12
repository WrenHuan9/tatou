# server/test/unit/test_metadata_watermark.py

import unittest
from pathlib import Path
import pypdf
from io import BytesIO
import json
import base64
from unittest.mock import patch, MagicMock

# 确保测试脚本可以找到 'src' 目录下的模块
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))

from watermarking_utils import apply_watermark, read_watermark
from watermarking_method import SecretNotFoundError, InvalidKeyError
from metadata_watermark import MetadataWatermark


class TestMetadataWatermark(unittest.TestCase):

    def setUp(self):
        """准备一个空白 PDF 和测试数据。"""
        self.secret_message = "这是一个元数据水印的秘密！"
        self.key = "my-metadata-key-123"
        self.wrong_key = "wrong-key-789"
        self.method = "metadata"
        self.impl = MetadataWatermark()

        writer = pypdf.PdfWriter()
        writer.add_blank_page(width=200, height=200)
        buffer = BytesIO()
        writer.write(buffer)
        self.original_pdf_bytes = buffer.getvalue()

    def test_full_lifecycle(self):
        """测试'metadata'方法的完整生命周期：添加、成功读取、失败读取。"""
        watermarked_bytes = apply_watermark(
            method=self.method,
            pdf=self.original_pdf_bytes,
            secret=self.secret_message,
            key=self.key
        )

        reader = pypdf.PdfReader(BytesIO(watermarked_bytes))
        self.assertIn("/TatouSecret", reader.metadata)

        retrieved_secret = read_watermark(
            method=self.method,
            pdf=watermarked_bytes,
            key=self.key
        )
        self.assertEqual(self.secret_message, retrieved_secret)

        with self.assertRaises(SecretNotFoundError):
            read_watermark(method=self.method, pdf=self.original_pdf_bytes, key=self.key)

        with self.assertRaises(InvalidKeyError):
            read_watermark(method=self.method, pdf=watermarked_bytes, key=self.wrong_key)

    def test_applicability_edge_cases(self):
        """测试 is_watermark_applicable 方法的边缘情况。"""
        self.assertTrue(self.impl.is_watermark_applicable(self.original_pdf_bytes))

        unparseable_pdf = b"%PDF-this-is-not-a-valid-pdf"
        self.assertFalse(self.impl.is_watermark_applicable(unparseable_pdf))


        with patch('metadata_watermark.pypdf.PdfReader') as mock_reader_class:
            mock_reader_instance = MagicMock()
            mock_reader_instance.pages = []
            mock_reader_class.return_value = mock_reader_instance


            self.assertFalse(self.impl.is_watermark_applicable(self.original_pdf_bytes))

    def test_applicability_generic_exception(self):
        """测试 is_watermark_applicable 能处理通用异常 (覆盖 except Exception)"""
        with patch('metadata_watermark.pypdf.PdfReader') as mock_reader_class:
            mock_reader_class.side_effect = Exception("Unexpected parsing error")

            self.assertFalse(self.impl.is_watermark_applicable(self.original_pdf_bytes))

    def _create_pdf_with_raw_payload(self, payload: str) -> bytes:
        """辅助方法：创建一个包含指定原始载荷的PDF。"""
        writer = pypdf.PdfWriter()
        writer.add_blank_page(width=10, height=10)
        writer.add_metadata({"/TatouSecret": payload})
        buffer = BytesIO()
        writer.write(buffer)
        return buffer.getvalue()

    def test_read_secret_malformed_payloads(self):
        """测试 read_secret 方法处理各种格式错误的载荷。"""
        test_cases = {
            "not_base64": "this-is-not-base64-!@#$",
            "not_json": base64.urlsafe_b64encode(b"this is not json").decode('ascii'),
            "wrong_version": base64.urlsafe_b64encode(json.dumps({"v": 2}).encode()).decode('ascii'),
            "not_a_dict": base64.urlsafe_b64encode(json.dumps([1, 2, 3]).encode()).decode('ascii')
        }

        for name, payload in test_cases.items():
            with self.subTest(payload_type=name):
                malformed_pdf = self._create_pdf_with_raw_payload(payload)
                with self.assertRaises(SecretNotFoundError):
                    self.impl.read_secret(malformed_pdf, self.key)

    def test_get_usage(self):
        """测试 get_usage 方法 (覆盖 return 语句)"""
        usage_string = self.impl.get_usage()
        self.assertIsInstance(usage_string, str)
        self.assertIn("metadata", usage_string.lower())


if __name__ == '__main__':
    unittest.main()