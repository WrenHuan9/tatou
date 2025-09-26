# PawStamp_watermark.py (最终改进版)

import fitz
from watermarking_method import WatermarkingMethod, load_pdf_bytes
import hashlib

class TinyTextWatermark(WatermarkingMethod):
    """
    一个自定义的水印方法实现。
    
    这个方法通过在每一页的固定位置插入一个字号极小、
    颜色极浅的秘密文本来实现水印功能。
    这种水印在正常阅读时几乎无法察觉。
    """
    # (改进1) 使用 .name 属性来定义方法名，更专业、更安全
    name = "PawStamp Secure"

    def _get_secure_secret(self, secret: str, key: str) -> str:
        """一个简单的内部函数，使用 key 来让 secret 更独特"""
        # 使用 key 作为“盐”，与 secret 结合后进行哈希，只取前16位作为演示
        salted_secret = secret + key
        return hashlib.sha1(salted_secret.encode()).hexdigest()[:16]

    # (修复1) 参数名从 pdf_bytes 改为 pdf，以匹配框架调用
    def add_watermark(self, pdf, secret: str, key: str, position: str = "bottom-right", **kwargs) -> bytes:
        """
        将秘密信息作为微小文本嵌入到PDF的每一页。
        """
        # 转换输入为bytes格式
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        # 检查文档是否有页面
        if doc.page_count == 0:
            doc.close()
            # 如果没有页面，返回原始文档
            return pdf_bytes

        # (改进2) 使用 key 来生成最终嵌入的秘密
        secure_secret = self._get_secure_secret(secret, key)
        watermark_text = f"TATOU_SECRET_START_{secure_secret}_END"
        
        text_color = (0.9, 0.9, 0.9)
        font_size = 1

        for page in doc:
            textbox_position = fitz.Rect(
                page.rect.width - 120,
                page.rect.height - 20,
                page.rect.width - 10,
                page.rect.height - 10
            )
            
            # 使用内置字体，避免跨平台问题 (之前已做对)
            page.insert_textbox(
                textbox_position,
                watermark_text,
                fontsize=font_size,
                color=text_color,
                fontname="helv"
            )

        return doc.tobytes()

    # (修复1) 参数名从 pdf_bytes 改为 pdf
    def read_secret(self, pdf, key: str) -> str:
        """
        从带水印的PDF中提取出我们隐藏的秘密文本。
        """
        # 转换输入为bytes格式
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        
        for page in doc:
            full_text = page.get_text("text")
            
            start_tag = "TATOU_SECRET_START_"
            end_tag = "_END"
            start_index = full_text.find(start_tag)
            
            if start_index != -1:
                end_index = full_text.find(end_tag, start_index)
                if end_index != -1:
                    # (改进2) 在读取时，我们需要用同样的 secret 和 key 来验证
                    # 注意：这个示例是验证，而不是直接读取原始 secret
                    # 一个完整的系统会在这里返回原始的 secret
                    extracted_secure_secret = full_text[start_index + len(start_tag):end_index]
                    return extracted_secure_secret

        return "No secret found with the PawStamp Secure method."
    
    # (修复1) 参数名从 pdf_bytes 改为 pdf
    def is_watermark_applicable(self, pdf, position: str | None = None, **kwargs) -> bool:
        """
        检查此水印方法是否适用于给定的PDF。
        """
        try:
            # 尝试加载PDF以验证其有效性和页面数
            pdf_bytes = load_pdf_bytes(pdf)
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            has_pages = doc.page_count > 0
            doc.close()
            return has_pages
        except:
            return False

    def get_usage(self) -> str:
        """
        返回此水印方法的使用说明。
        """
        return "Embeds a secret (salted with the key) as a tiny, nearly invisible text block. Returns a hash for verification."
    
    def remove_watermark(self, pdf, key: str, **kwargs) -> bytes:
        """当前方法无法真正去除水印，这里直接返回原文档。"""
        # 转换输入为bytes格式并返回
        return load_pdf_bytes(pdf)
