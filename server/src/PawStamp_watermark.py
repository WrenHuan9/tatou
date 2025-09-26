# PawStamp_watermark.py (最终改进版)

import fitz
from watermarking_method import WatermarkingMethod, load_pdf_bytes, SecretNotFoundError
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
        现在直接存储原始秘密，而不是哈希值，以便能够正确验证。
        """
        # 转换输入为bytes格式
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        try:
            # 检查文档是否有页面
            if doc.page_count == 0:
                # 如果没有页面，返回原始文档
                doc.close()
                return pdf_bytes

            # 直接使用原始秘密，而不是哈希值
            # 为了安全，我们可以对秘密进行简单的编码，但仍然可以恢复
            import base64
            encoded_secret = base64.b64encode(secret.encode('utf-8')).decode('ascii')
            watermark_text = f"TATOU_SECRET_START_{encoded_secret}_END"
            
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

            result = doc.tobytes()
            doc.close()
            return result
        except Exception as e:
            doc.close()
            raise

    # (修复1) 参数名从 pdf_bytes 改为 pdf
    def read_secret(self, pdf, key: str) -> str:
        """
        从带水印的PDF中提取出我们隐藏的秘密文本。
        现在解码存储的base64编码的秘密并返回原始秘密。
        """
        # 转换输入为bytes格式
        pdf_bytes = load_pdf_bytes(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        
        try:
            for page in doc:
                full_text = page.get_text("text")
                
                start_tag = "TATOU_SECRET_START_"
                end_tag = "_END"
                start_index = full_text.find(start_tag)
                
                if start_index != -1:
                    end_index = full_text.find(end_tag, start_index)
                    if end_index != -1:
                        # 提取存储的base64编码的秘密
                        encoded_secret = full_text[start_index + len(start_tag):end_index]
                        doc.close()
                        
                        try:
                            # 解码base64编码的秘密
                            import base64
                            decoded_secret = base64.b64decode(encoded_secret).decode('utf-8')
                            return decoded_secret
                        except Exception as decode_error:
                            raise SecretNotFoundError(f"Failed to decode secret: {str(decode_error)}")

            # 如果没有找到水印，抛出SecretNotFoundError异常而不是返回字符串
            doc.close()
            raise SecretNotFoundError("No secret found with the PawStamp Secure method.")
        except Exception as e:
            doc.close()
            # 如果是SecretNotFoundError，直接重新抛出
            if isinstance(e, SecretNotFoundError):
                raise
            # 其他异常转换为SecretNotFoundError
            raise SecretNotFoundError(f"Error reading watermark: {str(e)}") from e
    
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
        return "Embeds a secret as a tiny, nearly invisible text block. The secret is base64-encoded for storage and can be fully recovered during reading."
    
    def remove_watermark(self, pdf, key: str, **kwargs) -> bytes:
        """当前方法无法真正去除水印，这里直接返回原文档。"""
        # 转换输入为bytes格式并返回
        return load_pdf_bytes(pdf)
