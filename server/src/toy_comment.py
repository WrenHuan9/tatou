# toy_comment.py

from watermarking_method import WatermarkingMethod

class ToyComment(WatermarkingMethod):
    """
    一个简单的示例水印方法。
    它通过在PDF文件中插入一个PDF注释对象来隐藏秘密。
    """
        
    def add_watermark(self, pdf_bytes: bytes, secret: str, key: str, **kwargs) -> bytes:
        """在PDF末尾添加一个包含秘密的注释对象。"""
        # key 在这里没有使用
        comment_obj = f"\n% TATOU_SECRET: {secret}\n"
        return pdf_bytes + comment_obj.encode("utf-8")

    def read_secret(self, pdf_bytes: bytes, key: str) -> str:
        """通过正则表达式搜索PDF注释来找到秘密。"""
        import re
        # 在二进制数据中搜索我们的特定注释格式
        match = re.search(rb"% TATOU_SECRET: (.*)\n", pdf_bytes)
        if match:
            # 如果找到，解码并返回秘密
            return match.group(1).decode("utf-8", "ignore")
        return "No secret found with toy-comment method."
        
    def is_watermark_applicable(self, pdf_bytes: bytes, **kwargs) -> bool:
        """这个简单方法总是适用。"""
        return True
    def get_usage(self) -> str:
        """返回使用说明。"""
        return "A simple method that hides the secret inside a PDF comment line."