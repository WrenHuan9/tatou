# toy_bridge_eof.py

from watermarking_method import WatermarkingMethod

class ToyBridgeEOF(WatermarkingMethod):
    """
    一个简单的示例水印方法。
    它通过在PDF文件末尾（EOF）之后附加一个“桥”（bridge）和秘密信息来实现水印。
    这是一个非常脆弱的方法，很容易被破坏，仅用于教学演示。
    """

    def add_watermark(self, pdf_bytes: bytes, secret: str, key: str, **kwargs) -> bytes:
        """在PDF末尾附加一个标记和秘密。"""
        # "key"在这里被用作一个分隔符桥梁
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        secret_bytes = secret.encode("utf-8")
        return pdf_bytes + bridge + secret_bytes

    def read_secret(self, pdf_bytes: bytes, key: str) -> str:
        """从PDF末尾读取秘密。"""
        bridge = f"\n%%--{key}--%%\n".encode("utf-8")
        parts = pdf_bytes.split(bridge)
        if len(parts) > 1:
            # 返回桥之后的所有内容
            return parts[-1].decode("utf-8", "ignore")
        return "No secret found with toy-bridge-eof method."

    def is_watermark_applicable(self, pdf_bytes: bytes, **kwargs) -> bool:
        """这个简单方法总是适用。"""
        return True

    def get_usage(self) -> str:
        """返回使用说明。"""
        return "A simple method that appends a bridge and the secret after the PDF's EOF. The 'key' is used as the bridge delimiter."