# tests/test_unsafe_bash_bridge.py

import pytest
import subprocess
from pathlib import Path
import os  # <-- 确保导入 os 模块

# Import the class you want to test
from server.src.unsafe_bash_bridge_append_eof import UnsafeBashBridgeAppendEOF


# ... (顶部的 instance 和 pdf_file fixture 保持不变) ...
@pytest.fixture
def instance():
    """Provides a fresh instance of the class for each test."""
    return UnsafeBashBridgeAppendEOF()


@pytest.fixture
def pdf_file(tmp_path: Path) -> Path:
    """Creates a dummy PDF file in a temporary directory and returns its path."""
    file_path = tmp_path / "test_document.pdf"
    file_path.write_bytes(b"%PDF-1.4\nSome PDF content here.\n%%EOF")
    return file_path


# ---


class TestUnsafeBashBridgeAppendEOF:
    """Tests for the UnsafeBashBridgeAppendEOF watermarking method."""

    # ... (test_get_usage 和 test_is_watermark_applicable 保持不变) ...
    def test_get_usage(self, instance: UnsafeBashBridgeAppendEOF):
        assert "appends a watermark record" in instance.get_usage()

    def test_is_watermark_applicable(self, instance: UnsafeBashBridgeAppendEOF):
        assert instance.is_watermark_applicable(pdf="any/path") is True

    # ---

    ## Tests for add_watermark ##

    def test_add_watermark_happy_path(self, instance: UnsafeBashBridgeAppendEOF, pdf_file: Path):
        secret = "this-is-the-secret"
        original_content = pdf_file.read_bytes()
        watermarked_content = instance.add_watermark(pdf=pdf_file, secret=secret, key="ignored")
        expected_content = original_content + secret.encode('utf-8')
        assert watermarked_content == expected_content

    # --- 修正失败 1 ---
    def test_add_watermark_raises_on_process_error(self, instance: UnsafeBashBridgeAppendEOF, mocker):
        """
        Tests that a CalledProcessError is raised if the subprocess fails.
        """
        # 解决方案: 同时 mock 掉 load_pdf_bytes 来避免 FileNotFoundError
        mocker.patch(
            'server.src.unsafe_bash_bridge_append_eof.load_pdf_bytes',
            return_value=b''
        )
        mocker.patch(
            'subprocess.run',
            side_effect=subprocess.CalledProcessError(returncode=1, cmd="mocked command")
        )
        with pytest.raises(subprocess.CalledProcessError):
            # 即使文件不存在，测试也能继续，因为 load_pdf_bytes 被 mock 了
            instance.add_watermark(pdf=Path("non_existent_file.pdf"), secret="any", key="any")

    # --- 修正失败 2 ---
    def test_add_watermark_is_vulnerable_to_command_injection(self, instance: UnsafeBashBridgeAppendEOF, pdf_file: Path,
                                                              tmp_path: Path):
        """
        SECURITY TEST: Proves that the `secret` parameter can be used for command injection.
        """
        # 解决方案: 临时切换当前工作目录，以确保注入命令在预期位置执行
        original_cwd = os.getcwd()
        os.chdir(tmp_path)

        injection_file = tmp_path / "injection_successful.txt"
        assert not injection_file.exists()

        malicious_secret = '"; touch "injection_successful.txt'

        try:
            # pdf_file 是绝对路径，不受 chdir 影响
            instance.add_watermark(pdf=pdf_file, secret=malicious_secret, key="ignored")
        except subprocess.CalledProcessError:
            pass
        finally:
            # 确保测试结束后恢复原始工作目录
            os.chdir(original_cwd)

        assert injection_file.exists(), "Command injection vulnerability confirmed in add_watermark!"

    ## Tests for read_secret ##

    # --- 修正失败 3 ---
    def test_read_secret_happy_path(self, instance: UnsafeBashBridgeAppendEOF, tmp_path: Path):
        """
        Tests that a secret appended after %%EOF can be correctly read.
        """
        secret = "secret-after-eof"
        # 解决方案: 在 %%EOF 和 secret 之间添加一个换行符 \n
        content = f"%PDF-1.4\n%%EOF\n{secret}".encode('utf-8')
        watermarked_file = tmp_path / "watermarked.pdf"
        watermarked_file.write_bytes(content)

        extracted_secret = instance.read_secret(pdf=watermarked_file, key="ignored")

        assert extracted_secret.strip() == secret

    def test_read_secret_no_secret_present(self, instance: UnsafeBashBridgeAppendEOF, pdf_file: Path):
        extracted_secret = instance.read_secret(pdf=pdf_file, key="ignored")
        assert extracted_secret == ""

    # --- 修正失败 4 ---
    def test_read_secret_is_vulnerable_to_command_injection(self, instance: UnsafeBashBridgeAppendEOF, tmp_path: Path):
        """
        SECURITY TEST: Proves that the filename (`pdf` parameter) can be used for command injection.
        """
        # 解决方案: 同样使用临时切换工作目录的技巧
        original_cwd = os.getcwd()
        os.chdir(tmp_path)

        injection_file = tmp_path / "injection_from_read.txt"
        assert not injection_file.exists()

        # 使用一个相对路径的恶意文件名
        malicious_filename = 'safe.pdf; touch "injection_from_read.txt"'
        malicious_file_path = tmp_path / malicious_filename
        malicious_file_path.touch()

        try:
            # 因为我们改变了工作目录，所以可以直接传递相对路径
            instance.read_secret(pdf=Path(malicious_filename), key="ignored")
        except subprocess.CalledProcessError:
            pass
        finally:
            os.chdir(original_cwd)

        assert injection_file.exists(), "Command injection vulnerability confirmed in read_secret!"