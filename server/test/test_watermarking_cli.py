import pytest
import sys
import json
from pathlib import Path
from io import StringIO

# 导入要测试的主函数和自定义异常
from server.src.watermarking_cli import main
from server.src.watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
)


# --- 辅助 Fixtures ---

@pytest.fixture
def pdf_file(tmp_path: Path) -> Path:
    """创建一个虚拟的 PDF 文件用于测试。"""
    file = tmp_path / "document.pdf"
    file.write_text("dummy pdf content")
    return file


# --- 测试主函数和错误处理 ---

class TestCliMain:
    """测试 CLI 的主入口和通用的错误处理逻辑。"""

    def test_main_no_args_shows_help(self, capsys):
        """测试：不带任何参数运行时，应打印帮助信息并以错误码退出。"""
        with pytest.raises(SystemExit) as e:
            main([])
        assert e.value.code == 2  # argparse 在缺少参数时退出码为 2

        outerr = capsys.readouterr()
        assert "usage: pdfwm" in outerr.err

    def test_main_version_flag(self, capsys):
        """测试：--version 参数应打印版本信息并成功退出。"""
        with pytest.raises(SystemExit) as e:
            main(["--version"])
        assert e.value.code == 0

        outerr = capsys.readouterr()
        assert "pdfwm" in outerr.out

    @pytest.mark.parametrize("error_to_raise, expected_exit_code, error_text", [
        (FileNotFoundError("test file not found"), 2, "error: test file not found"),
        (ValueError("bad value"), 2, "error: bad value"),
        (SecretNotFoundError("secret gone"), 3, "secret not found: secret gone"),
        (InvalidKeyError("wrong key"), 4, "invalid key: wrong key"),
        (WatermarkingError("generic wm error"), 5, "watermarking error: generic wm error"),
    ])
    def test_main_error_to_exit_code_mapping(self, mocker, capsys, error_to_raise, expected_exit_code, error_text):
        """测试：不同的异常应被捕获并映射到正确的退出码和错误信息。"""
        # 我们 mock embed 命令的函数，让它抛出指定的异常
        mocker.patch('server.src.watermarking_cli.cmd_embed', side_effect=error_to_raise)

        # 构造一个能触发 cmd_embed 的最小命令
        argv = ["embed", "in.pdf", "out.pdf", "--secret", "s", "--key", "k"]
        exit_code = main(argv)

        assert exit_code == expected_exit_code
        outerr = capsys.readouterr()
        assert error_text in outerr.err


# --- 测试各个子命令 ---

class TestCliCommands:
    """测试 methods, explore, embed, extract 子命令。"""

    def test_cmd_methods(self, mocker, capsys):
        """测试：methods 命令应列出所有可用的方法。"""
        mocker.patch('server.src.watermarking_cli.METHODS', {"method-a": None, "method-b": None})

        exit_code = main(["methods"])

        assert exit_code == 0
        outerr = capsys.readouterr()
        assert "method-a" in outerr.out
        assert "method-b" in outerr.out

    def test_cmd_explore_to_stdout(self, pdf_file, mocker, capsys):
        """测试：explore 命令应将 JSON 树打印到标准输出。"""
        mock_tree = {"object": 1, "content": "test"}
        mocker.patch('server.src.watermarking_cli.explore_pdf', return_value=mock_tree)

        exit_code = main(["explore", str(pdf_file)])

        assert exit_code == 0
        outerr = capsys.readouterr()
        # 验证输出是否为格式化的 JSON
        assert json.loads(outerr.out) == mock_tree

    def test_cmd_explore_to_file(self, pdf_file, tmp_path, mocker):
        """测试：explore --out 应将 JSON 树写入到文件。"""
        output_file = tmp_path / "tree.json"
        mock_tree = {"object": 2}
        mocker.patch('server.src.watermarking_cli.explore_pdf', return_value=mock_tree)

        exit_code = main(["explore", str(pdf_file), "--out", str(output_file)])

        assert exit_code == 0
        assert output_file.exists()
        assert json.loads(output_file.read_text()) == mock_tree

    def test_cmd_embed_happy_path(self, pdf_file, tmp_path, mocker, capsys):
        """测试：embed 命令成功执行的完整流程。"""
        output_file = tmp_path / "watermarked.pdf"
        mocker.patch('server.src.watermarking_cli.is_watermarking_applicable', return_value=True)
        mock_apply = mocker.patch('server.src.watermarking_cli.apply_watermark', return_value=b"watermarked-content")

        argv = [
            "embed", str(pdf_file), str(output_file),
            "--secret", "my-secret", "--key", "my-key"
        ]
        exit_code = main(argv)

        assert exit_code == 0
        mock_apply.assert_called_once_with(
            method="toy-eof", pdf=str(pdf_file),
            secret="my-secret", key="my-key", position=None
        )
        assert output_file.read_bytes() == b"watermarked-content"
        outerr = capsys.readouterr()
        assert f"Wrote watermarked PDF -> {output_file}" in outerr.out

    def test_cmd_embed_resolves_secret_from_stdin(self, pdf_file, tmp_path, mocker):
        """测试：embed 命令能从标准输入读取 secret。"""
        output_file = tmp_path / "watermarked.pdf"
        mocker.patch('server.src.watermarking_cli.is_watermarking_applicable', return_value=True)
        mock_apply = mocker.patch('server.src.watermarking_cli.apply_watermark', return_value=b"mocked bytes")

        # 模拟标准输入
        mocker.patch.object(sys, 'stdin', StringIO('secret from stdin'))

        argv = [
            "embed", str(pdf_file), str(output_file),
            "--secret-stdin", "--key", "my-key"
        ]
        main(argv)

        # 验证 apply_watermark 是否收到了正确的 secret
        assert mock_apply.call_args.kwargs['secret'] == 'secret from stdin'

    def test_cmd_embed_resolves_key_from_prompt(self, pdf_file, tmp_path, mocker):
        """测试：embed 命令能通过交互式提示读取 key。"""
        output_file = tmp_path / "watermarked.pdf"
        mocker.patch('server.src.watermarking_cli.is_watermarking_applicable', return_value=True)
        mock_apply = mocker.patch('server.src.watermarking_cli.apply_watermark', return_value=b"mocked bytes")

        # 模拟 getpass.getpass 的返回值
        mocker.patch('getpass.getpass', return_value="key from prompt")

        argv = [
            "embed", str(pdf_file), str(output_file),
            "--secret", "s", "--key-prompt"
        ]
        main(argv)

        assert mock_apply.call_args.kwargs['key'] == 'key from prompt'

    def test_cmd_extract_happy_path(self, pdf_file, mocker, capsys):
        """测试：extract 命令成功提取 secret 并打印到标准输出。"""
        mock_read = mocker.patch('server.src.watermarking_cli.read_watermark', return_value="the-recovered-secret")

        argv = ["extract", str(pdf_file), "--key", "my-key"]
        exit_code = main(argv)

        assert exit_code == 0
        mock_read.assert_called_once_with(method="toy-eof", pdf=str(pdf_file), key="my-key")
        outerr = capsys.readouterr()
        assert "the-recovered-secret" in outerr.out