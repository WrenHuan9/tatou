# tests/test_server.py (基于新的 conftest.py 重构)

from io import BytesIO
from unittest.mock import patch, ANY  # ANY 用于匹配任意参数
import datetime as dt
import pytest
from collections import namedtuple
from pathlib import Path

# 假设 dill 安装了，并且是 server.py 中使用的 _pickle
try:
    import dill as _pickle
except ImportError:
    import pickle as _pickle

# 导入要测试的基类
from server.src.watermarking_method import WatermarkingMethod

class GoodPlugin(WatermarkingMethod):
    """A fully compliant plugin for testing success cases."""
    name = "GoodPlugin"
    def add_watermark(self, pdf, secret, key, position=None): return b"good"
    def read_secret(self, pdf, key, position=None): return "good"
    def get_usage(self): return "A good plugin"
    def is_watermark_applicable(self, **kwargs): return True

class BadApiPlugin(WatermarkingMethod):
    """An incomplete (abstract) plugin missing 'read_secret'."""
    name = "BadApiPlugin"
    def add_watermark(self, pdf, secret, key, position=None): return b"bad"
    def get_usage(self): return "A bad plugin"
    def is_watermark_applicable(self, **kwargs): return True

class PluginForNameTest(WatermarkingMethod):
    """A compliant plugin that intentionally lacks the '.name' attribute."""
    # Note: No 'name' attribute here
    def add_watermark(self, pdf, secret, key, position=None): return b"noname"
    def read_secret(self, pdf, key, position=None): return "noname"
    def get_usage(self): return "A plugin with no name"
    def is_watermark_applicable(self, **kwargs): return True

class BadNameTypePlugin(WatermarkingMethod):
    """一个 '.name' 属性存在但类型不是字符串的插件，用于测试名称类型验证。"""
    name = 123  # 关键：name 属性故意设置为非字符串类型

    def add_watermark(self, pdf, secret, key, position=None): return b"bad_type"
    def read_secret(self, pdf, key, position=None): return "bad_type"
    def get_usage(self): return "A plugin with a non-string name"
    def is_watermark_applicable(self, **kwargs): return True

# test_api.py

@pytest.fixture
def plugin_test_environment(app):
    """
    Creates the file environment for plugin tests using the top-level classes.
    """
    plugins_dir = app.config["STORAGE_DIR"] / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    # Use the globally defined classes
    with open(plugins_dir / "good_plugin.pkl", "wb") as f:
        _pickle.dump(GoodPlugin, f)

    with open(plugins_dir / "bad_api.pkl", "wb") as f:
        _pickle.dump(BadApiPlugin, f)

    with open(plugins_dir / "no_name.pkl", "wb") as f:
        _pickle.dump(PluginForNameTest, f)

    # --- 在这里添加以下代码 ---
    with open(plugins_dir / "bad_name_type.pkl", "wb") as f:
        _pickle.dump(BadNameTypePlugin, f)
    # --- 添加结束 ---

    (plugins_dir / "not_a_pickle.txt").write_text("this is just plain text")

    yield plugins_dir


class TestLoadPlugin:
    """全面测试 /api/load-plugin 端点"""

    def test_load_plugin_success(self, auth_client, plugin_test_environment):
        """测试：成功加载一个合规的插件。"""
        client, headers, _ = auth_client

        rv = client.post("/api/load-plugin", json={"filename": "good_plugin.pkl"}, headers=headers)

        assert rv.status_code == 201
        data = rv.get_json()
        assert data["loaded"] is True
        assert data["registered_as"] == "GoodPlugin"

        # 验证插件确实被注册了
        methods_rv = client.get("/api/get-watermarking-methods")
        assert any(m["name"] == "GoodPlugin" for m in methods_rv.get_json()["methods"])

    def test_load_plugin_missing_filename(self, auth_client):
        """测试：请求中没有提供 filename。"""
        client, headers, _ = auth_client
        rv = client.post("/api/load-plugin", json={}, headers=headers)
        assert rv.status_code == 400
        assert "filename is required" in rv.get_json()["error"]

    def test_load_plugin_file_not_found(self, auth_client, plugin_test_environment):
        """测试：请求的插件文件不存在。"""
        client, headers, _ = auth_client
        rv = client.post("/api/load-plugin", json={"filename": "non_existent.pkl"}, headers=headers)
        assert rv.status_code == 404
        assert "plugin file not found" in rv.get_json()["error"]

    def test_load_plugin_deserialize_error(self, auth_client, plugin_test_environment):
        """测试：文件不是一个有效的 pickle 文件。"""
        client, headers, _ = auth_client
        rv = client.post("/api/load-plugin", json={"filename": "not_a_pickle.txt"}, headers=headers)
        assert rv.status_code == 400
        assert "failed to deserialize plugin" in rv.get_json()["error"]

    def test_load_plugin_uses_class_name_as_fallback(self, auth_client, plugin_test_environment):
        """
        测试：当插件没有 .name 属性时，应成功加载并使用其类名作为后备。
        """
        client, headers, _ = auth_client
        rv = client.post("/api/load-plugin", json={"filename": "no_name.pkl"}, headers=headers)

        assert rv.status_code == 201
        # 【最终修复】现在断言返回的名称是新类名 "PluginForNameTest"
        assert rv.get_json()["registered_as"] == "PluginForNameTest"


    def test_load_plugin_bad_api_is_abstract(self, auth_client, plugin_test_environment):
        """
        测试：加载一个不完整的（抽象的）插件时，应返回 400 错误。
        """
        client, headers, _ = auth_client
        rv = client.post("/api/load-plugin", json={"filename": "bad_api.pkl"}, headers=headers)

        # 现在我们期望一个 400 错误，因为 inspect.isabstract 会正确地拒绝它
        assert rv.status_code == 400
        assert "must be a non-abstract subclass" in rv.get_json()["error"]

    def test_load_plugin_path_creation_error(self, auth_client, mocker):
        """测试：当创建插件目录失败时（例如，权限问题）。"""
        client, headers, _ = auth_client
        # 模拟 Path.mkdir 方法抛出异常
        mocker.patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied"))

        rv = client.post("/api/load-plugin", json={"filename": "any.pkl"}, headers=headers)
        assert rv.status_code == 500
        assert "plugin path error" in rv.get_json()["error"]

    def test_load_plugin_with_non_string_name(self, auth_client, plugin_test_environment):
        """
        测试：加载一个 .name 属性非字符串的插件。
        这将覆盖 `isinstance(method_name, str)` 为 False 的分支。
        """
        client, headers, _ = auth_client
        rv = client.post("/api/load-plugin", json={"filename": "bad_name_type.pkl"}, headers=headers)

        assert rv.status_code == 400
        assert "plugin class must define a readable name" in rv.get_json()["error"]


class TestAuth:
    """测试用户认证，现在使用 mock"""

    def test_create_user_success(self, client, mock_db_connection, mocker):
        # 核心：为这个测试配置 db_mock 的行为
        UserRow = namedtuple("UserRow", ["id", "email", "login"])
        mock_db_connection.execute.side_effect = [
            mocker.MagicMock(lastrowid=99),
            mocker.MagicMock(one=lambda: UserRow(id=99, email="test@example.com", login="testuser")),
        ]

        rv = client.post("/api/create-user", json={
            "email": "test@example.com", "login": "testuser", "password": "password123"
        })

        assert rv.status_code == 201
        assert rv.get_json()["id"] == 99

    def test_create_user_duplicate(self, client, mock_db_connection):
        # 核心：配置 mock 以抛出 IntegrityError
        from sqlalchemy.exc import IntegrityError
        mock_db_connection.execute.side_effect = IntegrityError(None, None, None)

        rv = client.post("/api/create-user", json={
            "email": "test@example.com", "login": "testuser", "password": "password123"
        })

        assert rv.status_code == 409
        assert "email or login already exists" in rv.get_json()["error"]

    def test_login_fail(self, client, mock_db_connection):
        # 核心：配置 mock 返回 None，模拟用户不存在
        mock_db_connection.execute.return_value.first.return_value = None

        rv = client.post("/api/login", json={"login": "nonexistent", "password": "password"})
        assert rv.status_code == 401

    @pytest.mark.parametrize("invalid_payload", [
        {"email": "test@example.com", "login": "user"},  # 缺少 password
        {"email": "test@example.com", "password": "pw"},  # 缺少 login
        {"login": "user", "password": "pw"},  # 缺少 email
        {"email": "test@example.com", "login": "", "password": "pw"},  # login 为空字符串
        {},  # 空 json
    ])
    def test_create_user_missing_fields(self, client, invalid_payload):
        """
        测试：当创建用户时缺少必要字段，应返回 400 错误。
        这将覆盖 `if not email or not login or not password:` 分支。
        """
        rv = client.post("/api/create-user", json=invalid_payload)

        assert rv.status_code == 400
        error_msg = rv.get_json()["error"]
        assert "email, login, and password are required" in error_msg

    def test_create_user_generic_db_error(self, client, mock_db_connection):
        """
        测试：当数据库操作抛出通用异常时，应返回 503 错误。
        这将覆盖 `except Exception as e:` 分支。
        """
        # 核心：让 mock 的数据库连接在执行时直接抛出一个通用异常
        mock_db_connection.execute.side_effect = Exception("Simulated DB connection error")

        # 我们提供一个有效的 payload，以确保代码能进入 try 块
        valid_payload = {
            "email": "another@example.com",
            "login": "anotheruser",
            "password": "password123"
        }

        rv = client.post("/api/create-user", json=valid_payload)

        assert rv.status_code == 503
        error_msg = rv.get_json()["error"]
        assert "database error" in error_msg
        # (可选) 也可以检查原始的异常信息是否被包含
        assert "Simulated DB connection error" in error_msg


class TestDocumentFlow:
    """测试文档流程，现在使用 auth_client 和 mock"""

    def test_upload_document(self, auth_client, mock_db_connection, mocker):
        client, headers, user_info = auth_client

        # 核心：配置 mock 以模拟文档插入
        DocRow = namedtuple("DocRow", ["id", "name", "creation", "sha256_hex", "size"])
        now = dt.datetime.now(dt.UTC)
        mock_db_connection.execute.side_effect = [
            # 第一次调用 (INSERT)
            mocker.MagicMock(),
            # 第二次调用 (SELECT LAST_INSERT_ID())
            mocker.MagicMock(scalar=lambda: 101),
            # 第三次调用 (SELECT after insert)
            mocker.MagicMock(one=lambda: DocRow(
                id=101, name='My Doc', creation=now, sha256_hex='...', size=123
            ))
        ]

        data = {'file': (BytesIO(b"content"), 'test.pdf'), 'name': 'My Doc'}
        rv = client.post("/api/upload-document", data=data, headers=headers)

        assert rv.status_code == 201
        assert rv.get_json()["id"] == 101
        assert rv.get_json()["name"] == "My Doc"

    def test_list_documents(self, auth_client, mock_db_connection):
        client, headers, user_info = auth_client

        # 核心：配置 mock 返回文档列表
        DocRow = namedtuple("DocRow", ["id", "name", "creation", "sha256_hex", "size"])
        now = dt.datetime.now(dt.UTC)
        mock_db_connection.execute.return_value.all.return_value = [
            DocRow(id=1, name='Doc 1', creation=now, sha256_hex='aaa', size=100),
            DocRow(id=2, name='Doc 2', creation=now, sha256_hex='bbb', size=200),
        ]

        rv = client.get("/api/list-documents", headers=headers)
        assert rv.status_code == 200
        docs = rv.get_json()["documents"]
        assert len(docs) == 2
        assert docs[0]["name"] == "Doc 1"

    def test_delete_document_success(self, auth_client, mock_db_connection, app):
        client, headers, user_info = auth_client

        # 1. 先创建一个假文件，以便测试删除它
        # app fixture 现在使用了 tmp_path，所以这是安全的
        doc_path = app.config["STORAGE_DIR"] / "files/testuser/some_file.pdf"
        doc_path.parent.mkdir(parents=True, exist_ok=True)
        doc_path.write_text("dummy content")
        assert doc_path.exists()

        # 2. 配置 mock 返回要删除的文档信息
        DocSelectRow = namedtuple("DocSelectRow", ["id", "path"])
        mock_db_connection.execute.return_value.first.return_value = DocSelectRow(
            id=42, path=str(doc_path)
        )
        # 之后 reset_mock() 确保第二次 execute (DELETE) 能正常工作
        mock_db_connection.execute.side_effect = [
            mock_db_connection.execute.return_value,  # for SELECT
            None  # for DELETE
        ]

        # 3. 调用 API
        rv = client.delete("/api/delete-document/42", headers=headers)

        # 4. 断言
        assert rv.status_code == 200
        assert rv.get_json()["file_deleted"] is True
        assert not doc_path.exists()  # 验证物理文件已被删除


class TestWatermarking:
    """测试水印功能，同样使用 mock"""

    @patch('server.src.server.WMUtils.is_watermarking_applicable', return_value=True)  # <-- 新增的 mock
    @patch('server.src.server.WMUtils.apply_watermark', return_value=b"watermarked")
    def test_create_watermark(self, mock_apply, mock_is_applicable, auth_client, mock_db_connection, mocker,
                              app):  # <-- 新增的 mock 参数
        # 注意：mock 参数的顺序与 @patch 装饰器的顺序相反（由内向外）
        client, headers, user_info = auth_client

        # 准备一个源文件
        source_path = app.config["STORAGE_DIR"] / "source.pdf"
        # 确保父目录存在
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text("source")

        # 配置数据库 mock
        DocRow = namedtuple("DocRow", ["id", "name", "path"])
        mock_db_connection.execute.side_effect = [
            # SELECT from Documents
            mocker.MagicMock(first=lambda: DocRow(id=50, name="Base Doc", path=str(source_path))),
            # INSERT into Versions
            mocker.MagicMock(),
            # SELECT LAST_INSERT_ID()
            mocker.MagicMock(scalar=lambda: 501),
        ]

        payload = {
            "method": "test_method", "intended_for": "Receiver",
            "secret": "secret", "key": "key"
        }
        rv = client.post("/api/create-watermark/50", json=payload, headers=headers)

        assert rv.status_code == 201
        assert rv.get_json()["id"] == 501
        assert rv.get_json()["link"] is not None

        # 验证两个 mock 都被正确调用
        mock_is_applicable.assert_called_once()
        mock_apply.assert_called_once()


class TestInfraHelpers:
    """
    专门测试基础设施辅助函数，如数据库连接和引擎管理。
    这些测试不使用 db_mock，以确保真实函数逻辑被执行。
    """

    def test_db_url_formatting(self, app):
        """
        测试 db_url() 函数是否能正确生成 MySQL 连接字符串。
        """
        # 使用 app context 来访问 current_app
        with app.app_context():
            # 为配置设置一些虚拟值
            app.config.update(
                DB_USER="test_user",
                DB_PASSWORD="test_password",
                DB_HOST="db_host",
                DB_PORT=3306,
                DB_NAME="test_db"
            )

            # 导入并调用真实的 db_url 函数
            from server.src.server import db_url
            generated_url = db_url()

            # 断言生成的 URL 包含所有我们设置的部分
            assert "mysql+pymysql://" in generated_url
            assert "test_user:test_password" in generated_url
            assert "@db_host:3306" in generated_url
            assert "/test_db?charset=utf8mb4" in generated_url

    def test_get_engine_creates_and_caches(self, app, mocker):
        """
        测试 get_engine() 首次调用时创建引擎，并进行缓存。
        """
        # 关键：我们只模拟底层的 create_engine，而不模拟 get_engine 本身
        mock_create_engine = mocker.patch('server.src.server.create_engine')
        # 让它返回一个模拟对象，假装是一个引擎
        mock_engine_instance = mocker.MagicMock()
        mock_create_engine.return_value = mock_engine_instance

        with app.app_context():
            from server.src.server import get_engine, current_app

            # 确保开始时没有缓存的引擎
            if "_ENGINE" in current_app.config:
                del current_app.config["_ENGINE"]

            # 1. 第一次调用
            engine1 = get_engine()

            # 2. 第二次调用
            engine2 = get_engine()

            # 断言：create_engine 只被调用了一次（在第一次 get_engine 时）
            mock_create_engine.assert_called_once()

            # 断言：两次调用返回的是同一个引擎实例
            assert engine1 is engine2

            # 断言：返回的实例就是我们 mock 的那个
            assert engine1 is mock_engine_instance

            # 断言：引擎实例被正确地缓存到了 app.config 中
            assert current_app.config["_ENGINE"] is mock_engine_instance

    def test_safe_resolve_under_storage(self, tmp_path):
        """
        测试路径安全解析函数的所有分支。
        """
        from server.src.server import _safe_resolve_under_storage

        # 1. 准备一个虚拟的、安全的存储根目录
        storage_root = tmp_path / "storage"
        storage_root.mkdir()

        # --- Case 1: 提供一个合法的【相对路径】 ---
        # 这将覆盖 `if not fp.is_absolute():` 分支
        relative_p = "files/document.pdf"
        expected_path = storage_root / relative_p

        resolved_path = _safe_resolve_under_storage(relative_p, storage_root)

        # 断言相对路径被正确地解析到了 storage_root 之下
        assert resolved_path == expected_path.resolve()

        # --- Case 2: 提供一个合法的【绝对路径】(用于完整性检查) ---
        absolute_p = storage_root / "files" / "absolute.pdf"

        resolved_path_abs = _safe_resolve_under_storage(str(absolute_p), storage_root)

        # 断言绝对路径保持不变
        assert resolved_path_abs == absolute_p.resolve()

        # --- Case 3: 尝试进行【目录遍历攻击】 ---
        # 这将覆盖 `except ValueError:` 分支，因为它会触发 RuntimeError
        # 我们使用 pytest.raises 来断言代码块中会抛出指定的异常
        malicious_p = "../../../etc/passwd"

        with pytest.raises(RuntimeError) as exc_info:
            _safe_resolve_under_storage(malicious_p, storage_root)

        # (可选) 断言异常信息中包含预期的文本，使测试更健壮
        assert "escapes storage root" in str(exc_info.value)


# =====================================================================
# 新增的测试类，用于完整覆盖 @require_auth 装饰器
# =====================================================================
class TestAuthDecorator:
    """
    专门针对 @require_auth 装饰器的所有逻辑分支进行测试。
    我们选择一个任意的受保护端点（如 /api/list-documents）来进行测试。
    """

    def test_success_with_valid_token(self, auth_client, mock_db_connection):
        """
        测试：使用有效 Token 访问受保护端点应该成功 (覆盖 happy path)。
        """
        client, headers, user_info = auth_client
        # 即使认证成功，端点本身也会查询数据库，所以我们依然需要 mock 它
        mock_db_connection.execute.return_value.all.return_value = []

        rv = client.get("/api/list-documents", headers=headers)
        assert rv.status_code == 200

    def test_failure_with_no_header(self, client):
        """
        测试：完全没有 Authorization 请求头。
        """
        rv = client.get("/api/list-documents")
        assert rv.status_code == 401
        error_msg = rv.get_json()["error"]
        assert "Missing or invalid Authorization header" in error_msg

    def test_failure_with_invalid_scheme(self, client):
        """
        测试：请求头格式错误，不是以 "Bearer " 开头。
        这将覆盖 `if not auth.startswith("Bearer "):` 分支。
        """
        rv = client.get("/api/list-documents", headers={"Authorization": "Token some-token"})
        assert rv.status_code == 401
        error_msg = rv.get_json()["error"]
        assert "Missing or invalid Authorization header" in error_msg

    def test_failure_with_bad_signature(self, client):
        """
        测试：Token 签名错误或被篡改。
        这将覆盖 `except BadSignature:` 分支。
        """
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.a_tampered_signature"}
        rv = client.get("/api/list-documents", headers=headers)
        assert rv.status_code == 401
        error_msg = rv.get_json()["error"]
        assert "Invalid token" in error_msg

    def test_failure_with_expired_token(self, app, client):
        """
        测试：Token 已过期。
        这将覆盖 `except SignatureExpired:` 分支。
        """
        # 技巧：我们生成一个正常的 token，然后在发送请求时，
        # 临时将 app 的 TOKEN_TTL_SECONDS (令牌有效期) 配置为负数，
        # 这样刚才生成的任何 token 都会被立即视为“已过期”。

        token = ""
        # 需要 app_context 来访问 _serializer 和 current_app
        with app.app_context():
            from server.src.server import _serializer
            # 生成一个 uid 为 1 的用户的 token
            token = _serializer().dumps({"uid": 1, "login": "testuser"})

            # 临时修改配置，让 token 失效
            original_ttl = app.config["TOKEN_TTL_SECONDS"]
            app.config["TOKEN_TTL_SECONDS"] = -1  # 设置为负数，确保立即过期

        # 使用刚才生成的、但现在已被视为“过期”的 token 发送请求
        headers = {"Authorization": f"Bearer {token}"}
        rv = client.get("/api/list-documents", headers=headers)

        # 恢复原始配置，避免影响其他测试
        with app.app_context():
            app.config["TOKEN_TTL_SECONDS"] = original_ttl

        # 断言结果
        assert rv.status_code == 401
        error_msg = rv.get_json()["error"]
        assert "Token expired" in error_msg


class TestCoreRoutes:
    """测试核心服务路由"""

    def test_home_and_static_routes(self, app, client):
        """
        测试首页 (/) 和静态文件服务 (/<path:filename>) 路由。
        """
        # --- 准备工作 ---
        # Flask 会在 app 实例的根目录寻找 "static" 文件夹。
        # 我们需要在测试期间手动创建这个文件夹和一些虚拟文件。
        # 我们的 app fixture 使用了 tmp_path, 所以这是在临时目录中操作，很安全。
        static_folder = Path(app.static_folder)
        static_folder.mkdir(exist_ok=True)

        # 创建一个虚拟的 index.html
        (static_folder / "index.html").write_text("<html><body>Hello World</body></html>")
        # 创建一个虚拟的 js 文件
        (static_folder / "app.js").write_text("console.log('Hello');")

        # --- 测试首页 (/) ---
        # 这个请求会触发 home() 函数
        rv_home = client.get("/")
        assert rv_home.status_code == 200
        assert b"Hello World" in rv_home.data

        # --- 测试静态文件 (/app.js) ---
        # 这个请求会触发 static_files() 函数
        rv_static = client.get("/app.js")
        assert rv_static.status_code == 200
        assert b"console.log('Hello');" in rv_static.data

        # --- 测试一个不存在的静态文件 ---
        rv_not_found = client.get("/nonexistent.css")
        assert rv_not_found.status_code == 404

    def test_healthz_db_ok(self, client, mock_db_connection):
        """
        测试 /healthz 端点在数据库连接【成功】时的情况。
        这将覆盖 `try` 块。
        """
        # mock_db_connection fixture 已经模拟了一个可以正常工作的连接
        rv = client.get("/healthz")

        assert rv.status_code == 200
        json_data = rv.get_json()
        assert json_data["message"] == "The server is up and running."
        assert json_data["db_connected"] is True

    def test_healthz_db_fail(self, client, db_mock):
        """
        测试 /healthz 端点在数据库连接【失败】时的情况。
        这将覆盖 `except` 块。
        """
        # 我们需要使用更底层的 db_mock 来模拟 connect() 方法本身抛出异常
        db_mock.return_value.connect.side_effect = Exception("Database is down")

        rv = client.get("/healthz")

        assert rv.status_code == 200
        json_data = rv.get_json()
        assert json_data["db_connected"] is False


class TestListingEndpoints:
    """测试各种列表端点的所有分支"""

    def test_list_documents_db_error(self, auth_client, mock_db_connection):
        """
        测试：当 list_documents 查询数据库时发生通用异常。
        这将覆盖 list_documents 的 `except Exception` 块。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.side_effect = Exception("Simulated DB connection error")

        rv = client.get("/api/list-documents", headers=headers)

        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]

    def test_list_versions_with_query_param(self, auth_client, mock_db_connection):
        """
        测试：通过查询参数成功获取版本列表 (?id=123)。
        这将覆盖 `if document_id is None:` 的成功路径。
        """
        client, headers, _ = auth_client
        # 模拟数据库成功返回一个空列表
        mock_db_connection.execute.return_value.all.return_value = []

        # 测试使用 ?id=...
        rv_id = client.get("/api/list-versions?id=123", headers=headers)
        assert rv_id.status_code == 200
        assert "versions" in rv_id.get_json()

        # 测试使用 ?documentid=...
        rv_docid = client.get("/api/list-versions?documentid=456", headers=headers)
        assert rv_docid.status_code == 200
        assert "versions" in rv_docid.get_json()

    def test_list_versions_with_invalid_query_param(self, auth_client):
        """
        测试：当 list_versions 收到无效或缺失的查询参数时。
        这将覆盖 `except (TypeError, ValueError)` 块。
        """
        client, headers, _ = auth_client

        # Case 1: 查询参数不是一个整数
        rv_nan = client.get("/api/list-versions?id=abc", headers=headers)
        assert rv_nan.status_code == 400
        assert "document id required" in rv_nan.get_json()["error"]

        # Case 2: 完全没有提供 document_id (既不在URL路径也不在查询参数中)
        rv_missing = client.get("/api/list-versions", headers=headers)
        assert rv_missing.status_code == 400
        assert "document id required" in rv_missing.get_json()["error"]

    def test_list_versions_db_error(self, auth_client, mock_db_connection):
        """
        测试：当 list_versions 查询数据库时发生通用异常。
        这将覆盖 list_versions 的 `except Exception` 块。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.side_effect = Exception("Simulated DB query error")

        # 我们可以用任何有效的方式调用，比如通过URL路径，因为我们测试的是数据库失败
        rv = client.get("/api/list-versions/123", headers=headers)

        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]

    def test_list_all_versions_success(self, auth_client, mock_db_connection):
        """
        测试：成功获取属于该用户的所有文档版本列表。
        这将覆盖 `list_all_versions` 的 `try` 块。
        """
        client, headers, _ = auth_client

        # 1. 准备一些虚拟的数据库返回行数据
        # 使用 namedtuple 可以方便地模拟 SQLAlchemy 的 Row 对象
        VersionRow = namedtuple("VersionRow", ["id", "documentid", "link", "intended_for", "method"])
        mock_rows = [
            VersionRow(id=101, documentid=1, link='abc', intended_for='Alice', method='method1'),
            VersionRow(id=202, documentid=5, link='xyz', intended_for='Bob', method='method2'),
        ]

        # 2. 配置 mock 返回这些虚拟数据
        mock_db_connection.execute.return_value.all.return_value = mock_rows

        # 3. 调用 API 端点
        rv = client.get("/api/list-all-versions", headers=headers)

        # 4. 断言结果
        assert rv.status_code == 200
        data = rv.get_json()
        assert "versions" in data
        assert len(data["versions"]) == 2
        assert data["versions"][0]["id"] == 101
        assert data["versions"][1]["link"] == 'xyz'

    def test_list_all_versions_db_error(self, auth_client, mock_db_connection):
        """
        测试：当 list_all_versions 查询数据库时发生通用异常。
        这将覆盖 `list_all_versions` 的 `except Exception` 块。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.side_effect = Exception("Simulated DB connection error")

        rv = client.get("/api/list-all-versions", headers=headers)

        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]


class TestGetDocument:
    """全面测试 get_document 端点的所有成功和失败路径"""

    def test_get_document_success(self, auth_client, mock_db_connection, app):
        """
        测试：成功获取文档（通过 URL 路径和查询参数两种方式）。
        """
        client, headers, _ = auth_client

        # 1. 准备一个虚拟文件
        doc_content = b"This is a test PDF document."
        doc_path = app.config["STORAGE_DIR"] / "test_doc.pdf"
        doc_path.write_bytes(doc_content)

        # 2. 准备一个虚拟的数据库返回行
        DocRow = namedtuple("DocRow", ["id", "name", "path", "sha256_hex", "size"])
        mock_row = DocRow(id=123, name="Test Doc", path=str(doc_path), sha256_hex="abc", size=len(doc_content))
        mock_db_connection.execute.return_value.first.return_value = mock_row

        # 3. Case A: 通过 URL 路径获取
        rv_path = client.get("/api/get-document/123", headers=headers)
        assert rv_path.status_code == 200
        assert rv_path.data == doc_content

        # 4. Case B: 通过查询参数获取
        rv_query = client.get("/api/get-document?id=123", headers=headers)
        assert rv_query.status_code == 200
        assert rv_query.data == doc_content

    def test_get_document_invalid_query_param(self, auth_client):
        """
        测试：当提供了无效的查询参数时，返回 400。
        """
        client, headers, _ = auth_client
        rv = client.get("/api/get-document?id=not-a-number", headers=headers)
        assert rv.status_code == 400
        assert "document id required" in rv.get_json()["error"]

    def test_get_document_db_error(self, auth_client, mock_db_connection):
        """
        测试：当数据库查询失败时，返回 503。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.side_effect = Exception("DB connection failed")

        rv = client.get("/api/get-document/123", headers=headers)
        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]

    def test_get_document_not_found_in_db(self, auth_client, mock_db_connection):
        """
        测试：当文档在数据库中不存在时，返回 404。
        """
        client, headers, _ = auth_client
        # 模拟数据库查询返回 None
        mock_db_connection.execute.return_value.first.return_value = None

        rv = client.get("/api/get-document/123", headers=headers)
        assert rv.status_code == 404
        assert "document not found" in rv.get_json()["error"]

    def test_get_document_invalid_path_escape(self, auth_client, mock_db_connection, tmp_path):
        """
        测试：当数据库中的路径试图逃逸存储目录时，返回 500 (安全错误)。
        """
        client, headers, _ = auth_client

        # 1. 构造一个恶意的、指向外部的路径
        malicious_path = tmp_path / "outside_file.txt"
        malicious_path.write_text("malicious content")

        # 2. 模拟数据库返回了这条恶意路径
        DocRow = namedtuple("DocRow", ["id", "name", "path", "sha256_hex", "size"])
        mock_row = DocRow(id=123, name="Malicious Doc", path=str(malicious_path), sha256_hex="abc", size=10)
        mock_db_connection.execute.return_value.first.return_value = mock_row

        rv = client.get("/api/get-document/123", headers=headers)
        assert rv.status_code == 500
        assert "document path invalid" in rv.get_json()["error"]

    def test_get_document_file_missing_on_disk(self, auth_client, mock_db_connection, app):
        """
        测试：当数据库记录存在，但物理文件丢失时，返回 410。
        """
        client, headers, _ = auth_client

        # 1. 构造一个指向不存在的文件的合法路径
        missing_file_path = app.config["STORAGE_DIR"] / "definitely_not_here.pdf"
        assert not missing_file_path.exists()  # 确认文件不存在

        # 2. 模拟数据库返回这条记录
        DocRow = namedtuple("DocRow", ["id", "name", "path", "sha256_hex", "size"])
        mock_row = DocRow(id=123, name="Missing File Doc", path=str(missing_file_path), sha256_hex="abc", size=10)
        mock_db_connection.execute.return_value.first.return_value = mock_row

        rv = client.get("/api/get-document/123", headers=headers)
        assert rv.status_code == 410
        assert "file missing on disk" in rv.get_json()["error"]


class TestGetVersion:
    """全面测试 get_version 端点的所有成功和失败路径"""

    def test_get_version_success(self, client, mock_db_connection, app):
        """
        测试：通过一个有效的链接成功获取版本文件。
        """
        # 1. 准备一个虚拟的版本文件
        version_content = b"This is a watermarked version."
        version_path = app.config["STORAGE_DIR"] / "versions" / "version_file.pdf"
        version_path.parent.mkdir(exist_ok=True)
        version_path.write_bytes(version_content)

        # 2. 准备一个虚拟的数据库返回行
        # get_version 函数会访问 row 的多个属性
        VersionRow = namedtuple("VersionRow", ["path", "link"])
        mock_row = VersionRow(path=str(version_path), link="some-valid-link.pdf")
        mock_db_connection.execute.return_value.first.return_value = mock_row

        # 3. 调用 API
        rv = client.get("/api/get-version/some-valid-link")

        # 4. 断言
        assert rv.status_code == 200
        assert rv.data == version_content

    def test_get_version_db_error(self, client, mock_db_connection):
        """
        测试：当数据库查询失败时，返回 503。
        """
        mock_db_connection.execute.side_effect = Exception("DB connection failed")

        rv = client.get("/api/get-version/any-link")
        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]

    def test_get_version_not_found_in_db(self, client, mock_db_connection):
        """
        测试：当链接在数据库中不存在时，返回 404。
        """
        # 模拟数据库查询返回 None
        mock_db_connection.execute.return_value.first.return_value = None

        rv = client.get("/api/get-version/non-existent-link")
        assert rv.status_code == 404
        assert "document not found" in rv.get_json()["error"]

    def test_get_version_invalid_path_escape(self, client, mock_db_connection, tmp_path):
        """
        测试：当数据库中的路径试图逃逸存储目录时，返回 500 (安全错误)。
        """
        # 1. 构造一个恶意的、指向外部的路径
        malicious_path = tmp_path / "outside_file.txt"
        malicious_path.write_text("malicious content")

        # 2. 模拟数据库返回了这条恶意路径
        VersionRow = namedtuple("VersionRow", ["path", "link"])
        mock_row = VersionRow(path=str(malicious_path), link="malicious-link")
        mock_db_connection.execute.return_value.first.return_value = mock_row

        rv = client.get("/api/get-version/malicious-link")
        assert rv.status_code == 500
        assert "document path invalid" in rv.get_json()["error"]

    def test_get_version_file_missing_on_disk(self, client, mock_db_connection, app):
        """
        测试：当数据库记录存在，但物理文件丢失时，返回 410。
        """
        # 1. 构造一个指向不存在的文件的合法路径
        missing_file_path = app.config["STORAGE_DIR"] / "versions" / "ghost_file.pdf"
        assert not missing_file_path.exists()  # 确认文件不存在

        # 2. 模拟数据库返回这条记录
        VersionRow = namedtuple("VersionRow", ["path", "link"])
        mock_row = VersionRow(path=str(missing_file_path), link="ghost-link")
        mock_db_connection.execute.return_value.first.return_value = mock_row

        rv = client.get("/api/get-version/ghost-link")
        assert rv.status_code == 410
        assert "file missing on disk" in rv.get_json()["error"]


class TestReadWatermark:
    """全面测试 /api/read-watermark 端点的所有分支"""

    # 辅助工具：创建一个模拟的数据库文档行
    DocRow = namedtuple("DocRow", ["id", "name", "path"])

    def test_read_watermark_id_from_json(self, auth_client, mock_db_connection, mocker, app):  # <-- 1. 添加 app fixture
        """
        测试分支 1: 成功从 JSON 请求体中获取 document_id。
        """
        client, headers, _ = auth_client

        # --- 开始修改 ---
        # 2. 在测试的临时存储目录中创建一个虚拟文件
        storage_root = app.config["STORAGE_DIR"]
        # 确保路径与应用逻辑一致，通常会在 'files' 子目录下
        dummy_file_path = storage_root / "files" / "dummy.pdf"
        dummy_file_path.parent.mkdir(parents=True, exist_ok=True)
        dummy_file_path.touch()  # 创建一个空的物理文件

        # 3. 模拟数据库返回这个真实存在的虚拟文件的【绝对路径】
        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=123, name="Test Doc", path=str(dummy_file_path)
        )
        # --- 修改结束 ---

        # 模拟 WMUtils 成功
        mocker.patch('server.src.server.WMUtils.read_watermark', return_value="secret_found")

        # 注意：API 路径中没有 ID
        rv = client.post("/api/read-watermark", headers=headers, json={
            "id": 123,  # <-- ID 在 JSON 体中
            "method": "some_method",
            "key": "some_key"
        })

        # 现在断言应该会成功
        assert rv.status_code == 201
        assert rv.get_json()["secret"] == "secret_found"

    def test_read_watermark_invalid_or_missing_id(self, auth_client):
        """
        测试分支 1 (except块): 当 document_id 无效或缺失时，返回 400。
        """
        client, headers, _ = auth_client
        payload = {"method": "some_method", "key": "some_key"}

        # Case A: ID 无效 (非数字)
        rv_invalid = client.post("/api/read-watermark?id=abc", headers=headers, json=payload)
        assert rv_invalid.status_code == 400
        assert "document id required" in rv_invalid.get_json()["error"]

        # Case B: ID 完全缺失
        rv_missing = client.post("/api/read-watermark", headers=headers, json=payload)
        assert rv_missing.status_code == 400
        assert "document id required" in rv_missing.get_json()["error"]

    @pytest.mark.parametrize("invalid_payload", [
        {"key": "some_key"},  # 缺少 method
        {"method": "some_method"},  # 缺少 key
        {"method": "some_method", "key": 123},  # key 不是字符串
        {},  # 空 payload
    ])
    def test_read_watermark_invalid_payload(self, auth_client, invalid_payload):
        """
        测试分支 2: 当请求体缺少 method 或 key 时，返回 400。
        """
        client, headers, _ = auth_client
        rv = client.post("/api/read-watermark/1", headers=headers, json=invalid_payload)
        assert rv.status_code == 400
        assert "method and key are required" in rv.get_json()["error"]

    def test_read_watermark_db_error(self, auth_client, mock_db_connection):
        """
        测试分支 3: 当数据库查询时发生通用异常，返回 503。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.side_effect = Exception("Simulated DB connection error")

        rv = client.post("/api/read-watermark/1", headers=headers, json={"method": "m", "key": "k"})
        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]

    def test_read_watermark_document_not_found_in_db(self, auth_client, mock_db_connection):
        """
        测试分支 4: 当文档在数据库中不存在时，返回 404。
        """
        client, headers, _ = auth_client
        # 模拟数据库查询返回 None
        mock_db_connection.execute.return_value.first.return_value = None

        rv = client.post("/api/read-watermark/999", headers=headers, json={"method": "m", "key": "k"})
        assert rv.status_code == 404
        assert "document not found" in rv.get_json()["error"]

    def test_read_watermark_invalid_path_escape(self, auth_client, mock_db_connection):
        """
        测试分支 5: 当数据库中的路径试图逃逸存储目录时，返回 500。
        """
        client, headers, _ = auth_client
        # 模拟数据库返回一个恶意的、指向外部的路径
        malicious_path = "/etc/passwd"
        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=1, name="Malicious Doc", path=malicious_path
        )

        rv = client.post("/api/read-watermark/1", headers=headers, json={"method": "m", "key": "k"})
        assert rv.status_code == 500
        assert "document path invalid" in rv.get_json()["error"]

    def test_read_watermark_file_missing_on_disk(self, auth_client, mock_db_connection, app):
        """
        测试分支 6: 数据库记录存在，但物理文件丢失时，返回 410。
        """
        client, headers, _ = auth_client
        # 构造一个指向不存在的文件的合法路径
        storage_root = app.config["STORAGE_DIR"]
        missing_file_path = storage_root / "files" / "definitely_not_here.pdf"
        assert not missing_file_path.exists()  # 确认文件不存在

        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=1, name="Missing File Doc", path=str(missing_file_path)
        )

        rv = client.post("/api/read-watermark/1", headers=headers, json={"method": "m", "key": "k"})
        assert rv.status_code == 410
        assert "file missing on disk" in rv.get_json()["error"]

    def test_read_watermark_wmutils_read_fails(self, auth_client, mock_db_connection, app, mocker):
        """
        测试分支 7: 当 WMUtils.read_watermark 自身执行失败时，返回 400。
        """
        client, headers, _ = auth_client

        # 1. 准备一个真实存在的虚拟文件
        storage_root = app.config["STORAGE_DIR"]
        doc_path = storage_root / "files" / "real_doc.pdf"
        doc_path.parent.mkdir(parents=True, exist_ok=True)
        doc_path.write_text("dummy content")

        # 2. 模拟数据库返回这个文件的信息
        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=1, name="Real Doc", path=str(doc_path)
        )

        # 3. 关键：模拟 WMUtils.read_watermark 抛出异常
        mocker.patch(
            'server.src.server.WMUtils.read_watermark',
            side_effect=Exception("Fake Watermark Reading Error")
        )

        rv = client.post("/api/read-watermark/1", headers=headers, json={"method": "m", "key": "k"})

        assert rv.status_code == 400
        assert "Error when attempting to read watermark" in rv.get_json()["error"]
        assert "Fake Watermark Reading Error" in rv.get_json()["error"]

class TestCreateWatermark:

    """全面测试 /api/create-watermark 端点的所有分支"""
    # 辅助工具：创建一个模拟的数据库文档行
    DocRow = namedtuple("DocRow", ["id", "name", "path"])

    # 这是一个通用的、有效的请求体，可以在多个测试中复用
    valid_payload = {
        "method": "test_method",
        "intended_for": "test_recipient",
        "secret": "my_secret",
        "key": "my_key"
    }

    def test_create_watermark_id_from_json(self, auth_client, mock_db_connection, mocker, app):
        """
        测试分支 1: 成功从 JSON 请求体中获取 document_id。
        """
        client, headers, _ = auth_client

        # 模拟一个完整的成功流程来验证ID获取是否正确
        doc_path = app.config["STORAGE_DIR"] / "source.pdf"
        doc_path.touch()
        mock_db_connection.execute.side_effect = [
            # 第一次 DB 调用 (SELECT)
            mocker.MagicMock(first=lambda: self.DocRow(id=123, name="Test Doc", path=str(doc_path))),
            # 第二次 DB 调用 (INSERT)
            mocker.MagicMock(),
            # 第三次 DB 调用 (LAST_INSERT_ID)
            mocker.MagicMock(scalar=lambda: 501),
        ]
        mocker.patch('server.src.server.WMUtils.is_watermarking_applicable', return_value=True)
        mocker.patch('server.src.server.WMUtils.apply_watermark', return_value=b"watermarked_content")

        # 注意：API 路径中没有 ID, ID 在 JSON 体中
        payload_with_id = self.valid_payload.copy()
        payload_with_id["id"] = 123

        rv = client.post("/api/create-watermark", headers=headers, json=payload_with_id)
        assert rv.status_code == 201
        assert rv.get_json()["documentid"] == 123

    def test_create_watermark_invalid_or_missing_id(self, auth_client):
        """
        测试分支 2: 当 document_id 无效或缺失时，返回 400。
        """
        client, headers, _ = auth_client
        rv = client.post("/api/create-watermark", headers=headers, json=self.valid_payload)
        assert rv.status_code == 400
        assert "document id required" in rv.get_json()["error"]

    @pytest.mark.parametrize("invalid_payload", [
        {"intended_for": "r", "secret": "s", "key": "k"},  # 缺少 method
        {"method": "m", "secret": "s", "key": "k"},  # 缺少 intended_for
        {"method": "m", "intended_for": "r", "key": "k"},  # 缺少 secret
        {"method": "m", "intended_for": "r", "secret": "s"},  # 缺少 key
        {"method": "m", "intended_for": "r", "secret": 123, "key": "k"},  # secret 类型错误
    ])
    def test_create_watermark_invalid_payload(self, auth_client, invalid_payload):
        """
        测试分支 3: 当请求体缺少必要字段或类型错误时，返回 400。
        """
        client, headers, _ = auth_client
        rv = client.post("/api/create-watermark/1", headers=headers, json=invalid_payload)
        assert rv.status_code == 400
        assert "method, intended_for, secret, and key are required" in rv.get_json()["error"]

    def test_create_watermark_db_error_on_select(self, auth_client, mock_db_connection):
        """
        测试分支 4: 当第一次查询数据库时发生通用异常，返回 503。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.side_effect = Exception("DB Select Failed")
        rv = client.post("/api/create-watermark/1", headers=headers, json=self.valid_payload)
        assert rv.status_code == 503
        assert "database error" in rv.get_json()["error"]

    def test_create_watermark_document_not_found(self, auth_client, mock_db_connection):
        """
        测试分支 5: 当文档在数据库中不存在时，返回 404。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.return_value.first.return_value = None
        rv = client.post("/api/create-watermark/999", headers=headers, json=self.valid_payload)
        assert rv.status_code == 404
        assert "document not found" in rv.get_json()["error"]

    def test_create_watermark_invalid_path(self, auth_client, mock_db_connection):
        """
        测试分支 6: 当数据库中的路径无效时，返回 500。
        """
        client, headers, _ = auth_client
        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=1, name="Malicious Doc", path="/etc/passwd"
        )
        rv = client.post("/api/create-watermark/1", headers=headers, json=self.valid_payload)
        assert rv.status_code == 500
        assert "document path invalid" in rv.get_json()["error"]

    def test_create_watermark_file_missing_on_disk(self, auth_client, mock_db_connection, app):
        """
        测试分支 7: 数据库记录存在，但物理文件丢失时，返回 410。
        """
        client, headers, _ = auth_client
        missing_file_path = app.config["STORAGE_DIR"] / "not_real.pdf"
        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=1, name="Missing Doc", path=str(missing_file_path)
        )
        rv = client.post("/api/create-watermark/1", headers=headers, json=self.valid_payload)
        assert rv.status_code == 410
        assert "file missing on disk" in rv.get_json()["error"]

    def test_create_watermark_not_applicable(self, auth_client, mock_db_connection, app, mocker):
        """
        测试分支 8: 当 WMUtils.is_watermarking_applicable 返回 False 时，返回 400。
        """
        client, headers, _ = auth_client

        # 模拟一个成功的文件查找流程
        doc_path = app.config["STORAGE_DIR"] / "source.pdf"
        doc_path.touch()
        mock_db_connection.execute.return_value.first.return_value = self.DocRow(
            id=1, name="Test Doc", path=str(doc_path)
        )

        # 关键：模拟适用性检查失败
        mocker.patch('server.src.server.WMUtils.is_watermarking_applicable', return_value=False)

        rv = client.post("/api/create-watermark/1", headers=headers, json=self.valid_payload)
        assert rv.status_code == 400
        assert "watermarking method not applicable" in rv.get_json()["error"]