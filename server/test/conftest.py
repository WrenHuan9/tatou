# tests/conftest.py (增强版)

import pytest
from pathlib import Path
from collections import namedtuple
from werkzeug.security import generate_password_hash

# 导入你的 app 工厂函数
from server.src.server import create_app


# 1. 使用 tmp_path 自动管理测试文件目录
@pytest.fixture
def app(tmp_path):
    """
    为每个测试创建一个新的 app 实例。
    使用 tmp_path 作为 STORAGE_DIR，确保测试文件被自动清理。
    """
    # 将临时存储目录传递给 app 配置
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "tests-secret-key",
        "WTF_CSRF_ENABLED": False,  # 在测试中通常禁用 CSRF 保护
        "STORAGE_DIR": storage_dir,
        # 由于我们完全 mock 数据库，DB 配置不再重要
    })
    yield app


@pytest.fixture
def client(app):
    """一个用于向 app 发送请求的测试客户端"""
    return app.test_client()


# 2. 基础的数据库引擎 mock
@pytest.fixture
def db_mock(mocker):
    """一个模拟顶层 get_engine 函数的 fixture。"""
    return mocker.patch('server.src.server.get_engine')


# 3. 创建一个更通用的 mock connection fixture 来减少重复代码
@pytest.fixture
def mock_db_connection(db_mock):
    """
    一个更便捷的 fixture，返回 mock 的 connection 对象。
    这样测试用例就不需要每次都写 `db_mock.return_value.begin...`
    """
    # 模拟 with get_engine().begin() as conn: or with get_engine().connect() as conn:
    # 两者在这个 mock 结构下是等价的
    mock_conn = db_mock.return_value.begin.return_value.__enter__.return_value
    db_mock.return_value.connect.return_value.__enter__.return_value = mock_conn
    return mock_conn


# 4. 保留并优化您的 auth_client fixture
@pytest.fixture
def auth_client(client, mock_db_connection, mocker):
    """
    一个会自动注册并登录用户的测试客户端夹具。
    返回一个元组：(客户端, 带有认证信息的请求头, 用户信息字典)
    """
    # --- 模拟注册 ---
    UserRow = namedtuple("UserRow", ["id", "email", "login"])
    # side_effect 允许对连续的调用返回不同的值
    mock_db_connection.execute.side_effect = [
        mocker.MagicMock(lastrowid=1),  # 第一次调用 (INSERT)
        mocker.MagicMock(one=lambda: UserRow(id=1, email="testuser@example.com", login="testuser")),  # 第二次调用 (SELECT)
    ]
    # 实际调用 API 以触发上述 mock
    client.post('/api/create-user',
                json={"email": "testuser@example.com", "login": "testuser", "password": "password123"})

    # --- 模拟登录 ---
    LoginUserRow = namedtuple("LoginUserRow", ["id", "email", "login", "hpassword"])
    hashed_password = generate_password_hash("password123")
    mock_user = LoginUserRow(id=1, email="testuser@example.com", login="testuser", hpassword=hashed_password)

    # 重置 mock 行为以用于登录
    mock_db_connection.execute.side_effect = None  # 清除之前的 side_effect
    mock_db_connection.execute.return_value.first.return_value = mock_user

    login_resp = client.post('/api/login', json={"login": "testuser", "password": "password123"})
    token = login_resp.get_json()['token']
    headers = {'Authorization': f'Bearer {token}'}
    user_info = {"id": 1, "login": "testuser", "email": "testuser@example.com"}

    # 在 yield 之前，重置 mock connection，以便后续测试可以自由配置
    mock_db_connection.reset_mock()
    # 特别重要：清除 side_effect，否则会影响其他测试
    mock_db_connection.execute.side_effect = None

    yield client, headers, user_info