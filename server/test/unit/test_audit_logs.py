# test_audit_logs.py (最终修复版 - 遵循 pytest-flask 最佳实践)

import json
import logging
from unittest.mock import patch

import pytest
from flask import Flask, g, jsonify

# 从你的源代码中导入需要被测试的模块和函数
# 确保 pytest 可以找到 src 目录
from src.audit_logger import get_audit_logger, audit_log, audit_log_auth, _audit_logger

# --- 测试设置 ---

@pytest.fixture(autouse=True)
def reset_singleton():
    """这是一个 pytest fixture，它会在每个测试函数运行前自动执行。"""
    # 我们的 get_audit_logger() 使用了一个全局单例变量 _audit_logger。
    # 为了确保每个测试都是独立的，我们在这里重置它。
    global _audit_logger
    _audit_logger = None

@pytest.fixture
def app(tmp_path):
    """
    创建一个临时的 Flask app 用于测试。
    关键：我们在这里配置日志目录，让它指向 pytest 提供的可写临时目录 (tmp_path)。
    """
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    # 将日志目录配置为临时目录，解决“只读文件系统”问题
    # 我们通过 patch 环境变量的方式来实现
    with patch.dict('os.environ', {'AUDIT_LOG_DIR': str(tmp_path)}):
        # 预先初始化一次 logger，确保它使用了临时目录
        get_audit_logger()

    # --- 定义一些被装饰器包裹的测试路由 ---
    @app.route("/test_action_success")
    @audit_log("test_action_success")
    def test_action_success_route():
        g.user = {"id": 1, "login": "testuser"}  # 模拟已登录用户
        return jsonify(message="Success")

    @app.route("/test_action_failure")
    @audit_log("test_action_failure")
    def test_action_failure_route():
        g.user = {"id": 1, "login": "testuser"}
        raise ValueError("This is a test error")

    @app.route("/auth_success", methods=['POST'])
    @audit_log_auth("login_attempt")
    def auth_success_route():
        # 模拟成功后 g.user 被设置
        g.user = {"id": 1, "login": "testuser"}
        return jsonify(message="Login OK")

    return app

@pytest.fixture
def client(app):
    """从 Flask app 创建一个测试客户端。"""
    return app.test_client()

# --- 测试开始 ---

@patch('logging.Logger.info')
def test_decorator_audit_log_on_success(mock_log_info, client):
    """
    测试 @audit_log 装饰器在路由成功时是否正确记录日志。
    这个测试解决了 "Working outside of request context" 错误。
    """
    # 使用 client 发起一个真实的（但内存中的）请求
    response = client.get('/test_action_success')
    
    # 确认 HTTP 请求是成功的
    assert response.status_code == 200
    
    # 确认 logger.info 被调用了一次
    mock_log_info.assert_called_once()
    
    # 解析日志内容并进行断言
    log_output = mock_log_info.call_args[0][0]
    log_data = json.loads(log_output)
    
    assert log_data['action'] == 'test_action_success'
    assert log_data['success'] is True
    assert log_data['user']['login'] == 'testuser'
    assert log_data['request']['path'] == '/test_action_success'

@patch('logging.Logger.warning')
def test_decorator_audit_log_on_failure(mock_log_warning, client):
    """
    测试 @audit_log 装饰器在路由抛出异常时是否正确记录日志。
    """
    try:
        # 这个请求会在 Flask 内部触发异常
        client.get('/test_action_failure')
    except ValueError:
        # 捕获我们预期的异常，防止测试本身崩溃
        pass

    # 确认 logger.warning 被调用了一次
    mock_log_warning.assert_called_once()
    
    # 解析日志内容并进行断言
    log_output = mock_log_warning.call_args[0][0]
    log_data = json.loads(log_output)

    assert log_data['action'] == 'test_action_failure'
    assert log_data['success'] is False
    assert 'This is a test error' in log_data['error']
    assert log_data['user']['login'] == 'testuser'

@patch('logging.Logger.info')
def test_decorator_audit_log_auth_on_success(mock_log_info, client):
    """
    测试 @audit_log_auth 装饰器是否正确工作。
    """
    # 模拟一个登录请求，附带 JSON 数据
    client.post('/auth_success', json={'email': 'testuser'})
    
    mock_log_info.assert_called_once()

    log_output = mock_log_info.call_args[0][0]
    log_data = json.loads(log_output)

    assert log_data['action'] == 'auth_login_attempt'
    assert log_data['success'] is True
    assert log_data['user']['login'] == 'testuser' # 检查是否从g.user获取