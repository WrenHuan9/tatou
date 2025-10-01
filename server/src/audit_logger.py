import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from functools import wraps
from flask import request, g, current_app


class AuditLogger:
    """审计日志记录器，用于记录用户行为和系统访问"""
    
    def __init__(self, log_dir: str = "/app/logs", log_level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # 设置日志格式
        self.formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 创建文件处理器
        self.file_handler = logging.FileHandler(
            self.log_dir / "audit.log",
            encoding='utf-8'
        )
        self.file_handler.setFormatter(self.formatter)
        
        # 创建控制台处理器（用于Docker日志）
        self.console_handler = logging.StreamHandler(sys.stdout)
        self.console_handler.setFormatter(self.formatter)
        
        # 创建审计日志器
        self.audit_logger = logging.getLogger('audit')
        self.audit_logger.setLevel(getattr(logging, log_level.upper()))
        self.audit_logger.addHandler(self.file_handler)
        self.audit_logger.addHandler(self.console_handler)
        
        # 防止日志传播到根日志器
        self.audit_logger.propagate = False
        
        # 设置文件权限（仅管理员可读）
        try:
            os.chmod(self.log_dir / "audit.log", 0o600)
        except Exception:
            pass  # 在某些环境下可能无法设置权限
    
    def _get_user_info(self) -> Dict[str, Any]:
        """获取当前用户信息"""
        user_info = {
            "user_id": None,
            "login": None,
            "email": None,
            "is_authenticated": False
        }
        
        if hasattr(g, 'user') and g.user:
            user_info.update({
                "user_id": g.user.get("id"),
                "login": g.user.get("login"),
                "email": g.user.get("email"),
                "is_authenticated": True
            })
        
        return user_info
    
    def _get_request_info(self) -> Dict[str, Any]:
        """获取请求信息"""
        info = {
            "method": request.method,
            "path": request.path,
            "endpoint": request.endpoint,
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', ''),
            "content_type": request.content_type,
            "content_length": request.content_length,
            "query_string": request.query_string.decode('utf-8') if request.query_string else None
        }
        
        # 添加路径参数
        if request.view_args:
            info["path_params"] = request.view_args
        
        # 添加查询参数
        if request.args:
            info["query_params"] = dict(request.args)
        
        return info
    
    def log_access(self, action: str, details: Optional[Dict[str, Any]] = None, 
                   success: bool = True, error_message: Optional[str] = None):
        """记录访问日志"""
        log_data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "action": action,
            "user": self._get_user_info(),
            "request": self._get_request_info(),
            "success": success,
            "details": details or {},
            "error": error_message
        }
        
        # 记录到文件和控制台
        log_message = json.dumps(log_data, ensure_ascii=False, indent=None)
        
        if success:
            self.audit_logger.info(log_message)
        else:
            self.audit_logger.warning(log_message)
    
    def log_authentication(self, action: str, login: str, success: bool, 
                          error_message: Optional[str] = None):
        """记录认证相关日志"""
        log_data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "action": f"auth_{action}",
            "user": {
                "login": login,
                "is_authenticated": success
            },
            "request": self._get_request_info(),
            "success": success,
            "error": error_message
        }
        
        log_message = json.dumps(log_data, ensure_ascii=False, indent=None)
        
        if success:
            self.audit_logger.info(log_message)
        else:
            self.audit_logger.warning(log_message)
    
    def log_file_access(self, action: str, file_info: Dict[str, Any], 
                       success: bool = True, error_message: Optional[str] = None):
        """记录文件访问日志"""
        log_data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "action": f"file_{action}",
            "user": self._get_user_info(),
            "request": self._get_request_info(),
            "file_info": file_info,
            "success": success,
            "error": error_message
        }
        
        log_message = json.dumps(log_data, ensure_ascii=False, indent=None)
        
        if success:
            self.audit_logger.info(log_message)
        else:
            self.audit_logger.warning(log_message)


# 全局审计日志器实例
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """获取审计日志器实例"""
    global _audit_logger
    if _audit_logger is None:
        log_dir = os.environ.get("AUDIT_LOG_DIR", "/app/logs")
        log_level = os.environ.get("AUDIT_LOG_LEVEL", "INFO")
        _audit_logger = AuditLogger(log_dir, log_level)
    return _audit_logger


def audit_log(action: str, details: Optional[Dict[str, Any]] = None):
    """装饰器：为API端点添加审计日志记录"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            audit_logger = get_audit_logger()
            
            # 自动提取详细信息
            auto_details = {}
            
            # 提取路径参数
            if request.view_args:
                auto_details.update(request.view_args)
            
            # 提取查询参数
            if request.args:
                auto_details["query_params"] = dict(request.args)
            
            # 提取文件信息
            if request.files:
                files_info = {}
                for key, file in request.files.items():
                    if file and file.filename:
                        files_info[key] = {
                            "filename": file.filename,
                            "content_type": file.content_type,
                            "content_length": file.content_length
                        }
                if files_info:
                    auto_details["files"] = files_info
            
            # 合并用户提供的详细信息
            if details:
                auto_details.update(details)
            
            try:
                # 执行原始函数
                result = f(*args, **kwargs)
                
                # 记录成功访问
                audit_logger.log_access(action, auto_details, success=True)
                
                return result
                
            except Exception as e:
                # 记录失败访问
                error_msg = str(e)
                audit_logger.log_access(action, auto_details, success=False, error_message=error_msg)
                raise
        
        return wrapper
    return decorator


def audit_log_auth(action: str):
    """装饰器：为认证相关端点添加审计日志记录"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            audit_logger = get_audit_logger()
            
            try:
                # 执行原始函数
                result = f(*args, **kwargs)
                
                # 从请求中提取登录信息
                payload = request.get_json(silent=True) or {}
                login = payload.get("email") or payload.get("login") or "unknown"
                
                # 记录成功认证
                audit_logger.log_authentication(action, login, success=True)
                
                return result
                
            except Exception as e:
                # 记录失败认证
                payload = request.get_json(silent=True) or {}
                login = payload.get("email") or payload.get("login") or "unknown"
                error_msg = str(e)
                audit_logger.log_authentication(action, login, success=False, error_message=error_msg)
                raise
        
        return wrapper
    return decorator


def audit_log_file_access(action: str, file_info_extractor=None):
    """装饰器：为文件访问端点添加审计日志记录"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            audit_logger = get_audit_logger()
            
            try:
                # 执行原始函数
                result = f(*args, **kwargs)
                
                # 提取文件信息
                file_info = {}
                if file_info_extractor:
                    file_info = file_info_extractor(*args, **kwargs)
                
                # 记录成功文件访问
                audit_logger.log_file_access(action, file_info, success=True)
                
                return result
                
            except Exception as e:
                # 记录失败文件访问
                file_info = {}
                if file_info_extractor:
                    try:
                        file_info = file_info_extractor(*args, **kwargs)
                    except:
                        pass
                
                error_msg = str(e)
                audit_logger.log_file_access(action, file_info, success=False, error_message=error_msg)
                raise
        
        return wrapper
    return decorator
