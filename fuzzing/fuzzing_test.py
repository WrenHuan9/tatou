#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tatou API Fuzzing Test Suite
使用schemathesis对Tatou API进行全面的fuzzing测试
"""

import os
import sys
import yaml
import json
import time
import requests
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fuzzing.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class TatouFuzzer:
    def __init__(self, config_path: str = "fuzzing_config.yaml"):
        """初始化Fuzzer"""
        self.config_path = config_path
        self.config = self.load_config()
        self.base_url = self.config.get('base_url', 'http://localhost:5001')
        self.openapi_spec = self.config.get('openapi_spec', './openapi.yaml')
        self.auth_token = None
        self.admin_key = self.config.get('auth', {}).get('admin_key', 'admin_secret_key_12345')
        
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"配置文件 {self.config_path} 不存在")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"配置文件解析错误: {e}")
            sys.exit(1)
    
    def check_server_health(self) -> bool:
        """检查服务器是否运行"""
        try:
            response = requests.get(f"{self.base_url}/healthz", timeout=10)
            if response.status_code == 200:
                logger.info("服务器健康检查通过")
                return True
            else:
                logger.warning(f"服务器健康检查失败: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"无法连接到服务器: {e}")
            return False
    
    def authenticate(self) -> bool:
        """获取认证token"""
        try:
            # 首先尝试创建测试用户
            user_data = {
                "login": "fuzzer_test_user",
                "password": "fuzzer_test_password_123",
                "email": "fuzzer@test.com"
            }
            
            response = requests.post(f"{self.base_url}/api/create-user", json=user_data, timeout=10)
            if response.status_code not in [200, 400, 409]:  # 400/409可能表示用户已存在
                logger.warning(f"创建测试用户失败: {response.status_code}")
            
            # 尝试登录
            login_data = {
                "email": "fuzzer@test.com",
                "password": "fuzzer_test_password_123"
            }
            
            response = requests.post(f"{self.base_url}/api/login", json=login_data, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data.get('token')
                logger.info("认证成功，获得token")
                return True
            else:
                logger.warning(f"登录失败: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"认证过程出错: {e}")
            return False
    
    def create_test_files(self) -> None:
        """创建测试用的PDF文件"""
        test_files_dir = Path("test_files")
        test_files_dir.mkdir(exist_ok=True)
        
        # 创建一个简单的测试PDF文件
        test_pdf_path = test_files_dir / "test_document.pdf"
        if not test_pdf_path.exists():
            # 创建一个最小的PDF文件用于测试
            pdf_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
72 720 Td
(Test Document) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
300
%%EOF"""
            
            with open(test_pdf_path, 'wb') as f:
                f.write(pdf_content)
            
            logger.info(f"创建测试PDF文件: {test_pdf_path}")
    
    def run_schemathesis_tests(self) -> bool:
        """运行schemathesis测试"""
        try:
            # 构建schemathesis命令
            cmd = [
                "schemathesis",
                "run",
                self.openapi_spec,
                "--url", self.base_url,
                "--workers", str(self.config.get('workers', 4)),
                "--max-response-time", str(self.config.get('max_response_time', 30)),
                "--max-examples", str(self.config.get('max_requests_per_test', 100)),
                "--max-failures", str(self.config.get('max_failures', 50)),
                "--report", "junit",
                "--report", "har"
            ]
            
            # 如果有认证token，添加到命令中
            if self.auth_token:
                cmd.extend(["--header", f"Authorization: Bearer {self.auth_token}"])
            
            # 添加admin key header
            cmd.extend(["--header", f"X-Admin-Key: {self.admin_key}"])
            
            logger.info(f"运行schemathesis命令: {' '.join(cmd)}")
            
            # 执行命令
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # 输出结果
            if result.stdout:
                logger.info("Schemathesis输出:")
                print(result.stdout)
            
            if result.stderr:
                logger.warning("Schemathesis错误:")
                print(result.stderr)
            
            # 检查返回码
            if result.returncode == 0:
                logger.info("Fuzzing测试完成，未发现严重问题")
                return True
            else:
                logger.warning(f"Fuzzing测试发现问题，返回码: {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Fuzzing测试超时")
            return False
        except Exception as e:
            logger.error(f"运行schemathesis测试时出错: {e}")
            return False
    
    def run_custom_fuzzing_tests(self) -> None:
        """运行自定义的fuzzing测试"""
        logger.info("开始运行自定义fuzzing测试...")
        
        # 测试各种边界条件和恶意输入
        test_cases = [
            {
                "name": "SQL注入测试",
                "endpoint": "/api/create-user",
                "method": "POST",
                "data": {
                    "login": "admin'; DROP TABLE users; --",
                    "password": "test",
                    "email": "test@test.com"
                }
            },
            {
                "name": "XSS测试",
                "endpoint": "/api/create-user", 
                "method": "POST",
                "data": {
                    "login": "<script>alert('xss')</script>",
                    "password": "test",
                    "email": "test@test.com"
                }
            },
            {
                "name": "路径遍历测试",
                "endpoint": "/api/get-document/../../../etc/passwd",
                "method": "GET"
            },
            {
                "name": "超大整数测试",
                "endpoint": "/api/get-document/9223372036854775807",
                "method": "GET"
            },
            {
                "name": "负数测试",
                "endpoint": "/api/get-document/-1",
                "method": "GET"
            },
            {
                "name": "空字符串测试",
                "endpoint": "/api/create-user",
                "method": "POST", 
                "data": {
                    "login": "",
                    "password": "",
                    "email": ""
                }
            },
            {
                "name": "超长字符串测试",
                "endpoint": "/api/create-user",
                "method": "POST",
                "data": {
                    "login": "A" * 10000,
                    "password": "B" * 10000,
                    "email": "C" * 1000 + "@test.com"
                }
            }
        ]
        
        for test_case in test_cases:
            try:
                logger.info(f"执行测试: {test_case['name']}")
                
                url = f"{self.base_url}{test_case['endpoint']}"
                headers = {}
                
                if self.auth_token:
                    headers["Authorization"] = f"Bearer {self.auth_token}"
                
                if test_case['method'] == 'GET':
                    response = requests.get(url, headers=headers, timeout=10)
                elif test_case['method'] == 'POST':
                    response = requests.post(url, json=test_case.get('data', {}), headers=headers, timeout=10)
                
                logger.info(f"测试 {test_case['name']} - 状态码: {response.status_code}")
                
                # 记录异常响应
                if response.status_code >= 400:
                    logger.warning(f"测试 {test_case['name']} 返回错误状态码: {response.status_code}")
                    if response.text:
                        logger.warning(f"响应内容: {response.text[:200]}...")
                
            except Exception as e:
                logger.error(f"测试 {test_case['name']} 执行失败: {e}")
    
    def generate_report(self) -> None:
        """生成测试报告"""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "base_url": self.base_url,
            "config": self.config,
            "auth_token_obtained": self.auth_token is not None,
            "test_files_created": True
        }
        
        with open("fuzzing_summary.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info("测试报告已生成: fuzzing_summary.json")
    
    def run(self) -> bool:
        """运行完整的fuzzing测试流程"""
        logger.info("开始Tatou API Fuzzing测试")
        
        # 1. 检查服务器健康状态
        if not self.check_server_health():
            logger.error("服务器不可用，退出测试")
            return False
        
        # 2. 尝试认证
        self.authenticate()
        
        # 3. 创建测试文件
        self.create_test_files()
        
        # 4. 运行schemathesis测试
        schemathesis_success = self.run_schemathesis_tests()
        
        # 5. 运行自定义fuzzing测试
        self.run_custom_fuzzing_tests()
        
        # 6. 生成报告
        self.generate_report()
        
        logger.info("Fuzzing测试完成")
        return schemathesis_success

def main():
    """主函数"""
    fuzzer = TatouFuzzer()
    success = fuzzer.run()
    
    if success:
        logger.info("所有测试完成，请查看生成的报告文件")
        sys.exit(0)
    else:
        logger.warning("测试过程中发现问题，请查看日志和报告")
        sys.exit(1)

if __name__ == "__main__":
    main()
