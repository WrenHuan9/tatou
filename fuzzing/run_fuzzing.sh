#!/bin/bash

# Tatou API Fuzzing Test Runner
# 这个脚本用于运行Tatou API的fuzzing测试

set -e

echo "=== Tatou API Fuzzing Test Suite ==="
echo "开始时间: $(date)"
echo

# 检查Python环境
if ! command -v python3 &> /dev/null; then
    echo "错误: 需要Python 3环境"
    exit 1
fi

# 检查服务器是否运行
echo "检查服务器状态..."
if ! curl -s http://localhost:5000/healthz > /dev/null 2>&1; then
    echo "警告: 无法连接到 http://localhost:5000/healthz"
    echo "请确保Tatou服务器正在运行"
    echo "可以使用以下命令启动服务器:"
    echo "  cd server && python3 src/server.py"
    echo
fi

# 创建虚拟环境（如果不存在）
if [ ! -d "fuzzing_env" ]; then
    echo "创建虚拟环境..."
    python3 -m venv fuzzing_env
fi

# 激活虚拟环境并安装依赖
echo "激活虚拟环境并安装fuzzing测试依赖..."
source fuzzing_env/bin/activate
pip install -r requirements-fuzzing.txt

# 创建测试目录
mkdir -p test_files
mkdir -p fuzzing_reports

# 运行fuzzing测试
echo "开始运行fuzzing测试..."
echo "这可能需要几分钟时间，请耐心等待..."
echo

python fuzzing_test.py

echo
echo "=== Fuzzing测试完成 ==="
echo "结束时间: $(date)"
echo
echo "生成的报告文件:"
echo "- fuzzing_report.html (HTML格式报告)"
echo "- fuzzing_report.json (JSON格式报告)"
echo "- fuzzing_summary.json (测试摘要)"
echo "- fuzzing.log (详细日志)"
echo
echo "请查看这些文件了解测试结果"
