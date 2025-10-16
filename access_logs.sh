#!/bin/bash

# Script to access application logs from Docker container
# This script helps access the logs that are now properly configured

echo "=== Tatou Server Log Access ==="
echo ""

# Check if docker-compose is running
if ! docker-compose ps | grep -q "tatou-server-1.*Up"; then
    echo "❌ Server container is not running. Please start it with:"
    echo "   docker-compose up -d"
    exit 1
fi

echo "✅ Server container is running"
echo ""

# Show log file information
echo "📁 Log files in container:"
docker-compose exec server ls -la /app/logs/
echo ""

# Show recent log entries
echo "📋 Recent log entries (last 20 lines):"
docker-compose exec server tail -20 /app/logs/app.log
echo ""

# Show log file size
echo "📊 Log file size:"
docker-compose exec server du -h /app/logs/app.log
echo ""

# Show log rotation info
echo "🔄 Log rotation status:"
docker-compose exec server ls -la /app/logs/ | grep -E "\.(log|log\.[0-9]+)$"
echo ""

echo "💡 To view logs in real-time, use:"
echo "   docker-compose exec server tail -f /app/logs/app.log"
echo ""
echo "💡 To copy logs to host, use:"
echo "   docker-compose exec server cat /app/logs/app.log > app.log"
echo ""
echo "💡 To search logs, use:"
echo "   docker-compose exec server grep 'search_term' /app/logs/app.log"
