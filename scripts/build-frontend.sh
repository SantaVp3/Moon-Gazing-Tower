#!/bin/bash

# 前端构建和部署脚本

set -e  # 遇到错误立即退出

echo "🏗️  Building frontend..."

# 进入前端目录
cd "$(dirname "$0")/../frontend"

# 安装依赖（如果需要）
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# 构建前端
echo "🔨 Building..."
npm run build

# 检查构建结果
if [ -d "../backend/web/dist" ]; then
    echo "✅ Frontend build successful!"
    echo "📂 Output: backend/web/dist/"
    echo ""
    echo "Files:"
    ls -lh ../backend/web/dist/
    echo ""
    echo "🚀 You can now start the backend server"
else
    echo "❌ Build failed - dist directory not found"
    exit 1
fi
