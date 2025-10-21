#!/bin/bash

# ARL_Vp3 构建脚本
# 支持多平台二进制编译

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 项目信息
APP_NAME="arl-vp3"
VERSION="v1.0.0"
BUILD_TIME=$(date +%Y%m%d_%H%M%S)
COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 目录设置
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${PROJECT_ROOT}/bin"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ARL_Vp3 构建工具${NC}"
echo -e "${GREEN}  Version: ${VERSION}${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 清理旧的构建文件
clean_build() {
    echo -e "${YELLOW}清理旧的构建文件...${NC}"
    rm -rf "${BIN_DIR}"
    mkdir -p "${BIN_DIR}"
    echo -e "${GREEN}✓ 清理完成${NC}"
    echo ""
}

# 编译二进制文件
build_binary() {
    local GOOS=$1
    local GOARCH=$2
    local OUTPUT_NAME=$3
    
    echo -e "${YELLOW}编译 ${GOOS}/${GOARCH}...${NC}"
    
    cd "${PROJECT_ROOT}"
    
    # 设置编译参数
    LDFLAGS="-s -w"
    LDFLAGS="${LDFLAGS} -X main.Version=${VERSION}"
    LDFLAGS="${LDFLAGS} -X main.BuildTime=${BUILD_TIME}"
    LDFLAGS="${LDFLAGS} -X main.CommitHash=${COMMIT_HASH}"
    
    # 编译
    CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -ldflags "${LDFLAGS}" \
        -o "${BIN_DIR}/${OUTPUT_NAME}" \
        ./cmd/server/main.go
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ 编译成功: ${OUTPUT_NAME}${NC}"
        ls -lh "${BIN_DIR}/${OUTPUT_NAME}"
    else
        echo -e "${RED}✗ 编译失败: ${OUTPUT_NAME}${NC}"
        exit 1
    fi
    echo ""
}

# 主构建流程
main() {
    clean_build
    
    # 编译不同平台的二进制文件
    echo -e "${GREEN}开始编译...${NC}"
    echo ""
    
    # Linux AMD64
    build_binary "linux" "amd64" "arl-vp3-linux-amd64"
    
    # Linux ARM64
    build_binary "linux" "arm64" "arl-vp3-linux-arm64"
    
    # macOS AMD64 (Intel)
    build_binary "darwin" "amd64" "arl-vp3-darwin-amd64"
    
    # macOS ARM64 (Apple Silicon)
    build_binary "darwin" "arm64" "arl-vp3-darwin-arm64"
    
    # Windows AMD64
    build_binary "windows" "amd64" "arl-vp3-windows-amd64.exe"
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  构建完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "二进制文件位于: ${BIN_DIR}"
    ls -lh "${BIN_DIR}"
    echo ""
    echo -e "${GREEN}总大小:${NC}"
    du -sh "${BIN_DIR}"
}

# 显示帮助
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help     显示帮助信息"
    echo "  -c, --clean    只清理构建文件"
    echo "  -p PLATFORM    只构建指定平台 (linux-amd64/linux-arm64/darwin-amd64/darwin-arm64/windows-amd64)"
    echo ""
    echo "示例:"
    echo "  $0                    # 构建所有平台"
    echo "  $0 -p linux-amd64     # 只构建Linux AMD64版本"
    echo "  $0 -p darwin-arm64    # 只构建macOS ARM64版本"
    echo "  $0 --clean            # 清理构建文件"
}

# 构建单个平台
build_platform() {
    local PLATFORM=$1
    
    case "${PLATFORM}" in
        linux-amd64)
            build_binary "linux" "amd64" "arl-vp3-linux-amd64"
            ;;
        linux-arm64)
            build_binary "linux" "arm64" "arl-vp3-linux-arm64"
            ;;
        darwin-amd64)
            build_binary "darwin" "amd64" "arl-vp3-darwin-amd64"
            ;;
        darwin-arm64)
            build_binary "darwin" "arm64" "arl-vp3-darwin-arm64"
            ;;
        windows-amd64)
            build_binary "windows" "amd64" "arl-vp3-windows-amd64.exe"
            ;;
        *)
            echo -e "${RED}✗ 不支持的平台: ${PLATFORM}${NC}"
            echo "支持的平台: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64"
            exit 1
            ;;
    esac
}

# 解析命令行参数
if [ $# -eq 0 ]; then
    main
else
    case "${1}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--clean)
            clean_build
            exit 0
            ;;
        -p)
            if [ -z "${2}" ]; then
                echo -e "${RED}✗ 请指定平台${NC}"
                show_help
                exit 1
            fi
            clean_build
            echo -e "${GREEN}开始编译 ${2}...${NC}"
            echo ""
            build_platform "${2}"
            echo -e "${GREEN}========================================${NC}"
            echo -e "${GREEN}  构建完成！${NC}"
            echo -e "${GREEN}========================================${NC}"
            echo ""
            echo -e "二进制文件位于: ${BIN_DIR}"
            ls -lh "${BIN_DIR}"
            ;;
        *)
            echo -e "${RED}✗ 未知选项: ${1}${NC}"
            show_help
            exit 1
            ;;
    esac
fi
