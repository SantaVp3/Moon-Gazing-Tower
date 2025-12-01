# Moon-Gazing-Tower (望月塔)

一款现代化的自动化安全扫描平台，集成资产管理、漏洞扫描、任务调度等功能。

## 功能特性

### 资产管理
- 支持多种资产类型：域名、IP、URL、服务
- 资产分组管理
- 资产标签系统
- 批量导入导出

### 任务管理
- 支持直接输入目标（IP、域名、URL、CIDR）
- 多种扫描类型：子域名枚举、端口扫描、漏洞扫描、指纹识别等
- 任务调度与状态跟踪
- 扫描结果实时推送

### 漏洞管理
- 漏洞统计仪表盘
- 严重程度分布（严重/高危/中危/低危/信息）
- 漏洞状态管理（待处理/已确认/已修复/已忽略/误报）
- 漏洞验证功能
- 批量操作

### 扫描能力
- **子域名枚举**：集成 subfinder
- **端口扫描**：集成 rustscan
- **Web 爬虫**：集成 katana、rad
- **漏洞扫描**：集成 Nuclei CLI
- **指纹识别**：内置指纹库
- **CDN 检测**：识别 CDN 节点
- **子域名接管检测**

### 第三方集成
- FOFA
- Hunter
- Quake
- SecurityTrails
- Crt.sh

### 其他功能
- 页面监控
- 邮件通知
- WebSocket 实时推送
- JWT 认证

## 技术栈

**后端**
- Go 1.24
- Gin Web Framework
- MongoDB
- Redis（可选）

**前端**
- React 18
- TypeScript
- TanStack Query
- Tailwind CSS
- shadcn/ui

## 快速开始

### 默认账号
- 用户名：admin
- 密码：admin123

### 手动部署

#### 环境要求
- Go 1.21+
- MongoDB 5.0+
- Redis 6.0+（可选，用于任务队列）

#### 配置

编辑 `config/config.yaml`：

```yaml
server:
  port: 8080
  mode: release

mongodb:
  uri: mongodb://localhost:27017
  database: moongazing

redis:
  addr: localhost:6379
  password: ""
  db: 0

jwt:
  secret: your-secret-key
  expire: 24h
```

#### 运行

```bash
# 编译
go build -o server .

# 运行
./server
```

访问 http://localhost:8080


### Docker 部署

1、编辑 `config/config.yaml`配置文件：

- 修改 JWT 密钥
- 将 MongoDB 和 Redis 的连接地址从`localhost`分别替换为容器名`mongo`和`redis`
- 如果 MongoDB(`27017`) 或 Redis(`6379`) 和其它服务端口冲突，可以在`docker-compose.yml`中进行自定义，在本文件同步修改即可

```yaml
jwt:
  secret: "moon-gazing-tower-secret-key-change-in-production"
  
mongodb:
  # uri: "mongodb://localhost:27017"
  uri: mongodb://mongo:27017  # Docker
  database: "moongazing"

redis:
  # host: "localhost"
  host: "redis"               # Docker
  port: 6379

```

2、按需将下方扫描工具放置在`Moon-Gazing-Tower/tools/linux/`目录

```shell
$ wget https://github.com/projectdiscovery/subfinder/releases/download/v2.10.1/subfinder_2.10.1_linux_amd64.zip
$ mv subfinder /<path>/Moon-Gazing-Tower/tools/linux/

```

3、准备以下`Dockerfile`和`docker-compose.yml`文件，构建并启动：

```shell
$ docker compose up -d --build

```

4、浏览器访问 http://localhost:5003

## 目录结构

```
backend/
├── api/            # HTTP 处理器
├── config/         # 配置文件
│   ├── dicts/      # 字典文件
│   └── nuclei-templates/  # Nuclei 模板
├── database/       # 数据库连接
├── middleware/     # 中间件
├── models/         # 数据模型
├── router/         # 路由配置
├── scanner/        # 扫描器实现
│   ├── nuclei/     # Nuclei 集成
│   ├── thirdparty/ # 第三方 API
│   └── fingerprint/ # 指纹识别
├── service/        # 业务逻辑
│   ├── monitor/    # 页面监控
│   ├── notify/     # 通知服务
│   └── queue/      # 任务队列
├── tools/          # 外部工具
│   ├── darwin/     # macOS 工具
│   └── linux/      # Linux 工具
├── utils/          # 工具函数
└── web/            # 前端静态文件
```

## 扫描工具

项目集成了以下扫描工具，需要放置在 `tools/` 目录：

| 工具 | 用途 | 下载地址 |
|------|------|----------|
| subfinder | 子域名枚举 | https://github.com/projectdiscovery/subfinder |
| rustscan | 端口扫描 | https://github.com/RustScan/RustScan |
| katana | Web 爬虫 | https://github.com/projectdiscovery/katana |
| rad | Web 爬虫 | https://github.com/chaitin/rad |
| nuclei | 漏洞扫描 | https://github.com/projectdiscovery/nuclei |

![Image_20251201092422_1_251](https://github.com/user-attachments/assets/a9adf59e-eccb-4ec2-9969-9871572243a9)


## 许可证

MIT License

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=SantaVp3/Moon-Gazing-Tower&type=date&legend=top-left)](https://www.star-history.com/#SantaVp3/Moon-Gazing-Tower&type=date&legend=top-left)
