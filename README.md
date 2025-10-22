# 望月塔 - 资产侦察平台

基于 Golang + React 的资产侦察与管理系统，用于安全团队的资产管理和授权测试。

本项目参考了 [adysec/ARL](https://github.com/adysec/ARL) 的设计思路。

微信沟通群：
![image](https://github.com/user-attachments/assets/54a3c6c4-dded-4cb7-8dbc-ed69084fa972)


---

## 📅 更新时间线

- **2025-10-22** - v0.2：优化端口扫描和漏洞检测功能逻辑
  - 集成 nmap 实现 SYN 扫描（性能提升 10-100 倍）
  - 重构漏洞扫描器，添加并发控制（性能提升 10 倍）
  - 优化 TCP Connect 扫描（500ms 超时，1000 并发）
  - 修复截图查看器无法关闭的问题
  - 清理冗余代码，统一目录结构

- **2025-10-21** - v0.1：添加在线修改密码功能
  - 用户可在个人设置中修改密码
  - 增强安全性和用户体验

---

## 项目简介

望月塔是一个用于资产侦察和管理的系统，主要功能包括：
- 发现和管理互联网资产（域名、IP、端口、站点）
- 定期监控资产变化
- 基于指纹的漏洞检测
- 适用于授权范围内的安全测试

## 主要功能

### 资产发现
- 子域名爆破：基于字典的子域名发现
- 端口扫描：支持 TOP100/TOP1000/全端口扫描
- 站点识别：HTTP/HTTPS 服务探测
- 指纹识别：Web 应用指纹识别

### 资产管理
- 域名、IP、端口、站点的统一管理
- 支持自定义指纹规则
- 资产分组和标签

### 任务系统
- 灵活的任务配置
- 计划任务（定时扫描）
- 任务执行状态跟踪
- 支持任务暂停和取消

### 漏洞检测
- 智能 PoC 检测：基于指纹自动匹配 PoC
- 文件泄露检测：检测常见敏感文件
- 支持自定义 PoC 导入

### 其他功能
- 资产监控：定期检测资产变化
- GitHub 监控：关键字监控
- 数据导出：JSON、CSV 格式
- 站点截图：使用 chromedp

## 🚀 快速开始

### 环境要求
- Go 1.21+
- PostgreSQL 12+
- Chrome/Chromium（用于站点截图）

### 部署步骤

#### 1. 安装数据库
```bash
# 安装 PostgreSQL
# 创建数据库
createdb reconmaster
```

#### 2. 配置系统
编辑 `backend/configs/config.yaml`：

```yaml
database:
  host: localhost
  port: 5432
  user: your_db_user
  password: your_db_password
  dbname: reconmaster

server:
  port: 8080
  
scanner:
  max_concurrent_tasks: 5
  domain_brute_threads: 30
  port_scan_threads: 50
```

#### 3. 初始化管理员
```bash
cd backend
go run cmd/init-admin/main.go
```

#### 4. 启动系统
```bash
cd backend
go run cmd/server/main.go
```

#### 5. 访问系统
浏览器打开：http://localhost:8080

使用初始化时设置的管理员账号登录。

### 生产部署

```bash
# 构建后端
cd backend
go build -o reconmaster ./cmd/server

# 运行
./reconmaster
```

**注意**：
- 前端已打包集成到后端，无需单独部署
- 确保 PostgreSQL 服务正常运行
- 首次运行会自动创建数据库表结构

## 技术栈

### 后端
- Golang 1.21
- Gin Web 框架
- GORM ORM
- PostgreSQL 数据库
- Cron 定时任务
- chromedp 浏览器自动化

### 前端
- React 18 + TypeScript
- Tailwind CSS
- shadcn/ui 组件库
- Vite 构建工具
- TanStack Query

### 目录结构

```
ARL_Vp3/
├── backend/
│   ├── cmd/
│   │   ├── server/         # 主程序入口
│   │   └── init-admin/     # 管理员初始化
│   ├── internal/
│   │   ├── api/           # API 接口
│   │   ├── models/        # 数据模型
│   │   ├── scanner/       # 扫描引擎
│   │   ├── services/      # 业务逻辑
│   │   ├── scheduler/     # 任务调度
│   │   └── ...
│   ├── configs/           # 配置文件
│   └── web/dist/          # 前端构建产物
└── frontend/              # 前端源码（构建后放到 backend/web/dist/）
```

## 任务配置

**基础配置**
- 任务名称、目标（支持域名/IP/IP段）
- 策略选择

**域名扫描**
- 子域名爆破（可选择字典）
- DNS 查询

**端口扫描**
- 端口范围（TOP100/TOP1000/全端口/自定义）
- CDN 识别和过滤

**站点检测**
- HTTP/HTTPS 探测
- 指纹识别
- 站点截图
- 文件泄露检测

**漏洞检测**
- 智能 PoC 检测（基于指纹匹配）

## 数据模型

主要数据表：

- `users` - 用户账号
- `tasks` - 扫描任务
- `policies` - 扫描策略
- `scheduled_tasks` - 计划任务
- `domains` - 域名资产
- `ips` - IP 资产
- `ports` - 端口信息
- `sites` - 站点信息
- `vulnerabilities` - 漏洞信息
- `fingerprints` - 指纹规则
- `pocs` - PoC 脚本
- `monitors` - 资产监控
- `github_monitors` - GitHub 监控

## 开发说明

### 前端开发

```bash
cd frontend
npm install
npm run dev
```

开发服务器运行在 `http://localhost:5173`

构建后需将 `dist/` 目录复制到 `backend/web/dist/`

### 后端开发

```bash
cd backend
go mod tidy
go run cmd/server/main.go
```

服务运行在 `http://localhost:5003`

## 许可证

MIT License

## 致谢

本项目参考了 [adysec/ARL](https://github.com/adysec/ARL) 的设计思路。

## 免责声明

本工具仅供安全研究和授权测试使用。使用本工具进行未授权的扫描是违法行为，使用者需自行承担法律责任。

**使用限制：**
- 仅限授权范围内的安全测试
- 需要 Chrome/Chromium 支持截图功能
- 扫描性能受网络环境影响
- 需合理配置并发参数
