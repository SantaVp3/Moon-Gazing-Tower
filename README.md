# 望月塔 - 资产侦察平台

基于 Golang + React 的资产侦察与管理系统，用于安全团队的资产管理和授权测试。

本项目参考了 [adysec/ARL](https://github.com/adysec/ARL) 的设计思路。

微信沟通群：
![image](https://github.com/user-attachments/assets/54a3c6c4-dded-4cb7-8dbc-ed69084fa972)


---

## 📅 更新时间线

- **2025-10-23** - v0.6：端口扫描重构与敏感信息检测
  - **端口扫描重构（纯Go实现）**：
    - 采用 **Naabu + gonmap** 组合扫描方案（ProjectDiscovery 生态）
    - 阶段1：Naabu 极速发现所有开放端口（SYN扫描，10000 packets/sec）
    - 阶段2：gonmap 详细识别服务版本和指纹（内置nmap指纹库）
    - **自适应速率**：根据扫描规模自动调整（TOP100端口=10000pps，全端口=8000pps）
    - **纯Go实现**：无需安装nmap/masscan等外部工具，开箱即用
    - 完美适配内网环境，不依赖域名查询插件
  - **新增敏感信息规则功能**：
    - 支持正则表达式和关键词两种匹配模式
    - 内置常见规则：API Key、私钥、数据库连接、JWT Token、身份证、手机号等
    - 支持自定义规则创建、编辑、启用/禁用
    - 规则分类管理（API Key、私钥、数据库、凭证、个人信息等）
    - 批量操作支持（批量删除、批量启用/禁用）
    - 匹配记录追踪和统计
  - **域名查询插件优化**：
    - 明确标记为可选扩展功能
    - 未配置 API 时不影响核心扫描流程
    - 优化错误提示和日志输出
  - **其他改进**：
    - 修复任务管理页面导出功能
    - 完善批量操作和任务删除
    - 优化监控功能和定时任务
    - 增强 PoC 和指纹导入功能

- **2025-10-23** - v0.5：资产监控功能增强
  - **监控UI优化**：
    - 修复徽章显示问题：「域名」和「运行中」等徽章添加 `whitespace-nowrap` 防止竖排显示
    - 优化字体样式：监控名称加粗放大、运行次数大号粗体显示、时间列添加字重
    - 按钮悬停效果：添加彩色背景高亮（黄/绿/蓝/红）
  - **编辑功能**：
    - 新增监控任务编辑对话框（EditMonitorDialog.tsx）
    - 支持修改：名称、目标、运行间隔、扫描选项
    - 监控类型创建后不可修改（禁用下拉框）
    - 后端 API：`PUT /monitors/:id`
  - **扫描选项增强**：
    - 新增「启用POC检测」选项
    - MonitorOptions 支持 5 种扫描选项：域名爆破、端口扫描、站点识别、站点截图、POC检测
  - **企业级功能完善**：
    - 监控类型选择器（Domain/IP/Site/GitHub/WebInfoHunter）
    - 状态切换（运行中/已暂停/已停止）
    - 批量删除监控任务
    - 运行次数统计与错误记录
    - Interval 单位修复（前端小时 ↔ 后端秒自动转换）

- **2025-10-23** - v0.5：UI优化与扫描器配置修复
  - **任务控制优化**：
    - 新增手动启动扫描功能，创建任务后需手动点击「启动」按钮开始扫描
    - 任务状态支持 pending → running 手动转换
  - **资产测绘页面优化**：
    - 扩展后端 API 支持多字段筛选（URL、域名、IP、端口、状态码）
    - 从 URL 解析并单独显示域名和端口信息
    - 修复搜索功能，筛选条件正确传递
    - 优化表头显示（「应用组件」和「发现时间」避免竖排）
    - 详情按钮可正常打开站点
  - **系统设置页面优化**：
    - 第三方 API 配置改为 2 列网格横向布局
    - 扫描器配置改为横向网格布局（域名/端口/站点 4 列，服务/IP 2 列）
    - 添加配置状态徽章，直观显示已配置项
  - **扫描器配置功能修复**（重要）：
    - **问题**：前端可以保存扫描器配置，但扫描器运行时使用硬编码值，配置未生效
    - **修复**：新增 `config_loader.go`，所有扫描器从数据库读取配置
    - **生效配置**：域名并发/超时/重试、端口并发/超时、站点并发/超时/爬虫参数、服务超时/Banner长度、子域名接管并发
    - ✅ 现在用户在前端设置的扫描器参数会真正生效

- **2025-10-22** - v0.4：配置管理重构与实时数据保存优化
  - **配置管理重构**：
    - JWT 密钥从硬编码改为从 `config.yaml` 读取
    - 加密密钥统一从配置文件读取
    - 实现全局配置管理（`config.GlobalConfig`）
    - 支持环境变量覆盖配置文件设置
    - 统一 `main.go` 和 `init-admin` 的配置加载逻辑
  - **WebSocket 连接优化**：
    - 修复 WebSocket 频繁重连问题（frantic reconnection）
    - 实现全局单例 `WebSocketManager`，确保每个任务只有一个 WebSocket 连接
    - 使用发布-订阅模式支持多组件监听同一任务
    - 优化心跳参数（pongWait: 60s, pingPeriod: 25s）
    - 改善错误处理，正确识别正常关闭（1000, 1001, 1005）
    - 减少日志噪音，移除常规连接/断开日志
  - **前端优化**：
    - 简化实时进度组件（RealTimeProgress），只显示基础进度条
    - 修复 React Strict Mode 导致的双重连接问题
    - 增加 WebSocket 连接延迟（500ms）以避免重复连接
  - **扫描器实时保存优化**：
    - **C段扫描器**：添加存活性检测，只保存存活的 IP（探测常用端口：80, 443, 22, 3389, 8080, 8443）
    - **端口扫描器**：改为实时保存，每发现一个开放端口立即存储到数据库
      - TCP Connect 扫描：实时保存
      - Nmap SYN 扫描：实时保存
    - **所有扫描器**：确认已使用实时保存模式（域名、站点、PoC、服务、爬虫等）
  - **修复问题**：
    - 修复 `config.go` 中 `getEnvOrConfigInt` 的逻辑错误
    - 修复 `task_service.go` 中缺失的语法错误（if 语句缺少花括号）
    - 移除未使用的 import（`sync` in `port_scanner.go`）
  - **优化效果**：
    - ✅ 用户体验提升：扫描结果实时展示，无需等待全部完成
    - ✅ 数据安全：即使扫描中断，已发现的结果也已保存
    - ✅ 内存优化：不再在内存中积累大量结果
    - ✅ WebSocket 稳定性：消除频繁重连，减少服务器负载

- **2025-10-22** - v0.3：指纹系统重构与批量扫描优化
  - **指纹格式升级**：从旧的 `rule_type` + `rule_content` 格式升级到 DSL 数组格式
    - 新格式：`{ name: "指纹名", dsl: ["contains(body, 'keyword')", ...] }`
    - 支持多条 DSL 规则，提升灵活性
    - 成功加载 3371 条指纹规则
  - **WebSocket 实时进度推送**：
    - 实现 WebSocket 连接，支持扫描任务实时进度更新
    - 动态批次优化：根据扫描目标数量自动调整批次大小（5-30个IP/批次）
    - 进度更新频率优化：每10-50次扫描或每0.5秒更新一次
    - 显示扫描速度、预计剩余时间（ETA）、已发现开放端口数
  - **前端优化**：
    - 更新指纹添加页面，支持动态添加/删除 DSL 规则
    - 移除可信度字段，简化表单
    - 优化表格显示，支持多条 DSL 规则展示
    - 修复资产测绘页面分页功能（pageSize 无法修改的问题）
    - 修复 GitHub 监控结果按钮（添加标签页切换功能）
    - 优化资产测绘页面表格列标题显示（斜杠改为中文圆点）
  - **后端优化**：
    - 实现 DSL 解析器，支持 `contains(target, 'keyword')` 语法
    - 更新指纹加载器，从 `finger.yaml` 自动加载指纹
    - 添加数据库迁移逻辑，自动清理旧格式数据和字段
    - 优化批量扫描性能，解决大量域名扫描卡在 0% 的问题
  - **修复问题**：
    - 修复数据库迁移时的 NULL 值约束错误
    - 移除指纹可信度（confidence）字段
    - 修复 WebSocket 连接自动重连机制
    - 优化扫描进度计算精度

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

redis:
  host: localhost
  port: 6379
  password: ""
  db: 0

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

#### 4. 端口扫描说明

**无需安装任何扫描工具！** 🎉

- **端口发现**: Naabu（纯Go实现，已集成）
- **服务识别**: gonmap（纯Go实现，内置nmap指纹库，已集成）
- **自适应速率**: 根据扫描规模自动调整（1000-10000 pps）

所有扫描功能已通过Go依赖集成，开箱即用。

#### 5. 启动系统
```bash
cd backend
# 编译
go build -o bin/server ./cmd/server

# ⚠️ 重要：Naabu需要root权限进行SYN扫描（高性能模式）
sudo ./bin/server
```

**说明**：Naabu使用原始套接字（raw socket）进行SYN扫描，需要root权限。如果不想使用sudo，Naabu会自动降级为TCP Connect扫描（速度较慢）。

#### 6. 访问系统
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
