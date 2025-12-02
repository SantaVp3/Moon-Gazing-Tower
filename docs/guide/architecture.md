# 架构设计

Moon-Gazing-Tower 采用前后端分离的架构设计，后端基于 Go 语言开发，前端基于 React 框架。

## 系统架构图

```mermaid
graph TD
    Client[前端 (React)] -->|REST API / WebSocket| Gateway[API 网关 (Gin)]
    Gateway --> Auth[认证服务]
    Gateway --> Asset[资产服务]
    Gateway --> Task[任务服务]
    Gateway --> Vuln[漏洞服务]
    
    Task -->|调度| Queue[任务队列 (Redis)]
    Queue --> Worker[扫描 Worker]
    
    Worker --> Subfinder[子域名枚举]
    Worker --> RustScan[端口扫描]
    Worker --> Nuclei[漏洞扫描]
    Worker --> Crawler[Web 爬虫]
    
    Worker -->|结果| DB[(MongoDB)]
    Asset -->|读写| DB
    Vuln -->|读写| DB
```

## 技术栈

### 后端 (Backend)
- **语言**: Go 1.24
- **Web 框架**: [Gin](https://github.com/gin-gonic/gin) - 高性能 Web 框架
- **数据库**: [MongoDB](https://www.mongodb.com/) - 灵活的文档数据库，存储资产和漏洞数据
- **缓存/队列**: [Redis](https://redis.io/) - 用于任务队列和缓存
- **认证**: JWT (JSON Web Token)

### 前端 (Frontend)
- **框架**: [React 18](https://react.dev/)
- **构建工具**: [Vite](https://vitejs.dev/)
- **UI 组件库**: [shadcn/ui](https://ui.shadcn.com/) + [Tailwind CSS](https://tailwindcss.com/)
- **状态管理**: [TanStack Query](https://tanstack.com/query/latest)

### 扫描引擎 (Scanners)
系统通过封装命令行工具或库的方式集成以下扫描引擎：

| 引擎 | 用途 |
|------|------|
| **Subfinder** | 被动子域名枚举 |
| **RustScan** | 高速端口扫描 |
| **Nuclei** | 基于模板的漏洞扫描 |
| **Katana** | 下一代网络爬虫 |
| **Rad** | 浏览器爬虫 |
| **Httpx** | HTTP 探测 |

## 目录结构

```
.
├── backend/                # 后端代码
│   ├── api/               # API 处理函数
│   ├── config/            # 配置文件
│   ├── database/          # 数据库连接
│   ├── models/            # 数据模型
│   ├── router/            # 路由定义
│   ├── scanner/           # 扫描器封装
│   ├── service/           # 业务逻辑
│   └── tools/             # 外部工具二进制文件
├── frontend/               # 前端代码
│   ├── src/
│   │   ├── components/    # UI 组件
│   │   ├── pages/         # 页面
│   │   └── services/      # API 调用
└── docs/                   # 文档中心
```
