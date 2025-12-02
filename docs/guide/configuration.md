# 配置指南

Moon-Gazing-Tower 的后端配置主要通过 `config/config.yaml` 文件进行管理。

## 配置文件结构

配置文件主要包含以下几个部分：

### 1. 服务器配置 (Server)

配置 HTTP 服务器的基本信息。

```yaml
server:
  host: "0.0.0.0"  # 监听地址
  port: 8080       # 监听端口
  mode: "release"  # 运行模式: debug, release, test
```

### 2. 认证配置 (JWT)

配置 JWT Token 的生成和验证参数。

```yaml
jwt:
  secret: "your-secret-key" # JWT 签名密钥，请务必修改
  expire: 24                # Token 过期时间（小时）
  issuer: "moongazing"      # Token 签发者
```

### 3. 数据库配置 (MongoDB)

配置 MongoDB 连接信息。

```yaml
mongodb:
  uri: "mongodb://localhost:27017" # MongoDB 连接 URI
  database: "moongazing"           # 数据库名称
  timeout: 10                      # 连接超时时间（秒）
```

### 4. 缓存/队列配置 (Redis)

配置 Redis 连接信息，用于缓存和任务队列。

```yaml
redis:
  host: "localhost"
  port: 6379
  password: ""     # Redis 密码，无密码留空
  db: 0            # 使用的数据库索引
```

### 5. 扫描器配置 (Scanner)

配置扫描任务的并发和重试策略。

```yaml
scanner:
  worker_count: 10 # 并发 Worker 数量
  timeout: 300     # 任务超时时间（秒）
  retry_count: 3   # 失败重试次数
  retry_delay: 5   # 重试延迟（秒）
```

### 6. 日志配置 (Log)

配置系统日志输出。

```yaml
log:
  level: "info"        # 日志级别: debug, info, warn, error
  file: "logs/app.log" # 日志文件路径
  max_size: 100        # 单个日志文件最大大小 (MB)
  max_backups: 3       # 保留旧日志文件的最大个数
  max_age: 28          # 保留旧日志文件的最大天数
```

### 7. 第三方 API 配置 (ThirdParty)

配置第三方安全服务的 API Key，用于增强扫描能力。

```yaml
thirdparty:
  fofa:
    email: "" # FOFA 账号邮箱
    key: ""   # FOFA API Key
  hunter:
    key: ""   # Hunter API Key
  quake:
    key: ""   # Quake API Key
```

## 环境变量覆盖

除了直接修改配置文件，你也可以通过环境变量来覆盖配置。环境变量的命名规则为 `MOONGAZING_` 前缀加上配置路径，用下划线分隔。

例如：
- `MOONGAZING_SERVER_PORT=9090` 覆盖 `server.port`
- `MOONGAZING_MONGODB_URI=mongodb://mongo:27017` 覆盖 `mongodb.uri`
