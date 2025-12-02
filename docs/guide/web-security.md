# Web 安全扫描

Moon-Gazing-Tower 提供了全面的 Web 安全扫描能力，除了常规的漏洞扫描外，还包含目录扫描、敏感信息检测等深度探测功能。

## 目录扫描 (Directory Scanning)

目录扫描用于发现 Web 服务器上未公开的目录、备份文件、配置文件等敏感资源。

### 核心功能

- **字典爆破**: 使用预置的高质量字典对目标进行路径爆破。
- **智能扩展**: 自动组合常见后缀（如 `.php`, `.bak`, `.zip`, `.sql`）进行探测。
- **状态码过滤**: 智能识别 404 页面，过滤误报。
- **并发控制**: 支持高并发扫描，同时提供速率限制以避免被 WAF 封禁。

### 扫描策略

系统内置了多种扫描策略：

1. **快速扫描 (Quick)**: 仅扫描最常见的敏感路径（如 `/admin`, `/backup`, `/.git`）。
2. **全量扫描 (Full)**: 使用大字典进行全面覆盖。
3. **自定义扫描**: 支持用户上传自定义字典。

### 常见发现

- **管理后台**: `/admin`, `/manager`, `/dashboard`
- **源码泄露**: `/.git`, `/.svn`, `/.DS_Store`
- **备份文件**: `www.zip`, `backup.sql`, `config.php.bak`
- **测试文件**: `test.php`, `info.php`

## 敏感信息检测 (Sensitive Info)

敏感信息检测模块用于识别网页源码、JS 文件、API 响应中泄露的敏感数据。

### 检测原理

基于正则表达式匹配和上下文分析，自动识别页面中的敏感信息。

### 检测范围

1. **凭证密钥**:
   - API Key / Secret Key
   - AWS / Azure / Google Cloud 凭证
   - SSH 私钥 (RSA/DSA)
   - JWT Token

2. **个人隐私 (PII)**:
   - 手机号码
   - 邮箱地址
   - 身份证号
   - 银行卡号

3. **配置信息**:
   - 数据库连接字符串
   - 内网 IP 地址
   - 调试信息 / 堆栈跟踪

### 规则配置

用户可以在 `config/config.yaml` 中自定义敏感信息匹配规则：

```yaml
vuln:
  sensitive_patterns:
    - name: "custom_token"
      pattern: "token=[a-zA-Z0-9]{32}"
      severity: "high"
```

## 弱口令检测 (Weak Password)

针对常见的 Web 服务和管理后台进行弱口令爆破。

### 支持协议/服务
- HTTP Basic Auth
- Tomcat Manager
- Jenkins
- WebLogic
- SSH / FTP / MySQL / Redis (通过端口扫描模块触发)

### 字典管理
系统内置了针对不同服务的精选弱口令字典，同时也支持用户导入自定义字典。

## 页面监控 (Page Monitor)

对关键页面进行周期性监控，及时发现篡改或异常。

- **内容变动监控**: 计算页面 Hash，发现内容变化即告警。
- **关键词监控**: 监控页面是否出现特定关键词（如博彩、色情词汇）。
- **状态码监控**: 监控页面可用性。
