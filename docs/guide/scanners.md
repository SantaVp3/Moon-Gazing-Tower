# 扫描引擎详解

Moon-Gazing-Tower 的核心能力来自于集成的多个开源安全工具。本章将详细介绍各个扫描模块的工作原理和配置。

## 1. 子域名枚举 (Subdomain Enumeration)

**核心工具**: [Subfinder](https://github.com/projectdiscovery/subfinder)

### 工作流程
1. **被动收集**: 从 Crt.sh, SecurityTrails, Fofa 等公开数据源收集子域名。
2. **主动爆破** (可选): 使用字典对域名进行爆破。
3. **DNS 解析**: 验证收集到的子域名是否存活，并解析其 IP 地址。
4. **泛解析处理**: 自动识别并处理泛解析域名，避免误报。

### 配置参数
- `threads`: 并发线程数
- `timeout`: DNS 解析超时时间
- `sources`: 启用的数据源列表

## 2. 端口扫描 (Port Scanning)

**核心工具**: [RustScan](https://github.com/RustScan/RustScan)

### 工作流程
1. **主机发现**: 确认目标主机是否存活。
2. **端口探测**: 使用 RustScan 进行超高速端口扫描。
3. **服务识别**: 对开放端口进行指纹识别，判断运行的服务 (HTTP, SSH, MySQL 等)。

### 扫描模式
- **快速模式 (Quick)**: 扫描 Top 100 常用端口。
- **全端口模式 (Full)**: 扫描 1-65535 全端口。
- **自定义模式 (Custom)**: 扫描用户指定的端口范围。

## 3. Web 爬虫 (Web Crawler)

**核心工具**: [Katana](https://github.com/projectdiscovery/katana), [Rad](https://github.com/chaitin/rad)

### 工作流程
1. **URL 收集**: 从首页开始爬取链接。
2. **动态渲染**: 使用 Headless Browser (如 Chrome) 渲染页面，抓取动态加载的内容。
3. **表单提取**: 自动识别页面中的表单参数。
4. **去重过滤**: 过滤重复的 URL 和静态资源。

## 4. 漏洞扫描 (Vulnerability Scanning)

**核心工具**: [Nuclei](https://github.com/projectdiscovery/nuclei)

### 工作流程
1. **模板匹配**: 根据目标指纹，选择合适的 Nuclei 模板。
2. **Payload 发送**: 向目标发送构造好的 HTTP 请求。
3. **响应匹配**: 检查响应内容是否包含漏洞特征。
4. **误报剔除**: 通过多重验证机制减少误报。

### 支持的漏洞类型
- Web 通用漏洞 (SQLi, XSS, RCE, SSRF)
- 中间件漏洞 (Tomcat, Weblogic, Jenkins)
- 框架漏洞 (Spring, Struts2, ThinkPHP)
- 弱口令检测
- 敏感信息泄露

## 5. 指纹识别 (Fingerprinting)

**核心工具**: 内置指纹库 + [Wappalyzer](https://www.wappalyzer.com/) 规则

### 识别内容
- **CMS**: WordPress, Discuz, Dedecms 等
- **Web 服务器**: Nginx, Apache, IIS
- **开发语言**: PHP, Java, Python, Go
- **操作系统**: Linux, Windows
- **WAF**: 阿里云 WAF, Cloudflare

## 6. 目录扫描 (Directory Scanning)

**核心工具**: 内置目录扫描器

### 工作流程
1. **字典加载**: 加载预置的敏感目录字典 (如 `admin/`, `backup/`, `.git/`)。
2. **Fuzzing**: 对目标 URL 进行路径拼接和探测。
3. **状态码分析**: 根据 HTTP 状态码 (200, 403) 判断目录是否存在。
