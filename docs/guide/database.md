# 数据库设计

Moon-Gazing-Tower 使用 MongoDB 作为主要的数据存储。以下是核心数据模型的设计文档。

## 1. 资产 (Asset)

存储发现的所有资产信息。

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | ObjectId | 唯一标识符 |
| `workspace_id` | ObjectId | 所属工作空间 ID |
| `type` | String | 资产类型: `ip`, `domain`, `subdomain`, `url`, `app`, `miniprogram` |
| `value` | String | 资产值 (如 IP 地址, 域名) |
| `title` | String | 资产标题 (如网页标题) |
| `status` | Int | 状态: `1` (活跃), `0` (非活跃) |
| `tags` | Array | 标签列表 |
| `group_id` | ObjectId | 所属分组 ID |
| `source` | String | 来源: `manual`, `scan`, `import` |
| `ip_info` | Object | IP 详细信息 (地理位置, ASN 等) |
| `domain_info` | Object | 域名详细信息 (DNS 记录, 注册商等) |
| `web_info` | Object | Web 服务信息 (Server, 指纹等) |

## 2. 任务 (Task)

存储扫描任务的配置和状态。

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | ObjectId | 唯一标识符 |
| `name` | String | 任务名称 |
| `type` | String | 任务类型: `full`, `subdomain`, `port_scan`, `vuln_scan` 等 |
| `status` | String | 状态: `pending`, `running`, `completed`, `failed`, `paused` |
| `targets` | Array | 扫描目标列表 |
| `target_type` | String | 目标类型: `ip`, `domain`, `url`, `cidr` |
| `config` | Object | 任务特定的扫描配置 |
| `created_at` | Date | 创建时间 |
| `started_at` | Date | 开始时间 |
| `completed_at` | Date | 完成时间 |

## 3. 漏洞 (Vulnerability)

存储扫描发现的漏洞信息。

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | ObjectId | 唯一标识符 |
| `asset_id` | ObjectId | 关联资产 ID |
| `task_id` | ObjectId | 关联任务 ID |
| `name` | String | 漏洞名称 |
| `severity` | String | 严重程度: `critical`, `high`, `medium`, `low`, `info` |
| `status` | String | 状态: `new`, `confirmed`, `fixed`, `ignored`, `false_positive` |
| `type` | String | 漏洞类型 (如 `sqli`, `xss`) |
| `template_id` | String | Nuclei 模板 ID |
| `target` | String | 漏洞目标 (URL 或 IP:Port) |
| `payload` | String | 攻击载荷 |
| `evidence` | String | 漏洞证据 (响应包等) |

## 4. 扫描结果 (ScanResult)

存储任务执行过程中的中间结果或最终结果。

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | ObjectId | 唯一标识符 |
| `task_id` | ObjectId | 关联任务 ID |
| `type` | String | 结果类型: `subdomain`, `port`, `service`, `vuln` |
| `data` | Object | 具体的扫描数据 (结构随类型变化) |
| `source` | String | 数据来源工具 (如 `subfinder`, `rustscan`) |
