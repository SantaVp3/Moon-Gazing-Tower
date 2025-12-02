# API 参考

Moon-Gazing-Tower 提供了一套 RESTful API 用于与前端交互和第三方集成。

## 基础信息

- **Base URL**: `/api`
- **认证方式**: Bearer Token (JWT)

## 认证 (Auth)

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/auth/login` | 用户登录 |
| POST | `/auth/refresh` | 刷新 Token |
| POST | `/auth/logout` | 退出登录 |
| GET | `/auth/profile` | 获取个人信息 |

## 资产 (Assets)

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/assets` | 获取资产列表 |
| POST | `/assets` | 创建新资产 |
| GET | `/assets/:id` | 获取资产详情 |
| PUT | `/assets/:id` | 更新资产 |
| DELETE | `/assets/:id` | 删除资产 |
| GET | `/assets/stats` | 获取资产统计信息 |
| POST | `/assets/batch-delete` | 批量删除资产 |

## 任务 (Tasks)

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/tasks` | 获取任务列表 |
| POST | `/tasks` | 创建扫描任务 |
| POST | `/tasks/:id/start` | 开始任务 |
| POST | `/tasks/:id/pause` | 暂停任务 |
| POST | `/tasks/:id/cancel` | 取消任务 |
| GET | `/tasks/:id/results` | 获取任务结果 |

## 漏洞 (Vulnerabilities)

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/vulnerabilities` | 获取漏洞列表 |
| GET | `/vulnerabilities/stats` | 获取漏洞统计 |
| PUT | `/vulnerabilities/:id/fixed` | 标记漏洞为已修复 |
| PUT | `/vulnerabilities/:id/ignore` | 忽略漏洞 |
| POST | `/vulnerabilities/:id/verify` | 验证漏洞 |

## 扫描 (Scan)

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/scan/subdomain/quick` | 快速子域名扫描 |
| POST | `/scan/port/quick` | 快速端口扫描 |
| POST | `/scan/vuln/quick` | 快速漏洞扫描 |
| POST | `/scan/fingerprint` | 指纹识别 |
| POST | `/scan/cdn/detect` | CDN 检测 |

> 更多 API 详情请参考后端代码中的 `router/router.go` 文件。
