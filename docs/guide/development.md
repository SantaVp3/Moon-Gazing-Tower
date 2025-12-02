# 开发指南

欢迎参与 Moon-Gazing-Tower 的开发！本指南将帮助你了解项目结构并进行二次开发。

## 后端开发

### 1. 添加新的 API

1. **定义路由**: 在 `backend/router/router.go` 中注册新的路由。
   ```go
   // 示例
   group.GET("/new-feature", handler.NewFeature)
   ```

2. **创建 Handler**: 在 `backend/api/` 目录下创建新的 Handler 文件。
   ```go
   func (h *Handler) NewFeature(c *gin.Context) {
       // 业务逻辑
       c.JSON(200, gin.H{"message": "success"})
   }
   ```

3. **实现 Service**: 在 `backend/service/` 中实现具体的业务逻辑。

### 2. 集成新的扫描工具

1. **封装工具**: 在 `backend/scanner/` 下创建新的扫描器封装。通常需要实现 `Scanner` 接口或提供执行命令的方法。
   ```go
   type NewScanner struct {
       // 配置
   }
   
   func (s *NewScanner) Scan(target string) (*Result, error) {
       // 调用外部命令或库
   }
   ```

2. **注册任务类型**: 在 `backend/models/task.go` 中添加新的 `TaskType`。

3. **更新 Worker**: 在 `backend/service/task_executor.go` 中处理新的任务类型，调用对应的扫描器。

## 前端开发

### 1. 项目结构

```
frontend/src/
├── components/    # 通用组件 (Button, Input, Table)
├── pages/         # 页面组件 (Dashboard, AssetList)
├── services/      # API 请求封装
├── store/         # 状态管理 (Zustand / Context)
├── types/         # TypeScript 类型定义
└── utils/         # 工具函数
```

### 2. 添加新页面

1. **创建页面组件**: 在 `frontend/src/pages/` 下创建新的 `.tsx` 文件。
2. **配置路由**: 在 `frontend/src/router.tsx` (或 `App.tsx`) 中添加路由配置。
3. **添加导航**: 在 `frontend/src/components/Layout/Sidebar.tsx` 中添加侧边栏菜单。

### 3. API 调用

使用 `axios` 或 `fetch` 封装 API 请求。建议在 `frontend/src/services/` 下统一管理。

```typescript
// services/api.ts
export const getNewFeature = async () => {
  const response = await request.get('/api/new-feature');
  return response.data;
};
```

## 调试

- **后端调试**: 使用 VS Code 的 `Run and Debug` 功能，配置 `launch.json` 启动 Go 程序。
- **前端调试**: 使用 Chrome DevTools 和 React Developer Tools。

## 代码规范

- **Go**: 遵循 `gofmt` 和官方 Go Code Review Comments。
- **TypeScript**: 遵循 ESLint 和 Prettier 配置。
