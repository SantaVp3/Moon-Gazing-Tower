import api, {
  ApiResponse,
  PaginationParams,
  PaginatedResponse,
} from '@/lib/api';

// Backend paginated response format
interface BackendPaginatedResponse<T> {
  code: number;
  message: string;
  data: T[];
  total: number;
  page: number;
  size: number;
}

// Helper to transform backend task to frontend format
const transformTask = (task: Record<string, unknown>): Task => {
  const config = (task.config as Record<string, unknown>) || {};
  const resultStats = (task.result_stats as Record<string, unknown>) || {};

  return {
    id: task.id as string,
    name: task.name as string,
    type: task.type as string,
    status: (task.status as Task['status']) || 'pending',
    progress: (task.progress as number) || 0,
    config: {
      scanTypes: (config.scan_types as string[]) || [],
      portRange: config.port_range as string,
      timeout: config.timeout as number,
      concurrent: config.concurrent as number,
      enabledPlugins: config.enabled_plugins as string[],
      pocIds: config.poc_ids as string[],
      customParams: config.custom_params as Record<string, unknown>,
    },
    targets: (task.targets as string[]) || [],
    targetType: task.target_type as string,
    nodeId: task.node_id as string,
    scheduledAt: task.scheduled_at as string,
    startedAt: task.started_at as string,
    completedAt: task.completed_at as string,
    results: {
      totalAssets: (resultStats.total_targets as number) || 0,
      scannedAssets: (resultStats.scanned_targets as number) || 0,
      vulnerabilities: (resultStats.vulnerabilities_found as number) || 0,
      duration: (resultStats.duration as number) || 0,
    },
    error: task.last_error as string,
    createdBy: task.created_by as string,
    createdAt: task.created_at as string,
    updatedAt: task.updated_at as string,
  };
};

export interface Task {
  id: string;
  name: string;
  type: string;
  status:
    | 'pending'
    | 'running'
    | 'paused'
    | 'completed'
    | 'failed'
    | 'cancelled';
  progress: number;
  config: TaskConfig;
  targets: string[]; // 扫描目标列表
  targetType?: string; // 目标类型
  nodeId?: string;
  scheduledAt?: string;
  startedAt?: string;
  completedAt?: string;
  results?: TaskResult;
  error?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface TaskConfig {
  scan_types?: string[]; // 后端使用 snake_case
  scanTypes?: string[]; // 兼容旧代码
  port_scan_mode?: string; // quick, full, top1000, custom
  portRange?: string;
  timeout?: number;
  concurrent?: number;
  enabledPlugins?: string[];
  pocIds?: string[];
  customParams?: Record<string, unknown>;
  // 第三方 API 配置
  use_thirdparty?: boolean;
  thirdparty_sources?: string[];
  fofa_email?: string;
  fofa_key?: string;
  hunter_key?: string;
  quake_key?: string;
}

export interface TaskResult {
  totalAssets: number;
  scannedAssets: number;
  vulnerabilities: number;
  duration: number;
}

export interface TaskLog {
  id: string;
  taskId: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  timestamp: string;
}

export interface TaskTemplate {
  id: string;
  name: string;
  description?: string;
  config: TaskConfig;
  createdAt: string;
}

export const taskApi = {
  // Tasks
  getTasks: async (
    params?: PaginationParams & {
      status?: string;
      type?: string;
    }
  ): Promise<PaginatedResponse<Task>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      status: params?.status,
      type: params?.type,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get('/tasks', { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformTask),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  getTask: async (id: string): Promise<ApiResponse<Task>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      `/tasks/${id}`
    );
    return {
      code: response.code,
      message: response.message,
      data: transformTask(response.data),
    };
  },

  createTask: (data: {
    name: string;
    type: string;
    targets: string[]; // 目标列表 (IP, domain, URL等)
    targetType: string; // 目标类型: ip, domain, url, mixed
    config: TaskConfig;
    description?: string;
    scheduledAt?: string;
    tags?: string[];
  }): Promise<ApiResponse<Task>> => {
    // Map frontend fields to backend expected fields (snake_case for backend)
    const backendConfig: Record<string, unknown> = {
      scan_types: data.config.scanTypes || data.config.scan_types,
      port_scan_mode: data.config.port_scan_mode,
      port_range: data.config.portRange,
      timeout: data.config.timeout,
      threads: data.config.concurrent, // 前端 concurrent -> 后端 threads
      poc_ids: data.config.pocIds,
      enabled_plugins: data.config.enabledPlugins,
      custom_params: data.config.customParams,
      // 第三方 API 配置
      use_thirdparty: data.config.use_thirdparty,
      thirdparty_sources: data.config.thirdparty_sources,
      fofa_email: data.config.fofa_email,
      fofa_key: data.config.fofa_key,
      hunter_key: data.config.hunter_key,
      quake_key: data.config.quake_key,
    };

    const payload = {
      name: data.name,
      type: data.type,
      targets: data.targets,
      target_type: data.targetType,
      config: backendConfig,
      description: data.description,
      tags: data.tags,
    };
    return api.post('/tasks', payload);
  },

  updateTask: (id: string, data: Partial<Task>): Promise<ApiResponse<Task>> =>
    api.put(`/tasks/${id}`, data),

  deleteTask: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/tasks/${id}`),

  // Task Actions
  startTask: (id: string): Promise<ApiResponse<Task>> =>
    api.post(`/tasks/${id}/start`),

  pauseTask: (id: string): Promise<ApiResponse<Task>> =>
    api.post(`/tasks/${id}/pause`),

  resumeTask: (id: string): Promise<ApiResponse<Task>> =>
    api.post(`/tasks/${id}/resume`),

  cancelTask: (id: string): Promise<ApiResponse<Task>> =>
    api.post(`/tasks/${id}/cancel`),

  retryTask: (id: string): Promise<ApiResponse<Task>> =>
    api.post(`/tasks/${id}/retry`),

  // 重新扫描任务（默认继续未完成部分，fromScratch=true 则从头开始）
  rescanTask: (
    id: string,
    fromScratch: boolean = false
  ): Promise<ApiResponse<Task>> =>
    api.post(`/tasks/${id}/rescan`, { from_scratch: fromScratch }),

  // Task Logs
  getTaskLogs: async (
    taskId: string,
    params?: PaginationParams
  ): Promise<PaginatedResponse<TaskLog>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get(`/tasks/${taskId}/logs`, { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(
          (log): TaskLog => ({
            id: log.id as string,
            taskId: log.task_id as string,
            level: log.level as TaskLog['level'],
            message: log.message as string,
            timestamp: (log.timestamp as string) || (log.created_at as string),
          })
        ),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  // Task Templates
  getTemplates: async (
    params?: PaginationParams
  ): Promise<PaginatedResponse<TaskTemplate>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get('/task-templates', { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(
          (t): TaskTemplate => ({
            id: t.id as string,
            name: t.name as string,
            description: t.description as string,
            config: t.config as TaskConfig,
            createdAt: t.created_at as string,
          })
        ),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  createTemplate: (data: {
    name: string;
    description?: string;
    config: TaskConfig;
  }): Promise<ApiResponse<TaskTemplate>> => api.post('/task-templates', data),

  updateTemplate: (
    id: string,
    data: Partial<TaskTemplate>
  ): Promise<ApiResponse<TaskTemplate>> =>
    api.put(`/task-templates/${id}`, data),

  deleteTemplate: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/task-templates/${id}`),
};
