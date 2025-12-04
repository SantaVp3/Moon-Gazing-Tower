import api, { PaginationParams } from '@/lib/api';
import { TaskConfig } from './tasks';

export type CruiseStatus = 'enabled' | 'disabled' | 'running';

export interface CruiseTask {
  id: string;
  workspace_id?: string;
  name: string;
  description: string;
  status: CruiseStatus;
  cron_expr: string;
  timezone: string;
  targets: string[];
  target_type: string;
  task_type: string;
  config: TaskConfig;
  notify_on_complete: boolean;
  notify_on_vuln: boolean;
  notify_channels: string[];
  tags: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
  last_run_at?: string;
  next_run_at?: string;
  last_task_id?: string;
  last_status?: string;
  run_count: number;
  success_count: number;
  fail_count: number;
}

export interface CruiseLog {
  id: string;
  cruise_id: string;
  task_id: string;
  status: string;
  start_time: string;
  end_time?: string;
  duration: number;
  result_count: number;
  vuln_count: number;
  error?: string;
  created_at: string;
}

export interface CruiseCreateRequest {
  name: string;
  description?: string;
  cron_expr: string;
  timezone?: string;
  targets: string[];
  target_type: string;
  task_type: string;
  config: TaskConfig;
  notify_on_complete?: boolean;
  notify_on_vuln?: boolean;
  notify_channels?: string[];
  tags?: string[];
}

export interface CruiseUpdateRequest {
  name?: string;
  description?: string;
  cron_expr?: string;
  timezone?: string;
  targets?: string[];
  target_type?: string;
  task_type?: string;
  config?: TaskConfig;
  notify_on_complete?: boolean;
  notify_on_vuln?: boolean;
  notify_channels?: string[];
  tags?: string[];
}

export interface CruiseStats {
  total: number;
  enabled: number;
  disabled: number;
  running: number;
}

// Backend response format (wrapped in code/message/data structure)
interface BackendResponse<T> {
  code: number;
  message: string;
  data: T;
}

interface CruiseListData {
  items: CruiseTask[];
  total: number;
  page: number;
  pageSize: number;
}

interface CruisePaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export const cruiseApi = {
  // 列出巡航任务
  getCruises: async (
    params: PaginationParams & { search?: string }
  ): Promise<CruisePaginatedResult<CruiseTask>> => {
    const response = await api.get<BackendResponse<CruiseListData>>(
      '/cruises',
      { params }
    );
    const backendResponse =
      response as unknown as BackendResponse<CruiseListData>;
    return {
      items: backendResponse.data?.items || [],
      total: backendResponse.data?.total || 0,
      page: backendResponse.data?.page || 1,
      pageSize: backendResponse.data?.pageSize || 10,
    };
  },

  // 获取巡航统计
  getCruiseStats: async (): Promise<CruiseStats> => {
    const response =
      await api.get<BackendResponse<CruiseStats>>('/cruises/stats');
    const backendResponse = response as unknown as BackendResponse<CruiseStats>;
    return backendResponse.data;
  },

  // 获取单个巡航任务
  getCruise: async (id: string): Promise<CruiseTask> => {
    const response = await api.get<BackendResponse<CruiseTask>>(
      `/cruises/${id}`
    );
    const backendResponse = response as unknown as BackendResponse<CruiseTask>;
    return backendResponse.data;
  },

  // 创建巡航任务
  createCruise: async (data: CruiseCreateRequest): Promise<CruiseTask> => {
    const response = await api.post<BackendResponse<CruiseTask>>(
      '/cruises',
      data
    );
    const backendResponse = response as unknown as BackendResponse<CruiseTask>;
    return backendResponse.data;
  },

  // 更新巡航任务
  updateCruise: async (
    id: string,
    data: CruiseUpdateRequest
  ): Promise<void> => {
    await api.put(`/cruises/${id}`, data);
  },

  // 删除巡航任务
  deleteCruise: async (id: string): Promise<void> => {
    await api.delete(`/cruises/${id}`);
  },

  // 启用巡航任务
  enableCruise: async (id: string): Promise<void> => {
    await api.post(`/cruises/${id}/enable`);
  },

  // 禁用巡航任务
  disableCruise: async (id: string): Promise<void> => {
    await api.post(`/cruises/${id}/disable`);
  },

  // 立即执行
  runCruise: async (id: string): Promise<void> => {
    await api.post(`/cruises/${id}/run`);
  },

  // 获取执行日志
  getCruiseLogs: async (
    id: string,
    params: PaginationParams
  ): Promise<CruisePaginatedResult<CruiseLog>> => {
    interface CruiseLogListData {
      items: CruiseLog[];
      total: number;
      page: number;
      pageSize: number;
    }
    const response = await api.get<BackendResponse<CruiseLogListData>>(
      `/cruises/${id}/logs`,
      { params }
    );
    const backendResponse =
      response as unknown as BackendResponse<CruiseLogListData>;
    return {
      items: backendResponse.data?.items || [],
      total: backendResponse.data?.total || 0,
      page: backendResponse.data?.page || 1,
      pageSize: backendResponse.data?.pageSize || 10,
    };
  },
};

export default cruiseApi;
