import api, { ApiResponse } from '@/lib/api';

// 监控页面
export interface MonitoredPage {
  id: string;
  url: string;
  name: string;
  interval: number; // 检查间隔(分钟)
  enabled: boolean;
  monitorTypes: MonitorType[];
  keywords?: string[]; // 关键词监控
  lastCheck?: string;
  lastSnapshot?: PageSnapshot;
  status: 'normal' | 'changed' | 'error' | 'pending';
  createdAt: string;
  updatedAt: string;
}

export type MonitorType =
  | 'content_hash'
  | 'dom_structure'
  | 'keywords'
  | 'links';

// 页面快照
export interface PageSnapshot {
  id: string;
  pageId: string;
  url: string;
  contentHash: string;
  domHash?: string;
  title?: string;
  links?: string[];
  keywords?: Record<string, number>; // 关键词出现次数
  statusCode: number;
  contentLength: number;
  capturedAt: string;
}

// 变化记录
export interface ChangeRecord {
  id: string;
  pageId: string;
  pageName: string;
  url: string;
  changeType: MonitorType;
  oldValue: string;
  newValue: string;
  oldSnapshot?: PageSnapshot;
  newSnapshot?: PageSnapshot;
  detectedAt: string;
  acknowledged: boolean;
}

// 监控类型信息
export interface MonitorTypeInfo {
  id: MonitorType;
  name: string;
  description: string;
}

export const monitorApi = {
  // 获取监控类型列表
  getMonitorTypes: (): Promise<ApiResponse<MonitorTypeInfo[]>> =>
    api.get('/monitor/types'),

  // 获取监控页面列表
  getPages: (params?: {
    page?: number;
    pageSize?: number;
    status?: string;
  }): Promise<ApiResponse<{ list: MonitoredPage[]; total: number }>> =>
    api.get('/monitor/pages', { params }),

  // 获取单个监控页面
  getPage: (id: string): Promise<ApiResponse<MonitoredPage>> =>
    api.get(`/monitor/pages/${id}`),

  // 添加监控页面
  addPage: (data: {
    url: string;
    name: string;
    interval: number;
    monitorTypes: MonitorType[];
    keywords?: string[];
  }): Promise<ApiResponse<MonitoredPage>> => api.post('/monitor/pages', data),

  // 更新监控页面
  updatePage: (
    id: string,
    data: Partial<MonitoredPage>
  ): Promise<ApiResponse<MonitoredPage>> =>
    api.put(`/monitor/pages/${id}`, data),

  // 删除监控页面
  deletePage: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/monitor/pages/${id}`),

  // 启用/禁用监控
  togglePage: (id: string, enabled: boolean): Promise<ApiResponse<null>> =>
    api.put(`/monitor/pages/${id}/enable`, { enabled }),

  // 立即检查
  checkNow: (
    id: string
  ): Promise<ApiResponse<{ changed: boolean; snapshot?: PageSnapshot }>> =>
    api.post(`/monitor/pages/${id}/check`),

  // 获取变化记录
  getChanges: (params?: {
    page?: number;
    pageSize?: number;
    pageId?: string;
    changeType?: MonitorType;
    acknowledged?: boolean;
  }): Promise<ApiResponse<{ list: ChangeRecord[]; total: number }>> =>
    api.get('/monitor/changes', { params }),

  // 确认变化
  acknowledgeChange: (id: string): Promise<ApiResponse<null>> =>
    api.put(`/monitor/changes/${id}/acknowledge`),

  // 获取快照历史
  getSnapshots: (
    pageId: string,
    params?: { page?: number; pageSize?: number }
  ): Promise<ApiResponse<{ list: PageSnapshot[]; total: number }>> =>
    api.get(`/monitor/pages/${pageId}/snapshots`, { params }),

  // 对比快照
  compareSnapshots: (
    id1: string,
    id2: string
  ): Promise<ApiResponse<{ diff: string; changes: string[] }>> =>
    api.get('/monitor/snapshots/compare', { params: { id1, id2 } }),
};
