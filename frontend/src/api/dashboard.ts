import api, { ApiResponse } from '@/lib/api';

export interface DashboardStats {
  assets: {
    total: number;
    byType: Record<string, number>;
    recentlyAdded: number;
  };
  tasks: {
    total: number;
    running: number;
    completed: number;
    failed: number;
  };
  vulnerabilities: {
    total: number;
    open: number;
    bySeverity: Record<string, number>;
    recentlyFound: number;
  };
  nodes: {
    total: number;
    online: number;
    offline: number;
  };
}

export interface ActivityLog {
  id: string;
  type: string;
  action: string;
  target: string;
  targetId: string;
  userId: string;
  username: string;
  details?: string;
  createdAt: string;
}

export interface TrendData {
  date: string;
  assets: number;
  vulnerabilities: number;
  tasks: number;
}

export const dashboardApi = {
  getStats: (): Promise<ApiResponse<DashboardStats>> =>
    api.get('/dashboard/stats'),

  getRecentActivities: (limit?: number): Promise<ApiResponse<ActivityLog[]>> =>
    api.get('/dashboard/activities', { params: { limit: limit || 10 } }),

  getTrends: (days?: number): Promise<ApiResponse<TrendData[]>> =>
    api.get('/dashboard/trends', { params: { days: days || 7 } }),

  getTopVulnerabilities: (
    limit?: number
  ): Promise<
    ApiResponse<
      Array<{
        type: string;
        count: number;
        severity: string;
      }>
    >
  > =>
    api.get('/dashboard/top-vulnerabilities', {
      params: { limit: limit || 10 },
    }),

  getAssetDistribution: (): Promise<
    ApiResponse<
      Array<{
        type: string;
        count: number;
      }>
    >
  > => api.get('/dashboard/asset-distribution'),
};
