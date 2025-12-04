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

// Transform backend vulnerability to frontend format
const transformVuln = (v: Record<string, unknown>): Vulnerability => ({
  id: v.id as string,
  name: v.name as string,
  severity: v.severity as Vulnerability['severity'],
  status: v.status as Vulnerability['status'],
  type: v.type as string,
  cve: v.cve_id as string,
  cwe: v.cwe_id as string,
  assetId: v.asset_id as string,
  assetName: v.asset_name as string,
  target: v.target as string,
  url: v.url as string,
  parameter: v.parameter as string,
  payload: v.payload as string,
  evidence: v.evidence as string,
  description: v.description as string,
  solution: v.solution as string,
  references: v.references as string[],
  pocId: v.poc_id as string,
  taskId: v.task_id as string,
  verifiedAt: v.verified_at as string,
  verifiedBy: v.verified_by as string,
  fixedAt: v.fixed_at as string,
  createdAt: v.created_at as string,
  updatedAt: v.updated_at as string,
});

// Transform backend POC to frontend format
const transformPOC = (p: Record<string, unknown>): POC => ({
  id: p.id as string,
  name: p.name as string,
  description: p.description as string,
  type: p.type as string,
  severity: p.severity as POC['severity'],
  cve: p.cve_id as string,
  author: p.author as string,
  content: p.content as string,
  language: p.language as POC['language'],
  tags: (p.tags as string[]) || [],
  enabled: p.enabled as boolean,
  createdAt: p.created_at as string,
  updatedAt: p.updated_at as string,
});

export interface Vulnerability {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'confirmed' | 'fixed' | 'ignored' | 'false_positive';
  type: string;
  cve?: string;
  cwe?: string;
  assetId: string;
  assetName: string;
  target: string;
  url?: string;
  parameter?: string;
  payload?: string;
  evidence?: string;
  description?: string;
  solution?: string;
  references?: string[];
  pocId?: string;
  taskId?: string;
  verifiedAt?: string;
  verifiedBy?: string;
  fixedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface POC {
  id: string;
  name: string;
  description?: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cve?: string;
  author?: string;
  content: string;
  language: 'yaml' | 'python' | 'go';
  tags: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface VulnStats {
  total: number;
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  byType: Record<string, number>;
  trend: Array<{
    date: string;
    count: number;
  }>;
}

// 漏洞统计详情
export interface VulnStatistics {
  total: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  statusCounts: {
    open: number;
    confirmed: number;
    fixed: number;
    ignored: number;
    false_positive: number;
  };
  typeCounts: Record<string, number>;
  recentVulnerabilities: Vulnerability[];
  trend: Array<{
    date: string;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  }>;
}

// 漏洞验证结果
export interface VulnVerifyResult {
  vulnerability: Vulnerability;
  verified: boolean;
}

export const vulnApi = {
  // Vulnerabilities
  getVulnerabilities: async (
    params?: PaginationParams & {
      severity?: string;
      status?: string;
      type?: string;
      assetId?: string;
      taskId?: string;
    }
  ): Promise<PaginatedResponse<Vulnerability>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      severity: params?.severity,
      status: params?.status,
      type: params?.type,
      asset_id: params?.assetId,
      task_id: params?.taskId,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get('/vulnerabilities', { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformVuln),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  getVulnerability: async (id: string): Promise<ApiResponse<Vulnerability>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      `/vulnerabilities/${id}`
    );
    return {
      code: response.code,
      message: response.message,
      data: transformVuln(response.data),
    };
  },

  updateVulnerability: (
    id: string,
    data: Partial<Vulnerability>
  ): Promise<ApiResponse<Vulnerability>> =>
    api.put(`/vulnerabilities/${id}`, data),

  deleteVulnerability: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/vulnerabilities/${id}`),

  batchUpdateStatus: (
    ids: string[],
    status: string
  ): Promise<ApiResponse<null>> =>
    api.post('/vulnerabilities/batch-update', { vuln_ids: ids, status }),

  verifyVulnerability: async (
    id: string
  ): Promise<ApiResponse<VulnVerifyResult>> => {
    const response: ApiResponse<{
      vulnerability: Record<string, unknown>;
      verified: boolean;
    }> = await api.post(`/vulnerabilities/${id}/verify`);
    return {
      code: response.code,
      message: response.message,
      data: {
        vulnerability: transformVuln(response.data.vulnerability),
        verified: response.data.verified,
      },
    };
  },

  // 获取详细统计
  getStatistics: async (
    workspaceId?: string
  ): Promise<ApiResponse<VulnStatistics>> => {
    const params = workspaceId ? { workspace_id: workspaceId } : {};
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      '/vulnerabilities/statistics',
      { params }
    );
    const data = response.data;

    // 后端返回格式: by_severity, by_status, by_type, recent_vulns, trend_data
    const bySeverity = (data.by_severity || {}) as Record<string, number>;
    const byStatus = (data.by_status || {}) as Record<string, number>;
    const trendData = (data.trend_data || []) as Array<{
      date: string;
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    }>;

    return {
      code: response.code,
      message: response.message,
      data: {
        total: (data.total as number) || 0,
        severityCounts: {
          critical: bySeverity['critical'] || 0,
          high: bySeverity['high'] || 0,
          medium: bySeverity['medium'] || 0,
          low: bySeverity['low'] || 0,
          info: bySeverity['info'] || 0,
        },
        statusCounts: {
          open: byStatus['open'] || 0,
          confirmed: byStatus['confirmed'] || 0,
          fixed: byStatus['fixed'] || 0,
          ignored: byStatus['ignored'] || 0,
          false_positive: byStatus['false_positive'] || 0,
        },
        typeCounts: (data.by_type || {}) as Record<string, number>,
        recentVulnerabilities: (
          (data.recent_vulns as Record<string, unknown>[]) || []
        ).map(transformVuln),
        trend: trendData.map((t) => ({
          ...t,
          total:
            (t.critical || 0) +
            (t.high || 0) +
            (t.medium || 0) +
            (t.low || 0) +
            (t.info || 0),
        })),
      },
    };
  },

  exportVulnerabilities: (params?: {
    severity?: string;
    status?: string;
  }): Promise<Blob> =>
    api.get('/vulnerabilities/export', { params, responseType: 'blob' }),

  getStats: (): Promise<ApiResponse<VulnStats>> =>
    api.get('/vulnerabilities/stats'),

  // POCs
  getPOCs: async (
    params?: PaginationParams & {
      type?: string;
      severity?: string;
      enabled?: boolean;
    }
  ): Promise<PaginatedResponse<POC>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      type: params?.type,
      severity: params?.severity,
      enabled: params?.enabled,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get('/pocs', { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformPOC),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  getPOC: async (id: string): Promise<ApiResponse<POC>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      `/pocs/${id}`
    );
    return {
      code: response.code,
      message: response.message,
      data: transformPOC(response.data),
    };
  },

  createPOC: (data: Partial<POC>): Promise<ApiResponse<POC>> =>
    api.post('/pocs', data),

  updatePOC: (id: string, data: Partial<POC>): Promise<ApiResponse<POC>> =>
    api.put(`/pocs/${id}`, data),

  deletePOC: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/pocs/${id}`),

  togglePOC: (id: string, enabled: boolean): Promise<ApiResponse<POC>> =>
    api.post(`/pocs/${id}/toggle`, { enabled }),

  importPOCs: (
    file: File
  ): Promise<ApiResponse<{ imported: number; failed: number }>> => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/pocs/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  testPOC: (
    id: string,
    target: string
  ): Promise<ApiResponse<{ success: boolean; message: string }>> =>
    api.post(`/pocs/${id}/test`, { target }),
};
