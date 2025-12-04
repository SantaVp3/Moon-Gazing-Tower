import api, { ApiResponse, PaginatedResponse } from '@/lib/api';

// Backend paginated response format
interface BackendPaginatedResponse {
  code: number;
  message: string;
  data: Record<string, unknown>[];
  total: number;
  page: number;
  size: number;
}

// Transform backend POC to frontend format
const transformPOC = (p: Record<string, unknown>): POC => ({
  id: p.id as string,
  name: p.name as string,
  type: p.type as string,
  severity: p.severity as string,
  description: (p.description as string) || '',
  content: p.content as string,
  cveId: p.cve_id as string,
  tags: (p.tags as string[]) || [],
  author: p.author as string,
  references: (p.references as string[]) || [],
  enabled: p.enabled as boolean,
  lastUsed: p.last_used as string,
  successCount: p.success_count as number,
  failCount: p.fail_count as number,
  createdAt: p.created_at as string,
  updatedAt: p.updated_at as string,
});

export interface POC {
  id: string;
  name: string;
  type: string; // nuclei, xray, custom
  severity: string; // critical, high, medium, low, info
  description: string;
  content: string;
  cveId?: string;
  tags: string[];
  author?: string;
  references?: string[];
  enabled: boolean;
  lastUsed?: string;
  successCount?: number;
  failCount?: number;
  createdAt: string;
  updatedAt: string;
}

export interface CreatePOCRequest {
  name: string;
  type: string;
  severity: string;
  description?: string;
  content: string;
  cveId?: string;
  tags?: string[];
  author?: string;
  references?: string[];
  enabled?: boolean;
}

export interface UpdatePOCRequest {
  name?: string;
  type?: string;
  severity?: string;
  description?: string;
  content?: string;
  cveId?: string;
  tags?: string[];
  author?: string;
  references?: string[];
  enabled?: boolean;
}

export interface POCListParams {
  page?: number;
  pageSize?: number;
  type?: string;
  severity?: string;
  enabled?: boolean;
  search?: string;
}

export interface POCStatistics {
  total: number;
  enabled: number;
  disabled: number;
  bySeverity: Record<string, number>;
  byType: Record<string, number>;
}

export interface POCImportResult {
  totalFiles: number;
  imported: number;
  failed: number;
  skipped: number;
  failedFiles: string[];
  skippedFiles: string[];
}

export const pocApi = {
  list: async (params?: POCListParams): Promise<PaginatedResponse<POC>> => {
    const response: BackendPaginatedResponse = await api.get('/pocs', {
      params: {
        page: params?.page || 1,
        page_size: params?.pageSize || 20,
        type: params?.type,
        severity: params?.severity,
        enabled: params?.enabled,
        search: params?.search,
      },
    });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformPOC),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 20,
      },
    };
  },

  getById: async (id: string): Promise<ApiResponse<POC>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      `/pocs/${id}`
    );
    return {
      code: response.code,
      message: response.message,
      data: transformPOC(response.data),
    };
  },

  create: (data: CreatePOCRequest): Promise<ApiResponse<POC>> => {
    const payload = {
      name: data.name,
      type: data.type,
      severity: data.severity,
      description: data.description,
      content: data.content,
      cve_id: data.cveId ? [data.cveId] : [],
      tags: data.tags || [],
      author: data.author,
      references: data.references || [],
      enabled: data.enabled ?? true,
    };
    return api.post('/pocs', payload);
  },

  update: (id: string, data: UpdatePOCRequest): Promise<ApiResponse<void>> => {
    const payload = {
      name: data.name,
      type: data.type,
      severity: data.severity,
      description: data.description,
      content: data.content,
      cve_id: data.cveId ? [data.cveId] : undefined,
      tags: data.tags,
      author: data.author,
      references: data.references,
      enabled: data.enabled,
    };
    return api.put(`/pocs/${id}`, payload);
  },

  delete: (id: string): Promise<ApiResponse<void>> => api.delete(`/pocs/${id}`),

  batchDelete: (
    ids: string[]
  ): Promise<ApiResponse<{ deleted: number; failed: number }>> =>
    api.post('/pocs/batch-delete', { ids }),

  clearAll: (): Promise<ApiResponse<{ deleted: number }>> =>
    api.delete('/pocs/clear-all'),

  toggleEnabled: (id: string, enabled: boolean): Promise<ApiResponse<void>> =>
    api.post(`/pocs/${id}/toggle`, { enabled }),

  getStatistics: (): Promise<ApiResponse<POCStatistics>> =>
    api.get('/pocs/statistics'),

  importZip: async (file: File): Promise<ApiResponse<POCImportResult>> => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/pocs/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
};
