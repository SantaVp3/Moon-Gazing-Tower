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

// Transform backend node to frontend format
const transformNode = (n: Record<string, unknown>): ScannerNode => {
  const systemInfo = (n.system_info as Record<string, unknown>) || {};
  return {
    id: n.id as string,
    name: n.name as string,
    hostname: n.hostname as string,
    ipAddress: n.ip_address as string,
    status: n.status as ScannerNode['status'],
    type: n.type as ScannerNode['type'],
    capabilities: (n.capabilities as string[]) || [],
    maxConcurrency: n.max_tasks as number,
    currentTasks: n.current_tasks as number,
    cpuUsage: (systemInfo.cpu_usage as number) || 0,
    memoryUsage: (systemInfo.memory_usage as number) || 0,
    version: n.version as string,
    lastHeartbeat: n.last_heartbeat as string,
    registeredAt: n.created_at as string,
  };
};

// Transform backend plugin to frontend format
const transformPlugin = (p: Record<string, unknown>): Plugin => ({
  id: p.id as string,
  name: p.name as string,
  type: p.type as string,
  version: p.version as string,
  description: p.description as string,
  author: p.author as string,
  enabled: p.enabled as boolean,
  config: p.config as Record<string, unknown>,
  capabilities: (p.capabilities as string[]) || [],
  createdAt: p.created_at as string,
  updatedAt: p.updated_at as string,
});

export interface ScannerNode {
  id: string;
  name: string;
  hostname: string;
  ipAddress: string;
  status: 'online' | 'offline' | 'busy' | 'error';
  type: 'master' | 'worker';
  capabilities: string[];
  maxConcurrency: number;
  currentTasks: number;
  cpuUsage: number;
  memoryUsage: number;
  version: string;
  lastHeartbeat: string;
  registeredAt: string;
}

export interface Plugin {
  id: string;
  name: string;
  type: string;
  version: string;
  description?: string;
  author?: string;
  enabled: boolean;
  config?: Record<string, unknown>;
  capabilities: string[];
  createdAt: string;
  updatedAt: string;
}

export interface NodeStats {
  total: number;
  online: number;
  offline: number;
  busy: number;
  averageCpu: number;
  averageMemory: number;
}

export const nodeApi = {
  // Nodes
  getNodes: async (
    params?: PaginationParams & {
      status?: string;
      type?: string;
    }
  ): Promise<PaginatedResponse<ScannerNode>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      status: params?.status,
      type: params?.type,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get('/nodes', { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformNode),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  getNode: async (id: string): Promise<ApiResponse<ScannerNode>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      `/nodes/${id}`
    );
    return {
      code: response.code,
      message: response.message,
      data: transformNode(response.data),
    };
  },

  updateNode: (
    id: string,
    data: Partial<ScannerNode>
  ): Promise<ApiResponse<ScannerNode>> => api.put(`/nodes/${id}`, data),

  deleteNode: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/nodes/${id}`),

  getNodeStats: (): Promise<ApiResponse<NodeStats>> => api.get('/nodes/stats'),

  // Plugins
  getPlugins: async (
    params?: PaginationParams & {
      type?: string;
      enabled?: boolean;
    }
  ): Promise<PaginatedResponse<Plugin>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      type: params?.type,
      enabled: params?.enabled,
    };
    const response: BackendPaginatedResponse<Record<string, unknown>> =
      await api.get('/plugins', { params: backendParams });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformPlugin),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  getPlugin: async (id: string): Promise<ApiResponse<Plugin>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(
      `/plugins/${id}`
    );
    return {
      code: response.code,
      message: response.message,
      data: transformPlugin(response.data),
    };
  },

  createPlugin: (data: Partial<Plugin>): Promise<ApiResponse<Plugin>> =>
    api.post('/plugins', data),

  updatePlugin: (
    id: string,
    data: Partial<Plugin>
  ): Promise<ApiResponse<Plugin>> => api.put(`/plugins/${id}`, data),

  deletePlugin: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/plugins/${id}`),

  togglePlugin: (id: string, enabled: boolean): Promise<ApiResponse<Plugin>> =>
    api.put(`/plugins/${id}/toggle`, { enabled }),

  uploadPlugin: (file: File): Promise<ApiResponse<Plugin>> => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/plugins/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
};
