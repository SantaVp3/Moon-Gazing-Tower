import api from '@/lib/api';

// 结果类型
export type ResultType =
  | 'domain'
  | 'subdomain'
  | 'takeover'
  | 'app'
  | 'miniapp'
  | 'url'
  | 'crawler'
  | 'sensitive'
  | 'dirscan'
  | 'vuln'
  | 'monitor'
  | 'port'
  | 'service'
  | 'topology';

// 通用结果接口
export interface ScanResult {
  id: string;
  taskId: string;
  type: ResultType;
  data: Record<string, unknown>;
  tags: string[];
  project: string;
  source: string;
  createdAt: string;
  updatedAt: string;
}

// 子域名结果
export interface SubdomainResult {
  id: string;
  subdomain: string;
  domain: string;
  url?: string;
  ips: string[];
  cdn: boolean;
  cdnName?: string;
  cdnProvider?: string;
  title: string;
  statusCode: number;
  webServer: string;
  technologies?: string[];
  fingerprint: string[];
  isAlive: boolean;
  tags: string[];
  project: string;
  createdAt: string;
}

// 子域名接管结果
export interface TakeoverResult {
  id: string;
  subdomain: string;
  cname: string;
  provider: string;
  vulnerable: boolean;
  severity: string;
  description: string;
  evidence: string;
  tags: string[];
  project: string;
  createdAt: string;
}

// URL结果
export interface URLResult {
  id: string;
  url: string;
  method: string;
  statusCode: number;
  contentType: string;
  title: string;
  length: number;
  fingerprint: string[];
  isApi: boolean;
  tags: string[];
  project: string;
  createdAt: string;
}

// 敏感信息结果
export interface SensitiveResult {
  id: string;
  url: string;
  type: string;
  value: string;
  context: string;
  location: string;
  severity: string;
  tags: string[];
  project: string;
  createdAt: string;
}

// 目录扫描结果
export interface DirScanResult {
  id: string;
  url: string;
  path: string;
  statusCode: number;
  contentType: string;
  length: number;
  redirect?: string;
  isBackup: boolean;
  isConfig: boolean;
  tags: string[];
  project: string;
  createdAt: string;
}

// 结果统计
export interface ResultStats {
  domain: number;
  subdomain: number;
  takeover: number;
  app: number;
  miniapp: number;
  url: number;
  crawler: number;
  sensitive: number;
  dirscan: number;
  vuln: number;
  monitor: number;
  port: number;
  service: number;
}

// 后端响应格式
interface BackendResponse<T> {
  code: number;
  message: string;
  data: T;
  total?: number;
  page?: number;
  size?: number;
}

// 转换函数：将后端 snake_case 转为前端 camelCase
function transformResult(
  item: Record<string, unknown>
): Record<string, unknown> {
  // 获取嵌套的 data 对象
  const dataObj = (item.data as Record<string, unknown>) || {};

  return {
    id: item.id || item._id,
    taskId: item.task_id,
    type: item.type,
    data: item.data,
    tags: item.tags || [],
    project: item.project || '',
    source: item.source || '',
    createdAt: item.created_at,
    updatedAt: item.updated_at,
    // 合并 data 中的字段到顶层
    ...transformDataFields(dataObj),
  };
}

function transformDataFields(
  data: Record<string, unknown>
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // 直接映射的字段
  const directFields = [
    'domain',
    'icp',
    'company',
    'url',
    'path',
    'title',
    'value',
    'context',
    'location',
    'severity',
    'cname',
    'provider',
    'evidence',
    'description',
    'service',
    'state',
    'port',
    'host',
    'target',
    'name',
    'version',
    'category',
    'confidence',
    'vuln_id',
    'matched_at',
    'type',
    'pattern',
    'matches',
    'banner',
    'fingerprint',
    'technologies',
    'cdn',
    'vulnerable',
    'length',
    'size',
    'status',
  ];

  // snake_case 到 camelCase 的映射表
  const snakeToCamelMap: Record<string, string> = {
    icp_type: 'icpType',
    status_code: 'statusCode',
    http_status: 'statusCode',
    content_type: 'contentType',
    web_server: 'webServer',
    cdn_provider: 'cdnProvider',
    cdn_name: 'cdnName',
    is_alive: 'isAlive',
    is_backup: 'isBackup',
    is_config: 'isConfig',
    is_api: 'isApi',
  };

  // 批量处理直接映射和snake_case转换
  const allFields = [...directFields, ...Object.keys(snakeToCamelMap)];
  for (const field of allFields) {
    if (data[field] !== undefined) {
      const targetField = snakeToCamelMap[field] || field;
      result[targetField] = data[field];
    }
  }

  // host 映射为 ip (端口扫描用)
  if (data.host !== undefined) {
    result.ip = data.host;
  }

  // 子域名处理：优先使用 full_domain，其次使用 subdomain，再次使用 domain
  if (data.full_domain !== undefined) {
    result.subdomain = data.full_domain;
    result.fullDomain = data.full_domain;
  } else if (data.subdomain !== undefined && data.subdomain !== '') {
    result.subdomain = data.subdomain;
    result.fullDomain = data.subdomain;
  } else if (data.domain !== undefined && data.domain !== '') {
    result.subdomain = data.domain;
    result.fullDomain = data.domain;
  }

  // IP 处理：如果是单个 ip 字符串，转换为 ips 数组
  if (data.ip !== undefined && typeof data.ip === 'string' && data.ip !== '') {
    result.ips = [data.ip];
    result.ip = data.ip;
  }
  if (data.ips !== undefined) {
    result.ips = data.ips;
  }

  // alive 特殊处理
  if (data.alive !== undefined) {
    result.alive = data.alive;
    if (data.alive && !result.statusCode) {
      result.statusCode = data.http_status || 0;
    }
  }

  return result;
}

export const resultApi = {
  // 获取任务扫描结果
  getTaskResults: async (
    taskId: string,
    params?: {
      type?: ResultType;
      page?: number;
      pageSize?: number;
      search?: string;
      statusCode?: number; // 状态码筛选
    }
  ) => {
    // 注意：api 拦截器已经返回 response.data，所以这里 response 就是后端返回的 JSON
    const response = (await api.get<BackendResponse<Record<string, unknown>[]>>(
      `/tasks/${taskId}/results`,
      {
        params: {
          type: params?.type,
          page: params?.page || 1,
          size: params?.pageSize || 20,
          search: params?.search,
          status_code: params?.statusCode || undefined,
        },
      }
    )) as unknown as BackendResponse<Record<string, unknown>[]>;

    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformResult),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 20,
      },
    };
  },

  // 获取结果统计
  getResultStats: async (taskId: string) => {
    const response = (await api.get<BackendResponse<Record<string, number>>>(
      `/tasks/${taskId}/results/stats`
    )) as unknown as BackendResponse<Record<string, number>>;
    return response;
  },

  // 获取子域名结果
  getSubdomainResults: async (
    taskId: string,
    params?: { page?: number; pageSize?: number; search?: string }
  ) => {
    const response = (await api.get<BackendResponse<Record<string, unknown>[]>>(
      `/tasks/${taskId}/results/subdomains`,
      {
        params: {
          page: params?.page || 1,
          size: params?.pageSize || 20,
          search: params?.search,
        },
      }
    )) as unknown as BackendResponse<Record<string, unknown>[]>;

    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(
          transformResult
        ) as unknown as SubdomainResult[],
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 20,
      },
    };
  },

  // 导出结果
  exportResults: async (taskId: string, type?: ResultType) => {
    const response = (await api.get<BackendResponse<Record<string, unknown>[]>>(
      `/tasks/${taskId}/results/export`,
      { params: { type } }
    )) as unknown as BackendResponse<Record<string, unknown>[]>;
    return response.data;
  },

  // 更新标签
  updateTags: async (resultId: string, tags: string[]) => {
    const response = (await api.put<BackendResponse<null>>(
      `/results/${resultId}/tags`,
      { tags }
    )) as unknown as BackendResponse<null>;
    return response;
  },

  // 添加标签
  addTag: async (resultId: string, tag: string) => {
    const response = (await api.post<BackendResponse<null>>(
      `/results/${resultId}/tags`,
      { tag }
    )) as unknown as BackendResponse<null>;
    return response;
  },

  // 移除标签
  removeTag: async (resultId: string, tag: string) => {
    const response = (await api.delete<BackendResponse<null>>(
      `/results/${resultId}/tags`,
      { params: { tag } }
    )) as unknown as BackendResponse<null>;
    return response;
  },

  // 批量删除
  batchDelete: async (ids: string[]) => {
    const response = (await api.post<BackendResponse<null>>(
      '/results/batch-delete',
      { ids }
    )) as unknown as BackendResponse<null>;
    return response;
  },
};
