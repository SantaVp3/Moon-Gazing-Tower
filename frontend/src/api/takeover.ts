import api, { ApiResponse } from '@/lib/api';

// 接管检测结果
export interface TakeoverResult {
  domain: string;
  vulnerable: boolean;
  provider?: string;
  cnames?: string[];
  fingerprint?: string;
  confidence: 'high' | 'medium' | 'low';
  checkedAt: string;
}

// 批量检测结果
export interface BatchTakeoverResult {
  total: number;
  vulnerable: number;
  results: TakeoverResult[];
  duration: string;
}

// 服务商信息
export interface TakeoverProvider {
  name: string;
  cnames: string[];
  fingerprints: string[];
  description: string;
}

export const takeoverApi = {
  // 单域名检测
  check: (domain: string): Promise<ApiResponse<TakeoverResult>> =>
    api.post('/scan/takeover', { domain }),

  // 批量检测
  batchCheck: (domains: string[]): Promise<ApiResponse<BatchTakeoverResult>> =>
    api.post('/scan/takeover/batch', { domains }),

  // 获取支持的服务商列表
  getProviders: (): Promise<ApiResponse<TakeoverProvider[]>> =>
    api.get('/scan/takeover/providers'),

  // 获取历史检测记录
  getHistory: (params?: {
    page?: number;
    pageSize?: number;
    vulnerable?: boolean;
  }): Promise<ApiResponse<{ list: TakeoverResult[]; total: number }>> =>
    api.get('/scan/takeover/history', { params }),
};
