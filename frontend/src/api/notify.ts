import api, { ApiResponse } from '@/lib/api';

// 通知配置 - 匹配后端 NotifyConfig 结构
export interface NotifyConfig {
  type: 'dingtalk' | 'feishu' | 'wechat' | 'email' | 'webhook';
  enabled: boolean;
  name: string;
  // DingTalk
  dingtalk_webhook?: string;
  dingtalk_secret?: string;
  // Feishu
  feishu_webhook?: string;
  feishu_secret?: string;
  // WeChat
  wechat_webhook?: string;
  // Email
  smtp_host?: string;
  smtp_port?: number;
  smtp_user?: string;
  smtp_password?: string;
  smtp_from?: string;
  email_to?: string[];
  // Webhook
  webhook_url?: string;
  webhook_method?: string;
  webhook_headers?: Record<string, string>;
}

// 通知历史
export interface NotifyHistory {
  id: string;
  message: {
    level: string;
    title: string;
    content: string;
    timestamp: string;
    source: string;
  };
  type: string;
  status: string;
  error?: string;
  timestamp: string;
}

// 通知类型
export interface NotifyType {
  id: string;
  name: string;
  description: string;
}

export const notifyApi = {
  // 获取通知配置列表
  getConfigs: (): Promise<ApiResponse<NotifyConfig[]>> =>
    api.get('/notify/configs'),

  // 添加通知配置
  addConfig: (data: NotifyConfig): Promise<ApiResponse<null>> =>
    api.post('/notify/configs', data),

  // 更新通知配置
  updateConfig: (data: NotifyConfig): Promise<ApiResponse<null>> =>
    api.put('/notify/configs', data),

  // 删除通知配置
  deleteConfig: (name: string, type: string): Promise<ApiResponse<null>> =>
    api.delete('/notify/configs', { params: { name, type } }),

  // 启用/禁用配置
  enableConfig: (
    name: string,
    type: string,
    enabled: boolean
  ): Promise<ApiResponse<null>> =>
    api.post('/notify/configs/enable', { name, type, enabled }),

  // 测试配置
  testConfig: (
    config: NotifyConfig
  ): Promise<ApiResponse<{ success: boolean; message: string }>> =>
    api.post('/notify/test', config),

  // 发送通知
  sendNotification: (data: {
    level: string;
    title: string;
    content: string;
    source: string;
  }): Promise<ApiResponse<null>> => api.post('/notify/send', data),

  // 获取通知历史
  getHistory: (params?: {
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<NotifyHistory[]>> =>
    api.get('/notify/history', { params }),

  // 获取支持的通知类型
  getTypes: (): Promise<ApiResponse<NotifyType[]>> => api.get('/notify/types'),
};

// 为了向后兼容，保留旧的类型别名
export type NotifyChannel = NotifyConfig;
