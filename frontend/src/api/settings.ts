import api, { ApiResponse } from '@/lib/api';

// 第三方 API 配置类型
export interface ThirdPartyConfig {
  fofa_email: string;
  fofa_key: string;
  hunter_key: string;
  quake_key: string;
  securitytrails_key: string;
}

// 获取第三方 API 配置（脱敏）
export const getThirdPartyConfig = (): Promise<
  ApiResponse<{ config: ThirdPartyConfig }>
> => api.get('/thirdparty/config');

// 更新第三方 API 配置
export const updateThirdPartyConfig = (
  config: Partial<ThirdPartyConfig>
): Promise<ApiResponse<{ message: string; configured_sources: string[] }>> =>
  api.put('/thirdparty/config', config);

// 获取已配置的数据源
export const getConfiguredSources = (): Promise<
  ApiResponse<{ sources: string[] }>
> => api.get('/thirdparty/sources');

export const settingsApi = {
  getThirdPartyConfig,
  updateThirdPartyConfig,
  getConfiguredSources,
};
