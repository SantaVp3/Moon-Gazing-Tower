import api, {
  ApiResponse,
  PaginationParams,
  PaginatedResponse,
} from '@/lib/api';
import { User } from '@/store/auth';

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
}

export const authApi = {
  login: (data: LoginRequest): Promise<ApiResponse<LoginResponse>> =>
    api.post('/auth/login', data),

  logout: (): Promise<ApiResponse<null>> => api.post('/auth/logout'),

  getCurrentUser: (): Promise<ApiResponse<User>> => api.get('/auth/me'),

  refreshToken: (): Promise<ApiResponse<{ token: string }>> =>
    api.post('/auth/refresh'),

  changePassword: (data: {
    oldPassword: string;
    newPassword: string;
  }): Promise<ApiResponse<null>> =>
    api.put('/auth/password', {
      old_password: data.oldPassword,
      new_password: data.newPassword,
    }),
};

// Backend response format for users
interface BackendUserResponse {
  code: number;
  message: string;
  data: Array<{
    id: string;
    username: string;
    email: string;
    phone?: string;
    role: string;
    status: number; // 1: active, 0: disabled
    last_login?: string;
    created_at: string;
  }>;
  total: number;
  page: number;
  size: number;
}

// Transform backend user to frontend format
const transformUser = (u: BackendUserResponse['data'][0]): User => ({
  id: u.id,
  username: u.username,
  email: u.email,
  nickname: '',
  avatar: '',
  role: u.role,
  status: u.status === 1 ? 'active' : 'disabled',
  createdAt: u.created_at,
});

export const userApi = {
  getUsers: async (
    params?: PaginationParams & { search?: string }
  ): Promise<PaginatedResponse<User>> => {
    const response: BackendUserResponse = await api.get('/users', {
      params: {
        page: params?.page,
        page_size: params?.pageSize,
        keyword: params?.search,
      },
    });
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformUser),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      },
    };
  },

  getUser: (id: string): Promise<ApiResponse<User>> => api.get(`/users/${id}`),

  createUser: (
    data: Partial<User> & { password: string }
  ): Promise<ApiResponse<User>> => api.post('/users', data),

  updateUser: (id: string, data: Partial<User>): Promise<ApiResponse<User>> =>
    api.put(`/users/${id}`, data),

  deleteUser: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/users/${id}`),

  resetPassword: (id: string, password: string): Promise<ApiResponse<null>> =>
    api.put(`/users/${id}/password`, { password }),
};
