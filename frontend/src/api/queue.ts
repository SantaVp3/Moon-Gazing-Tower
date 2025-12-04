import api, { ApiResponse } from '@/lib/api';

// 任务状态
export type TaskStatus =
  | 'pending'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'deadletter';

// 任务
export interface QueueTask {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  status: TaskStatus;
  priority: number;
  retries: number;
  maxRetries: number;
  error?: string;
  result?: Record<string, unknown>;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
}

// 队列统计
export interface QueueStats {
  pending: number;
  processing: number;
  completed: number;
  failed: number;
  deadletter: number;
  totalProcessed: number;
  averageProcessTime: number;
  workersActive: number;
  workersTotal: number;
}

// 任务类型
export interface TaskType {
  id: string;
  name: string;
  description: string;
  defaultPriority: number;
  maxRetries: number;
}

export interface WorkerInfo {
  id: string;
  status: 'idle' | 'busy';
  currentTask?: string;
  processedCount: number;
  startedAt: string;
}

// 辅助函数：处理队列不可用的情况
const handleQueueError = <T>(
  error: unknown,
  defaultValue: T
): ApiResponse<T> => {
  console.warn('Queue API not available (Redis not configured):', error);
  return {
    code: 0,
    message: 'Queue service not available',
    data: defaultValue,
  };
};

export const queueApi = {
  // 获取队列统计
  getStats: async (): Promise<ApiResponse<QueueStats>> => {
    try {
      return await api.get('/queue/stats');
    } catch (err) {
      return handleQueueError(err, {
        pending: 0,
        processing: 0,
        completed: 0,
        failed: 0,
        deadletter: 0,
        totalProcessed: 0,
        averageProcessTime: 0,
        workersActive: 0,
        workersTotal: 0,
      });
    }
  },

  // 获取任务类型
  getTaskTypes: async (): Promise<ApiResponse<TaskType[]>> => {
    try {
      return await api.get('/queue/types');
    } catch (err) {
      return handleQueueError(err, []);
    }
  },

  // 添加任务到队列
  enqueueTask: (data: {
    type: string;
    payload: Record<string, unknown>;
    priority?: number;
  }): Promise<ApiResponse<QueueTask>> => api.post('/queue/tasks', data),

  // 获取任务结果
  getTaskResult: (id: string): Promise<ApiResponse<QueueTask>> =>
    api.get(`/queue/tasks/${id}/result`),

  // 获取待处理任务
  getPendingTasks: async (params?: {
    page?: number;
    pageSize?: number;
    type?: string;
  }): Promise<ApiResponse<{ list: QueueTask[]; total: number }>> => {
    try {
      return await api.get('/queue/tasks/pending', { params });
    } catch (err) {
      return handleQueueError(err, { list: [], total: 0 });
    }
  },

  // 获取处理中任务
  getProcessingTasks: async (): Promise<ApiResponse<QueueTask[]>> => {
    try {
      return await api.get('/queue/tasks/processing');
    } catch (err) {
      return handleQueueError(err, []);
    }
  },

  // 获取死信队列任务
  getDeadLetterTasks: async (params?: {
    page?: number;
    pageSize?: number;
  }): Promise<ApiResponse<{ list: QueueTask[]; total: number }>> => {
    try {
      return await api.get('/queue/tasks/deadletter', { params });
    } catch (err) {
      return handleQueueError(err, { list: [], total: 0 });
    }
  },

  // 重试死信任务
  retryDeadLetterTask: (id: string): Promise<ApiResponse<null>> =>
    api.post(`/queue/tasks/deadletter/${id}/retry`),

  // 清空死信队列
  clearDeadLetter: (): Promise<ApiResponse<null>> =>
    api.delete('/queue/tasks/deadletter'),

  // 取消任务
  cancelTask: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/queue/tasks/${id}`),

  // 获取Worker状态
  getWorkerStatus: async (): Promise<
    ApiResponse<{ active: number; total: number; workers: WorkerInfo[] }>
  > => {
    try {
      return await api.get('/queue/workers');
    } catch (err) {
      return handleQueueError(err, { active: 0, total: 0, workers: [] });
    }
  },
};
