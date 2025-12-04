import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queueApi, QueueTask } from '@/api/queue';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/components/ui/use-toast';
import { formatDate } from '@/lib/utils';
import {
  ListTodo,
  RefreshCw,
  Trash2,
  RotateCcw,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Server,
} from 'lucide-react';

const statusConfig: Record<
  string,
  {
    label: string;
    variant: 'default' | 'destructive' | 'outline' | 'secondary';
    icon: React.ReactNode;
  }
> = {
  pending: {
    label: '等待中',
    variant: 'outline',
    icon: <Clock className="h-3 w-3" />,
  },
  processing: {
    label: '处理中',
    variant: 'default',
    icon: <Loader2 className="h-3 w-3 animate-spin" />,
  },
  completed: {
    label: '已完成',
    variant: 'secondary',
    icon: <CheckCircle className="h-3 w-3" />,
  },
  failed: {
    label: '失败',
    variant: 'destructive',
    icon: <XCircle className="h-3 w-3" />,
  },
  deadletter: {
    label: '死信',
    variant: 'destructive',
    icon: <AlertTriangle className="h-3 w-3" />,
  },
};

export default function QueuePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('overview');
  const [pendingPage, setPendingPage] = useState(1);
  const [deadletterPage, setDeadletterPage] = useState(1);

  // 获取队列统计
  const {
    data: statsData,
    isLoading: statsLoading,
    refetch: refetchStats,
  } = useQuery({
    queryKey: ['queue-stats'],
    queryFn: queueApi.getStats,
    refetchInterval: 5000, // 每5秒刷新
  });

  // 获取处理中任务
  const { data: processingData } = useQuery({
    queryKey: ['queue-processing'],
    queryFn: queueApi.getProcessingTasks,
    refetchInterval: 3000,
    enabled: activeTab === 'processing',
  });

  // 获取待处理任务
  const { data: pendingData, isLoading: pendingLoading } = useQuery({
    queryKey: ['queue-pending', pendingPage],
    queryFn: () =>
      queueApi.getPendingTasks({ page: pendingPage, pageSize: 10 }),
    enabled: activeTab === 'pending',
  });

  // 获取死信队列
  const { data: deadletterData, isLoading: deadletterLoading } = useQuery({
    queryKey: ['queue-deadletter', deadletterPage],
    queryFn: () =>
      queueApi.getDeadLetterTasks({ page: deadletterPage, pageSize: 10 }),
    enabled: activeTab === 'deadletter',
  });

  // 获取Worker状态
  const { data: workersData } = useQuery({
    queryKey: ['queue-workers'],
    queryFn: queueApi.getWorkerStatus,
    refetchInterval: 5000,
    enabled: activeTab === 'workers',
  });

  // 重试死信任务
  const retryMutation = useMutation({
    mutationFn: queueApi.retryDeadLetterTask,
    onSuccess: () => {
      toast({ title: '已重新加入队列' });
      queryClient.invalidateQueries({ queryKey: ['queue-deadletter'] });
      queryClient.invalidateQueries({ queryKey: ['queue-stats'] });
    },
  });

  // 清空死信队列
  const clearDeadletterMutation = useMutation({
    mutationFn: queueApi.clearDeadLetter,
    onSuccess: () => {
      toast({ title: '已清空死信队列' });
      queryClient.invalidateQueries({ queryKey: ['queue-deadletter'] });
      queryClient.invalidateQueries({ queryKey: ['queue-stats'] });
    },
  });

  // 取消任务
  const cancelMutation = useMutation({
    mutationFn: queueApi.cancelTask,
    onSuccess: () => {
      toast({ title: '任务已取消' });
      queryClient.invalidateQueries({ queryKey: ['queue-pending'] });
      queryClient.invalidateQueries({ queryKey: ['queue-stats'] });
    },
  });

  const stats = statsData?.data;
  const processing = processingData?.data || [];
  const pending = pendingData?.data?.list || [];
  const pendingTotal = pendingData?.data?.total || 0;
  const pendingTotalPages = Math.ceil(pendingTotal / 10);
  const deadletter = deadletterData?.data?.list || [];
  const deadletterTotal = deadletterData?.data?.total || 0;
  const deadletterTotalPages = Math.ceil(deadletterTotal / 10);
  const workers = workersData?.data?.workers || [];

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ListTodo className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">任务队列</h1>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetchStats()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          刷新
        </Button>
      </div>

      {/* 统计卡片 */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-blue-500" />
              等待中
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">
              {statsLoading ? '-' : stats?.pending || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Loader2 className="h-4 w-4 text-green-500" />
              处理中
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {statsLoading ? '-' : stats?.processing || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-gray-500" />
              已完成
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {statsLoading ? '-' : stats?.completed || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              失败
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {statsLoading ? '-' : stats?.failed || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              死信
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">
              {statsLoading ? '-' : stats?.deadletter || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Worker 状态 */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">Worker 状态</CardTitle>
            <Badge variant="outline">
              {stats?.workersActive || 0} / {stats?.workersTotal || 0} 活跃
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>平均处理时间</span>
              <span>
                {stats?.averageProcessTime
                  ? `${stats.averageProcessTime}ms`
                  : '-'}
              </span>
            </div>
            <Progress
              value={
                stats
                  ? (stats.workersActive / Math.max(stats.workersTotal, 1)) *
                    100
                  : 0
              }
            />
          </div>
        </CardContent>
      </Card>

      {/* 标签页 */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="processing">
            处理中
            {stats?.processing ? (
              <Badge
                variant="default"
                className="ml-2 h-5 w-5 p-0 justify-center"
              >
                {stats.processing}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="pending">
            等待中
            {stats?.pending ? (
              <Badge
                variant="outline"
                className="ml-2 h-5 w-5 p-0 justify-center"
              >
                {stats.pending}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="deadletter">
            死信队列
            {stats?.deadletter ? (
              <Badge
                variant="destructive"
                className="ml-2 h-5 w-5 p-0 justify-center"
              >
                {stats.deadletter}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="workers">Workers</TabsTrigger>
        </TabsList>

        {/* 概览 */}
        <TabsContent value="overview">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>队列健康度</CardTitle>
                <CardDescription>基于处理效率和失败率</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4">
                  <div className="flex-1">
                    <Progress
                      value={
                        100 -
                        ((stats?.failed || 0) /
                          Math.max(stats?.totalProcessed || 1, 1)) *
                          100
                      }
                    />
                  </div>
                  <span className="text-2xl font-bold text-green-600">
                    {Math.round(
                      100 -
                        ((stats?.failed || 0) /
                          Math.max(stats?.totalProcessed || 1, 1)) *
                          100
                    )}
                    %
                  </span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>总处理量</CardTitle>
                <CardDescription>历史处理任务总数</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">
                  {stats?.totalProcessed || 0}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 处理中任务 */}
        <TabsContent value="processing">
          <TaskTable
            tasks={processing}
            loading={false}
            emptyText="当前没有正在处理的任务"
          />
        </TabsContent>

        {/* 待处理任务 */}
        <TabsContent value="pending">
          <TaskTable
            tasks={pending}
            loading={pendingLoading}
            emptyText="队列为空"
            showCancel
            onCancel={(id) => cancelMutation.mutate(id)}
          />
          {pendingTotalPages > 1 && (
            <div className="flex justify-center gap-2 mt-4">
              <Button
                variant="outline"
                size="sm"
                disabled={pendingPage === 1}
                onClick={() => setPendingPage(pendingPage - 1)}
              >
                上一页
              </Button>
              <span className="py-2 px-4 text-sm">
                {pendingPage} / {pendingTotalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={pendingPage === pendingTotalPages}
                onClick={() => setPendingPage(pendingPage + 1)}
              >
                下一页
              </Button>
            </div>
          )}
        </TabsContent>

        {/* 死信队列 */}
        <TabsContent value="deadletter">
          <div className="flex justify-end mb-4">
            <Button
              variant="destructive"
              size="sm"
              onClick={() => clearDeadletterMutation.mutate()}
              disabled={
                clearDeadletterMutation.isPending || deadletter.length === 0
              }
            >
              <Trash2 className="h-4 w-4 mr-2" />
              清空队列
            </Button>
          </div>
          <TaskTable
            tasks={deadletter}
            loading={deadletterLoading}
            emptyText="死信队列为空"
            showRetry
            onRetry={(id) => retryMutation.mutate(id)}
          />
          {deadletterTotalPages > 1 && (
            <div className="flex justify-center gap-2 mt-4">
              <Button
                variant="outline"
                size="sm"
                disabled={deadletterPage === 1}
                onClick={() => setDeadletterPage(deadletterPage - 1)}
              >
                上一页
              </Button>
              <span className="py-2 px-4 text-sm">
                {deadletterPage} / {deadletterTotalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={deadletterPage === deadletterTotalPages}
                onClick={() => setDeadletterPage(deadletterPage + 1)}
              >
                下一页
              </Button>
            </div>
          )}
        </TabsContent>

        {/* Workers */}
        <TabsContent value="workers">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {workers.map((worker) => (
              <Card key={worker.id}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Server className="h-4 w-4" />
                      {worker.id}
                    </CardTitle>
                    <Badge
                      variant={worker.status === 'busy' ? 'default' : 'outline'}
                    >
                      {worker.status === 'busy' ? '忙碌' : '空闲'}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">已处理</span>
                    <span>{worker.processedCount}</span>
                  </div>
                  {worker.currentTask && (
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">当前任务</span>
                      <span className="truncate max-w-[150px]">
                        {worker.currentTask}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">启动时间</span>
                    <span>{formatDate(worker.startedAt)}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
            {workers.length === 0 && (
              <div className="col-span-full text-center py-8 text-muted-foreground">
                暂无 Worker 运行
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// 任务表格组件
function TaskTable({
  tasks,
  loading,
  emptyText,
  showCancel,
  showRetry,
  onCancel,
  onRetry,
}: {
  tasks: QueueTask[];
  loading: boolean;
  emptyText: string;
  showCancel?: boolean;
  showRetry?: boolean;
  onCancel?: (id: string) => void;
  onRetry?: (id: string) => void;
}) {
  return (
    <div className="border rounded-lg">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>任务ID</TableHead>
            <TableHead>类型</TableHead>
            <TableHead>状态</TableHead>
            <TableHead>优先级</TableHead>
            <TableHead>重试次数</TableHead>
            <TableHead>创建时间</TableHead>
            {(showCancel || showRetry) && <TableHead>操作</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading ? (
            <TableRow>
              <TableCell
                colSpan={showCancel || showRetry ? 7 : 6}
                className="text-center py-8"
              >
                加载中...
              </TableCell>
            </TableRow>
          ) : tasks.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={showCancel || showRetry ? 7 : 6}
                className="text-center py-8 text-muted-foreground"
              >
                {emptyText}
              </TableCell>
            </TableRow>
          ) : (
            tasks.map((task) => {
              const status = statusConfig[task.status] || statusConfig.pending;
              return (
                <TableRow key={task.id}>
                  <TableCell className="font-mono text-xs">{task.id}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{task.type}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={status.variant}
                      className="flex items-center gap-1 w-fit"
                    >
                      {status.icon}
                      {status.label}
                    </Badge>
                  </TableCell>
                  <TableCell>{task.priority}</TableCell>
                  <TableCell>
                    {task.retries} / {task.maxRetries}
                  </TableCell>
                  <TableCell>{formatDate(task.createdAt)}</TableCell>
                  {(showCancel || showRetry) && (
                    <TableCell>
                      <div className="flex gap-1">
                        {showRetry && (
                          <Button
                            variant="ghost"
                            size="icon"
                            title="重试"
                            onClick={() => onRetry?.(task.id)}
                          >
                            <RotateCcw className="h-4 w-4" />
                          </Button>
                        )}
                        {showCancel && (
                          <Button
                            variant="ghost"
                            size="icon"
                            title="取消"
                            onClick={() => onCancel?.(task.id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>
    </div>
  );
}
