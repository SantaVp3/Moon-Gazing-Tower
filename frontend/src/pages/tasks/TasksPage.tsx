import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { taskApi, Task } from '@/api/tasks';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/components/ui/use-toast';
import { cn, formatDate, getStatusColor } from '@/lib/utils';
import {
  Plus,
  Search,
  Trash2,
  Eye,
  Play,
  Pause,
  Square,
  RefreshCw,
  RotateCw,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import TaskCreateDialog from '@/components/tasks/TaskCreateDialog';

export default function TasksPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [page, setPage] = useState(1);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['tasks', page, search, statusFilter],
    queryFn: () =>
      taskApi.getTasks({
        page,
        pageSize: 10,
        search,
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
    refetchInterval: 5000, // Auto refresh every 5s for running tasks
  });

  const startMutation = useMutation({
    mutationFn: taskApi.startTask,
    onSuccess: () => {
      toast({ title: '任务已启动' });
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const pauseMutation = useMutation({
    mutationFn: taskApi.pauseTask,
    onSuccess: () => {
      toast({ title: '任务已暂停' });
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: taskApi.cancelTask,
    onSuccess: () => {
      toast({ title: '任务已取消' });
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const resumeMutation = useMutation({
    mutationFn: taskApi.resumeTask,
    onSuccess: () => {
      toast({ title: '任务已恢复' });
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const retryMutation = useMutation({
    mutationFn: taskApi.retryTask,
    onSuccess: () => {
      toast({ title: '任务已重试' });
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: taskApi.deleteTask,
    onSuccess: () => {
      toast({ title: '删除成功' });
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  const tasks = data?.data?.list || [];
  const total = data?.data?.total || 0;
  const totalPages = Math.ceil(total / 10);

  const getStatusLabel = (status: Task['status']) => {
    const labels: Record<string, string> = {
      pending: '等待中',
      running: '运行中',
      paused: '已暂停',
      completed: '已完成',
      failed: '失败',
      cancelled: '已取消',
    };
    return labels[status] || status;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">任务管理</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            创建任务
          </Button>
        </div>
      </div>

      {/* 创建任务弹窗 */}
      <TaskCreateDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
      />

      {/* Filters */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="搜索任务..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="选择状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="pending">等待中</SelectItem>
            <SelectItem value="running">运行中</SelectItem>
            <SelectItem value="paused">已暂停</SelectItem>
            <SelectItem value="completed">已完成</SelectItem>
            <SelectItem value="failed">失败</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>任务名称</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>进度</TableHead>
              <TableHead>创建时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8">
                  加载中...
                </TableCell>
              </TableRow>
            ) : tasks.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={6}
                  className="text-center py-8 text-muted-foreground"
                >
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              tasks.map((task) => (
                <TableRow key={task.id}>
                  <TableCell className="font-medium">{task.name}</TableCell>
                  <TableCell>{task.type}</TableCell>
                  <TableCell>
                    <Badge className={cn(getStatusColor(task.status))}>
                      {getStatusLabel(task.status)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="w-32">
                      <Progress value={task.progress} className="h-2" />
                      <span className="text-xs text-muted-foreground">
                        {task.progress}%
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>{formatDate(task.createdAt)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {task.status === 'pending' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => startMutation.mutate(task.id)}
                        >
                          <Play className="h-4 w-4 text-green-500" />
                        </Button>
                      )}
                      {task.status === 'running' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => pauseMutation.mutate(task.id)}
                        >
                          <Pause className="h-4 w-4 text-yellow-500" />
                        </Button>
                      )}
                      {task.status === 'paused' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => resumeMutation.mutate(task.id)}
                        >
                          <Play className="h-4 w-4 text-green-500" />
                        </Button>
                      )}
                      {['running', 'paused'].includes(task.status) && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => cancelMutation.mutate(task.id)}
                        >
                          <Square className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                      {(task.status === 'failed' ||
                        task.status === 'cancelled') && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => retryMutation.mutate(task.id)}
                        >
                          <RotateCw className="h-4 w-4 text-blue-500" />
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" asChild>
                        <Link to={`/tasks/${task.id}`}>
                          <Eye className="h-4 w-4" />
                        </Link>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => deleteMutation.mutate(task.id)}
                        disabled={task.status === 'running'}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            上一页
          </Button>
          <span className="py-2 px-4 text-sm">
            {page} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page === totalPages}
            onClick={() => setPage(page + 1)}
          >
            下一页
          </Button>
        </div>
      )}
    </div>
  );
}
