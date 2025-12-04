import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { cruiseApi, CruiseTask, CruiseCreateRequest } from '@/api/cruise';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { formatDate } from '@/lib/utils';
import {
  Plus,
  Search,
  Trash2,
  Edit,
  Play,
  Clock,
  RefreshCw,
  CheckCircle,
  XCircle,
  Loader2,
  History,
} from 'lucide-react';
import CruiseLogsDialog from './CruiseLogsDialog';

// 常用的 Cron 表达式预设
const CRON_PRESETS = [
  { label: '每天 00:00', value: '0 0 * * *' },
  { label: '每天 08:00', value: '0 8 * * *' },
  { label: '每天 12:00', value: '0 12 * * *' },
  { label: '每天 20:00', value: '0 20 * * *' },
  { label: '每周一 00:00', value: '0 0 * * 1' },
  { label: '每周一 08:00', value: '0 8 * * 1' },
  { label: '每月 1 日 00:00', value: '0 0 1 * *' },
  { label: '每小时', value: '0 * * * *' },
  { label: '每 6 小时', value: '0 */6 * * *' },
  { label: '每 12 小时', value: '0 */12 * * *' },
];

const TASK_TYPES = [
  { value: 'full', label: '全量扫描' },
  { value: 'subdomain', label: '子域名扫描' },
  { value: 'port_scan', label: '端口扫描' },
  { value: 'fingerprint', label: '指纹识别' },
  { value: 'vuln_scan', label: '漏洞扫描' },
  { value: 'dir_scan', label: '目录扫描' },
  { value: 'crawler', label: '爬虫扫描' },
];

const TARGET_TYPES = [
  { value: 'domain', label: '域名' },
  { value: 'ip', label: 'IP地址' },
  { value: 'url', label: 'URL' },
  { value: 'cidr', label: 'CIDR网段' },
];

export default function CruisePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editingCruise, setEditingCruise] = useState<CruiseTask | null>(null);
  const [logsDialogCruise, setLogsDialogCruise] = useState<CruiseTask | null>(
    null
  );

  // 表单状态
  const [formData, setFormData] = useState<Partial<CruiseCreateRequest>>({
    name: '',
    description: '',
    cron_expr: '0 0 * * *',
    targets: [],
    target_type: 'domain',
    task_type: 'full',
    config: {},
    notify_on_complete: false,
    notify_on_vuln: true,
  });
  const [targetsText, setTargetsText] = useState('');

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['cruises', page, search],
    queryFn: () => cruiseApi.getCruises({ page, pageSize: 10, search }),
    refetchInterval: 10000,
  });

  const { data: stats } = useQuery({
    queryKey: ['cruiseStats'],
    queryFn: () => cruiseApi.getCruiseStats(),
    refetchInterval: 10000,
  });

  const createMutation = useMutation({
    mutationFn: cruiseApi.createCruise,
    onSuccess: () => {
      toast({ title: '创建成功', description: '巡航任务已创建' });
      queryClient.invalidateQueries({ queryKey: ['cruises'] });
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] });
      closeDialog();
    },
    onError: (error: Error) => {
      toast({
        title: '创建失败',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: string;
      data: Partial<CruiseCreateRequest>;
    }) => cruiseApi.updateCruise(id, data),
    onSuccess: () => {
      toast({ title: '更新成功' });
      queryClient.invalidateQueries({ queryKey: ['cruises'] });
      closeDialog();
    },
    onError: (error: Error) => {
      toast({
        title: '更新失败',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: cruiseApi.deleteCruise,
    onSuccess: () => {
      toast({ title: '删除成功' });
      queryClient.invalidateQueries({ queryKey: ['cruises'] });
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] });
    },
  });

  const enableMutation = useMutation({
    mutationFn: cruiseApi.enableCruise,
    onSuccess: () => {
      toast({ title: '已启用' });
      queryClient.invalidateQueries({ queryKey: ['cruises'] });
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] });
    },
  });

  const disableMutation = useMutation({
    mutationFn: cruiseApi.disableCruise,
    onSuccess: () => {
      toast({ title: '已禁用' });
      queryClient.invalidateQueries({ queryKey: ['cruises'] });
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] });
    },
  });

  const runMutation = useMutation({
    mutationFn: cruiseApi.runCruise,
    onSuccess: () => {
      toast({ title: '已触发执行' });
      queryClient.invalidateQueries({ queryKey: ['cruises'] });
    },
  });

  const closeDialog = () => {
    setCreateDialogOpen(false);
    setEditingCruise(null);
    setFormData({
      name: '',
      description: '',
      cron_expr: '0 0 * * *',
      targets: [],
      target_type: 'domain',
      task_type: 'full',
      config: {},
      notify_on_complete: false,
      notify_on_vuln: true,
    });
    setTargetsText('');
  };

  const openEditDialog = (cruise: CruiseTask) => {
    setEditingCruise(cruise);
    setFormData({
      name: cruise.name,
      description: cruise.description,
      cron_expr: cruise.cron_expr,
      targets: cruise.targets,
      target_type: cruise.target_type,
      task_type: cruise.task_type,
      config: cruise.config,
      notify_on_complete: cruise.notify_on_complete,
      notify_on_vuln: cruise.notify_on_vuln,
    });
    setTargetsText(cruise.targets.join('\n'));
    setCreateDialogOpen(true);
  };

  const handleSubmit = () => {
    const targets = targetsText
      .split('\n')
      .map((t) => t.trim())
      .filter((t) => t);

    if (!formData.name) {
      toast({ title: '请输入名称', variant: 'destructive' });
      return;
    }
    if (!formData.cron_expr) {
      toast({ title: '请设置执行周期', variant: 'destructive' });
      return;
    }
    if (targets.length === 0) {
      toast({ title: '请输入扫描目标', variant: 'destructive' });
      return;
    }

    const submitData = {
      ...formData,
      targets,
    } as CruiseCreateRequest;

    if (editingCruise) {
      updateMutation.mutate({ id: editingCruise.id, data: submitData });
    } else {
      createMutation.mutate(submitData);
    }
  };

  const handleToggle = (cruise: CruiseTask) => {
    if (cruise.status === 'enabled' || cruise.status === 'running') {
      disableMutation.mutate(cruise.id);
    } else {
      enableMutation.mutate(cruise.id);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'enabled':
        return <Badge className="bg-green-500">已启用</Badge>;
      case 'disabled':
        return <Badge variant="secondary">已禁用</Badge>;
      case 'running':
        return <Badge className="bg-blue-500">执行中</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const getLastStatusIcon = (status?: string) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'running':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* 头部统计 */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold">{stats?.total || 0}</div>
          <div className="text-sm text-muted-foreground">总任务数</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold text-green-500">
            {stats?.enabled || 0}
          </div>
          <div className="text-sm text-muted-foreground">已启用</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold text-gray-500">
            {stats?.disabled || 0}
          </div>
          <div className="text-sm text-muted-foreground">已禁用</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold text-blue-500">
            {stats?.running || 0}
          </div>
          <div className="text-sm text-muted-foreground">执行中</div>
        </div>
      </div>

      {/* 工具栏 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="搜索巡航任务..."
              className="pl-8 w-64"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            刷新
          </Button>
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            新建巡航
          </Button>
        </div>
      </div>

      {/* 表格 */}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>执行周期</TableHead>
              <TableHead>目标数量</TableHead>
              <TableHead>任务类型</TableHead>
              <TableHead>上次执行</TableHead>
              <TableHead>下次执行</TableHead>
              <TableHead>执行统计</TableHead>
              <TableHead>启用</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={10} className="text-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                </TableCell>
              </TableRow>
            ) : data?.items?.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={10}
                  className="text-center py-8 text-muted-foreground"
                >
                  暂无巡航任务
                </TableCell>
              </TableRow>
            ) : (
              data?.items?.map((cruise) => (
                <TableRow key={cruise.id}>
                  <TableCell>
                    <div>
                      <div className="font-medium">{cruise.name}</div>
                      {cruise.description && (
                        <div className="text-sm text-muted-foreground truncate max-w-[200px]">
                          {cruise.description}
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>{getStatusBadge(cruise.status)}</TableCell>
                  <TableCell>
                    <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                      {cruise.cron_expr}
                    </code>
                  </TableCell>
                  <TableCell>{cruise.targets?.length || 0}</TableCell>
                  <TableCell>
                    {TASK_TYPES.find((t) => t.value === cruise.task_type)
                      ?.label || cruise.task_type}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-1">
                      {getLastStatusIcon(cruise.last_status)}
                      <span className="text-sm">
                        {cruise.last_run_at
                          ? formatDate(cruise.last_run_at)
                          : '-'}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm">
                    {cruise.next_run_at ? formatDate(cruise.next_run_at) : '-'}
                  </TableCell>
                  <TableCell>
                    <div className="text-sm">
                      <span className="text-green-600">
                        {cruise.success_count}
                      </span>
                      {' / '}
                      <span className="text-red-600">{cruise.fail_count}</span>
                      {' / '}
                      <span>{cruise.run_count}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={
                        cruise.status === 'enabled' ||
                        cruise.status === 'running'
                      }
                      onCheckedChange={() => handleToggle(cruise)}
                      disabled={cruise.status === 'running'}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end space-x-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => runMutation.mutate(cruise.id)}
                        title="立即执行"
                        disabled={cruise.status === 'running'}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setLogsDialogCruise(cruise)}
                        title="执行日志"
                      >
                        <History className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => openEditDialog(cruise)}
                        title="编辑"
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => deleteMutation.mutate(cruise.id)}
                        title="删除"
                      >
                        <Trash2 className="h-4 w-4 text-red-500" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* 分页 */}
      {data && data.total > 10 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            共 {data.total} 条记录
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              上一页
            </Button>
            <span className="text-sm">第 {page} 页</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={page * 10 >= data.total}
            >
              下一页
            </Button>
          </div>
        </div>
      )}

      {/* 创建/编辑对话框 */}
      <Dialog
        open={createDialogOpen}
        onOpenChange={(open) => !open && closeDialog()}
      >
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editingCruise ? '编辑巡航任务' : '新建巡航任务'}
            </DialogTitle>
            <DialogDescription>
              配置定时自动扫描任务，系统将按照设定的周期自动执行扫描
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>任务名称 *</Label>
                <Input
                  placeholder="例如：每日资产巡航"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label>任务类型</Label>
                <Select
                  value={formData.task_type}
                  onValueChange={(value) =>
                    setFormData({ ...formData, task_type: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择任务类型" />
                  </SelectTrigger>
                  <SelectContent>
                    {TASK_TYPES.map((type) => (
                      <SelectItem key={type.value} value={type.value}>
                        {type.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>描述</Label>
              <Input
                placeholder="任务描述（可选）"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>执行周期 *</Label>
                <Select
                  value={formData.cron_expr}
                  onValueChange={(value) =>
                    setFormData({ ...formData, cron_expr: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择执行周期" />
                  </SelectTrigger>
                  <SelectContent>
                    {CRON_PRESETS.map((preset) => (
                      <SelectItem key={preset.value} value={preset.value}>
                        {preset.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <div className="text-xs text-muted-foreground">
                  当前:{' '}
                  <code className="bg-muted px-1 rounded">
                    {formData.cron_expr}
                  </code>
                </div>
              </div>
              <div className="space-y-2">
                <Label>目标类型</Label>
                <Select
                  value={formData.target_type}
                  onValueChange={(value) =>
                    setFormData({ ...formData, target_type: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择目标类型" />
                  </SelectTrigger>
                  <SelectContent>
                    {TARGET_TYPES.map((type) => (
                      <SelectItem key={type.value} value={type.value}>
                        {type.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>扫描目标 *</Label>
              <Textarea
                placeholder="每行一个目标，例如：&#10;example.com&#10;192.168.1.1&#10;10.0.0.0/24"
                rows={6}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
              />
              <div className="text-xs text-muted-foreground">
                已输入 {targetsText.split('\n').filter((t) => t.trim()).length}{' '}
                个目标
              </div>
            </div>

            <div className="space-y-3">
              <Label>通知设置</Label>
              <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-2">
                  <Switch
                    checked={formData.notify_on_complete}
                    onCheckedChange={(checked) =>
                      setFormData({ ...formData, notify_on_complete: checked })
                    }
                  />
                  <Label className="font-normal">完成时通知</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Switch
                    checked={formData.notify_on_vuln}
                    onCheckedChange={(checked) =>
                      setFormData({ ...formData, notify_on_vuln: checked })
                    }
                  />
                  <Label className="font-normal">发现漏洞时通知</Label>
                </div>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              取消
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={createMutation.isPending || updateMutation.isPending}
            >
              {createMutation.isPending || updateMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  保存中...
                </>
              ) : (
                '保存'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 执行日志对话框 */}
      {logsDialogCruise && (
        <CruiseLogsDialog
          cruise={logsDialogCruise}
          open={!!logsDialogCruise}
          onOpenChange={(open) => !open && setLogsDialogCruise(null)}
        />
      )}
    </div>
  );
}
