import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { monitorApi, MonitorType } from '@/api/monitor';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { useToast } from '@/components/ui/use-toast';
import { formatDate } from '@/lib/utils';
import {
  Eye,
  Plus,
  RefreshCw,
  Trash2,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  FileText,
  Link as LinkIcon,
  Hash,
  Layout,
} from 'lucide-react';

const monitorTypeLabels: Record<MonitorType, string> = {
  content_hash: '内容哈希',
  dom_structure: 'DOM结构',
  keywords: '关键词',
  links: '链接',
};

const monitorTypeIcons: Record<MonitorType, React.ReactNode> = {
  content_hash: <Hash className="h-4 w-4" />,
  dom_structure: <Layout className="h-4 w-4" />,
  keywords: <FileText className="h-4 w-4" />,
  links: <LinkIcon className="h-4 w-4" />,
};

const statusConfig: Record<
  string,
  {
    label: string;
    variant: 'default' | 'destructive' | 'outline' | 'secondary';
    icon: React.ReactNode;
  }
> = {
  normal: {
    label: '正常',
    variant: 'default',
    icon: <CheckCircle className="h-3 w-3" />,
  },
  changed: {
    label: '已变化',
    variant: 'destructive',
    icon: <AlertTriangle className="h-3 w-3" />,
  },
  error: {
    label: '错误',
    variant: 'destructive',
    icon: <XCircle className="h-3 w-3" />,
  },
  pending: {
    label: '待检查',
    variant: 'outline',
    icon: <Clock className="h-3 w-3" />,
  },
};

export default function MonitorPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('pages');
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [changesPage, setChangesPage] = useState(1);

  // 新建监控表单
  const [newPage, setNewPage] = useState({
    url: '',
    name: '',
    interval: 60,
    monitorTypes: ['content_hash'] as MonitorType[],
    keywords: '',
  });

  // 获取监控页面列表
  const {
    data: pagesData,
    isLoading: pagesLoading,
    refetch: refetchPages,
  } = useQuery({
    queryKey: ['monitor-pages'],
    queryFn: () => monitorApi.getPages(),
  });

  // 获取变化记录
  const { data: changesData, isLoading: changesLoading } = useQuery({
    queryKey: ['monitor-changes', changesPage],
    queryFn: () => monitorApi.getChanges({ page: changesPage, pageSize: 10 }),
    enabled: activeTab === 'changes',
  });

  // 添加监控
  const addMutation = useMutation({
    mutationFn: monitorApi.addPage,
    onSuccess: () => {
      toast({ title: '添加成功' });
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] });
      setShowAddDialog(false);
      setNewPage({
        url: '',
        name: '',
        interval: 60,
        monitorTypes: ['content_hash'],
        keywords: '',
      });
    },
    onError: () => {
      toast({ title: '添加失败', variant: 'destructive' });
    },
  });

  // 删除监控
  const deleteMutation = useMutation({
    mutationFn: monitorApi.deletePage,
    onSuccess: () => {
      toast({ title: '删除成功' });
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] });
    },
  });

  // 切换启用状态
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      monitorApi.togglePage(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] });
    },
  });

  // 立即检查
  const checkMutation = useMutation({
    mutationFn: monitorApi.checkNow,
    onSuccess: (res) => {
      if (res.data?.changed) {
        toast({ title: '检测到变化', variant: 'destructive' });
      } else {
        toast({ title: '检查完成', description: '未检测到变化' });
      }
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] });
    },
    onError: () => {
      toast({ title: '检查失败', variant: 'destructive' });
    },
  });

  // 确认变化
  const acknowledgeMutation = useMutation({
    mutationFn: monitorApi.acknowledgeChange,
    onSuccess: () => {
      toast({ title: '已确认' });
      queryClient.invalidateQueries({ queryKey: ['monitor-changes'] });
    },
  });

  const pages = pagesData?.data?.list || [];
  const changes = changesData?.data?.list || [];
  const changesTotal = changesData?.data?.total || 0;
  const changesTotalPages = Math.ceil(changesTotal / 10);

  // 统计
  const stats = {
    total: pages.length,
    normal: pages.filter((p) => p.status === 'normal').length,
    changed: pages.filter((p) => p.status === 'changed').length,
    error: pages.filter((p) => p.status === 'error').length,
  };

  const handleAdd = () => {
    if (!newPage.url || !newPage.name) {
      toast({ title: '请填写完整信息', variant: 'destructive' });
      return;
    }
    addMutation.mutate({
      url: newPage.url,
      name: newPage.name,
      interval: newPage.interval,
      monitorTypes: newPage.monitorTypes,
      keywords: newPage.keywords
        ? newPage.keywords.split(',').map((k) => k.trim())
        : undefined,
    });
  };

  const toggleMonitorType = (type: MonitorType) => {
    if (newPage.monitorTypes.includes(type)) {
      setNewPage({
        ...newPage,
        monitorTypes: newPage.monitorTypes.filter((t) => t !== type),
      });
    } else {
      setNewPage({
        ...newPage,
        monitorTypes: [...newPage.monitorTypes, type],
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Eye className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">页面监控</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetchPages()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="sm" onClick={() => setShowAddDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加监控
          </Button>
        </div>
      </div>

      {/* 统计卡片 */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">总监控数</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-green-600">
              正常
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {stats.normal}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-orange-600">
              已变化
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">
              {stats.changed}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-red-600">
              错误
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.error}</div>
          </CardContent>
        </Card>
      </div>

      {/* 标签页 */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="pages">监控列表</TabsTrigger>
          <TabsTrigger value="changes">
            变化记录
            {stats.changed > 0 && (
              <Badge
                variant="destructive"
                className="ml-2 h-5 w-5 p-0 justify-center"
              >
                {stats.changed}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* 监控列表 */}
        <TabsContent value="pages">
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>监控类型</TableHead>
                  <TableHead>检查间隔</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>最后检查</TableHead>
                  <TableHead>启用</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pagesLoading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8">
                      加载中...
                    </TableCell>
                  </TableRow>
                ) : pages.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={8}
                      className="text-center py-8 text-muted-foreground"
                    >
                      暂无监控页面，点击"添加监控"开始
                    </TableCell>
                  </TableRow>
                ) : (
                  pages.map((page) => {
                    const status =
                      statusConfig[page.status] || statusConfig.pending;
                    return (
                      <TableRow key={page.id}>
                        <TableCell className="font-medium">
                          {page.name}
                        </TableCell>
                        <TableCell className="max-w-xs truncate">
                          <a
                            href={page.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary hover:underline"
                          >
                            {page.url}
                          </a>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {page.monitorTypes.map((type) => (
                              <Badge
                                key={type}
                                variant="outline"
                                className="text-xs"
                              >
                                {monitorTypeLabels[type]}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell>{page.interval}分钟</TableCell>
                        <TableCell>
                          <Badge
                            variant={status.variant}
                            className="flex items-center gap-1 w-fit"
                          >
                            {status.icon}
                            {status.label}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {page.lastCheck ? formatDate(page.lastCheck) : '-'}
                        </TableCell>
                        <TableCell>
                          <Switch
                            checked={page.enabled}
                            onCheckedChange={(checked) =>
                              toggleMutation.mutate({
                                id: page.id,
                                enabled: checked,
                              })
                            }
                          />
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              title="立即检查"
                              onClick={() => checkMutation.mutate(page.id)}
                              disabled={checkMutation.isPending}
                            >
                              <Play className="h-4 w-4 text-green-500" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              title="删除"
                              onClick={() => deleteMutation.mutate(page.id)}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        {/* 变化记录 */}
        <TabsContent value="changes">
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>页面</TableHead>
                  <TableHead>变化类型</TableHead>
                  <TableHead>检测时间</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {changesLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      加载中...
                    </TableCell>
                  </TableRow>
                ) : changes.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center py-8 text-muted-foreground"
                    >
                      暂无变化记录
                    </TableCell>
                  </TableRow>
                ) : (
                  changes.map((change) => (
                    <TableRow key={change.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{change.pageName}</p>
                          <p className="text-xs text-muted-foreground truncate max-w-xs">
                            {change.url}
                          </p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="flex items-center gap-1 w-fit"
                        >
                          {monitorTypeIcons[change.changeType]}
                          {monitorTypeLabels[change.changeType]}
                        </Badge>
                      </TableCell>
                      <TableCell>{formatDate(change.detectedAt)}</TableCell>
                      <TableCell>
                        {change.acknowledged ? (
                          <Badge variant="outline">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            已确认
                          </Badge>
                        ) : (
                          <Badge variant="destructive">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            待确认
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {!change.acknowledged && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              acknowledgeMutation.mutate(change.id)
                            }
                          >
                            确认
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* 分页 */}
          {changesTotalPages > 1 && (
            <div className="flex justify-center gap-2 mt-4">
              <Button
                variant="outline"
                size="sm"
                disabled={changesPage === 1}
                onClick={() => setChangesPage(changesPage - 1)}
              >
                上一页
              </Button>
              <span className="py-2 px-4 text-sm">
                {changesPage} / {changesTotalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={changesPage === changesTotalPages}
                onClick={() => setChangesPage(changesPage + 1)}
              >
                下一页
              </Button>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* 添加监控对话框 */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>添加页面监控</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>监控名称</Label>
              <Input
                placeholder="输入监控名称"
                value={newPage.name}
                onChange={(e) =>
                  setNewPage({ ...newPage, name: e.target.value })
                }
              />
            </div>
            <div className="space-y-2">
              <Label>页面 URL</Label>
              <Input
                placeholder="https://example.com"
                value={newPage.url}
                onChange={(e) =>
                  setNewPage({ ...newPage, url: e.target.value })
                }
              />
            </div>
            <div className="space-y-2">
              <Label>检查间隔 (分钟)</Label>
              <Select
                value={String(newPage.interval)}
                onValueChange={(value) =>
                  setNewPage({ ...newPage, interval: Number(value) })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5分钟</SelectItem>
                  <SelectItem value="15">15分钟</SelectItem>
                  <SelectItem value="30">30分钟</SelectItem>
                  <SelectItem value="60">1小时</SelectItem>
                  <SelectItem value="360">6小时</SelectItem>
                  <SelectItem value="1440">24小时</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>监控类型</Label>
              <div className="flex flex-wrap gap-2">
                {(Object.keys(monitorTypeLabels) as MonitorType[]).map(
                  (type) => (
                    <Button
                      key={type}
                      variant={
                        newPage.monitorTypes.includes(type)
                          ? 'default'
                          : 'outline'
                      }
                      size="sm"
                      onClick={() => toggleMonitorType(type)}
                    >
                      {monitorTypeIcons[type]}
                      <span className="ml-1">{monitorTypeLabels[type]}</span>
                    </Button>
                  )
                )}
              </div>
            </div>
            {newPage.monitorTypes.includes('keywords') && (
              <div className="space-y-2">
                <Label>关键词 (逗号分隔)</Label>
                <Input
                  placeholder="关键词1, 关键词2"
                  value={newPage.keywords}
                  onChange={(e) =>
                    setNewPage({ ...newPage, keywords: e.target.value })
                  }
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddDialog(false)}>
              取消
            </Button>
            <Button onClick={handleAdd} disabled={addMutation.isPending}>
              添加
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
