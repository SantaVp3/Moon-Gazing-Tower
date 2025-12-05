import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { taskApi } from '@/api/tasks';
import {
  resultApi,
  type SubdomainResult,
  type ResultType,
} from '@/api/results';
import TaskTopologyView from '@/components/tasks/TaskTopologyView';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/components/ui/use-toast';
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { cn, formatDate, getStatusColor } from '@/lib/utils';
import {
  ArrowLeft,
  Play,
  Pause,
  Square,
  Trash2,
  RotateCcw,
  Search,
  Download,
  Settings,
  ChevronDown,
  RefreshCw,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';

// Tab 配置 - ID 对应后端 ResultType
const tabConfig = [
  { id: 'subdomain', label: '子域名' },
  { id: 'takeover', label: '子域名接管' },
  { id: 'app', label: 'APP' },
  { id: 'miniapp', label: '小程序' },
  { id: 'url', label: 'URL' },
  { id: 'crawler', label: '爬虫' },
  { id: 'sensitive', label: '敏感信息' },
  { id: 'dirscan', label: '目录扫描' },
  { id: 'vuln', label: '漏洞' },
  { id: 'port', label: '端口' },
  { id: 'service', label: 'Web服务' },
  { id: 'topology', label: '资产星图' },
];

export default function TaskDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<ResultType | null>(null);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [selectedRows, setSelectedRows] = useState<string[]>([]);
  const [projectFilter, setProjectFilter] = useState<string>('all');
  const [statusCodeFilter, setStatusCodeFilter] = useState<string>('all');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  // Ensure id exists, otherwise provide empty string
  const taskId = id || '';

  // 所有 hooks 必须在条件返回之前调用
  const { data, isLoading } = useQuery({
    queryKey: ['task', taskId],
    queryFn: () => taskApi.getTask(taskId),
    enabled: !!taskId,
    refetchInterval: (query) => {
      const task = query.state.data?.data;
      return task?.status === 'running' ? 3000 : false;
    },
  });

  // 获取结果统计
  const { data: statsData } = useQuery({
    queryKey: ['task-results-stats', taskId],
    queryFn: () => resultApi.getResultStats(taskId),
    enabled: !!taskId,
  });

  // 自动选择第一个有数据的 Tab
  const resultStats = statsData?.data || {};
  useEffect(() => {
    if (activeTab === null && statsData?.data) {
      const stats = statsData.data as Record<string, number>;
      // 按 tabConfig 顺序找第一个有数据的 tab
      const firstWithData = tabConfig.find((tab) => (stats[tab.id] || 0) > 0);
      if (firstWithData) {
        setActiveTab(firstWithData.id as ResultType);
      } else {
        // 默认选择 domain
        setActiveTab('domain');
      }
    }
  }, [statsData?.data, activeTab]);

  // 确保 activeTab 有值后再查询结果
  const currentTab = activeTab || 'domain';

  // 获取当前Tab的结果数据（dirscan时支持状态码筛选）
  const statusCodeNum =
    statusCodeFilter !== 'all' ? parseInt(statusCodeFilter) : undefined;
  const { data: resultsData, isLoading: resultsLoading } = useQuery({
    queryKey: [
      'task-results',
      taskId,
      currentTab,
      page,
      search,
      statusCodeFilter,
    ],
    queryFn: () =>
      resultApi.getTaskResults(taskId, {
        type: currentTab,
        page,
        pageSize,
        search,
        statusCode: currentTab === 'dirscan' ? statusCodeNum : undefined,
      }),
    enabled: !!taskId && !!activeTab,
  });

  // 任务操作 mutations
  const startMutation = useMutation({
    mutationFn: () => taskApi.startTask(taskId),
    onSuccess: () => {
      toast({ title: '任务已开始' });
      queryClient.invalidateQueries({ queryKey: ['task', taskId] });
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  });

  const pauseMutation = useMutation({
    mutationFn: () => taskApi.pauseTask(taskId),
    onSuccess: () => {
      toast({ title: '任务已暂停' });
      queryClient.invalidateQueries({ queryKey: ['task', taskId] });
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  });

  const resumeMutation = useMutation({
    mutationFn: () => taskApi.resumeTask(taskId),
    onSuccess: () => {
      toast({ title: '任务已恢复' });
      queryClient.invalidateQueries({ queryKey: ['task', taskId] });
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  });

  const cancelMutation = useMutation({
    mutationFn: () => taskApi.cancelTask(taskId),
    onSuccess: () => {
      toast({ title: '任务已停止' });
      queryClient.invalidateQueries({ queryKey: ['task', taskId] });
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  });

  const retryMutation = useMutation({
    mutationFn: () => taskApi.retryTask(taskId),
    onSuccess: () => {
      toast({ title: '任务已重新启动' });
      queryClient.invalidateQueries({ queryKey: ['task', taskId] });
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  });

  const rescanMutation = useMutation({
    mutationFn: (fromScratch: boolean) => taskApi.rescanTask(taskId, fromScratch),
    onSuccess: (_, fromScratch) => {
      toast({ title: fromScratch ? '任务已从头开始扫描' : '任务已继续扫描' });
      queryClient.invalidateQueries({ queryKey: ['task', taskId] });
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  });

  const deleteMutation = useMutation({
    mutationFn: () => taskApi.deleteTask(taskId),
    onSuccess: () => {
      toast({ title: '任务已删除' });
      navigate('/tasks');
    },
    onError: () => toast({ title: '删除失败', variant: 'destructive' }),
  });

  // 计算派生状态
  const isOperating =
    startMutation.isPending ||
    pauseMutation.isPending ||
    resumeMutation.isPending ||
    cancelMutation.isPending ||
    retryMutation.isPending ||
    deleteMutation.isPending ||
    rescanMutation.isPending;

  const task = data?.data;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const results: any[] = resultsData?.data?.list || [];
  const total = resultsData?.data?.total || 0;

  // 生成带统计数字的tabs
  const tabs = tabConfig.map((tab) => ({
    ...tab,
    count: resultStats[tab.id] || 0,
  }));

  // 条件渲染 - 在所有 hooks 之后
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!task) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="text-6xl mb-4">🔍</div>
        <h2 className="text-xl font-semibold text-foreground mb-2">
          任务不存在
        </h2>
        <p className="text-muted-foreground mb-6 text-center max-w-md">
          该任务可能已被删除，或任务ID无效。
          <br />
          <span className="text-xs text-muted-foreground/70">任务ID: {id}</span>
        </p>
        <Button asChild>
          <Link to="/tasks">返回任务列表</Link>
        </Button>
      </div>
    );
  }

  const getStatusLabel = (status: string) => {
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

  const toggleSelectAll = () => {
    if (selectedRows.length === results.length) {
      setSelectedRows([]);
    } else {
      setSelectedRows(results.map((item: { id: string }) => item.id));
    }
  };

  const toggleSelectRow = (rowId: string) => {
    if (selectedRows.includes(rowId)) {
      setSelectedRows(selectedRows.filter((r) => r !== rowId));
    } else {
      setSelectedRows([...selectedRows, rowId]);
    }
  };

  const handleSearch = () => {
    setSearch(searchInput);
    setPage(1);
  };

  const handleExport = async () => {
    try {
      const data = await resultApi.exportResults(taskId, currentTab);
      // 转换为CSV并下载
      const results = Array.isArray(data)
        ? data
        : (data as Record<string, unknown>)?.data || [];
      const csvContent = convertToCSV(results as Record<string, unknown>[]);
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${task?.name}-${currentTab}-${new Date().toISOString().slice(0, 10)}.csv`;
      link.click();
      URL.revokeObjectURL(url);
      toast({ title: '导出成功' });
    } catch {
      toast({ title: '导出失败', variant: 'destructive' });
    }
  };

  // 转换为CSV格式
  const convertToCSV = (data: Record<string, unknown>[]) => {
    if (data.length === 0) return '';
    const headers = Object.keys(data[0]);
    const rows = data.map((item) =>
      headers.map((h) => JSON.stringify(item[h] ?? '')).join(',')
    );
    return [headers.join(','), ...rows].join('\n');
  };

  // 表格渲染映射
  const tableRenderers: Record<
    ResultType,
    () => React.ReactElement
  > = {
    subdomain: renderSubdomainTable,
    takeover: renderTakeoverTable,
    url: renderURLTable,
    sensitive: renderSensitiveTable,
    port: renderPortTable,
    service: renderServiceTable,
    dirscan: renderDirScanTable,
    crawler: renderCrawlerTable,
    domain: renderGenericTable,
    app: renderGenericTable,
    miniapp: renderGenericTable,
    vuln: renderGenericTable,
    topology: renderGenericTable,
  };

  // 渲染不同类型的表格
  const renderTable = () => {
    const renderer = tableRenderers[currentTab];
    return renderer ? renderer() : renderGenericTable();
  };

  const renderSubdomainTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>子域名</TableHead>
          <TableHead>IP</TableHead>
          <TableHead>标题</TableHead>
          <TableHead>状态码</TableHead>
          <TableHead>CDN</TableHead>
          <TableHead>指纹</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={9}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: SubdomainResult, index: number) => (
            <TableRow
              key={item.id}
              className={cn(selectedRows.includes(item.id) && 'bg-muted/50')}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id)}
                  onCheckedChange={() => toggleSelectRow(item.id)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell>
                <a
                  href={`https://${item.subdomain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline flex items-center gap-1"
                >
                  {item.subdomain}
                  <ExternalLink className="h-3 w-3" />
                </a>
              </TableCell>
              <TableCell className="text-muted-foreground font-mono text-xs">
                {item.ips?.join(', ') ||
                  (item as unknown as { ip?: string }).ip ||
                  '-'}
              </TableCell>
              <TableCell className="max-w-[200px] truncate">
                {item.title || '-'}
              </TableCell>
              <TableCell>
                {item.statusCode && item.statusCode > 0 ? (
                  <Badge
                    variant={item.statusCode === 200 ? 'default' : 'secondary'}
                  >
                    {item.statusCode}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground">
                    -
                  </Badge>
                )}
              </TableCell>
              <TableCell>
                {item.cdn ? (
                  <Badge variant="outline">
                    {item.cdnName || item.cdnProvider || 'CDN'}
                  </Badge>
                ) : (
                  '-'
                )}
              </TableCell>
              <TableCell>
                {(
                  item.technologies?.slice(0, 2) ||
                  item.fingerprint?.slice(0, 2)
                )?.map((fp: string) => (
                  <Badge key={fp} variant="outline" className="mr-1 text-xs">
                    {fp}
                  </Badge>
                )) || '-'}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  // 子域名接管检测结果表格
  const renderTakeoverTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>子域名</TableHead>
          <TableHead>CNAME</TableHead>
          <TableHead>服务商</TableHead>
          <TableHead>风险等级</TableHead>
          <TableHead>原因</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={8}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => (
            <TableRow
              key={item.id as string}
              className={cn(
                selectedRows.includes(item.id as string) && 'bg-muted/50',
                (item.vulnerable as boolean) && 'bg-destructive/5'
              )}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id as string)}
                  onCheckedChange={() => toggleSelectRow(item.id as string)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell className="font-mono">
                {item.subdomain as string}
              </TableCell>
              <TableCell className="font-mono text-xs max-w-[200px] truncate">
                {(item.cname as string) || '-'}
              </TableCell>
              <TableCell>
                <Badge variant="outline">
                  {(item.provider as string) || '-'}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    (item.severity as string) === 'high'
                      ? 'destructive'
                      : (item.severity as string) === 'medium'
                        ? 'secondary'
                        : 'outline'
                  }
                >
                  {(item.severity as string) || '高'}
                </Badge>
              </TableCell>
              <TableCell
                className="max-w-[300px] truncate"
                title={item.reason as string}
              >
                {(item.reason as string) || '-'}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt as string)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  const renderURLTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>URL</TableHead>
          <TableHead>方法</TableHead>
          <TableHead>状态码</TableHead>
          <TableHead>类型</TableHead>
          <TableHead>长度</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={8}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => (
            <TableRow
              key={item.id as string}
              className={cn(
                selectedRows.includes(item.id as string) && 'bg-muted/50'
              )}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id as string)}
                  onCheckedChange={() => toggleSelectRow(item.id as string)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell className="max-w-[400px] truncate">
                <a
                  href={item.url as string}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  {item.url as string}
                </a>
              </TableCell>
              <TableCell>
                <Badge variant="outline">
                  {(item.method as string) || 'GET'}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    (item.statusCode as number) === 200
                      ? 'default'
                      : 'secondary'
                  }
                >
                  {(item.statusCode as number) || '-'}
                </Badge>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(item.contentType as string) || '-'}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(item.length as number) || '-'}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt as string)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  const renderSensitiveTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>URL</TableHead>
          <TableHead>类型</TableHead>
          <TableHead>模式</TableHead>
          <TableHead>匹配内容</TableHead>
          <TableHead>级别</TableHead>
          <TableHead>位置</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={9}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => (
            <TableRow
              key={item.id as string}
              className={cn(
                selectedRows.includes(item.id as string) && 'bg-muted/50'
              )}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id as string)}
                  onCheckedChange={() => toggleSelectRow(item.id as string)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell className="max-w-[250px] truncate">
                <a
                  href={item.url as string}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  {item.url as string}
                </a>
              </TableCell>
              <TableCell>
                <Badge variant="outline">{item.type as string}</Badge>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {item.pattern as string}
              </TableCell>
              <TableCell
                className="font-mono text-xs max-w-[200px] truncate"
                title={
                  Array.isArray(item.matches)
                    ? (item.matches as string[]).join(', ')
                    : ''
                }
              >
                {Array.isArray(item.matches)
                  ? (item.matches as string[]).slice(0, 2).join(', ')
                  : '-'}
                {Array.isArray(item.matches) &&
                  (item.matches as string[]).length > 2 &&
                  '...'}
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    (item.severity as string) === 'critical'
                      ? 'destructive'
                      : (item.severity as string) === 'high'
                        ? 'destructive'
                        : (item.severity as string) === 'medium'
                          ? 'default'
                          : 'secondary'
                  }
                >
                  {item.severity as string}
                </Badge>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {item.location as string}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt as string)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  const renderPortTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>IP</TableHead>
          <TableHead>端口</TableHead>
          <TableHead>协议</TableHead>
          <TableHead>服务</TableHead>
          <TableHead>版本</TableHead>
          <TableHead>指纹</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={9}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => (
            <TableRow
              key={item.id as string}
              className={cn(
                selectedRows.includes(item.id as string) && 'bg-muted/50'
              )}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id as string)}
                  onCheckedChange={() => toggleSelectRow(item.id as string)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell className="font-mono">{item.ip as string}</TableCell>
              <TableCell>
                <Badge variant="outline">{item.port as number}</Badge>
              </TableCell>
              <TableCell>{(item.protocol as string) || 'tcp'}</TableCell>
              <TableCell>{(item.service as string) || '-'}</TableCell>
              <TableCell className="text-muted-foreground">
                {(item.version as string) || '-'}
              </TableCell>
              <TableCell>
                {(item.fingerprint as string[])
                  ?.slice(0, 2)
                  .map((fp: string) => (
                    <Badge key={fp} variant="outline" className="mr-1 text-xs">
                      {fp}
                    </Badge>
                  ))}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt as string)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  const renderServiceTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>URL</TableHead>
          <TableHead>标题</TableHead>
          <TableHead>状态码</TableHead>
          <TableHead>Server</TableHead>
          <TableHead>技术栈</TableHead>
          <TableHead>指纹</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={9}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => (
            <TableRow
              key={item.id as string}
              className={cn(
                selectedRows.includes(item.id as string) && 'bg-muted/50'
              )}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id as string)}
                  onCheckedChange={() => toggleSelectRow(item.id as string)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell>
                <a
                  href={item.url as string}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline flex items-center gap-1 max-w-xs truncate"
                >
                  {item.url as string}
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                </a>
              </TableCell>
              <TableCell
                className="max-w-[200px] truncate"
                title={item.title as string}
              >
                {(item.title as string) || '-'}
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    (item.status_code as number) >= 200 &&
                    (item.status_code as number) < 300
                      ? 'default'
                      : (item.status_code as number) >= 300 &&
                          (item.status_code as number) < 400
                        ? 'secondary'
                        : (item.status_code as number) >= 400
                          ? 'destructive'
                          : 'outline'
                  }
                >
                  {(item.status_code as number) || '-'}
                </Badge>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(item.server as string) || '-'}
              </TableCell>
              <TableCell>
                {(item.technologies as string[])
                  ?.slice(0, 3)
                  .map((tech: string) => (
                    <Badge
                      key={tech}
                      variant="outline"
                      className="mr-1 text-xs"
                    >
                      {tech}
                    </Badge>
                  ))}
              </TableCell>
              <TableCell>
                {(item.fingerprints as string[])
                  ?.slice(0, 2)
                  .map((fp: string) => (
                    <Badge
                      key={fp}
                      variant="secondary"
                      className="mr-1 text-xs"
                    >
                      {fp}
                    </Badge>
                  ))}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt as string)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  const renderDirScanTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>URL</TableHead>
          <TableHead>状态码</TableHead>
          <TableHead>大小</TableHead>
          <TableHead>类型</TableHead>
          <TableHead>目标</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={8}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => {
            // 从 data 字段中提取数据
            const data = (item.data || item) as Record<string, unknown>;
            return (
              <TableRow
                key={item.id as string}
                className={cn(
                  selectedRows.includes(item.id as string) && 'bg-muted/50'
                )}
              >
                <TableCell>
                  <Checkbox
                    checked={selectedRows.includes(item.id as string)}
                    onCheckedChange={() => toggleSelectRow(item.id as string)}
                  />
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {(page - 1) * pageSize + index + 1}
                </TableCell>
                <TableCell className="max-w-[400px] truncate">
                  <a
                    href={data.url as string}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    {data.url as string}
                  </a>
                </TableCell>
                <TableCell>
                  {data.status ? (
                    <Badge
                      variant={
                        (data.status as number) >= 200 &&
                        (data.status as number) < 300
                          ? 'default'
                          : (data.status as number) >= 400
                            ? 'destructive'
                            : 'secondary'
                      }
                    >
                      {data.status as number}
                    </Badge>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {data.size ? `${data.size}` : '-'}
                </TableCell>
                <TableCell className="text-muted-foreground text-xs">
                  {(data.content_type as string) || '-'}
                </TableCell>
                <TableCell className="text-muted-foreground max-w-[150px] truncate">
                  {(data.target as string) || '-'}
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {formatDate(item.createdAt as string)}
                </TableCell>
              </TableRow>
            );
          })
        )}
      </TableBody>
    </Table>
  );

  const renderCrawlerTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>URL</TableHead>
          <TableHead>方法</TableHead>
          <TableHead>状态码</TableHead>
          <TableHead>爬虫</TableHead>
          <TableHead>目标</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={8}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => {
            const data = (item.data || item) as Record<string, unknown>;
            return (
              <TableRow
                key={item.id as string}
                className={cn(
                  selectedRows.includes(item.id as string) && 'bg-muted/50'
                )}
              >
                <TableCell>
                  <Checkbox
                    checked={selectedRows.includes(item.id as string)}
                    onCheckedChange={() => toggleSelectRow(item.id as string)}
                  />
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {(page - 1) * pageSize + index + 1}
                </TableCell>
                <TableCell className="max-w-[400px] truncate">
                  <a
                    href={data.url as string}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    {data.url as string}
                  </a>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">
                    {(data.method as string) || 'GET'}
                  </Badge>
                </TableCell>
                <TableCell>
                  {data.status_code ? (
                    <Badge
                      variant={
                        (data.status_code as number) === 200
                          ? 'default'
                          : (data.status_code as number) >= 400
                            ? 'destructive'
                            : 'secondary'
                      }
                    >
                      {data.status_code as number}
                    </Badge>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-xs">
                    {(data.crawler as string) || (item.source as string) || '-'}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground max-w-[150px] truncate">
                  {(data.target as string) || '-'}
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {formatDate(item.createdAt as string)}
                </TableCell>
              </TableRow>
            );
          })
        )}
      </TableBody>
    </Table>
  );

  const renderGenericTable = () => (
    <Table>
      <TableHeader className="sticky top-0 bg-background">
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={
                selectedRows.length === results.length && results.length > 0
              }
              onCheckedChange={toggleSelectAll}
            />
          </TableHead>
          <TableHead className="w-16">序号</TableHead>
          <TableHead>数据</TableHead>
          <TableHead>项目</TableHead>
          <TableHead>TAG</TableHead>
          <TableHead>时间</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.length === 0 ? (
          <TableRow>
            <TableCell
              colSpan={6}
              className="text-center py-8 text-muted-foreground"
            >
              {resultsLoading ? '加载中...' : '暂无数据'}
            </TableCell>
          </TableRow>
        ) : (
          results.map((item: Record<string, unknown>, index: number) => (
            <TableRow
              key={item.id as string}
              className={cn(
                selectedRows.includes(item.id as string) && 'bg-muted/50'
              )}
            >
              <TableCell>
                <Checkbox
                  checked={selectedRows.includes(item.id as string)}
                  onCheckedChange={() => toggleSelectRow(item.id as string)}
                />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {(page - 1) * pageSize + index + 1}
              </TableCell>
              <TableCell className="max-w-[400px] truncate font-mono text-xs">
                {JSON.stringify(item.data || item)}
              </TableCell>
              <TableCell>{(item.project as string) || '-'}</TableCell>
              <TableCell>
                {(item.tags as string[])?.length > 0
                  ? (item.tags as string[]).map((tag: string) => (
                      <Badge key={tag} variant="outline" className="mr-1">
                        {tag}
                      </Badge>
                    ))
                  : '-'}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDate(item.createdAt as string)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );

  return (
    <div className="h-full flex flex-col -m-6">
      {/* Header - 固定在顶部 */}
      <div className="border-b bg-background px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" asChild>
              <Link to="/tasks">
                <ArrowLeft className="h-5 w-5" />
              </Link>
            </Button>
            <div>
              <h1 className="text-xl font-semibold">{task.name}</h1>
              <div className="flex items-center gap-2 mt-1">
                <Badge className={cn(getStatusColor(task.status), 'text-xs')}>
                  {getStatusLabel(task.status)}
                </Badge>
                <span className="text-muted-foreground text-sm">
                  {task.type}
                </span>
                <span className="text-muted-foreground text-sm">•</span>
                <span className="text-muted-foreground text-sm">
                  {formatDate(task.createdAt)}
                </span>
              </div>
            </div>
          </div>

          {/* 操作按钮 */}
          <div className="flex items-center gap-2">
            {task.status === 'pending' && (
              <Button
                onClick={() => startMutation.mutate()}
                disabled={isOperating}
              >
                <Play className="h-4 w-4 mr-2" />
                开始
              </Button>
            )}
            {task.status === 'running' && (
              <>
                <Button
                  variant="outline"
                  onClick={() => pauseMutation.mutate()}
                  disabled={isOperating}
                >
                  <Pause className="h-4 w-4 mr-2" />
                  暂停
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => cancelMutation.mutate()}
                  disabled={isOperating}
                >
                  <Square className="h-4 w-4 mr-2" />
                  停止
                </Button>
              </>
            )}
            {task.status === 'paused' && (
              <>
                <Button
                  onClick={() => resumeMutation.mutate()}
                  disabled={isOperating}
                >
                  <Play className="h-4 w-4 mr-2" />
                  继续
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => cancelMutation.mutate()}
                  disabled={isOperating}
                >
                  <Square className="h-4 w-4 mr-2" />
                  停止
                </Button>
              </>
            )}
            {(task.status === 'failed' || task.status === 'cancelled') && (
              <Button
                onClick={() => retryMutation.mutate()}
                disabled={isOperating}
              >
                <RotateCcw className="h-4 w-4 mr-2" />
                重试
              </Button>
            )}
            {task.status === 'completed' && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" disabled={isOperating}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    重新扫描
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem
                    onClick={() => rescanMutation.mutate(false)}
                  >
                    继续未完成部分
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => rescanMutation.mutate(true)}>
                    从头开始扫描
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  disabled={isOperating || task.status === 'running'}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>确认删除任务？</AlertDialogTitle>
                  <AlertDialogDescription>
                    此操作不可撤销。删除后，该任务及其所有相关数据将被永久删除。
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>取消</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => deleteMutation.mutate()}
                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                  >
                    删除
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b bg-background">
        <div className="flex overflow-x-auto px-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id as ResultType);
                setPage(1);
                setSelectedRows([]);
              }}
              className={cn(
                'px-4 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-colors',
                currentTab === tab.id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
              )}
            >
              {tab.label}
              {tab.count > 0 && (
                <span className="ml-2 text-xs bg-muted px-1.5 py-0.5 rounded">
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Toolbar - 只在非资产星图tab时显示 */}
      {currentTab !== 'topology' && (
        <div className="border-b bg-background px-6 py-3">
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="搜索"
                className="pl-9"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              />
            </div>
            <Button variant="outline" size="sm" onClick={handleSearch}>
              <Search className="h-4 w-4 mr-2" />
              搜索
            </Button>
            <Button variant="default" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              导出
            </Button>
            <Select value={projectFilter} onValueChange={setProjectFilter}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="项目筛选" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部项目</SelectItem>
              </SelectContent>
            </Select>
            {currentTab === 'dirscan' && (
              <div className="flex items-center gap-1">
                <Select
                  value={statusCodeFilter}
                  onValueChange={setStatusCodeFilter}
                >
                  <SelectTrigger className="w-28">
                    <SelectValue placeholder="状态码" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部</SelectItem>
                    <SelectItem value="200">200</SelectItem>
                    <SelectItem value="301">301</SelectItem>
                    <SelectItem value="302">302</SelectItem>
                    <SelectItem value="400">400</SelectItem>
                    <SelectItem value="401">401</SelectItem>
                    <SelectItem value="403">403</SelectItem>
                    <SelectItem value="404">404</SelectItem>
                    <SelectItem value="500">500</SelectItem>
                    <SelectItem value="502">502</SelectItem>
                    <SelectItem value="503">503</SelectItem>
                  </SelectContent>
                </Select>
                <Input
                  type="number"
                  placeholder="自定义"
                  className="w-20 h-9"
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val === '' || val === '0') {
                      setStatusCodeFilter('all');
                    } else {
                      setStatusCodeFilter(val);
                    }
                  }}
                />
              </div>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={selectedRows.length === 0}
                >
                  操作 ({selectedRows.length})
                  <ChevronDown className="h-4 w-4 ml-2" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem
                  onClick={() => {
                    resultApi.batchDelete(selectedRows).then(() => {
                      toast({ title: '删除成功' });
                      setSelectedRows([]);
                      queryClient.invalidateQueries({
                        queryKey: ['task-results', id],
                      });
                    });
                  }}
                >
                  批量删除
                </DropdownMenuItem>
                <DropdownMenuItem>批量导出</DropdownMenuItem>
                <DropdownMenuItem>批量标记</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button variant="ghost" size="icon">
              <Settings className="h-4 w-4" />
            </Button>
          </div>
          <div className="mt-2 flex items-center justify-between text-sm text-muted-foreground">
            <span>
              共 <span className="font-medium text-foreground">{total}</span>{' '}
              条结果
            </span>
            {total > pageSize && (
              <div className="flex items-center gap-1">
                {/* 首页 */}
                <Button
                  variant="outline"
                  size="icon"
                  className="h-8 w-8"
                  disabled={page === 1}
                  onClick={() => setPage(1)}
                  title="首页"
                >
                  <ChevronsLeft className="h-4 w-4" />
                </Button>

                {/* 上一页 */}
                <Button
                  variant="outline"
                  size="icon"
                  className="h-8 w-8"
                  disabled={page === 1}
                  onClick={() => setPage((p) => p - 1)}
                  title="上一页"
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>

                {/* 页码输入 */}
                <div className="flex items-center gap-1 px-2">
                  <span className="text-sm whitespace-nowrap">第</span>
                  <input
                    type="text"
                    placeholder={String(page)}
                    className="h-8 w-14 text-center px-1 border rounded-md text-sm"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        const val = parseInt(
                          (e.target as HTMLInputElement).value,
                          10
                        );
                        const maxPage = Math.ceil(total / pageSize);
                        if (!isNaN(val) && val >= 1 && val <= maxPage) {
                          setPage(val);
                          (e.target as HTMLInputElement).value = '';
                        }
                      }
                    }}
                  />
                  <span className="text-sm whitespace-nowrap">
                    / {Math.ceil(total / pageSize)} 页
                  </span>
                </div>

                {/* 下一页 */}
                <Button
                  variant="outline"
                  size="icon"
                  className="h-8 w-8"
                  disabled={page >= Math.ceil(total / pageSize)}
                  onClick={() => setPage((p) => p + 1)}
                  title="下一页"
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>

                {/* 末页 */}
                <Button
                  variant="outline"
                  size="icon"
                  className="h-8 w-8"
                  disabled={page >= Math.ceil(total / pageSize)}
                  onClick={() => setPage(Math.ceil(total / pageSize))}
                  title="末页"
                >
                  <ChevronsRight className="h-4 w-4" />
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Table Content or Topology View */}
      <div className="flex-1 overflow-auto">
        {currentTab === 'topology' ? (
          <TaskTopologyView taskId={taskId} taskName={task?.name || ''} />
        ) : (
          renderTable()
        )}
      </div>
    </div>
  );
}
