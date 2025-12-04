import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { vulnApi } from '@/api/vulnerabilities';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useToast } from '@/components/ui/use-toast';
import { cn, formatDate, getSeverityColor, getStatusColor } from '@/lib/utils';
import {
  Search,
  Eye,
  Download,
  RefreshCw,
  CheckCircle,
  MoreHorizontal,
  BarChart3,
  List,
  Loader2,
  Shield,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import VulnDashboard from '@/components/vulnerabilities/VulnDashboard';

export default function VulnerabilitiesPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [page, setPage] = useState(1);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['vulnerabilities', page, search, severityFilter, statusFilter],
    queryFn: () =>
      vulnApi.getVulnerabilities({
        page,
        pageSize: 10,
        search,
        severity: severityFilter === 'all' ? undefined : severityFilter,
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
  });

  const verifyMutation = useMutation({
    mutationFn: vulnApi.verifyVulnerability,
    onSuccess: (result) => {
      toast({
        title: result.data.verified ? '漏洞已验证存在' : '漏洞无法复现',
        variant: result.data.verified ? 'default' : 'destructive',
      });
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['vulnStatistics'] });
    },
    onError: () => {
      toast({ title: '验证失败', variant: 'destructive' });
    },
  });

  const batchUpdateMutation = useMutation({
    mutationFn: ({ ids, status }: { ids: string[]; status: string }) =>
      vulnApi.batchUpdateStatus(ids, status),
    onSuccess: () => {
      toast({ title: '批量更新成功' });
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['vulnStatistics'] });
    },
    onError: () => {
      toast({ title: '批量更新失败', variant: 'destructive' });
    },
  });

  const vulnerabilities = data?.data?.list || [];
  const total = data?.data?.total || 0;
  const totalPages = Math.ceil(total / 10);

  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
    };
    return labels[severity] || severity;
  };

  const getStatusLabel = (status: string) => {
    const labels: Record<string, string> = {
      open: '待处理',
      confirmed: '已确认',
      fixed: '已修复',
      ignored: '已忽略',
      false_positive: '误报',
    };
    return labels[status] || status;
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(vulnerabilities.map((v) => v.id));
    } else {
      setSelectedIds([]);
    }
  };

  const handleSelectOne = (id: string, checked: boolean) => {
    if (checked) {
      setSelectedIds([...selectedIds, id]);
    } else {
      setSelectedIds(selectedIds.filter((i) => i !== id));
    }
  };

  const handleBatchAction = (status: string) => {
    if (selectedIds.length === 0) {
      toast({ title: '请先选择漏洞', variant: 'destructive' });
      return;
    }
    batchUpdateMutation.mutate({ ids: selectedIds, status });
  };

  const VulnListContent = () => (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="搜索漏洞..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-32">
            <SelectValue placeholder="严重程度" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部</SelectItem>
            <SelectItem value="critical">严重</SelectItem>
            <SelectItem value="high">高危</SelectItem>
            <SelectItem value="medium">中危</SelectItem>
            <SelectItem value="low">低危</SelectItem>
            <SelectItem value="info">信息</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-32">
            <SelectValue placeholder="状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部</SelectItem>
            <SelectItem value="open">待处理</SelectItem>
            <SelectItem value="confirmed">已确认</SelectItem>
            <SelectItem value="fixed">已修复</SelectItem>
            <SelectItem value="ignored">已忽略</SelectItem>
            <SelectItem value="false_positive">误报</SelectItem>
          </SelectContent>
        </Select>

        {/* Batch Actions */}
        {selectedIds.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                批量操作 ({selectedIds.length})
                <MoreHorizontal className="ml-2 h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => handleBatchAction('confirmed')}>
                标记为已确认
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleBatchAction('fixed')}>
                标记为已修复
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleBatchAction('ignored')}>
                标记为已忽略
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => handleBatchAction('false_positive')}
              >
                标记为误报
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[40px]">
                <Checkbox
                  checked={
                    selectedIds.length === vulnerabilities.length &&
                    vulnerabilities.length > 0
                  }
                  onCheckedChange={handleSelectAll}
                />
              </TableHead>
              <TableHead>漏洞名称</TableHead>
              <TableHead>严重程度</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>目标</TableHead>
              <TableHead>CVE</TableHead>
              <TableHead>发现时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                </TableCell>
              </TableRow>
            ) : vulnerabilities.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={8}
                  className="text-center py-8 text-muted-foreground"
                >
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              vulnerabilities.map((vuln) => (
                <TableRow key={vuln.id}>
                  <TableCell>
                    <Checkbox
                      checked={selectedIds.includes(vuln.id)}
                      onCheckedChange={(checked) =>
                        handleSelectOne(vuln.id, checked as boolean)
                      }
                    />
                  </TableCell>
                  <TableCell className="font-medium max-w-xs truncate">
                    {vuln.name}
                  </TableCell>
                  <TableCell>
                    <Badge className={cn(getSeverityColor(vuln.severity))}>
                      {getSeverityLabel(vuln.severity)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={cn(getStatusColor(vuln.status))}
                    >
                      {getStatusLabel(vuln.status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm max-w-xs truncate">
                    {vuln.target}
                  </TableCell>
                  <TableCell>{vuln.cve || '-'}</TableCell>
                  <TableCell>{formatDate(vuln.createdAt)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {vuln.status === 'open' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={verifyMutation.isPending}
                          onClick={() => verifyMutation.mutate(vuln.id)}
                          title="验证漏洞"
                        >
                          {verifyMutation.isPending ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          )}
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" asChild>
                        <Link to={`/vulnerabilities/${vuln.id}`}>
                          <Eye className="h-4 w-4" />
                        </Link>
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

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Shield className="h-6 w-6" />
          漏洞管理
        </h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            导出报告
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="dashboard" className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4" />
            统计面板
          </TabsTrigger>
          <TabsTrigger value="list" className="flex items-center gap-2">
            <List className="h-4 w-4" />
            漏洞列表
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="mt-6">
          <VulnDashboard />
        </TabsContent>

        <TabsContent value="list" className="mt-6">
          <VulnListContent />
        </TabsContent>
      </Tabs>
    </div>
  );
}
