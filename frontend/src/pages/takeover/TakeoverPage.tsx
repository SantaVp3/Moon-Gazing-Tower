import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { takeoverApi, TakeoverResult } from '@/api/takeover';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/components/ui/use-toast';
import { formatDate } from '@/lib/utils';
import {
  Globe,
  Play,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Shield,
  Target,
} from 'lucide-react';

const confidenceConfig: Record<string, { label: string; color: string }> = {
  high: { label: '高', color: 'text-red-500' },
  medium: { label: '中', color: 'text-orange-500' },
  low: { label: '低', color: 'text-yellow-500' },
};

export default function TakeoverPage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('single');
  const [singleDomain, setSingleDomain] = useState('');
  const [batchDomains, setBatchDomains] = useState('');
  const [results, setResults] = useState<TakeoverResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);

  // 获取服务商列表
  const { data: providersData } = useQuery({
    queryKey: ['takeover-providers'],
    queryFn: takeoverApi.getProviders,
  });

  // 获取历史记录
  const {
    data: historyData,
    isLoading: historyLoading,
    refetch: refetchHistory,
  } = useQuery({
    queryKey: ['takeover-history'],
    queryFn: () => takeoverApi.getHistory({ pageSize: 20 }),
    enabled: activeTab === 'history',
  });

  // 单域名扫描
  const singleMutation = useMutation({
    mutationFn: takeoverApi.check,
    onSuccess: (res) => {
      setResults([res.data]);
      if (res.data.vulnerable) {
        toast({
          title: '发现可接管域名!',
          description: `${res.data.domain} - ${res.data.provider}`,
          variant: 'destructive',
        });
      } else {
        toast({ title: '扫描完成', description: '未发现可接管域名' });
      }
    },
    onError: () => {
      toast({ title: '扫描失败', variant: 'destructive' });
    },
  });

  // 批量扫描
  const batchMutation = useMutation({
    mutationFn: takeoverApi.batchCheck,
    onMutate: () => {
      setScanning(true);
      setProgress(0);
    },
    onSuccess: (res) => {
      setResults(res.data.results);
      setScanning(false);
      setProgress(100);
      if (res.data.vulnerable > 0) {
        toast({
          title: `发现 ${res.data.vulnerable} 个可接管域名!`,
          variant: 'destructive',
        });
      } else {
        toast({ title: '扫描完成', description: '未发现可接管域名' });
      }
    },
    onError: () => {
      setScanning(false);
      toast({ title: '扫描失败', variant: 'destructive' });
    },
  });

  const providers = providersData?.data || [];
  const history = historyData?.data?.list || [];

  const handleSingleScan = () => {
    if (!singleDomain) {
      toast({ title: '请输入域名', variant: 'destructive' });
      return;
    }
    setResults([]);
    singleMutation.mutate(singleDomain);
  };

  const handleBatchScan = () => {
    const domains = batchDomains
      .split('\n')
      .map((d) => d.trim())
      .filter((d) => d);

    if (domains.length === 0) {
      toast({ title: '请输入至少一个域名', variant: 'destructive' });
      return;
    }
    setResults([]);
    batchMutation.mutate(domains);
  };

  // 统计结果
  const vulnerableCount = results.filter((r) => r.vulnerable).length;
  const safeCount = results.filter((r) => !r.vulnerable).length;

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">子域名接管检测</h1>
        </div>
      </div>

      {/* 支持的服务商 */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">
            支持检测的服务商
          </CardTitle>
          <CardDescription>
            共支持 {providers.length} 个云服务商的接管检测
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {providers.slice(0, 20).map((provider) => (
              <Badge key={provider.name} variant="outline">
                {provider.name}
              </Badge>
            ))}
            {providers.length > 20 && (
              <Badge variant="outline">+{providers.length - 20} 更多</Badge>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 标签页 */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="single">单域名扫描</TabsTrigger>
          <TabsTrigger value="batch">批量扫描</TabsTrigger>
          <TabsTrigger value="history">历史记录</TabsTrigger>
        </TabsList>

        {/* 单域名扫描 */}
        <TabsContent value="single" className="space-y-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex gap-4">
                <div className="flex-1">
                  <Input
                    placeholder="输入子域名，如: sub.example.com"
                    value={singleDomain}
                    onChange={(e) => setSingleDomain(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSingleScan()}
                  />
                </div>
                <Button
                  onClick={handleSingleScan}
                  disabled={singleMutation.isPending}
                >
                  <Target className="h-4 w-4 mr-2" />
                  开始扫描
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 批量扫描 */}
        <TabsContent value="batch" className="space-y-4">
          <Card>
            <CardContent className="pt-6 space-y-4">
              <div className="space-y-2">
                <Label>域名列表 (每行一个)</Label>
                <Textarea
                  placeholder="sub1.example.com&#10;sub2.example.com&#10;sub3.example.com"
                  rows={8}
                  value={batchDomains}
                  onChange={(e) => setBatchDomains(e.target.value)}
                />
              </div>
              {scanning && (
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>扫描进度</span>
                    <span>{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}
              <Button
                onClick={handleBatchScan}
                disabled={batchMutation.isPending}
                className="w-full"
              >
                <Play className="h-4 w-4 mr-2" />
                批量扫描
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 历史记录 */}
        <TabsContent value="history">
          <div className="flex justify-end mb-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetchHistory()}
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              刷新
            </Button>
          </div>
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>域名</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>服务商</TableHead>
                  <TableHead>CNAME</TableHead>
                  <TableHead>置信度</TableHead>
                  <TableHead>检测时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {historyLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8">
                      加载中...
                    </TableCell>
                  </TableRow>
                ) : history.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="text-center py-8 text-muted-foreground"
                    >
                      暂无历史记录
                    </TableCell>
                  </TableRow>
                ) : (
                  history.map((result, index) => {
                    const conf =
                      confidenceConfig[result.confidence] ||
                      confidenceConfig.low;
                    return (
                      <TableRow key={index}>
                        <TableCell className="font-medium">
                          {result.domain}
                        </TableCell>
                        <TableCell>
                          {result.vulnerable ? (
                            <Badge
                              variant="destructive"
                              className="flex items-center gap-1 w-fit"
                            >
                              <AlertTriangle className="h-3 w-3" />
                              可接管
                            </Badge>
                          ) : (
                            <Badge
                              variant="outline"
                              className="flex items-center gap-1 w-fit"
                            >
                              <CheckCircle className="h-3 w-3" />
                              安全
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>{result.provider || '-'}</TableCell>
                        <TableCell className="max-w-xs truncate">
                          {result.cnames?.join(', ') || '-'}
                        </TableCell>
                        <TableCell>
                          {result.vulnerable && (
                            <span className={conf.color}>{conf.label}</span>
                          )}
                        </TableCell>
                        <TableCell>{formatDate(result.checkedAt)}</TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>

      {/* 扫描结果 */}
      {results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              扫描结果
            </CardTitle>
            <CardDescription>
              共扫描 {results.length} 个域名，发现 {vulnerableCount} 个可接管，
              {safeCount} 个安全
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="border rounded-lg">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>域名</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>服务商</TableHead>
                    <TableHead>CNAME</TableHead>
                    <TableHead>置信度</TableHead>
                    <TableHead>指纹</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {results.map((result, index) => {
                    const conf =
                      confidenceConfig[result.confidence] ||
                      confidenceConfig.low;
                    return (
                      <TableRow
                        key={index}
                        className={
                          result.vulnerable
                            ? 'bg-red-50 dark:bg-red-950/20'
                            : ''
                        }
                      >
                        <TableCell className="font-medium">
                          {result.domain}
                        </TableCell>
                        <TableCell>
                          {result.vulnerable ? (
                            <Badge
                              variant="destructive"
                              className="flex items-center gap-1 w-fit"
                            >
                              <AlertTriangle className="h-3 w-3" />
                              可接管
                            </Badge>
                          ) : (
                            <Badge
                              variant="outline"
                              className="flex items-center gap-1 w-fit"
                            >
                              <CheckCircle className="h-3 w-3" />
                              安全
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>{result.provider || '-'}</TableCell>
                        <TableCell className="max-w-xs truncate">
                          {result.cnames?.join(', ') || '-'}
                        </TableCell>
                        <TableCell>
                          {result.vulnerable && (
                            <span className={conf.color}>{conf.label}</span>
                          )}
                        </TableCell>
                        <TableCell className="max-w-xs truncate text-xs text-muted-foreground">
                          {result.fingerprint || '-'}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
