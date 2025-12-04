import { useQuery } from '@tanstack/react-query';
import { nodeApi } from '@/api/nodes';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { cn, getStatusColor } from '@/lib/utils';
import { RefreshCw, HardDrive, Cpu, Database } from 'lucide-react';

export default function NodesPage() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['nodes'],
    queryFn: () => nodeApi.getNodes({ pageSize: 100 }),
    refetchInterval: 10000,
  });

  const { data: statsData } = useQuery({
    queryKey: ['node-stats'],
    queryFn: () => nodeApi.getNodeStats(),
  });

  const nodes = data?.data?.list || [];
  const stats = statsData?.data;

  const getStatusLabel = (status: string) => {
    const labels: Record<string, string> = {
      online: '在线',
      offline: '离线',
      busy: '忙碌',
      error: '错误',
    };
    return labels[status] || status;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">节点管理</h1>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          刷新
        </Button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <HardDrive className="h-8 w-8 text-muted-foreground" />
                <div>
                  <p className="text-2xl font-bold">{stats.total}</p>
                  <p className="text-sm text-muted-foreground">总节点</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <div className="h-8 w-8 rounded-full bg-green-500 flex items-center justify-center text-white text-sm font-bold">
                  {stats.online}
                </div>
                <div>
                  <p className="text-2xl font-bold text-green-500">
                    {stats.online}
                  </p>
                  <p className="text-sm text-muted-foreground">在线</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Cpu className="h-8 w-8 text-blue-500" />
                <div>
                  <p className="text-2xl font-bold">
                    {(stats.averageCpu ?? 0).toFixed(1)}%
                  </p>
                  <p className="text-sm text-muted-foreground">平均CPU</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Database className="h-8 w-8 text-purple-500" />
                <div>
                  <p className="text-2xl font-bold">
                    {(stats.averageMemory ?? 0).toFixed(1)}%
                  </p>
                  <p className="text-sm text-muted-foreground">平均内存</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Node Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {nodes.length === 0 ? (
          <div className="col-span-full text-center py-8 text-muted-foreground">
            暂无节点
          </div>
        ) : (
          nodes.map((node) => (
            <Card key={node.id}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{node.name}</CardTitle>
                  <Badge className={cn(getStatusColor(node.status))}>
                    {getStatusLabel(node.status)}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground font-mono">
                  {node.ipAddress}
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">类型</p>
                    <p className="font-medium">
                      {node.type === 'master' ? '主节点' : '工作节点'}
                    </p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">版本</p>
                    <p className="font-medium">{node.version}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">当前任务</p>
                    <p className="font-medium">
                      {node.currentTasks} / {node.maxConcurrency}
                    </p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">最后心跳</p>
                    <p className="font-medium text-xs">
                      {new Date(node.lastHeartbeat).toLocaleTimeString('zh-CN')}
                    </p>
                  </div>
                </div>
                <div className="space-y-2">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>CPU</span>
                      <span>{node.cpuUsage.toFixed(1)}%</span>
                    </div>
                    <Progress value={node.cpuUsage} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>内存</span>
                      <span>{node.memoryUsage.toFixed(1)}%</span>
                    </div>
                    <Progress value={node.memoryUsage} className="h-2" />
                  </div>
                </div>
                {node.capabilities && node.capabilities.length > 0 && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">能力</p>
                    <div className="flex flex-wrap gap-1">
                      {node.capabilities.map((cap) => (
                        <Badge key={cap} variant="outline" className="text-xs">
                          {cap}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
