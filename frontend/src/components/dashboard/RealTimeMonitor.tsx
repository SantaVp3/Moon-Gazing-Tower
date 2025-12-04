import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Cpu, HardDrive, Server, Activity } from 'lucide-react';

interface SystemData {
  cpu_usage: number;
  memory_usage: number;
  memory_total: number;
  memory_used: number;
  disk_usage: number;
  disk_total: number;
  disk_used: number;
}

interface NodesData {
  total: number;
  online: number;
  offline: number;
}

interface MonitorData {
  type: string;
  timestamp: number;
  system: SystemData;
  nodes: NodesData;
  analytics?: {
    monthly_users: number;
    monthly_spend: number;
    monthly_revenue: number;
    monthly_transactions: number;
  };
}

export default function RealTimeMonitor() {
  const [monitorData, setMonitorData] = useState<MonitorData | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<
    'connected' | 'disconnected' | 'connecting'
  >('connecting');

  const { isConnected } = useWebSocket('/api/ws', {
    onMessage: (message) => {
      if (message.type === 'monitor_data') {
        setMonitorData(message as MonitorData);
      }
    },
    onOpen: () => setConnectionStatus('connected'),
    onClose: () => setConnectionStatus('disconnected'),
  });

  useEffect(() => {
    if (isConnected) {
      setConnectionStatus('connected');
    } else {
      setConnectionStatus('disconnected');
    }
  }, [isConnected]);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatPercentage = (value: number) => {
    return Math.min(100, Math.max(0, value)).toFixed(1);
  };

  return (
    <div className="space-y-4">
      {/* Connection Status */}
      <div className="flex items-center gap-2">
        <Activity className="h-4 w-4" />
        <span className="text-sm font-medium">实时监控</span>
        <Badge
          variant={connectionStatus === 'connected' ? 'default' : 'secondary'}
          className={connectionStatus === 'connected' ? 'bg-green-500' : ''}
        >
          {connectionStatus === 'connected'
            ? '已连接'
            : connectionStatus === 'connecting'
              ? '连接中'
              : '已断开'}
        </Badge>
      </div>

      {/* System Resources */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {/* CPU Usage */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">CPU 使用率</CardTitle>
            <Cpu className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {monitorData?.system?.cpu_usage
                ? formatPercentage(monitorData.system.cpu_usage) + '%'
                : '0%'}
            </div>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 transition-all duration-500"
                style={{
                  width: `${monitorData?.system?.cpu_usage ? Math.min(100, monitorData.system.cpu_usage) : 0}%`,
                }}
              />
            </div>
          </CardContent>
        </Card>

        {/* Memory Usage */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">内存使用</CardTitle>
            <HardDrive className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {monitorData?.system?.memory_usage
                ? formatPercentage(monitorData.system.memory_usage) + '%'
                : '0%'}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {monitorData?.system
                ? `${formatBytes(monitorData.system.memory_used)} / ${formatBytes(monitorData.system.memory_total)}`
                : '0 B / 0 B'}
            </p>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-green-500 transition-all duration-500"
                style={{
                  width: `${monitorData?.system?.memory_usage ? Math.min(100, monitorData.system.memory_usage) : 0}%`,
                }}
              />
            </div>
          </CardContent>
        </Card>

        {/* Disk Usage */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">磁盘使用</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {monitorData?.system?.disk_usage
                ? formatPercentage(monitorData.system.disk_usage) + '%'
                : '0%'}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {monitorData?.system
                ? `${formatBytes(monitorData.system.disk_used)} / ${formatBytes(monitorData.system.disk_total)}`
                : '0 B / 0 B'}
            </p>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-orange-500 transition-all duration-500"
                style={{
                  width: `${monitorData?.system?.disk_usage ? Math.min(100, monitorData.system.disk_usage) : 0}%`,
                }}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Scan Nodes Status */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">扫描节点状态</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-6">
            <div>
              <p className="text-sm text-muted-foreground">总数</p>
              <p className="text-2xl font-bold">
                {monitorData?.nodes?.total || 0}
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">在线</p>
              <p className="text-2xl font-bold text-green-600">
                {monitorData?.nodes?.online || 0}
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">离线</p>
              <p className="text-2xl font-bold text-red-600">
                {monitorData?.nodes?.offline || 0}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Last Update */}
      {monitorData?.timestamp && (
        <p className="text-xs text-muted-foreground text-center">
          最后更新:{' '}
          {new Date(monitorData.timestamp * 1000).toLocaleString('zh-CN')}
        </p>
      )}
    </div>
  );
}
