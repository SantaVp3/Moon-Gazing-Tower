import { useQuery } from '@tanstack/react-query';
import { dashboardApi, DashboardStats, TrendData } from '@/api/dashboard';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import RealTimeMonitor from '@/components/dashboard/RealTimeMonitor';
import {
  Server,
  Shield,
  ListTodo,
  HardDrive,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const ASSET_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444'];

export default function DashboardPage() {
  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => dashboardApi.getStats(),
  });

  const { data: trendsData } = useQuery({
    queryKey: ['dashboard-trends'],
    queryFn: () => dashboardApi.getTrends(7),
  });

  const { data: activitiesData } = useQuery({
    queryKey: ['dashboard-activities'],
    queryFn: () => dashboardApi.getRecentActivities(5),
  });

  const stats: DashboardStats | undefined = statsData?.data;
  const trends: TrendData[] = trendsData?.data || [];
  const activities = activitiesData?.data || [];

  const assetDistribution = stats?.assets?.byType
    ? Object.entries(stats.assets.byType).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  const vulnBySeverity = stats?.vulnerabilities?.bySeverity
    ? Object.entries(stats.vulnerabilities.bySeverity).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">仪表盘</h1>

      {/* Real-Time Monitor */}
      <RealTimeMonitor />

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">总资产</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.assets.total || 0}</div>
            <p className="text-xs text-muted-foreground">
              新增 {stats?.assets.recentlyAdded || 0} 个
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">漏洞数量</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.vulnerabilities.total || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              待修复 {stats?.vulnerabilities.open || 0} 个
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">扫描任务</CardTitle>
            <ListTodo className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.tasks.total || 0}</div>
            <p className="text-xs text-muted-foreground">
              运行中 {stats?.tasks.running || 0} 个
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">扫描节点</CardTitle>
            <HardDrive className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.nodes.total || 0}</div>
            <p className="text-xs text-muted-foreground">
              在线 {stats?.nodes.online || 0} 个
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Trend Chart */}
        <Card className="col-span-2 lg:col-span-1">
          <CardHeader>
            <CardTitle>趋势统计</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="assets"
                    stroke="#3b82f6"
                    name="资产"
                  />
                  <Line
                    type="monotone"
                    dataKey="vulnerabilities"
                    stroke="#ef4444"
                    name="漏洞"
                  />
                  <Line
                    type="monotone"
                    dataKey="tasks"
                    stroke="#10b981"
                    name="任务"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Vulnerability by Severity */}
        <Card>
          <CardHeader>
            <CardTitle>漏洞严重程度分布</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={vulnBySeverity} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={80} />
                  <Tooltip />
                  <Bar dataKey="value" name="数量">
                    {vulnBySeverity.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          SEVERITY_COLORS[
                            entry.name as keyof typeof SEVERITY_COLORS
                          ] || '#6b7280'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Asset Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>资产类型分布</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={assetDistribution}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) =>
                      `${name} ${(percent * 100).toFixed(0)}%`
                    }
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {assetDistribution.map((_entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={ASSET_COLORS[index % ASSET_COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activities */}
        <Card>
          <CardHeader>
            <CardTitle>最近活动</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {activities.length === 0 ? (
                <p className="text-muted-foreground text-center py-4">
                  暂无活动记录
                </p>
              ) : (
                activities.map((activity) => (
                  <div
                    key={activity.id}
                    className="flex items-center gap-3 text-sm"
                  >
                    <div className="h-8 w-8 rounded-full bg-muted flex items-center justify-center">
                      {activity.type === 'task' && (
                        <ListTodo className="h-4 w-4" />
                      )}
                      {activity.type === 'vulnerability' && (
                        <Shield className="h-4 w-4" />
                      )}
                      {activity.type === 'asset' && (
                        <Server className="h-4 w-4" />
                      )}
                    </div>
                    <div className="flex-1">
                      <p>
                        <span className="font-medium">{activity.username}</span>{' '}
                        {activity.action}{' '}
                        <span className="text-muted-foreground">
                          {activity.target}
                        </span>
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {new Date(activity.createdAt).toLocaleString('zh-CN')}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Task Status Summary */}
      <Card>
        <CardHeader>
          <CardTitle>任务状态概览</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="flex items-center gap-3 p-4 rounded-lg bg-muted">
              <Clock className="h-8 w-8 text-yellow-500" />
              <div>
                <p className="text-2xl font-bold">
                  {stats?.tasks.running || 0}
                </p>
                <p className="text-sm text-muted-foreground">运行中</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-4 rounded-lg bg-muted">
              <CheckCircle className="h-8 w-8 text-green-500" />
              <div>
                <p className="text-2xl font-bold">
                  {stats?.tasks.completed || 0}
                </p>
                <p className="text-sm text-muted-foreground">已完成</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-4 rounded-lg bg-muted">
              <XCircle className="h-8 w-8 text-red-500" />
              <div>
                <p className="text-2xl font-bold">{stats?.tasks.failed || 0}</p>
                <p className="text-sm text-muted-foreground">失败</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-4 rounded-lg bg-muted">
              <AlertTriangle className="h-8 w-8 text-orange-500" />
              <div>
                <p className="text-2xl font-bold">
                  {stats?.vulnerabilities.recentlyFound || 0}
                </p>
                <p className="text-sm text-muted-foreground">新发现漏洞</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
