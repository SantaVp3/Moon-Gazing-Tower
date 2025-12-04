import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { notifyApi, NotifyConfig, NotifyHistory } from '@/api/notify';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
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
  Bell,
  Plus,
  RefreshCw,
  Trash2,
  Send,
  MessageSquare,
  Mail,
  Webhook,
  CheckCircle,
  XCircle,
} from 'lucide-react';

const channelTypeIcons: Record<string, React.ReactNode> = {
  dingtalk: <MessageSquare className="h-4 w-4 text-blue-500" />,
  feishu: <MessageSquare className="h-4 w-4 text-purple-500" />,
  wechat: <MessageSquare className="h-4 w-4 text-green-500" />,
  email: <Mail className="h-4 w-4 text-orange-500" />,
  webhook: <Webhook className="h-4 w-4 text-gray-500" />,
};

const channelTypeLabels: Record<string, string> = {
  dingtalk: '钉钉',
  feishu: '飞书',
  wechat: '企业微信',
  email: '邮件',
  webhook: 'WebHook',
};

export default function NotifyPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('channels');
  const [showAddDialog, setShowAddDialog] = useState(false);

  // 新建渠道表单
  const [newChannel, setNewChannel] = useState({
    name: '',
    type: 'dingtalk' as NotifyConfig['type'],
    webhook: '',
    secret: '',
  });

  // 获取配置列表
  const {
    data: configsData,
    isLoading: configsLoading,
    refetch: refetchConfigs,
  } = useQuery({
    queryKey: ['notify-configs'],
    queryFn: notifyApi.getConfigs,
  });

  // 获取通知历史
  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ['notify-history'],
    queryFn: () => notifyApi.getHistory({ limit: 50 }),
    enabled: activeTab === 'history',
  });

  // 创建配置
  const createMutation = useMutation({
    mutationFn: notifyApi.addConfig,
    onSuccess: () => {
      toast({ title: '创建成功' });
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] });
      setShowAddDialog(false);
      setNewChannel({ name: '', type: 'dingtalk', webhook: '', secret: '' });
    },
    onError: () => {
      toast({ title: '创建失败', variant: 'destructive' });
    },
  });

  // 删除配置
  const deleteMutation = useMutation({
    mutationFn: ({ name, type }: { name: string; type: string }) =>
      notifyApi.deleteConfig(name, type),
    onSuccess: () => {
      toast({ title: '删除成功' });
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] });
    },
    onError: () => {
      toast({ title: '删除失败', variant: 'destructive' });
    },
  });

  // 切换配置状态
  const toggleMutation = useMutation({
    mutationFn: ({
      name,
      type,
      enabled,
    }: {
      name: string;
      type: string;
      enabled: boolean;
    }) => notifyApi.enableConfig(name, type, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] });
    },
  });

  // 测试配置
  const testMutation = useMutation({
    mutationFn: notifyApi.testConfig,
    onSuccess: (res) => {
      if (res.data?.success) {
        toast({ title: '测试成功', description: '通知已发送' });
      } else {
        toast({
          title: '测试失败',
          description: res.data?.message,
          variant: 'destructive',
        });
      }
    },
    onError: () => {
      toast({ title: '测试失败', variant: 'destructive' });
    },
  });

  const configs = configsData?.data || [];
  const history = historyData?.data || [];

  const handleCreate = () => {
    if (!newChannel.name || !newChannel.webhook) {
      toast({ title: '请填写完整信息', variant: 'destructive' });
      return;
    }

    // 根据类型构建配置
    const config: NotifyConfig = {
      name: newChannel.name,
      type: newChannel.type,
      enabled: true,
    };

    // 根据类型设置对应的 webhook 字段
    switch (newChannel.type) {
      case 'dingtalk':
        config.dingtalk_webhook = newChannel.webhook;
        if (newChannel.secret) config.dingtalk_secret = newChannel.secret;
        break;
      case 'feishu':
        config.feishu_webhook = newChannel.webhook;
        if (newChannel.secret) config.feishu_secret = newChannel.secret;
        break;
      case 'wechat':
        config.wechat_webhook = newChannel.webhook;
        break;
      case 'webhook':
        config.webhook_url = newChannel.webhook;
        config.webhook_method = 'POST';
        break;
    }

    createMutation.mutate(config);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success':
        return (
          <Badge className="bg-green-500">
            <CheckCircle className="h-3 w-3 mr-1" />
            成功
          </Badge>
        );
      case 'failed':
        return (
          <Badge variant="destructive">
            <XCircle className="h-3 w-3 mr-1" />
            失败
          </Badge>
        );
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  // 获取配置的webhook地址（用于显示）
  const getWebhook = (config: NotifyConfig): string => {
    switch (config.type) {
      case 'dingtalk':
        return config.dingtalk_webhook || '';
      case 'feishu':
        return config.feishu_webhook || '';
      case 'wechat':
        return config.wechat_webhook || '';
      case 'webhook':
        return config.webhook_url || '';
      default:
        return '';
    }
  };

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">通知管理</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetchConfigs()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="sm" onClick={() => setShowAddDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加渠道
          </Button>
        </div>
      </div>

      {/* 标签页 */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="channels">通知渠道</TabsTrigger>
          <TabsTrigger value="history">发送历史</TabsTrigger>
        </TabsList>

        {/* 渠道列表 */}
        <TabsContent value="channels" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {configsLoading ? (
              <div className="col-span-full text-center py-8 text-muted-foreground">
                加载中...
              </div>
            ) : configs.length === 0 ? (
              <div className="col-span-full text-center py-8 text-muted-foreground">
                暂无通知渠道，点击"添加渠道"创建
              </div>
            ) : (
              configs.map((config, index) => (
                <Card key={`${config.name}-${config.type}-${index}`}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {channelTypeIcons[config.type]}
                        <CardTitle className="text-base">
                          {config.name}
                        </CardTitle>
                      </div>
                      <Switch
                        checked={config.enabled}
                        onCheckedChange={(checked) =>
                          toggleMutation.mutate({
                            name: config.name,
                            type: config.type,
                            enabled: checked,
                          })
                        }
                      />
                    </div>
                    <CardDescription>
                      {channelTypeLabels[config.type]}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-xs text-muted-foreground mb-2 truncate">
                      {getWebhook(config).substring(0, 50)}...
                    </div>
                    <div className="flex items-center justify-end">
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => testMutation.mutate(config)}
                          disabled={testMutation.isPending}
                          title="测试"
                        >
                          <Send className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() =>
                            deleteMutation.mutate({
                              name: config.name,
                              type: config.type,
                            })
                          }
                          title="删除"
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </TabsContent>

        {/* 发送历史 */}
        <TabsContent value="history">
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>类型</TableHead>
                  <TableHead>标题</TableHead>
                  <TableHead>级别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {historyLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      加载中...
                    </TableCell>
                  </TableRow>
                ) : history.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center py-8 text-muted-foreground"
                    >
                      暂无发送记录
                    </TableCell>
                  </TableRow>
                ) : (
                  history.map((item: NotifyHistory) => (
                    <TableRow key={item.id}>
                      <TableCell>
                        <Badge variant="outline">
                          {channelTypeLabels[item.type] || item.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">
                        {item.message?.title}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            item.message?.level === 'warning'
                              ? 'destructive'
                              : 'outline'
                          }
                        >
                          {item.message?.level}
                        </Badge>
                      </TableCell>
                      <TableCell>{getStatusBadge(item.status)}</TableCell>
                      <TableCell>{formatDate(item.timestamp)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>

      {/* 添加渠道对话框 */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>添加通知渠道</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>渠道名称</Label>
              <Input
                placeholder="输入渠道名称"
                value={newChannel.name}
                onChange={(e) =>
                  setNewChannel({ ...newChannel, name: e.target.value })
                }
              />
            </div>
            <div className="space-y-2">
              <Label>渠道类型</Label>
              <Select
                value={newChannel.type}
                onValueChange={(value) =>
                  setNewChannel({
                    ...newChannel,
                    type: value as NotifyConfig['type'],
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="dingtalk">钉钉</SelectItem>
                  <SelectItem value="feishu">飞书</SelectItem>
                  <SelectItem value="wechat">企业微信</SelectItem>
                  <SelectItem value="webhook">WebHook</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Webhook 地址</Label>
              <Input
                placeholder="输入 Webhook URL"
                value={newChannel.webhook}
                onChange={(e) =>
                  setNewChannel({ ...newChannel, webhook: e.target.value })
                }
              />
            </div>
            {(newChannel.type === 'dingtalk' ||
              newChannel.type === 'feishu') && (
              <div className="space-y-2">
                <Label>签名密钥 (可选)</Label>
                <Input
                  placeholder="输入签名密钥"
                  value={newChannel.secret}
                  onChange={(e) =>
                    setNewChannel({ ...newChannel, secret: e.target.value })
                  }
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddDialog(false)}>
              取消
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              创建
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
