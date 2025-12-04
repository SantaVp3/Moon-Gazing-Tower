import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { taskApi, TaskConfig } from '@/api/tasks';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/components/ui/use-toast';
import { ArrowLeft, Play, Save, X, Plus } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

const scanTypes = [
  { id: 'port_scan', label: '端口扫描', description: '扫描开放端口' },
  {
    id: 'service_detect',
    label: '服务识别',
    description: '识别服务类型和版本',
  },
  { id: 'vuln_scan', label: '漏洞扫描', description: '检测已知漏洞' },
  { id: 'fingerprint', label: '指纹识别', description: '识别目标指纹' },
  { id: 'subdomain', label: '子域名枚举', description: '发现子域名' },
  { id: 'takeover', label: '子域名接管', description: '检测子域名接管漏洞' },
  { id: 'crawler', label: 'Web爬虫', description: '爬取网站URL和接口' },
  { id: 'dir_scan', label: '目录扫描', description: '扫描敏感目录' },
];

// 检测目标类型
function detectTargetType(target: string): string {
  // IP 地址
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) {
    return 'ip';
  }
  // CIDR
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) {
    return 'cidr';
  }
  // URL
  if (/^https?:\/\//.test(target)) {
    return 'url';
  }
  // 域名
  if (
    /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(
      target
    )
  ) {
    return 'domain';
  }
  return 'unknown';
}

export default function TaskCreatePage() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    config: {
      scanTypes: ['port_scan', 'service_detect'],
      port_scan_mode: 'quick',
      portRange: '1-65535',
      timeout: 30,
      concurrent: 10,
      // 第三方 API 配置
      use_thirdparty: false,
      thirdparty_sources: [] as string[],
      fofa_email: '',
      fofa_key: '',
      hunter_key: '',
      quake_key: '',
    } as TaskConfig,
  });

  // 直接输入的目标
  const [directTargets, setDirectTargets] = useState<string[]>([]);
  const [targetInput, setTargetInput] = useState('');

  // 创建任务
  const createMutation = useMutation({
    mutationFn: taskApi.createTask,
    onSuccess: () => {
      toast({ title: '任务创建成功' });
      navigate('/tasks');
    },
    onError: (error: Error) => {
      toast({
        title: '创建失败',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  // 根据选择的扫描类型自动确定任务类型
  const getTaskType = (scanTypes: string[]): string => {
    if (scanTypes.length === 0) return 'port_scan';
    if (scanTypes.length === 1) {
      // 单一扫描类型直接返回对应类型
      return scanTypes[0];
    }
    // 多种扫描类型使用 full 模式，让后端流水线处理
    return 'full';
  };

  // 添加直接输入的目标
  const addDirectTargets = () => {
    if (!targetInput.trim()) return;

    // 解析输入的目标（支持换行、逗号、空格分隔）
    const newTargets = targetInput
      .split(/[\n,\s]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    // 去重后添加
    const uniqueTargets = [...new Set([...directTargets, ...newTargets])];
    setDirectTargets(uniqueTargets);
    setTargetInput('');
  };

  // 删除单个目标
  const removeDirectTarget = (target: string) => {
    setDirectTargets(directTargets.filter((t) => t !== target));
  };

  // 清空所有目标
  const clearDirectTargets = () => {
    setDirectTargets([]);
  };

  const handleSubmit = () => {
    if (!formData.name.trim()) {
      toast({ title: '请输入任务名称', variant: 'destructive' });
      return;
    }

    // 验证目标 - 只支持直接输入模式
    let targets: string[] = [];
    let targetType: string = 'unknown';

    if (directTargets.length === 0) {
      toast({ title: '请输入至少一个扫描目标', variant: 'destructive' });
      return;
    }
    targets = directTargets;

    // 自动检测目标类型
    const types = [...new Set(targets.map(detectTargetType))];
    targetType = types.length === 1 ? types[0] : 'mixed';

    if ((formData.config.scanTypes?.length ?? 0) === 0) {
      toast({ title: '请选择至少一种扫描类型', variant: 'destructive' });
      return;
    }

    // 根据选择的扫描类型自动确定任务类型
    const taskType = getTaskType(formData.config.scanTypes || []);

    createMutation.mutate({
      name: formData.name,
      type: taskType,
      targets: targets,
      targetType: targetType,
      description: formData.description,
      config: formData.config,
    });
  };

  const toggleScanType = (scanTypeId: string) => {
    const current = formData.config.scanTypes || [];
    if (current.includes(scanTypeId)) {
      setFormData({
        ...formData,
        config: {
          ...formData.config,
          scanTypes: current.filter((t) => t !== scanTypeId),
        },
      });
    } else {
      setFormData({
        ...formData,
        config: {
          ...formData.config,
          scanTypes: [...current, scanTypeId],
        },
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* 头部 */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/tasks')}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <h1 className="text-2xl font-bold">创建扫描任务</h1>
      </div>

      {/* 表单内容 */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* 左侧 - 基本信息 */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>基本信息</CardTitle>
              <CardDescription>设置任务名称</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>任务名称 *</Label>
                <Input
                  placeholder="输入任务名称"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label>任务描述</Label>
                <Textarea
                  placeholder="输入任务描述（可选）"
                  value={formData.description}
                  onChange={(e) =>
                    setFormData({ ...formData, description: e.target.value })
                  }
                />
              </div>
            </CardContent>
          </Card>

          {/* 扫描配置 */}
          <Card>
            <CardHeader>
              <CardTitle>扫描配置</CardTitle>
              <CardDescription>配置扫描参数</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>端口扫描模式</Label>
                  <Select
                    value={formData.config.port_scan_mode || 'quick'}
                    onValueChange={(value) =>
                      setFormData({
                        ...formData,
                        config: { ...formData.config, port_scan_mode: value },
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="quick">快速扫描 (常用端口)</SelectItem>
                      <SelectItem value="top1000">Top 1000 端口</SelectItem>
                      <SelectItem value="full">全端口扫描 (1-65535)</SelectItem>
                      <SelectItem value="custom">自定义端口范围</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {formData.config.port_scan_mode === 'custom' && (
                  <div className="space-y-2">
                    <Label>端口范围</Label>
                    <Input
                      placeholder="1-1000, 8080, 8443"
                      value={formData.config.portRange || ''}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          config: {
                            ...formData.config,
                            portRange: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                )}
                <div className="space-y-2">
                  <Label>超时时间 (秒)</Label>
                  <Input
                    type="number"
                    placeholder="30"
                    value={formData.config.timeout || ''}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        config: {
                          ...formData.config,
                          timeout: Number(e.target.value),
                        },
                      })
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label>并发数</Label>
                  <Input
                    type="number"
                    placeholder="10"
                    value={formData.config.concurrent || ''}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        config: {
                          ...formData.config,
                          concurrent: Number(e.target.value),
                        },
                      })
                    }
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* 第三方 API 配置 - 仅在选择子域名枚举时显示 */}
          {formData.config.scanTypes?.includes('subdomain') && (
            <Card>
              <CardHeader>
                <CardTitle>第三方 API 配置</CardTitle>
                <CardDescription>
                  配置 FOFA/Hunter/Quake 等 API 收集更多子域名
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="use_thirdparty"
                    checked={formData.config.use_thirdparty}
                    onCheckedChange={(checked) =>
                      setFormData({
                        ...formData,
                        config: {
                          ...formData.config,
                          use_thirdparty: checked as boolean,
                        },
                      })
                    }
                  />
                  <Label htmlFor="use_thirdparty">
                    启用第三方 API 收集子域名
                  </Label>
                </div>

                {formData.config.use_thirdparty && (
                  <div className="space-y-4 pt-2">
                    {/* 数据源选择 */}
                    <div className="space-y-2">
                      <Label>数据源（不选则使用全部已配置的）</Label>
                      <div className="flex flex-wrap gap-2">
                        {['fofa', 'hunter', 'quake', 'crtsh'].map((source) => (
                          <Badge
                            key={source}
                            variant={
                              formData.config.thirdparty_sources?.includes(
                                source
                              )
                                ? 'default'
                                : 'outline'
                            }
                            className="cursor-pointer"
                            onClick={() => {
                              const current =
                                formData.config.thirdparty_sources || [];
                              const newSources = current.includes(source)
                                ? current.filter((s) => s !== source)
                                : [...current, source];
                              setFormData({
                                ...formData,
                                config: {
                                  ...formData.config,
                                  thirdparty_sources: newSources,
                                },
                              });
                            }}
                          >
                            {source.toUpperCase()}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* FOFA 配置 */}
                    <div className="grid grid-cols-2 gap-2">
                      <div className="space-y-1">
                        <Label className="text-xs">FOFA Email</Label>
                        <Input
                          placeholder="your@email.com"
                          value={formData.config.fofa_email || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              config: {
                                ...formData.config,
                                fofa_email: e.target.value,
                              },
                            })
                          }
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">FOFA Key</Label>
                        <Input
                          type="password"
                          placeholder="API Key"
                          value={formData.config.fofa_key || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              config: {
                                ...formData.config,
                                fofa_key: e.target.value,
                              },
                            })
                          }
                        />
                      </div>
                    </div>

                    {/* Hunter 配置 */}
                    <div className="space-y-1">
                      <Label className="text-xs">Hunter API Key</Label>
                      <Input
                        type="password"
                        placeholder="Hunter API Key"
                        value={formData.config.hunter_key || ''}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            config: {
                              ...formData.config,
                              hunter_key: e.target.value,
                            },
                          })
                        }
                      />
                    </div>

                    {/* Quake 配置 */}
                    <div className="space-y-1">
                      <Label className="text-xs">Quake API Key</Label>
                      <Input
                        type="password"
                        placeholder="Quake API Key"
                        value={formData.config.quake_key || ''}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            config: {
                              ...formData.config,
                              quake_key: e.target.value,
                            },
                          })
                        }
                      />
                    </div>

                    <p className="text-xs text-muted-foreground">
                      提示：CrtSh 免费无需配置，其他 API 需要填写对应的密钥
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* 右侧 */}
        <div className="space-y-6">
          {/* 扫描类型 */}
          <Card>
            <CardHeader>
              <CardTitle>扫描类型 *</CardTitle>
              <CardDescription>选择要执行的扫描类型</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {scanTypes.map((type) => (
                  <div
                    key={type.id}
                    className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                      formData.config.scanTypes?.includes(type.id)
                        ? 'border-primary bg-primary/5'
                        : 'hover:bg-muted'
                    }`}
                    onClick={() => toggleScanType(type.id)}
                  >
                    <div className="flex items-center gap-2">
                      <Checkbox
                        checked={formData.config.scanTypes?.includes(type.id)}
                      />
                      <div>
                        <div className="font-medium text-sm">{type.label}</div>
                        <div className="text-xs text-muted-foreground">
                          {type.description}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* 选择目标 - 只支持直接输入 */}
          <Card>
            <CardHeader>
              <CardTitle>扫描目标 *</CardTitle>
              <CardDescription>输入要扫描的目标</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>输入目标（支持IP、域名、URL、CIDR）</Label>
                <div className="flex gap-2">
                  <Textarea
                    placeholder="每行一个目标，或用逗号/空格分隔&#10;例如:&#10;192.168.1.1&#10;example.com&#10;https://example.com&#10;10.0.0.0/24"
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    rows={4}
                    className="flex-1"
                  />
                </div>
                <div className="flex gap-2">
                  <Button type="button" onClick={addDirectTargets} size="sm">
                    <Plus className="h-4 w-4 mr-1" />
                    添加
                  </Button>
                  {directTargets.length > 0 && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={clearDirectTargets}
                    >
                      清空全部
                    </Button>
                  )}
                </div>
              </div>

              {/* 已添加的目标列表 */}
              {directTargets.length > 0 && (
                <div className="space-y-2">
                  <Label>已添加目标（{directTargets.length}个）</Label>
                  <div className="max-h-40 overflow-auto border rounded-lg p-2 space-y-1">
                    {directTargets.map((target, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-2 bg-muted rounded text-sm"
                      >
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                          <Badge variant="outline" className="shrink-0">
                            {detectTargetType(target)}
                          </Badge>
                          <span className="truncate">{target}</span>
                        </div>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 shrink-0"
                          onClick={() => removeDirectTarget(target)}
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* 底部操作按钮 */}
      <div className="flex justify-end gap-4 pt-4 border-t">
        <Button variant="outline" onClick={() => navigate('/tasks')}>
          取消
        </Button>
        <Button
          variant="outline"
          onClick={() => handleSubmit()}
          disabled={createMutation.isPending}
        >
          <Save className="h-4 w-4 mr-2" />
          保存
        </Button>
        <Button
          onClick={() => handleSubmit()}
          disabled={createMutation.isPending}
        >
          <Play className="h-4 w-4 mr-2" />
          创建并启动
        </Button>
      </div>
    </div>
  );
}
