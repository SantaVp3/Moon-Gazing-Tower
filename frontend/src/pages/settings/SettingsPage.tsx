import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useAuthStore } from '@/store/auth';
import { useAppStore } from '@/store/app';
import { authApi } from '@/api/auth';
import { settingsApi, ThirdPartyConfig } from '@/api/settings';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/components/ui/use-toast';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import {
  Moon,
  Sun,
  Monitor,
  Palette,
  User,
  Lock,
  Key,
  CheckCircle,
  XCircle,
} from 'lucide-react';

export default function SettingsPage() {
  const { toast } = useToast();
  const { user } = useAuthStore();
  const { theme, setTheme } = useAppStore();
  const [passwordForm, setPasswordForm] = useState({
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [profileForm, setProfileForm] = useState({
    nickname: user?.nickname || '',
    email: user?.email || '',
  });
  const [apiConfigForm, setApiConfigForm] = useState<Partial<ThirdPartyConfig>>(
    {
      fofa_email: '',
      fofa_key: '',
      hunter_key: '',
      quake_key: '',
      securitytrails_key: '',
    }
  );

  // 获取当前 API 配置
  const { data: configData, refetch: refetchConfig } = useQuery({
    queryKey: ['thirdparty-config'],
    queryFn: settingsApi.getThirdPartyConfig,
  });

  // 获取已配置的数据源
  const { data: sourcesData, refetch: refetchSources } = useQuery({
    queryKey: ['thirdparty-sources'],
    queryFn: settingsApi.getConfiguredSources,
  });

  const configuredSources = sourcesData?.data?.sources || [];

  // 更新 API 配置
  const updateConfigMutation = useMutation({
    mutationFn: settingsApi.updateThirdPartyConfig,
    onSuccess: () => {
      toast({ title: 'API 配置更新成功' });
      refetchConfig();
      refetchSources();
      // 清空输入的密钥（保留 email）
      setApiConfigForm((prev) => ({
        ...prev,
        fofa_key: '',
        hunter_key: '',
        quake_key: '',
        securitytrails_key: '',
      }));
    },
    onError: () => {
      toast({ title: 'API 配置更新失败', variant: 'destructive' });
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: authApi.changePassword,
    onSuccess: () => {
      toast({ title: '密码修改成功' });
      setPasswordForm({
        oldPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
    },
    onError: () => {
      toast({ title: '密码修改失败', variant: 'destructive' });
    },
  });

  const handleChangePassword = () => {
    if (!passwordForm.oldPassword || !passwordForm.newPassword) {
      toast({ title: '请填写完整', variant: 'destructive' });
      return;
    }
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast({ title: '两次密码不一致', variant: 'destructive' });
      return;
    }
    changePasswordMutation.mutate({
      oldPassword: passwordForm.oldPassword,
      newPassword: passwordForm.newPassword,
    });
  };

  const handleSaveApiConfig = () => {
    // 只提交非空字段
    const configToUpdate: Partial<ThirdPartyConfig> = {};
    if (apiConfigForm.fofa_email)
      configToUpdate.fofa_email = apiConfigForm.fofa_email;
    if (apiConfigForm.fofa_key)
      configToUpdate.fofa_key = apiConfigForm.fofa_key;
    if (apiConfigForm.hunter_key)
      configToUpdate.hunter_key = apiConfigForm.hunter_key;
    if (apiConfigForm.quake_key)
      configToUpdate.quake_key = apiConfigForm.quake_key;
    if (apiConfigForm.securitytrails_key)
      configToUpdate.securitytrails_key = apiConfigForm.securitytrails_key;

    if (Object.keys(configToUpdate).length === 0) {
      toast({ title: '请填写至少一个配置项', variant: 'destructive' });
      return;
    }

    updateConfigMutation.mutate(configToUpdate);
  };

  // 检查某个来源是否已配置
  const isSourceConfigured = (source: string) =>
    configuredSources.includes(source);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">系统设置</h1>

      <Tabs defaultValue="appearance" className="w-full">
        <TabsList className="grid w-full grid-cols-4 lg:w-[520px]">
          <TabsTrigger value="appearance" className="flex items-center gap-2">
            <Palette className="h-4 w-4" />
            外观设置
          </TabsTrigger>
          <TabsTrigger value="profile" className="flex items-center gap-2">
            <User className="h-4 w-4" />
            个人信息
          </TabsTrigger>
          <TabsTrigger value="password" className="flex items-center gap-2">
            <Lock className="h-4 w-4" />
            修改密码
          </TabsTrigger>
          <TabsTrigger value="api" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            API配置
          </TabsTrigger>
        </TabsList>

        {/* 外观设置 */}
        <TabsContent value="appearance" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>外观设置</CardTitle>
              <CardDescription>自定义界面主题</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Label>主题模式</Label>
                <div className="flex gap-2">
                  <Button
                    variant={theme === 'light' ? 'default' : 'outline'}
                    className="flex-1"
                    onClick={() => setTheme('light')}
                  >
                    <Sun className="h-4 w-4 mr-2" />
                    浅色
                  </Button>
                  <Button
                    variant={theme === 'dark' ? 'default' : 'outline'}
                    className="flex-1"
                    onClick={() => setTheme('dark')}
                  >
                    <Moon className="h-4 w-4 mr-2" />
                    深色
                  </Button>
                  <Button
                    variant={theme === 'system' ? 'default' : 'outline'}
                    className="flex-1"
                    onClick={() => setTheme('system')}
                  >
                    <Monitor className="h-4 w-4 mr-2" />
                    跟随系统
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 个人信息 */}
        <TabsContent value="profile" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>个人信息</CardTitle>
              <CardDescription>更新您的个人资料</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>用户名</Label>
                <Input value={user?.username || ''} disabled />
              </div>
              <div className="space-y-2">
                <Label>昵称</Label>
                <Input
                  value={profileForm.nickname}
                  onChange={(e) =>
                    setProfileForm({ ...profileForm, nickname: e.target.value })
                  }
                  placeholder="昵称"
                />
              </div>
              <div className="space-y-2">
                <Label>邮箱</Label>
                <Input
                  type="email"
                  value={profileForm.email}
                  onChange={(e) =>
                    setProfileForm({ ...profileForm, email: e.target.value })
                  }
                  placeholder="邮箱"
                />
              </div>
              <Button>保存修改</Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 修改密码 */}
        <TabsContent value="password" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>修改密码</CardTitle>
              <CardDescription>更新您的登录密码</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>当前密码</Label>
                <Input
                  type="password"
                  value={passwordForm.oldPassword}
                  onChange={(e) =>
                    setPasswordForm({
                      ...passwordForm,
                      oldPassword: e.target.value,
                    })
                  }
                  placeholder="当前密码"
                />
              </div>
              <div className="space-y-2">
                <Label>新密码</Label>
                <Input
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(e) =>
                    setPasswordForm({
                      ...passwordForm,
                      newPassword: e.target.value,
                    })
                  }
                  placeholder="新密码"
                />
              </div>
              <div className="space-y-2">
                <Label>确认新密码</Label>
                <Input
                  type="password"
                  value={passwordForm.confirmPassword}
                  onChange={(e) =>
                    setPasswordForm({
                      ...passwordForm,
                      confirmPassword: e.target.value,
                    })
                  }
                  placeholder="确认新密码"
                />
              </div>
              <Button
                onClick={handleChangePassword}
                disabled={changePasswordMutation.isPending}
              >
                修改密码
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API 配置 */}
        <TabsContent value="api" className="mt-6">
          <div className="grid gap-6 lg:grid-cols-2">
            {/* FOFA */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      FOFA
                      {isSourceConfigured('fofa') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>
                      配置 FOFA 网络空间搜索引擎 API
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Email</Label>
                  <Input
                    value={apiConfigForm.fofa_email}
                    onChange={(e) =>
                      setApiConfigForm({
                        ...apiConfigForm,
                        fofa_email: e.target.value,
                      })
                    }
                    placeholder={
                      configData?.data?.config?.fofa_email ||
                      '输入 FOFA 账号邮箱'
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.fofa_key}
                    onChange={(e) =>
                      setApiConfigForm({
                        ...apiConfigForm,
                        fofa_key: e.target.value,
                      })
                    }
                    placeholder={
                      configData?.data?.config?.fofa_key || '输入 FOFA API Key'
                    }
                  />
                </div>
              </CardContent>
            </Card>

            {/* Hunter */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      Hunter (鹰图)
                      {isSourceConfigured('hunter') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>配置鹰图平台 API</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.hunter_key}
                    onChange={(e) =>
                      setApiConfigForm({
                        ...apiConfigForm,
                        hunter_key: e.target.value,
                      })
                    }
                    placeholder={
                      configData?.data?.config?.hunter_key ||
                      '输入 Hunter API Key'
                    }
                  />
                </div>
              </CardContent>
            </Card>

            {/* Quake */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      Quake (360)
                      {isSourceConfigured('quake') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>
                      配置 360 Quake 网络空间搜索引擎 API
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.quake_key}
                    onChange={(e) =>
                      setApiConfigForm({
                        ...apiConfigForm,
                        quake_key: e.target.value,
                      })
                    }
                    placeholder={
                      configData?.data?.config?.quake_key ||
                      '输入 Quake API Key'
                    }
                  />
                </div>
              </CardContent>
            </Card>

            {/* SecurityTrails */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      SecurityTrails
                      {isSourceConfigured('securitytrails') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>
                      配置 SecurityTrails DNS 数据 API
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.securitytrails_key}
                    onChange={(e) =>
                      setApiConfigForm({
                        ...apiConfigForm,
                        securitytrails_key: e.target.value,
                      })
                    }
                    placeholder={
                      configData?.data?.config?.securitytrails_key ||
                      '输入 SecurityTrails API Key'
                    }
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="mt-6 flex justify-end">
            <Button
              onClick={handleSaveApiConfig}
              disabled={updateConfigMutation.isPending}
            >
              保存 API 配置
            </Button>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
