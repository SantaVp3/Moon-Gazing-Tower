import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { nodeApi, Plugin } from '@/api/nodes';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
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
import { useToast } from '@/components/ui/use-toast';
import { formatDate } from '@/lib/utils';
import {
  Search,
  Plus,
  Upload,
  RefreshCw,
  Trash2,
  Settings,
} from 'lucide-react';

export default function PluginsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [newPlugin, setNewPlugin] = useState<Partial<Plugin>>({
    name: '',
    type: 'scanner',
    version: '1.0.0',
    description: '',
    author: '',
    enabled: true,
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['plugins', page, search],
    queryFn: () =>
      nodeApi.getPlugins({
        page,
        pageSize: 10,
        search,
      }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      nodeApi.togglePlugin(id, enabled),
    onSuccess: () => {
      toast({ title: '更新成功' });
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: nodeApi.deletePlugin,
    onSuccess: () => {
      toast({ title: '删除成功' });
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });

  const createMutation = useMutation({
    mutationFn: nodeApi.createPlugin,
    onSuccess: () => {
      toast({ title: '插件创建成功' });
      setIsCreateDialogOpen(false);
      setNewPlugin({
        name: '',
        type: 'scanner',
        version: '1.0.0',
        description: '',
        author: '',
        enabled: true,
      });
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
    onError: () => {
      toast({ title: '创建失败', variant: 'destructive' });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: nodeApi.uploadPlugin,
    onSuccess: () => {
      toast({ title: '插件上传成功' });
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
    onError: () => {
      toast({ title: '上传失败', variant: 'destructive' });
    },
  });

  const handleUpload = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      uploadMutation.mutate(file);
    }
    e.target.value = '';
  };

  const handleCreate = () => {
    if (!newPlugin.name) {
      toast({ title: '请填写插件名称', variant: 'destructive' });
      return;
    }
    createMutation.mutate(newPlugin);
  };

  const plugins = data?.data?.list || [];
  const total = data?.data?.total || 0;
  const totalPages = Math.ceil(total / 10);

  return (
    <div className="space-y-6">
      {/* Hidden file input */}
      <input
        type="file"
        ref={fileInputRef}
        className="hidden"
        accept=".zip,.tar.gz"
        onChange={handleFileChange}
      />

      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">插件管理</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button variant="outline" size="sm" onClick={handleUpload}>
            <Upload className="h-4 w-4 mr-2" />
            上传插件
          </Button>
          <Button size="sm" onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加插件
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="搜索插件..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>版本</TableHead>
              <TableHead>作者</TableHead>
              <TableHead>启用</TableHead>
              <TableHead>更新时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8">
                  加载中...
                </TableCell>
              </TableRow>
            ) : plugins.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={7}
                  className="text-center py-8 text-muted-foreground"
                >
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              plugins.map((plugin) => (
                <TableRow key={plugin.id}>
                  <TableCell>
                    <div>
                      <p className="font-medium">{plugin.name}</p>
                      {plugin.description && (
                        <p className="text-xs text-muted-foreground truncate max-w-xs">
                          {plugin.description}
                        </p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{plugin.type}</Badge>
                  </TableCell>
                  <TableCell>{plugin.version}</TableCell>
                  <TableCell>{plugin.author || '-'}</TableCell>
                  <TableCell>
                    <Switch
                      checked={plugin.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({
                          id: plugin.id,
                          enabled: checked,
                        })
                      }
                    />
                  </TableCell>
                  <TableCell>{formatDate(plugin.updatedAt)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="icon">
                        <Settings className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => deleteMutation.mutate(plugin.id)}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
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

      {/* Create Plugin Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>添加插件</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>插件名称 *</Label>
              <Input
                value={newPlugin.name}
                onChange={(e) =>
                  setNewPlugin({ ...newPlugin, name: e.target.value })
                }
                placeholder="插件名称"
              />
            </div>
            <div className="space-y-2">
              <Label>类型</Label>
              <Select
                value={newPlugin.type}
                onValueChange={(v) => setNewPlugin({ ...newPlugin, type: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="scanner">扫描器</SelectItem>
                  <SelectItem value="fingerprint">指纹识别</SelectItem>
                  <SelectItem value="poc">POC</SelectItem>
                  <SelectItem value="exploit">漏洞利用</SelectItem>
                  <SelectItem value="other">其他</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>版本</Label>
              <Input
                value={newPlugin.version}
                onChange={(e) =>
                  setNewPlugin({ ...newPlugin, version: e.target.value })
                }
                placeholder="1.0.0"
              />
            </div>
            <div className="space-y-2">
              <Label>作者</Label>
              <Input
                value={newPlugin.author}
                onChange={(e) =>
                  setNewPlugin({ ...newPlugin, author: e.target.value })
                }
                placeholder="作者名称"
              />
            </div>
            <div className="space-y-2">
              <Label>描述</Label>
              <Textarea
                value={newPlugin.description}
                onChange={(e) =>
                  setNewPlugin({ ...newPlugin, description: e.target.value })
                }
                placeholder="插件描述"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsCreateDialogOpen(false)}
            >
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
