import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { pocApi, POC, CreatePOCRequest } from '@/api/pocs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/components/ui/use-toast';
import { cn, formatDate, getSeverityColor } from '@/lib/utils';
import {
  Search,
  Plus,
  Eye,
  Upload,
  RefreshCw,
  Trash2,
  FileArchive,
  FileText,
  ChevronDown,
} from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';

export default function POCsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selectedPOC, setSelectedPOC] = useState<POC | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [newPOC, setNewPOC] = useState<CreatePOCRequest>({
    name: '',
    type: 'custom',
    severity: 'medium',
    description: '',
    content: '',
    cveId: '',
    tags: [],
    author: '',
    enabled: true,
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['pocs', page, search],
    queryFn: () =>
      pocApi.list({
        page,
        pageSize: 10,
        search,
      }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      pocApi.toggleEnabled(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pocs'] });
    },
  });

  const createMutation = useMutation({
    mutationFn: pocApi.create,
    onSuccess: () => {
      toast({ title: 'POC 创建成功' });
      setIsCreateDialogOpen(false);
      setNewPOC({
        name: '',
        type: 'custom',
        severity: 'medium',
        description: '',
        content: '',
        cveId: '',
        tags: [],
        author: '',
        enabled: true,
      });
      queryClient.invalidateQueries({ queryKey: ['pocs'] });
      refetch();
    },
    onError: () => {
      toast({ title: 'POC 创建失败', variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: pocApi.delete,
    onSuccess: () => {
      toast({ title: '删除成功' });
      queryClient.invalidateQueries({ queryKey: ['pocs'] });
    },
  });

  const batchDeleteMutation = useMutation({
    mutationFn: pocApi.batchDelete,
    onSuccess: (response) => {
      const result = response.data || response;
      toast({
        title: '批量删除完成',
        description: `成功删除 ${result.deleted} 个，失败 ${result.failed} 个`,
      });
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['pocs'] });
    },
    onError: () => {
      toast({ title: '批量删除失败', variant: 'destructive' });
    },
  });

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(pocs.map((p) => p.id));
    } else {
      setSelectedIds([]);
    }
  };

  const handleSelectOne = (id: string, checked: boolean) => {
    if (checked) {
      setSelectedIds((prev) => [...prev, id]);
    } else {
      setSelectedIds((prev) => prev.filter((i) => i !== id));
    }
  };

  const handleBatchDelete = () => {
    if (selectedIds.length === 0) {
      toast({ title: '请先选择要删除的POC', variant: 'destructive' });
      return;
    }
    if (confirm(`确定要删除选中的 ${selectedIds.length} 个POC吗？`)) {
      batchDeleteMutation.mutate(selectedIds);
    }
  };

  const clearAllMutation = useMutation({
    mutationFn: pocApi.clearAll,
    onSuccess: (response) => {
      const result = response.data || response;
      toast({
        title: '清除完成',
        description: `已删除 ${result.deleted} 个POC`,
      });
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['pocs'] });
      refetch();
    },
    onError: () => {
      toast({ title: '清除失败', variant: 'destructive' });
    },
  });

  const handleClearAll = () => {
    if (total === 0) {
      toast({ title: '没有POC可清除', variant: 'destructive' });
      return;
    }
    if (confirm(`确定要清除所有 ${total} 个POC吗？此操作不可恢复！`)) {
      clearAllMutation.mutate();
    }
  };

  const handleCreate = () => {
    if (!newPOC.name || !newPOC.content) {
      toast({ title: '请填写名称和内容', variant: 'destructive' });
      return;
    }
    createMutation.mutate(newPOC);
  };

  const handleImport = () => {
    fileInputRef.current?.click();
  };

  const handleZipImport = () => {
    zipInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;

      // 尝试解析 Nuclei YAML 模板
      const parsedPOC = parseNucleiTemplate(content, file.name);

      setNewPOC(parsedPOC);
      setIsCreateDialogOpen(true);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  // 提取多行描述的辅助函数
  const parseMultilineYaml = (lines: string[], startIndex: number): string => {
    let result = '';
    for (let j = startIndex + 1; j < lines.length; j++) {
      const nextLine = lines[j];
      if (nextLine.match(/^\s{2,}/) || nextLine.trim() === '') {
        result += nextLine.trim() + ' ';
      } else {
        break;
      }
    }
    return result;
  };

  // 提取CVE-ID数组的辅助函数
  const parseCveIdArray = (lines: string[], startIndex: number): string[] => {
    const result: string[] = [];
    for (
      let j = startIndex + 1;
      j < Math.min(startIndex + 5, lines.length);
      j++
    ) {
      const line = lines[j].trim();
      if (line.startsWith('-')) {
        result.push(line.replace(/^-\s*/, '').replace(/['"]/g, ''));
      } else if (!line.startsWith('#')) {
        break;
      }
    }
    return result;
  };

  // 解析 Nuclei 模板 YAML
  const parseNucleiTemplate = (
    content: string,
    filename: string
  ): CreatePOCRequest => {
    const result: CreatePOCRequest = {
      name: filename.replace(/\.(yaml|yml|json)$/, ''),
      type: 'nuclei',
      severity: 'medium',
      description: '',
      content: content,
      cveId: '',
      tags: [],
      author: '',
      enabled: true,
    };

    try {
      // 简单解析 YAML（不使用库，手动匹配关键字段）
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // 解析 id
        if (line.startsWith('id:')) {
          const id = line.replace('id:', '').trim().replace(/['"]/g, '');
          result.name = id;
        }

        // 解析 name
        if (line.startsWith('name:')) {
          const name = line.replace('name:', '').trim().replace(/['"]/g, '');
          if (name) result.name = name;
        }

        // 解析 author
        if (line.startsWith('author:')) {
          result.author = line
            .replace('author:', '')
            .trim()
            .replace(/['"]/g, '');
        }

        // 解析 severity
        if (line.startsWith('severity:')) {
          const severity = line
            .replace('severity:', '')
            .trim()
            .toLowerCase()
            .replace(/['"]/g, '');
          if (
            ['critical', 'high', 'medium', 'low', 'info'].includes(severity)
          ) {
            result.severity = severity;
          }
        }

        // 解析 description
        if (line.startsWith('description:')) {
          let desc = line.replace('description:', '').trim();
          // 处理多行描述
          if (desc === '|' || desc === '>') {
            desc = parseMultilineYaml(lines, i);
          }
          result.description = desc.replace(/['"]/g, '').trim();
        }

        // 解析 tags
        if (line.startsWith('tags:')) {
          const tagsStr = line.replace('tags:', '').trim().replace(/['"]/g, '');
          if (tagsStr) {
            result.tags = tagsStr
              .split(',')
              .map((t) => t.trim())
              .filter(Boolean);
          }
        }

        // 解析 cve-id
        if (line.includes('cve-id:') || line.includes('cveid:')) {
          // 可能是数组格式
          const cveArray = parseCveIdArray(lines, i);
          if (cveArray.length > 0) {
            result.cveId = cveArray[0];
          } else {
            const cveMatch = line.match(/CVE-\d{4}-\d+/i);
            if (cveMatch) {
              result.cveId = cveMatch[0].toUpperCase();
            }
          }
        }
      }

      // 如果在 content 中找到 CVE 但没解析到，尝试全文搜索
      if (!result.cveId) {
        const cveMatch = content.match(/CVE-\d{4}-\d+/i);
        if (cveMatch) {
          result.cveId = cveMatch[0].toUpperCase();
        }
      }
    } catch (error) {
      console.error('Failed to parse YAML:', error);
    }

    return result;
  };

  const handleZipFileChange = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.zip')) {
      toast({ title: '请选择 ZIP 文件', variant: 'destructive' });
      return;
    }

    setIsImporting(true);
    try {
      const response = await pocApi.importZip(file);
      // 兼容两种响应格式
      const result = response.data || response;
      const imported = result.imported ?? 0;
      const failed = result.failed ?? 0;
      const skipped = result.skipped ?? 0;

      toast({
        title: 'ZIP 导入完成',
        description: `成功导入 ${imported} 个POC，失败 ${failed} 个，跳过 ${skipped} 个`,
      });
      // 强制刷新列表
      await queryClient.invalidateQueries({ queryKey: ['pocs'] });
      refetch();
    } catch (error) {
      toast({ title: '导入失败', variant: 'destructive' });
    } finally {
      setIsImporting(false);
      e.target.value = '';
    }
  };

  const pocs = data?.data?.list || [];
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

  return (
    <div className="space-y-6">
      {/* Hidden file input for single file import */}
      <input
        type="file"
        ref={fileInputRef}
        className="hidden"
        accept=".yaml,.yml,.json"
        onChange={handleFileChange}
      />
      {/* Hidden file input for ZIP import */}
      <input
        type="file"
        ref={zipInputRef}
        className="hidden"
        accept=".zip"
        onChange={handleZipFileChange}
      />

      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">POC管理</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" disabled={isImporting}>
                <Upload className="h-4 w-4 mr-2" />
                {isImporting ? '导入中...' : '导入'}
                <ChevronDown className="h-4 w-4 ml-2" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  handleImport();
                }}
              >
                <FileText className="h-4 w-4 mr-2" />
                导入单个文件 (YAML/JSON)
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  handleZipImport();
                }}
              >
                <FileArchive className="h-4 w-4 mr-2" />
                批量导入 (ZIP包)
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button size="sm" onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            新建POC
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleClearAll}
            disabled={clearAllMutation.isPending || total === 0}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            {clearAllMutation.isPending ? '清除中...' : '清除所有'}
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4 items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="搜索POC..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        {selectedIds.length > 0 && (
          <Button
            variant="destructive"
            size="sm"
            onClick={handleBatchDelete}
            disabled={batchDeleteMutation.isPending}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            删除选中 ({selectedIds.length})
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">
                <Checkbox
                  checked={
                    pocs.length > 0 && selectedIds.length === pocs.length
                  }
                  onCheckedChange={handleSelectAll}
                />
              </TableHead>
              <TableHead>名称</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>严重程度</TableHead>
              <TableHead>CVE</TableHead>
              <TableHead>标签</TableHead>
              <TableHead>启用</TableHead>
              <TableHead>更新时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8">
                  加载中...
                </TableCell>
              </TableRow>
            ) : pocs.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={9}
                  className="text-center py-8 text-muted-foreground"
                >
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              pocs.map((poc) => (
                <TableRow key={poc.id}>
                  <TableCell>
                    <Checkbox
                      checked={selectedIds.includes(poc.id)}
                      onCheckedChange={(checked) =>
                        handleSelectOne(poc.id, !!checked)
                      }
                    />
                  </TableCell>
                  <TableCell className="font-medium max-w-xs truncate">
                    {poc.name}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{poc.type}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={cn(getSeverityColor(poc.severity))}>
                      {getSeverityLabel(poc.severity)}
                    </Badge>
                  </TableCell>
                  <TableCell>{poc.cveId || '-'}</TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap max-w-32">
                      {poc.tags?.slice(0, 2).map((tag) => (
                        <Badge
                          key={tag}
                          variant="secondary"
                          className="text-xs"
                        >
                          {tag}
                        </Badge>
                      ))}
                      {poc.tags && poc.tags.length > 2 && (
                        <Badge variant="secondary" className="text-xs">
                          +{poc.tags.length - 2}
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={poc.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: poc.id, enabled: checked })
                      }
                    />
                  </TableCell>
                  <TableCell>{formatDate(poc.updatedAt)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setSelectedPOC(poc)}
                      >
                        <Eye className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => deleteMutation.mutate(poc.id)}
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

      {/* POC Detail Dialog */}
      <Dialog open={!!selectedPOC} onOpenChange={() => setSelectedPOC(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>{selectedPOC?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">类型</p>
                <p className="font-medium">{selectedPOC?.type}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">CVE</p>
                <p className="font-medium">{selectedPOC?.cveId || '-'}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">作者</p>
                <p className="font-medium">{selectedPOC?.author || '-'}</p>
              </div>
            </div>
            {selectedPOC?.description && (
              <div>
                <p className="text-sm text-muted-foreground mb-1">描述</p>
                <p className="text-sm">{selectedPOC.description}</p>
              </div>
            )}
            {selectedPOC?.tags && selectedPOC.tags.length > 0 && (
              <div>
                <p className="text-sm text-muted-foreground mb-1">标签</p>
                <div className="flex gap-1 flex-wrap">
                  {selectedPOC.tags.map((tag) => (
                    <Badge key={tag} variant="outline">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            <div>
              <p className="text-sm text-muted-foreground mb-1">代码</p>
              <Textarea
                value={selectedPOC?.content || ''}
                readOnly
                className="font-mono text-sm h-64"
              />
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Create POC Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>新建 POC</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>名称 *</Label>
                <Input
                  value={newPOC.name}
                  onChange={(e) =>
                    setNewPOC({ ...newPOC, name: e.target.value })
                  }
                  placeholder="POC 名称"
                />
              </div>
              <div className="space-y-2">
                <Label>类型</Label>
                <Select
                  value={newPOC.type}
                  onValueChange={(v) => setNewPOC({ ...newPOC, type: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="nuclei">Nuclei</SelectItem>
                    <SelectItem value="xray">Xray</SelectItem>
                    <SelectItem value="custom">自定义</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>严重程度</Label>
                <Select
                  value={newPOC.severity}
                  onValueChange={(v) => setNewPOC({ ...newPOC, severity: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">严重</SelectItem>
                    <SelectItem value="high">高危</SelectItem>
                    <SelectItem value="medium">中危</SelectItem>
                    <SelectItem value="low">低危</SelectItem>
                    <SelectItem value="info">信息</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>CVE ID</Label>
                <Input
                  value={newPOC.cveId}
                  onChange={(e) =>
                    setNewPOC({ ...newPOC, cveId: e.target.value })
                  }
                  placeholder="CVE-XXXX-XXXX"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>描述</Label>
              <Input
                value={newPOC.description}
                onChange={(e) =>
                  setNewPOC({ ...newPOC, description: e.target.value })
                }
                placeholder="POC 描述"
              />
            </div>
            <div className="space-y-2">
              <Label>标签 (逗号分隔)</Label>
              <Input
                value={newPOC.tags?.join(', ')}
                onChange={(e) =>
                  setNewPOC({
                    ...newPOC,
                    tags: e.target.value
                      .split(',')
                      .map((t) => t.trim())
                      .filter(Boolean),
                  })
                }
                placeholder="web, rce, sql"
              />
            </div>
            <div className="space-y-2">
              <Label>POC 内容 *</Label>
              <Textarea
                value={newPOC.content}
                onChange={(e) =>
                  setNewPOC({ ...newPOC, content: e.target.value })
                }
                placeholder="POC YAML/JSON 内容"
                className="font-mono text-sm h-64"
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
