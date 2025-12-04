import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { cruiseApi, CruiseTask, CruiseLog } from '@/api/cruise';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { formatDate } from '@/lib/utils';
import {
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  ExternalLink,
} from 'lucide-react';
import { Link } from 'react-router-dom';

interface CruiseLogsDialogProps {
  cruise: CruiseTask;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function CruiseLogsDialog({
  cruise,
  open,
  onOpenChange,
}: CruiseLogsDialogProps) {
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['cruiseLogs', cruise.id, page],
    queryFn: () => cruiseApi.getCruiseLogs(cruise.id, { page, pageSize: 10 }),
    enabled: open,
  });

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
      case 'running':
        return (
          <Badge className="bg-blue-500">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            执行中
          </Badge>
        );
      case 'timeout':
        return (
          <Badge variant="secondary">
            <Clock className="h-3 w-3 mr-1" />
            超时
          </Badge>
        );
      case 'cancelled':
        return <Badge variant="secondary">已取消</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}分${seconds % 60}秒`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}时${mins}分`;
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>执行日志 - {cruise.name}</DialogTitle>
        </DialogHeader>

        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>开始时间</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>耗时</TableHead>
                <TableHead>发现资产</TableHead>
                <TableHead>发现漏洞</TableHead>
                <TableHead>错误信息</TableHead>
                <TableHead>关联任务</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : data?.items?.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={7}
                    className="text-center py-8 text-muted-foreground"
                  >
                    暂无执行记录
                  </TableCell>
                </TableRow>
              ) : (
                data?.items?.map((log: CruiseLog) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-sm">
                      {formatDate(log.start_time)}
                    </TableCell>
                    <TableCell>{getStatusBadge(log.status)}</TableCell>
                    <TableCell className="text-sm">
                      {log.duration > 0 ? formatDuration(log.duration) : '-'}
                    </TableCell>
                    <TableCell>{log.result_count}</TableCell>
                    <TableCell>
                      {log.vuln_count > 0 ? (
                        <span className="text-red-500 font-medium">
                          {log.vuln_count}
                        </span>
                      ) : (
                        0
                      )}
                    </TableCell>
                    <TableCell className="max-w-[200px]">
                      {log.error ? (
                        <span
                          className="text-red-500 text-sm truncate block"
                          title={log.error}
                        >
                          {log.error}
                        </span>
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    <TableCell>
                      {log.task_id &&
                      log.task_id !== '000000000000000000000000' ? (
                        <Link
                          to={`/tasks/${log.task_id}`}
                          className="text-blue-500 hover:underline inline-flex items-center"
                        >
                          查看
                          <ExternalLink className="h-3 w-3 ml-1" />
                        </Link>
                      ) : (
                        '-'
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* 分页 */}
        {data && data.total > 10 && (
          <div className="flex items-center justify-between mt-4">
            <div className="text-sm text-muted-foreground">
              共 {data.total} 条记录
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
              >
                上一页
              </Button>
              <span className="text-sm">第 {page} 页</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => p + 1)}
                disabled={page * 10 >= data.total}
              >
                下一页
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
