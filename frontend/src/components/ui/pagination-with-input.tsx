import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';

interface PaginationWithInputProps {
  page: number;
  totalPages: number;
  total: number;
  pageSize?: number;
  onPageChange: (page: number) => void;
  showTotal?: boolean;
  className?: string;
}

export function PaginationWithInput({
  page,
  totalPages,
  total,
  onPageChange,
  showTotal = true,
  className = '',
}: PaginationWithInputProps) {
  const [inputValue, setInputValue] = useState('');

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    setInputValue(value);
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleGoToPage();
    }
  };

  const handleGoToPage = () => {
    const pageNum = parseInt(inputValue, 10);
    if (!isNaN(pageNum) && pageNum >= 1 && pageNum <= totalPages) {
      onPageChange(pageNum);
      setInputValue('');
    }
  };

  const goToFirst = () => onPageChange(1);
  const goToPrev = () => onPageChange(Math.max(1, page - 1));
  const goToNext = () => onPageChange(Math.min(totalPages, page + 1));
  const goToLast = () => onPageChange(totalPages);

  if (totalPages <= 1) {
    return showTotal ? (
      <div className={`text-sm text-muted-foreground ${className}`}>
        共 <span className="font-medium text-foreground">{total}</span> 条结果
      </div>
    ) : null;
  }

  return (
    <div className={`flex items-center justify-between ${className}`}>
      {showTotal && (
        <span className="text-sm text-muted-foreground">
          共 <span className="font-medium text-foreground">{total}</span> 条结果
        </span>
      )}
      <div className="flex items-center gap-1">
        {/* 首页 */}
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8"
          disabled={page === 1}
          onClick={goToFirst}
          title="首页"
        >
          <ChevronsLeft className="h-4 w-4" />
        </Button>

        {/* 上一页 */}
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8"
          disabled={page === 1}
          onClick={goToPrev}
          title="上一页"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>

        {/* 页码显示和输入 */}
        <div className="flex items-center gap-1 px-2">
          <span className="text-sm whitespace-nowrap">第</span>
          <Input
            type="text"
            value={inputValue}
            onChange={handleInputChange}
            onKeyDown={handleInputKeyDown}
            placeholder={String(page)}
            className="h-8 w-14 text-center px-1"
          />
          <span className="text-sm whitespace-nowrap">/ {totalPages} 页</span>
        </div>

        {/* 跳转按钮 */}
        <Button
          variant="outline"
          size="sm"
          className="h-8 px-2"
          onClick={handleGoToPage}
          disabled={!inputValue}
        >
          跳转
        </Button>

        {/* 下一页 */}
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8"
          disabled={page >= totalPages}
          onClick={goToNext}
          title="下一页"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>

        {/* 末页 */}
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8"
          disabled={page >= totalPages}
          onClick={goToLast}
          title="末页"
        >
          <ChevronsRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
