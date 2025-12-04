import { Link, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { useAppStore } from '@/store/app';
import {
  LayoutDashboard,
  ListTodo,
  Shield,
  FileCode,
  HardDrive,
  Puzzle,
  Users,
  Settings,
  ChevronLeft,
  Moon,
  Bell,
  Layers,
  Calendar,
  Network,
} from 'lucide-react';
import { Button } from '@/components/ui/button';

const menuItems = [
  { path: '/dashboard', icon: LayoutDashboard, label: '仪表盘' },
  { path: '/topology', icon: Network, label: '资产星图' },
  { path: '/tasks', icon: ListTodo, label: '任务管理' },
  { path: '/cruise', icon: Calendar, label: '自动巡航' },
  { path: '/vulnerabilities', icon: Shield, label: '漏洞管理' },
  { path: '/pocs', icon: FileCode, label: 'POC管理' },
  { path: '/queue', icon: Layers, label: '任务队列' },
  { path: '/nodes', icon: HardDrive, label: '节点管理' },
  { path: '/plugins', icon: Puzzle, label: '插件管理' },
  { path: '/notify', icon: Bell, label: '通知管理' },
  { path: '/users', icon: Users, label: '用户管理' },
  { path: '/settings', icon: Settings, label: '系统设置' },
];

export default function Sidebar() {
  const location = useLocation();
  const { sidebarCollapsed, toggleSidebar } = useAppStore();

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 h-screen bg-card border-r transition-all duration-300',
        sidebarCollapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="h-16 flex items-center justify-between px-4 border-b">
        {!sidebarCollapsed && (
          <div className="flex items-center gap-2">
            <Moon className="h-6 w-6 text-primary" />
            <span className="font-bold text-lg">望月塔</span>
          </div>
        )}
        {sidebarCollapsed && <Moon className="h-6 w-6 text-primary mx-auto" />}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          className={cn('h-8 w-8', sidebarCollapsed && 'mx-auto')}
        >
          <ChevronLeft
            className={cn(
              'h-4 w-4 transition-transform',
              sidebarCollapsed && 'rotate-180'
            )}
          />
        </Button>
      </div>

      {/* Navigation */}
      <nav className="p-2 space-y-1">
        {menuItems.map((item) => {
          const isActive = location.pathname.startsWith(item.path);
          return (
            <Link
              key={item.path}
              to={item.path}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-md transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-muted',
                sidebarCollapsed && 'justify-center'
              )}
              title={sidebarCollapsed ? item.label : undefined}
            >
              <item.icon className="h-5 w-5 flex-shrink-0" />
              {!sidebarCollapsed && (
                <span className="truncate">{item.label}</span>
              )}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
