import { Outlet } from 'react-router-dom';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import { useAppStore } from '@/store/app';
import { cn } from '@/lib/utils';

export default function MainLayout() {
  const { sidebarCollapsed } = useAppStore();

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Sidebar />
      <div
        className={cn(
          'transition-all duration-300 flex-1 flex flex-col',
          sidebarCollapsed ? 'ml-16' : 'ml-64'
        )}
      >
        <Header />
        <main className="p-6 flex-1">
          <Outlet />
        </main>
        <footer className="border-t py-4 px-6">
          <p className="text-xs text-muted-foreground text-center">
            作者: SantaVp3 · 团队: NoSafe
          </p>
        </footer>
      </div>
    </div>
  );
}
