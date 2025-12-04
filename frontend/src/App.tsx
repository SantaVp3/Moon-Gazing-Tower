/**
 * 望月楼 - Moon Gazing Tower
 * 作者: SantaVp3
 * 团队: NoSafe
 */

import { Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from '@/components/ui/toaster';
import { useAuthStore } from '@/store/auth';
import MainLayout from '@/layouts/MainLayout';
import AuthLayout from '@/layouts/AuthLayout';
import LoginPage from '@/pages/auth/LoginPage';
import DashboardPage from '@/pages/dashboard/DashboardPage';
import TasksPage from '@/pages/tasks/TasksPage';
import TaskDetailPage from '@/pages/tasks/TaskDetailPage';
import TaskCreatePage from '@/pages/tasks/TaskCreatePage';
import VulnerabilitiesPage from '@/pages/vulnerabilities/VulnerabilitiesPage';
import VulnerabilityDetailPage from '@/pages/vulnerabilities/VulnerabilityDetailPage';
import POCsPage from '@/pages/pocs/POCsPage';
import NodesPage from '@/pages/nodes/NodesPage';
import PluginsPage from '@/pages/plugins/PluginsPage';
import UsersPage from '@/pages/users/UsersPage';
import SettingsPage from '@/pages/settings/SettingsPage';
import NotifyPage from '@/pages/notify/NotifyPage';
import MonitorPage from '@/pages/monitor/MonitorPage';
import TakeoverPage from '@/pages/takeover/TakeoverPage';
import QueuePage from '@/pages/queue/QueuePage';
import { CruisePage } from '@/pages/cruise';
import TopologyPage from '@/pages/topology/TopologyPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function App() {
  return (
    <>
      <Routes>
        {/* Auth routes */}
        <Route element={<AuthLayout />}>
          <Route path="/login" element={<LoginPage />} />
        </Route>

        {/* Protected routes */}
        <Route
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/topology" element={<TopologyPage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/tasks/new" element={<TaskCreatePage />} />
          <Route path="/tasks/:id" element={<TaskDetailPage />} />
          <Route path="/cruise" element={<CruisePage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route
            path="/vulnerabilities/:id"
            element={<VulnerabilityDetailPage />}
          />
          <Route path="/pocs" element={<POCsPage />} />
          <Route path="/takeover" element={<TakeoverPage />} />
          <Route path="/monitor" element={<MonitorPage />} />
          <Route path="/queue" element={<QueuePage />} />
          <Route path="/nodes" element={<NodesPage />} />
          <Route path="/plugins" element={<PluginsPage />} />
          <Route path="/notify" element={<NotifyPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Routes>
      <Toaster />
    </>
  );
}

export default App;
