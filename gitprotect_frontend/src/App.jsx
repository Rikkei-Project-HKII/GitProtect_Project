import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Sidebar from './components/common/Sidebar';
import Navbar from './components/common/Navbar';
import DashboardPage from './pages/DashboardPage';
import RepositoriesPage from './pages/RepositoriesPage';
import AlertsPage from './pages/AlertsPage';
import DemoPage from './pages/DemoPage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-50 flex">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <Navbar />
          {import.meta.env.VITE_DEMO_MODE === 'true' && <div className="border-b border-amber-200 bg-amber-50 px-6 py-2 text-xs text-amber-900">DEMO · Dữ liệu GitHub mô phỏng · Không nhập PAT thật · Dữ liệu được tạo lại khi khởi động</div>}
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/repos" element={<RepositoriesPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            {import.meta.env.VITE_DEMO_MODE === 'true' && <Route path="/demo" element={<DemoPage />} />}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}
