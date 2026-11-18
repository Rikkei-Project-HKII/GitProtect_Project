import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Sidebar from './components/common/Sidebar';
import Navbar from './components/common/Navbar';
import DashboardPage from './pages/DashboardPage';
import RepositoriesPage from './pages/RepositoriesPage';
import AlertsPage from './pages/AlertsPage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-50 flex">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <Navbar />
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/repos" element={<RepositoriesPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}
