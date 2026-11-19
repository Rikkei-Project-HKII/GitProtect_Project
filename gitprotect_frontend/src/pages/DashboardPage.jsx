import React, { useEffect, useState } from 'react';
import { AlertCircle, RefreshCw, GitBranch, Bell, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { dashboardApi } from '../api/dashboardApi';
import KpiCards from '../components/dashboard/KpiCards';
import LeakTrendChart from '../components/dashboard/LeakTrendChart';
import RepoRiskTable from '../components/dashboard/RepoRiskTable';
import LoadingSpinner from '../components/common/LoadingSpinner';

export default function DashboardPage() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadData = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await dashboardApi.getMetrics();
      setMetrics(data);
    } catch (err) {
      setError(err.message || 'Không thể tải số liệu thống kê Dashboard.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <main className="p-4 sm:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-slate-900">
              Dashboard Giám sát An toàn Đa Kho lưu trữ
            </h1>
            <span className="text-xs px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-medium">
              [PBI-09 / T05DB2C]
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Tổng hợp chỉ số KPI 4 mức độ nghiêm trọng, biểu đồ xu hướng và đánh giá điểm rủi ro an ninh theo thời gian thực.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 disabled:opacity-50 transition shadow-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Làm mới
          </button>
          <Link
            to="/repos"
            className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-700 transition shadow-sm"
          >
            <GitBranch className="w-4 h-4" />
            Kết nối Repo
          </Link>
          <Link
            to="/alerts"
            className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition shadow-sm"
          >
            <Bell className="w-4 h-4" />
            Xem Cảnh báo
          </Link>
        </div>
      </div>

      {/* Thông báo lỗi nếu có */}
      {error && (
        <div className="flex items-center gap-2.5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0 text-red-600" />
          <span>{error}</span>
        </div>
      )}

      {/* 4 Thẻ KPI Phân loại Severity (S2-09b) */}
      {loading ? (
        <LoadingSpinner label="Đang tải chỉ số KPI bảo mật..." />
      ) : (
        <KpiCards metrics={metrics} />
      )}

      {/* Biểu đồ Xu hướng rò rỉ Chart.js & Bảng điểm rủi ro RepoRiskTable */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <LeakTrendChart />
        <RepoRiskTable />
      </div>
    </main>
  );
}
