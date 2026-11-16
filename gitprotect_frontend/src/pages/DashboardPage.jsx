import { useEffect, useState } from 'react';
import { AlertCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { dashboardApi } from '../api/dashboardApi';
import KpiCards from '../components/dashboard/KpiCards';
import LoadingSpinner from '../components/common/LoadingSpinner';

export default function DashboardPage() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        setLoading(true);
        setError('');
        const data = await dashboardApi.getMetrics();
        if (!cancelled) setMetrics(data);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Không thể tải dashboard.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="p-4 sm:p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Dashboard hệ thống</h1>
        <p className="text-sm text-slate-500 mt-1">
          Theo dõi KPI bảo mật và chuyển tới màn hình kết nối kho lưu trữ GitHub.
        </p>
      </div>

      {error && (
        <div className="flex items-center gap-2.5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? <LoadingSpinner label="Đang tải số liệu dashboard..." /> : <KpiCards metrics={metrics} />}

      <Link
        to="/repos"
        className="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-700"
      >
        Quản lý kho lưu trữ
      </Link>
    </main>
  );
}


import { useEffect, useState } from 'react';
import { getMetrics, getRepoBreakdown } from '../api/dashboard';
import { KpiCards, TrendChart, RepoBreakdownChart } from '../components/dashboard/DashboardCharts';
import AlertList from '../components/dashboard/AlertList';
import AlertDetailModal from '../components/dashboard/AlertDetailModal';

export default function DashboardPage() {
  const [metrics, setMetrics] = useState(null);
  const [repos, setRepos] = useState([]);
  const [selectedId, setSelectedId] = useState(null);

  useEffect(() => {
    getMetrics().then(setMetrics).catch(() => {});
    getRepoBreakdown().then((d) => setRepos(d.items)).catch(() => {});
  }, []);

  return (
    <div className="mx-auto max-w-6xl space-y-5 p-5">
      <h1 className="text-2xl font-bold">Dashboard giám sát rò rỉ secret</h1>
      <KpiCards metrics={metrics} />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2"><TrendChart /></div>
        <RepoBreakdownChart items={repos} />
      </div>
      <AlertList repos={repos} onSelect={setSelectedId} />
      {selectedId && <AlertDetailModal alertId={selectedId} onClose={() => setSelectedId(null)} />}
    </div>
  );
}