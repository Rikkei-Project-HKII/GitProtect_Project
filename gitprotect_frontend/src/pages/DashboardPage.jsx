import { useEffect, useState } from 'react';
import { Download, FileText } from 'lucide-react';
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

  const handleExport = (format) => {
    const url = `/api/v1/dashboard/export?format=${format}`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `gitprotect_report.${format}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="mx-auto max-w-6xl space-y-5 p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold text-slate-900">Dashboard giám sát rò rỉ secret</h1>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => handleExport('csv')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 transition"
            data-testid="export-csv-btn"
          >
            <Download className="h-4 w-4 text-slate-500" />
            <span>Xuất CSV</span>
          </button>
          <button
            type="button"
            onClick={() => handleExport('pdf')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-transparent bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 transition"
            data-testid="export-pdf-btn"
          >
            <FileText className="h-4 w-4 text-white" />
            <span>Xuất PDF</span>
          </button>
        </div>
      </div>
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
