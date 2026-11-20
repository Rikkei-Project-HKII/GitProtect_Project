import { useEffect, useState } from 'react';
import { getMetrics, getRepoBreakdown } from '../api/dashboard';
import { KpiCards, TrendChart, RepoBreakdownChart } from '../components/dashboard/DashboardCharts';
import AlertList from '../components/dashboard/AlertList';
import AlertDetailModal from '../components/dashboard/AlertDetailModal';

import AuthorAuditPanel from '../components/dashboard/AuthorAuditPanel';

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
      <AuthorAuditPanel />
      <AlertList repos={repos} onSelect={setSelectedId} />
      {selectedId && <AlertDetailModal alertId={selectedId} onClose={() => setSelectedId(null)} />}
    </div>
  );
}
