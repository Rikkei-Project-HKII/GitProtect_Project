import { useEffect, useState } from 'react';
import { getRepoBreakdown } from '../api/dashboard';
import AlertList from '../components/dashboard/AlertList';
import AlertDetailModal from '../components/dashboard/AlertDetailModal';

export default function AlertsPage() {
  const [repos, setRepos] = useState([]);
  const [selectedId, setSelectedId] = useState(null);

  useEffect(() => {
    getRepoBreakdown()
      .then((d) => setRepos(d.items || []))
      .catch(() => setRepos([]));
  }, []);

  return (
    <main className="mx-auto max-w-6xl space-y-5 p-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Quản lý Cảnh báo Bảo mật</h1>
        <p className="text-sm text-slate-500 mt-1">
          Theo dõi, lọc đa tiêu chí và quản lý vòng đời cảnh báo rò rỉ bí mật.
        </p>
      </div>

      <AlertList repos={repos} onSelect={setSelectedId} />

      {selectedId && (
        <AlertDetailModal
          alertId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </main>
  );
}
