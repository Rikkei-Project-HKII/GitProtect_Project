import { useEffect, useState } from 'react';
import { getAlerts } from '../../api/dashboard';
import { SEV_COLORS } from './DashboardCharts';

const PAGE_SIZE = 50;
const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];
const STATUS_OPTIONS = ['open', 'in_review', 'resolved', 'false_positive', 'ignored'];
const SOURCE_OPTIONS = [
  { value: 'gitprotect_scanner', label: 'GitProtect Scanner' },
  { value: 'github_native', label: 'GitHub Native' },
];

export default function AlertList({ repos, onSelect }) {
  const [filters, setFilters] = useState({ repo_id: '', severity: '', status: '', source: '' });
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    getAlerts({ ...filters, page, page_size: PAGE_SIZE })
      .then(setData)
      .catch(() => setData({ items: [], total: 0 }))
      .finally(() => setLoading(false));
  }, [filters, page]);

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  const set = (k) => (e) => { setPage(1); setFilters((f) => ({ ...f, [k]: e.target.value })); };
  const repoName = (id) => repos.find((r) => r.repo_id === id)?.repo_name ?? `#${id}`;

  const Select = ({ k, label, options }) => (
    <select className="rounded border px-2 py-1 text-sm" value={filters[k]} onChange={set(k)}>
      <option value="">{label}</option>
      {options.map((o) => <option key={o.value ?? o} value={o.value ?? o}>{o.label ?? o}</option>)}
    </select>
  );

  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <div className="mb-3 flex flex-wrap gap-2">
        <Select k="repo_id" label="Mọi kho" options={repos.map((r) => ({ value: r.repo_id, label: r.repo_name }))} />
        <Select k="severity" label="Mọi mức độ" options={SEVERITY_OPTIONS} />
        <Select k="status" label="Mọi trạng thái" options={STATUS_OPTIONS} />
        {SOURCE_OPTIONS.length > 0 && <Select k="source" label="Mọi nguồn" options={SOURCE_OPTIONS} />}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-gray-500">
              <th className="p-2">#</th><th className="p-2">Kho</th><th className="p-2">Mức độ</th>
              <th className="p-2">Trạng thái</th><th className="p-2">Rule</th><th className="p-2">File</th><th className="p-2">Phát hiện</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((a) => (
              <tr key={a.id} className="cursor-pointer border-b hover:bg-gray-50" onClick={() => onSelect(a.id)}>
                <td className="p-2">{a.id}</td>
                <td className="p-2">{repoName(a.repo_id)}</td>
                <td className="p-2">
                  <span className="rounded-full px-2 py-0.5 text-xs text-white" style={{ background: SEV_COLORS[a.severity] }}>{a.severity}</span>
                </td>
                <td className="p-2">{a.status}</td>
                <td className="p-2">{a.rule_name}</td>
                <td className="p-2 font-mono text-xs">{a.file_path}</td>
                <td className="p-2">{new Date(a.detected_at).toLocaleString('vi-VN')}</td>
              </tr>
            ))}
            {!loading && data.items.length === 0 && (
              <tr><td colSpan={7} className="p-4 text-center text-gray-400">Không có cảnh báo</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex items-center justify-end gap-3 text-sm">
        <button className="rounded border px-3 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>‹</button>
        <span>Trang {page}/{totalPages} · {data.total} cảnh báo</span>
        <button className="rounded border px-3 py-1 disabled:opacity-40" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>›</button>
      </div>
    </div>
  );
}