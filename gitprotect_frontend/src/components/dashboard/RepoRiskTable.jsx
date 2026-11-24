import { useEffect, useState } from 'react';
import { dashboardApi } from '../../api/dashboardApi';
import { ShieldAlert, GitBranch } from 'lucide-react';

export default function RepoRiskTable() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        setLoading(true);
        const data = await dashboardApi.getRepoBreakdown();
        if (!cancelled) {
          setItems(data?.items || []);
        }
      } catch (err) {
        console.error('Không thể tải bảng rủi ro repo:', err);
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
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-purple-600" />
          <h3 className="font-semibold text-slate-800">
            Điểm số rủi ro an ninh theo Kho lưu trữ (Risk Score)
          </h3>
        </div>
        <span className="text-xs text-slate-400">
          Trọng số: Critical (10đ) • High (5đ) • Medium (2đ) • Low (1đ)
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600 uppercase tracking-wider">
              <th className="py-3 px-5">Kho lưu trữ</th>
              <th className="py-3 px-4 text-center">Critical</th>
              <th className="py-3 px-4 text-center">High</th>
              <th className="py-3 px-4 text-center">Medium</th>
              <th className="py-3 px-4 text-center">Low</th>
              <th className="py-3 px-4 text-center">Tổng</th>
              <th className="py-3 px-5 text-right">Risk Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {loading ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-xs text-slate-400">
                  Đang tính toán điểm số rủi ro...
                </td>
              </tr>
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-xs text-slate-400">
                  Chưa có kho lưu trữ nào có cảnh báo rò rỉ.
                </td>
              </tr>
            ) : (
              items.map((repo) => (
                <tr key={repo.repo_id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-3.5 px-5 font-medium text-slate-900 flex items-center gap-2">
                    <GitBranch className="w-4 h-4 text-slate-400" />
                    <span>{repo.repo_name}</span>
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-50 text-red-700">
                      {repo.critical}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-50 text-orange-700">
                      {repo.high}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-amber-50 text-amber-700">
                      {repo.medium}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-50 text-blue-700">
                      {repo.low}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-center font-semibold text-slate-700">
                    {repo.total}
                  </td>
                  <td className="py-3.5 px-5 text-right font-bold text-purple-700">
                    {repo.risk_score}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
