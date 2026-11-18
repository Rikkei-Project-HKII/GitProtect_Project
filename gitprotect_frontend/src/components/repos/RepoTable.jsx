import { CheckCircle2, XCircle, Clock, GitBranch, ExternalLink, AlertTriangle } from 'lucide-react';
import { formatDateTime } from '../../utils/formatters';
import LoadingSpinner from '../common/LoadingSpinner';

export default function RepoTable({ repos, loading }) {
  if (loading) {
    return <LoadingSpinner label="Đang tải danh sách kho lưu trữ..." />;
  }

  if (!repos || repos.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-12 text-center">
        <GitBranch className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <h3 className="text-base font-medium text-slate-800">Chưa có kho lưu trữ nào được kết nối</h3>
        <p className="text-sm text-slate-500 mt-1">
          Nhấn nút <strong>&quot;Kết nối Repo mới&quot;</strong> để liên kết GitHub Repository bằng PAT.
        </p>
      </div>
    );
  }

  const renderConnectionStatus = (status, errorMsg) => {
    if (status === 'active') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
          <CheckCircle2 className="w-3.5 h-3.5" />
          Active
        </span>
      );
    }
    return (
      <div className="space-y-1">
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">
          <XCircle className="w-3.5 h-3.5" />
          Error
        </span>
        {errorMsg && (
          <p className="text-xs text-red-600 flex items-center gap-1 max-w-xs" title={errorMsg}>
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">{errorMsg}</span>
          </p>
        )}
      </div>
    );
  };

  const renderScanStatus = (scanStatus) => {
    const styles = {
      completed: 'bg-blue-50 text-blue-700 border-blue-200',
      running: 'bg-amber-50 text-amber-700 border-amber-200',
      pending: 'bg-slate-100 text-slate-600 border-slate-200',
      failed: 'bg-red-50 text-red-700 border-red-200',
    };
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-medium border ${styles[scanStatus] || styles.pending}`}>
        {scanStatus || 'pending'}
      </span>
    );
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600 uppercase tracking-wider">
              <th className="py-3.5 px-5">Kho lưu trữ (Repository)</th>
              <th className="py-3.5 px-5">Nhánh mặc định</th>
              <th className="py-3.5 px-5">Trạng thái Kết nối</th>
              <th className="py-3.5 px-5">Trạng thái Quét</th>
              <th className="py-3.5 px-5">Quét gần nhất</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-sm">
            {repos.map((repo) => (
              <tr key={repo.id} className="hover:bg-slate-50/80 transition-colors">
                <td className="py-4 px-5">
                  <div className="font-medium text-slate-900">{repo.repo_name}</div>
                  <a
                    href={repo.repo_url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-emerald-600 mt-0.5"
                  >
                    {repo.repo_url}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </td>
                <td className="py-4 px-5">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-100 text-slate-700 font-mono text-xs">
                    <GitBranch className="w-3.5 h-3.5 text-slate-500" />
                    {repo.default_branch || 'main'}
                  </span>
                </td>
                <td className="py-4 px-5">
                  {renderConnectionStatus(repo.connection_status, repo.last_error_message)}
                </td>
                <td className="py-4 px-5">{renderScanStatus(repo.scan_status)}</td>
                <td className="py-4 px-5 text-slate-500 text-xs">
                  <div className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    {formatDateTime(repo.last_scanned_at)}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
