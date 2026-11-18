import { useCallback, useEffect, useState } from 'react';
import { Plus, RefreshCw, AlertCircle } from 'lucide-react';
import { repoApi } from '../api/repoApi';
import RepoTable from '../components/repos/RepoTable';
import ConnectRepoModal from '../components/repos/ConnectRepoModal';

export default function RepositoriesPage() {
  const [repos, setRepos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchRepos = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const data = await repoApi.getRepos();
      setRepos(Array.isArray(data) ? data : data.items || []);
    } catch (err) {
      setError(err.message || 'Không thể tải danh sách kho lưu trữ.');
      setRepos([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRepos();
  }, [fetchRepos]);

  return (
    <main className="p-4 sm:p-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Quản lý Kho lưu trữ (Repositories)</h1>
          <p className="text-sm text-slate-500 mt-1">
            Liên kết kho lưu trữ GitHub bằng PAT để tự động thiết lập Webhook và giám sát rò rỉ bí mật mã nguồn.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={fetchRepos}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Làm mới
          </button>
          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-700 shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Kết nối Repo mới
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 flex items-center gap-2.5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0 text-red-600" />
          <span>{error}</span>
        </div>
      )}

      <RepoTable repos={repos} loading={loading} />

      <ConnectRepoModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={fetchRepos}
      />
    </main>
  );
}
