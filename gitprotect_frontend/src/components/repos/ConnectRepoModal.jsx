import { useState } from 'react';
import { X, KeyRound, GitBranch, AlertCircle, ShieldCheck, Loader2 } from 'lucide-react';
import { repoApi } from '../../api/repoApi';

export default function ConnectRepoModal({ isOpen, onClose, onSuccess }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [githubPat, setGithubPat] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');

    if (!repoUrl.startsWith('https://github.com/')) {
      setError('URL kho lưu trữ phải bắt đầu bằng https://github.com/');
      return;
    }

    if (!githubPat.trim()) {
      setError('Vui lòng nhập GitHub Personal Access Token (PAT).');
      return;
    }

    try {
      setLoading(true);
      await repoApi.connectRepo({
        repo_url: repoUrl.trim().replace(/\/$/, ''),
        github_pat: githubPat.trim(),
      });
      setRepoUrl('');
      setGithubPat('');
      onSuccess();
      onClose();
    } catch (err) {
      setError(err.message || 'Lỗi kết nối kho lưu trữ (401/403/404).');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
      <div className="bg-white rounded-xl shadow-xl border border-slate-200 w-full max-w-lg overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 bg-slate-50">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-emerald-600" />
            <h3 className="text-lg font-semibold text-slate-800">Kết nối Kho lưu trữ GitHub</h3>
          </div>
          <button type="button" onClick={onClose} disabled={loading} className="text-slate-400 hover:text-slate-600">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {error && (
            <div className="flex items-start gap-2.5 p-3.5 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
              <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-red-600" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">
              GitHub Repository URL <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <GitBranch className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
              <input
                type="url"
                required
                placeholder="https://github.com/organization/backend-api"
                value={repoUrl}
                onChange={(event) => setRepoUrl(event.target.value)}
                disabled={loading}
                className="w-full pl-10 pr-4 py-2.5 text-sm border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">
              GitHub Personal Access Token (PAT) <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
              <input
                type="password"
                required
                minLength={20}
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxx hoặc github_pat_xxxx"
                value={githubPat}
                onChange={(event) => setGithubPat(event.target.value)}
                disabled={loading}
                className="w-full pl-10 pr-4 py-2.5 text-sm border border-slate-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none"
              />
            </div>
            <p className="mt-2 text-xs text-slate-500 leading-relaxed">
              Yêu cầu quyền <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-700">admin:repo_hook</code> (Classic PAT)
              hoặc <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-700">Webhooks: Read &amp; Write</code> (Fine-grained PAT).
              Token được mã hóa AES-256-GCM trên máy chủ.
            </p>
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-100">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50"
            >
              Hủy bỏ
            </button>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-emerald-600 rounded-lg hover:bg-emerald-700 disabled:opacity-60"
            >
              {loading && <Loader2 className="w-4 h-4 animate-spin" />}
              {loading ? 'Đang xác thực & Đăng ký Webhook...' : 'Xác nhận Kết nối'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
