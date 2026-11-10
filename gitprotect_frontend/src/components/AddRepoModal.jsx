import React, { useState } from 'react';
import { X, Key, GitFork, AlertCircle, Loader2, CheckCircle2 } from 'lucide-react';

export const AddRepoModal = ({ isOpen, onClose, onSuccess, onConnect }) => {
    const [repoUrl, setRepoUrl] = useState('');
    const [githubPat, setGithubPat] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            await onConnect(repoUrl.trim(), githubPat.trim());
            setRepoUrl('');
            setGithubPat('');
            onSuccess();
            onClose();
        } catch (err) {
            const msg = err.response?.data?.detail || err.response?.data?.message || err.message || 'Không thể kết nối đến kho lưu trữ.';
            setError(msg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
            <div class="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl max-w-md w-full overflow-hidden">
                {/* Header */}
                <div class="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-800/40">
                    <div class="flex items-center space-x-2">
                        <GitFork class="w-5 h-5 text-blue-400" />
                        <h3 class="text-base font-semibold text-slate-100">Kết nối Repo mới (GitHub PAT)</h3>
                    </div>
                    <button
                        onClick={onClose}
                        disabled={loading}
                        class="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded-lg hover:bg-slate-800"
                    >
                        <X class="w-5 h-5" />
                    </button>
                </div>

                {/* Form Body */}
                <form onSubmit={handleSubmit} class="p-6 space-y-4">
                    {error && (
                        <div class="p-3.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-start gap-2.5">
                            <AlertCircle class="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                            <div class="break-words font-medium">{error}</div>
                        </div>
                    )}

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1.5">
                            URL Kho lưu trữ GitHub <span class="text-red-400">*</span>
                        </label>
                        <div class="relative">
                            <input
                                type="url"
                                required
                                placeholder="https://github.com/organization/repository"
                                value={repoUrl}
                                onChange={(e) => setRepoUrl(e.target.value)}
                                disabled={loading}
                                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all disabled:opacity-50"
                            />
                        </div>
                        <p class="mt-1 text-[11px] text-slate-500">Định dạng mẫu: https://github.com/owner/repo</p>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-300 mb-1.5">
                            Personal Access Token (PAT) <span class="text-red-400">*</span>
                        </label>
                        <div class="relative">
                            <input
                                type="password"
                                required
                                placeholder="ghp_xxxxxxxxxxxxxxxxxxxx hoặc github_pat_..."
                                value={githubPat}
                                onChange={(e) => setGithubPat(e.target.value)}
                                disabled={loading}
                                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all font-mono disabled:opacity-50"
                            />
                            <Key class="w-4 h-4 text-slate-500 absolute right-3 top-2.5" />
                        </div>
                        <p class="mt-1 text-[11px] text-slate-500">
                            Cần scope <code class="text-slate-400 bg-slate-800 px-1 py-0.5 rounded">admin:repo_hook</code> hoặc Fine-grained Webhook Read/Write. Token sẽ được mã hóa AES-256-GCM.
                        </p>
                    </div>

                    <div class="flex items-center justify-end space-x-3 pt-4 border-t border-slate-800">
                        <button
                            type="button"
                            onClick={onClose}
                            disabled={loading}
                            class="px-4 py-2 text-xs font-medium text-slate-300 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
                        >
                            Hủy
                        </button>
                        <button
                            type="submit"
                            disabled={loading}
                            class="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-all shadow-lg shadow-blue-600/20 disabled:opacity-50"
                        >
                            {loading ? (
                                <>
                                    <Loader2 class="w-4 h-4 animate-spin" />
                                    Đang xác thực & đăng ký Webhook...
                                </>
                            ) : (
                                <>
                                    <CheckCircle2 class="w-4 h-4" />
                                    Xác nhận Kết nối Repo
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};