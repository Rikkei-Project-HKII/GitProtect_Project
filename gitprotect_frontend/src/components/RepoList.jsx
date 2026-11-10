import React, { useState } from 'react';
import { GitBranch, ShieldAlert, CheckCircle2, AlertOctagon, Plus, Search, ExternalLink, Clock, FolderGit2 } from 'lucide-react';

export const RepoList = ({ repos, loading, error, onOpenAddModal }) => {
    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState('all');

    const filteredRepos = repos.filter((repo) => {
        const matchesSearch = repo.repo_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            repo.repo_url.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesStatus = statusFilter === 'all' || repo.connection_status === statusFilter;
        return matchesSearch && matchesStatus;
    });

    return (
        <div class="space-y-6">
            {/* Header & Controls */}
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
                <div>
                    <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
                        <FolderGit2 class="w-5 h-5 text-blue-400" />
                        Danh sách Kho lưu trữ đã Kết nối ({repos.length})
                    </h2>
                    <p class="text-xs text-slate-400 mt-0.5">Theo dõi trạng thái Webhook và tiến trình quét mã nguồn tự động qua PAT</p>
                </div>

                <button
                    onClick={onOpenAddModal}
                    class="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-lg shadow-blue-600/20 transition-all cursor-pointer"
                >
                    <Plus class="w-4 h-4" />
                    Kết nối Repo Mới
                </button>
            </div>

            {/* Filter & Search Bar */}
            <div class="flex flex-col sm:flex-row gap-3 items-center justify-between">
                <div class="relative w-full sm:w-72">
                    <Search class="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                        type="text"
                        placeholder="Tìm theo tên repo hoặc URL..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        class="w-full bg-slate-900 border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-all"
                    />
                </div>

                <div class="flex items-center space-x-2 w-full sm:w-auto">
                    <span class="text-xs text-slate-400 font-medium">Trạng thái:</span>
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        class="bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    >
                        <option value="all">Tất cả ({repos.length})</option>
                        <option value="active">Active (Hoạt động)</option>
                        <option value="error">Error (Lỗi kết nối)</option>
                    </select>
                </div>
            </div>

            {/* Main Table / View */}
            {loading ? (
                <div class="flex flex-col items-center justify-center p-12 bg-slate-900/60 rounded-xl border border-slate-800 space-y-3">
                    <div class="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                    <p class="text-xs text-slate-400">Đang tải danh sách kho lưu trữ từ API...</p>
                </div>
            ) : error ? (
                <div class="p-6 bg-red-500/10 border border-red-500/20 rounded-xl text-center space-y-2">
                    <AlertOctagon class="w-8 h-8 text-red-400 mx-auto" />
                    <p class="text-sm font-semibold text-red-400">Lỗi khi tải dữ liệu từ API GET /api/v1/repos</p>
                    <p class="text-xs text-slate-400 max-w-md mx-auto">{error}</p>
                </div>
            ) : filteredRepos.length === 0 ? (
                <div class="text-center p-12 bg-slate-900/40 rounded-xl border border-slate-800 border-dashed space-y-3">
                    <FolderGit2 class="w-10 h-10 text-slate-600 mx-auto" />
                    <p class="text-sm font-medium text-slate-300">Chưa tìm thấy kho lưu trữ nào</p>
                    <p class="text-xs text-slate-500">Hãy thêm mới kho lưu trữ bằng GitHub PAT để bắt đầu giám sát bí mật.</p>
                </div>
            ) : (
                <div class="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/60 shadow-xl">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-slate-800/80 text-slate-400 uppercase font-mono text-[11px] tracking-wider border-b border-slate-700/80">
                            <tr>
                                <th class="py-3.5 px-4 font-semibold">Tên Repo & Nhánh</th>
                                <th class="py-3.5 px-4 font-semibold">Trạng thái Kết nối</th>
                                <th class="py-3.5 px-4 font-semibold">Tiến trình Quét</th>
                                <th class="py-3.5 px-4 font-semibold">Lần quét gần nhất</th>
                                <th class="py-3.5 px-4 font-semibold text-right">Hành động</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/60 font-sans">
                            {filteredRepos.map((repo) => (
                                <tr key={repo.id} class="hover:bg-slate-800/40 transition-colors">
                                    <td class="py-3.5 px-4">
                                        <div class="flex items-center space-x-2.5">
                                            <div class="font-semibold text-slate-100 flex items-center gap-1.5">
                                                {repo.repo_name}
                                            </div>
                                        </div>
                                        <div class="flex items-center gap-3 mt-1 text-[11px] text-slate-400">
                                            <span class="inline-flex items-center gap-1 text-slate-400 font-mono">
                                                <GitBranch class="w-3 h-3 text-slate-500" />
                                                {repo.default_branch || 'main'}
                                            </span>
                                            <span>•</span>
                                            <a
                                                href={repo.repo_url}
                                                target="_blank"
                                                rel="noreferrer"
                                                class="hover:underline hover:text-blue-400 flex items-center gap-1 text-slate-500"
                                            >
                                                {repo.repo_url}
                                                <ExternalLink class="w-2.5 h-2.5" />
                                            </a>
                                        </div>
                                    </td>
                                    <td class="py-3.5 px-4">
                                        {repo.connection_status === 'active' ? (
                                            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                <CheckCircle2 class="w-3.5 h-3.5" /> Active
                                            </span>
                                        ) : (
                                            <div class="space-y-1">
                                                <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                                                    <AlertOctagon class="w-3.5 h-3.5" /> Error
                                                </span>
                                                {repo.last_error_message && (
                                                    <p class="text-[10px] text-red-400/80 font-mono truncate max-w-xs" title={repo.last_error_message}>
                                                        {repo.last_error_message}
                                                    </p>
                                                )}
                                            </div>
                                        )}
                                    </td>
                                    <td class="py-3.5 px-4">
                                        <span class="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                                            {repo.scan_status || 'idle'}
                                        </span>
                                    </td>
                                    <td class="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                                        <div class="flex items-center gap-1.5">
                                            <Clock class="w-3.5 h-3.5 text-slate-500" />
                                            {repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleString('vi-VN') : 'Chưa thực hiện'}
                                        </div>
                                    </td>
                                    <td class="py-3.5 px-4 text-right">
                                        <button class="text-xs text-blue-400 hover:text-blue-300 font-medium px-2 py-1 rounded hover:bg-blue-500/10 transition-colors">
                                            Xem Alerts
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};