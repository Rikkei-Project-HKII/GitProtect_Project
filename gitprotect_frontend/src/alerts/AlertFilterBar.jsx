import React from 'react';
import { Filter, RefreshCw } from 'lucide-react';

export default function AlertFilterBar({ filters, setFilters, repos, onRefresh, loading }) {
  const handleChange = (key, value) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value === '' ? undefined : value,
      page: 1, // Reset về trang 1 khi lọc
    }));
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-800">
          <Filter className="w-4 h-4 text-emerald-600" />
          <span>Bộ lọc cảnh báo đa tiêu chí (FR-05)</span>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Làm mới
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
        {/* Lọc theo Repository */}
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1">
            Kho lưu trữ
          </label>
          <select
            value={filters.repo_id || ''}
            onChange={(e) => handleChange('repo_id', e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white text-slate-800 text-xs focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none"
          >
            <option value="">Tất cả kho lưu trữ</option>
            {repos.map((r) => (
              <option key={r.id} value={r.id}>
                {r.repo_name}
              </option>
            ))}
          </select>
        </div>

        {/* Lọc theo Mức độ nghiêm trọng */}
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1">
            Mức độ (Severity)
          </label>
          <select
            value={filters.severity || ''}
            onChange={(e) => handleChange('severity', e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white text-slate-800 text-xs focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none"
          >
            <option value="">Tất cả 4 mức độ</option>
            <option value="critical">Critical (Tối khẩn cấp)</option>
            <option value="high">High (Nghiêm trọng)</option>
            <option value="medium">Medium (Trung bình)</option>
            <option value="low">Low (Thấp)</option>
          </select>
        </div>

        {/* Lọc theo Trạng thái vòng đời */}
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1">
            Trạng thái (Status)
          </label>
          <select
            value={filters.status || ''}
            onChange={(e) => handleChange('status', e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white text-slate-800 text-xs focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none"
          >
            <option value="">Tất cả trạng thái</option>
            <option value="open">Open (Chưa xử lý)</option>
            <option value="in_review">In Review (Đang thẩm định)</option>
            <option value="resolved">Resolved (Đã khắc phục)</option>
            <option value="false_positive">False Positive (Báo sai)</option>
            <option value="ignored">Ignored (Bỏ qua rủi ro)</option>
          </select>
        </div>

        {/* Lọc theo Nguồn cảnh báo */}
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1">
            Nguồn phát hiện
          </label>
          <select
            value={filters.source || ''}
            onChange={(e) => handleChange('source', e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white text-slate-800 text-xs focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none"
          >
            <option value="">Tất cả nguồn</option>
            <option value="gitprotect_scanner">GitProtect Scanner (Nội bộ)</option>
            <option value="github_native">GitHub Native & Dependabot</option>
          </select>
        </div>
      </div>
    </div>
  );
}

