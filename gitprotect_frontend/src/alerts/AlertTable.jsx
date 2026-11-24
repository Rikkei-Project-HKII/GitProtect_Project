import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';
import { ShieldAlert, ChevronLeft, ChevronRight, Eye } from 'lucide-react';

export default function AlertTable({ alerts, total, page, pageSize, onPageChange, onSelectAlert, loading }) {
  const totalPages = Math.ceil(total / pageSize) || 1;

  if (loading) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm">
        <div className="inline-block w-8 h-8 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin mb-3" />
        <p className="text-sm text-slate-500">Đang tải danh sách cảnh báo...</p>
      </div>
    );
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm">
        <ShieldAlert className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <h3 className="text-base font-medium text-slate-800">Không tìm thấy cảnh báo nào</h3>
        <p className="text-sm text-slate-500 mt-1">
          Hệ thống chưa ghi nhận vi phạm bí mật phù hợp với tiêu chí lọc hiện tại.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600 uppercase tracking-wider">
              <th className="py-3.5 px-5">Quy tắc & Chuỗi bí mật (Masked)</th>
              <th className="py-3.5 px-4">Mức độ</th>
              <th className="py-3.5 px-4">Trạng thái</th>
              <th className="py-3.5 px-5">Tập tin & Vị trí</th>
              <th className="py-3.5 px-4">Nguồn</th>
              <th className="py-3.5 px-4">Thời gian</th>
              <th className="py-3.5 px-4 text-right">Thao tác</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {alerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-slate-50/70 transition-colors">
                <td className="py-3.5 px-5">
                  <div className="font-medium text-slate-900">{alert.rule_name}</div>
                  {alert.secret_masked ? (
                    <code className="inline-block mt-0.5 px-1.5 py-0.5 bg-slate-100 text-slate-700 rounded text-xs font-mono">
                      {alert.secret_masked}
                    </code>
                  ) : alert.package_name ? (
                    <span className="text-xs text-slate-500">
                      Gói: {alert.package_name} {alert.fixed_version ? `(Bản vá: ${alert.fixed_version})` : ''}
                    </span>
                  ) : null}
                </td>
                <td className="py-3.5 px-4">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="py-3.5 px-4">
                  <StatusBadge status={alert.status} />
                </td>
                <td className="py-3.5 px-5 text-xs text-slate-600 font-mono">
                  <div className="max-w-xs truncate" title={alert.file_path}>
                    {alert.file_path || 'Dependabot Alert'}
                  </div>
                  {alert.line_number && (
                    <span className="text-slate-400">Dòng: {alert.line_number}</span>
                  )}
                </td>
                <td className="py-3.5 px-4 text-xs text-slate-500">
                  {alert.source === 'gitprotect_scanner' ? (
                    <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                      Scanner
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                      GitHub Native
                    </span>
                  )}
                </td>
                <td className="py-3.5 px-4 text-xs text-slate-500">
                  {alert.detected_at
                    ? new Date(alert.detected_at).toLocaleString('vi-VN')
                    : 'N/A'}
                </td>
                <td className="py-3.5 px-4 text-right">
                  <button
                    type="button"
                    onClick={() => onSelectAlert(alert.id)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 rounded-lg transition"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Chi tiết
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Thanh phân trang 50 items/trang (S2-09c) */}
      <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-600 bg-slate-50">
        <div>
          Hiển thị{' '}
          <span className="font-semibold text-slate-800">
            {total > 0 ? (page - 1) * pageSize + 1 : 0}
          </span>{' '}
          đến{' '}
          <span className="font-semibold text-slate-800">
            {Math.min(page * pageSize, total)}
          </span>{' '}
          trong tổng số <span className="font-semibold text-slate-800">{total}</span> cảnh báo
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="p-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-100 disabled:opacity-40"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span>
            Trang <strong className="text-slate-800">{page}</strong> / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="p-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-100 disabled:opacity-40"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
