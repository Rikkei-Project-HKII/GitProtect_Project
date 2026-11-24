import { useEffect, useState, useCallback } from 'react';
import { AlertCircle } from 'lucide-react';
import { alertApi } from '../api/alertApi';
import { repoApi } from '../api/repoApi';
import AlertFilterBar from '../alerts/AlertFilterBar';
import AlertTable from '../alerts/AlertTable';
import AlertDetailModal from '../alerts/AlertDetailModal';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 50; // Phân trang 50 items/trang theo S2-09c

  const [filters, setFilters] = useState({
    repo_id: undefined,
    severity: undefined,
    status: undefined,
    source: undefined,
  });

  const [repos, setRepos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedAlertId, setSelectedAlertId] = useState(null);

  // Tải danh sách repos phục vụ dropdown filter
  useEffect(() => {
    repoApi
      .getRepos()
      .then((data) => setRepos(Array.isArray(data) ? data : data?.items || []))
      .catch(() => {});
  }, []);

  // Tải danh sách cảnh báo theo filters & pagination
  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const params = {
        ...filters,
        page,
        page_size: pageSize,
      };
      const res = await alertApi.getAlerts(params);
      setAlerts(res?.items || []);
      setTotal(res?.total || 0);
    } catch (err) {
      setError(err.message || 'Không thể tải danh sách cảnh báo.');
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  return (
    <main className="p-4 sm:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold text-slate-900">
            Quản lý Vòng đời Cảnh báo Bảo mật
          </h1>
        </div>
        <p className="text-sm text-slate-500 mt-1">
          Theo dõi, thẩm định và xử lý vòng đời cảnh báo rò rỉ mã nguồn với nhật ký kiểm toán Append-only bất biến.
        </p>
      </div>

      {error && (
        <div className="flex items-center gap-2.5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0 text-red-600" />
          <span>{error}</span>
        </div>
      )}

      {/* Bộ lọc đa tiêu chí (S2-09c) */}
      <AlertFilterBar
        filters={filters}
        setFilters={setFilters}
        onFilterChange={() => setPage(1)}
        repos={repos}
        onRefresh={fetchAlerts}
        loading={loading}
      />

      {/* Danh sách cảnh báo phân trang 50 bản ghi/trang (S2-09c) */}
      <AlertTable
        alerts={alerts}
        total={total}
        page={page}
        pageSize={pageSize}
        onPageChange={(newPage) => setPage(newPage)}
        onSelectAlert={(id) => setSelectedAlertId(id)}
        loading={loading}
      />

      {/* Modal chi tiết, cập nhật trạng thái & timeline lịch sử (S2-09d) */}
      {selectedAlertId && (
        <AlertDetailModal
          alertId={selectedAlertId}
          onClose={() => setSelectedAlertId(null)}
          onUpdated={fetchAlerts}
        />
      )}
    </main>
  );
}
