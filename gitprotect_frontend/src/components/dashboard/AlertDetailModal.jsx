import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { getAlert, getAlertHistory } from '../../api/dashboard';
import { SEV_COLORS } from './DashboardCharts';

export default function AlertDetailModal({ alertId, onClose }) {
  const [alert, setAlert] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    setAlert(null); setError(false);
    Promise.all([getAlert(alertId), getAlertHistory(alertId)])
      .then(([a, h]) => { setAlert(a); setHistory(h.items); })
      .catch(() => setError(true));
  }, [alertId]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      <div className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-xl bg-white p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold">Alert #{alertId}</h3>
          <button onClick={onClose} aria-label="Đóng"><X size={20} /></button>
        </div>
        {error && <p className="mt-4 text-red-600">Không tải được chi tiết cảnh báo.</p>}
        {!alert && !error && <p className="mt-4 text-gray-500">Đang tải...</p>}
        {alert && (
          <>
            <p className="mt-3">
              <span className="rounded-full px-2 py-0.5 text-xs text-white" style={{ background: SEV_COLORS[alert.severity] }}>{alert.severity}</span>
              <span className="ml-2 text-sm">{alert.status}</span>
            </p>
            <dl className="mt-3 space-y-1 text-sm">
              <div><dt className="inline text-gray-500">Rule: </dt><dd className="inline">{alert.rule_name}</dd></div>
              <div><dt className="inline text-gray-500">File: </dt><dd className="inline font-mono">{alert.file_path}{alert.line_number ? `:${alert.line_number}` : ''}</dd></div>
              {/* Chỉ hiển thị secret_masked, không bao giờ hiển thị secret gốc */}
              <div><dt className="inline text-gray-500">Secret: </dt><dd className="inline rounded bg-gray-100 px-1 font-mono">{alert.secret_masked ?? '—'}</dd></div>
              <div><dt className="inline text-gray-500">Commit: </dt><dd className="inline font-mono">{(alert.commit_sha || '').slice(0, 10)}</dd> <span className="text-gray-500">bởi {alert.author_name}</span></div>
              {alert.email_spoofing_flag && <div className="text-red-600">⚠ Nghi ngờ giả mạo email tác giả</div>}
            </dl>
            <h4 className="mt-4 font-semibold">Timeline lịch sử</h4>
            <ol className="mt-2 ml-2 border-l-2 pl-4">
              {history.length === 0 && <li className="text-sm text-gray-400">Chưa có lịch sử</li>}
              {history.map((h) => (
                <li key={h.id} className="mb-3 text-sm">
                  <div className="font-medium">{h.old_status ?? '—'} → {h.new_status}</div>
                  {/* actor_label là snapshot tại thời điểm thao tác */}
                  <div className="text-gray-500">{h.actor_label} · {new Date(h.created_at).toLocaleString('vi-VN')}</div>
                  {h.resolution_note && <div className="mt-0.5">{h.resolution_note}</div>}
                </li>
              ))}
            </ol>
          </>
        )}
      </div>
    </div>
  );
}