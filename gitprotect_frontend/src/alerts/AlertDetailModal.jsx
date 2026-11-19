import React, { useEffect, useState } from 'react';
import { X, ShieldCheck, Clock, User, AlertTriangle, CheckCircle2, History, GitCommit, FileText } from 'lucide-react';
import { alertApi } from '../api/alertApi';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';

export default function AlertDetailModal({ alertId, onClose, onUpdated }) {
  const [alert, setAlert] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Form cập nhật trạng thái
  const [newStatus, setNewStatus] = useState('in_review');
  const [resolutionNote, setResolutionNote] = useState('');

  useEffect(() => {
    let cancelled = false;

    const fetchDetailAndHistory = async () => {
      try {
        setLoading(true);
        setError('');
        const [detailData, historyData] = await Promise.all([
          alertApi.getAlertDetail(alertId),
          alertApi.getAlertHistory(alertId),
        ]);
        if (!cancelled) {
          setAlert(detailData);
          setHistory(historyData?.items || []);
          setNewStatus(detailData.status === 'open' ? 'in_review' : detailData.status);
          setResolutionNote(detailData.resolution_note || '');
        }
      } catch (err) {
        if (!cancelled) setError(err.message || 'Không thể tải chi tiết cảnh báo.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchDetailAndHistory();
    return () => {
      cancelled = true;
    };
  }, [alertId]);

  const handleUpdateStatus = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    // Ràng buộc AC-01: False positive bắt buộc resolution_note >= 10 ký tự
    if (newStatus === 'false_positive' && (!resolutionNote || resolutionNote.trim().length < 10)) {
      setError('Khi đánh dấu False Positive, bắt buộc phải nhập lý do giải trình ít nhất 10 ký tự (AC-01).');
      return;
    }

    try {
      setUpdating(true);
      // Ràng buộc AC-03: Client chỉ gửi new_status và resolution_note, tuyệt đối không gửi actor
      const payload = {
        new_status: newStatus,
        resolution_note: resolutionNote.trim() ? resolutionNote.trim() : null,
      };

      await alertApi.updateAlertStatus(alertId, payload);
      setSuccessMsg('Cập nhật trạng thái và ghi lịch sử kiểm toán thành công!');

      // Tải lại chi tiết và timeline lịch sử
      const [updatedDetail, updatedHistory] = await Promise.all([
        alertApi.getAlertDetail(alertId),
        alertApi.getAlertHistory(alertId),
      ]);
      setAlert(updatedDetail);
      setHistory(updatedHistory?.items || []);
      if (onUpdated) onUpdated();
    } catch (err) {
      setError(err.message || 'Lỗi khi cập nhật trạng thái.');
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-3xl my-8 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 bg-slate-50 shrink-0">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-emerald-600" />
            <div>
              <h3 className="text-base font-semibold text-slate-800">
                Chi tiết Cảnh báo #{alertId}
              </h3>
              <p className="text-xs text-slate-500">
                Quản lý vòng đời & Nhật ký kiểm toán Append-only (S2-09d)
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 transition-colors p-1"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm">
          {loading ? (
            <div className="py-12 text-center">
              <div className="inline-block w-8 h-8 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin mb-3" />
              <p className="text-xs text-slate-500">Đang tải dữ liệu cảnh báo...</p>
            </div>
          ) : (
            <>
              {error && (
                <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
                  <span>{error}</span>
                </div>
              )}

              {successMsg && (
                <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
                  <span>{successMsg}</span>
                </div>
              )}

              {/* Thông tin cốt lõi & Secret Masking */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-50 rounded-xl p-4 border border-slate-200/80 space-y-2">
                  <span className="text-xs font-semibold text-slate-500 uppercase">Quy tắc quét vi phạm</span>
                  <div className="font-semibold text-slate-900">{alert?.rule_name}</div>
                  <div className="flex items-center gap-2 pt-1">
                    <SeverityBadge severity={alert?.severity} />
                    <StatusBadge status={alert?.status} />
                  </div>
                </div>

                <div className="bg-slate-50 rounded-xl p-4 border border-slate-200/80 space-y-2">
                  <span className="text-xs font-semibold text-slate-500 uppercase">Chuỗi bí mật che (Masked NFR-01)</span>
                  <div className="font-mono text-xs font-semibold text-slate-800 bg-white px-3 py-2 rounded-lg border border-slate-200 break-all">
                    {alert?.secret_masked || 'Không có chuỗi bí mật (Dependabot Alert)'}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Bảo mật tuyệt đối: Chỉ lưu tiền tố + '****' + 4 ký tự cuối.
                  </div>
                </div>
              </div>

              {/* Thông tin vị trí & Tác giả commit */}
              <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-2.5 text-xs">
                <div className="font-semibold text-slate-800 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-slate-500" />
                  <span>Vị trí tệp & Metadata tác giả</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-600">
                  <div>
                    <span className="text-slate-400">Đường dẫn tệp:</span>{' '}
                    <code className="text-slate-800 font-mono">{alert?.file_path || 'N/A'}</code>
                    {alert?.line_number && <span> (Dòng {alert?.line_number})</span>}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <GitCommit className="w-3.5 h-3.5 text-slate-400" />
                    <span className="text-slate-400">Commit SHA:</span>{' '}
                    <code className="text-slate-800 font-mono">{alert?.commit_sha?.slice(0, 8) || 'N/A'}</code>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-slate-400" />
                    <span className="text-slate-400">Tác giả:</span>{' '}
                    <span>{alert?.author_name || 'N/A'} ({alert?.author_email || 'N/A'})</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Chữ ký GPG/SSH:</span>{' '}
                    <span className={alert?.signature_verified ? 'text-emerald-600 font-medium' : 'text-slate-500'}>
                      {alert?.signature_verified ? 'Verified ✓' : 'Unverified'}
                    </span>
                    {alert?.email_spoofing_flag && (
                      <span className="ml-2 text-red-600 font-semibold">[Email Spoofing Notice]</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Form Cập nhật trạng thái vòng đời */}
              <form onSubmit={handleUpdateStatus} className="bg-slate-50 rounded-xl p-4 border border-slate-200 space-y-3">
                <div className="font-semibold text-slate-800 flex items-center gap-2 text-xs">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  <span>Cập nhật vòng đời cảnh báo (Chống giả mạo Actor AC-01..AC-04)</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">
                      Trạng thái mới <span className="text-red-500">*</span>
                    </label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value)}
                      disabled={updating}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white text-xs font-medium focus:ring-2 focus:ring-emerald-500 outline-none"
                    >
                      <option value="in_review">In Review (Đang thẩm định)</option>
                      <option value="resolved">Resolved (Đã giải quyết)</option>
                      <option value="false_positive">False Positive (Báo sai - cần note &gt;= 10 ký tự)</option>
                      <option value="ignored">Ignored (Bỏ qua)</option>
                    </select>
                  </div>

                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-600 mb-1">
                      Lý do giải trình (Resolution Note) {newStatus === 'false_positive' && <span className="text-red-500">* (Tối thiểu 10 ký tự)</span>}
                    </label>
                    <input
                      type="text"
                      placeholder={newStatus === 'false_positive' ? 'Ví dụ: Khóa test mock trong unit test môi trường dev' : 'Nhập ghi chú giải quyết (nếu có)...'}
                      value={resolutionNote}
                      onChange={(e) => setResolutionNote(e.target.value)}
                      disabled={updating}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white text-xs focus:ring-2 focus:ring-emerald-500 outline-none"
                    />
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={updating}
                    className="px-4 py-2 bg-emerald-600 text-white rounded-lg text-xs font-medium hover:bg-emerald-700 transition disabled:opacity-50"
                  >
                    {updating ? 'Đang cập nhật...' : 'Lưu thay đổi trạng thái'}
                  </button>
                </div>
              </form>

              {/* Timeline Lịch sử Append-Only (AC-05 & S2-09d) */}
              <div className="space-y-3">
                <div className="font-semibold text-slate-800 flex items-center gap-2 text-xs">
                  <History className="w-4 h-4 text-purple-600" />
                  <span>Timeline Nhật ký kiểm toán trạng thái (Append-Only & Snapshot Actor)</span>
                </div>

                {history.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Chưa có bản ghi lịch sử thay đổi.</p>
                ) : (
                  <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
                    {history.map((h) => (
                      <div key={h.id} className="relative text-xs">
                        <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-emerald-500 ring-4 ring-white" />
                        <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-1">
                          <div className="flex items-center justify-between text-slate-500">
                            <span className="font-semibold text-slate-700">
                              {h.old_status ? `${h.old_status} ➔ ` : 'Khởi tạo: '}{h.new_status}
                            </span>
                            <span className="flex items-center gap-1 text-[11px]">
                              <Clock className="w-3 h-3" />
                              {new Date(h.created_at).toLocaleString('vi-VN')}
                            </span>
                          </div>
                          <div className="text-slate-600 text-[11px]">
                            Tác nhân (Actor snapshot):{' '}
                            <code className="bg-slate-200/80 px-1.5 py-0.5 rounded font-mono font-medium text-slate-800">
                              {h.actor_label}
                            </code>{' '}
                            (Phân loại: {h.actor_type})
                          </div>
                          {h.resolution_note && (
                            <p className="text-slate-700 text-xs mt-1 bg-white p-2 rounded border border-slate-100">
                              Lý do: {h.resolution_note}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-100 bg-slate-50 flex justify-end shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition"
          >
            Đóng
          </button>
        </div>
      </div>
    </div>
  );
}

