import { useState } from 'react';
import axiosClient from '../../api/axiosClient';

export default function ExportButtons() {
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  async function download(format) {
    setBusy(format);
    setError('');
    try {
      const blob = await axiosClient.get('/dashboard/export', {
        params: { format }, responseType: 'blob',
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'gitprotect-security-report.' + format;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setError(err.message || 'Không thể xuất báo cáo. Vui lòng thử lại.');
    } finally {
      setBusy('');
    }
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-4" aria-label="Xuất báo cáo">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-semibold text-slate-800">Báo cáo an ninh đa kho</h2>
          <p className="text-sm text-slate-500">Tải số liệu và cảnh báo đã che dữ liệu bí mật.</p>
        </div>
        <div className="flex gap-2">
          {['csv', 'pdf'].map(format => (
            <button key={format} disabled={Boolean(busy)} onClick={() => download(format)}
              className="rounded-lg bg-teal-700 px-4 py-2 text-sm text-white hover:bg-teal-800 disabled:opacity-50">
              {busy === format ? 'Đang xuất…' : 'Tải ' + format.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
      {error && <p role="alert" className="mt-2 text-sm text-red-700">{error}</p>}
    </section>
  );
}
