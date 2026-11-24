import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Play, ShieldCheck, GitBranch, FileDown, FlaskConical, CheckCircle2 } from 'lucide-react';
import axiosClient from '../api/axiosClient';
import ExportButtons from '../components/dashboard/ExportButtons';

async function demoRequest(path) {
  const response = await fetch('/api/demo/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data));
  return data;
}

const button = 'inline-flex items-center justify-center gap-2 rounded-lg bg-teal-700 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-800 disabled:opacity-50';
const secondary = 'rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:border-teal-400 disabled:opacity-50';

export default function DemoPage() {
  const [repos, setRepos] = useState([]);
  const [repoId, setRepoId] = useState('1');
  const [samples, setSamples] = useState([]);
  const [content, setContent] = useState('');
  const [path, setPath] = useState('src/config.py');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [results, setResults] = useState({});
  const [job, setJob] = useState(null);
  const [available, setAvailable] = useState(false);

  const reloadRepos = async () => {
    const data = await axiosClient.get('/repos', { params: { page_size: 50 } });
    setRepos(data.items);
  };

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetch('/api/demo/info').then(r => r.json()), axiosClient.get('/repos'), fetch('/api/demo/samples').then(r => { if (!r.ok) throw new Error('Samples unavailable'); return r.json(); })])
      .then(([info, data, examples]) => { if (!cancelled) { setAvailable(info.demo === true); setRepos(data.items); setSamples(examples); setContent(examples[0].content); setPath(examples[0].path); } })
      .catch(() => { if (!cancelled) setError('Backend demo chưa chạy. Khởi động scripts/demo_server.py.'); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!job?.job_id || ['completed', 'failed'].includes(job.scan_status)) return;
    let cancelled = false;
    const timer = setInterval(async () => {
      try {
        const value = await axiosClient.get('/scan/jobs/' + job.job_id);
        if (!cancelled) setJob(value);
      } catch (err) { if (!cancelled) { setError(err.message); setJob(null); } }
    }, 600);
    return () => { cancelled = true; clearInterval(timer); };
  }, [job?.job_id, job?.scan_status]);

  async function run(key, action) {
    setBusy(key); setError('');
    try { const value = await action(); setResults(previous => ({ ...previous, [key]: value })); }
    catch (err) { setError(err.message); }
    finally { setBusy(''); }
  }

  function result(key) {
    if (!results[key]) return null;
    return <details open className="mt-4 rounded-lg bg-slate-950 p-4 text-xs text-teal-100">
      <summary className="cursor-pointer font-medium">Kết quả trả về</summary>
      <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words">{JSON.stringify(results[key], null, 2)}</pre>
    </details>;
  }

  const disabled = Boolean(busy) || !available;
  return <main className="mx-auto w-full max-w-6xl space-y-6 p-4 sm:p-8">
    <div className="rounded-2xl bg-slate-900 p-6 text-white sm:p-8">
      <div className="mb-3 flex items-center gap-2 text-sm text-teal-300"><FlaskConical size={18} /> PHÒNG DEMO GITPROTECT</div>
      <h1 className="text-3xl font-bold tracking-tight">Một vòng bảo vệ mã nguồn</h1>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">Thử từ kết nối kho đến phát hiện, xử lý và xuất báo cáo. Dữ liệu GitHub là mẫu mô phỏng; API, engine, chữ ký HMAC và lịch sử xử lý chạy bằng code của dự án. Dữ liệu được tạo lại khi khởi động demo.</p>
      <div className="mt-5 flex flex-wrap gap-3 text-sm">
        <Link to="/" className="rounded-lg bg-white/10 px-4 py-2 hover:bg-white/20">Dashboard</Link>
        <Link to="/repos" className="rounded-lg bg-white/10 px-4 py-2 hover:bg-white/20">Kho lưu trữ</Link>
        <Link to="/alerts" className="rounded-lg bg-white/10 px-4 py-2 hover:bg-white/20">Cảnh báo & lịch sử</Link>
      </div>
    </div>
    {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 p-4 text-red-700">{error}</p>}

    <section className="rounded-xl border border-slate-200 bg-white p-6">
      <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900"><GitBranch size={20} className="text-teal-700" /> 1. Kết nối và quét kho</h2>
      <p className="mt-2 text-sm text-slate-500">Kết nối repo mẫu qua API thật, tự tạo webhook mô phỏng và đưa vào hàng đợi quét. Hoặc quét lại một kho đang có.</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <button className={button} disabled={disabled} onClick={() => run('connect', async () => { const data = await demoRequest('connect'); await reloadRepos(); setRepoId(String(data.id)); return data; })}>Kết nối repo mẫu</button>
        <select aria-label="Chọn kho demo" value={repoId} onChange={e => setRepoId(e.target.value)} className="max-w-full rounded-lg border border-slate-300 px-3 py-2 text-sm">
          {repos.map(repo => <option key={repo.id} value={repo.id}>{repo.repo_name}</option>)}
        </select>
        <button className={secondary} disabled={disabled} onClick={() => run('scan', async () => { const data = await axiosClient.post('/scan/trigger/' + repoId); setJob(data); return data; })}>Quét toàn bộ kho</button>
        <button className={secondary} disabled={disabled} onClick={() => run('native', () => axiosClient.post('/sync/native-alerts/' + repoId))}>Đồng bộ cảnh báo GitHub</button>
      </div>
      {job && <div className="mt-4 text-sm text-slate-600"><div className="mb-2 flex justify-between"><span>Tiến độ: {job.scan_status}</span><span>{job.progress_pct || 0}%</span></div><progress className="h-2 w-full accent-teal-600" max="100" value={job.progress_pct || 0} /><p className="mt-1">Đã quét {job.scanned_files || 0} tệp. {job.error_message || ''}</p></div>}
      {result('connect')}{result('scan')}{result('native')}
    </section>

    <section className="rounded-xl border border-slate-200 bg-white p-6">
      <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900"><Play size={20} className="text-teal-700" /> 2. Thử engine 3 lớp và 7 quy tắc</h2>
      <p className="mt-2 text-sm text-slate-500">Chọn mẫu hoặc nhập đoạn mã. Mẫu chỉ phục vụ trình diễn, không phải khóa thật. Quét nhanh không lưu cảnh báo vào kho.</p>
      <div className="my-4 flex flex-wrap gap-2">{samples.map(sample => <button key={sample.label} className={secondary} onClick={() => { setContent(sample.content); setPath(sample.path); }}>{sample.label}</button>)}</div>
      <label className="block text-sm font-medium text-slate-700">Đường dẫn tệp<input value={path} onChange={e => setPath(e.target.value)} className="my-2 block w-full rounded-lg border border-slate-300 px-3 py-2 font-mono" /></label>
      <label className="block text-sm font-medium text-slate-700">Mã nguồn<textarea value={content} onChange={e => setContent(e.target.value)} rows={4} className="my-2 block w-full rounded-lg border border-slate-300 bg-slate-50 p-3 font-mono text-sm" /></label>
      <button className={button} disabled={disabled} onClick={() => run('evaluate', () => axiosClient.post('/scan/evaluate-text', { content, file_path: path }))}><Play size={16} /> Quét đoạn mã</button>
      <button className={secondary + ' ml-2'} disabled={disabled} onClick={() => run('rules', () => axiosClient.get('/rules'))}>Xem 7 quy tắc</button>
      {results.evaluate && <p className={'mt-4 rounded-lg p-3 text-sm ' + (results.evaluate.is_leaked ? 'bg-amber-50 text-amber-800' : 'bg-teal-50 text-teal-800')}>{results.evaluate.is_leaked ? `Phát hiện ${results.evaluate.findings.length} cảnh báo` : results.evaluate.file_allowlisted ? 'Bỏ qua đúng theo allowlist' : 'Không phát hiện bí mật'} · {results.evaluate.execution_time_ms} ms</p>}
      {result('evaluate')}{result('rules')}
    </section>

    <section className="rounded-xl border border-slate-200 bg-white p-6">
      <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900"><ShieldCheck size={20} className="text-teal-700" /> 3. Webhook, chống gửi trùng và kiểm toán tác giả</h2>
      <p className="mt-2 text-sm text-slate-500">Webhook gửi vào kho payment-api. Chữ ký hợp lệ tạo cảnh báo qua worker; chữ ký sai bị từ chối; delivery trùng không tạo việc quét mới.</p>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{[['valid','Push hợp lệ'],['invalid','Chữ ký giả'],['replay','Gửi lại cùng delivery'],['spoofed','Tác giả đáng ngờ']].map(([key,label]) => <button key={key} className={secondary} disabled={disabled} onClick={() => run('webhook', () => demoRequest('webhook/' + key))}>{label}</button>)}</div>
      {result('webhook')}
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-teal-700 hover:underline">Xem kiểm toán tác giả trong Dashboard →</Link>
    </section>

    <section className="rounded-xl border border-slate-200 bg-white p-6">
      <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900"><CheckCircle2 size={20} className="text-teal-700" /> 4. Xử lý cảnh báo và lịch sử</h2>
      <p className="mt-2 text-sm leading-6 text-slate-500">Mở một cảnh báo, đổi sang In review hoặc Resolved và kiểm tra lịch sử. Với False positive, ghi chú phải có ít nhất 10 ký tự. Backend tự gắn người thao tác và lưu thay đổi cùng lịch sử trong một transaction.</p>
      <Link to="/alerts" className={button + ' mt-4'}>Mở danh sách cảnh báo</Link>
    </section>
    <section className="space-y-3"><h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900"><FileDown size={20} className="text-teal-700" /> 5. Tổng hợp và tải báo cáo</h2><ExportButtons /></section>
    <p className="pb-4 text-xs leading-5 text-slate-500">Phạm vi MVP: không có đăng nhập/RBAC và tạo quy tắc tùy chỉnh thuộc v2.0. Demo này không xác nhận TLS, MySQL/Redis thật hay độ trễ GitHub đến staging.</p>
  </main>;
}
