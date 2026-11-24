import { useEffect, useState } from 'react';
import { getAuthorAudit } from '../../api/auditApi';
import axiosClient from '../../api/axiosClient';

export default function AuthorAuditPanel() {
  const [repos, setRepos] = useState([]);
  const [repoId, setRepoId] = useState('');
  const [page, setPage] = useState(1);
  const [report, setReport] = useState(null);
  const [loadingRepos, setLoadingRepos] = useState(true);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const request = new AbortController();
    async function loadRepos() {
      const items = [];
      let current = 1;
      while (!request.signal.aborted) {
        const data = await axiosClient.get('/repos', {
          params: { page: current, page_size: 50 }, signal: request.signal
        });
        items.push(...data.items);
        if (!data.items.length || items.length >= data.total) break;
        current += 1;
      }
      if (!request.signal.aborted) {
        setRepos(items);
        setRepoId(old => items.some(r => String(r.id) === old) ? old : String(items[0]?.id ?? ''));
        setLoadingRepos(false);
      }
    }
    loadRepos().catch(() => {
      if (!request.signal.aborted) {
        setError('Không tải được danh sách kho.');
        setLoadingRepos(false);
      }
    });
    return () => request.abort();
  }, [refresh]);

  useEffect(() => {
    if (!repoId || loadingRepos) return;
    const request = new AbortController();
    getAuthorAudit(repoId, page, request.signal)
      .then(data => { if (!request.signal.aborted) setReport(data); })
      .catch(() => { if (!request.signal.aborted) setError('Không tải được báo cáo tác giả.'); });
    return () => request.abort();
  }, [repoId, page, refresh, loadingRepos]);

  const changePage = p => { setReport(null); setError(''); setPage(p); };
  return (
    <section className="space-y-3 rounded-lg border border-slate-200 bg-white p-5" aria-label="Kiểm toán tác giả">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">Kiểm toán tác giả commit</h2>
        {repos.length > 0 && <select aria-label="Kho cần kiểm toán" value={repoId}
          className="max-w-full rounded border px-2 py-1"
          onChange={e => { changePage(1); setRepoId(e.target.value); }}>
          {repos.map(repo => <option key={repo.id} value={repo.id}>{repo.repo_name}</option>)}
        </select>}
      </div>
      {error ? <div role="alert">{error} <button className="underline" onClick={() => {
        setReport(null); setError(''); setLoadingRepos(true); setRefresh(x => x+1);
      }}>Thử lại</button></div>
        : loadingRepos || (repoId && !report) ? <p role="status">Đang tải báo cáo…</p>
        : !repoId ? <p>Chưa có kho kết nối.</p>
        : report && <>
          <p>{report.spoofing_violations_count} commit cần rà soát / {report.total_commits_audited} commit đã kiểm toán.</p>
          {report.total_commits_audited === 0 && <p>Chưa có commit được kiểm toán cho kho này.</p>}
          {report.spoofing_violations_count > 0 && <div className="rounded border-l-4 border-amber-600 bg-amber-50 p-3">
            <strong className="text-amber-900">Email Spoofing Notice</strong>
            <ul className="mt-2 space-y-2">{report.items.map(item => <li key={item.commit_sha}>
              <code title={item.commit_sha}>{item.commit_sha.slice(0, 10)}</code>{' · '}
              <span className="break-all">{item.author_name} &lt;{item.author_email}&gt;</span>
              <p className="text-sm text-slate-700">{item.reasons.join(' · ')}</p>
            </li>)}</ul>
          </div>}
          {report.spoofing_violations_count > report.page_size && <div className="flex gap-3">
            <button disabled={page === 1} onClick={() => changePage(page-1)}>Trước</button>
            <span>Trang {page}</span>
            <button disabled={page*report.page_size >= report.spoofing_violations_count}
              onClick={() => changePage(page+1)}>Sau</button>
          </div>}
        </>}
    </section>
  );
}
