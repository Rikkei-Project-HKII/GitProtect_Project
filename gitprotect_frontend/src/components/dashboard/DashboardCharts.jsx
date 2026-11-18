import { useEffect, useState } from 'react';
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Tooltip, Legend,
} from 'chart.js';
import { Line, Bar } from 'react-chartjs-2';
import { getTrend } from '../../api/dashboard';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, Tooltip, Legend);

export const SEV_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb' };
const SEVS = Object.keys(SEV_COLORS);

export function KpiCards({ metrics }) {
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {SEVS.map((s) => (
        <div key={s} className="rounded-lg border bg-white p-4 shadow-sm" style={{ borderTop: `4px solid ${SEV_COLORS[s]}` }}>
          <div className="text-xs font-semibold uppercase text-gray-500">{s}</div>
          <div className="mt-1 text-3xl font-bold">{metrics?.[s] ?? '—'}</div>
        </div>
      ))}
    </div>
  );
}

export function TrendChart() {
  const [granularity, setGranularity] = useState('day');
  const [data, setData] = useState(null);

  useEffect(() => {
    getTrend(granularity).then(setData).catch(() => setData({ points: [] }));
  }, [granularity]);

  const points = data?.points ?? [];
  const chartData = {
    labels: points.map((p) => p.period),
    datasets: SEVS.map((s) => ({
      label: s.toUpperCase(), data: points.map((p) => p[s]),
      borderColor: SEV_COLORS[s], backgroundColor: SEV_COLORS[s], tension: 0.3,
    })),
  };
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="font-semibold">Xu hướng rò rỉ</h3>
        <select className="rounded border px-2 py-1 text-sm" value={granularity} onChange={(e) => setGranularity(e.target.value)}>
          <option value="day">Theo ngày</option>
          <option value="week">Theo tuần</option>
        </select>
      </div>
      <Line data={chartData} options={{ responsive: true, interaction: { mode: 'index', intersect: false } }} />
    </div>
  );
}

export function RepoBreakdownChart({ items }) {
  const chartData = {
    labels: items.map((r) => r.repo_name),
    datasets: SEVS.map((s) => ({ label: s.toUpperCase(), data: items.map((r) => r[s]), backgroundColor: SEV_COLORS[s] })),
  };
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <h3 className="mb-2 font-semibold">Theo kho lưu trữ</h3>
      <Bar data={chartData} options={{ indexAxis: 'y', scales: { x: { stacked: true }, y: { stacked: true } } }} />
    </div>
  );
}