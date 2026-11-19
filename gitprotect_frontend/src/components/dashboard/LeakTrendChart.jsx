import React, { useEffect, useRef, useState } from 'react';
import Chart from 'chart.js/auto';
import { dashboardApi } from '../../api/dashboardApi';
import { Calendar, TrendingUp } from 'lucide-react';

export default function LeakTrendChart() {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);
  const [granularity, setGranularity] = useState('day');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const fetchAndRender = async () => {
      try {
        setLoading(true);
        const data = await dashboardApi.getTrend({ granularity, days: 30 });
        if (cancelled || !chartRef.current) return;

        const points = data?.points || [];
        const labels = points.map((p) => p.period);
        const criticalData = points.map((p) => p.critical || 0);
        const highData = points.map((p) => p.high || 0);
        const mediumData = points.map((p) => p.medium || 0);
        const lowData = points.map((p) => p.low || 0);

        if (chartInstance.current) {
          chartInstance.current.destroy();
        }

        const ctx = chartRef.current.getContext('2d');
        chartInstance.current = new Chart(ctx, {
          type: 'line',
          data: {
            labels: labels.length > 0 ? labels : ['Không có dữ liệu'],
            datasets: [
              {
                label: 'Critical',
                data: criticalData.length > 0 ? criticalData : [0],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                tension: 0.3,
                fill: true,
              },
              {
                label: 'High',
                data: highData.length > 0 ? highData : [0],
                borderColor: '#f97316',
                backgroundColor: 'rgba(249, 115, 22, 0.1)',
                tension: 0.3,
                fill: true,
              },
              {
                label: 'Medium',
                data: mediumData.length > 0 ? mediumData : [0],
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                tension: 0.3,
                fill: false,
              },
              {
                label: 'Low',
                data: lowData.length > 0 ? lowData : [0],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.3,
                fill: false,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'top',
                labels: {
                  boxWidth: 12,
                  font: { size: 12 },
                },
              },
              tooltip: {
                mode: 'index',
                intersect: false,
              },
            },
            scales: {
              y: {
                beginAtZero: true,
                ticks: { precision: 0 },
                grid: { color: '#f1f5f9' },
              },
              x: {
                grid: { display: false },
              },
            },
          },
        });
      } catch (err) {
        console.error('Không thể tải biểu đồ xu hướng rò rỉ:', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchAndRender();

    return () => {
      cancelled = true;
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [granularity]);

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-emerald-600" />
          <h3 className="font-semibold text-slate-800">
            Xu hướng phát hiện rò rỉ theo thời gian
          </h3>
        </div>
        <div className="inline-flex items-center p-0.5 rounded-lg bg-slate-100 border border-slate-200 text-xs font-medium">
          <button
            type="button"
            onClick={() => setGranularity('day')}
            className={`px-3 py-1 rounded-md transition-colors ${
              granularity === 'day'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Theo ngày
          </button>
          <button
            type="button"
            onClick={() => setGranularity('week')}
            className={`px-3 py-1 rounded-md transition-colors ${
              granularity === 'week'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Theo tuần
          </button>
        </div>
      </div>

      <div className="relative h-64 sm:h-72 w-full">
        {loading && (
          <div className="absolute inset-0 bg-white/70 flex items-center justify-center z-10">
            <span className="text-xs text-slate-500 animate-pulse">Đang tải biểu đồ Chart.js...</span>
          </div>
        )}
        <canvas ref={chartRef} />
      </div>
    </div>
  );
}

