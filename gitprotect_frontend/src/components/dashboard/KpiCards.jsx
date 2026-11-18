export default function KpiCards({ metrics }) {
  const cards = [
    { label: 'Tổng cảnh báo', value: metrics?.total_alerts ?? 0 },
    { label: 'Cảnh báo đang mở', value: metrics?.open_alerts ?? 0 },
    { label: 'Đã xử lý', value: metrics?.resolved_alerts ?? 0 },
    { label: 'Kho lưu trữ', value: metrics?.repositories_summary?.total_repos ?? 0 },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {cards.map((card) => (
        <div key={card.label} className="bg-white border border-slate-200 rounded-xl p-5">
          <p className="text-sm text-slate-500">{card.label}</p>
          <p className="mt-2 text-2xl font-semibold text-slate-900">{card.value}</p>
        </div>
      ))}
    </div>
  );
}
