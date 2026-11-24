import { AlertTriangle, AlertCircle, Info, ShieldAlert, Activity, CheckCircle2 } from 'lucide-react';

export default function KpiCards({ metrics }) {
  const cards = [
    {
      title: 'Critical',
      count: metrics?.critical ?? 0,
      icon: ShieldAlert,
      textColor: 'text-red-700',
      bgColor: 'bg-red-50',
      borderColor: 'border-red-200',
      desc: 'Bí mật mức độ tối nguy hiểm (Private Keys, PAT)',
    },
    {
      title: 'High',
      count: metrics?.high ?? 0,
      icon: AlertTriangle,
      textColor: 'text-orange-700',
      bgColor: 'bg-orange-50',
      borderColor: 'border-orange-200',
      desc: 'Mật khẩu .env, AWS Key, CCCD Việt Nam',
    },
    {
      title: 'Medium',
      count: metrics?.medium ?? 0,
      icon: AlertCircle,
      textColor: 'text-amber-700',
      bgColor: 'bg-amber-50',
      borderColor: 'border-amber-200',
      desc: 'Generic High Entropy Secret, Token ứng dụng',
    },
    {
      title: 'Low',
      count: metrics?.low ?? 0,
      icon: Info,
      textColor: 'text-blue-700',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200',
      desc: 'Cảnh báo rủi ro thấp hoặc thư viện phụ thuộc',
    },
  ];

  return (
    <div className="space-y-4">
      {/* 4 Thẻ KPI Phân loại Severity */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.title}
              className={`rounded-xl border p-5 bg-white shadow-sm transition hover:shadow ${card.borderColor}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  {card.title}
                </span>
                <div className={`p-2 rounded-lg ${card.bgColor} ${card.textColor}`}>
                  <Icon className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3">
                <span className={`text-3xl font-bold ${card.textColor}`}>
                  {card.count}
                </span>
              </div>
              <p className="mt-2 text-xs text-slate-500 leading-relaxed">
                {card.desc}
              </p>
            </div>
          );
        })}
      </div>

      {/* Thẻ Thống kê tổng quan bổ sung */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-50 text-emerald-600">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-500">Tổng số cảnh báo</div>
            <div className="text-xl font-bold text-slate-800">{metrics?.total ?? 0}</div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-red-50 text-red-600">
            <AlertCircle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-500">Đang mở (Cần xử lý)</div>
            <div className="text-xl font-bold text-red-600">{metrics?.open_total ?? 0}</div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-50 text-purple-600">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-500">Điểm rủi ro (Risk Score)</div>
            <div className="text-xl font-bold text-purple-700">
              {metrics?.risk_score ?? 0}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
