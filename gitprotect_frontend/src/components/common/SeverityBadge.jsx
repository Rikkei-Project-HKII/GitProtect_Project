import React from 'react';

const SEVERITY_CONFIG = {
  critical: {
    bg: 'bg-red-50 text-red-700 border-red-200',
    dot: 'bg-red-500',
    label: 'Critical',
  },
  high: {
    bg: 'bg-orange-50 text-orange-700 border-orange-200',
    dot: 'bg-orange-500',
    label: 'High',
  },
  medium: {
    bg: 'bg-amber-50 text-amber-700 border-amber-200',
    dot: 'bg-amber-500',
    label: 'Medium',
  },
  low: {
    bg: 'bg-blue-50 text-blue-700 border-blue-200',
    dot: 'bg-blue-500',
    label: 'Low',
  },
};

export default function SeverityBadge({ severity }) {
  const key = String(severity || 'low').toLowerCase();
  const config = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.low;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${config.bg}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  );
}

