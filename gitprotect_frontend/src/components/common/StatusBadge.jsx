import React from 'react';

const STATUS_CONFIG = {
  open: {
    bg: 'bg-red-50 text-red-700 border-red-200',
    label: 'Open',
  },
  in_review: {
    bg: 'bg-amber-50 text-amber-700 border-amber-200',
    label: 'In Review',
  },
  resolved: {
    bg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    label: 'Resolved',
  },
  false_positive: {
    bg: 'bg-slate-100 text-slate-700 border-slate-300',
    label: 'False Positive',
  },
  ignored: {
    bg: 'bg-purple-50 text-purple-700 border-purple-200',
    label: 'Ignored',
  },
  active: {
    bg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    label: 'Active',
  },
  error: {
    bg: 'bg-red-50 text-red-700 border-red-200',
    label: 'Error',
  },
};

export default function StatusBadge({ status }) {
  const key = String(status || 'open').toLowerCase();
  const config = STATUS_CONFIG[key] || {
    bg: 'bg-slate-100 text-slate-600 border-slate-200',
    label: status,
  };

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${config.bg}`}
    >
      {config.label}
    </span>
  );
}

