export default function LoadingSpinner({ label = 'Đang tải...' }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-12 text-center">
      <div className="inline-block w-8 h-8 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin mb-3" />
      <p className="text-sm text-slate-500">{label}</p>
    </div>
  );
}
