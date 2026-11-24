import { NavLink } from 'react-router-dom';
import { Shield, LayoutDashboard, GitBranch, Bell, PlayCircle } from 'lucide-react';

const links = [
  ...(import.meta.env.VITE_DEMO_MODE === 'true' ? [{ to: '/demo', label: 'Demo chức năng', icon: PlayCircle }] : []),
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/repos', label: 'Kho lưu trữ', icon: GitBranch },
  { to: '/alerts', label: 'Cảnh báo', icon: Bell },
];

export default function Sidebar() {
  return (
    <aside className="hidden md:flex w-64 shrink-0 flex-col bg-slate-900 text-slate-200">
      <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-800">
        <Shield className="w-7 h-7 text-emerald-400" />
        <div>
          <div className="font-bold tracking-tight text-white">GitProtect</div>
          <div className="text-[11px] text-emerald-300">MVP v1.1</div>
        </div>
      </div>
      <nav className="p-3 space-y-1">
        {links.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-emerald-500/15 text-emerald-300'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
