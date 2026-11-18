import { NavLink } from 'react-router-dom';
import { Shield } from 'lucide-react';

export default function Navbar() {
  return (
    <header className="h-16 bg-white border-b border-slate-200 px-4 sm:px-6 flex items-center justify-between">
      <div className="flex items-center gap-3 md:hidden">
        <Shield className="w-6 h-6 text-emerald-600" />
        <span className="font-semibold text-slate-900">GitProtect</span>
      </div>
      <p className="hidden md:block text-sm text-slate-500">
        Internal Security Operations Dashboard
      </p>
      <nav className="flex items-center gap-2 text-sm">
        <NavLink to="/" className="px-2 py-1 text-slate-600 hover:text-emerald-700 md:hidden">
          Dashboard
        </NavLink>
        <NavLink to="/repos" className="px-2 py-1 text-slate-600 hover:text-emerald-700 md:hidden">
          Repo
        </NavLink>
        <span className="text-xs px-2 py-1 rounded-full bg-slate-100 text-slate-600">
          Internal Operator
        </span>
      </nav>
    </header>
  );
}
