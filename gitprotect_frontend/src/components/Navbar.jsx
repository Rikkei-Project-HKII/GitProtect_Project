import React from 'react';
import { ShieldAlert, GitBranch, RefreshCw, Layers } from 'lucide-react';

export const Navbar = ({ onRefresh, isRefreshing }) => {
    return (
        <header class="bg-slate-800/80 backdrop-blur border-b border-slate-700/60 sticky top-0 z-40">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
                        <ShieldAlert class="w-6 h-6" />
                    </div>
                    <div>
                        <h1 class="text-lg font-bold text-white tracking-wide flex items-center gap-2">
                            GitProtect <span class="text-xs font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">MVP v1.1</span>
                        </h1>
                        <p class="text-xs text-slate-400">Internal Operator Security & Repo Manager</p>
                    </div>
                </div>

                <div class="flex items-center space-x-4">
                    <button
                        onClick={onRefresh}
                        disabled={isRefreshing}
                        class="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-600/50 transition-all disabled:opacity-50"
                    >
                        <RefreshCw class={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-blue-400' : ''}`} />
                        Làm mới
                    </button>
                    <div class="h-4 w-[1px] bg-slate-700"></div>
                    <span class="inline-flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        Internal Operator
                    </span>
                </div>
            </div>
        </header>
    );
};