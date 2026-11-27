import {
  BookOpen,
  FlaskConical,
  History,
  ScanSearch,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { ScanRecord } from '../types/phishguard';

export type ActiveView = 'analyze' | 'history' | 'cases' | 'guidelines';

interface SidebarProps {
  activeView: ActiveView;
  onSelectView: (view: ActiveView) => void;
  scans: ScanRecord[];
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({
  activeView,
  onSelectView,
  scans,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const phishingCount = scans.filter((s) => s.result.verdict === 'phishing').length;
  const suspiciousCount = scans.filter((s) => s.result.verdict === 'suspicious').length;

  const navItems: Array<{
    id: ActiveView;
    label: string;
    icon: typeof ScanSearch;
    count?: number;
  }> = [
    { id: 'analyze', label: 'Analisi Rapida', icon: ScanSearch },
    { id: 'history', label: 'Registro Minacce', icon: History, count: scans.length },
    { id: 'cases', label: 'Laboratorio Casi', icon: FlaskConical },
    { id: 'guidelines', label: 'Regole e Indicatori', icon: BookOpen },
  ];

  const handleNavClick = (view: ActiveView) => {
    onSelectView(view);
    onCloseMobile();
  };

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-slate-900/40 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        aria-label="Navigazione principale"
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-slate-200 bg-white transition-transform duration-200 ease-out lg:static lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-slate-200 px-5">
          <button
            type="button"
            onClick={() => handleNavClick('analyze')}
            className="flex items-center gap-2.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded-md"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-900 text-white">
              <ShieldCheck className="h-4.5 w-4.5" aria-hidden="true" />
            </span>
            <span className="font-display text-base font-bold tracking-tight text-slate-900 whitespace-nowrap">
              PhishGuard IA
            </span>
          </button>

          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Chiudi menu laterale"
            className="rounded-md p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 lg:hidden"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNavClick(item.id)}
                aria-current={isActive ? 'page' : undefined}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium transition-colors whitespace-nowrap focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 ${
                  isActive
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <span className="flex items-center gap-2.5 truncate">
                  <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span className="truncate">{item.label}</span>
                </span>
                {typeof item.count === 'number' && (
                  <span
                    className={`font-mono text-xs tabular-nums ${
                      isActive ? 'text-slate-300' : 'text-slate-500'
                    }`}
                  >
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="border-t border-slate-200 px-5 py-4">
          <p className="text-xs font-medium text-slate-500">Riepilogo Archivio</p>
          <dl className="mt-2.5 space-y-1.5 text-xs">
            <div className="flex items-center justify-between">
              <dt className="text-slate-600">Scansioni salvate</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                {scans.length}
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-slate-600">Phishing confermati</dt>
              <dd className="font-mono font-medium text-red-700 tabular-nums">
                {phishingCount}
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-slate-600">Casi sospetti</dt>
              <dd className="font-mono font-medium text-amber-700 tabular-nums">
                {suspiciousCount}
              </dd>
            </div>
          </dl>
        </div>
      </aside>
    </>
  );
}
