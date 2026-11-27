import { ChevronRight, Menu, Plus } from 'lucide-react';
import type { ActiveView } from './Sidebar';

interface TopBarProps {
  activeView: ActiveView;
  onOpenMobileMenu: () => void;
  onNewScan: () => void;
}

const VIEW_LABELS: Record<ActiveView, string> = {
  analyze: 'Analisi Rapida',
  history: 'Registro Minacce',
  cases: 'Laboratorio Casi',
  guidelines: 'Regole e Indicatori',
};

export function TopBar({ activeView, onOpenMobileMenu, onNewScan }: TopBarProps) {
  return (
    <header className="flex h-16 shrink-0 items-center justify-between gap-8 border-b border-slate-200 bg-white px-4 sm:px-6 lg:px-8">
      <div className="flex min-w-0 items-center gap-3">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Apri menu di navigazione"
          className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-slate-200 text-slate-700 hover:bg-slate-50 lg:hidden"
        >
          <Menu className="h-4 w-4" aria-hidden="true" />
        </button>

        <nav aria-label="Percorso pagina" className="flex min-w-0 items-center gap-2 text-sm">
          <span className="hidden text-slate-500 sm:inline whitespace-nowrap">
            PhishGuard IA
          </span>
          <ChevronRight
            className="hidden h-3.5 w-3.5 text-slate-400 sm:inline shrink-0"
            aria-hidden="true"
          />
          <h1 className="truncate font-display text-sm font-semibold text-slate-900 sm:text-base">
            {VIEW_LABELS[activeView]}
          </h1>
        </nav>
      </div>

      <div className="flex shrink-0 items-center">
        <button
          type="button"
          onClick={onNewScan}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 whitespace-nowrap shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 focus-visible:ring-offset-2"
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
          <span>Nuova Analisi</span>
        </button>
      </div>
    </header>
  );
}
