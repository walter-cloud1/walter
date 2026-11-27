import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Eye,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { filterAndSortScans } from '../utils/phishingHeuristics';
import type { RiskFilter, RiskVerdict, ScanRecord } from '../types/phishguard';
import { ResultReport } from './ResultReport';

interface ThreatLogViewProps {
  scans: ScanRecord[];
  onDeleteScan: (id: string) => void;
  onStartNewAnalysis: () => void;
}

const VERDICT_META: Record<
  RiskVerdict,
  { label: string; textClass: string; icon: typeof ShieldAlert }
> = {
  phishing: {
    label: 'Phishing',
    textClass: 'text-red-700',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Sospetto',
    textClass: 'text-amber-700',
    icon: AlertTriangle,
  },
  safe: {
    label: 'Sicuro',
    textClass: 'text-emerald-700',
    icon: CheckCircle2,
  },
};

const TYPE_LABEL: Record<ScanRecord['type'], string> = {
  email: 'Email / Testo',
  url: 'URL / Dominio',
  image: 'Screenshot',
};

export function ThreatLogView({
  scans,
  onDeleteScan,
  onStartNewAnalysis,
}: ThreatLogViewProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<RiskFilter>('all');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const filteredScans = useMemo(
    () => filterAndSortScans(scans, query, filter),
    [scans, query, filter]
  );

  const selectedScan = useMemo(
    () => scans.find((s) => s.id === selectedScanId) || null,
    [scans, selectedScanId]
  );

  const counts = useMemo(
    () => ({
      all: scans.length,
      phishing: scans.filter((s) => s.result.verdict === 'phishing').length,
      suspicious: scans.filter((s) => s.result.verdict === 'suspicious').length,
      safe: scans.filter((s) => s.result.verdict === 'safe').length,
    }),
    [scans]
  );

  if (selectedScan) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-4">
          <button
            type="button"
            onClick={() => setSelectedScanId(null)}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Torna al Registro Minacce</span>
          </button>

          <button
            type="button"
            onClick={() => {
              onDeleteScan(selectedScan.id);
              setSelectedScanId(null);
            }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-white px-3 py-2 text-xs font-medium text-red-700 hover:bg-red-50"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Elimina voce</span>
          </button>
        </div>

        <ResultReport
          result={selectedScan.result}
          title={selectedScan.title}
          targetPreview={selectedScan.targetPreview}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            Registro Minacce e Scansioni
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Archivio cronologico delle ispezioni eseguite con verdetti, punteggi di rischio e dettagli tecnici.
          </p>
        </div>
      </div>

      {/* Barra di ricerca e filtri */}
      <div className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-4 md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
            aria-hidden="true"
          />
          <label htmlFor="pg-log-search" className="sr-only">
            Cerca nel registro minacce
          </label>
          <input
            id="pg-log-search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Cerca per dominio, mittente, brand o titolo..."
            className="w-full rounded-lg border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/20"
          />
        </div>

        <div
          role="group"
          aria-label="Filtra per verdetto"
          className="inline-flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1"
        >
          {(
            [
              { id: 'all', label: 'Tutti' },
              { id: 'phishing', label: 'Phishing' },
              { id: 'suspicious', label: 'Sospetti' },
              { id: 'safe', label: 'Sicuri' },
            ] as const
          ).map((tab) => {
            const active = filter === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                aria-pressed={active}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <span>{tab.label}</span>
                <span className="font-mono text-slate-400 tabular-nums">
                  {counts[tab.id]}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tabella Scansioni */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
        {scans.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <p className="font-display text-base font-semibold text-slate-900">
              Nessuna scansione nel registro
            </p>
            <p className="mt-1 text-sm text-slate-600">
              Avvia la prima analisi su un’email, un URL o uno screenshot per popolare lo storico.
            </p>
            <button
              type="button"
              onClick={onStartNewAnalysis}
              className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
            >
              Avvia Prima Analisi
            </button>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <p className="font-display text-base font-semibold text-slate-900">
              Nessun risultato corrisponde ai filtri
            </p>
            <p className="mt-1 text-sm text-slate-600">
              Modifica il testo cercato o ripristina il filtro dei verdetti.
            </p>
            <button
              type="button"
              onClick={() => {
                setQuery('');
                setFilter('all');
              }}
              className="mt-4 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              Reimposta filtri
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/70 text-xs text-slate-500">
                  <th className="px-5 py-3 font-medium">Oggetto / Target</th>
                  <th className="px-4 py-3 font-medium">Tipo</th>
                  <th className="px-4 py-3 font-medium">Verdetto</th>
                  <th className="px-4 py-3 text-right font-medium">Rischio</th>
                  <th className="px-4 py-3 text-right font-medium">Data</th>
                  <th className="px-5 py-3 text-right font-medium">Azioni</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredScans.map((scan) => {
                  const meta = VERDICT_META[scan.result.verdict];
                  const VerdictIcon = meta.icon;
                  const dateLabel = new Date(scan.createdAt).toLocaleDateString('it-IT', {
                    day: '2-digit',
                    month: 'short',
                    hour: '2-digit',
                    minute: '2-digit',
                  });

                  return (
                    <tr
                      key={scan.id}
                      className="transition-colors hover:bg-slate-50/80"
                    >
                      <td className="px-5 py-3">
                        <div className="max-w-sm">
                          <p className="truncate font-medium text-slate-900">{scan.title}</p>
                          <p className="truncate font-mono text-xs text-slate-500">
                            {scan.targetPreview}
                          </p>
                        </div>
                      </td>

                      <td className="px-4 py-3 text-xs text-slate-600 whitespace-nowrap">
                        {TYPE_LABEL[scan.type]}
                      </td>

                      <td className="px-4 py-3 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 text-xs font-semibold ${meta.textClass}`}
                        >
                          <VerdictIcon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                          <span>{meta.label}</span>
                        </span>
                      </td>

                      <td className="px-4 py-3 text-right font-mono text-xs font-semibold text-slate-900 tabular-nums whitespace-nowrap">
                        {scan.result.riskScore} / 100
                      </td>

                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-500 tabular-nums whitespace-nowrap">
                        {dateLabel}
                      </td>

                      <td className="px-5 py-3 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            onClick={() => setSelectedScanId(scan.id)}
                            aria-label={`Ispeziona ${scan.title}`}
                            className="inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-50"
                          >
                            <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Dettagli</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => onDeleteScan(scan.id)}
                            aria-label={`Elimina ${scan.title}`}
                            className="inline-flex items-center rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-700"
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
