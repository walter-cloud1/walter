import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ShieldAlert,
} from 'lucide-react';
import { SAMPLE_CASES } from '../data/sampleCases';
import type { RiskVerdict, SampleCase } from '../types/phishguard';

interface CaseLabViewProps {
  onLoadCaseIntoScanner: (sample: SampleCase) => void;
}

const EXPECTED_META: Record<
  RiskVerdict,
  { label: string; className: string; icon: typeof ShieldAlert }
> = {
  phishing: {
    label: 'Phishing atteso',
    className: 'text-red-700',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Sospetto (BEC)',
    className: 'text-amber-700',
    icon: AlertTriangle,
  },
  safe: {
    label: 'Legittimo',
    className: 'text-emerald-700',
    icon: CheckCircle2,
  },
};

export function CaseLabView({ onLoadCaseIntoScanner }: CaseLabViewProps) {
  const [categoryFilter, setCategoryFilter] = useState<string>('Tutti');

  const categories = useMemo(
    () => ['Tutti', 'Bancario', 'Logistica', 'Aziendale (BEC)', 'Cloud & Account', 'Legittimo'],
    []
  );

  const visibleCases = useMemo(() => {
    if (categoryFilter === 'Tutti') return SAMPLE_CASES;
    return SAMPLE_CASES.filter((c) => c.category === categoryFilter);
  }, [categoryFilter]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          Laboratorio Casi Reali
        </h2>
        <p className="mt-1 text-sm text-slate-600 max-w-2xl">
          Esplora scenari di phishing ricorrenti e comunicazioni legittime di controllo. Carica qualsiasi caso nello scanner principale per osservare come vengono valutati gli indicatori.
        </p>
      </div>

      {/* Filtro categorie */}
      <div
        role="group"
        aria-label="Filtra scenari per categoria"
        className="inline-flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1"
      >
        {categories.map((cat) => {
          const active = categoryFilter === cat;
          return (
            <button
              key={cat}
              type="button"
              onClick={() => setCategoryFilter(cat)}
              aria-pressed={active}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                active
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {cat}
            </button>
          );
        })}
      </div>

      {/* Griglia Casi */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {visibleCases.map((sample) => {
          const meta = EXPECTED_META[sample.expectedVerdict];
          const VerdictIcon = meta.icon;

          return (
            <article
              key={sample.id}
              className="flex flex-col justify-between rounded-xl border border-slate-200 bg-white p-6"
            >
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                  <span>
                    {sample.category} · Livello {sample.difficulty} ·{' '}
                    {sample.type === 'url' ? 'URL' : 'Email'}
                  </span>
                  <span className={`inline-flex items-center gap-1 font-semibold ${meta.className}`}>
                    <VerdictIcon className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{meta.label}</span>
                  </span>
                </div>

                <h3 className="mt-2 font-display text-lg font-semibold text-slate-900">
                  {sample.title}
                </h3>

                <p className="mt-1.5 text-sm text-slate-600">{sample.description}</p>

                <div className="mt-4 rounded-lg bg-slate-50 p-3.5 font-mono text-xs text-slate-700 space-y-1">
                  {sample.sender && (
                    <p className="truncate">
                      <span className="text-slate-400">Da:</span> {sample.sender}
                    </p>
                  )}
                  {sample.subject && (
                    <p className="truncate font-sans font-medium text-slate-800">
                      <span className="font-mono font-normal text-slate-400">Ogg:</span>{' '}
                      {sample.subject}
                    </p>
                  )}
                  <p className="line-clamp-3 whitespace-pre-wrap break-all text-slate-600">
                    {sample.content}
                  </p>
                </div>

                <p className="mt-3 text-xs leading-relaxed text-slate-600">
                  <span className="font-semibold text-slate-800">Punto chiave:</span>{' '}
                  {sample.learningPoint}
                </p>
              </div>

              <div className="mt-5 border-t border-slate-100 pt-4 flex justify-end">
                <button
                  type="button"
                  onClick={() => onLoadCaseIntoScanner(sample)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-slate-800 whitespace-nowrap shrink-0"
                >
                  <span>Analizza nello Scanner</span>
                  <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
