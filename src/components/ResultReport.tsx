import { useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { AnalysisFinding, AnalysisResult, RiskVerdict } from '../types/phishguard';

interface ResultReportProps {
  result: AnalysisResult;
  title?: string;
  targetPreview?: string;
}

const VERDICT_CONFIG: Record<
  RiskVerdict,
  {
    label: string;
    sublabel: string;
    textColor: string;
    surfaceColor: string;
    barColor: string;
    icon: typeof ShieldCheck;
  }
> = {
  phishing: {
    label: 'Phishing Rilevato',
    sublabel: 'Minaccia ad alto rischio',
    textColor: 'text-red-700',
    surfaceColor: 'bg-red-50 border-red-200',
    barColor: 'bg-red-600',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Sospetto — Verifica Richiesta',
    sublabel: 'Anomalie rilevate',
    textColor: 'text-amber-700',
    surfaceColor: 'bg-amber-50 border-amber-200',
    barColor: 'bg-amber-500',
    icon: AlertTriangle,
  },
  safe: {
    label: 'Sicuro / Coerente',
    sublabel: 'Nessun segnale critico rilevato',
    textColor: 'text-emerald-700',
    surfaceColor: 'bg-emerald-50 border-emerald-200',
    barColor: 'bg-emerald-600',
    icon: CheckCircle2,
  },
};

const SEVERITY_LABEL: Record<AnalysisFinding['severity'], { text: string; className: string }> = {
  high: { text: 'Severità Alta', className: 'text-red-700' },
  medium: { text: 'Severità Media', className: 'text-amber-700' },
  low: { text: 'Severità Bassa', className: 'text-slate-600' },
};

export function ResultReport({ result, title, targetPreview }: ResultReportProps) {
  const [copied, setCopied] = useState(false);
  const config = VERDICT_CONFIG[result.verdict];
  const VerdictIcon = config.icon;

  const formattedTime = new Date(result.analyzedAt).toLocaleString('it-IT', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const handleCopySummary = async () => {
    const lines = [
      `PhishGuard IA — Report Analisi`,
      title ? `Oggetto: ${title}` : null,
      targetPreview ? `Target: ${targetPreview}` : null,
      `Verdetto: ${config.label} (Rischio ${result.riskScore}/100, Affidabilità ${result.confidence}%)`,
      result.impersonatedBrand ? `Brand impersonificato: ${result.impersonatedBrand}` : null,
      `Sintesi: ${result.summary}`,
      ``,
      `Indicatori principali:`,
      ...result.findings.map(
        (f) => `- [${SEVERITY_LABEL[f.severity].text}] ${f.title}: ${f.description}`
      ),
      ``,
      `Azioni consigliate:`,
      ...result.recommendations.map((r) => `- ${r}`),
    ]
      .filter(Boolean)
      .join('\n');

    try {
      await navigator.clipboard.writeText(lines);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard fallback ignored silently
    }
  };

  const handleExportJson = () => {
    const payload = {
      title: title || 'Analisi PhishGuard IA',
      targetPreview: targetPreview || null,
      ...result,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishguard-report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section
      aria-label="Risultato dell'analisi di sicurezza"
      className="rounded-xl border border-slate-200 bg-white"
    >
      {/* Header Verdetto & Metriche */}
      <div className="p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 space-y-1.5">
            <div className={`inline-flex items-center gap-2 text-sm font-semibold ${config.textColor}`}>
              <VerdictIcon className="h-5 w-5 shrink-0" aria-hidden="true" />
              <span>{config.label}</span>
            </div>

            {title && (
              <h2 className="font-display text-lg font-semibold text-slate-900">
                {title}
              </h2>
            )}

            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
              <span>{config.sublabel}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{formattedTime}</span>
              {result.impersonatedBrand && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="font-medium text-slate-700">
                    Brand coinvolto: {result.impersonatedBrand}
                  </span>
                </>
              )}
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={handleCopySummary}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
                  <span>Copiato</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Copia Sintesi</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Esporta JSON</span>
            </button>
          </div>
        </div>

        {/* Barra Punteggio Rischio e Metriche Tabulari */}
        <div className="mt-6 grid grid-cols-1 gap-4 border-t border-slate-100 pt-5 sm:grid-cols-3">
          <div>
            <p className="text-xs font-medium text-slate-500">Indice di Rischio</p>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className={`font-mono text-2xl font-semibold tabular-nums ${config.textColor}`}>
                {result.riskScore}
              </span>
              <span className="font-mono text-xs text-slate-400 tabular-nums">/ 100</span>
            </div>
            <div
              className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-100"
              role="progressbar"
              aria-valuenow={result.riskScore}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Indice di rischio"
            >
              <div
                className={`h-full transition-all duration-300 ${config.barColor}`}
                style={{ width: `${result.riskScore}%` }}
              />
            </div>
          </div>

          <div>
            <p className="text-xs font-medium text-slate-500">Affidabilità Modello</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
              {result.confidence}%
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Correlazione euristica e semantica
            </p>
          </div>

          <div>
            <p className="text-xs font-medium text-slate-500">Indicatori Rilevati</p>
            <p className="mt-1 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
              {result.findings.length}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              URL estratti:{' '}
              <span className="font-mono tabular-nums text-slate-700">
                {result.extractedUrls.length}
              </span>
            </p>
          </div>
        </div>

        {/* Sintesi Esecutiva */}
        <div className="mt-5 border-t border-slate-100 pt-5">
          <h3 className="text-xs font-semibold text-slate-900">Valutazione Esecutiva</h3>
          <p className="mt-1.5 text-sm leading-relaxed text-slate-700">{result.summary}</p>
          {result.technicalNotes && (
            <p className="mt-2 text-xs text-slate-500">
              Nota tecnica: {result.technicalNotes}
            </p>
          )}
        </div>
      </div>

      {/* URL Estratti (se presenti) */}
      {result.extractedUrls.length > 0 && (
        <div className="border-t border-slate-200 p-6">
          <h3 className="text-sm font-semibold text-slate-900">
            Collegamenti Rilevati nell’Analisi
          </h3>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="py-2 pr-4 font-medium">Dominio / Host</th>
                  <th className="py-2 pr-4 font-medium">Protocollo</th>
                  <th className="py-2 pr-4 font-medium">Stato</th>
                  <th className="py-2 font-medium">URL Completo</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {result.extractedUrls.map((item) => (
                  <tr key={item.url} className="hover:bg-slate-50/70">
                    <td className="py-2.5 pr-4 font-mono font-medium text-slate-900">
                      {item.hostname}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-slate-600">
                      {item.protocol}
                    </td>
                    <td className="py-2.5 pr-4">
                      {item.suspicious ? (
                        <span className="font-medium text-red-700">
                          Sospetto {item.reason ? `· ${item.reason}` : ''}
                        </span>
                      ) : (
                        <span className="font-medium text-emerald-700">Coerente</span>
                      )}
                    </td>
                    <td className="max-w-xs truncate py-2.5 font-mono text-slate-600" title={item.url}>
                      <span className="inline-flex items-center gap-1">
                        <ExternalLink className="h-3 w-3 shrink-0 text-slate-400" aria-hidden="true" />
                        <span className="truncate">{item.url}</span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Segnali e Indicatori Rilevati */}
      <div className="border-t border-slate-200 p-6">
        <h3 className="text-sm font-semibold text-slate-900">
          Segnali Tecnici e Comportamentali
        </h3>

        {result.findings.length === 0 ? (
          <p className="mt-3 text-sm text-slate-600">
            Nessuna anomalia rilevata dagli indicatori analizzati.
          </p>
        ) : (
          <ul className="mt-4 divide-y divide-slate-100">
            {result.findings.map((finding) => {
              const sev = SEVERITY_LABEL[finding.severity];
              return (
                <li key={finding.id} className="py-3.5 first:pt-0 last:pb-0">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <p className="text-sm font-medium text-slate-900">{finding.title}</p>
                    <div className="flex items-center gap-2 text-xs">
                      <span className={`font-medium ${sev.className}`}>{sev.text}</span>
                      <span className="text-slate-300" aria-hidden="true">·</span>
                      <span className="text-slate-500">{finding.category}</span>
                    </div>
                  </div>
                  <p className="mt-1 text-sm text-slate-600">{finding.description}</p>
                  {finding.evidence && (
                    <p className="mt-1.5 font-mono text-xs text-slate-700 bg-slate-50 px-2.5 py-1.5 rounded-md inline-block max-w-full overflow-x-auto">
                      Evidenza: {finding.evidence}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Azioni Consigliate */}
      <div className="border-t border-slate-200 bg-slate-50/60 p-6 rounded-b-xl">
        <h3 className="text-sm font-semibold text-slate-900">Azioni Consigliate</h3>
        <ul className="mt-3 space-y-2">
          {result.recommendations.map((rec, index) => (
            <li key={index} className="flex items-start gap-2.5 text-sm text-slate-700">
              <span className="font-mono text-xs font-semibold text-blue-700 mt-0.5 tabular-nums">
                0{index + 1}.
              </span>
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
