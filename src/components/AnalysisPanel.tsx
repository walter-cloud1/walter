import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  ImagePlus,
  Link2,
  Loader2,
  Mail,
  RotateCcw,
  ScanSearch,
  Trash2,
} from 'lucide-react';
import {
  analyzeEmailTextHeuristics,
  analyzeUrlHeuristics,
  computeHeuristicRiskScore,
} from '../utils/phishingHeuristics';
import { SAMPLE_CASES } from '../data/sampleCases';
import type {
  AnalysisInputType,
  AnalysisResult,
  SampleCase,
  ScanRecord,
} from '../types/phishguard';
import { ResultReport } from './ResultReport';

interface AnalysisPanelProps {
  prefillCase: SampleCase | null;
  resetToken: number;
  onAnalysisComplete: (record: ScanRecord) => void;
}

export function AnalysisPanel({
  prefillCase,
  resetToken,
  onAnalysisComplete,
}: AnalysisPanelProps) {
  const [mode, setMode] = useState<AnalysisInputType>('email');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [imageNotes, setImageNotes] = useState('');
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null);
  const [imageBase64, setImageBase64] = useState<string | null>(null);
  const [imageMimeType, setImageMimeType] = useState<string | null>(null);
  const [imageFileName, setImageFileName] = useState<string | null>(null);

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [latestScan, setLatestScan] = useState<ScanRecord | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!prefillCase) return;
    setErrorMsg(null);
    setLatestScan(null);
    if (prefillCase.type === 'url') {
      setMode('url');
      setUrlInput(prefillCase.content);
    } else {
      setMode('email');
      setSender(prefillCase.sender || '');
      setSubject(prefillCase.subject || '');
      setEmailBody(prefillCase.content);
    }
  }, [prefillCase]);

  useEffect(() => {
    if (resetToken === 0) return;
    setSender('');
    setSubject('');
    setEmailBody('');
    setUrlInput('');
    setImageNotes('');
    setImagePreviewUrl(null);
    setImageBase64(null);
    setImageMimeType(null);
    setImageFileName(null);
    setErrorMsg(null);
    setLatestScan(null);
  }, [resetToken]);

  const liveHeuristicPreview = useMemo(() => {
    if (mode === 'url' && urlInput.trim().length > 3) {
      const { findings } = analyzeUrlHeuristics(urlInput);
      const summary = computeHeuristicRiskScore(findings);
      return { findings, ...summary };
    }
    if (mode === 'email' && (emailBody.trim().length > 8 || sender.trim().length > 4)) {
      const { findings } = analyzeEmailTextHeuristics({
        sender,
        subject,
        body: emailBody,
      });
      const summary = computeHeuristicRiskScore(findings);
      return { findings, ...summary };
    }
    return null;
  }, [mode, urlInput, emailBody, sender, subject]);

  const handleLoadQuickSample = (kind: 'phishing' | 'legit') => {
    setErrorMsg(null);
    setLatestScan(null);
    if (mode === 'url') {
      setUrlInput(
        kind === 'phishing'
          ? 'http://intesa-sanpaolo-verifica.top/login/aggiorna'
          : 'https://www.intesasanpaolo.com'
      );
      return;
    }

    const chosen =
      kind === 'phishing'
        ? SAMPLE_CASES[0]
        : SAMPLE_CASES.find((c) => c.expectedVerdict === 'safe') || SAMPLE_CASES[4];
    setMode('email');
    setSender(chosen.sender || '');
    setSubject(chosen.subject || '');
    setEmailBody(chosen.content);
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    setErrorMsg(null);
    if (!file) return;

    const allowed = ['image/png', 'image/jpeg', 'image/webp'];
    if (!allowed.includes(file.type)) {
      setErrorMsg('Formato non supportato. Carica un’immagine PNG, JPEG o WebP.');
      return;
    }
    if (file.size > 6 * 1024 * 1024) {
      setErrorMsg('L’immagine supera il limite massimo di 6 MB.');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const resultStr = typeof reader.result === 'string' ? reader.result : '';
      const base64Part = resultStr.includes(',') ? resultStr.split(',')[1] : '';
      if (!base64Part) {
        setErrorMsg('Impossibile leggere il file selezionato.');
        return;
      }
      setImagePreviewUrl(resultStr);
      setImageBase64(base64Part);
      setImageMimeType(file.type);
      setImageFileName(file.name);
    };
    reader.readAsDataURL(file);
  };

  const handleClearImage = () => {
    setImagePreviewUrl(null);
    setImageBase64(null);
    setImageMimeType(null);
    setImageFileName(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (mode === 'email' && !emailBody.trim() && !subject.trim()) {
      setErrorMsg('Inserisci almeno l’oggetto o il testo del messaggio da analizzare.');
      return;
    }
    if (mode === 'url' && !urlInput.trim()) {
      setErrorMsg('Inserisci un URL o dominio da verificare.');
      return;
    }
    if (mode === 'image' && (!imageBase64 || !imageMimeType)) {
      setErrorMsg('Seleziona uno screenshot da sottoporre all’analisi visiva.');
      return;
    }

    setIsAnalyzing(true);
    try {
      const payload =
        mode === 'url'
          ? { type: 'url', url: urlInput.trim() }
          : mode === 'image'
            ? {
                type: 'image',
                imageBase64,
                imageMimeType,
                content: imageNotes.trim() || undefined,
              }
            : {
                type: 'email',
                sender: sender.trim() || undefined,
                subject: subject.trim() || undefined,
                content: emailBody.trim(),
              };

      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        setErrorMsg(data.error || 'Impossibile completare l’analisi in questo momento.');
        return;
      }

      const result = data as AnalysisResult;
      const scanTitle =
        mode === 'url'
          ? `Analisi URL: ${urlInput.trim()}`
          : mode === 'image'
            ? `Screenshot: ${imageFileName || 'Immagine caricata'}`
            : subject.trim() || sender.trim() || 'Analisi messaggio email';

      const targetPreview =
        mode === 'url'
          ? urlInput.trim()
          : mode === 'image'
            ? imageFileName || 'Screenshot'
            : sender.trim() || emailBody.trim().slice(0, 72);

      const newRecord: ScanRecord = {
        id: `scan-${Date.now()}`,
        type: mode,
        title: scanTitle,
        targetPreview,
        sender: mode === 'email' ? sender.trim() || undefined : undefined,
        subject: mode === 'email' ? subject.trim() || undefined : undefined,
        rawContent: mode === 'url' ? urlInput.trim() : emailBody.trim(),
        result,
        createdAt: result.analyzedAt,
        source: 'user',
      };

      setLatestScan(newRecord);
      onAnalysisComplete(newRecord);
    } catch {
      setErrorMsg('Errore di connessione con il server di analisi. Riprova.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            Ispezione Anti-Phishing
          </h2>
          <p className="mt-1 text-sm text-slate-600 max-w-2xl">
            Analizza email sospette, URL potenzialmente contraffatti o screenshot di pagine di login combinando controlli euristici deterministici e analisi semantica Gemini.
          </p>
        </div>

        {mode !== 'image' && (
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => handleLoadQuickSample('phishing')}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              Carica esempio phishing
            </button>
            <button
              type="button"
              onClick={() => handleLoadQuickSample('legit')}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              Carica esempio sicuro
            </button>
          </div>
        )}
      </div>

      {/* Modulo Principale di Scansione */}
      <form
        onSubmit={handleSubmit}
        className="rounded-xl border border-slate-200 bg-white p-6"
        noValidate
      >
        <div className="flex flex-col gap-3 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div
            role="tablist"
            aria-label="Modalità di analisi"
            className="grid w-full grid-cols-3 gap-1 rounded-lg bg-slate-100 p-1 sm:inline-flex sm:w-auto"
          >
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'email'}
              onClick={() => {
                setMode('email');
                setErrorMsg(null);
              }}
              className={`inline-flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 sm:px-3 ${
                mode === 'email'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Mail className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">Email</span>
              <span className="hidden sm:inline">o Messaggio</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={mode === 'url'}
              onClick={() => {
                setMode('url');
                setErrorMsg(null);
              }}
              className={`inline-flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 sm:px-3 ${
                mode === 'url'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Link2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">URL</span>
              <span className="hidden sm:inline">o Dominio</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={mode === 'image'}
              onClick={() => {
                setMode('image');
                setErrorMsg(null);
              }}
              className={`inline-flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 sm:px-3 ${
                mode === 'image'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <ImagePlus className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">Screenshot</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => {
              setSender('');
              setSubject('');
              setEmailBody('');
              setUrlInput('');
              setImageNotes('');
              handleClearImage();
              setErrorMsg(null);
            }}
            className="inline-flex items-center gap-1.5 self-end text-xs font-medium text-slate-500 hover:text-slate-800 whitespace-nowrap shrink-0 sm:self-auto"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Pulisci campi</span>
          </button>
        </div>

        <div className="mt-5 space-y-4">
          {mode === 'email' && (
            <>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label
                    htmlFor="pg-sender"
                    className="block text-xs font-medium text-slate-700"
                  >
                    Mittente (opzionale)
                  </label>
                  <input
                    id="pg-sender"
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder="es. Servizio Clienti <alert@dominio-esempio.top>"
                    className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-xs text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/20"
                  />
                </div>

                <div>
                  <label
                    htmlFor="pg-subject"
                    className="block text-xs font-medium text-slate-700"
                  >
                    Oggetto del messaggio (opzionale)
                  </label>
                  <input
                    id="pg-subject"
                    type="text"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="es. URGENTE: Verifica le coordinate entro 24 ore"
                    className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/20"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="pg-body"
                  className="block text-xs font-medium text-slate-700"
                >
                  Testo completo dell’email o SMS
                </label>
                <textarea
                  id="pg-body"
                  rows={6}
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  placeholder="Incolla qui il contenuto del messaggio sospetto, inclusi eventuali link o firme..."
                  className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm leading-relaxed text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/20"
                />
              </div>
            </>
          )}

          {mode === 'url' && (
            <div>
              <label
                htmlFor="pg-url"
                className="block text-xs font-medium text-slate-700"
              >
                Indirizzo URL o nome a dominio da ispezionare
              </label>
              <input
                id="pg-url"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="es. https://brt-it.consegna-rapida.xyz/pagamento"
                className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3.5 py-3 font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/20"
              />
            </div>
          )}

          {mode === 'image' && (
            <div className="space-y-4">
              <div>
                <label
                  htmlFor="pg-screenshot"
                  className="block text-xs font-medium text-slate-700"
                >
                  Screenshot della pagina o del messaggio (PNG, JPEG, WebP — max 6 MB)
                </label>

                {!imagePreviewUrl ? (
                  <div className="mt-1.5 flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50/70 px-6 py-10 text-center">
                    <ImagePlus className="h-8 w-8 text-slate-400" aria-hidden="true" />
                    <p className="mt-2 text-sm font-medium text-slate-800">
                      Seleziona uno screenshot da analizzare
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      L’analisi visiva estrae loghi contraffatti, URL visibili e testi di ingegneria sociale.
                    </p>
                    <input
                      ref={fileInputRef}
                      id="pg-screenshot"
                      type="file"
                      accept="image/png,image/jpeg,image/webp"
                      onChange={handleFileChange}
                      className="sr-only"
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="mt-4 rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-medium text-slate-800 hover:bg-slate-50"
                    >
                      Scegli file immagine
                    </button>
                  </div>
                ) : (
                  <div className="mt-1.5 rounded-lg bg-slate-50 p-4">
                    <div className="flex items-center justify-between gap-4 pb-3">
                      <span className="truncate font-mono text-xs text-slate-700">
                        {imageFileName}
                      </span>
                      <button
                        type="button"
                        onClick={handleClearImage}
                        aria-label="Rimuovi immagine selezionata"
                        className="inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium text-red-700 hover:bg-red-50"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Rimuovi</span>
                      </button>
                    </div>
                    <img
                      src={imagePreviewUrl}
                      alt="Anteprima screenshot caricato per analisi phishing"
                      referrerPolicy="no-referrer"
                      className="max-h-72 w-auto rounded-md border border-slate-200 object-contain"
                    />
                  </div>
                )}
              </div>

              <div>
                <label
                  htmlFor="pg-image-notes"
                  className="block text-xs font-medium text-slate-700"
                >
                  Contesto aggiuntivo (opzionale)
                </label>
                <input
                  id="pg-image-notes"
                  type="text"
                  value={imageNotes}
                  onChange={(e) => setImageNotes(e.target.value)}
                  placeholder="es. Ricevuto via WhatsApp da un numero sconosciuto"
                  className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600/20"
                />
              </div>
            </div>
          )}

          {/* Anteprima Euristica Istantanea */}
          {liveHeuristicPreview && liveHeuristicPreview.findings.length > 0 && (
            <div className="rounded-lg border border-amber-200 bg-amber-50/70 px-4 py-3 text-xs text-amber-950">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold">
                  Pre-controllo euristico istantaneo: {liveHeuristicPreview.findings.length}{' '}
                  {liveHeuristicPreview.findings.length === 1
                    ? 'anomalia tecnica rilevata'
                    : 'anomalie tecniche rilevate'}
                </span>
                <span className="font-mono font-medium tabular-nums">
                  Punteggio preliminare: {liveHeuristicPreview.score}/100
                </span>
              </div>
              <p className="mt-1 text-amber-800">
                {liveHeuristicPreview.findings.map((f) => f.title).join(' · ')}
              </p>
            </div>
          )}

          {errorMsg && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" aria-hidden="true" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
            <p className="text-xs text-slate-500">
              I contenuti inviati vengono esaminati combinando regole deterministiche locali e modello Gemini.
            </p>
            <button
              type="submit"
              disabled={isAnalyzing}
              className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60 whitespace-nowrap shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 focus-visible:ring-offset-2"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  <span>Analisi in corso...</span>
                </>
              ) : (
                <>
                  <ScanSearch className="h-4 w-4" aria-hidden="true" />
                  <span>Avvia Analisi PhishGuard</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Stato di Caricamento Skeleton */}
      {isAnalyzing && (
        <div
          aria-live="polite"
          className="rounded-xl border border-slate-200 bg-white p-6 space-y-4 animate-pulse"
        >
          <div className="h-5 w-48 rounded bg-slate-200" />
          <div className="h-4 w-full max-w-xl rounded bg-slate-100" />
          <div className="grid grid-cols-1 gap-4 pt-2 sm:grid-cols-3">
            <div className="h-16 rounded-lg bg-slate-100" />
            <div className="h-16 rounded-lg bg-slate-100" />
            <div className="h-16 rounded-lg bg-slate-100" />
          </div>
          <div className="h-24 rounded-lg bg-slate-100" />
        </div>
      )}

      {/* Risultato Analisi */}
      {!isAnalyzing && latestScan && (
        <ResultReport
          result={latestScan.result}
          title={latestScan.title}
          targetPreview={latestScan.targetPreview}
        />
      )}
    </div>
  );
}
