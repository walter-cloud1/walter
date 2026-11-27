import { useState } from 'react';
import { CheckSquare, RotateCcw, Square } from 'lucide-react';

interface ChecklistItem {
  id: string;
  label: string;
  detail: string;
}

const TRIAGE_CHECKLIST: ChecklistItem[] = [
  {
    id: 'chk-domain',
    label: 'Controlla il dominio radice prima del primo "/"',
    detail:
      'In "brt-it.consegna-rapida.xyz/login", il dominio effettivo è "consegna-rapida.xyz", non BRT.',
  },
  {
    id: 'chk-sender',
    label: 'Confronta nome visualizzato e indirizzo email reale',
    detail:
      'Gli aggressori impostano un nome noto (es. "Intesa Sanpaolo") associato a domini gratuiti o registrati di recente.',
  },
  {
    id: 'chk-auth',
    label: 'Verifica i record SPF, DKIM e DMARC negli header',
    detail:
      'Un fallimento di DKIM o DMARC su comunicazioni bancarie o istituzionali è un forte segnale di spoofing.',
  },
  {
    id: 'chk-urgency',
    label: 'Diffida di scadenze artificiali e minacce di blocco',
    detail:
      'Formule come "entro 24 ore" o "conto sospeso" servono a bloccare il controllo razionale della vittima.',
  },
  {
    id: 'chk-outofband',
    label: 'Conferma le richieste di pagamento su canale secondario',
    detail:
      'Per cambi IBAN o bonifici urgenti (BEC), chiama sempre un numero già noto e salvato in rubrica.',
  },
];

const GUIDES = [
  {
    title: '01. Anatomia di un URL malevolo',
    points: [
      'Sottodomini ingannevoli: il brand viene inserito a sinistra per mascherare il dominio principale a destra.',
      'Attacchi omografi (IDN Punycode): prefissi "xn--" che nascondono caratteri cirillici o greci identici alle lettere latine.',
      'Offuscamento con "@": tutto ciò che precede "@" viene trattato dal browser come username e ignorato ai fini della destinazione.',
    ],
  },
  {
    title: '02. Autenticazione Email (SPF, DKIM, DMARC)',
    points: [
      'SPF (Sender Policy Framework): definisce quali indirizzi IP sono autorizzati a inviare email per un dominio.',
      'DKIM (DomainKeys Identified Mail): firma crittografica che garantisce integrità del messaggio e autenticità del dominio.',
      'DMARC: allinea SPF e DKIM con l’indirizzo "From" visibile al destinatario e imposta la policy di rifiuto.',
    ],
  },
  {
    title: '03. Ingegneria Sociale e BEC',
    points: [
      'Urgenza e paura: finti addebiti, pacchi bloccati alla dogana o accessi anomali al conto.',
      'Autorità (Frode del CEO): email prive di link malevoli che chiedono bonifici riservati o carte regalo.',
      'Raccolta multi-fase: richiesta prima di credenziali e subito dopo del codice OTP per bypassare l’autenticazione a due fattori.',
    ],
  },
];

export function GuidelinesView() {
  const [checkedIds, setCheckedIds] = useState<string[]>([]);

  const toggleItem = (id: string) => {
    setCheckedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          Regole Operative e Indicatori
        </h2>
        <p className="mt-1 text-sm text-slate-600 max-w-2xl">
          Riferimento pratico per l’analisi manuale di messaggi sospetti, intestazioni email e collegamenti web prima di interagire con contenuti non verificati.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Guide Tecniche */}
        <div className="space-y-4 lg:col-span-7">
          {GUIDES.map((guide) => (
            <section
              key={guide.title}
              className="rounded-xl border border-slate-200 bg-white p-6"
            >
              <h3 className="font-display text-base font-semibold text-slate-900">
                {guide.title}
              </h3>
              <ul className="mt-3 list-disc space-y-2.5 pl-4 text-sm leading-relaxed text-slate-600 marker:text-slate-400">
                {guide.points.map((point, idx) => (
                  <li key={idx}>
                    {point}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>

        {/* Checklist Interattiva di Triage */}
        <aside className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-5 h-fit">
          <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-4">
            <div>
              <h3 className="font-display text-base font-semibold text-slate-900">
                Checklist Rapida di Triage
              </h3>
              <p className="mt-0.5 text-xs text-slate-500">
                Verificati{' '}
                <span className="font-mono font-semibold text-slate-800 tabular-nums">
                  {checkedIds.length} / {TRIAGE_CHECKLIST.length}
                </span>
              </p>
            </div>

            {checkedIds.length > 0 && (
              <button
                type="button"
                onClick={() => setCheckedIds([])}
                className="inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium text-slate-600 hover:bg-slate-100"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Azzera</span>
              </button>
            )}
          </div>

          <ul className="mt-4 divide-y divide-slate-100">
            {TRIAGE_CHECKLIST.map((item) => {
              const isChecked = checkedIds.includes(item.id);
              return (
                <li key={item.id} className="py-3 first:pt-0 last:pb-0">
                  <button
                    type="button"
                    onClick={() => toggleItem(item.id)}
                    aria-pressed={isChecked}
                    className="flex w-full items-start gap-3 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded-md p-1 -m-1"
                  >
                    {isChecked ? (
                      <CheckSquare
                        className="mt-0.5 h-4 w-4 shrink-0 text-blue-600"
                        aria-hidden="true"
                      />
                    ) : (
                      <Square
                        className="mt-0.5 h-4 w-4 shrink-0 text-slate-400"
                        aria-hidden="true"
                      />
                    )}
                    <div>
                      <p
                        className={`text-sm font-medium ${
                          isChecked ? 'text-slate-400 line-through' : 'text-slate-900'
                        }`}
                      >
                        {item.label}
                      </p>
                      <p className="mt-0.5 text-xs text-slate-500">{item.detail}</p>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </aside>
      </div>
    </div>
  );
}
