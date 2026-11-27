import type { SampleCase, ScanRecord } from '../types/phishguard';

export const SAMPLE_CASES: SampleCase[] = [
  {
    id: 'case-bank-intesa',
    title: 'Finta Allerta Sicurezza Bancaria',
    category: 'Bancario',
    type: 'email',
    difficulty: 'Base',
    expectedVerdict: 'phishing',
    sender: 'Sicurezza Intesa Sanpaolo <notifiche.sicurezza@intesa-portale-verifica.top>',
    subject: 'URGENTE: Accesso anomalo rilevato — Conto temporaneamente limitato',
    content:
      'Gentile Cliente,\n\nAbbiamo rilevato un tentativo di accesso non autorizzato al tuo home banking da un dispositivo sconosciuto. Per evitare la sospensione definitiva del conto entro 24 ore, verifica la tua identità e conferma il codice OTP al seguente link sicuro:\n\nhttp://intesa-sanpaolo-verifica.top/login/aggiorna\n\nSe non completi la procedura il servizio verrà disattivato immediatamente.',
    description:
      'Classica email di credential harvesting bancario con dominio contraffatto su TLD .top, protocollo HTTP non cifrato e forte pressione psicologica.',
    learningPoint:
      'Le banche non inviano mai link diretti per inserire codici OTP o password con scadenze di 24 ore.',
  },
  {
    id: 'case-courier-brt',
    title: 'SMS / Email Finta Consegna Pacco',
    category: 'Logistica',
    type: 'email',
    difficulty: 'Intermedio',
    expectedVerdict: 'phishing',
    sender: 'BRT Servizio Consegne <tracking@brt-spedizioni-info.xyz>',
    subject: 'Pacco in giacenza: spese doganali di € 2,90 non pagate',
    content:
      'Il tuo pacco IT8849201 è fermo presso il centro smistamento per indirizzo incompleto e dazio di € 2,90. Aggiorna i dati della carta di credito entro oggi per riprogrammare la consegna:\n\nhttps://brt-it.consegna-rapida.xyz/pagamento-carta',
    description:
      'Esca basata su micro-pagamenti (smishing/phishing logistico) per sottrarre i dati completi della carta di pagamento.',
    learningPoint:
      'Nota il dominio radice "consegna-rapida.xyz": "brt-it" è solo un sottodominio creato ad arte per ingannare a colpo d’occhio.',
  },
  {
    id: 'case-bec-ceo',
    title: 'Frode del CEO / Cambio IBAN Fornitore (BEC)',
    category: 'Aziendale (BEC)',
    type: 'email',
    difficulty: 'Avanzato',
    expectedVerdict: 'suspicious',
    sender: 'Marco Bellini <direzione.amministrazione@gmail.com>',
    subject: 'Richiesta riservata pagamento urgente fattura fornitore',
    content:
      'Ciao,\nsono ancora in riunione fuori ufficio e non posso rispondere al telefono. Ho bisogno che tu predisponga subito il bonifico urgente di 14.800 € per la pratica di stamattina usando le nuove coordinate IBAN aggiornate del consulente, perché quelle vecchie sono in manutenzione. Confermami appena eseguito.',
    description:
      'Attacco Business Email Compromise senza link né allegati malevoli, basato interamente su autorità, riservatezza e cambio IBAN.',
    learningPoint:
      'I tentativi BEC spesso non contengono URL: l’analisi del dominio webmail gratuito del mittente e la verifica vocale su canale secondario sono essenziali.',
  },
  {
    id: 'case-url-idn',
    title: 'URL Omografo & Credenziali Mascherate',
    category: 'Cloud & Account',
    type: 'url',
    difficulty: 'Avanzato',
    expectedVerdict: 'phishing',
    content: 'https://accounts.google.com@xn--gogle-1qa.click/signin/oauth2',
    description:
      'Indirizzo che combina due tecniche avanzate: il carattere "@" per nascondere l’host reale e un dominio Punycode con TLD .click.',
    learningPoint:
      'Il browser ignora tutto ciò che precede "@" e si connette realmente al dominio Punycode finale.',
  },
  {
    id: 'case-legit-poste',
    title: 'Comunicazione Ufficiale Legittima',
    category: 'Legittimo',
    type: 'email',
    difficulty: 'Base',
    expectedVerdict: 'safe',
    sender: 'Poste Italiane <comunicazioni@poste.it>',
    subject: 'Ricevuta operazione effettuata nella tua area personale',
    content:
      'Gentile utente,\nti confermiamo che la tua richiesta di estratto conto digitale è disponibile nella tua Area Personale.\nPer consultare il documento accedi autonomamente dalla app ufficiale oppure dal sito istituzionale https://www.poste.it.\nNon ti chiederemo mai PIN, password o codici dispositivi via email.',
    description:
      'Comunicazione informativa priva di richieste di dati sensibili, con dominio ufficiale verificabile e invito ad accedere dai canali ufficiali.',
    learningPoint:
      'Un messaggio legittimo non mette fretta artificiale e rimanda al portale principale ufficiale senza token sospetti.',
  },
];

export const INITIAL_SCAN_HISTORY: ScanRecord[] = [
  {
    id: 'seed-scan-1',
    type: 'email',
    title: 'Allerta Sicurezza Intesa Sanpaolo',
    targetPreview: 'notifiche.sicurezza@intesa-portale-verifica.top',
    sender: 'Sicurezza Intesa Sanpaolo <notifiche.sicurezza@intesa-portale-verifica.top>',
    subject: 'URGENTE: Accesso anomalo rilevato — Conto temporaneamente limitato',
    rawContent: SAMPLE_CASES[0].content,
    createdAt: '2026-11-27T08:40:00.000Z',
    source: 'sample',
    result: {
      verdict: 'phishing',
      riskScore: 94,
      confidence: 97,
      summary:
        'Tentativo ad alto rischio di credential harvesting bancario. Il messaggio imita Intesa Sanpaolo usando un dominio non ufficiale (.top) e richiede l’inserimento del codice OTP su un collegamento HTTP non cifrato.',
      impersonatedBrand: 'Intesa Sanpaolo',
      findings: [
        {
          id: 's1-f1',
          title: 'Impersonificazione di Intesa Sanpaolo',
          description:
            'Il dominio del mittente e il link appartengono a domini .top estranei al gruppo bancario ufficiale.',
          severity: 'high',
          category: 'Dominio',
          evidence: 'intesa-sanpaolo-verifica.top',
        },
        {
          id: 's1-f2',
          title: 'Richiesta codice OTP via collegamento esterno',
          description:
            'Il testo chiede di confermare il codice OTP attraverso un modulo web esterno.',
          severity: 'high',
          category: 'Credenziali',
          evidence: 'conferma il codice OTP',
        },
        {
          id: 's1-f3',
          title: 'Urgenza artificiale entro 24 ore',
          description:
            'Minaccia la disattivazione immediata del servizio per ridurre la soglia critica della vittima.',
          severity: 'medium',
          category: 'Ingegneria Sociale',
          evidence: 'entro 24 ore',
        },
      ],
      heuristicFindings: [],
      extractedUrls: [
        {
          url: 'http://intesa-sanpaolo-verifica.top/login/aggiorna',
          hostname: 'intesa-sanpaolo-verifica.top',
          protocol: 'http',
          suspicious: true,
          reason: 'Connessione non cifrata HTTP · Estensione ad alto rischio .top',
        },
      ],
      recommendations: [
        'Non aprire il collegamento né inserire codici OTP o PIN.',
        'Elimina il messaggio e segnala il mittente come phishing al tuo client di posta.',
        'Verifica lo stato reale del conto accedendo esclusivamente dall’app ufficiale della banca.',
      ],
      technicalNotes: 'Analisi combinata euristiche URL + classificazione semantica Gemini.',
      analyzedAt: '2026-11-27T08:40:00.000Z',
    },
  },
  {
    id: 'seed-scan-2',
    type: 'url',
    title: 'Verifica URL pacco BRT',
    targetPreview: 'https://brt-it.consegna-rapida.xyz/pagamento-carta',
    rawContent: 'https://brt-it.consegna-rapida.xyz/pagamento-carta',
    createdAt: '2026-11-27T07:15:00.000Z',
    source: 'sample',
    result: {
      verdict: 'phishing',
      riskScore: 88,
      confidence: 95,
      summary:
        'URL fraudolento progettato per simulare una pagina di svincolo spedizione BRT e sottrarre dati della carta di pagamento.',
      impersonatedBrand: 'BRT / Bartolini',
      findings: [
        {
          id: 's2-f1',
          title: 'Sottodominio ingannevole su dominio .xyz',
          description:
            'Il nome "brt-it" è usato come sottodominio di "consegna-rapida.xyz", completamente scollegato da brt.it.',
          severity: 'high',
          category: 'Dominio',
          evidence: 'brt-it.consegna-rapida.xyz',
        },
        {
          id: 's2-f2',
          title: 'Percorso orientato al pagamento carta',
          description:
            'Il percorso /pagamento-carta su un dominio non ufficiale indica raccolta illecita di carte.',
          severity: 'high',
          category: 'Credenziali',
          evidence: '/pagamento-carta',
        },
      ],
      heuristicFindings: [],
      extractedUrls: [
        {
          url: 'https://brt-it.consegna-rapida.xyz/pagamento-carta',
          hostname: 'brt-it.consegna-rapida.xyz',
          protocol: 'https',
          suspicious: true,
          reason: 'Estensione ad alto rischio .xyz · Imitazione probabile del brand BRT / Bartolini',
        },
      ],
      recommendations: [
        'Chiudi la pagina immediatamente e non inserire dati della carta.',
        'Controlla eventuali spedizioni reali direttamente su brt.it inserendo il codice tracking.',
      ],
      technicalNotes: 'Rilevato TLD ad alto abuso e disallineamento del dominio registrabile.',
      analyzedAt: '2026-11-27T07:15:00.000Z',
    },
  },
  {
    id: 'seed-scan-3',
    type: 'email',
    title: 'Richiesta cambio IBAN urgente',
    targetPreview: 'direzione.amministrazione@gmail.com',
    sender: 'Marco Bellini <direzione.amministrazione@gmail.com>',
    subject: 'Richiesta riservata pagamento urgente fattura fornitore',
    rawContent: SAMPLE_CASES[2].content,
    createdAt: '2026-11-26T17:30:00.000Z',
    source: 'sample',
    result: {
      verdict: 'suspicious',
      riskScore: 72,
      confidence: 89,
      summary:
        'Forte sospetto di Business Email Compromise (Frode del CEO). Il mittente utilizza una casella Gmail generica per autorizzare un bonifico urgente verso un nuovo IBAN evitando verifiche telefoniche.',
      impersonatedBrand: null,
      findings: [
        {
          id: 's3-f1',
          title: 'Richiesta finanziaria da webmail personale',
          description:
            'Un’autorizzazione di bonifico aziendale proviene da @gmail.com invece che dal dominio aziendale.',
          severity: 'high',
          category: 'Mittente',
          evidence: 'direzione.amministrazione@gmail.com',
        },
        {
          id: 's3-f2',
          title: 'Elusione della verifica vocale',
          description:
            'Il testo dichiara impossibilità di rispondere al telefono per bloccare il controllo out-of-band.',
          severity: 'medium',
          category: 'Ingegneria Sociale',
          evidence: 'non posso rispondere al telefono',
        },
      ],
      heuristicFindings: [],
      extractedUrls: [],
      recommendations: [
        'Non eseguire alcun bonifico prima di una verifica telefonica su numero già noto.',
        'Confronta l’indirizzo email completo con la rubrica aziendale verificata.',
      ],
      technicalNotes: 'Assenza di link; minaccia basata esclusivamente su ingegneria sociale.',
      analyzedAt: '2026-11-26T17:30:00.000Z',
    },
  },
  {
    id: 'seed-scan-4',
    type: 'email',
    title: 'Ricevuta area personale Poste',
    targetPreview: 'comunicazioni@poste.it',
    sender: 'Poste Italiane <comunicazioni@poste.it>',
    subject: 'Ricevuta operazione effettuata nella tua area personale',
    rawContent: SAMPLE_CASES[4].content,
    createdAt: '2026-11-26T11:20:00.000Z',
    source: 'sample',
    result: {
      verdict: 'safe',
      riskScore: 6,
      confidence: 94,
      summary:
        'Messaggio coerente con comunicazioni informative legittime. Il dominio del mittente e il riferimento di navigazione puntano al dominio ufficiale poste.it senza richieste di dati sensibili.',
      impersonatedBrand: null,
      findings: [
        {
          id: 's4-f1',
          title: 'Dominio istituzionale coerente',
          description:
            'Sia il mittente sia il link indicato fanno riferimento al dominio ufficiale poste.it.',
          severity: 'low',
          category: 'Dominio',
          evidence: 'poste.it',
        },
      ],
      heuristicFindings: [],
      extractedUrls: [
        {
          url: 'https://www.poste.it',
          hostname: 'www.poste.it',
          protocol: 'https',
          suspicious: false,
        },
      ],
      recommendations: [
        'Per buona prassi, apri comunque il portale da segnalibro o app ufficiale.',
        'Verifica sempre gli header SPF/DKIM nel client di posta per ulteriore certezza.',
      ],
      technicalNotes: 'Nessun indicatore di urgenza o raccolta credenziali rilevato.',
      analyzedAt: '2026-11-26T11:20:00.000Z',
    },
  },
];
