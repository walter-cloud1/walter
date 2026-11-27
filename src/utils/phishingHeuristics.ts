import type {
  AnalysisFinding,
  ExtractedUrlInfo,
  RiskFilter,
  RiskVerdict,
  ScanRecord,
} from '../types/phishguard';

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'click',
  'work',
  'zip',
  'mov',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'buzz',
  'loan',
  'icu',
  'cam',
  'rest',
  'sbs',
  'cfd',
]);

const PROTECTED_BRANDS: Array<{ name: string; officialDomains: string[]; keywords: string[] }> = [
  {
    name: 'Intesa Sanpaolo',
    officialDomains: ['intesasanpaolo.com'],
    keywords: ['intesa', 'sanpaolo', 'intesasanpaolo'],
  },
  {
    name: 'UniCredit',
    officialDomains: ['unicredit.it', 'unicreditgroup.eu'],
    keywords: ['unicredit'],
  },
  {
    name: 'Poste Italiane',
    officialDomains: ['poste.it', 'posteitaliane.it'],
    keywords: ['poste', 'posteitaliane', 'postepay'],
  },
  {
    name: 'PayPal',
    officialDomains: ['paypal.com', 'paypal.it'],
    keywords: ['paypal', 'paypa1', 'paypai'],
  },
  {
    name: 'Amazon',
    officialDomains: ['amazon.it', 'amazon.com'],
    keywords: ['amazon', 'amaz0n'],
  },
  {
    name: 'DHL',
    officialDomains: ['dhl.com', 'dhl.it'],
    keywords: ['dhl'],
  },
  {
    name: 'BRT / Bartolini',
    officialDomains: ['brt.it'],
    keywords: ['brt', 'bartolini'],
  },
  {
    name: 'Microsoft 365',
    officialDomains: ['microsoft.com', 'office.com', 'live.com', 'outlook.com'],
    keywords: ['microsoft', 'micr0soft', 'office365', 'onedrive', 'sharepoint'],
  },
  {
    name: 'Google',
    officialDomains: ['google.com', 'google.it', 'accounts.google.com'],
    keywords: ['google', 'g00gle', 'gmail'],
  },
  {
    name: 'Agenzia delle Entrate',
    officialDomains: ['agenziaentrate.gov.it'],
    keywords: ['agenziaentrate', 'agenzia-entrate', 'fisco'],
  },
  {
    name: 'INPS',
    officialDomains: ['inps.it'],
    keywords: ['inps'],
  },
];

const FREE_WEBMAIL_DOMAINS = new Set([
  'gmail.com',
  'yahoo.com',
  'yahoo.it',
  'hotmail.com',
  'outlook.com',
  'libero.it',
  'virgilio.it',
  'tiscali.it',
  'proton.me',
  'protonmail.com',
  'gmx.com',
  'mail.com',
]);

const URL_REGEX = /\bhttps?:\/\/[^\s<>"{}|\\^`[\]]+/gi;

const URGENCY_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern: /\b(entro\s+24\s*ore|immediatamente|subito|scadenza\s+imminente|ultimo\s+avviso|urgente|azione\s+richiesta)\b/i,
    label: 'Pressione temporale o urgenza artificiale',
  },
  {
    pattern: /\b(account\s+(?:sospeso|bloccato|limitato)|accesso\s+non\s+autorizzato|sospensione\s+del\s+conto|conto\s+bloccato)\b/i,
    label: 'Minaccia di blocco o sospensione account',
  },
  {
    pattern: /\b(conferma\s+(?:i\s+tuoi\s+dati|la\s+tua\s+identità|il\s+pagamento)|aggiorna\s+(?:il\s+metodo|le\s+coordinate)|verifica\s+ora)\b/i,
    label: 'Richiesta diretta di verifica dati o pagamento',
  },
  {
    pattern: /\b(codice\s+otp|pin|password|carta\s+di\s+credito|iban|credenziali)\b/i,
    label: 'Riferimento a credenziali sensibili o codici OTP',
  },
  {
    pattern: /\b(immediately|suspended|unauthorized\s+login|verify\s+your\s+account|within\s+24\s*hours)\b/i,
    label: 'Urgenza o sospensione in lingua inglese',
  },
];

const SENSITIVE_URL_KEYWORDS = [
  'login',
  'signin',
  'verify',
  'verifica',
  'aggiorna',
  'update',
  'secure',
  'sicurezza',
  'sblocco',
  'rimborso',
  'wallet',
  'otp',
  'billing',
  'account',
];

export function extractUrlsFromText(text: string): string[] {
  if (!text) return [];
  const matches = text.match(URL_REGEX) || [];
  const cleaned = matches.map((m) => m.replace(/[),.;:!?]+$/, ''));
  return Array.from(new Set(cleaned));
}

export function normalizeUrlInput(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

function isOfficialDomain(hostname: string, officialDomains: string[]): boolean {
  const lower = hostname.toLowerCase();
  return officialDomains.some(
    (domain) => lower === domain || lower.endsWith(`.${domain}`)
  );
}

export function analyzeUrlHeuristics(rawUrl: string): {
  info: ExtractedUrlInfo | null;
  findings: AnalysisFinding[];
} {
  const findings: AnalysisFinding[] = [];
  const normalized = normalizeUrlInput(rawUrl);
  if (!normalized) {
    return { info: null, findings };
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    findings.push({
      id: 'url-invalid',
      title: 'Sintassi URL malformata',
      description: 'L’indirizzo inserito non rispetta una struttura URL valida.',
      severity: 'medium',
      category: 'URL',
      evidence: rawUrl,
    });
    return { info: null, findings };
  }

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.replace(':', '');
  const parts = hostname.split('.');
  const tld = parts[parts.length - 1] || '';

  let urlSuspicious = false;
  const reasons: string[] = [];

  if (protocol === 'http') {
    urlSuspicious = true;
    reasons.push('Connessione non cifrata HTTP');
    findings.push({
      id: `url-http-${hostname}`,
      title: 'Protocollo HTTP non cifrato',
      description:
        'Il collegamento utilizza HTTP in chiaro invece di HTTPS, esponendo i dati trasmessi a intercettazione.',
      severity: 'medium',
      category: 'URL',
      evidence: parsed.href,
    });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    urlSuspicious = true;
    reasons.push('Host espresso come indirizzo IP');
    findings.push({
      id: `url-ip-${hostname}`,
      title: 'Indirizzo IP diretto al posto del dominio',
      description:
        'I servizi legittimi usano nomi a dominio registrati. L’uso di un IP diretto è tipico di infrastrutture temporanee di phishing.',
      severity: 'high',
      category: 'Tecnico',
      evidence: hostname,
    });
  }

  if (parsed.username || parsed.href.includes('@')) {
    urlSuspicious = true;
    reasons.push('Presenza del simbolo @ nell’URL');
    findings.push({
      id: `url-at-${hostname}`,
      title: 'Offuscamento host tramite carattere "@"',
      description:
        'Tutto ciò che precede "@" viene trattato dal browser come credenziale, mascherando il dominio reale di destinazione.',
      severity: 'high',
      category: 'URL',
      evidence: parsed.href,
    });
  }

  if (hostname.includes('xn--')) {
    urlSuspicious = true;
    reasons.push('Dominio Punycode / IDN');
    findings.push({
      id: `url-punycode-${hostname}`,
      title: 'Possibile attacco omografo (Punycode IDN)',
      description:
        'Il dominio contiene codifica "xn--", spesso usata per sostituire caratteri latini con glifi simili (es. cirillici).',
      severity: 'high',
      category: 'Dominio',
      evidence: hostname,
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    urlSuspicious = true;
    reasons.push(`Estensione ad alto rischio .${tld}`);
    findings.push({
      id: `url-tld-${hostname}`,
      title: `Estensione di dominio ad alto abuso (.${tld})`,
      description: `Il TLD ".${tld}" è frequentemente sfruttato in campagne di phishing per via del basso costo e dei controlli ridotti.`,
      severity: 'medium',
      category: 'Dominio',
      evidence: `.${tld}`,
    });
  }

  if (parts.length >= 4) {
    urlSuspicious = true;
    reasons.push('Catena eccessiva di sottodomini');
    findings.push({
      id: `url-subdomains-${hostname}`,
      title: 'Eccessiva profondità di sottodomini',
      description:
        'L’URL utilizza molti livelli di sottodomini per far apparire un nome familiare all’inizio dell’indirizzo nascondendo il dominio radice.',
      severity: 'medium',
      category: 'Dominio',
      evidence: hostname,
    });
  }

  for (const brand of PROTECTED_BRANDS) {
    const matchedKeyword = brand.keywords.find((kw) =>
      hostname.includes(kw) || parsed.pathname.toLowerCase().includes(kw)
    );
    if (matchedKeyword && !isOfficialDomain(hostname, brand.officialDomains)) {
      urlSuspicious = true;
      reasons.push(`Imitazione probabile del brand ${brand.name}`);
      findings.push({
        id: `url-brand-${brand.name}-${hostname}`,
        title: `Possibile impersonificazione di ${brand.name}`,
        description: `L’URL richiama "${matchedKeyword}" ma punta al dominio "${hostname}", diverso dai domini ufficiali (${brand.officialDomains.join(', ')}).`,
        severity: 'high',
        category: 'Dominio',
        evidence: hostname,
      });
    }
  }

  const lowerFull = `${hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
  const matchedKeywords = SENSITIVE_URL_KEYWORDS.filter((kw) =>
    lowerFull.includes(kw)
  );
  if (matchedKeywords.length >= 2 && urlSuspicious) {
    findings.push({
      id: `url-keywords-${hostname}`,
      title: 'Percorso URL orientato alla raccolta credenziali',
      description: `Il collegamento combina parole chiave sensibili (${matchedKeywords.slice(0, 4).join(', ')}) su un dominio non verificato.`,
      severity: 'medium',
      category: 'Credenziali',
      evidence: parsed.pathname || parsed.href,
    });
  }

  return {
    info: {
      url: parsed.href,
      hostname,
      protocol,
      suspicious: urlSuspicious,
      reason: reasons.length > 0 ? reasons.join(' · ') : undefined,
    },
    findings,
  };
}

export function analyzeEmailTextHeuristics(input: {
  sender?: string;
  subject?: string;
  body: string;
}): {
  findings: AnalysisFinding[];
  extractedUrls: ExtractedUrlInfo[];
} {
  const findings: AnalysisFinding[] = [];
  const extractedUrls: ExtractedUrlInfo[] = [];

  const combinedText = `${input.subject || ''}\n${input.body || ''}`;
  const urls = extractUrlsFromText(combinedText);

  for (const url of urls) {
    const { info, findings: urlFindings } = analyzeUrlHeuristics(url);
    if (info) {
      extractedUrls.push(info);
    }
    for (const f of urlFindings) {
      if (!findings.some((existing) => existing.id === f.id)) {
        findings.push(f);
      }
    }
  }

  if (input.sender) {
    const emailMatch = input.sender.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i);
    const senderDomain = emailMatch?.[1]?.toLowerCase() || '';

    if (senderDomain) {
      for (const brand of PROTECTED_BRANDS) {
        const mentionsBrandInDisplayOrBody = brand.keywords.some(
          (kw) =>
            input.sender!.toLowerCase().includes(kw) ||
            (input.subject || '').toLowerCase().includes(kw)
        );
        if (
          mentionsBrandInDisplayOrBody &&
          !isOfficialDomain(senderDomain, brand.officialDomains)
        ) {
          findings.push({
            id: `sender-spoof-${brand.name}`,
            title: `Disallineamento mittente rispetto a ${brand.name}`,
            description: `Il messaggio richiama ${brand.name}, ma il dominio del mittente è "${senderDomain}"${FREE_WEBMAIL_DOMAINS.has(senderDomain) ? ' (provider webmail gratuito)' : ''}.`,
            severity: 'high',
            category: 'Mittente',
            evidence: input.sender,
          });
        }
      }

      const tld = senderDomain.split('.').pop() || '';
      if (SUSPICIOUS_TLDS.has(tld)) {
        findings.push({
          id: `sender-tld-${senderDomain}`,
          title: `Dominio mittente con TLD sospetto (.${tld})`,
          description: `L’indirizzo del mittente utilizza l’estensione .${tld}, insolita per comunicazioni istituzionali o bancarie.`,
          severity: 'medium',
          category: 'Mittente',
          evidence: senderDomain,
        });
      }
    }
  }

  for (const { pattern, label } of URGENCY_PATTERNS) {
    const match = combinedText.match(pattern);
    if (match) {
      findings.push({
        id: `text-urgency-${label}`,
        title: label,
        description: `È stata rilevata una formula tipica dell’ingegneria sociale ("${match[0]}") progettata per indurre un’azione affrettata.`,
        severity: 'medium',
        category: 'Ingegneria Sociale',
        evidence: match[0],
      });
    }
  }

  return { findings, extractedUrls };
}

export function computeHeuristicRiskScore(findings: AnalysisFinding[]): {
  score: number;
  verdict: RiskVerdict;
} {
  let score = 0;
  for (const f of findings) {
    if (f.severity === 'high') score += 34;
    else if (f.severity === 'medium') score += 18;
    else score += 8;
  }
  const bounded = Math.min(99, Math.max(0, score));
  let verdict: RiskVerdict = 'safe';
  if (bounded >= 60) verdict = 'phishing';
  else if (bounded >= 25) verdict = 'suspicious';
  return { score: bounded, verdict };
}

export function filterAndSortScans(
  scans: ScanRecord[],
  query: string,
  filter: RiskFilter
): ScanRecord[] {
  const normalizedQuery = query.trim().toLowerCase();
  return scans
    .filter((scan) => {
      if (filter !== 'all' && scan.result.verdict !== filter) {
        return false;
      }
      if (!normalizedQuery) return true;
      return (
        scan.title.toLowerCase().includes(normalizedQuery) ||
        scan.targetPreview.toLowerCase().includes(normalizedQuery) ||
        (scan.sender || '').toLowerCase().includes(normalizedQuery) ||
        (scan.result.impersonatedBrand || '').toLowerCase().includes(normalizedQuery)
      );
    })
    .sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
}
