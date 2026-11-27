import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeEmailTextHeuristics,
  analyzeUrlHeuristics,
  computeHeuristicRiskScore,
  extractUrlsFromText,
  filterAndSortScans,
} from './phishingHeuristics';
import type { ScanRecord } from '../types/phishguard';

test('extractUrlsFromText extracts clean unique URLs without trailing punctuation', () => {
  const text =
    'Verifica subito su https://intesa-verifica.top/login, oppure visita http://192.168.1.50/auth.';
  const urls = extractUrlsFromText(text);
  assert.deepEqual(urls, [
    'https://intesa-verifica.top/login',
    'http://192.168.1.50/auth',
  ]);
});

test('analyzeUrlHeuristics flags brand impersonation, HTTP, and suspicious TLD', () => {
  const { info, findings } = analyzeUrlHeuristics(
    'http://poste-italiane-sblocco.xyz/verifica-conto'
  );
  assert.ok(info);
  assert.equal(info.suspicious, true);
  assert.ok(findings.some((f) => f.category === 'Dominio' && f.severity === 'high'));
  assert.ok(findings.some((f) => f.title.includes('HTTP')));
  assert.ok(findings.some((f) => f.title.includes('.xyz')));
});

test('analyzeUrlHeuristics recognizes legitimate official domain as clean', () => {
  const { info, findings } = analyzeUrlHeuristics(
    'https://www.intesasanpaolo.com/it/persone-e-famiglie.html'
  );
  assert.ok(info);
  assert.equal(info.suspicious, false);
  assert.equal(findings.length, 0);
});

test('analyzeUrlHeuristics detects IP host and @ credential obfuscation', () => {
  const ipResult = analyzeUrlHeuristics('https://185.220.101.4/secure');
  assert.ok(ipResult.findings.some((f) => f.id.startsWith('url-ip-')));

  const atResult = analyzeUrlHeuristics('https://google.com@evil-domain.top/login');
  assert.ok(atResult.findings.some((f) => f.id.startsWith('url-at-')));
});

test('analyzeEmailTextHeuristics detects sender spoofing and social engineering urgency', () => {
  const { findings, extractedUrls } = analyzeEmailTextHeuristics({
    sender: 'Servizio Clienti Intesa Sanpaolo <alert.sicurezza@gmail.com>',
    subject: 'URGENTE: Account sospeso entro 24 ore',
    body: 'Il tuo conto è stato limitato. Conferma i tuoi dati e inserisci il codice OTP su https://intesa-aggiorna.top/login',
  });

  assert.equal(extractedUrls.length, 1);
  assert.ok(findings.some((f) => f.category === 'Mittente' && f.severity === 'high'));
  assert.ok(findings.some((f) => f.category === 'Ingegneria Sociale'));
  const score = computeHeuristicRiskScore(findings);
  assert.equal(score.verdict, 'phishing');
  assert.ok(score.score >= 60);
});

test('filterAndSortScans filters by verdict and query and sorts newest first', () => {
  const baseResult = {
    riskScore: 85,
    confidence: 92,
    summary: 'Test',
    impersonatedBrand: 'PayPal',
    findings: [],
    heuristicFindings: [],
    extractedUrls: [],
    recommendations: [],
    technicalNotes: '',
    analyzedAt: '2026-11-26T10:00:00.000Z',
  };

  const scans: ScanRecord[] = [
    {
      id: '1',
      type: 'url',
      title: 'Link PayPal falso',
      targetPreview: 'http://paypa1-support.xyz',
      result: { ...baseResult, verdict: 'phishing' },
      createdAt: '2026-11-25T10:00:00.000Z',
      source: 'user',
    },
    {
      id: '2',
      type: 'email',
      title: 'Newsletter ufficiale',
      targetPreview: 'news@amazon.it',
      result: { ...baseResult, verdict: 'safe', riskScore: 4, impersonatedBrand: null },
      createdAt: '2026-11-26T12:00:00.000Z',
      source: 'sample',
    },
  ];

  const allSorted = filterAndSortScans(scans, '', 'all');
  assert.equal(allSorted[0].id, '2');

  const onlyPhishing = filterAndSortScans(scans, 'paypal', 'phishing');
  assert.equal(onlyPhishing.length, 1);
  assert.equal(onlyPhishing[0].id, '1');
});
