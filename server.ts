import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, ThinkingLevel, Type } from '@google/genai';
import {
  analyzeEmailTextHeuristics,
  analyzeUrlHeuristics,
  computeHeuristicRiskScore,
} from './src/utils/phishingHeuristics.ts';
import type {
  AnalysisFinding,
  AnalysisInputType,
  AnalysisResult,
  ExtractedUrlInfo,
  RiskVerdict,
} from './src/types/phishguard.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;

interface AnalyzeRequestBody {
  type?: AnalysisInputType;
  sender?: string;
  subject?: string;
  content?: string;
  url?: string;
  imageBase64?: string;
  imageMimeType?: string;
}

const ANALYSIS_RESPONSE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    verdict: {
      type: Type.STRING,
      description: 'Must be one of: safe, suspicious, phishing',
    },
    riskScore: {
      type: Type.INTEGER,
      description: 'Integer risk score from 0 (completely safe) to 100 (confirmed phishing)',
    },
    confidence: {
      type: Type.INTEGER,
      description: 'Model confidence percentage from 0 to 100',
    },
    summary: {
      type: Type.STRING,
      description: 'Clear executive summary in Italian explaining the verdict in 2-3 sentences',
    },
    impersonatedBrand: {
      type: Type.STRING,
      description: 'Name of the impersonated brand or organization, or empty string if none',
    },
    findings: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          title: { type: Type.STRING },
          description: { type: Type.STRING },
          severity: {
            type: Type.STRING,
            description: 'Must be one of: high, medium, low',
          },
          category: {
            type: Type.STRING,
            description:
              'One of: Dominio, URL, Ingegneria Sociale, Mittente, Credenziali, Contenuto Visivo, Tecnico',
          },
          evidence: { type: Type.STRING },
        },
        required: ['title', 'description', 'severity', 'category'],
      },
    },
    recommendations: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: 'Concrete actionable next steps in Italian for the user',
    },
    technicalNotes: {
      type: Type.STRING,
      description: 'Brief technical note on domain, authentication, or linguistic signals in Italian',
    },
  },
  required: [
    'verdict',
    'riskScore',
    'confidence',
    'summary',
    'impersonatedBrand',
    'findings',
    'recommendations',
    'technicalNotes',
  ],
};

function normalizeVerdict(raw: unknown): RiskVerdict {
  if (raw === 'phishing' || raw === 'suspicious' || raw === 'safe') {
    return raw;
  }
  return 'suspicious';
}

function normalizeSeverity(raw: unknown): 'high' | 'medium' | 'low' {
  if (raw === 'high' || raw === 'medium' || raw === 'low') {
    return raw;
  }
  return 'medium';
}

function normalizeCategory(raw: unknown): AnalysisFinding['category'] {
  const allowed: AnalysisFinding['category'][] = [
    'Dominio',
    'URL',
    'Ingegneria Sociale',
    'Mittente',
    'Credenziali',
    'Contenuto Visivo',
    'Tecnico',
  ];
  if (typeof raw === 'string' && allowed.includes(raw as AnalysisFinding['category'])) {
    return raw as AnalysisFinding['category'];
  }
  return 'Tecnico';
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/api/analyze', async (req, res) => {
    try {
      const body = (req.body || {}) as AnalyzeRequestBody;
      const type = body.type;

      if (type !== 'email' && type !== 'url' && type !== 'image') {
        res.status(400).json({
          error: 'Tipo di analisi non valido. Scegli tra email, url o image.',
        });
        return;
      }

      let heuristicFindings: AnalysisFinding[] = [];
      let extractedUrls: ExtractedUrlInfo[] = [];

      if (type === 'url') {
        const targetUrl = (body.url || body.content || '').trim();
        if (!targetUrl) {
          res.status(400).json({ error: 'Inserisci un URL o dominio da analizzare.' });
          return;
        }
        const urlCheck = analyzeUrlHeuristics(targetUrl);
        heuristicFindings = urlCheck.findings;
        if (urlCheck.info) {
          extractedUrls = [urlCheck.info];
        }
      } else if (type === 'email') {
        const textBody = (body.content || '').trim();
        if (!textBody && !(body.subject || '').trim()) {
          res.status(400).json({
            error: 'Inserisci almeno l’oggetto o il testo del messaggio da analizzare.',
          });
          return;
        }
        const emailCheck = analyzeEmailTextHeuristics({
          sender: body.sender?.trim(),
          subject: body.subject?.trim(),
          body: textBody,
        });
        heuristicFindings = emailCheck.findings;
        extractedUrls = emailCheck.extractedUrls;
      } else if (type === 'image') {
        if (!body.imageBase64 || !body.imageMimeType) {
          res.status(400).json({
            error: 'Carica uno screenshot valido (PNG, JPEG o WebP) da analizzare.',
          });
          return;
        }
      }

      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        res.status(500).json({
          error:
            'Chiave API Gemini non disponibile sul server. Configura GEMINI_API_KEY nel pannello Settings > Secrets.',
        });
        return;
      }

      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });

      const heuristicSummary = computeHeuristicRiskScore(heuristicFindings);
      const heuristicContext =
        heuristicFindings.length > 0
          ? JSON.stringify(
              heuristicFindings.map((f) => ({
                title: f.title,
                severity: f.severity,
                evidence: f.evidence,
              }))
            )
          : 'Nessuna anomalia euristica preliminare rilevata.';

      const systemInstruction = `Sei PhishGuard IA, un analista senior di Threat Intelligence e difesa anti-phishing.
Analizza con rigore tecnico i dati forniti dall'utente (email, messaggi SMS/chat, URL o screenshot di pagine di login/messaggi) e produci una valutazione strutturata esclusivamente in italiano.
Regole:
- Sii preciso, oggettivo e basato sulle evidenze presenti nell'input.
- Riconosci falsi positivi legittimi: se un messaggio o dominio è ufficiale e privo di richieste di credenziali/urgenza manipolativa, classifica come "safe" con riskScore basso (0-20).
- Se vi sono segnali ambigui o tentativi BEC senza link certi, classifica come "suspicious" (25-64).
- Se emergono impersonificazioni di brand, domini contraffatti, raccolta OTP/carte/password o link malevoli evidenti, classifica come "phishing" (65-100).
- Non inventare URL o domini non presenti nell'input.`;

      const promptParts: Array<
        { text: string } | { inlineData: { mimeType: string; data: string } }
      > = [];

      if (type === 'image' && body.imageBase64 && body.imageMimeType) {
        promptParts.push({
          inlineData: {
            mimeType: body.imageMimeType,
            data: body.imageBase64,
          },
        });
        promptParts.push({
          text: `Analizza questo screenshot per individuare eventuali tentativi di phishing, pagine di login contraffatte, loghi falsificati, testi urgenti o URL visibili sospetti.${body.content ? `\nNote aggiuntive utente: ${body.content}` : ''}`,
        });
      } else if (type === 'url') {
        const targetUrl = (body.url || body.content || '').trim();
        promptParts.push({
          text: `Analizza il seguente URL o dominio per rischi di phishing, typosquatting, omografi o credential harvesting:
URL: ${targetUrl}
Pre-analisi euristica deterministica (punteggio ${heuristicSummary.score}/100): ${heuristicContext}`,
        });
      } else {
        promptParts.push({
          text: `Analizza il seguente messaggio o email sospetta:
Mittente: ${body.sender?.trim() || 'Non specificato'}
Oggetto: ${body.subject?.trim() || 'Non specificato'}
Corpo del messaggio:
${body.content?.trim() || ''}

Pre-analisi euristica deterministica (punteggio ${heuristicSummary.score}/100): ${heuristicContext}`,
        });
      }

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: { parts: promptParts },
        config: {
          systemInstruction,
          responseMimeType: 'application/json',
          responseSchema: ANALYSIS_RESPONSE_SCHEMA,
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        },
      });

      const rawText = (response.text || '').trim();
      if (!rawText) {
        res.status(502).json({
          error: 'Il motore AI ha restituito una risposta vuota. Riprova tra qualche secondo.',
        });
        return;
      }

      const parsed = JSON.parse(rawText) as {
        verdict?: unknown;
        riskScore?: unknown;
        confidence?: unknown;
        summary?: unknown;
        impersonatedBrand?: unknown;
        findings?: Array<{
          title?: unknown;
          description?: unknown;
          severity?: unknown;
          category?: unknown;
          evidence?: unknown;
        }>;
        recommendations?: unknown[];
        technicalNotes?: unknown;
      };

      const aiFindings: AnalysisFinding[] = Array.isArray(parsed.findings)
        ? parsed.findings.map((item, idx) => ({
            id: `ai-finding-${Date.now()}-${idx}`,
            title: typeof item.title === 'string' ? item.title : 'Indicatore rilevato',
            description: typeof item.description === 'string' ? item.description : '',
            severity: normalizeSeverity(item.severity),
            category: normalizeCategory(item.category),
            evidence: typeof item.evidence === 'string' && item.evidence ? item.evidence : undefined,
          }))
        : [];

      const rawScore =
        typeof parsed.riskScore === 'number'
          ? Math.min(100, Math.max(0, Math.round(parsed.riskScore)))
          : heuristicSummary.score;

      const rawConfidence =
        typeof parsed.confidence === 'number'
          ? Math.min(100, Math.max(10, Math.round(parsed.confidence)))
          : 85;

      const result: AnalysisResult = {
        verdict: normalizeVerdict(parsed.verdict),
        riskScore: rawScore,
        confidence: rawConfidence,
        summary:
          typeof parsed.summary === 'string' && parsed.summary
            ? parsed.summary
            : 'Analisi completata.',
        impersonatedBrand:
          typeof parsed.impersonatedBrand === 'string' && parsed.impersonatedBrand.trim()
            ? parsed.impersonatedBrand.trim()
            : null,
        findings: aiFindings.length > 0 ? aiFindings : heuristicFindings,
        heuristicFindings,
        extractedUrls,
        recommendations: Array.isArray(parsed.recommendations)
          ? parsed.recommendations.filter((r): r is string => typeof r === 'string' && r.trim().length > 0)
          : ['Verifica sempre i link prima di inserire credenziali.'],
        technicalNotes:
          typeof parsed.technicalNotes === 'string' ? parsed.technicalNotes : '',
        analyzedAt: new Date().toISOString(),
      };

      res.json(result);
    } catch (err: unknown) {
      console.error('Errore /api/analyze:', err);
      const message = err instanceof Error ? err.message : String(err);

      if (message.includes('403') || message.includes('PERMISSION_DENIED') || message.includes('API_KEY_INVALID')) {
        res.status(403).json({
          error:
            'Chiave API Gemini non valida o non autorizzata. Verifica la chiave in Settings > Secrets.',
        });
        return;
      }
      if (message.includes('429') || message.includes('RESOURCE_EXHAUSTED')) {
        res.status(429).json({
          error:
            'Quota richieste temporaneamente esaurita sul servizio AI. Attendi qualche istante e riprova.',
        });
        return;
      }

      res.status(500).json({
        error: 'Errore durante l’analisi tramite Gemini AI. Riprova tra qualche istante.',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishGuard IA server in ascolto sulla porta ${PORT}`);
  });
}

startServer();
