export type AnalysisInputType = 'email' | 'url' | 'image';

export type RiskVerdict = 'safe' | 'suspicious' | 'phishing';

export type RiskFilter = 'all' | RiskVerdict;

export type FindingSeverity = 'high' | 'medium' | 'low';

export type FindingCategory =
  | 'Dominio'
  | 'URL'
  | 'Ingegneria Sociale'
  | 'Mittente'
  | 'Credenziali'
  | 'Contenuto Visivo'
  | 'Tecnico';

export interface AnalysisFinding {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  category: FindingCategory;
  evidence?: string;
}

export interface ExtractedUrlInfo {
  url: string;
  hostname: string;
  protocol: string;
  suspicious: boolean;
  reason?: string;
}

export interface AnalysisResult {
  verdict: RiskVerdict;
  riskScore: number;
  confidence: number;
  summary: string;
  impersonatedBrand: string | null;
  findings: AnalysisFinding[];
  heuristicFindings: AnalysisFinding[];
  extractedUrls: ExtractedUrlInfo[];
  recommendations: string[];
  technicalNotes: string;
  analyzedAt: string;
}

export interface ScanRecord {
  id: string;
  type: AnalysisInputType;
  title: string;
  targetPreview: string;
  sender?: string;
  subject?: string;
  rawContent?: string;
  result: AnalysisResult;
  createdAt: string;
  source: 'user' | 'sample';
}

export interface SampleCase {
  id: string;
  title: string;
  category: 'Bancario' | 'Logistica' | 'Aziendale (BEC)' | 'Cloud & Account' | 'Legittimo';
  type: 'email' | 'url';
  difficulty: 'Base' | 'Intermedio' | 'Avanzato';
  expectedVerdict: RiskVerdict;
  sender?: string;
  subject?: string;
  content: string;
  description: string;
  learningPoint: string;
}
