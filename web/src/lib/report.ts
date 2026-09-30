// subset of the cli report.json, all optional

export interface ReportRecommendation {
  action?: string;
  targetVersion?: string | null;
  majorBump?: boolean;
  notes?: string;
  text?: string;
}

export interface ReportFinding {
  vulnId?: string;
  cve?: string;
  aliases?: string[];
  package?: string;
  version?: string;
  summary?: string;
  ghsa?: string;
  cvss?: number | null;
  cvssVector?: string | null;
  affectedRange?: string | null;
  fixedVersions?: string[];
  direct?: boolean | null;
  devOnly?: boolean | null;
  risk?: string;
  reachable?: string;
  confidence?: number;
  reasoning?: string;
  evidence?: string[];
  recommendation?: ReportRecommendation;
  badges?: string[];
  references?: string[];
  accepted?: { reason?: string; by?: string; until?: string | null } | null;
}

export interface ReportProject {
  root?: string;
  name?: string;
  lockfile?: string | null;
  lockfileVersion?: number | null;
}

export interface ReportCounts {
  dependencies?: number;
  direct?: number;
  dev?: number;
  vulnerablePackages?: number;
  vulnerabilities?: number;
}

export interface ReportSummary {
  cves?: number;
  investigated?: number;
  byRisk?: Record<string, number>;
  accepted?: number;
}

export interface ReportInvestigation {
  provider?: string;
  model?: string;
  models?: string[];
  complete?: boolean;
  cached?: number;
  adjusted?: number;
  forced?: number;
  verdicts?: number;
}

export interface ReportJson {
  schema?: string;
  version?: number;
  generatedAt?: string;
  patchPilotVersion?: string;
  project?: ReportProject;
  scannedAt?: string | null;
  vulnSource?: { label?: string; mode?: string } | null;
  counts?: ReportCounts | null;
  summary?: ReportSummary | null;
  investigation?: ReportInvestigation | null;
  findings?: ReportFinding[];
}

export function parseReport(raw: unknown): ReportJson | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const report = raw as ReportJson;
  if (report.schema !== 'patch-pilot.report') return null;
  return report;
}
