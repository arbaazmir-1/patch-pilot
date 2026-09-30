import type { FindingRow } from './queries.ts';

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

// same shape sync.ts stores, so FindingCard can render archived findings too
export function toFindingRow(finding: ReportFinding, index: number, projectId = 0): FindingRow {
  const flag = (value: boolean | null | undefined): number | null => (value === undefined || value === null ? null : value ? 1 : 0);
  return {
    id: index,
    project_id: projectId,
    vuln_id: finding.vulnId ?? finding.cve ?? `unknown-${index}`,
    cve: finding.cve ?? finding.vulnId ?? 'unknown',
    package: finding.package ?? 'unknown',
    version: finding.version ?? null,
    summary: finding.summary ?? null,
    ghsa: finding.ghsa ?? null,
    cvss: finding.cvss ?? null,
    affected_range: finding.affectedRange ?? null,
    fixed_versions: JSON.stringify(finding.fixedVersions ?? []),
    direct: flag(finding.direct),
    dev_only: flag(finding.devOnly),
    risk: finding.risk ?? null,
    reachable: finding.reachable ?? null,
    confidence: finding.confidence ?? null,
    reasoning: finding.reasoning ?? null,
    evidence: JSON.stringify(finding.evidence ?? []),
    recommendation_action: finding.recommendation?.action ?? null,
    recommendation_text: finding.recommendation?.text ?? null,
    target_version: finding.recommendation?.targetVersion ?? null,
    major_bump: finding.recommendation?.majorBump === undefined ? null : finding.recommendation.majorBump ? 1 : 0,
    badges: JSON.stringify(finding.badges ?? []),
    references: JSON.stringify(finding.references ?? []),
    accepted: finding.accepted ? 1 : 0,
    sort_index: index,
  };
}
