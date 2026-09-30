import { getDb } from './db.ts';

export interface ProjectRow {
  id: number;
  name: string;
  root: string;
  remote: string | null;
  lockfile: string | null;
  lockfile_version: number | null;
  scanned_at: string | null;
  report_generated_at: string | null;
  patch_pilot_version: string | null;
  vuln_source_label: string | null;
  dependencies: number | null;
  direct_deps: number | null;
  dev_deps: number | null;
  vulnerable_packages: number | null;
  total_vulnerabilities: number | null;
  investigated: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  noise_count: number;
  accepted_count: number;
  findings_total: number;
  report_json: string | null;
  report_mtime_ms: number | null;
  imported_at: string;
  updated_at: string;
}

export interface FindingRow {
  id: number;
  project_id: number;
  vuln_id: string;
  cve: string;
  package: string;
  version: string | null;
  summary: string | null;
  ghsa: string | null;
  cvss: number | null;
  affected_range: string | null;
  fixed_versions: string;
  direct: number | null;
  dev_only: number | null;
  risk: string | null;
  reachable: string | null;
  confidence: number | null;
  reasoning: string | null;
  evidence: string;
  recommendation_action: string | null;
  recommendation_text: string | null;
  target_version: string | null;
  major_bump: number | null;
  badges: string;
  references: string;
  accepted: number;
  sort_index: number;
}

export const RISK_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Noise'] as const;

export type RiskLevel = (typeof RISK_ORDER)[number];

const RISK_COLUMN = {
  Critical: 'critical_count',
  High: 'high_count',
  Medium: 'medium_count',
  Low: 'low_count',
  Noise: 'noise_count',
} as const satisfies Record<RiskLevel, keyof ProjectRow>;

export function riskCount(p: ProjectRow, risk: RiskLevel): number {
  return p[RISK_COLUMN[risk]];
}

export function riskRank(risk: string | null | undefined): number {
  const index = RISK_ORDER.indexOf(risk as RiskLevel);
  return index === -1 ? RISK_ORDER.length : index;
}

// worst risk first
export function listProjects(): ProjectRow[] {
  const rows = getDb().prepare('SELECT * FROM projects').all() as ProjectRow[];
  return rows.sort((a, b) => {
    for (const risk of RISK_ORDER) {
      const diff = riskCount(b, risk) - riskCount(a, risk);
      if (diff !== 0) return diff;
    }
    return a.name.localeCompare(b.name);
  });
}

export function getProject(id: number): ProjectRow | null {
  const row = getDb().prepare('SELECT * FROM projects WHERE id = ?').get(id) as ProjectRow | undefined;
  return row ?? null;
}

export function getFindings(projectId: number): FindingRow[] {
  const rows = getDb().prepare('SELECT * FROM findings WHERE project_id = ? ORDER BY sort_index').all(projectId) as FindingRow[];
  return rows.sort((a, b) => riskRank(a.risk) - riskRank(b.risk) || a.sort_index - b.sort_index);
}

export function deleteProject(id: number): boolean {
  const info = getDb().prepare('DELETE FROM projects WHERE id = ?').run(id);
  return info.changes > 0;
}

export function hideProject(root: string): void {
  getDb()
    .prepare('INSERT INTO hidden_projects (root, hidden_at) VALUES (?, ?) ON CONFLICT(root) DO NOTHING')
    .run(root, new Date().toISOString());
}

export function unhideProject(root: string): void {
  getDb().prepare('DELETE FROM hidden_projects WHERE root = ?').run(root);
}

export interface HiddenProject {
  root: string;
  hidden_at: string;
}

export function listHiddenProjects(): HiddenProject[] {
  return getDb().prepare('SELECT root, hidden_at FROM hidden_projects ORDER BY hidden_at DESC').all() as HiddenProject[];
}
