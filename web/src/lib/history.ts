// past runs the cli archived under .patch-pilot/history/<runId>/
import fs from 'node:fs';
import path from 'node:path';
import { historyDirFor } from './paths.ts';
import { RISK_ORDER, riskRank, type FindingRow, type RiskLevel } from './queries.ts';
import { parseReport, toFindingRow, type ReportJson } from './report.ts';

// "2026-10-01T10-22-33Z", the cli's runId()
export const RUN_ID_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$/;

export interface RunSummary {
  id: string;
  at: string;
  byRisk: Record<RiskLevel, number>;
  cves: number;
  investigated: number;
  accepted: number;
  provider: string | null;
  model: string | null;
  // only when the report says so
  incomplete: boolean;
  // why there is nothing to show
  problem: 'missing' | 'damaged' | null;
}

export interface RunDetail {
  summary: RunSummary;
  report: ReportJson;
  findings: FindingRow[];
}

export function isRunId(value: string | undefined): value is string {
  return typeof value === 'string' && RUN_ID_PATTERN.test(value);
}

// "2026-10-01T10-22-33Z" -> "2026-10-01T10:22:33Z"
export function runIdTime(id: string): string {
  return id.replace(/T(\d{2})-(\d{2})-(\d{2})Z$/, 'T$1:$2:$3Z');
}

function validDate(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  return Number.isNaN(new Date(value).getTime()) ? null : value;
}

export function summarizeReport(id: string, report: ReportJson | null, problem: RunSummary['problem'] = null): RunSummary {
  const byRisk = Object.fromEntries(RISK_ORDER.map((r) => [r, report?.summary?.byRisk?.[r] ?? 0])) as Record<RiskLevel, number>;
  const findings = report?.findings ?? [];
  const inv = report?.investigation ?? null;
  const model = inv?.models && inv.models.length > 0 ? inv.models.join(', ') : (inv?.model ?? null);
  return {
    id,
    at: validDate(report?.generatedAt) ?? runIdTime(id),
    byRisk,
    cves: report?.counts?.vulnerabilities ?? report?.summary?.cves ?? findings.length,
    investigated: report?.summary?.investigated ?? findings.length,
    accepted: report?.summary?.accepted ?? 0,
    provider: inv?.provider ?? null,
    model,
    incomplete: inv?.complete === false,
    problem,
  };
}

function runDir(root: string, id: string): string | null {
  if (!isRunId(id)) return null;
  const dir = path.join(historyDirFor(root), id);
  try {
    return fs.statSync(dir).isDirectory() ? dir : null;
  } catch {
    return null;
  }
}

function readReport(dir: string): { report: ReportJson | null; problem: RunSummary['problem'] } {
  let text: string;
  try {
    text = fs.readFileSync(path.join(dir, 'report.json'), 'utf8');
  } catch {
    return { report: null, problem: 'missing' };
  }
  try {
    const report = parseReport(JSON.parse(text));
    return report ? { report, problem: null } : { report: null, problem: 'damaged' };
  } catch {
    return { report: null, problem: 'damaged' };
  }
}

// newest first
export function listRuns(root: string): RunSummary[] {
  let names: string[];
  try {
    names = fs.readdirSync(historyDirFor(root));
  } catch {
    return [];
  }
  const runs: RunSummary[] = [];
  for (const id of names) {
    const dir = runDir(root, id);
    if (!dir) continue;
    const { report, problem } = readReport(dir);
    runs.push(summarizeReport(id, report, problem));
  }
  return runs.sort((a, b) => (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
}

export function readRun(root: string, id: string): RunDetail | null {
  const dir = runDir(root, id);
  if (!dir) return null;
  const { report } = readReport(dir);
  if (!report) return null;
  const findings = (report.findings ?? [])
    .map((f, i) => toFindingRow(f, i))
    .sort((a, b) => riskRank(a.risk) - riskRank(b.risk) || a.sort_index - b.sort_index);
  return { summary: summarizeReport(id, report), report, findings };
}

export type FindingChange = { kind: 'fixed' } | { kind: 'risk'; now: string; worse: boolean };

export interface RunComparison {
  changes: Map<FindingRow, FindingChange>;
  fixed: number;
  riskChanged: number;
  // in the latest run only
  added: number;
}

const findingKey = (f: FindingRow): string => `${f.vuln_id}|${f.package}|${f.version ?? ''}`;

// how a past run's findings look in the latest run
export function compareToLatest(past: FindingRow[], latest: FindingRow[]): RunComparison {
  const latestByKey = new Map(latest.map((f) => [findingKey(f), f]));
  const pastKeys = new Set(past.map(findingKey));
  const changes = new Map<FindingRow, FindingChange>();
  let fixed = 0;
  let riskChanged = 0;
  for (const f of past) {
    const now = latestByKey.get(findingKey(f));
    if (!now) {
      changes.set(f, { kind: 'fixed' });
      fixed += 1;
    } else if ((now.risk ?? '') !== (f.risk ?? '')) {
      changes.set(f, { kind: 'risk', now: now.risk ?? 'unrated', worse: riskRank(now.risk) < riskRank(f.risk) });
      riskChanged += 1;
    }
  }
  const added = [...latestByKey.keys()].filter((k) => !pastKeys.has(k)).length;
  return { changes, fixed, riskChanged, added };
}
