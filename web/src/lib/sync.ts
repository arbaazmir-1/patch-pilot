import fs from 'node:fs';
import path from 'node:path';
import { getDb, setMeta } from './db.ts';
import { candidatePaths, isDirectory } from './discover.ts';
import { reportFileFor } from './paths.ts';
import { parseReport, toFindingRow, type ReportFinding, type ReportJson } from './report.ts';

export interface SyncError {
  path: string;
  message: string;
}

export interface SyncOutcome {
  imported: number;
  updated: number;
  unchanged: number;
  missing: number; // no report yet
  errors: SyncError[];
}

const RISKS = ['Critical', 'High', 'Medium', 'Low', 'Noise'] as const;

function riskCounts(report: ReportJson): Record<(typeof RISKS)[number], number> {
  const counts: Record<(typeof RISKS)[number], number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Noise: 0 };
  for (const risk of RISKS) counts[risk] = report.summary?.byRisk?.[risk] ?? 0;
  return counts;
}

// keyed by root
export function syncReports(): SyncOutcome {
  const db = getDb();
  const outcome: SyncOutcome = { imported: 0, updated: 0, unchanged: 0, missing: 0, errors: [] };
  const now = new Date().toISOString();

  const findProject = db.prepare('SELECT id FROM projects WHERE root = ?');
  const storedMtime = new Map(
    (db.prepare('SELECT root, report_mtime_ms FROM projects').all() as { root: string; report_mtime_ms: number | null }[]).map((r) => [
      r.root,
      r.report_mtime_ms,
    ]),
  );
  const hiddenRoots = new Set(
    (db.prepare('SELECT root FROM hidden_projects').all() as { root: string }[]).map((r) => r.root),
  );
  const insertProject = db.prepare(`
    INSERT INTO projects (
      name, root, remote, lockfile, lockfile_version, scanned_at, report_generated_at,
      patch_pilot_version, vuln_source_label, dependencies, direct_deps, dev_deps,
      vulnerable_packages, total_vulnerabilities, investigated,
      critical_count, high_count, medium_count, low_count, noise_count, accepted_count,
      findings_total, report_json, report_mtime_ms, imported_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const updateProject = db.prepare(`
    UPDATE projects SET
      name = ?, remote = ?, lockfile = ?, lockfile_version = ?, scanned_at = ?, report_generated_at = ?,
      patch_pilot_version = ?, vuln_source_label = ?, dependencies = ?, direct_deps = ?, dev_deps = ?,
      vulnerable_packages = ?, total_vulnerabilities = ?, investigated = ?,
      critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, noise_count = ?, accepted_count = ?,
      findings_total = ?, report_json = ?, report_mtime_ms = ?, updated_at = ?
    WHERE root = ?
  `);
  const deleteFindings = db.prepare('DELETE FROM findings WHERE project_id = ?');
  const insertFinding = db.prepare(`
    INSERT INTO findings (
      project_id, vuln_id, cve, package, version, summary, ghsa, cvss, affected_range,
      fixed_versions, direct, dev_only, risk, reachable, confidence, reasoning, evidence,
      recommendation_action, recommendation_text, target_version, major_bump, badges, "references",
      accepted, sort_index
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const upsertOne = db.transaction((root: string, report: ReportJson, mtimeMs: number) => {
    const existing = findProject.get(root) as { id: number } | undefined;

    const name = report.project?.name || path.basename(root);
    const byRisk = riskCounts(report);
    const findings = report.findings ?? [];
    const summary = report.summary ?? {};
    const counts = report.counts ?? {};
    const reportJson = JSON.stringify(report);
    const values = [
      name,
      null, // not in the report
      report.project?.lockfile ?? null,
      report.project?.lockfileVersion ?? null,
      report.scannedAt ?? null,
      report.generatedAt ?? null,
      report.patchPilotVersion ?? null,
      report.vulnSource?.label ?? null,
      counts.dependencies ?? null,
      counts.direct ?? null,
      counts.dev ?? null,
      counts.vulnerablePackages ?? null,
      counts.vulnerabilities ?? summary.cves ?? findings.length,
      summary.investigated ?? findings.length,
      byRisk.Critical,
      byRisk.High,
      byRisk.Medium,
      byRisk.Low,
      byRisk.Noise,
      summary.accepted ?? 0,
      findings.length,
      reportJson,
      mtimeMs,
    ];

    let projectId: number;
    if (existing) {
      updateProject.run(...values, now, root);
      projectId = existing.id;
      deleteFindings.run(projectId);
      outcome.updated += 1;
    } else {
      const info = insertProject.run(values[0], root, ...values.slice(1), now, now);
      projectId = Number(info.lastInsertRowid);
      outcome.updated += 1;
    }

    findings.forEach((finding: ReportFinding, index: number) => {
      const row = toFindingRow(finding, index, projectId);
      insertFinding.run(
        row.project_id,
        row.vuln_id,
        row.cve,
        row.package,
        row.version,
        row.summary,
        row.ghsa,
        row.cvss,
        row.affected_range,
        row.fixed_versions,
        row.direct,
        row.dev_only,
        row.risk,
        row.reachable,
        row.confidence,
        row.reasoning,
        row.evidence,
        row.recommendation_action,
        row.recommendation_text,
        row.target_version,
        row.major_bump,
        row.badges,
        row.references,
        row.accepted,
        row.sort_index,
      );
    });
  });

  for (const candidate of candidatePaths()) {
    if (hiddenRoots.has(candidate.path)) continue;
    if (!isDirectory(candidate.path)) {
      outcome.missing += 1;
      continue;
    }
    const reportFile = reportFileFor(candidate.path);
    let mtimeMs: number;
    try {
      mtimeMs = Math.round(fs.statSync(reportFile).mtimeMs);
    } catch {
      outcome.missing += 1;
      continue;
    }
    // skip unchanged before reading
    if (storedMtime.get(candidate.path) === mtimeMs) {
      outcome.imported += 1;
      outcome.unchanged += 1;
      continue;
    }
    try {
      const report = parseReport(JSON.parse(fs.readFileSync(reportFile, 'utf8')));
      if (!report) {
        outcome.errors.push({ path: candidate.path, message: `${reportFile} is not a patch-pilot report` });
        continue;
      }
      upsertOne(candidate.path, report, mtimeMs);
      outcome.imported += 1;
    } catch (error) {
      outcome.errors.push({ path: candidate.path, message: error instanceof Error ? error.message : String(error) });
    }
  }

  setMeta('last_sync_at', now);
  return outcome;
}
