import path from 'node:path';
import { readAuditFile } from '../audit.ts';
import { findIgnore, readIgnoreEntries } from '../config.ts';
import { loadCaseFile, formatVulnSource, severityLabel } from '../evidence/casefile.ts';
import { loadAssessment } from '../investigation/assessment.ts';
import { recommendationText } from '../investigation/agent.ts';
import { displayVulnId } from '../investigation/prompts.ts';
import type {
  Action,
  Assessment,
  AuditRecord,
  AuditSink,
  CaseFile,
  Config,
  IgnoreEntry,
  Phase3Result,
  RiskLevel,
  Verdict,
} from '../types.ts';
import type { Ui } from '../ui.ts';
import { EXIT, PatchPilotError } from '../util/errors.ts';
import { atomicWrite, relativePosix, writeJsonAtomic } from '../util/fs.ts';
import { VERSION } from '../version.ts';
import { clean, sortVerdicts, verdictBadges, vulnFor } from './present.ts';

export interface ReportInput {
  config: Config;
  caseFile: CaseFile | null;
  assessment: Assessment | null;
  audit: readonly AuditRecord[];
  phase3?: Phase3Result | null;
}

export const REPORT_SCHEMA_VERSION = 1;

type RecordOf<N extends AuditRecord['event']> = Extract<AuditRecord, { event: N }>;

function isEvent<N extends AuditRecord['event']>(name: N): (r: AuditRecord) => r is RecordOf<N> {
  return (r: AuditRecord): r is RecordOf<N> => r.event === name;
}

// since the latest case file's run, else all
export function sessionRecords(records: readonly AuditRecord[]): AuditRecord[] {
  for (let i = records.length - 1; i >= 0; i -= 1) {
    const r = records[i] as AuditRecord;
    if (r.event !== 'casefile.saved') continue;
    const start = records.findIndex((x) => x.run === r.run);
    return records.slice(start === -1 ? i : start);
  }
  return [...records];
}

function auditRecordsOf(audit: AuditSink, config: Config): AuditRecord[] {
  const withRead = audit as AuditSink & { read?: () => AuditRecord[]; records?: AuditRecord[] };
  if (typeof withRead.read === 'function') return withRead.read();
  if (Array.isArray(withRead.records)) return [...withRead.records];
  return readAuditFile(config.paths.auditLog);
}

function shortHash(hash: string | null | undefined): string {
  return hash ? hash.slice(0, 12) : '';
}

// also drops em dashes
function cell(value: unknown): string {
  const text = clean(value === null || value === undefined ? '' : String(value));
  return text.replace(/\r?\n+/g, ' ').replace(/\|/g, '\\|').trim();
}

function pct(confidence: number): string {
  return `${Math.round(Math.min(1, Math.max(0, confidence)) * 100)}%`;
}

function identityText(by: { osUser: string; gitName: string | null; gitEmail: string | null } | undefined): string {
  if (!by) return 'unknown';
  const git = by.gitName && by.gitEmail ? `${by.gitName} <${by.gitEmail}>` : (by.gitName ?? by.gitEmail);
  return git ? `${git} (os user ${by.osUser})` : by.osUser;
}

const RISKS: readonly RiskLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Noise'];

// report.json as is, rendered into report.md
export function buildReportJson(input: ReportInput): Record<string, unknown> {
  const { config, caseFile, assessment } = input;
  const records = sessionRecords(input.audit);
  const phase3 = input.phase3 ?? null;
  const now = new Date();
  const verdicts: Verdict[] = assessment ? (caseFile ? sortVerdicts(assessment.verdicts, caseFile) : [...assessment.verdicts]) : [];

  const byRisk: Record<RiskLevel, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Noise: 0 };
  for (const v of verdicts) byRisk[v.risk] += 1;

  const acceptedFor = (vulnId: string, pkg: string, aliases: readonly string[]): { entry: IgnoreEntry; expired: boolean } | null =>
    findIgnore(config.ignore, vulnId, pkg, aliases, now);

  const findings = verdicts.map((v) => {
    const vuln = vulnFor(v, caseFile);
    const accepted = acceptedFor(v.vulnId, v.package, vuln ? [...vuln.aliases, ...vuln.mergedIds] : []);
    const inv = v.investigation;
    return {
      vulnId: v.vulnId,
      cve: vuln ? displayVulnId(vuln) : v.vulnId,
      aliases: vuln?.aliases ?? [],
      package: v.package,
      version: v.installedVersion,
      summary: clean(vuln?.summary ?? ''),
      ghsa: vuln ? severityLabel(vuln.severity, vuln.malware) : 'UNKNOWN',
      cvss: vuln?.severity.cvssScore ?? null,
      cvssVector: vuln?.severity.cvssVector ?? null,
      affectedRange: vuln?.affectedRange ?? null,
      fixedVersions: vuln?.fixedVersions ?? [],
      direct: vuln?.isDirect ?? null,
      devOnly: vuln?.isDevOnly ?? null,
      risk: v.risk,
      reachable: v.reachable,
      confidence: v.confidence,
      reasoning: clean(v.reasoning),
      evidence: v.evidence.map((e) => clean(e)),
      recommendation: { ...v.recommendation, text: recommendationText(v.recommendation) },
      badges: verdictBadges(v),
      investigation: {
        provider: inv?.provider ?? null,
        model: inv?.model ?? null,
        promptVersion: inv?.promptVersion ?? null,
        steps: inv?.steps ?? 0,
        durationMs: inv?.durationMs ?? 0,
        forced: inv?.forced ?? false,
        cached: inv?.cached ?? false,
        adjusted: inv?.adjusted ?? false,
        ...(inv?.adjusted ? { originalRisk: inv.originalRisk ?? null, adjustReason: inv.adjustReason ?? null } : {}),
        gate: inv?.gate ?? null,
        toolCalls: (inv?.toolCalls ?? []).map((t) => ({ stage: t.stage, tool: t.tool, args: t.args, by: t.by, ok: t.ok, summary: clean(t.summary) })),
      },
      references: (vuln?.references ?? []).slice(0, 5).map((r) => r.url),
      accepted: accepted ? { reason: clean(accepted.entry.reason), by: accepted.entry.by, since: accepted.entry.createdAt, until: accepted.entry.until ?? null, expired: accepted.expired } : null,
    };
  });

  const acceptedRisks = config.ignore.map((entry) => {
    const matches = (caseFile?.vulnerabilities ?? []).filter((v) => findIgnore([entry], v.id, v.package, [...v.aliases, ...v.mergedIds], now) !== null);
    const expired = findIgnore([entry], entry.id, entry.package ?? '', [], now)?.expired ?? false;
    return {
      id: entry.id,
      package: entry.package ?? null,
      reason: clean(entry.reason),
      by: entry.by,
      createdAt: entry.createdAt,
      until: entry.until ?? null,
      expired,
      matches: matches.map((m) => `${m.package}@${m.installedVersion} ${m.id}`),
    };
  });

  const approvalRecords = records.filter(isEvent('approval'));
  const approvals = approvalRecords
    .filter((r) => !r.actionId.startsWith('post:'))
    .map((r) => ({
      actionId: r.actionId,
      package: r.package,
      kind: r.kind,
      decision: r.decision,
      mode: r.mode,
      scope: r.scope,
      files: r.files ?? null,
      by: r.by,
      at: r.ts,
      reason: r.reason ? clean(r.reason) : null,
    }));
  const applies = records.filter(isEvent('patch.apply'));
  const postCommands = approvalRecords
    .filter((r) => r.actionId.startsWith('post:'))
    .map((r) => {
      const outcome = applies.find((a) => a.actionId === r.actionId && a.ts >= r.ts);
      return { id: r.actionId, command: r.reason ?? r.actionId, decision: r.decision, by: r.by, at: r.ts, ok: outcome ? outcome.ok : null, error: outcome?.error ?? null };
    });
  const patchApplies = applies
    .filter((r) => !r.actionId.startsWith('post:'))
    .map((r) => ({ actionId: r.actionId, package: r.package, kind: r.kind, before: r.before, after: r.after, command: r.command ?? null, ok: r.ok, error: r.error ? clean(r.error) : null, at: r.ts, files: r.files }));
  const filesChanged = patchApplies.filter((a) => a.ok).flatMap((a) => a.files.map((f) => ({ path: f.path, actionId: a.actionId, beforeHash: f.beforeHash, afterHash: f.afterHash, at: a.at })));
  const verification = records.filter(isEvent('verify.result')).map((r) => ({ vulnId: r.vulnId, package: r.package, cleared: r.cleared, versions: r.versions, at: r.ts }));
  const rollbacks = records.filter(isEvent('rollback')).map((r) => ({ backupId: r.backupId, restored: r.restored, mismatched: r.mismatched, reason: clean(r.reason), at: r.ts }));
  const backups = records.filter(isEvent('patch.backup')).map((r) => ({ backupId: r.backupId, dir: r.dir, files: r.files, at: r.ts }));
  const lockfileDiffs = records.filter(isEvent('lockfile.diff')).map((r) => ({ actionId: r.actionId, added: r.added, removed: r.removed, changed: r.changed, unexpected: r.unexpected, decision: r.decision, at: r.ts }));
  const codemodsApplied = records.filter(isEvent('codemod.applied')).map((r) => ({ package: r.package, file: r.file, beforeHash: r.beforeHash, afterHash: r.afterHash, syntaxOk: r.syntaxOk, at: r.ts }));
  const errors = records.filter(isEvent('error')).map((r) => ({ message: clean(r.message), phase: r.phase ?? null, at: r.ts }));

  // this run's actions, then the audit
  const searches = records.filter(isEvent('migration.search'));
  const briefEvents = records.filter(isEvent('migration.brief'));
  const actionBriefs = (phase3?.actions ?? []).filter((a) => a.brief);
  const migrationKeys = new Set<string>();
  const migrations: Record<string, unknown>[] = [];
  for (const a of actionBriefs) {
    const brief = a.brief as NonNullable<Action['brief']>;
    migrationKeys.add(`${brief.package}|${brief.to}`);
    migrations.push({
      package: brief.package,
      from: brief.from,
      to: brief.to,
      offline: brief.offline,
      model: brief.model,
      createdAt: brief.createdAt,
      items: brief.items.map((i) => ({ ...i, change: clean(i.change), evidenceQuote: clean(i.evidenceQuote) })),
      sources: brief.sources.map((s) => ({ url: s.url, kind: s.kind, title: s.title ? clean(s.title) : null, version: s.version, cached: s.cached, fetchedAt: s.fetchedAt })),
      queries: brief.queries,
      codemod: a.codemod
        ? {
            model: a.codemod.model,
            files: a.codemod.patches.map((p) => ({ file: p.file, edits: p.edits.length, beforeHash: p.beforeHash, diff: p.diff })),
            rejected: a.codemod.rejected.map((r) => ({ file: r.file, reason: clean(r.reason) })),
            manualChecklist: a.codemod.manualChecklist,
          }
        : null,
    });
  }
  for (const b of briefEvents) {
    if (migrationKeys.has(`${b.package}|${b.to}`)) continue;
    migrationKeys.add(`${b.package}|${b.to}`);
    migrations.push({
      package: b.package,
      from: b.from,
      to: b.to,
      offline: b.offline,
      items: b.items,
      verified: b.verified,
      sources: b.sources.map((url) => ({ url })),
      queries: searches.filter((s) => s.package === b.package).map((s) => ({ query: s.query, backend: s.backend, urls: s.urls, cached: s.cached })),
    });
  }

  const actions = (phase3?.actions ?? []).map((a) => ({
    id: a.id,
    kind: a.kind,
    package: a.package,
    from: a.fromVersion,
    to: a.toVersion,
    vulnIds: a.vulnIds,
    worstRisk: a.worstRisk,
    majorBump: a.majorBump,
    direct: a.direct,
    parents: a.parents,
    importedInSource: a.importedInSource,
    requiresMigration: a.requiresMigration,
    engines: a.engines,
    notes: a.notes.map((n) => clean(n)),
  }));

  const cleared = new Set(verification.filter((v) => v.cleared).map((v) => `${v.vulnId}|${v.package}`));
  const acceptedOpen = verdicts.filter((v) => {
    const hit = acceptedFor(v.vulnId, v.package, []);
    return hit && !hit.expired && !cleared.has(`${v.vulnId}|${v.package}`);
  }).length;
  const results = phase3?.results ?? [];
  const summary = {
    cves: caseFile?.vulnerabilities.length ?? verdicts.length,
    investigated: verdicts.length,
    byRisk,
    accepted: acceptedOpen,
    actions: phase3 ? phase3.actions.length : null,
    approved: approvals.filter((a) => a.decision === 'approve').length,
    rejected: approvals.filter((a) => a.decision === 'reject').length,
    riskAccepted: approvals.filter((a) => a.decision === 'accept-risk').length,
    applied: phase3 ? results.filter((r) => r.ok).length : patchApplies.filter((a) => a.ok).length,
    failed: phase3 ? results.filter((r) => !r.ok && r.rolledBack).length : patchApplies.filter((a) => !a.ok).length,
    cleared: cleared.size,
    deferred: Math.max(0, verdicts.filter((v) => !cleared.has(`${v.vulnId}|${v.package}`)).length - acceptedOpen),
    exitCode: phase3?.exitCode ?? null,
  };

  const models = [...new Set(verdicts.map((v) => v.investigation?.model).filter((m): m is string => typeof m === 'string'))];
  const codemodModels = [...new Set([...records.filter(isEvent('codemod.proposed')).map((r) => r.model), ...actionBriefs.map((a) => a.codemod?.model).filter((m): m is string => typeof m === 'string')])];
  const scanStart = records.filter(isEvent('scan.start'));
  const preflight = records.filter(isEvent('preflight')).at(-1);

  return {
    schema: 'patch-pilot.report',
    version: REPORT_SCHEMA_VERSION,
    generatedAt: now.toISOString(),
    patchPilotVersion: VERSION,
    project: caseFile ? { ...caseFile.project, root: config.projectRoot } : { root: config.projectRoot, name: path.basename(config.projectRoot), lockfile: null, lockfileVersion: null },
    scannedAt: caseFile?.scannedAt ?? null,
    vulnSource: caseFile ? { ...caseFile.vulnSource, label: formatVulnSource(caseFile.vulnSource) } : null,
    counts: caseFile?.counts ?? null,
    investigation: assessment
      ? {
          provider: assessment.provider,
          model: assessment.model,
          models,
          codemodModels,
          ollamaVersion: preflight?.ollamaVersion ?? null,
          promptVersion: assessment.promptVersion,
          complete: assessment.complete,
          createdAt: assessment.createdAt,
          updatedAt: assessment.updatedAt,
          caseFileHash: assessment.caseFileHash,
          verdicts: verdicts.length,
          cached: verdicts.filter((v) => v.investigation?.cached).length,
          adjusted: verdicts.filter((v) => v.investigation?.adjusted).length,
          forced: verdicts.filter((v) => v.investigation?.forced).length,
        }
      : null,
    runs: scanStart.map((r) => ({ run: r.run, command: r.command, at: r.ts, provider: r.provider, model: r.model })),
    summary,
    findings,
    acceptedRisks,
    actions,
    approvals,
    backups,
    patches: patchApplies,
    lockfileDiffs,
    codemods: codemodsApplied,
    filesChanged,
    verification,
    rollbacks,
    postCommands,
    migrations,
    errors,
  };
}

type Json = Record<string, any>;

function table(headers: readonly string[], rows: readonly (readonly unknown[])[]): string[] {
  if (rows.length === 0) return [];
  return [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`)];
}

export function renderReportMarkdown(input: ReportInput): string {
  return markdownFromModel(buildReportJson(input));
}

// same model, so both files agree
function markdownFromModel(reportModel: Record<string, unknown>): string {
  const model = reportModel as Json;
  const out: string[] = [];
  const push = (...lines: string[]): void => {
    out.push(...lines);
  };
  const project = model.project as Json;
  push(`# PatchPilot report: ${cell(project.name)}`, '');
  push(`Generated ${model.generatedAt} by PatchPilot ${model.patchPilotVersion}.`, '');
  push(`- Project: \`${project.root}\`${project.lockfile ? `, lockfile \`${project.lockfile}\` (v${project.lockfileVersion})` : ''}`);
  if (model.scannedAt) push(`- Scanned: ${model.scannedAt}`);
  const source = model.vulnSource as Json | null;
  if (source) push(`- Vulnerability data: ${cell(source.label)}, fetched ${source.fetchedAt}${source.warning ? ` (warning: ${cell(source.warning)})` : ''}`);
  const counts = model.counts as Json | null;
  if (counts) push(`- Dependencies: ${counts.dependencies} (${counts.direct} direct, ${counts.dev} dev); ${counts.vulnerabilities} CVEs across ${counts.vulnerablePackages} packages`);
  const inv = model.investigation as Json | null;
  if (inv) {
    push(`- Investigation: ${cell(inv.provider)} ${cell((inv.models as string[]).join(', ') || inv.model)}${inv.ollamaVersion ? ` (Ollama ${inv.ollamaVersion})` : ''}, prompt version \`${inv.promptVersion}\`${inv.complete ? '' : ' (incomplete: run `patch-pilot investigate --resume`)'}`);
    push(`- Verdict cache: ${inv.cached} of ${inv.verdicts} verdicts served from cache; ${inv.adjusted} adjusted by the rails; ${inv.forced} forced`);
    if ((inv.codemodModels as string[]).length > 0) push(`- Codemod model: ${cell((inv.codemodModels as string[]).join(', '))}`);
  }
  const s = model.summary as Json;
  const riskText = RISKS.filter((r) => (s.byRisk as Json)[r] > 0).map((r) => `${(s.byRisk as Json)[r]} ${r.toLowerCase()}`).join(', ');
  push(`- Findings: ${s.investigated} of ${s.cves} CVEs investigated${riskText ? ` (${riskText})` : ''}`);
  push(`- Patches: ${s.applied} applied, ${s.failed} failed; ${s.cleared} CVEs verified cleared, ${s.deferred} deferred, ${s.accepted} accepted`);
  push('');

  const findings = model.findings as Json[];
  push('## Findings', '');
  if (findings.length === 0) push('No investigated vulnerabilities.', '');
  else {
    push(
      ...table(
        ['Risk', 'Package', 'Version', 'Vulnerability', 'GHSA', 'Reachable', 'Confidence', 'Recommended', 'Badges'],
        findings.map((f) => [f.risk, f.package, f.version, f.cve, f.ghsa, f.reachable, pct(f.confidence), (f.recommendation as Json).text, [...(f.badges as string[]), ...(f.accepted ? ['accepted'] : [])].join(', ')]),
      ),
      '',
    );
    push('## Verdicts', '');
    for (const f of findings) {
      push(`### ${cell(f.cve)}${f.cve !== f.vulnId ? ` (${f.vulnId})` : ''} · ${cell(f.package)}@${cell(f.version)}`, '');
      push(`- Risk: **${f.risk}** (GHSA ${f.ghsa}${f.cvss !== null ? `, CVSS ${Number(f.cvss).toFixed(1)}` : ''}) · reachable: ${f.reachable} · confidence: ${pct(f.confidence)}`);
      if (f.summary) push(`- Advisory: ${cell(f.summary)}${f.affectedRange ? ` (affected ${cell(f.affectedRange)})` : ''}`);
      push(`- Reasoning: ${cell(f.reasoning) || 'none given'}`);
      const evidence = f.evidence as string[];
      if (evidence.length > 0) {
        push('- Evidence:');
        for (const e of evidence) push(`  - ${cell(e)}`);
      }
      const rec = f.recommendation as Json;
      push(`- Recommendation: ${cell(rec.text)}${rec.notes ? ` (${cell(rec.notes)})` : ''}`);
      const i = f.investigation as Json;
      const tools = (i.toolCalls as Json[]).map((t) => `${t.tool}${t.by === 'harness' ? ' [harness]' : ''}`);
      const flags = [
        i.cached ? 'served from the verdict cache' : '',
        i.forced ? 'forced verdict (the model did not answer)' : '',
        i.adjusted ? `adjusted from ${i.originalRisk ?? '?'} by the rails${i.adjustReason ? `: ${cell(i.adjustReason)}` : ''}` : '',
        i.gate?.fired ? `evidence gate fired${(i.gate.harnessCalls as string[] | undefined)?.length ? ` (harness ran ${(i.gate.harnessCalls as string[]).join(', ')})` : ''}` : '',
      ].filter(Boolean);
      push(`- Investigation: ${cell(i.model ?? 'unknown model')}, ${i.steps} steps, ${Math.round((i.durationMs ?? 0) / 100) / 10} s${tools.length > 0 ? `, tools: ${cell(tools.join(', '))}` : ''}${flags.length > 0 ? `; ${cell(flags.join('; '))}` : ''}`);
      if (f.accepted) push(`- Accepted risk: ${cell(f.accepted.reason)} (by ${cell(f.accepted.by)}${f.accepted.until ? `, until ${f.accepted.until}` : ''}${f.accepted.expired ? ', expired' : ''})`);
      push('');
    }
  }

  const accepted = model.acceptedRisks as Json[];
  push('## Accepted risks', '');
  if (accepted.length === 0) push('None.', '');
  else push(...table(['Vulnerability', 'Package', 'Reason', 'Accepted by', 'Since', 'Until', 'Status'], accepted.map((a) => [a.id, a.package ?? 'any', a.reason, a.by, a.createdAt, a.until ?? 'no expiry', a.expired ? 'expired, reported again' : 'active'])), '');

  const actions = model.actions as Json[];
  if (actions.length > 0) {
    push('## Planned actions', '');
    push(...table(['Action', 'Package', 'From', 'To', 'Closes', 'Risk', 'Notes'], actions.map((a) => [a.kind, a.package, a.from, a.to, (a.vulnIds as string[]).join(', '), a.worstRisk, (a.notes as string[]).join(' ')])), '');
  }

  const approvals = model.approvals as Json[];
  push('## Approvals', '');
  if (approvals.length === 0) push('No approval decisions recorded.', '');
  else push(...table(['Action', 'Decision', 'Mode', 'Scope', 'By', 'At', 'Reason'], approvals.map((a) => [a.actionId, a.decision, a.mode, a.scope, identityText(a.by), a.at, a.reason ?? ''])), '');

  const migrations = model.migrations as Json[];
  if (migrations.length > 0) {
    push('## Migration briefs', '');
    for (const m of migrations) {
      push(`### ${cell(m.package)} ${m.from} to ${m.to}${m.offline ? ' (offline: cached sources only)' : ''}`, '');
      const items = Array.isArray(m.items) ? (m.items as Json[]) : [];
      if (items.length > 0) {
        push(...table(['Change', 'Applies', 'Verified', 'Old API', 'New API', 'Files', 'Evidence'], items.map((i) => [i.change, i.appliesToProject, i.verified ? 'yes' : 'no', i.oldApi, i.newApi, (i.affectedFiles as string[]).join(', '), `"${cell(i.evidenceQuote)}" ${i.evidenceUrl ?? ''}`])), '');
      } else if (typeof m.items === 'number') {
        push(`- ${m.items} items, ${m.verified} verified against their sources`);
      }
      const sources = (m.sources as Json[]) ?? [];
      if (sources.length > 0) {
        push('- Sources:');
        for (const src of sources) push(`  - ${src.url}${src.kind ? ` (${src.kind}${src.cached ? ', cached' : ''})` : ''}`);
      }
      const queries = (m.queries as Json[]) ?? [];
      if (queries.length > 0) {
        push('- Search queries:');
        for (const q of queries) push(`  - \`${cell(q.query)}\` via ${q.backend}${q.cached ? ' (cached)' : ''}: ${(q.urls as string[]).slice(0, 3).join(', ') || 'no results'}`);
      }
      const codemod = m.codemod as Json | null | undefined;
      if (codemod) {
        push(`- Code edits (${cell(codemod.model)}): ${(codemod.files as Json[]).map((f) => `${f.file} (${f.edits} edits)`).join(', ') || 'none validated'}`);
        if ((codemod.rejected as Json[]).length > 0) push(`- Rejected edits: ${(codemod.rejected as Json[]).map((r) => `${r.file}: ${cell(r.reason)}`).join('; ')}`);
        for (const f of codemod.files as Json[]) push('', `\`\`\`diff`, String(f.diff).trimEnd(), '```');
      }
      push('');
    }
  }

  const patches = model.patches as Json[];
  if (patches.length > 0) {
    push('## Patches', '');
    push(...table(['Action', 'Before', 'After', 'Command', 'Result', 'At'], patches.map((p) => [p.actionId, p.before, p.after ?? '', p.command ? (p.command as string[]).join(' ') : '', p.ok ? 'applied' : `failed: ${p.error ?? 'unknown error'}`, p.at])), '');
  }
  const diffs = model.lockfileDiffs as Json[];
  if (diffs.length > 0) {
    push('## Lockfile diff guard', '');
    push(...table(['Action', 'Added', 'Removed', 'Changed', 'Unexpected', 'Decision'], diffs.map((d) => [d.actionId, d.added, d.removed, d.changed, (d.unexpected as string[]).join(', ') || 'none', d.decision])), '');
  }
  const files = model.filesChanged as Json[];
  push('## Files changed', '');
  if (files.length === 0) push('No project file was changed.', '');
  else push(...table(['File', 'Action', 'sha256 before', 'sha256 after'], files.map((f) => [f.path, f.actionId, shortHash(f.beforeHash), shortHash(f.afterHash)])), '');
  const verification = model.verification as Json[];
  push('## Verification', '');
  if (verification.length === 0) push('No patch was verified in this session.', '');
  else push(...table(['Vulnerability', 'Package', 'Cleared', 'Installed versions', 'At'], verification.map((v) => [v.vulnId, v.package, v.cleared ? 'yes' : 'no', (v.versions as string[]).join(', ') || 'removed', v.at])), '');
  const rollbacks = model.rollbacks as Json[];
  if (rollbacks.length > 0) {
    push('## Rollbacks', '');
    push(...table(['Backup', 'Restored', 'Kept (changed since)', 'Reason', 'At'], rollbacks.map((r) => [r.backupId, (r.restored as string[]).join(', ') || 'nothing', (r.mismatched as string[]).join(', ') || 'none', r.reason, r.at])), '');
    push('node_modules is never restored by a rollback: run your package manager\'s install afterwards (`npm install --ignore-scripts`, `yarn install` or `pnpm install`).', '');
  }
  const post = model.postCommands as Json[];
  if (post.length > 0) {
    push('## Post-apply commands', '');
    push(...table(['Command', 'Decision', 'By', 'At', 'Result'], post.map((p) => [p.command, p.decision, identityText(p.by), p.at, p.ok === null ? 'not run' : p.ok ? 'passed' : `failed${p.error ? `: ${p.error}` : ''}`])), '');
  }
  const errors = model.errors as Json[];
  if (errors.length > 0) {
    push('## Errors', '');
    for (const e of errors) push(`- ${e.at}${e.phase ? ` (${e.phase})` : ''}: ${cell(e.message)}`);
    push('');
  }
  push('The machine-readable twin of this report is `.patch-pilot/report.json`; every event is in `.patch-pilot/audit.jsonl`.', '');
  return clean(out.join('\n'));
}

export async function writeReports(
  config: Config,
  deps: { ui: Ui; audit: AuditSink; phase3?: Phase3Result | null; caseFile?: CaseFile | null; assessment?: Assessment | null },
): Promise<{ md: string; json: string }> {
  const caseFile = deps.caseFile !== undefined ? deps.caseFile : await loadCaseFile(config.paths.caseFile);
  const assessment = deps.assessment !== undefined ? deps.assessment : await loadAssessment(config.paths.assessmentFile);
  if (!caseFile && !assessment) {
    throw new PatchPilotError(`Nothing to report yet: no case file or assessment in ${relativePosix(config.projectRoot, config.paths.stateDir) || config.paths.stateDir}`, {
      exitCode: EXIT.USAGE,
      hint: 'Run `patch-pilot scan` first.',
    });
  }
  let ignore = config.ignore;
  try {
    ignore = await readIgnoreEntries(config.projectRoot);
  } catch {
    // keep loaded entries if the file broke
  }
  const input: ReportInput = { config: { ...config, ignore }, caseFile, assessment, audit: auditRecordsOf(deps.audit, config), phase3: deps.phase3 ?? null };
  const json = buildReportJson(input);
  const md = markdownFromModel(json);
  await atomicWrite(config.paths.reportMd, md);
  await writeJsonAtomic(config.paths.reportJson, json);
  deps.audit.log({ event: 'report.written', md: relativePosix(config.projectRoot, config.paths.reportMd), json: relativePosix(config.projectRoot, config.paths.reportJson) });
  return { md: config.paths.reportMd, json: config.paths.reportJson };
}
