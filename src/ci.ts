// exit codes and --json summary
import { findIgnore, riskAtOrAbove, riskRank } from './config.ts';
import type {
  ActionKind,
  ApprovalChoice,
  ApprovalMode,
  ApprovalRecord,
  Assessment,
  CaseFile,
  ExitCode,
  FailOn,
  Identity,
  IgnoreEntry,
  Phase3Result,
  ProviderName,
  Reachable,
  RecommendationAction,
  RiskLevel,
  SeverityLabel,
  Verdict,
  VulnCase,
  VulnSourceInfo,
} from './types.ts';
import { EXIT } from './util/errors.ts';
import { VERSION } from './version.ts';

export const JSON_SUMMARY_VERSION = 1;

export type VerdictStatus = 'open' | 'accepted' | 'fixed';

export interface JsonVerdict {
  vulnId: string;
  aliases: string[];
  // https://osv.dev/vulnerability/<id>
  url: string;
  package: string;
  installedVersion: string;
  summary: string;
  severity: SeverityLabel;
  cvssScore: number | null;
  risk: RiskLevel;
  reachable: Reachable;
  confidence: number;
  reasoning: string;
  evidence: string[];
  recommendation: { action: RecommendationAction; targetVersion: string | null; majorBump: boolean; notes: string | null };
  isDirect: boolean | null;
  isDevOnly: boolean | null;
  malware: boolean;
  status: VerdictStatus;
  // open and >= --fail-on, exits 1
  failing: boolean;
  acceptedRisk: { reason: string; by: string; createdAt: string; until: string | null; expired: boolean } | null;
  cached: boolean;
  forced: boolean;
  adjusted: boolean;
  originalRisk: RiskLevel | null;
  provider: ProviderName;
  model: string;
  steps: number;
  durationMs: number;
}

export interface JsonCounts {
  dependencies: number;
  direct: number;
  dev: number;
  vulnerablePackages: number;
  vulnerabilities: number;
  bySeverity: Record<SeverityLabel, number>;
  investigated: number;
  notInvestigated: number;
  byRisk: Record<RiskLevel, number>;
  failing: number;
  accepted: number;
  fixed: number;
  cached: number;
  forced: number;
  adjusted: number;
}

export interface JsonAction {
  id: string;
  kind: ActionKind;
  package: string;
  fromVersion: string;
  toVersion: string;
  vulnIds: string[];
  worstRisk: RiskLevel;
  majorBump: boolean;
  direct: boolean;
  importedInSource: boolean;
  requiresMigration: boolean;
  codeChanges: number;
  notes: string[];
}

export interface JsonApproval {
  actionId: string;
  package: string;
  decision: ApprovalChoice;
  mode: ApprovalMode;
  scope: ApprovalRecord['scope'];
  by: Identity;
  at: string;
  reason: string | null;
  until: string | null;
  files: { file: string; approved: boolean }[];
}

export interface JsonResult {
  actionId: string;
  ok: boolean;
  error: string | null;
  before: string;
  after: string | null;
  command: string[] | null;
  rolledBack: boolean;
  filesChanged: { path: string; beforeHash: string; afterHash: string }[];
  lockfile: { added: number; removed: number; changed: number; unexpected: string[] } | null;
  verify: { vulnId: string; package: string; cleared: boolean; versions: string[] }[];
}

export interface JsonSummary {
  version: number;
  tool: { name: 'patch-pilot'; version: string };
  generatedAt: string;
  project: { name: string; root: string; lockfile: string; lockfileVersion: number };
  vulnSource: VulnSourceInfo;
  investigation: { provider: ProviderName; model: string; promptVersion: string; complete: boolean; createdAt: string; updatedAt: string } | null;
  failOn: FailOn;
  counts: JsonCounts;
  verdicts: JsonVerdict[];
  actions: JsonAction[];
  approvals: JsonApproval[];
  results: JsonResult[];
  reports: { md: string; json: string } | null;
  exitCode: ExitCode;
}

export interface ExitCodeOptions {
  // config.ignore
  ignore?: readonly IgnoreEntry[];
  // cve aliases for ignore matching
  caseFile?: CaseFile | null;
  // fixed this run, not counted
  phase3?: Phase3Result | null;
  now?: Date;
}

export interface JsonSummaryOptions {
  // --fail-on, default high
  failOn?: FailOn;
  ignore?: readonly IgnoreEntry[];
  // derived if omitted
  exitCode?: ExitCode;
  now?: Date;
}

const FAIL_ON_LEVEL: Record<Exclude<FailOn, 'never'>, RiskLevel> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  noise: 'Noise',
};

const SEVERITY_RANK: Record<SeverityLabel, number> = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, UNKNOWN: 0 };

// most serious last
const EXIT_PRECEDENCE: readonly number[] = [EXIT.OK, EXIT.FINDINGS, EXIT.PATCH_FAILED, EXIT.USAGE, EXIT.ENVIRONMENT, EXIT.INTERRUPTED, EXIT.INTERNAL];

// "High" or a --fail-on value like "never"
export function riskAtLeast(risk: RiskLevel, threshold: RiskLevel | FailOn): boolean {
  if ((['Critical', 'High', 'Medium', 'Low', 'Noise'] as const).includes(threshold as RiskLevel)) {
    return riskRank(risk) >= riskRank(threshold as RiskLevel);
  }
  const failOn = String(threshold).toLowerCase() as FailOn;
  if (failOn === 'never') return false;
  const level = FAIL_ON_LEVEL[failOn];
  if (!level) throw new TypeError(`Unknown --fail-on level: ${String(threshold)}`);
  return riskAtOrAbove(risk, failOn);
}

// skips null and undefined
export function mergeExitCodes(...codes: (ExitCode | null | undefined)[]): ExitCode {
  let worst: ExitCode = EXIT.OK;
  for (const code of codes) {
    if (code === null || code === undefined) continue;
    const rank = EXIT_PRECEDENCE.indexOf(code);
    if (rank === -1 || rank > EXIT_PRECEDENCE.indexOf(worst)) worst = rank === -1 ? EXIT.INTERNAL : code;
  }
  return worst;
}

function verdictKey(vulnId: string, pkg: string): string {
  return `${vulnId}\u0000${pkg}`;
}

// (vulnId, package) pairs, applied fixes only
function clearedPairs(phase3: Phase3Result | null | undefined): Set<string> {
  const out = new Set<string>();
  for (const result of phase3?.results ?? []) {
    if (!result.ok || result.rolledBack) continue;
    for (const v of result.verify ?? []) if (v.cleared) out.add(verdictKey(v.vulnId, v.package));
  }
  return out;
}

function aliasLookup(caseFile: CaseFile | null | undefined): (vulnId: string) => string[] {
  const map = new Map<string, string[]>();
  for (const v of caseFile?.vulnerabilities ?? []) map.set(v.id, [...(v.aliases ?? []), ...(v.mergedIds ?? [])]);
  return (vulnId) => map.get(vulnId) ?? [];
}

interface Classified {
  status: VerdictStatus;
  failing: boolean;
  accepted: { entry: IgnoreEntry; expired: boolean } | null;
}

function classify(
  verdict: Pick<Verdict, 'vulnId' | 'package' | 'risk'>,
  failOn: FailOn,
  ignore: readonly IgnoreEntry[],
  aliasesOf: (vulnId: string) => string[],
  cleared: Set<string>,
  now: Date,
): Classified {
  const accepted = findIgnore(ignore, verdict.vulnId, verdict.package, aliasesOf(verdict.vulnId), now);
  let status: VerdictStatus = 'open';
  if (cleared.has(verdictKey(verdict.vulnId, verdict.package))) status = 'fixed';
  else if (accepted && !accepted.expired) status = 'accepted';
  return { status, failing: status === 'open' && riskAtLeast(verdict.risk, failOn), accepted };
}

// open = not accepted, not fixed
export function exitCodeFor(assessment: Pick<Assessment, 'verdicts'> | null | undefined, failOn: FailOn, options: ExitCodeOptions = {}): 0 | 1 {
  if (failOn === 'never' || !assessment) return EXIT.OK;
  const aliasesOf = aliasLookup(options.caseFile);
  const cleared = clearedPairs(options.phase3);
  const now = options.now ?? new Date();
  for (const verdict of assessment.verdicts) {
    if (classify(verdict, failOn, options.ignore ?? [], aliasesOf, cleared, now).failing) return EXIT.FINDINGS;
  }
  return EXIT.OK;
}

function severityOf(vuln: VulnCase | undefined): SeverityLabel {
  return vuln?.severity?.ghsa ?? 'UNKNOWN';
}

function sortForOutput(verdicts: readonly Verdict[], vulnOf: (v: Verdict) => VulnCase | undefined): Verdict[] {
  return [...verdicts].sort(
    (a, b) =>
      riskRank(b.risk) - riskRank(a.risk) ||
      SEVERITY_RANK[severityOf(vulnOf(b))] - SEVERITY_RANK[severityOf(vulnOf(a))] ||
      a.package.localeCompare(b.package) ||
      a.vulnId.localeCompare(b.vulnId),
  );
}

function zeroRisks(): Record<RiskLevel, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Noise: 0 };
}

function zeroSeverities(): Record<SeverityLabel, number> {
  return { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
}

// --json output
export function summarizeForJson(
  caseFile: CaseFile,
  assessment: Assessment | null,
  phase3Result?: Phase3Result | null,
  options: JsonSummaryOptions = {},
): JsonSummary {
  const failOn = options.failOn ?? 'high';
  const ignore = options.ignore ?? [];
  const now = options.now ?? new Date();
  const vulnByKey = new Map<string, VulnCase>();
  for (const v of caseFile.vulnerabilities) vulnByKey.set(`${v.id}\u0000${v.package}\u0000${v.installedVersion}`, v);
  const vulnOf = (v: Verdict): VulnCase | undefined =>
    vulnByKey.get(`${v.vulnId}\u0000${v.package}\u0000${v.installedVersion}`) ?? caseFile.vulnerabilities.find((c) => c.id === v.vulnId && c.package === v.package);
  const aliasesOf = aliasLookup(caseFile);
  const cleared = clearedPairs(phase3Result);
  const verdicts = sortForOutput(assessment?.verdicts ?? [], vulnOf);

  const counts: JsonCounts = {
    dependencies: caseFile.counts?.dependencies ?? 0,
    direct: caseFile.counts?.direct ?? 0,
    dev: caseFile.counts?.dev ?? 0,
    vulnerablePackages: caseFile.counts?.vulnerablePackages ?? caseFile.packages.length,
    vulnerabilities: caseFile.counts?.vulnerabilities ?? caseFile.vulnerabilities.length,
    bySeverity: { ...zeroSeverities(), ...(caseFile.counts?.bySeverity ?? {}) },
    investigated: verdicts.length,
    notInvestigated: 0,
    byRisk: zeroRisks(),
    failing: 0,
    accepted: 0,
    fixed: 0,
    cached: 0,
    forced: 0,
    adjusted: 0,
  };
  const investigated = new Set(verdicts.map((v) => `${v.vulnId}\u0000${v.package}\u0000${v.installedVersion}`));
  counts.notInvestigated = caseFile.vulnerabilities.filter((v) => !investigated.has(`${v.id}\u0000${v.package}\u0000${v.installedVersion}`)).length;

  const jsonVerdicts = verdicts.map((v): JsonVerdict => {
    const vuln = vulnOf(v);
    const c = classify(v, failOn, ignore, aliasesOf, cleared, now);
    const inv = v.investigation;
    counts.byRisk[v.risk] += 1;
    if (c.failing) counts.failing += 1;
    if (c.status === 'accepted') counts.accepted += 1;
    if (c.status === 'fixed') counts.fixed += 1;
    if (inv?.cached) counts.cached += 1;
    if (inv?.forced) counts.forced += 1;
    if (inv?.adjusted) counts.adjusted += 1;
    return {
      vulnId: v.vulnId,
      aliases: vuln?.aliases ?? [],
      url: `https://osv.dev/vulnerability/${encodeURIComponent(v.vulnId)}`,
      package: v.package,
      installedVersion: v.installedVersion,
      summary: vuln?.summary ?? '',
      severity: severityOf(vuln),
      cvssScore: typeof vuln?.severity?.cvssScore === 'number' ? vuln.severity.cvssScore : null,
      risk: v.risk,
      reachable: v.reachable,
      confidence: v.confidence,
      reasoning: v.reasoning,
      evidence: [...(v.evidence ?? [])],
      recommendation: {
        action: v.recommendation.action,
        targetVersion: v.recommendation.targetVersion ?? null,
        majorBump: Boolean(v.recommendation.majorBump),
        notes: v.recommendation.notes ?? null,
      },
      isDirect: vuln ? vuln.isDirect : null,
      isDevOnly: vuln ? vuln.isDevOnly : null,
      malware: Boolean(vuln?.malware),
      status: c.status,
      failing: c.failing,
      acceptedRisk: c.accepted
        ? {
            reason: c.accepted.entry.reason,
            by: c.accepted.entry.by,
            createdAt: c.accepted.entry.createdAt,
            until: c.accepted.entry.until ?? null,
            expired: c.accepted.expired,
          }
        : null,
      cached: Boolean(inv?.cached),
      forced: Boolean(inv?.forced),
      adjusted: Boolean(inv?.adjusted),
      originalRisk: inv?.originalRisk ?? null,
      provider: inv?.provider ?? assessment?.provider ?? 'ollama',
      model: inv?.model ?? assessment?.model ?? '',
      steps: inv?.steps ?? 0,
      durationMs: inv?.durationMs ?? 0,
    };
  });

  const actions = (phase3Result?.actions ?? []).map(
    (a): JsonAction => ({
      id: a.id,
      kind: a.kind,
      package: a.package,
      fromVersion: a.fromVersion,
      toVersion: a.toVersion,
      vulnIds: [...a.vulnIds],
      worstRisk: a.worstRisk,
      majorBump: a.majorBump,
      direct: a.direct !== null,
      importedInSource: a.importedInSource,
      requiresMigration: a.requiresMigration,
      codeChanges: a.codemod?.patches.length ?? 0,
      notes: [...(a.notes ?? [])],
    }),
  );
  const approvals = (phase3Result?.approvals ?? []).map(
    (r): JsonApproval => ({
      actionId: r.actionId,
      package: r.package,
      decision: r.decision,
      mode: r.mode,
      scope: r.scope,
      by: { osUser: r.by.osUser, gitName: r.by.gitName, gitEmail: r.by.gitEmail },
      at: r.at,
      reason: r.reason ?? null,
      until: r.until ?? null,
      files: (r.files ?? []).map((f) => ({ file: f.file, approved: f.approved })),
    }),
  );
  const results = (phase3Result?.results ?? []).map(
    (r): JsonResult => ({
      actionId: r.actionId,
      ok: r.ok,
      error: r.error ?? null,
      before: r.before,
      after: r.after,
      command: r.command ? [...r.command] : null,
      rolledBack: r.rolledBack,
      filesChanged: r.filesChanged.map((f) => ({ path: f.path, beforeHash: f.beforeHash, afterHash: f.afterHash })),
      lockfile: r.lockfileDiff
        ? {
            added: r.lockfileDiff.changes.filter((ch) => ch.change === 'added').length,
            removed: r.lockfileDiff.changes.filter((ch) => ch.change === 'removed').length,
            changed: r.lockfileDiff.changes.filter((ch) => ch.change === 'changed').length,
            unexpected: r.lockfileDiff.unexpected.map((ch) => ch.key),
          }
        : null,
      verify: r.verify.map((v) => ({ vulnId: v.vulnId, package: v.package, cleared: v.cleared, versions: v.nodes.map((n) => n.version) })),
    }),
  );

  const findings = exitCodeFor(assessment, failOn, { ignore, caseFile, phase3: phase3Result, now });
  const exitCode = options.exitCode ?? mergeExitCodes(findings, phase3Result?.exitCode === EXIT.FINDINGS ? null : phase3Result?.exitCode);

  return {
    version: JSON_SUMMARY_VERSION,
    tool: { name: 'patch-pilot', version: VERSION },
    generatedAt: now.toISOString(),
    project: {
      name: caseFile.project.name,
      root: caseFile.project.root,
      lockfile: caseFile.project.lockfile,
      lockfileVersion: caseFile.project.lockfileVersion,
    },
    vulnSource: { ...caseFile.vulnSource },
    investigation: assessment
      ? {
          provider: assessment.provider,
          model: assessment.model,
          promptVersion: assessment.promptVersion,
          complete: assessment.complete,
          createdAt: assessment.createdAt,
          updatedAt: assessment.updatedAt,
        }
      : null,
    failOn,
    counts,
    verdicts: jsonVerdicts,
    actions,
    approvals,
    results,
    reports: phase3Result?.reports ?? null,
    exitCode,
  };
}

function isEpipe(err: unknown): boolean {
  return (err as NodeJS.ErrnoException | null)?.code === 'EPIPE';
}

// closed pipe (--json | head) is fine
export function printJson(stream: NodeJS.WritableStream, value: unknown): Promise<void> {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  return new Promise((resolve, reject) => {
    let settled = false;
    let reported: unknown = null;
    const settle = (err: unknown): void => {
      if (settled) return;
      settled = true;
      if (err && !isEpipe(err)) reject(err);
      else resolve();
    };
    const onError = (err: unknown): void => {
      if (err !== reported) settle(err);
    };
    stream.once('error', onError);
    try {
      stream.write(text, (err?: Error | null) => {
        if (err) {
          // keep listener, 'error' fires next
          reported = err;
          settle(err);
        } else {
          stream.removeListener('error', onError);
          settle(null);
        }
      });
    } catch (err) {
      stream.removeListener('error', onError);
      settle(err);
    }
  });
}
