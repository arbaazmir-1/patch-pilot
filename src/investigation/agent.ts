// recon, per-cve verdicts, evidence gate, rails
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { riskRank } from '../config.ts';
import { LlmError } from '../llm/errors.ts';
import type { ChatProvider } from '../llm/provider.ts';
import { extractJsonObject, parseTextToolCalls, stripJsonBlocks, unwrapRawArguments } from '../llm/textToolCalls.ts';
import { classifyFile, findImportsInSource, walkProject } from '../evidence/codebase.ts';
import { loadDependencyGraph } from '../evidence/lockfile.ts';
import type {
  Assessment,
  AuditSink,
  CaseFile,
  ChatMessage,
  ChatPurpose,
  ChatResponse,
  Config,
  DependencyGraph,
  DependentUsage,
  Dossier,
  DossierModelOutput,
  GhsaSeverity,
  IndirectPath,
  InvestigationMeta,
  InvestigationStage,
  JsonSchema,
  KeyValueCache,
  PackageCase,
  ProviderName,
  Reachable,
  Recommendation,
  RecommendationAction,
  RiskLevel,
  ToolCall,
  ToolCallRecord,
  ToolContext,
  ToolExecution,
  ToolSchema,
  ToolStage,
  TraceLabel,
  UsageEvidence,
  Verdict,
  VerdictModelOutput,
  VulnCase,
} from '../types.ts';
import { formatArgs, type Card, type Spinner, type Ui } from '../ui.ts';
import { errorMessage, isNotImplemented } from '../util/errors.ts';
import { compareVersions, satisfiesRange } from '../util/semver.ts';
import { createAssessment, caseFileHash, loadAssessment, saveAssessment, upsertDossier, upsertVerdict } from './assessment.ts';
import {
  budgetSpentNote,
  clip,
  coachingPrompt,
  continuePrompt,
  displayVulnId,
  DOSSIER_SCHEMA,
  dossierTurnPrompt,
  packageFixText,
  PROMPT_VERSION,
  reconPrompt,
  repeatNote,
  repeatStopNote,
  symbolName,
  systemPrompt,
  usageOf,
  VERDICT_SCHEMA,
  verdictPrompt,
  verdictTurnPrompt,
} from './prompts.ts';
import type { GetUsageData, UsageCallSite } from './tools/getUsage.ts';
import { createToolRegistry, toolCallKey, type ToolRegistry } from './tools/index.ts';
import { loadVerdictCache, lookupVerdict, saveVerdictCache, storeVerdict, usageEvidenceHash, verdictCacheKey, type VerdictCacheFile } from './verdictCache.ts';

export interface Phase2Deps {
  provider: ChatProvider;
  ui: Ui;
  audit: AuditSink;
  // default createToolRegistry()
  registry?: ToolRegistry;
  // for check_deps, else from the case file
  graph?: DependencyGraph | null;
  cache?: KeyValueCache | null;
  signal?: AbortSignal;
  // defaults to a minimal one
  caseFile?: CaseFile | null;
  // for the ceiling Low rail, tests fake it
  scanImports?: (names: readonly string[]) => Promise<Map<string, boolean> | null>;
  // injectable for tests
  now?: () => number;
}

// gate needs this before a verdict
export interface EvidenceRequirement {
  tool: 'get_usage' | 'read_file';
  args: Record<string, unknown>;
  // for trace and audit
  reason: string;
}

export interface RailOutcome {
  // post-rails risk
  risk: RiskLevel;
  floor: RiskLevel | null;
  ceiling: RiskLevel | null;
  // e.g. "dev-only dependency (ceiling Medium)"
  violation: string | null;
  // only when evidence contradicts reachability
  reachable?: Reachable;
  reachableReason?: string;
}

// extra facts for the rails
export interface RailOptions {
  // null = unknown
  dependentsImportedInSource?: boolean | null;
  // all blamed exports checked, none called, caps Medium
  blamedApiNotCalled?: boolean;
  // blamed api reached via own functions
  indirectCalled?: boolean;
  // dependents imported in source
  importedDependents?: readonly string[];
}

export interface ForcedVerdictOptions extends RailOptions {
  // derived from evidence by default
  usedExportedSymbol?: boolean;
  graph?: DependencyGraph | null;
  steps?: number;
  durationMs?: number;
  breakingChanges?: string[];
}

// gate cap per cve
export const MAX_GATE_SYMBOLS = 3;
// in a row, then stop
const MAX_CONSECUTIVE_FAILURES = 6;
// in a row, each can cost minutes
const MAX_CONSECUTIVE_TIMEOUTS = 2;
const FATAL_KINDS = new Set(['unreachable', 'model-missing', 'no-tools', 'out-of-memory', 'aborted']);
// stops a model stuck repeating
export const LOOP_MAX_TOKENS = 1536;
export const SCHEMA_MAX_TOKENS = 1024;
const FORCED_CONFIDENCE = 0.3;

const GHSA_RANK: Record<GhsaSeverity, number> = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1 };

function severityRank(vuln: VulnCase): number {
  if (vuln.malware) return 5;
  return vuln.severity?.ghsa ? GHSA_RANK[vuln.severity.ghsa] : 0;
}

function compareVulns(a: VulnCase, b: VulnCase): number {
  return severityRank(b) - severityRank(a) || (b.severity?.cvssScore ?? -1) - (a.severity?.cvssScore ?? -1) || a.id.localeCompare(b.id);
}

function packageRank(pkg: PackageCase, vulns: readonly VulnCase[]): number {
  const fromPkg = pkg.worstSeverity && pkg.worstSeverity !== 'UNKNOWN' ? GHSA_RANK[pkg.worstSeverity] : 0;
  return Math.max(fromPkg, ...vulns.map(severityRank));
}

function matchesVuln(token: string, vuln: VulnCase): boolean {
  const t = token.toLowerCase();
  return [vuln.id, ...(vuln.aliases ?? []), ...(vuln.mergedIds ?? [])].some((id) => id.toLowerCase() === t);
}

function matchesPackage(token: string, pkg: PackageCase): boolean {
  const t = token.toLowerCase();
  return t === pkg.name.toLowerCase() || t === `${pkg.name}@${pkg.version}`.toLowerCase();
}

// worst first, --only --limit --max-cves
export function selectPackages(caseFile: CaseFile, config: Config): { pkg: PackageCase; vulns: VulnCase[] }[] {
  const byId = new Map(caseFile.vulnerabilities.map((v) => [v.id, v]));
  let entries = caseFile.packages
    .map((pkg) => {
      let vulns = (pkg.vulnIds ?? []).map((id) => byId.get(id)).filter((v): v is VulnCase => v !== undefined);
      if (vulns.length === 0) vulns = caseFile.vulnerabilities.filter((v) => v.package === pkg.name && v.installedVersion === pkg.version);
      return { pkg, vulns: [...new Map(vulns.map((v) => [v.id, v])).values()].sort(compareVulns) };
    })
    .filter((e) => e.vulns.length > 0);
  const only = (config.only ?? []).map((o) => o.trim()).filter(Boolean);
  if (only.length > 0) {
    entries = entries
      .map((e) => (only.some((o) => matchesPackage(o, e.pkg)) ? e : { pkg: e.pkg, vulns: e.vulns.filter((v) => only.some((o) => matchesVuln(o, v))) }))
      .filter((e) => e.vulns.length > 0);
  }
  entries.sort((a, b) => {
    const worst = packageRank(b.pkg, b.vulns) - packageRank(a.pkg, a.vulns);
    if (worst !== 0) return worst;
    const cvss = Math.max(-1, ...b.vulns.map((v) => v.severity?.cvssScore ?? -1)) - Math.max(-1, ...a.vulns.map((v) => v.severity?.cvssScore ?? -1));
    if (cvss !== 0) return cvss;
    return b.vulns.length - a.vulns.length || Number(b.pkg.isDirect) - Number(a.pkg.isDirect) || a.pkg.name.localeCompare(b.pkg.name) || compareVersions(a.pkg.version, b.pkg.version);
  });
  if (config.limit !== null && config.limit !== undefined && config.limit > 0) entries = entries.slice(0, config.limit);
  if (config.maxCves !== null && config.maxCves !== undefined && config.maxCves > 0) {
    let left = config.maxCves;
    const capped: { pkg: PackageCase; vulns: VulnCase[] }[] = [];
    for (const e of entries) {
      if (left <= 0) break;
      const vulns = e.vulns.slice(0, left);
      left -= vulns.length;
      capped.push({ pkg: e.pkg, vulns });
    }
    entries = capped;
  }
  return entries;
}

function exportedSymbols(vuln: VulnCase): { name: string; defaultCallable: boolean }[] {
  const seen = new Set<string>();
  const out: { name: string; defaultCallable: boolean }[] = [];
  for (const s of vuln.blamedSymbols ?? []) {
    if (s.kind !== 'exported') continue;
    const name = symbolName(s.name);
    const defaultCallable = s.via === 'default-callable';
    const key = defaultCallable ? '(default)' : name.toLowerCase();
    if (name === '' || seen.has(key)) continue;
    seen.add(key);
    out.push({ name, defaultCallable });
  }
  return out;
}

function importSiteFor(pkg: PackageCase): { path: string; line: number } | null {
  const files = usageOf(pkg).files;
  const site = files.find((f) => f.scope === 'source') ?? files[0];
  return site ? { path: site.path, line: site.line } : null;
}

// computed member, dynamic require, unparsed file
function hasDynamicAccess(usage: UsageEvidence): boolean {
  return (usage.dynamicAccess ?? []).length > 0;
}

// plus whether the default callable is blamed
function blamedNames(vuln: VulnCase): { names: Set<string>; defaultCallable: boolean; any: boolean } {
  const exported = exportedSymbols(vuln);
  return { names: new Set(exported.filter((s) => !s.defaultCallable).map((s) => s.name.toLowerCase())), defaultCallable: exported.some((s) => s.defaultCallable), any: exported.length > 0 };
}

// non-test indirect paths only
function blamedIndirectPaths(paths: readonly IndirectPath[] | undefined, vuln: VulnCase): IndirectPath[] {
  const blamed = blamedNames(vuln);
  if (!blamed.any) return [];
  return (paths ?? []).filter((p) => classifyFile(p.path) !== 'test' && (p.member === null ? blamed.defaultCallable : blamed.names.has(p.member.toLowerCase())));
}

// via dependents in node_modules
function blamedDependentUsage(usage: UsageEvidence, vuln: VulnCase): DependentUsage[] {
  const uses = usage.dependentUsage ?? [];
  const blamed = blamedNames(vuln);
  if (!blamed.any) return [...uses];
  return uses.filter((u) => u.member === null || blamed.names.has(u.member.toLowerCase()));
}

// case file or get_usage
function indirectlyCalled(pkg: PackageCase, vuln: VulnCase, executions: readonly ToolExecution[] = []): boolean {
  if (blamedIndirectPaths(usageOf(pkg).indirectPaths, vuln).length > 0) return true;
  return executions.some((exec) => {
    if (exec.tool !== 'get_usage' || !exec.ok) return false;
    const data = exec.result?.data as Partial<GetUsageData> | undefined;
    return String(data?.package ?? '').toLowerCase() === pkg.name.toLowerCase() && blamedIndirectPaths(data?.indirectPaths, vuln).length > 0;
  });
}

export function evidenceRequirements(pkg: PackageCase, vuln: VulnCase): EvidenceRequirement[] {
  const usage = usageOf(pkg);
  const label = displayVulnId(vuln);
  if (usage.scopes.source <= 0) {
    // not imported, a dependent calls it
    const first = usage.imported ? undefined : blamedDependentUsage(usage, vuln)[0];
    if (!first) return [];
    return [
      {
        tool: 'get_usage',
        args: { package: pkg.name },
        reason: `${label}: ${first.dependent} calls ${pkg.name} in its own code (${first.path}:${first.line}); check how the project reaches it`,
      },
    ];
  }
  const exported = exportedSymbols(vuln);
  const named = exported.filter((s) => !s.defaultCallable);
  const out: EvidenceRequirement[] = [];
  if (named.length > 0) {
    const ranked = [...named].sort((a, b) => Number((usage.membersUsed[b.name] ?? 0) > 0) - Number((usage.membersUsed[a.name] ?? 0) > 0));
    for (const s of ranked.slice(0, MAX_GATE_SYMBOLS)) {
      out.push({
        tool: 'get_usage',
        args: { package: pkg.name, symbol: s.name },
        reason: `${label} blames ${s.name}(), which the project could call; check whether it does`,
      });
    }
  }
  if (exported.some((s) => s.defaultCallable)) {
    out.push({ tool: 'get_usage', args: { package: pkg.name }, reason: `${label} blames the ${pkg.name} entry point itself; find where it is called` });
  }
  if (out.length > 0) return out;
  const internal = (vuln.blamedSymbols ?? []).filter((s) => s.kind === 'internal').map((s) => symbolName(s.name));
  const what = internal.length > 0 ? `internal code (${internal.slice(0, 3).join(', ')})` : 'no specific function';
  out.push({
    tool: 'get_usage',
    args: { package: pkg.name },
    reason: `${label} blames ${what}, so the question is whether ${pkg.name} itself is called with untrusted input; find its call sites`,
  });
  const site = importSiteFor(pkg);
  if (site) {
    out.push({
      tool: 'read_file',
      args: { path: site.path, startLine: Math.max(1, site.line - 5), endLine: site.line + 34 },
      reason: `read a ${pkg.name} call site to see where its input comes from`,
    });
  }
  return out;
}

function clampRisk(risk: RiskLevel, floor: RiskLevel | null, ceiling: RiskLevel | null): RiskLevel {
  let out = risk;
  if (floor && riskRank(out) < riskRank(floor)) out = floor;
  if (ceiling && riskRank(out) > riskRank(ceiling)) out = ceiling;
  return out;
}

function lower(a: RiskLevel | null, b: RiskLevel): RiskLevel {
  return a === null || riskRank(b) < riskRank(a) ? b : a;
}

// clamp verdict to rails
export function applyRails(output: VerdictModelOutput, pkg: PackageCase, vuln: VulnCase, usedExportedSymbol: boolean, options: RailOptions = {}): RailOutcome {
  const usage = usageOf(pkg);
  const importedInSource = usage.scopes.source > 0;
  const entryPointCalled = importedInSource && usage.bindingCalls > 0;
  // indirect, unresolved, via a dependent
  const indirect = importedInSource && (options.indirectCalled === true || blamedIndirectPaths(usage.indirectPaths, vuln).length > 0);
  const dynamic = hasDynamicAccess(usage);
  const importedDependents = new Set(options.importedDependents ?? []);
  const viaDependent = importedInSource ? undefined : blamedDependentUsage(usage, vuln).find((u) => importedDependents.has(u.dependent));
  const rules: { kind: 'floor' | 'ceiling'; level: RiskLevel; text: string }[] = [];
  if (importedInSource && usedExportedSymbol) rules.push({ kind: 'floor', level: 'Medium', text: 'imported in source and an exported blamed API is called (floor Medium)' });
  else if (entryPointCalled) {
    rules.push({ kind: 'floor', level: 'Medium', text: "imported in source and the package's default callable, its main entry point, is called (floor Medium)" });
  } else if (indirect) {
    rules.push({ kind: 'floor', level: 'Medium', text: "imported in source and an exported blamed API is called indirectly, through the project's own functions (floor Medium)" });
  } else if (viaDependent) {
    rules.push({ kind: 'floor', level: 'Medium', text: `${viaDependent.dependent} is imported in source and calls the blamed API in its own code (floor Medium)` });
  }
  const dependentsImported = options.dependentsImportedInSource ?? ((pkg.dependents ?? []).length === 0 ? false : null);
  if (!importedInSource && !usage.truncated && dependentsImported === false && !dynamic) {
    rules.push({ kind: 'ceiling', level: 'Low', text: 'neither the package nor any dependent of it is imported in source (ceiling Low)' });
  }
  if (pkg.isDevOnly || vuln.isDevOnly) rules.push({ kind: 'ceiling', level: 'Medium', text: 'dev-only dependency (ceiling Medium)' });
  if (importedInSource && options.blamedApiNotCalled && !usedExportedSymbol && !entryPointCalled && !indirect && !dynamic) {
    rules.push({ kind: 'ceiling', level: 'Medium', text: 'the blamed functions are not called anywhere in the project (ceiling Medium)' });
  }
  const floor = rules.filter((r) => r.kind === 'floor').reduce<RiskLevel | null>((acc, r) => (acc === null || riskRank(r.level) > riskRank(acc) ? r.level : acc), null);
  const ceiling = rules.filter((r) => r.kind === 'ceiling').reduce<RiskLevel | null>((acc, r) => lower(acc, r.level), null);
  const risk = clampRisk(output.risk, floor, ceiling);
  let violation: string | null = null;
  if (risk !== output.risk) {
    const raised = riskRank(risk) > riskRank(output.risk);
    const rule = rules.find((r) => (raised ? r.kind === 'floor' && r.level === floor : r.kind === 'ceiling' && r.level === ceiling));
    violation = rule?.text ?? (raised ? `floor ${floor}` : `ceiling ${ceiling}`);
  }
  const outcome: RailOutcome = { risk, floor, ceiling, violation };
  if (output.reachable === 'no') {
    if ((indirect && !usedExportedSymbol) || viaDependent) {
      outcome.reachable = 'likely';
      outcome.reachableReason = indirect ? "the blamed API is called through the project's own functions" : `${viaDependent?.dependent ?? 'a dependent'} calls it and is imported in source`;
    } else if (dynamic) {
      outcome.reachable = 'unknown';
      outcome.reachableReason = 'an access to the package cannot be resolved statically';
    }
  }
  return outcome;
}

// checkable fact behind a rail
function railFact(outcome: RailOutcome, pkg: PackageCase): string {
  const v = outcome.violation ?? '';
  if (v.startsWith('dev-only')) return `${pkg.name} is a dev-only dependency (it is not shipped to production)`;
  if (v.startsWith('neither')) return `neither ${pkg.name} nor any package that depends on it is imported in the project's source code`;
  if (v.startsWith("imported in source and the package's default callable")) {
    return `${pkg.name} is imported in source and the package itself is called there as its default callable, the package's main entry point`;
  }
  if (v.includes('called indirectly')) {
    return `${pkg.name} is imported in source and a function the advisory blames is called through the project's own functions (get_usage lists the indirect call sites)`;
  }
  if (v.includes('calls the blamed API in its own code')) return `${v.split(' is imported')[0]} is imported in the project's source and calls the function ${pkg.name}'s advisory blames`;
  if (v.startsWith('imported in source')) return `${pkg.name} is imported in source and a function the advisory blames is called there`;
  if (v.startsWith('the blamed functions')) {
    return 'get_usage found no call to the functions the advisory blames (and no dynamic member access) anywhere in the project';
  }
  return v || 'the rails';
}

// for the re-ask
function contradictionText(output: VerdictModelOutput, outcome: RailOutcome, pkg: PackageCase): string {
  const raised = riskRank(outcome.risk) > riskRank(output.risk);
  const bound = raised ? `at least ${outcome.floor}` : `at most ${outcome.ceiling}`;
  return `you rated the risk ${output.risk}, but ${railFact(outcome, pkg)}, so the risk must be ${bound}.`;
}

// reasoning says "a HIGH risk", verdict differs
function namesOtherRisk(reasoning: string, risk: RiskLevel): boolean {
  for (const m of reasoning.matchAll(/\b(critical|high|medium|moderate|low|noise)(?=[\s-]+risk\b)/gi)) {
    const named = RISK_ALIASES[(m[1] ?? '').toLowerCase()];
    if (named && named !== risk) return true;
  }
  return false;
}

// parent range excludes fix, needs override
function parentRejectsFix(graph: DependencyGraph | null | undefined, pkg: PackageCase, target: string): boolean | null {
  if (!graph) return null;
  let known = false;
  for (const key of pkg.keys ?? []) {
    const node = graph.nodes.get(key);
    for (const parentKey of node?.parents ?? []) {
      if (parentKey === '') continue;
      const range = graph.nodes.get(parentKey)?.requires?.[pkg.name];
      if (!range) continue;
      known = true;
      if (!satisfiesRange(target, range)) return true;
    }
  }
  return known ? false : null;
}

// deterministic, not the model
export function deriveRecommendation(
  pkg: PackageCase,
  vuln: VulnCase,
  modelAction: RecommendationAction,
  options: { graph?: DependencyGraph | null; breakingChanges?: string[]; risk?: RiskLevel } = {},
): Recommendation {
  const fix = vuln.recommendedFix;
  const targetVersion = fix?.version ?? null;
  const majorBump = fix?.majorBump ?? false;
  const risk = options.risk ?? 'High';
  const notes: string[] = [];
  const transitive = (target: string): RecommendationAction => {
    const rejects = parentRejectsFix(options.graph, pkg, target);
    if (rejects === true) return 'override';
    if (rejects === false) return 'update_transitive';
    return modelAction === 'override' || majorBump ? 'override' : 'update_transitive';
  };
  let action: RecommendationAction;
  if (risk === 'Noise') {
    action = 'ignore';
  } else if (!targetVersion) {
    action = 'monitor';
    notes.push('No fixed version is published yet.');
  } else if (!majorBump) {
    action = pkg.isDirect ? 'upgrade' : transitive(targetVersion);
  } else if (risk === 'Critical' || risk === 'High') {
    action = pkg.isDirect ? 'upgrade_major' : transitive(targetVersion);
    notes.push(`Major version bump to ${targetVersion}: breaking changes are expected.`);
  } else {
    action = 'monitor';
    notes.push(`Major upgrade to ${targetVersion} available.`);
  }
  if (fix?.skippedDeprecated?.length) notes.push(`Skips deprecated ${fix.skippedDeprecated.join(', ')}.`);
  const rec: Recommendation = { action, targetVersion, majorBump };
  if (options.breakingChanges && options.breakingChanges.length > 0) rec.breakingChanges = options.breakingChanges.slice(0, 8);
  if (notes.length > 0) rec.notes = notes.join(' ');
  return rec;
}

// card text: "bump to 4.17.21", "upgrade to 4.0.10 (major)", "ignore"
export function recommendationText(rec: Recommendation): string {
  const to = rec.targetVersion;
  switch (rec.action) {
    case 'upgrade':
      return to ? `bump to ${to}` : 'upgrade when a fix is published';
    case 'upgrade_major':
      return to ? `upgrade to ${to} (major)` : 'upgrade (major)';
    case 'update_transitive':
      return to ? `update the transitive dependency to ${to}` : 'update the transitive dependency';
    case 'override':
      return to ? `override to ${to}` : 'override the transitive version';
    case 'remove':
      return 'remove the dependency';
    case 'ignore':
      return 'ignore';
    default:
      return rec.targetVersion ? 'monitor' : 'monitor (no fix yet)';
  }
}

function callsFromSummary(summary: string): number | null {
  const m = /^(\d+) calls? to /.exec(summary);
  return m && m[1] !== undefined ? Number(m[1]) : null;
}

// per phase 1 usage and get_usage
function exportedCalled(pkg: PackageCase, vuln: VulnCase, records: readonly ToolCallRecord[], executions: readonly ToolExecution[] = [], countEntryPoint = true): boolean {
  const usage = usageOf(pkg);
  const exported = exportedSymbols(vuln);
  if (exported.length === 0) return false;
  const names = new Set(exported.filter((s) => !s.defaultCallable).map((s) => s.name.toLowerCase()));
  // marked(md) counts as marked.parse(md)
  if (countEntryPoint && usage.scopes.source > 0 && usage.bindingCalls > 0) return true;
  if (countEntryPoint && executions.some((e) => e.tool === 'get_usage' && e.ok && (e.result?.data as Partial<GetUsageData> | undefined)?.entryPointCalled === true)) return true;
  for (const [member, count] of Object.entries(usage.membersUsed)) if (count > 0 && names.has(member.toLowerCase())) return true;
  for (const exec of executions) {
    if (exec.tool !== 'get_usage' || !exec.ok) continue;
    const data = exec.result?.data as Partial<GetUsageData> | undefined;
    if (data && typeof data.symbol === 'string' && names.has(data.symbol.toLowerCase()) && !data.fallback && (data.symbolCalls ?? 0) > 0) return true;
  }
  for (const r of records) {
    if (r.tool !== 'get_usage' || !r.ok || typeof r.args.symbol !== 'string') continue;
    if (!names.has(symbolName(r.args.symbol).toLowerCase())) continue;
    const n = callsFromSummary(r.summary);
    if (n !== null && n > 0) return true;
  }
  return false;
}

// fallback when the model gives none
export function forcedVerdict(
  pkg: PackageCase,
  vuln: VulnCase,
  calls: readonly ToolCallRecord[],
  meta: { provider: ProviderName; model: string; promptVersion: string },
  options: ForcedVerdictOptions = {},
): Verdict {
  const usage = usageOf(pkg);
  const importedInSource = usage.scopes.source > 0;
  const importedAnywhere = usage.imported || usage.files.length > 0;
  const exported = exportedSymbols(vuln);
  const directlyCalled = options.usedExportedSymbol ?? exportedCalled(pkg, vuln, calls);
  const indirectPaths = blamedIndirectPaths(usage.indirectPaths, vuln);
  const indirect = importedInSource && (options.indirectCalled === true || indirectPaths.length > 0);
  const called = directlyCalled || indirect;
  const dynamic = usage.dynamicAccess ?? [];
  const importedDependents = new Set(options.importedDependents ?? []);
  const viaDependent = importedAnywhere ? undefined : blamedDependentUsage(usage, vuln).find((u) => importedDependents.has(u.dependent));
  const severe = vuln.severity?.ghsa === 'HIGH' || vuln.severity?.ghsa === 'CRITICAL';
  const files = [...new Set(usage.files.map((f) => f.path))].slice(0, 3).join(', ');
  const blamed = exported.map((s) => (s.defaultCallable ? `${pkg.name}()` : `${s.name}()`)).join(', ');
  let risk: RiskLevel;
  let reachable: Reachable;
  const facts: string[] = [];
  if (vuln.malware) {
    risk = 'Critical';
    reachable = 'unknown';
    facts.push(`${vuln.id} is a malware record: the installed version itself is malicious`);
  } else if (importedInSource && called) {
    risk = severe ? 'High' : 'Medium';
    reachable = 'likely';
    const memberCalled = exported.some((s) => !s.defaultCallable && (usage.membersUsed[s.name] ?? 0) > 0);
    const firstIndirect = indirectPaths[0];
    facts.push(
      !directlyCalled && firstIndirect
        ? `${pkg.name} is imported in source (${files}) and the blamed ${blamed || 'API'} is called indirectly (${firstIndirect.path}:${firstIndirect.line} via ${firstIndirect.via.map((v) => `${v}()`).join(' -> ')})`
        : usage.bindingCalls > 0 && !memberCalled
          ? `${pkg.name} is imported in source (${files}) and the package itself is called as its default callable, its main entry point (the advisory blames ${blamed})`
          : `${pkg.name} is imported in source (${files}) and the blamed ${blamed || 'API'} is called`,
    );
  } else if (importedInSource) {
    risk = 'Medium';
    reachable = exported.length > 0 && dynamic.length === 0 ? 'unlikely' : 'unknown';
    facts.push(
      exported.length > 0
        ? `${pkg.name} is imported in source (${files}) but no call to ${blamed} was found`
        : `${pkg.name} is imported in source (${files}); the advisory names no exported function, so reachability is unknown`,
    );
    const first = dynamic[0];
    if (first) facts.push(`${dynamic.length} access${dynamic.length === 1 ? '' : 'es'} to it cannot be resolved statically (${first.path}:${first.line} \`${clip(first.text, 60)}\`)`);
  } else if (importedAnywhere) {
    risk = 'Low';
    reachable = 'unlikely';
    facts.push(`${pkg.name} is imported only outside production source (${files})`);
  } else if (viaDependent) {
    risk = 'Medium';
    reachable = 'likely';
    facts.push(`${pkg.name} is not imported directly, but ${viaDependent.dependent}, which is imported in source, calls it in ${viaDependent.path}:${viaDependent.line}`);
  } else if ((options.dependentsImportedInSource === false || (pkg.dependents ?? []).length === 0) && dynamic.length === 0) {
    risk = 'Noise';
    reachable = 'no';
    facts.push(`${pkg.name} is not imported anywhere in the project`);
  } else {
    risk = 'Low';
    reachable = 'unknown';
    facts.push(`${pkg.name} is not imported directly; it is reached only through ${(pkg.dependents ?? []).map((d) => d.name).slice(0, 3).join(', ')}`);
    const dep = blamedDependentUsage(usage, vuln)[0];
    if (dep) facts.push(`${dep.dependent} calls it in ${dep.path}:${dep.line}`);
    const first = dynamic[0];
    if (first) facts.push(`an access at ${first.path}:${first.line} cannot be resolved statically`);
  }
  if (!vuln.malware) {
    const rails = applyRails({ risk, reachable, confidence: FORCED_CONFIDENCE, reasoning: '', evidence: [], recommendationAction: 'upgrade' }, pkg, vuln, called, options);
    if (rails.risk !== risk) facts.push(rails.violation ?? 'rails applied');
    risk = rails.risk;
  }
  facts.push(`GHSA severity ${vuln.severity?.ghsa ?? 'unknown'}${pkg.isDevOnly ? ', dev-only dependency' : ''}`);
  const evidence = [
    ...usage.files.slice(0, 3).map((f) => `${f.path}:${f.line} ${clip(f.statement, 100)} [${f.scope}]`),
    ...calls.filter((c) => c.ok && c.summary).slice(0, 5).map((c) => `${c.tool}: ${clip(c.summary, 160)}`),
  ];
  const investigation: InvestigationMeta = {
    provider: meta.provider,
    model: meta.model,
    promptVersion: meta.promptVersion,
    steps: options.steps ?? 0,
    toolCalls: [...calls],
    durationMs: options.durationMs ?? 0,
    forced: true,
  };
  return {
    vulnId: vuln.id,
    package: pkg.name,
    installedVersion: vuln.installedVersion || pkg.version,
    risk,
    reachable,
    confidence: FORCED_CONFIDENCE,
    reasoning: `Forced verdict from the evidence (the model gave no valid verdict): ${facts.join('; ')}.`,
    evidence,
    recommendation: deriveRecommendation(pkg, vuln, 'upgrade', {
      risk,
      ...(options.graph !== undefined ? { graph: options.graph } : {}),
      ...(options.breakingChanges ? { breakingChanges: options.breakingChanges } : {}),
    }),
    investigation,
  };
}

const RISK_ALIASES: Record<string, RiskLevel> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  moderate: 'Medium',
  low: 'Low',
  noise: 'Noise',
  none: 'Noise',
  info: 'Noise',
  informational: 'Noise',
};
const REACH_ALIASES: Record<string, Reachable> = {
  yes: 'yes',
  true: 'yes',
  reachable: 'yes',
  likely: 'likely',
  probably: 'likely',
  unlikely: 'unlikely',
  no: 'no',
  false: 'no',
  unreachable: 'no',
  unknown: 'unknown',
};
const ACTION_ALIASES: Record<string, RecommendationAction> = {
  upgrade: 'upgrade',
  update: 'upgrade',
  bump: 'upgrade',
  patch: 'upgrade',
  upgrade_major: 'upgrade_major',
  major: 'upgrade_major',
  update_transitive: 'update_transitive',
  override: 'override',
  remove: 'remove',
  ignore: 'ignore',
  accept: 'ignore',
  accept_risk: 'ignore',
  monitor: 'monitor',
  defer: 'monitor',
  none: 'monitor',
};

function key(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase().replace(/[\s-]+/g, '_') : '';
}

function stringList(value: unknown, max = 10, chars = 300): string[] {
  const items = Array.isArray(value) ? value : typeof value === 'string' && value.trim() !== '' ? [value] : [];
  const out: string[] = [];
  for (const item of items) {
    const text = clip(typeof item === 'string' ? item : JSON.stringify(item), chars);
    if (text !== '' && !out.includes(text)) out.push(text);
    if (out.length >= max) break;
  }
  return out;
}

// schema-checked
export function parseVerdictOutput(content: string): VerdictModelOutput | null {
  const raw = extractJsonObject(content);
  if (!raw) return null;
  const risk = RISK_ALIASES[key(raw.risk)];
  if (!risk) return null;
  let confidence = typeof raw.confidence === 'number' ? raw.confidence : typeof raw.confidence === 'string' ? Number.parseFloat(raw.confidence) : Number.NaN;
  if (!Number.isFinite(confidence)) confidence = 0.5;
  if (confidence > 1 && confidence <= 100) confidence /= 100;
  confidence = Math.min(1, Math.max(0, confidence));
  const reasoning = typeof raw.reasoning === 'string' ? raw.reasoning.trim() : Array.isArray(raw.reasoning) ? raw.reasoning.join(' ').trim() : '';
  return {
    risk,
    reachable: REACH_ALIASES[key(raw.reachable)] ?? 'unknown',
    confidence: Math.round(confidence * 100) / 100,
    reasoning,
    evidence: stringList(raw.evidence),
    recommendationAction: ACTION_ALIASES[key(raw.recommendationAction ?? raw.recommendation_action ?? raw.action)] ?? 'upgrade',
  };
}

export function parseDossierOutput(content: string): DossierModelOutput | null {
  const raw = extractJsonObject(content);
  if (!raw) return null;
  const fields = ['inputSources', 'callSiteNotes', 'dependentsSummary', 'fixCost', 'openQuestions'];
  if (!fields.some((f) => raw[f] !== undefined)) return null;
  const text = (value: unknown): string => (typeof value === 'string' ? clip(value, 400) : Array.isArray(value) ? clip(value.join('; '), 400) : '');
  return {
    inputSources: stringList(raw.inputSources, 6, 240),
    callSiteNotes: stringList(raw.callSiteNotes, 6, 240),
    dependentsSummary: text(raw.dependentsSummary),
    fixCost: text(raw.fixCost),
    openQuestions: stringList(raw.openQuestions, 5, 240),
  };
}

interface Trace {
  agent(text: string, tag?: TraceLabel | string): void;
  // max five lines, all with --verbose
  thought(text: string): void;
  result(text: string): void;
  detail(text: string): void;
  spinner(): Spinner;
}

function cardTrace(card: Card, ui: Ui): Trace {
  return {
    agent: (text, tag) => card.agent(text, tag ? { tag } : {}),
    thought: (text) => card.thought(text),
    result: (text) => card.result(text),
    detail: (text) => {
      if (!ui.verbose) return;
      for (const line of text.split('\n').slice(0, 40)) card.result(`  ${line}`);
    },
    spinner: () => card.spinner('thinking...'),
  };
}

function plainTrace(ui: Ui): Trace {
  return {
    agent: (text, tag) => ui.agentLine(text, tag ? { tag } : {}),
    thought: (text) => ui.agentThought(text),
    result: (text) => ui.resultLine(text),
    detail: (text) => ui.detail(text),
    spinner: () => ui.spinner(`${ui.purple('agent', ui.ce)} ${ui.ce.dim('thinking...')}`),
  };
}

interface Run {
  config: Config;
  deps: Phase2Deps;
  ui: Ui;
  audit: AuditSink;
  provider: ChatProvider;
  registry: ToolRegistry;
  caseFile: CaseFile;
  graph: DependencyGraph | null;
  meta: { provider: ProviderName; model: string; promptVersion: string };
  // ok tool runs across loops, by toolCallKey
  toolCache: Map<string, ToolExecution>;
  // from get_changelog
  changelogs: Map<string, string[]>;
  // null = unknown
  importScan: Map<string, boolean | null>;
  sources: { path: string; scope: string; text: string }[] | null;
  failures: number;
  timeouts: number;
  now: () => number;
}

function minimalCaseFile(config: Config, pkg: PackageCase, vulns: readonly VulnCase[]): CaseFile {
  return {
    version: 1,
    project: { root: config.projectRoot, name: path.basename(config.projectRoot), lockfile: '', lockfileVersion: 0 },
    scannedAt: new Date(0).toISOString(),
    vulnSource: { mode: 'cache', fetchedAt: new Date(0).toISOString(), ageHours: 0 },
    counts: {
      dependencies: 0,
      direct: 0,
      dev: 0,
      vulnerablePackages: 1,
      vulnerabilities: vulns.length,
      bySeverity: { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 0, UNKNOWN: 0 },
    },
    packages: [pkg],
    vulnerabilities: [...vulns],
    osvRecords: {},
  };
}

function createRun(config: Config, deps: Phase2Deps, caseFile: CaseFile, graph: DependencyGraph | null): Run {
  return {
    config,
    deps,
    ui: deps.ui,
    audit: deps.audit,
    provider: deps.provider,
    registry: deps.registry ?? createToolRegistry(),
    caseFile,
    graph,
    meta: { provider: deps.provider.name, model: deps.provider.model, promptVersion: PROMPT_VERSION },
    toolCache: new Map(),
    changelogs: new Map(),
    importScan: new Map(),
    sources: null,
    failures: 0,
    timeouts: 0,
    now: deps.now ?? (() => Date.now()),
  };
}

async function loadGraph(caseFile: CaseFile, config: Config): Promise<DependencyGraph | null> {
  const lockfile = caseFile.project?.lockfile;
  if (!lockfile) return null;
  const file = path.isAbsolute(lockfile) ? lockfile : path.join(config.projectRoot, lockfile);
  try {
    return await loadDependencyGraph(config.projectRoot, file);
  } catch {
    return null;
  }
}

function checkAborted(run: Run): void {
  if (run.deps.signal?.aborted) throw new LlmError('aborted', 'Investigation aborted');
}

// ceiling Low rail inputs

function hopName(hop: string): string {
  const at = hop.lastIndexOf('@');
  return at > 0 ? hop.slice(0, at) : hop;
}

function dependentNames(pkg: PackageCase, projectName: string): string[] {
  const names = new Set<string>();
  for (const d of pkg.dependents ?? []) names.add(d.name);
  for (const p of pkg.dependencyPaths ?? []) {
    for (const hop of p) {
      const name = hopName(hop);
      if (name && name !== pkg.name && name !== projectName) names.add(name);
    }
  }
  names.delete(pkg.name);
  return [...names];
}

async function defaultImportScan(run: Run, names: readonly string[]): Promise<Map<string, boolean> | null> {
  try {
    if (!run.sources) {
      const walk = await walkProject(run.config.projectRoot, { exclude: run.config.exclude, ...(run.deps.signal ? { signal: run.deps.signal } : {}) });
      const sources: { path: string; scope: string; text: string }[] = [];
      for (const file of walk.files) {
        if (file.scope !== 'source') continue;
        try {
          sources.push({ path: file.path, scope: file.scope, text: await readFile(file.abs, 'utf8') });
        } catch {
          // unreadable, skip
        }
      }
      run.sources = sources;
    }
    const out = new Map<string, boolean>();
    for (const name of names) {
      out.set(
        name,
        run.sources.some((f) => f.text.includes(name) && findImportsInSource(f.text, f.path, [name]).length > 0),
      );
    }
    return out;
  } catch {
    return null;
  }
}

// null when unknown
async function dependentsImportedInSource(run: Run, pkg: PackageCase): Promise<boolean | null> {
  const names = dependentNames(pkg, run.caseFile.project?.name ?? '');
  if (names.length === 0) return false;
  const missing: string[] = [];
  for (const name of names) {
    if (run.importScan.has(name)) continue;
    const known = run.caseFile.packages.find((p) => p.name === name);
    if (known) run.importScan.set(name, usageOf(known).scopes.source > 0);
    else missing.push(name);
  }
  if (missing.length > 0) {
    const scan = run.deps.scanImports ? await run.deps.scanImports(missing).catch(() => null) : await defaultImportScan(run, missing);
    for (const name of missing) run.importScan.set(name, scan ? (scan.get(name) ?? null) : null);
  }
  const values = names.map((n) => run.importScan.get(n) ?? null);
  if (values.some((v) => v === true)) return true;
  return values.every((v) => v === false) ? false : null;
}

// call after dependentsImportedInSource
function importedDependentNames(run: Run, pkg: PackageCase): string[] {
  return dependentNames(pkg, run.caseFile.project?.name ?? '').filter((n) => run.importScan.get(n) === true);
}

type EndReason = 'answer' | 'budget' | 'repeat' | 'turns' | 'error';

interface LoopCall {
  exec: ToolExecution;
  key: string;
  by: 'model' | 'harness';
}

interface Loop {
  stage: InvestigationStage;
  toolStage: ToolStage;
  purpose: ChatPurpose;
  pkg: PackageCase;
  vuln: VulnCase | null;
  ctx: ToolContext;
  trace: Trace;
  messages: ChatMessage[];
  tools: ToolSchema[];
  toolNames: string[];
  budget: number;
  maxTurns: number;
  used: number;
  turns: number;
  seq: number;
  seen: Map<string, { count: number; content: string; seq: number }>;
  calls: LoopCall[];
  records: ToolCallRecord[];
  lastProse: string;
  endReason: EndReason | null;
  started: number;
}

function newLoop(run: Run, stage: InvestigationStage, pkg: PackageCase, vuln: VulnCase | null, trace: Trace, firstUser: string): Loop {
  const toolStage: ToolStage = stage;
  const tools = run.registry.schemas(toolStage);
  const budget = Math.max(1, run.config.maxSteps || 3);
  const ctx: ToolContext = {
    projectRoot: run.config.projectRoot,
    config: run.config,
    caseFile: run.caseFile,
    graph: run.graph,
    cache: run.deps.cache ?? null,
    audit: run.audit,
    focus: vuln ? { package: pkg.name, version: pkg.version, vulnId: vuln.id } : { package: pkg.name, version: pkg.version },
  };
  if (run.deps.signal) ctx.signal = run.deps.signal;
  return {
    stage,
    toolStage,
    purpose: stage === 'recon' ? 'recon' : 'verdict-loop',
    pkg,
    vuln,
    ctx,
    trace,
    messages: [
      { role: 'system', content: systemPrompt(stage, budget) },
      { role: 'user', content: firstUser },
    ],
    tools,
    toolNames: tools.map((t) => t.function.name),
    budget,
    maxTurns: budget + 3,
    used: 0,
    turns: 0,
    seq: 0,
    seen: new Map(),
    calls: [],
    records: [],
    lastProse: '',
    endReason: null,
    started: run.now(),
  };
}

function isFatal(err: unknown): boolean {
  if (err instanceof LlmError) return FATAL_KINDS.has(err.kind);
  return true;
}

// null on timeout or http error
async function chatTurn(
  run: Run,
  loop: Loop,
  request: { messages: ChatMessage[]; tools?: ToolSchema[]; format?: JsonSchema; purpose: ChatPurpose },
): Promise<ChatResponse | null> {
  checkAborted(run);
  const spinner = loop.trace.spinner();
  let response: ChatResponse | null = null;
  let failure: unknown = null;
  try {
    response = await run.provider.chat({
      messages: request.messages,
      ...(request.tools && request.tools.length > 0 ? { tools: request.tools } : {}),
      ...(request.format ? { format: request.format } : {}),
      options: { num_predict: request.format ? SCHEMA_MAX_TOKENS : LOOP_MAX_TOKENS },
      purpose: request.purpose,
      ...(run.deps.signal ? { signal: run.deps.signal } : {}),
    });
  } catch (err) {
    failure = err;
  }
  spinner.stop();
  if (response) {
    run.failures = 0;
    run.timeouts = 0;
    return response;
  }
  if (isFatal(failure)) throw failure;
  run.failures += 1;
  run.timeouts = failure instanceof LlmError && failure.kind === 'timeout' ? run.timeouts + 1 : 0;
  loop.trace.result(`Model call failed: ${clip(errorMessage(failure), 160)}`);
  if (run.failures >= MAX_CONSECUTIVE_FAILURES || run.timeouts >= MAX_CONSECUTIVE_TIMEOUTS) throw failure;
  return null;
}

// strip tool json and filler labels
export function cleanProse(text: string, toolNames: readonly string[]): string {
  const out = stripJsonBlocks(parseTextToolCalls(text, toolNames).text)
    .replace(/\b(Answer|Verdict|Response|Output)\s*:\s*/gi, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/\s*\n\s*/g, '\n')
    .trim();
  return /[A-Za-z]{3,}.*[A-Za-z]{3,}/s.test(out) ? out : '';
}

// native calls, else parsed from text
function extractCalls(message: ChatMessage, toolNames: readonly string[]): { calls: ToolCall[]; prose: string } {
  const native = (message.tool_calls ?? []).filter((c) => c?.function?.name);
  if (native.length > 0) return { calls: native, prose: cleanProse(message.content ?? '', toolNames) };
  const recovered = parseTextToolCalls(message.content ?? '', toolNames);
  return { calls: recovered.calls, prose: cleanProse(recovered.text, toolNames) };
}

// "process.argv" is not a sentence end
function sentences(text: string, count: number): string {
  const one = text.replace(/\s+/g, ' ').trim();
  const parts = one.match(/[^]*?[.!?](?=\s|$)/g);
  return parts ? parts.slice(0, count).join('').trim() : one;
}

// fallback reasoning, two sentences max
function shortProse(text: string): string {
  return clip(sentences(text, 2) || text, 220);
}

interface PreparedCall {
  // as the model called it
  name: string;
  // requested name if unknown
  tool: string;
  rawArgs: unknown;
  // aliases resolved, focus pkg filled
  args: Record<string, unknown>;
  key: string;
  description: string;
}

function prepareCall(run: Run, loop: Loop, name: string, rawArgs: unknown): PreparedCall {
  const def = run.registry.get(name);
  if (!def) {
    const args = rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs) ? (rawArgs as Record<string, unknown>) : { value: rawArgs };
    return { name, tool: name, rawArgs, args, key: toolCallKey(name, args), description: `Calling ${name || 'an unknown tool'}...` };
  }
  const norm = run.registry.normalizeArgs(def, rawArgs, loop.ctx);
  return {
    name,
    tool: def.name,
    rawArgs,
    args: norm.args,
    key: toolCallKey(def.name, norm.args),
    description: run.registry.describeCall({ name, arguments: rawArgs }, loop.ctx),
  };
}

// mistral's template needs empty content
function toolCallTurn(calls: readonly PreparedCall[]): ChatMessage {
  return { role: 'assistant', content: '', tool_calls: calls.map((c) => ({ function: { name: c.tool, arguments: c.args } })) };
}

function pushToolMessage(loop: Loop, toolName: string, content: string): void {
  loop.messages.push({ role: 'tool', tool_name: toolName, content });
}

function record(loop: Loop, input: Omit<ToolCallRecord, 'stage' | 'step'>, step: number): ToolCallRecord {
  const rec: ToolCallRecord = { stage: loop.toolStage, step, ...input };
  loop.records.push(rec);
  return rec;
}

// trace, audit, tool message, records
async function executeCall(run: Run, loop: Loop, call: PreparedCall, by: 'model' | 'harness', tag?: TraceLabel): Promise<ToolExecution> {
  loop.seq += 1;
  const step = loop.seq;
  loop.trace.agent(call.description, tag);
  const toolName = call.tool;
  run.audit.log({
    event: 'tool.call',
    stage: loop.toolStage,
    package: loop.pkg.name,
    ...(loop.vuln ? { vulnId: loop.vuln.id } : {}),
    tool: toolName,
    args: call.args,
    by,
    step,
  });
  const cached = run.toolCache.get(call.key);
  let exec: ToolExecution;
  if (cached) {
    exec = { ...cached, stage: loop.toolStage, durationMs: 0 };
  } else {
    exec = await run.registry.execute({ name: call.name, arguments: call.rawArgs }, loop.ctx, loop.toolStage);
    if (exec.status === 'ok') run.toolCache.set(call.key, exec);
  }
  loop.trace.result(exec.hint || exec.status);
  loop.trace.detail(exec.content);
  pushToolMessage(loop, exec.tool ?? call.name, exec.content);
  const rec = record(
    loop,
    {
      tool: exec.tool ?? exec.requested,
      args: exec.args,
      by,
      ok: exec.ok,
      summary: exec.hint,
      cached: Boolean(cached) || Boolean(exec.result?.cached),
      truncated: exec.truncated,
      durationMs: exec.durationMs,
    },
    step,
  );
  loop.calls.push({ exec, key: call.key, by });
  run.audit.log({
    event: 'tool.result',
    stage: loop.toolStage,
    package: loop.pkg.name,
    ...(loop.vuln ? { vulnId: loop.vuln.id } : {}),
    tool: rec.tool,
    ok: rec.ok,
    summary: rec.summary,
    truncated: rec.truncated,
    cached: rec.cached,
    durationMs: rec.durationMs,
  });
  if (exec.tool === 'get_changelog' && exec.ok) {
    const lines = (exec.result?.data as { breakingLines?: unknown } | undefined)?.breakingLines;
    if (Array.isArray(lines)) run.changelogs.set(loop.pkg.name, lines.filter((l): l is string => typeof l === 'string').slice(0, 8));
  }
  return exec;
}

// dedupe, budget, execute
async function modelCall(run: Run, loop: Loop, prepared: PreparedCall): Promise<'ok' | 'stop'> {
  const prior = loop.seen.get(prepared.key);
  if (prior) {
    prior.count += 1;
    loop.trace.agent(prepared.description);
    if (prior.count >= 3) {
      loop.trace.result('Same call repeated again: no more tool calls in this step');
      pushToolMessage(loop, prepared.tool, repeatStopNote());
      return 'stop';
    }
    loop.seq += 1;
    loop.trace.result(`Already done at step ${prior.seq}: the earlier result was sent again`);
    pushToolMessage(loop, prepared.tool, repeatNote(prior.content));
    record(loop, { tool: prepared.tool, args: prepared.args, by: 'model', ok: true, summary: 'repeat: earlier result sent again', cached: true, truncated: false, durationMs: 0 }, loop.seq);
    return 'ok';
  }
  if (loop.used >= loop.budget) {
    loop.trace.agent(prepared.description);
    loop.trace.result('Not run: the tool budget for this step is spent');
    pushToolMessage(loop, prepared.tool, budgetSpentNote());
    return 'ok';
  }
  const exec = await executeCall(run, loop, prepared, 'model');
  loop.seen.set(prepared.key, { count: 1, content: exec.content, seq: loop.seq });
  if (exec.status === 'ok' || exec.status === 'error') loop.used += 1;
  return 'ok';
}

// parrots harness or previous prose
function echoesLastUser(loop: Loop, prose: string): boolean {
  const head = prose.replace(/\s+/g, ' ').trim().slice(0, 48);
  if (head.length < 24) return false;
  if (loop.lastProse.replace(/\s+/g, ' ').startsWith(head)) return true;
  return loop.messages.slice(2).some((m) => m.role === 'user' && m.content.replace(/\s+/g, ' ').includes(head));
}

// until answer, spent budget or repeat
async function toolLoop(run: Run, loop: Loop): Promise<void> {
  loop.endReason = null;
  while (loop.endReason === null) {
    if (loop.used >= loop.budget) {
      loop.endReason = 'budget';
      break;
    }
    if (loop.turns >= loop.maxTurns) {
      loop.endReason = 'turns';
      break;
    }
    loop.turns += 1;
    const response = await chatTurn(run, loop, { messages: loop.messages, tools: loop.tools, purpose: loop.purpose });
    if (!response) {
      loop.endReason = 'error';
      break;
    }
    const { calls, prose } = extractCalls(response.message, loop.toolNames);
    if (prose && !echoesLastUser(loop, prose)) {
      loop.lastProse = prose;
      loop.trace.thought(prose);
    }
    if (calls.length === 0) {
      loop.messages.push({ role: 'assistant', content: response.message.content ?? '' });
      loop.endReason = 'answer';
      break;
    }
    const prepared = calls.map((c) => prepareCall(run, loop, c.function.name, unwrapRawArguments(c.function.arguments)));
    loop.messages.push(toolCallTurn(prepared));
    let stop = false;
    for (const call of prepared) {
      if (stop) {
        pushToolMessage(loop, call.tool, repeatStopNote());
        continue;
      }
      if ((await modelCall(run, loop, call)) === 'stop') stop = true;
    }
    if (stop) {
      loop.endReason = 'repeat';
      break;
    }
    if (loop.used >= loop.budget) {
      loop.endReason = 'budget';
      break;
    }
    loop.messages.push({ role: 'user', content: continuePrompt(loop.budget - loop.used, loop.budget) });
  }
}

// no tools, two tries, else null
async function schemaTurn<T>(
  run: Run,
  loop: Loop,
  prompt: string,
  schema: JsonSchema,
  purpose: ChatPurpose,
  parse: (content: string) => T | null,
): Promise<{ value: T; content: string } | null> {
  const exchange: ChatMessage[] = [{ role: 'user', content: prompt }];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const response = await chatTurn(run, loop, { messages: [...loop.messages, ...exchange], format: schema, purpose });
    if (!response) continue;
    const content = response.message.content ?? '';
    const value = parse(content);
    if (value !== null) {
      loop.messages.push(...exchange, { role: 'assistant', content });
      return { value, content };
    }
    loop.trace.result(`The ${purpose} answer was not valid JSON for the schema`);
    exchange.push(
      { role: 'assistant', content },
      { role: 'user', content: `That was not a valid JSON object for the ${purpose} schema. Reply with only the JSON object.` },
    );
  }
  return null;
}

function deterministicDossier(pkg: PackageCase, vulns: readonly VulnCase[]): DossierModelOutput {
  const usage = usageOf(pkg);
  const members = Object.entries(usage.membersUsed)
    .filter(([, n]) => n > 0)
    .map(([m, n]) => `${m} (${n})`);
  const callSiteNotes = usage.files.slice(0, 4).map((f) => `${f.path}:${f.line} ${clip(f.statement, 100)} [${f.scope}]`);
  if (members.length > 0) callSiteNotes.push(`Members called: ${members.join(', ')}`);
  if (usage.bindingCalls > 0) callSiteNotes.push(`The binding itself is called ${usage.bindingCalls} time${usage.bindingCalls === 1 ? '' : 's'}`);
  const dependents = (pkg.dependents ?? []).map((d) => `${d.name}@${d.version}`);
  return {
    inputSources: [],
    callSiteNotes: callSiteNotes.length > 0 ? callSiteNotes : [`${pkg.name} is not imported by project files`],
    dependentsSummary: `${pkg.isDirect ? 'Direct' : 'Transitive'} ${pkg.isDevOnly ? 'dev-only' : 'production'} dependency${dependents.length > 0 ? `; required by ${dependents.slice(0, 4).join(', ')}` : ''}.`,
    fixCost: `${packageFixText(vulns)}.`,
    openQuestions: usage.files.length > 0 ? ['Where does the data passed to the package come from?'] : [],
  };
}

async function reconLoop(run: Run, pkg: PackageCase, vulns: readonly VulnCase[]): Promise<Dossier> {
  const trace = plainTrace(run.ui);
  const loop = newLoop(run, 'recon', pkg, null, trace, reconPrompt(pkg, vulns));
  await toolLoop(run, loop);
  const turn = await schemaTurn(run, loop, dossierTurnPrompt(), DOSSIER_SCHEMA, 'dossier', parseDossierOutput);
  const forced = turn === null;
  const output = turn?.value ?? deterministicDossier(pkg, vulns);
  const dossier: Dossier = {
    ...output,
    package: pkg.name,
    version: pkg.version,
    toolCalls: loop.records,
    steps: loop.turns,
    durationMs: run.now() - loop.started,
  };
  if (forced) dossier.forced = true;
  const summary = [output.inputSources[0] ? `inputs: ${clip(output.inputSources[0], 90)}` : null, output.fixCost ? `fix: ${clip(output.fixCost, 90)}` : null]
    .filter(Boolean)
    .join('; ');
  trace.agent(forced ? 'No valid dossier from the model; facts assembled from the evidence' : 'Fact dossier ready', forced ? 'forced' : undefined);
  if (summary) trace.result(summary);
  return dossier;
}

// stage 1, one package
export async function runReconLoop(pkg: PackageCase, vulns: readonly VulnCase[], config: Config, deps: Phase2Deps): Promise<Dossier> {
  const run = createRun(config, deps, deps.caseFile ?? minimalCaseFile(config, pkg, vulns), deps.graph ?? null);
  return reconLoop(run, pkg, vulns);
}

function normPath(p: unknown): string {
  return String(p ?? '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\.\/+/, '');
}

function callSitesOf(loop: Loop): UsageCallSite[] {
  const out: UsageCallSite[] = [];
  for (const c of loop.calls) {
    if (c.exec.tool !== 'get_usage' || !c.exec.ok) continue;
    const data = c.exec.result?.data as Partial<GetUsageData> | undefined;
    if (Array.isArray(data?.callSites)) out.push(...data.callSites);
  }
  return out;
}

function requirementMet(req: EvidenceRequirement, pkg: PackageCase, vuln: VulnCase, loop: Loop): boolean {
  const ran = loop.calls.filter((c) => c.exec.status === 'ok' || c.exec.status === 'error');
  if (req.tool === 'get_usage') {
    const want = typeof req.args.symbol === 'string' ? symbolName(req.args.symbol).toLowerCase() : null;
    const internal = new Set((vuln.blamedSymbols ?? []).filter((s) => s.kind === 'internal').map((s) => symbolName(s.name).toLowerCase()));
    const bindings = new Set(usageOf(pkg).files.map((f) => (f.binding ?? '').toLowerCase()).filter(Boolean));
    return ran.some((c) => {
      if (c.exec.tool !== 'get_usage' || String(c.exec.args.package ?? '').toLowerCase() !== pkg.name.toLowerCase()) return false;
      const given = typeof c.exec.args.symbol === 'string' && c.exec.args.symbol.trim() !== '' ? symbolName(c.exec.args.symbol).toLowerCase() : null;
      if (want !== null) return given === want;
      return given === null || internal.has(given) || bindings.has(given) || given === pkg.name.toLowerCase();
    });
  }
  const files = new Set<string>([...usageOf(pkg).files.map((f) => normPath(f.path)), ...callSitesOf(loop).map((s) => normPath(s.path))]);
  return ran.some((c) => c.exec.tool === 'read_file' && files.has(normPath(c.exec.args.path)));
}

// best call site, source bindings first
function callSiteReadArgs(pkg: PackageCase, loop: Loop, fallback: Record<string, unknown>): Record<string, unknown> {
  const sites = callSitesOf(loop);
  const site = sites.find((s) => s.scope === 'source' && s.member === null) ?? sites.find((s) => s.scope === 'source') ?? sites[0];
  if (site) return { path: site.path, startLine: Math.max(1, site.line - 10), endLine: site.line + 19 };
  const imp = importSiteFor(pkg);
  return imp ? { path: imp.path, startLine: Math.max(1, imp.line - 5), endLine: imp.line + 34 } : fallback;
}

function describeRequirement(req: EvidenceRequirement): string {
  return `${req.tool}(${formatArgs(req.args)})`;
}

interface GateState {
  fired: boolean;
  coached: boolean;
  harnessCalls: string[];
}

async function evidenceGate(run: Run, loop: Loop, pkg: PackageCase, vuln: VulnCase, gate: GateState): Promise<void> {
  const reqs = evidenceRequirements(pkg, vuln);
  if (reqs.length === 0) return;
  let missing = reqs.filter((r) => !requirementMet(r, pkg, vuln, loop));
  if (missing.length > 0 && !gate.coached && loop.endReason === 'answer' && loop.used < loop.budget) {
    const first = missing[0] as EvidenceRequirement;
    const args = first.tool === 'read_file' ? callSiteReadArgs(pkg, loop, first.args) : first.args;
    gate.fired = true;
    gate.coached = true;
    run.audit.log({ event: 'gate.evidence', package: pkg.name, vulnId: vuln.id, missing: missing.map(describeRequirement), action: 'coached', tool: first.tool, args });
    loop.trace.agent(`Evidence missing: ${first.reason}. Asking for ${first.tool}(${formatArgs(args)})`, 'evidence gate');
    loop.messages.push({ role: 'user', content: coachingPrompt({ tool: first.tool, args, reason: first.reason }) });
    loop.maxTurns = Math.max(loop.maxTurns, loop.turns + 2);
    await toolLoop(run, loop);
    missing = reqs.filter((r) => !requirementMet(r, pkg, vuln, loop));
  }
  if (missing.length === 0) {
    run.audit.log({ event: 'gate.evidence', package: pkg.name, vulnId: vuln.id, missing: [], action: 'satisfied' });
    return;
  }
  gate.fired = true;
  for (const req of missing) {
    if (requirementMet(req, pkg, vuln, loop)) continue;
    const args = req.tool === 'read_file' ? callSiteReadArgs(pkg, loop, req.args) : req.args;
    run.audit.log({ event: 'gate.evidence', package: pkg.name, vulnId: vuln.id, missing: [describeRequirement(req)], action: 'harness-ran', tool: req.tool, args });
    const prepared = prepareCall(run, loop, req.tool, args);
    loop.messages.push(toolCallTurn([prepared]));
    const exec = await executeCall(run, loop, prepared, 'harness', 'evidence gate');
    loop.seen.set(prepared.key, { count: 1, content: exec.content, seq: loop.seq });
    gate.harnessCalls.push(`${req.tool}(${formatArgs(exec.args)})`);
  }
}

// all blamed exports checked, none called
function blamedApiNotCalled(pkg: PackageCase, vuln: VulnCase, loop: Loop): boolean {
  const all = exportedSymbols(vuln);
  const named = all.filter((s) => !s.defaultCallable);
  if (named.length === 0 || named.length !== all.length) return false;
  const usage = usageOf(pkg);
  if (named.some((s) => (usage.membersUsed[s.name] ?? 0) > 0)) return false;
  if (usage.bindingCalls > 0) return false;
  // unresolved or indirect: may still be called
  if (hasDynamicAccess(usage) || indirectlyCalled(pkg, vuln, loop.calls.map((c) => c.exec))) return false;
  return named.every((s) =>
    loop.calls.some((c) => {
      if (c.exec.tool !== 'get_usage' || !c.exec.ok) return false;
      const data = c.exec.result?.data as Partial<GetUsageData> | undefined;
      return (
        typeof data?.symbol === 'string' &&
        data.symbol.toLowerCase() === s.name.toLowerCase() &&
        data.imported === true &&
        data.symbolCalls === 0 &&
        data.entryPointCalled !== true &&
        (data.dynamicAccess ?? []).length === 0 &&
        (data.indirectCalls ?? 0) === 0
      );
    }),
  );
}

function scoreText(vuln: VulnCase): string | null {
  if (typeof vuln.severity?.cvssScore === 'number') return `CVSS ${vuln.severity.cvssScore.toFixed(1)}`;
  return vuln.severity?.ghsa ?? null;
}

function firstSentence(text: string): string {
  const first = sentences(text, 1);
  return clip(first.length >= 20 ? first : sentences(text, 2), 260) || 'No reasoning given.';
}

async function verdictLoop(run: Run, pkg: PackageCase, vuln: VulnCase, dossier: Dossier): Promise<Verdict> {
  const card = run.ui.card(null);
  card.title(displayVulnId(vuln), `${pkg.name}@${pkg.version}`, scoreText(vuln));
  const trace = cardTrace(card, run.ui);
  const loop = newLoop(run, 'verdict', pkg, vuln, trace, verdictPrompt(pkg, vuln, dossier));
  const gate: GateState = { fired: false, coached: false, harnessCalls: [] };
  await toolLoop(run, loop);
  await evidenceGate(run, loop, pkg, vuln, gate);
  const dependents = await dependentsImportedInSource(run, pkg);
  const executions = loop.calls.map((c) => c.exec);
  const railOptions: RailOptions = {
    dependentsImportedInSource: dependents,
    blamedApiNotCalled: blamedApiNotCalled(pkg, vuln, loop),
    indirectCalled: indirectlyCalled(pkg, vuln, executions),
    importedDependents: importedDependentNames(run, pkg),
  };
  const breaking = run.changelogs.get(pkg.name);
  const first = await schemaTurn(run, loop, verdictTurnPrompt(), VERDICT_SCHEMA, 'verdict', parseVerdictOutput);
  let verdict: Verdict;
  let modelAction: RecommendationAction | null = null;
  if (!first) {
    trace.agent('No valid verdict from the model after two attempts; verdict derived from the evidence', 'forced');
    verdict = forcedVerdict(pkg, vuln, loop.records, run.meta, {
      ...railOptions,
      usedExportedSymbol: exportedCalled(pkg, vuln, loop.records, loop.calls.map((c) => c.exec)),
      graph: run.graph,
      steps: loop.turns,
      durationMs: run.now() - loop.started,
      ...(breaking ? { breakingChanges: breaking } : {}),
    });
  } else {
    const used = exportedCalled(pkg, vuln, loop.records, loop.calls.map((c) => c.exec), false);
    let output = first.value;
    let outcome = applyRails(output, pkg, vuln, used, railOptions);
    let adjusted: { originalRisk: RiskLevel; reason: string } | null = null;
    if (outcome.violation) {
      trace.agent(`Verdict ${output.risk} breaks a rail (${outcome.violation}); asking the model to re-check`, 'rails');
      const second = await schemaTurn(run, loop, verdictTurnPrompt(contradictionText(output, outcome, pkg)), VERDICT_SCHEMA, 'verdict', parseVerdictOutput);
      const firstOutcome = outcome;
      if (second) {
        output = second.value;
        outcome = applyRails(output, pkg, vuln, used, railOptions);
        if (!outcome.violation && namesOtherRisk(output.reasoning, output.risk)) {
          // new rating, swap in the checked fact
          output = { ...output, reasoning: `Re-checked against the evidence: ${railFact(firstOutcome, pkg)}, so the risk is ${output.risk}.` };
        }
      }
      if (outcome.violation) {
        adjusted = { originalRisk: output.risk, reason: outcome.violation };
        run.audit.log({ event: 'verdict.adjusted', vulnId: vuln.id, package: pkg.name, originalRisk: output.risk, risk: outcome.risk, rule: outcome.violation, reasked: true });
        const verb = riskRank(outcome.risk) > riskRank(output.risk) ? 'raised' : 'lowered';
        trace.agent(`Risk ${verb} from ${output.risk} to ${outcome.risk}: ${outcome.violation}`, 'adjusted');
        output = { ...output, risk: outcome.risk };
      }
    }
    if (outcome.reachable && outcome.reachable !== output.reachable) {
      trace.agent(`Reachability "${output.reachable}" changed to "${outcome.reachable}": ${outcome.reachableReason ?? 'the evidence contradicts it'}`, 'rails');
      output = { ...output, reachable: outcome.reachable };
    }
    const investigation: InvestigationMeta = {
      ...run.meta,
      steps: loop.turns,
      toolCalls: loop.records,
      durationMs: run.now() - loop.started,
      forced: false,
    };
    if (adjusted) {
      investigation.adjusted = true;
      investigation.originalRisk = adjusted.originalRisk;
      investigation.adjustReason = adjusted.reason;
    }
    modelAction = output.recommendationAction;
    verdict = {
      vulnId: vuln.id,
      package: pkg.name,
      installedVersion: vuln.installedVersion || pkg.version,
      risk: output.risk,
      reachable: output.reachable,
      confidence: output.confidence,
      reasoning: output.reasoning || shortProse(loop.lastProse) || 'No reasoning given.',
      evidence: output.evidence,
      recommendation: deriveRecommendation(pkg, vuln, output.recommendationAction, { graph: run.graph, risk: output.risk, ...(breaking ? { breakingChanges: breaking } : {}) }),
      investigation,
    };
  }
  if (gate.fired || gate.coached || gate.harnessCalls.length > 0) verdict.investigation.gate = { ...gate };
  const analysis = [loop.lastProse ? clip(loop.lastProse, 2000) : null, modelAction ? `Model recommendation: ${modelAction}` : null].filter(Boolean).join('\n');
  if (analysis) verdict.investigation.analysis = analysis;
  run.audit.log({
    event: 'verdict',
    vulnId: verdict.vulnId,
    package: verdict.package,
    installedVersion: verdict.installedVersion,
    risk: verdict.risk,
    reachable: verdict.reachable,
    confidence: verdict.confidence,
    // model's pick, derived action wins
    action: modelAction ?? verdict.recommendation.action,
    forced: verdict.investigation.forced,
    steps: verdict.investigation.steps,
    durationMs: verdict.investigation.durationMs,
    model: verdict.investigation.model,
  });
  card.verdict(verdict.risk, firstSentence(verdict.reasoning));
  card.confidence(verdict.confidence, recommendationText(verdict.recommendation));
  card.end();
  return verdict;
}

// stage 2, one cve
export async function runVerdictLoop(pkg: PackageCase, vuln: VulnCase, dossier: Dossier, config: Config, deps: Phase2Deps): Promise<Verdict> {
  const run = createRun(config, deps, deps.caseFile ?? minimalCaseFile(config, pkg, [vuln]), deps.graph ?? null);
  return verdictLoop(run, pkg, vuln, dossier);
}

interface CacheHandle {
  lookup(pkg: PackageCase, vuln: VulnCase): { verdict: Verdict; key: string } | null;
  store(pkg: PackageCase, vuln: VulnCase, verdict: Verdict): Promise<void>;
}

async function openVerdictCache(run: Run): Promise<CacheHandle> {
  const file = run.config.paths.verdictCacheFile;
  let cache: VerdictCacheFile | null = null;
  try {
    cache = await loadVerdictCache(file);
  } catch (err) {
    if (!isNotImplemented(err)) run.ui.warn('Verdict cache unreadable; investigating without it', errorMessage(err));
    cache = null;
  }
  const keyFor = (pkg: PackageCase, vuln: VulnCase): string | null => {
    try {
      return verdictCacheKey({
        provider: run.meta.provider,
        vulnId: vuln.id,
        package: pkg.name,
        version: pkg.version,
        model: run.meta.model,
        usageHash: usageEvidenceHash(usageOf(pkg), vuln),
        promptVersion: PROMPT_VERSION,
      });
    } catch {
      return null;
    }
  };
  return {
    lookup(pkg, vuln) {
      if (!cache || run.config.noCache) return null;
      const key = keyFor(pkg, vuln);
      if (!key) return null;
      try {
        const hit = lookupVerdict(cache, key);
        return hit ? { verdict: { ...hit, investigation: { ...hit.investigation, cached: true } }, key } : null;
      } catch {
        return null;
      }
    },
    async store(pkg, vuln, verdict) {
      if (!cache) return;
      const key = keyFor(pkg, vuln);
      if (!key) return;
      try {
        storeVerdict(cache, key, verdict);
        await saveVerdictCache(file, cache);
      } catch (err) {
        if (!isNotImplemented(err)) run.ui.debug(`verdict cache: ${errorMessage(err)}`);
      }
    },
  };
}

function cachedCard(run: Run, pkg: PackageCase, vuln: VulnCase, verdict: Verdict): void {
  const card = run.ui.card(verdict.risk);
  card.title(displayVulnId(vuln), `${pkg.name}@${pkg.version}`, scoreText(vuln));
  card.agent('Same model, prompt and evidence as an earlier run: verdict reused', { tag: 'cached' });
  card.verdict(verdict.risk, firstSentence(verdict.reasoning));
  card.confidence(verdict.confidence, recommendationText(verdict.recommendation));
  card.end();
}

function verdictId(vulnId: string, pkg: string, version: string): string {
  return `${vulnId}|${pkg}|${version}`;
}

// returns and saves the assessment
export async function runPhase2(caseFile: CaseFile, config: Config, deps: Phase2Deps): Promise<Assessment> {
  const now = deps.now ?? (() => Date.now());
  const started = now();
  const graph = deps.graph !== undefined ? deps.graph : await loadGraph(caseFile, config);
  const run = createRun(config, deps, caseFile, graph);
  const selected = selectPackages(caseFile, config);
  const totalCves = selected.reduce((n, e) => n + e.vulns.length, 0);
  const file = config.paths.assessmentFile;
  run.audit.log({
    event: 'investigate.start',
    packages: selected.length,
    vulnerabilities: totalCves,
    provider: run.meta.provider,
    model: run.meta.model,
    promptVersion: PROMPT_VERSION,
    resume: config.resume,
  });
  run.ui.sectionHeader('Investigating vulnerabilities...');

  let assessment = createAssessment(caseFile, run.meta);
  const done = new Set<string>();
  if (config.resume) {
    let existing: Assessment | null = null;
    try {
      existing = await loadAssessment(file);
    } catch (err) {
      run.ui.warn('Cannot resume: the saved assessment is unreadable; starting over', errorMessage(err));
    }
    if (existing && existing.caseFileHash === caseFileHash(caseFile)) {
      assessment = { ...existing, complete: false };
      for (const v of existing.verdicts) done.add(verdictId(v.vulnId, v.package, v.installedVersion));
      const resumable = selected.flatMap((e) => e.vulns.filter((v) => done.has(verdictId(v.id, e.pkg.name, v.installedVersion || e.pkg.version))));
      run.ui.infoLine(`Resuming: ${resumable.length} of ${totalCves} CVEs already investigated`);
    } else if (existing) {
      run.ui.warn('Cannot resume: the saved assessment was made from a different case file; starting over');
    }
  }
  const cache = await openVerdictCache(run);
  const save = async (): Promise<void> => {
    await saveAssessment(file, assessment);
  };

  if (selected.length === 0) run.ui.infoLine('No vulnerable packages to investigate');
  try {
    for (const [i, { pkg, vulns }] of selected.entries()) {
      checkAborted(run);
      // status bar, else activity line
      const activity = `Investigating ${pkg.name}@${pkg.version} (${i + 1} of ${selected.length})`;
      const onCve = (vuln: VulnCase): void => {
        run.ui.status.set({ activity, detail: `CVE ${vulns.indexOf(vuln) + 1} of ${vulns.length} ${displayVulnId(vuln)}` });
      };
      run.ui.status.set({ activity });
      if (!run.ui.status.active) run.ui.activity(`${activity}...`);
      const pending: VulnCase[] = [];
      for (const vuln of vulns) {
        if (done.has(verdictId(vuln.id, pkg.name, vuln.installedVersion || pkg.version))) continue;
        const hit = cache.lookup(pkg, vuln);
        if (hit) {
          onCve(vuln);
          cachedCard(run, pkg, vuln, hit.verdict);
          run.audit.log({ event: 'verdict.cached', vulnId: vuln.id, package: pkg.name, risk: hit.verdict.risk, key: hit.key });
          assessment = upsertVerdict(assessment, hit.verdict);
          await save();
          continue;
        }
        pending.push(vuln);
      }
      if (pending.length === 0) continue;
      let dossier = config.resume ? assessment.dossiers.find((d) => d.package === pkg.name && d.version === pkg.version) : undefined;
      if (!dossier) {
        run.ui.status.set({ activity, detail: `reconnaissance, ${vulns.length} CVE${vulns.length === 1 ? '' : 's'}` });
        dossier = await reconLoop(run, pkg, vulns);
        assessment = upsertDossier(assessment, dossier);
        await save();
      }
      for (const vuln of pending) {
        onCve(vuln);
        const verdict = await verdictLoop(run, pkg, vuln, dossier);
        assessment = upsertVerdict(assessment, verdict);
        await save();
        if (!verdict.investigation.forced) await cache.store(pkg, vuln, verdict);
      }
    }
  } catch (err) {
    await save().catch(() => {});
    throw err;
  }
  assessment = { ...assessment, complete: true, updatedAt: new Date().toISOString() };
  await save();
  run.ui.footer({ model: run.meta.model, numCtx: config.numCtx, packages: selected.length, cves: totalCves, elapsedMs: now() - started });
  return assessment;
}
