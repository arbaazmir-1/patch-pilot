// mcp tools with the evidence gate
import { appendFileSync, mkdirSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { Writable } from 'node:stream';
import { riskRank } from '../config.ts';
import { loadCaseFile, runPhase1 } from '../evidence/casefile.ts';
import { findImportsInSource, walkProject } from '../evidence/codebase.ts';
import { loadDependencyGraph } from '../evidence/lockfile.ts';
import { createAssessment, caseFileHash, loadAssessment, saveAssessment, upsertDossier, upsertVerdict } from '../investigation/assessment.ts';
import {
  alignRecommendation,
  applyRails,
  casePackageFix,
  deriveRecommendation,
  evidenceRequirements,
  parseDossierOutput,
  parseVerdictOutput,
  recommendationText,
  selectPackages,
  type EvidenceRequirement,
  type RailOptions,
  type RailOutcome,
} from '../investigation/agent.ts';
import {
  clip,
  dependencyText,
  displayVulnId,
  PROMPT_VERSION,
  RISK_RUBRIC,
  schemaText,
  severityText,
  symbolName,
  usageLines,
  usageOf,
  VERDICT_SCHEMA,
  DOSSIER_SCHEMA,
  vulnLabel,
  packageFixText,
} from '../investigation/prompts.ts';
import type { GetUsageData, UsageCallSite } from '../investigation/tools/getUsage.ts';
import { createToolRegistry, type ToolRegistry } from '../investigation/tools/index.ts';
import { loadVerdictCache, saveVerdictCache, storeVerdict, usageEvidenceHash, verdictCacheKey } from '../investigation/verdictCache.ts';
import type {
  Assessment,
  AuditSink,
  CaseFile,
  Config,
  DependencyGraph,
  Dossier,
  InvestigationMeta,
  KeyValueCache,
  PackageCase,
  ProviderName,
  Reachable,
  RiskLevel,
  ToolCallRecord,
  ToolContext,
  ToolExecution,
  ToolStage,
  Verdict,
  VerdictModelOutput,
  VulnCase,
} from '../types.ts';
import { createUi, formatArgs, type Ui } from '../ui.ts';
import { errorMessage } from '../util/errors.ts';

// part of the verdict cache key
export const MCP_PROMPT_VERSION = `mcp1-${PROMPT_VERSION}`;

// with the stage that allows each
export const MCP_REGISTRY_TOOLS: Readonly<Record<string, ToolStage>> = {
  get_usage: 'verdict',
  search_code: 'verdict',
  read_file: 'verdict',
  get_advisory: 'verdict',
  check_deps: 'recon',
  get_changelog: 'recon',
};

export const MCP_TOOL_NAMES = ['list_cases', 'get_case', ...Object.keys(MCP_REGISTRY_TOOLS), 'submit_dossier', 'submit_verdict'] as const;

export interface McpToolOutput {
  text: string;
  isError?: boolean;
}

// each line also gets ts
export type SessionEvent =
  | { type: 'ready'; packages: number; vulnerabilities: number; provider: ProviderName; model: string }
  | { type: 'tool'; tool: string; args: Record<string, unknown>; description: string; hint: string; ok: boolean; by: 'model' | 'harness'; package: string | null; step: number }
  | { type: 'gate'; action: 'coached' | 'harness-ran'; vulnId: string; package: string; calls: string[]; reason: string }
  | { type: 'rails'; action: 'reasked' | 'adjusted'; vulnId: string; package: string; violation: string; from: RiskLevel; to: RiskLevel }
  | { type: 'dossier'; package: string; version: string }
  | {
      type: 'verdict';
      vulnId: string;
      package: string;
      version: string;
      risk: RiskLevel;
      reachable: Reachable;
      confidence: number;
      reasoning: string;
      recommendation: string;
      adjusted: boolean;
      gate: boolean;
    }
  | { type: 'error'; message: string };

export type SessionLogEntry = SessionEvent & { ts: string };

export interface McpSessionOptions {
  config: Config;
  provider: ProviderName;
  model: string;
  audit: AuditSink;
  sessionFile?: string | null;
  registry?: ToolRegistry;
  cache?: KeyValueCache | null;
  // defaults to case-file.json or phase 1
  loadCase?: () => Promise<CaseFile>;
  // defaults to the parsed lockfile
  graph?: DependencyGraph | null;
  // faked in tests
  scanImports?: (names: readonly string[]) => Promise<Map<string, boolean> | null>;
  now?: () => number;
}

interface SessionCall {
  tool: string;
  exec: ToolExecution;
  by: 'model' | 'harness';
  package: string | null;
  stage: ToolStage;
  step: number;
}

interface GateState {
  fired: boolean;
  coached: boolean;
  harnessCalls: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normPath(p: unknown): string {
  return String(p ?? '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\.\/+/, '');
}

function describeRequirement(req: { tool: string; args: Record<string, unknown> }): string {
  return `${req.tool}(${formatArgs(req.args)})`;
}

function exactCall(tool: string, args: Record<string, unknown>): string {
  return `${tool}(${JSON.stringify(args)})`;
}

// stdout is the mcp channel
export function silentUi(): Ui {
  const discard = new Writable({
    write(_chunk, _enc, cb) {
      cb();
    },
  });
  return createUi({ quiet: true, json: true, interactive: false, color: false, stdout: discard as never, stderr: process.stderr as never });
}

// mirrors agent.ts

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

function usageData(exec: ToolExecution): Partial<GetUsageData> | undefined {
  return exec.tool === 'get_usage' && exec.ok ? (exec.result?.data as Partial<GetUsageData> | undefined) : undefined;
}

function callSites(calls: readonly SessionCall[]): UsageCallSite[] {
  const out: UsageCallSite[] = [];
  for (const c of calls) {
    const data = usageData(c.exec);
    if (Array.isArray(data?.callSites)) out.push(...data.callSites);
  }
  return out;
}

export function requirementMet(req: EvidenceRequirement, pkg: PackageCase, vuln: VulnCase, calls: readonly SessionCall[]): boolean {
  const ran = calls.filter((c) => c.exec.status === 'ok' || c.exec.status === 'error');
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
  const files = new Set<string>([...usageOf(pkg).files.map((f) => normPath(f.path)), ...callSites(ran).map((s) => normPath(s.path))]);
  return ran.some((c) => c.exec.tool === 'read_file' && files.has(normPath(c.exec.args.path)));
}

export function callSiteReadArgs(pkg: PackageCase, calls: readonly SessionCall[], fallback: Record<string, unknown>): Record<string, unknown> {
  const sites = callSites(calls);
  const site = sites.find((s) => s.scope === 'source' && s.member === null) ?? sites.find((s) => s.scope === 'source') ?? sites[0];
  if (site) return { path: site.path, startLine: Math.max(1, site.line - 10), endLine: site.line + 19 };
  const files = usageOf(pkg).files;
  const imp = files.find((f) => f.scope === 'source') ?? files[0];
  return imp ? { path: imp.path, startLine: Math.max(1, imp.line - 5), endLine: imp.line + 34 } : fallback;
}

// entry-point calls excluded
function exportedCalled(pkg: PackageCase, vuln: VulnCase, calls: readonly SessionCall[]): boolean {
  const exported = exportedSymbols(vuln);
  if (exported.length === 0) return false;
  const names = new Set(exported.filter((s) => !s.defaultCallable).map((s) => s.name.toLowerCase()));
  for (const [member, n] of Object.entries(usageOf(pkg).membersUsed)) if (n > 0 && names.has(member.toLowerCase())) return true;
  return calls.some((c) => {
    const data = usageData(c.exec);
    return Boolean(data && typeof data.symbol === 'string' && names.has(data.symbol.toLowerCase()) && !data.fallback && (data.symbolCalls ?? 0) > 0);
  });
}

function blamedApiNotCalled(pkg: PackageCase, vuln: VulnCase, calls: readonly SessionCall[]): boolean {
  const all = exportedSymbols(vuln);
  const named = all.filter((s) => !s.defaultCallable);
  if (named.length === 0 || named.length !== all.length) return false;
  const usage = usageOf(pkg);
  if (named.some((s) => (usage.membersUsed[s.name] ?? 0) > 0) || usage.bindingCalls > 0) return false;
  return named.every((s) =>
    calls.some((c) => {
      const data = usageData(c.exec);
      return (
        typeof data?.symbol === 'string' &&
        data.symbol.toLowerCase() === s.name.toLowerCase() &&
        data.imported === true &&
        data.symbolCalls === 0 &&
        data.entryPointCalled !== true &&
        (data.dynamicAccess ?? []).length === 0
      );
    }),
  );
}

function railFact(outcome: RailOutcome, pkg: PackageCase): string {
  const v = outcome.violation ?? '';
  if (v.startsWith('dev-only')) return `${pkg.name} is a dev-only dependency (it is not shipped to production)`;
  if (v.startsWith('neither')) return `neither ${pkg.name} nor any package that depends on it is imported in the project's source code`;
  if (v.startsWith("imported in source and the package's default callable")) {
    return `${pkg.name} is imported in source and the package itself is called there as its default callable, the package's main entry point`;
  }
  if (v.startsWith('imported in source')) return `${pkg.name} is imported in source and a function the advisory blames is called there`;
  if (v.startsWith('the blamed functions')) return 'get_usage found no call to the functions the advisory blames (and no dynamic member access) anywhere in the project';
  return v || 'the rails';
}

function contradiction(output: VerdictModelOutput, outcome: RailOutcome, pkg: PackageCase): string {
  const raised = riskRank(outcome.risk) > riskRank(output.risk);
  const bound = raised ? `at least ${outcome.floor}` : `at most ${outcome.ceiling}`;
  return `you rated the risk ${output.risk}, but ${railFact(outcome, pkg)}, so the risk must be ${bound}.`;
}

function hopName(hop: string): string {
  const at = hop.lastIndexOf('@');
  return at > 0 ? hop.slice(0, at) : hop;
}

export class McpSession {
  readonly config: Config;
  readonly provider: ProviderName;
  readonly model: string;
  readonly audit: AuditSink;
  readonly registry: ToolRegistry;
  private readonly options: McpSessionOptions;
  private readonly calls: SessionCall[] = [];
  private readonly gates = new Map<string, GateState>();
  private readonly refusals = new Map<string, number>();
  private readonly railsAsked = new Set<string>();
  private readonly firstActivity = new Map<string, number>();
  private readonly importScan = new Map<string, boolean | null>();
  private casePromise: Promise<CaseFile> | null = null;
  private graphPromise: Promise<DependencyGraph | null> | null = null;
  private writes: Promise<unknown> = Promise.resolve();
  private focus: { package: string; version: string; vulnId?: string } | null = null;
  private step = 0;
  private readonly now: () => number;

  constructor(options: McpSessionOptions) {
    this.options = options;
    this.config = options.config;
    this.provider = options.provider;
    this.model = options.model;
    this.audit = options.audit;
    this.registry = options.registry ?? createToolRegistry();
    this.now = options.now ?? (() => Date.now());
    if (options.graph !== undefined) this.graphPromise = Promise.resolve(options.graph);
  }

  // phase 1 if missing or stale
  ready(): Promise<CaseFile> {
    if (!this.casePromise) {
      this.casePromise = (this.options.loadCase ?? (() => defaultLoadCase(this.config, this.audit)))().then((caseFile) => {
        this.log({ type: 'ready', packages: caseFile.packages.length, vulnerabilities: caseFile.vulnerabilities.length, provider: this.provider, model: this.model });
        return caseFile;
      });
      this.casePromise.catch(() => {
        this.casePromise = null;
      });
    }
    return this.casePromise;
  }

  private graph(): Promise<DependencyGraph | null> {
    if (!this.graphPromise) {
      this.graphPromise = this.ready().then(async (caseFile) => {
        const lockfile = caseFile.project?.lockfile;
        if (!lockfile) return null;
        const file = path.isAbsolute(lockfile) ? lockfile : path.join(this.config.projectRoot, lockfile);
        try {
          return await loadDependencyGraph(this.config.projectRoot, file);
        } catch {
          return null;
        }
      });
    }
    return this.graphPromise;
  }

  // never throws
  log(entry: SessionEvent): void {
    const file = this.options.sessionFile;
    if (!file) return;
    try {
      mkdirSync(path.dirname(file), { recursive: true });
      appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, 'utf8');
    } catch {
      // best effort
    }
  }

  private async lookup(vulnId: string): Promise<{ caseFile: CaseFile; pkg: PackageCase; vuln: VulnCase } | { error: string }> {
    const caseFile = await this.ready();
    const want = vulnId.trim().toLowerCase();
    const vuln = caseFile.vulnerabilities.find((v) => [v.id, ...(v.aliases ?? []), ...(v.mergedIds ?? [])].some((id) => id.toLowerCase() === want));
    if (!vuln) {
      const known = caseFile.vulnerabilities.map((v) => displayVulnId(v)).slice(0, 20);
      return { error: `Unknown vulnerability id "${vulnId}". Known ids: ${known.join(', ') || 'none (no vulnerable packages)'}. Call list_cases for the full list.` };
    }
    const pkg =
      caseFile.packages.find((p) => p.vulnIds?.includes(vuln.id)) ??
      caseFile.packages.find((p) => p.name === vuln.package && p.version === vuln.installedVersion) ??
      caseFile.packages.find((p) => p.name === vuln.package);
    if (!pkg) return { error: `The case file has no package entry for ${vuln.package}; run patch-pilot scan again.` };
    return { caseFile, pkg, vuln };
  }

  private setFocus(pkg: PackageCase, vuln?: VulnCase): void {
    this.focus = vuln ? { package: pkg.name, version: pkg.version, vulnId: vuln.id } : { package: pkg.name, version: pkg.version };
    if (!this.firstActivity.has(pkg.name)) this.firstActivity.set(pkg.name, this.now());
  }

  private gateFor(vulnId: string): GateState {
    let gate = this.gates.get(vulnId);
    if (!gate) {
      gate = { fired: false, coached: false, harnessCalls: [] };
      this.gates.set(vulnId, gate);
    }
    return gate;
  }

  private async assessment(caseFile: CaseFile): Promise<Assessment> {
    let existing: Assessment | null = null;
    try {
      existing = await loadAssessment(this.config.paths.assessmentFile);
    } catch {
      existing = null;
    }
    if (existing && existing.caseFileHash === caseFileHash(caseFile)) return existing;
    return createAssessment(caseFile, { provider: this.provider, model: this.model, promptVersion: MCP_PROMPT_VERSION });
  }

  async listCases(): Promise<McpToolOutput> {
    const caseFile = await this.ready();
    const assessment = await this.assessment(caseFile).catch(() => null);
    const entries = selectPackages(caseFile, { ...this.config, only: [], limit: null, maxCves: null });
    const packages = entries.map(({ pkg, vulns }) => {
      const usage = usageOf(pkg);
      const members = Object.entries(usage.membersUsed)
        .filter(([, n]) => n > 0)
        .map(([m, n]) => `${m} (${n})`);
      return {
        package: pkg.name,
        version: pkg.version,
        dependency: dependencyText(pkg),
        usage: {
          imported: usage.files.length > 0,
          importSites: usage.files.slice(0, 5).map((f) => `${f.path}:${f.line} [${f.scope}]${f.binding ? ` as ${f.binding}` : ''}`),
          inSource: usage.scopes.source,
          membersCalled: members.slice(0, 10),
          packageCalledDirectly: usage.bindingCalls,
        },
        fix: packageFixText(vulns),
        vulnerabilities: vulns.map((v) => {
          const verdict = assessment?.verdicts.find((x) => x.vulnId === v.id && x.package === pkg.name && x.installedVersion === (v.installedVersion || pkg.version));
          return {
            id: v.id,
            cve: displayVulnId(v) !== v.id ? displayVulnId(v) : null,
            severity: severityText(v),
            summary: clip(v.summary, 160),
            blamed: (v.blamedSymbols ?? []).map((s) => `${symbolName(s.name)} (${s.kind})`),
            fixVersion: v.recommendedFix?.version ?? null,
            majorBump: v.recommendedFix?.majorBump ?? false,
            investigated: Boolean(verdict),
            ...(verdict ? { risk: verdict.risk, by: `${verdict.investigation.provider}/${verdict.investigation.model}` } : {}),
          };
        }),
      };
    });
    const total = packages.reduce((n, p) => n + p.vulnerabilities.length, 0);
    const done = packages.reduce((n, p) => n + p.vulnerabilities.filter((v) => v.investigated).length, 0);
    return {
      text: JSON.stringify(
        {
          project: caseFile.project?.name ?? path.basename(this.config.projectRoot),
          scannedAt: caseFile.scannedAt,
          vulnerabilities: total,
          investigated: done,
          packages,
          next: 'For each vulnerability: get_case(vulnId), make the calls it lists as required evidence, then submit_verdict(vulnId, verdict).',
        },
        null,
        1,
      ),
    };
  }

  async getCase(vulnId: string): Promise<McpToolOutput> {
    const found = await this.lookup(vulnId);
    if ('error' in found) return { text: found.error, isError: true };
    const { pkg, vuln, caseFile } = found;
    this.setFocus(pkg, vuln);
    const assessment = await this.assessment(caseFile).catch(() => null);
    const dossier = assessment?.dossiers.find((d) => d.package === pkg.name && d.version === pkg.version);
    const reqs = evidenceRequirements(pkg, vuln);
    const required = reqs.map((r) => {
      const args = r.tool === 'read_file' ? callSiteReadArgs(pkg, this.calls, r.args) : r.args;
      const met = requirementMet(r, pkg, vuln, this.calls);
      return `- ${exactCall(r.tool, args)}: ${r.reason}${met ? ' (done)' : ''}`;
    });
    const blamed = (vuln.blamedSymbols ?? []).map((s) => `${symbolName(s.name)} (${s.kind === 'exported' ? 'exported: public API the project could call' : 'internal: runs inside the package'})`);
    const fix = vuln.recommendedFix ? `${vuln.recommendedFix.version}${vuln.recommendedFix.majorBump ? ' (major bump, breaking changes likely)' : ''}` : 'none published';
    const record = caseFile.osvRecords?.[vuln.id];
    const refs = (vuln.references ?? []).slice(0, 4).map((r) => r.url);
    const lines = [
      `Vulnerability: ${vulnLabel(vuln)} in ${pkg.name}@${vuln.installedVersion || pkg.version}, ${severityText(vuln)}${vuln.cweIds?.length ? `, ${vuln.cweIds.slice(0, 3).join(', ')}` : ''}.`,
      vuln.malware ? 'This is a MALWARE record: the installed version itself is malicious.' : null,
      `Summary: ${clip(vuln.summary, 300)}`,
      `Details: ${clip(record?.details ?? vuln.detailsExcerpt, 1500) || '(none)'}`,
      `Blamed symbols: ${blamed.length > 0 ? blamed.join(', ') : 'none named in the advisory'}`,
      `Affected: ${vuln.affectedRange || 'unknown'}; fixed in ${vuln.fixedVersions?.join(', ') || 'none'}; recommended fix ${fix}`,
      refs.length > 0 ? `References: ${refs.join(' ')}` : null,
      '',
      `Package: ${dependencyText(pkg)}.`,
      ...usageLines(pkg),
      pkg.dependencyPaths?.[0]?.length ? `- Dependency path: ${pkg.dependencyPaths[0].join(' > ')}` : null,
      '',
      dossier ? 'Fact dossier (submitted earlier):' : null,
      ...(dossier
        ? [
            `- Input sources: ${dossier.inputSources.join('; ') || 'none'}`,
            `- Call sites: ${dossier.callSiteNotes.join('; ') || 'none'}`,
            `- Dependents: ${dossier.dependentsSummary || 'unknown'}`,
            `- Fix cost: ${dossier.fixCost || 'unknown'}`,
          ]
        : []),
      dossier ? '' : null,
      required.length > 0
        ? 'Evidence PatchPilot requires before it accepts a verdict (make these calls first):'
        : 'No specific evidence is required: the package is not imported in the project source (check_deps and search_code can still help).',
      ...required,
      '',
      'Question: is the code this advisory blames reachable from this project, and with untrusted input (user data, CLI arguments, network, user files)?',
      `Risk rubric:\n${RISK_RUBRIC}`,
      '',
      `Then call submit_verdict with vulnId "${vuln.id}" and verdict ${schemaText(VERDICT_SCHEMA)}. reasoning: one or two sentences naming the decisive fact; evidence: file:line facts and tool findings.`,
      'PatchPilot checks the verdict against rules (imported in source with a blamed exported function called: at least Medium; neither the package nor a dependent imported in source: at most Low; dev-only: at most Medium; blamed functions checked and never called: at most Medium) and derives the recommended action and target version itself.',
    ];
    return { text: lines.filter((l): l is string => l !== null).join('\n') };
  }

  private async packageOf(tool: string, args: Record<string, unknown>): Promise<string | null> {
    if (typeof args.package === 'string' && args.package.trim() !== '') return args.package.trim();
    if (tool === 'get_advisory' && typeof args.id === 'string') {
      const found = await this.lookup(args.id);
      if (!('error' in found)) {
        this.setFocus(found.pkg, found.vuln);
        return found.pkg.name;
      }
    }
    return this.focus?.package ?? null;
  }

  private async execute(tool: string, rawArgs: unknown, by: 'model' | 'harness', stage: ToolStage): Promise<ToolExecution> {
    const caseFile = await this.ready();
    const args = isRecord(rawArgs) ? rawArgs : {};
    const pkgName = await this.packageOf(tool, args);
    const pkg = pkgName ? caseFile.packages.find((p) => p.name.toLowerCase() === pkgName.toLowerCase()) : undefined;
    if (pkg && by === 'model' && this.focus?.package !== pkg.name) this.setFocus(pkg);
    const ctx: ToolContext = {
      projectRoot: this.config.projectRoot,
      config: this.config,
      caseFile,
      graph: await this.graph(),
      cache: this.options.cache ?? null,
      audit: this.audit,
    };
    if (this.focus) ctx.focus = { ...this.focus };
    const def = this.registry.get(tool);
    const normalized = def ? this.registry.normalizeArgs(def, args, ctx).args : args;
    this.step += 1;
    const step = this.step;
    const vulnId = this.focus?.vulnId;
    this.audit.log({ event: 'tool.call', stage, package: pkgName ?? '', ...(vulnId ? { vulnId } : {}), tool, args: normalized, by, step });
    const exec = await this.registry.execute({ name: tool, arguments: args }, ctx, stage);
    this.audit.log({
      event: 'tool.result',
      stage,
      package: pkgName ?? '',
      ...(vulnId ? { vulnId } : {}),
      tool: exec.tool ?? tool,
      ok: exec.ok,
      summary: exec.hint,
      truncated: exec.truncated,
      cached: Boolean(exec.result?.cached),
      durationMs: exec.durationMs,
    });
    this.calls.push({ tool: exec.tool ?? tool, exec, by, package: pkg?.name ?? pkgName, stage, step });
    this.log({ type: 'tool', tool: exec.tool ?? tool, args: exec.args, description: exec.description, hint: exec.hint || exec.status, ok: exec.ok, by, package: pkg?.name ?? pkgName, step });
    return exec;
  }

  async runTool(tool: string, rawArgs: unknown): Promise<McpToolOutput> {
    const stage = MCP_REGISTRY_TOOLS[tool];
    if (!stage) return { text: `Unknown tool "${tool}". Tools: ${MCP_TOOL_NAMES.join(', ')}.`, isError: true };
    const exec = await this.execute(tool, rawArgs, 'model', stage);
    return { text: exec.content, isError: !exec.ok };
  }

  async submitDossier(pkgName: string, raw: unknown): Promise<McpToolOutput> {
    const caseFile = await this.ready();
    const pkg = caseFile.packages.find((p) => p.name.toLowerCase() === pkgName.trim().toLowerCase() || `${p.name}@${p.version}`.toLowerCase() === pkgName.trim().toLowerCase());
    if (!pkg) return { text: `Unknown package "${pkgName}". Vulnerable packages: ${caseFile.packages.map((p) => p.name).join(', ') || 'none'}.`, isError: true };
    const output = parseDossierOutput(JSON.stringify(raw ?? {}));
    if (!output) return { text: `The dossier needs these fields: ${schemaText(DOSSIER_SCHEMA)}`, isError: true };
    this.setFocus(pkg);
    const records = this.records(pkg.name);
    const dossier: Dossier = {
      ...output,
      package: pkg.name,
      version: pkg.version,
      toolCalls: records,
      steps: records.length,
      durationMs: this.now() - (this.firstActivity.get(pkg.name) ?? this.now()),
    };
    await this.serialize(async () => {
      const assessment = upsertDossier(await this.assessment(caseFile), dossier);
      await saveAssessment(this.config.paths.assessmentFile, assessment);
    });
    this.log({ type: 'dossier', package: pkg.name, version: pkg.version });
    return { text: JSON.stringify({ status: 'saved', package: pkg.name, version: pkg.version, next: 'Now investigate each vulnerability: get_case, the required calls, then submit_verdict.' }) };
  }

  async submitVerdict(vulnId: string, raw: unknown): Promise<McpToolOutput> {
    const found = await this.lookup(vulnId);
    if ('error' in found) return { text: found.error, isError: true };
    const { pkg, vuln, caseFile } = found;
    this.setFocus(pkg, vuln);
    const parsed = parseVerdictOutput(JSON.stringify(raw ?? {}));
    if (!parsed) return { text: `Invalid verdict. It needs: ${schemaText(VERDICT_SCHEMA)}`, isError: true };
    let output: VerdictModelOutput = parsed;
    const label = displayVulnId(vuln);
    const gate = this.gateFor(vuln.id);

    const reqs = evidenceRequirements(pkg, vuln);
    const missing = reqs.filter((r) => !requirementMet(r, pkg, vuln, this.calls));
    if (missing.length > 0) {
      const refusals = this.refusals.get(vuln.id) ?? 0;
      this.refusals.set(vuln.id, refusals + 1);
      gate.fired = true;
      if (refusals === 0) {
        gate.coached = true;
        const first = missing[0] as EvidenceRequirement;
        const args = first.tool === 'read_file' ? callSiteReadArgs(pkg, this.calls, first.args) : first.args;
        this.audit.log({ event: 'gate.evidence', package: pkg.name, vulnId: vuln.id, missing: missing.map(describeRequirement), action: 'coached', tool: first.tool, args });
        this.log({ type: 'gate', action: 'coached', vulnId: vuln.id, package: pkg.name, calls: [describeRequirement({ tool: first.tool, args })], reason: first.reason });
        const also = missing.slice(1).map((r) => exactCall(r.tool, r.tool === 'read_file' ? callSiteReadArgs(pkg, this.calls, r.args) : r.args));
        return {
          isError: true,
          text: [
            `Refused: the evidence for ${label} is incomplete (${first.reason}).`,
            `Make this call with the PatchPilot tool ${first.tool}: ${exactCall(first.tool, args)}`,
            also.length > 0 ? `Also required: ${also.join(', ')}` : null,
            'Then call submit_verdict again.',
          ]
            .filter(Boolean)
            .join('\n'),
        };
      }
      const results: string[] = [];
      for (const req of missing) {
        const args = req.tool === 'read_file' ? callSiteReadArgs(pkg, this.calls, req.args) : req.args;
        this.audit.log({ event: 'gate.evidence', package: pkg.name, vulnId: vuln.id, missing: [describeRequirement(req)], action: 'harness-ran', tool: req.tool, args });
        const exec = await this.execute(req.tool, args, 'harness', 'verdict');
        const call = `${req.tool}(${formatArgs(exec.args)})`;
        gate.harnessCalls.push(call);
        results.push(`${call}:\n${exec.content}`);
      }
      this.log({ type: 'gate', action: 'harness-ran', vulnId: vuln.id, package: pkg.name, calls: gate.harnessCalls.slice(-missing.length), reason: missing.map((m) => m.reason).join('; ') });
      return {
        isError: true,
        text: `Refused again: the required evidence was still missing, so PatchPilot ran the calls itself. Read the results, then call submit_verdict for ${vuln.id} again (the next submission is judged).\n\n${results.join('\n\n')}`,
      };
    }
    if (reqs.length > 0) this.audit.log({ event: 'gate.evidence', package: pkg.name, vulnId: vuln.id, missing: [], action: 'satisfied' });

    const pkgCalls = this.calls;
    const used = exportedCalled(pkg, vuln, pkgCalls);
    const railOptions: RailOptions = { dependentsImportedInSource: await this.dependentsImported(caseFile, pkg), blamedApiNotCalled: blamedApiNotCalled(pkg, vuln, pkgCalls) };
    const outcome = applyRails(output, pkg, vuln, used, railOptions);
    let adjusted: { originalRisk: RiskLevel; reason: string } | null = null;
    if (outcome.violation) {
      if (!this.railsAsked.has(vuln.id)) {
        this.railsAsked.add(vuln.id);
        this.log({ type: 'rails', action: 'reasked', vulnId: vuln.id, package: pkg.name, violation: outcome.violation, from: output.risk, to: outcome.risk });
        return {
          isError: true,
          text: `Not accepted yet: ${contradiction(output, outcome, pkg)} Re-read the evidence and the rubric, then call submit_verdict for ${vuln.id} again with the corrected verdict.`,
        };
      }
      adjusted = { originalRisk: output.risk, reason: outcome.violation };
      this.audit.log({ event: 'verdict.adjusted', vulnId: vuln.id, package: pkg.name, originalRisk: output.risk, risk: outcome.risk, rule: outcome.violation, reasked: true });
      this.log({ type: 'rails', action: 'adjusted', vulnId: vuln.id, package: pkg.name, violation: outcome.violation, from: output.risk, to: outcome.risk });
      output = { ...output, risk: outcome.risk };
    }

    const breaking = this.breakingChanges(pkg.name);
    const records = this.records(pkg.name);
    const investigation: InvestigationMeta = {
      provider: this.provider,
      model: this.model,
      promptVersion: MCP_PROMPT_VERSION,
      steps: records.length,
      toolCalls: records,
      durationMs: this.now() - (this.firstActivity.get(pkg.name) ?? this.now()),
      forced: false,
      analysis: `Model recommendation: ${output.recommendationAction}`,
    };
    if (adjusted) {
      investigation.adjusted = true;
      investigation.originalRisk = adjusted.originalRisk;
      investigation.adjustReason = adjusted.reason;
    }
    if (gate.fired || gate.coached || gate.harnessCalls.length > 0) investigation.gate = { ...gate, harnessCalls: [...gate.harnessCalls] };
    let verdict: Verdict = {
      vulnId: vuln.id,
      package: pkg.name,
      installedVersion: vuln.installedVersion || pkg.version,
      risk: output.risk,
      reachable: output.reachable,
      confidence: output.confidence,
      reasoning: output.reasoning || 'No reasoning given.',
      evidence: output.evidence,
      recommendation: deriveRecommendation(pkg, vuln, output.recommendationAction, {
        graph: await this.graph(),
        risk: output.risk,
        ...(breaking.length > 0 ? { breakingChanges: breaking } : {}),
      }),
      investigation,
    };
    // card shows the version the package action will install
    verdict = alignRecommendation(verdict, pkg, vuln, casePackageFix(caseFile, pkg, vuln, this.config), {
      graph: await this.graph(),
      modelAction: output.recommendationAction,
    });
    await this.store(caseFile, pkg, vuln, verdict);
    this.audit.log({
      event: 'verdict',
      vulnId: verdict.vulnId,
      package: verdict.package,
      installedVersion: verdict.installedVersion,
      risk: verdict.risk,
      reachable: verdict.reachable,
      confidence: verdict.confidence,
      action: output.recommendationAction,
      forced: false,
      steps: investigation.steps,
      durationMs: investigation.durationMs,
      model: this.model,
    });
    const recommendation = recommendationText(verdict.recommendation);
    this.log({
      type: 'verdict',
      vulnId: vuln.id,
      package: pkg.name,
      version: verdict.installedVersion,
      risk: verdict.risk,
      reachable: verdict.reachable,
      confidence: verdict.confidence,
      reasoning: verdict.reasoning,
      recommendation,
      adjusted: Boolean(adjusted),
      gate: Boolean(investigation.gate),
    });
    return {
      text: JSON.stringify({
        status: 'accepted',
        vulnId: vuln.id,
        package: `${pkg.name}@${verdict.installedVersion}`,
        risk: verdict.risk,
        reachable: verdict.reachable,
        confidence: verdict.confidence,
        recommendation,
        ...(adjusted ? { adjusted: { from: adjusted.originalRisk, to: verdict.risk, rule: adjusted.reason } } : {}),
      }),
    };
  }

  private records(pkgName: string): ToolCallRecord[] {
    return this.calls
      .filter((c) => c.package === pkgName)
      .map((c) => ({
        stage: c.stage,
        tool: c.tool,
        args: c.exec.args,
        by: c.by,
        ok: c.exec.ok,
        summary: c.exec.hint,
        cached: Boolean(c.exec.result?.cached),
        truncated: c.exec.truncated,
        durationMs: c.exec.durationMs,
        step: c.step,
      }));
  }

  private breakingChanges(pkgName: string): string[] {
    for (let i = this.calls.length - 1; i >= 0; i -= 1) {
      const c = this.calls[i] as SessionCall;
      if (c.tool !== 'get_changelog' || !c.exec.ok || String(c.exec.args.package ?? '') !== pkgName) continue;
      const lines = (c.exec.result?.data as { breakingLines?: unknown } | undefined)?.breakingLines;
      if (Array.isArray(lines)) return lines.filter((l): l is string => typeof l === 'string').slice(0, 8);
    }
    return [];
  }

  // null when unknown
  private async dependentsImported(caseFile: CaseFile, pkg: PackageCase): Promise<boolean | null> {
    const names = new Set<string>();
    for (const d of pkg.dependents ?? []) names.add(d.name);
    for (const p of pkg.dependencyPaths ?? []) {
      for (const hop of p) {
        const name = hopName(hop);
        if (name && name !== pkg.name && name !== caseFile.project?.name) names.add(name);
      }
    }
    names.delete(pkg.name);
    if (names.size === 0) return false;
    const missing: string[] = [];
    for (const name of names) {
      if (this.importScan.has(name)) continue;
      const known = caseFile.packages.find((p) => p.name === name);
      if (known) this.importScan.set(name, usageOf(known).scopes.source > 0);
      else missing.push(name);
    }
    if (missing.length > 0) {
      const scan = await (this.options.scanImports ?? ((list: readonly string[]) => scanSourceImports(this.config, list)))(missing).catch(() => null);
      for (const name of missing) this.importScan.set(name, scan ? (scan.get(name) ?? null) : null);
    }
    const values = [...names].map((n) => this.importScan.get(n) ?? null);
    if (values.some((v) => v === true)) return true;
    return values.every((v) => v === false) ? false : null;
  }

  private serialize<T>(work: () => Promise<T>): Promise<T> {
    const next = this.writes.then(work, work);
    this.writes = next.catch(() => undefined);
    return next;
  }

  // serialised, calls can overlap
  private async store(caseFile: CaseFile, pkg: PackageCase, vuln: VulnCase, verdict: Verdict): Promise<void> {
    await this.serialize(async () => {
      let assessment = upsertVerdict(await this.assessment(caseFile), verdict);
      const allDone = caseFile.vulnerabilities.every((v) => assessment.verdicts.some((x) => x.vulnId === v.id && x.package === v.package));
      if (allDone) assessment = { ...assessment, complete: true };
      await saveAssessment(this.config.paths.assessmentFile, assessment);
      try {
        const file = this.config.paths.verdictCacheFile;
        const cache = await loadVerdictCache(file, { warn: () => {} });
        const key = verdictCacheKey({
          provider: this.provider,
          vulnId: vuln.id,
          package: pkg.name,
          version: pkg.version,
          model: this.model,
          usageHash: usageEvidenceHash(usageOf(pkg), vuln),
          promptVersion: MCP_PROMPT_VERSION,
        });
        storeVerdict(cache, key, verdict);
        await saveVerdictCache(file, cache);
      } catch (err) {
        this.log({ type: 'error', message: `verdict cache: ${errorMessage(err)}` });
      }
    });
  }
}

async function scanSourceImports(config: Config, names: readonly string[]): Promise<Map<string, boolean> | null> {
  try {
    const walk = await walkProject(config.projectRoot, { exclude: config.exclude });
    const out = new Map<string, boolean>(names.map((n) => [n, false]));
    for (const file of walk.files) {
      if (file.scope !== 'source') continue;
      let text: string;
      try {
        text = await readFile(file.abs, 'utf8');
      } catch {
        continue;
      }
      for (const name of names) {
        if (!out.get(name) && text.includes(name) && findImportsInSource(text, file.path, [name]).length > 0) out.set(name, true);
      }
    }
    return out;
  } catch {
    return null;
  }
}

// silent phase 1 if missing or stale
export async function defaultLoadCase(config: Config, audit: AuditSink): Promise<CaseFile> {
  const existing = await loadCaseFile(config.paths.caseFile).catch(() => null);
  if (existing) {
    const lockfile = existing.project?.lockfile;
    const file = lockfile ? (path.isAbsolute(lockfile) ? lockfile : path.join(config.projectRoot, lockfile)) : null;
    const lockMtime = file ? await stat(file).then((s) => s.mtimeMs).catch(() => null) : null;
    const scanned = Date.parse(existing.scannedAt);
    if (lockMtime === null || Number.isNaN(scanned) || lockMtime <= scanned) return existing;
  }
  return runPhase1({ ...config, interactive: false }, { ui: silentUi(), audit, provider: null });
}
