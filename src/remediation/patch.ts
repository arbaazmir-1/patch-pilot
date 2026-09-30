// phase 3: plan, apply, verify
import { existsSync } from 'node:fs';
import { appendFile, chmod, mkdir, readdir, readFile, rm, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import semver from 'semver';
import { Document, parse as parseYaml, parseDocument } from 'yaml';
import { captureIdentity, newRunId } from '../audit.ts';
import { findIgnore, riskRank } from '../config.ts';
import { severityLabel } from '../evidence/casefile.ts';
import { openDb, type PatchPilotDb } from '../evidence/db.ts';
import { discoverProject, MANAGER_INSTALL, MANAGER_NAMES, parsePackageManagerField } from '../evidence/discover.ts';
import { loadDependencyGraph, nodesByName } from '../evidence/lockfile.ts';
import { npmAlias, splitAt } from '../evidence/lockfiles/index.ts';
import { pnpmStorePath } from '../evidence/lockfiles/pnpm.ts';
import { removeYarnClassicRequests } from '../evidence/lockfiles/yarn.ts';
import { getPackument } from '../evidence/registry.ts';
import { alignAssessment } from '../investigation/agent.ts';
import { caseFileHash } from '../investigation/assessment.ts';
import { displayVulnId } from '../investigation/prompts.ts';
import { createToolRegistry } from '../investigation/tools/index.ts';
import type { ChatProvider } from '../llm/provider.ts';
import type {
  Action,
  ActionKind,
  ApplyResult,
  ApprovalRecord,
  Assessment,
  AuditSink,
  BackupFile,
  BackupManifest,
  CaseFile,
  CodemodResult,
  Config,
  DependencyGraph,
  EnginesCheck,
  FilePatch,
  Identity,
  LockfileDiff,
  LockfileNodeChange,
  MigrationBrief,
  PackageCase,
  PackageJson,
  PackageManager,
  PackageNode,
  Phase3Result,
  RiskLevel,
  RollbackResult,
  SeverityLabel,
  ToolContext,
  Verdict,
  VerifyResult,
  VulnCase,
} from '../types.ts';
import type { Ui } from '../ui.ts';
import { EnvironmentError, errorMessage, EXIT, isNotImplemented, isPromptCancelled, PatchPilotError } from '../util/errors.ts';
import { atomicWrite, detectEol, readJsonIfExists, relativePosix, resolveInside, sha256, toPosix, updateJsonFile, writeJsonAtomic } from '../util/fs.ts';
import { npmInvocation } from '../util/npm.ts';
import { run, type RunOptions, type RunResult } from '../util/proc.ts';
import { compareVersions, isMajorBump, satisfiesRange, specStyle } from '../util/semver.ts';
import { checkSyntax, proposeCodemod, writePatches } from './codemod.ts';
import { chooseTarget, vulnAffects } from './target.ts';
import { manualChecklist, renderBrief, researchMigration } from './migration.ts';
import { canPrompt, defaultPromptAdapter, logApproval, runApprovalGate, type PromptAdapter } from './approve.ts';
import { actionLabel, presentActions, presentFindings, renderLockfileChanges } from './present.ts';
import { writeReports } from './report.ts';

export { chooseTarget, vulnAffects, type TargetChoice } from './target.ts';

export { npmInvocation } from '../util/npm.ts';

// no shell, faked in tests
export type CommandRunner = (cmd: string, args: readonly string[], options?: RunOptions) => Promise<RunResult>;

// injectable for tests
export interface MigrationFns {
  researchMigration: typeof researchMigration;
  proposeCodemod: typeof proposeCodemod;
  writePatches: typeof writePatches;
  checkSyntax: typeof checkSyntax;
  manualChecklist: typeof manualChecklist;
  renderBrief: typeof renderBrief;
}

export function defaultMigrationFns(): MigrationFns {
  return { researchMigration, proposeCodemod, writePatches, checkSyntax, manualChecklist, renderBrief };
}

export interface Phase3Deps {
  ui: Ui;
  audit: AuditSink;
  // null offline or when unneeded
  provider: ChatProvider | null;
  // defaults to provider
  codemodProvider?: ChatProvider | null;
  identity?: Identity;
  signal?: AbortSignal;
  // opened by runPhase3 if absent
  db?: PatchPilotDb | null;
  // false if phase 2 printed cards
  showCards?: boolean;
  // faked in tests
  prompt?: PromptAdapter;
  // faked in tests
  runCommand?: CommandRunner;
  // faked in tests
  migration?: Partial<MigrationFns>;
}

export interface PatchContext extends Phase3Deps {
  config: Config;
  caseFile: CaseFile;
  graph: DependencyGraph;
  identity: Identity;
  // yarn or pnpm only
  manager?: ManagerInvocation | null;
  // applyAction makes one if absent
  backup?: BackupManifest | null;
  // verdict details at the gate
  assessment?: Assessment | null;
}

export interface PatchPreflight {
  dirtyTree: boolean | null;
  lockfileVersion: number;
  workspaces: boolean;
  // e.g. .npmrc package-lock=false
  refuse: string | null;
  unusualSpecs: { name: string; spec: string }[];
  warnings: string[];
}

// on-disk manifest plus post-apply hashes
interface StoredManifest extends BackupManifest {
  // rollback skips files edited since
  after?: Record<string, string | null>;
  restoredAt?: string;
  // rollback deletes these
  created?: string[];
}

const NPM_TIMEOUT_MS = 5 * 60_000;
const POST_TIMEOUT_MS = 10 * 60_000;
// no update notice, funding or audit
const NPM_ENV: Record<string, string> = {
  npm_config_update_notifier: 'false',
  npm_config_fund: 'false',
  npm_config_audit: 'false',
  npm_config_progress: 'false',
};
export const NODE_MODULES_NOTE = 'node_modules is not restored: run `npm install --ignore-scripts` to bring it in line with the restored lockfile.';

function unique<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}

function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return `${n} ${n === 1 ? word : pluralWord}`;
}

const GHSA_RANK: Record<SeverityLabel, number> = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

function pairKey(name: string, version: string): string {
  return `${name}@${version}`;
}

// project-relative posix path
export function lockfileRelPath(caseFile: CaseFile, config: Config): string {
  const abs = path.resolve(config.projectRoot, caseFile.project.lockfile);
  return relativePosix(config.projectRoot, abs);
}

function isScratchLockfile(rel: string): boolean {
  return rel === '.patch-pilot' || rel.startsWith('.patch-pilot/') || rel.startsWith('..');
}

function isAccepted(config: Pick<Config, 'ignore'>, vuln: VulnCase, now: Date): boolean {
  const hit = findIgnore(config.ignore, vuln.id, vuln.package, [...vuln.aliases, ...vuln.mergedIds], now);
  return hit !== null && !hit.expired;
}

// non-root dependents and their ranges
export function parentsOf(pkg: Pick<PackageCase, 'name' | 'keys'>, graph: DependencyGraph, target: string): Action['parents'] {
  const out: Action['parents'] = [];
  const seen = new Set<string>();
  for (const key of pkg.keys) {
    const node = graph.nodes.get(key);
    if (!node) continue;
    for (const parentKey of node.parents) {
      if (parentKey === '' || seen.has(parentKey)) continue;
      const parent = graph.nodes.get(parentKey);
      if (!parent) continue; // workspace folder, not a package
      seen.add(parentKey);
      const range = parent.requires[node.alias ?? node.name] ?? parent.requires[node.name] ?? '*';
      out.push({ name: parent.name, version: parent.version, key: parentKey, range, acceptsTarget: satisfiesRange(target, range) });
    }
  }
  return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

function worstOf(risks: readonly RiskLevel[]): RiskLevel {
  let worst: RiskLevel = 'Noise';
  for (const r of risks) if (riskRank(r) > riskRank(worst)) worst = r;
  return worst;
}

function scopeList(pkg: PackageCase): string[] {
  const scopes = pkg.usage?.scopes ?? { source: 0, test: 0, config: 0, scripts: 0 };
  return (['source', 'test', 'config', 'scripts'] as const).filter((s) => (scopes[s] ?? 0) > 0);
}

function projectEnginesNode(graph: DependencyGraph): string | null {
  const node = graph.root.engines?.node;
  return typeof node === 'string' && node.trim() !== '' ? node.trim() : null;
}

// scanned version left the lockfile
export function stalePackages(caseFile: CaseFile, graph: DependencyGraph): PackageCase[] {
  return caseFile.packages.filter((pkg) => !nodesByName(graph, pkg.name).some((n) => n.version === pkg.version));
}

// most urgent first
export function planActions(caseFile: CaseFile, assessment: Assessment, graph: DependencyGraph, config: Config): Action[] {
  const now = new Date();
  const verdicts = new Map<string, Verdict[]>();
  for (const v of assessment.verdicts) {
    const key = pairKey(v.package, v.installedVersion);
    const list = verdicts.get(key) ?? [];
    list.push(v);
    verdicts.set(key, list);
  }
  const usedIds = new Set<string>();
  const actions: Action[] = [];
  const severityOf = new Map<string, number>();
  for (const pkg of caseFile.packages) {
    const pkgVerdicts = verdicts.get(pairKey(pkg.name, pkg.version)) ?? [];
    if (pkgVerdicts.length === 0) continue; // not investigated (--only, --limit)
    if (!nodesByName(graph, pkg.name).some((n) => n.version === pkg.version)) continue; // already changed in lockfile
    const vulns = caseFile.vulnerabilities.filter((v) => v.package === pkg.name && v.installedVersion === pkg.version && !v.malware);
    const open = vulns.filter((v) => !isAccepted(config, v, now));
    const investigated = open.filter((v) => pkgVerdicts.some((x) => x.vulnId === v.id));
    if (investigated.length === 0) continue;
    const choice = chooseTarget(investigated, pkg.version, caseFile);
    if (!choice) continue;
    const target = choice.version;
    const cleared = open.filter((v) => !vulnAffects(v, target, caseFile));
    const remaining = open.filter((v) => vulnAffects(v, target, caseFile));
    const notes: string[] = [];
    const majorBump = isMajorBump(pkg.version, target);
    const parents = parentsOf(pkg, graph, target);

    const manager = managerOf(graph);
    const depType = pkg.depType;
    const alias = pkg.keys.map((k) => graph.nodes.get(k)?.alias).find((a): a is string => typeof a === 'string');
    const liveSpec = depType ? graph.root[depType]?.[alias ?? pkg.name] : undefined;
    const spec = liveSpec ?? pkg.spec;
    const direct = pkg.isDirect && depType !== null && typeof spec === 'string' ? { depType, spec, specStyle: specStyle(spec) } : null;

    let kind: ActionKind;
    if (direct) {
      kind = majorBump ? 'bump-major' : 'bump';
      if (alias || direct.spec.startsWith('npm:')) {
        direct.specStyle = 'other';
        notes.push(`${alias ?? pkg.name} is an npm alias: PatchPilot asks before rewriting its spec "${direct.spec}".`);
      } else if (direct.specStyle === 'other') {
        notes.push(`package.json spec "${direct.spec}" is not ^, ~ or exact: PatchPilot asks before replacing it with ^${target}.`);
      }
      const nested = parents.filter((p) => !p.acceptsTarget);
      if (nested.length > 0) {
        notes.push(
          `${nested.map((p) => `${p.name}@${p.version} (${p.range})`).join(', ')} still require an older ${pkg.name}: ${manager === 'npm' ? 'npm keeps a nested copy' : `${nested.length === 1 ? 'it keeps its' : 'they keep their'} own copy`}, which verification checks.`,
        );
      }
    } else if (parents.length === 0) {
      kind = 'update-transitive';
      notes.push(`No parent package found in the lockfile: ${IN_RANGE_UPDATE[manager]} is used.`);
    } else if (parents.every((p) => p.acceptsTarget)) {
      kind = 'update-transitive';
    } else {
      kind = 'override-transitive';
      const excluded = unique(parents.filter((p) => !p.acceptsTarget).map((p) => `${p.name}@${p.version}`));
      notes.push(`${excluded.join(', ')} ${excluded.length === 1 ? 'was' : 'were'} not tested with ${pkg.name}@${target} (outside ${unique(parents.filter((p) => !p.acceptsTarget).map((p) => p.range)).join(', ')}): the override is scoped to ${excluded.length === 1 ? 'that parent' : 'those parents'}.`);
      const accepting = unique(parents.filter((p) => p.acceptsTarget).map((p) => `${p.name}@${p.version}`));
      if (accepting.length > 0) notes.push(`${accepting.join(', ')} already accept ${target}: ${IN_RANGE_UPDATE[manager]} moves ${accepting.length === 1 ? 'it' : 'them'} after the override.`);
    }
    if (!choice.full || remaining.length > 0) {
      notes.push(`Still affected at ${target}: ${remaining.map((v) => displayVulnId(v)).join(', ')} (no single fix clears every CVE).`);
    }
    const skipped = unique(investigated.flatMap((v) => v.recommendedFix?.skippedDeprecated ?? []));
    if (skipped.length > 0) notes.push(`Skips deprecated ${skipped.join(', ')}.`);
    const scopes = scopeList(pkg);
    const importedInSource = (pkg.usage?.scopes?.source ?? 0) > 0;
    if (kind === 'bump-major' && !importedInSource && scopes.length > 0) {
      notes.push(`Imported in ${scopes.join(', ')} code only: review those files after the major bump.`);
    }

    let id = `${kind}:${pkg.name}@${target}`;
    if (usedIds.has(id)) id = `${id}+${pkg.version}`;
    usedIds.add(id);
    const vulnIds = cleared.map((v) => v.id);
    const risks = pkgVerdicts.filter((v) => vulnIds.includes(v.vulnId)).map((v) => v.risk);
    const action: Action = {
      id,
      kind,
      package: pkg.name,
      fromVersion: pkg.version,
      toVersion: target,
      vulnIds,
      worstRisk: worstOf(risks.length > 0 ? risks : pkgVerdicts.map((v) => v.risk)),
      majorBump,
      direct,
      parents,
      importedInSource,
      requiresMigration: kind === 'bump-major' && importedInSource,
      engines: { targetNode: null, projectNode: projectEnginesNode(graph), runningNode: process.versions.node, compatible: null },
      notes,
    };
    severityOf.set(action.id, Math.max(0, ...cleared.map((v) => GHSA_RANK[severityLabel(v.severity, v.malware)])));
    actions.push(action);
  }
  return actions.sort(
    (a, b) =>
      riskRank(b.worstRisk) - riskRank(a.worstRisk) ||
      (severityOf.get(b.id) ?? 0) - (severityOf.get(a.id) ?? 0) ||
      (a.package < b.package ? -1 : a.package > b.package ? 1 : 0),
  );
}

// target vs project vs running node
export function enginesCheck(targetNode: string | null, projectNode: string | null, runningNode: string, known = true): EnginesCheck {
  const check: EnginesCheck = { targetNode, projectNode, runningNode, compatible: null };
  if (!known) {
    check.message = 'engines.node of the target is unknown (no registry data)';
    return check;
  }
  if (!targetNode) {
    check.compatible = true;
    check.message = 'no engines.node requirement';
    return check;
  }
  const problems: string[] = [];
  if (!satisfiesRange(runningNode, targetNode)) problems.push(`this machine runs Node ${runningNode}`);
  if (projectNode) {
    let subset: boolean | null = null;
    try {
      subset = semver.subset(projectNode, targetNode, { loose: true });
    } catch {
      subset = null;
    }
    if (subset === false) problems.push(`the project declares node ${projectNode}`);
  }
  check.compatible = problems.length === 0;
  check.message = problems.length === 0 ? `needs Node ${targetNode}: compatible` : `needs Node ${targetNode}, but ${problems.join(' and ')}`;
  return check;
}

// cache only with --offline
export async function attachEngines(actions: Action[], config: Config, db: PatchPilotDb | null, signal?: AbortSignal): Promise<void> {
  for (const action of actions) {
    const projectNode = action.engines?.projectNode ?? null;
    let packument = null;
    try {
      packument = await getPackument(action.package, { db, offline: config.offline, timeoutMs: config.timeouts.registryMs, signal });
    } catch {
      packument = null;
    }
    const info = packument?.versions?.[action.toVersion];
    const engines = info?.engines as Record<string, unknown> | undefined;
    const targetNode = engines && typeof engines.node === 'string' && engines.node.trim() !== '' ? engines.node.trim() : null;
    action.engines = enginesCheck(targetNode, projectNode, process.versions.node, info !== undefined);
    if (action.engines.compatible === false && action.engines.message) action.notes.push(`Node compatibility: ${action.engines.message}.`);
  }
}

function fnsOf(deps: Phase3Deps): MigrationFns {
  return { ...defaultMigrationFns(), ...(deps.migration ?? {}) };
}

// major bumps imported in source
export async function prepareTransactions(actions: readonly Action[], ctx: PatchContext): Promise<Action[]> {
  const { config, ui, audit } = ctx;
  const fns = fnsOf(ctx);
  const out: Action[] = [];
  for (const action of actions) {
    if (!action.requiresMigration) {
      out.push(action);
      continue;
    }
    const next: Action = { ...action, notes: [...action.notes] };
    const provider = ctx.provider;
    if (!provider) {
      next.notes.push('Migration research unavailable: no model provider for this run.');
      out.push(next);
      continue;
    }
    const pkg = ctx.caseFile.packages.find((p) => p.name === action.package && p.version === action.fromVersion);
    const usage = pkg?.usage ?? { package: action.package, imported: false, files: [], scopes: { source: 0, test: 0, config: 0, scripts: 0 }, membersUsed: {}, bindingCalls: 0, scannedFiles: 0 };
    ui.status.set({ activity: `Researching breaking changes for ${action.package}`, detail: `${action.fromVersion} ${ui.glyphs.arrow} ${action.toVersion}` });
    ui.activity(`Researching breaking changes for ${action.package} ${action.fromVersion} ${ui.glyphs.arrow} ${action.toVersion}...`);
    const tools: ToolContext = {
      projectRoot: config.projectRoot,
      config,
      caseFile: ctx.caseFile,
      graph: ctx.graph,
      cache: ctx.db ?? null,
      audit,
      signal: ctx.signal,
      focus: { package: action.package, version: action.fromVersion },
    };
    let brief: MigrationBrief | undefined;
    try {
      brief = await fns.researchMigration(next, usage, { config, ui, audit, provider, registry: createToolRegistry(), tools });
      next.brief = brief;
    } catch (err) {
      if (isPromptCancelled(err)) throw err;
      const reason = isNotImplemented(err) ? 'the migration module is not available in this build' : errorMessage(err);
      next.notes.push(`Migration research unavailable: ${reason}.`);
      ui.warn(`Migration research for ${action.package} is unavailable`, reason);
      out.push(next);
      continue;
    }
    try {
      const codemod: CodemodResult = await fns.proposeCodemod(brief, { config, ui, audit, provider: ctx.codemodProvider ?? provider });
      next.codemod = codemod;
      if (codemod.patches.length > 0) {
        ui.check(`Prepared ${plural(codemod.patches.length, 'code change')} for ${action.package}`, codemod.patches.map((p) => p.file).join(', '));
      } else {
        ui.warn(`No validated code edits for ${action.package}`, 'the brief is shown as a manual checklist at the gate');
      }
    } catch (err) {
      if (isPromptCancelled(err)) throw err;
      const reason = isNotImplemented(err) ? 'the codemod module is not available in this build' : errorMessage(err);
      next.notes.push(`Code edits unavailable: ${reason}.`);
      ui.warn(`Code edits for ${action.package} are unavailable`, reason);
    }
    out.push(next);
  }
  return out;
}

export function transactionFiles(action: Action): string[] {
  return (action.codemod?.patches ?? []).map((p) => p.file);
}

// ignores .patch-pilot/, null outside git
export async function gitTreeDirty(root: string, runner: CommandRunner = run): Promise<boolean | null> {
  const res = await runner('git', ['status', '--porcelain', '--untracked-files=normal', '--', '.'], { cwd: root, timeoutMs: 10_000 });
  if (!res.ok) return null;
  const lines = res.stdout
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 3)
    .map((l) => l.slice(3).replace(/^"|"$/g, ''))
    .filter((p) => !/(^|\/)\.patch-pilot(\/|$)/.test(p));
  return lines.length > 0;
}

// .npmrc disables the lockfile
export async function npmrcRefusal(root: string): Promise<string | null> {
  let text: string;
  try {
    text = await readFile(path.join(root, '.npmrc'), 'utf8');
  } catch {
    return null;
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('#') || line.startsWith(';')) continue;
    if (/^package-lock\s*=\s*false$/i.test(line)) {
      return '.npmrc sets package-lock=false, so npm would not write a lockfile and PatchPilot cannot apply a lockfile change. Remove that line (or apply the fix yourself).';
    }
  }
  return null;
}

export async function checkPatchPreflight(config: Config, graph: DependencyGraph, runner: CommandRunner = run): Promise<PatchPreflight> {
  const warnings: string[] = [];
  const manager = managerOf(graph);
  const dirtyTree = await gitTreeDirty(config.projectRoot, runner);
  if (dirtyTree) warnings.push('The git working tree has uncommitted changes: commit or stash them first so the PatchPilot changes are easy to review.');
  const lockfileVersion = graph.lockfileVersion;
  // yarn 1 keeps v1 as is
  if (lockfileVersion === 1 && manager === 'npm') warnings.push('The lockfile is version 1: npm 11 rewrites it to version 3 when it changes it.');
  const workspaces = graph.root.workspaces.length > 0 || graph.workspaceKeys.length > 0;
  if (workspaces) warnings.push(`The project uses ${MANAGER_NAMES[manager]} workspaces: workspace packages are treated as part of the project.`);
  const refuse = manager === 'npm' ? await npmrcRefusal(config.projectRoot) : manager === 'pnpm' ? await pnpmLockfileRefusal(config.projectRoot) : null;
  const unusualSpecs: { name: string; spec: string }[] = [];
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
    for (const [name, spec] of Object.entries(graph.root[section] ?? {})) {
      if (specStyle(spec) === 'other') unusualSpecs.push({ name, spec });
    }
  }
  return { dirtyTree, lockfileVersion, workspaces, refuse, unusualSpecs, warnings };
}

// always lockfile-only, no scripts
export function npmArgsFor(action: Action, options: Pick<ManagerCommandOptions, 'alias'> = {}): string[] {
  switch (action.kind) {
    case 'bump':
    case 'bump-major': {
      // alias@npm:pkg@spec keeps the alias key
      const target = options.alias ? `${options.alias}@npm:${action.package}@${bumpSpec(action)}` : `${action.package}@${action.toVersion}`;
      const args = ['install', target, '--package-lock-only', '--ignore-scripts'];
      const d = action.direct;
      if (d?.depType === 'devDependencies') args.push('--save-dev');
      else if (d?.depType === 'optionalDependencies') args.push('--save-optional');
      else if (d?.depType === 'peerDependencies') args.push('--save-peer');
      if (d?.specStyle === 'exact') args.push('--save-exact');
      else if (d?.specStyle === 'tilde') args.push('--save-prefix=~');
      return args;
    }
    case 'update-transitive':
      return ['update', action.package, '--package-lock-only', '--ignore-scripts'];
    case 'override-transitive':
      return ['install', '--package-lock-only', '--ignore-scripts'];
  }
}

async function runNpm(runner: CommandRunner, args: readonly string[], cwd: string, timeoutMs: number, signal?: AbortSignal): Promise<RunResult> {
  const inv = npmInvocation();
  return runner(inv.cmd, [...inv.prefix, ...args], { cwd, env: { ...process.env, ...NPM_ENV }, timeoutMs, signal });
}

// from npm error lines
export function npmFailure(res: RunResult): string {
  if (res.error?.code === 'ENOENT') return 'npm was not found on PATH';
  if (res.signal) return `npm was stopped (${res.signal})`;
  const errors = res.stderr
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => /^npm (error|ERR!)/i.test(l))
    .map((l) => l.replace(/^npm (error|ERR!)\s*/i, '').trim())
    .filter((l) => l !== '' && !/^A complete log of this run/i.test(l) && !/^[\\/]|\.log$/.test(l));
  const detail = errors.slice(0, 3).join('; ');
  return `npm exited with code ${res.code ?? 'unknown'}${detail ? `: ${detail}` : ''}`;
}

// EOVERRIDE-style clash, null if safe
export function overrideConflict(pkgJson: PackageJson, action: Action): string | null {
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
    const spec = pkgJson[section]?.[action.package];
    if (typeof spec === 'string') {
      return `${action.package} is a direct dependency ("${spec}" in ${section}); npm refuses overrides that conflict with it (EOVERRIDE). Bump it instead.`;
    }
  }
  const overrides = pkgJson.overrides;
  if (overrides && typeof overrides === 'object' && !Array.isArray(overrides) && Object.hasOwn(overrides, action.package)) {
    return `package.json already overrides ${action.package} (${JSON.stringify(overrides[action.package])}); resolve that override first.`;
  }
  return null;
}

// parent -> { package: version }
export function overrideEntries(action: Action): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const parent of action.parents) {
    if (parent.acceptsTarget) continue;
    out[parent.name] = { [action.package]: action.toVersion };
  }
  return out;
}

// keeps package.json formatting
export async function writeOverride(packageJsonPath: string, action: Action): Promise<Record<string, unknown>> {
  const entries = overrideEntries(action);
  const next = await updateJsonFile<Record<string, unknown>>(packageJsonPath, (current) => {
    const existing = current.overrides && typeof current.overrides === 'object' && !Array.isArray(current.overrides) ? (current.overrides as Record<string, unknown>) : {};
    const overrides: Record<string, unknown> = { ...existing };
    for (const [parent, value] of Object.entries(entries)) {
      const prev = overrides[parent];
      if (typeof prev === 'string') overrides[parent] = { '.': prev, ...value };
      else if (prev && typeof prev === 'object' && !Array.isArray(prev)) overrides[parent] = { ...(prev as Record<string, unknown>), ...value };
      else overrides[parent] = value;
    }
    return { ...current, overrides };
  });
  return next.overrides as Record<string, unknown>;
}

// npm by default
export function managerOf(graph: Pick<DependencyGraph, 'packageManager'> | null | undefined): PackageManager {
  return graph?.packageManager ?? 'npm';
}

export const MANAGER_BINARY: Record<PackageManager, 'npm' | 'yarn' | 'pnpm'> = { npm: 'npm', yarn: 'yarn', 'yarn-berry': 'yarn', pnpm: 'pnpm' };

const IN_RANGE_UPDATE: Record<PackageManager, string> = {
  npm: 'npm update',
  yarn: 'yarn install (after removing the yarn.lock entries of the affected version)',
  'yarn-berry': 'yarn up -R',
  pnpm: 'pnpm update',
};

// no download prompt, pin or strict check
const COREPACK_ENV: Record<string, string> = { COREPACK_ENABLE_DOWNLOAD_PROMPT: '0', COREPACK_ENABLE_AUTO_PIN: '0', COREPACK_ENABLE_STRICT: '0' };
// yarn 2+ also skips scripts, immutable
const MANAGER_ENV: Record<'yarn' | 'yarn-berry' | 'pnpm', Record<string, string>> = {
  yarn: { ...COREPACK_ENV },
  'yarn-berry': { ...COREPACK_ENV, YARN_ENABLE_SCRIPTS: '0', YARN_ENABLE_IMMUTABLE_INSTALLS: 'false', YARN_ENABLE_TELEMETRY: '0', YARN_ENABLE_PROGRESS_BARS: 'false' },
  pnpm: { ...COREPACK_ENV, npm_config_update_notifier: 'false' },
};
// corepack may download first
const PROBE_TIMEOUT_MS = 2 * 60_000;

export interface ManagerInvocation {
  manager: PackageManager;
  cmd: string;
  // e.g. corepack spec "yarn@1"
  prefix: string[];
  // e.g. ["corepack", "yarn@1"]
  display: string[];
  // null for npm, never probed
  version: string | null;
  env: Record<string, string>;
}

export function npmManagerInvocation(platform: NodeJS.Platform = process.platform, execPath: string = process.execPath): ManagerInvocation {
  const inv = npmInvocation(platform, execPath);
  return { manager: 'npm', cmd: inv.cmd, prefix: inv.prefix, display: ['npm'], version: null, env: NPM_ENV };
}

export function managerMajor(invocation: Pick<ManagerInvocation, 'version'> | null | undefined): number | null {
  const major = Number.parseInt(invocation?.version ?? '', 10);
  return Number.isFinite(major) ? major : null;
}

// yarnPath in .yarnrc.yml
async function checkedInYarn(root: string): Promise<string | null> {
  let value: unknown;
  try {
    value = (parseYaml(await readFile(path.join(root, '.yarnrc.yml'), 'utf8'), { schema: 'failsafe' }) as Record<string, unknown> | null)?.yarnPath;
  } catch {
    return null;
  }
  if (typeof value !== 'string' || value.trim() === '') return null;
  const abs = path.resolve(root, value.trim());
  return existsSync(abs) ? abs : null;
}

// pinned version, else lockfile match
function corepackSpec(manager: PackageManager, pinned: string | null, lockfileVersion: number): string {
  const bin = MANAGER_BINARY[manager];
  if (pinned) return `${bin}@${pinned}`;
  if (manager === 'yarn') return 'yarn@1';
  if (manager === 'yarn-berry') return lockfileVersion > 10 ? 'yarn@stable' : lockfileVersion >= 8 ? 'yarn@4' : lockfileVersion >= 6 ? 'yarn@3' : 'yarn@2';
  return bin;
}

export interface ResolveManagerOptions {
  // e.g. "pnpm@9.15.9+sha512..."
  packageManagerField?: string | null;
  // yarn 2+ __metadata.version
  lockfileVersion?: number;
  signal?: AbortSignal;
}

export type ResolvedManager =
  | { ok: true; invocation: ManagerInvocation; notes: string[] }
  | { ok: false; error: string; fix: string[]; links: string[] };

// checked-in yarn, PATH, then corepack
export async function resolveManager(manager: PackageManager, root: string, runner: CommandRunner = run, options: ResolveManagerOptions = {}): Promise<ResolvedManager> {
  if (manager === 'npm') return { ok: true, invocation: npmManagerInvocation(), notes: [] };
  const bin = MANAGER_BINARY[manager];
  const env = MANAGER_ENV[manager];
  const field = parsePackageManagerField(options.packageManagerField);
  const pinned = field && field.name === bin ? field.version : null;
  const fits = (version: string): boolean => {
    const major = Number.parseInt(version, 10);
    if (!Number.isFinite(major)) return false;
    return manager === 'yarn' ? major === 1 : manager === 'yarn-berry' ? major >= 2 : true;
  };
  const probe = async (cmd: string, prefix: string[]): Promise<string | null> => {
    const res = await runner(cmd, [...prefix, '--version'], { cwd: root, env: { ...process.env, ...env }, timeoutMs: PROBE_TIMEOUT_MS, signal: options.signal });
    if (!res.ok) return null;
    return res.stdout.split('\n').map((l) => l.trim()).find((l) => /^\d+\.\d+/.test(l)) ?? null;
  };
  const notes: string[] = [];
  const found = (cmd: string, prefix: string[], display: string[], version: string): ResolvedManager => ({ ok: true, invocation: { manager, cmd, prefix, display, version, env }, notes });
  if (manager === 'yarn-berry') {
    const release = await checkedInYarn(root);
    if (release) {
      const version = await probe(process.execPath, [release]);
      if (version && fits(version)) return found(process.execPath, [release], ['node', relativePosix(root, release)], version);
    }
  }
  const onPath = await probe(bin, []);
  if (onPath && fits(onPath)) return found(bin, [], [bin], onPath);
  const mismatch = onPath ? `${bin} on PATH is ${onPath}, which ${manager === 'yarn' ? 'would convert the yarn 1 lockfile' : 'cannot change a yarn 2+ lockfile'}` : null;
  const spec = corepackSpec(manager, pinned, options.lockfileVersion ?? 0);
  const viaCorepack = await probe('corepack', [spec]);
  if (viaCorepack && fits(viaCorepack)) {
    notes.push(`${mismatch ?? `${bin} is not on PATH`}: running corepack ${spec} (${viaCorepack})`);
    return found('corepack', [spec], ['corepack', spec], viaCorepack);
  }
  const reason = mismatch ? `${mismatch}, and corepack could not run ${spec}` : `neither ${bin} nor corepack (${spec}) could be started`;
  return { ok: false, error: `${MANAGER_NAMES[manager]} is needed to change the lockfile, but ${reason}.`, ...MANAGER_INSTALL[manager] };
}

export interface ManagerCommandOptions {
  // workspaces need -w and -r
  workspaces?: boolean;
  // yarn 1 installs here, not node_modules
  modulesFolder?: string;
  // aliased direct dep name
  alias?: string;
}

// keep exact, ^ or ~ (else ^)
export function bumpSpec(action: Pick<Action, 'direct' | 'toVersion'>): string {
  const style = action.direct?.specStyle;
  if (style === 'exact') return action.toVersion;
  if (style === 'tilde') return `~${action.toVersion}`;
  return `^${action.toVersion}`;
}

function yarnClassicFlags(options: ManagerCommandOptions): string[] {
  return ['--ignore-scripts', '--non-interactive', ...(options.modulesFolder ? ['--modules-folder', options.modulesFolder] : [])];
}

export function refreshArgsFor(pkg: string, manager: PackageManager, options: ManagerCommandOptions = {}): string[] {
  switch (manager) {
    case 'npm':
      return ['update', pkg, '--package-lock-only', '--ignore-scripts'];
    case 'yarn':
      return ['install', ...yarnClassicFlags(options)];
    case 'yarn-berry':
      return ['up', '-R', pkg, '--mode=update-lockfile'];
    case 'pnpm':
      return ['update', pkg, ...(options.workspaces ? ['-r'] : []), '--lockfile-only', '--ignore-scripts'];
  }
}

// npm uses npmArgsFor
export function managerArgsFor(action: Action, manager: PackageManager, options: ManagerCommandOptions = {}): string[] {
  if (manager === 'npm') return npmArgsFor(action, options);
  const bump = action.kind === 'bump' || action.kind === 'bump-major';
  const name = options.alias ? `${options.alias}@npm:${action.package}` : action.package;
  if (manager === 'yarn') return bump ? ['upgrade', `${name}@${bumpSpec(action)}`, ...yarnClassicFlags(options)] : ['install', ...yarnClassicFlags(options)];
  if (manager === 'yarn-berry') {
    if (bump) return ['add', `${name}@${bumpSpec(action)}`, '--mode=update-lockfile'];
    return action.kind === 'update-transitive' ? refreshArgsFor(action.package, manager, options) : ['install', '--mode=update-lockfile'];
  }
  if (bump) {
    // pnpm keeps spec style itself
    const args = ['add', `${name}@${options.alias ? bumpSpec(action) : action.toVersion}`, '--lockfile-only', '--ignore-scripts'];
    const section = action.direct?.depType;
    if (section === 'devDependencies') args.push('-D');
    else if (section === 'optionalDependencies') args.push('-O');
    else if (section === 'peerDependencies') args.push('--save-peer');
    if (options.workspaces) args.push('-w');
    return args;
  }
  return action.kind === 'update-transitive' ? refreshArgsFor(action.package, manager, options) : ['install', '--lockfile-only', '--ignore-scripts'];
}

// e.g. "corepack yarn@1 (1.22.22)"
export function describeInvocation(invocation: Pick<ManagerInvocation, 'display' | 'version'>): string {
  const shown = invocation.display.join(' ');
  if (!invocation.version) return shown;
  if (invocation.display.length === 1) return `${shown} ${invocation.version}`;
  return shown.includes(invocation.version) ? shown : `${shown} (${invocation.version})`;
}

// as the user would type it
export function commandLine(action: Action, manager: PackageManager, invocation?: Pick<ManagerInvocation, 'display'> | null, options: ManagerCommandOptions = {}): string {
  const display = invocation?.display ?? [MANAGER_BINARY[manager]];
  const shown = options.modulesFolder ? { ...options, modulesFolder: '.patch-pilot/tmp/yarn-modules' } : options;
  return [...display, ...managerArgsFor(action, manager, shown)].join(' ');
}

// npm uses npmFailure
export function managerFailure(manager: PackageManager, res: RunResult): string {
  if (manager === 'npm') return npmFailure(res);
  const name = MANAGER_BINARY[manager];
  if (res.error?.code === 'ENOENT') return `${name} was not found on PATH`;
  if (res.signal) return `${name} was stopped (${res.signal})`;
  const lines = `${res.stderr}\n${res.stdout}`.split('\n').map((l) => l.trim()).filter(Boolean);
  let errors: string[];
  if (manager === 'yarn') {
    errors = lines.filter((l) => /^error\s/i.test(l)).map((l) => l.replace(/^error\s+/i, '')).filter((l) => !/^Command failed|yarn-error\.log/i.test(l));
  } else if (manager === 'yarn-berry') {
    errors = lines
      .filter((l) => /(Usage|Internal) Error|YN\d{4}:.*(error|Error|failed|No candidates|doesn't|not found|isn't)/.test(l) && !/YN0000:/.test(l))
      .map((l) => l.replace(/^➤\s*/, '').replace(/^YN\d{4}:\s*[│|]?\s*/, ''));
  } else {
    errors = lines.filter((l) => /ERR_PNPM_|^ERROR\b/.test(l)).map((l) => l.replace(/^\s*(ERROR\s+)?/, ''));
  }
  const detail = [...new Set(errors)].slice(0, 3).join('; ') || lines[lines.length - 1] || '';
  return `${name} exited with code ${res.code ?? 'unknown'}${detail ? `: ${detail}` : ''}`;
}

async function runManager(runner: CommandRunner, invocation: ManagerInvocation, args: readonly string[], cwd: string, timeoutMs: number, signal?: AbortSignal): Promise<RunResult> {
  if (invocation.manager === 'npm') return runNpm(runner, args, cwd, timeoutMs, signal);
  return runner(invocation.cmd, [...invocation.prefix, ...args], { cwd, env: { ...process.env, ...invocation.env }, timeoutMs, signal });
}

// parents whose range excludes target
export function yarnResolutionEntries(action: Action): Record<string, string> {
  const out: Record<string, string> = {};
  for (const parent of action.parents) if (!parent.acceptsTarget) out[`${parent.name}/${action.package}`] = action.toVersion;
  return out;
}

// parents whose range excludes target
export function pnpmOverrideEntries(action: Action): Record<string, string> {
  const out: Record<string, string> = {};
  for (const parent of action.parents) if (!parent.acceptsTarget) out[`${parent.name}>${action.package}`] = action.toVersion;
  return out;
}

// pnpm 11+ uses pnpm-workspace.yaml
export function pnpmOverrideFile(major: number | null): 'package.json' | 'pnpm-workspace.yaml' {
  return major !== null && major >= 11 ? 'pnpm-workspace.yaml' : 'package.json';
}

function objectOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

async function workspaceYaml(root: string): Promise<Record<string, unknown>> {
  try {
    return objectOf(parseYaml(await readFile(path.join(root, 'pnpm-workspace.yaml'), 'utf8'), { schema: 'failsafe' }));
  } catch {
    return {};
  }
}

// null if safe
export async function managerOverrideConflict(manager: PackageManager, root: string, pkgJson: PackageJson, action: Action, pnpmMajor: number | null): Promise<string | null> {
  if (manager === 'npm') return overrideConflict(pkgJson, action);
  const isPnpm = manager === 'pnpm';
  const entries = isPnpm ? pnpmOverrideEntries(action) : yarnResolutionEntries(action);
  const file = isPnpm ? pnpmOverrideFile(pnpmMajor) : 'package.json';
  const existing = isPnpm ? (file === 'package.json' ? objectOf(objectOf(pkgJson.pnpm).overrides) : objectOf((await workspaceYaml(root)).overrides)) : objectOf(pkgJson.resolutions);
  const where = isPnpm ? (file === 'package.json' ? 'package.json pnpm.overrides' : 'pnpm-workspace.yaml overrides') : 'package.json resolutions';
  for (const key of [...Object.keys(entries), action.package, `**/${action.package}`]) {
    if (Object.hasOwn(existing, key)) return `${where} already has "${key}": ${JSON.stringify(existing[key])}; resolve that entry first.`;
  }
  return null;
}

// returns file and entries
export async function writeManagerOverride(manager: PackageManager, root: string, action: Action, pnpmMajor: number | null): Promise<{ file: string; entries: Record<string, string> }> {
  const pkgFile = path.join(root, 'package.json');
  if (manager === 'yarn' || manager === 'yarn-berry') {
    const entries = yarnResolutionEntries(action);
    await updateJsonFile<Record<string, unknown>>(pkgFile, (current) => ({ ...current, resolutions: { ...objectOf(current.resolutions), ...entries } }));
    return { file: 'package.json', entries };
  }
  const entries = pnpmOverrideEntries(action);
  if (pnpmOverrideFile(pnpmMajor) === 'package.json') {
    await updateJsonFile<Record<string, unknown>>(pkgFile, (current) => {
      const pnpm = objectOf(current.pnpm);
      return { ...current, pnpm: { ...pnpm, overrides: { ...objectOf(pnpm.overrides), ...entries } } };
    });
    return { file: 'package.json', entries };
  }
  const file = path.join(root, 'pnpm-workspace.yaml');
  const text = await readFile(file, 'utf8').catch(() => null);
  const doc = text !== null && text.trim() !== '' ? parseDocument(text) : new Document({});
  for (const [key, value] of Object.entries(entries)) doc.setIn(['overrides', key], value);
  await atomicWrite(file, doc.toString());
  return { file: 'pnpm-workspace.yaml', entries };
}

// .npmrc or pnpm-workspace.yaml can disable it
export async function pnpmLockfileRefusal(root: string): Promise<string | null> {
  const npmrc = await readFile(path.join(root, '.npmrc'), 'utf8').catch(() => '');
  const off = npmrc.split(/\r?\n/).some((raw) => /^lockfile\s*=\s*false$/i.test(raw.trim()));
  if (off || String((await workspaceYaml(root)).lockfile) === 'false') {
    return `${off ? '.npmrc sets lockfile=false' : 'pnpm-workspace.yaml sets lockfile: false'}, so pnpm would not write pnpm-lock.yaml and PatchPilot cannot apply a lockfile change. Remove that setting (or apply the fix yourself).`;
  }
  return null;
}

// pnpm lockfiles lack ranges
export async function refineParentRanges(graph: DependencyGraph, caseFile: CaseFile, config: Config, db: PatchPilotDb | null, signal?: AbortSignal): Promise<number> {
  if (managerOf(graph) !== 'pnpm') return 0;
  const parents = new Set<string>();
  for (const pkg of caseFile.packages) {
    for (const key of pkg.keys) for (const parent of graph.nodes.get(key)?.parents ?? []) if (graph.nodes.has(parent)) parents.add(parent);
  }
  let refined = 0;
  for (const key of [...parents].sort()) {
    const node = graph.nodes.get(key) as PackageNode;
    const resolvedOnly = Object.entries(node.edges).some(([dep, target]) => node.requires[dep] !== undefined && node.requires[dep] === graph.nodes.get(target)?.version);
    if (!resolvedOnly) continue;
    let packument = null;
    try {
      packument = await getPackument(node.name, { db, offline: config.offline, timeoutMs: config.timeouts.registryMs, signal });
    } catch {
      packument = null;
    }
    const info = packument?.versions?.[node.version];
    if (!info) continue;
    const declared: Record<string, unknown> = { ...(info.optionalDependencies ?? {}), ...(info.dependencies ?? {}) };
    let changed = false;
    for (const [dep, range] of Object.entries(declared)) {
      if (typeof range !== 'string' || node.requires[dep] === undefined || node.requires[dep] === range) continue;
      node.requires[dep] = range;
      changed = true;
    }
    if (changed) refined += 1;
  }
  return refined;
}

// yarn 1 has no lockfile-only mode
export function yarnModulesFolder(config: Pick<Config, 'paths'>): string {
  return path.join(config.paths.tmpDir, 'yarn-modules');
}

// drop yarn.lock entries to re-resolve
export async function removeAffectedYarnRequests(lockAbs: string, action: Action, caseFile: CaseFile): Promise<string[]> {
  const text = await readFile(lockAbs, 'utf8');
  const vulns = action.vulnIds.map((id) => caseFile.vulnerabilities.find((v) => v.id === id && v.package === action.package)).filter((v): v is VulnCase => v !== undefined);
  const affected = (version: string): boolean => (vulns.length === 0 ? true : vulns.some((v) => vulnAffects(v, version, caseFile)));
  const { text: next, removed } = removeYarnClassicRequests(text, (request, version) => {
    const [name, range] = splitAt(request);
    const alias = npmAlias(range);
    if ((alias?.name ?? name) !== action.package) return false;
    return affected(version) && satisfiesRange(action.toVersion, alias?.range ?? range);
  });
  if (removed.length > 0) await atomicWrite(lockAbs, next);
  return removed;
}

// node_modules is not restored
export function nodeModulesNote(manager: PackageManager): string {
  if (manager === 'npm') return NODE_MODULES_NOTE;
  return `node_modules is not restored: run \`${postInstallText(manager)}\` to bring it in line with the restored lockfile.`;
}

function postInstallArgs(manager: PackageManager): string[] {
  switch (manager) {
    case 'npm':
      return ['install', '--ignore-scripts'];
    case 'yarn':
      return ['install', '--ignore-scripts', '--non-interactive'];
    case 'yarn-berry':
      return ['install'];
    case 'pnpm':
      return ['install', '--ignore-scripts'];
  }
}

function postInstallText(manager: PackageManager): string {
  if (manager === 'yarn-berry') return 'yarn install';
  if (manager === 'yarn') return 'yarn install --ignore-scripts';
  return `${MANAGER_BINARY[manager]} install --ignore-scripts`;
}

// npm: alias of the package
export function directAlias(action: Action, graph: DependencyGraph): string | undefined {
  const d = action.direct;
  if (!d || !d.spec.startsWith('npm:')) return undefined;
  return Object.entries(graph.root[d.depType] ?? {}).find(([name, spec]) => spec === d.spec && name !== action.package)?.[0];
}

// override, main command, refresh
async function changeWithManager(
  action: Action,
  ctx: PatchContext,
  invocation: ManagerInvocation,
  before: DependencyGraph,
  lockAbs: string,
  result: ApplyResult,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const { config, ui } = ctx;
  const root = config.projectRoot;
  const manager = invocation.manager;
  const runner = ctx.runCommand ?? run;
  const options: ManagerCommandOptions = { workspaces: before.workspaceKeys.length > 0, alias: directAlias(action, before) };
  if (manager === 'yarn') options.modulesFolder = yarnModulesFolder(config);
  // yarn 1 does a full install
  const timeoutMs = manager === 'yarn' ? POST_TIMEOUT_MS : NPM_TIMEOUT_MS;
  const exec = async (args: string[]): Promise<RunResult> => {
    const spinner = ui.spinner(`Running ${[...invocation.display, ...args].join(' ')}...`);
    try {
      return await runManager(runner, invocation, args, root, timeoutMs, ctx.signal);
    } finally {
      spinner.stop();
    }
  };
  try {
    if (action.kind === 'override-transitive') {
      const written = await writeManagerOverride(manager, root, action, managerMajor(invocation));
      const kind = manager === 'pnpm' ? 'override' : 'resolution';
      ui.check(`Added a parent-scoped ${kind}`, `${Object.entries(written.entries).map(([k, v]) => `${k} ${v}`).join(', ')} (${written.file})`);
    }
    if (manager === 'yarn' && action.kind === 'update-transitive') {
      const removed = await removeAffectedYarnRequests(lockAbs, action, ctx.caseFile);
      ui.debug(`yarn.lock requests removed for re-resolution: ${removed.join(', ') || 'none'}`);
    }
    const args = managerArgsFor(action, manager, options);
    result.command = [...invocation.display, ...args];
    const res = await exec(args);
    if (!res.ok) return { ok: false, error: managerFailure(manager, res) };
    if (action.kind !== 'update-transitive') {
      const mid = await loadDependencyGraph(root, lockAbs);
      if (verifyAction(action, mid, ctx.caseFile).some((v) => !v.cleared)) {
        const removed = manager === 'yarn' ? await removeAffectedYarnRequests(lockAbs, action, ctx.caseFile) : null;
        if (removed === null || removed.length > 0) {
          const refresh = refreshArgsFor(action.package, manager, options);
          ui.debug(`an affected ${action.package} copy remains: ${[...invocation.display, ...refresh].join(' ')}`);
          const again = await exec(refresh);
          if (!again.ok) return { ok: false, error: managerFailure(manager, again) };
        }
      }
    }
    return { ok: true };
  } finally {
    if (options.modulesFolder) await rm(options.modulesFolder, { recursive: true, force: true }).catch(() => {});
  }
}

// e.g. "package.json dependencies.lodash"
const ROOT_SPEC_KEY = /^package\.json (dependencies|devDependencies|optionalDependencies|peerDependencies)\.(.+)$/;

function nodeSignature(n: PackageNode): string {
  return [n.version, n.resolved ?? '', n.integrity ?? '', n.dev, n.optional, n.devOptional, n.peer].join('|');
}

function nodeLabel(n: PackageNode, other?: PackageNode): string {
  const flags = (x: PackageNode): string => [x.dev ? 'dev' : '', x.optional ? 'optional' : '', x.peer ? 'peer' : ''].filter(Boolean).join(', ');
  const mine = flags(n);
  if (other && other.version === n.version) {
    if (mine !== flags(other)) return `${n.version}${mine ? ` (${mine})` : ''}`;
    if ((other.integrity ?? '') !== (n.integrity ?? '')) return `${n.version} (integrity ${(n.integrity ?? 'none').slice(0, 15)})`;
    if ((other.resolved ?? '') !== (n.resolved ?? '')) return `${n.version} (${n.resolved ?? 'no resolved URL'})`;
  }
  return n.version;
}

function subtree(graph: DependencyGraph, roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const queue = [...roots];
  while (queue.length > 0) {
    const key = queue.shift() as string;
    if (seen.has(key)) continue;
    seen.add(key);
    const node = graph.nodes.get(key);
    for (const next of Object.values(node?.edges ?? {})) if (!seen.has(next)) queue.push(next);
  }
  return seen;
}

// new key re-hashes every package
function checksumFormat(integrity: string | undefined): string {
  const m = /^([0-9a-z]+)\//i.exec(integrity ?? '');
  return m ? (m[1] as string) : '';
}

// only target subtree may change
export function diffLockfiles(before: DependencyGraph, after: DependencyGraph, action: Action): LockfileDiff {
  const changes: LockfileNodeChange[] = [];
  const berry = managerOf(before) === 'yarn-berry' && managerOf(after) === 'yarn-berry';
  const differs = (a: PackageNode, b: PackageNode): boolean =>
    berry && checksumFormat(a.integrity) !== checksumFormat(b.integrity)
      ? nodeSignature({ ...a, integrity: undefined }) !== nodeSignature({ ...b, integrity: undefined })
      : nodeSignature(a) !== nodeSignature(b);
  const keys = [...new Set([...before.nodes.keys(), ...after.nodes.keys()])].sort();
  for (const key of keys) {
    const a = before.nodes.get(key);
    const b = after.nodes.get(key);
    if (a && !b) changes.push({ key, change: 'removed', from: nodeLabel(a) });
    else if (!a && b) changes.push({ key, change: 'added', to: nodeLabel(b) });
    else if (a && b && differs(a, b)) changes.push({ key, change: 'changed', from: nodeLabel(a, b), to: nodeLabel(b, a) });
  }
  // target's spec may change
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const) {
    const a = before.root[section] ?? {};
    const b = after.root[section] ?? {};
    for (const name of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
      if (a[name] === b[name]) continue;
      const key = `package.json ${section}.${name}`;
      if (a[name] === undefined) changes.push({ key, change: 'added', to: b[name] });
      else if (b[name] === undefined) changes.push({ key, change: 'removed', from: a[name] });
      else changes.push({ key, change: 'changed', from: a[name], to: b[name] });
    }
  }
  const allowedKeys = new Set<string>();
  for (const graph of [before, after]) {
    for (const key of subtree(graph, nodesByName(graph, action.package).map((n) => n.key))) allowedKeys.add(key);
  }
  const aliasOf = (graph: DependencyGraph): string | undefined => nodesByName(graph, action.package).map((n) => n.alias).find((a) => a !== undefined);
  const beforeAlias = aliasOf(before);
  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;
  const directByName = sections.some((section) => Object.hasOwn(before.root[section] ?? {}, action.package));
  // aliased only: a new plain key is a second copy
  const directNames = new Set<string>(beforeAlias && !directByName ? [] : [action.package]);
  for (const alias of [beforeAlias, aliasOf(after)]) if (alias) directNames.add(alias);
  const allowed: LockfileNodeChange[] = [];
  const unexpected: LockfileNodeChange[] = [];
  for (const change of changes) {
    let ok: boolean;
    const root = ROOT_SPEC_KEY.exec(change.key);
    if (root) {
      ok = directNames.has(root[2] as string);
    } else {
      const node = before.nodes.get(change.key) ?? after.nodes.get(change.key);
      const plainCopy = change.change === 'added' && !directNames.has(action.package) && node?.isDirect === true && !node.alias;
      ok = !plainCopy && (node?.name === action.package || allowedKeys.has(change.key));
    }
    (ok ? allowed : unexpected).push(change);
  }
  return { changes, allowed, unexpected };
}

// every installed copy vs cve ranges
export function verifyAction(action: Action, after: DependencyGraph, caseFile: CaseFile): VerifyResult[] {
  return action.vulnIds.map((vulnId) => {
    const vuln = caseFile.vulnerabilities.find((v) => v.id === vulnId && v.package === action.package);
    const nodes = nodesByName(after, action.package).map((n) => ({ key: n.key, version: n.version, affected: vuln ? vulnAffects(vuln, n.version, caseFile) : true }));
    return { vulnId, package: action.package, cleared: vuln !== undefined && nodes.every((n) => !n.affected), nodes };
  });
}

interface FileSnapshot {
  rel: string;
  abs: string;
  content: Buffer | null;
  mode: number | null;
}

async function readIfExists(abs: string): Promise<{ data: Buffer; mode: number } | null> {
  try {
    const [data, st] = await Promise.all([readFile(abs), stat(abs)]);
    return { data, mode: st.mode & 0o7777 };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

async function hashOf(abs: string): Promise<string | null> {
  const file = await readIfExists(abs);
  return file ? sha256(file.data) : null;
}

async function takeSnapshot(root: string, rels: readonly string[]): Promise<FileSnapshot[]> {
  const out: FileSnapshot[] = [];
  for (const rel of unique(rels.map((r) => toPosix(r)))) {
    const abs = resolveInside(root, rel);
    const file = await readIfExists(abs);
    out.push({ rel: relativePosix(root, abs), abs, content: file?.data ?? null, mode: file?.mode ?? null });
  }
  return out;
}

// returns rewritten files
async function restoreSnapshot(snapshot: readonly FileSnapshot[]): Promise<string[]> {
  const restored: string[] = [];
  for (const file of snapshot) {
    const current = await readIfExists(file.abs);
    if (file.content === null) {
      if (current) {
        await unlink(file.abs);
        restored.push(file.rel);
      }
      continue;
    }
    if (current && current.data.equals(file.content) && current.mode === file.mode) continue;
    await atomicWrite(file.abs, file.content);
    if (file.mode !== null) await chmod(file.abs, file.mode);
    restored.push(file.rel);
  }
  return restored;
}

function snapshotHash(snapshot: readonly FileSnapshot[], rel: string): string | null {
  const file = snapshot.find((f) => f.rel === rel);
  return file?.content ? sha256(file.content) : null;
}

export async function createBackup(config: Config, files: readonly string[], actionIds: readonly string[], audit: AuditSink): Promise<BackupManifest> {
  const root = config.projectRoot;
  const id = newRunId();
  const dir = path.join(config.paths.backupDir, id);
  const entries: BackupFile[] = [];
  const created: string[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    const abs = resolveInside(root, file);
    const rel = relativePosix(root, abs);
    if (seen.has(rel)) continue;
    seen.add(rel);
    const content = await readIfExists(abs);
    if (!content) {
      created.push(rel);
      continue;
    }
    const dest = path.join(dir, 'files', ...rel.split('/'));
    await mkdir(path.dirname(dest), { recursive: true });
    await writeFile(dest, content.data);
    entries.push({ path: rel, sha256: sha256(content.data), size: content.data.length, mode: content.mode });
  }
  const manifest: BackupManifest = { id, createdAt: new Date().toISOString(), dir, projectRoot: root, files: entries, actionIds: [...actionIds] };
  const stored: StoredManifest = created.length > 0 ? { ...manifest, created } : manifest;
  await writeJsonAtomic(path.join(dir, 'manifest.json'), stored);
  audit.log({ event: 'patch.backup', backupId: id, dir: relativePosix(root, dir), files: entries.map((f) => ({ path: f.path, sha256: f.sha256 })) });
  return manifest;
}

// lets rollback spot later edits
async function finalizeBackup(manifest: BackupManifest, actionIds?: readonly string[]): Promise<void> {
  const file = path.join(manifest.dir, 'manifest.json');
  const stored = (await readJsonIfExists<StoredManifest>(file)) ?? { ...manifest };
  const after: Record<string, string | null> = {};
  for (const f of stored.files) after[f.path] = await hashOf(path.join(stored.projectRoot, ...f.path.split('/')));
  for (const rel of stored.created ?? []) after[rel] = await hashOf(path.join(stored.projectRoot, ...rel.split('/')));
  stored.after = after;
  if (actionIds) stored.actionIds = unique([...stored.actionIds, ...actionIds]);
  await writeJsonAtomic(file, stored);
}

async function listBackups(backupDir: string): Promise<StoredManifest[]> {
  let names: string[];
  try {
    names = await readdir(backupDir);
  } catch {
    return [];
  }
  const out: StoredManifest[] = [];
  for (const name of names) {
    try {
      const manifest = await readJsonIfExists<StoredManifest>(path.join(backupDir, name, 'manifest.json'));
      if (manifest && typeof manifest.id === 'string' && Array.isArray(manifest.files)) out.push({ ...manifest, dir: path.join(backupDir, name) });
    } catch {
      // skip damaged manifest
    }
  }
  return out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : a.id < b.id ? 1 : -1));
}

// verifies hashes first
export async function rollbackLatest(config: Config, ui: Ui, audit: AuditSink): Promise<RollbackResult> {
  const backups = await listBackups(config.paths.backupDir);
  const latest = backups[0];
  if (!latest) {
    throw new PatchPilotError(`No backup to restore in ${relativePosix(config.projectRoot, config.paths.backupDir) || config.paths.backupDir}`, {
      exitCode: EXIT.USAGE,
      hint: 'PatchPilot takes a backup in .patch-pilot/backup/ before it changes package.json, the lockfile or source files.',
    });
  }
  const root = config.projectRoot;
  const restored: string[] = [];
  const mismatched: string[] = [];
  const missing: string[] = [];
  const unchanged: string[] = [];
  for (const file of latest.files) {
    const copy = await readIfExists(path.join(latest.dir, 'files', ...file.path.split('/')));
    if (!copy || sha256(copy.data) !== file.sha256) {
      missing.push(file.path);
      continue;
    }
    const target = resolveInside(root, file.path);
    const current = await hashOf(target);
    if (current === file.sha256) {
      unchanged.push(file.path);
      continue;
    }
    const recorded = latest.after?.[file.path];
    if (recorded !== undefined && current !== recorded) {
      let overwrite = false;
      if (config.interactive && ui.interactive) {
        overwrite = (await ui.singleKeyPrompt(`${file.path} changed after the patch was applied. Overwrite it with the backup?`, 'y/n')) === 'y';
      }
      if (!overwrite) {
        mismatched.push(file.path);
        continue;
      }
    }
    await atomicWrite(target, copy.data);
    await chmod(target, file.mode);
    restored.push(file.path);
  }
  // unless edited since
  const removedCreated: string[] = [];
  for (const rel of latest.created ?? []) {
    const target = resolveInside(root, rel);
    const current = await hashOf(target);
    const recorded = latest.after?.[rel] ?? null;
    if (current === null || recorded === null) continue;
    if (current !== recorded) {
      mismatched.push(rel);
      continue;
    }
    await unlink(target);
    removedCreated.push(rel);
    restored.push(rel);
  }
  const manager = (await discoverProject(root).catch(() => null))?.packageManager ?? 'npm';
  const note = nodeModulesNote(manager);
  audit.log({ event: 'rollback', backupId: latest.id, restored, mismatched, reason: 'patch-pilot rollback' });
  const manifestFile = path.join(latest.dir, 'manifest.json');
  if (restored.length > 0) await writeJsonAtomic(manifestFile, { ...latest, restoredAt: new Date().toISOString() }).catch(() => {});
  ui.activity(`Restoring backup ${latest.id} (${new Date(latest.createdAt).toLocaleString()})`);
  for (const f of restored) ui.check(removedCreated.includes(f) ? `Removed ${f}` : `Restored ${f}`, removedCreated.includes(f) ? 'it did not exist before the patch' : undefined);
  for (const f of unchanged) ui.infoLine(`${f} already matches the backup`);
  for (const f of mismatched) ui.warn(`Kept ${f}`, 'it changed after the patch was applied; restore it by hand from the backup if needed');
  for (const f of missing) ui.fail(`Cannot restore ${f}`, 'the backup copy is missing or does not match its recorded hash');
  if (restored.length === 0 && mismatched.length === 0 && missing.length === 0) ui.infoLine('Nothing to restore: the project already matches the backup');
  ui.warn(note);
  ui.info(ui.formatDimLines([`Backup: ${relativePosix(root, latest.dir)}`]));
  return { backupId: latest.id, restored, mismatched, missing, note };
}

function approvedPatches(action: Action, approval: ApprovalRecord): FilePatch[] {
  const patches = action.codemod?.patches ?? [];
  if (!action.requiresMigration || patches.length === 0) return [];
  if (!approval.files) return approval.scope === 'transaction' ? patches : [];
  const ok = new Set(approval.files.filter((f) => f.approved).map((f) => f.file));
  return patches.filter((p) => ok.has(p.file));
}

function interactiveOk(ctx: Pick<PatchContext, 'config' | 'ui' | 'prompt'>): boolean {
  return canPrompt(ctx.config, ctx.ui, ctx.prompt);
}

async function confirmWith(ctx: Pick<PatchContext, 'config' | 'ui' | 'prompt'>, question: string): Promise<boolean> {
  const prompt = ctx.prompt ?? defaultPromptAdapter(ctx.ui);
  return prompt.confirm(question, false);
}

function versionsOf(graph: DependencyGraph, name: string): string[] {
  return unique(nodesByName(graph, name).map((n) => n.version)).sort(compareVersions);
}

export async function applyAction(action: Action, approval: ApprovalRecord, ctx: PatchContext): Promise<ApplyResult> {
  const { config, ui, audit } = ctx;
  const root = config.projectRoot;
  const lockRel = lockfileRelPath(ctx.caseFile, config);
  const lockAbs = path.join(root, ...lockRel.split('/'));
  const result: ApplyResult = { actionId: action.id, ok: false, before: action.fromVersion, after: null, filesChanged: [], verify: [], rolledBack: false };
  const label = actionLabel(action, ui);
  const logApply = (ok: boolean, error?: string): void => {
    audit.log({
      event: 'patch.apply',
      actionId: action.id,
      package: action.package,
      kind: action.kind,
      before: action.fromVersion,
      after: result.after,
      ...(result.command ? { command: result.command } : {}),
      files: result.filesChanged,
      ok,
      ...(error ? { error } : {}),
    });
  };
  if (approval.decision !== 'approve') {
    result.error = 'not approved';
    return result;
  }
  if (isScratchLockfile(lockRel)) {
    result.error = 'the scanned lockfile is a scratch copy in .patch-pilot/tmp/, not the project lockfile';
    ui.warn(`Skipped ${label}`, result.error);
    return result;
  }
  if (action.direct?.specStyle === 'other') {
    const alias = directAlias(action, ctx.graph);
    const question = alias
      ? `package.json has ${alias}: "${action.direct.spec}". Replace it with npm:${action.package}@${bumpSpec(action)}?`
      : `package.json has ${action.package}: "${action.direct.spec}". Replace it with ${bumpSpec(action)}?`;
    const ok = interactiveOk(ctx) ? await confirmWith(ctx, question) : false;
    if (!ok) {
      result.error = `skipped: the spec "${action.direct.spec}" needs a confirmation in a terminal`;
      ui.warn(`Skipped ${label}`, result.error);
      logApply(false, result.error);
      return result;
    }
  }
  const pkgJsonPath = path.join(root, 'package.json');
  const manager = managerOf(ctx.graph);
  let invocation: ManagerInvocation | null = null;
  if (manager !== 'npm') {
    invocation = ctx.manager ?? null;
    if (!invocation) {
      const pkg = await readJsonIfExists<PackageJson>(pkgJsonPath).catch(() => null);
      const resolved = await resolveManager(manager, root, ctx.runCommand ?? run, {
        packageManagerField: typeof pkg?.packageManager === 'string' ? pkg.packageManager : null,
        lockfileVersion: ctx.graph.lockfileVersion,
        signal: ctx.signal,
      });
      if (!resolved.ok) {
        result.error = resolved.error;
        ui.fail(`Cannot apply ${label}`, resolved.error);
        ui.info(ui.formatDimLines([...resolved.fix, ...resolved.links]));
        logApply(false, resolved.error);
        return result;
      }
      invocation = resolved.invocation;
    }
  }
  if (action.kind === 'override-transitive') {
    const pkgJson = (await readJsonIfExists<PackageJson>(pkgJsonPath)) ?? {};
    const conflict = manager === 'npm' ? overrideConflict(pkgJson, action) : await managerOverrideConflict(manager, root, pkgJson, action, managerMajor(invocation));
    if (conflict) {
      result.error = conflict;
      ui.fail(`Cannot apply ${label}`, conflict);
      logApply(false, conflict);
      return result;
    }
  }
  const patches = approvedPatches(action, approval);
  // pnpm workspace yaml, yarn-error.log
  const managerFiles = manager === 'pnpm' ? ['pnpm-workspace.yaml'] : manager === 'yarn' ? ['yarn-error.log'] : [];
  const files = ['package.json', lockRel, ...managerFiles, ...patches.map((p) => p.file)];
  const snapshot = await takeSnapshot(root, files);
  let backup = ctx.backup ?? null;
  const ownBackup = backup === null;
  if (!backup) backup = await createBackup(config, files, [action.id], audit);
  const runner = ctx.runCommand ?? run;
  const fns = fnsOf(ctx);

  const fail = async (message: string): Promise<ApplyResult> => {
    let restored: string[] = [];
    try {
      restored = await restoreSnapshot(snapshot);
      result.rolledBack = true;
    } catch (err) {
      message = `${message}; restoring the files also failed (${errorMessage(err)}): run patch-pilot rollback`;
    }
    result.error = message;
    result.after = null;
    result.filesChanged = [];
    audit.log({ event: 'rollback', backupId: backup.id, restored, mismatched: [], reason: message });
    logApply(false, message);
    ui.fail(`Could not apply ${label}`, message);
    if (result.rolledBack) ui.info(ui.formatDimLines([`Rolled back: ${restored.length > 0 ? restored.join(', ') : 'nothing had changed'}`]));
    return result;
  };

  try {
    const before = await loadDependencyGraph(root, lockAbs);
    if (manager === 'npm') {
      if (action.kind === 'override-transitive') {
        const overrides = await writeOverride(pkgJsonPath, action);
        ui.check('Added a parent-scoped override', Object.keys(overrideEntries(action)).map((p) => `${p} > ${action.package} ${action.toVersion}`).join(', '));
        ui.debug(`overrides: ${JSON.stringify(overrides)}`);
      }
      const args = npmArgsFor(action, { alias: directAlias(action, before) });
      result.command = ['npm', ...args];
      const spinner = ui.spinner(`Running npm ${args.join(' ')}...`);
      let res: RunResult;
      try {
        res = await runNpm(runner, args, root, NPM_TIMEOUT_MS, ctx.signal);
      } finally {
        spinner.stop();
      }
      if (res.ok && action.kind === 'override-transitive' && action.parents.some((p) => p.acceptsTarget)) {
        res = await runNpm(runner, ['update', action.package, '--package-lock-only', '--ignore-scripts'], root, NPM_TIMEOUT_MS, ctx.signal);
      }
      if (!res.ok) return await fail(npmFailure(res));
    } else {
      const changed = await changeWithManager(action, ctx, invocation as ManagerInvocation, before, lockAbs, result);
      if (!changed.ok) return await fail(changed.error);
    }

    const after = await loadDependencyGraph(root, lockAbs);
    const diff = diffLockfiles(before, after, action);
    result.lockfileDiff = diff;
    let decision: 'clean' | 'confirmed' | 'aborted' = 'clean';
    if (diff.unexpected.length > 0) {
      ui.warn(`The lockfile changed outside ${action.package}'s dependency subtree`, plural(diff.unexpected.length, 'unexpected change'));
      ui.info(renderLockfileChanges(diff.unexpected, ui));
      decision = interactiveOk(ctx) && (await confirmWith(ctx, 'Keep these lockfile changes?')) ? 'confirmed' : 'aborted';
    }
    const count = (kind: LockfileNodeChange['change']): number => diff.changes.filter((c) => c.change === kind && !c.key.startsWith('package.json ')).length;
    audit.log({
      event: 'lockfile.diff',
      actionId: action.id,
      added: count('added'),
      removed: count('removed'),
      changed: count('changed'),
      unexpected: diff.unexpected.map((c) => c.key),
      decision,
    });
    if (decision === 'aborted') {
      return await fail(`unexpected lockfile changes (${diff.unexpected.map((c) => c.key).join(', ')})${interactiveOk(ctx) ? ' were rejected' : ' need a confirmation in a terminal'}`);
    }

    const codeFiles: { path: string; beforeHash: string; afterHash: string }[] = [];
    const syntaxOk = new Map<string, boolean | null>();
    if (patches.length > 0) {
      for (const patch of patches) {
        const current = await hashOf(resolveInside(root, patch.file));
        if (current !== patch.beforeHash) return await fail(`${patch.file} changed after the diff was shown; nothing was edited`);
      }
      let written: { file: string; beforeHash: string; afterHash: string }[];
      try {
        written = await fns.writePatches(patches, root);
      } catch (err) {
        return await fail(`a code edit could not be applied (${errorMessage(err)})`);
      }
      let syntax: { file: string; ok: boolean; error?: string }[] = [];
      try {
        syntax = await fns.checkSyntax(written.map((w) => w.file), root);
      } catch (err) {
        return await fail(`node --check could not run (${errorMessage(err)})`);
      }
      for (const w of written) {
        const check = syntax.find((s) => s.file === w.file);
        syntaxOk.set(w.file, check ? check.ok : null);
        audit.log({ event: 'codemod.applied', package: action.package, file: w.file, beforeHash: w.beforeHash, afterHash: w.afterHash, syntaxOk: check ? check.ok : null });
        codeFiles.push({ path: w.file, beforeHash: w.beforeHash, afterHash: w.afterHash });
      }
      const bad = syntax.filter((s) => !s.ok);
      if (bad.length > 0) return await fail(`node --check failed for ${bad.map((b) => b.file).join(', ')}${bad[0]?.error ? `: ${bad[0].error}` : ''}`);
    }

    result.verify = verifyAction(action, after, ctx.caseFile);
    for (const v of result.verify) {
      audit.log({ event: 'verify.result', vulnId: v.vulnId, package: v.package, cleared: v.cleared, versions: unique(v.nodes.map((n) => n.version)) });
    }
    const afterVersions = versionsOf(after, action.package);
    result.after = afterVersions.length > 0 ? afterVersions.join(', ') : null;
    for (const rel of ['package.json', lockRel]) {
      const beforeHash = snapshotHash(snapshot, rel);
      const afterHash = await hashOf(path.join(root, ...rel.split('/')));
      if (beforeHash && afterHash && beforeHash !== afterHash) result.filesChanged.push({ path: rel, beforeHash, afterHash });
    }
    if (manager === 'pnpm') {
      // may be new, no before hash
      const beforeHash = snapshotHash(snapshot, 'pnpm-workspace.yaml') ?? '';
      const afterHash = await hashOf(path.join(root, 'pnpm-workspace.yaml'));
      if (afterHash && beforeHash !== afterHash) result.filesChanged.push({ path: 'pnpm-workspace.yaml', beforeHash, afterHash });
    }
    result.filesChanged.push(...codeFiles);
    result.ok = true;
    logApply(true);

    const arrow = ui.glyphs.arrow;
    if (action.kind === 'bump' || action.kind === 'bump-major') {
      const spec = after.root[action.direct?.depType ?? 'dependencies']?.[action.package];
      ui.check(`Bumped ${action.package} to ${action.toVersion}`, `${action.fromVersion} ${arrow} ${action.toVersion}${spec ? ` ${ui.glyphs.dot} package.json "${spec}"` : ''}`);
    } else if (action.kind === 'update-transitive') {
      ui.check(`Updated ${action.package} to ${result.after ?? action.toVersion}`, `inside ${unique(action.parents.map((p) => `${p.name} ${p.range}`)).join(', ') || 'its parent ranges'}`);
    } else {
      ui.check(`Overrode ${action.package} to ${result.after ?? action.toVersion}`, `scoped to ${Object.keys(overrideEntries(action)).join(', ')}`);
      ui.warn(`${Object.keys(overrideEntries(action)).join(', ')} ${Object.keys(overrideEntries(action)).length === 1 ? 'was' : 'were'} not tested with ${action.package}@${action.toVersion}`, 'run the test suite after syncing node_modules');
    }
    ui.check(`Regenerated ${path.posix.basename(lockRel)}`, `${plural(diff.allowed.filter((c) => !c.key.startsWith('package.json ')).length, 'node')} changed${decision === 'confirmed' ? `, ${plural(diff.unexpected.length, 'confirmed change')}` : ''}`);
    if (manager !== 'npm' && after.lockfileVersion !== before.lockfileVersion) {
      ui.warn(`${MANAGER_NAMES[manager]} rewrote ${path.posix.basename(lockRel)} in its own format`, `lockfile version ${before.lockfileVersion} ${arrow} ${after.lockfileVersion}`);
    }
    for (const f of codeFiles) {
      const ok = syntaxOk.get(f.path);
      ui.check(`Updated ${f.path}`, ok === true ? 'node --check passed' : ok === false ? 'node --check failed' : 'not a JavaScript file: no syntax check');
    }
    const cleared = result.verify.filter((v) => v.cleared);
    const open = result.verify.filter((v) => !v.cleared);
    if (cleared.length > 0) ui.check(`Verified ${plural(cleared.length, 'CVE')} cleared`, cleared.map((v) => v.vulnId).join(', '));
    for (const v of open) {
      const still = v.nodes.filter((n) => n.affected).map((n) => `${n.key} (${n.version})`);
      ui.warn(`${v.vulnId} still affects ${action.package}`, still.join(', ') || 'no verifiable range');
    }
    ui.check(`Audit logged to ${relativePosix(root, config.paths.auditLog)}`);
    return result;
  } catch (err) {
    if (isPromptCancelled(err)) {
      await restoreSnapshot(snapshot).catch(() => []);
      throw err;
    }
    return await fail(errorMessage(err));
  } finally {
    if (ownBackup) await finalizeBackup(backup).catch(() => {});
  }
}

interface PostContext {
  config: Config;
  ui: Ui;
  audit: AuditSink;
  identity: Identity;
  prompt?: PromptAdapter;
  runCommand?: CommandRunner;
  signal?: AbortSignal;
  // npm when absent
  invocation?: ManagerInvocation | null;
}

function tail(text: string, lines: number): string[] {
  return text
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.trim() !== '')
    .slice(-lines);
}

async function postCommand(ctx: PostContext, id: string, question: string, args: string[]): Promise<RunResult | null> {
  const { config, ui, audit, identity } = ctx;
  const invocation = ctx.invocation ?? npmManagerInvocation();
  const shown = [...invocation.display, ...args];
  const approved = await confirmWith(ctx, question);
  const record: ApprovalRecord = {
    actionId: id,
    package: '*',
    decision: approved ? 'approve' : 'reject',
    mode: 'interactive',
    scope: 'bump',
    by: identity,
    at: new Date().toISOString(),
    reason: shown.join(' '),
  };
  logApproval(audit, { kind: 'bump' }, record);
  if (!approved) return null;
  const spinner = ui.spinner(`Running ${shown.join(' ')}...`);
  const res = await runManager(ctx.runCommand ?? run, invocation, args, config.projectRoot, POST_TIMEOUT_MS, ctx.signal);
  spinner.stop();
  audit.log({
    event: 'patch.apply',
    actionId: id,
    package: '*',
    kind: 'bump',
    before: '',
    after: null,
    command: shown,
    files: [],
    ok: res.ok,
    ...(res.ok ? {} : { error: managerFailure(invocation.manager, res) }),
  });
  return res;
}

// sync node_modules, then tests
export async function offerPostCommands(ctx: PostContext): Promise<{ synced: boolean; tests: boolean | null }> {
  const { config, ui } = ctx;
  const invocation = ctx.invocation ?? npmManagerInvocation();
  const manager = invocation.manager;
  const bin = MANAGER_BINARY[manager];
  const tool = invocation.display.join(' ');
  const installArgs = postInstallArgs(manager);
  const installText = `${tool} ${installArgs.join(' ')}${manager === 'yarn-berry' ? ' (scripts off)' : ''}`;
  const rebuild = manager === 'yarn' ? 'npm rebuild' : `${bin} rebuild`;
  const testArgs = manager === 'npm' ? ['test', '--ignore-scripts'] : ['test'];
  if (!canPrompt(config, ui, ctx.prompt)) {
    ui.infoLine('node_modules still holds the old versions', `sync it with: ${installText}`);
    return { synced: false, tests: null };
  }
  ui.info('');
  const install = await postCommand(ctx, `post:${bin}-install`, `Sync node_modules now with ${installText}?`, installArgs);
  if (!install) {
    ui.infoLine('node_modules still holds the old versions', `sync it later with: ${installText}`);
    return { synced: false, tests: null };
  }
  if (!install.ok) {
    ui.fail(`${bin} install failed`, managerFailure(manager, install));
    return { synced: false, tests: null };
  }
  ui.check('Synced node_modules', `${installText} (install scripts skipped; run ${rebuild} if a package needs its build step)`);
  const pkg = await readJsonIfExists<PackageJson>(path.join(config.projectRoot, 'package.json')).catch(() => null);
  const script = pkg?.scripts?.test;
  if (typeof script !== 'string' || script.trim() === '' || /no test specified/i.test(script)) return { synced: true, tests: null };
  const tests = await postCommand(ctx, `post:${bin}-test`, `Run the test suite with ${tool} test?`, testArgs);
  if (!tests) return { synced: true, tests: null };
  if (tests.ok) ui.check('Tests passed', `${tool} test ${ui.glyphs.dot} ${script}`);
  else {
    ui.fail('Tests failed', `${tool} test exited with code ${tests.code ?? 'unknown'}`);
    const out = tail(`${tests.stdout}\n${tests.stderr}`, 12);
    if (out.length > 0) ui.errorBlock(ui.formatDimLines(out, 2, ui.ce));
    ui.info(ui.formatDimLines(['Roll the changes back with: patch-pilot rollback']));
  }
  return { synced: true, tests: tests.ok };
}

// so the .gitignore offer runs once
export function stateDirExists(dir: string | undefined, cwd: string = process.cwd()): boolean {
  return existsSync(path.join(path.resolve(cwd, dir ?? '.'), '.patch-pilot'));
}

// warn and go on without it
export function openStateDb(config: Config, ui: Ui): PatchPilotDb | null {
  try {
    return openDb(config.paths.dbFile);
  } catch (err) {
    ui.warn('The local cache is unavailable, continuing without it', errorMessage(err));
    return null;
  }
}

// tty only
export async function offerGitignore(config: Config, ui: Ui, options: { prompt?: PromptAdapter; runCommand?: CommandRunner } = {}): Promise<boolean> {
  if (!canPrompt(config, ui, options.prompt)) return false;
  const root = config.projectRoot;
  const file = path.join(root, '.gitignore');
  const text = await readFile(file, 'utf8').catch(() => null);
  const check = await (options.runCommand ?? run)('git', ['check-ignore', '-q', '.patch-pilot/audit.jsonl'], { cwd: root, timeoutMs: 5_000 });
  if (check.code === 0) return false; // maybe by a parent .gitignore
  const inRepo = check.code === 1;
  if (text === null && !inRepo) return false;
  if (text !== null && /^\s*\/?\.patch-pilot\/?\s*$/m.test(text)) return false;
  const prompt = options.prompt ?? defaultPromptAdapter(ui);
  const yes = await prompt.confirm('Add .patch-pilot/ (PatchPilot state and backups) to .gitignore?', true);
  if (!yes) return false;
  const eol = text ? detectEol(text) : '\n';
  const lead = text && text.length > 0 && !text.endsWith('\n') ? eol : '';
  await appendFile(file, `${lead}.patch-pilot/${eol}`, 'utf8');
  ui.check('Added .patch-pilot/ to .gitignore');
  return true;
}

// cleared cves left out
export function remainingVerdicts(assessment: Assessment, phase3: Phase3Result | null): Verdict[] {
  const cleared = new Set((phase3?.results ?? []).filter((r) => r.ok).flatMap((r) => r.verify.filter((v) => v.cleared).map((v) => `${v.vulnId}|${v.package}`)));
  return assessment.verdicts.filter((v) => !cleared.has(`${v.vulnId}|${v.package}`));
}

function doneText(result: Phase3Result, assessment: Assessment, config: Config): string {
  const applied = result.results.filter((r) => r.ok);
  const failed = result.results.filter((r) => !r.ok && r.rolledBack);
  const sourceFiles = unique(
    applied.flatMap((r) => r.filesChanged.map((f) => f.path)).filter((p) => p !== 'package.json' && !/(package-lock|npm-shrinkwrap)\.json$|(^|\/)(yarn\.lock|pnpm-lock\.yaml|pnpm-workspace\.yaml)$/.test(p)),
  );
  const open = remainingVerdicts(assessment, result);
  const now = new Date();
  const accepted = open.filter((v) => {
    const hit = findIgnore(config.ignore, v.vulnId, v.package, [], now);
    return hit !== null && !hit.expired;
  });
  const parts = [
    `${plural(applied.length, 'patch', 'patches')} applied`,
    `${plural(sourceFiles.length, 'source file')} updated`,
    `${open.length - accepted.length} deferred`,
  ];
  if (accepted.length > 0) parts.push(`${accepted.length} accepted`);
  if (failed.length > 0) parts.push(`${failed.length} failed and rolled back`);
  return `Done. ${parts.join(', ')}.`;
}

// present, plan, gate, apply, report
export async function runPhase3(caseFile: CaseFile, assessment: Assessment, config: Config, deps: Phase3Deps): Promise<Phase3Result> {
  const { ui, audit } = deps;
  const identity = deps.identity ?? (await captureIdentity(config.projectRoot));
  const result: Phase3Result = { exitCode: EXIT.OK, actions: [], approvals: [], results: [], reports: null };
  const ownDb = deps.db === undefined;
  const db = ownDb ? openStateDb(config, ui) : (deps.db ?? null);
  const root = config.projectRoot;
  const reportRel = (): string => relativePosix(root, config.paths.reportMd);
  const finish = async (): Promise<void> => {
    ui.status.set({ activity: 'Writing the reports' });
    try {
      result.reports = await writeReports(config, { ui, audit, phase3: result, caseFile, assessment });
    } catch (err) {
      ui.warn('Could not write the reports', errorMessage(err));
    }
  };
  try {
    if (assessment.caseFileHash !== caseFileHash(caseFile)) {
      ui.warn('The saved assessment was made from an older case file', 'run patch-pilot investigate for fresh verdicts');
    }
    assessment = alignAssessment(caseFile, assessment, config.ignore);
    presentFindings(assessment, caseFile, config, ui, { cards: deps.showCards ?? true });
    ui.status.set({ activity: 'Planning the fixes' });
    const lockRel = lockfileRelPath(caseFile, config);
    let graph: DependencyGraph;
    try {
      graph = await loadDependencyGraph(root, path.join(root, ...lockRel.split('/')));
    } catch (err) {
      throw new EnvironmentError(`Cannot read the lockfile for Phase 3: ${errorMessage(err)}`, { hint: 'Run patch-pilot scan again.', cause: err });
    }
    const stale = stalePackages(caseFile, graph).filter((p) => assessment.verdicts.some((v) => v.package === p.name && v.installedVersion === p.version));
    if (stale.length > 0) {
      ui.warn(
        `The lockfile changed since the scan: ${stale.map((p) => `${p.name}@${p.version}`).join(', ')} ${stale.length === 1 ? 'is' : 'are'} no longer installed`,
        'run patch-pilot scan again to re-check them',
      );
    }
    const manager = managerOf(graph);
    // pnpm lockfiles lack ranges
    if (manager === 'pnpm') await refineParentRanges(graph, caseFile, config, db, deps.signal);
    const planned = planActions(caseFile, assessment, graph, config);
    await attachEngines(planned, config, db, deps.signal);
    const stopEarly = config.dryRun || config.ci;
    const ctx: PatchContext = { ...deps, config, caseFile, graph, identity, db, assessment, backup: null };
    const actions = stopEarly ? planned : await prepareTransactions(planned, ctx);
    result.actions = actions;
    presentActions(actions, ui, { caseFile, assessment, config, researched: !stopEarly });

    if (stopEarly) {
      await finish();
      // summary prints under the output
      ui.status.stop();
      ui.info('');
      ui.infoLine(config.ci ? 'CI mode: nothing was changed' : 'Dry run: nothing was changed', result.reports ? `report: ${reportRel()}` : undefined);
      return result;
    }
    if (actions.length === 0) {
      await finish();
      ui.status.stop();
      ui.doneLine('Done. Nothing to patch.', result.reports ? reportRel() : undefined);
      return result;
    }
    if (isScratchLockfile(lockRel)) {
      ui.warn('PatchPilot scanned a scratch lockfile (.patch-pilot/tmp), so there is no project lockfile to patch', 'create one with: npm install --package-lock-only --ignore-scripts');
      await finish();
      return result;
    }
    const preflight = await checkPatchPreflight(config, graph, deps.runCommand ?? run);
    if (preflight.dirtyTree) ui.warn('The git working tree has uncommitted changes', 'commit or stash them first so the PatchPilot changes are easy to review');
    if (preflight.refuse) {
      ui.fail('Applying is refused', preflight.refuse);
      result.exitCode = EXIT.USAGE;
      await finish();
      return result;
    }
    let invocation: ManagerInvocation | null = null;
    if (manager !== 'npm') {
      const pkgJson = await readJsonIfExists<PackageJson>(path.join(root, 'package.json')).catch(() => null);
      const resolved = await resolveManager(manager, root, deps.runCommand ?? run, {
        packageManagerField: typeof pkgJson?.packageManager === 'string' ? pkgJson.packageManager : null,
        lockfileVersion: graph.lockfileVersion,
        signal: deps.signal,
      });
      if (!resolved.ok) {
        ui.fail(`Cannot apply fixes with ${MANAGER_NAMES[manager]}`, resolved.error);
        ui.info(ui.formatDimLines([...resolved.fix, ...resolved.links]));
        result.exitCode = EXIT.ENVIRONMENT;
        await finish();
        return result;
      }
      invocation = resolved.invocation;
      ctx.manager = invocation;
      ui.check(`Package manager ${MANAGER_NAMES[manager]}`, describeInvocation(invocation));
      for (const note of resolved.notes) ui.infoLine(note);
    }
    const confirmations: string[] = [];
    if (preflight.lockfileVersion === 1 && manager === 'npm') confirmations.push('The lockfile is version 1 and npm 11 rewrites it to version 3 when it changes it. Continue?');
    const pnpmMajor = managerMajor(invocation);
    if (manager === 'pnpm' && graph.lockfileVersion < 9 && pnpmMajor !== null && pnpmMajor >= 9) {
      confirmations.push(`pnpm-lock.yaml is lockfile version ${graph.lockfileVersion} and pnpm ${invocation?.version ?? pnpmMajor} rewrites it as version 9 when it changes it. Continue?`);
    }
    if (preflight.workspaces) confirmations.push(`This project uses ${MANAGER_NAMES[manager]} workspaces; PatchPilot treats the workspace packages as part of the project. Continue?`);
    for (const question of confirmations) {
      if (!canPrompt(config, ui, deps.prompt)) {
        ui.fail('Nothing was applied', `${question.replace(/ Continue\?$/, '')} This needs a confirmation in a terminal.`);
        result.exitCode = EXIT.USAGE;
        await finish();
        return result;
      }
      if (!(await confirmWith(ctx, question))) {
        ui.infoLine('Nothing was applied');
        await finish();
        return result;
      }
    }

    const backupFiles = unique(['package.json', lockRel, ...(manager === 'pnpm' ? ['pnpm-workspace.yaml'] : []), ...actions.flatMap(transactionFiles)]);
    const appliedIds: string[] = [];
    const gate = { activity: 'Approval gate', detail: plural(actions.length, 'planned fix', 'planned fixes') };
    ui.status.set(gate);
    try {
      result.approvals = await runApprovalGate(actions, {
        config,
        ui,
        audit,
        identity,
        prompt: deps.prompt,
        caseFile,
        assessment,
        details: { graph, manager, invocation },
        migration: fnsOf(deps),
        onDecision: async (action, record) => {
          if (record.decision !== 'approve') return;
          if (!ctx.backup) ctx.backup = await createBackup(config, backupFiles, [action.id], audit);
          appliedIds.push(action.id);
          const index = actions.findIndex((a) => a.id === action.id);
          ui.status.set({ activity: `Applying ${index + 1} of ${actions.length}: ${action.package} ${action.fromVersion} ${ui.glyphs.arrow} ${action.toVersion}` });
          const applied = await applyAction(action, record, ctx);
          ui.status.set(gate);
          result.results.push(applied);
        },
      });
    } finally {
      // record hashes on ctrl+c too
      if (ctx.backup) await finalizeBackup(ctx.backup, appliedIds).catch(() => {});
    }
    if (result.results.some((r) => r.ok)) {
      // bar shows the running command
      ui.status.set({});
      await offerPostCommands({ config, ui, audit, identity, prompt: deps.prompt, runCommand: deps.runCommand, signal: deps.signal, invocation });
    }
    result.exitCode = result.results.some((r) => !r.ok && r.rolledBack) ? EXIT.PATCH_FAILED : EXIT.OK;
    await finish();
    ui.status.stop();
    ui.doneLine(doneText(result, assessment, config), result.reports ? reportRel() : undefined);
    if (ctx.backup) ui.info(ui.formatDimLines([`Backup: ${relativePosix(root, ctx.backup.dir)} ${ui.glyphs.dot} undo with: patch-pilot rollback`], 0));
    return result;
  } finally {
    if (ownDb) db?.close();
  }
}

