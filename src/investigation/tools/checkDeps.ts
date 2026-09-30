// check_deps, from the lockfile graph
import type { DependencyGraph, PackageCase, PackageNode, ToolContext, ToolResult, VulnCase } from '../../types.ts';
import { compareVersions, satisfiesRange } from '../../util/semver.ts';

export interface CheckDepsArgs {
  package: string;
}

interface DependentInfo {
  name: string;
  version: string;
  range?: string;
  acceptsFix?: boolean;
  dev?: boolean;
}

export interface CheckDepsData {
  package: string;
  version: string;
  isDirect: boolean;
  isDevOnly: boolean;
  declared: { section: string; spec: string } | null;
  dependents: DependentInfo[];
  pathsFromRoot: string[];
  otherVersionsInstalled: string[];
  fixVersion: string | null;
  fixIsMajor: boolean | null;
  source: 'lockfile' | 'case-file';
}

const MAX_PATHS = 3;
const MAX_DEPTH = 10;
const MAX_DEPENDENTS = 12;

// highest fix across its cves
function packageFix(ctx: ToolContext, name: string, version: string): { version: string; majorBump: boolean } | null {
  const vulns: VulnCase[] = (ctx.caseFile?.vulnerabilities ?? []).filter((v) => v.package === name && (v.installedVersion === version || !version));
  const fixes = vulns.map((v) => v.recommendedFix).filter((f): f is NonNullable<VulnCase['recommendedFix']> => Boolean(f));
  if (fixes.length === 0) return null;
  const best = [...fixes].sort((a, b) => compareVersions(b.version, a.version))[0];
  return best ? { version: best.version, majorBump: fixes.some((f) => f.majorBump) } : null;
}

function nodeLabel(node: PackageNode | undefined, key: string): string {
  return node ? `${node.name}@${node.version}` : key;
}

// up to 3
export function pathsToRoot(graph: DependencyGraph, key: string, rootName: string): string[] {
  const results: string[] = [];
  const queue: string[][] = [[key]];
  while (queue.length > 0 && results.length < MAX_PATHS) {
    const chain = queue.shift() as string[];
    const head = chain[chain.length - 1] as string;
    const node = graph.nodes.get(head);
    const parents = node?.parents ?? [];
    if (parents.length === 0 || chain.length > MAX_DEPTH) continue;
    for (const parent of parents) {
      if (results.length >= MAX_PATHS) break;
      if (parent === '') {
        results.push([rootName, ...[...chain].reverse().map((k) => nodeLabel(graph.nodes.get(k), k))].join(' > '));
      } else if (!chain.includes(parent)) {
        queue.push([...chain, parent]);
      }
    }
  }
  return results;
}

function fromGraph(graph: DependencyGraph, name: string, nodes: PackageNode[], ctx: ToolContext): ToolResult {
  const focusVersion = ctx.focus?.package === name ? ctx.focus.version : undefined;
  const versions = [...new Set(nodes.map((n) => n.version))];
  const version = focusVersion && versions.includes(focusVersion) ? focusVersion : (versions.sort((a, b) => compareVersions(a, b))[0] as string);
  const primary = nodes.filter((n) => n.version === version);
  const isDirect = primary.some((n) => n.isDirect);
  const isDevOnly = primary.every((n) => n.dev);
  const root = graph.root;
  const declaredSection = root.dependencies[name] !== undefined
    ? 'dependencies'
    : root.devDependencies[name] !== undefined
      ? 'devDependencies'
      : root.optionalDependencies[name] !== undefined
        ? 'optionalDependencies'
        : root.peerDependencies[name] !== undefined
          ? 'peerDependencies'
          : null;
  const declaredSpec = declaredSection ? (root as unknown as Record<string, Record<string, string>>)[declaredSection]?.[name] : undefined;
  const fix = packageFix(ctx, name, version);
  const dependents: DependentInfo[] = [];
  const seen = new Set<string>();
  for (const node of primary) {
    for (const parentKey of node.parents) {
      if (parentKey === '' || seen.has(parentKey)) continue;
      seen.add(parentKey);
      const parent = graph.nodes.get(parentKey);
      if (!parent) continue;
      const range = parent.requires?.[name] ?? parent.requires?.[node.alias ?? name];
      const info: DependentInfo = { name: parent.name, version: parent.version };
      if (range) info.range = range;
      if (range && fix) info.acceptsFix = satisfiesRange(fix.version, range);
      if (parent.dev) info.dev = true;
      dependents.push(info);
    }
  }
  const rootName = root.name || 'project';
  const paths = primary.flatMap((n) => pathsToRoot(graph, n.key, rootName)).slice(0, MAX_PATHS);
  const data: CheckDepsData = {
    package: name,
    version,
    isDirect,
    isDevOnly,
    declared: declaredSection && declaredSpec ? { section: declaredSection, spec: declaredSpec } : null,
    dependents: dependents.slice(0, MAX_DEPENDENTS),
    pathsFromRoot: paths,
    otherVersionsInstalled: versions.filter((v) => v !== version),
    fixVersion: fix?.version ?? null,
    fixIsMajor: fix?.majorBump ?? null,
    source: 'lockfile',
  };
  return { ok: true, hint: summarize(data), data };
}

function fromCaseFile(name: string, cases: PackageCase[], ctx: ToolContext): ToolResult {
  const focusVersion = ctx.focus?.package === name ? ctx.focus.version : undefined;
  const pkg = cases.find((c) => c.version === focusVersion) ?? cases[0];
  if (!pkg) return { ok: false, error: `No dependency data for ${name}`, hint: 'Check the package name' };
  const fix = packageFix(ctx, name, pkg.version);
  const data: CheckDepsData = {
    package: name,
    version: pkg.version,
    isDirect: pkg.isDirect,
    isDevOnly: pkg.isDevOnly,
    declared: pkg.isDirect && pkg.spec ? { section: pkg.depType ?? 'dependencies', spec: pkg.spec } : null,
    dependents: (pkg.dependents ?? []).slice(0, MAX_DEPENDENTS).map((d) => ({ name: d.name, version: d.version })),
    pathsFromRoot: (pkg.dependencyPaths ?? []).slice(0, MAX_PATHS).map((p) => p.join(' > ')),
    otherVersionsInstalled: cases.filter((c) => c.version !== pkg.version).map((c) => c.version),
    fixVersion: fix?.version ?? null,
    fixIsMajor: fix?.majorBump ?? null,
    source: 'case-file',
  };
  return { ok: true, hint: summarize(data), data };
}

function summarize(d: CheckDepsData): string {
  const kind = `${d.isDirect ? 'direct' : 'transitive'} ${d.isDevOnly ? 'dev-only' : 'production'} dependency`;
  const declared = d.declared ? ` (${d.declared.section}: ${d.declared.spec})` : '';
  const deps = d.dependents.slice(0, 3).map((x) => `${x.name}@${x.version}${x.range ? ` (${x.range}${x.acceptsFix !== undefined && d.fixVersion ? `, ${x.acceptsFix ? 'accepts' : 'excludes'} ${d.fixVersion}` : ''})` : ''}`);
  const via = deps.length > 0 ? `${d.isDirect ? '; also required by' : ' via'} ${deps.join(', ')}${d.dependents.length > 3 ? `, ${d.dependents.length - 3} more` : ''}` : d.isDirect ? '; no other package depends on it' : '';
  const others = d.otherVersionsInstalled.length > 0 ? `; other installed versions: ${d.otherVersionsInstalled.join(', ')}` : '';
  return `${d.package}@${d.version}: ${kind}${declared}${via}${others}`;
}

export async function handleCheckDeps(args: CheckDepsArgs, ctx: ToolContext): Promise<ToolResult> {
  const name = String(args.package ?? '').trim();
  if (name === '') return { ok: false, error: 'package is required', hint: 'Give the npm package name, for example {"package": "lodash"}' };
  const graph = ctx.graph;
  if (graph) {
    const keys = graph.byName.get(name) ?? [];
    const nodes = keys.map((k) => graph.nodes.get(k)).filter((n): n is PackageNode => n !== undefined);
    if (nodes.length > 0) return fromGraph(graph, name, nodes, ctx);
  }
  const cases = (ctx.caseFile?.packages ?? []).filter((p) => p.name === name);
  if (cases.length > 0) return fromCaseFile(name, cases, ctx);
  if (graph) return { ok: false, error: `${name} is not installed (it is not in the lockfile)`, hint: 'Check the package name; only installed packages can be checked' };
  const known = (ctx.caseFile?.packages ?? []).map((p) => p.name);
  return {
    ok: false,
    error: `No dependency data for ${name}`,
    hint: known.length > 0 ? `Packages in the case file: ${[...new Set(known)].slice(0, 10).join(', ')}` : 'The lockfile graph is not loaded',
  };
}
