// npm here, yarn and pnpm in lockfiles/
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type { DependencyGraph, PackageJson, PackageManager, PackageNode, RootPackage } from '../types.ts';
import { expandWorkspaceGlobs } from './lockfiles/index.ts';
import { parsePnpmLockfile, pnpmStorePath, refinePnpmRanges } from './lockfiles/pnpm.ts';
import { parseYarnLockfile, yarnFlavor, type YarnWorkspace } from './lockfiles/yarn.ts';

// package-lock v1, v2 or v3
export interface LockfileJson {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  requires?: boolean;
  packages?: Record<string, Record<string, unknown>>;
  dependencies?: Record<string, Record<string, unknown>>;
  [key: string]: unknown;
}

type Entry = Record<string, unknown>;

const NM = 'node_modules/';

export async function readLockfile(file: string): Promise<LockfileJson> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read the lockfile ${file}: ${(err as Error).message}`, { cause: err });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch (err) {
    throw new Error(
      `The lockfile ${file} is not valid JSON (${(err as Error).message}). A merge conflict? Regenerate it with: npm install --package-lock-only --ignore-scripts`,
      { cause: err },
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`The lockfile ${file} does not contain a JSON object`);
  return parsed as LockfileJson;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function specMap(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
    else if (v && typeof v === 'object' && typeof (v as { version?: unknown }).version === 'string') out[k] = (v as { version: string }).version;
  }
  return out;
}

function enginesMap(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
  return Object.keys(out).length > 0 ? out : undefined;
}

// "node_modules/a/node_modules/@s/b" -> "@s/b", null outside node_modules
export function nameFromKey(key: string): string | null {
  const idx = key.lastIndexOf(NM);
  if (idx === -1) return null;
  if (idx > 0 && key[idx - 1] !== '/') return null;
  const rest = key.slice(idx + NM.length);
  if (rest === '') return null;
  return rest;
}

// skips "" and workspace folders
function isInstalledKey(key: string): boolean {
  return key.startsWith(NM) || key.includes(`/${NM}`);
}

// walk up nested node_modules
export function resolveEdge(packages: Record<string, unknown>, fromKey: string, name: string): string | null {
  let base = fromKey;
  for (let guard = 0; guard < 200; guard += 1) {
    const candidate = base === '' ? `${NM}${name}` : `${base}/${NM}${name}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (base === '') return null;
    const idx = base.lastIndexOf(`/${NM}`);
    if (idx !== -1) {
      base = base.slice(0, idx);
      continue;
    }
    // top-level or workspace: root next
    base = '';
  }
  return null;
}

// "npm:bar@^1.2.0" -> { name: "bar", version: "^1.2.0" }
function parseNpmAlias(value: string): { name: string; version: string } | null {
  if (!value.startsWith('npm:')) return null;
  const rest = value.slice(4);
  const at = rest.lastIndexOf('@');
  if (at <= 0) return { name: rest, version: '' };
  return { name: rest.slice(0, at), version: rest.slice(at + 1) };
}

// v1 tree to v2 packages map
function packagesFromV1(lock: LockfileJson, rootPackage?: PackageJson): Record<string, Entry> {
  const packages: Record<string, Entry> = {};
  const root: Entry = { name: lock.name ?? rootPackage?.name, version: lock.version ?? rootPackage?.version };
  if (rootPackage) {
    root.dependencies = rootPackage.dependencies ?? {};
    root.devDependencies = rootPackage.devDependencies ?? {};
    root.optionalDependencies = rootPackage.optionalDependencies ?? {};
    root.peerDependencies = rootPackage.peerDependencies ?? {};
  }
  packages[''] = root;
  const visit = (deps: Record<string, Record<string, unknown>> | undefined, prefix: string): void => {
    if (!deps || typeof deps !== 'object') return;
    for (const [folder, raw] of Object.entries(deps)) {
      if (!raw || typeof raw !== 'object') continue;
      const key = `${prefix}${NM}${folder}`;
      const entry: Entry = {};
      const version = str(raw.version) ?? '';
      const alias = parseNpmAlias(version);
      if (alias) {
        entry.name = alias.name;
        entry.version = alias.version;
      } else if (/^(?:file:|link:)/.test(version)) {
        entry.version = version;
        if (version.startsWith('link:')) {
          entry.link = true;
          entry.resolved = version.slice(5);
        }
      } else {
        entry.version = version;
      }
      for (const field of ['resolved', 'integrity', 'dev', 'optional', 'bundled', 'license']) {
        if (raw[field] !== undefined && entry[field] === undefined) entry[field] = raw[field];
      }
      entry.dependencies = specMap(raw.requires);
      packages[key] = entry;
      visit(raw.dependencies as Record<string, Record<string, unknown>> | undefined, `${key}/`);
    }
  };
  visit(lock.dependencies, '');
  if (!rootPackage) {
    // no package.json: unrequired top-level is direct
    const required = new Set<string>();
    for (const [key, entry] of Object.entries(packages)) {
      if (key === '') continue;
      for (const name of Object.keys(specMap(entry.dependencies))) {
        const target = resolveEdge(packages, key, name);
        if (target) required.add(target);
      }
    }
    const direct: Record<string, string> = {};
    const directDev: Record<string, string> = {};
    for (const [key, entry] of Object.entries(packages)) {
      if (key === '' || key.slice(NM.length).includes(`/${NM}`) || !key.startsWith(NM) || required.has(key)) continue;
      const folder = key.slice(NM.length);
      (entry.dev === true ? directDev : direct)[folder] = str(entry.version) ?? '*';
    }
    root.dependencies = direct;
    root.devDependencies = directDev;
  }
  return packages;
}

function workspacesOf(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  if (value && typeof value === 'object' && Array.isArray((value as { packages?: unknown }).packages)) {
    return ((value as { packages: unknown[] }).packages).filter((v): v is string => typeof v === 'string');
  }
  return [];
}

// package.json gives root specs
export function parseLockfile(lock: LockfileJson, rootPackage?: PackageJson): DependencyGraph {
  const lockfileVersion = typeof lock.lockfileVersion === 'number' ? lock.lockfileVersion : 1;
  const hasPackages = lock.packages && typeof lock.packages === 'object' && Object.keys(lock.packages).length > 0;
  const packages: Record<string, Entry> = hasPackages ? { ...(lock.packages as Record<string, Entry>) } : packagesFromV1(lock, rootPackage);
  const rootEntry: Entry = packages[''] ?? {};

  const pick = (field: 'dependencies' | 'devDependencies' | 'optionalDependencies' | 'peerDependencies'): Record<string, string> => {
    const fromPkg = rootPackage?.[field];
    if (fromPkg && typeof fromPkg === 'object') return { ...specMap(fromPkg) };
    return specMap(rootEntry[field]);
  };
  const root: RootPackage = {
    name: str(rootPackage?.name) ?? str(rootEntry.name) ?? str(lock.name) ?? '',
    version: str(rootPackage?.version) ?? str(rootEntry.version) ?? str(lock.version) ?? null,
    dependencies: pick('dependencies'),
    devDependencies: pick('devDependencies'),
    optionalDependencies: pick('optionalDependencies'),
    peerDependencies: pick('peerDependencies'),
    workspaces: workspacesOf(rootPackage?.workspaces ?? rootEntry.workspaces),
    engines: enginesMap(rootPackage?.engines) ?? enginesMap(rootEntry.engines) ?? {},
    edges: {},
  };

  const nodes = new Map<string, PackageNode>();
  const byName = new Map<string, string[]>();
  const workspaceKeys: string[] = [];
  // link entry key -> target key
  const links = new Map<string, string>();
  // first-party folders
  const folders: string[] = [];

  for (const [key, entry] of Object.entries(packages)) {
    if (key === '' || !entry || typeof entry !== 'object') continue;
    if (entry.link === true) {
      workspaceKeys.push(key);
      const resolved = str(entry.resolved);
      if (resolved) links.set(key, path.posix.normalize(resolved.replace(/\\/g, '/')).replace(/^\.\//, ''));
      continue;
    }
    if (!isInstalledKey(key)) {
      folders.push(key);
      continue;
    }
    const folderName = nameFromKey(key);
    if (!folderName) continue;
    const declaredName = str(entry.name);
    const name = declaredName && declaredName !== folderName ? declaredName : folderName;
    const node: PackageNode = {
      key,
      name,
      version: str(entry.version) ?? '',
      dev: entry.dev === true,
      optional: entry.optional === true,
      devOptional: entry.devOptional === true,
      peer: entry.peer === true,
      bundled: entry.inBundle === true || entry.bundled === true,
      isDirect: false,
      parents: [],
      requires: { ...specMap(entry.peerDependencies), ...specMap(entry.optionalDependencies), ...specMap(entry.dependencies) },
      edges: {},
    };
    if (name !== folderName) node.alias = folderName;
    const resolved = str(entry.resolved);
    if (resolved) node.resolved = resolved;
    const integrity = str(entry.integrity);
    if (integrity) node.integrity = integrity;
    const license = str(entry.license);
    if (license) node.license = license;
    const engines = enginesMap(entry.engines);
    if (engines) node.engines = engines;
    const deprecated = str(entry.deprecated);
    if (deprecated) node.deprecated = deprecated;
    if (entry.hasInstallScript === true) node.hasInstallScript = true;
    nodes.set(key, node);
    const list = byName.get(name);
    if (list) list.push(key);
    else byName.set(name, [key]);
  }

  // follows links
  const resolveFrom = (fromKey: string, dep: string): string | null => {
    const hit = resolveEdge(packages, fromKey, dep);
    if (hit === null) return null;
    return links.get(hit) ?? hit;
  };
  const addParent = (target: string, parent: string): void => {
    const node = nodes.get(target);
    if (node && !node.parents.includes(parent)) node.parents.push(parent);
  };

  // root edges = direct deps
  const rootDeps = { ...root.peerDependencies, ...root.optionalDependencies, ...root.devDependencies, ...root.dependencies };
  for (const dep of Object.keys(rootDeps)) {
    const target = resolveFrom('', dep);
    if (!target) continue;
    root.edges[dep] = target;
    const node = nodes.get(target);
    if (node) node.isDirect = true;
    addParent(target, '');
  }
  // workspace folder deps count as direct
  for (const folder of folders) {
    const entry = packages[folder] ?? {};
    const deps = {
      ...specMap(entry.peerDependencies),
      ...specMap(entry.optionalDependencies),
      ...specMap(entry.devDependencies),
      ...specMap(entry.dependencies),
    };
    for (const dep of Object.keys(deps)) {
      const target = resolveFrom(folder, dep);
      if (!target) continue;
      const node = nodes.get(target);
      if (node) node.isDirect = true;
      addParent(target, folder);
    }
  }
  for (const node of nodes.values()) {
    for (const dep of Object.keys(node.requires)) {
      const target = resolveFrom(node.key, dep);
      if (!target || target === node.key) continue;
      node.edges[dep] = target;
      addParent(target, node.key);
    }
  }
  for (const node of nodes.values()) node.parents.sort((a, b) => (a === '' ? -1 : b === '' ? 1 : a < b ? -1 : a > b ? 1 : 0));
  return { root, lockfileVersion, nodes, byName, workspaceKeys };
}

// yarn 1 vs 2+ by content
export function lockfileManager(file: string, text?: string): PackageManager {
  const base = path.basename(file);
  if (base === 'pnpm-lock.yaml') return 'pnpm';
  if (base === 'yarn.lock') return text !== undefined && yarnFlavor(text) === 'berry' ? 'yarn-berry' : 'yarn';
  return 'npm';
}

async function readPackageJson(dir: string): Promise<PackageJson | undefined> {
  try {
    const parsed = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8')) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as PackageJson) : undefined;
  } catch {
    return undefined;
  }
}

// with their package.json
export async function loadYarnWorkspaces(projectRoot: string, rootPackage: PackageJson | undefined): Promise<YarnWorkspace[]> {
  const globs = workspacesOf(rootPackage?.workspaces);
  if (globs.length === 0) return [];
  const out: YarnWorkspace[] = [];
  for (const folder of await expandWorkspaceGlobs(projectRoot, globs)) {
    const pkg = await readPackageJson(path.join(projectRoot, ...folder.split('/')));
    if (pkg) out.push({ path: folder, pkg });
  }
  return out;
}

export async function loadDependencyGraph(projectRoot: string, lockfilePath: string): Promise<DependencyGraph> {
  const lockFile = path.isAbsolute(lockfilePath) ? lockfilePath : path.join(projectRoot, lockfilePath);
  const manager = lockfileManager(lockFile);
  if (manager !== 'npm') {
    let text: string;
    try {
      text = await readFile(lockFile, 'utf8');
    } catch (err) {
      throw new Error(`Cannot read the lockfile ${lockFile}: ${(err as Error).message}`, { cause: err });
    }
    const rootPackage = await readPackageJson(projectRoot);
    let graph: DependencyGraph;
    try {
      graph = manager === 'pnpm' ? parsePnpmLockfile(text, { rootPackage }) : parseYarnLockfile(text, { rootPackage, workspaces: await loadYarnWorkspaces(projectRoot, rootPackage) });
    } catch (err) {
      throw new Error(`Cannot parse the lockfile ${lockFile}: ${(err as Error).message}`, { cause: err });
    }
    // pnpm lock has no ranges, read manifests
    if (manager === 'pnpm' && (await stat(path.join(projectRoot, 'node_modules', '.pnpm')).then((s) => s.isDirectory(), () => false))) {
      await refinePnpmRanges(graph, projectRoot);
    }
    return graph;
  }
  const lock = await readLockfile(lockFile);
  let rootPackage: PackageJson | undefined;
  try {
    rootPackage = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8')) as PackageJson;
  } catch {
    rootPackage = undefined;
  }
  return parseLockfile(lock, rootPackage);
}

// yarn path is a hoisted guess
export function installedPath(graph: DependencyGraph, key: string): string | null {
  const node = graph.nodes.get(key);
  if (!node) return null;
  switch (graph.packageManager ?? 'npm') {
    case 'npm':
      return key;
    case 'pnpm':
      return pnpmStorePath(key, node.name);
    default:
      return `node_modules/${node.alias ?? node.name}`;
  }
}

function hop(graph: DependencyGraph, key: string): string {
  const node = graph.nodes.get(key);
  return node ? `${node.name}@${node.version}` : key;
}

// shortest first, name@version hops
export function dependencyPaths(graph: DependencyGraph, key: string, options: { maxPaths?: number; maxDepth?: number } = {}): string[][] {
  const maxPaths = options.maxPaths ?? 3;
  const maxDepth = options.maxDepth ?? 10;
  const start = graph.nodes.get(key);
  if (!start || maxPaths <= 0) return [];
  const results: string[][] = [];
  const expansions = new Map<string, number>();
  // bfs up, chain [key, parent, ...]
  let frontier: string[][] = [[key]];
  for (let depth = 0; depth < maxDepth && frontier.length > 0 && results.length < maxPaths; depth += 1) {
    const next: string[][] = [];
    for (const chain of frontier) {
      const current = chain[chain.length - 1] as string;
      const count = expansions.get(current) ?? 0;
      if (count >= maxPaths) continue;
      expansions.set(current, count + 1);
      const node = graph.nodes.get(current);
      for (const parent of node?.parents ?? []) {
        if (chain.includes(parent)) continue; // cycle
        if (parent === '' || !graph.nodes.has(parent)) {
          // root or workspace
          const hops = [...chain].reverse().map((k) => hop(graph, k));
          if (parent !== '') hops.unshift(parent);
          const text = hops.join(' > ');
          if (!results.some((r) => r.join(' > ') === text)) results.push(hops);
          if (results.length >= maxPaths) break;
          continue;
        }
        next.push([...chain, parent]);
      }
      if (results.length >= maxPaths) break;
    }
    frontier = next;
  }
  return results;
}

export function dependentsOf(graph: DependencyGraph, key: string): PackageNode[] {
  const node = graph.nodes.get(key);
  if (!node) return [];
  return node.parents.map((p) => graph.nodes.get(p)).filter((n): n is PackageNode => n !== undefined);
}

export function nodesByName(graph: DependencyGraph, name: string): PackageNode[] {
  return (graph.byName.get(name) ?? []).map((k) => graph.nodes.get(k)).filter((n): n is PackageNode => n !== undefined);
}

// for deps.parsed and the phase 1 line
export function graphCounts(graph: DependencyGraph): { total: number; direct: number; dev: number } {
  let direct = 0;
  let dev = 0;
  for (const node of graph.nodes.values()) {
    if (node.isDirect) direct += 1;
    if (node.dev) dev += 1;
  }
  return { total: graph.nodes.size, direct, dev };
}
