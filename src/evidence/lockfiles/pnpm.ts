// lockfile 9.x, 6.x, 5.x best effort
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { DependencyGraph, PackageJson, RootPackage } from '../../types.ts';
import { buildGraph, isTrue, normalizeFolder, splitAt, str, stringMap, type EdgeKind, type RawEdge, type RawImporter, type RawNode } from './index.ts';

export interface PnpmParseOptions {
  rootPackage?: PackageJson;
}

type Obj = Record<string, unknown>;

function obj(value: unknown): Obj {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Obj) : {};
}

// -> 9.x key form
export function normalizePnpmKey(raw: string, lockfileVersion: number): string {
  let key = raw.startsWith('/') ? raw.slice(1) : raw;
  if (lockfileVersion < 6) {
    const m = /^((?:@[^/]+\/)?[^/@]+)\/([^/]+)$/.exec(key);
    if (m) key = `${m[1]}@${m[2]}`;
  }
  return key;
}

export function splitPnpmKey(key: string, lockfileVersion = 9): { name: string; version: string; base: string } {
  const [name, rest] = splitAt(key);
  const paren = rest.indexOf('(');
  let version = paren === -1 ? rest : rest.slice(0, paren);
  if (lockfileVersion < 6) version = version.split('_')[0] ?? version;
  return { name, version, base: `${name}@${version}` };
}

function versionNumber(value: unknown): number {
  const n = Number.parseFloat(String(value ?? ''));
  return Number.isFinite(n) ? n : 0;
}

export function parsePnpmLockfile(text: string, options: PnpmParseOptions = {}): DependencyGraph {
  let doc: unknown;
  try {
    doc = parseYaml(text, { schema: 'failsafe' });
  } catch (err) {
    throw new Error(`pnpm-lock.yaml is not valid YAML (${(err as Error).message.split('\n')[0]}). A merge conflict? Regenerate it with: pnpm install --lockfile-only`, { cause: err });
  }
  const lock = obj(doc);
  const lockfileVersion = versionNumber(lock.lockfileVersion);
  if (lockfileVersion === 0) throw new Error('pnpm-lock.yaml has no lockfileVersion');
  const v9 = lockfileVersion >= 9;
  const packages = obj(lock.packages);
  const snapshots = obj(lock.snapshots);

  // per snapshot (9.x) or package (5.x, 6.x)
  const source = v9 ? snapshots : packages;
  const entries = new Map<string, { snapshot: Obj; meta: Obj }>();
  for (const [rawKey, value] of Object.entries(source)) {
    const key = normalizePnpmKey(rawKey, lockfileVersion);
    const snapshot = obj(value);
    const meta = v9 ? obj(packages[splitPnpmKey(key).base] ?? packages[key]) : snapshot;
    entries.set(key, { snapshot, meta });
  }

  const refToKey = (name: string, ref: string): string | null => {
    if (ref.startsWith('link:')) return null;
    const candidates: string[] = [];
    if (ref.startsWith('/')) candidates.push(normalizePnpmKey(ref, lockfileVersion));
    candidates.push(normalizePnpmKey(`${name}@${ref}`, lockfileVersion));
    if (lockfileVersion < 6) candidates.push(normalizePnpmKey(`/${name}/${ref}`, lockfileVersion));
    candidates.push(normalizePnpmKey(ref, lockfileVersion));
    return candidates.find((c) => entries.has(c)) ?? null;
  };

  const nodes: RawNode[] = [];
  for (const [key, { snapshot, meta }] of entries) {
    const parsed = splitPnpmKey(key, lockfileVersion);
    const name = str(meta.name) ?? parsed.name;
    const version = str(meta.version) ?? parsed.version;
    const peers = stringMap(meta.peerDependencies);
    const peerMeta = obj(meta.peerDependenciesMeta);
    const requires: Record<string, string> = {};
    const edges: RawEdge[] = [];
    const add = (deps: unknown, optional: boolean): void => {
      for (const [dep, ref] of Object.entries(stringMap(deps))) {
        const target = refToKey(dep, ref);
        const isPeer = peers[dep] !== undefined;
        const peerOptional = isPeer && isTrue(obj(peerMeta[dep]).optional);
        const kind: EdgeKind = isPeer ? (peerOptional || optional ? 'peerOptional' : 'peer') : optional ? 'optional' : 'prod';
        edges.push({ name: dep, target, kind });
        if (isPeer) continue;
        const resolved = target ? splitPnpmKey(target, lockfileVersion) : null;
        requires[dep] = resolved && resolved.name !== dep ? `npm:${resolved.name}@${resolved.version}` : (resolved?.version ?? ref);
      }
    };
    add(snapshot.dependencies, false);
    add(snapshot.optionalDependencies, true);
    for (const [peer, range] of Object.entries(peers)) requires[peer] = range;
    const raw: RawNode = { key, name, version, requires, edges };
    const resolution = obj(meta.resolution);
    const integrity = str(resolution.integrity);
    if (integrity) raw.integrity = integrity;
    const tarball = str(resolution.tarball) ?? str(resolution.repo);
    if (tarball) raw.resolved = tarball;
    const engines = stringMap(meta.engines);
    if (Object.keys(engines).length > 0) raw.engines = engines;
    const deprecated = str(meta.deprecated);
    if (deprecated) raw.deprecated = deprecated;
    if (isTrue(meta.requiresBuild)) raw.hasInstallScript = true;
    nodes.push(raw);
  }

  const importerDocs = new Map<string, Obj>();
  if (lock.importers && typeof lock.importers === 'object') {
    for (const [id, value] of Object.entries(obj(lock.importers))) importerDocs.set(normalizeFolder(id), obj(value));
  } else {
    importerDocs.set('', lock);
  }
  const importers: RawImporter[] = [];
  const rootSpecs: Record<'dependencies' | 'devDependencies' | 'optionalDependencies', Record<string, string>> = { dependencies: {}, devDependencies: {}, optionalDependencies: {} };
  for (const [folder, imp] of importerDocs) {
    const specifiers = stringMap(imp.specifiers);
    const edges: RawEdge[] = [];
    for (const [section, kind] of [['dependencies', 'prod'], ['devDependencies', 'dev'], ['optionalDependencies', 'optional']] as const) {
      for (const [dep, value] of Object.entries(obj(imp[section]))) {
        const entry = typeof value === 'string' ? { version: value, specifier: specifiers[dep] } : { version: str(obj(value).version), specifier: str(obj(value).specifier) ?? specifiers[dep] };
        const ref = entry.version ?? '';
        let target: string | null;
        if (ref.startsWith('link:')) target = normalizeFolder(path.posix.join(folder, ref.slice('link:'.length)));
        else target = refToKey(dep, ref);
        edges.push({ name: dep, target, kind });
        if (folder === '' && entry.specifier !== undefined) rootSpecs[section][dep] = entry.specifier;
      }
    }
    importers.push({ key: folder, edges });
  }
  importers.sort((a, b) => (a.key === '' ? -1 : b.key === '' ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  if (!importers.some((i) => i.key === '')) importers.unshift({ key: '', edges: [] });

  // single name every dependent uses
  const namesUsed = new Map<string, Set<string>>();
  for (const edges of [...importers.map((i) => i.edges), ...nodes.map((n) => n.edges)]) {
    for (const e of edges) {
      if (!e.target || !entries.has(e.target)) continue;
      const set = namesUsed.get(e.target) ?? new Set<string>();
      set.add(e.name);
      namesUsed.set(e.target, set);
    }
  }
  for (const node of nodes) {
    const used = [...(namesUsed.get(node.key) ?? [])];
    if (used.length === 1 && used[0] !== node.name) node.alias = used[0];
  }

  const workspaceFolders = importers.map((i) => i.key).filter((k) => k !== '');
  const root = rootOf(options.rootPackage, rootSpecs, workspaceFolders);
  return buildGraph({ root, lockfileVersion, packageManager: 'pnpm', nodes, importers });
}

function rootOf(
  pkg: PackageJson | undefined,
  specs: Record<'dependencies' | 'devDependencies' | 'optionalDependencies', Record<string, string>>,
  workspaceFolders: readonly string[],
): RootPackage {
  const engines: Record<string, string> = {};
  for (const [k, v] of Object.entries(pkg?.engines ?? {})) if (typeof v === 'string') engines[k] = v;
  const declared = Array.isArray(pkg?.workspaces) ? pkg.workspaces.filter((w): w is string => typeof w === 'string') : [];
  return {
    name: str(pkg?.name) ?? '',
    version: str(pkg?.version) ?? null,
    dependencies: pkg ? stringMap(pkg.dependencies) : { ...specs.dependencies },
    devDependencies: pkg ? stringMap(pkg.devDependencies) : { ...specs.devDependencies },
    optionalDependencies: pkg ? stringMap(pkg.optionalDependencies) : { ...specs.optionalDependencies },
    peerDependencies: pkg ? stringMap(pkg.peerDependencies) : {},
    workspaces: declared.length > 0 ? declared : [...workspaceFolders],
    engines,
    edges: {},
  };
}

// null when pnpm would hash the name
export function pnpmStorePath(key: string, name: string): string | null {
  let folder = key.replace(/[\\/:*?"<>|]/g, '+');
  if (folder.includes('(')) folder = folder.replace(/\)$/, '').replace(/\)\(|\(|\)/g, '_');
  if (folder.length > 120 || folder !== folder.toLowerCase()) return null;
  return `node_modules/.pnpm/${folder}/node_modules/${name}`;
}

// installed ranges replace resolved versions
export async function refinePnpmRanges(graph: DependencyGraph, projectRoot: string, keys?: readonly string[]): Promise<number> {
  const list = [...(keys ?? graph.nodes.keys())];
  let refined = 0;
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < list.length) {
      const key = list[next] as string;
      next += 1;
      const node = graph.nodes.get(key);
      const rel = node ? pnpmStorePath(key, node.name) : null;
      if (!node || !rel) continue;
      let manifest: PackageJson;
      try {
        manifest = JSON.parse(await readFile(path.join(projectRoot, ...rel.split('/'), 'package.json'), 'utf8')) as PackageJson;
      } catch {
        continue;
      }
      if (manifest.version !== node.version) continue;
      const declared = { ...stringMap(manifest.optionalDependencies), ...stringMap(manifest.dependencies) };
      let changed = false;
      for (const [dep, range] of Object.entries(declared)) {
        if (node.requires[dep] === undefined || node.requires[dep] === range) continue;
        node.requires[dep] = range;
        changed = true;
      }
      if (changed) refined += 1;
    }
  };
  await Promise.all(Array.from({ length: Math.min(16, list.length) }, () => worker()));
  return refined;
}
