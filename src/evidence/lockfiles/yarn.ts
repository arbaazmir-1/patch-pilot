// yarn 1 (classic) and 2+ (berry)
import { parse as parseYaml } from 'yaml';
import type { DependencyGraph, PackageJson, RootPackage } from '../../types.ts';
import { satisfiesRange } from '../../util/semver.ts';
import { buildGraph, isTrue, normalizeFolder, npmAlias, splitAt, str, stringMap, type EdgeKind, type RawEdge, type RawImporter, type RawNode } from './index.ts';

export type YarnFlavor = 'classic' | 'berry';

export interface YarnWorkspace {
  // posix, relative to root
  path: string;
  pkg: PackageJson;
}

export interface YarnParseOptions {
  rootPackage?: PackageJson;
  workspaces?: readonly YarnWorkspace[];
}

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;
type Section = (typeof SECTIONS)[number];
const KIND_OF: Record<Section, EdgeKind> = { dependencies: 'prod', devDependencies: 'dev', optionalDependencies: 'optional', peerDependencies: 'peer' };

// top-level __metadata means berry
export function yarnFlavor(text: string): YarnFlavor {
  return /^__metadata:\s*$/m.test(text) || /^"?__metadata"?:/m.test(text) ? 'berry' : 'classic';
}

export function parseYarnLockfile(text: string, options: YarnParseOptions = {}): DependencyGraph {
  return yarnFlavor(text) === 'berry' ? parseYarnBerry(text, options) : parseYarnClassic(text, options);
}

function workspacesOf(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  if (value && typeof value === 'object' && Array.isArray((value as { packages?: unknown }).packages)) {
    return ((value as { packages: unknown[] }).packages).filter((v): v is string => typeof v === 'string');
  }
  return [];
}

function rootFromPackage(pkg: PackageJson | undefined, fallbackWorkspaces: readonly string[]): RootPackage {
  const engines: Record<string, string> = {};
  for (const [k, v] of Object.entries(pkg?.engines ?? {})) if (typeof v === 'string') engines[k] = v;
  const declared = workspacesOf(pkg?.workspaces);
  return {
    name: str(pkg?.name) ?? '',
    version: str(pkg?.version) ?? null,
    dependencies: stringMap(pkg?.dependencies),
    devDependencies: stringMap(pkg?.devDependencies),
    optionalDependencies: stringMap(pkg?.optionalDependencies),
    peerDependencies: stringMap(pkg?.peerDependencies),
    workspaces: declared.length > 0 ? declared : [...fallbackWorkspaces],
    engines,
    edges: {},
  };
}

function manifestEdges(pkg: PackageJson | undefined, resolve: (name: string, spec: string) => string | null): RawEdge[] {
  const edges: RawEdge[] = [];
  const optional = stringMap(pkg?.optionalDependencies);
  for (const section of SECTIONS) {
    for (const [name, spec] of Object.entries(stringMap(pkg?.[section]))) {
      // optional deps are listed twice
      if (section === 'dependencies' && optional[name] !== undefined) continue;
      edges.push({ name, target: resolve(name, spec), kind: KIND_OF[section] });
    }
  }
  return edges;
}

// yarn 1

interface ClassicEntry {
  patterns: string[];
  data: Record<string, unknown>;
  line: number;
}

function closingQuote(text: string, start: number): number {
  for (let i = start + 1; i < text.length; i += 1) {
    if (text[i] === '\\') {
      i += 1;
      continue;
    }
    if (text[i] === '"') return i;
  }
  return -1;
}

function unquote(text: string): string {
  const t = text.trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
    try {
      return JSON.parse(t) as string;
    } catch {
      return t.slice(1, -1);
    }
  }
  return t;
}

// quoted commas kept
function splitPatterns(header: string): string[] {
  const out: string[] = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < header.length; i += 1) {
    const ch = header[i] as string;
    if (ch === '\\' && quoted) {
      current += ch + (header[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (ch === '"') quoted = !quoted;
    if (ch === ',' && !quoted) {
      out.push(unquote(current));
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim() !== '') out.push(unquote(current));
  return out.filter((p) => p !== '');
}

function keyValue(line: string): [string, unknown] {
  let key: string;
  let rest: string;
  if (line.startsWith('"')) {
    const end = closingQuote(line, 0);
    key = unquote(end === -1 ? line : line.slice(0, end + 1));
    rest = end === -1 ? '' : line.slice(end + 1).trim();
  } else {
    const space = line.search(/\s/);
    key = space === -1 ? line : line.slice(0, space);
    rest = space === -1 ? '' : line.slice(space).trim();
  }
  if (rest === 'true') return [key, true];
  if (rest === 'false') return [key, false];
  return [key, rest.startsWith('"') ? unquote(rest) : rest];
}

// throws on conflict markers
export function parseYarnClassicEntries(text: string): ClassicEntry[] {
  const entries: ClassicEntry[] = [];
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  let stack: { indent: number; obj: Record<string, unknown> }[] = [];
  let current: ClassicEntry | null = null;
  lines.forEach((line, index) => {
    if (/^(<{7}|={7}|>{7})(\s|$)/.test(line)) {
      throw new Error(`yarn.lock contains merge conflict markers (line ${index + 1}). Resolve them, or regenerate the lockfile with: yarn install`);
    }
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      if (!trimmed.endsWith(':')) {
        current = null;
        return;
      }
      current = { patterns: splitPatterns(trimmed.slice(0, -1)), data: {}, line: index + 1 };
      entries.push(current);
      stack = [{ indent: 0, obj: current.data }];
      return;
    }
    if (!current) return;
    while (stack.length > 1 && indent <= (stack[stack.length - 1] as { indent: number }).indent) stack.pop();
    const parent = (stack[stack.length - 1] as { obj: Record<string, unknown> }).obj;
    // "key:" opens an object, name "range" is a value
    const opensObject = trimmed.endsWith(':') && (trimmed.startsWith('"') ? closingQuote(trimmed, 0) === trimmed.length - 2 : !/\s/.test(trimmed));
    if (opensObject) {
      const obj: Record<string, unknown> = {};
      parent[unquote(trimmed.slice(0, -1))] = obj;
      stack.push({ indent, obj });
      return;
    }
    const [key, value] = keyValue(trimmed);
    parent[key] = value;
  });
  return entries;
}

export function parseYarnClassic(text: string, options: YarnParseOptions = {}): DependencyGraph {
  const entries = parseYarnClassicEntries(text);
  const rootPackage = options.rootPackage;
  const workspaces = [...(options.workspaces ?? [])];
  const nodes = new Map<string, RawNode>();
  const deps = new Map<string, { dependencies: Record<string, string>; optional: Record<string, string> }>();
  const byPattern = new Map<string, string>();
  // requested name (alias) -> node keys
  const byDepName = new Map<string, string[]>();
  const workspaceByName = new Map<string, YarnWorkspace>();
  for (const ws of workspaces) if (typeof ws.pkg.name === 'string') workspaceByName.set(ws.pkg.name, ws);
  const noteName = (name: string, key: string): void => {
    const list = byDepName.get(name) ?? [];
    if (!list.includes(key)) list.push(key);
    byDepName.set(name, list);
  };

  for (const entry of entries) {
    const first = entry.patterns[0];
    if (!first) continue;
    const version = typeof entry.data.version === 'string' ? entry.data.version : '';
    const names = entry.patterns.map((p) => splitAt(p));
    const [depName, range] = names[0] as [string, string];
    const alias = npmAlias(range);
    const name = alias?.name ?? depName;
    const allAliased = alias !== null && names.every(([n, r]) => n === depName && npmAlias(r)?.name === name);
    const resolved = str(entry.data.resolved);
    let key = allAliased ? `${depName}@npm:${name}@${version}` : `${name}@${version}`;
    const existing = nodes.get(key);
    if (existing && (existing.resolved ?? '') === (resolved ?? '')) {
      // hand-merged dupes share one node
      for (const p of entry.patterns) byPattern.set(p, key);
      for (const [n] of names) noteName(n, key);
      continue;
    }
    if (existing) {
      let n = 2;
      while (nodes.has(`${key}#${n}`)) n += 1;
      key = `${key}#${n}`;
    }
    const dependencies = stringMap(entry.data.dependencies);
    const optional = stringMap(entry.data.optionalDependencies);
    const raw: RawNode = { key, name, version, requires: { ...optional, ...dependencies }, edges: [] };
    if (allAliased) raw.alias = depName;
    if (resolved) raw.resolved = resolved;
    const integrity = str(entry.data.integrity);
    if (integrity) raw.integrity = integrity;
    nodes.set(key, raw);
    deps.set(key, { dependencies, optional });
    for (const p of entry.patterns) byPattern.set(p, key);
    for (const [n] of names) noteName(n, key);
  }

  const resolve = (name: string, spec: string): string | null => {
    const hit = byPattern.get(`${name}@${spec}`);
    if (hit) return hit;
    const ws = workspaceByName.get(name);
    if (ws && (spec === '*' || spec.startsWith('workspace:') || spec.startsWith('file:') || spec.startsWith('link:') || satisfiesRange(String(ws.pkg.version ?? ''), spec))) {
      return ws.path;
    }
    const candidates = byDepName.get(name) ?? [];
    const range = npmAlias(spec)?.range ?? spec;
    const matching = candidates.filter((k) => satisfiesRange(nodes.get(k)?.version ?? '', range));
    if (matching.length > 0) return matching[matching.length - 1] as string;
    return candidates.length === 1 ? (candidates[0] as string) : null;
  };

  for (const [key, raw] of nodes) {
    const d = deps.get(key) as { dependencies: Record<string, string>; optional: Record<string, string> };
    for (const [name, spec] of Object.entries(d.dependencies)) {
      if (d.optional[name] !== undefined) continue;
      raw.edges.push({ name, target: resolve(name, spec), kind: 'prod' });
    }
    for (const [name, spec] of Object.entries(d.optional)) raw.edges.push({ name, target: resolve(name, spec), kind: 'optional' });
  }

  let root = rootFromPackage(rootPackage, workspaces.map((w) => w.path));
  if (!rootPackage) {
    // no package.json, unrequired entries are direct
    const required = new Set<string>();
    for (const raw of nodes.values()) for (const e of raw.edges) if (e.target) required.add(e.target);
    const direct: Record<string, string> = {};
    for (const entry of entries) {
      const [depName, range] = splitAt(entry.patterns[0] ?? '');
      const key = byPattern.get(entry.patterns[0] ?? '');
      if (key && !required.has(key) && direct[depName] === undefined) direct[depName] = range;
    }
    root = { ...root, dependencies: direct };
  }
  const rootSections: PackageJson = {
    dependencies: root.dependencies,
    devDependencies: root.devDependencies,
    optionalDependencies: root.optionalDependencies,
    peerDependencies: root.peerDependencies,
  };
  const importers: RawImporter[] = [{ key: '', edges: manifestEdges(rootSections, resolve) }];
  for (const ws of workspaces) importers.push({ key: normalizeFolder(ws.path), edges: manifestEdges(ws.pkg, resolve) });
  return buildGraph({ root, lockfileVersion: 1, packageManager: 'yarn', nodes: [...nodes.values()], importers });
}

// yarn 2+ (berry)

interface BerryEntry {
  descriptors: string[];
  resolution: string;
  data: Record<string, unknown>;
}

function splitLocator(locator: string): [string, string] {
  return splitAt(locator);
}

export function patchedLocator(locator: string): string | null {
  const [name, reference] = splitLocator(locator);
  if (!reference.startsWith('patch:')) return null;
  const inner = reference.slice('patch:'.length).split('#')[0] ?? '';
  let decoded: string;
  try {
    decoded = decodeURIComponent(inner);
  } catch {
    return null;
  }
  return splitLocator(decoded)[0] === name ? decoded : null;
}

// "0.5.0" -> "npm:0.5.0"
function berryRange(range: string): string {
  if (/^[a-z][a-z0-9+.-]*:/i.test(range)) return range;
  return `npm:${range}`;
}

// aliases stay as is
function plainSpec(range: string): string {
  if (range.startsWith('npm:') && npmAlias(range) === null) return range.slice(4);
  return range;
}

// "parent@^6/pkg" -> {from, name}
export function parseResolutionKey(key: string): { from: string | null; name: string } {
  const rest = key.startsWith('**/') ? key.slice(3) : key;
  const parts = rest.split('/');
  const specs: string[] = [];
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i] as string;
    if (part.startsWith('@') && !part.slice(1).includes('@') && i + 1 < parts.length) {
      specs.push(`${part}/${parts[i + 1] as string}`);
      i += 1;
    } else {
      specs.push(part);
    }
  }
  const name = splitAt(specs[specs.length - 1] ?? '')[0];
  if (specs.length < 2) return { from: null, name };
  const from = splitAt(specs[specs.length - 2] as string)[0];
  return { from: from === '**' ? null : from, name };
}

function resolutionApplies(pattern: string, name: string, parent: string | null): boolean {
  const parsed = parseResolutionKey(pattern);
  return parsed.name === name && (parsed.from === null || parsed.from === parent);
}

export function parseYarnBerry(text: string, options: YarnParseOptions = {}): DependencyGraph {
  let doc: unknown;
  try {
    doc = parseYaml(text, { schema: 'failsafe' });
  } catch (err) {
    throw new Error(`yarn.lock is not valid YAML (${(err as Error).message.split('\n')[0]}). A merge conflict? Regenerate it with: yarn install`, { cause: err });
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('yarn.lock does not contain any entries');
  const all = doc as Record<string, unknown>;
  const metadata = (all.__metadata ?? {}) as Record<string, unknown>;
  const lockfileVersion = Number.parseInt(String(metadata.version ?? '0'), 10) || 0;
  const rootPackage = options.rootPackage;
  const workspacePkgs = new Map((options.workspaces ?? []).map((w) => [normalizeFolder(w.path), w.pkg]));

  const entries = new Map<string, BerryEntry>();
  const byDescriptor = new Map<string, string>();
  for (const [header, value] of Object.entries(all)) {
    if (header === '__metadata' || !value || typeof value !== 'object') continue;
    const data = value as Record<string, unknown>;
    const resolution = str(data.resolution);
    if (!resolution) continue;
    const descriptors = header.split(',').map((d) => d.trim()).filter(Boolean);
    const existing = entries.get(resolution);
    if (existing) existing.descriptors.push(...descriptors);
    else entries.set(resolution, { descriptors, resolution, data });
    for (const d of descriptors) byDescriptor.set(d, resolution);
  }

  // null for a soft link
  const targetOf = new Map<string, string | null>();
  const workspaceFolders = new Map<string, string>();
  const nodes = new Map<string, RawNode>();
  const locatorsByName = new Map<string, string[]>();
  for (const entry of entries.values()) {
    const [name, reference] = splitLocator(entry.resolution);
    if (reference.startsWith('workspace:')) {
      const folder = normalizeFolder(reference.slice('workspace:'.length));
      workspaceFolders.set(entry.resolution, folder);
      targetOf.set(entry.resolution, folder);
      continue;
    }
    if (str(entry.data.linkType) === 'soft') {
      targetOf.set(entry.resolution, null);
      continue;
    }
    const patched = patchedLocator(entry.resolution);
    if (patched && entries.has(patched)) continue; // folded into its target
    const aliases = [...new Set(entry.descriptors.map((d) => splitAt(d)[0]).filter((n) => n !== name))];
    const plainUse = entry.descriptors.some((d) => splitAt(d)[0] === name);
    const dependencies = stringMap(entry.data.dependencies);
    const peers = stringMap(entry.data.peerDependencies);
    const requires: Record<string, string> = {};
    for (const [dep, range] of Object.entries(peers)) requires[dep] = range;
    for (const [dep, range] of Object.entries(dependencies)) requires[dep] = plainSpec(range);
    const raw: RawNode = { key: entry.resolution, name, version: str(entry.data.version) ?? '', requires, edges: [] };
    if (aliases.length === 1 && !plainUse) raw.alias = aliases[0];
    const checksum = str(entry.data.checksum);
    if (checksum) raw.integrity = checksum;
    if (!reference.startsWith('npm:')) raw.resolved = entry.resolution;
    nodes.set(entry.resolution, raw);
    targetOf.set(entry.resolution, entry.resolution);
    const list = locatorsByName.get(name) ?? [];
    list.push(entry.resolution);
    locatorsByName.set(name, list);
  }
  for (const entry of entries.values()) {
    const patched = patchedLocator(entry.resolution);
    if (patched && entries.has(patched)) targetOf.set(entry.resolution, targetOf.get(patched) ?? patched);
  }

  const resolutions = stringMap(rootPackage?.resolutions);
  const resolve = (name: string, range: string, parent: string | null): string | null => {
    const direct = byDescriptor.get(`${name}@${range}`);
    if (direct !== undefined) return targetOf.get(direct) ?? null;
    for (const [pattern, value] of Object.entries(resolutions)) {
      if (!resolutionApplies(pattern, name, parent)) continue;
      const hit = byDescriptor.get(`${name}@${berryRange(value)}`);
      if (hit !== undefined) return targetOf.get(hit) ?? null;
    }
    const realName = npmAlias(range)?.name ?? name;
    const plain = npmAlias(range)?.range ?? plainSpec(range);
    const candidates = locatorsByName.get(realName) ?? [];
    const matching = candidates.filter((k) => satisfiesRange(nodes.get(k)?.version ?? '', plain));
    if (matching.length > 0) return matching[matching.length - 1] as string;
    return candidates.length === 1 ? (candidates[0] as string) : null;
  };

  // peers come later, via dependents
  for (const [locator, raw] of nodes) {
    const data = (entries.get(locator) as BerryEntry).data;
    const meta = (data.dependenciesMeta ?? {}) as Record<string, unknown>;
    for (const [dep, range] of Object.entries(stringMap(data.dependencies))) {
      const optional = isTrue((meta[dep] as Record<string, unknown> | undefined)?.optional);
      raw.edges.push({ name: dep, target: resolve(dep, range, raw.name), kind: optional ? 'optional' : 'prod' });
    }
  }

  const importers: RawImporter[] = [];
  for (const [locator, folder] of workspaceFolders) {
    const data = (entries.get(locator) as BerryEntry).data;
    const pkg = folder === '' ? rootPackage : workspacePkgs.get(folder);
    const meta = (data.dependenciesMeta ?? {}) as Record<string, unknown>;
    const edges: RawEdge[] = [];
    const lockDeps = stringMap(data.dependencies);
    const lockPeers = stringMap(data.peerDependencies);
    const fromLock = (dep: string): string | undefined => lockDeps[dep] ?? lockPeers[dep];
    const wsName = splitLocator(locator)[0];
    if (pkg) {
      const optional = stringMap(pkg.optionalDependencies);
      for (const section of SECTIONS) {
        for (const [dep, spec] of Object.entries(stringMap(pkg[section]))) {
          if (section === 'dependencies' && optional[dep] !== undefined) continue;
          const range = fromLock(dep) ?? berryRange(spec);
          edges.push({ name: dep, target: resolve(dep, range, wsName), kind: KIND_OF[section] });
        }
      }
    } else {
      for (const [dep, range] of Object.entries(lockDeps)) {
        const optional = isTrue((meta[dep] as Record<string, unknown> | undefined)?.optional);
        edges.push({ name: dep, target: resolve(dep, range, wsName), kind: optional ? 'optional' : 'prod' });
      }
      for (const [dep, range] of Object.entries(lockPeers)) edges.push({ name: dep, target: resolve(dep, range, wsName), kind: 'peer' });
    }
    importers.push({ key: folder, edges });
  }
  if (!importers.some((i) => i.key === '')) importers.unshift({ key: '', edges: manifestEdges(rootPackage, (dep, spec) => resolve(dep, berryRange(spec), null)) });
  importers.sort((a, b) => (a.key === '' ? -1 : b.key === '' ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  // peers resolve via each dependent's edge
  const providers = new Map<string, RawEdge[][]>();
  const noteProvider = (edges: RawEdge[]): void => {
    for (const e of edges) {
      if (!e.target || !nodes.has(e.target)) continue;
      const list = providers.get(e.target) ?? [];
      list.push(edges);
      providers.set(e.target, list);
    }
  };
  for (const importer of importers) noteProvider(importer.edges);
  for (const raw of nodes.values()) noteProvider(raw.edges);
  for (const [locator, raw] of nodes) {
    const data = (entries.get(locator) as BerryEntry).data;
    const peerMeta = (data.peerDependenciesMeta ?? {}) as Record<string, unknown>;
    for (const [peer, range] of Object.entries(stringMap(data.peerDependencies))) {
      const optional = isTrue((peerMeta[peer] as Record<string, unknown> | undefined)?.optional);
      let target: string | null = null;
      for (const edges of providers.get(locator) ?? []) {
        const hit = edges.find((e) => e.name === peer && e.target);
        if (hit) {
          target = hit.target;
          break;
        }
      }
      if (target === null && !optional) target = resolve(peer, berryRange(range), raw.name);
      raw.edges.push({ name: peer, target, kind: optional ? 'peerOptional' : 'peer' });
    }
  }

  const root = rootPackage ? rootFromPackage(rootPackage, [...workspaceFolders.values()].filter((f) => f !== '')) : berryRoot(entries, workspaceFolders);
  return buildGraph({ root, lockfileVersion, packageManager: 'yarn-berry', nodes: [...nodes.values()], importers });
}

// no package.json needed
function berryRoot(entries: Map<string, BerryEntry>, workspaceFolders: Map<string, string>): RootPackage {
  let name = '';
  let dependencies: Record<string, string> = {};
  let peerDependencies: Record<string, string> = {};
  for (const [locator, folder] of workspaceFolders) {
    if (folder !== '') continue;
    name = splitLocator(locator)[0];
    const data = (entries.get(locator) as BerryEntry).data;
    dependencies = Object.fromEntries(Object.entries(stringMap(data.dependencies)).map(([k, v]) => [k, plainSpec(v)]));
    peerDependencies = stringMap(data.peerDependencies);
  }
  return {
    name,
    version: null,
    dependencies,
    devDependencies: {},
    optionalDependencies: {},
    peerDependencies,
    workspaces: [...workspaceFolders.values()].filter((f) => f !== ''),
    engines: {},
    edges: {},
  };
}

// yarn 1 in-range refresh

// quotes kept
function rawPatternTokens(header: string): string[] {
  const out: string[] = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < header.length; i += 1) {
    const ch = header[i] as string;
    if (ch === '\\' && quoted) {
      current += ch + (header[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (ch === '"') quoted = !quoted;
    if (ch === ',' && !quoted) {
      if (current.trim() !== '') out.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim() !== '') out.push(current.trim());
  return out;
}

// next install re-resolves them in range
export function removeYarnClassicRequests(text: string, remove: (request: string, version: string) => boolean): { text: string; removed: string[] } {
  const versions = new Map<number, string>();
  for (const entry of parseYarnClassicEntries(text)) versions.set(entry.line, typeof entry.data.version === 'string' ? entry.data.version : '');
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  const out: string[] = [];
  const removed: string[] = [];
  let skipping = false;
  lines.forEach((line, index) => {
    const header = line !== '' && !/^\s/.test(line) && !line.startsWith('#') && line.trimEnd().endsWith(':');
    if (header) {
      skipping = false;
      const version = versions.get(index + 1) ?? '';
      const tokens = rawPatternTokens(line.trimEnd().slice(0, -1));
      const keep = tokens.filter((t) => !remove(unquote(t), version));
      if (keep.length === tokens.length) {
        out.push(line);
        return;
      }
      removed.push(...tokens.filter((t) => !keep.includes(t)).map(unquote));
      if (keep.length > 0) {
        out.push(`${keep.join(', ')}:`);
        return;
      }
      skipping = true;
      if (out.length > 0 && (out[out.length - 1] as string).trim() === '') out.pop();
      return;
    }
    if (skipping) {
      if (line.trim() !== '' && !/^\s/.test(line)) skipping = false;
      else if (line.trim() === '') {
        skipping = false;
        out.push(line);
        return;
      } else return;
    }
    out.push(line);
  });
  return { text: out.join(eol), removed };
}
