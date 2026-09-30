// shared by yarn and pnpm parsers
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import semver from 'semver';
import type { DependencyGraph, PackageManager, PackageNode, RootPackage } from '../../types.ts';

export type EdgeKind = 'prod' | 'dev' | 'optional' | 'peer' | 'peerOptional';

export interface RawEdge {
  // alias for an aliased dep
  name: string;
  // null when unresolved
  target: string | null;
  kind: EdgeKind;
}

export interface RawNode {
  key: string;
  name: string;
  version: string;
  alias?: string;
  resolved?: string;
  integrity?: string;
  license?: string;
  engines?: Record<string, string>;
  deprecated?: string;
  hasInstallScript?: boolean;
  // deps, optional and peer
  requires: Record<string, string>;
  edges: RawEdge[];
}

export interface RawImporter {
  // "" for root, POSIX
  key: string;
  edges: RawEdge[];
}

export interface GraphInput {
  root: RootPackage;
  lockfileVersion: number;
  packageManager: PackageManager;
  nodes: readonly RawNode[];
  importers: readonly RawImporter[];
}

interface FlagState {
  dev: boolean;
  optional: boolean;
  devOptional: boolean;
  peer: boolean;
}

const NO_FLAGS: FlagState = { dev: false, optional: false, devOptional: false, peer: false };

export function buildGraph(input: GraphInput): DependencyGraph {
  const root: RootPackage = { ...input.root, edges: { ...input.root.edges } };
  const nodes = new Map<string, PackageNode>();
  const byName = new Map<string, string[]>();
  const raws = new Map<string, RawNode>();
  for (const raw of input.nodes) {
    if (nodes.has(raw.key)) continue;
    raws.set(raw.key, raw);
    const node: PackageNode = {
      key: raw.key,
      name: raw.name,
      version: raw.version,
      dev: false,
      optional: false,
      devOptional: false,
      peer: false,
      bundled: false,
      isDirect: false,
      parents: [],
      requires: { ...raw.requires },
      edges: {},
    };
    if (raw.alias && raw.alias !== raw.name) node.alias = raw.alias;
    if (raw.resolved) node.resolved = raw.resolved;
    if (raw.integrity) node.integrity = raw.integrity;
    if (raw.license) node.license = raw.license;
    if (raw.engines && Object.keys(raw.engines).length > 0) node.engines = { ...raw.engines };
    if (raw.deprecated) node.deprecated = raw.deprecated;
    if (raw.hasInstallScript) node.hasInstallScript = true;
    nodes.set(raw.key, node);
    const list = byName.get(raw.name);
    if (list) list.push(raw.key);
    else byName.set(raw.name, [raw.key]);
  }

  const addParent = (target: string, parent: string): void => {
    const node = nodes.get(target);
    if (node && !node.parents.includes(parent)) node.parents.push(parent);
  };
  for (const importer of input.importers) {
    for (const edge of importer.edges) {
      if (edge.target === null || edge.target === importer.key) continue;
      if (importer.key === '' && root.edges[edge.name] === undefined) root.edges[edge.name] = edge.target;
      const node = nodes.get(edge.target);
      if (!node) continue;
      node.isDirect = true;
      addParent(edge.target, importer.key);
    }
  }
  for (const raw of raws.values()) {
    const node = nodes.get(raw.key) as PackageNode;
    for (const edge of raw.edges) {
      if (edge.target === null || edge.target === raw.key) continue;
      if (node.edges[edge.name] === undefined) node.edges[edge.name] = edge.target;
      addParent(edge.target, raw.key);
    }
  }
  for (const node of nodes.values()) node.parents.sort((a, b) => (a === '' ? -1 : b === '' ? 1 : a < b ? -1 : a > b ? 1 : 0));

  computeFlags(nodes, raws, input.importers);
  return {
    root,
    lockfileVersion: input.lockfileVersion,
    nodes,
    byName,
    workspaceKeys: input.importers.filter((i) => i.key !== '').map((i) => i.key),
    packageManager: input.packageManager,
  };
}

function computeFlags(nodes: Map<string, PackageNode>, raws: Map<string, RawNode>, importers: readonly RawImporter[]): void {
  const state = new Map<string, FlagState>();
  for (const key of nodes.keys()) state.set(key, { dev: true, optional: true, devOptional: true, peer: true });
  const firstPass = new Set<string>();
  const run = (pass: 1 | 2): void => {
    const reached = pass === 1 ? firstPass : new Set<string>();
    const queue: string[] = [];
    const visit = (from: FlagState, kind: EdgeKind, target: string | null): void => {
      if (target === null) return;
      const to = state.get(target);
      if (!to) return;
      if (kind === 'peerOptional' && pass === 1) return;
      if (pass === 2 && firstPass.has(target)) return;
      const edgeDev = kind === 'dev';
      const edgeOpt = kind === 'optional' || kind === 'peerOptional';
      const edgePeer = kind === 'peer' || kind === 'peerOptional';
      const unsetDevOpt = !from.devOptional && !edgeDev && !edgeOpt;
      const unsetDev = unsetDevOpt || (!from.dev && !edgeDev);
      const unsetOpt = unsetDevOpt || (!from.optional && !edgeOpt);
      const unsetPeer = !from.peer && !edgePeer;
      let changed = !reached.has(target);
      reached.add(target);
      if (unsetPeer && to.peer) {
        to.peer = false;
        changed = true;
      }
      if (unsetDevOpt && to.devOptional) {
        to.devOptional = false;
        changed = true;
      }
      if (unsetDev && to.dev) {
        to.dev = false;
        changed = true;
      }
      if (unsetOpt && to.optional) {
        to.optional = false;
        changed = true;
      }
      if (changed) queue.push(target);
    };
    if (pass === 1) {
      for (const importer of importers) for (const edge of importer.edges) visit(NO_FLAGS, edge.kind, edge.target);
    } else {
      for (const key of firstPass) {
        const from = state.get(key) as FlagState;
        for (const edge of raws.get(key)?.edges ?? []) visit(from, edge.kind, edge.target);
      }
    }
    for (let i = 0; i < queue.length; i += 1) {
      const key = queue[i] as string;
      const from = state.get(key) as FlagState;
      for (const edge of raws.get(key)?.edges ?? []) visit(from, edge.kind, edge.target);
    }
    if (pass === 2) for (const key of reached) firstPass.add(key);
  };
  run(1);
  run(2);
  for (const [key, node] of nodes) {
    const flags = firstPass.has(key) ? (state.get(key) as FlagState) : NO_FLAGS;
    node.dev = flags.dev;
    node.optional = flags.optional;
    node.peer = flags.peer;
    node.devOptional = flags.devOptional && !flags.dev && !flags.optional;
  }
}

// bare name gets ""
export function splitAt(spec: string): [string, string] {
  const idx = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  if (idx <= 0) return [spec, ''];
  return [spec.slice(0, idx), spec.slice(idx + 1)];
}

// null for "npm:^0.2.0"
export function npmAlias(range: string): { name: string; range: string } | null {
  if (!range.startsWith('npm:')) return null;
  const rest = range.slice(4);
  const [name, inner] = splitAt(rest);
  if (!/^(@[^/@\s]+\/)?[^/@\s]+$/.test(name)) return null;
  if (!rest.slice(1).includes('@') && semver.validRange(rest, { loose: true }) !== null) return null;
  return { name, range: inner };
}

export function stringMap(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
  return out;
}

export function isTrue(value: unknown): boolean {
  return value === true || value === 'true';
}

export function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

// no "./" or trailing "/", root is ""
export function normalizeFolder(folder: string): string {
  const posix = path.posix.normalize(folder.replace(/\\/g, '/')).replace(/^\.\/+/, '').replace(/\/+$/, '');
  return posix === '.' ? '' : posix;
}

async function isDir(p: string): Promise<boolean> {
  try {
    return (await stat(p)).isDirectory();
  } catch {
    return false;
  }
}

async function isFile(p: string): Promise<boolean> {
  try {
    return (await stat(p)).isFile();
  } catch {
    return false;
  }
}

function segmentSource(segment: string): string {
  return segment.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]');
}

function segmentRegex(segment: string): RegExp {
  return new RegExp(`^${segmentSource(segment)}$`);
}

// negated workspace patterns, ** spans dirs
function globRegex(pattern: string): RegExp {
  return new RegExp(`^${pattern.split('/').map((s) => (s === '**' ? '.*' : segmentSource(s))).join('/')}$`);
}

async function subdirs(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory() && e.name !== 'node_modules' && !e.name.startsWith('.')).map((e) => e.name);
  } catch {
    return [];
  }
}

// only folders with a package.json, sorted
export async function expandWorkspaceGlobs(root: string, patterns: readonly string[]): Promise<string[]> {
  const found = new Set<string>();
  const negative = patterns.filter((p) => p.startsWith('!')).map((p) => normalizeFolder(p.slice(1)));
  const walk = async (rel: string, segments: readonly string[]): Promise<void> => {
    if (segments.length === 0) {
      if (rel !== '' && (await isFile(path.join(root, rel, 'package.json')))) found.add(rel);
      return;
    }
    const [head, ...rest] = segments as [string, ...string[]];
    const here = path.join(root, rel);
    if (head === '**') {
      await walk(rel, rest);
      for (const name of await subdirs(here)) await walk(rel === '' ? name : `${rel}/${name}`, segments);
      return;
    }
    if (!/[*?]/.test(head)) {
      const next = rel === '' ? head : `${rel}/${head}`;
      if (await isDir(path.join(root, next))) await walk(next, rest);
      return;
    }
    const re = segmentRegex(head);
    for (const name of await subdirs(here)) if (re.test(name)) await walk(rel === '' ? name : `${rel}/${name}`, rest);
  };
  for (const pattern of patterns) {
    if (pattern.startsWith('!')) continue;
    const folder = normalizeFolder(pattern);
    if (folder === '' || folder.startsWith('..')) continue;
    await walk('', folder.split('/').filter((s) => s !== ''));
  }
  const excluded = negative.map(globRegex);
  return [...found].filter((f) => !excluded.some((re) => re.test(f))).sort();
}
