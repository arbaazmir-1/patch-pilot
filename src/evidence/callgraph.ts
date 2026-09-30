// cross-file reachability
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { IndirectPath } from '../types.ts';
import { moduleBaseName, typescript, type ExportTarget, type FileSummary, type SpecifierResolver } from './ast.ts';

export const CALL_GRAPH_MAX_DEPTH = 5;
export const CALL_GRAPH_MAX_FILES = 4000;
export const CALL_GRAPH_MAX_BYTES = 48 * 1024 * 1024;
export const MAX_INDIRECT_PATHS = 100;

const RESOLVE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte'];
// ./x.js in ts means x.ts
const EXTENSION_SWAPS: Readonly<Record<string, readonly string[]>> = {
  '.js': ['.ts', '.tsx', '.jsx'],
  '.mjs': ['.mts'],
  '.cjs': ['.cts'],
  '.jsx': ['.tsx'],
};

export interface PathAliases {
  baseUrl: string | null;
  // one * max, targets root-relative
  paths: { pattern: string; targets: string[] }[];
}

interface RawConfig {
  baseUrl: string | null;
  paths: Record<string, string[]> | null;
  pathsBase: string | null;
}

function toPosixRel(root: string, abs: string): string {
  const rel = path.relative(root, abs).split(path.sep).join('/');
  return rel === '' ? '.' : rel;
}

async function readConfig(file: string, depth: number): Promise<RawConfig | null> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    return null;
  }
  const T = typescript();
  const parsed = T.parseConfigFileTextToJson(file, text);
  if (parsed.error || !parsed.config || typeof parsed.config !== 'object') return null;
  const cfg = parsed.config as { extends?: unknown; compilerOptions?: { baseUrl?: unknown; paths?: unknown } };
  const dir = path.dirname(file);
  const out: RawConfig = { baseUrl: null, paths: null, pathsBase: null };
  const parents = Array.isArray(cfg.extends) ? cfg.extends : typeof cfg.extends === 'string' ? [cfg.extends] : [];
  for (const ext of parents) {
    // skip @tsconfig/node20 style extends
    if (typeof ext !== 'string' || depth >= 3 || !ext.startsWith('.')) continue;
    const parent = await readConfig(path.resolve(dir, ext.endsWith('.json') ? ext : `${ext}.json`), depth + 1);
    if (!parent) continue;
    if (parent.baseUrl) out.baseUrl = parent.baseUrl;
    if (parent.paths) {
      out.paths = parent.paths;
      out.pathsBase = parent.pathsBase;
    }
  }
  const co = cfg.compilerOptions ?? {};
  if (typeof co.baseUrl === 'string') out.baseUrl = path.resolve(dir, co.baseUrl);
  if (co.paths && typeof co.paths === 'object' && !Array.isArray(co.paths)) {
    const paths: Record<string, string[]> = {};
    for (const [pattern, targets] of Object.entries(co.paths as Record<string, unknown>)) {
      if (Array.isArray(targets)) paths[pattern] = targets.filter((t): t is string => typeof t === 'string');
    }
    out.paths = paths;
    out.pathsBase = dir;
  }
  return out;
}

export async function loadPathAliases(root: string): Promise<PathAliases> {
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const cfg = await readConfig(path.join(root, name), 0);
    if (!cfg) continue;
    const base = cfg.baseUrl ?? cfg.pathsBase;
    const paths = Object.entries(cfg.paths ?? {})
      .filter(([pattern]) => (pattern.match(/\*/g) ?? []).length <= 1)
      .map(([pattern, targets]) => ({ pattern, targets: targets.map((t) => toPosixRel(root, path.resolve(base ?? root, t))) }));
    return { baseUrl: cfg.baseUrl ? toPosixRel(root, cfg.baseUrl) : null, paths };
  }
  return { baseUrl: null, paths: [] };
}

const SPECIFIER_RE = /(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s*)(['"`])([^'"`\n]{1,300})\1/g;

// regex, no parse, bare only with keepBare
export function extractSpecifiers(text: string, keepBare = false): string[] {
  if (!text.includes('require') && !text.includes('import') && !text.includes('from')) return [];
  const out = new Set<string>();
  for (const m of text.matchAll(SPECIFIER_RE)) {
    const spec = m[2] as string;
    if (spec.startsWith('.') || (keepBare && !spec.startsWith('/') && !/^[a-z]+:/i.test(spec))) out.add(spec);
  }
  return [...out];
}

// never into node_modules
export function createResolver(files: ReadonlySet<string>, aliases: PathAliases = { baseUrl: null, paths: [] }): SpecifierResolver {
  const cache = new Map<string, string | null>();
  const patterns = aliases.paths
    .map((p) => {
      const star = p.pattern.indexOf('*');
      return { ...p, prefix: star === -1 ? p.pattern : p.pattern.slice(0, star), suffix: star === -1 ? '' : p.pattern.slice(star + 1), wildcard: star !== -1 };
    })
    .sort((a, b) => b.prefix.length - a.prefix.length);
  const resolveFile = (candidate: string): string | null => {
    const n = path.posix.normalize(candidate).replace(/\/+$/, '');
    if (n === '..' || n.startsWith('../') || n.startsWith('/')) return null;
    if (n.split('/').includes('node_modules')) return null;
    if (files.has(n)) return n;
    const ext = path.posix.extname(n);
    for (const swap of EXTENSION_SWAPS[ext] ?? []) {
      const c = `${n.slice(0, -ext.length)}${swap}`;
      if (files.has(c)) return c;
    }
    for (const e of RESOLVE_EXTENSIONS) if (files.has(`${n}${e}`)) return `${n}${e}`;
    const dir = n === '.' ? '' : `${n}/`;
    for (const e of RESOLVE_EXTENSIONS) if (files.has(`${dir}index${e}`)) return `${dir}index${e}`;
    return null;
  };
  const resolveBare = (spec: string): string | null => {
    for (const p of patterns) {
      if (p.wildcard) {
        if (!spec.startsWith(p.prefix) || !spec.endsWith(p.suffix) || spec.length < p.prefix.length + p.suffix.length) continue;
        const middle = spec.slice(p.prefix.length, spec.length - p.suffix.length);
        for (const t of p.targets) {
          const hit = resolveFile(t.replace('*', middle));
          if (hit) return hit;
        }
      } else if (spec === p.pattern) {
        for (const t of p.targets) {
          const hit = resolveFile(t);
          if (hit) return hit;
        }
      }
    }
    if (aliases.baseUrl !== null) return resolveFile(aliases.baseUrl === '.' ? spec : `${aliases.baseUrl}/${spec}`);
    return null;
  };
  return (spec, fromPath) => {
    const relative = spec === '.' || spec === '..' || spec.startsWith('./') || spec.startsWith('../');
    const key = relative ? `${path.posix.dirname(fromPath)}\u0000${spec}` : `\u0000${spec}`;
    const hit = cache.get(key);
    if (hit !== undefined) return hit;
    let out: string | null = null;
    if (relative) out = resolveFile(path.posix.join(path.posix.dirname(fromPath), spec));
    else if (!spec.startsWith('/') && !/^[a-z]+:/i.test(spec)) out = resolveBare(spec);
    cache.set(key, out);
    return out;
  };
}

// via is outermost first
export interface Chain {
  pkg: string;
  member: string | null;
  via: string[];
}

export interface CallGraphHost {
  specifiers: ReadonlyMap<string, readonly string[]>;
  resolve: SpecifierResolver;
  // call graph adds what it loads
  summaries: Map<string, FileSummary | null>;
  // null when unreadable or unparsable
  load(file: string): Promise<{ summary: FileSummary | null; bytes: number }>;
  signal?: AbortSignal;
}

export interface CallGraphOptions {
  maxDepth?: number;
  maxFiles?: number;
  maxBytes?: number;
  maxPaths?: number;
}

export interface CallGraphResult {
  byPackage: Map<string, IndirectPath[]>;
  // importers parsed here
  parsedFiles: number;
  capped: boolean;
  skipped: string[];
}

function chainKey(c: Chain): string {
  return `${c.pkg}\u0000${c.member ?? ''}`;
}

// shortest per member, true on change
function addChain(list: Chain[], chain: Chain, maxDepth: number): boolean {
  if (chain.via.length > maxDepth) return false;
  const key = chainKey(chain);
  const i = list.findIndex((c) => chainKey(c) === key);
  if (i === -1) {
    list.push(chain);
    return true;
  }
  if ((list[i] as Chain).via.length > chain.via.length) {
    list[i] = chain;
    return true;
  }
  return false;
}

function sameChains(a: readonly Chain[][] | undefined, b: readonly Chain[][]): boolean {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    const x = a[i] as Chain[];
    const y = b[i] as Chain[];
    if (x.length !== y.length) return false;
    const keys = new Set(x.map((c) => `${chainKey(c)}\u0000${c.via.join('>')}`));
    if (!y.every((c) => keys.has(`${chainKey(c)}\u0000${c.via.join('>')}`))) return false;
  }
  return true;
}

export async function computeIndirectPaths(host: CallGraphHost, options: CallGraphOptions = {}): Promise<CallGraphResult> {
  const maxDepth = options.maxDepth ?? CALL_GRAPH_MAX_DEPTH;
  const maxFiles = options.maxFiles ?? CALL_GRAPH_MAX_FILES;
  const maxBytes = options.maxBytes ?? CALL_GRAPH_MAX_BYTES;
  const maxPaths = options.maxPaths ?? MAX_INDIRECT_PATHS;
  const summaries = host.summaries;
  const unitChains = new Map<string, Chain[][]>();

  // reverse import index
  const importers = new Map<string, Set<string>>();
  for (const [file, specs] of host.specifiers) {
    for (const spec of specs) {
      const target = host.resolve(spec, file);
      if (!target || target === file) continue;
      const set = importers.get(target);
      if (set) set.add(file);
      else importers.set(target, new Set([file]));
    }
  }

  const targetChains = (t: ExportTarget, rest: readonly string[], name: string, seen: Set<string>): Chain[] => {
    switch (t.kind) {
      case 'unit':
        return unitChains.get(t.file)?.[t.unit] ?? [];
      case 'pkg': {
        const full = [...t.path, ...rest.slice(0, 1)];
        return [{ pkg: t.pkg, member: full.length > 0 ? (full[full.length - 1] as string) : null, via: [name] }];
      }
      case 'file':
        return lookup(t.file, [...t.path, ...rest], seen);
      case 'object': {
        const head = rest[0];
        if (head === undefined) return [];
        const prop = t.props.get(head);
        return prop ? targetChains(prop, rest.slice(1), head, seen) : [];
      }
      default:
        return [];
    }
  };
  // [] means calling it
  const lookup = (file: string, parts: readonly string[], seen: Set<string>): Chain[] => {
    const key = `${file}#${parts.join('.')}`;
    if (seen.has(key)) return [];
    seen.add(key);
    const s = summaries.get(file);
    if (!s) return [];
    if (parts.length === 0) {
      const d = s.exports.get('default');
      return d ? targetChains(d, [], moduleBaseName(file), seen) : [];
    }
    const head = parts[0] as string;
    const rest = parts.slice(1);
    let t = s.exports.get(head);
    if (!t) {
      const d = s.exports.get('default');
      if (d?.kind === 'object') t = d.props.get(head);
    }
    if (t) return targetChains(t, rest, head, seen);
    for (const star of s.stars) {
      const r = lookup(star, parts, seen);
      if (r.length > 0) return r;
    }
    const pkg = s.pkgStars[0];
    if (pkg !== undefined) return [{ pkg, member: head, via: [head] }];
    return [];
  };

  const computeUnits = (s: FileSummary): Chain[][] => {
    const chains: Chain[][] = s.units.map(() => []);
    for (const use of s.pkgUses) {
      if (use.unit < 0) continue;
      addChain(chains[use.unit] as Chain[], { pkg: use.pkg, member: use.member, via: [(s.units[use.unit] as FileSummary['units'][number]).name] }, maxDepth);
    }
    for (const use of s.fileUses) {
      if (use.unit < 0) continue;
      const name = (s.units[use.unit] as FileSummary['units'][number]).name;
      for (const c of lookup(use.file, use.path, new Set())) addChain(chains[use.unit] as Chain[], { ...c, via: [name, ...c.via] }, maxDepth);
    }
    for (let round = 0, changed = true; changed && round < 2 * maxDepth + 2; round += 1) {
      changed = false;
      s.units.forEach((unit, u) => {
        for (const v of unit.callees) {
          for (const c of chains[v] ?? []) if (addChain(chains[u] as Chain[], { ...c, via: [unit.name, ...c.via] }, maxDepth)) changed = true;
        }
      });
    }
    return chains;
  };

  const fixpoint = (): void => {
    for (let round = 0, changed = true; changed && round < 4 * maxDepth; round += 1) {
      changed = false;
      for (const [file, s] of summaries) {
        if (!s) continue;
        const next = computeUnits(s);
        if (!sameChains(unitChains.get(file), next)) {
          unitChains.set(file, next);
          changed = true;
        }
      }
    }
  };

  const reaches = (file: string, seen = new Set<string>()): boolean => {
    if (seen.has(file)) return false;
    seen.add(file);
    const s = summaries.get(file);
    if (!s) return false;
    if (s.pkgStars.length > 0) return true;
    for (const [name, t] of s.exports) {
      if (t.kind === 'object') {
        for (const [prop, pt] of t.props) if (targetChains(pt, [], prop, new Set()).length > 0) return true;
      } else if (t.kind === 'pkg' || targetChains(t, [], name, new Set()).length > 0) {
        return true;
      }
    }
    return s.stars.some((star) => reaches(star, seen));
  };

  let parsedFiles = 0;
  let bytes = 0;
  let capped = false;
  const skipped: string[] = [];
  const expanded = new Set<string>();
  fixpoint();
  for (let level = 0; level <= maxDepth + 1; level += 1) {
    const frontier = [...summaries.keys()].filter((f) => !expanded.has(f) && reaches(f));
    if (frontier.length === 0) break;
    let loaded = 0;
    for (const file of frontier) {
      expanded.add(file);
      for (const imp of [...(importers.get(file) ?? [])].sort()) {
        if (summaries.has(imp)) continue;
        if (host.signal?.aborted) break;
        if (parsedFiles >= maxFiles || bytes >= maxBytes) {
          capped = true;
          if (skipped.length < 5 && !skipped.includes(imp)) skipped.push(imp);
          continue;
        }
        const r = await host.load(imp);
        parsedFiles += 1;
        bytes += r.bytes;
        summaries.set(imp, r.summary);
        loaded += 1;
      }
    }
    if (loaded > 0) fixpoint();
  }

  const byPackage = new Map<string, IndirectPath[]>();
  const seenPaths = new Set<string>();
  for (const [file, s] of [...summaries.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    if (!s) continue;
    for (const use of [...s.fileUses].sort((a, b) => a.line - b.line)) {
      for (const c of lookup(use.file, use.path, new Set())) {
        if (c.via.length > maxDepth) continue;
        const key = `${c.pkg}\u0000${file}:${use.line}\u0000${c.member ?? ''}\u0000${c.via.join('>')}`;
        if (seenPaths.has(key)) continue;
        seenPaths.add(key);
        const list = byPackage.get(c.pkg) ?? [];
        if (list.length >= maxPaths) continue;
        list.push({ path: file, line: use.line, via: c.via, member: c.member });
        byPackage.set(c.pkg, list);
      }
    }
  }
  return { byPackage, parsedFiles, capped, skipped };
}
