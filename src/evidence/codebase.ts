// walker, search, imports, usage, blamed symbols
import { open, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type {
  AnalysisMethod,
  BlamedSymbol,
  DependentUsage,
  DynamicAccess,
  FileScope,
  ImportKind,
  ImportSite,
  IndirectPath,
  ProjectFile,
  SearchMatch,
  UsageEvidence,
  UsageMatch,
} from '../types.ts';
import { isPathInside } from '../util/fs.ts';
import { parseModule, scriptLangOf, useMember, type DynamicHit, type FileModel, type FileSummary, type ModuleUse, type PackageImport, type ParseOutcome, type SpecifierResolver } from './ast.ts';
import { computeIndirectPaths, createResolver, extractSpecifiers, loadPathAliases } from './callgraph.ts';

export const CODE_EXTENSIONS: readonly string[] = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.vue', '.svelte'];
export const BUILTIN_EXCLUDED_DIRS: readonly string[] = ['node_modules', '.git', 'dist', 'build', 'coverage', '.patch-pilot'];
export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_FILES = 20_000;

// generated/cache dirs, always pruned
export const GENERATED_DIRS: readonly string[] = [
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.cache',
  '.parcel-cache',
  '.output',
  '.vercel',
  '.yarn',
  '.pnpm-store',
  'bower_components',
  'jspm_packages',
];

// search_code exts, never lockfiles or .env
export const SEARCH_EXTENSIONS: readonly string[] = [
  ...CODE_EXTENSIONS,
  '.json',
  '.json5',
  '.jsonc',
  '.md',
  '.mdx',
  '.yml',
  '.yaml',
  '.html',
  '.htm',
  '.css',
  '.scss',
  '.less',
  '.sh',
  '.toml',
  '.graphql',
  '.gql',
  '.ejs',
  '.hbs',
  '.handlebars',
  '.pug',
  '.txt',
];

// huge, not code
export const LOCKFILE_NAMES: readonly string[] = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'];

// longer lines count as minified, skipped
export const MINIFIED_LINE_LENGTH = 1000;

export interface WalkOptions {
  // config.exclude globs
  exclude: readonly string[];
  maxFiles?: number;
  maxFileBytes?: number;
  // defaults to CODE_EXTENSIONS
  extensions?: readonly string[];
  respectGitignore?: boolean;
  signal?: AbortSignal;
  // all exts, binaries still skipped
  anyExtension?: boolean;
  // skip .d.ts and .min.*, default true
  skipGenerated?: boolean;
}

export interface WalkResult {
  files: ProjectFile[];
  // hit the file cap
  truncated: boolean;
  skipped: { path: string; reason: 'too-large' | 'binary' }[];
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

// glob to unanchored regex: **, *, ?, [...], {a,b}
function globBody(glob: string): string {
  let out = '';
  let i = 0;
  let braceDepth = 0;
  while (i < glob.length) {
    const ch = glob[i] as string;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        const before = i === 0 || glob[i - 1] === '/';
        let j = i + 2;
        while (glob[j] === '*') j += 1;
        const after = j >= glob.length || glob[j] === '/';
        if (before && after) {
          if (j >= glob.length) {
            // trailing **: the dir and everything below
            if (out.endsWith('\\/')) {
              out = `${out.slice(0, -2)}(?:\\/.*)?`;
            } else {
              out += '.*';
            }
            i = j;
          } else {
            // **/ is zero or more dirs
            out += '(?:.*\\/)?';
            i = j + 1;
          }
          continue;
        }
        out += '[^/]*';
        i = j;
        continue;
      }
      out += '[^/]*';
      i += 1;
      continue;
    }
    if (ch === '?') {
      out += '[^/]';
      i += 1;
      continue;
    }
    if (ch === '[') {
      const close = glob.indexOf(']', i + 2);
      if (close !== -1) {
        let cls = glob.slice(i + 1, close);
        if (cls.startsWith('!')) cls = `^${cls.slice(1)}`;
        out += `[${cls.replace(/\\/g, '\\\\')}]`;
        i = close + 1;
        continue;
      }
      out += '\\[';
      i += 1;
      continue;
    }
    if (ch === '{') {
      braceDepth += 1;
      out += '(?:';
      i += 1;
      continue;
    }
    if (ch === '}' && braceDepth > 0) {
      braceDepth -= 1;
      out += ')';
      i += 1;
      continue;
    }
    if (ch === ',' && braceDepth > 0) {
      out += '|';
      i += 1;
      continue;
    }
    if (ch === '\\' && i + 1 < glob.length) {
      out += escapeRegex(glob[i + 1] as string);
      i += 2;
      continue;
    }
    out += escapeRegex(ch);
    i += 1;
  }
  while (braceDepth > 0) {
    out += ')';
    braceDepth -= 1;
  }
  return out;
}

// anchored, relative posix paths
export function globToRegExp(glob: string): RegExp {
  const g = glob.trim().replace(/^\.\//, '').replace(/^\/+/, '');
  return new RegExp(`^${globBody(g)}$`);
}

interface CompiledGlob {
  re: RegExp;
  // no slash: basename at any depth
  basename: boolean;
}

function compileGlobs(globs: readonly string[]): CompiledGlob[] {
  const out: CompiledGlob[] = [];
  for (const raw of globs) {
    // "vendor/" means the dir, which is tested without the slash
    const glob = raw.trim().replace(/\/+$/, '');
    if (glob === '' || glob.startsWith('#')) continue;
    try {
      out.push({ re: globToRegExp(glob), basename: !glob.includes('/') });
    } catch {
      // bad glob, ignore
    }
  }
  return out;
}

function matchesCompiled(globs: readonly CompiledGlob[], relPath: string): boolean {
  if (globs.length === 0) return false;
  const base = relPath.slice(relPath.lastIndexOf('/') + 1);
  return globs.some((g) => g.re.test(relPath) || (g.basename && g.re.test(base)));
}

// slashless globs match basenames
export function matchesGlob(relPath: string, glob: string): boolean {
  return matchesCompiled(compileGlobs([glob]), relPath);
}

interface GitignoreRule {
  re: RegExp;
  negate: boolean;
  dirOnly: boolean;
}

// root .gitignore semantics only
export function parseGitignore(text: string): GitignoreRule[] {
  const rules: GitignoreRule[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.replace(/(?<!\\)\s+$/, '');
    if (line === '' || line.startsWith('#')) continue;
    let negate = false;
    if (line.startsWith('!')) {
      negate = true;
      line = line.slice(1);
    } else if (line.startsWith('\\!') || line.startsWith('\\#')) {
      line = line.slice(1);
    }
    let dirOnly = false;
    if (line.endsWith('/')) {
      dirOnly = true;
      line = line.replace(/\/+$/, '');
    }
    if (line === '') continue;
    const anchored = line.includes('/');
    const body = globBody(line.replace(/^\/+/, ''));
    const re = new RegExp(anchored ? `^${body}$` : `^(?:.*\\/)?${body}$`);
    rules.push({ re, negate, dirOnly });
  }
  return rules;
}

// last matching rule wins
export function isGitignored(rules: readonly GitignoreRule[], relPath: string, isDir: boolean): boolean {
  let ignored = false;
  for (const rule of rules) {
    if (rule.dirOnly && !isDir) continue;
    if (rule.re.test(relPath)) ignored = !rule.negate;
  }
  return ignored;
}

async function loadGitignore(root: string): Promise<GitignoreRule[]> {
  try {
    return parseGitignore(await readFile(path.join(root, '.gitignore'), 'utf8'));
  } catch {
    return [];
  }
}

const TEST_DIRS = new Set(['test', 'tests', '__tests__', '__test__', '__mocks__', '__fixtures__', 'spec', 'specs', 'e2e', 'cypress', 'playwright']);
const SCRIPT_DIRS = new Set(['scripts', 'script', 'bin', 'tools']);
const TEST_FILE = /\.(?:test|spec|e2e|cy|stories)\.[cm]?[jt]sx?$/i;
const TEST_BASENAME = /^tests?\.[cm]?[jt]sx?$/i;
const CONFIG_FILE = /(?:\.config(?:\.[\w-]+)?|\.conf)\.[cm]?[jt]sx?$/i;
const RC_FILE = /^\.[\w.-]*rc(?:\.[\w-]+)?\.[cm]?[jt]s$/i;
const TASK_FILE = /^(?:gruntfile|gulpfile|jakefile)(?:\.[\w-]+)?\.[cm]?[jt]s$/i;
const WORKSPACE_SCRIPTS = /^(?:packages|apps|libs|modules)\/[^/]+\/(?:scripts|script|bin|tools)\//;

// source/test/config/scripts by path
export function classifyFile(relPath: string): FileScope {
  const rel = relPath.replace(/\\/g, '/').replace(/^\.\//, '');
  const segments = rel.split('/');
  const base = segments[segments.length - 1] ?? rel;
  const dirs = segments.slice(0, -1);
  if (TEST_FILE.test(base) || TEST_BASENAME.test(base)) return 'test';
  if (CONFIG_FILE.test(base) || RC_FILE.test(base)) return 'config';
  if (dirs.some((d) => TEST_DIRS.has(d.toLowerCase()))) return 'test';
  if (dirs.length > 0 && (dirs[0] ?? '').startsWith('.')) return 'config';
  if (TASK_FILE.test(base)) return 'scripts';
  if ((dirs.length > 0 && SCRIPT_DIRS.has((dirs[0] ?? '').toLowerCase())) || WORKSPACE_SCRIPTS.test(rel)) return 'scripts';
  return 'source';
}

const SCOPE_ORDER: Record<FileScope, number> = { source: 0, scripts: 1, config: 2, test: 3 };

function abortIfNeeded(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const reason = signal.reason;
    throw reason instanceof Error ? reason : new Error('Aborted');
  }
}

async function mapPool<T, R>(items: readonly T[], concurrency: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      out[index] = await fn(items[index] as T, index);
    }
  });
  await Promise.all(workers);
  return out;
}

// head bytes for binary/shebang checks
async function readHead(file: string, bytes: number): Promise<Buffer> {
  const handle = await open(file, 'r');
  try {
    const buffer = Buffer.alloc(bytes);
    const { bytesRead } = await handle.read(buffer, 0, bytes, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

function isGeneratedFile(name: string): boolean {
  return /\.d\.[cm]?ts$/i.test(name) || /\.min\.[a-z]+$/i.test(name);
}

export async function walkProject(root: string, options: WalkOptions): Promise<WalkResult> {
  const maxFiles = options.maxFiles ?? MAX_FILES;
  const maxBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
  const extensions = new Set((options.extensions ?? CODE_EXTENSIONS).map((e) => e.toLowerCase()));
  const anyExtension = options.anyExtension === true;
  const skipGenerated = options.skipGenerated !== false;
  const excludes = compileGlobs(options.exclude ?? []);
  const gitignore = options.respectGitignore === false ? [] : await loadGitignore(root);
  const prunedDirs = new Set([...BUILTIN_EXCLUDED_DIRS, ...GENERATED_DIRS]);
  const lockfiles = new Set(LOCKFILE_NAMES);

  interface Candidate {
    rel: string;
    abs: string;
    ext: string;
    // extensionless node shebang
    shebangOnly: boolean;
  }
  const candidates: Candidate[] = [];
  let truncated = false;
  const queue: string[] = [''];
  while (queue.length > 0 && !truncated) {
    abortIfNeeded(options.signal);
    const relDir = queue.shift() as string;
    let entries;
    try {
      entries = await readdir(relDir === '' ? root : path.join(root, relDir), { withFileTypes: true });
    } catch {
      continue; // unreadable dir
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const rel = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (prunedDirs.has(entry.name)) continue;
        if (matchesCompiled(excludes, rel) || isGitignored(gitignore, rel, true)) continue;
        queue.push(rel);
        continue;
      }
      if (!entry.isFile()) continue;
      const name = entry.name;
      if (name.startsWith('.env') || lockfiles.has(name)) continue;
      if (skipGenerated && isGeneratedFile(name)) continue;
      const ext = path.extname(name).toLowerCase();
      const shebangOnly = ext === '' && !anyExtension && extensions.has('.js') && !name.startsWith('.');
      if (!anyExtension && !extensions.has(ext) && !shebangOnly) continue;
      if (matchesCompiled(excludes, rel) || isGitignored(gitignore, rel, false)) continue;
      const abs = path.join(root, rel);
      if (shebangOnly) {
        // extensionless needs a node shebang
        const head = await readHead(abs, 200).catch(() => null);
        const first = head ? (head.toString('utf8').split('\n')[0] ?? '') : '';
        if (!/^#!.*\bnode\b/.test(first)) continue;
      }
      if (candidates.length >= maxFiles) {
        truncated = true;
        break;
      }
      candidates.push({ rel, abs, ext, shebangOnly });
    }
  }

  const skipped: WalkResult['skipped'] = [];
  const checked = await mapPool(candidates, 32, async (c): Promise<ProjectFile | null> => {
    abortIfNeeded(options.signal);
    let size: number;
    try {
      size = (await stat(c.abs)).size;
    } catch {
      return null;
    }
    if (size > maxBytes) {
      if (!c.shebangOnly) skipped.push({ path: c.rel, reason: 'too-large' });
      return null;
    }
    let head: Buffer;
    try {
      head = await readHead(c.abs, 8000);
    } catch {
      return null;
    }
    if (head.includes(0)) {
      if (!c.shebangOnly) skipped.push({ path: c.rel, reason: 'binary' });
      return null;
    }
    return { path: c.rel, abs: c.abs, size, ext: c.ext, scope: classifyFile(c.rel) };
  });
  const files = checked.filter((f): f is ProjectFile => f !== null).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  skipped.sort((a, b) => (a.path < b.path ? -1 : 1));
  return { files, truncated, skipped };
}

// tiny js lexer for masking

const REGEX_PREFIX_CHARS = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^']);
const REGEX_PREFIX_WORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);

function isIdentStart(ch: string): boolean {
  return /[A-Za-z_$\u0080-￿]/.test(ch);
}

function isIdentPart(ch: string): boolean {
  return /[\w$\u0080-￿]/.test(ch);
}

// blank comments (and strings unless keepStrings), offsets kept
export function maskSource(source: string, options: { keepStrings?: boolean } = {}): string {
  const keep = options.keepStrings === true;
  const n = source.length;
  const out: string[] = new Array(n);
  for (let k = 0; k < n; k += 1) out[k] = source[k] as string;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k += 1) {
      const c = out[k];
      if (c !== '\n' && c !== '\r') out[k] = ' ';
    }
  };
  let i = 0;
  if (source.startsWith('#!')) {
    const end = source.indexOf('\n');
    i = end === -1 ? n : end;
    blank(0, i);
  }
  let mode: 'code' | 'template' = 'code';
  const templateStack: number[] = [];
  let braceDepth = 0;
  let lastChar = '';
  let lastWord = '';
  while (i < n) {
    const ch = source[i] as string;
    if (mode === 'template') {
      if (ch === '\\') {
        if (!keep) blank(i, i + 2);
        i += 2;
        continue;
      }
      if (ch === '`') {
        mode = 'code';
        lastChar = '`';
        lastWord = '';
        i += 1;
        continue;
      }
      if (ch === '$' && source[i + 1] === '{') {
        templateStack.push(braceDepth);
        braceDepth += 1;
        mode = 'code';
        lastChar = '{';
        lastWord = '';
        i += 2;
        continue;
      }
      if (!keep) blank(i, i + 1);
      i += 1;
      continue;
    }
    const next = source[i + 1];
    if (ch === '/' && next === '/') {
      let end = source.indexOf('\n', i);
      if (end === -1) end = n;
      blank(i, end);
      i = end;
      continue;
    }
    if (ch === '/' && next === '*') {
      const close = source.indexOf('*/', i + 2);
      const end = close === -1 ? n : close + 2;
      blank(i, end);
      i = end;
      continue;
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < n) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === ch) break;
        if (c === '\n') break;
        j += 1;
      }
      const closed = j < n && source[j] === ch;
      if (!keep) blank(i + 1, Math.min(j, n));
      i = closed ? j + 1 : j;
      lastChar = ch;
      lastWord = '';
      continue;
    }
    if (ch === '`') {
      mode = 'template';
      i += 1;
      continue;
    }
    if (ch === '/') {
      const regexAllowed = lastChar === '' || REGEX_PREFIX_CHARS.has(lastChar) || (lastChar === 'w' && REGEX_PREFIX_WORDS.has(lastWord));
      if (regexAllowed) {
        let j = i + 1;
        let inClass = false;
        let ok = false;
        while (j < n) {
          const c = source[j];
          if (c === '\n') break;
          if (c === '\\') {
            j += 2;
            continue;
          }
          if (c === '[') inClass = true;
          else if (c === ']') inClass = false;
          else if (c === '/' && !inClass) {
            ok = true;
            break;
          }
          j += 1;
        }
        if (ok) {
          if (!keep) blank(i + 1, j);
          j += 1;
          while (j < n && /[a-z]/i.test(source[j] as string)) j += 1;
          i = j;
          lastChar = ')';
          lastWord = '';
          continue;
        }
      }
      lastChar = '/';
      lastWord = '';
      i += 1;
      continue;
    }
    if (ch === '{') {
      braceDepth += 1;
      lastChar = '{';
      lastWord = '';
      i += 1;
      continue;
    }
    if (ch === '}') {
      if (templateStack.length > 0 && braceDepth - 1 === templateStack[templateStack.length - 1]) {
        templateStack.pop();
        braceDepth -= 1;
        mode = 'template';
        i += 1;
        continue;
      }
      braceDepth = Math.max(0, braceDepth - 1);
      lastChar = '}';
      lastWord = '';
      i += 1;
      continue;
    }
    if (isIdentStart(ch) || /[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < n && isIdentPart(source[j] as string)) j += 1;
      lastWord = source.slice(i, j);
      lastChar = 'w';
      i = j;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i += 1;
      continue;
    }
    lastChar = ch === ')' || ch === ']' ? ')' : ch;
    lastWord = '';
    i += 1;
  }
  return out.join('');
}

// .vue/.svelte: only <script> blocks survive
export function extractScriptBlocks(source: string): string {
  const out: string[] = [];
  let last = 0;
  const re = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi;
  const spaces = (text: string): string => text.replace(/[^\n\r]/g, ' ');
  for (const m of source.matchAll(re)) {
    const start = (m.index ?? 0) + m[0].indexOf('>') + 1;
    const end = start + (m[1] ?? '').length;
    out.push(spaces(source.slice(last, start)));
    out.push(source.slice(start, end));
    last = end;
  }
  out.push(spaces(source.slice(last)));
  return out.join('');
}

function scriptOf(source: string, relPath: string): string {
  const text = source.charCodeAt(0) === 0xfeff ? ` ${source.slice(1)}` : source;
  const ext = path.extname(relPath).toLowerCase();
  return ext === '.vue' || ext === '.svelte' ? extractScriptBlocks(text) : text;
}

class LineIndex {
  private readonly starts: number[];
  constructor(text: string) {
    this.starts = [0];
    for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
  }
  // 1-based
  lineOf(offset: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] as number) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
  startOf(line: number): number {
    return this.starts[line - 1] ?? 0;
  }
}

function splitLines(text: string): string[] {
  return text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
}

function capText(text: string, max = 240): string {
  const t = text.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export interface SearchOptions {
  exclude: readonly string[];
  fileGlob?: string;
  maxResults: number;
  // context lines, default 0
  contextLines?: number;
  // defaults to true
  skipMinified?: boolean;
  signal?: AbortSignal;
  // truncate after this, default 15 s
  timeBudgetMs?: number;
}

function contextOf(lines: readonly string[], index: number, count: number): { before: string[]; after: string[] } {
  return {
    before: lines.slice(Math.max(0, index - count), index).map((l) => capText(l, 200)),
    after: lines.slice(index + 1, index + 1 + count).map((l) => capText(l, 200)),
  };
}

// total is uncapped, matches capped
export async function searchProject(
  root: string,
  pattern: RegExp,
  options: SearchOptions,
): Promise<{ matches: SearchMatch[]; total: number; truncated: boolean }> {
  const re = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ''));
  const walk = await walkProject(root, {
    exclude: options.exclude,
    extensions: SEARCH_EXTENSIONS,
    anyExtension: Boolean(options.fileGlob),
    skipGenerated: !options.fileGlob,
    signal: options.signal,
  });
  const glob = options.fileGlob ? compileGlobs([options.fileGlob]) : [];
  const files = walk.files
    .filter((f) => glob.length === 0 || matchesCompiled(glob, f.path))
    .sort((a, b) => SCOPE_ORDER[a.scope] - SCOPE_ORDER[b.scope] || (a.path < b.path ? -1 : 1));
  const context = Math.max(0, options.contextLines ?? 0);
  const skipMinified = options.skipMinified !== false;
  const maxResults = Math.max(0, options.maxResults);
  const deadline = Date.now() + (options.timeBudgetMs ?? 15_000);
  const matches: SearchMatch[] = [];
  let total = 0;
  let truncated = walk.truncated;
  for (const file of files) {
    abortIfNeeded(options.signal);
    if (Date.now() > deadline) {
      truncated = true;
      break;
    }
    let text: string;
    try {
      text = await readFile(file.abs, 'utf8');
    } catch {
      continue;
    }
    const lines = splitLines(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] as string;
      if (skipMinified && line.length > MINIFIED_LINE_LENGTH) continue;
      if (!re.test(line)) continue;
      total += 1;
      if (matches.length < maxResults) {
        const match: SearchMatch = { path: file.path, line: i + 1, text: capText(line), scope: file.scope };
        if (context > 0) match.context = contextOf(lines, i, context);
        matches.push(match);
      }
    }
  }
  return { matches, total, truncated: truncated || total > matches.length };
}

const SPEC = String.raw`(['"\x60])([^'"\x60\n]+)\1`;
const ESM_IMPORT = new RegExp(
  String.raw`(?<![\w$.])import\s+(type\s+)?((?:[\w$]+)?\s*,?\s*(?:\*\s*as\s+[\w$]+|\{[^}]*\})?)\s*from\s*(['"\x60])([^'"\x60\n]+)\3`,
  'g',
);
const ESM_SIDE_EFFECT = new RegExp(String.raw`(?<![\w$.])import\s*${SPEC}`, 'g');
const DYNAMIC_IMPORT = new RegExp(String.raw`(?<![\w$.])import\s*\(\s*${SPEC}\s*\)`, 'g');
const RE_EXPORT = new RegExp(String.raw`(?<![\w$.])export\s+(type\s+)?(\*(?:\s*as\s+[\w$]+)?|\{[^}]*\})\s*from\s*(['"\x60])([^'"\x60\n]+)\3`, 'g');
const REQUIRE_CALL = new RegExp(String.raw`(?<![\w$.])require\s*\(\s*${SPEC}\s*\)`, 'g');
const LHS_BEFORE = /(?:\b(?:const|let|var)\s+|\bimport\s+)?((?:[\w$]+\s*\.\s*)*[\w$]+|\{[^{}]*\})\s*=\s*(?:await\s+)?$/;
const MEMBER_AFTER = /^\s*(?:\?\.)?\.\s*([A-Za-z_$][\w$]*)/;
const BRACKET_AFTER = /^\s*(?:\?\.)?\[\s*(['"\x60])([^'"\x60\n]+)\1\s*\]/;
const CALL_AFTER = /^\s*(?:\?\.)?\(/;

function matchPackage(spec: string, packages: readonly string[]): { pkg: string; subpath?: string } | null {
  let best: { pkg: string; subpath?: string } | null = null;
  for (const pkg of packages) {
    if (spec === pkg) return { pkg };
    if (spec.startsWith(`${pkg}/`) && (!best || pkg.length > best.pkg.length)) {
      const subpath = spec.slice(pkg.length + 1);
      best = subpath ? { pkg, subpath } : { pkg };
    }
  }
  return best;
}

function isIdentifier(text: string): boolean {
  return /^[A-Za-z_$][\w$]*$/.test(text);
}

// esm clause: { a, b as c, default as d, type T }
function parseEsmNamed(inner: string): { named: Record<string, string>; defaultLocal: string | null } {
  const named: Record<string, string> = {};
  let defaultLocal: string | null = null;
  for (const part of inner.split(',')) {
    const item = part.trim();
    if (item === '' || /^type\s/.test(item)) continue;
    const m = /^(['"]?)([^'"\s]+)\1(?:\s+as\s+([\w$]+))?$/.exec(item);
    if (!m) continue;
    const imported = m[2] as string;
    const local = m[3] ?? imported;
    if (!isIdentifier(local)) continue;
    if (imported === 'default') defaultLocal = local;
    else named[imported] = local;
  }
  return { named, defaultLocal };
}

// cjs destructuring, one level: { a, b: c, d = 1, ...rest }
function parseDestructure(inner: string): { named: Record<string, string>; rest: string | null } {
  const named: Record<string, string> = {};
  let rest: string | null = null;
  let depth = 0;
  let current = '';
  const parts: string[] = [];
  for (const ch of inner) {
    if (ch === '{' || ch === '[' || ch === '(') depth += 1;
    if (ch === '}' || ch === ']' || ch === ')') depth -= 1;
    if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  for (const part of parts) {
    const item = part.trim();
    if (item === '') continue;
    const restMatch = /^\.\.\.\s*([\w$]+)$/.exec(item);
    if (restMatch) {
      rest = restMatch[1] as string;
      continue;
    }
    const m = /^([\w$]+|['"][^'"]+['"])\s*(?::\s*([\w$]+))?\s*(?:=[\s\S]*)?$/.exec(item);
    if (!m) continue;
    const key = (m[1] as string).replace(/^['"]|['"]$/g, '');
    const local = m[2] ?? (isIdentifier(key) ? key : null);
    if (local && isIdentifier(local)) named[key] = local;
  }
  return { named, rest };
}

function statementText(script: string, lines: LineIndex, start: number, end: number): string {
  const lineStart = lines.startOf(lines.lineOf(start));
  let lineEnd = script.indexOf('\n', end);
  if (lineEnd === -1) lineEnd = script.length;
  return capText(script.slice(lineStart, lineEnd).replace(/\s+/g, ' '), 200);
}

// regex fallback for unparseable files
export function findImportsInSourceRegex(source: string, relPath: string, packages: readonly string[]): ImportSite[] {
  if (packages.length === 0) return [];
  const script = scriptOf(source, relPath);
  if (!packages.some((p) => script.includes(p))) return [];
  const code = maskSource(script, { keepStrings: true });
  const full = maskSource(script, { keepStrings: false });
  const lines = new LineIndex(script);
  const scope = classifyFile(relPath);
  const sites: ImportSite[] = [];
  const seen = new Set<string>();
  // not inside a string or comment
  const isCode = (index: number, keyword: string): boolean => full.startsWith(keyword, index);
  const add = (site: Omit<ImportSite, 'path' | 'scope'>): void => {
    const key = `${site.line}:${site.kind}:${site.binding ?? ''}:${JSON.stringify(site.named ?? {})}:${site.subpath ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    const out: ImportSite = { path: relPath, line: site.line, statement: site.statement, binding: site.binding, kind: site.kind, scope };
    if (site.named && Object.keys(site.named).length > 0) out.named = site.named;
    if (site.subpath) out.subpath = site.subpath;
    sites.push(out);
  };

  for (const m of code.matchAll(ESM_IMPORT)) {
    const index = m.index ?? 0;
    if (!isCode(index, 'import') || m[1]) continue; // import type is erased
    const target = matchPackage(m[4] as string, packages);
    if (!target) continue;
    const clause = (m[2] ?? '').trim();
    const line = lines.lineOf(index);
    const statement = statementText(script, lines, index, index + m[0].length);
    const base = { line, statement, subpath: target.subpath };
    const defaultMatch = /^([\w$]+)\s*(?:,|$)/.exec(clause);
    const namespaceMatch = /\*\s*as\s+([\w$]+)/.exec(clause);
    const namedMatch = /\{([^}]*)\}/.exec(clause);
    const parsed = namedMatch ? parseEsmNamed(namedMatch[1] ?? '') : { named: {}, defaultLocal: null };
    const defaultLocal = defaultMatch && defaultMatch[1] !== 'type' ? (defaultMatch[1] as string) : parsed.defaultLocal;
    if (defaultLocal) add({ ...base, kind: 'esm-default', binding: defaultLocal, named: parsed.named });
    if (namespaceMatch) add({ ...base, kind: 'esm-namespace', binding: namespaceMatch[1] as string });
    if (!defaultLocal && !namespaceMatch && namedMatch) add({ ...base, kind: 'esm-named', binding: null, named: parsed.named });
  }

  for (const m of code.matchAll(ESM_SIDE_EFFECT)) {
    const index = m.index ?? 0;
    if (!isCode(index, 'import')) continue;
    const target = matchPackage(m[2] as string, packages);
    if (!target) continue;
    add(
      { line: lines.lineOf(index), statement: statementText(script, lines, index, index + m[0].length), kind: 'esm-side-effect', binding: null, subpath: target.subpath },
    );
  }

  for (const m of code.matchAll(DYNAMIC_IMPORT)) {
    const index = m.index ?? 0;
    if (!isCode(index, 'import')) continue;
    const target = matchPackage(m[2] as string, packages);
    if (!target) continue;
    const before = code.slice(Math.max(0, index - 300), index);
    const lhs = LHS_BEFORE.exec(before);
    let binding: string | null = null;
    let named: Record<string, string> | undefined;
    const start = lhs ? index - lhs[0].length : index;
    if (lhs) {
      const target1 = lhs[1] as string;
      if (target1.startsWith('{')) named = parseDestructure(target1.slice(1, -1)).named;
      else if (isIdentifier(target1)) binding = target1;
    }
    add(
      { line: lines.lineOf(index), statement: statementText(script, lines, start, index + m[0].length), kind: 'dynamic-import', binding, named, subpath: target.subpath },
    );
  }

  for (const m of code.matchAll(RE_EXPORT)) {
    const index = m.index ?? 0;
    if (!isCode(index, 'export') || m[1]) continue;
    const target = matchPackage(m[4] as string, packages);
    if (!target) continue;
    const clause = (m[2] ?? '').trim();
    let named: Record<string, string> | undefined;
    if (clause.startsWith('{')) {
      named = {};
      for (const part of clause.slice(1, -1).split(',')) {
        const item = part.trim();
        if (item === '' || /^type\s/.test(item)) continue;
        const pm = /^([\w$]+)(?:\s+as\s+([\w$]+))?$/.exec(item);
        if (pm) named[pm[1] as string] = pm[2] ?? (pm[1] as string);
      }
    }
    add({ line: lines.lineOf(index), statement: statementText(script, lines, index, index + m[0].length), kind: 're-export', binding: null, named, subpath: target.subpath });
  }

  for (const m of code.matchAll(REQUIRE_CALL)) {
    const index = m.index ?? 0;
    if (!isCode(index, 'require')) continue;
    const target = matchPackage(m[2] as string, packages);
    if (!target) continue;
    const end = index + m[0].length;
    const before = code.slice(Math.max(0, index - 300), index);
    const after = code.slice(end, end + 200);
    const lhsMatch = LHS_BEFORE.exec(before);
    const lhs = lhsMatch ? (lhsMatch[1] as string).replace(/\s+/g, '') : null;
    const memberMatch = MEMBER_AFTER.exec(after) ?? null;
    const bracketMatch = memberMatch ? null : BRACKET_AFTER.exec(after);
    const member = memberMatch ? (memberMatch[1] as string) : bracketMatch ? (bracketMatch[2] as string) : null;
    const line = lines.lineOf(index);
    const statement = statementText(script, lines, index, end);
    const base = { line, statement, subpath: target.subpath };
    if (lhs && /^(?:module\.exports|exports)(?:\.|$)/.test(lhs)) {
      add({ ...base, kind: 're-export', binding: null, named: member ? { [member]: member } : undefined });
      continue;
    }
    if (lhs && lhs.startsWith('{')) {
      const parsed = parseDestructure(lhs.slice(1, -1));
      add({ ...base, kind: 'cjs-destructure', binding: parsed.rest, named: parsed.named });
      continue;
    }
    const local = lhs && isIdentifier(lhs) ? lhs : null;
    if (member) {
      if (member === 'default') add({ ...base, kind: 'cjs-require', binding: local });
      // no local, e.g. require('lodash').merge(a)
      else add({ ...base, kind: 'cjs-member', binding: null, named: local ? { [member]: local } : undefined });
      continue;
    }
    if (CALL_AFTER.test(after)) {
      // require('debug')('app') calls the default
      add({ ...base, kind: 'cjs-require', binding: null });
      continue;
    }
    add({ ...base, kind: 'cjs-require', binding: local });
  }

  sites.sort((a, b) => a.line - b.line);
  return sites;
}

// "_.template()" or "lodash.template" -> "template"
export function normalizeSymbol(symbol: string): string {
  const s = symbol.trim().replace(/\(\s*\)$/, '').replace(/^new\s+/, '');
  const last = s.split('.').pop() ?? s;
  return last.replace(/^\[['"`]?|['"`]?\]$/g, '').trim();
}

function subpathMember(subpath: string): string {
  const last = subpath.split('/').filter(Boolean).pop() ?? subpath;
  return last.replace(/\.[cm]?[jt]sx?$/i, '');
}

// regex fallback for unparseable files
export function findUsageInSourceRegex(source: string, relPath: string, sites: readonly ImportSite[], symbol?: string, contextLines?: number): UsageMatch[] {
  if (sites.length === 0) return [];
  const script = scriptOf(source, relPath);
  const full = maskSource(script, { keepStrings: false });
  const code = maskSource(script, { keepStrings: true });
  const index = new LineIndex(script);
  const lines = splitLines(script);
  const scope = sites[0]?.scope ?? classifyFile(relPath);
  const wanted = symbol === undefined || symbol.trim() === '' ? null : normalizeSymbol(symbol);
  const context = Math.max(0, contextLines ?? 0);
  const found: { offset: number; binding: string; member: string | null }[] = [];
  const seen = new Set<string>();
  const push = (offset: number, binding: string, member: string | null): void => {
    const key = `${offset}:${binding}:${member ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ offset, binding, member });
  };

  const trackWhole = (binding: string, calledAs: string | null): void => {
    const b = escapeRegex(binding);
    for (const m of full.matchAll(new RegExp(String.raw`(?<![\w$.])${b}\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)`, 'g'))) {
      push(m.index ?? 0, binding, m[1] as string);
    }
    for (const m of code.matchAll(new RegExp(String.raw`(?<![\w$.])${b}\s*(?:\?\.)?\[\s*(['"\x60])([^'"\x60\n]+)\1\s*\]`, 'g'))) {
      const at = m.index ?? 0;
      if (full.startsWith(binding, at)) push(at, binding, m[2] as string);
    }
    for (const m of full.matchAll(new RegExp(String.raw`(?<![\w$.])${b}\s*(?:\?\.)?\(`, 'g'))) {
      const at = m.index ?? 0;
      if (/\bfunction\s*\*?\s*$/.test(full.slice(Math.max(0, at - 20), at))) continue;
      push(at, binding, calledAs);
    }
  };

  const trackNamed = (local: string, imported: string): void => {
    const l = escapeRegex(local);
    for (const m of full.matchAll(new RegExp(String.raw`(?<![\w$.])${l}\s*(?:\?\.)?\(`, 'g'))) {
      const at = m.index ?? 0;
      if (/\bfunction\s*\*?\s*$/.test(full.slice(Math.max(0, at - 20), at))) continue;
      push(at, local, imported);
    }
    for (const m of full.matchAll(new RegExp(String.raw`(?<![\w$.])${l}\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)`, 'g'))) {
      push(m.index ?? 0, local, m[1] as string);
    }
  };

  for (const site of sites) {
    if (site.kind === 're-export') {
      const offset = index.startOf(site.line);
      for (const imported of Object.keys(site.named ?? {})) push(offset, '(re-export)', imported);
      continue;
    }
    const sub = site.subpath ? subpathMember(site.subpath) : null;
    if (site.binding) trackWhole(site.binding, sub);
    for (const [imported, local] of Object.entries(site.named ?? {})) trackNamed(local, imported);
    if (!site.binding && (site.kind === 'cjs-require' || site.kind === 'cjs-member')) {
      // require('pkg')(...) with no local
      const lineStart = index.startOf(site.line);
      const lineText = full.slice(lineStart, full.indexOf('\n', lineStart) === -1 ? full.length : full.indexOf('\n', lineStart));
      const direct = /(?<![\w$.])require\s*\(\s*(['"\x60])\s*\1\s*\)\s*(?:(?:\?\.)?\.\s*([A-Za-z_$][\w$]*))?\s*(?:\?\.)?\(/.exec(lineText);
      if (direct) push(lineStart + (direct.index ?? 0), 'require', direct[2] ?? sub);
    }
  }

  found.sort((a, b) => a.offset - b.offset);
  const out: UsageMatch[] = [];
  for (const f of found) {
    if (wanted !== null && f.member !== wanted) continue;
    const line = index.lineOf(f.offset);
    const match: UsageMatch = { path: relPath, line, text: capText(lines[line - 1] ?? ''), scope, binding: f.binding, member: f.member };
    if (context > 0) match.context = contextOf(lines, line - 1, context);
    out.push(match);
  }
  return out;
}

// parser first, regex per-file fallback

// parse cache for get_usage, skips big files
const PARSE_CACHE_SIZE = 32;
const PARSE_CACHE_MAX_CHARS = 256 * 1024;
const parseCache = new Map<string, { script: string; outcome: ParseOutcome }>();

function langOf(relPath: string, source: string): ReturnType<typeof scriptLangOf> | undefined {
  const ext = path.extname(relPath).toLowerCase();
  return ext === '.vue' || ext === '.svelte' ? scriptLangOf(source) : undefined;
}

// reuse if text unchanged
function parseCached(script: string, relPath: string, source: string): ParseOutcome {
  const hit = parseCache.get(relPath);
  if (hit && hit.script === script) return hit.outcome;
  const outcome = parseModule(script, relPath, langOf(relPath, source));
  parseCache.delete(relPath);
  if (script.length > PARSE_CACHE_MAX_CHARS) return outcome;
  parseCache.set(relPath, { script, outcome });
  if (parseCache.size > PARSE_CACHE_SIZE) {
    const oldest = parseCache.keys().next().value;
    if (oldest !== undefined) parseCache.delete(oldest);
  }
  return outcome;
}

// same shape as the regex path
function sitesFromImports(script: string, relPath: string, imports: readonly PackageImport[], scope: FileScope): ImportSite[] {
  const lines = new LineIndex(script);
  const sites: ImportSite[] = [];
  const seen = new Set<string>();
  for (const entry of imports) {
    const rec = entry.import;
    const site: ImportSite = { path: relPath, line: lines.lineOf(rec.at), statement: statementText(script, lines, rec.span.start, rec.span.end), binding: rec.binding, kind: rec.kind, scope };
    if (rec.named && Object.keys(rec.named).length > 0) site.named = { ...rec.named };
    if (entry.subpath) site.subpath = entry.subpath;
    const key = `${site.line}:${site.kind}:${site.binding ?? ''}:${JSON.stringify(site.named ?? {})}:${site.subpath ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    sites.push(site);
  }
  sites.sort((a, b) => a.line - b.line);
  return sites;
}

// optionally one symbol
function matchesFromUses(script: string, relPath: string, scope: FileScope, uses: readonly ModuleUse[], symbol?: string, contextLines?: number): UsageMatch[] {
  const index = new LineIndex(script);
  const lines = splitLines(script);
  const wanted = symbol === undefined || symbol.trim() === '' ? null : normalizeSymbol(symbol);
  const context = Math.max(0, contextLines ?? 0);
  const out: UsageMatch[] = [];
  for (const use of uses) {
    const member = useMember(use);
    if (wanted !== null && member !== wanted) continue;
    const line = index.lineOf(use.at);
    const match: UsageMatch = { path: relPath, line, text: capText(lines[line - 1] ?? ''), scope, binding: use.local, member };
    if (context > 0) match.context = contextOf(lines, line - 1, context);
    out.push(match);
  }
  return out;
}

function dynamicFromHit(script: string, relPath: string, model: FileModel, hit: DynamicHit): DynamicAccess {
  return { path: relPath, line: model.lineOf(hit.at), text: capText(script.slice(hit.span.start, hit.span.end).replace(/\s+/g, ' '), 100), reason: hit.reason };
}

// parser first, regex fallback
export function findImportsInSource(source: string, relPath: string, packages: readonly string[]): ImportSite[] {
  if (packages.length === 0) return [];
  const script = scriptOf(source, relPath);
  if (!packages.some((p) => script.includes(p))) return [];
  const parsed = parseCached(script, relPath, source);
  if (parsed.ok) {
    try {
      return sitesFromImports(script, relPath, parsed.model.packageImports(packages), classifyFile(relPath));
    } catch {
      // odd shape, fall back to regex
    }
  }
  return findImportsInSourceRegex(source, relPath, packages);
}

// scope-aware, regex fallback
export function findUsageInSource(source: string, relPath: string, sites: readonly ImportSite[], symbol?: string, contextLines?: number): UsageMatch[] {
  if (sites.length === 0) return [];
  const script = scriptOf(source, relPath);
  const parsed = parseCached(script, relPath, source);
  if (parsed.ok) {
    try {
      const uses = parsed.model.usesForSites(sites);
      if (uses !== null) return matchesFromUses(script, relPath, sites[0]?.scope ?? classifyFile(relPath), uses, symbol, contextLines);
    } catch {
      // odd shape, fall back to regex
    }
  }
  return findUsageInSourceRegex(source, relPath, sites, symbol, contextLines);
}

// only files importing the package
export async function findUsage(
  root: string,
  sites: readonly ImportSite[],
  symbol: string | undefined,
  options: { contextLines?: number; maxResults?: number },
): Promise<UsageMatch[]> {
  const byPath = new Map<string, ImportSite[]>();
  for (const site of sites) {
    const list = byPath.get(site.path);
    if (list) list.push(site);
    else byPath.set(site.path, [site]);
  }
  const paths = [...byPath.keys()].sort((a, b) => {
    const sa = SCOPE_ORDER[byPath.get(a)?.[0]?.scope ?? 'source'];
    const sb = SCOPE_ORDER[byPath.get(b)?.[0]?.scope ?? 'source'];
    return sa - sb || (a < b ? -1 : 1);
  });
  const max = options.maxResults ?? 50;
  const out: UsageMatch[] = [];
  for (const rel of paths) {
    if (!isPathInside(root, rel)) continue;
    let text: string;
    try {
      text = await readFile(path.join(root, rel), 'utf8');
    } catch {
      continue;
    }
    out.push(...findUsageInSource(text, rel, byPath.get(rel) ?? [], symbol, options.contextLines));
    if (out.length >= max) break;
  }
  return out.slice(0, max);
}

function emptyEvidence(pkg: string, scannedFiles: number, truncated: boolean): UsageEvidence {
  const evidence: UsageEvidence = {
    package: pkg,
    imported: false,
    files: [],
    scopes: { source: 0, test: 0, config: 0, scripts: 0 },
    membersUsed: {},
    bindingCalls: 0,
    scannedFiles,
  };
  if (truncated) evidence.truncated = true;
  return evidence;
}

interface FileEvidence {
  pkg: string;
  sites: ImportSite[];
  usage: UsageMatch[];
  dynamic: DynamicAccess[];
}

// one file, packages it mentions
function analyzeForPackages(
  text: string,
  file: { path: string; scope: FileScope },
  present: readonly string[],
  summarize: ((model: FileModel) => void) | null,
): { method: 'ast' | 'regex'; entries: FileEvidence[] } | null {
  const script = scriptOf(text, file.path);
  if (!present.some((p) => script.includes(p))) return null;
  let parsed = parseModule(script, file.path, langOf(file.path, text));
  const entries: FileEvidence[] = [];
  if (parsed.ok) {
    const model = parsed.model;
    try {
      for (const pkg of present) {
        const analysis = model.analyzePackage(pkg);
        const sites = sitesFromImports(script, file.path, analysis.imports, file.scope);
        const dynamic = analysis.dynamic.map((hit) => dynamicFromHit(script, file.path, model, hit));
        if (sites.length === 0 && dynamic.length === 0) continue;
        entries.push({ pkg, sites, usage: sites.length > 0 ? matchesFromUses(script, file.path, file.scope, analysis.uses) : [], dynamic });
      }
      summarize?.(model);
      return { method: 'ast', entries };
    } catch (err) {
      entries.length = 0;
      parsed = { ok: false, line: 1, message: `analysis failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }
  for (const pkg of present) {
    const sites = findImportsInSourceRegex(text, file.path, [pkg]);
    if (sites.length === 0) continue;
    entries.push({
      pkg,
      sites,
      usage: findUsageInSourceRegex(text, file.path, sites),
      dynamic: [{ path: file.path, line: parsed.line, text: capText(`not parsed (${parsed.message}); scanned with patterns instead`, 160), reason: 'unparsed-file' }],
    });
  }
  return { method: 'regex', entries };
}

// dynamic accesses kept per package
export const MAX_DYNAMIC_ACCESS = 50;

function sortByScope<T extends { path: string; line: number }>(items: T[]): T[] {
  return items.sort((a, b) => SCOPE_ORDER[classifyFile(a.path)] - SCOPE_ORDER[classifyFile(b.path)] || (a.path < b.path ? -1 : a.path > b.path ? 1 : a.line - b.line));
}

// single walk for all packages
export async function collectUsageEvidence(root: string, packages: readonly string[], options: WalkOptions): Promise<Map<string, UsageEvidence>> {
  const names = [...new Set(packages.filter((p) => typeof p === 'string' && p.trim() !== ''))];
  const walk = await walkProject(root, options);
  const result = new Map<string, UsageEvidence>();
  for (const name of names) result.set(name, emptyEvidence(name, walk.files.length, walk.truncated));
  if (names.length === 0) return result;
  const aliases = await loadPathAliases(root);
  const keepBare = aliases.baseUrl !== null || aliases.paths.length > 0;
  const resolve: SpecifierResolver = createResolver(new Set(walk.files.map((f) => f.path)), aliases);
  const specifiers = new Map<string, string[]>();
  const summaries = new Map<string, FileSummary | null>();
  const perFile = await mapPool(walk.files, 16, async (file) => {
    abortIfNeeded(options.signal);
    let text: string;
    try {
      text = await readFile(file.abs, 'utf8');
    } catch {
      return null;
    }
    const specs = extractSpecifiers(text, keepBare);
    if (specs.length > 0) specifiers.set(file.path, specs);
    const present = names.filter((n) => text.includes(n));
    if (present.length === 0) return null;
    return analyzeForPackages(text, file, present, (model) => summaries.set(file.path, model.summarize(names, resolve)));
  });
  const votes = new Map<string, { ast: number; regex: number }>();
  const dynamic = new Map<string, DynamicAccess[]>();
  for (const r of perFile) {
    if (!r) continue;
    for (const entry of r.entries) {
      const evidence = result.get(entry.pkg);
      if (!evidence) continue;
      const vote = votes.get(entry.pkg) ?? { ast: 0, regex: 0 };
      vote[r.method] += 1;
      votes.set(entry.pkg, vote);
      if (entry.dynamic.length > 0) dynamic.set(entry.pkg, [...(dynamic.get(entry.pkg) ?? []), ...entry.dynamic]);
      if (entry.sites.length === 0) continue;
      evidence.imported = true;
      evidence.files.push(...entry.sites);
      for (const site of entry.sites) evidence.scopes[site.scope] += 1;
      for (const use of entry.usage) {
        if (use.member === null) evidence.bindingCalls += 1;
        else evidence.membersUsed[use.member] = (evidence.membersUsed[use.member] ?? 0) + 1;
      }
    }
  }

  for (const evidence of result.values()) {
    evidence.files.sort((a, b) => SCOPE_ORDER[a.scope] - SCOPE_ORDER[b.scope] || (a.path < b.path ? -1 : a.path > b.path ? 1 : a.line - b.line));
    evidence.membersUsed = Object.fromEntries(Object.entries(evidence.membersUsed).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)));
    const vote = votes.get(evidence.package);
    const method: AnalysisMethod = !vote || vote.regex === 0 ? 'ast' : vote.ast === 0 ? 'regex' : 'mixed';
    evidence.method = method;
    const found = dynamic.get(evidence.package);
    if (found && found.length > 0) evidence.dynamicAccess = sortByScope(found).slice(0, MAX_DYNAMIC_ACCESS);
  }

  // calls via own wrappers, re-exports
  if ([...result.values()].some((e) => e.imported) && summaries.size > 0) {
    const graph = await computeIndirectPaths({
      specifiers,
      resolve,
      summaries,
      ...(options.signal ? { signal: options.signal } : {}),
      load: async (rel) => {
        let text: string;
        try {
          text = await readFile(path.join(root, rel), 'utf8');
        } catch {
          return { summary: null, bytes: 0 };
        }
        const script = scriptOf(text, rel);
        const parsed = parseModule(script, rel, langOf(rel, text));
        try {
          return { summary: parsed.ok ? parsed.model.summarize(names, resolve) : null, bytes: text.length };
        } catch {
          return { summary: null, bytes: text.length };
        }
      },
    });
    for (const [pkg, paths] of graph.byPackage) {
      const evidence = result.get(pkg);
      if (evidence && paths.length > 0) evidence.indirectPaths = sortByScope<IndirectPath>(paths);
    }
    if (graph.capped) {
      const note: DynamicAccess = {
        path: graph.skipped[0] ?? '',
        line: 1,
        text: `the call graph stopped after parsing ${graph.parsedFiles} importing files; calls through the remaining files were not followed`,
        reason: 'unparsed-file',
      };
      for (const evidence of result.values()) if (evidence.imported) (evidence.dynamicAccess ??= []).push(note);
    }
  }
  return result;
}

// caps per dependent
export const DEPENDENT_MAX_FILES = 150;
export const DEPENDENT_MAX_BYTES = 2 * 1024 * 1024;
// dependents scanned, uses kept
export const DEPENDENT_MAX_PACKAGES = 10;
export const MAX_DEPENDENT_USAGE = 20;

const DEPENDENT_SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'test',
  'tests',
  '__tests__',
  'spec',
  'example',
  'examples',
  'docs',
  'doc',
  'benchmark',
  'benchmarks',
  'coverage',
  'fixtures',
  '.git',
  '.github',
]);
const DEPENDENT_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.jsx']);

// dir is the lockfile key
export interface DependentRef {
  name: string;
  version: string;
  dir?: string;
}

async function isDirectory(abs: string): Promise<boolean> {
  try {
    return (await stat(abs)).isDirectory();
  } catch {
    return false;
  }
}

async function installedVersion(root: string, dir: string): Promise<string | null> {
  try {
    const pkg = JSON.parse(await readFile(path.join(root, dir, 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : null;
  } catch {
    return null;
  }
}

// lockfile key, hoisted or pnpm
async function locateDependent(root: string, dep: DependentRef): Promise<string | null> {
  const candidates: string[] = [];
  if (dep.dir && dep.dir.split('/').includes('node_modules')) candidates.push(dep.dir);
  const folder = `${dep.name.replace('/', '+')}@${dep.version}`;
  candidates.push(`node_modules/${dep.name}`, `node_modules/.pnpm/${folder}/node_modules/${dep.name}`);
  // peer-suffixed store folders: <name>@<ver>_<peers>
  try {
    const store = await readdir(path.join(root, 'node_modules/.pnpm'));
    for (const entry of store.sort()) if (entry.startsWith(`${folder}_`)) candidates.push(`node_modules/.pnpm/${entry}/node_modules/${dep.name}`);
  } catch {
    // no pnpm store
  }
  let fallback: string | null = null;
  for (const dir of candidates) {
    if (!isPathInside(root, dir)) continue;
    const version = await installedVersion(root, dir);
    if (version === null) continue;
    if (version === dep.version) return dir;
    fallback ??= dir;
  }
  return fallback;
}

function looksMinified(text: string): boolean {
  if (text.length < 2000) return false;
  const lines = text.split('\n').length;
  return text.length / lines > 300;
}

// main, module, exports
async function entryFiles(root: string, dir: string): Promise<string[]> {
  let manifest: { main?: unknown; module?: unknown; exports?: unknown };
  try {
    manifest = JSON.parse(await readFile(path.join(root, dir, 'package.json'), 'utf8')) as typeof manifest;
  } catch {
    return [];
  }
  const specs: string[] = [];
  const collect = (value: unknown, depth: number): void => {
    if (typeof value === 'string') specs.push(value);
    else if (value && typeof value === 'object' && depth < 3) for (const v of Object.values(value as Record<string, unknown>)) collect(v, depth + 1);
  };
  collect(manifest.main, 0);
  collect(manifest.module, 0);
  collect(manifest.exports, 0);
  specs.push('index.js');
  const out: string[] = [];
  for (const spec of specs) {
    if (spec.includes('*')) continue;
    const base = path.posix.normalize(path.posix.join(dir, spec));
    if (!base.startsWith(`${dir}/`)) continue;
    for (const candidate of [base, `${base}.js`, `${base}/index.js`]) {
      if (!DEPENDENT_EXTENSIONS.has(path.extname(candidate).toLowerCase()) || isGeneratedFile(path.basename(candidate))) continue;
      try {
        if ((await stat(path.join(root, candidate))).isFile()) {
          if (!out.includes(candidate)) out.push(candidate);
          break;
        }
      } catch {
        // missing
      }
    }
  }
  return out;
}

// entry points first, capped
async function dependentFiles(root: string, dir: string): Promise<string[]> {
  const out: string[] = [];
  let bytes = 0;
  for (const entry of await entryFiles(root, dir)) {
    const segments = entry.slice(dir.length + 1).split('/');
    if (segments.slice(0, -1).some((s) => DEPENDENT_SKIP_DIRS.has(s))) continue;
    try {
      const size = (await stat(path.join(root, entry))).size;
      if (size > MAX_FILE_BYTES) continue;
      bytes += size;
      out.push(entry);
    } catch {
      // unreadable
    }
  }
  const queue = [dir];
  while (queue.length > 0 && out.length < DEPENDENT_MAX_FILES && bytes < DEPENDENT_MAX_BYTES) {
    const rel = queue.shift() as string;
    let entries;
    try {
      entries = await readdir(path.join(root, rel), { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const child = `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!DEPENDENT_SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) queue.push(child);
        continue;
      }
      if (!entry.isFile() || isGeneratedFile(entry.name) || !DEPENDENT_EXTENSIONS.has(path.extname(entry.name).toLowerCase()) || out.includes(child)) continue;
      let size = 0;
      try {
        size = (await stat(path.join(root, child))).size;
      } catch {
        continue;
      }
      if (size > MAX_FILE_BYTES || bytes + size > DEPENDENT_MAX_BYTES) continue;
      bytes += size;
      out.push(child);
      if (out.length >= DEPENDENT_MAX_FILES) break;
    }
  }
  return out;
}

// undefined without node_modules
export async function collectDependentUsage(
  root: string,
  names: readonly string[],
  dependents: readonly DependentRef[],
  options: { signal?: AbortSignal } = {},
): Promise<DependentUsage[] | undefined> {
  if (!(await isDirectory(path.join(root, 'node_modules')))) return undefined;
  const wanted = [...new Set(names.filter((n) => typeof n === 'string' && n !== ''))];
  const out: DependentUsage[] = [];
  const seen = new Set<string>();
  for (const dep of dependents.slice(0, DEPENDENT_MAX_PACKAGES)) {
    abortIfNeeded(options.signal);
    if (seen.has(`${dep.name}@${dep.version}`)) continue;
    seen.add(`${dep.name}@${dep.version}`);
    const dir = await locateDependent(root, dep);
    if (!dir) continue;
    for (const rel of await dependentFiles(root, dir)) {
      if (out.length >= MAX_DEPENDENT_USAGE) return out;
      let text: string;
      try {
        text = await readFile(path.join(root, rel), 'utf8');
      } catch {
        continue;
      }
      if (!wanted.some((n) => text.includes(n)) || looksMinified(text)) continue;
      const sites = findImportsInSource(text, rel, wanted);
      if (sites.length === 0) continue;
      for (const use of findUsageInSource(text, rel, sites)) {
        out.push({ dependent: dep.name, version: dep.version, path: rel, line: use.line, member: use.member, text: use.text });
        if (out.length >= MAX_DEPENDENT_USAGE) return out;
      }
    }
  }
  return out;
}

// fix/reference sections, not api
const SKIP_SECTION = /patch|workaround|reference|credit|acknowledg|timeline|remediation|mitigation|recommendation|resources|for more information|fix(?:es|ed)?\b|upgrade|solution|disclosure/i;

const words = (text: string): Set<string> => new Set(text.split(/\s+/).filter(Boolean));

// globals, node core, generic receivers
const NON_PACKAGE_OBJECTS = words(`
  Object Array String Number Boolean JSON Math Date Promise Reflect Symbol RegExp Function Buffer Error Map Set WeakMap
  WeakSet Proxy Intl BigInt URL URLSearchParams process console window document globalThis global module exports require
  this self fs path os util crypto http https http2 net tls dns zlib stream events child_process url querystring vm
  options opts option config cfg settings args argv params ctx context event err error data obj object input output
  result value props state node Node npm www parts str arr list items item entry key keys name text uri host headers
`);

// never blamed
const STOP_WORDS = words(`
  a an the and or not is it its to of in on at by as be if no yes any all each every some such only also very most more
  other another this that these those which when where then there their than true false null undefined NaN Infinity
  new function functions return var let const class async await yield typeof instanceof for while else do try catch
  finally throw import export default from with delete void switch case break continue super extends static eval
  require setTimeout setInterval parseInt parseFloat encodeURIComponent decodeURIComponent encodeURI decodeURI escape
  unescape toString valueOf hasOwnProperty constructor prototype __proto__ proto Object Array String Number Boolean
  Function JSON Math Date Promise RegExp Error TypeError RangeError SyntaxError ReferenceError EvalError URIError
  AggregateError Symbol Buffer Set Map WeakMap WeakSet Proxy Reflect BigInt ArrayBuffer DataView Uint8Array Int8Array
  URL URLSearchParams FormData Headers Request Response Blob File fetch XMLHttpRequest AbortController TextEncoder
  TextDecoder console process window document globalThis localStorage sessionStorage navigator location
  input inputs output value values data string strings object objects array arrays number numbers key keys name names
  type types path paths url urls file files option options config param params argument arguments args argv callback
  callbacks cb fn func error errors err result results payload body header headers query content text html json xml
  regex regexp pattern length index item items element elements node nodes module modules package packages library
  version versions user users attacker application app code script scripts method methods property properties field
  fields attribute attributes variable variables parser parsing denial service vulnerable vulnerability affected
  impacted same following internal exported public private utility helper hash crafted malicious untrusted arbitrary
  specially main custom provided specific certain named native global sink anonymous recursive arrow regular
  expression expressions catastrophic backtracking patched fixed unsafe safe insecure dangerous underlying original
  inner outer wrapper handler listener builtin built core top level sanitization validation lookup comparison check
  checks test tests example poc PoC CVE GHSA npm yarn node_modules http https www com org io md js ts none own
  implementation retrieval build forEach push pop splice slice split join concat includes indexOf lastIndexOf then
  call apply bind charAt charCodeAt startsWith endsWith toLowerCase toUpperCase
`);

const VIA_RANK: Record<BlamedSymbol['via'], number> = { 'member-access': 0, 'default-callable': 1, call: 2, backticks: 3, summary: 4 };

// after a `name`: data, not a function
const NOT_A_FUNCTION_AFTER = /^\s*(?:option|options|parameter|parameters|param|argument|arguments|arg|key|keys|key names|property|properties|field|fields|flag|flags|header|headers|attribute|attributes|variable|value|values|setting|settings|module|file|files|package|library|directory|folder|object|type|event|events|string|element|algorithm|environment variable)\b/i;
const NOT_A_FUNCTION_BEFORE = /\b(?:option|options|parameter|argument|key|property|field|flag|header|attribute|variable|file|package|library|directory|folder|version|versions|value|algorithm)\s*$/i;
// after a name: it's a function
const FUNCTION_AFTER = /^\s*(?:\(\))?\s*(?:function|functions|method|methods|helper|helpers|api|call|calls|callback|constructor|class|regex|regexp|regular expression)\b/i;
const REGEX_BEFORE = /\b(?:regular expressions?|regex(?:es)?|regexp|pattern)\s*$/i;
// non-js fences
const NON_JS_FENCE = /^(?:bash|sh|shell|zsh|console|terminal|text|txt|plain|plaintext|http|json|yaml|yml|toml|ini|html|xml|diff|patch|python|py|ruby|rb|go|java|c|cpp|csharp|php|rust|sql|powershell|ps1|bat|cmd|dockerfile|makefile|md|markdown)$/i;
const FILE_LIKE = /\.(?:[cm]?[jt]sx?|json5?|md|markdown|txt|html?|css|scss|less|ya?ml|toml|lock|log|tar|tgz|gz|zip|png|jpe?g|gif|svg|xml|csv|sh|py|rb|go|exe|dll|so)$/i;

// usual locals, e.g. jwt for jsonwebtoken
const CONVENTIONAL_BINDINGS: Readonly<Record<string, readonly string[]>> = {
  jsonwebtoken: ['jwt'],
  jquery: ['$', 'jQuery'],
  underscore: ['_'],
  'crypto-js': ['CryptoJS'],
  'js-yaml': ['yaml', 'jsyaml'],
  'socket.io': ['io'],
  'socket.io-client': ['io'],
  'node-fetch': ['fetch'],
  cheerio: ['$', 'cheerio'],
  shelljs: ['shell'],
  'node-forge': ['forge'],
  'moment-timezone': ['moment'],
  dompurify: ['DOMPurify'],
  ws: ['WebSocket'],
};

function camelCase(name: string): string {
  return name.replace(/[-_.]+([a-zA-Z0-9])/g, (_m, c: string) => c.toUpperCase());
}

// camelCase, snake_case or digits
function isCodeLike(name: string): boolean {
  return /[a-z][A-Z]/.test(name) || /[A-Za-z]_[A-Za-z]/.test(name) || /[A-Za-z][0-9]/.test(name) || /^[A-Z][a-z]+[A-Z]/.test(name);
}

// constants, env vars, hashes, short tokens
function isDataToken(name: string): boolean {
  return /^[A-Z0-9_]{2,}$/.test(name) || /^[0-9a-f]{7,40}$/.test(name) || name.length < 3;
}

// the package itself, e.g. _ for lodash
function packageAliases(pkg: string, usage: UsageEvidence | null): Set<string> {
  const aliases = new Set<string>();
  const bare = pkg.startsWith('@') ? (pkg.split('/')[1] ?? pkg) : pkg;
  const camel = camelCase(bare);
  for (const candidate of [bare, camel, camel.charAt(0).toUpperCase() + camel.slice(1), bare.toUpperCase()]) {
    if (isIdentifier(candidate)) aliases.add(candidate);
  }
  if (/^lodash(?:$|[-.])/.test(bare)) aliases.add('_');
  for (const alias of CONVENTIONAL_BINDINGS[pkg] ?? []) aliases.add(alias);
  for (const site of usage?.files ?? []) if (site.binding && isIdentifier(site.binding)) aliases.add(site.binding);
  return aliases;
}

interface Candidate {
  name: string;
  via: BlamedSymbol['via'];
  forceExported: boolean;
  // any sentence marks it internal
  internalMarked: boolean;
  order: number;
}

type AddSymbol = (name: string, via: BlamedSymbol['via'], forceExported: boolean, internalHint?: boolean) => void;

// not public api
const INTERNAL_WORDS = /\b(?:internal(?:ly)?|private|helpers?|non-public|not exported|undocumented)\b/i;
// source path, @file@ is a removed span
const PATH_IN_TEXT = /`[^`\s]*\/[^`\s]*`|`[\w.-]+\.[cm]?[jt]sx?`|@file@|(?<![\w/.])(?:lib|src|dist|build)\/[\w./-]+|\b(?!node\.js\b)[a-z][\w-]*\.[cm]?[jt]sx?\b/;

// sentence around offset
function sentenceAt(text: string, offset: number): string {
  let start = 0;
  for (const m of text.matchAll(/[.!?](?=\s)|\n\s*\n/g)) {
    const end = (m.index ?? 0) + m[0].length;
    if (end > offset) return text.slice(start, end);
    start = end;
  }
  return text.slice(start);
}

// internal, or names a source file
function marksInternal(text: string, offset: number): boolean {
  const sentence = sentenceAt(text, offset);
  return INTERNAL_WORDS.test(sentence) || PATH_IN_TEXT.test(sentence);
}

// drop fix sections and urls, split prose/js
function prepareAdvisoryText(text: string): { prose: string; code: string } {
  const withoutUrls = text.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/\b(?:https?|ftp):\/\/[^\s)>\]]+/g, ' ');
  const kept: string[] = [];
  let skipping = false;
  for (const line of withoutUrls.split(/\r?\n/)) {
    const heading = /^\s{0,3}#{1,6}\s+(.*)$/.exec(line);
    if (heading) {
      skipping = SKIP_SECTION.test(heading[1] ?? '');
      continue;
    }
    if (!skipping) kept.push(line);
  }
  const code: string[] = [];
  const prose = kept.join('\n').replace(/^\s*(```|~~~)([^\n]*)\n([\s\S]*?)(?:^\s*\1[^\n]*$|$(?![\s\S]))/gm, (_m, _fence: string, info: string, inner: string) => {
    const lang = info.trim().split(/\s+/)[0] ?? '';
    if (!NON_JS_FENCE.test(lang)) code.push(inner);
    return '\n';
  });
  return { prose, code: code.join('\n') };
}

function collectFromProse(prose: string, aliases: Set<string>, used: Set<string>, calledNames: Set<string>, add: AddSymbol, summaryMode: boolean): void {
  const via = (v: BlamedSymbol['via']): BlamedSymbol['via'] => (summaryMode && v !== 'member-access' && v !== 'default-callable' ? 'summary' : v);
  // 1. inline code
  for (const m of prose.matchAll(/`([^`\n]+)`/g)) {
    const raw = (m[1] ?? '').trim();
    const at = m.index ?? 0;
    const afterText = prose.slice(at + m[0].length, at + m[0].length + 40);
    const beforeText = prose.slice(Math.max(0, at - 40), at);
    const token = /^(?:new\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(\([^)]*\))?\s*;?$/.exec(raw);
    if (!token) continue;
    const pathText = token[1] as string;
    const called = token[2] !== undefined || raw.startsWith('new ');
    if (FILE_LIKE.test(pathText)) continue;
    const parts = pathText.split('.');
    if (parts.length > 1) {
      const object = parts[0] as string;
      const member = parts[1] as string;
      if (aliases.has(object)) {
        if (!['prototype', 'constructor', '__proto__'].includes(member)) add(member, via('member-access'), true);
        continue;
      }
      if (NON_PACKAGE_OBJECTS.has(object)) continue;
      // e.g. `res.location()`, marked's `inline.reflinkSearch`
      if (called || REGEX_BEFORE.test(beforeText) || FUNCTION_AFTER.test(afterText)) add(pathText, via(called ? 'call' : 'backticks'), false, true);
      continue;
    }
    const name = parts[0] as string;
    if (aliases.has(name)) {
      if (called) add(name, via('default-callable'), true);
      continue;
    }
    if (STOP_WORDS.has(name) || isDataToken(name)) continue;
    const hint = marksInternal(prose, at);
    if (called) {
      add(name, via('call'), false, hint);
      continue;
    }
    if (NOT_A_FUNCTION_AFTER.test(afterText) || NOT_A_FUNCTION_BEFORE.test(beforeText)) continue;
    // bare word needs a function hint
    if (isCodeLike(name) || FUNCTION_AFTER.test(afterText) || used.has(name) || calledNames.has(name)) add(name, via('backticks'), false, hint);
  }
  // code spans to #@#, paths to @file@
  const plain = prose.replace(/`([^`\n]*)`/g, (_s, inner: string) => (/\/|\.[cm]?[jt]sx?$/.test(inner.trim()) ? ' @file@ ' : ' #@# '));
  // 2. pkg member access: _.template, jwt.verify()
  for (const m of plain.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)/g)) {
    const object = m[1] as string;
    const member = m[2] as string;
    if (!aliases.has(object) || ['prototype', 'constructor', '__proto__'].includes(member) || FILE_LIKE.test(`.${member}`)) continue;
    add(member, via('member-access'), true);
  }
  // 3. name() tokens
  for (const m of plain.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\(\s*\)/g)) {
    const name = m[1] as string;
    if (aliases.has(name)) {
      add(name, via('default-callable'), true);
      continue;
    }
    if (STOP_WORDS.has(name) || isDataToken(name)) continue;
    add(name, via('call'), false, marksInternal(plain, m.index ?? 0));
  }
  // 4. "function setKey", "setKey function", "the template function"
  const accept = (name: string, strict: boolean): boolean => {
    if (aliases.has(name) || STOP_WORDS.has(name) || STOP_WORDS.has(name.toLowerCase()) || isDataToken(name)) return false;
    if (strict) return isCodeLike(name);
    return isCodeLike(name) || !/(?:ed|ing|ly|able|ive|al)$/.test(name);
  };
  for (const m of plain.matchAll(/\b(?:function|method)\s+(new\s+)?([A-Za-z_$][\w$]*)/g)) {
    const name = m[2] as string;
    if (m[1] ? /^[A-Z]/.test(name) && !STOP_WORDS.has(name) : accept(name, true)) add(name, via('call'), false, marksInternal(plain, m.index ?? 0));
  }
  for (const m of plain.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s+(?:function|method)s?\b/g)) {
    const name = m[1] as string;
    if (accept(name, true)) add(name, via('call'), false, marksInternal(plain, m.index ?? 0));
  }
  for (const re of [/\b(?:the|a|an)\s+([A-Za-z_$][\w$]*)\s+(?:function|method)s?\b/gi, /\b(?:in|via)\s+(?:the\s+)?([A-Za-z_$][\w$]*)\s+(?:function|method)s?\b/gi]) {
    for (const m of plain.matchAll(re)) {
      let name = m[1] as string;
      if (summaryMode && /^[A-Z][a-z0-9]+$/.test(name)) name = name.toLowerCase(); // title case summary
      if (accept(name, false)) add(name, via('call'), false, marksInternal(plain, m.index ?? 0));
    }
  }
}

function collectFromCode(code: string, pkg: string, aliases: Set<string>, add: AddSymbol): void {
  if (code.trim() === '') return;
  const quoted = escapeRegex(pkg);
  const local = new Set<string>();
  const declare = [
    new RegExp(String.raw`(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"\x60]${quoted}(?:\/[^'"\x60]*)?['"\x60]\s*\)`, 'g'),
    new RegExp(String.raw`import\s+([\w$]+)\s*(?:,\s*\{[^}]*\})?\s*from\s*['"\x60]${quoted}(?:\/[^'"\x60]*)?['"\x60]`, 'g'),
    new RegExp(String.raw`import\s*\*\s*as\s+([\w$]+)\s+from\s*['"\x60]${quoted}(?:\/[^'"\x60]*)?['"\x60]`, 'g'),
  ];
  for (const re of declare) for (const m of code.matchAll(re)) local.add(m[1] as string);
  for (const m of code.matchAll(new RegExp(String.raw`(?:import\s*\{([^}]*)\}\s*from|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\()\s*['"\x60]${quoted}['"\x60]`, 'g'))) {
    for (const part of (m[1] ?? m[2] ?? '').split(',')) {
      const name = part.trim().split(/\s+as\s+|\s*:\s*/)[0]?.trim() ?? '';
      if (isIdentifier(name) && !STOP_WORDS.has(name)) add(name, 'member-access', true);
    }
  }
  const all = new Set([...aliases, ...local]);
  const masked = maskSource(code, { keepStrings: false });
  for (const alias of all) {
    const a = escapeRegex(alias);
    for (const m of masked.matchAll(new RegExp(String.raw`(?<![\w$.])${a}\s*\.\s*([A-Za-z_$][\w$]*)`, 'g'))) {
      const member = m[1] as string;
      if (!['prototype', 'constructor', '__proto__'].includes(member) && !FILE_LIKE.test(`.${member}`)) add(member, 'member-access', true);
    }
    for (const m of masked.matchAll(new RegExp(String.raw`(?<![\w$.])${a}\s*\(`, 'g'))) {
      const before = masked.slice(Math.max(0, (m.index ?? 0) - 12), m.index ?? 0);
      if (/\bfunction\s*$/.test(before)) continue;
      add(alias, 'default-callable', true);
    }
  }
}

// exported vs internal from usage
export function extractBlamedSymbols(details: string, summary: string, pkg: string, usage: UsageEvidence): BlamedSymbol[] {
  const aliases = packageAliases(pkg, usage);
  const used = new Set(Object.keys(usage?.membersUsed ?? {}));
  for (const site of usage?.files ?? []) {
    for (const imported of Object.keys(site.named ?? {})) used.add(imported);
    if (site.subpath) used.add(subpathMember(site.subpath));
  }
  // whole-module import reaches any public fn
  const wholeModule = (usage?.files ?? []).some(
    (s) => s.binding !== null && !s.subpath && (s.kind === 'esm-default' || s.kind === 'esm-namespace' || s.kind === 'cjs-require' || s.kind === 'dynamic-import'),
  );
  const candidates = new Map<string, Candidate>();
  let order = 0;
  const add: AddSymbol = (name, via, forceExported, internalHint = false) => {
    const clean = name.replace(/\(\s*\)$/, '');
    if (clean === '' || clean.length > 60) return;
    const existing = candidates.get(clean);
    if (existing) {
      if (VIA_RANK[via] < VIA_RANK[existing.via]) existing.via = via;
      existing.forceExported = existing.forceExported || forceExported;
      existing.internalMarked = existing.internalMarked || internalHint;
      return;
    }
    order += 1;
    candidates.set(clean, { name: clean, via, forceExported, internalMarked: internalHint, order });
  };
  const { prose, code } = prepareAdvisoryText(details ?? '');
  const calledNames = new Set([...`${prose}\n${code}`.matchAll(/(?<![\w$])([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1] as string));
  collectFromProse(prose, aliases, used, calledNames, add, false);
  collectFromCode(code, pkg, aliases, add);
  if (summary) collectFromProse(prepareAdvisoryText(summary).prose, aliases, used, calledNames, add, true);

  const symbols = [...candidates.values()].map((c) => {
    // bare lowerCamel is public unless marked internal
    const inferred = wholeModule && /^[a-z_$][\w$]*$/.test(c.name) && !c.internalMarked;
    const exported = c.forceExported || used.has(c.name) || inferred;
    return { symbol: { name: c.name, kind: exported ? 'exported' : 'internal', via: c.via } as BlamedSymbol, order: c.order };
  });
  symbols.sort((a, b) => (a.symbol.kind === b.symbol.kind ? a.order - b.order : a.symbol.kind === 'exported' ? -1 : 1));
  return symbols.slice(0, 8).map((s) => s.symbol);
}

// reading order, for tests and tools
export const IMPORT_KINDS: readonly ImportKind[] = [
  'esm-default',
  'esm-namespace',
  'esm-named',
  'esm-side-effect',
  'cjs-require',
  'cjs-destructure',
  'cjs-member',
  'dynamic-import',
  're-export',
];
