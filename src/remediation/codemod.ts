import { builtinModules } from 'node:module';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createTwoFilesPatch, FILE_HEADERS_ONLY } from 'diff';
import { findImportsInSource, findUsageInSource } from '../evidence/codebase.ts';
import { LlmError } from '../llm/errors.ts';
import type { ChatProvider } from '../llm/provider.ts';
import { extractJsonObject, parseLenientJson } from '../llm/textToolCalls.ts';
import type { AuditSink, ChatMessage, CodeEdit, CodemodResult, Config, FilePatch, JsonSchema, MigrationBrief, MigrationBriefItem, RejectedEdit } from '../types.ts';
import type { Ui } from '../ui.ts';
import { errorMessage } from '../util/errors.ts';
import { atomicWrite, detectEol, isPathInside, resolveInside, resolveInsideReal, sha256, toPosix } from '../util/fs.ts';
import { run } from '../util/proc.ts';
import { manualChecklist } from './migration.ts';

const str: JsonSchema = { type: 'string' };

export const EDITS_SCHEMA: JsonSchema = {
  type: 'object',
  properties: {
    edits: {
      type: 'array',
      items: {
        type: 'object',
        properties: { file: str, search: str, replace: str, why: str },
        required: ['file', 'search', 'replace', 'why'],
      },
    },
  },
  required: ['edits'],
};

export const MAX_SEARCH_LINES = 20;

export interface CodemodContext {
  config: Config;
  ui: Ui;
  audit: AuditSink;
  // falls back to the main model
  provider: ChatProvider;
}

export type ModuleType = 'commonjs' | 'module';

// smaller files go whole
const WHOLE_FILE_LINES = 120;
const CONTEXT_LINES = 3;
const MAX_FILE_BYTES = 1024 * 1024;
const CODEMOD_MAX_TOKENS = 1536;
const MAX_EDITS = 12;
const SYNTAX_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

function oneLine(text: string, max: number): string {
  const t = String(text ?? '').replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, Math.max(0, max - 3)).trimEnd()}...` : t;
}

// "./src\\a.js" -> "src/a.js"
function normalizeRel(file: string, projectRoot?: string): string {
  let f = String(file ?? '').trim();
  if (projectRoot && path.isAbsolute(f) && isPathInside(projectRoot, f)) f = path.relative(projectRoot, f);
  return toPosix(f).replace(/^\.\/+/, '').replace(/\/{2,}/g, '/');
}

function lineCount(text: string): number {
  const t = text.replace(/\r\n/g, '\n').replace(/\n+$/, '');
  return t === '' ? 0 : t.split('\n').length;
}

interface Span {
  start: number;
  end: number;
}

type MatchMode = 'exact' | 'crlf' | 'normalized' | 'compact';

interface Location {
  spans: Span[];
  mode: MatchMode;
}

function findAll(hay: string, needle: string): number[] {
  const out: number[] = [];
  if (!needle) return out;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + 1)) out.push(i);
  return out;
}

const QUOTE_CHARS = new Set(['"', "'", '`', '\u2018', '\u2019', '\u201c', '\u201d']);
const HSPACE = new Set([' ', '\t', '\f', '\v', '\u00a0']);

// maps back to original offsets
function normalizedWithMap(text: string, compact: boolean): { text: string; map: number[] } {
  const out: string[] = [];
  const map: number[] = [];
  let lineStart = true;
  let space = -1;
  let newline = -1;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i] as string;
    if (ch === '\r') continue;
    if (ch === '\n') {
      space = -1;
      if (out.length > 0 && newline === -1) newline = i;
      lineStart = true;
      continue;
    }
    if (HSPACE.has(ch)) {
      if (!lineStart && space === -1) space = i;
      continue;
    }
    if (newline !== -1) {
      out.push('\n');
      map.push(newline);
      newline = -1;
    } else if (space !== -1 && !compact) {
      out.push(' ');
      map.push(space);
    }
    space = -1;
    lineStart = false;
    out.push(QUOTE_CHARS.has(ch) ? "'" : ch);
    map.push(i);
  }
  return { text: out.join(''), map };
}

// exact, CRLF, then normalised
export function locateSearch(content: string, search: string): Location {
  if (!search) return { spans: [], mode: 'exact' };
  const exact = findAll(content, search);
  if (exact.length > 0) return { spans: exact.map((s) => ({ start: s, end: s + search.length })), mode: 'exact' };
  if (content.includes('\r\n')) {
    const crlf = search.replace(/\r?\n/g, '\r\n');
    if (crlf !== search) {
      const hits = findAll(content, crlf);
      if (hits.length > 0) return { spans: hits.map((s) => ({ start: s, end: s + crlf.length })), mode: 'crlf' };
    }
  }
  for (const compact of [false, true]) {
    const hay = normalizedWithMap(content, compact);
    const needle = normalizedWithMap(search, compact).text;
    if (!needle) continue;
    const hits = findAll(hay.text, needle);
    if (hits.length > 0) {
      return {
        spans: hits.map((h) => ({ start: hay.map[h] ?? 0, end: (hay.map[h + needle.length - 1] ?? 0) + 1 })),
        mode: compact ? 'compact' : 'normalized',
      };
    }
  }
  return { spans: [], mode: 'normalized' };
}

function indentOf(line: string): string {
  return /^[ \t]*/.exec(line)?.[0] ?? '';
}

function reindent(content: string, span: Span, edit: CodeEdit, text: string, compact: boolean): string {
  const lineStart = content.lastIndexOf('\n', span.start - 1) + 1;
  const regionEnd = content.indexOf('\n', Math.max(span.start, span.end - 1));
  const original = content
    .slice(lineStart, regionEnd === -1 ? content.length : regionEnd)
    .replace(/\r/g, '')
    .split('\n')
    .filter((l) => l.trim() !== '');
  const search = edit.search.replace(/\r\n/g, '\n').split('\n').filter((l) => l.trim() !== '');
  const lines = text.replace(/^(?:[ \t]*\n)+/, '').replace(/\s+$/, '').split('\n');
  const aligned = original.length === search.length;
  const key = (l: string): string => normalizedWithMap(l, compact).text;
  let cursor = 0;
  const mapped = lines.map((l) => {
    if (!aligned || l.trim() === '') return -1;
    const k = key(l);
    for (let j = cursor; j < search.length; j += 1) {
      if (key(search[j] ?? '') === k) {
        cursor = j + 1;
        return j;
      }
    }
    return -1;
  });
  const nonEmpty = lines.filter((l) => l.trim() !== '').length;
  const base = indentOf(original[0] ?? '');
  const searchBase = indentOf(search[0] ?? '');
  let position = 0;
  return lines
    .map((line, i) => {
      if (line.trim() === '') return '';
      const index = position;
      position += 1;
      if (i === 0) return line.trimStart();
      if (!aligned) {
        // file vs model first-line indent
        return line.startsWith(searchBase) ? base + line.slice(searchBase.length) : base + line.trimStart();
      }
      const own = mapped[i] ?? -1;
      if (own !== -1) return indentOf(original[own] ?? '') + line.trimStart();
      if (nonEmpty === search.length) return indentOf(original[index] ?? '') + line.trimStart();
      const next = mapped.slice(i + 1).find((m) => m !== -1);
      const prev = [...mapped.slice(0, i)].reverse().find((m) => m !== -1);
      const ref = next ?? prev ?? 0;
      return indentOf(original[ref] ?? '') + line.trimStart();
    })
    .join('\n');
}

function adaptReplace(content: string, span: Span, edit: CodeEdit, mode: MatchMode): { text: string; span: Span } {
  const eol = detectEol(content);
  let text = edit.replace.replace(/\r\n/g, '\n');
  let target = span;
  if (mode === 'normalized' || mode === 'compact') {
    text = reindent(content, span, edit, text, mode === 'compact');
    if (text === '') {
      // whole-line delete eats indent and newline
      const lineStart = content.lastIndexOf('\n', span.start - 1) + 1;
      const lineEnd = content.indexOf('\n', span.end);
      const restOfLine = content.slice(span.end, lineEnd === -1 ? content.length : lineEnd).trim();
      if (content.slice(lineStart, span.start).trim() === '' && restOfLine === '') {
        target = { start: lineStart, end: lineEnd === -1 ? content.length : lineEnd + 1 };
      }
    }
  }
  if (eol === '\r\n') text = text.replace(/\n/g, '\r\n');
  return { text, span: target };
}

function splice(content: string, span: Span, text: string): string {
  return content.slice(0, span.start) + text + content.slice(span.end);
}

const ESM_PATTERNS: readonly RegExp[] = [
  /^[ \t]*import\s+['"][^'"\n]+['"]/gm,
  /^[ \t]*import\s+[\w$*{][^;\n]*?\bfrom\s*['"][^'"\n]+['"]/gm,
  /^[ \t]*export\s+(?:default\b|const\b|let\b|var\b|function\b|async\s+function\b|class\b|\{|\*)/gm,
  /\bimport\.meta\b/g,
];

function esmStatements(text: string): number {
  return ESM_PATTERNS.reduce((n, re) => n + (text.match(re) ?? []).length, 0);
}

export function moduleTypeOf(file: string, packageType: 'module' | 'commonjs' | undefined): ModuleType {
  const ext = path.extname(file).toLowerCase();
  if (ext === '.mjs' || ext === '.mts') return 'module';
  if (ext === '.cjs' || ext === '.cts') return 'commonjs';
  // ts, jsx and components are esm
  if (ext === '.ts' || ext === '.tsx' || ext === '.jsx' || ext === '.vue' || ext === '.svelte') return 'module';
  return packageType === 'module' ? 'module' : 'commonjs';
}

// nearest package.json type, node's rule
async function nearestPackageType(projectRoot: string, file: string): Promise<'module' | 'commonjs' | undefined> {
  const root = path.resolve(projectRoot);
  let dir = path.dirname(path.resolve(root, file));
  for (;;) {
    let text: string | null = null;
    try {
      text = await readFile(path.join(dir, 'package.json'), 'utf8');
    } catch {
      text = null;
    }
    if (text !== null) {
      try {
        const type = (JSON.parse(text) as { type?: unknown }).type;
        return type === 'module' ? 'module' : type === 'commonjs' ? 'commonjs' : undefined;
      } catch {
        return undefined;
      }
    }
    if (dir === root || !isPathInside(root, dir)) return undefined;
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export interface EditValidationOptions {
  projectRoot: string;
  affectedFiles: readonly string[];
  moduleType: ModuleType;
}

function cleanEdit(raw: CodeEdit, fallbackFile: string): CodeEdit {
  const r = (raw ?? {}) as Partial<Record<keyof CodeEdit, unknown>>;
  const text = (v: unknown): string => (typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v));
  return { file: text(r.file).trim() || fallbackFile, search: text(r.search), replace: text(r.replace), why: text(r.why).trim() };
}

function looseEqual(a: string, b: string): boolean {
  return normalizedWithMap(a, false).text === normalizedWithMap(b, false).text;
}

export function validateEdits(
  file: string,
  content: string,
  edits: readonly CodeEdit[],
  options: EditValidationOptions,
): { valid: CodeEdit[]; rejected: RejectedEdit[] } {
  const target = normalizeRel(file, options.projectRoot);
  const affected = new Set(options.affectedFiles.map((f) => normalizeRel(f, options.projectRoot)));
  const rejected: RejectedEdit[] = [];
  const reject = (edit: CodeEdit, reason: string): void => {
    rejected.push({ file: edit.file, edit, reason });
  };
  const fileIsEsm = esmStatements(content) > 0;
  const located: { edit: CodeEdit; span: Span; index: number }[] = [];
  edits.forEach((raw, index) => {
    const edit = cleanEdit(raw, target);
    const editFile = normalizeRel(edit.file, options.projectRoot);
    edit.file = editFile;
    if (path.isAbsolute(editFile) || !isPathInside(options.projectRoot, editFile)) return reject(edit, `${editFile} is outside the project`);
    if (!affected.has(editFile)) return reject(edit, `${editFile} is not one of the files the brief lists as affected`);
    if (editFile !== target) return reject(edit, `the edit is for ${editFile}, not ${target}: only ${target} is edited here`);
    if (edit.search.trim() === '') return reject(edit, 'search is empty: copy the lines to change from the file');
    const lines = lineCount(edit.search);
    if (lines > MAX_SEARCH_LINES) return reject(edit, `search has ${lines} lines; use at most ${MAX_SEARCH_LINES} lines around the change`);
    if (edit.replace === edit.search) return reject(edit, 'replace is identical to search');
    if (looseEqual(edit.replace, edit.search)) return reject(edit, 'replace only changes whitespace or quotes');
    if (options.moduleType === 'commonjs' && !fileIsEsm && esmStatements(edit.replace) > esmStatements(edit.search)) {
      return reject(edit, `the edit adds import/export syntax to ${target}, which is a CommonJS file; keep require() and module.exports`);
    }
    const where = locateSearch(content, edit.search);
    if (where.spans.length === 0) return reject(edit, 'search text was not found in the file; copy it exactly, including indentation');
    if (where.spans.length > 1) return reject(edit, `search text matches ${where.spans.length} places; include more surrounding lines so it matches once`);
    located.push({ edit, span: where.spans[0] as Span, index });
  });
  located.sort((a, b) => a.span.start - b.span.start || a.index - b.index);
  const ordered: { edit: CodeEdit; span: Span }[] = [];
  for (const l of located) {
    const prev = ordered[ordered.length - 1];
    if (prev && l.span.start < prev.span.end) {
      reject(l.edit, 'overlaps an earlier edit; merge the two into one edit');
      continue;
    }
    ordered.push(l);
  }
  // each search must still match once
  const valid: CodeEdit[] = [];
  let current = content;
  for (const { edit } of ordered) {
    const where = locateSearch(current, edit.search);
    if (where.spans.length !== 1) {
      reject(edit, where.spans.length === 0 ? 'search text is gone after the earlier edits' : `after the earlier edits, search matches ${where.spans.length} places`);
      continue;
    }
    const adapted = adaptReplace(current, where.spans[0] as Span, edit, where.mode);
    current = splice(current, adapted.span, adapted.text);
    valid.push(edit);
  }
  return { valid, rejected };
}

export function applyEdits(content: string, edits: readonly CodeEdit[]): { content: string; failed: RejectedEdit[] } {
  let current = content;
  const failed: RejectedEdit[] = [];
  for (const raw of edits) {
    const edit = cleanEdit(raw, raw?.file ?? '');
    const where = locateSearch(current, edit.search);
    if (edit.search === '' || where.spans.length !== 1) {
      failed.push({ file: edit.file, edit, reason: where.spans.length === 0 ? 'search text not found' : `search text matches ${where.spans.length} places` });
      continue;
    }
    const adapted = adaptReplace(current, where.spans[0] as Span, edit, where.mode);
    current = splice(current, adapted.span, adapted.text);
  }
  return { content: current, failed };
}

export function renderDiff(file: string, before: string, after: string): string {
  const rel = normalizeRel(file);
  return createTwoFilesPatch(rel, rel, before, after, undefined, undefined, { context: 3, stripTrailingCr: true, headerOptions: FILE_HEADERS_ONLY });
}

const JS_WORDS = new Set([
  'await', 'async', 'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends',
  'false', 'finally', 'for', 'from', 'function', 'get', 'if', 'import', 'in', 'instanceof', 'let', 'new', 'null', 'of', 'return', 'set',
  'static', 'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof', 'undefined', 'var', 'void', 'while', 'with', 'yield', 'as',
  'require', 'module', 'exports', 'console', 'process', 'globalThis', 'Object', 'Array', 'String', 'Number', 'Boolean', 'JSON', 'Promise',
  'Error', 'Symbol', 'Map', 'Set', 'Math', 'Date', 'RegExp', 'type', 'interface',
]);

function identifiers(text: string): Set<string> {
  return new Set(text.match(/[A-Za-z_$][\w$]*/g) ?? []);
}

function specifiers(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/\brequire\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\)|\bfrom\s*['"]([^'"\n]+)['"]|\bimport\s*\(?\s*['"]([^'"\n]+)['"]/g)) {
    const spec = m[1] ?? m[2] ?? m[3];
    if (spec) out.push(spec);
  }
  return out;
}

function bareName(spec: string): string {
  if (spec.startsWith('@')) return spec.split('/').slice(0, 2).join('/');
  return spec.split('/')[0] ?? spec;
}

const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

interface FileEvidence {
  pkg: string;
  bindings: string[];
  // verified quotes only
  quotes: string;
  content: string;
  dependencies: Set<string>;
}

// null when supported
function evidenceProblem(edit: CodeEdit, ev: FileEvidence): string | null {
  const names = unique([ev.pkg, ...ev.bindings]);
  const mentions = new RegExp(`(?<![\\w$])(?:${names.map(escapeRegExp).join('|')})(?![\\w$])`);
  if (!mentions.test(edit.search)) return `the edit changes code that does not use ${ev.pkg}`;
  for (const spec of specifiers(edit.replace)) {
    if (specifiers(edit.search).includes(spec)) continue;
    if (spec.startsWith('.') || spec.startsWith('/') || BUILTINS.has(spec)) continue;
    const name = bareName(spec);
    if (name === ev.pkg || ev.dependencies.has(name)) continue;
    return `the edit adds a dependency on ${name}, which the project does not declare`;
  }
  const before = identifiers(edit.search);
  const quoteIds = identifiers(ev.quotes);
  const fileIds = identifiers(ev.content);
  for (const binding of ev.bindings) {
    const re = new RegExp(`(?<![\\w$.])${escapeRegExp(binding)}\\s*\\??\\.\\s*([A-Za-z_$][\\w$]*)`, 'g');
    const had = new Set([...edit.search.matchAll(re)].map((m) => m[1]));
    for (const m of edit.replace.matchAll(re)) {
      const member = m[1] ?? '';
      if (had.has(member)) continue;
      if (!new RegExp(`\\.\\s*${escapeRegExp(member)}\\b`).test(ev.quotes)) return `the edit introduces ${binding}.${member}, which no verified evidence quote for this file mentions`;
    }
  }
  for (const id of identifiers(edit.replace)) {
    if (before.has(id) || JS_WORDS.has(id) || quoteIds.has(id) || fileIds.has(id) || names.includes(id)) continue;
    return `the edit introduces "${id}", which neither the file nor a verified evidence quote contains`;
  }
  return null;
}

// net open brackets, skips strings and comments
function bracketDelta(code: string): [number, number, number] {
  const d: [number, number, number] = [0, 0, 0];
  for (let i = 0; i < code.length; i += 1) {
    const ch = code[i];
    const next = code[i + 1];
    if (ch === '/' && next === '/') {
      const nl = code.indexOf('\n', i);
      i = nl === -1 ? code.length : nl;
    } else if (ch === '/' && next === '*') {
      const end = code.indexOf('*/', i + 2);
      i = end === -1 ? code.length : end + 1;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      while (j < code.length && code[j] !== ch && !(ch !== '`' && code[j] === '\n')) j += code[j] === '\\' ? 2 : 1;
      i = j;
    } else if (ch === '(') d[0] += 1;
    else if (ch === ')') d[0] -= 1;
    else if (ch === '{') d[1] += 1;
    else if (ch === '}') d[1] -= 1;
    else if (ch === '[') d[2] += 1;
    else if (ch === ']') d[2] -= 1;
  }
  return d;
}

// brackets must balance like search
function bracketProblem(edit: CodeEdit): string | null {
  const a = bracketDelta(edit.search);
  const b = bracketDelta(edit.replace);
  if (a[0] === b[0] && a[1] === b[1] && a[2] === b[2]) return null;
  return 'the replace opens or closes brackets differently from the search; put the whole statement (up to its closing bracket) in search and replace';
}

const CHECK_ENV = (() => {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return env;
})();

// temp copy, never the project file
async function syntaxProblem(file: string, content: string, moduleType: ModuleType): Promise<string | null> {
  const ext = path.extname(file).toLowerCase();
  if (!SYNTAX_EXTENSIONS.has(ext)) return null;
  const target = ext !== '.js' ? ext : moduleType === 'module' ? '.mjs' : esmStatements(content) > 0 ? '.js' : '.cjs';
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-check-'));
  try {
    const tmp = path.join(dir, `${path.basename(file, ext)}${target}`);
    await writeFile(tmp, content);
    const res = await run(process.execPath, ['--check', tmp], { env: CHECK_ENV, timeoutMs: 30_000 });
    if (res.ok) return null;
    if (res.code === null) return null; // node did not run
    return syntaxError(res.stderr, tmp, file);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

async function projectDependencies(projectRoot: string): Promise<Set<string>> {
  try {
    const pkg = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8')) as Record<string, unknown>;
    const names = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap((k) => Object.keys((pkg[k] as Record<string, string> | undefined) ?? {}));
    return new Set(names);
  } catch {
    return new Set();
  }
}

function fence(file: string): string {
  const ext = path.extname(file).toLowerCase().replace('.', '');
  return ['js', 'mjs', 'cjs', 'jsx'].includes(ext) ? 'js' : ['ts', 'tsx', 'mts', 'cts'].includes(ext) ? 'ts' : ext || 'text';
}

function systemPrompt(brief: MigrationBrief, moduleType: ModuleType): string {
  return [
    `You are PatchPilot's code migration assistant. You edit ONE file of this project so it keeps working after upgrading the npm package ${brief.package} from ${brief.from} to ${brief.to}.`,
    'Rules: make only the changes the brief items below require, and only on lines that use the package. Follow the evidence quote; do not refactor, reformat, rename, add dependencies or change behaviour otherwise. If the file needs no change, return {"edits": []}.',
    `Each edit replaces one exact piece of the file: "search" is copied character for character from the file (whole lines, at most ${MAX_SEARCH_LINES}, unique in the file, without line numbers); "replace" is the new text for those lines; "why" names the brief item it implements.`,
    moduleType === 'commonjs'
      ? 'The file is CommonJS: keep require() and module.exports; never add import or export statements.'
      : 'The file is an ES module (or compiled source): keep its import and export style.',
    'Answer with JSON only: {"edits": [{"file": "<path>", "search": "<exact lines>", "replace": "<new lines>", "why": "<brief item>"}]}',
  ].join('\n\n');
}

interface Excerpt {
  whole: boolean;
  text: string;
  relevant: string[];
}

// whole file when short
function fileExcerpt(file: string, content: string, pkg: string): Excerpt {
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  let sites: ReturnType<typeof findImportsInSource> = [];
  try {
    sites = findImportsInSource(content, file, [pkg]);
  } catch {
    sites = [];
  }
  let calls: ReturnType<typeof findUsageInSource> = [];
  try {
    calls = findUsageInSource(content, file, sites, undefined, 0);
  } catch {
    calls = [];
  }
  const marks = new Map<number, string>();
  for (const s of sites) marks.set(s.line, `line ${s.line} (import): ${oneLine(s.statement, 140)}`);
  for (const c of calls) if (!marks.has(c.line)) marks.set(c.line, `line ${c.line} (${c.member ? `${c.binding}.${c.member}` : `${c.binding}()`}): ${oneLine(c.text, 140)}`);
  if (marks.size === 0) {
    lines.forEach((l, i) => {
      if (l.includes(pkg) && marks.size < 12) marks.set(i + 1, `line ${i + 1}: ${oneLine(l, 140)}`);
    });
  }
  const relevant = [...marks.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
  if (lines.length < WHOLE_FILE_LINES) return { whole: true, text: content.replace(/\r\n/g, '\n').replace(/\n+$/, ''), relevant };
  const ranges: [number, number][] = [];
  for (const line of [...marks.keys()].sort((a, b) => a - b)) {
    const start = Math.max(1, line - CONTEXT_LINES);
    const end = Math.min(lines.length, line + CONTEXT_LINES);
    const prev = ranges[ranges.length - 1];
    if (prev && start <= prev[1] + 1) prev[1] = Math.max(prev[1], end);
    else ranges.push([start, end]);
  }
  const text = ranges.map(([s, e]) => `(lines ${s}-${e})\n${lines.slice(s - 1, e).join('\n')}`).join('\n\n');
  return { whole: false, text, relevant };
}

function userPrompt(file: string, moduleType: ModuleType, lines: number, items: readonly MigrationBriefItem[], excerpt: Excerpt): string {
  const out = [
    `File: ${file} (${moduleType === 'commonjs' ? 'CommonJS' : 'ES module'}, ${lines} lines)`,
    '',
    'Brief items for this file (the evidence quote is what the release notes say):',
  ];
  items.forEach((item, i) => {
    out.push(`${i + 1}. ${oneLine(item.change, 240)}`);
    out.push(`   Evidence: "${oneLine(item.evidenceQuote, 400)}" (${item.evidenceUrl})`);
    if (item.oldApi) out.push(`   Old API: ${oneLine(item.oldApi, 200)}`);
    if (item.newApi) out.push(`   New API: ${oneLine(item.newApi, 200)}`);
  });
  out.push('', 'Lines that use the package:', ...(excerpt.relevant.length > 0 ? excerpt.relevant.map((r) => `- ${r}`) : ['- (none found)']), '');
  out.push(excerpt.whole ? 'The whole file:' : 'The relevant parts of the file (line ranges in parentheses are not part of the file):');
  out.push(`\`\`\`${fence(file)}`, excerpt.text, '```', '', `Return the edits for ${file} as JSON.`);
  return out.join('\n');
}

function retryPrompt(file: string, rejected: readonly RejectedEdit[], parseFailed: boolean): string {
  const lines = parseFailed
    ? ['That was not a valid JSON object {"edits": [...]}.']
    : ['Some edits were rejected:', ...rejected.slice(0, 8).map((r, i) => `${i + 1}. ${r.edit ? `search ${JSON.stringify(oneLine(r.edit.search, 120))}: ` : ''}${r.reason}`)];
  lines.push(`Reply with the complete corrected list of edits for ${file} as JSON: copy "search" exactly from the file, keep only the changes the brief requires, or return {"edits": []} when no change is needed.`);
  return lines.join('\n');
}

// models drop the trailing semicolon
function keepStatementEnd(edit: CodeEdit): CodeEdit {
  const search = edit.search.replace(/\r?\n$/, '');
  const replace = edit.replace.replace(/\r?\n$/, '');
  if (search.includes('\n') || replace.includes('\n') || !search.trimEnd().endsWith(';')) return edit;
  if (replace.trim() === '' || /[;,{}([\]]\s*$/.test(replace) || replace.includes('//')) return edit;
  return { ...edit, replace: `${replace.trimEnd()};${edit.replace.slice(replace.length)}` };
}

// null when not json
export function parseEditsOutput(content: string): CodeEdit[] | null {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    value = extractJsonObject(content) ?? parseLenientJson(content);
  }
  const list = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { edits?: unknown }).edits)
      ? (value as { edits: unknown[] }).edits
      : null;
  if (!list) return null;
  return list
    .filter((e): e is Record<string, unknown> => Boolean(e) && typeof e === 'object' && !Array.isArray(e))
    .slice(0, MAX_EDITS)
    .map((e) =>
      keepStatementEnd({
        file: typeof e.file === 'string' ? e.file : '',
        search: typeof e.search === 'string' ? e.search : '',
        replace: typeof e.replace === 'string' ? e.replace : '',
        why: typeof e.why === 'string' ? e.why : '',
      }),
    );
}

interface Attempt {
  valid: CodeEdit[];
  rejected: RejectedEdit[];
  parsed: boolean;
}

async function modelEdits(ctx: CodemodContext, messages: ChatMessage[]): Promise<{ content: string | null; error: unknown }> {
  const spinner = ctx.ui.spinner(`${ctx.ui.purple('agent', ctx.ui.ce)} ${ctx.ui.ce.dim('drafting edits...')}`);
  try {
    const res = await ctx.provider.chat({ messages, format: EDITS_SCHEMA, options: { num_predict: CODEMOD_MAX_TOKENS }, purpose: 'codemod' });
    return { content: res.message.content ?? '', error: null };
  } catch (err) {
    if (err instanceof LlmError && err.kind === 'aborted') throw err;
    return { content: null, error: err };
  } finally {
    spinner.stop();
  }
}

async function checkAttempt(
  edits: CodeEdit[] | null,
  file: string,
  content: string,
  affected: readonly string[],
  moduleType: ModuleType,
  projectRoot: string,
  ev: FileEvidence,
): Promise<Attempt> {
  if (edits === null) return { valid: [], rejected: [], parsed: false };
  const { valid, rejected } = validateEdits(file, content, edits, { projectRoot, affectedFiles: affected, moduleType });
  const kept: CodeEdit[] = [];
  for (const edit of valid) {
    const problem = evidenceProblem(edit, ev) ?? bracketProblem(edit);
    if (problem) rejected.push({ file: edit.file, edit, reason: problem });
    else kept.push(edit);
  }
  let candidates = kept;
  if (kept.length !== valid.length) {
    // dropping one shifts the rest
    const again = validateEdits(file, content, kept, { projectRoot, affectedFiles: affected, moduleType });
    candidates = again.valid;
    rejected.push(...again.rejected);
  }
  // syntax gate, keep order
  const good: CodeEdit[] = [];
  for (const edit of candidates) {
    const next = applyEdits(content, [...good, edit]);
    if (next.failed.length > 0) {
      rejected.push(...next.failed);
      continue;
    }
    const problem = await syntaxProblem(file, next.content, moduleType);
    if (problem) rejected.push({ file: edit.file, edit, reason: `the edit leaves a syntax error: ${problem}` });
    else good.push(edit);
  }
  return { valid: good, rejected, parsed: true };
}

// nothing removed, so no edit
function deprecationOnly(item: MigrationBriefItem): boolean {
  const q = item.evidenceQuote;
  return /\bdeprecat/i.test(q) && !/\b(?:remov|no longer|dropped|renamed|instead|replaced|must)\b/i.test(q);
}

export async function proposeCodemod(brief: MigrationBrief, ctx: CodemodContext): Promise<CodemodResult> {
  const root = ctx.config.projectRoot;
  const model = ctx.provider?.model ?? 'none';
  const applicable = brief.items.filter((i) => i.verified && i.appliesToProject === 'yes' && !deprecationOnly(i));
  const files = unique(applicable.flatMap((i) => i.affectedFiles.map((f) => normalizeRel(f, root))).filter(Boolean));
  const patches: FilePatch[] = [];
  const rejected: RejectedEdit[] = [];
  if (files.length === 0 || !ctx.provider) {
    if (applicable.length > 0 && !ctx.provider) rejected.push({ file: '', edit: null, reason: 'no model provider for code edits' });
    return { package: brief.package, model, patches, rejected, manualChecklist: manualChecklist(brief) };
  }
  const dependencies = await projectDependencies(root);
  for (const file of files) {
    const fileRejected: RejectedEdit[] = [];
    let abs: string;
    try {
      abs = await resolveInsideReal(root, file);
    } catch {
      rejected.push({ file, edit: null, reason: 'the file is outside the project' });
      continue;
    }
    let bytes: Buffer;
    try {
      bytes = await readFile(abs);
    } catch {
      rejected.push({ file, edit: null, reason: 'the file does not exist' });
      continue;
    }
    if (bytes.length > MAX_FILE_BYTES) {
      rejected.push({ file, edit: null, reason: 'the file is larger than 1 MB' });
      continue;
    }
    const content = bytes.toString('utf8');
    if (!Buffer.from(content, 'utf8').equals(bytes) || content.includes('\u0000')) {
      rejected.push({ file, edit: null, reason: 'the file is not UTF-8 text' });
      continue;
    }
    const moduleType = moduleTypeOf(file, await nearestPackageType(root, file));
    const items = applicable.filter((i) => i.affectedFiles.some((f) => normalizeRel(f, root) === file));
    const sites = (() => {
      try {
        return findImportsInSource(content, file, [brief.package]);
      } catch {
        return [];
      }
    })();
    const ev: FileEvidence = {
      pkg: brief.package,
      bindings: unique(sites.flatMap((s) => [s.binding, ...Object.values(s.named ?? {})]).filter((b): b is string => Boolean(b))),
      quotes: items.map((i) => i.evidenceQuote).join('\n'),
      content,
      dependencies,
    };
    const excerpt = fileExcerpt(file, content, brief.package);
    ctx.ui.agentLine(`Drafting code edits for ${file}...`);
    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt(brief, moduleType) },
      { role: 'user', content: userPrompt(file, moduleType, lineCount(content), items, excerpt) },
    ];
    const first = await modelEdits(ctx, messages);
    if (first.content === null) {
      ctx.ui.resultLine(`Model call failed: ${oneLine(errorMessage(first.error), 140)}`);
      rejected.push({ file, edit: null, reason: `the model call failed: ${oneLine(errorMessage(first.error), 160)}` });
      ctx.audit.log({ event: 'codemod.proposed', package: brief.package, file, edits: 0, rejected: 1, model });
      continue;
    }
    let attempt = await checkAttempt(parseEditsOutput(first.content), file, content, files, moduleType, root, ev);
    if (!attempt.parsed || attempt.rejected.length > 0) {
      ctx.ui.resultLine(
        attempt.parsed
          ? `${attempt.valid.length} edit${attempt.valid.length === 1 ? '' : 's'} valid, ${attempt.rejected.length} rejected: ${oneLine(attempt.rejected[0]?.reason ?? '', 110)}`
          : 'The answer was not valid JSON for the edits schema',
      );
      ctx.ui.agentLine(`Asking again with the validation errors for ${file}...`);
      const retry = await modelEdits(ctx, [...messages, { role: 'assistant', content: first.content }, { role: 'user', content: retryPrompt(file, attempt.rejected, !attempt.parsed) }]);
      if (retry.content !== null) {
        const second = await checkAttempt(parseEditsOutput(retry.content), file, content, files, moduleType, root, ev);
        if (second.parsed && (second.valid.length >= attempt.valid.length || !attempt.parsed)) attempt = second;
      }
    }
    fileRejected.push(...attempt.rejected);
    if (!attempt.parsed) fileRejected.push({ file, edit: null, reason: 'the model did not return valid JSON edits' });
    let patch: FilePatch | null = null;
    if (attempt.valid.length > 0) {
      const applied = applyEdits(content, attempt.valid);
      fileRejected.push(...applied.failed);
      const applies = attempt.valid.filter((e) => !applied.failed.some((f) => f.edit?.search === e.search));
      if (applied.content !== content && applies.length > 0) {
        patch = { file, edits: applies, diff: renderDiff(file, content, applied.content), beforeHash: sha256(bytes), newContent: applied.content };
        patches.push(patch);
      }
    }
    if (!patch && fileRejected.length === 0) fileRejected.push({ file, edit: null, reason: 'the model proposed no change for this file' });
    rejected.push(...fileRejected);
    ctx.audit.log({ event: 'codemod.proposed', package: brief.package, file, edits: patch?.edits.length ?? 0, rejected: fileRejected.length, model });
    ctx.ui.resultLine(
      patch
        ? `${patch.edits.length} edit${patch.edits.length === 1 ? '' : 's'} validated${fileRejected.length > 0 ? `, ${fileRejected.length} rejected` : ''}`
        : `No valid edit for ${file}${fileRejected[0] ? `: ${oneLine(fileRejected[0].reason, 110)}` : ''}`,
    );
  }
  return { package: brief.package, model, patches, rejected, manualChecklist: patches.length > 0 ? null : manualChecklist(brief) };
}

// rolls back on write failure
export async function writePatches(patches: readonly FilePatch[], projectRoot: string): Promise<{ file: string; beforeHash: string; afterHash: string }[]> {
  const plans: { patch: FilePatch; abs: string; before: Buffer }[] = [];
  for (const patch of patches) {
    const abs = await resolveInsideReal(projectRoot, patch.file);
    const before = await readFile(abs);
    if (sha256(before) !== patch.beforeHash) throw new Error(`${patch.file} changed after the diff was made; nothing was written`);
    plans.push({ patch, abs, before });
  }
  const written: { abs: string; before: Buffer }[] = [];
  const out: { file: string; beforeHash: string; afterHash: string }[] = [];
  try {
    for (const { patch, abs, before } of plans) {
      await atomicWrite(abs, patch.newContent);
      written.push({ abs, before });
      out.push({ file: normalizeRel(patch.file), beforeHash: patch.beforeHash, afterHash: sha256(patch.newContent) });
    }
  } catch (err) {
    for (const w of written.reverse()) await atomicWrite(w.abs, w.before).catch(() => {});
    throw err;
  }
  return out;
}

function syntaxError(stderr: string, abs: string, file: string): string {
  const lines = stderr.split('\n').map((l) => l.trimEnd());
  // macOS: /var is /private/var
  const base = path.basename(abs);
  const location = lines.find((l) => /:\d+$/.test(l) && (l.startsWith(abs) || l.replace(/:\d+$/, '').endsWith(`${path.sep}${base}`)));
  const message = lines.find((l) => /^\w*Error\b/.test(l.trim())) ?? lines.find((l) => l.trim() !== '') ?? 'syntax check failed';
  const lineNo = location ? /:(\d+)$/.exec(location)?.[1] : undefined;
  return `${message.trim()}${lineNo ? ` (${file}:${lineNo})` : ''}`;
}

// no shell
export async function checkSyntax(files: readonly string[], projectRoot: string): Promise<{ file: string; ok: boolean; error?: string }[]> {
  const out: { file: string; ok: boolean; error?: string }[] = [];
  for (const raw of unique(files.map((f) => normalizeRel(f, projectRoot)))) {
    if (!SYNTAX_EXTENSIONS.has(path.extname(raw).toLowerCase())) continue;
    let abs: string;
    try {
      abs = resolveInside(projectRoot, raw);
    } catch {
      out.push({ file: raw, ok: false, error: 'the file is outside the project' });
      continue;
    }
    const res = await run(process.execPath, ['--check', abs], { cwd: projectRoot, env: CHECK_ENV, timeoutMs: 30_000 });
    if (res.ok) out.push({ file: raw, ok: true });
    else out.push({ file: raw, ok: false, error: res.error && res.code === null ? `node --check could not run: ${res.error.message}` : syntaxError(res.stderr, abs, raw) });
  }
  return out;
}
