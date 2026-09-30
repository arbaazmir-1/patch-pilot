import { DEFAULT_EXCLUDES } from '../../config.ts';
import { searchProject } from '../../evidence/codebase.ts';
import type { SearchMatch, ToolContext, ToolHandler, ToolResult } from '../../types.ts';
import { isSecretPath } from './readFile.ts';

export interface SearchCodeArgs {
  pattern: string;
  fileGlob?: string;
  maxResults?: number;
}

export interface SearchCodeDeps {
  searchProject: typeof searchProject;
}

export const SEARCH_DEFAULT_RESULTS = 10;
export const SEARCH_MAX_RESULTS = 30;
const MAX_PATTERN_LENGTH = 400;
// longer lines count as minified
const MAX_LINE_LENGTH = 500;
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb']);

const ESCAPE_HINT = 'Escape regex special characters ( ) [ ] { } . * + ? ^ $ | \\ with a backslash, for example \\.template\\( to find ".template(".';

const NESTED_HINT = 'nested quantifiers such as (a+)+ can hang the search; quantify the inner part only, for example a+ instead of (a+)+';

interface Quantifier {
  length: number;
  unbounded: boolean;
}

// *, +, {n,}, {n,m} with m > n repeat freely; ? and {n} do not
function quantifierAt(src: string, i: number): Quantifier | null {
  const c = src[i];
  if (c === '*' || c === '+') return { length: src[i + 1] === '?' ? 2 : 1, unbounded: true };
  if (c === '?') return { length: 1, unbounded: false };
  if (c !== '{') return null;
  const m = /^\{(\d+)(,(\d*))?\}\??/.exec(src.slice(i));
  if (!m) return null;
  const min = Number(m[1]);
  const max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
  return { length: m[0].length, unbounded: max > min };
}

// quantified group holding a quantifier, the classic redos shape
export function hasNestedQuantifier(src: string): boolean {
  const stack: boolean[] = [false];
  let i = 0;
  const markQuantified = (unbounded: boolean): void => {
    if (unbounded) stack[stack.length - 1] = true;
  };
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') {
      i += 2;
    } else if (c === '[') {
      i += 1;
      if (src[i] === '^') i += 1;
      if (src[i] === ']') i += 1;
      while (i < src.length && src[i] !== ']') i += src[i] === '\\' ? 2 : 1;
      i += 1;
    } else if (c === '(') {
      stack.push(false);
      i += 1;
      if (src[i] === '?') {
        const head = /^\?(<[A-Za-z_$][\w$]*>|<=|<!|[:=!])/.exec(src.slice(i));
        if (head) i += head[0].length;
      }
      continue;
    } else if (c === ')') {
      const inner = stack.length > 1 ? (stack.pop() as boolean) : false;
      i += 1;
      const q = quantifierAt(src, i);
      if (q) {
        if (q.unbounded && inner) return true;
        i += q.length;
        markQuantified(q.unbounded || inner);
      } else if (inner) {
        markQuantified(true);
      }
      continue;
    } else {
      i += 1;
    }
    const q = quantifierAt(src, i);
    if (q) {
      markQuantified(q.unbounded);
      i += q.length;
    }
  }
  return false;
}

// line cap runs before the pattern does
function guardLineLength(regex: RegExp): RegExp {
  return new RegExp(`^(?![\\s\\S]{${MAX_LINE_LENGTH + 1}})[\\s\\S]*?(?:${regex.source})`, regex.flags);
}

// `/body/flags` literals work too
export function compilePattern(pattern: string): { regex: RegExp } | { error: string } {
  const raw = String(pattern ?? '');
  if (raw.trim() === '') return { error: 'pattern is empty' };
  if (raw.length > MAX_PATTERN_LENGTH) return { error: `pattern is longer than ${MAX_PATTERN_LENGTH} characters` };
  let body = raw;
  let flags = '';
  const literal = /^\/([\s\S]+)\/([a-z]*)$/.exec(raw.trim());
  if (literal && literal[1] !== undefined) {
    body = literal[1];
    flags = [...new Set((literal[2] ?? '').split('').filter((f) => 'imsu'.includes(f)))].join('');
  }
  let regex: RegExp;
  try {
    regex = new RegExp(body, flags);
  } catch (err) {
    const message = (err as Error).message;
    return { error: message.startsWith('Invalid regular expression') ? message : `Invalid regular expression: ${message}` };
  }
  if (hasNestedQuantifier(body)) return { error: `Pattern rejected: ${NESTED_HINT}` };
  return { regex };
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

function formatMatch(m: SearchMatch): string {
  const text = m.text.trim();
  const shown = text.length > 200 ? `${text.slice(0, 197)}...` : text;
  return `${m.path}:${m.line}: ${shown}${m.scope && m.scope !== 'source' ? ` [${m.scope}]` : ''}`;
}

export function makeSearchCodeHandler(overrides: Partial<SearchCodeDeps> = {}): ToolHandler<SearchCodeArgs> {
  const deps: SearchCodeDeps = { searchProject, ...overrides };
  return async (args: SearchCodeArgs, ctx: ToolContext): Promise<ToolResult> => {
    const compiled = compilePattern(args.pattern);
    if ('error' in compiled) return { ok: false, error: compiled.error, hint: ESCAPE_HINT };
    const max = Math.min(Math.max(Math.trunc(args.maxResults ?? SEARCH_DEFAULT_RESULTS) || SEARCH_DEFAULT_RESULTS, 1), SEARCH_MAX_RESULTS);
    const fileGlob = args.fileGlob?.trim() ? args.fileGlob.trim().replace(/^\.\//, '') : undefined;
    const found = await deps.searchProject(ctx.projectRoot, guardLineLength(compiled.regex), {
      exclude: ctx.config?.exclude ?? DEFAULT_EXCLUDES,
      ...(fileGlob ? { fileGlob } : {}),
      maxResults: max + 10,
      contextLines: 0,
      skipMinified: true,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });
    const kept = found.matches.filter((m) => !LOCKFILES.has(basename(m.path)) && !isSecretPath(m.path) && m.text.length <= MAX_LINE_LENGTH);
    const dropped = found.matches.length - kept.length;
    const total = Math.max(kept.length, found.total - dropped);
    const shown = kept.slice(0, max);
    const where = fileGlob ? ` in ${fileGlob}` : '';
    const label = `/${compiled.regex.source}/${compiled.regex.flags}`;
    if (shown.length === 0) {
      return { ok: true, hint: `No matches for ${label}${where}`, data: { pattern: compiled.regex.source, total: 0, matches: [] } };
    }
    const files = new Set(shown.map((m) => m.path)).size;
    const more = total > shown.length;
    const hint = `${total} match${total === 1 ? '' : 'es'}${more ? ` (showing ${shown.length})` : ''} in ${files}${more ? '+' : ''} file${files === 1 && !more ? '' : 's'}${where}`;
    const lines = shown.map(formatMatch);
    if (more) lines.push(`... ${total - shown.length} more; narrow the pattern or add fileGlob`);
    return { ok: true, hint, text: lines.join('\n'), truncated: more || found.truncated };
  };
}

export async function handleSearchCode(args: SearchCodeArgs, ctx: ToolContext): Promise<ToolResult> {
  return defaultHandler(args, ctx);
}

const defaultHandler = makeSearchCodeHandler();
