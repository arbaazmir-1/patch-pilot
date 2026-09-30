// read_file, confined to root
import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import type { ToolContext, ToolResult } from '../../types.ts';
import { PathEscapeError, relativePosix, resolveInsideReal, toPosix } from '../../util/fs.ts';

export interface ReadFileArgs {
  path: string;
  startLine?: number;
  endLine?: number;
}

export const READ_DEFAULT_LINES = 40;
export const READ_MAX_LINES = 120;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_LINE_CHARS = 300;

export function normalizeProjectPath(p: string): string {
  return toPosix(String(p ?? '').trim())
    .replace(/^\.\/+/, '')
    .replace(/\/{2,}/g, '/');
}

const SECRET_NAMES = new Set(['.env', '.npmrc', '.yarnrc', '.yarnrc.yml', '.netrc', '.pypirc']);
const SECRET_DIRS = new Set(['.git', '.patch-pilot']);
const SECRET_EXTENSIONS = ['.pem', '.key', '.p12', '.pfx'];

// credentials the model never sees
export function isSecretPath(p: string): boolean {
  const segments = toPosix(String(p ?? '')).toLowerCase().split('/');
  return segments.some(
    (seg) =>
      SECRET_DIRS.has(seg) ||
      SECRET_NAMES.has(seg) ||
      seg.startsWith('.env.') ||
      SECRET_EXTENSIONS.some((ext) => seg.endsWith(ext)) ||
      /^id_[a-z0-9_-]+$/.test(seg),
  );
}

function withheld(shownPath: string): ToolResult {
  return { ok: false, error: `${shownPath} is withheld as a likely secret`, hint: 'Credential and VCS files are never read; look at source files instead' };
}

function knownFiles(ctx: ToolContext): string[] {
  const files = new Set<string>();
  for (const pkg of ctx.caseFile?.packages ?? []) for (const site of pkg.usage?.files ?? []) files.add(site.path);
  return [...files].slice(0, 8);
}

export async function handleReadFile(args: ReadFileArgs, ctx: ToolContext): Promise<ToolResult> {
  const rel = normalizeProjectPath(args.path);
  if (rel === '') return { ok: false, error: 'path is empty', hint: 'Give a project-relative path such as src/index.js' };
  let abs: string;
  try {
    abs = await resolveInsideReal(ctx.projectRoot, rel);
  } catch (err) {
    if (err instanceof PathEscapeError) {
      return { ok: false, error: `${args.path} is outside the project`, hint: 'Only files inside the project can be read; use a project-relative path such as src/index.js' };
    }
    return { ok: false, error: `Cannot resolve ${rel}: ${(err as Error).message}`, hint: 'Use a project-relative path' };
  }
  const shownPath = toPosix(rel);
  if (isSecretPath(rel) || isSecretPath(relativePosix(ctx.projectRoot, abs))) return withheld(shownPath);
  try {
    // symlinks onto secrets
    if (isSecretPath(relativePosix(await realpath(ctx.projectRoot), await realpath(abs)))) return withheld(shownPath);
  } catch {
    // missing, handled below
  }
  let info;
  try {
    info = await stat(abs);
  } catch {
    const known = knownFiles(ctx);
    return {
      ok: false,
      error: `File not found: ${shownPath}`,
      hint: known.length > 0 ? `Files that import the vulnerable packages: ${known.join(', ')}` : 'Use search_code to find the file first',
    };
  }
  if (info.isDirectory()) {
    let entries: string[] = [];
    try {
      entries = (await readdir(abs)).filter((e) => !e.startsWith('.')).sort().slice(0, 20);
    } catch {
      // unreadable dir
    }
    return { ok: false, error: `${shownPath} is a directory`, hint: entries.length > 0 ? `It contains: ${entries.join(', ')}` : 'Give a file path' };
  }
  if (info.size > MAX_FILE_BYTES) return { ok: false, error: `${shownPath} is too large to read (${info.size} bytes)`, hint: 'Use search_code to find the lines you need' };
  const buffer = await readFile(abs);
  if (buffer.includes(0)) return { ok: false, error: `${shownPath} is a binary file`, hint: 'Only text files can be read' };
  const lines = buffer.toString('utf8').split(/\r?\n/);
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  const total = lines.length;
  let start = Math.max(1, Math.trunc(args.startLine ?? 1) || 1);
  let requestedEnd = args.endLine === undefined ? start + READ_DEFAULT_LINES - 1 : Math.trunc(args.endLine);
  if (requestedEnd < start) {
    // reversed range, swap
    [start, requestedEnd] = [Math.max(1, requestedEnd), start];
  }
  if (start > total) {
    return { ok: false, error: `${shownPath} has only ${total} line${total === 1 ? '' : 's'}`, hint: `Use startLine between 1 and ${total}` };
  }
  let end = Math.min(requestedEnd, start + READ_MAX_LINES - 1, total);
  if (end < start) end = start;
  const omitted = Math.max(0, Math.min(requestedEnd, total) - end);
  const width = String(end).length;
  const body = lines
    .slice(start - 1, end)
    .map((text, i) => {
      const line = text.length > MAX_LINE_CHARS ? `${text.slice(0, MAX_LINE_CHARS)}...` : text;
      return `${String(start + i).padStart(width)}| ${line}`;
    })
    .join('\n');
  const notes: string[] = [];
  if (omitted > 0) notes.push(`${omitted} lines omitted, narrow the range (at most ${READ_MAX_LINES} lines per call)`);
  else if (args.endLine === undefined && end < total) notes.push(`${total - end} more lines below; read them with startLine ${end + 1}`);
  const hint = `${shownPath}:${start}-${end} of ${total} lines${omitted > 0 ? `, ${omitted} lines omitted` : ''}`;
  return {
    ok: true,
    hint,
    text: [`${shownPath} (lines ${start}-${end} of ${total})`, body, ...notes].join('\n'),
    truncated: omitted > 0,
  };
}
