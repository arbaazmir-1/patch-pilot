import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { access, chmod, mkdir, readFile, realpath, rename, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

export class PathEscapeError extends Error {
  readonly target: string;
  constructor(target: string, root: string) {
    super(`Path is outside the project: ${target} (project root: ${root})`);
    this.name = 'PathEscapeError';
    this.target = target;
  }
}

export function toPosix(p: string): string {
  return p.split(path.sep).join('/').replace(/\\/g, '/');
}

// root itself counts
export function isPathInside(root: string, target: string): boolean {
  if (target.includes('\0')) return false;
  const base = path.resolve(root);
  const resolved = path.resolve(base, target);
  const rel = path.relative(base, resolved);
  if (rel === '') return true;
  if (path.isAbsolute(rel)) return false;
  return rel !== '..' && !rel.startsWith(`..${path.sep}`) && !rel.startsWith('../');
}

export function resolveInside(root: string, target: string): string {
  if (!isPathInside(root, target)) throw new PathEscapeError(target, root);
  return path.resolve(root, target);
}

// also rejects escaping symlinks
export async function resolveInsideReal(root: string, target: string): Promise<string> {
  const lexical = resolveInside(root, target);
  const realRoot = await realpath(root);
  let probe = lexical;
  const tail: string[] = [];
  for (;;) {
    try {
      const real = await realpath(probe);
      const full = tail.length > 0 ? path.join(real, ...tail.reverse()) : real;
      if (!isPathInside(realRoot, full)) throw new PathEscapeError(target, root);
      return lexical;
    } catch (err) {
      if (err instanceof PathEscapeError) throw err;
      const parent = path.dirname(probe);
      if (parent === probe) throw err;
      tail.push(path.basename(probe));
      probe = parent;
    }
  }
}

export function relativePosix(root: string, abs: string): string {
  return toPosix(path.relative(root, abs));
}

export function sha256(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export async function sha256File(file: string): Promise<string> {
  return sha256(await readFile(file));
}

// stable hashes and cache keys
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value instanceof Map) return sortKeys(Object.fromEntries(value));
  if (value instanceof Set) return [...value].map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

export function hashJson(value: unknown): string {
  return sha256(stableStringify(value));
}

export async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

export interface AtomicWriteOptions {
  // existing files keep their mode
  mode?: number;
}

// readers never see half a file
export async function atomicWrite(file: string, data: string | Uint8Array, options: AtomicWriteOptions = {}): Promise<void> {
  const dir = path.dirname(file);
  await ensureDir(dir);
  let mode = options.mode;
  try {
    mode = (await stat(file)).mode & 0o7777;
  } catch {
  }
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  try {
    await writeFile(tmp, data, mode === undefined ? undefined : { mode });
    if (mode !== undefined) await chmod(tmp, mode);
    await rename(tmp, file);
  } catch (err) {
    await unlink(tmp).catch(() => {});
    throw err;
  }
}

// two spaces by default
export function detectIndent(text: string): string {
  const match = /^([ \t]+)\S/m.exec(text);
  if (!match || match[1] === undefined) return '  ';
  const indent = match[1];
  if (indent.startsWith('\t')) return '\t';
  return indent;
}

export function detectEol(text: string): '\n' | '\r\n' {
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/(?<!\r)\n/g) ?? []).length;
  return crlf > lf ? '\r\n' : '\n';
}

export async function readJsonFile<T = unknown>(file: string): Promise<T> {
  const text = await readFile(file, 'utf8');
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new Error(`Invalid JSON in ${file}: ${(err as Error).message}`, { cause: err });
  }
}

export async function readJsonIfExists<T = unknown>(file: string): Promise<T | null> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new Error(`Invalid JSON in ${file}: ${(err as Error).message}`, { cause: err });
  }
}

export interface JsonWriteOptions {
  indent?: string | number;
  eol?: '\n' | '\r\n';
  // default true
  trailingNewline?: boolean;
}

export function formatJson(value: unknown, options: JsonWriteOptions = {}): string {
  const eol = options.eol ?? '\n';
  let text = JSON.stringify(value, null, options.indent ?? 2);
  if (eol === '\r\n') text = text.replace(/\n/g, '\r\n');
  return options.trailingNewline === false ? text : text + eol;
}

export async function writeJsonAtomic(file: string, value: unknown, options: JsonWriteOptions = {}): Promise<void> {
  await atomicWrite(file, formatJson(value, options));
}

// keeps formatting, missing file is {}
export async function updateJsonFile<T extends Record<string, unknown>>(file: string, update: (current: T) => T): Promise<T> {
  let text: string | null = null;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  let current = {} as T;
  if (text !== null && text.trim() !== '') {
    try {
      current = JSON.parse(text) as T;
    } catch (err) {
      throw new Error(`Invalid JSON in ${file}: ${(err as Error).message}`, { cause: err });
    }
  }
  const next = update(current);
  const options: JsonWriteOptions =
    text === null
      ? {}
      : { indent: detectIndent(text), eol: detectEol(text), trailingNewline: /\n$/.test(text) };
  await writeJsonAtomic(file, next, options);
  return next;
}
