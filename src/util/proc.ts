// no shell, with timeouts
import { execFile } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { access, stat } from 'node:fs/promises';
import path from 'node:path';

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  // default 60 s
  timeoutMs?: number;
  // default 32 mb
  maxBuffer?: number;
  input?: string;
  signal?: AbortSignal;
}

export interface RunResult {
  ok: boolean;
  // null if it never started or was killed
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  // ENOENT, ETIMEDOUT
  error: NodeJS.ErrnoException | null;
  durationMs: number;
}

// never rejects
export function run(cmd: string, args: readonly string[], options: RunOptions = {}): Promise<RunResult> {
  const started = Date.now();
  return new Promise((resolve) => {
    const child = execFile(
      cmd,
      [...args],
      {
        cwd: options.cwd,
        env: options.env ?? process.env,
        timeout: options.timeoutMs ?? 60_000,
        maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
        signal: options.signal,
        windowsHide: true,
        encoding: 'utf8',
        shell: false,
      },
      (error, stdout, stderr) => {
        const err = error as (NodeJS.ErrnoException & { code?: number | string; killed?: boolean; signal?: string }) | null;
        const numericCode = err ? (typeof err.code === 'number' ? err.code : null) : 0;
        const spawnError = err && typeof err.code === 'string' ? err : err?.killed ? err : null;
        resolve({
          ok: !err,
          code: numericCode,
          signal: err?.signal ?? null,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
          error: spawnError,
          durationMs: Date.now() - started,
        });
      },
    );
    if (options.input !== undefined) {
      child.stdin?.end(options.input);
    }
  });
}

// no shell
export async function which(cmd: string, env: NodeJS.ProcessEnv = process.env): Promise<string | null> {
  if (cmd.includes('/') || cmd.includes('\\')) {
    return (await isExecutable(cmd)) ? path.resolve(cmd) : null;
  }
  const dirs = (env.PATH ?? env.Path ?? '').split(path.delimiter).filter(Boolean);
  const exts =
    process.platform === 'win32' ? (env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';').map((e) => e.toLowerCase()) : [''];
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, cmd + ext);
      if (await isExecutable(candidate)) return candidate;
    }
  }
  return null;
}

async function isExecutable(file: string): Promise<boolean> {
  try {
    const st = await stat(file);
    if (!st.isFile()) return false;
    if (process.platform === 'win32') return true;
    await access(file, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export async function gitConfig(key: string, cwd: string): Promise<string | null> {
  const res = await run('git', ['config', '--get', key], { cwd, timeoutMs: 5_000 });
  const value = res.stdout.trim();
  return res.ok && value !== '' ? value : null;
}

// origin, else first remote
export async function gitRemoteUrl(cwd: string): Promise<string | null> {
  const origin = await run('git', ['remote', 'get-url', 'origin'], { cwd, timeoutMs: 5_000 });
  if (origin.ok && origin.stdout.trim() !== '') return origin.stdout.trim();
  const remotes = await run('git', ['remote'], { cwd, timeoutMs: 5_000 });
  const first = remotes.ok ? remotes.stdout.split('\n').map((s) => s.trim()).find(Boolean) : undefined;
  if (!first) return null;
  const url = await run('git', ['remote', 'get-url', first], { cwd, timeoutMs: 5_000 });
  return url.ok && url.stdout.trim() !== '' ? url.stdout.trim() : null;
}

export async function commandVersion(cmd: string, args: readonly string[] = ['--version']): Promise<string | null> {
  const res = await run(cmd, args, { timeoutMs: 10_000 });
  if (!res.ok) return null;
  const line = (res.stdout || res.stderr).split('\n').map((s) => s.trim()).find(Boolean);
  return line ?? null;
}
