// phase 3 test doubles
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { loadConfig, type CliFlags } from '../../src/config.ts';
import { parseLockfile, type LockfileJson } from '../../src/evidence/lockfile.ts';
import type { PromptAdapter } from '../../src/remediation/approve.ts';
import type { CommandRunner } from '../../src/remediation/patch.ts';
import type { Assessment, CaseFile, Config, DependencyGraph, Identity, PackageJson } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';
import type { RunResult } from '../../src/util/proc.ts';

export const FIXTURE_APP = fileURLToPath(new URL('../../examples/vulnerable-app/', import.meta.url));
const FIXTURES = fileURLToPath(new URL('./patch-fixtures/', import.meta.url));

export const IDENTITY: Identity = { osUser: 'tester', gitName: 'Test User', gitEmail: 'test@example.com' };

export async function loadFixtures(): Promise<{ caseFile: CaseFile; assessment: Assessment }> {
  const caseFile = JSON.parse(await readFile(path.join(FIXTURES, 'case-file.json'), 'utf8')) as CaseFile;
  const assessment = JSON.parse(await readFile(path.join(FIXTURES, 'assessment.json'), 'utf8')) as Assessment;
  return { caseFile, assessment };
}

export async function fixtureLock(): Promise<LockfileJson> {
  return JSON.parse(await readFile(path.join(FIXTURE_APP, 'package-lock.json'), 'utf8')) as LockfileJson;
}

export async function fixturePackage(): Promise<PackageJson> {
  return JSON.parse(await readFile(path.join(FIXTURE_APP, 'package.json'), 'utf8')) as PackageJson;
}

export async function fixtureGraph(): Promise<DependencyGraph> {
  return parseLockfile(await fixtureLock(), await fixturePackage());
}

export function captureUi(options: ConstructorParameters<typeof Ui>[0] = {}): { ui: Ui; out: () => string; err: () => string; all: () => string } {
  let out = '';
  let err = '';
  let all = '';
  const stream = (write: (s: string) => void): Writable =>
    new Writable({
      write(chunk, _enc, cb) {
        write(String(chunk));
        cb();
      },
    });
  const ui = new Ui({
    color: false,
    env: {},
    width: 100,
    stdout: stream((s) => {
      out += s;
      all += s;
    }) as never,
    stderr: stream((s) => {
      err += s;
      all += s;
    }) as never,
    ...options,
  });
  return { ui, out: () => out, err: () => err, all: () => all };
}

export interface TempProject {
  dir: string;
  home: string;
  cleanup: () => Promise<void>;
}

// plus an empty HOME
export async function tempProject(): Promise<TempProject> {
  const base = await mkdtemp(path.join(os.tmpdir(), 'pp-phase3-'));
  const dir = path.join(base, 'app');
  const home = path.join(base, 'home');
  await mkdir(home, { recursive: true });
  await cp(FIXTURE_APP, dir, {
    recursive: true,
    filter: (src) => !/[\\/](\.patch-pilot|node_modules)([\\/]|$)/.test(src.slice(FIXTURE_APP.length - 1)),
  });
  return { dir, home, cleanup: () => rm(base, { recursive: true, force: true }) };
}

// tty makes it interactive
export async function projectConfig(dir: string, home: string, flags: CliFlags = {}, tty = false): Promise<Config> {
  return loadConfig({ dir, homeDir: home, env: {}, flags: { provider: 'mock', offline: true, ...flags }, stdinIsTTY: tty, stdoutIsTTY: tty });
}

// pops one answer per question
export function fakePrompt(answers: readonly string[]): PromptAdapter & { asked: string[] } {
  const queue = [...answers];
  const asked: string[] = [];
  const next = (question: string): string => {
    asked.push(question);
    const answer = queue.shift();
    if (answer === undefined) throw new Error(`No scripted answer for: ${question}`);
    return answer;
  };
  return {
    asked,
    select: async <T extends string>(message: string): Promise<T> => next(message) as T,
    input: async (message, options = {}) => {
      const value = next(message);
      const ok = options.validate ? options.validate(value) : true;
      if (ok !== true) throw new Error(`Invalid scripted answer for ${message}: ${ok}`);
      return value;
    },
    confirm: async (message) => next(message) === 'y',
    key: async (question, keys) => {
      const key = next(`${question} (${keys})`);
      if (!keys.split('/').includes(key)) throw new Error(`Key ${key} is not one of ${keys}`);
      return key;
    },
  };
}

function result(partial: Partial<RunResult>): RunResult {
  return { ok: true, code: 0, signal: null, stdout: '', stderr: '', error: null, durationMs: 1, ...partial };
}

async function readJson<T>(file: string): Promise<T> {
  return JSON.parse(await readFile(file, 'utf8')) as T;
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

function integrityFor(name: string, version: string): string {
  return `sha512-fake-${name}-${version}`;
}

export function setNodeVersion(lock: LockfileJson, key: string, version: string): void {
  const packages = lock.packages as Record<string, Record<string, unknown>>;
  const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
  packages[key] = {
    ...(packages[key] ?? {}),
    version,
    resolved: `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${version}.tgz`,
    integrity: integrityFor(name, version),
  };
}

export interface FakeNpmOptions {
  updateTo?: Record<string, string>;
  renest?: boolean;
  // unexpected extra node
  extra?: (lock: LockfileJson) => void;
  fail?: string;
  // default: not a repo
  git?: Partial<RunResult>;
}

// records calls
export function fakeNpm(options: FakeNpmOptions = {}): CommandRunner & { calls: { cmd: string; args: string[]; cwd: string | undefined }[] } {
  const calls: { cmd: string; args: string[]; cwd: string | undefined }[] = [];
  const runner = async (cmd: string, args: readonly string[], runOptions: { cwd?: string } = {}): Promise<RunResult> => {
    calls.push({ cmd, args: [...args], cwd: runOptions.cwd });
    if (cmd === 'git') return result({ ok: false, code: 128, stderr: 'fatal: not a git repository', ...(options.git ?? {}) });
    const cwd = runOptions.cwd as string;
    if (options.fail) return result({ ok: false, code: 1, stderr: options.fail });
    const lockFile = path.join(cwd, 'package-lock.json');
    const pkgFile = path.join(cwd, 'package.json');
    const lock = await readJson<LockfileJson>(lockFile);
    const pkg = await readJson<PackageJson>(pkgFile);
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    const [command, target] = args;
    if (command === 'install' && target && !target.startsWith('-')) {
      const at = target.lastIndexOf('@');
      const name = target.slice(0, at);
      const version = target.slice(at + 1);
      const spec = args.includes('--save-exact') ? version : args.includes('--save-prefix=~') ? `~${version}` : `^${version}`;
      const section = args.includes('--save-dev') ? 'devDependencies' : args.includes('--save-optional') ? 'optionalDependencies' : 'dependencies';
      pkg[section] = { ...((pkg[section] as Record<string, string> | undefined) ?? {}), [name]: spec };
      (packages[''] as Record<string, Record<string, string>>)[section] = { ...((packages[''] as Record<string, Record<string, string>>)[section] ?? {}), [name]: spec };
      setNodeVersion(lock, `node_modules/${name}`, version);
    } else if (command === 'update' && target) {
      const to = options.updateTo?.[target];
      if (to) setNodeVersion(lock, `node_modules/${target}`, to);
    } else if (command === 'install') {
      for (const [parent, value] of Object.entries((pkg.overrides ?? {}) as Record<string, unknown>)) {
        if (!value || typeof value !== 'object') continue;
        for (const [name, version] of Object.entries(value as Record<string, string>)) {
          if (name === '.') continue;
          if (options.renest) {
            delete packages[`node_modules/${name}`];
            setNodeVersion(lock, `node_modules/${parent}/node_modules/${name}`, version);
          } else {
            setNodeVersion(lock, `node_modules/${name}`, version);
          }
        }
      }
    }
    options.extra?.(lock);
    await writeJson(lockFile, lock);
    await writeJson(pkgFile, pkg);
    return result({ stdout: '\nup to date in 1ms\n', stderr: 'npm notice New major version of npm available!\n' });
  };
  return Object.assign(runner, { calls });
}
