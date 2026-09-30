import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readAuditFile } from '../../src/audit.ts';

const BIN = fileURLToPath(new URL('../../bin/patch-pilot.ts', import.meta.url));
const PKG = JSON.parse(await readFile(fileURLToPath(new URL('../../package.json', import.meta.url)), 'utf8')) as { version: string };

let tmp: string;
let home: string;
let project: string;

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

function cli(args: string[], cwd?: string): Promise<Run> {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [BIN, ...args],
      { cwd: cwd ?? project, env: { ...process.env, HOME: home, NO_COLOR: '1', FORCE_COLOR: undefined, OLLAMA_API_KEY: '' }, timeout: 30_000 },
      (error, stdout, stderr) => {
        const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? ((error as { code: number }).code) : 1) : 0;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
    child.stdin?.end();
  });
}

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-cli-'));
  home = path.join(tmp, 'home');
  project = path.join(tmp, 'app');
  await mkdir(home, { recursive: true });
  await mkdir(project, { recursive: true });
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0' }));
});

after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe('patch-pilot CLI surface', () => {
  it('--help lists every command and --version prints the package version', async () => {
    const help = await cli(['--help']);
    assert.equal(help.code, 0);
    for (const command of ['scan', 'investigate', 'apply', 'report', 'ignore', 'trust', 'untrust', 'db', 'config', 'doctor', 'rollback']) {
      assert.match(help.stdout, new RegExp(`\\n  ${command}\\b`), command);
    }
    const version = await cli(['--version']);
    assert.equal(version.code, 0);
    assert.equal(version.stdout.trim(), PKG.version);
  });

  it('registers every scan flag from the plan', async () => {
    const help = await cli(['scan', '--help']);
    assert.equal(help.code, 0);
    for (const flag of [
      '--provider',
      '--model',
      '--codemod-model',
      '--ollama-host',
      '--num-ctx',
      '--max-steps',
      '--limit',
      '--only',
      '--max-cves',
      '--offline',
      '--dry-run',
      '--no-cache',
      '--approve-all',
      '--approve-codemods',
      '--approve ',
      '--trust',
      '--json',
      '--verbose',
      '--quiet',
      '--seed',
      '--search',
      '--ci',
      '--fail-on',
    ]) {
      assert.ok(help.stdout.includes(flag), flag);
    }
    assert.match((await cli(['investigate', '--help'])).stdout, /--resume/);
    assert.match((await cli(['doctor', '--help'])).stdout, /--fix/);
    assert.match((await cli(['ignore', '--help'])).stdout, /--reason <text>[\s\S]*--until <date>/);
    const db = await cli(['db', '--help']);
    assert.match(db.stdout, /sync/);
    assert.match(db.stdout, /status/);
    const config = await cli(['config', '--help']);
    for (const sub of ['set', 'get', 'unset']) assert.match(config.stdout, new RegExp(`\\n  ${sub} `), sub);
    assert.match((await cli(['config', 'set', '--help'])).stdout, /ollama-api-key/);
    assert.match((await cli(['config', 'get', '--help'])).stdout, /--reveal/);
  });

  it('usage errors exit 2', async () => {
    assert.equal((await cli(['scan', '--bogus'])).code, 2);
    assert.equal((await cli(['scan', '--provider', 'deepseek'])).code, 2);
    assert.equal((await cli(['scan', '--num-ctx', 'lots'])).code, 2);
    assert.equal((await cli(['ignore', 'GHSA-1'])).code, 2, '--reason is required');
    assert.equal((await cli(['db'])).code, 2, 'db needs a subcommand');
    assert.equal((await cli(['scan', path.join(tmp, 'missing-dir'), '--provider', 'mock'])).code, 2);
  });
});

describe('trust gate through the CLI', () => {
  it('an untrusted directory without a TTY exits 2 with the instruction', async () => {
    const res = await cli(['--provider', 'mock']);
    assert.equal(res.code, 2);
    assert.match(res.stderr, /Directory not trusted/);
    assert.match(res.stderr, /patch-pilot trust .* once, or pass --trust/);
  });

  it('trust lets the default command pass the gate; untrust closes it again', async () => {
    const trusted = await cli(['trust']);
    assert.equal(trusted.code, 0);
    assert.match(trusted.stdout, /Trusted /);
    const store = JSON.parse(await readFile(path.join(home, '.patch-pilot', 'trusted.json'), 'utf8')) as { directories: Record<string, unknown> };
    assert.equal(Object.keys(store.directories).length, 1);
    const audit = readAuditFile(path.join(project, '.patch-pilot', 'audit.jsonl'));
    assert.ok(audit.some((r) => r.event === 'trust.granted' && r.method === 'command'));

    const scan = await cli(['--provider', 'mock']);
    assert.notEqual(scan.code, 2, scan.stderr);
    assert.ok(!scan.stderr.includes('Directory not trusted'));
    const records = readAuditFile(path.join(project, '.patch-pilot', 'audit.jsonl'));
    const start = records.find((r) => r.event === 'scan.start');
    assert.ok(start && start.event === 'scan.start');
    assert.equal(start.provider, 'mock');
    assert.equal(start.model, 'mock');
    assert.ok(records.some((r) => r.event === 'preflight'));

    assert.equal((await cli(['untrust'])).code, 0);
    assert.equal((await cli(['--provider', 'mock'])).code, 2);
  });

  it('--trust pre-accepts and records how trust was granted', async () => {
    const dir = path.join(tmp, 'ci-app');
    await mkdir(dir);
    const res = await cli(['scan', dir, '--provider', 'mock', '--trust', '--quiet']);
    assert.notEqual(res.code, 2, res.stderr);
    const audit = readAuditFile(path.join(dir, '.patch-pilot', 'audit.jsonl'));
    assert.ok(audit.some((r) => r.event === 'trust.granted' && r.method === 'flag'));
  });
});

describe('ignore and doctor through the CLI', () => {
  it('ignore records the accepted risk in patch-pilot.config.json and the audit log', async () => {
    const res = await cli(['ignore', 'GHSA-xvch-5gv4-984h', '--reason', 'argv comes from our build scripts', '--until', '2099-01-31', '--package', 'minimist', '--trust']);
    assert.equal(res.code, 0, res.stderr);
    const config = JSON.parse(await readFile(path.join(project, 'patch-pilot.config.json'), 'utf8')) as { ignore: Record<string, string>[] };
    assert.equal(config.ignore[0]?.id, 'GHSA-xvch-5gv4-984h');
    assert.equal(config.ignore[0]?.package, 'minimist');
    assert.equal(config.ignore[0]?.until, '2099-01-31');
    const audit = readAuditFile(path.join(project, '.patch-pilot', 'audit.jsonl'));
    assert.ok(audit.some((r) => r.event === 'risk.accepted' && r.vulnId === 'GHSA-xvch-5gv4-984h' && r.source === 'command'));
    assert.equal((await cli(['ignore', 'GHSA-1', '--reason', 'x', '--until', 'tomorrow', '--trust'])).code, 2);
  });

  it('doctor --json runs without Ollama for the mock provider', async () => {
    const res = await cli(['doctor', '--provider', 'mock', '--offline', '--json']);
    const result = JSON.parse(res.stdout) as { ok: boolean; checks: { id: string; status: string }[] };
    assert.equal(res.code, result.ok ? 0 : 3);
    assert.ok(result.checks.some((c) => c.id === 'node' && c.status === 'ok'));
    assert.ok(result.checks.some((c) => c.id === 'osv' && c.status === 'skip'));
  });
});
