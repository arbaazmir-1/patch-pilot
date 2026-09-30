// yarn and pnpm preflight and doctor
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { loadConfig } from '../../src/config.ts';
import { NEEDS, renderPreflight, runPreflight, summarizePreflight, type PreflightDeps } from '../../src/preflight.ts';
import type { Config, PackageManager } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

let root: string;
const ui = new Ui({ color: false, unicode: true });

before(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), 'pp-pm-preflight-'));
});
after(async () => {
  await rm(root, { recursive: true, force: true });
});

async function config(): Promise<Config> {
  return loadConfig({ dir: root, homeDir: root, env: {}, flags: { provider: 'mock' }, stdinIsTTY: false, stdoutIsTTY: false });
}

function deps(manager: PackageManager | null, onPath: string[]): Partial<PreflightDeps> {
  return {
    nodeVersion: '24.14.1',
    which: async (cmd) => (onPath.includes(cmd) ? `/usr/local/bin/${cmd}` : null),
    commandVersion: async (cmd) => (cmd === 'pnpm' ? '11.9.0' : cmd === 'corepack' ? '0.34.6' : cmd === 'git' ? 'git version 2.54.0' : '11.19.1'),
    fetch: (async () => new Response('{}', { status: 200 })) as typeof fetch,
    freeBytes: async () => 100 * 1024 ** 3,
    fileInfo: async () => null,
    now: () => 1_000,
    projectManager: async () => manager,
  };
}

describe('preflight: the package manager of a yarn or pnpm project', () => {
  it('an npm project keeps the npm check', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps('npm', ['npm', 'git']));
    const npm = result.checks.find((c) => c.id === 'npm');
    assert.equal(npm?.label, 'npm');
    assert.equal(npm?.status, 'ok');
  });

  it('pnpm on PATH: ok, with the version in doctor', async () => {
    const scan = await runPreflight(await config(), NEEDS.scan, deps('pnpm', ['pnpm', 'git']));
    assert.deepEqual(scan.checks.filter((c) => c.id === 'npm').map((c) => [c.label, c.status, c.detail]), [['pnpm', 'ok', '/usr/local/bin/pnpm']]);
    assert.equal(scan.ok, true);
    assert.match(summarizePreflight(scan, await config()), /^Node v24\.14\.1 · pnpm · mock provider$/);
    const doctor = await runPreflight(await config(), NEEDS.doctor, deps('pnpm', ['pnpm', 'git']));
    assert.equal(doctor.checks.find((c) => c.id === 'npm')?.detail, '11.9.0 (/usr/local/bin/pnpm)');
  });

  it('yarn through corepack: ok, PatchPilot runs it through corepack', async () => {
    const result = await runPreflight(await config(), NEEDS.scan, deps('yarn-berry', ['corepack', 'git']));
    const check = result.checks.find((c) => c.id === 'npm');
    assert.equal(check?.label, 'yarn 2+');
    assert.equal(check?.status, 'ok');
    assert.match(check?.detail ?? '', /yarn not on PATH: runs through corepack \(\/usr\/local\/bin\/corepack\)/);
  });

  it('neither the binary nor corepack: a hard failure for scan and apply, a warning in doctor and for investigate nothing', async () => {
    const scan = await runPreflight(await config(), NEEDS.scan, deps('pnpm', ['npm', 'git']));
    const check = scan.checks.find((c) => c.id === 'npm');
    assert.equal(scan.ok, false);
    assert.equal(check?.status, 'fail');
    assert.equal(check?.hard, true);
    assert.ok(check?.fix.includes('npm install -g pnpm'));
    assert.deepEqual(check?.links, ['https://pnpm.io/installation']);
    const text = renderPreflight(scan, ui, { mode: 'failure' });
    assert.match(text, /PatchPilot cannot start: pnpm was not found\./);
    assert.match(text, /npm install -g pnpm/);
    assert.match(text, /https:\/\/pnpm\.io\/installation/);

    const apply = await runPreflight(await config(), NEEDS.apply, deps('yarn', ['git']));
    assert.equal(apply.ok, false);
    assert.match(renderPreflight(apply, ui, { mode: 'failure' }), /corepack enable[\s\S]*https:\/\/yarnpkg\.com\/getting-started\/install/);

    const doctor = await runPreflight(await config(), NEEDS.doctor, deps('pnpm', ['npm', 'git']));
    const warned = doctor.checks.find((c) => c.id === 'npm');
    assert.equal(warned?.status, 'warn');
    assert.equal(warned?.hard, false);
    assert.equal(doctor.ok, true, 'doctor reports it; only commands that patch need it');

    const investigate = await runPreflight(await config(), NEEDS.investigate, deps('pnpm', []));
    assert.equal(investigate.checks.some((c) => c.id === 'npm'), false);
  });

  it('reads the manager from the project lockfile by default', async () => {
    await writeFile(path.join(root, 'package.json'), '{"name":"x","version":"1.0.0"}');
    await writeFile(path.join(root, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n");
    const { projectManager: _ignored, ...rest } = deps(null, ['pnpm', 'git']);
    const result = await runPreflight(await config(), NEEDS.scan, rest);
    assert.equal(result.checks.find((c) => c.id === 'npm')?.label, 'pnpm');
  });
});
