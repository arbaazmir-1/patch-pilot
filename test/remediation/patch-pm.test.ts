// yarn and pnpm without running them
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { managerFailure, pnpmLockfileRefusal, resolveManager, type CommandRunner } from '../../src/remediation/patch.ts';
import type { RunResult } from '../../src/util/proc.ts';

let tmp: string;

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-pm-'));
});

after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe('starting yarn and pnpm', () => {
  const ok = (stdout: string): RunResult => ({ ok: true, code: 0, signal: null, stdout, stderr: '', error: null, durationMs: 1 });
  const missing = (): RunResult => ({ ok: false, code: null, signal: null, stdout: '', stderr: '', error: Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }), durationMs: 1 });
  const runner = (answers: Record<string, string | null>): CommandRunner & { calls: string[] } => {
    const calls: string[] = [];
    const fn = async (cmd: string, args: readonly string[]): Promise<RunResult> => {
      const key = [path.basename(cmd), ...args.slice(0, -1)].join(' ');
      calls.push(`${key} ${args[args.length - 1]}`);
      const version = answers[key];
      return version ? ok(`${version}\n`) : missing();
    };
    return Object.assign(fn, { calls });
  };

  it('npm is never probed', async () => {
    const fake = runner({});
    const resolved = await resolveManager('npm', tmp, fake);
    assert.equal(resolved.ok, true);
    assert.deepEqual(fake.calls, []);
  });

  it('prefers the binary on PATH and probes it in the project', async () => {
    const resolved = await resolveManager('pnpm', tmp, runner({ pnpm: '11.9.0' }));
    assert.ok(resolved.ok);
    assert.deepEqual(resolved.invocation.display, ['pnpm']);
    assert.equal(resolved.invocation.version, '11.9.0');
    assert.equal(resolved.invocation.env.COREPACK_ENABLE_DOWNLOAD_PROMPT, '0');
  });

  it('falls back to corepack with the packageManager version, and never runs yarn 2+ on a yarn 1 lockfile', async () => {
    const berry = await resolveManager('yarn-berry', tmp, runner({ 'corepack yarn@4.18.0': '4.18.0' }), { packageManagerField: 'yarn@4.18.0+sha224.abc' });
    assert.ok(berry.ok);
    assert.deepEqual(berry.invocation.display, ['corepack', 'yarn@4.18.0']);
    assert.equal(berry.invocation.env.YARN_ENABLE_SCRIPTS, '0');
    assert.match(berry.notes[0] ?? '', /yarn is not on PATH: running corepack yarn@4\.18\.0/);
    const classic = await resolveManager('yarn', tmp, runner({ yarn: '4.18.0', 'corepack yarn@1': '1.22.22' }));
    assert.ok(classic.ok);
    assert.deepEqual(classic.invocation.display, ['corepack', 'yarn@1']);
    assert.match(classic.notes[0] ?? '', /yarn on PATH is 4\.18\.0, which would convert the yarn 1 lockfile/);
    const guessed = await resolveManager('yarn-berry', tmp, runner({ 'corepack yarn@4': '4.18.0' }), { lockfileVersion: 8 });
    assert.ok(guessed.ok, 'no packageManager field: the yarn major of the lockfile format');
  });

  it('runs the yarn release a yarn 2+ project checks in', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-yarnpath-'));
    try {
      await mkdir(path.join(dir, '.yarn', 'releases'), { recursive: true });
      await writeFile(path.join(dir, '.yarn', 'releases', 'yarn-4.5.0.cjs'), '');
      await writeFile(path.join(dir, '.yarnrc.yml'), 'yarnPath: .yarn/releases/yarn-4.5.0.cjs\n');
      const resolved = await resolveManager('yarn-berry', dir, runner({ [`${path.basename(process.execPath)} ${path.join(dir, '.yarn', 'releases', 'yarn-4.5.0.cjs')}`]: '4.5.0' }));
      assert.ok(resolved.ok);
      assert.deepEqual(resolved.invocation.display, ['node', '.yarn/releases/yarn-4.5.0.cjs']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('says how to install the manager when nothing can run it', async () => {
    const pnpm = await resolveManager('pnpm', tmp, runner({}));
    assert.equal(pnpm.ok, false);
    if (pnpm.ok) return;
    assert.match(pnpm.error, /pnpm is needed to change the lockfile, but neither pnpm nor corepack \(pnpm\) could be started/);
    assert.ok(pnpm.fix.includes('npm install -g pnpm'));
    assert.deepEqual(pnpm.links, ['https://pnpm.io/installation']);
    const yarn = await resolveManager('yarn', tmp, runner({}));
    assert.ok(!yarn.ok && yarn.fix.some((f) => f.startsWith('corepack enable')) && yarn.links.includes('https://yarnpkg.com/getting-started/install'));
  });

  it('explains failures from the real error output of each manager', () => {
    const fail = (stdout: string, stderr = ''): RunResult => ({ ok: false, code: 1, signal: null, stdout, stderr, error: null, durationMs: 1 });
    assert.equal(
      managerFailure('yarn', fail('yarn upgrade v1.22.22\n[1/5] Validating package.json...\n[2/5] Resolving packages...\ninfo Visit https://yarnpkg.com/en/docs/cli/upgrade for documentation about this command.\n', 'error Couldn\'t find any versions for "lodash" that matches "99.0.0"\n')),
      'yarn exited with code 1: Couldn\'t find any versions for "lodash" that matches "99.0.0"',
    );
    assert.equal(
      managerFailure('yarn-berry', fail('➤ YN0000: · Yarn 4.18.0\n➤ YN0000: ┌ Resolution step\n➤ YN0082: │ lodash@npm:99.0.0: No candidates found\n➤ YN0000: └ Completed\n➤ YN0000: · Failed with errors in 0s 79ms\n')),
      'yarn exited with code 1: lodash@npm:99.0.0: No candidates found',
    );
    assert.equal(
      managerFailure('pnpm', fail('Progress: resolved 1, reused 0, downloaded 0, added 0\n[ERR_PNPM_NO_MATCHING_VERSION] No matching version found for lodash@99.0.0 while fetching it from https://registry.npmjs.org/\n\nThe latest release of lodash is "4.18.1".\n')),
      'pnpm exited with code 1: [ERR_PNPM_NO_MATCHING_VERSION] No matching version found for lodash@99.0.0 while fetching it from https://registry.npmjs.org/',
    );
    assert.equal(managerFailure('pnpm', { ...fail(''), error: Object.assign(new Error('x'), { code: 'ENOENT' }) }), 'pnpm was not found on PATH');
  });
});

describe('refusing lockfile-less setups', () => {
  it('refuses a pnpm setup that writes no lockfile', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-pnpm-refuse-'));
    try {
      assert.equal(await pnpmLockfileRefusal(dir), null);
      await writeFile(path.join(dir, '.npmrc'), 'lockfile=false\n');
      assert.match((await pnpmLockfileRefusal(dir)) ?? '', /\.npmrc sets lockfile=false/);
      await writeFile(path.join(dir, '.npmrc'), '');
      await writeFile(path.join(dir, 'pnpm-workspace.yaml'), 'lockfile: false\n');
      assert.match((await pnpmLockfileRefusal(dir)) ?? '', /pnpm-workspace\.yaml sets lockfile: false/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
