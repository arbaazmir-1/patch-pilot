import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { discoverProject, parsePackageManagerField, unsupportedLockfileMessage } from '../../src/evidence/discover.ts';
import { tempDir } from './helpers.ts';
import { text } from './yarn-pnpm-helpers.ts';

async function project(files: Record<string, string>): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const tmp = await tempDir('pp-discover-pm-');
  for (const [name, content] of Object.entries(files)) await writeFile(path.join(tmp.dir, name), content);
  return tmp;
}

const pkg = (extra: Record<string, unknown> = {}): string => JSON.stringify({ name: 'demo', version: '1.0.0', ...extra });

describe('discoverProject: yarn and pnpm lockfiles', async () => {
  const yarn1 = await text('workspaces', 'yarn.lock');
  const berry = await text('workspaces', 'berry', 'yarn.lock');
  const pnpm = await text('workspaces', 'pnpm-lock.yaml');

  it('finds yarn.lock and tells yarn 1 from yarn 2+ by the file', async () => {
    for (const [lock, manager] of [
      [yarn1, 'yarn'],
      [berry, 'yarn-berry'],
    ] as const) {
      const tmp = await project({ 'package.json': pkg(), 'yarn.lock': lock });
      try {
        const result = await discoverProject(tmp.dir);
        assert.equal(result.lockfileKind, 'yarn');
        assert.equal(result.lockfilePath, path.join(tmp.dir, 'yarn.lock'));
        assert.equal(result.packageManager, manager);
        assert.equal(result.needsLockfile, false);
        assert.deepEqual(result.unsupported, []);
        assert.equal(unsupportedLockfileMessage(result), '');
      } finally {
        await tmp.cleanup();
      }
    }
  });

  it('uses the packageManager field when the yarn.lock is still empty', async () => {
    const tmp = await project({ 'package.json': pkg({ packageManager: 'yarn@4.18.0' }), 'yarn.lock': '' });
    try {
      assert.equal((await discoverProject(tmp.dir)).packageManager, 'yarn-berry');
    } finally {
      await tmp.cleanup();
    }
  });

  it('finds pnpm-lock.yaml', async () => {
    const tmp = await project({ 'package.json': pkg(), 'pnpm-lock.yaml': pnpm });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'pnpm');
      assert.equal(result.packageManager, 'pnpm');
    } finally {
      await tmp.cleanup();
    }
  });

  it('precedence without packageManager: npm-shrinkwrap > package-lock > pnpm > yarn, the others listed', async () => {
    const tmp = await project({ 'package.json': pkg(), 'package-lock.json': '{}', 'pnpm-lock.yaml': pnpm, 'yarn.lock': yarn1 });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'package-lock');
      assert.equal(result.packageManager, 'npm');
      assert.equal(result.chosenBy, 'precedence');
      assert.deepEqual(result.otherLockfiles, [
        { kind: 'pnpm', file: 'pnpm-lock.yaml' },
        { kind: 'yarn', file: 'yarn.lock' },
      ]);
      const message = unsupportedLockfileMessage(result);
      assert.match(message, /Found several lockfiles: package-lock\.json, pnpm-lock\.yaml, yarn\.lock\. Using package-lock\.json/);
      assert.match(message, /pnpm-lock\.yaml and yarn\.lock are not scanned/);
      assert.match(message, /set "packageManager" in package\.json/);
    } finally {
      await tmp.cleanup();
    }
    const two = await project({ 'package.json': pkg(), 'pnpm-lock.yaml': pnpm, 'yarn.lock': berry });
    try {
      const result = await discoverProject(two.dir);
      assert.equal(result.lockfileKind, 'pnpm', 'pnpm before yarn');
      assert.match(unsupportedLockfileMessage(result), /yarn\.lock is not scanned/);
    } finally {
      await two.cleanup();
    }
  });

  it('the lockfile of the packageManager field wins', async () => {
    const tmp = await project({ 'package.json': pkg({ packageManager: 'yarn@1.22.22+sha512.abc' }), 'package-lock.json': '{}', 'yarn.lock': yarn1 });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'yarn');
      assert.equal(result.packageManager, 'yarn');
      assert.equal(result.chosenBy, 'packageManager');
      assert.equal(result.packageManagerField, 'yarn@1.22.22+sha512.abc');
      assert.match(unsupportedLockfileMessage(result), /Using yarn\.lock \(package\.json says "packageManager": "yarn@1\.22\.22"\); package-lock\.json is not scanned/);
    } finally {
      await tmp.cleanup();
    }
    const missing = await project({ 'package.json': pkg({ packageManager: 'pnpm@9.15.9' }), 'package-lock.json': '{}' });
    try {
      const result = await discoverProject(missing.dir);
      assert.equal(result.lockfileKind, 'package-lock', 'no pnpm-lock.yaml: the precedence decides');
      assert.equal(result.packageManager, 'npm');
    } finally {
      await missing.cleanup();
    }
  });

  it('npm-shrinkwrap.json next to package-lock.json is not a warning (npm itself ignores package-lock.json then)', async () => {
    const tmp = await project({ 'package.json': pkg(), 'package-lock.json': '{}', 'npm-shrinkwrap.json': '{}' });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'npm-shrinkwrap');
      assert.deepEqual(result.otherLockfiles, []);
      assert.equal(unsupportedLockfileMessage(result), '');
    } finally {
      await tmp.cleanup();
    }
  });

  it('without a lockfile, the packageManager field still names the manager', async () => {
    const tmp = await project({ 'package.json': pkg({ packageManager: 'pnpm@10.34.5' }) });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.needsLockfile, true);
      assert.equal(result.packageManager, 'pnpm');
    } finally {
      await tmp.cleanup();
    }
  });

  it('parses the packageManager field', () => {
    assert.deepEqual(parsePackageManagerField('pnpm@9.15.9+sha512.68046141893c66fad01c079231128e9afb89ef87e2691d69e4d40eee228988295fd4682181bae55b58418c3a253bde65a505ec7c5f9403ece5cc3cd37dcf2531'), { name: 'pnpm', version: '9.15.9' });
    assert.deepEqual(parsePackageManagerField('yarn@4.18.0'), { name: 'yarn', version: '4.18.0' });
    assert.deepEqual(parsePackageManagerField('npm'), { name: 'npm', version: null });
    assert.equal(parsePackageManagerField('deno@2'), null);
    assert.equal(parsePackageManagerField(42), null);
  });
});
