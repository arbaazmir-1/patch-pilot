import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { discoverProject, generateScratchLockfile, LOCKFILE_COMMAND, unsupportedLockfileMessage } from '../../src/evidence/discover.ts';
import { EnvironmentError } from '../../src/util/errors.ts';
import { tempDir } from './helpers.ts';

async function project(files: Record<string, string>): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const tmp = await tempDir('pp-discover-');
  for (const [name, content] of Object.entries(files)) await writeFile(path.join(tmp.dir, name), content);
  return tmp;
}

const PKG = JSON.stringify({ name: 'demo', version: '1.0.0' });

describe('discoverProject', () => {
  it('prefers npm-shrinkwrap.json over package-lock.json', async () => {
    const tmp = await project({ 'package.json': PKG, 'package-lock.json': '{}', 'npm-shrinkwrap.json': '{}' });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'npm-shrinkwrap');
      assert.equal(result.lockfilePath, path.join(tmp.dir, 'npm-shrinkwrap.json'));
      assert.equal(result.needsLockfile, false);
      assert.equal(result.packageJsonPath, path.join(tmp.dir, 'package.json'));
      assert.deepEqual(result.unsupported, []);
      assert.equal(unsupportedLockfileMessage(result), '');
    } finally {
      await tmp.cleanup();
    }
  });

  it('finds package-lock.json', async () => {
    const tmp = await project({ 'package.json': PKG, 'package-lock.json': '{}' });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'package-lock');
      assert.equal(result.needsLockfile, false);
    } finally {
      await tmp.cleanup();
    }
  });

  it('flags a project with only package.json', async () => {
    const tmp = await project({ 'package.json': PKG });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfilePath, null);
      assert.equal(result.needsLockfile, true);
      const message = unsupportedLockfileMessage(result);
      assert.match(message, /No package-lock\.json, npm-shrinkwrap\.json, yarn\.lock or pnpm-lock\.yaml/);
      assert.match(message, /\.patch-pilot\/tmp\//);
      assert.ok(message.includes(LOCKFILE_COMMAND));
    } finally {
      await tmp.cleanup();
    }
  });

  it('reports a bun lockfile with the scratch-lockfile workaround', async () => {
    const tmp = await project({ 'package.json': PKG, 'bun.lockb': '' });
    try {
      const result = await discoverProject(tmp.dir);
      assert.deepEqual(result.unsupported, [{ kind: 'bun', file: 'bun.lockb' }]);
      assert.equal(result.needsLockfile, true);
      assert.equal(result.lockfilePath, null);
      const message = unsupportedLockfileMessage(result);
      assert.match(message, /Found bun\.lockb \(Bun\): Bun lockfiles are not supported yet \(npm, yarn and pnpm lockfiles are\)/);
      assert.match(message, /Workaround/);
      assert.ok(message.includes(LOCKFILE_COMMAND));
      assert.match(message, /can differ from the ones pinned/);
    } finally {
      await tmp.cleanup();
    }
  });

  it('notes a bun lockfile next to a supported one', async () => {
    const tmp = await project({ 'package.json': PKG, 'pnpm-lock.yaml': "lockfileVersion: '9.0'\n", 'bun.lock': '{}' });
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.lockfileKind, 'pnpm');
      assert.match(unsupportedLockfileMessage(result), /Using pnpm-lock\.yaml, which may not match the Bun lockfile/);
    } finally {
      await tmp.cleanup();
    }
  });

  it('explains a directory without package.json', async () => {
    const tmp = await project({});
    try {
      const result = await discoverProject(tmp.dir);
      assert.equal(result.packageJsonPath, null);
      assert.equal(result.needsLockfile, false);
      assert.match(unsupportedLockfileMessage(result), /No package\.json in .*npm, yarn and pnpm projects/s);
    } finally {
      await tmp.cleanup();
    }
  });
});

describe('generateScratchLockfile', () => {
  it('runs npm on a copy of package.json in the scratch directory and leaves the project alone', async () => {
    const tmp = await project({ 'package.json': JSON.stringify({ name: 'scratch-demo', version: '1.0.0', private: true }), '.npmrc': 'fund=false\n' });
    try {
      const before = (await readdir(tmp.dir)).sort();
      const tmpDir = path.join(tmp.dir, '.patch-pilot', 'tmp');
      const lockfile = await generateScratchLockfile(tmp.dir, tmpDir);
      assert.equal(lockfile, path.join(tmpDir, 'scratch', 'package-lock.json'));
      const lock = JSON.parse(readFileSync(lockfile, 'utf8')) as { name: string; lockfileVersion: number };
      assert.equal(lock.name, 'scratch-demo');
      assert.ok(lock.lockfileVersion >= 2);
      assert.equal(existsSync(path.join(tmpDir, 'scratch', '.npmrc')), false, 'the copied .npmrc is removed again');
      assert.deepEqual((await readdir(tmp.dir)).filter((f) => f !== '.patch-pilot').sort(), before);
      assert.equal(existsSync(path.join(tmp.dir, 'package-lock.json')), false);
    } finally {
      await tmp.cleanup();
    }
  });

  it('refuses workspaces and a missing package.json without running npm', async () => {
    const tmp = await project({ 'package.json': JSON.stringify({ name: 'mono', workspaces: ['packages/*'] }) });
    try {
      await mkdir(path.join(tmp.dir, 'packages'));
      await assert.rejects(generateScratchLockfile(tmp.dir, path.join(tmp.dir, '.patch-pilot', 'tmp')), (err: unknown) => {
        assert.ok(err instanceof EnvironmentError);
        assert.match(err.message, /workspaces/);
        return true;
      });
      await assert.rejects(generateScratchLockfile(path.join(tmp.dir, 'packages'), path.join(tmp.dir, 't')), /No package\.json/);
    } finally {
      await tmp.cleanup();
    }
  });
});
