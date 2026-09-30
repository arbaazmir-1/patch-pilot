import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { projectPaths } from '../../src/config.ts';
import { clearProjectState } from '../../src/reset.ts';
import type { Config } from '../../src/types.ts';

let root = '';

afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

async function project(): Promise<Config> {
  root = await mkdtemp(path.join(os.tmpdir(), 'pp-reset-'));
  return { projectRoot: root, paths: projectPaths(root, root) } as Config;
}

describe('clearProjectState', () => {
  it('removes findings, verdicts, cache, reports and status, keeps backups and the audit log', async () => {
    const config = await project();
    const state = config.paths.stateDir;
    await mkdir(path.join(state, 'backup', '2026-10-01T00-00-00Z'), { recursive: true });
    await mkdir(path.join(state, 'tmp', 'yarn-modules'), { recursive: true });
    for (const name of ['case-file.json', 'assessment.json', 'verdict-cache.json', 'report.md', 'report.json', 'status.json', 'audit.jsonl', 'debug.log']) {
      await writeFile(path.join(state, name), '{}');
    }
    await writeFile(path.join(state, 'backup', '2026-10-01T00-00-00Z', 'package.json'), '{}');

    const removed = await clearProjectState(config);

    assert.deepEqual(removed.sort(), [
      '.patch-pilot/assessment.json',
      '.patch-pilot/case-file.json',
      '.patch-pilot/debug.log',
      '.patch-pilot/report.json',
      '.patch-pilot/report.md',
      '.patch-pilot/status.json',
      '.patch-pilot/tmp',
      '.patch-pilot/verdict-cache.json',
    ]);
    assert.deepEqual((await readdir(state)).sort(), ['audit.jsonl', 'backup']);
    assert.deepEqual(await readdir(path.join(state, 'backup', '2026-10-01T00-00-00Z')), ['package.json']);
  });

  it('is a no-op on a project that was never scanned', async () => {
    const config = await project();
    assert.deepEqual(await clearProjectState(config), []);
  });
});
