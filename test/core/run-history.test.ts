import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { projectPaths } from '../../src/config.ts';
import { archiveLastRun, clearProjectState, runId } from '../../src/runHistory.ts';
import type { Config } from '../../src/types.ts';

let root = '';

afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

async function project(): Promise<Config> {
  root = await mkdtemp(path.join(os.tmpdir(), 'pp-history-'));
  const config = { projectRoot: root, paths: projectPaths(root, root) } as Config;
  await mkdir(config.paths.stateDir, { recursive: true });
  return config;
}

async function lastRun(config: Config, generatedAt = '2026-09-30T08:15:02.123Z'): Promise<void> {
  const state = config.paths.stateDir;
  await writeFile(path.join(state, 'case-file.json'), '{"case":1}');
  await writeFile(path.join(state, 'assessment.json'), '{"updatedAt":"2026-09-30T08:14:00.000Z"}');
  await writeFile(path.join(state, 'report.md'), '# old report');
  await writeFile(path.join(state, 'report.json'), JSON.stringify({ schema: 'patch-pilot.report', generatedAt }));
  await writeFile(path.join(state, 'verdict-cache.json'), '{"cache":1}');
  await writeFile(path.join(state, 'audit.jsonl'), '{}\n');
}

describe('run history', () => {
  it('names a run folder by time, safe for file systems', () => {
    assert.equal(runId(new Date('2026-09-30T08:15:02.123Z')), '2026-09-30T08-15-02Z');
  });

  it('copies the last run into history/<time> and leaves the originals', async () => {
    const config = await project();
    await lastRun(config);
    const archived = await archiveLastRun(config);
    assert.deepEqual(archived, {
      dir: '.patch-pilot/history/2026-09-30T08-15-02Z',
      files: ['case-file.json', 'assessment.json', 'report.md', 'report.json'],
    });
    const dir = path.join(root, archived.dir);
    assert.equal(await readFile(path.join(dir, 'report.md'), 'utf8'), '# old report');
    assert.ok((await readdir(config.paths.stateDir)).includes('report.md'), 'original kept for this run');
  });

  it('keeps the verdict cache in the archive with --fresh', async () => {
    const config = await project();
    await lastRun(config);
    const archived = await archiveLastRun(config, { withCache: true });
    assert.ok(archived?.files.includes('verdict-cache.json'));
  });

  it('does not archive the same run twice or a project never scanned', async () => {
    const config = await project();
    assert.equal(await archiveLastRun(config), null);
    await lastRun(config);
    assert.ok(await archiveLastRun(config));
    assert.equal(await archiveLastRun(config), null);
  });

  it('archives each rerun separately', async () => {
    const config = await project();
    await lastRun(config, '2026-09-30T08:15:02.000Z');
    await archiveLastRun(config);
    await lastRun(config, '2026-10-01T09:00:00.000Z');
    await archiveLastRun(config);
    assert.deepEqual(await readdir(path.join(config.paths.stateDir, 'history')), ['2026-09-30T08-15-02Z', '2026-10-01T09-00-00Z']);
  });

  it('--fresh clears the current results and cache, keeps history, backups and the audit log', async () => {
    const config = await project();
    await lastRun(config);
    await mkdir(path.join(config.paths.stateDir, 'backup', 'b1'), { recursive: true });
    await archiveLastRun(config, { withCache: true });
    const removed = await clearProjectState(config);
    assert.deepEqual(removed.sort(), [
      '.patch-pilot/assessment.json',
      '.patch-pilot/case-file.json',
      '.patch-pilot/report.json',
      '.patch-pilot/report.md',
      '.patch-pilot/verdict-cache.json',
    ]);
    assert.deepEqual((await readdir(config.paths.stateDir)).sort(), ['audit.jsonl', 'backup', 'history']);
  });
});
