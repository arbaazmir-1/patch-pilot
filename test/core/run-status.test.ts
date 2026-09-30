import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, it } from 'node:test';
import { runStatusFile, trackRun, type RunStatusFile } from '../../src/runStatus.ts';
import type { Config } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

let dir = '';

async function setup(): Promise<{ config: Config; ui: Ui }> {
  dir = await mkdtemp(path.join(os.tmpdir(), 'pp-status-'));
  const config = { paths: { stateDir: path.join(dir, '.patch-pilot') } } as Config;
  const ui = new Ui({ quiet: true, color: false, stdout: new PassThrough(), stderr: new PassThrough() });
  return { config, ui };
}

async function readStatus(config: Config): Promise<RunStatusFile> {
  return JSON.parse(await readFile(runStatusFile(config), 'utf8')) as RunStatusFile;
}

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe('run status file', () => {
  it('writes running at start and mirrors status bar changes', async () => {
    const { config, ui } = await setup();
    const run = trackRun(config, ui, 'scan');
    let status = await readStatus(config);
    assert.equal(status.schema, 'patch-pilot.status');
    assert.equal(status.state, 'running');
    assert.equal(status.command, 'scan');
    assert.equal(status.pid, process.pid);

    ui.status.set({ phases: ui.phaseItems(2), activity: 'Investigating lodash@4.17.20', detail: 'CVE 3 of 12' });
    await wait(400);
    status = await readStatus(config);
    assert.deepEqual(
      status.phases.map((p) => p.state),
      ['done', 'current', 'pending'],
    );
    assert.equal(status.activity, 'Investigating lodash@4.17.20');
    assert.equal(status.detail, 'CVE 3 of 12');
    run.finish('done');
  });

  it('keeps the last phases when a set omits them', async () => {
    const { config, ui } = await setup();
    const run = trackRun(config, ui, 'scan');
    ui.status.set({ phases: ui.phaseItems(3) });
    ui.status.set({ activity: 'Planning the fixes' });
    run.finish('failed', new Error('registry down'));
    const status = await readStatus(config);
    assert.equal(status.state, 'failed');
    assert.equal(status.error, 'registry down');
    assert.equal(status.phases.length, 3);
    assert.equal(status.activity, null);
    assert.ok(status.finishedAt);
  });

  it('marks every phase done on success and ignores later changes', async () => {
    const { config, ui } = await setup();
    const run = trackRun(config, ui, 'apply');
    ui.status.set({ phases: ui.phaseItems(3) });
    run.finish('done');
    ui.status.set({ activity: 'late' });
    run.finish('failed');
    await wait(300);
    const status = await readStatus(config);
    assert.equal(status.state, 'done');
    assert.ok(status.phases.every((p) => p.state === 'done'));
    assert.equal(status.activity, null);
  });
});
