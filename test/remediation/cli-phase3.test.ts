import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadFixtures, tempProject, type TempProject } from './patch-helpers.ts';

const BIN = fileURLToPath(new URL('../../bin/patch-pilot.ts', import.meta.url));

let project: TempProject;

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

function cli(args: string[]): Promise<Run> {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [BIN, ...args],
      {
        cwd: project.dir,
        env: { ...process.env, HOME: project.home, USERPROFILE: project.home, NO_COLOR: '1', FORCE_COLOR: undefined, OLLAMA_API_KEY: '', PATCHPILOT_DEBUG: '' },
        timeout: 60_000,
      },
      (error, stdout, stderr) => {
        const code = error ? (typeof (error as { code?: unknown }).code === 'number' ? (error as { code: number }).code : 1) : 0;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
    child.stdin?.end();
  });
}

const COMMON = ['--provider', 'mock', '--trust', '--offline'];

before(async () => {
  project = await tempProject();
});

after(async () => {
  await project.cleanup();
});

describe('CLI handlers (apply, report, rollback, investigate) and exit codes', () => {
  it('explain what is missing before a scan (exit 2)', async () => {
    const apply = await cli(['apply', ...COMMON]);
    assert.equal(apply.code, 2, apply.stderr);
    assert.match(apply.stderr, /No case file found/);
    assert.match(apply.stderr, /patch-pilot scan/);
    const investigate = await cli(['investigate', ...COMMON]);
    assert.equal(investigate.code, 2);
    assert.match(investigate.stderr, /No case file found/);
    const report = await cli(['report', '--trust']);
    assert.equal(report.code, 2);
    assert.match(report.stderr, /Nothing to report yet/);
    const rollback = await cli(['rollback', '--trust']);
    assert.equal(rollback.code, 2);
    assert.match(rollback.stderr, /No backup to restore/);

    const { caseFile } = await loadFixtures();
    await mkdir(path.join(project.dir, '.patch-pilot'), { recursive: true });
    await writeFile(path.join(project.dir, '.patch-pilot', 'case-file.json'), JSON.stringify(caseFile));
    const noAssessment = await cli(['apply', ...COMMON]);
    assert.equal(noAssessment.code, 2);
    assert.match(noAssessment.stderr, /No assessment found/);
  });

  it('apply --ci: findings at or above --fail-on exit 1, reports written, nothing changed', async () => {
    const { assessment } = await loadFixtures();
    await writeFile(path.join(project.dir, '.patch-pilot', 'assessment.json'), JSON.stringify(assessment));
    const before = await readFile(path.join(project.dir, 'package.json'), 'utf8');
    const high = await cli(['apply', ...COMMON, '--ci', '--fail-on', 'high']);
    assert.equal(high.code, 1, high.stderr);
    assert.match(high.stdout, /Action required/);
    assert.match(high.stdout, /CI mode: nothing was changed/);
    assert.match(high.stderr, /Open findings at or above --fail-on high/);
    assert.equal(await readFile(path.join(project.dir, 'package.json'), 'utf8'), before);
    const report = JSON.parse(await readFile(path.join(project.dir, '.patch-pilot', 'report.json'), 'utf8')) as { findings: unknown[] };
    assert.equal(report.findings.length, 13);
    assert.match(await readFile(path.join(project.dir, '.patch-pilot', 'report.md'), 'utf8'), /## Findings/);

    const never = await cli(['apply', ...COMMON, '--ci', '--fail-on', 'never']);
    assert.equal(never.code, 0, never.stderr);
    const critical = await cli(['apply', ...COMMON, '--ci', '--fail-on', 'critical']);
    assert.equal(critical.code, 0, 'no Critical verdict in the fixture');
  });

  it('apply --ci --json prints one JSON document with the exit code', async () => {
    const run = await cli(['apply', ...COMMON, '--ci', '--json', '--fail-on', 'medium']);
    assert.equal(run.code, 1, run.stderr);
    const doc = JSON.parse(run.stdout) as { exitCode: number; failOn: string; actions: unknown[]; results: unknown[]; verdicts: unknown[] };
    assert.equal(doc.exitCode, 1);
    assert.equal(doc.failOn, 'medium');
    assert.equal(doc.verdicts.length, 13);
    assert.equal(doc.results.length, 0);
  });

  it('apply without a TTY and without flags changes nothing and exits 0', async () => {
    const before = await readFile(path.join(project.dir, 'package-lock.json'), 'utf8');
    const run = await cli(['apply', ...COMMON]);
    assert.equal(run.code, 0, run.stderr);
    assert.match(run.stdout, /No interactive terminal: nothing is applied/);
    assert.equal(await readFile(path.join(project.dir, 'package-lock.json'), 'utf8'), before);
  });

  it('report re-renders both files', async () => {
    const run = await cli(['report', '--trust']);
    assert.equal(run.code, 0, run.stderr);
    assert.match(run.stdout, /Wrote the reports\s+\.patch-pilot\/report\.md - \.patch-pilot\/report\.json/);
    const json = await cli(['report', '--trust', '--json']);
    assert.equal(json.code, 0);
    assert.match(JSON.parse(json.stdout).md, /report\.md$/);
  });
});
