import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { buildReportJson, renderReportMarkdown, sessionRecords, writeReports } from '../../src/remediation/report.ts';
import type { AuditEvent, AuditRecord, Config } from '../../src/types.ts';
import { captureUi, IDENTITY, loadFixtures, projectConfig } from './patch-helpers.ts';

let dir: string;
let config: Config;

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'pp-report-'));
  config = await projectConfig(dir, dir);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const EM_DASH = String.fromCharCode(0x2014);

function rec(run: string, ts: string, event: AuditEvent): AuditRecord {
  return { ...event, ts, run } as AuditRecord;
}

function sessionAudit(): AuditRecord[] {
  return [
    rec('old', '2026-09-20T10:00:00Z', { event: 'casefile.saved', path: '.patch-pilot/case-file.json', sha256: 'old', packages: 1, vulnerabilities: 1 }),
    rec('old', '2026-09-20T10:01:00Z', { event: 'approval', actionId: 'bump:old@1.0.0', package: 'old', kind: 'bump', decision: 'approve', mode: 'flag', scope: 'bump', by: IDENTITY }),
    rec('scan', '2026-09-24T10:00:00Z', { event: 'scan.start', command: 'scan', dir, version: '0.1.0', provider: 'ollama', model: 'mistral:7b', options: {} }),
    rec('scan', '2026-09-24T10:00:05Z', { event: 'casefile.saved', path: '.patch-pilot/case-file.json', sha256: 'new', packages: 6, vulnerabilities: 13 }),
    rec('scan', '2026-09-24T10:05:00Z', { event: 'migration.search', package: 'marked', backend: 'docs', query: 'marked 4 migration breaking changes default export require', urls: ['https://github.com/markedjs/marked/releases/tag/v4.0.0'], cached: false }),
    rec('scan', '2026-09-24T10:05:01Z', { event: 'migration.brief', package: 'marked', from: '0.3.6', to: '4.0.10', items: 2, verified: 2, sources: ['https://github.com/markedjs/marked/releases/tag/v4.0.0'], offline: false }),
    rec('scan', '2026-09-24T10:06:00Z', { event: 'approval', actionId: 'bump:lodash@4.18.1', package: 'lodash', kind: 'bump', decision: 'approve', mode: 'interactive', scope: 'bump', by: IDENTITY }),
    rec('scan', '2026-09-24T10:06:01Z', { event: 'patch.backup', backupId: '20260924T100601Z-abc123', dir: '.patch-pilot/backup/20260924T100601Z-abc123', files: [{ path: 'package.json', sha256: 'a'.repeat(64) }] }),
    rec('scan', '2026-09-24T10:06:03Z', { event: 'lockfile.diff', actionId: 'bump:lodash@4.18.1', added: 0, removed: 0, changed: 1, unexpected: [], decision: 'clean' }),
    rec('scan', '2026-09-24T10:06:03Z', { event: 'verify.result', vulnId: 'GHSA-35jh-r3h4-6jhm', package: 'lodash', cleared: true, versions: ['4.18.1'] }),
    rec('scan', '2026-09-24T10:06:03Z', {
      event: 'patch.apply',
      actionId: 'bump:lodash@4.18.1',
      package: 'lodash',
      kind: 'bump',
      before: '4.17.20',
      after: '4.18.1',
      command: ['npm', 'install', 'lodash@4.18.1', '--package-lock-only', '--ignore-scripts', '--save-exact'],
      files: [{ path: 'package-lock.json', beforeHash: 'b'.repeat(64), afterHash: 'c'.repeat(64) }],
      ok: true,
    }),
    rec('scan', '2026-09-24T10:06:10Z', { event: 'approval', actionId: 'bump-major:marked@4.0.10', package: 'marked', kind: 'bump-major', decision: 'reject', mode: 'interactive', scope: 'transaction', files: [{ file: 'src/render.js', approved: false }], by: IDENTITY }),
    rec('scan', '2026-09-24T10:06:20Z', { event: 'risk.accepted', vulnId: 'GHSA-c2qf-rxjj-qqgw', package: 'semver', reason: 'dev only', until: '2027-01-01', by: IDENTITY, source: 'gate' }),
    rec('scan', '2026-09-24T10:07:00Z', { event: 'approval', actionId: 'post:npm-install', package: '*', kind: 'bump', decision: 'approve', mode: 'interactive', scope: 'bump', by: IDENTITY, reason: 'npm install --ignore-scripts' }),
    rec('scan', '2026-09-24T10:07:30Z', { event: 'patch.apply', actionId: 'post:npm-install', package: '*', kind: 'bump', before: '', after: null, command: ['npm', 'install', '--ignore-scripts'], files: [], ok: true }),
    rec('rb', '2026-09-24T11:00:00Z', { event: 'rollback', backupId: '20260924T100601Z-abc123', restored: ['package.json', 'package-lock.json'], mismatched: [], reason: 'patch-pilot rollback' }),
  ];
}

describe('report model', () => {
  it('covers the records since the run that saved the latest case file', () => {
    const records = sessionRecords(sessionAudit());
    assert.equal(records[0]?.event, 'scan.start', 'starts at the first record of the scan run');
    assert.ok(!records.some((r) => r.run === 'old'));
    assert.equal(records.at(-1)?.event, 'rollback', 'later runs (rollback) are included');
  });

  it('report.json has data source, models, prompt version, cache hits, verdicts, approvals, files, verification', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const ignore = [{ id: 'GHSA-c2qf-rxjj-qqgw', package: 'semver', reason: 'dev only', by: 'Test User <test@example.com>', createdAt: '2026-09-24T10:06:20Z', until: '2027-01-01' }];
    const json = buildReportJson({ config: { ...config, ignore }, caseFile, assessment, audit: sessionAudit() }) as Record<string, any>;
    assert.equal(json.schema, 'patch-pilot.report');
    assert.equal(json.vulnSource.mode, 'live');
    assert.match(json.vulnSource.label, /OSV\.dev \(live/);
    assert.equal(json.investigation.model, 'mistral:7b');
    assert.equal(json.investigation.promptVersion, assessment.promptVersion);
    assert.equal(json.investigation.cached, 1);
    assert.equal(json.investigation.forced, 1);
    assert.equal(json.findings.length, 13);
    assert.equal(json.findings[0].package, 'minimist');
    assert.equal(json.findings[0].cve, 'CVE-2021-44906');
    assert.ok(json.findings[0].evidence.length > 0);
    assert.equal(json.findings.find((f: any) => f.package === 'semver').accepted.reason, 'dev only');
    assert.deepEqual(json.approvals.map((a: any) => [a.actionId, a.decision]), [
      ['bump:lodash@4.18.1', 'approve'],
      ['bump-major:marked@4.0.10', 'reject'],
    ]);
    assert.deepEqual(json.approvals[0].by, IDENTITY);
    assert.deepEqual(json.filesChanged, [{ path: 'package-lock.json', actionId: 'bump:lodash@4.18.1', beforeHash: 'b'.repeat(64), afterHash: 'c'.repeat(64), at: '2026-09-24T10:06:03Z' }]);
    assert.deepEqual(json.verification.map((v: any) => [v.vulnId, v.cleared]), [['GHSA-35jh-r3h4-6jhm', true]]);
    assert.equal(json.migrations[0].package, 'marked');
    assert.equal(json.migrations[0].queries[0].query, 'marked 4 migration breaking changes default export require');
    assert.deepEqual(json.postCommands.map((p: any) => [p.command, p.ok]), [['npm install --ignore-scripts', true]]);
    assert.equal(json.rollbacks.length, 1);
    assert.equal(json.summary.cleared, 1);
    assert.equal(json.summary.accepted, 1);
    assert.equal(json.acceptedRisks[0].expired, false);
  });

  it('report.md renders every section, escapes table cells and contains no em dash', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const tricky = { ...assessment, verdicts: assessment.verdicts.map((v, i) => (i === 0 ? { ...v, reasoning: `Reachable ${EM_DASH} user input | flows in` } : v)) };
    const md = renderReportMarkdown({ config, caseFile, assessment: tricky, audit: sessionAudit() });
    for (const heading of ['# PatchPilot report: vulnerable-app', '## Findings', '## Verdicts', '## Accepted risks', '## Approvals', '## Migration briefs', '## Patches', '## Lockfile diff guard', '## Files changed', '## Verification', '## Rollbacks', '## Post-apply commands']) {
      assert.ok(md.includes(heading), heading);
    }
    assert.match(md, /Vulnerability data: OSV\.dev \(live/);
    assert.match(md, /prompt version `b1-/);
    assert.match(md, /Verdict cache: 1 of 13 verdicts served from cache/);
    assert.match(md, /\| bump:lodash@4\.18\.1 \| approve \| interactive \| bump \| Test User <test@example\.com> \(os user tester\) \| 2026-09-24T10:06:00Z \|/);
    assert.match(md, /\| package-lock\.json \| bump:lodash@4\.18\.1 \| bbbbbbbbbbbb \| cccccccccccc \|/);
    assert.match(md, /Reasoning: Reachable, user input \\\| flows in/);
    assert.ok(!md.includes(EM_DASH));
    assert.match(md, /node_modules is never restored by a rollback/);
  });
});

describe('writeReports', () => {
  it('writes report.md and report.json from the saved state and logs report.written', async () => {
    const { caseFile, assessment } = await loadFixtures();
    await mkdir(config.paths.stateDir, { recursive: true });
    await writeFile(config.paths.caseFile, JSON.stringify(caseFile));
    await writeFile(config.paths.assessmentFile, JSON.stringify(assessment));
    const audit = new MemoryAudit();
    const { ui } = captureUi();
    const written = await writeReports(config, { ui, audit });
    assert.equal(written.md, config.paths.reportMd);
    assert.equal(written.json, config.paths.reportJson);
    const md = await readFile(written.md, 'utf8');
    const json = JSON.parse(await readFile(written.json, 'utf8')) as { findings: unknown[]; generatedAt: string };
    assert.match(md, /## Findings/);
    assert.equal(json.findings.length, 13);
    assert.ok(md.includes(json.generatedAt), 'both files come from one model');
    assert.deepEqual(audit.events('report.written').map((e) => [e.md, e.json]), [['.patch-pilot/report.md', '.patch-pilot/report.json']]);
  });

  it('says there is nothing to report before a scan', async () => {
    const { ui } = captureUi();
    await assert.rejects(writeReports(config, { ui, audit: new MemoryAudit() }), /Nothing to report yet/);
  });
});
