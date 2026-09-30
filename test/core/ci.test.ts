import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { describe, it } from 'node:test';
import { exitCodeFor, JSON_SUMMARY_VERSION, mergeExitCodes, printJson, riskAtLeast, summarizeForJson } from '../../src/ci.ts';
import { FAIL_ON_VALUES, RISK_ORDER } from '../../src/config.ts';
import type { Action, ApplyResult, ApprovalRecord, Assessment, FailOn, IgnoreEntry, Phase3Result, RiskLevel, Verdict } from '../../src/types.ts';
import { EXIT } from '../../src/util/errors.ts';
import { VERSION } from '../../src/version.ts';
import { caseFileOf, lodashFixture, minimistFixture, semverFixture } from '../investigation/helpers.ts';

const lodash = lodashFixture();
const minimist = minimistFixture();
const semver = semverFixture();
const caseFile = caseFileOf([minimist.pkg, lodash.pkg, semver.pkg], [minimist.vuln, lodash.template, lodash.merge, semver.vuln], '/tmp/vulnerable-app');

function verdict(vulnId: string, pkg: string, installedVersion: string, risk: RiskLevel, extra: Partial<Verdict['investigation']> = {}): Verdict {
  return {
    vulnId,
    package: pkg,
    installedVersion,
    risk,
    reachable: risk === 'Noise' ? 'no' : 'yes',
    confidence: 0.75,
    reasoning: `${pkg} ${risk}`,
    evidence: [`${pkg} evidence`],
    recommendation: { action: 'upgrade', targetVersion: '9.9.9', majorBump: false },
    investigation: { provider: 'ollama', model: 'mistral:7b', promptVersion: 'p', steps: 2, toolCalls: [], durationMs: 10, forced: false, ...extra },
  };
}

function assessment(verdicts: Verdict[]): Assessment {
  return {
    version: 1,
    caseFileHash: 'h',
    createdAt: '2026-09-24T10:00:00.000Z',
    updatedAt: '2026-09-24T10:05:00.000Z',
    provider: 'ollama',
    model: 'mistral:7b',
    promptVersion: 'p',
    complete: true,
    dossiers: [],
    verdicts,
  };
}

const V = {
  minimist: verdict(minimist.vuln.id, 'minimist', '1.2.5', 'High'),
  template: verdict(lodash.template.id, 'lodash', '4.17.20', 'Noise', { cached: true }),
  merge: verdict(lodash.merge.id, 'lodash', '4.17.20', 'Medium', { adjusted: true, originalRisk: 'Low' }),
  semver: verdict(semver.vuln.id, 'semver', '5.7.1', 'Low', { forced: true }),
};

describe('riskAtLeast', () => {
  it('compares risk levels and --fail-on values for every combination', () => {
    const levelOf: Record<Exclude<FailOn, 'never'>, RiskLevel> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', noise: 'Noise' };
    for (const risk of RISK_ORDER) {
      for (const failOn of FAIL_ON_VALUES) {
        const expected = failOn === 'never' ? false : RISK_ORDER.indexOf(risk) >= RISK_ORDER.indexOf(levelOf[failOn]);
        assert.equal(riskAtLeast(risk, failOn), expected, `${risk} vs ${failOn}`);
        if (failOn !== 'never') assert.equal(riskAtLeast(risk, levelOf[failOn]), expected, `${risk} vs ${levelOf[failOn]}`);
      }
    }
    assert.equal(riskAtLeast('High', 'HIGH' as FailOn), true, 'case-insensitive');
    assert.throws(() => riskAtLeast('High', 'severe' as FailOn), /Unknown --fail-on/);
  });
});

describe('exitCodeFor', () => {
  const all = assessment([V.minimist, V.template, V.merge, V.semver]);

  it('gives 1 at or above every threshold and 0 below it; never gives 0', () => {
    const expected: Record<FailOn, 0 | 1> = { critical: 0, high: 1, medium: 1, low: 1, noise: 1, never: 0 };
    for (const failOn of FAIL_ON_VALUES) assert.equal(exitCodeFor(all, failOn), expected[failOn], failOn);
    const onlyNoise = assessment([V.template]);
    const noiseExpected: Record<FailOn, 0 | 1> = { critical: 0, high: 0, medium: 0, low: 0, noise: 1, never: 0 };
    for (const failOn of FAIL_ON_VALUES) assert.equal(exitCodeFor(onlyNoise, failOn), noiseExpected[failOn], `noise only, ${failOn}`);
    assert.equal(exitCodeFor(assessment([]), 'noise'), 0);
    assert.equal(exitCodeFor(null, 'noise'), 0);
    assert.equal(exitCodeFor(assessment([verdict('GHSA-c', 'x', '1.0.0', 'Critical')]), 'critical'), 1);
  });

  it('skips active accepted risks, by OSV id, by CVE alias and per package', () => {
    const accept = (id: string, extra: Partial<IgnoreEntry> = {}): IgnoreEntry => ({ id, reason: 'argv comes from our own scripts', by: 'me', createdAt: '2026-09-01', ...extra });
    const high = assessment([V.minimist]);
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept(minimist.vuln.id)] }), 0, 'by OSV id');
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept('CVE-2021-44906')], caseFile }), 0, 'by CVE alias (needs the case file)');
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept('CVE-2021-44906')] }), 1, 'no case file, no aliases');
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept(minimist.vuln.id, { package: 'minimist' })] }), 0, 'same package');
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept(minimist.vuln.id, { package: 'yargs' })] }), 1, 'another package');
    const now = new Date('2026-10-01T00:00:00Z');
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept(minimist.vuln.id, { until: '2026-09-30' })], now }), 1, 'expired');
    assert.equal(exitCodeFor(high, 'high', { ignore: [accept(minimist.vuln.id, { until: '2026-10-31' })], now }), 0, 'not expired yet');
  });

  it('skips vulnerabilities cleared by an applied fix, not by a rolled back one', () => {
    const high = assessment([V.minimist]);
    const cleared = phase3([applyResult({ ok: true, rolledBack: false })]);
    assert.equal(exitCodeFor(high, 'high', { phase3: cleared }), 0);
    assert.equal(exitCodeFor(high, 'high', { phase3: phase3([applyResult({ ok: false, rolledBack: true })]) }), 1);
    assert.equal(exitCodeFor(high, 'high', { phase3: phase3([applyResult({ ok: true, rolledBack: false, cleared: false })]) }), 1);
  });
});

describe('mergeExitCodes', () => {
  it('keeps the most serious exit code', () => {
    assert.equal(mergeExitCodes(), EXIT.OK);
    assert.equal(mergeExitCodes(EXIT.OK, EXIT.FINDINGS), EXIT.FINDINGS);
    assert.equal(mergeExitCodes(EXIT.FINDINGS, EXIT.PATCH_FAILED), EXIT.PATCH_FAILED);
    assert.equal(mergeExitCodes(EXIT.PATCH_FAILED, EXIT.FINDINGS), EXIT.PATCH_FAILED);
    assert.equal(mergeExitCodes(EXIT.FINDINGS, undefined, null), EXIT.FINDINGS);
    assert.equal(mergeExitCodes(EXIT.ENVIRONMENT, EXIT.USAGE), EXIT.ENVIRONMENT);
    assert.equal(mergeExitCodes(EXIT.INTERRUPTED, EXIT.INTERNAL), EXIT.INTERNAL);
  });
});

function action(): Action {
  return {
    id: 'bump:minimist@1.2.6',
    kind: 'bump',
    package: 'minimist',
    fromVersion: '1.2.5',
    toVersion: '1.2.6',
    vulnIds: [minimist.vuln.id],
    worstRisk: 'High',
    majorBump: false,
    direct: { depType: 'dependencies', spec: '^1.2.5', specStyle: 'caret' },
    parents: [],
    importedInSource: true,
    requiresMigration: false,
    engines: null,
    notes: ['version bump only'],
  };
}

function applyResult(options: { ok: boolean; rolledBack: boolean; cleared?: boolean }): ApplyResult {
  return {
    actionId: 'bump:minimist@1.2.6',
    ok: options.ok,
    ...(options.ok ? {} : { error: 'npm failed' }),
    before: '1.2.5',
    after: options.ok ? '1.2.6' : null,
    command: ['npm', 'install', 'minimist@1.2.6', '--package-lock-only', '--ignore-scripts'],
    filesChanged: [{ path: 'package-lock.json', beforeHash: 'a', afterHash: 'b' }],
    lockfileDiff: {
      changes: [{ key: 'node_modules/minimist', change: 'changed', from: '1.2.5', to: '1.2.6' }],
      allowed: [{ key: 'node_modules/minimist', change: 'changed', from: '1.2.5', to: '1.2.6' }],
      unexpected: [],
    },
    verify: [{ vulnId: minimist.vuln.id, package: 'minimist', cleared: options.cleared ?? true, nodes: [{ key: 'node_modules/minimist', version: '1.2.6', affected: false }] }],
    rolledBack: options.rolledBack,
  };
}

function phase3(results: ApplyResult[], exitCode: Phase3Result['exitCode'] = EXIT.OK): Phase3Result {
  const approval: ApprovalRecord = {
    actionId: 'bump:minimist@1.2.6',
    package: 'minimist',
    decision: 'approve',
    mode: 'interactive',
    scope: 'bump',
    by: { osUser: 'abdullah', gitName: 'Abdullah', gitEmail: null },
    at: '2026-09-24T10:06:00.000Z',
  };
  return { exitCode, actions: [action()], approvals: [approval], results, reports: { md: '/tmp/r.md', json: '/tmp/r.json' } };
}

describe('summarizeForJson', () => {
  const TOP_LEVEL = ['version', 'tool', 'generatedAt', 'project', 'vulnSource', 'investigation', 'failOn', 'counts', 'verdicts', 'actions', 'approvals', 'results', 'reports', 'exitCode'];
  const VERDICT_FIELDS = [
    'vulnId', 'aliases', 'url', 'package', 'installedVersion', 'summary', 'severity', 'cvssScore', 'risk', 'reachable', 'confidence', 'reasoning',
    'evidence', 'recommendation', 'isDirect', 'isDevOnly', 'malware', 'status', 'failing', 'acceptedRisk', 'cached', 'forced', 'adjusted',
    'originalRisk', 'provider', 'model', 'steps', 'durationMs',
  ];
  const now = new Date('2026-09-24T12:00:00.000Z');

  it('has the documented shape without Phase 3', () => {
    const summary = summarizeForJson(caseFile, assessment([V.template, V.semver, V.minimist]), null, { failOn: 'high', now });
    assert.deepEqual(Object.keys(summary), TOP_LEVEL);
    assert.equal(summary.version, JSON_SUMMARY_VERSION);
    assert.deepEqual(summary.tool, { name: 'patch-pilot', version: VERSION });
    assert.equal(summary.generatedAt, now.toISOString());
    assert.deepEqual(summary.project, { name: 'vulnerable-app', root: '/tmp/vulnerable-app', lockfile: 'package-lock.json', lockfileVersion: 3 });
    assert.deepEqual(summary.vulnSource, caseFile.vulnSource);
    assert.deepEqual(summary.investigation, { provider: 'ollama', model: 'mistral:7b', promptVersion: 'p', complete: true, createdAt: '2026-09-24T10:00:00.000Z', updatedAt: '2026-09-24T10:05:00.000Z' });
    assert.equal(summary.failOn, 'high');
    assert.deepEqual(summary.actions, []);
    assert.deepEqual(summary.approvals, []);
    assert.deepEqual(summary.results, []);
    assert.equal(summary.reports, null);
    assert.equal(summary.exitCode, EXIT.FINDINGS);
    assert.deepEqual(summary.verdicts.map((v) => [v.package, v.risk]), [['minimist', 'High'], ['semver', 'Low'], ['lodash', 'Noise']], 'highest risk first');
    for (const v of summary.verdicts) assert.deepEqual(Object.keys(v), VERDICT_FIELDS);
    const [top] = summary.verdicts;
    assert.ok(top);
    assert.deepEqual(top.aliases, ['CVE-2021-44906']);
    assert.equal(top.url, `https://osv.dev/vulnerability/${minimist.vuln.id}`);
    assert.equal(top.severity, 'CRITICAL');
    assert.equal(top.cvssScore, 9.8);
    assert.equal(top.summary, 'Prototype Pollution in minimist');
    assert.deepEqual(top.recommendation, { action: 'upgrade', targetVersion: '9.9.9', majorBump: false, notes: null });
    assert.equal(top.status, 'open');
    assert.equal(top.failing, true);
    assert.equal(top.acceptedRisk, null);
    assert.equal(top.isDirect, true);
    assert.equal(summary.verdicts[1]?.forced, true);
    assert.equal(summary.verdicts[2]?.cached, true);
    assert.equal(summary.verdicts[2]?.failing, false);
    assert.deepEqual(summary.counts, {
      dependencies: 12,
      direct: 6,
      dev: 1,
      vulnerablePackages: 3,
      vulnerabilities: 4,
      bySeverity: { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 0, UNKNOWN: 0 },
      investigated: 3,
      notInvestigated: 1,
      byRisk: { Critical: 0, High: 1, Medium: 0, Low: 1, Noise: 1 },
      failing: 1,
      accepted: 0,
      fixed: 0,
      cached: 1,
      forced: 1,
      adjusted: 0,
    });
    assert.deepEqual(JSON.parse(JSON.stringify(summary)), summary, 'plain JSON, no undefined values');
  });

  it('reports accepted risks, applied fixes, actions, approvals and results', () => {
    const accepted: IgnoreEntry = { id: 'CVE-2021-23337', reason: 'templates are ours', by: 'Abdullah <a@example.com>', createdAt: '2026-09-01T00:00:00.000Z', until: '2027-01-31' };
    const risky = verdict(lodash.template.id, 'lodash', '4.17.20', 'High');
    const summary = summarizeForJson(caseFile, assessment([V.minimist, risky, V.merge]), phase3([applyResult({ ok: true, rolledBack: false })]), {
      failOn: 'medium',
      ignore: [accepted],
      now,
    });
    const byId = new Map(summary.verdicts.map((v) => [v.vulnId, v]));
    assert.equal(byId.get(minimist.vuln.id)?.status, 'fixed');
    assert.equal(byId.get(minimist.vuln.id)?.failing, false);
    assert.equal(byId.get(lodash.template.id)?.status, 'accepted');
    assert.deepEqual(byId.get(lodash.template.id)?.acceptedRisk, { reason: 'templates are ours', by: 'Abdullah <a@example.com>', createdAt: '2026-09-01T00:00:00.000Z', until: '2027-01-31', expired: false });
    assert.equal(byId.get(lodash.merge.id)?.status, 'open');
    assert.equal(byId.get(lodash.merge.id)?.failing, true, 'Medium fails --fail-on medium');
    assert.equal(byId.get(lodash.merge.id)?.adjusted, true);
    assert.equal(byId.get(lodash.merge.id)?.originalRisk, 'Low');
    assert.equal(summary.counts.fixed, 1);
    assert.equal(summary.counts.accepted, 1);
    assert.equal(summary.counts.failing, 1);
    assert.equal(summary.exitCode, EXIT.FINDINGS);
    assert.deepEqual(summary.actions, [
      {
        id: 'bump:minimist@1.2.6',
        kind: 'bump',
        package: 'minimist',
        fromVersion: '1.2.5',
        toVersion: '1.2.6',
        vulnIds: [minimist.vuln.id],
        worstRisk: 'High',
        majorBump: false,
        direct: true,
        importedInSource: true,
        requiresMigration: false,
        codeChanges: 0,
        notes: ['version bump only'],
      },
    ]);
    assert.deepEqual(summary.approvals, [
      {
        actionId: 'bump:minimist@1.2.6',
        package: 'minimist',
        decision: 'approve',
        mode: 'interactive',
        scope: 'bump',
        by: { osUser: 'abdullah', gitName: 'Abdullah', gitEmail: null },
        at: '2026-09-24T10:06:00.000Z',
        reason: null,
        until: null,
        files: [],
      },
    ]);
    assert.deepEqual(summary.results, [
      {
        actionId: 'bump:minimist@1.2.6',
        ok: true,
        error: null,
        before: '1.2.5',
        after: '1.2.6',
        command: ['npm', 'install', 'minimist@1.2.6', '--package-lock-only', '--ignore-scripts'],
        rolledBack: false,
        filesChanged: [{ path: 'package-lock.json', beforeHash: 'a', afterHash: 'b' }],
        lockfile: { added: 0, removed: 0, changed: 1, unexpected: [] },
        verify: [{ vulnId: minimist.vuln.id, package: 'minimist', cleared: true, versions: ['1.2.6'] }],
      },
    ]);
    assert.deepEqual(summary.reports, { md: '/tmp/r.md', json: '/tmp/r.json' });
    assert.deepEqual(JSON.parse(JSON.stringify(summary)), summary);
  });

  it('takes the exit code from Phase 3 failures and from the caller', () => {
    const clean = assessment([V.template]);
    assert.equal(summarizeForJson(caseFile, clean, null, { now }).exitCode, EXIT.OK);
    assert.equal(summarizeForJson(caseFile, clean, phase3([applyResult({ ok: false, rolledBack: true })], EXIT.PATCH_FAILED), { now }).exitCode, EXIT.PATCH_FAILED);
    assert.equal(summarizeForJson(caseFile, assessment([V.minimist]), phase3([], EXIT.PATCH_FAILED), { now }).exitCode, EXIT.PATCH_FAILED, 'patch failure beats findings');
    assert.equal(summarizeForJson(caseFile, clean, phase3([], EXIT.FINDINGS), { now }).exitCode, EXIT.OK, 'the findings code is recomputed here');
    assert.equal(summarizeForJson(caseFile, clean, null, { now, exitCode: EXIT.ENVIRONMENT }).exitCode, EXIT.ENVIRONMENT);
    assert.equal(summarizeForJson(caseFile, assessment([V.minimist]), null, { failOn: 'never', now }).exitCode, EXIT.OK);
    const none = summarizeForJson(caseFile, null, null, { now });
    assert.equal(none.investigation, null);
    assert.deepEqual(none.verdicts, []);
    assert.equal(none.counts.notInvestigated, 4);
  });
});

describe('printJson', () => {
  function sink(onWrite?: (chunk: string) => Error | null): { stream: Writable; text: () => string } {
    let text = '';
    const stream = new Writable({
      write(chunk, _enc, cb) {
        const err = onWrite?.(String(chunk)) ?? null;
        if (!err) text += String(chunk);
        cb(err);
      },
    });
    return { stream, text: () => text };
  }

  it('writes pretty JSON and a newline', async () => {
    const out = sink();
    await printJson(out.stream, { a: 1, b: ['x'] });
    assert.equal(out.text(), '{\n  "a": 1,\n  "b": [\n    "x"\n  ]\n}\n');
  });

  it('treats a closed pipe as done and other errors as errors', async () => {
    const epipe = sink(() => Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }));
    await printJson(epipe.stream, { a: 1 });
    const broken = sink(() => Object.assign(new Error('disk full'), { code: 'ENOSPC' }));
    await assert.rejects(printJson(broken.stream, { a: 1 }), /disk full/);
  });
});
