import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { LlmError } from '../../src/llm/errors.ts';
import { MockProvider, type MockScript } from '../../src/llm/mock.ts';
import { runPhase2 } from '../../src/investigation/agent.ts';
import { caseFileHash, loadAssessment } from '../../src/investigation/assessment.ts';
import { PROMPT_VERSION } from '../../src/investigation/prompts.ts';
import type { CaseFile, Config } from '../../src/types.ts';
import { captureUi, caseFileOf, fakeRegistry, lodashFixture, markedThreeFixture, minimistFixture, tempDir, testConfig, usageResult } from './helpers.ts';

const lodash = lodashFixture();
const minimist = minimistFixture();

function caseFile(root: string): CaseFile {
  return caseFileOf([lodash.pkg, minimist.pkg], [lodash.template, minimist.vuln], root);
}

function setup(script: MockScript) {
  const provider = new MockProvider(script);
  const { ui, out, err } = captureUi();
  const audit = new MemoryAudit();
  const { registry, calls } = fakeRegistry({
    get_usage: (a) => usageResult(String(a.package), typeof a.symbol === 'string' ? a.symbol : null, 0, [{ path: 'src/cli.js', line: 21, member: null }]),
    read_file: () => ({ ok: true, hint: 'src/cli.js:11-40 of 49 lines', text: 'code' }),
    check_deps: () => ({ ok: true, hint: 'direct production dependency', data: {} }),
  });
  return { provider, ui, out, err, audit, registry, calls };
}

describe('runPhase2', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  let config: Config;
  beforeEach(async () => {
    tmp = await tempDir();
    config = await testConfig(tmp.dir, { maxSteps: 3 });
  });
  afterEach(async () => {
    await tmp.cleanup();
  });

  it('investigates worst first, saves the assessment, logs investigate.start and prints the footer (verdict cache stub: a miss)', async () => {
    const s = setup({ rules: [] });
    const cf = caseFile(tmp.dir);
    const assessment = await runPhase2(cf, config, { provider: s.provider, ui: s.ui, audit: s.audit, registry: s.registry, graph: null });
    assert.equal(assessment.complete, true);
    assert.equal(assessment.caseFileHash, caseFileHash(cf));
    assert.deepEqual(assessment.verdicts.map((v) => v.vulnId), ['GHSA-xvch-5gv4-984h', 'GHSA-35jh-r3h4-6jhm'], 'minimist (CRITICAL) before lodash (HIGH)');
    assert.deepEqual(assessment.dossiers.map((d) => d.package), ['minimist', 'lodash']);
    assert.deepEqual(await loadAssessment(config.paths.assessmentFile), assessment);
    assert.deepEqual(s.audit.events('investigate.start').map(({ ts: _ts, run: _run, ...e }) => e), [
      { event: 'investigate.start', packages: 2, vulnerabilities: 2, provider: 'mock', model: 'mock', promptVersion: PROMPT_VERSION, resume: false },
    ]);
    assert.deepEqual(s.audit.events('verdict.cached'), []);
    assert.equal(s.audit.events('verdict').length, 2);
    assert.doesNotMatch(s.err(), /Verdict cache/);
    const text = s.out();
    assert.match(text, /Investigating vulnerabilities\.\.\./);
    assert.match(text, /\* Investigating minimist@1\.2\.5 \(1 of 2\)\.\.\./);
    assert.match(text, /\* Investigating lodash@4\.17\.20 \(2 of 2\)\.\.\./);
    assert.match(text, /mock - 16k ctx - 2 packages - 2 CVEs - \d+ms\n$/);
    assert.deepEqual(
      [...new Set(s.provider.calls.map((c) => c.purpose))],
      ['recon', 'dossier', 'verdict-loop', 'verdict'],
    );
  });

  it('every card of a multi-cve package recommends the version the package action applies', async () => {
    const s = setup({ rules: [] });
    const marked = markedThreeFixture();
    const cf = caseFileOf([marked.pkg], marked.vulns, tmp.dir);
    const assessment = await runPhase2(cf, config, { provider: s.provider, ui: s.ui, audit: s.audit, registry: s.registry, graph: null });
    assert.deepEqual(assessment.verdicts.map((v) => v.recommendation.targetVersion), ['4.0.10', '4.0.10', '4.0.10']);
    const text = s.out();
    assert.doesNotMatch(text, /Recommended: upgrade to 2\.0\.0/);
    assert.match(text, /Recommended: upgrade to 4\.0\.10 \(major\); this CVE alone is fixed in 2\.0\.0/);
    assert.equal(text.match(/Recommended: upgrade to 4\.0\.10 \(major\)\n/g)?.length, 2);
  });

  it('saves after every verdict, and --resume skips the finished CVEs and reuses the dossier', async () => {
    const cf = caseFile(tmp.dir);
    const first = setup({ rules: [{ match: { purpose: 'verdict', anyMessageIncludes: 'GHSA-35jh-r3h4-6jhm' }, replies: [{ error: { message: 'connection refused', kind: 'unreachable' } }] }] });
    await assert.rejects(
      runPhase2(cf, config, { provider: first.provider, ui: first.ui, audit: first.audit, registry: first.registry, graph: null }),
      (e: unknown) => e instanceof LlmError && e.kind === 'unreachable',
    );
    const saved = await loadAssessment(config.paths.assessmentFile);
    assert.equal(saved?.complete, false);
    assert.deepEqual(saved?.verdicts.map((v) => v.vulnId), ['GHSA-xvch-5gv4-984h']);
    assert.deepEqual(saved?.dossiers.map((d) => d.package), ['minimist', 'lodash']);

    const resumed = setup({ rules: [] });
    const resumeConfig = await testConfig(tmp.dir, { maxSteps: 3, resume: true });
    const assessment = await runPhase2(cf, resumeConfig, { provider: resumed.provider, ui: resumed.ui, audit: resumed.audit, registry: resumed.registry, graph: null });
    assert.equal(assessment.complete, true);
    assert.deepEqual(assessment.verdicts.map((v) => v.vulnId), ['GHSA-xvch-5gv4-984h', 'GHSA-35jh-r3h4-6jhm']);
    assert.equal(resumed.provider.calls.filter((c) => c.purpose === 'recon' || c.purpose === 'dossier').length, 0, 'the saved dossier is reused');
    assert.ok(resumed.provider.calls.every((c) => !c.messages.some((m) => m.content.includes('GHSA-xvch-5gv4-984h'))), 'minimist is not investigated again');
    assert.match(resumed.out(), /Resuming: 1 of 2 CVEs already investigated/);
    assert.equal(resumed.audit.events('investigate.start')[0]?.resume, true);
  });

  it('starts over when the saved assessment belongs to another case file', async () => {
    const s = setup({ rules: [] });
    await runPhase2(caseFile(tmp.dir), config, { provider: s.provider, ui: s.ui, audit: s.audit, registry: s.registry, graph: null });
    const changed = caseFileOf([minimist.pkg], [minimist.vuln], tmp.dir);
    const again = setup({ rules: [] });
    const resumeConfig = await testConfig(tmp.dir, { resume: true });
    const assessment = await runPhase2(changed, resumeConfig, { provider: again.provider, ui: again.ui, audit: again.audit, registry: again.registry, graph: null });
    assert.match(again.err(), /different case file; starting over/);
    assert.deepEqual(assessment.verdicts.map((v) => v.vulnId), ['GHSA-xvch-5gv4-984h']);
  });

  it('honours --only and --max-cves and handles an empty selection', async () => {
    const s = setup({ rules: [] });
    const only = await testConfig(tmp.dir, { only: 'CVE-2021-23337' });
    const a = await runPhase2(caseFile(tmp.dir), only, { provider: s.provider, ui: s.ui, audit: s.audit, registry: s.registry, graph: null });
    assert.deepEqual(a.verdicts.map((v) => v.vulnId), ['GHSA-35jh-r3h4-6jhm']);
    const none = setup({ rules: [] });
    const empty = await runPhase2(caseFile(tmp.dir), await testConfig(tmp.dir, { only: 'left-pad' }), { provider: none.provider, ui: none.ui, audit: none.audit, registry: none.registry, graph: null });
    assert.deepEqual(empty.verdicts, []);
    assert.equal(empty.complete, true);
    assert.match(none.out(), /No vulnerable packages to investigate/);
    assert.equal(none.provider.calls.length, 0);
  });

  it('loads no graph when the lockfile cannot be parsed and still runs', async () => {
    const s = setup({ rules: [] });
    const a = await runPhase2(caseFileOf([minimist.pkg], [minimist.vuln], tmp.dir), config, { provider: s.provider, ui: s.ui, audit: s.audit, registry: s.registry });
    assert.equal(a.verdicts.length, 1);
  });
});
