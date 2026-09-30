import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  applyRails,
  cleanProse,
  deriveRecommendation,
  evidenceRequirements,
  forcedVerdict,
  parseDossierOutput,
  parseVerdictOutput,
  recommendationText,
  selectPackages,
} from '../../src/investigation/agent.ts';
import type { Config, VerdictModelOutput } from '../../src/types.ts';
import { caseFileOf, decodeFixture, lodashFixture, markedFixture, markedParseFixture, minimistFixture, semverFixture, tempDir, testConfig } from './helpers.ts';

const META = { provider: 'mock' as const, model: 'mock', promptVersion: 'p1' };

function out(risk: VerdictModelOutput['risk']): VerdictModelOutput {
  return { risk, reachable: 'unknown', confidence: 0.7, reasoning: 'r', evidence: [], recommendationAction: 'upgrade' };
}

describe('selectPackages', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  let config: Config;
  before(async () => {
    tmp = await tempDir();
    config = await testConfig(tmp.dir);
  });
  after(async () => {
    await tmp.cleanup();
  });

  const lodash = lodashFixture();
  const minimist = minimistFixture();
  const semver = semverFixture();
  const decode = decodeFixture();
  const caseFile = caseFileOf([lodash.pkg, semver.pkg, decode.pkg, minimist.pkg], [lodash.template, lodash.merge, semver.vuln, decode.vuln, minimist.vuln]);
  const order = (c: Partial<Config>) => selectPackages(caseFile, { ...config, ...c }).map((e) => `${e.pkg.name}:${e.vulns.map((v) => v.id).join(',')}`);

  it('orders by worst GHSA severity, then CVSS, then direct before transitive; CVEs worst first', () => {
    assert.deepEqual(order({}), [
      'minimist:GHSA-xvch-5gv4-984h',
      'semver:GHSA-c2qf-rxjj-qqgw',
      'decode-uri-component:GHSA-w573-4hg7-7wgq',
      'lodash:GHSA-35jh-r3h4-6jhm,GHSA-test-merge-0001',
    ]);
  });

  it('filters with --only by package name, name@version, OSV id or CVE alias', () => {
    assert.deepEqual(order({ only: ['lodash'] }), ['lodash:GHSA-35jh-r3h4-6jhm,GHSA-test-merge-0001']);
    assert.deepEqual(order({ only: ['lodash@4.17.20', 'minimist'] }), ['minimist:GHSA-xvch-5gv4-984h', 'lodash:GHSA-35jh-r3h4-6jhm,GHSA-test-merge-0001']);
    assert.deepEqual(order({ only: ['cve-2021-23337'] }), ['lodash:GHSA-35jh-r3h4-6jhm']);
    assert.deepEqual(order({ only: ['GHSA-w573-4hg7-7wgq', 'nothing'] }), ['decode-uri-component:GHSA-w573-4hg7-7wgq']);
  });

  it('bounds the run with --limit and --max-cves', () => {
    assert.deepEqual(order({ limit: 2 }), ['minimist:GHSA-xvch-5gv4-984h', 'semver:GHSA-c2qf-rxjj-qqgw']);
    assert.deepEqual(order({ only: ['lodash'], maxCves: 1 }), ['lodash:GHSA-35jh-r3h4-6jhm']);
    assert.deepEqual(order({ maxCves: 3 }), ['minimist:GHSA-xvch-5gv4-984h', 'semver:GHSA-c2qf-rxjj-qqgw', 'decode-uri-component:GHSA-w573-4hg7-7wgq']);
  });
});

describe('evidenceRequirements', () => {
  it('requires get_usage(pkg, symbol) for an exported blamed symbol', () => {
    const { pkg, template } = lodashFixture();
    assert.deepEqual(evidenceRequirements(pkg, template).map((r) => [r.tool, r.args]), [['get_usage', { package: 'lodash', symbol: 'template' }]]);
    assert.match(evidenceRequirements(pkg, template)[0]?.reason ?? '', /CVE-2021-23337 blames template\(\)/);
  });

  it('requires the call sites plus one read for internal or no blamed symbols', () => {
    const { pkg, vuln } = minimistFixture();
    const reqs = evidenceRequirements(pkg, vuln);
    assert.deepEqual(reqs.map((r) => [r.tool, r.args]), [
      ['get_usage', { package: 'minimist' }],
      ['read_file', { path: 'src/cli.js', startLine: 2, endLine: 41 }],
    ]);
    assert.match(reqs[0]?.reason ?? '', /internal code \(setKey\)/);
    const none = { ...vuln, blamedSymbols: [] };
    assert.match(evidenceRequirements(pkg, none)[0]?.reason ?? '', /no specific function/);
  });

  it('treats a default-callable blamed symbol as the entry point', () => {
    const { pkg, vuln } = markedFixture();
    assert.deepEqual(evidenceRequirements(pkg, vuln).map((r) => [r.tool, r.args]), [['get_usage', { package: 'marked' }]]);
  });

  it('requires nothing when the package is not imported in source', () => {
    assert.deepEqual(evidenceRequirements(semverFixture().pkg, semverFixture().vuln), []);
    assert.deepEqual(evidenceRequirements(decodeFixture().pkg, decodeFixture().vuln), []);
  });
});

describe('applyRails', () => {
  it('floors at Medium when imported in source and an exported blamed API is called', () => {
    const { pkg, merge } = lodashFixture();
    const r = applyRails(out('Low'), pkg, merge, true);
    assert.deepEqual(r, { risk: 'Medium', floor: 'Medium', ceiling: null, violation: 'imported in source and an exported blamed API is called (floor Medium)' });
    assert.equal(applyRails(out('High'), pkg, merge, true).violation, null);
    assert.equal(applyRails(out('Low'), pkg, merge, false).violation, null, 'no floor when the API is not called');
  });

  it('caps at Low when neither the package nor a dependent is imported in source', () => {
    const { pkg, vuln } = decodeFixture();
    assert.deepEqual(applyRails(out('High'), pkg, vuln, false, { dependentsImportedInSource: false }), {
      risk: 'Low',
      floor: null,
      ceiling: 'Low',
      violation: 'neither the package nor any dependent of it is imported in source (ceiling Low)',
    });
    assert.equal(applyRails(out('High'), pkg, vuln, false, { dependentsImportedInSource: true }).ceiling, null);
    assert.equal(applyRails(out('High'), pkg, vuln, false).ceiling, null, 'unknown dependents: no ceiling');
    const direct = { ...pkg, isDirect: true, dependents: [] };
    assert.equal(applyRails(out('High'), direct, vuln, false).ceiling, 'Low', 'nothing depends on it: only the package counts');
    assert.equal(applyRails(out('High'), { ...direct, usage: { ...direct.usage, truncated: true } }, vuln, false).ceiling, null, 'incomplete scan: no ceiling');
  });

  it('caps at Medium for dev-only dependencies, combining with the Low ceiling', () => {
    const lodash = lodashFixture();
    const devInSource = { ...lodash.pkg, isDevOnly: true };
    assert.deepEqual(applyRails(out('High'), devInSource, lodash.template, false), { risk: 'Medium', floor: null, ceiling: 'Medium', violation: 'dev-only dependency (ceiling Medium)' });
    assert.equal(applyRails(out('Medium'), devInSource, lodash.template, false).violation, null);
    assert.equal(applyRails(out('Low'), devInSource, lodash.merge, true).risk, 'Medium', 'floor and ceiling meet at Medium');
    const { pkg, vuln } = semverFixture();
    const both = applyRails(out('Critical'), pkg, vuln, false);
    assert.equal(both.ceiling, 'Low', 'semver: dev-only, only in scripts, nothing depends on it');
    assert.equal(both.risk, 'Low');
  });
});

describe('applyRails with the default callable', () => {
  it('floors at Medium when the package itself is called in source, even with 0 calls to the blamed member', () => {
    const { pkg, vuln } = markedParseFixture();
    assert.deepEqual(applyRails(out('Low'), pkg, vuln, false), {
      risk: 'Medium',
      floor: 'Medium',
      ceiling: null,
      violation: "imported in source and the package's default callable, its main entry point, is called (floor Medium)",
    });
    const m = minimistFixture();
    assert.equal(applyRails(out('Low'), m.pkg, m.vuln, false).risk, 'Medium', 'internal blamed code behind a called entry point');
    const lodash = lodashFixture();
    assert.equal(applyRails(out('Low'), lodash.pkg, lodash.template, false).violation, null, 'lodash: the binding itself is never called');
  });

  it('never applies the evidence ceiling when the package itself is called', () => {
    const { pkg, vuln } = markedParseFixture();
    const r = applyRails(out('High'), pkg, vuln, false, { blamedApiNotCalled: true });
    assert.equal(r.violation, null);
    assert.equal(r.ceiling, null);
  });

  it('treats the called entry point as the blamed API in a forced verdict', () => {
    const { pkg, vuln } = markedParseFixture();
    const v = forcedVerdict(pkg, vuln, [], META);
    assert.equal(v.risk, 'High');
    assert.equal(v.reachable, 'likely');
    assert.match(v.reasoning, /the package itself is called as its default callable, its main entry point \(the advisory blames parse\(\)\)/);
  });
});

describe('applyRails evidence ceiling', () => {
  it('caps at Medium when every exported blamed function was checked and is not called', () => {
    const { pkg, template } = lodashFixture();
    assert.deepEqual(applyRails(out('High'), pkg, template, false, { blamedApiNotCalled: true }), {
      risk: 'Medium',
      floor: null,
      ceiling: 'Medium',
      violation: 'the blamed functions are not called anywhere in the project (ceiling Medium)',
    });
    assert.equal(applyRails(out('High'), pkg, template, false).violation, null, 'without the evidence the model decides');
    assert.equal(applyRails(out('High'), pkg, template, true, { blamedApiNotCalled: true }).violation, null, 'never when the API is called');
  });
});

describe('forcedVerdict', () => {
  it('derives a low-confidence verdict from severity, imports and blamed-symbol findings', () => {
    const m = minimistFixture();
    const v = forcedVerdict(m.pkg, m.vuln, [], META);
    assert.equal(v.investigation.forced, true);
    assert.equal(v.confidence, 0.3);
    assert.equal(v.risk, 'Medium');
    assert.equal(v.reachable, 'unknown');
    assert.match(v.reasoning, /^Forced verdict from the evidence/);
    assert.deepEqual(v.recommendation, { action: 'upgrade', targetVersion: '1.2.6', majorBump: false });

    const l = lodashFixture();
    assert.equal(forcedVerdict(l.pkg, l.template, [], META).risk, 'Medium', 'imported, template not called');
    const calledTemplate = forcedVerdict(l.pkg, l.template, [{ stage: 'verdict', tool: 'get_usage', args: { package: 'lodash', symbol: 'template' }, by: 'model', ok: true, summary: '2 calls to _.template in 1 file', cached: false, truncated: false, durationMs: 1, step: 1 }], META);
    assert.equal(calledTemplate.risk, 'High');
    assert.equal(calledTemplate.reachable, 'likely');
    assert.equal(forcedVerdict(l.pkg, l.merge, [], META).risk, 'Medium', 'merge is called but MODERATE severity');

    const d = decodeFixture();
    assert.equal(forcedVerdict(d.pkg, d.vuln, [], META, { dependentsImportedInSource: false }).risk, 'Noise');
    assert.equal(forcedVerdict(d.pkg, d.vuln, [], META).risk, 'Low');
    const s = semverFixture();
    const dev = forcedVerdict(s.pkg, s.vuln, [], META);
    assert.equal(dev.risk, 'Low');
    assert.equal(dev.recommendation.action, 'upgrade');
  });
});

describe('recommendation', () => {
  const lodash = lodashFixture();
  const marked = markedFixture();
  const decode = decodeFixture();

  it('Noise is ignored whatever the fix or the model says', () => {
    assert.equal(deriveRecommendation(lodash.pkg, lodash.template, 'upgrade', { risk: 'Noise' }).action, 'ignore');
    assert.equal(deriveRecommendation(marked.pkg, marked.vuln, 'upgrade_major', { risk: 'Noise' }).action, 'ignore');
  });

  it('a fix within the installed line is an upgrade at every risk above Noise, whatever the model says', () => {
    for (const risk of ['Critical', 'High', 'Medium', 'Low'] as const) {
      for (const model of ['monitor', 'ignore', 'upgrade_major', 'remove'] as const) {
        assert.deepEqual(deriveRecommendation(lodash.pkg, lodash.template, model, { risk }), { action: 'upgrade', targetVersion: '4.17.21', majorBump: false }, `${risk}/${model}`);
      }
    }
    const deprecated = deriveRecommendation(lodash.pkg, { ...lodash.template, recommendedFix: { version: '4.18.1', majorBump: false, skippedDeprecated: ['4.18.0'] } }, 'monitor', { risk: 'Medium' });
    assert.deepEqual(deprecated, { action: 'upgrade', targetVersion: '4.18.1', majorBump: false, notes: 'Skips deprecated 4.18.0.' });
  });

  it('transitive packages get update_transitive, or override when the fix is outside the parent range', () => {
    assert.equal(deriveRecommendation(decode.pkg, decode.vuln, 'monitor', { risk: 'Medium' }).action, 'update_transitive');
    assert.equal(deriveRecommendation(decode.pkg, decode.vuln, 'override', { risk: 'Low' }).action, 'override', 'unknown parent ranges: the model breaks the tie');
    const majorFix = { ...decode.vuln, recommendedFix: { version: '1.0.0', majorBump: true } };
    assert.equal(deriveRecommendation(decode.pkg, majorFix, 'upgrade', { risk: 'High' }).action, 'override');
    assert.equal(deriveRecommendation(decode.pkg, majorFix, 'upgrade', { risk: 'Medium' }).action, 'monitor');
  });

  it('a major-bump-only fix is upgrade_major for Critical and High, monitor with a note for Medium and Low', () => {
    for (const risk of ['Critical', 'High'] as const) {
      assert.deepEqual(deriveRecommendation(marked.pkg, marked.vuln, 'monitor', { risk }), {
        action: 'upgrade_major',
        targetVersion: '4.0.10',
        majorBump: true,
        notes: 'Major version bump to 4.0.10: breaking changes are expected.',
      });
    }
    for (const risk of ['Medium', 'Low'] as const) {
      assert.deepEqual(deriveRecommendation(marked.pkg, marked.vuln, 'upgrade_major', { risk }), {
        action: 'monitor',
        targetVersion: '4.0.10',
        majorBump: true,
        notes: 'Major upgrade to 4.0.10 available.',
      });
    }
  });

  it('no fix is monitor', () => {
    const noFix = deriveRecommendation(lodash.pkg, { ...lodash.template, recommendedFix: null }, 'upgrade', { risk: 'Critical' });
    assert.deepEqual(noFix, { action: 'monitor', targetVersion: null, majorBump: false, notes: 'No fixed version is published yet.' });
  });

  it('renders the card text', () => {
    assert.equal(recommendationText({ action: 'upgrade', targetVersion: '4.17.21', majorBump: false }), 'bump to 4.17.21');
    assert.equal(recommendationText({ action: 'upgrade_major', targetVersion: '4.0.10', majorBump: true }), 'upgrade to 4.0.10 (major)');
    assert.equal(recommendationText({ action: 'ignore', targetVersion: null, majorBump: false }), 'ignore');
  });
});

describe('model output parsing', () => {
  it('accepts schema-valid verdicts and normalises near misses', () => {
    assert.deepEqual(parseVerdictOutput('{"risk":"High","reachable":"yes","confidence":0.8,"reasoning":"CLI input","evidence":["src/cli.js:21"],"recommendationAction":"upgrade"}'), {
      risk: 'High',
      reachable: 'yes',
      confidence: 0.8,
      reasoning: 'CLI input',
      evidence: ['src/cli.js:21'],
      recommendationAction: 'upgrade',
    });
    const loose = parseVerdictOutput('```json\n{"risk":"moderate","reachable":"Unlikely","confidence":"85","reasoning":"x","evidence":"one","recommendationAction":"update-transitive"}\n```');
    assert.deepEqual(loose, { risk: 'Medium', reachable: 'unlikely', confidence: 0.85, reasoning: 'x', evidence: ['one'], recommendationAction: 'update_transitive' });
    assert.equal(parseVerdictOutput('not json'), null);
    assert.equal(parseVerdictOutput('{"risk":"Severe"}'), null);
  });

  it('accepts dossiers and rejects unrelated JSON', () => {
    assert.deepEqual(parseDossierOutput('{"inputSources":["argv"],"callSiteNotes":"src/cli.js:21","dependentsSummary":"direct","fixCost":"patch","openQuestions":[]}'), {
      inputSources: ['argv'],
      callSiteNotes: ['src/cli.js:21'],
      dependentsSummary: 'direct',
      fixCost: 'patch',
      openQuestions: [],
    });
    assert.equal(parseDossierOutput('{"risk":"High"}'), null);
  });
});

describe('cleanProse', () => {
  const tools = ['get_usage', 'read_file', 'search_code'];
  it('drops tool-call JSON, early verdict JSON, fences and filler labels', () => {
    assert.equal(cleanProse('Answer: Answer: ``` {"name":"search_code","arguments":{"pattern":"x"}} ``` Answer: {"risk": "High"}', tools), '');
    assert.equal(cleanProse('The template function is not called. Verdict: {"risk": "Low", "reachable": "no"} Done.', tools), 'The template function is not called. Done.');
    assert.equal(cleanProse('minimist parses process.argv directly.', tools), 'minimist parses process.argv directly.');
  });
});
