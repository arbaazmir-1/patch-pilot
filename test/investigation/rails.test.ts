import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { MockProvider, type MockScript } from '../../src/llm/mock.ts';
import { applyRails, evidenceRequirements, forcedVerdict, runVerdictLoop, type Phase2Deps } from '../../src/investigation/agent.ts';
import type { CaseFile, Config, DependentUsage, DynamicAccess, IndirectPath, PackageCase, ToolResult, VerdictModelOutput } from '../../src/types.ts';
import { captureUi, caseFileOf, decodeFixture, dossierFor, fakeRegistry, lodashFixture, tempDir, testConfig, usageResult, type FakeHandler } from './helpers.ts';

const META = { provider: 'mock' as const, model: 'mock', promptVersion: 'p1' };

function out(risk: VerdictModelOutput['risk'], reachable: VerdictModelOutput['reachable'] = 'unknown'): VerdictModelOutput {
  return { risk, reachable, confidence: 0.7, reasoning: 'r', evidence: [], recommendationAction: 'upgrade' };
}

const VIA_WRAPPER: IndirectPath = { path: 'src/cli.js', line: 31, via: ['compile'], member: 'template' };
const COMPUTED: DynamicAccess = { path: 'src/x.js', line: 12, text: '_[name]', reason: 'computed-member' };
const IN_QUERY_STRING: DependentUsage = { dependent: 'query-string', version: '6.14.1', path: 'node_modules/query-string/index.js', line: 45, member: null, text: 'return decodeComponent(value);' };

// imported in source, template never called
function lodashWith(usage: Partial<PackageCase['usage']>) {
  const l = lodashFixture();
  return { ...l, pkg: { ...l.pkg, usage: { ...l.pkg.usage, ...usage } } };
}

function decodeWith(usage: Partial<PackageCase['usage']>) {
  const d = decodeFixture();
  return { ...d, pkg: { ...d.pkg, usage: { ...d.pkg.usage, ...usage } } };
}

describe('rails: calls through the project\'s own functions', () => {
  it('an indirect path to a blamed member counts as called (floor Medium)', () => {
    const { pkg, template } = lodashWith({ indirectPaths: [VIA_WRAPPER] });
    assert.deepEqual(applyRails(out('Low'), pkg, template, false), {
      risk: 'Medium',
      floor: 'Medium',
      ceiling: null,
      violation: "imported in source and an exported blamed API is called indirectly, through the project's own functions (floor Medium)",
    });
    assert.equal(applyRails(out('Low'), lodashFixture().pkg, template, false, { indirectCalled: true }).floor, 'Medium', 'get_usage found it in this loop');
  });

  it('only indirect paths to a blamed member from outside tests count', () => {
    const other = lodashWith({ indirectPaths: [{ ...VIA_WRAPPER, member: 'get' }] });
    assert.equal(applyRails(out('Low'), other.pkg, other.template, false).floor, null, 'get is not blamed');
    const fromTest = lodashWith({ indirectPaths: [{ ...VIA_WRAPPER, path: 'test/cli.test.js' }] });
    assert.equal(applyRails(out('Low'), fromTest.pkg, fromTest.template, false).floor, null);
  });

  it('turns reachability "no" into "likely" and never lets the "not called" ceiling fire', () => {
    const { pkg, template } = lodashWith({ indirectPaths: [VIA_WRAPPER] });
    const r = applyRails(out('High', 'no'), pkg, template, false, { blamedApiNotCalled: true });
    assert.equal(r.ceiling, null);
    assert.equal(r.violation, null);
    assert.equal(r.reachable, 'likely');
    assert.equal(r.reachableReason, "the blamed API is called through the project's own functions");
  });

  it('a forced verdict names the indirect call', () => {
    const { pkg, template } = lodashWith({ indirectPaths: [VIA_WRAPPER] });
    const v = forcedVerdict(pkg, template, [], META);
    assert.equal(v.risk, 'High');
    assert.equal(v.reachable, 'likely');
    assert.match(v.reasoning, /the blamed template\(\) is called indirectly \(src\/cli\.js:31 via compile\(\)\)/);
  });
});

describe('rails: accesses that cannot be resolved statically', () => {
  it('a dynamic access on the binding keeps the "not called" ceiling from firing and reachability from being "no"', () => {
    const { pkg, template } = lodashWith({ dynamicAccess: [COMPUTED] });
    const r = applyRails(out('High', 'no'), pkg, template, false, { blamedApiNotCalled: true });
    assert.equal(r.ceiling, null);
    assert.equal(r.risk, 'High');
    assert.equal(r.reachable, 'unknown');
    assert.equal(r.reachableReason, 'an access to the package cannot be resolved statically');
    assert.equal(applyRails(out('High', 'unlikely'), pkg, template, false).reachable, undefined, 'only "no" is contradicted');
    assert.equal(applyRails(out('High'), lodashFixture().pkg, template, false, { blamedApiNotCalled: true }).ceiling, 'Medium', 'without it the ceiling applies');
  });

  it('a dynamic require keeps the "not imported" ceiling Low from firing', () => {
    const d = decodeWith({ dynamicAccess: [{ path: 'src/load.js', line: 2, text: 'require(name)', reason: 'dynamic-require' }] });
    assert.equal(applyRails(out('High'), d.pkg, d.vuln, false, { dependentsImportedInSource: false }).ceiling, null);
    assert.equal(applyRails(out('High'), decodeFixture().pkg, d.vuln, false, { dependentsImportedInSource: false }).ceiling, 'Low');
    const forced = forcedVerdict(d.pkg, d.vuln, [], META, { dependentsImportedInSource: false });
    assert.equal(forced.risk, 'Low');
    assert.equal(forced.reachable, 'unknown', 'not "no"');
    assert.match(forced.reasoning, /an access at src\/load\.js:2 cannot be resolved statically/);
  });

  it('a forced verdict says reachability is unknown, not unlikely', () => {
    const { pkg, template } = lodashWith({ dynamicAccess: [COMPUTED] });
    const v = forcedVerdict(pkg, template, [], META);
    assert.equal(v.risk, 'Medium');
    assert.equal(v.reachable, 'unknown');
    assert.match(v.reasoning, /1 access to it cannot be resolved statically \(src\/x\.js:12 `_\[name\]`\)/);
  });
});

describe('rails: a transitive package called inside its dependents', () => {
  it('counts as reachable through a dependent that is imported in source (floor Medium)', () => {
    const { pkg, vuln } = decodeWith({ dependentUsage: [IN_QUERY_STRING] });
    const r = applyRails(out('Low', 'no'), pkg, vuln, false, { dependentsImportedInSource: true, importedDependents: ['query-string'] });
    assert.deepEqual(r, {
      risk: 'Medium',
      floor: 'Medium',
      ceiling: null,
      violation: 'query-string is imported in source and calls the blamed API in its own code (floor Medium)',
      reachable: 'likely',
      reachableReason: 'query-string calls it and is imported in source',
    });
    assert.equal(applyRails(out('Low'), pkg, vuln, false, { dependentsImportedInSource: false }).ceiling, 'Low', 'a dependent that is not imported: ceiling Low stays');
    assert.equal(applyRails(out('Low'), pkg, vuln, false, { dependentsImportedInSource: true, importedDependents: ['other'] }).floor, null);
  });

  it('only calls of the blamed member (or the package itself) count', () => {
    const blamed = { ...decodeFixture().vuln, blamedSymbols: [{ name: 'parse', kind: 'exported' as const, via: 'member-access' as const }] };
    const member = decodeWith({ dependentUsage: [{ ...IN_QUERY_STRING, member: 'stringify' }] });
    assert.equal(applyRails(out('Low'), member.pkg, blamed, false, { importedDependents: ['query-string'] }).floor, null);
    const parse = decodeWith({ dependentUsage: [{ ...IN_QUERY_STRING, member: 'parse' }] });
    assert.equal(applyRails(out('Low'), parse.pkg, blamed, false, { importedDependents: ['query-string'] }).floor, 'Medium');
  });

  it('a forced verdict and the evidence gate use it', () => {
    const { pkg, vuln } = decodeWith({ dependentUsage: [IN_QUERY_STRING] });
    const v = forcedVerdict(pkg, vuln, [], META, { dependentsImportedInSource: true, importedDependents: ['query-string'] });
    assert.equal(v.risk, 'Medium');
    assert.equal(v.reachable, 'likely');
    assert.match(v.reasoning, /decode-uri-component is not imported directly, but query-string, which is imported in source, calls it in node_modules\/query-string\/index\.js:45/);
    assert.deepEqual(
      evidenceRequirements(pkg, vuln).map((r) => [r.tool, r.args, r.reason]),
      [['get_usage', { package: 'decode-uri-component' }, 'CVE-2022-38900: query-string calls decode-uri-component in its own code (node_modules/query-string/index.js:45); check how the project reaches it']],
    );
    assert.deepEqual(evidenceRequirements(decodeFixture().pkg, vuln), [], 'no dependent usage: nothing required, as before');
  });
});

const verdictJson = (risk: string, reachable = 'no') => ({ risk, reachable, confidence: 0.8, reasoning: `Rated ${risk}.`, evidence: [], recommendationAction: 'upgrade' });

function harness(script: MockScript, handlers: Record<string, FakeHandler>, caseFile: CaseFile, extra: Partial<Phase2Deps> = {}) {
  const provider = new MockProvider(script);
  const { ui, out: text } = captureUi();
  const audit = new MemoryAudit();
  const { registry, calls } = fakeRegistry({ read_file: () => ({ ok: true, hint: 'lines', text: 'lines' }), ...handlers });
  return { deps: { provider, ui, audit, registry, graph: null, caseFile, ...extra } as Phase2Deps, provider, audit, out: text, calls };
}

describe('rails in the verdict loop', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  let config: Config;
  before(async () => {
    tmp = await tempDir();
    config = await testConfig(tmp.dir, { maxSteps: 3 });
  });
  after(async () => {
    await tmp.cleanup();
  });

  it('raises a Low verdict when the case file shows the blamed API called through a wrapper, and fixes reachability', async () => {
    const { pkg, template } = lodashWith({ indirectPaths: [VIA_WRAPPER] });
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Not called.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }], repeat: true },
        ],
      },
      { get_usage: () => usageResult('lodash', 'template', 0) },
      caseFileOf([pkg], [template]),
    );
    const verdict = await runVerdictLoop(pkg, template, dossierFor(pkg), config, h.deps);
    assert.equal(verdict.risk, 'Medium');
    assert.equal(verdict.reachable, 'likely');
    assert.equal(verdict.investigation.adjustReason, "imported in source and an exported blamed API is called indirectly, through the project's own functions (floor Medium)");
    const trace = h.out().replace(/\n\|\s+/g, ' ');
    assert.match(trace, /\[rails\] Reachability "no" changed to "likely": the blamed API is called through the project's own functions/);
    const reask = h.provider.calls.filter((c) => c.purpose === 'verdict')[1];
    assert.match(reask?.messages.at(-1)?.content ?? '', /lodash is imported in source and a function the advisory blames is called through the project's own functions/);
  });

  it('counts an indirect call that get_usage reports in this loop', async () => {
    const { pkg, template } = lodashFixture();
    const withIndirect = (): ToolResult => {
      const r = usageResult('lodash', 'template', 0);
      Object.assign(r.data as object, { fallback: false, indirectCalls: 1, indirectPaths: [VIA_WRAPPER] });
      return r;
    };
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Only through compile().' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High', 'likely') }] },
        ],
      },
      { get_usage: withIndirect },
      caseFileOf([pkg], [template]),
    );
    const verdict = await runVerdictLoop(pkg, template, dossierFor(pkg), config, h.deps);
    assert.equal(verdict.risk, 'High', 'no "not called" ceiling');
    assert.equal(verdict.investigation.adjusted, undefined);
  });

  it('keeps a High verdict when the case file has a computed access, and reachability is not "no"', async () => {
    const { pkg, template } = lodashWith({ dynamicAccess: [COMPUTED] });
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Not called directly.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High') }] },
        ],
      },
      { get_usage: () => usageResult('lodash', 'template', 0) },
      caseFileOf([pkg], [template]),
    );
    const verdict = await runVerdictLoop(pkg, template, dossierFor(pkg), config, h.deps);
    assert.equal(verdict.risk, 'High');
    assert.equal(verdict.reachable, 'unknown');
    assert.equal(verdict.investigation.adjusted, undefined);
  });

  it('requires get_usage for a transitive package its dependents call, and floors it when the dependent is imported', async () => {
    const { pkg, vuln } = decodeWith({ dependentUsage: [IN_QUERY_STRING] });
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ content: 'It is only a transitive dependency.' }, { content: 'Still transitive.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }], repeat: true },
        ],
      },
      { get_usage: () => ({ ok: true, hint: 'query-string calls decodeUriComponent()', text: 'dependents text' }) },
      caseFileOf([pkg], [vuln]),
      { scanImports: async (names) => new Map(names.map((n) => [n, n === 'query-string'])) },
    );
    const verdict = await runVerdictLoop(pkg, vuln, dossierFor(pkg), config, h.deps);
    assert.deepEqual(h.calls.map((c) => [c.tool, c.args]), [['get_usage', { package: 'decode-uri-component' }]], 'the harness ran get_usage');
    assert.equal(verdict.investigation.gate?.harnessCalls[0], 'get_usage(decode-uri-component)');
    assert.equal(verdict.risk, 'Medium');
    assert.equal(verdict.reachable, 'likely');
    assert.equal(verdict.investigation.adjustReason, 'query-string is imported in source and calls the blamed API in its own code (floor Medium)');
  });
});
