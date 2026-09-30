import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { LlmError } from '../../src/llm/errors.ts';
import { MockProvider, type MockScript } from '../../src/llm/mock.ts';
import { LOOP_MAX_TOKENS, runReconLoop, runVerdictLoop, SCHEMA_MAX_TOKENS, type Phase2Deps } from '../../src/investigation/agent.ts';
import { DOSSIER_SCHEMA, NUDGE_TEXT, REPEAT_NOTE, VERDICT_SCHEMA } from '../../src/investigation/prompts.ts';
import type { CaseFile, ChatRequest, Config, ToolResult } from '../../src/types.ts';
import {
  captureUi,
  caseFileOf,
  decodeFixture,
  dossierFor,
  fakeRegistry,
  lodashFixture,
  markedParseFixture,
  minimistFixture,
  semverFixture,
  tempDir,
  testConfig,
  usageResult,
  type FakeHandler,
} from './helpers.ts';

const lodash = lodashFixture();
const minimist = minimistFixture();
const decode = decodeFixture();
const semver = semverFixture();
const CASE_FILE: CaseFile = caseFileOf(
  [lodash.pkg, minimist.pkg, decode.pkg, semver.pkg],
  [lodash.template, lodash.merge, minimist.vuln, decode.vuln, semver.vuln],
);

const verdictJson = (risk: string, extra: Record<string, unknown> = {}) => ({
  risk,
  reachable: 'no',
  confidence: 0.8,
  reasoning: `Rated ${risk} from the evidence.`,
  evidence: ['0 calls to _.template'],
  recommendationAction: 'upgrade',
  ...extra,
});

const okResult = (hint: string): ToolResult => ({ ok: true, hint, text: `${hint} (text)` });

const DEFAULT_HANDLERS: Record<string, FakeHandler> = {
  check_deps: (a) => okResult(`${String(a.package)}@x: direct production dependency`),
  read_file: (a) => okResult(`${String(a.path)}:${String(a.startLine ?? 1)}-${String(a.endLine ?? 40)}`),
  get_changelog: () => okResult('no breaking changes'),
  search_code: () => okResult('No matches'),
  get_advisory: () => okResult('advisory text'),
  get_usage: (a) => usageResult(String(a.package), typeof a.symbol === 'string' ? a.symbol : null, 0, [{ path: 'src/cli.js', line: 21, member: null }]),
};

interface Harness {
  deps: Phase2Deps;
  provider: MockProvider;
  audit: MemoryAudit;
  out: () => string;
  calls: ReturnType<typeof fakeRegistry>['calls'];
  purposes: () => string[];
}

function harness(script: MockScript, handlers: Record<string, FakeHandler> = {}, extra: Partial<Phase2Deps> = {}): Harness {
  const provider = new MockProvider(script);
  const { ui, out } = captureUi();
  const audit = new MemoryAudit();
  const { registry, calls } = fakeRegistry({ ...DEFAULT_HANDLERS, ...handlers });
  return {
    deps: { provider, ui, audit, registry, graph: null, caseFile: CASE_FILE, ...extra },
    provider,
    audit,
    out,
    calls,
    purposes: () => provider.calls.map((c) => c.purpose ?? 'other'),
  };
}

const lastMessage = (req: ChatRequest | undefined) => req?.messages[req.messages.length - 1];

describe('stage 1 reconnaissance loop', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  let config: Config;
  before(async () => {
    tmp = await tempDir();
    config = await testConfig(tmp.dir, { maxSteps: 3 });
  });
  after(async () => {
    await tmp.cleanup();
  });

  it('ends when the model answers without a tool call, then runs the schema-enforced dossier turn', async () => {
    const h = harness({
      rules: [
        { match: { purpose: 'recon' }, replies: [{ content: 'The case file answers it: lodash merges a trusted config file.' }] },
        {
          match: { purpose: 'dossier' },
          replies: [{ json: { inputSources: ['config file from disk'], callSiteNotes: ['src/config.js:22 _.merge'], dependentsSummary: 'direct', fixCost: '4.17.21, patch', openQuestions: [] } }],
        },
      ],
    });
    const dossier = await runReconLoop(lodash.pkg, [lodash.template, lodash.merge], config, h.deps);
    assert.deepEqual(h.purposes(), ['recon', 'dossier']);
    const [recon, dossierReq] = h.provider.calls;
    assert.deepEqual(recon?.tools?.map((t) => t.function.name), ['check_deps', 'read_file', 'get_changelog', 'search_code']);
    assert.equal(recon?.messages[0]?.role, 'system');
    assert.match(recon?.messages[0]?.content ?? '', /do not rate the risk yet/);
    assert.match(recon?.messages[1]?.content ?? '', /^Package case: lodash@4\.17\.20/);
    assert.equal(dossierReq?.tools, undefined);
    assert.deepEqual(dossierReq?.format, DOSSIER_SCHEMA);
    assert.deepEqual(recon?.options, { num_predict: LOOP_MAX_TOKENS });
    assert.deepEqual(dossierReq?.options, { num_predict: SCHEMA_MAX_TOKENS });
    assert.match(lastMessage(dossierReq)?.content ?? '', /fact dossier as JSON/);
    assert.equal(dossier.steps, 1);
    assert.deepEqual(dossier.toolCalls, []);
    assert.equal(dossier.forced, undefined);
    assert.deepEqual(dossier.inputSources, ['config file from disk']);
    assert.equal(dossier.package, 'lodash');
  });

  it('stops at the budget, with the nudge appended at budget-1', async () => {
    const h = harness({
      rules: [
        {
          match: { purpose: 'recon' },
          replies: [
            { toolCalls: [{ name: 'check_deps', arguments: { package: 'lodash' } }] },
            { toolCalls: [{ name: 'read_file', arguments: { path: 'src/config.js' } }] },
            { toolCalls: [{ name: 'search_code', arguments: { pattern: 'merge' } }] },
            { content: 'never reached' },
          ],
        },
      ],
    });
    const dossier = await runReconLoop(lodash.pkg, [lodash.template], config, h.deps);
    assert.deepEqual(h.purposes(), ['recon', 'recon', 'recon', 'dossier']);
    assert.match(lastMessage(h.provider.calls[1])?.content ?? '', /^2 of 3 tool calls left/);
    assert.ok(lastMessage(h.provider.calls[2])?.content.startsWith(NUDGE_TEXT));
    assert.deepEqual(dossier.toolCalls.map((c) => [c.tool, c.by, c.step]), [['check_deps', 'model', 1], ['read_file', 'model', 2], ['search_code', 'model', 3]]);
    assert.deepEqual(h.provider.pending(), [{ rule: 'rules[0]', remaining: 1 }]);
    const dossierMessages = h.provider.calls[3]?.messages ?? [];
    assert.equal(dossierMessages[dossierMessages.length - 2]?.role, 'tool', 'the dossier turn follows the last tool result');
    assert.deepEqual(h.audit.events('tool.call').map((e) => e.tool), ['check_deps', 'read_file', 'search_code']);
    assert.equal(h.audit.events('tool.result').length, 3);
  });

  it('answers the first identical repeat from cache ("you already have this") and ends the loop on the second', async () => {
    const h = harness({ rules: [{ match: { purpose: 'recon' }, replies: [{ toolCalls: [{ name: 'check_deps', arguments: { pkg: 'lodash' } }] }], repeat: true }] });
    const dossier = await runReconLoop(lodash.pkg, [lodash.template], config, h.deps);
    assert.deepEqual(h.purposes(), ['recon', 'recon', 'recon', 'dossier']);
    assert.equal(h.calls.filter((c) => c.tool === 'check_deps').length, 1, 'the handler ran once');
    const third = h.provider.calls[2]?.messages ?? [];
    const repeatMessage = third.filter((m) => m.role === 'tool').pop();
    assert.ok(repeatMessage?.content.startsWith(REPEAT_NOTE));
    assert.match(repeatMessage?.content ?? '', /lodash@x: direct production dependency/);
    assert.deepEqual(dossier.toolCalls.map((c) => [c.tool, c.cached]), [['check_deps', false], ['check_deps', true]]);
    assert.match(h.out(), /Same call repeated again: no more tool calls in this step/);
  });

  for (const [label, content] of [
    ['a fenced json block', 'Checking.\n```json\n{"name": "check_deps", "arguments": {"package": "lodash"}}\n```'],
    ['Mistral [TOOL_CALLS]', '[TOOL_CALLS] [{"name": "check_deps", "arguments": {"package": "lodash"}}]'],
    ['<function=...>', '<function=check_deps>{"package": "lodash"}</function>'],
    ['prose-wrapped JSON with parameters', 'I will call {"name": "check_deps", "parameters": {"package": "lodash"}} first.'],
    ['call syntax', 'check_deps({"package": "lodash"})'],
    ['call syntax with one bare string', 'check_deps("lodash")'],
    ['an argument alias', '{"name": "check_deps", "arguments": {"pkg": "lodash"}}'],
  ] as const) {
    it(`recovers a tool call written as ${label}`, async () => {
      const h = harness({ rules: [{ match: { purpose: 'recon' }, replies: [{ content }, { content: 'Done.' }] }] });
      const dossier = await runReconLoop(lodash.pkg, [lodash.template], config, h.deps);
      assert.deepEqual(h.calls.map((c) => [c.tool, c.args]), [['check_deps', { package: 'lodash' }]]);
      assert.equal(dossier.toolCalls[0]?.by, 'model');
      const history = h.provider.calls[1]?.messages ?? [];
      const assistant = history.find((m) => m.role === 'assistant');
      assert.equal(assistant?.content, '', 'tool-call turns are stored with empty content (Mistral renders their calls)');
      assert.deepEqual(assistant?.tool_calls, [{ function: { name: 'check_deps', arguments: { package: 'lodash' } } }], 'history carries the normalised call');
    });
  }

  it('builds a deterministic dossier when the dossier turn fails twice', async () => {
    const h = harness({
      rules: [
        { match: { purpose: 'recon' }, replies: [{ content: 'Nothing to add.' }] },
        { match: { purpose: 'dossier' }, replies: [{ content: 'not json' }, { error: { message: 'boom', kind: 'http', status: 500 } }] },
      ],
    });
    const dossier = await runReconLoop(minimist.pkg, [minimist.vuln], config, h.deps);
    assert.equal(dossier.forced, true);
    assert.deepEqual(h.purposes(), ['recon', 'dossier', 'dossier']);
    assert.match(lastMessage(h.provider.calls[2])?.content ?? '', /not a valid JSON object for the dossier schema/);
    assert.match(dossier.callSiteNotes.join(' '), /src\/cli\.js:7/);
    assert.match(dossier.fixCost, /1\.2\.6/);
    assert.match(h.out(), /agent \[forced\] No valid dossier from the model/);
  });
});

describe('stage 2 verdict loop', () => {
  let tmp: Awaited<ReturnType<typeof tempDir>>;
  let config: Config;
  before(async () => {
    tmp = await tempDir();
    config = await testConfig(tmp.dir, { maxSteps: 3 });
  });
  after(async () => {
    await tmp.cleanup();
  });

  it('evidence gate, exported symbol: coaches with the literal call, then runs get_usage(pkg, symbol) as the harness', async () => {
    const h = harness({
      rules: [
        { match: { purpose: 'verdict-loop' }, replies: [{ content: 'lodash only merges config, so this is fine.' }, { content: 'Still fine.' }] },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low', { reasoning: 'template() is never called; the project only calls _.merge and _.get.' }) }] },
      ],
    });
    const verdict = await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, h.deps);
    assert.deepEqual(h.purposes(), ['verdict-loop', 'verdict-loop', 'verdict']);
    assert.deepEqual(h.provider.calls[0]?.tools?.map((t) => t.function.name), ['get_usage', 'read_file', 'get_advisory', 'search_code']);
    const coaching = lastMessage(h.provider.calls[1]);
    assert.equal(coaching?.role, 'user');
    assert.ok(coaching?.content.endsWith('{"name":"get_usage","arguments":{"package":"lodash","symbol":"template"}}'));
    const gate = h.audit.events('gate.evidence');
    assert.deepEqual(gate.map((e) => e.action), ['coached', 'harness-ran']);
    assert.deepEqual(gate[1]?.args, { package: 'lodash', symbol: 'template' });
    assert.deepEqual(h.calls, [{ tool: 'get_usage', args: { package: 'lodash', symbol: 'template' } }]);
    assert.deepEqual(verdict.investigation.toolCalls.map((c) => [c.tool, c.by]), [['get_usage', 'harness']]);
    assert.deepEqual(verdict.investigation.gate, { fired: true, coached: true, harnessCalls: ['get_usage(lodash, template)'] });
    const verdictReq = h.provider.calls[2];
    assert.deepEqual(verdictReq?.format, VERDICT_SCHEMA);
    assert.equal(verdictReq?.tools, undefined);
    const harnessTurn = verdictReq?.messages.find((m) => m.role === 'assistant' && m.tool_calls?.length);
    assert.deepEqual(harnessTurn?.tool_calls, [{ function: { name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } } }]);
    assert.equal(h.audit.events('tool.call')[0]?.by, 'harness');
    assert.equal(verdict.risk, 'Low');
    assert.equal(verdict.investigation.analysis, 'Still fine.\nModel recommendation: upgrade');
    assert.deepEqual(verdict.recommendation, { action: 'upgrade', targetVersion: '4.17.21', majorBump: false });
    const text = h.out();
    assert.match(text, /^\| CVE-2021-23337 - lodash@4\.17\.20 - CVSS 7\.2/m);
    assert.match(text, /\| agent \[evidence gate\] Evidence missing: CVE-2021-23337 blames template\(\)/);
    assert.match(text, /\| agent \[evidence gate\] Checking if template\(\) is called\.\.\./);
    assert.match(text, /\| \[LOW\] {2}template\(\) is never called; the project only calls _\.merge and _\.get\./);
    assert.match(text, /\| Confidence: 80% - Recommended: bump to 4\.17\.21/);
    assert.deepEqual(h.audit.events('verdict').map((e) => [e.vulnId, e.risk, e.forced, e.action]), [['GHSA-35jh-r3h4-6jhm', 'Low', false, 'upgrade']]);
  });

  it('derives the action from the rules and keeps the model suggestion in the audit and the analysis', async () => {
    const h = harness({
      rules: [
        { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Not called; keep an eye on it.' }] },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Medium', { recommendationAction: 'monitor' }) }] },
      ],
    });
    const verdict = await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, h.deps);
    assert.deepEqual(verdict.recommendation, { action: 'upgrade', targetVersion: '4.17.21', majorBump: false });
    assert.equal(h.audit.events('verdict')[0]?.action, 'monitor');
    assert.match(verdict.investigation.analysis ?? '', /\nModel recommendation: monitor$/);
    assert.match(h.out(), /Recommended: bump to 4\.17\.21/);
  });

  it('evidence gate is satisfied when the model makes the required call itself', async () => {
    const h = harness({
      rules: [
        { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: '_.template' } }] }, { content: 'template() is never called.' }] },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }] },
      ],
    });
    const verdict = await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, h.deps);
    assert.deepEqual(h.audit.events('gate.evidence').map((e) => e.action), ['satisfied']);
    assert.equal(verdict.investigation.gate, undefined);
    assert.deepEqual(verdict.investigation.toolCalls.map((c) => c.by), ['model']);
  });

  it('evidence gate accepts the coached call when the model complies', async () => {
    const parrot = 'The evidence is incomplete: CVE-2021-23337 blames template(), which the project could call; check whether it does.';
    const h = harness({
      rules: [
        {
          match: { purpose: 'verdict-loop' },
          replies: [{ content: 'Fine.' }, { content: parrot, toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Not called.' }],
        },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }] },
      ],
    });
    const verdict = await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, h.deps);
    assert.deepEqual(h.audit.events('gate.evidence').map((e) => e.action), ['coached', 'satisfied']);
    assert.deepEqual(verdict.investigation.gate, { fired: true, coached: true, harnessCalls: [] });
    assert.equal(h.out().split('\n').filter((l) => l.includes('The evidence is incomplete')).length, 0, 'parroted coaching text is not traced');
    const later = harness({
      rules: [
        {
          match: { purpose: 'verdict-loop' },
          replies: [
            { content: 'Fine for now, nothing to check.' },
            { toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] },
            { content: parrot, toolCalls: [{ name: 'read_file', arguments: { path: 'src/config.js' } }] },
            { content: 'Fine for now, nothing to check.' },
          ],
        },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }] },
      ],
    });
    await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, later.deps);
    const traced = later.out().split('\n');
    assert.equal(traced.filter((l) => l.includes('The evidence is incomplete')).length, 0, 'an echo of an earlier coaching message is not traced');
    assert.equal(traced.filter((l) => l.includes('Fine for now, nothing to check.')).length, 1, 'identical prose is traced once');
    assert.equal(verdict.investigation.analysis, 'Not called.\nModel recommendation: upgrade');
  });

  it('evidence gate, internal symbol: requires the call sites and one read of a call site', async () => {
    const h = harness({
      rules: [
        { match: { purpose: 'verdict-loop' }, replies: [{ content: 'minimist just parses flags.' }, { toolCalls: [{ name: 'get_usage', arguments: { package: 'minimist' } }] }, { content: 'It parses process.argv.' }] },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High', { reachable: 'yes', reasoning: 'parseArgs(argv) runs on user CLI input.' }) }] },
      ],
    });
    const verdict = await runVerdictLoop(minimist.pkg, minimist.vuln, dossierFor(minimist.pkg), config, h.deps);
    const gate = h.audit.events('gate.evidence');
    assert.deepEqual(gate.map((e) => [e.action, e.tool]), [['coached', 'get_usage'], ['harness-ran', 'read_file']]);
    assert.deepEqual(gate[0]?.missing, ['get_usage(minimist)', 'read_file(src/cli.js, 2, 41)']);
    assert.ok(lastMessage(h.provider.calls[1])?.content.endsWith('{"name":"get_usage","arguments":{"package":"minimist"}}'));
    assert.deepEqual(h.calls.map((c) => [c.tool, c.args]), [
      ['get_usage', { package: 'minimist' }],
      ['read_file', { path: 'src/cli.js', startLine: 11, endLine: 40 }],
    ]);
    assert.deepEqual(verdict.investigation.toolCalls.map((c) => [c.tool, c.by]), [['get_usage', 'model'], ['read_file', 'harness']]);
    assert.equal(verdict.risk, 'High');
    assert.match(h.out(), /agent \[evidence gate\] Reading src\/cli\.js:11-40\.\.\./);
  });

  it('rails: re-asks once with the contradiction, then clamps and marks the verdict adjusted', async () => {
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'merge' } }] }, { content: 'merge is called on config.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }, { json: verdictJson('Low') }] },
        ],
      },
      { get_usage: (a) => usageResult('lodash', String(a.symbol), 1, [{ path: 'src/config.js', line: 22, member: 'merge' }]) },
    );
    const verdict = await runVerdictLoop(lodash.pkg, lodash.merge, dossierFor(lodash.pkg), config, h.deps);
    assert.deepEqual(h.purposes(), ['verdict-loop', 'verdict-loop', 'verdict', 'verdict']);
    assert.match(
      lastMessage(h.provider.calls[3])?.content ?? '',
      /^Your verdict breaks a rule: you rated the risk Low, but lodash is imported in source and a function the advisory blames is called there, so the risk must be at least Medium\./,
    );
    assert.equal(verdict.risk, 'Medium');
    assert.equal(verdict.investigation.adjusted, true);
    assert.equal(verdict.investigation.originalRisk, 'Low');
    assert.equal(verdict.investigation.adjustReason, 'imported in source and an exported blamed API is called (floor Medium)');
    assert.deepEqual(h.audit.events('verdict.adjusted').map((e) => [e.originalRisk, e.risk, e.rule, e.reasked]), [
      ['Low', 'Medium', 'imported in source and an exported blamed API is called (floor Medium)', true],
    ]);
    assert.match(h.out(), /agent \[adjusted\] Risk raised from Low to Medium/);
  });

  it('rails: caps a High verdict when get_usage shows the blamed function is never called', async () => {
    const h = harness({
      rules: [
        {
          match: { purpose: 'verdict-loop' },
          replies: [
            { toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] },
            { content: 'The template function is called with the config object.' },
          ],
        },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High', { reachable: 'yes', confidence: 1 }) }], repeat: true },
      ],
    });
    const verdict = await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, h.deps);
    assert.match(
      lastMessage(h.provider.calls[3])?.content ?? '',
      /you rated the risk High, but get_usage found no call to the functions the advisory blames \(and no dynamic member access\) anywhere in the project, so the risk must be at most Medium\./,
    );
    assert.equal(verdict.risk, 'Medium');
    assert.equal(verdict.investigation.adjustReason, 'the blamed functions are not called anywhere in the project (ceiling Medium)');
  });

  it('rails: 0 calls to a blamed member is no evidence of safety when the entry point is called (floor, no ceiling)', async () => {
    const marked = markedParseFixture();
    const entryResult = (): ToolResult => ({
      ok: true,
      hint: "0 calls to marked.parse, but the package itself is called 1 time (src/render.js:8); the default call is the package's main entry point",
      data: {
        package: 'marked',
        symbol: 'parse',
        imported: true,
        importSites: [],
        membersUsed: {},
        bindingCalls: 1,
        symbolCalls: 0,
        callSites: [{ path: 'src/render.js', line: 8, text: 'return marked(userMarkdown, {', scope: 'source', binding: 'marked', member: null }],
        fallback: true,
        entryPointCalled: true,
        dynamicAccess: [],
        scannedFiles: 5,
      },
      text: 'entry point text',
    });
    const low = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'marked', symbol: 'parse' } }] }, { content: 'parse is never called.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Low') }], repeat: true },
        ],
      },
      { get_usage: entryResult },
    );
    const clamped = await runVerdictLoop(marked.pkg, marked.vuln, dossierFor(marked.pkg), config, low.deps);
    assert.match(
      lastMessage(low.provider.calls[3])?.content ?? '',
      /you rated the risk Low, but marked is imported in source and the package itself is called there as its default callable, the package's main entry point, so the risk must be at least Medium\./,
    );
    assert.equal(clamped.risk, 'Medium');
    assert.equal(clamped.investigation.adjustReason, "imported in source and the package's default callable, its main entry point, is called (floor Medium)");
    const high = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'marked', symbol: 'parse' } }] }, { content: 'marked() renders user markdown.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High', { reachable: 'yes' }) }] },
        ],
      },
      { get_usage: entryResult },
    );
    const kept = await runVerdictLoop(marked.pkg, marked.vuln, dossierFor(marked.pkg), config, high.deps);
    assert.equal(kept.risk, 'High', 'the "not called" ceiling does not fire when the entry point is called');
    assert.equal(kept.investigation.adjusted, undefined);
    assert.equal(high.purposes().filter((p) => p === 'verdict').length, 1, 'no re-ask');
  });

  it('rails: no evidence ceiling when get_usage reports dynamic member access', async () => {
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Dynamic access.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High') }] },
        ],
      },
      {
        get_usage: () => {
          const r = usageResult('lodash', 'template', 0);
          (r.data as { dynamicAccess: string[] }).dynamicAccess = ['src/config.js:30'];
          return r;
        },
      },
    );
    const verdict = await runVerdictLoop(lodash.pkg, lodash.template, dossierFor(lodash.pkg), config, h.deps);
    assert.equal(verdict.risk, 'High');
    assert.equal(verdict.investigation.adjusted, undefined);
  });

  it('rails: accepts a re-asked verdict that is back within the rails (dependents not imported)', async () => {
    const h = harness(
      {
        rules: [
          { match: { purpose: 'verdict-loop' }, replies: [{ content: 'Not imported at all.' }] },
          { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('High') }, { json: verdictJson('Noise', { reasoning: 'This is a HIGH risk for the project.' }) }] },
        ],
      },
      {},
      { scanImports: async (names) => new Map(names.map((n) => [n, false])) },
    );
    const verdict = await runVerdictLoop(decode.pkg, decode.vuln, dossierFor(decode.pkg), config, h.deps);
    assert.match(lastMessage(h.provider.calls[2])?.content ?? '', /neither decode-uri-component nor any package that depends on it is imported in the project's source code, so the risk must be at most Low\./);
    assert.equal(verdict.risk, 'Noise');
    assert.equal(verdict.investigation.adjusted, undefined);
    assert.equal(
      verdict.reasoning,
      "Re-checked against the evidence: neither decode-uri-component nor any package that depends on it is imported in the project's source code, so the risk is Noise.",
      'a stale sentence naming another risk level is replaced by the checked fact',
    );
    assert.deepEqual(h.audit.events('verdict.adjusted'), []);
    assert.equal(verdict.recommendation.action, 'ignore', 'Noise is ignored');
    assert.deepEqual(h.audit.events('gate.evidence'), [], 'no gate for a package that is not imported in source');
  });

  it('rails: clamps a dev-only dependency to Medium', async () => {
    const devPkg = { ...lodash.pkg, isDevOnly: true };
    const h = harness({
      rules: [
        { match: { purpose: 'verdict-loop' }, replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' } }] }, { content: 'Dev only.' }] },
        { match: { purpose: 'verdict' }, replies: [{ json: verdictJson('Critical') }], repeat: true },
      ],
    });
    const verdict = await runVerdictLoop(devPkg, lodash.template, dossierFor(devPkg), config, h.deps);
    assert.equal(verdict.risk, 'Medium');
    assert.equal(verdict.investigation.adjustReason, 'dev-only dependency (ceiling Medium)');
    assert.match(lastMessage(h.provider.calls[3])?.content ?? '', /lodash is a dev-only dependency \(it is not shipped to production\), so the risk must be at most Medium\./);
  });

  it('produces a forced verdict after two failed verdict turns', async () => {
    const h = harness({
      rules: [
        {
          match: { purpose: 'verdict-loop' },
          replies: [{ toolCalls: [{ name: 'get_usage', arguments: { package: 'minimist' } }] }, { toolCalls: [{ name: 'read_file', arguments: { path: 'src/cli.js', startLine: 15, endLine: 30 } }] }, { content: 'CLI input.' }],
        },
        { match: { purpose: 'verdict' }, replies: [{ content: 'I think it is high' }, { content: '{"risk": "Severe"}' }] },
      ],
    });
    const verdict = await runVerdictLoop(minimist.pkg, minimist.vuln, dossierFor(minimist.pkg), config, h.deps);
    assert.equal(verdict.investigation.forced, true);
    assert.equal(verdict.confidence, 0.3);
    assert.match(verdict.reasoning, /^Forced verdict from the evidence/);
    assert.deepEqual(h.purposes(), ['verdict-loop', 'verdict-loop', 'verdict-loop', 'verdict', 'verdict']);
    assert.match(lastMessage(h.provider.calls[4])?.content ?? '', /not a valid JSON object for the verdict schema/);
    assert.deepEqual(h.audit.events('gate.evidence').map((e) => e.action), ['satisfied']);
    assert.equal(h.audit.events('verdict')[0]?.forced, true);
    assert.match(h.out(), /agent \[forced\] No valid verdict from the model after two attempts/);
  });

  it('degrades HTTP errors to a forced verdict but stops on fatal provider errors', async () => {
    const http = harness({
      rules: [
        { match: { purpose: 'verdict-loop' }, replies: [{ error: { message: 'runner busy', kind: 'http', status: 500 } }] },
        { match: { purpose: 'verdict' }, replies: [{ error: { message: 'runner busy', kind: 'http', status: 500 } }], repeat: true },
      ],
    });
    const forced = await runVerdictLoop(semver.pkg, semver.vuln, dossierFor(semver.pkg), config, http.deps);
    assert.equal(forced.investigation.forced, true);
    assert.equal(forced.risk, 'Low', 'dev-only, used only by a script');
    const fatal = harness({ rules: [{ match: { purpose: 'verdict-loop' }, replies: [{ error: { message: 'connection refused', kind: 'unreachable' } }] }] });
    await assert.rejects(runVerdictLoop(semver.pkg, semver.vuln, dossierFor(semver.pkg), config, fatal.deps), (e: unknown) => e instanceof LlmError && e.kind === 'unreachable');
    const timeouts = harness({ rules: [{ replies: [{ error: { message: 'Ollama did not answer within 180 s', kind: 'timeout' } }], repeat: true }] });
    await assert.rejects(runVerdictLoop(semver.pkg, semver.vuln, dossierFor(semver.pkg), config, timeouts.deps), (e: unknown) => e instanceof LlmError && e.kind === 'timeout');
    assert.equal(timeouts.provider.calls.length, 2, 'two consecutive timeouts stop the run');
  });
});
