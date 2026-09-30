import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  continuePrompt,
  coachingPrompt,
  displayVulnId,
  DOSSIER_SCHEMA,
  dossierTurnPrompt,
  NUDGE_TEXT,
  PROMPT_VERSION,
  railsReaskPrompt,
  reconPrompt,
  repeatNote,
  REPEAT_NOTE,
  RISK_RUBRIC,
  schemaText,
  systemPrompt,
  symbolName,
  VERDICT_SCHEMA,
  verdictPrompt,
  verdictTurnPrompt,
} from '../../src/investigation/prompts.ts';
import { validateJson } from '../../src/util/schema.ts';
import { decodeFixture, dossierFor, lodashFixture, minimistFixture } from './helpers.ts';

const EM_DASH = String.fromCharCode(0x2014);
// rough token estimate
const tokens = (text: string): number => Math.round(text.length / 4);

describe('system prompt', () => {
  it('is compact and carries role, method, tool rules, budget, rubric and the verdict schema', () => {
    const text = systemPrompt('verdict', 3);
    assert.ok(tokens(text) <= 420, `about ${tokens(text)} tokens`);
    assert.match(text, /You are PatchPilot/);
    assert.match(text, /Method: 1\. Is the package imported/);
    assert.match(text, /prefer one tool call per turn; never repeat an identical call; budget 3 tool calls/);
    assert.match(text, /Stop as soon as the evidence answers the question/);
    assert.ok(text.includes(RISK_RUBRIC));
    assert.ok(text.includes(schemaText(VERDICT_SCHEMA)));
    assert.match(text, /"risk": "Critical"\|"High"\|"Medium"\|"Low"\|"Noise"/);
    assert.match(text, /"confidence": number 0\.\.1/);
    assert.match(text, /"recommendationAction": "upgrade"\|"upgrade_major"\|"update_transitive"\|"override"\|"remove"\|"ignore"\|"monitor"/);
    assert.equal(systemPrompt('verdict', 1).includes('budget 1 tool call.'), true);
  });

  it('keeps the recon stage to facts with the dossier schema', () => {
    const text = systemPrompt('recon', 3);
    assert.ok(tokens(text) <= 300, `about ${tokens(text)} tokens`);
    assert.match(text, /do not rate the risk yet/);
    assert.ok(text.includes(schemaText(DOSSIER_SCHEMA)));
    assert.equal(text.includes('Risk rubric'), false);
  });

  it('renders schemas exactly (every field, enum and range)', () => {
    assert.equal(
      schemaText(DOSSIER_SCHEMA),
      '{"inputSources": string[], "callSiteNotes": string[], "dependentsSummary": string, "fixCost": string, "openQuestions": string[]} (all fields required)',
    );
    assert.deepEqual(VERDICT_SCHEMA.required, ['risk', 'reachable', 'confidence', 'reasoning', 'evidence', 'recommendationAction']);
    assert.deepEqual(validateJson({ risk: 'Low', reachable: 'no', confidence: 1.2, reasoning: '', evidence: [], recommendationAction: 'upgrade' }, VERDICT_SCHEMA), ['$.confidence: above maximum 1']);
  });

  it('has a prompt version for the verdict cache key', () => {
    assert.match(PROMPT_VERSION, /\S/);
    assert.notEqual(PROMPT_VERSION, '0-wave0');
  });
});

describe('stage messages', () => {
  it('builds the package case for stage 1', () => {
    const { pkg, template, merge } = lodashFixture();
    const text = reconPrompt(pkg, [template, merge]);
    assert.match(text, /^Package case: lodash@4\.17\.20, direct production dependency \(dependencies: 4\.17\.20\)\./);
    assert.match(text, /Dependency path: vulnerable-app@1\.0\.0 > lodash@4\.17\.20/);
    assert.match(text, /Import sites \(6 files scanned\): src\/config\.js:7 `const _ = require\('lodash'\);` as _ \[source\]/);
    assert.match(text, /Members called: _\.get \(3\), _\.merge \(1\); the imported binding itself is called 0 times/);
    assert.match(text, /1\. GHSA-35jh-r3h4-6jhm \(CVE-2021-23337\), HIGH, CVSS 7\.2: Command Injection in lodash\. Blamed: template \(exported/);
    assert.match(text, /recommended fix 4\.17\.21 \(no major bump\)/);
    assert.match(text, /Fix cost: upgrading to 4\.17\.21 clears all of them \(no major bump\)/);
    assert.match(text, /check_deps/);
  });

  it('describes a transitive package that is not imported', () => {
    const { pkg, vuln } = decodeFixture();
    const text = reconPrompt(pkg, [vuln]);
    assert.match(text, /transitive production dependency, required by query-string@6\.14\.1/);
    assert.match(text, /Not imported anywhere in the project \(6 files scanned\)\. It is installed because query-string@6\.14\.1 depends on it\./);
  });

  it('builds the CVE case for stage 2 with the dossier and a suggested first call', () => {
    const { pkg, template } = lodashFixture();
    const text = verdictPrompt(pkg, template, dossierFor(pkg, { inputSources: ['config file from disk (trusted)'] }));
    assert.match(text, /^Vulnerability: GHSA-35jh-r3h4-6jhm \(CVE-2021-23337\) in lodash@4\.17\.20, HIGH, CVSS 7\.2, CWE-77, CWE-94\./);
    assert.match(text, /Details: Lodash versions prior to 4\.17\.21/);
    assert.match(text, /Blamed symbols: template \(exported: public API the project could call\)/);
    assert.match(text, /Input sources: config file from disk \(trusted\)/);
    assert.match(text, /Start with this tool call: \{"name":"get_usage","arguments":\{"package":"lodash","symbol":"template"\}\}/);
    const m = minimistFixture();
    const internal = verdictPrompt(m.pkg, m.vuln, dossierFor(m.pkg));
    assert.match(internal, /setKey \(internal: runs inside the package\)/);
    assert.match(internal, /Start with this tool call: \{"name":"get_usage","arguments":\{"package":"minimist"\}\}/);
    assert.match(internal, /MAJOR|no major bump/);
  });

  it('asks for the dossier and the verdict, and re-asks with the contradiction spelled out', () => {
    assert.match(dossierTurnPrompt(), /fact dossier as JSON/);
    assert.match(dossierTurnPrompt(), /No risk rating\./);
    assert.match(dossierTurnPrompt(), /write "unknown" when no evidence here shows it/);
    assert.doesNotMatch(dossierTurnPrompt(), /process\.argv|maintainers/, 'no fixture-shaped examples for the model to copy');
    assert.match(verdictTurnPrompt(), /verdict as JSON matching the verdict schema/);
    const reask = verdictTurnPrompt('you rated the risk High, but semver is a dev-only dependency, so the risk must be at most Medium.');
    assert.match(reask, /^Your verdict breaks a rule: you rated the risk High, but semver is a dev-only dependency, so the risk must be at most Medium\./);
    assert.match(reask, /corrected verdict/);
    assert.equal(railsReaskPrompt('x.'), verdictTurnPrompt('x.'));
  });
});

describe('loop messages', () => {
  it('nudges at budget-1 and otherwise reports the remaining budget', () => {
    assert.match(continuePrompt(1, 3), new RegExp(`^${NUDGE_TEXT}`));
    assert.equal(NUDGE_TEXT, '1 tool call left, wrap up');
    assert.match(continuePrompt(2, 3), /^2 of 3 tool calls left/);
  });

  it('coaches with the literal tool call JSON', () => {
    const text = coachingPrompt({ tool: 'get_usage', args: { package: 'lodash', symbol: 'template' }, reason: 'the advisory blames template()' });
    assert.match(text, /the advisory blames template\(\)/);
    assert.ok(text.endsWith('{"name":"get_usage","arguments":{"package":"lodash","symbol":"template"}}'));
  });

  it('notes repeats with the earlier result', () => {
    assert.equal(repeatNote('earlier'), `${REPEAT_NOTE}\nearlier`);
  });

  it('never contains an em dash', () => {
    const { pkg, template } = lodashFixture();
    const all = [systemPrompt('recon', 3), systemPrompt('verdict', 3), reconPrompt(pkg, [template]), verdictPrompt(pkg, template, dossierFor(pkg)), dossierTurnPrompt(), verdictTurnPrompt('x'), continuePrompt(1, 3)];
    for (const text of all) assert.equal(text.includes(EM_DASH), false);
  });
});

describe('helpers', () => {
  it('normalises symbol names and prefers the CVE alias for display', () => {
    assert.equal(symbolName('_.template()'), 'template');
    assert.equal(symbolName('JSON5.parse'), 'parse');
    assert.equal(symbolName('setKey()'), 'setKey');
    assert.equal(displayVulnId({ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'] }), 'CVE-2021-23337');
    assert.equal(displayVulnId({ id: 'GHSA-93q8-gq69-wqmw', aliases: [] }), 'GHSA-93q8-gq69-wqmw');
  });
});
