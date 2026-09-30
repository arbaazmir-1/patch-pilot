import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { planActions } from '../../src/remediation/patch.ts';
import { actionItemInfo, clean, presentActions, presentFindings, renderFindingsTable, renderVerdictCard, sortVerdicts, vulnFor } from '../../src/remediation/present.ts';
import type { Action, Config } from '../../src/types.ts';
import { captureUi, fixtureGraph, loadFixtures, projectConfig } from './patch-helpers.ts';

let dir: string;
let config: Config;

before(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'pp-present-'));
  config = await projectConfig(dir, dir);
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

const EM_DASH = String.fromCharCode(0x2014);

describe('findings', () => {
  it('sorts by risk, then GHSA severity, then package name', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const sorted = sortVerdicts(assessment.verdicts, caseFile);
    assert.deepEqual(sorted.slice(0, 3).map((v) => [v.package, v.risk]), [
      ['minimist', 'High'],
      ['marked', 'High'],
      ['marked', 'High'],
    ]);
    assert.equal(sorted.at(-1)?.risk, 'Noise');
    const ranks = sorted.map((v) => ['Noise', 'Low', 'Medium', 'High', 'Critical'].indexOf(v.risk));
    assert.deepEqual(ranks, [...ranks].sort((a, b) => b - a));
  });

  it('the table shows package, version, id, GHSA, risk, reachable, confidence, action and badges', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const { ui } = captureUi();
    const table = renderFindingsTable(assessment, caseFile, ui);
    const lines = table.split('\n');
    assert.match(lines[0] ?? '', /Package\s+Version\s+Vulnerability\s+GHSA\s+Risk\s+Reach\s+Conf\s+Recommended\s+Badges/);
    assert.match(table, /minimist\s+1\.2\.5\s+CVE-2021-44906\s+CRITICAL\s+High\s+yes\s+80%\s+bump 1\.2\.6/);
    assert.match(table, /marked\s+0\.3\.6\s+CVE-2022-21680\s+HIGH\s+High\s+yes\s+80%\s+major 4\.0\.10\s+cached/);
    assert.match(table, /adjusted/);
    assert.match(table, /forced/);
    assert.ok(lines.every((l) => l.length <= 100), 'fits in 100 columns');
  });

  it('a card carries the reasoning, the confidence line and the evidence', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const { ui } = captureUi();
    const verdict = assessment.verdicts.find((v) => v.package === 'minimist');
    assert.ok(verdict);
    const card = renderVerdictCard(verdict, vulnFor(verdict, caseFile), ui);
    const lines = card.split('\n');
    assert.ok(lines.every((l) => l.startsWith('|')), 'every card line has the left border');
    assert.match(card, /CVE-2021-44906 - minimist@1\.2\.5 - CVSS 9\.8/);
    assert.match(card, /\[HIGH\]\s+minimist imported in src\/cli\.js/);
    assert.match(card, /Confidence: 80% - Recommended: bump to 1\.2\.6/);
    assert.match(card, /Evidence/);
    assert.match(card, /src\/cli\.js:21/);
  });

  it('presentFindings prints the table, the summary line and the accepted risks; --json prints nothing', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const { ui, out, err } = captureUi();
    const withIgnore = { ...config, ignore: [{ id: 'CVE-2022-25883', package: 'semver', reason: 'build script only', by: 'Test User', createdAt: '2026-09-01T00:00:00Z', until: '2027-01-01' }] };
    presentFindings(assessment, caseFile, withIgnore, ui, { cards: false });
    const text = out();
    assert.match(text, /Findings/);
    assert.match(text, /Summary/);
    assert.match(text, /13 CVEs scanned - 3 high - 5 medium - 4 low - 1 noise/);
    assert.match(text, /1 from the verdict cache - 1 adjusted by the rails - 1 forced/);
    assert.match(text.replace(/\s+/g, ' '), /Accepted risk GHSA-c2qf-rxjj-qqgw \(CVE-2022-25883\) in semver: build script only \(accepted by Test User - until 2027-01-01\)/);
    assert.equal(err(), '');
    assert.doesNotMatch(text, /\|.*CVE-2021-44906 - minimist/, 'no cards with cards: false');

    const json = captureUi({ json: true });
    presentFindings(assessment, caseFile, { ...config, json: true }, json.ui);
    assert.equal(json.out(), '');
  });

  it('counts only the investigated CVEs and says how many were left out', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const { ui, out } = captureUi();
    presentFindings({ ...assessment, verdicts: assessment.verdicts.filter((v) => v.package === 'lodash') }, caseFile, config, ui, { cards: false });
    assert.match(out(), /3 of 13 CVEs investigated - 3 medium/);
    assert.match(out(), /10 more CVEs were not investigated/);
  });

  it('clean() removes em dashes from advisory and model text', () => {
    assert.equal(clean(`Prototype pollution ${EM_DASH} fixed in 1.2.6`), 'Prototype pollution, fixed in 1.2.6');
    assert.equal(clean(null), '');
  });
});

describe('Action required', () => {
  async function actions(): Promise<Action[]> {
    const { caseFile, assessment } = await loadFixtures();
    return planActions(caseFile, assessment, await fixtureGraph(), config);
  }

  it('lists each action with the patch and source notes from the UI design', async () => {
    const list = await actions();
    const { ui, out } = captureUi();
    const { caseFile, assessment } = await loadFixtures();
    presentActions(list, ui, { caseFile, assessment, config, researched: false });
    const text = out();
    assert.match(text, /Action required/);
    assert.match(text, /1\. minimist 1\.2\.5 -> 1\.2\.6 \[HIGH\]\n {3}Patch: version bump only, no breaking changes \(closes 1 CVE\)\n {3}Source changes: none required/);
    assert.match(text, /marked 0\.3\.6 -> 4\.0\.10 \[HIGH\]\n {3}Patch: major version \(closes 5 CVEs\)\n {3}Source changes: likely \(imported in source\); researched before approval/);
    assert.match(text, /decode-uri-component 0\.2\.0 -> 0\.5\.0 \[LOW\]\n {3}Patch: parent-scoped override in package\.json \(closes 2 CVEs\); query-string not tested with 0\.5\.0/);
  });

  it('describes a researched transaction by its brief and code changes', async () => {
    const marked = (await actions()).find((a) => a.package === 'marked') as Action;
    const withBrief: Action = {
      ...marked,
      brief: { package: 'marked', from: '0.3.6', to: '4.0.10', items: [], sources: [], queries: [], offline: false, model: 'm', createdAt: '' },
      codemod: { package: 'marked', model: 'm', patches: [{ file: 'src/render.js', edits: [], diff: '', beforeHash: '', newContent: '' }], rejected: [], manualChecklist: null },
    };
    withBrief.brief?.items.push({ change: 'Default export removed', appliesToProject: 'yes', evidenceQuote: 'q', evidenceUrl: 'u', oldApi: 'a', newApi: 'b', affectedFiles: ['src/render.js'], verified: true });
    const info = actionItemInfo(withBrief, 2);
    assert.equal(info.patchNote, 'Patch: major version, 1 breaking change detected (closes 5 CVEs)');
    assert.equal(info.sourceNote, 'Source changes: 1 file needs updates (src/render.js)');
    const unavailable = actionItemInfo({ ...marked, notes: ['Migration research unavailable: offline.'] }, 2);
    assert.equal(unavailable.sourceNote, 'Source changes: unknown (migration research unavailable)');
  });
});
