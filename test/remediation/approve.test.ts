import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { acceptRisk, approveMatches, canPrompt, nonInteractiveApprovals, runApprovalGate, type ApprovalContext } from '../../src/remediation/approve.ts';
import { planActions } from '../../src/remediation/patch.ts';
import type { Action, ApprovalRecord, Config, FilePatch, MigrationBrief } from '../../src/types.ts';
import { captureUi, fakePrompt, fixtureGraph, IDENTITY, loadFixtures, projectConfig } from './patch-helpers.ts';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'pp-approve-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function fixtureActions(config: Config): Promise<Action[]> {
  const { caseFile, assessment } = await loadFixtures();
  return planActions(caseFile, assessment, await fixtureGraph(), config);
}

const PATCH: FilePatch = {
  file: 'src/render.js',
  edits: [{ file: 'src/render.js', search: "const marked = require('marked');", replace: "const { marked } = require('marked');", why: 'default export removed in v4' }],
  diff: "--- a/src/render.js\n+++ b/src/render.js\n@@ -1,1 +1,1 @@\n-const marked = require('marked');\n+const { marked } = require('marked');\n",
  beforeHash: 'abc',
  newContent: "const { marked } = require('marked');\n",
};

const BRIEF: MigrationBrief = {
  package: 'marked',
  from: '0.3.6',
  to: '4.0.10',
  items: [
    {
      change: 'Default export removed',
      appliesToProject: 'yes',
      evidenceQuote: 'Default export removed.',
      evidenceUrl: 'https://github.com/markedjs/marked/releases/tag/v4.0.0',
      oldApi: "const marked = require('marked')",
      newApi: "const { marked } = require('marked')",
      affectedFiles: ['src/render.js'],
      verified: true,
    },
  ],
  sources: [],
  queries: [],
  offline: false,
  model: 'mistral:7b',
  createdAt: '2026-09-24T00:00:00Z',
};

function withTransaction(actions: Action[], patches: FilePatch[] = [PATCH]): Action[] {
  return actions.map((a) =>
    a.requiresMigration ? { ...a, brief: BRIEF, codemod: { package: a.package, model: 'mistral:7b', patches, rejected: [], manualChecklist: patches.length ? null : ['Replace the default export'] } } : a,
  );
}

function ctxFor(config: Config, prompt?: ReturnType<typeof fakePrompt>): { ctx: ApprovalContext; audit: MemoryAudit; out: () => string; decided: ApprovalRecord[] } {
  const audit = new MemoryAudit();
  const { ui, all } = captureUi({ interactive: config.interactive });
  const decided: ApprovalRecord[] = [];
  const ctx: ApprovalContext = {
    config,
    ui,
    audit,
    identity: IDENTITY,
    prompt,
    migration: { renderBrief: () => 'BRIEF RENDERED' },
    onDecision: async (_action, record) => {
      decided.push(record);
    },
  };
  return { ctx, audit, out: all, decided };
}

describe('non-interactive approvals', () => {
  it('without a TTY and without flags nothing is approved', async () => {
    const config = await projectConfig(dir, dir);
    const actions = withTransaction(await fixtureActions(config));
    const records = nonInteractiveApprovals(actions, config, IDENTITY);
    assert.ok(records.every((r) => r.decision === 'reject' && r.mode === 'non-interactive'));
    assert.match(records[0]?.reason ?? '', /no interactive terminal/);
  });

  it('--approve-all covers version bumps only; code edits need --approve-codemods', async () => {
    const config = await projectConfig(dir, dir, { approveAll: true });
    const actions = withTransaction(await fixtureActions(config));
    const records = nonInteractiveApprovals(actions, config, IDENTITY);
    const byPkg = new Map(records.map((r) => [r.package, r]));
    assert.equal(byPkg.get('marked')?.decision, 'reject');
    assert.match(byPkg.get('marked')?.reason ?? '', /--approve-codemods/);
    for (const name of ['minimist', 'lodash', 'json5', 'semver', 'decode-uri-component']) {
      assert.equal(byPkg.get(name)?.decision, 'approve', name);
      assert.equal(byPkg.get(name)?.mode, 'flag');
      assert.equal(byPkg.get(name)?.scope, 'bump');
    }
    const both = await projectConfig(dir, dir, { approveAll: true, approveCodemods: true });
    const marked = nonInteractiveApprovals(actions, both, IDENTITY).find((r) => r.package === 'marked');
    assert.equal(marked?.decision, 'approve');
    assert.equal(marked?.scope, 'transaction');
    assert.deepEqual(marked?.files, [{ file: 'src/render.js', approved: true }]);
  });

  it('never approves a major bump whose code edits are unknown, even with --approve-codemods', async () => {
    const config = await projectConfig(dir, dir, { approveAll: true, approveCodemods: true });
    const actions = withTransaction(await fixtureActions(config), []);
    const marked = nonInteractiveApprovals(actions, config, IDENTITY).find((r) => r.package === 'marked');
    assert.equal(marked?.decision, 'reject');
    assert.match(marked?.reason ?? '', /no validated code edits/);
  });

  it('--approve picks packages (name, name@version or action id)', async () => {
    const config = await projectConfig(dir, dir, { approve: 'lodash,minimist@1.2.5' });
    const actions = await fixtureActions(config);
    const approved = nonInteractiveApprovals(actions, config, IDENTITY).filter((r) => r.decision === 'approve').map((r) => r.package);
    assert.deepEqual(approved.sort(), ['lodash', 'minimist']);
    assert.equal(approveMatches(['bump:json5@2.2.2'], actions.find((a) => a.package === 'json5') as Action), true);
  });

  it('the gate logs every flag decision with identity and hands approvals on', async () => {
    const config = await projectConfig(dir, dir, { approve: 'lodash,nope' });
    const actions = await fixtureActions(config);
    const { ctx, audit, out, decided } = ctxFor(config);
    const records = await runApprovalGate(actions, ctx);
    assert.equal(records.length, actions.length);
    assert.equal(decided.length, actions.length);
    const events = audit.events('approval');
    assert.equal(events.length, actions.length);
    assert.deepEqual(events.find((e) => e.package === 'lodash')?.by, IDENTITY);
    assert.equal(events.find((e) => e.package === 'lodash')?.decision, 'approve');
    assert.equal(events.find((e) => e.package === 'lodash')?.kind, 'bump');
    assert.match(out(), /--approve nope: no planned action for that package/);
  });
});

describe('interactive gate', () => {
  it('y approves, n rejects, d shows details and asks again, q rejects all remaining', async () => {
    const config = await projectConfig(dir, dir, {}, true);
    assert.equal(canPrompt(config, captureUi().ui, fakePrompt([])), true);
    const actions = (await fixtureActions(config)).filter((a) => !a.requiresMigration);
    const prompt = fakePrompt(['d', 'y', 'n', 'q']);
    const { ctx, out, decided } = ctxFor(config, prompt);
    const { caseFile, assessment } = await loadFixtures();
    ctx.caseFile = caseFile;
    ctx.assessment = assessment;
    const records = await runApprovalGate(actions, ctx);
    assert.deepEqual(
      records.map((r) => [r.package, r.decision, r.reason ?? null]),
      [
        [actions[0]?.package, 'approve', null],
        [actions[1]?.package, 'reject', null],
        [actions[2]?.package, 'reject', 'reject all remaining'],
        ...actions.slice(3).map((a) => [a.package, 'reject', 'reject all remaining']),
      ],
    );
    assert.equal(prompt.asked[0], `Apply patch for ${actions[0]?.package}@${actions[0]?.toVersion}? (y/n/d/a/q)`);
    assert.match(out(), /Command\s+npm install minimist@1\.2\.6 --package-lock-only --ignore-scripts --save-exact/);
    assert.match(out(), /Required by\s+json5@2\.2\.0 \^1\.2\.5 \(accepts 1\.2\.6\)/);
    assert.equal(decided.length, actions.length);
    assert.ok(records.every((r) => r.mode === 'interactive' && r.by === IDENTITY));
  });

  it('a transaction shows the brief and the diffs, then asks "Apply these changes? (y/n)"', async () => {
    const config = await projectConfig(dir, dir, {}, true);
    const actions = withTransaction(await fixtureActions(config)).filter((a) => a.package === 'marked');
    const prompt = fakePrompt(['y', 'y']);
    const { ctx, out } = ctxFor(config, prompt);
    const [record] = await runApprovalGate(actions, ctx);
    assert.deepEqual(prompt.asked, ['Apply patch for marked@4.0.10? (y/n/d/a/q)', 'Apply these changes? (y/n)']);
    assert.equal(record?.decision, 'approve');
    assert.equal(record?.scope, 'transaction');
    assert.deepEqual(record?.files, [{ file: 'src/render.js', approved: true }]);
    assert.match(out(), /BRIEF RENDERED/);
    assert.match(out(), /- const marked = require\('marked'\);/);
    assert.match(out(), /\+ const \{ marked \} = require\('marked'\);/);

    const reject = fakePrompt(['d', 'n']);
    const second = ctxFor(config, reject);
    const [rejected] = await runApprovalGate(actions, second.ctx);
    assert.equal(rejected?.decision, 'reject');
    assert.deepEqual(rejected?.files, [{ file: 'src/render.js', approved: false }], 'rejecting the diff rejects the transaction');
  });

  it('without validated edits the gate shows the checklist and asks whether to bump anyway', async () => {
    const config = await projectConfig(dir, dir, {}, true);
    const actions = withTransaction(await fixtureActions(config), []).filter((a) => a.package === 'marked');
    const prompt = fakePrompt(['y', 'y']);
    const { ctx, out } = ctxFor(config, prompt);
    const [record] = await runApprovalGate(actions, ctx);
    assert.equal(prompt.asked[1], 'Bump marked to 4.0.10 without code changes? (y/n)');
    assert.equal(record?.decision, 'approve');
    assert.equal(record?.scope, 'bump');
    assert.match(record?.reason ?? '', /without code changes/);
    assert.match(out(), /Manual migration checklist/);
  });

  it('a accepts the risk with a reason and expiry, written to patch-pilot.config.json and the audit', async () => {
    const config = await projectConfig(dir, dir, {}, true);
    const actions = (await fixtureActions(config)).filter((a) => a.package === 'semver');
    const prompt = fakePrompt(['a', 'dev-only build script with a fixed range', '2026-12-31']);
    const { ctx, audit } = ctxFor(config, prompt);
    const [record] = await runApprovalGate(actions, ctx);
    assert.equal(record?.decision, 'accept-risk');
    assert.equal(record?.reason, 'dev-only build script with a fixed range');
    assert.equal(record?.until, '2026-12-31');
    const file = JSON.parse(await readFile(path.join(config.projectRoot, 'patch-pilot.config.json'), 'utf8')) as { ignore: { id: string; package: string; until: string; by: string }[] };
    assert.deepEqual(file.ignore.map((e) => [e.id, e.package, e.until, e.by]), [['GHSA-c2qf-rxjj-qqgw', 'semver', '2026-12-31', 'Test User <test@example.com>']]);
    const accepted = audit.events('risk.accepted');
    assert.deepEqual(accepted.map((e) => [e.vulnId, e.source, e.until]), [['GHSA-c2qf-rxjj-qqgw', 'gate', '2026-12-31']]);
    assert.equal(audit.events('approval')[0]?.decision, 'accept-risk');
    assert.equal(config.ignore.length, 1, 'the run sees the new accepted risk');
  });

  it('acceptRisk validates the reason and the date', async () => {
    const config = await projectConfig(dir, dir);
    const action = (await fixtureActions(config))[0] as Action;
    const { ctx } = ctxFor(config);
    await assert.rejects(acceptRisk(action, '  ', undefined, ctx), /needs a reason/);
    await assert.rejects(acceptRisk(action, 'ok', '31/12/2026', ctx), /Invalid expiry date/);
  });
});
