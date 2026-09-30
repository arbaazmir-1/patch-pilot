import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { runPhase3, type MigrationFns } from '../../src/remediation/patch.ts';
import type { CliFlags } from '../../src/config.ts';
import type { MigrationBrief } from '../../src/types.ts';
import { sha256 } from '../../src/util/fs.ts';
import { EXIT } from '../../src/util/errors.ts';
import { captureUi, fakeNpm, fakePrompt, IDENTITY, loadFixtures, projectConfig, setNodeVersion, tempProject, type TempProject } from './patch-helpers.ts';

let project: TempProject;

beforeEach(async () => {
  project = await tempProject();
});

afterEach(async () => {
  await project.cleanup();
});

// v4 default-export change
function fakeMigration(calls: string[]): Partial<MigrationFns> {
  return {
    researchMigration: async (action) => {
      calls.push(`research ${action.package}`);
      const brief: MigrationBrief = {
        package: action.package,
        from: action.fromVersion,
        to: action.toVersion,
        items: [],
        sources: [],
        queries: [],
        offline: true,
        model: 'fake',
        createdAt: new Date().toISOString(),
      };
      return brief;
    },
    proposeCodemod: async (brief) => {
      calls.push(`codemod ${brief.package}`);
      const file = path.join(project.dir, 'src/render.js');
      const before = await readFile(file, 'utf8');
      const after = before.replace("require('marked')", "require('marked').marked");
      return {
        package: brief.package,
        model: 'fake',
        patches: [{ file: 'src/render.js', edits: [], diff: '--- a/src/render.js\n+++ b/src/render.js\n@@ -1 +1 @@\n-old\n+new\n', beforeHash: sha256(before), newContent: after }],
        rejected: [],
        manualChecklist: null,
      };
    },
    renderBrief: () => 'fake brief',
    writePatches: async (patches, root) => {
      const { writeFile } = await import('node:fs/promises');
      const out = [];
      for (const p of patches) {
        const file = path.join(root, p.file);
        const before = await readFile(file, 'utf8');
        await writeFile(file, p.newContent);
        out.push({ file: p.file, beforeHash: sha256(before), afterHash: sha256(p.newContent) });
      }
      return out;
    },
    checkSyntax: async (files) => files.map((file) => ({ file, ok: true })),
  };
}

async function run(flags: CliFlags, options: { tty?: boolean; answers?: string[]; npm?: Parameters<typeof fakeNpm>[0] } = {}) {
  const config = await projectConfig(project.dir, project.home, flags, options.tty ?? false);
  const { caseFile, assessment } = await loadFixtures();
  const audit = new MemoryAudit();
  const { ui, all } = captureUi({ interactive: config.interactive });
  const runner = fakeNpm(options.npm ?? {});
  const calls: string[] = [];
  const prompt = options.answers ? fakePrompt(options.answers) : undefined;
  const result = await runPhase3(caseFile, assessment, config, {
    ui,
    audit,
    provider: { name: 'mock', model: 'mock', chat: async () => assert.fail('no chat'), checkModel: async () => assert.fail('no check') },
    identity: IDENTITY,
    db: null,
    showCards: false,
    prompt,
    runCommand: runner,
    migration: fakeMigration(calls),
  });
  return { result, audit, out: all, runner, calls, config, prompt };
}

describe('runPhase3', () => {
  it('--approve-all applies every bump, holds the transaction back, backs up once and writes the reports', async () => {
    const { result, audit, out, calls, config } = await run({ approveAll: true });
    assert.equal(result.exitCode, EXIT.OK);
    assert.equal(result.actions.length, 6);
    assert.deepEqual(calls, ['research marked', 'codemod marked'], 'migration research runs before the gate');
    const applied = result.results.filter((r) => r.ok).map((r) => r.actionId).sort();
    assert.deepEqual(applied, ['bump:json5@2.2.2', 'bump:lodash@4.18.1', 'bump:minimist@1.2.6', 'bump:semver@5.7.2', 'override-transitive:decode-uri-component@0.5.0']);
    assert.equal(result.approvals.find((a) => a.package === 'marked')?.decision, 'reject');
    const pkg = JSON.parse(await readFile(path.join(project.dir, 'package.json'), 'utf8'));
    assert.deepEqual(pkg.dependencies, { json5: '2.2.2', lodash: '4.18.1', marked: '0.3.6', minimist: '1.2.6', 'query-string': '6.14.1' });
    assert.equal(pkg.devDependencies.semver, '5.7.2');
    assert.equal(audit.events('patch.backup').length, 1, 'one backup for the whole run');
    const backups = await readdir(config.paths.backupDir);
    assert.equal(backups.length, 1);
    const manifest = JSON.parse(await readFile(path.join(config.paths.backupDir, backups[0] as string, 'manifest.json'), 'utf8'));
    assert.deepEqual(manifest.files.map((f: { path: string }) => f.path), ['package.json', 'package-lock.json', 'src/render.js']);
    assert.equal(manifest.actionIds.length, 5);
    assert.ok(manifest.after['package.json'], 'post-run hashes recorded for rollback');
    assert.ok(result.reports);
    const reportJson = JSON.parse(await readFile(config.paths.reportJson, 'utf8'));
    assert.equal(reportJson.summary.applied, 5);
    assert.equal(reportJson.summary.cleared, 8);
    assert.match(out(), /Done\. 5 patches applied, 0 source files updated, 5 deferred\./);
    assert.match(out(), /Full report: \.patch-pilot\/report\.md/);
    assert.match(out(), /node_modules still holds the old versions/);
  });

  it('interactive: approves the transaction after the diff, applies it right away and offers npm install then npm test', async () => {
    const answers = [
      'y',
      'n', // marked: first question
    ];
    const first = await run({}, { tty: true, answers: [...answers, 'q', 'n'] });
    assert.deepEqual(first.result.results.map((r) => r.actionId), ['bump:minimist@1.2.6']);
    assert.equal(first.prompt?.asked[0], 'Apply patch for minimist@1.2.6? (y/n/d/a/q)');
    assert.equal(first.prompt?.asked[1], 'Apply patch for marked@4.0.10? (y/n/d/a/q)');
    assert.equal(first.prompt?.asked[3], 'Sync node_modules now with npm install --ignore-scripts?', 'offered once after the actions');
    assert.equal(first.prompt?.asked.length, 4);
    assert.match(first.out(), /sync it later with: npm install --ignore-scripts/);

    await project.cleanup();
    project = await tempProject();
    const second = await run({}, { tty: true, answers: ['n', 'y', 'y', 'q', 'y', 'y'] });
    assert.deepEqual(second.result.results.map((r) => [r.actionId, r.ok]), [['bump-major:marked@4.0.10', true]]);
    const record = second.result.approvals.find((a) => a.package === 'marked');
    assert.equal(record?.scope, 'transaction');
    assert.match(await readFile(path.join(project.dir, 'src/render.js'), 'utf8'), /require\('marked'\)\.marked/);
    assert.ok(second.prompt?.asked.includes('Apply these changes? (y/n)'));
    const npmCalls = second.runner.calls.filter((c) => c.cmd !== 'git').map((c) => c.args.join(' '));
    assert.deepEqual(npmCalls, ['install marked@4.0.10 --package-lock-only --ignore-scripts --save-exact', 'install --ignore-scripts', 'test --ignore-scripts']);
    const post = second.audit.events('approval').filter((e) => e.actionId.startsWith('post:')).map((e) => [e.actionId, e.decision]);
    assert.deepEqual(post, [['post:npm-install', 'approve'], ['post:npm-test', 'approve']]);
    assert.match(second.out(), /Done\. 1 patch applied, 1 source file updated/);
  });

  it('a failed action is rolled back on its own and the exit code is 4', async () => {
    const { result } = await run({ approve: 'lodash,minimist' }, { npm: { extra: (lock) => setNodeVersion(lock, 'node_modules/filter-obj', '9.9.9') } });
    assert.equal(result.exitCode, EXIT.PATCH_FAILED);
    assert.ok(result.results.every((r) => !r.ok && r.rolledBack));
    const pkg = JSON.parse(await readFile(path.join(project.dir, 'package.json'), 'utf8'));
    assert.equal(pkg.dependencies.lodash, '4.17.20');
  });

  it('--dry-run and --ci present and plan but change nothing', async () => {
    for (const flags of [{ dryRun: true, approveAll: true }, { ci: true, approveAll: true }] as CliFlags[]) {
      const { result, runner, calls, out, config } = await run(flags);
      assert.equal(result.results.length, 0);
      assert.equal(result.approvals.length, 0);
      assert.equal(result.actions.length, 6);
      assert.deepEqual(calls, [], 'no migration research');
      assert.equal(runner.calls.length, 0, 'no npm, no git');
      assert.ok(result.reports, 'reports are still written');
      assert.match(out(), flags.ci ? /CI mode: nothing was changed/ : /Dry run: nothing was changed/);
      assert.ok(JSON.parse(await readFile(config.paths.reportJson, 'utf8')).findings.length > 0);
    }
  });

  it('without a TTY and without approval flags nothing is applied', async () => {
    const { result, runner, out } = await run({});
    assert.equal(result.results.length, 0);
    assert.ok(result.approvals.every((a) => a.decision === 'reject' && a.mode === 'non-interactive'));
    assert.equal(runner.calls.filter((c) => c.cmd !== 'git').length, 0);
    assert.match(out(), /No interactive terminal: nothing is applied/);
  });
});
