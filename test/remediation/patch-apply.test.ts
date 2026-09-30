import assert from 'node:assert/strict';
import { chmod, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { loadDependencyGraph } from '../../src/evidence/lockfile.ts';
import { makeRecord } from '../../src/remediation/approve.ts';
import {
  applyAction,
  checkPatchPreflight,
  createBackup,
  gitTreeDirty,
  planActions,
  rollbackLatest,
  type MigrationFns,
  type PatchContext,
} from '../../src/remediation/patch.ts';
import type { Action, CaseFile, Config, FilePatch } from '../../src/types.ts';
import { sha256 } from '../../src/util/fs.ts';
import { captureUi, fakeNpm, IDENTITY, loadFixtures, projectConfig, setNodeVersion, tempProject, type TempProject } from './patch-helpers.ts';

let project: TempProject;

beforeEach(async () => {
  project = await tempProject();
});

afterEach(async () => {
  await project.cleanup();
});

async function context(options: { runner: ReturnType<typeof fakeNpm>; migration?: Partial<MigrationFns>; tty?: boolean }): Promise<{ ctx: PatchContext; audit: MemoryAudit; config: Config; caseFile: CaseFile; out: () => string }> {
  const config = await projectConfig(project.dir, project.home, {}, options.tty ?? false);
  const { caseFile, assessment } = await loadFixtures();
  const graph = await loadDependencyGraph(project.dir, path.join(project.dir, 'package-lock.json'));
  const audit = new MemoryAudit();
  const { ui, all } = captureUi();
  const ctx: PatchContext = { ui, audit, provider: null, config, caseFile, graph, identity: IDENTITY, assessment, runCommand: options.runner, migration: options.migration };
  return { ctx, audit, config, caseFile, out: all };
}

async function planned(ctx: PatchContext, name: string): Promise<Action> {
  const action = planActions(ctx.caseFile, ctx.assessment as NonNullable<PatchContext['assessment']>, ctx.graph, ctx.config).find((a) => a.package === name);
  if (!action) throw new Error(`no action for ${name}`);
  return action;
}

const read = (file: string): Promise<string> => readFile(path.join(project.dir, file), 'utf8');

describe('backup and rollback', () => {
  it('round-trips package.json, the lockfile and a source file, verifying hashes first', async () => {
    const config = await projectConfig(project.dir, project.home);
    const audit = new MemoryAudit();
    const { ui, all } = captureUi();
    await chmod(path.join(project.dir, 'src/render.js'), 0o750);
    const originals = { pkg: await read('package.json'), lock: await read('package-lock.json'), src: await read('src/render.js') };
    const manifest = await createBackup(config, ['package.json', 'package-lock.json', 'src/render.js', 'missing.txt'], ['bump:lodash@4.18.1'], audit);
    assert.deepEqual(manifest.files.map((f) => f.path), ['package.json', 'package-lock.json', 'src/render.js'], 'missing files are skipped');
    assert.equal(manifest.files[0]?.sha256, sha256(originals.pkg));
    assert.equal(manifest.files[2]?.mode, 0o750);
    assert.deepEqual(audit.events('patch.backup').map((e) => e.files.length), [3]);

    await writeFile(path.join(project.dir, 'package.json'), '{"changed":true}\n');
    await writeFile(path.join(project.dir, 'package-lock.json'), '{}\n');
    await writeFile(path.join(project.dir, 'src/render.js'), '// edited\n');
    await chmod(path.join(project.dir, 'src/render.js'), 0o644);

    const result = await rollbackLatest(config, ui, audit);
    assert.equal(result.backupId, manifest.id);
    assert.deepEqual(result.restored.sort(), ['package-lock.json', 'package.json', 'src/render.js']);
    assert.deepEqual(result.mismatched, []);
    assert.deepEqual(result.missing, []);
    assert.match(result.note, /node_modules is not restored/);
    assert.equal(await read('package.json'), originals.pkg);
    assert.equal(await read('package-lock.json'), originals.lock);
    assert.equal(await read('src/render.js'), originals.src);
    assert.equal((await stat(path.join(project.dir, 'src/render.js'))).mode & 0o777, 0o750, 'file mode restored');
    assert.equal(audit.events('rollback').length, 1);
    assert.match(all(), /node_modules is not restored/);

    const again = await rollbackLatest(config, ui, audit);
    assert.deepEqual(again.restored, [], 'a second rollback has nothing to do');
  });

  it('refuses to restore a corrupted backup copy and says when there is no backup', async () => {
    const config = await projectConfig(project.dir, project.home);
    const { ui } = captureUi();
    await assert.rejects(rollbackLatest(config, ui, new MemoryAudit()), /No backup to restore/);
    const manifest = await createBackup(config, ['package.json'], ['x'], new MemoryAudit());
    await writeFile(path.join(manifest.dir, 'files', 'package.json'), 'tampered');
    await writeFile(path.join(project.dir, 'package.json'), '{}');
    const result = await rollbackLatest(config, ui, new MemoryAudit());
    assert.deepEqual(result.missing, ['package.json']);
    assert.equal(await read('package.json'), '{}', 'nothing written from a copy whose hash does not match');
  });
});

describe('applyAction', () => {
  it('bumps a direct dependency: npm args, diff guard, verify and audit events', async () => {
    const runner = fakeNpm();
    const { ctx, audit, out, config } = await context({ runner });
    const action = await planned(ctx, 'lodash');
    const result = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(result.ok, true, result.error);
    assert.equal(result.after, '4.18.1');
    assert.deepEqual(result.command, ['npm', 'install', 'lodash@4.18.1', '--package-lock-only', '--ignore-scripts', '--save-exact']);
    const npmCall = runner.calls.find((c) => c.cmd !== 'git');
    assert.equal(npmCall?.cwd, config.projectRoot);
    assert.equal(npmCall?.cmd, process.platform === 'win32' ? process.execPath : 'npm', 'no shell: npm itself (node + npm-cli.js on Windows)');
    assert.equal(JSON.parse(await read('package.json')).dependencies.lodash, '4.18.1', 'exact spec kept exact');
    assert.deepEqual(result.verify.map((v) => v.cleared), [true, true, true]);
    assert.deepEqual(result.filesChanged.map((f) => f.path), ['package.json', 'package-lock.json']);
    assert.deepEqual(audit.events('lockfile.diff').map((e) => [e.changed, e.decision]), [[1, 'clean']]);
    assert.equal(audit.events('verify.result').length, 3);
    const apply = audit.events('patch.apply')[0];
    assert.equal(apply?.ok, true);
    assert.equal(apply?.before, '4.17.20');
    assert.equal(apply?.files.length, 2);
    assert.equal(audit.events('patch.backup').length, 1, 'a standalone apply takes its own backup');
    assert.match(out(), /Bumped lodash to 4\.18\.1/);
    assert.match(out(), /Regenerated package-lock\.json/);
  });

  it('writes a parent-scoped override, runs npm install and accepts the re-nesting', async () => {
    const runner = fakeNpm({ renest: true });
    const { ctx } = await context({ runner });
    const action = await planned(ctx, 'decode-uri-component');
    const result = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(result.ok, true, result.error);
    assert.deepEqual(JSON.parse(await read('package.json')).overrides, { 'query-string': { 'decode-uri-component': '0.5.0' } });
    assert.deepEqual(result.lockfileDiff?.unexpected, []);
    assert.deepEqual(result.verify.map((v) => v.cleared), [true, true]);
    assert.deepEqual(result.command, ['npm', 'install', '--package-lock-only', '--ignore-scripts']);
  });

  it('rolls back when npm fails and reports npm error lines only', async () => {
    const runner = fakeNpm({ fail: 'npm notice something\nnpm error code ETARGET\nnpm error notarget No matching version found for lodash@4.18.1.\nnpm error A complete log of this run can be found in: /x.log\n' });
    const { ctx, audit } = await context({ runner });
    const before = { pkg: await read('package.json'), lock: await read('package-lock.json') };
    const action = await planned(ctx, 'lodash');
    const result = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(result.ok, false);
    assert.equal(result.rolledBack, true);
    assert.equal(result.error, 'npm exited with code 1: code ETARGET; notarget No matching version found for lodash@4.18.1.');
    assert.equal(await read('package.json'), before.pkg);
    assert.equal(await read('package-lock.json'), before.lock);
    assert.equal(audit.events('rollback').length, 1);
    assert.equal(audit.events('patch.apply')[0]?.ok, false);
  });

  it('aborts and rolls back unexpected lockfile changes without a TTY', async () => {
    const runner = fakeNpm({ extra: (lock) => setNodeVersion(lock, 'node_modules/filter-obj', '9.9.9') });
    const { ctx, audit } = await context({ runner });
    const before = await read('package-lock.json');
    const action = await planned(ctx, 'minimist');
    const result = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(result.ok, false);
    assert.equal(result.rolledBack, true);
    assert.match(result.error ?? '', /unexpected lockfile changes \(node_modules\/filter-obj\) need a confirmation in a terminal/);
    assert.deepEqual(audit.events('lockfile.diff').map((e) => [e.unexpected, e.decision]), [[['node_modules/filter-obj'], 'aborted']]);
    assert.equal(await read('package-lock.json'), before);
  });

  it('keeps confirmed unexpected changes on a TTY', async () => {
    const runner = fakeNpm({ extra: (lock) => setNodeVersion(lock, 'node_modules/filter-obj', '9.9.9') });
    const { ctx, audit } = await context({ runner, tty: true });
    const { fakePrompt } = await import('./patch-helpers.ts');
    ctx.prompt = fakePrompt(['y']);
    const action = await planned(ctx, 'minimist');
    const result = await applyAction(action, makeRecord(action, 'approve', 'interactive', IDENTITY), ctx);
    assert.equal(result.ok, true, result.error);
    assert.deepEqual(audit.events('lockfile.diff').map((e) => e.decision), ['confirmed']);
  });

  it('applies a transaction: lockfile change, code edits and node --check, with the whole transaction rolled back on failure', async () => {
    const renderPath = path.join(project.dir, 'src/render.js');
    const original = await readFile(renderPath, 'utf8');
    const edited = original.replace("const marked = require('marked')", "const { marked } = require('marked')");
    assert.notEqual(edited, original, 'fixture uses the default export');
    const patch: FilePatch = {
      file: 'src/render.js',
      edits: [{ file: 'src/render.js', search: "const marked = require('marked')", replace: "const { marked } = require('marked')", why: 'v4 removed the default export' }],
      diff: "--- a/src/render.js\n+++ b/src/render.js\n@@ -1 +1 @@\n-const marked = require('marked')\n+const { marked } = require('marked')\n",
      beforeHash: sha256(original),
      newContent: edited,
    };
    const writePatches: MigrationFns['writePatches'] = async (patches, root) => {
      const out = [];
      for (const p of patches) {
        const file = path.join(root, p.file);
        const before = await readFile(file, 'utf8');
        await writeFile(file, p.newContent);
        out.push({ file: p.file, beforeHash: sha256(before), afterHash: sha256(p.newContent) });
      }
      return out;
    };
    const withCodemod = (a: Action): Action => ({ ...a, codemod: { package: 'marked', model: 'fake', patches: [patch], rejected: [], manualChecklist: null } });

    let syntaxOk = true;
    const migration: Partial<MigrationFns> = { writePatches, checkSyntax: async (files) => files.map((file) => ({ file, ok: syntaxOk, ...(syntaxOk ? {} : { error: 'SyntaxError: Unexpected token' }) })) };
    const { ctx, audit } = await context({ runner: fakeNpm(), migration });
    const action = withCodemod(await planned(ctx, 'marked'));
    const approval = makeRecord(action, 'approve', 'flag', IDENTITY, { scope: 'transaction', files: [{ file: 'src/render.js', approved: true }] });
    const ok = await applyAction(action, approval, ctx);
    assert.equal(ok.ok, true, ok.error);
    assert.equal(await readFile(renderPath, 'utf8'), edited);
    assert.deepEqual(ok.filesChanged.map((f) => f.path), ['package.json', 'package-lock.json', 'src/render.js']);
    assert.deepEqual(audit.events('codemod.applied').map((e) => [e.file, e.syntaxOk]), [['src/render.js', true]]);
    assert.equal(JSON.parse(await read('package.json')).dependencies.marked, '4.0.10');

    // node --check fails, all rolls back
    await project.cleanup();
    project = await tempProject();
    syntaxOk = false;
    const second = await context({ runner: fakeNpm(), migration });
    const before = { pkg: await read('package.json'), lock: await read('package-lock.json'), src: await readFile(path.join(project.dir, 'src/render.js'), 'utf8') };
    const failing = withCodemod(await planned(second.ctx, 'marked'));
    const failed = await applyAction(failing, approval, second.ctx);
    assert.equal(failed.ok, false);
    assert.equal(failed.rolledBack, true);
    assert.match(failed.error ?? '', /node --check failed for src\/render\.js: SyntaxError/);
    assert.equal(await read('package.json'), before.pkg);
    assert.equal(await read('package-lock.json'), before.lock);
    assert.equal(await readFile(path.join(project.dir, 'src/render.js'), 'utf8'), before.src);
  });

  it('refuses code edits when the file changed after the diff was shown', async () => {
    const renderPath = path.join(project.dir, 'src/render.js');
    const patch: FilePatch = { file: 'src/render.js', edits: [], diff: '', beforeHash: 'not-the-current-hash', newContent: '// new' };
    const { ctx } = await context({ runner: fakeNpm(), migration: { writePatches: async () => assert.fail('must not write'), checkSyntax: async () => [] } });
    const action: Action = { ...(await planned(ctx, 'marked')), codemod: { package: 'marked', model: 'fake', patches: [patch], rejected: [], manualChecklist: null } };
    const result = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY, { scope: 'transaction', files: [{ file: 'src/render.js', approved: true }] }), ctx);
    assert.equal(result.ok, false);
    assert.match(result.error ?? '', /changed after the diff was shown/);
    assert.notEqual(await readFile(renderPath, 'utf8'), '// new');
  });

  it('does nothing for a rejected approval', async () => {
    const runner = fakeNpm();
    const { ctx } = await context({ runner });
    const action = await planned(ctx, 'lodash');
    const result = await applyAction(action, makeRecord(action, 'reject', 'interactive', IDENTITY), ctx);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'not approved');
    assert.equal(runner.calls.length, 0);
  });
});

describe('checkPatchPreflight', () => {
  it('refuses package-lock=false and flags lockfile v1, workspaces and unusual specs', async () => {
    const config = await projectConfig(project.dir, project.home);
    const graph = await loadDependencyGraph(project.dir, path.join(project.dir, 'package-lock.json'));
    const clean = await checkPatchPreflight(config, graph, fakeNpm());
    assert.equal(clean.refuse, null);
    assert.equal(clean.dirtyTree, null, 'not a git repository');
    assert.deepEqual(clean.unusualSpecs, []);
    assert.equal(clean.workspaces, false);

    await writeFile(path.join(project.dir, '.npmrc'), '# local\nsave-exact=true\npackage-lock = false\n');
    const refused = await checkPatchPreflight(config, { ...graph, lockfileVersion: 1, root: { ...graph.root, workspaces: ['packages/*'], dependencies: { ...graph.root.dependencies, lodash: 'latest' } } }, fakeNpm());
    assert.match(refused.refuse ?? '', /package-lock=false/);
    assert.equal(refused.lockfileVersion, 1);
    assert.equal(refused.workspaces, true);
    assert.deepEqual(refused.unusualSpecs, [{ name: 'lodash', spec: 'latest' }]);
    assert.equal(refused.warnings.length, 2);
  });

  it('reports a dirty git tree but ignores PatchPilot state', async () => {
    const clean = fakeNpm({ git: { ok: true, code: 0, stdout: '?? .patch-pilot/audit.jsonl\n?? examples/app/.patch-pilot/report.md\n' } });
    assert.equal(await gitTreeDirty(project.dir, clean), false);
    const dirty = fakeNpm({ git: { ok: true, code: 0, stdout: ' M src/cli.js\n?? .patch-pilot/audit.jsonl\n' } });
    assert.equal(await gitTreeDirty(project.dir, dirty), true);
  });
});
