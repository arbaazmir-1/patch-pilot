// yarn/pnpm apply, fake manager, real lockfiles
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile, rm, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { loadDependencyGraph } from '../../src/evidence/lockfile.ts';
import { makeRecord } from '../../src/remediation/approve.ts';
import { applyAction, offerPostCommands, planActions, rollbackLatest, runPhase3, yarnModulesFolder, type CommandRunner, type PatchContext } from '../../src/remediation/patch.ts';
import type { Action, CaseFile, Config, DependencyGraph, PackageJson } from '../../src/types.ts';
import { EXIT } from '../../src/util/errors.ts';
import type { RunResult } from '../../src/util/proc.ts';
import { captureUi, fakePrompt, IDENTITY, loadFixtures, projectConfig, tempProject, type TempProject } from './patch-helpers.ts';

const LOCKFILES = new URL('../evidence/fixtures/lockfiles/', import.meta.url);
const fixture = (...parts: string[]): Promise<string> => readFile(new URL(parts.join('/'), LOCKFILES), 'utf8');

type Manager = 'yarn' | 'yarn-berry' | 'pnpm';
const LOCK_NAME: Record<Manager, string> = { yarn: 'yarn.lock', 'yarn-berry': 'yarn.lock', pnpm: 'pnpm-lock.yaml' };
const SOURCE: Record<Manager, string[]> = { yarn: ['vulnerable-app', 'yarn.lock'], 'yarn-berry': ['vulnerable-app', 'berry', 'yarn.lock'], pnpm: ['vulnerable-app', 'pnpm-lock.yaml'] };

let project: TempProject | null = null;

afterEach(async () => {
  await project?.cleanup();
  project = null;
});

// vulnerable-app with a yarn or pnpm lock
async function pmProject(manager: Manager): Promise<TempProject> {
  project = await tempProject();
  await unlink(path.join(project.dir, 'package-lock.json'));
  await writeFile(path.join(project.dir, LOCK_NAME[manager]), await fixture(...SOURCE[manager]));
  return project;
}

// case file rekeyed to that graph
function caseFileFor(caseFile: CaseFile, graph: DependencyGraph, lockfile: string): CaseFile {
  return {
    ...caseFile,
    project: { ...caseFile.project, lockfile, lockfileVersion: graph.lockfileVersion },
    packages: caseFile.packages.map((p) => ({ ...p, keys: (graph.byName.get(p.name) ?? []).filter((k) => graph.nodes.get(k)?.version === p.version) })),
  };
}

interface Step {
  // --modules-folder path as <modules>
  args: string[];
  // after/ fixture becomes the lockfile
  lock?: string;
  pkg?: (pkg: PackageJson) => PackageJson;
  check?: (state: { lock: string; pkg: PackageJson; dir: string }) => void | Promise<void>;
  fail?: string;
}

type FakeRunner = CommandRunner & { calls: string[]; commands: string[][] };

function result(partial: Partial<RunResult>): RunResult {
  return { ok: true, code: 0, signal: null, stdout: '', stderr: '', error: null, durationMs: 1, ...partial };
}

// fake pm, scripted steps
function fakeManager(manager: Manager, versions: Record<string, string>, steps: Step[]): FakeRunner {
  const calls: string[] = [];
  const commands: string[][] = [];
  const queue = [...steps];
  const fn = async (cmd: string, args: readonly string[], options: { cwd?: string } = {}): Promise<RunResult> => {
    const base = path.basename(cmd);
    calls.push([base, ...args].join(' '));
    if (base === 'git') return result({ ok: false, code: 128, stderr: 'fatal: not a git repository' });
    if (args[args.length - 1] === '--version') {
      const version = versions[[base, ...args.slice(0, -1)].join(' ')];
      return version ? result({ stdout: `${version}\n` }) : result({ ok: false, code: null, error: Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }) });
    }
    const dir = options.cwd as string;
    const own = base === 'corepack' ? args.slice(1) : [...args];
    const modules = own.indexOf('--modules-folder');
    const shown = modules === -1 ? own : own.map((a, i) => (i === modules + 1 ? '<modules>' : a));
    commands.push(shown);
    const step = queue[0];
    if (!step || JSON.stringify(step.args) !== JSON.stringify(shown)) return result({ ok: false, code: 1, stderr: `error unexpected command: ${shown.join(' ')}` });
    queue.shift();
    const lockFile = path.join(dir, LOCK_NAME[manager]);
    const pkgFile = path.join(dir, 'package.json');
    const pkg = JSON.parse(await readFile(pkgFile, 'utf8')) as PackageJson;
    await step.check?.({ lock: await readFile(lockFile, 'utf8'), pkg, dir });
    if (step.fail) return result({ ok: false, code: 1, stderr: step.fail });
    if (step.lock) await writeFile(lockFile, await fixture('after', step.lock));
    if (step.pkg) await writeFile(pkgFile, `${JSON.stringify(step.pkg(pkg), null, 2)}\n`);
    return result({ stdout: 'Done\n' });
  };
  return Object.assign(fn, { calls, commands });
}

const setDep = (name: string, spec: string) => (pkg: PackageJson): PackageJson => ({ ...pkg, dependencies: { ...pkg.dependencies, [name]: spec } });

async function context(manager: Manager, runner: FakeRunner, options: { ignoreVcc3?: boolean; tty?: boolean } = {}): Promise<{ ctx: PatchContext; audit: MemoryAudit; config: Config; out: () => string; plan: (name: string) => Action }> {
  const p = project as TempProject;
  const config = await projectConfig(p.dir, p.home, {}, options.tty ?? false);
  if (options.ignoreVcc3) config.ignore = [{ id: 'GHSA-vcc3-ghjq-m6fr', reason: 'x', by: 'x', createdAt: '' }];
  const fixtures = await loadFixtures();
  const graph = await loadDependencyGraph(p.dir, path.join(p.dir, LOCK_NAME[manager]));
  const caseFile = caseFileFor(fixtures.caseFile, graph, LOCK_NAME[manager]);
  const audit = new MemoryAudit();
  const { ui, all } = captureUi();
  const ctx: PatchContext = { ui, audit, provider: null, config, caseFile, graph, identity: IDENTITY, assessment: fixtures.assessment, runCommand: runner };
  const actions = planActions(caseFile, fixtures.assessment, graph, config);
  const plan = (name: string): Action => {
    const action = actions.find((a) => a.package === name);
    if (!action) throw new Error(`no action for ${name}`);
    return action;
  };
  return { ctx, audit, config, out: all, plan };
}

const read = (file: string): Promise<string> => readFile(path.join((project as TempProject).dir, file), 'utf8');

describe('applyAction with yarn and pnpm', () => {
  it('pnpm: add keeps the section, the diff guard sees only lodash, the CVEs are cleared', async () => {
    await pmProject('pnpm');
    const runner = fakeManager('pnpm', { pnpm: '11.9.0' }, [{ args: ['add', 'lodash@4.18.1', '--lockfile-only', '--ignore-scripts'], lock: 'pnpm-bump-lodash.yaml', pkg: setDep('lodash', '4.18.1') }]);
    const { ctx, audit, out, plan } = await context('pnpm', runner);
    const action = plan('lodash');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(res.ok, true, res.error);
    assert.deepEqual(res.command, ['pnpm', 'add', 'lodash@4.18.1', '--lockfile-only', '--ignore-scripts']);
    assert.deepEqual(res.lockfileDiff?.unexpected, []);
    assert.deepEqual(res.verify.map((v) => v.cleared), [true, true, true]);
    assert.deepEqual(res.filesChanged.map((f) => f.path), ['package.json', 'pnpm-lock.yaml']);
    assert.deepEqual(audit.events('lockfile.diff').map((e) => [e.added, e.removed, e.decision]), [[1, 1, 'clean']]);
    assert.deepEqual(runner.calls.filter((c) => c.endsWith('--version')), ['pnpm --version'], 'probed once, in the project');
    assert.match(out(), /Regenerated pnpm-lock\.yaml/);
  });

  it('yarn 1 through corepack: upgrade, then the in-range refresh for the copy json5 keeps', async () => {
    const p = await pmProject('yarn');
    const runner = fakeManager('yarn', { 'corepack yarn@1': '1.22.22' }, [
      { args: ['upgrade', 'minimist@1.2.6', '--ignore-scripts', '--non-interactive', '--modules-folder', '<modules>'], lock: 'yarn1-bump-minimist.lock', pkg: setDep('minimist', '1.2.6') },
      {
        args: ['install', '--ignore-scripts', '--non-interactive', '--modules-folder', '<modules>'],
        check: ({ lock }) => {
          assert.doesNotMatch(lock, /minimist@\^1\.2\.5/, 'PatchPilot removed the affected request so yarn re-resolves it');
          assert.match(lock, /\nminimist@1\.2\.6:/);
        },
        lock: 'yarn1-bump-minimist-refreshed.lock',
      },
    ]);
    const { ctx, config, plan } = await context('yarn', runner);
    const action = plan('minimist');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(res.ok, true, res.error);
    assert.deepEqual(res.command?.slice(0, 4), ['corepack', 'yarn@1', 'upgrade', 'minimist@1.2.6']);
    assert.equal(res.command?.[res.command.length - 1], yarnModulesFolder(config), 'installs into .patch-pilot/tmp, not node_modules');
    assert.equal(existsSync(yarnModulesFolder(config)), false, 'the scratch modules folder is removed');
    assert.equal(existsSync(path.join(p.dir, 'node_modules')), false);
    assert.deepEqual(res.verify.map((v) => v.cleared), [true]);
    assert.equal(res.after, '1.2.6, 1.2.8');
    assert.deepEqual(res.lockfileDiff?.unexpected, []);
  });

  it('yarn 1 in-range update: the affected request is removed, yarn install re-resolves it', async () => {
    await pmProject('yarn');
    const runner = fakeManager('yarn', { yarn: '1.22.22' }, [
      {
        args: ['install', '--ignore-scripts', '--non-interactive', '--modules-folder', '<modules>'],
        check: ({ lock }) => assert.doesNotMatch(lock, /decode-uri-component@/),
        lock: 'yarn1-update-decode.lock',
      },
    ]);
    const { ctx, plan } = await context('yarn', runner, { ignoreVcc3: true });
    const action = plan('decode-uri-component');
    assert.equal(action.kind, 'update-transitive');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(res.ok, true, res.error);
    assert.equal(res.after, '0.2.2');
    assert.equal(JSON.parse(await read('package.json')).resolutions, undefined, 'no permanent pin');
  });

  it('yarn 2+: a parent-scoped resolution, then install --mode=update-lockfile', async () => {
    await pmProject('yarn-berry');
    const runner = fakeManager('yarn-berry', { yarn: '4.18.0' }, [
      {
        args: ['install', '--mode=update-lockfile'],
        check: ({ pkg }) => assert.deepEqual(pkg.resolutions, { 'query-string/decode-uri-component': '0.5.0' }),
        lock: 'berry-override-decode.lock',
      },
    ]);
    const { ctx, out, plan } = await context('yarn-berry', runner);
    const action = plan('decode-uri-component');
    assert.equal(action.kind, 'override-transitive');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(res.ok, true, res.error);
    assert.deepEqual(res.verify.map((v) => v.cleared), [true, true]);
    assert.match(out(), /Added a parent-scoped resolution {2}query-string\/decode-uri-component 0\.5\.0 \(package\.json\)/);
  });

  it('pnpm 11: the override goes to pnpm-workspace.yaml, and a failure removes the file again', async () => {
    await pmProject('pnpm');
    const ok = fakeManager('pnpm', { pnpm: '11.9.0' }, [
      { args: ['install', '--lockfile-only', '--ignore-scripts'], check: async ({ dir }) => assert.match(await readFile(path.join(dir, 'pnpm-workspace.yaml'), 'utf8'), /query-string>decode-uri-component: 0\.5\.0/), lock: 'pnpm-override-decode.yaml' },
    ]);
    const first = await context('pnpm', ok);
    const action = first.plan('decode-uri-component');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), first.ctx);
    assert.equal(res.ok, true, res.error);
    assert.deepEqual(res.filesChanged.map((f) => f.path), ['pnpm-lock.yaml', 'pnpm-workspace.yaml']);
    assert.equal(res.filesChanged[1]?.beforeHash, '', 'created by the override');

    await (project as TempProject).cleanup();
    await pmProject('pnpm');
    const failing = fakeManager('pnpm', { pnpm: '11.9.0' }, [{ args: ['install', '--lockfile-only', '--ignore-scripts'], fail: '[ERR_PNPM_FETCH_404] GET https://registry.npmjs.org/decode-uri-component: Not Found - 404' }]);
    const second = await context('pnpm', failing);
    const again = await applyAction(second.plan('decode-uri-component'), makeRecord(second.plan('decode-uri-component'), 'approve', 'flag', IDENTITY), second.ctx);
    assert.equal(again.ok, false);
    assert.equal(again.rolledBack, true);
    assert.match(again.error ?? '', /^pnpm exited with code 1: \[ERR_PNPM_FETCH_404\]/);
    assert.equal(existsSync(path.join((project as TempProject).dir, 'pnpm-workspace.yaml')), false);
  });

  it('aborts and rolls back an unexpected lockfile change without a TTY', async () => {
    await pmProject('yarn-berry');
    const tampered = (await fixture('after', 'berry-bump-lodash.lock')).replace('version: 1.1.0\n  resolution: "filter-obj@npm:1.1.0"', 'version: 1.2.0\n  resolution: "filter-obj@npm:1.2.0"');
    const runner = fakeManager('yarn-berry', { yarn: '4.18.0' }, [{ args: ['add', 'lodash@4.18.1', '--mode=update-lockfile'], pkg: setDep('lodash', '4.18.1') }]);
    const { ctx, audit, plan } = await context('yarn-berry', runner);
    const wrapped: CommandRunner = async (cmd, args, options) => {
      const res = await runner(cmd, args, options);
      if (args.includes('add')) await writeFile(path.join((project as TempProject).dir, 'yarn.lock'), tampered);
      return res;
    };
    ctx.runCommand = wrapped;
    const before = await read('yarn.lock');
    const action = plan('lodash');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(res.ok, false);
    assert.match(res.error ?? '', /unexpected lockfile changes \(filter-obj@npm:1\.1\.0, filter-obj@npm:1\.2\.0\) need a confirmation in a terminal/);
    assert.deepEqual(audit.events('lockfile.diff').map((e) => e.decision), ['aborted']);
    assert.equal(await read('yarn.lock'), before);
    assert.equal(JSON.parse(await read('package.json')).dependencies.lodash, '4.17.20');
  });

  it('says how to install the manager when it cannot be started, and touches nothing', async () => {
    await pmProject('pnpm');
    const runner = fakeManager('pnpm', {}, []);
    const { ctx, audit, out, plan } = await context('pnpm', runner);
    const action = plan('lodash');
    const res = await applyAction(action, makeRecord(action, 'approve', 'flag', IDENTITY), ctx);
    assert.equal(res.ok, false);
    assert.equal(res.rolledBack, false);
    assert.match(res.error ?? '', /pnpm is needed to change the lockfile/);
    assert.match(out(), /npm install -g pnpm/);
    assert.match(out(), /https:\/\/pnpm\.io\/installation/);
    assert.equal(audit.events('patch.backup').length, 0, 'no backup: nothing was about to change');
    assert.deepEqual(runner.commands, []);
  });
});

describe('runPhase3 and rollback with yarn and pnpm', () => {
  async function phase3(manager: Manager, runner: FakeRunner, flags: Record<string, unknown>, tty = false, answers?: string[]) {
    const p = project as TempProject;
    const config = await projectConfig(p.dir, p.home, flags, tty);
    const fixtures = await loadFixtures();
    const graph = await loadDependencyGraph(p.dir, path.join(p.dir, LOCK_NAME[manager]));
    const caseFile = caseFileFor(fixtures.caseFile, graph, LOCK_NAME[manager]);
    const audit = new MemoryAudit();
    const { ui, all } = captureUi({ interactive: config.interactive });
    const res = await runPhase3(caseFile, fixtures.assessment, config, {
      ui,
      audit,
      provider: null,
      identity: IDENTITY,
      db: null,
      showCards: false,
      runCommand: runner,
      prompt: answers ? fakePrompt(answers) : undefined,
    });
    return { res, audit, out: all, config, ui };
  }

  it('resolves pnpm once before the gate, applies, and names the pnpm sync command', async () => {
    await pmProject('pnpm');
    const runner = fakeManager('pnpm', { pnpm: '11.9.0' }, [{ args: ['add', 'lodash@4.18.1', '--lockfile-only', '--ignore-scripts'], lock: 'pnpm-bump-lodash.yaml', pkg: setDep('lodash', '4.18.1') }]);
    const { res, out } = await phase3('pnpm', runner, { approve: 'lodash' });
    assert.equal(res.exitCode, EXIT.OK);
    assert.deepEqual(res.results.map((r) => [r.actionId, r.ok]), [['bump:lodash@4.18.1', true]]);
    assert.match(out(), /Package manager pnpm {2}pnpm 11\.9\.0/);
    assert.match(out(), /sync it with: pnpm install --ignore-scripts/);
    assert.deepEqual(runner.calls.filter((c) => c.endsWith('--version')), ['pnpm --version']);
  });

  it('stops with exit 3 and the install instructions when pnpm cannot be started', async () => {
    await pmProject('pnpm');
    const before = await read('pnpm-lock.yaml');
    const { res, out } = await phase3('pnpm', fakeManager('pnpm', {}, []), { approveAll: true });
    assert.equal(res.exitCode, EXIT.ENVIRONMENT);
    assert.equal(res.results.length, 0);
    assert.match(out(), /Cannot apply fixes with pnpm/);
    assert.match(out(), /corepack enable pnpm/);
    assert.equal(await read('pnpm-lock.yaml'), before);
  });

  it('rollback restores the lockfile and removes the pnpm-workspace.yaml the override created', async () => {
    await pmProject('pnpm');
    const runner = fakeManager('pnpm', { pnpm: '11.9.0' }, [{ args: ['install', '--lockfile-only', '--ignore-scripts'], lock: 'pnpm-override-decode.yaml' }]);
    const before = await read('pnpm-lock.yaml');
    const { res, config, ui } = await phase3('pnpm', runner, { approve: 'decode-uri-component' });
    assert.deepEqual(res.results.map((r) => [r.actionId, r.ok]), [['override-transitive:decode-uri-component@0.5.0', true]]);
    assert.ok(existsSync(path.join(config.projectRoot, 'pnpm-workspace.yaml')));
    const audit = new MemoryAudit();
    const rolled = await rollbackLatest(config, ui, audit);
    assert.deepEqual(rolled.restored.sort(), ['pnpm-lock.yaml', 'pnpm-workspace.yaml']);
    assert.match(rolled.note, /run `pnpm install --ignore-scripts`/);
    assert.equal(existsSync(path.join(config.projectRoot, 'pnpm-workspace.yaml')), false);
    assert.equal(await read('pnpm-lock.yaml'), before);
  });

  it('the node_modules sync and the tests run through the manager (yarn 2+ via corepack)', async () => {
    const p = await pmProject('yarn-berry');
    const runner = fakeManager('yarn-berry', { 'corepack yarn@4.18.0': '4.18.0' }, [{ args: ['install'] }, { args: ['test'] }]);
    const config = await projectConfig(p.dir, p.home, {}, true);
    const { ui, all } = captureUi({ interactive: true });
    const audit = new MemoryAudit();
    const invocation = { manager: 'yarn-berry' as const, cmd: 'corepack', prefix: ['yarn@4.18.0'], display: ['corepack', 'yarn@4.18.0'], version: '4.18.0', env: { YARN_ENABLE_SCRIPTS: '0' } };
    const prompt = fakePrompt(['y', 'y']);
    const post = await offerPostCommands({ config, ui, audit, identity: IDENTITY, prompt, runCommand: runner, invocation });
    assert.deepEqual(post, { synced: true, tests: true });
    assert.deepEqual(prompt.asked, ['Sync node_modules now with corepack yarn@4.18.0 install (scripts off)?', 'Run the test suite with corepack yarn@4.18.0 test?']);
    assert.deepEqual(runner.commands, [['install'], ['test']]);
    assert.deepEqual(audit.events('approval').map((e) => e.actionId), ['post:yarn-install', 'post:yarn-test']);
    assert.match(all(), /Tests passed {2}corepack yarn@4\.18\.0 test/);
    await rm(path.join(p.dir, '.patch-pilot'), { recursive: true, force: true });
  });
});
