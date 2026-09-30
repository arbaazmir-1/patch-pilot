// yarn and pnpm without running them
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { parseLockfile, type LockfileJson } from '../../src/evidence/lockfile.ts';
import { parsePnpmLockfile } from '../../src/evidence/lockfiles/pnpm.ts';
import { parseYarnLockfile } from '../../src/evidence/lockfiles/yarn.ts';
import {
  bumpSpec,
  checkPatchPreflight,
  commandLine,
  diffLockfiles,
  managerArgsFor,
  managerFailure,
  managerOf,
  managerOverrideConflict,
  nodeModulesNote,
  NODE_MODULES_NOTE,
  npmArgsFor,
  planActions,
  pnpmLockfileRefusal,
  pnpmOverrideEntries,
  pnpmOverrideFile,
  refreshArgsFor,
  resolveManager,
  verifyAction,
  writeManagerOverride,
  yarnResolutionEntries,
  type CommandRunner,
} from '../../src/remediation/patch.ts';
import type { Action, CaseFile, Config, DependencyGraph, PackageJson } from '../../src/types.ts';
import type { RunResult } from '../../src/util/proc.ts';
import { fixtureGraph, fixturePackage, loadFixtures, projectConfig } from './patch-helpers.ts';

const LOCKFILES = new URL('../evidence/fixtures/lockfiles/', import.meta.url);
const lockText = (...parts: string[]): Promise<string> => readFile(new URL(parts.join('/'), LOCKFILES), 'utf8');

let tmp: string;
let config: Config;

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-pm-'));
  config = await projectConfig(tmp, tmp);
});

after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

async function plannedFor(name: string): Promise<Action> {
  const { caseFile, assessment } = await loadFixtures();
  const action = planActions(caseFile, assessment, await fixtureGraph(), config).find((a) => a.package === name);
  if (!action) throw new Error(`no action for ${name}`);
  return action;
}

// yarn and pnpm keys differ
function caseFileFor(caseFile: CaseFile, graph: DependencyGraph, lockfile: string): CaseFile {
  return {
    ...caseFile,
    project: { ...caseFile.project, lockfile, lockfileVersion: graph.lockfileVersion },
    packages: caseFile.packages.map((p) => ({ ...p, keys: (graph.byName.get(p.name) ?? []).filter((k) => graph.nodes.get(k)?.version === p.version) })),
  };
}

describe('command construction per package manager', async () => {
  const lodash = await plannedFor('lodash');
  const semver = await plannedFor('semver');
  const decode = await plannedFor('decode-uri-component');
  const { caseFile, assessment } = await loadFixtures();
  const npmGraph = await fixtureGraph();
  const accepted = [{ id: 'GHSA-vcc3-ghjq-m6fr', reason: 'x', by: 'x', createdAt: '' }];
  const update = planActions(caseFile, assessment, npmGraph, { ...config, ignore: accepted } as Config).find((a) => a.package === 'decode-uri-component') as Action;

  it('npm is unchanged', () => {
    for (const action of [lodash, semver, decode, update]) assert.deepEqual(managerArgsFor(action, 'npm'), npmArgsFor(action));
    assert.deepEqual(refreshArgsFor('decode-uri-component', 'npm'), ['update', 'decode-uri-component', '--package-lock-only', '--ignore-scripts']);
    assert.equal(nodeModulesNote('npm'), NODE_MODULES_NOTE);
    assert.equal(managerOf(npmGraph), 'npm');
  });

  it('yarn 1: upgrade with the spec style, install into a scratch modules folder', () => {
    const folder = '/p/.patch-pilot/tmp/yarn-modules';
    assert.deepEqual(managerArgsFor(lodash, 'yarn', { modulesFolder: folder }), ['upgrade', 'lodash@4.18.1', '--ignore-scripts', '--non-interactive', '--modules-folder', folder]);
    const caret: Action = { ...lodash, direct: { depType: 'dependencies', spec: '^4.17.20', specStyle: 'caret' } };
    const tilde: Action = { ...lodash, direct: { depType: 'dependencies', spec: '~4.17.20', specStyle: 'tilde' } };
    assert.equal(bumpSpec(caret), '^4.18.1');
    assert.equal(bumpSpec(tilde), '~4.18.1');
    assert.deepEqual(managerArgsFor(semver, 'yarn'), ['upgrade', 'semver@5.7.2', '--ignore-scripts', '--non-interactive'], 'yarn keeps the devDependencies section itself');
    assert.deepEqual(managerArgsFor(update, 'yarn', { modulesFolder: folder }), ['install', '--ignore-scripts', '--non-interactive', '--modules-folder', folder]);
    assert.deepEqual(managerArgsFor(decode, 'yarn'), ['install', '--ignore-scripts', '--non-interactive']);
    assert.equal(nodeModulesNote('yarn'), 'node_modules is not restored: run `yarn install --ignore-scripts` to bring it in line with the restored lockfile.');
  });

  it('yarn 2+: add at the root (not up, which rewrites every workspace), up -R in range', () => {
    assert.deepEqual(managerArgsFor(lodash, 'yarn-berry'), ['add', 'lodash@4.18.1', '--mode=update-lockfile']);
    assert.deepEqual(managerArgsFor({ ...semver, direct: { depType: 'devDependencies', spec: '^5.7.1', specStyle: 'caret' } }, 'yarn-berry'), ['add', 'semver@^5.7.2', '--mode=update-lockfile']);
    assert.deepEqual(managerArgsFor(update, 'yarn-berry'), ['up', '-R', 'decode-uri-component', '--mode=update-lockfile']);
    assert.deepEqual(managerArgsFor(decode, 'yarn-berry'), ['install', '--mode=update-lockfile']);
    assert.deepEqual(managerArgsFor(lodash, 'yarn-berry', { alias: 'my-lodash' }), ['add', 'my-lodash@npm:lodash@4.18.1', '--mode=update-lockfile']);
  });

  it('pnpm: add with the section flag (pnpm keeps the spec style), -w and -r in a workspace', () => {
    assert.deepEqual(managerArgsFor(lodash, 'pnpm'), ['add', 'lodash@4.18.1', '--lockfile-only', '--ignore-scripts']);
    assert.deepEqual(managerArgsFor(semver, 'pnpm'), ['add', 'semver@5.7.2', '--lockfile-only', '--ignore-scripts', '-D']);
    assert.deepEqual(managerArgsFor({ ...lodash, direct: { depType: 'optionalDependencies', spec: '4.17.20', specStyle: 'exact' } }, 'pnpm', { workspaces: true }), [
      'add',
      'lodash@4.18.1',
      '--lockfile-only',
      '--ignore-scripts',
      '-O',
      '-w',
    ]);
    assert.deepEqual(managerArgsFor(update, 'pnpm'), ['update', 'decode-uri-component', '--lockfile-only', '--ignore-scripts']);
    assert.deepEqual(managerArgsFor(update, 'pnpm', { workspaces: true }), ['update', 'decode-uri-component', '-r', '--lockfile-only', '--ignore-scripts']);
    assert.deepEqual(managerArgsFor(decode, 'pnpm'), ['install', '--lockfile-only', '--ignore-scripts']);
    assert.equal(commandLine(lodash, 'pnpm', { display: ['corepack', 'pnpm@9.15.9'] }), 'corepack pnpm@9.15.9 add lodash@4.18.1 --lockfile-only --ignore-scripts');
    assert.equal(commandLine(lodash, 'yarn', null, { modulesFolder: '/abs/tmp/yarn-modules' }), 'yarn upgrade lodash@4.18.1 --ignore-scripts --non-interactive --modules-folder .patch-pilot/tmp/yarn-modules');
  });

  it('parent-scoped overrides: yarn resolutions and pnpm overrides, and where pnpm reads them', () => {
    assert.deepEqual(yarnResolutionEntries(decode), { 'query-string/decode-uri-component': '0.5.0' });
    assert.deepEqual(pnpmOverrideEntries(decode), { 'query-string>decode-uri-component': '0.5.0' });
    assert.equal(pnpmOverrideFile(9), 'package.json');
    assert.equal(pnpmOverrideFile(10), 'package.json');
    assert.equal(pnpmOverrideFile(11), 'pnpm-workspace.yaml', 'pnpm 11 ignores the package.json "pnpm" field');
    assert.equal(pnpmOverrideFile(null), 'package.json');
  });

  it('plan notes name the manager in yarn and pnpm projects', async () => {
    const graph = parsePnpmLockfile(await lockText('vulnerable-app', 'pnpm-lock.yaml'), { rootPackage: await fixturePackage() });
    const pnpmCase = caseFileFor(caseFile, graph, 'pnpm-lock.yaml');
    const planned = planActions(pnpmCase, assessment, graph, config);
    const decodePnpm = planned.find((a) => a.package === 'decode-uri-component') as Action;
    assert.equal(decodePnpm.kind, 'override-transitive', 'resolved versions only (no installed manifest, no registry): the conservative override');
    const orphan = planActions(pnpmCase, assessment, { ...graph, nodes: new Map([...graph.nodes].map(([k, n]) => [k, k.startsWith('decode') ? { ...n, parents: [] } : n])) }, config).find((a) => a.package === 'decode-uri-component');
    assert.ok(orphan?.notes.some((n) => n.includes('pnpm update is used')));
  });
});

describe('starting yarn and pnpm', () => {
  const ok = (stdout: string): RunResult => ({ ok: true, code: 0, signal: null, stdout, stderr: '', error: null, durationMs: 1 });
  const missing = (): RunResult => ({ ok: false, code: null, signal: null, stdout: '', stderr: '', error: Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }), durationMs: 1 });
  const runner = (answers: Record<string, string | null>): CommandRunner & { calls: string[] } => {
    const calls: string[] = [];
    const fn = async (cmd: string, args: readonly string[]): Promise<RunResult> => {
      const key = [path.basename(cmd), ...args.slice(0, -1)].join(' ');
      calls.push(`${key} ${args[args.length - 1]}`);
      const version = answers[key];
      return version ? ok(`${version}\n`) : missing();
    };
    return Object.assign(fn, { calls });
  };

  it('npm is never probed', async () => {
    const fake = runner({});
    const resolved = await resolveManager('npm', tmp, fake);
    assert.equal(resolved.ok, true);
    assert.deepEqual(fake.calls, []);
  });

  it('prefers the binary on PATH and probes it in the project', async () => {
    const resolved = await resolveManager('pnpm', tmp, runner({ pnpm: '11.9.0' }));
    assert.ok(resolved.ok);
    assert.deepEqual(resolved.invocation.display, ['pnpm']);
    assert.equal(resolved.invocation.version, '11.9.0');
    assert.equal(resolved.invocation.env.COREPACK_ENABLE_DOWNLOAD_PROMPT, '0');
  });

  it('falls back to corepack with the packageManager version, and never runs yarn 2+ on a yarn 1 lockfile', async () => {
    const berry = await resolveManager('yarn-berry', tmp, runner({ 'corepack yarn@4.18.0': '4.18.0' }), { packageManagerField: 'yarn@4.18.0+sha224.abc' });
    assert.ok(berry.ok);
    assert.deepEqual(berry.invocation.display, ['corepack', 'yarn@4.18.0']);
    assert.equal(berry.invocation.env.YARN_ENABLE_SCRIPTS, '0');
    assert.match(berry.notes[0] ?? '', /yarn is not on PATH: running corepack yarn@4\.18\.0/);
    const classic = await resolveManager('yarn', tmp, runner({ yarn: '4.18.0', 'corepack yarn@1': '1.22.22' }));
    assert.ok(classic.ok);
    assert.deepEqual(classic.invocation.display, ['corepack', 'yarn@1']);
    assert.match(classic.notes[0] ?? '', /yarn on PATH is 4\.18\.0, which would convert the yarn 1 lockfile/);
    const guessed = await resolveManager('yarn-berry', tmp, runner({ 'corepack yarn@4': '4.18.0' }), { lockfileVersion: 8 });
    assert.ok(guessed.ok, 'no packageManager field: the yarn major of the lockfile format');
  });

  it('runs the yarn release a yarn 2+ project checks in', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-yarnpath-'));
    try {
      await mkdir(path.join(dir, '.yarn', 'releases'), { recursive: true });
      await writeFile(path.join(dir, '.yarn', 'releases', 'yarn-4.5.0.cjs'), '');
      await writeFile(path.join(dir, '.yarnrc.yml'), 'yarnPath: .yarn/releases/yarn-4.5.0.cjs\n');
      const resolved = await resolveManager('yarn-berry', dir, runner({ [`${path.basename(process.execPath)} ${path.join(dir, '.yarn', 'releases', 'yarn-4.5.0.cjs')}`]: '4.5.0' }));
      assert.ok(resolved.ok);
      assert.deepEqual(resolved.invocation.display, ['node', '.yarn/releases/yarn-4.5.0.cjs']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('says how to install the manager when nothing can run it', async () => {
    const pnpm = await resolveManager('pnpm', tmp, runner({}));
    assert.equal(pnpm.ok, false);
    if (pnpm.ok) return;
    assert.match(pnpm.error, /pnpm is needed to change the lockfile, but neither pnpm nor corepack \(pnpm\) could be started/);
    assert.ok(pnpm.fix.includes('npm install -g pnpm'));
    assert.deepEqual(pnpm.links, ['https://pnpm.io/installation']);
    const yarn = await resolveManager('yarn', tmp, runner({}));
    assert.ok(!yarn.ok && yarn.fix.some((f) => f.startsWith('corepack enable')) && yarn.links.includes('https://yarnpkg.com/getting-started/install'));
  });

  it('explains failures from the real error output of each manager', () => {
    const fail = (stdout: string, stderr = ''): RunResult => ({ ok: false, code: 1, signal: null, stdout, stderr, error: null, durationMs: 1 });
    assert.equal(
      managerFailure('yarn', fail('yarn upgrade v1.22.22\n[1/5] Validating package.json...\n[2/5] Resolving packages...\ninfo Visit https://yarnpkg.com/en/docs/cli/upgrade for documentation about this command.\n', 'error Couldn\'t find any versions for "lodash" that matches "99.0.0"\n')),
      'yarn exited with code 1: Couldn\'t find any versions for "lodash" that matches "99.0.0"',
    );
    assert.equal(
      managerFailure('yarn-berry', fail('➤ YN0000: · Yarn 4.18.0\n➤ YN0000: ┌ Resolution step\n➤ YN0082: │ lodash@npm:99.0.0: No candidates found\n➤ YN0000: └ Completed\n➤ YN0000: · Failed with errors in 0s 79ms\n')),
      'yarn exited with code 1: lodash@npm:99.0.0: No candidates found',
    );
    assert.equal(
      managerFailure('pnpm', fail('Progress: resolved 1, reused 0, downloaded 0, added 0\n[ERR_PNPM_NO_MATCHING_VERSION] No matching version found for lodash@99.0.0 while fetching it from https://registry.npmjs.org/\n\nThe latest release of lodash is "4.18.1".\n')),
      'pnpm exited with code 1: [ERR_PNPM_NO_MATCHING_VERSION] No matching version found for lodash@99.0.0 while fetching it from https://registry.npmjs.org/',
    );
    assert.equal(managerFailure('pnpm', { ...fail(''), error: Object.assign(new Error('x'), { code: 'ENOENT' }) }), 'pnpm was not found on PATH');
  });
});

describe('writing overrides and refusing lockfile-less setups', () => {
  it('yarn resolutions and pnpm overrides go where the manager reads them; comments in pnpm-workspace.yaml survive', async () => {
    const decode = await plannedFor('decode-uri-component');
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-override-'));
    try {
      const pkgFile = path.join(dir, 'package.json');
      await writeFile(pkgFile, '{\n    "name": "x",\n    "resolutions": { "left-pad": "1.3.0" }\n}\n');
      assert.deepEqual(await writeManagerOverride('yarn', dir, decode, null), { file: 'package.json', entries: { 'query-string/decode-uri-component': '0.5.0' } });
      const yarnPkg = await readFile(pkgFile, 'utf8');
      assert.match(yarnPkg, /^ {4}"resolutions": \{/m, 'indentation kept');
      assert.deepEqual(JSON.parse(yarnPkg).resolutions, { 'left-pad': '1.3.0', 'query-string/decode-uri-component': '0.5.0' });

      await writeManagerOverride('pnpm', dir, decode, 10);
      assert.deepEqual(JSON.parse(await readFile(pkgFile, 'utf8')).pnpm, { overrides: { 'query-string>decode-uri-component': '0.5.0' } });

      await writeFile(path.join(dir, 'pnpm-workspace.yaml'), "# workspace\npackages:\n  - 'packages/*'\n");
      assert.equal((await writeManagerOverride('pnpm', dir, decode, 11)).file, 'pnpm-workspace.yaml');
      const yamlText = await readFile(path.join(dir, 'pnpm-workspace.yaml'), 'utf8');
      assert.match(yamlText, /^# workspace$/m);
      assert.match(yamlText, /packages:\n {2}- 'packages\/\*'/);
      assert.match(yamlText, /overrides:\n {2}query-string>decode-uri-component: 0\.5\.0/);

      const pkg = JSON.parse(await readFile(pkgFile, 'utf8')) as PackageJson;
      assert.match((await managerOverrideConflict('yarn', dir, pkg, decode, null)) ?? '', /package\.json resolutions already has "query-string\/decode-uri-component"/);
      assert.match((await managerOverrideConflict('pnpm', dir, pkg, decode, 11)) ?? '', /pnpm-workspace\.yaml overrides already has "query-string>decode-uri-component"/);
      assert.equal(await managerOverrideConflict('pnpm', dir, { name: 'x' }, decode, 9), null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('refuses a pnpm setup that writes no lockfile', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-pnpm-refuse-'));
    try {
      assert.equal(await pnpmLockfileRefusal(dir), null);
      await writeFile(path.join(dir, '.npmrc'), 'lockfile=false\n');
      assert.match((await pnpmLockfileRefusal(dir)) ?? '', /\.npmrc sets lockfile=false/);
      await writeFile(path.join(dir, '.npmrc'), '');
      await writeFile(path.join(dir, 'pnpm-workspace.yaml'), 'lockfile: false\n');
      assert.match((await pnpmLockfileRefusal(dir)) ?? '', /pnpm-workspace\.yaml sets lockfile: false/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('the patch preflight knows yarn 1 lockfiles are version 1 by design and names the manager for workspaces', async () => {
    const graph = parseYarnLockfile(await lockText('vulnerable-app', 'yarn.lock'), { rootPackage: await fixturePackage() });
    const noGit: CommandRunner = async () => ({ ok: false, code: 128, signal: null, stdout: '', stderr: 'fatal', error: null, durationMs: 1 });
    const pre = await checkPatchPreflight(config, graph, noGit);
    assert.equal(pre.lockfileVersion, 1);
    assert.deepEqual(pre.warnings, [], 'no "npm 11 rewrites it" warning for yarn 1');
    const ws = await checkPatchPreflight(config, { ...graph, workspaceKeys: ['packages/a'] }, noGit);
    assert.deepEqual(ws.warnings, ['The project uses yarn 1 workspaces: workspace packages are treated as part of the project.']);
  });
});

describe('diff guard and verification on the lockfiles the verified commands wrote', async () => {
  const { caseFile } = await loadFixtures();
  const pkg = await fixturePackage();
  const withDeps = (deps: Record<string, string>, extra: Partial<PackageJson> = {}): PackageJson => ({ ...pkg, dependencies: { ...pkg.dependencies, ...deps }, ...extra });
  const yarn = async (file: string, rootPackage: PackageJson = pkg): Promise<DependencyGraph> =>
    parseYarnLockfile(file.endsWith('.lock') && !file.includes('/') ? await lockText('after', file) : await lockText(...file.split('/')), { rootPackage });
  const pnpm = async (file: string, rootPackage: PackageJson = pkg): Promise<DependencyGraph> => parsePnpmLockfile(await lockText(...file.split('/')), { rootPackage });
  const resolutions = { resolutions: { 'query-string/decode-uri-component': '0.5.0' } };

  const cases: { name: string; before: () => Promise<DependencyGraph>; after: () => Promise<DependencyGraph>; action: string; ignore?: boolean; allowed: string[] }[] = [
    { name: 'yarn 1 bump', before: () => yarn('vulnerable-app/yarn.lock'), after: () => yarn('yarn1-bump-lodash.lock', withDeps({ lodash: '4.18.1' })), action: 'lodash', allowed: ['added lodash@4.18.1', 'changed package.json dependencies.lodash', 'removed lodash@4.17.20'] },
    { name: 'yarn 1 in-range update', before: () => yarn('vulnerable-app/yarn.lock'), after: () => yarn('yarn1-update-decode.lock'), action: 'decode-uri-component', ignore: true, allowed: ['added decode-uri-component@0.2.2', 'removed decode-uri-component@0.2.0'] },
    { name: 'yarn 1 resolution', before: () => yarn('vulnerable-app/yarn.lock'), after: () => yarn('yarn1-override-decode.lock', { ...pkg, ...resolutions }), action: 'decode-uri-component', allowed: ['added decode-uri-component@0.5.0', 'removed decode-uri-component@0.2.0'] },
    { name: 'yarn 2+ bump', before: () => yarn('vulnerable-app/berry/yarn.lock'), after: () => yarn('berry-bump-lodash.lock', withDeps({ lodash: '4.18.1' })), action: 'lodash', allowed: ['added lodash@npm:4.18.1', 'changed package.json dependencies.lodash', 'removed lodash@npm:4.17.20'] },
    { name: 'yarn 2+ up -R', before: () => yarn('vulnerable-app/berry/yarn.lock'), after: () => yarn('berry-update-decode.lock'), action: 'decode-uri-component', ignore: true, allowed: ['added decode-uri-component@npm:0.2.2', 'removed decode-uri-component@npm:0.2.0'] },
    { name: 'yarn 2+ resolution', before: () => yarn('vulnerable-app/berry/yarn.lock'), after: () => yarn('berry-override-decode.lock', { ...pkg, ...resolutions }), action: 'decode-uri-component', allowed: ['added decode-uri-component@npm:0.5.0', 'removed decode-uri-component@npm:0.2.0'] },
    { name: 'pnpm add', before: () => pnpm('vulnerable-app/pnpm-lock.yaml'), after: () => pnpm('after/pnpm-bump-lodash.yaml', withDeps({ lodash: '4.18.1' })), action: 'lodash', allowed: ['added lodash@4.18.1', 'changed package.json dependencies.lodash', 'removed lodash@4.17.20'] },
    { name: 'pnpm update', before: () => pnpm('vulnerable-app/pnpm-lock.yaml'), after: () => pnpm('after/pnpm-update-decode.yaml'), action: 'decode-uri-component', ignore: true, allowed: ['added decode-uri-component@0.2.2', 'removed decode-uri-component@0.2.0'] },
    { name: 'pnpm override', before: () => pnpm('vulnerable-app/pnpm-lock.yaml'), after: () => pnpm('after/pnpm-override-decode.yaml'), action: 'decode-uri-component', allowed: ['added decode-uri-component@0.5.0', 'removed decode-uri-component@0.2.0'] },
    { name: 'pnpm 6.0 rewritten as 9.0 by a newer pnpm', before: () => pnpm('vulnerable-app/pnpm-v6/pnpm-lock.yaml'), after: () => pnpm('after/pnpm-bump-lodash.yaml', withDeps({ lodash: '4.18.1' })), action: 'lodash', allowed: ['added lodash@4.18.1', 'changed package.json dependencies.lodash', 'removed lodash@4.17.20'] },
  ];

  for (const c of cases) {
    it(`${c.name}: only the target changed, and the CVEs are cleared`, async () => {
      const action = c.ignore
        ? ((await (async () => {
            const { assessment } = await loadFixtures();
            return planActions(caseFile, assessment, await fixtureGraph(), { ...config, ignore: [{ id: 'GHSA-vcc3-ghjq-m6fr', reason: 'x', by: 'x', createdAt: '' }] } as Config).find((a) => a.package === c.action);
          })()) as Action)
        : await plannedFor(c.action);
      const beforeGraph = await c.before();
      const afterGraph = await c.after();
      const diff = diffLockfiles(beforeGraph, afterGraph, action);
      assert.deepEqual(diff.unexpected, []);
      assert.deepEqual(diff.allowed.map((ch) => `${ch.change} ${ch.key}`).sort(), c.allowed);
      assert.ok(verifyAction(action, afterGraph, caseFile).every((v) => v.cleared));
    });
  }

  it('yarn 1 and yarn 2+ bumps leave the dependent\'s in-range copy until the refresh', async () => {
    const minimist = await plannedFor('minimist');
    for (const [bumped, refreshed, rootPackage] of [
      ['yarn1-bump-minimist.lock', 'yarn1-bump-minimist-refreshed.lock', withDeps({ minimist: '1.2.6' })],
      ['berry-bump-minimist.lock', 'berry-bump-minimist-refreshed.lock', withDeps({ minimist: '1.2.6' })],
    ] as const) {
      const bumpedGraph = await yarn(bumped, rootPackage);
      const [open] = verifyAction(minimist, bumpedGraph, caseFile);
      assert.equal(open?.cleared, false, `${bumped}: json5 still gets minimist 1.2.5`);
      const refreshedGraph = await yarn(refreshed, rootPackage);
      assert.deepEqual(verifyAction(minimist, refreshedGraph, caseFile).map((v) => v.cleared), [true]);
      assert.deepEqual(
        [...new Set((refreshedGraph.byName.get('minimist') ?? []).map((k) => refreshedGraph.nodes.get(k)?.version))].sort(),
        ['1.2.6', '1.2.8'],
      );
    }
    const pnpmGraph = await pnpm('after/pnpm-bump-minimist.yaml', withDeps({ minimist: '1.2.6' }));
    assert.deepEqual(verifyAction(minimist, pnpmGraph, caseFile).map((v) => v.cleared), [true], 'pnpm add dedupes json5\'s ^1.2.5 to 1.2.6 itself');
  });

  it('flags a change outside the target, and ignores a yarn 2+ cache key change', async () => {
    const lodash = await plannedFor('lodash');
    const before = await yarn('vulnerable-app/berry/yarn.lock');
    const afterText = (await lockText('after', 'berry-bump-lodash.lock')).replace('version: 1.1.0\n  resolution: "filter-obj@npm:1.1.0"', 'version: 1.2.0\n  resolution: "filter-obj@npm:1.2.0"');
    const tampered = parseYarnLockfile(afterText, { rootPackage: withDeps({ lodash: '4.18.1' }) });
    assert.deepEqual(diffLockfiles(before, tampered, lodash).unexpected.map((c) => `${c.change} ${c.key}`).sort(), ['added filter-obj@npm:1.2.0', 'removed filter-obj@npm:1.1.0']);
    const rehashed = parseYarnLockfile((await lockText('after', 'berry-bump-lodash.lock')).replace(/checksum: 10c0\//g, 'checksum: 11c0/').replace('cacheKey: 10c0', 'cacheKey: 11c0'), {
      rootPackage: withDeps({ lodash: '4.18.1' }),
    });
    assert.deepEqual(diffLockfiles(before, rehashed, lodash).unexpected, [], 'a new cache key re-hashes every package without changing it');
    const npmBefore = parseLockfile(JSON.parse(await readFile(new URL('../../examples/vulnerable-app/package-lock.json', import.meta.url), 'utf8')) as LockfileJson, pkg);
    assert.equal(managerOf(npmBefore), 'npm');
  });
});
