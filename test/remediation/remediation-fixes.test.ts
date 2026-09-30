// npm aliases, per-manager details, windows npm
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { after, before, describe, it } from 'node:test';
import { parseLockfile, type LockfileJson } from '../../src/evidence/lockfile.ts';
import { detailsManager, renderActionDetails } from '../../src/remediation/present.ts';
import { diffLockfiles, managerArgsFor, npmArgsFor, npmInvocation as reexported, planActions } from '../../src/remediation/patch.ts';
import type { Action, Assessment, CaseFile, Config, PackageJson } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';
import { npmInvocation } from '../../src/util/npm.ts';

let tmp: string;

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-fixes-'));
});

after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

const ALIAS_SPEC = 'npm:lodash@^4.17.0';
const aliasPkg = (spec = ALIAS_SPEC): PackageJson => ({ name: 'app', version: '1.0.0', dependencies: { 'my-lodash': spec } }) as PackageJson;

function aliasLock(extra: Record<string, unknown> = {}, rootDeps: Record<string, string> = { 'my-lodash': ALIAS_SPEC }, version = '4.17.15'): LockfileJson {
  return {
    name: 'app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0', dependencies: rootDeps },
      'node_modules/my-lodash': { name: 'lodash', version, resolved: `https://registry.npmjs.org/lodash/-/lodash-${version}.tgz`, integrity: `sha512-${version}` },
      ...extra,
    },
  } as unknown as LockfileJson;
}

const aliasCaseFile = {
  project: { root: '/tmp/app', name: 'app', lockfile: 'package-lock.json', lockfileVersion: 3 },
  packages: [{ name: 'lodash', version: '4.17.15', keys: ['node_modules/my-lodash'], isDirect: true, isDevOnly: false, depType: 'dependencies', spec: ALIAS_SPEC, usage: null }],
  vulnerabilities: [
    {
      id: 'GHSA-x',
      package: 'lodash',
      installedVersion: '4.17.15',
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      recommendedFix: { version: '4.17.21', majorBump: false },
      mergedIds: [],
      aliases: [],
      severity: {},
      malware: false,
    },
  ],
} as unknown as CaseFile;

const aliasAssessment = { verdicts: [{ package: 'lodash', installedVersion: '4.17.15', vulnId: 'GHSA-x', risk: 'High' }] } as unknown as Assessment;

describe('npm alias bumps', () => {
  const graph = parseLockfile(aliasLock(), aliasPkg());
  const action = planActions(aliasCaseFile, aliasAssessment, graph, { ignore: [], projectRoot: '/tmp/app' } as unknown as Config)[0] as Action;

  it('installs through the alias instead of adding a plain lodash', () => {
    assert.equal(action.kind, 'bump');
    assert.equal(action.direct?.specStyle, 'other');
    assert.deepEqual(npmArgsFor(action, { alias: 'my-lodash' }), ['install', 'my-lodash@npm:lodash@^4.17.21', '--package-lock-only', '--ignore-scripts']);
    assert.deepEqual(managerArgsFor(action, 'npm', { alias: 'my-lodash' }), npmArgsFor(action, { alias: 'my-lodash' }));
    assert.deepEqual(npmArgsFor(action), ['install', 'lodash@4.17.21', '--package-lock-only', '--ignore-scripts'], 'no alias, no change');
  });

  it('flags a second plain copy but allows the alias bump', () => {
    const plain = parseLockfile(
      aliasLock({ 'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', integrity: 'sha512-4.17.21' } }, { 'my-lodash': ALIAS_SPEC, lodash: '^4.17.21' }),
      { ...aliasPkg(), dependencies: { 'my-lodash': ALIAS_SPEC, lodash: '^4.17.21' } } as PackageJson,
    );
    const bad = diffLockfiles(graph, plain, action).unexpected.map((c) => `${c.change} ${c.key}`).sort();
    assert.deepEqual(bad, ['added node_modules/lodash', 'added package.json dependencies.lodash']);

    const bumped = parseLockfile(aliasLock({}, { 'my-lodash': 'npm:lodash@^4.17.21' }, '4.17.21'), aliasPkg('npm:lodash@^4.17.21'));
    const good = diffLockfiles(graph, bumped, action);
    assert.deepEqual(good.unexpected, []);
    assert.ok(good.allowed.some((c) => c.key === 'package.json dependencies.my-lodash'));
  });

  it('shows the alias in the details', () => {
    const text = renderActionDetails(action, ui(), { graph });
    assert.match(text, /npm install my-lodash@npm:lodash@\^4\.17\.21 /);
    assert.match(text, /"my-lodash": "npm:lodash@\^4\.17\.0"/);
  });
});

function ui(): Ui {
  return new Ui({ color: false, unicode: true, width: 200, env: {}, stdout: new PassThrough() as never, stderr: new PassThrough() as never });
}

describe('action details per package manager', () => {
  const bump = {
    id: 'bump:lodash@4.18.1',
    kind: 'bump',
    package: 'lodash',
    fromVersion: '4.17.20',
    toVersion: '4.18.1',
    vulnIds: [],
    worstRisk: 'High',
    majorBump: false,
    direct: { depType: 'dependencies', spec: '^4.17.20', specStyle: 'caret' },
    parents: [],
    importedInSource: true,
    requiresMigration: false,
    engines: null,
    notes: [],
  } as unknown as Action;
  const override = {
    ...bump,
    id: 'override-transitive:decode-uri-component@0.5.0',
    kind: 'override-transitive',
    package: 'decode-uri-component',
    fromVersion: '0.2.0',
    toVersion: '0.5.0',
    direct: null,
    parents: [{ name: 'query-string', version: '6.14.1', key: 'node_modules/query-string', range: '^0.2.0', acceptsTarget: false }],
  } as unknown as Action;
  const caseFileWith = (lockfile: string, lockfileVersion: number): CaseFile => ({ project: { root: '/x', name: 'x', lockfile, lockfileVersion } }) as unknown as CaseFile;

  it('picks the manager from the scanned lockfile', () => {
    assert.equal(detailsManager({ caseFile: caseFileWith('yarn.lock', 1) }), 'yarn');
    assert.equal(detailsManager({ caseFile: caseFileWith('yarn.lock', 8) }), 'yarn-berry');
    assert.equal(detailsManager({ caseFile: caseFileWith('pnpm-lock.yaml', 9) }), 'pnpm');
    assert.equal(detailsManager({ caseFile: caseFileWith('package-lock.json', 3) }), 'npm');
    assert.equal(detailsManager({}), 'npm');
    assert.equal(detailsManager({ caseFile: caseFileWith('package-lock.json', 3), manager: 'pnpm' }), 'pnpm');
  });

  it('prints the yarn command and resolution', () => {
    const text = renderActionDetails(bump, ui(), { caseFile: caseFileWith('yarn.lock', 1) });
    assert.match(text, /yarn upgrade lodash@\^4\.18\.1 --ignore-scripts --non-interactive --modules-folder \.patch-pilot\/tmp\/yarn-modules/);
    assert.doesNotMatch(text, /Command +npm /);
    const over = renderActionDetails(override, ui(), { caseFile: caseFileWith('yarn.lock', 8) });
    assert.match(over, /Resolution\s+"query-string\/decode-uri-component": "0\.5\.0" \(resolutions in package\.json\)/);
    assert.match(over, /yarn install --mode=update-lockfile/);
  });

  it('prints the pnpm command and override', () => {
    const text = renderActionDetails(bump, ui(), { manager: 'pnpm', invocation: { display: ['corepack', 'pnpm@9.15.9'], version: '9.15.9' } });
    assert.match(text, /corepack pnpm@9\.15\.9 add lodash@4\.18\.1 --lockfile-only --ignore-scripts/);
    const over = renderActionDetails(override, ui(), { manager: 'pnpm', invocation: { display: ['pnpm'], version: '11.0.0' } });
    assert.match(over, /Override\s+"query-string>decode-uri-component": "0\.5\.0" \(overrides in pnpm-workspace\.yaml\)/);
    assert.match(over, /Command +pnpm install --lockfile-only --ignore-scripts/);
    const old = renderActionDetails(override, ui(), { caseFile: caseFileWith('pnpm-lock.yaml', 9) });
    assert.match(old, /\(pnpm\.overrides in package\.json\)/);
  });

  it('keeps the npm command and override for npm', () => {
    const over = renderActionDetails(override, ui(), { caseFile: caseFileWith('package-lock.json', 3) });
    assert.match(over, /Override\s+"query-string": \{"decode-uri-component":"0\.5\.0"\}/);
    assert.match(over, /npm install --package-lock-only --ignore-scripts/);
  });
});

describe('npm invocation', () => {
  it('runs npm-cli.js through node on windows', async () => {
    const bin = path.join(tmp, 'nodejs');
    const cli = path.join(bin, 'node_modules', 'npm', 'bin', 'npm-cli.js');
    await mkdir(path.dirname(cli), { recursive: true });
    await writeFile(cli, '');
    const exe = path.join(bin, 'node.exe');
    assert.deepEqual(npmInvocation('win32', exe), { cmd: exe, prefix: [cli] });
    assert.deepEqual(npmInvocation('darwin', exe), { cmd: 'npm', prefix: [] });
    assert.equal(reexported, npmInvocation, 'patch.ts re-exports the shared one');
  });
});
