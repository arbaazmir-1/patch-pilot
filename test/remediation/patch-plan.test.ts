import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { parseLockfile } from '../../src/evidence/lockfile.ts';
import {
  chooseTarget,
  enginesCheck,
  npmArgsFor,
  npmInvocation,
  overrideConflict,
  overrideEntries,
  planActions,
  stalePackages,
  writeOverride,
} from '../../src/remediation/patch.ts';
import type { Action, Config, IgnoreEntry, VulnCase } from '../../src/types.ts';
import { fixtureGraph, fixtureLock, fixturePackage, loadFixtures, projectConfig, setNodeVersion } from './patch-helpers.ts';

let tmp: string;
let config: Config;

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-plan-'));
  config = await projectConfig(tmp, tmp);
});

after(async () => {
  await rm(tmp, { recursive: true, force: true });
});

function byPackage(actions: readonly Action[]): Map<string, Action> {
  return new Map(actions.map((a) => [a.package, a]));
}

describe('planActions on the vulnerable-app fixture', () => {
  it('plans one action per package with kind, target, CVEs, spec style and parents', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const actions = planActions(caseFile, assessment, await fixtureGraph(), config);
    const map = byPackage(actions);
    assert.deepEqual([...map.keys()].sort(), ['decode-uri-component', 'json5', 'lodash', 'marked', 'minimist', 'semver']);

    const lodash = map.get('lodash') as Action;
    assert.equal(lodash.kind, 'bump');
    assert.equal(lodash.id, 'bump:lodash@4.18.1');
    assert.equal(lodash.toVersion, '4.18.1', 'skips the deprecated 4.18.0');
    assert.deepEqual(lodash.vulnIds.sort(), ['GHSA-29mw-wpgm-hmr9', 'GHSA-35jh-r3h4-6jhm', 'GHSA-xxjr-mmjv-4gpg']);
    assert.deepEqual(lodash.direct, { depType: 'dependencies', spec: '4.17.20', specStyle: 'exact' });
    assert.equal(lodash.worstRisk, 'Medium');
    assert.ok(lodash.notes.some((n) => n.includes('Skips deprecated 4.18.0')));
    assert.equal(lodash.requiresMigration, false);

    const minimist = map.get('minimist') as Action;
    assert.equal(minimist.kind, 'bump');
    assert.equal(minimist.toVersion, '1.2.6');
    assert.equal(minimist.worstRisk, 'High');
    assert.deepEqual(minimist.parents, [{ name: 'json5', version: '2.2.0', key: 'node_modules/json5', range: '^1.2.5', acceptsTarget: true }]);

    const marked = map.get('marked') as Action;
    assert.equal(marked.kind, 'bump-major');
    assert.equal(marked.toVersion, '4.0.10');
    assert.equal(marked.majorBump, true);
    assert.equal(marked.importedInSource, true);
    assert.equal(marked.requiresMigration, true, 'a major bump imported in source is a transaction');
    assert.equal(marked.vulnIds.length, 5, 'one bump closes all five marked CVEs');

    const semver = map.get('semver') as Action;
    assert.equal(semver.kind, 'bump');
    assert.equal(semver.direct?.depType, 'devDependencies');

    const decode = map.get('decode-uri-component') as Action;
    assert.equal(decode.kind, 'override-transitive', '0.5.0 clears both CVEs but is outside query-string ^0.2.0');
    assert.equal(decode.toVersion, '0.5.0');
    assert.equal(decode.direct, null);
    assert.deepEqual(decode.parents, [{ name: 'query-string', version: '6.14.1', key: 'node_modules/query-string', range: '^0.2.0', acceptsTarget: false }]);
    assert.ok(decode.notes.some((n) => n.includes('not tested with decode-uri-component@0.5.0')));

    // high, medium, then low
    assert.deepEqual(actions.map((a) => a.worstRisk), ['High', 'High', 'Medium', 'Low', 'Low', 'Low']);
    assert.equal(actions[0]?.package, 'minimist', 'GHSA CRITICAL sorts before HIGH at the same risk');
    for (const a of actions) {
      assert.equal(a.engines?.projectNode, '>=18');
      assert.equal(a.engines?.runningNode, process.versions.node);
    }
  });

  it('leaves accepted risks out: with GHSA-vcc3 accepted, decode-uri-component is an in-range update', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const ignore: IgnoreEntry[] = [{ id: 'CVE-2026-45822', reason: 'query-string never sees attacker input', by: 'Test', createdAt: '2026-09-01T00:00:00Z' }];
    const actions = planActions(caseFile, assessment, await fixtureGraph(), { ...config, ignore });
    const decode = byPackage(actions).get('decode-uri-component') as Action;
    assert.equal(decode.kind, 'update-transitive');
    assert.equal(decode.toVersion, '0.2.1');
    assert.deepEqual(decode.vulnIds, ['GHSA-w573-4hg7-7wgq']);
    assert.equal(decode.parents[0]?.acceptsTarget, true);
    assert.equal(decode.majorBump, false);
  });

  it('an expired accepted risk counts again', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const ignore: IgnoreEntry[] = [{ id: 'GHSA-vcc3-ghjq-m6fr', reason: 'old', by: 'Test', createdAt: '2025-01-01T00:00:00Z', until: '2025-06-30' }];
    const decode = byPackage(planActions(caseFile, assessment, await fixtureGraph(), { ...config, ignore })).get('decode-uri-component') as Action;
    assert.equal(decode.kind, 'override-transitive');
  });

  it('drops a package whose CVEs are all accepted', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const ignore: IgnoreEntry[] = [{ id: 'GHSA-c2qf-rxjj-qqgw', package: 'semver', reason: 'dev only', by: 'Test', createdAt: '2026-09-01T00:00:00Z' }];
    const actions = planActions(caseFile, assessment, await fixtureGraph(), { ...config, ignore });
    assert.equal(byPackage(actions).has('semver'), false);
  });

  it('skips packages that were not investigated or are no longer at the scanned version', async () => {
    const { caseFile, assessment } = await loadFixtures();
    const onlyTwo = { ...assessment, verdicts: assessment.verdicts.filter((v) => v.package === 'minimist' || v.package === 'lodash') };
    assert.deepEqual(
      planActions(caseFile, onlyTwo, await fixtureGraph(), config).map((a) => a.package).sort(),
      ['lodash', 'minimist'],
    );
    const lock = await fixtureLock();
    setNodeVersion(lock, 'node_modules/lodash', '4.18.1');
    const graph = parseLockfile(lock, await fixturePackage());
    assert.deepEqual(stalePackages(caseFile, graph).map((p) => p.name), ['lodash']);
    assert.equal(byPackage(planActions(caseFile, assessment, graph, config)).has('lodash'), false);
  });
});

describe('chooseTarget', () => {
  const vuln = (id: string, fixed: string | null, ranges: VulnCase['ranges']): VulnCase =>
    ({ id, package: 'pkg', installedVersion: '1.2.0', ranges, recommendedFix: fixed ? { version: fixed, majorBump: false } : null, mergedIds: [], aliases: [] }) as unknown as VulnCase;
  const upTo = (fixed: string): VulnCase['ranges'] => [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }];

  it('picks the highest recommended fix when it clears every CVE', () => {
    const choice = chooseTarget([vuln('A', '1.2.6', upTo('1.2.6')), vuln('B', '1.4.0', upTo('1.4.0'))], '1.2.0');
    assert.equal(choice?.version, '1.4.0');
    assert.equal(choice?.full, true);
  });

  it('falls back to the best fix in the installed line and reports what remains', () => {
    const regression: VulnCase['ranges'] = [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.6' }, { introduced: '1.3.0' }] }];
    const choice = chooseTarget([vuln('A', '1.2.6', regression), vuln('B', '2.0.0', upTo('2.0.0')), vuln('C', null, upTo('9.9.9'))], '1.2.0');
    assert.equal(choice?.version, '1.2.6', 'no candidate clears all, so the same-line fix wins over the major one');
    assert.equal(choice?.full, false);
    assert.deepEqual(choice?.remaining.map((v) => v.id).sort(), ['B', 'C']);
  });

  it('returns null when no CVE has a fix', () => {
    assert.equal(chooseTarget([vuln('A', null, upTo('2.0.0'))], '1.2.0'), null);
  });
});

describe('npm arguments', () => {
  const base = { id: 'x', package: 'lodash', fromVersion: '4.17.20', toVersion: '4.18.1', vulnIds: [], worstRisk: 'High', majorBump: false, parents: [], importedInSource: true, requiresMigration: false, engines: null, notes: [] } as unknown as Action;
  const direct = (depType: NonNullable<Action['direct']>['depType'], specStyle: NonNullable<Action['direct']>['specStyle']): Action => ({ ...base, kind: 'bump', direct: { depType, spec: 'x', specStyle } });

  it('keeps the spec style and the package.json section', () => {
    assert.deepEqual(npmArgsFor(direct('dependencies', 'caret')), ['install', 'lodash@4.18.1', '--package-lock-only', '--ignore-scripts']);
    assert.deepEqual(npmArgsFor(direct('dependencies', 'exact')), ['install', 'lodash@4.18.1', '--package-lock-only', '--ignore-scripts', '--save-exact']);
    assert.deepEqual(npmArgsFor(direct('dependencies', 'tilde')), ['install', 'lodash@4.18.1', '--package-lock-only', '--ignore-scripts', '--save-prefix=~']);
    assert.deepEqual(npmArgsFor(direct('devDependencies', 'exact')), ['install', 'lodash@4.18.1', '--package-lock-only', '--ignore-scripts', '--save-dev', '--save-exact']);
    assert.ok(npmArgsFor(direct('optionalDependencies', 'caret')).includes('--save-optional'));
    assert.ok(npmArgsFor(direct('peerDependencies', 'caret')).includes('--save-peer'));
    assert.deepEqual(npmArgsFor({ ...base, kind: 'bump-major', direct: { depType: 'dependencies', spec: '^0.3.6', specStyle: 'caret' }, package: 'marked', toVersion: '4.0.10' }), [
      'install',
      'marked@4.0.10',
      '--package-lock-only',
      '--ignore-scripts',
    ]);
  });

  it('uses npm update in range and a plain install after an override', () => {
    assert.deepEqual(npmArgsFor({ ...base, kind: 'update-transitive', direct: null, package: 'decode-uri-component' }), ['update', 'decode-uri-component', '--package-lock-only', '--ignore-scripts']);
    assert.deepEqual(npmArgsFor({ ...base, kind: 'override-transitive', direct: null }), ['install', '--package-lock-only', '--ignore-scripts']);
    for (const kind of ['bump', 'bump-major', 'update-transitive', 'override-transitive'] as const) {
      assert.ok(npmArgsFor({ ...base, kind, direct: kind.startsWith('bump') ? { depType: 'dependencies', spec: '1', specStyle: 'exact' } : null }).includes('--ignore-scripts'), kind);
    }
  });

  it('never needs a shell: npm on POSIX, node + npm-cli.js on Windows when present', () => {
    assert.deepEqual(npmInvocation('darwin'), { cmd: 'npm', prefix: [] });
    assert.deepEqual(npmInvocation('linux'), { cmd: 'npm', prefix: [] });
    const win = npmInvocation('win32', path.join(tmp, 'node.exe'));
    assert.equal(win.cmd, 'npm.cmd', 'falls back to npm.cmd when npm-cli.js is not next to node');
  });
});

describe('parent-scoped overrides', () => {
  const action = {
    id: 'override-transitive:decode-uri-component@0.5.0',
    kind: 'override-transitive',
    package: 'decode-uri-component',
    fromVersion: '0.2.0',
    toVersion: '0.5.0',
    parents: [
      { name: 'query-string', version: '6.14.1', key: 'node_modules/query-string', range: '^0.2.0', acceptsTarget: false },
      { name: 'other', version: '1.0.0', key: 'node_modules/other', range: '*', acceptsTarget: true },
    ],
  } as unknown as Action;

  it('scopes the override to the parents whose range excludes the target', () => {
    assert.deepEqual(overrideEntries(action), { 'query-string': { 'decode-uri-component': '0.5.0' } });
  });

  it('writes package.json with its indentation and merges an existing string override', async () => {
    const file = path.join(tmp, 'package.json');
    await writeFile(file, '{\n    "name": "x",\n    "overrides": {\n        "query-string": "6.14.1"\n    },\n    "dependencies": {}\n}\n');
    await writeOverride(file, action);
    const text = await readFile(file, 'utf8');
    assert.match(text, /^ {4}"name"/m, 'four-space indentation kept');
    const json = JSON.parse(text) as { overrides: Record<string, unknown> };
    assert.deepEqual(json.overrides, { 'query-string': { '.': '6.14.1', 'decode-uri-component': '0.5.0' } });
    assert.deepEqual(Object.keys(JSON.parse(text)), ['name', 'overrides', 'dependencies'], 'key order kept');
  });

  it('refuses a direct dependency or an existing top-level override (EOVERRIDE)', () => {
    assert.match(overrideConflict({ dependencies: { 'decode-uri-component': '0.2.0' } }, action) ?? '', /direct dependency/);
    assert.match(overrideConflict({ overrides: { 'decode-uri-component': '0.2.2' } }, action) ?? '', /already overrides/);
    assert.equal(overrideConflict({ dependencies: { 'query-string': '6.14.1' } }, action), null, 'a direct parent is fine for a scoped override');
  });
});

describe('engines check', () => {
  it('compares the target engines.node with the project and the running Node', () => {
    assert.equal(enginesCheck('>=14.16', '>=18', '24.14.1').compatible, true);
    const tooNew = enginesCheck('>=20', '>=18', '24.14.1');
    assert.equal(tooNew.compatible, false);
    assert.match(tooNew.message ?? '', /project declares node >=18/);
    assert.equal(enginesCheck('>=26', null, '24.14.1').compatible, false);
    assert.equal(enginesCheck(null, '>=18', '24.14.1').compatible, true);
    assert.equal(enginesCheck(null, '>=18', '24.14.1', false).compatible, null);
  });
});
