import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { chooseTarget, enginesCheck, npmArgsFor, npmInvocation, overrideConflict, overrideEntries, writeOverride } from '../../src/remediation/patch.ts';
import type { Action, VulnCase } from '../../src/types.ts';

let tmp: string;

before(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-plan-'));
});

after(async () => {
  await rm(tmp, { recursive: true, force: true });
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
