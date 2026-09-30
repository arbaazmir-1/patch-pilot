import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseLockfile, type LockfileJson } from '../../src/evidence/lockfile.ts';
import { diffLockfiles, planActions, verifyAction, vulnAffects } from '../../src/remediation/patch.ts';
import type { Action, Config, DependencyGraph, PackageJson } from '../../src/types.ts';
import { fixtureGraph, fixtureLock, fixturePackage, loadFixtures, setNodeVersion } from './patch-helpers.ts';

function graphOf(lock: LockfileJson, pkg: PackageJson): DependencyGraph {
  return parseLockfile(lock, pkg);
}

async function actionFor(name: string, ignore: Config['ignore'] = []): Promise<Action> {
  const { caseFile, assessment } = await loadFixtures();
  const actions = planActions(caseFile, assessment, await fixtureGraph(), { ignore } as unknown as Config);
  const action = actions.find((a) => a.package === name);
  if (!action) throw new Error(`no action for ${name}`);
  return action;
}

describe('lockfile diff guard', () => {
  it('a direct bump changes only the target node and its package.json spec', async () => {
    const pkg = await fixturePackage();
    const before = graphOf(await fixtureLock(), pkg);
    const lock = await fixtureLock();
    setNodeVersion(lock, 'node_modules/lodash', '4.18.1');
    const after = graphOf(lock, { ...pkg, dependencies: { ...pkg.dependencies, lodash: '4.18.1' } });
    const diff = diffLockfiles(before, after, await actionFor('lodash'));
    assert.deepEqual(diff.unexpected, []);
    assert.deepEqual(
      diff.allowed.map((c) => [c.key, c.change, c.from, c.to]),
      [
        ['node_modules/lodash', 'changed', '4.17.20', '4.18.1'],
        ['package.json dependencies.lodash', 'changed', '4.17.20', '4.18.1'],
      ],
    );
  });

  it('accepts the re-nesting of an overridden package under its parent', async () => {
    const pkg = await fixturePackage();
    const before = graphOf(await fixtureLock(), pkg);
    const lock = await fixtureLock();
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    delete packages['node_modules/decode-uri-component'];
    setNodeVersion(lock, 'node_modules/query-string/node_modules/decode-uri-component', '0.5.0');
    const after = graphOf(lock, pkg);
    const diff = diffLockfiles(before, after, await actionFor('decode-uri-component'));
    assert.deepEqual(diff.unexpected, [], 'removing the hoisted copy and adding the nested one are both the target');
    assert.deepEqual(diff.changes.map((c) => `${c.change} ${c.key}`).sort(), [
      'added node_modules/query-string/node_modules/decode-uri-component',
      'removed node_modules/decode-uri-component',
    ]);
  });

  it('allows new dependencies of the target (its subtree) and flags unrelated changes', async () => {
    const pkg = await fixturePackage();
    const before = graphOf(await fixtureLock(), pkg);
    const lock = await fixtureLock();
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    setNodeVersion(lock, 'node_modules/marked', '4.0.10');
    (packages['node_modules/marked'] as Record<string, unknown>).dependencies = { 'marked-helper': '^1.0.0' };
    setNodeVersion(lock, 'node_modules/marked-helper', '1.0.0');
    setNodeVersion(lock, 'node_modules/filter-obj', '1.2.0'); // not in marked's tree
    const after = graphOf(lock, { ...pkg, dependencies: { ...pkg.dependencies, marked: '4.0.10' } });
    const diff = diffLockfiles(before, after, await actionFor('marked'));
    assert.deepEqual(diff.allowed.map((c) => c.key).sort(), ['node_modules/marked', 'node_modules/marked-helper', 'package.json dependencies.marked']);
    assert.deepEqual(diff.unexpected, [{ key: 'node_modules/filter-obj', change: 'changed', from: '1.1.0', to: '1.2.0' }]);
  });

  it('flags a package.json spec change of another dependency and an integrity-only change', async () => {
    const pkg = await fixturePackage();
    const before = graphOf(await fixtureLock(), pkg);
    const lock = await fixtureLock();
    const packages = lock.packages as Record<string, Record<string, unknown>>;
    setNodeVersion(lock, 'node_modules/minimist', '1.2.6');
    (packages['node_modules/json5'] as Record<string, unknown>).integrity = 'sha512-tampered';
    const after = graphOf(lock, { ...pkg, dependencies: { ...pkg.dependencies, minimist: '1.2.6', json5: '^2.2.0' } });
    const diff = diffLockfiles(before, after, await actionFor('minimist'));
    assert.deepEqual(diff.unexpected.map((c) => c.key).sort(), ['node_modules/json5', 'package.json dependencies.json5']);
    assert.match(diff.unexpected.find((c) => c.key === 'node_modules/json5')?.to ?? '', /integrity/);
  });
});

describe('verifyAction', () => {
  it('clears a CVE only when every node of the package is outside the affected ranges', async () => {
    const { caseFile } = await loadFixtures();
    const action = await actionFor('minimist');
    const pkg = await fixturePackage();
    const fixed = await fixtureLock();
    setNodeVersion(fixed, 'node_modules/minimist', '1.2.6');
    const ok = verifyAction(action, graphOf(fixed, pkg), caseFile);
    assert.deepEqual(ok, [{ vulnId: 'GHSA-xvch-5gv4-984h', package: 'minimist', cleared: true, nodes: [{ key: 'node_modules/minimist', version: '1.2.6', affected: false }] }]);

    // nested vulnerable copy stays
    setNodeVersion(fixed, 'node_modules/json5/node_modules/minimist', '1.2.5');
    const nested = verifyAction(action, graphOf(fixed, pkg), caseFile);
    assert.equal(nested[0]?.cleared, false);
    assert.deepEqual(nested[0]?.nodes.find((n) => n.affected), { key: 'node_modules/json5/node_modules/minimist', version: '1.2.5', affected: true });
  });

  it('checks ranges, not equality with the target: npm update landing on 0.2.2 clears the in-range CVE', async () => {
    const { caseFile } = await loadFixtures();
    const action = await actionFor('decode-uri-component', [{ id: 'GHSA-vcc3-ghjq-m6fr', reason: 'x', by: 'x', createdAt: '' }]);
    assert.equal(action.kind, 'update-transitive');
    const lock = await fixtureLock();
    setNodeVersion(lock, 'node_modules/decode-uri-component', '0.2.2');
    const results = verifyAction(action, graphOf(lock, await fixturePackage()), caseFile);
    assert.deepEqual(results.map((r) => [r.vulnId, r.cleared]), [['GHSA-w573-4hg7-7wgq', true]]);
    const vcc3 = caseFile.vulnerabilities.find((v) => v.id === 'GHSA-vcc3-ghjq-m6fr');
    assert.ok(vcc3 && vulnAffects(vcc3, '0.2.2'), 'the out-of-range CVE still affects 0.2.2');
  });

  it('a removed package counts as cleared', async () => {
    const { caseFile } = await loadFixtures();
    const action = await actionFor('semver');
    const lock = await fixtureLock();
    delete (lock.packages as Record<string, unknown>)['node_modules/semver'];
    const [result] = verifyAction(action, graphOf(lock, await fixturePackage()), caseFile);
    assert.equal(result?.cleared, true);
    assert.deepEqual(result?.nodes, []);
  });
});
