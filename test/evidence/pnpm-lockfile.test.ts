import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { installedPath, loadDependencyGraph, lockfileManager } from '../../src/evidence/lockfile.ts';
import { normalizePnpmKey, parsePnpmLockfile, pnpmStorePath, refinePnpmRanges, splitPnpmKey } from '../../src/evidence/lockfiles/pnpm.ts';
import type { NodeSummary } from './yarn-pnpm-helpers.ts';
import { APP, appNpmGraph, appPackage, rootEdges, summarize, text, workspacePackages, workspacesNpmGraph } from './yarn-pnpm-helpers.ts';

describe('pnpm lockfile 9.0: examples/vulnerable-app (pnpm import of package-lock.json)', async () => {
  const graph = parsePnpmLockfile(await text('vulnerable-app', 'pnpm-lock.yaml'), { rootPackage: await appPackage() });

  it('builds the same graph as the npm lockfile: flags, direct, dependents, paths', async () => {
    const npm = await appNpmGraph();
    assert.deepEqual(summarize(graph), summarize(npm));
    assert.deepEqual(rootEdges(graph), rootEdges(npm));
    assert.equal(graph.packageManager, 'pnpm');
    assert.equal(graph.lockfileVersion, 9);
  });

  it('keys nodes by snapshot, keeps integrity and engines, and records resolved versions as requires', () => {
    const qs = graph.nodes.get('query-string@6.14.1');
    assert.equal(qs?.edges['decode-uri-component'], 'decode-uri-component@0.2.0');
    assert.deepEqual(qs?.requires, { 'decode-uri-component': '0.2.0', 'filter-obj': '1.1.0', 'split-on-first': '1.1.0', 'strict-uri-encode': '2.0.0' }, 'pnpm-lock.yaml has no declared ranges');
    assert.deepEqual(qs?.engines, { node: '>=6' });
    assert.match(qs?.integrity ?? '', /^sha512-XDxAeV/);
    assert.equal(installedPath(graph, 'query-string@6.14.1'), 'node_modules/.pnpm/query-string@6.14.1/node_modules/query-string');
  });

  it('lockfile 6.0 gives the same graph and the same keys', async () => {
    const v6 = parsePnpmLockfile(await text('vulnerable-app', 'pnpm-v6', 'pnpm-lock.yaml'), { rootPackage: await appPackage() });
    assert.equal(v6.lockfileVersion, 6);
    assert.deepEqual(summarize(v6), summarize(graph));
    assert.deepEqual([...v6.nodes.keys()].sort(), [...graph.nodes.keys()].sort(), 'a pnpm upgrade that rewrites 6.0 as 9.0 changes no key');
  });

  it('works from the lockfile alone (the root specifiers)', async () => {
    const bare = parsePnpmLockfile(await text('vulnerable-app', 'pnpm-lock.yaml'));
    assert.deepEqual(bare.root.devDependencies, { semver: '5.7.1' });
    assert.equal(bare.root.dependencies.lodash, '4.17.20');
    assert.deepEqual(summarize(bare), summarize(graph));
  });
});

describe('pnpm lockfile: workspaces, peers, an alias, optional and dev dependencies', async () => {
  const { root } = await workspacePackages();
  const v9 = parsePnpmLockfile(await text('workspaces', 'pnpm-lock.yaml'), { rootPackage: root });
  const v6 = parsePnpmLockfile(await text('workspaces', 'pnpm-v6', 'pnpm-lock.yaml'), { rootPackage: root });

  it('matches the npm graph, plus the optional peers pnpm actually linked', async () => {
    const npm = summarize(await workspacesNpmGraph());
    // pnpm also links debug's optional peer
    const extra: Record<string, Partial<NodeSummary>> = {
      'supports-color@7.2.0': { parents: ['', 'debug@2.6.9', 'debug@4.3.4'], paths: ['debug@2.6.9 > supports-color@7.2.0', 'packages/b > debug@4.3.4 > supports-color@7.2.0', 'supports-color@7.2.0'] },
      'has-flag@4.0.0': { paths: [...(npm['has-flag@4.0.0'] as NodeSummary).paths, 'debug@2.6.9 > supports-color@7.2.0 > has-flag@4.0.0'].sort() },
    };
    for (const [id, patch] of Object.entries(extra)) npm[id] = { ...(npm[id] as NodeSummary), ...patch };
    assert.deepEqual(summarize(v9), npm);
    assert.deepEqual(summarize(v6), npm);
  });

  it('keeps peer suffixes in keys and strips them for the version', () => {
    const debug = v9.nodes.get('debug@2.6.9(supports-color@7.2.0)');
    assert.equal(debug?.version, '2.6.9');
    assert.equal(debug?.requires['supports-color'], '*', 'a peer keeps its declared range');
    assert.equal(v9.root.edges['use-sync-external-store'], 'use-sync-external-store@1.2.0(react@18.2.0)');
    assert.deepEqual([...v6.nodes.keys()].sort(), [...v9.nodes.keys()].sort());
    assert.equal(installedPath(v9, 'use-sync-external-store@1.2.0(react@18.2.0)'), 'node_modules/.pnpm/use-sync-external-store@1.2.0_react@18.2.0/node_modules/use-sync-external-store');
  });

  it('turns importers into the root and workspace folders and follows link: versions', () => {
    assert.deepEqual(v9.workspaceKeys, ['packages/a', 'packages/b']);
    assert.deepEqual(v9.root.workspaces, ['packages/*']);
    assert.deepEqual(v9.nodes.get('left-pad@1.3.0')?.parents, ['packages/a']);
    assert.equal(v9.nodes.get('left-pad@1.3.0')?.deprecated, 'use String.prototype.padStart()');
    assert.equal(v9.nodes.get('ms@2.1.3')?.dev, true);
    assert.equal(v9.nodes.get('is-number@7.0.0')?.optional, true);
  });

  it('maps an alias to its package', () => {
    assert.equal(v9.root.edges['my-lodash'], 'lodash@4.17.21');
    assert.equal(v9.nodes.get('lodash@4.17.21')?.alias, 'my-lodash');
    assert.equal(v6.nodes.get('lodash@4.17.21')?.alias, 'my-lodash');
  });
});

describe('pnpm keys and the virtual store', () => {
  it('normalises 5.x and 6.x keys to the 9.x form', () => {
    assert.equal(normalizePnpmKey('/lodash@4.17.21', 6), 'lodash@4.17.21');
    assert.equal(normalizePnpmKey('/@babel/core@7.0.0(supports-color@7.2.0)', 6), '@babel/core@7.0.0(supports-color@7.2.0)');
    assert.equal(normalizePnpmKey('/lodash/4.17.21', 5.4), 'lodash@4.17.21');
    assert.equal(normalizePnpmKey('/@babel/core/7.0.0_supports-color@7.2.0', 5.4), '@babel/core@7.0.0_supports-color@7.2.0');
    assert.deepEqual(splitPnpmKey('@babel/core@7.0.0_supports-color@7.2.0', 5.4), { name: '@babel/core', version: '7.0.0', base: '@babel/core@7.0.0' });
    assert.deepEqual(splitPnpmKey('debug@4.3.4(supports-color@7.2.0)'), { name: 'debug', version: '4.3.4', base: 'debug@4.3.4' });
  });

  it('derives the virtual store folder names pnpm 11 wrote for the workspaces fixture', () => {
    assert.equal(pnpmStorePath('@sindresorhus/is@4.6.0', '@sindresorhus/is'), 'node_modules/.pnpm/@sindresorhus+is@4.6.0/node_modules/@sindresorhus/is');
    assert.equal(pnpmStorePath('debug@4.3.4(supports-color@7.2.0)', 'debug'), 'node_modules/.pnpm/debug@4.3.4_supports-color@7.2.0/node_modules/debug');
    assert.equal(pnpmStorePath('Upper@1.0.0', 'Upper'), null, 'pnpm hashes upper-case folder names');
  });

  it('refines requires from the installed package.json, and loadDependencyGraph does it when node_modules/.pnpm exists', async () => {
    const tmp = await mkdtemp(path.join(os.tmpdir(), 'pp-pnpm-'));
    try {
      await cp(path.join(APP, 'package.json'), path.join(tmp, 'package.json'));
      await writeFile(path.join(tmp, 'pnpm-lock.yaml'), await text('vulnerable-app', 'pnpm-lock.yaml'));
      const store = path.join(tmp, 'node_modules', '.pnpm', 'query-string@6.14.1', 'node_modules', 'query-string');
      await mkdir(store, { recursive: true });
      await writeFile(
        path.join(store, 'package.json'),
        JSON.stringify({ name: 'query-string', version: '6.14.1', dependencies: { 'decode-uri-component': '^0.2.0', 'filter-obj': '^1.1.0', 'split-on-first': '^1.0.0', 'strict-uri-encode': '^2.0.0' } }),
      );
      const plain = parsePnpmLockfile(await text('vulnerable-app', 'pnpm-lock.yaml'));
      assert.equal(await refinePnpmRanges(plain, tmp), 1);
      assert.equal(plain.nodes.get('query-string@6.14.1')?.requires['decode-uri-component'], '^0.2.0');
      const loaded = await loadDependencyGraph(tmp, path.join(tmp, 'pnpm-lock.yaml'));
      assert.equal(loaded.nodes.get('query-string@6.14.1')?.requires['decode-uri-component'], '^0.2.0');
      assert.equal(loaded.nodes.get('json5@2.2.0')?.requires.minimist, '1.2.5', 'not installed: the resolved version stays');
      assert.equal(lockfileManager('pnpm-lock.yaml'), 'pnpm');
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it('explains an invalid or unversioned lockfile', () => {
    assert.throws(() => parsePnpmLockfile('lockfileVersion: 9.0\nimporters: [\n'), /not valid YAML.*pnpm install --lockfile-only/s);
    assert.throws(() => parsePnpmLockfile('importers: {}\n'), /no lockfileVersion/);
  });
});
