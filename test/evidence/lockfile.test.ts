import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  dependencyPaths,
  dependentsOf,
  graphCounts,
  loadDependencyGraph,
  nameFromKey,
  nodesByName,
  parseLockfile,
  readLockfile,
  resolveEdge,
  type LockfileJson,
} from '../../src/evidence/lockfile.ts';
import { FIXTURE_APP, tempDir } from './helpers.ts';

describe('lockfile v3: the fixture examples/vulnerable-app', async () => {
  const graph = await loadDependencyGraph(FIXTURE_APP, path.join(FIXTURE_APP, 'package-lock.json'));

  it('parses every package entry with its flags', () => {
    assert.equal(graph.lockfileVersion, 3);
    assert.equal(graph.nodes.size, 10);
    assert.deepEqual(graphCounts(graph), { total: 10, direct: 6, dev: 1 });
    const semver = graph.nodes.get('node_modules/semver');
    assert.ok(semver);
    assert.equal(semver.dev, true);
    assert.equal(semver.isDirect, true);
    assert.equal(graph.nodes.get('node_modules/decode-uri-component')?.isDirect, false);
    assert.equal(graph.nodes.get('node_modules/lodash')?.version, '4.17.20');
    assert.equal(graph.nodes.get('node_modules/lodash')?.license, 'MIT');
    assert.deepEqual(graph.workspaceKeys, []);
  });

  it('reads the root package (direct specs, engines) and resolves the root edges', () => {
    assert.equal(graph.root.name, 'vulnerable-app');
    assert.equal(graph.root.dependencies.lodash, '4.17.20');
    assert.equal(graph.root.devDependencies.semver, '5.7.1');
    assert.deepEqual(graph.root.engines, { node: '>=18' });
    assert.equal(graph.root.edges.minimist, 'node_modules/minimist');
    assert.equal(Object.keys(graph.root.edges).length, 6);
  });

  it('resolves package edges and parents (minimist is direct and required by json5)', () => {
    const json5 = graph.nodes.get('node_modules/json5');
    assert.deepEqual(json5?.requires, { minimist: '^1.2.5' });
    assert.deepEqual(json5?.edges, { minimist: 'node_modules/minimist' });
    assert.deepEqual(graph.nodes.get('node_modules/minimist')?.parents, ['', 'node_modules/json5']);
    assert.deepEqual(graph.nodes.get('node_modules/decode-uri-component')?.parents, ['node_modules/query-string']);
    assert.deepEqual(
      dependentsOf(graph, 'node_modules/decode-uri-component').map((n) => `${n.name}@${n.version}`),
      ['query-string@6.14.1'],
    );
    assert.deepEqual(graph.byName.get('lodash'), ['node_modules/lodash']);
  });

  it('computes shortest dependency paths from the root', () => {
    assert.deepEqual(dependencyPaths(graph, 'node_modules/minimist'), [['minimist@1.2.5'], ['json5@2.2.0', 'minimist@1.2.5']]);
    assert.deepEqual(dependencyPaths(graph, 'node_modules/decode-uri-component'), [['query-string@6.14.1', 'decode-uri-component@0.2.0']]);
    assert.deepEqual(dependencyPaths(graph, 'node_modules/minimist', { maxPaths: 1 }), [['minimist@1.2.5']]);
    assert.deepEqual(dependencyPaths(graph, 'node_modules/missing'), []);
  });
});

// nesting, scopes, alias, workspace link, flags
const NESTED: LockfileJson = {
  name: 'nested',
  version: '1.0.0',
  lockfileVersion: 3,
  packages: {
    '': {
      name: 'nested',
      version: '1.0.0',
      workspaces: ['packages/*'],
      dependencies: { a: '^1.0.0', c: '^1.0.0', 'my-alias': 'npm:real-pkg@^1.2.0', ws: '*' },
      devDependencies: { '@s/tool': '^3.0.0' },
      optionalDependencies: { opt: '^1.0.0' },
    },
    'node_modules/a': { version: '1.0.0', dependencies: { b: '^1.0.0', c: '^2.0.0' } },
    'node_modules/a/node_modules/b': { version: '1.0.0', dependencies: { c: '*', d: '^1.0.0', '@s/util': '^1.0.0' }, peerDependencies: { e: '^1.0.0' } },
    'node_modules/a/node_modules/c': { version: '2.0.0' },
    'node_modules/c': { version: '1.0.0' },
    'node_modules/d': { version: '1.0.0', devOptional: true },
    'node_modules/e': { version: '1.0.0', peer: true },
    'node_modules/@s/tool': { version: '3.0.0', dev: true, dependencies: { '@s/util': '^2.0.0' } },
    'node_modules/@s/tool/node_modules/@s/util': { version: '2.0.0', dev: true, inBundle: true },
    'node_modules/@s/util': { version: '1.0.0' },
    'node_modules/my-alias': { name: 'real-pkg', version: '1.2.3', deprecated: 'use other-pkg' },
    'node_modules/opt': { version: '1.0.0', optional: true, hasInstallScript: true },
    'node_modules/ws': { resolved: 'packages/ws', link: true },
    'packages/ws': { name: 'ws', version: '0.0.1', dependencies: { c: '^1.0.0', local: '^1.0.0' } },
    'packages/ws/node_modules/local': { version: '1.0.0' },
  },
};

describe('lockfile v3: nested node_modules, scopes, aliases, workspaces', () => {
  const graph = parseLockfile(NESTED);

  it('derives names from the last node_modules segment (scoped packages too)', () => {
    assert.equal(nameFromKey('node_modules/a/node_modules/@s/b'), '@s/b');
    assert.equal(nameFromKey('node_modules/lodash'), 'lodash');
    assert.equal(nameFromKey('packages/ws'), null);
    assert.equal(graph.nodes.get('node_modules/@s/tool/node_modules/@s/util')?.name, '@s/util');
  });

  it('resolves edges by walking up the nested node_modules folders', () => {
    const packages = NESTED.packages as Record<string, unknown>;
    // b needs c: nested 2.0.0 beats hoisted 1.0.0
    assert.equal(resolveEdge(packages, 'node_modules/a/node_modules/b', 'c'), 'node_modules/a/node_modules/c');
    // b needs d: top-level copy
    assert.equal(resolveEdge(packages, 'node_modules/a/node_modules/b', 'd'), 'node_modules/d');
    assert.equal(resolveEdge(packages, 'node_modules/a', 'c'), 'node_modules/a/node_modules/c');
    assert.equal(resolveEdge(packages, '', 'c'), 'node_modules/c');
    assert.equal(resolveEdge(packages, 'node_modules/@s/tool', '@s/util'), 'node_modules/@s/tool/node_modules/@s/util');
    assert.equal(resolveEdge(packages, 'node_modules/a/node_modules/b', '@s/util'), 'node_modules/@s/util');
    assert.equal(resolveEdge(packages, 'packages/ws', 'local'), 'packages/ws/node_modules/local');
    assert.equal(resolveEdge(packages, 'node_modules/a', 'missing'), null);
    const b = graph.nodes.get('node_modules/a/node_modules/b');
    assert.deepEqual(b?.edges, { e: 'node_modules/e', c: 'node_modules/a/node_modules/c', d: 'node_modules/d', '@s/util': 'node_modules/@s/util' });
  });

  it('keeps several installed versions under one name', () => {
    assert.deepEqual(graph.byName.get('c'), ['node_modules/a/node_modules/c', 'node_modules/c']);
    assert.deepEqual(
      nodesByName(graph, 'c').map((n) => n.version),
      ['2.0.0', '1.0.0'],
    );
    assert.deepEqual(nodesByName(graph, '@s/util').map((n) => n.version), ['2.0.0', '1.0.0']);
  });

  it('records flags: dev, optional, devOptional, peer, bundled, install scripts', () => {
    assert.equal(graph.nodes.get('node_modules/@s/tool')?.dev, true);
    assert.equal(graph.nodes.get('node_modules/opt')?.optional, true);
    assert.equal(graph.nodes.get('node_modules/opt')?.hasInstallScript, true);
    assert.equal(graph.nodes.get('node_modules/d')?.devOptional, true);
    assert.equal(graph.nodes.get('node_modules/e')?.peer, true);
    assert.equal(graph.nodes.get('node_modules/@s/tool/node_modules/@s/util')?.bundled, true);
    assert.equal(graph.nodes.get('node_modules/c')?.bundled, false);
  });

  it('maps an npm alias to the real package name', () => {
    const alias = graph.nodes.get('node_modules/my-alias');
    assert.equal(alias?.name, 'real-pkg');
    assert.equal(alias?.alias, 'my-alias');
    assert.equal(alias?.deprecated, 'use other-pkg');
    assert.equal(alias?.isDirect, true);
    assert.deepEqual(graph.byName.get('real-pkg'), ['node_modules/my-alias']);
    assert.equal(graph.byName.has('my-alias'), false);
  });

  it('skips link entries (workspaceKeys) and treats workspace dependencies as direct', () => {
    assert.deepEqual(graph.workspaceKeys, ['node_modules/ws']);
    assert.equal(graph.nodes.has('node_modules/ws'), false);
    assert.equal(graph.nodes.has('packages/ws'), false);
    assert.equal(graph.root.edges.ws, 'packages/ws');
    assert.deepEqual(graph.root.workspaces, ['packages/*']);
    const local = graph.nodes.get('packages/ws/node_modules/local');
    assert.equal(local?.isDirect, true);
    assert.deepEqual(local?.parents, ['packages/ws']);
    assert.deepEqual(dependencyPaths(graph, 'packages/ws/node_modules/local'), [['packages/ws', 'local@1.0.0']]);
    assert.ok(graph.nodes.get('node_modules/c')?.parents.includes('packages/ws'));
  });

  it('finds several paths, shortest first, and caps them', () => {
    assert.deepEqual(dependencyPaths(graph, 'node_modules/d'), [['a@1.0.0', 'b@1.0.0', 'd@1.0.0']]);
    assert.deepEqual(dependencyPaths(graph, 'node_modules/c'), [['c@1.0.0'], ['packages/ws', 'c@1.0.0']]);
    assert.deepEqual(dependencyPaths(graph, 'node_modules/@s/util'), [['a@1.0.0', 'b@1.0.0', '@s/util@1.0.0']]);
  });

  it('terminates on cycles and respects the depth cap', () => {
    const cyclic = parseLockfile({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { x: '*' } },
        'node_modules/x': { version: '1.0.0', dependencies: { y: '*' } },
        'node_modules/y': { version: '1.0.0', dependencies: { x: '*', z: '*' } },
        'node_modules/z': { version: '1.0.0' },
      },
    });
    assert.deepEqual(dependencyPaths(cyclic, 'node_modules/z'), [['x@1.0.0', 'y@1.0.0', 'z@1.0.0']]);
    assert.deepEqual(dependencyPaths(cyclic, 'node_modules/z', { maxDepth: 1 }), []);
    assert.deepEqual(dependencyPaths(cyclic, 'node_modules/x'), [['x@1.0.0']]);
  });

  it('uses package.json for the root specs when given', () => {
    const withPkg = parseLockfile(NESTED, { name: 'from-package-json', dependencies: { a: '1.0.0' } });
    assert.equal(withPkg.root.name, 'from-package-json');
    assert.deepEqual(withPkg.root.dependencies, { a: '1.0.0' });
    assert.deepEqual(Object.keys(withPkg.root.edges).sort(), ['@s/tool', 'opt', 'a'].sort());
  });
});

describe('lockfile v1 (nested dependencies tree)', () => {
  const V1: LockfileJson = {
    name: 'old-app',
    version: '0.1.0',
    lockfileVersion: 1,
    requires: true,
    dependencies: {
      a: { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', requires: { b: '^2.0.0', c: '^1.0.0' }, dependencies: { b: { version: '2.0.0' } } },
      b: { version: '1.0.0', dev: true },
      c: { version: '1.1.0', optional: true, bundled: true },
      al: { version: 'npm:real@1.0.0' },
    },
  };

  it('converts the tree and resolves nested requires', () => {
    const graph = parseLockfile(V1, { name: 'old-app', dependencies: { a: '^1.0.0', al: 'npm:real@^1.0.0' }, devDependencies: { b: '^1.0.0' } });
    assert.equal(graph.lockfileVersion, 1);
    assert.equal(graph.nodes.size, 5);
    assert.deepEqual(graph.nodes.get('node_modules/a')?.edges, { b: 'node_modules/a/node_modules/b', c: 'node_modules/c' });
    assert.equal(graph.nodes.get('node_modules/a/node_modules/b')?.version, '2.0.0');
    assert.equal(graph.nodes.get('node_modules/b')?.dev, true);
    assert.equal(graph.nodes.get('node_modules/b')?.isDirect, true);
    assert.equal(graph.nodes.get('node_modules/a/node_modules/b')?.isDirect, false);
    assert.equal(graph.nodes.get('node_modules/c')?.bundled, true);
    assert.equal(graph.nodes.get('node_modules/c')?.optional, true);
    const alias = graph.nodes.get('node_modules/al');
    assert.equal(alias?.name, 'real');
    assert.equal(alias?.version, '1.0.0');
    assert.equal(alias?.alias, 'al');
    assert.deepEqual(dependencyPaths(graph, 'node_modules/a/node_modules/b'), [['a@1.0.0', 'b@2.0.0']]);
  });

  it('infers direct dependencies without package.json', () => {
    const graph = parseLockfile(V1);
    assert.equal(graph.root.name, 'old-app');
    assert.deepEqual(Object.keys(graph.root.dependencies).sort(), ['a', 'al']);
    assert.deepEqual(Object.keys(graph.root.devDependencies), ['b']);
    assert.equal(graph.nodes.get('node_modules/c')?.isDirect, false);
  });
});

describe('readLockfile', () => {
  it('explains invalid JSON with the command that regenerates the lockfile', async () => {
    const tmp = await tempDir();
    try {
      const file = path.join(tmp.dir, 'package-lock.json');
      await writeFile(file, '{ "lockfileVersion": 3, <<<<<<< HEAD');
      await assert.rejects(readLockfile(file), /not valid JSON.*npm install --package-lock-only/s);
      await assert.rejects(readLockfile(path.join(tmp.dir, 'missing.json')), /Cannot read the lockfile/);
    } finally {
      await tmp.cleanup();
    }
  });
});
