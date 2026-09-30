import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  dependencyPaths,
  nameFromKey,
  nodesByName,
  parseLockfile,
  readLockfile,
  resolveEdge,
  type LockfileJson,
} from '../../src/evidence/lockfile.ts';
import { tempDir } from './helpers.ts';

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
