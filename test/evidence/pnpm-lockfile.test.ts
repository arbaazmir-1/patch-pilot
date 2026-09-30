import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { installedPath } from '../../src/evidence/lockfile.ts';
import { normalizePnpmKey, parsePnpmLockfile, pnpmStorePath, splitPnpmKey } from '../../src/evidence/lockfiles/pnpm.ts';
import type { NodeSummary } from './yarn-pnpm-helpers.ts';
import { summarize, text, workspacePackages, workspacesNpmGraph } from './yarn-pnpm-helpers.ts';

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

  it('explains an invalid or unversioned lockfile', () => {
    assert.throws(() => parsePnpmLockfile('lockfileVersion: 9.0\nimporters: [\n'), /not valid YAML.*pnpm install --lockfile-only/s);
    assert.throws(() => parsePnpmLockfile('importers: {}\n'), /no lockfileVersion/);
  });
});
