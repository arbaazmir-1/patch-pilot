import assert from 'node:assert/strict';
import path from 'node:path';
import { after, afterEach, before, beforeEach, describe, it } from 'node:test';
import { openDb, type PatchPilotDb } from '../../src/evidence/db.ts';
import {
  clearRegistryMemo,
  encodePackageName,
  getAvailableVersions,
  getDeprecatedVersions,
  getDeprecation,
  getEnginesNode,
  getPackument,
  getRepository,
  getVersionManifest,
  parseRepositoryUrl,
  type RegistryOptions,
} from '../../src/evidence/registry.ts';
import type { AbbreviatedPackument } from '../../src/types.ts';
import { fixtureData, jsonResponse, refused, stubFetch, tempDir } from './helpers.ts';

describe('registry client', () => {
  let tmp: { dir: string; cleanup: () => Promise<void> };
  let db: PatchPilotDb;
  let lodash: AbbreviatedPackument;
  let stub: ReturnType<typeof stubFetch> | null = null;
  const opts = (extra: Partial<RegistryOptions> = {}): RegistryOptions => ({ db, offline: false, timeoutMs: 5_000, ...extra });
  const manifests: Record<string, unknown> = {
    'marked/0.3.6': { name: 'marked', version: '0.3.6', repository: { type: 'git', url: 'git://github.com/chjj/marked.git' }, homepage: 'https://github.com/chjj/marked' },
    '@babel%2Fcore/7.0.0': { name: '@babel/core', version: '7.0.0', repository: { type: 'git', url: 'https://github.com/babel/babel/tree/master/packages/babel-core' } },
    'mono/1.0.0': { name: 'mono', version: '1.0.0', repository: { type: 'git', url: 'git+https://github.com/o/mono.git', directory: 'packages/mono' } },
    'short/1.0.0': { name: 'short', version: '1.0.0', repository: 'owner/short' },
    'home/1.0.0': { name: 'home', version: '1.0.0', homepage: 'https://gitlab.com/group/sub/home#readme' },
    'bare/1.0.0': { name: 'bare', version: '1.0.0' },
  };
  const server = () =>
    stubFetch((call) => {
      const rest = call.url.slice('https://registry.npmjs.org/'.length);
      if (rest === 'lodash') return jsonResponse({ ...lodash, versions: { ...lodash.versions, '4.17.20': { version: '4.17.20', bin: { x: 'y' }, dist: { tarball: 't', integrity: 'i', fileCount: 3 } } } });
      if (rest in manifests) return jsonResponse(manifests[rest]);
      return jsonResponse({ error: 'Not found' }, 404);
    });

  before(async () => {
    tmp = await tempDir('pp-registry-');
    db = openDb(path.join(tmp.dir, 'r.db'));
    lodash = (await fixtureData()).packuments.lodash as AbbreviatedPackument;
  });
  beforeEach(() => clearRegistryMemo());
  afterEach(() => {
    stub?.restore();
    stub = null;
  });
  after(async () => {
    db.close();
    await tmp.cleanup();
  });

  it('encodes scoped package names for URLs', () => {
    assert.equal(encodePackageName('lodash'), 'lodash');
    assert.equal(encodePackageName('@babel/core'), '@babel%2Fcore');
  });

  it('fetches the abbreviated packument, trims it and caches it in SQLite', async () => {
    stub = server();
    const packument = await getPackument('lodash', opts());
    assert.equal(stub.calls.length, 1);
    assert.match(stub.calls[0]?.headers.accept ?? '', /^application\/vnd\.npm\.install-v1\+json/);
    assert.equal(packument?.['dist-tags'].latest, '4.18.1');
    assert.deepEqual(packument?.versions['4.17.20'], { version: '4.17.20', dist: { tarball: 't', integrity: 'i' } }, 'unused fields are dropped');
    clearRegistryMemo();
    const again = await getPackument('lodash', opts());
    assert.equal(stub.calls.length, 1, 'served from registry_cache');
    assert.equal(again?.name, 'lodash');
    await getPackument('lodash', opts({ maxAgeMs: 0 }));
    assert.equal(stub.calls.length, 2, 'an expired entry is fetched again');
    await getPackument('lodash', opts({ refresh: true }));
    assert.equal(stub.calls.length, 3);
  });

  it('answers deprecations, versions and engines from the packument', async () => {
    stub = server();
    assert.deepEqual([...(await getDeprecatedVersions('lodash', opts()))], ['4.18.0']);
    const versions = await getAvailableVersions('lodash', opts());
    assert.deepEqual(versions.slice(-4), ['4.17.21', '4.17.23', '4.18.0', '4.18.1']);
    assert.equal(await getDeprecation('lodash', '4.18.0', opts()), 'Bad release. Please use lodash@4.17.21 instead.');
    assert.equal(await getDeprecation('lodash', '4.18.1', opts()), null);
    assert.equal(await getEnginesNode('lodash', '4.18.1', opts()), null);
    assert.ok(stub.calls.length <= 1, 'one packument (fetched once, or already cached) serves every lookup');
  });

  it('caches a 404 as null and uses only the cache offline', async () => {
    stub = server();
    assert.equal(await getPackument('does-not-exist', opts()), null);
    clearRegistryMemo();
    assert.equal(await getPackument('does-not-exist', opts()), null);
    assert.equal(stub.calls.length, 1);
    assert.deepEqual(await getAvailableVersions('does-not-exist', opts()), []);
    stub.restore();
    stub = stubFetch(() => {
      throw new Error('offline lookups must not fetch');
    });
    clearRegistryMemo();
    assert.equal((await getPackument('lodash', opts({ offline: true, maxAgeMs: 0 })))?.name, 'lodash', 'a stale copy is fine offline');
    assert.equal(await getPackument('never-cached', opts({ offline: true })), null);
    assert.equal(stub.calls.length, 0);
  });

  it('falls back to a stale copy when the registry is down, and throws without one', async () => {
    stub = stubFetch(() => refused());
    clearRegistryMemo();
    assert.equal((await getPackument('lodash', opts({ maxAgeMs: 0 })))?.name, 'lodash');
    await assert.rejects(getPackument('uncached-package', opts()), /ECONNREFUSED/);
  });

  it('reads repositories from version manifests', async () => {
    stub = server();
    assert.deepEqual(await getRepository('marked', '0.3.6', opts()), { url: 'https://github.com/chjj/marked', host: 'github', owner: 'chjj', repo: 'marked', directory: null });
    assert.deepEqual(await getRepository('@babel/core', '7.0.0', opts()), {
      url: 'https://github.com/babel/babel',
      host: 'github',
      owner: 'babel',
      repo: 'babel',
      directory: 'packages/babel-core',
    });
    assert.equal((await getRepository('mono', '1.0.0', opts()))?.directory, 'packages/mono');
    assert.equal((await getRepository('short', '1.0.0', opts()))?.url, 'https://github.com/owner/short');
    assert.deepEqual(await getRepository('home', '1.0.0', opts()), { url: 'https://gitlab.com/group/sub/home', host: 'gitlab', owner: 'group/sub', repo: 'home', directory: null });
    assert.equal(await getRepository('bare', '1.0.0', opts()), null);
    assert.equal(await getRepository('missing', '1.0.0', opts()), null);
    assert.equal((await getVersionManifest('marked', '0.3.6', opts()))?.version, '0.3.6');
    assert.ok(stub.calls.some((c) => c.url === 'https://registry.npmjs.org/@babel%2Fcore/7.0.0'));
  });

  it('normalises repository URLs', () => {
    const cases: [string, string | null, string | null, string | null][] = [
      ['git+https://github.com/lodash/lodash.git', 'https://github.com/lodash/lodash', 'lodash', 'lodash'],
      ['git://github.com/chjj/marked.git', 'https://github.com/chjj/marked', 'chjj', 'marked'],
      ['git+ssh://git@github.com/o/r.git', 'https://github.com/o/r', 'o', 'r'],
      ['git@github.com:o/r.git', 'https://github.com/o/r', 'o', 'r'],
      ['https://www.github.com/o/r/', 'https://github.com/o/r', 'o', 'r'],
      ['http://github.com/o/r#readme', 'https://github.com/o/r', 'o', 'r'],
      ['github:o/r', 'https://github.com/o/r', 'o', 'r'],
      ['o/r', 'https://github.com/o/r', 'o', 'r'],
      ['gitlab:g/sub/r', 'https://gitlab.com/g/sub/r', 'g/sub', 'r'],
      ['https://gitlab.com/g/r/-/tree/main', 'https://gitlab.com/g/r', 'g', 'r'],
      ['bitbucket:o/r', 'https://bitbucket.org/o/r', 'o', 'r'],
      ['https://git.example.com/team/lib.git', 'https://git.example.com/team/lib', 'team', 'lib'],
    ];
    for (const [input, url, owner, repo] of cases) {
      const info = parseRepositoryUrl(input);
      assert.equal(info?.url ?? null, url, input);
      assert.equal(info?.owner ?? null, owner, input);
      assert.equal(info?.repo ?? null, repo, input);
    }
    assert.equal(parseRepositoryUrl('https://github.com/o/r/tree/main/packages/x')?.directory, 'packages/x');
    assert.equal(parseRepositoryUrl('git+https://github.com/o/r.git', './packages/y/')?.directory, 'packages/y');
    assert.equal(parseRepositoryUrl('https://github.com/o/r')?.host, 'github');
    assert.equal(parseRepositoryUrl('https://example.org/x')?.host, 'other');
    assert.equal(parseRepositoryUrl(''), null);
    assert.equal(parseRepositoryUrl('not a url at all'), null);
    assert.equal(parseRepositoryUrl('file:../local'), null);
  });
});
