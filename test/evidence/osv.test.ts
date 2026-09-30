import assert from 'node:assert/strict';
import path from 'node:path';
import { after, afterEach, before, describe, it } from 'node:test';
import { META_KEYS, openDb, type PatchPilotDb } from '../../src/evidence/db.ts';
import { fetchVuln, formatDataAge, pairKey, queryBatch, queryOsv, type OsvPackageVersion } from '../../src/evidence/osv.ts';
import { EnvironmentError } from '../../src/util/errors.ts';
import { fixtureData, fixtureServer, jsonResponse, stubFetch, tempDir, type FixtureData } from './helpers.ts';

const FIXTURE_PAIRS: OsvPackageVersion[] = [
  ['decode-uri-component', '0.2.0'],
  ['filter-obj', '1.1.0'],
  ['json5', '2.2.0'],
  ['lodash', '4.17.20'],
  ['marked', '0.3.6'],
  ['minimist', '1.2.5'],
  ['query-string', '6.14.1'],
  ['semver', '5.7.1'],
  ['split-on-first', '1.1.0'],
  ['strict-uri-encode', '2.0.0'],
].map(([name, version]) => ({ name: name as string, version: version as string }));

const LODASH_IDS = ['GHSA-29mw-wpgm-hmr9', 'GHSA-35jh-r3h4-6jhm', 'GHSA-f23m-r3pf-42rh', 'GHSA-r5fr-rjxr-66jc', 'GHSA-xxjr-mmjv-4gpg'];

describe('queryOsv', () => {
  let data: FixtureData;
  let tmp: { dir: string; cleanup: () => Promise<void> };
  let stub: ReturnType<typeof stubFetch> | null = null;
  const dbs: PatchPilotDb[] = [];
  const newDb = (name: string): PatchPilotDb => {
    const db = openDb(path.join(tmp.dir, `${name}.db`));
    dbs.push(db);
    return db;
  };

  before(async () => {
    data = await fixtureData();
    tmp = await tempDir('pp-osv-');
  });
  afterEach(() => {
    stub?.restore();
    stub = null;
  });
  after(async () => {
    for (const db of dbs) db.close();
    await tmp.cleanup();
  });

  it('queries in one batch, hydrates every id and caches both', async () => {
    const db = newDb('live');
    stub = stubFetch(fixtureServer(data));
    const progress: string[] = [];
    const result = await queryOsv([...FIXTURE_PAIRS, FIXTURE_PAIRS[3] as OsvPackageVersion], {
      db,
      offline: false,
      timeoutMs: 5_000,
      onProgress: (_done, _total, label) => progress.push(label),
    });
    assert.equal(result.source.mode, 'live');
    assert.equal(result.source.ageHours, 0);
    assert.equal(result.source.warning, undefined);
    assert.deepEqual(result.stats.queried, 10);
    assert.equal(result.stats.vulnIds, 15);
    assert.equal(result.stats.hydrated, 15);
    assert.equal(result.stats.cacheHits, 0);
    assert.deepEqual([...(result.idsByPackage.get('lodash@4.17.20') ?? [])].sort(), LODASH_IDS);
    assert.deepEqual(result.idsByPackage.get('filter-obj@1.1.0'), []);
    assert.equal(result.records.size, 15);
    const posts = stub.calls.filter((c) => c.method === 'POST');
    assert.equal(posts.length, 1);
    const body = JSON.parse(posts[0]?.body ?? '{}') as { queries: unknown[] };
    assert.equal(body.queries.length, 10);
    assert.deepEqual(body.queries[0], { package: { name: 'decode-uri-component', ecosystem: 'npm' }, version: '0.2.0' });
    assert.equal(stub.calls.filter((c) => c.url.startsWith('https://api.osv.dev/v1/vulns/')).length, 15);
    assert.ok(progress.includes('querybatch'));
    assert.deepEqual(db.getQuery('lodash', '4.17.20')?.ids.sort(), LODASH_IDS);
    assert.ok(db.getVuln('GHSA-xvch-5gv4-984h'));
  });

  it('skips hydration when the cached modified matches (microseconds vs nanoseconds)', async () => {
    const db = newDb('live');
    stub = stubFetch(fixtureServer(data));
    const result = await queryOsv(FIXTURE_PAIRS, { db, offline: false, timeoutMs: 5_000 });
    assert.equal(result.source.mode, 'live');
    assert.equal(result.stats.hydrated, 0);
    assert.equal(result.stats.cacheHits, 15);
    assert.equal(stub.calls.length, 1, 'only the querybatch');
    const refreshed = await queryOsv(FIXTURE_PAIRS, { db, offline: false, timeoutMs: 5_000, refresh: true });
    assert.equal(refreshed.stats.hydrated, 15);
  });

  it('re-downloads a record whose modified changed', async () => {
    const db = newDb('live');
    const bumped = structuredClone(data);
    const entry = bumped.querybatch['minimist@1.2.5']?.[0];
    assert.ok(entry);
    entry.modified = '2027-01-01T00:00:00Z';
    stub = stubFetch(fixtureServer(bumped));
    const result = await queryOsv(FIXTURE_PAIRS, { db, offline: false, timeoutMs: 5_000 });
    assert.equal(result.stats.hydrated, 1);
    assert.deepEqual(
      stub.calls.filter((c) => c.method === 'GET').map((c) => c.url),
      ['https://api.osv.dev/v1/vulns/GHSA-xvch-5gv4-984h'],
    );
  });

  it('splits large inputs into chunks', async () => {
    stub = stubFetch(fixtureServer(data));
    const result = await queryOsv(FIXTURE_PAIRS, { db: null, offline: false, timeoutMs: 5_000, chunkSize: 3 });
    assert.equal(stub.calls.filter((c) => c.method === 'POST').length, 4);
    assert.equal(result.stats.vulnIds, 15);
  });

  it('follows next_page_token for huge result sets', async () => {
    let page = 0;
    stub = stubFetch((call) => {
      if (call.method === 'POST') {
        page += 1;
        const body = JSON.parse(call.body ?? '{}') as { queries: { page_token?: string }[] };
        if (page === 1) return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-1', modified: '2026-01-01T00:00:00Z' }], next_page_token: 'tok' }, {}] });
        assert.equal(body.queries.length, 1);
        assert.equal(body.queries[0]?.page_token, 'tok');
        return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-2', modified: '2026-01-01T00:00:00Z' }, { id: 'GHSA-1', modified: '2026-01-01T00:00:00Z' }] }] });
      }
      return jsonResponse({ code: 5 }, 404);
    });
    const pages = await queryBatch(
      [
        { name: 'a', version: '1.0.0' },
        { name: 'b', version: '1.0.0' },
      ],
      { timeoutMs: 5_000 },
    );
    assert.deepEqual(pages, [
      [
        { id: 'GHSA-1', modified: '2026-01-01T00:00:00Z' },
        { id: 'GHSA-2', modified: '2026-01-01T00:00:00Z' },
      ],
      [],
    ]);
  });

  it('skips withdrawn records and keeps MAL-* records', async () => {
    const withdrawn = { id: 'GHSA-gone', modified: '2026-01-01T00:00:00Z', withdrawn: '2026-02-01T00:00:00Z', summary: 'withdrawn' };
    const malware = { id: 'MAL-2026-1', modified: '2026-01-01T00:00:00Z', summary: 'Malicious code in evil-pkg', affected: [{ package: { name: 'evil-pkg', ecosystem: 'npm' }, versions: ['1.0.0'] }] };
    stub = stubFetch((call) => {
      if (call.method === 'POST') return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-gone', modified: withdrawn.modified }, { id: 'MAL-2026-1', modified: malware.modified }] }] });
      return jsonResponse(call.url.endsWith('GHSA-gone') ? withdrawn : malware);
    });
    const result = await queryOsv([{ name: 'evil-pkg', version: '1.0.0' }], { db: null, offline: false, timeoutMs: 5_000 });
    assert.deepEqual(result.idsByPackage.get('evil-pkg@1.0.0'), ['MAL-2026-1']);
    assert.equal(result.records.has('GHSA-gone'), false);
    assert.equal(result.stats.vulnIds, 1);
  });

  it('falls back to the query cache when OSV.dev is unreachable', async () => {
    const db = newDb('live');
    stub = stubFetch(fixtureServer(data, { osvDown: true }));
    const result = await queryOsv(FIXTURE_PAIRS, { db, offline: false, timeoutMs: 5_000 });
    assert.equal(result.source.mode, 'cache');
    assert.match(result.source.warning ?? '', /could not be reached \(Connection failed \(ECONNREFUSED\)/);
    assert.match(result.source.warning ?? '', /10 of 10 packages were checked against cached data/);
    assert.deepEqual([...(result.idsByPackage.get('lodash@4.17.20') ?? [])].sort(), LODASH_IDS);
    assert.equal(result.records.size, 15);
    assert.ok(result.source.ageHours < 1);
  });

  it('reads only the cache offline and warns when the data is older than 7 days', async () => {
    const db = newDb('live');
    const nineDaysAgo = new Date(Date.now() - 9 * 24 * 3_600_000).toISOString();
    db.putQueries(FIXTURE_PAIRS.map((p) => ({ pkg: p.name, version: p.version, ids: db.getQuery(p.name, p.version)?.ids ?? [], fetchedAt: nineDaysAgo })));
    stub = stubFetch(() => {
      throw new Error('offline mode must not touch the network');
    });
    const result = await queryOsv(FIXTURE_PAIRS, { db, offline: true, timeoutMs: 5_000 });
    assert.equal(stub.calls.length, 0);
    assert.equal(result.source.mode, 'cache');
    assert.equal(result.source.fetchedAt, nineDaysAgo);
    assert.ok(Math.abs(result.source.ageHours - 216) < 0.1);
    assert.match(result.source.warning ?? '', /Vulnerability data is 9 days old/);
    assert.doesNotMatch(result.source.warning ?? '', /could not be reached/);
  });

  it('evaluates the offline snapshot when a package is not in the query cache', async () => {
    const db = newDb('snapshot');
    const records = data.records.filter((r) => LODASH_IDS.includes(r.id));
    db.putVulns(records, 'snapshot');
    db.putSnapshotAffected(
      records.flatMap((r) =>
        (r.affected ?? []).filter((a) => a.package?.ecosystem === 'npm').map((a) => ({ pkg: a.package?.name ?? '', id: r.id, ranges: a.ranges ?? [], versions: a.versions ?? null })),
      ),
    );
    const loadedAt = new Date(Date.now() - 2 * 3_600_000).toISOString();
    db.setSnapshotInfo({ loadedAt, source: 'test' });
    assert.equal(db.getMeta(META_KEYS.snapshotLoadedAt), loadedAt);
    const result = await queryOsv(
      [
        { name: 'lodash', version: '4.17.20' },
        { name: 'lodash', version: '4.17.21' },
        { name: 'lodash', version: '4.18.1' },
      ],
      { db, offline: true, timeoutMs: 5_000 },
    );
    assert.equal(result.source.mode, 'snapshot');
    assert.equal(result.source.fetchedAt, loadedAt);
    assert.deepEqual([...(result.idsByPackage.get('lodash@4.17.20') ?? [])].sort(), LODASH_IDS);
    assert.deepEqual([...(result.idsByPackage.get('lodash@4.17.21') ?? [])].sort(), ['GHSA-f23m-r3pf-42rh', 'GHSA-r5fr-rjxr-66jc', 'GHSA-xxjr-mmjv-4gpg']);
    assert.deepEqual(result.idsByPackage.get('lodash@4.18.1'), []);
  });

  it('refuses to report zero findings when there is no data at all', async () => {
    const db = newDb('empty');
    stub = stubFetch(fixtureServer(data, { osvDown: true }));
    await assert.rejects(queryOsv(FIXTURE_PAIRS, { db, offline: false, timeoutMs: 5_000 }), (err: unknown) => {
      assert.ok(err instanceof EnvironmentError);
      assert.equal(err.exitCode, 3);
      assert.match(err.message, /OSV\.dev is unreachable/);
      assert.match(err.hint ?? '', /patch-pilot db sync/);
      return true;
    });
    await assert.rejects(queryOsv(FIXTURE_PAIRS, { db, offline: true, timeoutMs: 5_000 }), /Offline mode is on/);
    const none = await queryOsv([], { db, offline: true, timeoutMs: 5_000 });
    assert.equal(none.idsByPackage.size, 0);
  });

  it('uses a stale cached record when its download fails, and reports missing ones', async () => {
    const db = newDb('partial');
    const [first, second] = data.records;
    assert.ok(first && second);
    db.putVulns([first]);
    stub = stubFetch((call) => {
      if (call.method === 'POST') return jsonResponse({ results: [{ vulns: [{ id: first.id, modified: '2030-01-01T00:00:00Z' }, { id: second.id, modified: second.modified }] }] });
      return jsonResponse({ error: 'boom' }, 500);
    });
    const result = await queryOsv([{ name: 'x', version: '1.0.0' }], { db, offline: false, timeoutMs: 5_000 });
    assert.deepEqual(result.idsByPackage.get('x@1.0.0'), [first.id]);
    assert.match(result.source.warning ?? '', /1 vulnerability record could not be loaded/);
  });

  it('fetchVuln returns null for an unknown id and formats data age', async () => {
    stub = stubFetch(() => jsonResponse({ code: 5, message: 'Bug not found.' }, 404));
    assert.equal(await fetchVuln('GHSA-none', { timeoutMs: 5_000 }), null);
    assert.equal(stub.calls[0]?.url, 'https://api.osv.dev/v1/vulns/GHSA-none');
    assert.equal(pairKey('@s/a', '1.0.0'), '@s/a@1.0.0');
    assert.equal(formatDataAge(0), 'just now');
    assert.equal(formatDataAge(0.5), '30 min old');
    assert.equal(formatDataAge(2.2), '2 h old');
    assert.equal(formatDataAge(24 * 9), '9 days old');
  });
});
