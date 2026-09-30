import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { after, afterEach, before, describe, it, mock } from 'node:test';
import { strToU8, Unzip, UnzipInflate, zipSync } from 'fflate';
import { loadConfig } from '../../src/config.ts';
import { META_KEYS, openDb, type SnapshotAffectedRow } from '../../src/evidence/db.ts';
import {
  INCREMENTAL_MAX,
  isMalwareId,
  loadSnapshotZip,
  MALWARE_META_KEY,
  OSV_NPM_MODIFIED,
  OSV_NPM_RECORD_BASE,
  OSV_NPM_ZIP,
  parseSnapshotRecord,
  planIncremental,
  readModifiedSince,
  renderDbStatus,
  snapshotMatches,
  snapshotRowsFor,
  snapshotStatus,
  syncSnapshot,
  trimUnzipState,
  type SnapshotSink,
} from '../../src/evidence/snapshot.ts';
import type { Config, OsvRecord } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

function osv(id: string, modified: string, affected: OsvRecord['affected'], extra: Partial<OsvRecord> = {}): OsvRecord {
  return { id, modified, summary: `${id} summary`, affected, ...extra };
}

const semver = (...events: Record<string, string>[]): { type: 'SEMVER'; events: never[] } => ({ type: 'SEMVER', events: events as never[] });

const LODASH = osv('GHSA-35jh-r3h4-6jhm', '2024-01-02T03:04:05.123456789Z', [
  { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [semver({ introduced: '0' }, { fixed: '4.17.21' })] },
]);
const MINIMIST = osv('GHSA-xvch-5gv4-984h', '2024-02-01T00:00:00Z', [
  { package: { name: 'minimist', ecosystem: 'npm' }, ranges: [semver({ introduced: '0' }, { fixed: '0.2.4' })] },
  // same package merges into one row
  { package: { name: 'minimist', ecosystem: 'npm' }, ranges: [semver({ introduced: '1.0.0' }, { fixed: '1.2.6' })] },
]);
const LISTED = osv('GHSA-list-only-0001', '2024-02-02T00:00:00Z', [{ package: { name: 'tiny', ecosystem: 'npm' }, versions: ['1.0.0', '1.0.1'] }]);
const WITHDRAWN = osv('GHSA-with-draw-0001', '2024-03-01T00:00:00Z', [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [semver({ introduced: '0' })] }], {
  withdrawn: '2024-03-01T00:00:00Z',
});
const PYPI = osv('PYSEC-2024-1', '2024-01-01T00:00:00Z', [{ package: { name: 'requests', ecosystem: 'PyPI' }, ranges: [semver({ introduced: '0' })] }]);
const MALWARE = osv('MAL-2026-6371', '2026-09-24T09:41:11.407995532Z', [{ package: { name: 'evil-pkg', ecosystem: 'npm' }, ranges: [semver({ introduced: '0' })] }]);

function buildZip(records: readonly OsvRecord[], extra: Record<string, Uint8Array> = {}): Uint8Array {
  const files: Record<string, Uint8Array> = {};
  for (const r of records) files[`${r.id}.json`] = strToU8(JSON.stringify(r));
  return zipSync({ ...files, ...extra }, { level: 6 });
}

async function* chunked(bytes: Uint8Array, size: number): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
}

class FakeSink implements SnapshotSink {
  vulns: OsvRecord[] = [];
  rows: SnapshotAffectedRow[] = [];
  deleted: string[] = [];
  transactions = 0;
  transaction<T>(fn: () => T): T {
    this.transactions += 1;
    return fn();
  }
  putVulns(records: readonly OsvRecord[]): void {
    this.vulns.push(...records);
  }
  putSnapshotAffected(rows: readonly SnapshotAffectedRow[]): void {
    this.rows.push(...rows);
  }
  deleteSnapshotIds(ids: readonly string[]): void {
    this.deleted.push(...ids);
  }
}

// temp home, fake network

let home: string;
let config: Config;
before(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), 'pp-db-'));
  config = await loadConfig({ dir: home, cwd: home, homeDir: home, env: {}, flags: {}, stdinIsTTY: false, stdoutIsTTY: false });
});
after(async () => {
  await rm(home, { recursive: true, force: true });
});
afterEach(() => mock.restoreAll());

function capture(): { ui: Ui; out: () => string } {
  let buf = '';
  const stream = new Writable({
    write(chunk, _enc, cb) {
      buf += String(chunk);
      cb();
    },
  });
  return { ui: new Ui({ color: false, env: {}, stdout: stream as never, stderr: stream as never }), out: () => buf };
}

interface Network {
  zip: Uint8Array;
  csv: string;
  records: Map<string, OsvRecord>;
  calls: string[];
}

function network(net: Network): void {
  mock.method(globalThis, 'fetch', async (input: string | URL) => {
    const url = String(input);
    net.calls.push(url);
    if (url === OSV_NPM_ZIP) return new Response(net.zip, { headers: { 'content-length': String(net.zip.byteLength), 'content-type': 'application/zip' } });
    if (url === OSV_NPM_MODIFIED) return new Response(net.csv, { headers: { 'content-type': 'text/csv' } });
    if (url.startsWith(`${OSV_NPM_RECORD_BASE}/`)) {
      const id = decodeURIComponent(url.slice(OSV_NPM_RECORD_BASE.length + 1).replace(/\.json$/, ''));
      const record = net.records.get(id);
      return record ? new Response(JSON.stringify(record), { headers: { 'content-type': 'application/json' } }) : new Response('not found', { status: 404 });
    }
    return new Response('unexpected', { status: 500 });
  });
}

const csvLine = (modified: string, id: string): string => `${modified},${id}`;

describe('records and index rows', () => {
  it('recognises malware ids and entries', () => {
    assert.equal(isMalwareId('MAL-2026-6371'), true);
    assert.equal(isMalwareId('npm/MAL-2026-6371.json'), true);
    assert.equal(isMalwareId('GHSA-35jh-r3h4-6jhm.json'), false);
  });

  it('indexes npm packages with merged ranges and listed versions, never withdrawn or other ecosystems', () => {
    assert.deepEqual(snapshotRowsFor(MINIMIST), [
      { pkg: 'minimist', id: 'GHSA-xvch-5gv4-984h', ranges: [semver({ introduced: '0' }, { fixed: '0.2.4' }), semver({ introduced: '1.0.0' }, { fixed: '1.2.6' })], versions: null },
    ]);
    assert.deepEqual(snapshotRowsFor(LISTED), [{ pkg: 'tiny', id: 'GHSA-list-only-0001', ranges: [], versions: ['1.0.0', '1.0.1'] }]);
    assert.deepEqual(snapshotRowsFor(WITHDRAWN), []);
    assert.deepEqual(snapshotRowsFor(PYPI), []);
    assert.equal(parseSnapshotRecord('{"id":"X-1","modified":"2024-01-01T00:00:00Z"}')?.id, 'X-1');
    assert.equal(parseSnapshotRecord('{"no":"id"}'), null);
    assert.equal(parseSnapshotRecord('not json'), null);
  });
});

describe('streaming the zip', () => {
  const zip = buildZip([LODASH, MINIMIST, LISTED, WITHDRAWN, PYPI, MALWARE], {
    'GHSA-bad-json-0001.json': strToU8('{ this is not json'),
    'README.txt': strToU8('not a record'),
  });

  it('loads records in small chunks, skips MAL-* and non-JSON entries, counts problems', async () => {
    const sink = new FakeSink();
    const progress: number[] = [];
    const stats = await loadSnapshotZip(chunked(zip, 7), sink, { totalBytes: zip.byteLength, batchSize: 2, onProgress: (p) => progress.push(p.bytes) });
    assert.equal(stats.entries, 8);
    assert.equal(stats.records, 5);
    assert.equal(stats.skippedMalware, 1);
    assert.equal(stats.invalid, 1);
    assert.equal(stats.withdrawn, 1);
    assert.equal(stats.bytes, zip.byteLength);
    assert.equal(stats.indexed, 3);
    assert.equal(stats.lastModified, '2024-03-01T00:00:00.000000Z');
    assert.deepEqual(sink.vulns.map((r) => r.id).sort(), [LISTED.id, LODASH.id, MINIMIST.id, PYPI.id, WITHDRAWN.id].sort());
    assert.deepEqual([...new Set(sink.rows.map((r) => r.id))].sort(), [LISTED.id, LODASH.id, MINIMIST.id].sort());
    assert.deepEqual(sink.deleted, [WITHDRAWN.id], 'a withdrawn record loses its old index rows');
    assert.ok(sink.transactions >= 3, 'batched transactions');
    assert.equal(progress.at(-1), zip.byteLength);
  });

  it('keeps malware records when asked', async () => {
    const sink = new FakeSink();
    const stats = await loadSnapshotZip(chunked(zip, 64), sink, { includeMalware: true, totalBytes: zip.byteLength });
    assert.equal(stats.skippedMalware, 0);
    assert.ok(sink.vulns.some((r) => r.id === MALWARE.id));
    assert.ok(sink.rows.some((r) => r.pkg === 'evil-pkg'));
  });

  it('keeps fflate linear on archives with many entries', async () => {
    // loader trims fflate's k array
    const many: Record<string, Uint8Array> = {};
    for (let i = 0; i < 3000; i += 1) many[`MAL-2026-${i}.json`] = strToU8(JSON.stringify({ id: `MAL-2026-${i}`, modified: '2026-01-01T00:00:00Z' }));
    const bytes = zipSync({ ...many, [`${LODASH.id}.json`]: strToU8(JSON.stringify(LODASH)) });
    const raw = new Unzip((file) => {
      file.ondata = () => {};
      file.start();
    });
    raw.register(UnzipInflate);
    for (let i = 0; i < bytes.length; i += 4096) raw.push(bytes.subarray(i, i + 4096), false);
    const k = (raw as unknown as { k?: unknown[] }).k;
    assert.ok(Array.isArray(k) && k.length >= 3000, 'upstream behaviour the trim relies on (update trimUnzipState if this changes)');
    trimUnzipState(raw);
    assert.equal(k.length, 2);
    // must not overflow the stack
    const stats = await loadSnapshotZip(chunked(bytes, bytes.byteLength), new FakeSink(), { totalBytes: bytes.byteLength });
    assert.equal(stats.skippedMalware, 3000);
    assert.equal(stats.records, 1);
  });

  it('fails on a truncated archive', async () => {
    const cut = zip.subarray(0, Math.floor(zip.byteLength / 3));
    await assert.rejects(loadSnapshotZip(chunked(cut, 100), new FakeSink(), { totalBytes: zip.byteLength }), /ended unexpectedly/);
  });
});

describe('modified_id.csv', () => {
  const lines = [
    csvLine('2026-09-24T09:41:11.407995532Z', 'MAL-2026-6371'),
    csvLine('2026-09-24T09:40:00.5Z', 'GHSA-new1-0000-0001'),
    csvLine('2026-09-24T09:39:00Z', 'GHSA-new2-0000-0002'),
    csvLine('2026-09-24T09:38:00Z', 'GHSA-new1-0000-0001'),
    'garbage line',
    csvLine('2026-09-24T08:00:00Z', 'GHSA-old1-0000-0003'),
    ...Array.from({ length: 300 }, (_, i) => csvLine(`2026-09-23T${String(10 + (i % 10)).padStart(2, '0')}:00:00Z`, `GHSA-older-${i}`)),
    csvLine('2026-09-24T09:59:00Z', 'GHSA-too-late-after-older'),
  ];

  it('reads entries newer than the watermark, newest first, without malware', async () => {
    const scan = await readModifiedSince(lines, '2026-09-24T09:00:00Z');
    assert.deepEqual(scan.entries.map((e) => e.id), ['GHSA-new1-0000-0001', 'GHSA-new2-0000-0002']);
    assert.equal(scan.entries[0]?.modified, '2026-09-24T09:40:00.500000Z', 'normalised timestamps, newest per id');
    assert.equal(scan.newest, '2026-09-24T09:40:00.500000Z');
    assert.equal(scan.truncated, false);
    const withMalware = await readModifiedSince(['modified,id', ...lines], '2026-09-24T09:00:00Z', { includeMalware: true });
    assert.equal(withMalware.entries[0]?.id, 'MAL-2026-6371');
  });

  it('stops at the max and reports it', async () => {
    const scan = await readModifiedSince(lines, '2026-01-01T00:00:00Z', { maxEntries: 3 });
    assert.equal(scan.truncated, true);
    assert.equal(scan.entries.length, 3);
  });

  it('plans up-to-date, incremental or full', () => {
    const mark = '2026-09-24T09:00:00.000000Z';
    const fresh = [{ id: 'A', modified: '2026-09-24T09:30:00.000000Z' }];
    const margin = [
      { id: 'B', modified: '2026-09-24T08:30:00.000000Z' },
      { id: 'C', modified: '2026-09-24T08:40:00.000000Z' },
    ];
    const stored = new Map([
      ['B', '2026-09-24T08:30:00.000000Z'],
      ['C', '2026-09-20T00:00:00.000000Z'],
    ]);
    assert.equal(planIncremental(margin, mark, stored).mode, 'up-to-date');
    const plan = planIncremental([...fresh, ...margin], mark, stored);
    assert.equal(plan.mode, 'incremental');
    assert.deepEqual(plan.fetch.map((e) => e.id), ['A', 'C']);
    const many = Array.from({ length: INCREMENTAL_MAX }, (_, i) => ({ id: `X${i}`, modified: '2026-09-24T10:00:00.000000Z' }));
    const full = planIncremental(many, mark, new Map());
    assert.equal(full.mode, 'full');
    assert.equal(full.changed, INCREMENTAL_MAX);
    assert.equal(planIncremental(fresh, mark, new Map(), { truncated: true }).mode, 'full');
  });
});

describe('db sync end to end (temporary database, fake network)', () => {
  it('runs a full sync, then up-to-date, then incremental, then full when too much changed', async () => {
    const net: Network = { zip: buildZip([LODASH, MINIMIST, LISTED, WITHDRAWN, MALWARE]), csv: '', records: new Map(), calls: [] };
    network(net);

    // 1. full
    const first = capture();
    const r1 = await syncSnapshot(config, first.ui);
    assert.equal(r1.mode, 'full');
    assert.equal(r1.records, 4);
    assert.equal(r1.skippedMalware, 1);
    assert.match(first.out(), /Loaded the OSV snapshot {2}3 records . 1 malware records skipped/);
    assert.deepEqual(net.calls, [OSV_NPM_ZIP]);
    let db = openDb(config.paths.dbFile);
    assert.deepEqual(snapshotMatches(db, 'lodash', '4.17.20'), [LODASH.id]);
    assert.deepEqual(snapshotMatches(db, 'lodash', '4.17.21'), []);
    assert.deepEqual(snapshotMatches(db, 'minimist', '1.2.5'), [MINIMIST.id]);
    assert.deepEqual(snapshotMatches(db, 'minimist', '0.2.4'), []);
    assert.deepEqual(snapshotMatches(db, 'tiny', '1.0.1'), [LISTED.id]);
    assert.deepEqual(snapshotMatches(db, 'tiny', '1.0.2'), []);
    assert.deepEqual(snapshotMatches(db, 'evil-pkg', '1.0.0'), [], 'malware skipped by default');
    const info = db.getSnapshotInfo();
    assert.equal(info.records, 3);
    assert.equal(info.lastModified, '2024-03-01T00:00:00.000000Z');
    assert.equal(info.source, 'OSV npm all.zip');
    assert.equal(db.getMeta(MALWARE_META_KEY), 'false');
    assert.equal(db.getVuln(WITHDRAWN.id)?.withdrawn, WITHDRAWN.withdrawn, 'withdrawn records are stored, not indexed');
    db.close();

    // 2. up to date, no zip
    net.calls.length = 0;
    net.csv = [csvLine('2026-09-24T09:41:11Z', 'MAL-2026-6371'), csvLine('2024-03-01T00:00:00Z', WITHDRAWN.id), csvLine('2024-01-02T03:04:05Z', LODASH.id)].join('\n');
    const r2 = await syncSnapshot(config, capture().ui);
    assert.equal(r2.mode, 'up-to-date');
    assert.deepEqual(net.calls, [OSV_NPM_MODIFIED]);

    // 3. incremental
    const lodash2 = osv(LODASH.id, '2024-04-01T00:00:00Z', [
      { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [semver({ introduced: '0' }, { fixed: '4.17.21' })] },
      { package: { name: 'lodash-es', ecosystem: 'npm' }, ranges: [semver({ introduced: '0' }, { fixed: '4.17.21' })] },
    ]);
    const json5 = osv('GHSA-9c47-m6qq-7p4h', '2024-04-02T00:00:00Z', [{ package: { name: 'json5', ecosystem: 'npm' }, ranges: [semver({ introduced: '2.0.0' }, { fixed: '2.2.2' })] }]);
    net.records.set(lodash2.id, lodash2);
    net.records.set(json5.id, json5);
    net.calls.length = 0;
    net.csv = [
      csvLine('2026-09-24T09:41:11Z', 'MAL-2026-9999'),
      csvLine('2024-04-02T00:00:00Z', json5.id),
      csvLine('2024-04-01T00:00:00Z', lodash2.id),
      csvLine('2024-03-01T00:00:00Z', WITHDRAWN.id),
    ].join('\n');
    const third = capture();
    const r3 = await syncSnapshot(config, third.ui);
    assert.equal(r3.mode, 'incremental');
    assert.equal(r3.records, 2);
    assert.match(third.out(), /Updated the OSV snapshot {2}2 updated . 4 records/);
    assert.deepEqual(net.calls.sort(), [OSV_NPM_MODIFIED, `${OSV_NPM_RECORD_BASE}/${json5.id}.json`, `${OSV_NPM_RECORD_BASE}/${lodash2.id}.json`].sort());
    db = openDb(config.paths.dbFile);
    assert.deepEqual(snapshotMatches(db, 'json5', '2.2.0'), [json5.id]);
    assert.deepEqual(snapshotMatches(db, 'lodash-es', '4.17.20'), [LODASH.id]);
    assert.equal(db.getSnapshotInfo().lastModified, '2024-04-02T00:00:00.000000Z');
    assert.equal(db.getSnapshotInfo().source, 'OSV npm all.zip + incremental updates');
    db.close();

    // 4. too many changes, zip again
    net.calls.length = 0;
    net.csv = Array.from({ length: INCREMENTAL_MAX + 5 }, (_, i) => csvLine('2025-01-01T00:00:00Z', `GHSA-bulk-${i}`)).join('\n');
    const fourth = capture();
    const r4 = await syncSnapshot(config, fourth.ui);
    assert.equal(r4.mode, 'full');
    assert.match(fourth.out(), /2000 or more changed records/);
    assert.deepEqual(net.calls, [OSV_NPM_MODIFIED, OSV_NPM_ZIP]);

    // 5. --full, --include-malware
    net.calls.length = 0;
    const r5 = await syncSnapshot(config, capture().ui, { full: true, includeMalware: true });
    assert.equal(r5.mode, 'full');
    assert.deepEqual(net.calls, [OSV_NPM_ZIP]);
    db = openDb(config.paths.dbFile);
    assert.deepEqual(snapshotMatches(db, 'evil-pkg', '1.0.0'), [MALWARE.id]);
    assert.equal(db.getMeta(MALWARE_META_KEY), 'true');
    db.close();

    // 6. dropping malware clears first
    const r6 = await syncSnapshot(config, capture().ui);
    assert.equal(r6.mode, 'full');
    db = openDb(config.paths.dbFile);
    assert.deepEqual(snapshotMatches(db, 'evil-pkg', '1.0.0'), []);
    db.close();
  });

  it('refuses to sync offline and reports a failed download', async () => {
    await assert.rejects(syncSnapshot({ ...config, offline: true }, capture().ui), /needs the network/);
    mock.method(globalThis, 'fetch', async () => new Response('nope', { status: 503 }));
    const other = await loadConfig({ dir: home, cwd: home, homeDir: path.join(home, 'other-home'), env: {}, flags: {} });
    await assert.rejects(syncSnapshot(other, capture().ui), /Could not download .*all\.zip: HTTP 503/);
  });
});

describe('db status', () => {
  it('reports a missing database without creating it', async () => {
    const fresh = await loadConfig({ dir: home, cwd: home, homeDir: path.join(home, 'empty-home'), env: {}, flags: {} });
    const status = await snapshotStatus(fresh);
    assert.equal(status.exists, false);
    const { ui } = capture();
    assert.match(renderDbStatus(status, ui), /No local database yet/);
  });

  it('renders the snapshot and warns when it is old', () => {
    const { ui } = capture();
    const base = {
      path: path.join(os.homedir(), '.patch-pilot', 'patch-pilot.db'),
      exists: true,
      sizeBytes: 12_900_000,
      schemaVersion: 1,
      vulns: 7512,
      queryCacheEntries: 34,
      registryEntries: 12,
      webEntries: 8,
    };
    const recent = renderDbStatus({ ...base, snapshot: { loadedAt: new Date(Date.now() - 2 * 3600_000).toISOString(), records: 7512, source: 'OSV npm all.zip' } }, ui);
    assert.match(recent, /Local database {2}~\/\.patch-pilot\/patch-pilot\.db . 12\.3 MB . schema v1/);
    assert.match(recent, /Advisories {6}7,512/);
    assert.match(recent, /Offline snapshot {2}7,512 records . synced 2 h ago/);
    assert.match(recent, /Source {10}OSV npm all\.zip/);
    const old = renderDbStatus({ ...base, snapshot: { loadedAt: new Date(Date.now() - 10 * 86_400_000).toISOString(), records: 7512, source: null } }, ui);
    assert.match(old, /Offline snapshot is out of date/);
    const none = renderDbStatus({ ...base, snapshot: { loadedAt: null, records: 0, source: null } }, ui);
    assert.match(none, /No offline snapshot {2}run patch-pilot db sync/);
  });

  it('reads the status of a synced database', async () => {
    const status = await snapshotStatus(config);
    assert.equal(status.exists, true);
    assert.ok(status.snapshot.records > 0);
    assert.ok(status.snapshot.loadedAt);
    const db = openDb(config.paths.dbFile, { readonly: true });
    assert.equal(db.getMeta(META_KEYS.snapshotSource), status.snapshot.source);
    db.close();
  });
});
