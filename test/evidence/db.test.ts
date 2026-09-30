import assert from 'node:assert/strict';
import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { META_KEYS, normalizeTimestamp, openDb, PatchPilotDb, SCHEMA_VERSION } from '../../src/evidence/db.ts';
import type { OsvRecord } from '../../src/types.ts';
import { tempDir } from './helpers.ts';

const record = (id: string, modified: string, summary = id): OsvRecord => ({ id, modified, summary });

describe('PatchPilotDb on a temp file', () => {
  let tmp: { dir: string; cleanup: () => Promise<void> };
  let file: string;
  let db: PatchPilotDb;

  before(async () => {
    tmp = await tempDir('pp-db-');
    file = path.join(tmp.dir, 'nested', 'dir', 'patch-pilot.db');
    db = openDb(file);
  });
  after(async () => {
    db.close();
    await tmp.cleanup();
  });

  it('creates the directory, the schema and the meta rows', () => {
    assert.ok(existsSync(file));
    assert.equal(db.getMeta(META_KEYS.schemaVersion), String(SCHEMA_VERSION));
    assert.ok(db.getMeta(META_KEYS.createdAt));
    const status = db.status();
    assert.equal(status.exists, true);
    assert.equal(status.schemaVersion, SCHEMA_VERSION);
    assert.ok(status.sizeBytes > 0);
    assert.equal(status.vulns, 0);
  });

  it('normalises OSV timestamps so querybatch and record values compare equal', () => {
    assert.equal(normalizeTimestamp('2026-09-10T03:51:14.713899943Z'), '2026-09-10T03:51:14.713899Z');
    assert.equal(normalizeTimestamp('2026-09-10T03:51:14.713899Z'), '2026-09-10T03:51:14.713899Z');
    assert.equal(normalizeTimestamp('2023-11-08T04:10:14Z'), '2023-11-08T04:10:14.000000Z');
    assert.equal(normalizeTimestamp('2023-11-08T06:10:14.5+02:00'), '2023-11-08T04:10:14.500000Z');
    assert.equal(normalizeTimestamp('not a date'), 'not a date');
  });

  it('stores vulns, reports cached modified values and never downgrades a record', () => {
    db.putVulns([record('GHSA-a', '2026-09-10T03:51:14.713899943Z', 'first'), record('GHSA-b', '2024-01-01T00:00:00Z')]);
    assert.equal(db.getVuln('GHSA-a')?.summary, 'first');
    assert.equal(db.getVuln('GHSA-a')?.modified, '2026-09-10T03:51:14.713899943Z', 'the JSON keeps its own value');
    assert.deepEqual(db.getVulnModified(['GHSA-a', 'GHSA-b', 'GHSA-missing']), new Map([
      ['GHSA-a', '2026-09-10T03:51:14.713899Z'],
      ['GHSA-b', '2024-01-01T00:00:00.000000Z'],
    ]));
    db.putVulns([record('GHSA-a', '2020-01-01T00:00:00Z', 'older')]);
    assert.equal(db.getVuln('GHSA-a')?.summary, 'first');
    db.putVulns([record('GHSA-a', '2026-09-11T00:00:00Z', 'newer')], 'snapshot');
    assert.equal(db.getVuln('GHSA-a')?.summary, 'newer');
    assert.equal(db.getVuln('GHSA-none'), null);
    assert.deepEqual([...db.getVulns(['GHSA-a', 'GHSA-b', 'GHSA-x']).keys()], ['GHSA-a', 'GHSA-b']);
  });

  it('round-trips the query cache (deduplicated ids, explicit fetchedAt)', () => {
    db.putQuery('lodash', '4.17.20', ['GHSA-a', 'GHSA-b', 'GHSA-a'], '2026-09-01T00:00:00.000Z');
    assert.deepEqual(db.getQuery('lodash', '4.17.20'), { ids: ['GHSA-a', 'GHSA-b'], fetchedAt: '2026-09-01T00:00:00.000Z' });
    db.putQueries([
      { pkg: 'lodash', version: '4.17.20', ids: [] },
      { pkg: 'marked', version: '0.3.6', ids: ['GHSA-m'] },
    ]);
    assert.deepEqual(db.getQuery('lodash', '4.17.20')?.ids, []);
    assert.ok(Date.now() - Date.parse(db.getQuery('marked', '0.3.6')?.fetchedAt ?? '') < 60_000);
    assert.equal(db.getQuery('marked', '9.9.9'), null);
  });

  it('round-trips registry entries, including a cached null (404)', () => {
    db.putRegistry('packument:lodash', { name: 'lodash', versions: { '4.18.1': {} } });
    const row = db.getRegistry<{ name: string }>('packument:lodash');
    assert.equal(row?.value.name, 'lodash');
    assert.ok(row?.fetchedAt);
    db.putRegistry('packument:nope', null);
    assert.deepEqual(db.getRegistry('packument:nope')?.value, null);
    assert.equal(db.getRegistry('packument:unknown'), null);
  });

  it('implements KeyValueCache over web_cache with a TTL', async () => {
    db.set('fetch_page', 'https://example.com', { text: 'hi' });
    assert.deepEqual(db.get('fetch_page', 'https://example.com'), { text: 'hi' });
    db.set('search', 'q', ['a'], 30);
    assert.deepEqual(db.get('search', 'q'), ['a']);
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(db.get('search', 'q'), undefined, 'expired');
    assert.equal(db.pruneExpired(), 1);
    db.delete('fetch_page', 'https://example.com');
    assert.equal(db.get('fetch_page', 'https://example.com'), undefined);
    db.set('ns', 'null-value', null);
    assert.equal(db.get('ns', 'null-value'), null);
  });

  it('stores meta values and snapshot rows, and reports the snapshot in status()', () => {
    assert.equal(db.hasSnapshot(), false);
    db.putSnapshotAffected([
      { pkg: 'lodash', id: 'GHSA-a', ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }], versions: null },
      { pkg: 'evil', id: 'MAL-1', ranges: [], versions: ['1.0.0'] },
    ]);
    assert.equal(db.hasSnapshot(), true);
    assert.deepEqual(db.snapshotFor('lodash'), [
      { pkg: 'lodash', id: 'GHSA-a', ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }], versions: null },
    ]);
    assert.deepEqual(db.snapshotFor('evil')[0]?.versions, ['1.0.0']);
    db.setSnapshotInfo({ loadedAt: '2026-09-20T00:00:00.000Z', source: 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip', records: 2 });
    assert.equal(db.getMeta(META_KEYS.snapshotLoadedAt), '2026-09-20T00:00:00.000Z');
    const status = db.status();
    assert.deepEqual(status.snapshot, { loadedAt: '2026-09-20T00:00:00.000Z', records: 2, source: 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip' });
    assert.equal(status.queryCacheEntries, 2);
    assert.ok(status.registryEntries >= 2);
    db.deleteSnapshotIds(['MAL-1']);
    assert.deepEqual(db.snapshotFor('evil'), []);
    db.clearSnapshot();
    assert.equal(db.hasSnapshot(), false);
    assert.equal(db.getMeta(META_KEYS.snapshotLoadedAt), null);
    assert.equal(db.getVuln('GHSA-a'), null, 'records loaded by the snapshot go with it');
    assert.ok(db.getVuln('GHSA-b'), 'API records stay');
  });

  it('rolls a transaction back when it throws', () => {
    assert.throws(() =>
      db.transaction(() => {
        db.setMeta('tx-test', 'written');
        throw new Error('boom');
      }),
    );
    assert.equal(db.getMeta('tx-test'), null);
    assert.equal(db.transaction(() => 42), 42);
  });

  it('persists across reopen, including read-only mode', () => {
    db.setMeta('persist', 'yes');
    const again = PatchPilotDb.open(file, { readonly: true });
    try {
      assert.equal(again.getMeta('persist'), 'yes');
      assert.equal(again.readonly, true);
      assert.throws(() => again.setMeta('x', 'y'));
    } finally {
      again.close();
    }
  });
});

describe('PatchPilotDb edge cases', () => {
  it('opens a missing file read-only as an empty in-memory store without creating it', async () => {
    const tmp = await tempDir('pp-db-');
    try {
      const missing = path.join(tmp.dir, 'none', 'patch-pilot.db');
      const db = openDb(missing, { readonly: true });
      assert.equal(db.isMemoryFallback, true);
      assert.equal(db.status().exists, false);
      assert.equal(db.getVuln('x'), null);
      db.close();
      assert.equal(existsSync(missing), false);
    } finally {
      await tmp.cleanup();
    }
  });

  it('explains an unreadable database file', async () => {
    const tmp = await tempDir('pp-db-');
    try {
      const bad = path.join(tmp.dir, 'patch-pilot.db');
      writeFileSync(bad, 'this is not a sqlite database, just text '.repeat(40));
      assert.throws(() => openDb(bad), /unreadable.*Delete it/s);
    } finally {
      await tmp.cleanup();
    }
  });

  it('refuses calls after close()', async () => {
    const tmp = await tempDir('pp-db-');
    try {
      const db = openDb(path.join(tmp.dir, 'a.db'));
      db.close();
      db.close();
      assert.throws(() => db.getMeta('x'), /closed/);
    } finally {
      await tmp.cleanup();
    }
  });
});
