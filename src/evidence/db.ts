// ~/.patch-pilot/patch-pilot.db
import { existsSync, mkdirSync, statSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import type { KeyValueCache, OsvRange, OsvRecord } from '../types.ts';

// shared by osv, registry, snapshot, web tools
export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vulns (
  id TEXT PRIMARY KEY,
  modified TEXT NOT NULL,
  json TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'api'
);
CREATE TABLE IF NOT EXISTS query_cache (
  pkg TEXT NOT NULL,
  version TEXT NOT NULL,
  ids_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (pkg, version)
);
CREATE TABLE IF NOT EXISTS registry_cache (
  key TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS web_cache (
  namespace TEXT NOT NULL,
  key TEXT NOT NULL,
  json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  expires_at TEXT,
  PRIMARY KEY (namespace, key)
);
CREATE TABLE IF NOT EXISTS snapshot_affected (
  pkg TEXT NOT NULL,
  id TEXT NOT NULL,
  ranges_json TEXT NOT NULL,
  versions_json TEXT,
  PRIMARY KEY (pkg, id)
);
CREATE INDEX IF NOT EXISTS snapshot_affected_pkg ON snapshot_affected (pkg);
`;

export const META_KEYS = {
  schemaVersion: 'schema_version',
  createdAt: 'created_at',
  // last successful db sync
  snapshotLoadedAt: 'snapshot_loaded_at',
  snapshotSource: 'snapshot_source',
  snapshotRecords: 'snapshot_records',
  // incremental sync watermark
  snapshotLastModified: 'snapshot_last_modified',
} as const;

export interface QueryCacheRow {
  ids: string[];
  fetchedAt: string;
}

export interface SnapshotAffectedRow {
  pkg: string;
  id: string;
  ranges: OsvRange[];
  versions: string[] | null;
}

export interface DbStatus {
  path: string;
  exists: boolean;
  sizeBytes: number;
  schemaVersion: number | null;
  vulns: number;
  queryCacheEntries: number;
  registryEntries: number;
  webEntries: number;
  snapshot: { loadedAt: string | null; records: number; source: string | null };
}

export interface OpenDbOptions {
  readonly?: boolean;
}

export interface SnapshotInfo {
  loadedAt: string;
  source: string;
  records?: number;
  lastModified?: string;
}

export interface QueryCacheInput {
  pkg: string;
  version: string;
  ids: readonly string[];
  fetchedAt?: string;
}

const TIMESTAMP = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})$/;

// utc, 6 fraction digits, string-comparable
export function normalizeTimestamp(value: string): string {
  if (typeof value !== 'string') return String(value);
  const text = value.trim();
  const m = TIMESTAMP.exec(text);
  if (m && m[3] === 'Z') return `${m[1]}.${`${m[2] ?? ''}000000`.slice(0, 6)}Z`;
  const ms = Date.parse(text);
  if (Number.isNaN(ms)) return text;
  const iso = new Date(ms).toISOString();
  return `${iso.slice(0, 23)}000Z`;
}

function parseJson<T>(text: string | null | undefined): T | null {
  if (typeof text !== 'string') return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

type Statement = Database.Statement<unknown[], unknown>;

export class PatchPilotDb implements KeyValueCache {
  readonly path: string;
  private conn: Database.Database | null = null;
  private readonly statements = new Map<string, Statement>();
  private memoryFallback = false;
  private readonlyMode = false;

  constructor(file: string) {
    this.path = file;
  }

  // creates dir and schema if needed
  static open(file: string, options: OpenDbOptions = {}): PatchPilotDb {
    const db = new PatchPilotDb(file);
    db.init(options);
    return db;
  }

  private init(options: OpenDbOptions): void {
    const readonly = options.readonly === true;
    this.readonlyMode = readonly;
    if (readonly && !existsSync(this.path)) {
      // no file yet, in-memory keeps lookups working
      const conn = new Database(':memory:');
      conn.exec(SCHEMA_SQL);
      this.conn = conn;
      this.memoryFallback = true;
      return;
    }
    if (!readonly) mkdirSync(path.dirname(this.path), { recursive: true });
    let conn: Database.Database;
    try {
      conn = new Database(this.path, { readonly, fileMustExist: readonly, timeout: 5_000 });
    } catch (err) {
      throw new Error(`Cannot open the PatchPilot database ${this.path}: ${(err as Error).message}`, { cause: err });
    }
    try {
      if (!readonly) {
        conn.pragma('journal_mode = WAL');
        conn.pragma('synchronous = NORMAL');
        conn.exec(SCHEMA_SQL);
        const insertMeta = conn.prepare('INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)');
        insertMeta.run(META_KEYS.schemaVersion, String(SCHEMA_VERSION));
        insertMeta.run(META_KEYS.createdAt, new Date().toISOString());
      } else {
        // throws SQLITE_NOTADB if not ours
        conn.prepare('SELECT count(*) FROM meta').get();
      }
    } catch (err) {
      conn.close();
      throw new Error(
        `The PatchPilot database ${this.path} is unreadable (${(err as Error).message}). Delete it to start with an empty cache.`,
        { cause: err },
      );
    }
    this.conn = conn;
  }

  private get db(): Database.Database {
    if (!this.conn) throw new Error(`The PatchPilot database ${this.path} is closed`);
    return this.conn;
  }

  private stmt(sql: string): Statement {
    let statement = this.statements.get(sql);
    if (!statement) {
      statement = this.db.prepare(sql) as Statement;
      this.statements.set(sql, statement);
    }
    return statement;
  }

  get isMemoryFallback(): boolean {
    return this.memoryFallback;
  }

  get readonly(): boolean {
    return this.readonlyMode;
  }

  close(): void {
    if (!this.conn) return;
    this.statements.clear();
    this.conn.close();
    this.conn = null;
  }

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  getVuln(id: string): OsvRecord | null {
    const row = this.stmt('SELECT json FROM vulns WHERE id = ?').get(id) as { json: string } | undefined;
    return parseJson<OsvRecord>(row?.json);
  }

  // missing ids left out
  getVulns(ids: readonly string[]): Map<string, OsvRecord> {
    const out = new Map<string, OsvRecord>();
    const statement = this.stmt('SELECT json FROM vulns WHERE id = ?');
    for (const id of new Set(ids)) {
      const row = statement.get(id) as { json: string } | undefined;
      const record = parseJson<OsvRecord>(row?.json);
      if (record) out.set(id, record);
    }
    return out;
  }

  // skips unchanged hydrations
  getVulnModified(ids: readonly string[]): Map<string, string> {
    const out = new Map<string, string>();
    const statement = this.stmt('SELECT modified FROM vulns WHERE id = ?');
    for (const id of new Set(ids)) {
      const row = statement.get(id) as { modified: string } | undefined;
      if (row) out.set(id, row.modified);
    }
    return out;
  }

  putVulns(records: readonly OsvRecord[], source: 'api' | 'snapshot' = 'api'): void {
    if (records.length === 0) return;
    const statement = this.stmt(
      `INSERT INTO vulns (id, modified, json, source) VALUES (?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET modified = excluded.modified, json = excluded.json, source = excluded.source
       WHERE excluded.modified >= vulns.modified`,
    );
    this.transaction(() => {
      for (const record of records) {
        if (!record || typeof record.id !== 'string' || record.id === '') continue;
        statement.run(record.id, normalizeTimestamp(record.modified ?? ''), JSON.stringify(record), source);
      }
    });
  }

  getQuery(pkg: string, version: string): QueryCacheRow | null {
    const row = this.stmt('SELECT ids_json, fetched_at FROM query_cache WHERE pkg = ? AND version = ?').get(pkg, version) as
      | { ids_json: string; fetched_at: string }
      | undefined;
    if (!row) return null;
    const ids = parseJson<string[]>(row.ids_json);
    return { ids: Array.isArray(ids) ? ids.filter((x) => typeof x === 'string') : [], fetchedAt: row.fetched_at };
  }

  putQuery(pkg: string, version: string, ids: readonly string[], fetchedAt?: string): void {
    this.putQueries([{ pkg, version, ids, fetchedAt }]);
  }

  // one transaction
  putQueries(rows: readonly QueryCacheInput[]): void {
    if (rows.length === 0) return;
    const now = new Date().toISOString();
    const statement = this.stmt(
      `INSERT INTO query_cache (pkg, version, ids_json, fetched_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(pkg, version) DO UPDATE SET ids_json = excluded.ids_json, fetched_at = excluded.fetched_at`,
    );
    this.transaction(() => {
      for (const row of rows) statement.run(row.pkg, row.version, JSON.stringify([...new Set(row.ids)]), row.fetchedAt ?? now);
    });
  }

  getRegistry<T = unknown>(key: string): { value: T; fetchedAt: string } | null {
    const row = this.stmt('SELECT json, fetched_at FROM registry_cache WHERE key = ?').get(key) as
      | { json: string; fetched_at: string }
      | undefined;
    if (!row) return null;
    const value = parseJson<T>(row.json);
    if (value === null && row.json !== 'null') return null;
    return { value: value as T, fetchedAt: row.fetched_at };
  }

  putRegistry(key: string, value: unknown): void {
    this.stmt(
      `INSERT INTO registry_cache (key, json, fetched_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET json = excluded.json, fetched_at = excluded.fetched_at`,
    ).run(key, JSON.stringify(value ?? null), new Date().toISOString());
  }

  get<T = unknown>(namespace: string, key: string): T | undefined {
    const row = this.stmt('SELECT json, expires_at FROM web_cache WHERE namespace = ? AND key = ?').get(namespace, key) as
      | { json: string; expires_at: string | null }
      | undefined;
    if (!row) return undefined;
    if (row.expires_at) {
      const expires = Date.parse(row.expires_at);
      if (!Number.isNaN(expires) && expires <= Date.now()) return undefined;
    }
    const value = parseJson<T>(row.json);
    if (value === null && row.json !== 'null') return undefined;
    return value as T;
  }

  set(namespace: string, key: string, value: unknown, ttlMs?: number): void {
    const now = Date.now();
    const expires = ttlMs !== undefined && Number.isFinite(ttlMs) && ttlMs > 0 ? new Date(now + ttlMs).toISOString() : null;
    this.stmt(
      `INSERT INTO web_cache (namespace, key, json, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(namespace, key) DO UPDATE SET json = excluded.json, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`,
    ).run(namespace, key, JSON.stringify(value ?? null), new Date(now).toISOString(), expires);
  }

  delete(namespace: string, key: string): void {
    this.stmt('DELETE FROM web_cache WHERE namespace = ? AND key = ?').run(namespace, key);
  }

  pruneExpired(now: Date = new Date()): number {
    return this.stmt('DELETE FROM web_cache WHERE expires_at IS NOT NULL AND expires_at <= ?').run(now.toISOString()).changes;
  }

  getMeta(key: string): string | null {
    const row = this.stmt('SELECT value FROM meta WHERE key = ?').get(key) as { value: string } | undefined;
    return row ? row.value : null;
  }

  setMeta(key: string, value: string): void {
    this.stmt('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
  }

  putSnapshotAffected(rows: readonly SnapshotAffectedRow[]): void {
    if (rows.length === 0) return;
    const statement = this.stmt(
      `INSERT INTO snapshot_affected (pkg, id, ranges_json, versions_json) VALUES (?, ?, ?, ?)
       ON CONFLICT(pkg, id) DO UPDATE SET ranges_json = excluded.ranges_json, versions_json = excluded.versions_json`,
    );
    this.transaction(() => {
      for (const row of rows) {
        statement.run(row.pkg, row.id, JSON.stringify(row.ranges ?? []), row.versions ? JSON.stringify(row.versions) : null);
      }
    });
  }

  snapshotFor(pkg: string): SnapshotAffectedRow[] {
    const rows = this.stmt('SELECT pkg, id, ranges_json, versions_json FROM snapshot_affected WHERE pkg = ? ORDER BY id').all(pkg) as {
      pkg: string;
      id: string;
      ranges_json: string;
      versions_json: string | null;
    }[];
    return rows.map((row) => {
      const ranges = parseJson<OsvRange[]>(row.ranges_json);
      const versions = parseJson<string[]>(row.versions_json);
      return { pkg: row.pkg, id: row.id, ranges: Array.isArray(ranges) ? ranges : [], versions: Array.isArray(versions) ? versions : null };
    });
  }

  // incremental sync replaces them
  deleteSnapshotIds(ids: readonly string[]): void {
    if (ids.length === 0) return;
    const statement = this.stmt('DELETE FROM snapshot_affected WHERE id = ?');
    this.transaction(() => {
      for (const id of ids) statement.run(id);
    });
  }

  // index rows and loaded records
  clearSnapshot(): void {
    this.transaction(() => {
      this.stmt('DELETE FROM snapshot_affected').run();
      this.stmt("DELETE FROM vulns WHERE source = 'snapshot'").run();
      for (const key of [META_KEYS.snapshotLoadedAt, META_KEYS.snapshotSource, META_KEYS.snapshotRecords, META_KEYS.snapshotLastModified]) {
        this.stmt('DELETE FROM meta WHERE key = ?').run(key);
      }
    });
  }

  hasSnapshot(): boolean {
    return this.stmt('SELECT 1 AS present FROM snapshot_affected LIMIT 1').get() !== undefined;
  }

  setSnapshotInfo(info: SnapshotInfo): void {
    this.transaction(() => {
      this.setMeta(META_KEYS.snapshotLoadedAt, info.loadedAt);
      this.setMeta(META_KEYS.snapshotSource, info.source);
      if (info.records !== undefined) this.setMeta(META_KEYS.snapshotRecords, String(info.records));
      if (info.lastModified !== undefined) this.setMeta(META_KEYS.snapshotLastModified, info.lastModified);
    });
  }

  getSnapshotInfo(): { loadedAt: string | null; source: string | null; records: number; lastModified: string | null } {
    const recordsMeta = Number(this.getMeta(META_KEYS.snapshotRecords));
    const counted = (this.stmt('SELECT count(DISTINCT id) AS n FROM snapshot_affected').get() as { n: number }).n;
    return {
      loadedAt: this.getMeta(META_KEYS.snapshotLoadedAt),
      source: this.getMeta(META_KEYS.snapshotSource),
      records: Number.isFinite(recordsMeta) && recordsMeta > 0 ? recordsMeta : counted,
      lastModified: this.getMeta(META_KEYS.snapshotLastModified),
    };
  }

  status(): DbStatus {
    const count = (table: string): number => (this.stmt(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
    const exists = !this.memoryFallback && existsSync(this.path);
    let sizeBytes = 0;
    if (exists) {
      for (const suffix of ['', '-wal', '-shm']) {
        try {
          sizeBytes += statSync(this.path + suffix).size;
        } catch {
          // no wal/shm file
        }
      }
    }
    const schema = Number(this.getMeta(META_KEYS.schemaVersion));
    const snapshot = this.getSnapshotInfo();
    return {
      path: this.path,
      exists,
      sizeBytes,
      schemaVersion: Number.isFinite(schema) && schema > 0 ? schema : null,
      vulns: count('vulns'),
      queryCacheEntries: count('query_cache'),
      registryEntries: count('registry_cache'),
      webEntries: count('web_cache'),
      snapshot: { loadedAt: snapshot.loadedAt, records: snapshot.records, source: snapshot.source },
    };
  }
}

export function openDb(file: string, options: OpenDbOptions = {}): PatchPilotDb {
  return PatchPilotDb.open(file, options);
}
