// offline osv npm snapshot
import os from 'node:os';
import { Inflate, Unzip, type AsyncFlateStreamHandler, type FlateError, type UnzipDecoder, type UnzipDecoderConstructor } from 'fflate';
import type { Config, OsvRange, OsvRecord } from '../types.ts';
import { formatBytes, formatDuration, type Ui } from '../ui.ts';
import { EnvironmentError } from '../util/errors.ts';
import { describeHttpError, tryGetJson } from '../util/http.ts';
import { isAffected } from '../util/semver.ts';
import { USER_AGENT } from '../version.ts';
import { META_KEYS, normalizeTimestamp, openDb, type DbStatus, type PatchPilotDb, type SnapshotAffectedRow } from './db.ts';

export const OSV_NPM_ZIP = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';
export const OSV_NPM_MODIFIED = 'https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv';
export const OSV_NPM_RECORD_BASE = 'https://osv-vulnerabilities.storage.googleapis.com/npm';

// this many changes means full sync
export const INCREMENTAL_MAX = 2000;
// osv export lag
export const WATERMARK_MARGIN_MS = 60 * 60 * 1000;
export const MALWARE_META_KEY = 'snapshot_include_malware';
const BATCH_SIZE = 500;
// Unzip.push recurses per entry
const PUSH_SLICE = 32 * 1024;
const FETCH_CONCURRENCY = 8;
const STALL_MS = 60_000;
const SOURCE_FULL = 'OSV npm all.zip';
const SOURCE_INCREMENTAL = 'OSV npm all.zip + incremental updates';

export interface SyncOptions {
  // default false
  includeMalware?: boolean;
  full?: boolean;
  signal?: AbortSignal;
}

export interface SyncResult {
  mode: 'full' | 'incremental' | 'up-to-date';
  records: number;
  skippedMalware: number;
  durationMs: number;
  loadedAt: string;
}

// any folder prefix
export function isMalwareId(idOrEntry: string): boolean {
  const base = idOrEntry.slice(idOrEntry.lastIndexOf('/') + 1);
  return base.startsWith('MAL-');
}

function isJsonEntry(name: string): boolean {
  return name.toLowerCase().endsWith('.json') && !name.endsWith('/');
}

// none for withdrawn records
export function snapshotRowsFor(record: OsvRecord): SnapshotAffectedRow[] {
  if (record.withdrawn) return [];
  const byPkg = new Map<string, { ranges: OsvRange[]; versions: string[] }>();
  for (const affected of record.affected ?? []) {
    const name = affected?.package?.name;
    const ecosystem = affected?.package?.ecosystem;
    if (!name || typeof ecosystem !== 'string' || ecosystem.toLowerCase() !== 'npm') continue;
    const entry = byPkg.get(name) ?? { ranges: [], versions: [] };
    for (const range of affected.ranges ?? []) {
      if (range && (range.type === 'SEMVER' || range.type === 'ECOSYSTEM') && Array.isArray(range.events)) entry.ranges.push(range);
    }
    for (const v of affected.versions ?? []) if (typeof v === 'string') entry.versions.push(v);
    byPkg.set(name, entry);
  }
  const rows: SnapshotAffectedRow[] = [];
  for (const [pkg, entry] of byPkg) {
    if (entry.ranges.length === 0 && entry.versions.length === 0) continue;
    rows.push({ pkg, id: record.id, ranges: entry.ranges, versions: entry.versions.length > 0 ? [...new Set(entry.versions)] : null });
  }
  return rows;
}

// null if not osv
export function parseSnapshotRecord(text: string): OsvRecord | null {
  try {
    const value = JSON.parse(text) as OsvRecord;
    if (!value || typeof value !== 'object' || typeof value.id !== 'string' || !value.id) return null;
    if (typeof value.modified !== 'string') value.modified = '';
    return value;
  } catch {
    return null;
  }
}

// PatchPilotDb, or a fake
export interface SnapshotSink {
  transaction<T>(fn: () => T): T;
  putVulns(records: readonly OsvRecord[], source?: 'api' | 'snapshot'): void;
  putSnapshotAffected(rows: readonly SnapshotAffectedRow[]): void;
  deleteSnapshotIds(ids: readonly string[]): void;
}

function writeBatch(sink: SnapshotSink, records: readonly OsvRecord[], replace: boolean): number {
  if (records.length === 0) return 0;
  let indexed = 0;
  sink.transaction(() => {
    const withdrawn = records.filter((r) => r.withdrawn).map((r) => r.id);
    if (replace) sink.deleteSnapshotIds(records.map((r) => r.id));
    else if (withdrawn.length > 0) sink.deleteSnapshotIds(withdrawn);
    sink.putVulns(records, 'snapshot');
    const rows = records.flatMap(snapshotRowsFor);
    indexed = new Set(rows.map((r) => r.id)).size;
    sink.putSnapshotAffected(rows);
  });
  return indexed;
}

function newer(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return a >= b ? a : b;
}

// skipped entries never inflate
function selectiveInflate(skip: (name: string) => boolean): UnzipDecoderConstructor {
  return class SelectiveInflate implements UnzipDecoder {
    static compression = 8;
    ondata: AsyncFlateStreamHandler = () => {};
    private readonly inflate: Inflate | null;
    constructor(name: string) {
      this.inflate = skip(name) ? null : new Inflate((data, final) => this.ondata(null, data, final));
    }
    push(chunk: Uint8Array, final: boolean): void {
      if (!this.inflate) {
        if (final) this.ondata(null, new Uint8Array(0), true);
        return;
      }
      try {
        this.inflate.push(chunk, final);
      } catch (err) {
        this.ondata(err as FlateError, new Uint8Array(0), true);
      }
    }
  };
}

// else the sync goes quadratic
export function trimUnzipState(unzip: Unzip): void {
  const state = (unzip as unknown as { k?: unknown }).k;
  if (Array.isArray(state) && state.length > 8) state.length = 2;
}

export interface LoadProgress {
  bytes: number;
  totalBytes: number | null;
  records: number;
  skippedMalware: number;
}

export interface LoadOptions {
  includeMalware?: boolean;
  // for progress and end check
  totalBytes?: number | null;
  batchSize?: number;
  onProgress?: (progress: LoadProgress) => void;
}

export interface LoadStats {
  entries: number;
  records: number;
  indexed: number;
  skippedMalware: number;
  withdrawn: number;
  // failed inflate or parse
  invalid: number;
  bytes: number;
  lastModified: string | null;
}

// full sync
export async function loadSnapshotZip(chunks: AsyncIterable<Uint8Array>, sink: SnapshotSink, options: LoadOptions = {}): Promise<LoadStats> {
  const includeMalware = options.includeMalware ?? false;
  const batchSize = options.batchSize ?? BATCH_SIZE;
  const skip = (name: string): boolean => !isJsonEntry(name) || (!includeMalware && isMalwareId(name));
  const stats: LoadStats = { entries: 0, records: 0, indexed: 0, skippedMalware: 0, withdrawn: 0, invalid: 0, bytes: 0, lastModified: null };
  let batch: OsvRecord[] = [];
  const decoder = new TextDecoder();
  const flush = (): void => {
    const records = batch;
    batch = [];
    stats.indexed += writeBatch(sink, records, false);
  };

  const unzip = new Unzip();
  unzip.register(selectiveInflate(skip));
  unzip.onfile = (file) => {
    stats.entries += 1;
    if (skip(file.name)) {
      if (isJsonEntry(file.name) && isMalwareId(file.name)) stats.skippedMalware += 1;
      file.ondata = () => {};
      file.start();
      return;
    }
    const parts: Uint8Array[] = [];
    let failed = false;
    file.ondata = (err, data, final) => {
      if (failed) return;
      if (err) {
        failed = true;
        stats.invalid += 1;
        return;
      }
      if (data && data.length > 0) parts.push(data);
      if (!final) return;
      const record = parseSnapshotRecord(parts.length === 1 ? decoder.decode(parts[0]) : decoder.decode(concat(parts)));
      if (!record) {
        stats.invalid += 1;
        return;
      }
      stats.records += 1;
      if (record.withdrawn) stats.withdrawn += 1;
      stats.lastModified = newer(stats.lastModified, record.modified ? normalizeTimestamp(record.modified) : null);
      batch.push(record);
    };
    file.start();
  };

  for await (const chunk of chunks) {
    stats.bytes += chunk.byteLength;
    for (let offset = 0; offset < chunk.byteLength; offset += PUSH_SLICE) {
      unzip.push(chunk.subarray(offset, offset + PUSH_SLICE), false);
      trimUnzipState(unzip);
    }
    if (batch.length >= batchSize) flush();
    options.onProgress?.({ bytes: stats.bytes, totalBytes: options.totalBytes ?? null, records: stats.records, skippedMalware: stats.skippedMalware });
  }
  try {
    unzip.push(new Uint8Array(0), true);
  } catch (err) {
    // trailing error is central-directory noise
    const complete = options.totalBytes !== undefined && options.totalBytes !== null && stats.bytes >= options.totalBytes;
    if (!complete || stats.records === 0) {
      flush();
      throw new Error(`The snapshot archive ended unexpectedly after ${formatBytes(stats.bytes)} (${(err as Error).message})`, { cause: err });
    }
  }
  flush();
  return stats;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const size = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

export interface ModifiedEntry {
  id: string;
  modified: string;
}

export interface ModifiedScan {
  // newest first, one per id
  entries: ModifiedEntry[];
  newest: string | null;
  truncated: boolean;
}

export async function readModifiedSince(
  lines: AsyncIterable<string> | Iterable<string>,
  since: string,
  options: { includeMalware?: boolean; maxEntries?: number } = {},
): Promise<ModifiedScan> {
  const floor = normalizeTimestamp(since);
  const max = options.maxEntries ?? 50_000;
  const seen = new Map<string, ModifiedEntry>();
  let newest: string | null = null;
  let older = 0;
  let truncated = false;
  for await (const raw of lines) {
    const line = raw.trim();
    const comma = line.indexOf(',');
    if (comma <= 0) continue;
    const stamp = line.slice(0, comma).trim();
    const id = line.slice(comma + 1).trim();
    if (!/^\d{4}-\d{2}-\d{2}T/.test(stamp) || !/^[A-Za-z0-9._-]+$/.test(id)) continue;
    const modified = normalizeTimestamp(stamp);
    if (modified <= floor) {
      older += 1;
      if (older > 200) break;
      continue;
    }
    if (!options.includeMalware && isMalwareId(id)) continue;
    const prev = seen.get(id);
    if (!prev || prev.modified < modified) seen.set(id, { id, modified });
    newest = newer(newest, modified);
    if (seen.size >= max) {
      truncated = true;
      break;
    }
  }
  const entries = [...seen.values()].sort((a, b) => (a.modified < b.modified ? 1 : a.modified > b.modified ? -1 : 0));
  return { entries, newest, truncated };
}

export interface IncrementalPlan {
  mode: 'up-to-date' | 'incremental' | 'full';
  // empty unless incremental
  fetch: ModifiedEntry[];
  // strictly newer than watermark
  fresh: number;
  // at least INCREMENTAL_MAX if cut short
  changed: number;
}

export function planIncremental(
  entries: readonly ModifiedEntry[],
  watermark: string,
  stored: ReadonlyMap<string, string>,
  options: { max?: number; truncated?: boolean } = {},
): IncrementalPlan {
  const max = options.max ?? INCREMENTAL_MAX;
  const mark = normalizeTimestamp(watermark);
  const fresh = entries.filter((e) => e.modified > mark);
  if (fresh.length === 0 && !options.truncated) return { mode: 'up-to-date', fetch: [], fresh: 0, changed: 0 };
  const margin = entries.filter((e) => e.modified <= mark && (stored.get(e.id) ?? '') < e.modified);
  const fetch = [...fresh, ...margin];
  if (options.truncated || fetch.length >= max) return { mode: 'full', fetch: [], fresh: fresh.length, changed: Math.max(fetch.length, options.truncated ? max : 0) };
  return { mode: 'incremental', fetch, fresh: fresh.length, changed: fetch.length };
}

function watermarkWithMargin(watermark: string): string {
  const ms = Date.parse(watermark);
  if (Number.isNaN(ms)) return watermark;
  return normalizeTimestamp(new Date(ms - WATERMARK_MARGIN_MS).toISOString());
}

function abortWith(signal: AbortSignal | undefined, controller: AbortController): void {
  if (!signal) return;
  if (signal.aborted) controller.abort(signal.reason);
  else signal.addEventListener('abort', () => controller.abort(signal.reason), { once: true });
}

// STALL_MS of silence aborts
async function* bodyChunks(res: Response, controller: AbortController, stallMs: number = STALL_MS): AsyncGenerator<Uint8Array> {
  if (!res.body) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const arm = (): void => {
    clearTimeout(timer);
    timer = setTimeout(() => controller.abort(new Error(`no data for ${Math.round(stallMs / 1000)} s`)), stallMs);
  };
  arm();
  try {
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      arm();
      yield chunk;
    }
  } finally {
    clearTimeout(timer);
  }
}

async function* textLines(chunks: AsyncIterable<Uint8Array>): AsyncGenerator<string> {
  const decoder = new TextDecoder();
  let buffer = '';
  for await (const chunk of chunks) {
    buffer += decoder.decode(chunk, { stream: true });
    let nl = buffer.indexOf('\n');
    while (nl !== -1) {
      yield buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      nl = buffer.indexOf('\n');
    }
  }
  buffer += decoder.decode();
  if (buffer) yield buffer;
}

async function openDownload(url: string, controller: AbortController): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: controller.signal });
  } catch (err) {
    throw new EnvironmentError(`Could not download ${url}: ${describeHttpError(err)}`, {
      hint: 'Check your connection and run patch-pilot db sync again.',
      cause: err,
    });
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    throw new EnvironmentError(`Could not download ${url}: HTTP ${res.status}`, { hint: 'Try again later: patch-pilot db sync' });
  }
  return res;
}

async function mapPool<T, R>(items: readonly T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      out[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return out;
}

function progressReporter(ui: Ui, label: string): { update: (p: LoadProgress) => void; done: (text?: string) => void } {
  const line = ui.progressLine();
  let lastStep = -1;
  return {
    update: (p) => {
      const pct = p.totalBytes ? Math.min(100, Math.floor((p.bytes / p.totalBytes) * 100)) : null;
      if (!line.tty) {
        // every 10% when not a tty
        const step = pct === null ? Math.floor(p.bytes / (25 * 1024 * 1024)) : Math.floor(pct / 10);
        if (step === lastStep) return;
        lastStep = step;
      }
      const size = p.totalBytes ? `${formatBytes(p.bytes)} of ${formatBytes(p.totalBytes)}` : formatBytes(p.bytes);
      line.update(`${label} ${pct === null ? '' : `${pct}% \u00b7 `}${size} \u00b7 ${p.records.toLocaleString('en-US')} records`);
    },
    done: (text) => line.done(text),
  };
}

function finishMeta(db: PatchPilotDb, source: string, lastModified: string | null, includeMalware: boolean): { loadedAt: string; records: number } {
  const loadedAt = new Date().toISOString();
  // 0 makes getSnapshotInfo count ids
  db.setMeta(META_KEYS.snapshotRecords, '0');
  const records = db.getSnapshotInfo().records;
  db.setSnapshotInfo({ loadedAt, source, records, ...(lastModified ? { lastModified } : {}) });
  db.setMeta(MALWARE_META_KEY, includeMalware ? 'true' : 'false');
  return { loadedAt, records };
}

async function fullSync(db: PatchPilotDb, ui: Ui, includeMalware: boolean, signal: AbortSignal | undefined): Promise<{ stats: LoadStats; loadedAt: string; total: number }> {
  const controller = new AbortController();
  abortWith(signal, controller);
  const res = await openDownload(OSV_NPM_ZIP, controller);
  const totalBytes = Number(res.headers.get('content-length')) || null;
  const progress = progressReporter(ui, 'Downloading the OSV npm snapshot');
  let stats: LoadStats;
  try {
    stats = await loadSnapshotZip(bodyChunks(res, controller), db, { includeMalware, totalBytes, onProgress: progress.update });
  } catch (err) {
    progress.done();
    if (err instanceof EnvironmentError) throw err;
    const reason = controller.signal.aborted ? String((controller.signal.reason as Error | undefined)?.message ?? 'aborted') : describeHttpError(err);
    throw new EnvironmentError(`The OSV snapshot download failed: ${reason}`, {
      hint: 'Records loaded so far are kept. Run patch-pilot db sync again to finish.',
      cause: err,
    });
  }
  progress.done();
  const { loadedAt, records } = finishMeta(db, SOURCE_FULL, stats.lastModified, includeMalware);
  return { stats, loadedAt, total: records };
}

async function fetchRecord(id: string, config: Config, signal: AbortSignal | undefined): Promise<{ id: string; record: OsvRecord | null; error: string | null }> {
  try {
    const record = await tryGetJson<OsvRecord>(`${OSV_NPM_RECORD_BASE}/${encodeURIComponent(id)}.json`, {
      timeoutMs: config.timeouts.osvMs,
      signal,
    });
    return { id, record: record && typeof record.id === 'string' ? record : null, error: null };
  } catch (err) {
    return { id, record: null, error: describeHttpError(err) };
  }
}

export async function syncSnapshot(config: Config, ui: Ui, options: SyncOptions = {}): Promise<SyncResult> {
  if (config.offline) {
    throw new EnvironmentError('patch-pilot db sync needs the network', { hint: 'Run it without --offline.' });
  }
  const started = Date.now();
  const includeMalware = options.includeMalware ?? false;
  const db = openDb(config.paths.dbFile);
  try {
    const info = db.getSnapshotInfo();
    const hadMalware = db.getMeta(MALWARE_META_KEY) === 'true';
    const previous = Boolean(info.loadedAt && info.lastModified && db.hasSnapshot());
    let reason: string | null = null;
    if (!previous) reason = 'first sync';
    else if (options.full) reason = '--full';
    else if (includeMalware && !hadMalware) reason = 'malware records requested';
    else if (!includeMalware && hadMalware) reason = 'malware records dropped';

    if (reason === null && info.lastModified) {
      const watermark = info.lastModified;
      const controller = new AbortController();
      abortWith(options.signal, controller);
      const res = await openDownload(OSV_NPM_MODIFIED, controller);
      let scan: ModifiedScan;
      try {
        scan = await readModifiedSince(textLines(bodyChunks(res, controller)), watermarkWithMargin(watermark), { includeMalware });
      } finally {
        controller.abort();
      }
      const stored = db.getVulnModified(scan.entries.map((e) => e.id));
      const plan = planIncremental(scan.entries, watermark, stored, { truncated: scan.truncated });
      if (plan.mode === 'up-to-date') {
        const loadedAt = new Date().toISOString();
        db.setSnapshotInfo({ loadedAt, source: info.source ?? SOURCE_FULL });
        ui.check('OSV snapshot is up to date', `${info.records.toLocaleString('en-US')} records \u00b7 ${formatDuration(Date.now() - started)}`);
        return { mode: 'up-to-date', records: 0, skippedMalware: 0, durationMs: Date.now() - started, loadedAt };
      }
      if (plan.mode === 'incremental') {
        const progress = ui.progressLine();
        const count = plan.fetch.length;
        let done = 0;
        const results = await mapPool(plan.fetch, FETCH_CONCURRENCY, async (entry) => {
          const result = await fetchRecord(entry.id, config, options.signal);
          done += 1;
          // every record on a tty, else 10%
          if (progress.tty || done === count || Math.floor((done * 10) / count) > Math.floor(((done - 1) * 10) / count)) {
            progress.update(`Updating the OSV snapshot ${done} of ${count}`);
          }
          return result;
        });
        progress.done();
        const records = results.map((r) => r.record).filter((r): r is OsvRecord => r !== null);
        const failed = results.filter((r) => r.error !== null);
        const missing = results.filter((r) => r.record === null && r.error === null).map((r) => r.id);
        db.transaction(() => {
          writeBatch(db, records, true);
          if (missing.length > 0) db.deleteSnapshotIds(missing);
        });
        // keep watermark so next sync retries
        const lastModified = failed.length > 0 ? watermark : (newer(watermark, scan.newest) ?? watermark);
        const { loadedAt, records: total } = finishMeta(db, SOURCE_INCREMENTAL, lastModified, includeMalware);
        const detail = `${records.length.toLocaleString('en-US')} updated \u00b7 ${total.toLocaleString('en-US')} records \u00b7 ${formatDuration(Date.now() - started)}`;
        ui.check('Updated the OSV snapshot', detail);
        if (failed.length > 0) ui.warn(`${failed.length} records could not be fetched`, `${failed[0]?.error ?? ''} \u00b7 run patch-pilot db sync again`);
        return { mode: 'incremental', records: records.length, skippedMalware: 0, durationMs: Date.now() - started, loadedAt };
      }
      reason = `${plan.changed >= INCREMENTAL_MAX ? `${INCREMENTAL_MAX} or more` : plan.changed} changed records`;
    }

    if (!includeMalware && hadMalware) db.clearSnapshot();
    ui.infoLine('Full OSV snapshot sync', `${reason ?? 'full'} \u00b7 about ${formatBytes(216_552_102)}${includeMalware ? ' \u00b7 including malware records' : ''}`);
    const { stats, loadedAt, total } = await fullSync(db, ui, includeMalware, options.signal);
    const parts = [
      `${total.toLocaleString('en-US')} records`,
      includeMalware ? null : `${stats.skippedMalware.toLocaleString('en-US')} malware records skipped`,
      stats.invalid > 0 ? `${stats.invalid} unreadable` : null,
      formatDuration(Date.now() - started),
    ].filter(Boolean);
    ui.check('Loaded the OSV snapshot', parts.join(' \u00b7 '));
    return { mode: 'full', records: stats.records, skippedMalware: stats.skippedMalware, durationMs: Date.now() - started, loadedAt };
  } finally {
    db.close();
  }
}

export async function snapshotStatus(config: Config): Promise<DbStatus> {
  const db = openDb(config.paths.dbFile, { readonly: true });
  try {
    return db.status();
  } finally {
    db.close();
  }
}

function tildify(file: string): string {
  const home = os.homedir();
  return home && file.startsWith(home) ? `~${file.slice(home.length)}` : file;
}

const STALE_DAYS = 7;

function formatAge(ms: number): string {
  const minutes = Math.max(0, Math.round(ms / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export function renderDbStatus(status: DbStatus, ui: Ui): string {
  const c = ui.c;
  const lines: string[] = [];
  if (!status.exists) {
    lines.push(ui.formatInfoLine('No local database yet', tildify(status.path), c));
    lines.push(ui.formatDimLines(['It is created on the first scan. For offline scans: patch-pilot db sync'], 2, c));
    return ui.text(lines.join('\n'));
  }
  const schema = status.schemaVersion === null ? 'schema unknown' : `schema v${status.schemaVersion}`;
  lines.push(ui.formatCheck('Local database', `${tildify(status.path)} \u00b7 ${formatBytes(status.sizeBytes)} \u00b7 ${schema}`, c));
  lines.push(
    ui.kv([
      ['Advisories', status.vulns.toLocaleString('en-US')],
      ['Query cache', `${status.queryCacheEntries.toLocaleString('en-US')} entries`],
      ['Registry cache', `${status.registryEntries.toLocaleString('en-US')} entries`],
      ['Web cache', `${status.webEntries.toLocaleString('en-US')} entries`],
    ]),
  );
  const snap = status.snapshot;
  if (!snap.loadedAt || snap.records === 0) {
    lines.push(ui.formatWarn('No offline snapshot', 'run patch-pilot db sync (about 207 MB download)', c));
  } else {
    const loaded = Date.parse(snap.loadedAt);
    const age = Number.isNaN(loaded) ? null : Date.now() - loaded;
    const when = Number.isNaN(loaded) ? snap.loadedAt : `${new Date(loaded).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
    const detail = `${snap.records.toLocaleString('en-US')} records \u00b7 synced ${age === null ? when : `${formatAge(age)} (${when})`}`;
    if (age !== null && age > STALE_DAYS * 24 * 60 * 60 * 1000) {
      lines.push(ui.formatWarn('Offline snapshot is out of date', `${detail} \u00b7 run patch-pilot db sync`, c));
    } else {
      lines.push(ui.formatCheck('Offline snapshot', detail, c));
    }
    // "Registry cache" is the longest key
    if (snap.source) lines.push(ui.kv([['Source'.padEnd('Registry cache'.length), snap.source]]));
  }
  return ui.text(lines.join('\n'));
}

// offline fallback for osv.ts
export function snapshotMatches(db: PatchPilotDb, name: string, version: string): string[] {
  const ids = new Set<string>();
  for (const row of db.snapshotFor(name)) {
    if (row.versions?.includes(version) || isAffected(version, row.ranges)) ids.add(row.id);
  }
  return [...ids].sort();
}
