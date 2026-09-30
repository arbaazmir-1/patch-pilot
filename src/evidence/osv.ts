// osv.dev client with cache and snapshot
import type { OsvRecord, VulnSourceInfo, VulnSourceMode } from '../types.ts';
import { EnvironmentError, isNotImplemented } from '../util/errors.ts';
import { describeHttpError, postJson, tryGetJson } from '../util/http.ts';
import { isAffected } from '../util/semver.ts';
import { META_KEYS, normalizeTimestamp, type PatchPilotDb } from './db.ts';
import { snapshotMatches } from './snapshot.ts';

export const OSV_API = 'https://api.osv.dev/v1';
export const QUERYBATCH_CHUNK = 500;
export const HYDRATE_CONCURRENCY = 6;
export const STALE_AFTER_HOURS = 24 * 7;
// osv 400s above this
export const QUERYBATCH_MAX = 1000;

export interface OsvPackageVersion {
  name: string;
  version: string;
}

export interface OsvQueryOptions {
  db: PatchPilotDb | null;
  offline: boolean;
  // still writes the cache
  refresh?: boolean;
  timeoutMs: number;
  concurrency?: number;
  chunkSize?: number;
  onProgress?: (done: number, total: number, label: string) => void;
  signal?: AbortSignal;
}

export interface OsvQueryResult {
  // "name@version" -> non-withdrawn ids
  idsByPackage: Map<string, string[]>;
  records: Map<string, OsvRecord>;
  source: VulnSourceInfo;
  stats: { queried: number; vulnIds: number; hydrated: number; cacheHits: number; durationMs: number };
}

export function pairKey(name: string, version: string): string {
  return `${name}@${version}`;
}

interface BatchResponse {
  results?: { vulns?: { id?: string; modified?: string }[]; next_page_token?: string }[];
}

// max 1000 pairs
export async function queryBatch(
  pairs: readonly OsvPackageVersion[],
  options: Pick<OsvQueryOptions, 'timeoutMs' | 'signal'>,
): Promise<{ id: string; modified: string }[][]> {
  if (pairs.length === 0) return [];
  if (pairs.length > QUERYBATCH_MAX) throw new Error(`querybatch accepts at most ${QUERYBATCH_MAX} queries (got ${pairs.length})`);
  const toQuery = (p: OsvPackageVersion, pageToken?: string): Record<string, unknown> => {
    const query: Record<string, unknown> = { package: { name: p.name, ecosystem: 'npm' }, version: p.version };
    if (pageToken) query.page_token = pageToken;
    return query;
  };
  const collect = (entry: { vulns?: { id?: string; modified?: string }[] } | undefined): { id: string; modified: string }[] =>
    (entry?.vulns ?? []).filter((v) => typeof v?.id === 'string' && v.id !== '').map((v) => ({ id: v.id as string, modified: v.modified ?? '' }));
  const http = { timeoutMs: options.timeoutMs, signal: options.signal };
  const first = await postJson<BatchResponse>(`${OSV_API}/querybatch`, { queries: pairs.map((p) => toQuery(p)) }, http);
  const results = first.results ?? [];
  const out = pairs.map((_, i) => collect(results[i]));
  // big results page via next_page_token
  let pending = pairs.flatMap((p, i) => (results[i]?.next_page_token ? [{ i, p, token: results[i]?.next_page_token as string }] : []));
  for (let page = 0; pending.length > 0 && page < 20; page += 1) {
    const next = await postJson<BatchResponse>(`${OSV_API}/querybatch`, { queries: pending.map((x) => toQuery(x.p, x.token)) }, http);
    const again: typeof pending = [];
    pending.forEach((x, j) => {
      const entry = next.results?.[j];
      (out[x.i] as { id: string; modified: string }[]).push(...collect(entry));
      if (entry?.next_page_token) again.push({ ...x, token: entry.next_page_token });
    });
    pending = again;
  }
  return out.map((list) => {
    const seen = new Set<string>();
    return list.filter((v) => (seen.has(v.id) ? false : (seen.add(v.id), true)));
  });
}

// null on 404
export async function fetchVuln(id: string, options: Pick<OsvQueryOptions, 'timeoutMs' | 'signal'>): Promise<OsvRecord | null> {
  const record = await tryGetJson<OsvRecord>(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { timeoutMs: options.timeoutMs, signal: options.signal });
  if (!record || typeof record !== 'object' || typeof record.id !== 'string') return null;
  return record;
}

async function mapPool<T, R>(items: readonly T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      out[index] = await fn(items[index] as T);
    }
  });
  await Promise.all(workers);
  return out;
}

function chunks<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

// local query as fallback
function snapshotIds(db: PatchPilotDb, name: string, version: string): string[] {
  try {
    return snapshotMatches(db, name, version);
  } catch (err) {
    if (!isNotImplemented(err)) throw err;
  }
  return db
    .snapshotFor(name)
    .filter((row) => (row.versions ?? []).includes(version) || isAffected(version, row.ranges))
    .map((row) => row.id);
}

function isWithdrawn(record: OsvRecord): boolean {
  return typeof record.withdrawn === 'string' && record.withdrawn.trim() !== '';
}

export function formatDataAge(ageHours: number): string {
  if (!Number.isFinite(ageHours) || ageHours < 0) return 'age unknown';
  if (ageHours < 1 / 60) return 'just now';
  if (ageHours < 1) return `${Math.max(1, Math.round(ageHours * 60))} min old`;
  if (ageHours < 48) return `${Math.round(ageHours)} h old`;
  return `${Math.round(ageHours / 24)} days old`;
}

export async function queryOsv(pairs: readonly OsvPackageVersion[], options: OsvQueryOptions): Promise<OsvQueryResult> {
  const started = Date.now();
  const db = options.db;
  const concurrency = options.concurrency ?? HYDRATE_CONCURRENCY;
  const chunkSize = Math.min(Math.max(1, options.chunkSize ?? QUERYBATCH_CHUNK), QUERYBATCH_MAX);
  const unique: OsvPackageVersion[] = [];
  const seenPairs = new Set<string>();
  for (const p of pairs) {
    if (!p || typeof p.name !== 'string' || typeof p.version !== 'string' || p.name === '' || p.version.trim() === '') continue;
    const key = pairKey(p.name, p.version);
    if (seenPairs.has(key)) continue;
    seenPairs.add(key);
    unique.push({ name: p.name, version: p.version });
  }
  const idsByPackage = new Map<string, string[]>();
  const records = new Map<string, OsvRecord>();
  const warnings: string[] = [];
  let hydrated = 0;
  let cacheHits = 0;
  const safeDb = <T>(fn: (d: PatchPilotDb) => T, fallback: T): T => {
    if (!db) return fallback;
    try {
      return fn(db);
    } catch {
      return fallback;
    }
  };

  const live = new Map<string, { id: string; modified: string }[]>();
  let liveError: unknown = null;
  if (!options.offline && unique.length > 0) {
    let done = 0;
    for (const chunk of chunks(unique, chunkSize)) {
      try {
        const results = await queryBatch(chunk, options);
        chunk.forEach((p, i) => live.set(pairKey(p.name, p.version), results[i] ?? []));
        done += chunk.length;
        options.onProgress?.(done, unique.length, 'querybatch');
      } catch (err) {
        if (options.signal?.aborted) throw err;
        liveError = err;
        break;
      }
    }
  }
  const liveFetchedAt = new Date().toISOString();

  // skip unchanged cached records
  const liveIds = new Map<string, string>();
  for (const vulns of live.values()) for (const v of vulns) liveIds.set(v.id, v.modified);
  const cachedModified = safeDb((d) => d.getVulnModified([...liveIds.keys()]), new Map<string, string>());
  const toFetch: string[] = [];
  for (const [id, modified] of liveIds) {
    if (!options.refresh && modified !== '' && cachedModified.get(id) === normalizeTimestamp(modified)) {
      const record = safeDb((d) => d.getVuln(id), null);
      if (record) {
        records.set(id, record);
        cacheHits += 1;
        continue;
      }
    }
    toFetch.push(id);
  }
  let staleRecords = 0;
  let missingRecords = 0;
  if (toFetch.length > 0) {
    let done = 0;
    const fetched = await mapPool(toFetch, concurrency, async (id) => {
      try {
        const record = await fetchVuln(id, options);
        return { id, record, error: null as unknown };
      } catch (error) {
        if (options.signal?.aborted) throw error;
        return { id, record: null, error };
      } finally {
        done += 1;
        options.onProgress?.(done, toFetch.length, id);
      }
    });
    const fresh: OsvRecord[] = [];
    for (const item of fetched) {
      if (item.record) {
        records.set(item.id, item.record);
        fresh.push(item.record);
        hydrated += 1;
        continue;
      }
      const cached = safeDb((d) => d.getVuln(item.id), null);
      if (cached) {
        records.set(item.id, cached);
        cacheHits += 1;
        if (item.error) staleRecords += 1;
      } else {
        missingRecords += 1;
      }
    }
    safeDb((d) => d.putVulns(fresh, 'api'), undefined);
  }
  if (live.size > 0) {
    safeDb(
      (d) => d.putQueries([...live.entries()].map(([key, vulns]) => {
        const at = key.lastIndexOf('@');
        return { pkg: key.slice(0, at), version: key.slice(at + 1), ids: vulns.map((v) => v.id), fetchedAt: liveFetchedAt };
      })),
      undefined,
    );
  }
  for (const [key, vulns] of live) idsByPackage.set(key, vulns.map((v) => v.id));

  // unanswered: cache, then snapshot
  const fallback = unique.filter((p) => !live.has(pairKey(p.name, p.version)));
  let fromCache = 0;
  let fromSnapshot = 0;
  let uncovered = 0;
  let oldest = live.size > 0 ? Date.parse(liveFetchedAt) : Number.POSITIVE_INFINITY;
  let snapshotAgeUnknown = false;
  if (fallback.length > 0) {
    const hasSnapshot = safeDb((d) => d.hasSnapshot(), false);
    const snapshotLoadedAt = hasSnapshot ? safeDb((d) => d.getMeta(META_KEYS.snapshotLoadedAt), null) : null;
    for (const p of fallback) {
      const key = pairKey(p.name, p.version);
      const row = safeDb((d) => d.getQuery(p.name, p.version), null);
      if (row) {
        idsByPackage.set(key, row.ids);
        fromCache += 1;
        const t = Date.parse(row.fetchedAt);
        if (Number.isFinite(t)) oldest = Math.min(oldest, t);
        continue;
      }
      if (hasSnapshot && db) {
        let ids: string[] = [];
        try {
          ids = snapshotIds(db, p.name, p.version);
        } catch {
          ids = [];
        }
        idsByPackage.set(key, ids);
        fromSnapshot += 1;
        const t = snapshotLoadedAt ? Date.parse(snapshotLoadedAt) : Number.NaN;
        if (Number.isFinite(t)) oldest = Math.min(oldest, t);
        else snapshotAgeUnknown = true;
        continue;
      }
      uncovered += 1;
    }
    const wanted = new Set<string>();
    for (const p of fallback) for (const id of idsByPackage.get(pairKey(p.name, p.version)) ?? []) if (!records.has(id)) wanted.add(id);
    const cachedRecords = safeDb((d) => d.getVulns([...wanted]), new Map<string, OsvRecord>());
    for (const id of wanted) {
      const record = cachedRecords.get(id);
      if (record) {
        records.set(id, record);
        cacheHits += 1;
      } else {
        missingRecords += 1;
      }
    }
  }

  if (unique.length > 0 && live.size === 0 && fromCache === 0 && fromSnapshot === 0) {
    const reason = options.offline ? 'Offline mode is on' : `OSV.dev is unreachable (${describeHttpError(liveError)})`;
    throw new EnvironmentError(`${reason} and there is no cached vulnerability data for this project.`, {
      hint: options.offline
        ? 'Run once without --offline to fill the cache, or download the offline snapshot with: patch-pilot db sync'
        : 'Check the network and run again, or download the offline snapshot with: patch-pilot db sync',
    });
  }

  // drop withdrawn and recordless ids
  for (const [key, ids] of idsByPackage) {
    const kept: string[] = [];
    for (const id of ids) {
      const record = records.get(id);
      if (record && !isWithdrawn(record)) kept.push(id);
    }
    idsByPackage.set(key, [...new Set(kept)]);
  }
  for (const [id, record] of records) if (isWithdrawn(record)) records.delete(id);

  const mode: VulnSourceMode = fallback.length === 0 ? 'live' : fromCache > 0 ? 'cache' : fromSnapshot > 0 ? 'snapshot' : 'live';
  const now = Date.now();
  const fetchedAtMs = Number.isFinite(oldest) ? oldest : now;
  const ageHours = Math.max(0, (now - fetchedAtMs) / 3_600_000);
  if (liveError && !options.offline) {
    warnings.push(`OSV.dev could not be reached (${describeHttpError(liveError)}); ${fallback.length} of ${unique.length} packages were checked against cached data.`);
  }
  if (ageHours > STALE_AFTER_HOURS) {
    warnings.push(`Vulnerability data is ${formatDataAge(ageHours)}: run again online to refresh it, or update the offline snapshot with patch-pilot db sync.`);
  }
  if (snapshotAgeUnknown) warnings.push('The offline snapshot has no recorded sync time, so its age is unknown.');
  if (uncovered > 0) {
    warnings.push(`${uncovered} of ${unique.length} packages have no cached vulnerability data and were not checked.`);
  }
  if (missingRecords > 0) warnings.push(`${missingRecords} vulnerability record${missingRecords === 1 ? '' : 's'} could not be loaded and ${missingRecords === 1 ? 'was' : 'were'} left out.`);
  if (staleRecords > 0) warnings.push(`${staleRecords} record${staleRecords === 1 ? '' : 's'} could not be refreshed; the cached copy was used.`);
  const source: VulnSourceInfo = { mode, fetchedAt: new Date(fetchedAtMs).toISOString(), ageHours: Math.round(ageHours * 100) / 100 };
  if (warnings.length > 0) source.warning = warnings.join(' ');
  const vulnIds = new Set<string>();
  for (const ids of idsByPackage.values()) for (const id of ids) vulnIds.add(id);
  return {
    idsByPackage,
    records,
    source,
    stats: { queried: unique.length, vulnIds: vulnIds.size, hydrated, cacheHits, durationMs: Date.now() - started },
  };
}
