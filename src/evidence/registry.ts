import type { AbbreviatedPackument, AbbreviatedVersion, RepositoryInfo, VersionManifest } from '../types.ts';
import { getJson, HttpError } from '../util/http.ts';
import { sortVersions } from '../util/semver.ts';
import type { PatchPilotDb } from './db.ts';

export const NPM_REGISTRY = 'https://registry.npmjs.org';
export const REGISTRY_TTL_MS = 24 * 60 * 60 * 1000;
const ABBREVIATED_ACCEPT = 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8';

export interface RegistryOptions {
  db: PatchPilotDb | null;
  offline: boolean;
  timeoutMs: number;
  refresh?: boolean;
  // default 24 h
  maxAgeMs?: number;
  signal?: AbortSignal;
}

const memo = new Map<string, { value: unknown; fetchedAt: number }>();

// tests
export function clearRegistryMemo(): void {
  memo.clear();
}

// "@scope/name" -> "@scope%2Fname"
export function encodePackageName(name: string): string {
  const trimmed = name.trim();
  if (trimmed.startsWith('@')) {
    const slash = trimmed.indexOf('/');
    if (slash > 1) return `@${encodeURIComponent(trimmed.slice(1, slash))}%2F${encodeURIComponent(trimmed.slice(slash + 1))}`;
  }
  return encodeURIComponent(trimmed);
}

async function cachedLookup<T>(key: string, options: RegistryOptions, fetcher: () => Promise<T | null>): Promise<T | null> {
  const maxAge = options.maxAgeMs ?? REGISTRY_TTL_MS;
  const now = Date.now();
  const inMemory = memo.get(key);
  if (inMemory && !options.refresh && now - inMemory.fetchedAt < maxAge) return inMemory.value as T | null;
  let row: { value: T | null; fetchedAt: string } | null = null;
  try {
    row = options.db?.getRegistry<T | null>(key) ?? null;
  } catch {
    row = null;
  }
  const rowTime = row ? Date.parse(row.fetchedAt) : Number.NaN;
  if (row && !options.refresh && Number.isFinite(rowTime) && now - rowTime < maxAge) {
    memo.set(key, { value: row.value, fetchedAt: rowTime });
    return row.value;
  }
  if (options.offline) return row ? row.value : ((inMemory?.value as T | null | undefined) ?? null);
  try {
    const value = await fetcher();
    memo.set(key, { value, fetchedAt: now });
    try {
      options.db?.putRegistry(key, value);
    } catch {
      // bad cache never fails a lookup
    }
    return value;
  } catch (err) {
    // caller aborts must surface, not fall back to stale cache
    if (options.signal?.aborted) throw err;
    if (row) return row.value;
    if (inMemory) return inMemory.value as T | null;
    throw err;
  }
}

function trimVersion(raw: Record<string, unknown>, version: string): AbbreviatedVersion {
  const out: AbbreviatedVersion = { version: typeof raw.version === 'string' ? raw.version : version };
  if (typeof raw.name === 'string') out.name = raw.name;
  if (typeof raw.deprecated === 'string' && raw.deprecated.trim() !== '') out.deprecated = raw.deprecated;
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'engines'] as const) {
    const value = raw[field];
    if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length > 0) out[field] = value as Record<string, string>;
  }
  const dist = raw.dist as { tarball?: unknown; integrity?: unknown; shasum?: unknown } | undefined;
  if (dist && typeof dist.tarball === 'string') {
    out.dist = { tarball: dist.tarball };
    if (typeof dist.integrity === 'string') out.dist.integrity = dist.integrity;
    if (typeof dist.shasum === 'string') out.dist.shasum = dist.shasum;
  }
  if (raw.hasInstallScript === true) out.hasInstallScript = true;
  return out;
}

function trimPackument(raw: Record<string, unknown>, name: string): AbbreviatedPackument {
  const versions: Record<string, AbbreviatedVersion> = {};
  const rawVersions = raw.versions && typeof raw.versions === 'object' ? (raw.versions as Record<string, Record<string, unknown>>) : {};
  for (const [version, value] of Object.entries(rawVersions)) {
    if (value && typeof value === 'object') versions[version] = trimVersion(value, version);
  }
  const tags = raw['dist-tags'] && typeof raw['dist-tags'] === 'object' ? (raw['dist-tags'] as Record<string, string>) : {};
  const out: AbbreviatedPackument = { name: typeof raw.name === 'string' ? raw.name : name, 'dist-tags': { ...tags }, versions };
  if (typeof raw.modified === 'string') out.modified = raw.modified;
  return out;
}

async function fetchRegistryJson(url: string, options: RegistryOptions, accept?: string): Promise<Record<string, unknown> | null> {
  try {
    return await getJson<Record<string, unknown>>(url, {
      timeoutMs: options.timeoutMs,
      signal: options.signal,
      headers: accept ? { accept } : undefined,
    });
  } catch (err) {
    if (err instanceof HttpError && (err.status === 404 || err.status === 405 || err.status === 410)) return null;
    throw err;
  }
}

export async function getPackument(name: string, options: RegistryOptions): Promise<AbbreviatedPackument | null> {
  return cachedLookup<AbbreviatedPackument>(`packument:${name}`, options, async () => {
    const raw = await fetchRegistryJson(`${NPM_REGISTRY}/${encodePackageName(name)}`, options, ABBREVIATED_ACCEPT);
    return raw ? trimPackument(raw, name) : null;
  });
}

export async function getVersionManifest(name: string, version: string, options: RegistryOptions): Promise<VersionManifest | null> {
  return cachedLookup<VersionManifest>(`manifest:${name}@${version}`, options, async () => {
    const raw = await fetchRegistryJson(`${NPM_REGISTRY}/${encodePackageName(name)}/${encodeURIComponent(version)}`, options);
    if (!raw || typeof raw.version !== 'string') return null;
    const keep: VersionManifest = { name: typeof raw.name === 'string' ? raw.name : name, version: raw.version };
    for (const field of ['description', 'repository', 'homepage', 'bugs', 'main', 'type', 'exports', 'dependencies', 'engines', 'deprecated', 'dist', 'license', 'module', 'types']) {
      if (raw[field] !== undefined) (keep as Record<string, unknown>)[field] = raw[field];
    }
    return keep;
  });
}

// packument keys
export async function getAvailableVersions(name: string, options: RegistryOptions): Promise<string[]> {
  const packument = await getPackument(name, options);
  return packument ? sortVersions(Object.keys(packument.versions)) : [];
}

// e.g. lodash 4.18.0
export async function getDeprecatedVersions(name: string, options: RegistryOptions): Promise<Set<string>> {
  const packument = await getPackument(name, options);
  const out = new Set<string>();
  for (const [version, info] of Object.entries(packument?.versions ?? {})) {
    if (typeof info.deprecated === 'string' && info.deprecated.trim() !== '') out.add(version);
  }
  return out;
}

export async function getDeprecation(name: string, version: string, options: RegistryOptions): Promise<string | null> {
  const packument = await getPackument(name, options);
  const message = packument?.versions[version]?.deprecated;
  return typeof message === 'string' && message.trim() !== '' ? message : null;
}

export async function getEnginesNode(name: string, version: string, options: RegistryOptions): Promise<string | null> {
  const packument = await getPackument(name, options);
  const engines = packument?.versions[version]?.engines as unknown;
  if (engines && typeof engines === 'object' && !Array.isArray(engines)) {
    const node = (engines as Record<string, unknown>).node;
    if (typeof node === 'string' && node.trim() !== '') return node.trim();
  }
  return null;
}

// manifest repo, else homepage or bugs
export async function getRepository(name: string, version: string, options: RegistryOptions): Promise<RepositoryInfo | null> {
  const manifest = await getVersionManifest(name, version, options);
  if (!manifest) return null;
  const repo = manifest.repository;
  if (typeof repo === 'string') {
    const parsed = parseRepositoryUrl(repo);
    if (parsed) return parsed;
  } else if (repo && typeof repo === 'object' && typeof repo.url === 'string') {
    const parsed = parseRepositoryUrl(repo.url, repo.directory ?? null);
    if (parsed) return parsed;
  }
  const bugs = typeof manifest.bugs === 'string' ? manifest.bugs : manifest.bugs?.url;
  for (const candidate of [manifest.homepage, bugs]) {
    if (typeof candidate !== 'string') continue;
    const parsed = parseRepositoryUrl(candidate);
    if (parsed && parsed.host !== 'other') return parsed;
  }
  return null;
}

const HOSTS: Record<string, { domain: string; host: RepositoryInfo['host'] }> = {
  github: { domain: 'github.com', host: 'github' },
  gitlab: { domain: 'gitlab.com', host: 'gitlab' },
  bitbucket: { domain: 'bitbucket.org', host: 'other' },
};

function hostKind(domain: string): RepositoryInfo['host'] {
  if (domain === 'github.com') return 'github';
  if (domain === 'gitlab.com') return 'gitlab';
  return 'other';
}

function build(domain: string, segments: string[], directory: string | null): RepositoryInfo | null {
  const host = hostKind(domain);
  const clean = segments.map((s) => s.trim()).filter((s) => s !== '');
  if (clean.length === 0) return { url: `https://${domain}`, host, owner: null, repo: null, directory };
  let owner: string | null = null;
  let repo: string | null = null;
  let rest: string[] = [];
  if (host === 'gitlab') {
    const marker = clean.indexOf('-');
    const repoPath = marker === -1 ? clean : clean.slice(0, marker);
    rest = marker === -1 ? [] : clean.slice(marker + 1);
    if (repoPath.length >= 2) {
      repo = (repoPath[repoPath.length - 1] as string).replace(/\.git$/i, '');
      owner = repoPath.slice(0, -1).join('/');
    }
  } else if (clean.length >= 2) {
    owner = clean[0] as string;
    repo = (clean[1] as string).replace(/\.git$/i, '');
    rest = clean.slice(2);
  }
  let dir = directory;
  if (!dir && (rest[0] === 'tree' || rest[0] === 'blob') && rest.length > 2) dir = rest.slice(2).join('/');
  if (owner && repo) return { url: `https://${domain}/${owner}/${repo}`, host, owner, repo, directory: dir ?? null };
  return { url: `https://${domain}/${clean.join('/').replace(/\.git$/i, '')}`, host, owner: null, repo: null, directory: dir ?? null };
}

export function parseRepositoryUrl(url: string, directory?: string | null): RepositoryInfo | null {
  if (typeof url !== 'string') return null;
  const raw = url.trim();
  if (raw === '') return null;
  const dir = typeof directory === 'string' && directory.trim() !== '' ? directory.trim().replace(/^\.?\/+|\/+$/g, '') : null;
  // "github:owner/repo" and friends
  const shorthand = /^(github|gitlab|bitbucket):([^\s#]+?)(?:\.git)?(?:#.*)?$/i.exec(raw);
  if (shorthand) {
    const spec = HOSTS[(shorthand[1] as string).toLowerCase()];
    if (spec) return build(spec.domain, (shorthand[2] as string).split('/'), dir);
  }
  // npm's github shorthand
  if (/^[\w.-]+\/[\w.-]+$/.test(raw) && !raw.includes('..')) return build('github.com', raw.split('/'), dir);
  // scp-like git@github.com:owner/repo.git
  const scp = /^(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,}):(?!\/\/)([^\s]+)$/i.exec(raw);
  if (scp) return build((scp[1] as string).toLowerCase().replace(/^www\./, ''), (scp[2] as string).replace(/#.*$/, '').split('/'), dir);
  let parsed: URL;
  try {
    parsed = new URL(raw.replace(/^git\+/i, ''));
  } catch {
    return null;
  }
  if (!['http:', 'https:', 'git:', 'ssh:', 'git+ssh:', 'git+https:'].includes(parsed.protocol)) return null;
  const domain = parsed.hostname.toLowerCase().replace(/^www\./, '');
  if (domain === '') return null;
  let pathname = parsed.pathname;
  try {
    pathname = decodeURIComponent(pathname);
  } catch {
  }
  return build(domain, pathname.split('/'), dir);
}
