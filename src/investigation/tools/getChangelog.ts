// release notes, plus shared web helpers
import { getPackument, getVersionManifest, parseRepositoryUrl, type RegistryOptions } from '../../evidence/registry.ts';
import type {
  AbbreviatedPackument,
  ChangelogInfo,
  ChangelogRelease,
  Config,
  RepositoryInfo,
  ToolContext,
  ToolResult,
  VersionManifest,
} from '../../types.ts';
import { normalizeText } from '../../util/html.ts';
import { describeHttpError, getJson, getText, HttpError, tryGetJson } from '../../util/http.ts';
import { compareVersions, isMajorBump, parseVersion } from '../../util/semver.ts';

export interface GetChangelogArgs {
  package: string;
  fromVersion: string;
  toVersion: string;
}

// web tools cache envelope

export const DAY_MS = 24 * 60 * 60 * 1000;
// kept for --offline, age checked on read
const STORE_TTL_MS = 30 * DAY_MS;
const MEMORY_MAX = 300;

export class OfflineCacheMiss extends Error {
  constructor(what: string) {
    super(`${what} is not cached and the network is off (--offline)`);
    this.name = 'OfflineCacheMiss';
  }
}

interface Envelope<T> {
  v: T;
  at: number;
}

export interface CacheHit<T> {
  value: T;
  fetchedAt: number;
  stale: boolean;
}

type CacheCtx = Pick<ToolContext, 'cache' | 'config'>;

// fallback when ctx.cache is null
const memory = new Map<string, Envelope<unknown>>();

// tests
export function clearWebMemoryCache(): void {
  memory.clear();
}

// any age under --offline
export function readCache<T>(ctx: CacheCtx, namespace: string, key: string, maxAgeMs: number = DAY_MS): CacheHit<T> | null {
  let env: unknown;
  try {
    env = ctx.cache ? ctx.cache.get(namespace, key) : memory.get(`${namespace}::${key}`);
  } catch {
    return null;
  }
  if (!env || typeof env !== 'object' || !('v' in env) || typeof (env as Envelope<T>).at !== 'number') return null;
  const { v, at } = env as Envelope<T>;
  const stale = Date.now() - at > maxAgeMs;
  if (stale && !ctx.config.offline) return null;
  return { value: v, fetchedAt: at, stale };
}

// cache failure never fails a tool
export function writeCache(ctx: CacheCtx, namespace: string, key: string, value: unknown): void {
  const env: Envelope<unknown> = { v: value, at: Date.now() };
  try {
    if (ctx.cache) ctx.cache.set(namespace, key, env, STORE_TTL_MS);
    else {
      memory.set(`${namespace}::${key}`, env);
      if (memory.size > MEMORY_MAX) {
        const oldest = memory.keys().next().value;
        if (oldest !== undefined) memory.delete(oldest);
      }
    }
  } catch {
    // ignore
  }
}

export async function cachedFetch<T>(
  ctx: CacheCtx,
  namespace: string,
  key: string,
  fetcher: () => Promise<T>,
  options: { maxAgeMs?: number; what?: string } = {},
): Promise<{ value: T; cached: boolean; fetchedAt: number }> {
  const hit = readCache<T>(ctx, namespace, key, options.maxAgeMs);
  if (hit) return { value: hit.value, cached: true, fetchedAt: hit.fetchedAt };
  if (ctx.config.offline) throw new OfflineCacheMiss(options.what ?? `${namespace} ${key}`);
  const value = await fetcher();
  writeCache(ctx, namespace, key, value);
  return { value, cached: false, fetchedAt: Date.now() };
}

export function ageText(fetchedAt: number, now: number = Date.now()): string {
  const minutes = Math.max(0, Math.round((now - fetchedAt) / 60_000));
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export const GITHUB_API = 'https://api.github.com';
export const GITHUB_RAW = 'https://raw.githubusercontent.com';

// GITHUB_TOKEN raises the rate limit, never logged
export function githubHeaders(config: Pick<Config, 'githubToken'>): Record<string, string> {
  const headers: Record<string, string> = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
  if (config.githubToken) headers.authorization = `Bearer ${config.githubToken}`;
  return headers;
}

// 403 or 429
export function isRateLimited(err: unknown): boolean {
  return err instanceof HttpError && (err.status === 429 || (err.status === 403 && /rate limit/i.test(err.body)));
}

export function describeWebError(err: unknown): string {
  if (isRateLimited(err)) return 'GitHub API rate limit reached (set GITHUB_TOKEN to raise it)';
  if (err instanceof OfflineCacheMiss) return 'not cached (offline)';
  return describeHttpError(err);
}

export interface GithubRelease {
  tag: string;
  name: string | null;
  body: string;
  publishedAt: string | null;
  url: string | null;
  prerelease: boolean;
}

interface RawRelease {
  tag_name?: string;
  name?: string | null;
  body?: string | null;
  published_at?: string | null;
  created_at?: string | null;
  html_url?: string | null;
  draft?: boolean;
  prerelease?: boolean;
}

export const RELEASE_PAGES_MAX = 5;
const RELEASE_BODY_MAX = 20_000;

export function trimRelease(raw: RawRelease): GithubRelease {
  return {
    tag: String(raw.tag_name ?? ''),
    name: raw.name ? String(raw.name) : null,
    body: String(raw.body ?? '').slice(0, RELEASE_BODY_MAX),
    publishedAt: raw.published_at ?? raw.created_at ?? null,
    url: raw.html_url ?? null,
    prerelease: Boolean(raw.prerelease),
  };
}

interface ReleaseListEntry {
  releases: GithubRelease[];
  pages: number;
  complete: boolean;
}

export interface ReleaseListing {
  releases: GithubRelease[];
  complete: boolean;
  cached: boolean;
  // later page failed, list is partial
  error?: unknown;
}

// newest first, max 5 pages
export async function listGithubReleases(
  owner: string,
  repo: string,
  ctx: CacheCtx & Pick<ToolContext, 'signal'>,
  options: { stopBelow?: string | null; pkg?: string } = {},
): Promise<ReleaseListing> {
  const key = `releases:${owner}/${repo}`.toLowerCase();
  const hit = readCache<ReleaseListEntry>(ctx, 'github', key);
  let entry: ReleaseListEntry = hit?.value ?? { releases: [], pages: 0, complete: false };
  const reached = (): boolean =>
    entry.complete ||
    (options.stopBelow !== undefined &&
      options.stopBelow !== null &&
      entry.releases.some((r) => {
        const v = versionFromTag(r.tag, options.pkg);
        return v !== null && compareVersions(v, options.stopBelow as string) <= 0;
      }));
  if (hit && (reached() || entry.pages >= RELEASE_PAGES_MAX || ctx.config.offline)) {
    return { releases: entry.releases, complete: entry.complete, cached: true };
  }
  if (ctx.config.offline) throw new OfflineCacheMiss(`GitHub releases of ${owner}/${repo}`);
  const startPages = entry.pages;
  let error: unknown;
  for (let page = entry.pages + 1; page <= RELEASE_PAGES_MAX; page += 1) {
    try {
      const list = await getJson<RawRelease[]>(`${GITHUB_API}/repos/${owner}/${repo}/releases?per_page=100&page=${page}`, {
        headers: githubHeaders(ctx.config),
        timeoutMs: ctx.config.timeouts.webMs,
        signal: ctx.signal,
      });
      const items = Array.isArray(list) ? list : [];
      entry = {
        releases: [...entry.releases, ...items.filter((r) => !r.draft && r.tag_name).map(trimRelease)],
        pages: page,
        complete: items.length < 100,
      };
      if (reached()) break;
    } catch (err) {
      error = err;
      break;
    }
  }
  if (entry.pages > startPages) writeCache(ctx, 'github', key, entry);
  if (error !== undefined && entry.pages === 0) throw error;
  return error === undefined
    ? { releases: entry.releases, complete: entry.complete, cached: false }
    : { releases: entry.releases, complete: entry.complete, cached: false, error };
}

function samePackage(prefix: string, pkg: string): boolean {
  const p = prefix.toLowerCase();
  const n = pkg.toLowerCase();
  const base = n.includes('/') ? n.slice(n.lastIndexOf('/') + 1) : n;
  return p === n || p === base || p === n.replace(/^@/, '');
}

// null for another package's tag
export function versionFromTag(tag: string, pkg?: string): string | null {
  let t = tag.trim();
  if (!t) return null;
  const at = t.lastIndexOf('@');
  if (at > 0) {
    if (pkg && !samePackage(t.slice(0, at), pkg)) return null;
    t = t.slice(at + 1);
  } else {
    const m = /^([A-Za-z][\w.-]*?)[-_/ ]v?(\d+\.\d+.*)$/.exec(t);
    if (m?.[1] && m[2]) {
      if (!/^(?:release|releases|version|rel|tag)$/i.test(m[1]) && pkg && !samePackage(m[1], pkg)) return null;
      t = m[2];
    }
  }
  t = t.replace(/^v(?=\d)/i, '');
  if (/^\d+\.\d+$/.test(t)) t = `${t}.0`;
  if (!/^\d+\.\d+\.\d+/.test(t)) return null;
  return parseVersion(t)?.version ?? null;
}

// from < v <= to, one per version
export function releasesBetween(releases: readonly GithubRelease[], pkg: string, from: string, to: string): GithubRelease[] {
  const byVersion = new Map<string, GithubRelease>();
  for (const r of releases) {
    const v = versionFromTag(r.tag, pkg) ?? (r.name ? versionFromTag(r.name, pkg) : null);
    if (v === null) continue;
    if (compareVersions(v, from) <= 0 || compareVersions(v, to) > 0) continue;
    if (!byVersion.has(v)) byVersion.set(v, r);
  }
  return [...byVersion.entries()].sort((a, b) => compareVersions(b[0], a[0])).map(([, r]) => r);
}

export const NPM_REGISTRY_URL = 'https://registry.npmjs.org';

function registryPath(name: string): string {
  return name.startsWith('@') ? name.replace('/', '%2F') : encodeURIComponent(name);
}

function isDbCache(cache: unknown): boolean {
  const c = cache as { getRegistry?: unknown; putRegistry?: unknown } | null;
  return Boolean(c && typeof c.getRegistry === 'function' && typeof c.putRegistry === 'function');
}

function registryOptions(ctx: CacheCtx & Pick<ToolContext, 'signal'>): RegistryOptions {
  return {
    db: isDbCache(ctx.cache) ? (ctx.cache as unknown as RegistryOptions['db']) : null,
    offline: ctx.config.offline,
    timeoutMs: ctx.config.timeouts.registryMs,
    signal: ctx.signal,
  };
}

// registry.ts first, then web cache
async function viaRegistry<T>(primary: () => Promise<T | null>, fallback: () => Promise<T | null>, offline: boolean): Promise<T | null> {
  try {
    const value = await primary();
    if (value !== null || !offline) return value;
  } catch (err) {
    if (err instanceof OfflineCacheMiss) throw err;
  }
  return fallback();
}

export async function loadPackument(pkg: string, ctx: CacheCtx & Pick<ToolContext, 'signal'>): Promise<AbbreviatedPackument | null> {
  return viaRegistry(
    () => getPackument(pkg, registryOptions(ctx)),
    async () =>
      (
        await cachedFetch(
          ctx,
          'registry',
          `packument:${pkg}`,
          () =>
            tryGetJson<AbbreviatedPackument>(`${NPM_REGISTRY_URL}/${registryPath(pkg)}`, {
              headers: { accept: 'application/vnd.npm.install-v1+json' },
              timeoutMs: ctx.config.timeouts.registryMs,
              signal: ctx.signal,
            }),
          { what: `registry data for ${pkg}` },
        )
      ).value,
    ctx.config.offline,
  );
}

export async function loadManifest(pkg: string, version: string, ctx: CacheCtx & Pick<ToolContext, 'signal'>): Promise<VersionManifest | null> {
  return viaRegistry(
    () => getVersionManifest(pkg, version, registryOptions(ctx)),
    async () =>
      (
        await cachedFetch(
          ctx,
          'registry',
          `manifest:${pkg}@${version}`,
          () =>
            tryGetJson<VersionManifest>(`${NPM_REGISTRY_URL}/${registryPath(pkg)}/${encodeURIComponent(version)}`, {
              timeoutMs: ctx.config.timeouts.registryMs,
              signal: ctx.signal,
            }),
          { what: `the registry manifest of ${pkg}@${version}` },
        )
      ).value,
    ctx.config.offline,
  );
}

// registry.ts can't parse some repo urls
export function parseRepoUrl(raw: string, directory: string | null = null): RepositoryInfo | null {
  let s = raw.trim();
  if (!s) return null;
  const shorthand = /^(?:(github|gitlab|bitbucket):)?([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:#.*)?$/.exec(s);
  if (shorthand && !s.includes('://') && !s.startsWith('git@')) {
    const hostName = shorthand[1] ?? 'github';
    const owner = shorthand[2] ?? '';
    const repo = shorthand[3] ?? '';
    const host = hostName === 'github' ? 'github' : hostName === 'gitlab' ? 'gitlab' : 'other';
    return { url: `https://${hostName}.${hostName === 'bitbucket' ? 'org' : 'com'}/${owner}/${repo}`, host, owner, repo, directory };
  }
  s = s
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^ssh:\/\/(?:[^@/]+@)?/, 'https://')
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/^http:\/\//, 'https://');
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  const hostname = url.hostname.replace(/^www\./, '').toLowerCase();
  const [owner, repoRaw] = url.pathname.split('/').filter(Boolean);
  if (!owner || !repoRaw) return null;
  const repo = repoRaw.replace(/\.git$/, '');
  const host = hostname === 'github.com' ? 'github' : hostname === 'gitlab.com' ? 'gitlab' : 'other';
  return { url: `https://${hostname}/${owner}/${repo}`, host, owner, repo, directory };
}

export function repositoryFromManifest(manifest: VersionManifest | null): RepositoryInfo | null {
  const field = manifest?.repository;
  if (!field) return null;
  const raw = typeof field === 'string' ? field : field.url;
  const directory = typeof field === 'object' ? (field.directory ?? null) : null;
  if (!raw) return null;
  try {
    const parsed = parseRepositoryUrl(raw, directory);
    if (parsed) return parsed;
  } catch {
  }
  return parseRepoUrl(raw, directory);
}

export interface PackageMeta {
  repository: RepositoryInfo | null;
  homepage: string | null;
}

// given versions first, then latest
export async function resolvePackageMeta(pkg: string, versions: readonly (string | null | undefined)[], ctx: CacheCtx & Pick<ToolContext, 'signal'>): Promise<PackageMeta> {
  const tried = new Set<string>();
  let lastError: unknown;
  for (const version of [...versions, 'latest']) {
    if (!version || tried.has(version)) continue;
    tried.add(version);
    try {
      const manifest = await loadManifest(pkg, version, ctx);
      if (!manifest) continue;
      const repository = repositoryFromManifest(manifest);
      const homepage = typeof manifest.homepage === 'string' && /^https?:\/\//.test(manifest.homepage) ? manifest.homepage : null;
      if (repository || homepage) return { repository, homepage };
    } catch (err) {
      lastError = err;
      if (err instanceof OfflineCacheMiss) break;
    }
  }
  if (lastError !== undefined) throw lastError;
  return { repository: null, homepage: null };
}

const CHANGELOG_FILES = ['CHANGELOG.md', 'HISTORY.md', 'History.md', 'CHANGES.md', 'changelog.md', 'CHANGELOG'];
const CHANGELOG_MAX_CHARS = 1_000_000;

export interface ChangelogFile {
  // e.g. "CHANGELOG.md"
  path: string;
  // for humans
  url: string;
  text: string;
}

// package dir first in a monorepo
export async function fetchChangelogFile(repo: RepositoryInfo, ctx: CacheCtx & Pick<ToolContext, 'signal'>): Promise<ChangelogFile | null> {
  if (repo.host !== 'github' || !repo.owner || !repo.repo) return null;
  const { owner, repo: name } = repo;
  const dir = repo.directory ? repo.directory.replace(/^\.?\/+|\/+$/g, '') : '';
  const candidates = [...(dir ? CHANGELOG_FILES.slice(0, 4).map((f) => `${dir}/${f}`) : []), ...CHANGELOG_FILES];
  const key = `changelog-file:${owner}/${name}${dir ? `/${dir}` : ''}`.toLowerCase();
  const { value } = await cachedFetch<ChangelogFile | null>(
    ctx,
    'github',
    key,
    async () => {
      for (const path of candidates) {
        try {
          const text = await getText(`${GITHUB_RAW}/${owner}/${name}/HEAD/${path}`, {
            timeoutMs: ctx.config.timeouts.webMs,
            signal: ctx.signal,
            retries: 0,
          });
          if (text.trim()) return { path, url: `https://github.com/${owner}/${name}/blob/HEAD/${path}`, text: text.slice(0, CHANGELOG_MAX_CHARS) };
        } catch (err) {
          if (err instanceof HttpError && err.status === 404) continue;
          throw err;
        }
      }
      return null;
    },
    { what: `the changelog of ${owner}/${name}` },
  );
  return value;
}

export interface ChangelogSection {
  version: string;
  heading: string;
  date: string | null;
  body: string;
  // 1-based
  line: number;
}

// null for "Bug Fixes" or "Unreleased"
export function versionInHeading(heading: string): string | null {
  const text = heading
    .replace(/<[^>]+>/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[[\]*_`]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const lead = /^(?:(?:version|release|v\.)\s*)?(?:[\w@/.-]+?[@ ])?v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)(?![\d.]*\d)/i.exec(text);
  const node = /\bversion\s+v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/i.exec(text);
  const raw = lead && lead.index === 0 ? lead[1] : node?.[1];
  if (!raw) return null;
  const full = /^\d+\.\d+$/.test(raw) ? `${raw}.0` : raw;
  return parseVersion(full)?.version ?? null;
}

// ATX and setext headings
export function parseChangelogSections(markdown: string): ChangelogSection[] {
  const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
  const sections: ChangelogSection[] = [];
  let current: { version: string; heading: string; line: number; body: string[] } | null = null;
  const close = (): void => {
    if (!current) return;
    const body = current.body
      .filter((l) => !/^\s*\[[^\]]+\]:\s*\S+\s*$/.test(l))
      .join('\n')
      .trim();
    sections.push({
      version: current.version,
      heading: current.heading,
      date: /\b(\d{4}-\d{2}-\d{2})\b/.exec(current.heading)?.[1] ?? null,
      body,
      line: current.line,
    });
  };
  let fence = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    if (!fence) {
      const atx = /^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
      const next = lines[i + 1] ?? '';
      const setext = !atx && line.trim() !== '' && /^\s{0,3}(=+|-+)\s*$/.test(next) && next.trim().length >= 3 ? line.trim() : null;
      const headingText = atx?.[1] ?? setext;
      const version = headingText ? versionInHeading(headingText) : null;
      if (headingText && version) {
        close();
        current = { version, heading: headingText, line: i + 1, body: [] };
        if (setext) i += 1;
        continue;
      }
    }
    current?.body.push(line);
  }
  close();
  return sections;
}

// from < v <= to, newest first
export function sliceChangelog(markdown: string, from: string, to: string): ChangelogSection[] {
  const seen = new Set<string>();
  return parseChangelogSections(markdown)
    .filter((s) => compareVersions(s.version, from) > 0 && compareVersions(s.version, to) <= 0)
    .filter((s) => (seen.has(s.version) ? false : (seen.add(s.version), true)))
    .sort((a, b) => compareVersions(b.version, a.version));
}

const BREAKING_PATTERNS: readonly RegExp[] = [
  /\bBREAKING\b/,
  /\bbreaking changes?\b/i,
  /\bremoved\b/i,
  /\bdrop(?:ped|s)? support\b/i,
  /\bno longer\b/i,
  /\brenamed\b/i,
  /\bnow requires?\b/i,
];

export function isBreakingLine(line: string): boolean {
  return BREAKING_PATTERNS.some((re) => re.test(line));
}

export function cleanNoteLine(line: string): string {
  let s = line.trim();
  s = s.replace(/^(?:[-*+]|\d+[.)])\s+/, '');
  s = s.replace(/^\[[ xX]\]\s+/, '');
  // " ([#2227](...))", " (#1234)", " #1532"
  for (let i = 0; i < 6; i += 1) {
    const before = s;
    s = s
      .replace(/\s*\(\s*\[[^\]]*\]\([^)]*\)(?:\s*,\s*\[[^\]]*\]\([^)]*\))*\s*\)\s*$/, '')
      .replace(/\s*\[[#@]?[\w.-]+\]\([^)]*\)\s*$/, '')
      .replace(/\s*\(#\d+\)\s*$/, '')
      .replace(/(?:\s+#\d+)+\s*$/, '');
    if (s === before) break;
  }
  s = s.replace(/\*\*|__/g, '').replace(/\s+/g, ' ').trim();
  return s.length > 300 ? `${s.slice(0, 299)}\u2026` : s;
}

export interface BreakingLine {
  tag: string;
  text: string;
}

export function findBreakingLines(body: string): string[] {
  const out: string[] = [];
  let inBreaking = false;
  // -1 when none
  let listIndent = -1;
  let fence = false;
  for (const raw of body.replace(/\r\n?/g, '\n').split('\n')) {
    if (/^\s*(```|~~~)/.test(raw)) {
      fence = !fence;
      continue;
    }
    if (fence) continue;
    const heading = /^\s{0,3}#{1,6}\s+(.*)$/.exec(raw) ?? /^\s*\*\*([^*]+)\*\*:?\s*$/.exec(raw);
    if (heading) {
      inBreaking = /breaking/i.test(heading[1] ?? '');
      listIndent = -1;
      continue;
    }
    if (!raw.trim() || /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(raw)) continue;
    const indent = raw.length - raw.trimStart().length;
    if (listIndent >= 0 && indent <= listIndent) listIndent = -1;
    // express style nested breaking list
    if (/^\s*[-*+]\s+(?:\*\*|__)?breaking(?: changes?)?(?:\*\*|__)?:?\s*$/i.test(raw)) {
      listIndent = indent;
      continue;
    }
    if (inBreaking || listIndent >= 0 || isBreakingLine(raw)) {
      const clean = cleanNoteLine(raw);
      if (clean.length >= 3) out.push(clean);
    }
  }
  return out;
}

const BREAKING_MAX = 60;

export function collectBreakingLines(releases: readonly ChangelogRelease[]): BreakingLine[] {
  const seen = new Set<string>();
  const out: BreakingLine[] = [];
  for (const release of releases) {
    for (const text of findBreakingLines(release.body)) {
      const key = text.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ tag: release.tag, text });
      if (out.length >= BREAKING_MAX) return out;
    }
  }
  return out;
}

function cleanVersion(version: string): string {
  return parseVersion(version)?.version ?? version.trim().replace(/^v(?=\d)/i, '');
}

function sectionToRelease(section: ChangelogSection, file: ChangelogFile): ChangelogRelease {
  return { tag: section.version, name: section.heading, publishedAt: section.date, url: file.url, body: section.body.slice(0, RELEASE_BODY_MAX) };
}

function githubToRelease(release: GithubRelease): ChangelogRelease {
  return { tag: release.tag, name: release.name, publishedAt: release.publishedAt, url: release.url, body: normalizeText(release.body) };
}

export async function getChangelogInfo(pkg: string, fromVersion: string, toVersion: string, ctx: ToolContext): Promise<ChangelogInfo> {
  const from = cleanVersion(fromVersion);
  const to = cleanVersion(toVersion);
  const info: ChangelogInfo = {
    package: pkg,
    fromVersion: from,
    toVersion: to,
    majorBump: isMajorBump(from, to),
    source: 'unavailable',
    repository: null,
    releases: [],
    breakingLines: [],
    targetDeprecated: null,
    targetEnginesNode: null,
  };
  const cacheKey = `${pkg}@${from}..${to}`;
  const hit = readCache<ChangelogInfo>(ctx, 'changelog', cacheKey);
  if (hit) {
    const original = hit.value.source;
    return { ...hit.value, source: 'cache', note: `cached ${ageText(hit.fetchedAt)} (from ${original === 'changelog-file' ? 'the changelog file' : 'GitHub releases'})` };
  }

  const notes: string[] = [];
  let offlineMiss = false;
  const handle = (err: unknown, what: string): void => {
    if (err instanceof OfflineCacheMiss) offlineMiss = true;
    else notes.push(`${what}: ${describeWebError(err)}`);
  };

  try {
    const packument = await loadPackument(pkg, ctx);
    if (!packument) notes.push(`${pkg} was not found in the npm registry`);
    else {
      const target = packument.versions?.[to];
      if (target) {
        info.targetDeprecated = typeof target.deprecated === 'string' && target.deprecated ? target.deprecated : null;
        info.targetEnginesNode = target.engines?.node ?? null;
      } else notes.push(`${pkg}@${to} is not published`);
    }
  } catch (err) {
    handle(err, 'registry lookup failed');
  }

  let repo: RepositoryInfo | null = null;
  try {
    repo = (await resolvePackageMeta(pkg, [to, from], ctx)).repository;
  } catch (err) {
    handle(err, 'repository lookup failed');
  }
  if (repo) info.repository = repo.url;

  if (repo && repo.host === 'github' && repo.owner && repo.repo) {
    let releasesError: unknown = null;
    try {
      const listing = await listGithubReleases(repo.owner, repo.repo, ctx, { stopBelow: from, pkg });
      const between = releasesBetween(listing.releases, pkg, from, to);
      if (listing.error !== undefined) notes.push(`the release list may be incomplete (${describeWebError(listing.error)})`);
      else if (!listing.complete) {
        const listed = listing.releases.map((r) => versionFromTag(r.tag, pkg)).filter((v): v is string => v !== null);
        const oldest = listed.sort(compareVersions)[0];
        if (oldest !== undefined && compareVersions(oldest, from) > 0) {
          notes.push(`only the newest ${RELEASE_PAGES_MAX * 100} GitHub releases were read; notes older than ${oldest} are missing`);
        }
      }
      if (between.some((r) => r.body.trim() !== '')) {
        info.releases = between.map(githubToRelease);
        info.source = 'github-releases';
      }
    } catch (err) {
      if (err instanceof OfflineCacheMiss) offlineMiss = true;
      else releasesError = err;
    }
    if (info.source === 'unavailable') {
      try {
        const file = await fetchChangelogFile(repo, ctx);
        const sections = file ? sliceChangelog(file.text, from, to) : [];
        if (file && sections.length > 0) {
          info.releases = sections.map((s) => sectionToRelease(s, file));
          info.source = 'changelog-file';
          if (releasesError !== null) notes.push(`GitHub releases unavailable (${describeWebError(releasesError)}); used ${file.path}`);
          else notes.push(`no GitHub releases in range; used ${file.path}`);
        }
      } catch (err) {
        if (err instanceof OfflineCacheMiss) offlineMiss = true;
        else notes.push(`changelog file: ${describeWebError(err)}`);
      }
    }
    if (info.source === 'unavailable') {
      if (releasesError !== null) notes.push(`GitHub releases: ${describeWebError(releasesError)}`);
      if (!offlineMiss) notes.push(`no release notes between ${from} and ${to} in ${repo.url}`);
    }
  } else if (repo) {
    notes.push(`release notes are read from GitHub only; the repository is ${repo.url}`);
  } else if (!offlineMiss) {
    notes.push(`no repository is listed in the npm registry for ${pkg}`);
  }

  if (info.source === 'unavailable' && offlineMiss) notes.unshift('unavailable offline');
  info.breakingLines = collectBreakingLines(info.releases).map((b) => b.text);
  if (notes.length > 0) info.note = [...new Set(notes)].join('; ');
  if (info.source === 'github-releases' || info.source === 'changelog-file') writeCache(ctx, 'changelog', cacheKey, info);
  return info;
}

const TEXT_BUDGET = 1400;
const LINE_MAX = 220;

function shortDate(iso: string | null): string {
  return iso ? iso.slice(0, 10) : '';
}

function capLine(text: string, max: number = LINE_MAX): string {
  return text.length > max ? `${text.slice(0, max - 1)}\u2026` : text;
}

function tagLabel(tag: string): string {
  return /^\d/.test(tag) ? `v${tag}` : tag;
}

export function formatChangelogText(info: ChangelogInfo, budget: number = TEXT_BUDGET): { text: string; truncated: boolean } {
  const lines: string[] = [];
  const sourceLabel: Record<ChangelogInfo['source'], string> = {
    'github-releases': 'GitHub releases',
    'changelog-file': 'changelog file',
    cache: 'cache',
    unavailable: 'unavailable',
  };
  lines.push(
    `${info.package} ${info.fromVersion} \u2192 ${info.toVersion}: ${info.majorBump ? 'major bump, breaking changes possible' : 'same major line'}.`,
  );
  const target: string[] = [`engines.node ${info.targetEnginesNode ?? 'not declared'}`];
  target.push(info.targetDeprecated ? `DEPRECATED: ${capLine(info.targetDeprecated, 160)}` : 'not deprecated');
  lines.push(`Target ${info.toVersion}: ${target.join(', ')}.`);
  lines.push(`Release notes: ${sourceLabel[info.source]}${info.releases.length > 0 ? `, ${info.releases.length} releases` : ''}${info.repository ? ` (${info.repository})` : ''}.`);
  if (info.note) lines.push(`Note: ${capLine(info.note, 300)}`);

  let used = lines.join('\n').length;
  let truncated = false;
  const breaking = collectBreakingLines(info.releases);
  const releaseReserve = info.releases.length > 0 ? 160 : 0;
  if (breaking.length > 0) {
    const head = `Breaking changes (${breaking.length}):`;
    lines.push(head);
    used += head.length + 1;
    let shown = 0;
    for (const b of breaking) {
      const line = `- ${tagLabel(b.tag)}: ${capLine(b.text)}`;
      if (used + line.length + 1 > budget - releaseReserve) {
        truncated = true;
        break;
      }
      lines.push(line);
      used += line.length + 1;
      shown += 1;
    }
    if (shown < breaking.length) {
      const more = `  (${breaking.length - shown} more breaking lines omitted)`;
      lines.push(more);
      used += more.length + 1;
    }
  } else if (info.releases.length > 0) {
    lines.push('No lines flagged as breaking.');
    used += 29;
  }
  if (info.releases.length > 0) {
    const items = info.releases.map((r) => `${tagLabel(r.tag)}${r.publishedAt ? ` ${shortDate(r.publishedAt)}` : ''}`);
    let list = 'Releases: ';
    let shown = 0;
    for (const item of items) {
      const piece = `${shown > 0 ? ', ' : ''}${item}`;
      if (used + list.length + piece.length + 16 > budget) {
        truncated = true;
        break;
      }
      list += piece;
      shown += 1;
    }
    if (shown < items.length) list += `, +${items.length - shown} more`;
    lines.push(list);
  }
  return { text: lines.join('\n'), truncated };
}

export async function handleGetChangelog(args: GetChangelogArgs, ctx: ToolContext): Promise<ToolResult> {
  const pkg = String(args.package ?? '').trim();
  if (!pkg) return { ok: false, hint: 'package is required', error: 'package is required, for example {"package":"marked","fromVersion":"0.3.6","toVersion":"4.0.10"}' };
  let from = String(args.fromVersion ?? '').trim();
  let to = String(args.toVersion ?? '').trim();
  for (const [name, value] of [
    ['fromVersion', from],
    ['toVersion', to],
  ] as const) {
    if (!parseVersion(value)) {
      return { ok: false, hint: `${name} is not a version`, error: `${name} "${value}" is not a semver version; use an exact version such as 4.0.10` };
    }
  }
  let swapped = false;
  if (compareVersions(from, to) > 0) {
    [from, to] = [to, from];
    swapped = true;
  }
  const info = await getChangelogInfo(pkg, from, to, ctx);
  const formatted = formatChangelogText(info);
  const text = swapped ? `(fromVersion and toVersion were swapped so the range goes up)\n${formatted.text}` : formatted.text;
  const breaking = info.breakingLines.length;
  const major = info.majorBump ? ', major bump' : '';
  const hint =
    info.source === 'unavailable'
      ? `release notes ${info.note?.startsWith('unavailable offline') ? 'unavailable offline' : 'not found'}${major}${info.targetEnginesNode ? `; target needs Node ${info.targetEnginesNode}` : ''}`
      : `${info.releases.length} releases, ${breaking} breaking-change line${breaking === 1 ? '' : 's'}${major}${info.source === 'cache' ? ' (cached)' : ''}`;
  return {
    ok: true,
    hint,
    text,
    truncated: formatted.truncated,
    cached: info.source === 'cache',
    data: {
      package: info.package,
      fromVersion: info.fromVersion,
      toVersion: info.toVersion,
      majorBump: info.majorBump,
      source: info.source,
      repository: info.repository,
      releases: info.releases.length,
      breakingLines: info.breakingLines.slice(0, 20),
      targetDeprecated: info.targetDeprecated,
      targetEnginesNode: info.targetEnginesNode,
      note: info.note ?? null,
    },
  };
}
