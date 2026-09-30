// web_search: ollama, brave or package docs
import type { Config, RepositoryInfo, SearchBackendName, ToolContext, ToolResult, WebSearchHit, WebSearchResponse } from '../../types.ts';
import { decodeEntities, oneLineText, queryKeywords, queryWeights, snippetAround, stripMarkdownNoise } from '../../util/html.ts';
import { getJson, getText, HttpError, postJson } from '../../util/http.ts';
import { compareVersions, isMajorBump, parseVersion } from '../../util/semver.ts';
import {
  cachedFetch,
  describeWebError,
  GITHUB_API,
  type GithubRelease,
  githubHeaders,
  isRateLimited,
  listGithubReleases,
  loadPackument,
  OfflineCacheMiss,
  type PackageMeta,
  readCache,
  resolvePackageMeta,
  trimRelease,
  versionFromTag,
  writeCache,
} from './getChangelog.ts';

export interface WebSearchArgs {
  query: string;
  maxResults?: number;
}

export interface WebSearchContext {
  // drives docs search and ranking
  package?: string;
  fromVersion?: string;
  toVersion?: string;
  repository?: RepositoryInfo | null;
  maxResults?: number;
}

export const OLLAMA_WEB_SEARCH_URL = 'https://ollama.com/api/web_search';
export const JSDELIVR_DATA_URL = 'https://data.jsdelivr.com/v1/packages/npm';
export const JSDELIVR_CDN_URL = 'https://cdn.jsdelivr.net/npm';
export const SNIPPET_CHARS = 300;
export const DEFAULT_SEARCH_RESULTS = 5;
// under the registry's 2000-char cap
const TOOL_TEXT_BUDGET = 1800;
export const MAX_SEARCH_RESULTS = 10;

// auto: ollama with a key, else docs
function backendFor(config: Pick<Config, 'search' | 'ollamaApiKey' | 'offline'>): SearchBackendName | null {
  if (config.offline || config.search === 'off') return null;
  if (config.search === 'auto') return config.ollamaApiKey ? 'ollama' : 'docs';
  return config.search;
}

// null when off or offline
export function resolveSearchBackend(ctx: ToolContext): SearchBackendName | null {
  return backendFor(ctx.config);
}

interface SearchTarget {
  package: string | null;
  from: string | null;
  to: string | null;
  // undefined resolves via registry
  repository: RepositoryInfo | null | undefined;
}

// bare majors become X.0.0
export function versionsInQuery(query: string, pkg?: string | null): string[] {
  const out = new Set<string>();
  for (const m of query.matchAll(/(?:^|[\s@(])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?=$|[\s),;])/g)) {
    const v = parseVersion(m[1] ?? '');
    if (v) out.add(v.version);
  }
  for (const m of query.matchAll(/(?:^|\s)v(\d{1,3})(?:\.x)?(?=$|[\s,;])/gi)) out.add(`${m[1]}.0.0`);
  for (const m of query.matchAll(/(?:^|\s)(\d{1,3})\.x(?=$|[\s,;])/g)) out.add(`${m[1]}.0.0`);
  if (pkg) {
    const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const m of query.matchAll(new RegExp(`(?:^|\\s)${escaped}\\s+v?(\\d{1,3})(?=$|[\\s,;])`, 'gi'))) out.add(`${m[1]}.0.0`);
  }
  return [...out];
}

function resolveTarget(ctx: ToolContext, search: WebSearchContext, query: string): SearchTarget {
  const pkg = search.package?.trim() || ctx.focus?.package || null;
  let from = search.fromVersion ?? null;
  let to = search.toVersion ?? null;
  if (pkg && (!from || !to)) {
    const focusVersion = ctx.focus?.package === pkg ? ctx.focus.version : null;
    const cases = ctx.caseFile?.packages.filter((p) => p.name === pkg) ?? [];
    const installed = cases.find((p) => p.version === focusVersion)?.version ?? cases[0]?.version ?? null;
    if (!from) from = installed ?? focusVersion;
    if (!to) {
      if (focusVersion && from && compareVersions(focusVersion, from) > 0) to = focusVersion;
      else {
        const fixes = (ctx.caseFile?.vulnerabilities ?? [])
          .filter((v) => v.package === pkg && (!from || v.installedVersion === from) && v.recommendedFix)
          .map((v) => v.recommendedFix?.version ?? '')
          .filter(Boolean)
          .sort(compareVersions);
        to = fixes[fixes.length - 1] ?? null;
      }
    }
  }
  if (pkg && !to) {
    const named = versionsInQuery(query, pkg).sort(compareVersions);
    to = named[named.length - 1] ?? null;
  }
  return { package: pkg, from, to, repository: search.repository };
}

// first version of each line crossed
export function majorBoundaries(from: string | null, to: string | null, available?: readonly string[]): string[] {
  const f = from ? parseVersion(from) : null;
  const t = to ? parseVersion(to) : null;
  if (!f || !t || !isMajorBump(f.version, t.version)) return [];
  const out: string[] = [];
  if (available && available.length > 0) {
    let line = f.version;
    for (const v of [...available].sort(compareVersions)) {
      if (compareVersions(v, f.version) <= 0 || compareVersions(v, t.version) > 0) continue;
      if ((parseVersion(v)?.prerelease.length ?? 0) > 0) continue;
      if (isMajorBump(line, v)) {
        out.push(v);
        line = v;
      }
    }
    return out;
  }
  if (f.major === 0) {
    const next = `0.${f.minor + 1}.0`;
    if (compareVersions(next, t.version) <= 0) out.push(next);
  }
  for (let major = Math.max(1, f.major + 1); major <= t.major; major += 1) out.push(`${major}.0.0`);
  return out;
}

type CandidateKind = 'release' | 'migration' | 'changelog' | 'readme' | 'issue';

interface Candidate {
  kind: CandidateKind;
  title: string;
  url: string;
  // for ranking and snippet
  text: string;
  version?: string;
  // boost boundary notes, queried versions
  boost?: number;
}

const KIND_BONUS: Record<CandidateKind, number> = { migration: 2, release: 1.2, changelog: 0.8, readme: 1.5, issue: 0 };
// older boundaries fade
const BOUNDARY_BOOST: readonly number[] = [3, 1.5, 0.75];

function presence(text: string, keywords: readonly string[], weights: readonly number[]): number {
  const lower = text.toLowerCase();
  let score = 0;
  keywords.forEach((k, i) => {
    if (lower.includes(k.toLowerCase())) score += weights[i] ?? 1;
  });
  return score;
}

function rankCandidates(candidates: readonly Candidate[], query: string): Candidate[] {
  const keywords = queryKeywords(query);
  const weights = queryWeights(keywords);
  const scored = candidates.map((c, index) => ({
    c,
    index,
    score:
      presence(stripMarkdownNoise(c.text), keywords, weights) +
      0.5 * presence(c.title, keywords, weights) +
      KIND_BONUS[c.kind] +
      (c.boost ?? 0),
  }));
  return scored.sort((a, b) => b.score - a.score || a.index - b.index).map((s) => s.c);
}

// capped per kind, leftovers by rank
function diversify(ranked: readonly Candidate[], max: number): Candidate[] {
  const caps: Record<CandidateKind, number> = {
    release: Math.max(2, max - 3),
    migration: max,
    changelog: 2,
    readme: 1,
    issue: Math.max(1, Math.floor(max / 3)),
  };
  const used: Record<CandidateKind, number> = { release: 0, migration: 0, changelog: 0, readme: 0, issue: 0 };
  const picked = new Set<Candidate>();
  for (const c of ranked) {
    if (picked.size >= max) break;
    if (used[c.kind] >= caps[c.kind]) continue;
    used[c.kind] += 1;
    picked.add(c);
  }
  for (const c of ranked) {
    if (picked.size >= max) break;
    picked.add(c);
  }
  return ranked.filter((c) => picked.has(c));
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

// repo, homepage, gh pages, npm/cdn
export function isOwnDomain(url: string, pkg: string | null, meta: PackageMeta): boolean {
  const host = hostOf(url);
  if (!host) return false;
  const lower = url.toLowerCase();
  const repo = meta.repository;
  if (repo?.url && (lower.startsWith(repo.url.toLowerCase()) || lower.startsWith(repo.url.toLowerCase().replace('https://', 'https://www.')))) return true;
  if (repo?.owner && host === `${repo.owner.toLowerCase()}.github.io`) return true;
  const home = meta.homepage ? hostOf(meta.homepage) : null;
  if (home && home !== 'github.com' && (host === home || host.endsWith(`.${home}`))) return true;
  if (pkg) {
    const name = pkg.toLowerCase();
    if (host === 'npmjs.com' && lower.includes(`/package/${name}`)) return true;
    if ((host === 'cdn.jsdelivr.net' || host === 'unpkg.com') && lower.includes(`/${name}@`)) return true;
  }
  return false;
}

// own-domain first, stable
export function rankOwnDomainsFirst<T extends { url: string }>(hits: readonly T[], pkg: string | null, meta: PackageMeta): T[] {
  const own = hits.filter((h) => isOwnDomain(h.url, pkg, meta));
  return [...own, ...hits.filter((h) => !own.includes(h))];
}

interface OllamaSearchResponse {
  results?: { title?: string; url?: string; content?: string }[];
}

// snippets capped at 300 chars
export async function ollamaSearch(query: string, maxResults: number, ctx: ToolContext): Promise<WebSearchHit[]> {
  const res = await postJson<OllamaSearchResponse>(
    OLLAMA_WEB_SEARCH_URL,
    { query, max_results: Math.max(1, Math.min(MAX_SEARCH_RESULTS, maxResults)) },
    {
      headers: { authorization: `Bearer ${ctx.config.ollamaApiKey ?? ''}` },
      timeoutMs: ctx.config.timeouts.webMs,
      signal: ctx.signal,
      retries: 1,
    },
  );
  const keywords = queryKeywords(query);
  const weights = queryWeights(keywords);
  const hits: WebSearchHit[] = [];
  for (const r of Array.isArray(res?.results) ? res.results : []) {
    const url = typeof r?.url === 'string' ? r.url.trim() : '';
    if (!/^https?:\/\//i.test(url)) continue;
    const title = oneLineText(typeof r.title === 'string' && r.title.trim() ? r.title : url).slice(0, 200);
    const snippet = snippetAround(typeof r.content === 'string' ? r.content.slice(0, 60_000) : '', keywords, SNIPPET_CHARS, weights);
    hits.push({ title, url, snippet, backend: 'ollama' });
  }
  return hits.slice(0, maxResults);
}

export const BRAVE_SEARCH_URL = 'https://api.search.brave.com/res/v1/web/search';

interface BraveSearchResponse {
  web?: { results?: { title?: string; url?: string; description?: string; extra_snippets?: string[] }[] };
}

// strip highlight tags, decode entities
function braveText(value: unknown): string {
  return typeof value === 'string' ? oneLineText(decodeEntities(value.replace(/<[^>]*>/g, ''))) : '';
}

// never leaks the key
function braveFailure(err: unknown, token: string): Error {
  let message: string;
  if (err instanceof HttpError) {
    let reason = '';
    try {
      const body = JSON.parse(err.body) as { error?: { detail?: unknown; code?: unknown } };
      const detail = body?.error?.detail ?? body?.error?.code;
      if (typeof detail === 'string') reason = oneLineText(detail).slice(0, 160);
    } catch {
      // not JSON: status only
    }
    const auth = err.status === 401 || err.status === 403 ? ' (check BRAVE_SEARCH_API_KEY)' : err.status === 429 ? ' (rate limit)' : '';
    message = `HTTP ${err.status} from Brave Search${reason ? `: ${reason}` : ''}${auth}`;
  } else {
    message = describeWebError(err);
  }
  if (token.length >= 4) message = message.split(token).join('****');
  // no cause, keeps raw body out of logs
  return new Error(message);
}

// needs BRAVE_SEARCH_API_KEY
export async function braveSearch(query: string, maxResults: number, ctx: ToolContext): Promise<WebSearchHit[]> {
  const token = ctx.config.braveApiKey ?? '';
  if (!token) throw new Error('Brave search needs BRAVE_SEARCH_API_KEY');
  const count = Math.max(1, Math.min(MAX_SEARCH_RESULTS, Math.trunc(maxResults) || DEFAULT_SEARCH_RESULTS));
  const url = `${BRAVE_SEARCH_URL}?${new URLSearchParams({ q: query, count: String(count) }).toString()}`;
  let res: BraveSearchResponse;
  try {
    res = await getJson<BraveSearchResponse>(url, {
      headers: { accept: 'application/json', 'x-subscription-token': token },
      timeoutMs: ctx.config.timeouts.webMs,
      signal: ctx.signal,
      retries: 1,
    });
  } catch (err) {
    throw braveFailure(err, token);
  }
  const keywords = queryKeywords(query);
  const weights = queryWeights(keywords);
  const hits: WebSearchHit[] = [];
  const seen = new Set<string>();
  const results = Array.isArray(res?.web?.results) ? res.web.results : [];
  for (const r of results) {
    const link = typeof r?.url === 'string' ? r.url.trim() : '';
    if (!/^https?:\/\//i.test(link) || seen.has(link)) continue;
    seen.add(link);
    const title = (braveText(r.title) || link).slice(0, 200);
    const extra = Array.isArray(r.extra_snippets) ? r.extra_snippets.map(braveText).filter(Boolean) : [];
    const text = [braveText(r.description), ...extra].filter(Boolean).join(' ');
    hits.push({ title, url: link, snippet: snippetAround(text, keywords, SNIPPET_CHARS, weights), backend: 'brave' });
  }
  return hits.slice(0, count);
}

interface JsdelivrListing {
  version?: string;
  files?: { name: string; size?: number }[];
}

const DOC_FILE = /^(?:readme|changelog|changes|history|migrat|upgrad)[\w.-]*$/i;
const DOC_EXT = /(?:\.(?:md|markdown|txt|rst))?$/i;
const DOC_FILES_MAX = 4;
const DOC_FILE_MAX_BYTES = 1_000_000;

function docKind(name: string): CandidateKind {
  if (/migrat|upgrad/i.test(name)) return 'migration';
  if (/changelog|changes|history/i.test(name)) return 'changelog';
  return 'readme';
}

async function jsdelivrCandidates(pkg: string, version: string, ctx: ToolContext): Promise<Candidate[]> {
  const listing = (
    await cachedFetch(
      ctx,
      'docs',
      `jsdelivr:${pkg}@${version}`,
      () => getJson<JsdelivrListing>(`${JSDELIVR_DATA_URL}/${pkg}@${version}?structure=flat`, { timeoutMs: ctx.config.timeouts.webMs, signal: ctx.signal }),
      { what: `the file list of ${pkg}@${version}` },
    )
  ).value;
  const resolved = listing.version ?? version;
  const files = (listing.files ?? [])
    .filter((f) => {
      const base = f.name.slice(f.name.lastIndexOf('/') + 1);
      return DOC_FILE.test(base) && DOC_EXT.test(base) && !f.name.includes('/node_modules/') && (f.size ?? 0) <= DOC_FILE_MAX_BYTES;
    })
    .sort((a, b) => {
      const depth = (n: string): number => n.split('/').length;
      const rank = (n: string): number => ({ migration: 0, changelog: 1, readme: 2, release: 3, issue: 4 })[docKind(n)];
      return depth(a.name) - depth(b.name) || rank(a.name) - rank(b.name) || a.name.localeCompare(b.name);
    })
    .slice(0, DOC_FILES_MAX);
  const out: Candidate[] = [];
  for (const file of files) {
    const url = `${JSDELIVR_CDN_URL}/${pkg}@${resolved}${file.name.startsWith('/') ? '' : '/'}${file.name}`;
    try {
      const text = (
        await cachedFetch(ctx, 'docs', `file:${pkg}@${resolved}${file.name}`, () => getText(url, { timeoutMs: ctx.config.timeouts.webMs, signal: ctx.signal }), {
          what: url,
        })
      ).value;
      out.push({ kind: docKind(file.name), title: `${pkg}@${resolved} ${file.name.replace(/^\//, '')}`, url, text: text.slice(0, 200_000) });
    } catch (err) {
      if (err instanceof OfflineCacheMiss) throw err;
      // one bad file doesn't sink the rest
    }
  }
  return out;
}

async function releaseByTag(owner: string, repo: string, pkg: string, version: string, ctx: ToolContext): Promise<GithubRelease | null> {
  for (const tag of [`v${version}`, version, `${pkg}@${version}`]) {
    const key = `release-tag:${owner}/${repo}:${tag}`.toLowerCase();
    try {
      const { value } = await cachedFetch<GithubRelease | null>(
        ctx,
        'github',
        key,
        async () => {
          try {
            return trimRelease(
              await getJson(`${GITHUB_API}/repos/${owner}/${repo}/releases/tags/${encodeURIComponent(tag)}`, {
                headers: githubHeaders(ctx.config),
                timeoutMs: ctx.config.timeouts.webMs,
                signal: ctx.signal,
                retries: 0,
              }),
            );
          } catch (err) {
            if (err instanceof HttpError && err.status === 404) return null;
            throw err;
          }
        },
        { what: `the release ${tag}` },
      );
      if (value) return value;
    } catch (err) {
      if (isRateLimited(err) || err instanceof OfflineCacheMiss) throw err;
    }
  }
  return null;
}

async function releaseCandidates(pkg: string, repo: RepositoryInfo, target: SearchTarget, query: string, ctx: ToolContext, notes: string[]): Promise<Candidate[]> {
  const owner = repo.owner ?? '';
  const name = repo.repo ?? '';
  let releases: GithubRelease[] = [];
  let complete = false;
  try {
    const listing = await listGithubReleases(owner, name, ctx, { stopBelow: target.from, pkg });
    releases = listing.releases;
    complete = listing.complete;
    if (listing.error !== undefined) notes.push(`release list incomplete (${describeWebError(listing.error)})`);
  } catch (err) {
    if (err instanceof OfflineCacheMiss) throw err;
    notes.push(`GitHub releases: ${describeWebError(err)}`);
    if (isRateLimited(err)) return [];
  }
  const byVersion = new Map<string, GithubRelease>();
  for (const r of releases) {
    const v = versionFromTag(r.tag, pkg);
    if (v && !byVersion.has(v)) byVersion.set(v, r);
  }
  const named = versionsInQuery(query, pkg);
  const listed = [...byVersion.keys()].sort(compareVersions);
  const oldestListed = listed[0];
  // partial list may stop above from
  const unlisted = complete || oldestListed === undefined ? [] : majorBoundaries(target.from, target.to).filter((v) => compareVersions(v, oldestListed) < 0);
  let wanted = [...new Set([...majorBoundaries(target.from, target.to, listed.length > 0 ? listed : undefined), ...unlisted, ...named])];
  if (wanted.length === 0) {
    // no range: newest majors
    wanted = [...byVersion.keys()].filter((v) => /^\d+\.0\.0$/.test(v)).sort((a, b) => compareVersions(b, a)).slice(0, 3);
  }
  wanted.sort((a, b) => compareVersions(b, a));
  const out: Candidate[] = [];
  let lookups = 0;
  let boundaryRank = 0;
  for (const version of wanted) {
    let release = byVersion.get(version) ?? null;
    if (!release && !complete && lookups < 2) {
      lookups += 1;
      try {
        release = await releaseByTag(owner, name, pkg, version, ctx);
      } catch (err) {
        if (err instanceof OfflineCacheMiss) continue;
        notes.push(`GitHub release ${version}: ${describeWebError(err)}`);
        break;
      }
    }
    if (!release) continue;
    const label = release.name && release.name !== release.tag ? `${release.tag}: ${release.name}` : release.tag;
    const boost = (BOUNDARY_BOOST[boundaryRank] ?? 0) + (named.includes(version) ? 1 : 0);
    boundaryRank += 1;
    out.push({
      kind: 'release',
      title: `${pkg} ${label} release notes`,
      url: release.url ?? `https://github.com/${owner}/${name}/releases/tag/${encodeURIComponent(release.tag)}`,
      text: `${release.name ?? release.tag}\n${release.body}`,
      version,
      boost,
    });
  }
  return out;
}

interface ApiSearchIssues {
  items?: { number?: number; title?: string; body?: string | null; state?: string; html_url?: string; pull_request?: unknown }[];
}

// gh issue search ANDs every term
const ISSUE_NOISE = new Set([
  'breaking',
  'break',
  'breaks',
  'change',
  'changes',
  'changed',
  'changelog',
  'migrate',
  'migrating',
  'migration',
  'guide',
  'upgrade',
  'upgrading',
  'update',
  'version',
  'versions',
  'release',
  'releases',
  'notes',
  'new',
  'old',
  'npm',
  'javascript',
  'node',
  'nodejs',
]);

// max 4 terms, no name or versions
export function issueSearchTerms(query: string, pkg: string | null): string[] {
  const pkgWords = new Set((pkg ?? '').toLowerCase().split(/[@/._-]+/).filter(Boolean));
  if (pkg) pkgWords.add(pkg.toLowerCase());
  return queryKeywords(query)
    .filter((k) => !k.includes(' '))
    .filter((k) => !pkgWords.has(k) && !ISSUE_NOISE.has(k) && !/^v?\d+(?:\.\d+|\.x)*$/.test(k))
    .slice(0, 4);
}

async function issueCandidates(repo: RepositoryInfo, query: string, pkg: string, ctx: ToolContext): Promise<Candidate[]> {
  const terms = issueSearchTerms(query, pkg);
  if (terms.length === 0 || !repo.owner || !repo.repo) return [];
  const q = `repo:${repo.owner}/${repo.repo} ${terms.join(' ')} -author:app/dependabot`;
  const { value } = await cachedFetch(
    ctx,
    'github-search',
    q.toLowerCase(),
    () =>
      getJson<ApiSearchIssues>(`${GITHUB_API}/search/issues?q=${encodeURIComponent(q)}&per_page=10`, {
        headers: githubHeaders(ctx.config),
        timeoutMs: ctx.config.timeouts.webMs,
        signal: ctx.signal,
        retries: 0,
      }),
    { what: 'the GitHub issue search' },
  );
  return (value.items ?? [])
    .filter((i) => i.html_url && i.title)
    .map((i) => ({
      kind: 'issue' as const,
      title: `#${i.number ?? '?'} ${oneLineText(i.title ?? '')} (${i.state ?? 'open'} ${i.pull_request ? 'pull request' : 'issue'})`,
      url: i.html_url ?? '',
      text: `${i.title ?? ''}\n${String(i.body ?? '').slice(0, 20_000)}`,
    }));
}

async function docsSearch(query: string, ctx: ToolContext, target: SearchTarget, maxResults: number): Promise<{ hits: WebSearchHit[]; notes: string[] }> {
  const notes: string[] = [];
  if (!target.package) return { hits: [], notes: ['the package docs search needs a package (none is in focus)'] };
  const pkg = target.package;
  let meta: PackageMeta = { repository: target.repository ?? null, homepage: null };
  if (target.repository === undefined) {
    try {
      meta = await resolvePackageMeta(pkg, [target.to, target.from], ctx);
    } catch (err) {
      if (err instanceof OfflineCacheMiss) throw err;
      notes.push(`registry: ${describeWebError(err)}`);
    }
  }
  const candidates: Candidate[] = [];
  const repo = meta.repository;
  if (repo?.host === 'github' && repo.owner && repo.repo) candidates.push(...(await releaseCandidates(pkg, repo, target, query, ctx, notes)));

  let version = target.to;
  if (!version) {
    try {
      version = (await loadPackument(pkg, ctx))?.['dist-tags']?.latest ?? null;
    } catch (err) {
      if (err instanceof OfflineCacheMiss) throw err;
    }
  }
  if (version) {
    try {
      candidates.push(...(await jsdelivrCandidates(pkg, version, ctx)));
    } catch (err) {
      if (err instanceof OfflineCacheMiss) throw err;
      notes.push(`jsDelivr: ${describeWebError(err)}`);
    }
  }
  if (repo?.host === 'github') {
    try {
      candidates.push(...(await issueCandidates(repo, query, pkg, ctx)));
    } catch (err) {
      if (err instanceof OfflineCacheMiss) throw err;
      notes.push(`GitHub issue search: ${describeWebError(err)}`);
    }
  }
  const keywords = queryKeywords(query);
  const weights = queryWeights(keywords);
  const seen = new Set<string>();
  const unique = rankOwnDomainsFirst(rankCandidates(candidates, query), pkg, meta).filter((c) => (seen.has(c.url) ? false : (seen.add(c.url), true)));
  const hits = diversify(unique, maxResults)
    .map((c) => ({ title: c.title, url: c.url, snippet: snippetAround(c.text, keywords, SNIPPET_CHARS, weights), backend: 'docs' as const }));
  return { hits, notes };
}

function cacheKey(backend: SearchBackendName, target: SearchTarget, maxResults: number, query: string): string {
  return [backend, target.package ?? '', target.from ?? '', target.to ?? '', String(maxResults), query.toLowerCase()].join('|');
}

function logSearch(ctx: ToolContext, pkg: string | null, response: WebSearchResponse): void {
  try {
    ctx.audit?.log({
      event: 'migration.search',
      package: pkg ?? '',
      backend: response.backend,
      query: response.query,
      urls: response.hits.map((h) => h.url),
      cached: response.cached,
    });
  } catch {
    // audit must not break search
  }
}

function withNotes(response: WebSearchResponse, notes: readonly string[]): WebSearchResponse {
  const all = [...(response.note ? [response.note] : []), ...notes].filter(Boolean);
  if (all.length === 0) return response;
  return { ...response, note: [...new Set(all)].join('; ') };
}

async function runDocs(query: string, ctx: ToolContext, target: SearchTarget, maxResults: number, notes: string[]): Promise<WebSearchResponse> {
  const key = cacheKey('docs', target, maxResults, query);
  const hit = readCache<WebSearchResponse>(ctx, 'search', key);
  if (hit) return withNotes({ ...hit.value, cached: true }, notes);
  const docs = await docsSearch(query, ctx, target, maxResults);
  const response: WebSearchResponse = { query, backend: 'docs', hits: docs.hits, cached: false };
  // only complete answers, failures retry
  if (docs.notes.length === 0 || docs.hits.length > 0) writeCache(ctx, 'search', key, docs.notes.length > 0 ? withNotes(response, docs.notes) : response);
  return withNotes(response, [...notes, ...docs.notes]);
}

async function runSearch(query: string, ctx: ToolContext, target: SearchTarget, maxResults: number): Promise<WebSearchResponse> {
  const backend = resolveSearchBackend(ctx) ?? 'docs';
  const notes: string[] = [];
  if (backend === 'ollama' || backend === 'brave') {
    const key = cacheKey(backend, target, maxResults, query);
    const hit = readCache<WebSearchResponse>(ctx, 'search', key);
    if (hit) return { ...hit.value, cached: true };
    const apiKey = backend === 'ollama' ? ctx.config.ollamaApiKey : ctx.config.braveApiKey;
    if (!apiKey) {
      notes.push(
        backend === 'ollama'
          ? 'Ollama web search needs OLLAMA_API_KEY (https://ollama.com/settings/keys); used the package docs instead'
          : 'Brave search is not configured (set BRAVE_SEARCH_API_KEY); used the package docs instead',
      );
    } else {
      try {
        let hits = backend === 'ollama' ? await ollamaSearch(query, maxResults, ctx) : await braveSearch(query, maxResults, ctx);
        if (target.package) {
          try {
            const meta = await resolvePackageMeta(target.package, [target.to, target.from], ctx);
            hits = rankOwnDomainsFirst(hits, target.package, meta);
          } catch {
            // no package domains
          }
        }
        const response: WebSearchResponse = { query, backend, hits, cached: false };
        writeCache(ctx, 'search', key, response);
        return response;
      } catch (err) {
        const reason = err instanceof Error && err.message.startsWith('NotImplemented') ? 'not available in this version' : `failed: ${describeWebError(err)}`;
        notes.push(`${backend === 'ollama' ? 'Ollama web search' : 'Brave search'} ${reason}; used the package docs instead`);
      }
    }
  }
  return runDocs(query, ctx, target, maxResults, notes);
}

function offlineResponse(query: string, ctx: ToolContext, target: SearchTarget, maxResults: number): WebSearchResponse {
  const online = backendFor({ ...ctx.config, offline: false });
  const backends: SearchBackendName[] = online === null ? [] : [...new Set<SearchBackendName>([online, 'docs'])];
  for (const backend of backends) {
    const hit = readCache<WebSearchResponse>(ctx, 'search', cacheKey(backend, target, maxResults, query));
    if (hit) return withNotes({ ...hit.value, cached: true }, ['offline: cached results']);
  }
  return { query, backend: 'none', hits: [], cached: false, note: 'search disabled (offline)' };
}

// docs fallback when hosted api fails
export async function searchWeb(query: string, ctx: ToolContext, search: WebSearchContext = {}): Promise<WebSearchResponse> {
  const q = oneLineText(query).slice(0, 400);
  const maxResults = Math.max(1, Math.min(MAX_SEARCH_RESULTS, Math.trunc(search.maxResults ?? DEFAULT_SEARCH_RESULTS) || DEFAULT_SEARCH_RESULTS));
  const target = resolveTarget(ctx, search, q);
  let response: WebSearchResponse;
  if (ctx.config.search === 'off') {
    response = { query: q, backend: 'none', hits: [], cached: false, note: 'web search is off (--search off)' };
  } else if (ctx.config.offline) {
    response = offlineResponse(q, ctx, target, maxResults);
  } else {
    try {
      response = await runSearch(q, ctx, target, maxResults);
    } catch (err) {
      response = { query: q, backend: 'none', hits: [], cached: false, note: `search failed: ${describeWebError(err)}` };
    }
  }
  logSearch(ctx, target.package, response);
  return response;
}

const BACKEND_LABEL: Record<WebSearchResponse['backend'], string> = {
  ollama: 'Ollama web search',
  docs: 'package docs (GitHub releases, jsDelivr, issues)',
  brave: 'Brave search',
  none: 'no backend',
};

export async function handleWebSearch(args: WebSearchArgs, ctx: ToolContext): Promise<ToolResult> {
  const query = String(args.query ?? '').trim();
  if (!query) {
    return { ok: false, hint: 'query is required', error: 'query is required, for example {"query":"marked 4.0.0 breaking changes default export"}' };
  }
  const response = await searchWeb(query, ctx, typeof args.maxResults === 'number' ? { maxResults: args.maxResults } : {});
  if (response.backend === 'none') {
    const note = response.note ?? 'search unavailable';
    return { ok: false, hint: note, error: `${note}. Use get_changelog and the sources already gathered.` };
  }
  const lines: string[] = [];
  // snippets share what's left of 2000 chars
  const fixed = response.hits.reduce((n, hit, i) => n + `${i + 1}. ${hit.title}`.length + hit.url.length + 12, 0);
  const noteChars = response.note ? response.note.length + 8 : 0;
  const perSnippet = Math.max(80, Math.min(SNIPPET_CHARS, Math.floor((TOOL_TEXT_BUDGET - fixed - noteChars) / Math.max(1, response.hits.length))));
  response.hits.forEach((hit, i) => {
    lines.push(`${i + 1}. ${hit.title}`, `   ${hit.url}`);
    if (hit.snippet) lines.push(`   ${hit.snippet.length > perSnippet ? `${hit.snippet.slice(0, perSnippet - 3).trimEnd()}...` : hit.snippet}`);
  });
  if (response.hits.length === 0) lines.push(`No results for "${response.query}". Try fewer or different keywords, or get_changelog for the release notes.`);
  if (response.note) lines.push(`Note: ${response.note}`);
  const count = response.hits.length;
  const hint = `${count} result${count === 1 ? '' : 's'} via ${BACKEND_LABEL[response.backend]}${response.cached ? ' (cached)' : ''}${response.note ? ` \u00b7 ${response.note.slice(0, 80)}` : ''}`;
  return { ok: true, hint, text: lines.join('\n'), cached: response.cached, data: response };
}
