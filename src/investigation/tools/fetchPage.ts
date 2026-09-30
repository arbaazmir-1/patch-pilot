// fetch_page
import dns from 'node:dns';
import net from 'node:net';
import type { PageText, ToolContext, ToolResult } from '../../types.ts';
import {
  BREAKING_KEYWORDS,
  extractTitle,
  htmlToText,
  isLikelyJsRendered,
  keywordWindow,
  looksLikeHtml,
  normalizeText,
  queryKeywords,
  queryWeights,
} from '../../util/html.ts';
import { describeHttpError, getJson, HttpError, NetworkError, postJson, readBodyCapped } from '../../util/http.ts';
import { USER_AGENT } from '../../version.ts';
import { GITHUB_API, GITHUB_RAW, githubHeaders, readCache, writeCache, describeWebError } from './getChangelog.ts';

export interface FetchPageArgs {
  url: string;
  query?: string;
}

export const PAGE_WINDOW_CHARS = 3000;
export const PAGE_MAX_BYTES = 2 * 1024 * 1024;
export const MAX_REDIRECTS = 5;
export const OLLAMA_WEB_FETCH_URL = 'https://ollama.com/api/web_fetch';
const STORED_TEXT_MAX = 400_000;

export type FetchPageErrorCode = 'invalid-url' | 'blocked' | 'offline' | 'http' | 'network' | 'not-text' | 'redirects';

export class FetchPageError extends Error {
  readonly code: FetchPageErrorCode;
  readonly url: string;
  readonly status: number | null;
  constructor(code: FetchPageErrorCode, message: string, url: string, status: number | null = null) {
    super(message);
    this.name = 'FetchPageError';
    this.code = code;
    this.url = url;
    this.status = status;
  }
}

const BLOCKED_RANGES: readonly [string, number, 'ipv4' | 'ipv6'][] = [
  ['0.0.0.0', 8, 'ipv4'],
  ['10.0.0.0', 8, 'ipv4'],
  ['100.64.0.0', 10, 'ipv4'],
  ['127.0.0.0', 8, 'ipv4'],
  ['169.254.0.0', 16, 'ipv4'],
  ['172.16.0.0', 12, 'ipv4'],
  ['192.0.0.0', 24, 'ipv4'],
  ['192.0.2.0', 24, 'ipv4'],
  ['192.88.99.0', 24, 'ipv4'],
  ['192.168.0.0', 16, 'ipv4'],
  ['198.18.0.0', 15, 'ipv4'],
  ['198.51.100.0', 24, 'ipv4'],
  ['203.0.113.0', 24, 'ipv4'],
  ['224.0.0.0', 4, 'ipv4'],
  ['240.0.0.0', 4, 'ipv4'],
  ['::', 96, 'ipv6'],
  ['64:ff9b::', 96, 'ipv6'],
  ['64:ff9b:1::', 48, 'ipv6'],
  ['100::', 64, 'ipv6'],
  ['2001::', 32, 'ipv6'],
  ['2001:db8::', 32, 'ipv6'],
  ['2002::', 16, 'ipv6'],
  ['fc00::', 7, 'ipv6'],
  ['fe80::', 10, 'ipv6'],
  ['fec0::', 10, 'ipv6'],
  ['ff00::', 8, 'ipv6'],
];

const BLOCKLIST = (() => {
  const list = new net.BlockList();
  for (const [address, prefix, type] of BLOCKED_RANGES) list.addSubnet(address, prefix, type);
  return list;
})();

// ipv4-mapped ipv6 included
export function isPrivateAddress(ip: string): boolean {
  const address = ip.replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  const family = net.isIP(address);
  if (family === 0) return false;
  return BLOCKLIST.check(address, family === 6 ? 'ipv6' : 'ipv4');
}

function blockedHostname(hostname: string): string | null {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return 'the local machine';
  if (/\.(?:local|internal|intranet|lan|home|corp|home\.arpa)$/.test(h)) return 'a local network name';
  if (!h.includes('.')) return 'not a public host name';
  return null;
}

// http(s) with a public host only
export function checkFetchUrl(url: string): { ok: true; url: URL } | { ok: false; reason: string } {
  let raw = String(url ?? '').trim();
  if (!raw) return { ok: false, reason: 'the URL is empty' };
  if (!/^[a-z][a-z0-9+.-]*:/i.test(raw) && /^[\w-]+(?:\.[\w-]+)+(?:[/:?#]|$)/.test(raw)) raw = `https://${raw}`;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: `not a valid URL: ${raw.slice(0, 200)}` };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: `only http and https URLs can be fetched (got ${parsed.protocol.replace(/:$/, '')})` };
  }
  if (parsed.username || parsed.password) return { ok: false, reason: 'URLs with credentials are not fetched' };
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateAddress(host)) return { ok: false, reason: `${host} is a private, loopback or link-local address` };
  } else {
    const why = blockedHostname(host);
    if (why) return { ok: false, reason: `${parsed.hostname} is ${why}` };
  }
  return { ok: true, url: parsed };
}

export type HostLookup = (hostname: string) => Promise<string[]>;

const systemLookup: HostLookup = async (hostname) => (await dns.promises.lookup(hostname, { all: true, verbatim: true })).map((r) => r.address);
let hostLookup: HostLookup = systemLookup;

// null restores the system lookup
export function setHostLookup(lookup: HostLookup | null): void {
  hostLookup = lookup ?? systemLookup;
}

// any private address refuses the host
export async function assertPublicHost(url: URL): Promise<void> {
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateAddress(host)) throw new FetchPageError('blocked', `${host} is a private, loopback or link-local address`, url.href);
    return;
  }
  let addresses: string[];
  try {
    addresses = await hostLookup(host);
  } catch (err) {
    const code = (err as { code?: string }).code;
    throw new FetchPageError('network', `cannot resolve ${host}${code ? ` (${code})` : ''}`, url.href);
  }
  if (addresses.length === 0) throw new FetchPageError('network', `cannot resolve ${host}`, url.href);
  const bad = addresses.find((a) => isPrivateAddress(a));
  if (bad) throw new FetchPageError('blocked', `${host} resolves to ${bad}, a private or local address`, url.href);
}

export type GithubRewrite =
  | { kind: 'release'; owner: string; repo: string; tag: string; apiUrl: string }
  | { kind: 'issue'; owner: string; repo: string; number: number; apiUrl: string }
  | { kind: 'blob'; owner: string; repo: string; path: string; rawUrl: string };

// releases, issues, blobs -> api or raw
export function rewriteGithubUrl(input: URL | string): GithubRewrite | null {
  let u: URL;
  try {
    u = typeof input === 'string' ? new URL(input) : input;
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  if (host !== 'github.com') return null;
  const segs = u.pathname.split('/').filter(Boolean);
  const [owner, repo, kind, ...rest] = segs;
  if (!owner || !repo || !kind) return null;
  const base = `${GITHUB_API}/repos/${owner}/${repo}`;
  if (kind === 'releases' && rest[0] === 'tag' && rest.length >= 2) {
    const tag = rest.slice(1).join('/');
    return { kind: 'release', owner, repo, tag: decodeURIComponent(tag), apiUrl: `${base}/releases/tags/${tag}` };
  }
  if (kind === 'releases' && rest[0] === 'latest' && rest.length === 1) {
    return { kind: 'release', owner, repo, tag: 'latest', apiUrl: `${base}/releases/latest` };
  }
  if ((kind === 'issues' || kind === 'pull') && rest[0] !== undefined && /^\d+$/.test(rest[0])) {
    return { kind: 'issue', owner, repo, number: Number(rest[0]), apiUrl: `${base}/issues/${rest[0]}` };
  }
  if ((kind === 'blob' || kind === 'raw') && rest.length >= 2) {
    const path = rest.join('/');
    return { kind: 'blob', owner, repo, path: decodeURIComponent(rest.slice(1).join('/')), rawUrl: `${GITHUB_RAW}/${owner}/${repo}/${path}` };
  }
  return null;
}

// windowed per query on read
interface StoredPage {
  url: string;
  finalUrl: string;
  title: string | null;
  text: string;
  jsRendered: boolean;
  bodyTruncated: boolean;
  via: 'ollama' | 'github-api' | 'raw' | 'http';
  fetchedAt: string;
}

function capText(text: string): string {
  return text.length > STORED_TEXT_MAX ? text.slice(0, STORED_TEXT_MAX) : text;
}

function signalFor(ctx: ToolContext): AbortSignal {
  const timeout = AbortSignal.timeout(ctx.config.timeouts.webMs);
  return ctx.signal ? AbortSignal.any([timeout, ctx.signal]) : timeout;
}

function isTextType(contentType: string): boolean {
  const type = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
  if (!type) return true;
  return type.startsWith('text/') || /^application\/(?:xhtml\+xml|xml|json|ld\+json|javascript|x-javascript|markdown|rss\+xml|atom\+xml)$/.test(type);
}

function firstMarkdownHeading(text: string): string | null {
  const m = /^#{1,3}\s+(.+)$/m.exec(text);
  return m?.[1]?.trim() || null;
}

interface RawBody {
  body: string;
  truncated: boolean;
  finalUrl: URL;
  contentType: string;
}

// each redirect hop checked, 2 mb cap
async function fetchPublic(start: URL, ctx: ToolContext, accept: string): Promise<RawBody> {
  const signal = signalFor(ctx);
  let current = start;
  for (let hop = 0; ; hop += 1) {
    await assertPublicHost(current);
    let res: Response;
    try {
      res = await fetch(current, {
        redirect: 'manual',
        headers: { accept, 'accept-language': 'en', 'user-agent': USER_AGENT },
        signal,
      });
    } catch (err) {
      const timedOut = (err as { name?: string }).name === 'TimeoutError';
      throw new FetchPageError(
        'network',
        timedOut ? `timed out after ${Math.round(ctx.config.timeouts.webMs / 1000)} s: ${current.href}` : `network error for ${current.href}: ${describeHttpError(err)}`,
        start.href,
      );
    }
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      await res.body?.cancel().catch(() => {});
      if (!location) throw new FetchPageError('http', `HTTP ${res.status} without a Location header from ${current.href}`, start.href, res.status);
      if (hop >= MAX_REDIRECTS) throw new FetchPageError('redirects', `more than ${MAX_REDIRECTS} redirects from ${start.href}`, start.href);
      const next = checkFetchUrl(new URL(location, current).href);
      if (!next.ok) throw new FetchPageError('blocked', `redirected to a refused URL: ${next.reason}`, start.href);
      current = next.url;
      continue;
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      throw new FetchPageError('http', `HTTP ${res.status} from ${current.href}`, start.href, res.status);
    }
    const contentType = res.headers.get('content-type') ?? '';
    if (!isTextType(contentType)) {
      await res.body?.cancel().catch(() => {});
      throw new FetchPageError('not-text', `not a text page (${contentType.split(';')[0]}): ${current.href}`, start.href);
    }
    let capped;
    try {
      capped = await readBodyCapped(res, PAGE_MAX_BYTES);
    } catch (err) {
      throw new FetchPageError('network', `reading ${current.href} failed: ${describeHttpError(err)}`, start.href);
    }
    if (!contentType && capped.text.slice(0, 1024).includes('\u0000')) {
      throw new FetchPageError('not-text', `not a text page (binary content): ${current.href}`, start.href);
    }
    return { body: capped.text, truncated: capped.truncated, finalUrl: current, contentType };
  }
}

async function fetchViaHttp(target: URL, original: URL, ctx: ToolContext, raw: boolean): Promise<StoredPage> {
  const accept = raw ? 'text/plain, text/markdown;q=0.9, */*;q=0.5' : 'text/html, application/xhtml+xml;q=0.9, text/plain;q=0.8, */*;q=0.5';
  const res = await fetchPublic(target, ctx, accept);
  const html = !raw && (/html/i.test(res.contentType) || looksLikeHtml(res.body));
  let text: string;
  let title: string | null;
  let jsRendered = false;
  if (html) {
    text = htmlToText(res.body);
    title = extractTitle(res.body);
    jsRendered = isLikelyJsRendered(res.body, text);
  } else {
    text = normalizeText(res.body);
    title = firstMarkdownHeading(text);
  }
  return {
    url: original.href,
    finalUrl: raw ? original.href : res.finalUrl.href,
    title,
    text: capText(text),
    jsRendered,
    bodyTruncated: res.truncated,
    via: raw ? 'raw' : 'http',
    fetchedAt: new Date().toISOString(),
  };
}

interface ApiRelease {
  tag_name?: string;
  name?: string | null;
  body?: string | null;
  published_at?: string | null;
  html_url?: string;
}

interface ApiIssue {
  number?: number;
  title?: string;
  body?: string | null;
  state?: string;
  html_url?: string;
  pull_request?: unknown;
}

async function fetchViaGithubApi(rewrite: Exclude<GithubRewrite, { kind: 'blob' }>, original: URL, ctx: ToolContext): Promise<StoredPage> {
  const options = { headers: githubHeaders(ctx.config), timeoutMs: ctx.config.timeouts.webMs, signal: ctx.signal, retries: 0 };
  const fetchedAt = new Date().toISOString();
  if (rewrite.kind === 'release') {
    const r = await getJson<ApiRelease>(rewrite.apiUrl, options);
    const label = r.name?.trim() || r.tag_name || rewrite.tag;
    const lines = [`# ${label}`, r.published_at ? `Published ${r.published_at.slice(0, 10)} (tag ${r.tag_name ?? rewrite.tag})` : `Tag ${r.tag_name ?? rewrite.tag}`, '', normalizeText(r.body ?? '')];
    return {
      url: original.href,
      finalUrl: r.html_url ?? original.href,
      title: `${rewrite.owner}/${rewrite.repo} ${label}`,
      text: capText(normalizeText(lines.join('\n'))),
      jsRendered: false,
      bodyTruncated: false,
      via: 'github-api',
      fetchedAt,
    };
  }
  const issue = await getJson<ApiIssue>(rewrite.apiUrl, options);
  const kind = issue.pull_request ? 'pull request' : 'issue';
  const lines = [`# ${issue.title ?? `${kind} #${rewrite.number}`}`, `${issue.state ?? 'unknown'} ${kind} #${issue.number ?? rewrite.number}`, '', normalizeText(issue.body ?? '')];
  return {
    url: original.href,
    finalUrl: issue.html_url ?? original.href,
    title: issue.title ?? null,
    text: capText(normalizeText(lines.join('\n'))),
    jsRendered: false,
    bodyTruncated: false,
    via: 'github-api',
    fetchedAt,
  };
}

interface OllamaFetchResponse {
  title?: string;
  content?: string;
  links?: string[];
}

async function fetchViaOllama(target: URL, ctx: ToolContext): Promise<StoredPage> {
  const res = await postJson<OllamaFetchResponse>(
    OLLAMA_WEB_FETCH_URL,
    { url: target.href },
    { headers: { authorization: `Bearer ${ctx.config.ollamaApiKey ?? ''}` }, timeoutMs: ctx.config.timeouts.webMs, signal: ctx.signal, retries: 1 },
  );
  const content = typeof res?.content === 'string' ? normalizeText(res.content) : '';
  if (!content) throw new Error('Ollama web_fetch returned no content');
  return {
    url: target.href,
    finalUrl: target.href,
    title: typeof res.title === 'string' && res.title.trim() ? res.title.trim() : firstMarkdownHeading(content),
    text: capText(content),
    jsRendered: content.replace(/\s+/g, '').length < 200,
    bodyTruncated: false,
    via: 'ollama',
    fetchedAt: new Date().toISOString(),
  };
}

async function loadPage(target: URL, ctx: ToolContext): Promise<StoredPage> {
  const earlier: string[] = [];
  if (ctx.config.ollamaApiKey) {
    try {
      return await fetchViaOllama(target, ctx);
    } catch (err) {
      earlier.push(`Ollama web_fetch failed (${describeHttpError(err)})`);
    }
  }
  const rewrite = rewriteGithubUrl(target);
  if (rewrite && rewrite.kind !== 'blob') {
    try {
      return await fetchViaGithubApi(rewrite, target, ctx);
    } catch (err) {
      earlier.push(`GitHub API: ${describeWebError(err)}`);
    }
  }
  try {
    return rewrite?.kind === 'blob' ? await fetchViaHttp(new URL(rewrite.rawUrl), target, ctx, true) : await fetchViaHttp(target, target, ctx, false);
  } catch (err) {
    if (err instanceof FetchPageError && earlier.length > 0) {
      throw new FetchPageError(err.code, `${err.message} (after: ${earlier.join('; ')})`, err.url, err.status);
    }
    throw err;
  }
}

function toPageText(stored: StoredPage, url: string, query: string | undefined, cached: boolean): PageText {
  const q = query?.trim();
  const keywords = q ? queryKeywords(q) : [...BREAKING_KEYWORDS];
  const window = keywordWindow(stored.text, keywords, PAGE_WINDOW_CHARS, q ? { weights: queryWeights(keywords) } : {});
  return {
    url,
    finalUrl: stored.finalUrl,
    title: stored.title,
    text: window,
    totalChars: stored.text.length,
    truncated: window !== stored.text || stored.bodyTruncated,
    jsRendered: stored.jsRendered,
    cached,
    fetchedAt: stored.fetchedAt,
  };
}

// url minus fragment
export function pageCacheKey(url: URL): string {
  const copy = new URL(url.href);
  copy.hash = '';
  return copy.href;
}

export async function fetchPageText(url: string, query: string | undefined, ctx: ToolContext): Promise<PageText> {
  const checked = checkFetchUrl(url);
  if (!checked.ok) throw new FetchPageError(/valid URL|empty/.test(checked.reason) ? 'invalid-url' : 'blocked', checked.reason, url);
  const key = pageCacheKey(checked.url);
  const hit = readCache<StoredPage>(ctx, 'page', key);
  if (hit) return toPageText(hit.value, url, query, true);
  if (ctx.config.offline) throw new FetchPageError('offline', `page unavailable offline (not cached): ${key}`, url);
  const stored = await loadPage(checked.url, ctx);
  writeCache(ctx, 'page', key, stored);
  return toPageText(stored, url, query, false);
}

export async function handleFetchPage(args: FetchPageArgs, ctx: ToolContext): Promise<ToolResult> {
  const url = String(args.url ?? '').trim();
  const check = checkFetchUrl(url);
  if (!check.ok) {
    return {
      ok: false,
      hint: `refused: ${check.reason}`,
      error: `${check.reason}. Give a public http(s) documentation URL, for example https://github.com/markedjs/marked/releases/tag/v4.0.0`,
    };
  }
  const query = typeof args.query === 'string' && args.query.trim() ? args.query.trim() : undefined;
  let page: PageText;
  try {
    page = await fetchPageText(check.url.href, query, ctx);
  } catch (err) {
    const message = err instanceof FetchPageError || err instanceof HttpError || err instanceof NetworkError ? err.message : describeHttpError(err);
    if (err instanceof FetchPageError && err.code === 'offline') {
      return { ok: false, hint: 'page unavailable offline', error: `${message}. Work with the release notes and files already gathered.` };
    }
    return { ok: false, hint: `could not fetch the page: ${message.slice(0, 120)}`, error: message };
  }
  const around = query ? `"${query}"` : 'breaking-change keywords';
  const header = [
    page.title ? `Title: ${page.title}` : null,
    `URL: ${page.finalUrl}`,
    page.truncated ? `Showing ${page.text.length} of ${page.totalChars} characters around ${around}.` : null,
    page.jsRendered ? 'Little text could be extracted: the page is probably rendered by JavaScript. Prefer the GitHub release notes or the README.' : null,
  ]
    .filter((line): line is string => line !== null)
    .join('\n');
  const size = page.totalChars.toLocaleString('en-US');
  const hint = [
    page.truncated ? `${page.text.length.toLocaleString('en-US')} of ${size} chars around ${around}` : `${size} chars`,
    page.cached ? 'cached' : null,
    page.jsRendered ? 'probably a JavaScript-rendered page' : null,
  ]
    .filter(Boolean)
    .join(' \u00b7 ');
  return { ok: true, hint, text: `${header}\n\n${page.text}`, truncated: page.truncated, cached: page.cached };
}
