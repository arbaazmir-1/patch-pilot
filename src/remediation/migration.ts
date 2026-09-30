// breaking-change research for major bumps
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { findImportsInSource, findUsage, searchProject } from '../evidence/codebase.ts';
import { schemaText } from '../investigation/prompts.ts';
import { FetchPageError, fetchPageText } from '../investigation/tools/fetchPage.ts';
import {
  cachedFetch,
  collectBreakingLines,
  describeWebError,
  getChangelogInfo,
  GITHUB_API,
  GITHUB_RAW,
  githubHeaders,
  isRateLimited,
  OfflineCacheMiss,
  parseRepoUrl,
  resolvePackageMeta,
  trimRelease,
  versionFromTag,
  type GithubRelease,
  type PackageMeta,
} from '../investigation/tools/getChangelog.ts';
import { toolCallKey, type ToolRegistry } from '../investigation/tools/index.ts';
import { JSDELIVR_CDN_URL, JSDELIVR_DATA_URL, majorBoundaries, rankOwnDomainsFirst, searchWeb } from '../investigation/tools/webSearch.ts';
import { LlmError } from '../llm/errors.ts';
import type { ChatProvider } from '../llm/provider.ts';
import { extractJsonObject, parseLenientJson, parseTextToolCalls, unwrapRawArguments } from '../llm/textToolCalls.ts';
import type {
  Action,
  AuditSink,
  ChangelogInfo,
  ChangelogRelease,
  ChatMessage,
  ChatResponse,
  Config,
  ImportSite,
  JsonSchema,
  MigrationBrief,
  MigrationBriefItem,
  MigrationQuery,
  MigrationSource,
  PageText,
  RepositoryInfo,
  ToolCall,
  ToolContext,
  ToolExecution,
  UsageEvidence,
  WebSearchResponse,
} from '../types.ts';
import { wrapText, type Ui } from '../ui.ts';
import { errorMessage } from '../util/errors.ts';
import { isPathInside, toPosix } from '../util/fs.ts';
import { normalizeText } from '../util/html.ts';
import { getJson, HttpError } from '../util/http.ts';
import { compareVersions, parseVersion } from '../util/semver.ts';

const str: JsonSchema = { type: 'string' };

// verified is computed, not asked
export const BRIEF_SCHEMA: JsonSchema = {
  type: 'object',
  properties: {
    items: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          change: str,
          appliesToProject: { type: 'string', enum: ['yes', 'no', 'unsure'] },
          evidenceQuote: str,
          evidenceUrl: str,
          oldApi: str,
          newApi: str,
          affectedFiles: { type: 'array', items: str },
        },
        required: ['change', 'appliesToProject', 'evidenceQuote', 'evidenceUrl', 'oldApi', 'newApi', 'affectedFiles'],
      },
    },
  },
  required: ['items'],
};

export interface MigrationContext {
  config: Config;
  ui: Ui;
  audit: AuditSink;
  provider: ChatProvider;
  registry: ToolRegistry;
  tools: ToolContext;
}

// about 2.5k tokens
export const DIGEST_MAX_CHARS = 10_000;
// per source, after keyword filter
export const SOURCE_TEXT_MAX = 3_000;
// all kinds
export const MAX_SOURCES = 12;
export const MAX_RELEASE_SOURCES = 6;
// tag lookups for missing majors
export const MAX_TAG_LOOKUPS = 4;
export const MAX_DOC_FILES = 4;
export const MAX_WEB_QUERIES = 2;
// attempts, not successes
export const MAX_WEB_FETCHES = 2;
// tool calls before the brief turn
export const BRIEF_BUDGET = 4;
export const MAX_BRIEF_ITEMS = 10;
const MAX_COVERAGE_ITEMS = 6;
const AGGREGATE_LINES_MAX = 20;
// one tool call or a few lines
const LOOP_MAX_TOKENS = 256;
// extras get "not run"
const CALLS_PER_TURN = 2;
const BRIEF_MAX_TOKENS = 2048;
const MODEL_PAGE_TEXT_MAX = 3_500;

type DraftItem = Omit<MigrationBriefItem, 'verified'>;
type SourceKind = MigrationSource['kind'];

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

function oneLine(text: string, max: number): string {
  const t = String(text ?? '').replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, Math.max(0, max - 3)).trimEnd()}...` : t;
}

// cut at a nearby line break
function capLines(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.lastIndexOf('\n', max);
  return (cut > max * 0.5 ? text.slice(0, cut) : text.slice(0, max)).trimEnd();
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    const text = `${u.host.replace(/^www\./, '')}${u.pathname === '/' ? '' : u.pathname}`;
    return text.length > 70 ? `${text.slice(0, 67)}...` : text;
  } catch {
    return oneLine(url, 70);
  }
}

function tagLabel(tag: string): string {
  return /^\d/.test(tag) ? `v${tag}` : tag;
}

function isoFrom(value: number | string | null | undefined): string {
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value).toISOString();
  if (typeof value === 'string' && value) return value;
  return new Date().toISOString();
}

// dedupe key: case, www, slash, raw vs blob
export function canonicalUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(String(url).trim());
  } catch {
    return String(url).trim().toLowerCase();
  }
  let host = u.hostname.toLowerCase().replace(/^www\./, '');
  let pathname = u.pathname.replace(/\/+$/, '');
  if (host === 'raw.githubusercontent.com') {
    const [owner, repo, ...rest] = pathname.split('/').filter(Boolean);
    if (owner && repo && rest.length >= 2) {
      host = 'github.com';
      pathname = `/${owner}/${repo}/blob/${rest.join('/')}`;
    }
  }
  return `${host}${pathname.toLowerCase()}${u.search}`;
}

function sameUrl(a: string, b: string): boolean {
  return Boolean(a) && Boolean(b) && canonicalUrl(a) === canonicalUrl(b);
}

function agent(ctx: MigrationContext, text: string, tag?: string): void {
  ctx.ui.agentLine(text, tag ? { tag } : {});
}

function result(ctx: MigrationContext, text: string): void {
  ctx.ui.resultLine(text);
}

export interface EvidenceKeywords {
  prose: RegExp[];
  // code-block lines
  code: RegExp[];
}

const BREAKING_PROSE: readonly RegExp[] = [
  /\bBREAKING\b/i,
  /\bremov(?:e|ed|es|ing|al)\b/i,
  /\brenam(?:e|ed|es|ing)\b/i,
  /\bdeprecat(?:e|ed|es|ing|ion)\b/i,
  /\bnow requires?\b/i,
  /\bno longer\b/i,
  /\bdrop(?:s|ped|ping)?\b.{0,40}\bsupport/i,
  /\bdefault export\b/i,
  /\bexport default\b/i,
  /\bnamed exports?\b/i,
  /\bESM\b/,
  /\bES ?modules?\b/i,
  /\bCommonJS\b/i,
  /\bNode(?:\.js)?\s*(?:v?\d{1,2}\b|>=|versions?\b)/i,
  /\bengines?\b.{0,20}\bnode\b/i,
  /\binstead of\b/i,
  /\breplaced (?:by|with)\b/i,
  /\bmigrat(?:e|es|ed|ing|ion)\b/i,
];

// whole section counts as evidence
const BREAKING_HEADING = /\b(?:breaking|migrat|upgrad|deprecat|remov|incompatib)/i;

function isIdentifier(name: string): boolean {
  return /^[A-Za-z_$][\w$]*$/.test(name);
}

// membersUsed plus named imports
function usedMembers(usage: UsageEvidence | null | undefined): string[] {
  const counts = new Map<string, number>();
  for (const [name, n] of Object.entries(usage?.membersUsed ?? {})) counts.set(name, (counts.get(name) ?? 0) + (Number(n) || 0));
  for (const site of usage?.files ?? []) {
    for (const imported of Object.keys(site.named ?? {})) counts.set(imported, (counts.get(imported) ?? 0) + 1);
  }
  return [...counts.entries()]
    .filter(([name]) => name !== 'default' && isIdentifier(name) && name.length >= 2)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([name]) => name);
}

export function evidenceKeywords(pkg: string, usage: UsageEvidence | null | undefined): EvidenceKeywords {
  const name = escapeRegExp(pkg);
  const imports = [
    new RegExp(`require\\(\\s*['"\`]${name}(?:/[^'"\`]*)?['"\`]\\s*\\)`),
    new RegExp(`\\bfrom\\s+['"]${name}(?:/[^'"]*)?['"]`),
    new RegExp(`\\bimport\\s*\\(?\\s*['"]${name}(?:/[^'"]*)?['"]`),
  ];
  const members = usedMembers(usage)
    .slice(0, 12)
    .map((m) => new RegExp(`(?<![\\w$])${escapeRegExp(m)}(?![\\w$])`));
  return { prose: [...BREAKING_PROSE, ...imports, ...members], code: [...imports, ...members] };
}

// drops refs, images, badges, links
export function tidyLine(line: string): string {
  const raw = line.replace(/\t/g, '  ').trimEnd();
  const indent = Math.min(6, raw.length - raw.trimStart().length);
  let s = raw.trim();
  for (let i = 0; i < 6; i += 1) {
    const before = s;
    s = s
      .replace(/\s*\(\s*\[[^\]]*\]\([^)]*\)(?:\s*,\s*\[[^\]]*\]\([^)]*\))*\s*\)\s*$/, '')
      .replace(/\s*\[[#@]?[\w.-]+\]\(https?:\/\/github\.com\/[^)]*\/(?:issues|pull|commit|compare)\/[^)]*\)\s*$/, '')
      .replace(/\s*\(#\d+(?:,\s*#\d+)*\)\s*$/, '')
      .replace(/(?:\s+#\d+)+\s*$/, '');
    if (s === before) break;
  }
  s = s
    .replace(/\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)/g, '')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]*)\]\((https?:\/\/[^)\s]+)\)/g, (_m, text: string, url: string) =>
      /github\.com\/[^/]+\/[^/]+\/(?:issues|pull|commit|compare)\//.test(url) || text.trim() === '' || text.trim() === url ? text : `${text} (${url})`,
    )
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
  return s ? `${' '.repeat(indent)}${s}` : '';
}

function codeLine(line: string): string {
  return line.replace(/\t/g, '  ').trimEnd();
}

function matchesAny(line: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((re) => re.test(line));
}

// migration guides kept whole
export function filterEvidenceText(text: string, keywords: EvidenceKeywords, kind: SourceKind, maxChars: number = SOURCE_TEXT_MAX): string {
  const keepAll = kind === 'migration-guide';
  const out: string[] = [];
  let fence = false;
  let breaking = false;
  let heading: string | null = null;
  let headingUsed = true;
  const push = (line: string): void => {
    if (out[out.length - 1] !== line) out.push(line);
  };
  for (const raw of String(text ?? '').replace(/\r\n?/g, '\n').split('\n')) {
    if (/^\s*(```|~~~)/.test(raw)) {
      fence = !fence;
      if (keepAll) push(raw.trim());
      continue;
    }
    if (!fence) {
      const h = /^\s{0,3}#{1,6}\s+(.+)$/.exec(raw) ?? /^\s*\*\*([^*]{2,80})\*\*:?\s*$/.exec(raw);
      if (h) {
        breaking = BREAKING_HEADING.test(h[1] ?? '');
        heading = tidyLine(raw);
        headingUsed = false;
        if ((breaking || keepAll) && heading) {
          push(heading);
          headingUsed = true;
        }
        continue;
      }
      if (/^\s*(?:-{3,}|\*{3,}|_{3,}|={3,})\s*$/.test(raw)) continue;
    }
    const line = fence ? codeLine(raw) : tidyLine(raw);
    if (!/[A-Za-z]{2,}/.test(line)) continue;
    const keep = keepAll || (!fence && breaking) || matchesAny(line, fence ? keywords.code : keywords.prose);
    if (!keep) continue;
    if (heading && !headingUsed) {
      push(heading);
      headingUsed = true;
    }
    push(line);
  }
  return capLines(out.join('\n').trim(), maxChars);
}

class SourceCollector {
  readonly sources: MigrationSource[] = [];
  private readonly seen = new Set<string>();
  private readonly max: number;

  constructor(max: number) {
    this.max = max;
  }

  has(url: string): boolean {
    return this.seen.has(canonicalUrl(url));
  }

  // so the web step skips it
  mark(url: string): void {
    this.seen.add(canonicalUrl(url));
  }

  get full(): boolean {
    return this.sources.length >= this.max;
  }

  add(source: MigrationSource): boolean {
    if (!source.text.trim() || this.full) return false;
    const key = canonicalUrl(source.url);
    if (this.sources.some((s) => canonicalUrl(s.url) === key)) return false;
    this.seen.add(key);
    this.sources.push(source);
    return true;
  }
}

// focus fills a missing package arg
function researchContext(ctx: MigrationContext, pkg: string, from: string): ToolContext {
  return { ...ctx.tools, config: ctx.tools?.config ?? ctx.config, focus: { package: pkg, version: from } };
}

function releaseVersion(release: ChangelogRelease, pkg: string): string | null {
  return versionFromTag(release.tag, pkg) ?? (release.name ? versionFromTag(release.name, pkg) : null);
}

function lineKey(version: string): string {
  const p = parseVersion(version);
  if (!p) return version;
  return p.major > 0 ? `${p.major}` : `0.${p.minor}`;
}

// newest major first, then 0.x
export function boundaryOrder(from: string, to: string, listed: readonly string[]): string[] {
  const actual = listed.length > 0 ? majorBoundaries(from, to, listed) : [];
  const covered = new Set(actual.map(lineKey));
  const theoretical = majorBoundaries(from, to).filter((v) => !covered.has(lineKey(v)));
  const all = unique([...actual, ...theoretical]);
  const majors = all.filter((v) => (parseVersion(v)?.major ?? 0) >= 1).sort((a, b) => compareVersions(b, a));
  const minors = all.filter((v) => (parseVersion(v)?.major ?? 0) === 0).sort((a, b) => compareVersions(b, a));
  return [...majors, ...minors];
}

interface PickedRelease {
  version: string;
  release: ChangelogRelease;
  kind: 'release-notes' | 'changelog';
  cached: boolean;
  fetchedAt: string;
  viaTag: boolean;
}

function githubRepo(meta: PackageMeta): (RepositoryInfo & { owner: string; repo: string }) | null {
  const repo = meta.repository;
  if (!repo || repo.host !== 'github' || !repo.owner || !repo.repo) return null;
  return repo as RepositoryInfo & { owner: string; repo: string };
}

function toChangelogRelease(r: GithubRelease): ChangelogRelease {
  return { tag: r.tag, name: r.name, publishedAt: r.publishedAt, url: r.url, body: normalizeText(r.body) };
}

// v4.0.0, 4.0.0, pkg@4.0.0
async function releaseByTag(
  owner: string,
  repo: string,
  pkg: string,
  version: string,
  t: ToolContext,
): Promise<{ release: ChangelogRelease; cached: boolean; fetchedAt: string } | null> {
  for (const tag of unique([`v${version}`, version, `${pkg}@${version}`])) {
    const key = `release-tag:${owner}/${repo}:${tag}`.toLowerCase();
    try {
      const hit = await cachedFetch<GithubRelease | null>(
        t,
        'github',
        key,
        async () => {
          try {
            return trimRelease(
              await getJson(`${GITHUB_API}/repos/${owner}/${repo}/releases/tags/${encodeURIComponent(tag)}`, {
                headers: githubHeaders(t.config),
                timeoutMs: t.config.timeouts.webMs,
                signal: t.signal,
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
      if (hit.value) return { release: toChangelogRelease(hit.value), cached: hit.cached, fetchedAt: isoFrom(hit.fetchedAt) };
    } catch (err) {
      if (isRateLimited(err)) throw err;
      // try the next spelling
    }
  }
  return null;
}

// missing majors looked up by tag
async function boundaryReleases(
  pkg: string,
  from: string,
  to: string,
  info: ChangelogInfo | null,
  meta: PackageMeta,
  t: ToolContext,
  notes: string[],
): Promise<{ picked: PickedRelease[]; lookups: number }> {
  const releases = info?.releases ?? [];
  const byVersion = new Map<string, ChangelogRelease>();
  for (const r of releases) {
    const v = releaseVersion(r, pkg);
    if (v && !byVersion.has(v)) byVersion.set(v, r);
  }
  const cached = info?.source === 'cache' || t.config.offline;
  const kindOf = (r: ChangelogRelease): 'release-notes' | 'changelog' =>
    (r.url && /\/releases\/tag\//.test(r.url)) || info?.source === 'github-releases' ? 'release-notes' : 'changelog';
  const repo = githubRepo(meta);
  const picked: PickedRelease[] = [];
  let lookups = 0;
  let rateLimited = false;
  for (const version of boundaryOrder(from, to, [...byVersion.keys()])) {
    if (picked.length >= MAX_RELEASE_SOURCES) break;
    const listed = byVersion.get(version);
    if (listed) {
      if (listed.body.trim()) picked.push({ version, release: listed, kind: kindOf(listed), cached, fetchedAt: new Date().toISOString(), viaTag: false });
      continue;
    }
    const major = parseVersion(version)?.major ?? 0;
    if (!repo || rateLimited || major < 1 || lookups >= MAX_TAG_LOOKUPS) continue;
    lookups += 1;
    try {
      const found = await releaseByTag(repo.owner, repo.repo, pkg, version, t);
      if (found && found.release.body.trim()) {
        picked.push({ version, release: found.release, kind: 'release-notes', cached: found.cached, fetchedAt: found.fetchedAt, viaTag: true });
      }
    } catch (err) {
      rateLimited = true;
      notes.push(`release ${version}: ${describeWebError(err)}`);
    }
  }
  return { picked, lookups };
}

function releaseSource(pkg: string, p: PickedRelease, repo: RepositoryInfo | null, keywords: EvidenceKeywords): MigrationSource {
  const r = p.release;
  const url = r.url ?? (repo ? `${repo.url}/releases/tag/${encodeURIComponent(r.tag)}` : `https://www.npmjs.com/package/${pkg}/v/${p.version}`);
  return {
    url,
    kind: p.kind,
    title: `${pkg} ${tagLabel(r.tag)} ${p.kind === 'release-notes' ? 'release notes' : 'changelog section'}`,
    version: p.version,
    cached: p.cached,
    fetchedAt: p.fetchedAt,
    text: filterEvidenceText(r.body, keywords, p.kind),
  };
}

function docKind(name: string): SourceKind {
  if (/migrat|upgrad/i.test(name)) return 'migration-guide';
  if (/changelog|changes|history/i.test(name)) return 'changelog';
  return 'readme';
}

// raw 404 body or js shell
function isMissingPage(page: PageText): boolean {
  const t = page.text.trim();
  return t.length < 20 || /^404: Not Found/i.test(t) || (page.jsRendered && t.length < 200);
}

function isNotFound(err: unknown): boolean {
  return (err instanceof FetchPageError && err.status === 404) || (err instanceof HttpError && err.status === 404);
}

interface DocPage {
  name: string;
  url: string;
  title: string;
  page: PageText;
}

function docQuery(to: string): string {
  const major = parseVersion(to)?.major ?? 0;
  return `${major}.0.0 breaking changes removed deprecated migration upgrade require import`;
}

async function githubDocs(pkg: string, to: string, repo: RepositoryInfo & { owner: string; repo: string }, tag: string | null, t: ToolContext): Promise<DocPage[] | null> {
  const dir = repo.directory ? repo.directory.replace(/^\.?\/+|\/+$/g, '') : '';
  const prefix = dir ? `${dir}/` : '';
  const query = docQuery(to);
  const raw = (ref: string, name: string): string => `${GITHUB_RAW}/${repo.owner}/${repo.repo}/${encodeURIComponent(ref)}/${prefix}${name}`;
  const blob = (ref: string, name: string): string => `https://github.com/${repo.owner}/${repo.repo}/blob/${encodeURIComponent(ref)}/${prefix}${name}`;
  let ref: string | null = null;
  let readme: PageText | null = null;
  for (const candidate of unique([tag, `v${to}`, to, `${pkg}@${to}`].filter((r): r is string => Boolean(r))).slice(0, 3)) {
    try {
      const page = await fetchPageText(raw(candidate, 'README.md'), query, t);
      if (isMissingPage(page)) continue;
      ref = candidate;
      readme = page;
      break;
    } catch (err) {
      if (isNotFound(err)) continue;
      return null;
    }
  }
  if (!ref || !readme) return null;
  const found: DocPage[] = [];
  const others = ['MIGRATION.md', 'UPGRADING.md', 'CHANGELOG.md'];
  const settled = await Promise.allSettled(others.map((name) => fetchPageText(raw(ref as string, name), query, t)));
  settled.forEach((outcome, i) => {
    const name = others[i] ?? '';
    if (outcome.status === 'fulfilled' && !isMissingPage(outcome.value)) {
      found.push({ name, url: blob(ref as string, name), title: `${repo.owner}/${repo.repo} ${prefix}${name} at ${ref}`, page: outcome.value });
    }
  });
  found.push({ name: 'README.md', url: blob(ref, 'README.md'), title: `${repo.owner}/${repo.repo} ${prefix}README.md at ${ref}`, page: readme });
  return found;
}

interface JsdelivrListing {
  version?: string;
  files?: { name: string; size?: number }[];
}

const DOC_FILE = /^(?:readme|changelog|changes|history|migrat\w*|upgrad\w*)(?:\.(?:md|markdown|txt))?$/i;

function docRank(name: string): number {
  const kind = docKind(name);
  return kind === 'migration-guide' ? 0 : kind === 'changelog' ? 1 : 2;
}

// jsdelivr fallback
async function jsdelivrDocs(pkg: string, to: string, t: ToolContext): Promise<DocPage[]> {
  const listing = (
    await cachedFetch<JsdelivrListing>(
      t,
      'docs',
      `jsdelivr:${pkg}@${to}`,
      () => getJson<JsdelivrListing>(`${JSDELIVR_DATA_URL}/${pkg}@${to}?structure=flat`, { timeoutMs: t.config.timeouts.webMs, signal: t.signal }),
      { what: `the file list of ${pkg}@${to}` },
    )
  ).value;
  const version = listing.version ?? to;
  const files = (listing.files ?? [])
    .filter((f) => f.name.split('/').filter(Boolean).length === 1 && DOC_FILE.test(f.name.replace(/^\//, '')) && (f.size ?? 0) <= 2_000_000)
    .sort((a, b) => docRank(a.name) - docRank(b.name) || a.name.localeCompare(b.name))
    .slice(0, MAX_DOC_FILES);
  const query = docQuery(to);
  const out: DocPage[] = [];
  for (const file of files) {
    const name = file.name.replace(/^\//, '');
    const url = `${JSDELIVR_CDN_URL}/${pkg}@${version}/${name}`;
    try {
      const page = await fetchPageText(url, query, t);
      if (!isMissingPage(page)) out.push({ name, url, title: `${pkg}@${version} ${name}`, page });
    } catch {
      // skip unreadable file
    }
  }
  return out;
}

function importStyle(usage: UsageEvidence | null | undefined): 'require' | 'import' | null {
  const kinds = (usage?.files ?? []).map((f) => f.kind);
  if (kinds.some((k) => k === 'cjs-require' || k === 'cjs-destructure' || k === 'cjs-member')) return 'require';
  if (kinds.some((k) => k.startsWith('esm-') || k === 'dynamic-import')) return 'import';
  return null;
}

function usesDefaultBinding(usage: UsageEvidence | null | undefined): boolean {
  return (usage?.files ?? []).some((f) => f.binding !== null && (f.kind === 'cjs-require' || f.kind === 'esm-default'));
}

// second query is the upgrade guide
export function migrationQueries(pkg: string, from: string, to: string, usage: UsageEvidence | null | undefined): string[] {
  const target = parseVersion(to);
  const source = parseVersion(from);
  const major = target ? (target.major > 0 ? `${target.major}` : `0.${target.minor}`) : to;
  const terms = [pkg, major, 'migration', 'breaking changes'];
  if (usesDefaultBinding(usage)) terms.push('default export');
  const style = importStyle(usage);
  if (style) terms.push(style);
  terms.push(...usedMembers(usage).slice(0, 3));
  const fromLine = source ? (source.major > 0 ? `${source.major}` : `0.${source.minor}`) : from;
  return [unique(terms).join(' '), `${pkg} upgrade guide ${fromLine} to ${major}`];
}

function classifyUrl(url: string): { kind: SourceKind; version: string | null } {
  let u: URL | null = null;
  try {
    u = new URL(url);
  } catch {
    return { kind: 'web', version: null };
  }
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  const p = u.pathname;
  if (host === 'github.com') {
    const tag = /\/releases\/tag\/([^/]+)/.exec(p)?.[1];
    if (tag) return { kind: 'release-notes', version: versionFromTag(decodeURIComponent(tag)) };
    if (/\/(?:issues|pull|discussions)\/\d+/.test(p)) return { kind: 'issue', version: null };
  }
  const base = decodeURIComponent(p.split('/').pop() ?? '');
  // only MIGRATION/UPGRADING names count
  if (/^(?:migrat|upgrad)\w*(?:\.(?:md|markdown|txt|html?))?$/i.test(base)) return { kind: 'migration-guide', version: null };
  if (/^(?:changelog|history|changes)/i.test(base)) return { kind: 'changelog', version: null };
  if (/^readme/i.test(base)) return { kind: 'readme', version: null };
  return { kind: 'web', version: null };
}

// deterministic sources first, web capped
export async function gatherSources(
  pkg: string,
  from: string,
  to: string,
  usage: UsageEvidence,
  ctx: MigrationContext,
): Promise<{ sources: MigrationSource[]; queries: MigrationQuery[] }> {
  const t = researchContext(ctx, pkg, from);
  const keywords = evidenceKeywords(pkg, usage);
  const collector = new SourceCollector(MAX_SOURCES);
  const queries: MigrationQuery[] = [];
  const notes: string[] = [];

  agent(ctx, `Checking the changelog of ${pkg} ${from} → ${to}...`);
  let info: ChangelogInfo | null = null;
  try {
    info = await getChangelogInfo(pkg, from, to, t);
    const breaking = info.breakingLines.length;
    const where = info.source === 'github-releases' ? 'GitHub releases' : info.source === 'changelog-file' ? 'changelog file' : info.source;
    result(
      ctx,
      info.source === 'unavailable'
        ? `Release notes unavailable${info.note ? `: ${oneLine(info.note, 120)}` : ''}`
        : `${info.releases.length} releases, ${breaking} breaking-change line${breaking === 1 ? '' : 's'} (${where})`,
    );
  } catch (err) {
    result(ctx, `Changelog unavailable: ${oneLine(describeWebError(err), 120)}`);
  }

  let meta: PackageMeta = { repository: null, homepage: null };
  try {
    meta = await resolvePackageMeta(pkg, [to, from], t);
  } catch {
    // fall back to the changelog repo url
  }
  if (!meta.repository && info?.repository) meta = { ...meta, repository: parseRepoUrl(info.repository) };
  const repo = githubRepo(meta);

  const { picked, lookups } = await boundaryReleases(pkg, from, to, info, meta, t, notes);
  if (picked.length > 0 || lookups > 0) {
    const labels = picked.map((p) => tagLabel(p.release.tag));
    agent(ctx, `Reading the release notes of ${pkg} ${labels.length > 0 ? labels.join(', ') : 'major versions'}...`, picked.length > 0 && picked.every((p) => p.cached) ? 'cached' : undefined);
    const kept = picked.map((p) => releaseSource(pkg, p, meta.repository, keywords)).filter((s) => collector.add(s)).length;
    result(ctx, `${kept} release note${kept === 1 ? '' : 's'} kept${lookups > 0 ? `, ${lookups} looked up by tag` : ''}${notes.length > 0 ? ` · ${oneLine(notes.join('; '), 100)}` : ''}`);
  }
  const pickedReleases = new Set(picked.map((p) => p.release));
  const rest = (info?.releases ?? []).filter((r) => !pickedReleases.has(r));
  const otherLines = collectBreakingLines(rest).slice(0, AGGREGATE_LINES_MAX);
  if (otherLines.length > 0) {
    collector.add({
      url: repo ? `${repo.url}/releases` : (rest[0]?.url ?? `https://www.npmjs.com/package/${pkg}?activeTab=versions`),
      kind: 'changelog',
      title: `${pkg} breaking-change lines of the other releases ${from} to ${to}`,
      version: null,
      cached: info?.source === 'cache' || t.config.offline,
      fetchedAt: new Date().toISOString(),
      text: otherLines.map((b) => `- ${tagLabel(b.tag)}: ${b.text}`).join('\n'),
    });
  }

  const targetTag = (info?.releases ?? []).find((r) => releaseVersion(r, pkg) === (parseVersion(to)?.version ?? to))?.tag ?? null;
  agent(ctx, `Reading the migration guide, changelog and README of ${pkg}@${to}...`);
  let docs: DocPage[] | null = null;
  let via = 'GitHub';
  if (repo) {
    try {
      docs = await githubDocs(pkg, to, repo, targetTag, t);
    } catch {
      docs = null;
    }
  }
  if (!docs || docs.length === 0) {
    via = 'jsDelivr';
    try {
      docs = await jsdelivrDocs(pkg, to, t);
    } catch (err) {
      docs = [];
      notes.push(`jsDelivr: ${describeWebError(err)}`);
    }
  }
  const docNames: string[] = [];
  for (const doc of docs ?? []) {
    collector.mark(doc.url);
    collector.mark(doc.page.url);
    const kind = docKind(doc.name);
    const added = collector.add({
      url: doc.url,
      kind,
      title: doc.title,
      version: parseVersion(to)?.version ?? to,
      cached: doc.page.cached,
      fetchedAt: doc.page.fetchedAt,
      text: filterEvidenceText(doc.page.text, keywords, kind),
    });
    if (added) docNames.push(doc.name);
  }
  result(ctx, docNames.length > 0 ? `${docNames.join(', ')} (${via})` : `No migration guide or usable README found${t.config.offline ? ' in the cache' : ''}`);

  // second query only if the first found nothing
  let fetches = 0;
  let fromWeb = 0;
  for (const query of migrationQueries(pkg, from, to, usage).slice(0, MAX_WEB_QUERIES)) {
    if (queries.length > 0 && (fromWeb > 0 || fetches >= MAX_WEB_FETCHES)) break;
    agent(ctx, `Searching the web for "${oneLine(query, 70)}"...`);
    let response: WebSearchResponse;
    try {
      response = await searchWeb(query, t, { package: pkg, fromVersion: from, toVersion: to, maxResults: 5, ...(meta.repository ? { repository: meta.repository } : {}) });
    } catch (err) {
      response = { query, backend: 'none', hits: [], cached: false, note: `search failed: ${errorMessage(err)}` };
    }
    queries.push({ query: response.query, backend: response.backend, urls: response.hits.map((h) => h.url), cached: response.cached });
    result(
      ctx,
      response.backend === 'none'
        ? `No web search: ${oneLine(response.note ?? 'search unavailable', 100)}`
        : `${response.hits.length} result${response.hits.length === 1 ? '' : 's'} via ${response.backend}${response.cached ? ' (cached)' : ''}`,
    );
    if (response.backend === 'none') break;
    const candidates = rankOwnDomainsFirst(response.hits, pkg, meta).filter((h) => /^https?:\/\//i.test(h.url) && !collector.has(h.url));
    for (const hit of candidates) {
      if (fetches >= MAX_WEB_FETCHES || collector.full) break;
      fetches += 1;
      collector.mark(hit.url);
      agent(ctx, `Reading ${shortUrl(hit.url)}...`);
      let page: PageText;
      try {
        page = await fetchPageText(hit.url, query, t);
      } catch (err) {
        result(ctx, `Could not fetch the page: ${oneLine(errorMessage(err), 100)}`);
        continue;
      }
      if (page.jsRendered && page.text.trim().length < 400) {
        result(ctx, 'Little text could be extracted (JavaScript-rendered page); skipped');
        continue;
      }
      const { kind, version } = classifyUrl(page.finalUrl || hit.url);
      const text = filterEvidenceText(page.text, keywords, kind);
      if (!text) {
        result(ctx, 'No breaking-change text on the page; skipped');
        continue;
      }
      if (collector.add({ url: hit.url, kind, title: page.title ?? hit.title, version, cached: page.cached, fetchedAt: page.fetchedAt, text })) fromWeb += 1;
      result(ctx, `${text.length.toLocaleString('en-US')} chars of evidence${page.cached ? ' (cached)' : ''}`);
    }
  }
  return { sources: collector.sources, queries };
}

const KIND_LABEL: Record<SourceKind, string> = {
  'release-notes': 'release notes',
  changelog: 'changelog',
  'migration-guide': 'migration guide',
  readme: 'README',
  web: 'web page',
  issue: 'issue',
};

// target notes, guides, older notes, rest
export function rankSources(sources: readonly MigrationSource[]): MigrationSource[] {
  const versioned = sources.filter((s) => (s.kind === 'release-notes' || s.kind === 'changelog') && s.version);
  const newest =
    [...versioned].sort((a, b) => compareVersions(b.version as string, a.version as string))[0] ?? sources.find((s) => s.kind === 'release-notes');
  const group = (s: MigrationSource): number => {
    if (s === newest) return 0;
    switch (s.kind) {
      case 'migration-guide':
        return 1;
      case 'release-notes':
        return 2;
      case 'readme':
        return 3;
      case 'web':
        return 4;
      case 'changelog':
        return s.version ? 2 : 5;
      default:
        return 6;
    }
  };
  return sources
    .map((s, i) => ({ s, i, g: group(s) }))
    .sort((a, b) => {
      if (a.g !== b.g) return a.g - b.g;
      if (a.g === 2 && a.s.version && b.s.version) return compareVersions(b.s.version, a.s.version) || a.i - b.i;
      return a.i - b.i;
    })
    .map((x) => x.s);
}

export function buildDigest(sources: readonly MigrationSource[], maxChars?: number): string {
  const max = maxChars ?? DIGEST_MAX_CHARS;
  const parts: string[] = [];
  let used = 0;
  let n = 0;
  for (const source of rankSources(sources)) {
    const body = source.text.trim();
    if (!body) continue;
    n += 1;
    const label = `${KIND_LABEL[source.kind]}${source.version ? ` ${source.version}` : ''}`;
    const header = `[${n}] ${label}${source.title ? ` · ${oneLine(source.title, 90)}` : ''}\nURL: ${source.url}`;
    const room = max - used - header.length - 3;
    if (room < 160) break;
    const text = body.length <= room ? body : capLines(body, room);
    if (!text) break;
    const part = `${header}\n${text}`;
    parts.push(part);
    used += part.length + 2;
  }
  return parts.join('\n\n');
}

interface MappedText {
  text: string;
  // normalised index -> original index
  map: number[];
}

const QUOTE_CHARS = new Set(['"', "'", '\u2018', '\u2019', '\u201c', '\u201d', '\u00ab', '\u00bb']);

// loose also drops markdown, quotes, case
function normalizeMapped(text: string, mode: 'strict' | 'loose'): MappedText {
  const out: string[] = [];
  const map: number[] = [];
  let space = -1;
  let lineStart = true;
  for (let i = 0; i < text.length; i += 1) {
    let ch = text[i] as string;
    if (/\s/.test(ch)) {
      if (ch === '\n') lineStart = true;
      if (out.length > 0 && space === -1) space = i;
      continue;
    }
    if (mode === 'loose') {
      if (lineStart && (ch === '-' || ch === '+' || ch === '*') && /\s/.test(text[i + 1] ?? '')) {
        lineStart = false;
        continue;
      }
      if (ch === '`' || ch === '*') continue;
      if (QUOTE_CHARS.has(ch)) ch = "'";
      ch = ch.toLowerCase();
    }
    lineStart = false;
    if (space !== -1) {
      out.push(' ');
      map.push(space);
      space = -1;
    }
    out.push(ch);
    map.push(i);
  }
  return { text: out.join(''), map };
}

function cleanQuote(quote: string): string {
  let q = String(quote ?? '').trim();
  for (let i = 0; i < 3; i += 1) {
    const before = q;
    q = q
      .replace(/^[>\s]+/, '')
      .replace(/^(?:[-*+]|\d+[.)])\s+/, '')
      .replace(/^(?:\.{3}|\u2026)\s*/, '')
      .replace(/^["'\u201c\u2018]+|["'\u201d\u2019]+$/g, '')
      .replace(/(?:\s*\u2026|[.,;:!])+$/, '')
      .trim();
    if (q === before) break;
  }
  return q;
}

// spaced ellipses only, not parse(...)
function quoteFragments(quote: string): string[] {
  return quote
    .split(/\s+(?:\.{3}|\u2026)\s+/)
    .map((f) => cleanQuote(f))
    .filter((f) => normalizeMapped(f, 'loose').text.length >= 8);
}

function wordCount(text: string): number {
  return (text.match(/[A-Za-z0-9_$]+/g) ?? []).length;
}

interface PreparedSource {
  source: MigrationSource;
  strict: MappedText | null;
  loose: MappedText | null;
}

function prepared(p: PreparedSource, mode: 'strict' | 'loose'): MappedText {
  if (mode === 'strict') return (p.strict ??= normalizeMapped(p.source.text, 'strict'));
  return (p.loose ??= normalizeMapped(p.source.text, 'loose'));
}

// widened over markdown and punctuation
function originalSpan(source: string, mapped: MappedText, start: number, length: number): string {
  let s = mapped.map[start] ?? 0;
  let e = (mapped.map[start + length - 1] ?? s) + 1;
  while (s > 0 && (source[s - 1] === '`' || source[s - 1] === '*')) s -= 1;
  while (e < source.length && (source[e] === '`' || source[e] === '*')) e += 1;
  if (e < source.length && /[.;:!]/.test(source[e] ?? '')) e += 1;
  return source.slice(s, e).replace(/\s+/g, ' ').trim();
}

function findFragments(p: PreparedSource, fragments: readonly string[]): string[] | null {
  for (const mode of ['strict', 'loose'] as const) {
    const hay = prepared(p, mode);
    const found: string[] = [];
    let from = 0;
    for (const fragment of fragments) {
      const needle = normalizeMapped(fragment, mode).text;
      const at = needle ? hay.text.indexOf(needle, from) : -1;
      if (at === -1) break;
      found.push(originalSpan(p.source.text, hay, at, needle.length));
      from = at + needle.length;
    }
    if (found.length === fragments.length) return found;
  }
  return null;
}

// verbatim quote check
export function verifyEvidenceQuotes(items: readonly Omit<MigrationBriefItem, 'verified'>[], sources: readonly MigrationSource[]): MigrationBriefItem[] {
  const pool: PreparedSource[] = sources.filter((s) => s.text.trim()).map((source) => ({ source, strict: null, loose: null }));
  return items.map((item) => {
    const base: MigrationBriefItem = { ...item, affectedFiles: [...(item.affectedFiles ?? [])], verified: false };
    const quote = cleanQuote(item.evidenceQuote);
    const loose = normalizeMapped(quote, 'loose').text;
    if (loose.length < 12 || wordCount(quote) < 3) return base;
    const fragments = quoteFragments(quote);
    const ordered = [...pool].sort((a, b) => Number(sameUrl(b.source.url, item.evidenceUrl)) - Number(sameUrl(a.source.url, item.evidenceUrl)));
    // whole quote, then its pieces in order
    for (const pieces of fragments.length > 1 ? [[quote], fragments] : [[quote]]) {
      for (const p of ordered) {
        const found = findFragments(p, pieces);
        if (found) return { ...base, evidenceQuote: found.join(' ... '), evidenceUrl: p.source.url, verified: true };
      }
    }
    return base;
  });
}

// banded, Infinity past max
function boundedDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return Infinity;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i += 1) {
    const row = new Array<number>(b.length + 1).fill(Infinity);
    row[0] = i;
    const from = Math.max(1, i - max);
    const to = Math.min(b.length, i + max);
    let best = row[0] as number;
    for (let j = from; j <= to; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min((prev[j] ?? Infinity) + 1, (row[j - 1] ?? Infinity) + 1, (prev[j - 1] ?? Infinity) + cost);
      if ((row[j] as number) < best) best = row[j] as number;
    }
    if (best > max) return Infinity;
    prev = row;
  }
  return (prev[b.length] ?? Infinity) <= max ? (prev[b.length] as number) : Infinity;
}

// within 3% and 6 chars
export function repairNearQuotes(items: readonly MigrationBriefItem[], sources: readonly MigrationSource[]): { items: MigrationBriefItem[]; repaired: number } {
  const lines = sources.flatMap((source) =>
    source.text
      .split('\n')
      .map((l) => bulletless(l))
      .filter((l) => l.length >= 12)
      .map((line) => ({ source, line, loose: normalizeMapped(line, 'loose').text })),
  );
  let repaired = 0;
  const out = items.map((item) => {
    if (item.verified) return item;
    const quote = normalizeMapped(cleanQuote(item.evidenceQuote), 'loose').text;
    if (quote.length < 20) return item;
    const max = Math.min(6, Math.max(1, Math.floor(quote.length * 0.03)));
    let best: { line: string; url: string; d: number } | null = null;
    for (const l of lines) {
      const target = normalizeMapped(cleanQuote(l.line), 'loose').text;
      const d = boundedDistance(quote, target, max);
      if (d < (best?.d ?? Infinity)) best = { line: l.line, url: l.source.url, d };
      if (best?.d === 0) break;
    }
    if (!best) return item;
    repaired += 1;
    return { ...item, evidenceQuote: best.line, evidenceUrl: best.url, verified: true };
  });
  return { items: out, repaired };
}

export interface ProjectFacts {
  pkg: string;
  sites: ImportSite[];
  // source files first
  importFiles: string[];
  sourceImportFiles: string[];
  // esm default or directly called require
  defaultImportFiles: string[];
  moduleStyle: 'commonjs' | 'module' | 'mixed' | 'unknown';
  // <script> tag mentions
  scriptTagFiles: string[];
  // any text file
  mentions: { path: string; line: number; text: string }[];
  bindings: string[];
  // within 6 lines of a use
  usedNames: Set<string>;
  runningNodeMajor: number;
  callSitesText: string;
}

const DEFAULT_KINDS = new Set<ImportSite['kind']>(['cjs-require', 'esm-default']);

export async function collectProjectFacts(pkg: string, usage: UsageEvidence | null | undefined, t: ToolContext, callSitesText = ''): Promise<ProjectFacts> {
  let sites = [...(usage?.files ?? [])];
  let mentions: ProjectFacts['mentions'] = [];
  try {
    const found = await searchProject(t.projectRoot, new RegExp(escapeRegExp(pkg)), { exclude: t.config.exclude, maxResults: 300, contextLines: 0 });
    mentions = found.matches.map((m) => ({ path: m.path, line: m.line, text: m.text }));
  } catch {
    // partial is fine
  }
  if (sites.length === 0 && mentions.length > 0) {
    // no usage evidence, scan mentions
    const byFile = unique(mentions.map((m) => m.path));
    for (const file of byFile.slice(0, 50)) {
      try {
        const source = await readFile(path.join(t.projectRoot, file), 'utf8');
        sites.push(...findImportsInSource(source, file, [pkg]));
      } catch {
        // unreadable
      }
    }
  }
  sites = sites.filter((s) => isPathInside(t.projectRoot, s.path));
  const importFiles = unique([...sites].sort((a, b) => Number(a.scope !== 'source') - Number(b.scope !== 'source')).map((s) => s.path));
  const sourceImportFiles = unique(sites.filter((s) => s.scope === 'source').map((s) => s.path));
  let calledDirectly = new Set<string>();
  try {
    const calls = await findUsage(t.projectRoot, sites.filter((s) => s.binding && s.kind === 'cjs-require'), undefined, { contextLines: 0, maxResults: 200 });
    calledDirectly = new Set(calls.filter((m) => m.member === null).map((m) => m.path));
  } catch {
    // no call evidence
  }
  const defaultImportFiles = unique(
    sites.filter((s) => s.binding !== null && DEFAULT_KINDS.has(s.kind) && (s.kind === 'esm-default' || calledDirectly.has(s.path))).map((s) => s.path),
  );
  const cjs = sites.some((s) => s.kind.startsWith('cjs-'));
  const esm = sites.some((s) => s.kind.startsWith('esm-') || s.kind === 're-export');
  const moduleStyle = cjs && esm ? 'mixed' : cjs ? 'commonjs' : esm ? 'module' : 'unknown';
  const scriptTagFiles = unique(mentions.filter((m) => /<script\b/i.test(m.text) && !/\.(?:md|mdx|txt)$/i.test(m.path)).map((m) => m.path));
  const bindings = unique(sites.flatMap((s) => [s.binding, ...Object.values(s.named ?? {})]).filter((b): b is string => Boolean(b)));
  const usedNames = new Set<string>(usedMembers(usage));
  for (const site of sites) for (const imported of Object.keys(site.named ?? {})) usedNames.add(imported);
  const near = new RegExp(`(?<![\\w$])(?:${[pkg, ...bindings].map(escapeRegExp).join('|')})(?![\\w$])`);
  for (const file of importFiles.slice(0, 20)) {
    let lines: string[];
    try {
      lines = (await readFile(path.join(t.projectRoot, file), 'utf8')).split('\n');
    } catch {
      continue;
    }
    lines.forEach((line, i) => {
      if (!near.test(line)) return;
      for (let j = Math.max(0, i - 6); j <= Math.min(lines.length - 1, i + 6); j += 1) {
        for (const id of (lines[j] ?? '').match(/[A-Za-z_$][\w$]*/g) ?? []) usedNames.add(id);
      }
    });
  }
  return {
    pkg,
    sites,
    importFiles,
    sourceImportFiles,
    defaultImportFiles,
    moduleStyle,
    scriptTagFiles,
    mentions,
    bindings,
    usedNames,
    runningNodeMajor: Number(process.versions.node.split('.')[0]) || 0,
    callSitesText,
  };
}

function factsLines(facts: ProjectFacts): string[] {
  const style =
    facts.moduleStyle === 'commonjs'
      ? 'CommonJS (require)'
      : facts.moduleStyle === 'module'
        ? 'ES modules (import)'
        : facts.moduleStyle === 'mixed'
          ? 'both require and import'
          : 'unknown';
  return [
    `- The project loads ${facts.pkg} with: ${style}.`,
    `- Files importing ${facts.pkg}: ${facts.importFiles.length > 0 ? facts.importFiles.slice(0, 8).join(', ') : 'none'}.`,
    `- <script> tags loading ${facts.pkg}: ${facts.scriptTagFiles.length > 0 ? facts.scriptTagFiles.slice(0, 4).join(', ') : 'none (it is not used from a script tag or CDN)'}.`,
    facts.defaultImportFiles.length > 0 ? `- The default export of ${facts.pkg} is used in: ${facts.defaultImportFiles.join(', ')}.` : null,
    `- Node.js running PatchPilot: ${process.versions.node}.`,
  ].filter((l): l is string => l !== null);
}

const CODE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte)$/i;
// code-span words that are not api
const CODE_WORDS = new Set([
  'this', 'new', 'function', 'return', 'const', 'let', 'var', 'true', 'false', 'null', 'undefined', 'import', 'export', 'from', 'require',
  'default', 'async', 'await', 'class', 'extends', 'module', 'exports', 'typeof', 'instanceof', 'void', 'delete', 'object', 'string',
  'number', 'boolean', 'array', 'options', 'option',
]);
const SCRIPT_TAG = /script[- ]tags?\b|<script\b|\bCDN\b|\bUMD\b|browser globals?|global variable|window\.\w+/i;
const DEFAULT_EXPORT_REMOVED =
  /\bdefault export\b[^.\n]{0,40}\b(?:removed|dropped|no longer|gone)\b|\b(?:removed?|dropped|no longer (?:has|have|provides?|exports?))\b[^.\n]{0,30}\bdefault export\b|\bno default export\b/i;
const IMPORT_CHANGE = /\b(?:require|import|export|ESM|CommonJS|CJS|default export|named exports?|entry ?point|main field|exports field)\b/i;

function codeSpans(text: string): string[] {
  return [...String(text ?? '').matchAll(/`([^`\n]+)`/g)].map((m) => (m[1] ?? '').trim()).filter(Boolean);
}

// not specifiers or calls
function internalPaths(text: string, pkg: string): string[] {
  return unique(
    codeSpans(text).filter((s) => !/[()\s{}=;,'"]/.test(s) && s !== pkg && /^(?:\.{0,2}\/)?[\w@.-]+(?:\/[\w@.-]+)*\.(?:m?js|cjs|css|json|map)$|^\/?(?:lib|dist|src|build|umd|esm|cjs)\//.test(s)),
  ).map((s) => s.replace(/^\.{0,2}\//, '').replace(new RegExp(`^${escapeRegExp(pkg)}/`), ''));
}

function filesReferencing(paths: readonly string[], facts: ProjectFacts): string[] {
  const out = new Set<string>();
  for (const p of paths) {
    const bare = p.replace(/\.(?:m?js|cjs)$/, '');
    for (const site of facts.sites) {
      if (site.subpath && (site.subpath === p || site.subpath === bare || site.subpath.replace(/\.(?:m?js|cjs)$/, '') === bare)) out.add(site.path);
    }
    for (const m of facts.mentions) {
      if (/\.(?:md|mdx|txt)$/i.test(m.path)) continue;
      if (m.text.includes(`${facts.pkg}/${p}`) || m.text.includes(`${facts.pkg}/${bare}`)) out.add(m.path);
    }
  }
  return [...out];
}

function nodeVersionChange(text: string): { kind: 'drop' | 'require'; major: number } | null {
  const drop =
    /\bdrop(?:s|ped|ping)?\s+(?:support\s+(?:for\s+)?)?node(?:\.js)?\s*v?(\d+)/i.exec(text) ??
    /\bnode(?:\.js)?\s*v?(\d+)(?:\s*(?:and|or)\s*(?:below|lower|older))?\s+(?:is\s+|are\s+)?no longer supported/i.exec(text);
  if (drop?.[1]) return { kind: 'drop', major: Number(drop[1]) };
  const req = /\b(?:now\s+)?requires?\s+node(?:\.js)?\s*(?:>=?\s*|v|version\s+)?(\d+)/i.exec(text);
  if (req?.[1]) return { kind: 'require', major: Number(req[1]) };
  return null;
}

function normalizeFile(file: string): string {
  return toPosix(String(file ?? '').trim())
    .replace(/^\.\/+/, '')
    .replace(/:\d+(?::\d+)?$/, '');
}

export interface RailOutcome {
  item: DraftItem;
  // null when unchanged
  rule: string | null;
}

// oldApi for a removed default export
function defaultImportStatement(facts: ProjectFacts): string {
  const site = facts.sites.find((s) => facts.defaultImportFiles.includes(s.path) && DEFAULT_KINDS.has(s.kind));
  return site ? site.statement.replace(/;\s*$/, '') : '';
}

function namedImportFor(spans: readonly string[], facts: ProjectFacts): string {
  const want = facts.moduleStyle === 'module' ? /^import\b/ : /\brequire\s*\(/;
  return spans.find((s) => want.test(s)) ?? spans.find((s) => /\brequire\s*\(|^import\b/.test(s)) ?? '';
}

// harness facts beat the model's guess
export function applyBriefRails(item: DraftItem, facts: ProjectFacts): RailOutcome {
  const text = `${item.change}\n${item.evidenceQuote}\n${item.oldApi}`;
  // import files plus non-code mentions
  const known = new Set([
    ...facts.importFiles,
    ...facts.mentions.filter((m) => !CODE_FILE.test(m.path) && !/\.(?:md|mdx|txt)$/i.test(m.path)).map((m) => m.path),
  ]);
  const files = unique((item.affectedFiles ?? []).map(normalizeFile).filter((f) => f && known.has(f)));
  let applies = item.appliesToProject;
  let affected = files;
  let oldApi = item.oldApi;
  let newApi = item.newApi;
  let rule: string | null = null;

  const paths = internalPaths(`${item.change}\n${item.evidenceQuote}`, facts.pkg);
  if (paths.length > 0) {
    const referencing = filesReferencing(paths, facts);
    if (referencing.length > 0) {
      applies = 'yes';
      affected = unique([...affected, ...referencing]);
      rule = 'the project references a path the change names';
    } else {
      applies = 'no';
      affected = [];
      rule = `the project does not reference ${paths.map((p) => `\`${p}\``).join(', ')}`;
    }
  }
  if (rule === null && SCRIPT_TAG.test(text)) {
    if (facts.scriptTagFiles.length === 0) {
      applies = 'no';
      affected = [];
      rule = `no <script> tag loads ${facts.pkg} in this project`;
    } else {
      affected = unique([...affected, ...facts.scriptTagFiles]);
    }
  }
  if (rule === null && DEFAULT_EXPORT_REMOVED.test(text) && facts.defaultImportFiles.length > 0) {
    applies = 'yes';
    affected = unique([...affected, ...facts.defaultImportFiles]);
    if (!oldApi.trim()) oldApi = defaultImportStatement(facts);
    if (!newApi.trim()) newApi = namedImportFor(codeSpans(item.evidenceQuote), facts);
    rule = `the project uses the default export of ${facts.pkg}`;
  }
  if (rule === null && !IMPORT_CHANGE.test(text) && !nodeVersionChange(text) && !SCRIPT_TAG.test(text)) {
    // no backticked api used -> applies no
    const named = unique(
      codeSpans(`${item.evidenceQuote}\n${item.change}`).flatMap((span) => span.match(/[A-Za-z_$][\w$]*/g) ?? []),
    ).filter((id) => id.length >= 3 && !CODE_WORDS.has(id) && id !== facts.pkg && !facts.bindings.includes(id));
    if (named.length > 0 && !named.some((id) => facts.usedNames.has(id))) {
      applies = 'no';
      affected = [];
      rule = `the project does not use ${named.slice(0, 4).join(', ')}`;
    }
  }
  if (rule === null) {
    const node = nodeVersionChange(text);
    if (node && facts.runningNodeMajor > 0 && (node.kind === 'drop' ? node.major < facts.runningNodeMajor : node.major <= facts.runningNodeMajor)) {
      applies = 'no';
      affected = [];
      rule = `a Node.js version change needs no code edit (Node ${process.versions.node} runs here)`;
    }
  }
  // match the project's module style
  const esmForm = /^\s*import\s[^;]*\bfrom\s*['"]/.test(newApi);
  const cjsForm = /\brequire\s*\(/.test(newApi);
  if ((facts.moduleStyle === 'commonjs' && esmForm) || (facts.moduleStyle === 'module' && cjsForm && !esmForm)) {
    const fit = namedImportFor(codeSpans(item.evidenceQuote), facts);
    if (fit && fit !== newApi) {
      newApi = fit;
      rule ??= `the new API in the project's module style (${facts.moduleStyle === 'commonjs' ? 'require' : 'import'})`;
    }
  }
  if (applies === 'no') affected = [];
  if (applies === 'yes' && affected.length === 0 && IMPORT_CHANGE.test(text)) affected = facts.sourceImportFiles.length > 0 ? [...facts.sourceImportFiles] : [...facts.importFiles];
  const changed =
    applies !== item.appliesToProject ||
    affected.join('\n') !== (item.affectedFiles ?? []).join('\n') ||
    oldApi !== item.oldApi ||
    newApi !== item.newApi;
  return { item: { ...item, appliesToProject: applies, affectedFiles: affected, oldApi, newApi }, rule: changed ? (rule ?? 'affected files checked against the project') : null };
}

function bulletless(line: string): string {
  return line.trim().replace(/^(?:[-*+]|\d+[.)])\s+/, '').trim();
}

// BREAKING heading or keyword
export function breakingLinesOf(text: string): string[] {
  const out: string[] = [];
  let breaking = false;
  for (const raw of String(text ?? '').split('\n')) {
    const h = /^\s{0,3}#{1,6}\s+(.+)$/.exec(raw);
    if (h) {
      breaking = /breaking/i.test(h[1] ?? '');
      continue;
    }
    const line = bulletless(raw);
    if (line.length < 8) continue;
    if (breaking || /\bBREAKING\b|\bremoved\b|\brenamed\b|\bno longer\b|\bnow requires?\b|\bdrop(?:s|ped)?\s+support\b/i.test(line)) out.push(line);
  }
  return unique(out);
}

const COVER_STOP = new Set(['the', 'and', 'use', 'instead', 'with', 'for', 'from', 'when', 'using', 'was', 'has', 'been', 'are', 'now', 'its', 'this', 'that']);

function words(text: string, pkg: string): Set<string> {
  const skip = new Set(pkg.toLowerCase().split(/[^a-z0-9_$]+/));
  return new Set(
    normalizeMapped(text, 'loose')
      .text.split(/[^a-z0-9_$]+/)
      .filter((w) => w.length >= 3 && !COVER_STOP.has(w) && !skip.has(w)),
  );
}

// text or word overlap
function covers(item: DraftItem, line: string, pkg: string): boolean {
  const l = normalizeMapped(line, 'loose').text;
  for (const text of [item.evidenceQuote, item.change]) {
    const q = normalizeMapped(cleanQuote(text), 'loose').text;
    if (q.length >= 12 && (l.includes(q) || q.includes(l))) return true;
  }
  const itemWords = words(`${item.evidenceQuote} ${item.change}`, pkg);
  const head = words(line.split(/\.\s/)[0] ?? line, pkg);
  if (head.size >= 2 && [...head].every((w) => itemWords.has(w))) return true;
  const all = words(line, pkg);
  let shared = 0;
  for (const w of all) if (itemWords.has(w)) shared += 1;
  return shared >= 3 && shared / Math.max(1, all.size) >= 0.6;
}

export function itemFromLine(line: string, url: string, facts: ProjectFacts): DraftItem {
  const quote = bulletless(line);
  const spans = codeSpans(quote);
  let oldApi = '';
  let newApi = '';
  const instead = /\buse\s+`([^`]+)`[^`]*?\binstead of\s+`([^`]+)`/i.exec(quote);
  const renamed = /`([^`]+)`\s+(?:is\s+|was\s+|has been\s+)?renamed to\s+`([^`]+)`/i.exec(quote);
  const removed = /`([^`]+)`\s+(?:is\s+|was\s+|has been\s+)?removed/i.exec(quote);
  if (instead) {
    newApi = instead[1] ?? '';
    oldApi = instead[2] ?? '';
  } else if (renamed) {
    oldApi = renamed[1] ?? '';
    newApi = renamed[2] ?? '';
  } else if (removed) {
    oldApi = removed[1] ?? '';
    newApi = spans.find((s) => s !== oldApi) ?? '';
  } else if (DEFAULT_EXPORT_REMOVED.test(quote)) {
    oldApi = defaultImportStatement(facts);
    newApi = namedImportFor(spans, facts);
  } else if (spans.length > 0) {
    newApi = spans.join(' or ');
  }
  return {
    change: oneLine(quote, 240),
    appliesToProject: 'unsure',
    evidenceQuote: quote,
    evidenceUrl: url,
    oldApi,
    newApi,
    affectedFiles: [],
  };
}

// 4.0.10 -> the 4.0.0 notes
function targetReleaseSource(sources: readonly MigrationSource[], to: string): MigrationSource | null {
  const key = lineKey(to);
  const candidates = sources.filter((s) => (s.kind === 'release-notes' || s.kind === 'changelog') && s.version && lineKey(s.version) === key && compareVersions(s.version, to) <= 0);
  return candidates.sort((a, b) => compareVersions(a.version as string, b.version as string))[0] ?? null;
}

// pass only verified items
export function coverageItems(items: readonly DraftItem[], sources: readonly MigrationSource[], to: string, facts: ProjectFacts): DraftItem[] {
  const target = targetReleaseSource(sources, to);
  if (!target) return [];
  const added: DraftItem[] = [];
  for (const line of breakingLinesOf(target.text)) {
    if (added.length >= MAX_COVERAGE_ITEMS) break;
    if ([...items, ...added].some((i) => covers(i, line, facts.pkg))) continue;
    added.push(itemFromLine(line, target.url, facts));
  }
  return added;
}

function normalizeApplies(value: unknown): DraftItem['appliesToProject'] {
  const v = String(value ?? '')
    .trim()
    .toLowerCase();
  if (v === 'yes' || v === 'true' || v === 'y' || v === 'applies') return 'yes';
  if (v === 'no' || v === 'false' || v === 'n' || v === 'not applicable' || v === 'n/a') return 'no';
  return 'unsure';
}

function toFileList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v ?? '').trim()).filter(Boolean);
  if (typeof value === 'string' && value.trim()) return value.split(/[,\n]/).map((v) => v.trim()).filter(Boolean);
  return [];
}

function toDraft(raw: unknown): DraftItem | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const text = (v: unknown): string => (typeof v === 'string' ? v.trim() : v === null || v === undefined ? '' : String(v).trim());
  const change = text(r.change);
  if (!change) return null;
  return {
    change: oneLine(change, 300),
    appliesToProject: normalizeApplies(r.appliesToProject),
    evidenceQuote: text(r.evidenceQuote).slice(0, 600),
    evidenceUrl: text(r.evidenceUrl),
    oldApi: text(r.oldApi).slice(0, 300),
    newApi: text(r.newApi).slice(0, 300),
    affectedFiles: toFileList(r.affectedFiles).slice(0, 20),
  };
}

// null when not a json brief
export function parseBriefOutput(content: string): DraftItem[] | null {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    value = extractJsonObject(content) ?? parseLenientJson(content);
  }
  const list = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { items?: unknown }).items)
      ? (value as { items: unknown[] }).items
      : null;
  if (!list) return null;
  return list
    .map(toDraft)
    .filter((i): i is DraftItem => i !== null)
    .slice(0, MAX_BRIEF_ITEMS);
}

function briefSystemPrompt(pkg: string, from: string, to: string, budget: number): string {
  return [
    `You are PatchPilot, preparing the migration brief for upgrading the npm package ${pkg} from ${from} to ${to} in THIS project. The brief lists the breaking changes between those versions and says, for each one, whether this project's code is affected.`,
    'Rules: use only the evidence sources in this conversation and never invent a change. evidenceQuote is one sentence copied exactly, character for character, from one evidence source; evidenceUrl is that source\'s URL. appliesToProject is "yes" when the project\'s code (the call sites) uses the changed API, "no" when it does not (for example a change for script-tag or browser use, the CLI, or an API the project never calls), "unsure" when the evidence cannot tell. oldApi and newApi are short code snippets before and after. affectedFiles are project files from the call sites that need a change, [] when the change does not apply.',
    `Tool rules: call a tool only when the evidence leaves a question open (for example fetch_page for a migration guide the notes link to); never repeat a call; budget ${budget} tool calls. Otherwise answer without a tool call.`,
    `At the end you write the brief as JSON: ${schemaText(BRIEF_SCHEMA)}`,
  ].join('\n\n');
}

function briefUserPrompt(pkg: string, from: string, to: string, facts: ProjectFacts, digest: string): string {
  return [
    `Upgrade: ${pkg} ${from} → ${to}.`,
    '',
    'Project facts (deterministic scan):',
    ...factsLines(facts),
    '',
    'Call sites:',
    facts.callSitesText.trim() || '(none found)',
    '',
    'Evidence sources (keyword-filtered release notes, docs and web pages):',
    digest || '(no sources were found)',
    '',
    `Task: decide which breaking changes affect this project's code. Every source above is already fetched: do not fetch or search for it again. Only if a document you need is missing (for example a migration guide the notes link to), call fetch_page once. Otherwise reply now with one short line per breaking change: applies yes, no or unsure, and why.`,
  ].join('\n');
}

function briefContinuePrompt(remaining: number, budget: number): string {
  if (remaining <= 1) return '1 tool call left, wrap up: make one last call only if it is essential, otherwise reply now with one short line per breaking change (applies yes, no or unsure, and why).';
  return `${remaining} of ${budget} tool calls left. Call another tool only if it answers an open question; otherwise reply with one short line per breaking change (applies yes, no or unsure, and why).`;
}

function briefSchemaPrompt(): string {
  return [
    'Now write the migration brief as JSON matching the schema: {"items": [...]}, at most 6 items: the changes that apply first, then the ones that could; leave out internal changes the call sites never touch.',
    'evidenceQuote: copy the exact sentence from one evidence source above, character for character (keep backticks); evidenceUrl: the URL of that source.',
    'appliesToProject: "yes", "no" or "unsure" as decided above. oldApi and newApi: short code before and after. affectedFiles: files from the call sites, [] when the change does not apply.',
    'Use only the evidence in this conversation.',
  ].join('\n');
}

const REPEAT_NOTE = 'You already have this result from an earlier call; do not repeat it.';

interface BriefLoopState {
  messages: ChatMessage[];
  budget: number;
  used: number;
  seen: Map<string, { count: number; content: string }>;
  executions: ToolExecution[];
  step: number;
  // canonical url -> digest number
  known: Map<string, number>;
  // lower case
  searched: Set<string>;
  // two end the loop
  wasted: number;
}

// canned answer, result already in evidence
function alreadyInEvidence(tool: string, args: Record<string, unknown>, pkg: string, state: BriefLoopState): string | null {
  if (tool === 'fetch_page' && typeof args.url === 'string') {
    const n = state.known.get(canonicalUrl(args.url));
    if (n !== undefined) return `This page is already in the evidence as source [${n}] (${args.url}). Do not fetch it again; use the evidence above.`;
  }
  if (tool === 'get_changelog' && String(args.package ?? pkg) === pkg) {
    return `The release notes of ${pkg} between these versions are already in the evidence above (keyword-filtered). Do not fetch them again.`;
  }
  if (tool === 'web_search' && typeof args.query === 'string' && state.searched.has(args.query.trim().toLowerCase())) {
    return 'This search already ran; its useful results are in the evidence above.';
  }
  return null;
}

async function chat(
  ctx: MigrationContext,
  request: { messages: ChatMessage[]; tools?: ReturnType<ToolRegistry['schemas']>; format?: JsonSchema; purpose: 'migration' | 'brief'; maxTokens: number },
): Promise<{ response: ChatResponse | null; error: unknown }> {
  const spinner = ctx.ui.spinner(`${ctx.ui.purple('agent', ctx.ui.ce)} ${ctx.ui.ce.dim('thinking...')}`);
  try {
    const response = await ctx.provider.chat({
      messages: request.messages,
      ...(request.tools && request.tools.length > 0 ? { tools: request.tools } : {}),
      ...(request.format ? { format: request.format } : {}),
      options: { num_predict: request.maxTokens },
      purpose: request.purpose,
      ...(ctx.tools?.signal ? { signal: ctx.tools.signal } : {}),
    });
    return { response, error: null };
  } catch (err) {
    if (err instanceof LlmError && err.kind === 'aborted') throw err;
    return { response: null, error: err };
  } finally {
    spinner.stop();
  }
}

function cleanProse(text: string, toolNames: readonly string[]): string {
  const prose = parseTextToolCalls(text ?? '', toolNames).text.replace(/```[\s\S]*?```/g, ' ').replace(/\s+/g, ' ').trim();
  // half-written tool call, not analysis
  if (/^[[{]|\{\s*"name"\s*:|\[TOOL_CALLS\]/.test(prose)) return '';
  return /[A-Za-z]{3,}.*[A-Za-z]{3,}/.test(prose) ? prose : '';
}

function logToolCall(ctx: MigrationContext, pkg: string, tool: string, args: Record<string, unknown>, by: 'model' | 'harness', step: number): void {
  ctx.audit.log({ event: 'tool.call', stage: 'migration', package: pkg, tool, args, by, step });
}

function logToolResult(ctx: MigrationContext, pkg: string, exec: ToolExecution): void {
  ctx.audit.log({
    event: 'tool.result',
    stage: 'migration',
    package: pkg,
    tool: exec.tool ?? exec.requested,
    ok: exec.ok,
    summary: exec.hint,
    truncated: exec.truncated,
    cached: Boolean(exec.result?.cached),
    durationMs: exec.durationMs,
  });
}

// traced and audited
async function harnessCall(ctx: MigrationContext, t: ToolContext, pkg: string, name: 'get_usage' | 'search_code', args: Record<string, unknown>, step: number): Promise<ToolExecution> {
  const def = ctx.registry.get(name);
  const norm = def ? ctx.registry.normalizeArgs(def, args, t) : null;
  agent(ctx, ctx.registry.describeCall({ name, arguments: args }, t));
  logToolCall(ctx, pkg, name, norm?.args ?? args, 'harness', step);
  const exec = await ctx.registry.execute({ name, arguments: args }, t, 'migration');
  logToolResult(ctx, pkg, exec);
  result(ctx, exec.hint || exec.status);
  return exec;
}

async function callSiteEvidence(ctx: MigrationContext, t: ToolContext, pkg: string, usage: UsageEvidence | null | undefined): Promise<{ text: string; keys: Map<string, string> }> {
  const keys = new Map<string, string>();
  const parts: string[] = [];
  const usageArgs = { package: pkg };
  const usageExec = await harnessCall(ctx, t, pkg, 'get_usage', usageArgs, 1);
  parts.push(`get_usage(${JSON.stringify(usageArgs)}):\n${usageExec.content}`);
  keys.set(toolCallKey('get_usage', usageExec.args), usageExec.content);
  const name = escapeRegExp(pkg);
  const bindings = unique((usage?.files ?? []).flatMap((f) => [f.binding, ...Object.values(f.named ?? {})]).filter((b): b is string => Boolean(b) && isIdentifier(b as string))).slice(0, 6);
  const calls = bindings.length > 0 ? `|\\b(?:${bindings.map(escapeRegExp).join('|')})\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*\\s*)?\\(` : '';
  const pattern = `require\\(\\s*['"]${name}(?:/[^'"]*)?['"]\\s*\\)|from\\s+['"]${name}(?:/[^'"]*)?['"]|<script[^>]*${name}${calls}`;
  const searchArgs = { pattern, maxResults: 20 };
  const searchExec = await harnessCall(ctx, t, pkg, 'search_code', searchArgs, 2);
  parts.push(`search_code(${JSON.stringify({ pattern })}):\n${searchExec.content}`);
  keys.set(toolCallKey('search_code', searchExec.args), searchExec.content);
  return { text: parts.join('\n\n'), keys };
}

// no js shells or old versions
async function modelPageSources(executions: readonly ToolExecution[], t: ToolContext, collectorUrls: readonly string[], from: string): Promise<MigrationSource[]> {
  const out: MigrationSource[] = [];
  for (const exec of executions) {
    if (exec.tool !== 'fetch_page' || !exec.ok) continue;
    const url = String(exec.args.url ?? '');
    if (!url || collectorUrls.some((u) => sameUrl(u, url)) || out.some((s) => sameUrl(s.url, url))) continue;
    try {
      const query = typeof exec.args.query === 'string' && exec.args.query.trim() ? exec.args.query : undefined;
      const page = await fetchPageText(url, query, t);
      const { kind, version } = classifyUrl(page.finalUrl || url);
      if (page.jsRendered || page.text.trim().length < 40) continue;
      if (version && parseVersion(version) && parseVersion(from) && compareVersions(version, from) <= 0) continue;
      const text = capLines(
        page.text
          .split('\n')
          .map((l) => tidyLine(l))
          .filter(Boolean)
          .join('\n'),
        MODEL_PAGE_TEXT_MAX,
      );
      if (text) out.push({ url, kind, title: page.title, version, cached: page.cached, fetchedAt: page.fetchedAt, text });
    } catch {
      // gone from cache, quotes stay unverified
    }
  }
  return out;
}

function toolCallTurn(calls: readonly { tool: string; args: Record<string, unknown> }[]): ChatMessage {
  return { role: 'assistant', content: '', tool_calls: calls.map((c) => ({ function: { name: c.tool, arguments: c.args } })) };
}

async function runBriefLoop(
  ctx: MigrationContext,
  t: ToolContext,
  pkg: string,
  state: BriefLoopState,
  queries: MigrationQuery[],
): Promise<void> {
  const tools = ctx.registry.schemas('migration');
  const toolNames = tools.map((s) => s.function.name);
  const maxTurns = state.budget + 2;
  for (let turn = 0; turn < maxTurns && state.used < state.budget; turn += 1) {
    const { response, error } = await chat(ctx, { messages: state.messages, tools, purpose: 'migration', maxTokens: LOOP_MAX_TOKENS });
    if (!response) {
      result(ctx, `Model call failed: ${oneLine(errorMessage(error), 140)}`);
      return;
    }
    const native = (response.message.tool_calls ?? []).filter((c) => c?.function?.name);
    const recovered = native.length > 0 ? { calls: native as ToolCall[], text: response.message.content ?? '' } : parseTextToolCalls(response.message.content ?? '', toolNames);
    const prose = cleanProse(recovered.text, toolNames);
    if (prose) agent(ctx, oneLine(prose, 220));
    if (recovered.calls.length === 0) {
      state.messages.push({ role: 'assistant', content: response.message.content ?? '' });
      return;
    }
    const prepared = recovered.calls.map((c) => {
      const rawArgs = unwrapRawArguments(c.function.arguments);
      const def = ctx.registry.get(c.function.name);
      const norm = def ? ctx.registry.normalizeArgs(def, rawArgs, t) : null;
      const tool = def?.name ?? c.function.name;
      const args = norm?.args ?? (rawArgs && typeof rawArgs === 'object' ? (rawArgs as Record<string, unknown>) : {});
      return { name: c.function.name, tool, rawArgs, args, key: toolCallKey(tool, args) };
    });
    state.messages.push(toolCallTurn(prepared));
    let stop = false;
    let ran = 0;
    for (const call of prepared) {
      if (stop || ran >= CALLS_PER_TURN) {
        state.messages.push({ role: 'tool', tool_name: call.tool, content: 'Not run: at most two tool calls per turn, and only for evidence that is missing. Answer with the evidence you have.' });
        continue;
      }
      const prior = state.seen.get(call.key);
      if (prior) {
        prior.count += 1;
        state.wasted += 1;
        agent(ctx, ctx.registry.describeCall({ name: call.name, arguments: call.rawArgs }, t));
        result(ctx, 'Already done: the earlier result was sent again');
        state.messages.push({ role: 'tool', tool_name: call.tool, content: `${REPEAT_NOTE}\n${prior.content}` });
        if (prior.count >= 3 || state.wasted >= 2) stop = true;
        continue;
      }
      const known = alreadyInEvidence(call.tool, call.args, pkg, state);
      if (known) {
        state.wasted += 1;
        state.seen.set(call.key, { count: 1, content: known });
        agent(ctx, ctx.registry.describeCall({ name: call.name, arguments: call.rawArgs }, t));
        result(ctx, 'Already in the evidence: not run again');
        state.messages.push({ role: 'tool', tool_name: call.tool, content: known });
        if (state.wasted >= 2) stop = true;
        continue;
      }
      if (state.used >= state.budget) {
        state.messages.push({ role: 'tool', tool_name: call.tool, content: 'Not run: the tool budget for this step is spent. Answer with the evidence you have.' });
        continue;
      }
      state.step += 1;
      ran += 1;
      agent(ctx, ctx.registry.describeCall({ name: call.name, arguments: call.rawArgs }, t));
      logToolCall(ctx, pkg, call.tool, call.args, 'model', state.step);
      const exec = await ctx.registry.execute({ name: call.name, arguments: call.rawArgs }, t, 'migration');
      logToolResult(ctx, pkg, exec);
      result(ctx, exec.hint || exec.status);
      state.messages.push({ role: 'tool', tool_name: exec.tool ?? call.tool, content: exec.content });
      state.seen.set(call.key, { count: 1, content: exec.content });
      state.executions.push(exec);
      if (exec.status === 'ok' || exec.status === 'error') state.used += 1;
      if (exec.tool === 'web_search' && typeof call.args.query === 'string') state.searched.add(call.args.query.trim().toLowerCase());
      if (exec.tool === 'web_search' && exec.ok) {
        const data = exec.result?.data as WebSearchResponse | undefined;
        if (data && typeof data.query === 'string') queries.push({ query: data.query, backend: data.backend, urls: (data.hits ?? []).map((h) => h.url), cached: Boolean(data.cached) });
      }
    }
    if (stop || state.used >= state.budget) return;
    state.messages.push({ role: 'user', content: briefContinuePrompt(state.budget - state.used, state.budget) });
  }
}

// items null when no valid brief
async function briefTurn(
  ctx: MigrationContext,
  t: ToolContext,
  pkg: string,
  from: string,
  to: string,
  sources: readonly MigrationSource[],
  facts: ProjectFacts,
  seenKeys: Map<string, string>,
  queries: MigrationQuery[],
): Promise<{ items: DraftItem[] | null; executions: ToolExecution[] }> {
  const digest = buildDigest(sources);
  const state: BriefLoopState = {
    messages: [
      { role: 'system', content: briefSystemPrompt(pkg, from, to, BRIEF_BUDGET) },
      { role: 'user', content: briefUserPrompt(pkg, from, to, facts, digest) },
    ],
    budget: BRIEF_BUDGET,
    used: 0,
    seen: new Map([...seenKeys.entries()].map(([k, content]) => [k, { count: 1, content }])),
    executions: [],
    step: 2,
    known: new Map(rankSources(sources).map((s, i) => [canonicalUrl(s.url), i + 1])),
    searched: new Set(queries.map((q) => q.query.trim().toLowerCase())),
    wasted: 0,
  };
  await runBriefLoop(ctx, t, pkg, state, queries);
  const exchange: ChatMessage[] = [{ role: 'user', content: briefSchemaPrompt() }];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const { response, error } = await chat(ctx, { messages: [...state.messages, ...exchange], format: BRIEF_SCHEMA, purpose: 'brief', maxTokens: BRIEF_MAX_TOKENS });
    if (!response) {
      result(ctx, `Model call failed: ${oneLine(errorMessage(error), 140)}`);
      continue;
    }
    const content = response.message.content ?? '';
    const items = parseBriefOutput(content);
    if (items !== null) return { items, executions: state.executions };
    result(ctx, 'The brief answer was not valid JSON for the schema');
    exchange.push({ role: 'assistant', content }, { role: 'user', content: 'That was not a valid JSON object for the brief schema. Reply with only the JSON object {"items": [...]}.' });
  }
  return { items: null, executions: state.executions };
}

function itemKey(item: DraftItem): string {
  const q = normalizeMapped(cleanQuote(item.evidenceQuote), 'loose').text;
  return q.length >= 12 ? q : normalizeMapped(item.change, 'loose').text;
}

const APPLIES_ORDER: Record<DraftItem['appliesToProject'], number> = { yes: 0, unsure: 1, no: 2 };

export async function researchMigration(action: Action, usage: UsageEvidence, ctx: MigrationContext): Promise<MigrationBrief> {
  const started = Date.now();
  const pkg = action.package;
  const from = action.fromVersion;
  const to = action.toVersion;
  const t = researchContext(ctx, pkg, from);
  const offline = Boolean(t.config.offline || ctx.config.offline);
  // caller prints the activity line
  if (offline) ctx.ui.infoLine('Offline: the research uses cached sources only');

  const { sources, queries } = await gatherSources(pkg, from, to, usage, ctx);
  const evidence = await callSiteEvidence(ctx, t, pkg, usage);
  const facts = await collectProjectFacts(pkg, usage, t, evidence.text);

  let drafts: DraftItem[] = [];
  let forced = false;
  let modelSources: MigrationSource[] = [];
  if (sources.length === 0) {
    agent(ctx, 'No release notes or migration documents were found: the brief stays empty');
  } else if (!ctx.provider) {
    forced = true;
  } else {
    const turn = await briefTurn(ctx, t, pkg, from, to, sources, facts, evidence.keys, queries);
    modelSources = await modelPageSources(turn.executions, t, sources.map((s) => s.url), from);
    if (turn.items === null) forced = true;
    else drafts = turn.items;
  }
  const allSources = [...sources, ...modelSources];

  const adjusted: string[] = [];
  const checked = repairNearQuotes(verifyEvidenceQuotes(drafts, allSources), allSources);
  if (checked.repaired > 0) {
    adjusted.push(`${checked.repaired} quote${checked.repaired === 1 ? '' : 's'} repaired to the exact source text (a few characters differed)`);
  }
  const railed = checked.items.map((d) => {
    const outcome = applyBriefRails(d, facts);
    if (outcome.rule && outcome.item.appliesToProject !== d.appliesToProject) {
      adjusted.push(`${oneLine(d.change, 60)}: ${d.appliesToProject} → ${outcome.item.appliesToProject} (${outcome.rule})`);
    }
    return { ...outcome.item, verified: d.verified };
  });
  const covered = coverageItems(
    railed.filter((d) => d.verified),
    allSources,
    to,
    facts,
  ).map((d) => applyBriefRails(d, facts).item);
  // coverage items beat unverified dupes
  const kept = railed.filter((d) => d.verified || !covered.some((c) => covers(d, c.evidenceQuote, pkg)));
  const seen = new Set<string>();
  const merged = [...kept.map(({ verified: _verified, ...d }) => d), ...covered].filter((d) => {
    const key = itemKey(d);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const items = verifyEvidenceQuotes(merged, allSources)
    .map((item, index) => ({ item, index }))
    .sort((a, b) => APPLIES_ORDER[a.item.appliesToProject] - APPLIES_ORDER[b.item.appliesToProject] || a.index - b.index)
    .map((x) => x.item)
    .slice(0, MAX_BRIEF_ITEMS);

  if (forced) agent(ctx, 'No valid brief from the model: items built from the release notes of the target version', 'forced');
  for (const note of adjusted.slice(0, 6)) agent(ctx, note, 'adjusted');
  if (covered.length > 0 && !forced) agent(ctx, `${covered.length} breaking change${covered.length === 1 ? '' : 's'} of the target release notes added (not in the model's brief)`, 'adjusted');

  const brief: MigrationBrief = {
    package: pkg,
    from,
    to,
    items,
    sources: allSources,
    queries,
    offline,
    model: ctx.provider?.model ?? 'none',
    createdAt: new Date().toISOString(),
  };
  const verified = items.filter((i) => i.verified).length;
  ctx.audit.log({ event: 'migration.brief', package: pkg, from, to, items: items.length, verified, sources: allSources.map((s) => s.url), offline });
  const applies = items.filter((i) => i.appliesToProject === 'yes').length;
  agent(
    ctx,
    `Migration brief ready: ${items.length} change${items.length === 1 ? '' : 's'}, ${applies} appl${applies === 1 ? 'ies' : 'y'} to this project, ${items.length - verified} unverified (${Math.round((Date.now() - started) / 100) / 10} s)`,
  );
  return brief;
}

function filesText(files: readonly string[]): string {
  return files.length > 0 ? files.join(', ') : 'no file named';
}

// when no valid edit survives
export function manualChecklist(brief: MigrationBrief): string[] {
  const relevant = brief.items.filter((i) => i.appliesToProject !== 'no');
  const lines: string[] = [];
  relevant.forEach((item, i) => {
    const what =
      item.oldApi && item.newApi
        ? `replace \`${oneLine(item.oldApi, 100)}\` with \`${oneLine(item.newApi, 100)}\``
        : item.newApi
          ? `use \`${oneLine(item.newApi, 100)}\``
          : 'review the code for this change';
    const lead = item.appliesToProject === 'unsure' ? 'Check whether this applies: ' : '';
    const flag = item.verified ? '' : ' [unverified: the quote was not found in the sources]';
    lines.push(`${i + 1}. ${lead}${oneLine(item.change, 200)} (${filesText(item.affectedFiles)}): ${what}. Source: ${item.evidenceUrl || 'none'}${flag}`);
  });
  if (lines.length === 0) {
    const urls = unique(brief.sources.map((s) => s.url)).slice(0, 4);
    lines.push(
      `No breaking change in the brief applies to this project's code; review the release notes of ${brief.package} ${brief.to} before bumping${urls.length > 0 ? `: ${urls.join(', ')}` : '.'}`,
    );
  }
  const skipped = brief.items.length - relevant.length;
  if (skipped > 0) lines.push(`${skipped} change${skipped === 1 ? '' : 's'} not applicable to this project (see the brief).`);
  return lines;
}

export function renderBrief(brief: MigrationBrief, ui: Ui): string {
  const c = ui.c;
  const dot = ui.glyphs.dot;
  const width = ui.width;
  const out: string[] = [];
  out.push(ui.formatRule(), '', ui.formatSectionHeader(`Migration brief ${dot} ${brief.package} ${brief.from} ${ui.glyphs.arrow} ${brief.to}`));
  const applies = brief.items.filter((i) => i.appliesToProject === 'yes').length;
  const unverified = brief.items.filter((i) => !i.verified).length;
  const summary = [
    `${brief.items.length} change${brief.items.length === 1 ? '' : 's'}`,
    `${applies} appl${applies === 1 ? 'ies' : 'y'}`,
    unverified > 0 ? `${unverified} unverified` : null,
    `${brief.sources.length} source${brief.sources.length === 1 ? '' : 's'}`,
    brief.offline ? 'offline: cached sources only' : null,
  ].filter((p): p is string => p !== null);
  out.push(c.dim(ui.text(summary.join(` ${dot} `))), '');
  if (brief.items.length === 0) out.push(c.dim(ui.text('  No breaking changes found in the sources.')));
  const wrap = (text: string, indent: number, style: (s: string) => string): string[] =>
    wrapText(ui.text(text), Math.max(20, width - indent)).map((line) => `${' '.repeat(indent)}${style(line)}`);
  for (const item of brief.items) {
    const label = `applies: ${item.appliesToProject}`;
    const colored = item.appliesToProject === 'yes' ? ui.green(label) : item.appliesToProject === 'unsure' ? c.yellow(label) : c.dim(label);
    const head = wrapText(ui.text(oneLine(item.change, 400)), Math.max(20, width - 2 - label.length - 3));
    out.push(`  ${colored} ${c.dim(dot)} ${head[0] ?? ''}`, ...head.slice(1).map((l) => `${' '.repeat(label.length + 5)}${l}`));
    if (item.evidenceQuote) out.push(...wrap(`"${oneLine(item.evidenceQuote, 400)}"${item.verified ? '' : ' (unverified: not found in the sources, no edit drafted)'}`, 4, (s) => c.dim(s)));
    if (item.oldApi || item.newApi) out.push(...wrap(`${oneLine(item.oldApi || '?', 120)} ${ui.glyphs.arrow} ${oneLine(item.newApi || '?', 120)}`, 4, (s) => c.dim(s)));
    const where = [item.affectedFiles.length > 0 ? item.affectedFiles.join(', ') : null, item.evidenceUrl || null].filter((p): p is string => p !== null);
    if (where.length > 0) out.push(...wrap(where.join(` ${dot} `), 4, (s) => c.dim(s)));
    out.push('');
  }
  if (brief.queries.length > 0) {
    const q = brief.queries.map((x) => `"${oneLine(x.query, 80)}" (${x.backend}${x.cached ? ', cached' : ''}, ${x.urls.length} result${x.urls.length === 1 ? '' : 's'})`);
    out.push(...wrap(`Searches: ${q.join('; ')}`, 2, (s) => c.dim(s)));
  }
  return out.join('\n');
}
