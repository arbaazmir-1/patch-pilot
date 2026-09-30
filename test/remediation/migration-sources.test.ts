import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  buildDigest,
  DIGEST_MAX_CHARS,
  evidenceKeywords,
  filterEvidenceText,
  gatherSources,
  MAX_RELEASE_SOURCES,
  MAX_SOURCES,
  MAX_TAG_LOOKUPS,
  MAX_WEB_FETCHES,
  migrationQueries,
  rankSources,
  SOURCE_TEXT_MAX,
  tidyLine,
} from '../../src/remediation/migration.ts';
import type { MigrationSource } from '../../src/types.ts';
import {
  DEFAULT_EXPORT_LINE,
  fixture,
  fixtureJson,
  installFetch,
  json,
  LIB_PATH_LINE,
  markedRoutes,
  markedUsage,
  MemoryCache,
  migrationCtx,
  resetWebState,
  RELEASE_V4_URL,
  SCRIPT_TAG_LINE,
  tempApp,
  testConfig,
  text,
  type FakeFetch,
} from './migration-helpers.ts';

const BLOG = 'https://blog.example.com/marked-4-upgrade';
const NOTES = 'https://notes.example.org/marked-4';
const NPM = 'https://www.npmjs.com/package/marked';
const BLOG_TEXT =
  "Marked 4 removed the default export, so require('marked') no longer returns a function. Calling it throws TypeError: marked is not a function.\n\nThe fix is one line: destructure the named export with const { marked } = require('marked'). The function itself still works, so marked(markdown) keeps rendering.";

let fake: FakeFetch | null = null;
let cleanup: (() => Promise<void>) | null = null;

beforeEach(() => resetWebState());
afterEach(async () => {
  fake?.restore();
  fake = null;
  await cleanup?.();
  cleanup = null;
});

async function app(): Promise<string> {
  const a = await tempApp();
  cleanup = a.cleanup;
  return a.dir;
}

function webRoutes(): Parameters<typeof markedRoutes>[0] {
  return {
    search: fixtureJson('search-results.json'),
    pages: {
      [BLOG]: { title: 'Upgrading to marked 4: the default export is gone', content: BLOG_TEXT },
      [NPM]: { title: 'marked - npm', content: 'A markdown parser built for speed.' },
      [NOTES]: { title: 'Another marked 4 article', content: 'marked 4 migration notes: the default export was removed.' },
    },
  };
}

function webFetchTargets(f: FakeFetch): string[] {
  return f.calls.filter((c) => c.url === 'https://ollama.com/api/web_fetch').map((c) => String((JSON.parse(c.body ?? '{}') as { url?: string }).url));
}

describe('gatherSources', () => {
  it('reads the deterministic sources first, then the web, within the caps', async () => {
    const dir = await app();
    const config = await testConfig(dir, { search: 'ollama', ollamaApiKey: 'test-key' });
    const ctx = migrationCtx(config);
    fake = installFetch(markedRoutes(webRoutes()));
    const { sources, queries } = await gatherSources('marked', '0.3.6', '4.0.10', markedUsage(), ctx);

    const kinds = sources.map((s) => s.kind);
    assert.equal(sources[0]?.url, RELEASE_V4_URL, 'the target major first');
    assert.equal(sources[0]?.version, '4.0.0');
    const releases = sources.filter((s) => s.kind === 'release-notes');
    assert.deepEqual(
      releases.map((s) => s.version),
      ['4.0.0', '3.0.0', '2.0.0', '1.0.0', '0.8.0', '0.7.0'],
      'every breaking line crossed, majors first, newest first',
    );
    assert.ok(releases.length <= MAX_RELEASE_SOURCES);
    const readme = kinds.indexOf('readme');
    const web = kinds.indexOf('web');
    assert.ok(readme > kinds.lastIndexOf('release-notes'), 'docs after the release notes');
    assert.ok(web > readme, 'web pages last');
    assert.equal(sources[readme]?.url, 'https://github.com/markedjs/marked/blob/v4.0.10/README.md');
    assert.ok(sources.length <= MAX_SOURCES);
    for (const s of sources) assert.ok(s.text.length <= SOURCE_TEXT_MAX, `${s.url} is capped`);

    // repo first, max two fetches
    assert.equal(queries.length, 1);
    assert.equal(queries[0]?.query, 'marked 4 migration breaking changes default export require');
    assert.equal(queries[0]?.backend, 'ollama');
    const fetched = webFetchTargets(fake);
    assert.ok(!fetched.includes(RELEASE_V4_URL), 'a result already gathered is not fetched again');
    assert.ok(fetched.includes(NPM) && fetched.includes(BLOG));
    assert.ok(!fetched.includes(NOTES), `at most ${MAX_WEB_FETCHES} result pages`);
    assert.ok(fetched.indexOf(NPM) < fetched.indexOf(BLOG), 'own domain (npm page) before the blog');
    assert.equal(sources.some((s) => s.url === NPM), false, 'a near-empty page is not a source');
    const blog = sources.find((s) => s.url === BLOG);
    assert.equal(blog?.kind, 'web');
    assert.match(blog?.text ?? '', /removed the default export/);

    const searches = ctx.audit.events('migration.search');
    assert.equal(searches.length, 1);
    assert.equal(searches[0]?.query, queries[0]?.query);
    assert.deepEqual(searches[0]?.urls, queries[0]?.urls);
    assert.match(ctx.out(), /Checking the changelog of marked 0\.3\.6 -> 4\.0\.10/);
  });

  it('with --search off makes no web request and records the query as backend none', async () => {
    const dir = await app();
    const config = await testConfig(dir, { search: 'off' });
    const ctx = migrationCtx(config);
    fake = installFetch(markedRoutes());
    const { sources, queries } = await gatherSources('marked', '0.3.6', '4.0.10', markedUsage(), ctx);
    assert.equal(fake.calls.some((c) => c.url.startsWith('https://ollama.com/')), false);
    assert.equal(queries.length, 1);
    assert.equal(queries[0]?.backend, 'none');
    assert.deepEqual(queries[0]?.urls, []);
    assert.equal(sources.some((s) => s.kind === 'web'), false);
    assert.ok(sources.some((s) => s.url === RELEASE_V4_URL));
    // no ollama key: raw readme fetch
    assert.ok(fake.urls().includes('https://raw.githubusercontent.com/markedjs/marked/v4.0.10/README.md'));
  });

  it('offline serves cached sources only, with no network request', async () => {
    const dir = await app();
    const cache = new MemoryCache();
    const online = await testConfig(dir, { search: 'ollama', ollamaApiKey: 'test-key' });
    fake = installFetch(markedRoutes(webRoutes()));
    const first = await gatherSources('marked', '0.3.6', '4.0.10', markedUsage(), migrationCtx(online, { rules: [] }, cache));
    fake.restore();
    resetWebState();

    fake = installFetch([]);
    const offline = await testConfig(dir, { search: 'ollama', ollamaApiKey: 'test-key', offline: true });
    const second = await gatherSources('marked', '0.3.6', '4.0.10', markedUsage(), migrationCtx(offline, { rules: [] }, cache));
    assert.deepEqual(fake.calls, [], 'nothing leaves the machine');
    assert.deepEqual(
      second.sources.map((s) => s.url),
      first.sources.map((s) => s.url),
    );
    assert.ok(second.sources.every((s) => s.cached), 'every source comes from the cache');
    assert.equal(second.queries[0]?.cached, true);
  });

  it('offline with an empty cache finds nothing and does not fail', async () => {
    const dir = await app();
    fake = installFetch([]);
    const config = await testConfig(dir, { offline: true });
    const { sources, queries } = await gatherSources('marked', '0.3.6', '4.0.10', markedUsage(), migrationCtx(config));
    assert.deepEqual(sources, []);
    assert.equal(queries[0]?.backend, 'none');
    assert.deepEqual(fake.calls, []);
  });

  it('without a release list: release notes by tag (capped) and the jsDelivr files of the published version', async () => {
    const dir = await app();
    const config = await testConfig(dir, { search: 'off' });
    const release = fixtureJson<Record<string, unknown>>('release-v4.0.0.json');
    const listing = { type: 'npm', name: 'marked', version: '4.0.10', files: [{ name: '/README.md', size: 600 }, { name: '/lib/marked.cjs', size: 90000 }, { name: '/LICENSE.md', size: 2900 }] };
    fake = installFetch([
      ['https://api.github.com/repos/markedjs/marked/releases/tags/v4.0.0', () => json(release)],
      [(url) => url.startsWith('https://api.github.com/repos/markedjs/marked/releases/tags/'), () => json({ message: 'Not Found' }, 404)],
      ['https://data.jsdelivr.com/v1/packages/npm/marked@4.0.10', () => json(listing)],
      ['https://cdn.jsdelivr.net/npm/marked@4.0.10/README.md', () => text(fixture('README.md'))],
      ...markedRoutes({ releases: false, rawFiles: {} }),
    ]);
    const { sources } = await gatherSources('marked', '0.3.6', '4.0.10', markedUsage(), migrationCtx(config));
    const v4 = sources.find((s) => s.kind === 'release-notes');
    assert.equal(v4?.version, '4.0.0');
    assert.match(v4?.text ?? '', /Default export removed/);
    const readme = sources.find((s) => s.kind === 'readme');
    assert.equal(readme?.url, 'https://cdn.jsdelivr.net/npm/marked@4.0.10/README.md');
    const tagCalls = fake.urls().filter((u) => u.includes('/releases/tags/'));
    const versions = new Set(tagCalls.map((u) => decodeURIComponent(u.split('/tags/')[1] ?? '').replace(/^v|^marked@/, '')));
    assert.ok(versions.size <= MAX_TAG_LOOKUPS, `at most ${MAX_TAG_LOOKUPS} versions looked up by tag`);
    assert.equal(tagCalls.some((u) => u.endsWith('/0.4.0')), false, 'no per-tag lookups for 0.x minors');
  });
});

describe('keyword filtering', () => {
  const keywords = evidenceKeywords('marked', markedUsage());

  it('keeps the BREAKING section verbatim and drops commit links and unrelated lines', () => {
    const body = fixtureJson<{ body: string }>('release-v4.0.0.json').body;
    const kept = filterEvidenceText(body, keywords, 'release-notes');
    for (const line of [DEFAULT_EXPORT_LINE, LIB_PATH_LINE, SCRIPT_TAG_LINE]) assert.ok(kept.includes(line), `verbatim: ${line}`);
    assert.match(kept, /### BREAKING CHANGES/);
    assert.match(kept, /^\* Convert to ESM$/m, 'ESM line kept, its commit and issue links dropped');
    assert.doesNotMatch(kept, /commit\/|issues\/2227/);
  });

  it('keeps usage examples and version lines of a README, not the marketing', () => {
    const kept = filterEvidenceText(fixture('README.md'), keywords, 'readme');
    assert.match(kept, /const \{ marked \} = require\('marked'\);/);
    assert.match(kept, /Node\.js versions are supported/);
    assert.doesNotMatch(kept, /built for speed|npm install -g|document\.getElementById|License/);
  });

  it('adds the members the project uses to the keywords', () => {
    const withParse = evidenceKeywords('marked', { ...markedUsage(), membersUsed: { parse: 2 } });
    assert.match(filterEvidenceText(fixture('README.md'), withParse, 'readme'), /marked\.parse\('# Marked in Node\.js'\)/);
    assert.doesNotMatch(filterEvidenceText(fixture('README.md'), keywords, 'readme'), /marked\.parse/);
  });

  it('keeps a migration guide whole and tidies link targets', () => {
    const guide = '# Migrating\n\nSome intro.\n\n```js\nconst x = 1;\n```\n';
    assert.equal(filterEvidenceText(guide, keywords, 'migration-guide'), '# Migrating\nSome intro.\n```js\nconst x = 1;\n```');
    assert.equal(tidyLine('* Fix lists ([#2112](https://github.com/o/r/issues/2112)) ([eb33d3b](https://github.com/o/r/commit/eb33d3b))'), '* Fix lists');
    assert.equal(tidyLine('See the [guide](https://marked.js.org/using_pro) now'), 'See the guide (https://marked.js.org/using_pro) now');
    assert.equal(tidyLine('# [4.0.0](https://github.com/markedjs/marked/compare/v3.0.8...v4.0.0) (2021-11-02)'), '# 4.0.0 (2021-11-02)');
  });

  it('caps a source at SOURCE_TEXT_MAX on a line break', () => {
    const long = Array.from({ length: 400 }, (_, i) => `- removed option number ${i}`).join('\n');
    const kept = filterEvidenceText(long, keywords, 'changelog');
    assert.ok(kept.length <= SOURCE_TEXT_MAX);
    assert.match(kept, /removed option number \d+$/);
  });

  it('builds the queries from the package, the target major and the import style', () => {
    assert.deepEqual(migrationQueries('marked', '0.3.6', '4.0.10', markedUsage()), [
      'marked 4 migration breaking changes default export require',
      'marked upgrade guide 0.3 to 4',
    ]);
    const esm = { ...markedUsage(), files: [{ path: 'a.mjs', line: 1, statement: "import { merge } from 'lodash'", binding: null, kind: 'esm-named' as const, named: { merge: 'merge' }, scope: 'source' as const }], membersUsed: { merge: 3 } };
    assert.equal(migrationQueries('lodash', '3.10.1', '4.17.21', esm)[0], 'lodash 4 migration breaking changes import merge');
  });
});

describe('buildDigest', () => {
  const src = (partial: Partial<MigrationSource> & { url: string; kind: MigrationSource['kind'] }): MigrationSource => ({
    title: null,
    version: null,
    cached: false,
    fetchedAt: '2026-09-24T00:00:00.000Z',
    text: `text of ${partial.url}`,
    ...partial,
  });

  it('puts the target release notes first, then the migration guide, older notes, README, web, changelog lines', () => {
    const sources = [
      src({ url: 'https://x/readme', kind: 'readme' }),
      src({ url: 'https://x/lines', kind: 'changelog' }),
      src({ url: 'https://x/v2', kind: 'release-notes', version: '2.0.0' }),
      src({ url: 'https://x/web', kind: 'web' }),
      src({ url: 'https://x/v4', kind: 'release-notes', version: '4.0.0' }),
      src({ url: 'https://x/guide', kind: 'migration-guide' }),
      src({ url: 'https://x/v3', kind: 'release-notes', version: '3.0.0' }),
    ];
    assert.deepEqual(
      rankSources(sources).map((s) => s.url.slice('https://x/'.length)),
      ['v4', 'guide', 'v3', 'v2', 'readme', 'web', 'lines'],
    );
    const digest = buildDigest(sources);
    assert.match(digest, /^\[1\] release notes 4\.0\.0\nURL: https:\/\/x\/v4\ntext of https:\/\/x\/v4/);
    assert.ok(digest.indexOf('https://x/guide') < digest.indexOf('https://x/readme'));
  });

  it('stays under the cap (about 2.5k tokens by default) and cuts the least relevant sources', () => {
    const big = (url: string, version: string): MigrationSource =>
      src({ url, kind: 'release-notes', version, text: Array.from({ length: 80 }, (_, i) => `* removed thing ${i} in ${version}`).join('\n') });
    const sources = [big('https://x/v1', '1.0.0'), big('https://x/v4', '4.0.0'), big('https://x/v3', '3.0.0'), big('https://x/v2', '2.0.0')];
    const digest = buildDigest(sources);
    assert.ok(digest.length <= DIGEST_MAX_CHARS, `${digest.length} chars`);
    assert.ok(digest.indexOf('https://x/v4') < digest.indexOf('https://x/v3'));
    const small = buildDigest(sources, 900);
    assert.ok(small.length <= 900);
    assert.match(small, /https:\/\/x\/v4/);
    assert.doesNotMatch(small, /https:\/\/x\/v1/);
  });

  it('skips sources without evidence text', () => {
    assert.equal(buildDigest([src({ url: 'https://x/empty', kind: 'web', text: '  ' })]), '');
  });
});
