import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { effectiveSearchBackend } from '../../src/config.ts';
import { clearWebMemoryCache } from '../../src/investigation/tools/getChangelog.ts';
import { BRAVE_SEARCH_URL, braveSearch, handleWebSearch, resolveSearchBackend, searchWeb } from '../../src/investigation/tools/webSearch.ts';
import { fixture, fixtureJson, installFetch, json, MemoryAuditSink, MemoryCache, testCtx, text, type FakeFetch, type RouteHandler } from '../web/helpers.ts';

const QUERY = 'marked 4.0.0 breaking changes default export';
const TOKEN = 'BSAtestSubscriptionToken0123456789';
const REGISTRY = 'https://registry.npmjs.org';

let fake: FakeFetch | null = null;
beforeEach(() => clearWebMemoryCache());
afterEach(() => {
  fake?.restore();
  fake = null;
});

// saved docs-backend responses for marked
function docsRoutes(): [string | RegExp | ((url: string) => boolean), RouteHandler][] {
  const manifest = { name: 'marked', version: '4.0.10', repository: { type: 'git', url: 'git://github.com/markedjs/marked.git' }, homepage: 'https://marked.js.org' };
  return [
    [`${REGISTRY}/marked/4.0.10`, () => json(manifest)],
    [`${REGISTRY}/marked/0.3.6`, () => json({ ...manifest, version: '0.3.6' })],
    [`${REGISTRY}/marked`, () => json({ name: 'marked', 'dist-tags': { latest: '4.0.10' }, versions: { '0.3.6': {}, '4.0.10': {} } })],
    [(url) => url.startsWith('https://api.github.com/repos/markedjs/marked/releases?'), (call) => json(new URL(call.url).searchParams.get('page') === '1' ? fixtureJson('marked-releases.json') : [])],
    ['https://data.jsdelivr.com/v1/packages/npm/marked@4.0.10', () => json(fixtureJson('jsdelivr-marked-4.0.10.json'))],
    ['https://cdn.jsdelivr.net/npm/marked@4.0.10/README.md', () => text(fixture('marked-4.0.10-README.md'), 'text/markdown; charset=utf-8')],
    [(url) => url.startsWith('https://api.github.com/search/issues?'), () => json(fixtureJson('github-search-issues.json'))],
  ];
}

// includes fields we ignore
function braveResponse(): unknown {
  return {
    type: 'search',
    query: { original: QUERY },
    web: {
      type: 'search',
      results: [
        {
          title: 'Stack Overflow: <strong>marked</strong> is not a function',
          url: 'https://stackoverflow.com/questions/70000000',
          description: 'After upgrading, <strong>marked</strong> is not a function: in v4 the <strong>default export</strong> was removed &amp; you need <code>const { marked } = require(&#x27;marked&#x27;)</code>.',
          age: '2 years ago',
          profile: { name: 'Stack Overflow' },
        },
        {
          title: 'Release v4.0.0 &middot; markedjs/marked',
          url: 'https://github.com/markedjs/marked/releases/tag/v4.0.0',
          description: '<strong>BREAKING CHANGES</strong>: <strong>Default export</strong> removed. Use import { marked } from &quot;marked&quot;.',
          extra_snippets: ['Script tag users must call marked.parse(...).'],
        },
        { title: 'not a web page', url: 'ftp://example.com/marked', description: 'x' },
        { title: 'Duplicate', url: 'https://stackoverflow.com/questions/70000000', description: 'again' },
        { title: '', url: 'https://marked.js.org/using_advanced', description: 'marked.parse(markdownString [,options])' },
      ],
    },
    mixed: { main: [] },
  };
}

describe('Brave backend', () => {
  it('sends GET with the subscription token and maps web.results to hits', async () => {
    fake = installFetch([[BRAVE_SEARCH_URL, () => json(braveResponse())]]);
    const ctx = await testCtx({ config: { search: 'brave', braveApiKey: TOKEN } });
    const hits = await braveSearch(QUERY, 5, ctx);
    const call = fake.callsTo(BRAVE_SEARCH_URL)[0];
    assert.ok(call);
    assert.equal(call.method, 'GET');
    const url = new URL(call.url);
    assert.equal(`${url.origin}${url.pathname}`, BRAVE_SEARCH_URL);
    assert.equal(url.searchParams.get('q'), QUERY);
    assert.equal(url.searchParams.get('count'), '5');
    assert.equal(call.headers.accept, 'application/json');
    assert.equal(call.headers['x-subscription-token'], TOKEN);
    assert.ok(!call.url.includes(TOKEN), 'the token travels in a header only');
    assert.deepEqual(
      hits.map((h) => [h.title, h.url, h.backend]),
      [
        ['Stack Overflow: marked is not a function', 'https://stackoverflow.com/questions/70000000', 'brave'],
        ['Release v4.0.0 · markedjs/marked', 'https://github.com/markedjs/marked/releases/tag/v4.0.0', 'brave'],
        ['https://marked.js.org/using_advanced', 'https://marked.js.org/using_advanced', 'brave'],
      ],
    );
    assert.match(hits[0]?.snippet ?? '', /the default export was removed & you need const \{ marked \} = require\('marked'\)/);
    assert.match(hits[1]?.snippet ?? '', /Default export removed\. Use import \{ marked \} from "marked"\. Script tag users must call marked\.parse/);
    assert.ok(hits.every((h) => !/<\/?strong>/.test(h.title + h.snippet) && h.snippet.length <= 300));
  });

  it('caps count at 10 and the hits at the requested number', async () => {
    fake = installFetch([[BRAVE_SEARCH_URL, () => json(braveResponse())]]);
    const ctx = await testCtx({ config: { search: 'brave', braveApiKey: TOKEN } });
    assert.equal((await braveSearch(QUERY, 1, ctx)).length, 1);
    await braveSearch(QUERY, 50, ctx);
    assert.deepEqual(fake.calls.map((c) => new URL(c.url).searchParams.get('count')), ['1', '10']);
    fake.restore();
    fake = installFetch([[BRAVE_SEARCH_URL, () => json({ type: 'search' })]]);
    assert.deepEqual(await braveSearch(QUERY, 5, ctx), [], 'no web section, no hits');
  });

  it('is used through searchWeb and the tool when --search brave has a key, ranked and cached', async () => {
    fake = installFetch([[BRAVE_SEARCH_URL, () => json(braveResponse())], ...docsRoutes()]);
    const audit = new MemoryAuditSink();
    const cache = new MemoryCache();
    const ctx = await testCtx({ cache, audit, config: { search: 'brave', braveApiKey: TOKEN }, focus: { package: 'marked', version: '0.3.6' } });
    assert.equal(resolveSearchBackend(ctx), 'brave');
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'brave');
    assert.equal(res.note, undefined);
    assert.deepEqual(
      res.hits.map((h) => h.url),
      ['https://github.com/markedjs/marked/releases/tag/v4.0.0', 'https://marked.js.org/using_advanced', 'https://stackoverflow.com/questions/70000000'],
      "the package's own domains first",
    );
    assert.equal(fake.callsTo('https://api.github.com/search').length, 0, 'no docs search when Brave answers');
    assert.deepEqual(audit.events, [{ event: 'migration.search', package: 'marked', backend: 'brave', query: QUERY, urls: res.hits.map((h) => h.url), cached: false }]);

    const again = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(again.cached, true);
    assert.equal(fake.callsTo(BRAVE_SEARCH_URL).length, 1, 'served from the search cache');

    const tool = await handleWebSearch({ query: 'marked v4 migration' }, ctx);
    assert.equal(tool.ok, true);
    assert.match(tool.hint, /via Brave search/);
    const everything = JSON.stringify({ res, again, tool, audit: audit.events, cache: [...cache.entries.values()] });
    assert.ok(!everything.includes(TOKEN), 'the token appears in no result, cache entry or audit event');
  });

  it('falls back to the docs on an HTTP error, without the token in the note', async () => {
    const echo = { type: 'ErrorResponse', error: { status: 422, code: 'SUBSCRIPTION_TOKEN_INVALID', detail: `The provided subscription token ${TOKEN} is invalid.` } };
    fake = installFetch([[BRAVE_SEARCH_URL, () => json(echo, { status: 422 })], ...docsRoutes()]);
    const audit = new MemoryAuditSink();
    const ctx = await testCtx({ audit, config: { search: 'brave', braveApiKey: TOKEN }, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.match(res.note ?? '', /Brave search failed: HTTP 422 from Brave Search: The provided subscription token \*\*\*\* is invalid\.; used the package docs instead/);
    assert.equal(res.hits[0]?.url, 'https://github.com/markedjs/marked/releases/tag/v4.0.0');
    assert.ok(!JSON.stringify({ res, audit: audit.events }).includes(TOKEN));
    assert.equal(fake.callsTo(BRAVE_SEARCH_URL).length, 1, '422 is not retried');
  });

  it('says to check the key on 401 and survives a network failure', async () => {
    fake = installFetch([[BRAVE_SEARCH_URL, () => new Response('Unauthorized', { status: 401 })], ...docsRoutes()]);
    const ctx = await testCtx({ config: { search: 'brave', braveApiKey: TOKEN }, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.match(res.note ?? '', /Brave search failed: HTTP 401 from Brave Search \(check BRAVE_SEARCH_API_KEY\)/);
    fake.restore();
    clearWebMemoryCache();
    fake = installFetch([
      [
        BRAVE_SEARCH_URL,
        () => {
          throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
        },
      ],
      ...docsRoutes(),
    ]);
    const down = await searchWeb(QUERY, await testCtx({ config: { search: 'brave', braveApiKey: TOKEN }, focus: { package: 'marked', version: '0.3.6' } }), { toVersion: '4.0.10' });
    assert.equal(down.backend, 'docs');
    assert.match(down.note ?? '', /Brave search failed: Connection failed \(ECONNREFUSED\)/);
    assert.ok(!(down.note ?? '').includes(TOKEN));
  });

  it('needs --search brave: auto never picks it, and a missing key uses the docs', async () => {
    fake = installFetch([[BRAVE_SEARCH_URL, () => json(braveResponse())], ...docsRoutes()]);
    const auto = await testCtx({ config: { search: 'auto', braveApiKey: TOKEN }, focus: { package: 'marked', version: '0.3.6' } });
    assert.equal(resolveSearchBackend(auto), 'docs');
    assert.equal(effectiveSearchBackend({ search: 'auto', ollamaApiKey: null, braveApiKey: TOKEN, offline: false }), 'docs');
    assert.equal(effectiveSearchBackend({ search: 'auto', ollamaApiKey: 'k', braveApiKey: TOKEN, offline: false }), 'ollama');
    const res = await searchWeb(QUERY, auto, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.equal(fake.callsTo(BRAVE_SEARCH_URL).length, 0);
    const noKey = await searchWeb(QUERY, await testCtx({ config: { search: 'brave' }, focus: { package: 'marked', version: '0.3.6' } }), { toVersion: '4.0.10' });
    assert.equal(noKey.backend, 'docs');
    assert.match(noKey.note ?? '', /Brave search is not configured/);
    assert.equal(fake.callsTo(BRAVE_SEARCH_URL).length, 0);
    await assert.rejects(braveSearch(QUERY, 5, await testCtx({ config: { search: 'brave' } })), /needs BRAVE_SEARCH_API_KEY/);
  });
});
