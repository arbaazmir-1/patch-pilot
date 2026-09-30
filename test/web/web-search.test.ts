import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { clearWebMemoryCache } from '../../src/investigation/tools/getChangelog.ts';
import {
  handleWebSearch,
  isOwnDomain,
  issueSearchTerms,
  majorBoundaries,
  rankOwnDomainsFirst,
  resolveSearchBackend,
  searchWeb,
  versionsInQuery,
} from '../../src/investigation/tools/webSearch.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import type { CaseFile } from '../../src/types.ts';
import { fixture, fixtureJson, installFetch, json, MemoryAuditSink, MemoryCache, testCtx, text, type FakeFetch, type RouteHandler } from './helpers.ts';

const QUERY = 'marked 4.0.0 breaking changes default export';
const REGISTRY = 'https://registry.npmjs.org';

let fake: FakeFetch | null = null;
beforeEach(() => clearWebMemoryCache());
afterEach(() => {
  fake?.restore();
  fake = null;
});

function markedDocsRoutes(): [string | RegExp | ((url: string) => boolean), RouteHandler][] {
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

describe('backend resolution', () => {
  it('follows config.search: auto picks ollama with a key, off and offline disable search', async () => {
    const pick = async (search: 'auto' | 'ollama' | 'docs' | 'brave' | 'off', extra: Record<string, unknown> = {}) =>
      resolveSearchBackend(await testCtx({ config: { search, ...extra } }));
    assert.equal(await pick('auto'), 'docs');
    assert.equal(await pick('auto', { ollamaApiKey: 'k' }), 'ollama');
    assert.equal(await pick('docs', { ollamaApiKey: 'k' }), 'docs');
    assert.equal(await pick('ollama'), 'ollama');
    assert.equal(await pick('brave'), 'brave');
    assert.equal(await pick('off', { ollamaApiKey: 'k' }), null);
    assert.equal(await pick('auto', { ollamaApiKey: 'k', offline: true }), null);
  });
});

describe('query parsing and boundaries', () => {
  it('finds versions named in a query', () => {
    assert.deepEqual(versionsInQuery('marked 4.0.0 breaking changes'), ['4.0.0']);
    assert.deepEqual(versionsInQuery('upgrade to v5 of express', 'express'), ['5.0.0']);
    assert.deepEqual(versionsInQuery('marked 4 migration', 'marked'), ['4.0.0']);
    assert.deepEqual(versionsInQuery('lodash 4.x changes'), ['4.0.0']);
    assert.deepEqual(versionsInQuery('top 10 changes'), []);
  });

  it('lists the first release of every breaking line crossed', () => {
    const available = ['0.3.6', '0.3.9', '0.4.0', '0.5.0', '0.5.2', '0.6.0', '0.7.0', '0.8.0', '0.8.2', '1.0.0', '1.2.9', '2.0.0', '2.1.3', '3.0.0', '4.0.0', '4.0.10', '4.1.0'];
    assert.deepEqual(majorBoundaries('0.3.6', '4.0.10', available), ['0.4.0', '0.5.0', '0.6.0', '0.7.0', '0.8.0', '1.0.0', '2.0.0', '3.0.0', '4.0.0']);
    assert.deepEqual(majorBoundaries('0.3.6', '4.0.10'), ['0.4.0', '1.0.0', '2.0.0', '3.0.0', '4.0.0']);
    assert.deepEqual(majorBoundaries('4.17.1', '5.0.0'), ['5.0.0']);
    assert.deepEqual(majorBoundaries('4.17.1', '4.17.21'), []);
    assert.deepEqual(majorBoundaries(null, '4.0.0'), []);
  });

  it('keeps issue search terms narrow', () => {
    assert.deepEqual(issueSearchTerms(QUERY, 'marked'), ['default', 'export']);
    assert.deepEqual(issueSearchTerms('marked 4 migration breaking changes', 'marked'), []);
    assert.deepEqual(issueSearchTerms('@babel/core upgrade config loading error', '@babel/core'), ['config', 'loading', 'error']);
  });

  it('knows the package domains', () => {
    const meta = { repository: { url: 'https://github.com/markedjs/marked', host: 'github' as const, owner: 'markedjs', repo: 'marked', directory: null }, homepage: 'https://marked.js.org' };
    assert.equal(isOwnDomain('https://github.com/markedjs/marked/releases/tag/v4.0.0', 'marked', meta), true);
    assert.equal(isOwnDomain('https://marked.js.org/using_advanced', 'marked', meta), true);
    assert.equal(isOwnDomain('https://markedjs.github.io/marked/', 'marked', meta), true);
    assert.equal(isOwnDomain('https://www.npmjs.com/package/marked', 'marked', meta), true);
    assert.equal(isOwnDomain('https://github.com/other/marked-fork', 'marked', meta), false);
    assert.equal(isOwnDomain('https://stackoverflow.com/questions/1', 'marked', meta), false);
    const ranked = rankOwnDomainsFirst([{ url: 'https://stackoverflow.com/q/1' }, { url: 'https://marked.js.org/' }, { url: 'https://blog.example.com/' }], 'marked', meta);
    assert.deepEqual(ranked.map((h) => h.url), ['https://marked.js.org/', 'https://stackoverflow.com/q/1', 'https://blog.example.com/']);
  });
});

describe('docs backend (keyless)', () => {
  it('ranks release notes of the crossed majors, docs files and issues from saved responses', async () => {
    fake = installFetch(markedDocsRoutes());
    const audit = new MemoryAuditSink();
    const cache = new MemoryCache();
    const ctx = await testCtx({ cache, audit, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.equal(res.cached, false);
    assert.equal(res.note, undefined);
    assert.equal(res.hits.length, 5);
    assert.equal(res.hits[0]?.url, 'https://github.com/markedjs/marked/releases/tag/v4.0.0');
    assert.match(res.hits[0]?.snippet ?? '', /Default export removed/);
    assert.ok(res.hits.every((h) => h.backend === 'docs' && h.snippet.length <= 300));
    const kinds = res.hits.map((h) => (/\/releases\/tag\//.test(h.url) ? 'release' : h.url.includes('cdn.jsdelivr.net') ? 'doc' : 'issue'));
    assert.ok(kinds.filter((k) => k === 'release').length >= 2, `release notes of other boundaries too: ${kinds.join(',')}`);
    assert.ok(kinds.includes('doc'), 'the target README makes the top five');
    assert.ok(kinds.includes('issue'));
    assert.equal(res.hits.some((h) => h.snippet.includes('](http')), false, 'snippets carry no markdown link targets');
    const search = fake.callsTo('https://api.github.com/search/issues');
    assert.equal(search.length, 1, 'one issue search per query');
    assert.equal(new URL(search[0]?.url ?? '').searchParams.get('q'), 'repo:markedjs/marked default export -author:app/dependabot');
    assert.equal(fake.callsTo('https://cdn.jsdelivr.net/npm/marked@4.0.10/README.md').length, 1);
    assert.equal(fake.callsTo('https://api.github.com/repos/markedjs/marked/releases/tags/').length, 0, 'the release list covered every boundary');
    assert.deepEqual(audit.events, [
      { event: 'migration.search', package: 'marked', backend: 'docs', query: QUERY, urls: res.hits.map((h) => h.url), cached: false },
    ]);

    const all = await searchWeb(QUERY, ctx, { toVersion: '4.0.10', maxResults: 10 });
    assert.ok(all.hits.some((h) => h.url === 'https://cdn.jsdelivr.net/npm/marked@4.0.10/README.md'));
    assert.ok(all.hits.some((h) => h.url.startsWith('https://github.com/markedjs/marked/issues/') || h.url.startsWith('https://github.com/markedjs/marked/pull/')));

    const calls = fake.calls.length;
    const again = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(again.cached, true);
    assert.deepEqual(again.hits, res.hits);
    assert.equal(fake.calls.length, calls, 'served from the search cache');
    assert.equal(audit.events.at(-1)?.event, 'migration.search');
    assert.equal((audit.events.at(-1) as { cached: boolean }).cached, true);
  });

  it('takes the target version from the case file when the model only sends a query', async () => {
    fake = installFetch(markedDocsRoutes());
    const ctx = await testCtx({ focus: { package: 'marked', version: '0.3.6' } });
    ctx.caseFile = {
      packages: [{ name: 'marked', version: '0.3.6' }],
      vulnerabilities: [
        { package: 'marked', installedVersion: '0.3.6', recommendedFix: { version: '0.3.9', majorBump: false } },
        { package: 'marked', installedVersion: '0.3.6', recommendedFix: { version: '4.0.10', majorBump: true } },
      ],
    } as unknown as CaseFile;
    const result = await handleWebSearch({ query: QUERY }, ctx);
    assert.equal(result.ok, true);
    assert.match(result.hint, /^5 results via package docs/);
    assert.match(result.text ?? '', /^1\. marked v4\.0\.0 release notes\n {3}https:\/\/github\.com\/markedjs\/marked\/releases\/tag\/v4\.0\.0\n {3}.*Default export removed/);
    assert.equal(fake.callsTo('https://data.jsdelivr.com/v1/packages/npm/marked@4.0.10').length, 1);
    const exec = await createToolRegistry().execute({ name: 'web_search', arguments: { q: QUERY } }, ctx, 'migration');
    assert.equal(exec.status, 'ok');
    assert.equal(exec.content.includes('[output truncated'), false, `${exec.content.length} chars`);
    assert.equal(exec.content.split('\n').filter((l) => /^\d\. /.test(l)).length, 5, 'all five results fit');
  });

  it('works without a package only with a note', async () => {
    fake = installFetch([]);
    const res = await searchWeb('some library breaking changes', await testCtx());
    assert.equal(res.backend, 'docs');
    assert.deepEqual(res.hits, []);
    assert.match(res.note ?? '', /needs a package/);
    assert.equal(fake.calls.length, 0);
  });

  it('degrades when GitHub is rate limited and does not cache the partial answer', async () => {
    const routes = markedDocsRoutes().filter(([m]) => !(typeof m === 'function'));
    fake = installFetch([[(url) => url.startsWith('https://api.github.com/'), () => json({ message: 'API rate limit exceeded' }, { status: 403 })], ...routes]);
    const cache = new MemoryCache();
    const ctx = await testCtx({ cache, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.equal(res.hits[0]?.url, 'https://cdn.jsdelivr.net/npm/marked@4.0.10/README.md');
    assert.match(res.note ?? '', /rate limit/);
    const again = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(again.cached, true, 'hits are cached with the note');
  });
});

describe('ollama backend', () => {
  const longContent = `${'Navigation Home Docs Blog '.repeat(200)} In v4 the default export was removed; use const { marked } = require('marked'). ${'Footer text '.repeat(2500)}`;

  it('maps results, truncates content to 300-character snippets and ranks the package domains first', async () => {
    fake = installFetch([
      [
        'https://ollama.com/api/web_search',
        () =>
          json({
            results: [
              { title: 'Stack Overflow: marked is not a function', url: 'https://stackoverflow.com/questions/70000000', content: longContent },
              { title: 'Using Advanced - Marked Documentation', url: 'https://marked.js.org/using_advanced', content: 'marked.parse(markdownString [,options]) '.repeat(50) },
              { title: '', url: 'https://github.com/markedjs/marked/releases/tag/v4.0.0', content: '### BREAKING CHANGES\n* Default export removed.' },
              { title: 'not a web page', url: 'ftp://example.com/x', content: 'x' },
            ],
          }),
      ],
      ...markedDocsRoutes(),
    ]);
    const audit = new MemoryAuditSink();
    const ctx = await testCtx({ config: { ollamaApiKey: 'ollama-key' }, audit, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10', maxResults: 25 });
    assert.equal(res.backend, 'ollama');
    const call = fake.callsTo('https://ollama.com/api/web_search')[0];
    assert.equal(call?.headers.authorization, 'Bearer ollama-key');
    assert.deepEqual(JSON.parse(call?.body ?? '{}'), { query: QUERY, max_results: 10 });
    assert.deepEqual(
      res.hits.map((h) => h.url),
      ['https://marked.js.org/using_advanced', 'https://github.com/markedjs/marked/releases/tag/v4.0.0', 'https://stackoverflow.com/questions/70000000'],
    );
    assert.equal(res.hits[1]?.title, 'https://github.com/markedjs/marked/releases/tag/v4.0.0', 'a missing title falls back to the URL');
    const so = res.hits[2];
    assert.ok(so && so.snippet.length <= 300, `${so?.snippet.length}`);
    assert.match(so?.snippet ?? '', /default export was removed/);
    assert.ok(res.hits.every((h) => h.backend === 'ollama'));
    assert.equal(fake.callsTo('https://api.github.com').length, 0, 'no docs requests when the hosted search works');
    assert.equal(audit.events.length, 1);
    assert.equal((audit.events[0] as { backend: string }).backend, 'ollama');
  });

  it('falls back to the docs backend on HTTP errors, with a note', async () => {
    fake = installFetch([['https://ollama.com/api/web_search', () => json({ error: 'unauthorized' }, { status: 401 })], ...markedDocsRoutes()]);
    const ctx = await testCtx({ config: { ollamaApiKey: 'bad' }, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx, { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.match(res.note ?? '', /Ollama web search failed: HTTP 401/);
    assert.equal(res.hits[0]?.url, 'https://github.com/markedjs/marked/releases/tag/v4.0.0');
  });

  it('needs the key when ollama is selected explicitly', async () => {
    fake = installFetch(markedDocsRoutes());
    const res = await searchWeb(QUERY, await testCtx({ config: { search: 'ollama' }, focus: { package: 'marked', version: '0.3.6' } }), { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.match(res.note ?? '', /needs OLLAMA_API_KEY/);
    assert.equal(fake.callsTo('https://ollama.com').length, 0);
  });
});

describe('brave, off and offline', () => {
  it('says brave is not configured without a key and uses the docs', async () => {
    fake = installFetch(markedDocsRoutes());
    const res = await searchWeb(QUERY, await testCtx({ config: { search: 'brave' }, focus: { package: 'marked', version: '0.3.6' } }), { toVersion: '4.0.10' });
    assert.equal(res.backend, 'docs');
    assert.match(res.note ?? '', /Brave search is not configured \(set BRAVE_SEARCH_API_KEY\)/);
    assert.ok(res.hits.length > 0);
  });

  it('is off with --search off', async () => {
    fake = installFetch([]);
    const audit = new MemoryAuditSink();
    const ctx = await testCtx({ config: { search: 'off' }, audit, focus: { package: 'marked', version: '0.3.6' } });
    const res = await searchWeb(QUERY, ctx);
    assert.deepEqual(res, { query: QUERY, backend: 'none', hits: [], cached: false, note: 'web search is off (--search off)' });
    assert.equal(audit.events.length, 1);
    assert.equal(fake.calls.length, 0);
  });

  it('is disabled offline unless the same search is cached', async () => {
    fake = installFetch(markedDocsRoutes());
    const cache = new MemoryCache();
    const offline = await testCtx({ cache, config: { offline: true }, focus: { package: 'marked', version: '0.3.6' } });
    const cold = await searchWeb(QUERY, offline, { toVersion: '4.0.10' });
    assert.deepEqual(cold, { query: QUERY, backend: 'none', hits: [], cached: false, note: 'search disabled (offline)' });
    const tool = await handleWebSearch({ query: QUERY }, offline);
    assert.equal(tool.ok, false);
    assert.equal(tool.hint, 'search disabled (offline)');
    assert.equal(fake.calls.length, 0);

    await searchWeb(QUERY, await testCtx({ cache, focus: { package: 'marked', version: '0.3.6' } }), { toVersion: '4.0.10' });
    cache.age(5 * 24 * 60 * 60 * 1000);
    const calls = fake.calls.length;
    const warm = await searchWeb(QUERY, offline, { toVersion: '4.0.10' });
    assert.equal(warm.cached, true);
    assert.equal(warm.backend, 'docs');
    assert.match(warm.note ?? '', /offline: cached results/);
    assert.equal(fake.calls.length, calls);
  });

  it('rejects an empty query', async () => {
    const result = await handleWebSearch({ query: '  ' }, await testCtx());
    assert.equal(result.ok, false);
    assert.match(result.error ?? '', /query is required/);
  });
});
