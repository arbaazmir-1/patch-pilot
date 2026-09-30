import assert from 'node:assert/strict';
import { after, afterEach, before, beforeEach, describe, it } from 'node:test';
import { clearWebMemoryCache } from '../../src/investigation/tools/getChangelog.ts';
import {
  assertPublicHost,
  checkFetchUrl,
  fetchPageText,
  FetchPageError,
  handleFetchPage,
  isPrivateAddress,
  PAGE_MAX_BYTES,
  rewriteGithubUrl,
  setHostLookup,
} from '../../src/investigation/tools/fetchPage.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import { fixture, fixtureJson, installFetch, json, MemoryCache, testCtx, text, type FakeFetch } from './helpers.ts';

const RELEASE_URL = 'https://github.com/markedjs/marked/releases/tag/v4.0.0';
const RELEASE_API = 'https://api.github.com/repos/markedjs/marked/releases/tags/v4.0.0';
const lookups: string[] = [];

before(() => {
  setHostLookup(async (host) => {
    lookups.push(host);
    if (host === 'evil.example.com') return ['10.0.0.7'];
    if (host === 'rebind.example.com') return ['93.184.216.34', '127.0.0.1'];
    if (host === 'nx.example.com') throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
    return ['93.184.216.34'];
  });
});
after(() => setHostLookup(null));

let fake: FakeFetch | null = null;
beforeEach(() => {
  clearWebMemoryCache();
  lookups.length = 0;
});
afterEach(() => {
  fake?.restore();
  fake = null;
});

describe('URL policy', () => {
  it('allows public http(s) URLs and adds https:// to a bare host', () => {
    for (const url of ['https://github.com/markedjs/marked', 'http://example.com/docs?x=1#y', 'https://93.184.216.34/']) {
      assert.equal(checkFetchUrl(url).ok, true, url);
    }
    const bare = checkFetchUrl('github.com/markedjs/marked/releases');
    assert.ok(bare.ok);
    assert.equal(bare.ok && bare.url.href, 'https://github.com/markedjs/marked/releases');
  });

  it('refuses other schemes, credentials, local names and private addresses', () => {
    const refused = [
      'ftp://example.com/file',
      'file:///etc/passwd',
      'javascript:alert(1)',
      'data:text/html,hi',
      'http://localhost:3000/',
      'http://api.localhost/',
      'http://127.0.0.1/',
      'http://127.1/',
      'http://2130706433/',
      'http://0x7f.1/',
      'http://[::1]/',
      'http://[::ffff:127.0.0.1]/',
      'http://[fd00::1]/',
      'http://[fe80::1]/',
      'http://10.0.0.5/',
      'http://172.16.3.4/',
      'http://192.168.1.1/',
      'http://169.254.169.254/latest/meta-data/',
      'http://100.64.0.1/',
      'http://0.0.0.0/',
      'http://224.0.0.1/',
      'http://metadata.google.internal/',
      'http://printer.local/',
      'http://intranet/',
      'https://user:secret@example.com/',
      'not a url at all',
      '',
    ];
    for (const url of refused) assert.equal(checkFetchUrl(url).ok, false, url);
  });

  it('classifies addresses', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.31.255.255', '192.168.0.1', '169.254.1.1', '100.100.100.100', '::1', 'fc00::1', 'fe80::1', '::ffff:10.0.0.1', '::ffff:7f00:1', '64:ff9b::a00:1']) {
      assert.equal(isPrivateAddress(ip), true, ip);
    }
    for (const ip of ['93.184.216.34', '140.82.112.3', '8.8.8.8', '2606:4700::6810:84e5', '172.32.0.1']) {
      assert.equal(isPrivateAddress(ip), false, ip);
    }
    assert.equal(isPrivateAddress('github.com'), false);
  });

  it('resolves the host before a local fetch and refuses private answers', async () => {
    await assertPublicHost(new URL('https://docs.example.com/'));
    await assert.rejects(assertPublicHost(new URL('https://evil.example.com/')), (err: unknown) => err instanceof FetchPageError && err.code === 'blocked');
    await assert.rejects(assertPublicHost(new URL('https://rebind.example.com/')), /resolves to 127\.0\.0\.1/);
    await assert.rejects(assertPublicHost(new URL('https://nx.example.com/')), (err: unknown) => err instanceof FetchPageError && err.code === 'network');
  });
});

describe('GitHub URL rewriting', () => {
  it('maps release, issue, pull and blob URLs to the API and raw hosts', () => {
    assert.deepEqual(rewriteGithubUrl(RELEASE_URL), { kind: 'release', owner: 'markedjs', repo: 'marked', tag: 'v4.0.0', apiUrl: RELEASE_API });
    assert.deepEqual(rewriteGithubUrl('https://github.com/o/r/releases/tag/pkg@1.2.3'), {
      kind: 'release',
      owner: 'o',
      repo: 'r',
      tag: 'pkg@1.2.3',
      apiUrl: 'https://api.github.com/repos/o/r/releases/tags/pkg@1.2.3',
    });
    assert.equal(rewriteGithubUrl('https://github.com/o/r/releases/latest')?.kind, 'release');
    assert.deepEqual(rewriteGithubUrl('https://www.github.com/markedjs/marked/issues/2265'), {
      kind: 'issue',
      owner: 'markedjs',
      repo: 'marked',
      number: 2265,
      apiUrl: 'https://api.github.com/repos/markedjs/marked/issues/2265',
    });
    assert.equal(rewriteGithubUrl('https://github.com/o/r/pull/7')?.kind, 'issue');
    assert.deepEqual(rewriteGithubUrl('https://github.com/markedjs/marked/blob/v4.0.0/docs/USING_ADVANCED.md#options'), {
      kind: 'blob',
      owner: 'markedjs',
      repo: 'marked',
      path: 'docs/USING_ADVANCED.md',
      rawUrl: 'https://raw.githubusercontent.com/markedjs/marked/v4.0.0/docs/USING_ADVANCED.md',
    });
    for (const other of ['https://github.com/markedjs/marked', 'https://github.com/o/r/releases', 'https://github.com/o/r/issues', 'https://gitlab.com/o/r/-/releases/v1', 'not a url']) {
      assert.equal(rewriteGithubUrl(other), null, other);
    }
  });
});

describe('fetchPageText', () => {
  it('reads a GitHub release through the REST API and caches the page', async () => {
    fake = installFetch([[RELEASE_API, () => json(fixtureJson('github-release-v4.0.0.json'))]]);
    const cache = new MemoryCache();
    const ctx = await testCtx({ cache });
    const page = await fetchPageText(RELEASE_URL, 'default export', ctx);
    assert.match(page.text, /Default export removed\. Use `import \{ marked \} from 'marked'`/);
    assert.equal(page.finalUrl, RELEASE_URL);
    assert.equal(page.title, 'markedjs/marked v4.0.0');
    assert.equal(page.cached, false);
    assert.equal(page.jsRendered, false);
    assert.equal(fake.calls.length, 1);
    assert.equal(fake.calls[0]?.headers.accept, 'application/vnd.github+json');
    assert.equal(fake.calls[0]?.headers.authorization, undefined);
    assert.deepEqual(cache.namespaces(), ['page']);
    const again = await fetchPageText(`${RELEASE_URL}#breaking`, 'script tag', ctx);
    assert.equal(again.cached, true);
    assert.equal(fake.calls.length, 1, 'served from the page cache');
  });

  it('sends GITHUB_TOKEN to the GitHub API when configured', async () => {
    fake = installFetch([[RELEASE_API, () => json(fixtureJson('github-release-v4.0.0.json'))]]);
    const ctx = await testCtx({ config: { githubToken: 'ghp_test' } });
    await fetchPageText(RELEASE_URL, undefined, ctx);
    assert.equal(fake.calls[0]?.headers.authorization, 'Bearer ghp_test');
  });

  it('converts a generic HTML page, windowed around the query', async () => {
    const page = fixture('docs-page.html');
    fake = installFetch([['https://docs.example.com/upgrading', () => text(page, 'text/html; charset=utf-8')]]);
    const ctx = await testCtx();
    const result = await fetchPageText('https://docs.example.com/upgrading', 'default export', ctx);
    assert.match(result.text, /^# Upgrading to v4$/m);
    assert.equal(result.title, 'Upgrading to v4 - Example Docs');
    assert.equal(result.truncated, false);
    assert.equal(fake.calls[0]?.headers.accept?.startsWith('text/html'), true);
    assert.deepEqual(lookups, ['docs.example.com']);
  });

  it('keeps big pages to a keyword window of about 3000 characters', async () => {
    const filler = Array.from({ length: 400 }, (_, i) => `<p>Paragraph ${i} about unrelated things.</p>`).join('');
    const html = `<html><body><main>${filler}<h2>v4</h2><p>The default export was removed.</p>${filler}</main></body></html>`;
    fake = installFetch([['https://docs.example.com/big', () => text(html, 'text/html')]]);
    const result = await fetchPageText('https://docs.example.com/big', 'default export', await testCtx());
    assert.ok(result.text.length <= 3000, `${result.text.length}`);
    assert.ok(result.totalChars > 10_000);
    assert.equal(result.truncated, true);
    assert.match(result.text, /The default export was removed\./);
    const exec = await createToolRegistry().execute({ name: 'fetch_page', arguments: { link: 'https://docs.example.com/big', keywords: 'default export' } }, await testCtx(), 'migration');
    assert.equal(exec.status, 'ok');
    assert.equal(exec.content.includes('[output truncated'), false, `${exec.content.length} chars`);
    assert.match(exec.content, /The default export was removed\./);
  });

  it('reads blob URLs from raw.githubusercontent.com', async () => {
    fake = installFetch([['https://raw.githubusercontent.com/o/r/main/docs/MIGRATION.md', () => text('# Migration\r\n\r\n\r\n- `foo()` was renamed to `bar()`\r\n')]]);
    const result = await fetchPageText('https://github.com/o/r/blob/main/docs/MIGRATION.md', undefined, await testCtx());
    assert.equal(result.text, '# Migration\n\n- `foo()` was renamed to `bar()`');
    assert.equal(result.title, 'Migration');
    assert.equal(result.finalUrl, 'https://github.com/o/r/blob/main/docs/MIGRATION.md');
  });

  it('follows redirects by hand and re-checks every hop', async () => {
    fake = installFetch([
      ['https://short.example.com/a', () => new Response(null, { status: 301, headers: { location: 'https://docs.example.com/final' } })],
      ['https://docs.example.com/final', () => text('<html><body><p>Final page text.</p></body></html>', 'text/html')],
      ['https://short.example.com/private', () => new Response(null, { status: 302, headers: { location: 'http://127.0.0.1:8080/admin' } })],
      ['https://short.example.com/evil', () => new Response(null, { status: 302, headers: { location: 'https://evil.example.com/' } })],
      [/^https:\/\/loop\.example\.com\//, (call) => new Response(null, { status: 302, headers: { location: `${call.url}x` } })],
    ]);
    const ctx = await testCtx();
    const ok = await fetchPageText('https://short.example.com/a', undefined, ctx);
    assert.equal(ok.finalUrl, 'https://docs.example.com/final');
    assert.equal(ok.text, 'Final page text.');
    assert.deepEqual(lookups, ['short.example.com', 'docs.example.com']);
    await assert.rejects(fetchPageText('https://short.example.com/private', undefined, ctx), (err: unknown) => err instanceof FetchPageError && err.code === 'blocked');
    await assert.rejects(fetchPageText('https://short.example.com/evil', undefined, ctx), (err: unknown) => err instanceof FetchPageError && err.code === 'blocked');
    await assert.rejects(fetchPageText('https://loop.example.com/', undefined, ctx), (err: unknown) => err instanceof FetchPageError && err.code === 'redirects');
    assert.equal(fake.callsTo('http://127.0.0.1').length, 0, 'never contacted the private host');
    assert.equal(fake.callsTo('https://evil.example.com').length, 0);
  });

  it('never fetches a host that resolves to a private address', async () => {
    fake = installFetch([]);
    await assert.rejects(fetchPageText('https://evil.example.com/docs', undefined, await testCtx()), /private or local address/);
    assert.equal(fake.calls.length, 0);
  });

  it('refuses binary content and caps bodies at 2 MB', async () => {
    const big = `<html><body><p>${'word '.repeat((PAGE_MAX_BYTES / 5) * 1.5)}</p></body></html>`;
    fake = installFetch([
      ['https://docs.example.com/logo.png', () => new Response(new Uint8Array([137, 80, 78, 71]), { headers: { 'content-type': 'image/png' } })],
      ['https://docs.example.com/huge', () => text(big, 'text/html')],
    ]);
    const ctx = await testCtx();
    await assert.rejects(fetchPageText('https://docs.example.com/logo.png', undefined, ctx), (err: unknown) => err instanceof FetchPageError && err.code === 'not-text');
    const huge = await fetchPageText('https://docs.example.com/huge', undefined, ctx);
    assert.equal(huge.truncated, true);
    assert.ok(huge.totalChars <= PAGE_MAX_BYTES);
  });

  it('flags JavaScript-rendered pages', async () => {
    const shell = `<!doctype html><html><head><script>${'let x = 1;'.repeat(300)}</script></head><body><div id="app"></div></body></html>`;
    fake = installFetch([['https://spa.example.com/', () => text(shell, 'text/html')]]);
    const ctx = await testCtx();
    const page = await fetchPageText('https://spa.example.com/', undefined, ctx);
    assert.equal(page.jsRendered, true);
    const result = await handleFetchPage({ url: 'https://spa.example.com/' }, ctx);
    assert.equal(result.ok, true);
    assert.match(result.hint, /JavaScript-rendered/);
    assert.match(result.text ?? '', /probably rendered by JavaScript/);
  });

  it('uses Ollama web_fetch with the key and falls back to the local path on errors', async () => {
    let ollamaStatus = 200;
    fake = installFetch([
      [
        'https://ollama.com/api/web_fetch',
        () =>
          ollamaStatus === 200
            ? json({ title: 'Release v4.0.0 markedjs/marked', content: `## BREAKING CHANGES\n\n* Default export removed.\n${'more text '.repeat(40)}`, links: [] })
            : json({ error: 'unauthorized' }, { status: ollamaStatus }),
      ],
      [RELEASE_API, () => json(fixtureJson('github-release-v4.0.0.json'))],
    ]);
    const ctx = await testCtx({ config: { ollamaApiKey: 'ollama-test-key' } });
    const viaOllama = await fetchPageText(RELEASE_URL, 'default export', ctx);
    assert.match(viaOllama.text, /Default export removed\./);
    assert.equal(viaOllama.title, 'Release v4.0.0 markedjs/marked');
    const call = fake.callsTo('https://ollama.com/api/web_fetch')[0];
    assert.equal(call?.method, 'POST');
    assert.equal(call?.headers.authorization, 'Bearer ollama-test-key');
    assert.deepEqual(JSON.parse(call?.body ?? '{}'), { url: RELEASE_URL });
    assert.equal(fake.callsTo('https://api.github.com').length, 0);

    ollamaStatus = 401;
    const ctx2 = await testCtx({ config: { ollamaApiKey: 'bad-key' } });
    const local = await fetchPageText(RELEASE_URL, 'default export', ctx2);
    assert.match(local.text, /Default export removed\. Use `import/);
    assert.equal(fake.callsTo(RELEASE_API).length, 1, 'fell back to the GitHub API');
    for (const c of fake.calls.filter((c) => !c.url.startsWith('https://ollama.com'))) assert.equal(c.headers.authorization, undefined, 'the Ollama key never leaves ollama.com');
  });

  it('falls back to the HTML page when the GitHub API fails', async () => {
    fake = installFetch([
      [RELEASE_API, () => json({ message: 'API rate limit exceeded for 1.2.3.4.' }, { status: 403 })],
      [RELEASE_URL, () => text(fixture('github-release-v4.0.0.html'), 'text/html; charset=utf-8')],
    ]);
    const page = await fetchPageText(RELEASE_URL, 'default export', await testCtx());
    assert.match(page.text, /Default export removed\./);
    assert.equal(page.title, 'Release v4.0.0 \u00b7 markedjs/marked \u00b7 GitHub');
  });
});

describe('offline and the tool handler', () => {
  it('serves cached pages offline and refuses the rest', async () => {
    fake = installFetch([[RELEASE_API, () => json(fixtureJson('github-release-v4.0.0.json'))]]);
    const cache = new MemoryCache();
    await fetchPageText(RELEASE_URL, undefined, await testCtx({ cache }));
    cache.age(10 * 24 * 60 * 60 * 1000);
    const offline = await testCtx({ cache, config: { offline: true } });
    const page = await fetchPageText(RELEASE_URL, 'default export', offline);
    assert.equal(page.cached, true);
    await assert.rejects(fetchPageText('https://docs.example.com/other', undefined, offline), (err: unknown) => err instanceof FetchPageError && err.code === 'offline');
    const result = await handleFetchPage({ url: 'https://docs.example.com/other' }, offline);
    assert.equal(result.ok, false);
    assert.equal(result.hint, 'page unavailable offline');
    assert.match(result.error ?? '', /unavailable offline/);
    assert.equal(fake.calls.length, 1);
  });

  it('a stale cached page is fetched again online', async () => {
    fake = installFetch([[RELEASE_API, () => json(fixtureJson('github-release-v4.0.0.json'))]]);
    const cache = new MemoryCache();
    await fetchPageText(RELEASE_URL, undefined, await testCtx({ cache }));
    cache.age(25 * 60 * 60 * 1000);
    const page = await fetchPageText(RELEASE_URL, undefined, await testCtx({ cache }));
    assert.equal(page.cached, false);
    assert.equal(fake.calls.length, 2);
  });

  it('returns compact text with a one-line hint', async () => {
    fake = installFetch([[RELEASE_API, () => json(fixtureJson('github-release-v4.0.0.json'))]]);
    const result = await handleFetchPage({ url: RELEASE_URL, query: 'default export' }, await testCtx());
    assert.equal(result.ok, true);
    assert.match(result.hint, /chars/);
    assert.ok((result.text ?? '').startsWith('Title: markedjs/marked v4.0.0\nURL: https://github.com/markedjs/marked/releases/tag/v4.0.0\n'));
    assert.ok((result.text ?? '').length <= 3500);
  });

  it('refuses private URLs with a fixable error', async () => {
    fake = installFetch([]);
    const result = await handleFetchPage({ url: 'http://169.254.169.254/latest/meta-data/' }, await testCtx());
    assert.equal(result.ok, false);
    assert.match(result.hint, /^refused: /);
    assert.match(result.error ?? '', /public http\(s\) documentation URL/);
    assert.equal(fake.calls.length, 0);
  });
});
