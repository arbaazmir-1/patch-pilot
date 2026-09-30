import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  cleanNoteLine,
  clearWebMemoryCache,
  collectBreakingLines,
  findBreakingLines,
  formatChangelogText,
  getChangelogInfo,
  githubHeaders,
  handleGetChangelog,
  parseChangelogSections,
  parseRepoUrl,
  releasesBetween,
  sliceChangelog,
  trimRelease,
  versionFromTag,
  versionInHeading,
} from '../../src/investigation/tools/getChangelog.ts';
import { createToolRegistry, formatToolContent } from '../../src/investigation/tools/index.ts';
import type { ChangelogRelease } from '../../src/types.ts';
import { fixture, fixtureJson, installFetch, json, MemoryCache, release, testCtx, text, type FakeFetch, type RouteHandler } from './helpers.ts';

const REGISTRY = 'https://registry.npmjs.org';
const DEFAULT_EXPORT = "Default export removed. Use `import { marked } from 'marked'` or `const { marked } = require('marked')` instead.";

let fake: FakeFetch | null = null;
beforeEach(() => clearWebMemoryCache());
afterEach(() => {
  fake?.restore();
  fake = null;
});

// packument plus version manifests
function registryRoutes(pkg: string, repository: unknown, versions: Record<string, Record<string, unknown>>): [string, RouteHandler][] {
  const packument = { name: pkg, 'dist-tags': { latest: Object.keys(versions).at(-1) }, versions: Object.fromEntries(Object.entries(versions).map(([v, extra]) => [v, { name: pkg, version: v, ...extra }])) };
  const routes: [string, RouteHandler][] = [[`${REGISTRY}/${pkg}`, () => json(packument)]];
  for (const v of [...Object.keys(versions), 'latest']) {
    routes.push([`${REGISTRY}/${pkg}/${v}`, () => json({ name: pkg, version: v === 'latest' ? Object.keys(versions).at(-1) : v, repository })]);
  }
  return routes;
}

function releasesRoute(owner: string, repo: string, pages: (page: number) => unknown[]): [(url: string) => boolean, RouteHandler] {
  const prefix = `https://api.github.com/repos/${owner}/${repo}/releases?`;
  return [
    (url) => url.startsWith(prefix),
    (call) => {
      const page = Number(new URL(call.url).searchParams.get('page') ?? '1');
      return json(pages(page));
    },
  ];
}

const markedReleases = (): unknown[] => fixtureJson<unknown[]>('marked-releases.json');

describe('tag normalisation and release ranges', () => {
  it('reads versions from tag styles', () => {
    const cases: [string, string | undefined, string | null][] = [
      ['v1.2.3', undefined, '1.2.3'],
      ['1.2.3', undefined, '1.2.3'],
      ['marked@4.0.0', 'marked', '4.0.0'],
      ['@babel/core@7.0.0', '@babel/core', '7.0.0'],
      ['core-v1.2.3', '@scope/core', '1.2.3'],
      ['release-2.0.0', 'x', '2.0.0'],
      ['v4.0.0-beta.1', undefined, '4.0.0-beta.1'],
      ['v6.0', undefined, '6.0.0'],
      ['other@4.0.0', 'marked', null],
      ['other-v4.0.0', 'marked', null],
      ['nightly', undefined, null],
      ['', undefined, null],
    ];
    for (const [tag, pkg, expected] of cases) assert.equal(versionFromTag(tag, pkg), expected, `${tag} (${pkg})`);
  });

  it('keeps releases with from < version <= to, newest first', () => {
    const releases = markedReleases().map((r) => trimRelease(r as Parameters<typeof trimRelease>[0]));
    const between = releasesBetween(releases, 'marked', '0.3.6', '4.0.10');
    assert.equal(between.length, 66);
    assert.equal(between[0]?.tag, 'v4.0.10');
    assert.equal(between.at(-1)?.tag, 'v0.3.7');
    assert.ok(between.some((r) => r.tag === '0.4.0'), 'a tag without the v prefix');
    assert.equal(between.some((r) => r.tag === 'v4.0.11'), false);
    assert.equal(releasesBetween(releases, 'marked', '4.0.0', '4.0.2').map((r) => r.tag).join(' '), 'v4.0.2 v4.0.1');
  });
});

describe('breaking-change lines', () => {
  it('takes the lines under a BREAKING heading and keyword lines, verbatim', () => {
    const body = fixtureJson<{ body: string }>('github-release-v4.0.0.json').body;
    const lines = findBreakingLines(body);
    assert.deepEqual(lines, [
      DEFAULT_EXPORT,
      '`/lib/marked.js` removed. Use `/marked.min.js` in script tag instead.',
      'When using marked in a script tag use `marked.parse(...)` instead of `marked(...)`',
    ]);
    for (const line of lines) assert.ok(body.includes(line), `verbatim: ${line}`);
  });

  it('understands nested "breaking:" lists and keywords in changelog files', () => {
    const [section] = sliceChangelog(fixture('express-History.md'), '4.21.0', '5.0.0');
    assert.equal(section?.version, '5.0.0');
    const lines = findBreakingLines(section?.body ?? '');
    assert.ok(lines.includes('`res.status()` accepts only integers, and input must be greater than 99 and less than 1000'));
    assert.ok(lines.some((l) => l.startsWith("`res.redirect('back')` and `res.location('back')` is no longer a supported magic string")));
    assert.equal(lines.some((l) => l.includes('cookie-signature')), false);
  });

  it('flags the listed keywords only', () => {
    const body = [
      '### Features',
      '- Add a new option',
      '- The `foo` option was removed',
      '- Dropped support for Node 14',
      '- `bar()` is no longer exported',
      '- `baz` renamed to `qux`',
      '- Now requires Node.js 18',
      '- Fix block-level elements breaking tables',
      '- BREAKING: the default is now strict',
      '```js',
      '// removed inside a code block',
      '```',
    ].join('\n');
    assert.deepEqual(findBreakingLines(body), [
      'The `foo` option was removed',
      'Dropped support for Node 14',
      '`bar()` is no longer exported',
      '`baz` renamed to `qux`',
      'Now requires Node.js 18',
      'BREAKING: the default is now strict',
    ]);
  });

  it('strips bullets, emphasis and trailing commit or issue links', () => {
    assert.equal(
      cleanNoteLine('* Convert to ESM ([#2227](https://github.com/markedjs/marked/issues/2227)) ([4afb228](https://github.com/markedjs/marked/commit/4afb228))'),
      'Convert to ESM',
    );
    assert.equal(cleanNoteLine('- Remove substitutions #1532'), 'Remove substitutions');
    assert.equal(cleanNoteLine('- Separate source into modules #1563 #1572 #1573'), 'Separate source into modules');
    assert.equal(cleanNoteLine('**possible breaking change**: capture group 2 (#1234)'), 'possible breaking change: capture group 2');
  });

  it('collects across releases without duplicates, newest first', () => {
    const releases: ChangelogRelease[] = [
      { tag: 'v2.0.0', name: null, publishedAt: null, url: null, body: '### BREAKING CHANGES\n* A removed\n* B renamed' },
      { tag: 'v1.0.0', name: null, publishedAt: null, url: null, body: '* A removed\n* C no longer works' },
    ];
    assert.deepEqual(collectBreakingLines(releases), [
      { tag: 'v2.0.0', text: 'A removed' },
      { tag: 'v2.0.0', text: 'B renamed' },
      { tag: 'v1.0.0', text: 'C no longer works' },
    ]);
  });
});

describe('changelog files', () => {
  it('detects version headings in the common styles', () => {
    const cases: [string, string | null][] = [
      ['[4.0.0](https://github.com/o/r/compare/v3.0.8...v4.0.0) (2021-11-02)', '4.0.0'],
      ['v2.2.3 [[code][c2.2.3], [diff][d2.2.3]]', '2.2.3'],
      ['4.17.2 / 2021-12-16', '4.17.2'],
      ['6.0', '6.0.0'],
      ['<small>4.0.0 (2021-11-02)</small>', '4.0.0'],
      ['[1.0.0] - 2020-01-01', '1.0.0'],
      ['marked v1.2.3', '1.2.3'],
      ['2021-01-01, Version 14.15.0 (LTS), @user', '14.15.0'],
      ['5.0.0-beta.1', '5.0.0-beta.1'],
      ['Changelog', null],
      ['Bug Fixes', null],
      ['Unreleased', null],
      ['2021-11-02', null],
    ];
    for (const [heading, expected] of cases) assert.equal(versionInHeading(heading), expected, heading);
  });

  it('slices setext sections (express History.md) to the version range', () => {
    const sections = sliceChangelog(fixture('express-History.md'), '4.17.1', '5.0.0');
    const versions = sections.map((s) => s.version);
    assert.equal(versions[0], '5.0.0');
    assert.ok(versions.includes('5.0.0-beta.1'));
    assert.ok(versions.includes('4.18.0'));
    assert.equal(versions.at(-1), '4.17.2');
    assert.equal(versions.includes('4.17.1'), false, 'from is exclusive');
    assert.equal(versions.includes('5.0.1'), false, 'to is inclusive, nothing above');
    assert.equal(sections[0]?.date, '2024-09-10');
  });

  it('slices ATX sections (json5, semver) and drops link reference lines', () => {
    const json5 = sliceChangelog(fixture('json5-CHANGELOG.md'), '2.2.0', '2.2.3');
    assert.deepEqual(json5.map((s) => s.version), ['2.2.3', '2.2.2', '2.2.1']);
    assert.match(json5[1]?.body ?? '', /`__proto__`/);
    assert.equal(json5.some((s) => /^\[c2\.2\.\d\]:/m.test(s.body)), false);
    const semver = fixture('semver-CHANGELOG.md');
    assert.deepEqual(sliceChangelog(semver, '7.3.0', '7.3.7').map((s) => s.version), ['7.3.7', '7.3.6']);
    assert.deepEqual(sliceChangelog(semver, '5.7.1', '6.0.0').map((s) => s.version), ['6.0.0']);
    assert.ok(parseChangelogSections(semver).length > 40);
  });
});

describe('getChangelogInfo', () => {
  const markedRegistry = (): [string, RouteHandler][] =>
    registryRoutes('marked', { type: 'git', url: 'git://github.com/markedjs/marked.git' }, {
      '0.3.6': {},
      '4.0.10': { engines: { node: '>= 12' } },
    });

  it('reads GitHub releases between the versions with the target facts, then serves the cache', async () => {
    fake = installFetch([...markedRegistry(), releasesRoute('markedjs', 'marked', (page) => (page === 1 ? markedReleases() : []))]);
    const cache = new MemoryCache();
    const ctx = await testCtx({ cache });
    const info = await getChangelogInfo('marked', '0.3.6', '4.0.10', ctx);
    assert.equal(info.source, 'github-releases');
    assert.equal(info.majorBump, true);
    assert.equal(info.repository, 'https://github.com/markedjs/marked');
    assert.equal(info.releases.length, 66);
    assert.equal(info.releases[0]?.tag, 'v4.0.10');
    assert.equal(info.breakingLines[0], DEFAULT_EXPORT);
    assert.equal(info.targetEnginesNode, '>= 12');
    assert.equal(info.targetDeprecated, null);
    assert.equal(info.note, undefined);
    assert.equal(fake.callsTo('https://api.github.com/repos/markedjs/marked/releases').length, 1, 'fewer than 100 releases: one page');

    const calls = fake.calls.length;
    const cached = await getChangelogInfo('marked', '0.3.6', '4.0.10', ctx);
    assert.equal(cached.source, 'cache');
    assert.match(cached.note ?? '', /cached .* \(from GitHub releases\)/);
    assert.equal(cached.releases.length, 66);
    assert.equal(fake.calls.length, calls);
  });

  it('pages until a tag falls below from, at most 5 pages', async () => {
    const page = (major: number): unknown[] => Array.from({ length: 100 }, (_, i) => release(`v${major}.0.${99 - i}`, `notes ${major}.0.${99 - i}`));
    fake = installFetch([
      ...registryRoutes('pkg', 'github:o/r', { '8.0.0': {}, '10.0.50': {} }),
      releasesRoute('o', 'r', (p) => (p <= 3 ? page(11 - p) : [])),
    ]);
    const info = await getChangelogInfo('pkg', '8.0.0', '10.0.50', await testCtx());
    assert.equal(fake.callsTo('https://api.github.com/repos/o/r/releases').length, 3);
    assert.equal(info.releases.length, 51 + 100 + 99);
    assert.equal(info.releases[0]?.tag, 'v10.0.50');

    fake.restore();
    clearWebMemoryCache();
    fake = installFetch([...registryRoutes('pkg', 'github:o/r', { '0.0.1': {}, '99.0.0': {} }), releasesRoute('o', 'r', (p) => page(100 - p))]);
    const capped = await getChangelogInfo('pkg', '0.0.1', '99.0.0', await testCtx());
    assert.equal(fake.callsTo('https://api.github.com/repos/o/r/releases').length, 5);
    assert.match(capped.note ?? '', /only the newest 500 GitHub releases were read/);
  });

  it('falls back to the changelog file when the GitHub API is rate limited', async () => {
    fake = installFetch([
      ...registryRoutes('express', 'git+https://github.com/expressjs/express.git', { '4.17.1': {}, '5.0.0': { engines: { node: '>= 18' } } }),
      [(url) => url.startsWith('https://api.github.com/'), () => json({ message: 'API rate limit exceeded for 1.2.3.4.' }, { status: 403 })],
      ['https://raw.githubusercontent.com/expressjs/express/HEAD/HISTORY.md', () => text(fixture('express-History.md'))],
    ]);
    const info = await getChangelogInfo('express', '4.17.1', '5.0.0', await testCtx());
    assert.equal(info.source, 'changelog-file');
    assert.equal(info.releases[0]?.tag, '5.0.0');
    assert.equal(info.releases[0]?.url, 'https://github.com/expressjs/express/blob/HEAD/HISTORY.md');
    assert.match(info.note ?? '', /rate limit/);
    assert.match(info.note ?? '', /used HISTORY\.md/);
    assert.ok(info.breakingLines.some((l) => l.startsWith('`res.status()` accepts only integers')));
    assert.equal(info.targetEnginesNode, '>= 18');
    assert.equal(fake.callsTo('https://raw.githubusercontent.com/expressjs/express/HEAD/CHANGELOG.md').length, 1, 'tried CHANGELOG.md first');
  });

  it('reports the target deprecation and a repository outside GitHub', async () => {
    fake = installFetch([...registryRoutes('lib', 'https://gitlab.com/o/lib.git', { '1.0.0': {}, '2.0.0': { deprecated: 'Use 2.0.1 instead', engines: { node: '>=18' } } })]);
    const info = await getChangelogInfo('lib', '1.0.0', '2.0.0', await testCtx());
    assert.equal(info.source, 'unavailable');
    assert.equal(info.targetDeprecated, 'Use 2.0.1 instead');
    assert.equal(info.targetEnginesNode, '>=18');
    assert.equal(info.repository, 'https://gitlab.com/o/lib');
    assert.match(info.note ?? '', /GitHub only/);
    assert.equal(fake.callsTo('https://api.github.com').length, 0);
  });

  it('is unavailable offline unless cached, and serves a warm cache offline', async () => {
    fake = installFetch([...markedRegistry(), releasesRoute('markedjs', 'marked', (page) => (page === 1 ? markedReleases() : []))]);
    const cold = await getChangelogInfo('marked', '0.3.6', '4.0.10', await testCtx({ config: { offline: true } }));
    assert.equal(cold.source, 'unavailable');
    assert.equal(cold.majorBump, true);
    assert.match(cold.note ?? '', /^unavailable offline/);
    assert.equal(fake.calls.length, 0);

    const cache = new MemoryCache();
    await getChangelogInfo('marked', '0.3.6', '4.0.10', await testCtx({ cache }));
    cache.age(3 * 24 * 60 * 60 * 1000);
    const warm = await getChangelogInfo('marked', '0.3.6', '4.0.10', await testCtx({ cache, config: { offline: true } }));
    assert.equal(warm.source, 'cache');
    assert.equal(warm.breakingLines[0], DEFAULT_EXPORT);
  });

  it('counts 0.x minor bumps as major', async () => {
    const ctx = await testCtx({ config: { offline: true } });
    assert.equal((await getChangelogInfo('p', '0.2.0', '0.3.0', ctx)).majorBump, true);
    assert.equal((await getChangelogInfo('p', '0.2.0', '0.2.5', ctx)).majorBump, false);
    assert.equal((await getChangelogInfo('p', '1.2.0', '1.9.0', ctx)).majorBump, false);
    assert.equal((await getChangelogInfo('p', '1.2.0', '2.0.0', ctx)).majorBump, true);
  });

  it('uses GITHUB_TOKEN when configured', async () => {
    assert.deepEqual(githubHeaders({ githubToken: null }), { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' });
    assert.equal(githubHeaders({ githubToken: 'ghp_x' }).authorization, 'Bearer ghp_x');
    fake = installFetch([...markedRegistry(), releasesRoute('markedjs', 'marked', (page) => (page === 1 ? markedReleases() : []))]);
    await getChangelogInfo('marked', '0.3.6', '4.0.10', await testCtx({ config: { githubToken: 'ghp_x' } }));
    assert.equal(fake.callsTo('https://api.github.com/')[0]?.headers.authorization, 'Bearer ghp_x');
    assert.equal(fake.callsTo(REGISTRY)[0]?.headers.authorization, undefined, 'the token only goes to GitHub');
  });

  it('parses repository URLs in the registry styles', () => {
    assert.deepEqual(parseRepoUrl('git+https://github.com/lodash/lodash.git'), { url: 'https://github.com/lodash/lodash', host: 'github', owner: 'lodash', repo: 'lodash', directory: null });
    assert.equal(parseRepoUrl('git://github.com/markedjs/marked.git')?.url, 'https://github.com/markedjs/marked');
    assert.equal(parseRepoUrl('git@github.com:o/r.git')?.repo, 'r');
    assert.equal(parseRepoUrl('github:o/r')?.url, 'https://github.com/o/r');
    assert.equal(parseRepoUrl('o/r')?.host, 'github');
    assert.equal(parseRepoUrl('https://gitlab.com/o/r', 'packages/x')?.directory, 'packages/x');
    assert.equal(parseRepoUrl(''), null);
  });
});

describe('get_changelog tool output', () => {
  it('lists the breaking lines with their release and stays under the registry cap', async () => {
    fake = installFetch([
      ...registryRoutes('marked', 'https://github.com/markedjs/marked', { '0.3.6': {}, '4.0.10': { engines: { node: '>= 12' } } }),
      releasesRoute('markedjs', 'marked', (page) => (page === 1 ? markedReleases() : [])),
    ]);
    const ctx = await testCtx();
    const result = await handleGetChangelog({ package: 'marked', fromVersion: '0.3.6', toVersion: '4.0.10' }, ctx);
    assert.equal(result.ok, true);
    assert.match(result.hint, /^66 releases, 50 breaking-change lines, major bump$/);
    const body = result.text ?? '';
    assert.match(body, /^marked 0\.3\.6 \u2192 4\.0\.10: major bump/);
    assert.match(body, /Target 4\.0\.10: engines\.node >= 12, not deprecated\./);
    assert.ok(body.includes(`- v4.0.0: ${DEFAULT_EXPORT}`));
    assert.match(body, /^Releases: v4\.0\.10 2022-01-13, /m);
    assert.ok(formatToolContent(result).length <= 1500, `${formatToolContent(result).length}`);
    assert.equal(result.truncated, true);

    const exec = await createToolRegistry().execute({ name: 'get_changelog', arguments: { pkg: 'marked', from: '0.3.6', to: '4.0.10' } }, ctx, 'migration');
    assert.equal(exec.status, 'ok');
    assert.equal(exec.content.includes('[output truncated'), false);
    assert.ok(exec.content.includes('Default export removed'));
  });

  it('rejects versions that are not semver and swaps a reversed range', async () => {
    const ctx = await testCtx({ config: { offline: true } });
    const bad = await handleGetChangelog({ package: 'marked', fromVersion: 'latest', toVersion: '4.0.10' }, ctx);
    assert.equal(bad.ok, false);
    assert.match(bad.error ?? '', /fromVersion "latest" is not a semver version/);
    const swapped = await handleGetChangelog({ package: 'marked', fromVersion: '4.0.10', toVersion: '0.3.6' }, ctx);
    assert.equal(swapped.ok, true);
    assert.match(swapped.text ?? '', /^\(fromVersion and toVersion were swapped/);
    assert.match(swapped.hint, /unavailable offline, major bump/);
  });

  it('formats an unavailable result compactly', () => {
    const { text: out } = formatChangelogText({
      package: 'x',
      fromVersion: '1.0.0',
      toVersion: '1.0.1',
      majorBump: false,
      source: 'unavailable',
      repository: null,
      releases: [],
      breakingLines: [],
      targetDeprecated: 'do not use',
      targetEnginesNode: null,
      note: 'unavailable offline',
    });
    assert.equal(out, 'x 1.0.0 \u2192 1.0.1: same major line.\nTarget 1.0.1: engines.node not declared, DEPRECATED: do not use.\nRelease notes: unavailable.\nNote: unavailable offline');
  });
});
