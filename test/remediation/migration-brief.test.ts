import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  applyBriefRails,
  BRIEF_SCHEMA,
  collectProjectFacts,
  coverageItems,
  itemFromLine,
  manualChecklist,
  parseBriefOutput,
  renderBrief,
  repairNearQuotes,
  researchMigration,
  verifyEvidenceQuotes,
  type ProjectFacts,
} from '../../src/remediation/migration.ts';
import type { MigrationBrief, MigrationBriefItem, MigrationSource } from '../../src/types.ts';
import {
  captureUi,
  DEFAULT_EXPORT_LINE,
  fixtureJson,
  installFetch,
  LIB_PATH_LINE,
  markedAction,
  markedRoutes,
  markedUsage,
  migrationCtx,
  RELEASE_V4_URL,
  resetWebState,
  SCRIPT_TAG_LINE,
  tempApp,
  testConfig,
  type FakeFetch,
} from './migration-helpers.ts';

type Draft = Omit<MigrationBriefItem, 'verified'>;

const releaseSource: MigrationSource = {
  url: RELEASE_V4_URL,
  kind: 'release-notes',
  title: 'marked v4.0.0 release notes',
  version: '4.0.0',
  cached: false,
  fetchedAt: '2026-09-24T00:00:00.000Z',
  text: ['### BREAKING CHANGES', `* ${DEFAULT_EXPORT_LINE}`, `* ${LIB_PATH_LINE}`, `* ${SCRIPT_TAG_LINE}`].join('\n'),
};
const blogSource: MigrationSource = {
  url: 'https://blog.example.com/marked-4-upgrade',
  kind: 'web',
  title: 'Upgrading to marked 4',
  version: null,
  cached: false,
  fetchedAt: '2026-09-24T00:00:00.000Z',
  text: "Marked 4 removed the default export, so require('marked') no longer returns a function.\nThe function itself still works, so marked(markdown) keeps rendering.",
};

function draft(partial: Partial<Draft> & { evidenceQuote: string }): Draft {
  return { change: 'a change', appliesToProject: 'unsure', evidenceUrl: RELEASE_V4_URL, oldApi: '', newApi: '', affectedFiles: [], ...partial };
}

describe('verifyEvidenceQuotes', () => {
  const verify = (quote: string, url = RELEASE_V4_URL): MigrationBriefItem => verifyEvidenceQuotes([draft({ evidenceQuote: quote, evidenceUrl: url })], [releaseSource, blogSource])[0] as MigrationBriefItem;

  it('accepts a verbatim quote', () => {
    const item = verify(DEFAULT_EXPORT_LINE);
    assert.equal(item.verified, true);
    assert.equal(item.evidenceQuote, DEFAULT_EXPORT_LINE);
    assert.equal(item.evidenceUrl, RELEASE_V4_URL);
  });

  it('accepts a whitespace-normalised quote and keeps the source text', () => {
    const item = verify('Default export   removed.\n  Use `import { marked } from \'marked\'`  or\t`const { marked } = require(\'marked\')` instead.');
    assert.equal(item.verified, true);
    assert.equal(item.evidenceQuote, DEFAULT_EXPORT_LINE);
  });

  it('accepts a quote without markdown backticks, with other quote marks, and restores the exact source text', () => {
    const item = verify('"Default export removed. Use import { marked } from "marked" or const { marked } = require("marked") instead"');
    assert.equal(item.verified, true);
    assert.equal(item.evidenceQuote, DEFAULT_EXPORT_LINE);
  });

  it('keeps the ellipsis inside `marked.parse(...)` and understands " ... " between pieces', () => {
    assert.equal(verify(SCRIPT_TAG_LINE).evidenceQuote, SCRIPT_TAG_LINE);
    const pieces = verify('Default export removed ... in script tag instead');
    assert.equal(pieces.verified, true);
    assert.equal(pieces.evidenceQuote, 'Default export removed. ... in script tag instead.');
    assert.equal(verify('in script tag instead ... Default export removed').verified, false, 'pieces out of order');
  });

  it('marks a hallucinated quote unverified', () => {
    const item = verify('The marked() function was removed; call marked.render() instead.');
    assert.equal(item.verified, false);
    assert.equal(item.evidenceQuote, 'The marked() function was removed; call marked.render() instead.');
  });

  it('rejects quotes too short to be evidence and empty quotes', () => {
    assert.equal(verify('removed').verified, false);
    assert.equal(verify('').verified, false);
  });

  it('repairs a near-verbatim copy (one quote mark dropped) to the exact source text, never a paraphrase', () => {
    const typo = "Default export removed. Use `import { marked } from 'marked` or `const { marked } = require('marked')` instead.";
    const unverified = verifyEvidenceQuotes([draft({ evidenceQuote: typo, evidenceUrl: 'https://example.com/x' })], [releaseSource]);
    assert.equal(unverified[0]?.verified, false, 'not verbatim');
    const { items, repaired } = repairNearQuotes(unverified, [releaseSource]);
    assert.equal(repaired, 1);
    assert.equal(items[0]?.verified, true);
    assert.equal(items[0]?.evidenceQuote, DEFAULT_EXPORT_LINE);
    assert.equal(items[0]?.evidenceUrl, RELEASE_V4_URL);
    const paraphrase = verifyEvidenceQuotes([draft({ evidenceQuote: 'The default export is removed; use the named marked export with require or import.' })], [releaseSource]);
    assert.equal(repairNearQuotes(paraphrase, [releaseSource]).items[0]?.verified, false);
    const invented = verifyEvidenceQuotes([draft({ evidenceQuote: 'Default export renamed. Use `import { marked } from "marked"` or `const { md } = require("marked")` now.' })], [releaseSource]);
    assert.equal(repairNearQuotes(invented, [releaseSource]).items[0]?.verified, false, 'more than a few characters differ');
  });

  it('corrects the URL to the source that holds the quote', () => {
    const item = verify("Marked 4 removed the default export, so require('marked') no longer returns a function.", 'https://example.com/made-up');
    assert.equal(item.verified, true);
    assert.equal(item.evidenceUrl, blogSource.url);
  });
});

describe('applies logic', () => {
  let cleanup: (() => Promise<void>) | null = null;
  afterEach(async () => {
    await cleanup?.();
    cleanup = null;
  });

  async function facts(extra?: (dir: string) => Promise<void>): Promise<ProjectFacts> {
    const app = await tempApp();
    cleanup = app.cleanup;
    await extra?.(app.dir);
    const config = await testConfig(app.dir);
    const ctx = migrationCtx(config);
    return collectProjectFacts('marked', markedUsage(), ctx.tools);
  }

  it('reads the project facts from the usage evidence and the code', async () => {
    const f = await facts();
    assert.deepEqual(f.importFiles, ['src/render.js']);
    assert.deepEqual(f.defaultImportFiles, ['src/render.js'], 'require binding called directly');
    assert.equal(f.moduleStyle, 'commonjs');
    assert.deepEqual(f.scriptTagFiles, []);
  });

  it('a removed default export applies to the files that call the default binding', async () => {
    const f = await facts();
    const out = applyBriefRails(draft({ evidenceQuote: DEFAULT_EXPORT_LINE, appliesToProject: 'unsure' }), f);
    assert.equal(out.item.appliesToProject, 'yes');
    assert.deepEqual(out.item.affectedFiles, ['src/render.js']);
    assert.equal(out.item.oldApi, "const marked = require('marked')");
    assert.equal(out.item.newApi, "const { marked } = require('marked')", 'the CommonJS form from the quote');
    assert.match(out.rule ?? '', /default export/);
  });

  it('a script-tag change does not apply without a <script> tag, and applies with one', async () => {
    const f = await facts();
    const out = applyBriefRails(draft({ evidenceQuote: SCRIPT_TAG_LINE, appliesToProject: 'yes', affectedFiles: ['src/render.js'] }), f);
    assert.equal(out.item.appliesToProject, 'no');
    assert.deepEqual(out.item.affectedFiles, []);
    await cleanup?.();
    const withTag = await facts(async (dir) => {
      await writeFile(path.join(dir, 'index.html'), '<html><body>\n<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>\n</body></html>\n');
    });
    const kept = applyBriefRails(draft({ evidenceQuote: SCRIPT_TAG_LINE, appliesToProject: 'yes' }), withTag);
    assert.equal(kept.item.appliesToProject, 'yes');
    assert.deepEqual(kept.item.affectedFiles, ['index.html']);
  });

  it('a removed package-internal path applies only when the project references it', async () => {
    const f = await facts();
    assert.equal(applyBriefRails(draft({ evidenceQuote: LIB_PATH_LINE, appliesToProject: 'yes' }), f).item.appliesToProject, 'no');
    await cleanup?.();
    const withPath = await facts(async (dir) => {
      await writeFile(path.join(dir, 'src', 'legacy.js'), "'use strict';\nconst render = require('marked/lib/marked.js');\nmodule.exports = render;\n");
    });
    const out = applyBriefRails(draft({ evidenceQuote: LIB_PATH_LINE }), withPath);
    assert.equal(out.item.appliesToProject, 'yes');
    assert.deepEqual(out.item.affectedFiles, ['src/legacy.js']);
  });

  it('puts the new API in the project\'s module style', async () => {
    const f = await facts();
    const esmAdvice = applyBriefRails(draft({ evidenceQuote: DEFAULT_EXPORT_LINE, appliesToProject: 'yes', oldApi: "const marked = require('marked');", newApi: "import { marked } from 'marked';" }), f);
    assert.equal(esmAdvice.item.newApi, "const { marked } = require('marked')", 'a CommonJS project keeps require()');
    assert.equal(esmAdvice.item.oldApi, "const marked = require('marked');");
  });

  it('a change to an API the project never uses does not apply; one it uses keeps the model\'s answer', async () => {
    const f = await facts();
    const tokenizer = applyBriefRails(
      draft({ evidenceQuote: 'Tokenizers will create their own tokens with `this.lexer.inline(text, tokens)`.', appliesToProject: 'unsure' }),
      f,
    );
    assert.equal(tokenizer.item.appliesToProject, 'no');
    assert.match(tokenizer.rule ?? '', /does not use lexer, inline/);
    const sanitize = applyBriefRails(draft({ evidenceQuote: 'Deprecate `sanitize` and `sanitizer` options', appliesToProject: 'unsure' }), f);
    assert.equal(sanitize.item.appliesToProject, 'unsure', 'src/render.js passes sanitize to marked');
    assert.ok(f.usedNames.has('sanitize') && f.usedNames.has('gfm'));
  });

  it('dropping an old Node.js line needs no code change', async () => {
    const f = await facts();
    assert.equal(applyBriefRails(draft({ evidenceQuote: 'Drop support for node 10.', appliesToProject: 'yes' }), f).item.appliesToProject, 'no');
    assert.equal(applyBriefRails(draft({ evidenceQuote: 'Now requires Node.js 12 or later.', appliesToProject: 'unsure' }), f).item.appliesToProject, 'no');
  });

  it('keeps only real project files, and fills the import files for an import change', async () => {
    const f = await facts();
    const out = applyBriefRails(
      draft({ evidenceQuote: 'The package is ESM only: use import instead of require.', appliesToProject: 'yes', affectedFiles: ['./src/missing.js', 'src/cli.js:3'] }),
      f,
    );
    assert.deepEqual(out.item.affectedFiles, ['src/render.js'], 'hallucinated and unrelated files dropped, the import file filled in');
    const unrelated = applyBriefRails(draft({ evidenceQuote: 'Tokens now carry a raw property.', appliesToProject: 'no', affectedFiles: ['src/render.js'] }), f);
    assert.deepEqual(unrelated.item.affectedFiles, [], 'a change that does not apply has no files');
  });

  it('adds every breaking line of the target release notes that no item covers', async () => {
    const f = await facts();
    const all = coverageItems([], [releaseSource], '4.0.10', f);
    assert.deepEqual(
      all.map((i) => i.evidenceQuote),
      [DEFAULT_EXPORT_LINE, LIB_PATH_LINE, SCRIPT_TAG_LINE],
    );
    const covered = coverageItems([draft({ evidenceQuote: 'Default export removed.', change: 'The default export was removed' })], [releaseSource], '4.0.10', f);
    assert.deepEqual(
      covered.map((i) => i.evidenceQuote),
      [LIB_PATH_LINE, SCRIPT_TAG_LINE],
    );
    const fromLine = itemFromLine(`* ${SCRIPT_TAG_LINE}`, RELEASE_V4_URL, f);
    assert.equal(fromLine.oldApi, 'marked(...)');
    assert.equal(fromLine.newApi, 'marked.parse(...)');
  });
});

describe('parseBriefOutput', () => {
  it('reads the schema answer, a fenced answer and a bare array', () => {
    const item = { change: 'x', appliesToProject: 'Yes', evidenceQuote: 'q', evidenceUrl: 'u', oldApi: 'a', newApi: 'b', affectedFiles: 'src/a.js' };
    assert.equal(parseBriefOutput(JSON.stringify({ items: [item] }))?.[0]?.appliesToProject, 'yes');
    assert.deepEqual(parseBriefOutput(`Here it is:\n\`\`\`json\n${JSON.stringify({ items: [item] })}\n\`\`\``)?.[0]?.affectedFiles, ['src/a.js']);
    assert.equal(parseBriefOutput(JSON.stringify([{ ...item, appliesToProject: 'not applicable' }]))?.[0]?.appliesToProject, 'no');
    assert.equal(parseBriefOutput(JSON.stringify({ items: [{ ...item, appliesToProject: 'maybe' }] }))?.[0]?.appliesToProject, 'unsure');
    assert.deepEqual(parseBriefOutput(JSON.stringify({ items: [{ appliesToProject: 'yes' }] })), [], 'items without a change are dropped');
    assert.equal(parseBriefOutput('I cannot answer that.'), null);
  });
});

describe('researchMigration', () => {
  let fake: FakeFetch | null = null;
  let cleanup: (() => Promise<void>) | null = null;
  beforeEach(() => resetWebState());
  afterEach(async () => {
    fake?.restore();
    fake = null;
    await cleanup?.();
    cleanup = null;
  });

  async function setup(script: Parameters<typeof migrationCtx>[1], overrides: Parameters<typeof testConfig>[1] = { search: 'off' }): Promise<ReturnType<typeof migrationCtx>> {
    const app = await tempApp();
    cleanup = app.cleanup;
    const config = await testConfig(app.dir, overrides);
    return migrationCtx(config, script);
  }

  const modelItems = {
    items: [
      {
        change: 'The default export was removed',
        appliesToProject: 'unsure',
        evidenceQuote: "Default export removed. Use import { marked } from 'marked' or const { marked } = require('marked') instead.",
        evidenceUrl: RELEASE_V4_URL,
        oldApi: "const marked = require('marked')",
        newApi: "const { marked } = require('marked')",
        affectedFiles: ['src/render.js'],
      },
      {
        change: 'Call marked.parse() instead of marked()',
        appliesToProject: 'yes',
        evidenceQuote: SCRIPT_TAG_LINE,
        evidenceUrl: RELEASE_V4_URL,
        oldApi: 'marked(...)',
        newApi: 'marked.parse(...)',
        affectedFiles: ['src/render.js'],
      },
      {
        change: 'Tables render differently',
        appliesToProject: 'yes',
        evidenceQuote: 'Tables are rendered by a new renderer in v4.',
        evidenceUrl: 'https://example.com/tables',
        oldApi: '',
        newApi: '',
        affectedFiles: ['src/render.js'],
      },
    ],
  };

  it('maps the sources to call sites: the default export item verified and applicable, the script-tag item not', async () => {
    const ctx = await setup({
      rules: [
        { id: 'loop', match: { purpose: 'migration' }, replies: [{ content: 'The default export removal applies to src/render.js; the script-tag change does not.' }] },
        { id: 'brief', match: { purpose: 'brief', hasFormat: true }, replies: [{ json: modelItems }] },
      ],
    });
    fake = installFetch(markedRoutes());
    const brief = await researchMigration(markedAction(), markedUsage(), ctx);

    const byQuote = (q: string): MigrationBriefItem | undefined => brief.items.find((i) => i.evidenceQuote === q);
    const defaultExport = byQuote(DEFAULT_EXPORT_LINE);
    assert.ok(defaultExport, 'default export item present');
    assert.equal(defaultExport.verified, true);
    assert.equal(defaultExport.appliesToProject, 'yes');
    assert.equal(defaultExport.evidenceUrl, RELEASE_V4_URL);
    assert.deepEqual(defaultExport.affectedFiles, ['src/render.js']);
    assert.equal(defaultExport.newApi, "const { marked } = require('marked')");
    const scriptTag = byQuote(SCRIPT_TAG_LINE);
    assert.equal(scriptTag?.verified, true);
    assert.equal(scriptTag?.appliesToProject, 'no', 'script-tag use is not how the project loads marked');
    assert.deepEqual(scriptTag?.affectedFiles, []);
    const tables = brief.items.find((i) => i.change === 'Tables render differently');
    assert.equal(tables?.verified, false, 'hallucinated quote');
    assert.equal(byQuote(LIB_PATH_LINE)?.appliesToProject, 'no', 'coverage added the /lib/marked.js line');
    assert.equal(brief.items[0]?.appliesToProject, 'yes', 'applicable items first');

    assert.equal(brief.package, 'marked');
    assert.equal(brief.from, '0.3.6');
    assert.equal(brief.to, '4.0.10');
    assert.equal(brief.offline, false);
    assert.equal(brief.model, 'mock-model');
    assert.ok(brief.sources.some((s) => s.url === RELEASE_V4_URL));
    assert.equal(brief.queries[0]?.backend, 'none');

    const [event] = ctx.audit.events('migration.brief');
    assert.equal(event?.items, brief.items.length);
    assert.equal(event?.verified, brief.items.filter((i) => i.verified).length);
    assert.deepEqual(event?.sources, brief.sources.map((s) => s.url));
    assert.ok(ctx.audit.events('tool.call').some((e) => e.tool === 'get_usage' && e.by === 'harness' && e.stage === 'migration'));

    // user message goes last
    const calls = ctx.provider.calls;
    assert.equal(calls[0]?.purpose, 'migration');
    assert.deepEqual(calls[0]?.tools?.map((t) => t.function.name), ['web_search', 'fetch_page', 'get_changelog', 'get_usage', 'search_code', 'read_file']);
    const firstUser = calls[0]?.messages.find((m) => m.role === 'user')?.content ?? '';
    assert.match(firstUser, /Default export removed/);
    assert.match(firstUser, /src\/render\.js:5/);
    assert.match(firstUser, /<script> tags loading marked: none/);
    const briefCall = calls.find((c) => c.purpose === 'brief');
    assert.deepEqual(briefCall?.format, BRIEF_SCHEMA);
    assert.equal(briefCall?.tools, undefined);
    for (const call of calls) assert.equal(call.messages.at(-1)?.role, 'user');
  });

  it('runs the tools the model asks for, dedupes repeats, and verifies quotes from a page it fetched', async () => {
    const blog = 'https://blog.example.com/marked-4-upgrade';
    const quote = "Marked 4 removed the default export, so require('marked') no longer returns a function.";
    const ctx = await setup({
      rules: [
        {
          id: 'loop',
          match: { purpose: 'migration' },
          replies: [
            { toolCalls: [{ name: 'fetch_page', arguments: { url: blog } }, { name: 'get_usage', arguments: { package: 'marked' } }] },
            { content: 'The blog confirms the default export removal.' },
          ],
        },
        {
          id: 'brief',
          match: { purpose: 'brief' },
          replies: [{ json: { items: [{ change: 'Default export removed', appliesToProject: 'yes', evidenceQuote: quote, evidenceUrl: blog, oldApi: '', newApi: '', affectedFiles: [] }] } }],
        },
      ],
    });
    fake = installFetch([
      [blog, () => new Response(`<html><body><main><p>${quote}</p><p>Use the named export instead.</p></main></body></html>`, { headers: { 'content-type': 'text/html' } })],
      ...markedRoutes(),
    ]);
    const brief = await researchMigration(markedAction(), markedUsage(), ctx);
    const item = brief.items.find((i) => i.evidenceUrl === blog);
    assert.equal(item?.verified, true, 'the page the model fetched is a source');
    assert.equal(item?.appliesToProject, 'yes');
    assert.deepEqual(item?.affectedFiles, ['src/render.js']);
    assert.ok(brief.sources.some((s) => s.url === blog));
    const toolMessages = ctx.provider.calls[1]?.messages.filter((m) => m.role === 'tool') ?? [];
    assert.equal(toolMessages.length, 2);
    assert.match(toolMessages[1]?.content ?? '', /You already have this result/, 'get_usage(marked) was already run by the harness');
    const modelCalls = ctx.audit.events('tool.call').filter((e) => e.by === 'model');
    assert.deepEqual(modelCalls.map((e) => e.tool), ['fetch_page']);
    assert.equal(ctx.provider.calls[1]?.messages.at(-1)?.role, 'user', 'a user message after the tool results');
  });

  it('answers calls for evidence already gathered without running them, and ends the loop after two', async () => {
    const ctx = await setup({
      rules: [
        {
          match: { purpose: 'migration' },
          replies: [
            { toolCalls: [{ name: 'fetch_page', arguments: { url: RELEASE_V4_URL } }] },
            { toolCalls: [{ name: 'get_changelog', arguments: { package: 'marked', fromVersion: '0.3.6', toVersion: '4.0.10' } }] },
            { content: 'never reached' },
          ],
        },
        { match: { purpose: 'brief' }, replies: [{ json: { items: [] } }] },
      ],
    });
    fake = installFetch(markedRoutes());
    const before = fake.calls.length;
    await researchMigration(markedAction(), markedUsage(), ctx);
    const loopCalls = ctx.provider.calls.filter((c) => c.purpose === 'migration');
    assert.equal(loopCalls.length, 2, 'the second wasted call ends the loop');
    const tool = loopCalls[1]?.messages.filter((m) => m.role === 'tool') ?? [];
    assert.match(tool[0]?.content ?? '', /already in the evidence as source \[1\]/);
    assert.equal(ctx.audit.events('tool.call').filter((e) => e.by === 'model').length, 0, 'nothing was run for the model');
    assert.equal(fake.calls.slice(before).some((c) => c.url.includes('/releases/tags/v4.0.0')), false);
    assert.match(ctx.out(), /Already in the evidence: not run again/);
  });

  it('a near-verbatim model quote is repaired, and a paraphrase is superseded by the verbatim line', async () => {
    const typo = "Default export removed. Use `import { marked } from 'marked` or `const { marked } = require('marked')` instead.";
    const ctx = await setup({
      rules: [
        { match: { purpose: 'migration' }, replies: [{ content: 'ok' }] },
        {
          match: { purpose: 'brief' },
          replies: [
            {
              json: {
                items: [
                  { change: 'Default export removed', appliesToProject: 'yes', evidenceQuote: typo, evidenceUrl: RELEASE_V4_URL, oldApi: "const marked = require('marked');", newApi: "import { marked } from 'marked';", affectedFiles: ['src/render.js'] },
                  { change: 'script tag users must call marked.parse', appliesToProject: 'yes', evidenceQuote: 'In a script tag you must now call marked.parse instead of marked', evidenceUrl: RELEASE_V4_URL, oldApi: '', newApi: '', affectedFiles: [] },
                ],
              },
            },
          ],
        },
      ],
    });
    fake = installFetch(markedRoutes());
    const brief = await researchMigration(markedAction(), markedUsage(), ctx);
    const first = brief.items[0];
    assert.equal(first?.evidenceQuote, DEFAULT_EXPORT_LINE);
    assert.equal(first?.verified, true);
    assert.equal(first?.appliesToProject, 'yes');
    assert.equal(first?.newApi, "const { marked } = require('marked')");
    assert.equal(brief.items.some((i) => i.change === 'script tag users must call marked.parse'), false, 'the unverified paraphrase is gone');
    assert.equal(brief.items.find((i) => i.evidenceQuote === SCRIPT_TAG_LINE)?.appliesToProject, 'no');
    assert.equal(brief.items.every((i) => i.verified), true);
    assert.match(ctx.out(), /1 quote repaired to the exact source text/);
  });

  it('builds the brief from the target release notes when the model gives no valid JSON', async () => {
    const ctx = await setup({
      rules: [
        { match: { purpose: 'migration' }, replies: [{ content: 'ok' }] },
        { match: { purpose: 'brief' }, replies: [{ content: 'not json' }], repeat: true },
      ],
    });
    fake = installFetch(markedRoutes());
    const brief = await researchMigration(markedAction(), markedUsage(), ctx);
    assert.equal(ctx.provider.calls.filter((c) => c.purpose === 'brief').length, 2, 'two schema attempts');
    assert.deepEqual(
      brief.items.map((i) => [i.evidenceQuote, i.appliesToProject, i.verified]),
      [
        [DEFAULT_EXPORT_LINE, 'yes', true],
        [LIB_PATH_LINE, 'no', true],
        [SCRIPT_TAG_LINE, 'no', true],
      ],
    );
    assert.match(ctx.out(), /\[forced\]/);
  });

  it('offline: cached sources only and the brief is flagged', async () => {
    const app = await tempApp();
    cleanup = app.cleanup;
    const script = { rules: [{ match: { purpose: 'brief' as const }, replies: [{ json: modelItems }], repeat: true }] };
    const online = migrationCtx(await testConfig(app.dir, { search: 'off' }), script);
    fake = installFetch(markedRoutes());
    await researchMigration(markedAction(), markedUsage(), online);
    fake.restore();
    resetWebState();
    fake = installFetch([]);
    const offline = migrationCtx(await testConfig(app.dir, { search: 'off', offline: true }), script, online.cache);
    const brief = await researchMigration(markedAction(), markedUsage(), offline);
    assert.deepEqual(fake.calls, []);
    assert.equal(brief.offline, true);
    assert.ok(brief.sources.length > 0 && brief.sources.every((s) => s.cached));
    assert.equal(brief.items.find((i) => i.evidenceQuote === DEFAULT_EXPORT_LINE)?.verified, true);
    assert.equal(offline.audit.events('migration.brief')[0]?.offline, true);
    assert.match(offline.out(), /Offline: the research uses cached sources only/);
  });

  it('with no sources at all the brief is empty and the model is not asked', async () => {
    const ctx = await setup({ rules: [] }, { offline: true });
    fake = installFetch([]);
    const brief = await researchMigration(markedAction(), markedUsage(), ctx);
    assert.deepEqual(brief.items, []);
    assert.deepEqual(brief.sources, []);
    assert.equal(ctx.provider.calls.length, 0);
    assert.match(manualChecklist(brief)[0] ?? '', /No breaking change in the brief applies/);
  });
});

describe('renderBrief and manualChecklist', () => {
  const brief: MigrationBrief = {
    package: 'marked',
    from: '0.3.6',
    to: '4.0.10',
    items: [
      {
        change: 'The default export was removed',
        appliesToProject: 'yes',
        evidenceQuote: DEFAULT_EXPORT_LINE,
        evidenceUrl: RELEASE_V4_URL,
        oldApi: "const marked = require('marked')",
        newApi: "const { marked } = require('marked')",
        affectedFiles: ['src/render.js'],
        verified: true,
      },
      { change: 'Tables render differently', appliesToProject: 'unsure', evidenceQuote: 'Tables are new.', evidenceUrl: 'https://example.com', oldApi: '', newApi: '', affectedFiles: [], verified: false },
      { change: 'Script tag users call marked.parse', appliesToProject: 'no', evidenceQuote: SCRIPT_TAG_LINE, evidenceUrl: RELEASE_V4_URL, oldApi: 'marked(...)', newApi: 'marked.parse(...)', affectedFiles: [], verified: true },
    ],
    sources: [{ url: RELEASE_V4_URL, kind: 'release-notes', title: null, version: '4.0.0', cached: true, fetchedAt: '2026-09-24T00:00:00.000Z', text: DEFAULT_EXPORT_LINE }],
    queries: [{ query: 'marked 4 migration breaking changes default export require', backend: 'docs', urls: [RELEASE_V4_URL], cached: false }],
    offline: true,
    model: 'mistral:7b',
    createdAt: '2026-09-24T00:00:00.000Z',
  };

  it('renders a section header and one entry per item with applies, the quote and the source', () => {
    const { ui } = captureUi();
    const text = renderBrief(brief, ui);
    assert.match(text, /Migration brief - marked 0\.3\.6 -> 4\.0\.10/, 'ASCII fallback without colours');
    assert.match(text, /3 changes - 1 applies - 1 unverified - 1 source - offline: cached sources only/);
    assert.match(text, /applies: yes - The default export was removed/);
    assert.match(text, /applies: unsure - Tables render differently/);
    assert.match(text, /applies: no - Script tag users call marked\.parse/);
    assert.match(text, /"Default export removed\. Use `import \{ marked \} from 'marked'` or `const \{ marked \} =\s+require\('marked'\)` instead\."/);
    assert.match(text, /\(unverified: not found in the sources, no edit drafted\)/);
    assert.match(text, /const marked = require\('marked'\) -> const \{ marked \} = require\('marked'\)/);
    assert.match(text, /src\/render\.js - https:\/\/github\.com\/markedjs\/marked\/releases\/tag\/v4\.0\.0/);
    assert.match(text, /Searches: "marked 4 migration breaking changes default export require" \(docs, 1 result\)/);
    assert.ok(!text.includes(String.fromCharCode(0x2014)));
    for (const line of text.split('\n')) assert.ok(line.length <= 100, `fits the width: ${line}`);
    const unicode = renderBrief(brief, captureUi({ unicode: true }).ui);
    assert.match(unicode, /Migration brief · marked 0\.3\.6 → 4\.0\.10/);
  });

  it('turns the brief into a manual checklist with source links, skipping what does not apply', () => {
    const list = manualChecklist(brief);
    assert.equal(list.length, 3);
    assert.match(list[0] ?? '', /^1\. The default export was removed \(src\/render\.js\): replace `const marked = require\('marked'\)` with `const \{ marked \} = require\('marked'\)`\. Source: https:\/\/github\.com\/markedjs\/marked\/releases\/tag\/v4\.0\.0$/);
    assert.match(list[1] ?? '', /^2\. Check whether this applies: Tables render differently .*\[unverified/);
    assert.equal(list[2], '1 change not applicable to this project (see the brief).');
  });

  it('uses the fixture v4.0.0 release for the verbatim quote', () => {
    const body = fixtureJson<{ body: string }>('release-v4.0.0.json').body.replace(/\r\n/g, '\n');
    assert.ok(body.includes(`* ${DEFAULT_EXPORT_LINE}`));
  });
});
