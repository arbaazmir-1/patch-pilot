import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { MemoryAudit } from '../../src/audit.ts';
import { MockProvider, type MockScript } from '../../src/llm/mock.ts';
import { checkSyntax, EDITS_SCHEMA, proposeCodemod, writePatches, type CodemodContext } from '../../src/remediation/codemod.ts';
import type { FilePatch, MigrationBrief, MigrationBriefItem } from '../../src/types.ts';
import { captureUi, DEFAULT_EXPORT_LINE, RELEASE_V4_URL, SCRIPT_TAG_LINE, tempApp, testConfig } from './migration-helpers.ts';

const IMPORT = { file: 'src/render.js', search: "const marked = require('marked');", replace: "const { marked } = require('marked');", why: 'Default export removed' };
const PARSE = { file: 'src/render.js', search: '  return marked(userMarkdown, {', replace: '  return marked.parse(userMarkdown, {', why: 'use marked.parse' };

const sha = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');

function item(partial: Partial<MigrationBriefItem> = {}): MigrationBriefItem {
  return {
    change: 'The default export was removed',
    appliesToProject: 'yes',
    evidenceQuote: DEFAULT_EXPORT_LINE,
    evidenceUrl: RELEASE_V4_URL,
    oldApi: "const marked = require('marked')",
    newApi: "const { marked } = require('marked')",
    affectedFiles: ['src/render.js'],
    verified: true,
    ...partial,
  };
}

function brief(items: MigrationBriefItem[]): MigrationBrief {
  return { package: 'marked', from: '0.3.6', to: '4.0.10', items, sources: [], queries: [], offline: false, model: 'mock-model', createdAt: '2026-09-24T00:00:00.000Z' };
}

let cleanup: (() => Promise<void>) | null = null;
afterEach(async () => {
  await cleanup?.();
  cleanup = null;
});

async function setup(script: MockScript): Promise<{ dir: string; ctx: CodemodContext & { provider: MockProvider; audit: MemoryAudit }; out: () => string }> {
  const app = await tempApp();
  cleanup = app.cleanup;
  const config = await testConfig(app.dir);
  const { ui, out } = captureUi();
  return { dir: app.dir, ctx: { config, ui, audit: new MemoryAudit(), provider: new MockProvider(script, { model: 'coder' }) }, out };
}

describe('proposeCodemod', () => {
  it('turns a verified, applicable brief item into a validated patch with a diff', async () => {
    const { dir, ctx } = await setup({ rules: [{ match: { purpose: 'codemod' }, replies: [{ json: { edits: [IMPORT] } }] }] });
    const before = await readFile(path.join(dir, 'src/render.js'));
    const result = await proposeCodemod(brief([item(), item({ evidenceQuote: SCRIPT_TAG_LINE, appliesToProject: 'no', affectedFiles: [] })]), ctx);
    assert.equal(result.package, 'marked');
    assert.equal(result.model, 'coder');
    assert.equal(result.manualChecklist, null);
    assert.deepEqual(result.rejected, []);
    const [patch] = result.patches;
    assert.equal(patch?.file, 'src/render.js');
    assert.deepEqual(patch?.edits, [IMPORT]);
    assert.equal(patch?.beforeHash, sha(before));
    assert.match(patch?.newContent ?? '', /^const \{ marked \} = require\('marked'\);$/m);
    assert.match(patch?.diff ?? '', /^--- src\/render\.js\n\+\+\+ src\/render\.js\n@@/);
    assert.match(patch?.diff ?? '', /^-const marked = require\('marked'\);\n\+const \{ marked \} = require\('marked'\);$/m);
    assert.equal(await readFile(path.join(dir, 'src/render.js'), 'utf8'), before.toString('utf8'), 'nothing written before approval');

    const [call] = ctx.provider.calls;
    assert.equal(ctx.provider.calls.length, 1, 'one file, one call');
    assert.equal(call?.purpose, 'codemod');
    assert.deepEqual(call?.format, EDITS_SCHEMA);
    const user = call?.messages.at(-1)?.content ?? '';
    assert.equal(call?.messages.at(-1)?.role, 'user');
    assert.match(user, /File: src\/render\.js \(CommonJS, 24 lines\)/);
    assert.ok(user.includes(DEFAULT_EXPORT_LINE), 'the verified evidence quote');
    assert.ok(!user.includes(SCRIPT_TAG_LINE), 'an item that does not apply is not sent');
    assert.match(user, /line 5 \(import\): const marked = require\('marked'\);/);
    assert.match(user, /line 8 \(marked\(\)\): return marked\(userMarkdown, \{/);
    assert.match(user, /The whole file:\n```js\n'use strict';/);
    assert.match(call?.messages[0]?.content ?? '', /CommonJS: keep require\(\) and module\.exports/);
    assert.deepEqual(ctx.audit.events('codemod.proposed').map((e) => [e.file, e.edits, e.rejected, e.model]), [['src/render.js', 1, 0, 'coder']]);
  });

  it('retries once with the validation errors and rejects marked.parse without a verified quote for it', async () => {
    const { ctx } = await setup({
      rules: [
        {
          match: { purpose: 'codemod' },
          replies: [{ json: { edits: [IMPORT, PARSE, { ...IMPORT, search: "const marked = require('markdown');" }] } }, { json: { edits: [IMPORT, PARSE] } }],
        },
      ],
    });
    const result = await proposeCodemod(brief([item()]), ctx);
    assert.equal(ctx.provider.calls.length, 2, 'one feedback retry');
    const retry = ctx.provider.calls[1]?.messages.at(-1)?.content ?? '';
    assert.match(retry, /Some edits were rejected/);
    assert.match(retry, /introduces marked\.parse, which no verified evidence quote/);
    assert.match(retry, /not found in the file/);
    assert.deepEqual(result.patches[0]?.edits, [IMPORT]);
    assert.match(result.patches[0]?.newContent ?? '', /return marked\(userMarkdown, \{/, 'marked(...) stays: still callable in v4');
    assert.deepEqual(
      result.rejected.map((r) => r.reason),
      ['the edit introduces marked.parse, which no verified evidence quote for this file mentions'],
    );
  });

  it('keeps the semicolon of a one-line statement the model dropped', async () => {
    const { ctx } = await setup({ rules: [{ match: { purpose: 'codemod' }, replies: [{ json: { edits: [{ ...IMPORT, replace: "const { marked } = require('marked')" }] } }] }] });
    const result = await proposeCodemod(brief([item()]), ctx);
    assert.deepEqual(result.patches[0]?.edits, [IMPORT]);
  });

  it('allows marked.parse when a verified, applicable quote names it', async () => {
    const { ctx } = await setup({ rules: [{ match: { purpose: 'codemod' }, replies: [{ json: { edits: [IMPORT, PARSE] } }] }] });
    const result = await proposeCodemod(brief([item(), item({ change: 'Use marked.parse', evidenceQuote: SCRIPT_TAG_LINE, oldApi: 'marked(...)', newApi: 'marked.parse(...)' })]), ctx);
    assert.deepEqual(result.patches[0]?.edits, [IMPORT, PARSE]);
  });

  it('rejects edits on code that does not use the package, and new dependencies', async () => {
    const { ctx } = await setup({
      rules: [
        {
          match: { purpose: 'codemod' },
          replies: [
            {
              json: {
                edits: [
                  { file: 'src/render.js', search: 'function escapeHtml(text) {', replace: 'function escapeHtml(value) {', why: 'rename' },
                  { file: 'src/render.js', search: "const marked = require('marked');", replace: "const { marked } = require('marked');\nconst DOMPurify = require('dompurify');", why: 'sanitize' },
                ],
              },
            },
          ],
          repeat: true,
        },
      ],
    });
    const result = await proposeCodemod(brief([item()]), ctx);
    assert.deepEqual(result.patches, []);
    const why = result.rejected.map((r) => r.reason);
    assert.ok(why.includes('the edit changes code that does not use marked'));
    assert.ok(why.includes('the edit adds a dependency on dompurify, which the project does not declare'));
    assert.ok(result.manualChecklist && result.manualChecklist.length > 0, 'nothing survived: the manual checklist');
  });

  it('rejects an edit that duplicates a block (brackets differ) and keeps the good one', async () => {
    const duplicate = {
      file: 'src/render.js',
      search: '  return marked(userMarkdown, {',
      replace: '  return marked(userMarkdown, {\n  gfm: options.gfm !== false,\n  breaks: Boolean(options.breaks),\n});',
      why: 'default export',
    };
    const { ctx } = await setup({ rules: [{ match: { purpose: 'codemod' }, replies: [{ json: { edits: [IMPORT, duplicate] } }, { json: { edits: [IMPORT, duplicate] } }] }] });
    const result = await proposeCodemod(brief([item()]), ctx);
    assert.deepEqual(result.patches[0]?.edits, [IMPORT]);
    assert.match(result.rejected[0]?.reason ?? '', /opens or closes brackets differently/);
    assert.match(ctx.provider.calls[1]?.messages.at(-1)?.content ?? '', /opens or closes brackets differently/, 'the retry says why');
  });

  it('never offers a diff that does not parse (node --check on a temporary copy)', async () => {
    const broken = { file: 'src/render.js', search: "const marked = require('marked');", replace: "const { marked } == require('marked');", why: 'typo' };
    const { dir, ctx } = await setup({ rules: [{ match: { purpose: 'codemod' }, replies: [{ json: { edits: [broken] } }], repeat: true }] });
    const before = await readFile(path.join(dir, 'src/render.js'), 'utf8');
    const result = await proposeCodemod(brief([item()]), ctx);
    assert.deepEqual(result.patches, []);
    assert.ok(result.rejected.some((r) => /the edit leaves a syntax error: SyntaxError/.test(r.reason)), JSON.stringify(result.rejected));
    assert.equal(await readFile(path.join(dir, 'src/render.js'), 'utf8'), before, 'the project file is never touched');
  });

  it('drafts nothing from unverified or non-applicable items and returns the checklist', async () => {
    const { ctx } = await setup({ rules: [] });
    const result = await proposeCodemod(brief([item({ verified: false }), item({ evidenceQuote: SCRIPT_TAG_LINE, appliesToProject: 'no', affectedFiles: [] })]), ctx);
    assert.equal(ctx.provider.calls.length, 0);
    assert.deepEqual(result.patches, []);
    assert.match(result.manualChecklist?.[0] ?? '', /The default export was removed \(src\/render\.js\).*\[unverified/);
  });

  it('does not edit code for a deprecation that removes nothing', async () => {
    const { ctx } = await setup({ rules: [] });
    const deprecation = item({ change: 'sanitize is deprecated', evidenceQuote: 'Deprecate `sanitize` and `sanitizer` options', oldApi: 'sanitize: true', newApi: '' });
    const result = await proposeCodemod(brief([deprecation]), ctx);
    assert.equal(ctx.provider.calls.length, 0);
    assert.deepEqual(result.patches, []);
    assert.match(result.manualChecklist?.[0] ?? '', /sanitize is deprecated/);
  });

  it('refuses files outside the project and missing files without asking the model', async () => {
    const { ctx } = await setup({ rules: [] });
    const result = await proposeCodemod(brief([item({ affectedFiles: ['../elsewhere/render.js', 'src/missing.js'] })]), ctx);
    assert.equal(ctx.provider.calls.length, 0);
    assert.deepEqual(result.rejected.map((r) => [r.file, r.reason]), [
      ['../elsewhere/render.js', 'the file is outside the project'],
      ['src/missing.js', 'the file does not exist'],
    ]);
  });

  it('survives a model that does not answer JSON (retry, then the checklist)', async () => {
    const { ctx } = await setup({ rules: [{ match: { purpose: 'codemod' }, replies: [{ content: 'Sure! Here is the change.' }], repeat: true }] });
    const result = await proposeCodemod(brief([item()]), ctx);
    assert.equal(ctx.provider.calls.length, 2);
    assert.match(ctx.provider.calls[1]?.messages.at(-1)?.content ?? '', /not a valid JSON object/);
    assert.deepEqual(result.patches, []);
    assert.ok(result.rejected.some((r) => /did not return valid JSON/.test(r.reason)));
    assert.ok(result.manualChecklist);
  });
});

describe('writePatches', () => {
  async function patchFor(dir: string, file: string, next: string): Promise<FilePatch> {
    const bytes = await readFile(path.join(dir, file));
    return { file, edits: [], diff: '', beforeHash: sha(bytes), newContent: next };
  }

  it('writes atomically, keeps the file mode and returns the before and after hashes', async () => {
    const app = await tempApp();
    cleanup = app.cleanup;
    const file = path.join(app.dir, 'src/render.js');
    await chmod(file, 0o755);
    const next = (await readFile(file, 'utf8')).replace("const marked = require('marked');", "const { marked } = require('marked');");
    const patch = await patchFor(app.dir, 'src/render.js', next);
    const written = await writePatches([patch], app.dir);
    assert.deepEqual(written, [{ file: 'src/render.js', beforeHash: patch.beforeHash, afterHash: sha(next) }]);
    assert.equal(await readFile(file, 'utf8'), next);
    assert.equal((await stat(file)).mode & 0o777, 0o755);
  });

  it('writes nothing when a file changed after the diff was made', async () => {
    const app = await tempApp();
    cleanup = app.cleanup;
    const a = await patchFor(app.dir, 'src/cli.js', '// changed\n');
    const b = await patchFor(app.dir, 'src/render.js', '// changed too\n');
    await writeFile(path.join(app.dir, 'src/render.js'), '// edited by hand\n');
    await assert.rejects(writePatches([a, b], app.dir), /src\/render\.js changed after the diff was made/);
    assert.notEqual(await readFile(path.join(app.dir, 'src/cli.js'), 'utf8'), '// changed\n', 'the first file is untouched too');
  });

  it('restores the files already written when a later write fails', async () => {
    const app = await tempApp();
    cleanup = async () => {
      await chmod(path.join(app.dir, 'locked'), 0o755).catch(() => {});
      await app.cleanup();
    };
    await mkdir(path.join(app.dir, 'locked'));
    await writeFile(path.join(app.dir, 'locked', 'x.js'), 'module.exports = 1;\n');
    const original = await readFile(path.join(app.dir, 'src/render.js'), 'utf8');
    const first = await patchFor(app.dir, 'src/render.js', '// new render\n');
    const second = await patchFor(app.dir, 'locked/x.js', 'module.exports = 2;\n');
    await chmod(path.join(app.dir, 'locked'), 0o555);
    await assert.rejects(writePatches([first, second], app.dir));
    assert.equal(await readFile(path.join(app.dir, 'src/render.js'), 'utf8'), original);
  });

  it('refuses a path outside the project', async () => {
    const app = await tempApp();
    cleanup = app.cleanup;
    await assert.rejects(writePatches([{ file: '../escape.js', edits: [], diff: '', beforeHash: 'x', newContent: '' }], app.dir), /outside the project/);
  });
});

describe('checkSyntax', () => {
  it('runs node --check on .js/.mjs/.cjs files and leaves other files out', async () => {
    const app = await tempApp();
    cleanup = app.cleanup;
    await writeFile(path.join(app.dir, 'src/broken.js'), "'use strict';\nconst { marked } = require('marked'\nmodule.exports = marked;\n");
    await writeFile(path.join(app.dir, 'src/esm.mjs'), "import { marked } from 'marked';\nexport default marked;\n");
    await writeFile(path.join(app.dir, 'src/types.ts'), 'export type X = { a: string };\n');
    const results = await checkSyntax(['src/render.js', 'src/broken.js', 'src/esm.mjs', 'src/types.ts'], app.dir);
    assert.deepEqual(results.map((r) => [r.file, r.ok]), [
      ['src/render.js', true],
      ['src/broken.js', false],
      ['src/esm.mjs', true],
    ]);
    assert.match(results[1]?.error ?? '', /SyntaxError: .*\(src\/broken\.js:2\)$/);
  });
});
