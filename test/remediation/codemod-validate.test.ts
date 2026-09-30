import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { applyEdits, locateSearch, MAX_SEARCH_LINES, moduleTypeOf, renderDiff, validateEdits, type EditValidationOptions } from '../../src/remediation/codemod.ts';
import type { CodeEdit } from '../../src/types.ts';
import { APP_FIXTURE } from './migration-helpers.ts';

const FILE = 'src/render.js';
const CONTENT = readFileSync(path.join(APP_FIXTURE, FILE), 'utf8');
const ROOT = '/tmp/pp-project';
const OPTIONS: EditValidationOptions = { projectRoot: ROOT, affectedFiles: [FILE], moduleType: 'commonjs' };
const IMPORT_EDIT: CodeEdit = { file: FILE, search: "const marked = require('marked');", replace: "const { marked } = require('marked');", why: 'default export removed' };

function edit(partial: Partial<CodeEdit>): CodeEdit {
  return { ...IMPORT_EDIT, ...partial };
}

function reasons(result: ReturnType<typeof validateEdits>): string[] {
  return result.rejected.map((r) => r.reason);
}

describe('moduleTypeOf', () => {
  it('uses the extension first, then the package.json type', () => {
    assert.equal(moduleTypeOf('src/a.mjs', 'commonjs'), 'module');
    assert.equal(moduleTypeOf('src/a.cjs', 'module'), 'commonjs');
    assert.equal(moduleTypeOf('src/a.js', 'module'), 'module');
    assert.equal(moduleTypeOf('src/a.js', 'commonjs'), 'commonjs');
    assert.equal(moduleTypeOf('src/a.js', undefined), 'commonjs', 'no type field: Node treats .js as CommonJS');
    assert.equal(moduleTypeOf('src/a.ts', 'commonjs'), 'module', 'TypeScript is written with import/export');
    assert.equal(moduleTypeOf('src/a.cts', undefined), 'commonjs');
    assert.equal(moduleTypeOf('src/a.mts', undefined), 'module');
  });
});

describe('validateEdits', () => {
  it('accepts an exact match', () => {
    const result = validateEdits(FILE, CONTENT, [IMPORT_EDIT], OPTIONS);
    assert.deepEqual(result.rejected, []);
    assert.deepEqual(result.valid, [IMPORT_EDIT]);
  });

  it('accepts a whitespace- and quote-normalised match and maps it back to the original span', () => {
    const fuzzy = edit({ search: '   const   marked = require("marked");  \n', replace: 'const { marked } = require("marked");' });
    const result = validateEdits(FILE, CONTENT, [fuzzy], OPTIONS);
    assert.deepEqual(reasons(result), []);
    const where = locateSearch(CONTENT, fuzzy.search);
    assert.equal(where.mode, 'normalized');
    assert.equal(CONTENT.slice(where.spans[0]?.start, where.spans[0]?.end), "const marked = require('marked');");
    const applied = applyEdits(CONTENT, result.valid);
    assert.deepEqual(applied.failed, []);
    assert.match(applied.content, /\n\/\/ renderer sees untrusted input\.\nconst \{ marked \} = require\("marked"\);\n\nfunction renderMarkdown/);
    const compact = locateSearch(CONTENT, 'const marked=require("marked") ;');
    assert.equal(compact.mode, 'compact', 'spaces ignored entirely as the last resort');
    assert.equal(CONTENT.slice(compact.spans[0]?.start, compact.spans[0]?.end), "const marked = require('marked');");
  });

  it('re-indents a multi-line replacement found by the normalised match', () => {
    const search = 'return marked(userMarkdown, {\ngfm: options.gfm !== false,';
    const replace = 'return marked(userMarkdown, {\n  async: false,\ngfm: options.gfm !== false,';
    const applied = applyEdits(CONTENT, [edit({ search, replace })]);
    assert.deepEqual(applied.failed, []);
    assert.match(applied.content, /\n {2}return marked\(userMarkdown, \{\n {4}async: false,\n {4}gfm: options\.gfm !== false,\n {4}breaks:/);
    const changed = applyEdits(CONTENT, [edit({ search: 'return marked(userMarkdown, {\ngfm: options.gfm !== false,', replace: 'return marked(userMarkdown, {\ngfm: true,' })]);
    assert.match(changed.content, /\n {2}return marked\(userMarkdown, \{\n {4}gfm: true,\n {4}breaks:/, 'a changed line keeps the indentation of its position');
  });

  it('rejects a search that matches more than once or not at all', () => {
    const many = validateEdits(FILE, CONTENT, [edit({ search: 'options', replace: 'opts' })], OPTIONS);
    assert.match(reasons(many)[0] ?? '', /matches \d+ places; include more surrounding lines/);
    const none = validateEdits(FILE, CONTENT, [edit({ search: "const marked = require('markdown-it');" })], OPTIONS);
    assert.match(reasons(none)[0] ?? '', /not found in the file/);
  });

  it('rejects overlapping edits (the later one)', () => {
    const second = edit({ search: "renderer sees untrusted input.\nconst marked = require('marked');", replace: "renderer sees untrusted input.\nconst { marked: md } = require('marked');" });
    const result = validateEdits(FILE, CONTENT, [IMPORT_EDIT, second], OPTIONS);
    assert.equal(result.valid.length, 1);
    assert.match(reasons(result)[0] ?? '', /overlaps an earlier edit/);
  });

  it('rejects import/export syntax in a CommonJS file, allows it in an ES module', () => {
    const esm = edit({ replace: "import { marked } from 'marked';" });
    assert.match(reasons(validateEdits(FILE, CONTENT, [esm], OPTIONS))[0] ?? '', /adds import\/export syntax .* CommonJS/);
    const exporting = edit({ search: 'module.exports = { renderMarkdown, renderDocument };', replace: 'export { renderMarkdown, renderDocument };' });
    assert.match(reasons(validateEdits(FILE, CONTENT, [exporting], OPTIONS))[0] ?? '', /CommonJS/);
    assert.deepEqual(reasons(validateEdits(FILE, CONTENT, [esm], { ...OPTIONS, moduleType: 'module' })), []);
    const dynamicImport = edit({ replace: "const markedPromise = import('marked');" });
    assert.deepEqual(reasons(validateEdits(FILE, CONTENT, [dynamicImport], OPTIONS)), [], 'dynamic import() is valid CommonJS');
  });

  it('rejects files outside the project, outside the brief, and edits for another file', () => {
    const outside = validateEdits(FILE, CONTENT, [edit({ file: '../other/render.js' })], OPTIONS);
    assert.match(reasons(outside)[0] ?? '', /outside the project/);
    const absolute = validateEdits(FILE, CONTENT, [edit({ file: '/etc/passwd' })], OPTIONS);
    assert.match(reasons(absolute)[0] ?? '', /outside the project/);
    const notListed = validateEdits(FILE, CONTENT, [edit({ file: 'src/cli.js' })], OPTIONS);
    assert.match(reasons(notListed)[0] ?? '', /not one of the files the brief lists/);
    const otherAffected = validateEdits(FILE, CONTENT, [edit({ file: 'src/cli.js' })], { ...OPTIONS, affectedFiles: [FILE, 'src/cli.js'] });
    assert.match(reasons(otherAffected)[0] ?? '', /only src\/render\.js is edited here/);
    const spelled = validateEdits(FILE, CONTENT, [edit({ file: './src/render.js' }), edit({ file: `${ROOT}/src/render.js`, search: 'return marked(', replace: 'return marked.parse(' })], OPTIONS);
    assert.deepEqual(reasons(spelled), [], './ and absolute spellings of the same file are accepted');
    assert.equal(validateEdits(FILE, CONTENT, [edit({ file: '' })], OPTIONS).valid[0]?.file, FILE, 'an empty file means this file');
  });

  it(`rejects a search longer than ${MAX_SEARCH_LINES} lines`, () => {
    const lines = CONTENT.split('\n').slice(0, MAX_SEARCH_LINES + 1).join('\n');
    const result = validateEdits(FILE, CONTENT, [edit({ search: lines, replace: `${lines}\n// x` })], OPTIONS);
    assert.match(reasons(result)[0] ?? '', /search has 21 lines; use at most 20/);
    const twenty = CONTENT.split('\n').slice(0, MAX_SEARCH_LINES).join('\n');
    assert.deepEqual(reasons(validateEdits(FILE, CONTENT, [edit({ search: twenty, replace: twenty.replace("require('marked')", "require('marked').marked") })], OPTIONS)), []);
  });

  it('rejects a replace that changes nothing, or only whitespace and quotes', () => {
    assert.match(reasons(validateEdits(FILE, CONTENT, [edit({ replace: IMPORT_EDIT.search })], OPTIONS))[0] ?? '', /identical/);
    assert.match(reasons(validateEdits(FILE, CONTENT, [edit({ replace: 'const  marked = require("marked");' })], OPTIONS))[0] ?? '', /only changes whitespace or quotes/);
    assert.match(reasons(validateEdits(FILE, CONTENT, [edit({ search: '   ' })], OPTIONS))[0] ?? '', /search is empty/);
  });

  it('orders edits top to bottom and re-validates each after the earlier ones', () => {
    const call = edit({ search: '  return marked(userMarkdown, {', replace: '  return marked.parse(userMarkdown, {' });
    const result = validateEdits(FILE, CONTENT, [call, IMPORT_EDIT], OPTIONS);
    assert.deepEqual(result.valid, [IMPORT_EDIT, call], 'top to bottom');
    const applied = applyEdits(CONTENT, result.valid);
    assert.deepEqual(applied.failed, []);
    assert.match(applied.content, /const \{ marked \} = require\('marked'\);[\s\S]*return marked\.parse\(userMarkdown, \{/);

    // first edit duplicates the next search
    const first = edit({ replace: "const { marked } = require('marked');\n// was: function renderMarkdown(userMarkdown, options = {}) {" });
    const later = edit({ search: 'function renderMarkdown(userMarkdown, options = {}) {', replace: 'function renderMarkdown(userMarkdown, options = { gfm: true }) {' });
    const ambiguous = validateEdits(FILE, CONTENT, [first, later], OPTIONS);
    assert.deepEqual(ambiguous.valid, [first]);
    assert.match(reasons(ambiguous)[0] ?? '', /after the earlier edits, search matches 2 places/);
  });
});

describe('applyEdits and renderDiff', () => {
  it('preserves CRLF line endings, including in the replaced lines', () => {
    const crlf = CONTENT.replace(/\n/g, '\r\n');
    const result = validateEdits(FILE, crlf, [edit({ search: "// renderer sees untrusted input.\nconst marked = require('marked');", replace: "// renderer sees untrusted input.\nconst { marked } = require('marked');" })], OPTIONS);
    assert.deepEqual(reasons(result), []);
    const applied = applyEdits(crlf, result.valid);
    assert.deepEqual(applied.failed, []);
    assert.ok(applied.content.includes("// renderer sees untrusted input.\r\nconst { marked } = require('marked');\r\n"));
    assert.equal(/(?<!\r)\n/.test(applied.content), false, 'no bare LF');
    assert.equal(applied.content.split('\r\n').length, crlf.split('\r\n').length);
  });

  it('reports edits that no longer apply', () => {
    const applied = applyEdits(CONTENT, [IMPORT_EDIT, IMPORT_EDIT]);
    assert.equal(applied.failed.length, 1);
    assert.match(applied.failed[0]?.reason ?? '', /not found/);
  });

  it('renders a unified diff with the project-relative path in the header', () => {
    const after = applyEdits(CONTENT, [IMPORT_EDIT]).content;
    const diff = renderDiff('./src/render.js', CONTENT, after);
    const lines = diff.split('\n');
    assert.equal(lines[0], '--- src/render.js');
    assert.equal(lines[1], '+++ src/render.js');
    assert.match(lines[2] ?? '', /^@@ -\d+,\d+ \+\d+,\d+ @@$/);
    assert.ok(lines.includes("-const marked = require('marked');"));
    assert.ok(lines.includes("+const { marked } = require('marked');"));
    assert.equal(lines.filter((l) => l.startsWith('+') || l.startsWith('-')).length, 4, 'headers plus one changed line');
    const crlf = CONTENT.replace(/\n/g, '\r\n');
    assert.equal(renderDiff(FILE, crlf, applyEdits(crlf, [IMPORT_EDIT]).content).includes('\r'), false, 'no carriage returns in the diff');
  });
});
