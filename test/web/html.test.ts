import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  BREAKING_KEYWORDS,
  decodeEntities,
  extractTitle,
  htmlToText,
  isLikelyJsRendered,
  keywordWindow,
  looksLikeHtml,
  normalizeText,
  queryKeywords,
  queryWeights,
  snippetAround,
} from '../../src/util/html.ts';
import { fixture, fixtureJson } from './helpers.ts';

const EM_DASH = String.fromCharCode(0x2014);

describe('htmlToText on a documentation page', () => {
  const html = fixture('docs-page.html');
  const text = htmlToText(html);

  it('keeps headings, list structure, tables and code as plain lines', () => {
    assert.match(text, /^# Upgrading to v4$/m);
    assert.match(text, /^## Breaking changes$/m);
    assert.match(text, /^- Default export removed\. Use `const \{ marked \} = require\('marked'\)` instead\.$/m);
    assert.match(text, /^ {2}1\. Replace `\/lib\/marked\.js` with `\/marked\.min\.js`\.$/m);
    assert.match(text, /^ {2}2\. Call `marked\.parse\(\)` instead of `marked\(\)`\.$/m);
    assert.match(text, /^Option \| Type \| Default$/m);
    assert.match(text, /^`gfm` \| boolean \| true$/m);
    assert.match(text, /^Unescaped less-than: 3 < 4 stays readable\.$/m);
  });

  it('keeps the line breaks and indentation of <pre> blocks', () => {
    assert.match(text, /^function render\(md\) \{\n {2}const \{ marked \} = require\('marked'\);\n {2}return marked\.parse\(md\);\n\}$/m);
    assert.match(text, /Line\nbreak here\./);
  });

  it('decodes entities and never emits an em dash', () => {
    assert.match(text, /Tom & Jerry say it's fine & they don\u2019t mind\./);
    assert.match(text, /The `<script>` build moved/);
    assert.equal(text.includes(EM_DASH), false);
    assert.equal(extractTitle(html), 'Upgrading to v4 - Example Docs');
  });

  it('drops scripts, styles, head, comments, hidden elements, buttons and page chrome', () => {
    for (const noise of ['SCRIPT TEXT', 'STYLE TEXT', 'META DESCRIPTION', 'COMMENT TEXT', 'HIDDEN TEXT', 'ARIA HIDDEN', 'BUTTON TEXT', 'NOSCRIPT', 'TEMPLATE TEXT', 'NAV LINK', 'HEADER TEXT', 'SIDEBAR AD', 'FOOTER TEXT', 'fake']) {
      assert.equal(text.includes(noise), false, `${noise} leaked into the text`);
    }
  });

  it('keeps chrome when asked and can keep link targets', () => {
    const full = htmlToText(html, { dropChrome: false, keepLinks: true });
    assert.match(full, /Guide NAV LINK/);
    assert.match(full, /FOOTER TEXT/);
    assert.match(full, /full migration guide \(https:\/\/example\.com\/migration\) for details/);
    assert.equal(full.includes('SCRIPT TEXT'), false);
    assert.equal(full.includes('HIDDEN TEXT'), false);
  });
});

describe('htmlToText on a saved GitHub release page', () => {
  const html = fixture('github-release-v4.0.0.html');
  const text = htmlToText(html);
  const body = fixtureJson<{ body: string }>('github-release-v4.0.0.json').body;

  it('extracts the release notes verbatim from 120 KB of page', () => {
    const quote = "Default export removed. Use `import { marked } from 'marked'` or `const { marked } = require('marked')` instead.";
    assert.ok(text.includes(quote));
    assert.ok(body.includes(quote), 'the quote is also verbatim in the REST body');
    assert.match(text, /^### BREAKING CHANGES$/m);
    assert.match(text, /`\/lib\/marked\.js` removed\. Use `\/marked\.min\.js` in script tag instead\./);
    assert.ok(text.length < 5000, `text is ${text.length} chars`);
    assert.equal(text.includes('SCRIPT TEXT SHOULD NOT APPEAR'), false);
    assert.equal(isLikelyJsRendered(html, text), false);
    assert.equal(extractTitle(html), 'Release v4.0.0 \u00b7 markedjs/marked \u00b7 GitHub');
    assert.equal(looksLikeHtml(html), true);
    assert.equal(looksLikeHtml(body), false);
  });
});

describe('JavaScript-rendered pages', () => {
  it('flags a large page with almost no text', () => {
    const shell = `<!doctype html><html><head><title>App</title><script>${'var a=1;'.repeat(400)}</script></head><body><div id="root"></div><noscript>You need to enable JavaScript to run this app.</noscript></body></html>`;
    const text = htmlToText(shell);
    assert.ok(text.length < 200);
    assert.equal(isLikelyJsRendered(shell, text), true);
  });

  it('does not flag a small static page or a page with real text', () => {
    const small = '<html><body><p>Moved to the new docs.</p></body></html>';
    assert.equal(isLikelyJsRendered(small, htmlToText(small)), false);
    const html = fixture('docs-page.html');
    assert.equal(isLikelyJsRendered(html, htmlToText(html)), false);
  });
});

describe('entities and whitespace', () => {
  it('decodes named, decimal and hex references', () => {
    assert.equal(decodeEntities('&lt;a&gt; &amp;&amp; &quot;q&quot; &#39;s&#39; &#x41;&#66; &hellip;'), '<a> && "q" \'s\' AB \u2026');
    assert.equal(decodeEntities('AT&T &copy2024 &unknown; &amp'), 'AT&T &copy2024 &unknown; &');
    assert.equal(decodeEntities('&#0; &#xD800; &#1114112;'), '\ufffd \ufffd \ufffd');
    assert.equal(decodeEntities('a&nbsp;b'), 'a b');
  });

  it('normalises line endings, spaces, zero-width characters and em dashes', () => {
    const input = `a\r\nb\u00a0\u00a0c\u200b\n\n\n\nd ${EM_DASH} e${EM_DASH}f   \n   indented  line`;
    assert.equal(normalizeText(input), 'a\nb c\n\nd - e - f\n   indented line');
  });
});

describe('keywordWindow', () => {
  it('returns the whole text when it fits', () => {
    assert.equal(keywordWindow('short text', ['text'], 100), 'short text');
  });

  it('returns the start of the text when nothing matches', () => {
    const text = Array.from({ length: 200 }, (_, i) => `line ${i} of filler`).join('\n');
    const out = keywordWindow(text, ['absent'], 300);
    assert.ok(out.length <= 300);
    assert.ok(out.startsWith('line 0 of filler'));
    assert.ok(out.endsWith('\n...'));
  });

  it('centres the window on the densest cluster of keywords', () => {
    const filler = (n: number): string => Array.from({ length: n }, (_, i) => `filler sentence number ${i}.`).join(' ');
    const text = [
      filler(40),
      'An export here.',
      filler(60),
      'CLUSTER: the default export was removed; use the named export and require it instead.',
      filler(60),
      'Another export there.',
      filler(40),
    ].join('\n');
    const keywords = queryKeywords('default export require');
    const out = keywordWindow(text, keywords, 600, { weights: queryWeights(keywords) });
    assert.ok(out.length <= 600, `${out.length}`);
    assert.ok(out.includes('CLUSTER: the default export was removed'));
    assert.ok(out.startsWith('...\n'));
    assert.ok(out.endsWith('\n...'));
    assert.equal(out.includes('An export here.'), false);
  });

  it('lets heavier keywords win', () => {
    const pad = 'x'.repeat(2000);
    const text = `${pad}\nalpha beta gamma\n${pad}\nthe default export\n${pad}`;
    const light = keywordWindow(text, ['alpha', 'beta', 'default export'], 300);
    assert.ok(light.includes('alpha beta'));
    const heavy = keywordWindow(text, ['alpha', 'beta', 'default export'], 300, { weights: [1, 1, 5] });
    assert.ok(heavy.includes('the default export'));
  });

  it('matches case-insensitively by default', () => {
    const text = `${'y'.repeat(3000)} BREAKING CHANGES here ${'y'.repeat(3000)}`;
    assert.ok(keywordWindow(text, ['breaking changes'], 500).includes('BREAKING CHANGES here'));
    assert.equal(keywordWindow(text, ['breaking changes'], 500, { ignoreCase: false }).includes('BREAKING'), false);
  });

  it('spread mode joins windows around separate hits', () => {
    const pad = 'z'.repeat(3000);
    const text = `${pad} removed the foo option ${pad} renamed bar to baz ${pad}`;
    const out = keywordWindow(text, ['removed', 'renamed'], 700, { mode: 'spread', radius: 60 });
    assert.ok(out.length <= 700, `${out.length}`);
    assert.ok(out.includes('removed the foo option'));
    assert.ok(out.includes('renamed bar to baz'));
    assert.ok(out.includes('\n...\n'));
  });

  it('centres on the breaking change in a real release body', () => {
    const body = fixtureJson<{ body: string }>('github-release-v4.0.0.json').body;
    const keywords = queryKeywords('default export');
    const out = keywordWindow(body, keywords, 220, { weights: queryWeights(keywords) });
    assert.ok(out.length <= 220);
    assert.match(out, /Default export removed/);
  });
});

describe('query keywords and snippets', () => {
  it('keeps significant terms, versions and adjacent pairs', () => {
    const k = queryKeywords('How to migrate marked 4.0.0 breaking changes: the default export');
    for (const term of ['migrate', 'marked', '4.0.0', 'breaking', 'changes', 'default', 'export', 'default export', 'breaking changes']) {
      assert.ok(k.includes(term), `${term} in ${JSON.stringify(k)}`);
    }
    for (const stop of ['how', 'to', 'the']) assert.equal(k.includes(stop), false);
    assert.deepEqual(queryWeights(['a', 'b c']), [1, 2]);
    assert.ok(BREAKING_KEYWORDS.includes('default export'));
  });

  it('builds single-line snippets of at most the requested size', () => {
    const content = `${'intro words '.repeat(500)}\nThe default export was removed in v4.\n${'outro words '.repeat(2500)}`;
    const k = queryKeywords('default export');
    const snippet = snippetAround(content, k, 300, queryWeights(k));
    assert.ok(snippet.length <= 300);
    assert.equal(snippet.includes('\n'), false);
    assert.match(snippet, /default export was removed/);
  });
});
