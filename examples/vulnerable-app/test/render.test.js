'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { renderMarkdown, renderDocument } = require('../src/render');

test('renders headings and emphasis', () => {
  const html = renderMarkdown('# Title\n\nSome *emphasis* here.');
  assert.match(html, /<h1[^>]*>Title<\/h1>/);
  assert.match(html, /<em>emphasis<\/em>/);
});

test('wraps the body in an HTML document with an escaped title', () => {
  const html = renderDocument('A <b> title', 'text');
  assert.match(html, /<title>A &lt;b&gt; title<\/title>/);
  assert.match(html, /<p>text<\/p>/);
});
