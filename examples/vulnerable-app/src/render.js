'use strict';

// untrusted markdown from file or stdin

const marked = require('marked');

function renderMarkdown(userMarkdown, options = {}) {
  return marked(userMarkdown, {
    gfm: options.gfm !== false,
    breaks: Boolean(options.breaks),
    sanitize: options.sanitize !== false,
  });
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}

function renderDocument(title, userMarkdown, options = {}) {
  const body = renderMarkdown(userMarkdown, options);
  return `<!doctype html>\n<html>\n<head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head>\n<body>\n${body}</body>\n</html>\n`;
}

module.exports = { renderMarkdown, renderDocument };
