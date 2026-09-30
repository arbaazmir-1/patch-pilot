const { readFileSync } = require('node:fs');
const marked = require('marked');

marked.setOptions({ gfm: true, breaks: true, sanitize: true });

function renderMarkdown(markdown) {
  return marked(markdown);
}

const file = process.argv[2];
const input = file ? readFileSync(file, 'utf8') : readFileSync(0, 'utf8');
process.stdout.write(renderMarkdown(input));

module.exports = { renderMarkdown };
