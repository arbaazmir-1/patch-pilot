# Marked

- built for speed
- works in a browser, on a server, or from a command line interface (CLI)

## Installation

**CLI:** `npm install -g marked`

## Usage

**Node.js**

```js
const { marked } = require('marked');
const html = marked.parse('# Marked in Node.js');
```

**Browser**

```html
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script>
  document.getElementById('content').innerHTML = marked.parse('# Marked in the browser');
</script>
```

## Compatibility

**Node.js:** Only current and LTS Node.js versions are supported.

## License

MIT
