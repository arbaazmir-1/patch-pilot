const { readFile } = require('node:fs/promises');
const path = require('node:path');

async function main() {
  const file = process.argv[2] || path.join(__dirname, '..', 'package.json');
  const text = await readFile(file, 'utf8');
  const lines = text.split('\n').length;
  const words = text.split(/\s+/).filter(Boolean).length;
  console.log(`${path.basename(file)}: ${lines} lines, ${words} words, ${Buffer.byteLength(text)} bytes`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
