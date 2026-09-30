import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { it } from 'node:test';
import { fileURLToPath } from 'node:url';

// no U+2014 anywhere in the repo
const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const EM_DASH = String.fromCharCode(0x2014);
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.patch-pilot', 'coverage']);

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walk(path.join(dir, entry.name));
    } else if (entry.isFile() && !entry.name.startsWith('.env')) {
      // local secrets, never read
      yield path.join(dir, entry.name);
    }
  }
}

it('no text file in the repository contains an em dash (U+2014)', async () => {
  const offenders: string[] = [];
  let scanned = 0;
  for await (const file of walk(ROOT)) {
    const bytes = await readFile(file);
    if (bytes.includes(0)) continue; // binary
    scanned += 1;
    const lines = bytes.toString('utf8').split('\n');
    lines.forEach((line, i) => {
      if (line.includes(EM_DASH)) offenders.push(`${path.relative(ROOT, file)}:${i + 1}`);
    });
  }
  assert.ok(scanned > 20, `scanned ${scanned} files`);
  assert.deepEqual(offenders, [], `em dashes found (use a colon, comma, period, parentheses or the middle dot):\n${offenders.join('\n')}`);
});
