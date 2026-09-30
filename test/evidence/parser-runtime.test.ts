import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseModule, typescript } from '../../src/evidence/ast.ts';

// a missing api fails silently into the regex fallback, so check it loudly here
const SRC = fileURLToPath(new URL('../../src', import.meta.url));

async function sourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await sourceFiles(full)));
    else if (entry.name.endsWith('.ts')) out.push(full);
  }
  return out;
}

describe('runtime typescript parser', () => {
  it('loads the ts 6 api, not the ts 7 version stub', () => {
    const T = typescript();
    assert.equal(typeof T.createSourceFile, 'function');
    assert.match(T.version, /^6\./);
  });

  it('has every api function the source calls', async () => {
    const T = typescript() as unknown as Record<string, unknown>;
    const used = new Set<string>();
    for (const file of await sourceFiles(SRC)) {
      const text = await readFile(file, 'utf8');
      for (const m of text.matchAll(/\b(?:T|ts)\.([a-zA-Z]+)\(/g)) used.add(m[1]!);
    }
    assert.ok(used.size > 20, `found only ${used.size} calls`);
    const missing = [...used].filter((name) => typeof T[name] !== 'function');
    assert.deepEqual(missing, []);
  });

  it('parses modern syntax through the ast path', () => {
    const outcome = parseModule(
      [
        "import type { Options } from 'marked';",
        "import { marked } from 'marked';",
        'const opts = { gfm: true } satisfies Partial<Options>;',
        'export const render = (md: string) => marked.parse(md, opts);',
      ].join('\n'),
      'src/render.ts',
    );
    assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.message);
  });
});
