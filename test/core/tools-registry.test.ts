import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  canonicalToolName,
  createToolRegistry,
  formatToolContent,
  STAGE_TOOLS,
  TOOL_DEFS,
  TOOL_NAMES,
  toolCallKey,
  truncateContent,
} from '../../src/investigation/tools/index.ts';
import type { ToolContext } from '../../src/types.ts';

const ctx = {
  projectRoot: '/tmp/project',
  config: {} as ToolContext['config'],
  caseFile: null,
  graph: null,
  cache: null,
  audit: null,
} satisfies ToolContext;

describe('stage subsets', () => {
  it('match the plan exactly', () => {
    assert.deepEqual(STAGE_TOOLS.recon, ['check_deps', 'read_file', 'get_changelog', 'search_code']);
    assert.deepEqual(STAGE_TOOLS.verdict, ['get_usage', 'read_file', 'get_advisory', 'search_code']);
    assert.deepEqual(STAGE_TOOLS.migration, ['web_search', 'fetch_page', 'get_changelog', 'get_usage', 'search_code', 'read_file']);
  });

  it('never expose web tools to the investigation loops', () => {
    for (const stage of ['recon', 'verdict'] as const) {
      assert.ok(!STAGE_TOOLS[stage].includes('web_search'));
      assert.ok(!STAGE_TOOLS[stage].includes('fetch_page'));
    }
  });

  it('registers every tool with a schema, example and truncation limit', () => {
    const registry = createToolRegistry();
    assert.deepEqual(registry.list().map((d) => d.name).sort(), [...TOOL_NAMES].sort());
    for (const def of TOOL_DEFS) {
      assert.equal(def.parameters.type, 'object');
      assert.ok(def.truncation.maxChars >= 1500, def.name);
      for (const key of def.parameters.required ?? []) assert.ok(key in def.example, `${def.name} example has ${key}`);
    }
    const readFile = registry.get('read_file');
    assert.equal(readFile?.truncation.defaultLines, 40);
    assert.equal(readFile?.truncation.maxLines, 120);
    assert.equal(registry.get('search_code')?.truncation.defaultResults, 10);
    assert.equal(registry.get('search_code')?.truncation.maxResults, 30);
  });

  it('builds Ollama tool schemas per stage', () => {
    const schemas = createToolRegistry().schemas('verdict');
    assert.deepEqual(schemas.map((s) => s.function.name), ['get_usage', 'read_file', 'get_advisory', 'search_code']);
    assert.equal(schemas[0]?.type, 'function');
    assert.deepEqual(schemas[0]?.function.parameters.required, ['package']);
  });
});

describe('argument normalisation', () => {
  const registry = createToolRegistry();
  const def = (name: string) => {
    const d = registry.get(name);
    assert.ok(d);
    return d;
  };

  it('maps the global aliases (pkg, package_name -> package; fn, function, method -> symbol)', () => {
    assert.deepEqual(registry.normalizeArgs(def('get_usage'), { pkg: 'lodash', fn: 'template' }).args, { package: 'lodash', symbol: 'template' });
    assert.deepEqual(registry.normalizeArgs(def('get_usage'), { package_name: 'lodash', method: 'merge' }).args, { package: 'lodash', symbol: 'merge' });
    const n = registry.normalizeArgs(def('get_usage'), { packageName: 'lodash', function: 'get' });
    assert.deepEqual(n.args, { package: 'lodash', symbol: 'get' });
    assert.deepEqual(n.renamed, [['packageName', 'package'], ['function', 'symbol']]);
  });

  it('applies per-tool aliases, case variants and coercion', () => {
    const n = registry.normalizeArgs(def('read_file'), { file: 'src/a.js', start_line: '5', end: 40, bogus: 1 });
    assert.deepEqual(n.args, { path: 'src/a.js', startLine: 5, endLine: 40 });
    assert.deepEqual(n.dropped, ['bogus']);
    const capped = registry.normalizeArgs(def('search_code'), { regex: 'merge\\(', maxResults: 99 });
    assert.equal(capped.args.maxResults, 30);
    assert.ok(capped.notes.some((note) => note.includes('capped at 30')));
    assert.deepEqual(registry.normalizeArgs(def('get_changelog'), { package: 'marked', from: '0.3.6', to: '4.0.10' }).args, {
      package: 'marked',
      fromVersion: '0.3.6',
      toVersion: '4.0.10',
    });
    assert.deepEqual(registry.normalizeArgs(def('get_usage'), { package: 'lodash', symbol: null }).args, { package: 'lodash' });
  });

  it('parses JSON-string arguments and a bare string for a single required parameter', () => {
    assert.deepEqual(registry.normalizeArgs(def('get_usage'), '{"package":"minimist"}').args, { package: 'minimist' });
    assert.deepEqual(registry.normalizeArgs(def('search_code'), 'merge(').args, { pattern: 'merge(' });
    assert.deepEqual(registry.normalizeArgs(def('get_changelog'), 'marked').errors, ['arguments must be a JSON object']);
    assert.deepEqual(registry.normalizeArgs(def('get_usage'), [1, 2]).errors, ['arguments must be a JSON object']);
  });

  it('fills a missing package from the focus', () => {
    const n = registry.normalizeArgs(def('get_usage'), { symbol: 'template' }, { focus: { package: 'lodash', version: '4.17.20' } });
    assert.deepEqual(n.args, { symbol: 'template', package: 'lodash' });
    assert.deepEqual(n.filled, ['package']);
  });
});

describe('execute', () => {
  it('answers an unknown tool with the stage tools and their schemas', async () => {
    const exec = await createToolRegistry().execute({ name: 'check_import', arguments: { package: 'lodash' } }, ctx, 'verdict');
    assert.equal(exec.status, 'unknown-tool');
    assert.equal(exec.ok, false);
    assert.equal(exec.tool, null);
    assert.match(exec.content, /Unknown tool "check_import"/);
    assert.match(exec.content, /get_usage\(package: string, symbol\?: string\)/);
    assert.match(exec.content, /"required":\["package"\]/);
    assert.ok(!exec.content.includes('web_search'));
  });

  it('refuses a tool outside the stage', async () => {
    const exec = await createToolRegistry().execute({ name: 'web_search', arguments: { query: 'x' } }, ctx, 'verdict');
    assert.equal(exec.status, 'not-in-stage');
    assert.match(exec.content, /not available in this step/);
  });

  it('answers a malformed call with the schema and an example', async () => {
    const exec = await createToolRegistry().execute({ name: 'get_usage', arguments: { symbol: 'template' } }, ctx, 'verdict');
    assert.equal(exec.status, 'invalid-args');
    assert.match(exec.content, /missing required "package"/);
    assert.match(exec.content, /Schema: \{"type":"object"/);
    assert.match(exec.content, /Example: get_usage\(\{"package":"lodash","symbol":"template"\}\)/);
  });

  it('resolves near-miss tool names', async () => {
    assert.equal(canonicalToolName('getUsage'), 'get_usage');
    assert.equal(canonicalToolName('get-usage'), 'get_usage');
    assert.equal(canonicalToolName('functions.read_file'), 'read_file');
    const registry = createToolRegistry();
    registry.setHandler('get_usage', async () => ({ ok: true, hint: 'ok', data: {} }));
    assert.equal((await registry.execute({ name: 'getUsage', arguments: { package: 'lodash' } }, ctx, 'verdict')).status, 'ok');
  });

  it('turns a stub handler (NotImplemented) into an error the model can work around', async () => {
    const registry = createToolRegistry();
    registry.setHandler('check_deps', async () => {
      throw new Error('NotImplemented: investigation/tools/checkDeps');
    });
    const exec = await registry.execute({ name: 'check_deps', arguments: { package: 'lodash' } }, ctx, 'recon');
    assert.equal(exec.status, 'error');
    assert.match(exec.content, /check_deps is not available yet/);
  });

  it('formats results as hint + JSON and truncates to the tool limit', async () => {
    const registry = createToolRegistry();
    registry.setHandler('get_usage', async (args) => ({
      ok: true,
      hint: `0 calls to _.template; project calls _.merge (3), _.get (2)`,
      data: { args, calls: [] },
    }));
    const exec = await registry.execute({ name: 'get_usage', arguments: { pkg: 'lodash', fn: 'template' } }, ctx, 'verdict');
    assert.equal(exec.ok, true);
    assert.equal(exec.content, '0 calls to _.template; project calls _.merge (3), _.get (2)\n{"args":{"package":"lodash","symbol":"template"},"calls":[]}');
    assert.deepEqual(exec.renamedArgs, [['pkg', 'package'], ['fn', 'symbol']]);

    registry.setHandler('get_advisory', async () => ({ ok: true, hint: 'long', text: 'x'.repeat(5000) }));
    const long = await registry.execute({ name: 'get_advisory', arguments: { id: 'GHSA-1' } }, ctx, 'verdict');
    assert.equal(long.truncated, true);
    assert.ok(long.content.length <= 2000);
    assert.match(long.content, /output truncated: \d+ more characters omitted; narrow the request/);

    registry.setHandler('search_code', async () => ({ ok: false, hint: 'fix the regex', error: 'Invalid regular expression: /(/' }));
    const bad = await registry.execute({ name: 'search_code', arguments: { pattern: '(' } }, ctx, 'verdict');
    assert.equal(bad.status, 'error');
    assert.equal(bad.content, 'Error: Invalid regular expression: /(/\nfix the regex');
  });
});

describe('helpers', () => {
  it('builds order-independent call keys', () => {
    assert.equal(toolCallKey('get_usage', { symbol: 'a', package: 'b' }), toolCallKey('get_usage', { package: 'b', symbol: 'a' }));
    assert.notEqual(toolCallKey('get_usage', { package: 'b' }), toolCallKey('get_usage', { package: 'c' }));
  });

  it('truncates at a line break when one is close', () => {
    const text = Array.from({ length: 50 }, (_, i) => `line ${i}`).join('\n');
    const cut = truncateContent(text, 120);
    assert.equal(cut.truncated, true);
    assert.ok(cut.content.length <= 120);
    assert.ok(cut.content.split('\n')[0]?.startsWith('line 0'));
    assert.deepEqual(truncateContent('short', 100), { content: 'short', truncated: false, omitted: 0 });
  });

  it('formats results without data as the hint alone', () => {
    assert.equal(formatToolContent({ ok: true, hint: 'nothing found' }), 'nothing found');
    assert.equal(formatToolContent({ ok: false, hint: 'x' }), 'Error: x');
  });
});
