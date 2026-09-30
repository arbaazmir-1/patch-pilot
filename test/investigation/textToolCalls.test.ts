import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  extractJsonObject,
  normalizeToolArguments,
  parseLenientJson,
  parseTextToolCalls,
  RAW_ARGUMENTS_KEY,
  stripJsonBlocks,
  unwrapRawArguments,
} from '../../src/llm/textToolCalls.ts';

const TOOLS = ['get_usage', 'read_file', 'get_advisory', 'search_code', 'check_deps'];

function names(content: string): string[] {
  return parseTextToolCalls(content, TOOLS).calls.map((c) => c.function.name);
}

describe('parseTextToolCalls', () => {
  it('recovers a fenced ```json block and keeps the prose', () => {
    const r = parseTextToolCalls('I will check.\n```json\n{"name": "get_usage", "arguments": {"package": "lodash", "symbol": "template"}}\n```\nThen decide.', TOOLS);
    assert.deepEqual(r.calls, [{ function: { name: 'get_usage', arguments: { package: 'lodash', symbol: 'template' }, index: 0 }, source: 'text' }]);
    assert.equal(r.text, 'I will check.\n\nThen decide.');
  });

  it('recovers bare and prose-wrapped objects with "arguments" or "parameters"', () => {
    assert.deepEqual(parseTextToolCalls('{"name": "check_deps", "arguments": {"package": "lodash"}}', TOOLS).calls[0]?.function.arguments, { package: 'lodash' });
    const wrapped = parseTextToolCalls('Let me call {"name": "read_file", "parameters": {"path": "src/cli.js", "startLine": 1}} now.', TOOLS);
    assert.deepEqual(wrapped.calls[0]?.function, { name: 'read_file', arguments: { path: 'src/cli.js', startLine: 1 }, index: 0 });
    assert.equal(wrapped.text, 'Let me call now.');
  });

  it('recovers arrays of calls in order', () => {
    const r = parseTextToolCalls('[{"name": "get_usage", "arguments": {"package": "minimist"}}, {"name": "read_file", "arguments": {"path": "src/cli.js"}}]', TOOLS);
    assert.deepEqual(r.calls.map((c) => [c.function.name, c.function.index]), [['get_usage', 0], ['read_file', 1]]);
    assert.equal(r.text, '');
  });

  it('recovers Mistral [TOOL_CALLS] forms', () => {
    const list = parseTextToolCalls('[TOOL_CALLS] [{"name": "check_deps", "arguments": {"package": "lodash"}}]', TOOLS);
    assert.deepEqual(list.calls[0]?.function.arguments, { package: 'lodash' });
    assert.equal(list.text, '');
    const args = parseTextToolCalls('[TOOL_CALLS]get_usage[ARGS]{"package": "lodash", "symbol": "merge"}', TOOLS);
    assert.deepEqual(args.calls[0]?.function, { name: 'get_usage', arguments: { package: 'lodash', symbol: 'merge' }, index: 0 });
  });

  it('recovers <function=name> and <tool_call> tags', () => {
    const fn = parseTextToolCalls('<function=get_usage>{"package": "lodash", "symbol": "merge"}</function>', TOOLS);
    assert.deepEqual(fn.calls[0]?.function.arguments, { package: 'lodash', symbol: 'merge' });
    assert.equal(fn.text, '');
    const tag = parseTextToolCalls('<tool_call>\n{"name": "get_advisory", "arguments": {"id": "GHSA-1"}}\n</tool_call>', TOOLS);
    assert.deepEqual(tag.calls[0]?.function.arguments, { id: 'GHSA-1' });
  });

  it('recovers call syntax with a JSON object, key=value pairs or one string', () => {
    const json = parseTextToolCalls('Next: get_usage({"package": "lodash", "symbol": "template"}) to confirm.', TOOLS);
    assert.deepEqual(json.calls[0]?.function.arguments, { package: 'lodash', symbol: 'template' });
    assert.equal(json.text, 'Next: to confirm.');
    const kwargs = parseTextToolCalls('search_code(pattern="merge\\\\(", fileGlob="src/**/*.js", maxResults=5)', TOOLS);
    assert.deepEqual(kwargs.calls[0]?.function.arguments, { pattern: 'merge\\(', fileGlob: 'src/**/*.js', maxResults: 5 });
    const single = parseTextToolCalls('check_deps("lodash")', TOOLS);
    assert.deepEqual(single.calls[0]?.function.arguments, { [RAW_ARGUMENTS_KEY]: 'lodash' });
  });

  it('accepts a bare name() only when it stands alone', () => {
    assert.deepEqual(names('get_usage()'), ['get_usage']);
    assert.deepEqual(names('I used get_usage() earlier and found nothing.'), []);
  });

  it('parses single quotes, Python literals, bare keys and trailing commas', () => {
    assert.deepEqual(parseTextToolCalls("{'name': 'get_usage', 'arguments': {'package': 'lodash'}}", TOOLS).calls[0]?.function.arguments, { package: 'lodash' });
    assert.deepEqual(parseLenientJson("{name: 'x', ok: True, none: None, list: [1, 2,],}"), { name: 'x', ok: true, none: null, list: [1, 2] });
  });

  it('understands OpenAI-style, wrapper and name-keyed shapes, with near-miss names', () => {
    assert.deepEqual(names('{"function": {"name": "getUsage", "arguments": "{\\"package\\": \\"lodash\\"}"}}'), ['get_usage']);
    assert.deepEqual(names('{"tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "a.js"}}}]}'), ['read_file']);
    assert.deepEqual(names('{"check_deps": {"package": "lodash"}}'), ['check_deps']);
    assert.deepEqual(names('{"tool": "functions.search_code", "args": {"pattern": "x"}}'), ['search_code']);
  });

  it('leaves unknown tools and non-call JSON in the text', () => {
    const unknown = parseTextToolCalls('{"name": "check_import", "arguments": {"package": "lodash"}}', TOOLS);
    assert.deepEqual(unknown.calls, []);
    assert.match(unknown.text, /check_import/);
    const verdict = parseTextToolCalls('The verdict: {"risk": "Low", "reachable": "no"}', TOOLS);
    assert.deepEqual(verdict.calls, []);
    assert.equal(verdict.text, 'The verdict: {"risk": "Low", "reachable": "no"}');
    assert.deepEqual(parseTextToolCalls('', TOOLS), { calls: [], text: '' });
  });

  it('deduplicates the same call written twice', () => {
    const r = parseTextToolCalls('```json\n{"name": "get_usage", "arguments": {"package": "lodash"}}\n```\nAgain: get_usage({"package": "lodash"})', TOOLS);
    assert.equal(r.calls.length, 1);
  });
});

describe('argument helpers', () => {
  it('normalises arguments to objects and unwraps raw strings', () => {
    assert.deepEqual(normalizeToolArguments('{"package":"lodash"}'), { package: 'lodash' });
    assert.deepEqual(normalizeToolArguments(null), {});
    assert.deepEqual(normalizeToolArguments('lodash'), { [RAW_ARGUMENTS_KEY]: 'lodash' });
    assert.equal(unwrapRawArguments({ [RAW_ARGUMENTS_KEY]: 'lodash' }), 'lodash');
    assert.deepEqual(unwrapRawArguments({ package: 'lodash' }), { package: 'lodash' });
  });

  it('extracts the first JSON object from fenced or wrapped replies', () => {
    assert.deepEqual(extractJsonObject('```json\n{"risk": "High"}\n```'), { risk: 'High' });
    assert.deepEqual(extractJsonObject('Here it is: {"risk": "Low", "evidence": ["a"]} done'), { risk: 'Low', evidence: ['a'] });
    assert.equal(extractJsonObject('no json here'), undefined);
  });
});

describe('stripJsonBlocks', () => {
  it('removes fenced blocks and parseable JSON, keeping other brackets', () => {
    assert.equal(stripJsonBlocks('Before ```json\n{"a":1}\n``` after {"risk": "Low"} end [see a.js:3]').replace(/\s+/g, ' ').trim(), 'Before after end [see a.js:3]');
  });
});
