import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { describe, it } from 'node:test';
import { fitProse, THOUGHT_MARKER, THOUGHT_MAX_LINES, Ui, wrapText, type UiOptions } from '../../src/ui.ts';

function makeUi(options: UiOptions = {}) {
  let out = '';
  const sink = (): Writable =>
    new Writable({
      write(chunk, _enc, cb) {
        out += String(chunk);
        cb();
      },
    });
  const ui = new Ui({ color: false, unicode: true, env: {}, stdout: sink() as never, stderr: sink() as never, ...options });
  return { ui, out: () => out };
}

// small-model prose, backticked ids
const PROSE = [
  'The `astro` package is a direct production dependency imported in two source files.',
  'The advisory blames the internal renderer rather than an exported function.',
  'Both call sites pass the request body to `renderMarkdown()` without sanitising it first.',
  'That makes the vulnerable path reachable whenever a visitor submits content through the form.',
  'A fix exists in the next major version, so the upgrade needs a migration review.',
  'The changelog lists two breaking changes that touch the configuration file.',
].join(' ');

// does the marker fit after the last line
function markerRoom(lines: readonly string[], width: number): boolean {
  const last = lines[lines.length - 1] ?? '';
  return last.length + 1 + THOUGHT_MARKER.length <= width;
}

describe('fitProse', () => {
  it('keeps text that fits in five lines whole, without a marker', () => {
    assert.deepEqual(fitProse('Checked the call sites. Nothing else to read.', 40), { lines: ['Checked the call sites. Nothing else to', 'read.'], cut: false });
    assert.deepEqual(fitProse('', 40), { lines: [], cut: false });
  });

  it('cuts at the end of the last complete sentence that fits with the marker', () => {
    const width = 60;
    const fit = fitProse(PROSE, width);
    assert.equal(fit.cut, true);
    const shown = fit.lines.join(' ');
    assert.ok(PROSE.startsWith(shown), shown);
    assert.match(shown, /[.!?]$/, 'ends at a sentence end');
    assert.ok(fit.lines.length < THOUGHT_MAX_LINES || (fit.lines.length === THOUGHT_MAX_LINES && markerRoom(fit.lines, width)));
    // next sentence won't fit with marker
    const next = PROSE.slice(0, PROSE.indexOf('. ', shown.length) + 1);
    const longer = wrapText(next, width);
    assert.ok(longer.length > THOUGHT_MAX_LINES || (longer.length === THOUGHT_MAX_LINES && !markerRoom(longer, width)), next);
    assert.equal(shown, PROSE.split('. ').slice(0, 3).join('. ') + '.');
  });

  it('treats a line break as a sentence end', () => {
    const text = `Checked how minimist is used\n${'The binding is called once with process.argv and the result drives every flag the tool accepts '.repeat(3)}`;
    assert.deepEqual(fitProse(text, 40), { lines: ['Checked how minimist is used'], cut: true });
  });

  it('falls back to the last word boundary when no sentence end fits', () => {
    const text = 'the model keeps describing the call site in src/cli.js where minimist parses the arguments and never reaches a full stop because it goes on about the flags and the defaults and the aliases and the parsing rules until the budget runs out';
    const width = 40;
    const fit = fitProse(text, width);
    assert.equal(fit.cut, true);
    const shown = fit.lines.join(' ');
    assert.ok(text.startsWith(shown), shown);
    assert.equal(text[shown.length], ' ', 'cut at a word boundary, never inside a word');
    assert.equal(fit.lines.length, THOUGHT_MAX_LINES);
    assert.ok(markerRoom(fit.lines, width), 'room for the marker on the last line');
  });

  it('never cuts inside a backtick span', () => {
    const span = '`const { marked } = require("marked"); marked(userMarkdown, { gfm: true, breaks: true, sanitize: false, smartypants: true })`';
    const text = `Checked the call ${span} which renders what the visitor typed`;
    const fit = fitProse(text, 30, { maxLines: 3 });
    assert.deepEqual(fit, { lines: ['Checked the call'], cut: true }, 'cut before the span, not at a space inside it');
    // no sentence end inside a span
    const dotted = `It reads ${'`opts.a. opts.b. opts.c. opts.d. opts.e. opts.f. opts.g. opts.h. opts.i. opts.j. opts.k`'} before the schema check and then keeps going for a while`;
    const shown = fitProse(dotted, 30, { maxLines: 2 }).lines.join(' ');
    assert.equal((shown.match(/`/g) ?? []).length % 2, 0, shown);
    assert.equal(shown, 'It reads');
  });

  it('shows only the marker when nothing before the first boundary fits', () => {
    assert.deepEqual(fitProse(`${'`'}${'x'.repeat(400)}${'`'} is the whole prose`, 30), { lines: [], cut: true });
  });
});

describe('model prose in the live trace', () => {
  it('prints at most five lines, the dim marker on the last line or the next', () => {
    const { ui } = makeUi({ width: 66 });
    const lines = ui.formatThoughtLines(PROSE);
    assert.ok(lines.length <= THOUGHT_MAX_LINES, lines.join('\n'));
    assert.ok(lines[0]?.startsWith('agent The `astro` package'));
    for (const line of lines.slice(1)) assert.ok(line.startsWith('      '), 'continuation lines keep the indent');
    assert.equal(lines.join('\n').split(THOUGHT_MARKER).length - 1, 1, 'one marker');
    assert.ok(!lines.join(' ').includes('...'), 'no bare dots in the middle of a sentence');
    const text = lines.join(' ').replace(/\s+/g, ' ');
    assert.match(text, /\. \(full reasoning in the report\)$/);
  });

  it('puts the marker on its own line when the last line is full', () => {
    const { ui } = makeUi({ width: 40 });
    const text = 'One short sentence here. ' + 'x'.repeat(33) + ' ends. ' + 'Then a very long tail that cannot fit in the remaining space at all, not even close to it.'.repeat(3);
    const lines = ui.formatThoughtLines(text);
    assert.ok(lines.length <= THOUGHT_MAX_LINES);
    assert.equal(lines[lines.length - 1], `      ${THOUGHT_MARKER}`);
  });

  it('prints the whole text with --verbose (and with full)', () => {
    const verbose = makeUi({ width: 66, verbose: true }).ui;
    const lines = verbose.formatThoughtLines(PROSE);
    assert.ok(lines.length > THOUGHT_MAX_LINES);
    const joined = lines.map((l) => l.replace(/^agent |^ {6}/, '')).join(' ');
    assert.equal(joined, PROSE);
    assert.ok(!joined.includes(THOUGHT_MARKER));
    assert.deepEqual(makeUi({ width: 66 }).ui.formatThoughtLines(PROSE, { full: true }), lines);
  });

  it('prints through agentThought and Card.thought (border kept, silenced by --quiet)', () => {
    const { ui, out } = makeUi({ width: 66, unicode: false });
    ui.agentThought(PROSE);
    const printed = out().trimEnd().split('\n');
    assert.ok(printed.length <= THOUGHT_MAX_LINES && printed[0]?.startsWith('agent '), out());
    const card = makeUi({ width: 66, unicode: false });
    card.ui.card('High').thought(PROSE);
    const cardLines = card.out().trimEnd().split('\n');
    assert.ok(cardLines.length <= THOUGHT_MAX_LINES);
    for (const line of cardLines) assert.ok(line.startsWith('| '), line);
    const quiet = makeUi({ quiet: true });
    quiet.ui.agentThought(PROSE);
    assert.equal(quiet.out(), '');
  });
});
