import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { describe, it } from 'node:test';
import { Chalk } from 'chalk';
import { createPatch } from 'diff';
import {
  formatArgs,
  formatBytes,
  formatDuration,
  formatElapsed,
  MAX_WIDTH,
  renderTable,
  resolveColorLevel,
  toAscii,
  truncateLine,
  Ui,
  wrapText,
} from '../../src/ui.ts';
import { EXIT, PatchPilotError } from '../../src/util/errors.ts';

function capture(): { stream: Writable; text: () => string } {
  let buf = '';
  const stream = new Writable({
    write(chunk, _enc, cb) {
      buf += String(chunk);
      cb();
    },
  });
  return { stream, text: () => buf };
}

// ascii unless unicode is set
function makeUi(options: ConstructorParameters<typeof Ui>[0] = {}) {
  const out = capture();
  const err = capture();
  const ui = new Ui({ color: false, env: {}, stdout: out.stream as never, stderr: err.stream as never, ...options });
  return { ui, out: out.text, err: err.text };
}

const isAscii = (text: string): boolean => [...text].every((ch) => ch.charCodeAt(0) < 128);

describe('ASCII fallback (NO_COLOR or not a TTY)', () => {
  it('is selected for non-TTY output and for disabled colours', () => {
    assert.equal(makeUi().ui.ascii, true);
    assert.equal(makeUi({ color: undefined, env: { NO_COLOR: '1' } }).ui.ascii, true);
    assert.equal(makeUi({ unicode: true }).ui.ascii, false);
  });

  it('renders the header, check lines, rule and section headers', () => {
    const { ui } = makeUi();
    assert.equal(ui.formatHeader('0.1.0', 'Dependency security agent', '~/my-project'), 'PatchPilot v0.1.0 - Dependency security agent\n~/my-project');
    assert.equal(ui.formatCheck('Discovered lockfile', 'package-lock.json'), '+ Discovered lockfile  package-lock.json');
    assert.equal(ui.formatCheck('Parsed 847 dependencies'), '+ Parsed 847 dependencies');
    assert.equal(ui.formatFail('Ollama server', 'not reachable'), 'x Ollama server  not reachable');
    assert.equal(ui.formatWarn('git', 'not found'), '! git  not found');
    assert.equal(ui.formatInfoLine('Web search key', 'not set'), '- Web search key  not set');
    assert.equal(ui.formatRule(), '-'.repeat(MAX_WIDTH));
    assert.equal(ui.formatRule(20), '-'.repeat(20));
    assert.equal(ui.formatSectionHeader('Action required', 'green'), 'Action required');
  });

  it('renders the phase checklist and the activity line', () => {
    const { ui } = makeUi();
    assert.equal(
      ui.formatChecklist(ui.phaseItems(2)),
      ['* Working on 3 phases', '  [x] Take in evidence', '  [>] Investigate and decide', '  [ ] Act safely'].join('\n'),
    );
    assert.equal(ui.formatChecklist(ui.phaseItems('complete')).split('\n').filter((l) => l.includes('[x]')).length, 3);
    assert.equal(ui.formatActivity('Investigating lodash@4.17.20 (2 of 8)...'), '* Investigating lodash@4.17.20 (2 of 8)...');
  });

  it('renders a CVE card with the border on every line', () => {
    const { ui, out } = makeUi();
    const card = ui.card(null);
    card.title('CVE-2021-23337', 'lodash@4.17.20', 'CVSS 7.2');
    card.agent('Checking if lodash is imported...');
    card.result('Found in: src/utils.js, src/api/transform.js');
    card.agent('Checking if template() is called...', { tag: 'evidence gate' });
    card.agent('Checking the changelog of lodash 4.17.20 → 4.17.21...');
    card.verdict('Critical', 'Vulnerable function template() is called directly. Safe patch available.');
    card.confidence(0.95, 'bump to 4.17.21');
    card.end();
    assert.equal(
      out(),
      [
        '| CVE-2021-23337 - lodash@4.17.20 - CVSS 7.2',
        '|',
        '| agent Checking if lodash is imported...',
        '|   Found in: src/utils.js, src/api/transform.js',
        '| agent [evidence gate] Checking if template() is called...',
        '| agent Checking the changelog of lodash 4.17.20 -> 4.17.21...',
        '|',
        '| [CRITICAL]  Vulnerable function template() is called directly. Safe patch available.',
        '| Confidence: 95% - Recommended: bump to 4.17.21',
        '',
        '',
      ].join('\n'),
    );
  });

  it('wraps long card lines within the width, keeping the border and a hanging indent', () => {
    const { ui, out } = makeUi({ width: 40 });
    const card = ui.card('Low');
    card.verdict('Low', 'Transitive dependency. The vulnerable path is not reachable from project code.');
    const lines = out().trimEnd().split('\n');
    assert.ok(lines.every((l) => l.length <= 40), lines.join('\n'));
    assert.ok(lines.every((l) => l.startsWith('|')));
    assert.match(lines[1] ?? '', /^\| \[LOW\] {2}Transitive/);
    assert.match(lines[2] ?? '', /^\| {8}\S/, 'continuation aligned after the pill ([LOW] plus two spaces)');
  });

  it('renders pills, verdict, confidence, summary, action items, done line and footer', () => {
    const { ui } = makeUi();
    assert.equal(ui.pill('Critical'), '[CRITICAL]');
    assert.equal(ui.pill('Noise'), '[NOISE]');
    assert.deepEqual(ui.formatVerdictLine('Noise', 'Not exploitable in this context.'), ['[NOISE]  Not exploitable in this context.']);
    assert.equal(ui.formatConfidenceLine(0.88, 'defer'), 'Confidence: 88% - Recommended: defer');
    assert.equal(ui.formatSummaryLine({ total: 12, byRisk: { Critical: 2, Low: 3, Noise: 7, High: 0 } }), '12 CVEs scanned - 2 critical - 3 low - 7 noise');
    assert.equal(
      ui.formatActionItem({ n: 1, pkg: 'lodash', from: '4.17.20', to: '4.17.21', risk: 'Critical', patchNote: 'Patch: version bump only, no breaking changes', sourceNote: 'Source changes: none required' }),
      ['1. lodash 4.17.20 -> 4.17.21 [CRITICAL]', '   Patch: version bump only, no breaking changes', '   Source changes: none required'].join('\n'),
    );
    assert.equal(
      ui.formatDoneLine('Done. 2 patches applied, 1 source file updated, 10 deferred.', '.patch-pilot/report.md'),
      'Done. 2 patches applied, 1 source file updated, 10 deferred.\nFull report: .patch-pilot/report.md',
    );
    assert.equal(ui.formatFooter({ model: 'mistral:7b', numCtx: 16384, packages: 8, cves: 12, elapsedMs: 252_000 }), 'mistral:7b - 16k ctx - 8 packages - 12 CVEs - 4m 12s');
    assert.equal(ui.formatPrompt('Apply patch for lodash@4.17.21?', 'y/n/d/a/q'), '? Apply patch for lodash@4.17.21? (y/n/d/a/q)');
  });

  it('renders unified diffs with -/+ lines, context and a line cap', () => {
    const { ui } = makeUi();
    const before = "'use strict';\nconst marked = require('marked');\n\nfunction render(md) {\n  return marked(md);\n}\n";
    const after = "'use strict';\nconst { marked } = require('marked');\n\nfunction render(md) {\n  return marked(md);\n}\n";
    const block = ui.formatDiffBlock('src/render.js', createPatch('src/render.js', before, after));
    const lines = block.split('\n');
    assert.equal(lines[0], '  src/render.js');
    assert.ok(lines.includes("  - const marked = require('marked');"));
    assert.ok(lines.includes("  + const { marked } = require('marked');"));
    assert.ok(lines.includes("    'use strict';"), 'context lines are kept (dim)');
    const big = createPatch('a.js', Array.from({ length: 60 }, (_, i) => `a${i}`).join('\n'), Array.from({ length: 60 }, (_, i) => `b${i}`).join('\n'));
    const capped = ui.formatDiffBlock('a.js', big, 40).split('\n');
    assert.equal(capped.length, 1 + 40 + 1);
    // 122 body lines, 40 shown
    assert.match(capped[capped.length - 1] ?? '', /^ {2}\.\.\. 82 more lines \(d to expand\)$/);
  });

  it('never emits a non-ASCII character or an ANSI code', () => {
    const { ui, out, err } = makeUi();
    ui.header('0.1.0', 'Dependency security agent', '~/app');
    ui.check('Found 12 CVEs across 8 packages');
    ui.warn('git not found', 'install it from https://git-scm.com/downloads');
    ui.fail('Ollama server not reachable');
    ui.phaseChecklist(1);
    ui.activity('Investigating minimist@1.2.5 (1 of 6)...');
    ui.sectionHeader('Investigating vulnerabilities...');
    const card = ui.card('High');
    card.title('GHSA-xvch-5gv4-984h', 'minimist@1.2.5', 'CRITICAL');
    card.agent('Reading github.com/markedjs/marked/releases/tag/v4.0.0…');
    card.verdict('High', 'Parses process.argv from the user → prototype pollution is reachable.');
    card.confidence(0.9, 'bump to 1.2.6');
    ui.summaryLine({ total: 6, byRisk: { High: 1, Low: 5 } });
    ui.actionItem({ n: 1, pkg: 'minimist', from: '1.2.5', to: '1.2.6', risk: 'High' });
    ui.diffBlock('src/cli.js', createPatch('src/cli.js', 'a\n', 'b\n'));
    ui.doneLine('Done. 1 patch applied.', '.patch-pilot/report.md');
    ui.footer({ model: 'mistral:7b', numCtx: 16384, packages: 6, cves: 15, elapsedMs: 61_000 });
    ui.printTable([{ key: 'a', header: 'Package' }], [{ a: 'lodash' }]);
    const all = out() + err();
    assert.ok(isAscii(all), all.split('\n').filter((l) => !isAscii(l)).join('\n'));
    assert.ok(!all.includes('\u001b['));
  });
});

describe('Unicode glyphs and colours on a capable terminal', () => {
  it('uses only the allowed glyphs', () => {
    const { ui } = makeUi({ unicode: true });
    assert.equal(ui.formatCheck('Parsed 847 dependencies'), '✓ Parsed 847 dependencies');
    assert.equal(ui.formatFail('x'), '✗ x');
    assert.equal(ui.formatHeader('0.1.0'), 'PatchPilot v0.1.0 · Dependency security agent');
    assert.equal(ui.formatChecklist(ui.phaseItems(3)).split('\n')[0], '⬢ Working on 3 phases');
    assert.match(ui.formatChecklist(ui.phaseItems(3)), /☒ Take in evidence[\s\S]*▣ Act safely/);
    assert.match(ui.formatChecklist(ui.phaseItems(1)), /☐ Act safely/);
    assert.equal(ui.formatRule(3), '───');
    assert.equal(ui.formatActionItem({ n: 2, pkg: 'marked', from: '0.3.6', to: '4.0.10', risk: 'High' }), '2. marked 0.3.6 → 4.0.10 [HIGH]');
    const allowed = new Set([...'✓✗!?→─│⬢☐▣☒·…']);
    const rendered = [ui.formatConfidenceLine(0.5, 'x'), ui.formatSummaryLine({ total: 1, byRisk: { Low: 1 } }), ui.formatFooter({ model: 'm', numCtx: 8192 })].join('');
    for (const ch of rendered) if (ch.charCodeAt(0) >= 128) assert.ok(allowed.has(ch), `unexpected glyph ${ch}`);
  });

  it('colours the card border and pill by risk', () => {
    const { ui } = makeUi({ color: undefined, unicode: true, env: { FORCE_COLOR: '3' } });
    const critical = ui.card('Critical').border();
    const low = ui.card('Low').border();
    assert.notEqual(critical, low);
    assert.match(critical, /\u001b\[/);
    assert.match(ui.pill('High'), /\u001b\[.*HIGH/);
    assert.ok(ui.formatAgentLine('Checking...')[0]?.includes('\u001b['), 'agent label is coloured');
  });
});

describe('channels and silencing', () => {
  it('flow output goes to stdout, diagnostics to stderr', () => {
    const { ui, out, err } = makeUi();
    ui.print('result');
    ui.info('progress');
    ui.check('done');
    ui.warn('careful');
    ui.fail('broken');
    ui.debug('hidden without --verbose');
    assert.equal(out(), 'result\nprogress\n+ done\n');
    assert.equal(err(), '! careful\nx broken\n');
  });

  it('--quiet and --json silence every flow primitive but keep diagnostics on stderr', () => {
    for (const mode of [{ quiet: true }, { json: true }]) {
      const { ui, out, err } = makeUi(mode);
      ui.header('0.1.0');
      ui.check('x');
      ui.phaseChecklist(1);
      ui.activity('y');
      ui.sectionHeader('Summary');
      const card = ui.card('Low');
      card.title('id', 'p@1');
      card.agent('a');
      card.verdict('Low', 's');
      ui.summaryLine({ total: 1, byRisk: {} });
      ui.footer({ model: 'm' });
      ui.warn('still shown');
      if ('json' in mode) ui.printJson({ ok: true });
      assert.equal(out(), 'json' in mode ? '{\n  "ok": true\n}\n' : '');
      assert.match(err(), /still shown/);
    }
  });

  it('degrades the spinner and the progress line to plain lines without a TTY', () => {
    const { ui, out, err } = makeUi();
    const spin = ui.spinner('Querying OSV');
    assert.equal(spin.enabled, false);
    spin.update('Querying OSV (3/6)');
    spin.succeed('Queried 6 packages');
    assert.equal(out(), '+ Queried 6 packages\n');
    assert.equal(ui.card('Low').spinner().enabled, false);
    const progress = ui.progressLine();
    assert.equal(progress.tty, false);
    progress.update('pulling 25%');
    progress.update('pulling 25%');
    progress.update('pulling 50%');
    progress.done('done');
    assert.equal(err(), 'pulling 25%\npulling 50%\ndone\n');
  });

  it('caps the width at 100 columns', () => {
    assert.equal(makeUi({ width: 200 }).ui.width, 100);
    assert.equal(makeUi({ width: 60 }).ui.width, 60);
    assert.equal(makeUi().ui.width, 100);
  });
});

describe('singleKeyPrompt', () => {
  function fakeTty() {
    const stdin = new PassThrough() as PassThrough & { isTTY: boolean; isRaw: boolean; setRawMode: (m: boolean) => void };
    stdin.isTTY = true;
    stdin.isRaw = false;
    stdin.setRawMode = (m: boolean) => {
      stdin.isRaw = m;
    };
    return stdin;
  }

  it('reads one allowed key, ignores others and escape sequences, and echoes the answer', async () => {
    const stdin = fakeTty();
    const { ui, out } = makeUi({ interactive: true, stdin });
    const answer = ui.singleKeyPrompt('Apply patch for lodash@4.17.21?', 'y/n/d/a/q');
    stdin.write('x');
    stdin.write('\u001b[A');
    stdin.write('D');
    assert.equal(await answer, 'd');
    assert.equal(out(), '? Apply patch for lodash@4.17.21? (y/n/d/a/q) d\n');
    assert.equal(stdin.isRaw, false, 'raw mode restored');
  });

  it('uses the default on Enter and treats Ctrl+C as a cancelled prompt', async () => {
    const stdin = fakeTty();
    const { ui } = makeUi({ interactive: true, stdin });
    const answer = ui.singleKeyPrompt('Continue?', 'y/n', { defaultKey: 'n' });
    stdin.write('\r');
    assert.equal(await answer, 'n');
    const cancelled = ui.singleKeyPrompt('Continue?', 'y/n');
    stdin.write('\u0003');
    await assert.rejects(cancelled, (err: unknown) => err instanceof Error && err.name === 'ExitPromptError');
  });

  it('refuses to prompt without an interactive terminal', async () => {
    const { ui } = makeUi({ interactive: false });
    await assert.rejects(ui.singleKeyPrompt('Trust this directory?', 'y/n'), (err: unknown) => err instanceof PatchPilotError && err.exitCode === EXIT.USAGE);
  });
});

describe('ui helpers', () => {
  it('resolves colour levels: --no-color > FORCE_COLOR > NO_COLOR > TTY', () => {
    assert.equal(resolveColorLevel({ env: { FORCE_COLOR: '3' }, flag: false, isTTY: true }), 0);
    assert.equal(resolveColorLevel({ env: { FORCE_COLOR: '0' }, isTTY: true }), 0);
    assert.equal(resolveColorLevel({ env: { FORCE_COLOR: '2', NO_COLOR: '1' }, isTTY: false }), 2);
    assert.equal(resolveColorLevel({ env: { NO_COLOR: '1' }, isTTY: true }), 0);
    assert.equal(resolveColorLevel({ env: { NO_COLOR: '' }, isTTY: true }), 1);
    assert.equal(resolveColorLevel({ env: {}, isTTY: false }), 0);
    assert.equal(resolveColorLevel({ env: { TERM: 'dumb' }, isTTY: true }), 0);
  });

  it('renders tables with ANSI-aware widths and shrinks to fit', () => {
    const c = new Chalk({ level: 0 });
    const text = renderTable(
      [
        { key: 'pkg', header: 'Package' },
        { key: 'n', header: 'CVEs', align: 'right' },
      ],
      [
        { pkg: 'lodash', n: 5 },
        { pkg: 'decode-uri-component', n: 2 },
      ],
      c,
      { ruleChar: '-' },
    );
    assert.equal(text, ['Package               CVEs', '--------------------  ----', 'lodash                   5', 'decode-uri-component     2'].join('\n'));
    const narrow = renderTable([{ key: 'a', header: 'Summary' }], [{ a: 'a very long advisory summary that will not fit' }], c, { maxWidth: 20, ellipsis: '...' });
    assert.ok(narrow.split('\n').every((line) => line.length <= 20));
    assert.ok(narrow.includes('...'));
  });

  it('wraps, truncates and formats', () => {
    assert.deepEqual(wrapText('one two three four', 10), ['one two', 'three four']);
    assert.deepEqual(wrapText('one two three four five', 10), ['one two', 'three four', 'five']);
    assert.deepEqual(wrapText('abcdefghijklmnop', 10), ['abcdefghij', 'klmnop']);
    assert.equal(toAscii('a → b · c ─ ✓ ✗ … ⬢ ☒ ▣ ☐ │'), 'a -> b - c - + x ... * [x] [>] [ ] |');
    assert.equal(formatArgs({ path: 'src/render.js', startLine: 1, endLine: 40 }), 'src/render.js, 1, 40');
    assert.equal(truncateLine('a  b\nc', 10), 'a b c');
    assert.equal(truncateLine('abcdefghijkl', 6), 'abcde…');
    assert.equal(formatDuration(850), '850 ms');
    assert.equal(formatDuration(12_340), '12.3 s');
    assert.equal(formatDuration(4 * 60_000 + 12_000), '4 min 12 s');
    assert.equal(formatDuration(482 * 60_000 + 22_000), '8 h 2 min');
    assert.equal(formatDuration(3 * 3_600_000), '3 h');
    assert.equal(formatDuration(26 * 3_600_000 + 5 * 60_000), '1 d 2 h');
    assert.equal(formatDuration(59 * 60_000 + 59_600), '1 h');
    assert.equal(formatElapsed(850), '850ms');
    assert.equal(formatElapsed(12_400), '12s');
    assert.equal(formatElapsed(252_000), '4m 12s');
    assert.equal(formatElapsed(3_900_000), '1h 5m');
    assert.equal(formatBytes(4372824384), '4.1 GB');
  });
});
