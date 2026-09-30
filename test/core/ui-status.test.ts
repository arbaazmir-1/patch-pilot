import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { clearLine, cursorTo, moveCursor } from 'node:readline';
import { PassThrough, Writable } from 'node:stream';
import { afterEach, describe, it } from 'node:test';
import { restoreTerminal, Ui, type UiOptions } from '../../src/ui.ts';

const E = '\u001b';

// fake tty, records writes, emits resize
class FakeTty extends EventEmitter {
  isTTY = true;
  rows: number | undefined;
  columns: number | undefined;
  writes: string[] = [];

  constructor(rows: number | undefined, columns: number | undefined) {
    super();
    this.rows = rows;
    this.columns = columns;
  }

  write(chunk: unknown, ...rest: unknown[]): boolean {
    this.writes.push(String(chunk));
    const callback = rest.find((r) => typeof r === 'function') as (() => void) | undefined;
    callback?.();
    return true;
  }

  // ora needs these
  cursorTo(x: number): boolean {
    return cursorTo(this as never, x);
  }

  moveCursor(dx: number, dy: number): boolean {
    return moveCursor(this as never, dx, dy);
  }

  clearLine(dir: -1 | 0 | 1): boolean {
    return clearLine(this as never, dir);
  }

  // since last take()
  take(): string {
    const text = this.writes.join('');
    this.writes = [];
    return text;
  }
}

function makeTtyUi(options: { rows?: number; columns?: number; ui?: UiOptions } = {}) {
  const tty = new FakeTty('rows' in options ? options.rows : 40, 'columns' in options ? options.columns : 100);
  const clock = { now: 1_000_000 };
  const ui = new Ui({ stdout: tty as never, stderr: tty as never, color: false, unicode: true, env: {}, now: () => clock.now, ...options.ui });
  return { ui, tty, clock };
}

// save cursor, rows, restore
function frame(top: number, rows: readonly string[]): string {
  return `${E}7${rows.map((row, i) => `${E}[${top + i};1H${row}${E}[K`).join('')}${E}8`;
}

const SETUP_40 = `\n\n\n${E}7${E}[1;37r${E}8${E}[3A`;
const RESTORE_40 = `${E}7${E}[r${E}[38;1H${E}[2K${E}[39;1H${E}[2K${E}[40;1H${E}[2K${E}8`;
const RULE_99 = '─'.repeat(99);
const PHASE_1 = '⬢ Working on 3 phases   ▣ Take in evidence   ☐ Investigate and decide   ☐ Act safely';
const PHASE_2 = '⬢ Working on 3 phases   ☒ Take in evidence   ▣ Investigate and decide   ☐ Act safely';
const ASTRO = 'Investigating astro@5.1.2 (3 of 20)';

afterEach(() => restoreTerminal());

describe('status bar on a terminal (40 rows, 100 columns)', () => {
  it('reserves the bottom three rows with a scroll region and draws the bar at rows 38 to 40', () => {
    const { ui, tty, clock } = makeTtyUi();
    assert.equal(ui.status.enabled, true);
    ui.status.set({ phases: ui.phaseItems(2), activity: ASTRO, detail: 'CVE 4 of 12 GHSA-xxxx' });
    assert.equal(tty.take(), '', 'set() before start() only stores the state');
    ui.status.start();
    assert.equal(ui.status.active, true);
    // scroll 3, set region, back to last line
    assert.equal(tty.take(), SETUP_40 + frame(38, [RULE_99, PHASE_2, `  ${ASTRO} · CVE 4 of 12 GHSA-xxxx · 0s`]));
    clock.now += 130_000;
    ui.status.tick();
    assert.equal(tty.take(), frame(38, [RULE_99, PHASE_2, `  ${ASTRO} · CVE 4 of 12 GHSA-xxxx · 2m 10s`]));
    ui.status.start();
    assert.equal(tty.take(), '', 'start() is a no-op while running');
  });

  it('redraws on set() and on the elapsed second, and writes nothing when nothing changed', () => {
    const { ui, tty, clock } = makeTtyUi();
    ui.status.start({ phases: ui.phaseItems(1) });
    assert.equal(tty.take(), SETUP_40 + frame(38, [RULE_99, PHASE_1, '  0s']));
    ui.status.set({ phases: ui.phaseItems(1) });
    ui.status.tick();
    clock.now += 400;
    ui.status.tick();
    assert.equal(tty.take(), '', 'same rows: no redraw');
    ui.status.set({ activity: 'Parsing the lockfile...' });
    assert.equal(tty.take(), frame(38, [RULE_99, PHASE_1, '  Parsing the lockfile · 0s']), 'the phases are kept, the trailing dots dropped');
    ui.status.set({ activity: 'Parsing the lockfile' });
    assert.equal(tty.take(), '');
    clock.now += 1000;
    ui.status.tick();
    assert.equal(tty.take(), frame(38, [RULE_99, PHASE_1, '  Parsing the lockfile · 1s']));
    ui.status.set({ phases: ui.phaseItems(2) });
    assert.equal(tty.take(), frame(38, [RULE_99, PHASE_2, '  1s']), 'a new phase clears the activity');
  });

  it("shows a spinner's text while no activity is set; an activity wins over it", () => {
    const { ui, tty } = makeTtyUi();
    ui.status.start({ phases: ui.phaseItems(1) });
    tty.take();
    ui.status.mirror('Checking 861 packages against OSV.dev (12 of 69)...');
    assert.equal(tty.take(), frame(38, [RULE_99, PHASE_1, '  Checking 861 packages against OSV.dev (12 of 69) · 0s']));
    ui.status.set({ activity: ASTRO });
    tty.take();
    ui.status.mirror(`${E}[35magent${E}[39m thinking...`);
    assert.equal(tty.take(), '', 'the explicit activity stays');
  });

  it('mirrors the text of a running spinner', () => {
    const { ui, tty } = makeTtyUi();
    ui.status.start({ phases: ui.phaseItems(1) });
    tty.take();
    const spinner = ui.spinner('Locating usage in the project code...');
    spinner.update('Checking the npm registry for 6 packages...');
    spinner.stop();
    const out = tty.take();
    assert.ok(out.includes(frame(38, [RULE_99, PHASE_1, '  Locating usage in the project code · 0s'])), JSON.stringify(out));
    assert.ok(out.includes(frame(38, [RULE_99, PHASE_1, '  Checking the npm registry for 6 packages · 0s'])), JSON.stringify(out));
  });

  it('restores the terminal on stop(): region reset, the three rows cleared, the cursor back', () => {
    const { ui, tty } = makeTtyUi();
    const counts = (): number[] => ['exit', 'SIGINT', 'SIGTERM', 'SIGWINCH', 'uncaughtExceptionMonitor'].map((e) => process.listenerCount(e));
    const before = counts();
    ui.status.start({ phases: ui.phaseItems(3), activity: 'Approval gate' });
    assert.deepEqual(
      counts(),
      before.map((n) => n + 1),
      'exit, Ctrl+C, SIGTERM, resize and crash hooks',
    );
    assert.equal(tty.listenerCount('resize'), 1);
    tty.take();
    ui.status.stop();
    assert.equal(tty.take(), RESTORE_40);
    assert.equal(ui.status.active, false);
    assert.deepEqual(counts(), before);
    assert.equal(tty.listenerCount('resize'), 0);
    ui.status.stop();
    ui.status.set({ activity: 'Applying 1 of 3: lodash 4.17.20 → 4.18.1' });
    ui.status.tick();
    assert.equal(tty.take(), '', 'nothing is drawn after stop()');
  });

  it('restores the terminal on process exit, on an uncaught error and through restoreTerminal()', () => {
    const { ui, tty } = makeTtyUi();
    const exitBefore = process.listeners('exit');
    ui.status.start({ phases: ui.phaseItems(2) });
    tty.take();
    const onExit = process.listeners('exit').find((l) => !exitBefore.includes(l));
    assert.ok(onExit, 'process.once("exit") hook');
    (onExit as () => void)();
    assert.equal(tty.take(), RESTORE_40);
    assert.equal(process.listeners('exit').length, exitBefore.length);

    const crashBefore = process.listeners('uncaughtExceptionMonitor');
    ui.status.start();
    tty.take();
    const onCrash = process.listeners('uncaughtExceptionMonitor').find((l) => !crashBefore.includes(l));
    assert.ok(onCrash, 'uncaught error hook');
    (onCrash as (err: Error, origin: string) => void)(new Error('boom'), 'uncaughtException');
    assert.equal(tty.take(), RESTORE_40);

    ui.status.start();
    tty.take();
    restoreTerminal();
    assert.equal(tty.take(), RESTORE_40);
    assert.equal(ui.status.active, false);
  });

  it('handles a resize: resets the region for the new size, redraws, and steps aside under 12 rows', () => {
    const { ui, tty } = makeTtyUi();
    ui.status.start({ phases: ui.phaseItems(2), activity: ASTRO });
    tty.take();
    tty.rows = 30;
    tty.columns = 80;
    tty.emit('resize');
    // drop region, erase bar, new region
    const compact = '⬢ ☒ Take in evidence   ▣ Investigate and decide   ☐ Act safely';
    assert.equal(tty.take(), `${E}7${E}[r${E}8${E}[J` + `\n\n\n${E}7${E}[1;27r${E}8${E}[3A` + frame(28, ['─'.repeat(79), compact, `  ${ASTRO} · 0s`]));
    process.emit('SIGWINCH');
    assert.equal(tty.take(), '', 'SIGWINCH after the resize event: same size, nothing to redo');
    tty.rows = 11;
    tty.emit('resize');
    assert.equal(tty.take(), `${E}7${E}[r${E}8${E}[J`, 'too short: the region is dropped');
    assert.equal(ui.status.active, false);
    ui.status.set({ activity: 'Investigating astro@5.1.2 (4 of 20)' });
    ui.status.tick();
    assert.equal(tty.take(), '');
    tty.rows = 40;
    tty.columns = 100;
    process.emit('SIGWINCH');
    assert.equal(tty.take(), SETUP_40 + frame(38, [RULE_99, PHASE_2, '  Investigating astro@5.1.2 (4 of 20) · 0s']), 'back on a tall terminal: set up again');
    ui.status.stop();
    assert.equal(tty.take(), RESTORE_40);
  });

  it('scrolls first so that a prompt at the bottom of the region never needs the bar rows', async () => {
    const stdin = new PassThrough() as PassThrough & { isTTY: boolean; isRaw: boolean; setRawMode: (m: boolean) => void };
    stdin.isTTY = true;
    stdin.isRaw = false;
    stdin.setRawMode = (m: boolean) => {
      stdin.isRaw = m;
    };
    const { ui, tty } = makeTtyUi({ ui: { interactive: true, stdin } });
    ui.status.start({ phases: ui.phaseItems(3), activity: 'Approval gate' });
    tty.take();
    const answer = ui.singleKeyPrompt('Apply patch for lodash@4.18.1?', 'y/n');
    stdin.write('y');
    assert.equal(await answer, 'y');
    // prompt and answer rows: two down, up two
    assert.equal(tty.take(), `\n\n${E}[2A? Apply patch for lodash@4.18.1? (y/n) y\n`);
    ui.status.ensureRows(200);
    assert.equal(tty.take(), `${'\n'.repeat(36)}${E}[36A`, 'never more than the 37-row region holds');
  });

  it('fits narrow terminals: the checklist drops its title, the activity keeps the elapsed time', () => {
    const { ui, clock } = makeTtyUi();
    ui.status.start({ phases: ui.phaseItems(2), activity: ASTRO, detail: 'CVE 4 of 12 GHSA-xxxx' });
    clock.now += 130_000;
    const [rule, checklist, activity] = ui.status.render(45);
    assert.equal(rule, '─'.repeat(45));
    assert.equal(checklist, '⬢ ☒ Take in evidence   ▣ Investigate and dec…');
    assert.equal(activity, '  Investigating astro@5.1.2 (3 of 2… · 2m 10s');
    assert.equal(ui.status.render(70)[1], '⬢ ☒ Take in evidence   ▣ Investigate and decide   ☐ Act safely');
  });

  it('uses the ASCII glyphs of the fallback and keeps the current phase bright with colours', () => {
    const ascii = makeTtyUi({ ui: { unicode: false } });
    ascii.ui.status.start({ phases: ascii.ui.phaseItems(2), activity: 'Applying 2 of 3: marked 0.3.6 → 4.0.10' });
    assert.deepEqual(ascii.ui.status.render(100), [
      '-'.repeat(100),
      '* Working on 3 phases   [x] Take in evidence   [>] Investigate and decide   [ ] Act safely',
      '  Applying 2 of 3: marked 0.3.6 -> 4.0.10 - 0s',
    ]);
    ascii.ui.status.stop();
    const coloured = makeTtyUi({ ui: { color: undefined, env: { FORCE_COLOR: '1' } } });
    coloured.ui.status.start({ phases: coloured.ui.phaseItems(2) });
    const row = coloured.ui.status.render(100)[1] ?? '';
    assert.ok(row.includes(`${E}[1m▣ Investigate and decide${E}[22m`), JSON.stringify(row));
    assert.ok(row.includes(`${E}[2m☒ Take in evidence${E}[22m`), JSON.stringify(row));
  });
});

describe('status bar fallback', () => {
  it('prints nothing and hooks nothing without a usable terminal', () => {
    const plain = new Writable({
      write(_chunk, _enc, cb) {
        cb();
      },
    });
    const cases: [string, () => { ui: Ui; tty: FakeTty }][] = [
      [
        'stderr is not a TTY',
        () => {
          const made = makeTtyUi();
          made.tty.isTTY = false;
          return made;
        },
      ],
      ['zero columns (a bare pseudo-terminal)', () => makeTtyUi({ columns: 0 })],
      ['unknown size', () => makeTtyUi({ rows: undefined, columns: undefined })],
      ['under 12 rows', () => makeTtyUi({ rows: 11 })],
      ['--quiet', () => makeTtyUi({ ui: { quiet: true } })],
      ['--json', () => makeTtyUi({ ui: { json: true } })],
      ['TERM=dumb', () => makeTtyUi({ ui: { env: { TERM: 'dumb' } } })],
      ['stdout is not a TTY', () => makeTtyUi({ ui: { stdout: plain as never } })],
    ];
    const before = process.listenerCount('SIGINT');
    for (const [label, make] of cases) {
      const { ui, tty } = make();
      assert.equal(ui.status.enabled, false, label);
      ui.status.start({ phases: ui.phaseItems(1), activity: 'Parsing the lockfile' });
      assert.equal(process.listenerCount('SIGINT'), before, label);
      ui.status.set({ activity: 'Fetching vulnerabilities (12 of 69 records)' });
      ui.status.mirror('Locating usage evidence...');
      ui.status.ensureRows(3);
      ui.status.tick();
      assert.equal(ui.status.active, false, label);
      ui.status.stop();
      assert.equal(tty.take(), '', label);
    }
  });
});
