// terminal output for all commands
import { stripVTControlCharacters } from 'node:util';
import { input } from '@inquirer/prompts';
import { Chalk, type ChalkInstance } from 'chalk';
import ora, { type Ora } from 'ora';
import type { CheckStatus, RiskLevel, SeverityLabel, TraceLabel } from './types.ts';
import { EXIT, PatchPilotError } from './util/errors.ts';

export type ColorLevel = 0 | 1 | 2 | 3;

type OutStream = NodeJS.WritableStream & { isTTY?: boolean; columns?: number; rows?: number; getColorDepth?: (env?: object) => number };
type InStream = NodeJS.ReadableStream & { isTTY?: boolean; isRaw?: boolean; setRawMode?: (mode: boolean) => unknown };

export const MAX_WIDTH = 100;

export interface ColorInput {
  env?: NodeJS.ProcessEnv;
  isTTY?: boolean;
  // false for --no-color
  flag?: boolean;
  stream?: OutStream;
}

// --no-color, FORCE_COLOR, NO_COLOR, TERM=dumb, tty
export function resolveColorLevel(options: ColorInput = {}): ColorLevel {
  const env = options.env ?? process.env;
  if (options.flag === false) return 0;
  const detected = (): ColorLevel => {
    const depth = options.stream?.getColorDepth?.(env) ?? 4;
    if (depth >= 24) return 3;
    if (depth >= 8) return 2;
    if (depth >= 4) return 1;
    return 0;
  };
  const force = env.FORCE_COLOR;
  if (force !== undefined) {
    if (force === '0' || force.toLowerCase() === 'false') return 0;
    if (force === '' || force.toLowerCase() === 'true') return Math.max(1, detected()) as ColorLevel;
    const n = Number.parseInt(force, 10);
    if (Number.isFinite(n)) return Math.min(Math.max(n, 0), 3) as ColorLevel;
    return 1;
  }
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return 0;
  if (env.TERM === 'dumb') return 0;
  const tty = options.isTTY ?? options.stream?.isTTY ?? false;
  return tty ? detected() : 0;
}

export function supportsUnicode(env: NodeJS.ProcessEnv = process.env): boolean {
  if (process.platform !== 'win32') return env.TERM !== 'linux';
  return Boolean(env.WT_SESSION || env.TERMINUS_SUBLIME || env.TERM_PROGRAM === 'vscode' || env.ConEmuTask);
}

export interface Glyphs {
  ok: string;
  fail: string;
  warn: string;
  info: string;
  skip: string;
  prompt: string;
  // activity marker
  hex: string;
  // done, current, pending
  done: string;
  current: string;
  todo: string;
  arrow: string;
  rule: string;
  // card left border
  border: string;
  // inline separator
  dot: string;
  bullet: string;
  ellipsis: string;
}

export const UNICODE_GLYPHS: Glyphs = {
  ok: '✓',
  fail: '✗',
  warn: '!',
  info: '·',
  skip: '·',
  prompt: '?',
  hex: '⬢',
  done: '☒',
  current: '▣',
  todo: '☐',
  arrow: '→',
  rule: '─',
  border: '│',
  dot: '·',
  bullet: '·',
  ellipsis: '…',
};

export const ASCII_GLYPHS: Glyphs = {
  ok: '+',
  fail: 'x',
  warn: '!',
  info: '-',
  skip: '-',
  prompt: '?',
  hex: '*',
  done: '[x]',
  current: '[>]',
  todo: '[ ]',
  arrow: '->',
  rule: '-',
  border: '|',
  dot: '-',
  bullet: '-',
  ellipsis: '...',
};

// ascii forms for text outside the ui
export function toAscii(text: string): string {
  return text
    .replace(/→/g, '->')
    .replace(/─/g, '-')
    .replace(/│/g, '|')
    .replace(/·/g, '-')
    .replace(/…/g, '...')
    .replace(/✓/g, '+')
    .replace(/✗/g, 'x')
    .replace(/⬢/g, '*')
    .replace(/☒/g, '[x]')
    .replace(/▣/g, '[>]')
    .replace(/☐/g, '[ ]');
}

export type PhaseNumber = 1 | 2 | 3;

// 1 green, 2 purple, 3 red
export const PHASES: Record<PhaseNumber, { title: string; subtitle: string; hex: string; basic: 'green' | 'magenta' | 'red' }> = {
  1: { title: 'Take in evidence', subtitle: 'Deterministic code, no LLM', hex: '#2f9e6f', basic: 'green' },
  2: { title: 'Investigate and decide', subtitle: 'Agentic LLM loop via Ollama', hex: '#8b6cf0', basic: 'magenta' },
  3: { title: 'Act safely', subtitle: 'Human approval required', hex: '#d0513a', basic: 'red' },
};

export type ChecklistState = 'done' | 'current' | 'pending';

export interface ChecklistItem {
  title: string;
  state: ChecklistState;
}

const RISK_HEX: Record<RiskLevel, string> = {
  Critical: '#ff5f5f',
  High: '#ff9f43',
  Medium: '#f2cc4b',
  Low: '#5fafff',
  Noise: '#8a8a8a',
};

const PURPLE_HEX = '#b48cff';
const BLUE_HEX = '#6cb6ff';
const GREEN_HEX = '#56d364';

export interface TableColumn {
  key: string;
  header: string;
  align?: 'left' | 'right';
  // longer cells get an ellipsis
  maxWidth?: number;
  // floor when fitting
  minWidth?: number;
}

export type TableRow = Record<string, string | number | boolean | null | undefined>;

export interface TableOptions {
  // default ui width, max 100
  maxWidth?: number;
  indent?: number;
  // default 2
  gap?: number;
  header?: boolean;
  // default ─
  ruleChar?: string;
  ellipsis?: string;
}

export interface Spinner {
  readonly enabled: boolean;
  start(text?: string): Spinner;
  update(text: string): Spinner;
  // prints a ✓ line
  succeed(text?: string): void;
  // ✗ line on stderr
  fail(text?: string): void;
  // ! line on stderr
  warn(text?: string): void;
  info(text?: string): void;
  // clears, prints nothing
  stop(): void;
}

// rewritable on a tty, else one per message
export interface ProgressLine {
  readonly tty: boolean;
  update(text: string): void;
  done(text?: string): void;
}

export interface UiOptions {
  // undefined auto-detects
  color?: boolean;
  quiet?: boolean;
  json?: boolean;
  verbose?: boolean;
  // tty, not --ci, not --json
  interactive?: boolean;
  // auto-detected by default
  unicode?: boolean;
  // capped at 100
  width?: number;
  env?: NodeJS.ProcessEnv;
  stdout?: OutStream;
  stderr?: OutStream;
  stdin?: InStream;
  // tests pass a fake
  now?: () => number;
}

export interface AgentLineOptions {
  // e.g. "evidence gate"
  tag?: TraceLabel | string;
}

export interface SummaryCounts {
  total: number;
  byRisk: Partial<Record<RiskLevel, number>>;
  // default "CVEs scanned"
  noun?: string;
}

export interface FooterInfo {
  model: string;
  numCtx?: number;
  packages?: number;
  cves?: number;
  elapsedMs?: number;
}

export interface ActionItemInfo {
  n: number;
  pkg: string;
  from: string;
  to: string;
  risk: RiskLevel;
  // e.g. "Patch: version bump only, no breaking changes"
  patchNote?: string;
  // e.g. "Source changes: none required"
  sourceNote?: string;
}

// ignores ansi codes
export function visibleLength(text: string): number {
  return stripVTControlCharacters(text).length;
}

export function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

// cut with an ellipsis
export function truncateLine(text: string, max: number, ellipsis = '…'): string {
  const single = oneLine(text);
  if (visibleLength(single) <= max) return single;
  const plain = stripVTControlCharacters(single);
  if (max <= ellipsis.length) return plain.slice(0, max);
  return plain.slice(0, max - ellipsis.length) + ellipsis;
}

// cuts long words
export function wrapText(text: string, width: number): string[] {
  const out: string[] = [];
  const w = Math.max(10, width);
  for (const paragraph of text.split('\n')) {
    const words = paragraph.split(/\s+/).filter(Boolean);
    if (words.length === 0) {
      out.push('');
      continue;
    }
    let line = '';
    for (let word of words) {
      while (word.length > w) {
        if (line) {
          out.push(line);
          line = '';
        }
        out.push(word.slice(0, w));
        word = word.slice(w);
      }
      if (!line) line = word;
      else if (line.length + 1 + word.length <= w) line += ` ${word}`;
      else {
        out.push(line);
        line = word;
      }
    }
    if (line) out.push(line);
  }
  return out;
}

// shown when the trace cuts prose
export const THOUGHT_MARKER = '(full reasoning in the report)';

// prose lines before the cut
export const THOUGHT_MAX_LINES = 5;

export interface ProseFit {
  // without the marker
  lines: string[];
  // caller adds the marker
  cut: boolean;
}

// keeps single line breaks
function normalizeProse(text: string): string {
  return text
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t\f\v]+/g, ' ')
    .replace(/ *\n\s*/g, '\n')
    .trim();
}

function markerFits(line: string, marker: string, width: number): boolean {
  return visibleLength(line) + 1 + marker.length <= width;
}

// cut at a sentence, else a word
export function fitProse(text: string, width: number, options: { maxLines?: number; marker?: string } = {}): ProseFit {
  const maxLines = Math.max(1, options.maxLines ?? THOUGHT_MAX_LINES);
  const marker = options.marker ?? THOUGHT_MARKER;
  const w = Math.max(10, width);
  const prose = normalizeProse(text);
  const all = prose === '' ? [] : wrapText(prose, w);
  if (all.length <= maxLines) return { lines: all, cut: false };
  const sentenceCuts: number[] = [];
  const wordCuts: number[] = [];
  let inCode = false;
  for (let i = 0; i < prose.length; i += 1) {
    const ch = prose[i];
    if (ch === '`') {
      inCode = !inCode;
      continue;
    }
    if (inCode || (ch !== ' ' && ch !== '\n')) continue;
    wordCuts.push(i);
    const prev = prose[i - 1];
    if (ch === '\n' || prev === '.' || prev === '!' || prev === '?') sentenceCuts.push(i);
  }
  const fits = (end: number): string[] | null => {
    const lines = wrapText(prose.slice(0, end).trimEnd(), w);
    if (lines.length < maxLines) return lines;
    if (lines.length === maxLines && markerFits(lines[maxLines - 1] ?? '', marker, w)) return lines;
    return null;
  };
  // w chars plus the break space
  const limit = maxLines * (w + 1);
  for (const cuts of [sentenceCuts, wordCuts]) {
    for (let k = cuts.length - 1; k >= 0; k -= 1) {
      const end = cuts[k] ?? 0;
      if (end === 0 || end > limit) continue;
      const lines = fits(end);
      if (lines) return { lines, cut: true };
    }
  }
  return { lines: [], cut: true };
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '?';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes} min ${seconds} s`;
}

// "850ms", "12s", "4m 12s", "1h 5m"
export function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '?';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const totalSeconds = Math.round(ms / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m ${seconds}s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '?';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(1)} ${units[unit]}`;
}

// 16384 -> "16k"
export function formatContext(numCtx: number): string {
  return numCtx >= 1024 && numCtx % 1024 === 0 ? `${numCtx / 1024}k` : String(numCtx);
}

function formatArgValue(value: unknown): string {
  if (typeof value === 'string') return truncateLine(value, 60);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null || value === undefined) return String(value);
  return truncateLine(JSON.stringify(value), 60);
}

// e.g. lodash, template
export function formatArgs(args: Record<string, unknown> | null | undefined): string {
  if (!args) return '';
  return Object.values(args)
    .filter((v) => v !== undefined)
    .map(formatArgValue)
    .join(', ');
}

// shrinks widest columns to fit
export function renderTable(columns: readonly TableColumn[], rows: readonly TableRow[], c: ChalkInstance, options: TableOptions = {}): string {
  const gap = options.gap ?? 2;
  const indent = options.indent ?? 0;
  const showHeader = options.header ?? true;
  const ellipsis = options.ellipsis ?? '…';
  const cells = rows.map((row) => columns.map((col) => (row[col.key] === null || row[col.key] === undefined ? '' : String(row[col.key]))));
  const widths = columns.map((col, i) => {
    const contentMax = Math.max(showHeader ? col.header.length : 0, ...cells.map((r) => visibleLength(r[i] ?? '')));
    return Math.min(contentMax, col.maxWidth ?? Number.POSITIVE_INFINITY);
  });
  const limit = Math.min(options.maxWidth ?? MAX_WIDTH, MAX_WIDTH);
  const total = (): number => indent + widths.reduce((a, b) => a + b, 0) + gap * Math.max(0, columns.length - 1);
  let guard = 0;
  while (total() > limit && guard < 1000) {
    guard += 1;
    let widest = -1;
    for (let i = 0; i < widths.length; i += 1) {
      const floor = Math.max(columns[i]?.minWidth ?? 4, Math.min(columns[i]?.header.length ?? 4, 12));
      if ((widths[i] ?? 0) > floor && (widest === -1 || (widths[i] ?? 0) > (widths[widest] ?? 0))) widest = i;
    }
    if (widest === -1) break;
    widths[widest] = (widths[widest] ?? 1) - 1;
  }
  const fit = (text: string, width: number, align: 'left' | 'right' = 'left'): string => {
    let out = text;
    if (visibleLength(out) > width) out = truncateLine(out, width, ellipsis);
    const pad = ' '.repeat(Math.max(0, width - visibleLength(out)));
    return align === 'right' ? pad + out : out + pad;
  };
  const lines: string[] = [];
  const prefix = ' '.repeat(indent);
  const join = (parts: string[]): string => (prefix + parts.join(' '.repeat(gap))).replace(/\s+$/, '');
  if (showHeader) {
    lines.push(join(columns.map((col, i) => c.bold(fit(col.header, widths[i] ?? 0, col.align)))));
    lines.push(join(columns.map((_, i) => c.dim((options.ruleChar ?? '─').repeat(widths[i] ?? 0)))));
  }
  for (const row of cells) lines.push(join(columns.map((col, i) => fit(row[i] ?? '', widths[i] ?? 0, col.align))));
  return lines.join('\n');
}

// drops the file headers
function diffBodyLines(unifiedDiff: string): string[] {
  const lines = unifiedDiff.replace(/\r\n/g, '\n').split('\n');
  const body: string[] = [];
  let inHunk = false;
  for (const line of lines) {
    if (line.startsWith('@@')) {
      inHunk = true;
      continue;
    }
    if (!inHunk) continue; // Index:, ====, ---, +++ headers
    body.push(line);
  }
  while (body.length > 0 && body[body.length - 1] === '') body.pop();
  return body;
}

// middle dots only
const DOT_SPINNER = { interval: 110, frames: ['·  ', '·· ', '···', ' ··', '  ·', '   '] };

class StaticSpinner implements Spinner {
  readonly enabled = false;
  private readonly ui: Ui;
  private text: string;
  constructor(ui: Ui, text: string) {
    this.ui = ui;
    this.text = text;
  }
  start(text?: string): Spinner {
    if (text) {
      this.text = text;
      this.ui.status.mirror(text);
    }
    return this;
  }
  update(text: string): Spinner {
    this.text = text;
    this.ui.status.mirror(text);
    return this;
  }
  succeed(text?: string): void {
    this.ui.check(text ?? this.text);
  }
  fail(text?: string): void {
    this.ui.fail(text ?? this.text);
  }
  warn(text?: string): void {
    this.ui.warn(text ?? this.text);
  }
  info(text?: string): void {
    this.ui.infoLine(text ?? this.text);
  }
  stop(): void {}
}

class OraSpinner implements Spinner {
  readonly enabled = true;
  private readonly ui: Ui;
  private readonly ora: Ora;
  private readonly release: () => void;
  constructor(ui: Ui, instance: Ora, release: () => void) {
    this.ui = ui;
    this.ora = instance;
    this.release = release;
  }
  start(text?: string): Spinner {
    if (text) this.ui.status.mirror(text);
    this.ora.start(text);
    return this;
  }
  update(text: string): Spinner {
    this.ora.text = text;
    this.ui.status.mirror(text);
    return this;
  }
  private finish(): string {
    const text = this.ora.text;
    this.ora.stop();
    this.release();
    return text;
  }
  succeed(text?: string): void {
    const last = this.finish();
    this.ui.check(text ?? last);
  }
  fail(text?: string): void {
    const last = this.finish();
    this.ui.fail(text ?? last);
  }
  warn(text?: string): void {
    const last = this.finish();
    this.ui.warn(text ?? last);
  }
  info(text?: string): void {
    const last = this.finish();
    this.ui.infoLine(text ?? last);
  }
  stop(): void {
    this.finish();
  }
}

const ESC = '\u001b';

export const STATUS_BAR_ROWS = 3;

// smaller terminals get plain lines
export const STATUS_MIN_ROWS = 12;

export interface StatusState {
  // kept from last call when omitted
  phases?: readonly ChecklistItem[];
  // cleared when omitted
  activity?: string;
  // cleared when omitted
  detail?: string;
}

export interface StatusSnapshot {
  phases: ChecklistItem[];
  activity: string | undefined;
  detail: string | undefined;
}

interface StatusBarOptions {
  // stderr
  stream: OutStream;
  // stdout, region only helps same terminal
  flow: OutStream;
  env: NodeJS.ProcessEnv;
  // --quiet or --json
  silent: boolean;
  c: ChalkInstance;
  glyphs: Glyphs;
  // ascii fallback
  text: (value: string) => string;
  now: () => number;
}

interface Segment {
  text: string;
  style?: (text: string) => string;
}

// cuts first overflow with an ellipsis
function fitSegments(segments: readonly Segment[], width: number, ellipsis: string): string {
  let out = '';
  let used = 0;
  for (const segment of segments) {
    if (segment.text === '') continue;
    const room = width - used;
    if (room <= 0) break;
    let text = segment.text;
    const overflow = text.length > room;
    if (overflow) text = room > ellipsis.length ? `${text.slice(0, room - ellipsis.length)}${ellipsis}` : ellipsis.slice(0, room);
    out += segment.style ? segment.style(text) : text;
    used += text.length;
    if (overflow) break;
  }
  return out;
}

function segmentsLength(segments: readonly Segment[]): number {
  return segments.reduce((n, s) => n + s.text.length, 0);
}

// "0s", "12s", "2m 10s"
function formatClock(ms: number): string {
  const seconds = Number.isFinite(ms) ? Math.max(0, Math.floor(ms / 1000)) : 0;
  return seconds === 0 ? '0s' : formatElapsed(seconds * 1000);
}

// drops the spinner's "..."
function statusText(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const text = oneLine(stripVTControlCharacters(value)).replace(/\s*(?:\.{3}|…)$/, '');
  return text === '' ? undefined : text;
}

function usableSize(rows: number, columns: number): boolean {
  return Number.isFinite(rows) && Number.isFinite(columns) && columns > 0 && rows >= STATUS_MIN_ROWS;
}

const runningBars = new Set<StatusBar>();

// error and interrupt paths
export function restoreTerminal(): void {
  for (const bar of [...runningBars]) bar.stop();
}

// 3 rows under a DECSTBM scroll region
export class StatusBar {
  private readonly stream: OutStream;
  private readonly flow: OutStream;
  private readonly env: NodeJS.ProcessEnv;
  private readonly silent: boolean;
  private readonly c: ChalkInstance;
  private readonly glyphs: Glyphs;
  private readonly text: (value: string) => string;
  private readonly now: () => number;
  private readonly rawWrite: (text: string) => void;
  private phases: ChecklistItem[] = [];
  private activity: string | undefined;
  private detail: string | undefined;
  // shown while no activity is set
  private mirrored: string | undefined;
  private running = false;
  private drawn = false;
  private rows = 0;
  private cols = 0;
  private startedAt = 0;
  private lastDrawn: string | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly listeners = new Set<(snapshot: StatusSnapshot) => void>();

  constructor(options: StatusBarOptions) {
    this.stream = options.stream;
    this.flow = options.flow;
    this.env = options.env;
    this.silent = options.silent;
    this.c = options.c;
    this.glyphs = options.glyphs;
    this.text = options.text;
    this.now = options.now;
    // ora swaps stream.write while spinning
    const write = options.stream.write;
    this.rawWrite = (text: string): void => {
      try {
        write.call(options.stream, text);
      } catch {
        // closed tty
      }
    };
  }

  // else plain checklist lines
  get enabled(): boolean {
    if (this.silent || !this.stream.isTTY || !this.flow.isTTY || this.env.TERM === 'dumb') return false;
    const { rows, columns } = this.size();
    return usableSize(rows, columns);
  }

  // false while terminal too small
  get active(): boolean {
    return this.running && this.drawn;
  }

  // no-op if disabled or running
  start(state?: StatusState): void {
    if (state) this.apply(state);
    if (this.running || !this.enabled) return;
    this.running = true;
    this.startedAt = this.now();
    this.hook();
    this.setup();
    this.timer = setInterval(() => this.tick(), 1000);
    this.timer.unref?.();
  }

  // redraws only on change
  set(state: StatusState): void {
    this.apply(state);
    this.draw();
    this.notify();
  }

  // fires even when not drawn
  onChange(listener: (snapshot: StatusSnapshot) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // safe to call twice
  stop(): void {
    if (!this.running) return;
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.unhook();
    if (this.drawn) this.restore();
    this.drawn = false;
    this.lastDrawn = null;
  }

  // null clears it
  mirror(text: string | null | undefined): void {
    const next = statusText(text ?? undefined);
    if (next === this.mirrored) return;
    this.mirrored = next;
    if (this.activity === undefined) this.draw();
  }

  // keep prompts off the bar rows
  ensureRows(rows: number): void {
    if (!this.active) return;
    const count = Math.max(0, Math.min(Math.floor(rows), this.rows - STATUS_BAR_ROWS - 1));
    if (count > 0) this.rawWrite(`${'\n'.repeat(count)}${ESC}[${count}A`);
  }

  // plus one for the answer
  rowsFor(text: string): number {
    const columns = Math.max(1, this.cols);
    return text.split('\n').reduce((n, line) => n + Math.max(1, Math.ceil(visibleLength(line) / columns)), 0) + 1;
  }

  // rule, checklist, activity
  render(width = this.width()): string[] {
    return [this.c.dim(this.glyphs.rule.repeat(Math.max(1, width))), this.checklistRow(width), this.activityRow(width)];
  }

  // elapsed timer, writes only on change
  tick(): void {
    this.draw();
  }

  // SIGWINCH
  resize(): void {
    if (!this.running) return;
    const { rows, columns } = this.size();
    if (this.drawn && rows === this.rows && columns === this.cols) return;
    if (this.drawn) {
      // erase down to clear the moved bar
      this.rawWrite(`${ESC}7${ESC}[r${ESC}8${ESC}[J`);
      this.drawn = false;
    }
    this.setup();
  }

  private readonly onResize = (): void => this.resize();
  private readonly onExit = (): void => this.stop();
  private readonly onCrash = (): void => this.stop();
  private readonly onSignal = (signal: NodeJS.Signals): void => {
    this.stop();
    // re-raise, exit 130 on ctrl+c
    process.kill(process.pid, signal);
  };

  private size(): { rows: number; columns: number } {
    return { rows: Number(this.stream.rows ?? 0), columns: Number(this.stream.columns ?? 0) };
  }

  // one short to avoid autowrap, max 100
  private width(): number {
    return Math.max(1, Math.min(this.cols - 1, MAX_WIDTH));
  }

  private notify(): void {
    if (this.listeners.size === 0) return;
    const snapshot: StatusSnapshot = { phases: this.phases.map((item) => ({ ...item })), activity: this.activity, detail: this.detail };
    for (const listener of this.listeners) {
      try {
        listener(snapshot);
      } catch {
        // never break the run
      }
    }
  }

  private apply(state: StatusState): void {
    if (state.phases) this.phases = state.phases.map((item) => ({ ...item }));
    this.activity = statusText(state.activity);
    this.detail = statusText(state.detail);
    this.mirrored = undefined;
  }

  private hook(): void {
    runningBars.add(this);
    process.once('exit', this.onExit);
    process.on('SIGINT', this.onSignal);
    process.on('SIGTERM', this.onSignal);
    process.on('uncaughtExceptionMonitor', this.onCrash);
    process.on('SIGWINCH', this.onResize);
    this.stream.on('resize', this.onResize);
  }

  private unhook(): void {
    runningBars.delete(this);
    process.off('exit', this.onExit);
    process.off('SIGINT', this.onSignal);
    process.off('SIGTERM', this.onSignal);
    process.off('uncaughtExceptionMonitor', this.onCrash);
    process.off('SIGWINCH', this.onResize);
    this.stream.off('resize', this.onResize);
  }

  // scroll up, set region, draw
  private setup(): void {
    const { rows, columns } = this.size();
    this.rows = rows;
    this.cols = columns;
    if (!usableSize(rows, columns)) {
      this.drawn = false;
      return;
    }
    const n = STATUS_BAR_ROWS;
    this.rawWrite(`${'\n'.repeat(n)}${ESC}7${ESC}[1;${rows - n}r${ESC}8${ESC}[${n}A`);
    this.drawn = true;
    this.lastDrawn = null;
    this.draw();
  }

  private draw(): void {
    if (!this.running || !this.drawn) return;
    const lines = this.render();
    const key = lines.join('\n');
    if (key === this.lastDrawn) return;
    this.lastDrawn = key;
    const top = this.rows - STATUS_BAR_ROWS + 1;
    let out = `${ESC}7`;
    lines.forEach((line, i) => {
      out += `${ESC}[${top + i};1H${line}${ESC}[K`;
    });
    this.rawWrite(`${out}${ESC}8`);
  }

  private restore(): void {
    const top = this.rows - STATUS_BAR_ROWS + 1;
    let out = `${ESC}7${ESC}[r`;
    for (let i = 0; i < STATUS_BAR_ROWS; i += 1) out += `${ESC}[${top + i};1H${ESC}[2K`;
    this.rawWrite(`${out}${ESC}8`);
  }

  private checklistRow(width: number): string {
    const c = this.c;
    const g = this.glyphs;
    const items: Segment[] = [];
    for (const item of this.phases) {
      const glyph = item.state === 'done' ? g.done : item.state === 'current' ? g.current : g.todo;
      items.push({ text: '   ' }, { text: `${glyph} ${this.text(item.title)}`, style: item.state === 'current' ? c.bold : c.dim });
    }
    const count = this.phases.length;
    const title: Segment[] = [
      { text: g.hex, style: c.dim },
      { text: ' ' },
      { text: 'Working', style: c.bold },
      { text: count > 0 ? ` on ${count} phase${count === 1 ? '' : 's'}` : '' },
    ];
    const full = [...title, ...items];
    if (segmentsLength(full) <= width) return fitSegments(full, width, g.ellipsis);
    // narrow: drop the title
    return fitSegments([{ text: g.hex, style: c.dim }, ...items.map((s, i) => (i === 0 ? { text: ' ' } : s))], width, g.ellipsis);
  }

  private activityRow(width: number): string {
    const c = this.c;
    const dot = this.glyphs.dot;
    const elapsed = formatClock(this.now() - this.startedAt);
    const main = this.activity ?? this.mirrored;
    if (!main) return fitSegments([{ text: '  ' }, { text: elapsed, style: c.dim }], width, this.glyphs.ellipsis);
    const suffix = ` ${dot} ${elapsed}`;
    const segments: Segment[] = [{ text: '  ' }, { text: this.text(main) }];
    if (this.activity !== undefined && this.detail) segments.push({ text: ` ${dot} `, style: c.dim }, { text: this.text(this.detail), style: c.dim });
    if (width <= suffix.length + 4) return fitSegments([...segments, { text: suffix, style: c.dim }], width, this.glyphs.ellipsis);
    return `${fitSegments(segments, width - suffix.length, this.glyphs.ellipsis)}${c.dim(suffix)}`;
  }
}

export class Ui {
  readonly quiet: boolean;
  readonly json: boolean;
  readonly verbose: boolean;
  readonly interactive: boolean;
  readonly ascii: boolean;
  readonly glyphs: Glyphs;
  // stdout styling
  readonly c: ChalkInstance;
  // stderr styling
  readonly ce: ChalkInstance;
  // no-op without a capable terminal
  readonly status: StatusBar;
  private readonly stdout: OutStream;
  private readonly stderr: OutStream;
  private readonly stdin: InStream;
  private readonly widthOverride: number | undefined;
  private active: Ora | null = null;

  constructor(options: UiOptions = {}) {
    const env = options.env ?? process.env;
    this.stdout = options.stdout ?? process.stdout;
    this.stderr = options.stderr ?? process.stderr;
    this.stdin = options.stdin ?? process.stdin;
    this.quiet = options.quiet ?? false;
    this.json = options.json ?? false;
    this.verbose = options.verbose ?? false;
    this.interactive = options.interactive ?? false;
    this.widthOverride = options.width;
    const flag = options.color === false ? false : undefined;
    this.c = new Chalk({ level: resolveColorLevel({ env, flag, stream: this.stdout }) });
    this.ce = new Chalk({ level: resolveColorLevel({ env, flag, stream: this.stderr }) });
    const colorOff = options.color === false || (env.NO_COLOR !== undefined && env.NO_COLOR !== '' && env.FORCE_COLOR === undefined);
    this.ascii = options.unicode !== undefined ? !options.unicode : colorOff || !this.stdout.isTTY || !supportsUnicode(env);
    this.glyphs = this.ascii ? ASCII_GLYPHS : UNICODE_GLYPHS;
    this.status = new StatusBar({
      stream: this.stderr,
      flow: this.stdout,
      env,
      silent: this.quiet || this.json,
      c: this.ce,
      glyphs: this.glyphs,
      text: (value) => this.text(value),
      now: options.now ?? Date.now,
    });
  }

  // capped at 100, 100 when unknown
  get width(): number {
    const cols = this.widthOverride ?? (this.stdout.columns && this.stdout.columns > 20 ? this.stdout.columns : MAX_WIDTH);
    return Math.min(cols, MAX_WIDTH);
  }

  // for table sizing
  get columns(): number {
    return this.width;
  }

  // uncapped
  get terminalWidth(): number {
    if (this.widthOverride !== undefined) return Math.max(1, this.widthOverride);
    const cols = this.stdout.columns;
    return typeof cols === 'number' && cols > 20 ? cols : MAX_WIDTH;
  }

  get stdoutIsTTY(): boolean {
    return Boolean(this.stdout.isTTY);
  }

  get stderrIsTTY(): boolean {
    return Boolean(this.stderr.isTTY);
  }

  text(value: string): string {
    return this.ascii ? toAscii(value) : value;
  }

  private tint(hex: string, basic: 'blue' | 'green' | 'magenta' | 'red' | 'yellow' | 'gray', c: ChalkInstance = this.c): ChalkInstance {
    return c.level >= 2 ? c.hex(hex) : c[basic];
  }

  blue(text: string, c: ChalkInstance = this.c): string {
    return this.tint(BLUE_HEX, 'blue', c)(text);
  }

  green(text: string, c: ChalkInstance = this.c): string {
    return this.tint(GREEN_HEX, 'green', c)(text);
  }

  purple(text: string, c: ChalkInstance = this.c): string {
    return this.tint(PURPLE_HEX, 'magenta', c)(text);
  }

  dim(text: string, c: ChalkInstance = this.c): string {
    return c.dim(text);
  }

  riskColor(level: RiskLevel, c: ChalkInstance = this.c): ChalkInstance {
    if (c.level >= 2) return c.hex(RISK_HEX[level]);
    switch (level) {
      case 'Critical':
        return c.red;
      case 'High':
        return c.redBright;
      case 'Medium':
        return c.yellow;
      case 'Low':
        return c.blue;
      default:
        return c.gray;
    }
  }

  private write(stream: OutStream, text: string): void {
    const spinning = this.active?.isSpinning ? this.active : null;
    spinning?.clear();
    stream.write(text.endsWith('\n') ? text : `${text}\n`);
    spinning?.render();
  }

  // stdout, only --json hides it
  print(text = ''): void {
    if (this.json) return;
    this.write(this.stdout, text);
  }

  // stdout, hidden by --quiet and --json
  info(text = ''): void {
    if (this.quiet || this.json) return;
    this.write(this.stdout, text);
  }

  // stderr, always shown
  errorBlock(text: string): void {
    this.write(this.stderr, text);
  }

  // stderr, --verbose only
  debug(text: string): void {
    if (!this.verbose) return;
    this.write(this.stderr, this.ce.dim(text));
  }

  // only output in --json mode
  printJson(value: unknown): void {
    this.write(this.stdout, JSON.stringify(value, null, 2));
  }

  // then the dim project dir
  formatHeader(version: string, subtitle = 'Dependency security agent', dir?: string): string {
    const c = this.c;
    const first = `${this.blue(`PatchPilot v${version}`)} ${c.dim(`${this.glyphs.dot} ${subtitle}`)}`;
    return dir ? `${first}\n${c.dim(this.text(dir))}` : first;
  }

  header(version: string, subtitle?: string, dir?: string): void {
    this.info(this.formatHeader(version, subtitle, dir));
    this.info('');
  }

  formatRule(width = this.width): string {
    return this.c.dim(this.glyphs.rule.repeat(Math.max(1, Math.min(width, MAX_WIDTH))));
  }

  rule(): void {
    this.info(this.formatRule());
  }

  formatSectionHeader(text: string, color: 'blue' | 'green' = 'blue'): string {
    return color === 'green' ? this.green(this.text(text)) : this.blue(this.text(text));
  }

  // green for "Action required"
  sectionHeader(text: string, color: 'blue' | 'green' = 'blue'): void {
    this.info('');
    this.rule();
    this.info('');
    this.info(this.formatSectionHeader(text, color));
    this.info('');
  }

  renderBanner(phase: PhaseNumber, detail?: string): string {
    const spec = PHASES[phase];
    const c = this.c;
    const tint = c.level >= 2 ? c.hex(spec.hex) : c[spec.basic];
    return `${tint.bold(`Phase ${phase}: ${spec.title}`)} ${c.dim(`${this.glyphs.dot} ${detail ?? spec.subtitle}`)}`;
  }

  banner(phase: PhaseNumber, detail?: string): void {
    this.info('');
    this.info(this.renderBanner(phase, detail));
  }

  // dim part wraps under itself
  private statusLine(symbol: string, text: string, dimPart: string | undefined, c: ChalkInstance): string {
    const head = `${symbol} ${this.text(text)}`;
    if (!dimPart) return head;
    const detail = this.text(dimPart);
    const headLength = visibleLength(head);
    if (headLength + 2 + detail.length <= this.width) return `${head}  ${c.dim(detail)}`;
    const indent = headLength + 2 <= Math.floor(this.width * 0.6) ? headLength + 2 : visibleLength(symbol) + 1;
    const wrapped = wrapText(detail, this.width - indent);
    if (indent === headLength + 2) {
      const [first = '', ...rest] = wrapped;
      return [`${head}  ${c.dim(first)}`, ...rest.map((l) => `${' '.repeat(indent)}${c.dim(l)}`)].join('\n');
    }
    return [head, ...wrapped.map((l) => `${' '.repeat(indent)}${c.dim(l)}`)].join('\n');
  }

  // e.g. "✓ Parsed 847 dependencies"
  formatCheck(text: string, dimPart?: string, c: ChalkInstance = this.c): string {
    return this.statusLine(this.green(this.glyphs.ok, c), text, dimPart, c);
  }

  formatFail(text: string, dimPart?: string, c: ChalkInstance = this.ce): string {
    return this.statusLine(c.red(this.glyphs.fail), text, dimPart, c);
  }

  formatWarn(text: string, dimPart?: string, c: ChalkInstance = this.ce): string {
    return this.statusLine(c.yellow(this.glyphs.warn), text, dimPart, c);
  }

  formatInfoLine(text: string, dimPart?: string, c: ChalkInstance = this.c): string {
    return this.statusLine(c.dim(this.glyphs.info), text, dimPart, c);
  }

  // stdout
  check(text: string, dimPart?: string): void {
    this.info(this.formatCheck(text, dimPart));
  }

  // kept for spinners and old callers
  success(text: string, dimPart?: string): void {
    this.check(text, dimPart);
  }

  // stderr, always shown
  fail(text: string, dimPart?: string): void {
    this.write(this.stderr, this.formatFail(text, dimPart));
  }

  // stderr, always shown
  warn(text: string, dimPart?: string): void {
    this.write(this.stderr, this.formatWarn(text, dimPart));
  }

  // stderr, always shown
  error(text: string): void {
    this.fail(text);
  }

  // hidden by --quiet and --json
  infoLine(text: string, dimPart?: string): void {
    this.info(this.formatInfoLine(text, dimPart));
  }

  // stderr, hidden by --quiet
  notice(text: string, dimPart?: string): void {
    if (this.quiet) return;
    this.write(this.stderr, this.formatInfoLine(text, dimPart, this.ce));
  }

  // fixes, links and notes
  formatDimLines(lines: readonly string[], indent = 2, c: ChalkInstance = this.c): string {
    return lines.map((l) => `${' '.repeat(indent)}${c.dim(this.text(l))}`).join('\n');
  }

  // "⬢ Working on 3 phases" + one per phase
  formatChecklist(items: readonly ChecklistItem[], title = `Working on ${items.length} phases`): string {
    const c = this.c;
    const [first, ...rest] = title.split(' ');
    const lines = [`${c.dim(this.glyphs.hex)} ${c.bold(first ?? '')}${rest.length ? ` ${rest.join(' ')}` : ''}`];
    for (const item of items) {
      if (item.state === 'done') lines.push(`  ${c.dim(`${this.glyphs.done} ${item.title}`)}`);
      else if (item.state === 'current') lines.push(`  ${c.bold(`${this.glyphs.current} ${item.title}`)}`);
      else lines.push(`  ${c.dim(`${this.glyphs.todo} ${item.title}`)}`);
    }
    return lines.join('\n');
  }

  // "complete" means all done
  phaseItems(current: PhaseNumber | 'complete'): ChecklistItem[] {
    return ([1, 2, 3] as const).map((n) => ({
      title: PHASES[n].title,
      state: current === 'complete' || n < current ? 'done' : n === current ? 'current' : 'pending',
    }));
  }

  phaseChecklist(current: PhaseNumber | 'complete' | readonly ChecklistItem[], title?: string): void {
    const items = typeof current === 'object' ? current : this.phaseItems(current);
    this.info('');
    this.info(this.formatChecklist(items, title));
    this.info('');
  }

  // e.g. "⬢ Investigating lodash@4.17.20"
  formatActivity(text: string): string {
    return `${this.green(this.glyphs.hex)} ${this.green(this.c.bold(this.text(text)))}`;
  }

  activity(text: string): void {
    this.info(this.formatActivity(text));
  }

  // purple agent, dim [tag], action
  formatAgentLine(action: string, options: AgentLineOptions = {}, width = this.width): string[] {
    const c = this.c;
    const label = this.purple('agent');
    const tag = options.tag ? `${c.dim(`[${options.tag}]`)} ` : '';
    const lead = 6 + (options.tag ? options.tag.length + 3 : 0);
    const wrapped = wrapText(this.text(action), Math.max(20, width - lead));
    return wrapped.map((line, i) => (i === 0 ? `${label} ${tag}${line}` : `${' '.repeat(lead)}${line}`));
  }

  agentLine(action: string, options: AgentLineOptions = {}): void {
    this.info(this.formatAgentLine(action, options).join('\n'));
  }

  // max five lines unless --verbose
  formatThoughtLines(text: string, options: AgentLineOptions & { full?: boolean } = {}, width = this.width): string[] {
    const c = this.c;
    const label = this.purple('agent');
    const tag = options.tag ? `${c.dim(`[${options.tag}]`)} ` : '';
    const lead = 6 + (options.tag ? options.tag.length + 3 : 0);
    const inner = Math.max(20, width - lead);
    const prose = this.text(text);
    const fit = (options.full ?? this.verbose) ? { lines: wrapText(normalizeProse(prose), inner), cut: false } : fitProse(prose, inner);
    const lines = [...fit.lines];
    if (fit.cut) {
      const last = lines[lines.length - 1];
      if (last !== undefined && markerFits(last, THOUGHT_MARKER, inner)) lines[lines.length - 1] = `${last} ${c.dim(THOUGHT_MARKER)}`;
      else lines.push(c.dim(THOUGHT_MARKER));
    }
    if (lines.length === 0) lines.push('');
    return lines.map((line, i) => (i === 0 ? `${label} ${tag}${line}` : `${' '.repeat(lead)}${line}`));
  }

  agentThought(text: string, options: AgentLineOptions = {}): void {
    this.info(this.formatThoughtLines(text, options).join('\n'));
  }

  formatResultLine(text: string, width = this.width): string[] {
    return wrapText(this.text(text), Math.max(20, width - 2)).map((line) => `  ${this.c.dim(line)}`);
  }

  resultLine(text: string): void {
    this.info(this.formatResultLine(text).join('\n'));
  }

  // [CRITICAL] without colour
  pill(level: RiskLevel, c: ChalkInstance = this.c): string {
    const label = level.toUpperCase();
    if (c.level === 0) return `[${label}]`;
    if (c.level >= 2) {
      const bg = c.bgHex(RISK_HEX[level]);
      const fg = level === 'Medium' || level === 'High' ? bg.hex('#1b1b1b') : bg.whiteBright;
      return fg.bold(` ${label} `);
    }
    switch (level) {
      case 'Critical':
        return c.bgRed.whiteBright.bold(` ${label} `);
      case 'High':
        return c.bgRedBright.black.bold(` ${label} `);
      case 'Medium':
        return c.bgYellow.black.bold(` ${label} `);
      case 'Low':
        return c.bgBlue.whiteBright.bold(` ${label} `);
      default:
        return c.bgGray.whiteBright.bold(` ${label} `);
    }
  }

  // hanging indent
  formatVerdictLine(level: RiskLevel, sentence: string, width = this.width): string[] {
    const pill = this.pill(level);
    const lead = visibleLength(pill) + 2;
    const wrapped = wrapText(this.text(sentence), Math.max(20, width - lead));
    return wrapped.map((line, i) => (i === 0 ? `${pill}  ${line}` : `${' '.repeat(lead)}${line}`));
  }

  verdictLine(level: RiskLevel, sentence: string): void {
    this.info(this.formatVerdictLine(level, sentence).join('\n'));
  }

  // "Confidence: 95% · Recommended: bump to 4.17.21"
  formatConfidenceLine(confidence: number, recommendation: string): string {
    const pct = Math.round(Math.min(1, Math.max(0, confidence)) * 100);
    return this.c.dim(this.text(`Confidence: ${pct}% ${this.glyphs.dot} Recommended: ${recommendation}`));
  }

  confidenceLine(confidence: number, recommendation: string): void {
    this.info(this.formatConfidenceLine(confidence, recommendation));
  }

  // id in risk colour, package bold, score dim
  formatCardTitle(id: string, pkgAtVersion: string, scoreOrSeverity: string | null | undefined, level: RiskLevel | null): string {
    const c = this.c;
    const idText = level ? this.riskColor(level)(id) : c.dim(id);
    const sep = c.dim(` ${this.glyphs.dot} `);
    return `${idText}${sep}${c.bold(pkgAtVersion)}${scoreOrSeverity ? `${sep}${c.dim(scoreOrSeverity)}` : ''}`;
  }

  // risk-coloured left border
  card(level: RiskLevel | null): Card {
    return new Card(this, level);
  }

  // "12 CVEs scanned · 2 critical"
  formatSummaryLine(counts: SummaryCounts): string {
    const c = this.c;
    const sep = c.dim(` ${this.glyphs.dot} `);
    const order: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Noise'];
    const parts = [`${counts.total} ${counts.noun ?? 'CVEs scanned'}`];
    for (const level of order) {
      const n = counts.byRisk[level] ?? 0;
      if (n > 0) parts.push(this.riskColor(level)(`${n} ${level.toLowerCase()}`));
    }
    return parts.join(sep);
  }

  summaryLine(counts: SummaryCounts): void {
    this.info(this.formatSummaryLine(counts));
  }

  // plus dim patch and source notes
  formatActionItem(item: ActionItemInfo): string {
    const c = this.c;
    const num = `${item.n}.`;
    const indent = ' '.repeat(num.length + 1);
    const lines = [
      `${num} ${c.bold(item.pkg)} ${c.dim(`${item.from} ${this.glyphs.arrow} ${item.to}`)} ${this.riskColor(item.risk)(`[${item.risk.toUpperCase()}]`)}`,
    ];
    if (item.patchNote) lines.push(`${indent}${c.dim(this.text(item.patchNote))}`);
    if (item.sourceNote) lines.push(`${indent}${c.dim(this.text(item.sourceNote))}`);
    return lines.join('\n');
  }

  actionItem(item: ActionItemInfo): void {
    this.info(this.formatActionItem(item));
    this.info('');
  }

  // then the dim report path
  formatDoneLine(text: string, reportPath?: string): string {
    const first = this.green(this.text(text));
    return reportPath ? `${first}\n${this.c.dim(`Full report: ${reportPath}`)}` : first;
  }

  doneLine(text: string, reportPath?: string): void {
    this.info('');
    this.rule();
    this.info('');
    this.info(this.formatDoneLine(text, reportPath));
  }

  // model, context, packages, CVEs, elapsed
  formatFooter(info: FooterInfo): string {
    const parts = [info.model];
    if (info.numCtx !== undefined) parts.push(`${formatContext(info.numCtx)} ctx`);
    if (info.packages !== undefined) parts.push(`${info.packages} package${info.packages === 1 ? '' : 's'}`);
    if (info.cves !== undefined) parts.push(`${info.cves} CVE${info.cves === 1 ? '' : 's'}`);
    if (info.elapsedMs !== undefined) parts.push(formatElapsed(info.elapsedMs));
    return this.c.dim(parts.join(` ${this.glyphs.dot} `));
  }

  footer(info: FooterInfo): void {
    this.info('');
    this.info(this.formatFooter(info));
  }

  // capped at maxLines body lines
  formatDiffBlock(filePath: string, unifiedDiff: string, maxLines = 40): string {
    const c = this.c;
    const body = diffBodyLines(unifiedDiff);
    const shown = body.slice(0, Math.max(0, maxLines));
    const lines = [`  ${c.dim(filePath)}`];
    for (const line of shown) {
      if (line.startsWith('+')) lines.push(`  ${c.green(`+ ${line.slice(1)}`)}`);
      else if (line.startsWith('-')) lines.push(`  ${c.red(`- ${line.slice(1)}`)}`);
      else if (line.startsWith('\\')) lines.push(`  ${c.dim(line)}`);
      else lines.push(`  ${c.dim(`  ${line.startsWith(' ') ? line.slice(1) : line}`)}`);
    }
    if (body.length > shown.length) lines.push(`  ${c.dim(`${this.glyphs.ellipsis} ${body.length - shown.length} more lines (d to expand)`)}`);
    return lines.join('\n');
  }

  diffBlock(filePath: string, unifiedDiff: string, maxLines = 40): void {
    this.info(this.formatDiffBlock(filePath, unifiedDiff, maxLines));
    this.info('');
  }

  // "? Question (y/n)", labels spell out keys
  formatPrompt(question: string, keys: string, labels?: Record<string, string>): string {
    const hint = labels ? formatKeyLabels(keys, labels) : `(${keys})`;
    return `${this.blue(this.glyphs.prompt)} ${this.text(question)} ${this.c.dim(hint)}`;
  }

  // tty only, echoes key in blue
  async singleKeyPrompt(question: string, keys: string, options: { defaultKey?: string; labels?: Record<string, string> } = {}): Promise<string> {
    const allowed = keys
      .split('/')
      .map((k) => k.trim().toLowerCase())
      .filter((k) => k.length === 1);
    if (options.labels) allowed.push('?');
    const stdin = this.stdin;
    if (!this.interactive || !stdin.isTTY || typeof stdin.setRawMode !== 'function') {
      throw new PatchPilotError(`"${question}" needs an interactive terminal`, {
        exitCode: EXIT.USAGE,
        hint: 'Run it in a terminal, or use the non-interactive flags (--trust, --approve-all, --approve <pkgs>, --ci).',
      });
    }
    this.active?.stop();
    this.active = null;
    for (;;) {
      const prompt = `${this.formatPrompt(question, keys, options.labels)} `;
      // keep prompt above the status bar
      this.status.ensureRows(this.status.rowsFor(prompt));
      this.stdout.write(prompt);
      const key = await readSingleKey(stdin, allowed, options.defaultKey);
      this.stdout.write(`${this.blue(key)}\n`);
      if (key === '?' && options.labels) {
        this.stdout.write(`${this.c.dim(formatKeyLegend(keys, options.labels))}\n`);
        continue;
      }
      return key;
    }
  }

  // e.g. the accept-risk reason
  async textPrompt(question: string, options: { default?: string; validate?: (value: string) => true | string } = {}): Promise<string> {
    if (!this.interactive) {
      throw new PatchPilotError(`"${question}" needs an interactive terminal`, { exitCode: EXIT.USAGE });
    }
    this.active?.stop();
    this.active = null;
    // plus room for a validation message
    this.status.ensureRows(this.status.rowsFor(`? ${question} `) + 1);
    return input({
      message: this.text(question),
      default: options.default,
      validate: options.validate,
      theme: { prefix: this.blue(this.glyphs.prompt) },
    });
  }

  // static lines off a tty or quiet/json
  spinner(text: string, options: { prefix?: string } = {}): Spinner {
    // no width loops ora forever
    const columns = (this.stderr as { columns?: number }).columns;
    // bar shows it while no activity
    this.status.mirror(text);
    if (this.quiet || this.json || !this.stderr.isTTY || !(typeof columns === 'number' && columns > 0)) return new StaticSpinner(this, text);
    this.active?.stop();
    const instance = ora({
      text,
      prefixText: options.prefix,
      stream: this.stderr,
      discardStdin: false,
      spinner: DOT_SPINNER,
      color: this.ce.level > 0 ? 'magenta' : false,
      isEnabled: true,
    });
    this.active = instance;
    const spinner = new OraSpinner(this, instance, () => {
      if (this.active === instance) this.active = null;
    });
    return spinner.start();
  }

  // model pull, db sync
  progressLine(): ProgressLine {
    const silent = this.quiet || this.json;
    const tty = !silent && Boolean(this.stderr.isTTY);
    let last = '';
    let lastWrite = 0;
    return {
      tty,
      update: (text: string): void => {
        if (silent || text === last) return;
        if (tty) {
          const now = Date.now();
          if (now - lastWrite < 80) return;
          lastWrite = now;
          this.stderr.write(`\r\x1b[2K${truncateLine(text, Math.max(20, this.width - 1))}`);
        } else {
          this.write(this.stderr, this.text(text));
        }
        last = text;
      },
      done: (text?: string): void => {
        if (silent) return;
        if (tty) this.stderr.write('\r\x1b[2K');
        if (text) this.write(this.stderr, this.text(text));
      },
    };
  }

  // verbose only, e.g. full tool results
  detail(text: string, indent = 4): void {
    if (!this.verbose) return;
    this.info(this.formatDimLines(text.split('\n'), indent));
  }

  table(columns: readonly TableColumn[], rows: readonly TableRow[], options: TableOptions = {}): string {
    return renderTable(columns, rows, this.c, {
      maxWidth: this.width,
      ruleChar: this.glyphs.rule,
      ellipsis: this.glyphs.ellipsis,
      ...options,
    });
  }

  printTable(columns: readonly TableColumn[], rows: readonly TableRow[], options: TableOptions = {}): void {
    this.print(this.table(columns, rows, options));
  }

  // "key  value"
  kv(pairs: readonly (readonly [string, string])[], indent = 2): string {
    const width = Math.max(0, ...pairs.map(([k]) => k.length));
    return pairs.map(([k, v]) => `${' '.repeat(indent)}${this.c.dim(k.padEnd(width))}  ${v}`).join('\n');
  }

  // for tables
  risk(level: RiskLevel): string {
    return this.riskColor(level)(level);
  }

  // for tables
  severity(label: SeverityLabel | string): string {
    const map: Record<string, RiskLevel> = { CRITICAL: 'Critical', HIGH: 'High', MODERATE: 'Medium', LOW: 'Low' };
    const level = map[label];
    return level ? this.riskColor(level)(label) : this.c.gray(label);
  }

  statusGlyph(status: CheckStatus, stream: 'stdout' | 'stderr' = 'stdout'): string {
    const c = stream === 'stdout' ? this.c : this.ce;
    switch (status) {
      case 'ok':
        return c.green(this.glyphs.ok);
      case 'fail':
        return c.red(this.glyphs.fail);
      case 'warn':
        return c.yellow(this.glyphs.warn);
      case 'info':
        return c.dim(this.glyphs.info);
      default:
        return c.dim(this.glyphs.skip);
    }
  }
}

// lines with a coloured left border
export class Card {
  private readonly ui: Ui;
  private level: RiskLevel | null;

  constructor(ui: Ui, level: RiskLevel | null) {
    this.ui = ui;
    this.level = level;
  }

  get risk(): RiskLevel | null {
    return this.level;
  }

  // affects following lines
  setRisk(level: RiskLevel): void {
    this.level = level;
  }

  // "│ " prefix
  border(): string {
    const glyph = this.ui.glyphs.border;
    return `${this.level ? this.ui.riskColor(this.level)(glyph) : this.ui.c.dim(glyph)} `;
  }

  private get inner(): number {
    return this.ui.width - 2;
  }

  format(lines: readonly string[]): string {
    const border = this.border();
    return lines.map((line) => (line === '' ? border.trimEnd() : `${border}${line}`)).join('\n');
  }

  private emit(lines: readonly string[]): void {
    this.ui.info(this.format(lines));
  }

  title(id: string, pkgAtVersion: string, scoreOrSeverity?: string | null): void {
    this.emit([this.ui.formatCardTitle(id, pkgAtVersion, scoreOrSeverity, this.level)]);
    this.emit(['']);
  }

  agent(action: string, options: AgentLineOptions = {}): void {
    this.emit(this.ui.formatAgentLine(action, options, this.inner));
  }

  // fitted like formatThoughtLines
  thought(text: string, options: AgentLineOptions = {}): void {
    this.emit(this.ui.formatThoughtLines(text, options, this.inner));
  }

  result(text: string): void {
    this.emit(this.ui.formatResultLine(text, this.inner));
  }

  line(text = ''): void {
    this.emit(text === '' ? [''] : wrapText(this.ui.text(text), this.inner));
  }

  // recolours border to the verdict
  verdict(level: RiskLevel, sentence: string): void {
    this.level = level;
    this.emit(['']);
    this.emit(this.ui.formatVerdictLine(level, sentence, this.inner));
  }

  confidence(confidence: number, recommendation: string): void {
    this.emit([this.ui.formatConfidenceLine(confidence, recommendation)]);
  }

  spinner(text = 'thinking...'): Spinner {
    return this.ui.spinner(`${this.ui.purple('agent', this.ui.ce)} ${this.ui.ce.dim(text)}`, { prefix: this.border().trimEnd() });
  }

  // ends with a blank line
  end(): void {
    this.ui.info('');
  }
}

// "[y]es  [n]o  [q]uit"
export function formatKeyLabels(keys: string, labels: Record<string, string>): string {
  return keys
    .split('/')
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k) => {
      const label = labels[k];
      if (!label) return `[${k}]`;
      return label.toLowerCase().startsWith(k.toLowerCase()) ? `[${k}]${label.slice(1)}` : `[${k}] ${label}`;
    })
    .join('  ');
}

// for the ? help
export function formatKeyLegend(keys: string, labels: Record<string, string>): string {
  return keys
    .split('/')
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k) => `  ${k}  ${labels[k] ?? k}`)
    .join('\n');
}

// raw mode
function readSingleKey(stdin: InStream, allowed: readonly string[], defaultKey?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const wasRaw = Boolean(stdin.isRaw);
    stdin.setRawMode?.(true);
    stdin.resume();
    const cleanup = (): void => {
      stdin.off('data', onData);
      stdin.setRawMode?.(wasRaw);
      stdin.pause();
    };
    function onData(chunk: Buffer | string): void {
      const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      if (text.startsWith('\u001b')) return; // skip arrows and escapes
      for (const ch of text) {
        if (ch === '\u0003' || ch === '\u0004') {
          cleanup();
          const err = new Error('User force closed the prompt');
          err.name = 'ExitPromptError';
          reject(err);
          return;
        }
        if ((ch === '\r' || ch === '\n') && defaultKey) {
          cleanup();
          resolve(defaultKey);
          return;
        }
        const key = ch.toLowerCase();
        if (allowed.includes(key)) {
          cleanup();
          resolve(key);
          return;
        }
      }
    }
    stdin.on('data', onData);
  });
}

// a Config works
export function createUi(options: UiOptions = {}): Ui {
  return new Ui(options);
}
