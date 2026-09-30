// html to text for fetch_page

export interface HtmlToTextOptions {
  // "text (url)"
  keepLinks?: boolean;
  // nav, header, footer, aside
  dropChrome?: boolean;
}

export interface KeywordWindowOptions {
  radius?: number;
  ignoreCase?: boolean;
  // parallel to keywords
  weights?: readonly number[];
  // spread joins windows with "..."
  mode?: 'cluster' | 'spread';
}

// used when fetch_page has no query
export const BREAKING_KEYWORDS: readonly string[] = [
  'BREAKING',
  'breaking change',
  'removed',
  'renamed',
  'deprecated',
  'no longer',
  'now requires',
  'dropped support',
  'default export',
  'ESM',
  'Node.js',
  'migration',
];

const EM_DASH = String.fromCharCode(0x2014);

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  ensp: ' ',
  emsp: ' ',
  thinsp: ' ',
  zwnj: '',
  zwj: '',
  shy: '',
  hellip: '\u2026',
  mdash: EM_DASH,
  ndash: '\u2013',
  minus: '\u2212',
  lsquo: '\u2018',
  rsquo: '\u2019',
  sbquo: '\u201a',
  ldquo: '\u201c',
  rdquo: '\u201d',
  bdquo: '\u201e',
  laquo: '\u00ab',
  raquo: '\u00bb',
  lsaquo: '\u2039',
  rsaquo: '\u203a',
  bull: '\u2022',
  middot: '\u00b7',
  copy: '\u00a9',
  reg: '\u00ae',
  trade: '\u2122',
  deg: '\u00b0',
  plusmn: '\u00b1',
  times: '\u00d7',
  divide: '\u00f7',
  para: '\u00b6',
  sect: '\u00a7',
  cent: '\u00a2',
  pound: '\u00a3',
  euro: '\u20ac',
  yen: '\u00a5',
  larr: '\u2190',
  rarr: '\u2192',
  uarr: '\u2191',
  darr: '\u2193',
  harr: '\u2194',
  lArr: '\u21d0',
  rArr: '\u21d2',
  hArr: '\u21d4',
  le: '\u2264',
  ge: '\u2265',
  ne: '\u2260',
  asymp: '\u2248',
  infin: '\u221e',
  check: '\u2713',
  cross: '\u2717',
  star: '\u2606',
  hearts: '\u2665',
  dagger: '\u2020',
  Dagger: '\u2021',
  prime: '\u2032',
  Prime: '\u2033',
  frac12: '\u00bd',
  frac14: '\u00bc',
  frac34: '\u00be',
  sup2: '\u00b2',
  sup3: '\u00b3',
  micro: '\u00b5',
  iexcl: '\u00a1',
  iquest: '\u00bf',
  grave: '`',
  Tab: '\t',
  NewLine: '\n',
  colon: ':',
  comma: ',',
  period: '.',
  excl: '!',
  quest: '?',
  num: '#',
  dollar: '$',
  percnt: '%',
  lpar: '(',
  rpar: ')',
  ast: '*',
  plus: '+',
  sol: '/',
  bsol: '\\',
  lsqb: '[',
  rsqb: ']',
  lcub: '{',
  rcub: '}',
  verbar: '|',
  lowbar: '_',
  equals: '=',
  semi: ';',
  commat: '@',
  Hat: '^',
  auml: '\u00e4',
  ouml: '\u00f6',
  uuml: '\u00fc',
  Auml: '\u00c4',
  Ouml: '\u00d6',
  Uuml: '\u00dc',
  szlig: '\u00df',
  eacute: '\u00e9',
  egrave: '\u00e8',
  ecirc: '\u00ea',
  aacute: '\u00e1',
  agrave: '\u00e0',
  acirc: '\u00e2',
  ccedil: '\u00e7',
  ntilde: '\u00f1',
  oacute: '\u00f3',
  iacute: '\u00ed',
  uacute: '\u00fa',
};

// browsers accept these without the semicolon
const LEGACY_NO_SEMICOLON = new Set(['amp', 'lt', 'gt', 'quot', 'nbsp']);

// unknown names kept
export function decodeEntities(text: string): string {
  if (!text.includes('&')) return text;
  return text.replace(/&(#[0-9]{1,8}|#[xX][0-9a-fA-F]{1,7}|[A-Za-z][A-Za-z0-9]{1,31})(;?)/g, (match, body: string, semi: string) => {
    if (body.startsWith('#')) {
      const code = body[1] === 'x' || body[1] === 'X' ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return '\ufffd';
      if (code === 0xa0) return ' ';
      return String.fromCodePoint(code);
    }
    const value = NAMED_ENTITIES[body];
    if (value === undefined) return match;
    if (!semi && !LEGACY_NO_SEMICOLON.has(body)) return match;
    return value;
  });
}

export function normalizeText(text: string): string {
  const unified = text
    .replace(/\r\n?/g, '\n')
    .replace(/[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/g, ' ')
    .replace(/[\u200b-\u200d\u2060\ufeff]/g, '')
    .replace(new RegExp(`[ \\t]*${EM_DASH}[ \\t]*`, 'g'), ' - ');
  const lines = unified.split('\n').map((line) => {
    const lead = /^[ \t]*/.exec(line)?.[0] ?? '';
    const rest = line.slice(lead.length).replace(/[ \t]+/g, ' ').trimEnd();
    return rest === '' ? '' : lead.replace(/\t/g, '  ') + rest;
  });
  return lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}

export function oneLineText(text: string): string {
  return normalizeText(text).replace(/\s+/g, ' ').trim();
}

// attr values may contain >
const TAG_RE = /<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:"[^"]*"|'[^']*'|[^'">])*)>/g;

const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);

// removed up to the first closing tag
const RAW_TEXT_TAGS = ['script', 'style', 'noscript', 'template', 'textarea', 'title'];

// removed with content, nesting-aware
const ALWAYS_DROP = new Set(['head', 'svg', 'math', 'iframe', 'object', 'canvas', 'select', 'button', 'video', 'audio', 'picture', 'map', 'dialog']);
const CHROME_TAGS = new Set(['nav', 'header', 'footer', 'aside']);
const CHROME_ROLE = /\brole\s*=\s*["']?(?:navigation|banner|contentinfo|search|complementary|menu|menubar|toolbar)\b/i;
const HIDDEN_ATTR = /(?:^|\s)hidden(?:\s|=|$)|\baria-hidden\s*=\s*["']?true\b|\bstyle\s*=\s*["'][^"']*display\s*:\s*none/i;

function stripComments(html: string): string {
  return html
    .replace(/<!--[\s\S]*?(?:-->|$)/g, ' ')
    .replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, ' ')
    .replace(/<![^>]*>/g, ' ')
    .replace(/<\?[^>]*>/g, ' ');
}

function stripRawTextElements(html: string): string {
  let out = html;
  for (const tag of RAW_TEXT_TAGS) {
    out = out.replace(new RegExp(`<${tag}\\b(?:"[^"]*"|'[^']*'|[^'">])*>[\\s\\S]*?(?:<\\/${tag}\\s*>|$)`, 'gi'), ' ');
  }
  return out;
}

// unclosed ones lose only the open tag
function removeElements(html: string, shouldRemove: (tag: string, attrs: string) => boolean): string {
  let result = '';
  let rest = html;
  for (let guard = 0; guard < 1000; guard += 1) {
    const pass = removeOnce(rest, shouldRemove);
    result += pass.out;
    if (pass.resumeAt < 0) return result;
    rest = rest.slice(pass.resumeAt);
  }
  return result + rest;
}

// resumeAt -1 when done
function removeOnce(html: string, shouldRemove: (tag: string, attrs: string) => boolean): { out: string; resumeAt: number } {
  const re = new RegExp(TAG_RE.source, 'g');
  let out = '';
  let last = 0;
  let removing: { tag: string; depth: number; openEnd: number } | null = null;
  for (let m = re.exec(html); m !== null; m = re.exec(html)) {
    const slash = m[1] ?? '';
    const name = (m[2] ?? '').toLowerCase();
    const attrs = m[3] ?? '';
    const selfClosing = /\/\s*$/.test(attrs) || VOID_TAGS.has(name);
    if (removing) {
      if (name === removing.tag) {
        if (slash) {
          removing.depth -= 1;
          if (removing.depth === 0) {
            removing = null;
            last = m.index + m[0].length;
          }
        } else if (!selfClosing) {
          removing.depth += 1;
        }
      }
      continue;
    }
    if (!slash && shouldRemove(name, attrs)) {
      out += `${html.slice(last, m.index)} `;
      if (selfClosing) {
        last = m.index + m[0].length;
        continue;
      }
      removing = { tag: name, depth: 1, openEnd: m.index + m[0].length };
    }
  }
  if (removing) return { out, resumeAt: removing.openEnd };
  return { out: out + html.slice(last), resumeAt: -1 };
}

// nesting-aware
function innerOfFirst(html: string, tag: string): string | null {
  const re = new RegExp(TAG_RE.source, 'g');
  let depth = 0;
  let start = -1;
  for (let m = re.exec(html); m !== null; m = re.exec(html)) {
    const name = (m[2] ?? '').toLowerCase();
    if (name !== tag) continue;
    if (m[1]) {
      if (depth > 0) {
        depth -= 1;
        if (depth === 0) return html.slice(start, m.index);
      }
    } else if (!/\/\s*$/.test(m[3] ?? '')) {
      if (depth === 0) start = m.index + m[0].length;
      depth += 1;
    }
  }
  return start >= 0 ? html.slice(start) : null;
}

function countTags(html: string, tag: string): number {
  return (html.match(new RegExp(`<${tag}\\b`, 'gi')) ?? []).length;
}

function roughTextLength(html: string): number {
  return decodeEntities(html.replace(new RegExp(TAG_RE.source, 'g'), ' ')).replace(/\s+/g, '').length;
}

function attrValue(attrs: string, name: string): string | null {
  const m = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i').exec(attrs);
  if (!m) return null;
  return decodeEntities(m[1] ?? m[2] ?? m[3] ?? '');
}

const BLOCK_TAGS = new Set([
  'address',
  'article',
  'blockquote',
  'body',
  'center',
  'dd',
  'details',
  'div',
  'dl',
  'dt',
  'fieldset',
  'figcaption',
  'figure',
  'form',
  'html',
  'legend',
  'main',
  'section',
  'summary',
  'caption',
  'thead',
  'tbody',
  'tfoot',
  'table',
  'header',
  'footer',
  'nav',
  'aside',
  'menu',
]);

const PRE_MARK = '\u0000PRE';

// keeps breaks and indent
function preToText(inner: string): string {
  const text = decodeEntities(inner.replace(/<br\s*\/?>/gi, '\n').replace(new RegExp(TAG_RE.source, 'g'), ''));
  const lines = text.replace(/\r\n?/g, '\n').split('\n').map((l) => l.replace(/\s+$/, ''));
  while (lines.length > 0 && lines[0] === '') lines.shift();
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines.join('\n');
}

export function htmlToText(html: string, options: HtmlToTextOptions = {}): string {
  const dropChrome = options.dropChrome ?? true;
  let doc = stripRawTextElements(stripComments(html));

  // placeholders keep pre layout
  const pres: string[] = [];
  doc = doc.replace(/<pre\b(?:"[^"]*"|'[^']*'|[^'">])*>([\s\S]*?)(?:<\/pre\s*>|$)/gi, (_m, inner: string) => {
    pres.push(preToText(inner));
    return `<div>${PRE_MARK}${pres.length - 1}\u0000</div>`;
  });

  doc = removeElements(doc, (tag, attrs) => ALWAYS_DROP.has(tag) || HIDDEN_ATTR.test(attrs));
  if (dropChrome) {
    const main = innerOfFirst(doc, 'main');
    if (main !== null && roughTextLength(main) >= 200) doc = main;
    else if (countTags(doc, 'article') === 1) {
      const article = innerOfFirst(doc, 'article');
      if (article !== null && roughTextLength(article) >= 200) doc = article;
    }
    doc = removeElements(doc, (tag, attrs) => CHROME_TAGS.has(tag) || CHROME_ROLE.test(attrs));
  }

  let out = '';
  const lists: { ordered: boolean; n: number }[] = [];
  const links: (string | null)[] = [];
  let cell = 0;
  let codeOpenAt = -1;

  const ensureNewlines = (n: number): void => {
    if (out === '') return;
    let have = 0;
    for (let i = out.length - 1; i >= 0 && out[i] === '\n'; i -= 1) have += 1;
    if (have === 0) out = out.replace(/[ \t]+$/, '');
    for (; have < n; have += 1) out += '\n';
  };
  const appendText = (raw: string): void => {
    let text = decodeEntities(raw).replace(/[\s\u00a0]+/g, ' ');
    if (out === '' || out.endsWith('\n') || out.endsWith(' ') || out.length === codeOpenAt + 1) text = text.replace(/^ +/, '');
    if (text) out += text;
  };

  const tokenRe = new RegExp(`${TAG_RE.source}|([^<]+)|(<)`, 'g');
  for (let m = tokenRe.exec(doc); m !== null; m = tokenRe.exec(doc)) {
    if (m[4] !== undefined) {
      appendText(m[4]);
      continue;
    }
    if (m[5] !== undefined) {
      appendText('<');
      continue;
    }
    const closing = m[1] === '/';
    const tag = (m[2] ?? '').toLowerCase();
    const attrs = m[3] ?? '';
    const heading = /^h([1-6])$/.exec(tag);
    if (heading) {
      ensureNewlines(2);
      if (!closing) out += `${'#'.repeat(Number(heading[1]))} `;
      continue;
    }
    switch (tag) {
      case 'br':
        out = out.replace(/[ \t]+$/, '') + '\n';
        break;
      case 'hr':
        ensureNewlines(2);
        break;
      case 'p':
        ensureNewlines(2);
        break;
      case 'ul':
      case 'ol':
        if (closing) lists.pop();
        else lists.push({ ordered: tag === 'ol', n: Number(attrValue(attrs, 'start') ?? '1') - 1 });
        ensureNewlines(lists.length === 0 ? 2 : 1);
        break;
      case 'li': {
        ensureNewlines(1);
        if (!closing) {
          const list = lists[lists.length - 1];
          const indent = '  '.repeat(Math.max(0, lists.length - 1));
          if (list?.ordered) {
            list.n += 1;
            out += `${indent}${list.n}. `;
          } else out += `${indent}- `;
        }
        break;
      }
      case 'tr':
        ensureNewlines(1);
        cell = 0;
        break;
      case 'td':
      case 'th':
        if (!closing) {
          if (cell > 0) out = out.replace(/[ \t]+$/, '') + ' | ';
          cell += 1;
        }
        break;
      case 'code':
      case 'kbd':
      case 'samp':
        if (!closing) {
          codeOpenAt = out.length;
          out += '`';
        } else if (codeOpenAt >= 0) {
          out = out.replace(/[ \t]+$/, '');
          if (out.length <= codeOpenAt + 1) out = out.slice(0, codeOpenAt);
          else out += '`';
          codeOpenAt = -1;
        }
        break;
      case 'a':
        if (!closing) links.push(options.keepLinks ? attrValue(attrs, 'href') : null);
        else {
          const href = links.pop();
          if (href && /^https?:\/\//i.test(href) && !out.endsWith(href)) out = `${out.replace(/[ \t]+$/, '')} (${href})`;
        }
        break;
      case 'img':
      case 'input':
      case 'wbr':
        break;
      default:
        if (BLOCK_TAGS.has(tag)) ensureNewlines(1);
    }
  }

  let text = normalizeText(out);
  // separator-only lines from empty cells
  text = text
    .split('\n')
    .filter((line) => !/^[\s|\-*#>.]*$/.test(line) || line.trim() === '' || /^-{3,}$/.test(line.trim()))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n');
  if (pres.length > 0) {
    text = text.replace(/\u0000PRE(\d+)\u0000/g, (_m, i: string) => `\n${pres[Number(i)] ?? ''}\n`).replace(/\n{3,}/g, '\n\n');
  }
  return text.trim();
}

// <title>, else first <h1>
export function extractTitle(html: string): string | null {
  const title = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html)?.[1];
  const clean = (s: string): string => oneLineText(decodeEntities(s.replace(new RegExp(TAG_RE.source, 'g'), ' ')));
  if (title !== undefined) {
    const t = clean(title);
    if (t) return t;
  }
  const h1 = /<h1\b[^>]*>([\s\S]*?)<\/h1\s*>/i.exec(html)?.[1];
  if (h1 !== undefined) {
    const t = clean(h1);
    if (t) return t;
  }
  return null;
}

export function looksLikeHtml(text: string): boolean {
  const head = text.slice(0, 2048).trimStart().toLowerCase();
  return head.startsWith('<!doctype html') || head.startsWith('<html') || /<(?:head|body|div|p|meta|title)\b/.test(head);
}

// under 200 visible chars from a big page
export function isLikelyJsRendered(html: string, text: string): boolean {
  const visible = text.replace(/\s+/g, '').length;
  if (visible >= 200) return false;
  return html.length >= 2000 || /<script\b/i.test(html);
}

const STOP_WORDS = new Set([
  'a',
  'an',
  'and',
  'are',
  'as',
  'at',
  'be',
  'by',
  'can',
  'do',
  'does',
  'for',
  'from',
  'how',
  'i',
  'in',
  'into',
  'is',
  'it',
  'its',
  'of',
  'on',
  'or',
  'the',
  'this',
  'to',
  'use',
  'using',
  'vs',
  'what',
  'when',
  'where',
  'which',
  'with',
  'why',
]);

// terms, then adjacent pairs
export function queryKeywords(query: string): string[] {
  const terms = query
    .toLowerCase()
    .split(/[^a-z0-9@/._+-]+/)
    .map((t) => t.replace(/^[._/-]+|[._/-]+$/g, ''))
    .filter((t) => t.length >= 2 && !STOP_WORDS.has(t));
  const unique = [...new Set(terms)];
  const pairs: string[] = [];
  for (let i = 0; i + 1 < terms.length; i += 1) {
    const pair = `${terms[i]} ${terms[i + 1]}`;
    if (!pairs.includes(pair) && terms[i] !== terms[i + 1]) pairs.push(pair);
  }
  return [...unique, ...pairs];
}

// 1 per term, 2 per pair
export function queryWeights(keywords: readonly string[]): number[] {
  return keywords.map((k) => (k.includes(' ') ? 2 : 1));
}

interface Hit {
  start: number;
  end: number;
  k: number;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const MAX_HITS = 2000;

function findHits(text: string, keywords: readonly string[], ignoreCase: boolean): Hit[] {
  const hits: Hit[] = [];
  keywords.forEach((keyword, k) => {
    const kw = keyword.trim();
    if (!kw) return;
    // leading boundary only, export finds exports
    const lead = /^\w/.test(kw) ? '(?<![A-Za-z0-9_])' : '';
    const re = new RegExp(lead + escapeRegExp(kw).replace(/\s+/g, '\\s+'), ignoreCase ? 'gi' : 'g');
    for (let m = re.exec(text); m !== null && hits.length < MAX_HITS; m = re.exec(text)) {
      hits.push({ start: m.index, end: m.index + m[0].length, k });
      if (m[0].length === 0) re.lastIndex += 1;
    }
  });
  return hits.sort((a, b) => a.start - b.start || b.end - a.end);
}

function windowScore(hits: readonly Hit[], from: number, to: number, weights: readonly number[]): number {
  const seen = new Set<number>();
  let distinct = 0;
  for (let i = from; i <= to; i += 1) {
    const hit = hits[i];
    if (!hit || seen.has(hit.k)) continue;
    seen.add(hit.k);
    distinct += weights[hit.k] ?? 1;
  }
  return distinct * 1000 + Math.min(999, to - from + 1);
}

function snapToLines(text: string, start: number, end: number, keepFrom: number, keepTo: number, slack: number): [number, number] {
  let s = start;
  let e = end;
  if (s > 0) {
    const nl = text.indexOf('\n', s);
    if (nl !== -1 && nl + 1 <= keepFrom && nl + 1 - s <= slack) s = nl + 1;
  }
  if (e < text.length) {
    const nl = text.lastIndexOf('\n', e - 1);
    if (nl !== -1 && nl >= keepTo && e - nl <= slack) e = nl;
  }
  return [s, e];
}

function clipStart(text: string, maxChars: number): string {
  const marker = '\n...';
  const budget = Math.max(0, maxChars - marker.length);
  let cut = text.lastIndexOf('\n', budget);
  if (cut < budget * 0.6) cut = budget;
  return text.slice(0, cut).trimEnd() + marker;
}

export function keywordWindow(text: string, keywords: readonly string[], maxChars: number, options: KeywordWindowOptions = {}): string {
  if (maxChars <= 0) return '';
  if (text.length <= maxChars) return text;
  const hits = findHits(text, keywords, options.ignoreCase ?? true);
  if (hits.length === 0) return clipStart(text, maxChars);
  const weights = options.weights ?? [];
  if (options.mode === 'spread') return spreadWindows(text, hits, maxChars, options.radius ?? 400, weights);

  const markers = 8;
  const size = maxChars - markers;
  const radius = Math.max(0, Math.min(options.radius ?? 400, Math.floor(size / 4)));
  const span = Math.max(1, size - 2 * radius);

  // best-scoring run of hits within span
  let bestFrom = 0;
  let bestTo = 0;
  let bestScore = -1;
  let j = 0;
  for (let i = 0; i < hits.length; i += 1) {
    const first = hits[i];
    if (!first) continue;
    if (j < i) j = i;
    while (j + 1 < hits.length && (hits[j + 1]?.end ?? Infinity) - first.start <= span) j += 1;
    const score = windowScore(hits, i, j, weights);
    if (score > bestScore) {
      bestScore = score;
      bestFrom = i;
      bestTo = j;
    }
  }
  const clusterStart = hits[bestFrom]?.start ?? 0;
  const clusterEnd = Math.max(hits[bestTo]?.end ?? clusterStart, hits[bestFrom]?.end ?? clusterStart);
  const centre = Math.round((clusterStart + clusterEnd) / 2);
  let start = Math.max(0, Math.min(text.length - size, centre - Math.floor(size / 2)));
  let end = Math.min(text.length, start + size);
  [start, end] = snapToLines(text, start, end, clusterStart, clusterEnd, Math.max(40, Math.floor(radius / 2)));
  const body = text.slice(start, end).trim();
  return `${start > 0 ? '...\n' : ''}${body}${end < text.length ? '\n...' : ''}`;
}

function mergeRanges(ranges: readonly [number, number][], gap: number): [number, number][] {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  const out: [number, number][] = [];
  for (const [s, e] of sorted) {
    const prev = out[out.length - 1];
    if (prev && s <= prev[1] + gap) prev[1] = Math.max(prev[1], e);
    else out.push([s, e]);
  }
  return out;
}

function spreadWindows(text: string, hits: readonly Hit[], maxChars: number, radius: number, weights: readonly number[]): string {
  const joiner = '\n...\n';
  const cost = (ranges: readonly [number, number][]): number =>
    ranges.reduce((sum, [s, e]) => sum + (e - s), 0) + Math.max(0, ranges.length - 1) * joiner.length + 8;
  // best keywords first, then doc order
  const order = [...hits].sort((a, b) => (weights[b.k] ?? 1) - (weights[a.k] ?? 1) || a.start - b.start);
  let ranges: [number, number][] = [];
  for (const hit of order) {
    if (ranges.some(([s, e]) => hit.start >= s && hit.end <= e)) continue;
    const candidate = mergeRanges([...ranges, [Math.max(0, hit.start - radius), Math.min(text.length, hit.end + radius)]], joiner.length);
    if (cost(candidate) <= maxChars) ranges = candidate;
  }
  if (ranges.length === 0) return keywordWindow(text, [], maxChars);
  const first = ranges[0];
  const last = ranges[ranges.length - 1];
  const body = ranges.map(([s, e]) => text.slice(s, e).trim()).join(joiner);
  return `${first && first[0] > 0 ? '...\n' : ''}${body}${last && last[1] < text.length ? '\n...' : ''}`;
}

// snippets only, never evidence
export function stripMarkdownNoise(text: string): string {
  return text
    .replace(/\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)/g, ' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]*)\]\((?:[^()]|\([^)]*\))*\)/g, '$1')
    .replace(/^\s*\[[^\]]+\]:\s*\S+.*$/gm, '')
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ')
    .replace(/\bhttps?:\/\/[^\s)>\]]+/g, ' ')
    .replace(/\(\s*[0-9a-f]{7,40}\s*\)/g, ' ')
    .replace(/\(\s*\)/g, ' ');
}

export function snippetAround(text: string, keywords: readonly string[], maxChars: number, weights?: readonly number[]): string {
  const flat = oneLineText(stripMarkdownNoise(text));
  if (flat.length <= maxChars) return flat;
  const window = keywordWindow(flat, keywords, maxChars, { radius: Math.floor(maxChars / 3), weights });
  return window.replace(/\s*\n\s*/g, ' ').slice(0, maxChars);
}
