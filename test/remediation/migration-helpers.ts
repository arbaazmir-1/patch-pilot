// migration test doubles, offline
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { mock } from 'node:test';
import { fileURLToPath } from 'node:url';
import { MemoryAudit } from '../../src/audit.ts';
import { loadConfig } from '../../src/config.ts';
import { clearRegistryMemo } from '../../src/evidence/registry.ts';
import { setHostLookup } from '../../src/investigation/tools/fetchPage.ts';
import { clearWebMemoryCache } from '../../src/investigation/tools/getChangelog.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import { MockProvider, type MockScript } from '../../src/llm/mock.ts';
import type { MigrationContext } from '../../src/remediation/migration.ts';
import type { Action, Config, KeyValueCache, ToolContext, UsageEvidence } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.join(HERE, 'fixtures', 'migration');
export const APP_FIXTURE = path.join(HERE, 'fixtures', 'migration-app');

export function fixture(name: string): string {
  return readFileSync(path.join(FIXTURES, name), 'utf8');
}

export function fixtureJson<T = unknown>(name: string): T {
  return JSON.parse(fixture(name)) as T;
}

// verbatim v4.0.0 notes
export const DEFAULT_EXPORT_LINE = "Default export removed. Use `import { marked } from 'marked'` or `const { marked } = require('marked')` instead.";
export const LIB_PATH_LINE = '`/lib/marked.js` removed. Use `/marked.min.js` in script tag instead.';
export const SCRIPT_TAG_LINE = 'When using marked in a script tag use `marked.parse(...)` instead of `marked(...)`';
export const RELEASE_V4_URL = 'https://github.com/markedjs/marked/releases/tag/v4.0.0';

export class MemoryCache implements KeyValueCache {
  readonly entries = new Map<string, unknown>();
  get<T = unknown>(namespace: string, key: string): T | undefined {
    const hit = this.entries.get(`${namespace}\n${key}`);
    return hit === undefined ? undefined : (structuredClone(hit) as T);
  }
  set(namespace: string, key: string, value: unknown): void {
    this.entries.set(`${namespace}\n${key}`, structuredClone(value));
  }
  delete(namespace: string, key: string): void {
    this.entries.delete(`${namespace}\n${key}`);
  }
}

export function captureUi(options: ConstructorParameters<typeof Ui>[0] = {}): { ui: Ui; out: () => string; err: () => string } {
  let out = '';
  let err = '';
  const stream = (write: (s: string) => void): Writable =>
    new Writable({
      write(chunk, _enc, cb) {
        write(String(chunk));
        cb();
      },
    });
  const ui = new Ui({ color: false, env: {}, width: 100, stdout: stream((s) => (out += s)) as never, stderr: stream((s) => (err += s)) as never, ...options });
  return { ui, out: () => out, err: () => err };
}

export interface FetchCall {
  url: string;
  method: string;
  body: string | null;
}

export type Route = [string | RegExp | ((url: string, call: FetchCall) => boolean), (call: FetchCall) => Response | Promise<Response>];

export interface FakeFetch {
  calls: FetchCall[];
  urls(): string[];
  restore(): void;
}

export function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

export function text(body: string, contentType = 'text/plain; charset=utf-8', status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': contentType } });
}

// unmatched is 404, also fakes DNS
export function installFetch(routes: readonly Route[]): FakeFetch {
  const calls: FetchCall[] = [];
  const m = mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const call: FetchCall = { url, method: (init?.method ?? 'GET').toUpperCase(), body: typeof init?.body === 'string' ? init.body : null };
    calls.push(call);
    for (const [match, handler] of routes) {
      const ok = typeof match === 'string' ? url === match || url.startsWith(`${match}?`) : match instanceof RegExp ? match.test(url) : match(url, call);
      if (ok) return handler(call);
    }
    return text(`no route for ${url}`, 'text/plain', 404);
  });
  setHostLookup(async () => ['140.82.112.3']);
  return {
    calls,
    urls: () => calls.map((c) => c.url),
    restore: () => {
      m.mock.restore();
      setHostLookup(null);
    },
  };
}

// web and registry caches
export function resetWebState(): void {
  clearWebMemoryCache();
  clearRegistryMemo();
}

const REGISTRY = 'https://registry.npmjs.org';
const RAW = 'https://raw.githubusercontent.com/markedjs/marked';

export interface MarkedRouteOptions {
  // needs the key in config
  search?: unknown;
  // keyed by URL
  pages?: Record<string, { title: string; content: string }>;
  // at v4.0.10, others 404
  rawFiles?: Record<string, string>;
  // default true
  releases?: boolean;
}

export function markedRoutes(options: MarkedRouteOptions = {}): Route[] {
  const releases = fixtureJson<unknown[]>('marked-releases.json');
  const versions = ['0.3.6', '0.3.7', '0.4.0', '0.5.0', '0.6.0', '0.7.0', '0.8.0', '1.0.0', '2.0.0', '3.0.0', '3.0.8', '4.0.0', '4.0.1', '4.0.10'];
  const packument = {
    name: 'marked',
    'dist-tags': { latest: '4.0.10' },
    versions: Object.fromEntries(versions.map((v) => [v, { name: 'marked', version: v, ...(v === '4.0.10' ? { engines: { node: '>= 12' } } : {}) }])),
  };
  const manifest = (v: string): unknown => ({ name: 'marked', version: v, repository: { type: 'git', url: 'git://github.com/markedjs/marked.git' }, homepage: 'https://marked.js.org' });
  const rawFiles = options.rawFiles ?? { 'README.md': fixture('README.md') };
  const pages = options.pages ?? {};
  const routes: Route[] = [
    [`${REGISTRY}/marked`, () => json(packument)],
    [new RegExp(`^${REGISTRY}/marked/(latest|[0-9.]+)$`), (call) => json(manifest(call.url.split('/').pop() === 'latest' ? '4.0.10' : (call.url.split('/').pop() ?? '')))],
    [
      (url) => url.startsWith('https://api.github.com/repos/markedjs/marked/releases?'),
      (call) => (options.releases === false ? json({ message: 'Not Found' }, 404) : json(Number(new URL(call.url).searchParams.get('page') ?? '1') === 1 ? releases : [])),
    ],
    [
      (url) => url.startsWith(`${RAW}/`),
      (call) => {
        const rest = call.url.slice(RAW.length + 1).split('/');
        const ref = decodeURIComponent(rest[0] ?? '');
        const file = rest.slice(1).join('/');
        const body = ref === 'v4.0.10' ? rawFiles[file] : undefined;
        return body === undefined ? text('404: Not Found', 'text/plain', 404) : text(body);
      },
    ],
    [
      'https://ollama.com/api/web_search',
      () => (options.search === undefined ? json({ error: 'unauthorized' }, 401) : json(options.search)),
    ],
    [
      'https://ollama.com/api/web_fetch',
      (call) => {
        const url = String((JSON.parse(call.body ?? '{}') as { url?: string }).url ?? '');
        if (pages[url]) return json(pages[url]);
        if (url.startsWith(`${RAW}/v4.0.10/`)) {
          const body = rawFiles[url.slice(`${RAW}/v4.0.10/`.length)];
          if (body !== undefined) return json({ title: '', content: body });
        }
        return json({ error: 'not found' }, 404);
      },
    ],
  ];
  return routes;
}

export async function tempApp(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-migration-'));
  await cp(APP_FIXTURE, dir, { recursive: true });
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

export async function testConfig(dir: string, overrides: Partial<Config> = {}): Promise<Config> {
  const config = await loadConfig({ dir, cwd: dir, homeDir: dir, env: {}, flags: { provider: 'mock' }, stdinIsTTY: false, stdoutIsTTY: false });
  return { ...config, ...overrides, timeouts: { ...config.timeouts, webMs: 5_000, registryMs: 5_000, llmMs: 5_000 } };
}

// for the fixture's src/render.js
export function markedUsage(): UsageEvidence {
  return {
    package: 'marked',
    imported: true,
    files: [{ path: 'src/render.js', line: 5, statement: "const marked = require('marked');", binding: 'marked', kind: 'cjs-require', scope: 'source' }],
    scopes: { source: 1, test: 0, config: 0, scripts: 0 },
    membersUsed: {},
    bindingCalls: 1,
    scannedFiles: 2,
  };
}

export function markedAction(): Action {
  return {
    id: 'bump-major:marked@4.0.10',
    kind: 'bump-major',
    package: 'marked',
    fromVersion: '0.3.6',
    toVersion: '4.0.10',
    vulnIds: ['GHSA-xxxx'],
    worstRisk: 'High',
    majorBump: true,
    direct: { depType: 'dependencies', spec: '0.3.6', specStyle: 'exact' },
    parents: [],
    importedInSource: true,
    requiresMigration: true,
    engines: null,
    notes: [],
  };
}

export interface TestMigrationContext extends MigrationContext {
  provider: MockProvider;
  audit: MemoryAudit;
  cache: MemoryCache;
  out: () => string;
}

export function migrationCtx(config: Config, script: MockScript = { rules: [] }, cache: MemoryCache = new MemoryCache()): TestMigrationContext {
  const { ui, out } = captureUi();
  const audit = new MemoryAudit();
  const tools: ToolContext = { projectRoot: config.projectRoot, config, caseFile: null, graph: null, cache, audit, focus: { package: 'marked', version: '0.3.6' } };
  return { config, ui, audit, provider: new MockProvider(script, { model: 'mock-model' }), registry: createToolRegistry(), tools, cache, out };
}
