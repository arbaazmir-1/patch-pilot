import { mkdtemp } from 'node:fs/promises';
import { readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mock } from 'node:test';
import { loadConfig } from '../../src/config.ts';
import type { AuditEvent, AuditSink, Config, KeyValueCache, ToolContext } from '../../src/types.ts';

const FIXTURES = fileURLToPath(new URL('./fixtures/', import.meta.url));

export function fixture(name: string): string {
  return readFileSync(path.join(FIXTURES, name), 'utf8');
}

export function fixtureJson<T = unknown>(name: string): T {
  return JSON.parse(fixture(name)) as T;
}

// map-backed cache with ttl
export class MemoryCache implements KeyValueCache {
  readonly entries = new Map<string, { value: unknown; expires: number | null }>();
  sets = 0;
  get<T = unknown>(namespace: string, key: string): T | undefined {
    const hit = this.entries.get(`${namespace}\n${key}`);
    if (!hit) return undefined;
    if (hit.expires !== null && hit.expires <= Date.now()) return undefined;
    return structuredClone(hit.value) as T;
  }
  set(namespace: string, key: string, value: unknown, ttlMs?: number): void {
    this.sets += 1;
    this.entries.set(`${namespace}\n${key}`, { value: structuredClone(value), expires: ttlMs ? Date.now() + ttlMs : null });
  }
  delete(namespace: string, key: string): void {
    this.entries.delete(`${namespace}\n${key}`);
  }
  namespaces(): string[] {
    return [...new Set([...this.entries.keys()].map((k) => k.split('\n')[0] ?? ''))].sort();
  }
  // moves the envelope's at back
  age(ms: number): void {
    for (const entry of this.entries.values()) {
      const v = entry.value as { at?: number } | null;
      if (v && typeof v === 'object' && typeof v.at === 'number') v.at -= ms;
    }
  }
}

export class MemoryAuditSink implements AuditSink {
  readonly events: AuditEvent[] = [];
  log(event: AuditEvent): void {
    this.events.push(event);
  }
}

export interface FetchCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

export type RouteHandler = (call: FetchCall) => Response | Promise<Response>;

export interface FakeFetch {
  calls: FetchCall[];
  callsTo(prefix: string): FetchCall[];
  restore(): void;
}

function headersOf(init: RequestInit | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  const h = init?.headers;
  if (!h) return out;
  if (h instanceof Headers) h.forEach((v, k) => (out[k.toLowerCase()] = v));
  else if (Array.isArray(h)) for (const [k, v] of h) out[String(k).toLowerCase()] = String(v);
  else for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = String(v);
  return out;
}

// unmatched urls 404
export function installFetch(routes: [string | RegExp | ((url: string) => boolean), RouteHandler][]): FakeFetch {
  const calls: FetchCall[] = [];
  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const call: FetchCall = {
      url,
      method: (init?.method ?? 'GET').toUpperCase(),
      headers: headersOf(init),
      body: typeof init?.body === 'string' ? init.body : null,
    };
    calls.push(call);
    if (init?.signal?.aborted) throw init.signal.reason ?? new Error('aborted');
    for (const [match, handler] of routes) {
      const ok =
        typeof match === 'string' ? url === match || url.startsWith(`${match}?`) : match instanceof RegExp ? match.test(url) : match(url);
      if (ok) return handler(call);
    }
    return new Response(`no route for ${url}`, { status: 404 });
  };
  const m = mock.method(globalThis, 'fetch', impl);
  return {
    calls,
    callsTo: (prefix) => calls.filter((c) => c.url.startsWith(prefix)),
    restore: () => m.mock.restore(),
  };
}

export function json(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), { status: 200, ...init, headers: { 'content-type': 'application/json', ...(init.headers as Record<string, string>) } });
}

export function text(body: string, contentType = 'text/plain; charset=utf-8', status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': contentType } });
}

let baseConfig: Config | null = null;

// defaults, no env, temp dirs
export async function testConfig(overrides: Partial<Config> = {}): Promise<Config> {
  if (!baseConfig) {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pp-web-'));
    process.once('exit', () => rmSync(dir, { recursive: true, force: true }));
    baseConfig = await loadConfig({ dir, cwd: dir, homeDir: dir, env: {}, flags: {}, stdinIsTTY: false, stdoutIsTTY: false });
  }
  return { ...baseConfig, ...overrides, timeouts: { ...baseConfig.timeouts, webMs: 5_000, registryMs: 5_000, ...(overrides.timeouts ?? {}) } };
}

export async function testCtx(options: { config?: Partial<Config>; cache?: KeyValueCache | null; audit?: AuditSink | null; focus?: ToolContext['focus'] } = {}): Promise<ToolContext> {
  const config = await testConfig(options.config);
  const ctx: ToolContext = {
    projectRoot: config.projectRoot,
    config,
    caseFile: null,
    graph: null,
    cache: options.cache === undefined ? new MemoryCache() : options.cache,
    audit: options.audit ?? null,
  };
  if (options.focus) ctx.focus = options.focus;
  return ctx;
}

// fields PatchPilot reads
export function release(tag: string, body = '', extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tag_name: tag,
    name: tag,
    body,
    published_at: '2021-11-02T14:42:34Z',
    html_url: `https://github.com/o/r/releases/tag/${tag}`,
    draft: false,
    prerelease: false,
    ...extra,
  };
}
