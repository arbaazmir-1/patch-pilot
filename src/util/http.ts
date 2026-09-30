// fetch with timeout and one retry
import { USER_AGENT } from '../version.ts';

export interface HttpOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  // per attempt, default 15 s
  timeoutMs?: number;
  // default 1
  retries?: number;
  // default 400 ms, doubled plus jitter
  retryDelayMs?: number;
  retryOn?: readonly number[];
  // never retried
  signal?: AbortSignal;
}

export const DEFAULT_RETRY_STATUSES: readonly number[] = [408, 425, 429, 500, 502, 503, 504];
const MAX_RETRY_AFTER_MS = 10_000;

export type NetworkErrorKind = 'timeout' | 'refused' | 'dns' | 'aborted' | 'other';

// no http response at all
export class NetworkError extends Error {
  readonly url: string;
  readonly kind: NetworkErrorKind;
  // e.g. ECONNREFUSED, ENOTFOUND
  readonly code: string | null;
  constructor(url: string, kind: NetworkErrorKind, message: string, code: string | null, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'NetworkError';
    this.url = url;
    this.kind = kind;
    this.code = code;
  }
}

export class HttpError extends Error {
  readonly url: string;
  readonly status: number;
  // first 1000 chars
  readonly body: string;
  constructor(url: string, status: number, body: string) {
    super(`HTTP ${status} from ${redactUrl(url)}${body ? `: ${body.slice(0, 200)}` : ''}`);
    this.name = 'HttpError';
    this.url = url;
    this.status = status;
    this.body = body.slice(0, 1000);
  }
}

// query strings may carry keys
export function redactUrl(url: string): string {
  const q = url.indexOf('?');
  return q === -1 ? url : `${url.slice(0, q)}?...`;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function toNetworkError(url: string, err: unknown, callerSignal?: AbortSignal): NetworkError {
  if (err instanceof NetworkError) return err;
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string; name?: string; errors?: { code?: string }[] } };
  if (callerSignal?.aborted) return new NetworkError(url, 'aborted', `Request aborted: ${redactUrl(url)}`, null, err);
  const code = e?.cause?.code ?? e?.cause?.errors?.find((x) => x?.code)?.code ?? null;
  if (e?.name === 'TimeoutError' || code === 'UND_ERR_CONNECT_TIMEOUT' || code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'ETIMEDOUT') {
    return new NetworkError(url, 'timeout', `Request timed out: ${redactUrl(url)}`, code, err);
  }
  if (e?.name === 'AbortError') return new NetworkError(url, 'aborted', `Request aborted: ${redactUrl(url)}`, code, err);
  if (code === 'ECONNREFUSED' || code === 'ECONNRESET' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return new NetworkError(url, 'refused', `Connection failed (${code}): ${redactUrl(url)}`, code, err);
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return new NetworkError(url, 'dns', `Host not found (${code}): ${redactUrl(url)}`, code, err);
  }
  const detail = e?.cause?.message ?? e?.message ?? String(err);
  return new NetworkError(url, 'other', `Network error for ${redactUrl(url)}: ${detail}`, code, err);
}

function retryAfterMs(res: Response): number | null {
  const header = res.headers.get('retry-after');
  if (!header) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return seconds * 1000;
  const date = Date.parse(header);
  return Number.isNaN(date) ? null : Math.max(0, date - Date.now());
}

// throws only on network errors
export async function fetchWithRetry(url: string, options: HttpOptions = {}): Promise<Response> {
  const retries = options.retries ?? 1;
  const retryOn = options.retryOn ?? DEFAULT_RETRY_STATUSES;
  const baseDelay = options.retryDelayMs ?? 400;
  const headers: Record<string, string> = { 'user-agent': USER_AGENT, ...options.headers };
  let lastError: NetworkError | null = null;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const timeout = AbortSignal.timeout(options.timeoutMs ?? 15_000);
    const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
    try {
      const res = await fetch(url, { method: options.method ?? 'GET', headers, body: options.body, signal });
      if (attempt < retries && retryOn.includes(res.status)) {
        const wait = retryAfterMs(res);
        await res.body?.cancel().catch(() => {});
        const delay = wait !== null && wait <= MAX_RETRY_AFTER_MS ? wait : baseDelay * 2 ** attempt + Math.random() * 100;
        await sleep(delay, options.signal);
        continue;
      }
      return res;
    } catch (err) {
      lastError = toNetworkError(url, err, options.signal);
      if (lastError.kind === 'aborted' || attempt >= retries) throw lastError;
      try {
        await sleep(baseDelay * 2 ** attempt + Math.random() * 100, options.signal);
      } catch {
        throw new NetworkError(url, 'aborted', `Request aborted: ${redactUrl(url)}`, null);
      }
    }
  }
  throw lastError ?? new NetworkError(url, 'other', `Request failed: ${redactUrl(url)}`, null);
}

async function bodyText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return '';
  }
}

export async function getJson<T = unknown>(url: string, options: HttpOptions = {}): Promise<T> {
  const res = await fetchWithRetry(url, { ...options, headers: { accept: 'application/json', ...options.headers } });
  const text = await bodyText(res);
  if (!res.ok) throw new HttpError(url, res.status, text);
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new HttpError(url, res.status, `invalid JSON: ${(err as Error).message}`);
  }
}

// null on 404/410
export async function tryGetJson<T = unknown>(url: string, options: HttpOptions = {}): Promise<T | null> {
  try {
    return await getJson<T>(url, options);
  } catch (err) {
    if (err instanceof HttpError && (err.status === 404 || err.status === 410)) return null;
    throw err;
  }
}

export async function postJson<T = unknown>(url: string, body: unknown, options: HttpOptions = {}): Promise<T> {
  return getJson<T>(url, {
    ...options,
    method: options.method ?? 'POST',
    headers: { 'content-type': 'application/json', ...options.headers },
    body: JSON.stringify(body),
  });
}

export async function getText(url: string, options: HttpOptions = {}): Promise<string> {
  const res = await fetchWithRetry(url, options);
  const text = await bodyText(res);
  if (!res.ok) throw new HttpError(url, res.status, text);
  return text;
}

export interface CappedBody {
  text: string;
  bytes: number;
  truncated: boolean;
}

// cancels the stream after maxBytes
export async function readBodyCapped(res: Response, maxBytes: number): Promise<CappedBody> {
  if (!res.body) return { text: '', bytes: 0, truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (bytes + value.byteLength > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - bytes));
      bytes = maxBytes;
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    bytes += value.byteLength;
  }
  const merged = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder('utf-8', { fatal: false }).decode(merged), bytes, truncated };
}

export function isNetworkError(err: unknown): err is NetworkError {
  return err instanceof NetworkError;
}

export function isTimeoutError(err: unknown): boolean {
  return err instanceof NetworkError && err.kind === 'timeout';
}

export function describeHttpError(err: unknown): string {
  if (err instanceof NetworkError || err instanceof HttpError) return err.message;
  return err instanceof Error ? err.message : String(err);
}
