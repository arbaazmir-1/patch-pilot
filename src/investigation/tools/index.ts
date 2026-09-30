import type {
  JsonSchema,
  ToolContext,
  ToolDef,
  ToolExecution,
  ToolName,
  ToolResult,
  ToolSchema,
  ToolStage,
} from '../../types.ts';
import { isNotImplemented } from '../../util/errors.ts';
import { stableStringify } from '../../util/fs.ts';
import { coerceToSchema, schemaSignature, validateJson } from '../../util/schema.ts';
import { handleCheckDeps, type CheckDepsArgs } from './checkDeps.ts';
import { handleFetchPage, type FetchPageArgs } from './fetchPage.ts';
import { handleGetAdvisory, type GetAdvisoryArgs } from './getAdvisory.ts';
import { handleGetChangelog, type GetChangelogArgs } from './getChangelog.ts';
import { handleGetUsage, type GetUsageArgs } from './getUsage.ts';
import { handleReadFile, type ReadFileArgs } from './readFile.ts';
import { handleSearchCode, type SearchCodeArgs } from './searchCode.ts';
import { handleWebSearch, type WebSearchArgs } from './webSearch.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyToolDef = ToolDef<any>;

export const TOOL_NAMES: readonly ToolName[] = [
  'search_code',
  'get_usage',
  'get_changelog',
  'check_deps',
  'read_file',
  'get_advisory',
  'web_search',
  'fetch_page',
];

// order the model sees
export const STAGE_TOOLS: Readonly<Record<ToolStage, readonly ToolName[]>> = {
  recon: ['check_deps', 'read_file', 'get_changelog', 'search_code'],
  verdict: ['get_usage', 'read_file', 'get_advisory', 'search_code'],
  migration: ['web_search', 'fetch_page', 'get_changelog', 'get_usage', 'search_code', 'read_file'],
};

// only when the target param exists
export const GLOBAL_ARG_ALIASES: Readonly<Record<string, string>> = {
  pkg: 'package',
  package_name: 'package',
  packageName: 'package',
  fn: 'symbol',
  function: 'symbol',
  method: 'symbol',
  function_name: 'symbol',
};

export const DEFAULT_MAX_CHARS = 1500;

// keeps the handler arg type
export function defineTool<A>(def: ToolDef<A>): ToolDef<A> {
  return def;
}

const str = (description: string): JsonSchema => ({ type: 'string', description });
const int = (description: string, minimum: number, maximum: number): JsonSchema => ({ type: 'integer', description, minimum, maximum });

// "template" -> "template()"
function callable(symbol: string): string {
  const s = symbol.trim();
  return s.endsWith(')') ? s : `${s}()`;
}

// capped at 70 chars
function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    const text = `${u.host}${u.pathname === '/' ? '' : u.pathname}`;
    return text.length > 70 ? `${text.slice(0, 69)}…` : text;
  } catch {
    return url.length > 70 ? `${url.slice(0, 69)}…` : url;
  }
}

function quoteShort(text: string, max = 60): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export const TOOL_DEFS: readonly AnyToolDef[] = [
  defineTool<SearchCodeArgs>({
    name: 'search_code',
    description:
      "Search the project's own source files with a JavaScript regular expression. Returns matches as path:line: text. Skips node_modules, build output, lockfiles and minified lines.",
    parameters: {
      type: 'object',
      properties: {
        pattern: str('JavaScript regular expression, for example \\bmerge\\('),
        fileGlob: str('Only search files matching this glob, for example src/**/*.js'),
        maxResults: int('Maximum matches to return (default 10, at most 30)', 1, 30),
      },
      required: ['pattern'],
    },
    stages: ['recon', 'verdict', 'migration'],
    truncation: { maxChars: 3000, defaultResults: 10, maxResults: 30 },
    aliases: { regex: 'pattern', query: 'pattern', search: 'pattern', glob: 'fileGlob', file_glob: 'fileGlob', files: 'fileGlob', limit: 'maxResults' },
    example: { pattern: '\\.template\\(', fileGlob: 'src/**/*.js' },
    describe: (a) => `Searching the code for ${quoteShort(a.pattern, 50)}${a.fileGlob ? ` in ${a.fileGlob}` : ''}...`,
    handler: handleSearchCode,
  }),
  defineTool<GetUsageArgs>({
    name: 'get_usage',
    description:
      'How the project uses a package: its import sites, which members it calls (with counts), and where a given symbol is called, with 2 lines of context. Without a symbol it also lists where the package itself is called.',
    parameters: {
      type: 'object',
      properties: {
        package: str('npm package name, for example lodash'),
        symbol: str('Function or member to look for, for example template'),
      },
      required: ['package'],
    },
    stages: ['verdict', 'migration'],
    truncation: { maxChars: DEFAULT_MAX_CHARS },
    aliases: { member: 'symbol', api: 'symbol', symbol_name: 'symbol' },
    example: { package: 'lodash', symbol: 'template' },
    describe: (a) => (a.symbol ? `Checking if ${callable(a.symbol)} is called...` : `Checking how ${a.package} is used...`),
    handler: handleGetUsage,
  }),
  defineTool<GetChangelogArgs>({
    name: 'get_changelog',
    description:
      'Release notes between two versions of a package: lines flagged as breaking changes, whether the target version is deprecated, and its Node.js engine requirement.',
    parameters: {
      type: 'object',
      properties: {
        package: str('npm package name'),
        fromVersion: str('Installed version, for example 0.3.6'),
        toVersion: str('Target version, for example 4.0.10'),
      },
      required: ['package', 'fromVersion', 'toVersion'],
    },
    stages: ['recon', 'migration'],
    truncation: { maxChars: DEFAULT_MAX_CHARS },
    aliases: { from: 'fromVersion', from_version: 'fromVersion', to: 'toVersion', to_version: 'toVersion', target: 'toVersion' },
    example: { package: 'marked', fromVersion: '0.3.6', toVersion: '4.0.10' },
    describe: (a) => `Checking the changelog of ${a.package} ${a.fromVersion} → ${a.toVersion}...`,
    handler: handleGetChangelog,
  }),
  defineTool<CheckDepsArgs>({
    name: 'check_deps',
    description:
      'Dependency facts for an installed package: version, direct or transitive, dev-only, which packages depend on it, the paths from the project root, and other installed versions.',
    parameters: {
      type: 'object',
      properties: { package: str('npm package name, for example decode-uri-component') },
      required: ['package'],
    },
    stages: ['recon'],
    truncation: { maxChars: DEFAULT_MAX_CHARS },
    aliases: { name: 'package' },
    example: { package: 'decode-uri-component' },
    describe: (a) => `Checking what depends on ${a.package}...`,
    handler: handleCheckDeps,
  }),
  defineTool<ReadFileArgs>({
    name: 'read_file',
    description:
      'Read numbered lines from a project file (40 lines by default, at most 120). Give startLine and endLine around a call site.',
    parameters: {
      type: 'object',
      properties: {
        path: str('Project-relative path, for example src/render.js'),
        startLine: int('First line to read (1-based)', 1, 1_000_000),
        endLine: int('Last line to read', 1, 1_000_000),
      },
      required: ['path'],
    },
    stages: ['recon', 'verdict', 'migration'],
    truncation: { maxChars: 8000, defaultLines: 40, maxLines: 120 },
    aliases: { file: 'path', filePath: 'path', file_path: 'path', filename: 'path', start: 'startLine', line: 'startLine', end: 'endLine' },
    example: { path: 'src/render.js', startLine: 1, endLine: 40 },
    describe: (a) =>
      a.startLine !== undefined ? `Reading ${a.path}:${a.startLine}-${a.endLine ?? a.startLine + 39}...` : `Reading ${a.path}...`,
    handler: handleReadFile,
  }),
  defineTool<GetAdvisoryArgs>({
    name: 'get_advisory',
    description:
      'Full advisory text for one vulnerability id (GHSA, CVE or OSV id) from the case file: details, CWE ids, references and publish date.',
    parameters: {
      type: 'object',
      properties: { id: str('Vulnerability id, for example GHSA-xvch-5gv4-984h or CVE-2021-44906') },
      required: ['id'],
    },
    stages: ['verdict'],
    truncation: { maxChars: 2000 },
    aliases: { vulnId: 'id', vuln_id: 'id', advisory: 'id', advisory_id: 'id', cve: 'id', ghsa: 'id' },
    example: { id: 'GHSA-xvch-5gv4-984h' },
    describe: (a) => `Reading the advisory ${a.id}...`,
    handler: handleGetAdvisory,
  }),
  defineTool<WebSearchArgs>({
    name: 'web_search',
    description:
      'Search for migration guides and breaking-change notes about a package upgrade. Returns titles, URLs and snippets.',
    parameters: {
      type: 'object',
      properties: {
        query: str('Search query, for example marked 4 migration breaking changes default export'),
        maxResults: int('Maximum results (default 5, at most 10)', 1, 10),
      },
      required: ['query'],
    },
    stages: ['migration'],
    truncation: { maxChars: 2000, defaultResults: 5, maxResults: 10 },
    aliases: { q: 'query', search: 'query', text: 'query', limit: 'maxResults' },
    example: { query: 'marked 4.0.0 breaking changes default export' },
    describe: (a) => `Searching the web for "${quoteShort(a.query)}"...`,
    handler: handleWebSearch,
  }),
  defineTool<FetchPageArgs>({
    name: 'fetch_page',
    description:
      'Fetch a public documentation page (http or https) and return its readable text around the query keywords (about 3000 characters).',
    parameters: {
      type: 'object',
      properties: {
        url: str('Page URL, for example https://github.com/markedjs/marked/releases/tag/v4.0.0'),
        query: str('Keywords to centre the extract on, for example default export'),
      },
      required: ['url'],
    },
    stages: ['migration'],
    truncation: { maxChars: 3500 },
    aliases: { link: 'url', href: 'url', page: 'url', keywords: 'query', q: 'query' },
    example: { url: 'https://github.com/markedjs/marked/releases/tag/v4.0.0', query: 'default export' },
    describe: (a) => `Reading ${shortUrl(a.url)}...`,
    handler: handleFetchPage,
  }),
];

// dedupe key
export function toolCallKey(name: string, args: Record<string, unknown>): string {
  return `${name}:${stableStringify(args)}`;
}

// cut near a line break
export function truncateContent(content: string, maxChars: number): { content: string; truncated: boolean; omitted: number } {
  if (content.length <= maxChars) return { content, truncated: false, omitted: 0 };
  const note = (n: number): string => `\n[output truncated: ${n} more characters omitted; narrow the request]`;
  const budget = Math.max(0, maxChars - note(content.length).length);
  let cut = content.lastIndexOf('\n', budget);
  if (cut < budget * 0.6) cut = budget;
  const omitted = content.length - cut;
  return { content: content.slice(0, cut) + note(omitted), truncated: true, omitted };
}

export function formatToolContent(result: ToolResult): string {
  if (!result.ok) {
    const error = result.error ?? result.hint;
    return result.hint && result.error && result.hint !== result.error ? `Error: ${error}\n${result.hint}` : `Error: ${error}`;
  }
  const body = result.text ?? (result.data === undefined ? '' : JSON.stringify(result.data));
  return body ? `${result.hint}\n${body}` : result.hint;
}

function describeTool(def: AnyToolDef): string {
  return `- ${schemaSignature(def.name, def.parameters)}: ${def.description}\n  schema: ${JSON.stringify(def.parameters)}`;
}

export function unknownToolMessage(requested: string, available: readonly AnyToolDef[], reason: 'unknown' | 'not-in-stage' = 'unknown'): string {
  const head =
    reason === 'unknown'
      ? `Unknown tool "${requested}". Tools available in this step:`
      : `Tool "${requested}" is not available in this step. Tools available in this step:`;
  return [head, ...available.map(describeTool), 'Call one of these with JSON arguments, or answer without a tool call when you have enough evidence.'].join('\n');
}

// errors, signature, schema, example
export function invalidArgsMessage(def: AnyToolDef, errors: readonly string[]): string {
  return [
    `Invalid arguments for ${def.name}: ${errors.join('; ')}.`,
    `Signature: ${schemaSignature(def.name, def.parameters)}`,
    `Schema: ${JSON.stringify(def.parameters)}`,
    `Example: ${def.name}(${JSON.stringify(def.example)})`,
  ].join('\n');
}

// "get-usage", "functions.get_usage" -> "get_usage"
export function canonicalToolName(name: string): string {
  return name
    .trim()
    .replace(/^(functions|tools?)\./i, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-\s]+/g, '_')
    .toLowerCase();
}

function canonicalArgName(name: string): string {
  return name.replace(/[_-]/g, '').toLowerCase();
}

function describeWith(def: AnyToolDef, norm: NormalizedArgs): string {
  if (norm.errors.length > 0) return `Calling ${def.name}...`;
  try {
    return def.describe(norm.args);
  } catch {
    return `Calling ${def.name}...`;
  }
}

export interface NormalizedArgs {
  args: Record<string, unknown>;
  renamed: [string, string][];
  dropped: string[];
  filled: string[];
  notes: string[];
  errors: string[];
}

export class ToolRegistry {
  private readonly defs = new Map<ToolName, AnyToolDef>();

  constructor(defs: readonly AnyToolDef[] = TOOL_DEFS) {
    for (const def of defs) this.register(def);
  }

  // tests register fakes
  register(def: AnyToolDef): void {
    this.defs.set(def.name, def);
  }

  // tests only
  setHandler<A>(name: ToolName, handler: ToolDef<A>['handler']): void {
    const def = this.defs.get(name);
    if (!def) throw new Error(`Unknown tool: ${name}`);
    this.defs.set(name, { ...def, handler });
  }

  get(name: string): AnyToolDef | undefined {
    const exact = this.defs.get(name as ToolName);
    return exact ?? this.defs.get(canonicalToolName(name) as ToolName);
  }

  has(name: string): boolean {
    return this.get(name) !== undefined;
  }

  list(): AnyToolDef[] {
    return [...this.defs.values()];
  }

  forStage(stage: ToolStage): AnyToolDef[] {
    return STAGE_TOOLS[stage]
      .map((name) => this.defs.get(name))
      .filter((def): def is AnyToolDef => def !== undefined && def.stages.includes(stage));
  }

  schemas(stage: ToolStage): ToolSchema[] {
    return this.forStage(stage).map((def) => ({
      type: 'function',
      function: { name: def.name, description: def.description, parameters: def.parameters },
    }));
  }

  // never throws
  describeCall(call: { name: string; arguments?: unknown }, ctx?: Pick<ToolContext, 'focus'>): string {
    const def = this.get(String(call.name ?? ''));
    if (!def) return `Calling ${String(call.name ?? 'an unknown tool')}...`;
    return describeWith(def, this.normalizeArgs(def, call.arguments, ctx));
  }

  normalizeArgs(def: AnyToolDef, raw: unknown, ctx?: Pick<ToolContext, 'focus'>): NormalizedArgs {
    const out: NormalizedArgs = { args: {}, renamed: [], dropped: [], filled: [], notes: [], errors: [] };
    const props = def.parameters.properties ?? {};
    const required = def.parameters.required ?? [];
    let input: unknown = raw ?? {};
    if (typeof input === 'string') {
      const text = input.trim();
      if (text === '') input = {};
      else {
        try {
          input = JSON.parse(text);
        } catch {
          const firstRequired = required[0];
          if (required.length === 1 && firstRequired !== undefined && Object.hasOwn(props, firstRequired) && props[firstRequired]?.type === 'string') {
            input = { [firstRequired]: text };
          } else {
            out.errors.push('arguments must be a JSON object');
            return out;
          }
        }
      }
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      out.errors.push('arguments must be a JSON object');
      return out;
    }
    const given = input as Record<string, unknown>;
    const byCanonical = new Map(Object.keys(props).map((key) => [canonicalArgName(key), key]));
    const collected: Record<string, unknown> = {};
    const declared = (key: string): boolean => key !== '__proto__' && Object.hasOwn(props, key);
    for (const [key, value] of Object.entries(given)) {
      if (declared(key)) collected[key] = value;
    }
    for (const [key, value] of Object.entries(given)) {
      if (declared(key)) continue;
      const alias = (table: Readonly<Record<string, string>> | undefined): string | undefined => (table && Object.hasOwn(table, key) ? table[key] : undefined);
      const aliasTarget = alias(def.aliases) ?? alias(GLOBAL_ARG_ALIASES) ?? byCanonical.get(canonicalArgName(key));
      if (aliasTarget !== undefined && declared(aliasTarget) && collected[aliasTarget] === undefined) {
        collected[aliasTarget] = value;
        out.renamed.push([key, aliasTarget]);
      } else {
        out.dropped.push(key);
      }
    }
    const coerced = coerceToSchema(collected, def.parameters);
    out.args = coerced.value;
    out.notes.push(...coerced.notes);
    if (required.includes('package') && out.args.package === undefined && ctx?.focus?.package) {
      out.args.package = ctx.focus.package;
      out.filled.push('package');
    }
    out.errors.push(...validateJson(out.args, def.parameters));
    return out;
  }

  // never throws
  async execute(call: { name: string; arguments?: unknown }, ctx: ToolContext, stage: ToolStage): Promise<ToolExecution> {
    const started = Date.now();
    const requested = String(call.name ?? '').trim();
    const base = (): Omit<ToolExecution, 'status' | 'ok' | 'content' | 'hint' | 'tool' | 'description'> => ({
      requested,
      stage,
      args: {},
      rawArgs: call.arguments,
      renamedArgs: [],
      droppedArgs: [],
      filledArgs: [],
      result: null,
      truncated: false,
      durationMs: Date.now() - started,
    });
    const def = this.get(requested);
    if (!def) {
      return {
        ...base(),
        tool: null,
        description: `Calling ${requested || 'an unknown tool'}...`,
        status: 'unknown-tool',
        ok: false,
        content: unknownToolMessage(requested, this.forStage(stage)),
        hint: `unknown tool "${requested}"`,
      };
    }
    if (!def.stages.includes(stage)) {
      return {
        ...base(),
        tool: def.name,
        description: `Calling ${def.name}...`,
        status: 'not-in-stage',
        ok: false,
        content: unknownToolMessage(def.name, this.forStage(stage), 'not-in-stage'),
        hint: `${def.name} is not available in this step`,
      };
    }
    const norm = this.normalizeArgs(def, call.arguments, ctx);
    const common = {
      ...base(),
      tool: def.name,
      description: describeWith(def, norm),
      args: norm.args,
      renamedArgs: norm.renamed,
      droppedArgs: norm.dropped,
      filledArgs: norm.filled,
    };
    if (norm.errors.length > 0) {
      return {
        ...common,
        status: 'invalid-args',
        ok: false,
        content: invalidArgsMessage(def, norm.errors),
        hint: `invalid arguments for ${def.name}: ${norm.errors[0] ?? ''}`,
        durationMs: Date.now() - started,
      };
    }
    let result: ToolResult;
    try {
      result = await def.handler(norm.args, ctx);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const content = isNotImplemented(err)
        ? `Error: ${def.name} is not available yet (${message}). Use another tool or answer with the evidence you have.`
        : `Error: ${def.name} failed: ${message}`;
      return { ...common, status: 'error', ok: false, content, hint: `${def.name} failed: ${message}`, durationMs: Date.now() - started };
    }
    const capped = truncateContent(formatToolContent(result), def.truncation.maxChars);
    let hint = result.hint;
    if (def.summarize) {
      try {
        hint = def.summarize(result, norm.args);
      } catch {
      }
    }
    return {
      ...common,
      status: result.ok ? 'ok' : 'error',
      ok: result.ok,
      content: capped.content,
      hint,
      result,
      truncated: capped.truncated || Boolean(result.truncated),
      durationMs: Date.now() - started,
    };
  }
}

export function createToolRegistry(defs: readonly AnyToolDef[] = TOOL_DEFS): ToolRegistry {
  return new ToolRegistry(defs);
}
