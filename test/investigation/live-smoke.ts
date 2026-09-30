// live ollama smoke, not in npm test
import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MemoryAudit } from '../../src/audit.ts';
import { OllamaProvider } from '../../src/llm/ollama.ts';
import type { ChatProvider } from '../../src/llm/provider.ts';
import { runReconLoop, runVerdictLoop, type Phase2Deps } from '../../src/investigation/agent.ts';
import { makeGetUsageHandler } from '../../src/investigation/tools/getUsage.ts';
import { createToolRegistry } from '../../src/investigation/tools/index.ts';
import { makeSearchCodeHandler } from '../../src/investigation/tools/searchCode.ts';
import type { ChatRequest, ChatResponse, Config, ModelCheck, SearchMatch } from '../../src/types.ts';
import { Ui } from '../../src/ui.ts';
import { loadConfig } from '../../src/config.ts';
import { caseFileOf, fakeFindUsage, lodashFixture, minimistFixture, osvRecordFor, site, tempDir } from './helpers.ts';

const APP = await realpath(fileURLToPath(new URL('../../examples/vulnerable-app/', import.meta.url)));
const FILES = ['src/cli.js', 'src/config.js', 'src/render.js', 'scripts/check-version.js', 'test/render.test.js'];
const sources: Record<string, string> = {};
for (const f of FILES) sources[f] = await readFile(path.join(APP, f), 'utf8');
const lineOf = (file: string, needle: string): number => (sources[file] ?? '').split('\n').findIndex((l) => l.includes(needle)) + 1;

const lodash = lodashFixture();
lodash.pkg.vulnIds = [lodash.template.id];
lodash.pkg.usage.files = [site('src/config.js', lineOf('src/config.js', "require('lodash')"), "const _ = require('lodash');", '_')];
lodash.pkg.usage.membersUsed = { merge: 1, get: 3 };
lodash.pkg.usage.scannedFiles = FILES.length;
const minimist = minimistFixture();
minimist.pkg.usage.files = [site('src/cli.js', lineOf('src/cli.js', "require('minimist')"), "const parseArgs = require('minimist');", 'parseArgs')];
minimist.pkg.usage.scannedFiles = FILES.length;
const records = {
  [lodash.template.id]: osvRecordFor(lodash.template, '`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.'),
  [minimist.vuln.id]: osvRecordFor(minimist.vuln, 'Minimist <=1.2.5 is vulnerable to Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95).'),
};
const caseFile = caseFileOf([minimist.pkg, lodash.pkg], [minimist.vuln, lodash.template], APP, records);

// real handlers, fake codebase
const registry = createToolRegistry();
registry.setHandler('get_usage', makeGetUsageHandler({ findUsage: fakeFindUsage(sources) }));
registry.setHandler(
  'search_code',
  makeSearchCodeHandler({
    searchProject: async (_root, pattern, options) => {
      const matches: SearchMatch[] = [];
      for (const [file, text] of Object.entries(sources)) {
        text.split('\n').forEach((line, i) => {
          if (pattern.test(line)) matches.push({ path: file, line: i + 1, text: line, scope: file.startsWith('src/') ? 'source' : file.startsWith('test/') ? 'test' : 'scripts' });
        });
      }
      return { matches: matches.slice(0, options.maxResults), total: matches.length, truncated: matches.length > options.maxResults };
    },
  }),
);
registry.setHandler('get_changelog', async (args: Record<string, unknown>) => ({
  ok: true,
  hint: `${String(args.package)} ${String(args.fromVersion)} → ${String(args.toVersion)}: patch release, no breaking changes listed`,
  data: { majorBump: false, breakingLines: [], targetDeprecated: null },
}));

interface CallLog {
  purpose: string;
  ms: number;
  tools: number;
  format: boolean;
  promptTokens?: number;
  completionTokens?: number;
  toolCalls: number;
  error?: string;
}
const log: CallLog[] = [];

class TimedProvider implements ChatProvider {
  readonly name = 'ollama' as const;
  readonly model: string;
  private readonly inner: OllamaProvider;
  constructor(inner: OllamaProvider) {
    this.inner = inner;
    this.model = inner.model;
  }
  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = Date.now();
    try {
      const res = await this.inner.chat(req);
      log.push({ purpose: req.purpose ?? 'other', ms: Date.now() - started, tools: req.tools?.length ?? 0, format: Boolean(req.format), toolCalls: res.message.tool_calls?.length ?? 0, ...(res.usage?.promptTokens ? { promptTokens: res.usage.promptTokens } : {}), ...(res.usage?.completionTokens ? { completionTokens: res.usage.completionTokens } : {}) });
      return res;
    } catch (err) {
      log.push({ purpose: req.purpose ?? 'other', ms: Date.now() - started, tools: req.tools?.length ?? 0, format: Boolean(req.format), toolCalls: 0, error: (err as Error).message });
      throw err;
    }
  }
  checkModel(model?: string): Promise<ModelCheck> {
    return this.inner.checkModel(model);
  }
  warmup(): Promise<void> {
    return this.inner.warmup();
  }
}

const home = await tempDir('pp-smoke-home-');
const config: Config = await loadConfig({ dir: APP, homeDir: home.dir, env: {}, flags: { provider: 'ollama', ...(process.env.PATCHPILOT_MODEL ? { model: process.env.PATCHPILOT_MODEL } : {}), ...(process.env.OLLAMA_HOST ? { ollamaHost: process.env.OLLAMA_HOST } : {}) }, stdinIsTTY: false, stdoutIsTTY: false });
const ollama = new OllamaProvider({ host: config.ollamaHost, model: config.model, numCtx: config.numCtx, seed: config.seed, temperature: 0, timeoutMs: config.timeouts.llmMs, keepAlive: '30m', debugLog: process.env.PATCHPILOT_DEBUG ? path.resolve(process.env.PATCHPILOT_DEBUG_FILE ?? path.join(home.dir, 'debug.log')) : null });
const check = await ollama.checkModel();
if (!check.ok) {
  console.error(`Model check failed: ${check.message ?? ''}\n${(check.fix ?? []).join('\n')}`);
  process.exit(3);
}
const provider = new TimedProvider(new OllamaProvider({ ...ollama.options, model: check.resolvedModel ?? config.model }));
const ui = new Ui({ color: process.stdout.isTTY ? undefined : false, env: process.env, verbose: Boolean(process.env.SMOKE_VERBOSE) });
const audit = new MemoryAudit();
const deps: Phase2Deps = { provider, ui, audit, registry, graph: null, caseFile };

const t0 = Date.now();
await provider.warmup();
const warmupMs = Date.now() - t0;
ui.infoLine(`Warm-up ${warmupMs} ms`, `${provider.model} · num_ctx ${config.numCtx}`);

const results: Record<string, unknown>[] = [];
for (const { pkg, vulns } of [
  { pkg: lodash.pkg, vulns: [lodash.template] },
  { pkg: minimist.pkg, vulns: [minimist.vuln] },
]) {
  ui.activity(`Investigating ${pkg.name}@${pkg.version}...`);
  const tRecon = Date.now();
  const before = log.length;
  const dossier = await runReconLoop(pkg, vulns, config, deps);
  const reconMs = Date.now() - tRecon;
  const reconCalls = log.slice(before);
  for (const vuln of vulns) {
    const tVerdict = Date.now();
    const vBefore = log.length;
    const verdict = await runVerdictLoop(pkg, vuln, dossier, config, deps);
    const vCalls = log.slice(vBefore);
    results.push({
      package: `${pkg.name}@${pkg.version}`,
      vuln: `${vuln.id} (${vuln.aliases.join(', ')})`,
      recon: {
        modelTurns: dossier.steps,
        toolCalls: dossier.toolCalls.map((c) => `${c.tool}(${JSON.stringify(c.args)}) by ${c.by}`),
        dossierForced: Boolean(dossier.forced),
        dossier: { inputSources: dossier.inputSources, callSiteNotes: dossier.callSiteNotes, fixCost: dossier.fixCost },
        llmCalls: reconCalls.map((c) => `${c.purpose} ${c.ms}ms${c.promptTokens ? ` in=${c.promptTokens}` : ''}${c.completionTokens ? ` out=${c.completionTokens}` : ''}${c.toolCalls ? ` calls=${c.toolCalls}` : ''}${c.error ? ` ERROR ${c.error}` : ''}`),
        ms: reconMs,
      },
      verdictLoop: {
        modelTurns: verdict.investigation.steps,
        toolCalls: verdict.investigation.toolCalls.map((c) => `${c.tool}(${JSON.stringify(c.args)}) by ${c.by}: ${c.summary}`),
        gate: audit.events('gate.evidence').filter((e) => e.vulnId === vuln.id).map((e) => `${e.action}${e.tool ? ` ${e.tool}(${JSON.stringify(e.args)})` : ''}`),
        llmCalls: vCalls.map((c) => `${c.purpose} ${c.ms}ms${c.promptTokens ? ` in=${c.promptTokens}` : ''}${c.completionTokens ? ` out=${c.completionTokens}` : ''}${c.toolCalls ? ` calls=${c.toolCalls}` : ''}${c.error ? ` ERROR ${c.error}` : ''}`),
        ms: Date.now() - tVerdict,
      },
      verdict: {
        risk: verdict.risk,
        reachable: verdict.reachable,
        confidence: verdict.confidence,
        reasoning: verdict.reasoning,
        evidence: verdict.evidence,
        recommendation: verdict.recommendation,
        forced: verdict.investigation.forced,
        adjusted: verdict.investigation.adjusted ?? false,
        originalRisk: verdict.investigation.originalRisk ?? null,
        analysis: verdict.investigation.analysis ?? null,
      },
    });
  }
}
const totalMs = Date.now() - t0;
console.log('\n=== SMOKE SUMMARY ===');
console.log(JSON.stringify({ model: provider.model, numCtx: config.numCtx, warmupMs, totalMs, llmCalls: log.length, results }, null, 2));
await home.cleanup();
