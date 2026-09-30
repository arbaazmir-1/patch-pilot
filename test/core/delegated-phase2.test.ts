import assert from 'node:assert/strict';
import { cp, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { MemoryAudit, readAuditFile } from '../../src/audit.ts';
import { saveCaseFile } from '../../src/evidence/casefile.ts';
import { forcedVerdict } from '../../src/investigation/agent.ts';
import { delegatedPrompt, runPhase2Delegated } from '../../src/investigation/delegated.ts';
import { usageOf } from '../../src/investigation/prompts.ts';
import { loadVerdictCache, saveVerdictCache, storeVerdict, usageEvidenceHash, verdictCacheKey } from '../../src/investigation/verdictCache.ts';
import type { CodexRunOptions, CodexRunResult } from '../../src/llm/codex.ts';
import { MCP_PROMPT_VERSION } from '../../src/mcp/tools.ts';
import type { CaseFile, Config, PackageCase, VulnCase } from '../../src/types.ts';
import { EnvironmentError } from '../../src/util/errors.ts';
import { captureUi, caseFileOf, minimistFixture, site, tempDir, testConfig, usage } from '../investigation/helpers.ts';
import { fakeCodexEnv, PATCH_PILOT_BIN, writeFakeCodex } from './codex-helpers.ts';

const FIXTURE = fileURLToPath(new URL('../../examples/vulnerable-app', import.meta.url));

let dir: string;
let cleanup: () => Promise<void>;
let binDir: string;
let logFile: string;

before(async () => {
  ({ dir, cleanup } = await tempDir('pp-delegated-'));
  ({ binDir, logFile } = await writeFakeCodex(dir));
});
after(async () => {
  await cleanup();
});

// case file newer than lockfile
async function project(name: string): Promise<{ root: string; config: Config; caseFile: CaseFile; pkg: PackageCase; vuln: VulnCase; home: string; codexHome: string }> {
  const root = path.join(dir, name);
  await cp(FIXTURE, root, { recursive: true, filter: (src) => !src.includes(`${path.sep}.patch-pilot`) && !src.includes(`${path.sep}node_modules`) });
  const home = path.join(dir, `${name}-home`);
  const codexHome = path.join(dir, `${name}-codex-home`);
  await mkdir(home, { recursive: true });
  await mkdir(codexHome, { recursive: true });
  const base = minimistFixture();
  const pkg: PackageCase = { ...base.pkg, usage: usage({ package: 'minimist', files: [site('src/cli.js', 8, "const parseArgs = require('minimist');", 'parseArgs')], bindingCalls: 1 }) };
  const caseFile: CaseFile = { ...caseFileOf([pkg], [base.vuln], root), scannedAt: new Date(Date.now() + 1000).toISOString() };
  const config = await testConfig(root, { provider: 'codex' });
  await saveCaseFile(config.paths.caseFile, caseFile);
  return { root, config, caseFile, pkg, vuln: base.vuln, home, codexHome };
}

describe('runPhase2Delegated with a fake codex driving the real MCP server', () => {
  it('investigates through PatchPilot tools, enforces the gate, and collects the verdict from the assessment', { timeout: 60_000 }, async () => {
    const p = await project('e2e');
    p.config.codexApiKey = 'codex-secret';
    const { ui, out } = captureUi();
    const audit = new MemoryAudit();
    const assessment = await runPhase2Delegated(p.caseFile, p.config, {
      ui,
      audit,
      self: { command: process.execPath, args: [PATCH_PILOT_BIN] },
      env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'mcp', FAKE_CODEX_LOG: logFile, HOME: p.home, CODEX_HOME: p.codexHome }),
    });
    assert.equal(assessment.complete, true);
    assert.equal(assessment.provider, 'codex');
    const v = assessment.verdicts[0];
    assert.ok(v, out());
    assert.equal(v.vulnId, 'GHSA-xvch-5gv4-984h');
    assert.equal(v.risk, 'High');
    assert.equal(v.investigation.provider, 'codex');
    assert.equal(v.investigation.model, 'codex-default');
    assert.equal(v.investigation.promptVersion, MCP_PROMPT_VERSION);
    assert.equal(v.investigation.forced, false);
    assert.equal(v.investigation.gate?.coached, true, 'the first submission was refused by the gate');
    assert.equal(v.recommendation.targetVersion, '1.2.6');

    const text = out();
    assert.match(text, /Investigating minimist@1\.2\.5 with Codex/);
    assert.match(text, /agent Listing the vulnerable packages\.\.\./);
    assert.match(text, /agent Checking how minimist is used\.\.\./);
    assert.match(text, /agent \[evidence gate\] Evidence missing for GHSA-xvch-5gv4-984h/);
    assert.match(text, /\[HIGH\]  minimist parses process\.argv/);
    assert.match(text, /Confidence: 85% - Recommended: bump to 1\.2\.6/);

    const run = audit.events('delegated.run')[0];
    assert.ok(run);
    assert.equal(run.exitCode, 0);
    assert.equal(run.verdicts, 1);
    assert.equal(run.usage?.inputTokens, 1200);
    assert.ok(run.toolCalls >= 5);
    assert.equal(run.command[2], '<prompt>');
    assert.ok(run.command.some((a) => a.startsWith('mcp_servers.patchpilot.command=')));
    assert.ok(run.command.some((a) => a.startsWith('mcp_servers.patchpilot.args=') && a.includes('"--session"') && a.includes('"--provider","codex"')));

    const invocation = (await readFile(logFile, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as { args: string[]; keyOk: boolean }).at(-1);
    assert.ok(invocation);
    for (const flag of ['--json', '--sandbox', 'read-only', '-a', 'never', '--skip-git-repo-check', '--output-schema', '-o']) assert.ok(invocation.args.includes(flag), flag);
    assert.equal(invocation.args[invocation.args.indexOf('-C') + 1], p.config.projectRoot);
    assert.ok(!invocation.args.includes('-m'), 'no model flag without --model');
    assert.equal(invocation.keyOk, true, 'CODEX_API_KEY reaches codex through the environment');
    assert.ok(!invocation.args.some((a) => a.includes('codex-secret')));

    const records = readAuditFile(p.config.paths.auditLog);
    assert.ok(records.some((r) => r.event === 'tool.call' && r.tool === 'get_usage'));
    assert.ok(records.some((r) => r.event === 'gate.evidence' && r.action === 'coached'));
    assert.ok(records.some((r) => r.event === 'verdict' && r.vulnId === 'GHSA-xvch-5gv4-984h'));
    const cache = await loadVerdictCache(p.config.paths.verdictCacheFile, { warn: () => {} });
    assert.ok(Object.keys(cache.entries).some((k) => k.startsWith('codex:')));
  });

  it('gives a vulnerability Codex did not decide a forced verdict', { timeout: 60_000 }, async () => {
    const p = await project('nosubmit');
    const { ui, out } = captureUi();
    const audit = new MemoryAudit();
    const assessment = await runPhase2Delegated(p.caseFile, p.config, {
      ui,
      audit,
      self: { command: process.execPath, args: [PATCH_PILOT_BIN] },
      env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'mcp-nosubmit', HOME: p.home, CODEX_HOME: p.codexHome }),
    });
    const v = assessment.verdicts[0];
    assert.equal(v?.investigation.forced, true);
    assert.equal(v?.investigation.provider, 'codex');
    assert.match(out(), /\[forced\] Codex did not submit a verdict/);
    assert.equal(audit.events('delegated.run')[0]?.verdicts, 0);
  });
});

function fakeResult(overrides: Partial<CodexRunResult> = {}): CodexRunResult {
  return {
    exitCode: 0,
    signal: null,
    durationMs: 5,
    timedOut: false,
    aborted: false,
    finalMessage: null,
    lastError: null,
    usage: { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0, reasoningOutputTokens: 0 },
    toolCalls: 0,
    events: 0,
    stderr: '',
    command: ['codex', 'exec', '<prompt>'],
    ...overrides,
  };
}

describe('runPhase2Delegated errors, cache and prompt', () => {
  it('stops with the fix when codex exits non-zero, after saving the assessment', async () => {
    const p = await project('fail');
    const { ui } = captureUi();
    const audit = new MemoryAudit();
    await assert.rejects(
      () => runPhase2Delegated(p.caseFile, p.config, { ui, audit, self: { command: process.execPath, args: [PATCH_PILOT_BIN] }, env: fakeCodexEnv(binDir, { FAKE_CODEX_SCENARIO: 'fail', HOME: p.home, CODEX_HOME: p.codexHome }) }),
      (err: unknown) => err instanceof EnvironmentError && /exited with code 1/.test(err.message) && /codex login/.test(String(err.hint)) && /investigate --resume/.test(String(err.hint)),
    );
    assert.equal(audit.events('delegated.run')[0]?.exitCode, 1);
    const saved = JSON.parse(await readFile(p.config.paths.assessmentFile, 'utf8')) as { provider: string; complete: boolean };
    assert.equal(saved.provider, 'codex');
    assert.equal(saved.complete, false);
  });

  it('explains how to install codex when it is not on PATH', async () => {
    const p = await project('missing');
    const { ui } = captureUi();
    await assert.rejects(
      () => runPhase2Delegated(p.caseFile, p.config, { ui, audit: new MemoryAudit(), env: { PATH: path.join(dir, 'empty-bin'), HOME: p.home, CODEX_HOME: p.codexHome } }),
      (err: unknown) => err instanceof EnvironmentError && /not installed/.test(err.message) && /npm install -g @openai\/codex/.test(String(err.hint)),
    );
  });

  it('serves unchanged vulnerabilities from the verdict cache without running codex', async () => {
    const p = await project('cached');
    const verdict = forcedVerdict(p.pkg, p.vuln, [], { provider: 'codex', model: 'codex-default', promptVersion: MCP_PROMPT_VERSION });
    verdict.investigation.forced = false;
    verdict.risk = 'Medium';
    const cache = await loadVerdictCache(p.config.paths.verdictCacheFile, { warn: () => {} });
    const key = verdictCacheKey({ provider: 'codex', vulnId: p.vuln.id, package: p.pkg.name, version: p.pkg.version, model: 'codex-default', usageHash: usageEvidenceHash(usageOf(p.pkg), p.vuln), promptVersion: MCP_PROMPT_VERSION });
    storeVerdict(cache, key, verdict);
    await saveVerdictCache(p.config.paths.verdictCacheFile, cache);
    const runs: CodexRunOptions[] = [];
    const { ui, out } = captureUi();
    const audit = new MemoryAudit();
    const assessment = await runPhase2Delegated(p.caseFile, p.config, {
      ui,
      audit,
      env: { HOME: p.home, CODEX_HOME: p.codexHome },
      runCodex: async (options) => {
        runs.push(options);
        return fakeResult();
      },
    });
    assert.equal(runs.length, 0);
    assert.equal(assessment.verdicts[0]?.risk, 'Medium');
    assert.equal(assessment.verdicts[0]?.investigation.cached, true);
    assert.match(out(), /\[cached\]/);
    assert.equal(audit.events('verdict.cached').length, 1);
    const fresh = { ...p.config, noCache: true } as Config;
    await runPhase2Delegated(p.caseFile, fresh, { ui, audit, env: { HOME: p.home, CODEX_HOME: p.codexHome }, runCodex: async (options) => (runs.push(options), fakeResult()) });
    assert.equal(runs.length, 1, '--no-cache runs codex again');
    assert.equal(runs[0]?.mcpServer?.name, 'patchpilot');
    assert.deepEqual(runs[0]?.mcpServer?.args.slice(-8, -6), ['--project', p.config.projectRoot]);
  });

  it('asks Codex to work only through the PatchPilot tools and to submit every verdict', () => {
    const { pkg, vuln } = minimistFixture();
    const prompt = delegatedPrompt(pkg, [vuln]);
    assert.match(prompt, /Work only through the PatchPilot MCP tools \(server "patchpilot"; they appear as mcp__patchpilot__<tool>\)/);
    assert.match(prompt, /Do not edit files/);
    assert.match(prompt, /GHSA-xvch-5gv4-984h \(CVE-2021-44906\)/);
    assert.match(prompt, /Call submit_verdict for every vulnerability id above/);
    assert.ok(!prompt.startsWith('-'));
  });
});
