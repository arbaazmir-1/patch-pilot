# PatchPilot

**Supply chain defence**

An AI agent for software supply chain security.

_Local model. Human approval. Full audit trail._

It reads your codebase. It checks whether the vulnerable function is actually called. It explains why. Then it asks before it changes anything.

|         |                                         |
| ------- | --------------------------------------- |
| Event   | Agentic AI Cybersecurity Hackathon 2026 |
| Track   | Track 1, Cybersecurity defence agents   |
| Date    | 7 November 2026                         |
| Venue   | UTAR Kampar, FICT                       |
| Website | hackai.my                               |

## Team Zero Day Pilots

INTI International University

| Member                       | Role        |
| ---------------------------- | ----------- |
| Abdullah Ibn Shahin          | Team leader |
| Imtiaz Ahmed Talukder Biplob | Developer   |
| Junaid Hussain Mohammed      | Web Dev     |
| Wang Peifeng                 | UI/UX       |

---

## 01. Problem

### If it works, don't touch it.

The most dangerous vulnerabilities live in code nobody wants to update.

A typical Node.js project depends on hundreds of open-source packages. When a vulnerability is published, the tools most teams have report it with a severity score and a version to upgrade to. What they do not tell you is whether the vulnerable code is actually reachable in your project.

A prototype-pollution bug in a function your project never calls is not a risk today. A regex denial-of-service in the function that parses user-supplied input is. Both arrive with similar CVSS scores. When the two look the same, developers learn to ignore the entire list, and the one genuinely exploitable finding gets buried alongside the twenty that are not.

When a fix requires a major version bump, those tools stop at the version number and leave the breaking changes to the developer. That is where most upgrades stall.

> **2 of 20** vulnerable packages in a real Astro project are actually imported. PatchPilot shows which two.

_Untouched code, unpatched risk._

---

## 02. Overview

### What PatchPilot does

It investigates dependency vulnerabilities the way a security engineer would.

PatchPilot reads the codebase, checks whether vulnerable functions are actually imported and called, assesses real-world exploitability, and proposes a patching plan, including source code changes when a major upgrade introduces breaking API changes.

Nothing changes until you approve it. Every decision is logged in a JSONL audit trail. By default the language model runs on your machine through Ollama, so your code stays on it.

---

## 03. Philosophy

### Design philosophy

| Layer | Role            | Principle                                                |
| ----- | --------------- | -------------------------------------------------------- |
| Code  | _deterministic_ | Everything deterministic is done by code.                |
| Model | _judgement_     | Everything that needs judgement is done by the model.    |
| Code  | _verification_  | Everything the model concludes is checked by code again. |

---

## 04. Mechanism

### How it works

Three phases.

#### I. Take in evidence (No LLM) _gather_

Discover the lockfile (npm, yarn or pnpm) and parse the dependency graph the way the package manager resolves it. Batch-query every dependency against the OSV vulnerability database, with a local SQLite cache and an offline snapshot that reports its own data age. Walk the project source with the TypeScript compiler API and record every import site, member call and alias chain, resolved across files. Extract the blamed symbols from each advisory. Build the case file.

#### II. Investigate and decide (Agentic LLM loop) _judge_

For each vulnerable package the model receives the case file and a set of tools it can call in a loop. It checks imports, traces function usage, reads source files, fetches changelogs, pulls the full advisory. An evidence gate ensures the model cannot skip a required check; if it tries, the harness runs the check itself. Guard rails bound the verdict by the evidence gathered. The recommended action is derived by rules, not by the model's opinion.

#### III. Act safely (Human approval required) _act_

Present findings with risk level, reachability, reasoning and confidence. Research breaking changes from release notes, changelogs, migration guides and package documentation, and check every quote against its source. Draft code edits that are syntax-checked before being shown. Apply approved patches with a backup and a one-command rollback. Write the audit report.

---

## 05. Evidence

### The product, running

Scanning a real Astro project. 861 dependencies. 69 CVEs across 20 packages.

```text
❯ patch-pilot
PatchPilot v0.1.0     Dependency security agent
~/Dev/revamp-abdullahibnshahin

✓ Environment OK      Node v24.14.1 · Ollama 0.34.4 · qwen3:8b (tools)

✓ Discovered lockfile         package-lock.json
✓ Parsed 861 dependencies     15 direct · 0 dev
✓ Vulnerability data          OSV.dev (live, just now)
✓ Found 69 CVEs across 20 packages
✓ Located usage evidence      9 files scanned · 2 of 20 vulnerable packages imported

  Severity     CVEs   Packages
  ────────────────────────────────────────────────────────────────────────────────────
  CRITICAL        1   astro
  HIGH           31   astro, undici, js-yaml, brace-expansion, svgo, browserslist, devalue
  MODERATE       27   astro, undici, js-yaml, svgo, devalue, postcss, vite, ws, baseline-browser-mapping
  LOW            10   astro, undici, @astrojs/cloudflare, @babel/core, esbuild

astro@5.18.1    direct, imported in 1 source file and 1 config file, 10 CVEs, fix 7.2.8 (major)
  CRITICAL   GHSA-26w7-cxv4-gfx2                       Remote code execution                fixed in 7.2.8
  HIGH       CVE-2026-50146    (GHSA-8hv8-536x-4wqp)   Reflected XSS via unescaped output   fixed in 6.3.3
  HIGH       CVE-2026-54299    (GHSA-2pvr-wf23-7pc7)   Host header SSRF in prerendering     fixed in 6.4.6
  MODERATE   CVE-2026-41067    (GHSA-j687-52p2-xcff)   XSS in define:vars                   fixed in 6.1.6
  MODERATE   CVE-2026-54298    (GHSA-jrpj-wcv7-9fh9)   XSS via unescaped attributes         fixed in 6.4.6
  MODERATE   CVE-2026-59729    (GHSA-f48w-9m4c-m7f5)   XSS via unescaped spread             fixed in 7.0.6
  MODERATE   CVE-2026-73422    (GHSA-4g3v-8h47-v7g6)   Reflected XSS via unescaped output   fixed in 7.1.0
  MODERATE   CVE-2026-84376    (GHSA-376h-93r7-7g6f)   Authorization bypass                 fixed in 7.2.4
  LOW        CVE-2026-45028    (GHSA-xr5h-phrj-8vxv)   Server island encryption             fixed in 6.1.10
  LOW        CVE-2026-59727    (GHSA-7pw4-f3q4-r2p2)   Cross-site scripting                 fixed in 7.0.4

brace-expansion@2.1.0      transitive via minimatch, not imported, 3 CVEs, fix 2.1.4
  HIGH       CVE-2026-13149    (GHSA-3jxr-9vmj-r5cp)   DoS via exponential expansion        fixed in 2.1.2
  HIGH       CVE-2026-14257    (GHSA-mh99-v99m-4gvg)   DoS via unbounded expansion          fixed in 2.1.3
  HIGH       CVE-2026-69152    (GHSA-rgw5-rvv9-x895)   DoS via unbounded expansion          fixed in 2.1.4
```

_Fig. 1. Phase one output. Dependency graph parsed, OSV queried, usage evidence located._

Phase one finishes with a severity table and every advisory grouped by package. Note the line that matters: 2 of 20 vulnerable packages are actually imported. The other eighteen are transitive dependencies the project never touches directly.

---

## 06. Reasoning

### The agent reasoning

The investigation loop, visible as it runs.

```text
│         Confidence 100%, recommended: monitor
│
│ CVE-2026-54298    astro@5.18.1   CVSS 4.2
│
│ agent [cached] Same model, prompt and evidence as an earlier run: verdict reused
│
│   LOW   The vulnerable function 'spreadAttributes' is not called by the project,
│         and the package is used in a way that does not involve untrusted input.
│         Confidence 100%, recommended: monitor
│
│ CVE-2026-45028    astro@5.18.1   CVSS 6.1
│
│ agent [cached] Same model, prompt and evidence as an earlier run: verdict reused
│
│   LOW   The vulnerable functions are not used with untrusted input in this project.
│         Confidence 100%, recommended: monitor
│
│ CVE-2026-59727    astro@5.18.1   CVSS 2.1
│
│ agent [cached] Same model, prompt and evidence as an earlier run: verdict reused
│
│   LOW   The vulnerable functions in the advisory are not called in the project, and
│         the package is used only for configuration and utility functions that are
│         not implicated in the vulnerability.
│         Confidence 100%, recommended: monitor
│

agent Checking what depends on sharp...
    sharp@0.34.5: transitive production dependency via
     miniflare@4.20260114.0   (^0.34.5, excludes 0.35.4)
     astro@5.18.1             (^0.34.0, excludes 0.35.4)
     miniflare@4.20260507.1   (^0.34.5, excludes 0.35.4)
agent Checking the changelog of sharp 0.34.5 to 0.35.4...
    22 releases, 1 breaking-change line, major bump
     agent thinking...
────────────────────────────────────────────────────────────────────────────────────────────
● Working on 3 phases      ■ Take in evidence     ■ Investigate and decide   □ Act safely
    Investigating sharp@0.34.5 (2 of 20), reconnaissance, 2 CVEs, 21s
```

_Fig. 2. Phase two. Per-CVE verdicts with reasoning, confidence and cached results._

Each verdict states the reasoning in plain English: the vulnerable function is not called, the package is not fed untrusted input, the risk is Low and the recommendation is monitor rather than upgrade. Verdicts are cached against the model, the prompt version and a hash of the usage evidence, so a re-scan of unchanged code reuses them instead of asking the model again. The checklist at the bottom of the terminal tracks all three phases live.

---

## 07. Rationale

### Why not just use Claude Code or Codex?

A general coding agent can do this if you prompt it correctly. PatchPilot does it the same way, every time.

1. **Coverage is systematic, not remembered.** OSV is queried for every dependency in the lockfile. A general agent checks what it thinks to check, and what a model recalls about a package's advisories is not a vulnerability database.
2. **The audit trail is structured, not chat history.** Every tool call, evidence gate intervention, verdict, approval and applied patch is one JSON line with a timestamp and an identity.
3. **The approval gate is part of the workflow.** Backups, lockfile diff guards, syntax validation and rollback are enforced by code before any change lands, not by asking the model to be careful.
4. **It is repeatable and it runs in CI.** `patch-pilot --ci` runs without prompts or changes, writes JSON and Markdown reports, and sets the exit code from `--fail-on`.
5. **It runs on a laptop.** An 8B model on local hardware (qwen3:8b by default), no per-scan cost, and no source code leaving the machine. The evidence gate and guard rails are what make a small model's verdicts trustworthy.

You can still use them: `--provider claude` (Anthropic API key) or `--provider codex` (Codex CLI) run the same investigation in the cloud, and `patch-pilot mcp claude` gives your own Claude Code PatchPilot's tools with the same evidence gate. With a cloud provider, code snippets are sent to that provider, and the trust prompt says so.

---

## 08. Stack

### Tech stack

| Component     | Technology                                                                              |
| ------------- | --------------------------------------------------------------------------------------- |
| Runtime       | Node.js 22.12+ and TypeScript, ES modules                                               |
| CLI           | Commander.js and Chalk                                                                  |
| Model         | Ollama, local-first. qwen3:8b by default. Optional Claude (API key) and Codex providers |
| CVE data      | OSV.dev API, with a SQLite cache and offline snapshot                                   |
| Code analysis | TypeScript compiler API. A real syntax tree with cross-file resolution                  |
| Lockfiles     | npm v1 to v3, yarn 1 and 2+, pnpm v5 to v9                                              |
| Dashboard     | Astro, reads each project's report and live run status                                  |

---

## 09. Get started

```bash
npm install
npm run build
npm link              # puts `patch-pilot` on your PATH

ollama pull qwen3:8b
cd your-project
patch-pilot           # asks to trust the folder, then runs all three phases
```

`patch-pilot doctor` checks Node, Ollama, the model and the network. `patch-pilot rollback` restores the last backup. `examples/` has four small intentionally vulnerable apps for a quick first run.

The dashboard lists every scanned project:

```bash
cd web
npm install
npm run build
npm start             # http://localhost:4321
```

---

## 10. Limits

### Scope and limitations

Scoped to the npm, yarn and pnpm ecosystems. Reachability is static: import sites, member calls and alias chains come from a real syntax tree with cross-file resolution, but there is no data-flow analysis, so whether the value reaching a call is untrusted is judged by the model from the surrounding code. Verdicts carry a reachability value and a confidence rather than a yes or no for exactly this reason.

Source code modifications for breaking API changes are syntax-checked and shown as diffs before applying, and an edit whose supporting quote cannot be verified against a real source is never drafted. Small local models are weak reasoners; the correctness of the verdicts comes largely from the evidence gate and the guard rails.

Breaking-change research uses the web: Ollama Web Search (with an API key) or Brave Search, falling back to the package's own docs. Only search queries and page requests go out; source files are never uploaded. `--offline` skips it and uses cached data only.

---

## 11. Closing

### In one sentence

**A security analyst that never misses a dependency, never skips an audit log, and runs on a laptop.**

The AI is the engine, not the product. The product is a security workflow that produces auditable results and that a solo developer or a five-person team can actually afford to run.

---

INTI International University · Track 1, Defence agents · hackai.my · _Think agents. Build impact._

## License

Copyright (C) 2026 Abdullah Ibn Shahin. Licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
