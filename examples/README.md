# PatchPilot demo apps

Four tiny, intentionally vulnerable apps. Each has one dependency and no transitive ones, so a full run is quick. Do not deploy them.

| App | Story | Manager | Package | CVEs | Run |
| --- | --- | --- | --- | --- | --- |
| [reachable-template](reachable-template) | `_.template` renders a template from the request query string: the vulnerable function is reachable with untrusted input, so the command injection is flagged and a bump is recommended. | npm | lodash 4.17.20 | 3 | `patch-pilot scan examples/reachable-template` |
| [unused-dependency](unused-dependency) | node-fetch is installed but never imported (the app uses only Node built-ins): low risk, monitor rather than panic. | npm | node-fetch 2.6.0 | 2 | `patch-pilot scan examples/unused-dependency` |
| [major-bump](major-bump) | marked is called through its pre-v4 default export with `sanitize`; the fix is a major upgrade (4.0.10) that also needs a source edit. | npm | marked 1.2.9 | 3 | `patch-pilot scan examples/major-bump` |
| [pnpm-argv](pnpm-argv) | A CLI parses `process.argv` with minimist (prototype pollution): same analysis on a pnpm lockfile. | pnpm | minimist 1.2.5 | 1 | `patch-pilot scan examples/pnpm-argv` |

Add `--dry-run` to only report findings, or `--trust` to skip the trust prompt. To run an app itself: `npm ci && npm start` (or `pnpm install && pnpm start`).
