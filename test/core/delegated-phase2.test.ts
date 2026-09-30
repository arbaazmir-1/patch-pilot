import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { delegatedPrompt } from '../../src/investigation/delegated.ts';
import { minimistFixture } from '../investigation/helpers.ts';

describe('runPhase2Delegated prompt', () => {
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
