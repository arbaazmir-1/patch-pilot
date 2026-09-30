import type { Assessment, CaseFile, Dossier, ProviderName, Verdict } from '../types.ts';
import { PatchPilotError, EXIT } from '../util/errors.ts';
import { hashJson, readJsonIfExists, writeJsonAtomic } from '../util/fs.ts';

export const ASSESSMENT_VERSION = 1;

// ties assessment to its case file
export function caseFileHash(caseFile: CaseFile): string {
  return hashJson(caseFile);
}

export function createAssessment(caseFile: CaseFile, meta: { provider: ProviderName; model: string; promptVersion: string }): Assessment {
  const now = new Date().toISOString();
  return {
    version: ASSESSMENT_VERSION,
    caseFileHash: caseFileHash(caseFile),
    createdAt: now,
    updatedAt: now,
    provider: meta.provider,
    model: meta.model,
    promptVersion: meta.promptVersion,
    complete: false,
    dossiers: [],
    verdicts: [],
  };
}

function sameVerdict(a: Pick<Verdict, 'vulnId' | 'package' | 'installedVersion'>, b: Pick<Verdict, 'vulnId' | 'package' | 'installedVersion'>): boolean {
  return a.vulnId === b.vulnId && a.package === b.package && a.installedVersion === b.installedVersion;
}

// returns a copy
export function upsertVerdict(assessment: Assessment, verdict: Verdict): Assessment {
  const index = assessment.verdicts.findIndex((v) => sameVerdict(v, verdict));
  const verdicts = [...assessment.verdicts];
  if (index === -1) verdicts.push(verdict);
  else verdicts[index] = verdict;
  return { ...assessment, verdicts, updatedAt: new Date().toISOString() };
}

// returns a copy
export function upsertDossier(assessment: Assessment, dossier: Dossier): Assessment {
  const index = assessment.dossiers.findIndex((d) => d.package === dossier.package && d.version === dossier.version);
  const dossiers = [...assessment.dossiers];
  if (index === -1) dossiers.push(dossier);
  else dossiers[index] = dossier;
  return { ...assessment, dossiers, updatedAt: new Date().toISOString() };
}

export function findVerdict(assessment: Assessment, vulnId: string, pkg: string, version: string): Verdict | undefined {
  return assessment.verdicts.find((v) => sameVerdict(v, { vulnId, package: pkg, installedVersion: version }));
}

export async function saveAssessment(file: string, assessment: Assessment): Promise<void> {
  await writeJsonAtomic(file, assessment);
}

// damaged or other-version files throw
export async function loadAssessment(file: string): Promise<Assessment | null> {
  let raw: unknown;
  try {
    raw = await readJsonIfExists<unknown>(file);
  } catch (err) {
    throw new PatchPilotError(`Cannot read ${file}: ${(err as Error).message}`, {
      exitCode: EXIT.USAGE,
      hint: 'Delete it and run `patch-pilot investigate` again.',
      cause: err,
    });
  }
  if (raw === null) return null;
  const obj = raw as Partial<Assessment> | null;
  if (!obj || typeof obj !== 'object' || Array.isArray(obj) || !Array.isArray(obj.verdicts)) {
    throw new PatchPilotError(`${file} is not a PatchPilot assessment`, {
      exitCode: EXIT.USAGE,
      hint: 'Delete it and run `patch-pilot investigate` again.',
    });
  }
  if (obj.version !== ASSESSMENT_VERSION) {
    throw new PatchPilotError(`${file} has assessment version ${String(obj.version)}; this PatchPilot reads version ${ASSESSMENT_VERSION}`, {
      exitCode: EXIT.USAGE,
      hint: 'Run `patch-pilot investigate` again to rebuild it.',
    });
  }
  return { ...(obj as Assessment), dossiers: Array.isArray(obj.dossiers) ? obj.dossiers : [] };
}
