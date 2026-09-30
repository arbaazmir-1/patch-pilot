export const EXIT = {
  OK: 0,
  FINDINGS: 1,
  USAGE: 2,
  ENVIRONMENT: 3,
  PATCH_FAILED: 4,
  INTERNAL: 70,
  INTERRUPTED: 130,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

export interface PatchPilotErrorOptions {
  exitCode?: ExitCode;
  // printed under the message
  hint?: string;
  cause?: unknown;
  // already printed, e.g. preflight block
  printed?: boolean;
}

export class PatchPilotError extends Error {
  readonly exitCode: ExitCode;
  readonly hint: string | undefined;
  readonly printed: boolean;

  constructor(message: string, options: PatchPilotErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'PatchPilotError';
    this.exitCode = options.exitCode ?? EXIT.INTERNAL;
    this.hint = options.hint;
    this.printed = options.printed ?? false;
  }
}

// exit 2
export class ConfigError extends PatchPilotError {
  constructor(message: string, options: Omit<PatchPilotErrorOptions, 'exitCode'> = {}) {
    super(message, { ...options, exitCode: EXIT.USAGE });
    this.name = 'ConfigError';
  }
}

// exit 3
export class EnvironmentError extends PatchPilotError {
  constructor(message: string, options: Omit<PatchPilotErrorOptions, 'exitCode'> = {}) {
    super(message, { ...options, exitCode: EXIT.ENVIRONMENT });
    this.name = 'EnvironmentError';
  }
}

// thrown by unimplemented stubs
export const NOT_IMPLEMENTED_PREFIX = 'NotImplemented: ';

export function isNotImplemented(err: unknown): boolean {
  return err instanceof Error && err.message.startsWith(NOT_IMPLEMENTED_PREFIX);
}

// ctrl+c in an inquirer prompt
export function isPromptCancelled(err: unknown): boolean {
  return err instanceof Error && (err.name === 'ExitPromptError' || err.name === 'AbortPromptError');
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
