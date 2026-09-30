// separate file avoids an import cycle

export type LlmErrorKind =
  | 'unreachable'
  | 'timeout'
  | 'http'
  | 'model-missing'
  | 'no-tools'
  | 'out-of-memory'
  | 'invalid-response'
  | 'aborted';

// e.g. hint "ollama pull mistral"
export class LlmError extends Error {
  readonly kind: LlmErrorKind;
  readonly status: number | null;
  readonly hint: string | null;
  constructor(kind: LlmErrorKind, message: string, options: { status?: number; hint?: string; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'LlmError';
    this.kind = kind;
    this.status = options.status ?? null;
    this.hint = options.hint ?? null;
  }
}
