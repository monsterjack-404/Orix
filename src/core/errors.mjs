// JavaScript, src/core/errors.mjs, Node.js 20+, shared typed error boundary.

export class OrixError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'OrixError';
    this.code = code;
    this.details = options.details ?? null;
    this.recoverable = options.recoverable ?? false;
  }
}

export function fail(code, message, details = null, cause = undefined) {
  throw new OrixError(code, message, { details, cause });
}

export function normalize_error(error) {
  if (error instanceof OrixError) {
    return { name: error.name, code: error.code, message: error.message, details: error.details };
  }
  if (error instanceof Error) {
    return { name: error.name, code: 'ORIX_UNEXPECTED', message: error.message, details: null };
  }
  return { name: 'Error', code: 'ORIX_UNKNOWN', message: String(error), details: null };
}
