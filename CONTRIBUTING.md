# Contributing

Thanks for helping improve ORIX.

## Development requirements

- Node.js 20+
- Git

## Local checks

```bash
npm run check
npm test
```

## Pull requests

1. Describe the problem and intended behavior.
2. Keep changes focused and document new interfaces.
3. Add tests for normal, malformed, and boundary inputs.
4. Preserve read-only behavior unless a separately reviewed feature explicitly requires otherwise.
5. Do not add dependencies without explaining why they are needed.
6. Do not include private binaries, credentials, or user data.

## Code conventions

- ECMAScript modules.
- Four-space indentation.
- Descriptive names and explicit errors.
- Prefer streaming and bounded reads for untrusted artifacts.
