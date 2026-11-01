# ORIX

**Open Research & Intelligence eXplorer**  
*Understand. Analyze. Engineer.*

ORIX is an AI-assisted engineering research platform for authorized reverse engineering, code intelligence, binary analysis, debugging, and software security research.

## Current status

The repository is an early foundation. The first vertical slice is a read-only artifact inspector with SHA-256 hashing, file-signature recognition, and a bounded hexadecimal preview. Planned capabilities are documented in `docs/ROADMAP.md`; they are not represented as implemented.

## Requirements

- Node.js 20 or newer
- npm (bundled with Node.js)

No runtime dependencies are required.

## Quick start

```bash
npm test
npm run check
node src/cli.mjs help
node src/cli.mjs inspect ./sample.bin
node src/cli.mjs inspect ./sample.bin --json
```

## Project layout

```text
src/
  cli.mjs
  core/inspect.mjs
tests/inspect.test.mjs
docs/ARCHITECTURE.md
docs/ROADMAP.md
.github/workflows/ci.yml
```

## Safety boundary

The current inspector reads regular files and does not execute them, modify them, or contact a network. Use ORIX only on software and systems you own or are explicitly authorized to assess. See `SECURITY.md`.

## Contributing

Read `CONTRIBUTING.md` before opening a pull request. Changes should include tests and preserve the read-only default.

## License

Apache-2.0. See `LICENSE`.
