# Contributing to ORIX

ORIX welcomes focused contributions that make inspection more correct, explainable, bounded and reproducible. The project is early-stage; review favors working vertical slices over large unverified feature branches.

## Before changing code

1. Read `docs/ARCHITECTURE.md`, `docs/FORMATS.md` and `docs/SECURITY_MODEL.md`.
2. Identify the component that owns the behavior. Do not duplicate interpretation in downstream layers.
3. Search existing tests and report contracts before adding a parallel abstraction.
4. For third-party engines, libraries, fixtures or copied snippets, record the source and license before implementation.

## Development setup

- Node.js 20.11 or newer.
- npm compatible with the selected Node.js release.
- No external runtime dependencies are currently required.

```bash
npm ci
npm run check
npm test
```

## Code conventions

- Use ECMAScript modules and Node.js built-ins unless a reviewed dependency is justified.
- Use `snake_case` for functions and variables, and `PascalCase` for classes.
- Prefer pure parser functions over `Buffer` input.
- Use `BinaryReader` for format field access and `OrixError` for stable boundary failures.
- Do not silently turn unknown fields into zero, empty strings or success states.
- Preserve raw values when normalization could lose information.
- Put resource ceilings next to the operation that consumes the resource.
- Keep command-line rendering out of parser modules.
- Do not execute inspected content or invoke package/build scripts during an ordinary scan.

## Parser contribution checklist

- [ ] Valid minimal fixture for each supported class/endianness.
- [ ] Truncated-header and invalid-signature tests.
- [ ] Out-of-range offset and length tests.
- [ ] Count-limit and integer-overflow tests.
- [ ] Unsupported version or extension behavior is explicit.
- [ ] Parser notes document structures that are not yet decoded.
- [ ] Format support matrix and README are updated.
- [ ] Tests and syntax checks pass locally.

## Reports and public API

Treat JSON report fields and `src/index.mjs` exports as public interfaces. Add or change report schema versions when a change is breaking. Update Markdown and JSON behavior together. Never remove evidence provenance or coverage information merely to shorten output.

## Pull requests

Use a Conventional Commit style title where practical, for example `feat(pe): parse import directory` or `fix(scan): preserve truncated inventory state`. A pull request should explain:

- the observable problem or capability;
- the owning component and design choice;
- limits and failure behavior;
- tests executed and their results;
- any parser/provider behavior not verified with real-world samples.

Do not claim benchmarks, provider compatibility or human review that did not occur. Small, independently reviewable pull requests are preferred.
