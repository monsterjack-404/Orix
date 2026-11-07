# Project Intelligence

ORIX inventories a local source tree without executing project code, package scripts, build hooks, tests, binaries or plugins.

## Commands

```bash
node src/cli.mjs project ./my-repository
node src/cli.mjs project ./my-repository --json
node src/cli.mjs project ./my-repository --json --out ./project-report.json
node src/cli.mjs project ./my-repository --format cyclonedx --out ./sbom.cdx.json
```

## Inventory and source model

- Deterministic, bounded directory traversal with symlink rejection and generated/dependency-directory exclusions.
- Read-only Git metadata inventory: HEAD branch/detached state, loose and packed refs, tags, sanitized remote coordinates, shallow boundaries and verified loose HEAD commit metadata. Packed object contents and linked-worktree gitdir targets are not followed.
- File size, SHA-256, extension/language classification and bounded text reads.
- Manifest metadata for npm, Python, Cargo, Go modules, Composer, Maven, NuGet and Ruby.
- Dependency declarations with manifest and dependency-group provenance.
- Bounded JavaScript/TypeScript tokenizer that ignores comments and string contents while extracting static imports, re-exports, literal `require()` / `import()` specifiers and declaration candidates.
- Polyglot source inventory and syntax-pattern import/declaration candidates for Python, Go, Rust, C/C++, Objective-C/Objective-C++, Java, Kotlin, C#, Swift, PHP, Ruby, Shell, SQL, Dart, Scala, Lua, Perl, R, Elixir, Haskell, Clojure, F#, Visual Basic and PowerShell.
- Best-effort local relative-import resolution across supported extensions, file graph edges and syntax-pattern symbol candidates. These are lightweight language-specific patterns, not compiler ASTs or semantic type analysis.
- README, license, CI, tests, package-manager and container signals.
- Redacted findings for selected credential-shaped patterns.

## Electron static triage

Project scans inspect JavaScript and TypeScript source for Electron module imports and literal `webPreferences` settings. The current rules flag enabled renderer Node integration, disabled context isolation, disabled sandboxing, disabled web security, insecure content allowance and the deprecated remote module setting. Each finding includes a source file and line number.

This is bounded lexical triage, not a complete JavaScript parser or Electron runtime model. Only direct literal boolean properties inside a `webPreferences` object are inspected; nested properties and computed values are not interpreted. Comments, ordinary strings, regular-expression bodies and template literal bodies are treated as opaque. Each source file is capped at 100,000 tokens, and the report records how many files hit that cap in `electron.analysis_truncated_files`. Process roles inferred from file names are candidates only. Findings require manual review and are not exploitability verdicts.

## Website offline analysis

Project scans identify HTML, HTM and XHTML files and build a bounded offline inventory of page titles/language, script and stylesheet references, links, forms, iframes, images and selected metadata. References are normalized against the scanned project without DNS or HTTP requests; query strings and fragments are not retained in reference records.

Review findings include `javascript:` URLs, local references that escape the project root, plain-HTTP references and form actions, `_blank` links without `noopener`/`noreferrer`, inline event handlers and external scripts without an integrity attribute. These are triage leads, not exploitability or compliance verdicts.

The tokenizer is a bounded lexical HTML scanner, not a standards-complete HTML5 parser or browser DOM. Scripts, stylesheets, templates and embedded documents are never executed or fetched. Default ceilings are 500 pages, 1 MiB per page, 20,000 tags per page, 100,000 attributes per page, 2,000 references per page and 500 findings. Truncation is reported in `website.coverage`.

Live browser observation, DOM snapshots, console/network events, screenshots, storage inspection and runtime traces remain separate future provider capabilities requiring explicit scope and approval.

## Lockfile analysis

The lockfile reader currently supports:

- npm `package-lock.json` versions 1, 2 and 3, including nested package placement, root dependencies, package metadata and dependency edges.
- Yarn classic and Berry lockfiles, including selector groups, resolved versions, checksums/integrity fields and dependency edges.
- pnpm lockfiles using versions 5.x, 6.x and 9.x, including importers, snapshots, peer-context package identities and dependency edges.
- Cargo `Cargo.lock` versions 1 through 4, package sources, checksums and workspace/package dependency relationships.
- Composer `composer.lock` runtime/development packages, package requirements, checksums and root manifest edges.
- Poetry `poetry.lock` package groups, dependency requirements, package hashes and root edges derived from `pyproject.toml`.
- Astral uv `uv.lock` workspace packages, registry/source identities, dependency constraints and package-to-package edges.
- Pipenv `Pipfile.lock` resolved versions and hashes, matched to `Pipfile` root declarations. Pipfile.lock does not encode package-to-package edges, so ORIX explicitly marks that graph incomplete.
- Go `go.sum` module checksums, matched against exact `go.mod` declarations where available.
- Ruby `Gemfile.lock` specs, platforms, source metadata and dependency edges.
- NuGet `packages.lock.json` direct/transitive package records, target-framework aggregation, content hashes and dependency edges.
- Gradle `gradle.lockfile` module versions and configuration memberships. Gradle lockfiles do not encode package-to-package edges, so ORIX marks the graph incomplete.

The project report records lockfile format, path, package inventory, root edges, package-to-package edges, warnings and completeness. Package locations are kept distinct so nested versions of the same package do not collapse in the dependency graph. Lockfile package records are not registry lookups: ORIX does not download packages or validate their integrity hashes against remote content.

Unresolved selectors and malformed records are surfaced as warnings rather than silently treated as a complete graph. Formats without a parser are omitted from lockfile analysis while supported manifest declarations remain visible.
 
## CycloneDX export

`--format cyclonedx` emits a CycloneDX 1.5 SBOM. When supported npm, Yarn, pnpm, Cargo, Composer, Poetry or uv lockfiles are present, ORIX uses exact locked package versions and the observed dependency relationships. Without a supported lockfile, the export falls back to recognized declared dependencies and their manifest provenance.

Package URLs are emitted only for recognized ecosystems. Development dependencies are marked optional where that classification is available. Unknown ecosystems are omitted rather than assigned guessed package URLs. A lockfile graph is an inventory of recorded package metadata, not a vulnerability assessment, publisher-authenticity check or guarantee that the lockfile matches an installed tree.

## Resource limits and interpretation

Traversal, entries, depth, individual file size, aggregate bytes, symbols, imports, lockfile packages/edges, Git refs and Git metadata reads are bounded. Oversized files are skipped and recorded. Coverage is marked incomplete when traversal limits are reached. Lockfile parsers enforce independent package and edge ceilings.

Manifest and import parsing are conservative heuristics, not compiler front-ends. Dependency declarations are not vulnerability findings. For exact resolved package versions, the optional `audit --osv` command queries OSV.dev; it never sends source or manifest contents. See [Dependency Vulnerability Intelligence](VULNERABILITY-INTELLIGENCE.md). Credential matches never include matched values; they identify a file and line for manual review, and false positives are possible.

## Security boundary

Only filesystem metadata and bounded file reads are used. File descriptors are opened with no-follow semantics where the platform exposes them, and file identity and size are checked around reads. No package manager, registry, script, build, test, binary or project-supplied code is executed. Reports may contain local paths and project metadata; review them before sharing.
