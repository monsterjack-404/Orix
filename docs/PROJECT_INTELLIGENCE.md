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
- Bounded JavaScript/TypeScript tokenizer that ignores comments and string contents while extracting static imports, re-exports, literal `require()` / `import()` specifiers and declaration candidates. Other languages retain conservative import patterns for Python, Go, Rust, C/C++, Java, Kotlin, C# and Ruby.
- Best-effort local import resolution, file graph edges and syntax-pattern symbol candidates.
- README, license, CI, tests, package-manager and container signals.
- Redacted findings for selected credential-shaped patterns.

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
