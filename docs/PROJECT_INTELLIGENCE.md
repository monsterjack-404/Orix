# Project Intelligence

ORIX Project Intelligence inventories a local source tree without running project code.

## Commands

~~~bash
node src/cli.mjs project ./my-repository
node src/cli.mjs project ./my-repository --json
node src/cli.mjs project ./my-repository --json --out ./project-report.json
~~~

## Current analysis

- Deterministic traversal, symlink rejection and exclusions for generated/dependency directories.
- File inventory, SHA-256, extension/language classification and bounded source reads.
- Manifest metadata for npm-compatible package.json, Python requirements and basic pyproject.toml, Cargo, Go modules, Composer, Maven, NuGet and Gemfile.
- Dependency declarations with dependency group and manifest provenance.
- Conservative import extraction for JavaScript/TypeScript, Python, Go, Rust, C/C++, Java, Kotlin, C# and Ruby.
- Best-effort local import resolution, file graph edges and syntax-pattern symbol candidates.
- README, license, CI, tests, package-manager and container project signals.
- Redacted indicators for selected credential-shaped patterns.

## Limits and interpretation

The scanner enforces ceilings for files, entries, depth, individual file size, aggregate bytes, symbols and imports. It marks coverage incomplete when traversal limits are reached. Oversized files are skipped and recorded. It does not follow symlinks.

Manifest parsers are conservative. They do not execute package managers, resolve version ranges, fetch registries, inspect transitive lockfile graphs, run build scripts, install packages, or claim vulnerability status. Import resolution and symbol extraction are heuristic, not compiler front-ends.

Credential matches never include matched values. They identify a file and line for manual review; false positives are possible. Reports may contain local paths and project metadata, so review them before sharing.

## Security boundary

No package scripts, hooks, build tools, tests, binaries, plugins, or source files are executed. Only filesystem metadata and bounded file reads are performed. Use this feature only on repositories you own or are authorized to inspect.
