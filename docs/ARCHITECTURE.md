# ORIX Architecture

## Design principles

1. **Read-only by default:** inspection never executes or mutates the target artifact.
2. **Evidence before inference:** preserve hashes, parser versions, offsets, and provenance with analysis results.
3. **Adapters over assumptions:** external disassemblers, decompilers, debuggers, and scanners integrate behind explicit provider interfaces.
4. **Capability isolation:** risky operations require an explicit, separately sandboxed execution boundary.
5. **Reproducibility:** inputs, tool versions, configuration, and outputs should be recorded in each analysis session.

## Current vertical slice

- Node.js 20+ ESM CLI.
- Core inspector streams file bytes to SHA-256 and retains only the first 64 bytes for signature detection and preview.
- Supported signatures: ELF, DOS/PE marker, ZIP, PDF, PNG, JPEG, WebAssembly, GZIP, SQLite, and Mach-O.
- Node's built-in test runner; no runtime dependencies.

The DOS MZ marker is not sufficient to prove that a file is a valid PE image. A future PE parser must validate the DOS header, `e_lfanew`, and PE signature before reporting a confirmed PE format.

## Target architecture (planned)

- **Application layer:** web dashboard and desktop shell.
- **API layer:** typed project, artifact, analysis-session, and report APIs.
- **Core engine:** format registry, bounded parsers, normalized evidence model.
- **Provider layer:** adapters for approved disassemblers, decompilers, debuggers, and scanners.
- **Intelligence layer:** retrieval-grounded codebase explanations and optional model providers.
- **Storage:** local SQLite for single-user mode; PostgreSQL for multi-user deployments.
- **Isolation:** disposable containers or VMs for any future dynamic analysis.

## Trust boundaries

Untrusted files are data, never instructions. Parsers must enforce size, recursion, and time limits. External tool invocations must use argument arrays rather than shell interpolation. Secrets must never be written into analysis artifacts or logs.
