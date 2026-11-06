# ORIX Provider Manifests and Registry

The provider layer validates metadata, maintains an in-memory capability catalog, and supports an opt-in bounded runner for explicitly declared static providers. It does **not** load JavaScript plugins, install software, grant authorization, create an OS sandbox, or claim that a provider is available before it has actually been located and invoked.



### Executable argument prefixes

For wrapper executables, the provider adapter accepts an optional `executable_args` array. These literal arguments are prepended to the provider's own argument vector; they are passed directly to the selected absolute executable with `shell: false`. The CLI exposes this as repeatable `--executable-arg <value>` (maximum 16), and the MCP `orix.rizin_functions` tool accepts `executable_args` with the same 16-item bound. Prefix arguments are subject to the process runner's argument-count, byte-size and NUL-byte checks. This does not change executable allowlisting or turn the provider into an OS sandbox.
## 1. Manifest format

Provider manifests use the **orix.provider.v1** contract defined by [provider-manifest.v1.schema.json](../schemas/provider-manifest.v1.schema.json).

Example static provider:

~~~json
{
  "contract_version": "orix.provider.v1",
  "id": "rizin.static",
  "name": "Rizin static analysis",
  "version": "1.2.3",
  "description": "Read-only native binary metadata and disassembly provider.",
  "capabilities": ["binary.headers", "binary.disassembly"],
  "supported_platforms": ["linux", "windows", "macos"],
  "input_formats": ["pe", "elf", "macho", "wasm"],
  "execution": {
    "mode": "static",
    "requires_authorization": false,
    "executes_target": false,
    "writes_target": false,
    "uses_network": false
  },
  "limits": {
    "timeout_ms": 30000,
    "max_input_bytes": 134217728,
    "max_output_bytes": 16777216
  },
  "license": {
    "spdx_id": "LGPL-3.0-only",
    "redistribution": "external-install",
    "source_url": "https://github.com/rizinorg/rizin"
  },
  "documentation_url": "https://rizin.re/"
}
~~~

The execution object describes declared side effects. Target execution, target writes, and network access require requires_authorization to be true. A static provider cannot declare those side effects. This is a policy validation rule, not proof that a third-party executable behaves as declared.

Resource limits are mandatory declarations. The static process runner enforces the declared timeout and output ceilings when invoked, but cannot enforce a provider's filesystem, network or child-process behavior.

The license redistribution field distinguishes components that ORIX may bundle from separately installed or proprietary providers. This is metadata for review, not legal advice or a substitute for reading the upstream license.

## 2. Validate a manifest

Use the public programmatic API:

~~~js
import { read_provider_manifest } from './src/providers/manifest.mjs';

const manifest = await read_provider_manifest('./providers/rizin.provider.json');
process.stdout.write(JSON.stringify(manifest, null, 2));
~~~

The reader:
- Accepts only regular files and rejects symbolic links.
- Defaults to a 64 KiB input limit (configurable up to 1 MiB).
- Opens the file read-only and checks file identity before and after reading.
- Rejects files that change while being read.
- Requires valid UTF-8 and JSON.
- Rejects unknown fields, accessors, sparse arrays, duplicate array values, and non-enumerable data.
- Validates semantic-version syntax, platform and format identifiers, resource ceilings, URLs, and authorization declarations.
- Never evaluates or imports the manifest.

The returned object and nested values are frozen.

## 3. Query provider capabilities

The metadata-only registry can filter registered manifests:

~~~js
import { ProviderRegistry } from './src/providers/registry.mjs';
import { read_provider_manifest } from './src/providers/manifest.mjs';

const registry = new ProviderRegistry();
const manifest = await read_provider_manifest('./providers/rizin.provider.json');

registry.register(manifest);

for (const provider of registry.list({
  capability: 'binary.disassembly',
  input_format: 'elf'
})) {
  process.stdout.write(provider.id + ' ' + provider.version);
}
~~~

The registry:
- Rejects duplicate provider IDs.
- Filters by capability, input format, and platform.
- Returns deterministic ID-sorted results.
- Keeps registered manifests immutable.
- Produces an immutable metadata snapshot.
- Does not probe, install, or automatically switch providers. Invocation is a separate explicit API call.


## 4. Static process runner

The public `run_static_provider` API launches a provider through a validated absolute executable path and an argument vector. It uses `shell: false`, does not inherit the full parent environment, caps argument and environment sizes, bounds runtime and captured output, supports `AbortSignal` cancellation, and records exit/timeout/cancellation details.

~~~js
import { run_static_provider } from '@orix/cli';

const result = await run_static_provider({
  manifest,
  executable: '/opt/rizin/bin/rizin',
  args: ['-N', '-q', '-c', 'iij', '/evidence/sample.bin'],
  timeout_ms: 30000,
  max_output_bytes: 4 * 1024 * 1024,
});

if (!result.ok) {
  throw new Error('Provider did not complete successfully');
}
~~~

This runner is a process-control boundary, **not an operating-system sandbox**. It cannot force a declared-static executable to avoid network access, filesystem writes, or malicious behavior. POSIX process groups are signalled on timeout/cancellation. On Windows, the runner invokes the system `taskkill.exe` with `/T /F` to request termination of the provider and its descendants; if the utility cannot be started or reports failure, it falls back to terminating the direct child. Tree teardown is best-effort and is not an absolute guarantee. Do not run untrusted provider binaries on a sensitive host. Strong isolation requires an OS/container/VM policy supplied and verified separately.

## 5. Rizin import adapter

`analyze_rizin_imports` is the first concrete optional adapter. It probes the installed Rizin version, invokes the documented command-line JSON import command, normalizes import name/library/binding/type/ordinal/PLT fields, hashes the input, and rejects an input whose identity or metadata changes during the run.

~~~js
import { analyze_rizin_imports } from '@orix/cli';

const report = await analyze_rizin_imports({
  executable: '/opt/rizin/bin/rizin',
  input_path: '/evidence/sample.elf',
});

console.log(report.provider.engine_version);
console.log(report.artifact.sha256);
console.log(report.imports);
~~~

The adapter report contract is defined in [rizin-imports.v1.schema.json](../schemas/rizin-imports.v1.schema.json). The adapter checks the manifest's supported platform before launch (`linux`, `windows`, or `macos`), uses Rizin's `-N` no-user-settings option and `-q -c iij` command form, and passes only the bounded private snapshot path to the import command. See the [Rizin CLI options](https://book.rizin.re/src/first_steps/commandline_options.html) and [Rizin command-line guide](https://book.rizin.re/src/first_steps/commandline_rizin.html). Rizin remains an optional external installation; ORIX does not bundle it or claim it was run when it is unavailable. The upstream repository contains files under multiple licenses, including LGPL and GPL; the manifest therefore uses SPDX `NOASSERTION` rather than claiming one license covers the whole installation. The automated adapter tests use a deterministic executable fixture and do not substitute for verification against every supported upstream Rizin release.

### Function inventory and bounded disassembly

`analyze_rizin_functions` uses Rizin's `-A` automatic-analysis option and `aflj` JSON output to return a bounded function inventory. Pass `address` to request a bounded instruction window from one exact function-entry address; the adapter confirms that the address is present in the returned function inventory before using Rizin's `pdj` JSON disassembly command. Add `decompile: true` to request optional pseudocode from Rizin's `pdg` command.

~~~js
import { analyze_rizin_functions } from '@orix/cli';

const report = await analyze_rizin_functions({
  executable: '/opt/rizin/bin/rizin',
  input_path: '/evidence/sample.elf',
  max_functions: 10000,
  address: '0x401000',
  max_instructions: 100,
  decompile: true, // optional; requires rz-ghidra to be installed in Rizin
});

console.log(report.functions);
console.log(report.disassembly?.instructions);
~~~

The function inventory is capped at 100,000 entries; the default is 10,000. Address-scoped disassembly is optional and capped at 1,000 instructions; the default is 100. Runtime and captured stdout/stderr share one total budget across the version, function and optional disassembly processes. Each report includes the input SHA-256 and records whether function inventory was truncated.

The `pdg` pseudocode mode requires the separately installed `rz-ghidra` plugin; it is never downloaded or installed by ORIX. The upstream project is LGPL-3.0 and documents Rizin-version compatibility; choose a compatible plugin/Rizin pair before enabling it. ORIX does not redistribute or auto-install the plugin. Its output is heuristic and may be incomplete, incorrect or non-compilable. When the plugin is absent, the request returns `ORIX_RIZIN_DECOMPILER_UNAVAILABLE`. Rizin's automatic analysis is heuristic and may miss or misclassify functions. See the [rz-ghidra project and command reference](https://github.com/rizinorg/rz-ghidra), which documents `pdg` as its native Ghidra decompiler command. See the [Rizin command-line options](https://book.rizin.re/src/first_steps/commandline_options.html), [code analysis guide](https://book.rizin.re/src/analysis/code_analysis.html) and [function analysis reference](https://book.rizin.re/src/analysis/code_analysis.html#analyze-functions).
### CLI

List adapters without probing external installations:

~~~sh
node src/cli.mjs providers list --json
~~~

Check an explicit Rizin installation without opening an artifact:

~~~sh
node src/cli.mjs providers rizin doctor --executable /opt/rizin/bin/rizin --json
~~~

The doctor command launches only the version probe. It never searches PATH and does not prove that all Rizin analysis commands work.

Run import extraction with an explicit Rizin executable:

~~~sh
node src/cli.mjs providers rizin imports ./sample.elf \
  --executable /opt/rizin/bin/rizin \
  --format json \
  --timeout-ms 30000 \
  --max-output-kib 4096 \
  --max-imports 100000
~~~

The timeout applies to the complete adapter workflow, including the version and import probes. The output cap is applied per process and covers combined stdout/stderr capture. The Markdown renderer displays at most 2,000 rows by default; use JSON to preserve the complete normalized result.

Run bounded function inventory and an optional instruction window:

~~~sh
orix providers rizin functions ./sample.elf --executable /opt/rizin/bin/rizin --max-functions 10000 --json
orix providers rizin functions ./sample.elf --executable /opt/rizin/bin/rizin --address 0x401000 --max-instructions 100 --json
~~~


## 6. Runtime adapter requirements

A provider is not an implemented analysis integration merely because its manifest validates or appears in the registry. Before an adapter can be advertised as operational, it must implement and test:

1. Exact executable identity and version probing.
2. Explicit capability and platform checks.
3. Argument-vector process launch without shell interpolation.
4. Input/output byte ceilings and bounded temporary storage.
5. Deadline enforcement and cancellation.
6. Process-tree ownership and teardown.
7. Network and target-side-effect declarations.
8. Structured diagnostics and stable error mapping.
9. Evidence provenance, input digest, provider version, and output digest.
10. Golden, malformed, timeout, cancellation, and cleanup tests.

Provider failure must remain visible. ORIX must not silently substitute another engine or imply that an unavailable provider ran.

## 7. Security boundary

A manifest is untrusted input. It is descriptive metadata, not a signed identity, executable policy, sandbox, or authorization token. Provider installation and execution remain separate operations. Dynamic analysis must be explicitly scoped to systems the operator owns or is authorized to assess.

## 8. Public API

- validate_provider_manifest(value) — validate an in-memory data object.
- parse_provider_manifest_json(text, options) — parse bounded JSON text.
- read_provider_manifest(path, options) — safely read and validate a local manifest.
- ProviderRegistry — register, query, snapshot, and unregister manifest metadata.
- PROVIDER_CONTRACT_VERSION — current contract identifier.
- DEFAULT_PROVIDER_MANIFEST_LIMIT — default 64 KiB input ceiling.
- run_static_provider(options) — bounded shell-free process launch for a declared static provider.
- analyze_rizin_imports(options) — Rizin CLI adapter returning an `orix.rizin-imports.v1` report.
- analyze_rizin_functions(options) — Rizin CLI adapter returning a bounded `orix.rizin-functions.v1` function inventory and optional address-scoped instruction disassembly; it does not decompile source. The adapter hashes the source, creates a private read-only temporary snapshot, analyzes the snapshot rather than the caller's original path, and verifies the snapshot digest after provider execution.
- probe_rizin(options) — invoke an explicitly selected executable with `-v` and return an `orix.provider-probe.v1` availability/version report. This does not search PATH or claim compatibility beyond the version probe.
- render_rizin_functions_markdown(report, options) — bounded Markdown renderer for function and disassembly reports.
- RIZIN_PROVIDER_MANIFEST and RIZIN_ADAPTER_VERSION — Rizin integration metadata.


## 9. Executable, workspace and environment policy

The static runner accepts two optional allowlists:

- `allowed_executables`: absolute executable paths. If omitted, the requested `executable` is the single permitted path. If supplied, the selected executable must canonicalize to one regular, non-symlink entry.
- `allowed_working_directories`: absolute directory roots. If omitted, the chosen `cwd` is its own permitted root (or the current process directory when `cwd` is omitted). If supplied, the canonical working directory must be equal to or beneath one of the listed regular, non-symlink roots.

Allowlist arrays reject sparse entries, accessors and custom properties. The child does not inherit the full parent environment. Explicit overrides reject command-search and executable-loader keys including `PATH`, `PATHEXT`, `NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`, `PERL5OPT` and `RUBYOPT`.

Execution results include a versioned `orix.provider-execution.v1` receipt defined by [provider-execution.v1.schema.json](../schemas/provider-execution.v1.schema.json). Legacy result properties remain available for the current Rizin adapter. POSIX termination signals the detached process group. Windows uses the system `taskkill.exe` `/T /F` process-tree option and falls back to direct-child termination if tree termination fails.

These path checks constrain the selected executable and working directory; they do not confine every file the child can read or write. The manifest still cannot enforce provider behavior.
