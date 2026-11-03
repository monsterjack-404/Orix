# ORIX Provider Manifests and Registry

The provider layer starts with a deliberately narrow contract: ORIX can validate provider metadata and maintain an in-memory capability catalog. It does **not** load JavaScript plugins, execute external tools, install software, grant authorization, or claim that a provider is available.

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

Resource limits are mandatory declarations. They do not enforce a process timeout by themselves; a future process adapter must enforce them at the execution boundary.

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
- Does not probe, invoke, install, or switch providers.

## 4. Runtime adapter requirements

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

## 5. Security boundary

A manifest is untrusted input. It is descriptive metadata, not a signed identity, executable policy, sandbox, or authorization token. Provider installation and execution remain separate operations. Dynamic analysis must be explicitly scoped to systems the operator owns or is authorized to assess.

## 6. Public API

- validate_provider_manifest(value) — validate an in-memory data object.
- parse_provider_manifest_json(text, options) — parse bounded JSON text.
- read_provider_manifest(path, options) — safely read and validate a local manifest.
- ProviderRegistry — register, query, snapshot, and unregister manifest metadata.
- PROVIDER_CONTRACT_VERSION — current contract identifier.
- DEFAULT_PROVIDER_MANIFEST_LIMIT — default 64 KiB input ceiling.
