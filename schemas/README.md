# ORIX Report Schemas

The JSON Schema documents in this directory describe the public JSON report contracts. They use JSON Schema Draft 2020-12 and are intentionally additive: unknown report properties are permitted so compatible consumers can ignore fields introduced by newer ORIX releases.

| Schema | Report | Compatibility identifier |
|---|---|---|
| `artifact.v1.schema.json` | One inspected file | `orix.artifact.v1` |
| `scan.v1.schema.json` | Directory inventory and analysis | `orix.scan.v1` |
| `indicator.v1.schema.json` | One deterministic static finding | Referenced by artifact indicators |
| `ledger.v1.schema.json` | One hash-chained evidence ledger record | `orix.evidence-ledger.v1` |
| `provider-manifest.v1.schema.json` | Declarative provider capability and risk contract | `orix.provider.v1` |
| `provider-execution.v1.schema.json` | Versioned static-provider process outcome receipt | `orix.provider-execution.v1` |
| `provider-probe.v1.schema.json` | Explicit provider executable version/availability probe | `orix.provider-probe.v1` |
| `rizin-imports.v1.schema.json` | Normalized Rizin native import inventory | `orix.rizin-imports.v1` |
| `rizin-functions.v1.schema.json` | Rizin function inventory and bounded instruction disassembly | `orix.rizin-functions.v1` |
| `vulnerability-audit.v1.schema.json` | Opt-in OSV dependency vulnerability audit | `orix.vulnerability-audit.v1` |
| `capabilities.v1.schema.json` | Source-backed capability inventory | `orix.capabilities.v1` |
| `har.v1.schema.json` | Offline HAR 1.2 network investigation | `orix.har.v1` |
| `android-package.v1.schema.json` | Offline APK/AAB inventory, manifests, DEX metadata and BundleConfig result | `orix.android-package.v1` |
| `android-bundle-config.v1.schema.json` | Bounded BundleConfig protobuf metadata | `orix.android-bundle-config.v1` |
| `android-resource-table.v1.schema.json` | Bounded AAPT2 resources.pb package/type/entry/configuration inventory | `orix.android-resource-table.v1` |
| `case.v1.schema.json` | Reconstructed local investigation case | `orix.case.v1` |
| `case-bundle.v1.schema.json` | Portable case bundle manifest | `orix.case-bundle.v1` |

The provider manifest describes declared capabilities, execution side effects, resource ceilings and redistribution status. It is metadata only: a valid manifest does not prove a provider is installed, trusted, safe, or authorized to run.

The schemas document shape and basic constraints. They do not prove that a parser result is truthful, that a report was generated from authentic bytes, or that a file is safe. Consumers that need runtime validation should use a JSON Schema Draft 2020-12 validator and pin the exact schema files they accept.

The receipt carries provider identity/version, executable path, timestamps, exit/termination outcome, bounded output metadata and effective process limits. It is operational metadata, not proof of trust or sandboxing.
