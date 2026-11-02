# ORIX Report Schemas

The JSON Schema documents in this directory describe the public JSON report contracts. They use JSON Schema Draft 2020-12 and are intentionally additive: unknown report properties are permitted so compatible consumers can ignore fields introduced by newer ORIX releases.

| Schema | Report | Compatibility identifier |
|---|---|---|
| `artifact.v1.schema.json` | One inspected file | `orix.artifact.v1` |
| `scan.v1.schema.json` | Directory inventory and analysis | `orix.scan.v1` |
| `indicator.v1.schema.json` | One deterministic static finding | Referenced by artifact indicators |
| `ledger.v1.schema.json` | One hash-chained evidence ledger record | `orix.evidence-ledger.v1` |

The schemas document shape and basic constraints. They do not prove that a parser result is truthful, that a report was generated from authentic bytes, or that a file is safe. Consumers that need runtime validation should use a JSON Schema Draft 2020-12 validator and pin the exact schema files they accept.
