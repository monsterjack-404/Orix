# ORIX MCP Integration

ORIX currently negotiates MCP protocol version `2025-03-26` over stdio. The newer `2026-07-28` specification is a research target, not a compatibility claim. HTTP transport and remote authorization are not implemented; stdio clients should use credentials from their local environment rather than the HTTP OAuth flow. See the [implemented protocol](https://modelcontextprotocol.io/specification/2025-03-26) and [authorization guidance](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization).

ORIX includes a dependency-free Model Context Protocol server using the standard input/output transport.



The `orix.rizin_functions` and `orix.rizin_imports` tools accept an optional `executable_args` array (up to 16 literal strings) for explicitly selected wrapper executables. Values are prepended to Rizin's argv without shell evaluation and remain subject to the bounded provider process runner. It also accepts `isolation: 'required'`, `sandbox_root`, and an optional workspace-confined `cwd` (defaults to the sandbox root) to opt into Linux Bubblewrap namespace/filesystem isolation. The sandbox root must be an existing directory inside a configured MCP workspace root; isolation defaults to `none`.
## Start

From the repository root:

```bash
node ./src/mcp.mjs
```

Configure an MCP client with command `node`, one argument containing the absolute path to `src/mcp.mjs`, and the repository root as its working directory. Keep standard output dedicated to MCP JSON-RPC messages. The server writes diagnostics to standard error.

## Tools

| Tool | Input | Result |
|---|---|---|
| `orix.inspect_file` | `path`, optional read/file MiB and string limits | Versioned artifact report with complete-file SHA-256 |
| `orix.rizin_imports` | Workspace-confined `path`, explicit `executable`, optional import/time/output limits, `isolation: none|required`, workspace-confined `sandbox_root` and optional `cwd` | Bounded static imported-symbol inventory with SHA-256 provenance; explicit Linux Bubblewrap isolation when requested |
| `orix.rizin_functions` | Workspace-confined `path`, explicit `executable`, optional function/address/instruction/decompile/time/output limits, `isolation: none|required`, workspace-confined `sandbox_root` | Rizin function inventory, address-scoped assembly disassembly and optional rz-ghidra pseudocode with SHA-256 provenance; explicit Linux Bubblewrap isolation when requested |
| `orix.scan_directory` | `path`, optional file/entry/depth/concurrency limits | Bounded directory scan and artifact reports |
| `orix.scan_project` | `path`, optional file/entry/depth limits | Project inventory, manifests, imports and symbol candidates |
| `orix.analyze_architecture` | `path`, optional inventory and graph limits | Static source-import graph with entry-point candidates, cycles, reachability, hotspots and explicit limitations |
| `orix.analyze_har` | `path`, optional `max_entries` and `max_hosts` | Offline HAR 1.2 request metadata, bounded host/status/timing summaries and evidence-linked review findings |
| `orix.formats` | No arguments | Recognized signatures and parser capability metadata |
| `orix.capabilities` | No arguments | Source-backed implemented/partial/planned inventory, format registry, provider declarations and explicit boundaries |
| `orix.compare_reports` | `baseline_path`, `current_path` | Deterministic artifact/scan comparison, SHA-256 deltas and indicator changes |
| `orix.ledger.verify` | `path` | Evidence-ledger chain verification |
| `orix.ledger.list` | `path` | Verified evidence-ledger records |
| `orix.ledger.append` | `path`, event `type`, JSON object `payload` | Workspace-confined append receipt for the hash-chained ledger |
| `orix.case.create` | `workspace`, `title`, optional `description` | Create a persistent local case without copying sample bytes |
| `orix.case.get` | `workspace`, `action` (`list`, `show`, `verify`), optional `case_id` | List/retrieve cases or verify their event chains |
| `orix.case.mutate` | `workspace`, `case_id`, action-specific fields | Add artifact references, analysis reports, findings, notes, relationships and lifecycle transitions |
| `orix.case.exchange` | `workspace`, `action` (`export`, `import`), `path`, optional `case_id` | Export/import unsigned portable case directories after digest and event-chain checks |

The server advertises only its implemented `tools` capability; resource and prompt catalogs are not exposed. Each stdio connection enforces the MCP lifecycle: only `ping` is accepted before initialization, tool requests remain blocked until the client sends `notifications/initialized`, and duplicate initialization is rejected. It negotiates the requested protocol version when it supports it and otherwise reports its supported version (`2025-03-26`). Initialize requests require `protocolVersion`, `capabilities` and `clientInfo.name/version`. JSON-RPC request IDs are restricted to strings or finite numbers; malformed request envelopes and malformed `tools/call` parameters receive protocol-level errors. Valid notifications never receive responses. Batches are processed sequentially with a 100-message ceiling; notification replies are omitted, empty batches are rejected, and `initialize` is rejected inside a batch. Each stdio server instance also limits tool execution to 60 calls per 60-second window by default; `start_mcp_server({ max_tool_calls_per_minute })` can set a value from 1 to 10,000. Protocol pings and tool discovery are not counted against this limit.

The `orix.capabilities` tool derives its format list from the live parser registry and its MCP tool list from the same definitions returned by `tools/list`; it does not probe provider executables or perform network access.

Every tool validates its input server-side against the same schema advertised by `tools/list`. Output is capped at 2 MiB per tool response; reduce scan limits if a result exceeds the cap.

Tool definitions also publish MCP safety annotations. Inspection, inventory, comparison, case reads and ledger reads are marked read-only; case creation/mutation/exchange and ledger append are state-changing operations. These annotations are client-facing hints, not an authorization boundary. Workspace confinement and server-side validation remain authoritative.

### Explicit Linux isolation example

```json
{
  "path": "/workspace/evidence/sample.elf",
  "executable": "/workspace/tools/rizin",
  "isolation": "required",
  "sandbox_root": "/workspace/provider-root"
}
```

The sandbox root must contain the executable, its runtime dependencies, the configured working directory, and the adapter's private snapshot area. The root is resolved through the same configured workspace allowlist as the input artifact; symlink roots and paths outside that allowlist are rejected. The caller is responsible for preparing and maintaining a trusted root filesystem.

## Security boundary

- Static analysis tools do not execute target code. Case creation, case mutations and bundle exchange are explicit workspace-confined writes; HAR analysis remains offline and does not replay requests or export payload/header/query values. The Rizin tool is an external-process operation and starts the user-selected executable with fixed adapter arguments. By default it runs with the account's OS permissions and is not sandboxed; on Linux, callers may explicitly request Bubblewrap namespace and read-only-root filesystem isolation with `isolation: 'required'` and a workspace-contained `sandbox_root`. Required isolation fails closed when its backend or root prerequisites are unavailable. Use trusted Rizin/plugin installations regardless of mode. The inspected target file and project code are not executed.
- No shell command-string, arbitrary command-argument, remote URL or network-request tool is exposed. `orix.rizin_functions` and `orix.rizin_imports` are the explicit exceptions that launches a user-selected Rizin executable with fixed adapter arguments. Bubblewrap mode adds namespace/filesystem isolation only; it does not enforce cgroup CPU, memory or task-count limits.
- Symlinks are not followed by the underlying scanners.
- Existing parser, traversal and file-size limits remain active.
- Tool output is JSON text in MCP content blocks. Errors are returned with `isError: true`. Comparison reads each report through a no-follow, 64 MiB-bounded file reader and never rescans the original artifacts.
- Ledger append is explicit, workspace-confined and serialized through the ledger writer lock; records are hash-chained and size-bounded.
- Input frames are streamed with a 4 MiB maximum; tool responses are capped at 2 MiB.

Architecture analysis uses only the scanner's resolved local-import graph. It is not compiler-backed, a runtime call graph, or proof that a module is dead code. Its default graph ceilings are 4,000 nodes, 8,000 edges and 25 hotspots to keep ordinary responses within the transport budget; callers can request higher limits up to the tool schema ceilings. Its limits are independently bounded before the result is returned.

MCP is a transport adapter over ORIX's existing public analysis functions; it does not fork or reimplement parsers.
