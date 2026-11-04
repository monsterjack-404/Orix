# ORIX MCP Integration

ORIX includes a dependency-free Model Context Protocol server using the standard input/output transport.

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
| `orix.scan_directory` | `path`, optional file/entry/depth/concurrency limits | Bounded directory scan and artifact reports |
| `orix.scan_project` | `path`, optional file/entry/depth limits | Project inventory, manifests, imports and symbol candidates |
| `orix.analyze_architecture` | `path`, optional inventory and graph limits | Static source-import graph with entry-point candidates, cycles, reachability, hotspots and explicit limitations |
| `orix.formats` | No arguments | Recognized signatures and parser capability metadata |
| `orix.compare_reports` | `baseline_path`, `current_path` | Deterministic artifact/scan comparison, SHA-256 deltas and indicator changes |
| `orix.ledger.verify` | `path` | Evidence-ledger chain verification |
| `orix.ledger.list` | `path` | Verified evidence-ledger records |
| `orix.ledger.append` | `path`, event `type`, JSON object `payload` | Workspace-confined append receipt for the hash-chained ledger |

The server advertises only its implemented `tools` capability; resource and prompt catalogs are not exposed. It negotiates the requested protocol version when it supports it and otherwise reports its supported version (`2025-03-26`). Initialize requests require `protocolVersion`, `capabilities` and `clientInfo.name/version`. JSON-RPC request IDs are restricted to strings or finite numbers; malformed request envelopes and malformed `tools/call` parameters receive protocol-level errors. Valid notifications never receive responses. Batches are processed sequentially with a 100-message ceiling; notification replies are omitted, empty batches are rejected, and `initialize` is rejected inside a batch. Each stdio server instance also limits tool execution to 60 calls per 60-second window by default; `start_mcp_server({ max_tool_calls_per_minute })` can set a value from 1 to 10,000. Protocol pings and tool discovery are not counted against this limit.

Every tool validates its input server-side against the same schema advertised by `tools/list`. Output is capped at 2 MiB per tool response; reduce scan limits if a result exceeds the cap.

Tool definitions also publish MCP safety annotations: inspection, inventory, comparison and ledger-read tools are marked read-only and idempotent; `orix.ledger.append` is marked as a state-changing, non-idempotent operation. These annotations are client-facing hints, not an authorization boundary. Workspace confinement and server-side validation remain authoritative.

## Security boundary

- Static and read-only. No target file or project code is executed.
- No shell, arbitrary command, plugin, network or remote URL tools are exposed.
- Symlinks are not followed by the underlying scanners.
- Existing parser, traversal and file-size limits remain active.
- Tool output is JSON text in MCP content blocks. Errors are returned with `isError: true`. Comparison reads each report through a no-follow, 64 MiB-bounded file reader and never rescans the original artifacts.
- Ledger append is explicit, workspace-confined and serialized through the ledger writer lock; records are hash-chained and size-bounded.
- Input frames are streamed with a 4 MiB maximum; tool responses are capped at 2 MiB.

Architecture analysis uses only the scanner's resolved local-import graph. It is not compiler-backed, a runtime call graph, or proof that a module is dead code. Its default graph ceilings are 4,000 nodes, 8,000 edges and 25 hotspots to keep ordinary responses within the transport budget; callers can request higher limits up to the tool schema ceilings. Its limits are independently bounded before the result is returned.

MCP is a transport adapter over ORIX's existing public analysis functions; it does not fork or reimplement parsers.
