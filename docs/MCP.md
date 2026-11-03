# ORIX MCP Integration

ORIX 0.5.0 includes a dependency-free Model Context Protocol server using the standard input/output transport. The implementation currently negotiates MCP protocol version `2025-03-26` and exposes eight bounded tools. This is the implemented version, not the newest published MCP specification.

## Protocol compatibility

The MCP implementation constant in `src/mcp/server.mjs` is `2025-03-26`. The latest specification reviewed for the current product plan is `2026-07-28`. ORIX does not claim support for that newer revision yet. Compatibility work must be incremental and tested against official protocol fixtures before changing the negotiated version. See the [2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28) and [release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/).

The present transport is stdio. HTTP transport is not implemented and must not be enabled by simply binding a socket; it requires a separate authorization, origin, session and deployment threat model.

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
| `orix.formats` | No arguments | Recognized signatures and parser capability metadata |
| `orix.compare_reports` | `baseline_path`, `current_path` | Deterministic artifact/scan comparison, SHA-256 deltas and indicator changes |
| `orix.ledger.verify` | `path` | Evidence-ledger chain verification |
| `orix.ledger.list` | `path` | Verified evidence-ledger records |
| `orix.ledger.append` | `path`, event `type`, JSON object `payload` | Workspace-confined append receipt for the hash-chained ledger |

Every tool validates its input server-side against the same schema advertised by `tools/list`. Output is capped at 2 MiB per tool response; reduce scan limits if a result exceeds the cap.

## Security boundary

- Static and read-only. No target file or project code is executed.
- No shell, arbitrary command, plugin, network or remote URL tools are exposed.
- Symlinks are not followed by the underlying scanners.
- Existing parser, traversal and file-size limits remain active.
- Tool output is JSON text in MCP content blocks. Errors are returned with `isError: true`. Comparison reads each report through a no-follow, 64 MiB-bounded file reader and never rescans the original artifacts.
- Ledger append is explicit, workspace-confined and serialized through the ledger writer lock; records are hash-chained and size-bounded.
- Input frames are streamed with a 4 MiB maximum; tool responses are capped at 2 MiB.

MCP is a transport adapter over ORIX's existing public analysis functions; it does not fork or reimplement parsers.
