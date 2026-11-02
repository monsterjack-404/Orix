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
| `orix.formats` | No arguments | Recognized signatures and parser capability metadata |
| `orix.compare_reports` | `baseline_path`, `current_path` | Deterministic artifact/scan comparison, SHA-256 deltas and indicator changes |
| `orix.ledger.verify` | `path` | Evidence-ledger chain verification |
| `orix.ledger.list` | `path` | Verified evidence-ledger records |

Every tool validates its input server-side against the same schema advertised by `tools/list`. Output is capped at 2 MiB per tool response; reduce scan limits if a result exceeds the cap.

## Security boundary

- Static and read-only. No target file or project code is executed.
- No shell, arbitrary command, plugin, network or remote URL tools are exposed.
- Symlinks are not followed by the underlying scanners.
- Existing parser, traversal and file-size limits remain active.
- Tool output is JSON text in MCP content blocks. Errors are returned with `isError: true`. Comparison reads each report through a no-follow, 64 MiB-bounded file reader and never rescans the original artifacts.
- The ledger tools only read and verify. The MCP server does not provide a ledger append tool.

MCP is a transport adapter over ORIX's existing public analysis functions; it does not fork or reimplement parsers.
