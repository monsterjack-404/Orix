# Project Architecture Analysis

ORIX adds a static architecture-analysis layer on top of the existing bounded project scanner. It consumes the source-import graph already produced by scan_project and writes an orix.architecture.v1 report.

## Run it

```bash
orix architecture ./my-project
orix architecture ./my-project --json --out ./architecture.json
orix architecture ./my-project --format mermaid --out ./architecture.mmd
```


The command reuses the existing project inventory limits: --max-files, --max-entries and --max-depth. Report files are created exclusively; ORIX refuses to overwrite an existing path.

## What it calculates

- Import cycles: strongly connected components in the discovered local-import graph, including self-import loops.
- Entry-point candidates: source-graph roots with outgoing local imports. Familiar filenames such as index or main strengthen a heuristic label; they do not establish the true runtime entry point.
- Reachability: files reachable from the candidate roots, limited to the discovered graph.
- Connectivity hotspots: modules ranked by incoming plus outgoing local-import edges.
- Isolated and leaf modules: files with no discovered local edges, or with incoming edges and no outgoing edges.
- External import inventory: non-relative import specifiers observed in files already read by the scanner.
- Language and directory counts: deterministic inventory summaries.
- Mermaid diagram: bounded to 120 nodes and 300 edges by default.

## Important interpretation limits

This is not a compiler, call-graph engine, dead-code proof, or runtime tracer. The existing scanner uses bounded text patterns and resolves only supported relative paths. Dynamic imports, reflection, generated code, conditional exports, runtime plugin loading and language-specific module resolution can be missing. An isolated file may still be loaded dynamically; an entry-point candidate may not be launched. No source, script, build, test, package manager, or target program is executed.

The output contract is schemas/orix.architecture.v1.schema.json. The architecture report records both input-inventory completeness and graph-analysis completeness.
