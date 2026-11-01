# ORIX Roadmap

This roadmap is directional. Items below are planned unless explicitly listed as implemented.

## Foundation — in progress

- [x] Node.js ESM project skeleton
- [x] Read-only artifact inspector
- [x] SHA-256 streaming hash
- [x] Initial magic-byte signature recognition
- [x] CLI and automated tests
- [x] CI workflow
- [ ] Validate the initial GitHub Actions run

## Next: format intelligence

- [ ] Typed artifact and evidence schemas
- [ ] Extensible format registry
- [ ] Validated PE parser with section and import metadata
- [ ] ELF and Mach-O metadata parsers
- [ ] Safe archive listing with decompression limits
- [ ] JSON report schema and versioning

## Next: code intelligence

- [ ] Repository inventory and language detection
- [ ] Symbol and dependency index
- [ ] Cross-reference graph
- [ ] Architecture and call-flow reports
- [ ] Incremental indexing

## Research workflows

- [ ] Provider adapters for approved local tools
- [ ] Reproducible analysis sessions
- [ ] Evidence provenance and export
- [ ] Optional local model integration
- [ ] Sandboxed dynamic-analysis design review

## Product surface

- [ ] Local web dashboard
- [ ] Desktop packaging
- [ ] Plugin and MCP interfaces
- [ ] Team collaboration and access controls

Every milestone must ship with tests, documented limitations, and a security review appropriate to its capabilities.
