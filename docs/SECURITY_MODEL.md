# Security Model and Threat Boundaries

## Current security posture

ORIX 0.2.0 is a static local inspector. It reads file bytes, calculates hashes, extracts printable strings, calculates entropy, parses selected headers and writes optional reports. It does not execute the target, load a target library, attach to another process, modify the artifact, elevate privileges, connect to the network or dynamically load third-party parser code.

## Threats considered

| Threat | Current mitigation | Residual risk |
|---|---|---|
| Malformed offsets and truncated files | Central bounds-checked `BinaryReader`; parser-specific range and size checks | A parser logic bug can still misinterpret a valid range |
| Count-driven memory or CPU exhaustion | Limits on file bytes, read bytes, section counts, scan depth, files, concurrency and strings | Very large but permitted inputs can still consume resources within configured ceilings |
| Symlink traversal | Inspector rejects symlinks; walker skips symlink entries | Filesystem races and platform-specific link semantics require continued testing |
| File replacement during open | `lstat`, no-follow open where available, opened-file identity checks | Not a complete anti-race guarantee on all filesystems and platforms |
| File mutation during analysis | Before/after metadata comparison and `stable_during_read` result | A sufficiently unusual filesystem or timestamp behavior may evade metadata comparison |
| Report overwrite | `--out` uses exclusive-create semantics | Parent-directory permissions and storage integrity remain OS responsibilities |
| False confidence | Evidence confidence labels, explicit parser status and limitations | Users can still over-interpret results; reports must be read with their warnings |
| Dependency supply chain | No third-party runtime dependencies in current package | Node.js runtime, npm and development tooling still require trusted acquisition |

## Input handling rules

- Treat file contents, file names, extensions, section names and string values as untrusted data.
- Never interpret extracted strings as commands or HTML.
- Never execute a file because its signature, filename or parser output resembles a trusted artifact.
- Never treat entropy as a malware detector.
- Never equate a parser rejection with evidence of maliciousness.
- Do not silently follow symlinks or expand archives in the core inspector.
- Keep format parsers pure over provided buffers.
- Add resource ceilings before accepting any input-controlled loops or allocations.

## Future dynamic-analysis boundary

Dynamic analysis is not part of this release. A future implementation must be a separately documented opt-in subsystem. Minimum design requirements include explicit authorization context, a disposable isolated environment, resource/time limits, network policy, process ownership and identity verification, cancellation, cleanup on every exit path, audit events, and evidence provenance that distinguishes observed runtime behavior from static inference.

A sandbox is a risk reduction control, not a guarantee. Dynamic analysis must not silently start from `inspect` or `scan`.

## Vulnerability reporting

Please use GitHub's private vulnerability reporting or Security Advisories for sensitive reports. Include the ORIX version, Node.js version, operating system, exact command, a minimal non-sensitive reproducer and observed impact. Do not publish sensitive sample files, credentials or private target data in a public issue.
