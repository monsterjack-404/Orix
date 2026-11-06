# Security Model and Threat Boundaries

## Current security posture

ORIX's built-in analysis remains static and read-only: it reads file bytes, calculates hashes, extracts strings, calculates entropy, parses supported formats and writes optional reports. It does not execute the inspected target, load target libraries, attach to target processes or modify the artifact. An operator can explicitly invoke an optional external static provider such as Rizin. ORIX executes that provider process—not the inspected sample—through a shell-free argument vector with a timeout and captured-output ceiling. This is process control, not a sandbox: a provider can still access files, spawn children or use the network unless the operating system or a separately managed container/VM restricts it.

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
| External provider process | Absolute executable path, no shell interpolation, minimal explicit environment, timeout, cancellation and output-byte cap | Provider binaries are not sandboxed; filesystem/network side effects and Windows child-tree teardown are not enforced |
| Dependency supply chain | No third-party runtime dependencies in current package | Node.js runtime, npm and development tooling still require trusted acquisition |

## MCP, browser viewer and network boundaries

| Surface | Threat | Current mitigation | Residual risk / non-claim |
|---|---|---|---|
| MCP stdio | Malformed JSON-RPC envelopes, oversized frames/batches and repeated tool calls | Strict UTF-8/JSON parsing, request-ID validation, 4 MiB frame cap, 100-message batch cap, 60 tool calls per minute by default, argument schemas | No remote HTTP transport or remote authorization; stdio clients must be locally trusted |
| MCP workspace tools | Path traversal, symlink escape and unintended writes | Workspace-root resolution, no-follow file reads, bounded reports and explicit case/ledger mutation routes confined to configured roots | Safety annotations are hints, not authorization; local filesystem permissions remain authoritative |
| Browser report viewer | Stored script injection through report strings or untrusted filenames | DOM construction with `textContent`, fixed static-asset allowlist, loopback-only binding, CSP with `connect-src 'none'`, `nosniff` | The viewer is not a sandbox for a compromised browser; do not open untrusted files in a compromised environment |
| CSV export | Spreadsheet formula injection and CSV quoting confusion | Cells beginning with whitespace then `=`, `+`, `-` or `@` are prefixed with an apostrophe; quotes are doubled and line breaks normalized | CSV is for review/interchange, not a signed or canonical evidence format |
| OSV dependency audit | Network disclosure and oversized/untrusted advisory responses | Explicit `--osv` opt-in; only ecosystem/name/version package identities are queried; response bytes, batches, pages and advisory counts are bounded | Public OSV service availability and data quality are external; source files are not uploaded; partial results must remain partial |
| Evidence ledger and cases | Local modification, truncation, record reordering, unsafe bundle paths and accidental source-sample disclosure | Append-only writer lock, SHA-256 chain verification, case-local workspace confinement, no-follow reads, bounded report/bundle sizes, member digests and event-chain verification on import | Tamper-evident, not tamper-proof; bundles are unsigned; no trusted timestamp, multi-user isolation, retention/deletion policy or remote transparency log |

Strings, package metadata and report fields may contain prompt-injection text. ORIX currently has no autonomous agent that consumes these strings as instructions. Any future agent must treat artifact/report content as untrusted data, keep instructions separate from evidence, require approval for writes/network actions and retain replayable tool/audit records.

ORIX does not decompress ZIP entries or inflate PNG IDAT data. ZIP-bomb and decompression-bomb behavior is therefore not exercised by current core parsing; adding decompression requires separate expansion-ratio, output-byte, nesting-depth, time and cancellation limits.

## Static indicator interpretation

The built-in rule set is deliberately small and explainable. It can report PE writable/executable sections, invalid section raw ranges, unsafe ZIP entry paths or symlink markers, encrypted ZIP entries, high-entropy samples, selected process-memory or credential-access API-name strings, parser rejection and file-metadata instability. Each finding carries a stable rule ID, a triage severity, a confidence label and a bounded list of supporting observations.

These findings are not detections of malicious behavior. API-name strings do not prove that a symbol is imported or called. High entropy commonly appears in ordinary compressed or encrypted content. Writable/executable memory can have legitimate uses. Unsafe archive paths identify a risk if an extracting consumer handles them incorrectly; ORIX itself does not extract them. A report without findings is not a benign verdict.

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

Executing the inspected target is not part of this release. The static provider runner starts only explicitly selected analysis tools. A future dynamic-analysis subsystem must be separate and opt-in. Minimum design requirements include explicit authorization context, a disposable isolated environment, resource/time limits, network policy, process ownership and identity verification, cancellation, cleanup on every exit path, audit events, and evidence provenance that distinguishes observed runtime behavior from static inference.

A sandbox is a risk reduction control, not a guarantee. Dynamic analysis must not silently start from `inspect`, `scan`, or a static provider adapter.

## Vulnerability reporting

Please use GitHub's private vulnerability reporting or Security Advisories for sensitive reports. Include the ORIX version, Node.js version, operating system, exact command, a minimal non-sensitive reproducer and observed impact. Do not publish sensitive sample files, credentials or private target data in a public issue.


## Provider path and environment controls

The provider runner compares the canonical executable with an explicit allowlist (or uses the selected executable as its single-entry default) and validates the working directory against explicit canonical roots (or the exact cwd as its default). It rejects final symlink paths and malformed/accessor-backed allowlist arrays. The child does not inherit the full parent environment; explicit values reject PATH/search and runtime-loader variables such as NODE_OPTIONS, LD_PRELOAD, DYLD_INSERT_LIBRARIES, PYTHONPATH and RUBYOPT.

These controls reduce accidental path substitution and environment injection but do not confine filesystem reads/writes, network access or provider-spawned descendants. A privileged actor can still replace an executable or its dependencies between validation and launch. Windows currently terminates only the direct child.


## Enforced provider isolation (Linux implementation gate)

The provider runner requires every caller to explicitly select an execution
policy. Omitting `isolation` is rejected before launch. `isolation: "none"`
is an explicitly unsandboxed legacy mode: it retains shell-free argv, an
allowlisted executable, a reduced environment, a timeout and output ceiling,
but it does not confine filesystem access, networking or descendants.
Execution results report `isolation: "none"` and
`isolation_enforced: false` for this mode.

`isolation: "required"` is the enforced Linux path. It requires an explicit
sandbox root and an administrator-provisioned delegated cgroup-v2 parent with
the `cpu`, `memory` and `pids` controllers available. The adapter uses
Bubblewrap with unshared network, PID, IPC, UTS and user namespaces, a
read-only provider rootfs, a fresh ephemeral `/tmp`, private `/proc`, and
minimal `/dev`. It disables nested user namespaces and fails closed if the
installed Bubblewrap does not support the required controls. The provider
executable and working directory must resolve inside the deliberately
provisioned rootfs.

Before provider execution, a trusted bootstrap moves itself into the
per-provider cgroup; the spawned Bubblewrap and provider descendants inherit
membership. The cgroup enforces `cpu.max=50000 100000` (50% of one CPU),
`memory.max=536870912` (512 MiB), `memory.swap.max=0`,
`memory.oom.group=1` and `pids.max=64`. Per-process RLIMIT ceilings are
60 CPU seconds, 64 MiB file size, 256 open descriptors and zero core-dump
bytes. The lifecycle kills and verifies descendants, waits for
`cgroup.events populated=0`, removes the per-run cgroup, and surfaces
cleanup failures instead of reporting successful execution.

The Linux hostile-process integration test exercises filesystem and network
boundaries, nested-user-namespace denial, kernel CPU throttling, memory OOM,
PID-limit rejection, RLIMIT values, and descendant teardown against a
temporary delegated cgroup-v2 hierarchy. The caller must supply a correctly
delegated, exclusively managed parent; ORIX does not change controllers on a
parent it does not own. This is a risk-reduction boundary, not protection
against privileged host administrators or kernel vulnerabilities.

## Windows AppContainer + Job Object

The Windows backend creates a unique AppContainer profile with no network
capabilities. Before profile creation, the native launcher walks the canonical
rootfs and its ancestors, rejects reparse points, and requires each owner to be
the service identity, LocalSystem, local Administrators or TrustedInstaller.
The rootfs itself must have no write-capable ACL grant to another principal.
Ancestors must not grant untrusted principals deletion/replacement, ownership
or ACL-control rights; ordinary sibling-creation rights on an ancestor are not
treated as permission to modify an existing rootfs child. Any inherited
write-capable ACE effective on the rootfs is rejected at the rootfs itself.
This is a conservative ACL preflight, not a defense against privileged host
administrators or a subsequent trusted-host ACL/mount change. It grants the package SID
read/execute access to the explicit provider rootfs and confines writable
scratch to `rootfs/tmp`, including the package-specific
`Packages/<profile>/AC/Temp` location used by Windows temporary-file APIs. The native launcher creates the provider suspended,
assigns it to a Job Object before resume, verifies the process token is an
AppContainer token, and configures a 50% CPU hard cap, 512 MiB aggregate job
memory limit, 64 active processes and kill-on-job-close. It terminates and
waits for remaining descendants before cleanup. Windows does not expose the
same per-process RLIMIT file-size/open-descriptor controls used by Linux and
macOS; ORIX's parent runner still limits wall-clock time and captured output.
The Windows hostile-process integration test checks host-file denial,
read-only rootfs, confined writable temporary storage and loopback network
denial, and the launcher confirms Job Object configuration.

## macOS Seatbelt (experimental)

The macOS backend applies a deny-by-default Seatbelt profile through a native
launcher. The profile restricts provider reads/execution to the explicit
rootfs and required system runtime files, allows writes only under
`rootfs/tmp`, and denies network operations. The launcher verifies that the
kernel sandbox is active before exec and applies inherited RLIMIT ceilings:
60 CPU seconds, 64 MiB file size, 256 open descriptors and disabled core
dumps. Before launch, the canonical rootfs and each ancestor must be owned by
root or the ORIX service account and must not be group/other writable; only
root-owned sticky ancestors (such as /tmp) are exempt, and the filesystem
root itself is rejected. Every rootfs descendant is also checked: entries must
be root/service-owned regular files or directories, cannot be group/other
writable, setuid/setgid, symlinks, hard-linked files or special filesystem
objects. These are mode/ownership preflight checks, not a race-free filesystem
pin or a complete inspection of extended ACLs; operators must still protect
ACLs, mount configuration and rootfs contents. Hostile-
process tests verify an outside-rootfs secret is unreadable, the rootfs cannot
be modified, private temporary writes work and host loopback networking is
blocked.

macOS Seatbelt does not provide the aggregate memory/PID quotas enforced by
Linux cgroup v2 or Windows Job Objects; ORIX does not claim those controls on
macOS. The native integration uses Apple's reserved
`sandbox_init_with_parameters` / `sandbox_check` interfaces rather than the
supported signed App Sandbox entitlement model. Apple does not guarantee the
long-term availability of these reserved interfaces, so this backend is
experimental and must be revalidated against each supported macOS release.
It fails closed if its compiler, Seatbelt API or policy setup is unavailable.

Across all platforms, `isolation: "none"` remains explicit legacy process
control, not an OS sandbox. `isolation: "required"` is reported as enforced
only after the selected platform backend has successfully prepared its
kernel-enforced restrictions. OS sandboxes are risk-reduction boundaries,
not protection against privileged host administrators, kernel vulnerabilities
or compromised OS security services.
