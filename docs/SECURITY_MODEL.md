# Security Model and Threat Boundaries

## Current security posture

ORIX's built-in analysis remains static and read-only: it reads file bytes, calculates hashes, extracts strings, calculates entropy, parses supported formats and writes optional reports. It does not execute the inspected target, load target libraries, attach to target processes or modify the artifact. An operator can explicitly invoke an optional external static provider such as Rizin. ORIX executes that provider process—not the inspected sample—through a shell-free argument vector with a timeout and captured-output ceiling. This is process control, not a sandbox: a provider can still access files, spawn children or use the network unless the operating system or a separately managed container/VM restricts it.

## Threats considered

| Threat | Current mitigation | Residual risk |
|---|---|---|
| Malformed offsets and truncated files | Central bounds-checked BinaryReader; parser-specific range and size checks | A parser logic bug can still misinterpret a valid range |
| Count-driven memory or CPU exhaustion | Limits on file bytes, read bytes, section counts, scan depth, files, concurrency and strings | Very large but permitted inputs can still consume resources within configured ceilings |
| Symlink traversal | Inspector rejects symlinks; walker skips symlink entries | Filesystem races and platform-specific link semantics require continued testing |
| File replacement during open | lstat, no-follow open where available, opened-file identity checks | Not a complete anti-race guarantee on all filesystems and platforms |
| File mutation during analysis | Before/after metadata comparison and stable_during_read result | A sufficiently unusual filesystem or timestamp behavior may evade metadata comparison |
| Report overwrite | --out uses exclusive-create semantics | Parent-directory permissions and storage integrity remain OS responsibilities |
| False confidence | Evidence confidence labels, explicit parser status and limitations | Users can still over-interpret results; reports must be read with their warnings |
| External provider process | Absolute executable path, no shell interpolation, minimal explicit environment, timeout, cancellation and output-byte cap | Legacy mode is not sandboxed; platform isolation remains incomplete |
| Dependency supply chain | No third-party runtime dependencies in current package | Node.js runtime, npm and development tooling still require trusted acquisition |

## MCP, browser viewer and network boundaries

| Surface | Threat | Current mitigation | Residual risk / non-claim |
|---|---|---|---|
| MCP stdio | Malformed JSON-RPC envelopes, oversized frames/batches and repeated tool calls | Strict UTF-8/JSON parsing, request-ID validation, 4 MiB frame cap, 100-message batch cap, 60 tool calls per minute by default, argument schemas | No remote HTTP transport or remote authorization; stdio clients must be locally trusted |
| MCP workspace tools | Path traversal, symlink escape and unintended writes | Workspace-root resolution, no-follow file reads, bounded reports and explicit case/ledger mutation routes confined to configured roots | Safety annotations are hints, not authorization; local filesystem permissions remain authoritative |
| Browser report viewer | Stored script injection through report strings or untrusted filenames | DOM construction with textContent, fixed static-asset allowlist, loopback-only binding, CSP with connect-src 'none', nosniff | The viewer is not a sandbox for a compromised browser; do not open untrusted files in a compromised environment |
| CSV export | Spreadsheet formula injection and CSV quoting confusion | Cells beginning with whitespace then =, +, - or @ are prefixed with an apostrophe; quotes are doubled and line breaks normalized | CSV is for review/interchange, not a signed or canonical evidence format |
| OSV dependency audit | Network disclosure and oversized/untrusted advisory responses | Explicit --osv opt-in; only ecosystem/name/version package identities are queried; response bytes, batches, pages and advisory counts are bounded | Public OSV service availability and data quality are external; source files are not uploaded; partial results must remain partial |
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

A sandbox is a risk reduction control, not a guarantee. Dynamic analysis must not silently start from inspect, scan, or a static provider adapter.

## Vulnerability reporting

Please use GitHub's private vulnerability reporting or Security Advisories for sensitive reports. Include the ORIX version, Node.js version, operating system, exact command, a minimal non-sensitive reproducer and observed impact. Do not publish sensitive sample files, credentials or private target data in a public issue.

## Provider path and environment controls

The provider runner compares the canonical executable with an explicit allowlist (or uses the selected executable as its single-entry default) and validates the working directory against explicit canonical roots (or the exact cwd as its default). It rejects final symlink paths and malformed/accessor-backed allowlist arrays. The child does not inherit the full parent environment; explicit values reject PATH/search and runtime-loader variables such as NODE_OPTIONS, LD_PRELOAD, DYLD_INSERT_LIBRARIES, PYTHONPATH and RUBYOPT.

These controls reduce accidental path substitution and environment injection but do not confine filesystem reads/writes, network access or provider-spawned descendants. A privileged actor can still replace an executable or its dependencies between validation and launch. Legacy process-control mode does not provide process-tree containment; required Windows isolation uses a Job Object.

## Enforced provider isolation (Linux implementation gate)

The provider runner accepts isolation: "required" only when an explicit Linux sandbox root and an explicitly delegated cgroup-v2 parent are supplied. The current Linux adapter uses Bubblewrap with an unshared network, PID, IPC, UTS and user namespace set; a read-only sandbox-root mount; fresh ephemeral /tmp; a private /proc and minimal /dev. The provider executable and working directory must resolve inside that root. Host project, home directories and credentials are not bind-mounted into the provider namespace.

The adapter also requires util-linux prlimit at a fixed trusted system path and applies inherited per-process RLIMIT ceilings before Bubblewrap starts: 60 seconds of CPU time per process, 64 MiB maximum file size, 256 open file descriptors and zero core-dump bytes. It additionally requires a caller-provided delegated cgroup-v2 parent with cpu, memory and pids controllers already enabled; ORIX never enables controllers in a parent it does not own. For each provider it creates a unique child cgroup and enforces cpu.max=50000 100000 (50% of one CPU), memory.max=536870912 (512 MiB), memory.swap.max=0, memory.oom.group=1 and pids.max=64. A trusted launcher moves itself into the cgroup before spawning the Bubblewrap/prlimit chain, so descendants inherit the same cgroup. On normal exit, spawn error, timeout, cancellation or output-limit termination, ORIX writes cgroup.kill, waits for populated=0 and removes the cgroup; cleanup failure is surfaced rather than silently reported as success. The hostile-process integration job inspects live cgroup controls and membership, verifies memory accounting, observes CPU throttling and confirms that pids.max rejects excess process creation.

These are kernel-enforced aggregate cgroup limits within the delegated subtree, combined with per-process RLIMITs; they are not a complete security boundary against a privileged host administrator or kernel vulnerabilities. The caller must provide a correctly delegated, exclusively managed cgroup subtree. If cgroup-v2 controllers, cgroup.kill, Bubblewrap, prlimit, a valid rootfs or the delegated parent are unavailable, required isolation fails closed before the provider is started. Legacy mode remains process control, not a sandbox. The Windows backend uses a unique AppContainer profile with no network capabilities and grants that package SID read/execute access only to the explicit provider rootfs. Temporary writes are redirected to the explicitly provisioned rootfs/tmp scratch directory. ORIX grants the AppContainer package SID Modify access only to that directory and applies a low mandatory integrity label; the rest of the rootfs remains read/execute-only. A Windows Job Object applies a 50% CPU hard cap, 512 MiB aggregate job-memory limit, 64 active-process limit and kill-on-job-close behavior. The native launcher verifies that the created process token is an AppContainer token, assigns the process to the Job Object before resuming it, and terminates remaining descendants when the main provider exits. Windows does not currently expose the same per-process RLIMIT file-size/open-descriptor controls used on Linux; output bytes and wall-clock time remain enforced by the ORIX parent runner.

The macOS backend applies a deny-by-default Seatbelt profile to the provider using the `sandbox_init_with_parameters` C API from a small native launcher. The profile allows read/execute access only to the provider rootfs and required system libraries, allows writes only under rootfs/tmp, denies network operations by default, and permits child process creation while restricting executable paths to the rootfs. The launcher verifies the process is sandboxed with `sandbox_check` before `exec`-ing the provider. It also applies inherited per-process RLIMITs: 60 seconds CPU, 64 MiB maximum file size, 256 open descriptors and zero core dumps. The parent runner retains wall-clock/output limits and POSIX process-group termination. macOS Seatbelt does not provide the aggregate memory/PID quotas used by Linux cgroup v2 or Windows Job Objects; these are not claimed.

The `sandbox_init_with_parameters` API used here is itself an Apple-reserved/deprecated interface; Apple's headers warn developers not to depend on its availability. It is not the supported App Sandbox entitlement model for signed application bundles. This backend is therefore experimental, not a stable long-term security guarantee. It must pass hostile-process integration tests on each supported macOS release and fails closed if the compiler, Seatbelt API or profile setup is unavailable. See the macOS integration test for the exact enforced behaviors.
