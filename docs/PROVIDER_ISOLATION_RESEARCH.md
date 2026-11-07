# Provider Isolation: Research and Implementation Plan

## Status

Research baseline only. This document does not claim that ORIX providers are sandboxed. The existing `run_static_provider` runner provides shell-free launch, executable and working-directory validation, a reduced environment, timeout, output caps and POSIX process-group signalling. It does not enforce OS-level filesystem, network, syscall, memory, CPU or Windows process-tree isolation.

## Security objective

Treat every external provider as potentially compromised, regardless of its manifest declaration. The manifest is metadata, not a security boundary. A provider must receive only explicitly granted resources; unavailable or unverified isolation must be reported as unavailable and must never be represented as sandboxed.

## Research set

The design was compared against these public projects and primary documentation:

- **Anthropic sandbox-runtime** (`anthropics/sandbox-runtime`, Apache-2.0): mature reference for deny-by-default writes, explicit filesystem grants, mediated network allowlists and OS-specific backends. Its own documentation calls out Windows-specific limitations and alpha status; do not copy its claims as universal guarantees.
- **Bubblewrap** (`containers/bubblewrap`): Linux namespace/mount construction used by Flatpak and other systems. It is a mechanism, not a complete policy; the caller must construct a safe mount namespace.
- **Landlock + seccomp-BPF**: Linux kernel-enforced filesystem and syscall restrictions. Landlock is complementary to namespaces; seccomp is not a filesystem policy. Probe kernel ABI/features at runtime and fail closed for required controls.
- **Google NSJail / Sandbox2**: useful Linux references for namespaces, resource limits and syscall filters. NSJail adds a policy language; Sandbox2 demonstrates layered isolation rather than relying on a single switch.
- **gVisor**: stronger Linux isolation option for hostile workloads through a userspace application kernel, with higher operational cost and compatibility tradeoffs.
- **macOS Seatbelt**: available through `sandbox-exec` profiles and used by existing projects, but deprecated/unsupported status and OS-version behavior must be treated as a platform risk. Never claim it is a future-proof Apple API.
- **Windows AppContainer + Job Objects + restricted tokens**: separate controls are needed for filesystem/network identity and process-tree/resource lifetime. Killing only the direct child is insufficient. A native helper may be needed for reliable Job Object assignment before untrusted code executes.
- **Arapuca** (`LeGambiArt/arapuca`, Apache-2.0): interesting cross-platform Rust reference combining Linux Landlock/seccomp/cgroups/network namespaces, macOS Seatbelt, and Windows AppContainer/Job Objects. Its current project maturity and platform coverage must be independently audited before adopting it as a production dependency.
- **Convira Sandbox**: useful reference for probe-verified capability reporting and explicit platform adapters; its small public history means it is an architectural reference, not a proven dependency.

## Selected architecture

Use a **capability-driven, per-platform backend**, not a pretend cross-platform JavaScript-only sandbox:

1. A stable JavaScript policy/API layer validates immutable grants and emits a structured isolation report.
2. A platform adapter applies kernel/OS controls before the provider executable starts.
3. The provider runs as a separate process tree/job with bounded wall time, memory, CPU, process count and output.
4. Filesystem grants are deny-by-default: read-only access to the selected executable/runtime dependencies and explicitly selected analysis inputs; write access only to a fresh, disposable scratch directory.
5. Network is disabled by default. Future network access must use a mediated allowlist/proxy, not a boolean manifest claim.
6. Each control is reported as `enforced`, `unavailable`, or `not-requested`, with probe evidence. A successful spawn is not proof of confinement.
7. `isolation: required` must fail before launch if any required control is unavailable. Best-effort mode must be explicit and visibly downgraded. Legacy unsandboxed execution remains clearly labelled and must never be called isolated.

## Platform plan

### Linux
- Primary unprivileged backend: Bubblewrap with new mount, PID, IPC, UTS and network namespaces; minimal read-only runtime mounts; no host home mount; isolated proc/dev; scratch-only writable tmpfs; no network namespace interfaces.
- Add Landlock rules for path-level read/write/execute grants where supported.
- Add a conservative seccomp profile for the selected provider class; block namespace/mount/ptrace/keyring and other escape-sensitive syscalls where compatible.
- Apply cgroup v2 or rlimits for memory, CPU and process counts. Report which limits were actually applied.
- Consider gVisor/NSJail as optional stronger deployment backends, not mandatory runtime dependencies.

### macOS
- Use a generated deny-default Seatbelt profile only after validating supported rules on each supported macOS runner.
- Grant the minimum executable/runtime reads, selected input reads and scratch writes; deny network and home/credential access.
- Treat `sandbox-exec` as a compatibility backend with an explicit deprecation warning. If the policy cannot be applied, required isolation fails closed.
- Add process-tree ownership and cleanup tests; do not rely on direct-child termination.

### Windows
- Use a native helper to create a restricted token/AppContainer, apply explicit filesystem capabilities and network isolation, assign the process to a Job Object before untrusted code runs, and set memory/CPU/active-process limits.
- Use explicit handle inheritance (stdio only), process mitigations and kill-on-job-close semantics.
- Do not claim Windows isolation until native helper behavior is tested on Windows CI. `taskkill /T` alone is not a security boundary.

## Mandatory security invariants

- No shell, command-string interpolation, PATH lookup or inherited ambient credentials.
- No implicit host home, SSH, cloud credentials, browser profile, package manager cache or repository write access.
- No network by default, including DNS.
- No writable mount except per-run scratch.
- No child process escape from the managed process tree/job.
- Resource ceilings are applied by the OS where available, not merely checked in JavaScript.
- Cleanup is idempotent and runs after success, failure, timeout, abort and parent shutdown.
- Policy paths are canonicalized and revalidated; symlink and mount traversal must not widen grants.
- Provider output, exit status and isolation evidence remain separate fields.
- A capability is marked enforced only after a successful runtime probe; unsupported controls are never silently downgraded.

## Verification plan

- Unit tests for policy validation, path grant normalization, command/profile generation and capability-state transitions.
- Hostile fixture processes that attempt home/credential reads, writes outside scratch, network/DNS, ptrace, mount/namespace changes, fork bombs, memory exhaustion, output floods and descendant survival after timeout.
- Verify denials with OS-level observations, not only mocked return values.
- CI matrix: Linux, macOS and Windows, with per-platform integration suites. Unsupported host controls must be reported explicitly, not skipped while the aggregate is presented as full sandbox coverage.
- Fuzz policy serialization, path normalization and helper IPC.
- Security review native code and keep the helper protocol versioned and length-bounded.

## Delivery gates

1. Capability report and policy contract.
2. Linux Bubblewrap backend with Landlock/seccomp/resource controls and hostile integration tests.
3. macOS Seatbelt backend with tested deny-default policy and documented support limits.
4. Windows native AppContainer/Job Object backend and process-tree tests.
5. Cross-platform conformance suite, threat-model review and post-merge verification.

Until all platform gates pass, ORIX must continue to describe the existing provider runner as **process control, not sandboxing**.
