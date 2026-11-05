# Linux cgroup v2 provider resource-isolation design

**Status: research/design only — no cgroup resource enforcement is implemented by this document or the current provider runner.**

## Goal

Add a Linux-only, opt-in resource-control layer to the existing required Bubblewrap provider sandbox. The initial enforced controls are:

- `cpu.max`: a configured CPU bandwidth quota and period.
- `memory.max`: a hard memory ceiling.
- `pids.max`: a hard limit on tasks/processes.
- `cgroup.kill` plus `cgroup.events`: whole-cgroup termination and an observable empty-state check during teardown.

These controls complement, but do not replace, the existing Bubblewrap filesystem and namespace boundary, output cap, wall-clock timeout, and process validation. CPU bandwidth is not a total CPU-time budget; the existing wall-clock timeout remains necessary.

## Threat model and trust boundary

The provider is hostile after launch. It may fork rapidly, create descendants, ignore ordinary termination signals, consume memory/CPU, and attempt to escape the intended lifecycle. The provider must not choose the cgroup parent, write resource-control files, move itself or descendants between cgroups, or change limits.

The cgroup parent is administrator configuration owned by the ORIX host deployment. It is not a provider manifest field, provider argument, environment override, or per-request path. The parent must be a pre-existing delegated cgroup v2 subtree whose controllers are already enabled for child cgroups. ORIX must never enable controllers by writing to the parent’s `cgroup.subtree_control`, and must never write resource settings outside the one per-run child cgroup.

A cgroup v2 mount alone is insufficient. Missing delegation, missing controllers, unavailable required control files, unsupported kernel behavior, or unsafe parent permissions must cause required isolation to fail closed. There is no fallback to process-group-only control and no silent “best effort” mode.

## Why direct spawn-then-move is rejected

Moving the Bubblewrap PID into `cgroup.procs` after `spawn()` is racy: the process can execute and fork before the host moves it. Moving only the initial PID later does not retroactively guarantee that all descendants entered the intended cgroup.

The selected design therefore uses a small trusted bootstrap process:

1. The host validates the configured delegated cgroup v2 parent and creates a unique per-run child cgroup.
2. The host writes all mandatory limits to the child cgroup and reads them back to verify the kernel accepted the exact values.
3. The host launches a packaged, trusted Node.js bootstrap helper (not a provider executable) with a narrow configuration channel.
4. The bootstrap writes **its own PID** to the child cgroup’s `cgroup.procs` before it spawns Bubblewrap.
5. The bootstrap then spawns the already-prepared Bubblewrap command. Bubblewrap and its provider descendants inherit cgroup membership from the bootstrap.
6. The host captures stdout/stderr from the bootstrap’s inherited pipes and retains the existing output and wall-clock bounds.
7. On timeout, cancellation, output overflow, spawn failure, or normal completion, the host uses the child cgroup’s `cgroup.kill` when termination is needed, waits for `cgroup.events` to report `populated 0`, and only then removes the per-run cgroup.

The helper must not accept provider-controlled configuration. Its input is a single bounded, schema-checked host-generated record. It must not invoke a shell, resolve commands through PATH, or inherit the provider’s environment. The host must use the validated absolute Node executable and the packaged helper path.

## Parent and child cgroup validation

Before creating a child, implementation must:

- Require Linux and a cgroup v2 filesystem (not a v1 hierarchy or an arbitrary directory).
- Require a configured absolute parent path and resolve it without accepting symlink components.
- Verify the parent is the expected cgroup2 mount and is a delegated subtree writable by the ORIX service identity, without granting the provider access to that parent.
- Require `cpu`, `memory`, and `pids` in the parent’s `cgroup.controllers` and require their child-controller availability before creating a run.
- Require the child control files `cpu.max`, `memory.max`, `pids.max`, `cgroup.procs`, `cgroup.events`, and `cgroup.kill`.
- Reject path traversal, symlink substitution, unsafe ownership/permissions, unexpected mount types, malformed controller values, and stale/colliding run directories.
- Create a unique child with restrictive permissions and keep all control-file operations inside that child.
- Never change parent controller state or parent limits.

Node’s path-based filesystem APIs do not provide a complete openat-style directory-fd API. The implementation must explicitly address path-component TOCTOU risks; if it cannot guarantee a safe delegated parent under the documented ownership/permission model, it must reject that configuration rather than overstate race resistance.

## Limit model

The public API should accept a small validated resource-limit object with conservative finite defaults or require all three limits explicitly. The exact defaults and maximums must be chosen from documented ORIX policy, not guessed from the host’s available resources.

- CPU: validate integer quota and period in the kernel-supported range; serialize as `<quota> <period>` for `cpu.max`.
- Memory: validate a positive safe integer byte count and serialize to `memory.max`.
- Processes/tasks: validate a positive bounded integer and serialize to `pids.max`.

Provider manifests may request a stricter limit only if policy explicitly allows it; they must never raise host policy ceilings. The host-side configuration owns the maximum allowed values. If there is no trusted host configuration, required cgroup isolation is unavailable.

## Lifecycle and failure handling

- Set and verify limits before the bootstrap is launched.
- Treat bootstrap attach failure as a launch failure; Bubblewrap must not be spawned in that case.
- Keep the cgroup alive until all descendants are gone.
- On termination, write `1` to `cgroup.kill`, then wait for `cgroup.events` to show `populated 0` with a bounded cleanup deadline.
- Do not remove a non-empty cgroup. If cleanup cannot prove the cgroup is empty, return a distinct cleanup/isolation failure and retain enough diagnostics for an operator to recover safely.
- Handle races among normal exit, timeout, abort, output-limit termination, and spawn errors with a single idempotent teardown state machine.
- Do not resolve the provider result as successful until teardown has completed and the child cgroup has been removed.
- Ensure a failed setup cleans up an empty child cgroup without ever launching the provider.
- Do not rely on process groups for descendant cleanup: Bubblewrap’s session behavior can separate process groups, while cgroup membership remains the authoritative grouping.

## Required test plan

### Deterministic unit tests

Use an injected cgroup filesystem adapter or a narrowly scoped internal abstraction to test:

- cgroup2 detection and rejection of cgroup v1 / ordinary filesystems;
- missing controllers, missing control files, missing delegation, unsafe parent permissions, symlinks, traversal and malformed paths;
- exact limit serialization and read-back mismatch;
- bootstrap attach failure preventing Bubblewrap launch;
- bounded config parsing and rejection of malformed/oversized bootstrap input;
- idempotent cleanup across timeout, abort, output overflow, spawn error and normal exit;
- cleanup refusal when `populated` remains non-zero;
- no writes to parent `cgroup.subtree_control` or parent resource files.

Fake filesystem tests prove validation logic only; they do not prove kernel enforcement.

### Linux integration tests

A dedicated Linux test environment must provide a real delegated cgroup v2 subtree with `cpu`, `memory`, and `pids` controllers enabled and `cgroup.kill` available. The test must prove, using real kernel state, that:

- bootstrap is in the run cgroup before Bubblewrap/provider code begins;
- a provider-created child remains in the same cgroup;
- `pids.max` prevents task creation beyond the configured ceiling;
- `memory.max` is enforced (with the expected cgroup OOM behavior);
- `cpu.max` produces bounded CPU bandwidth as reflected by `cpu.stat`;
- cancellation/timeout kills all descendants and the cgroup reaches `populated 0`;
- the run cgroup is removed after successful cleanup.

The integration job must not silently skip when the security gate is expected to run. If the standard hosted runner cannot supply a delegated subtree, add a dedicated self-hosted/VM test environment or a reproducible privileged harness before claiming the feature is validated. A skipped integration test is not evidence of enforcement.

## Rollout and documentation rules

Implement as a separate follow-up after the Linux Bubblewrap stack is merged in dependency order. Keep this research document distinct from implementation status. Update provider docs, CLI/API docs, threat-model notes, and CI only when the behavior exists and the real-kernel integration gate is available.

Until then, ORIX must continue to describe its current Linux provider backend as Bubblewrap namespace/filesystem isolation with bounded process execution—not as CPU, memory, or process-count isolated.
