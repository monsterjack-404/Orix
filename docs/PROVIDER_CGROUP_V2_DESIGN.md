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

## Required delegated hierarchy layout

The delegated parent must be an **empty inner cgroup** when domain controllers are enabled for its children. Linux cgroup v2 enforces the no-internal-process constraint: a non-root domain cgroup cannot distribute domain resources to children while it still contains processes of its own. Therefore, ORIX must not leave its long-lived supervisor process in the delegated parent and then create provider children underneath it.

The administrator-provisioned layout must place the ORIX manager and provider runs in sibling cgroups:

```text
<delegated-parent>/        # empty; cpu, memory and pids already enabled
├── supervisor/            # long-lived ORIX host process(es)
├── provider-<run-id>/     # one leaf cgroup per provider execution
└── provider-<run-id>/     # another independent leaf
```

Requirements:

- The parent is a dedicated, administrator-delegated subtree, not an arbitrary systemd-managed cgroup or the cgroup filesystem root.
- Before child resource controllers are enabled, the manager must be moved to an administrator-provisioned `supervisor/` child. The parent must have no direct processes.
- The administrator enables `cpu`, `memory` and `pids` for the parent’s children before ORIX starts. ORIX verifies the exact controller state; it does not modify parent `cgroup.subtree_control` or parent resource limits at runtime.
- ORIX is the single writer for its delegated subtree while running. Multiple independent ORIX managers must not concurrently manage the same subtree.
- The host manager must verify the parent is empty and that the expected sibling layout and ownership/permissions are valid. If not, required isolation fails closed.
- Each provider run is a leaf cgroup. The trusted bootstrap process is moved from `supervisor/` into that leaf before Bubblewrap is spawned; all later descendants inherit the leaf membership.
- The provider-visible rootfs must not expose the host cgroup hierarchy or the delegated parent.

This layout follows the kernel’s no-internal-process constraint and systemd’s delegation guidance. See the [Linux kernel cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#no-internal-process-constraint) and [systemd cgroup delegation guidance](https://github.com/systemd/systemd/blob/main/docs/CGROUP_DELEGATION.md).

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

### Descriptor-anchored filesystem access and bootstrap handoff

The implementation should avoid reopening attacker-influenced absolute paths after validation. A Node-only implementation candidate is to retain directory FileHandles and perform each next-component operation through /proc/self/fd/<dirfd>/<single-component>, opening every directory with O_DIRECTORY | O_NOFOLLOW. Components must be validated as single names (no slash, dot, dot-dot, NUL or empty value); never append a multi-component relative path to the descriptor path. Control files must likewise be opened with O_NOFOLLOW relative to the retained cgroup directory handle. If procfs descriptor paths are unavailable or their semantics cannot be verified on the target host, fail closed. This is not a substitute for administrator-owned, non-writable-by-untrusted-users delegation, and it must be tested on the actual cgroup2 filesystem before being treated as a security guarantee.

For the bootstrap attach step, prefer descriptor passing over giving the helper a cgroup path:

1. The trusted host manager opens the new leaf's cgroup.procs for writing and passes that already-open descriptor as a dedicated extra stdio descriptor to the trusted bootstrap process.
2. The bootstrap writes only its own PID to that descriptor as its first operation. It must treat a short/failed write as fatal and must not spawn Bubblewrap unless the attach operation succeeds.
3. The bootstrap closes the inherited cgroup descriptor before spawning Bubblewrap. The provider and Bubblewrap must never inherit it.
4. The host closes its copy after the bootstrap spawn handoff; on spawn failure, the host closes it and removes only the still-empty leaf.
5. Tests must prove the bootstrap is a member of the leaf before provider code begins, the provider cannot access the attach descriptor, and attach failure prevents any Bubblewrap/provider spawn.

This narrows the bootstrap's authority: it receives one write-only capability to attach itself, not the delegated parent path, directory handles, controller files, or a general-purpose cgroup-management API. Verify descriptor inheritance and closure on every supported Node.js version before relying on it.

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

## Existing process-runner lifecycle constraints

The current `run_static_provider()` implementation directly spawns the prepared executable, owns stdout/stderr capture, starts a wall-clock timer, and settles its result from child-process `close`. Timeout, abort and output overflow currently signal the POSIX process group (or the direct child on Windows). A cgroup-backed implementation must change this lifecycle rather than bolting a PID move onto the existing spawn call.

Required integration behavior:

- Spawn only the trusted bootstrap helper as the initial child. The provider executable is passed to it as validated, bounded host-generated configuration; the helper must join the run cgroup before launching Bubblewrap.
- Keep the existing argument, environment, wall-clock and captured-output validation. The bootstrap must not inherit provider-controlled environment values or execute a shell.
- Route timeout, abort, output overflow, bootstrap failure, child spawn error and normal child completion through one idempotent finalization path.
- On every terminal path, kill any remaining tasks in the run cgroup, wait for `cgroup.events` to report `populated 0`, and remove the run cgroup only after emptiness is proven. Normal provider exit also requires this check because descendants may outlive the first process.
- Do not settle a successful result on the initial child `close` event alone. A descendant may retain inherited stdout/stderr descriptors, and the cgroup’s populated state is the authority for process cleanup.
- Preserve separate diagnostics for provider exit status, termination reason and cgroup cleanup failure. Cleanup failure must never be reported as successful provider execution.

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

## Read-only deployment preflight (diagnostic only)

The follow-up `scripts/linux-cgroup-v2-preflight.mjs` command inspects the host's unified cgroup v2 mount, current process membership, and an optional administrator-configured `ORIX_CGROUP_PARENT`. It reports whether the expected empty-parent / sibling-supervisor layout and required controllers appear to be present.

The command is intentionally read-only: it does not create a child cgroup, move a process, enable controllers, change limits, or claim that kernel enforcement has been proven. It is suitable for CI environment discovery and operator diagnostics. A positive result is a deployment precondition, not a substitute for the real-kernel enforcement tests below.
