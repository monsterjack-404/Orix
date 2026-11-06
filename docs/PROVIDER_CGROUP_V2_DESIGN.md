# Linux cgroup v2 provider resource-isolation design

**Status: implementation is wired in the PR #64 branch (not yet merged).** The Linux `isolation: 'required'` path now creates a per-run cgroup v2 leaf, applies and reads back fixed host policy limits, launches the descriptor-attaching bootstrap, and removes the leaf only after the kernel reports it empty. The real-kernel CI gate exercises the implementation on its Ubuntu Linux runner. This branch-level status is not a claim that the feature is available from the current `main` release, nor that every Linux distribution/kernel has been certified.

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

PR #64 currently uses a fixed host-owned policy in `LINUX_PROVIDER_CGROUP_LIMITS`; neither provider manifests nor individual requests can raise or override it. The enforced cgroup values are:

- `cpu.max = 50000 100000` (50% of one CPU's bandwidth; not a total CPU-time budget).
- `memory.max = 536870912` (512 MiB).
- `memory.swap.max = 0`.
- `memory.oom.group = 1` (an OOM event kills the whole provider leaf group).
- `pids.max = 64` (Linux tasks, including threads).

The Bubblewrap launch also applies per-process `RLIMIT_CPU=60s`, `RLIMIT_FSIZE=64 MiB`, `RLIMIT_NOFILE=256`, and `RLIMIT_CORE=0`. Wall-clock timeout and captured-output limits remain separate runner controls. The fixed limits are conservative implementation policy, not host auto-detection; changing them requires a reviewed code/policy change.

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

`run_static_provider()` is now wired to the cgroup lifecycle for Linux `isolation: 'required'`:

- The host creates/configures a leaf and launches the package-owned bootstrap with only the write-only `cgroup.procs` descriptor at child FD 3. The bootstrap writes its own PID, closes FD 3, then launches the absolute `prlimit` command and Bubblewrap with `shell: false` and a minimal environment.
- The provider never receives the attach descriptor or the delegated parent path. Provider arguments remain bounded and are passed as literal argv values.
- On timeout, AbortSignal cancellation, or output overflow, the runner first terminates/verifies the bootstrap's original POSIX process group. This closes the window in which a bootstrap that has not yet attached could join after an empty cgroup was removed. It then uses `cgroup.kill` as the authoritative whole-leaf cleanup and waits for `cgroup.events` to report `populated 0`.
- On normal completion and launch failure, it also runs idempotent cgroup cleanup. A result is not successful unless process-group and isolation teardown complete; cleanup failures have explicit unsuccessful termination diagnostics.
- Process groups are a pre-attach race guard, not the descendant-security boundary. Bubblewrap can create a separate session; the cgroup leaf remains authoritative for all attached descendants.
- The default remains `isolation: 'none'`. Windows and macOS have no enforced backend and fail closed when required isolation is requested.

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

The PR #64 CI job requires a privileged Linux runner with a real cgroup v2 filesystem, `cpu`, `memory`, and `pids` controllers, and `cgroup.kill`. The integration harness creates a unique temporary parent/supervisor layout on that runner, enables the controllers only for the test setup, and removes its hierarchy during teardown. The runtime cgroup manager itself does not enable parent controllers or write parent resource limits. The test proves, using real kernel state, that:

- bootstrap is in the run cgroup before Bubblewrap/provider code begins;
- a provider-created child remains in the same cgroup;
- `pids.max` prevents task creation beyond the configured ceiling;
- `memory.max` is enforced (with the expected cgroup OOM behavior);
- `cpu.max` produces bounded CPU bandwidth as reflected by `cpu.stat`;
- cancellation/timeout kills all descendants and the cgroup reaches `populated 0`;
- the run cgroup is removed after successful cleanup.

The integration job must not silently skip when the security gate is expected to run. The current workflow invokes the harness with `sudo`; missing controllers, unavailable `cgroup.kill`, or failed setup are hard failures. This proves behavior on the exact CI kernel/runner image only; it is not cross-distribution or cross-kernel certification. Deployments must run the read-only preflight and validate their own delegated hierarchy.

## Rollout and documentation rules

Keep the feature opt-in and merge its stacked dependencies in order. The implementation in this branch must not be described as generally available until the PR chain is reviewed and merged. The provider API remains process-controlled but unsandboxed by default; only Linux calls that explicitly request `isolation: 'required'`, supply a trusted rootfs, and satisfy `ORIX_CGROUP_PARENT` can use this backend. No cgroup enforcement is claimed for `isolation: 'none'`, Windows, or macOS.

The delegated parent and its `supervisor/` child must be owned by the ORIX service effective UID and must not be group- or other-writable. The read-only preflight reports and enforces these conservative ownership/mode-bit checks, and also confirms that `cgroup.events` is readable and `cgroup.kill` is writable. This is not a full host trust proof: operators still control delegation, account membership, mount configuration, and any external policy beyond the mode-bit checks.

## Read-only deployment preflight (diagnostic only)

The follow-up `scripts/linux-cgroup-v2-preflight.mjs` command inspects the host's unified cgroup v2 mount, current process membership, and an optional administrator-configured `ORIX_CGROUP_PARENT`. It reports whether the expected empty-parent / sibling-supervisor layout and required controllers appear to be present.

The command is intentionally read-only: it does not create a child cgroup, move a process, enable controllers, change limits, or claim that kernel enforcement has been proven. It is suitable for CI environment discovery and operator diagnostics. A positive result is a deployment precondition, not a substitute for the real-kernel enforcement tests below.


## Integrated trusted bootstrap descriptor handoff

The integrated helper in \`src/providers/linux-cgroup-v2-bootstrap.mjs\` consumes only child descriptor 3, writes the bootstrap PID, closes that descriptor before launching the already-prepared absolute command, and never accepts a cgroup path or controller-management capability. Its argument vector is bounded and NUL-free; command launch uses \`shell: false\`.

The Node child-process tests in \`tests/linux-cgroup-v2-bootstrap.test.mjs\` use ordinary temporary files as stand-ins for \`cgroup.procs\` to check descriptor handoff, attach-before-provider order, descriptor non-inheritance, and attach failure. These tests run in the Node 20/22/24 matrix. The privileged \`scripts/linux-cgroup-v2-integration.mjs\` additionally exercises actual cgroup v2 membership, CPU/memory/task limits, OOM group behavior, process cleanup, cancellation, timeout, and leaf removal on the CI Linux kernel.

**Validation boundary:** the integration gate validates the current hosted Ubuntu kernel only. Deterministic fake-filesystem coverage for every setup/rollback/cleanup failure mode and validation on other supported Linux distributions/kernels remain further hardening tasks. The backend remains opt-in and does not certify arbitrary host delegation setups.
