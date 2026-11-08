# Windows native-helper bootstrap trust

## Decision

The runtime-compiled Windows AppContainer launcher previously located .NET Framework `csc.exe` using host environment values. Even with path checks, runtime compiler discovery adds an unnecessary dependency on host toolchain provenance.

The runtime now consumes a prebuilt, package-owned .NET Framework 4.8 AnyCPU launcher. The exact executable is source-pinned by SHA-256 in `src/providers/windows-launcher-integrity.mjs`; its compressed package payload has a separate pinned SHA-256.

## Runtime trust

The reviewed package payload is stored as four bounded base64 segments under `native/bin/win32-anycpu/launcher-payload-01.b64` through `launcher-payload-04.b64`. Runtime assembles the segments in a fixed order, requires canonical base64, then verifies the compressed bytes and executable digest. Runtime:
1. Opens each fixed payload segment through a handle and checks the opened object against the path entry; symlinks, non-regular files, oversized segments and concurrent file changes fail closed.
2. Assembles the four ASCII segments in a fixed order, rejects invalid/non-canonical base64 and enforces the compressed-size limit.
3. Verifies the compressed SHA-256 before bounded gzip decompression.
4. Verifies the exact executable SHA-256 after decompression.
5. Stages the verified bytes into a fresh per-invocation temporary directory, makes the launcher read/execute-only, then reads and hashes the staged executable again before spawn.
6. Fails closed with `ORIX_PROVIDER_ISOLATION_UNAVAILABLE` if any step is missing, malformed, oversized, replaced or unverified.

Runtime no longer discovers a compiler, invokes `csc.exe`, or compiles C# source. A Windows host still needs .NET Framework 4.8 to execute the managed launcher; it does not need the compiler or SDK at provider-launch time.

## Reviewed build identity

The source-pinned executable SHA-256 is:

```text
9dfbf55f31e9ff2e215da31153afc74a4117ec96af47ab5de56fc0daeae5ec31
```

The source-pinned gzip SHA-256 is:

```text
d1e783190ba3f69a867a6a2d622c44ca616e18cd091205c6964b2820fe5fdc61
```

Both independent Windows CI runners built the launcher from the exact PR head. Their fresh executables were byte-for-byte identical and passed the PE/CLR metadata and IL-only AnyCPU checks. The exact matching binary was then packaged and its compressed and uncompressed hashes checked. The launcher creates a fresh hidden console (`CREATE_NEW_CONSOLE`, `SW_HIDE`) while leaving `STARTUPINFO.lpDesktop` null. ORIX does not select or create a private desktop/window station; Windows uses the caller's desktop context. The provider remains suspended until Job Object assignment and AppContainer verification complete. This artifact's GitHub Actions provenance is a CI build result, not a publisher signature.

CI also checks that `npm pack --dry-run --json` contains the integrity module and all four payload segments. The Windows hostile-process smoke test runs through the actual runtime path using the packaged executable, rather than treating a compiler-success step as proof of isolation.

## Rootfs path and ACL trust

Before creating the AppContainer, the native helper checks the rootfs and each existing ancestor for reparse points and trusted ownership. It rejects write-capable grants on the rootfs itself and destructive grants on ancestor directories.

The volume root is not renameable as a path component, but its ACL still matters: an untrusted `DeleteSubdirectoriesAndFiles` (Windows `FILE_DELETE_CHILD`) grant on `C:\\` can delete or replace a child rootfs directory. The helper therefore applies the destructive ancestor mask at the volume root as well, while continuing to tolerate ordinary volume namespace create-file/create-directory grants. It does not skip the volume-root ACL entirely.

## Ancestor traversal ACL behavior

The AppContainer provider must be able to traverse each directory component between the volume root and its private rootfs. The helper first inspects each ancestor DACL for an existing traverse grant to the built-in **ALL APPLICATION PACKAGES** AppContainer group. A sufficient existing grant is preserved and logged; it is not rewritten. Where no sufficient grant exists, the helper adds only a per-profile FILE_TRAVERSE ACE. Applicable deny ACEs are not overridden.

Cleanup removes a per-profile ancestor ACE only when that exact explicit ACE was added by this invocation. Protected ancestors with inherited or group-based traversal grants are left unchanged. Reparse-point ancestors fail closed. This prevents unnecessary WRITE_DAC operations on protected paths such as Program Files, while retaining least-privilege traversal for the provider and a bounded cleanup path.

## Process-tree teardown and cleanup ordering

The native launcher now treats process termination as an operation that must be observed, not merely requested.

Before launch, it sets `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` with `PROCESS_CREATION_CHILD_PROCESS_OVERRIDE` so the provider can spawn required descendants. The launcher is trusted and not itself an AppContainer; the provider's descendants inherit the provider's AppContainer token and remain inside the assigned non-breakaway Job Object. The provider is created with a fresh hidden console (`CREATE_NEW_CONSOLE`, `SW_HIDE`) and `STARTUPINFO.lpDesktop = null`; ORIX does not select a private desktop/window station. The process remains suspended until Job Object assignment and AppContainer verification complete.

- After the provider is assigned to its Job Object, teardown checks whether the job is already signaled; otherwise it calls `TerminateJobObject` and waits up to five seconds for the Job Object to become empty.
- If process creation succeeded but Job Object assignment did not, teardown terminates the direct suspended process and waits for its process handle to become signaled.
- A failed or timed-out wait emits the durable `RUN:TEARDOWN_INCOMPLETE` marker and returns a distinct failure. The native `Main` path skips profile ACL, AppContainer scratch and profile deletion in that case.
- The Node cleanup callback checks the helper log before starting a second cleanup helper. If the marker exists, it fails with `ORIX_PROVIDER_WINDOWS_TEARDOWN_UNVERIFIED` and leaves the staged helper workspace and AppContainer state untouched.

This is deliberately fail-closed. It can leave a profile, ACL entries or temporary state behind when Windows does not confirm that the provider Job Object is empty. That residual state requires operator investigation/recovery; it must not be “fixed” by deleting paths while a provider descendant may still be alive. A Windows integration regression simulates the marker and verifies that the host cleanup path does not launch a second helper or mutate the log/workspace.

## Security limits

- The checksum is a source-pinned integrity control, not a cryptographic publisher signature. A malicious change that alters both the payload and trusted source digest in the same reviewed branch could replace the trust anchor.
- It does not defend against a compromised repository, compromised build/release system, privileged local administrator, kernel vulnerability or malicious Windows security service.
- Hosted Windows runner images and package feeds are not fully hermetic. Double builds and cross-runner reproducibility detect many sources of drift but do not prove reproducible builds in every environment.
- The launcher is managed .NET Framework 4.8. Hosts without that runtime cannot use this backend; ORIX fails closed rather than compiling at runtime.
- Keep the PR draft until current exact-head Node, Linux, Windows and macOS checks pass and the native launcher lifecycle remains reviewed.

## Child-process and Job Object policy

The trusted, non-AppContainer launcher explicitly sets `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` to `PROCESS_CREATION_CHILD_PROCESS_OVERRIDE` when it creates the provider. This allows the provider to create descendants while preserving the AppContainer token and the already-assigned Job Object. The Job Object is not configured with breakaway permissions, so descendants remain subject to the same CPU, memory and active-process limits and are terminated with the job. The Windows integration test verifies that the child starts under the provider, the launcher reports the override policy, and the child stops writing after its provider leader exits.

The override is applied only by the trusted host launcher; it does not remove the provider's AppContainer identity or grant host filesystem/network access. If descendant containment cannot be verified, the integration gate must fail rather than interpreting a blocked child spawn as proof of Job Object cleanup.
