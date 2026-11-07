# Windows native-helper bootstrap trust

## Decision

The runtime-compiled Windows AppContainer launcher previously located .NET Framework `csc.exe` using host environment values. Even with path checks, runtime compiler discovery adds an unnecessary dependency on host toolchain provenance.

The runtime now consumes a prebuilt, package-owned .NET Framework 4.8 AnyCPU launcher. The exact executable is source-pinned by SHA-256 in `src/providers/windows-launcher-integrity.mjs`; its compressed package payload has a separate pinned SHA-256.

## Runtime trust

The reviewed package asset is `native/bin/win32-anycpu/orix-windows-provider-launcher.exe.gz`. Runtime:
1. Uses `lstat` to reject symlinks, non-regular files and oversized input.
2. Opens the file through a handle and checks file identity before and after reading so path replacement during the read fails closed.
3. Verifies the compressed SHA-256 before bounded gzip decompression.
4. Verifies the exact executable SHA-256 after decompression.
5. Stages the verified bytes into a fresh per-invocation temporary directory, makes the launcher read/execute-only, then reads and hashes the staged executable again before spawn.
6. Fails closed with `ORIX_PROVIDER_ISOLATION_UNAVAILABLE` if any step is missing, malformed, oversized, replaced or unverified.

Runtime no longer discovers a compiler, invokes `csc.exe`, or compiles C# source. A Windows host still needs .NET Framework 4.8 to execute the managed launcher; it does not need the compiler or SDK at provider-launch time.

## Reviewed build identity

The source-pinned executable SHA-256 is:

```text
606ee81a79466bfeec08df60ac11517c96f7b1f2fb97f9ef6283a6f72391c69f
```

The source-pinned gzip SHA-256 is:

```text
b30e64c18d5c8c35286812867d3a20157276f80d2c74788de3233ad9a1a2078e
```

Both independent Windows CI runners built the launcher from the exact PR head. Their fresh executables were byte-for-byte identical and passed the PE/CLR metadata and IL-only AnyCPU checks. The exact matching binary was then packaged and its compressed and uncompressed hashes checked. This artifact's GitHub Actions provenance is a CI build result, not a publisher signature.

CI also checks that `npm pack --dry-run --json` contains both the integrity module and the compressed launcher. The Windows hostile-process smoke test runs through the actual runtime path using the packaged executable, rather than treating a compiler-success step as proof of isolation.

## Rootfs path and ACL trust

Before creating the AppContainer, the native helper checks the rootfs and each existing ancestor for reparse points and trusted ownership. It rejects write-capable grants on the rootfs itself and destructive grants on ancestor directories.

The volume root is not renameable as a path component, but its ACL still matters: an untrusted `DeleteSubdirectoriesAndFiles` (Windows `FILE_DELETE_CHILD`) grant on `C:\\` can delete or replace a child rootfs directory. The helper therefore applies the destructive ancestor mask at the volume root as well, while continuing to tolerate ordinary volume namespace create-file/create-directory grants. It does not skip the volume-root ACL entirely.

## Process-tree teardown and cleanup ordering

The native launcher now treats process termination as an operation that must be observed, not merely requested.

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

