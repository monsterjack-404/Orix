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
14c4902a89e369cde661fae61a1779b0f1b0a8cb01e41c69c9210feeab674a34
```

The source-pinned gzip SHA-256 is:

```text
d0667d4c4f5702e2aab6f02d11094f955f8b6de7a379d4ce089065c5600d28db
```

Both independent Windows CI runners built the launcher from the exact PR head. Their fresh executables were byte-for-byte identical and passed the PE/CLR metadata and IL-only AnyCPU checks. The exact matching binary was then packaged and its compressed and uncompressed hashes checked. This artifact's GitHub Actions provenance is a CI build result, not a publisher signature.

CI also checks that `npm pack --dry-run --json` contains both the integrity module and the compressed launcher. The Windows hostile-process smoke test runs through the actual runtime path using the packaged executable, rather than treating a compiler-success step as proof of isolation.

## Security limits

- The checksum is a source-pinned integrity control, not a cryptographic publisher signature. A malicious change that alters both the payload and trusted source digest in the same reviewed branch could replace the trust anchor.
- It does not defend against a compromised repository, compromised build/release system, privileged local administrator, kernel vulnerability or malicious Windows security service.
- Hosted Windows runner images and package feeds are not fully hermetic. Double builds and cross-runner reproducibility detect many sources of drift but do not prove reproducible builds in every environment.
- The launcher is managed .NET Framework 4.8. Hosts without that runtime cannot use this backend; ORIX fails closed rather than compiling at runtime.
- Keep the PR draft until current exact-head Node, Linux, Windows and macOS checks pass and the native launcher lifecycle remains reviewed.

