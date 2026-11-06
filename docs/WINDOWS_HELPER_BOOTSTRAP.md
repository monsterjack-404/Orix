# Windows native-helper bootstrap trust

## Decision

Do not treat the current runtime-compiled Windows AppContainer launcher as fully hardened. The current implementation locates .NET Framework `csc.exe` below `SystemRoot` / `WINDIR` inherited by the Node host. Those values are normally populated by Windows, but they are still process-environment inputs; checking that the compiler is a regular file or that its path is absolute does not establish that the compiler is trusted.

The safe target architecture is a prebuilt, package-owned native launcher. Runtime provider setup must not discover or execute a compiler.

## Required implementation

1. Build `native/windows-provider-launcher.cs` in a dedicated Windows build job using a pinned, known-good .NET Framework compiler/toolchain supplied by the controlled build runner.
2. Produce the launcher as a versioned package artifact at a fixed package-relative path (for example, `native/bin/win32-x64/orix-windows-provider-launcher.exe`). Do not fetch it dynamically at runtime.
3. Record the expected SHA-256 digest in reviewed source metadata. The digest must be changed in the same reviewed commit as the binary. A checksum file shipped beside the executable is insufficient because an attacker able to replace both files could replace the trust anchor too.
4. At runtime, resolve the artifact relative to the installed module, reject symlink/reparse-point path components, require a regular file, hash the bytes with Node's built-in `node:crypto`, and compare against the source-pinned digest before execution.
5. Remove runtime `csc.exe` discovery and compilation completely. A missing, mismatched, unsupported-architecture, or unverifiable helper must fail closed with `ORIX_PROVIDER_ISOLATION_UNAVAILABLE`; never fall back to a compiler found through `PATH`, `SystemRoot`, `WINDIR`, registry values, or the current directory.
6. Make the Windows hostile-process integration job execute the packaged helper, and add negative tests for a modified binary, missing binary, symlink/reparse path, and architecture mismatch.
7. Ensure the package manifest includes the helper for supported Windows architectures and excludes it from unrelated platform packages where practical. Verify the packed package contents in CI, not only the repository checkout.

## Release and validation gates

- Build output must be reproducible for the pinned toolchain, or CI must compare the generated artifact to the reviewed checked-in artifact and fail on drift.
- The exact packaged executable's SHA-256 must match the source-pinned digest.
- Windows CI must exercise the exact packaged executable through AppContainer token, Job Object quota, filesystem, private-temp, network-denial, and cleanup tests.
- A clean install test must prove the helper is present without a local .NET SDK or compiler.
- The runtime must never compile native helper source.

## Current status

This is an architectural blocker, not a completed fix. The repository currently contains the C# source but no verified, package-owned launcher binary or source-pinned digest. The current GitHub file-edit workflow cannot produce and verify a Windows executable by itself. Until the build/package artifact and exact-binary tests exist, keep the Windows isolation PR draft and do not describe the Windows backend as fully hardened or production-ready.

## Explicit non-goals

- Do not substitute a different environment variable, PATH lookup, registry lookup, or PowerShell command for the current compiler lookup; these are not equivalent to a source-pinned executable trust anchor.
- Do not claim that a hash stored only beside the binary authenticates the binary.
- Do not weaken Windows integration tests or silently skip them when the helper is absent.

## Build-pipeline progress

The Windows CI job now compiles this launcher through the checked-in .NET Framework 4.8 project definition and retains the resulting executable as a short-lived Actions artifact for inspection. This is a compile-validation milestone only: the artifact is built from the PR checkout, is not included in the npm package, is not authenticated by a source-pinned digest, and is not used by runtime provider setup. The existing runtime compiler path and its trust limitation therefore remain unchanged.

The Windows CI job now performs two clean, non-incremental builds in the same runner job and requires the resulting executable SHA-256 values to match. This is a useful deterministic-build regression check, but it does not pin the SDK/compiler version, compare independent runners, establish long-term reproducibility, or authenticate the binary for runtime use.

The next acceptance steps are to review the produced binary, establish a reproducible/pinned toolchain and reviewed digest, admit the exact executable into the package, and switch runtime + hostile-process tests to that exact packaged binary. Do not treat the temporary CI artifact or its printed hash as a runtime trust anchor.
