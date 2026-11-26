# Linux x64 as a host

## Decision

Linux x64 is a host like macOS on Apple Silicon and Windows x64. The launcher targets glibc 2.34 and takes TLS and cryptography from the system: it loads libcurl (`libcurl.so.4`) for downloads and OpenSSL 3 libcrypto (`libcrypto.so.3`) for APK signing.

## Context

Many developers and CI runners work on Linux. RHEL 9, Ubuntu 22.04 and Debian 12 ship glibc 2.34 or newer together with libcurl and OpenSSL 3. The pinned Android Emulator on Linux x64 requires an x86_64 Android system image for Passion multimedia. The [Passion `x86` target](../profiles/passion-11-russian-20260403-2.1.4.80.md#x86-target) uses that ABI with hardware acceleration and the host GPU.

## Alternatives

**Linux only as a build and test target.** The shared code would compile and pass its tests on Linux, but Linux users could not prepare or run machines.

**A pinned TLS library linked into the launcher.** Voyemu would carry and update its own TLS code and would not follow the system certificate store.

## Argument

The [single implementation](single-implementation.md) keeps host code in thin `os/` backends, so Linux adds backends instead of branches in shared code. The system libraries keep a stable ABI under their file names and get security updates from the distribution, so loading them at run time keeps the launcher small and its TLS current. The same Linux runner runs clang-tidy over the shared code and cross-builds the Windows executable with the [Zig toolchain](zig-toolchain.md).

## Consequences

Linux has its own `os/` backends; `curl_linux` and `rsa_linux` load the system libraries. The QNX engine runs the cluster with single-thread TCG and the clock of the Windows engine and keeps the guest RAM in a shared file, as on macOS; it is QEMU from the `linux_x64` recipe of `src/app/qnx-host.json`. The graphics worker runs ANGLE of the pinned Emulator on its Vulkan backend, which renders through the Vulkan driver of the system with or without a display server. The window opens on X11 or Wayland through SDL3, which loads the X11, Wayland, xkbcommon and libdecor libraries of the system. A missing system library stops `deps` or `build` with `DOWNLOAD_LIBRARY` or `APK_CRYPTO_LIBRARY` naming it; see [deps](../how/preparation.md#deps). [Build](../dev/build.md) gives the toolchain files and the glibc baseline.
