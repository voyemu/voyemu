# Why this way

This section records Voyemu's design decisions. Each page is a record of one choice: which alternatives were considered, why one of them won and what it costs.

A record is needed when the decision is not obvious and its rationale will matter later. An obvious choice does not belong here.

Every record follows the same template: **Decision → Context → Alternatives → Argument → Consequences**.

## Build and code

- [C++ for the host](cpp.md) — C++20 on the host and C11 in the QNX guest instead of Rust
- [Zig toolchain](zig-toolchain.md) — Zig and MinGW-w64 instead of MSVC and Xcode
- [Ninja only](ninja-only.md) — one CMake generator on every host
- [Release only](release-only.md) — no debug builds, diagnosis from logs
- [Size-optimized Release](size-optimized-release.md) — `-Os` for the launcher, `-O2` for the per-frame path of the window
- [Single implementation](single-implementation.md) — shared C++ with thin host backends
- [Linux x64 as a host](linux-target.md) — Linux as a host with the system TLS and cryptography
- [SDL3 window](sdl3-window.md) — one window on static SDL3 and Dear ImGui
- [Host video decoders](host-video-decoders.md) — the OEM startup videos decode with the decoder of the host operating system
- [Own LZO1X packer](lzo-packer.md) — the QNX boot stream packs with Voyemu's own code and unpacks with lzokay, without the GPL liblzo2
- [Java preparation](java-preparation.md) — APK and DEX work in Java without a user JDK
- [No Python](no-python.md) — CMake, C++, Java and shell only
- [Tests check behavior](behavior-tests.md) — no source-text or file-hash tests

## Inputs and storage

- [Pins for external inputs](pins.md) — exact version, URL and SHA-256 for every download
- [Development kernels built in CI](guest-kernels.md) — CI-built kernels with the CAN driver instead of the standard emulator kernel
- [Profiles as sources, machines as results](profiles-machines.md) — direct profile reads, self-contained machines
- [Four `.local` roots](local-roots.md) — one rule per kind of local data

## Runtime and API

- [Embedded ADB](embedded-adb.md) — the session's own ADB transport instead of a shared server
- [Voyemu API through `voyemu test`](api.md) — one JSON request per process, no network service
- [Error codes and the unknown outcome](error-codes.md) — the `_UNKNOWN` suffix decides the outcome
- [Audio output without a host](audio-output.md) — the `none` driver keeps the guest sound device when the host cannot play
