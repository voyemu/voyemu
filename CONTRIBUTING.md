# Contributing

English | [Русский](CONTRIBUTING.ru.md)

Voyemu accepts fixes, profile adaptations and documentation. OEM firmware files, prepared machine disks and downloads without a pin are not accepted. The complete working rules are in [AGENTS.md](AGENTS.md); report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Build

Voyemu builds with the pinned Zig toolchain of its host, as described in [build](docs/dev/build.md). Zig, CMake and Ninja come from `optionalTools` in `src/app/toolchain.json`, each archive checked by its SHA-256. Each toolchain needs a fresh build directory.

| Host | Toolchain file |
| --- | --- |
| macOS arm64 | `src/dev/toolchains/zig-macos-arm64.cmake` |
| Windows x64, natively or cross-built on Linux | `src/dev/toolchains/zig-windows-x64.cmake` |
| Linux x64, build and tests | `src/dev/toolchains/zig-linux-x64.cmake` |

On Linux, build and run the host tests with the following commands.

```sh
cmake -S src/app -B .local/build/linux -G Ninja -DCMAKE_TOOLCHAIN_FILE="$PWD/src/dev/toolchains/zig-linux-x64.cmake" -DBUILD_TESTING=ON
cmake --build .local/build/linux --parallel 2
ctest --test-dir .local/build/linux --output-on-failure
```

## Checks before commit

Enable the repository hook once per clone. It checks staged whitespace, source formatting and Checkstyle using the pinned tools. It reads the staged bytes without changing the index or working files.

```sh
git config --local core.hooksPath src/dev/git-hooks
```

Run `lint-fix` before every commit: it applies the automatic fixes of clang-format, google-java-format and clang-tidy, then runs `lint`, the same checks as CI. Fix every remaining finding; suppress a finding only with a comment that gives the reason. Run it in a worktree containing only your changes because it formats the whole tree. Each check needs its pinned tools from `optionalTools` in `src/app/toolchain.json`; see [checks](docs/dev/checks.md).

```sh
cmake --build .local/build/linux --target lint-fix
```

## Tests

- Keep C++ tests next to their code as `*.test.cpp`; Java tests live under `src/prepare/test`.
- Tests check behavior: they never read source files or pin hashes of repository files; see [tests check behavior](docs/why/behavior-tests.md).
- Reproduce a bug with a failing test before fixing it when practical.
- Register every test with `voyemu_add_test` and its labels and timeout; tests that need OEM inputs or real graphics exit with the skip code 77 when their pinned inputs are absent; see [tests](docs/dev/tests.md).
- Host tests do not replace guest acceptance; a change names the guest scenarios checked and the host they were checked on.

## Pins

Use exact dependency versions, the latest release unless a reason is recorded. Pin every download by URL and SHA-256 in `toolchain.json`, `qnx-host.json`, `dependencies.lock.json` or `component.json`, and Android images and device imports in `profile.json`. Do not pin files of the repository itself; see [pins for external inputs](docs/why/pins.md).

## Code

- Do not add Python files or Python tooling; see [no Python](docs/why/no-python.md).
- Follow the existing architecture, naming and style; end every text file with exactly one LF.
- Keep one implementation for all hosts and put host differences into `src/app/os/` backends; see [single implementation](docs/why/single-implementation.md).
- Report failures as `VoyemuError("CODE", "message")`; see [error codes](docs/why/error-codes.md).

## Documentation

[docs/](docs/index.md) is canonical. Every docs page and the root README, CONTRIBUTING, SECURITY and CHANGELOG are pairs `X.md`/`X.ru.md`; edit both by meaning. Use the terms of the [glossary](docs/GLOSSARY.md), make every docs page reachable by links from [docs/index.md](docs/index.md) in reading order, the order in which the Voyemu website publishes the pages, and make `java src/dev/checks/CheckDocs.java .` pass.

## Pull requests

Merging a pull request or pushing directly to `main` requires a successful `Lint (Linux x64, Zig)` check from GitHub Actions on the change. For a direct push, first run the `ci` workflow on a branch with the same commit.

One pull request serves one purpose. Its description names the checks run, the checks skipped and why. OEM files, machine disks, tokens and other secrets are never attached.
