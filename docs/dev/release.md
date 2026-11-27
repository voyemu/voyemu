# Release

A release is one version of the launcher, packed for each host together with the profiles of the same revision. The `release` workflow builds and publishes it from a tag, see [CI](ci.md#the-release-workflow).

## Version

A release sets its version and release date by hand in `src/app/CMakeLists.txt`, the only place that names them: `VOYEMU_VERSION`, such as `1.0.0-beta1` or `1.0.0`, and `VOYEMU_RELEASE_DATE` as `YYYY-MM-DD`. The build takes neither from the commit or the build time. `voyemu --version`, the About panel of the [window](../how/window.md) and the `info` operation of the [Voyemu API](../how/api.md) report the version; About shows the release date in the interface language and `info` returns it as `release_date`. The archive names, the Homebrew formula and the release notes use the same version. The tag of a release is `v` and the same version, such as `v1.0.0-beta1`.

A version with a suffix after `-`, such as `1.0.0-beta1`, is a prerelease: the `release` workflow publishes it as a GitHub prerelease and leaves the Homebrew formula unchanged. A version without a suffix, such as `1.0.0`, is a stable release and also updates the formula. The release notes are the section of the version in `CHANGELOG.md` under the heading `## <version>` or `## <version> — <date>`.

Pushing a stable release tag starts the workflow automatically. For a prerelease, dispatch the workflow on its tag. Set `macos_only` or `windows_only` to publish a single host archive. Leave both unset to publish all hosts.

## Archives

| Host | Archive |
| --- | --- |
| macOS arm64 | `voyemu-<version>-macos-arm64.tar.xz` |
| Linux x64 | `voyemu-<version>-linux-x64.tar.xz` |
| Windows x64 | `voyemu-<version>-windows-x64.zip` |

`SHA256SUMS` next to them lists their SHA-256. Each archive holds one directory, `voyemu-<version>/`:

| Path | Content |
| --- | --- |
| `voyemu` or `voyemu.exe` | The launcher: CLI, supervisor, window and graphics worker |
| `profiles/` | Every profile of the revision of the launcher |
| `notices/` | The Voyemu license, third-party licenses and `dependencies.lock.json` |
| `README.md`, `CHANGELOG.md`, `SECURITY.md`, their Russian versions and `LICENSE` | The texts of the project root |

OEM inputs and images derived from them are never part of a release.

## Installation root

The extracted directory is the installation root: `deps`, `fetch` and `build` create `.local/` and `machines/` in it, see [local roots](../how/local-roots.md). The launcher selects the root from its own location, so commands need no root option. It takes the first of:

1. The directory of the launcher when it holds `profiles/` or `.local/`, as an extracted archive does.
2. The nearest directory above the launcher that holds `profiles/` and `src/app/`, a source checkout.
3. The working directory when it holds `.local/`.
4. On macOS, `~/Library/Application Support/Voyemu`.

## Project files

`deps`, `fetch`, `build` and `check` read the content of a few files of the source tree: the pins of `src/app/toolchain.json` and `src/prepare/`, the QNX guest scripts, screen configuration and MCU layouts of `src/guest/qnx/`, the steering-wheel routes and the splash image. `src/app/project_files.cmake` embeds copies of exactly these files in the launcher at build time; a root with `src/` reads its tree, an installation without `src/` reads the copies. During a session the cluster adapter takes the MCU layouts from the copies in both cases. The Java helper takes the toolchain manifest from its request and the AudioPolicy helper sources from its own JAR.

Without `--jdk`, preparation uses the pinned Java helper and guest Java assets even in a source checkout. An unavailable helper asset stops preparation with `JAVA_HELPER_ASSET_MISSING`; it does not start a source build. In a source checkout, `--jdk PATH` selects the developer recipe, whose cache key includes its actual source inputs, see [Java helper CI](ci.md#the-java-helper-workflow). Prepared machines keep checksums of their embedded files, not compatibility checks against the current authoring sources. Preparation still detects changes to inputs during the operation and verifies external pins and output artifacts. Recipes that build CI assets from source run in a source checkout.

## Building the archives

```sh
cmake --install .local/build/native --component Runtime --prefix "$PWD/.local/build/stage"
src/dev/release/archive.sh 1.0.0-beta1 linux-x64 .local/build/stage .local/build/release
```

The `Runtime` install component of CMake holds the launcher, `notices/` and the window artwork of `profiles/common/`. `archive.sh VERSION HOST STAGE OUTPUT` takes the launcher and `notices/` from it, adds the tracked files of `profiles/` and the root texts and writes the archive of `HOST` with its `.sha256` file to `OUTPUT`. Entries are sorted, directories have mode 755, files 644 and the launcher 755, owner and group are 0, and every time is 00:00 UTC of `VOYEMU_RELEASE_DATE` in the HEAD commit, or `SOURCE_DATE_EPOCH` when it is set, so a rerun writes the same bytes. The script runs on Linux with git, GNU tar and xz; the Windows zip needs the `jar` tool of the pinned JDK in `JAR`. The CTest `release_archive` builds the Linux and Windows archives twice, compares them, checks their layout and runs the extracted Linux launcher without `src/`.

## Homebrew

On macOS arm64 and Linux x64, `brew install voyemu/tap/voyemu` installs the archive of the host from the latest stable release. The formula is `Formula/voyemu.rb` of the `voyemu/homebrew-tap` repository; `src/dev/release/homebrew/voyemu.rb.in` is its template, and `src/dev/release/homebrew.sh VERSION REPOSITORY SHA256SUMS OUTPUT` fills in the version, the archive URLs and their SHA-256. The formula keeps the launcher and `profiles/` in the keg and copies both to `var/voyemu` of the Homebrew prefix after every installation; `bin/voyemu` links that copy, so `var/voyemu` is the installation root and its `.local/` and `machines/` outlive upgrades. The test of the formula runs `voyemu --version`.

## Release assets

Development kernels and the other CI-built inputs of preparation are published as GitHub release assets under their own tags by their workflows, see [CI](ci.md).
