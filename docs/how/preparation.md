# Preparation

Preparation turns a [profile](profiles-machines.md) and its OEM inputs into a machine in three commands: `deps` installs pinned tools, `fetch` imports and verifies OEM inputs, and `build` prepares the machine. Each step checks the [pins](../why/pins.md) of what it uses and stops on a mismatch.

```sh
./voyemu deps free-09-chinese-20260106-6.0.3
./voyemu fetch free-09-chinese-20260106-6.0.3 --source=path/to/update.zip
./voyemu build free-09-chinese-20260106-6.0.3
```

Run the launcher from the installation root; on Windows the launcher is `voyemu.exe`. The installation root holds the launcher and `profiles/`; the default preparation path needs no `src/`, see [release](../dev/release.md#project-files). The launcher comes from a release archive or is built from source in the project root, see [build](../dev/build.md). Preparation of a QNX machine needs a launcher built with the graphics worker; the release archives have it.

A file or directory path in an option, such as `--source=update.zip`, may be relative to the current directory or start with `~/` for the home directory; symbolic links in it are followed. Voyemu turns such a path into an absolute one before use.

A guest whose ABI is that of the host processor runs with hardware acceleration. For a [build target](profiles-machines.md#build-targets) that requires it, the pinned emulator confirms the acceleration before `build` and `start` boot the guest; without it they stop with `ANDROID_ACCELERATION`. For host GPU rendering, use a hardware-accelerated graphical session with access to the GPU render device.

## deps

`deps [PROFILE]` installs the pinned host tools into `.local/toolchains/`: the Android Emulator, Platform Tools, Build Tools, the SDK CMake and Ninja, and the QEMU engine for QNX. With a profile it also prepares that profile's Android base when the profile needs one. `deps` also installs the Android platform JARs and the Java tools of preparation, which CI builds and publishes: a minimal Java runtime of the host, the Java helper and the guest Java code of the profiles, see [CI](../dev/ci.md). No JDK is needed; [Java preparation](../why/java-preparation.md) explains why. By default the pinned helper asset is used even in a source checkout. If it is unavailable, preparation stops with `JAVA_HELPER_ASSET_MISSING`; developers can explicitly select the source recipe with `--jdk`, see [Java helper CI](../dev/ci.md#the-java-helper-workflow).

Downloads go over the host's HTTPS stack and certificate store: WinHTTP on Windows, libcurl on macOS and Linux. On Linux Voyemu carries no TLS or cryptography of its own: it loads the system libcurl (`libcurl.so.4`) for downloads and OpenSSL 3 (`libcrypto.so.3`) for APK signing in `build`, and stops with `DOWNLOAD_LIBRARY` or `APK_CRYPTO_LIBRARY` naming the missing library. When a server answers HTTP 429 or 503, Voyemu repeats the request after its `Retry-After` delay (at most five minutes) or after a backoff from 2 to 64 seconds, up to seven attempts; files already downloaded stay in the cache, so a repeated command continues where it stopped.

On stderr each command names every download with its size and source host, shows the bytes received, percent, rate and remaining time, and reports each extraction and each step that was already installed. A terminal shows one status line updated in place; other output gets a status line at each further 10% or after 30 seconds without one. An empty line separates each download and each step, and sizes, rates and times follow the language of the command output. A transfer fails after 60 seconds without a received byte, however long it runs in all. A failed download says whether the host could not be reached, the transfer stalled, the server answered an HTTP status or the file differs from its pin; `--offline` without a cached file names that file. `deps` and `fetch` need the size of each download or extraction plus 2 GiB free on the volume of the installation root, and `build` keeps 20 GiB free for machine preparation. When space is short, the error names the free and required space in whole GiB, how much to free and the installation root, which can also move to another disk, see [installation root](../dev/release.md#installation-root).

`build` checks the cold boot of each prepared guest without a time limit: it waits for the first cluster frame and for the Android boot, reports the elapsed time once a minute and stops with an error when the guest process exits.

The records of each command, including those of the cold boot check, go to its [command log](logs.md#command-log), whose path a failed or interrupted command prints; `--verbose` also shows them on stderr.

`deps` installs the QNX engine from its pinned CI-built asset, see [the qnx-host workflow](../dev/ci.md#the-qnx-host-workflow). While a `prebuilt` pin is pending, `deps` on macOS and Linux builds the engine from its recipe: on macOS with Clang and `/usr/bin/python3` 3.9 or newer from the Command Line Tools, which `xcode-select --install` installs, and the Ninja of the SDK CMake package; on Linux with the pinned Zig, `/usr/bin/python3` 3.9 or newer, `/usr/bin/make` and the Ninja of the SDK CMake package. On Windows it takes only a verified ready-to-run engine of its local cache and otherwise reports the engine unavailable, and machines run without the cluster. An installed engine of the same recipe is reused. On Windows `build` formats the cache image of a machine with `mke2fs.exe` and `mke2fs.conf` of Platform Tools, and the prepared machine carries the formatted `cache.img`.

`--jdk PATH` runs preparation on a JDK 25 or newer instead of the Java runtime and can compile guest Java code from the profile. In a source checkout it also selects the developer recipe for the helper; the option is meant for development.

## fetch

`fetch PROFILE` imports or verifies the OEM inputs of a profile in `.local/profiles/<profile>/`.

| Form | Effect |
| --- | --- |
| `fetch PROFILE` | Verifies the inputs already retained for the profile |
| `fetch PROFILE --source=FILE` | Imports a pinned firmware archive from a local path |
| `fetch PROFILE --source=adb --serial SERIAL` | Reads the Android files declared in `original` of `profile.json` from a physical vehicle over authorized ADB; a profile with `status` `incomplete` reads them by `capture.json` |

The archive and the files are checked against the sizes and SHA-256 in the profile before anything is published. Each [profile page](../profiles/index.md) names its input route and OEM file names. The launcher imports an archive itself, and an import from a vehicle uses the pinned SDK `adb`; the capture of an incomplete profile runs on the Java tools that `deps` installs.

For a profile with build targets, `fetch` imports the shared OEM inputs once. `deps PROFILE` uses the default target of the current host, and `build` ensures the dependencies of its selected target.

On stderr `fetch` names the archive and its size and shows the bytes of the archive check, of each Android image it unpacks and of the QNX images, the number of files extracted from each image and the time the import took. A repeated `fetch` checks the archive and the retained originals and reports them as already imported. A missing file or an archive of another size names the expected update and, when the size matches the update of another profile, that profile. The summary ends with the next command, `voyemu build PROFILE`.

## build

`build PROFILE [MACHINE_PATH]` prepares a new machine, `machines/PROFILE` by default. It applies [components and recipes](components.md), builds the guest images, boots the guests for verification and writes `runtime.json` last. A failed verification boot of QNX ends the QEMU and graphics processes that `build` started and removes their RAM and image copies.

For a profile with [build targets](profiles-machines.md#build-targets), `build` selects the target before preparing any inputs and prints the target, Android ABI and machine path. By default it takes the only target whose guest ABI is that of the host processor; `--target=TARGET` selects any declared target and warns that a guest of another ABI runs in software translation. A missing, ambiguous or undeclared target stops preparation with `PROFILE_TARGET` and lists the targets of the profile. The default output is `machines/PROFILE` for the target of the host ABI and `machines/PROFILE-TARGET` for another one; an explicit path takes precedence. A `signed-offline` target builds multimedia only, and only on Linux.

On stderr `build` first names the machine, its subsystems and the free space it needs; without hardware acceleration of the cluster, as under TCG on Windows and Linux, one more line warns that the cold boot of the cluster can take hours. Each phase follows in its own block: the check of tools and OEM inputs, the QNX image build, the cold boot of the cluster, the Android preparation with the number of components, the cold boot of Android, the bytes of the system image and of the machine assembly, and the space freed by removing temporary files. Lines that a phase reports, such as downloads and checks, appear indented below it, and a phase ends with the time it took. The summary names the machine and the time of the whole build and ends with the command that starts it, `voyemu start MACHINE_PATH`; with `--verbose` it also names its `runtime.json`.

The QNX guest images take CI-built binaries: `build` downloads them by their pins, checks that the OEM libraries of the profile export everything they import and, for Free 6.0.3, writes the OEM startup script and `sysmgrtool` into the section the front library reserves for them, as data and without a compiler. See [the qnx-guest workflow](../dev/ci.md#the-qnx-guest-workflow).

The QNX guest shell scripts are installed without comments, indentation, trailing blanks and blank lines, so that each fits the OEM file it replaces; the scripts in the repository keep them. Preparation refuses a guest script with a here-document (`<<`).

For native Android components built by CI, `build` downloads the pinned artifacts and hands them to the Java helper. These components need no local NDK. A library that imports from libraries of the Android image, such as the multi-display library, links with those imports undefined, and `build` checks that the libraries of the image export them. See [the android-native workflow](../dev/ci.md#the-android-native-workflow).

The QNX host image keeps the OEM bytes of every unchanged 64 KiB block of its boot stream; Voyemu packs the changed blocks itself and, on Free 6.0.3, sizes them so that the startup accepts the stream. See [own LZO1X packer](../why/lzo-packer.md).

`--cluster=on|off` and `--multimedia=on|off` select the subsystems; both are on by default, and a profile without `profile-qnx.json` builds only the multimedia. `--cluster=off --multimedia=on` prepares only the multimedia, and a cluster-only build is rejected before preparation. For profiles that support it, `--force` with an Android-only build of an existing stopped machine updates its Android system and keeps the writable disks and an existing cluster.

Without `--force` `build` refuses an existing machine before any work and suggests starting it or deleting its directory; `--force` needs an existing machine. Preparation checks free space before each storage-heavy stage; tools, OEM inputs, intermediate files and writable disks need far more space than the firmware archive alone.

On Linux a target with an offline filesystem recipe builds its Android 11 x86_64 system partitions from a pinned SDK archive. `build` applies the recipe, verifies the result and signs it with a local development key. The first build creates the key in `.local/toolchains/avd-image-tools/`. The SDK archive stays in its cache under its own digest. Before publishing a new machine, `build` boots the signed system twice, observes distinct kernel boot IDs and checks Android Verified Boot, the active dm-verity root and the read-only system mount. Writable user data follows the ordinary preparation path.

Use an independently signed release for a fresh multimedia build with `--target=x86 --signed-android RELEASE --android-public-key FILE --android-public-key-sha256 SHA256`. The SHA-256 is the fingerprint of the public key's DER SubjectPublicKeyInfo. Obtain the original public PEM and the fingerprint through a trusted channel independent of the release. Signed system and vendor disks have no writable overlays.

Profiles using `qg-runtime` keep emulated NVRAM in `/data/user_de/0/com.voyemu/nvram` inside the guest. The first caller atomically creates it from the read-only `/system/etc/nvram` seed; later calls from OEM processes share the same file, which survives a cold boot in the machine's writable Android disk. Clearing the Android app data of `com.voyemu` removes this state, so the next access creates it from the seed again.

## Trust a signed Android machine

On a new Linux installation, register the signing key before running `check` or `start` on a copied signed machine. Use the original public PEM supplied by the builder and the independently obtained fingerprint. The machine's receipt also pins the exact bytes of that PEM.

```sh
./voyemu trust-android-key --android-public-key FILE --android-public-key-sha256 SHA256
```

The command verifies the fingerprint before storing the public key. `check` and `start` verify the signed manifest and boot files against the key trusted by that installation.

## Offline preparation

`--offline` on `deps`, `fetch` and `build` uses only files already in the `.local` roots and fails when a pinned input is missing. Successful preparation does not prove that every OEM application works; that is checked by acceptance on a running machine.
