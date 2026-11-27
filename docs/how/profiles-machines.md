# Profiles and machines

A profile describes one firmware; a machine is what preparation makes from it. Preparation reads the profile, and launch reads only the machine. The reasons are in [profiles as sources, machines as results](../why/profiles-machines.md).

## Profile

A profile is the authoring directory `profiles/<profile>/`. Its name encodes the vehicle line, the Android generation, the firmware language, the firmware date and its version, for example `free-09-chinese-20260106-6.0.3`. `voyemu list` prints the known profile identifiers; the [published profiles](../profiles/index.md) have their own pages.

| File or directory | Content |
| --- | --- |
| `profile.json` | Android system image pin, emulator settings, displays, OEM inputs with SHA-256, recipes, installed files, guest configuration and checks |
| `capture.json` | Which OEM files an import takes from a physical vehicle |
| `profile-qnx.json` | OEM QNX images, the hardware adapter, storage settings and the OEM inputs taken from another profile; only in profiles with a cluster |
| `components/` | [Components](components.md) of this profile |
| `patches/` | Recipe steps that `profile.json` refers to |
| `files/` | Small own files that preparation installs into the guest |
| `targets/<target>/` | Files used only by a build target, where present |

The `status` field of `profile.json` is `ready` when the multimedia is supported and `incomplete` while the OEM inputs of the profile are still being collected: then `fetch PROFILE --source=adb --serial SERIAL` reads them as `capture.json` lists. The `status` field of `profile-qnx.json` is `incomplete` while the cluster is experimental. The support of each published profile is listed in [profiles](../profiles/index.md).

The `title` field of `profile.json` names the profile in text for people, for example `Free 7.3.1`. `platform` is `qinggan09` or `qinggan11` for the Android 9 or Android 11 generation of the [Free/Dreamer platform](../GLOSSARY.md), or `passion` for Passion. `board` names the multimedia board: `8155` for Qualcomm SA8155 or `nxp` for NXP i.MX 8QuadMax. Voyemu rejects a published profile without these fields or with another value.

The `features` field of `profile.json` turns on optional functions of the firmware. `original_navi` set to `true` installs the OEM navigation app of the firmware together with the recipes it needs; preparation selects them by this field, not by the profile name. `system_upgrade` lets a rebuild of an existing machine replace only its Android system and keep the user data, with the packages the machine delivers. `ui_observer_required` makes every Android machine of the profile carry the observer. `measured_disk_reserve` makes preparation reserve the disk space measured for the pinned system image of the profile instead of the larger default.

The `emulator` field of `profile.json` sets the Android emulator of the machine: `port`, `memory`, `gpuMode` and optionally `cores`. `candidatePort` fixes the port of the emulator that preparation boots to build the machine; without it, preparation takes a free port.

`gpuMode` selects the renderer of the emulator: `host` renders on the host GPU, `auto` and `auto-no-window` let the emulator choose, `swiftshader_indirect` renders in software on the host, and `guest` renders in software inside the guest. The machine records the renderer it was prepared with, and `start` runs it with the same one; `build` and `start` reject any other value. `guest` needs no GPU on the host, so a host without one can prepare and start the machine, but the screens draw and animate much slower than with the host GPU.

## Build targets

A build target prepares one firmware for one guest ABI. The OEM inputs and recipes stay those of the profile; the `targets` field of `profile.json` names each target and declares what differs:

| Field | Meaning |
| --- | --- |
| `guestAbi` | The Android ABI of the guest, `arm64-v8a` or `x86_64` |
| `preparation` | `sdk` for the preparation of the SDK image on its running guest |
| `androidBase` | A pinned Android base in `profiles/common/android-bases/` instead of the `android` base of the profile |
| `developmentKernel` | The [development kernel](components.md#development-kernels) of the target ABI; a target of another ABI than the kernel of the profile declares its own |
| `emulator` | Emulator settings of the target: `memory`, `gpuMode`, and `acceleration` set to `required` for a guest that needs hardware acceleration |

`deps` and `build` take the target whose guest ABI is that of the host processor; `--target` selects any declared target, and a guest of another ABI runs in software translation. The [Passion profile](../profiles/passion-11-russian-20260403-2.1.4.80.md) declares the `arm` and `x86` targets. See [selecting a target](preparation.md#build).

The `wheel` field of `profile.json` names the steering-wheel artwork in `assets` and the Android key routes in `androidRoutes`; `provider` set to `com.voyemu.input.wheel` delivers the wheel to Android through that content provider of the profile instead of the routes.

Shared parts live outside the profiles: `profiles/common/` holds common components, icons and steering-wheel artwork, and `profiles/common-qinggan-09/` and `profiles/common-qinggan-11/` hold the development kernel recipes of each Android generation, `profiles/common-passion/` the Passion variant of the `qinggan-11` recipe.

The `fonts` field of `profile.json` names the fonts of the vehicle that the [window](window.md#fonts) draws with: `primary` for all text and `fallback` for the characters the primary font lacks, each with `regular`, `medium` and `bold`. A font is an OEM input of the profile or a file inside an OEM APK, each with its size and SHA-256.

OEM inputs never enter the repository. The user imports them into `.local/profiles/<profile>/`, and the profile records only their names, sizes and SHA-256.

## Machine

A machine is a prepared directory under `machines/<name>/`. `voyemu build PROFILE` creates `machines/PROFILE` by default, also for the build target of the host ABI; a target of another ABI creates `machines/PROFILE-TARGET`. `build PROFILE machines/NAME` picks another name. The destination must be a new directory directly inside the installation's `machines/`.

| Path | Content |
| --- | --- |
| `runtime.json` | Machine manifest with profile identity, Android ABI, guest images, boot files and resources with sizes and SHA-256 |
| `profile.json` | The embedded profile resolved for the selected build target |
| `android/` | Android system and vendor images, the kernel, writable user and cache disks, installed packages |
| `qnx/` | QNX boot images and the writable QNX disk; only when the cluster is prepared |
| `ui/` | Voyemu logo, OEM boot animations in `ui/startup/`, the fonts of the vehicle in `ui/fonts/`, steering-wheel artwork and button routes |

`runtime.json` appears last, after the guests have booted for verification, so a directory without it is not a machine. Lifecycle commands select a machine by its path, relative or absolute, also outside the installation root, and infer the profile from `runtime.json`.

## Copying and moving a machine

A machine carries everything a launch needs from the profile, so it runs without `profiles/` and moves as one directory. Writable disks inside the machine, the Android QCOW2 layers among them, keep installed applications, files and settings: copy or archive the whole machine directory after a clean stop. Each QCOW2 layer names its raw image relative to the layer, so the copy keeps working in another directory. Session state lives separately in `.local/machines/<name>/` and is recreated when absent; see [local roots](local-roots.md).

A machine needs the installed host tools and a compatible backend for the guest ABI recorded in its manifest. A cluster launch needs the QEMU and ANGLE binding in `.local/toolchains/installed.json`, which machine preparation writes on its host; `deps` installs the engine and `start` does not create the binding, so on a host without it start the machine with `--cluster=off`. `voyemu check MACHINE_PATH` verifies the stored files and the launch configuration without starting guests.

Give independent copies distinct directory names: session state is keyed by the machine directory name, and each machine has at most one session.
