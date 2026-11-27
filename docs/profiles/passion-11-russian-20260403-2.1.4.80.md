# passion-11-russian-20260403-2.1.4.80

The Russian Voyah Passion firmware 2.1.4.80 of 3 April 2026 on Android 11. Multimedia is supported, the cluster is experimental.

The profile declares two [build targets](../how/profiles-machines.md#build-targets) that use the same H53 firmware originals and shared recipes.

## Guests

| Target | Android ABI | Emulator | Cluster |
| --- | --- | --- | --- |
| `arm` | `arm64-v8a` | 2048 MiB, 4 cores | QNX, experimental |
| `x86` | `x86_64` | 4096 MiB, 4 cores | QNX, experimental |

Both targets use API 30 and the `passion-2024` steering wheel.

## x86 target

The `x86` target runs the multimedia in an x86_64 guest: with hardware acceleration on a host with an x86_64 processor, in software translation on another host. Its x86_64 [development kernel](../how/components.md#development-kernels) is not published yet, so preparation of this target stops with `PROFILE_TARGET`. Preparation checks the two OEM home screens and their Android Binder services. This target includes the Voyemu MCU adapter for the battery state of charge and separate power control for each multimedia display.

Android plays sound through the host audio output, see [audio](../how/launch.md#audio). The firmware sets playback volume to its minimum at cold boot, and the normal volume controls raise it.

The target uses API 30 `default` x86_64 r11 and prepares it like the `arm` target on its running guest. The first-stage mount of r11 verifies the vbmeta chain, so the machine boots with its own boot parameters, and dm-verity stays off; see [preparation](../how/preparation.md#build). The ARM code of the firmware runs through the pinned Native Bridge from Google APIs r16: `MonzaCarService` needs its ARM64 JNI library to register the service that both OEM home screens use. See [profiles as sources, machines as results](../why/profiles-machines.md).

### Prepare and run

[Build the launcher from source](../dev/build.md) with the pinned Linux build tools, including JDK 25. Run the commands from the checkout root in a hardware-accelerated graphical session with access to `/dev/kvm` and the GPU render device. The SDK Emulator needs the Qt/X11 runtime libraries, including `libxkbfile.so.1`, `libSM.so.6` and `libICE.so.6`.

Use the local path to `OIB_8155_H53Y3632802AW.zip`. On an x86_64 host `x86` is the default target, and the machine goes to `machines/PROFILE`.

Building the HAB component from source requires Android NDK r29 (`29.0.14206865`). Separately from `deps`, download the complete Linux NDK archive using the URL and SHA-256 in `sdk.archives.linux.ndk` in [`src/app/toolchain.json`](../../src/app/toolchain.json). Verify the download, extract it outside the managed SDK directory and set `NDK_HOME` to the absolute canonical path of the directory containing `source.properties`. Voyemu checks the external NDK inventory against its pin.

```sh
profile=passion-11-russian-20260403-2.1.4.80
firmware=/path/to/OIB_8155_H53Y3632802AW.zip
machine=machines/${profile}
export NDK_HOME=/path/to/android-ndk-r29

./voyemu deps "$profile"
./voyemu fetch "$profile" --source="$firmware"
./voyemu build "$profile"
./voyemu check "$machine"
./voyemu start "$machine"
./voyemu status "$machine"
```

Repeat `status` to watch Android boot. Stop the session when finished. The machine directory and its writable disks remain available for the next start.

```sh
./voyemu stop "$machine"
```

## OEM inputs

Import the pinned firmware archive `OIB_8155_H53Y3632802AW.zip` from a local path. `fetch` reads the OTA package inside it and extracts the shared OEM inputs for both targets. The inner TGZ can also be supplied directly under the filename in the update manifest. The command verifies its byte count and SHA-256.

The `arm` target follows the [common preparation steps](../how/preparation.md). On Apple Silicon it is the default target, and the machine goes to `machines/passion-11-russian-20260403-2.1.4.80`. On a host with an x86_64 processor `--target=arm` selects it; its guest then runs in software translation in `machines/passion-11-russian-20260403-2.1.4.80-arm`. `--cluster=off` prepares only multimedia.

```sh
./voyemu build passion-11-russian-20260403-2.1.4.80 --cluster=off
```

## Notes

A multimedia-only `build --force` into an existing stopped machine updates its Android system and keeps the writable disks. See [preparation](../how/preparation.md).

The application list shows the nine tiles of the vehicle in its order: Vehicle, Bluetooth Phone, Scenes, 360 View, Drive Recorder, Camera, Photos, Music and Video. Each tile opens the OEM application of the firmware: `com.voyah.scenemode` for Scenes, `com.mega.dvr` for Drive Recorder and `com.voyah.gallery` for Photos among them. Photos and Scenes run with the system rights they have in the vehicle, so Photos reads the photos and videos of the internal storage and of the USB drives. Drive Recorder shows the virtual camera, see [Passion Drive Recorder](../how/camera.md#passion-drive-recorder).

At power-on the window plays the three OEM startup videos of `ifs_video.img` inside `ifs2_la.img` together, as the vehicle does: `proc/boot/startup_video_screen_2.mp4` on the primary screen and `proc/boot/startup_video_screen_3.mp4` on the secondary screen for up to 5 s, and `proc/boot/startup_video_screen_0.mp4` in the cluster area for up to 3 s when the window shows the cluster; no separate import is needed. After its video the primary screen shows the OEM boot animation until Android is ready. The profile imports only the boot animation of the primary screen, so the secondary screen stays black after its video, see [the window](../how/window.md#startup-screen).

The vehicle has a fourth screen, 1280×720: the second QNX screen, with the screen role `hud`. The [screens window](../how/window.md#screens) shows it with its OEM startup video `proc/boot/startup_video_screen_1.mp4` for up to 3 s, then black, because the QNX output to this screen is not emulated yet.
