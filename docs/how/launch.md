# Launch and sessions

A session is one run of a machine's guests under a supervisor process. Lifecycle commands take the machine path, start or stop its session and print a short text result. A machine has at most one session, and a command rejects a session that belongs to another machine directory, even with the same profile.

## Lifecycle commands

| Command | Effect | Output on success |
| --- | --- | --- |
| `start MACHINE_PATH` | Starts the guests and opens the [window](window.md) | That the session started, or that the machine is already running, and the `stop` command; with `--verbose` the session and its subsystems |
| `restart MACHINE_PATH` | Validates the selection, stops the session and starts it again | The session and its subsystems |
| `status MACHINE_PATH` | Shows the active session | The machine, the session state and the state of each guest |
| `stop MACHINE_PATH` | Stops the session and its guest processes | `Session stopped:` and the machine |
| `check MACHINE_PATH` | Verifies stored files and the launch configuration; never installs or starts anything | The profile, the installation and whether each subsystem can launch |
| `patch MACHINE_PATH --values JSON` | Applies values to the [vehicle model](vehicle.md) | `Vehicle state updated:` and the machine |

```sh
./voyemu start machines/free-09-chinese-20260106-6.0.3
./voyemu status machines/free-09-chinese-20260106-6.0.3
./voyemu patch machines/free-09-chinese-20260106-6.0.3 --values '{"speed":80}'
./voyemu stop machines/free-09-chinese-20260106-6.0.3
```

Lifecycle commands take the path of a machine directory with `runtime.json`, relative or absolute, also outside the installation root; preparation commands take a profile name from `profiles/`, see [preparation](preparation.md). `voyemu list` prints the profile identifiers, unfinished profiles included, `voyemu help` the complete syntax with the preparation options and `voyemu --version` the version.

`status` prints one row with the session state, `running` or `stopped`, and the state of the multimedia and the cluster: `ready` once the guest has acknowledged delivery, `off` for a disabled or stopped guest, `not started` before the guest starts, or the current startup state. While the cluster runs, `status` also prints the path of the QNX frame discovery file.

## Subsystems

`--multimedia=on|off` and `--cluster=on|off` select the guests of `start` and `restart`. The multimedia is on by default, and the cluster is on when the machine has one. At least one subsystem stays enabled, and a disabled subsystem starts no guest process. To change the selection, stop the session first or use `restart` with the new flags.

## Several machines

Different machines run at the same time, each in its own session. Every start claims the Android console and ADB ports of its emulator before the emulator opens them, so starts that run at once receive different ports, and ports that another program listens on are skipped.

`stop` also ends the Android emulator when a start failed part way or the session's supervisor exited. It signals only the emulator that the session launched, recognized by its process start time and session token; when that cannot be proven, it fails with an `_UNKNOWN` code and leaves the session running, see [errors](errors.md).

## Launch options

| Option | Effect |
| --- | --- |
| `--network=yes\|no` | Outbound NAT for the guest; off by default |
| `--background` | Keeps the window and audio in the background |
| `--resume` | Restores the saved vehicle scenario instead of default vehicle values |
| `--seconds 1..3600` | Bounds QNX execution time |
| `--provider FILE` | Registers a provider manifest, up to four; the path follows the [path rule](preparation.md) |
| `--verbose` | Prints the session details after a successful `start` and the log records on `stderr`, see [logs](logs.md) |

## Audio

Android plays its sound through the audio output of the host: Core Audio on macOS, DirectSound on Windows and PulseAudio on Linux. Microphone capture stays disabled.

On Linux, Voyemu connects to PulseAudio, or to PipeWire through its PulseAudio server, on the local socket named by `PULSE_SERVER=unix:/path/to/socket` and, without that variable, on `$XDG_RUNTIME_DIR/pulse/native`.

When the host cannot play, because nothing listens on the socket or `PULSE_SERVER` names no local socket, such as a `tcp:` address, Android still starts with its sound device and plays into no output. `start` then prints one line with the reason, and `deliveries.android.audio` of `session.status` reports `state` `unavailable` with `reason` `no_server` or `unsupported_server`. When the host plays, `state` is `playing` and `driver` names the host driver. Why the guest keeps its sound device is explained in [audio output without a host](../why/audio-output.md).

## Output language

Commands print text; only `test` writes JSON, see [Voyemu API](api.md). Help, output and errors of the commands are in English, Russian or Chinese. `--lang=en|ru|zh` anywhere on the command line selects the language; without it the first non-empty `LC_ALL`, `LC_MESSAGES` or `LANG` decides, then the interface language of the host. A `C` or `POSIX` locale, an unknown language and no setting at all mean English. Error codes and the JSON of `test` are the same in every language. The [window](window.md) keeps its own interface language.

## Android checkpoint

When a session stops and the disk has room, the supervisor saves the Android RAM as a checkpoint in `.local/machines/<name>/`. The next start restores it when the machine disks are unchanged and otherwise performs a cold boot. `--resume` concerns only the vehicle scenario and does not promise a RAM restore.

## Failures

A failed command prints `Voyemu:` followed by `CODE: message` on `stderr` and exits with code `4`; see [errors](errors.md). `start`, `restart`, `stop` and `patch` then also print the path of their [command log](logs.md#command-log). Session logs stay in the session directory, see [logs](logs.md).

## QNX frames over gRPC

While the cluster runs, the supervisor serves its frames over plaintext gRPC on `127.0.0.1` and writes the private discovery file `qnx-frame-grpc.json` with the `host`, `port` and `token` of the current cluster generation. `status` prints the path of the file, and the JSON of `session.status` carries it in `deliveries.qnx.frame_grpc.discovery`. A client sends `authorization: Bearer <token>` with each call. After a cluster restart the file holds a new port and token, so a client reads it again.

The service is `android.emulation.control.EmulatorController` of the SDK's `emulator/lib/emulator_controller.proto`: `getScreenshot` returns one frame and `streamScreenshot` a stream. The request selects display `0` and an inline `PNG`, `RGBA8888` or `RGB888` image; optional `width` and `height` bound the size and keep the aspect ratio, and without them a frame is 1920×720. The stream samples new frames at most about 30 times per second and skips frames for a slower client. An empty `Image` means that the cluster has no current frame yet. A full-size RGBA frame needs a message limit of at least 6,000,000 bytes.

With `QNX_GRPC_PORT` set from the discovery file, `QNX_GRPC_TOKEN` exported with the token and the SDK in `.local/toolchains/native-sdk`, grpcurl takes one frame; `streamScreenshot` in the same command streams until the client is interrupted:

```sh
grpcurl -plaintext -max-msg-sz 6000000 -expand-headers \
  -import-path .local/toolchains/native-sdk/emulator/lib -proto emulator_controller.proto \
  -H 'authorization: Bearer ${QNX_GRPC_TOKEN}' -d '{"format":"RGBA8888"}' \
  "127.0.0.1:$QNX_GRPC_PORT" android.emulation.control.EmulatorController/getScreenshot
```
