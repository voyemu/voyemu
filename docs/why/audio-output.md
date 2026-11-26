# Audio output without a host

## Decision

When the multimedia has sound but the host cannot play it, Voyemu starts the Android Emulator with the QEMU audio driver `none` instead of `-no-audio`. The guest keeps its sound device, and only the output to the host is missing. `start` prints the reason and `session.status` reports it, see [audio](../how/launch.md#audio). `-no-audio` remains for a launch with sound turned off.

## Context

The emulator plays through a QEMU driver of the host: Core Audio, DirectSound or PulseAudio. A host can lack that output: on Linux no PulseAudio socket may exist, or `PULSE_SERVER` may name a server that QEMU cannot reach. `-no-audio` turns off the audio of the emulator configuration as a whole, so the sound device of the guest would depend on the state of the host at each start. A [checkpoint](../GLOSSARY.md) of Android RAM is keyed by the launch configuration, not by the host, and the startup volume check and the PCM acceptance read the guest audio service.

## Alternatives

**`-no-audio` when the host cannot play.** The guest then boots with or without a sound device depending on the host, a checkpoint saved without the device can meet a launch with it, and the missing sound stays silent apart from a log record.

**Stop `start` with an error.** The firmware runs without sound, so a host without a sound server, such as an automation host, would lose the whole machine because of one output.

## Argument

The `none` driver changes only where the sound goes, so the guest, its checkpoint and its audio checks see the same device on every host. One line of `start` and one field of `session.status` show the missing output, and the start itself succeeds.

## Consequences

The guest audio service plays into no output while the host has no server, and a later start with a server plays without other changes. `deliveries.android.audio` reports `playing`, `unavailable`, `disabled` or `diagnostic`. On Linux the windowless emulator executable lacks PulseAudio, so playback runs the emulator with a window and hides that window.
