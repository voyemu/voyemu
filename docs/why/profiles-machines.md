# Profiles as sources, machines as results

## Decision

Preparation reads authoring profiles directly from `profiles/<profile>/`, without a snapshot copy. A prepared machine in `machines/<name>/` embeds its own profile and resources, so launching it does not depend on authoring profiles or build inputs.

## Context

A profile describes OEM inputs, recipes, components and pins for one firmware. A machine contains guest images, writable disks, artwork, button routes, the UI observer and boot files. Users copy and archive machines; developers change profiles.

## Alternatives

**A snapshot of the profile under `.local/` for each preparation.** A second copy of the source drifts from the original, and nothing tells which copy a machine came from.

**A machine that refers back to the authoring profile at launch.** Editing a profile or moving the project silently changes or breaks a prepared machine, and a copied machine stops working on another host.

## Argument

The SDK archive digest identifies the files supplied by Google. A signed Android system image is bound the same way: the machine manifest pins its disks, its boot files and the vbmeta digest of its boot parameters by SHA-256, and `check` and `start` verify them on any host. Inside Android, the guest compares the vbmeta digest with its boot parameters, and dm-verity checks blocks as the guest reads the system partition.

One copy of the source removes the question of which profile is current. Embedding everything a launch needs makes the machine self-contained: after a clean stop, copying the whole directory is enough to move it. The profile identity in the machine manifest still tells which profile it came from.

Targets share a firmware profile because its OEM checks and most adaptation recipes describe the same inputs. Preparation keeps the selected Android base and ABI with its results. This lets builds share the OEM import while keeping artifacts of different architectures or SDK revisions distinct. A copied machine retains its guest ABI and runs on a backend compatible with that ABI.

## Consequences

Changing a profile affects a machine only after it is prepared again. Launch needs the machine directory and the installed host tools; for QNX it also needs the local QEMU and ANGLE binding in `.local/toolchains/installed.json`. Machines are independent of the [`.local` roots](local-roots.md) that hold OEM inputs and build results. [Profiles and machines](../how/profiles-machines.md) describes the profile and machine layout.
