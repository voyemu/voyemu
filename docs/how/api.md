# Voyemu API

Scripts drive sessions through the Voyemu API, which exchanges JSON objects: each `voyemu test` process reads one JSON request with `schema: 1` and writes one JSON response to `stdout`, with diagnostics on `stderr`. There is no network service and no MCP; the reasons are in [Voyemu API through `voyemu test`](../why/api.md).

```sh
./voyemu test --request - <<'JSON'
{"schema":1,"request_id":"discover-1","op":"info"}
JSON
```

`--request FILE` reads the request from a file; `-` or no option reads it from `stdin`, up to 128 KiB. `info` returns the Voyemu version and release date, the schema, the operations of the installed version, the screens and the limits.

## Request and response

| Request field | Purpose |
| --- | --- |
| `schema` | Always `1`; anything else returns `TEST_SCHEMA` |
| `request_id` | An identifier the client chooses; it identifies a repeated request |
| `op` | The operation name |
| `profile`, `session: {id}` | The profile and the session; required by session requests |
| `session.ownership_id` | Proof of ownership; required by requests that change the session |
| `machine` | A machine by its directory name in `machines/` |
| `machine_path` | A machine path; `session.start` only |

A response contains `schema`, `request_id`, `operation_id`, `ok`, `elapsed_ms` and either `result` or `error`. An error has `code`, `message`, `retryable` and `outcome`, see [errors](errors.md). When the request cannot be read, `voyemu test` still prints a JSON response with an error.

## Ownership

`session.start` creates a session and returns its `id` and `ownership_id`. Only a request with the correct `ownership_id` can change the session: input, power, reboots, vehicle values and stop. `session.attach` gives another client read access without ownership. Every guest start has its own generation, so a client knows which guest start it observed.

## Receipts

Voyemu registers every action, screenshot and `test.run` before it runs. The key is the request scope, the `request_id` and the canonical request content. The scope is the profile for `session.start` and for a `test.run` that creates its own session, and the session for the other requests.

- Repeating the same request returns the saved receipt and does not run the action again.
- The same `request_id` with different content fails with `REQUEST_CONFLICT`.
- Repeating a request that is still running returns `OPERATION_PENDING_UNKNOWN`, and repeating an interrupted one returns `OPERATION_UNKNOWN`: an operation in the `pending` or `unknown` state never runs again by itself.

`operation.get` reads a receipt later, for example after the client process crashed. It accepts exactly one lookup method: `target: {operation_id: "32-hex-id"}` or `target: {request_id: "original-id"}`; the request's own `request_id` identifies the lookup itself. Results are stored in `.local/build/automation`. Ending the CLI process does not stop the supervisor, so the outcome can remain `unknown`.

In a terminal receipt (`receipt`), `outcome` follows from the saved response: `ok: true` gives `completed`, `ok: false` keeps `error.outcome` (`not_started` or `unknown`), and an unrecognized response gives `unknown`. `completed` means that the command finished, not that the UI changed visibly. `unknown` does not permit a retry. A failure has `error.outcome: unknown` exactly when `error.code` ends with `_UNKNOWN`.

A `session.wait` result is saved too, but unlike an action a repeated request is not resolved to the saved result. A client does not repeat a change with an uncertain outcome under a new `request_id`.

## Operations

| Area | Operations |
| --- | --- |
| Discovery | `info`, `profile.list`, `profile.get` |
| Session | `session.start`, `session.attach`, `session.status`, `session.stop`, `session.restart`, `session.wait`, `session.watch.start`, `session.watch.read`, `session.watch.stop`, `session.ui`, `session.screenshot`, `session.logs`, `session.observe` |
| Multimedia | `multimedia.power`, `multimedia.reboot`, `multimedia.launch`, `multimedia.system` |
| Phone | `multimedia.phone.configure`, `multimedia.phone.connect`, `multimedia.phone.disconnect`, `multimedia.phone.incoming`, `multimedia.phone.answer`, `multimedia.phone.hangup`, `multimedia.phone.state` |
| USB drive | `multimedia.usb.attach`, `multimedia.usb.detach` |
| Cluster | `cluster.power`, `cluster.reboot`, `cluster.system`, `cluster.ipk.history` |
| Vehicle | `vehicle.fields`, `vehicle.get`, `vehicle.set`, `vehicle.can.get`, `vehicle.can.model`, `vehicle.can.history`, `vehicle.mode.history` |
| Input | `input.tap`, `input.drag`, `input.gesture`, `input.key.press`, `input.wheel.buttons`, `input.wheel.press`, `input.wheel.release`, `input.voice.trigger` |
| Results | `operation.get`, `test.run` |

The set of operations is closed: a request with an unknown name fails with `TEST_UNSUPPORTED`. The phone operations drive the synthetic phone scenario and make no real calls. `input.voice.trigger` presses the voice assistant button on the steering wheel and does not inject text or audio.

## Screens and observations

Operations address screens by [screen role](../GLOSSARY.md): `primary`, `secondary` or `cluster`, each 1920×720, and the other screens of the machine when it has them: `rear`, 1902×540, on Free 6.11.1 and 7.3.1, and `hud`, 1280×720, on Passion. A role is neither an SDK slot number nor a guest display ID. `session.status` lists the screens of the machine.

Pointer input takes `screen`; UI observation and screenshots take either `screen` or a list of unique `screens`, never both. The former names `surface` and `surfaces` are not accepted. By default `session.ui` reads `primary`, `secondary` and `cluster`, and `session.screenshot` takes `primary` and `secondary`; `rear` and `hud` are requested explicitly.

| Screen | Screenshot | UI tree | Pointer input |
| --- | --- | --- | --- |
| `primary`, `secondary` | Yes | Android | Taps, gestures, drags, selectors and `expected` |
| `rear` | Yes, together with the others | Android | Plain taps and gestures in the screen's own pixels |
| `cluster` | Yes | Kanzi, see [the cluster UI tree](#cluster-ui-tree) | No |
| `hud` | No, `TEST_UNSUPPORTED` | No, `TEST_UNSUPPORTED` | No |

A screenshot proves what the guest showed, not that a scenario succeeded. `session.ui` reads the Android UI tree through the UI observer in the guest; attached window nodes also carry the current drawable state, the level and state set of the image and background, see [observations](#observations). `session.wait` waits for readiness or a condition, and `session.watch.*` delivers session events in batches.

Providers are external processes that `session.start` registers from pinned manifest files, up to four; their observations appear in `session.observe`. QNX frames are also available over gRPC, see [launch and sessions](launch.md).

## Cluster UI tree

The `cluster` slot of `session.ui` holds the Kanzi node tree of the Gauge layer. An observer built into Gauge walks the tree on its render thread right after a successful Screen post, calls only exported Kanzi functions and writes the result into pinned guest memory, where the host reads it. Every request rereads this memory and waits for a liveness confirmation from the same producer, so a stopped or restarted Gauge never returns a stale tree.

```sh
./voyemu test --request - <<'JSON'
{"schema":1,"request_id":"ui-cluster-1","op":"session.ui","profile":"free-09-chinese-20260106-6.0.3","session":{"id":"SESSION"},"screen":"cluster","timeout_ms":5000}
JSON
```

| Profile | Observation |
| --- | --- |
| `free-09-chinese-20260106-6.0.3`, `free-11-chinese-20250710-6.11.1`, `free-11-chinese-20260731-7.3.1` | The current Gauge tree: node names, effective visibility and enabled state, Kanzi text, the resolved visibility, enabled state, opacity and actual size of each node with an explicit status, and the Screen window whose post produced the snapshot |
| `passion-11-russian-20260403-2.1.4.80` | `status: "unsupported"`: the Passion cluster has no Kanzi Gauge |

Memory and traversal time budgets bound the size and depth of the tree. An interrupted traversal returns a prefix of complete nodes marked `partial` with an explicit reason. The whole `session.ui` JSON response fits one shared 100 MiB budget for all requested screens. When some nodes do not fit, the response and the affected screens get `partial` and `partial_reason: host_response_byte_budget`, and the remaining nodes keep all their required ancestors. When the metadata alone exceeds the budget, the response is `CLUSTER_UI_RESOURCE_LIMIT`. A response with an unavailable source after the deadline can keep small observations already received; it is limited to 64 KiB and makes no further guest reads.

Node IDs are valid only within one `observation_id`, so a client compares nodes of two observations by their position in the scene, not by ID. The tree snapshot is renewed at most every 250 ms and only when a frame is posted; `freshness` tells whether a later post followed it. The fields and statuses are described in [observations](#observations).

## General rules

Session operations need a prepared machine with its pinned dependencies; the available sources and guest capabilities depend on the platform and the machine. Changes need the `session.ownership_id` obtained when starting with exclusive ownership. A client checks readiness, `accepted` and the condition status: command delivery does not prove the expected result.

`timeout_ms` sets the waiting time:

| Operation | `timeout_ms`, ms | Default |
| --- | --- | --- |
| `session.restart`, `multimedia.reboot` | 1..180000 | `180000` |
| `multimedia.power` | 1..90000 | `90000` |
| `multimedia.usb.attach`, `multimedia.usb.detach` | 1..25000 | `20000` |
| `session.ui`, `cluster.system` | 1..30000 | `5000` and `1000` |
| `session.screenshot`, `vehicle.can.get`, `vehicle.can.model`, `cluster.ipk.history`, `vehicle.mode.history`, `session.logs` with `android`, `anr` or `native` | 1..10000 | `5000` |
| `vehicle.can.history` | 1..15000 | `5000` |
| `session.wait` | 1..60000 | `10000` |
| `session.observe`, `session.watch.start`, `session.watch.read` | 0..60000 | `1000` |

## Session

`session.start` takes these fields:

| Field | Values | Default |
| --- | --- | --- |
| `profile` | The profile of the machine | — |
| `scenario` | `fresh` or `resume` | `fresh` |
| `boot` | Only `auto`; another value returns `TEST_UNSUPPORTED` | `auto` |
| `with_cluster` | Starts the cluster | `false` |
| `seconds` | 1..3600, the QNX run limit with `with_cluster: true` | No limit |
| `background` | Window in the background | `true` |
| `machine` | A `machines/<machine>/` directory whose manifest references `profile` | — |
| `machine_path` | A relative or absolute path to a prepared machine, also outside the project | — |
| `providers` | Up to four absolute provider manifest paths | — |

`machine` and `machine_path` are mutually exclusive (`MACHINE_ARGUMENT`). A relative `machine_path` resolves against the working directory of the API process, and the machine manifest must reference the requested `profile`. The session is created with the canonical machine path; the response keeps `machine`, the canonical `machine_seed` and `machine_manifest_sha256`. The `seconds` field is also available in `test.run.start`. An Android-only machine rejects `with_cluster: true`.

Preflight admits a registered portable machine before local launch settings exist: the launcher checks the manifest and the required host tool bindings, then activates the machine. `scenario` does not select Quick Boot: `session.status` reports the actual mode under `deliveries`. There is no forced cold boot instead of Quick Boot and no restore-required mode.

`session.restart` cold-restarts both guests and keeps the session and its ownership. It needs running Android and QNX guests with the current interguest handshake and `expected_boot: {android: "Linux-UUID", qnx_generation: "positive-decimal", qnx_pid: 123}` from fresh observations. Before the action the operation checks the owner's authority and both previous guest starts. The end of the old processes and of the QNX RAM must be verified; checkpoints are not restored. The receipt contains `before`, `after`, the original request and operation IDs, `old_processes_stopped`, `guest_acknowledged` and `authority_retained`. The QNX identity is a typed record of an owned cold boot, `{kind: "owned_cold_incarnation", generation: "decimal", qemu_pid}`, with a fresh guest handshake, not a fabricated QNX UUID. A client checks Android readiness and the required UI, locale and native component ACKs separately.

The `session.restart` timeout bounds the client's wait and the checks between the shutdown and startup stages, each of which has its own time limit. When the timeout expires or the reply is lost, a started stage is not cancelled and another restart is not authorized. For the original action a client calls `operation.get` with the same profile, session and ownership. The additional `runtime_receipt` and `runtime_outcome` expose the durably saved restart result after an IPC reply is lost. The `pending` and `unknown` outcomes and a partial guest replacement do not mean completion and authorize neither a replay nor an ownership takeover. A client checks that the machine, session, action and both guest boots match. The operation is forbidden inside a `test.run` test; the owner calls it as a separate recorded action.

`session.stop` checks that its session has stopped and released its resources.

## Power and reboot

`multimedia.power` requires session ownership and a boolean `enabled` field and starts or stops Android only. The result contains `enabled`, `changed`, `android_generation`, `android_pid` (`null` after a stop), `process_alive`, `verified`, `qnx_unchanged: true` and `source: "supervisor.android_lifecycle"`. When the operation stopped Android, `shutdown` confirms that the wrapper ended and the ports were released. Application readiness is checked separately.

`multimedia.reboot` requires session ownership and `mode: warm` or `mode: cold`. `timeout_ms` bounds only the client's wait: expiry does not cancel the reboot, the outcome remains `unknown` and an automatic retry is forbidden.

`cluster.power` and `cluster.reboot` require `expected_generation`, and `cluster.power` also requires `enabled`. Both operations use the QNX time limit set at session start.

## Profiles and vehicle

`profile.list` and `profile.get` report whether a profile is prepared; that does not confirm that it starts. `vehicle.fields`, `vehicle.get` and `vehicle.set` work on the host input model rather than reading CAN through guest getters. `vehicle.fields` describes the field catalog of the platform of the running machine with `session`, or of the profile named in `profile`, see [vehicle model](vehicle.md#vehicle-model); with `session` it names in `delivery` of each field the guests of the running machine that receive it, see [delivery to the guests](vehicle.md#delivery-to-the-guests). `vehicle.set` requires `expected_revision` and `values`; the session checks coupled fields atomically and sets the fields coupled to the written ones. The revision is a JSON number.

## Input

| Operation | Fields | Limits |
| --- | --- | --- |
| `input.tap` | `screen`, `x`, `y`; for a series `count` and `interval_ms` | `x` at most 1919, `y` at most 719, both within the screen; `count` 1..8 (default `1`), `interval_ms` 0..300 (default `100`) |
| `input.gesture` | `screen`, `points: [{x, y, at_ms}]` | 1 to 64 points; the first at time `0`, the others in time order up to 2000 ms |
| `input.drag` | `screen`, `from: {x, y}`, `to: {x, y}`, `duration_ms` | `duration_ms` 1..2000 (default `300`); multimedia screens only |
| `input.key.press` | `key` | Exact W3C names of the SDK |
| `input.wheel.press` | `button`, `hold_ms` | `hold_ms` 1..2000 (default `100`) |
| `input.wheel.release` | — | Releases the owner's holds |
| `input.voice.trigger` | — | Presses the voice assistant button |

Pointer coordinates are pixels of the original screen; the window zoom does not affect them. Intermediate gesture moves are given explicitly: there is no interpolation. `input.drag` reads fresh geometry and builds a bounded gesture with intervals of at most 32 ms.

A selector-based tap requires `selector: {resource_id, package?}` and `expected: {boot_id, source_instance, revision, window, target}` from a previous observation; only `input.tap` supports a selector. Before the first input, a fresh read checks the target identity, its geometry and known overlapping windows. The check is not atomic with tap delivery and does not prove that the window accepts touch (`touchability: unknown`). An optional `expected` on `input.drag` also checks the target identity. For a series of taps admission is checked once before the first tap; uncertain or partial delivery must not be retried. `TEST_INPUT_CLEANUP_UNKNOWN` means that the release was not confirmed.

`input.gesture` with `expected` needs no `intent`: a visible, enabled node with positive clipped geometry can receive gestures without `clickable`. The boot, source, window, target and known-overlap checks still apply. `target_basis: visible_enabled_geometry` does not prove touch acceptance or a visible result. An optional `intent: scroll` or `intent: drag` keeps the strict `scrollable` or `clickable` requirements. The requirements of `input.tap` and `input.drag` do not change.

`input.key.press` does not guarantee focus. `Power` toggles the OEM Android power, `WakeUp` requests wake-up and `Standby` requests sleep. SDK command completion does not confirm a display or ACC change: a client checks power and CAN separately. There is no automatic substitution of `Power` for `WakeUp` and no repeated input.

A steering-wheel hold expires after 5 seconds without renewal. `input.voice.trigger` does not submit recognized speech. There is no text entry, clipboard access or arbitrary guest shell.

### Input admission rejection

A pointer admission rejection can contain `error.details`:

| Field | Content |
| --- | --- |
| `reason` | Required: `boot_changed`, `source_changed`, `window_missing`, `window_changed`, `target_missing`, `target_ambiguous`, `target_changed`, `point_outside` or `coverage_unavailable` |
| `expected_window`, `observed_window` | Optional; only the signed 32-bit integer fields `id`, `type`, `layer` and `bounds` (`x`, `y`, `width`, `height`) |
| `target_count` | Optional; a number from 0 to 2147483647 |

Invalid projection fields are omitted. The details contain no arrays or arbitrary strings, and their serialization is smaller than 512 bytes. Diagnostics use the same fresh observation without another read and explain the admission rejection, not pixel presentation or a visible result. The `code`, `message`, `outcome` and `retryable` fields and the delivery and retry rules do not change. When no target or several targets match, the response is `TEST_INPUT_BLOCKED`. The saved result, repeated reads and `operation.get` keep `details`.

## Applications and phone

`multimedia.launch` requires session ownership, `package` and the current `boot_id`; `screen` defaults to `primary`. An optional `component` must belong to an installed package. The operation starts the application with a fixed ActivityManager invocation, without arbitrary shell commands or intents. Command acceptance does not prove that the interface is ready.

The `multimedia.phone` actions `configure`, `connect`, `disconnect`, `incoming`, `answer` and `hangup` require session ownership. `configure` takes a `payload` with a `contacts` array of exactly two synthetic `{name, number}` contacts and an optional `peer_name`. `incoming` takes `payload: {number}`. A number is `+7` followed by ten digits. The other actions take an empty or omitted `payload`. `multimedia.phone.state` reads a phone snapshot without session ownership. Availability depends on the adapter installed on the machine.

## USB drive

`multimedia.usb.attach` plugs the [USB drive](usb-drive.md) into the running multimedia and `multimedia.usb.detach` unplugs it; both require session ownership and take only `timeout_ms`. The result contains `attached`, `changed` (`false` when the drive already was in the requested state), `android_generation` and `volume`. After the port changes, the operation waits up to `timeout_ms` for the guest: `volume` is `{uuid: "2026-1122", state}` with the state of the volume in `vold`, `mounted` once Android has mounted it, and `null` when Android lists no volume of the drive. After an attach, a `volume` that is `null` or not yet `mounted` at the end of the wait means that Android has not finished; the drive stays plugged in.

`USB_DRIVE` means that the port did not change, for example while the multimedia is off; `USB_DRIVE_UNKNOWN` means that the connection to the emulator was lost after the command was sent, and the state of the port is checked with `session.status`, whose `deliveries.android.usb_drive.attached` reports it.

## Observations

`session.ui` reads the cluster and both multimedia screens concurrently within one `timeout_ms`. The `voyemu.session.ui.v1` result always contains `cluster`, `multimedia[0]` for the primary screen and `multimedia[1]` for the secondary screen; unselected slots are `null`. Each selected slot has `screen`, `status`, `complete`, `nodes` and `windows`. An unavailable or unsupported source returns empty arrays. A source read error appears in `error_code`, and with explicitly selected screens also in `error`. The aggregate status `ready` means that the response is complete for all selected screens, `partial` that there is at least one observation and `unavailable` that there is none. Reads of different screens are not atomic.

When both multimedia screens are selected, Voyemu reads them concurrently through the attached-window observer. Requests with a selector or the `interactive` scope use a separate observation mode. With `scope` and `selector` a request selects multimedia screens only, and only explicitly. `scope` takes `all_attached` and `interactive`; `interactive` needs Android API30 and observer support. `selector: {resource_id: "package:id/name", package: "package"}` returns up to 64 matches per screen; `resource_id` is required and `package` only narrows the selection. `all_attached` can include windows whose geometry is not mapped to the screen. An empty selection can be a complete observation.

### Kanzi tree

The `cluster` slot reads the current Kanzi node tree of the Gauge layer on Free 6.0.3, 6.11.1 and 7.3.1 prepared with matching instrumented QNX images; with a running cluster, Passion returns `status: "unsupported"` in this slot. The observer inside Gauge walks the tree on its render thread right after a successful Screen post, at most every 250 ms, calls only exported Kanzi functions and never changes the scene.

| Field | Content |
| --- | --- |
| `id`, `parent` | Strings valid only within one `observation_id`; a root has `parent: null` |
| `name` | The node name, or `null` when it is unavailable |
| `visible`, `enabled` | The effective values, including ancestors |
| `properties.text` | The Kanzi text of the node: `{"status": "ok", "value": "..."}`, `{"status": "unset"}` when the node has no value, or `{"status": "unavailable", "reason": ...}` |
| `properties.visible`, `properties.enabled` | Booleans: `{"status": "ok", "value": ...}` or `{"status": "unavailable", "reason": ...}` |
| `properties.opacity`, `properties.actual_width`, `properties.actual_height` | Numbers in the same form |

The reasons for unavailable text are `property_type_unavailable` when the image exports no such property type, `too_long` for text above 255 bytes and `not_utf8`. The reasons for the other properties are `property_type_unavailable`, `value_unavailable` when the node resolves no value, and `non_finite_value` for NaN or infinity. A value is never substituted. The properties hold the resolved Kanzi value, which can be inherited or a default, so `properties.visible` can be `true` while the effective `visible` is `false`.

`windows` holds one entry with `id: "0"`, `source: "qnx.screen"`, `binding: "posted_before_snapshot"` and `buffer_size`: the Screen window whose post produced the tree snapshot. `selection_coverage` is `gauge_node2d_tree`. The source and the read time are described by `source`, `source_clock_domain`, `host_interval`, `qnx_generation`, `sequence`, `observation_id`, `guest_monotonic_ns` (the snapshot time) and `latest_present_guest_monotonic_ns`. `freshness` is `latest_present` when no post followed the snapshot and `older_than_latest_present` when one did; then the tree can differ from the frame on screen. Every request rereads guest memory and requires a liveness confirmation from the same producer during the request; only the next post renews the snapshot itself, hence `observation: "last_sampled_present"`. When the cluster is powered off or Gauge does not confirm liveness before the timeout, the slot contains `error_code: "CLUSTER_UI_NOT_READY"`.

### Android

The supervisor reads the Android UI observer through embedded ADB and carries its response over private session IPC. A guest observer response is limited to 6 MiB. Android observations include boot, display and observer identity. Node IDs are valid only within an observation. Accessibility and ViewServer have different limitations, so a client checks completeness, geometry reliability, sensitive-data redaction and the source. Redaction rules depend on the source; a client checks `text_redacted` and the node metadata. The `actionable` flag proves neither the absence of occlusion nor the end of an animation. Nested backend metadata partly keeps its earlier form.

For the attached ViewServer source, `enumeration_complete` means that every listed window was read, and `metadata_complete` that the node privacy and text metadata are known. Even without read failures a tree with windows and nodes can report `complete: false` because metadata is unknown; this is not a tree read timeout. A client checks `window_read_failures`, `unavailable_windows`, `selection_coverage` and `text_redacted`. Unknown metadata confirms neither that text is available nor that input is unobstructed.

Attached ViewServer nodes also carry the current drawable state, read on the UI thread of the application during this observation. Accessibility nodes have no drawable fields.

| Field | Content |
| --- | --- |
| `image.drawable_status` | On an `ImageView` node: `available`, `none` when there is no drawable, or `unavailable` when the read failed |
| `image.drawable_level` | Only with `available`: the actual `Drawable.getLevel()` |
| `image.drawable_state` | Only with `available`: the ascending nonzero attribute IDs of `Drawable.getState()`, for example `16842913` for `android:state_selected` |
| `image.drawable_state_status` | `unavailable` when the state set could not be read; the level stays valid |
| `background` | On every node with `bridge_version: 1`: the same four fields for `View.getBackground()` |

A level is never substituted: without a read it is absent and the status is `unavailable`. These fields come with a request for both multimedia screens without a selector, or for explicit screens with `scope: "all_attached"`, for example `{"schema":1,"request_id":"ui-1","op":"session.ui","profile":"PROFILE","session":{"id":"SESSION"},"screen":"primary","scope":"all_attached"}`. A client compares levels within the same window and node, not across a rebuilt window by `resource_id`.

A primary-screen Accessibility observation needs at least one `TYPE_APPLICATION` window with a non-null root. An inventory of system windows only is rejected with `application_window_unverified`. Within the original deadline one reconnect is allowed, keeping the boot identity checks and the snapshot gate; when the application root is still absent, the observation is rejected. This check does not fully reconcile WindowManager with Accessibility and does not guarantee that it detects every omitted window.

### Editor fields

For a non-password editable node on the primary screen, Accessibility returns `hint` (a string), `showing_hint` (a boolean), and `selection_start` and `selection_end` (integer offsets in UTF-16 code units, `selection_unit: "utf16"`). A value of `-1` means an unknown boundary. The node reports `editor_status: "available"`; `selection_status` is `"available"` when both boundaries are nonnegative and `"unknown"` otherwise. These are Accessibility values; the caret position is not inferred from focus or text.

A password node has no `hint`, `showing_hint`, `selection_start` or `selection_end`, and its `editor_status` and `selection_status` are `"redacted"`. A non-password non-editable primary node and attached ViewServer nodes lack those four fields as well, and both statuses are `"unsupported"`. When the editor metadata of the primary screen is unavailable, `selection_unit` is `null`; ViewServer does not return this field.

### CAN

`vehicle.can.get` reads the actual guest getters, ACC and the transport state. The `states` field selects supported enums, including `IVI_SOC_MODESET` and `HUM_VSP_FUNCTION_SW`; unknown values are rejected. `limit` takes 1..32. Without `cursor` the operation returns the initial state and the current cursor. To read history, a request passes `cursor: {source_instance, after_seq: "decimal"}`; `after_seq: "0"` selects the retained history from its beginning. An initial zero value is preserved.

`vehicle.can.model` reads the installed CAN model observer of Free 6.0.3 on supported prepared machines. The mode is `mode: "snapshot"` (default) or `mode: "drain"` with `limit: 1..32` and an optional `cursor: {session: "decimal", next_cursor: "decimal"}` from the preceding `terminal`. All 64-bit values are decimal strings. A gap or loss makes the result partial; an unknown, stale or overflowing cursor is rejected. A raw-frame read by the model does not confirm ioctl admission, and an RX emission attempt does not confirm delivery to the receiver. Until the installed observer is confirmed, the operation is unavailable.

Write, apply and deferred feedback are distinct stages. A Binder UID alone does not identify an application. The operations mark boot changes, service changes and history overflow as gaps (`gaps`). Android elapsed time and host receipt time use different clocks.

### System

`multimedia.system` returns a point-in-time process snapshot (`PID`, `PPID`, `UID`, `name`) and a saved `lastanr` summary and checks that the boot has not changed. The `activities` and `services` fields contain `status`, `items: [{user, component}]`, `complete` and read boundaries. Fixed, bounded `dumpsys` commands collect the data; intents, their extras and raw lines are excluded. Unknown formats, damaged records and truncation give `partial` or `unavailable`. Only an explicit OEM marker confirms an empty result. When a subsource is incomplete, `value.complete` is `false`. A process missing from one snapshot does not prove that it was absent all the time.

In `result.value.power`, `multimedia.system` returns bounded Android power diagnostics: `status`, `complete`, `wakefulness` (`Awake`/`Asleep`/`Dreaming`/`Dozing`), `display_state` (`ON`/`OFF`/`DOZE`/`DOZE_SUSPEND`/`VR`/`UNKNOWN`) and a boolean `display_ready`. Missing values are `null`. An unknown or ambiguous format gives `unavailable`, incomplete fields give `partial`. The raw dump is not returned. Display power and vehicle ACC are different states.

`cluster.system` reads bounded cluster diagnostics without session ownership. The result contains `status: partial/unavailable`, `complete: false`, `qnx_generation`, `processes` and `gauge`. An available snapshot covers only the Gauge process: its producer identity, sequence number, heartbeat and guest time stamps, node count and scene completeness. The snapshot is available only when the heartbeat advanced during the request. When it is unavailable, `gauge` is `null` and `reason` gives the reason.

### Sources and providers

`session.observe` combines sources in `sources: {status, source_instance, boot_id, revision, value, host_interval}` and returns `complete`, `epoch` and `atomic: false`. Reads are coordinated, but the combined snapshot is not atomic; `timeout_ms` bounds the coordinator wait.

`session.observe`, `session.watch.start` and `session.wait` with a `condition` take `sources: [ID, ...]`. Without this field all registered UI, CAN, system and provider source IDs are selected. An empty list, duplicates or unknown IDs give `TEST_ARGUMENT`; the order of IDs does not matter. The response contains only the selected sources with their `status` and `coverage`. An unavailable unselected source does not affect `complete`. Collectors are shared; demand on them is bounded by read and subscription lifetimes. Selecting a subset of sources does not create continuous coverage.

The `session.start.providers` field registers up to four absolute manifest paths with pinned workers, runtimes and allowed reads. To read one provider, a client passes `sources: [provider_id]` to `session.observe` and takes `result.sources[provider_id]`. A provider failure gives the provider the status `unavailable`. Voyemu keeps provider data under `value`. A worker runs trusted code as the same user. Providers take part in observations and subscriptions by default, with `sampled` coverage.

### Logs

`session.logs` selects the source with `source`, `supervisor` by default:

| Source | What it returns |
| --- | --- |
| `supervisor` | Up to 64 KiB or 128 structured events, gap information (`gap`) and the number of skipped records; takes `cursor: {file_id, offset}`, `details` is forbidden |
| `android` | Android log metadata; with `details: true` also the diagnostic text of fixed ART and native tags, up to 2048 bytes per message, with credentials removed; `cursor` is unsupported (`TEST_UNSUPPORTED`) |
| `anr` | The saved ANR summary (including `unknown`), an ASCII excerpt of up to 16 KiB with credentials removed, `excerpt_truncated`, `source_bytes` and `source_sha256`; `details` and `cursor` are forbidden |
| `native` | The `crash` buffer, the list of files in `/data/tombstones` and `handler_diagnostics`; `details` and `cursor` are forbidden |
| `incidents` | Session journal of Android incidents with a cursor and bounded waiting. Requires `system: "multimedia"` |

Logs do not prove that events were absent all the time.

`anr` checks that `boot_id` is unchanged. The source uses the fixed `dumpsys activity lastanr` command and enumerates regular files in `/data/anr` with standard dated Android names or `traces.txt`; arbitrary paths are unavailable. It returns a sanitized excerpt of up to 16 KiB from a prefix no larger than 131,071 bytes. `captured_sha256` describes only that prefix; `source_complete: false`. Filename selection and the check of the current boot during the read do not prove that a retained stack belongs to that boot (`boot_association: unknown`). The snapshot has no cursor and provides no continuous coverage. A read failure does not mean that there was no ANR.

`native` reads the retained `crash` buffer (the last 512 lines, at most 32 KiB) and the list of regular files in `/data/tombstones`; the optional `tombstone: "tombstone_00"` reads one file (`00`–`99`) of up to 32 KiB. The response contains credential-redacted ASCII text, the SHA-256 of the captured original prefix (`captured_sha256`), `captured_bytes`, `source_complete`, `excerpt_truncated`, any recognized PID and time, and the current `boot_id`, `session_id` and `android_pid`. The current boot describes the collection, not the origin of an old tombstone, so `boot_association` marks it as unknown. An unreadable directory or file is marked `unavailable`; permissions are not elevated and buffers are not cleared. `timeout_ms` bounds all reads together.

The `handler_diagnostics` field holds the first 128 matching lines of the `main`, `system` and `crash` buffers with the fixed tags `libc`, `DEBUG`, `crash_dump32`, `crash_dump64`, `tombstoned`, `libdebuggerd_client` and `debuggerd` at all levels, and `IPCThreadState` and `ProcessState` at warning level or above; other tags are disabled. The prefix is limited to 32 KiB plus one byte that reveals truncation. The same size and time limits, credential redaction and session ownership and boot checks apply. `collection_epoch` binds the collection to the session, the SDK emulator PID and the boot; retained lines are not proven to belong to that boot. Arbitrary tags and commands are rejected. This is not a continuous log and does not prove that there were no crashes.

The supervisor collects the `anr` and `native` snapshots over a direct connection to the `adbd` of its session. Before and after the collection the client checks the selected launch configuration, the SDK descriptor and the supervisor boot proof. The supervisor checks the emulator PID, port ownership, the AVD name, the Linux boot ID and the guest nonce. A guest restored from a checkpoint can keep its previous nonce when these checks pass. `timeout_ms` bounds the collection of the whole snapshot.

`session.logs` with `source: "incidents"` requires `system: "multimedia"`. `system: "cluster"` returns `TEST_UNSUPPORTED`. Missing or unknown systems return `TEST_ARGUMENT`. The supervisor observes the owned Android while it runs. The journal contains Java fatal exceptions, native fatal signals and debuggerd stack frames, and Activity Manager crash and ANR reports. It retains normalized identifiers and bounded stack frames. A later correlated observation adds an `enriched` record with the same incident ID and a higher revision. Repeated crashes have separate IDs. An unresolved `am_crash` is an Activity Manager report whose relation to another crash is unknown.

```json
{"schema":1,"request_id":"read-incidents-1","op":"session.logs","profile":"PROFILE","session":{"id":"SESSION"},"source":"incidents","system":"multimedia","limit":16,"timeout_ms":1000}
```

`limit` is 1–32 records, default 16. `timeout_ms` is 0–60000, default 1000. Zero returns immediately. Read with `result.cursor` to continue after the returned page. An omitted cursor starts at the beginning of the retained journal. `head_cursor` gives the current end if the client wants only later publications. Every cursor carries the session, system and journal ID (`stream_id`). Retrying the same cursor can replay the same records. Save it after processing the page. The supervisor retains up to 512 records and bounds the journal to 2 MiB. `has_more` means more records are already available. The journal is discarded when the supervisor exits.

Each incident carries the Android `boot_id`, SDK launch generation, affected process, reported guest wall clock, reason and stack excerpt. The sequence and cursor order records by publication. The boot field outside the entries describes the current verified guest. Each log reader starts after its initial tail record and reports when its baseline has been armed. This excludes retained log data on Quick Boot. Guest reboot, lost coverage and journal eviction are explicit gap records. If a cursor carries an earlier journal ID in the same session, `cursor_reset` signals the change and the returned cursor starts at the available window. `sources` reports availability independently for text and Activity Manager events. A source can lose entries before observation, while disconnected, or inside Android. Empty results cannot establish that no crash occurred.

## Subscriptions

`session.watch.start` takes `condition`, `lease_ms: 1..60000` (default `30000`), `timeout_ms` and `sources`, a list of unique registered IDs; without the list all sources are selected. The readiness response contains `watch_id`, `epoch`, `cursor`, `baseline` and `result`. A client creates the subscription before the action it checks.

`session.watch.read` takes `watch_id`, `epoch`, `cursor`, `limit: 1..32` (default `1`) and `timeout_ms`. `session.watch.stop` takes `watch_id` and `epoch`. The result states expiry, gaps and termination explicitly. Long polling does not hold the session lock. `TEST_WATCH_SIZE` rejects an oversized batch without acknowledging the cursor.

A condition is an expression tree:

| Operators | Form |
| --- | --- |
| `eq`, `count` | `{op, path, value}` |
| `present`, `absent`, `changed` | `{op, path}` |
| `all`, `any`, `ordered`, `first` | `{op, args: [...]}` |
| `stable`, `never` | `{op, condition, duration_ms}` |

A `path` is a JSON Pointer into the normalized state, such as `/sources/can/value`; events are under `/event`. The limits are depth 16, 128 nodes and 4096 history entries. Children of interval conditions, `ordered` and `first` are limited to the state checks `eq`, `present`, `absent`, `count`, `all` and `any`. `changed` remembers an observed difference. `ordered` requires distinct successive events. `first` accepts the first satisfied alternative, and simultaneous matches are resolved by the order of `args`.

A condition status is `passed`, `pending`, `failed` or `unavailable`. `baseline` describes a state, not a past event. Stability and absence checks need continuous coverage and a mark of its boundary (`watermark`); individual reads do not prove the absence of a record, and gaps prevent acceptance.

`session.wait` with a `condition` and supported `sources` runs a bounded subscription; a client checks `result.status`, `gap` and `timed_out`. Instead of a condition a request can pass `predicate`: `session.reachable`, `android.ready`, `android.delivery`, `qnx.delivery` or `inputs.released`; `delivery` needs a `revision` from 1 to 4294967295. Transport readiness does not prove a correct scene.

A UI subscription reports the coverage `sampled_state_with_accessibility_notifications`. Accessibility notifications do not guarantee that every brief state was captured, so they cannot confirm continuous absence for `stable` and `never`.

## Screenshots

`session.screenshot` takes a screen or a list of screens, a new absolute `artifact_dir` within the current project's `.local/build/tmp`, `timeout_ms`, `max_skew_ms: 1..10000` (default `500`) and an optional `expected_generation`. The `rect: {x, y, width, height}` field crops one screen in original coordinates. The PNG and the manifest contain SHA values, the source, read intervals and the consistency verdict. A joint three-screen screenshot takes `screens: [primary, secondary, cluster]` and a new `artifact_dir`; `max_age_ms` is unsupported in such a request because it is for Android only.

Parallel reads check that the session, boot and frame generation remain unchanged, but screen output is not synchronized. Android does not support a positive `after_sequence`, and the cluster does. For one Android screen, `max_age_ms: 1..10000` checks the SDK frame creation-time estimate on the Unix clock at receipt, with a 2 ms margin. When the realtime and steady clocks differ by more than 2 ms or the timestamp is zero or in the future, the response is `TEST_FRAME_CLOCK`; when the frame is older than the limit, `TEST_FRAME_STALE`.

These checks prove neither when the guest displayed a frame nor whether pixels changed. A new request does not by itself mean a new image. A screenshot of a powered-off cluster is rejected as `unavailable`. Artifacts rejected because of a generation change or time skew are kept with `accepted: false`; a lost frame does not turn into an accepted partial result. The test itself defines reference images, tolerances and explicit reference updates.

A screenshot's `accepted` confirms that the session and generation did not change and that the time skew is acceptable, not that the expected scene is ready. A black startup frame or a cluster self-test can be a valid screenshot. UI and CAN readiness and the visible result are checked separately; a file or `accepted` does not replace that check.

### Selector region screenshot

For one Android screen, `session.screenshot` takes `selector: {"resource_id":"package:id/name","package":"package"}`; the `package` field is optional. `selector` and `rect` cannot be combined. A container is selected by its own `resource_id`.

The operation makes complete fresh UI observations before and after the SDK frame within one deadline. Exactly one visible node must fit fully inside the screen, and the boot, source, window and target geometry must not change. No overlapping window and no window with an unknown layer may be above the target; `clickable` and `enabled` are not considered here. When display mapping of the UI is unsupported, the selector screenshot is rejected, and a screenshot with a fixed `rect` remains available.

An optional `expected` contains `boot_id`, `source_instance`, `revision`, `window` and `target`, as for input; `revision` serves diagnostics. The manifest's `roi` section keeps both observations and the flags `geometry_verified: true`, `atomic: false` and `pixels_match_node: false`. An atomic correspondence between UI and pixels and a newer frame are not guaranteed. The Android limitations of `max_age_ms` and a positive `after_sequence` remain the same.

## CAN boundary at cold restart

To prove the OFF mode across a cold restart, a client reads `vehicle.can.history` in the same session. The sealed helper on a supported native machine returns a kernel record with `producer: "closed_ecu_boundary"`, `capability: "closed_ecu_boundary_v1"`, an integer `status: 0`, `session_id`, `owned_android_pid`, `guest_boot_id`, Linux `boot_uuid`, the first mode and decimal identities and counters. Without that evidence the response contains `status: "unavailable"` and a `reason`.

The restart sequence:

1. Read `vehicle.can.history` in the OFF mode. Voyemu keeps up to 16 eligible snapshots, so the history is read right before the next step.
2. Separately obtain a terminal native receive (RX) observation of the same source.
3. Call `session.restart` with `expected_boot` and `expected_can: {anchor, native_terminal_boottime_ms}`.

`anchor` is the entire unmodified fresh `vehicle.can.history` result in the OFF mode with empty raw and semantic queues and no raw operation in flight. `native_terminal_boottime_ms` is a positive decimal string with the native receive time strictly after the snapshot. The restart fences the source itself. From the snapshot to the stop of both guests it checks the OFF mode, empty queues, no unfinished work and unchanged counters of raw admission, ON transitions and loss. The `can_boundary` receipt includes `anchor`, `native_terminal_boottime_ms`, `prepared`, `before_qnx_stop`, `before_android_stop`, `old_kernel_stopped` and `after`. After the cold boot the restart checks that the first and current modes are OFF, the global ON count is zero and the new kernel has no loss. Native receiver coverage and the rendered PW are checked separately.

## Runs

`test.run` runs a list of tests in one session:

| Field | Values | Default |
| --- | --- | --- |
| `start` | `{profile, with_cluster, seconds, scenario, boot}` for a new session | — |
| `profile`, `session` | An existing session instead of `start` | — |
| `cases` | `[{id, op, ...}]`, 1 to 64 tests with unique `id` values | — |
| `artifact_dir` | A new artifact directory | — |
| `artifact_budget_bytes` | 16777216..536870912 | `134217728` |
| `cleanup` | `stop` or `leave_running` | `stop` for a new session, `leave_running` for an existing one |

`start` and `session` are mutually exclusive. A run needs a prepared Android of the profile; otherwise the response is `PROFILE_NOT_PREPARED`. Each test gets the run's `request_id`, a colon and its own `id`. The first failure stops the run, and the remaining tests get `not-run`. `test.run`, `session.start`, `session.stop`, `session.restart`, `session.attach` and `operation.get` are forbidden inside tests. `passed` proves only the listed checks.

The usual sequence is `profile.get` → `session.start` → `session.wait` with `predicate: android.ready` → observations and actions → `session.stop`. A client keeps session ownership and operation results. Host tests use substitute transports; guest boot, secondary-screen and dialog UI, CAN, provider permissions and application behavior need separate verification inside the guest.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `3` | Unsupported operation, `TEST_UNSUPPORTED` |
| `4` | Rejection, timeout, an unaccepted screenshot or a failed run |
