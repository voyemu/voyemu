#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 4 ]]; then
    echo "Usage: $0 RELEASE KEY_PEM NEW_RUN_DIR EVEN_EMULATOR_PORT" >&2
    exit 2
fi

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(cd -- "$here/../../.." && pwd -P)
release=$(realpath -e -- "$1")
key=$(realpath -e -- "$2")
work=$(realpath -m -- "$3")
port=$4
if [[ ! "$port" =~ ^[0-9]{4}$ ]] || (( port < 5554 || port > 5682 || port % 2 != 0 )); then
    echo "Choose an unused even emulator console port from 5554 to 5682." >&2
    exit 2
fi
[[ ! -e "$work" && ! -L "$work" && "$work" != "$release" && "$work" != "$release/"* ]] || {
    echo "The run directory must be new and outside the signed release." >&2
    exit 2
}
sdk=$(realpath -e -- "${ANDROID_SDK_ROOT:-$repo/.local/toolchains/native-sdk}")
emulator="$sdk/emulator/emulator"
adb="$sdk/platform-tools/adb"
[[ -x "$emulator" && -x "$adb" && -w /dev/kvm && -r /dev/kvm ]] || {
    echo "The Linux Android SDK and read/write access to /dev/kvm are required." >&2
    exit 1
}
command -v ss >/dev/null || { echo "The ss utility is required to identify the private ADB listener." >&2; exit 1; }
for listener in "$port" "$((port + 1))" "$((port + 20000))"; do
    if [[ -n "$(ss -H -lnt "sport = :$listener")" ]]; then
        echo "Port $listener is in use." >&2
        exit 1
    fi
done
[[ -n "${DISPLAY:-}" ]] || { echo "Set DISPLAY to a hardware-accelerated X server." >&2; exit 1; }

"$here/verify-image.sh" "$release" "$key"
mkdir -m 700 -- "$work"
mkdir -m 700 -- "$work/avd" "$work/avd/signed.avd" "$work/android" "$work/emulator" "$work/tmp"
export ANDROID_SDK_ROOT="$sdk" ANDROID_HOME="$sdk"
export ANDROID_AVD_HOME="$work/avd" ANDROID_USER_HOME="$work/android" ANDROID_EMULATOR_HOME="$work/emulator"
export TMPDIR="$work/tmp"
export ADB_USB=0 ADB_EMU=1 ADB_MDNS=0 ADB_MDNS_AUTO_CONNECT=0 ADB_LOCAL_TRANSPORT_MAX_PORT=1
server=$((port + 20000))
export ANDROID_ADB_SERVER_ADDRESS=127.0.0.1 ANDROID_ADB_SERVER_PORT="$server"
export ADB_SERVER_SOCKET="tcp:127.0.0.1:$server"
machine="$work/avd/signed.avd"
printf 'avd.ini.encoding=UTF-8\npath=%s\ntarget=android-30\n' "$machine" > "$work/avd/signed.ini"
cat > "$machine/config.ini" <<CONFIG
AvdId=signed
abi.type=x86_64
tag.id=default
hw.cpu.arch=x86_64
hw.cpu.ncore=4
hw.ramSize=4096
hw.lcd.width=1920
hw.lcd.height=720
hw.lcd.density=160
hw.display1.width=1920
hw.display1.height=720
hw.display1.density=160
hw.display1.xOffset=1920
hw.display1.yOffset=0
hw.display1.flag=0
hw.hotplug_multi_display=false
hw.multi_display_window=false
hw.gpu.enabled=yes
hw.gpu.mode=host
disk.dataPartition.size=6G
image.sysdir.1=$release/sdk/
CONFIG

adb_pid=
emu_pid=
cleanup() {
    if [[ -n "$emu_pid" ]]; then kill "$emu_pid" 2>/dev/null || true; wait "$emu_pid" 2>/dev/null || true; fi
    if [[ -n "$adb_pid" ]]; then kill "$adb_pid" 2>/dev/null || true; wait "$adb_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
"$adb" -L "tcp:$server" --one-device "voyemu-private-$port" server nodaemon > "$work/adb.log" 2>&1 &
adb_pid=$!
owns_adb_listener() {
    ss -H -lntp "sport = :$server" | grep -F "127.0.0.1:$server " | grep -Fq "pid=$adb_pid,"
}
for ((i = 0; i < 50; i++)); do
    kill -0 "$adb_pid" 2>/dev/null || break
    if owns_adb_listener; then break; fi
    sleep 0.1
done
owns_adb_listener || { echo "Private ADB did not start. See $work/adb.log" >&2; exit 1; }
printf 'Private ADB: %q -H 127.0.0.1 -P %s -s emulator-%s\n' "$adb" "$server" "$port"
"$emulator" -avd signed -port "$port" -sysdir "$release/sdk" -datadir "$machine" \
    -no-snapshot -no-audio -accel on -gpu host -feature MultiDisplay -feature VirtioInput \
    -feature -VirtioTablet -show-kernel > "$work/emulator.log" 2>&1 &
emu_pid=$!
guest=("$adb" -H 127.0.0.1 -P "$server" -s "emulator-$port")
for ((i = 0; i < 150; i++)); do
    if ! kill -0 "$emu_pid" 2>/dev/null || ! owns_adb_listener; then break; fi
    if [[ "$(timeout 2 "${guest[@]}" shell getprop sys.boot_completed 2>/dev/null)" == 1 ]]; then
        if timeout 2 "${guest[@]}" shell wm size -d 1 2>/dev/null | grep -Fq '1920x720'; then
            echo "Secondary display 1920x720 is ready."
            break
        fi
        timeout 3 "${guest[@]}" shell am broadcast --user 0 -a com.android.emulator.multidisplay.START \
            -n com.android.emulator.multidisplay/.MultiDisplayServiceReceiver >/dev/null 2>&1 || true
    fi
    sleep 1
done
wait "$emu_pid"
emu_pid=
