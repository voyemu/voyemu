#!/usr/bin/env bash
# Hardware-independent checks against an actual release. Never write into the tested release.
set -euo pipefail
umask 077
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
[[ $# == 2 ]] || { echo "Usage: $0 RELEASE KEY_PEM" >&2; exit 2; }
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
release=$(realpath -- "$1")
key=$(realpath -- "$2")
"$here/verify-image.sh" "$release" "$key"
work=$(mktemp -d "$(dirname -- "$release")/.avd-integrity-test.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cp --reflink=auto --sparse=always -- "$release/partitions/system.img" "$work/system.img"
# Flip a bit in the ext4 data that the signed root descriptor covers. Keep its AVB footer.
byte=$(od -An -tu1 -N1 -j1048576 "$work/system.img")
printf -v replacement '%03o' "$((byte ^ 1))"
printf '%b' "\\$replacement" | dd of="$work/system.img" bs=1 seek=1048576 conv=notrunc status=none
tools=$("$here/prepare-tools.sh" --verify-only)
if "$tools/bin/avbtool" verify_image --image "$work/system.img" --key "$key" > "$work/negative-system" 2>&1; then
    echo 'Changed filesystem was accepted' >&2; exit 1
fi
grep -Fq 'does not match descriptor' "$work/negative-system"
echo 'Valid release accepted; changed ext4 rejected.'
