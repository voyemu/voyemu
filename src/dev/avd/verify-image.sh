#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
if [[ $# != 2 ]]; then
    echo "Usage: $0 RELEASE KEY_PEM" >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
release=$(realpath -- "$1")
key=$(realpath -- "$2")
[[ "$key" != "$release/"* ]] || exit 2
cd "$release"
for input in kernel-ranchu ramdisk.img system.img vendor.img userdata.img encryptionkey.img VerifiedBootParams.textproto; do
    [[ -s "sdk/$input" && ! -L "sdk/$input" ]] || exit 1
done
[[ -d sdk/data && -n "$(find sdk/data -type f -print -quit)" ]] || exit 1
[[ -z "$(find sdk partitions ! -type f ! -type d -print -quit)" ]] || exit 1
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
tools=$("$here/prepare-tools.sh" --verify-only)
export PATH="$tools/bin:$PATH" LD_LIBRARY_PATH="$tools/lib64"
avbtool extract_public_key --key "$key" --output "$temp/key.avbpubkey"
avbtool verify_image --image partitions/vbmeta.img --key "$key" \
    --expected_chain_partition "system:1:$temp/key.avbpubkey" --follow_chain_partitions
avbtool verify_image --image partitions/system.img --key "$key"
digest=$(avbtool calculate_vbmeta_digest --image partitions/vbmeta.img --hash_algorithm sha256)
top=$(avbtool info_image --image partitions/vbmeta.img)
system=$(avbtool info_image --image partitions/system.img)
[[ "$(awk '/^Descriptors:/ {exit} $1=="Flags:" {print $2}' <<< "$top")" == 0 &&
   "$(awk '/^Descriptors:/ {exit} $1=="Flags:" {print $2}' <<< "$system")" == 0 ]] || {
    echo 'Expected AVB integrity checks on the signed root and system' >&2
    exit 1
}
child=$(awk '$1=="VBMeta" && $2=="size:" {print $3}' <<< "$system")
system_root=$(awk '$1=="Root" && $2=="Digest:" {print $3}' <<< "$system")
[[ "$child" =~ ^[0-9]+$ ]]
[[ "$system_root" =~ ^[a-f0-9]{64}$ ]]
bytes=$(( $(stat -c %s partitions/vbmeta.img) + child ))
printf 'major_version: 2\nparam: "androidboot.vbmeta.size=%s"\nparam: "androidboot.vbmeta.hash_alg=sha256"\nparam: "androidboot.vbmeta.digest=%s"\n' \
    "$bytes" "$digest" | cmp - sdk/VerifiedBootParams.textproto
printf 'Verified system root: %s\n' "$system_root"
