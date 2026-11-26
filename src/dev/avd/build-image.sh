#!/usr/bin/env bash
# Build a separate, AVB-signed Linux AVD product. Every required partition is signed with the
# given key.
set -euo pipefail
umask 077
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
if [[ $# != 6 && $# != 7 ]]; then
    echo "Usage: $0 BASE_JSON EXTRACTED_SDK OVERLAY_DIR RELEASE_LABEL PRIVATE_PEM NEW_RELEASE [BUILD_DISPLAY_ID]" >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
root=$(cd "$here/../../.." && pwd -P)
base_desc=$(realpath -- "$1")
recipe="${base_desc%.json}-packing.json"
sdk=$(realpath -- "$2")
inputs=$(realpath -- "$3")
label=$4
signer=$(realpath -- "$5")
dest=$(realpath -m -- "$6")
die() { echo "$*" >&2; exit 1; }
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
[[ "$signer" != "$dest/"* && ! -e "$dest" && ! -L "$dest" ]] || die 'Fresh destination and external key required'
[[ "$(stat -c '%u %a %h' "$signer")" == "$(id -u) 600 1" ]] || die 'Expected an owner-only, unlinked private key'
checksum() { sha256sum -- "$1" | cut -d' ' -f1; }
layout="$here/voyemu_avd_layout"
[[ -x "$layout" ]] || layout="$root/.local/build/native/voyemu_avd_layout"
[[ -x "$layout" ]] || die 'Build the CMake target voyemu_avd_layout first'
[[ -f "$inputs/system.ext4" && -f "$inputs/filesystems.sha256" ]] || die 'A pinned system.ext4 is required'
while IFS= read -r row; do
    [[ "$row" =~ ^[a-f0-9]{64}[[:space:]]\ (system|system_ext|product|vendor)\.ext4$ ]] || die 'Invalid input manifest'
done < "$inputs/filesystems.sha256"
[[ -z "$(find "$inputs" -maxdepth 1 -name '*.ext4' ! -type f -print -quit)" ]] || die 'Ordinary filesystem inputs required'
(cd "$inputs" && sha256sum --strict --check --status filesystems.sha256)
base_archive=$(jq -er '.sha256' "$base_desc")
[[ "$(jq -er '.sourceArchiveSha256' "$recipe")" == "$base_archive" &&
   "$(checksum "$sdk/base.json")" == "$(jq -er '.clean_base.receipt_sha256' "$base_desc")" ]] || die 'Wrong SDK descriptor or receipt'
[[ -z "$(find "$sdk/data" ! -type f ! -type d -print -quit)" ]] || die 'Ordinary SDK seed data required'
tools=$("$here/prepare-tools.sh")
export PATH="$tools/bin:$PATH" LD_LIBRARY_PATH="$tools/lib64"
stage=$(mktemp -d "$(dirname -- "$dest")/.signed-avd.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
out="$stage/release"
mkdir -p "$stage/original" "$out/sdk" "$out/partitions"
parts="$out/partitions"
jq -r '.files|to_entries[]|"\(.value.sha256)  \(.key)"' "$sdk/base.json" > "$stage/sdk.sha256"
(cd "$sdk" && sha256sum --strict --check --status "$stage/sdk.sha256")
# Copy only the files named by the SDK receipt. Per-instance writable disks are created on launch.
while read -r _ name; do
    case "$name" in system.img|vendor.img|VerifiedBootParams.textproto) continue;; esac
    [[ "$name" =~ ^[A-Za-z0-9_./+@-]+$ && "$name" != /* && "/$name/" != *'/../'* && -f "$sdk/$name" && ! -L "$sdk/$name" ]] || die 'Invalid SDK resource path'
    mkdir -p -- "$out/sdk/$(dirname -- "$name")"
    cp --reflink=auto -- "$sdk/$name" "$out/sdk/$name"
done < "$stage/sdk.sha256"
"$layout" "$sdk/system.img" "$(jq -er '.clean_base.images["system.img"]' "$base_desc")" > "$stage/source-layout.json"
[[ "$(jq -er .metadata_sha256 "$stage/source-layout.json")" == "$(jq -er .clean_base.logical_partitions.metadata_sha256 "$base_desc")" ]] || die 'Input LP metadata differs'
names=(system system_ext product vendor)
for name in "${names[@]}"; do
    bytes=$(jq -er --arg name "$name" '.partitions[$name].bytes' "$stage/source-layout.json")
    off=$(jq -er --arg name "$name" '.partitions[$name].offset' "$stage/source-layout.json")
    part="$parts/$name.img"
    if [[ ! -f "$inputs/$name.ext4" ]]; then
        dd if="$sdk/system.img" of="$part" bs=4M iflag=skip_bytes,count_bytes skip="$off" count="$bytes" conv=sparse status=none
        continue
    fi
    pin=$(awk -v f="$name.ext4" '$2==f{print $1}' "$inputs/filesystems.sha256")
    cp --reflink=auto -- "$inputs/$name.ext4" "$part"
    [[ -n "$pin" && "$(checksum "$part")" == "$pin" ]] || die "Changed input filesystem $name"
    fs=$(stat -c %s "$part")
    ((fs > 0 && fs % 4096 == 0 && fs <= 8*1024*1024*1024)) || die "Unsupported filesystem size for $name"
    if [[ "$name" == system && $# == 7 ]]; then
        "$here/set-build-display-id.sh" "$part" "$7"
        e2fsck -fn "$part"
    fi
    signing=(--algorithm SHA256_RSA4096 --key "$signer")
    if [[ "$name" == system ]]; then
        signing+=(--rollback_index "$(jq -er '.systemRollbackIndex' "$recipe")")
    fi
    max_fs=$(avbtool add_hashtree_footer --calc_max_image_size --partition_size "$bytes" --hash_algorithm sha256 --fec_num_roots 2)
    if ((fs > max_fs)); then
        bytes=$(( (fs + fs/16 + 3*1048576 - 1) / 1048576 * 1048576 ))
        max_fs=$(avbtool add_hashtree_footer --calc_max_image_size --partition_size "$bytes" --hash_algorithm sha256 --fec_num_roots 2)
        ((fs <= max_fs)) || die "Insufficient verity/FEC capacity for $name"
    fi
    salt=$(printf 'VoyEmu AVB filesystem %s\n' "$name" | sha256sum | cut -d' ' -f1)
    [[ "$name" != system ]] || salt=390f4074c883076a875394ea1b0ece6e28d99bd113be1b3b0bfa166b03e16440
    avbtool add_hashtree_footer --image "$part" --partition_name "$name" --partition_size "$bytes" --hash_algorithm sha256 --fec_num_roots 2 --salt "$salt" "${signing[@]}"
    avbtool verify_image --image "$part" --key "$signer"
done
offset=$(jq -er '.vendorRamdiskOffset' "$recipe")
dd if="$out/sdk/ramdisk.img" of="$stage/vendor-ramdisk.gz" bs=1M iflag=skip_bytes skip="$offset" status=none
gzip -t "$stage/vendor-ramdisk.gz"
mkbootimg --header_version 3 --pagesize "$(jq -er '.vendorBootV3PageBytes' "$recipe")" --vendor_ramdisk "$stage/vendor-ramdisk.gz" --vendor_boot "$parts/vendor_boot.img"
avbtool add_hash_footer --image "$parts/vendor_boot.img" --partition_name vendor_boot --partition_size "$(jq -er '.vendorBootPartitionBytes' "$recipe")" \
    --hash_algorithm sha256 --salt 9d10a68585dd552448d68a390c209dd60082619ba0c35b31a3acdbfa9eb297dc --output_vbmeta_image "$stage/vendor-boot-descriptor.img" --do_not_append_vbmeta_image
avbtool extract_public_key --key "$signer" --output "$stage/key.avbpubkey"
avbtool make_vbmeta_image --key "$signer" --algorithm SHA256_RSA4096 --chain_partition "system:1:$stage/key.avbpubkey" \
    --include_descriptors_from_image "$parts/product.img" --include_descriptors_from_image "$parts/system_ext.img" \
    --include_descriptors_from_image "$parts/vendor.img" --include_descriptors_from_image "$stage/vendor-boot-descriptor.img" --output "$parts/vbmeta.img"
avbtool verify_image --image "$parts/vbmeta.img" --key "$signer" --expected_chain_partition "system:1:$stage/key.avbpubkey" --follow_chain_partitions
"$here/pack-disks.sh" "$sdk" "$parts" "$out/sdk" "$stage" "$layout" "$recipe"
digest=$(avbtool calculate_vbmeta_digest --image "$parts/vbmeta.img" --hash_algorithm sha256)
child=$(avbtool info_image --image "$parts/system.img" | awk '$1=="VBMeta" && $2=="size:" {print $3}')
[[ "$child" =~ ^[0-9]+$ ]]
size=$(( $(stat -c %s "$parts/vbmeta.img") + child ))
printf 'major_version: 2\nparam: "androidboot.vbmeta.size=%s"\nparam: "androidboot.vbmeta.hash_alg=sha256"\nparam: "androidboot.vbmeta.digest=%s"\n' \
    "$size" "$digest" > "$out/sdk/VerifiedBootParams.textproto"
printf '%s\n' format=1 'producer=VoyEmu local Android emulator development image' "stage=$label" \
    "baseArchiveSha256=$base_archive" \
    "filesystemManifestSha256=$(checksum "$inputs/filesystems.sha256")" \
    'vendorBoot=new AOSP v3 from the approved SDK vendor ramdisk gzip member; no DTB on this SDK model' > "$out/release.properties"
if [[ $# == 7 ]]; then printf 'buildDisplayId=%s\n' "$7" >> "$out/release.properties"; fi
"$here/verify-image.sh" "$out" "$signer"
mv -T --no-clobber -- "$out" "$dest"
[[ ! -d "$out" ]] || die 'Destination already published by another build'
printf 'Verified release: %s\n' "$dest"
