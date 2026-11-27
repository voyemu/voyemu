#!/bin/bash
# Builds the release archive of one host: the launcher and notices/ that
# `cmake --install BUILD --component Runtime --prefix STAGE` installs, and profiles/ and the root texts
# of the HEAD commit under the top-level directory voyemu-VERSION. Entries are sorted, directories have
# mode 755, files 644 and the launcher 755, owner and group are 0, and every time is 00:00 UTC of the
# VOYEMU_RELEASE_DATE of src/app/CMakeLists.txt in HEAD, or SOURCE_DATE_EPOCH when it is set, so a rerun
# writes the same bytes. OUTPUT receives voyemu-VERSION-HOST.tar.xz for macos-arm64 and linux-x64 or
# voyemu-VERSION-HOST.zip for windows-x64 and its .sha256 file. Runs on Linux with git, GNU tar and xz;
# the zip needs the jar tool of the pinned JDK in $JAR.
# Usage: archive.sh VERSION HOST STAGE OUTPUT
set -euo pipefail
version=${1:?version required}
host=${2:?host required}
stage=$(cd "${3:?Runtime install directory required}" && pwd -P)
output=${4:?output directory required}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "Invalid version $version" >&2; exit 1; }
case "$host" in
    macos-arm64 | linux-x64) launcher=voyemu extension=tar.xz ;;
    windows-x64) launcher=voyemu.exe extension=zip ;;
    *) echo "Unknown host $host" >&2; exit 1 ;;
esac
project=$(cd "$(dirname "$0")/../../.." && pwd -P)
release_date=$(git -C "$project" show HEAD:src/app/CMakeLists.txt |
    sed -n 's/^set(VOYEMU_RELEASE_DATE "\([0-9-]*\)")$/\1/p')
[[ "$release_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
    { echo "No VOYEMU_RELEASE_DATE in src/app/CMakeLists.txt" >&2; exit 1; }
epoch=${SOURCE_DATE_EPOCH:-$(date -u -d "$release_date" +%s)}
name="voyemu-$version"
file="voyemu-$version-$host.$extension"
mkdir -p "$project/.local/build/jobs" "$output"
output=$(cd "$output" && pwd -P)
work=$(mktemp -d "$project/.local/build/jobs/release-archive.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
tree="$work/$name"
mkdir "$tree"
cp "$stage/$launcher" "$tree/$launcher"
cp -R "$stage/notices" "$tree/notices"
git -C "$project" archive --format=tar HEAD profiles README.md README.ru.md LICENSE CHANGELOG.md \
    CHANGELOG.ru.md SECURITY.md SECURITY.ru.md | tar -C "$tree" -xf -
find "$tree" -type d -exec chmod 755 {} +
find "$tree" -type f -exec chmod 644 {} +
chmod 755 "$tree/$launcher"
cd "$work"
archive="$output/$file"
if [[ "$extension" == tar.xz ]]; then
    find "$name" | LC_ALL=C sort > entries
    tar --create --format=gnu --no-recursion --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
        --files-from=entries | xz --threads=1 > "$archive.part"
else
    # jar writes only the listed files, in list order, with the given time and no owner.
    find "$name" -type f | LC_ALL=C sort > entries
    "${JAR:?jar tool of the pinned JDK required}" --create --no-manifest \
        --date="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)" --file "$archive.part" @entries
fi
mv "$archive.part" "$archive"
(cd "$output" && sha256sum "$file" > "$file.sha256")
echo "$archive"
