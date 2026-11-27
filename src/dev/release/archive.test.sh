#!/bin/bash
# Builds the linux-x64 and windows-x64 release archives twice from the Runtime install of BUILD and
# checks that the runs match byte for byte, the layout, the order, owners and times; then runs the
# launcher of the extracted Linux archive, which has no src/, from another directory: --version, the
# info operation with the version and release date, list, check of a fixture machine, deps --offline and
# build --offline; then the archive times of the release date without SOURCE_DATE_EPOCH; last, the
# Homebrew formula and the release notes of a beta and a stable version.
# Usage: archive.test.sh CMAKE BUILD JAR
set -euo pipefail
cmake=${1:?cmake required}
build=${2:?build directory required}
export JAR=${3:?jar tool required}
project=$(cd "$(dirname "$0")/../../.." && pwd -P)
script="$project/src/dev/release/archive.sh"
mkdir -p "$project/.local/build/jobs"
work=$(mktemp -d "$project/.local/build/jobs/release-archive-test.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
fail() {
    echo "FAIL: $*" >&2
    exit 1
}
"$cmake" --install "$build" --component Runtime --prefix "$work/stage" > /dev/null
version=$("$work/stage/voyemu" --version | sed -n 's/^Voyemu \([0-9A-Za-z.-]*\)$/\1/p')
[[ -n "$version" ]] || fail "launcher version"
# The zip layout is checked with the same bytes under the Windows name.
cp "$work/stage/voyemu" "$work/stage/voyemu.exe"
export SOURCE_DATE_EPOCH=1767225600
for run in first second; do
    for host in linux-x64 windows-x64; do
        "$script" "$version" "$host" "$work/stage" "$work/$run" > /dev/null
    done
done
top="voyemu-$version"
linux="voyemu-$version-linux-x64"
windows="voyemu-$version-windows-x64"
for file in "$linux.tar.xz" "$windows.zip"; do
    cmp -s "$work/first/$file" "$work/second/$file" || fail "$file differs between runs"
    (cd "$work/first" && sha256sum --quiet -c "$file.sha256") || fail "$file.sha256"
done
expected=$(printf '%s\n' CHANGELOG.md CHANGELOG.ru.md LICENSE README.md README.ru.md SECURITY.md \
    SECURITY.ru.md notices profiles)
tarball="$work/first/$linux.tar.xz"
tar -tJf "$tarball" > "$work/entries"
# The archive sorts paths; the listing adds a slash to directories.
sed 's|/$||' "$work/entries" | LC_ALL=C sort -c || fail "tar entries are not sorted"
[[ "$(grep -v "^$top/" "$work/entries" || true)" == "" ]] || fail "tar entries outside $top/"
listed=$(cut -d/ -f2 "$work/entries" | grep -v '^$' | grep -vx voyemu | LC_ALL=C sort -u)
[[ "$listed" == "$expected" ]] || fail "tar top level: $listed"
grep -qx "$top/voyemu" "$work/entries" || fail "tar launcher"
[[ "$(grep -c "^$top/profiles/.*[^/]$" "$work/entries")" == "$(git -C "$project" ls-tree -r --name-only HEAD profiles | wc -l)" ]] ||
    fail "tar profiles differ from the profiles of HEAD"
[[ "$(tar -tvJf "$tarball" --numeric-owner | awk '{print $2}' | sort -u)" == 0/0 ]] || fail "tar owners"
[[ "$(tar -tvJf "$tarball" --full-time --utc | awk '{print $4 " " $5}' | sort -u)" == "2026-01-01 00:00:00" ]] ||
    fail "tar times"
[[ "$(tar -tvJf "$tarball" | grep " $top/voyemu$" | cut -c1-10)" == -rwxr-xr-x ]] || fail "launcher mode"
unzip -Z1 "$work/first/$windows.zip" > "$work/zip-entries"
LC_ALL=C sort -c "$work/zip-entries" || fail "zip entries are not sorted"
listed=$(cut -d/ -f2 "$work/zip-entries" | grep -vx voyemu.exe | LC_ALL=C sort -u)
[[ "$listed" == "$expected" ]] || fail "zip top level: $listed"
grep -qx "$top/voyemu.exe" "$work/zip-entries" || fail "zip launcher"

mkdir "$work/install" "$work/elsewhere"
tar -xJf "$tarball" -C "$work/install"
app="$work/install/$top"
cd "$work/elsewhere"
[[ ! -e "$app/src" ]] || fail "the archive holds src/"
[[ "$("$app/voyemu" --version)" == "Voyemu $version" ]] || fail "--version"
info=$(printf '%s' '{"schema":1,"request_id":"release","op":"info"}' | "$app/voyemu" test)
[[ "$info" == *"\"version\":\"$version\""* ]] || fail "info version: $info"
release_date=$(sed -n 's/.*"release_date":"\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\)".*/\1/p' \
    <<< "$info")
[[ -n "$release_date" ]] || fail "info release date: $info"
"$app/voyemu" list --lang=en | grep -qx '  free-09-chinese-20260106-6.0.3' || fail "list"
[[ ! -e "$app/.local" ]] || fail "list created .local"
machine="$app/machines/free-09-chinese-20260106-6.0.3"
mkdir -p "$machine"
printf '%s' '{"schema":1,"kind":"portable-guest-runtime","profile":"free-09-chinese-20260106-6.0.3"}' \
    > "$machine/runtime.json"
# The fixture machine has no embedded profile; check reaches that audit in the archive root.
checked=$("$app/voyemu" check "$machine" --lang=en 2>&1 || true)
[[ "$checked" == "Voyemu: PORTABLE_RUNTIME: machine profile snapshot missing"* ]] || fail "check: $checked"
# Nothing is cached, so offline deps stops at its first pinned download inside the archive root.
deps=$("$app/voyemu" deps --offline --lang=en 2>&1 || true)
[[ "$deps" == "Voyemu: DOWNLOAD_OFFLINE: "* ]] || fail "deps --offline: $deps"
[[ -d "$app/.local/toolchains" && ! -e "$app/src" ]] || fail "deps root"
# Offline build reads the profile and stops at its first pinned download after its progress
# lines, still without src/.
built=$("$app/voyemu" build free-09-chinese-20260106-6.0.3 "$app/machines/release-build" --offline --lang=en 2>&1 || true)
[[ "$built" == "Preparing machine "*$'\n\n'"Voyemu: DOWNLOAD_OFFLINE: "* && ! -e "$app/src" ]] ||
    fail "build --offline: $built"
# Without SOURCE_DATE_EPOCH every archive time is 00:00 UTC of the release date of the launcher.
(unset SOURCE_DATE_EPOCH && "$script" "$version" linux-x64 "$work/stage" "$work/dated" > /dev/null)
[[ "$(tar -tvJf "$work/dated/$linux.tar.xz" --full-time --utc |
    awk '{print $4 " " $5}' | sort -u)" == "$release_date 00:00:00" ]] ||
    fail "tar times without SOURCE_DATE_EPOCH"
# The formula takes the version, the archive URLs and their SHA-256 from SHA256SUMS.
sha=$(cut -d' ' -f1 "$work/first/$linux.tar.xz.sha256")
printf '%s  %s\n' "$sha" "$linux.tar.xz" "${sha//[0-9]/0}" "voyemu-$version-macos-arm64.tar.xz" > "$work/SHA256SUMS"
"$project/src/dev/release/homebrew.sh" "$version" voyemu/voyemu "$work/SHA256SUMS" "$work/voyemu.rb"
grep -qx "      url \"https://github.com/voyemu/voyemu/releases/download/v$version/$linux.tar.xz\"" "$work/voyemu.rb" ||
    fail "formula Linux URL"
grep -qx "      sha256 \"$sha\"" "$work/voyemu.rb" && grep -qx "      sha256 \"${sha//[0-9]/0}\"" "$work/voyemu.rb" &&
    grep -qx "  version \"$version\"" "$work/voyemu.rb" || fail "formula version and SHA-256"
if "$project/src/dev/release/homebrew.sh" "$version" voyemu/voyemu /dev/null "$work/missing.rb" 2> /dev/null; then
    fail "formula without SHA256SUMS entries"
fi
# The notes of a version are its CHANGELOG section, with or without a date after the heading.
printf '%s\n' '# Changelog' '' '## 1.2.3 — 2026-12-01' '' 'Stable notes.' '' \
    '## 1.2.3-beta1 — 2026-11-17' '' 'Beta notes.' '' '## 1.2.2' '' 'Old notes.' \
    > "$work/CHANGELOG.md"
notes="$project/src/dev/release/notes.sh"
"$notes" 1.2.3-beta1 "$work/CHANGELOG.md" "$work/beta.md"
[[ "$(grep -v '^$' "$work/beta.md")" == "Beta notes." ]] || fail "beta notes: $(cat "$work/beta.md")"
"$notes" 1.2.3 "$work/CHANGELOG.md" "$work/stable.md"
[[ "$(grep -v '^$' "$work/stable.md")" == "Stable notes." ]] || fail "stable notes: $(cat "$work/stable.md")"
"$notes" 1.2.2 "$work/CHANGELOG.md" "$work/old.md"
[[ "$(grep -v '^$' "$work/old.md")" == "Old notes." ]] || fail "undated notes: $(cat "$work/old.md")"
if "$notes" 1.2.4 "$work/CHANGELOG.md" "$work/missing.md" 2> /dev/null; then
    fail "notes of a version without a CHANGELOG section"
fi
echo "release archives of $version are reproducible and run without src/"
