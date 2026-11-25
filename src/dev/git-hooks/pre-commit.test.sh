#!/usr/bin/env bash
# Runs the hook through git commit against a temporary repository.
set -euo pipefail
export LC_ALL=C
hooks=$(cd "$(dirname "$0")" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/voyemu-pre-commit-test.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$work/bin" "$work/repo/src/app"
cat > "$work/bin/cmake" <<'CMAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == -DVOYEMU_FORMAT_MODE=check ]]
snapshot=${2#-DVOYEMU_FORMAT_STAGED_DIRECTORY=}
[[ $snapshot != "$2" ]]
case $(cat "$snapshot/src/app/with space.cpp") in
    'int example(){return 1;}') exit 1 ;;
    'int example() { return 1; }') exit 0 ;;
    *) exit 2 ;;
esac
CMAKE
chmod +x "$work/bin/cmake"
export PATH="$work/bin:$PATH"

cd "$work/repo"
git init -q
git config user.name 'Voyemu test'
git config user.email 'test@example.invalid'
git config core.autocrlf false
git config commit.gpgsign false
printf '%s\n' 'int example() { return 0; }' > 'src/app/with space.cpp'
git add .
git -c core.hooksPath="$work/no-hooks" commit -qm Initial
git config core.hooksPath "$hooks"

# Reject unformatted staged bytes even after the worktree file was fixed.
path='src/app/with space.cpp'
printf '%s\n' 'int example(){return 1;}' > "$path"
git add -- "$path"
printf '%s\n' 'int example() { return 1; }' > "$path"
if git commit -qm 'Unformatted staged source' > "$work/rejected.log" 2>&1; then
    printf '%s\n' 'Pre-commit accepted unformatted staged source' >&2
    exit 1
fi
grep -Fq 'staged formatting' "$work/rejected.log"
[[ $(git show ":$path") == 'int example(){return 1;}' ]]
[[ $(cat "$path") == 'int example() { return 1; }' ]]

# Accept formatted staged bytes without altering unformatted unstaged bytes.
git add -- "$path"
printf '%s\n' 'int example(){return 1;}' > "$path"
git commit -qm 'Formatted staged source'
[[ $(git show "HEAD:$path") == 'int example() { return 1; }' ]]
[[ $(cat "$path") == 'int example(){return 1;}' ]]

# The whitespace gate also checks commits that contain no source files.
printf '%s\n' 'Trailing space ' > README.md
git add README.md
if git commit -qm 'Invalid staged Markdown' > "$work/rejected.log" 2>&1; then
    printf '%s\n' 'Pre-commit accepted trailing whitespace' >&2
    exit 1
fi
grep -Fq 'trailing whitespace' "$work/rejected.log"
printf '%s\n' 'Clean Markdown' > README.md
git add README.md
git commit -qm 'Markdown does not invoke source formatters'
printf '%s\n' 'Pre-commit fixtures passed'
