# Contributing

- Keep AGENTS.md short and precise; include only mandatory project rules
- Follow [CONTRIBUTING.md](CONTRIBUTING.md) when preparing a PR
- Use English for commit messages, code comments, review comments, and pull request descriptions
- Keep each commit atomic by including all code, tests, and documentation needed for one logical change
- Review the final diff and keep it scoped to the change
- Preserve existing user changes and edit generated artifacts through their sources
- Keep OEM files, prepared machine disks, and secrets out of the repository

# Documentation

- Keep canonical documentation in `docs/` and verify technical claims against the code
- Update English and Russian pairs together and link each page from its language index in reading order
- Follow the [documentation structure](docs/index.md), use the canonical [English](docs/GLOSSARY.md) and [Russian](docs/GLOSSARY.ru.md) terms, and follow the [Russian prose rules](docs/GLOSSARY.ru.md#русская-проза)
- Describe each feature once for all hosts, link to its explanation, and report untested hosts as verification gaps
- Keep README short
- Name the OEM files users must import
- Keep acceptance logs, check counts, candidate SHAs, private hosts and processes, and unpublished profiles out of public docs
- Write concise Markdown without emoji or hard wraps; use one line per paragraph

# Implementation

- Use one profile per firmware across supported host platforms and architectures
- Run prepared machines on compatible hosts without rebuilding or relying on the original checkout or build inputs
- Read authoring profiles directly from `profiles/`; embed the launch profile and resources in each prepared machine
- Follow the [local directory layout](docs/how/local-roots.md) and share one canonical copy of pinned host tools
- Keep `voyemu check` read-only, including no installation, downloads, or guest startup
- Share feature logic across hosts and isolate host differences in [thin backends](docs/why/single-implementation.md)
- Select behavior by profile properties; keep concrete profile IDs out of production code and CI workflows
- Pin external downloads, device imports, and third-party code as specified in [pins](docs/dev/pins.md); keep repository files out of pin lists
- Use the latest release of a new dependency unless a reason is documented
- Build in Release without debug symbols
- Use concept-first type names and configure tools explicitly through `config/config-*`
- Use CMake for build logic, Java for preparation, Java, CMake, or C++ for checks and generators, and shell for short glue scripts
- Report failures with [VoyemuError codes](docs/why/error-codes.md) and use `_UNKNOWN` only for an unknown outcome
- Avoid unrelated refactors, cleanup, and formatting
- Add abstractions, settings, and error handling only when needed for the requested change
- Define observable behavior, failure handling, and regression tests before changing persistent state, recovery, protocols, or trust boundaries

# Verification

- Keep C++ tests next to their code and Java preparation tests under `src/prepare/test`
- Update affected tests, mocks, and fixtures when behavior or types change
- Test behavior without asserting source text or pinning repository files by hash
- Reproduce bugs with a failing test before fixing them when practical
- Build affected targets and run relevant tests; report skipped checks and why
- Verify changed guest behavior on a running machine and report untested scenarios and hosts
- Test machine portability in CI by starting a copied, stopped machine in a clean compatible installation with only destination host dependencies; verify every enabled guest reaches readiness
- Enable the [pre-commit hook](CONTRIBUTING.md#checks-before-commit)
- Run the [pre-commit lint checks](docs/dev/checks.md); fix findings or document a specific reason for suppression
- Serialize builds that share a build directory
- Verify the result before reporting completion

# Releases

- Carry unresolved known issues and limitations into each release changelog
