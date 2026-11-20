#include "qnx_host_windows.hpp"
#include "qnx_host.hpp"
#include "qnx_host_prebuilt.hpp"
#include <fstream>
#include <iostream>
#include <string_view>
using namespace voyemu;
namespace {
bool check(bool value, const std::string &message) {
    if (!value) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }

    std::cout << message << " passed\n";

    return true;
}

void write_exact(const std::filesystem::path &path, const std::string &bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);

    file << bytes;
    file.close();

    if (!file) {
        throw std::runtime_error("test write failed: " + path.string());
    }
}

// Every fixture is self-contained: hermetic recipes, hermetic SLT listings, hermetic trees. No
// fixture depends on .local/cache or any other pre-existing host state in the default (CTest) mode.
bool expect_throw(const std::function<void()> &action, const std::string &needle,
                  const std::string &message) {
    try {
        action();
        check(false, message + " (accepted)");

        return false;
    } catch (const std::exception &error) {
        if (std::string(error.what()).find(needle) != std::string::npos) {
            std::cout << message << " passed\n";

            return true;
        }

        std::cerr << "FAILED: " << message
                  << " rejected but with unexpected reason: " << error.what() << '\n';
        std::exit(1);
    }
}

// SLT listing fixture: canonical 7z `l -slt` entry text per the contract with the native owner
// (/root/windows_qnx_factory_bootstrap_finish): entries are `Path = <archive-relative>` blocks with
// `Folder` and `Size` required; link entries additionally carry `Symbolic Link = <target>` (target
// kept verbatim: parent-relative or MSYS-absolute) or `Hard Link = <archive-root target>` (recorded
// root- relative after prefix normalization). Record lines are `S<TAB>relative<TAB>target` for
// symlinks and `H<TAB>relative<TAB>root-relative-target` for hardlinks; the producer returns the
// archive names of the link entries for exact extraction exclusions.
std::string slt_regular(const std::string &path, std::uint64_t size) {
    return "Path = " + path + "\nFolder = -\nSize = " + std::to_string(size) + "\n\n";
}

std::string slt_symlink(const std::string &path, const std::string &target) {
    return "Path = " + path + "\nFolder = -\nSize = 0\nSymbolic Link = " + target + "\n\n";
}

std::string slt_hardlink(const std::string &path, const std::string &target) {
    return "Path = " + path + "\nFolder = -\nSize = 0\nHard Link = " + target + "\n\n";
}

std::vector<std::string> record_lines(const std::filesystem::path &records) {
    std::ifstream input(records);
    std::vector<std::string> lines;
    std::string line;

    while (std::getline(input, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    return lines;
}

// Hermetic synthetic recipe+closure for the reuse validator: self-chosen pins, self-written payload
// — no real runtime package or cache directory is involved.
Json hermetic_recipe(const std::string &engine_bytes) {
    auto spec = [&](const std::string &content) {
        return Json{{"bytes", content.size()}, {"sha256", sha256_bytes(content)}};
    };
    std::string dll = "hermetic-dll-body", license = "hermetic-license-body";

    return Json{
            {"version", "11.1.2"},
            {"verified_runtime",
             {{"files", Json{{"qemu-system-aarch64.exe", spec(engine_bytes)},
                             {"libhermetic-1.dll", spec(dll)},
                             {"licenses/hermetic/COPYING", spec(license)}}}}},
    };
}

void build_installed(const std::filesystem::path &directory, const Json &recipe,
                     const std::string &engine, Json files_override = Json(),
                     std::string executable_sha256 = std::string()) {
    const auto &runtime = qnx_windows_source_payload_spec(recipe);

    ensure_private_directory(directory);
    write_exact(directory / "qemu-system-aarch64.exe", engine);
    Json assembled = Json::object();

    for (const auto &[relative, pinned] : runtime.items()) {
        if (relative == "qemu-system-aarch64.exe") {
            continue;
        }

        const std::string content = relative == "licenses/hermetic/COPYING"
                                            ? std::string("hermetic-license-body")
                                            : std::string("hermetic-dll-body");
        const auto destination = directory / relative;
        ensure_private_directory(destination.parent_path());
        write_exact(destination, content);
        assembled[relative] = {{"bytes", content.size()}, {"sha256", sha256_bytes(content)}};
    }

    const Json engine_override = files_override.is_object() &&
                                                 files_override.contains("qemu-system-aarch64.exe")
                                         ? files_override.at("qemu-system-aarch64.exe")
                                         : Json();

    if (engine_override.is_boolean() && !engine_override.get<bool>()) {
    } else {
        assembled["qemu-system-aarch64.exe"] = {{"bytes", engine.size()},
                                                {"sha256", sha256_bytes(engine)}};
    }

    Json receipt{{"schema", 1},
                 {"component_sha256", sha256_bytes(recipe.dump())},
                 {"recipe", recipe},
                 {"files", assembled},
                 {"executable_sha256",
                  executable_sha256.empty() ? sha256_bytes(engine) : executable_sha256}};
    write_private_json(directory / "qnx-host.json", receipt);
}
} // namespace

int main(int argc, char **argv) {
    try {
        const auto &real_recipe = qnx_host_catalog().at("windows_file_backend");
        check(real_recipe.at("version") == "11.1.2" && real_recipe.at("build_tools").size() == 7 &&
                      real_recipe.at("dependencies").size() == 6 &&
                      real_recipe.at("python_wheels").size() == 4 &&
                      real_recipe.at("patched_sources").size() == 9,
              "embedded pinned MSYS/Zig/QEMU recipe closure");
        {
            const std::filesystem::path source_msys = "/msys";
            check(qnx_windows_source_file(source_msys, "licenses/glib2/COPYING") ==
                                  source_msys / "ucrt64/share/licenses/glib2/COPYING" &&
                          qnx_windows_source_file(source_msys, "licenses/libiconv/COPYING.LIB") ==
                                  source_msys / "ucrt64/share/licenses/libiconv/COPYING.LIB" &&
                          qnx_windows_source_file(source_msys,
                                                  "licenses/gettext-runtime/intl/COPYING.LIB") ==
                                  source_msys /
                                          "ucrt64/share/licenses/gettext-runtime/intl/COPYING.LIB" &&
                          qnx_windows_source_file(source_msys, "zlib1.dll") ==
                                  source_msys / "ucrt64/bin/zlib1.dll",
                  "runtime source mapping strips exactly the licenses/ prefix (9 bytes) keeping the full package name and routes non-license files to bin");
        }
        // Builder entry refusals (hermetic, no network possible: refusal precedes any archive
        // resolution).
        const auto base = std::filesystem::canonical(".");
        const auto scratch = base / ".local/build/tmp" /
                             ("qnx-host-windows-source-test-" + random_token());
        ensure_private_directory(scratch);
        struct Scratch {
            std::filesystem::path scratch_path;

            ~Scratch() {
                std::error_code error;
                std::filesystem::remove_all(scratch_path, error);
            }
        } scratch_guard{scratch};
        expect_throw(
                [&] {
                    install_qnx_host_windows_source(scratch / "..", false, 0);
                },
                "canonical project root",
                "non-canonical root refused before any download or publication");
        check(!std::filesystem::exists(scratch / ".local/toolchains"), "refusal published nothing");
#ifdef _WIN32
        // While the prebuilt pin is pending and no engine is cached, deps reports the engine
        // unavailable instead of running the source recipe.
        if (qnx_host_prebuilt_pin(qnx_host_catalog(), "windows_file_backend").is_null()) {
            check(!qnx_host_unavailable(scratch).empty(), "pending Windows engine unavailable");
            expect_throw(
                    [&] {
                        install_qnx_host(scratch, false, 0);
                    },
                    "QNX_HOST_ASSET_MISSING", "deps without a published or cached Windows engine");
            check(!std::filesystem::exists(scratch / ".local/toolchains"),
                  "missing Windows engine started no recipe");
        }
#else
        // macOS and Linux build a pending engine from its recipe.
        check(qnx_host_unavailable(scratch).empty(), "POSIX engine installable from its recipe");
#endif
#ifdef __APPLE__
        expect_throw(
                [&] {
                    install_qnx_host_windows_source(scratch, false, 0);
                },
                "Windows source builder requires Windows x64",
                "non-Windows host refused by the actual builder entry");
#endif
        //----------- SLT listing -> record producer contract (native owner API) -----------
        const auto work = scratch / "slt";
        ensure_private_directory(work);
        {
            const auto rom = "qemu-11.1.2/roms/u-boot/tools/sha1.h";
            const auto prefix = "qemu-11.1.2";
            const auto records = work / "qemu-links";
            const auto listing = slt_regular("qemu-11.1.2/system/physmem.c", 32) +
                                 slt_symlink(rom, "../include/sha1.h");
            check(record_msys_archive_links(listing, records, prefix, true) ==
                          std::vector<std::string>{rom},
                  "QEMU source extraction excludes exact unused ROM link");
            expect_throw(
                    [&] {
                        record_msys_archive_links(slt_symlink("qemu-11.1.2/system/memory.c",
                                                              "../include/system/memory.h"),
                                                  records, prefix, true);
                    },
                    "archive listing", "QEMU source link in a compiled directory rejected");
            expect_throw(
                    [&] {
                        record_msys_archive_links(slt_hardlink(rom, "qemu-11.1.2/system/memory.c"),
                                                  records, prefix, true);
                    },
                    "archive listing", "QEMU source hardlink rejected even in an unused directory");
        }
        { // valid no-links listing: success, consumed records, zero restores, no destinations
            const auto listing = slt_regular("msys64/usr/bin/bash.exe", 2048);
            const auto records = work / "no-links-records";
            const auto excluded = record_msys_archive_links(listing, records, "msys64");
            check(excluded.empty(), "no-links listing excludes no archive entries");
            check(std::filesystem::is_regular_file(records),
                  "no-links listing produces a record file");
            check(record_lines(records).empty(), "no-links listing records zero links");
            const auto root = work / "no-links-root";
            ensure_private_directory(root / "usr/bin");
            const auto restored = restore_msys_symlinks(root, records);
            check(restored == 0 && !std::filesystem::exists(records),
                  "no-links records restore zero links and are consumed");
            // Windows denies removal while the parser still holds its input handle. Reuse the exact
            // path.
            write_exact(records, "");
            check(restore_msys_symlinks(root, records) == 0 && !std::filesystem::exists(records),
                  "consumed record path can be reused without an open reader handle");
        }
        { // symlink absolute target, hardlink root-relative target, prefix normalization msys64 ->
          // root
            std::string listing;
            listing += slt_regular("msys64/usr/bin/python3.12.exe", 18);
            listing += slt_symlink("msys64/usr/bin/python3", "python3.12.exe");
            listing += slt_symlink("msys64/usr/lib/libpython.so", "/usr/bin/python3.12.exe");
            listing += slt_hardlink("msys64/usr/bin/tar.exe", "msys64/usr/bin/tar-impl.exe");
            const auto records = work / "links-records";
            const auto excluded = record_msys_archive_links(listing, records, "msys64");
            check(excluded.size() == 3 && excluded[0] == "msys64/usr/bin/python3" &&
                          excluded[1] == "msys64/usr/lib/libpython.so" &&
                          excluded[2] == "msys64/usr/bin/tar.exe",
                  "producer returns the archive names of every link entry for extraction exclusions");
            const auto lines = record_lines(records);
            check(lines.size() == 3, "listing records exactly the three link entries");
            check(lines.size() > 0 && lines[0] == "S\tusr/bin/python3\tpython3.12.exe",
                  "relative symlink record: kind S, prefix-normalized path, verbatim relative target");
            check(lines.size() > 1 &&
                          lines[1] == "S\tusr/lib/libpython.so\t/usr/bin/python3.12.exe",
                  "absolute symlink record keeps the absolute target");
            check(lines.size() > 2 && lines[2] == "H\tusr/bin/tar.exe\tusr/bin/tar-impl.exe",
                  "hardlink record kind H normalizes the archive-root target to root-relative");
            // restore in the unprivileged representation: ordinary materialized files, never
            // symlinks
            const auto root = work / "links-root";
            ensure_private_directory(root / "usr/bin");
            ensure_private_directory(root / "usr/lib");
            write_exact(root / "usr/bin/python3.12.exe", "python-interpreter");
            write_exact(root / "usr/bin/tar-impl.exe", "tar-implementation");
            const auto restored = restore_msys_symlinks(root, records);
            check(restored == 3, "all recorded links restored");
            check(std::filesystem::is_regular_file(
                          std::filesystem::symlink_status(root / "usr/bin/python3")) &&
                          !std::filesystem::is_symlink(root / "usr/bin/python3") &&
                          sha256_file(root / "usr/bin/python3") ==
                                  sha256_bytes("python-interpreter"),
                  "symlink restored as an ordinary materialized file with resolved content (unprivileged representation)");
            check(std::filesystem::is_regular_file(
                          std::filesystem::symlink_status(root / "usr/lib/libpython.so")) &&
                          sha256_file(root / "usr/lib/libpython.so") ==
                                  sha256_file(root / "usr/bin/python3.12.exe"),
                  "absolute-target link resolves against the root and materializes the target content");
            check(std::filesystem::is_regular_file(
                          std::filesystem::symlink_status(root / "usr/bin/tar.exe")) &&
                          sha256_file(root / "usr/bin/tar.exe") ==
                                  sha256_bytes("tar-implementation"),
                  "hardlink restored as a root-relative content-identical ordinary file");
            check(!std::filesystem::exists(records), "link records are consumed by restore");
        }
        { // chain: python3 -> python3-impl -> python3.12.exe resolves through the record graph
            std::string listing;
            listing += slt_regular("msys64/usr/bin/python3.12.exe", 18);
            listing += slt_symlink("msys64/usr/bin/python3-impl.exe", "python3.12.exe");
            listing += slt_symlink("msys64/usr/bin/python3", "python3-impl.exe");
            const auto records = work / "chain-records";
            record_msys_archive_links(listing, records, "msys64");
            const auto root = work / "chain-root";
            ensure_private_directory(root / "usr/bin");
            write_exact(root / "usr/bin/python3.12.exe", "chained-interpreter");
            const auto restored = restore_msys_symlinks(root, records);
            check(restored == 2, "chain records restored");
            check(sha256_file(root / "usr/bin/python3-impl.exe") ==
                                  sha256_bytes("chained-interpreter") &&
                          sha256_file(root / "usr/bin/python3") ==
                                  sha256_bytes("chained-interpreter"),
                  "chain links resolve to the final target content");
        }
        // Regression from a real 7zz listing: SLT paths may arrive verbatim as
        // './msys64/usr/alias'. The exclusion must be the VERBATIM SLT path ('./msys64/usr/alias',
        // feeding 7z -x@exclusions byte-for-byte), while the record path is the normalized
        // 'usr/alias' used by restore. Exercised through the actual producer and ordinary restore.
        // (A literal './usr/alias' without the archive prefix is rejected by prefix normalization,
        // so the fixture carries the prefix under the './'.)
        {
            const std::string listing =
                    "Path = ./msys64/usr/alias\nFolder = -\nSize = 0\nSymbolic Link = target\n\n";
            const auto records = work / "dot-slash-records";
            const auto excluded = record_msys_archive_links(listing, records, "msys64");
            check(excluded.size() == 1 && excluded[0] == "./msys64/usr/alias",
                  "SLT Path './msys64/usr/alias' is excluded verbatim for 7z extraction");
            const auto lines = record_lines(records);
            check(lines.size() == 1 && lines[0] == "S\tusr/alias\ttarget",
                  "record path normalizes './msys64/usr/alias' to 'usr/alias' keeping the verbatim relative target");
            const auto root = work / "dot-slash-root";
            ensure_private_directory(root / "usr");
            write_exact(root / "usr/target", "dot-slash-contents");
            const auto restored = restore_msys_symlinks(root, records);
            check(restored == 1, "dot-slash record restores one link");
            check(std::filesystem::is_regular_file(
                          std::filesystem::symlink_status(root / "usr/alias")) &&
                          !std::filesystem::is_symlink(root / "usr/alias") &&
                          sha256_file(root / "usr/alias") == sha256_bytes("dot-slash-contents"),
                  "dot-slash alias materializes as an ordinary copy preserving target contents");
        }
        // GNU long-name/PAX entries surface in 7z SLT listings as a single ordinary Path field
        // carrying the full long name — the producer must accept it without any tar-variant
        // awareness. Only the aspects the producer actually consumes are asserted (full Path,
        // verbatim exclusion).
        {
            const std::string long_dir(101, 'd');
            const std::string archive_path = "msys64/" + long_dir + "/alias";
            const std::string listing = "Path = " + archive_path +
                                        "\nFolder = -\nSize = 0\nSymbolic Link = target\n\n";
            const auto records = work / "longname-records";
            const auto excluded = record_msys_archive_links(listing, records, "msys64");
            check(excluded.size() == 1 && excluded[0] == archive_path,
                  "GNU/PAX long-name entry is excluded by its full SLT path");
            const auto lines = record_lines(records);
            check(lines.size() == 1 && lines[0] == "S\t" + long_dir + "/alias\ttarget",
                  "GNU/PAX long-name record path is prefix-normalized without tar-variant parsing");
            const auto root = work / "longname-root";
            ensure_private_directory(root / long_dir);
            write_exact(root / long_dir / "target", "long-name-contents");
            const auto restored = restore_msys_symlinks(root, records);
            check(restored == 1 && sha256_file(root / long_dir / "alias") ==
                                           sha256_bytes("long-name-contents"),
                  "GNU/PAX long-name alias restores by ordinary copy preserving contents");
        }
        // Fixture from the pinned Windows 7-Zip 25.01 run (2026-10-24T00:14:20Z; evidence
        // .local/build/tmp/wine-7zz-proof/dot.win.slt.txt, independently verified by root): the
        // captured member path and link fields with CRLF line endings, in the -ba body form
        // production obtains from argv `l -slt -ba -sccUTF-8` (an earlier probe had omitted -ba;
        // header blocks are never seen). This is a selected-fields fixture, not the verbatim whole
        // body. Production keeps the raw exclusion '.\usr\alias' and normalizes the record to
        // 'S\tusr/alias\treal' with ordinary-copy restore.
        {
            const std::string windows_body = "Path = .\\usr\\real\r\n"
                                             "Folder = -\r\n"
                                             "Size = 7\r\n"
                                             "Packed Size = 512\r\n"
                                             "Modified = 1970-01-01 03:00:00\r\n"
                                             "Mode = -rw-r--r--\r\n"
                                             "Symbolic Link = \r\n"
                                             "Hard Link = \r\n"
                                             "\r\n"
                                             "Path = .\\usr\\alias\r\n"
                                             "Folder = -\r\n"
                                             "Size = 4\r\n"
                                             "Packed Size = 0\r\n"
                                             "Modified = 1970-01-01 03:00:00\r\n"
                                             "Mode = lrw-r--r--\r\n"
                                             "Symbolic Link = real\r\n"
                                             "Hard Link = \r\n"
                                             "\r\n";
            const auto records = work / "winbody-records";
            const auto excluded = record_msys_archive_links(windows_body, records, "");
            check(excluded.size() == 1 && excluded[0] == ".\\usr\\alias",
                  "actual Windows 25.01 -ba body: raw exclusion preserves the Windows member path verbatim");
            const auto lines = record_lines(records);
            check(lines.size() == 1 && lines[0] == "S\tusr/alias\treal",
                  "actual Windows 25.01 -ba body: record normalized to S usr/alias -> real");
            const auto root = work / "winbody-root";
            ensure_private_directory(root / "usr");
            write_exact(root / "usr/real", "windows-body-contents");
            const auto restored = restore_msys_symlinks(root, records);
            check(restored == 1 && std::filesystem::is_regular_file(root / "usr/alias") &&
                          !std::filesystem::is_symlink(root / "usr/alias") &&
                          sha256_file(root / "usr/alias") == sha256_bytes("windows-body-contents"),
                  "actual Windows body alias materializes as an ordinary copy preserving contents");
        }
        // Malicious member/link shapes must stay rejected: drive letters, UNC, and backslash
        // traversal.
        {
            const std::string drive =
                    "Path = C:\\msys64\\alias\r\nFolder = -\r\nSize = 0\r\nSymbolic Link = alias\r\n\r\n";
            expect_throw(
                    [&] {
                        record_msys_archive_links(drive, work / "neg-drive", "msys64");
                    },
                    "invalid bounded MSYS archive listing", "drive-letter member path rejected");
        }
        {
            const std::string unc = "\\\\server\\share\\alias";
            const std::string listing =
                    "Path = " + unc + "\r\nFolder = -\r\nSize = 0\r\nSymbolic Link = alias\r\n\r\n";
            expect_throw(
                    [&] {
                        record_msys_archive_links(listing, work / "neg-unc", "");
                    },
                    "invalid bounded MSYS archive listing", "UNC member path rejected");
        }
        {
            const std::string traversal =
                    "Path = msys64\\usr\\..\\..\\escape\r\nFolder = -\r\nSize = 0\r\nSymbolic Link = alias\r\n\r\n";
            expect_throw(
                    [&] {
                        record_msys_archive_links(traversal, work / "neg-trav", "msys64");
                    },
                    "invalid bounded MSYS archive listing",
                    "backslash traversal member path rejected");
        }
        {
            const std::string target_traversal =
                    "Path = msys64/usr/alias\r\nFolder = -\r\nSize = 0\r\nSymbolic Link = ..\\..\\outside\r\n\r\n";
            // Parser normalizes separators as production design and defers traversal judgment to
            // restore.
            const auto records = work / "neg-target";
            const auto excluded = record_msys_archive_links(target_traversal, records, "msys64");
            check(excluded.size() == 1 && excluded[0] == "msys64/usr/alias",
                  "backslash traversal link target produced a record for restore-level judgment");
            const auto root = work / "neg-target-root";
            ensure_private_directory(root / "usr");
            write_exact(root / "usr/outside", "nothing");
            expect_throw(
                    [&] {
                        restore_msys_symlinks(root, records);
                    },
                    "escapes", "backslash-normalized traversal link target rejected at restore");
        }
        {
            const std::string target_drive =
                    "Path = msys64/usr/alias\r\nFolder = -\r\nSize = 0\r\nSymbolic Link = C:\\evil\r\n\r\n";
            expect_throw(
                    [&] {
                        record_msys_archive_links(target_drive, work / "neg-target-drive",
                                                  "msys64");
                    },
                    "invalid bounded MSYS archive listing", "drive-letter link target rejected");
        }
        { // cycle: a->b, b->a must be rejected
            std::string listing;
            listing += slt_symlink("msys64/usr/bin/a", "b");
            listing += slt_symlink("msys64/usr/bin/b", "a");
            const auto records = work / "cycle-records";
            record_msys_archive_links(listing, records, "msys64");
            const auto root = work / "cycle-root";
            ensure_private_directory(root / "usr/bin");
            expect_throw(
                    [&] {
                        restore_msys_symlinks(root, records);
                    },
                    "cyclic", "symlink cycle rejected by the record graph");
        }
        { // traversal: target escaping the root must be rejected
            const std::string listing = slt_symlink("msys64/usr/bin/escape", "../../../outside");
            const auto records = work / "escape-records";
            record_msys_archive_links(listing, records, "msys64");
            const auto root = work / "escape-root";
            ensure_private_directory(root / "usr/bin");
            expect_throw(
                    [&] {
                        restore_msys_symlinks(root, records);
                    },
                    "escapes", "traversal attempt rejected");
            check(!std::filesystem::exists(work / "outside"),
                  "traversal attempt published nothing outside the root");
        }
        //----------- reuse validator: hermetic recipe and closure -----------
        const auto recipe = hermetic_recipe("engine-binary");
        const auto installed = scratch / "installed";
        ensure_private_directory(installed);
        {
            const auto good = installed / "good";
            build_installed(good, recipe, "engine-binary");
            bool valid = true;
            try {
                validate_installed_windows_source(good, scratch, recipe);
            } catch (const std::exception &error) {
                valid = false;
                std::cerr << "  (hermetic positive control rejected: " << error.what() << ")\n";
            }

            check(valid, "truthful hermetic closure validates");
        }
        {
            const auto tampered = installed / "tampered-recipe";
            build_installed(tampered, recipe, "engine-binary");
            auto receipt = read_private_json(tampered / "qnx-host.json");
            receipt["component_sha256"] = "00";
            write_private_json(tampered / "qnx-host.json", receipt);
            expect_throw(
                    [&] {
                        validate_installed_windows_source(tampered, scratch, recipe);
                    },
                    "recipe differs", "tampered recipe identity rejected");
        }
        {
            const auto missing = installed / "missing-engine";
            build_installed(missing, recipe, "engine-binary");
            std::filesystem::remove(missing / "qemu-system-aarch64.exe");
            expect_throw(
                    [&] {
                        validate_installed_windows_source(missing, scratch, recipe);
                    },
                    "payload required", "missing engine rejected");
        }
        {
            const auto extra = installed / "extra";
            build_installed(extra, recipe, "engine-binary");
            write_exact(extra / "extra.dll", "rogue");
            expect_throw(
                    [&] {
                        validate_installed_windows_source(extra, scratch, recipe);
                    },
                    "unexpected", "extra payload rejected");
        }
        {
            const auto empty = installed / "empty-map";
            build_installed(empty, recipe, "engine-binary");
            auto receipt = read_private_json(empty / "qnx-host.json");
            receipt["files"] = Json::object();
            write_private_json(empty / "qnx-host.json", receipt);
            expect_throw(
                    [&] {
                        validate_installed_windows_source(empty, scratch, recipe);
                    },
                    "closure differs", "empty receipt files map rejected");
        }
        {
            const auto dll = installed / "pinned-dll";
            build_installed(dll, recipe, "engine-binary");
            write_exact(dll / "libhermetic-1.dll", "tampered");
            expect_throw(
                    [&] {
                        validate_installed_windows_source(dll, scratch, recipe);
                    },
                    "differs", "tampered pinned payload rejected");
        }
        {
            const auto stale = installed / "stale-forgery";
            build_installed(stale, recipe, "engine-binary");
            write_exact(stale / "qemu-system-aarch64.exe", "unrelated-program");
            // incoherent forgery: only the file changed, the receipt map is stale -> consistency
            // rejects
            expect_throw(
                    [&] {
                        validate_installed_windows_source(stale, scratch, recipe);
                    },
                    "differs", "incoherent receipt/file pair rejected by consistency checks");
            ;
        }
        {
            const auto coherent = installed / "coherent-rewrite";
            build_installed(coherent, recipe, "engine-binary");
            write_exact(coherent / "qemu-system-aarch64.exe", "locally-rewritten-engine");
            auto receipt = read_private_json(coherent / "qnx-host.json");
            receipt["files"]["qemu-system-aarch64.exe"] = {
                    {"bytes", std::string("locally-rewritten-engine").size()},
                    {"sha256", sha256_bytes("locally-rewritten-engine")}};
            receipt["executable_sha256"] = sha256_bytes("locally-rewritten-engine");
            write_private_json(coherent / "qnx-host.json", receipt);
            // Honest trust boundary: a locally coherent receipt+engine rewrite is indistinguishable
            // from an actual build by hashes alone — the validator checks receipt<->disk
            // consistency, not provenance. Provenance rests on the install lock and receipt
            // production path, which tests cannot and do not claim.
            bool validated = false;
            try {
                validate_installed_windows_source(coherent, scratch, recipe);
                validated = true;
            } catch (const std::exception &error) {
                std::cerr << "  (coherent rewrite unexpectedly rejected: " << error.what() << ")\n";
                std::exit(1);
            }

            check(validated,
                  "coherent local receipt+engine rewrite validates: consistency, not provenance, is what hashes prove");
        }
        {
            const auto linked = installed / "linked-engine";
            build_installed(linked, recipe, "engine-binary");
            std::filesystem::remove(linked / "qemu-system-aarch64.exe");
            std::error_code link_error;
            const auto foreign = scratch / "foreign-directory";
            ensure_private_directory(foreign);
            std::filesystem::create_directory_symlink(foreign, linked / "qemu-system-aarch64.exe",
                                                      link_error);

            if (!link_error) {
                expect_throw(
                        [&] {
                            validate_installed_windows_source(linked, scratch, recipe);
                        },
                        "linked source engine payload",
                        "linked engine rejected when symlinks are representable");
                std::filesystem::remove_all(linked / "qemu-system-aarch64.exe");
            } else {
                // Unprivileged environment: symlinks are not representable, so the symlink-specific
                // negative is explicitly recorded as skipped — not counted as PASS — and the
                // ordinary tamper negative still runs.
                write_exact(linked / "qemu-system-aarch64.exe", "foreign engine bytes");
                expect_throw(
                        [&] {
                            validate_installed_windows_source(linked, scratch, recipe);
                        },
                        "differs",
                        "linked-engine fixture degrades to an ordinary tamper which is still rejected");
                std::cout
                        << "SKIPPED (no symlink privilege): linked-engine symlink-specific rejection not exercised here\n";
            }
        }
        std::cout << "QNX Windows source builder shared validations passed\n";
#ifdef _WIN32
        // The qnx-host workflow packs the runtime files of the installed engine, without its
        // receipt, into the release asset that deps checks against verified_runtime.
        if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--source-root") {
            const auto actual = std::filesystem::canonical(argv[2]);
            const auto result = install_qnx_host_windows_source(actual, false, 0);
            check(result.at("ready") == true && result.at("cached") == false,
                  "actual online source install");
            validate_installed_windows_source(
                    std::filesystem::path(result.at("directory").get<std::string>()), actual,
                    real_recipe);
            check(install_qnx_host_windows_source(actual, true, 0).at("cached") == true,
                  "actual source install offline reuse");

            if (argc == 4) {
                write_qnx_host_asset(result.at("directory").get<std::string>(), argv[3], false,
                                     "windows-x64");
            }

            std::cout << result.dump() << '\n';

            return 0;
        }
#endif

        if (argc == 3 && std::string(argv[1]) == "--integration") {
            // Explicitly selected acceptance against the real pinned runtime files already in the
            // local cache. Never part of the default CTest run; a missing cache is a reported
            // failure, not a fixture.
            const auto repo = std::filesystem::canonical(argv[2]);
            const auto pinned_runtime =
                    repo / ".local/toolchains/downloads/qnx-host/windows-file-backend-11.1.2";
            const auto &runtime = qnx_windows_source_payload_spec(real_recipe);
            const auto integrated = scratch / "integration";
            ensure_private_directory(integrated);

            for (const auto &[relative, pinned] : runtime.items()) {
                const auto source = pinned_runtime / relative, destination = integrated / relative;
                ensure_private_directory(destination.parent_path());

                if (relative == "qemu-system-aarch64.exe") {
                    std::filesystem::copy_file(source, destination);
                    continue;
                }

                check(sha256_file(source) == pinned.at("sha256").get<std::string>() &&
                              std::filesystem::file_size(source) ==
                                      pinned.at("bytes").get<std::uint64_t>(),
                      "integration runtime pin agrees with disk: " + relative);
                std::filesystem::copy_file(source, destination);
            }

            const auto engine_sha = sha256_file(integrated / "qemu-system-aarch64.exe");
            Json files = Json::object();

            for (const auto &[relative, pinned] : runtime.items()) {
                if (relative == "qemu-system-aarch64.exe") {
                    files[relative] = {{"bytes", std::filesystem::file_size(integrated / relative)},
                                       {"sha256", engine_sha}};
                } else {
                    files[relative] = {{"bytes", pinned.at("bytes")},
                                       {"sha256", pinned.at("sha256")}};
                }
            }

            write_private_json(integrated / "qnx-host.json",
                               Json{{"schema", 1},
                                    {"component_sha256", sha256_bytes(real_recipe.dump())},
                                    {"recipe", real_recipe},
                                    {"executable_sha256", engine_sha},
                                    {"files", files}});
            bool valid = false;
            try {
                validate_installed_windows_source(integrated, scratch, real_recipe);
                valid = true;
            } catch (const std::exception &error) {
                std::cerr << "integration validation failed: " << error.what() << '\n';
            }

            check(valid,
                  "integration mode: real pinned runtime closure validates against the real recipe");
            std::cout << "integration acceptance completed\n";
        }

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
