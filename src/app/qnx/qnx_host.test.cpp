#include "qnx_host.hpp"
#include "process.hpp"
#include "qnx_host_prebuilt.hpp"
#include "qnx_host_windows.hpp"
#include "qnx_host_windows_cache.hpp"
#include "qnx_process_ram.hpp"
#include "quickboot.hpp"
#include "session.hpp"
#ifdef __APPLE__
#include "host_refresh.hpp"
#include "qnx_host_build_diagnostics.hpp"
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif
#include <algorithm>
#include <array>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
using namespace voyemu;

static void check(bool ok, const char *message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

// Developer packaging only: unlike --source-root this verifies an existing installation and
// never compiles QEMU. Two identical packages are not evidence of two independent builds.
static Json pack_installed(const Json &catalog, const std::string &section,
                           const std::filesystem::path &directory,
                           const std::filesystem::path &output) {
    check(section == "macos_arm64" || section == "linux_x64" || section == "windows_file_backend",
          "known installed engine recipe required");
    check(directory.is_absolute() && std::filesystem::canonical(directory) == directory &&
                  std::filesystem::is_directory(std::filesystem::symlink_status(directory)),
          "canonical installed engine directory required");
    check(output.is_absolute() && !std::filesystem::exists(std::filesystem::symlink_status(output)),
          "new absolute engine archive path required");
    const auto &component = catalog.at(section);
    const auto pin = sha256_bytes(component.dump());
    const auto prefix = section == "macos_arm64" ? "qnx-host-macos-11.1.2-"
                        : section == "linux_x64" ? "qnx-host-linux-11.1.2-"
                                                 : "qnx-host-windows-11.1.2-";
    const bool windows_source = section == "windows_file_backend" &&
                                directory.filename() ==
                                        "qnx-host-windows-source-11.1.2-" + pin.substr(0, 12);
    const auto receipt = read_private_json(directory / "qnx-host.json", 128 * 1024);
    const auto archive = receipt.value("archive_sha256", std::string{});
    check(windows_source ? archive.empty()
                         : directory.filename() == prefix + qnx_host_cache_key(pin, archive),
          "installed engine directory does not name its recipe");
    Json identities = Json::object();

    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        check(!entry.is_symlink() && (entry.is_directory() || entry.is_regular_file()),
              "ordinary installed engine entries required");

        if (entry.is_regular_file()) {
            const auto name = entry.path().lexically_relative(directory).generic_string();
            identities[name] = cache_file_identity(entry.path());
        }
    }

    check(receipt.at("schema") == 1 && receipt.at("component_sha256") == pin &&
                  receipt.at("recipe") == component,
          "installed engine recipe differs");
    const bool windows = section == "windows_file_backend";

    if (windows) {
        const auto root = directory.parent_path().parent_path().parent_path();

        if (windows_source) {
            check(directory.parent_path().filename() == "toolchains" &&
                          directory.parent_path().parent_path().filename() == ".local",
                  "installed Windows source directory differs");
            validate_installed_windows_source(directory, root, component);
        } else {
            const auto verified = install_cached_windows_qnx_host(
                    root, component, 0, archive.empty() ? Json() : Json{{"sha256", archive}});
            check(verified.at("cached") == true && verified.at("directory") == directory.string(),
                  "existing pinned Windows installation required");
        }
    } else {
        check(identities.contains("COPYING") && identities.contains("licenses/LGPL-2.1.txt") &&
                      (section != "macos_arm64" || component.at("system_only_runtime") == true) &&
                      receipt.at("system_only_runtime") == true &&
                      receipt.at("executable_sha256") ==
                              sha256_file(directory / "qemu-system-aarch64"),
              "installed engine payload differs");

        if (section == "linux_x64") {
            const auto &allowed = component.at("system_libraries");

            for (const auto &name : qnx_host_elf_needed(directory / "qemu-system-aarch64")) {
                check(std::find(allowed.begin(), allowed.end(), name) != allowed.end(),
                      "non-system installed engine dependency rejected");
            }
        }
    }

    const auto host = section == "macos_arm64" ? "macos-arm64"
                      : section == "linux_x64" ? "linux-x64"
                                               : "windows-x64";
    write_qnx_host_asset(directory, output, !windows, host);
    try {
        Json after = Json::object();

        for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
            check(!entry.is_symlink() && (entry.is_directory() || entry.is_regular_file()),
                  "installed engine entry changed during packaging");

            if (entry.is_regular_file()) {
                const auto name = entry.path().lexically_relative(directory).generic_string();
                after[name] = cache_file_identity(entry.path());
            }
        }

        check(after == identities, "installed engine changed during packaging");
    } catch (...) {
        std::filesystem::remove(output);
        throw;
    }

    return {{"section", section},
            {"archive", output.string()},
            {"sha256", sha256_file(output)},
            {"bytes", std::filesystem::file_size(output)},
            {"recipe_sha256", pin},
            {"independent_builds_verified", false}};
}

static void pack_installed_tests(const std::filesystem::path &root) {
    const Json recipe{{"version", "11.1.2"}, {"system_only_runtime", true}};
    const Json catalog{{"macos_arm64", recipe}};
    const auto directory = root /
                           ("qnx-host-macos-11.1.2-" + sha256_bytes(recipe.dump()).substr(0, 12));

    ensure_private_directory(directory / "licenses");

    for (const auto &name : {"qemu-system-aarch64", "COPYING", "licenses/LGPL-2.1.txt"}) {
        std::ofstream file(directory / name, std::ios::binary);
        file << name << '\n';
    }

    const Json receipt{{"schema", 1},
                       {"recipe", recipe},
                       {"component_sha256", sha256_bytes(recipe.dump())},
                       {"executable_sha256", sha256_file(directory / "qemu-system-aarch64")},
                       {"system_only_runtime", true}};
    write_private_json(directory / "qnx-host.json", receipt);
    const auto first = pack_installed(catalog, "macos_arm64", directory, root / "first.zip");
    const auto again = pack_installed(catalog, "macos_arm64", directory, root / "again.zip");
    check(first.at("sha256") == again.at("sha256") &&
                  first.at("independent_builds_verified") == false,
          "installed engine packaging is deterministic, not a source rebuild");
    auto reject = [&](const std::function<void()> &alter, const std::function<void()> &restore) {
        alter();
        bool failed = false;
        try {
            pack_installed(catalog, "macos_arm64", directory, root / "rejected.zip");
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(root / "rejected.zip"),
              "stale or aliased installation must not produce an archive");
        restore();
    };
    reject(
            [&] {
                auto stale = receipt;
                stale["recipe"]["version"] = "stale";
                write_private_json(directory / "qnx-host.json", stale);
            },
            [&] {
                write_private_json(directory / "qnx-host.json", receipt);
            });
    reject(
            [&] {
                std::ofstream file(directory / "qemu-system-aarch64", std::ios::app);
                file << "changed";
            },
            [&] {
                std::ofstream file(directory / "qemu-system-aarch64", std::ios::trunc);
                file << "qemu-system-aarch64\n";
            });
    reject(
            [&] {
                std::filesystem::create_hard_link(directory / "COPYING", root / "alias");
            },
            [&] {
                std::filesystem::remove(root / "alias");
            });
    reject(
            [&] {
                std::filesystem::create_symlink(directory / "COPYING", directory / "link");
            },
            [&] {
                std::filesystem::remove(directory / "link");
            });
}

static void pack_windows_source_tests(const std::filesystem::path &root) {
    auto recipe = qnx_host_catalog().at("windows_file_backend");
    std::map<std::string, std::string> payload;
    Json actual = Json::object();

    for (auto &[name, spec] : recipe.at("verified_runtime").at("files").items()) {
        const auto bytes = name + "\n";
        payload[name] = bytes;
        actual[name] = {{"bytes", bytes.size()}, {"sha256", sha256_bytes(bytes)}};

        if (name != "qemu-system-aarch64.exe") {
            spec = actual.at(name);
        }
    }

    const auto pin = sha256_bytes(recipe.dump());
    const Json catalog{{"windows_file_backend", recipe}};
    const auto directory = root / ".local/toolchains" /
                           ("qnx-host-windows-source-11.1.2-" + pin.substr(0, 12));
    const auto write = [&](const std::string &name, const std::string &bytes) {
        ensure_private_directory((directory / name).parent_path());
        std::ofstream file(directory / name, std::ios::binary | std::ios::trunc);
        file << bytes;
    };

    for (const auto &[name, bytes] : payload) {
        write(name, bytes);
    }

    const Json receipt{{"schema", 1},
                       {"recipe", recipe},
                       {"component_sha256", pin},
                       {"files", actual},
                       {"executable_sha256", actual.at("qemu-system-aarch64.exe").at("sha256")}};
    write_private_json(directory / "qnx-host.json", receipt);
    const auto first = pack_installed(catalog, "windows_file_backend", directory,
                                      root / "windows-source-first.zip");
    const auto again = pack_installed(catalog, "windows_file_backend", directory,
                                      root / "windows-source-again.zip");
    const auto asset = root / "windows-source-first.zip";
    const auto sha = sha256_file(asset);
    check(first.at("sha256") == again.at("sha256") &&
                  first.at("independent_builds_verified") == false &&
                  read_pinned_zip_entry(asset, sha, "qemu-system-aarch64.exe", 4096) ==
                          payload.at("qemu-system-aarch64.exe") &&
                  receipt.at("executable_sha256") != recipe.at("verified_runtime")
                                                             .at("files")
                                                             .at("qemu-system-aarch64.exe")
                                                             .at("sha256") &&
                  read_pinned_zip_entry(asset, sha, "SOURCE-INFO.txt", 4096) ==
                          qnx_host_source_info("windows-x64") &&
                  pinned_zip_inventory(asset, sha).size() == actual.size() + 1 &&
                  !std::filesystem::exists(directory / "SOURCE-INFO.txt"),
          "Windows source installation packs its actual engine, strict closure and source metadata");
    auto reject = [&](const std::function<void()> &alter, const std::function<void()> &restore) {
        alter();
        bool failed = false;
        try {
            pack_installed(catalog, "windows_file_backend", directory,
                           root / "windows-source-rejected.zip");
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(root / "windows-source-rejected.zip"),
              "stale or changed Windows source payload must not produce an archive");
        restore();
    };
    reject(
            [&] {
                auto stale = receipt;
                stale["recipe"]["version"] = "stale";
                write_private_json(directory / "qnx-host.json", stale);
            },
            [&] {
                write_private_json(directory / "qnx-host.json", receipt);
            });
    reject(
            [&] {
                auto stale = receipt;
                stale["archive_sha256"] = std::string(64, 'a');
                write_private_json(directory / "qnx-host.json", stale);
            },
            [&] {
                write_private_json(directory / "qnx-host.json", receipt);
            });
    reject(
            [&] {
                std::filesystem::create_hard_link(directory / "zlib1.dll",
                                                  root / "windows-source-alias");
            },
            [&] {
                std::filesystem::remove(root / "windows-source-alias");
            });
    reject(
            [&] {
                write("foreign.dll", "foreign\n");
            },
            [&] {
                std::filesystem::remove(directory / "foreign.dll");
            });
    reject(
            [&] {
                auto changed = payload.at("qemu-system-aarch64.exe");
                changed[0] = '!';
                write("qemu-system-aarch64.exe", changed);
            },
            [&] {
                write("qemu-system-aarch64.exe", payload.at("qemu-system-aarch64.exe"));
            });
    reject(
            [&] {
                auto changed = payload.at("zlib1.dll");
                changed[0] = '!';
                write("zlib1.dll", changed);
            },
            [&] {
                write("zlib1.dll", payload.at("zlib1.dll"));
            });
    reject(
            [&] {
                std::filesystem::create_hard_link(directory / "qemu-system-aarch64.exe",
                                                  root / "windows-source-alias");
            },
            [&] {
                std::filesystem::remove(root / "windows-source-alias");
            });
}

int main(int argc, char **argv) {
    try {
        const auto &c = qnx_host_catalog();

        if (argc == 5 && std::string_view(argv[1]) == "--pack-installed") {
            std::cout << pack_installed(c, argv[2], std::filesystem::absolute(argv[3]),
                                        std::filesystem::absolute(argv[4]))
                                 .dump()
                      << '\n';

            return 0;
        }

        check(c.at("schema") == 1 && c.at("windows_x64").at("version") == "11.1.0",
              "pinned component schema");

        for (const auto *role : {"qemu", "extractor"}) {
            const auto &p = c.at("windows_x64").at(role);
            check(p.at("url").get<std::string>().starts_with("https://") &&
                          p.at("sha256").get<std::string>().size() == 64,
                  "exact HTTPS/SHA pins");
        }

        const auto &mac = c.at("macos_arm64");
        check(mac.at("version") == "11.1.2" && mac.at("system_only_runtime") == true,
              "portable Mac recipe");

        for (const auto *role : {"source", "pkgconf"}) {
            check(mac.at(role).at("sha256").get<std::string>().size() == 64, "Mac source pins");
        }

        check(mac.at("dependencies").size() == 4 && mac.at("python_wheels").size() == 4 &&
                      mac.at("patched_sources").size() == 5,
              "complete pinned Mac build graph");
        const auto root = std::filesystem::canonical(std::filesystem::path(__FILE__)
                                                             .parent_path()
                                                             .parent_path()
                                                             .parent_path()
                                                             .parent_path() /
                                                     ".local/build/tmp") /
                          ("voyemu-qnx-host-" + random_token());
        ensure_private_directory(root);
        struct Cleanup {
            std::filesystem::path root;

            ~Cleanup() {
                std::filesystem::remove_all(root);
            }
        } cleanup{root};
        pack_installed_tests(root);
        pack_windows_source_tests(root);
        bool failed = false;
        try {
            install_qnx_host(root, true, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed &&
                      !std::filesystem::exists(root /
                                               ".local/toolchains/qnx-host-windows-11.1.0") &&
                      !std::filesystem::exists(root / ".local/toolchains/qnx-host.lock"),
              "offline missing input cannot publish and lock released");
        const auto &win = c.at("windows_file_backend");
        check(win.at("version") == "11.1.2" && win.at("patched_sources").size() == 9 &&
                      win.at("dependencies").size() == 6,
              "complete Windows source recipe");
        check(win.at("verified_runtime").at("files").size() == 13 &&
                      win.at("verified_runtime").at("files").contains("licenses/qemu/COPYING") &&
                      win.at("verified_runtime").at("files").contains("licenses/glib2/COPYING") &&
                      win.at("verified_runtime")
                              .at("files")
                              .contains("licenses/libiconv/COPYING.LIB"),
              "Windows runtime retains dependency licenses");
        const auto cache = root /
                           ".local/toolchains/downloads/qnx-host/windows-file-backend-11.1.2";
        ensure_private_directory(cache);
        Json fixture = win;
        fixture["verified_runtime"]["files"] = Json::object();

        for (const auto *name : {"qemu-system-aarch64.exe", "libglib-2.0-0.dll", "libintl-8.dll",
                                 "libiconv-2.dll", "libpcre2-8-0.dll", "zlib1.dll"}) {
            write_private_json(cache / name, Json{{"fixture", name}});
            fixture["verified_runtime"]["files"][name] = {
                    {"sha256", sha256_file(cache / name)},
                    {"bytes", std::filesystem::file_size(cache / name)}};
        }

        fixture["verified_runtime"]["qnx_file_backend"]["engine_sha256"] =
                sha256_file(cache / "qemu-system-aarch64.exe");
        const auto installed_windows = install_cached_windows_qnx_host(root, fixture, 0);
        check(installed_windows.at("cached") == false &&
                      installed_windows.at("qnx_file_backend") ==
                              fixture.at("verified_runtime").at("qnx_file_backend"),
              "Windows cached engine installs capability");
        check(install_cached_windows_qnx_host(root, fixture, 0).at("cached") == true,
              "Windows installed engine validates without rebuild");
        const std::filesystem::path installed_directory =
                installed_windows.at("directory").get<std::string>();
        write_private_json(installed_directory / "zlib1.dll", Json{{"foreign", true}});
        failed = false;
        try {
            install_cached_windows_qnx_host(root, fixture, 0);
        } catch (...) {
            failed = true;
        }

        check(failed, "changed installed DLL rejected");
        std::filesystem::remove_all(installed_directory);
        write_private_json(cache / "foreign.dll", Json{{"foreign", true}});
        failed = false;
        try {
            install_cached_windows_qnx_host(root, fixture, 0);
        } catch (...) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(installed_directory),
              "unselected runtime DLL rejected before publish");
        std::filesystem::remove(cache / "foreign.dll");
        const auto moved_cache = root / "moved-cache";
        std::filesystem::rename(cache, moved_cache);
        std::filesystem::create_directory_symlink(moved_cache, cache);
        failed = false;
        try {
            install_cached_windows_qnx_host(root, fixture, 0);
        } catch (...) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(installed_directory),
              "linked runtime directory rejected");
        std::filesystem::remove(cache);
        std::filesystem::rename(moved_cache, cache);
        const auto cache_parent = cache.parent_path(), moved_parent = root / "moved-cache-parent";
        std::filesystem::rename(cache_parent, moved_parent);
        std::filesystem::create_directory_symlink(moved_parent, cache_parent);
        failed = false;
        try {
            install_cached_windows_qnx_host(root, fixture, 0);
        } catch (...) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(installed_directory),
              "linked runtime parent rejected");
        std::filesystem::remove(cache_parent);
        std::filesystem::rename(moved_parent, cache_parent);
        install_cached_windows_qnx_host(root, fixture, 0);
        const auto moved_install = root / "moved-install";
        std::filesystem::rename(installed_directory, moved_install);
        std::filesystem::create_directory_symlink(moved_install, installed_directory);
        failed = false;
        try {
            install_cached_windows_qnx_host(root, fixture, 0);
        } catch (...) {
            failed = true;
        }

        check(failed, "linked installed engine directory rejected");
        std::filesystem::remove(installed_directory);
        std::filesystem::remove_all(moved_install);
        auto wrong = fixture;
        wrong["verified_runtime"]["qnx_file_backend"]["engine_sha256"] = std::string(64, '0');
        failed = false;
        try {
            install_cached_windows_qnx_host(root, wrong, 0);
        } catch (...) {
            failed = true;
        }

        check(failed, "capability cannot name a different engine");
        std::filesystem::rename(cache / "zlib1.dll", root / "external.dll");
        std::filesystem::create_symlink(root / "external.dll", cache / "zlib1.dll");
        failed = false;
        try {
            install_cached_windows_qnx_host(root, fixture, 0);
        } catch (...) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(installed_directory),
              "linked runtime payload rejected");
        std::filesystem::remove(cache / "zlib1.dll");
        std::filesystem::rename(root / "external.dll", cache / "zlib1.dll");
        const auto windows_binding = [&](const std::filesystem::path &base) {
            Json value{{"schema", 1},
                       {"qnx_qemu", (base / "qemu-system-aarch64.exe").string()},
                       {"graphics", (base / "voyemu.exe").string()},
                       {"angle", (base / "gles_angle").string()},
                       {"pins", Json::array()},
                       {"qnx_file_backend", {{"schema", 1}, {"version", "11.1.2"}}}};
            const std::string engine_pin(64, '7'), angle = value.at("angle").get<std::string>();
            value["pins"].push_back(
                    {{"path", value.at("qnx_qemu").get<std::string>()}, {"sha256", engine_pin}});
            value["pins"].push_back({{"path", value.at("graphics").get<std::string>()},
                                     {"sha256", std::string(64, '8')}});
            value["pins"].push_back(
                    {{"path", (std::filesystem::path(angle) / "libEGL.dll").string()},
                     {"sha256", std::string(64, '9')}});
            value["pins"].push_back(
                    {{"path", (std::filesystem::path(angle) / "libGLESv2.dll").string()},
                     {"sha256", std::string(64, 'a')}});
            value["qnx_file_backend"]["engine_sha256"] = engine_pin;

            return value;
        };
        const auto binding = qnx_host_bindings_path(root);
        ensure_private_directory(binding.parent_path());
        check(binding.filename() == "installed.json" &&
                      binding == root / ".local/toolchains/installed.json",
              "single shared host binding file");
#ifdef _WIN32
        const auto legacy_windows = root / ".local/toolchains/installed.windows.json";
        const auto windows_section = windows_binding(root / "windows-toolchains");
        const Json flat{{"schema", 1},
                        {"qnx_qemu", "macos-engine"},
                        {"graphics", "macos-self"},
                        {"angle", "macos-angle"},
                        {"pins", Json::array()},
                        {"factory",
                         {{"kind", "voyemu-macos-qnx-host"},
                          {"component_sha256", std::string(64, '0')},
                          {"engine_receipt_sha256", std::string(64, '0')}}}};
        write_private_json(binding, flat);
        bool refused = false;
        try {
            ensure_qnx_host_bindings(root, true);
        } catch (...) {
            refused = true;
        }

        check(refused && read_private_json(binding) == flat,
              "flat shared binding without a legacy Windows file is refused");
        write_private_json(binding, flat);
        write_private_json(legacy_windows, windows_section);
        const auto merged = ensure_qnx_host_bindings(root, true);
        const auto merged_file = read_private_json(binding);
        check(merged == windows_section, "Windows migration did not return the Windows section");

        for (const auto *key : {"schema", "qnx_qemu", "graphics", "angle", "pins", "factory"}) {
            check(merged_file.at(key) == flat.at(key),
                  "macOS factory key changed by Windows migration");
        }

        check(merged_file.size() == flat.size() + 1 && merged_file.at("windows") == windows_section,
              "legacy Windows binding did not migrate into the shared file");
        const auto migrated_bytes = read_private_json(binding);
        check(ensure_qnx_host_bindings(root, true) == windows_section &&
                      read_private_json(binding) == migrated_bytes,
              "repeat Windows migration is not idempotent");
        std::filesystem::remove(legacy_windows);
        {
            const auto section = windows_binding(root / "windows-toolchains");
            write_private_json(binding, {{"schema", 1}, {"windows", section}});
            check(ensure_qnx_host_bindings(root, true) == section,
                  "Windows host binding section is read from the shared file");
        }
        {
            const Json plain{{"schema", 1},
                             {"qnx_qemu", "macos-engine"},
                             {"graphics", "macos-self"},
                             {"angle", "macos-angle"},
                             {"pins", Json::array()}};
            check(qnx_host_binding_view(root, Json{{"schema", 1}, {"windows", windows_section}}) ==
                          windows_section,
                  "Windows binding view returns the shared windows section");
            check(qnx_host_binding_view(root, plain) == plain,
                  "Windows binding view falls back to the flat document without a legacy file");
            write_private_json(legacy_windows, windows_section);
            check(qnx_host_binding_view(root, plain) == windows_section,
                  "Windows binding view reads the legacy adjacent file");
            auto invalid = windows_section;
            invalid["schema"] = 2;
            write_private_json(legacy_windows, invalid);
            check(qnx_host_binding_view(root, plain) == plain,
                  "invalid legacy Windows binding is not substituted");
            std::filesystem::remove(legacy_windows);
        }
#else
        const Json explicit_binding{{"schema", 1}, {"qnx_qemu", "explicit-user-engine"}};
        write_private_json(binding, explicit_binding);
        check(ensure_qnx_host_bindings(root, true) == explicit_binding &&
                      read_private_json(binding) == explicit_binding,
              "explicit host bindings preserved without installation");
        {
            const Json shared_with_windows{{"schema", 1}, {"windows", {{"schema", 1}}}};
            check(qnx_host_binding_view(root, shared_with_windows) == shared_with_windows,
                  "non-Windows binding view stays the flat document");
        }
#endif
#ifdef _WIN32
        if (argc == 3 && std::string(argv[1]) == "--extract") {
            extract_qnx_unpacker(std::filesystem::canonical(argv[2]), root / "unpacker");
            check(std::filesystem::file_size(root / "unpacker/7z.exe") == 575488 &&
                          std::filesystem::file_size(root / "unpacker/7z.dll") == 1906176,
                  "exact ready extractor payload");
            ProcessSpec spec;
            spec.executable = root / "unpacker/7z.exe";
            spec.arguments = {"i"};
            spec.directory = root;
            spec.output = root / "probe.log";
            const auto result = execute(spec, 15000);
            check(result.exit_code == 0 && result.output.find("Nsis") != std::string::npos,
                  "ready extractor supports QEMU archive");
            bool duplicate = false;
            try {
                extract_qnx_unpacker(std::filesystem::canonical(argv[2]), root / "unpacker");
            } catch (...) {
                duplicate = true;
            }

            check(duplicate, "cannot overwrite extractor output");
        }

        if (argc == 3 && std::string(argv[1]) == "--install") {
            const auto actual = std::filesystem::canonical(argv[2]);
            const auto installed = install_qnx_host(actual, true, 0);
            check(installed.at("ready") == true, "offline retained package install");
            check(install_qnx_host(actual, true, 0).at("cached") == true,
                  "installed tree reverified");
            std::cout << installed.dump() << '\n';
        }
#elif defined(__APPLE__)
        const auto diagnostics_stage = root / "diagnostic-source",
                   diagnostics_logs = root / "diagnostic-logs";
        ensure_private_directory(diagnostics_stage / "build/meson-logs");
        write_private_json(diagnostics_stage / "17.log", Json{{"phase", "configure"}});
        write_private_json(diagnostics_stage / "build/config.log",
                           Json{{"failure", "offline pip configure failure"}});
        write_private_json(diagnostics_stage / "build/meson-logs/meson-log.txt",
                           Json{{"phase", "meson"}});
        bool original_preserved = false;
        try {
            QnxHostBuildStage stage(diagnostics_stage, diagnostics_logs);
            throw std::runtime_error("original configure failure");
        } catch (const std::exception &error) {
            original_preserved = std::string(error.what()) == "original configure failure";
        }

        check(original_preserved && !std::filesystem::exists(diagnostics_stage) &&
                      read_private_json(diagnostics_logs / "configure.log").at("failure") ==
                              "offline pip configure failure" &&
                      read_private_json(diagnostics_logs / "17.log").at("phase") == "configure" &&
                      read_private_json(diagnostics_logs / "meson-log.txt").at("phase") == "meson",
              "nested diagnostics survive failure without masking original or leaking stage");
        const auto rejected_logs = root / "diagnostic-logs-file",
                   failed_stage = root / "diagnostic-cleanup-source";
        write_private_json(rejected_logs, Json{{"ordinary", true}});
        ensure_private_directory(failed_stage);
        original_preserved = false;
        try {
            QnxHostBuildStage stage(failed_stage, rejected_logs);
            throw std::runtime_error("original configure failure");
        } catch (const std::exception &error) {
            original_preserved = std::string(error.what()) == "original configure failure";
        }

        check(original_preserved && !std::filesystem::exists(failed_stage) &&
                      read_private_json(rejected_logs).at("ordinary") == true,
              "diagnostic destination failure cannot mask original or prevent source cleanup");
        const auto bounded_stage = root / "diagnostic-bounded-source",
                   bounded_logs = root / "diagnostic-bounded-logs";
        ensure_private_directory(bounded_stage / "build");
        {
            std::ofstream large(bounded_stage / "build/config.log", std::ios::binary);
            large.seekp(5ULL << 20);
            large.put('Z');
        }
        { QnxHostBuildStage stage(bounded_stage, bounded_logs); }
        check(!std::filesystem::exists(bounded_stage) &&
                      std::filesystem::file_size(bounded_logs / "configure.log") <= (4ULL << 20),
              "retained nested log has finite per-file bound");
        const auto linked_stage = root / "diagnostic-linked-source",
                   linked_logs = root / "diagnostic-linked-logs",
                   external = root / "diagnostic-external";
        ensure_private_directory(linked_stage / "build");
        write_private_json(external, Json{{"private", true}});
        std::filesystem::create_symlink(external, linked_stage / "build/config.log");
        { QnxHostBuildStage stage(linked_stage, linked_logs); }
        check(!std::filesystem::exists(linked_stage) &&
                      !std::filesystem::exists(linked_logs / "configure.log") &&
                      read_private_json(external).at("private") == true,
              "nested symlink cannot copy or remove external diagnostic");
        const auto component_pin = sha256_bytes(mac.dump());
        const auto legacy = root / ".local/toolchains/qnx-host-macos-11.1.2",
                   current = root / ".local/toolchains" /
                             ("qnx-host-macos-11.1.2-" +
                              qnx_host_cache_key(component_pin,
                                                 qnx_host_prebuilt_pin(c, "macos_arm64")
                                                         .at("sha256")
                                                         .get<std::string>()));
        ensure_private_directory(legacy);
        const Json old_receipt{{"component_sha256", "old-recipe"},
                               {"executable_sha256", "old-binary"}};
        write_private_json(legacy / "qnx-host.json", old_receipt);
        write_private_json(legacy / "qemu-system-aarch64", Json{{"legacy", true}});
        const auto old_binary_pin = sha256_file(legacy / "qemu-system-aarch64");
        failed = false;
        try {
            install_qnx_host(root, true, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(current) &&
                      read_private_json(legacy / "qnx-host.json") == old_receipt &&
                      sha256_file(legacy / "qemu-system-aarch64") == old_binary_pin,
              "new recipe cannot overwrite legacy installation");
        ensure_private_directory(current);
        write_private_json(current / "qemu-system-aarch64", Json{{"fixture", true}});
        const auto binary_pin = sha256_file(current / "qemu-system-aarch64");
        auto colliding_pin = component_pin;
        colliding_pin.back() = colliding_pin.back() == '0' ? '1' : '0';
        write_private_json(current / "qnx-host.json", Json{{"component_sha256", colliding_pin},
                                                           {"executable_sha256", binary_pin}});
        failed = false;
        try {
            install_qnx_host(root, true, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed, "matching path prefix cannot bypass full recipe SHA");
        write_private_json(
                current / "qnx-host.json",
                Json{{"component_sha256", component_pin},
                     {"executable_sha256", binary_pin},
                     {"recipe", mac},
                     {"archive_sha256", qnx_host_prebuilt_pin(c, "macos_arm64").at("sha256")}});
        const auto installed_fixture = install_qnx_host(root, true, 0);
        check(installed_fixture.at("cached") == true &&
                      installed_fixture.at("directory") == current.string() && current != legacy,
              "new recipe uses distinct validated cache path");
        check(read_private_json(legacy / "qnx-host.json") == old_receipt &&
                      sha256_file(legacy / "qemu-system-aarch64") == old_binary_pin,
              "new recipe cache preserves old receipt and executable");

        // One recognized legacy factory migrates; explicit user bindings remain untouched.
        auto legacy_recipe = mac;
        legacy_recipe["patch"]["sha256"] =
                "ff41121e355d2c95532f176121af2b971d468e5d614e9ae2d794e1318f6e8d5b";
        legacy_recipe["patched_sources"]["hw/intc/arm_gicv3_hvf_mmio.h"] =
                "f283d2840651cc9f02596ef56a1568ad58e6f1165554e32a8cde61749207ac37";
        const auto legacy_component = sha256_bytes(legacy_recipe.dump());
        check(legacy_component ==
                      "da0ad5ed17d8db183366e25702f7d6214745849b70c66df1a04d5be527348edc",
              "exact historical factory recipe reconstructed");
        write_private_json(legacy / "qnx-host.json", {{"component_sha256", legacy_component},
                                                      {"executable_sha256", old_binary_pin},
                                                      {"recipe", legacy_recipe}});
        const auto program = root / "voyemu",
                   angle = root / ".local/toolchains/native-sdk/emulator/lib64/gles_angle";
        ensure_private_directory(angle);
        write_private_json(program, Json{{"current-self", true}});
        write_private_json(angle / "libEGL.dylib", Json{{"EGL", true}});
        write_private_json(angle / "libGLESv2.dylib", Json{{"GLES", true}});
        Json managed_old = {{"schema", 1},
                            {"qnx_qemu", (legacy / "qemu-system-aarch64").string()},
                            {"graphics", program.string()},
                            {"angle", angle.string()},
                            {"pins", Json::array()}};

        for (const auto &file : {legacy / "qemu-system-aarch64", program, angle / "libEGL.dylib",
                                 angle / "libGLESv2.dylib"}) {
            managed_old["pins"].push_back(
                    {{"path", file.string()},
                     {"sha256", file == program ? std::string(64, 'a') : sha256_file(file)}});
        }

        write_private_json(binding, managed_old);
        const auto binding_pin = sha256_file(binding);
        const auto migrated = ensure_qnx_host_bindings(root, true);
        check(migrated.at("qnx_qemu") == (current / "qemu-system-aarch64").string() &&
                      migrated.contains("factory") &&
                      migrated.at("pins").at(1).at("sha256") == sha256_file(program),
              "managed factory did not upgrade engine/current self");
        check(sha256_file(binding.parent_path() /
                          ("portable-host-" + binding_pin + ".previous.json")) == binding_pin &&
                      read_private_json(legacy / "qnx-host.json").at("component_sha256") ==
                              legacy_component &&
                      sha256_file(legacy / "qemu-system-aarch64") == old_binary_pin,
              "migration snapshot/legacy preservation failed");
        const auto migrated_identity = cache_file_identity(binding);
        check(ensure_qnx_host_bindings(root, true) == migrated &&
                      cache_file_identity(binding) == migrated_identity,
              "current managed factory unexpectedly rewritten");
        write_private_json(program, Json{{"new-current-self", true}});
        const auto self_refreshed = ensure_qnx_host_bindings(root, true);
        check(self_refreshed.at("qnx_qemu") == migrated.at("qnx_qemu") &&
                      self_refreshed.at("pins").at(1).at("sha256") == sha256_file(program) &&
                      self_refreshed.at("pins").at(0) == migrated.at("pins").at(0),
              "managed self refresh changed engine");
        auto rejects_managed = [&](Json value) {
            write_private_json(binding, value);
            const auto before = sha256_file(binding);
            bool rejected = false;
            try {
                ensure_qnx_host_bindings(root, true);
            } catch (...) {
                rejected = true;
            }

            check(rejected && sha256_file(binding) == before,
                  "invalid managed binding was installed");
        };
        auto malformed = self_refreshed;
        malformed["factory"]["component_sha256"] = std::string(64, '0');
        rejects_managed(malformed);
        malformed = self_refreshed;
        malformed["pins"][0]["sha256"] = std::string(64, '0');
        rejects_managed(malformed);
        malformed = self_refreshed;
        malformed["pins"][3] = malformed["pins"][2];
        rejects_managed(malformed);
        const auto lockfile = binding.string() + ".factory.lock";
        const int held = ::open(lockfile.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        check(held >= 0 && ::flock(held, LOCK_EX | LOCK_NB) == 0, "fixture factory lock");
        bool locked = false;
        try {
            ensure_qnx_host_bindings(root, true);
        } catch (const std::exception &error) {
            locked = std::string(error.what()).find("already in preparation") != std::string::npos;
        }

        ::close(held);
        check(locked, "concurrent factory publication was not rejected");
        std::string mutable_record = "old", foreign_record = "foreign";
        unsigned writes = 0;
        bool foreign_rejected = false;
        try {
            publish_host_refresh(
                    std::array<HostRefreshRecord, 3>{{{binding, "old", "ours"}, {}, {}}},
                    [&](const auto &) {
                        return mutable_record;
                    },
                    [&](const auto &, const auto &bytes) {
                        ++writes;
                        mutable_record = bytes;
                    },
                    [&] {
                        mutable_record = foreign_record;
                    });
        } catch (...) {
            foreign_rejected = true;
        }

        check(foreign_rejected && mutable_record == foreign_record && writes == 0,
              "foreign binding replaced during recognition/publication was overwritten");

        // One shared file carries the macOS factory keys and the Windows binding section; a legacy
        // adjacent file migrates into it.
        write_private_json(binding, self_refreshed);
        const auto legacy_windows = root / ".local/toolchains/installed.windows.json";
        const auto windows_section = windows_binding(root / "windows-toolchains");
        write_private_json(legacy_windows, windows_section);
        const auto unified = ensure_qnx_host_bindings(root, true);

        for (const auto *key : {"schema", "qnx_qemu", "graphics", "angle", "pins", "factory"}) {
            check(unified.at(key) == self_refreshed.at(key),
                  "macOS factory key changed by Windows unification");
        }

        check(unified.size() == self_refreshed.size() + 1 &&
                      unified.at("windows") == windows_section &&
                      read_private_json(binding) == unified,
              "legacy Windows binding did not migrate into the shared file");
        const auto unified_bytes = read_private_json(binding);
        check(ensure_qnx_host_bindings(root, true) == unified &&
                      read_private_json(binding) == unified_bytes,
              "macOS Windows-section unification is not idempotent");
        std::filesystem::remove(legacy_windows);
        const auto kept = ensure_qnx_host_bindings(root, true);
        check(kept == unified && read_private_json(binding) == unified,
              "macOS refresh dropped the inherited Windows section once the legacy file was gone");
        // A legacy Windows record is read on macOS too; its path spelling is not a native POSIX
        // path.
        const auto foreign_windows = Json{
                {"schema", 1},
                {"qnx_qemu", R"(Z:\Users\owner\voyemu\qemu-system-aarch64.exe)"},
                {"graphics", R"(Z:\Users\owner\voyemu\voyemu.exe)"},
                {"angle", R"(Z:\Users\owner\voyemu\gles_angle)"},
                {"pins",
                 Json::array({{{"path", R"(Z:\Users\owner\voyemu\qemu-system-aarch64.exe)"},
                               {"sha256", std::string(64, '7')}},
                              {{"path", R"(Z:\Users\owner\voyemu\voyemu.exe)"},
                               {"sha256", std::string(64, '8')}},
                              {{"path", R"(Z:\Users\owner\voyemu\gles_angle\libEGL.dll)"},
                               {"sha256", std::string(64, '9')}},
                              {{"path", R"(Z:\Users\owner\voyemu\gles_angle\libGLESv2.dll)"},
                               {"sha256", std::string(64, 'a')}}})},
                {"qnx_file_backend",
                 {{"schema", 1}, {"version", "11.1.2"}, {"engine_sha256", std::string(64, '7')}}}};

        for (unsigned mode = 0; mode < 2; ++mode) {
            auto section = foreign_windows;

            if (mode == 1) {
                section["qnx_qemu"] = "Z:/Users/owner/voyemu/qemu-system-aarch64.exe";
                section["pins"][0]["path"] = section.at("qnx_qemu");
            }

            write_private_json(binding, self_refreshed);
            write_private_json(legacy_windows, section);
            const auto joined = ensure_qnx_host_bindings(root, true);
            check(joined.at("windows") == section,
                  "foreign Windows paths lost their exact spelling during migration");
            const auto joined_identity = cache_file_identity(binding);
            check(ensure_qnx_host_bindings(root, true) == joined &&
                          cache_file_identity(binding) == joined_identity,
                  "foreign Windows migration is not idempotent");
        }

        auto rejects_windows = [&](Json value) {
            write_private_json(binding, self_refreshed);
            write_private_json(legacy_windows, value);
            const auto before = sha256_file(binding);
            bool rejected = false;
            try {
                ensure_qnx_host_bindings(root, true);
            } catch (...) {
                rejected = true;
            }

            check(rejected && sha256_file(binding) == before,
                  "invalid Windows binding section was installed");
        };
        {
            auto value = foreign_windows;
            value["qnx_qemu"] = R"(Z:\Users\owner\voyemu\qemu-system-aarch64.exe.bak)";
            value["pins"][0]["path"] = value.at("qnx_qemu");
            rejects_windows(value);
        }
        {
            auto value = foreign_windows;
            value["pins"][2]["path"] = R"(Z:\Users\owner\voyemu\foreign\libEGL.dll)";
            rejects_windows(value);
        }
        {
            auto value = foreign_windows;
            value["pins"][3] = value["pins"][2];
            rejects_windows(value);
        }
        {
            auto value = foreign_windows;
            value["pins"][3] = value["pins"][2];
            value["pins"][3]["path"] = "Z:/Users/owner/voyemu/gles_angle/libEGL.dll";
            rejects_windows(value);
        }
        {
            auto value = foreign_windows;
            value["qnx_file_backend"]["engine_sha256"] = std::string(64, '0');
            rejects_windows(value);
        }
        {
            auto value = windows_section;
            value["schema"] = 2;
            rejects_windows(value);
        }
        {
            auto value = windows_section;
            value["angle"] = program.string();
            rejects_windows(value);
        }
        {
            auto value = windows_section;
            value["qnx_file_backend"]["engine_sha256"] = std::string(64, '0');
            rejects_windows(value);
        }
        std::filesystem::remove(legacy_windows);

        write_private_json(binding, explicit_binding);
        const auto custom_identity = cache_file_identity(binding);
        check(ensure_qnx_host_bindings(root, true) == explicit_binding &&
                      cache_file_identity(binding) == custom_identity,
              "explicit custom binding was refreshed");

        if (argc == 3 && std::string(argv[1]) == "--install") {
            const auto actual = std::filesystem::canonical(argv[2]);
            const auto installed = install_qnx_host(actual, false);
            check(installed.at("ready") == true, "Mac pinned source install");
            check(install_qnx_host(actual, true).at("cached") == true,
                  "Mac receipt reverified offline");
            std::cout << installed.dump() << '\n';
        }

        // The qnx-host workflow builds the engine from the recipe even when a prebuilt pin exists
        // and packs the installed directory with its receipt into the release asset.
        if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--source-root") {
            const auto actual = std::filesystem::canonical(argv[2]);
            const auto installed = install_qnx_host_macos(actual, false, 0, true);
            check(installed.at("ready") == true && installed.at("cached") == false,
                  "Mac recipe source install");

            if (argc == 4) {
                write_qnx_host_asset(installed.at("directory").get<std::string>(), argv[3], true,
                                     "macos-arm64");
            }

            std::cout << installed.dump() << '\n';
        }
#elif defined(__linux__) && defined(__x86_64__)
        const auto &linux_recipe = c.at("linux_x64");
        check(linux_recipe.at("version") == "11.1.2" &&
                      linux_recipe.at("source") == mac.at("source") &&
                      linux_recipe.at("dependencies").size() == 5 &&
                      linux_recipe.at("python_wheels") == mac.at("python_wheels") &&
                      linux_recipe.at("compiler").at("target") == "x86_64-linux-gnu.2.34",
              "complete pinned Linux build graph");
        // The engine links only the system C library of the glibc baseline.
        const auto needed = qnx_host_elf_needed(std::filesystem::canonical("/proc/self/exe"));
        check(std::find(needed.begin(), needed.end(), "libc.so.6") != needed.end(),
              "ELF dependencies of a dynamic executable");
        const auto linux_pin = sha256_bytes(linux_recipe.dump());
        const auto engine_directory =
                root / ".local/toolchains" /
                ("qnx-host-linux-11.1.2-" +
                 qnx_host_cache_key(
                         linux_pin,
                         qnx_host_prebuilt_pin(c, "linux_x64").at("sha256").get<std::string>()));
        ensure_private_directory(engine_directory);
        write_private_json(engine_directory / "qemu-system-aarch64", Json{{"engine", true}});
        const auto engine_pin = sha256_file(engine_directory / "qemu-system-aarch64");
        write_private_json(engine_directory / "qnx-host.json",
                           Json{{"component_sha256", std::string(64, '0')},
                                {"executable_sha256", engine_pin}});
        bool linux_failed = false;
        try {
            install_qnx_host(root, true, 0);
        } catch (const std::exception &) {
            linux_failed = true;
        }

        check(linux_failed, "installed Linux engine of another recipe accepted");
        write_private_json(
                engine_directory / "qnx-host.json",
                Json{{"component_sha256", linux_pin},
                     {"executable_sha256", engine_pin},
                     {"recipe", linux_recipe},
                     {"archive_sha256", qnx_host_prebuilt_pin(c, "linux_x64").at("sha256")}});
        const auto linux_installed = install_qnx_host(root, true, 0);
        check(linux_installed.at("cached") == true &&
                      linux_installed.at("executable") ==
                              (engine_directory / "qemu-system-aarch64").string(),
              "installed Linux engine reverified offline");
        // A fresh shared binding file gets the factory binding of the Linux engine and ANGLE.
        const auto program = root / "voyemu",
                   angle = root / ".local/toolchains/native-sdk/emulator/lib64/gles_angle";
        ensure_private_directory(angle);
        write_private_json(program, Json{{"self", true}});
        write_private_json(angle / "libEGL.so", Json{{"EGL", true}});
        write_private_json(angle / "libGLESv2.so", Json{{"GLES", true}});
        std::filesystem::remove(binding);
        const auto factory = ensure_qnx_host_bindings(root, true);
        check(factory.at("qnx_qemu") == (engine_directory / "qemu-system-aarch64").string() &&
                      factory.at("angle") == angle.string() &&
                      factory.at("factory").at("kind") == "voyemu-linux-qnx-host" &&
                      factory.at("pins").size() == 4 &&
                      factory.at("pins").at(2).at("path") == (angle / "libEGL.so").string() &&
                      read_private_json(binding) == factory,
              "Linux factory binding");
        const auto factory_identity = cache_file_identity(binding);
        check(ensure_qnx_host_bindings(root, true) == factory &&
                      cache_file_identity(binding) == factory_identity,
              "current Linux factory binding rewritten");
        write_private_json(program, Json{{"new-self", true}});
        const auto refreshed = ensure_qnx_host_bindings(root, true);
        check(refreshed.at("pins").at(1).at("sha256") == sha256_file(program) &&
                      refreshed.at("pins").at(0) == factory.at("pins").at(0),
              "Linux factory self refresh");
        auto tampered = refreshed;
        tampered["pins"][2]["sha256"] = std::string(64, '0');
        write_private_json(binding, tampered);
        linux_failed = false;
        try {
            ensure_qnx_host_bindings(root, true);
        } catch (const std::exception &) {
            linux_failed = true;
        }

        check(linux_failed && read_private_json(binding) == tampered,
              "changed Linux ANGLE pin accepted");

        // The qnx-host workflow builds the engine from the recipe and packs the installed
        // directory with its receipt into the release asset.
        if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--source-root") {
            const auto actual = std::filesystem::canonical(argv[2]);
            const auto installed = install_qnx_host_linux(actual, false, 0, true);
            check(installed.at("ready") == true && installed.at("cached") == false,
                  "Linux recipe source install");

            if (argc == 4) {
                write_qnx_host_asset(installed.at("directory").get<std::string>(), argv[3], true,
                                     "linux-x64");
            }

            std::cout << installed.dump() << '\n';
        }

        // The installed engine boots an AArch64 guest with the machine, translation, clock and
        // shared RAM file of the QNX launch: the guest writes a line to the PL011 UART and powers
        // off through PSCI.
        if (argc == 3 && std::string(argv[1]) == "--boot") {
            const auto actual = std::filesystem::canonical(argv[2]);
            Json engine;
            try {
                engine = install_qnx_host(actual, true, 0);
            } catch (const std::exception &error) {
                std::cerr << "Installed QNX engine required: " << error.what() << '\n';

                return 77;
            }

            // movz x1, #0x0900, lsl #16; adr x2, message; 1: ldrb w3, [x2], #1; cbz w3, 2f;
            // strb w3, [x1]; b 1b; 2: movz x0, #8; movk x0, #0x8400, lsl #16; smc #0; hvc #0;
            // 3: wfi; b 3b; message: "VOYEMU QNX ENGINE BOOT\n"
            const std::array<std::uint32_t, 20> guest{
                    0xd2a12001, 0x10000162, 0x38401443, 0x34000063, 0x39000023,
                    0x17fffffd, 0xd2800100, 0xf2b08000, 0xd4000003, 0xd4000002,
                    0xd503207f, 0x17ffffff, 0x45594f56, 0x5120554d, 0x4520584e,
                    0x4e49474e, 0x4f422045, 0x000a544f, 0x00000000, 0x00000000};
            const auto session = root / "boot";
            ensure_private_directory(session);
            {
                std::ofstream image(session / "guest.bin", std::ios::binary);
                image.write(reinterpret_cast<const char *>(guest.data()),
                            static_cast<std::streamsize>(guest.size() * sizeof(std::uint32_t)));
            }
            // The QMP socket lives in the runtime directory of a session launch, not under the
            // project root, whose length is unbounded and exceeds sun_path in a deep checkout.
            const auto qmp = native_socket_root() / (random_token() + "-qmp.sock");
            const auto launch = qnx_ram_launch(host_qnx_engine);
            ProcessSpec spec;
            spec.executable = engine.at("executable").get<std::string>();
            spec.arguments = {"-machine",
                              launch.machine,
                              "-accel",
                              launch.accelerator,
                              "-cpu",
                              qnx_engine_cpu(host_qnx_engine),
                              "-m",
                              "8192",
                              "-smp",
                              "8",
                              "-nodefaults",
                              "-display",
                              "none",
                              "-qmp",
                              "unix:" + qmp.string() + ",server=on,wait=off",
                              "-nic",
                              "none",
                              "-no-reboot",
                              "-kernel",
                              (session / "guest.bin").string(),
                              "-serial",
                              "file:" + (session / "serial.log").string()};

            for (auto option : launch.options) {
                const auto at = option.find("${SESSION}");

                if (at != std::string::npos) {
                    option.replace(at, 10, session.string());
                }

                spec.arguments.push_back(option);
            }

            spec.directory = session;
            spec.output = session / "engine.log";
            const auto result = execute(spec, 60000);
            std::filesystem::remove(qmp);
            std::ifstream serial(session / "serial.log");
            const std::string line((std::istreambuf_iterator<char>(serial)),
                                   std::istreambuf_iterator<char>());
            check(!result.timed_out && result.exit_code == 0 &&
                          line == "VOYEMU QNX ENGINE BOOT\n" &&
                          std::filesystem::file_size(session / "qnx-ram.bin") == 8ULL << 30,
                  "installed engine boots the guest with the QNX launch");
            std::cout << "QNX engine booted the AArch64 guest: " << engine.at("executable") << '\n';
        }
#else
        (void)argc;
        (void)argv;
#endif

        if (argc == 3 && std::string(argv[1]) == "--install-windows-cached") {
            const auto actual = std::filesystem::canonical(argv[2]);
            const auto installed = install_cached_windows_qnx_host(actual, win, 0);
            check(installed.at("ready") == true &&
                          installed.at("qnx_file_backend") ==
                                  win.at("verified_runtime").at("qnx_file_backend"),
                  "actual pinned Windows runtime installed");
            check(install_cached_windows_qnx_host(actual, win, 0).at("cached") == true,
                  "actual pinned Windows runtime offline reuse");
            std::cout << installed.dump() << '\n';
        }

        std::cout << "QNX host pins and installation guards passed\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
