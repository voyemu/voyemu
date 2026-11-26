#include "java_toolchain.hpp"
#include "error.hpp"
#include "java_runtime.hpp"
#include "os/https.hpp"
#include "os/platform.hpp"
#include "process.hpp"
#include "project_files.hpp"
#include "quickboot.hpp"
#include "toolchain_manifest.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <miniz.h>
#include <source_location>
#include <stdexcept>
using namespace voyemu;
namespace {
void check(bool value, const std::source_location where = std::source_location::current()) {
    if (!value) {
        throw std::runtime_error("Java toolchain check failed at " + std::to_string(where.line()) +
                                 ":" + std::to_string(where.column()));
    }
}

std::string read(const std::filesystem::path &p) {
    std::ifstream in(p, std::ios::binary);

    check(bool(in));

    return std::string((std::istreambuf_iterator<char>(in)), {});
}

std::string zip(const std::map<std::string, std::string> &entries) {
    mz_zip_archive archive{};

    check(mz_zip_writer_init_heap(&archive, 0, 0));

    for (const auto &[name, bytes] : entries) {
        check(mz_zip_writer_add_mem(&archive, name.c_str(), bytes.data(), bytes.size(),
                                    MZ_DEFAULT_COMPRESSION));
    }

    void *data = nullptr;
    std::size_t size = 0;
    check(mz_zip_writer_finalize_heap_archive(&archive, &data, &size));
    std::string result(static_cast<const char *>(data), size);
    mz_zip_writer_end(&archive);

    return result;
}

// A fixture checkout with one helper source and one library, the java-helper.zip built from it and
// a recipe that writes the same helper.
void helper_installation_checks(const std::filesystem::path &scratch) {
    const auto root = scratch / "checkout";
    auto put = [](const std::filesystem::path &p, const std::string &value) {
        ensure_private_directory(p.parent_path());
        std::ofstream out(p, std::ios::binary);
        out << value;
        out.close();
        check(bool(out));
    };

    put(root / "src/prepare/JavaHelperBuild.java",
        "package com.voyemu.prepare;\n\npublic final class JavaHelperBuild {\n}\n");
    put(root / "src/prepare/java/com/voyemu/prepare/PreparationMain.java", "class A {}\n");
    put(root / "src/prepare/test/fixtures/com/voyemu/prepare/fixture/BuildMarker.java",
        "class B {}\n");
    put(root / "src/guest/android/oem/audio/OemAudioPolicy.java", "policy\n");
    put(root / "src/guest/android/oem/audio/OemAudioPolicyUnavailable.java", "unavailable\n");
    const std::string library = "library", d8 = "d8", apksigner = "apksigner";
    write_private_json(
            root / "src/prepare/libraries.json",
            Json::array({{{"filename", "fixture.jar"}, {"sha256", sha256_bytes(library)}}}));
    write_private_json(root / "src/prepare/toolchain.json",
                       {{"libraries",
                         {{"d8", {{"sha256", sha256_bytes(d8)}}},
                          {"apksigner", {{"sha256", sha256_bytes(apksigner)}}}}}});
    put(root / ".local/toolchains/java-sdk/build-tools/36.1.0/lib/d8.jar", d8);
    put(root / ".local/toolchains/java-sdk/build-tools/36.1.0/lib/apksigner.jar", apksigner);
    const auto jar = zip({{"com/voyemu/prepare/PreparationMain.class", "class"}});
    const auto inputs = java_helper_source_inputs(root);
    auto receipt = [&] {
        Json dependencies = Json::array();

        for (const auto &[file, bytes] :
             std::map<std::string, std::string>{{"lib/fixture.jar", library},
                                                {"lib/d8.jar", d8},
                                                {"lib/apksigner.jar", apksigner}}) {
            dependencies.push_back(
                    {{"file", file}, {"sha256", sha256_bytes(bytes)}, {"bytes", bytes.size()}});
        }

        return Json{{"schema", 1},
                    {"kind", "java-preparation-helper"},
                    {"java_release", 25},
                    {"jar", "voyemu-java-helper.jar"},
                    {"sha256", sha256_bytes(jar)},
                    {"bytes", jar.size()},
                    {"dependencies", dependencies}}
                .dump();
    };
    const auto asset = zip({{"voyemu-java-helper.jar", jar},
                            {"build-receipt.json", receipt()},
                            {"lib/fixture.jar", library}});
    const Json pin = {{"url", "https://github.com/voyemu/voyemu/releases/download/java-helper-0/"
                              "java-helper.zip"},
                      {"sha256", sha256_bytes(asset)}};
    const auto folder = root / ".local/toolchains/java-helper" / sha256_bytes(inputs.dump());
    int served = 0, built = 0;
    auto serve = [&](const std::string &bytes) {
        return DownloadTransport([&served, bytes](const DownloadPin &, const DownloadSink &sink) {
            ++served;
            sink(bytes);
        });
    };
    const DownloadTransport missing = [](const DownloadPin &, const DownloadSink &) {
        throw os::HttpsFailure(os::HttpsFailure::Kind::status, 404, "fixture");
    };
    const auto recipe = [&](const std::filesystem::path &, const std::filesystem::path &output) {
        ++built;
        put(output / "voyemu-java-helper.jar", jar);
        put(output / "build-receipt.json", receipt());
        put(output / "lib/fixture.jar", library);
        put(output / "lib/d8.jar", d8);
        put(output / "lib/apksigner.jar", apksigner);
    };
    const auto absent = [](const std::filesystem::path &, const std::filesystem::path &) {
        throw VoyemuError("JAVA_HELPER_ASSET_MISSING", "fixture recipe without a JDK");
    };
    auto clear = [&] {
        std::filesystem::remove_all(root / ".local/toolchains/java-helper");
        std::filesystem::remove_all(root / ".local/toolchains/downloads");
        served = built = 0;
    };
    auto failure = [](const std::function<void()> &action) {
        try {
            action();
        } catch (const std::exception &error) {
            return std::string(error.what());
        }

        return std::string();
    };

    // A checkout builds once for the actual input key, never adopting an older release helper.
    check(install_java_helper(root, pin, false, 0, serve(asset), recipe) == folder && served == 0 &&
          built == 1);
    check(read(folder / "lib/d8.jar") == d8 && read(folder / "lib/apksigner.jar") == apksigner &&
          read(folder / "voyemu-java-helper.jar") == jar &&
          !read_private_json(folder / "toolchain-receipt.json").contains("inputs") &&
          !read_private_json(folder / "build-receipt.json").contains("sources"));
    check(install_java_helper(root, pin, true, 0, missing, absent) == folder && served == 0 &&
          built == 1);
    // An unpublished asset falls back to the recipe, also offline without a cached asset.
    clear();
    check(install_java_helper(root, pin, false, 0, missing, recipe) == folder && built == 1);
    clear();
    check(install_java_helper(root, pin, true, 0, missing, recipe) == folder && built == 1);
    // Without an asset and without a recipe JDK the asset is reported missing.
    clear();
    check(failure([&] {
              install_java_helper(root, pin, false, 0, missing, absent);
          }).starts_with("JAVA_HELPER_ASSET_MISSING:") &&
          !std::filesystem::exists(folder));
    // Output corruption and external dependency changes are still rejected.
    clear();
    check(install_java_helper(root, pin, false, 0, missing, recipe) == folder);
    put(folder / "voyemu-java-helper.jar", "changed");
    check(!failure([&] {
               install_java_helper(root, pin, true, 0, missing, absent);
           }).empty());
    put(folder / "voyemu-java-helper.jar", jar);
    put(folder / "lib/fixture.jar", "changed dependency");
    check(!failure([&] {
               install_java_helper(root, pin, true, 0, missing, absent);
           }).empty());
    put(folder / "lib/fixture.jar", library);
    const auto ownership = read_private_json(folder / "toolchain-receipt.json");
    auto foreign = ownership;
    foreign["fingerprint"] = std::string(64, '0');
    write_private_json(folder / "toolchain-receipt.json", foreign);
    check(!failure([&] {
               install_java_helper(root, pin, true, 0, missing, absent);
           }).empty());
    std::filesystem::remove(folder / "toolchain-receipt.json");
    put(folder / "foreign.txt", "preserve this file");
    check(!failure([&] {
               install_java_helper(root, pin, true, 0, missing, absent);
           }).empty() &&
          !std::filesystem::exists(folder / "toolchain-receipt.json") &&
          read(folder / "foreign.txt") == "preserve this file" && built == 1);
    write_private_json(folder / "toolchain-receipt.json", ownership);
    std::filesystem::remove(folder / "foreign.txt");
    // A changed helper source selects a new folder and invokes the recipe.
    put(root / "src/prepare/java/com/voyemu/prepare/PreparationMain.java", "class C {}\n");
    check(java_helper_source_inputs(root) != inputs);
    const auto changed = install_java_helper(root, pin, false, 0, serve(asset), recipe);
    check(changed != folder && built == 2 && served == 0 && std::filesystem::exists(folder));
    // Source-free installations select the pinned release without touching a recipe or sources.
    const auto installation = scratch / "installed-helper";
    ensure_private_directory(installation);
    const auto installed_inputs = java_helper_source_inputs(installation);
    check(!installed_inputs.contains("sources") && installed_inputs.contains("asset_sha256"));
    int installed_downloads = 0, installed_builds = 0;
    const auto bad_asset = DownloadTransport([&](const DownloadPin &, const DownloadSink &sink) {
        ++installed_downloads;
        sink("not the pinned asset");
    });
    check(failure([&] {
              install_java_helper(installation, pin, false, 0, bad_asset,
                                  [&](const auto &, const auto &) {
                                      ++installed_builds;
                                  });
          }).starts_with("DOWNLOAD_SHA:") &&
          installed_downloads == 1 && installed_builds == 0);
    std::cout
            << "PASS helper cache rebuild/reuse, output/dependency guards and source-free asset pin\n";
}

// The dependency fixture uses prepared external JARs; the destination has no sources or JDK.
void installed_helper_checks(const std::filesystem::path &source_root) {
    const auto root = source_root / ".local/build/tmp" /
                      ("installed-helper-test-" + random_token());

    ensure_private_directory(root);
    std::map<std::string, std::string> entries;
    Json dependencies = Json::array();
    auto add = [&](const std::string &name, const std::filesystem::path &file,
                   const std::string &expected, bool sdk) {
        const auto value = read(file);
        check(sha256_bytes(value) == expected);
        dependencies.push_back(
                {{"file", "lib/" + name}, {"sha256", expected}, {"bytes", value.size()}});

        if (sdk) {
            const auto copy = root / ".local/toolchains/java-sdk/build-tools/36.1.0/lib" / name;
            ensure_private_directory(copy.parent_path());
            std::filesystem::copy_file(file, copy);
        } else {
            entries["lib/" + name] = value;
        }
    };

    for (const auto &library : project_file_json(root, "src/prepare/libraries.json", 256 * 1024)) {
        const auto name = library.at("filename").get<std::string>();
        add(name, source_root / ".local/toolchains/java/libraries" / name,
            library.at("sha256").get<std::string>(), false);
    }

    const auto tools = project_file_json(root, "src/prepare/toolchain.json", 256 * 1024);

    for (const auto *name : {"d8", "apksigner"}) {
        const auto file = std::string(name) + ".jar";
        add(file, source_root / ".local/toolchains/java-sdk/build-tools/36.1.0/lib" / file,
            tools.at("libraries").at(name).at("sha256").get<std::string>(), true);
    }

    const auto jar = zip({{"com/voyemu/prepare/PreparationMain.class", "fixture entrypoint"}});
    entries["voyemu-java-helper.jar"] = jar;
    entries["build-receipt.json"] = Json{
            {"schema", 1},
            {"kind", "java-preparation-helper"},
            {"java_release", 25},
            {"jar", "voyemu-java-helper.jar"},
            {"sha256", sha256_bytes(jar)},
            {"bytes", jar.size()},
            {"dependencies", dependencies}}.dump();
    const auto asset = zip(entries);
    const Json pin = {{"url", "https://fixture.invalid/java-helper.zip"},
                      {"sha256", sha256_bytes(asset)}};
    int downloads = 0, builds = 0;
    DownloadTransport serve = [&](const DownloadPin &, const DownloadSink &sink) {
        ++downloads;
        sink(asset);
    };
    const auto folder = install_java_helper(root, pin, false, 0, serve,
                                            [&](const auto &, const auto &) {
                                                ++builds;
                                            });
    check(downloads == 1 && builds == 0 && !std::filesystem::exists(root / "src") &&
          !std::filesystem::exists(root / ".local/toolchains/jdk") &&
          read(folder / "voyemu-java-helper.jar") == jar);
    const auto owner = read_private_json(folder / "toolchain-receipt.json");
    check(!owner.contains("inputs") && owner.at("helper_sha256") == sha256_bytes(jar));
    check(install_java_helper(root, pin, true, 0, {},
                              [&](const auto &, const auto &) {
                                  ++builds;
                              }) == folder &&
          downloads == 1 && builds == 0);
    // A ready launcher inside a checkout still uses the asset unless --jdk selected a recipe.
    ensure_private_directory(root / "src/prepare");

    for (const auto *file : {"libraries.json", "toolchain.json"}) {
        std::filesystem::copy_file(source_root / "src/prepare" / file, root / "src/prepare" / file);
    }

    ensure_private_directory(root / "src/prepare/java/com/voyemu/prepare");
    {
        std::ofstream source(root / "src/prepare/java/com/voyemu/prepare/PreparationMain.java");
        source << "This fixture must never be compiled without an explicit recipe request.\n";
        check(bool(source));
    }
    check(project_source_checkout(root));
    check(java_helper_source_inputs(root, false).contains("asset_sha256"));
    std::filesystem::remove_all(root / ".local/toolchains/java-helper");
    const auto checkout_folder = install_java_helper(
            root, pin, false, 0, serve,
            [&](const auto &, const auto &) {
                ++builds;
            },
            false);
    check(checkout_folder == folder && downloads == 1 && builds == 0);
    std::filesystem::remove_all(root / ".local/toolchains/java-helper");
    std::filesystem::remove_all(root / ".local/toolchains/downloads");
    const DownloadTransport missing = [](const DownloadPin &, const DownloadSink &) {
        throw os::HttpsFailure(os::HttpsFailure::Kind::status, 404, "fixture");
    };
    bool rejected = false;
    try {
        install_java_helper(
                root, pin, false, 0, missing,
                [&](const auto &, const auto &) {
                    ++builds;
                },
                false);
    } catch (const std::exception &error) {
        rejected = std::string(error.what()).starts_with("JAVA_HELPER_ASSET_MISSING:");
    }

    check(rejected && builds == 0);
    const DownloadTransport unreachable = [](const DownloadPin &, const DownloadSink &) {
        throw os::HttpsFailure(os::HttpsFailure::Kind::unreachable, 0, "fixture");
    };
    bool network = false;
    try {
        install_java_helper(
                root, pin, false, 0, unreachable,
                [&](const auto &, const auto &) {
                    ++builds;
                },
                false);
    } catch (const std::exception &error) {
        network = std::string(error.what()).starts_with("DOWNLOAD_HTTP: no connection");
    }

    check(network && builds == 0);
    std::filesystem::remove_all(root);
    std::cout << "PASS pinned helper installed/reused with or without checkout, no JDK/recipe\n";
}

// The Java of the helper: --jdk when given, otherwise the Java runtime, whose missing asset is
// reported; the recipe of an unpublished helper needs --jdk or the developer JDK.
void selection_checks(const std::filesystem::path &scratch, const std::filesystem::path &jdk) {
    const auto root = scratch / "selection", installation = scratch / "installation";

    // A checkout holds src/; an installation without it has no recipe sources.
    ensure_private_directory(root / "src");
    ensure_private_directory(installation);
    auto failure = [](const std::function<void()> &action) {
        try {
            action();
        } catch (const std::exception &error) {
            return std::string(error.what());
        }

        return std::string();
    };
    const DownloadTransport missing = [](const DownloadPin &, const DownloadSink &) {
        throw os::HttpsFailure(os::HttpsFailure::Kind::status, 404, "fixture");
    };
    const auto &runtime = embedded_toolchain_manifest().at("javaRuntime");
    const auto java_name = "java" + std::string(voyemu::os::executable_suffix);
    // --jdk runs the helper on that JDK and installs no Java runtime.
    check(java_preparation_java(root, jdk, runtime, true, 0, missing) ==
                  std::filesystem::canonical(jdk) / "bin" / java_name &&
          !std::filesystem::exists(root / ".local/toolchains/java-runtime"));
    check(java_helper_recipe_jdk(root, jdk) == jdk);
    // Without it, an unpublished runtime or helper without the developer JDK is reported missing.
    check(failure([&] {
              java_preparation_java(root, {}, runtime, false, 0, missing);
          }).starts_with("JAVA_RUNTIME_ASSET_MISSING:"));
    check(failure([&] {
              java_helper_recipe_jdk(root, {});
          }).starts_with("JAVA_HELPER_ASSET_MISSING:"));
    check(failure([&] {
              java_helper_recipe_jdk(installation, jdk);
          }).starts_with("JAVA_HELPER_ASSET_MISSING:"));
    const Json legacy_helper = Json::object();
    auto compatible_helper = legacy_helper;
    check(profile_preparation_jdk(installation, {}, legacy_helper, false).empty());
    check(profile_preparation_jdk(installation, jdk, legacy_helper, false) == jdk);
    check(failure([&] {
              profile_preparation_jdk(installation, {}, legacy_helper, true);
          }).find("does not support profile build targets") != std::string::npos);
    check(profile_preparation_jdk(root, jdk, legacy_helper, true) == jdk);
    compatible_helper["profileTargetSchema"] = 1;
    check(profile_preparation_jdk(installation, {}, compatible_helper, true).empty());
    const auto local_jdk = java_developer_jdk(root);
    ensure_private_directory(local_jdk / "bin");
    std::ofstream(local_jdk / "bin" / ("javac" + std::string(os::executable_suffix))) << "fixture";
    check(profile_preparation_jdk(root, {}, legacy_helper, true) == local_jdk);
    std::cout << "PASS --jdk selects its java; missing runtime and helper assets reported\n";
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--installed-asset-fixture") {
            installed_helper_checks(std::filesystem::canonical(argv[2]));

            return 0;
        }

        if (argc == 3 && std::string(argv[1]) == "--select") {
            const auto root = std::filesystem::path(__FILE__)
                                      .parent_path()
                                      .parent_path()
                                      .parent_path()
                                      .parent_path();
            const auto scratch = root / ".local/build/tmp" /
                                 ("java-selection-test-" + random_token());
            ensure_private_directory(scratch);
            selection_checks(scratch, std::filesystem::canonical(argv[2]));
            std::filesystem::remove_all(scratch);

            return 0;
        }

        if (argc == 5 && std::string(argv[1]) == "--ensure") {
            const std::string mode = argv[4];
            check(mode == "offline" || mode == "fetch");
            const auto result = ensure_java_preparation_tools(std::filesystem::absolute(argv[2]),
                                                              std::filesystem::absolute(argv[3]),
                                                              mode == "offline", 0);
            std::cout << result.receipt.dump() << '\n';

            return 0;
        }

        check(argc == 1);
        const auto root = std::filesystem::path(__FILE__)
                                  .parent_path()
                                  .parent_path()
                                  .parent_path()
                                  .parent_path();
        const std::string script = "package com.voyemu.prepare;\n\n"
                                   "public final class JavaHelperBuild {\n"
                                   "    public static void main(String[] args) {}\n"
                                   "}\n";
        const auto builder = java_helper_builder_source(script);
        check(builder == script);
        std::string crlf;

        for (char c : script) {
            if (c == '\n') {
                crlf += '\r';
            }

            crlf += c;
        }

        check(java_helper_builder_source(crlf) == builder);
        auto reject = [&](const std::string &input) {
            bool failed = false;
            try {
                java_helper_builder_source(input);
            } catch (const std::runtime_error &e) {
                failed = std::string(e.what()).starts_with("JAVA_TOOLCHAIN:");
            }

            check(failed);
        };
        reject("");
        reject("not shared Java source");
        reject("#!/bin/bash\n" + script);
        reject(script.substr(1));
        reject(script + "\r");
        reject(script + std::string(1, '\0'));
        reject(std::string(256 * 1024 + 1, 'a'));
        bool failed = false;
        try {
            ensure_java_preparation_tools("relative", "relative", true, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed);
        failed = false;
        try {
            ensure_java_preparation_tools(root, "relative", true, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed);
        failed = false;
        try {
            ensure_java_preparation_tools(root, root / ".local/nonexistent-installed-jdk", true, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed);
        const auto temporary = root / ".local/build/tmp" /
                               ("java-helper-publication-test-" + random_token());
        ensure_private_directory(temporary);
        const auto input = temporary / "input.jar", link = temporary / "shared.jar";
        {
            std::ofstream out(input);
            out << "immutable pinned payload";
        }
        const auto input_pin = sha256_file(input);
        std::filesystem::create_hard_link(input, link);
        check(java_toolchain_input_sha256(input) == input_pin &&
              java_toolchain_input_sha256(link) == input_pin);

        // POSIX keeps a root-owned system tool at /usr/bin/env.
        if (!voyemu::os::host_windows) {
            // A system JDK is installed root-owned; its executables are immutable inputs too.
            const std::filesystem::path system_tool = "/usr/bin/env";
            check(java_toolchain_input_sha256(system_tool) == sha256_file(system_tool));
        }

        bool cache_rejected = false;
        try {
            cache_file_identity(input);
        } catch (const std::exception &) {
            cache_rejected = true;
        }

        check(cache_rejected);
        auto rejects_input = [&](const std::filesystem::path &path, std::uint64_t bound,
                                 const std::function<void()> &change = {}) {
            bool rejected = false;
            try {
                java_toolchain_input_sha256(path, bound, change);
            } catch (const std::exception &) {
                rejected = true;
            }

            check(rejected);
        };
        rejects_input(input, 1);

        // Creating a symbolic link needs a privilege on Windows.
        if (!voyemu::os::host_windows) {
            const auto symlink = temporary / "linked.jar";
            std::filesystem::create_symlink(input, symlink);
            rejects_input(symlink, 1024);
        }

        rejects_input(input, 1024, [&] {
            std::ofstream out(link);
            out << "changed pinned payload";
        });
        check(java_toolchain_input_sha256(input) != input_pin);
        rejects_input(input, 1024, [&] {
            std::filesystem::remove(input);
            std::ofstream out(input);
            out << "changed pinned payload";
        });
        const auto stage = temporary / "stage", destination = temporary / "published";
        ensure_private_directory(stage);
        auto put = [](const std::filesystem::path &p, const std::string &value) {
            std::ofstream out(p, std::ios::binary);
            out << value;
            out.close();
            check(bool(out));
        };
        put(stage / "voyemu-java-helper.jar", "bounded test payload");
        put(stage / "build-receipt.json", "{}\n");
        const Json owner = {{"helper_sha256", sha256_file(stage / "voyemu-java-helper.jar")},
                            {"build_receipt_sha256", sha256_file(stage / "build-receipt.json")}};
        // A builder interruption before the ownership receipt never exposes a final cache
        // directory.
        check(!std::filesystem::exists(destination) &&
              !std::filesystem::exists(stage / "toolchain-receipt.json"));
        auto bad = owner;
        bad["helper_sha256"] = std::string(64, '0');
        failed = false;
        try {
            publish_java_helper_directory(stage, destination, bad);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(destination) &&
              std::filesystem::exists(stage / "voyemu-java-helper.jar") &&
              !std::filesystem::exists(stage / "toolchain-receipt.json"));
        publish_java_helper_directory(stage, destination, owner);
        check(!std::filesystem::exists(stage) &&
              read_private_json(destination / "toolchain-receipt.json") == owner);
        const auto second = temporary / "second";
        ensure_private_directory(second);
        put(second / "voyemu-java-helper.jar", "bounded test payload");
        put(second / "build-receipt.json", "{}\n");
        failed = false;
        try {
            publish_java_helper_directory(second, destination, owner);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && std::filesystem::exists(second / "voyemu-java-helper.jar") &&
              read_private_json(destination / "toolchain-receipt.json") == owner);
        const auto late_stage = temporary / "late-stage",
                   late_destination = temporary / "late-destination";
        ensure_private_directory(late_stage);
        put(late_stage / "voyemu-java-helper.jar", "bounded test payload");
        put(late_stage / "build-receipt.json", "{}\n");
        failed = false;
        try {
            publish_java_helper_directory(late_stage, late_destination, owner, [&] {
                std::filesystem::create_directory(late_destination);
            });
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && std::filesystem::is_directory(late_destination) &&
              std::filesystem::is_empty(late_destination) &&
              read_private_json(late_stage / "toolchain-receipt.json") == owner);
        std::filesystem::remove_all(temporary);
        const auto scratch = root / ".local/build/tmp" /
                             ("java-helper-install-test-" + random_token());
        ensure_private_directory(scratch);
        helper_installation_checks(scratch);
        std::filesystem::remove_all(scratch);
        std::cout
                << "Java helper source/JDK path guards passed; no compiler/download/process executed\n";

        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';

        return 1;
    }
}
