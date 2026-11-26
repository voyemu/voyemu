#include "native_component.hpp"
#include "deps.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "qnx_link_interface.hpp"
#include "source_edits.hpp"
#include "toolchain_manifest.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
using namespace voyemu;

static void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

int main(int argc, char **argv) {
    try {
        if (argc > 1 && (std::string_view(argv[1]) == "--target=aarch64-linux-android28" ||
                         std::string_view(argv[1]) == "--target=x86_64-linux-android28")) {
            std::filesystem::path fixture, output;
            std::vector<std::string> args;

            for (int i = 1; i < argc; ++i) {
                const std::string arg = argv[i];
                args.push_back(arg);

                if (arg.starts_with("-I") && fixture.empty()) {
                    fixture = arg.substr(2);
                }

                if (arg == "-o" && i + 1 < argc) {
                    output = argv[++i];
                }
            }

            auto has = [&](const char *value) {
                return std::find(args.begin(), args.end(), value) != args.end();
            };

            // A guest library stub: an empty shared object that carries only its soname.
            if (fixture.empty()) {
                check(has("-shared") && has("-nostdlib"), "guest stub arguments");
                std::ofstream(output, std::ios::binary) << "stub";

                return 0;
            }

            const bool executable = read_private_json(fixture.parent_path() / "component.json")
                                            .value("outputType", std::string{}) == "executable";
            check((has("--target=aarch64-linux-android28") ||
                   has("--target=x86_64-linux-android28")) &&
                          (executable ? (has("-pie") && has("-fPIE") && !has("-shared"))
                                      : (has("-shared") && has("-fPIC") && !has("-pie"))),
                  "native compiler arguments match output type");

            if (std::filesystem::exists(fixture / "mutate-source")) {
                std::ofstream(fixture / "own.c") << "changed while compiling\n";
            }

            std::filesystem::copy_file(fixture / "fixture.elf", output);

            return 0;
        }

        // Producer modes build one small fixture component: the bounded build allowance of
        // build_native_component covers it, so they keep no machine-sized reserve.
        if (argc == 6 && std::string_view(argv[1]) == "--build") {
            std::cout << build_native_component(std::filesystem::canonical(argv[2]),
                                                std::filesystem::canonical(argv[3]), argv[4],
                                                std::filesystem::path(argv[5]), 0)
                                 .dump(2)
                      << '\n';

            return 0;
        }

        // CI builds every native component of every profile into one flat release directory.
        if (argc == 5 && std::string_view(argv[1]) == "--recipe") {
            const auto root = std::filesystem::canonical(argv[2]);
            const auto compiler = std::filesystem::canonical(native_ndk_directory(root) /
                                                             native_ndk_tool("clang"));
            std::cout << build_native_component_recipe(root, compiler, sha256_file(compiler),
                                                       std::filesystem::absolute(argv[3]),
                                                       std::string_view(argv[4]) == "--offline")
                                 .dump(2)
                      << '\n';

            return 0;
        }

        // Every host builds the pinned bytes of a component from its recipe with its pinned NDK,
        // which differs per host in the identity strings of clang and LLD; no cache takes part.
        if (argc == 5 && std::string_view(argv[1]) == "--recipe-pin") {
            const auto root = std::filesystem::canonical(argv[2]);
            const std::string profile = argv[3], component = argv[4];
            const auto source = authoring_directory(root, profile) /
                                authoring_profile(root, profile)
                                        .at("components")
                                        .at(component)
                                        .get<std::string>();
            const auto compiler = std::filesystem::canonical(native_ndk_directory(root) /
                                                             native_ndk_tool("clang"));
            const auto job = root / ".local/build/jobs" / ("native-recipe-pin-" + random_token());
            struct Job {
                std::filesystem::path path;

                ~Job() {
                    std::error_code ignored;
                    std::filesystem::remove_all(path, ignored);
                }
            } owned{job};
            const auto receipt = build_native_component(
                    native_component_sources(root, source, job / (component + "-sources")),
                    compiler, sha256_file(compiler), job / component, 0);
            std::ifstream file(job / component / receipt.at("output").get<std::string>(),
                               std::ios::binary);
            const std::string bytes{std::istreambuf_iterator<char>(file), {}};

            for (const auto &section : qnx_elf_sections(bytes)) {
                check(section.name != ".comment", "native component kept the host tool identity");
            }

            const auto definition = read_private_json(source / "component.json");
            const auto key = native_component_pin(profile, component, definition);
            const auto origin = native_component_origin(
                    embedded_toolchain_manifest().at("androidNativeComponents"), key, definition);
            check(receipt.at("sha256") == origin.at("sha256"),
                  "native component recipe differs from its pin");
            std::cout << "native component recipe matches its pin: " << profile << '/' << component
                      << '\n';

            return 0;
        }

        // Installs the pinned native components of a profile and writes their Java handoff.
        if (argc == 5 && std::string_view(argv[1]) == "--handoff") {
            const auto root = std::filesystem::canonical(argv[2]);
            const std::string profile = argv[3];
            Json handoff = Json::object();
            const auto components = authoring_profile(root, profile).at("components");

            for (auto it = components.begin(); it != components.end(); ++it) {
                const auto definition = read_private_json(authoring_directory(root, profile) /
                                                          it.value().get<std::string>() /
                                                          "component.json");

                if (definition.value("type", std::string{}) != "native") {
                    continue;
                }

                const auto receipt = install_native_component(
                        root, profile, it.key(),
                        embedded_toolchain_manifest().at("androidNativeComponents"), false);
                const auto proof = read_private_json(receipt);
                handoff[it.key()] = {{"receipt", receipt.string()},
                                     {"receipt_sha256", sha256_file(receipt)},
                                     {"output_type", proof.at("output_type")},
                                     {"output", proof.at("output")},
                                     {"sha256", proof.at("sha256")}};
            }

            write_private_json(std::filesystem::absolute(argv[4]), handoff);

            return 0;
        }

        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-component-" + random_token());
        ensure_private_directory(root / "source/src");
        struct Cleanup {
            std::filesystem::path path;

            ~Cleanup() {
                std::filesystem::remove_all(path);
            }
        } cleanup{root};
        {
            std::ofstream file(root / "source/src/own.c");
            file << "int own(void){return 1;}\n";
        }
        const auto source = root / "source";
        write_private_json(source / "component.json",
                           {{"type", "apk"}, {"minSdk", 28}, {"output", "libown.so"}});
        bool recipe = false;
        try {
            build_native_component(source, root / "missing-compiler", std::string(64, '0'),
                                   root / "output", 0);
        } catch (const std::exception &error) {
            recipe = std::string_view(error.what()).starts_with("COMPONENT_RECIPE:");
        }

        check(recipe && !std::filesystem::exists(root / "output"),
              "wrong recipe cannot spawn compiler or create output");
        write_private_json(source / "component.json",
                           {{"type", "native"}, {"minSdk", 28}, {"output", "../escaped.so"}});
        bool path = false;
        try {
            build_native_component(source, root / "missing-compiler", std::string(64, '0'),
                                   root / "output", 0);
        } catch (const std::exception &error) {
            path = std::string_view(error.what()).starts_with("COMPONENT_OUTPUT:");
        }

        check(path && !std::filesystem::exists(root / "output"),
              "unsafe output rejected before compiler lookup");

        for (const auto &[kind, output] :
             std::vector<std::pair<std::string, std::string>>{{"unknown", "libown.so"},
                                                              {"executable", "../own"},
                                                              {"executable", "libown.so"}}) {
            write_private_json(
                    source / "component.json",
                    {{"type", "native"}, {"minSdk", 28}, {"outputType", kind}, {"output", output}});
            bool rejected = false;
            try {
                build_native_component(source, root / "missing-compiler", std::string(64, '0'),
                                       root / "output", 0);
            } catch (const std::exception &error) {
                const std::string_view message = error.what();
                rejected = message.starts_with("COMPONENT_RECIPE:") ||
                           message.starts_with("COMPONENT_OUTPUT:");
            }

            check(rejected && !std::filesystem::exists(root / "output"),
                  "unknown kind or unsafe executable output rejected before compiler lookup");
        }

        write_private_json(source / "component.json", {{"type", "native"},
                                                       {"minSdk", 28},
                                                       {"outputType", "executable"},
                                                       {"output", "model"}});
        std::array<unsigned char, 512> executable{};
        auto put = [&](int at, std::uint64_t value, int size) {
            for (int i = 0; i < size; ++i) {
                executable[at + i] = static_cast<unsigned char>(value >> (8 * i));
            }
        };
        executable[0] = 127;
        executable[1] = 'E';
        executable[2] = 'L';
        executable[3] = 'F';
        executable[4] = 2;
        executable[5] = 1;
        executable[6] = 1;
        put(16, 3, 2);
        put(18, 183, 2);
        put(20, 1, 4);
        put(24, 0x10140, 8);
        put(32, 64, 8);
        put(52, 64, 2);
        put(54, 56, 2);
        put(56, 3, 2);
        put(64, 1, 4);
        put(68, 5, 4);
        put(80, 0x10000, 8);
        put(96, 512, 8);
        put(104, 512, 8);
        put(112, 4096, 8);
        put(120, 3, 4);
        put(128, 240, 8);
        put(136, 0x100f0, 8);
        put(152, 21, 8);
        put(160, 21, 8);
        put(176, 2, 4);
        put(184, 272, 8);
        put(192, 0x10110, 8);
        put(208, 32, 8);
        put(216, 32, 8);
        put(272, 0x6ffffffb, 8);
        put(280, 0x08000000, 8);
        const std::string interpreter = "/system/bin/linker64";
        std::copy(interpreter.begin(), interpreter.end(), executable.begin() + 240);
        const auto compiler = std::filesystem::canonical(argv[0]);
        const auto pin = sha256_file(compiler);
        auto run_fixture = [&](const char *name, bool success) {
            std::ofstream file(source / "src/fixture.elf", std::ios::binary);
            file.write(reinterpret_cast<const char *>(executable.data()), executable.size());
            file.close();
            bool built = false;
            try {
                const auto result = build_native_component(source, compiler, pin, root / name, 0);
                built = result.value("output_type", std::string{}) == "executable";
            } catch (const std::exception &error) {
                if (!std::string_view(error.what()).starts_with("COMPONENT_ELF:")) {
                    throw;
                }
            }

            check(built == success, "executable ELF validation");

            if (!success) {
                check(!std::filesystem::exists(root / name), "invalid ELF stage cleaned");
            }
        };
        // Exercise the real producer space gate with controlled available bytes.
        {
            std::ofstream file(source / "src/fixture.elf", std::ios::binary);
            file.write(reinterpret_cast<const char *>(executable.data()), executable.size());
        }

        for (const std::uint64_t floor : std::vector<std::uint64_t>{8ULL << 30, 20ULL << 30}) {
            const auto required = floor + (256ULL << 20);
            const auto suffix = std::to_string(floor);
            const auto accepted = root / ("space-exact-" + suffix),
                       rejected = root / ("space-short-" + suffix);
            const auto proof = build_native_component(source, compiler, pin, accepted, floor, [&] {
                return required;
            });
            check(proof.value("output_type", std::string{}) == "executable" &&
                          std::filesystem::exists(accepted / "receipt.json"),
                  "exact native space boundary accepts");
            bool denied = false;
            try {
                build_native_component(source, compiler, pin, rejected, floor, [&] {
                    return required - 1;
                });
            } catch (const std::exception &error) {
                denied = std::string_view(error.what()).starts_with("COMPONENT_SPACE:");
            }

            check(denied && !std::filesystem::exists(rejected),
                  "one byte below native space boundary rejects without destination");
        }

        {
            const auto rejected = root / "space-overflow";
            bool called = false, denied = false;
            try {
                build_native_component(source, compiler, pin, rejected,
                                       std::numeric_limits<std::uint64_t>::max(), [&] {
                                           called = true;

                                           return std::numeric_limits<std::uint64_t>::max();
                                       });
            } catch (const std::exception &error) {
                denied = std::string_view(error.what()).starts_with("COMPONENT_SPACE:");
            }

            check(denied && !called && !std::filesystem::exists(rejected),
                  "overflow rejects before measuring space or creating destination");
        }
        run_fixture("valid", true);
        put(64, 0, 4);
        run_fixture("no-load", false);
        put(64, 1, 4);
        put(18, 62, 2);
        run_fixture("wrong-abi", false);
        put(18, 183, 2);
        put(16, 2, 2);
        run_fixture("wrong-type", false);
        put(16, 3, 2);
        put(24, 0x10200, 8);
        run_fixture("bad-entry", false);
        put(24, 0x10140, 8);
        put(68, 4, 4);
        run_fixture("non-executable-entry", false);
        put(68, 5, 4);
        put(104, 511, 8);
        run_fixture("load-filesz-exceeds-memsz", false);
        put(104, 512, 8);
        put(112, 3, 8);
        run_fixture("bad-alignment", false);
        put(112, 4096, 8);
        put(80, UINT64_MAX - 100, 8);
        run_fixture("address-overflow", false);
        put(80, 0x10000, 8);
        put(128, 500, 8);
        run_fixture("unmapped-interpreter", false);
        put(128, 240, 8);
        put(192, 0x10200, 8);
        run_fixture("unmapped-dynamic", false);
        put(192, 0x10110, 8);
        put(120, 0, 4);
        run_fixture("no-interpreter", false);
        put(120, 3, 4);
        executable[240] = 'x';
        run_fixture("wrong-interpreter", false);
        executable[240] = '/';
        put(280, 0, 8);
        run_fixture("not-pie", false);
        put(280, 0x08000000, 8);
        put(32, 255, 8);
        run_fixture("bad-headers", false);
        put(32, 64, 8);
        executable[6] = 0;
        run_fixture("bad-ident-version", false);
        executable[6] = 1;
        put(20, 0, 4);
        run_fixture("bad-elf-version", false);
        put(20, 1, 4);
        put(52, 0, 2);
        run_fixture("bad-header-size", false);
        put(52, 64, 2);
        write_private_json(source / "component.json",
                           {{"type", "native"}, {"minSdk", 28}, {"output", "libown.so"}});
        const auto shared_default = build_native_component(source, compiler, pin,
                                                           root / "shared-default", 0);
        check(!shared_default.contains("sources") && !shared_default.contains("source_tree_sha256"),
              "native output receipt must not persist repository source pins");
        std::ifstream fixture_input(source / "src/fixture.elf", std::ios::binary);
        const std::string fixture_before{std::istreambuf_iterator<char>(fixture_input), {}};
        fixture_input.close();
        { std::ofstream(source / "src/fixture.elf", std::ios::binary | std::ios::app) << 'x'; }
        const auto changed_source = build_native_component(source, compiler, pin,
                                                           root / "changed-source", 0);
        check(changed_source.at("sha256") != shared_default.at("sha256"),
              "a fresh component build consumes changed inputs instead of old output");
        {
            std::ofstream file(source / "src/fixture.elf", std::ios::binary);
            file.write(fixture_before.data(), fixture_before.size());
        }
        { std::ofstream(source / "src/mutate-source") << "mutate fixture while compiling\n"; }
        bool race_rejected = false;
        try {
            build_native_component(source, compiler, pin, root / "changed-during-build", 0);
        } catch (const VoyemuError &error) {
            race_rejected = std::string_view(error.what()).starts_with("COMPONENT_CHANGED:");
        }

        check(race_rejected && !std::filesystem::exists(root / "changed-during-build"),
              "source changes during compilation reject and clean incomplete output");
        std::filesystem::remove(source / "src/mutate-source");
        std::ofstream(source / "src/own.c") << "int own(void){return 1;}\n";
        write_private_json(source / "component.json", {{"type", "native"},
                                                       {"minSdk", 28},
                                                       {"outputType", "shared-library"},
                                                       {"output", "libown.so"}});
        const auto shared_explicit = build_native_component(source, compiler, pin,
                                                            root / "shared-explicit", 0);
        check(!shared_default.contains("output_type") && !shared_explicit.contains("output_type") &&
                      shared_default.at("sha256") == shared_explicit.at("sha256"),
              "shared output type retains legacy receipt and bytes");
        const auto stage_arguments = [](Json arguments, const std::filesystem::path &stage) {
            check(arguments.size() >= 4 && arguments.at(arguments.size() - 2) == "-o" &&
                          arguments.back() == (stage / "libown.so").string(),
                  "shared compiler output belongs to its stage");
            arguments.back() = "<stage>/libown.so";
            unsigned scripts = 0;

            for (std::size_t i = 0; i < arguments.size(); ++i) {
                const auto argument = arguments[i].get<std::string>();

                if (argument.starts_with("--script=")) {
                    check(argument == "--script=" + (stage / "reproducible.ld").string() && i > 0 &&
                                  arguments[i - 1] == "-Xlinker",
                          "shared compiler uses its owned reproducible linker script");
                    arguments[i] = "--script=<stage>/reproducible.ld";
                    ++scripts;
                }
            }

            check(scripts == 1, "one reproducible linker script required");

            return arguments;
        };
        check(stage_arguments(shared_default.at("command"), root / "shared-default") ==
                      stage_arguments(shared_explicit.at("command"), root / "shared-explicit"),
              "shared compiler commands match");
        write_private_json(source / "component.json",
                           {{"type", "native"},
                            {"minSdk", 28},
                            {"output", "libown.so"},
                            {"guestLibs", Json::array({"/system/lib64/libgui.so"})}});
        bool inputs = false;
        try {
            build_native_component(source, root / "missing-compiler", std::string(64, '0'),
                                   root / "output", 0);
        } catch (const std::exception &error) {
            inputs = std::string_view(error.what()).starts_with("COMPONENT_RECIPE:");
        }

        check(inputs, "unmaterialized guest inputs cannot claim complete native build");
        write_private_json(source / "native-sources.json",
                           {{"schema", 1},
                            {"native", true},
                            {"files", 2},
                            {"definition_sha256", sha256_file(source / "component.json")},
                            {"source_tree_sha256", std::string(64, '0')}});
        bool changed = false;
        try {
            build_native_component(source, root / "missing-compiler", std::string(64, '0'),
                                   root / "output", 0);
        } catch (const std::exception &error) {
            changed = std::string_view(error.what()).starts_with("COMPONENT_INPUTS:");
        }

        check(changed && !std::filesystem::exists(root / "output"),
              "forged or stale materialization cannot compile or publish output");
        std::filesystem::remove(source / "native-sources.json");
        ensure_private_directory(root / "cache");
        materialize_native_component_sources(source, root / "cache", root / "materialized");
        // Guest libraries link as soname-only stubs, with imports left undefined for the linker.
        const auto stubbed = build_native_component(root / "materialized", compiler, pin,
                                                    root / "stubbed", 0);
        const auto args = stubbed.at("command").dump();
        check(stubbed.at("guest_sonames") == Json::array({"libgui.so"}) &&
                      !stubbed.at("materialized_source").contains("definition_sha256") &&
                      !stubbed.at("materialized_source").contains("source_tree_sha256") &&
                      stubbed.at("materialized_source").contains("external_tree_sha256") &&
                      args.find("-l:libgui.so") != std::string::npos &&
                      args.find("--no-undefined") == std::string::npos &&
                      !std::filesystem::exists(root / "stubbed/guest-stubs"),
              "guest library links as a soname stub without --no-undefined");
        // A component that declares sourceFiles compiles its local tree plus the common sources.
        const auto common = root / "profiles/common/components/shared/src";
        ensure_private_directory(common);
        {
            std::ofstream file(common / "shared.c");
            file << "int shared(void){return 2;}\n";
        }
        const auto component = root / "profiles/p/components/own";
        ensure_private_directory(component / "src");
        std::filesystem::copy_file(root / "source/src/own.c", component / "src/own.c");
        const Json local = {{"type", "native"}, {"minSdk", 28}, {"output", "libown.so"}};
        write_private_json(component / "component.json", local);
        check(native_component_sources(root, component, root / "unused") == component &&
                      !std::filesystem::exists(root / "unused"),
              "a component without sourceFiles builds from its own directory");
        auto declared = local;
        declared["sourceFiles"] = {
                {"src/shared.c", "voyemu/profiles/common/components/shared/src/shared.c"}};
        write_private_json(component / "component.json", declared);
        const auto shared = native_component_sources(root, component, root / "shared-1");
        check(shared == root / "shared-1" &&
                      sha256_file(shared / "src/shared.c") == sha256_file(common / "shared.c") &&
                      sha256_file(shared / "src/own.c") == sha256_file(component / "src/own.c") &&
                      sha256_file(shared / "component.json") ==
                              sha256_file(component / "component.json"),
              "declared common source joins the local tree");
        const auto rejected = [&](const Json &files, bool external, const std::string &work) {
            auto definition = local;
            definition["sourceFiles"] = files;

            if (external) {
                definition["externalSources"] = Json::object();
            }

            write_private_json(component / "component.json", definition);
            try {
                native_component_sources(root, component, root / work);
            } catch (const VoyemuError &) {
                return true;
            }

            return false;
        };
        check(rejected({{"src/own.c", "voyemu/profiles/common/components/shared/src/shared.c"}},
                       false, "shared-2") &&
                      rejected({{"src/x.c", "voyemu/profiles/p/components/own/src/own.c"}}, false,
                               "shared-3") &&
                      rejected({{"src/x.c", "voyemu/profiles/common/components/shared/src/../x.c"}},
                               false, "shared-4") &&
                      rejected({{"src/x.h", "voyemu/profiles/common/components/shared/src/x.h"}},
                               false, "shared-5") &&
                      rejected({{"src/x.c",
                                 "voyemu/profiles/common/components/shared/src/shared.c"}},
                               true, "shared-6") &&
                      rejected(Json::object(), false, "shared-7"),
              "shared sources overwrite nothing, stay in common sources and exclude external edits");
        // Local profiles remain buildable, but their components are not public release assets.
        write_private_json(component / "component.json", local);
        std::filesystem::copy_file(root / "shared-default/libown.so",
                                   component / "src/fixture.elf");
        write_private_json(root / "profiles/p/profile.json",
                           {{"components", {{"own", "components/own"}}}});
        const auto private_component = root / "profiles/private/components/own";
        ensure_private_directory(private_component / "src");
        std::filesystem::copy_file(component / "component.json",
                                   private_component / "component.json");
        std::filesystem::copy_file(component / "src/own.c", private_component / "src/own.c");
        std::filesystem::copy_file(component / "src/fixture.elf",
                                   private_component / "src/fixture.elf");
        write_private_json(root / "profiles/private/profile.json",
                           {{"local", true}, {"components", {{"own", "components/own"}}}});
        build_native_component(private_component, compiler, pin, root / "private-direct", 0);
        const auto private_binary = root / "private-direct/libown.so";
        const auto private_sha = sha256_file(private_binary);
        const auto native_cache = root / ".local/toolchains/android-native" / private_sha;
        ensure_private_directory(native_cache);
        std::filesystem::copy_file(private_binary, native_cache / "libown.so");
        const Json private_pins{{"private/own",
                                 {{"sha256", private_sha},
                                  {"url", "https://example.invalid/private-own-libown.so"}}}};
        const auto direct = install_native_component(root, "private", "own", private_pins, true);
        check(std::filesystem::is_regular_file(direct.parent_path() / "libown.so"),
              "local profile remains directly buildable and installable");
        // Materialize a different output with the same SONAME, for a process running x86_64.
        const auto x86_component = root / "profiles/p_x86_64/components/own";
        ensure_private_directory(x86_component / "src");
        std::filesystem::copy_file(private_binary, x86_component / "src/fixture.elf");
        {
            std::fstream file(x86_component / "src/fixture.elf",
                              std::ios::binary | std::ios::out | std::ios::in);
            file.seekp(18);
            file.put(62);
        }
        std::filesystem::copy_file(component / "src/own.c", x86_component / "src/own.c");
        const auto x86_sha = sha256_file(x86_component / "src/fixture.elf");
        const auto x86_definition = Json{{"type", "native"},
                                         {"minSdk", 28},
                                         {"output", "libown.so"},
                                         {"abi", "x86_64"},
                                         {"sourceBuildSha256", x86_sha}};
        write_private_json(x86_component / "component.json", x86_definition);
        write_private_json(root / "profiles/p_x86_64/profile.json",
                           {{"local", true}, {"components", {{"own", "components/own"}}}});
        const auto x86 = build_native_component(x86_component, compiler, pin, root / "x86-compiler",
                                                0);
        check(x86.at("abi") == "x86_64" &&
                      x86.at("command").at(0) == "--target=x86_64-linux-android28",
              "compiler target and ELF ABI of declared process");
        unsigned built = 0;
        const auto source_build = [&](const std::filesystem::path &job) {
            ++built;
            std::filesystem::copy_file(root / "x86-compiler/libown.so", job / "libown.so");
        };
        const auto install_x86 = [&] {
            return read_private_json(install_native_component(
                    root, "p_x86_64", "own", Json::object(), true, {}, source_build));
        };
        const auto source_receipt = install_x86();
        check(source_receipt.at("source") == "recipe" && !source_receipt.contains("asset") &&
                      source_receipt.at("abi") == "x86_64" &&
                      source_receipt.at("sha256") == x86_sha && install_x86() == source_receipt &&
                      built == 1,
              "offline source recipe uses measured pin and reuses validated cache");
        auto wrong_consumer = x86_definition;
        wrong_consumer["abi"] = "arm64-v8a";
        write_private_json(x86_component / "component.json", wrong_consumer);
        bool mismatch = false;
        try {
            (void)install_x86();
        } catch (const VoyemuError &error) {
            mismatch = std::string_view(error.what()).starts_with("COMPONENT_ELF:");
        }

        check(mismatch && built == 1, "cached x86 DSO rejected for ARM consumer");
        // A component that names the pin of another profile installs that published asset.
        const auto reuse_component = root / "profiles/reuse/components/own";
        ensure_private_directory(reuse_component / "src");
        auto reuse = local;
        reuse["pin"] = "private/own";
        write_private_json(reuse_component / "component.json", reuse);
        std::filesystem::copy_file(component / "src/own.c", reuse_component / "src/own.c");
        write_private_json(root / "profiles/reuse/profile.json",
                           {{"components", {{"own", "components/own"}}}});
        const auto reused = read_private_json(
                install_native_component(root, "reuse", "own", private_pins, true));
        check(reused.at("sha256") == private_sha &&
                      reused.at("asset") == private_pins.at("private/own").at("url"),
              "a component installs the asset of the pin it names");
        const auto exported = build_native_component_recipe(root, compiler, pin,
                                                            root / "public-export", true);
        check(exported.size() == 1 && exported.contains("p/own") &&
                      !std::filesystem::exists(root / "public-export/private-own-libown.so"),
              "public native assets exclude local profiles without excluding published components");
        check(!exported.contains("reuse/own") &&
                      !std::filesystem::exists(root / "public-export/reuse-own-libown.so"),
              "a component that names another pin publishes no asset of its own");
        std::cout
                << "native component recipe, output confinement, materialization and guest library guards passed\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
