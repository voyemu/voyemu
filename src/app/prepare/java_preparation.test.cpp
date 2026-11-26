#include "java_preparation.hpp"
#include "../platform/startup_animation_fixture.hpp"
#include "ext4_image.hpp"
#include "file_patch.hpp"
#include "original_navi_candidate.hpp"
#include "os/platform.hpp"
#include "process.hpp"
#include "profile_build.hpp"
#include "profile_catalog.hpp"
#include "profile_file_nodes.hpp"
#include "profile_preparation.hpp"
#include "selinux_patch.hpp"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <source_location>
#include <stdexcept>
#include <thread>
using namespace voyemu;

// The bundled Android 9 profile on the 8155 board, read from the catalog.
static const std::string &qinggan09_profile() {
    static const auto id =
            embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);

    return id;
}

namespace {
void check(bool value, const std::source_location where = std::source_location::current()) {
    if (!value) {
        throw std::runtime_error("Java preparation check failed at " +
                                 std::to_string(where.line()) + ":" +
                                 std::to_string(where.column()));
    }
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--version") {
            std::cout << "openjdk 25\n";

            return 0;
        }

        if (argc == 7 && std::string_view(argv[1]) == "-Xmx1g") {
            const auto request = read_private_json(argv[6]);
            const auto source = std::filesystem::path(request.at("root").get<std::string>()) /
                                "profiles/inflight-fixture/components/own/src/Changed.java";
            ensure_private_directory(source.parent_path());
            std::ofstream(source) << "changed during helper execution\n";
            std::cout << Json{{"schema", 1},
                              {"operation", "plan"},
                              {"profile", "inflight-fixture"},
                              {"components", Json::array()},
                              {"patch_nodes", Json::array()},
                              {"machine_ready", false},
                              {"guest_started", false}}
                                 .dump()
                      << '\n';

            return 0;
        }

        if (argc == 5 && std::string_view(argv[1]) == "--helper-isolation") {
            const auto root = std::filesystem::absolute(argv[2]),
                       jar = std::filesystem::canonical(argv[3]),
                       other_jar = std::filesystem::canonical(argv[4]);
            check(sha256_file(jar) != sha256_file(other_jar));
            check(!std::filesystem::exists(root));
            ensure_private_directory(root);
            struct Cleanup {
                std::filesystem::path p;

                ~Cleanup() {
                    std::error_code e;
                    std::filesystem::remove_all(p, e);
                }
            } cleanup{root};
            auto put = [](const std::filesystem::path &p, const std::string &value) {
                ensure_private_directory(p.parent_path());
                std::ofstream out(p, std::ios::binary);
                out << value;
                out.close();
                check(bool(out));

                return sha256_file(p);
            };
            const auto dep = sha256_bytes("dependency");
            const auto spec = root / "src/prepare/libraries.json",
                       tools = root / "src/prepare/toolchain.json";
            ensure_private_directory(spec.parent_path());
            write_private_json(spec, Json::array({{{"filename", "fixture.jar"}, {"sha256", dep}}}));
            write_private_json(
                    tools,
                    {{"libraries", {{"d8", {{"sha256", dep}}}, {"apksigner", {{"sha256", dep}}}}}});
            const Json resources = {{"voyemu/src/guest/android/oem/audio/OemAudioPolicy.java",
                                     sha256_bytes("policy")},
                                    {"voyemu/src/guest/android/oem/audio/"
                                     "OemAudioPolicyUnavailable.java",
                                     sha256_bytes("unavailable")}};
            auto make = [&](const std::string &source, const std::filesystem::path &binary) {
                Json inputs = {{"sources",
                                {{"src/prepare/java/com/voyemu/prepare/PreparationMain.java",
                                  sha256_bytes(source)}}},
                               {"resource_snapshot", resources},
                               {"libraries_spec_sha256", sha256_file(spec)},
                               {"tool_pins_sha256", sha256_file(tools)}};
                const auto folder = root / ".local/toolchains/java-helper" /
                                    sha256_bytes(inputs.dump());
                ensure_private_directory(folder / "lib");
                std::filesystem::copy_file(binary, folder / "voyemu-java-helper.jar");
                Json dependencies = Json::array();

                for (const auto *name : {"fixture.jar", "d8.jar", "apksigner.jar"}) {
                    const auto relative = std::string("lib/") + name;
                    check(put(folder / relative, "dependency") == dep);
                    dependencies.push_back({{"file", relative}, {"sha256", dep}, {"bytes", 10}});
                }

                JavaPreparationRuntime r;
                r.helper_cache_key = folder.filename().string();
                r.helper = folder / "voyemu-java-helper.jar";
                r.helper_sha256 = sha256_file(r.helper);
                r.receipt = folder / "build-receipt.json";
                Json receipt = {{"schema", 1},
                                {"kind", "java-preparation-helper"},
                                {"java_release", 25},
                                {"sha256", r.helper_sha256},
                                {"jar", r.helper.filename().string()},
                                {"sources", inputs.at("sources")},
                                {"resource_snapshot", resources},
                                {"libraries_spec_sha256", inputs.at("libraries_spec_sha256")},
                                {"tool_pins_sha256", inputs.at("tool_pins_sha256")},
                                {"dependencies", dependencies}};
                write_private_json(r.receipt, receipt);
                r.receipt_sha256 = sha256_file(r.receipt);
                write_private_json(folder / "toolchain-receipt.json",
                                   {{"schema", 1},
                                    {"kind", "java-preparation-toolchain"},
                                    {"fingerprint", folder.filename().string()},
                                    {"inputs", inputs},
                                    {"helper_sha256", r.helper_sha256},
                                    {"build_receipt_sha256", r.receipt_sha256}});

                return r;
            };
            auto first = make("first source cut", jar),
                 second = make("second source cut", other_jar);
            const auto cp1 = java_preparation_classpath(root, first),
                       cp2 = java_preparation_classpath(root, second);
            check(cp1 != cp2 && first.helper_sha256 != second.helper_sha256);
            std::exception_ptr failure1, failure2;
            std::thread a([&] {
                try {
                    for (int i = 0; i < 5; ++i) {
                        check(java_preparation_classpath(root, first) == cp1);
                    }
                } catch (...) {
                    failure1 = std::current_exception();
                }
            }),
                    b([&] {
                        try {
                            for (int i = 0; i < 5; ++i) {
                                check(java_preparation_classpath(root, second) == cp2);
                            }
                        } catch (...) {
                            failure2 = std::current_exception();
                        }
                    });
            a.join();
            b.join();

            if (failure1) {
                std::rethrow_exception(failure1);
            }

            if (failure2) {
                std::rethrow_exception(failure2);
            }

            put(root / "src/prepare/java/com/voyemu/prepare/Unrelated.java",
                "new other profile helper");
            check(java_preparation_classpath(root, first) == cp1 &&
                  java_preparation_classpath(root, second) == cp2);
            auto reject = [&](const JavaPreparationRuntime &r) {
                bool failed = false;
                try {
                    java_preparation_classpath(root, r);
                } catch (const std::exception &) {
                    failed = true;
                }

                check(failed);
            };
            auto bad = first;
            bad.helper_cache_key = second.helper_cache_key;
            reject(bad);
            bad = first;
            bad.helper_sha256 = std::string(64, '0');
            reject(bad);
            bad = first;
            bad.receipt_sha256 = std::string(64, '0');
            reject(bad);
            put(first.helper.parent_path() / "lib/d8.jar", "corrupt");
            reject(first);
            check(java_preparation_classpath(root, second) == cp2);
            put(first.helper.parent_path() / "lib/d8.jar", "dependency");
            check(java_preparation_classpath(root, first) == cp1);
            put(first.helper.parent_path() / "toolchain-receipt.json", "{}");
            reject(first);
            check(java_preparation_classpath(root, second) == cp2);
            const auto definition = root / "profiles/inflight-fixture/profile.json";
            ensure_private_directory(definition.parent_path());
            write_private_json(definition, {{"schema", 1},
                                            {"id", "inflight-fixture"},
                                            {"components", Json::object()},
                                            {"patches", Json::object()}});
            auto mutation_runtime = second;
            mutation_runtime.jdk = root / ".local/toolchains/test-jdk";
            const std::string java_name = "java" + std::string(voyemu::os::executable_suffix);
            const auto java = mutation_runtime.jdk / "bin" / java_name;
            ensure_private_directory(java.parent_path());
            std::filesystem::copy_file(std::filesystem::canonical(argv[0]), java);
            mutation_runtime.java_sha256 = sha256_file(java);
            JavaPreparationRequest mutation_request;
            mutation_request.profile = "inflight-fixture";
            mutation_request.profile_sha256 = sha256_file(definition);
            bool mutation_rejected = false;
            try {
                prepare_java_artifacts(root, mutation_runtime, mutation_request,
                                       root / ".local/build/inflight-fixture", 10000);
            } catch (const std::exception &error) {
                mutation_rejected =
                        std::string(error.what()).find("profile source changed during operation") !=
                        std::string::npos;
            }

            check(mutation_rejected &&
                  !std::filesystem::exists(root / ".local/build/inflight-fixture/result.json"));
            std::cout << "Pinned helper cuts survive unrelated Java edit; corrupt helper, "
                         "receipt, dependency and owner rejected independently\n";

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--native-files-oem") {
            // The draft that profile preparation publishes for the imported Free A11 profiles,
            // whose bounded su policies use the OEM system_ext and vendor policies, is accepted
            // as built and rejected with any changed dependency.
            const auto root = std::filesystem::path(__FILE__)
                                      .parent_path()
                                      .parent_path()
                                      .parent_path()
                                      .parent_path();
            const auto scratch = root / ".local/build/tmp" /
                                 ("native-files-oem-test-" + random_token());
            ensure_private_directory(scratch);
            struct Cleanup {
                std::filesystem::path p;

                ~Cleanup() {
                    std::error_code error;
                    std::filesystem::remove_all(p, error);
                }
            } cleanup{scratch};

            for (const std::string profile :
                 {"free-11-chinese-20250710-6.11.1", "free-11-chinese-20260731-7.3.1"}) {
                const auto definition =
                        read_private_json(root / "profiles" / profile / "profile.json", 512 * 1024);
                const auto base = read_private_json(
                        root / ".local/profiles/common/android-base" /
                                definition.at("android").at("sha256").get<std::string>() /
                                "base.json",
                        512 * 1024);
                const auto image_pin =
                        base.at("files").at("system.img").at("sha256").get<std::string>();
                std::vector<std::string> selected{"/system/etc/selinux/mapping/30.0.cil"};

                for (const auto &recipe : api30_file_recipes_for_profile(definition)) {
                    selected.emplace_back(recipe.target);
                }

                std::ranges::sort(selected);
                selected.erase(std::ranges::unique(selected).begin(), selected.end());
                auto system = cached_native_android_inputs(
                        root / ".local/profiles/common/android-extracted", image_pin, selected,
                        "system");

                if (system.empty()) {
                    system = scratch / (profile + "-system");
                    extract_pinned_ext4_files(
                            root / ".local/profiles/common/android-base" /
                                    definition.at("android").at("sha256").get<std::string>() /
                                    "system.img",
                            image_pin, selected, system, 1ULL << 30, "system");
                }

                const auto nodes = plan_profile_file_nodes(root, profile, system, {});
                const auto draft = scratch / (profile + "-native");
                publish_file_patches(nodes.patches, draft);
                auto receipt = read_private_json(draft / "receipt.json", 128 * 1024);
                receipt["profile_provenance"] = nodes.provenance;
                write_private_json(draft / "receipt.json", receipt);
                JavaPreparationRequest request;
                request.profile = profile;
                request.profile_sha256 = sha256_file(root / "profiles" / profile / "profile.json");
                request.operation = JavaPreparationOperation::build_artifacts;
                request.build = JavaPreparationBuildInputs{};
                auto &b = *request.build;

                for (const auto &path : selected) {
                    b.android_inputs[path] = {system / "receipt.json",
                                              sha256_file(system / "receipt.json")};
                }

                b.native_files_receipt = draft / "receipt.json";
                b.native_files_receipt_sha256 = sha256_file(b.native_files_receipt);
                check(java_preparation_native_files(root, request) ==
                      Json({{"receipt", b.native_files_receipt.string()},
                            {"receipt_sha256", b.native_files_receipt_sha256}}));
                unsigned bounded = 0;

                for (std::size_t i = 0; i < receipt.at("files").size(); ++i) {
                    if (!receipt.at("files").at(i).contains("vendor_donor")) {
                        continue;
                    }

                    ++bounded;

                    for (int mode = 0; mode < 3; ++mode) {
                        auto changed = receipt;
                        auto &file = changed["files"][i];

                        if (mode == 0) {
                            file.erase("vendor_donor");
                        } else if (mode == 1) {
                            file["donor"]["sha256"] = std::string(64, '0');
                        } else {
                            file["vendor_donor"]["input"] = (scratch / "outside.cil").string();
                        }

                        const auto path = draft / "changed.json";
                        write_private_json(path, changed);
                        auto tampered = request;
                        tampered.build->native_files_receipt = path;
                        tampered.build->native_files_receipt_sha256 = sha256_file(path);
                        bool rejected = false;
                        try {
                            java_preparation_native_files(root, tampered);
                        } catch (const std::exception &) {
                            rejected = true;
                        }

                        check(rejected);
                    }
                }

                check(bounded == 2);
                std::cout << profile << ": native file draft with " << bounded
                          << " bounded su policies accepted, changed dependencies rejected\n";
            }

            return 0;
        }

        if (argc == 4 && std::string_view(argv[1]) == "--native-files") {
            const auto root = std::filesystem::canonical(argv[2]);
            const auto document = read_private_json(std::filesystem::canonical(argv[3]), 2 << 20);
            JavaPreparationRequest request;
            request.profile = document.at("profile");
            request.profile_sha256 = document.at("profile_sha256");
            request.operation = JavaPreparationOperation::build_artifacts;
            request.build = JavaPreparationBuildInputs{};
            auto &b = *request.build;
            const auto scratch = root / ".local/build/tmp" /
                                 ("native-handoff-test-" + random_token());
            ensure_private_directory(scratch);
            struct Cleanup {
                std::filesystem::path p;

                ~Cleanup() {
                    std::error_code error;
                    std::filesystem::remove_all(p, error);
                }
            } cleanup{scratch};
            b.work = scratch / "work";
            b.patch_data = document.at("patch_data").get<std::string>();
            b.patch_data_sha256 = document.at("patch_data_sha256");
            const auto &tools = document.at("tools");
            b.sdk = tools.at("sdk").get<std::string>();
            b.tool_manifest_sha256 = tools.at("manifest_sha256");
            const auto &signing = tools.at("signing");
            b.key = signing.at("key").get<std::string>();
            b.key_sha256 = signing.at("key_sha256");
            b.certificate = signing.at("certificate").get<std::string>();
            b.certificate_sha256 = signing.at("certificate_sha256");
            b.platform = tools.at("platform").at("file").get<std::string>();
            b.platform_sha256 = tools.at("platform").at("sha256");

            for (auto it = tools.at("files").begin(); it != tools.at("files").end(); ++it) {
                b.tool_files[it.key()] = it.value();
            }

            if (document.contains("native_components")) {
                const auto &components = document.at("native_components");

                for (auto it = components.begin(); it != components.end(); ++it) {
                    b.native_components[it.key()] = {
                            it.value().at("receipt").get<std::string>(),
                            it.value().at("receipt_sha256").get<std::string>()};
                }
            }

            for (auto it = document.at("android_inputs").begin();
                 it != document.at("android_inputs").end(); ++it) {
                b.android_inputs[it.key()] = {it.value().at("receipt").get<std::string>(),
                                              it.value().at("receipt_sha256").get<std::string>()};
            }

            b.native_files_receipt = document.at("native_files").at("receipt").get<std::string>();
            b.native_files_receipt_sha256 = document.at("native_files").at("receipt_sha256");
            const auto original = b.native_files_receipt;
            const auto original_pin = b.native_files_receipt_sha256;
            const auto receipt = read_private_json(original, 128 * 1024);
            check(java_preparation_request(root, request).at("native_files") ==
                  document.at("native_files"));
            unsigned malformed_bindings = 0;

            if (!b.native_components.empty()) {
                auto &component = b.native_components.begin()->second;
                const auto pin = component.receipt_sha256;
                component.receipt_sha256 = std::string(64, '0');
                bool rejected = false;
                try {
                    java_preparation_request(root, request);
                } catch (...) {
                    rejected = true;
                }

                component.receipt_sha256 = pin;
                check(rejected && !std::filesystem::exists(b.work));
                ++malformed_bindings;
            }

            unsigned rejected = 0;
            const auto different_sha = [](const Json &value) {
                auto altered = value.get<std::string>();
                check(altered.size() == 64);
                altered.front() = altered.front() == '0' ? '1' : '0';

                return altered;
            };

            for (unsigned mode = 0; mode < (receipt.at("files").size() == 6   ? 37u
                                            : receipt.at("files").size() == 5 ? 27u
                                            : receipt.at("files").size() == 4 ? 21u
                                                                              : 13u);
                 ++mode) {
                const auto directory = scratch / ("case-" + std::to_string(mode));
                ensure_private_directory(directory);
                auto changed = receipt;
                const auto output = receipt.at("files").at(0).at("output").get<std::string>();

                for (const auto &item : receipt.at("files")) {
                    const auto member = item.at("output").get<std::string>();
                    std::filesystem::copy_file(original.parent_path() / member, directory / member);
                }

                if (mode == 0) {
                    changed["profile_provenance"]["profile"] =
                            receipt.at("profile_provenance").at("profile").get<std::string>() +
                            "-other";
                }

                if (mode == 1) {
                    changed["profile_provenance"]["native"] = false;
                }

                if (mode == 2) {
                    changed["profile_provenance"]["system_image_sha256"] = different_sha(
                            receipt.at("profile_provenance").at("system_image_sha256"));
                }

                if (mode == 3) {
                    changed["profile_provenance"]["extraction_receipt_sha256"] = different_sha(
                            receipt.at("profile_provenance").at("extraction_receipt_sha256"));
                }

                if (mode == 4) {
                    changed["profile_provenance"]["machine_ready"] = true;
                }

                if (mode == 5) {
                    changed["files"][0]["output_sha256"] =
                            different_sha(receipt.at("files").at(0).at("output_sha256"));
                }

                if (mode == 6) {
                    changed["files"][0]["id"] =
                            receipt.at("files").at(0).at("id").get<std::string>() + "-other";
                }

                if (mode == 7) {
                    changed["files"][0]["api"] = receipt.at("files").at(0).at("api") == 28 ? 30
                                                                                           : 28;
                }

                if (mode == 8) {
                    changed["files"][0]["output"] = "../outside";
                }

                if (mode == 9) {
                    changed["files"][0]["input"] = "/outside";
                }

                if (mode == 12) {
                    std::ofstream out(directory / output);
                    out << "corrupt native output";
                }

                if (mode == 13) {
                    changed["files"][receipt.at("files").size() - 1].erase("donor");
                }

                if (mode == 14) {
                    changed["files"][receipt.at("files").size() - 1]["donor"]["input"] = "/outside";
                }

                if (mode == 15) {
                    changed["files"][receipt.at("files").size() - 1]["donor"]["sha256"] =
                            different_sha(receipt.at("files").back().at("donor").at("sha256"));
                }

                if (mode == 16) {
                    changed["files"][receipt.at("files").size() - 1].erase("patched_dependency");
                }

                if (mode == 17) {
                    changed["files"][receipt.at("files").size() - 1]["patched_dependency"]
                           ["sha256"] = different_sha(receipt.at("files")
                                                              .back()
                                                              .at("patched_dependency")
                                                              .at("sha256"));
                }

                if (mode == 18) {
                    changed["files"][1] = changed["files"][0];
                }

                if (mode == 19) {
                    changed["files"].push_back(changed["files"][0]);
                }

                if (mode == 20) {
                    changed["profile_provenance"]["nodes"].erase(
                            receipt.at("files").back().at("id").get<std::string>());
                }

                if (mode == 33) {
                    changed["files"][1].erase("profile");
                }

                if (mode == 34) {
                    changed["files"][1]["profile"] =
                            receipt.at("files").at(1).at("profile").get<std::string>() + "-other";
                }

                if (mode == 35) {
                    changed["files"][5].erase("profile");
                }

                if (mode == 36) {
                    changed["files"][5]["profile"] =
                            receipt.at("files").at(5).at("profile").get<std::string>() + "-other";
                }

                if (mode == 21) {
                    changed["files"][3].erase("profile");
                }

                if (mode == 22) {
                    changed["files"][3]["profile"] =
                            receipt.at("files").at(3).at("profile").get<std::string>() + "-other";
                }

                if (mode == 23) {
                    changed["files"][3]["output_sha256"] =
                            different_sha(receipt.at("files").at(3).at("output_sha256"));
                }

                if (mode == 24) {
                    changed["files"][3]["donor"] = {{"input", "/outside"},
                                                    {"sha256", std::string(64, '0')}};
                }

                if (mode == 25) {
                    changed["files"].erase(3);
                }

                if (mode == 26) {
                    changed["profile_provenance"]["nodes"].erase(
                            receipt.at("files").at(3).at("id").get<std::string>());
                }

                if (mode == 27) {
                    changed["files"][4].erase("profile");
                }

                if (mode == 28) {
                    changed["files"][4]["profile"] =
                            receipt.at("files").at(4).at("profile").get<std::string>() + "-other";
                }

                if (mode == 29) {
                    changed["files"][4]["output_sha256"] =
                            different_sha(receipt.at("files").at(4).at("output_sha256"));
                }

                if (mode == 30) {
                    changed["files"][4]["donor"] = {{"input", "/outside"},
                                                    {"sha256", std::string(64, '0')}};
                }

                if (mode == 31) {
                    changed["files"].erase(4);
                }

                if (mode == 32) {
                    changed["profile_provenance"]["nodes"].erase(
                            receipt.at("files").at(4).at("id").get<std::string>());
                }

                b.native_files_receipt = directory / "receipt.json";
                write_private_json(b.native_files_receipt, changed);
                b.native_files_receipt_sha256 = sha256_file(b.native_files_receipt);

                if (mode == 10) {
                    b.native_files_receipt.clear();
                    b.native_files_receipt_sha256.clear();
                }

                if (mode == 11) {
                    b.native_files_receipt_sha256 = different_sha(b.native_files_receipt_sha256);
                }

                bool bad = false;
                try {
                    java_preparation_request(root, request);
                } catch (...) {
                    bad = true;
                }

                check(bad && !std::filesystem::exists(b.work));
                ++rejected;
            }

            check(sha256_file(original) == original_pin);
            std::cout << Json{{"native_files", receipt.at("files").size()},
                              {"malformed_bindings_rejected", malformed_bindings},
                              {"malformed_handoffs_rejected", rejected},
                              {"helper_started", false},
                              {"guest_started", false},
                              {"native_receipt_modified", false}}
                                 .dump()
                      << '\n';

            return 0;
        }

        if ((argc == 9 && std::string(argv[1]) == "--plan") ||
            (argc == 10 && std::string(argv[1]) == "--plan-profile")) {
            const auto root = std::filesystem::absolute(argv[2]);
            JavaPreparationRuntime runtime;
            runtime.jdk = std::filesystem::absolute(argv[3]);
            runtime.java_sha256 = argv[4];
            runtime.helper = std::filesystem::absolute(argv[5]);
            runtime.helper_cache_key = runtime.helper.parent_path().filename().string();
            runtime.helper_sha256 = argv[6];
            runtime.receipt = runtime.helper.parent_path() / "build-receipt.json";
            runtime.receipt_sha256 = argv[7];
            JavaPreparationRequest request;
            request.profile = argc == 10 ? argv[9] : qinggan09_profile();
            request.profile_sha256 =
                    sha256_file(root / "profiles" / request.profile / "profile.json");
            const auto result = prepare_java_artifacts(root, runtime, request,
                                                       std::filesystem::absolute(argv[8]));
            std::cout << result.dump() << '\n';

            return 0;
        }

        const auto codec_draft = argc == 3 && std::string_view(argv[1]) == "--codec-native"
                                         ? std::filesystem::canonical(argv[2])
                                         : std::filesystem::path{};
        check(argc == 1 || !codec_draft.empty());

        if (argc == 1) {
            const auto scratch =
                    std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                    ("voyemu-preparation-isolation-" + random_token());
            ensure_private_directory(scratch);
            struct Cleanup {
                std::filesystem::path directory;

                ~Cleanup() {
                    std::error_code error;
                    std::filesystem::remove_all(directory, error);
                }
            } cleanup{scratch};
            const auto first = scratch / "first.jar", second = scratch / "second.jar";
            startup_fixture::zip(
                    first, {{"com/voyemu/prepare/PreparationMain.class", "first helper cut"}});
            startup_fixture::zip(
                    second, {{"com/voyemu/prepare/PreparationMain.class", "second helper cut"}});
            ProcessSpec isolated;
            isolated.executable = std::filesystem::canonical(argv[0]);
            isolated.directory = scratch;
            isolated.arguments = {"--helper-isolation", (scratch / "checkout").string(),
                                  first.string(), second.string()};
            const auto result = execute(isolated, 20000, 16 * 1024);

            if (result.timed_out || result.exit_code != 0) {
                throw std::runtime_error("helper ownership/invocation isolation: " + result.output);
            }
        }

        const auto root = std::filesystem::path(__FILE__)
                                  .parent_path()
                                  .parent_path()
                                  .parent_path()
                                  .parent_path();
        JavaPreparationRequest request;
        request.profile = qinggan09_profile();
        request.profile_sha256 = sha256_file(root / "profiles" / request.profile / "profile.json");
        const auto plan = java_preparation_request(root, request);
        check(plan.size() == 6 && plan.at("schema") == 1 && plan.at("operation") == "plan" &&
              plan.at("root") == root.string() && !plan.contains("tools") &&
              !plan.contains("work"));
        // A profile without build targets travels as its exact authoring bytes.
        check(sha256_bytes(plan.at("resolved_profile").get<std::string>()) ==
              request.profile_sha256);
        auto reject = [&](const std::filesystem::path &selected,
                          const JavaPreparationRequest &input) {
            bool failed = false;
            try {
                java_preparation_request(selected, input);
            } catch (const std::exception &) {
                failed = true;
            }

            check(failed);
        };
        auto bad = request;
        bad.profile = "../escape";
        reject(root, bad);
        bad = request;
        bad.profile_sha256 = std::string(64, '0');
        reject(root, bad);
        reject("relative", request);
        bad = request;
        bad.build = JavaPreparationBuildInputs{};
        reject(root, bad);
        bad = request;
        bad.operation = static_cast<JavaPreparationOperation>(99);
        reject(root, bad);
        bad = request;
        bad.operation = JavaPreparationOperation::build_artifacts;
        reject(root, bad);
        bad.build = JavaPreparationBuildInputs{};
        reject(root, bad);
        bad.build->sdk = "relative";
        reject(root, bad);
        const auto fixture = root / ".local/build/tmp" /
                             ("java-platform-overlay-test-" + random_token());
        ensure_private_directory(fixture);
        struct Cleanup {
            std::filesystem::path p;

            ~Cleanup() {
                std::error_code e;
                std::filesystem::remove_all(p, e);
            }
        } cleanup{fixture};
        auto file = [&](const std::filesystem::path &p, const std::string &value) {
            ensure_private_directory(p.parent_path());
            std::ofstream out(p, std::ios::binary);
            out << value;
            out.close();
            check(bool(out));

            return sha256_file(p);
        };
        const auto overlay_root = fixture / "overlay-root";
        ensure_private_directory(overlay_root / ".local");
        ensure_private_directory(overlay_root / "src/app");
        std::filesystem::copy_file(root / "src/app/toolchain.json",
                                   overlay_root / "src/app/toolchain.json");
        const Json overlay_profile = {
                {"schema", 1},
                {"android", read_private_json(root / "profiles" / request.profile / "profile.json")
                                    .at("android")},
                {"patches", Json::object()},
                {"components", Json::object()}};
        write_private_json(overlay_root / "profiles/platform-overlay-fixture/profile.json",
                           overlay_profile);
        JavaPreparationRequest build = request;
        build.profile = "platform-overlay-fixture";
        build.profile_sha256 =
                sha256_file(overlay_root / "profiles" / build.profile / "profile.json");
        build.operation = JavaPreparationOperation::build_artifacts;
        build.build = JavaPreparationBuildInputs{};
        auto &b = *build.build;
        b.sdk = overlay_root / ".local/sdk";
        ensure_private_directory(b.sdk);
        b.work = overlay_root / ".local/work";
        b.patch_data = fixture / "patch-data.json";
        b.patch_data_sha256 = file(b.patch_data, "{}");
        b.key = fixture / "platform.pk8";
        b.key_sha256 = file(b.key, "test key bytes");
        b.certificate = fixture / "platform.pem";
        b.certificate_sha256 = file(b.certificate, "test certificate bytes");
        b.tool_manifest_sha256 = sha256_file(root / "src/app/toolchain.json");
        const auto specs = read_private_json(root / "src/app/toolchain.json", 1 << 20);
        const auto tools = specs.at("sdk").at("buildTools").get<std::string>();
        const std::string exe(voyemu::os::executable_suffix);

        for (const auto &name : {"build-tools/" + tools + "/aapt2" + exe,
                                 "build-tools/" + tools + "/zipalign" + exe}) {
            b.tool_files[name] = file(b.sdk / name, "pinned fixture SDK file");
        }

        b.platform = overlay_root / ".local/java-sdk/platforms/android-34/android.jar";
        b.platform_sha256 = file(b.platform, "pinned fixture platform JAR");
        const auto overlay = java_preparation_request(overlay_root, build);
        check(overlay.at("tools").at("platform").at("file") == b.platform.string() &&
              overlay.at("tools").at("platform").at("sha256") == b.platform_sha256 &&
              overlay.at("tools").at("files").size() == 2 &&
              !overlay.at("tools").contains("guest_java"));
        // The installed android-java asset reaches the helper with its pin; another path does not.
        auto guest = build;
        guest.build->guest_java = overlay_root / ".local/toolchains/android-java" /
                                  std::string(64, 'b') / "android-java.zip";
        guest.build->guest_java_sha256 = file(guest.build->guest_java, "guest java fixture");
        const auto guest_request = java_preparation_request(overlay_root, guest);
        check(guest_request.at("tools").at("guest_java").at("file") ==
                      guest.build->guest_java.string() &&
              guest_request.at("tools").at("guest_java").at("sha256") ==
                      guest.build->guest_java_sha256);
        auto foreign_guest = guest;
        foreign_guest.build->guest_java = overlay_root / ".local/android-java.zip";
        foreign_guest.build->guest_java_sha256 = file(foreign_guest.build->guest_java,
                                                      "guest java fixture");
        bool foreign_rejected = false;

        try {
            java_preparation_request(overlay_root, foreign_guest);
        } catch (const std::exception &) {
            foreign_rejected = true;
        }

        check(foreign_rejected);
        // Exercise the production request factory with two executable receipts and
        // a legacy library.
        auto executable_profile = overlay_profile;
        executable_profile["components"] = {{"first", "components/first"},
                                            {"second", "components/second"},
                                            {"library", "components/library"}};
        const auto profile_dir = overlay_root / "profiles" / build.profile;
        auto executable_build = build;
        std::string elf_bytes(512, '\0');
        auto put = [&](int at, std::uint64_t value, int size) {
            for (int n = 0; n < size; ++n) {
                elf_bytes[at + n] = static_cast<char>(value >> (8 * n));
            }
        };
        elf_bytes.replace(0, 4,
                          "\x7f"
                          "ELF");
        elf_bytes[4] = 2;
        elf_bytes[5] = 1;
        elf_bytes[6] = 1;
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
        elf_bytes.replace(240, 20, "/system/bin/linker64");

        // The handoff receipts name the CI-built assets that the overlay manifest pins.
        auto manifest = read_private_json(overlay_root / "src/app/toolchain.json", 1 << 20);

        for (const auto *id : {"first", "second", "library"}) {
            const std::string name = id;
            const bool library = name == "library";
            const auto output = library ? std::string("libown.so") : name;
            const auto dir = overlay_root / ".local/build" / id;
            const auto output_pin = file(dir / output, elf_bytes);
            const auto url = "https://example.invalid/" + build.profile + "-" + name + "-" + output;
            manifest["androidNativeComponents"][build.profile + "/" + name] = {
                    {"url", url}, {"sha256", output_pin}};
            const auto receipt = dir / "receipt.json";
            write_private_json(receipt, {{"schema", 1},
                                         {"type", "native"},
                                         {"output_type", library ? "shared-library" : "executable"},
                                         {"api", 28},
                                         {"abi", "arm64-v8a"},
                                         {"output", output},
                                         {"bytes", 512},
                                         {"sha256", output_pin},
                                         {"asset", url}});
            executable_build.build->native_components[id] = {receipt, sha256_file(receipt)};

            if (!library) {
                write_private_json(profile_dir / "components" / id / "component.json",
                                   {{"type", "native"},
                                    {"minSdk", 28},
                                    {"outputType", "executable"},
                                    {"output", id}});
            }
        }

        std::filesystem::remove(overlay_root / "src/app/toolchain.json");
        write_private_json(overlay_root / "src/app/toolchain.json", manifest);
        executable_build.build->tool_manifest_sha256 =
                sha256_file(overlay_root / "src/app/toolchain.json");
        write_private_json(profile_dir / "components/library/component.json",
                           {{"type", "native"}, {"minSdk", 28}, {"output", "libown.so"}});
        write_private_json(profile_dir / "profile.json", executable_profile);
        executable_build.profile_sha256 = sha256_file(profile_dir / "profile.json");
        check(java_preparation_request(overlay_root, executable_build)
                      .at("native_components")
                      .size() == 3);
        Json executable_response = {
                {"schema", 1},
                {"operation", "build-artifacts"},
                {"profile", build.profile},
                {"revision", current_profile_revision(overlay_root, build.profile)},
                {"machine_ready", false},
                {"guest_started", false},
                {"components", Json::array({"first", "second", "library"})},
                {"patch_nodes", Json::array()},
                {"step_source_pins", Json::object()},
                {"artifacts_built", true},
                {"artifacts", Json::object()}};

        for (const auto &[id, item] : executable_build.build->native_components) {
            const auto proof = read_private_json(item.receipt);
            executable_response["artifacts"]["component:" + id] = {
                    {"file",
                     (item.receipt.parent_path() / proof.at("output").get<std::string>()).string()},
                    {"sha256", proof.at("sha256")},
                    {"bytes", proof.at("bytes")}};
        }

        validate_java_preparation_response(overlay_root, executable_build, executable_response);
        auto wrong_response = executable_response;
        wrong_response["artifacts"]["component:first"] =
                wrong_response["artifacts"]["component:second"];
        bool response_rejected = false;
        try {
            validate_java_preparation_response(overlay_root, executable_build, wrong_response);
        } catch (...) {
            response_rejected = true;
        }

        check(response_rejected);
        auto invalid_executable = executable_build;
        invalid_executable.build->native_components.erase("first");
        reject(overlay_root, invalid_executable);
        invalid_executable = executable_build;
        invalid_executable.build.value().native_components["extra"] =
                invalid_executable.build.value().native_components.at("first");
        reject(overlay_root, invalid_executable);
        invalid_executable = executable_build;
        invalid_executable.build.value().native_components["first"].receipt_sha256 =
                std::string(64, '0');
        reject(overlay_root, invalid_executable);
        invalid_executable = executable_build;
        std::swap(invalid_executable.build.value().native_components["first"],
                  invalid_executable.build.value().native_components["second"]);
        reject(overlay_root, invalid_executable);
        file(overlay_root / ".local/build/first/first", "tampered");
        reject(overlay_root, executable_build);
        file(overlay_root / ".local/build/first/first", elf_bytes);
        write_private_json(profile_dir / "profile.json", overlay_profile);
        std::filesystem::remove(overlay_root / "src/app/toolchain.json");
        std::filesystem::copy_file(root / "src/app/toolchain.json",
                                   overlay_root / "src/app/toolchain.json");

        if (!codec_draft.empty()) {
            auto codec_build = build;
            codec_build.build->tool_manifest_sha256 = sha256_file(root / "src/app/toolchain.json");
            codec_build.profile = request.profile;
            codec_build.profile_sha256 = request.profile_sha256;
            auto &cb = *codec_build.build;
            const auto native = codec_draft / "receipt.json";
            const auto receipt = read_private_json(native, 128 * 1024);
            const auto input =
                    std::filesystem::path(receipt.at("files")[0].at("input").get<std::string>());
            const auto extracted = input.parent_path().parent_path().parent_path() / "receipt.json";
            cb.native_files_receipt = native;
            cb.native_files_receipt_sha256 = sha256_file(native);
            cb.android_inputs["/system/lib64/libstagefright_ccodec.so"] = {extracted,
                                                                           sha256_file(extracted)};
            const auto accepted = java_preparation_request(root, codec_build);
            check(accepted.at("native_files") ==
                          Json({{"receipt", native.string()},
                                {"receipt_sha256", cb.native_files_receipt_sha256}}) &&
                  !std::filesystem::exists(cb.work));

            for (unsigned mode = 0; mode < 6; ++mode) {
                auto changed = receipt;

                if (mode == 0) {
                    changed["profile_provenance"]["profile"] = "other";
                }

                if (mode == 1) {
                    changed["files"][0]["api"] = 30;
                }

                if (mode == 2) {
                    changed["files"][0]["profile"] = "other";
                }

                if (mode == 3) {
                    changed["files"].push_back(changed["files"][0]);
                }

                if (mode == 4) {
                    changed["files"][0]["donor"] = {{"input", "/outside"},
                                                    {"sha256", std::string(64, '0')}};
                }

                const auto directory = fixture / ("codec-native-" + std::to_string(mode));
                ensure_private_directory(directory);
                std::filesystem::copy_file(codec_draft / "ccodec-allocation-a9.output",
                                           directory / "ccodec-allocation-a9.output");

                if (mode == 5) {
                    file(directory / "ccodec-allocation-a9.output", "corrupt codec");
                }

                write_private_json(directory / "receipt.json", changed);
                auto bad_codec = codec_build;
                bad_codec.build->native_files_receipt = directory / "receipt.json";
                bad_codec.build->native_files_receipt_sha256 =
                        sha256_file(directory / "receipt.json");
                reject(root, bad_codec);
            }

            auto absent = codec_build;
            absent.build->native_files_receipt.clear();
            absent.build->native_files_receipt_sha256.clear();
            reject(root, absent);
            check(!std::filesystem::exists(cb.work));
            std::cout << "actual codec native receipt accepted by C++ request factory; "
                         "seven malformed/missing handoffs refused, no helper/guest\n";
        }

        auto invalid = build;
        invalid.build->platform_sha256 = std::string(64, '0');
        reject(overlay_root, invalid);
        invalid = build;
        invalid.build.value().platform = "/outside/android.jar";
        reject(overlay_root, invalid);
        invalid = build;
        invalid.build.value().platform.clear();
        reject(overlay_root, invalid);
        invalid = build;
        invalid.build.value().platform.clear();
        invalid.build.value().platform_sha256.clear();
        reject(overlay_root, invalid);
        invalid = build;
        invalid.build.value().tool_files.erase("build-tools/" + tools + "/zipalign" + exe);
        reject(overlay_root, invalid);
        const auto receipt_root = fixture / "receipt-root";
        ensure_private_directory(receipt_root / ".local/sdk");
        ensure_private_directory(receipt_root / "src/app");
        std::filesystem::copy_file(root / "src/app/toolchain.json",
                                   receipt_root / "src/app/toolchain.json");
        const auto qinggan11_descriptor =
                read_private_json(root / "profiles/free-11-chinese-20260731-7.3.1/profile.json")
                        .at("android");
        const Json tiny = {{"schema", 1},
                           {"android", qinggan11_descriptor},
                           {"patches", Json::object()},
                           {"components", Json::object()}};
        write_private_json(receipt_root / "profiles/api30-fixture/profile.json", tiny);
        auto tiny_qinggan09 = tiny;
        tiny_qinggan09["android"] =
                read_private_json(root / "profiles" / request.profile / "profile.json")
                        .at("android");
        write_private_json(receipt_root / "profiles" / request.profile / "profile.json",
                           tiny_qinggan09);
        // Source profile files are valid artifacts; siblings, aliases and
        // undeclared files are not.
        auto response_profile = tiny;
        response_profile["files"] = {{"declared", {{"file", "source.txt"}}}};
        const auto response_root = receipt_root / "profiles/api30-fixture",
                   source = response_root / "files/source.txt";
        const auto source_pin = file(source, "profile source artifact");
        write_private_json(response_root / "profile.json", response_profile);
        auto response_request = build;
        response_request.profile = "api30-fixture";
        response_request.profile_sha256 = sha256_file(response_root / "profile.json");
        Json helper = {{"schema", 1},
                       {"operation", "build-artifacts"},
                       {"profile", "api30-fixture"},
                       {"revision", current_profile_revision(receipt_root, "api30-fixture")},
                       {"machine_ready", false},
                       {"guest_started", false},
                       {"components", Json::array()},
                       {"patch_nodes", Json::array()},
                       {"step_source_pins", Json::object()},
                       {"artifacts_built", true},
                       {"artifacts",
                        {{"files:declared",
                          {{"file", source.string()},
                           {"sha256", source_pin},
                           {"bytes", std::filesystem::file_size(source)}}}}}};
        validate_java_preparation_response(receipt_root, response_request, helper);
        auto reject_response = [&](const Json &value) {
            bool failed = false;
            try {
                validate_java_preparation_response(receipt_root, response_request, value);
            } catch (const std::exception &) {
                failed = true;
            }

            check(failed);
        };
        const auto component_source = response_root / "components/own/src/Main.java";
        const auto source_snapshot = current_profile_revision(receipt_root, "api30-fixture");
        response_request.source_snapshot = source_snapshot;
        file(component_source, "changed consumed source");
        reject_response(helper);
        std::filesystem::remove(component_source);
        check(current_profile_revision(receipt_root, "api30-fixture") == source_snapshot);
        response_request.source_snapshot.clear();
        validate_java_preparation_response(receipt_root, response_request, helper);

        for (const auto &candidate : {receipt_root / "profiles/sibling/files/source.txt",
                                      response_root / "files/undeclared.txt",
                                      response_root / "files/../files/source.txt"}) {
            if (candidate.lexically_normal() == candidate) {
                file(candidate, "profile source artifact");
            }

            auto changed = helper;
            changed["artifacts"]["files:declared"]["file"] = candidate.string();
            reject_response(changed);
        }

        auto changed = helper;
        changed["artifacts"] = {
                {"component:declared", helper.at("artifacts").at("files:declared")}};
        reject_response(changed);
        changed = helper;
        changed["artifacts"]["files:declared"]["sha256"] = std::string(64, '0');
        reject_response(changed);
        response_profile["files"]["declared"]["sha256"] = source_pin;
        write_private_json(response_root / "profile.json", response_profile);
        response_request.profile_sha256 = sha256_file(response_root / "profile.json");
        helper["revision"] = current_profile_revision(receipt_root, "api30-fixture");
        validate_java_preparation_response(receipt_root, response_request, helper);
        changed = helper;
        changed["artifacts"]["files:declared"]["sha256"] = file(source, "changed profile artifact");
        changed["artifacts"]["files:declared"]["bytes"] = std::filesystem::file_size(source);
        reject_response(changed);
        auto a11build = build;
        a11build.profile = "api30-fixture";
        a11build.profile_sha256 =
                sha256_file(receipt_root / "profiles" / a11build.profile / "profile.json");
        a11build.build->sdk = receipt_root / ".local/sdk";
        a11build.build->work = receipt_root / ".local/work";

        for (const auto &[name, pin] : b.tool_files) {
            (void)pin;
            file(a11build.build->sdk / name, "pinned fixture SDK file");
        }

        a11build.build->platform = receipt_root / ".local/android.jar";
        a11build.build->platform_sha256 = file(a11build.build->platform,
                                               "pinned fixture platform JAR");
        const auto extracted = receipt_root / ".local/extracted/system/own";
        const auto extracted_pin = file(extracted, "fixture extracted bytes");
        const auto extraction_receipt = receipt_root / ".local/extracted/receipt.json";
        Json receipt = {{"schema", 1},
                        {"native", true},
                        {"filesystem_mounted", false},
                        {"image_sha256",
                         "b9879a686e47e26d1ba1c2f2eafd417e5f9415d68a4e03a0c2adae47f3fb53ec"},
                        {"logical_partition", "system"},
                        {"partition_offset", 3145728},
                        {"logical_partition_bytes", 789696512},
                        {"lp_metadata_sha256",
                         "f535d7f845ccdbd69a01d41639031e7d1a4950f21dc30df57dc4a438af030eee"},
                        {"files", {{"system/own", {{"sha256", extracted_pin}, {"bytes", 23}}}}}};
        auto bind = [&](const Json &data) {
            write_private_json(extraction_receipt, data);
            a11build.build->android_inputs["/system/own"] = {extraction_receipt,
                                                             sha256_file(extraction_receipt)};
        };
        bind(receipt);
        check(java_preparation_request(receipt_root, a11build).at("android_inputs").size() == 1);

        for (unsigned mode = 0; mode < 5; ++mode) {
            auto changed = receipt;

            if (mode == 0) {
                changed["image_sha256"] =
                        "1d38dd537caa931441dc92949098b0f61b112587769877266f79f6e826822009";
            }

            if (mode == 1) {
                changed.erase("logical_partition");
            }

            if (mode == 2) {
                changed["lp_metadata_sha256"] = std::string(64, '0');
            }

            if (mode == 3) {
                changed["partition_offset"] = 0;
            }

            if (mode == 4) {
                changed["logical_partition_bytes"] = 789696513;
            }

            bind(changed);
            reject(receipt_root, a11build);
        }

        bind(receipt);
        auto cross = a11build;
        cross.profile = request.profile;
        cross.profile_sha256 =
                sha256_file(receipt_root / "profiles" / request.profile / "profile.json");
        reject(receipt_root, cross);
        const auto ext_file = receipt_root / ".local/extracted-ext/priv-app/SystemUI/SystemUI.apk",
                   ext_receipt = receipt_root / ".local/extracted-ext/receipt.json";
        const auto ext_pin = file(ext_file, "fixture stock SystemUI");
        auto extension = receipt;
        extension["logical_partition"] = "system_ext";
        extension["partition_offset"] = 793772032;
        extension["logical_partition_bytes"] = 106733568;
        extension["files"] = {
                {"priv-app/SystemUI/SystemUI.apk",
                 {{"sha256", ext_pin}, {"bytes", std::filesystem::file_size(ext_file)}}}};
        auto bind_extension = [&](const Json &data) {
            write_private_json(ext_receipt, data);
            a11build.build->android_inputs.clear();
            a11build.build->android_inputs["/system_ext/priv-app/SystemUI/SystemUI.apk"] = {
                    ext_receipt, sha256_file(ext_receipt)};
        };
        bind_extension(extension);
        check(java_preparation_request(receipt_root, a11build)
                      .at("android_inputs")
                      .contains("/system_ext/priv-app/SystemUI/SystemUI.apk"));

        for (unsigned mode = 0; mode < 6; ++mode) {
            auto changed = extension;

            if (mode == 0) {
                changed["logical_partition"] = "system";
            }

            if (mode == 1) {
                changed["partition_offset"] = 3145728;
            }

            if (mode == 2) {
                changed["logical_partition_bytes"] = 789696512;
            }

            if (mode == 3) {
                changed["lp_metadata_sha256"] = std::string(64, '0');
            }

            if (mode == 4) {
                changed["image_sha256"] = std::string(64, '0');
            }

            if (mode == 5) {
                changed["files"]["priv-app/SystemUI/SystemUI.apk"]["bytes"] = 1;
            }

            bind_extension(changed);
            reject(receipt_root, a11build);
        }

        bind_extension(extension);

        for (const auto *path :
             {"/system_ext/../own", "/system_ext2/priv-app/SystemUI/SystemUI.apk",
              "/outside/SystemUI.apk"}) {
            auto invalid = a11build;
            invalid.build->android_inputs.clear();
            invalid.build->android_inputs[path] = {ext_receipt, sha256_file(ext_receipt)};
            reject(receipt_root, invalid);
        }

        cross = a11build;
        cross.profile = request.profile;
        cross.profile_sha256 =
                sha256_file(receipt_root / "profiles" / request.profile / "profile.json");
        reject(receipt_root, cross);
        const auto destination = root / ".local/build/tmp" /
                                 ("java-preparation-preflight-" + random_token());
        JavaPreparationRuntime runtime;
        runtime.jdk = "relative";
        bool failed = false;
        try {
            prepare_java_artifacts(root, runtime, request, destination);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(destination));
        runtime.jdk = root / ".local/missing-jdk";
        failed = false;
        try {
            prepare_java_artifacts(root, runtime, request, destination);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(destination));
        failed = false;
        try {
            prepare_java_artifacts(root, runtime, request, destination, 300001);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed && !std::filesystem::exists(destination));
        // Every full artifact graph may use an hour; plans retain the five-minute bound.
        runtime.jdk = "relative";
        auto timeout_guard = [&](const std::filesystem::path &selected_root,
                                 const JavaPreparationRequest &selected, int timeout,
                                 bool accepted) {
            std::string reason;
            try {
                prepare_java_artifacts(selected_root, runtime, selected, destination, timeout);
            } catch (const std::exception &error) {
                reason = error.what();
            }

            const std::string expected =
                    accepted ? "JAVA_PREPARATION: normalized absolute path required"
                             : "JAVA_PREPARATION: bounded timeout required";

            if (reason != expected) {
                throw std::runtime_error("Java preparation timeout guard for " + selected.profile +
                                         " at " + std::to_string(timeout) + " ms expected " +
                                         expected + ", got " + reason);
            }

            check(!std::filesystem::exists(destination));
        };

        for (const auto *id :
             {"passion-11-russian-20260403-2.1.4.80", "free-11-chinese-20250710-6.11.1",
              "free-11-chinese-20260731-7.3.1", "free-09-chinese-20260106-6.0.3",
              "free-09-chinese-20221230-nxp-rc45", "other"}) {
            auto selected = a11build;
            selected.profile = id;
            check(java_preparation_timeout_ms(selected) == 3600000);
            selected.operation = JavaPreparationOperation::plan;
            check(java_preparation_timeout_ms(selected) == 300000);
        }

        auto passion_build = a11build;
        passion_build.profile = "passion-11-russian-20260403-2.1.4.80";
        const auto passion_profile = receipt_root / "profiles" / passion_build.profile /
                                     "profile.json";
        write_private_json(passion_profile,
                           read_private_json(receipt_root / "profiles/api30-fixture/profile.json"));
        passion_build.profile_sha256 = sha256_file(passion_profile);
        check(java_preparation_request(receipt_root, passion_build).at("operation") ==
              "build-artifacts");
        timeout_guard(receipt_root, passion_build, 3600000, true);
        timeout_guard(receipt_root, passion_build, 3600001, false);
        timeout_guard(receipt_root, a11build, 3600000, true);
        timeout_guard(receipt_root, a11build, 3600001, false);
        timeout_guard(root, request, 300000, true);
        timeout_guard(root, request, 300001, false);
        timeout_guard(root, request, 600000, false);
        std::cout << "typed Java preparation request/path/operation/runtime bounds "
                     "passed; no process started\n";

        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';

        return 1;
    }
}
