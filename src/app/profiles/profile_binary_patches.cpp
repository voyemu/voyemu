#include "profile_binary_patches.hpp"
#include "check.hpp"
#include "error.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_originals.hpp"
#include "profile_step_inputs.hpp"
#include "quickboot.hpp"
#include <algorithm>
#include <fstream>
namespace voyemu {
namespace {
constexpr Check require{"BINARY_PATCH"};
constexpr ProfileStepInputs inputs{require};
} // namespace

ProfileBinaryPatch plan_profile_binary_patch(
        const std::filesystem::path &root, std::string_view profile, std::string_view name,
        const std::map<std::string, std::filesystem::path> &builds,
        const std::filesystem::path &compiler, const std::string &compiler_sha256) {
    inputs.ordinary(root);
    require(valid_profile_name(profile), "safe profile name required");
    const bool music = name == "MusicConcate";
    require(music || name == "QGIME" || name == "QGIMESecond", "unsupported binary step");
    require((music && builds.empty() && compiler.empty() && compiler_sha256.empty()) ||
                    (!music && builds.size() == 2 && builds.contains("qgime-handwrite") &&
                     builds.contains("qgime-pinyin")),
            "exact native producers required");
    const auto directory = authoring_directory(root, profile);
    const std::string step = music ? "music-arm64-libs.json" : "qgime-arm64-natives.json";
    std::map<std::filesystem::path, std::pair<Json, std::string>> tracked;
    std::map<std::filesystem::path, Json> source_trees;
    auto track = [&](const std::filesystem::path &path, std::uint64_t maximum) {
        inputs.file(path, maximum);
        const auto epoch = cache_file_identity(path);
        const auto hash = sha256_file(path);
        require(cache_file_identity(path) == epoch, "input changed during hash");
        tracked[path] = {epoch, hash};

        return hash;
    };
    track(directory / "patches" / step, 128 * 1024);
    const auto definition =
            Json::parse(authoring_profile_bytes(root, profile, [&](const auto &path) {
                const auto pin = track(path, 512 * 1024);
                const auto bytes = read_private_json_bytes(path, 512 * 1024);
                require(pin == sha256_bytes(bytes), "profile changed during read");

                return bytes;
            }));
    require(definition.at("schema") == 1, "profile schema");
    const auto &node = definition.at("patches").at(std::string(name));
    const Json expected_uses =
            music ? Json::array({"component:qg-runtime"})
                  : Json::array({"component:qg-runtime", "component:qgime-handwrite",
                                 "component:qgime-pinyin"});
    const Json expected_steps =
            music ? Json::array({"music-arm64-libs.json", "add-qg-runtime.json"})
                  : Json::array({"add-qg-runtime.json", "qgime-arm64-natives.json",
                                 "ime-display-routing/ime-display-routing.json"});
    require(node == Json({{"type", "apk"},
                          {"input", "original:" + std::string(name)},
                          {"uses", expected_uses},
                          {"steps", expected_steps},
                          {"sign", "platform"}}),
            "profile node changed from implemented partial recipe");
    bool installed = false;

    for (const auto &item : definition.at("install")) {
        if (item.value("artifact", std::string{}) == "patched:" + std::string(name)) {
            require(item == Json({{"artifact", "patched:" + std::string(name)}, {"type", "apk"}}) &&
                            !installed,
                    "ambiguous install declaration");
            installed = true;
        }
    }

    require(installed, "profile node not installed");
    const auto &original = definition.at("original").at(std::string(name));
    const auto original_pin = original.at("sha256").get<std::string>();
    require(original.at("file") == std::string(name) + ".apk" && sha256_text(original_pin),
            "original declaration");
    ProfileBinaryPatch result;
    result.source = profile_originals_directory(root, profile) / (std::string(name) + ".apk");
    result.source_sha256 = original_pin;
    require(track(result.source, 1ULL << 30) == original_pin, "original APK pin mismatch");

    if (music) {
        result.removals = {{"lib/armeabi-v7a/libBugly.so",
                            "e3094e2d13dd6f65ceb9138d8562dea219718d9f0536ac19f6c9f1d17da95c20"},
                           {"lib/armeabi-v7a/libpl_droidsonroids_gif.so",
                            "4f8e8ef4dd9c05ca84e797522d301dcf165d5a4879456707be5787acdeaab402"}};
    } else {
        result.removals = {{"lib/armeabi-v7a/libjni_qgHandWrite.so",
                            "0726317b7f88149f493ea342f1fa51e9185f1845bd823416d47690f1f099dbb3"},
                           {"lib/armeabi-v7a/libjni_qgime.so",
                            "4bedfd2d15fa79adb770e3864583d058e464f1cef7a3f64918d5e38fab023221"}};
    }

    for (const auto &item : result.removals) {
        read_pinned_zip_entry(result.source, original_pin, item.entry, item.sha256);
    }

    Json producers = Json::object();

    if (!music) {
        require(sha256_text(compiler_sha256) && track(compiler, 512ULL << 20) == compiler_sha256,
                "native compiler pin mismatch");

        for (const auto &[component, build] : builds) {
            inputs.ordinary(build);
            require(definition.at("components").at(component) == "components/" + component,
                    "component source mapping");
            const auto source = directory / "components" / component;
            const auto files = inputs.inventory(source);
            source_trees[source] = files;
            const auto output = component == "qgime-handwrite" ? "libjni_qgHandWrite.so"
                                                               : "libjni_qgime.so";
            require(read_private_json(source / "component.json") ==
                            Json({{"type", "native"}, {"minSdk", 28}, {"output", output}}),
                    "native recipe mismatch");
            const auto receipt_path = build / "receipt.json";
            const auto receipt_pin = track(receipt_path, 128 * 1024);
            const auto receipt = read_private_json(receipt_path);
            require(receipt.at("schema") == 1 && receipt.at("type") == "native" &&
                            receipt.at("api") == 28 && receipt.at("abi") == "arm64-v8a" &&
                            receipt.at("output") == output && receipt.at("language") == "c11" &&
                            receipt.at("compiler_sha256") == compiler_sha256 &&
                            receipt.at("guest_sonames").empty() &&
                            receipt.at("materialized_source").empty() &&
                            receipt.at("host_java_required") == false &&
                            receipt.at("host_node_required") == false &&
                            receipt.at("host_python_required") == false,
                    "native producer receipt mismatch");
            const auto library = build / output;
            const auto hash = track(library, 32ULL << 20);
            require(receipt.at("sha256") == hash &&
                            receipt.at("bytes") == std::filesystem::file_size(library),
                    "native output mismatch");
            std::ifstream input(library, std::ios::binary);
            std::string payload((std::istreambuf_iterator<char>(input)), {});
            require(payload.size() >= 64 &&
                            payload.substr(0, 4) == std::string("\x7f"
                                                                "ELF",
                                                                4) &&
                            payload[4] == 2 && payload[5] == 1 && payload[16] == 3 &&
                            payload[17] == 0 && static_cast<unsigned char>(payload[18]) == 183 &&
                            payload[19] == 0 && sha256_bytes(payload) == hash,
                    "native ARM64 shared ELF required");
            result.additions.push_back(
                    {std::string("lib/arm64-v8a/") + output, std::move(payload), hash});
            producers[component] = {{"receipt_sha256", receipt_pin},
                                    {"output_sha256", hash},
                                    {"compiler_sha256", compiler_sha256}};
        }
    }

    Json removed = Json::array();

    for (const auto &item : result.removals) {
        removed.push_back({{"entry", item.entry}, {"sha256", item.sha256}});
    }

    result.provenance = {{"profile", profile},
                         {"node", name},
                         {"step", step},
                         {"source_sha256", original_pin},
                         {"removed", removed},
                         {"producers", producers},
                         {"full_node_supported", false},
                         {"machine_ready", false},
                         {"remaining_steps",
                          music ? Json::array({"add-qg-runtime.json"})
                                : Json::array({"add-qg-runtime.json",
                                               "ime-display-routing/ime-display-routing.json"})}};
    result.revalidate = [tracked, source_trees] {
        for (const auto &[path, value] : tracked) {
            require(cache_file_identity(path) == value.first && sha256_file(path) == value.second,
                    "bound input changed");
        }

        for (const auto &[source, files] : source_trees) {
            require(inputs.inventory(source) == files, "component source changed");
        }
    };
    result.revalidate();

    return result;
}
} // namespace voyemu
