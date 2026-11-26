#include "profile_catalog.hpp"
#include "check.hpp"
#include "cli_messages.hpp"
#include "embedded_data.hpp"
#include "error.hpp"
#include "file_patch.hpp"
#include "process.hpp"
#include "qinggan11_startup.hpp"
#include "quickboot.hpp"
#include <algorithm>
#include <functional>
#include <map>
#include <stdexcept>
namespace voyemu {
#include "profile_catalog.inc"

namespace {
constexpr std::size_t max_profile_bytes = 1 << 20;

std::string profile_bytes(const std::filesystem::path &file) {
    const auto epoch = cache_file_identity(file);
    const auto bytes = read_private_json_bytes(file, max_profile_bytes);

    if (cache_file_identity(file) != epoch) {
        throw VoyemuError("PROFILE_CHANGED", "profile input changed while reading");
    }

    return bytes;
}

Json resolve_target(Json definition, std::string_view name,
                    const std::function<Json(const std::string &)> &read_base) {
    const Check need{"PROFILE_TARGET"};
    const auto &targets = definition.at("targets");

    need(targets.is_object() && targets.size() == 2 && targets.contains("arm") &&
                 targets.contains("x86") && (name == "arm" || name == "x86") &&
                 !definition.contains("target") &&
                 definition.at("android").value("package", std::string{}) ==
                         "system-images;android-30;default;arm64-v8a",
         "invalid Android target catalogue");
    const auto entry = targets.at(name);
    const bool x86 = name == "x86";
    const auto abi = x86 ? "x86_64" : "arm64-v8a";
    const auto preparation = x86 ? "signed-offline" : "sdk";
    need(entry.is_object() && entry.size() == (x86 ? 4U : 2U) &&
                 entry.value("guestAbi", std::string{}) == abi &&
                 entry.value("preparation", std::string{}) == preparation,
         "target ABI or preparation differs");
    Json target = {{"name", name}, {"guestAbi", abi}, {"preparation", preparation}};

    if (x86) {
        const auto base_name = entry.value("androidBase", std::string{});
        const auto emulator = entry.value("emulator", Json::object());
        const auto memory = emulator.is_object() ? emulator.value("memory", Json(4096)) : Json{};
        need(valid_profile_name(base_name) && emulator.is_object() &&
                     emulator.size() ==
                             2U + emulator.contains("memory") + emulator.contains("audioOutput") &&
                     emulator.value("acceleration", std::string{}) == "kvm" &&
                     emulator.value("gpuMode", std::string{}) == "host" &&
                     emulator.value("audioOutput", Json(false)).is_boolean() &&
                     memory.is_number_integer() && memory >= 512 && memory <= 16384,
             "invalid x86 base or emulator settings");
        auto base = read_base(base_name);
        need(base.is_object() &&
                     base.value("package", std::string{}) ==
                             "system-images;android-30;default;x86_64" &&
                     base.contains("clean_base") && !base.contains("development_kernel"),
             "x86 target requires a pinned API30 SDK base");
        const auto features = definition.at("android").value("features", Json::object());

        if (!features.empty()) {
            base["features"].update(features);
        }

        definition["android"] = std::move(base);
        definition["emulator"].update(emulator);
        target["androidBase"] = base_name;
    }

    definition.erase("targets");
    definition["target"] = std::move(target);

    return definition;
}
} // namespace

std::filesystem::path authoring_directory(const std::filesystem::path &root,
                                          std::string_view name) {
    if (!valid_profile_name(name)) {
        throw VoyemuError("PROFILE_INVALID", "valid profile id required");
    }

    return root / "profiles" / std::string(name);
}

std::string authoring_profile_bytes(const std::filesystem::path &root, std::string_view name,
                                    std::string_view target) {
    return authoring_profile_bytes(root, name, profile_bytes, target);
}

std::string
authoring_profile_bytes(const std::filesystem::path &root, std::string_view name,
                        const std::function<std::string(const std::filesystem::path &)> &read,
                        std::string_view target) {
    const auto bytes = read(authoring_directory(root, name) / "profile.json");
    const auto source = Json::parse(bytes);

    if (!target.empty()) {
        if (!source.contains("targets") || source.value("id", std::string{}) != name) {
            throw VoyemuError("PROFILE_TARGET",
                              "profile does not declare the selected build target");
        }

        return resolve_target(source, target,
                              [&](const std::string &base) {
                                  return Json::parse(read(root / "profiles/common/android-bases" /
                                                          (base + ".json")));
                              })
                       .dump(2) +
               "\n";
    }

    return bytes;
}

Json authoring_profile(const std::filesystem::path &root, std::string_view name,
                       std::string_view target) {
    return Json::parse(authoring_profile_bytes(root, name, target));
}

std::string select_profile_target(const Json &definition, std::string_view requested,
                                  std::string_view host, bool kvm_available) {
    if (!definition.contains("targets")) {
        if (!requested.empty()) {
            throw cli::LocalizedError("PROFILE_TARGET", "error.profile_target_single");
        }

        return {};
    }

    const auto &targets = definition.at("targets");
    const auto selected =
            requested.empty() ? (host == "linux/x64" && kvm_available ? "x86" : "arm") : requested;

    if (!targets.is_object() || !targets.contains(selected)) {
        throw cli::LocalizedError("PROFILE_TARGET", "error.profile_target_missing",
                                  {{"target", std::string(selected)}});
    }

    if (selected == "arm") {
        return "arm";
    }

    if (selected == "x86" && host == "linux/x64") {
        if (!kvm_available) {
            throw cli::LocalizedError("PROFILE_TARGET", "error.profile_target_kvm");
        }

        return "x86";
    }

    throw cli::LocalizedError("PROFILE_TARGET", "error.profile_target_host",
                              {{"target", std::string(selected)}, {"host", std::string(host)}});
}

Json profile_target_identity(const Json &definition) {
    if (!definition.contains("target")) {
        return nullptr;
    }

    const auto &target = definition.at("target");

    return {{"name", target.at("name")},
            {"abi", target.at("guestAbi")},
            {"base_sha256", definition.at("android").at("sha256")}};
}

bool profile_multimedia_only(const Json &definition) {
    const auto target = definition.value("target", Json::object());

    return target.value("name", std::string{}) == "x86" &&
           target.value("guestAbi", std::string{}) == "x86_64" &&
           target.value("preparation", std::string{}) == "signed-offline" &&
           valid_profile_name(target.value("androidBase", std::string{}));
}

const Json &embedded_profile_catalog() {
    static const Json catalog = [] {
        auto parsed =
                Json::parse(inflate_embedded(embedded_catalog_json, embedded_catalog_json_size));

        for (const auto &record : parsed) {
            const auto &definition = record.at("definition");
            (void)profile_platform(definition);
            (void)profile_board(definition);
            (void)profile_title(definition);
        }

        return parsed;
    }();

    return catalog;
}

const Json &embedded_profile(std::string_view id) {
    for (const auto &record : embedded_profile_catalog()) {
        if (record.at("id") == id) {
            return record;
        }
    }

    throw VoyemuError("PROFILE_NOT_FOUND", "profile is not bundled");
}

std::vector<std::string> embedded_profile_names() {
    std::vector<std::string> result;

    for (const auto &record : embedded_profile_catalog()) {
        result.push_back(record.at("id").get<std::string>());
    }

    return result;
}

std::vector<std::string> embedded_profile_names(ProfilePlatform platform, ProfileBoard board) {
    std::vector<std::string> result;

    for (const auto &record : embedded_profile_catalog()) {
        const auto &definition = record.at("definition");

        if (profile_platform(definition) == platform && profile_board(definition) == board) {
            result.push_back(record.at("id").get<std::string>());
        }
    }

    return result;
}

bool embedded_profile_declares(std::string_view id, ProfilePlatform platform, ProfileBoard board) {
    for (const auto &record : embedded_profile_catalog()) {
        if (record.at("id") == id) {
            const auto &definition = record.at("definition");

            return profile_platform(definition) == platform && profile_board(definition) == board;
        }
    }

    return false;
}

bool record_declares(const Json &record, ProfilePlatform platform, ProfileBoard board) {
    return record.is_object() && record.contains("platform") &&
           profile_platform(record) == platform && profile_board(record) == board;
}

Json declared_patch_plan(const Json &definition) {
    const auto patches = definition.value("patches", Json::object());

    if (!patches.is_object()) {
        throw VoyemuError("PREPARATION_SCHEMA", "patches must be an object");
    }

    const auto android = definition.value("android", Json::object());
    const bool native_api28 =
            android.is_object() &&
            android.value("package", std::string{}).starts_with("system-images;android-28;");
    const bool original_navi = original_navi_requested(definition);

    if (original_navi || free731_usb_test_volume_visibility(definition)) {
        original_navi_preflight(definition, 30);
    }

    Json ordered = Json::array();
    std::map<std::string, unsigned> state;
    std::function<void(const std::string &)> visit;
    visit = [&](const std::string &id) {
        if (!patches.contains(id)) {
            throw VoyemuError("PREPARATION_REFERENCE", "unknown patch " + id);
        }

        if (state[id] == 2) {
            return;
        }

        if (state[id] == 1) {
            throw VoyemuError("PREPARATION_CYCLE", "patch dependency cycle at " + id);
        }

        state[id] = 1;
        const auto &patch = patches.at(id);
        const auto type = patch.at("type").get<std::string>();
        const bool qinggan11 = record_declares(definition, ProfilePlatform::qinggan11,
                                               ProfileBoard::sa8155),
                   passion = record_declares(definition, ProfilePlatform::passion,
                                             ProfileBoard::sa8155);
        const bool secondary_binding = (qinggan11 && id == "api30-secondary-navigation") ||
                                       (passion && id == "passion-api30-secondary-navigation");
        const auto package = android.value("package", std::string{});
        const bool secondary_sdk =
                package == "system-images;android-30;default;arm64-v8a" ||
                (passion && package == "system-images;android-30;default;x86_64" &&
                 profile_multimedia_only(definition) &&
                 !runtime_profile_reference(definition).empty() &&
                 definition.at("emulator").value("acceleration", std::string{}) == "kvm" &&
                 definition.at("emulator").value("gpuMode", std::string{}) == "host");
        const bool secondary_jar =
                secondary_binding && secondary_sdk &&
                (patch == Json{{"type", "jar"},
                               {"input", "android:/system/framework/services.jar"},
                               {"steps", Json::array({id + ".json"})}} ||
                 (passion &&
                  patch == Json{{"type", "jar"},
                                {"input", "android:/system/framework/services.jar"},
                                {"steps", Json::array({"passion-api30-secondary-navigation.json",
                                                       "passion-api30-display-power.json"})}}) ||
                 (passion &&
                  patch == Json{{"type", "jar"},
                                {"input", "android:/system/framework/services.jar"},
                                {"steps", Json::array({"passion-api30-secondary-navigation.json",
                                                       "passion-api30-display-power.json",
                                                       "passion-api30-startup-volume.json"})}}));
        const bool audio_consumer_jar =
                qinggan11 && id == "QGAPI" &&
                android.value("package", std::string{}) ==
                        "system-images;android-30;default;arm64-v8a" &&
                qinggan11_pinned_original(definition.value("original", Json::object())
                                                  .value("QGAPI", Json::object())) &&
                patch == Json{{"type", "jar"},
                              {"input", "original:QGAPI"},
                              {"steps", Json::array({"api30-audio-consumer.json"})}};
        const bool original_jar =
                original_navi &&
                android.value("package", std::string{}) ==
                        "system-images;android-30;default;arm64-v8a" &&
                (patch == Json{{"type", "jar"},
                               {"input", "component:view-observation"},
                               {"steps", Json::array({"original-navi-egl.json"})}} ||
                 patch == Json{{"type", "jar"},
                               {"input", "patched:api30-secondary-navigation"},
                               {"steps", original_navi_services_steps(definition)}} ||
                 (qinggan11_pinned_original(definition.value("original", Json::object())
                                                    .value("QGAPI", Json::object())) &&
                  patch == Json{{"type", "jar"},
                                {"input", "original:QGAPI"},
                                {"steps", original_navi_qgapi_steps(definition)}}) ||
                 patch == Json{{"type", "jar"},
                               {"input", "original:QGVehicle"},
                               {"steps", Json::array({"original-navi-vehicle.json"})}});

        if (type != "apk" && type != "dex" && type != "file" && !secondary_jar &&
            !audio_consumer_jar && !original_jar) {
            throw VoyemuError("PREPARATION_SCHEMA", "unsupported patch type");
        }

        Json dependencies = Json::array({patch.at("input")});

        if (patch.contains("uses")) {
            if (!patch.at("uses").is_array()) {
                throw VoyemuError("PREPARATION_SCHEMA", "uses must be an array");
            }

            for (const auto &reference : patch.at("uses")) {
                dependencies.push_back(reference);
            }
        }

        for (const auto &reference : dependencies) {
            const auto ref = reference.get<std::string>();
            const auto separator = ref.find(':');

            if (separator == std::string::npos || separator + 1 == ref.size()) {
                throw VoyemuError("PREPARATION_REFERENCE", "malformed reference");
            }

            const auto kind = ref.substr(0, separator), name = ref.substr(separator + 1);

            if (kind == "patched") {
                visit(name);
            } else if (kind == "original" || kind == "component") {
                const auto group = kind == "original" ? "original" : "components";

                if (!definition.contains(group) || !definition.at(group).contains(name)) {
                    throw VoyemuError("PREPARATION_REFERENCE", "unknown " + ref);
                }
            } else if (kind != "android") {
                throw VoyemuError("PREPARATION_REFERENCE", "unsupported " + kind);
            }
        }

        state[id] = 2;
        Json node = {{"id", id}, {"type", type}, {"dependencies", dependencies}};
        const auto native_steps = native_file_patch_steps(id);

        if (type == "file" && !native_steps.empty() && patch.contains("steps") &&
            patch.at("steps") == Json(native_steps)) {
            if (native_api28) {
                node["native_recipe"] = {
                        {"id", id}, {"api", 28}, {"scope", "pinned-file-draft-handler"}};
            } else {
                node["native_recipe_unavailable"] = "android_api_not_supported";
            }
        }

        ordered.push_back(std::move(node));
    };

    for (auto it = patches.begin(); it != patches.end(); ++it) {
        visit(it.key());
    }

    return {{"schema", 1},
            {"scope", "declared-patch-dependencies"},
            {"executable", false},
            {"patches", ordered}};
}
} // namespace voyemu
