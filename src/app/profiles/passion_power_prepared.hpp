#pragma once
#include "check.hpp"
#include "error.hpp"
#include "os/fs.hpp"
#include "passion_power_owner.hpp"
#include "passion_prepared_guest.hpp"
#include "process.hpp"
#include "quickboot.hpp"
#include "zip_archive.hpp"
#include <algorithm>
#include <set>
namespace voyemu {
inline constexpr Check power_need{"OEM_DISPLAY_POWER"};

inline bool power_pin(const std::string &pin) {
    return sha256_text(pin);
}

inline bool passion_power_requested(const Json &definition) {
    if (definition.value("platform", Json()) != "passion") {
        return false;
    }

    const auto &patches = definition.at("patches");
    auto contains = [&](const char *name, const char *step) {
        const auto &steps = patches.at(name).at("steps");

        return std::find(steps.begin(), steps.end(), Json(step)) != steps.end();
    };
    const bool sdk = contains("passion-api30-secondary-navigation",
                              "passion-api30-display-power.json"),
               oem = contains("MegaNexusService", "passion-api30-nexus-power.json");
    power_need(sdk == oem, "partial power graph rejected");

    return sdk;
}

inline Json passion_power_csv() {
    return Json::parse(std::string(
            R"CSV({"system/etc/screen-control/screen0_off_change.csv":"7e82e683f773e0e300fe7e1f2c097381f0f94ff784d9705d350523f870081881","system/etc/screen-control/screen0_off_keep.csv":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","system/etc/screen-control/screen0_on_change.csv":"dbfe5e0802173415484a1640ed3024a181843ad40d895320952db3a4d8a7bfff","system/etc/screen-control/screen0_on_keep.csv":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","system/etc/screen-control/screen1_off_change.csv":"3aee3f501728d48de7a4c2a189fec04b1c9ddfb7898cd0dcc636129faa908ac0","system/etc/screen-control/screen1_off_keep.csv":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","system/etc/screen-control/screen1_on_change.csv":"e2a2f3a83123cf347c7f0ec8cba58fa077e402b9a3317b36bec2225cbfb65f82","system/etc/screen-control/screen1_on_keep.csv":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f"})CSV"));
}

inline Json passion_power_targets() {
    Json targets = {
            {"/system/framework/services.jar", "patched:passion-api30-secondary-navigation"},
            {"/system/priv-app/MegaNexusService/MegaNexusService.apk", "patched:MegaNexusService"}};
    const auto csv = passion_power_csv();

    for (auto it = csv.begin(); it != csv.end(); ++it) {
        auto name = std::filesystem::path(it.key()).stem().string();
        targets["/" + it.key()] = "original:screen-control-" + name;
    }

    return targets;
}

inline void passion_power_cold_check(const Json &candidate, const std::string &artifact,
                                     const std::string &target, const std::string &pin) {
    unsigned installed = 0, checked = 0;

    for (const auto &row : candidate.at("installed")) {
        if (row.at("artifact") == artifact && row.at("target") == target) {
            power_need(row.at("sha256") == pin && !row.value("mutable", false),
                       "cold installed artifact differs");
            ++installed;
        }
    }

    const auto id = "artifact:" + artifact + ":" + target;

    for (const auto &row : candidate.at("checks")) {
        if (row.at("id") == id) {
            power_need(row.at("expected") == pin && row.at("actual") == pin &&
                               row.at("passed") == true,
                       "cold merged-view guest hash failed");
            ++checked;
        }
    }

    power_need(installed == 1 && checked == 1,
               "exact one installed artifact and cold merged-view hash required");
}

inline std::string passion_power_file(const std::filesystem::path &root,
                                      const std::filesystem::path &file) {
    const auto local = root / ".local";

    power_need(file.is_absolute() && file == file.lexically_normal(),
               "absolute ordinary artifact required");
    bool within = false;

    for (const auto &path : os::ancestors(file)) {
        power_need(!std::filesystem::is_symlink(path), "symlink artifact ancestor rejected");

        if (path == local) {
            within = true;
            break;
        }
    }

    power_need(within && std::filesystem::is_regular_file(std::filesystem::symlink_status(file)) &&
                       std::filesystem::hard_link_count(file) == 1 &&
                       std::filesystem::file_size(file) <= (64ULL << 20),
               "owned bounded artifact required");
    const auto epoch = cache_file_identity(file);
    auto pin = sha256_file(file);
    power_need(cache_file_identity(file) == epoch, "artifact changed during hash");

    return pin;
}

inline std::string passion_power_sdk_hook_pin(const Json &definition) {
    const auto &steps =
            definition.at("patches").at("passion-api30-secondary-navigation").at("steps");

    if (std::find(steps.begin(), steps.end(), Json("passion-api30-startup-volume.json")) ==
        steps.end()) {
        return "96df9b766b226c67f138232e1716a7d372dd1adf4d691b5ae471f2c31deb83e7";
    }

    power_need(steps == Json::array({"passion-api30-secondary-navigation.json",
                                     "passion-api30-display-power.json",
                                     "passion-api30-startup-volume.json"}),
               "exact composed navigation/power/startup-volume order required");

    return "b8d882888bd7575d78db9797a9b8f81e1897f786b0687d59ac79dffb40eba558";
}

inline void passion_power_helper_receipt(const std::string &reference, const std::string &archive,
                                         const Json &helper) {
    const bool sdk = reference == "patched:passion-api30-secondary-navigation";

    power_need(sdk || reference == "patched:MegaNexusService",
               "declared power helper artifact required");
    power_need(helper.is_object() && helper.size() == 6 &&
                       helper.at("contract") == "passion-display-power-helper-v1" &&
                       helper.at("artifact") == reference &&
                       helper.at("archive_sha256") == archive &&
                       helper.at("entry") == (sdk ? "classes3.dex" : "classes2.dex") &&
                       power_pin(helper.at("sha256").get<std::string>()) &&
                       helper.at("bytes").is_number_unsigned() &&
                       helper.at("bytes").get<std::uint64_t>() > 0 &&
                       helper.at("bytes").get<std::uint64_t>() <= (64ULL << 20),
               "helper receipt artifact/archive/entry contract differs");
}

// The extra field is admitted only after both the ordinary archive and its actual helper agree.
inline void passion_power_helper_artifact(const std::filesystem::path &root,
                                          const std::string &reference, const Json &artifact) {
    power_need(artifact.is_object() && artifact.size() == 4,
               "exact power artifact descriptor required");
    const std::filesystem::path file = artifact.at("file").get<std::string>();
    const auto pin = passion_power_file(root, file);
    power_need(artifact.at("sha256") == pin &&
                       artifact.at("bytes") == std::filesystem::file_size(file),
               "power artifact file changed");
    const auto &helper = artifact.at("power_helper");
    passion_power_helper_receipt(reference, pin, helper);
    const auto dex = read_pinned_zip_entry(file, pin, helper.at("entry").get<std::string>(),
                                           helper.at("sha256").get<std::string>());
    power_need(dex.size() == helper.at("bytes").get<std::uint64_t>(),
               "actual helper DEX size differs from artifact result");
}

inline Json passion_power_contract(const Json &definition, const Json &candidate, const Json &pins,
                                   const Json &helpers) {
    power_need(passion_power_requested(definition), "power graph not requested");
    power_need(candidate.at("schema") == 1 && candidate.at("kind") == "android-candidate" &&
                       candidate.at("profile") == definition.at("id") &&
                       candidate.at("prepared_VM") == true && candidate.at("stopped") == true &&
                       candidate.at("cold_boot_verified") == true,
               "accepted stopped cold candidate required");
    power_need(candidate.at("clean_base_archive_sha256") == definition.at("android").at("sha256"),
               "exact registered API30 clean source required");
    const auto abi = passion_prepared_guest_abi(definition, candidate, power_need);

    for (const auto &pair : std::vector<std::pair<std::string, std::string>>{
                 {"boot", "1"}, {"api", "30"}, {"abi", abi}, {"selinux", "Enforcing"}}) {
        unsigned count = 0;

        for (const auto &check : candidate.at("checks")) {
            if (check.at("id") == pair.first) {
                power_need(check.at("expected") == pair.second &&
                                   check.at("actual") == pair.second && check.at("passed") == true,
                           "cold API/ABI/boot/SELinux check differs");
                ++count;
            }
        }

        power_need(count == 1, "exact cold baseline check required");
    }

    const auto targets = passion_power_targets(), csv = passion_power_csv();
    power_need(pins.is_object() && pins.size() == targets.size(),
               "exact ten cold artifacts required");

    for (auto it = targets.begin(); it != targets.end(); ++it) {
        const auto pin = pins.at(it.key()).get<std::string>();
        power_need(power_pin(pin), "cold artifact pin required");

        if (csv.contains(it.key().substr(1))) {
            power_need(csv.at(it.key().substr(1)) == pin, "genuine screen policy differs");
        }

        passion_power_cold_check(candidate, it.value().get<std::string>(), it.key(), pin);
    }

    power_need(helpers.is_object() && helpers.size() == 2, "two helper receipts required");

    for (const auto &target :
         {std::string("/system/framework/services.jar"),
          std::string("/system/priv-app/MegaNexusService/MegaNexusService.apk")}) {
        passion_power_helper_receipt(targets.at(target).get<std::string>(),
                                     pins.at(target).get<std::string>(), helpers.at(target));
    }

    return {{"schema", 1},
            {"capability", media::PassionPowerOwner::capability()},
            {"artifact_result_sha256", candidate.at("artifact_result_sha256")},
            {"installed", pins},
            {"helpers", helpers},
            {"sdk_hook_dex_sha256", passion_power_sdk_hook_pin(definition)},
            {"oem_hook_dex_sha256",
             "886086f464577afd108ccedb83dbf42942c60c88554f73ba503c5fd1fafbc6f7"}};
}

// Called only after ordinary build_android_candidate's real merged guest cold SHA checks and stop.
inline Json build_passion_power_proof(const std::filesystem::path &root, const Json &definition,
                                      const Json &artifacts, const Json &candidate) {
    Json pins = Json::object();
    const auto targets = passion_power_targets();

    for (auto it = targets.begin(); it != targets.end(); ++it) {
        const auto &artifact = artifacts.at(it.value().get<std::string>());
        const std::filesystem::path file = artifact.at("file").get<std::string>();
        const auto pin = passion_power_file(root, file);
        power_need(artifact.at("sha256") == pin, "actual host artifact hash differs");
        pins[it.key()] = pin;
    }

    Json helpers = Json::object();

    for (const auto &target :
         {std::string("/system/framework/services.jar"),
          std::string("/system/priv-app/MegaNexusService/MegaNexusService.apk")}) {
        const bool sdk = target == "/system/framework/services.jar";
        const auto &artifact = artifacts.at(targets.at(target).get<std::string>());
        const std::filesystem::path file = artifact.at("file").get<std::string>();
        const auto pin = pins.at(target).get<std::string>();
        const auto &helper = artifact.at("power_helper");
        passion_power_helper_artifact(root, targets.at(target).get<std::string>(), artifact);
        helpers[target] = helper;
        (void)read_pinned_zip_entry(
                file, pin, "classes.dex",
                sdk ? passion_power_sdk_hook_pin(definition)
                    : "886086f464577afd108ccedb83dbf42942c60c88554f73ba503c5fd1fafbc6f7");
        const auto dex = read_pinned_zip_entry(file, pin, sdk ? "classes3.dex" : "classes2.dex",
                                               helper.at("sha256").get<std::string>());
        power_need(dex.size() == helper.at("bytes").get<std::uint64_t>(),
                   "actual helper DEX size differs from artifact result");
        power_need(passion_power_file(root, file) == pin, "archive changed after DEX verification");
    }

    return passion_power_contract(definition, candidate, pins, helpers);
}

inline Json validate_passion_power_candidate(const Json &definition, const Json &candidate,
                                             const Json &images, const std::string &profile_pin) {
    power_need(candidate.at("profile_sha256") == profile_pin && power_pin(profile_pin) &&
                       power_pin(candidate.at("artifact_result_sha256").get<std::string>()),
               "candidate profile/artifact source binding differs");
    power_need(candidate.at("android").at("images") == images,
               "cold candidate and exported image set differ");
    const auto &proof = candidate.at("display_power");
    power_need(proof == passion_power_contract(definition, candidate, proof.at("installed"),
                                               proof.at("helpers")),
               "cold power contract differs");

    return proof.at("capability");
}

// Copy only bounded evidence metadata, never lower/upper filesystem bytes or a VM image.
inline Json export_passion_power(const Json &definition, const Json &candidate,
                                 const std::filesystem::path &stage,
                                 const std::string &profile_pin) {
    if (!passion_power_requested(definition)) {
        return Json::object();
    }

    const auto cap = validate_passion_power_candidate(
            definition, candidate, candidate.at("android").at("images"), profile_pin);
    const auto file = stage / "display-power/candidate.json";
    power_need(!std::filesystem::exists(file) && !std::filesystem::is_symlink(file),
               "fresh cold evidence file required");
    ensure_private_directory(file.parent_path());
    write_private_json(file, candidate);
    power_need(std::filesystem::file_size(file) <= 1ULL << 20, "bounded cold evidence required");

    return {{"schema", 1},
            {"file", "display-power/candidate.json"},
            {"bytes", std::filesystem::file_size(file)},
            {"sha256", sha256_file(file)},
            {"capability", cap}};
}
} // namespace voyemu
