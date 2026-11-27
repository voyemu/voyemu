#pragma once
#include "check.hpp"
#include "os/fs.hpp"
#include "passion_mcu_property.hpp"
#include "passion_prepared_guest.hpp"
#include "quickboot.hpp"
#include "zip_archive.hpp"
#include <algorithm>
namespace voyemu {
inline bool passion_mcu_requested(const Json &definition) {
    if (definition.value("platform", Json()) != "passion") {
        return false;
    }

    const auto &patch = definition.at("patches").at("MonzaCarService");
    const auto &steps = patch.at("steps");
    const Json recipe = "passion-api30-mcu-property.json";

    if (std::find(steps.begin(), steps.end(), recipe) == steps.end()) {
        return false;
    }

    passion_mcu_need(patch.at("input") == "original:MonzaCarService" && patch.at("type") == "apk" &&
                             steps == Json::array({"framework-libraries.json",
                                                   "passion-api30-diagnostics.json", recipe}),
                     "exact Monza property recipe chain required");

    return true;
}

inline bool passion_mcu_pin(const std::string &pin) {
    return sha256_text(pin);
}

inline void passion_mcu_helper_receipt(const std::string &apk, const Json &helper) {
    passion_mcu_need(helper.is_object() && helper.size() == 6 &&
                             helper.at("contract") == "passion-mcu-property-helper-v1" &&
                             helper.at("artifact") == "patched:MonzaCarService" &&
                             helper.at("archive_sha256") == apk &&
                             helper.at("entry") == "classes18.dex" &&
                             passion_mcu_pin(helper.at("sha256").get<std::string>()) &&
                             helper.at("bytes").is_number_unsigned() &&
                             helper.at("bytes").get<std::uint64_t>() > 0 &&
                             helper.at("bytes").get<std::uint64_t>() <= (64ULL << 20),
                     "exact MCU helper output receipt required");
}

inline void passion_mcu_helper_artifact(const std::filesystem::path &root,
                                        const std::string &reference, const Json &artifact) {
    passion_mcu_need(reference == "patched:MonzaCarService" && artifact.is_object() &&
                             artifact.size() == 4,
                     "exact MCU artifact descriptor required");
    const std::filesystem::path file = artifact.at("file").get<std::string>();
    passion_mcu_need(file.is_absolute() && file == file.lexically_normal(),
                     "absolute ordinary MCU artifact required");
    bool local = false;

    for (const auto &path : os::ancestors(file)) {
        passion_mcu_need(!std::filesystem::is_symlink(path), "symlink MCU ancestor rejected");

        if (path == root / ".local") {
            local = true;
            break;
        }
    }

    passion_mcu_need(local && std::filesystem::is_regular_file(file) &&
                             std::filesystem::hard_link_count(file) == 1 &&
                             std::filesystem::file_size(file) <= (128ULL << 20),
                     "owned bounded MCU artifact required");
    const auto epoch = cache_file_identity(file);
    const auto apk = sha256_file(file);
    passion_mcu_need(artifact.at("sha256") == apk &&
                             artifact.at("bytes") == std::filesystem::file_size(file),
                     "MCU artifact archive differs");
    const auto &helper = artifact.at("mcu_helper");
    passion_mcu_helper_receipt(apk, helper);
    const auto dex = read_pinned_zip_entry(file, apk, "classes18.dex",
                                           helper.at("sha256").get<std::string>());
    passion_mcu_need(dex.size() == helper.at("bytes").get<std::uint64_t>() &&
                             cache_file_identity(file) == epoch,
                     "actual MCU helper output differs");
}

inline void passion_mcu_helper_graph(const std::filesystem::path &root, const Json &definition,
                                     const Json &artifacts) {
    const bool requested = passion_mcu_requested(definition);

    if (requested) {
        passion_mcu_need(artifacts.contains("patched:MonzaCarService") &&
                                 artifacts.at("patched:MonzaCarService").contains("mcu_helper"),
                         "requested MCU helper receipt required");
    }

    for (auto at = artifacts.begin(); at != artifacts.end(); ++at) {
        if (at.value().contains("mcu_helper")) {
            passion_mcu_need(requested, "undeclared MCU helper receipt rejected");
            passion_mcu_helper_artifact(root, at.key(), at.value());
        }
    }
}

inline Json passion_mcu_contract(const Json &definition, const Json &candidate,
                                 const std::string &apk, const Json &helper) {
    passion_mcu_need(passion_mcu_requested(definition) && passion_mcu_pin(apk),
                     "requested graph and APK pin required");
    passion_mcu_need(
            candidate.at("schema") == 1 && candidate.at("kind") == "android-candidate" &&
                    candidate.at("profile") == definition.at("id") &&
                    candidate.at("prepared_VM") == true && candidate.at("stopped") == true &&
                    candidate.at("cold_boot_verified") == true &&
                    candidate.at("clean_base_archive_sha256") ==
                            definition.at("android").at("sha256") &&
                    passion_mcu_pin(candidate.at("artifact_result_sha256").get<std::string>()),
            "stopped source-bound cold candidate required");

    const auto abi = passion_prepared_guest_abi(definition, candidate, passion_mcu_need);

    for (const auto &pair : std::vector<std::pair<std::string, std::string>>{
                 {"boot", "1"}, {"api", "30"}, {"abi", abi}, {"selinux", "Enforcing"}}) {
        unsigned found = 0;

        for (const auto &row : candidate.at("checks")) {
            if (row.at("id") == pair.first) {
                passion_mcu_need(row.at("expected") == pair.second &&
                                         row.at("actual") == pair.second &&
                                         row.at("passed") == true,
                                 "cold guest prerequisite failed");
                ++found;
            }
        }

        passion_mcu_need(found == 1, "exact cold guest prerequisite required");
    }

    unsigned installed = 0, checked = 0;

    for (const auto &row : candidate.at("installed")) {
        if (row.at("artifact") == "patched:MonzaCarService" &&
            row.at("target") == "/system/priv-app/MonzaCarService/MonzaCarService.apk") {
            passion_mcu_need(row.at("sha256") == apk && !row.value("mutable", false),
                             "immutable installed Monza differs");
            ++installed;
        }
    }

    for (const auto &row : candidate.at("checks")) {
        if (row.at("id") ==
            "artifact:patched:MonzaCarService:/system/priv-app/MonzaCarService/MonzaCarService.apk") {
            passion_mcu_need(row.at("expected") == apk && row.at("actual") == apk &&
                                     row.at("passed") == true,
                             "cold merged Monza hash failed");
            ++checked;
        }
    }

    passion_mcu_need(installed == 1 && checked == 1,
                     "exact installed and cold merged Monza rows required");

    passion_mcu_helper_receipt(apk, helper);

    return {{"schema", 1},
            {"capability", passion_mcu_capability()},
            {"helper", helper},
            {"apk_sha256", apk},
            {"artifact_result_sha256", candidate.at("artifact_result_sha256")}};
}

inline Json build_passion_mcu_proof(const std::filesystem::path &root, const Json &definition,
                                    const Json &artifacts, const Json &candidate) {
    passion_mcu_helper_graph(root, definition, artifacts);
    const auto &artifact = artifacts.at("patched:MonzaCarService");
    const std::filesystem::path file = artifact.at("file").get<std::string>();

    passion_mcu_need(file.is_absolute() && file == file.lexically_normal() &&
                             std::filesystem::is_regular_file(file) &&
                             std::filesystem::file_size(file) <= (128ULL << 20),
                     "bounded ordinary host Monza required");
    bool local = false;

    for (const auto &path : os::ancestors(file)) {
        passion_mcu_need(!std::filesystem::is_symlink(path), "symlink Monza ancestor rejected");

        if (path == root / ".local") {
            local = true;
            break;
        }
    }

    passion_mcu_need(local, "production local artifact required");
    const auto apk = sha256_file(file);
    passion_mcu_need(artifact.at("sha256") == apk, "host Monza artifact changed");
    const auto cap = passion_mcu_capability();
    (void)read_pinned_zip_entry(file, apk, "classes16.dex",
                                cap.at("factory_dex_sha256").get<std::string>());
    (void)read_pinned_zip_entry(file, apk, "classes18.dex",
                                artifact.at("mcu_helper").at("sha256").get<std::string>());
    (void)read_pinned_zip_entry(file, apk, "AndroidManifest.xml",
                                cap.at("manifest_sha256").get<std::string>());
    passion_mcu_need(sha256_file(file) == apk, "Monza changed after ZIP checks");

    return passion_mcu_contract(definition, candidate, apk, artifact.at("mcu_helper"));
}

inline Json validate_passion_mcu_candidate(const Json &definition, const Json &candidate,
                                           const Json &images, const std::string &profilePin) {
    passion_mcu_need(passion_mcu_pin(profilePin) && candidate.at("profile_sha256") == profilePin &&
                             candidate.at("android").at("images") == images,
                     "cold profile/images binding differs");
    const auto &proof = candidate.at("mcu_property");
    passion_mcu_need(proof == passion_mcu_contract(definition, candidate,
                                                   proof.at("apk_sha256").get<std::string>(),
                                                   proof.at("helper")),
                     "partial MCU proof differs");

    return proof.at("capability");
}

inline Json export_passion_mcu(const Json &definition, const Json &candidate,
                               const std::filesystem::path &stage, const std::string &profilePin) {
    const auto cap = validate_passion_mcu_candidate(
            definition, candidate, candidate.at("android").at("images"), profilePin);
    const auto file = stage / "mcu-property/candidate.json";

    passion_mcu_need(!std::filesystem::exists(file) && !std::filesystem::is_symlink(file),
                     "fresh evidence destination required");
    ensure_private_directory(file.parent_path());
    write_private_json(file, candidate, 1 << 20);
    passion_mcu_need(std::filesystem::file_size(file) <= 1ULL << 20,
                     "bounded evidence metadata required");

    return {{"schema", 1},
            {"file", "mcu-property/candidate.json"},
            {"bytes", std::filesystem::file_size(file)},
            {"sha256", sha256_file(file)},
            {"capability", cap}};
}
} // namespace voyemu
