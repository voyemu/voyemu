#pragma once

#include "model.hpp"

namespace voyemu::test {
// Use synthetic values in the same two-boot AVB receipt shape as the signed x86 guest.
inline void use_signed_x86_guest(Json &definition, Json &candidate) {
    definition["android"]["package"] = "system-images;android-30;default;x86_64";
    definition["emulator"]["acceleration"] = "required";
    candidate["android"]["abi"] = "x86_64";

    const std::string vbmeta(64, '5'), root(64, '6');
    auto &images = candidate["android"]["images"];
    images["vendor.img"] = {
            {"file", "android/vendor.img"}, {"bytes", 84}, {"sha256", std::string(64, '7')}};
    Json files = Json::object();

    for (const auto *name : {"system.img", "vendor.img"}) {
        files[name] = {{"bytes", images.at(name).at("bytes")},
                       {"sha256", images.at(name).at("sha256")}};
    }

    candidate["signed_android"] = {{"base_archive_sha256", definition.at("android").at("sha256")},
                                   {"first_boot_id", "6712c071-a649-43a9-8bab-81d440fe323b"},
                                   {"cold_boot_id", "e8c38b50-aa59-4703-9525-b1ecdab800e7"},
                                   {"vbmeta_digest", vbmeta},
                                   {"system_root_sha256", root},
                                   {"files", files}};

    auto &checks = candidate["checks"];

    for (auto &row : checks) {
        if (row.at("id") == "abi") {
            row["actual"] = row["expected"] = "x86_64";
        }
    }

    for (const auto *prefix : {"signed-first-boot:", "signed-cold:"}) {
        for (const auto &[name, value] :
             std::vector<std::pair<std::string, std::string>>{{"vbmeta", vbmeta},
                                                              {"dm-verity-root", root},
                                                              {"dm-verity-status", "V"},
                                                              {"readonly-mount", "ro"}}) {
            checks.push_back({{"id", prefix + name},
                              {"actual", value},
                              {"expected", value},
                              {"passed", true}});
        }
    }
}
} // namespace voyemu::test
