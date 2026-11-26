#pragma once

#include "android_reboot.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "model.hpp"
#include <algorithm>

namespace voyemu {
inline std::string passion_prepared_guest_abi(const Json &definition, const Json &candidate,
                                              Check need) {
    const auto &base = definition.at("android");
    const auto &package = base.at("package");

    if (package == "system-images;android-30;default;arm64-v8a") {
        return "arm64-v8a";
    }

    need(package == "system-images;android-30;default;x86_64" &&
                 android_acceleration_required(definition) &&
                 candidate.at("android").at("abi") == "x86_64" &&
                 candidate.contains("signed_android"),
         "x86_64 requires the signed API30 guest with hardware acceleration");
    const auto &proof = candidate.at("signed_android");
    need(proof.is_object() && proof.size() == 6 &&
                 proof.at("base_archive_sha256") == base.at("sha256"),
         "signed guest source differs");

    for (const auto *name : {"vbmeta_digest", "system_root_sha256"}) {
        need(sha256_text(proof.at(name).get<std::string>()), "signed guest pin required");
    }

    const auto first = proof.at("first_boot_id").get<std::string>(),
               cold = proof.at("cold_boot_id").get<std::string>();
    need(android_boot_id_valid(first) && android_boot_id_valid(cold) && first != cold,
         "two distinct signed boots required");

    // The signed image verifier checked the release; bind the capability to the same installed
    // images and successful live verification.
    for (const auto *name : {"system.img", "vendor.img"}) {
        const auto &signed_file = proof.at("files").at(name);
        const auto &image = candidate.at("android").at("images").at(name);
        need(sha256_text(signed_file.at("sha256").get<std::string>()) &&
                     image.at("sha256") == signed_file.at("sha256") &&
                     image.at("bytes") == signed_file.at("bytes"),
             "signed guest image differs");
    }

    const auto &checks = candidate.at("checks");

    for (const auto *prefix : {"signed-first-boot:", "signed-cold:"}) {
        for (const auto &[name, value] : std::vector<std::pair<std::string, Json>>{
                     {"vbmeta", proof.at("vbmeta_digest")},
                     {"dm-verity-root", proof.at("system_root_sha256")},
                     {"dm-verity-status", "V"},
                     {"readonly-mount", "ro"}}) {
            const auto id = prefix + name;
            auto matches = [&](const Json &row) {
                return row.at("id") == id;
            };
            const auto check = std::ranges::find_if(checks, matches);
            need(check != checks.end() && std::ranges::count_if(checks, matches) == 1 &&
                         check->at("passed") == true && check->at("actual") == value &&
                         check->at("expected") == value,
                 "x86_64 requires exact live signed guest check: " + id);
        }
    }

    return "x86_64";
}
} // namespace voyemu
