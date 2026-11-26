#pragma once

#include "android_reboot.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "model.hpp"
#include <algorithm>

namespace voyemu {
inline std::string passion_prepared_guest_abi(const Json &definition, const Json &candidate,
                                              Check need) {
    // A missing or mistyped field fails with the code of the caller.
    const auto field = [&](const Json &object, const char *key) -> const Json & {
        need(object.is_object() && object.contains(key),
             std::string("prepared guest field required: ") + key);

        return object.at(key);
    };
    const auto text = [&](const Json &object, const char *key) {
        const auto &value = field(object, key);
        need(value.is_string(), std::string("prepared guest text required: ") + key);

        return value.get<std::string>();
    };
    const auto &base = field(definition, "android");
    const auto &package = field(base, "package");

    if (package == "system-images;android-30;default;arm64-v8a") {
        return "arm64-v8a";
    }

    const auto &android = field(candidate, "android");
    need(package == "system-images;android-30;default;x86_64" &&
                 android_acceleration_required(definition) && field(android, "abi") == "x86_64" &&
                 candidate.contains("signed_android"),
         "x86_64 requires the signed API30 guest with hardware acceleration");
    const auto &proof = field(candidate, "signed_android");
    need(proof.is_object() && proof.size() == 6 &&
                 field(proof, "base_archive_sha256") == field(base, "sha256"),
         "signed guest source differs");

    for (const auto *name : {"vbmeta_digest", "system_root_sha256"}) {
        need(sha256_text(text(proof, name)), "signed guest pin required");
    }

    const auto first = text(proof, "first_boot_id"), cold = text(proof, "cold_boot_id");
    need(android_boot_id_valid(first) && android_boot_id_valid(cold) && first != cold,
         "two distinct signed boots required");

    // The signed image verifier checked the release; bind the capability to the same installed
    // images and successful live verification.
    const auto &files = field(proof, "files");
    const auto &images = field(android, "images");

    for (const auto *name : {"system.img", "vendor.img"}) {
        const auto &signed_file = field(files, name);
        const auto &image = field(images, name);
        need(sha256_text(text(signed_file, "sha256")) &&
                     field(image, "sha256") == field(signed_file, "sha256") &&
                     field(image, "bytes") == field(signed_file, "bytes"),
             "signed guest image differs");
    }

    const auto &checks = field(candidate, "checks");
    need(checks.is_array(), "cold guest checks required");

    for (const auto *prefix : {"signed-first-boot:", "signed-cold:"}) {
        for (const auto &[name, value] : std::vector<std::pair<std::string, Json>>{
                     {"vbmeta", proof.at("vbmeta_digest")},
                     {"dm-verity-root", proof.at("system_root_sha256")},
                     {"dm-verity-status", "V"},
                     {"readonly-mount", "ro"}}) {
            const auto id = prefix + name;
            auto matches = [&](const Json &row) {
                return row.is_object() && row.value("id", Json{}) == id;
            };
            const auto check = std::ranges::find_if(checks, matches);
            need(check != checks.end() && std::ranges::count_if(checks, matches) == 1 &&
                         field(*check, "passed") == true && field(*check, "actual") == value &&
                         field(*check, "expected") == value,
                 "x86_64 requires exact live signed guest check: " + id);
        }
    }

    return "x86_64";
}
} // namespace voyemu
