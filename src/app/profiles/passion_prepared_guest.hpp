#pragma once

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
    const auto &base = field(definition, "android");
    const auto &package = field(base, "package");

    if (package == "system-images;android-30;default;arm64-v8a") {
        return "arm64-v8a";
    }

    const auto &android = field(candidate, "android");
    need(package == "system-images;android-30;default;x86_64" &&
                 android_acceleration_required(definition) && field(android, "abi") == "x86_64",
         "x86_64 requires the API30 guest with hardware acceleration");

    // The guest booted with the vbmeta digest of the machine at its cold verification.
    if (base.value("clean_base", Json::object()).contains("vbmeta_digest")) {
        const auto &digest = field(field(android, "verified_boot"), "vbmeta_digest");
        const auto &checks = field(candidate, "checks");
        need(digest.is_string() && sha256_text(digest.get<std::string>()) && checks.is_array(),
             "machine vbmeta digest required");
        const auto matches = [&](const Json &row) {
            return row.is_object() && row.value("id", Json{}) == "vbmeta-digest";
        };
        const auto check = std::ranges::find_if(checks, matches);
        need(check != checks.end() && std::ranges::count_if(checks, matches) == 1 &&
                     field(*check, "passed") == true && field(*check, "actual") == digest &&
                     field(*check, "expected") == digest,
             "x86_64 requires the cold guest check of its vbmeta digest");
    }

    return "x86_64";
}
} // namespace voyemu
