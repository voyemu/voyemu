#pragma once

#include "model.hpp"

namespace voyemu::test {
// Use synthetic values in the receipt shape of the x86_64 guest whose base binds a vbmeta digest.
inline void use_x86_guest(Json &definition, Json &candidate) {
    auto &base = definition["android"];

    base["package"] = "system-images;android-30;default;x86_64";
    base["url"] = "https://dl.google.com/android/repository/sys-img/android/x86_64-30_r11.zip";
    base["clean_base"]["vbmeta_digest"] = std::string(64, '4');
    definition["emulator"]["acceleration"] = "required";
    candidate["android"]["abi"] = "x86_64";

    const std::string digest(64, '5');
    candidate["android"]["verified_boot"] = {{"vbmeta_digest", digest},
                                             {"file", "android/VerifiedBootParams.textproto"},
                                             {"sha256", std::string(64, '6')}};
    auto &checks = candidate["checks"];

    for (auto &row : checks) {
        if (row.at("id") == "abi") {
            row["actual"] = row["expected"] = "x86_64";
        }
    }

    checks.push_back(
            {{"id", "vbmeta-digest"}, {"actual", digest}, {"expected", digest}, {"passed", true}});
}
} // namespace voyemu::test
