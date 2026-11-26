#pragma once
#include "base_image.hpp"
#include "error.hpp"
#include "model.hpp"
#include "original_navi_candidate.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
namespace voyemu::api30_framework_boot {
inline constexpr std::array<const char *, 6> core = {"core-oj", "core-libart",  "core-icu4j",
                                                     "okhttp",  "bouncycastle", "apache-xml"};
inline constexpr std::array<const char *, 6> extension = {
        "framework",   "ext",        "telephony-common",
        "voip-common", "ims-common", "framework-atb-backward-compatibility"};

inline std::vector<std::string> instruction_sets(const Json &profile) {
    if (android_package_identity(profile.at("android").value("package", std::string{})).abi ==
        "x86_64") {
        return {"x86", "x86_64"};
    }

    return {"arm64"};
}

inline void verify(const Json &profile) {
    Json install = {{"artifact", "component:view-observation"},
                    {"type", "file"},
                    {"target", "/system/framework/framework.jar"},
                    {"mode", "0644"}};

    if (original_navi_requested(profile)) {
        original_navi_preflight(profile, 30);

        for (auto p = profile.at("patches").begin(); p != profile.at("patches").end(); ++p) {
            if (p.value().value("input", std::string{}) == "component:view-observation" &&
                p.value().value("type", std::string{}) == "jar" &&
                p.value().value("steps", Json::array()) ==
                        Json::array({"original-navi-egl.json"})) {
                install["artifact"] = "patched:" + p.key();
            }
        }
    }

    const auto entries = profile.value("install", Json::array());

    const auto identity =
            android_package_identity(profile.at("android").value("package", std::string{}));

    if ((profile.value("platform", Json()) != "qinggan11" &&
         profile.value("platform", Json()) != "passion") ||
        identity.api != 30 ||
        profile.value("components", Json::object()).value("view-observation", std::string{}) !=
                "components/view-observation" ||
        std::count(entries.begin(), entries.end(), install) != 1) {
        throw VoyemuError("ANDROID_CANDIDATE",
                          "exact qinggan11/Passion API30 framework boot extension required");
    }
}

inline std::string classpath() {
    std::string result;

    for (const auto *name : core) {
        if (!result.empty()) {
            result += ':';
        }

        result += "/apex/com.android.art/javalib/" + std::string(name) + ".jar";
    }

    for (const auto *name : extension) {
        result += ":/system/framework/" + std::string(name) + ".jar";
    }

    return result;
}

inline std::vector<std::string> paths(const Json &profile) {
    verify(profile);
    std::vector<std::string> result;

    for (const auto &isa : instruction_sets(profile)) {
        for (const auto *name : extension) {
            for (const auto *suffix : {".art", ".oat", ".vdex"}) {
                result.push_back("/system/framework/" + isa + "/boot-" + name + suffix);
            }
        }
    }

    return result;
}

inline std::vector<std::string> command(const Json &profile, const std::string &isa) {
    verify(profile);
    const auto expected = instruction_sets(profile);

    if (std::find(expected.begin(), expected.end(), isa) == expected.end()) {
        throw VoyemuError("ANDROID_CANDIDATE", "unregistered ART instruction set");
    }

    const auto directory = "/system/framework/" + isa;
    std::vector<std::string> result = {isa == "x86" ? "/apex/com.android.art/bin/dex2oat32"
                                                    : "/apex/com.android.art/bin/dex2oat64",
                                       "--image=" + directory + "/boot.art",
                                       "--oat-file=" + directory + "/boot.oat",
                                       "--oat-location=" + directory + "/boot.oat",
                                       "--boot-image=/apex/com.android.art/javalib/boot.art",
                                       "--multi-image",
                                       "--instruction-set=" + isa,
                                       "--instruction-set-variant=generic",
                                       "--instruction-set-features=default",
                                       "--compiler-filter=speed",
                                       "--image-format=lz4hc",
                                       "--android-root=/system",
                                       "--runtime-arg",
                                       "-Xms64m",
                                       "--runtime-arg",
                                       "-Xmx512m",
                                       "--runtime-arg",
                                       "-Xbootclasspath:" + classpath(),
                                       "--runtime-arg",
                                       "-Xbootclasspath-locations:" + classpath(),
                                       "--no-inline-from=core-oj.jar",
                                       "--force-determinism",
                                       "--abort-on-hard-verifier-error"};

    for (const auto *name : extension) {
        const auto jar = "/system/framework/" + std::string(name) + ".jar";
        result.push_back("--dex-file=" + jar);
        result.push_back("--dex-location=" + jar);
    }

    return result;
}

inline bool compiled(const Json &profile, const Json &events) {
    if (!events.is_array()) {
        return false;
    }

    const auto expected = instruction_sets(profile);
    std::size_t next = 0;

    for (const auto &event : events) {
        if (event.at("phase") == "boot-art-compiled") {
            if (next == expected.size() || event.at("files") != extension.size() * 3 ||
                event.at("command") != command(profile, expected[next])) {
                return false;
            }

            ++next;
        }
    }

    return next == expected.size();
}
} // namespace voyemu::api30_framework_boot
