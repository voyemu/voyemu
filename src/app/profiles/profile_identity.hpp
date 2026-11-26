#pragma once
#include "model.hpp"
#include <string>
#include <string_view>

namespace voyemu {
// The platform and board a profile declares in profile.json; behavior follows them, not the id.
enum class ProfilePlatform {
    qinggan09,
    qinggan11,
    passion,
    aosp
};
// "8155" is the Qualcomm SA8155 board, "nxp" the NXP i.MX 8QuadMax board.
enum class ProfileBoard {
    sa8155,
    nxp,
    ranchu
};

inline ProfilePlatform profile_platform(const Json &definition) {
    const auto value = definition.is_object() && definition.contains("platform")
                               ? definition.at("platform")
                               : Json();

    if (value == "qinggan09") {
        return ProfilePlatform::qinggan09;
    }

    if (value == "qinggan11") {
        return ProfilePlatform::qinggan11;
    }

    if (value == "passion") {
        return ProfilePlatform::passion;
    }

    if (value == "aosp" && definition.value("board", std::string{}) == "ranchu") {
        return ProfilePlatform::aosp;
    }

    throw VoyemuError("PROFILE_INVALID", "unsupported profile platform");
}

inline ProfileBoard profile_board(const Json &definition) {
    const auto value = definition.is_object() && definition.contains("board")
                               ? definition.at("board")
                               : Json();

    if (value == "8155") {
        return ProfileBoard::sa8155;
    }

    if (value == "nxp") {
        return ProfileBoard::nxp;
    }

    if (value == "ranchu" && definition.value("platform", std::string{}) == "aosp") {
        return ProfileBoard::ranchu;
    }

    throw VoyemuError("PROFILE_INVALID", "unsupported profile board");
}

// The clean SDK guest has no OEM vehicle adapters.
inline bool android_sdk_profile(const Json &definition) {
    return definition.is_object() && definition.value("platform", std::string{}) == "aosp" &&
           definition.value("board", std::string{}) == "ranchu";
}

// The platform and board of a profile, which scope its recipes.
struct ProfileScope {
    ProfilePlatform platform;
    ProfileBoard board;
    bool operator==(const ProfileScope &) const = default;
};

inline ProfileScope profile_scope(const Json &definition) {
    return {profile_platform(definition), profile_board(definition)};
}

// Whether profile.json sets the named boolean of its features object: system_upgrade, an existing
// machine takes a rebuilt Android system in place with its delivered packages;
// ui_observer_required, a multimedia machine always carries the UI observer;
// measured_disk_reserve, preparation and the candidate reserve the disk budget measured on the
// pinned system image.
inline bool profile_feature(const Json &definition, std::string_view name) {
    const auto features = definition.is_object() ? definition.value("features", Json::object())
                                                 : Json::object();

    return features.is_object() && features.value(std::string(name), Json(false)) == true;
}

// The name of the profile in human text, such as "Free 7.3.1".
inline std::string profile_title(const Json &definition) {
    if (!definition.is_object() || !definition.contains("title") ||
        !definition.at("title").is_string() || definition.at("title").get<std::string>().empty()) {
        throw VoyemuError("PROFILE_INVALID", "profile title must be a nonempty string");
    }

    return definition.at("title").get<std::string>();
}

// Logical identity owns selection and state; the embedded reference selects guest adapters.
inline std::string runtime_profile_reference(const Json &definition,
                                             std::string_view verified_profile = {}) {
    if (!definition.is_object()) {
        return {};
    }

    const auto id = definition.value("id", std::string(verified_profile));

    if (id.empty() || (!verified_profile.empty() && id != verified_profile)) {
        return {};
    }

    if (!definition.contains("capture") || !definition.at("capture").is_object()) {
        return id;
    }

    const auto &capture = definition.at("capture");

    if (!capture.contains("referenceProfile")) {
        return id;
    }

    if (!capture.contains("profile") || capture.at("profile") != id ||
        !capture.at("referenceProfile").is_string()) {
        return {};
    }

    const auto reference = capture.at("referenceProfile").get<std::string>();

    return reference.empty() ? std::string{} : reference;
}
} // namespace voyemu
