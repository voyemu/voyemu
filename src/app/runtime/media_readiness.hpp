#pragma once
#include "model.hpp"
#include "nxp_presentation.hpp"
#include "passion_presentation.hpp"
#include "screens.hpp"
#include <stdexcept>
#include <string_view>

namespace voyemu::media {
// The presentation family of a machine whose OEM screens are presented as they are, by the platform
// or board it belongs to; empty for a machine that acknowledges vehicle state.
inline std::string presentation_family(const Json &android_spec) {
    if (passion_presentation(android_spec)) {
        return "passion";
    }

    if (nxp_presentation(android_spec)) {
        return "nxp";
    }

    return {};
}

inline bool presentation_family_known(const Json &value) {
    return value == "passion" || value == "nxp";
}

// Written once by the session owner before launching its frontend; never inferred from deliveries.
inline Json readiness_owner(std::string_view session, const Json &android_spec) {
    Json owner = {{"schema", 1},
                  {"session_id", session},
                  {"require_oem_systemui", android_spec.contains("systemui_adapter")}};

    if (const auto family = presentation_family(android_spec); !family.empty()) {
        owner["presentation_family"] = family;
    }

    // The window takes the screens of the machine from the displays list of its profile.
    if (android_spec.contains("screens")) {
        owner["screens"] = android_spec.at("screens");
    }

    return owner;
}

inline bool require_oem_systemui(const Json &owner, std::string_view session) {
    if (!owner.is_object() || !owner.contains("schema") || !owner["schema"].is_number_integer() ||
        owner["schema"] != 1 || !owner.contains("session_id") || !owner["session_id"].is_string() ||
        owner["session_id"] != session || !owner.contains("require_oem_systemui") ||
        !owner["require_oem_systemui"].is_boolean()) {
        throw VoyemuError("MEDIA_OWNER", "missing or invalid session readiness contract");
    }

    return owner["require_oem_systemui"].get<bool>();
}

inline std::vector<Screen> owner_screens(const Json &owner, std::string_view session) {
    (void)require_oem_systemui(owner, session);

    if (!owner.contains("screens")) {
        throw VoyemuError("MEDIA_OWNER", "screens of the machine required");
    }

    return profile_screens(owner.at("screens"));
}

inline bool presentation_only(const Json &owner, std::string_view session) {
    (void)require_oem_systemui(owner, session);

    if (!owner.contains("presentation_family")) {
        return false;
    }

    if (!presentation_family_known(owner.at("presentation_family")) ||
        owner.at("require_oem_systemui") != false) {
        throw VoyemuError("MEDIA_OWNER", "unsupported presentation family");
    }

    return true;
}

inline bool presentation_ready(const Json &android, bool require_oem,
                               bool presentation_only = false) {
    const bool acknowledged = android.value("status", std::string{}) == "guest_acknowledged";
    const bool presented =
            android.value("status", std::string{}) == "presentation_ready" &&
            presentation_family_known(android.value("presentation_family", Json{})) &&
            !android.value("guest_acknowledged", false);

    return (presentation_only ? presented : acknowledged) &&
           android.value("home", Json::object()).value("status", std::string{}) ==
                   "visible_on_primary" &&
           android.value("displays", Json::object()).value("status", std::string{}) ==
                   "both_guest_displays_ready" &&
           (!require_oem ||
            android.value("systemui", Json::object()).value("status", std::string{}) ==
                    "both_OEM_bars_visible");
}

// A delivered presentation family selects presentation readiness instead of acknowledgement.
inline bool android_public_ready(const Json &android) {
    if (android.contains("last_error")) {
        return false;
    }

    if (android.contains("presentation_family")) {
        return presentation_ready(android, false, true);
    }

    return android.value("guest_acknowledged", false) &&
           android.value("home", Json::object()).value("status", std::string{}) ==
                   "visible_on_primary" &&
           android.value("displays", Json::object()).value("status", std::string{}) ==
                   "both_guest_displays_ready";
}
} // namespace voyemu::media
