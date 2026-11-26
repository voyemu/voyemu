#pragma once
#include "base_image.hpp"
#include "model.hpp"
#include "passion_mcu_property.hpp"
#include "passion_wheel.hpp"
#include "profile_catalog.hpp"
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>

namespace voyemu {
// Whether a machine launch record belongs to a profile of the Passion platform.
inline bool passion_launch(const Json &android) {
    return record_declares(android, ProfilePlatform::passion, ProfileBoard::sa8155);
}

inline void passion_camera_config(const Json &definition,
                                  std::map<std::string, std::string> &values) {
    if (record_declares(definition, ProfilePlatform::passion, ProfileBoard::sa8155)) {
        values["hw.camera.back"] = "emulated";
        values["hw.camera.front"] = "none";
    }
}

inline bool passion_camera_identity(const Json &android) {
    return passion_launch(android) ||
           android.value("home", Json::object()).value("package", std::string{}) ==
                   "com.voyah.os.carlauncher";
}

inline std::string passion_camera_config_text(const Json &android) {
    const auto path = android.at("config_template").get<std::string>();

    if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path)) ||
        std::filesystem::file_size(path) > 65536) {
        throw VoyemuError("PASSION_CAMERA", "bounded config required");
    }

    std::ifstream camera_input(path, std::ios::binary);

    if (!camera_input) {
        throw VoyemuError("PASSION_CAMERA", "config unreadable");
    }

    return std::string((std::istreambuf_iterator<char>(camera_input)), {});
}

inline void passion_camera_validate(const Json &android, const std::string &config) {
    const auto reference = android.value("reference_profile", std::string{});

    if (reference.empty() || !passion_launch(android) ||
        android.value("presentation_adapter", Json::object()).value("family", std::string{}) !=
                reference) {
        throw VoyemuError("PASSION_CAMERA", "exact presentation identity required");
    }

    unsigned back = 0, front = 0;
    std::istringstream input(config);
    std::string line;

    while (std::getline(input, line)) {
        const auto at = line.find('=');

        if (at == std::string::npos) {
            continue;
        }

        auto key = line.substr(0, at), value = line.substr(at + 1);
        auto trim = [](std::string v) {
            auto first = v.find_first_not_of(" \t\r");
            auto last = v.find_last_not_of(" \t\r");

            return first == std::string::npos ? std::string{} : v.substr(first, last - first + 1);
        };
        key = trim(key);
        value = trim(value);

        if (key == "hw.camera.back") {
            ++back;

            if (value != "emulated") {
                throw VoyemuError("PASSION_CAMERA", "emulated back required");
            }
        }

        if (key == "hw.camera.front") {
            ++front;

            if (value != "none") {
                throw VoyemuError("PASSION_CAMERA", "front camera disabled");
            }
        }
    }

    if (back != 1 || front != 1) {
        throw VoyemuError("PASSION_CAMERA", "exact camera config required");
    }

    for (const auto &arg : android.value("args", Json::array())) {
        const auto value = arg.get<std::string>();

        if (value.starts_with("-camera-back") || value.starts_with("-camera-front")) {
            throw VoyemuError("PASSION_CAMERA", "prepared emulated camera override forbidden");
        }
    }
}

inline constexpr const char *passion_home =
        "com.voyah.os.carlauncher/com.voyah.os.carlauncher.LauncherActivityMain";
inline constexpr const char *passion_secondary =
        "com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond";

inline Json passion_startup_values(const Json &definition) {
    const auto status = definition.value("status", std::string{});
    const auto package =
            definition.value("android", Json::object()).value("package", std::string{});

    if (definition.value("schema", 0) != 1 ||
        !record_declares(definition, ProfilePlatform::passion, ProfileBoard::sa8155) ||
        (status != "ready" && status != "incomplete") ||
        android_package_identity(package).api != 30 ||
        definition.value("initial_state", Json::object()) != Json::object()) {
        throw VoyemuError("PASSION_PRESENTATION",
                          "exact API30 Passion profile with unsupported vehicle state required");
    }

    return Json::object();
}

// The family is the reference profile of the machine.
inline Json passion_presentation_contract(std::string_view family, bool mcu = false,
                                          bool media_wheel = false) {
    return {{"family", family},
            {"secondary_component", passion_secondary},
            {"bootstrap_component", "com.voyemu/com.voyemu.output.SecondScreenService"},
            {"vehicle_state", mcu ? "partial-soc" : "unsupported"},
            {"wheel", media_wheel ? "android-media-keys" : "unsupported"},
            {"language", "unsupported"}};
}

inline bool passion_presentation(const Json &android) {
    if (!android.contains("presentation_adapter") || !passion_launch(android)) {
        return false;
    }

    passion_wheel_validate(android);
    const bool media_wheel = passion_wheel_partial(android.value("wheel_capability", Json()));

    const auto reference = android.value("reference_profile", std::string{});

    if (reference.empty() ||
        android.at("presentation_adapter") !=
                passion_presentation_contract(reference, passion_mcu_available(android),
                                              media_wheel) ||
        android.value("api", 0) != 30 ||
        android.value("home", Json::object()) !=
                Json{{"package", "com.voyah.os.carlauncher"}, {"component", passion_home}} ||
        android.contains("vehicle_adapter") || android.contains("systemui_adapter")) {
        throw VoyemuError("PASSION_PRESENTATION", "exact API30 OEM presentation contract required");
    }

    return true;
}
} // namespace voyemu
