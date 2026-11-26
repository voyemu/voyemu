#pragma once
#include "error.hpp"
#include "os/fs.hpp"
#include "profile_identity.hpp"
#include <stdexcept>
namespace voyemu {
inline std::filesystem::path profile_originals_directory(const std::filesystem::path &root,
                                                         std::string_view profile) {
    const auto ordinary = [](const std::filesystem::path &path) {
        for (const auto &at : os::ancestors(path)) {
            if (std::filesystem::is_symlink(std::filesystem::symlink_status(at))) {
                throw VoyemuError("PROFILE_ORIGINALS_LINK", "linked input rejected");
            }
        }
    };

    if (!root.is_absolute() || !valid_profile_name(profile)) {
        throw VoyemuError("PROFILE_ORIGINALS_ARGUMENT", "absolute root and valid profile required");
    }

    const auto own = root / ".local/profiles" / std::string(profile) / "originals";
    ordinary(own);

    if (std::filesystem::exists(own)) {
        return own;
    }

    const auto file = root / "profiles" / std::string(profile) / "profile.json";
    ordinary(file);

    if (!std::filesystem::is_regular_file(file)) {
        return own;
    }

    const auto definition = read_private_json(file, 1 << 20);

    if (!definition.contains("capture") || !definition.at("capture").is_object() ||
        !definition.at("capture").contains("referenceProfile")) {
        return own;
    }

    const auto reference = runtime_profile_reference(definition, profile);

    if (!valid_profile_name(reference)) {
        throw VoyemuError("PROFILE_ORIGINALS_REFERENCE", "valid explicit reference required");
    }

    if (reference == profile) {
        return own;
    }

    const auto reference_file = root / "profiles" / reference / "profile.json";
    ordinary(reference_file);
    const auto source_definition = read_private_json(reference_file, 1 << 20);

    if (!definition.contains("original") ||
        definition.at("original") != source_definition.at("original")) {
        throw VoyemuError("PROFILE_ORIGINALS_REFERENCE", "original declarations differ");
    }

    const auto source = root / ".local/profiles" / reference / "originals";
    ordinary(source);
    const auto require_file = [&](const std::filesystem::path &relative) {
        if (relative.empty() || relative.is_absolute() || relative.has_root_name() ||
            relative.generic_string().find('\\') != std::string::npos) {
            throw VoyemuError("PROFILE_ORIGINALS_PATH", "relative original required");
        }

        for (const auto &part : relative) {
            if (part == "." || part == "..") {
                throw VoyemuError("PROFILE_ORIGINALS_PATH", "confined original required");
            }
        }

        const auto input = source / relative;
        ordinary(input);

        if (!std::filesystem::is_regular_file(input)) {
            throw VoyemuError("PROFILE_ORIGINALS_MISSING", "fetch reference originals first");
        }
    };

    for (const auto &item : definition.at("original")) {
        const std::filesystem::path relative = item.at("file").get<std::string>();

        if (item.value("type", std::string("file")) == "tree") {
            for (auto at = item.at("sha256").begin(); at != item.at("sha256").end(); ++at) {
                require_file(relative / at.key());
            }
        } else {
            require_file(relative);
        }
    }

    return source;
}
} // namespace voyemu
