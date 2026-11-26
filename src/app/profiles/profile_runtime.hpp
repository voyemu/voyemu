#pragma once
#include "model.hpp"
#include "process.hpp"
#include <set>
#include <stdexcept>
namespace voyemu {
inline std::filesystem::path native_runtime_directory(const std::filesystem::path &root) {
    return root / ".local/machines";
}

// The canonical machine is selected either unnamed or by its profile name; both spell one scope,
// whose single canonical spelling is the machine directory name. Machine identities from
// arguments, requests and records are compared only in this form.
inline std::string canonical_machine_name(std::string_view profile, std::string_view machine) {
    return std::string(machine.empty() ? profile : machine);
}

// A machine identity normalized once where a CLI argument, API request or retained session
// selection enters. name is always the canonical machine directory name; selected tells a machine
// chosen by directory, name or machine-selection.json from the default machine named like the
// profile. Internal code compares names; selector() is the spelling of runtime interfaces and
// published records in which an empty machine means the default machine.
struct MachineIdentity {
    std::string profile;
    std::string name;
    bool selected = false;

    bool valid_for(std::string_view profile_name) const {
        return profile == profile_name && valid_profile_name(profile) && valid_profile_name(name) &&
               (selected || name == profile);
    }

    std::string selector() const {
        return selected ? name : std::string();
    }
};

inline MachineIdentity machine_identity(std::string_view profile, std::string_view selector) {
    return {std::string(profile), canonical_machine_name(profile, selector), !selector.empty()};
}

inline std::filesystem::path native_machine_directory(const std::filesystem::path &root,
                                                      std::string_view profile,
                                                      const MachineIdentity &machine) {
    if (!machine.valid_for(profile)) {
        throw VoyemuError("MACHINE_NAME", "unsafe runtime selection");
    }

    const auto result = native_runtime_directory(root) / machine.name;

    for (auto path = result; path != root && !path.empty(); path = path.parent_path()) {
        if (std::filesystem::is_symlink(path)) {
            throw VoyemuError("SESSION_IDENTITY", "linked runtime scope");
        }
    }

    return result;
}

inline std::filesystem::path native_current_active_directory(const std::filesystem::path &root,
                                                             std::string_view profile,
                                                             const MachineIdentity &machine) {
    return native_machine_directory(root, profile, machine) / "active";
}

inline std::filesystem::path native_session_directory(const std::filesystem::path &root,
                                                      std::string_view profile,
                                                      const MachineIdentity &machine,
                                                      std::string_view id) {
    if (!valid_profile_name(id)) {
        throw VoyemuError("SESSION_IDENTITY", "unsafe session name");
    }

    return native_machine_directory(root, profile, machine) / "sessions" / std::string(id);
}

// Hosts spell one directory differently (/Users/... on macOS, Z:\... on Windows) and even one host
// can spell it with either separator, so two spellings name the same directory exactly when their
// trailing components agree.
inline bool same_directory_tail(std::filesystem::path lhs, std::filesystem::path rhs,
                                unsigned components) {
    for (unsigned index = 0; index < components; ++index) {
        if (lhs.filename() != rhs.filename()) {
            return false;
        }

        lhs = lhs.parent_path();
        rhs = rhs.parent_path();

        if (lhs.empty() || rhs.empty()) {
            return index + 1 == components;
        }
    }

    return true;
}

inline bool ordinary_native_launch_file(const std::filesystem::path &file) {
    return !std::filesystem::is_symlink(file) && std::filesystem::is_regular_file(file);
}

inline std::filesystem::path profile_launch_directory(const std::filesystem::path &root,
                                                      std::string_view profile,
                                                      const MachineIdentity &machine) {
    if (machine.selected && !valid_profile_name(machine.name)) {
        throw VoyemuError("MACHINE_NAME", "unsafe name");
    }

    if (!valid_profile_name(profile)) {
        throw VoyemuError("PROFILE_NAME", "unsafe name");
    }

    const auto base = native_runtime_directory(root),
               scoped = native_machine_directory(root, profile, machine);

    for (const auto &path : {root / ".local", base, scoped}) {
        if (std::filesystem::is_symlink(path)) {
            throw VoyemuError("PROFILE_LAUNCH", "linked configuration directory");
        }

        if (std::filesystem::exists(path) && !std::filesystem::is_directory(path)) {
            throw VoyemuError("PROFILE_LAUNCH", "configuration directory required");
        }
    }

    return scoped;
}

inline std::vector<std::string> native_profile_names(const std::filesystem::path &root) {
    std::set<std::string> names;
    const auto base = native_runtime_directory(root);

    for (const auto &group : {root / "profiles", base}) {
        if (std::filesystem::is_symlink(group) || !std::filesystem::is_directory(group)) {
            continue;
        }

        for (const auto &entry : std::filesystem::directory_iterator(group)) {
            const auto name = entry.path().filename().string();

            if (!valid_profile_name(name) || entry.is_symlink() || !entry.is_directory()) {
                continue;
            }

            const auto file = entry.path() /
                              (group == root / "profiles" ? "profile.json" : "android-launch.json");

            if (ordinary_native_launch_file(file)) {
                names.insert(name);
            }
        }
    }

    return {names.begin(), names.end()};
}
} // namespace voyemu
