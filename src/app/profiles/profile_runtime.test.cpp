#include "profile_runtime.hpp"
#include "os/platform.hpp"
#include "process.hpp"
#include <exception>
#include <fstream>
#include <iostream>
using namespace voyemu;

static void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

int main() try {
    auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                ("voyemu-profile-runtime-" + random_token());

    ensure_private_directory(root);
    try {
        const auto base = root / ".local/machines";
        const std::string profile = "same-car", variant = "same-car-copy", id(32, 'a');
        const auto unnamed = machine_identity(profile, {}),
                   named = machine_identity(profile, profile),
                   copy = machine_identity(profile, variant);

        check(profile_launch_directory(root, profile, unnamed) == base / profile,
              "default runtime uses readable machine name");
        check(profile_launch_directory(root, profile, copy) == base / variant,
              "copy has independent readable runtime scope");
        check(native_session_directory(root, profile, copy, id) == base / variant / "sessions" / id,
              "session belongs to selected machine");
        check(native_current_active_directory(root, profile, copy) == base / variant / "active",
              "active owner belongs to selected machine");
        check(canonical_machine_name(profile, "") == profile &&
                      canonical_machine_name(profile, profile) == profile &&
                      canonical_machine_name(profile, variant) == variant,
              "unnamed and profile-named canonical machine share one spelling");
        check(native_machine_directory(root, profile, named) ==
                      native_machine_directory(root, profile, unnamed),
              "canonical spelling names the unnamed machine scope");
        {
            check(unnamed.name == named.name && !unnamed.selected && named.selected &&
                          unnamed.profile == profile && named.valid_for(profile) &&
                          unnamed.selector().empty() && named.selector() == profile &&
                          copy.name == variant && copy.selector() == variant,
                  "machine identity normalizes the name and keeps the selection");
        }

        for (const auto &invalid : {MachineIdentity{}, machine_identity("other-profile", profile),
                                    MachineIdentity{profile, variant, false}}) {
            bool rejected = false;
            try {
                native_machine_directory(root, profile, invalid);
            } catch (const VoyemuError &error) {
                rejected = std::string(error.what()) == "MACHINE_NAME: unsafe runtime selection";
            }

            check(rejected, "empty, foreign-profile or noncanonical identity rejected");
        }

        ensure_private_directory(root / ".local/native-cpp/active");
        write_private_json(root / ".local/native-cpp/active" / (profile + ".json"),
                           {{"old", true}});
        check(native_current_active_directory(root, profile, unnamed) == base / profile / "active",
              "old metadata is never a fallback");
        ensure_private_directory(root / "profiles/source-only");
        write_private_json(root / "profiles/source-only/profile.json", Json::object());
        ensure_private_directory(base / profile);
        write_private_json(base / profile / "android-launch.json", Json::object());
        check(native_profile_names(root) == std::vector<std::string>{profile, "source-only"},
              "source and prepared profile names are discovered");

        for (const auto &unsafe : {"../outside", "bad/name"}) {
            bool rejected = false;
            try {
                profile_launch_directory(root, profile, voyemu::machine_identity(profile, unsafe));
            } catch (...) {
                rejected = true;
            }

            check(rejected, "unsafe machine name rejected");
        }

        // Creating a symbolic link needs a privilege on Windows.
        if (!voyemu::os::host_windows) {
            std::filesystem::create_directory_symlink(base / profile, base / "linked");
            bool linked = false;
            try {
                profile_launch_directory(root, profile,
                                         voyemu::machine_identity(profile, "linked"));
            } catch (...) {
                linked = true;
            }

            check(linked, "linked runtime cannot alias another machine");
        }

        std::filesystem::remove_all(root);
        std::cout << "machine-scoped runtime isolation passed\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        std::filesystem::remove_all(root);

        return 1;
    }
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
