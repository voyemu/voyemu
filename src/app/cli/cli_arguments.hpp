#pragma once
#include "check.hpp"
#include "cli_messages.hpp"
#include "error.hpp"
#include "machine_path.hpp"
#include "os/fs.hpp"
#include "os/platform.hpp"
#include "profile_catalog.hpp"
#include "profile_runtime.hpp"
#include "progress.hpp"
#include <charconv>
#include <cstdlib>
#include <set>
namespace voyemu::cli {
struct Arguments {
    // Empty until a positional profile, a machine path or the internal --profile names one.
    std::string command = "help", profile;
    std::filesystem::path root, session, request_file, jdk, update, machine_path, build_destination,
            reuse_qnx, reuse_qnx_source;
    std::string ownership_id, serial, refresh_session, reuse_qnx_sha256, build_target;
    // Normalized at the end of parse; a positional machine directory, a build destination or the
    // internal --machine selects it.
    voyemu::MachineIdentity machine;
    bool refresh_host = false, profile_explicit = false, private_start = false;
    bool exclusive = false, offline = false, verbose = false;
    // build --force: the build updates an existing machine instead of refusing it.
    bool force_existing = false;
    std::string token, language;
    std::vector<std::filesystem::path> providers;
    voyemu::Json values = voyemu::Json::object();
    std::optional<unsigned> seconds;
    bool cluster = false, cluster_explicit = false, multimedia = true, multimedia_explicit = false,
         resume = false, background = false;
    bool network = false, network_explicit = false;
};

// A path the user passes in an option: a leading ~/ starts at the home directory, a relative path
// starts at the current directory, and links resolve, so later checks see the real absolute path.
inline std::filesystem::path user_path(const std::string &value) {
    std::filesystem::path path = value;

    if (value.starts_with("~/")) {
        const auto home = os::home_directory();

        if (home.empty() || !home.is_absolute()) {
            throw LocalizedError("USER_HOME", "error.user_home");
        }

        path = std::filesystem::path(home) / value.substr(2);
    }

    return std::filesystem::weakly_canonical(std::filesystem::absolute(path));
}

inline Arguments parse(int argc, char **argv, const std::filesystem::path &executable) {
    Arguments result;
    std::string machine;
    // The global --lang may appear anywhere; the remaining arguments keep their positions.
    std::vector<char *> kept;

    for (int i = 0; i < argc; ++i) {
        const std::string_view argument = argv[i];

        if (i == 0 || !argument.starts_with("--lang=")) {
            kept.push_back(argv[i]);
            continue;
        }

        if (!result.language.empty()) {
            throw LocalizedError("CLI_ARGUMENT", "error.duplicate_option", {{"option", "--lang"}});
        }

        result.language = argument.substr(7);

        if (!language_option(result.language)) {
            throw LocalizedError("CLI_ARGUMENT", "error.lang_value");
        }
    }

    argc = static_cast<int>(kept.size());
    argv = kept.data();

    if (argc > 1) {
        result.command = argv[1];
    }

    if (result.command == "_start") {
        result.private_start = true;
        result.command = "start";
    }

    const std::set<std::string> commands{"help",   "--help", "--version", "test",  "list",
                                         "fetch",  "deps",   "build",     "check", "restart",
                                         "status", "stop",   "patch",     "start", "_supervise"};

    if (!commands.contains(result.command)) {
        throw LocalizedError("CLI_COMMAND", "error.unknown_command", {{"command", result.command}});
    }

    if (result.command == "build") {
        result.cluster = true;
    }

    const bool internal = result.private_start || result.command == "_supervise";
    const bool lifecycle = result.command == "start" || result.command == "restart" ||
                           result.command == "status" || result.command == "stop" ||
                           result.command == "check" || result.command == "patch";
    const bool preparation = result.command == "deps" || result.command == "fetch" ||
                             result.command == "build";
    bool adb_source = false;
    std::set<std::string> seen;

    for (int i = 2; i < argc; ++i) {
        std::string option = argv[i];
        auto next = [&]() {
            if (++i >= argc) {
                throw LocalizedError("CLI_ARGUMENT", "error.missing_value", {{"option", option}});
            }

            const auto value = std::string(argv[i]);

            if (value.empty()) {
                throw LocalizedError("CLI_ARGUMENT", "error.empty_value", {{"option", option}});
            }

            return value;
        };

        if (option.starts_with("--")) {
            const auto key = option.substr(0, option.find('='));

            if (!seen.insert(key).second && key != "--provider") {
                throw LocalizedError("CLI_ARGUMENT", "error.duplicate_option", {{"option", key}});
            }
        }

        if (!internal) {
            if (option == "--root" && result.command != "test") {
                throw LocalizedError("CLI_ARGUMENT", "error.root_internal");
            }

            if (option == "--profile" || option == "--machine") {
                throw LocalizedError("CLI_ARGUMENT", "error.positional_selection");
            }

            if (option == "--with-cluster" || option == "--no-cluster") {
                throw LocalizedError("CLI_ARGUMENT", "error.cluster_syntax");
            }

            if (option == "--session" || option == "--token" || option == "--exclusive" ||
                option == "--ownership-id" || option == "--refresh-host" ||
                option == "--refresh-session") {
                throw LocalizedError("CLI_ARGUMENT", "error.internal_option", {{"option", option}});
            }
        }

        if (option.starts_with("--source=")) {
            if (result.command != "fetch") {
                throw LocalizedError("CLI_ARGUMENT", "error.source_requires_fetch");
            }

            const auto source = option.substr(9);

            if (source == "adb") {
                adb_source = true;
            } else if (source.empty()) {
                throw LocalizedError("CLI_ARGUMENT", "error.source_value");
            } else {
                result.update = user_path(source);
            }

            continue;
        }

        if (result.command == "build" && result.profile_explicit && !option.starts_with("-")) {
            if (option.empty() || !result.build_destination.empty()) {
                throw LocalizedError("CLI_ARGUMENT", "error.one_destination",
                                     {{"command", result.command}});
            }

            result.build_destination = option;
            continue;
        }

        if (option.starts_with("--target=")) {
            const auto target = option.substr(9);

            if (result.command != "deps" && result.command != "build") {
                throw LocalizedError("CLI_ARGUMENT", "error.target_scope");
            }

            if (!voyemu::valid_profile_name(target)) {
                throw LocalizedError("CLI_ARGUMENT", "error.target_name", {{"target", target}});
            }

            result.build_target = target;
            continue;
        }

        if (!option.starts_with("-") && lifecycle) {
            if (!result.machine_path.empty()) {
                throw LocalizedError("MACHINE_PATH", "error.one_machine");
            }

            result.machine_path = option;
        } else if (!option.starts_with("-") && preparation) {
            if (result.profile_explicit) {
                throw LocalizedError("CLI_ARGUMENT", "error.one_profile");
            }

            result.profile = option;
            result.profile_explicit = true;
        } else if (option == "--provider") {
            if (result.providers.size() >= 4) {
                throw VoyemuError("PROVIDER_ARGUMENT", "invalid provider argument");
            }

            result.providers.push_back(user_path(next()));
        } else if (option == "--reuse-qnx-source") {
            result.reuse_qnx_source = user_path(next());
        } else if (option == "--reuse-qnx") {
            result.reuse_qnx = user_path(next());
        } else if (option == "--reuse-qnx-sha256") {
            result.reuse_qnx_sha256 = next();
        } else if (option == "--jdk") {
            result.jdk = user_path(next());
        } else if (option == "--serial") {
            result.serial = next();
        } else if (option == "--verbose") {
            result.verbose = true;
        } else if (option == "--offline") {
            result.offline = true;
        } else if (option == "--force" && result.command == "build") {
            result.force_existing = true;
        } else if (option == "--background") {
            result.background = true;
        } else if (option == "--request") {
            const auto value = next();
            result.request_file = value == "-" ? std::filesystem::path(value) : user_path(value);
        } else if (option == "--exclusive") {
            result.exclusive = true;
        } else if (option == "--refresh-host") {
            result.refresh_host = true;
        } else if (option == "--refresh-session") {
            result.refresh_session = next();
        } else if (option == "--ownership-id") {
            result.ownership_id = next();
        } else if (option == "--resume") {
            if (result.resume) {
                throw LocalizedError("CLI_ARGUMENT", "error.duplicate_option",
                                     {{"option", "--resume"}});
            }

            result.resume = true;
        } else if (option == "--root") {
            result.root = next();
        } else if (option == "--machine") {
            if (!machine.empty()) {
                throw VoyemuError("CLI_ARGUMENT", "duplicate --machine");
            }

            machine = next();
        } else if (option == "--profile") {
            result.profile = next();
            result.profile_explicit = true;
        } else if (option == "--session") {
            result.session = next();
        } else if (option == "--token") {
            result.token = next();
        } else if (option == "--seconds") {
            auto text = next();
            unsigned value = 0;
            auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);

            if (error != std::errc{} || end != text.data() + text.size() || value < 1 ||
                value > 3600) {
                throw LocalizedError("QNX_BOUND", "error.seconds_range");
            }

            result.seconds = value;
        } else if (option.starts_with("--cluster=") || option.starts_with("--multimedia=")) {
            const auto equal = option.find('=');
            const auto value = option.substr(equal + 1);

            if (value != "on" && value != "off") {
                throw LocalizedError("CLI_ARGUMENT", "error.on_off",
                                     {{"option", option.substr(0, equal)}});
            }

            if (option.starts_with("--cluster=")) {
                result.cluster = value == "on";
                result.cluster_explicit = true;
            } else {
                result.multimedia = value == "on";
                result.multimedia_explicit = true;
            }
        } else if (option == "--network=yes" || option == "--network=no") {
            if (result.network_explicit) {
                throw LocalizedError("CLI_ARGUMENT", "error.duplicate_option",
                                     {{"option", "--network"}});
            }

            result.network = option == "--network=yes";
            result.network_explicit = true;
        } else if (option.starts_with("--network=")) {
            throw LocalizedError("CLI_ARGUMENT", "error.network_value");
        } else if (option == "--with-cluster" || option == "--no-cluster") {
            result.cluster = option == "--with-cluster";
            result.cluster_explicit = true;
        } else if (option == "--values") {
            result.values = voyemu::Json::parse(next(), nullptr, false);

            if (result.values.is_discarded() || !result.values.is_object()) {
                throw LocalizedError("CLI_ARGUMENT", "error.values_object");
            }
        } else {
            throw LocalizedError("CLI_ARGUMENT", "error.unknown_option", {{"option", option}});
        }
    }

    if (result.verbose && !preparation && result.command != "start" &&
        result.command != "restart") {
        throw LocalizedError("CLI_ARGUMENT", "error.verbose_scope");
    }

    if (!internal && lifecycle && result.machine_path.empty()) {
        throw LocalizedError("MACHINE_PATH", "error.machine_required",
                             {{"command", result.command}});
    }

    if (!internal && preparation && result.command != "deps" && !result.profile_explicit) {
        throw LocalizedError("PROFILE_NAME", "error.profile_required",
                             {{"command", result.command}});
    }

    if ((result.cluster_explicit || result.multimedia_explicit) && result.command != "start" &&
        result.command != "restart" && result.command != "build" &&
        result.command != "_supervise") {
        throw LocalizedError("CLI_ARGUMENT", "error.subsystem_scope");
    }

    if ((result.background || result.seconds) && result.command != "start" &&
        result.command != "restart" && result.command != "_supervise") {
        throw LocalizedError("CLI_ARGUMENT", "error.launch_scope");
    }

    if (result.network_explicit && result.command != "start" && result.command != "restart" &&
        result.command != "_supervise") {
        throw LocalizedError("CLI_ARGUMENT", "error.network_scope");
    }

    if (result.multimedia_explicit && !result.multimedia && result.cluster_explicit &&
        !result.cluster) {
        throw LocalizedError("CLI_ARGUMENT", "error.both_off");
    }

    if (seen.contains("--values") && result.command != "patch") {
        throw LocalizedError("CLI_ARGUMENT", "error.values_scope");
    }

    if (result.command == "patch" && !seen.contains("--values")) {
        throw LocalizedError("CLI_ARGUMENT", "error.patch_values");
    }

    if (!result.machine_path.empty()) {
        if (!machine.empty()) {
            throw VoyemuError("MACHINE_PATH", "positional machine excludes --machine");
        }

        const auto selected = voyemu::inspect_machine_path(result.machine_path);

        if (result.profile_explicit && result.profile != selected.profile) {
            throw VoyemuError("MACHINE_PATH", "explicit profile differs from machine manifest");
        }

        result.machine_path = selected.seed;
        result.profile = selected.profile;
    }

    if (internal && result.profile.empty()) {
        throw LocalizedError("PROFILE_NAME", "error.profile_required",
                             {{"command", result.command}});
    }

    if (!result.providers.empty() && result.command != "start") {
        throw LocalizedError("PROVIDER_ARGUMENT", "error.provider_scope");
    }

    if (!result.reuse_qnx.empty() || !result.reuse_qnx_sha256.empty() ||
        !result.reuse_qnx_source.empty()) {
        if (result.command != "build" || !result.cluster || !result.multimedia ||
            result.reuse_qnx.empty() || !sha256_text(result.reuse_qnx_sha256)) {
            throw LocalizedError("CLI_ARGUMENT", "error.reuse_qnx");
        }
    }

    if (result.offline && result.command != "deps" && result.command != "fetch" &&
        result.command != "build") {
        throw LocalizedError("CLI_ARGUMENT", "error.offline_scope");
    }

    if (!result.jdk.empty() && result.command != "build" && result.command != "deps") {
        throw LocalizedError("CLI_ARGUMENT", "error.jdk_scope");
    }

    if (adb_source && result.serial.empty()) {
        throw LocalizedError("CLI_ARGUMENT", "error.adb_serial");
    }

    if (!adb_source && !result.serial.empty()) {
        throw LocalizedError("CLI_ARGUMENT", "error.serial_scope");
    }

    if ((result.exclusive || !result.ownership_id.empty()) && result.command != "start") {
        throw VoyemuError("CLI_ARGUMENT", "exclusive ownership is only valid for start");
    }

    if (!result.ownership_id.empty() && (!result.exclusive || !hex_text(result.ownership_id, 32))) {
        throw VoyemuError("CLI_ARGUMENT", "valid exclusive ownership ID required");
    }

    if (!result.request_file.empty() && result.command != "test") {
        throw LocalizedError("CLI_ARGUMENT", "error.request_scope");
    }

    if (result.resume && result.command != "start" && result.command != "restart" &&
        result.command != "_supervise") {
        throw LocalizedError("CLI_ARGUMENT", "error.resume_scope");
    }

    if (!machine.empty() && (!voyemu::valid_profile_name(machine) ||
                             (result.command != "start" && result.command != "restart" &&
                              result.command != "_supervise" && result.command != "check" &&
                              result.command != "build"))) {
        throw VoyemuError("MACHINE_ARGUMENT",
                          "valid machine child name requires start/restart/check/build");
    }

    if ((result.profile_explicit || !result.profile.empty()) &&
        !voyemu::valid_profile_name(result.profile)) {
        throw LocalizedError("PROFILE_NAME", "error.unsafe_profile");
    }

    if (result.root.empty()) {
        const auto executable_root = executable.parent_path();

        // A release archive holds the launcher beside profiles/ and no src/.
        if ((std::filesystem::is_directory(executable_root / ".local/machines") ||
             std::filesystem::is_directory(executable_root / ".local/toolchains") ||
             std::filesystem::is_directory(executable_root / ".local/build") ||
             std::filesystem::is_directory(executable_root / "profiles"))) {
            result.root = executable_root;
        }

        for (auto directory = executable.parent_path(); result.root.empty() && !directory.empty();
             directory = directory.parent_path()) {
            if (std::filesystem::exists(directory / "profiles") &&
                std::filesystem::exists(directory / "src/app")) {
                result.root = directory;
                break;
            }

            if (directory == directory.parent_path()) {
                break;
            }
        }

        if (result.root.empty()) {
            const auto current = std::filesystem::current_path();

            if ((std::filesystem::is_directory(current / ".local/machines") ||
                 std::filesystem::is_directory(current / ".local/toolchains") ||
                 std::filesystem::is_directory(current / ".local/build"))) {
                result.root = current;
            }
        }
    }

    if (!result.root.empty()) {
        result.root = std::filesystem::canonical(result.root);
    } else if (const auto *home = std::getenv("HOME");
               os::platform_name == "macOS" && home && *home) {
        const std::filesystem::path directory(home);

        if (!directory.is_absolute()) {
            throw LocalizedError("USER_HOME", "error.user_home");
        }

        result.root = (directory / "Library/Application Support/Voyemu").lexically_normal();
    }

    if (!result.build_destination.empty()) {
        const auto supplied = result.build_destination;

        if (result.root.empty() || supplied != supplied.lexically_normal() ||
            !voyemu::valid_profile_name(supplied.filename().string())) {
            throw LocalizedError("CLI_ARGUMENT", "error.destination_name");
        }

        const auto target = supplied.is_absolute() ? supplied : result.root / supplied;
        const auto parent = result.root / "machines";

        if (target.parent_path() != parent ||
            std::filesystem::is_symlink(std::filesystem::symlink_status(parent)) ||
            (std::filesystem::exists(parent) && (!std::filesystem::is_directory(parent) ||
                                                 std::filesystem::canonical(parent) != parent)) ||
            std::filesystem::is_symlink(std::filesystem::symlink_status(target))) {
            throw LocalizedError("CLI_ARGUMENT", "error.destination_parent",
                                 {{"path", parent.string()}});
        }

        // Only --force changes an existing machine.
        if (std::filesystem::exists(target) && !result.force_existing) {
            throw LocalizedError("CLI_ARGUMENT", "error.machine_exists",
                                 {{"machine", voyemu::progress::path_text(target)}});
        }

        result.build_destination = target;
        machine = target.filename().string();
    }

    if (!result.machine_path.empty()) {
        if (result.root.empty()) {
            throw LocalizedError("MACHINE_PATH", "error.installation_missing");
        }

        machine = voyemu::machine_path_name(result.root, {result.machine_path, result.profile});
    }

    result.machine = voyemu::machine_identity(result.profile, machine);

    if (!result.cluster_explicit && !result.root.empty() &&
        (result.command == "start" || result.command == "restart")) {
        result.cluster = result.machine_path.empty()
                                 ? voyemu::ordinary_native_launch_file(
                                           voyemu::profile_launch_directory(
                                                   result.root, result.profile, result.machine) /
                                           "cluster-launch.json")
                                 : voyemu::read_private_json(result.machine_path / "runtime.json",
                                                             128 * 1024)
                                           .contains("qnx");
    }

    if (result.seconds && !result.cluster) {
        throw LocalizedError("CLI_ARGUMENT", "error.seconds_cluster");
    }

    return result;
}
} // namespace voyemu::cli
