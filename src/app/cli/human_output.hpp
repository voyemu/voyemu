#pragma once
#include "cli_messages.hpp"
#include "logging.hpp"
#include "model.hpp"
#include "progress.hpp"
#include <exception>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string_view>
namespace voyemu {
inline std::string human_cli_error(std::string_view message) {
    return "Voyemu: " + std::string(message) + "\n";
}

// A failure cause as the end of a catalog sentence: without the trailing period, spaces and line
// breaks that Windows system messages carry.
inline std::string failure_reason(std::string text) {
    while (!text.empty() && (text.back() == '.' || text.back() == ' ' || text.back() == '\r' ||
                             text.back() == '\n')) {
        text.pop_back();
    }

    return text;
}

// The catalog text of an exception by code, its failure_code(), with the cause from its what() text
// and, for a filesystem exception, its paths; empty for an exception with a CODE.
inline std::string uncoded_failure(std::string_view code, std::string_view text,
                                   const std::filesystem::filesystem_error *filesystem,
                                   cli::Language language) {
    if (code == "FILESYSTEM" && filesystem) {
        const auto reason = filesystem->code().message();
        // what() is "filesystem error: OPERATION: REASON [PATH]...", libc++ prefixes OPERATION with
        // "in ".
        constexpr std::string_view prefix = "filesystem error: ";

        if (text.starts_with(prefix)) {
            text.remove_prefix(prefix.size());
        }

        auto end = text.find(": " + reason);

        if (end == std::string_view::npos) {
            end = text.find(": ");
        }

        auto operation = text.substr(0, end);

        if (operation.starts_with("in ")) {
            operation.remove_prefix(3);
        }

        auto path = filesystem->path1().string();

        if (!filesystem->path2().empty()) {
            path += ", " + filesystem->path2().string();
        }

        return "FILESYSTEM: " + cli::message(language, "error.filesystem",
                                             {{"operation", std::string(operation)},
                                              {"path", path},
                                              {"reason", failure_reason(reason)}});
    }

    if (code == "SYSTEM") {
        return "SYSTEM: " + cli::message(language, "error.system",
                                         {{"reason", failure_reason(std::string(text))}});
    }

    if (code == "JSON") {
        // nlohmann::json prefixes its message with "[json.exception.KIND.ID] ".
        if (text.starts_with("[json.exception.") && text.find("] ") != std::string_view::npos) {
            text.remove_prefix(text.find("] ") + 2);
        }

        return "JSON: " + cli::message(language, "error.json",
                                       {{"reason", failure_reason(std::string(text))}});
    }

    if (code.empty()) {
        return "INTERNAL_ERROR: " + cli::message(language, "error.internal",
                                                 {{"reason", failure_reason(std::string(text))}});
    }

    return {};
}

// The catalog text of a thrown exception without a CODE, by its kind, with its cause; empty for an
// exception with a CODE.
inline std::string uncoded_failure(const std::exception_ptr &failure, cli::Language language) {
    const auto code = failure_code(failure);

    try {
        std::rethrow_exception(failure);
    } catch (const std::filesystem::filesystem_error &error) {
        return uncoded_failure(code, error.what(), &error, language);
    } catch (const std::exception &error) {
        return uncoded_failure(code, error.what(), nullptr, language);
    }
}

// A catalog error in language for a thrown exception. With the log file of the command, its path
// follows. An exception without a CODE shows FILESYSTEM, SYSTEM or JSON by its kind, else
// INTERNAL_ERROR, with its cause. Another error outside the catalog shows only its CODE with the
// log file and leaves its English text to the log, or keeps its English "CODE: message" without a
// log file.
inline std::string human_cli_error(const std::exception_ptr &failure, cli::Language language,
                                   const std::filesystem::path &log = {}) {
    const auto log_line =
            log.empty() ? std::string{}
                        : cli::message(language, "error.log", {{"path", log.string()}}) + "\n";

    try {
        std::rethrow_exception(failure);
    } catch (const cli::LocalizedError &localized) {
        return human_cli_error(localized.render(language)) + log_line;
    } catch (const std::exception &error) {
        if (const auto uncoded = uncoded_failure(failure, language); !uncoded.empty()) {
            return human_cli_error(uncoded) + log_line;
        }

        if (message_code(error.what()) == "ANDROID_ACCELERATION") {
            return human_cli_error("ANDROID_ACCELERATION: " +
                                   cli::message(language, "error.android_acceleration")) +
                   log_line;
        }

        if (message_code(error.what()) == "ANDROID_VERIFIED_BOOT") {
            return human_cli_error("ANDROID_VERIFIED_BOOT: " +
                                   cli::message(language, "error.android_verified_boot")) +
                   log_line;
        }

        if (log.empty()) {
            return human_cli_error(error.what());
        }

        return human_cli_error(std::string(message_code(error.what())) + ": " +
                               cli::message(language, "error.unexpected", {{"log", log.string()}}));
    }
}

// Ctrl+C ends a command as interrupted unless an owned process survived it: that process may still
// hold the machine, so its PROCESS_STOP failure is shown instead.
inline bool reports_interruption(bool interrupted, const std::exception &error) {
    return interrupted && message_code(error.what()) != "PROCESS_STOP";
}

// Pads to a terminal column width.
inline std::string pad_columns(std::string_view text, std::size_t width) {
    const auto columns = logging::terminal_columns(text);

    return std::string(text) + std::string(columns < width ? width - columns : 1, ' ');
}

inline std::string human_cli_output(std::string_view command, const Json &result,
                                    std::string_view profile,
                                    const std::filesystem::path &machine_path = {},
                                    bool verbose = false,
                                    cli::Language language = cli::Language::english) {
    const auto text = [&](std::string_view key, const cli::MessageArguments &arguments = {}) {
        return cli::message(language, key, arguments);
    };
    // deps, check and build name a QNX engine that this host cannot install.
    const auto qnx_host_line = [&]() {
        return result.is_object() && result.contains("qnx_host") &&
                               result.at("qnx_host").value("status", std::string{}) == "unavailable"
                       ? text("output.qnx_host_unavailable") + "\n"
                       : std::string{};
    };
    auto label = machine_path.empty() ? std::string(profile) : machine_path.string();

    if (result.is_object() && result.contains("machine_seed") &&
        result.at("machine_seed").is_string()) {
        label = result.at("machine_seed").get<std::string>();
    }

    if (result.is_object() && result.contains("ok") && result.at("ok") == false) {
        const auto failed = text("output.operation_failed");
        const auto error = result.value("error", Json(failed));

        return human_cli_error(error.is_string() ? error.get<std::string>()
                                                 : error.value("message", failed));
    }

    if (command == "start" && !verbose) {
        const auto machine = machine_path.empty() ? label : machine_path.string();
        // A new session reports its subsystems; the status of a running one does not.
        const bool cluster = result.value("with_cluster", false),
                   multimedia = result.value("with_multimedia", false);
        const auto first = !cluster && !multimedia
                                   ? text("output.already_running", {{"machine", machine}})
                           : !cluster    ? text("output.session_started_multimedia")
                           : !multimedia ? text("output.session_started_cluster")
                                         : text("output.session_started_both");

        return first + "\n" + text("output.stop_hint", {{"machine", machine}}) + "\n";
    }

    std::ostringstream out;

    if (command == "list") {
        out << text("output.profiles") << '\n';

        for (const auto &name : result) {
            out << "  " << name.get<std::string>() << '\n';
        }

        return out.str();
    }

    if (command == "start" || command == "restart") {
        const auto state = [&](const char *field) {
            return text(result.at(field).get<bool>() ? "output.on" : "output.off");
        };
        out << text("output.session_active", {{"machine", label}}) << '\n';

        if (result.contains("with_cluster")) {
            out << text("output.cluster", {{"state", state("with_cluster")}}) << '\n';
        }

        if (result.contains("with_multimedia")) {
            out << text("output.multimedia", {{"state", state("with_multimedia")}}) << '\n';
        }

        return out.str();
    }

    if (command == "status") {
        const auto deliveries = result.value("deliveries", Json::object());
        auto state = [&](const char *role) {
            const auto delivery = deliveries.value(role, Json::object());

            if (!delivery.contains("status")) {
                return text("output.not_started");
            }

            const auto value = delivery.value("status", std::string{});

            if (value == "guest_acknowledged") {
                return text("output.ready");
            }

            if (value == "not_started" || value == "stopped" || value == "host_terminal") {
                return text("output.off");
            }

            return value;
        };
        out << text("output.machine", {{"machine", label}}) << '\n'
            << pad_columns(text("output.column_state"), 14)
            << pad_columns(text("output.column_multimedia"), 22) << text("output.column_cluster")
            << '\n'
            << pad_columns(
                       text(result.value("stopped", false) ? "output.stopped" : "output.running"),
                       14)
            << pad_columns(state("android"), 22) << state("qnx") << '\n';
        const auto grpc =
                deliveries.value("qnx", Json::object()).value("frame_grpc", Json::object());

        if (!result.value("stopped", false) && grpc.value("status", std::string{}) == "listening") {
            out << text("output.frame_grpc", {{"path", grpc.at("discovery").get<std::string>()}})
                << '\n';
        }

        return out.str();
    }

    if (command == "stop") {
        return text("output.session_stopped", {{"machine", label}}) + "\n";
    }

    if (command == "patch") {
        return text("output.vehicle_updated", {{"machine", label}}) + "\n";
    }

    if (command == "check") {
        const auto launch = [&](const char *field) {
            return text(result.at(field).get<bool>() ? "output.available" : "output.missing");
        };
        out << text("output.profile", {{"profile", std::string(profile)}}) << '\n'
            << text("output.installation", {{"path", result.at("root").get<std::string>()}}) << '\n'
            << text("output.multimedia_launch", {{"state", launch("android_launch_spec")}}) << '\n'
            << text("output.cluster_launch", {{"state", launch("cluster_launch_spec")}}) << '\n';
        out << qnx_host_line();

        return out.str();
    }

    // fetch names the profile by the profile_name that its command adds for the console.
    if (command == "fetch") {
        return text("output.fetch",
                    {{"profile_name", result.value("profile_name", std::string(profile))}}) +
               "\n" + text("output.next", {{"command", "voyemu build " + std::string(profile)}}) +
               "\n";
    }

    if (command == "deps") {
        out << text("output.deps") << '\n';

        if (result.contains("preparation_tools_ready") &&
            !result.at("preparation_tools_ready").get<bool>()) {
            out << text("output.deps_java") << '\n';
        }

        out << qnx_host_line();

        return out.str();
    }

    // build names the machine and its build time, which its command adds for the console, and
    // how to start it.
    if (command == "build") {
        if (result.value("profile_ready", false) ||
            (result.value("machine_ready", false) && result.value("android_ready", false))) {
            const auto time = progress::duration_text(
                    result.value("build_seconds", std::uint64_t{}), language);
            out << text(result.value("machine_updated", false) ? "output.machine_updated"
                                                               : "output.machine_prepared",
                        {{"time", time}, {"machine", label}})
                << '\n'
                << text("output.start_hint", {{"machine", label}}) << '\n';
        } else {
            out << text("output.build_incomplete", {{"machine", label}}) << '\n';
        }

        // The configuration file matters only to diagnostics.
        if (verbose && result.contains("runtime")) {
            out << text("output.runtime", {{"path", result.at("runtime").get<std::string>()}})
                << '\n';
        }

        out << qnx_host_line();

        return out.str();
    }

    throw std::logic_error("CLI_OUTPUT: unsupported public command");
}
} // namespace voyemu
