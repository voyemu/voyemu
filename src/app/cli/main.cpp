#include "cli_commands.hpp"
#include "interruption.hpp"
#include "main_host.hpp"
#include "version.hpp"

namespace {
// Whether the command stops at the interruption checks of its preparation work: deps, fetch, build.
std::atomic<bool> preparation = false;

void interrupt(int) {
    voyemu::cli::interrupted = true;

    if (preparation) {
        voyemu::interruption::requested = true;
    }
}
} // namespace

std::atomic<bool> voyemu::cli::interrupted = false;

// NOLINTNEXTLINE(bugprone-exception-escape): only unreachable nlohmann::json invariants escape.
int main(int argc, char **argv) {
    if (const auto result = voyemu::cli::host_command(argc, argv)) {
        return *result;
    }

#ifdef VOYEMU_HAS_GRAPHICS
    if (argc > 1 && std::string_view(argv[1]) == "_graphics") {
        return voyemu::graphics_main(argc - 1, argv + 1);
    }
#endif
#ifdef VOYEMU_HAS_WINDOW
    if (argc > 1 && std::string_view(argv[1]) == "_window") {
        return voyemu::window_main(argc - 1, argv + 1);
    }
#endif
    std::signal(SIGINT, interrupt);
    std::signal(SIGTERM, interrupt);
    voyemu::cli::ignore_broken_pipe();
    const auto language = voyemu::cli::select_language(
            argc, argv,
            [](const char *name) {
                return std::getenv(name);
            },
            voyemu::os::user_interface_language);
    // The log file of an ordinary command in its installation, named on failure.
    std::filesystem::path log_file;
    try {
        auto args = voyemu::cli::parse(argc, argv, voyemu::os::executable_path());
        using voyemu::Json;

        if (!args.private_start && args.command != "test" && args.command != "_supervise") {
            voyemu::logging::human_console(true);
            voyemu::logging::verbose(args.verbose);
            voyemu::progress::console(language, voyemu::os::error_terminal());
        }

        const auto public_command = args.command;
        preparation = args.command == "deps" || args.command == "fetch" || args.command == "build";
        const auto emit = [&](const Json &value) {
            if (args.private_start) {
                std::cout << value.dump(2) << '\n';
            } else {
                voyemu::progress::separate();
                std::cout << voyemu::human_cli_output(public_command, value, args.profile,
                                                      args.machine_path, args.verbose, language);
            }
        };

        if (args.command == "help" || args.command == "--help") {
            std::cout << voyemu::cli_help(language);

            return 0;
        }

        if (args.command == "--version") {
            std::cout << "Voyemu " << voyemu::version() << '\n';

            return 0;
        }

        if (args.command == "test") {
            return voyemu::cli::test_command(args);
        }

        // Commands that change state or run long keep a log; the read-only list, status and check
        // create nothing, so their records go nowhere and their errors are shown in full.
        if (!args.private_start && !args.root.empty() &&
            (args.command == "deps" || args.command == "fetch" || args.command == "build" ||
             args.command == "start" || args.command == "restart" || args.command == "stop" ||
             args.command == "patch")) {
            log_file = voyemu::logging::open_file(args.root / ".local/build/logs", args.command);
            voyemu::logging::write(voyemu::logging::Level::info, "cli", "command.started",
                                   {{"command", args.command}, {"version", voyemu::version()}});
        }

        if (args.command == "list") {
            return voyemu::cli::list_command(args, emit);
        }

        if (args.command == "_supervise") {
            return voyemu::cli::supervise(args, voyemu::os::executable_path());
        }

        if (args.root.empty()) {
            throw voyemu::cli::LocalizedError("PROJECT_ROOT", "error.project_root");
        }

        // A deleted .local root, such as .local/build, comes back on the next command that writes.
        if (args.command == "deps" || args.command == "fetch" || args.command == "build" ||
            args.command == "start" || args.command == "restart") {
            voyemu::ensure_local_roots(args.root);
        }

        if (args.command == "fetch") {
            return voyemu::cli::fetch_command(args, emit);
        }

        if (args.command == "deps") {
            return voyemu::cli::deps_command(args, emit);
        }

        if (args.command == "build") {
            return voyemu::cli::build_command(args, emit);
        }

        // Without an installable QNX engine a machine starts without its cluster unless
        // --cluster=on asks for it.
        if ((args.command == "start" || args.command == "restart") && args.cluster &&
            !args.cluster_explicit && args.multimedia &&
            !voyemu::qnx_host_unavailable(args.root).empty()) {
            args.cluster = false;
            std::cerr << voyemu::cli::message(language, "output.qnx_host_unavailable") << '\n';
        }

        if (args.command == "start" || args.command == "restart") {
            voyemu::ensure_private_directory(
                    voyemu::native_current_active_directory(args.root, args.profile, args.machine));
        }

        if (args.command == "check") {
            return voyemu::cli::check_command(args, emit);
        }

        if (args.command == "restart") {
            if (const auto failed = voyemu::cli::restart_command(args, emit)) {
                return *failed;
            }
        }

        if (args.command == "status" || args.command == "stop" || args.command == "patch") {
            return voyemu::cli::session_command(args, emit);
        }

        if (args.command == "start") {
            return voyemu::cli::start_command(args, emit);
        }

        throw voyemu::cli::LocalizedError("CLI_COMMAND", "error.unknown_command_generic");
    } catch (const std::exception &error) {
        if (!log_file.empty()) {
            // The log keeps the English text that the console replaces by the log path.
            voyemu::logging::write(voyemu::logging::Level::error, "cli",
                                   std::string(error.what()).substr(0, 4096));
        }

        if (argc > 1 && std::string_view(argv[1]) == "test") {
            std::string message = error.what(), code(voyemu::message_code(message));

            if (code.empty()) {
                code = "TEST_ARGUMENT";
                message = "Invalid JSON automation arguments";
            }

            std::cout << voyemu::Json{{"schema", 1},
                                      {"request_id", nullptr},
                                      {"ok", false},
                                      {"error",
                                       {{"code", code},
                                        {"message", message},
                                        {"retryable", false},
                                        {"outcome", "not_started"}}}}
                                 .dump()
                      << '\n';

            return 4;
        }

        if (argc > 1 &&
            (std::string_view(argv[1]) == "_start" || std::string_view(argv[1]) == "_supervise")) {
            std::cerr << voyemu::Json{{"ok", false}, {"error", error.what()}}.dump() << '\n';
        } else if (voyemu::reports_interruption(voyemu::cli::interrupted, error)) {
            // Ctrl+C ends a command with the shell code of SIGINT, whichever step it stopped.
            voyemu::progress::separate();
            std::cerr << voyemu::human_cli_error(
                    std::make_exception_ptr(
                            voyemu::cli::LocalizedError("INTERRUPTED", "error.interrupted")),
                    language, log_file);

            return 130;
        } else {
            // An empty line separates the error from the progress before it.
            voyemu::progress::separate();
            std::cerr << voyemu::human_cli_error(std::current_exception(), language, log_file);
        }

        return 4;
    }
}
