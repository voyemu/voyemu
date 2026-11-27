#include "build_cli_test_host.hpp"
#include "model.hpp"
#include "os/platform.hpp"
#include "process.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <regex>
#include <thread>
using namespace voyemu;

static void require(bool value, const std::string &message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

// The Windows console writes CRLF line ends; the assertions read LF.
static auto execute_lf(const ProcessSpec &spec) {
    auto result = execute(spec, 15000);
    std::string output;

    for (std::size_t i = 0; i < result.output.size(); ++i) {
        if (result.output[i] != '\r' || i + 1 == result.output.size() ||
            result.output[i + 1] != '\n') {
            output += result.output[i];
        }
    }

    result.output = output;

    return result;
}

int main(int argc, char **argv) {
    try {
        require(argc == 2, "CLI binary required");
        const auto project = std::filesystem::canonical(std::filesystem::path(__FILE__))
                                     .parent_path()
                                     .parent_path()
                                     .parent_path()
                                     .parent_path();
        const auto root = project / ".local/build/tmp" / ("public-build-cli-" + random_token());
        ensure_private_directory(root / ".local/machines");
        struct Cleanup {
            std::filesystem::path root;

            ~Cleanup() {
                std::filesystem::remove_all(root);
            }
        } cleanup{root};
        const auto installed = root / ("voyemu" + std::string(voyemu::os::executable_suffix));
        std::filesystem::copy_file(std::filesystem::canonical(argv[1]), installed);
        // A failed command names its log file in the installation, which keeps the English text
        // of the error as JSON Lines.
        const auto named_log = [&](const std::string &output) {
            std::smatch match;
            require(std::regex_search(
                            output, match,
                            std::regex(R"((?:Log|Details are in the log): ([^\n]+?\.log))")),
                    "failed command named no log: " + output);
            const std::filesystem::path log = match[1].str();
            require(log.parent_path() == root / ".local/build/logs" &&
                            std::filesystem::is_regular_file(log),
                    "named log is not a file of .local/build/logs: " + log.string());
            std::ifstream stream(log);

            return std::string(std::istreambuf_iterator<char>(stream), {});
        };
        // Log records look like "component: message"; the console of a command shows none.
        const auto shows_records = [](const std::string &output) {
            return std::regex_search(output, std::regex(R"((^|\n)[a-z][a-z_]*: )"));
        };

        const auto run_unknown = [&](const char *command) {
            ProcessSpec spec;
            spec.executable = installed;
            spec.arguments = {command, "nosuch", "--offline", "--lang=en"};
            spec.directory = root;

            return execute(spec, 15000);
        };

        // An unknown profile stops deps and build before any work, as it stops fetch.
        for (const auto *command : {"deps", "fetch", "build"}) {
            const auto unknown = run_unknown(command);
            require(!unknown.timed_out && unknown.exit_code == 4 &&
                            unknown.output.starts_with("Voyemu: PROFILE_NOT_FOUND:"),
                    std::string(command) + " accepted an unknown profile: " + unknown.output);
        }

        // Ctrl+C reaches the child as SIGINT on POSIX hosts.
        if (!voyemu::os::host_windows) {
            // Ctrl+C stops fetch while it hashes the update archive and ends it with code 130.
            {
                // A synthetic profile whose owner archive the import hashes for seconds.
                const std::string synthetic = "sigint-fixture";
                const auto archive = root / "update.zip";
                const std::string pin(64, '0');
                write_private_json(root / "profiles" / synthetic / "profile.json",
                                   {{"schema", 1},
                                    {"acquisition",
                                     {{"format", "pinned-zip-tgz-raw-scatter"},
                                      {"diff", false},
                                      {"qnxOriginals", Json::array({"role.img"})}}},
                                    {"ownerUpdate",
                                     {{"file", "update.zip"},
                                      {"bytes", 4ULL << 30},
                                      {"sha256", pin},
                                      {"inner", {{"file", "inner.tgz"}, {"sha256", pin}}}}}});
                write_private_json(
                        root / "profiles" / synthetic / "profile-qnx.json",
                        {{"schema", 1},
                         {"originals", {{"role.img", {{"file", "role.img"}, {"sha256", pin}}}}},
                         {"update",
                          {{"container", "zip-stored-tgz"},
                           {"sha256", pin},
                           {"nested_member", "inner.tgz"},
                           {"nested_sha256", pin}}}});
                std::ofstream(archive).close();
                std::filesystem::resize_file(archive, 4ULL << 30);
                ProcessSpec spec;
                spec.executable = installed;
                spec.arguments = {"fetch", synthetic, "--source=" + archive.string(), "--lang=en"};
                spec.directory = root;
                spec.output = root / "fetch-interrupted.log";
                auto fetch = ChildProcess::launch(spec);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                const auto signalled = std::chrono::steady_clock::now();
                require(interrupt_child(fetch.pid()), "SIGINT not sent");

                while (fetch.alive() &&
                       std::chrono::steady_clock::now() - signalled < std::chrono::seconds(30)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }

                const auto stopped = std::chrono::steady_clock::now() - signalled;
                std::ifstream log(spec.output);
                const std::string output(std::istreambuf_iterator<char>(log), {});
                require(!fetch.alive() && fetch.exit_code() == 130 &&
                                stopped < std::chrono::seconds(3) &&
                                output.find(
                                        "Voyemu: INTERRUPTED: the command was interrupted.\nLog: ") !=
                                        std::string::npos,
                        "Ctrl+C did not stop fetch promptly with code 130: " +
                                std::to_string(fetch.exit_code()) + " " + output);
                require(named_log(output).find("\"command.started\"") != std::string::npos,
                        "interrupted fetch log lacks its start record");
                std::filesystem::remove(archive);
            }
        }

        {
            const auto *profile = "free-11-chinese-20260731-7.3.1";
            const auto file = root / "profiles" / profile / "profile.json";
            const auto definition =
                    read_private_json(project / "profiles" / profile / "profile.json");
            require(definition.at("status") == "ready", "API30 source acceptance scope differs");
            write_private_json(file, definition);
            const auto pin = sha256_file(file);
            auto run = [&](std::vector<std::string> arguments) {
                ProcessSpec command;
                command.executable = installed;
                command.arguments = std::move(arguments);
                // Human text assertions read English regardless of the host locale.
                command.arguments.emplace_back("--lang=en");
                command.directory = root;

                return execute_lf(command);
            };
            const auto disabled =
                    run({"build", profile, "--cluster=off", "--multimedia=off", "--offline"});
            require(disabled.exit_code != 0 &&
                            disabled.output.find("cannot both be off") != std::string::npos,
                    "both-off build was not rejected before preparation: " + disabled.output);

            for (const bool android_only : {true, false}) {
                std::vector<std::string> arguments{"build", profile, "--offline"};

                if (android_only) {
                    arguments.insert(arguments.end(), {"--cluster=off", "--multimedia=on"});
                }

                const auto result = run(arguments);
                require(!result.timed_out && result.exit_code != 0,
                        "fixture without retained inputs unexpectedly built or timed out");
                // The header names the machine, its subsystems and the space it needs; an empty
                // line separates the progress from the error. The fixture copies no
                // profile-qnx.json, so the default build prepares only the multimedia.
                const auto header = "Preparing machine " +
                                    (std::filesystem::path("machines") / profile).string() +
                                    ": multimedia only.\nUp to 20 GiB of free space is needed, ";
                const auto failure = result.output.find("\n\nVoyemu:");
                require(result.output.starts_with(header) && failure != std::string::npos &&
                                result.output.find("CLI_ARGUMENT:") == std::string::npos &&
                                result.output.find("PROFILE_INCOMPLETE:") == std::string::npos,
                        "public API30 build did not reach genuine preparation: " + result.output);
                const auto error = result.output.substr(failure + 2);

                // Observer preparation first needs the Java runtime, which offline is not cached.
                require(error.starts_with("Voyemu: DOWNLOAD_OFFLINE: "),
                        "multimedia-only build did not reach observer preparation: " +
                                result.output);

                if (android_only) {
                    require(error.starts_with("Voyemu: DOWNLOAD_OFFLINE: ") &&
                                    error.find(
                                            " is not downloaded and --offline forbids downloads.") !=
                                            std::string::npos &&
                                    result.output.find("\n\nPreparing Android\n") !=
                                            std::string::npos,
                            "Android-only build did not reach observer preparation with absent fixture toolchain sources: " +
                                    result.output);
                    require(!shows_records(result.output),
                            "build printed log records without --verbose: " + result.output);
                    // --verbose prints the records of the log on the console as well.
                    arguments.emplace_back("--verbose");
                    const auto verbose = run(arguments);
                    require(verbose.exit_code == result.exit_code &&
                                    verbose.output.find("cli: command.started; command=build") !=
                                            std::string::npos &&
                                    verbose.output.find("cli: DOWNLOAD_OFFLINE: ") !=
                                            std::string::npos,
                            "build --verbose did not print its log records: " + verbose.output);
                }

                require(sha256_file(file) == pin &&
                                !std::filesystem::exists(root / "machines" / profile) &&
                                std::filesystem::is_directory(root / ".local/machines") &&
                                std::filesystem::is_empty(root / ".local/machines"),
                        "failed offline preparation changed status, published a machine or started a session");
            }
        }

        // Copy the actual target definitions and preparation recipes, while leaving the SDK and
        // helper caches empty.
        {
            const std::string profile = "passion-11-russian-20260403-2.1.4.80";
            const auto source = project / "profiles" / profile;
            const auto expected = root / "profiles" / profile;
            const auto definition = read_private_json(source / "profile.json");
            write_private_json(expected / "profile.json", definition);

            for (const auto &[name, entry] : definition.at("targets").items()) {
                if (entry.contains("androidBase")) {
                    const auto base = std::filesystem::path("profiles/common/android-bases") /
                                      (entry.at("androidBase").get<std::string>() + ".json");
                    ensure_private_directory((root / base).parent_path());
                    std::filesystem::copy_file(project / base, root / base,
                                               std::filesystem::copy_options::skip_existing);
                }
            }

            ProcessSpec spec;
            spec.executable = installed;
            spec.directory = root;
            // Each declared target, and the default one of the host ABI, either reaches its
            // preparation or names the missing host capability before preparing anything.
            const auto attempt = [&](const std::string &name, bool explicit_target) {
                const auto &entry = definition.at("targets").at(name);
                const auto abi = entry.at("guestAbi").get<std::string>();
                const bool translated = abi != os::host_android_abi;
                const auto machine = std::filesystem::path("machines") /
                                     (translated ? profile + "-" + name : profile);
                spec.arguments = {"build", profile, "--offline", "--lang=en"};

                if (explicit_target) {
                    spec.arguments.emplace_back("--target=" + name);
                }

                const auto result = execute_lf(spec);
                require(!result.timed_out && result.exit_code == 4 &&
                                (result.output.find("software translation") != std::string::npos) ==
                                        translated,
                        "targeted build did not stop at its fixture boundary or warn about "
                        "translation: " +
                                result.output);

                const auto kernel = definition.at("android").value("development_kernel", Json{});
                const bool kernel_missing = !entry.contains("developmentKernel") &&
                                            kernel.is_object() && kernel.at("abi") != abi;

                if (kernel_missing) {
                    require(result.output.find("Voyemu: PROFILE_TARGET:") != std::string::npos &&
                                    result.output.find("Preparing machine") == std::string::npos,
                            "a target without the kernel of its ABI did not name it: " +
                                    result.output);
                } else {
                    require(result.output.find("Selected " + name + " (" + abi + ") for " +
                                               machine.string() + ".\n") != std::string::npos &&
                                    (result.output.find("JAVA_HELPER_ASSET_MISSING:") !=
                                             std::string::npos ||
                                     result.output.find("DOWNLOAD_OFFLINE:") != std::string::npos),
                            "targeted build did not select its destination or reach preparation: " +
                                    result.output);
                }

                require(!std::filesystem::exists(root / machine) &&
                                std::filesystem::is_empty(root / ".local/machines"),
                        "offline targeted build published a machine or started a session");
            };

            for (const auto &[name, entry] : definition.at("targets").items()) {
                attempt(name, true);

                if (entry.at("guestAbi").get<std::string>() == os::host_android_abi) {
                    attempt(name, false);
                }
            }
        }

        // build refuses an existing machine before any work and names the next steps; --force
        // needs an existing machine.
        {
            const std::string profile = "free-11-chinese-20260731-7.3.1";
            const auto machine = (std::filesystem::path("machines") / profile).string();
            ensure_private_directory(root / "machines" / profile);
            ProcessSpec spec;
            spec.executable = installed;
            spec.arguments = {"build", profile, "--offline", "--lang=en"};
            spec.directory = root;
            const auto existing = execute_lf(spec);
            require(!existing.timed_out && existing.exit_code == 4 &&
                            existing.output.starts_with(
                                    "Voyemu: PROFILE_BUILD: machine " + machine +
                                    " already exists.\nStart it: voyemu start " + machine +
                                    ", or delete its directory and run build again.\nLog: "),
                    "build of an existing machine did not name it: " + existing.output);
            std::filesystem::remove(root / "machines" / profile);
            spec.arguments = {"build", profile, "--force", "--offline", "--lang=en"};
            const auto missing = execute(spec, 15000);
            require(!missing.timed_out && missing.exit_code == 4 &&
                            missing.output.starts_with("Voyemu: MACHINE_PATH: "),
                    "build --force accepted a missing machine: " + missing.output);
        }

        // The read-only list keeps no log.
        {
            ProcessSpec spec;
            spec.executable = installed;
            spec.arguments = {"list", "--lang=en"};
            spec.directory = root;
            const auto listed = execute(spec, 15000);
            bool logged = false;

            for (const auto &entry :
                 std::filesystem::directory_iterator(root / ".local/build/logs")) {
                logged |= entry.path().filename().string().starts_with("list-");
            }

            require(!listed.timed_out && listed.exit_code == 0 && !logged &&
                            !shows_records(listed.output),
                    "list wrote a log or printed records: " + listed.output);
        }

        // JSON automation keeps its single JSON reply and writes no command log.
        {
            ProcessSpec spec;
            spec.executable = installed;
            spec.arguments = {"test", "--request", (root / "missing-request.json").string()};
            spec.directory = root;
            const auto reply = execute(spec, 15000);
            const auto parsed = Json::parse(reply.output, nullptr, false);
            require(!reply.timed_out && reply.exit_code == 4 && parsed.is_object() &&
                            parsed.at("ok") == false,
                    "test did not keep its JSON reply: " + reply.output);

            for (const auto &entry :
                 std::filesystem::directory_iterator(root / ".local/build/logs")) {
                require(!entry.path().filename().string().starts_with("test-"),
                        "test wrote a command log");
            }
        }

        // The preparation commands recreate the missing roots of .local as private directories.
        for (const auto *name : {"profiles", "toolchains", "build", "machines"}) {
            const auto directory = root / ".local" / name;
            require(std::filesystem::is_directory(directory) &&
                            !std::filesystem::is_symlink(directory),
                    std::string("preparation did not recreate .local/") + name);

            // Windows guards the directories with ACLs, not mode bits.
            if (!voyemu::os::host_windows) {
                require(std::filesystem::status(directory).permissions() ==
                                std::filesystem::perms::owner_all,
                        std::string(".local/") + name + " is not private");
            }
        }

        std::cout
                << "Public Free/Passion API30 build roles reach genuine offline preparation without false readiness or guests\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
