#include "human_output.hpp"
#include <cassert>
#include <exception>
#include <iostream>
using namespace voyemu;

int main() try {
    auto plain = [](const std::string &text) {
        assert(!text.empty() && text.back() == '\n' &&
               Json::parse(text, nullptr, false).is_discarded());
    };
    const auto names = human_cli_output("list", Json::array({"free-profile", "passion-profile"}),
                                        "free-profile");

    plain(names);
    assert(names == "Profiles\n  free-profile\n  passion-profile\n");
    const auto status = human_cli_output("status",
                                         {{"stopped", false},
                                          {"machine_seed", "/machines/My car"},
                                          {"deliveries",
                                           {{"android", {{"status", "guest_acknowledged"}}},
                                            {"qnx", {{"status", "not_started"}}}}}},
                                         "free-profile");
    plain(status);
    assert(status.find("/machines/My car") != std::string::npos &&
           status.find("ready") != std::string::npos && status.find("off") != std::string::npos);
    const Json grpc{{"status", "listening"},
                    {"host", "127.0.0.1"},
                    {"port", 30123},
                    {"discovery", "/private/session/qnx-frame-grpc.json"},
                    {"token", "fixture-secret"}};
    const auto cluster_status = human_cli_output(
            "status", {{"stopped", false}, {"deliveries", {{"qnx", {{"frame_grpc", grpc}}}}}},
            "free-profile");
    assert(cluster_status.find("/private/session/qnx-frame-grpc.json") != std::string::npos &&
           cluster_status.find("fixture-secret") == std::string::npos);
    const auto stopped = human_cli_output("status", {{"stopped", true}}, "free-profile");
    plain(stopped);
    assert(stopped.find("stopped") != std::string::npos);

    for (const auto *command : {"restart", "stop", "patch", "fetch"}) {
        plain(human_cli_output(command, {{"ok", true}, {"with_cluster", true}}, "free-profile"));
    }

    // fetch names the profile by its title and gives the next command.
    assert(human_cli_output("fetch", {{"profile_name", "Free 7.3.1"}}, "free-profile") ==
           "Free 7.3.1 originals are ready.\nNext: voyemu build free-profile\n");
    assert(human_cli_output("fetch", {{"profile_name", "Free 7.3.1"}}, "free-profile", {}, false,
                            cli::Language::russian) ==
           "Оригиналы Free 7.3.1 готовы.\nДальше: voyemu build free-profile\n");

    const auto recovered = human_cli_output("status",
                                            {{"stopped", true},
                                             {"deliveries",
                                              {{"android", {{"status", "host_terminal"}}},
                                               {"qnx", {{"status", "host_terminal"}}}}}},
                                            "free-profile");
    assert(recovered.find("host_terminal") == std::string::npos &&
           recovered.find("off") != std::string::npos);
    const auto failed = human_cli_output(
            "status",
            {{"stopped", true}, {"deliveries", {{"qnx", {{"status", "graphics_worker_exited"}}}}}},
            "free-profile");
    assert(failed.find("graphics_worker_exited") != std::string::npos);
    const Json started{{"ok", true}, {"with_cluster", true}, {"with_multimedia", true}};
    // start names the opening windows of a new session, or says the session already runs; both
    // show how to stop it.
    assert(human_cli_output("start", started, "free-profile", "/machines/car") ==
           "Session started; the multimedia and cluster windows open in a few seconds.\n"
           "Stop it: voyemu stop /machines/car\n");
    assert(human_cli_output("start",
                            {{"ok", true}, {"with_cluster", false}, {"with_multimedia", true}},
                            "free-profile", "/machines/car") ==
           "Session started; the multimedia window opens in a few seconds.\n"
           "Stop it: voyemu stop /machines/car\n");
    assert(human_cli_output("start",
                            {{"ok", true}, {"with_cluster", true}, {"with_multimedia", false}},
                            "free-profile", "/machines/car", false, cli::Language::russian) ==
           "Сеанс запущен, окно приборки откроется через несколько секунд.\n"
           "Остановить: voyemu stop /machines/car\n");
    // Unavailable host audio adds one line in either language; playback adds none.
    auto silent = started;
    silent["audio"] = {{"state", "unavailable"},
                       {"driver", "none"},
                       {"reason", "no_server"},
                       {"detail", "/run/user/1/pulse/native"}};
    assert(human_cli_output("start", silent, "free-profile", "/machines/car") ==
           "Session started; the multimedia and cluster windows open in a few seconds.\n"
           "Multimedia sound is off: no local PulseAudio socket at $XDG_RUNTIME_DIR/pulse/native. "
           "Set PULSE_SERVER=unix:/path to use another one.\n"
           "Stop it: voyemu stop /machines/car\n");
    silent["audio"]["reason"] = "unsupported_server";
    assert(human_cli_output("start", silent, "free-profile", "/machines/car", false,
                            cli::Language::russian)
                   .find("Звук мультимедиа выключен: в PULSE_SERVER нужен локальный сокет вида "
                         "unix:/путь.\n") != std::string::npos);
    assert(human_cli_output("start", silent, "free-profile", "/machines/car", true)
                   .ends_with("Multimedia: on\nMultimedia sound is off: PULSE_SERVER must name a "
                              "local socket as unix:/path.\n"));
    silent["audio"] = {{"state", "playing"}, {"driver", "pa"}, {"reason", ""}, {"detail", ""}};
    assert(human_cli_output("start", silent, "free-profile", "/machines/car") ==
           human_cli_output("start", started, "free-profile", "/machines/car"));
    assert(human_cli_output("start", {{"ok", true}, {"stopped", false}, {"android_pid", 7}},
                            "free-profile", "/machines/car") ==
           "Machine is already running: /machines/car\nStop it: voyemu stop /machines/car\n");
    assert(human_cli_output("start", started, "free-profile", "/machines/car", true) ==
           "Session active: /machines/car\nCluster: on\nMultimedia: on\n");
    assert(human_cli_output("start", {{"ok", false}, {"error", "launch failed"}}, "free-profile") ==
           "Voyemu: launch failed\n");
    const auto check = human_cli_output("check",
                                        {{"root", "/host installation"},
                                         {"android_launch_spec", false},
                                         {"cluster_launch_spec", true}},
                                        "free-profile");
    plain(check);
    assert(check.find("Installation: /host installation") != std::string::npos &&
           check.find("Multimedia launch: missing") != std::string::npos);
    const auto deps = human_cli_output("deps", {{"preparation_tools_ready", false}},
                                       "free-profile");
    plain(deps);
    assert(deps.find("--jdk") != std::string::npos && deps.find("QNX") == std::string::npos);
    // build names the machine, its build time and how to start it; the configuration file only
    // with --verbose.
    const Json ready{{"android_ready", true},
                     {"machine_ready", true},
                     {"build_seconds", 845},
                     {"machine_seed", "machines/car"},
                     {"runtime", "/machines/car/runtime.json"}};
    const auto built = human_cli_output("build", ready, "free-profile");
    plain(built);
    assert(built == "Machine ready in 14 min 5 s: machines/car\n"
                    "Start it: voyemu start machines/car\n");
    assert(human_cli_output("build",
                            {{"profile_ready", true},
                             {"build_seconds", 845},
                             {"machine_seed", "machines/car"}},
                            "free-profile", {}, false, cli::Language::russian) ==
           "Машина готова за 14 мин 5 с: machines/car\nЗапуск: voyemu start machines/car\n");
    auto updated = ready;
    updated["machine_updated"] = true;
    updated["build_seconds"] = 180;
    assert(human_cli_output("build", updated, "free-profile") ==
           "Machine updated in 3 min: machines/car\nStart it: voyemu start machines/car\n");
    assert(human_cli_output("build", ready, "free-profile", {}, true)
                   .ends_with("Runtime: /machines/car/runtime.json\n"));
    assert(human_cli_output("build", {{"android_ready", true}, {"machine_seed", "machines/car"}},
                            "free-profile") == "Build incomplete: machines/car\n");
    // deps, check and build name a QNX engine that this host cannot install.
    const Json unavailable = {{"status", "unavailable"},
                              {"reason", "QNX_HOST_ASSET_MISSING: not published yet"}};
    const auto qnx_deps = human_cli_output("deps", {{"qnx_host", unavailable}}, "free-profile");
    const auto qnx_build = human_cli_output(
            "build", {{"android_ready", true}, {"qnx_host", unavailable}}, "free-profile");
    const auto qnx_check = human_cli_output("check",
                                            {{"root", "/host installation"},
                                             {"android_launch_spec", true},
                                             {"cluster_launch_spec", false},
                                             {"qnx_host", unavailable}},
                                            "free-profile");

    for (const auto &output : {qnx_deps, qnx_build, qnx_check}) {
        plain(output);
        assert(output.find("The QNX engine of this host is unavailable") != std::string::npos);
    }

    assert(human_cli_output("deps", {{"qnx_host", {{"executable", "/qemu"}}}}, "free-profile")
                   .find("QNX engine") == std::string::npos);
    plain(human_cli_output("build", {{"profile_ready", true}}, "free-profile"));
    const auto failure = human_cli_output(
            "stop", {{"ok", false}, {"error", {{"message", "owned guest is still running"}}}},
            "free-profile");
    plain(failure);
    assert(failure.find("owned guest is still running") != std::string::npos &&
           failure.find("Session stopped") == std::string::npos);
    const auto error = human_cli_error("CLI_COMMAND: unknown command 'strat'; run 'voyemu help'");
    plain(error);
    assert(error.find("unknown command 'strat'") != std::string::npos &&
           error.find("prototype") == std::string::npos);
    // Ctrl+C reports an interruption, but not when the starting supervisor survived it.
    const cli::LocalizedError survived("PROCESS_STOP", "error.start_not_stopped",
                                       {{"log", "/session/supervisor.log"}});
    assert(reports_interruption(true, VoyemuError("INTERRUPTED", "start interrupted")) &&
           reports_interruption(true, VoyemuError("JAVA_HELPER", "helper exited 130")) &&
           !reports_interruption(false, VoyemuError("INTERRUPTED", "start interrupted")) &&
           !reports_interruption(true, survived));
    assert(human_cli_error(std::make_exception_ptr(survived), cli::Language::english,
                           "/logs/start.log") ==
           "Voyemu: PROCESS_STOP: the interrupted session did not stop; its supervisor may still "
           "hold the machine.\nSession log: /session/supervisor.log\nLog: /logs/start.log\n");
    std::cout << "Human CLI summaries, tables and errors remain plain text\n";
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
