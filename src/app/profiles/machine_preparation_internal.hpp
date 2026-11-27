#pragma once
#include "a9_precompiled_policy.hpp"
#include "android_audio.hpp"
#include "android_engine.hpp"
#include "android_owned_package.hpp"
#include "android_vbmeta.hpp"
#include "api30_framework_boot.hpp"
#include "apk_base.hpp"
#include "base_image.hpp"
#include "can_observation.hpp"
#include "candidate_ui_observer_transport.hpp"
#include "capture_png.hpp"
#include "check.hpp"
#include "deps.hpp"
#include "disk_space.hpp"
#include "e2fs_helper.hpp"
#include "error.hpp"
#include "java_preparation.hpp"
#include "logging.hpp"
#include "lp_image.hpp"
#include "machine_preparation.hpp"
#include "media_discovery.hpp"
#include "media_rpc.hpp"
#include "native_bridge.hpp"
#include "original_navi_candidate.hpp"
#include "os/fs.hpp"
#include "os/platform.hpp"
#include "os/process.hpp"
#include "passion_presentation.hpp"
#include "portable_runtime.hpp"
#include "process.hpp"
#include "profile_build.hpp"
#include "profile_catalog.hpp"
#include "profile_identity.hpp"
#include "profile_runtime.hpp"
#include "progress.hpp"
#include "qinggan09_owned_packages.hpp"
#include "quickboot.hpp"
#include "screens.hpp"
#include "session.hpp"
#include "system_observation.hpp"
#include "ui_source.hpp"
#include "windows_startup.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <tuple>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "os/private_state_security.hpp"
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Helpers shared by the parts of machine preparation; each part includes this header.
namespace voyemu::machine_preparation_detail {
inline constexpr Check need{"MACHINE_PREPARATION"};
void ordinary(const std::filesystem::path &p);
bool inside(const std::filesystem::path &p, const std::filesystem::path &root);
void relative(const std::string &s);
void guest_path(const std::string &p);
void check_file(const std::filesystem::path &p, const std::string &expected,
                std::uint64_t maximum = 8ULL << 30);
std::string text(const std::filesystem::path &p, std::uint64_t maximum = 1ULL << 20);
void write(const std::filesystem::path &p, const std::string &value);
std::string trim(std::string s);
std::vector<std::string> lines(std::string_view value);
std::string regex_escape(const std::string &s);
std::string expanded(std::string component);
std::string shell_line(const std::vector<std::string> &args);
std::vector<std::string> blocks(const std::string &dump);
bool visible(const std::string &dump, const std::string &component, unsigned display);
std::string tool(const AndroidCandidateRequest &request, const std::filesystem::path &path);
void artifact_files(const Json &artifact);
std::string privileged_apk_target(const Json &entry);
bool binding_ready(const std::string &dump, const std::string &component);
std::string avd_config(const Json &profile, const std::filesystem::path &base,
                       const std::string &avd);
void base_features(const std::filesystem::path &file, const Json &features);
using Clock = std::chrono::steady_clock;
struct Installed {
    std::string artifact, target, sha256, package, mode;
    bool mutable_seed = false;
};
// Reads only the new kernel console bytes of one owned SDK boot.
struct CandidateAvbConsole {
    std::uintmax_t offset = 0;
    std::string incomplete;
    unsigned stage = 0;
    bool rejected(const std::filesystem::path &log);
};

struct Candidate {
    std::filesystem::path root, stage, machine, sdk, adb, emulator, qemu_img;
    std::string avd, token, kernel_sha;
    unsigned port;
    Clock::time_point deadline;
    ChildProcess process, adb_server;
    AndroidOwnedAdb adb_binding;
    Json events = Json::array();
    unsigned boots = 0;
    std::function<bool()> cancelled;
    bool capture_frames = false, retained_disks = false, watch_verified_boot = false;
    // A base whose first-stage mount verifies vbmeta: its stock boot parameters, the digest they
    // declare, the extents of the partitions its vbmeta chains to and the digest of the machine.
    std::string stock_boot_parameters, stock_vbmeta_digest, vbmeta_digest;
    std::map<std::string, LogicalPartitionExtent> vbmeta_partitions;
    Json boot_profile;

    Candidate(std::filesystem::path r, std::filesystem::path s, std::filesystem::path sdk_root,
              std::filesystem::path a, std::filesystem::path e, std::filesystem::path q, unsigned p,
              int overall, std::function<bool()> cancel, bool capture = false)
        : root(std::move(r)), stage(std::move(s)), machine(stage / "machine"),
          sdk(std::move(sdk_root)), adb(std::move(a)), emulator(std::move(e)),
          qemu_img(std::move(q)), port(p),
          deadline(Clock::now() + std::chrono::milliseconds(overall)), cancelled(std::move(cancel)),
          capture_frames(capture) {}

    void phase(const std::string &name) {
        write_private_json(stage / "phase.json", {{"schema", 1},
                                                  {"phase", name},
                                                  {"boots", boots},
                                                  {"owned_emulator_alive", process.alive()}});
    }

    int remaining(int maximum) {
        need(!cancelled || !cancelled(), "candidate preparation cancelled");
        const auto value =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                        .count();
        need(value > 0, "overall candidate deadline exceeded");

        return static_cast<int>(std::min<std::int64_t>(maximum, value));
    }

    ProcessResult host(const std::filesystem::path &executable, std::vector<std::string> args,
                       int timeout = 60000, ProcessResult *captured = nullptr,
                       const std::string &log = {}, bool require_success = true) {
        ProcessSpec cmd;
        cmd.executable = executable;
        cmd.arguments = std::move(args);
        cmd.directory = stage;
        cmd.environment = {
                {"TMPDIR", stage.string()}, {"TMP", stage.string()}, {"TEMP", stage.string()}};

        if (executable == adb) {
            for (const auto &[key, value] : android_owned_adb_sdk_environment(adb_binding)) {
                cmd.environment[key] = value;
            }
        }

        std::string description = executable.filename().string();

        for (const auto &arg : cmd.arguments) {
            if (description.size() > 1024) {
                break;
            }

            description += " " + arg;
        }

        const auto operation = description.substr(0, 1024);
        logging::write(logging::Level::debug, "prepare", "candidate command begin",
                       {{"command", operation}, {"boot", boots}});
        auto result = execute(cmd, remaining(timeout), 1 << 20);
        logging::write(logging::Level::debug, "prepare", "candidate command end",
                       {{"command", operation},
                        {"boot", boots},
                        {"exit_code", result.exit_code},
                        {"timed_out", result.timed_out}});

        if (captured) {
            *captured = result;
        }

        if (!log.empty()) {
            write(stage / log, result.output);

            if (log == "boot-image-compile.log" || log == "boot-image-compile-x86.log") {
                write_private_json(stage / (log == "boot-image-compile-x86.log"
                                                    ? "boot-image-process-x86.json"
                                                    : "boot-image-process.json"),
                                   {{"argv", cmd.arguments},
                                    {"host_exit_code", result.exit_code},
                                    {"timed_out", result.timed_out},
                                    {"output_bytes", result.output.size()},
                                    {"output_sha256", sha256_bytes(result.output)}});
            }
        }

        need(!require_success || (!result.timed_out && result.exit_code == 0),
             "host command failed: " + description + ": " + result.output.substr(0, 4096));

        return result;
    }

    std::string raw(std::vector<std::string> args, int timeout = 10000,
                    const std::string &log = {}) {
        const auto owned = [&] {
            return adb_server.alive() && adb_server.owns_tcp_listener(adb_binding.server);
        };
        auto routed = android_owned_adb_prefix(adb_binding, owned());
        routed.insert(routed.end(), {"-s", adb_binding.serial()});
        routed.insert(routed.end(), args.begin(), args.end());
        auto result = host(adb, std::move(routed), timeout, nullptr, log);
        need(owned(), "private ADB owner changed during command");

        return trim(result.output);
    }

    void identity() {
        need(process.alive(), "owned emulator exited");
        need(process.owns_tcp_listener(port) && process.owns_tcp_listener(port + 1),
             "owned emulator does not own console/transport TCP listeners");
        const auto name = lines(raw({"emu", "avd", "name"}));
        need(!name.empty() && name.front() == avd, "console AVD identity differs");
        need(raw({"shell", "getprop", "qemu.voyemu.token"}) == token, "guest nonce differs");
    }

    std::string shell(std::vector<std::string> args, int timeout = 10000) {
        identity();
        const auto log = android_candidate_command_log(args);

        return raw({"shell", shell_line(args)}, timeout, log);
    }

    std::string adbd(std::vector<std::string> args, int timeout = 60000) {
        identity();

        return raw(std::move(args), timeout);
    }

    // Polls check until it passes (true) or the bounded time ends (false); last keeps the text of
    // the last failed check.
    bool poll(const std::function<bool()> &check, int milliseconds, const std::string &what,
              std::string &last) {
        const auto end = Clock::now() + std::chrono::milliseconds(remaining(milliseconds));

        while (Clock::now() < end) {
            need(process.alive(), "owned emulator exited while waiting: " + what);
            try {
                if (check()) {
                    return true;
                }
            } catch (const std::exception &e) {
                last = e.what();
                need(process.alive(), "owned emulator exited while waiting: " + what);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }

        return false;
    }

    void wait(const std::function<bool()> &check, int milliseconds, const std::string &what) {
        std::string last;

        if (!poll(check, milliseconds, what, last)) {
            throw VoyemuError("MACHINE_PREPARATION", "timeout " + what + ": " + last);
        }
    }

    // The bounded polls of the HOME role steps, with the shell of the candidate.
    AndroidCandidatePoll home_role_poll(const std::string &what) {
        return [this, what](const std::function<bool()> &check, int milliseconds) {
            std::string last;

            return poll(check, milliseconds, what, last);
        };
    }

    // Waits for a boot of the emulator without a time limit: until check passes, the emulator
    // exits or the build is interrupted. The boot does not count against the deadline of the other
    // steps.
    void wait_boot(const std::function<bool()> &check, const std::string &what,
                   progress::Elapsed *elapsed = nullptr, std::uintmax_t console_offset = 0) {
        const auto left = deadline - Clock::now();
        CandidateAvbConsole console;
        console.offset = console_offset;
        const auto log = stage / ("emulator-" + std::to_string(boots) + ".log");

        for (;;) {
            deadline = Clock::now() + left;

            if (watch_verified_boot && console.rejected(log)) {
                throw VoyemuError(
                        "ANDROID_VERIFIED_BOOT",
                        "the guest rejected the vbmeta digest and init requested a fatal reboot during " +
                                what + "; kernel console: " + log.string());
            }

            need(!cancelled || !cancelled(), "candidate preparation cancelled");
            need(process.alive(), "owned emulator exited while waiting: " + what);

            if (elapsed) {
                elapsed->tick();
            }

            try {
                if (check()) {
                    break;
                }
            } catch (const std::exception &) {
                need(process.alive(), "owned emulator exited while waiting: " + what);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }

        deadline = Clock::now() + left;
    }

    void boot(const Json &profile) {
        boot_profile = profile;
        const auto kernel = portable_development_kernel(profile);
        kernel_sha = kernel.is_null() ? std::string{} : kernel.at("sha256").get<std::string>();

        if (!kernel_sha.empty()) {
            check_file(machine / "base/kernel-ranchu", kernel_sha, 64ULL << 20);
        }

        if (retained_disks) {
            prepare_android_avd_version_marker(machine, machine / "base/build.prop", true);
        }

        need(tcp_port_free(port) && tcp_port_free(port + 1),
             "candidate TCP ports busy; foreign sessions untouched");

        if (capture_frames) {
            need(tcp_port_free(port + 30000),
                 "candidate SDK capture port busy; foreign listener untouched");
        }

        token = random_token();
        adb_binding = android_owned_adb(port, port + 30000, token);
        need(tcp_port_free(adb_binding.server),
             "candidate private ADB port busy; foreign listener untouched");
        ProcessSpec server;
        server.executable = adb;
        server.arguments = android_owned_adb_server_arguments(adb_binding);
        server.environment = android_owned_adb_sdk_environment(adb_binding);
        server.directory = stage;
        server.output = stage / ("adb-server-" + std::to_string(boots + 1) + ".log");
        adb_server = ChildProcess::launch(server);
        const auto server_deadline = Clock::now() + std::chrono::milliseconds(remaining(5000));

        while (adb_server.alive() && !adb_server.owns_tcp_listener(adb_binding.server) &&
               Clock::now() < server_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        need(adb_server.alive() && adb_server.owns_tcp_listener(adb_binding.server),
             "candidate private ADB listener unavailable");
        avd = "voyemu-candidate-" + token.substr(0, 12);
        ensure_private_directory(stage / "avd-home");
        ensure_private_directory(stage / "emulator-home");
        ordinary(machine / "config.ini");
        {
            std::ofstream config(machine / "config.ini", std::ios::binary | std::ios::trunc);
            config << avd_config(profile, machine / "base", avd);

            if (retained_disks) {
                config << "hw.sdCard=no\n";
            }

            config.close();
            need(bool(config), "owned AVD config rewrite");
        }
        write(stage / "avd-home" / (avd + ".ini"),
              "avd.ini.encoding=UTF-8\npath=" + machine.string() + "\ntarget=android-" +
                      std::to_string(android_candidate_api(profile)) + "\n");
        ProcessSpec cmd;
        cmd.executable = emulator;
        cmd.directory = machine;
        cmd.output = stage / ("emulator-" + std::to_string(++boots) + ".log");
        cmd.environment = {{"ANDROID_AVD_HOME", (stage / "avd-home").string()},
                           {"ANDROID_EMULATOR_HOME", (stage / "emulator-home").string()},
                           {"ANDROID_SDK_ROOT", sdk.string()},
                           {"ANDROID_HOME", sdk.string()},
                           {"TMPDIR", stage.string()},
                           {"ANDROID_TMP", stage.string()}};
        const char *inherited_path = std::getenv("PATH");
#ifdef _WIN32
        for (const auto &[key, value] :
             android_candidate_sdk_environment(sdk, true, inherited_path ? inherited_path : "")) {
            cmd.environment[key] = value;
        }
#else
        for (const auto &[key, value] :
             android_candidate_sdk_environment(sdk, false, inherited_path ? inherited_path : "")) {
            cmd.environment[key] = value;
        }
#endif
        cmd.arguments = {"-avd",
                         avd,
                         "-port",
                         std::to_string(port),
                         "-sysdir",
                         (machine / "base").string(),
                         "-datadir",
                         machine.string(),
                         "-writable-system",
                         "-no-snapshot",
                         "-no-window",
                         "-prop",
                         "qemu.voyemu.token=" + token};

        watch_verified_boot = !stock_vbmeta_digest.empty();
        const auto trace = android_boot_trace_arguments(std::getenv("VOYEMU_ANDROID_BOOT_TRACE"));

        if (watch_verified_boot && trace.empty()) {
            cmd.arguments.push_back("-show-kernel");
        }

        cmd.arguments.insert(cmd.arguments.end(), trace.begin(), trace.end());
        const auto control = android_candidate_capture_arguments(profile, capture_frames, port);
        cmd.arguments.insert(cmd.arguments.end(), control.begin(), control.end());

        if (profile.at("emulator").contains("gpuMode")) {
            cmd.arguments.insert(cmd.arguments.end(),
                                 {"-gpu", profile.at("emulator").at("gpuMode").get<std::string>()});
        }

        const auto features = profile.at("android").value("features", Json::object());

        for (auto it = features.begin(); it != features.end(); ++it) {
            cmd.arguments.insert(cmd.arguments.end(),
                                 {"-feature", (it.value() == "off" ? "-" : "") + it.key()});
        }

        const bool accelerated = android_hardware_acceleration(android_guest_abi(profile));
        cmd.arguments.insert(cmd.arguments.end(), {"-accel", accelerated ? "on" : "off"});
#ifdef _WIN32
        const auto machine_arguments = android_sdk_machine_arguments(true, false,
                                                                     android_guest_abi(profile));
        cmd.arguments.insert(cmd.arguments.end(), machine_arguments.begin(),
                             machine_arguments.end());
#endif

        for (const auto &[key, value] : android_owned_adb_sdk_environment(adb_binding)) {
            cmd.environment[key] = value;
        }

        configure_android_wav_audio(
                cmd, stage / ("android-audio-g" + std::to_string(boots) + ".wav"),
                stage / ("android-no-input-g" + std::to_string(boots) + ".wav"));

        if (accelerated && android_acceleration_required(profile)) {
            require_android_acceleration(cmd);
        }

        process = ChildProcess::launch(cmd);
        phase("booting");
        write_private_json(stage / "runtime.json", {{"schema", 1},
                                                    {"pid", process.pid()},
                                                    {"adb_pid", adb_server.pid()},
                                                    {"adb_server_port", adb_binding.server},
                                                    {"port", port},
                                                    {"avd", avd},
                                                    {"token", token},
                                                    {"phase", "booting"}});
        progress::Elapsed elapsed("cold_boot_multimedia");
        wait_boot(
                [&] {
                    identity();

                    return raw({"shell", "getprop", "sys.boot_completed"}) == "1" &&
                           raw({"shell", "pm", "path", "android"}).starts_with("package:");
                },
                "Android boot", &elapsed);
        elapsed.done("cold_boot_multimedia_done");

        if (!kernel_sha.empty()) {
            check_file(machine / "base/kernel-ranchu", kernel_sha, 64ULL << 20);
        }

        events.push_back({{"phase", "boot"},
                          {"boot", boots},
                          {"guest_nonce_verified", true},
                          {"tcp_owner_verified", true}});
    }

    void root_adbd() {
        const auto end = Clock::now() + std::chrono::milliseconds(remaining(60000));
        const auto budget = [&] {
            const auto left =
                    std::chrono::duration_cast<std::chrono::milliseconds>(end - Clock::now())
                            .count();
            need(left > 0, "timeout rooted adbd lifetime transition");

            return remaining(static_cast<int>(std::min<std::int64_t>(10000, left)));
        };
        const auto owner = [&] {
            need(process.alive() && process.owns_tcp_listener(port) &&
                         process.owns_tcp_listener(port + 1),
                 "owned emulator lost during adb root");
            need(adb_server.alive() && adb_server.owns_tcp_listener(adb_binding.server),
                 "private ADB owner lost during adb root");
        };
        const auto command = [&](const std::vector<std::string> &args,
                                 bool transitioning) -> std::optional<std::string> {
            owner();
            auto routed = android_owned_adb_prefix(adb_binding, true);
            routed.insert(routed.end(), {"-s", adb_binding.serial()});
            routed.insert(routed.end(), args.begin(), args.end());
            const auto result = host(adb, std::move(routed), budget(), nullptr, {}, false);
            owner();
            const auto output = trim(result.output);

            const auto missing_device = "device '" + adb_binding.serial() + "' not found";

            if (transitioning && !result.timed_out && result.exit_code == 1 &&
                (output == "error: device offline" || output == "adb: device offline" ||
                 output == "error: closed" || output == "error: " + missing_device ||
                 output == "adb: " + missing_device)) {
                return std::nullopt;
            }

            if (transitioning && !result.timed_out && result.exit_code != 0 &&
                output == "adb: unable to connect for root: closed") {
                // The SDK client saw the connection close while adbd restarted; the
                // lifetime loop below remains the sole authority on the outcome.
                return std::nullopt;
            }

            need(!result.timed_out && result.exit_code == 0,
                 "adb root command failed: " + output.substr(0, 4096));

            return output;
        };
        struct Snapshot {
            std::string boot, pid, start, uid;

            bool same_lifetime(const Snapshot &other) const {
                return pid == other.pid && start == other.start;
            }
        };
        // Walk the serving shell's ancestors, never a global pidof result. Android's shell
        // inherits READPROC from adbd; unreadable or malformed proc data fails closed.
        const std::string probe = R"sh(set -e
adbd_lifetime() {
    p=$$
    n=0
    while [ "$n" -lt 16 ] && [ "$p" -gt 1 ]; do
        s=$(cat "/proc/$p/stat")
        t=${s##*) }
        set -- $t
        parent=$2
        shift 19
        case "$s" in
            "$p (adbd) "*) printf '%s\n%s\n' "$p" "$1"; return 0;;
        esac
        p=$parent
        n=$((n + 1))
    done
    echo 'serving adbd ancestry unavailable' >&2
    return 1
}
printf 'VOYEMU_ADBD_LIFETIME\n'
getprop qemu.voyemu.token
cat /proc/sys/kernel/random/boot_id
adbd_lifetime
id -u
adbd_lifetime
cat /proc/sys/kernel/random/boot_id
getprop qemu.voyemu.token
)sh";
        const auto snapshot = [&](bool transitioning) -> std::optional<Snapshot> {
            const auto name = command({"emu", "avd", "name"}, transitioning);

            if (!name) {
                return std::nullopt;
            }

            const auto names = lines(*name);
            need(!names.empty() && names.front() == avd, "console AVD identity differs");
            const auto output = command({"shell", probe}, transitioning);

            if (!output) {
                return std::nullopt;
            }

            const auto fields = lines(*output);
            need(fields.size() == 10 && fields[0] == "VOYEMU_ADBD_LIFETIME",
                 "invalid adbd lifetime protocol");
            need(fields[1] == token && fields[9] == token, "guest nonce differs");
            need(std::regex_match(fields[2],
                                  std::regex("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")) &&
                         fields[2] == fields[8],
                 "kernel boot identity differs during adb root");

            for (const auto index : {3, 4, 5, 6, 7}) {
                need(std::regex_match(fields[index], std::regex("[0-9]+")),
                     "invalid adbd lifetime value");
            }

            need(fields[3] != "0" && fields[4] != "0" && fields[3] == fields[6] &&
                         fields[4] == fields[7],
                 "serving adbd lifetime differs within probe");
            logging::write(logging::Level::debug, "prepare", "serving adbd lifetime verified",
                           {{"boot_id", fields[2]},
                            {"pid", fields[3]},
                            {"start", fields[4]},
                            {"uid", fields[5]}});

            return Snapshot{fields[2], fields[3], fields[4], fields[5]};
        };
        const auto before = snapshot(false).value();

        if (before.uid == "0") {
            const auto after = snapshot(false).value();
            need(before.boot == after.boot && before.same_lifetime(after) && after.uid == "0",
                 "rooted adbd changed during confirmation");

            return;
        }

        const auto response = command({"root"}, true);
        // AOSP adbd answers rc=0 either with the transition text or with an empty
        // reply while it restarts; the ownership loop below is the actual authority.
        need(!response || response->empty() || *response == "restarting adbd as root",
             "adb root request refused or invalid response");

        while (Clock::now() < end) {
            const auto current = snapshot(true);

            if (current) {
                need(current->boot == before.boot, "kernel boot identity changed during adb root");

                if (current->uid == "0" && !current->same_lifetime(before)) {
                    const auto confirmed = snapshot(true);

                    if (confirmed) {
                        need(confirmed->boot == before.boot,
                             "kernel boot identity changed during adb root confirmation");

                        if (confirmed->uid == "0" && confirmed->same_lifetime(*current)) {
                            return;
                        }
                    }
                }
            }

            // Poll only the bounded root transition; elapsed time is never readiness evidence.
            std::this_thread::sleep_for(std::chrono::milliseconds(std::min(250, budget())));
        }

        throw VoyemuError("MACHINE_PREPARATION", "timeout rooted adbd lifetime transition");
    }

    void reboot() {
        if (!kernel_sha.empty()) {
            check_file(machine / "base/kernel-ranchu", kernel_sha, 64ULL << 20);
        }

        const auto previous = shell({"cat", "/proc/sys/kernel/random/boot_id"});
        need(!previous.empty(), "kernel boot identity missing");
        const auto offset =
                watch_verified_boot
                        ? std::filesystem::file_size(stage /
                                                     ("emulator-" + std::to_string(boots) + ".log"))
                        : 0;
        adbd({"reboot"});
        wait_boot(
                [&] {
                    identity();

                    return raw({"shell", "cat", "/proc/sys/kernel/random/boot_id"}) != previous &&
                           raw({"shell", "getprop", "sys.boot_completed"}) == "1" &&
                           raw({"shell", "pm", "path", "android"}).starts_with("package:");
                },
                "guest reboot", nullptr, offset);

        if (!kernel_sha.empty()) {
            check_file(machine / "base/kernel-ranchu", kernel_sha, 64ULL << 20);
        }

        events.push_back({{"phase", "reboot"}, {"kernel_boot_id_changed", true}});
    }

    void writable() {
        root_adbd();
        const auto result = adbd({"remount"});

        if (std::regex_search(result, std::regex("reboot", std::regex::icase))) {
            if (stock_vbmeta_digest.empty()) {
                reboot();
            } else {
                bind_verified_boot();
            }

            root_adbd();
            adbd({"remount"});
        }
    }

    // The first remount disables the dm-verity hashtree in the top vbmeta and so changes the
    // vbmeta digest; the guest boots again only with boot parameters that declare the new one.
    void bind_verified_boot() {
        stop();
        const auto overlay = machine / "system.img.qcow2", raw = stage / "vbmeta-system.img";
        need(std::filesystem::is_regular_file(std::filesystem::symlink_status(overlay)),
             "remounted system overlay missing");
        std::filesystem::remove(raw);
        host(qemu_img, {"convert", "-f", "qcow2", "-O", "raw", overlay.string(), raw.string()},
             600000);
        const auto chain = android_vbmeta_chain(raw_disk_reader(raw), vbmeta_partitions);
        std::filesystem::remove(raw);
        const auto parameters = machine / "base/VerifiedBootParams.textproto";
        std::filesystem::remove(parameters);
        write(parameters,
              android_verified_boot_parameters(stock_boot_parameters, stock_vbmeta_digest, chain));
        vbmeta_digest = chain.digest;
        events.push_back({{"phase", "verified-boot-parameters"},
                          {"vbmeta_digest", chain.digest},
                          {"vbmeta_flags", chain.flags}});
        boot(boot_profile);
    }

    void stop() {
        if (!process.alive()) {
            if (adb_server.alive()) {
                adb_server.terminate(1000);
            }

            if (std::filesystem::exists(stage / "runtime.json")) {
                std::filesystem::remove(stage / "runtime.json");
            }

            return;
        }

        identity();
        shell({"sync"});
        adbd({"emu", "kill"});
        const auto until = Clock::now() + std::chrono::seconds(30);

        while (process.alive() && Clock::now() < until) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (process.alive()) {
            process.terminate(5000);
        }

        need(!process.alive(), "owned emulator did not exit");

        if (adb_server.alive()) {
            adb_server.terminate(1000);
        }

        need(!adb_server.alive(), "owned private ADB did not exit");
        std::filesystem::remove(stage / "runtime.json");
        events.push_back({{"phase", "stop"}, {"owned_pid_exited", true}});
    }

    ~Candidate() {
        if (process.alive()) {
            try {
                process.terminate(5000);
            } catch (...) { /* Ignored: termination is best-effort here. */
            };
        }

        if (adb_server.alive()) {
            try {
                adb_server.terminate(1000);
            } catch (...) { /* Ignored: termination is best-effort here. */
            };
        }
    }
};
bool android_candidate_ui_shell_ready(
        const std::function<std::string(const std::vector<std::string> &)> &shell);
Json read_candidate_ui(const Json &connection, int timeout_ms,
                       const std::function<Json(const Json &, int)> &exchange);
Json capture_candidate_ui(Candidate &c, const Json &profile);
std::pair<Json, Json> data_install_phases(const Json &entries);
// Installs the planned entries into the candidate; meter counts the bytes of their files.
void install_entries(Candidate &c, const Json &entries, const Json &artifacts,
                     const std::filesystem::path &aapt2, std::vector<Installed> &installed,
                     progress::Meter *meter = nullptr);
// Installs the donated Native Bridge files and enables it in the property files of the base.
void install_native_bridge(Candidate &c, const NativeBridge &bridge,
                           std::vector<Installed> &installed);
// Whether every donated file of the guest has its pinned bytes, checked with one shell command.
bool native_bridge_files_pinned(Candidate &c, const NativeBridge &bridge);
// Records the cold checks of the donated files and of each property that enables the bridge.
void verify_cold_native_bridge(Candidate &c, const NativeBridge &bridge, Json &checks);
std::string home_component(Candidate &c, const Json &config, bool establish);
// Guest mode, owner and label of one path in the form of android_candidate_file_metadata.
std::string guest_file_metadata(Candidate &c, const std::string &path);
std::string
guest_file_metadata(const std::string &path,
                    const std::function<std::string(const std::vector<std::string> &)> &shell);
void prepare_a9_precompiled_policy(Candidate &c, const Json &profile,
                                   std::vector<Installed> &installed);
void verify_a9_precompiled_policy(Candidate &c, const Json &profile);
void configure_settings(Candidate &c, const Json &settings, bool late);
void configure_boot_properties(Candidate &c, const Json &profile,
                               std::vector<Installed> &installed);
void configure(Candidate &c, const Json &profile, std::vector<Installed> &installed);
void start_qinggan11_secondary_service(
        const std::function<std::string(const std::vector<std::string> &, int)> &shell,
        const std::function<void(const std::function<bool()> &, int, const std::string &)> &wait,
        const std::function<void()> &activate_multidisplay);
void wake_displays(Candidate &c, const Json &profile);
void persisted(Candidate &c, const Json &profile, const std::vector<Installed> &installed);
void record_cold_check(Json &checks, const std::string &id, const std::string &actual,
                       const std::string &expected);
void verify_cold_policy_files(
        const Json &profile, const std::vector<Installed> &installed, Json &checks,
        const std::function<std::string(const std::vector<std::string> &)> &shell,
        const std::function<void()> &root_for_policy = {});
bool cold_policy_verified(const Json &profile, const Installed &item, const Json &checks,
                          const std::string &boot_id);
void verify_cold_installed_file(
        const Json &profile, const Installed &item, const std::string &target, Json &checks,
        const std::string &boot_id,
        const std::function<std::string(const std::vector<std::string> &)> &shell);
void verify_cold_original_navi(Candidate &c, Json &checks);
void verify_cold(Candidate &c, const Json &profile, const std::vector<Installed> &installed,
                 Json &checks);
Json capture_candidate_frames(Candidate &c, const Json &profile);
// The helper is needed only while producing the explicitly opted-in A9 candidate.
void prepare_api30_root_layout(Candidate &c, const Json &profile, const std::string &image_pin,
                               std::uint64_t reserve);
void repair_a9_offline_labels(Candidate &c, const Json &profile, const Json &artifacts,
                              const std::vector<Installed> &installed, std::uint64_t reserve);
// API30 policy/contexts are installed as pinned system files before the first OEM boot;
// the new label definitions load with that boot, so the A11 opt-in only fences the
// resulting on-disk labels through an in-guest restorecon before the cold verification.
void repair_a11_offline_labels(Candidate &c, const Json &profile, const Json &artifacts);
Json export_images(Candidate &c, const std::filesystem::path &destination, std::uint64_t reserve);
} // namespace voyemu::machine_preparation_detail
