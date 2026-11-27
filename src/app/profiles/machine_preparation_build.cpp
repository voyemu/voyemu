#include "android_boot_pins.hpp"
#include "machine_preparation_internal.hpp"
#include "profile_catalog.hpp"
#include "qinggan11_startup.hpp"

// Builds an Android candidate machine from its base image, packages and install plan.
namespace voyemu {
using namespace machine_preparation_detail;

std::map<std::string, LogicalPartitionExtent> android_vbmeta_partitions(const Json &base) {
    const auto clean = native_clean_base(base);

    return {{"system", {clean.system.offset, clean.system.bytes}},
            {"system_ext", {clean.system_ext.offset, clean.system_ext.bytes}}};
}

std::map<std::string, std::string> checked_android_boot_pins(const std::filesystem::path &seed,
                                                             const Json &definition,
                                                             const Json &manifest) {
    need(definition.contains("android"), "profile declares no Android base");
    auto pins = portable_clean_boot_pins(definition.at("android"));
    const auto clean = native_clean_base(definition.at("android"));
    const auto &android = manifest.at("android");

    if (clean.vbmeta_digest.empty()) {
        need(!android.contains("vbmeta_digest"), "Android base binds no vbmeta digest");

        return pins;
    }

    // The machine boots its system through its own boot parameters: the stock ones with the
    // vbmeta digest of its system image, which the guest compares at first-stage mount.
    const std::string name = "VerifiedBootParams.textproto";
    const auto digest = android.value("vbmeta_digest", std::string{});
    const auto &descriptor = android.at("boot_files").at(name);
    const auto pin = descriptor.at("sha256").get<std::string>();
    need(sha256_text(digest) && sha256_text(pin) && descriptor.at("file") == "android/" + name,
         "machine vbmeta digest and boot parameters required");
    check_file(seed / "android" / name, pin, 4096);
    const auto parameters = machine_preparation_detail::text(seed / "android" / name, 4096);
    need(android_verified_boot_digest(parameters) == digest,
         "machine boot parameters differ from their vbmeta digest");
    std::string stock = parameters;

    for (auto at = stock.find(digest); at != std::string::npos; at = stock.find(digest, at)) {
        stock.replace(at, digest.size(), clean.vbmeta_digest);
    }

    need(sha256_bytes(stock) == pins.at(name),
         "machine boot parameters differ from the stock ones beyond the vbmeta digest");
    const auto chain = android_vbmeta_chain(raw_disk_reader(seed / "android/system.img"),
                                            android_vbmeta_partitions(definition.at("android")));
    need(chain.digest == digest, "machine vbmeta digest differs from its system image");
    pins[name] = pin;

    return pins;
}

// Cleanup-only observation: independent of expired preparation/cancellation budget.
// All subprocesses share one five-second deadline; failed fences publish no guest bytes.
// NOLINTNEXTLINE(bugprone-exception-escape): only unreachable nlohmann::json invariants escape.
Json capture_android_candidate_failure(ChildProcess &process, const std::filesystem::path &adb,
                                       const std::filesystem::path &stage, unsigned port,
                                       const std::string &avd_name, const std::string &nonce,
                                       const AndroidOwnedAdb *binding,
                                       ChildProcess *server) noexcept {
    Json unavailable = {{"status", "unavailable"},
                        {"reason", "fresh owned diagnostic fences unavailable"},
                        {"maximum_bytes", 512 * 1024},
                        {"maximum_ms", 5000}};

    try {
        const auto deadline = Clock::now() + std::chrono::seconds(5);
        const auto pid = process.pid();
        auto owner = [&] {
            need(pid > 0 && process.pid() == pid && process.alive() &&
                         process.owns_tcp_listener(port) && process.owns_tcp_listener(port + 1),
                 "diagnostic retained owner differs");

            if (binding) {
                need(binding->console == port && server && server->alive() &&
                             server->owns_tcp_listener(binding->server),
                     "diagnostic retained private ADB owner differs");
            }
        };
        auto run = [&](std::vector<std::string> args, int maximum, std::size_t limit) {
            owner();
            const auto left =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                            .count();
            need(left > 0, "diagnostic deadline exhausted");
            args.insert(args.begin(), {"-s", "emulator-" + std::to_string(port)});

            if (binding) {
                need(binding->console == port, "diagnostic ADB binding differs");
                auto prefix = android_owned_adb_prefix(
                        *binding,
                        server && server->alive() && server->owns_tcp_listener(binding->server));
                args.insert(args.begin(), prefix.begin(), prefix.end());
            }

            ProcessSpec command;
            command.executable = adb;
            command.arguments = std::move(args);
            command.directory = stage;
            command.environment = {
                    {"TMPDIR", stage.string()}, {"TMP", stage.string()}, {"TEMP", stage.string()}};

            if (binding) {
                for (const auto &[key, value] : android_owned_adb_sdk_environment(*binding)) {
                    command.environment[key] = value;
                }
            }

            auto result = execute(command, static_cast<int>(std::min<std::int64_t>(maximum, left)),
                                  limit);
            owner();
            need(Clock::now() < deadline && !result.timed_out && result.exit_code == 0,
                 "diagnostic command unavailable");

            return result;
        };
        auto avd = [&] {
            const auto name = lines(run({"emu", "avd", "name"}, 1000, 4096).output);
            need(!name.empty() && name.front() == avd_name, "diagnostic AVD differs");
        };
        avd();
        std::string boot;
        Json supplementary = Json::object();
        std::map<std::string, std::string> captured_text;
        auto collect = [&](const std::string &name, const std::vector<std::string> &command,
                           int maximum, std::size_t limit) {
            supplementary[name] = {
                    {"status", "unavailable"},
                    {"reason",
                     "diagnostic command failed, exceeded its bound, or shared budget exhausted"},
                    {"maximum_bytes", limit}};

            if (std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                        .count() <= 1500) {
                return;
            }

            try {
                const auto frame = random_token();
                const auto captured =
                        run({"shell", windows_startup_command(command, frame, nonce, {}, false)},
                            maximum, limit);
                auto report = android_candidate_failure_log_frame(captured, frame, nonce,
                                                                  {nonce, avd_name});
                const auto current = report.at("boot_id").get<std::string>();

                if (boot.empty()) {
                    boot = current;
                }

                need(current == boot, "supplementary diagnostic boot differs");
                const auto file = "failure-" + name + ".txt";
                captured_text[file] = report.at("text").get<std::string>();
                report.erase("text");
                report["file"] = file;
                report["sha256"] = sha256_bytes(captured_text.at(file));
                report["maximum_bytes"] = limit;
                supplementary[name] = report;
            } catch (...) { /* Ignored: supplementary capture records only available evidence. */
            }
        };
        collect("home-resolve",
                {"cmd", "package", "resolve-activity", "--brief", "--user", "0", "-a",
                 "android.intent.action.MAIN", "-c", "android.intent.category.HOME"},
                500, 64 * 1024);
        collect("home-query",
                {"cmd", "package", "query-activities", "--brief", "--user", "0", "-a",
                 "android.intent.action.MAIN", "-c", "android.intent.category.HOME"},
                500, 64 * 1024);
        collect("package-preferred", {"dumpsys", "package", "preferred"}, 500, 64 * 1024);
        collect("package-preferred-xml",
                {"sed", "-n", "/<preferred-activities>/,/<\\/preferred-activities>/p",
                 "/data/system/users/0/package-restrictions.xml"},
                500, 64 * 1024);
        collect("packages", {"pm", "list", "packages", "--user", "0"}, 500, 64 * 1024);
        collect("focus", {"dumpsys", "activity", "activities"}, 500, 64 * 1024);
        const std::vector<std::string> logcat = {"logcat",
                                                 "-d",
                                                 "-b",
                                                 "main",
                                                 "-b",
                                                 "system",
                                                 "-b",
                                                 "crash",
                                                 "-b",
                                                 "events",
                                                 "-v",
                                                 "threadtime",
                                                 "notification_alert:I",
                                                 "AndroidRuntime:E",
                                                 "PackageManager:I",
                                                 "AppMain:D",
                                                 "linker:W",
                                                 "nativeloader:V",
                                                 "MMKV:V",
                                                 "CertCache:V",
                                                 "QGRuntime:E",
                                                 "System.err:W",
                                                 "*:S"};
        collect("startup-logcat", logcat, 1500, 512 * 1024);

        for (const auto *kind : {"audio", "notification"}) {
            collect(kind, {"dumpsys", kind}, 500, 128 * 1024);
        }

        need(!boot.empty(), "no fenced diagnostic available");
        const auto frame = random_token();
        const auto post =
                run({"shell", windows_startup_command({"true"}, frame, nonce, boot, false)}, 1000,
                    4096);
        const auto verified = parse_windows_startup_frame(post, frame, nonce, boot);
        need(!verified.boot_changed && !verified.result.timed_out &&
                     verified.result.exit_code == 0 && verified.boot_id == boot,
             "diagnostic postfence boot differs");
        avd();
        owner();
        need(Clock::now() < deadline, "diagnostic complete postfence deadline exhausted");

        for (const auto &[name, value] : captured_text) {
            need(!std::filesystem::exists(stage / name), "fresh diagnostic output required");
        }

        for (const auto &[name, value] : captured_text) {
            write(stage / name, value);
        }

        Json result = {{"status", supplementary.at("startup-logcat").at("status") == "captured"
                                          ? "captured"
                                          : "partial"},
                       {"boot_id", boot},
                       {"boot_association", "fresh diagnostic boot; failure boot not inferred"},
                       {"supplementary", supplementary},
                       {"maximum_total_bytes", 1152 * 1024},
                       {"maximum_ms", 5000},
                       {"pid", pid}};

        if (supplementary.at("startup-logcat").at("status") == "captured") {
            result["file"] = "failure-startup-logcat.txt";
            result["sha256"] = sha256_bytes(captured_text.at("failure-startup-logcat.txt"));
        }

        return result;
    } catch (...) {
        return unavailable;
    }
}

// Cleanup sync has its own deadline and never uses a default/global ADB server.
// NOLINTNEXTLINE(bugprone-exception-escape): only unreachable nlohmann::json invariants escape.
Json sync_android_candidate_failure(ChildProcess &process, const std::filesystem::path &adb,
                                    const std::filesystem::path &stage, unsigned port,
                                    const std::string &avd_name, const std::string &nonce,
                                    const AndroidOwnedAdb *binding, ChildProcess *server) noexcept {
    Json report = {{"status", "unavailable"},
                   {"maximum_ms", 10000},
                   {"pid", process.pid()},
                   {"boot_id", nullptr}};

    try {
        const auto deadline = Clock::now() + std::chrono::seconds(10);
        const auto pid = process.pid();
        auto owner = [&] {
            need(pid > 0 && process.pid() == pid && process.alive() &&
                         process.owns_tcp_listener(port) && process.owns_tcp_listener(port + 1),
                 "cleanup sync retained owner differs");
            need(binding && binding->console == port && server && server->alive() &&
                         server->owns_tcp_listener(binding->server),
                 "cleanup sync retained private ADB owner differs");
        };
        auto run = [&](std::vector<std::string> args, int maximum) {
            owner();
            const auto left =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                            .count();
            need(left > 0, "cleanup sync deadline exhausted");
            const auto prefix = android_owned_adb_prefix(*binding, true);
            args.insert(args.begin(), {"-s", "emulator-" + std::to_string(port)});
            args.insert(args.begin(), prefix.begin(), prefix.end());
            ProcessSpec command;
            command.executable = adb;
            command.arguments = std::move(args);
            command.directory = stage;
            command.environment = android_owned_adb_sdk_environment(*binding);
            command.environment["TMPDIR"] = stage.string();
            command.environment["TMP"] = stage.string();
            command.environment["TEMP"] = stage.string();
            auto result = execute(command, static_cast<int>(std::min<std::int64_t>(maximum, left)),
                                  16384);
            owner();
            need(Clock::now() < deadline && !result.timed_out && result.exit_code == 0,
                 "cleanup sync command unavailable");

            return result;
        };
        auto avd = [&] {
            const auto name = lines(run({"emu", "avd", "name"}, 1000).output);
            need(!name.empty() && name.front() == avd_name, "cleanup sync AVD differs");
        };
        auto framed = [&](const char *action, const std::string &boot, bool mutation, int maximum) {
            const auto frame = random_token();
            const auto captured =
                    run({"shell", windows_startup_command({action}, frame, nonce, boot, mutation)},
                        maximum);
            const auto parsed = parse_windows_startup_frame(captured, frame, nonce, boot);
            need(!parsed.boot_changed && !parsed.result.timed_out && parsed.result.exit_code == 0,
                 "cleanup sync guest fence differs");

            return parsed.boot_id;
        };
        avd();
        const auto boot = framed("true", {}, false, 1000);
        report["boot_id"] = boot;
        // Leave time for fresh boot/nonce, AVD and host ownership post-fences.
        const auto left =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                        .count();
        need(left > 2000, "cleanup sync postfence budget missing");
        framed("sync", boot, true, static_cast<int>(left - 2000));
        framed("true", boot, false, 1000);
        avd();
        owner();
        need(Clock::now() < deadline, "cleanup sync postfence deadline exhausted");
        report["status"] = "synced";
    } catch (...) { /* Ignored: the report keeps the last reached cleanup status. */
    }

    return report;
}

void android_candidate_start_multidisplay(ChildProcess &child, const std::filesystem::path &adb,
                                          const std::filesystem::path &stage, unsigned port,
                                          int remaining_ms, const AndroidOwnedAdb *binding,
                                          ChildProcess *server) {
    need(remaining_ms > 0 && remaining_ms <= 30000,
         "SDK broadcast remaining budget must be in1..30000ms");
    need(child.alive() && child.owns_tcp_listener(port) && child.owns_tcp_listener(port + 1),
         "retained SDK broadcast owner/listeners required");
    ordinary(adb);
    ordinary(stage);
    need(std::filesystem::is_regular_file(adb) && std::filesystem::is_directory(stage),
         "SDK broadcast host paths required");
    ProcessSpec command;
    command.executable = adb;
    command.directory = stage;
    command.arguments = {
            "-s", "emulator-" + std::to_string(port), "shell",
            shell_line({"am", "broadcast", "--receiver-foreground", "--user", "0", "-a",
                        "com.android.emulator.multidisplay.START", "-n",
                        "com.android.emulator.multidisplay/.MultiDisplayServiceReceiver"})};
    command.environment = {
            {"TMPDIR", stage.string()}, {"TMP", stage.string()}, {"TEMP", stage.string()}};

    if (binding) {
        need(binding->console == port, "broadcast ADB binding differs");
        auto prefix = android_owned_adb_prefix(
                *binding, server && server->alive() && server->owns_tcp_listener(binding->server));
        command.arguments.insert(command.arguments.begin(), prefix.begin(), prefix.end());

        for (const auto &[key, value] : android_owned_adb_sdk_environment(*binding)) {
            command.environment[key] = value;
        }
    }

    const auto result = execute(command, remaining_ms, 65536);

    if (binding) {
        need(server && server->alive() && server->owns_tcp_listener(binding->server),
             "broadcast private ADB owner changed");
    }

    need(child.alive() && child.owns_tcp_listener(port) && child.owns_tcp_listener(port + 1),
         "retained SDK broadcast owner changed");
    need(!result.timed_out && result.exit_code == 0,
         "SDK startup broadcast failed: timed_out=" + std::to_string(result.timed_out) +
                 " exit=" + std::to_string(result.exit_code));
    const auto rows = lines(result.output);
    need(std::count(rows.begin(), rows.end(), "Broadcast completed: result=0") == 1,
         "SDK startup broadcast completion ACK missing");
}

Json android_candidate_failure_log_frame(const ProcessResult &captured, std::string_view frame,
                                         std::string_view nonce,
                                         const std::vector<std::string> &secrets) {
    const auto parsed = parse_windows_startup_frame(captured, frame, nonce, {});

    need(!parsed.boot_changed && !parsed.result.timed_out && parsed.result.exit_code == 0,
         "complete diagnostic boot/nonce frame required");
    const auto text = redact_diagnostic_text(parsed.result.output, secrets);
    need(text.size() <= 512 * 1024, "bounded diagnostic text required");

    return {{"status", "captured"},
            {"boot_id", parsed.boot_id},
            {"boot_association", "fresh log-read boot; failure boot not inferred"},
            {"redacted", true},
            {"maximum_bytes", 512 * 1024},
            {"text", text}};
}

std::uint64_t checked_add(std::uint64_t a, std::uint64_t b) {
    need(a <= std::numeric_limits<std::uint64_t>::max() - b,
         "checked disk budget addition overflow");

    return a + b;
}

static std::uint64_t candidate_scratch_growth_limit(const Json &profile) {
    if (!record_declares(profile, ProfilePlatform::passion, ProfileBoard::sa8155)) {
        return 0;
    }

    // The API30 x86_64 super has only 1630 MiB free after the original aligned extents.
    return native_base_identity(profile.at("android")).abi == "x86_64" ? lp_scratch_max_growth
                                                                       : lp_scratch_growth_limit;
}

std::uint64_t android_candidate_peak_extra_bytes(const Json &profile, std::uint64_t base_bytes,
                                                 std::uint64_t payload_bytes,
                                                 std::string_view requested_profile) {
    if (!requested_profile.empty() &&
        embedded_profile_declares(runtime_profile_reference(profile, requested_profile),
                                  ProfilePlatform::qinggan09, ProfileBoard::sa8155)) {
        (void)android_candidate_reserve_bytes(profile, requested_profile);
        need(base_bytes > 0 && base_bytes <= 4ULL << 30 && payload_bytes <= 2ULL << 30,
             "bounded A9 base/payload extents required");
        // The A9 builder expands userdata to 6GiB. Both the system payload in
        // the writable overlay and its RAW export coexist, plus a 2GiB
        // working allowance for ART, qcow metadata, cache and diagnostics.
        const auto normal =
                checked_add(checked_add(base_bytes, 6ULL << 30),
                            checked_add(checked_add(payload_bytes, payload_bytes), 2ULL << 30));

        if (!profile.at("android").contains("offline_selinux_labels")) {
            return normal;
        }

        // The labelled RAW replaces the private base. Account for a fully
        // allocated 4GiB promoted base even when the initial base was a clone;
        // it remains alive during final export. There is no standalone QCOW copy.
        const auto final_peak = checked_add(normal, 4ULL << 30);
        const auto label_peak =
                checked_add(checked_add(6ULL << 30, checked_add(payload_bytes, payload_bytes)),
                            (2ULL << 30) + (4ULL << 30) + (512ULL << 20));

        return std::max(final_peak, label_peak);
    }

    // Measured Passion API30 guest growth across install/reboot/art/export: 2GiB.
    constexpr std::uint64_t guest_growth = 2ULL << 30;
    need(base_bytes <= 4ULL << 30 && payload_bytes <= 2ULL << 30,
         "bounded base/payload extents required");
    const auto scratch = android_candidate_overlay_scratch_bytes(profile, payload_bytes);
    // Peak concurrent extras beyond the copied base: the in-place scratch preseed
    // plus the RAW re-export of the grown guest images (installed payload plus
    // measured guest growth) written while base copy and scratch remain on disk.
    const auto export_raw = checked_add(checked_add(base_bytes, payload_bytes), guest_growth);

    // Include the extended base and the raw export at the same time.
    const auto growth = scratch ? 2 * candidate_scratch_growth_limit(profile) : 0;

    return checked_add(checked_add(scratch, export_raw), growth);
}

std::uint64_t android_candidate_reserve_bytes(const Json &profile,
                                              std::string_view requested_profile) {
    need(requested_profile.empty() || !profile.contains("id") ||
                 profile.at("id") == requested_profile,
         "requested profile identity differs");

    // A profile with the measured_disk_reserve feature has its budget only for the image package,
    // labels and OEM system image it was measured on, and only as its own reference.
    if (profile_feature(profile, "measured_disk_reserve")) {
        const auto android = profile.value("android", Json::object()),
                   acquisition = profile.value("acquisition", Json::object());
        const auto images = acquisition.value("images", Json::object()),
                   system = images.value("system", Json::object());
        const bool exact =
                runtime_profile_reference(profile, requested_profile) ==
                        profile.value("id", std::string(requested_profile)) &&
                record_declares(profile, ProfilePlatform::qinggan11, ProfileBoard::sa8155) &&
                android.value("package", std::string{}) ==
                        "system-images;android-30;default;arm64-v8a" &&
                android.value("offline_selinux_labels", std::string{}) ==
                        "qinggan11-can-early-v1" &&
                system.value("sha256", std::string{}) ==
                        "ee0c8241b7293b9cd9f936f622c556ac11ab3f92a0f60733e92dca1c1610f5c4";

        return exact ? 8ULL << 30 : 20ULL << 30;
    }

    if (!requested_profile.empty() &&
        embedded_profile_declares(runtime_profile_reference(profile, requested_profile),
                                  ProfilePlatform::qinggan09, ProfileBoard::sa8155)) {
        need(!profile.contains("id") || profile.at("id") == requested_profile,
             "requested A9 identity differs");
        const auto &android = profile.at("android");
        need(native_base_api(android) == 28,
             "exact A9 API28 base required for measured disk budget");

        return 8ULL << 30;
    }

    // The NXP, qinggan11 and Passion candidates have a measured disk budget.
    const bool nxp = record_declares(profile, ProfilePlatform::qinggan09, ProfileBoard::nxp);

    if (!nxp && !record_declares(profile, ProfilePlatform::qinggan11, ProfileBoard::sa8155) &&
        !record_declares(profile, ProfilePlatform::passion, ProfileBoard::sa8155)) {
        return 20ULL << 30;
    }

    const auto &android = profile.at("android");

    if (nxp) {
        need(native_base_api(android) == 28,
             "exact NXP API28 base required for measured disk budget");
    } else {
        need(native_base_api(android) == 30,
             "exact registered API30 base required for measured disk budget");
    }

    return 8ULL << 30;
}

AndroidCandidateBudget android_candidate_build_budget(const Json &profile, std::uint64_t base_bytes,
                                                      std::uint64_t payload_bytes,
                                                      std::string_view requested_profile) {
    const auto reserve = android_candidate_reserve_bytes(profile, requested_profile);

    return {reserve, (reserve == 8ULL << 30 || profile_feature(profile, "measured_disk_reserve"))
                             ? android_candidate_peak_extra_bytes(profile, base_bytes,
                                                                  payload_bytes, requested_profile)
                             : 12ULL << 30};
}

void prepare_android_candidate_base(const std::filesystem::path &source, const Json &files,
                                    const std::filesystem::path &destination, std::uint64_t reserve,
                                    std::uint64_t peak_extra,
                                    std::function<std::uint64_t()> available,
                                    const std::filesystem::path &development_kernel,
                                    const std::string &development_sha) {
    ordinary(source);
    ordinary(destination);
    need(development_kernel.empty() == development_sha.empty(),
         "paired development kernel input required");

    if (!development_kernel.empty()) {
        need(files.contains("kernel-ranchu"), "clean base kernel role required");
        check_file(development_kernel, development_sha, 64ULL << 20);
    }

    need(files.is_object() && !files.empty() && files.size() <= 64,
         "bounded clean base files required");
    need(!std::filesystem::exists(destination) && !std::filesystem::is_symlink(destination),
         "fresh candidate base destination required");
    const auto space = [&] {
        return available ? available()
                         : std::filesystem::space(destination.parent_path()).available;
    };

    // Short space fails with the disk space error that names the installation root.
    const auto require_space = [&](std::uint64_t required) {
        if (const auto free = space(); free < required) {
            throw disk_space_error("MACHINE_PREPARATION", installation_root_of(destination), free,
                                   required);
        }
    };

    for (auto it = files.begin(); it != files.end(); ++it) {
        relative(it.key());
    }

    need(reserve <= std::numeric_limits<std::uint64_t>::max() - (16ULL << 30),
         "disk reserve before private base copy");
    require_space(reserve);
    ensure_private_directory(destination.parent_path());
    need(std::filesystem::create_directory(destination), "exclusive candidate directory");
    try {
        ensure_private_directory(destination);
        const auto base = destination / "machine/base";
        ensure_private_directory(base);

        for (auto it = files.begin(); it != files.end(); ++it) {
            const bool selected = !development_kernel.empty() && it.key() == "kernel-ranchu";
            const auto input = selected ? development_kernel : source / it.key(),
                       target = base / it.key();
            const auto expected = selected ? development_sha
                                           : it.value().at("sha256").get<std::string>();
            ensure_private_directory(target.parent_path());
            // An injected measurement stands for the disk in every reserve check, so the copy
            // itself checks the real disk only when none is injected.
            copy_portable_image(input, expected, target, available ? 0 : reserve);
            check_file(target, expected);
            require_space(reserve);
        }

        need(peak_extra <= std::numeric_limits<std::uint64_t>::max() - reserve,
             "disk reserve for candidate/export after clean base copy");
        require_space(checked_add(reserve, peak_extra));
    } catch (...) {
        std::filesystem::remove_all(destination);
        throw;
    }
}

Json export_android_candidate_owned_package(const Json &profile, const Json &artifacts,
                                            const Json &installed,
                                            const std::filesystem::path &destination,
                                            std::uint64_t reserve) {
    if (!qinggan11_wheel_provider(profile)) {
        return Json::object();
    }

    const Json install = {{"artifact", "component:wheel-input"}, {"type", "apk"}};
    const auto entries = profile.at("install");
    need(std::count(entries.begin(), entries.end(), install) == 1,
         "exact owned provider APK install required");
    const auto &artifact = artifacts.at("component:wheel-input");
    need(artifact.is_object() && artifact.size() == 3,
         "owned provider artifact descriptor required");
    const std::filesystem::path source = artifact.at("file").get<std::string>();
    const auto sha = artifact.at("sha256").get<std::string>();
    check_file(source, sha, 16ULL << 20);
    need(artifact.at("bytes") == std::filesystem::file_size(source),
         "owned provider APK extent differs");
    unsigned matches = 0;

    for (const auto &item : installed) {
        if (item.at("artifact") == "component:wheel-input") {
            need(item.at("package") == "com.voyemu.input.wheel" && item.at("sha256") == sha &&
                         item.at("target").get<std::string>().starts_with("/data/app/") &&
                         !item.at("mutable").get<bool>(),
                 "cold installed owned provider differs");
            ++matches;
        }
    }

    need(matches == 1, "one cold-verified owned provider required");
    Json descriptor = {{"package", "com.voyemu.input.wheel"},
                       {"file", "android/packages/" + sha + ".apk"},
                       {"sha256", sha},
                       {"bytes", std::filesystem::file_size(source)}};
    android_owned_package_descriptor(descriptor, true);
    const auto target = destination / descriptor.at("file").get<std::string>();
    ensure_private_directory(target.parent_path());
    copy_portable_image(source, sha, target, reserve);
    check_file(target, sha, 16ULL << 20);

    return descriptor;
}

Json export_android_candidate_camera_package(const Json &profile, const Json &artifacts,
                                             const Json &installed,
                                             const std::filesystem::path &destination,
                                             std::uint64_t reserve) {
    if (!qinggan11_package_delivery(profile)) {
        return Json::object();
    }

    const auto &artifact = artifacts.at("patched:Camera");
    need(artifact.is_object() && artifact.size() == 3,
         "prepared Camera artifact descriptor required");
    const std::filesystem::path source = artifact.at("file").get<std::string>();
    const auto sha = artifact.at("sha256").get<std::string>();
    check_file(source, sha, 128ULL << 20);
    need(artifact.at("bytes") == std::filesystem::file_size(source), "Camera APK extent differs");
    unsigned matches = 0;

    for (const auto &item : installed) {
        if (item.at("artifact") == "patched:Camera") {
            need(item.at("package") == "com.qinggan.camera" && item.at("sha256") == sha &&
                         item.at("target").get<std::string>().starts_with("/data/app/") &&
                         !item.at("mutable").get<bool>(),
                 "cold installed Camera differs");
            ++matches;
        }
    }

    need(matches == 1, "one cold-verified Camera required");
    Json descriptor = {{"package", "com.qinggan.camera"},
                       {"file", "android/packages/" + sha + ".apk"},
                       {"sha256", sha},
                       {"bytes", std::filesystem::file_size(source)}};
    android_camera_package_descriptor(descriptor, true);
    const auto target = destination / descriptor.at("file").get<std::string>();
    ensure_private_directory(target.parent_path());
    copy_portable_image(source, sha, target, reserve);
    check_file(target, sha, 128ULL << 20);

    return descriptor;
}

static Json export_android_candidate_prepared_packages(const Json &profile, const Json &artifacts,
                                                       const Json &installed,
                                                       const std::filesystem::path &destination,
                                                       std::uint64_t reserve) {
    if (!qinggan11_package_delivery(profile)) {
        return Json::array();
    }

    auto camera = export_android_candidate_camera_package(profile, artifacts, installed,
                                                          destination, reserve);

    if (!profile.at("patches").contains("Navi")) {
        // A profile without a Navi patch exports only its Camera.
        auto packages = Json::array({camera});
        android_prepared_packages_descriptor(packages, true);

        return packages;
    }

    const auto &artifact = artifacts.at("patched:Navi");
    need(artifact.is_object() && artifact.size() == 3,
         "prepared Navi artifact descriptor required");
    const std::filesystem::path source = artifact.at("file").get<std::string>();
    const auto sha = artifact.at("sha256").get<std::string>();
    check_file(source, sha, 512ULL << 20);
    need(artifact.at("bytes") == std::filesystem::file_size(source), "Navi APK extent differs");
    unsigned matches = 0;

    for (const auto &item : installed) {
        if (item.at("artifact") == "patched:Navi") {
            need(item.at("package") == "com.baidu.naviauto" && item.at("sha256") == sha &&
                         item.at("target").get<std::string>().starts_with("/data/app/") &&
                         !item.at("mutable").get<bool>(),
                 "cold installed Navi differs");
            ++matches;
        }
    }

    need(matches == 1, "one cold-verified Navi required");
    Json navi = {{"package", "com.baidu.naviauto"},
                 {"file", "android/packages/" + sha + ".apk"},
                 {"sha256", sha},
                 {"bytes", std::filesystem::file_size(source)}};
    auto packages = Json::array({camera, navi});
    android_prepared_packages_descriptor(packages, true);
    const auto target = destination / navi.at("file").get<std::string>();
    ensure_private_directory(target.parent_path());
    copy_portable_image(source, sha, target, reserve);
    check_file(target, sha, 512ULL << 20);

    return packages;
}

// Includes: qinggan09_owned_packages.hpp, apk_base.hpp. Insert beside existing Free exporter.
static Json export_android_candidate_qinggan09_packages(const std::filesystem::path &root,
                                                        const AndroidCandidateRequest &request,
                                                        const Json &installed,
                                                        const std::filesystem::path &destination,
                                                        std::uint64_t reserve) {
    const auto definition = authoring_profile(root, request.profile, request.target);

    if (!embedded_profile_declares(runtime_profile_reference(definition, request.profile),
                                   ProfilePlatform::qinggan09, ProfileBoard::sa8155)) {
        return Json::object();
    }

    const auto revision = current_profile_revision(root, request.profile);
    const auto bytes = text(request.artifact_result, 16ULL << 20);
    need(sha256_bytes(bytes) == request.artifact_result_sha256, "A9 full artifact receipt changed");
    const auto result = Json::parse(bytes);
    std::array<std::string, 3> certificates;

    for (std::size_t i = 0; i < certificates.size(); ++i) {
        const auto &artifact = result.at("artifacts")
                                       .at(i == 2 ? "component:canbus"
                                           : i    ? "component:bootstrap"
                                                  : "component:audiopolicy");
        const std::filesystem::path file = artifact.at("file").get<std::string>();
        need(inside(file, root / ".local"), "A9 own artifact outside production data");
        artifact_files(artifact);
        certificates[i] = sha256_bytes(
                pinned_apk_v2_certificate(file, artifact.at("sha256").get<std::string>()));
    }

    auto descriptor = qinggan09_owned_packages_artifacts_candidate(bytes, installed, certificates,
                                                                   request.profile);
    const auto payloads = qinggan09_owned_packages_payloads(descriptor);

    for (std::size_t i = 0; i < payloads.size(); ++i) {
        auto package = payloads.at(i);
        const std::filesystem::path source = package.at("file").get<std::string>();
        const auto sha = package.at("sha256").get<std::string>();
        const auto relative = "android/packages/" + sha + ".apk";
        const auto target = destination / relative;
        ensure_private_directory(target.parent_path());
        copy_portable_image(source, sha, target, reserve);
        check_file(target, sha, 16ULL << 20);
        need(std::filesystem::file_size(target) == package.at("bytes"),
             "A9 exported APK extent differs");
        package["file"] = relative;
        qinggan09_owned_packages_set_payload(descriptor, i, package);
    }

    need(current_profile_revision(root, request.profile) == revision &&
                 sha256_file(request.artifact_result) == request.artifact_result_sha256,
         "A9 full producer source closure changed during export");
    qinggan09_owned_packages_descriptor(descriptor, true);

    return descriptor;
}

void validate_android_candidate_artifacts(const std::filesystem::path &root,
                                          const AndroidCandidateRequest &request,
                                          const Json &result) {
    JavaPreparationRequest producer;

    producer.profile = request.profile;
    producer.target = request.target;
    producer.profile_sha256 = request.profile_sha256;
    producer.operation = JavaPreparationOperation::build_artifacts;
    validate_java_preparation_response(root, producer, result);
    const auto profile = authoring_profile(root, request.profile, request.target);

    for (const auto &entry : profile.at("install")) {
        if (entry.at("type") != "directory") {
            artifact_files(result.at("artifacts").at(entry.at("artifact").get<std::string>()));
        }
    }
}

Json build_android_candidate(const std::filesystem::path &root,
                             const AndroidCandidateRequest &request,
                             const std::filesystem::path &destination, std::uint64_t reserve,
                             std::uint64_t peak_extra) {
    (void)peak_extra;
    ordinary(root);
    ordinary(destination);
    ordinary(request.sdk);
    ordinary(request.clean_base);
    need(std::filesystem::is_directory(root) && valid_profile_name(request.profile) &&
                 inside(destination, root / ".local") && destination != root / ".local" &&
                 !std::filesystem::exists(destination),
         "fresh owned candidate destination required");
    need(inside(request.sdk, root / ".local") && inside(request.clean_base, root / ".local"),
         "owned SDK/clean base required");
    need(request.port >= 5554 && request.port <= 5682 && request.port % 2 == 0 &&
                 request.port != 5562 && request.overall_timeout_ms >= 1000 &&
                 request.overall_timeout_ms <= 3600000,
         "isolated port/bounded deadlines required");
    need(tcp_port_free(request.port) && tcp_port_free(request.port + 1),
         "candidate ports occupied; peer untouched");
    const auto profile_bytes = authoring_profile_bytes(root, request.profile, request.target);
    need(sha256_bytes(profile_bytes) == request.profile_sha256,
         "authoring profile changed while reading candidate inputs");
    const auto profile = portable_profile_json(profile_bytes);

    if (original_navi_requested(profile)) {
        original_navi_preflight(profile, android_candidate_api(profile));
    }

    android_candidate_api(profile);
    android_candidate_cpu_config(profile);
    android_candidate_start_commands(profile);
    android_candidate_vehicle_observer_policy(profile);
    android_candidate_capture_arguments(profile, request.capture_frames, request.port);

    if (request.capture_frames) {
        need(tcp_port_free(request.port + 30000),
             "candidate SDK capture port occupied; foreign listener untouched");
    }

    android_candidate_boot_cache_paths(profile);
    android_candidate_system_server_commands(profile);
    check_file(request.artifact_result, request.artifact_result_sha256, 16 << 20);
    const auto result = read_private_json(request.artifact_result, 16 << 20);
    need(result.at("schema") == 1 && result.at("profile") == request.profile &&
                 result.value("artifacts_built", false) && result.contains("artifacts") &&
                 result.at("guest_started") == false && result.at("machine_ready") == false,
         "actual Java artifact result required");
    const auto &artifacts = result.at("artifacts");
    need(profile.at("emulator").value("memory", 4096) >= 512 &&
                 profile.at("emulator").value("memory", 4096) <= 16384,
         "candidate RAM bound");
    const auto plan = android_candidate_install_plan(profile, artifacts);
    const auto [early_data, late_data] = data_install_phases(plan.at("data"));
    validate_android_candidate_artifacts(root, request, result);

    if (original_navi_requested(profile)) {
        const auto &source = artifacts.at("original:Navi");
        need(source.at("sha256") == original_navi_sha && source.at("bytes") == 226402144,
             "exact original Navi source required");
        const std::filesystem::path apk = source.at("file").get<std::string>();
        check_file(apk, std::string(original_navi_sha), 512ULL << 20);
        need(sha256_bytes(pinned_apk_v2_certificate(apk, std::string(original_navi_sha))) ==
                     original_navi_cert,
             "original Navi signer differs");
    }

    check_file(request.clean_base / "base.json", request.clean_receipt_sha256, 128 * 1024);
    const auto clean = read_private_json(request.clean_base / "base.json");
    need(clean.at("schema") == 1 && clean.value("native", false) &&
                 clean.at("prepared_VM") == false &&
                 clean.at("archive_sha256") == profile.at("android").at("sha256") &&
                 clean.at("package") == profile.at("android").at("package") &&
                 clean.at("revision") == profile.at("android").at("revision") &&
                 clean.at("files").is_object() && clean.at("files").size() <= 64,
         "clean native dependency receipt required");
    std::uint64_t base_bytes = 0;
    std::set<std::string> clean_files;

    for (auto it = clean.at("files").begin(); it != clean.at("files").end(); ++it) {
        relative(it.key());
        check_file(request.clean_base / it.key(), it.value().at("sha256").get<std::string>());
        need(it.value().at("bytes") == std::filesystem::file_size(request.clean_base / it.key()),
             "clean base extent differs");
        base_bytes += std::filesystem::file_size(request.clean_base / it.key());
        need(base_bytes <= 4ULL << 30, "clean base byte bound");
        clean_files.insert(it.key());
    }

    std::set<std::string> actual;

    for (const auto &e : std::filesystem::recursive_directory_iterator(request.clean_base)) {
        need(!e.is_symlink() && (e.is_directory() || e.is_regular_file()),
             "ordinary clean base tree");

        if (e.is_regular_file() && e.path().filename() != "base.json") {
            actual.insert(e.path().lexically_relative(request.clean_base).generic_string());
        }
    }

    need(actual == clean_files, "clean base inventory differs");
    const auto abi = native_base_identity(profile.at("android")).abi;
    const bool x86 = abi == "x86_64";
    const std::string exe(os::executable_suffix), host(os::emulator_host);
    const auto emulator = request.sdk / ("emulator/emulator" + exe),
               adb = request.sdk / ("platform-tools/adb" + exe),
               aapt2 = request.sdk / ("build-tools/36.1.0/aapt2" + exe),
               qemu_img = request.sdk / ("emulator/qemu-img" + exe),
               backend = request.sdk / "emulator/qemu" / host /
                         ("qemu-system-" + std::string(android_qemu_arch(abi)) + exe);

    for (const auto &file : {emulator, adb, aapt2, qemu_img, backend}) {
        tool(request, file);
    }

    if (x86) {
        tool(request, android_sdk_headless_engine(backend.parent_path()));
    }

    Candidate candidate(root, destination, request.sdk, adb,
                        android_sdk_program(request.sdk, !exe.empty(), abi), qemu_img, request.port,
                        request.overall_timeout_ms, request.cancelled, request.capture_frames);
    std::uint64_t base_bytes_total = 0;

    for (auto it = clean.at("files").begin(); it != clean.at("files").end(); ++it) {
        base_bytes_total = checked_add(
                base_bytes_total, clean.at("files").at(it.key()).at("bytes").get<std::uint64_t>());
    }

    std::uint64_t system_payload = 0;

    for (const auto &entry : plan.at("system")) {
        if (entry.at("type") == "directory") {
            continue;
        }

        const auto &artifact = artifacts.at(entry.at("artifact").get<std::string>());

        if (artifact.contains("file")) {
            system_payload =
                    checked_add(system_payload,
                                std::filesystem::file_size(artifact.at("file").get<std::string>()));
        } else {
            for (auto item = artifact.at("files").begin(); item != artifact.at("files").end();
                 ++item) {
                system_payload = checked_add(
                        system_payload,
                        std::filesystem::file_size(
                                std::filesystem::path(artifact.at("directory").get<std::string>()) /
                                item.key()));
            }
        }
    }

    // The Native Bridge files live in the same system overlay.
    if (!request.native_bridge.empty()) {
        for (const auto &[path, pin] : request.native_bridge_descriptor.at("files").items()) {
            (void)pin;
            system_payload =
                    checked_add(system_payload,
                                std::filesystem::file_size(request.native_bridge / path.substr(1)));
        }
    }

    const auto peak_extra_total = android_candidate_peak_extra_bytes(
            profile, base_bytes_total, system_payload, request.profile);
    need(peak_extra >= peak_extra_total,
         "peak_extra below the measured remaining-write peak; callers may raise it, never lower");
    const auto development = portable_development_kernel(profile);
    const auto development_file = development.is_null()
                                          ? std::filesystem::path{}
                                          : portable_development_kernel_file(root, development);
    const auto development_sha =
            development.is_null() ? std::string{} : development.at("sha256").get<std::string>();
    prepare_android_candidate_base(request.clean_base, clean.at("files"), destination, reserve,
                                   peak_extra, {}, development_file, development_sha);
    const auto clean_base = native_clean_base(profile.at("android"));

    // The stock system image and boot parameters must declare the same vbmeta chain.
    if (!clean_base.vbmeta_digest.empty()) {
        const auto parameters = candidate.machine / "base/VerifiedBootParams.textproto";
        candidate.stock_boot_parameters = text(parameters, 4096);
        candidate.stock_vbmeta_digest = clean_base.vbmeta_digest;
        candidate.vbmeta_partitions = android_vbmeta_partitions(profile.at("android"));
        const auto stock =
                android_vbmeta_chain(raw_disk_reader(candidate.machine / "base/system.img"),
                                     candidate.vbmeta_partitions);
        need(stock.digest == clean_base.vbmeta_digest &&
                     android_verified_boot_digest(candidate.stock_boot_parameters) == stock.digest,
             "stock vbmeta chain differs from the Android base pin");
        candidate.vbmeta_digest = stock.digest;
    }

    const auto owner = random_token();
    write_private_json(
            destination / ".owner.json",
            {{"kind", "android-candidate"}, {"token", owner}, {"profile", request.profile}});
    Json checks = Json::array();
    std::string verification_boot_id;
    unsigned verification_boots = 0;
    try {
        const auto scratch_bytes = android_candidate_overlay_scratch_bytes(profile, system_payload);

        if (scratch_bytes) {
            const auto source_pin =
                    clean.at("files").at("system.img").at("sha256").get<std::string>();
            need(source_pin == native_base_pin(profile.at("android"), "images", "system.img"),
                 "exact API30 clean dynamic SDK image required");
            const auto growth_limit = candidate_scratch_growth_limit(profile);
            const auto placement = growth_limit ? LpScratchPlacement::grow_terminal_super
                                                : LpScratchPlacement::within_super;
            auto scratch = seed_lp_overlay_scratch(candidate.machine / "base/system.img",
                                                   source_pin, scratch_bytes, placement,
                                                   growth_limit);

            if (android_candidate_api30_root_layout(profile)) {
                prepare_api30_root_layout(candidate, profile,
                                          scratch.at("image_sha256").get<std::string>(), reserve);
            }

            scratch["system_install_payload_bytes"] = system_payload;
            scratch["directory_headroom_bytes"] = 384ULL << 20;
            scratch["f2fs_reserve_fraction"] = "1/5";
            write_private_json(destination / "scratch-capacity.json", scratch);
            candidate.events.push_back({{"phase", "fresh-overlay-scratch-preseed"},
                                        {"bytes", scratch_bytes},
                                        {"payload_bytes", system_payload},
                                        {"metadata_copies", scratch.at("metadata_copies")},
                                        {"original_payloads_unchanged", true}});
        }

        base_features(candidate.machine / "base/advancedFeatures.ini",
                      profile.at("android").value("features", Json::object()));

        write(candidate.machine / "config.ini",
              avd_config(profile, candidate.machine / "base", "voyemu-candidate"));
        candidate.boot(profile);
        candidate.phase("system-install");
        std::vector<Installed> installed;

        if (!plan.at("system").empty() || !request.native_bridge.empty()) {
            candidate.writable();

            if (!request.native_bridge.empty()) {
                candidate.phase("native-bridge");
                install_native_bridge(candidate,
                                      {request.native_bridge_descriptor, request.native_bridge},
                                      installed);
            }

            // The system image grows by the bytes of the system entries.
            std::optional<progress::Meter> building;

            if (system_payload) {
                progress::block();
                building.emplace("build_system", progress::Arguments{});
                building->length(system_payload);
            }

            install_entries(candidate, plan.at("system"), artifacts, aapt2, installed,
                            building ? &*building : nullptr);

            if (building) {
                building->finish("");
            }

            const auto stale_boot = android_candidate_boot_cache_paths(profile);

            if (!stale_boot.empty()) {
                const bool api30_boot = android_candidate_api(profile) == 30;
                auto verify_boot_inputs = [&] {
                    if (!api30_boot) {
                        return;
                    }

                    need(candidate.shell({"getprop", "ro.zygote"}) ==
                                         (x86 ? "zygote64_32" : "zygote64") &&
                                 candidate.shell({"getprop", "ro.product.cpu.abilist"}) ==
                                         (x86 ? "x86_64,x86" : "arm64-v8a") &&
                                 candidate.shell({"printenv", "DEX2OATBOOTCLASSPATH"}) ==
                                         api30_framework_boot::classpath(),
                         "pinned API30 boot classpath and ABI list required");
                };
                verify_boot_inputs();
                std::vector<std::string> remove = {"rm", "-f"};
                remove.insert(remove.end(), stale_boot.begin(), stale_boot.end());
                candidate.shell(remove);
                candidate.shell({"rm", "-rf",
                                 x86 ? "/data/dalvik-cache/x86" : "/data/dalvik-cache/arm",
                                 x86 ? "/data/dalvik-cache/x86_64" : "/data/dalvik-cache/arm64"});
                candidate.events.push_back({{"phase", "boot-art-invalidated"},
                                            {"system_paths", stale_boot.size()},
                                            {"scope", "owned candidate only"}});
                const auto instruction_sets =
                        api30_boot ? api30_framework_boot::instruction_sets(profile)
                                   : std::vector<std::string>{"arm64"};

                for (const auto &isa : instruction_sets) {
                    const auto command = api30_boot ? api30_framework_boot::command(profile, isa)
                                                    : android_candidate_boot_image_command(profile);
                    candidate.phase("boot-image-compile");
                    write_private_json(candidate.stage / (isa == "x86"
                                                                  ? "boot-image-command-x86.json"
                                                                  : "boot-image-command.json"),
                                       {{"command", command},
                                        {"api", android_candidate_api(profile)},
                                        {"boot", candidate.boots}});
                    candidate.shell(api30_boot ? android_candidate_boot_compile_diagnostic_command(
                                                         profile, candidate.token, isa)
                                               : command,
                                    300000);
                    std::size_t compiled = 0;

                    for (const auto &target : stale_boot) {
                        if (target.starts_with("/system/framework/" + isa + "/") &&
                            !target.ends_with(".art.rel")) {
                            candidate.shell({"test", "-s", target});
                            candidate.shell({"chmod", "0644", target});
                            candidate.shell({"chown", "0:0", target});
                            candidate.shell({"restorecon", target});
                            const auto digest =
                                    candidate.shell({"sha256sum", target}).substr(0, 64);
                            need(std::regex_match(digest, std::regex("[0-9a-f]{64}")),
                                 "compiled boot image hash required");
                            installed.push_back(
                                    {"compiled-boot-image", target, digest, {}, "0644", false});
                            ++compiled;
                        }
                    }

                    need(compiled == (api30_boot ? 18u : 45u),
                         "complete compiled boot image family required");
                    verify_boot_inputs();
                    candidate.events.push_back(
                            {{"phase", "boot-art-compiled"},
                             {"files", compiled},
                             {"command", command},
                             {"log_sha256", sha256_file(candidate.stage /
                                                        android_candidate_command_log(command))}});
                }

                const auto relocation = android_candidate_boot_relocation_command(profile);

                if (!relocation.empty()) {
                    candidate.phase("boot-image-relocation");
                    candidate.shell({"test", "!", "-e", "/system/framework/arm64/dalvik-cache"});
                    candidate.shell(relocation, 300000);
                    std::size_t relocated = 0;

                    for (const auto &target : stale_boot) {
                        if (target.starts_with("/system/framework/arm64/") &&
                            target.ends_with(".art.rel")) {
                            candidate.shell({"test", "-s", target});
                            candidate.shell({"chmod", "0644", target});
                            candidate.shell({"chown", "0:0", target});
                            candidate.shell({"restorecon", target});
                            const auto digest =
                                               candidate.shell({"sha256sum", target}).substr(0, 64),
                                       image_digest =
                                               candidate
                                                       .shell({"sha256sum",
                                                               target.substr(0, target.size() - 4)})
                                                       .substr(0, 64);
                            auto embedded = candidate.shell({"od", "-An", "-N32", "-tx1", target});
                            std::erase_if(embedded, [](char c) {
                                return c == ' ' || c == '\n' || c == '\r' || c == '\t';
                            });
                            need(std::regex_match(digest, std::regex("[0-9a-f]{64}")) &&
                                         embedded == image_digest,
                                 "boot relocation metadata must match compiled image");
                            installed.push_back({"compiled-boot-relocation",
                                                 target,
                                                 digest,
                                                 {},
                                                 "0644",
                                                 false});
                            ++relocated;
                        }
                    }

                    need(relocated == 15, "complete boot relocation family required");
                    candidate.shell({"test", "-d", "/system/framework/arm64/dalvik-cache"});
                    candidate.shell({"rm", "-rf", "/system/framework/arm64/dalvik-cache"});
                    candidate.shell({"test", "!", "-e", "/system/framework/arm64/dalvik-cache"});
                    candidate.events.push_back(
                            {{"phase", "boot-art-relocations-generated"},
                             {"files", relocated},
                             {"command", relocation},
                             {"log_sha256",
                              sha256_file(candidate.stage / "boot-image-relocation.log")}});
                }
            }

            for (const auto &command : android_candidate_system_server_commands(profile)) {
                const auto target = command.at(3).substr(std::string("--oat-file=").size());
                candidate.phase("system-server-compile");
                candidate.shell({"mkdir", "-p", "/system/framework/oat/arm64"});
                candidate.shell(command, 300000);

                for (const auto &file :
                     {target, std::filesystem::path(target).replace_extension(".vdex").string(),
                      std::filesystem::path(target).replace_extension(".art").string()}) {
                    candidate.shell({"test", "-s", file});
                    candidate.shell({"chmod", "0644", file});
                    candidate.shell({"chown", "0:0", file});
                    candidate.shell({"restorecon", file});
                    const auto digest = candidate.shell({"sha256sum", file}).substr(0, 64);
                    need(std::regex_match(digest, std::regex("[0-9a-f]{64}")),
                         "compiled system server hash required");
                    installed.push_back(
                            {"compiled-system-server", file, digest, {}, "0644", false});
                }

                candidate.events.push_back(
                        {{"phase", "system-server-compiled"}, {"command", command}});
            }

            candidate.events.push_back(
                    {{"phase", "system-installed"}, {"count", plan.at("system").size()}});
            prepare_a9_precompiled_policy(candidate, profile, installed);
            android_candidate_first_oem_boot(
                    profile,
                    [&](const auto &command) {
                        return candidate.shell(command);
                    },
                    [&] {
                        if (profile.at("android").contains("offline_selinux_labels")) {
                            const auto option = profile.at("android")
                                                        .at("offline_selinux_labels")
                                                        .get<std::string>();

                            if (option == "qinggan09-can-early-v1") {
                                repair_a9_offline_labels(candidate, profile, artifacts, installed,
                                                         reserve);
                            } else {
                                repair_a11_offline_labels(candidate, profile, artifacts);
                            }
                        } else {
                            candidate.reboot();
                        }
                    },
                    [&] {
                        install_entries(candidate, early_data, artifacts, aapt2, installed);
                        configure_boot_properties(candidate, profile, installed);
                    });
        }

        const auto navi_storage = original_navi_storage_set(profile,
                                                            android_candidate_api(profile));

        const auto verify_navi_shell = [&] {
            need(candidate.shell({"id", "-u"}) == "2000" &&
                         candidate.shell({"id", "-Z"}) == "u:r:shell:s0",
                 "original Navi AppOps requires the stock Android shell");
        };

        if (!navi_storage.empty()) {
            candidate.phase("original-navi-storage");
            verify_navi_shell();
            candidate.wait(
                    [&] {
                        const auto service = candidate.shell({"service", "check", "appops"});
                        need(service == "Service appops: found",
                             "Android service check: " + service);

                        return true;
                    },
                    30000,
                    "AppOps visibility from Android shell before original Navi storage configuration");
            candidate.shell(navi_storage);
            const auto flushed = candidate.shell({"cmd", "appops", "write-settings"});
            need(flushed == "Current settings written.", "original Navi AppOps flush: " + flushed);
        }

        if (plan.at("system").empty() && request.native_bridge.empty() && !early_data.empty()) {
            candidate.root_adbd();
            install_entries(candidate, early_data, artifacts, aapt2, installed);
        }

        candidate.phase("data-apk-install");

        if (!late_data.empty()) {
            candidate.root_adbd();
        }

        install_entries(candidate, late_data, artifacts, aapt2, installed);
        install_entries(candidate, plan.at("apks"), artifacts, aapt2, installed);
        candidate.events.push_back(
                {{"phase", "data-apks-installed"}, {"apks", plan.at("apks").size()}});
        candidate.phase("configure");
        configure(candidate, profile, installed);
        candidate.phase("persist");
        candidate.root_adbd();
        candidate.wait(
                [&] {
                    return android_candidate_package_settings_flushed(
                            candidate.shell(
                                    {"cat", "/data/system/users/0/package-restrictions.xml"}),
                            profile.value("configure", Json::object()));
                },
                120000, "PackageManager settings flush");

        if (profile.value("configure", Json::object()).contains("home")) {
            android_candidate_home_role_persisted(
                    android_candidate_api(profile),
                    profile.at("configure").at("home").get<std::string>(),
                    [&](const auto &command) {
                        return candidate.shell(command);
                    },
                    candidate.home_role_poll("persisted HOME role holder"));
        }

        candidate.shell({"sync"});
        configure_settings(
                candidate,
                profile.value("configure", Json::object()).value("settings", Json::object()), true);
        candidate.shell({"sync"});
        candidate.reboot();
        android_candidate_home_reboot_checkpoints(
                android_candidate_api(profile),
                profile.value("configure", Json::object()).contains("home"),
                [&] {
                    candidate.phase("home-establish");
                    candidate.root_adbd();
                    home_component(candidate, profile.at("configure"), true);
                    std::string home_query, restrictions;
                    candidate.wait(
                            [&] {
                                home_query = candidate.shell({"cmd", "package", "query-activities",
                                                              "--brief", "--user", "0", "-a",
                                                              "android.intent.action.MAIN", "-c",
                                                              "android.intent.category.HOME", "-c",
                                                              "android.intent.category.DEFAULT"});
                                restrictions = candidate.shell(
                                        {"cat", "/data/system/users/0/package-restrictions.xml"});

                                return android_candidate_package_settings_flushed(
                                        restrictions, profile.at("configure"), home_query);
                            },
                            120000, "PackageManager settings flush after HOME");
                    const auto pref_start = restrictions.find("<preferred-activities>"),
                               pref_end = restrictions.find("</preferred-activities>", pref_start);
                    write_private_json(
                            candidate.stage / "home-preference-before-cold.json",
                            {{"home_query", home_query},
                             {"preferred_xml",
                              restrictions.substr(pref_start, pref_end - pref_start + 23)}});
                    candidate.shell({"sync"});
                },
                [&] {
                    if (android_candidate_api(profile) == 28 && candidate.boots > 1) {
                        try {
                            const auto home_query = candidate.shell(
                                    {"cmd", "package", "query-activities", "--brief", "--user", "0",
                                     "-a", "android.intent.action.MAIN", "-c",
                                     "android.intent.category.HOME", "-c",
                                     "android.intent.category.DEFAULT"});
                            const auto restrictions = candidate.shell(
                                    {"cat", "/data/system/users/0/package-restrictions.xml"});
                            const auto begin = restrictions.find("<preferred-activities>"),
                                       end = restrictions.find("</preferred-activities>", begin);
                            need(begin != std::string::npos && end != std::string::npos,
                                 "preferred XML unavailable");
                            write_private_json(candidate.stage / "home-preference-after-cold.json",
                                               {{"home_query", home_query},
                                                {"preferred_xml",
                                                 restrictions.substr(begin, end - begin + 23)}});
                        } catch (...) { /* Ignored: the failure report records only available
                                           evidence. */
                        }
                    }

                    persisted(candidate, profile, installed);
                },
                [&] {
                    for (const auto &package : android_candidate_art_verify_packages(profile)) {
                        const std::string phase = package == "com.voyah.car" ? "vehicle-art-verify"
                                                  : package == "com.voyah.avm"
                                                          ? "avm-art-verify"
                                                          : "launcher-art-verify";
                        candidate.phase(phase);
                        const auto verified = candidate.shell(
                                {"cmd", "package", "compile", "-m", "verify", "-f", package},
                                180000);
                        write(destination / (phase + ".txt"), verified + "\n");
                        need(verified == "Success", phase + " ART package verify failed");
                        candidate.events.push_back({{"phase", phase},
                                                    {"package", package},
                                                    {"compiler_filter", "verify"},
                                                    {"result", verified}});
                    }

                    candidate.stop();
                    candidate.boot(profile);
                });
        wake_displays(candidate, profile);
        candidate.phase("cold-verification");

        if (!navi_storage.empty()) {
            verify_navi_shell();
            const auto storage = candidate.shell(
                    {"cmd", "appops", "get", "com.baidu.naviauto", "NO_ISOLATED_STORAGE"});
            need(original_navi_storage_allowed(storage), "original Navi storage appop not allowed");
            checks.push_back({{"id", "original-navi-storage-appop"},
                              {"expected", "allow"},
                              {"actual", storage},
                              {"passed", true}});
            verify_cold_original_navi(candidate, checks);
        }

        if (original_navi_requested(profile) &&
            profile.value("components", Json::object()).contains("view-observation")) {
            candidate.phase("rich-ui-observation");
            candidate.wait(
                    [&] {
                        if (!android_candidate_ui_shell_ready([&](const auto &command) {
                                return candidate.shell(command);
                            })) {
                            return false;
                        }

                        const auto displays = candidate.shell({"dumpsys", "display"});
                        const auto windows = candidate.shell({"dumpsys", "window", "windows"});

                        return android_candidate_secondary_display_ready(profile, displays, windows)
                                .has_value();
                    },
                    60000, "stock shell accessibility service and secondary display readiness");
            checks.push_back(capture_candidate_ui(candidate, profile));
            candidate.phase("cold-verification");
        }

        verify_cold_policy_files(
                profile, installed, checks,
                [&](const auto &command) {
                    return candidate.shell(command,
                                           android_candidate_cold_command_timeout(command));
                },
                [&] {
                    candidate.root_adbd();
                });
        verify_a9_precompiled_policy(candidate, profile);

        candidate.root_adbd();
        verification_boot_id = candidate.shell({"cat", "/proc/sys/kernel/random/boot_id"});

        // The cold guest boots with the vbmeta digest of the machine; dm-verity stays disabled
        // since the first remount, which leaves the verified boot state orange.
        if (!candidate.stock_vbmeta_digest.empty()) {
            record_cold_check(checks, "vbmeta-digest",
                              candidate.shell({"getprop", "ro.boot.vbmeta.digest"}),
                              candidate.vbmeta_digest);
        }

        verification_boots = candidate.boots;
        verify_cold(candidate, profile, installed, checks);

        if (!request.native_bridge.empty()) {
            verify_cold_native_bridge(
                    candidate, {request.native_bridge_descriptor, request.native_bridge}, checks);
        }

        Json frames = Json::array();

        if (request.capture_frames) {
            candidate.phase("native-frame-capture");
            frames = capture_candidate_frames(candidate, profile);
        }

        candidate.stop();
        candidate.phase("portable-export");
        const auto images = export_images(candidate, destination, reserve);

        if (!development.is_null()) {
            check_file(development_file, development_sha, 64ULL << 20);
            check_file(candidate.machine / "base/kernel-ranchu", development_sha, 64ULL << 20);
        }

        need(sha256_bytes(authoring_profile_bytes(root, request.profile, request.target)) ==
                     request.profile_sha256,
             "authoring profile changed during candidate build");
        check_file(request.artifact_result, request.artifact_result_sha256, 16 << 20);
        check_file(request.clean_base / "base.json", request.clean_receipt_sha256, 128 * 1024);

        for (auto it = clean.at("files").begin(); it != clean.at("files").end(); ++it) {
            check_file(request.clean_base / it.key(), it.value().at("sha256").get<std::string>());
        }

        for (const auto &file : {emulator, adb, aapt2, qemu_img, backend}) {
            tool(request, file);
        }

        Json installed_json = Json::array();

        for (const auto &item : installed) {
            installed_json.push_back({{"artifact", item.artifact},
                                      {"target", item.target},
                                      {"sha256", item.sha256},
                                      {"package", item.package},
                                      {"mode", item.mode},
                                      {"mutable", item.mutable_seed}});
        }

        const auto owned_package = export_android_candidate_owned_package(
                profile, artifacts, installed_json, destination, reserve);
        const bool original_navi = original_navi_requested(profile);
        const auto camera_package = original_navi ? export_android_candidate_camera_package(
                                                            profile, artifacts, installed_json,
                                                            destination, reserve)
                                                  : Json::object();
        const auto prepared_packages = original_navi ? Json::array()
                                                     : export_android_candidate_prepared_packages(
                                                               profile, artifacts, installed_json,
                                                               destination, reserve);
        const auto qinggan09_packages = export_android_candidate_qinggan09_packages(
                root, request, installed_json, destination, reserve);
        // This is a cold-accepted output snapshot, not a future checkout compatibility pin.
        write(destination / "profile.json", profile_bytes);
        check_file(destination / "profile.json", request.profile_sha256, 4 << 20);
        Json receipt = {
                {"schema", 1},
                {"kind", "android-candidate"},
                {"profile", request.profile},
                {"profile_file", "profile.json"},
                {"profile_sha256", request.profile_sha256},
                {"artifact_result_sha256", request.artifact_result_sha256},
                {"clean_base_archive_sha256", clean.at("archive_sha256")},
                {"prepared_VM", true},
                {"stopped", true},
                {"old_machine_modified", false},
                {"cold_boot_verified", true},
                {"guest_frame_exported", request.capture_frames},
                {"evidence_scope",
                 request.capture_frames
                         ? "boot/package/hash/SELinux/settings/service/display/window and two original SDK frames"
                         : "boot/package/hash/SELinux/settings/service/display/window; no exported frames"},
                {"android", {{"abi", abi}, {"images", images}}},
                {"installed", installed_json},
                {"checks", checks},
                {"events", candidate.events}};

        if (!request.target.empty()) {
            receipt["target"] = profile_target_identity(profile);
        }

        if (!candidate.stock_vbmeta_digest.empty()) {
            const std::string name = "VerifiedBootParams.textproto";
            const auto parameters = candidate.machine / "base" / name;
            const auto pin = sha256_file(parameters);
            need(android_verified_boot_digest(text(parameters, 4096)) == candidate.vbmeta_digest &&
                         android_vbmeta_chain(raw_disk_reader(destination / "android/system.img"),
                                              candidate.vbmeta_partitions)
                                         .digest == candidate.vbmeta_digest,
                 "exported system image differs from the machine vbmeta digest");
            copy_portable_image(parameters, pin, destination / "android" / name, reserve);
            receipt["android"]["verified_boot"] = {{"vbmeta_digest", candidate.vbmeta_digest},
                                                   {"file", "android/" + name},
                                                   {"sha256", pin}};
        }

        if (!development.is_null()) {
            receipt["development_kernel"] = development;
        }

        if (!owned_package.empty()) {
            receipt["owned_package"] = owned_package;
        }

        if (original_navi) {
            receipt["camera_package"] = camera_package;
            receipt["original_navi_system"] = original_navi_marker();
            const auto &source = artifacts.at("original:Navi");
            const std::filesystem::path apk = source.at("file").get<std::string>();
            check_file(apk, std::string(original_navi_sha), 512ULL << 20);
            const auto cert =
                    sha256_bytes(pinned_apk_v2_certificate(apk, std::string(original_navi_sha)));
            original_navi_candidate(profile, 30, receipt, artifacts, cert);
        }

        if (!prepared_packages.empty()) {
            receipt["prepared_packages"] = prepared_packages;
        }

        if (!qinggan09_packages.empty()) {
            receipt["qinggan09_owned_packages"] = qinggan09_packages;
        }

        if (request.capture_frames) {
            receipt["frames"] = frames;
        }

        write_private_json(destination / "receipt.json", receipt, 1 << 20);
        candidate.phase("complete-stopped");

        return receipt;
    } catch (const std::exception &error) {
        const auto diagnostic = capture_android_candidate_failure(
                candidate.process, candidate.adb, candidate.stage, candidate.port, candidate.avd,
                candidate.token, &candidate.adb_binding, &candidate.adb_server);
        const auto guest_sync = sync_android_candidate_failure(
                candidate.process, candidate.adb, candidate.stage, candidate.port, candidate.avd,
                candidate.token, &candidate.adb_binding, &candidate.adb_server);
        bool stopped = !candidate.process.alive();

        if (!stopped) {
            try {
                candidate.process.terminate(5000);
                stopped = !candidate.process.alive();
            } catch (...) { /* Ignored: termination is best-effort here. */
            }
        }

        bool adb_stopped = !candidate.adb_server.alive();

        if (!adb_stopped) {
            try {
                candidate.adb_server.terminate(1000);
                adb_stopped = !candidate.adb_server.alive();
            } catch (...) { /* Ignored: termination is best-effort here. */
            }
        }

        try {
            write_private_json(destination / "failure.json",
                               {{"schema", 1},
                                {"profile", request.profile},
                                {"message", error.what()},
                                {"checks", checks},
                                {"verification_boot_id", verification_boot_id},
                                {"verification_boots", verification_boots},
                                {"startup_diagnostic", diagnostic},
                                {"owned_guest_sync", guest_sync},
                                {"owned_emulator_stopped", stopped},
                                {"owned_adb_server_stopped", adb_stopped},
                                {"old_machine_modified", false},
                                {"events", candidate.events}},
                               1 << 20);
        } catch (...) { /* Ignored: the failure report must not replace the original failure. */
        }

        throw std::runtime_error(std::string(error.what()) +
                                 "; candidate diagnostics: " + destination.string());
    }
}
} // namespace voyemu
