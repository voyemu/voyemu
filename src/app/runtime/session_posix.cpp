#include "session_posix.hpp"
#include "error.hpp"

// The parts of Session that differ on macOS and Linux, where Android runs through the SDK ADB
// endpoints and QNX through Unix-domain sockets; session_windows.cpp holds the Windows parts.
namespace voyemu {
using namespace session_detail;
namespace session_detail {
std::filesystem::path session_sdk_registration_directory(const std::filesystem::path &directory,
                                                         bool) {
    // The SDK registers its emulator below the discovery root in the environment of the child.
    ProcessSpec sdk;

    android_session_environment(sdk, directory);
    const std::filesystem::path root =
            sdk.environment.at(std::string(os::sdk_discovery_root_variable));

    return sdk_registration_directory(root, directory / "emulator-home");
}

bool android_windows_renderer(const Json &, bool) {
    return false;
}

int android_stop_sync_budget() {
    return 15000;
}

void check_restart_can_boundary(bool) {}

void require_short_pair_transport() {}

std::chrono::milliseconds source_collector_budget(const std::string &) {
    return std::chrono::milliseconds(1500);
}

std::string native_backend_path(const std::filesystem::path &path, bool) {
    return path.string();
}

std::string native_backend_avd_config(std::string text, bool, const std::filesystem::path &) {
    return text;
}

bool native_backend_same_file(const std::filesystem::path &, const std::filesystem::path &) {
    return false;
}

bool owned_symlink(const std::filesystem::path &alias) {
    struct stat info{};

    return ::lstat(alias.c_str(), &info) == 0 && S_ISLNK(info.st_mode) &&
           info.st_uid == ::geteuid();
}

void link_overlay(const std::filesystem::path &disk, const std::filesystem::path &alias) {
    std::filesystem::create_symlink(disk, alias);
}

OwnedRamReader owned_ram_reader(const std::filesystem::path &ram, std::uint64_t bytes) {
    auto file = std::make_shared<Fd>(::open(ram.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    struct stat info{};

    if (file->value < 0 || ::fstat(file->value, &info) || !S_ISREG(info.st_mode) ||
        info.st_uid != ::geteuid() || info.st_nlink != 1 || std::uint64_t(info.st_size) != bytes) {
        return {};
    }

    return [file](std::uint64_t offset, std::span<std::byte> output) {
        return ::pread(file->value, output.data(), output.size(), static_cast<off_t>(offset)) ==
               static_cast<ssize_t>(output.size());
    };
}

void write_handoff_file(const std::filesystem::path &path, const std::string &text) {
    Fd file(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));

    if (file.value < 0) {
        throw VoyemuError("QNX_HANDOFF", "exclusive creation failed");
    }

    std::size_t offset = 0;

    while (offset < text.size()) {
        auto count = ::write(file.value, text.data() + offset, text.size() - offset);

        if (count < 0 && errno == EINTR) {
            continue;
        }

        if (count <= 0) {
            throw VoyemuError("QNX_HANDOFF", "incomplete write; RAM retained");
        }

        offset += static_cast<std::size_t>(count);
    }

    if (::fsync(file.value) != 0) {
        throw VoyemuError("QNX_HANDOFF", "durable write failed; RAM retained");
    }

    Fd folder(::open(path.parent_path().c_str(), O_RDONLY | O_CLOEXEC));

    if (folder.value >= 0) {
        ::fsync(folder.value);
    }
}

struct OwnedRamBacking::Handle {
    std::optional<Fd> file;
    struct stat identity{};
};

OwnedRamBacking::OwnedRamBacking(const std::filesystem::path &path, bool exists,
                                 std::uint64_t bytes)
    : path_(path), handle_(std::make_unique<Handle>()) {
    if (!exists) {
        return;
    }

    auto &identity = handle_->identity;
    const auto &file =
            handle_->file.emplace(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));

    if (file.value < 0 || ::fstat(file.value, &identity) != 0 || !S_ISREG(identity.st_mode) ||
        identity.st_uid != ::geteuid() || identity.st_nlink != 1 ||
        std::uint64_t(identity.st_size) != bytes) {
        throw VoyemuError("QNX_CLEANUP_RAM", "foreign or invalid backing");
    }
}

OwnedRamBacking::~OwnedRamBacking() = default;

void OwnedRamBacking::remove() {
    const auto &identity = handle_->identity;
    struct stat current{};

    if (::lstat(path_.c_str(), &current) != 0 || !S_ISREG(current.st_mode) ||
        current.st_ino != identity.st_ino || current.st_dev != identity.st_dev ||
        current.st_uid != identity.st_uid || current.st_size != identity.st_size ||
        current.st_nlink != 1) {
        throw VoyemuError("QNX_CLEANUP_REMOVE", "backing identity changed; retained");
    }

    if (::unlink(path_.c_str()) != 0) {
        throw VoyemuError("QNX_CLEANUP_REMOVE", "terminal backing removal failed");
    }

    Fd folder(::open(path_.parent_path().c_str(), O_RDONLY | O_CLOEXEC));

    if (folder.value >= 0) {
        ::fsync(folder.value);
    }
}

std::tm local_time(std::time_t time) {
    std::tm local{};

    localtime_r(&time, &local);

    return local;
}
} // namespace session_detail

void Session::advance_android(bool guest_possible, std::chrono::steady_clock::time_point now) {
    auto drain_wheel = [&] {
        // Cooperative ADB waits admit an owner's UP; drain it before display/state work.
        std::size_t processed = 0;
        std::optional<WheelEvent> confirmed_down;
        std::uint64_t proof_generation = 0;
        std::int64_t proof_pid = 0;

        while (android_identity_ && android_clock_observed_ && !android_events_.empty() &&
               processed++ < 1024) {
            auto event = android_events_.front();
            try {
                const auto pair = android_short_pairs_.find(event.sequence);

                if (pair != android_short_pairs_.end()) {
                    if (android_events_.size() < 2) {
                        throw VoyemuError("WHEEL_PAIR", "queued release unavailable");
                    }

                    const auto release = android_events_[1];
                    deliver_android_short_pair(event, release, pair->second.first,
                                               pair->second.second);
                    android_events_.pop_front();
                    android_events_.pop_front();
                    android_short_pairs_.erase(pair);
                    confirmed_down.reset();
                } else {
                    const bool same_release = confirmed_down &&
                                              android_wheel_release_reuses_identity(*confirmed_down,
                                                                                    event);
                    const auto port = android_spec_.at("port").get<unsigned>();
                    const bool retained = same_release &&
                                          qinggan11_partial_wheel_capability_matches(
                                                  android_spec_.contains("wheel_capability")
                                                          ? android_spec_.at("wheel_capability")
                                                          : Json(nullptr)) &&
                                          android_powered_ &&
                                          proof_generation == android_generation_ &&
                                          proof_pid == android_.pid() && android_.alive() &&
                                          android_.owns_tcp_listener(port) &&
                                          android_.owns_tcp_listener(port + 1);
                    confirmed_down.reset();
                    deliver_android_event(event, retained);
                    android_events_.pop_front();

                    if (event.phase == "down" && deliveries_["android"]["wheel"]
                                                         .value("receipt", Json::object())
                                                         .value("submission_confirmed", false)) {
                        confirmed_down = event;
                        proof_generation = android_generation_;
                        proof_pid = android_.pid();
                    }
                }
            } catch (const std::exception &error) {
                deliveries_["android"]["wheel"] = {{"event_sequence", event.sequence},
                                                   {"status", "awaiting_receipt"},
                                                   {"error", error.what()}};
                break;
            }
        }
    };

    drain_wheel();

    if (guest_possible && now >= next_android_) {
        auto stage_errors = run_android_startup_stages(
                [&] {
                    assert_android_identity();
                    bootstrap_android_transport();
                    prepare_android_audio();
                    configure_android_interguest_network();
                    synchronize_android_clock();
                },
                [&] {
                    if ((android_spec_.contains("camera_package") ||
                         android_spec_.contains("prepared_packages")) &&
                        !android_spec_.contains("wheel_adapter")) {
                        throw VoyemuError("ANDROID_OWNED_PACKAGE",
                                          "Camera requires Free A11 wheel bootstrap");
                    }

                    if (android_spec_.contains("wheel_adapter")) {
                        prepare_android_wheel();
                    }

                    if (passion_mcu_available(android_spec_) ||
                        android_revision_ != model_.state()["sequence"].get<std::uint32_t>()) {
                        deliver_android_state();
                    }
                },
                [&] {
                    prepare_android_displays();
                    const auto theme_now = std::chrono::steady_clock::now();

                    if (theme_now >= next_oem_settings_) {
                        next_oem_settings_ = theme_now + std::chrono::seconds(2);
                        poll_oem_settings();
                    }
                });
        deliveries_["android"]["stage_errors"] = stage_errors;

        if (stage_errors.empty()) {
            deliveries_["android"].erase("last_error");
        } else {
            for (const char *stage : {"guard", "vehicle", "display"}) {
                if (stage_errors.contains(stage)) {
                    deliveries_["android"]["last_error"] = stage_errors.at(stage);
                    break;
                }
            }
        }

        const bool bootstrap_ready = !android_spec_.contains("wheel_adapter") || wheel_provisioned_;
        const bool home_ready = !android_spec_.contains("home") || primary_home_ready_;
        const bool displays_ready = !android_spec_.contains("features") ||
                                    android_spec_["features"].value("MultiDisplay",
                                                                    std::string{}) != "on" ||
                                    android_displays_ready_;
        const bool presentation_only = !media::presentation_family(android_spec_).empty();
        const bool current_state =
                passion_mcu_available(android_spec_)
                        ? passion_mcu_delivery_current(
                                  deliveries_["android"].value("vehicle", Json::object()),
                                  android_transport_boot_,
                                  model_.state()["sequence"].get<std::uint32_t>(),
                                  passion_mcu_now_ms())
                        : (presentation_only ||
                           android_revision_ == model_.state()["sequence"].get<std::uint32_t>());
        const bool ready = stage_errors.empty() && android_identity_ && android_clock_observed_ &&
                           bootstrap_ready && home_ready && displays_ready && current_state;

        if (presentation_only) {
            deliveries_["android"]["status"] = ready ? "presentation_ready"
                                                     : "awaiting_presentation";
            deliveries_["android"]["guest_acknowledged"] = false;
            deliveries_["android"]["presentation_family"] =
                    media::presentation_family(android_spec_);

            if (!android_spec_.contains("wheel_adapter")) {
                deliveries_["android"]["wheel"] = {{"status", "unsupported"}, {"supported", false}};
            }
        }

        // Schedule after bounded ADB work so a slow failure cannot cause a tight retry loop.
        const bool newer_source = android_identity_ && android_clock_observed_ && bootstrap_ready &&
                                  home_ready && displays_ready && !current_state &&
                                  !deliveries_["android"].contains("last_error");
        next_android_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(newer_source
                                                                                             ? 0
                                                                                     : ready ? 2000
                                                                                             : 200);

        // Keep the watchdog deadline independent of state-triggered passes and ADB duration.
        // Otherwise a three-second watchdog is rounded up by repeated two-second ready sleeps.
        if (ready && android_displays_ready_ && !deliveries_["android"].contains("last_error")) {
            next_android_ = std::min(next_android_, next_display_observation_);
        }
    }

    drain_wheel();
}

Session::IoLockLoan Session::lend_android_request_io(std::unique_lock<std::recursive_mutex> &) {
    return {};
}

void Session::cancel_android_identity_probe() {}

void Session::add_interguest_delivery(Json &) const {}

void Session::reset_android_transaction() {}

void Session::configure_android_native_backend(ProcessSpec &, const Json &, unsigned, std::uint64_t,
                                               bool) {}

std::optional<ProcessResult> Session::execute_android_transaction(const Json &,
                                                                  const std::vector<std::string> &,
                                                                  int &, std::size_t, std::int64_t,
                                                                  std::uint64_t) {
    return std::nullopt;
}

void Session::assert_android_identity() {
    auto trim = [](std::string text) {
        auto pos = text.find_first_of("\r\n");

        if (pos != std::string::npos) {
            text.resize(pos);
        }

        return text;
    };
    const auto started = std::chrono::steady_clock::now();
    const auto token = adb({"shell", "getprop", "qemu.voyemu.token"}, 1500);
    const auto token_finished = std::chrono::steady_clock::now();
    const auto name = adb({"emu", "avd", "name"}, 1500);

    if (token.timed_out || token.exit_code || name.timed_out || name.exit_code) {
        // Fixed scalar diagnostics only; nonce, AVD name and raw output stay private.
        try {
            logging::write(
                    logging::Level::error, "android", "identity.unavailable",
                    {{"token_exit_code", token.exit_code},
                     {"token_timed_out", token.timed_out},
                     {"token_elapsed_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  token_finished - started)
                                                  .count()},
                     {"avd_exit_code", name.exit_code},
                     {"avd_timed_out", name.timed_out},
                     {"avd_elapsed_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::steady_clock::now() - token_finished)
                                                .count()}});
        } catch (...) { /* Ignored: diagnostics are best-effort. */
        }

        throw VoyemuError("ANDROID_IDENTITY_NOT_READY", "owned SDK endpoint unavailable");
    }

    const auto boot = trim(token.output);
    const auto port = android_spec_.at("port").get<unsigned>();
    const bool native_owned = android_.owns_tcp_listener(port) &&
                              android_.owns_tcp_listener(port + 1);

    if (trim(name.output) != android_spec_.at("avd_name").get<std::string>() ||
        !android_nonce_matches(boot, session_id_, android_boot_nonce_, android_resume_)) {
        throw VoyemuError("ANDROID_IDENTITY_MISMATCH", "SDK target is not this owned boot");
    }

    if (boot != session_id_ && !native_owned) {
        throw VoyemuError("ANDROID_IDENTITY_MISMATCH",
                          "cached boot lacks current native SDK listener ownership");
    }

    if (boot == session_id_ && android_resume_) {
        android_boot_nonce_ = session_id_;
        android_resume_ = false;
        deliveries_["android"]["quickboot"]["mode"] = "sdk_cold_fallback";
    } else if (android_resume_) {
        deliveries_["android"]["quickboot"]["mode"] = "restored";
    }

    deliveries_["android"]["native_listener_ownership"] = native_owned;

    if (native_owned) {
        const auto launcher =
                std::filesystem::path(android_spec_.at("executable").get<std::string>());
        const auto arch = android_spec_.value("guest_arch", std::string("aarch64"));

        if (arch != "x86_64" && arch != "aarch64") {
            throw VoyemuError("ANDROID_IDENTITY_MISMATCH",
                              "unsupported Android SDK guest architecture");
        }

        const auto engine = "qemu-system-" + arch + (android_sdk_headless_ ? "-headless" : "");
        const auto backend = launcher.parent_path() / "qemu" / std::string(os::emulator_host) /
                             engine;
        refresh_android_launch_identity(directory_, session_id_, android_.pid(),
                                        android_generation_, launcher, backend);
    }

    android_identity_ = true;
    android_seen_guest_ = true;
}

void Session::assert_android_identity_until(std::chrono::steady_clock::time_point) {
    assert_android_identity();
}

bool Session::android_ports_released_after_kill(unsigned, bool,
                                                const std::function<bool()> &released) {
    return released();
}

bool Session::android_ports_released_at_stop(unsigned, const std::function<bool()> &released) {
    return released();
}

std::optional<std::string> Session::android_boot_id() {
    const auto observed = adb({"shell", "cat", "/proc/sys/kernel/random/boot_id"}, 1500);

    if (observed.timed_out || observed.exit_code) {
        return std::nullopt;
    }

    auto value = observed.output;

    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }

    return value;
}

void Session::prevalidate_android_reboot() {
    // Reject unavailable transport before retiring the live observation services.
    // The fresh fence below still revalidates ownership before VM mutation.
    assert_android_identity();
}

std::optional<std::string>
Session::await_android_reboot(std::unique_lock<std::recursive_mutex> &lock,
                              const std::string &before, const std::function<std::string()> &boot) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const auto port = android_spec_.at("port").get<unsigned>();
    std::string after;

    // Lifecycle fences replacement; release state during bounded SDK I/O so other control reads
    // and input cleanup can proceed.
    while (std::chrono::steady_clock::now() < deadline) {
        lock.unlock();
        bool changed = false;
        try {
            if (!android_.owns_tcp_listener(port) || !android_.owns_tcp_listener(port + 1)) {
                throw VoyemuError("ANDROID_REBOOT_WAIT", "owned listeners are not ready");
            }

            auto result = adb({"shell", "cat", "/proc/sys/kernel/random/boot_id"}, 1500);
            after = result.output;

            while (!after.empty() && (after.back() == '\n' || after.back() == '\r')) {
                after.pop_back();
            }

            if (!result.timed_out && !result.exit_code && android_boot_id_valid(after)) {
                changed = android_reboot_changed(before, after);
            }
        } catch (const std::exception &) { /* Ignored: missing boot-time transport is not proof
                                              of a new boot. */
        }

        lock.lock();

        if (changed) {
            assert_android_identity();

            // Fence the token/AVD verification itself with a second Linux boot read.
            if (boot() != after) {
                throw VoyemuError("ANDROID_REBOOT_UNKNOWN",
                                  "guest boot changed during completion fence");
            }

            deliveries_["android"]["reboot"]["status"] = "completed";
            deliveries_["android"]["reboot"]["boot_id"] = after;
            deliveries_["android"]["status"] = "booting";

            return after;
        }

        lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        lock.lock();
    }

    return std::nullopt;
}

void Session::configure_qnx_event_monitor(ProcessSpec &qemu, const std::string &) {
    // A separate monitor leaves the existing single-client QMP command channel available.
    qnx_shutdown_monitor_.reset();

    if (qnx_persistent_storage_ && cluster_spec_.at("qmp").is_string() &&
        std::find(qemu.arguments.begin(), qemu.arguments.end(), "-no-reboot") !=
                qemu.arguments.end() &&
        std::find(qemu.arguments.begin(), qemu.arguments.end(), "-S") != qemu.arguments.end()) {
        const auto events = native_socket_root() / (session_id_ + "-evt.sock");
        qnx_shutdown_monitor_ = std::make_unique<QnxShutdownMonitor>(Json(events.string()),
                                                                     cluster_generation_ + 1);
        qemu.arguments.insert(qemu.arguments.end(),
                              {"-qmp", "unix:" + events.string() + ",server=on,wait=off"});
    }
}

bool Session::continue_qnx_guest() {
    if (qnx_shutdown_monitor_) {
        qnx_shutdown_monitor_->connect_owned(qnx_.pid());
    }

    auto path = expand_session_path(cluster_spec_.at("qmp").get<std::string>(), directory_,
                                    session_id_);
    Fd fd(unix_connect(path, 300, false));
    std::string carry;
    auto greeting = Json::parse(receive_line(fd.value, 300, &carry));

    if (!greeting.contains("QMP")) {
        throw VoyemuError("QMP_GREETING", "invalid server");
    }

    send_text(fd.value, bounded_message({{"execute", "qmp_capabilities"}}), 300);
    auto capabilities = Json::parse(receive_line(fd.value, 300, &carry));

    if (!capabilities.contains("return")) {
        throw VoyemuError("QMP_CAPABILITIES", "rejected");
    }

    if (qnx_checkpoint_.resume) {
        auto query = [&](const char *command, Json arguments = Json{}) {
            const std::string id = std::string("checkpoint-") + command;
            Json request{{"execute", command}, {"id", id}};

            if (!arguments.is_null()) {
                request["arguments"] = std::move(arguments);
            }

            send_text(fd.value, bounded_message(request), 300);

            for (unsigned i = 0; i < 8; ++i) {
                auto reply = Json::parse(receive_line(fd.value, 300, &carry));

                if (reply.value("id", std::string{}) == id) {
                    if (reply.contains("error")) {
                        throw VoyemuError("QNX_CHECKPOINT", "query rejected");
                    }

                    return reply.at("return");
                }
            }

            throw VoyemuError("QNX_CHECKPOINT", "missing query reply");
        };
        const auto migration = query("query-migrate"), status = query("query-status");

        if (qnx_checkpoint_.external_ram &&
            migration.value("status", std::string{"none"}) == "none") {
            if (status.value("running", true) ||
                status.value("status", std::string{}) != "inmigrate") {
                throw VoyemuError("QNX_CACHE_RAM", "deferred guest must remain paused");
            }

            const auto roms = query("human-monitor-command", {{"command-line", "info roms"}});
            restore_qnx_checkpoint_boot_roms(
                    qnx_checkpoint_,
                    std::filesystem::path(expand_session_path(
                            cluster_spec_.at("ram").get<std::string>(), directory_, session_id_)),
                    roms.get<std::string>());
            query("migrate-set-parameters", {{"mode", "cpr-reboot"}});
            query("migrate-set-capabilities",
                  {{"capabilities",
                    Json::array({{{"capability", "x-ignore-shared"}, {"state", true}}})}});
            query("migrate-incoming",
                  {{"uri", "file:" + (qnx_checkpoint_.directory / "vmstate.bin").string()}});

            return false;
        }

        if (!qnx_checkpoint_migration_ready(migration, status)) {
            return false;
        }

        logging::write(logging::Level::info, "qnx", "checkpoint.vm_ready",
                       {{"host_elapsed_ms", std::chrono::duration<double, std::milli>(
                                                    std::chrono::steady_clock::now() - qnx_started_)
                                                    .count()}});
    }

    send_text(fd.value, bounded_message({{"execute", "cont"}}), 300);
    bool continued = false;

    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        auto response = Json::parse(receive_line(fd.value, 300, &carry));

        if (response.contains("return")) {
            continued = true;
            break;
        }

        if (response.contains("error")) {
            throw VoyemuError("QMP_CONT", "rejected");
        }
    }

    if (!continued) {
        throw VoyemuError("QMP_CONT", "missing reply");
    }

    qmp_cont_ = true;

    return true;
}

void Session::start_qnx_ring_collector(const std::filesystem::path &ram, std::uint64_t address,
                                       std::size_t extent, std::uint64_t mailbox_end) {
    if (!qnx_ready_collector_) {
        qnx_ready_collector_ = std::make_unique<QnxReadyCollector>(ram, address, extent,
                                                                   mailbox_end);
    }
}

void Session::add_retained_qnx_producers(
        std::vector<std::uint64_t> &ready_producers,
        std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> &incarnations,
        const std::function<void(std::uint64_t, const char *)> &origin) {
    if (qnx_ready_collector_) {
        const auto retained = qnx_ready_collector_->ready();

        for (const auto &producer : retained) {
            ready_producers.push_back(producer.address);
            incarnations[producer.address] = {producer.pid, producer.incarnation};
            origin(producer.address, "retained_collector");
        }
    }
}

void Session::set_qnx_persistence_paused(bool paused) {
    if (!qnx_.alive()) {
        throw VoyemuError("QNX_PERSISTENCE", "owned QEMU unavailable");
    }

    const auto path = std::filesystem::path(expand_session_path(
            cluster_spec_.at("qmp").get<std::string>(), directory_, session_id_));
    const auto expected = std::filesystem::absolute(directory_).lexically_normal() / "qmp.sock";

    if (path != expected && path != native_socket_root() / (session_id_ + "-qmp.sock")) {
        throw VoyemuError("QNX_PERSISTENCE", "unexpected QMP path");
    }

    terminal_path_guard(path);
    const auto parent = path.parent_path();
    Fd folder(::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    struct stat parent_identity{}, socket_identity{};

    if (folder.value < 0 || ::fstat(folder.value, &parent_identity) ||
        !S_ISDIR(parent_identity.st_mode) || parent_identity.st_uid != ::geteuid() ||
        (parent_identity.st_mode & 0077)) {
        throw VoyemuError("QNX_PERSISTENCE", "private owned QMP directory required");
    }

    if (::lstat(path.c_str(), &socket_identity) || !S_ISSOCK(socket_identity.st_mode) ||
        socket_identity.st_uid != ::geteuid() || (socket_identity.st_mode & 0022)) {
        throw VoyemuError("QNX_PERSISTENCE", "owned QMP socket required");
    }

    auto unchanged = [&] {
        struct stat folder_now{}, socket_now{};

        if (::lstat(parent.c_str(), &folder_now) || !S_ISDIR(folder_now.st_mode) ||
            folder_now.st_dev != parent_identity.st_dev ||
            folder_now.st_ino != parent_identity.st_ino || folder_now.st_uid != ::geteuid() ||
            (folder_now.st_mode & 0077) || ::lstat(path.c_str(), &socket_now) ||
            !S_ISSOCK(socket_now.st_mode) || socket_now.st_dev != socket_identity.st_dev ||
            socket_now.st_ino != socket_identity.st_ino || socket_now.st_uid != ::geteuid() ||
            (socket_now.st_mode & 0022)) {
            throw VoyemuError("QNX_PERSISTENCE", "QMP pathname identity changed");
        }
    };
    // QEMU creates a 0755 socket under its private 0700 parent. IPC socket policy stays strict
    // elsewhere.
    Fd fd(unix_connect(path, 300, false));
    unchanged();

    if (os::unix_peer_pid(fd.value) != qnx_.pid()) {
        throw VoyemuError("QNX_PERSISTENCE", "QMP peer is not owned QEMU");
    }

    std::string carry;

    if (!Json::parse(receive_line(fd.value, 300, &carry)).contains("QMP")) {
        throw VoyemuError("QNX_PERSISTENCE", "invalid QMP greeting");
    }

    unchanged();
    auto query = [&](const char *command) {
        const auto id = std::string("persistent-") + command;
        send_text(fd.value, bounded_message({{"execute", command}, {"id", id}}), 300);

        for (unsigned i = 0; i < 8; ++i) {
            const auto reply = Json::parse(receive_line(fd.value, 300, &carry));

            if (reply.value("id", std::string{}) == id) {
                if (reply.contains("error") || !reply.contains("return")) {
                    throw VoyemuError("QNX_PERSISTENCE", "QMP command rejected");
                }

                return reply.at("return");
            }
        }

        throw VoyemuError("QNX_PERSISTENCE", "QMP acknowledgement missing");
    };
    query("qmp_capabilities");

    if (paused) {
        qnx_persistence_paused_ = true;
    }

    query(paused ? "stop" : "cont");

    if (query("query-status").value("running", paused) != !paused) {
        throw VoyemuError("QNX_PERSISTENCE", "QMP pause state unverified");
    }

    qnx_persistence_paused_ = paused;
}

void Session::stop_qnx_ready_collector() {
    qnx_ready_collector_.reset();
}

void Session::remove_qmp_socket(Json &evidence) {
    auto socket = std::filesystem::path(expand_session_path(
            cluster_spec_.at("qmp").get<std::string>(), directory_, session_id_));
    auto private_root = native_socket_root();
    auto short_socket = private_root / (session_id_ + "-qmp.sock");
    auto session_socket = std::filesystem::absolute(directory_).lexically_normal() / "qmp.sock";

    if (socket != short_socket && socket != session_socket) {
        throw VoyemuError("QMP_CLEANUP_OWNER", "unexpected socket path");
    }

    terminal_path_guard(socket);
    struct stat status{};

    if (::lstat(socket.c_str(), &status) == 0) {
        if (!S_ISSOCK(status.st_mode) || status.st_uid != ::geteuid()) {
            throw VoyemuError("QMP_CLEANUP_OWNER", "foreign socket retained");
        }

        if (::unlink(socket.c_str()) != 0) {
            throw VoyemuError("QMP_CLEANUP_REMOVE", "owned terminal socket retained");
        }

        evidence["qmp_socket_cleanup"] = {{"status", "removed_after_owned_QEMU_exit"},
                                          {"path", socket.string()}};
    } else if (errno == ENOENT) {
        evidence["qmp_socket_cleanup"] = {{"status", "not_present"}, {"path", socket.string()}};
    } else {
        throw VoyemuError("QMP_CLEANUP_READ", "socket inspection failed");
    }
}

void Session::require_unborrowed_state_lock() const {
    if (android_io_state_lock_) {
        throw VoyemuError("CAN_SOURCE", "unexpected borrowed state lock");
    }
}

Json Session::observe_can_boundary(const std::function<Json(const std::string &)> &unavailable,
                                   std::unique_lock<std::recursive_mutex> &lock,
                                   std::chrono::steady_clock::time_point received, int timeout) {
    Json observed;

    try {
        if (stopped_ || !android_powered_ || !android_.alive() ||
            !android_spec_.contains("can_model_observer_sha256")) {
            throw VoyemuError("CAN_BOUNDARY_UNAVAILABLE",
                              "live owned SDK guest and sealed helper required");
        }

        assert_android_identity();
        const auto pid = android_.pid();
        const auto generation = android_generation_;
        const auto port = android_spec_.at("port").get<unsigned>();
        const auto boot_reply = adb({"shell", "cat", "/proc/sys/kernel/random/boot_id"}, 1500);
        auto boot = boot_reply.output;

        while (!boot.empty() && (boot.back() == '\n' || boot.back() == '\r')) {
            boot.pop_back();
        }

        if (boot_reply.exit_code || boot_reply.timed_out || !android_boot_id_valid(boot)) {
            throw VoyemuError("CAN_BOUNDARY_STALE", "complete actual Linux boot required");
        }

        const CanGuestIdentity identity{session_id_,
                                        android_spec_.at("avd_name").get<std::string>(),
                                        android_boot_nonce_, android_resume_};
        const auto sha = android_spec_.at("can_model_observer_sha256").get<std::string>();
        struct Relock {
            std::unique_lock<std::recursive_mutex> &value;

            ~Relock() {
                if (!value.owns_lock()) {
                    value.lock();
                }
            }
        } relock{lock};
        lock.unlock();
        const auto spent = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now() - received)
                                   .count();

        if (spent >= timeout) {
            throw VoyemuError("CAN_BOUNDARY_TIMEOUT", "history deadline before collection");
        }

        observed = collect_can_boundary("boundary", Json(), identity, sha, boot,
                                        timeout - static_cast<int>(spent),
                                        [&](const auto &args, int left) {
                                            return adb(args, left);
                                        });
        validate_can_history(observed, boot);
        lock.lock();

        if (stopped_ || !android_powered_ || pid != android_.pid() ||
            generation != android_generation_ || !android_.owns_tcp_listener(port) ||
            !android_.owns_tcp_listener(port + 1)) {
            throw VoyemuError("CAN_BOUNDARY_STALE",
                              "owned Android changed during history collection");
        }

        observed.update({{"session_id", session_id_},
                         {"owned_android_pid", pid},
                         {"guest_boot_id", boot},
                         {"capability", "closed_ecu_boundary_v1"}});

        if (observed.at("mode") == 2 &&
            (observed.at("stage") == "none" || observed.at("stage") == "aborted") &&
            observed.at("raw_queued") == "0" && observed.at("raw_inflight_seq") == "0" &&
            observed.at("semantic_queue") == "0") {
            if (can_history_anchors_.size() == 16) {
                can_history_anchors_.pop_front();
            }

            can_history_anchors_.push_back(observed);
        }
    } catch (const std::exception &failure) {
        observed = unavailable(failure.what());
    }

    return observed;
}

void Session::prepare_android_media_input() {}

void Session::bound_android_request(const Json &, std::chrono::steady_clock::time_point) {}

void Session::request_frontend_stop() {}

int Session::android_provider_budget() const {
    return 2500;
}

void Session::retire_android_transaction_for_flush(bool) {}

void Session::reset_android_identity_for_new_boot() {}

ChildProcess launch_session_child(const ProcessSpec &spec, const std::filesystem::path &directory,
                                  const std::string &session_id, std::uint64_t nonce) {
    return launch_session_process(spec, directory, session_id, nonce);
}
} // namespace voyemu
