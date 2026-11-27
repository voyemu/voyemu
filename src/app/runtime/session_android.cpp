#include "error.hpp"
#include "session_internal.hpp"
#include <charconv>
#include <cstdio>

namespace voyemu {
using namespace session_detail;

void validate_app_launch(const std::string &package, const std::string &screen,
                         const std::string &boot_id) {
    static const std::regex shape(R"(^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$)");

    if (package.size() > 255 || !std::regex_match(package, shape)) {
        throw VoyemuError("TEST_ARGUMENT", "Android package identifier required");
    }

    if (screen != "primary" && screen != "secondary") {
        throw VoyemuError("TEST_ARGUMENT", "app screen must be primary or secondary");
    }

    if (!android_boot_id_valid(boot_id)) {
        throw VoyemuError("TEST_ARGUMENT", "complete Linux boot_id required");
    }
}

Json launch_android_app(
        const std::string &package, const std::string &screen, const std::string &boot_id,
        const std::string &component, unsigned display_id,
        const std::function<std::string()> &fenced_boot,
        const std::function<ProcessResult(const std::vector<std::string> &, int)> &run) {
    validate_app_launch(package, screen, boot_id);

    if ((screen == "primary" && display_id != 0) || (screen == "secondary" && display_id == 0)) {
        throw VoyemuError("APP_DISPLAY", "current logical display mapping unavailable");
    }

    if (fenced_boot() != boot_id) {
        throw VoyemuError("APP_STALE", "guest boot differs before package resolution");
    }

    static const std::regex requested_component(R"(^[A-Za-z0-9_.]+/[A-Za-z0-9_.]+$)");

    if (!component.empty() &&
        (component.size() > 512 || !std::regex_match(component, requested_component) ||
         !component.starts_with(package + "/"))) {
        throw VoyemuError("TEST_ARGUMENT", "component must belong to package");
    }

    std::vector<std::string> resolve{"shell",   "cmd",    "package", "resolve-activity",
                                     "--brief", "--user", "0"};

    if (component.empty()) {
        resolve.insert(resolve.end(), {"-a", "android.intent.action.MAIN", "-c",
                                       "android.intent.category.LAUNCHER", package});
    } else {
        resolve.insert(resolve.end(), {"-n", component});
    }

    const auto resolved = run(resolve, 3000);

    if (resolved.timed_out || resolved.exit_code || resolved.output.size() > 8192) {
        throw VoyemuError("APP_RESOLVE", "launcher activity resolution failed");
    }

    // Android --brief writes ResolveInfo metadata before the component. Parse the
    // unique installed activity instead of treating the whole reply as its name.
    const auto activity = resolved_home_component(resolved.output, package);

    if (!activity) {
        throw VoyemuError("APP_UNLAUNCHABLE", "package resolution has no unique activity");
    }

    if (!component.empty() && activity != resolved_home_component(component, package)) {
        throw VoyemuError("APP_UNLAUNCHABLE", "resolved component differs from request");
    }

    const auto &text = *activity;

    if (fenced_boot() != boot_id) {
        throw VoyemuError("APP_STALE", "guest boot changed before launch");
    }

    ProcessResult started;
    try {
        started = run({"shell", "am", "start", "--user", "0", "--display",
                       std::to_string(display_id), "-a", "android.intent.action.MAIN", "-c",
                       "android.intent.category.LAUNCHER", "-n", text},
                      5000);
    } catch (...) {
        throw VoyemuError("APP_LAUNCH_UNKNOWN", "transport failed after launch dispatch");
    }

    if (started.timed_out) {
        throw VoyemuError("APP_LAUNCH_UNKNOWN", "launch dispatch timed out");
    }

    if (started.exit_code || started.output.size() > 8192 ||
        started.output.find("Error") != std::string::npos ||
        started.output.find("Exception") != std::string::npos ||
        started.output.find("Starting: Intent") == std::string::npos) {
        throw VoyemuError("APP_LAUNCH_UNKNOWN", "ActivityManager acceptance unconfirmed");
    }

    try {
        if (fenced_boot() != boot_id) {
            throw VoyemuError("APP_LAUNCH_UNKNOWN", "guest identity changed after dispatch");
        }
    } catch (...) {
        throw VoyemuError("APP_LAUNCH_UNKNOWN", "guest identity changed after dispatch");
    }

    return {{"ok", true},
            {"accepted", true},
            {"package", package},
            {"component", text},
            {"screen", screen},
            {"display_id", display_id},
            {"boot_id", boot_id},
            {"visible_effect_verified", false},
            {"application_ready", false}};
}

void Session::attach_android(const Json &input, bool explicit_cold_boot) {
    auto specification = input;

    if (machine_start_ && !machine_program_.empty() && specification.contains("frontend")) {
        auto &frontend = specification["frontend"];

        if (frontend.value("backend", std::string{}) == "voyemu" ||
            builtin_program_name(frontend.at("executable").get<std::string>())) {
            frontend["executable"] = machine_program_.string();
        }
    }

    if (machine_start_) {
        normalize_ready_android_adb(specification);
    }

    if (specification.contains("interguest_network")) {
        validate_qnx_interguest_contract(specification.at("interguest_network"));
    }

    if (specification.contains("network")) {
        validate_android_network_contract(specification.at("network"));
    }

    const bool passion_wheel = passion_presentation(specification);

    if (passion_wheel) {
        passion_wheel_validate(specification);
    }

    const bool wheel_unsupported = !passion_wheel && qinggan11_wheel_unsupported(specification);
    const auto boot_trace_arguments =
            android_boot_trace_arguments(std::getenv("VOYEMU_ANDROID_BOOT_TRACE"));
    const bool audio_output = android_audio_output_enabled(specification);
    const bool diagnostic_native = specification.contains("diagnostic_native");
    const bool windows_renderer = android_windows_renderer(specification, diagnostic_native);
    std::lock_guard lifecycle(lifecycle_mutex_);
    std::lock_guard lock(mutex_);
    AndroidIdentityScope identity_scope(android_identity_scope_depth_, android_identity_operation_);
    validate_pins(specification, machine_start_);
    auto port = specification.at("port").get<unsigned>();

    if (android_adb_console_port_ && android_adb_console_port_ != port) {
        throw VoyemuError("ANDROID_ADB_OWNER", "retained console port cannot change");
    }

    if (port < 5554 || port > 5682 || port % 2 || port == 5562) {
        throw VoyemuError("ANDROID_PORT", "isolated free port required");
    }

    // A start that selected the same free tuple concurrently leased it first; the lease is held
    // until this session's SDK is gone, so free listeners never stand for an unclaimed tuple.
    if (!android_port_lease_ || android_port_lease_->console() != port) {
        auto lease = std::make_unique<AndroidPortLease>(port);

        if (!lease->held()) {
            throw VoyemuError("ANDROID_PORT_BUSY", "another session leases the console tuple");
        }

        android_port_lease_ = std::move(lease);
    }

    if (!tcp_port_free(port) || !tcp_port_free(port + 1)) {
        throw VoyemuError("ANDROID_PORT_BUSY", "another process listens on the console tuple");
    }

    if (specification.contains("sdk_control")) {
        const auto &control = specification.at("sdk_control");
        const auto grpc = control.at("grpc_port").get<unsigned>();
        const std::filesystem::path discovery = control.at("discovery_root").get<std::string>();

        if (grpc < 1024 || grpc > 65535 || grpc == port || grpc == port + 1 ||
            !tcp_port_free(grpc) || !discovery.is_absolute()) {
            throw VoyemuError("ANDROID_SDK_CONTROL",
                              "isolated port and absolute discovery root required");
        }
    }

    auto machine = std::filesystem::path(specification.at("machine").get<std::string>());
    auto base = std::filesystem::path(specification.at("base").get<std::string>());

    if (!machine.is_absolute() || !base.is_absolute() ||
        !std::filesystem::exists(machine / "machine.json")) {
        throw VoyemuError("ANDROID_MACHINE", "prepared private machine required");
    }

    const auto project = qnx_project(directory_, session_id_);

    for (const auto &path : {machine, base}) {
        if (!path.is_absolute() || path.lexically_normal() != path ||
            std::filesystem::canonical(path) != path) {
            throw VoyemuError("ANDROID_MACHINE", "canonical machine directory required");
        }

        if (!machine_start_) {
            const auto relative = path.lexically_relative(project);

            if (relative.empty() || relative.is_absolute()) {
                throw VoyemuError("ANDROID_MACHINE", "canonical project-owned machine required");
            }

            for (const auto &part : relative) {
                if (part == "..") {
                    throw VoyemuError("ANDROID_MACHINE", "foreign project machine forbidden");
                }
            }
        }
    }

    android_identity_ = false;
    android_clock_observed_ = false;
    android_clock_correction_attempted_ = false;
    android_clock_exit_code_ = -1;
    android_clock_arrival_ = {};
    android_transport_ready_ = false;
    android_transport_attempted_ = false;
    android_transport_boot_.clear();
    wheel_provisioned_ = false;
    android_seen_guest_ = false;
    android_revision_ = 0;
    theme_.reset();
    oem_language_.reset();
    next_android_ = {};
    next_oem_settings_ = {};
    android_boot_completed_ = false;
    android_displays_ready_ = false;
    android_display_activated_ = false;
    android_canvas_refreshed_ = false;
    primary_home_ready_ = false;
    clear_android_home_delivery(deliveries_["android"]);
    clear_android_camera_delivery(deliveries_["android"]);
    next_display_observation_ = {};
    next_display_activation_ = {};
    auto avd = specification.at("avd_name").get<std::string>();

    if (avd.empty() || avd.find_first_of("/\\\r\n") != std::string::npos) {
        throw VoyemuError("ANDROID_AVD", "invalid name");
    }

    auto config_template = specification.at("config_template").get<std::string>();
    std::string config_sha256;

    for (const auto &pin : specification.at("pins")) {
        if (pin.at("path").get<std::string>() == config_template) {
            config_sha256 = pin.at("sha256").get<std::string>();
        }
    }

    if (machine_start_) {
        normalize_android_disk_backings(
                machine,
                std::filesystem::path(specification.at("android_sdk_root").get<std::string>()) /
                        "emulator" / ("qemu-img" + std::string(os::executable_suffix)),
                specification.value("system_binding", Json()));
    }

    const auto content = directory_.parent_path().parent_path() / "android";
    prepare_android_emulator_home(project, content);

    if (machine_start_) {
        const auto empty_data = machine / "data";

        if (std::filesystem::is_directory(empty_data) && std::filesystem::is_empty(empty_data)) {
            std::filesystem::remove(empty_data);
        }
    }

    auto checkpoint_spec = specification;

    if (config_sha256.empty() && machine_start_) {
        android_regular_input(config_template);

        if (std::filesystem::file_size(config_template) > 65536) {
            throw VoyemuError("ANDROID_AVD", "bounded runtime configuration required");
        }

        config_sha256 = sha256_file(config_template);
        checkpoint_spec["pins"].push_back({{"path", config_template}, {"sha256", config_sha256}});
    }

    auto quickboot = std::make_unique<AndroidQuickBoot>(
            machine, android_quickboot_key(checkpoint_spec), content);
    const auto checkpoint = machine_start_ ? quickboot->runtime_checkpoint() : quickboot->inspect();
    const bool resume = checkpoint.resume && !explicit_cold_boot;
    const auto boot_nonce = resume ? checkpoint.boot_nonce : session_id_;
    // Invalidate before any launch/config write: a crashed or externally closed SDK cannot restore
    // stale disks.
    quickboot->begin();
    const auto generation = android_generation_ + 1;
    const auto home = directory_ /
                      (generation == 1 ? "avd-home" : "avd-home-g" + std::to_string(generation));
    prepare_android_avd_impl(home, machine, avd, config_template, config_sha256, base,
                             machine_start_, specification.value("api", 28u), diagnostic_native,
                             content, specification.value("system_binding", Json()),
                             specification.value("previous_machine", std::string{}));
    android_quickboot_ = std::move(quickboot);
    android_resume_ = resume;
    android_boot_nonce_ = boot_nonce;
    android_generation_ = generation;
    android_home_ = home;
    reset_android_transaction();
    android_identity_mismatch_ = false;

    // Reattach from the prepared discovery root so the next QuickBoot key stays stable.
    if (specification.contains("sdk_control")) {
        prepare_android_emulator_home(
                project, session_sdk_registration_directory(directory_, diagnostic_native));
    }

    android_spec_ = specification;
    android_spec_.erase("owned_adb");
    ProcessSpec spec;
    spec.executable = specification.at("executable").get<std::string>();
    spec.directory = directory_;
    spec.output = directory_ / "android.log";
    // The window plays the OEM boot animation, so the guest starts without the SDK image fallback,
    // which would otherwise show in guest frames that reach the window during a boot.
    spec.arguments = {"-avd",
                      avd,
                      "-port",
                      std::to_string(port),
                      "-sysdir",
                      base.string(),
                      "-datadir",
                      content.string(),
                      "-data",
                      (machine / "userdata-qemu.img").string(),
                      "-encryption-key",
                      (machine / "encryptionkey.img").string(),
                      "-cache",
                      (content / "cache.img").string(),
                      "-writable-system",
                      "-fixed-scale",
                      "-no-boot-anim",
                      "-prop",
                      "qemu.voyemu.token=" + session_id_};

    if (specification.contains("system_binding")) {
        const auto system = android_system_binding(specification);
        spec.arguments.insert(spec.arguments.end(), {"-system", system.raw.string()});
    }

    if (android_resume_) {
        spec.arguments.insert(spec.arguments.end(),
                              {"-snapshot", AndroidQuickBoot::snapshot_name, "-no-snapshot-save"});
    } else {
        spec.arguments.push_back("-no-snapshot");
    }

    auto gpu_mode = specification.value("gpuMode", std::string{});
    auto features = specification.value("features", Json::object());
    std::map<std::string, std::string> renderer_environment;

    if (windows_renderer) {
        const char *inherited = std::getenv("PATH");
        const auto renderer =
                machine_start_ ? prepare_windows_android_renderer_layout(
                                         specification.at("android_sdk_root").get<std::string>(),
                                         home, inherited ? inherited : "")
                               : prepare_windows_android_renderer(
                                         specification.at("android_sdk_root").get<std::string>(),
                                         home, inherited ? inherited : "");
        gpu_mode = renderer.gpu_mode;

        for (const auto &[key, value] : renderer.features.items()) {
            features[key] = value;
        }

        renderer_environment = renderer.environment;
    }

    if (specification.contains("gpuMode") || !gpu_mode.empty()) {
        auto mode = gpu_mode;

        if (mode != "auto" && mode != "auto-no-window" && mode != "host" &&
            mode != "swiftshader_indirect") {
            throw VoyemuError("ANDROID_GPU", "unsupported prepared renderer");
        }

        spec.arguments.insert(spec.arguments.end(), {"-gpu", mode});
    }

    if (passion_camera_identity(specification)) {
        passion_camera_validate(specification, passion_camera_config_text(specification));
    }

    for (const auto &[key, value] : features.items()) {
        spec.arguments.push_back("-feature");
        spec.arguments.push_back(value == "off" ? "-" + key : key);
    }

    static const std::set<std::string> owned_arguments{"-avd",
                                                       "-sysdir",
                                                       "-datadir",
                                                       "-data",
                                                       "-cache",
                                                       "-encryption-key",
                                                       "-wipe-data",
                                                       "-qemu",
                                                       "-port",
                                                       "-ports",
                                                       "-prop",
                                                       "-snapshot",
                                                       "-no-snapshot",
                                                       "-no-snapshot-load",
                                                       "-no-snapshot-save",
                                                       "-read-only",
                                                       "-audio",
                                                       "-no-audio",
                                                       "-noaudio",
                                                       "-no_audio",
                                                       "-allow-host-audio",
                                                       "-allow_host_audio"};

    for (const auto &arg : specification.value("args", Json::array())) {
        auto value = arg.get<std::string>();

        if (owned_arguments.contains(value) ||
            (specification.contains("system_binding") && value == "-system")) {
            throw VoyemuError("ANDROID_AVD", "prepared partition/configuration override forbidden");
        }

        spec.arguments.push_back(value);
    }

    auto environment = specification.value("env", Json::object());

    for (const auto &[key, value] : environment.items()) {
        spec.environment[key] = value.get<std::string>();
    }

    const auto emulator_home = directory_ / "emulator-home", temporary = directory_ / "tmp";
    prepare_android_emulator_home(project, emulator_home);
    prepare_android_emulator_home(project, temporary);
    android_session_environment(spec, directory_);
    spec.environment["ANDROID_AVD_HOME"] = home.string();
    auto sdk = specification.at("android_sdk_root").get<std::string>();
    spec.environment["ANDROID_HOME"] = sdk;
    spec.environment["ANDROID_SDK_ROOT"] = sdk;

    for (const auto &[key, value] : renderer_environment) {
        spec.environment[key] = value;
    }

    spec.arguments.insert(spec.arguments.begin(), boot_trace_arguments.begin(),
                          boot_trace_arguments.end());

    if (diagnostic_native && specification.contains("diagnostic_audio")) {
        throw VoyemuError("ANDROID_AUDIO_DIAGNOSTIC", "direct SDK route required");
    }

    const auto audio = configure_android_audio(
            spec, audio_output, android_emulator_audio_output(diagnostic_native),
            specification.value("diagnostic_audio", Json()), directory_, generation);
    // The window mode follows the audio route, before the engine identity reads the arguments.
    android_sdk_hidden_window(spec.arguments, audio.full_engine);
    configure_android_native_backend(spec, specification, port, generation);
    const auto audio_delivery = android_audio_delivery(audio);
    logging::write(
            logging::Level::info, "android", "audio.configured",
            {{"output", audio.driver.empty() ? "disabled" : audio.driver},
             {"input", "disabled"},
             {"state", audio_delivery.at("state")},
             {"reason", audio.reason},
             {"engine", android_sdk_headless_backend(spec.arguments) ? "headless" : "full"}});
    // Keep backend board arguments last, after every owned emulator option.
    const auto machine_arguments = android_sdk_machine_arguments(
            os::host_windows, diagnostic_native,
            specification.value("guest_arch", std::string("arm64-v8a")));
    spec.arguments.insert(spec.arguments.end(), machine_arguments.begin(), machine_arguments.end());
    {
        // Every generation starts with an empty USB port; a stale socket of a lost SDK process
        // would make QEMU fail to bind its QMP channel.
        android_qmp_ = android_qmp_endpoint(session_id_, port);
        usb_drive_attached_ = false;

        if (android_qmp_.is_string()) {
            std::filesystem::remove(android_qmp_.get<std::string>());
        }

        const bool boundary = std::find(spec.arguments.begin(), spec.arguments.end(), "-qemu") !=
                              spec.arguments.end();
        const auto usb_arguments = android_usb_arguments(boundary, android_qmp_);
        spec.arguments.insert(spec.arguments.end(), usb_arguments.begin(), usb_arguments.end());
    }

    if (specification.contains("interguest_network")) {
        if (!interguest_link_) {
            interguest_link_ = std::make_unique<InterguestLink>();
        }

        auto network_port = interguest_link_->status().port;

        if (!network_port) {
            network_port = interguest_link_->start(directory_, session_id_, diagnostic_native);
        }

        const bool boundary = std::find(spec.arguments.begin(), spec.arguments.end(), "-qemu") !=
                              spec.arguments.end();
        const auto network_arguments = android_interguest_arguments(
                network_port, boundary, android_interguest_listener && !diagnostic_native);
        spec.arguments.insert(spec.arguments.end(), network_arguments.begin(),
                              network_arguments.end());
    }

    // The outbound NAT interface stays optional and last: the legacy eth0 backend must keep its
    // emergence order.
    if (specification.contains("network")) {
        const bool boundary = std::find(spec.arguments.begin(), spec.arguments.end(), "-qemu") !=
                              spec.arguments.end();
        const auto network_arguments = android_network_arguments(boundary);
        spec.arguments.insert(spec.arguments.end(), network_arguments.begin(),
                              network_arguments.end());
    }

    sdk_descriptor_.reset();
    stop_owned_android_adb();

    if (!android_adb_) {
        android_adb_ = std::make_shared<AndroidEmbeddedAdb>(port);
        android_adb_console_port_ = port;
    }

    auto sink = std::make_unique<AndroidSdkAdbSink>();
    const auto notification_port = std::to_string(sink->port());
    spec.environment["ANDROID_ADB_SERVER_ADDRESS"] = "127.0.0.1";
    spec.environment["ANDROID_ADB_SERVER_PORT"] = notification_port;
    spec.environment["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:" + notification_port;
    spec.environment["ADB_TRACE"] = "";
    spec.environment["ADB_VENDOR_KEYS"] = "";
    android_spec_["owned_adb"] = {
            {"schema", 1}, {"owner", session_id_}, {"console_port", port}, {"adbd_port", port + 1}};
    // The SDK selects its backend from the arguments, independently of VoyEmu presentation.
    android_sdk_headless_ = android_sdk_headless_backend(spec.arguments);

    if (specification.value("acceleration", std::string{}) == "required") {
        require_android_acceleration(spec);
    }

    record_android_processes(true);
    try {
        android_ = ChildProcess::launch(spec);
        record_android_processes(false);

        if (specification.contains("interguest_network") && !diagnostic_native) {
            interguest_link_->bind_android(android_.pid());
        }

        android_adb_->attach([this, pid = android_.pid(), port] {
            // The connector can be joined while lifecycle code holds the state lock.
            std::unique_lock lock(mutex_, std::try_to_lock);

            return lock.owns_lock() && android_adb_sink_ && android_.pid() == pid &&
                   android_.alive() && android_.owns_tcp_listener(port) &&
                   android_.owns_tcp_listener(port + 1);
        });
        android_adb_sink_ = std::move(sink);
    } catch (...) {
        stop_owned_android_adb();
        android_.terminate(1000);
        throw;
    }

    android_powered_ = true;
    android_started_ = std::chrono::steady_clock::now();
    deliveries_["android"] = {
            {"status", "booting"},
            {"powered", true},
            {"lifecycle_supported", true},
            {"generation", android_generation_},
            {"pid", android_.pid()},
            {"serial", "emulator-" + std::to_string(port)},
            {"quickboot",
             {{"mode", android_resume_ ? "restore_requested" : "cold"},
              {"reason", explicit_cold_boot ? "explicit_cold_boot" : checkpoint.reason},
              {"checkpoint_saved", false}}},
            {"usb_drive", {{"attached", false}}},
            {"audio", audio_delivery}};
    deliveries_["android"]["pid_namespace"] = android_.pid_namespace();
    deliveries_["android"]["owned_adb"] = android_spec_.at("owned_adb");

    if (wheel_unsupported) {
        deliveries_["android"]["wheel"] = android_spec_.at("wheel_capability");
        deliveries_["android"]["wheel_bootstrap"] = {{"status", "unsupported"},
                                                     {"supported", false},
                                                     {"reason", "provider_not_installed"}};
    }
}

void Session::record_android_processes(bool launch_pending) {
    if (android_spec_.empty()) {
        return;
    }

    const auto path = directory_ / "session-owner.json";
    auto owner = read_private_json(path, 16384);
    const auto creator = os::current_process();

    if (owner.at("session_id") != session_id_ || owner.at("creator_pid") != creator) {
        throw VoyemuError("SESSION_OWNER", "process publication owner differs");
    }

    const auto port = android_spec_.at("port").get<unsigned>(),
               grpc = android_spec_.value("sdk_control", Json::object())
                              .value("grpc_port", port + 30000);
    const auto previous = owner.value("android_processes", Json::object());
    owner["android_processes"] = {{"generation", android_generation_},
                                  {"phase", launch_pending ? "launch_pending" : "recorded"},
                                  {"sdk_pid", android_.pid()},
                                  {"sdk_pid_namespace", android_.pid_namespace()},
                                  {"frontend_pid", frontend_.pid()},
                                  {"console_port", port},
                                  {"grpc_port", grpc},
                                  {"adbd_port", port + 1}};

    if (previous.value("sdk_pid", std::int64_t{0}) == android_.pid() &&
        previous.value("generation", std::uint64_t{0}) == android_generation_ &&
        previous.contains("sdk_start")) {
        owner["android_processes"]["sdk_start"] = previous.at("sdk_start");

        if (previous.contains("sdk_identity")) {
            owner["android_processes"]["sdk_identity"] = previous.at("sdk_identity");
        }
    } else if (!launch_pending) {
        owner["android_processes"].update(android_launch_identity(android_.pid()));
    }

    write_private_json(path, owner);
}

namespace {
constexpr unsigned local_adb_server_port = 5037;

bool register_emulator_with_adb(android_console_detail::Socket &server, unsigned console_port) {
    using namespace std::chrono_literals;
    const auto deadline = std::chrono::steady_clock::now() + 500ms;
    const auto ports = std::to_string(console_port) + "," + std::to_string(console_port + 1);
    const auto request = "host:connect:emu:" + ports;
    char size[5]{};
    std::snprintf(size, sizeof(size), "%04x", static_cast<unsigned>(request.size()));
    server.send(size + request, deadline);

    std::string response;
    const auto connected = "Connected to emulator on ports " + ports;
    const auto registered = "Emulator already registered on port " +
                            std::to_string(console_port + 1);

    while (response.size() < 8) {
        response += server.receive(deadline);
    }

    if (!response.starts_with("OKAY")) {
        return false;
    }

    std::size_t length = 0;
    const auto size_end = response.data() + 8;
    const auto [end, error] = std::from_chars(response.data() + 4, size_end, length, 16);

    if (error != std::errc{} || end != size_end || length > 4096) {
        return false;
    }

    while (response.size() < 8 + length) {
        response += server.receive(deadline);
    }

    const auto payload = std::string_view(response).substr(8, length);

    return payload == connected || payload == registered;
}
} // namespace

void Session::publish_android_to_local_adb(std::chrono::steady_clock::time_point now) {
    if (android_adb_published_ || !android_identity_ || now < next_local_adb_publish_) {
        return;
    }

    using namespace std::chrono_literals;
    next_local_adb_publish_ = now + 5s;
    const auto port = android_adb_console_port_;

    if (!android_adb_sink_ || !android_.alive() || !android_.owns_tcp_listener(port) ||
        !android_.owns_tcp_listener(port + 1)) {
        return;
    }

    try {
        std::optional<android_console_detail::Socket> server(std::in_place);
        try {
            server->connect(local_adb_server_port, std::chrono::steady_clock::now() + 100ms);
        } catch (const android_console_detail::Disconnected &) {
            const auto sdk = android_spec_.at("android_sdk_root").get<std::string>();
            ProcessSpec starter;
            starter.executable = std::filesystem::path(sdk) / "platform-tools" /
                                 (os::host_windows ? "adb.exe" : "adb");
            starter.arguments = {"start-server"};
            starter.environment["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:5037";
            const auto result = execute(starter, 3000, 4096);

            if (result.timed_out || result.exit_code != 0) {
                throw VoyemuError("ANDROID_ADB_SERVER", "local ADB server could not be started");
            }

            // A failed connect leaves the original socket unusable on some hosts.
            server.emplace();
            server->connect(local_adb_server_port, std::chrono::steady_clock::now() + 100ms);
        }

        if (!register_emulator_with_adb(*server, port)) {
            throw VoyemuError("ANDROID_ADB_SERVER",
                              "local ADB server rejected emulator registration");
        }

        android_adb_published_ = true;
    } catch (const std::exception &error) {
        logging::try_write(android_adb_registration_warned_ ? logging::Level::debug
                                                            : logging::Level::info,
                           "android", "local_adb.registration_failed", "reason", error.what());
        android_adb_registration_warned_ = true;
    }
}

void Session::stop_owned_android_adb() {
    android_adb_published_ = false;
    android_adb_registration_warned_ = false;
    next_local_adb_publish_ = {};
    cancel_android_identity_probe();
    android_identity_proof_operation_ = 0;

    if (android_adb_) {
        android_adb_->detach();
    }

    android_adb_sink_.reset();
}

std::shared_ptr<AndroidEmbeddedAdb> Session::owned_android_adb(const Json &specification,
                                                               std::int64_t expected_pid,
                                                               std::uint64_t expected_generation,
                                                               bool require_backend) {
    std::lock_guard lock(mutex_);
    const auto &binding = specification.at("owned_adb");
    const auto port = specification.at("port").get<unsigned>();

    if (!android_adb_ || !android_adb_sink_ || android_adb_console_port_ != port ||
        expected_pid < 2 || expected_pid != android_.pid() ||
        expected_generation != android_generation_ || binding != android_spec_.at("owned_adb") ||
        binding.at("schema") != 1 || binding.at("owner") != session_id_ ||
        binding.at("console_port") != port || binding.at("adbd_port") != port + 1) {
        throw VoyemuError("ANDROID_ADB_OWNER", "SDK generation changed");
    }

    if (require_backend && (!android_.alive() || !android_.owns_tcp_listener(port) ||
                            !android_.owns_tcp_listener(port + 1))) {
        throw VoyemuError("ANDROID_IDENTITY_NOT_READY", "retained SDK listeners unavailable");
    }

    return android_adb_;
}

ProcessResult Session::execute_android_adb(const Json &specification,
                                           const std::vector<std::string> &arguments,
                                           int timeout_ms, std::size_t limit,
                                           std::int64_t expected_pid,
                                           std::uint64_t expected_generation) {
    if (auto result = execute_android_transaction(specification, arguments, timeout_ms, limit,
                                                  expected_pid, expected_generation)) {
        return *result;
    }

    auto fence = [&] {
        (void)owned_android_adb(specification, expected_pid, expected_generation);
    };
    const bool console = !arguments.empty() && arguments.front() == "emu";
    ProcessResult result;

    if (console) {
        result = android_console_command(specification.at("port").get<unsigned>(),
                                         directory_ / "emulator-home", arguments, timeout_ms, limit,
                                         fence);
    } else {
        const auto [transport, lease] = [&] {
            std::lock_guard lock(mutex_);
            auto current = owned_android_adb(specification, expected_pid, expected_generation);

            return std::pair{current, current->lease()};
        }();
        result = transport->run(arguments, timeout_ms, limit, {}, lease);
    }

    (void)owned_android_adb(specification, expected_pid, expected_generation,
                            arguments != std::vector<std::string>{"emu", "kill"});

    return result;
}

ProcessResult Session::adb(const std::vector<std::string> &arguments, int timeout_ms) {
    const auto started = std::chrono::steady_clock::now();
    std::string_view operation = "unknown";

    if (!arguments.empty() && arguments[0] == "push") {
        operation = "push";
    } else if (arguments.size() > 1 && arguments[0] == "emu") {
        operation = arguments[1] == "avd"            ? "emu.avd"
                    : arguments[1] == "kill"         ? "emu.kill"
                    : arguments[1] == "multidisplay" ? "emu.multidisplay"
                                                     : "emu.other";
    } else if (arguments.size() > 1 && arguments[0] == "shell") {
        operation = "shell.other";
        const std::string_view command = arguments[1];
        constexpr std::array<std::pair<std::string_view, std::string_view>, 7> allowed{
                {{"getprop", "shell.getprop"},
                 {"content", "shell.content"},
                 {"dumpsys", "shell.dumpsys"},
                 {"cmd", "shell.cmd"},
                 {"am", "shell.am"},
                 {"service", "shell.service"},
                 {"sync", "shell.sync"}}};

        if (arguments ==
            std::vector<std::string>{"shell", "cat", "/proc/sys/kernel/random/boot_id"}) {
            operation = "shell.boot_id";
        }

        for (const auto &[verb, label] : allowed) {
            const bool direct = command == verb ||
                                (command.size() > verb.size() && command.starts_with(verb) &&
                                 command[verb.size()] == ' ');
            const bool quoted = command.size() > verb.size() + 2 && command[0] == '\'' &&
                                command.substr(1, verb.size()) == verb &&
                                command[verb.size() + 1] == '\'' && command[verb.size() + 2] == ' ';

            if (direct || quoted) {
                operation = label;
                break;
            }
        }
    }

    auto finish = [&](const ProcessResult *result, const char *status) noexcept {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started)
                                     .count();
        // Diagnostics contain constant categories and scalar metrics, never argv, output or
        // credentials.
        try {
            logging::write(logging::Level::debug, "android", "adb.completed",
                           {{"operation", operation},
                            {"elapsed_ms", elapsed},
                            {"timeout_ms", timeout_ms},
                            {"status", status},
                            {"exit_code", result ? result->exit_code : -1},
                            {"output_bytes", result ? result->output.size() : 0}});
        } catch (...) { /* Ignored: observability must not change delivery or exception behavior. */
        }
    };
    const auto specification = android_spec_;
    const auto pid = android_.pid();
    const auto generation = android_generation_;
    // Only tick's normal Android stage lends state access; its lifecycle lock remains held.
    auto *state_lock = android_io_state_lock_;
    const bool lent = state_lock && state_lock->owns_lock();
    struct Relock {
        std::unique_lock<std::recursive_mutex> *value;
        bool lent;

        ~Relock() {
            if (lent && !value->owns_lock()) {
                value->lock();
            }
        }
    } relock{state_lock, lent};

    if (lent) {
        state_lock->unlock();
    }

    try {
        auto result = execute_android_adb(specification, arguments, timeout_ms, 128 * 1024, pid,
                                          generation);
        finish(&result, result.timed_out ? "timeout" : result.exit_code ? "failed" : "ok");

        return result;
    } catch (...) {
        finish(nullptr, "exception");
        throw;
    }
}

bool android_nonce_matches(std::string_view observed, std::string_view session_id,
                           std::string_view retained_nonce, bool resumed) {
    return observed == session_id || (resumed && observed == retained_nonce);
}

void Session::stop_android(std::unique_lock<std::recursive_mutex> &state, bool save_checkpoint) {
    close_passion_display_power();
    AndroidIdentityScope identity_scope(android_identity_scope_depth_, android_identity_operation_);
    cancel_android_identity_probe();
    android_identity_proof_operation_ = 0;

    if (android_identity_mismatch_) {
        throw VoyemuError("ANDROID_IDENTITY_MISMATCH",
                          "mismatched generation cannot authorize shutdown");
    }

    const Restore stopping(android_identity_stopping_, true);
    const auto observer = ui_observer_;
    auto forget_observer = [&] {
        if (!observer) {
            return;
        }

        clear_ui_observer_metadata(directory_, session_id_);
        ui_observer_.reset();
    };

    if (observer) {
        // A source collection can hold the observer lock while waiting for a
        // Session generation fence. Lifecycle stays held while we lend state.
        state.unlock();
        bool closed;
        try {
            closed = observer->stop();
        } catch (...) {
            state.lock();
            throw;
        }

        state.lock();
        deliveries_["android"]["ui_observer"]["cleanup_verified"] = closed;

        if (closed) {
            forget_observer();
        } else {
            frontend_releases_verified_ = false;
        }
    }

    if (android_spec_.empty()) {
        android_.terminate(5000);
        stop_owned_android_adb();
        forget_observer();

        return;
    }

    auto port = android_spec_.at("port").get<unsigned>();
    auto released = [&] {
        return tcp_port_free(port) && tcp_port_free(port + 1);
    };
    bool identity_verified = false, kill_submitted = false, guest_synced = false,
         snapshot_saved = false, owned_shutdown = false;
    Json presave_receipt;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto assert_identity = [&] {
        assert_android_identity_until(deadline);
    };
    // A launched SDK may not have bound either port yet. Free ports alone do
    // not end this lifetime; keep probing until identity, exit or the deadline.
    const auto stopping_pid = android_.pid();
    const auto stopping_generation = android_generation_;
    identity_verified = await_android_stop_identity(
            [&] {
                return android_.alive();
            },
            released,
            [&] {
                return std::chrono::steady_clock::now() < deadline;
            },
            [&] {
                // Missing endpoint during SDK teardown is retried; mismatched identity never
                // authorizes a kill.
                try {
                    assert_identity();

                    return true;
                } catch (const std::exception &error) {
                    if (std::string(error.what()).starts_with("ANDROID_IDENTITY_MISMATCH")) {
                        throw;
                    }

                    return false;
                }
            },
            [&] {
                // The embedded ADB connector fences this generation through mutex_. Lend state
                // while waiting so an early stop can establish its owned transport. Lifecycle
                // remains held and prevents a concurrent replacement of the SDK generation.
                state.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                state.lock();

                if (android_.pid() != stopping_pid || android_generation_ != stopping_generation) {
                    throw VoyemuError("ANDROID_STOP_IDENTITY_UNKNOWN",
                                      "SDK generation changed while stopping");
                }
            });

    if ((!released() || android_.alive()) && !identity_verified) {
        // waitpid-backed ChildProcess retains this launch, not a rediscovered PID. A live child is
        // stopped even when another session holds its console tuple.
        const bool owned_listeners = android_.owns_tcp_listener(port) ||
                                     android_.owns_tcp_listener(port + 1);

        if (!allow_unready_android_stop(android_.alive(), false)) {
            throw VoyemuError(
                    "ANDROID_STOP_IDENTITY_UNKNOWN",
                    "SDK listeners remain without verified guest or host ownership; session not marked stopped");
        }

        deliveries_["android"]["shutdown"] = {
                {"mode", "host_only"},         {"identity_verified", false},
                {"emu_kill_submitted", false}, {"guest_sync_completed", false},
                {"ports_released", false},     {"wrapper_terminal", false},
                {"owned_clean_exit", false}};
        deliveries_["android"]["quickboot"]["checkpoint_saved"] = false;
        deliveries_["android"]["quickboot"]["save_status"] = "unready_host_termination";

        // No SDK command or checkpoint is permitted without guest identity.
        if (android_adb_) {
            android_adb_->detach();
        }

        android_.terminate(5000);
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        while (owned_listeners && !released() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        const bool wrapper_alive = android_.alive();
        const bool ports_released = android_ports_released_after_kill(port, wrapper_alive,
                                                                      released);
        deliveries_["android"]["shutdown"]["ports_released"] = ports_released;
        deliveries_["android"]["shutdown"]["wrapper_terminal"] = !wrapper_alive;
        deliveries_["android"]["shutdown"]["wrapper_exit_code"] = android_.exit_code();
        deliveries_["android"]["shutdown"]["foreign_listeners"] = !owned_listeners &&
                                                                  !ports_released;

        if (!android_host_stop_complete(!wrapper_alive, owned_listeners, ports_released)) {
            throw VoyemuError("ANDROID_STOP_TIMEOUT_UNKNOWN",
                              "host-only termination did not release owned SDK lifetime");
        }

        verify_android_avd_storage_impl(
                android_home_, android_spec_.at("machine").get<std::string>(),
                android_spec_.at("avd_name").get<std::string>(), machine_start_,
                android_spec_.contains("diagnostic_native"), android_spec_);
        stop_owned_android_adb();
        forget_observer();

        return;
    }

    if (identity_verified) {
        // A restore must never resurrect held inputs or an old provider credential.
        flush_android_releases(false);
        bool inputs_released = true;
        try {
            while (!android_events_.empty()) {
                deliver_android_event(android_events_.front());
                android_events_.pop_front();
            }
        } catch (const std::exception &) {
            inputs_released = false;
        }

        owned_shutdown = android_.owns_tcp_listener(port) && android_.owns_tcp_listener(port + 1);
        const int sync_budget = android_stop_sync_budget();
        auto sync = adb({"shell", "sync"}, sync_budget);

        if (sync.timed_out || sync.exit_code) {
            throw VoyemuError("ANDROID_STOP_SYNC_UNKNOWN",
                              "guest writes not flushed; keep emulator running");
        }

        guest_synced = true;
        // A checkpoint holds the device state, so a plugged drive would leave it unloadable by
        // the next session; after the sync above the drive leaves like a pulled stick.
        bool usb_drive_released = !usb_drive_attached_;

        if (!usb_drive_released) {
            try {
                plug_usb_drive(false);
                usb_drive_released = true;
            } catch (const std::exception &error) {
                logging::write(logging::Level::error, "android", "usb.release_failed",
                               {{"error", error.what()}});
            }
        }

        if (save_checkpoint && usb_drive_released && owned_shutdown && inputs_released &&
            frontend_releases_verified_ && android_possible_pressed_.empty() &&
            wheel_provisioned_ && android_quickboot_) {
            // The checkpoint is an optimization. A failed save is recorded and the owned
            // shutdown below still proceeds, exactly as an ineligible checkpoint does.
            try {
                std::error_code space_error;
                const auto space = std::filesystem::space(
                        android_spec_.at("machine").get<std::string>(), space_error);
                const auto budget = android_quickboot_->snapshot_save_budget(
                        space_error ? std::nullopt : std::optional<std::uint64_t>(space.available));
                deliveries_["android"]["quickboot"]["save_budget"] = budget;

                if (budget.at("allowed").get<bool>()) {
                    auto save = [&] {
                        prepare_android_audio(true);
                        auto saved = adb(
                                {"emu", "avd", "snapshot", "save", AndroidQuickBoot::snapshot_name},
                                45000);

                        return !saved.timed_out && saved.exit_code == 0 &&
                               saved.output.find("OK") != std::string::npos &&
                               saved.output.find("KO:") == std::string::npos;
                    };

                    if (android_presave_required(android_spec_)) {
                        auto receipt = android_presave_snapshot(
                                session_id_, android_transport_boot_, android_input_sequence_,
                                [&](const std::string &challenge) {
                                    return wheel_provider("presave", {"save_nonce:s:" + challenge});
                                },
                                save);
                        snapshot_saved = receipt.has_value();

                        if (receipt) {
                            presave_receipt = std::move(*receipt);
                        }
                    } else {
                        snapshot_saved = save();
                    }

                    deliveries_["android"]["quickboot"]["save_status"] =
                            snapshot_saved ? "sdk_snapshot_saved" : "sdk_snapshot_failed";
                } else {
                    deliveries_["android"]["quickboot"]["save_status"] = budget.at("reason");
                    logging::write(logging::Level::info, "android", "checkpoint.save_skipped",
                                   budget);
                }
            } catch (const std::exception &error) {
                snapshot_saved = false;
                presave_receipt = Json();
                deliveries_["android"]["quickboot"]["checkpoint_saved"] = false;
                deliveries_["android"]["quickboot"]["save_status"] = "checkpoint_save_failed";
                try {
                    logging::write(logging::Level::error, "android", "checkpoint.save_failed",
                                   {{"session_id", session_id_},
                                    {"generation", android_generation_},
                                    {"error", error.what()}});
                } catch (...) { /* Ignored: diagnostics never change the shutdown that follows. */
                }
            }
        } else {
            deliveries_["android"]["quickboot"]["save_status"] =
                    "ineligible_owned_clean_checkpoint";
        }

        auto result = adb({"emu", "kill"}, 5000);
        kill_submitted = !result.timed_out && result.exit_code == 0;

        if (!kill_submitted && !released()) {
            throw VoyemuError("ANDROID_STOP_UNKNOWN", "identity-checked SDK kill did not complete");
        }
    }

    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while (!released() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    if (!released()) {
        deliveries_["android"]["shutdown"] = {{"identity_verified", identity_verified},
                                              {"emu_kill_submitted", kill_submitted},
                                              {"guest_sync_completed", guest_synced},
                                              {"ports_released", false}};
        throw VoyemuError("ANDROID_STOP_TIMEOUT_UNKNOWN",
                          "owned SDK listeners remain; session not marked stopped");
    }

    // A forced host termination is not a clean SDK checkpoint boundary.
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while (android_.alive() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    const bool clean_exit = !android_.alive() && android_.exit_code() == 0;
    android_.terminate(5000);
    verify_android_avd_storage_impl(android_home_, android_spec_.at("machine").get<std::string>(),
                                    android_spec_.at("avd_name").get<std::string>(), machine_start_,
                                    android_spec_.contains("diagnostic_native"), android_spec_);
    const bool final_released = android_ports_released_at_stop(port, released);

    if (!final_released) {
        throw VoyemuError("ANDROID_STOP_PORT_UNKNOWN",
                          "SDK port was reoccupied; session not marked stopped");
    }

    if (machine_start_) {
        normalize_android_disk_backings(
                android_spec_.at("machine").get<std::string>(),
                std::filesystem::path(android_spec_.at("android_sdk_root").get<std::string>()) /
                        "emulator" / ("qemu-img" + std::string(os::executable_suffix)),
                android_spec_.value("system_binding", Json()));
    }

    if (snapshot_saved && guest_synced && kill_submitted && owned_shutdown && clean_exit) {
        try {
            android_quickboot_->commit(android_boot_nonce_, session_id_, presave_receipt,
                                       android_transport_boot_, android_input_sequence_);
            deliveries_["android"]["quickboot"]["checkpoint_saved"] = true;
        } catch (const std::exception &error) {
            deliveries_["android"]["quickboot"]["save_status"] = "checkpoint_fingerprint_failed";
            try {
                logging::write(logging::Level::error, "android", "checkpoint.fingerprint_failed",
                               {{"session_id", session_id_},
                                {"generation", android_generation_},
                                {"error", error.what()}});
            } catch (...) { /* Ignored: diagnostics never change the shutdown that follows. */
            }
        }
    }

    stop_owned_android_adb();
    forget_observer();
    deliveries_["android"]["shutdown"] = {{"identity_verified", identity_verified},
                                          {"emu_kill_submitted", kill_submitted},
                                          {"guest_sync_completed", guest_synced},
                                          {"ports_released", true},
                                          {"wrapper_terminal", !android_.alive()},
                                          {"wrapper_exit_code", android_.exit_code()},
                                          {"owned_clean_exit", owned_shutdown && clean_exit}};
}
} // namespace voyemu
