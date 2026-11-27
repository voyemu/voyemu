#include "android_boot_pins.hpp"
#include "os/platform.hpp"
#include "portable_runtime_internal.hpp"

// Activates a prepared machine as the runtime of a profile.
namespace voyemu {
using namespace portable_detail;

Json activate_portable_runtime(const std::filesystem::path &root, std::string_view profile,
                               const MachineIdentity &machine,
                               const PortableRuntimeHostBindings &provided_host,
                               std::uint64_t reserve) {
    auto host = provided_host;

    host.seed = seed_directory(root, profile, machine, host.seed);
    const auto source_metadata = read_private_json(host.seed / "runtime.json");

    if (host.require_cluster && source_metadata.contains("qnx") &&
        source_metadata.at("qnx").contains("persistence")) {
        throw VoyemuError("QNX_PERSISTENCE_MACHINE_REQUIRED",
                          "use the portable machine configuration for persistent QNX storage");
    }

    const auto manifest = inspect_portable_runtime(root, profile, machine, host.seed);
    need(!host.require_cluster || manifest.contains("qnx"),
         "cluster unavailable in Android-only profile");
    const auto seed = seed_directory(root, profile, machine, host.seed);
    const auto manifest_sha = sha256_file(seed / "runtime.json");
    const int activation_version = 5;
    const auto scoped_parent = native_runtime_directory(root);
    const auto scoped = native_machine_directory(root, profile, machine);
    const std::string host_name(os::dependency_host);

    if (std::filesystem::exists(scoped / "activation.json")) {
        ordinary(scoped);
        const auto record = read_private_json(scoped / "activation.json");
        need(record.value("activation_version", 0) == activation_version,
             "activation version differs; existing writable disks are preserved and require explicit migration");
        need(!machine.selected ||
                     (canonical_machine_name(profile, record.value("machine", std::string{})) ==
                              machine.name &&
                      record.value("seed", std::string{}) == seed.string()),
             "cached machine identity differs");
        const auto recorded_runtime =
                std::filesystem::path(record.at("runtime").get<std::string>());
        inside(root, recorded_runtime);
        ordinary(recorded_runtime);
        need(record.at("schema") == 1 && record.at("manifest_sha256") == manifest_sha &&
                     record.at("profile") == profile && record.at("host") == host_name,
             "existing scoped launch is not this activation");
        need(sha256_file(scoped / "android-launch.json") ==
                     record.at("android_launch_sha256").get<std::string>(),
             "existing launch changed");
#ifdef _WIN32
        windows_android_renderer_policy(read_private_json(scoped / "android-launch.json"), true);
#endif

        if (record.contains("cluster_launch_sha256")) {
            need(sha256_file(scoped / "cluster-launch.json") ==
                         record.at("cluster_launch_sha256").get<std::string>(),
                 "existing cluster launch changed");
        }

        need(!host.require_cluster || !manifest.contains("qnx") ||
                     record.contains("cluster_launch_sha256"),
             "existing Android-only activation cannot be upgraded in place; explicit cluster activation required");
#if defined(_WIN32) || defined(__APPLE__)
        if (!host.frontend.empty() &&
            read_private_json(scoped / "android-launch.json").value("frontend", Json::object()) !=
                    host.frontend) {
            return refresh_observer(root, scoped, host, record);
        }

        if (record.contains("cluster_launch_sha256") && !host.frontend.empty()) {
            const auto program = root /
#ifdef _WIN32
                                 "voyemu.exe";
#else
                                 "voyemu";
#endif
            const auto cluster = read_private_json(scoped / "cluster-launch.json");

            for (const auto &item : cluster.at("pins")) {
                if (item.at("path") == program.string() &&
                    item.at("sha256") != tool_pin(root, host, program)) {
                    return refresh_observer(root, scoped, host, record);
                }
            }
        }
#endif

        if (!host.ui_observer.empty()) {
            const auto launch = read_private_json(scoped / "android-launch.json");

            if (launch.value("ui_observer", Json::object()) != host.ui_observer) {
                return refresh_observer(root, scoped, host, record);
            }

            const std::filesystem::path dex = host.ui_observer.at("dex").get<std::string>();
            need(tool_pin(root, host, dex) == host.ui_observer.at("sha256").get<std::string>(),
                 "cached observer pin mismatch");
        }

        auto cached = record;
        cached["cached"] = true;
        cached["cluster_requested"] = host.require_cluster;
        cached["cluster_seed_present"] = manifest.contains("qnx");

        return cached;
    }

    need(host.android_port >= 5554 && host.android_port <= 5682 && host.android_port % 2 == 0 &&
                 host.android_port != 5562,
         "isolated even Android port required");
    inside(root, host.sdk);
    ordinary(host.sdk);
    inside(root, host.clean_base);
    ordinary(host.clean_base);
#ifdef _WIN32
    const std::string suffix = ".exe";
#else
    const std::string suffix;
#endif
    const auto emulator = host.sdk / "emulator" / ("emulator" + suffix),
               qemu_image = host.sdk / "emulator" / ("qemu-img" + suffix);
    const auto emulator_sha = tool_pin(root, host, emulator);
    tool_pin(root, host, qemu_image);
    const auto definition = portable_profile_definition(root, profile, machine, seed);
    const auto family = runtime_profile_reference(definition, profile);
    const auto &guest = manifest.at("android");
    const auto abi = guest.at("abi").get<std::string>();
    const auto api = guest.at("api").get<unsigned>();
    const auto backend =
            host.sdk / "emulator" / "qemu" / std::string(os::emulator_host) /
            ((abi == "x86_64" ? "qemu-system-x86_64" : "qemu-system-aarch64") + suffix);
    const auto backend_sha = tool_pin(root, host, backend);

    const auto development_kernel = checked_development_kernel(seed, definition, manifest);
    const auto can_model_sha = checked_can_model_receipt(seed, manifest);
    const auto clean_pins = checked_android_boot_pins(seed, definition, manifest);

    for (const auto &[name, sha] : clean_pins) {
        // A seed clean base carries the development kernel the profile declares.
        const bool selected = !development_kernel.is_null() && name == "kernel-ranchu" &&
                              host.clean_base == seed / "android";
        checked_file(host.clean_base / name,
                     selected ? development_kernel.at("sha256").get<std::string>() : sha, 64 * mib);
    }

    need(host.frontend.is_object(), "frontend host object required");
    const bool frontend = !host.frontend.empty();

    if (frontend) {
        need(host.frontend.value("schema", 0) == 1 && host.frontend.contains("pins") &&
                     host.frontend.at("pins").is_array(),
             "pinned frontend required");

        for (const auto &item : host.frontend.at("pins")) {
            const auto path = std::filesystem::path(item.at("path").get<std::string>());
            need(tool_pin(root, host, path) == item.at("sha256").get<std::string>(),
                 "frontend pin differs");
        }
    }

    const bool cluster = host.require_cluster && manifest.contains("qnx") &&
                         !host.qnx_qemu.empty() && !host.graphics.empty() && !host.angle.empty();
    need(!host.require_cluster || !manifest.contains("qnx") || cluster,
         "QNX host bindings required unless cluster is explicitly disabled");

    if (cluster) {
        tool_pin(root, host, host.qnx_qemu, true);
        tool_pin(root, host, host.graphics);
        ordinary(host.angle);
        inside(root, host.angle);

        for (const auto *name : {"libEGL", "libGLESv2"}) {
            tool_pin(root, host, host.angle / (name + std::string(os::shared_library_suffix)));
        }

        need(host.qmp_port >= 1024 && host.qmp_port <= 65535, "QMP port required");
    }

    const auto runtime_parent = native_machine_directory(root, profile, machine) / "portable";
    const auto runtime = runtime_parent / ("portable-" + manifest_sha);
    need(!std::filesystem::exists(runtime), "existing writable runtime is never replaced");
    ensure_private_directory(scoped_parent);
    ordinary(scoped_parent);
    auto lock = owned_directory(scoped_parent / (machine.name + ".activation.lock"));
    ensure_private_directory(runtime_parent);
    ordinary(runtime_parent);
    std::uint64_t planned = 128 * mib;

    for (auto at = manifest.at("android").at("images").begin();
         at != manifest.at("android").at("images").end(); ++at) {
        planned += at.value().at("bytes").get<std::uint64_t>();
    }

    if (cluster) {
        for (auto at = manifest.at("qnx").at("images").begin();
             at != manifest.at("qnx").at("images").end(); ++at) {
            planned += at.value().at("bytes").get<std::uint64_t>();
        }
    }

    need(reserve <= std::numeric_limits<std::uint64_t>::max() - planned &&
                 std::filesystem::space(runtime_parent).available >= reserve + planned,
         "reserve plus writable extent required");
    auto stage = owned_directory(runtime_parent / (".portable-pending-" + random_token()));
    auto launch_stage = owned_directory(scoped_parent / (".launch-pending-" + random_token()));
    const auto machine_dir = stage.path / "android-machine",
               final_machine = runtime / "android-machine";
    ensure_private_directory(machine_dir / "base");
    const auto &images = manifest.at("android").at("images");

    for (const auto *name : android_names) {
        const bool base = std::string_view(name) == "system.img" ||
                          std::string_view(name) == "vendor.img";
        copy_sparse(seed / images.at(name).at("file").get<std::string>(), image_sha(images, name),
                    base ? machine_dir / "base" / name : machine_dir / name, reserve);
    }

    copy_sparse(seed / "android/cache.img", image_sha(images, "cache.img"),
                machine_dir / "cache.img", reserve);

    for (const auto &[name, sha] : clean_pins) {
        const bool selected = !development_kernel.is_null() && name == "kernel-ranchu";
        copy_sparse(selected ? seed / "android/kernel-ranchu" : host.clean_base / name,
                    selected ? development_kernel.at("sha256").get<std::string>() : sha,
                    machine_dir / "base" / name, reserve);
    }

    auto native_tool = [&](const std::filesystem::path &tool,
                           const std::vector<std::string> &args) {
        const auto sha = tool_pin(root, host, tool);
        ProcessSpec command;
        command.executable = tool;
        command.arguments = args;
        command.directory = machine_dir;
        command.environment = {{"TMPDIR", stage.path.string()},
                               {"TMP", stage.path.string()},
                               {"TEMP", stage.path.string()},
                               {"JAVA_HOME", "/nonexistent"},
                               {"NODE_PATH", "/nonexistent"}};
        const auto result = execute(command, 30000, 128 * 1024);
        need(!result.timed_out && result.exit_code == 0, "native disk initialization failed");
        need(tool_pin(root, host, tool) == sha, "disk tool changed");
    };

    for (const auto &backing : {"userdata-qemu.img", "cache.img", "encryptionkey.img",
                                "base/system.img", "base/vendor.img"}) {
        const auto name = std::filesystem::path(backing).filename().string() + ".qcow2";
        native_tool(qemu_image, {"create", "-f", "qcow2", "-F", "raw", "-b", backing, name});
        need(std::filesystem::is_regular_file(machine_dir / name) &&
                     std::filesystem::file_size(machine_dir / name) < 16 * mib,
             "fresh bounded QCOW required");
        std::ifstream in(machine_dir / name, std::ios::binary);
        std::array<char, 4> magic{};
        in.read(magic.data(), magic.size());
        need(magic == std::array<char, 4>{'Q', 'F', 'I', static_cast<char>(0xfb)},
             "QCOW output magic");
    }

    const auto avd = "voyemu-" + machine.name;
    const auto config = runtime_avd_config(definition, final_machine / "base", avd);
    private_text(machine_dir / "config-template.ini", config);
    private_text(machine_dir / "config.ini", config);
    write_private_json(machine_dir / "machine.json", {{"schema", 1},
                                                      {"profile", profile},
                                                      {"abi", abi},
                                                      {"fingerprint", manifest_sha},
                                                      {"portable_seed_sha256", manifest_sha},
                                                      {"cold_boot_verified_here", false}});
    Json pins = Json::array();
    add_pin(pins, emulator, emulator_sha);
    add_pin(pins, backend, backend_sha);
    std::string headless_sha;

    if (abi == "x86_64") {
        const auto headless = backend.parent_path() / "qemu-system-x86_64-headless";
        headless_sha = tool_pin(root, host, headless);
        add_pin(pins, headless, headless_sha);
    }

    add_pin(pins, final_machine / "config-template.ini",
            sha256_file(machine_dir / "config-template.ini"));
    add_pin(pins, final_machine / "machine.json", sha256_file(machine_dir / "machine.json"));

    for (const auto &name : {"system.img", "vendor.img"}) {
        add_pin(pins, final_machine / "base" / name, image_sha(images, name));
    }

    for (const auto &[name, sha] : clean_pins) {
        add_pin(pins, final_machine / "base" / name,
                !development_kernel.is_null() && name == "kernel-ranchu"
                        ? development_kernel.at("sha256").get<std::string>()
                        : sha);
    }

    auto android = portable_android_launch(root, host, final_machine, final_machine / "base",
                                           final_machine / "config-template.ini", avd,
                                           std::move(pins), definition, Json::object(),
                                           manifest.at("profile").get<std::string>());

    if (!can_model_sha.empty()) {
        android["can_model_observer_sha256"] = can_model_sha;
    }

    if (manifest.at("android").contains("owned_package")) {
        auto package = manifest.at("android").at("owned_package");
        android_owned_package_descriptor(package, true);
        const auto relative = std::filesystem::path(package.at("file").get<std::string>())
                                      .lexically_relative("android");
        ensure_private_directory((machine_dir / relative).parent_path());
        copy_sparse(seed / package.at("file").get<std::string>(),
                    package.at("sha256").get<std::string>(), machine_dir / relative, reserve);
        package["file"] = (final_machine / relative).string();
        android["owned_package"] = package;
    }

    if (manifest.at("android").contains("display_power")) {
        android["display_power_capability"] = portable_passion_power(seed, manifest, definition);
    }

    if (manifest.at("android").contains("mcu_property")) {
        android["mcu_property_adapter"] = portable_passion_mcu(seed, manifest, definition);
        android["presentation_adapter"] = passion_presentation_contract(
                family, true, passion_wheel_partial(android.value("wheel_capability", Json())));
    }

    if (manifest.at("android").contains("camera_package")) {
        auto package = manifest.at("android").at("camera_package");
        android_camera_package_descriptor(package, true);
        const auto relative = std::filesystem::path(package.at("file").get<std::string>())
                                      .lexically_relative("android");
        ensure_private_directory((machine_dir / relative).parent_path());
        copy_sparse(seed / package.at("file").get<std::string>(),
                    package.at("sha256").get<std::string>(), machine_dir / relative, reserve);
        package["file"] = (final_machine / relative).string();
        android["camera_package"] = package;
    }

    if (manifest.at("android").contains("prepared_packages")) {
        auto packages = manifest.at("android").at("prepared_packages");
        android_prepared_packages_descriptor(packages, true);

        for (auto &package : packages) {
            const auto relative = std::filesystem::path(package.at("file").get<std::string>())
                                          .lexically_relative("android");
            ensure_private_directory((machine_dir / relative).parent_path());
            copy_sparse(seed / package.at("file").get<std::string>(),
                        package.at("sha256").get<std::string>(), machine_dir / relative, reserve);
            package["file"] = (final_machine / relative).string();
        }

        android["prepared_packages"] = packages;
    }

    if (manifest.at("android").contains("qinggan09_owned_packages")) {
        auto packages = manifest.at("android").at("qinggan09_owned_packages");
        qinggan09_owned_packages_descriptor(packages, true);
        need(record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
                     api == 28,
             "exact A9 activation required");

        for (unsigned i = 0; i < qinggan09_owned_packages_payloads(packages).size(); ++i) {
            auto package = qinggan09_owned_packages_payloads(packages).at(i);
            const auto relative = std::filesystem::path(package.at("file").get<std::string>())
                                          .lexically_relative("android");
            ensure_private_directory((machine_dir / relative).parent_path());
            copy_sparse(seed / package.at("file").get<std::string>(),
                        package.at("sha256").get<std::string>(), machine_dir / relative, reserve);
            package["file"] = (final_machine / relative).string();
            qinggan09_owned_packages_set_payload(packages, i, package);
        }

        qinggan09_owned_packages_descriptor(packages, false);
        android["qinggan09_owned_packages"] = packages;
        android["profile"] = profile;
        android["audio_startup"] = {{"schema", 1},
                                    {"authority", "com.voyemu.output.audio.startup"}};
    }

    if (manifest.at("android").contains("qinggan09_phone_package")) {
        auto descriptor = manifest.at("android").at("qinggan09_phone_package");
        qinggan09_phone_package_descriptor(descriptor, true);
        need(record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
                     api == 28,
             "exact A9 Phone activation required");
        auto &package = descriptor.at("package");
        const auto relative = std::filesystem::path(package.at("file").get<std::string>())
                                      .lexically_relative("android");
        ensure_private_directory((machine_dir / relative).parent_path());
        copy_sparse(seed / package.at("file").get<std::string>(),
                    package.at("sha256").get<std::string>(), machine_dir / relative, reserve);
        package["file"] = (final_machine / relative).string();
        android["qinggan09_phone_package"] = descriptor;
        android["profile"] = profile;
    }

    if (manifest.contains("qnx") && manifest.at("qnx").contains("interguest_network")) {
        android["interguest_network"] = manifest.at("qnx").at("interguest_network");
    }

    write_private_json(launch_stage.path / "android-launch.json", android);
    Json record = {
            {"schema", 1},
            {"activation_version", activation_version},
            {"profile", profile},
            {"manifest_sha256", manifest_sha},
            {"host", host_name},
            {"runtime", runtime.string()},
            {"cached", false},
            {"android_launch_sha256", sha256_file(launch_stage.path / "android-launch.json")},
            {"cold_boot_verified_here", false},
            {"host_file_pins",
             {{"emulator", emulator_sha},
              {"qemu_backend", backend_sha},
              {"qemu_img", host.pins.at(qemu_image.string())}}},
            {"guest_image_pins", manifest.at("android").at("images")},
            {"cluster_configured", cluster},
            {"cluster_requested", host.require_cluster},
            {"cluster_seed_present", manifest.contains("qnx")},
            {"presentation", frontend ? "native-frontend" : "Android SDK window"}};

    if (!headless_sha.empty()) {
        record["host_file_pins"]["qemu_backend_headless"] = headless_sha;
    }

    if (cluster) {
        ensure_private_directory(stage.path / "qnx");
        Json qpins = Json::array();
        add_pin(qpins, host.qnx_qemu, tool_pin(root, host, host.qnx_qemu, true));
        add_pin(qpins, host.graphics, tool_pin(root, host, host.graphics));

        for (const auto *name : {"libEGL", "libGLESv2"}) {
            const auto lib = host.angle / (name + std::string(os::shared_library_suffix));
            add_pin(qpins, lib, tool_pin(root, host, lib));
        }

        const auto layout = qnx_portable_layout(family, manifest.at("qnx"));
        const auto &files = manifest.at("qnx").at("images");

        for (const auto &name : layout.images) {
            const auto sha = image_sha(files, name);
            copy_sparse(seed / files.at(name).at("file").get<std::string>(), sha,
                        stage.path / "qnx" / name, reserve);
            add_pin(qpins, runtime / "qnx" / name, sha);
        }

        const auto ram_launch = qnx_ram_launch(host_qnx_engine, layout.memory_mib);
        std::vector<std::string> args = {"-machine", ram_launch.machine,
                                         "-accel",   ram_launch.accelerator,
                                         "-cpu",     qnx_engine_cpu(host_qnx_engine)};
#ifdef _WIN32
        const Json qmp = {{"host", "127.0.0.1"}, {"port", host.qmp_port}};
        const auto qmp_arg = "tcp:127.0.0.1:" + std::to_string(host.qmp_port) +
                             ",server=on,wait=off";
#else
        const Json qmp = "${RUNTIME}/${TOKEN}-qmp.sock";
        const std::string qmp_arg = "unix:${RUNTIME}/${TOKEN}-qmp.sock,server=on,wait=off";
#endif
        args.insert(args.end(), {"-m", std::to_string(layout.memory_mib), "-smp", "8",
                                 "-nodefaults", "-display", "none", "-qmp", qmp_arg, "-nic", "none",
                                 "-no-reboot", "-kernel", (runtime / "qnx/hyp-hvf.img").string()});
        const auto &loaders = layout.loaders;

        for (const auto &[name, address] : loaders) {
            args.insert(args.end(), {"-device", "loader,file=" + (runtime / "qnx" / name).string() +
                                                        ",addr=" + address + ",force-raw=on"});
        }

        args.insert(args.end(), {"-device",
                                 "loader,file=" + (runtime / "qnx/qnx-ipl-virt.bin").string() +
                                         ",addr=0x40200000,force-raw=on,cpu-num=0",
                                 "-serial", "file:${SESSION}/qnx-serial.log", "-S"});
        args.insert(args.end(), ram_launch.options.begin(), ram_launch.options.end());
        Json cluster_launch = {
                {"schema", 1},
                {"qemu", {{"executable", host.qnx_qemu.string()}, {"args", args}}},
                {"ram_backend", ram_launch.backend},
                {"ram", "${SESSION}/qnx-ram.bin"},
                {"console", "${SESSION}/qnx-console.log"},
                {"qmp", qmp},
                {"pins", qpins},
                {"graphics",
                 {{"executable", host.graphics.string()}, {"angle", host.angle.string()}}},
                {"ready_ring_address", 1342242816},
                {"ready_ring_bytes", 262144},
                {"guest_arch", "aarch64"},
                {"owner_local_oem_inputs", true}};
        qnx_runtime_launch_metadata(cluster_launch, layout);
        cluster_launch = portable_qnx_diagnostic_launch(std::move(cluster_launch),
                                                        wine_native_diagnostic_binding());
        write_private_json(launch_stage.path / "cluster-launch.json", cluster_launch);
        record["cluster_launch_sha256"] = sha256_file(launch_stage.path / "cluster-launch.json");
        record["cluster_tcg_verified"] = false;
    }

    need(inspect_portable_runtime(root, profile, machine, host.seed) == manifest &&
                 sha256_file(seed / "runtime.json") == manifest_sha,
         "seed changed during activation");

    if (machine.selected) {
        record["machine"] = machine.selector();
        record["seed"] = seed.string();
    }

    write_private_json(stage.path / "activation-source.json",
                       {{"schema", 1}, {"manifest_sha256", manifest_sha}, {"profile", profile}});
    write_private_json(launch_stage.path / "activation.json", record);
    rename_exclusive(stage.path, runtime);
    stage.retained = true;
    try {
        ensure_private_directory(scoped);

        for (const auto &entry : std::filesystem::directory_iterator(launch_stage.path)) {
            rename_exclusive(entry.path(), scoped / entry.path().filename());
        }
    } catch (...) {
        try {
            if (read_private_json(runtime / ".owner.json").at("token") == stage.token) {
                std::filesystem::remove_all(runtime);
            }
        } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
        }

        throw;
    }

    return record;
}
} // namespace voyemu
