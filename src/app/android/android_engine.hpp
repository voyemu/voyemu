#pragma once
#include "error.hpp"
#include "os/platform.hpp"
#include "process.hpp"
#include <algorithm>
#include <filesystem>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace voyemu {
// The launcher that answers -accel-check for a launch: the program itself, or the emulator launcher
// of the SDK for an engine that Windows starts directly from emulator/qemu/<host>/.
inline std::filesystem::path
android_acceleration_check_program(const std::filesystem::path &program) {
    if (!program.filename().string().starts_with("qemu-system-")) {
        return program;
    }

    return program.parent_path().parent_path().parent_path() /
           ("emulator" + std::string(os::executable_suffix));
}

// The pinned emulator reports whether this host accelerates its guest: with the environment of the
// launch, -accel-check exits 0 when the hypervisor is usable and with another code, such as 11
// without access to it, otherwise.
inline bool
android_acceleration_usable(const ProcessSpec &emulator,
                            const std::function<ProcessResult(const ProcessSpec &)> &run) {
    auto check = emulator;

    check.executable = android_acceleration_check_program(emulator.executable);
    check.arguments = {"-accel-check"};
    check.output.clear();
    check.detached = false;
    const auto result = run(check);

    return !result.timed_out && result.exit_code == 0;
}

// The guest of a machine that requires acceleration starts only where the emulator confirms it.
inline void require_android_acceleration(const ProcessSpec &emulator) {
    if (!android_acceleration_usable(emulator, [](const ProcessSpec &check) {
            return execute(check, 60000, 16 * 1024);
        })) {
        throw VoyemuError("ANDROID_ACCELERATION",
                          "the pinned emulator found no usable hardware acceleration for this "
                          "guest (-accel-check)");
    }
}

// The renderers that preparation and start pass to the pinned emulator as -gpu: host GPU modes,
// SwiftShader on the host, and guest, which renders in software inside the guest for a host
// without a usable GPU.
inline bool android_renderer_supported(std::string_view mode) {
    return mode == "auto" || mode == "auto-no-window" || mode == "host" ||
           mode == "swiftshader_indirect" || mode == "guest";
}

inline const std::string &checked_android_renderer(const std::string &mode) {
    if (!android_renderer_supported(mode)) {
        throw VoyemuError("ANDROID_GPU", "unsupported prepared renderer");
    }

    return mode;
}

inline bool android_sdk_headless_backend(const std::vector<std::string> &arguments) {
    const auto options_end = std::find(arguments.begin(), arguments.end(), "-qemu");

    return std::find(arguments.begin(), options_end, "-no-window") != options_end;
}

// The hidden SDK window: -no-window selects the headless engine, and a host audio driver that
// only the full engine has hides the Qt window of that engine instead. Runs after the audio route
// and before the engine identity; QEMU arguments after -qemu stay unchanged.
inline void android_sdk_hidden_window(std::vector<std::string> &arguments, bool full_engine) {
    const auto options_end = std::find(arguments.begin(), arguments.end(), "-qemu");

    if (full_engine) {
        std::replace(arguments.begin(), options_end, std::string("-no-window"),
                     std::string("-qt-hide-window"));
    }
}

// An explicit binding always wins; Windows prefers its shipped PE SDK when present; every other
// host keeps the native SDK.
inline std::filesystem::path android_runtime_sdk_root(const std::filesystem::path &root,
                                                      const std::filesystem::path &binding_sdk,
                                                      bool windows) {
    if (!binding_sdk.empty()) {
        return binding_sdk;
    }

    if (windows && std::filesystem::exists(root / ".local/toolchains/windows-sdk")) {
        return root / ".local/toolchains/windows-sdk";
    }

    return root / ".local/toolchains/native-sdk";
}

// The Windows launcher rejects ARM64 on x64, so Windows starts the shipped engine of the guest ABI
// directly, qemu-system-aarch64.exe or qemu-system-x86_64.exe.
inline std::filesystem::path android_sdk_program(const std::filesystem::path &sdk, bool windows,
                                                 std::string_view guest_abi = "arm64-v8a") {
    return windows ? sdk / "emulator" / "qemu" / "windows-x86_64" /
                             (guest_abi == "x86_64" ? "qemu-system-x86_64.exe"
                                                    : "qemu-system-aarch64.exe")
                   : sdk / "emulator" / "emulator";
}

// The engine of an x86_64 guest without a window: emulator/qemu/<host>/qemu-system-x86_64-headless
// with the executable suffix of the host.
inline std::filesystem::path android_sdk_headless_engine(const std::filesystem::path &engines) {
    return engines / ("qemu-system-x86_64-headless" + std::string(os::executable_suffix));
}

// Windows SDK ships the formatter with platform-tools, not emulator/bin64.
inline std::filesystem::path android_sdk_ext4_program(const std::filesystem::path &sdk,
                                                      bool windows) {
    return windows ? sdk / "platform-tools" / "mke2fs.exe"
                   : sdk / "emulator" / "bin64" / "mkfs.ext4";
}

inline std::filesystem::path android_sdk_ext4_config(const std::filesystem::path &sdk,
                                                     bool windows) {
    return windows ? sdk / "platform-tools" / "mke2fs.conf" : std::filesystem::path{};
}

inline std::vector<std::string> android_sdk_ext4_arguments(const std::filesystem::path &image,
                                                           bool windows) {
    return windows ? std::vector<std::string>{"-t", "ext4", "-F", "-q", image.string()}
                   : std::vector<std::string>{"-F", "-q", image.string()};
}

inline std::map<std::string, std::string>
android_sdk_ext4_environment(const std::filesystem::path &sdk, bool windows) {
    return windows ? std::map<std::string, std::string>{{"MKE2FS_CONFIG",
                                                         android_sdk_ext4_config(sdk, true)
                                                                 .string()}}
                   : std::map<std::string, std::string>{};
}

// Private diagnostic opt-in; never accept free-form SDK arguments from the environment.
inline std::vector<std::string> android_boot_trace_arguments(const char *value) {
    if (!value) {
        return {};
    }

    if (std::string_view(value) != "1") {
        throw VoyemuError("ANDROID_BOOT_TRACE", "expected exact value 1 or an unset variable");
    }

    return {"-show-kernel", "-logcat",
            "ActivityManager:I SystemServer:I Watchdog:W Zygote:I AndroidRuntime:E libc:F art:I dex2oat:I app_process:I init:I adbd:I *:S"};
}

// Private Passion clock trace opt-in. The caller never supplies a pathname: the only accepted value
// is the exact marker "1", and the single permitted destination is the fixed name below under the
// watch directory that the session owner derives from its own private session directory. Any other
// value is rejected so a mistyped opt-in can never open an arbitrary file.
inline std::string passion_clock_trace_file(const char *value) {
    if (!value || !*value) {
        return {};
    }

    if (std::string_view(value) != "1") {
        throw VoyemuError("PASSION_CLOCK_TRACE", "expected exact value 1 or an unset variable");
    }

    return "clock-trace.jsonl";
}

// Windows ARM64 uses multi-threaded TCG with host-paced virtual timers.
// Pinned SDK capability probe verifies four distinct owned vCPU threads; virt supplies HDA PCI.
// An x86_64 guest keeps the machine of its engine and the hypervisor that -accel selects.
inline std::vector<std::string>
android_sdk_machine_arguments(bool windows, bool diagnostic_native = false,
                              std::string_view guest_abi = "arm64-v8a") {
    return windows && !diagnostic_native && guest_abi != "x86_64"
                   ? std::vector<std::string>{"-qemu", "-machine", "type=virt", "-accel",
                                              "tcg,thread=multi"}
                   : std::vector<std::string>{};
}

// Fixed third NIC carrying QEMU user-mode NAT (slirp) identically on macOS and Windows.
inline std::vector<std::string> android_network_arguments(bool qemu_boundary_present) {
    std::vector<std::string> result;

    if (!qemu_boundary_present) {
        result.push_back("-qemu");
    }

    result.insert(result.end(), {"-netdev", "user,id=voyemu-wan", "-device",
                                 "virtio-net-pci,netdev=voyemu-wan,mac=52:54:00:76:6f:22"});

    return result;
}

// Fixed second NIC; the legacy SDK eth0/router and its backend remain unchanged.
inline constexpr bool android_interguest_listener = os::host_windows;

inline std::vector<std::string>
android_interguest_arguments(unsigned port, bool qemu_boundary_present,
                             bool listener = android_interguest_listener) {
    if (port < 1024 || port > 65535) {
        throw VoyemuError("INTERGUEST_ARGUMENT", "owned loopback port required");
    }

    std::vector<std::string> result;

    if (!qemu_boundary_present) {
        result.push_back("-qemu");
    }

    result.insert(result.end(),
                  {"-netdev",
                   "socket,id=voyemu-interguest," + std::string(listener ? "listen" : "connect") +
                           "=127.0.0.1:" + std::to_string(port),
                   "-device", "virtio-net-pci,netdev=voyemu-interguest,mac=52:54:00:76:6f:21"});

    return result;
}

inline std::map<std::string, std::string> android_sdk_environment(const std::filesystem::path &sdk,
                                                                  bool windows,
                                                                  std::string_view inherited_path) {
    if (!windows) {
        return {};
    }

    const auto emulator = sdk / "emulator";

    return {{"ANDROID_EMULATOR_LAUNCHER_DIR", emulator.string()},
            {"PATH", (emulator / "lib64").string() + ";" +
                             (emulator / "lib64" / "qt" / "lib").string() + ";" +
                             emulator.string() +
                             (inherited_path.empty() ? "" : ";" + std::string(inherited_path))}};
}
} // namespace voyemu
