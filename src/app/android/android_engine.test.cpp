#include "android_engine.hpp"
#include "os/platform.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace voyemu;

int main() {
    try {
        const auto empty_trace = android_boot_trace_arguments(nullptr);

        if (!empty_trace.empty()) {
            throw std::runtime_error("default boot arguments changed");
        }

        std::vector<std::string> unchanged{"-avd", "fixture", "-qemu", "-machine", "type=virt"};
        const auto before = unchanged;
        unchanged.insert(unchanged.begin(), empty_trace.begin(), empty_trace.end());

        if (unchanged != before) {
            throw std::runtime_error("unset trace changed argument bytes");
        }

        if (android_boot_trace_arguments("1") !=
            std::vector<std::string>{
                    "-show-kernel", "-logcat",
                    "ActivityManager:I SystemServer:I Watchdog:W Zygote:I AndroidRuntime:E libc:F art:I dex2oat:I app_process:I init:I adbd:I *:S"}) {
            throw std::runtime_error("boot trace filter differs");
        }

        for (const auto *value : {"", "0", "true", "1 ", "-show-kernel"}) {
            bool rejected = false;
            try {
                (void)android_boot_trace_arguments(value);
            } catch (const std::exception &error) {
                rejected = std::string(error.what()).starts_with("ANDROID_BOOT_TRACE:");
            }

            if (!rejected) {
                throw std::runtime_error("unknown boot trace value accepted");
            }
        }

        // Clock trace opt-in carries no pathname: only the exact marker "1" is accepted, and it
        // yields the single fixed file name; every other value (including any pathname) is refused
        // before a file opens.
        if (!passion_clock_trace_file(nullptr).empty() || !passion_clock_trace_file("").empty()) {
            throw std::runtime_error("default clock trace enabled");
        }

        if (passion_clock_trace_file("1") != "clock-trace.jsonl") {
            throw std::runtime_error("clock trace destination is not the fixed private file name");
        }

        for (const auto *value : {"0", "true", "1 ", "1\n", "/tmp/clock-trace.jsonl", ".", "..",
                                  "../clock-trace.jsonl", "sub/clock-trace.jsonl", "/etc/passwd"}) {
            bool rejected = false;
            try {
                (void)passion_clock_trace_file(value);
            } catch (const std::exception &error) {
                rejected = std::string(error.what()).starts_with("PASSION_CLOCK_TRACE:");
            }

            if (!rejected) {
                throw std::runtime_error("unknown clock trace value accepted");
            }
        }

        // The accepted value is a bare leaf name, so it can only ever resolve under the owner's own
        // watch directory; no environment text reaches the path.
        {
            const auto watch = std::filesystem::path("private-session") / "display-power-watch";
            const std::filesystem::path joined = watch / passion_clock_trace_file("1");

            if (joined.parent_path() != watch || joined.filename() != "clock-trace.jsonl" ||
                std::filesystem::path(passion_clock_trace_file("1")).is_absolute() ||
                std::string(passion_clock_trace_file("1")).find('/') != std::string::npos) {
                throw std::runtime_error("clock trace escaped the owner watch directory");
            }
        }
        const auto sdk = std::filesystem::path("fixture SDK");
        {
            // The emulator itself answers whether this host accelerates the guest.
            ProcessSpec emulator;
            emulator.executable = sdk / "emulator/emulator";
            emulator.arguments = {"-avd", "fixture", "-accel", "on"};
            emulator.environment["ANDROID_SDK_ROOT"] = sdk.string();
            const auto answer = [&](ProcessResult result) {
                return android_acceleration_usable(emulator, [&](const ProcessSpec &check) {
                    if (check.executable != emulator.executable ||
                        check.arguments != std::vector<std::string>{"-accel-check"} ||
                        check.environment != emulator.environment) {
                        throw std::runtime_error("acceleration check changed its emulator");
                    }

                    return result;
                });
            };

            if (!answer({0, "KVM (version 12) is installed and usable.", false}) ||
                answer({11, "/dev/kvm is not found or no access", false}) ||
                answer({0, "", true})) {
                throw std::runtime_error("acceleration check differs from the emulator answer");
            }
        }

        if (android_sdk_program(sdk, true) !=
            sdk / "emulator/qemu/windows-x86_64/qemu-system-aarch64.exe") {
            throw std::runtime_error("Windows ARM64 uses rejecting launcher");
        }

        if (android_sdk_program(sdk, false) != sdk / "emulator/emulator") {
            throw std::runtime_error("Mac launcher changed");
        }

        if (android_sdk_ext4_program(sdk, true) != sdk / "platform-tools" / "mke2fs.exe" ||
            android_sdk_ext4_config(sdk, true) != sdk / "platform-tools" / "mke2fs.conf") {
            throw std::runtime_error("Windows SDK formatter/config not found in shipped component");
        }

        if (android_sdk_ext4_arguments("cache image.img", true) !=
                    std::vector<std::string>{"-t", "ext4", "-F", "-q", "cache image.img"} ||
            android_sdk_ext4_environment(sdk, true).at("MKE2FS_CONFIG") !=
                    (sdk / "platform-tools" / "mke2fs.conf").string()) {
            throw std::runtime_error(
                    "Windows formatter lost ext4 type, path boundary or fixed config");
        }

        if (android_sdk_ext4_program(sdk, false) != sdk / "emulator/bin64/mkfs.ext4" ||
            !android_sdk_ext4_config(sdk, false).empty() ||
            !android_sdk_ext4_environment(sdk, false).empty() ||
            android_sdk_ext4_arguments("cache.img", false) !=
                    std::vector<std::string>{"-F", "-q", "cache.img"}) {
            throw std::runtime_error("Mac/native diagnostic ext4 behavior changed");
        }

        if (android_sdk_machine_arguments(true) != std::vector<std::string>{"-qemu", "-machine",
                                                                            "type=virt", "-accel",
                                                                            "tcg,thread=multi"} ||
            !android_sdk_machine_arguments(false).empty()) {
            throw std::runtime_error("Windows ARM board or multi-threaded TCG policy differs");
        }

        if (!android_sdk_machine_arguments(true, true).empty()) {
            throw std::runtime_error(
                    "Wine native diagnostic inherited Windows TCG board arguments");
        }

        const auto net = android_interguest_arguments(23456, false, false);

        if (net != std::vector<std::string>{
                           "-qemu", "-netdev",
                           "socket,id=voyemu-interguest,connect=127.0.0.1:23456", "-device",
                           "virtio-net-pci,netdev=voyemu-interguest,mac=52:54:00:76:6f:21"}) {
            throw std::runtime_error("second NIC topology/address differs");
        }

        const auto windows_net = android_interguest_arguments(23456, true, true);

        if (windows_net !=
            std::vector<std::string>{
                    "-netdev", "socket,id=voyemu-interguest,listen=127.0.0.1:23456", "-device",
                    "virtio-net-pci,netdev=voyemu-interguest,mac=52:54:00:76:6f:21"}) {
            throw std::runtime_error("Windows listener direction or backend boundary differs");
        }

        const auto native_net = android_interguest_arguments(23456, true);

        if (voyemu::os::host_windows && native_net != windows_net) {
            throw std::runtime_error("Windows default interguest direction differs");
        }

        if (!voyemu::os::host_windows &&
            native_net != android_interguest_arguments(23456, true, false)) {
            throw std::runtime_error("Mac default interguest direction changed");
        }

        for (unsigned invalid : {0u, 1023u, 65536u}) {
            bool rejected = false;
            try {
                android_interguest_arguments(invalid, false);
            } catch (const std::exception &e) {
                rejected = std::string(e.what()).starts_with("INTERGUEST_ARGUMENT:");
            }

            if (!rejected) {
                throw std::runtime_error("unowned port accepted");
            }
        }

        if (android_network_arguments(false) !=
            std::vector<std::string>{"-qemu", "-netdev", "user,id=voyemu-wan", "-device",
                                     "virtio-net-pci,netdev=voyemu-wan,mac=52:54:00:76:6f:22"}) {
            throw std::runtime_error("external NAT NIC topology or address differs");
        }

        if (android_network_arguments(true) !=
            std::vector<std::string>{"-netdev", "user,id=voyemu-wan", "-device",
                                     "virtio-net-pci,netdev=voyemu-wan,mac=52:54:00:76:6f:22"}) {
            throw std::runtime_error("external NAT boundary deduplication differs");
        }

        const auto env = android_sdk_environment(sdk, true, "original-path");

        if (env.at("ANDROID_EMULATOR_LAUNCHER_DIR") != (sdk / "emulator").string() ||
            env.at("PATH") != (sdk / "emulator" / "lib64").string() + ";" +
                                      (sdk / "emulator" / "lib64" / "qt" / "lib").string() + ";" +
                                      (sdk / "emulator").string() + ";original-path") {
            throw std::runtime_error(
                    "SDK DLL search path or inherited PATH lost; actual=" + env.at("PATH") +
                    "; expected=" + (sdk / "emulator" / "lib64").string() + ";" +
                    (sdk / "emulator" / "lib64" / "qt" / "lib").string() + ";" +
                    (sdk / "emulator").string() + ";original-path");
        }

        // A drive-letter path is absolute only on Windows.
        if (voyemu::os::host_windows) {
            const auto absolute = std::filesystem::path(LR"(C:\Voyemu SDK)");

            if (!absolute.is_absolute()) {
                throw std::runtime_error("Windows SDK fixture must be absolute");
            }

            const auto absolute_env = android_sdk_environment(absolute, true, R"(C:\Windows)");

            if (android_sdk_ext4_program(absolute, true).string().find('/') != std::string::npos ||
                android_sdk_ext4_config(absolute, true).string().find('/') != std::string::npos) {
                throw std::runtime_error("Windows formatter/config paths contain mixed separators");
            }

            if (absolute_env.at("PATH").find('/') != std::string::npos ||
                android_sdk_program(absolute, true).string().find('/') != std::string::npos) {
                throw std::runtime_error("Windows SDK paths contain mixed separators");
            }
        }

        if (!android_sdk_environment(sdk, false, "original-path").empty()) {
            throw std::runtime_error("Mac environment changed");
        }

        if (android_sdk_environment(sdk, true, {}).at("PATH").back() == ';') {
            throw std::runtime_error("empty current-directory PATH entry added");
        }

        // The runtime SDK root honours an explicit binding first, then prefers the shipped Windows
        // PE SDK only when that directory exists, and otherwise keeps the native SDK; macOS never
        // selects it.
        {
            const auto base = std::filesystem::path(__FILE__)
                                      .parent_path()
                                      .parent_path()
                                      .parent_path()
                                      .parent_path() /
                              ".local/build/tmp" / "android-engine-sdk-root";
            std::error_code cleanup_error;
            std::filesystem::remove_all(base, cleanup_error);
            const auto root = base / "root";
            std::filesystem::create_directories(root / ".local/toolchains/windows-sdk");
            const std::filesystem::path binding("explicit-binding-sdk");

            if (android_runtime_sdk_root(root, binding, true) != binding ||
                android_runtime_sdk_root(root, binding, false) != binding) {
                throw std::runtime_error("explicit runtime SDK binding was not honoured");
            }

            if (android_runtime_sdk_root(root, std::filesystem::path{}, true) !=
                root / ".local/toolchains/windows-sdk") {
                throw std::runtime_error("present Windows SDK was not selected on Windows");
            }

            if (android_runtime_sdk_root(root, std::filesystem::path{}, false) !=
                root / ".local/toolchains/native-sdk") {
                throw std::runtime_error("macOS selected the Windows SDK");
            }

            const auto missing = base / "missing";
            std::filesystem::create_directories(missing);

            if (android_runtime_sdk_root(missing, std::filesystem::path{}, true) !=
                missing / ".local/toolchains/native-sdk") {
                throw std::runtime_error("absent Windows SDK did not fall back to the native SDK");
            }

            if (android_runtime_sdk_root(missing, std::filesystem::path{}, false) !=
                missing / ".local/toolchains/native-sdk") {
                throw std::runtime_error("macOS fallback SDK differs");
            }

            std::filesystem::remove_all(base, cleanup_error);
        }
        std::cout
                << "Windows ARM64 backend, multi-threaded TCG and SDK DLL environment passed; Mac unchanged\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
