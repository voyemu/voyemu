#pragma once
#include "android_engine.hpp"
#include "android_launch_adb.hpp"
#include "android_owned_package.hpp"
#include "android_port_lease.hpp"
#include "android_system_binding.hpp"
#include "api30_framework_boot.hpp"
#include "base_image.hpp"
#include "can_model_candidate_binding.hpp"
#include "check.hpp"
#include "error.hpp"
#include "host_refresh.hpp"
#include "image_clone.hpp"
#include "inactive_profile.hpp"
#include "machine_host_ports.hpp"
#include "machine_preparation.hpp"
#include "media_discovery.hpp"
#include "nxp_presentation.hpp"
#include "os/fs.hpp"
#include "os/process.hpp"
#include "passion_mcu_prepared.hpp"
#include "passion_power_prepared.hpp"
#include "passion_presentation.hpp"
#include "passion_wheel.hpp"
#include "phone_control.hpp"
#include "portable_resources.hpp"
#include "portable_runtime.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_identity.hpp"
#include "profile_runtime.hpp"
#include "qinggan09_owned_packages.hpp"
#include "qinggan09_phone_package.hpp"
#include "qinggan11_startup.hpp"
#include "qnx_host.hpp"
#include "qnx_persistent_storage.hpp"
#include "qnx_process_ram.hpp"
#include "qnx_runtime_layout.hpp"
#include "quickboot.hpp"
#include "screens.hpp"
#include "windows_renderer.hpp"
#ifdef _WIN32
#include "os/private_state_security.hpp"
#include "wine_native_backend_windows.hpp"
#endif
#include <algorithm>
#include <array>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <limits>
#include <thread>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <set>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include <shlobj.h>
#else
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Helpers shared by the parts of the portable runtime; each part includes this header.
namespace voyemu::portable_detail {
inline constexpr Check need{"PORTABLE_RUNTIME"};

inline bool android_launch_audio_output(const Json &emulator, bool kvm) {
    return emulator.value("audioOutput", !kvm);
}

void ordinary(const std::filesystem::path &path, bool allow_windows_spelling = false);
void inside(const std::filesystem::path &root, const std::filesystem::path &path);
Json checked_file(const std::filesystem::path &file, const std::string &sha,
                  std::uint64_t maximum = 8ULL << 30,
                  const std::filesystem::path &android_alias = {});
std::filesystem::path seed_directory(const std::filesystem::path &root, std::string_view profile,
                                     const MachineIdentity &machine,
                                     const std::filesystem::path &explicit_seed = {});
void rename_exclusive(const std::filesystem::path &from, const std::filesystem::path &to);
void copy_sparse(const std::filesystem::path &source, const std::string &sha,
                 const std::filesystem::path &target, std::uint64_t reserve);
void private_text(const std::filesystem::path &path, const std::string &text);
std::string bounded_text(const std::filesystem::path &path);
std::string tool_pin(const std::filesystem::path &root, const PortableRuntimeHostBindings &host,
                     const std::filesystem::path &file, bool allow_installed_qnx = false);
Json portable_observer_descriptor(const std::filesystem::path &seed, const Json &manifest);
void add_pin(Json &pins, const std::filesystem::path &file, const std::string &sha);
Json refresh_observer(const std::filesystem::path &root, const std::filesystem::path &scoped,
                      const PortableRuntimeHostBindings &host, const Json &record);
std::string image_sha(const Json &files, const std::string &name);
std::string runtime_avd_config(const Json &definition, const std::filesystem::path &base,
                               const std::string &avd);
Json wine_native_diagnostic_binding();
// A system generation retains the accepted machine snapshot and application disks.
// Its cold proof belongs to its own source snapshot and five fresh candidate images.
Json passion_system_evidence(const std::filesystem::path &seed, const Json &manifest,
                             const std::filesystem::path &staged = {});
Json portable_passion_power(const std::filesystem::path &seed, const Json &manifest,
                            const Json &definition);
Json portable_passion_mcu(const std::filesystem::path &seed, const Json &manifest,
                          const Json &definition);
void check_android_guest_identity(const Json &definition, const Json &manifest);
std::string checked_can_model_receipt(const std::filesystem::path &seed, const Json &manifest);
Json checked_development_kernel(const std::filesystem::path &seed, const Json &definition,
                                const Json &manifest);
constexpr std::uint64_t mib = 1024 * 1024;
const std::array<const char *, 4> android_names{"system.img", "vendor.img", "userdata-qemu.img",
                                                "encryptionkey.img"};
struct OwnedDirectory {
    std::filesystem::path path;
    std::string token;
    bool retained = false;

    ~OwnedDirectory() {
        if (retained || path.empty()) {
            return;
        }

        try {
            ordinary(path);

            if (read_private_json(path / ".owner.json").at("token") == token) {
                std::filesystem::remove_all(path);
            }
        } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
        }
    }
};
OwnedDirectory owned_directory(const std::filesystem::path &path);
} // namespace voyemu::portable_detail
