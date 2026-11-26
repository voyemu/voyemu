#pragma once
#include "model.hpp"
#include "os/platform.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
namespace voyemu {
struct AndroidBaseIdentity {
    unsigned api;
    std::string_view abi;
};

// The API and ABI of a supported clean SDK system image package: API28 or API30, ARM64 or x86_64.
inline AndroidBaseIdentity android_package_identity(std::string_view package) {
    for (const unsigned api : {28U, 30U}) {
        for (const std::string_view abi : {"arm64-v8a", "x86_64"}) {
            if (package ==
                "system-images;android-" + std::to_string(api) + ";default;" + std::string(abi)) {
                return {api, abi};
            }
        }
    }

    return {};
}

// Verifies the SDK package, revision, URL and archive pin declared by the profile.
AndroidBaseIdentity native_base_identity(const Json &descriptor);
// The guest ABI of the Android base of a profile definition; one without a base runs ARM64.
std::string_view android_guest_abi(const Json &definition);
// Whether the profile requires hardware acceleration wherever its guest runs natively:
// emulator.acceleration accepts only "required"; the host is checked when the guest starts.
bool android_acceleration_required(const Json &definition);

// The emulator accelerates a guest whose ABI the processor of the host runs natively; another
// guest ABI runs in software translation.
inline bool android_hardware_acceleration(std::string_view guest_abi) {
    return guest_abi == os::host_android_abi;
}

// The QEMU system architecture and the AVD hw.cpu.arch of a guest ABI.
inline std::string_view android_qemu_arch(std::string_view abi) {
    return abi == "x86_64" ? "x86_64" : "aarch64";
}

inline std::string_view android_avd_cpu_arch(std::string_view abi) {
    return abi == "x86_64" ? "x86_64" : "arm64";
}

unsigned native_base_api(const Json &descriptor);
struct CleanBasePartition {
    std::uint64_t offset{}, bytes{};
};
// The pins of the image contents that a descriptor declares in clean_base: receipt_sha256 of the
// extraction receipt, boot_files, images and guest files by name, and on API30 the metadata pin
// and the logical system and system_ext partitions of the super image.
struct CleanBase {
    std::string receipt_sha256;
    std::map<std::string, std::string> boot_files, images, files;
    std::string metadata_sha256;
    CleanBasePartition system, system_ext;
    // The SHA-256 of name in group, such as images and system.img.
    std::string pin(const char *group, const std::string &name) const;
};
CleanBase native_clean_base(const Json &descriptor);
// The SHA-256 of name in the clean_base group of descriptor, such as images and system.img.
std::string native_base_pin(const Json &descriptor, const char *group, const std::string &name);
// Verifies the complete immutable extracted inventory against its registered SDK receipt.
// Does not require the original ZIP after a successful pinned extraction.
Json verify_native_base_image(const Json &descriptor, const std::filesystem::path &directory);
// Expands a pinned clean AOSP archive into a fresh immutable cache; never imports an AVD or
// userdata.
Json prepare_native_base_image(const Json &descriptor, const std::filesystem::path &archive,
                               const std::filesystem::path &destination,
                               std::uint64_t reserve_bytes = 20ULL << 30);
} // namespace voyemu
