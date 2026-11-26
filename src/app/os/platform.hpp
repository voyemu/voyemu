#pragma once
#include <string_view>

namespace voyemu::os {
// The host operating system name that info reports.
#if defined(_WIN32)
inline constexpr std::string_view platform_name = "Windows";
#elif defined(__APPLE__)
inline constexpr std::string_view platform_name = "macOS";
#else
inline constexpr std::string_view platform_name = "Linux";
#endif
// The host key of the pinned dependencies in toolchain.json, operating system and architecture;
// empty on a host without pins. The Android Emulator keeps its QEMU binaries under
// emulator/qemu/<emulator_host>, the NDK its LLVM tools under toolchains/llvm/prebuilt/<ndk_host>.
// host_android_abi is the Android ABI that the processor of this host runs natively.
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
inline constexpr std::string_view dependency_host = "win32/x64";
inline constexpr std::string_view host_android_abi = "x86_64";
inline constexpr std::string_view emulator_host = "windows-x86_64";
inline constexpr std::string_view ndk_host = "windows-x86_64";
#elif defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
inline constexpr std::string_view dependency_host = "darwin/arm64";
inline constexpr std::string_view host_android_abi = "arm64-v8a";
inline constexpr std::string_view emulator_host = "darwin-aarch64";
inline constexpr std::string_view ndk_host = "darwin-x86_64";
#elif defined(__APPLE__) && defined(__x86_64__)
inline constexpr std::string_view dependency_host = "darwin/x64";
inline constexpr std::string_view host_android_abi = "x86_64";
inline constexpr std::string_view emulator_host = "darwin-x86_64";
inline constexpr std::string_view ndk_host = "darwin-x86_64";
#elif defined(__linux__) && defined(__x86_64__)
inline constexpr std::string_view dependency_host = "linux/x64";
inline constexpr std::string_view host_android_abi = "x86_64";
inline constexpr std::string_view emulator_host = "linux-x86_64";
inline constexpr std::string_view ndk_host = "linux-x86_64";
#else
inline constexpr std::string_view dependency_host;
inline constexpr std::string_view host_android_abi;
inline constexpr std::string_view emulator_host;
inline constexpr std::string_view ndk_host;
#endif
// The operating system part of dependency_host, the key of per-system pins in toolchain.json.
inline constexpr std::string_view dependency_system =
        dependency_host.substr(0, dependency_host.find('/'));
// The file name suffix and the file format of host executables.
#if defined(_WIN32)
inline constexpr std::string_view executable_suffix = ".exe";
inline constexpr std::string_view executable_format = "PE";
#elif defined(__APPLE__)
inline constexpr std::string_view executable_suffix;
inline constexpr std::string_view executable_format = "Mach-O";
#else
inline constexpr std::string_view executable_suffix;
inline constexpr std::string_view executable_format = "ELF";
#endif
// The file name suffix of shared libraries, such as the ANGLE libraries of the Emulator.
#if defined(_WIN32)
inline constexpr std::string_view shared_library_suffix = ".dll";
#elif defined(__APPLE__)
inline constexpr std::string_view shared_library_suffix = ".dylib";
#else
inline constexpr std::string_view shared_library_suffix = ".so";
#endif
// Whether the host is Windows, for interfaces that take the host as a value.
inline constexpr bool host_windows = platform_name == "Windows";
// The key of the build tools of this host in the optionalTools of toolchain.json.
inline constexpr std::string_view build_tools_host = host_windows               ? "windowsBuild"
                                                     : platform_name == "macOS" ? "macosBuild"
                                                                                : "linuxBuild";
// Whether this host builds a signed Android system offline: the image tools of that preparation
// run only on Linux until the launcher takes them over.
inline constexpr bool host_signed_android_preparation = platform_name == "Linux";
// The separator of the entries of a path list such as PATH or a Java class path.
inline constexpr char path_list_separator = host_windows ? ';' : ':';
} // namespace voyemu::os
