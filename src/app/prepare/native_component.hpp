#pragma once
#include "download.hpp"
#include "model.hpp"
#include <functional>
namespace voyemu {
// Builds an owned API28/API30 native component with a pinned NDK clang; never invokes a shell
// or interpreter. Guest libraries named by guestLibs link as stubs that carry only their soname.
Json build_native_component(const std::filesystem::path &source,
                            const std::filesystem::path &compiler,
                            const std::string &compiler_sha256,
                            const std::filesystem::path &destination,
                            std::uint64_t reserve_bytes = 20ULL << 30,
                            std::function<std::uint64_t()> available_space = {},
                            std::string_view guest_abi = "arm64-v8a");
// The source tree of a native component: its directory, or with sourceFiles a fresh copy in work
// that adds each declared file of profiles/common/components, named like an APK component's.
std::filesystem::path native_component_sources(const std::filesystem::path &root,
                                               const std::filesystem::path &component,
                                               const std::filesystem::path &work);
// The androidNativeComponents key of a native component: the pin its definition names, which
// another profile publishes for the same bytes, or else <profile>/<component>.
std::string native_component_pin(const std::string &profile, const std::string &component,
                                 const Json &definition);
// A native library can declare the ABI of the OEM process that loads it; the one rule of the
// component ABI, which the Java helper receives with each component.
std::string native_component_abi(const Json &definition, std::string_view guest);
// Origin and pinned output digest for the source recipe or published release asset.
Json native_component_origin(const Json &pins, const std::string &key, const Json &definition);
// The recipe of the release assets: materializes and builds every native component of every profile
// with the pinned NDK clang into output as <profile>-<component>-<output>; returns the SHA-256 of
// each by <profile>/<component>; a component that names a pin is built by the profile that
// publishes it.
Json build_native_component_recipe(const std::filesystem::path &root,
                                   const std::filesystem::path &compiler,
                                   const std::string &compiler_sha256,
                                   const std::filesystem::path &output, bool offline);
// Installs the native component of a profile pinned in pins (androidNativeComponents of
// toolchain.json) into .local/toolchains/android-native/<sha256>/ and returns the receipt of a
// fresh handoff directory in .local/build that holds the output. It downloads the CI-built asset;
// while it cannot be downloaded, build (by default the recipe with the pinned NDK of the developer
// tools) produces it, and without that NDK it stops with ANDROID_NATIVE_ASSET_MISSING. Both paths
// are checked against the same pin.
std::filesystem::path
install_native_component(const std::filesystem::path &root, const std::string &profile,
                         const std::string &component, const Json &pins, bool offline,
                         const DownloadTransport &transport = {},
                         const std::function<void(const std::filesystem::path &)> &build = {},
                         std::string_view guest_abi = {});
} // namespace voyemu
