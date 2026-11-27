#pragma once
#include "model.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace voyemu {
// A Native Bridge lets an x86_64 guest run ARM code. Its descriptor in
// profiles/common/native-bridges/<name>.json pins the SDK image that donates the translator, each
// donated system file, and the property values that enable it in the property files of the base.
struct NativeBridge {
    Json descriptor;
    // The donated files at their guest paths; native-bridge.json beside it holds their mode, uid
    // and gid.
    std::filesystem::path directory;
};
// The descriptor that the Android base of definition names in native_bridge, or null.
Json native_bridge_descriptor(const std::filesystem::path &root, const Json &definition);
// Extracts the donated files once into .local/profiles/common/native-bridge/<archive SHA-256>/
// from the pinned donor archive, which is downloaded into downloads; returns the verified tree.
NativeBridge prepare_native_bridge(const std::filesystem::path &root, const Json &descriptor,
                                   const std::filesystem::path &downloads, bool offline,
                                   std::uint64_t reserve_bytes);
// Verifies the extracted tree of descriptor without writing; returns its receipt.
Json verify_native_bridge(const NativeBridge &bridge);
// The property file text with each key of values set: a present key keeps its line position, a
// missing one is appended in key order after the trailing empty lines are removed.
std::string merge_android_properties(std::string_view text, const Json &values);
} // namespace voyemu
