#pragma once
#include "model.hpp"
#include <map>

namespace voyemu {
std::filesystem::path signed_android_tools(const std::filesystem::path &root);

// Verifies a release of build-image.sh and returns its immutable SDK files and boot digest.
Json verify_signed_android_release(const std::filesystem::path &root,
                                   const std::filesystem::path &release,
                                   const std::filesystem::path &key, const Json &profile);
// Read-only check of the immutable portable boot roles against the SHA-256 pins of the manifest.
std::map<std::string, std::string>
checked_signed_android_boot_pins(const std::filesystem::path &seed, const Json &definition,
                                 const Json &manifest);
} // namespace voyemu
