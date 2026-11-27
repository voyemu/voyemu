#pragma once
#include "android_vbmeta.hpp"
#include "model.hpp"
#include <map>

namespace voyemu {
// The extents of the logical partitions that the vbmeta chain of an Android base descriptor
// reaches.
std::map<std::string, LogicalPartitionExtent> android_vbmeta_partitions(const Json &base);
// Read-only check of the portable boot files against the SHA-256 pins of the manifest. A base that
// binds a vbmeta digest takes the boot parameters of the machine: the stock ones with the digest of
// the vbmeta chain of the machine system image.
std::map<std::string, std::string> checked_android_boot_pins(const std::filesystem::path &seed,
                                                             const Json &definition,
                                                             const Json &manifest);
} // namespace voyemu
