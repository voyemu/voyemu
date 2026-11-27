#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <string_view>

namespace voyemu {
// The bytes of a disk image at an offset, such as a raw read of system.img.
using DiskRead = std::function<std::string(std::uint64_t offset, std::size_t bytes)>;
struct LogicalPartitionExtent {
    std::uint64_t offset{}, bytes{};
};
// The vbmeta chain the guest verifies at first-stage mount: the vbmeta GPT partition and each
// partition it chains to, whose vbmeta the AVB footer at the end of that partition locates.
struct VbmetaChain {
    std::string digest;
    std::uint64_t bytes{};
    std::uint32_t flags{};
};
// Reads the chain from a disk; partitions gives the extent of every chained logical partition.
// Fails with ANDROID_VBMETA when a structure is missing or a chained partition is unknown.
VbmetaChain android_vbmeta_chain(const DiskRead &read,
                                 const std::map<std::string, LogicalPartitionExtent> &partitions);
// A reader of the regular file image; each read is bounded and must stay inside the file.
DiskRead raw_disk_reader(const std::filesystem::path &image);
// The boot parameters with every digest of stock replaced by that of chain; the vbmeta size of
// the parameters stays and must equal the chain size.
std::string android_verified_boot_parameters(std::string_view stock, std::string_view stock_digest,
                                             const VbmetaChain &chain);
// The digest that boot parameters declare in androidboot.vbmeta.digest.
std::string android_verified_boot_digest(std::string_view parameters);
} // namespace voyemu
