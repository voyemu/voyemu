#pragma once
#include "model.hpp"
#include <map>
namespace voyemu {
// The permission bits and owner of an extracted inode.
struct Ext4Inode {
    unsigned mode{}, uid{}, gid{};
};
// Read-only extraction from a pinned raw ext4 filesystem or its single GPT partition.
// Paths are inside the filesystem, not host paths; aliases and unsupported features fail closed.
// inodes, when given, receives the inode of each requested path.
Json extract_pinned_ext4_files(const std::filesystem::path &image, const std::string &image_sha256,
                               const std::vector<std::string> &paths,
                               const std::filesystem::path &destination,
                               std::uint64_t reserve_bytes = 20ULL << 30,
                               std::string_view logical_partition = {},
                               std::map<std::string, Ext4Inode> *inodes = nullptr);
} // namespace voyemu
