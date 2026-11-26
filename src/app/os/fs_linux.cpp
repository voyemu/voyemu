#include "fs.hpp"
#include <fcntl.h>
#include <stdio.h>

namespace voyemu::os {
bool rename_exclusive(const std::filesystem::path &from, const std::filesystem::path &to) {
    return ::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(), RENAME_NOREPLACE) == 0;
}

bool cloning_volume(const std::filesystem::path &) {
    return false;
}

bool clone_file(const std::filesystem::path &, const std::filesystem::path &) {
    return false;
}

bool exchange_paths(const std::filesystem::path &first, const std::filesystem::path &second) {
    return ::renameat2(AT_FDCWD, first.c_str(), AT_FDCWD, second.c_str(), RENAME_EXCHANGE) == 0;
}
} // namespace voyemu::os
