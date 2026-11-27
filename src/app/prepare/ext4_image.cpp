#include "ext4_image.hpp"
#include "check.hpp"
#include "disk_space.hpp"
#include "error.hpp"
#include "lp_image.hpp"
#include "process.hpp"
#include "quickboot.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <map>
#include <set>
namespace voyemu {
namespace {
[[noreturn]] void bad(const char *reason) {
    throw VoyemuError("EXT4_IMAGE", reason);
}

std::uint64_t number(std::string_view bytes, std::size_t offset, unsigned width) {
    if (offset > bytes.size() || width > bytes.size() - offset) {
        bad("metadata extent invalid");
    }

    std::uint64_t result = 0;

    for (unsigned i = 0; i < width; ++i) {
        result |= std::uint64_t(static_cast<unsigned char>(bytes[offset + i])) << (8 * i);
    }

    return result;
}

std::uint32_t crc32(std::string_view bytes) {
    std::uint32_t value = 0xffffffff;

    for (unsigned char c : bytes) {
        value ^= c;

        for (unsigned i = 0; i < 8; ++i) {
            value = (value >> 1) ^ (0xedb88320 & std::uint32_t(-std::int32_t(value & 1)));
        }
    }

    return value ^ 0xffffffff;
}

struct Image {
    std::ifstream stream;
    std::uint64_t bytes, offset = 0, partition_bytes = 0, blocks = 0;
    std::uint32_t block_size = 0, inodes = 0, inodes_per_group = 0, inode_size = 0,
                  descriptor_size = 0;
    bool wide = false, logical_view = false;

    explicit Image(const std::filesystem::path &file, const LpPartitionView *logical = nullptr)
        : stream(file, std::ios::binary), bytes(std::filesystem::file_size(file)) {
        if (!stream || bytes < 2048 || bytes > (16ULL << 30)) {
            bad("bounded image required");
        }

        partition_bytes = bytes;

        if (logical) {
            if (logical->bytes < 2048 || logical->offset > bytes ||
                logical->bytes > bytes - logical->offset) {
                bad("logical partition outside image");
            }

            offset = logical->offset;
            partition_bytes = logical->bytes;
            logical_view = true;
        } else if (number(read(1024, 1024), 56, 2) != 0xef53) {
            const auto header = read(512, 512);

            if (header.substr(0, 8) != "EFI PART" || number(header, 8, 4) != 0x10000 ||
                number(header, 12, 4) < 92 || number(header, 12, 4) > 512 ||
                number(header, 24, 8) != 1) {
                bad("raw ext4 or primary GPT required");
            }

            const auto header_size = static_cast<std::size_t>(number(header, 12, 4));
            auto checked = header.substr(0, header_size);
            std::fill(checked.begin() + 16, checked.begin() + 20, '\0');

            if (crc32(checked) != number(header, 16, 4)) {
                bad("GPT header CRC mismatch");
            }

            const auto table_lba = number(header, 72, 8), count = number(header, 80, 4),
                       width = number(header, 84, 4), first = number(header, 40, 8),
                       last = number(header, 48, 8);

            if (!count || count > 256 || width < 128 || width > 1024 || width % 8 ||
                table_lba > bytes / 512 || count * width > bytes - table_lba * 512 ||
                first > last || last >= bytes / 512 || number(header, 32, 8) >= bytes / 512) {
                bad("GPT table bounds invalid");
            }

            const auto table = read(table_lba * 512, static_cast<std::size_t>(count * width));

            if (crc32(table) != number(header, 88, 4)) {
                bad("GPT table CRC mismatch");
            }

            unsigned partitions = 0;

            for (std::size_t i = 0; i < count; ++i) {
                const auto entry = std::string_view(table).substr(i * width, width);

                if (entry.substr(0, 16) == std::string(16, '\0')) {
                    continue;
                }

                const auto begin = number(entry, 32, 8), end = number(entry, 40, 8);

                if (++partitions != 1 || begin < first || end > last || begin > end ||
                    end >= bytes / 512) {
                    bad("one bounded GPT data partition required");
                }

                offset = begin * 512;
                partition_bytes = (end - begin + 1) * 512;
            }

            if (partitions != 1) {
                bad("GPT data partition missing");
            }
        }

        const auto super = read(offset + 1024, 1024);

        if (number(super, 56, 2) != 0xef53 || number(super, 24, 4) > 2) {
            bad("supported ext4 superblock required");
        }

        block_size = 1024u << number(super, 24, 4);
        const auto incompatible = number(super, 96, 4);
        wide = (incompatible & 0x80) != 0;

        if (incompatible & ~std::uint64_t(0x2 | 0x40 | 0x80 | 0x200)) {
            bad("unsupported incompatible ext4 feature");
        }

        if (number(super, 100, 4) & 0x200) {
            bad("bigalloc ext4 unsupported");
        }

        blocks = number(super, 4, 4) | (wide ? number(super, 0x150, 4) << 32 : 0);
        inodes = static_cast<std::uint32_t>(number(super, 0, 4));
        inodes_per_group = static_cast<std::uint32_t>(number(super, 40, 4));
        inode_size = static_cast<std::uint32_t>(number(super, 88, 2));
        descriptor_size = wide ? static_cast<std::uint32_t>(number(super, 254, 2)) : 32;

        if (!blocks || blocks > partition_bytes / block_size || !inodes || !inodes_per_group ||
            inode_size < 128 || inode_size > block_size || inode_size % 4 ||
            descriptor_size < (wide ? 64u : 32u) || descriptor_size > block_size ||
            descriptor_size % 8 || number(super, 20, 4) != (block_size == 1024 ? 1u : 0u)) {
            bad("filesystem bounds invalid");
        }
    }

    std::string read(std::uint64_t at, std::size_t count) {
        if (logical_view && (at < offset || at - offset > partition_bytes ||
                             count > partition_bytes - (at - offset))) {
            bad("read outside logical partition");
        }

        if (at > bytes || count > bytes - at || count > (256ULL << 20)) {
            bad("image read exceeds bound");
        }

        std::string result(count, '\0');
        stream.clear();
        stream.seekg(static_cast<std::streamoff>(at));
        stream.read(result.data(), static_cast<std::streamsize>(count));

        if (static_cast<std::size_t>(stream.gcount()) != count) {
            bad("short image read");
        }

        return result;
    }

    std::string inode(std::uint32_t id) {
        if (!id || id > inodes) {
            bad("inode outside table");
        }

        const auto group = (id - 1) / inodes_per_group, index = (id - 1) % inodes_per_group;
        const auto descriptor = read(offset + (block_size == 1024 ? 2ULL : 1ULL) * block_size +
                                             std::uint64_t(group) * descriptor_size,
                                     descriptor_size);
        const auto table = number(descriptor, 8, 4) | (wide ? number(descriptor, 40, 4) << 32 : 0);

        if (!table || table >= blocks) {
            bad("inode table block outside filesystem");
        }

        const auto at = table * block_size + std::uint64_t(index) * inode_size;

        if (at > partition_bytes || inode_size > partition_bytes - at) {
            bad("inode outside partition");
        }

        return read(offset + at, inode_size);
    }

    struct Extent {
        std::uint64_t logical, physical, count;
        bool unwritten;
    };

    void extents(std::string_view node, unsigned expected, std::set<std::uint64_t> &visited,
                 std::vector<Extent> &result) {
        if (node.size() < 12 || number(node, 0, 2) != 0xf30a || number(node, 6, 2) != expected ||
            expected > 5) {
            bad("invalid extent tree");
        }

        const auto count = number(node, 2, 2), capacity = number(node, 4, 2);

        if (count > capacity || capacity > (node.size() - 12) / 12 ||
            result.size() + count > 65536) {
            bad("extent count outside node");
        }

        std::uint64_t previous = 0;

        for (unsigned i = 0; i < count; ++i) {
            const auto at = 12 + i * 12;
            const auto logical = number(node, at, 4);

            if (i && logical <= previous) {
                bad("unsorted extents");
            }

            previous = logical;

            if (expected) {
                const auto block = number(node, at + 4, 4) | (number(node, at + 8, 2) << 32);

                if (!block || block >= blocks || !visited.insert(block).second ||
                    visited.size() > 65536) {
                    bad("extent node outside filesystem or cyclic");
                }

                const auto child = read(offset + block * block_size, block_size);
                extents(child, expected - 1, visited, result);
            } else {
                const auto encoded = number(node, at + 4, 2),
                           physical = number(node, at + 8, 4) | (number(node, at + 6, 2) << 32);
                const bool unwritten = encoded > 32768;
                const auto length = unwritten ? encoded - 32768 : encoded;

                if (!length || !physical || physical >= blocks || length > blocks - physical) {
                    bad("extent data outside filesystem");
                }

                result.push_back({logical, physical, length, unwritten});
            }
        }
    }

    std::string content(const std::string &record, std::uint64_t maximum) {
        const auto size = number(record, 4, 4) | (number(record, 108, 4) << 32);

        if (size > maximum) {
            bad("file outside extraction budget");
        }

        if ((number(record, 32, 4) & 0x80000) == 0) {
            bad("non-extent or inline inode unsupported");
        }

        std::vector<Extent> mapped;
        std::set<std::uint64_t> visited;
        extents(std::string_view(record).substr(40, 60),
                static_cast<unsigned>(number(record, 46, 2)), visited, mapped);
        std::sort(mapped.begin(), mapped.end(), [](const auto &a, const auto &b) {
            return a.logical < b.logical;
        });
        std::uint64_t end = 0;
        std::string output(static_cast<std::size_t>(size), '\0');

        for (const auto &item : mapped) {
            if (item.logical < end) {
                bad("overlapping logical extents");
            }

            end = item.logical + item.count;
            const auto start = item.logical * block_size;

            if (start >= size || item.unwritten) {
                continue;
            }

            const auto count = static_cast<std::size_t>(
                    std::min<std::uint64_t>(item.count * block_size, size - start));
            const auto payload = read(offset + item.physical * block_size, count);
            std::copy(payload.begin(), payload.end(),
                      output.begin() + static_cast<std::ptrdiff_t>(start));
        }

        return output;
    }

    std::uint32_t lookup(std::string_view path) {
        std::uint32_t current = 2;
        std::size_t start = 1;

        while (start < path.size()) {
            const auto end = path.find('/', start);
            const auto part = path.substr(start, end == std::string_view::npos ? path.size() - start
                                                                               : end - start);
            const auto record = inode(current);

            if ((number(record, 0, 2) & 0170000) != 0040000) {
                bad("path component is not a directory");
            }

            const auto entries = content(record, 16ULL << 20);
            std::uint32_t found = 0;

            for (std::size_t at = 0; at < entries.size();) {
                if (entries.size() - at < 8) {
                    bad("truncated directory entry");
                }

                const auto id = number(entries, at, 4), length = number(entries, at + 4, 2),
                           name_length = number(entries, at + 6, 1);

                if (length < 8 || length % 4 || length > entries.size() - at ||
                    length > block_size - at % block_size || name_length > length - 8) {
                    bad("directory entry extent invalid");
                }

                if (id && std::string_view(entries).substr(at + 8, name_length) == part) {
                    if (found || id > inodes) {
                        bad("duplicate directory name or invalid inode");
                    }

                    found = static_cast<std::uint32_t>(id);
                }

                at += static_cast<std::size_t>(length);
            }

            if (!found) {
                bad("requested file not found");
            }

            current = found;

            if (end == std::string_view::npos) {
                break;
            }

            start = end + 1;
        }

        return current;
    }
};

std::string safe_path(const std::string &value) {
    if (value.size() < 2 || value.size() > 1024 || value.front() != '/' || value.back() == '/' ||
        value.find_first_of("\\:\r\n\t") != std::string::npos ||
        value.find("//") != std::string::npos) {
        bad("absolute filesystem path required");
    }

    const std::filesystem::path path(value);

    if (path.lexically_normal() != path) {
        bad("noncanonical filesystem path");
    }

    for (const auto &component : path.relative_path()) {
        if (component == "." || component == ".." || component.empty()) {
            bad("path traversal rejected");
        }
    }

    return value.substr(1);
}
} // namespace

Json extract_pinned_ext4_files(const std::filesystem::path &image, const std::string &pin,
                               const std::vector<std::string> &paths,
                               const std::filesystem::path &destination, std::uint64_t reserve,
                               std::string_view logical_partition,
                               std::map<std::string, Ext4Inode> *inodes) {
    if (!sha256_text(pin) || paths.empty() || paths.size() > 256) {
        bad("bounded pinned extraction required");
    }

    std::set<std::string> unique;

    for (const auto &path : paths) {
        if (!unique.insert(safe_path(path)).second) {
            bad("duplicate extraction path");
        }
    }

    if (!image.is_absolute() ||
        !std::filesystem::is_regular_file(std::filesystem::symlink_status(image)) ||
        std::filesystem::hard_link_count(image) != 1 || !destination.is_absolute() ||
        destination.lexically_normal() != destination || std::filesystem::exists(destination) ||
        std::filesystem::is_symlink(destination)) {
        bad("ordinary image and fresh destination required");
    }

    const auto epoch = cache_file_identity(image);

    if (sha256_file(image) != pin) {
        bad("image differs from SHA pin");
    }

    const bool raw_vendor = logical_partition == "vendor";
    LpPartitionView view;

    if (!logical_partition.empty() && !raw_vendor) {
        if (logical_partition != "system" && logical_partition != "system_ext") {
            bad("unsupported logical partition selection");
        }

        view = read_lp_partition(image, pin, logical_partition);
    }

    Image filesystem(image, logical_partition.empty() || raw_vendor ? nullptr : &view);
    struct Item {
        std::string path, bytes;
    };
    std::vector<Item> requested;
    std::uint64_t total = 0;

    for (const auto &path : paths) {
        if (raw_vendor && !path.starts_with("/vendor/")) {
            bad("vendor mount path required");
        }

        const auto record = filesystem.inode(filesystem.lookup(raw_vendor ? path.substr(7) : path));

        if ((number(record, 0, 2) & 0170000) != 0100000) {
            bad("requested inode is not a regular file; aliases unsupported");
        }

        if (inodes) {
            (*inodes)[path] = {
                    static_cast<unsigned>(number(record, 0, 2) & 07777),
                    static_cast<unsigned>(number(record, 2, 2) | number(record, 120, 2) << 16),
                    static_cast<unsigned>(number(record, 24, 2) | number(record, 122, 2) << 16)};
        }

        // VehicleSetting of the Qinggan11 6.11.1 and 7.3.1 system images exceeds the 256 MiB file
        // budget; it is read only from its exact image and must match its exact extent and SHA.
        struct Vehicle {
            std::string_view image, sha256;
            std::uint64_t bytes;
        };
        constexpr Vehicle vehicles[] = {
                {"ee0c8241b7293b9cd9f936f622c556ac11ab3f92a0f60733e92dca1c1610f5c4",
                 "cd5f85c02e10b4ed99691251caf73b137fb7a152186fad3057578f1c0317dd92", 425993577},
                {"c602475a9890bbe725a75ede7c8f667635fc1be69f9db65cae22e752c28fa3cd",
                 "f37a53f1397678af472a87d89d903ba8f6ed6ac892d83ae3117b57bbe3b21360", 426096627},
                {"563f613c13c104f129a3b996b32328f0751a08626f2ca5847d14695dc39f2456",
                 "8f76a02085fe03eb0292c22453977ff407fa9e6a491a9d6a13af3cfbdaee1784", 396876814}};
        const auto vehicle = std::find_if(std::begin(vehicles), std::end(vehicles),
                                          [&](const Vehicle &item) {
                                              return item.image == pin;
                                          });
        const bool qinggan11_vehicle =
                logical_partition.empty() && vehicle != std::end(vehicles) &&
                path == "/system/priv-app/VehicleSetting-release-signed/VehicleSetting-release-signed.apk";
        auto bytes = filesystem.content(
                record, ((raw_vendor || qinggan11_vehicle) ? 512ULL : 256ULL) << 20);

        if (qinggan11_vehicle &&
            (bytes.size() != vehicle->bytes || sha256_bytes(bytes) != vehicle->sha256)) {
            bad("Free A11 vehicle original differs");
        }

        if (bytes.size() > (512ULL << 20) - total) {
            bad("combined extraction exceeds maximum");
        }

        total += bytes.size();
        requested.push_back({safe_path(path), std::move(bytes)});
    }

    auto ancestor = destination.parent_path();

    while (!std::filesystem::exists(ancestor)) {
        ancestor = ancestor.parent_path();
    }

    require_disk_space("EXT4_IMAGE", ancestor, total, reserve);

    ensure_private_directory(destination.parent_path());

    if (!std::filesystem::create_directory(destination)) {
        bad("exclusive destination creation failed");
    }

    const auto token = random_token();
    write_private_json(destination / ".owner.json", {{"token", token}});
    struct Cleanup {
        std::filesystem::path path;
        std::string token;
        bool published = false;

        ~Cleanup() {
            if (published) {
                return;
            }

            try {
                if (read_private_json(path / ".owner.json").at("token") == token) {
                    std::filesystem::remove_all(path);
                }
            } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
            }
        }
    } cleanup{destination, token};
    Json files = Json::object();

    for (const auto &item : requested) {
        const auto output = destination / item.path;
        ensure_private_directory(output.parent_path());
        std::ofstream stream(output, std::ios::binary | std::ios::out);
        stream.write(item.bytes.data(), static_cast<std::streamsize>(item.bytes.size()));
        stream.close();
        const auto hash = sha256_bytes(item.bytes);

        if (!stream || sha256_file(output) != hash) {
            bad("incomplete output write");
        }

        files[item.path] = {{"bytes", item.bytes.size()}, {"sha256", hash}};
    }

    if (cache_file_identity(image) != epoch || sha256_file(image) != pin) {
        bad("source changed during extraction");
    }

    Json result = {{"schema", 1},
                   {"image_sha256", pin},
                   {"partition_offset", filesystem.offset},
                   {"block_size", filesystem.block_size},
                   {"files", files},
                   {"bytes", total},
                   {"native", true},
                   {"filesystem_mounted", false}};

    if (raw_vendor) {
        result["logical_partition"] = "vendor";
        result["logical_partition_bytes"] = std::filesystem::file_size(image);
    } else if (!logical_partition.empty()) {
        result["logical_partition"] = view.name;
        result["logical_partition_bytes"] = view.bytes;
        result["lp_metadata_sha256"] = view.metadata_sha256;
    }

    write_private_json(destination / "receipt.json", result);
    std::filesystem::remove(destination / ".owner.json");
    cleanup.published = true;

    return result;
}
} // namespace voyemu
