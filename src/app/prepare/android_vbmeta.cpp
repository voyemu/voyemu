#include "android_vbmeta.hpp"
#include "check.hpp"
#include "process.hpp"
#include <fstream>
#include <memory>
#include <regex>
#include <vector>

namespace voyemu {
namespace {
constexpr Check need{"ANDROID_VBMETA"};
constexpr std::size_t max_vbmeta_bytes = 64 * 1024;

std::uint64_t little(std::string_view s, std::size_t at, unsigned count) {
    need(at <= s.size() && count <= s.size() - at, "field outside structure");
    std::uint64_t value = 0;

    for (unsigned i = 0; i < count; ++i) {
        value |= std::uint64_t(static_cast<unsigned char>(s[at + i])) << (i * 8);
    }

    return value;
}

std::uint64_t big(std::string_view s, std::size_t at, unsigned count) {
    need(at <= s.size() && count <= s.size() - at, "field outside structure");
    std::uint64_t value = 0;

    for (unsigned i = 0; i < count; ++i) {
        value = value << 8 | static_cast<unsigned char>(s[at + i]);
    }

    return value;
}

std::string read_exact(const DiskRead &read, std::uint64_t offset, std::uint64_t bytes) {
    need(bytes <= max_vbmeta_bytes, "vbmeta structure exceeds its bound");
    auto data = read(offset, static_cast<std::size_t>(bytes));
    need(data.size() == bytes, "short disk read");

    return data;
}

// The byte offset of the GPT partition name.
std::uint64_t gpt_partition(const DiskRead &read, std::string_view name) {
    const auto header = read_exact(read, 512, 92);

    need(header.substr(0, 8) == "EFI PART", "primary GPT required");
    const auto lba = little(header, 72, 8), count = little(header, 80, 4),
               width = little(header, 84, 4);
    need(count > 0 && count <= 256 && width >= 128 && width <= 1024 && lba > 0 &&
                 lba <= (UINT64_MAX >> 10),
         "GPT entry table bounds invalid");
    std::uint64_t found = 0;

    for (std::uint64_t i = 0; i < count; ++i) {
        const auto entry = read_exact(read, lba * 512 + i * width, 128);

        if (entry.substr(0, 16) == std::string(16, '\0')) {
            continue;
        }

        std::string label;

        for (unsigned j = 0; j < 36; ++j) {
            const auto c = little(entry, 56 + j * 2, 2);

            if (!c) {
                break;
            }

            label += c < 127 ? static_cast<char>(c) : '?';
        }

        if (label == name) {
            need(!found, "duplicate GPT partition " + std::string(name));
            found = little(entry, 32, 8) * 512;
            need(found > 0 && little(entry, 40, 8) >= little(entry, 32, 8),
                 "GPT partition extent invalid");
        }
    }

    need(found, "GPT partition missing: " + std::string(name));

    return found;
}

struct Vbmeta {
    std::string bytes;
    std::uint32_t flags{};
    std::vector<std::string> chained;
};

Vbmeta vbmeta_at(const DiskRead &read, std::uint64_t offset) {
    const auto header = read_exact(read, offset, 256);

    need(header.substr(0, 4) == "AVB0", "vbmeta magic required");
    const auto authentication = big(header, 12, 8), auxiliary = big(header, 20, 8);
    need(authentication <= max_vbmeta_bytes && auxiliary <= max_vbmeta_bytes &&
                 256 + authentication + auxiliary <= max_vbmeta_bytes,
         "vbmeta blocks exceed their bound");
    Vbmeta result;
    result.bytes = read_exact(read, offset, 256 + authentication + auxiliary);
    result.flags = static_cast<std::uint32_t>(big(header, 120, 4));
    const auto descriptors = big(header, 96, 8), size = big(header, 104, 8);
    need(descriptors <= auxiliary && size <= auxiliary - descriptors,
         "vbmeta descriptors outside the auxiliary block");
    const auto all =
            std::string_view(result.bytes).substr(256 + authentication + descriptors, size);

    for (std::size_t at = 0; at < all.size();) {
        const auto tag = big(all, at, 8), following = big(all, at + 8, 8);
        need(following % 8 == 0 && following <= all.size() - at - 16,
             "vbmeta descriptor extent invalid");

        // AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: the partition name follows a 92-byte header.
        if (tag == 4) {
            const auto length = big(all, at + 20, 4);
            need(following >= 76 && length > 0 && length <= following - 76,
                 "chain descriptor name invalid");
            result.chained.emplace_back(all.substr(at + 92, length));
        }

        at += 16 + following;
    }

    return result;
}
} // namespace

VbmetaChain android_vbmeta_chain(const DiskRead &read,
                                 const std::map<std::string, LogicalPartitionExtent> &partitions) {
    const auto top = vbmeta_at(read, gpt_partition(read, "vbmeta"));
    auto digest_input = top.bytes;

    for (const auto &name : top.chained) {
        const auto found = partitions.find(name);
        need(found != partitions.end(), "chained partition without a known extent: " + name);
        const auto &extent = found->second;
        need(extent.bytes >= 4096 && extent.offset <= UINT64_MAX - extent.bytes,
             "chained partition extent invalid: " + name);
        const auto footer = read_exact(read, extent.offset + extent.bytes - 64, 64);
        need(footer.substr(0, 4) == "AVBf", "AVB footer required: " + name);
        const auto offset = big(footer, 20, 8), size = big(footer, 28, 8);
        need(size >= 256 && size <= max_vbmeta_bytes && offset <= extent.bytes - 64 - size,
             "AVB footer vbmeta outside its partition: " + name);
        const auto chained = vbmeta_at(read, extent.offset + offset);
        need(chained.bytes.size() <= size && chained.chained.empty(),
             "chained vbmeta exceeds its footer: " + name);
        digest_input += chained.bytes;
    }

    return {sha256_bytes(digest_input), digest_input.size(), top.flags};
}

DiskRead raw_disk_reader(const std::filesystem::path &image) {
    const auto size = std::filesystem::file_size(image);
    auto file = std::make_shared<std::ifstream>(image, std::ios::binary);

    need(bool(*file), "disk image could not be opened");

    return [file, size](std::uint64_t offset, std::size_t bytes) {
        need(bytes <= max_vbmeta_bytes && offset <= size && bytes <= size - offset,
             "read outside the disk image");
        std::string data(bytes, '\0');
        file->clear();
        file->seekg(static_cast<std::streamoff>(offset));
        file->read(data.data(), static_cast<std::streamsize>(bytes));
        need(bool(*file), "short disk image read");

        return data;
    };
}

std::string android_verified_boot_parameters(std::string_view stock, std::string_view stock_digest,
                                             const VbmetaChain &chain) {
    need(sha256_text(stock_digest) && sha256_text(chain.digest) && stock.size() <= 4096,
         "bounded boot parameters and digests required");
    const std::string text(stock);
    need(android_verified_boot_digest(text) == stock_digest &&
                 text.find("param: \"androidboot.vbmeta.size=" + std::to_string(chain.bytes) +
                           "\"\n") != std::string::npos,
         "boot parameters differ from the stock vbmeta chain");
    std::string result;

    for (std::size_t at = 0;;) {
        const auto next = text.find(stock_digest, at);
        result += text.substr(at, next == std::string::npos ? std::string::npos : next - at);

        if (next == std::string::npos) {
            break;
        }

        result += chain.digest;
        at = next + stock_digest.size();
    }

    return result;
}

std::string android_verified_boot_digest(std::string_view parameters) {
    const std::string text(parameters);
    const std::regex field("(?:^|\\n)param: \"androidboot\\.vbmeta\\.digest=([0-9a-f]{64})\"\\n");
    std::smatch match;

    need(text.size() <= 4096 && std::regex_search(text, match, field),
         "boot parameters declare no vbmeta digest");
    const auto digest = match[1].str();
    need(std::regex_search(match.suffix().str(), field) == false,
         "boot parameters declare more than one vbmeta digest");

    return digest;
}
} // namespace voyemu
