#pragma once
#include "android_vbmeta.hpp"
#include <cstdint>
#include <map>
#include <string>

// A synthetic disk with the GPT vbmeta partition and the vbmeta chain of an API 30 system image.
namespace voyemu::vbmeta_fixture {
inline void little(std::string &bytes, std::size_t at, std::uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) {
        bytes.at(at + i) = static_cast<char>(value >> (8 * i));
    }
}

inline void big(std::string &bytes, std::size_t at, std::uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) {
        bytes.at(at + i) = static_cast<char>(value >> (8 * (width - 1 - i)));
    }
}

inline std::string descriptor(std::uint64_t tag, std::string body) {
    body.resize((body.size() + 7) / 8 * 8, '\0');
    std::string bytes(16, '\0');
    big(bytes, 0, tag, 8);
    big(bytes, 8, body.size(), 8);

    return bytes + body;
}

inline std::string chain(const std::string &name) {
    std::string body(76, '\0');

    big(body, 0, 1, 4);
    big(body, 4, name.size(), 4);

    return descriptor(4, body + name);
}

inline std::string vbmeta(const std::string &descriptors, std::uint32_t flags) {
    const std::string authentication(64, 'a');
    const std::string auxiliary = descriptors + std::string(32, 'k');
    std::string header(256, '\0');

    header.replace(0, 4, "AVB0");
    big(header, 12, authentication.size(), 8);
    big(header, 20, auxiliary.size(), 8);
    big(header, 96, 0, 8);
    big(header, 104, descriptors.size(), 8);
    big(header, 120, flags, 4);

    return header + authentication + auxiliary;
}

struct Disk {
    std::string bytes, top, system;
    std::map<std::string, LogicalPartitionExtent> partitions;
};

// GPT entries at LBA 2; vbmeta at LBA 16; the system logical partition at 64 KiB. flags 1 is the
// HASHTREE_DISABLED flag that adb remount sets.
inline Disk disk(std::uint32_t flags, const std::string &chained = "system") {
    Disk result;

    result.bytes.assign(128 * 1024, '\0');
    result.bytes.replace(512, 8, "EFI PART");
    little(result.bytes, 512 + 72, 2, 8);
    little(result.bytes, 512 + 80, 4, 4);
    little(result.bytes, 512 + 84, 128, 4);
    const auto entry = [&](unsigned index, std::uint64_t first, std::uint64_t last,
                           const std::string &name) {
        const auto at = 1024 + index * 128;
        result.bytes[at] = 1;
        little(result.bytes, at + 32, first, 8);
        little(result.bytes, at + 40, last, 8);

        for (std::size_t i = 0; i < name.size(); ++i) {
            little(result.bytes, at + 56 + i * 2, static_cast<unsigned char>(name[i]), 2);
        }
    };
    entry(0, 16, 31, "vbmeta");
    entry(1, 32, 255, "super");
    result.top = vbmeta(descriptor(1, std::string(40, 'h')) + chain(chained), flags);
    result.bytes.replace(16 * 512, result.top.size(), result.top);
    const std::uint64_t offset = 64 * 1024, bytes = 32 * 1024;
    result.system = vbmeta(descriptor(1, std::string(24, 's')), 0);
    const std::uint64_t at = 8 * 1024;
    result.bytes.replace(offset + at, result.system.size(), result.system);
    std::string footer(64, '\0');
    footer.replace(0, 4, "AVBf");
    big(footer, 20, at, 8);
    big(footer, 28, result.system.size(), 8);
    result.bytes.replace(offset + bytes - 64, 64, footer);
    result.partitions = {{"system", {offset, bytes}}};

    return result;
}

// The boot parameters that declare digest and the vbmeta size bytes, in the form of the SDK.
inline std::string parameters(const std::string &digest, std::uint64_t bytes) {
    const auto size = std::to_string(bytes);

    return "# androidboot.vbmeta.size=" + size +
           " androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.digest=" + digest +
           "\nmajor_version: 2\nparam: \"androidboot.vbmeta.size=" + size +
           "\"\nparam: \"androidboot.vbmeta.hash_alg=sha256\"\nparam: "
           "\"androidboot.vbmeta.digest=" +
           digest + "\"\n";
}
} // namespace voyemu::vbmeta_fixture
