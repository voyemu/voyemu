#include "android_vbmeta.hpp"
#include "android_vbmeta_fixture.hpp"
#include "process.hpp"
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace voyemu;
using namespace voyemu::vbmeta_fixture;

namespace {
void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

DiskRead memory(const std::string &bytes) {
    return [&bytes](std::uint64_t offset, std::size_t size) {
        return offset <= bytes.size() ? bytes.substr(offset, size) : std::string{};
    };
}

bool rejected(const std::function<void()> &call, std::string_view message) {
    try {
        call();
    } catch (const std::exception &error) {
        const std::string_view text = error.what();

        return text.starts_with("ANDROID_VBMETA: ") && text.find(message) != std::string::npos;
    }

    return false;
}
} // namespace

int main(int argc, char **argv) {
    try {
        // The digest covers the top vbmeta and then each chained vbmeta, as the guest hashes them.
        const auto stock = disk(0);
        const auto chain = android_vbmeta_chain(memory(stock.bytes), stock.partitions);
        check(chain.digest == sha256_bytes(stock.top + stock.system) &&
                      chain.bytes == stock.top.size() + stock.system.size() && chain.flags == 0,
              "vbmeta chain digest differs");

        // adb remount sets HASHTREE_DISABLED in the top vbmeta, which changes the digest.
        const auto remounted = disk(1);
        const auto disabled = android_vbmeta_chain(memory(remounted.bytes), remounted.partitions);
        check(disabled.flags == 1 && disabled.digest != chain.digest &&
                      disabled.digest == sha256_bytes(remounted.top + remounted.system),
              "remounted vbmeta digest differs");

        check(rejected(
                      [&] {
                          const auto other = disk(0, "vendor");
                          (void)android_vbmeta_chain(memory(other.bytes), other.partitions);
                      },
                      "chained partition without a known extent: vendor"),
              "unknown chained partition accepted");
        auto broken = stock;
        broken.bytes.replace(broken.partitions.at("system").offset + 32 * 1024 - 64, 4, "XXXX");
        check(rejected(
                      [&] {
                          (void)android_vbmeta_chain(memory(broken.bytes), broken.partitions);
                      },
                      "AVB footer required: system"),
              "missing AVB footer accepted");

        // The machine parameters keep the stock text and change only the digest.
        const auto stock_parameters = parameters(chain.digest, chain.bytes);
        const auto machine = android_verified_boot_parameters(stock_parameters, chain.digest,
                                                              disabled);
        check(machine == parameters(disabled.digest, chain.bytes) &&
                      android_verified_boot_digest(machine) == disabled.digest,
              "machine boot parameters differ");
        check(rejected(
                      [&] {
                          (void)android_verified_boot_parameters(
                                  parameters(chain.digest, chain.bytes + 1), chain.digest,
                                  disabled);
                      },
                      "boot parameters differ from the stock vbmeta chain"),
              "boot parameters of another vbmeta size accepted");
        check(rejected(
                      [&] {
                          (void)android_verified_boot_parameters(stock_parameters,
                                                                 std::string(64, 'c'), disabled);
                      },
                      "boot parameters differ from the stock vbmeta chain"),
              "boot parameters of another stock digest accepted");
        check(rejected(
                      [&] {
                          (void)android_verified_boot_digest("major_version: 2\n");
                      },
                      "declare no vbmeta digest"),
              "boot parameters without a digest accepted");

        // The raw reader reads the same chain from a file and refuses reads past its end.
        const std::filesystem::path directory = argc > 1 ? argv[1] : ".";
        std::filesystem::create_directories(directory);
        const auto file = directory / ("android-vbmeta-" + random_token() + ".img");
        {
            std::ofstream out(file, std::ios::binary);
            out.write(remounted.bytes.data(), static_cast<std::streamsize>(remounted.bytes.size()));
        }
        {
            // The reader keeps the image open, and Windows refuses to remove an open file.
            const auto reader = raw_disk_reader(file);
            check(android_vbmeta_chain(reader, remounted.partitions).digest == disabled.digest,
                  "raw disk chain differs");
            check(rejected(
                          [&] {
                              (void)reader(remounted.bytes.size() - 8, 16);
                          },
                          "read outside the disk image"),
                  "read past the disk accepted");
        }
        std::filesystem::remove(file);
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }

    return 0;
}
