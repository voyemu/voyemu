#include "ext4_image.hpp"
#include "lp_image_fixture.hpp"
#include "process.hpp"
#include <fstream>
#include <iostream>
using namespace voyemu;

static void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

static void put(std::string &bytes, std::size_t at, std::uint64_t value, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i) {
        bytes.at(at + i) = static_cast<char>(value >> (8 * i));
    }
}

static std::string fixture() {
    std::string image(8192, '\0');
    const auto super = 1024;

    put(image, super, 16);
    put(image, super + 4, 8);
    put(image, super + 20, 1);
    put(image, super + 32, 8);
    put(image, super + 40, 16);
    put(image, super + 56, 0xef53, 2);
    put(image, super + 88, 128, 2);
    put(image, super + 96, 0x42);
    put(image, 2048 + 8, 3);
    auto inode = [&](unsigned index, unsigned mode, unsigned size, unsigned physical) {
        const auto at = 3072 + (index - 1) * 128;
        put(image, at, mode, 2);
        put(image, at + 4, size);
        put(image, at + 32, 0x80000);
        put(image, at + 40, 0xf30a, 2);
        put(image, at + 42, 1, 2);
        put(image, at + 44, 4, 2);
        put(image, at + 56, 1, 2);
        put(image, at + 60, physical);
    };
    inode(2, 0040755, 1024, 5);
    inode(3, 0100644, 6, 6);
    auto entry = [&](unsigned at, unsigned id, unsigned length, const std::string &name) {
        put(image, 5120 + at, id);
        put(image, 5120 + at + 4, length, 2);
        put(image, 5120 + at + 6, name.size(), 1);
        image.replace(5120 + at + 8, name.size(), name);
    };
    entry(0, 2, 12, ".");
    entry(12, 2, 12, "..");
    entry(24, 3, 1000, "own");
    image.replace(6144, 6, "native");

    return image;
}

int main(int argc, char **argv) {
    try {
        if (argc >= 7 && std::string_view(argv[1]) == "--extract-logical") {
            std::vector<std::string> paths;

            for (int i = 6; i < argc; ++i) {
                paths.emplace_back(argv[i]);
            }

            std::cout << extract_pinned_ext4_files(std::filesystem::canonical(argv[2]), argv[3],
                                                   paths, std::filesystem::path(argv[5]),
                                                   20ULL << 30, argv[4])
                                 .dump(2)
                      << '\n';

            return 0;
        }

        if (argc >= 6 && std::string_view(argv[1]) == "--extract-batch") {
            std::vector<std::string> paths;

            for (int i = 5; i < argc; ++i) {
                paths.emplace_back(argv[i]);
            }

            std::cout << extract_pinned_ext4_files(std::filesystem::canonical(argv[2]), argv[3],
                                                   paths, std::filesystem::path(argv[4]))
                                 .dump(2)
                      << '\n';

            return 0;
        }

        if (argc == 6 && std::string_view(argv[1]) == "--extract") {
            std::cout << extract_pinned_ext4_files(std::filesystem::canonical(argv[2]), argv[3],
                                                   {argv[4]}, std::filesystem::path(argv[5]))
                                 .dump(2)
                      << '\n';

            return 0;
        }

        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-ext4-" + random_token());
        ensure_private_directory(root);
        struct Cleanup {
            std::filesystem::path path;

            ~Cleanup() {
                std::filesystem::remove_all(path);
            }
        } cleanup{root};
        auto store = [&](const std::string &name, const std::string &data) {
            const auto file = root / name;
            std::ofstream out(file, std::ios::binary);
            out << data;
            out.close();

            return file;
        };
        const auto good = fixture();
        const auto file = store("good.img", good);
        const auto output = root / "good";
        const auto result = extract_pinned_ext4_files(file, sha256_bytes(good), {"/own"}, output,
                                                      0);
        check(result.at("bytes") == 6 && sha256_file(output / "own") == sha256_bytes("native") &&
                      result.at("filesystem_mounted") == false,
              "raw filesystem extent extraction exact without mount");
        // The inode of each requested path carries its permission bits and full owner ids.
        auto owned = good;
        put(owned, 3072 + 2 * 128 + 2, 1000, 2);
        put(owned, 3072 + 2 * 128 + 120, 1, 2);
        put(owned, 3072 + 2 * 128 + 24, 2000, 2);
        const auto owned_file = store("owned.img", owned);
        std::map<std::string, Ext4Inode> inodes;
        (void)extract_pinned_ext4_files(owned_file, sha256_bytes(owned), {"/own"}, root / "owned",
                                        0, {}, &inodes);
        check(inodes.size() == 1 && inodes.at("/own").mode == 0644 &&
                      inodes.at("/own").uid == 65536 + 1000 && inodes.at("/own").gid == 2000,
              "extracted inode mode and owner differ");
        const auto dynamic = lp_fixture::fixture(good);
        const auto dynamic_file = store("dynamic.img", dynamic);
        const auto dynamic_output = root / "dynamic";
        const auto dynamic_result = extract_pinned_ext4_files(
                dynamic_file, sha256_bytes(dynamic), {"/own"}, dynamic_output, 0, "system");
        check(dynamic_result.at("bytes") == 6 &&
                      dynamic_result.at("logical_partition") == "system" &&
                      dynamic_result.at("partition_offset") == 98304 &&
                      sha256_file(dynamic_output / "own") == sha256_bytes("native"),
              "explicit validated LP system extracts exact ext4 bytes without copying image");

        for (const auto selector : {"", "product"}) {
            const auto rejected_output =
                    root / (std::string("selector-") + (selector[0] ? selector : "default"));
            bool rejected = false;
            try {
                extract_pinned_ext4_files(dynamic_file, sha256_bytes(dynamic), {"/own"},
                                          rejected_output, 0, selector);
            } catch (...) {
                rejected = true;
            }

            check(rejected && !std::filesystem::exists(rejected_output),
                  "default strict GPT and unsupported logical selections reject before output");
        }

        auto malformed = dynamic;
        malformed.at(65536 + 12288 + 10) ^= 1;
        const auto malformed_file = store("dynamic-invalid.img", malformed);
        bool rejected_lp = false;
        try {
            extract_pinned_ext4_files(malformed_file, sha256_bytes(malformed), {"/own"},
                                      root / "invalid-lp", 0, "system");
        } catch (...) {
            rejected_lp = true;
        }

        check(rejected_lp && !std::filesystem::exists(root / "invalid-lp"),
              "invalid LP metadata rejects before extraction output");

        for (unsigned mode = 0; mode < 5; ++mode) {
            auto data = good;
            auto paths = std::vector<std::string>{"/own"};

            if (mode == 0) {
                put(data, 5120 + 24 + 4, 0, 2);
            }

            if (mode == 1) {
                put(data, 3072 + 2 * 128 + 60, 99);
            }

            if (mode == 2) {
                put(data, 3072 + 2 * 128, 0120777, 2);
            }

            if (mode == 3) {
                paths = {"/../own"};
            }

            if (mode == 4) {
                paths = {"/own", "/own"};
            }

            const auto source = store("bad-" + std::to_string(mode) + ".img", data),
                       destination = root / ("bad-" + std::to_string(mode));
            bool rejected = false;
            try {
                extract_pinned_ext4_files(source, sha256_bytes(data), paths, destination, 0);
            } catch (...) {
                rejected = true;
            }

            check(rejected && !std::filesystem::exists(destination),
                  "invalid directory/extent/alias/path rejected before output");
        }

        const auto vendor_output = root / "vendor";
        const auto vendor = extract_pinned_ext4_files(file, sha256_bytes(good), {"/vendor/own"},
                                                      vendor_output, 0, "vendor");
        check(vendor.at("logical_partition") == "vendor" && vendor.at("partition_offset") == 0 &&
                      vendor.at("files").contains("vendor/own") &&
                      sha256_file(vendor_output / "vendor/own") == sha256_bytes("native"),
              "raw vendor uses explicit mount prefix and retains provenance");

        for (unsigned mode = 0; mode < 4; ++mode) {
            const auto rejected_output = root / ("vendor-negative-" + std::to_string(mode));
            bool rejected = false;
            try {
                extract_pinned_ext4_files(file,
                                          mode == 3 ? std::string(64, 'f') : sha256_bytes(good),
                                          {mode == 0   ? "/own"
                                           : mode == 1 ? "/vendor/../own"
                                                       : "/vendor/own"},
                                          rejected_output, 0, mode == 2 ? "unknown" : "vendor");
            } catch (...) {
                rejected = true;
            }

            check(rejected && !std::filesystem::exists(rejected_output),
                  "vendor mount, traversal, unknown partition and SHA mismatch reject before output");
        }

        std::cout << "native ext4 reader, exact extents, bounds and aliases guards passed\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
