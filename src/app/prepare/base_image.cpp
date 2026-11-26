#include "base_image.hpp"
#include "check.hpp"
#include "error.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include "quickboot.hpp"
#include "sdk_archive.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
namespace voyemu {
namespace {
bool sha256_pin(const Json &value) {
    return value.is_string() && sha256_text(value.get_ref<const std::string &>());
}
} // namespace

AndroidBaseIdentity native_base_identity(const Json &descriptor) {
    const auto package = descriptor.value("package", std::string{}),
               revision = descriptor.value("revision", std::string{}),
               url = descriptor.value("url", std::string{});
    const auto identity = android_package_identity(package);
    const bool x86 = identity.abi == "x86_64";

    if (identity.api == 0 || revision.empty() ||
        revision.find_first_not_of("0123456789") != std::string::npos ||
        !url.starts_with("https://dl.google.com/android/repository/sys-img/android/") ||
        (x86 &&
         !url.starts_with("https://dl.google.com/android/repository/sys-img/android/x86_64-" +
                          std::to_string(identity.api) + "_")) ||
        !sha256_pin(descriptor.value("sha256", Json()))) {
        throw VoyemuError("BASE_DESCRIPTOR", "unsupported or unpinned Android system image");
    }

    return identity;
}

std::string_view android_guest_abi(const Json &definition) {
    if (!definition.contains("android")) {
        return "arm64-v8a";
    }

    return native_base_identity(definition.at("android")).abi;
}

bool android_acceleration_required(const Json &definition) {
    const auto emulator = definition.value("emulator", Json::object());

    if (!emulator.contains("acceleration")) {
        return false;
    }

    if (emulator.at("acceleration") != "required") {
        throw VoyemuError("ANDROID_ACCELERATION", "emulator.acceleration accepts only required");
    }

    return true;
}

unsigned native_base_api(const Json &descriptor) {
    return native_base_identity(descriptor).api;
}

CleanBase native_clean_base(const Json &descriptor) {
    const auto api = native_base_api(descriptor);
    const auto clean = descriptor.find("clean_base");
    bool valid = clean != descriptor.end() && clean->is_object() &&
                 sha256_pin(clean->value("receipt_sha256", Json()));

    for (const auto *group : {"boot_files", "images", "files"}) {
        valid = valid && clean->value(group, Json()).is_object() && !clean->at(group).empty() &&
                std::all_of(clean->at(group).begin(), clean->at(group).end(), sha256_pin);
    }

    // The API30 system image is a super image whose logical partitions Voyemu reads.
    if (valid && api == 30) {
        const auto partitions = clean->value("logical_partitions", Json());
        valid = partitions.is_object() && sha256_pin(partitions.value("metadata_sha256", Json()));

        for (const auto *name : {"system", "system_ext"}) {
            const auto partition = valid ? partitions.value(name, Json()) : Json();
            valid = valid && partition.is_object() &&
                    partition.value("offset", Json()).is_number_unsigned() &&
                    partition.value("bytes", Json()).is_number_unsigned();
        }
    }

    if (!valid) {
        throw VoyemuError("BASE_DESCRIPTOR", "clean base pins required");
    }

    CleanBase result;
    result.receipt_sha256 = clean->at("receipt_sha256").get<std::string>();
    result.boot_files = clean->at("boot_files").get<std::map<std::string, std::string>>();
    result.images = clean->at("images").get<std::map<std::string, std::string>>();
    result.files = clean->at("files").get<std::map<std::string, std::string>>();

    if (api == 30) {
        const auto &partitions = clean->at("logical_partitions");
        result.metadata_sha256 = partitions.at("metadata_sha256").get<std::string>();

        for (auto [name, partition] :
             {std::pair{"system", &result.system}, std::pair{"system_ext", &result.system_ext}}) {
            partition->offset = partitions.at(name).at("offset").get<std::uint64_t>();
            partition->bytes = partitions.at(name).at("bytes").get<std::uint64_t>();
        }
    }

    return result;
}

std::string CleanBase::pin(const char *group, const std::string &name) const {
    const auto &pins = std::string_view(group) == "boot_files" ? boot_files
                       : std::string_view(group) == "images"   ? images
                                                               : files;
    const auto found = pins.find(name);

    if (found == pins.end()) {
        throw VoyemuError("BASE_DESCRIPTOR",
                          "no clean base pin for " + std::string(group) + " " + name);
    }

    return found->second;
}

std::string native_base_pin(const Json &descriptor, const char *group, const std::string &name) {
    return native_clean_base(descriptor).pin(group, name);
}

Json verify_native_base_image(const Json &descriptor, const std::filesystem::path &directory) {
    // The deterministic inventory receipt of the pinned public SDK ZIP, pinned in clean_base.
    // Binding the receipt prevents replacing both a cached image and its declared hash.
    const auto receipt_pin = native_clean_base(descriptor).receipt_sha256;
    auto require = [](bool value, const char *message) {
        if (!value) {
            throw VoyemuError("BASE_CACHE", message);
        }
    };
    auto ordinary = [&](const std::filesystem::path &path) {
        require(path.is_absolute() && path.lexically_normal() == path,
                "normalized absolute cache path required");

        require(!os::linked_ancestor(path), "linked cache input rejected");
    };

    ordinary(directory);
    require(std::filesystem::is_directory(directory), "extracted cache directory missing");
    const auto receipt_file = directory / "base.json";
    ordinary(receipt_file);
    require(std::filesystem::is_regular_file(receipt_file) &&
                    std::filesystem::file_size(receipt_file) <= 512 * 1024,
            "bounded extraction receipt missing");
    const auto receipt_epoch = cache_file_identity(receipt_file);
    require(sha256_file(receipt_file) == receipt_pin, "registered extraction receipt differs");
    const auto receipt = read_private_json(receipt_file, 512 * 1024);
    require(receipt.at("schema") == 1 && receipt.at("native") == true &&
                    receipt.at("prepared_VM") == false &&
                    receipt.at("archive_sha256") == descriptor.at("sha256") &&
                    receipt.at("package") == descriptor.at("package") &&
                    receipt.at("revision") == descriptor.at("revision") &&
                    receipt.at("files").is_object() && !receipt.at("files").empty() &&
                    receipt.at("files").size() <= 256,
            "registered extraction identity differs");
    std::set<std::string> expected = {"base.json"};
    std::uint64_t total = 0;

    for (auto item = receipt.at("files").begin(); item != receipt.at("files").end(); ++item) {
        const auto name = item.key();
        const std::filesystem::path relative = name;
        require(!name.empty() && name.size() <= 1024 && !relative.is_absolute() &&
                        relative.lexically_normal() == relative &&
                        name.find_first_of("\\:\r\n") == std::string::npos,
                "confined inventory path required");

        for (const auto &part : relative) {
            require(part != "." && part != ".." && !part.empty(), "inventory traversal rejected");
        }

        const auto file = directory / relative;
        ordinary(file);
        require(std::filesystem::is_regular_file(file) &&
                        std::filesystem::hard_link_count(file) == 1,
                "ordinary extracted file missing");
        const auto size = std::filesystem::file_size(file);
        require(size <= 4ULL << 30 && item.value().at("bytes") == size &&
                        total <= (8ULL << 30) - size,
                "extracted file extent differs");
        const auto epoch = cache_file_identity(file);
        require(sha256_file(file) == item.value().at("sha256").get<std::string>() &&
                        cache_file_identity(file) == epoch,
                "extracted file hash changed");
        total += size;
        expected.insert(name);
    }

    std::set<std::string> actual;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        require(!entry.is_symlink() && (entry.is_directory() || entry.is_regular_file()),
                "ordinary extracted inventory required");

        if (entry.is_regular_file()) {
            actual.insert(entry.path().lexically_relative(directory).generic_string());
        }
    }

    require(actual == expected && receipt.at("bytes") == total, "extracted inventory differs");
    require(cache_file_identity(receipt_file) == receipt_epoch &&
                    sha256_file(receipt_file) == receipt_pin,
            "extraction receipt changed during verification");

    return receipt;
}

Json prepare_native_base_image(const Json &descriptor, const std::filesystem::path &archive,
                               const std::filesystem::path &destination, std::uint64_t reserve) {
    const auto package = descriptor.at("package").get<std::string>(),
               revision = descriptor.at("revision").get<std::string>(),
               sha = descriptor.at("sha256").get<std::string>();
    const auto identity = native_base_identity(descriptor);

    if (!archive.is_absolute() || !destination.is_absolute() ||
        std::filesystem::exists(destination) || std::filesystem::is_symlink(destination)) {
        throw VoyemuError("BASE_PATH", "absolute archive and fresh cache destination required");
    }

    const auto extraction = extract_sdk_archive(archive, sha, destination, reserve, 8ULL << 30);
    // The image ZIP contains no host tools. SDK extraction omits only interpreter/JAR paths.
    const auto marker = destination / ".base-owner.json";
    const auto token = random_token();
    write_private_json(marker, {{"token", token}});
    struct Cleanup {
        std::filesystem::path directory;
        std::string token;
        bool published = false;

        ~Cleanup() {
            if (published) {
                return;
            }

            try {
                if (read_private_json(directory / ".base-owner.json").at("token") == token) {
                    std::filesystem::remove_all(directory);
                }
            } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
            }
        }
    } cleanup{destination, token};
    std::ifstream metadata(destination / "source.properties");

    if (!metadata) {
        throw VoyemuError("BASE_META", "image source.properties required");
    }

    std::map<std::string, std::string> values;
    std::string line;
    auto trim = [](std::string value) {
        const auto at = value.find_first_not_of(" \t\r");

        return at == std::string::npos ? std::string{}
                                       : value.substr(at, value.find_last_not_of(" \t\r") - at + 1);
    };

    while (std::getline(metadata, line)) {
        const auto at = line.find('=');

        if (at != std::string::npos &&
            !values.emplace(trim(line.substr(0, at)), trim(line.substr(at + 1))).second) {
            throw VoyemuError("BASE_META", "duplicate image metadata");
        }
    }

    if (values["AndroidVersion.ApiLevel"] != std::to_string(identity.api) ||
        values["SystemImage.Abi"] != identity.abi || values["Pkg.Revision"] != revision ||
        values["SystemImage.TagId"] != "default") {
        throw VoyemuError("BASE_META", "image identity differs from descriptor");
    }

    for (const auto *required :
         {"system.img", "vendor.img", "userdata.img", "encryptionkey.img", "kernel-ranchu",
          "ramdisk.img", "advancedFeatures.ini", "build.prop"}) {
        if (!std::filesystem::is_regular_file(
                    std::filesystem::symlink_status(destination / required)) ||
            !std::filesystem::file_size(destination / required)) {
            throw VoyemuError("BASE_FILES", "required clean image payload missing");
        }
    }

    Json files = Json::object();
    std::uint64_t bytes = 0;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(destination)) {
        if (entry.is_symlink() || (!entry.is_directory() && !entry.is_regular_file())) {
            throw VoyemuError("BASE_FILES", "ordinary image payload required");
        }

        if (!entry.is_regular_file() || entry.path() == marker) {
            continue;
        }

        const auto epoch = cache_file_identity(entry.path());
        const auto hash = sha256_file(entry.path());

        if (cache_file_identity(entry.path()) != epoch) {
            throw VoyemuError("BASE_CHANGED", "clean image changed during hashing");
        }

        const auto path = entry.path().lexically_relative(destination).generic_string();
        files[path] = {{"sha256", hash}, {"bytes", entry.file_size()}};
        bytes += entry.file_size();
    }

    const Json receipt = {{"schema", 1},           {"package", package},  {"revision", revision},
                          {"archive_sha256", sha}, {"files", files},      {"bytes", bytes},
                          {"native", true},        {"prepared_VM", false}};
    write_private_json(destination / "base.json", receipt);
    std::filesystem::remove(marker);
    cleanup.published = true;

    return receipt;
}
} // namespace voyemu
