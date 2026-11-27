#include "native_bridge.hpp"
#include "check.hpp"
#include "download.hpp"
#include "ext4_image.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include "profile_identity.hpp"
#include "zip_archive.hpp"
#include <regex>
#include <sstream>
#include <vector>

namespace voyemu {
namespace {
constexpr Check need{"NATIVE_BRIDGE"};

bool guest_file(const std::string &path) {
    static const std::regex form(R"(/(system|vendor)(/[A-Za-z0-9_.+@-]+)+)");

    return path.size() <= 256 && std::regex_match(path, form) &&
           path.find("/../") == std::string::npos && path.find("/./") == std::string::npos;
}

void validate(const Json &descriptor) {
    need(descriptor.is_object() && descriptor.value("schema", 0) == 1 &&
                 descriptor.contains("archive") && descriptor.contains("files") &&
                 descriptor.contains("propertyFiles"),
         "native bridge descriptor fields required");
    const auto &archive = descriptor.at("archive");
    need(archive.is_object() &&
                 archive.value("url", std::string{})
                         .starts_with("https://dl.google.com/android/repository/") &&
                 sha256_text(archive.value("sha256", std::string{})) &&
                 sha256_text(archive.value("systemImageSha256", std::string{})) &&
                 std::regex_match(archive.value("member", std::string{}),
                                  std::regex("[A-Za-z0-9_]+/system[.]img")),
         "pinned native bridge donor archive required");
    const auto &files = descriptor.at("files");
    need(files.is_object() && !files.empty() && files.size() <= 256,
         "bounded native bridge files required");

    for (const auto &[path, pin] : files.items()) {
        need(path.starts_with("/system/") && guest_file(path) && pin.is_string() &&
                     sha256_text(pin.get<std::string>()),
             "native bridge file pin invalid: " + path);
    }

    const auto &properties = descriptor.at("propertyFiles");
    need(properties.is_object() && properties.size() <= 16,
         "bounded native bridge property files required");

    for (const auto &[path, file] : properties.items()) {
        need(guest_file(path) && !files.contains(path) && file.is_object() &&
                     sha256_text(file.value("inputSha256", std::string{})) &&
                     sha256_text(file.value("outputSha256", std::string{})) &&
                     file.value("values", Json()).is_object() && !file.at("values").empty(),
             "native bridge property file invalid: " + path);

        for (const auto &[key, value] : file.at("values").items()) {
            need(std::regex_match(key, std::regex(R"(ro\.[A-Za-z0-9_.-]+)")) && value.is_string() &&
                         value.get<std::string>().find_first_of("\r\n") == std::string::npos,
                 "native bridge property invalid: " + key);
        }
    }
}

std::filesystem::path cache_directory(const std::filesystem::path &root, const Json &descriptor) {
    return root / ".local/profiles/common/native-bridge" /
           descriptor.at("archive").at("sha256").get<std::string>();
}
} // namespace

Json native_bridge_descriptor(const std::filesystem::path &root, const Json &definition) {
    const auto name = definition.value("android", Json::object()).value("native_bridge", Json{});

    if (name.is_null()) {
        return nullptr;
    }

    need(name.is_string() && valid_profile_name(name.get<std::string>()),
         "native bridge name required");
    const auto file = root / "profiles/common/native-bridges" / (name.get<std::string>() + ".json");
    need(std::filesystem::is_regular_file(std::filesystem::symlink_status(file)),
         "native bridge descriptor missing: " + file.string());
    auto descriptor = read_private_json(file, 256 * 1024);
    validate(descriptor);

    return descriptor;
}

Json verify_native_bridge(const NativeBridge &bridge) {
    validate(bridge.descriptor);
    const auto receipt = read_private_json(bridge.directory.parent_path() / "native-bridge.json",
                                           256 * 1024);
    const auto &files = bridge.descriptor.at("files");
    need(receipt.value("schema", 0) == 1 &&
                 receipt.value("archive_sha256", Json()) ==
                         bridge.descriptor.at("archive").at("sha256") &&
                 receipt.value("files", Json()).is_object() &&
                 receipt.at("files").size() == files.size(),
         "native bridge receipt differs from its descriptor");

    for (const auto &[path, pin] : files.items()) {
        const auto &entry = receipt.at("files").value(path, Json());
        need(entry.is_object() && entry.value("sha256", Json()) == pin &&
                     entry.value("mode", 010000U) <= 07777U && entry.contains("uid") &&
                     entry.contains("gid"),
             "native bridge receipt entry differs: " + path);
        const auto file = bridge.directory / path.substr(1);
        need(std::filesystem::is_regular_file(std::filesystem::symlink_status(file)) &&
                     sha256_file(file) == pin.get<std::string>(),
             "native bridge file differs from its pin: " + path);
    }

    return receipt;
}

NativeBridge prepare_native_bridge(const std::filesystem::path &root, const Json &descriptor,
                                   const std::filesystem::path &downloads, bool offline,
                                   std::uint64_t reserve_bytes) {
    validate(descriptor);
    const auto target = cache_directory(root, descriptor);
    NativeBridge bridge{descriptor, target / "files"};

    if (std::filesystem::exists(std::filesystem::symlink_status(target))) {
        (void)verify_native_bridge(bridge);

        return bridge;
    }

    const auto &archive = descriptor.at("archive");
    const auto sha = archive.at("sha256").get<std::string>();
    const auto donor = download_pinned({archive.at("url").get<std::string>(),
                                        sha,
                                        2ULL << 30,
                                        DownloadEncoding::raw,
                                        "Android Native Bridge SDK",
                                        {},
                                        {},
                                        false},
                                       downloads, offline, reserve_bytes);
    const auto member = archive.at("member").get<std::string>();
    std::uint64_t image_bytes = 0;

    for (const auto &entry : zip_layout(donor.file)) {
        if (entry.name == member && !entry.directory && !entry.symlink) {
            need(!image_bytes, "duplicate native bridge donor image");
            image_bytes = entry.bytes;
        }
    }

    need(image_bytes > 0 && image_bytes <= (8ULL << 30), "native bridge donor image missing");
    ensure_private_directory(target.parent_path());
    const auto stage = target.parent_path() / (".stage-" + random_token());
    need(std::filesystem::create_directory(stage), "fresh native bridge stage required");
    struct Cleanup {
        std::filesystem::path path;

        ~Cleanup() {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } cleanup{stage};
    ensure_private_directory(stage);
    const auto image = stage / "system.img";
    extract_pinned_zip_members(donor.file, sha, {{member, 0, image_bytes}}, image, image_bytes,
                               reserve_bytes);
    const auto image_sha = archive.at("systemImageSha256").get<std::string>();
    need(sha256_file(image) == image_sha, "native bridge donor image differs from its pin");
    std::vector<std::string> paths;

    for (const auto &[path, pin] : descriptor.at("files").items()) {
        (void)pin;
        paths.push_back(path);
    }

    std::map<std::string, Ext4Inode> inodes;
    const auto extraction = extract_pinned_ext4_files(image, image_sha, paths, stage / "files",
                                                      reserve_bytes, "system", &inodes);
    std::filesystem::remove(image);
    Json files = Json::object();

    for (const auto &[path, pin] : descriptor.at("files").items()) {
        const auto &extracted = extraction.at("files").at(path.substr(1));
        const auto &inode = inodes.at(path);
        need(extracted.at("sha256") == pin,
             "native bridge donor file differs from its pin: " + path);
        files[path] = {{"sha256", pin},
                       {"bytes", extracted.at("bytes")},
                       {"mode", inode.mode},
                       {"uid", inode.uid},
                       {"gid", inode.gid}};
    }

    write_private_json(stage / "native-bridge.json",
                       {{"schema", 1}, {"archive_sha256", sha}, {"files", files}}, 256 * 1024);
    need(os::rename_exclusive(stage, target), "exclusive native bridge publication");
    (void)verify_native_bridge(bridge);

    return bridge;
}

std::string merge_android_properties(std::string_view text, const Json &values) {
    need(values.is_object() && text.size() <= (1U << 20), "bounded property merge required");
    std::vector<std::string> lines;
    std::map<std::string, unsigned> seen;
    std::istringstream input{std::string(text)};

    for (std::string line; std::getline(input, line);) {
        const auto key = line.substr(0, line.find('='));

        if (values.contains(key)) {
            need(++seen[key] == 1, "repeated property key: " + key);
            line = key + "=" + values.at(key).get<std::string>();
        }

        lines.push_back(std::move(line));
    }

    for (const auto &[key, value] : values.items()) {
        if (!seen.contains(key)) {
            while (!lines.empty() && lines.back().empty()) {
                lines.pop_back();
            }

            lines.push_back(key + "=" + value.get<std::string>());
        }
    }

    std::string result;

    for (const auto &line : lines) {
        result += line + "\n";
    }

    return result;
}
} // namespace voyemu
