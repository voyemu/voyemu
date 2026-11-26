#include "fetch.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "cli_messages.hpp"
#include "deps.hpp"
#include "error.hpp"
#include "ext4_image.hpp"
#include "fetch_internal.hpp"
#include "fetch_segmented.hpp"
#include "fetch_snapshot.hpp"
#include "os/fs.hpp"
#include "owner_update_archive.hpp"
#include "portable_runtime.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_identity.hpp"
#include "profile_originals.hpp"
#include "qnx_originals_directory.hpp"
#include "quickboot.hpp"
#include "vehicle_capture.hpp"
#include "zip_archive.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#ifdef __APPLE__
#include <stdio.h>
#endif
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
namespace voyemu {
namespace {
std::string relative_path(const std::string &value) {
    if (value.empty() || value.size() > 1024 || value.front() == '/' ||
        value.find_first_of("\\:\r\n\t") != std::string::npos ||
        value.find("//") != std::string::npos) {
        throw VoyemuError("FETCH_PATH", "ordinary relative input path required");
    }

    const std::filesystem::path path(std::u8string(value.begin(), value.end()));

    if (path.lexically_normal() != path) {
        throw VoyemuError("FETCH_PATH", "normalized relative path required");
    }

    for (const auto &part : path) {
        if (part == "." || part == ".." || part.empty()) {
            throw VoyemuError("FETCH_PATH", "traversal rejected");
        }
    }

    return value;
}

std::string pinned_sha(const Json &value) {
    const auto hash = value.get<std::string>();

    if (!sha256_text(hash)) {
        throw VoyemuError("FETCH_PIN", "exact lowercase SHA256 required");
    }

    return hash;
}

void ordinary_ancestors(const std::filesystem::path &path) {
    for (const auto &at : os::ancestors(path)) {
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(at))) {
            throw VoyemuError("FETCH_PATH", "linked input ancestor rejected");
        }
    }
}

// advance receives the byte count of each hashed block, for a progress meter.
std::uint64_t verify_file(const std::filesystem::path &file, const std::string &sha,
                          std::uint64_t maximum,
                          const std::function<void(std::uint64_t)> &advance = {}) {
    ordinary_ancestors(file);

    if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(file)) ||
        std::filesystem::hard_link_count(file) != 1 || std::filesystem::file_size(file) > maximum) {
        throw VoyemuError("FETCH_FILE", "ordinary bounded input required");
    }

    const auto epoch = cache_file_identity(file);

    if (sha256_file(file, advance) != sha) {
        throw VoyemuError("FETCH_SHA", "input differs from declared profile SHA256");
    }

    if (cache_file_identity(file) != epoch) {
        throw VoyemuError("FETCH_CHANGED", "input changed during verification");
    }

    return std::filesystem::file_size(file);
}

bool remote_path(const std::string &value) {
    static const std::regex pattern(
            R"(^/(system|system_ext|vendor|product|data|resc)/[A-Za-z0-9_./+=@~:-]+$)");

    if (!std::regex_match(value, pattern)) {
        return false;
    }

    for (const auto &part : std::filesystem::path(value)) {
        if (part == ".." || part == ".") {
            return false;
        }
    }

    return true;
}

std::string trim(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
    }

    return text;
}

Json load_profile(const std::filesystem::path &root, std::string_view name) {
    const auto source = root / "profiles" / std::string(name) / "profile.json";

    if (std::filesystem::exists(source) || std::filesystem::is_symlink(source)) {
        return authoring_profile(root, name);
    }

    return embedded_profile(name).at("definition");
}

// The console version of an Android image descriptor: its release and API level, "11 (API 30)".
std::string android_image_version(const Json &image) {
    const auto package = image.value("package", std::string{});
    const auto at = package.find(";android-");

    if (at == std::string::npos) {
        return {};
    }

    const auto api = package.substr(at + 9, package.find(';', at + 9) - at - 9);
    static const std::map<std::string, std::string> releases{{"28", "9"}, {"30", "11"}};
    const auto release = releases.find(api);

    return release == releases.end() ? "API " + api : release->second + " (API " + api + ")";
}

// The console meter of an Android image that an import unpacks, in its own block.
std::unique_ptr<progress::Meter> unpacking(const std::string &image, std::uint64_t bytes) {
    progress::block();
    auto meter = std::make_unique<progress::Meter>("fetch_image",
                                                   progress::Arguments{{"image", image}});
    meter->length(bytes);

    return meter;
}

// The console line of the saved originals and the time since started.
void report_saved(std::size_t android, std::size_t qnx,
                  std::chrono::steady_clock::time_point started) {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now() - started)
                                 .count();
    const auto time = progress::duration_text(static_cast<std::uint64_t>(seconds),
                                              progress::language());

    progress::block();

    if (qnx) {
        progress::report("fetch_saved", {{"android", std::to_string(android)},
                                         {"qnx", std::to_string(qnx)},
                                         {"time", time}});
    } else {
        progress::report("fetch_saved_android",
                         {{"android", std::to_string(android)}, {"time", time}});
    }
}

std::string acquisition_identity(const Json &definition, const Json &qnx) {
    Json declared = Json::object();

    for (auto it = definition.at("original").begin(); it != definition.at("original").end(); ++it) {
        const auto &item = it.value();
        declared[it.key()] = {{"file", item.at("file")},
                              {"type", item.value("type", std::string("file"))},
                              {"bytes", item.at("bytes")},
                              {"sha256", item.at("sha256")},
                              {"source", item.value("source", Json::object())},
                              {"acquisition", item.at("acquisition")}};
    }

    const auto &acquisition = definition.at("acquisition");
    Json images = {{"system", acquisition.at("system")}};

    if (acquisition.contains("vendor")) {
        images["vendor"] = acquisition.at("vendor");
    }

    return sha256_bytes(Json{
            {"ownerUpdate", definition.at("ownerUpdate")},
            {"format", acquisition.at("format")},
            {"diff", acquisition.at("diff")},
            {"system", acquisition.contains("vendor") ? images : acquisition.at("system")},
            {"original", declared},
            {"qnx_originals", qnx.at("originals")},
            {"qnx_update",
             qnx.at("update")}}.dump());
}

bool passion_media_role(const Json &definition, const std::string &name) {
    static const Json roles = {
            {"LY_Camera",
             {{"package", "com.voyah.camera"},
              {"path", "/system/app/LY_Camera/LY_Camera.apk"},
              {"bytes", 111142678u},
              {"sha256", "e0e57f7cd9099136541c3ed35e1042fba1762a13640bea7f6a2ac3415f426bf0"}}},
            {"LY_Video",
             {{"package", "com.voyah.video"},
              {"path", "/system/app/LY_Video/LY_Video.apk"},
              {"bytes", 83820059u},
              {"sha256", "11bd7f83630949a997836753a65e4782f3235cbbe83db037c7b47e25ddd21c5c"}}},
            {"LY_AVM",
             {{"package", "com.voyah.avm"},
              {"path", "/system/priv-app/LY_AVM/LY_AVM.apk"},
              {"bytes", 59707822u},
              {"sha256", "ca78d415246c5be5c892d93a1b90c9dc19a638024af3ec61877c309cee7b8ecb"}}}};

    if (!roles.contains(name)) {
        return false;
    }

    const auto &role = roles.at(name);
    const auto &item = definition.at("original").at(name);

    if (profile_platform(definition) != ProfilePlatform::passion ||
        definition.at("android").at("package") != "system-images;android-30;default;arm64-v8a" ||
        item.at("file") != name + ".apk" || item.value("type", std::string("file")) != "file" ||
        item.value("source", Json::object()) != Json{{"package", role.at("package")}} ||
        item.at("acquisition") != Json{{"image", "system"}, {"path", role.at("path")}} ||
        item.at("bytes") != role.at("bytes") || item.at("sha256") != role.at("sha256")) {
        throw VoyemuError("FETCH_UPDATE", "exact pinned Passion media role required");
    }

    return true;
}

std::vector<std::string> passion_screen_control_roles(const Json &definition) {
    static const std::map<std::string, std::string> pins = {
            {"screen-control-screen0_off_change",
             "7e82e683f773e0e300fe7e1f2c097381f0f94ff784d9705d350523f870081881"},
            {"screen-control-screen0_off_keep",
             "826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f"},
            {"screen-control-screen0_on_change",
             "dbfe5e0802173415484a1640ed3024a181843ad40d895320952db3a4d8a7bfff"},
            {"screen-control-screen0_on_keep",
             "826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f"},
            {"screen-control-screen1_off_change",
             "3aee3f501728d48de7a4c2a189fec04b1c9ddfb7898cd0dcc636129faa908ac0"},
            {"screen-control-screen1_off_keep",
             "826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f"},
            {"screen-control-screen1_on_change",
             "e2a2f3a83123cf347c7f0ec8cba58fa077e402b9a3317b36bec2225cbfb65f82"},
            {"screen-control-screen1_on_keep",
             "826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f"}};
    std::vector<std::string> roles;

    for (auto it = definition.at("original").begin(); it != definition.at("original").end(); ++it) {
        if (it.key().starts_with("screen-control-")) {
            roles.push_back(it.key());
        }
    }

    if (roles.empty()) {
        return roles;
    }

    if (profile_platform(definition) != ProfilePlatform::passion ||
        definition.at("android").at("package") != "system-images;android-30;default;arm64-v8a" ||
        roles.size() != pins.size()) {
        throw VoyemuError("FETCH_UPDATE",
                          "complete pinned Passion screen-control extension required");
    }

    for (const auto &name : roles) {
        const auto &item = definition.at("original").at(name);
        const auto found = pins.find(name);
        const auto file = name.substr(15) + ".csv", path = "/system/etc/screen-control/" + file;

        if (found == pins.end() || item.at("file") != file ||
            item.value("type", std::string("file")) != "file" || item.at("bytes") != 6111u ||
            item.at("sha256") != found->second ||
            item.value("source", Json::object()) != Json{{"path", path}} ||
            item.at("acquisition") != Json{{"image", "system"}, {"path", path}}) {
            throw VoyemuError("FETCH_UPDATE", "exact pinned Passion screen-control role required");
        }
    }

    return roles;
}

// An NXP owner update import needs the NXP board, the pinned device board and API 28.
void nxp_update_profile(const Json &definition) {
    if (definition.value("acquisition", Json::object()).value("format", std::string{}) !=
                "nxp-update-zip" ||
        profile_board(definition) != ProfileBoard::nxp ||
        definition.at("device").at("board") != "f0501h" ||
        native_base_api(definition.at("android")) != 28) {
        throw VoyemuError("FETCH_NXP", "exact NXP API28 owner update profile required");
    }
}

Json fetch_nxp_update(const std::filesystem::path &root, std::string_view profile,
                      const std::filesystem::path &archive, std::uint64_t reserve) {
    const auto started = std::chrono::steady_clock::now();
    const auto profile_file = root / "profiles" / std::string(profile) / "profile.json";
    const auto definition = read_private_json(profile_file, 512 * 1024);
    const auto profile_epoch = cache_file_identity(profile_file);
    const auto profile_pin = sha256_file(profile_file);

    nxp_update_profile(definition);
    const Json source = {
            {"bytes", 2415112497ULL},
            {"sha256", "e91855241d9587a17f9f2349784fe86bcd23fdf88800eec368a61d71b12a5523"}};

    if (definition.at("device").at("sourceArchives").at("update_zip") != source) {
        throw VoyemuError("FETCH_NXP", "exact retained owner archive declaration required");
    }

    ordinary_ancestors(archive);
    verify_owner_archive(root, profile, archive, source.at("bytes").get<std::uint64_t>(),
                         source.at("sha256").get<std::string>(), true, "FETCH_FILE", "FETCH_SHA");

    const auto archive_epoch = cache_file_identity(archive);
    const auto acquisition_plan = nxp_acquisition_plan(definition);
    const auto inputs = original_input_plan(definition);

    if (inputs.empty() || inputs.size() > 512) {
        throw VoyemuError("FETCH_NXP", "bounded source originals required");
    }

    const auto destination = root / ".local/profiles" / std::string(profile),
               originals = destination / "originals";
    ordinary_ancestors(destination);
    std::vector<OriginalInput> missing;
    std::vector<std::string> paths, resource_paths, vendor_paths;

    for (const auto &input : inputs) {
        const auto &item = definition.at("original").at(input.name);
        const auto &acquisition = item.at("acquisition");
        const auto image = acquisition.at("image").get<std::string>();
        const auto source_path = acquisition.at("path").get<std::string>();
        (image == "resource" ? resource_paths
         : image == "vendor" ? vendor_paths
                             : paths)
                .push_back(source_path);
        const auto target = originals / input.file;

        if (std::filesystem::exists(target) || std::filesystem::is_symlink(target)) {
            if (verify_file(target, input.sha256, 1ULL << 30) !=
                item.at("bytes").get<std::uint64_t>()) {
                throw VoyemuError("FETCH_NXP", "retained original extent differs");
            }
        } else {
            missing.push_back(input);
        }
    }

    const auto stable = [&] {
        if (cache_file_identity(profile_file) != profile_epoch ||
            sha256_file(profile_file) != profile_pin ||
            cache_file_identity(archive) != archive_epoch ||
            pinned_file_sha256(archive) != source.at("sha256").get<std::string>()) {
            throw VoyemuError("FETCH_NXP", "source/profile changed during acquisition");
        }
    };

    if (missing.empty()) {
        stable();

        return {{"schema", 1},
                {"profile", profile},
                {"source", "owner-update"},
                {"archive_sha256", source.at("sha256")},
                {"originals", verify_original_inputs(root, profile, inputs)},
                {"native", true},
                {"cached", true},
                {"guest_started", false},
                {"vehicle_modified", false}};
    }

    const auto stage = root / ".local/build/tmp" / ("nxp-owner-" + random_token());
    ensure_private_directory(stage);
    const auto token = random_token();
    write_private_json(stage / "owner.json", {{"token", token}});
    const auto stage_epoch = cache_file_identity(stage / "owner.json");
    struct Cleanup {
        std::filesystem::path path;
        std::string token;
        Json epoch;

        ~Cleanup() {
            try {
                if (cache_file_identity(path / "owner.json") == epoch &&
                    read_private_json(path / "owner.json").at("token") == token) {
                    std::filesystem::remove_all(path);
                }
            } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
            }
        }
    } cleanup{stage, token, stage_epoch};
    const Json image = {
            {"bytes", 3758096384ULL},
            {"sha256", "4b795f89e7c343afc32fd4e6bc06e5be8a544804f4820af8142457ea8c982c7e"},
            {"segments", Json::array({{{"member", "factory_image/system_raw.img0"},
                                       {"offset", 0ULL},
                                       {"bytes", 2147483648ULL}},
                                      {{"member", "factory_image/system_raw.img1"},
                                       {"offset", 2147483648ULL},
                                       {"bytes", 1610612736ULL}}})}};
    auto meter = unpacking("system", image.at("bytes").get<std::uint64_t>());
    const auto advance = [&meter](std::uint64_t block) {
        meter->advance(block);
    };
    const auto imported = import_pinned_zip_image(archive, source, image, stage / "image", reserve,
                                                  {}, PinnedZipImageKind::SplitFragments, advance);
    const auto extracted = stage / "extracted";
    ensure_private_directory(extracted);
    Json extraction = {
            {"schema", 1}, {"files", Json::object()}, {"bytes", 0ULL}, {"batches", Json::array()}};
    unsigned batch_index = 0;

    for (const auto &batch : acquisition_plan.at("system_batches")) {
        const auto batch_output = stage / ("system-extracted-" + std::to_string(batch_index++));
        const auto batch_receipt = extract_pinned_ext4_files(
                stage / "image/system.img", image.at("sha256").get<std::string>(),
                batch.get<std::vector<std::string>>(), batch_output, reserve);

        for (auto file = batch_receipt.at("files").begin(); file != batch_receipt.at("files").end();
             ++file) {
            const auto target = extracted / file.key();
            ensure_private_directory(target.parent_path());
            std::filesystem::rename(batch_output / file.key(), target);
            extraction["files"][file.key()] = file.value();
        }

        extraction["bytes"] = extraction.at("bytes").get<std::uint64_t>() +
                              batch_receipt.at("bytes").get<std::uint64_t>();
        extraction["batches"].push_back(batch_receipt);
    }

    progress::report("fetch_extracted", {{"count", std::to_string(extraction.at("files").size())}});

    const auto resource_extracted = stage / "resource-extracted";
    Json resource_import = Json::object(), resource_extraction = Json::object();

    if (!resource_paths.empty()) {
        const Json resource_image = {
                {"bytes", 1073741824ULL},
                {"sha256", "b96edc131f4c81d66339e87d54023cff4a2af8d25affff5cb07f820654b2c986"},
                {"segments", Json::array({{{"member", "factory_image/resource.img"},
                                           {"offset", 0ULL},
                                           {"bytes", 1073741824ULL}}})}};
        meter = unpacking("resource", resource_image.at("bytes").get<std::uint64_t>());
        resource_import = import_pinned_zip_image(archive, source, resource_image,
                                                  stage / "resource-image", reserve, {},
                                                  PinnedZipImageKind::SingleImage, advance);
        resource_extraction = extract_pinned_ext4_files(
                stage / "resource-image/system.img", resource_image.at("sha256").get<std::string>(),
                resource_paths, resource_extracted, reserve);
        progress::report("fetch_extracted", {{"count", std::to_string(resource_paths.size())}});
    }

    const auto vendor_extracted = stage / "vendor-extracted";
    Json vendor_import = Json::object(), vendor_extraction = Json::object();

    if (!vendor_paths.empty()) {
        const Json vendor_image = {
                {"bytes", 268435456ULL},
                {"sha256", "598b1cfcb1299b4af24e86b39d9e08d94b64eb847bd24e97e9a73462beac9975"},
                {"segments", Json::array({{{"member", "factory_image/vendor_raw.img"},
                                           {"offset", 0ULL},
                                           {"bytes", 268435456ULL}}})}};
        meter = unpacking("vendor", vendor_image.at("bytes").get<std::uint64_t>());
        vendor_import = import_pinned_zip_image(archive, source, vendor_image,
                                                stage / "vendor-image", reserve, {},
                                                PinnedZipImageKind::SingleImage, advance);
        vendor_extraction = extract_pinned_ext4_files(
                stage / "vendor-image/system.img", vendor_image.at("sha256").get<std::string>(),
                vendor_paths, vendor_extracted, reserve, "vendor");
        progress::report("fetch_extracted", {{"count", std::to_string(vendor_paths.size())}});
    }

    const auto extracted_input = [&](const OriginalInput &input) {
        const auto &acquisition = definition.at("original").at(input.name).at("acquisition");
        const auto image = acquisition.at("image");

        return (image == "resource" ? resource_extracted
                : image == "vendor" ? vendor_extracted
                                    : extracted) /
               acquisition.at("path").get<std::string>().substr(1);
    };

    for (const auto &input : inputs) {
        const auto file = extracted_input(input);

        if (verify_file(file, input.sha256, 1ULL << 30) !=
            definition.at("original").at(input.name).at("bytes").get<std::uint64_t>()) {
            throw VoyemuError("FETCH_NXP", "extracted OEM original differs");
        }
    }

    stable();
    ensure_private_directory(originals);

    for (const auto &input : missing) {
        const auto target = originals / input.file;
        ensure_private_directory(target.parent_path());

        if (std::filesystem::exists(target) || std::filesystem::is_symlink(target)) {
            throw VoyemuError("FETCH_NXP", "original appeared during acquisition");
        }

        const auto extracted_file = extracted_input(input);

        if (!os::rename_exclusive(extracted_file, target)) {
            throw VoyemuError("FETCH_NXP", "exclusive original publication failed");
        }
    }

    Json receipt = {{"schema", 1},
                    {"profile", profile},
                    {"source", "owner-update"},
                    {"archive_sha256", source.at("sha256")},
                    {"originals", verify_original_inputs(root, profile, inputs)},
                    {"native", true},
                    {"cached", false},
                    {"guest_started", false},
                    {"vehicle_modified", false},
                    {"image_import", imported},
                    {"ext4", extraction},
                    {"resource_image_import", resource_import},
                    {"resource_ext4", resource_extraction},
                    {"vendor_image_import", vendor_import},
                    {"vendor_ext4", vendor_extraction}};
    write_private_json(destination / "nxp-owner-inputs.json", receipt);
    meter.reset();
    report_saved(inputs.size(), 0, started);

    return receipt;
}

bool owner_archive_matches(const Json &receipt, const Json &owner) {
    const auto container = receipt.value("source_container", std::string("zip"));
    const auto &pin = container == "inner-tgz" ? owner.at("inner") : owner;

    return (container == "zip" || container == "inner-tgz") &&
           receipt.at("owner_archive").at("sha256") == pin.at("sha256") &&
           receipt.at("owner_archive").at("bytes") == pin.at("bytes");
}

Json fetch_update(const std::filesystem::path &root, std::string_view profile,
                  const std::filesystem::path &archive, std::uint64_t reserve) {
    const auto started = std::chrono::steady_clock::now();

    if (!archive.is_absolute() || archive.lexically_normal() != archive) {
        throw VoyemuError("FETCH_UPDATE", "absolute normalized local archive required");
    }

    const auto profile_file = root / "profiles" / std::string(profile) / "profile.json",
               qnx_file = profile_file.parent_path() / "profile-qnx.json";
    const auto profile_sha = sha256_file(profile_file), qnx_sha = sha256_file(qnx_file);
    verify_file(profile_file, profile_sha, 512 * 1024);
    verify_file(qnx_file, qnx_sha, 128 * 1024);
    const auto profile_identity = cache_file_identity(profile_file),
               qnx_identity = cache_file_identity(qnx_file);
    const auto definition = read_private_json(profile_file, 512 * 1024),
               qnx = read_private_json(qnx_file, 128 * 1024);
    const auto &acquisition = definition.at("acquisition");
    const auto &owner = definition.at("ownerUpdate");

    if (acquisition.at("format") != "pinned-zip-tgz-raw-scatter" ||
        acquisition.at("diff") != false || qnx.at("update").at("container") != "zip-stored-tgz" ||
        qnx.at("update").at("sha256") != owner.at("sha256") ||
        qnx.at("update").at("nested_member") != owner.at("inner").at("file") ||
        qnx.at("update").at("nested_sha256") != owner.at("inner").at("sha256") ||
        !qnx_acquisition_originals_match(acquisition, qnx.at("originals"))) {
        throw VoyemuError("FETCH_UPDATE", "exact shared Android/QNX owner recipe required");
    }

    const bool direct = archive.filename() == owner.at("inner").at("file").get<std::string>();
    const auto &source_pin = direct ? owner.at("inner") : owner;
    const auto archive_sha = pinned_sha(source_pin.at("sha256"));

    ordinary_ancestors(archive);
    verify_owner_archive(root, profile, archive, source_pin.at("bytes").get<std::uint64_t>(),
                         archive_sha, true, "FETCH_FILE", "FETCH_SHA");

    const auto archive_identity = cache_file_identity(archive);
    const auto inputs = original_input_plan(definition);

    if (inputs.empty() || inputs.size() > 256) {
        throw VoyemuError("FETCH_UPDATE", "bounded originals required");
    }

    const auto acquisition_sha = acquisition_identity(definition, qnx);
    const auto screen_roles = passion_screen_control_roles(definition);
    std::vector<std::string> paths, vendor_paths, vendor_apps, media_paths;
    std::set<std::string> selected;

    for (const auto &input : inputs) {
        const auto &item = definition.at("original").at(input.name);
        const auto &source = item.at("acquisition");
        const auto path = source.at("path").get<std::string>();
        const bool vendor = source.at("image") == "vendor";

        const bool vehicle = input.name == "LY_Car";
        const bool application = vendor && (vehicle || path.starts_with("/vendor/app/"));

        if (vendor) {
            const auto origin = item.value("source", Json::object());

            if (profile_platform(definition) != ProfilePlatform::passion ||
                definition.at("android").at("package") !=
                        "system-images;android-30;default;arm64-v8a" ||
                !acquisition.contains("vendor") ||
                (application &&
                 (input.package.empty() || origin != Json{{"package", input.package}} ||
                  input.file != input.name + ".apk" ||
                  path != "/vendor/app/" + input.name + "/" + input.file ||
                  (vehicle && input.package != "com.voyah.car"))) ||
                (!application && origin != Json{{"path", path}})) {
                throw VoyemuError("FETCH_UPDATE", "exact Passion vendor role required");
            }
        }

        if ((!vendor && source.at("image") != "system") || !remote_path(path) ||
            !path.starts_with(vendor ? "/vendor/" : "/system/") || !selected.insert(path).second ||
            !item.at("bytes").is_number_unsigned()) {
            throw VoyemuError("FETCH_UPDATE", "exact system/vendor original path/extent required");
        }

        (application && !vehicle                      ? vendor_apps
         : vendor                                     ? vendor_paths
         : passion_media_role(definition, input.name) ? media_paths
                                                      : paths)
                .push_back(path);
    }

    const auto destination = root / ".local/profiles" / std::string(profile);
    auto unchanged = [&] {
        if (cache_file_identity(profile_file) != profile_identity ||
            cache_file_identity(qnx_file) != qnx_identity ||
            cache_file_identity(archive) != archive_identity ||
            pinned_file_sha256(archive) != archive_sha) {
            throw VoyemuError("FETCH_UPDATE", "acquisition source changed");
        }
    };
    auto verify = [&](const std::filesystem::path &directory, const Json &expected_definition,
                      const std::string &expected_sha) {
        ordinary_ancestors(directory);
        const auto receipt = read_private_json(directory / "owner-inputs.json", 256 * 1024);

        if (receipt.at("schema") != 1 || receipt.at("profile") != profile ||
            receipt.at("source") != "owner-update" ||
            receipt.at("acquisition_sha256") != expected_sha ||
            !owner_archive_matches(receipt, owner) || receipt.at("native") != true ||
            receipt.at("frame_verified") != false || receipt.at("preparation_ready") != false) {
            throw VoyemuError("FETCH_UPDATE", "retained acquisition receipt differs");
        }

        Json originals = Json::array(), raw = Json::array();
        std::set<std::string> expected = {"owner-inputs.json", "owner-update.json",
                                          "ext4-extraction.json"};

        for (const auto &input : original_input_plan(expected_definition)) {
            const auto size = verify_file(directory / "originals" / input.file, input.sha256,
                                          1ULL << 30);

            if (size != expected_definition.at("original")
                                .at(input.name)
                                .at("bytes")
                                .get<std::uint64_t>()) {
                throw VoyemuError("FETCH_UPDATE", "original extent differs");
            }

            expected.insert("originals/" + input.file);
            originals.push_back({{"file", input.file}, {"sha256", input.sha256}, {"bytes", size}});
        }

        for (auto it = qnx.at("originals").begin(); it != qnx.at("originals").end(); ++it) {
            const auto name = relative_path(it.value().at("file").get<std::string>()),
                       sha = pinned_sha(it.value().at("sha256"));
            const auto size = verify_file(directory / "qnx" / name, sha, 4ULL << 30);

            if (size != it.value().at("bytes").get<std::uint64_t>()) {
                throw VoyemuError("FETCH_UPDATE", "QNX raw extent differs");
            }

            expected.insert("qnx/" + name);
            raw.push_back({{"file", name}, {"sha256", sha}, {"bytes", size}});
        }

        if (receipt.at("originals").at("files") != originals ||
            receipt.at("qnx").at("files") != raw ||
            verify_file(directory / "owner-update.json", receipt.at("owner_update_receipt_sha256"),
                        256 * 1024) == 0 ||
            verify_file(directory / "ext4-extraction.json", receipt.at("ext4_receipt_sha256"),
                        256 * 1024) == 0) {
            throw VoyemuError("FETCH_UPDATE", "retained inventory/receipt differs");
        }

        if (std::filesystem::exists(directory / "native-inputs.json") ||
            std::filesystem::is_symlink(directory / "native-inputs.json")) {
            const auto fetched = read_private_json(directory / "native-inputs.json", 256 * 1024);

            if (fetched.at("profile") != profile || fetched.at("native") != true ||
                fetched.at("frame_verified") != false ||
                fetched.at("owner_inputs_sha256") != sha256_file(directory / "owner-inputs.json")) {
                throw VoyemuError("FETCH_UPDATE", "ordinary fetch receipt differs");
            }

            expected.insert("native-inputs.json");
        }

        std::set<std::string> actual, actual_dirs, expected_dirs;

        for (const auto &file : expected) {
            for (auto parent = std::filesystem::path(file).parent_path(); !parent.empty();
                 parent = parent.parent_path()) {
                expected_dirs.insert(parent.generic_string());
            }
        }

        for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
            ordinary_ancestors(entry.path());

            if (!entry.is_directory() && !entry.is_regular_file()) {
                throw VoyemuError("FETCH_UPDATE", "ordinary input tree required");
            }

            const auto relative = entry.path().lexically_relative(directory).generic_string();

            if (entry.is_regular_file()) {
                actual.insert(relative);
            } else {
                actual_dirs.insert(relative);
            }
        }

        if (actual != expected || actual_dirs != expected_dirs) {
            throw VoyemuError("FETCH_UPDATE", "retained input inventory differs");
        }

        return receipt;
    };

    if (std::filesystem::exists(destination) || std::filesystem::is_symlink(destination)) {
        const auto retained = read_private_json(destination / "owner-inputs.json", 256 * 1024);

        if (retained.at("acquisition_sha256") == acquisition_sha) {
            auto result = verify(destination, definition, acquisition_sha);
            unchanged();
            result["cached"] = true;

            return result;
        }

        // Only reviewed finite role extensions may migrate a retained cache.
        std::vector<std::string> additions;
        std::string extension_kind;
        const auto &declared = definition.at("original");

        if (declared.contains("BootAnimation")) {
            for (const auto *name : {"BootAnimation", "BootAnimation1"}) {
                if (!declared.contains(name)) {
                    continue;
                }

                const auto file = std::string(name) == "BootAnimation" ? "bootanimation.zip"
                                                                       : "bootanimation1.zip";
                const auto &item = declared.at(name);

                if (item.at("file") != std::string("media/") + file ||
                    item.value("type", std::string("file")) != "file" ||
                    item.at("acquisition") !=
                            Json{{"image", "system"},
                                 {"path", std::string("/system/media/") + file}}) {
                    throw VoyemuError("FETCH_UPDATE", "exact boot animation extension required");
                }

                additions.emplace_back(name);
            }

            extension_kind = "StartupAnimation";
        } else if (!screen_roles.empty()) {
            additions = screen_roles;
            extension_kind = "PassionScreenControl";
        } else if (declared.contains("LY_Camera") || declared.contains("LY_Video") ||
                   declared.contains("LY_AVM")) {
            for (const auto *name : {"LY_Camera", "LY_Video", "LY_AVM"}) {
                if (!declared.contains(name) || !passion_media_role(definition, name)) {
                    throw VoyemuError("FETCH_UPDATE",
                                      "complete pinned Passion media extension required");
                }

                additions.emplace_back(name);
            }

            extension_kind = "PassionMedia";
        } else if (declared.contains("LY_Car")) {
            additions.emplace_back("LY_Car");
            extension_kind = "PassionVehicle";
        } else if (declared.contains("LY_Multimedia") || declared.contains("LY_BtPhone")) {
            if (!declared.contains("frameworkBase") || !declared.contains("LY_Multimedia") ||
                !declared.contains("LY_BtPhone")) {
                throw VoyemuError("FETCH_UPDATE", "complete Music/Phone extension required");
            }

            auto role = [&](const char *name, const char *file, const char *package,
                            const char *path) {
                const auto &item = declared.at(name);

                if (item.at("file") != file || item.value("type", std::string("file")) != "file" ||
                    item.value("source", Json::object()) != Json{{"package", package}} ||
                    item.at("acquisition") != Json{{"image", "system"}, {"path", path}}) {
                    throw VoyemuError("FETCH_UPDATE", "exact Music/Phone extension required");
                }

                additions.emplace_back(name);
            };
            role("LY_Multimedia", "LY_Multimedia.apk", "com.voyah.multimedia",
                 "/system/app/LY_Multimedia/LY_Multimedia.apk");
            role("LY_BtPhone", "LY_BtPhone.apk", "com.voyah.btphone",
                 "/system/priv-app/LY_BtPhone/LY_BtPhone.apk");
            extension_kind = "MusicPhone";
        } else {
            if (!declared.contains("frameworkBase")) {
                throw VoyemuError("FETCH_UPDATE", "retained acquisition receipt differs");
            }

            const auto &item = declared.at("frameworkBase");

            if (item.at("file") != "framework/framework.jar" ||
                item.value("type", std::string("file")) != "file" ||
                item.value("source", Json::object()).value("path", std::string{}) !=
                        "/system/framework/framework.jar" ||
                item.at("acquisition").at("image") != "system" ||
                item.at("acquisition").at("path") != "/system/framework/framework.jar") {
                throw VoyemuError("FETCH_UPDATE", "exact framework extension required");
            }

            additions.emplace_back("frameworkBase");
            extension_kind = "frameworkBase";
        }

        auto previous = definition;

        for (const auto &name : additions) {
            previous["original"].erase(name);
        }

        if (extension_kind == "PassionVehicle") {
            previous["acquisition"].erase("vendor");
        }

        const auto previous_sha = acquisition_identity(previous, qnx);
        const auto before = verify(destination, previous, previous_sha);
        std::vector<std::string> extra_paths;

        for (const auto &name : additions) {
            const auto &item = declared.at(name);
            const auto target = destination / "originals" / item.at("file").get<std::string>();

            if (std::filesystem::exists(target) || std::filesystem::is_symlink(target)) {
                throw VoyemuError("FETCH_UPDATE", "extension destination already present");
            }

            extra_paths.push_back(item.at("acquisition").at("path").get<std::string>());
        }

        std::map<std::filesystem::path, Json> old_files;

        for (const auto &entry : std::filesystem::recursive_directory_iterator(destination)) {
            if (entry.is_regular_file()) {
                old_files.emplace(entry.path(), cache_file_identity(entry.path()));
            }
        }

        const auto stage = root / ".local/build/tmp" / ("owner-extend-" + random_token());
        ensure_private_directory(stage);
        const auto token = random_token();
        write_private_json(stage / "owner.json", {{"token", token}});
        const auto stage_owner = cache_file_identity(stage / "owner.json");
        struct Cleanup {
            std::filesystem::path path;
            std::string token;
            Json identity;

            ~Cleanup() {
                try {
                    ordinary_ancestors(path);

                    if (cache_file_identity(path / "owner.json") == identity &&
                        read_private_json(path / "owner.json").at("token") == token) {
                        std::filesystem::remove_all(path);
                    }
                } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
                }
            }
        } cleanup{stage, token, stage_owner};
        const auto imported = stage / "archive", extracted = stage / "extracted";
        const bool vendor = extension_kind == "PassionVehicle";
        const auto &image = acquisition.at(vendor ? "vendor" : "system");
        const auto meter = unpacking(vendor ? "vendor" : "system",
                                     image.at("bytes").get<std::uint64_t>());
        const auto import_receipt = import_owner_update_system(
                archive, owner, image, imported, reserve, [&meter](std::uint64_t block) {
                    meter->advance(block);
                });
        const auto extra_receipt =
                extract_pinned_ext4_files(imported / "system.img", pinned_sha(image.at("sha256")),
                                          extra_paths, extracted, reserve, vendor ? "vendor" : "");
        progress::report("fetch_extracted", {{"count", std::to_string(extra_paths.size())}});

        for (const auto &name : additions) {
            const auto &item = declared.at(name);
            const auto relative = item.at("acquisition").at("path").get<std::string>().substr(1);

            if (verify_file(extracted / relative, pinned_sha(item.at("sha256")), 1ULL << 30) !=
                item.at("bytes").get<std::uint64_t>()) {
                throw VoyemuError("FETCH_UPDATE", "extension extent differs");
            }
        }

        const auto ext4_path = destination / "ext4-extraction.json",
                   owner_path = destination / "owner-inputs.json",
                   normal_path = destination / "native-inputs.json";
        auto ext4 = read_private_json(ext4_path, 256 * 1024);

        if ((!vendor && (ext4.at("image_sha256") != extra_receipt.at("image_sha256") ||
                         ext4.at("partition_offset") != extra_receipt.at("partition_offset") ||
                         ext4.at("block_size") != extra_receipt.at("block_size"))) ||
            ext4.at("native") != true || ext4.at("filesystem_mounted") != false) {
            throw VoyemuError("FETCH_UPDATE", "retained filesystem receipt differs");
        }

        if (vendor) {
            if (ext4.contains("vendor")) {
                throw VoyemuError("FETCH_UPDATE", "vendor receipt already present");
            }

            ext4["vendor"] = extra_receipt;
        }

        for (const auto &name : additions) {
            const auto &item = declared.at(name);
            const auto relative = item.at("acquisition").at("path").get<std::string>().substr(1);

            if (ext4.at("files").contains(relative)) {
                throw VoyemuError("FETCH_UPDATE", "extension already in filesystem receipt");
            }

            ext4["files"][relative] = extra_receipt.at("files").at(relative);
            ext4["bytes"] = ext4.at("bytes").get<std::uint64_t>() +
                            item.at("bytes").get<std::uint64_t>();
        }

        auto result = before;
        result["acquisition_sha256"] = acquisition_sha;
        result.erase("profile_sha256");
        result.erase("qnx_profile_sha256");
        result["originals"]["files"] = Json::array();

        for (const auto &input : inputs) {
            result["originals"]["files"].push_back(
                    {{"file", input.file},
                     {"sha256", input.sha256},
                     {"bytes", definition.at("original").at(input.name).at("bytes")}});
        }

        const auto ext4_bytes = ext4.dump(2) + "\n";
        result["ext4_receipt_sha256"] = sha256_bytes(ext4_bytes);
        result["extension"] = {{"kind", extension_kind},
                               {"previous_acquisition_sha256", previous_sha},
                               {"previous_owner_inputs_sha256", sha256_file(owner_path)},
                               {"native_system_import", import_receipt}};
        struct Record {
            std::filesystem::path path;
            std::string before, after;
            Json before_id, after_id;
        };
        std::vector<Record> records;
        auto record = [&](const std::filesystem::path &path, const Json &value) {
            records.push_back({path,
                               read_private_json_bytes(path, 256 * 1024),
                               value.dump(2) + "\n",
                               cache_file_identity(path),
                               {}});
        };
        record(ext4_path, ext4);
        record(owner_path, result);

        if (old_files.contains(normal_path)) {
            auto normal = read_private_json(normal_path, 256 * 1024);
            Json inventory = Json::array();
            std::uint64_t total = 0;

            for (const auto &input : inputs) {
                const auto size =
                        definition.at("original").at(input.name).at("bytes").get<std::uint64_t>();
                total += size;
                inventory.push_back(
                        {{"file", input.file}, {"sha256", input.sha256}, {"bytes", size}});
            }

            normal["originals"] = {{"files", inputs.size()},
                                   {"bytes", total},
                                   {"inputs_sha256", sha256_bytes(inventory.dump())},
                                   {"verified", true}};
            normal["owner_inputs_sha256"] = sha256_bytes(result.dump(2) + "\n");
            record(normal_path, normal);
        }

        auto guard = [&](unsigned written) {
            unchanged();

            for (const auto &[path, identity] : old_files) {
                ordinary_ancestors(path);
                bool metadata = false;

                for (unsigned i = 0; i < records.size(); ++i) {
                    if (records[i].path == path) {
                        metadata = true;
                        const auto &r = records[i];

                        if (cache_file_identity(path) != (i < written ? r.after_id : r.before_id) ||
                            read_private_json_bytes(path, 256 * 1024) !=
                                    (i < written ? r.after : r.before)) {
                            throw VoyemuError("FETCH_UPDATE_CAS", "receipt changed");
                        }

                        break;
                    }
                }

                if (!metadata && cache_file_identity(path) != identity) {
                    throw VoyemuError("FETCH_UPDATE_CAS", "retained input changed");
                }
            }
        };
        struct Published {
            std::filesystem::path path;
            std::string sha;
            Json identity;
        };
        std::vector<Published> published;
        std::map<std::filesystem::path, Json> retained_parents;

        for (const auto &entry : std::filesystem::recursive_directory_iterator(destination)) {
            if (entry.is_directory()) {
                retained_parents.emplace(entry.path(),
                                         owner_update_directory_identity(entry.path()));
            }
        }

        std::vector<std::pair<std::filesystem::path, Json>> created_parents;
        unsigned attempted = 0;
        auto targets_unchanged = [&] {
            for (const auto &item : created_parents) {
                if (owner_update_directory_identity(item.first) != item.second) {
                    throw VoyemuError("FETCH_UPDATE_CAS", "extension parent changed");
                }
            }

            for (const auto &item : published) {
                if (cache_file_identity(item.path) != item.identity) {
                    throw VoyemuError("FETCH_UPDATE_CAS", "extension changed");
                }
            }
        };
        try {
            guard(0);
            verify(destination, previous, previous_sha);

            for (const auto &name : additions) {
                const auto &item = declared.at(name);
                const auto source = extracted /
                                    item.at("acquisition").at("path").get<std::string>().substr(1),
                           target = destination / "originals" / item.at("file").get<std::string>();
                guard(0);
                targets_unchanged();
                auto parents = os::ancestors(target.parent_path());
                std::reverse(parents.begin(), parents.end());

                for (const auto &parent : parents) {
                    const auto relative = parent.lexically_relative(destination);

                    if (relative.empty() || relative == "." || *relative.begin() == "..") {
                        continue;
                    }

                    ordinary_ancestors(parent);
                    auto retained = retained_parents.find(parent);
                    auto owned = std::find_if(created_parents.begin(), created_parents.end(),
                                              [&](const auto &made) {
                                                  return made.first == parent;
                                              });

                    if (retained != retained_parents.end() || owned != created_parents.end()) {
                        const auto &expected = retained != retained_parents.end() ? retained->second
                                                                                  : owned->second;

                        if (owner_update_directory_identity(parent) != expected) {
                            throw VoyemuError("FETCH_UPDATE_CAS", "extension parent changed");
                        }

                        continue;
                    }

                    for (const auto &entry :
                         std::filesystem::directory_iterator(parent.parent_path())) {
                        auto actual = entry.path().filename().string(),
                             expected = parent.filename().string();
                        const auto lower = [](unsigned char c) {
                            return std::tolower(c);
                        };
                        std::transform(actual.begin(), actual.end(), actual.begin(), lower);
                        std::transform(expected.begin(), expected.end(), expected.begin(), lower);

                        if (actual == expected) {
                            throw VoyemuError("FETCH_UPDATE_CAS", "foreign extension parent");
                        }
                    }

                    if (!std::filesystem::create_directory(parent)) {
                        throw VoyemuError("FETCH_UPDATE_CAS",
                                          "exclusive extension parent required");
                    }

                    created_parents.emplace_back(parent, owner_update_directory_identity(parent));
                }

                if (!os::rename_exclusive(source, target)) {
                    throw VoyemuError("FETCH_UPDATE", "exclusive extension publication failed");
                }

                published.push_back({target, pinned_sha(item.at("sha256")), {}});
                published.back().identity = cache_file_identity(target);
            }

            for (unsigned i = 0; i < records.size(); ++i) {
                guard(i);
                targets_unchanged();
                attempted = i + 1;
                write_private_json_bytes(records[i].path, records[i].after, 256 * 1024);
                records[i].after_id = cache_file_identity(records[i].path);
            }

            guard(records.size());
            verify(destination, definition, acquisition_sha);
            targets_unchanged();
            result["extended"] = true;

            return result;
        } catch (...) {
            const auto failure = std::current_exception();
            bool incomplete = false;

            while (attempted) {
                auto &r = records[--attempted];
                try {
                    const auto bytes = read_private_json_bytes(r.path, 256 * 1024);
                    const auto id = cache_file_identity(r.path);

                    if (bytes == r.before && id == r.before_id) {
                        continue;
                    }

                    if (!r.after_id.empty() && id == r.after_id && bytes == r.after) {
                        write_private_json_bytes(r.path, r.before, 256 * 1024);
                    } else {
                        incomplete = true;
                    }
                } catch (...) {
                    incomplete = true;
                }
            }

            for (auto item = published.rbegin(); item != published.rend(); ++item) {
                try {
                    ordinary_ancestors(item->path);

                    if (cache_file_identity(item->path) == item->identity &&
                        sha256_file(item->path) == item->sha) {
                        std::filesystem::remove(item->path);
                    } else {
                        incomplete = true;
                    }
                } catch (...) {
                    incomplete = true;
                }
            }

            for (auto item = created_parents.rbegin(); item != created_parents.rend(); ++item) {
                try {
                    ordinary_ancestors(item->first);

                    if (owner_update_directory_identity(item->first) != item->second ||
                        !std::filesystem::is_empty(item->first) ||
                        !std::filesystem::remove(item->first)) {
                        incomplete = true;
                    }
                } catch (...) {
                    incomplete = true;
                }
            }

            if (incomplete) {
                throw VoyemuError("FETCH_UPDATE_ROLLBACK",
                                  "foreign/unverifiable extension retained");
            }

            std::rethrow_exception(failure);
        }
    }

    ensure_private_directory(root / ".local/build/tmp");
    ensure_private_directory(destination.parent_path());
    const auto stage = root / ".local/build/tmp" / ("owner-fetch-" + random_token());
    ensure_private_directory(stage);
    const auto token = random_token();
    write_private_json(stage / "owner.json", {{"token", token}});
    const auto owner_identity = cache_file_identity(stage / "owner.json");
    struct Cleanup {
        std::filesystem::path path;
        std::string token;
        Json identity;

        ~Cleanup() {
            try {
                ordinary_ancestors(path);

                if (cache_file_identity(path / "owner.json") == identity &&
                    read_private_json(path / "owner.json").at("token") == token) {
                    std::filesystem::remove_all(path);
                }
            } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
            }
        }
    } cleanup{stage, token, owner_identity};
    const auto imported = stage / "archive", extracted = stage / "extracted",
               pending = stage / "publish";
    // The QNX images come out of the same nested archive as the system image, so one meter shows
    // both.
    auto meter = unpacking("system", acquisition.at("system").at("bytes").get<std::uint64_t>());
    const auto advance = [&meter](std::uint64_t block) {
        meter->advance(block);
    };
    const auto imported_receipt =
            import_owner_update_archive(archive, owner, acquisition.at("system"),
                                        qnx.at("originals"), imported, reserve, advance);
    extract_pinned_ext4_files(imported / "system.img",
                              pinned_sha(acquisition.at("system").at("sha256")), paths, extracted,
                              reserve);
    ensure_private_directory(pending / "originals");
    std::filesystem::rename(imported / "qnx", pending / "qnx");

    const auto merge_extraction = [](Json &receipt, const std::filesystem::path &directory,
                                     const Json &extra,
                                     const std::filesystem::path &extra_directory) {
        for (auto it = extra.at("files").begin(); it != extra.at("files").end(); ++it) {
            if (receipt.at("files").contains(it.key())) {
                throw VoyemuError("FETCH_UPDATE", "duplicate extraction path");
            }

            const auto target = directory / it.key();
            ensure_private_directory(target.parent_path());
            std::filesystem::rename(extra_directory / it.key(), target);
            receipt["files"][it.key()] = it.value();
        }

        receipt["bytes"] = receipt.at("bytes").get<std::uint64_t>() +
                           extra.at("bytes").get<std::uint64_t>();
    };

    // The finite three-app media group has its own bounded extraction; retain the 512 MiB per-call
    // ceiling.
    if (!media_paths.empty()) {
        const auto media_extracted = stage / "media-extracted";
        const auto media_receipt = extract_pinned_ext4_files(
                imported / "system.img", pinned_sha(acquisition.at("system").at("sha256")),
                media_paths, media_extracted, reserve);
        auto combined = read_private_json(extracted / "receipt.json", 256 * 1024);

        merge_extraction(combined, extracted, media_receipt, media_extracted);
        write_private_json(extracted / "receipt.json", combined);
    }

    progress::report("fetch_extracted",
                     {{"count", std::to_string(paths.size() + media_paths.size())}});
    const auto vendor_extracted = stage / "vendor-extracted";

    if (!vendor_paths.empty() || !vendor_apps.empty()) {
        const auto imported_vendor = stage / "vendor-archive";
        meter = unpacking("vendor", acquisition.at("vendor").at("bytes").get<std::uint64_t>());
        import_owner_update_system(archive, owner, acquisition.at("vendor"), imported_vendor,
                                   reserve, advance);
        const auto vendor_image = imported_vendor / "system.img";
        const auto vendor_pin = pinned_sha(acquisition.at("vendor").at("sha256"));
        auto vendor_receipt = extract_pinned_ext4_files(
                vendor_image, vendor_pin, vendor_paths.empty() ? vendor_apps : vendor_paths,
                vendor_extracted, reserve, "vendor");

        if (!vendor_paths.empty() && !vendor_apps.empty()) {
            // The OEM vendor libraries and launcher APKs have independent 512 MiB batches.
            const auto apps_extracted = stage / "vendor-apps-extracted";
            const auto apps_receipt = extract_pinned_ext4_files(
                    vendor_image, vendor_pin, vendor_apps, apps_extracted, reserve, "vendor");
            merge_extraction(vendor_receipt, vendor_extracted, apps_receipt, apps_extracted);
        }

        progress::report("fetch_extracted",
                         {{"count", std::to_string(vendor_paths.size() + vendor_apps.size())}});
        auto combined = read_private_json(extracted / "receipt.json", 256 * 1024);
        combined["vendor"] = vendor_receipt;

        for (auto it = vendor_receipt.at("files").begin(); it != vendor_receipt.at("files").end();
             ++it) {
            combined["files"][it.key()] = it.value();
        }

        combined["bytes"] = combined.at("bytes").get<std::uint64_t>() +
                            vendor_receipt.at("bytes").get<std::uint64_t>();
        write_private_json(extracted / "receipt.json", combined);
    }

    Json original_files = Json::array(), raw_files = Json::array();

    for (const auto &input : inputs) {
        const auto &spec = definition.at("original").at(input.name);
        const auto source = (spec.at("acquisition").at("image") == "vendor" ? vendor_extracted
                                                                            : extracted) /
                            spec.at("acquisition").at("path").get<std::string>().substr(1);
        const auto size = verify_file(source, input.sha256, 1ULL << 30);

        if (size != spec.at("bytes").get<std::uint64_t>()) {
            throw VoyemuError("FETCH_UPDATE", "extracted original extent differs");
        }

        const auto target = pending / "originals" / input.file;
        ensure_private_directory(target.parent_path());
        std::filesystem::rename(source, target);
        original_files.push_back({{"file", input.file}, {"sha256", input.sha256}, {"bytes", size}});
    }

    for (auto it = qnx.at("originals").begin(); it != qnx.at("originals").end(); ++it) {
        const auto name = relative_path(it.value().at("file").get<std::string>());
        raw_files.push_back({{"file", name},
                             {"sha256", it.value().at("sha256")},
                             {"bytes", it.value().at("bytes")}});
    }

    std::filesystem::rename(imported / "receipt.json", pending / "owner-update.json");
    std::filesystem::rename(extracted / "receipt.json", pending / "ext4-extraction.json");
    const Json result = {
            {"schema", 1},
            {"profile", profile},
            {"source", "owner-update"},
            {"acquisition_sha256", acquisition_sha},
            {"owner_archive", {{"sha256", archive_sha}, {"bytes", source_pin.at("bytes")}}},
            {"source_container", direct ? "inner-tgz" : "zip"},
            {"originals", {{"files", original_files}, {"verified", true}}},
            {"qnx", {{"files", raw_files}, {"verified", true}}},
            {"owner_update_receipt_sha256", sha256_file(pending / "owner-update.json")},
            {"ext4_receipt_sha256", sha256_file(pending / "ext4-extraction.json")},
            {"native", true},
            {"frame_verified", false},
            {"guest_started", false},
            {"vehicle_modified", false},
            {"preparation_ready", false}};
    write_private_json(pending / "owner-inputs.json", result);
    verify(pending, definition, acquisition_sha);
    unchanged();

    if (!os::rename_exclusive(pending, destination)) {
        throw VoyemuError("FETCH_UPDATE", "exclusive input publication failed");
    }

    meter.reset();
    report_saved(inputs.size(), qnx.at("originals").size(), started);

    return result;
}
} // namespace

namespace fetch_detail {
void bind_owner_inputs(const std::filesystem::path &root, std::string_view profile,
                       const Json &definition, const Json &imported, Json &result) {
    const auto native_qnx = root / "profiles" / std::string(profile) / "profile-qnx.json";
    const auto owner_file = root / ".local/profiles" / std::string(profile) / "owner-inputs.json";
    const bool declared_qnx = std::filesystem::exists(native_qnx) ||
                              std::filesystem::is_symlink(native_qnx);

    if (!declared_qnx) {
        if (result.contains("qnx") || imported.contains("qnx")) {
            throw VoyemuError("FETCH_UPDATE", "QNX inputs require a declared QNX profile");
        }

        return;
    }

    ordinary_ancestors(native_qnx);
    const auto config = read_private_json(native_qnx, 128 * 1024);

    if (!result.contains("qnx")) {
        throw VoyemuError("FETCH_UPDATE", "declared QNX inputs missing from fetch result");
    }

    const auto acquisition = definition.value("acquisition", Json::object());
    const bool generic_import = !imported.is_null() && acquisition.value("format", std::string{}) ==
                                                               "pinned-zip-tgz-raw-scatter";

    if (generic_import && (!imported.contains("qnx") || imported.at("qnx") != result.at("qnx"))) {
        throw VoyemuError("FETCH_UPDATE", "imported QNX binding differs from verified result");
    }

    if (generic_import || std::filesystem::exists(owner_file) ||
        std::filesystem::is_symlink(owner_file)) {
        ordinary_ancestors(owner_file);
        const auto identity = cache_file_identity(owner_file);
        const auto owner_pin = sha256_file(owner_file);
        const auto owner = read_private_json(owner_file, 256 * 1024);

        if (owner.at("schema") != 1 || owner.at("profile") != profile ||
            owner.at("source") != "owner-update" || owner.at("native") != true ||
            owner.at("frame_verified") != false || owner.at("preparation_ready") != false ||
            owner.at("acquisition_sha256") != acquisition_identity(definition, config) ||
            !owner_archive_matches(owner, definition.at("ownerUpdate")) ||
            sha256_bytes(owner.at("originals").at("files").dump()) !=
                    result.at("originals").at("inputs_sha256").get<std::string>() ||
            owner.at("qnx").at("files") != result.at("qnx").at("files")) {
            throw VoyemuError("FETCH_UPDATE",
                              "verified owner binding differs from ordinary fetch inputs");
        }

        const auto owner_directory = owner_file.parent_path();
        verify_file(owner_directory / "owner-update.json",
                    pinned_sha(owner.at("owner_update_receipt_sha256")), 256 * 1024);
        verify_file(owner_directory / "ext4-extraction.json",
                    pinned_sha(owner.at("ext4_receipt_sha256")), 256 * 1024);

        if (cache_file_identity(owner_file) != identity || sha256_file(owner_file) != owner_pin) {
            throw VoyemuError("FETCH_UPDATE", "owner receipt changed during ordinary fetch");
        }

        result["owner_inputs_sha256"] = owner_pin;
        result["frame_verified"] = false;
    }
}
} // namespace fetch_detail

std::string profile_display_name(const std::filesystem::path &root, std::string_view profile) {
    try {
        return profile_title(load_profile(root, profile));
    } catch (const std::exception &) { /* Ignored: a profile without a title is named by id. */
    }

    return std::string(profile);
}

void verify_owner_archive(const std::filesystem::path &root, std::string_view profile,
                          const std::filesystem::path &archive, std::uint64_t bytes,
                          const std::string &sha256, bool announce, const char *missing_code,
                          const char *mismatch_code) {
    const auto name = profile_display_name(root, profile);
    const auto status = std::filesystem::symlink_status(archive);

    if (!std::filesystem::exists(status)) {
        throw cli::LocalizedError(
                missing_code, "error.archive_missing",
                {{"path", archive.string()}, {"archive", "update.zip"}, {"profile_name", name}});
    }

    const std::uint64_t size =
            std::filesystem::is_regular_file(status) ? std::filesystem::file_size(archive) : 0;

    if (size != bytes) {
        // The bundled profile whose pinned update has this size names the update it is.
        std::string other;

        for (const auto &record : embedded_profile_catalog()) {
            const auto &definition = record.at("definition");
            const auto id = record.at("id").get<std::string>();
            const auto owner = definition.value("ownerUpdate", Json::object());
            const auto device = definition.value("device", Json::object())
                                        .value("sourceArchives", Json::object())
                                        .value("update_zip", Json::object());

            if (size && id != profile &&
                (owner.value("bytes", std::uint64_t{0}) == size ||
                 device.value("bytes", std::uint64_t{0}) == size)) {
                other = id;
                break;
            }
        }

        const auto dash = profile.rfind('-');
        throw cli::LocalizedError(
                mismatch_code,
                other.empty() ? "error.archive_foreign" : "error.archive_other_profile",
                {{"path", archive.string()},
                 {"profile_name", name},
                 {"size", progress::size_text(size, progress::language())},
                 {"bytes", std::to_string(size)},
                 {"expected", std::to_string(bytes)},
                 {"version",
                  std::string(profile.substr(dash == std::string_view::npos ? 0 : dash + 1))},
                 {"archive", "update.zip"},
                 {"other", other}});
    }

    if (std::filesystem::hard_link_count(archive) != 1) {
        throw VoyemuError(missing_code, "ordinary unlinked owner archive required");
    }

    if (announce) {
        progress::block();
        progress::report("fetch_archive",
                         {{"profile_name", name},
                          {"path", archive.string()},
                          {"total", progress::size_text(size, progress::language())}});
    }

    progress::block();
    progress::Meter meter("fetch_check", {{"profile_name", name}});
    meter.length(bytes);
    const auto epoch = cache_file_identity(archive);

    if (pinned_file_sha256(archive, [&meter](std::uint64_t block) {
            meter.advance(block);
        }) != sha256) {
        throw cli::LocalizedError(mismatch_code, "error.archive_changed",
                                  {{"path", archive.string()}});
    }

    if (cache_file_identity(archive) != epoch) {
        throw VoyemuError(mismatch_code, "owner archive changed during verification");
    }

    meter.finish();
}

std::filesystem::path install_development_kernel(const std::filesystem::path &root,
                                                 const Json &descriptor, bool offline,
                                                 std::uint64_t reserve,
                                                 const DownloadTransport &transport) {
    DownloadPin pin{descriptor.at("url").get<std::string>(),
                    descriptor.at("sha256").get<std::string>(), 64ULL << 20};
    // The console names the kernel by the version of its release, "5.4.86".
    const auto release =
            descriptor.value("provenance", Json::object()).value("kernel_release", std::string{});

    pin.label = "development_kernel";
    pin.version = release.substr(0, release.find('-'));

    try {
        return download_pinned(pin,
                               portable_development_kernel_file(root, descriptor).parent_path(),
                               offline, reserve, transport)
                .file;
    } catch (const std::runtime_error &error) {
        // An asset that is not published names the release it needs; a network failure stays.
        if (!download_unpublished(std::current_exception())) {
            throw;
        }

        throw VoyemuError("DEVELOPMENT_KERNEL_ASSET_MISSING",
                          "published release asset " + pin.url + " required: " + error.what());
    }
}

Json import_owner_profile_inputs(const std::filesystem::path &root, std::string_view profile,
                                 const std::filesystem::path &update, std::uint64_t reserve) {
    if (!valid_profile_name(profile) || !root.is_absolute() ||
        std::filesystem::canonical(root) != root) {
        throw VoyemuError("FETCH_ROOT", "canonical root and safe profile required");
    }

    // The acquisition format of the profile selects the importer of its owner update.
    const auto format = read_private_json(root / "profiles" / std::string(profile) / "profile.json",
                                          512 * 1024)
                                .value("acquisition", Json::object())
                                .value("format", std::string{});

    if (format == "pinned-zip-zero-base-zstd-segments") {
        return import_segmented_profile_inputs(root, profile, update, reserve);
    }

    if (format == "pinned-snapshot-raw-images") {
        return import_snapshot_profile_inputs(root, profile, update, reserve);
    }

    if (format == "nxp-update-zip") {
        return fetch_nxp_update(root, profile, update, reserve);
    }

    return fetch_update(root, profile, update, reserve);
}

Json nxp_acquisition_plan(const Json &definition) {
    nxp_update_profile(definition);

    const auto inputs = original_input_plan(definition);

    if (inputs.empty() || inputs.size() > 512) {
        throw VoyemuError("FETCH_NXP", "bounded source originals required");
    }

    Json rows = Json::array();
    std::set<std::string> paths;

    for (const auto &input : inputs) {
        const auto &item = definition.at("original").at(input.name);
        const auto &acquisition = item.at("acquisition");
        const bool resource = acquisition.at("image") == "resource",
                   vendor = acquisition.at("image") == "vendor";
        const auto path = acquisition.at("path").get<std::string>();

        if (!input.package.empty() || item.value("type", std::string("file")) != "file" ||
            (!resource && !vendor && acquisition.at("image") != "system") ||
            !remote_path(resource ? "/resc" + path : path) ||
            std::filesystem::path(path).lexically_normal().generic_string() != path ||
            (resource ? (!path.starts_with("/resc_qgspeech/aispeech/") ||
                         input.remote != "/resc" + path)
                      : (path != input.remote ||
                         !path.starts_with(vendor ? "/vendor/" : "/system/"))) ||
            !item.at("bytes").is_number_unsigned() || item.at("bytes").get<std::uint64_t>() == 0 ||
            !paths.insert(acquisition.at("image").get<std::string>() + path).second) {
            throw VoyemuError(
                    "FETCH_NXP",
                    "exact pinned OEM system, vendor or speech-resource path/extent required");
        }

        rows.push_back({{"file", input.file},
                        {"image", acquisition.at("image")},
                        {"path", path},
                        {"sha256", input.sha256},
                        {"bytes", item.at("bytes")}});
    }

    Json batches = Json::array(), batch = Json::array();
    std::uint64_t batch_bytes = 0, resource_bytes = 0;
    unsigned resource_count = 0, vendor_count = 0;

    for (const auto &row : rows) {
        const auto bytes = row.at("bytes").get<std::uint64_t>();

        if (bytes > (256ULL << 20)) {
            throw VoyemuError("FETCH_NXP", "original exceeds pinned extractor file bound");
        }

        if (row.at("image") == "resource") {
            if (bytes > (512ULL << 20) - resource_bytes || ++resource_count > 256) {
                throw VoyemuError("FETCH_NXP", "resource extraction bound exceeded");
            }

            resource_bytes += bytes;
            continue;
        }

        // The vendor originals are the few files read from the vendor image in one extraction.
        if (row.at("image") == "vendor") {
            if (++vendor_count > 16) {
                throw VoyemuError("FETCH_NXP", "vendor extraction bound exceeded");
            }

            continue;
        }

        if (batch.size() == 256 || bytes > (512ULL << 20) - batch_bytes) {
            batches.push_back(batch);
            batch = Json::array();
            batch_bytes = 0;
        }

        batch.push_back(row.at("path"));
        batch_bytes += bytes;
    }

    if (!batch.empty()) {
        batches.push_back(batch);
    }

    return {{"profile", definition.at("id")}, {"originals", rows}, {"system_batches", batches}};
}

std::vector<OriginalInput> original_input_plan(const Json &profile) {
    if (!profile.is_object() || profile.at("schema") != 1 || !profile.at("original").is_object()) {
        throw VoyemuError("FETCH_PROFILE", "original input declarations required");
    }

    std::vector<OriginalInput> result;
    std::set<std::string> files;

    for (auto it = profile.at("original").begin(); it != profile.at("original").end(); ++it) {
        const auto &item = it.value();
        const auto base = relative_path(item.at("file").get<std::string>());
        const auto source = item.value("source", Json::object());
        const auto package = source.value("package", std::string{}),
                   remote = source.value("path", std::string{});

        if (!package.empty() &&
            !std::regex_match(package,
                              std::regex(R"(^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$)"))) {
            throw VoyemuError("FETCH_SOURCE", "invalid package");
        }

        if (!remote.empty() && !remote_path(remote)) {
            throw VoyemuError("FETCH_SOURCE", "explicit Android system path required");
        }

        if (!remote.empty() && !package.empty()) {
            throw VoyemuError("FETCH_SOURCE", "ambiguous source");
        }

        auto add = [&](const std::string &file, const Json &hash, const std::string &origin) {
            auto key = file;

            for (char &c : key) {
                if (c >= 'A' && c <= 'Z') {
                    c += 32;
                }
            }

            if (!files.insert(key).second) {
                throw VoyemuError("FETCH_DUPLICATE", "duplicate or case-aliased input");
            }

            result.push_back({it.key(), file, pinned_sha(hash), origin, package});

            if (result.size() > 20000) {
                throw VoyemuError("FETCH_BOUND", "input count exceeds maximum");
            }
        };

        if (item.value("type", std::string{}) == "tree") {
            if (!item.at("sha256").is_object() || item.at("sha256").empty() || remote.empty() ||
                !package.empty()) {
                throw VoyemuError("FETCH_TREE", "pinned tree requires explicit path");
            }

            for (auto child = item.at("sha256").begin(); child != item.at("sha256").end();
                 ++child) {
                const auto member = relative_path(child.key());
                add(base + "/" + member, child.value(), remote + "/" + member);
            }
        } else {
            if (item.contains("type") && item.at("type") != "file") {
                throw VoyemuError("FETCH_TYPE", "supported input type required");
            }

            add(base, item.at("sha256"), remote);
        }
    }

    for (const auto &input : result) {
        for (auto parent = std::filesystem::path(input.file).parent_path(); !parent.empty();
             parent = parent.parent_path()) {
            auto key = parent.generic_string();

            for (char &c : key) {
                if (c >= 'A' && c <= 'Z') {
                    c += 32;
                }
            }

            if (files.contains(key)) {
                throw VoyemuError("FETCH_PATH", "declared file used as directory");
            }
        }
    }

    return result;
}

Json verify_original_inputs(const std::filesystem::path &root, std::string_view profile,
                            const std::vector<OriginalInput> &inputs) {
    if (!valid_profile_name(profile) || !root.is_absolute()) {
        throw VoyemuError("FETCH_PROFILE", "safe profile and absolute root required");
    }

    const auto originals = profile_originals_directory(root, profile);
    std::uint64_t bytes = 0;
    Json entries = Json::array();

    for (const auto &input : inputs) {
        relative_path(input.file);
        const auto file = originals / input.file;

        if (!std::filesystem::exists(file) && !std::filesystem::is_symlink(file)) {
            throw VoyemuError("FETCH_MISSING", "declared original input missing: " + input.file);
        }

        const auto size = verify_file(file, input.sha256, 1ULL << 30);

        if (size > (8ULL << 30) - bytes) {
            throw VoyemuError("FETCH_BOUND", "original input bytes exceed maximum");
        }

        bytes += size;
        entries.push_back({{"file", input.file}, {"sha256", input.sha256}, {"bytes", size}});
    }

    return {{"files", entries.size()},
            {"bytes", bytes},
            {"inputs_sha256", sha256_bytes(entries.dump())},
            {"verified", true}};
}

Json fetch_native_inputs(const std::filesystem::path &root, std::string_view profile, bool offline,
                         const std::string &serial, std::uint64_t reserve,
                         const std::filesystem::path &jdk, const std::filesystem::path &update,
                         std::string_view target) {
    if (!valid_profile_name(profile) || !root.is_absolute() ||
        std::filesystem::canonical(root) != root) {
        throw VoyemuError("FETCH_ROOT", "canonical root and safe profile required");
    }

    const auto recipe = authoring_directory(root, profile);
    const auto input_profile = recipe.filename().string();
    Json imported;

    if (!update.empty()) {
        if (!serial.empty()) {
            throw VoyemuError("FETCH_UPDATE", "archive source and serial are mutually exclusive");
        }

        imported = import_owner_profile_inputs(root, input_profile, update, reserve);
    }

    if (!serial.empty() &&
        (offline || serial.starts_with("emulator-") ||
         !std::regex_match(serial, std::regex(R"(^[A-Za-z0-9][A-Za-z0-9_.:-]*$)")))) {
        throw VoyemuError("FETCH_SERIAL",
                          "a valid physical serial and online mode are required for --source=adb");
    }

    const auto profile_directory = root / "profiles" / std::string(profile);

    if (update.empty() && std::filesystem::is_regular_file(profile_directory / "profile.json") &&
        std::filesystem::is_regular_file(profile_directory / "capture.json") &&
        read_private_json(profile_directory / "profile.json", 512 * 1024)
                        .value("status", std::string("ready")) != "ready") {
        if (!serial.empty()) {
            return capture_vehicle_inputs(root, profile, serial, jdk, offline);
        }

        const auto retained = original_input_plan(load_profile(root, profile));

        if (retained.empty()) {
            throw VoyemuError(
                    "FETCH_MISSING",
                    "incomplete profile requires retained pinned original inputs or --source=adb --serial SERIAL");
        }

        verify_original_inputs(root, profile, retained);
    }

    const auto definition = target.empty() ? load_profile(root, profile)
                                           : authoring_profile(root, profile, target);
    const auto multimedia_only = profile_multimedia_only(definition);
    const auto profile_name = profile_display_name(root, profile);
    const auto inputs = original_input_plan(definition);
    const auto own_originals = root / ".local/profiles" / input_profile / "originals";
    const auto originals = serial.empty() && update.empty()
                                   ? profile_originals_directory(root, profile)
                                   : own_originals;
    // Hashing retained originals takes seconds, so it shows its bytes; an archive import of this
    // run has just verified them.
    const auto verifying = [&](const std::string &label,
                               std::uint64_t bytes) -> std::unique_ptr<progress::Meter> {
        if (!bytes || !imported.is_null()) {
            return {};
        }

        progress::block();
        auto meter = std::make_unique<progress::Meter>(
                "verify", progress::Arguments{{"label", label}, {"version", profile_name}});
        meter->length(bytes);

        return meter;
    };
    const auto present_bytes = [](const std::filesystem::path &file) -> std::uint64_t {
        return std::filesystem::is_regular_file(std::filesystem::symlink_status(file))
                       ? std::filesystem::file_size(file)
                       : 0;
    };
    std::uint64_t retained_bytes = 0;

    for (const auto &input : inputs) {
        retained_bytes += present_bytes(originals / input.file);
    }

    auto retained_meter = verifying("originals", retained_bytes);
    std::vector<OriginalInput> missing;

    for (const auto &input : inputs) {
        const auto file = originals / input.file;

        if (std::filesystem::exists(file) || std::filesystem::is_symlink(file)) {
            verify_file(file, input.sha256, 1ULL << 30, [&retained_meter](std::uint64_t block) {
                if (retained_meter) {
                    retained_meter->advance(block);
                }
            });
        } else {
            missing.push_back(input);
        }
    }

    if (retained_meter && missing.empty()) {
        retained_meter->finish();
    }

    retained_meter.reset();

    if (!missing.empty()) {
        if (originals != own_originals) {
            throw VoyemuError("FETCH_MISSING",
                              "reference inputs missing; shared originals are read-only");
        }

        if (serial.empty()) {
            throw cli::LocalizedError("FETCH_MISSING", "error.originals_missing",
                                      {{"profile_name", profile_name},
                                       {"profile", std::string(profile)},
                                       {"archive", "update.zip"}});
        }

        // The physical device is read with the adb that deps installed.
        try {
            install_native_dependencies(root, true, reserve);
        } catch (const std::runtime_error &error) {
            if (message_code(error.what()) != "DOWNLOAD_OFFLINE") {
                throw;
            }

            throw cli::LocalizedError("DOWNLOAD_OFFLINE", "error.deps_missing",
                                      {{"profile", std::string(profile)}});
        }

        const auto adb = root / ".local/toolchains/native-sdk/platform-tools" /
#ifdef _WIN32
                         "adb.exe";
#else
                         "adb";
#endif
        const auto stage = root / ".local/build/tmp" / ("native-fetch-" + random_token());
        ensure_private_directory(stage);
        struct Cleanup {
            std::filesystem::path path;

            ~Cleanup() {
                std::error_code error;
                std::filesystem::remove_all(path, error);
            }
        } cleanup{stage};
        auto device = [&](std::vector<std::string> arguments, int timeout = 300000) {
            ProcessSpec command;
            command.executable = adb;
            command.arguments = {"-s", serial};
            command.arguments.insert(command.arguments.end(), arguments.begin(), arguments.end());
            command.directory = root;
            command.output = stage / "adb.log";
            const auto result = execute(command, timeout, 128 * 1024);

            if (result.exit_code || result.timed_out) {
                throw VoyemuError("FETCH_ADB", "declared read-only device operation failed");
            }

            return trim(result.output);
        };

        if (device({"get-state"}, 10000) != "device") {
            throw VoyemuError("FETCH_ADB", "selected vehicle is not authorized and ready");
        }

        std::uint64_t bytes = 0;

        for (const auto &input : missing) {
            if (std::filesystem::space(root).available < reserve) {
                throw VoyemuError("FETCH_SPACE", "acquisition reserve reached");
            }

            auto remote = input.remote;

            if (!input.package.empty()) {
                const auto resolved = device({"shell", "pm", "path", input.package}, 15000);

                if (!resolved.starts_with("package:") || resolved.find('\n') != std::string::npos) {
                    throw VoyemuError("FETCH_PACKAGE", "one APK path required; splits unsupported");
                }

                remote = resolved.substr(8);
            }

            if (!remote_path(remote)) {
                throw VoyemuError("FETCH_SOURCE", "no declared vehicle source for " + input.name);
            }

            const auto file = stage / "originals" / input.file;
            ensure_private_directory(file.parent_path());

            if (std::filesystem::exists(file)) {
                throw VoyemuError("FETCH_OUTPUT", "fresh staged input required");
            }

            device({"pull", remote, file.string()});
            const auto size = verify_file(file, input.sha256, 1ULL << 30);

            if (size > (8ULL << 30) - bytes) {
                throw VoyemuError("FETCH_BOUND", "acquisition bytes exceed maximum");
            }

            bytes += size;
        }

        for (const auto &input : missing) {
            const auto destination = own_originals / input.file;
            ensure_private_directory(destination.parent_path());

            if (std::filesystem::exists(destination) || std::filesystem::is_symlink(destination)) {
                throw VoyemuError("FETCH_OUTPUT", "input appeared during acquisition");
            }

            std::filesystem::rename(stage / "originals" / input.file, destination);
        }

        write_private_json(root / ".local/profiles" / std::string(profile) /
                                   ("fetch-" + random_token() + ".json"),
                           {{"schema", 1},
                            {"profile", profile},
                            {"source", "vehicle"},
                            {"vehicle_modified", false},
                            {"files", missing.size()},
                            {"checked_at", utc_now()}});
    }

    const auto original_result = verify_original_inputs(root, profile, inputs);

    if (definition.contains("targets")) {
        Json result{{"schema", 1},
                    {"profile", profile},
                    {"originals", original_result},
                    {"vehicle_modified", false},
                    {"native", true},
                    {"preparation_ready", false}};

        if (!imported.is_null()) {
            result["owner_update"] = imported;
        }

        return result;
    }

    const auto &image = definition.at("android");
    DownloadPin image_pin{image.at("url").get<std::string>(), pinned_sha(image.at("sha256")),
                          8ULL << 30};
    image_pin.label = "android_image";
    image_pin.version = android_image_version(image);

    if (!image_pin.url.starts_with("https://dl.google.com/android/repository/sys-img/android/")) {
        throw VoyemuError("FETCH_IMAGE", "pinned official non-GMS image required");
    }

    std::filesystem::path archive;
    const auto base = root / ".local/profiles/common/android-base" / image_pin.sha256;
    bool cached_base = false;

    if (std::filesystem::exists(base) || std::filesystem::is_symlink(base)) {
        verify_native_base_image(image, base);
        cached_base = true;
    } else {
        archive = download_pinned(image_pin, root / ".local/toolchains/downloads/native", offline,
                                  reserve)
                          .file;
    }

    Json signing = Json::object();

    for (const auto *name : {"key", "cert"}) {
        const auto &entry = embedded_toolchain_manifest().at("signing").at("platform").at(name);
        DownloadPin pin{entry.at("url").get<std::string>(), entry.at("sha256").get<std::string>(),
                        65536, DownloadEncoding::base64};
        pin.label = std::string_view(name) == "key" ? "signing_key" : "signing_certificate";
        const auto file = download_pinned(pin, root / ".local/toolchains/downloads/native", offline,
                                          reserve);
        signing[name] = {{"file", file.file.string()}, {"sha256", pin.sha256}};
    }

    Json result = {{"schema", 1},
                   {"profile", profile},
                   {"originals", original_result},
                   {"signing", signing},
                   {"vehicle_modified", false},
                   {"native", true},
                   {"preparation_ready", false}};

    // Development kernels are CI-built release assets pinned by URL and SHA-256.
    if (const auto development = portable_development_kernel(definition); !development.is_null()) {
        result["development_kernel"] = {
                {"file", install_development_kernel(root, development, offline, reserve).string()},
                {"sha256", development.at("sha256")}};
    }

    if (cached_base) {
        result["android_base"] = {{"directory", base.string()},
                                  {"archive_sha256", image_pin.sha256},
                                  {"receipt_sha256", sha256_file(base / "base.json")}};
    } else {
        result["android_archive"] = {{"file", archive.string()}, {"sha256", image_pin.sha256}};
    }

    const auto native_qnx = recipe / "profile-qnx.json";

    if (!multimedia_only && std::filesystem::exists(native_qnx)) {
        if (update.empty()) {
            materialize_qnx_originals(root, input_profile, jdk, offline);
        }

        const auto config = read_private_json(native_qnx, 128 * 1024);
        Json files = Json::array();
        std::uint64_t qnx_bytes = 0;

        for (const auto &item : config.at("originals")) {
            qnx_bytes += present_bytes(qnx_originals_directory(root, input_profile) /
                                       relative_path(item.at("file").get<std::string>()));
        }

        auto qnx_meter = verifying("qnx_originals", qnx_bytes);

        for (auto it = config.at("originals").begin(); it != config.at("originals").end(); ++it) {
            const auto name = relative_path(it.value().at("file").get<std::string>());
            const auto pin = pinned_sha(it.value().at("sha256"));
            const auto bytes = verify_file(qnx_originals_directory(root, input_profile) / name, pin,
                                           4ULL << 30, [&qnx_meter](std::uint64_t block) {
                                               if (qnx_meter) {
                                                   qnx_meter->advance(block);
                                               }
                                           });
            files.push_back({{"file", name}, {"bytes", bytes}, {"sha256", pin}});
        }

        if (qnx_meter) {
            qnx_meter->finish();
        }

        result["qnx"] = {{"files", files}, {"verified", true}};
    }

    Json source_pins = Json::object();
    std::size_t source_count = 0, sources_downloaded = 0;
    const auto sources_start = std::chrono::steady_clock::now();
    const auto components = definition.value("components", Json::object());

    for (auto it = components.begin(); it != components.end(); ++it) {
        const auto relative = relative_path(it.value().get<std::string>());
        const auto metadata = recipe / relative / "component.json";

        if (!std::filesystem::exists(metadata)) {
            throw VoyemuError("FETCH_COMPONENT",
                              "component source metadata missing from selected project");
        }

        const auto description = read_private_json(metadata, 512 * 1024);
        const auto external = description.value("externalSources", Json::object());

        if (!external.is_object() || external.size() > 1024) {
            throw VoyemuError("FETCH_COMPONENT", "bounded external source map required");
        }

        for (auto entry = external.begin(); entry != external.end(); ++entry) {
            relative_path(entry.key());
            const auto &source = entry.value();
            const auto hash = pinned_sha(source.at("sha256"));
            const auto url = source.at("url").get<std::string>();
            std::uint64_t maximum = 1024 * 1024;
            const bool archive = source.contains("kind");

            if (archive) {
                if (source.size() != 5 || source.at("kind") != "archive" ||
                    source.at("format") != "aar" || !source.at("bytes").is_number_unsigned()) {
                    throw VoyemuError("FETCH_COMPONENT", "exact typed AAR descriptor required");
                }

                maximum = source.at("bytes").get<std::uint64_t>();
                const auto host = url.substr(std::min<std::size_t>(8, url.size()),
                                             url.find('/', 8) == std::string::npos
                                                     ? std::string::npos
                                                     : url.find('/', 8) - 8);

                if (!maximum || maximum > 16ULL * 1024 * 1024 || !url.starts_with("https://") ||
                    host.empty() || host.find('@') != std::string::npos || url.size() > 4096 ||
                    url.find('#') != std::string::npos ||
                    url.find_first_of("\r\n\t\\ ") != std::string::npos) {
                    throw VoyemuError("FETCH_COMPONENT", "bounded HTTPS AAR required");
                }
            }

            const auto cached = root / ".local/toolchains/downloads/sources" / hash;

            if (std::filesystem::exists(cached) || std::filesystem::is_symlink(cached)) {
                verify_file(cached, hash, maximum);
            } else {
                const auto encoding = url.starts_with("https://android.googlesource.com/") &&
                                                      url.ends_with("?format=TEXT")
                                              ? DownloadEncoding::base64
                                              : DownloadEncoding::raw;

                // One phase line stands for the hundreds of small source files of a profile.
                if (!sources_downloaded++) {
                    progress::block();
                    progress::report("fetch_sources");
                }

                DownloadPin source_pin{url, hash, maximum, encoding};
                source_pin.quiet = true;
                const auto blob = download_pinned(
                        source_pin, root / ".local/toolchains/downloads/native", offline, reserve);

                if (archive && blob.bytes != maximum) {
                    throw VoyemuError("FETCH_COMPONENT",
                                      "exact archive bytes differ before publication");
                }

                ensure_private_directory(cached.parent_path());

                if (std::filesystem::exists(cached) || std::filesystem::is_symlink(cached)) {
                    throw VoyemuError("FETCH_COMPONENT", "source cache destination appeared");
                }

                if (!std::filesystem::copy_file(blob.file, cached,
                                                std::filesystem::copy_options::none)) {
                    throw VoyemuError("FETCH_COMPONENT", "decoded source cache publication failed");
                }

                verify_file(cached, hash, maximum);
            }

            if (archive && std::filesystem::file_size(cached) != maximum) {
                throw VoyemuError("FETCH_COMPONENT", "exact archive bytes differ");
            }

            source_pins[it.key() + "/" + entry.key()] = hash;

            if (++source_count > 4096) {
                throw VoyemuError("FETCH_COMPONENT", "external source count exceeds maximum");
            }
        }
    }

    if (sources_downloaded) {
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::steady_clock::now() - sources_start)
                                     .count();
        progress::report("fetch_sources_done",
                         {{"count", std::to_string(sources_downloaded)},
                          {"time", progress::duration_text(static_cast<std::uint64_t>(seconds),
                                                           progress::language())}});
    }

    result["external_sources"] = {{"files", source_count},
                                  {"pins_sha256", sha256_bytes(source_pins.dump())},
                                  {"verified", true}};

    if (!multimedia_only) {
        fetch_detail::bind_owner_inputs(root, input_profile, definition, imported, result);
    }

    if (!imported.is_null()) {
        result["owner_update"] = imported;
    }

    // The shared owner cache accepts only its bound native-inputs receipt. A signed target
    // records its selected inputs in the separate Android preparation stage.
    if (target.empty() || !multimedia_only) {
        write_private_json(root / ".local/profiles" / std::string(profile) / "native-inputs.json",
                           result);
    }

    return result;
}
} // namespace voyemu
