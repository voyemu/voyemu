#include "fetch.hpp"
#include "archive_fixture.hpp"
#include "deps.hpp"
#include "fetch_internal.hpp"
#include "fetch_segmented.hpp"
#include "os/https.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_originals.hpp"
#include "progress.hpp"
#include "qinggan11_startup.hpp"
#include "quickboot.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#ifdef __APPLE__
#include <sys/stat.h>
#endif
using namespace voyemu;

static void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

#ifdef __APPLE__
static void number(std::string &data, unsigned at, std::uint64_t value, unsigned size = 4) {
    for (unsigned i = 0; i < size; ++i) {
        data.at(at + i) = static_cast<char>(value >> (8 * i));
    }
}

static std::string filesystem_fixture(bool vendor = false) {
    std::string data(16384, '\0');

    number(data, 1024, 16);
    number(data, 1028, 16);
    number(data, 1044, 1);
    number(data, 1056, 16);
    number(data, 1064, 16);
    number(data, 1080, 0xef53, 2);
    number(data, 1112, 128, 2);
    number(data, 1120, 0x42);
    number(data, 2056, 3);
    auto inode = [&](unsigned id, unsigned mode, unsigned size, unsigned block) {
        const auto at = 3072 + (id - 1) * 128;
        number(data, at, mode, 2);
        number(data, at + 4, size);
        number(data, at + 32, 0x80000);
        number(data, at + 40, 0xf30a, 2);
        number(data, at + 42, 1, 2);
        number(data, at + 44, 4, 2);
        number(data, at + 56, 1, 2);
        number(data, at + 60, block);
    };
    inode(2, 0040755, 1024, 5);
    inode(3, 0040755, 1024, 6);
    inode(4, 0100644, 6, 7);
    inode(5, 0040755, 1024, 8);
    inode(6, 0100644, 5, 9);
    inode(7, 0040755, 1024, 10);
    inode(8, 0040755, 1024, 11);
    inode(9, 0040755, 1024, 12);
    inode(10, 0040755, 1024, 13);
    inode(11, 0100644, 5, 14);
    inode(12, 0100644, 5, 15);
    auto entry = [&](unsigned at, unsigned id, unsigned length, const std::string &name) {
        number(data, at, id);
        number(data, at + 4, length, 2);
        number(data, at + 6, name.size(), 1);
        data.replace(at + 8, name.size(), name);
    };
    entry(5120, 2, 12, ".");
    entry(5132, 2, 12, "..");

    if (vendor) {
        entry(5144, 7, 12, "app");
        entry(5156, 4, 988, "native");
    } else {
        entry(5144, 3, 1000, "system");
    }

    entry(6144, 3, 12, ".");
    entry(6156, 2, 12, "..");
    entry(6168, 4, 12, "own");
    entry(6180, 5, 20, "framework");
    entry(6200, 7, 12, "app");
    entry(6212, 8, 20, "priv-app");
    entry(6232, 5, 936, "media");
    entry(8192, 5, 12, ".");
    entry(8204, 3, 12, "..");
    entry(8216, 6, 24, "framework.jar");
    entry(8240, 6, 976, "bootanimation.zip");
    data.replace(7168, 6, "native");
    data.replace(9216, 5, "extra");
    entry(10240, 7, 12, ".");
    entry(10252, 3, 12, "..");
    entry(10264, 9, 1000, "LY_Multimedia");
    entry(11264, 8, 12, ".");
    entry(11276, 3, 12, "..");
    entry(11288, 10, 1000, "LY_BtPhone");
    entry(12288, 9, 12, ".");
    entry(12300, 7, 12, "..");
    entry(12312, 11, 1000, "LY_Multimedia.apk");
    entry(13312, 10, 12, ".");
    entry(13324, 8, 12, "..");
    entry(13336, 12, 1000, "LY_BtPhone.apk");
    data.replace(14336, 5, "music");
    data.replace(15360, 5, "phone");

    return data;
}

static void archive_fixture(const std::filesystem::path &file,
                            const std::vector<std::pair<std::string, std::string>> &entries,
                            bool zip) {
    std::vector<ArchiveFixtureEntry> members;

    for (const auto &[name, data] : entries) {
        members.push_back({name, data});
    }

    write_archive_fixture(file, members, zip);
}

static std::string contents(const std::filesystem::path &file) {
    std::ifstream input(file, std::ios::binary);

    return {(std::istreambuf_iterator<char>(input)), {}};
}
#endif
#ifdef __APPLE__
static void owner_fetch_sequence(const std::filesystem::path &project) {
    const auto root = std::filesystem::canonical(std::filesystem::path(__FILE__))
                              .parent_path()
                              .parent_path()
                              .parent_path()
                              .parent_path() /
                      ".local/build/tmp" / ("voyemu-owner-sequence-" + random_token());

    ensure_private_directory(root);
    struct Cleanup {
        std::filesystem::path p;

        ~Cleanup() {
            std::filesystem::remove_all(p);
        }
    } cleanup{root};
    const auto raw = filesystem_fixture(), first = raw.substr(0, 4096), second = raw.substr(4096);
    const auto tgz = root / "owner.tgz", zip = root / "owner.zip";
    archive_fixture(tgz,
                    {{"ota/first", first},
                     {"ota/second", second},
                     {"ota/hyp", "hyp"},
                     {"ota/ifs", "ifs"},
                     {"ota/system", "sys"},
                     {"ota/recovery", "rec"}},
                    false);
    archive_fixture(zip, {{"update.tgz", contents(tgz)}}, true);
    const Json owner = {{"bytes", std::filesystem::file_size(zip)},
                        {"sha256", sha256_file(zip)},
                        {"inner",
                         {{"file", "update.tgz"},
                          {"bytes", std::filesystem::file_size(tgz)},
                          {"sha256", sha256_file(tgz)}}}};
    const Json scatter = {{"bytes", raw.size()},
                          {"sha256", sha256_bytes(raw)},
                          {"segments", Json::array({{{"member", "ota/first"},
                                                     {"offset", 0u},
                                                     {"bytes", first.size()},
                                                     {"sha256", sha256_bytes(first)}},
                                                    {{"member", "ota/second"},
                                                     {"offset", 4096u},
                                                     {"bytes", second.size()},
                                                     {"sha256", sha256_bytes(second)}}})}};
    Json roles = Json::object();

    for (const auto &row :
         std::vector<std::array<std::string, 3>>{{"hyp_la.img", "hyp", "ota/hyp"},
                                                 {"ifs2_la.img", "ifs", "ota/ifs"},
                                                 {"system_la.img", "sys", "ota/system"},
                                                 {"ifs2_recovery_la.img", "rec", "ota/recovery"}}) {
        roles[row[0]] = {{"file", row[0]},
                         {"bytes", 3u},
                         {"sha256", sha256_bytes(row[1])},
                         {"acquisition", {{"kind", "raw-tar-member"}, {"member", row[2]}}}};
    }

    const Json qnx = {{"schema", 1},
                      {"originals", roles},
                      {"update",
                       {{"container", "zip-stored-tgz"},
                        {"sha256", owner.at("sha256")},
                        {"nested_member", "update.tgz"},
                        {"nested_sha256", owner.at("inner").at("sha256")}}}};
    const Json definition = {
            {"schema", 1},
            {"status", "incomplete"},
            {"android",
             {{"url", "https://dl.google.com/android/repository/sys-img/android/fixture.zip"},
              {"sha256", sha256_bytes("archive")}}},
            {"original",
             {{"own",
               {{"file", "own.jar"},
                {"bytes", 6u},
                {"sha256", sha256_bytes("native")},
                {"acquisition", {{"image", "system"}, {"path", "/system/own"}}}}}}},
            {"ownerUpdate", owner},
            {"acquisition",
             {{"format", "pinned-zip-tgz-raw-scatter"},
              {"diff", false},
              {"qnxOriginals",
               Json::array({"hyp_la.img", "ifs2_la.img", "system_la.img", "ifs2_recovery_la.img"})},
              {"system", scatter}}}};
    const auto selected = root / "profiles/owner-sequence",
               destination = root / ".local/profiles/owner-sequence";
    write_private_json(selected / "profile.json", definition);
    write_private_json(selected / "profile-qnx.json", qnx);
    write_private_json(selected / "capture.json", {{"schema", 1}});
    ensure_private_directory(root / ".local/toolchains/downloads/native");
    {
        std::ofstream out(root / ".local/toolchains/downloads/native" /
                          (sha256_bytes("archive") + ".blob"));
        out << "archive";
    }

    for (const auto *key : {"key", "cert"}) {
        const auto pin = embedded_toolchain_manifest()
                                 .at("signing")
                                 .at("platform")
                                 .at(key)
                                 .at("sha256")
                                 .get<std::string>();
        const auto source = project / ".local/toolchains/downloads/native" / (pin + ".blob");
        check(sha256_file(source) == pin, "existing pinned public signing fixture differs");
        std::filesystem::copy_file(source,
                                   root / ".local/toolchains/downloads/native" / (pin + ".blob"));
    }

    const auto imported = fetch_native_inputs(root, "owner-sequence", true, "", 0, {}, zip);
    const auto &acquired = imported.at("owner_update");
    const auto owner_proof = read_private_json(destination / "owner-inputs.json");
    check(!acquired.contains("profile_sha256") && !acquired.contains("qnx_profile_sha256") &&
                  !owner_proof.contains("profile_sha256") &&
                  !owner_proof.contains("qnx_profile_sha256"),
          "update fetch must not pin its authoring profiles");
    check(imported.at("owner_inputs_sha256") == sha256_file(destination / "owner-inputs.json"),
          "update fetch creates verified owner binding");
    const auto old_id = cache_file_identity(destination / "originals/own.jar"),
               owner_id = cache_file_identity(destination / "owner-inputs.json");
    const auto ordinary = fetch_native_inputs(root, "owner-sequence", true, "", 0);

    for (unsigned fault = 0; fault < 2; ++fault) {
        auto altered = acquired;

        if (fault == 0) {
            altered.erase("qnx");
        } else {
            altered["qnx"]["files"][0]["sha256"] = std::string(64, '0');
        }

        auto result = ordinary;
        bool denied = false;
        try {
            fetch_detail::bind_owner_inputs(root, "owner-sequence", definition, altered, result);
        } catch (const std::exception &error) {
            denied = std::string(message_code(error.what())) == "FETCH_UPDATE";
        }

        check(denied && cache_file_identity(destination / "owner-inputs.json") == owner_id,
              "a valid retained owner must not validate missing or inconsistent import QNX data");
    }

    check(ordinary.contains("owner_inputs_sha256") &&
                  ordinary.at("owner_inputs_sha256") ==
                          sha256_file(destination / "owner-inputs.json") &&
                  ordinary.at("frame_verified") == false,
          "ordinary offline fetch dropped verified acquisition binding");
    check(fetch_native_inputs(root, "owner-sequence", true, "", 0, {}, zip)
                                  .at("owner_inputs_sha256") ==
                          ordinary.at("owner_inputs_sha256") &&
                  cache_file_identity(destination / "originals/own.jar") == old_id &&
                  cache_file_identity(destination / "owner-inputs.json") == owner_id,
          "update ordinary cached-update sequence preserves acquired inputs");
    auto targeted = definition;
    targeted["id"] = "owner-sequence";
    targeted["android"]["package"] = "system-images;android-30;default;arm64-v8a";
    targeted["targets"] = {{"arm", {{"guestAbi", "arm64-v8a"}, {"preparation", "sdk"}}},
                           {"x86",
                            {{"guestAbi", "x86_64"},
                             {"preparation", "sdk"},
                             {"androidBase", "owner-sequence-x86"},
                             {"emulator", {{"acceleration", "required"}, {"gpuMode", "host"}}}}}};
    write_private_json(selected / "profile.json", targeted);
    const auto x86_pin = sha256_bytes("x86-archive");
    write_private_json(root / "profiles/common/android-bases/owner-sequence-x86.json",
                       {{"package", "system-images;android-30;default;x86_64"},
                        {"url", targeted.at("android").at("url")},
                        {"sha256", x86_pin},
                        {"clean_base", Json::object()}});
    {
        std::ofstream out(root / ".local/toolchains/downloads/native" / (x86_pin + ".blob"));
        out << "x86-archive";
    }
    const auto owner_inventory_pin = sha256_file(destination / "native-inputs.json");
    const auto x86 = fetch_native_inputs(root, "owner-sequence", true, "", 0, {}, {}, "x86");
    check(x86.at("android_archive").at("sha256") == x86_pin && x86.contains("qnx") &&
                  sha256_file(destination / "native-inputs.json") == owner_inventory_pin &&
                  fetch_native_inputs(root, "owner-sequence", true, "", 0, {}, zip)
                                  .at("owner_update")
                                  .at("cached") == true,
          "preparing x86 leaves the shared owner import reusable");
    const auto arm = fetch_native_inputs(root, "owner-sequence", true, "", 0, {}, {}, "arm");
    check(arm.at("android_archive").at("sha256") == definition.at("android").at("sha256") &&
                  arm.contains("qnx") &&
                  fetch_native_inputs(root, "owner-sequence", true, "", 0, {}, zip)
                                  .at("owner_update")
                                  .at("cached") == true &&
                  cache_file_identity(destination / "owner-inputs.json") == owner_id,
          "preparing ARM publishes the shared receipt and leaves the import reusable");
    write_private_json(selected / "profile.json", definition);
    const std::string aar(1024 * 1024 + 1, 'A');
    const auto aar_sha = sha256_bytes(aar);
    ensure_private_directory(root / ".local/toolchains/downloads/sources");
    {
        std::ofstream out(root / ".local/toolchains/downloads/sources" / aar_sha, std::ios::binary);
        out << aar;
    }
    auto with_component = definition;
    with_component["components"] = {{"gallery", "components/gallery"}};
    write_private_json(selected / "profile.json", with_component);
    const auto component_file = selected / "components/gallery/component.json";
    const Json archive_pin = {{"kind", "archive"},
                              {"format", "aar"},
                              {"url", "https://example.org/pinned.aar"},
                              {"sha256", aar_sha},
                              {"bytes", aar.size()}};
    auto select_pin = [&](const Json &pin) {
        write_private_json(component_file, {{"externalSources", {{"ijk.aar", pin}}}});
    };
    select_pin(archive_pin);
    const auto typed = fetch_native_inputs(root, "owner-sequence", true, "", 0);
    check(typed.at("external_sources").at("files") == 1,
          "typed cached AAR above legacy 1 MiB must pass through real fetch");
    std::filesystem::remove(root / ".local/toolchains/downloads/sources" / aar_sha);
    {
        std::ofstream blob(root / ".local/toolchains/downloads/native" / (aar_sha + ".blob"),
                           std::ios::binary);
        blob << aar;
    }
    check(fetch_native_inputs(root, "owner-sequence", true, "", 0)
                                  .at("external_sources")
                                  .at("files") == 1 &&
                  std::filesystem::file_size(root / ".local/toolchains/downloads/sources" /
                                             aar_sha) == aar.size(),
          "source-cache miss materializes exact typed archive through production downloader cache offline");
    const auto published_typed = contents(destination / "native-inputs.json");

    for (unsigned fault = 0; fault < 17; ++fault) {
        auto pin = archive_pin;

        if (fault == 0) {
            pin.erase("kind");
        }

        if (fault == 1) {
            pin["kind"] = "source";
        }

        if (fault == 2) {
            pin.erase("format");
        }

        if (fault == 3) {
            pin["format"] = "zip";
        }

        if (fault == 4) {
            pin["bytes"] = 0u;
        }

        if (fault == 5) {
            pin["bytes"] = -1;
        }

        if (fault == 6) {
            pin["bytes"] = 1.5;
        }

        if (fault == 7) {
            pin["bytes"] = 16ULL * 1024 * 1024 + 1;
        }

        if (fault == 8) {
            pin["bytes"] = aar.size() + 1;
        }

        if (fault == 9) {
            pin["sha256"] = std::string(64, 'f');
        }

        if (fault == 10) {
            pin["url"] = "http://example.org/pinned.aar";
        }

        if (fault == 11) {
            pin["extra"] = true;
        }

        if (fault == 12) {
            pin["url"] = "https:///empty";
        }

        if (fault == 13) {
            pin["url"] = "https://user@example.org/file.aar";
        }

        if (fault == 14) {
            pin["url"] = "https://example.org/file.aar#fragment";
        }

        if (fault == 15) {
            pin["url"] = "https://example.org/a b";
        }

        if (fault == 16) {
            pin["bytes"] = 18446744073709551615ULL;
        }

        select_pin(pin);
        bool denied = false;
        try {
            fetch_native_inputs(root, "owner-sequence", true, "", 0);
        } catch (...) {
            denied = true;
        }

        check(denied && contents(destination / "native-inputs.json") == published_typed,
              "typed archive negative must preserve previous receipt");
    }

    write_private_json(selected / "profile.json", definition);
    std::filesystem::remove(component_file);
    fetch_native_inputs(root, "owner-sequence", true, "", 0);
    std::cout
            << "Typed cached AAR >1MiB PASS; 17 typed/legacy extent/offline/schema negatives PASS\n";
    const auto original_owner = read_private_json(destination / "owner-inputs.json");
    const auto published = contents(destination / "native-inputs.json");

    for (unsigned fault = 0; fault < 6; ++fault) {
        auto bad = original_owner;

        if (fault == 0) {
            bad["profile"] = "foreign";
        }

        if (fault == 1) {
            bad["frame_verified"] = true;
        }

        if (fault == 2) {
            bad["acquisition_sha256"] = std::string(64, 'f');
        }

        if (fault == 3) {
            bad["originals"]["files"][0]["sha256"] = std::string(64, 'f');
        }

        if (fault == 4) {
            bad["qnx"]["files"][0]["sha256"] = std::string(64, 'f');
        }

        if (fault == 5) {
            bad["ext4_receipt_sha256"] = std::string(64, 'f');
        }

        write_private_json(destination / "owner-inputs.json", bad);
        bool denied = false;
        try {
            fetch_native_inputs(root, "owner-sequence", true, "", 0);
        } catch (...) {
            denied = true;
        }

        check(denied && contents(destination / "native-inputs.json") == published,
              "ordinary owner binding refusal must preserve previous receipt");
    }

    write_private_json(destination / "owner-inputs.json", original_owner);
    std::cout
            << "update -> ordinary offline -> cached update owner binding, six no-publication negatives PASS\n";
}
#endif

static void owner_binding_capabilities(const std::filesystem::path &root) {
    const Json originals = {{"verified", true}, {"inputs_sha256", sha256_bytes("originals")}};
    const Json imported = {{"source", "owner-update"}, {"originals", originals}};
    Json multimedia = {{"originals", originals}, {"native", true}};

    fetch_detail::bind_owner_inputs(root, "media-only", Json::object(), imported, multimedia);
    check(!multimedia.contains("owner_inputs_sha256"),
          "multimedia-only import must not claim a QNX owner binding");

    auto declare = [&](const std::string &profile) {
        const auto config = root / "profiles" / profile / "profile-qnx.json";
        ensure_private_directory(config.parent_path());
        write_private_json(config, Json::object());
    };
    declare("segmented");
    Json segmented = multimedia;
    segmented["qnx"] = {{"files", Json::array()}, {"verified", true}};
    const Json segmented_definition = {
            {"acquisition", {{"format", "pinned-zip-zero-base-zstd-segments"}}}};
    fetch_detail::bind_owner_inputs(root, "segmented", segmented_definition, imported, segmented);
    check(!segmented.contains("owner_inputs_sha256"),
          "segmented import without a generic owner must retain its own verified inputs");

    declare("generic");
    const Json generic_definition = {{"acquisition", {{"format", "pinned-zip-tgz-raw-scatter"}}}};
    auto rejected = [&](const std::string &profile, const Json &definition, const Json &proof,
                        Json result) {
        try {
            fetch_detail::bind_owner_inputs(root, profile, definition, proof, result);
        } catch (const std::exception &error) {
            return std::string(message_code(error.what()));
        }

        return std::string{};
    };
    auto generic_import = imported;
    generic_import["qnx"] = segmented.at("qnx");
    check(rejected("generic", generic_definition, generic_import, segmented) == "QUICKBOOT_FILE",
          "generic QNX import requires its owner proof");
    check(rejected("generic", generic_definition, imported, segmented) == "FETCH_UPDATE",
          "generic QNX import cannot omit its imported QNX data");
    check(rejected("generic", generic_definition, imported, multimedia) == "FETCH_UPDATE",
          "declared QNX capability cannot disappear from verified results");
    check(rejected("undeclared", generic_definition, imported, segmented) == "FETCH_UPDATE",
          "an output field cannot invent a declared QNX capability");

#ifndef _WIN32
    const auto owner = root / ".local/profiles/segmented/owner-inputs.json";
    ensure_private_directory(owner.parent_path());
    std::filesystem::create_symlink(root / "absent-owner", owner);
    check(rejected("segmented", segmented_definition, Json(), segmented) == "FETCH_PATH",
          "retained owner symlinks remain rejected");
    std::filesystem::remove(owner);
    const auto linked = root / "profiles/linked/profile-qnx.json";
    ensure_private_directory(linked.parent_path());
    std::filesystem::create_symlink(root / "absent-qnx", linked);
    check(rejected("linked", segmented_definition, imported, segmented) == "FETCH_PATH",
          "a linked QNX capability is not an absent capability");
#endif
}

int main(int argc, char **argv) {
    try {
        if (argc == 3 && std::string_view(argv[1]) == "--nxp-voice-plan") {
            const auto profile = read_private_json(argv[2], 512 * 1024);
            const auto plan = nxp_acquisition_plan(profile);
            unsigned resource = 0;
            std::string first;

            for (auto it = profile.at("original").begin(); it != profile.at("original").end();
                 ++it) {
                if (it.value().at("acquisition").at("image") == "resource") {
                    ++resource;

                    if (first.empty()) {
                        first = it.key();
                    }
                }
            }

            check(resource >= 215 && plan.at("originals").size() > 256 &&
                          plan.at("originals").size() <= 512,
                  "NXP Voice actual resource and expanded source plan required");
            check(plan.at("system_batches").size() >= 2,
                  "NXP retained system inputs exceed one generic extraction batch");
            unsigned vendor = 0;

            for (const auto &row : plan.at("originals")) {
                if (row.at("image") == "vendor") {
                    ++vendor;

                    for (const auto &batch : plan.at("system_batches")) {
                        check(std::find(batch.begin(), batch.end(), row.at("path")) == batch.end(),
                              "NXP vendor original stays out of the system batches");
                    }
                }
            }

            check(vendor == 2,
                  "NXP vendor SELinux policy and HiCar acquired from the vendor image");
            auto outside = profile;
            outside["original"]["VendorSepolicy"]["acquisition"]["path"] =
                    "/system/etc/selinux/vendor_sepolicy.cil";
            outside["original"]["VendorSepolicy"]["source"]["path"] =
                    "/system/etc/selinux/vendor_sepolicy.cil";
            bool rejected = false;
            try {
                (void)nxp_acquisition_plan(outside);
            } catch (const std::runtime_error &) {
                rejected = true;
            }

            check(rejected, "NXP vendor original outside /vendor rejected");

            for (const auto &batch : plan.at("system_batches")) {
                std::uint64_t bytes = 0;
                check(!batch.empty() && batch.size() <= 256, "System batch path count bound");

                for (const auto &path : batch) {
                    for (const auto &row : plan.at("originals")) {
                        if (row.at("image") == "system" && row.at("path") == path) {
                            bytes += row.at("bytes").get<std::uint64_t>();
                        }
                    }
                }

                check(bytes <= (512ULL << 20), "System batch byte bound");
            }

            for (unsigned boundary = 0; boundary < 4; ++boundary) {
                auto synthetic = profile;
                synthetic["original"] = Json::object();
                const unsigned count = boundary == 0   ? 2
                                       : boundary == 1 ? 3
                                       : boundary == 2 ? 256
                                                       : 257;

                for (unsigned i = 0; i < count; ++i) {
                    auto item = profile.at("original").at(first);
                    item["file"] = "batch/" + std::to_string(i);
                    item["bytes"] = boundary < 2 ? (256ULL << 20) : 1ULL;
                    item["source"] = {{"path", "/system/batch/" + std::to_string(i)}};
                    item["acquisition"] = {{"image", "system"},
                                           {"path", "/system/batch/" + std::to_string(i)}};
                    synthetic["original"]["batch-" + std::to_string(i)] = item;
                }

                const auto split = nxp_acquisition_plan(synthetic);
                check(split.at("system_batches").size() ==
                              (boundary == 0 || boundary == 2 ? 1u : 2u),
                      "Exact512MiB and256path extraction boundaries must split only after the limit");
            }

            // The plan follows the profile data, not its id.
            auto renamed = profile;
            renamed["id"] = "test-nxp";
            check(nxp_acquisition_plan(renamed).at("originals") == plan.at("originals"),
                  "NXP plan depends on the profile id");

            for (unsigned fault = 0; fault < 10; ++fault) {
                auto bad = profile;
                auto &item = bad["original"][first];

                if (fault == 0) {
                    bad["acquisition"]["format"] = "pinned-zip-tgz-raw-scatter";
                }

                if (fault == 1) {
                    item["acquisition"]["image"] = "vendor";
                }

                if (fault == 2) {
                    item["acquisition"]["path"] = "/resc_qgspeech/../outside";
                }

                if (fault == 3) {
                    item["source"]["path"] = "/resc/resc_qgspeech/aispeech/foreign";
                }

                if (fault == 4) {
                    item["bytes"] = 0u;
                }

                if (fault == 5) {
                    item["bytes"] = 0.5;
                }

                if (fault == 6) {
                    item["acquisition"]["path"] = "/resc_qgspeech/aispeech//foreign";
                }

                if (fault == 7) {
                    auto extra = item;

                    for (unsigned i = 0; i < 513; ++i) {
                        extra["file"] = "bound/" + std::to_string(i);
                        extra["source"]["path"] = "/resc/resc_qgspeech/aispeech/bound/" +
                                                  std::to_string(i);
                        extra["acquisition"]["path"] = "/resc_qgspeech/aispeech/bound/" +
                                                       std::to_string(i);
                        bad["original"]["bound-" + std::to_string(i)] = extra;
                    }
                }

                if (fault == 8) {
                    item["bytes"] = (256ULL << 20) + 1;
                }

                if (fault == 9) {
                    bad["board"] = "8155";
                }

                bool rejected = false;
                try {
                    nxp_acquisition_plan(bad);
                } catch (...) {
                    rejected = true;
                }

                check(rejected,
                      "NXP Voice foreign image/format/board, traversal, mapping, extent, alias and count negatives rejected");
            }

            std::cout
                    << "NXP Voice owner acquisition plan PASS: actual system/resource mapping and expanded bounded originals; ten negatives plus exact extraction batch bounds; no archive expansion or guest\n";

            return 0;
        }

        if (argc == 4 && std::string_view(argv[1]) == "--qinggan11-segmented-plan") {
            const auto root = std::filesystem::canonical(argv[2]);
            const auto source = std::filesystem::path(argv[3]);
            const auto id = source.parent_path().filename().string();
            const auto profile = read_private_json(source, 512 * 1024),
                       qnx = read_private_json(source.parent_path() / "profile-qnx.json",
                                               128 * 1024);
            const auto plan = segmented_acquisition_plan(profile, qnx);
            check(!declared_patch_plan(profile).at("patches").empty(),
                  "acquired profile patch graph rejected");
            check(qinggan11_wheel_capability(profile).at("supported") == true,
                  "acquired profile wheel graph rejected");

            for (const auto &row : plan.at("originals")) {
                const auto file = root / ".local/profiles" / id / "originals" /
                                  row.at("file").get<std::string>();
                check(std::filesystem::file_size(file) == row.at("bytes") &&
                              sha256_file(file) == row.at("sha256").get<std::string>(),
                      "declared original pin/extent differs from retained OEM input");
            }

            for (unsigned fault = 0; fault < 19; ++fault) {
                auto bad = profile, badq = qnx;

                if (fault == 0) {
                    badq["hardware_adapter"] = qnx.at("hardware_adapter") == "sa8155-qinggan11-731"
                                                       ? "sa8155-qinggan11-611"
                                                       : "sa8155-qinggan11-731";
                }

                if (fault == 1) {
                    bad["ownerUpdate"]["sha256"] = std::string(64, '0');
                }

                if (fault == 2) {
                    bad["ownerUpdate"]["bytes"] = -1;
                }

                if (fault == 3) {
                    bad["acquisition"]["diff"] = true;
                }

                if (fault == 4) {
                    bad["acquisition"]["images"]["system"]["sha256"] = "not-a-sha256";
                }

                if (fault == 5) {
                    std::swap(bad["acquisition"]["images"]["system"]["update"]["entries"][0],
                              bad["acquisition"]["images"]["system"]["update"]["entries"][1]);
                }

                if (fault == 6) {
                    bad["acquisition"]["images"]["system"]["update"]["segment_bytes"][0] = 1u;
                }

                if (fault == 7) {
                    bad["original"]["Launcher"]["bytes"] = (512ULL << 20) + 1;
                }

                if (fault == 8) {
                    bad["original"]["Launcher"]["acquisition"]["path"] = "/system/../foreign.apk";
                }

                if (fault == 9) {
                    bad["original"]["Launcher"]["acquisition"]["image"] = "foreign";
                }

                if (fault == 10) {
                    badq["originals"]["hyp_la.img"]["file"] = "../foreign";
                }

                if (fault == 11) {
                    badq["originals"]["hyp_la.img"]["sha256"] = std::string(64, '0');
                }

                if (fault == 12) {
                    badq["originals"]["system_la.img"]["update"]["segment_bytes"][0] = 1u;
                }

                if (fault == 13) {
                    bad["original"]["Launcher"]["bytes"] = 126653880.5;
                }

                if (fault == 14) {
                    bad["acquisition"]["images"]["system"]["bytes"] = 4294967296.0;
                }

                if (fault == 15) {
                    bad["acquisition"]["images"]["system"]["update"]["segment_bytes"][0] =
                            536870912.0;
                }

                if (fault == 16) {
                    bad["original"]["Launcher"]["acquisition"]["path"] = "/system//file.apk";
                }

                if (fault == 17) {
                    bad["original"]["Launcher"]["acquisition"]["path"] = "/system/file.apk/";
                }

                if (fault == 18) {
                    badq["originals"]["system_la.img"]["update"]["segment_bytes"][0] = 536870912.0;
                }

                bool denied = false;
                try {
                    segmented_acquisition_plan(bad, badq);
                } catch (...) {
                    denied = true;
                }

                check(denied, "segmented acquisition plan negative accepted");
            }

            std::cout << Json{{"plan", plan},
                              {"original_files_verified", plan.at("originals").size()},
                              {"negative_cases", 19},
                              {"guest_started", false},
                              {"source_images_rebuilt", false}}
                                 .dump(2)
                      << '\n';

            return 0;
        }

#ifdef __APPLE__
        if (argc == 3 && std::string_view(argv[1]) == "--owner-fetch-sequence") {
            owner_fetch_sequence(std::filesystem::canonical(argv[2]));

            return 0;
        }
#endif

        if (argc == 5 && std::string_view(argv[1]) == "--import-update") {
            std::cout << import_owner_profile_inputs(std::filesystem::canonical(argv[2]), argv[3],
                                                     std::filesystem::path(argv[4]), 40ULL << 30)
                                 .dump(2)
                      << '\n';

            return 0;
        }

        const Json apk = {{"file", "app.apk"},
                          {"sha256", sha256_bytes("app")},
                          {"source", {{"package", "com.example.fixture"}}}};
        const Json tree = {{"file", "framework"},
                           {"type", "tree"},
                           {"sha256", {{"one.jar", sha256_bytes("one")}}},
                           {"source", {{"path", "/system/framework"}}}};
        const Json image = {
                {"url", "https://dl.google.com/android/repository/sys-img/android/fixture.zip"},
                {"sha256", sha256_bytes("archive")}};
        const Json definition = {
                {"schema", 1}, {"android", image}, {"original", {{"apk", apk}, {"tree", tree}}}};
        const auto inputs = original_input_plan(definition);
        check(inputs.size() == 2 && inputs[0].package == "com.example.fixture" &&
                      inputs[1].remote == "/system/framework/one.jar",
              "closed package and per-file tree source plan");
        const auto qinggan09 =
                embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);
        const auto qinggan09_inputs =
                original_input_plan(embedded_profile(qinggan09).at("definition"));
        check(qinggan09_inputs.size() == 117,
              "first vehicle declares 117 exact Android inputs with the stock launcher apps and CAN service");
        check(std::count_if(qinggan09_inputs.begin(), qinggan09_inputs.end(),
                            [](const auto &input) {
                                return input.name == "CanBusService" &&
                                       input.file == "CanBusService-release.apk" &&
                                       input.package == "com.qinggan.canbus.service" &&
                                       input.remote.empty();
                            }) == 1,
              "the drive mode fixture takes the exact OEM CAN service APK");

        for (const auto &[role, name] :
             {std::pair{"FontRobotoRegular", "Roboto-Regular.ttf"},
              std::pair{"FontRobotoMedium", "Roboto-Medium.ttf"},
              std::pair{"FontRobotoBold", "Roboto-Bold.ttf"},
              std::pair{"FontDfpRegular", "HuaKangJinGangHei-Regular-2.ttf"},
              std::pair{"FontDfpSemibold", "DFPKingGothicGB-Semibold-2.ttf"}}) {
            check(std::count_if(qinggan09_inputs.begin(), qinggan09_inputs.end(),
                                [&](const auto &input) {
                                    return input.name == role &&
                                           input.file == std::string("fonts/") + name &&
                                           input.remote == std::string("/system/fonts/") + name &&
                                           input.package.empty();
                                }) == 1,
                  "first vehicle imports each required OEM font from its exact system path");
        }

        for (unsigned mode = 0; mode < 6; ++mode) {
            auto bad = definition;

            if (mode == 0) {
                bad["original"]["apk"]["file"] = "../escape";
            }

            if (mode == 1) {
                bad["original"]["apk"]["sha256"] = "unpinned";
            }

            if (mode == 2) {
                bad["original"]["duplicate"] = bad["original"]["apk"];
            }

            if (mode == 3) {
                bad["original"]["tree"]["source"]["path"] = "/system/../../data";
            }

            if (mode == 4) {
                bad["original"]["apk"]["source"]["package"] = "com.example;reboot";
            }

            if (mode == 5) {
                bad["original"]["apk"]["file"] = "framework";
            }

            bool rejected = false;
            try {
                original_input_plan(bad);
            } catch (...) {
                rejected = true;
            }

            check(rejected, "unsafe missing or ambiguous input declarations rejected");
        }

        const auto root = std::filesystem::canonical(std::filesystem::path(__FILE__))
                                  .parent_path()
                                  .parent_path()
                                  .parent_path()
                                  .parent_path() /
                          ".local/build/tmp" / ("voyemu-fetch-" + random_token());
        ensure_private_directory(root);
        struct Cleanup {
            std::filesystem::path path;

            ~Cleanup() {
                std::filesystem::remove_all(path);
            }
        } cleanup{root};
        owner_binding_capabilities(root / "owner-boundary");
        const auto originals = root / ".local/profiles/fixture/originals";
        ensure_private_directory(originals / "framework");
        {
            std::ofstream out(originals / "app.apk");
            out << "app";
        }
        {
            std::ofstream out(originals / "framework/one.jar");
            out << "one";
        }
        const auto verified = verify_original_inputs(root, "fixture", inputs);
        check(verified.at("verified") == true && verified.at("files") == 2 &&
                      verified.at("bytes") == 6,
              "exact input hashes and extents verified");
        const auto source = root / "profiles/fixture/profile.json";
        write_private_json(source, definition);
        bool offline = false;
        try {
            fetch_native_inputs(root, "fixture", true, "", 0);
        } catch (const std::exception &error) {
            offline = std::string_view(error.what()).starts_with("DOWNLOAD_OFFLINE:");
        }

        check(offline &&
                      !std::filesystem::exists(root / ".local/profiles/fixture/native-inputs.json"),
              "offline misses cannot publish false-ready receipt");

        const auto clone_profile = root / "profiles/local-copy/profile.json";
        auto clone = definition;
        clone["id"] = "local-copy";
        clone["capture"] = {{"profile", "local-copy"}, {"referenceProfile", "fixture"}};
        write_private_json(clone_profile, clone);
        check(profile_originals_directory(root, "local-copy") == originals &&
                      verify_original_inputs(root, "local-copy", inputs) == verified,
              "logical clone reads exact canonical originals without copying");
        bool clone_offline = false;
        try {
            fetch_native_inputs(root, "local-copy", true, "", 0);
        } catch (const std::exception &error) {
            clone_offline = std::string_view(error.what()).starts_with("DOWNLOAD_OFFLINE:");
        }

        check(clone_offline && !std::filesystem::exists(root / ".local/profiles/local-copy"),
              "clone fetch reaches dependencies without private OEM copies or false receipts");
        auto bad_clone = clone;
        bad_clone["capture"]["referenceProfile"] = "../foreign";
        write_private_json(clone_profile, bad_clone);
        bool bad_ref = false;
        try {
            profile_originals_directory(root, "local-copy");
        } catch (...) {
            bad_ref = true;
        }

        check(bad_ref, "foreign reference path rejected");
        bad_clone = clone;
        bad_clone["original"].begin().value()["sha256"] = std::string(64, '0');
        write_private_json(clone_profile, bad_clone);
        bool bad_map = false;
        try {
            profile_originals_directory(root, "local-copy");
        } catch (...) {
            bad_map = true;
        }

        check(bad_map, "different declared original pins rejected");
        write_private_json(clone_profile, clone);
        const auto retained_file = originals / "app.apk", saved_file = originals / "app.saved";
        std::filesystem::rename(retained_file, saved_file);
        bool missing_reference = false;
        try {
            profile_originals_directory(root, "local-copy");
        } catch (...) {
            missing_reference = true;
        }

        check(missing_reference, "missing shared input fails instead of filling shared directory");
        std::filesystem::create_symlink(saved_file, retained_file);
        bool linked_reference = false;
        try {
            profile_originals_directory(root, "local-copy");
        } catch (...) {
            linked_reference = true;
        }

        check(linked_reference, "linked canonical input rejected");
        std::filesystem::remove(retained_file);
        std::filesystem::rename(saved_file, retained_file);
        const auto private_originals = root / ".local/profiles/local-copy/originals";
        ensure_private_directory(private_originals);
        check(profile_originals_directory(root, "local-copy") == private_originals,
              "private originals take precedence");
        bool private_missing = false;
        try {
            verify_original_inputs(root, "local-copy", inputs);
        } catch (...) {
            private_missing = true;
        }

        check(private_missing, "incomplete private originals never silently fall back");
        std::filesystem::remove(private_originals);
        std::filesystem::remove(private_originals.parent_path());
        bool conflicting = false;
        try {
            fetch_native_inputs(root, "fixture", false, "vehicle", 0, {}, root / "owner.zip");
        } catch (const std::exception &error) {
            conflicting = std::string_view(error.what()).starts_with("FETCH_UPDATE:");
        }

        check(conflicting, "update/serial rejected before acquisition");
        bool relative = false;
        try {
            import_owner_profile_inputs(root, "fixture", "owner.zip", 0);
        } catch (const std::exception &error) {
            relative = std::string_view(error.what()).starts_with("FETCH_UPDATE:");
        }

        check(relative, "relative update rejected");
#ifdef __APPLE__
        const auto raw = filesystem_fixture(), first = raw.substr(0, 4096),
                   second = raw.substr(4096);
        const auto tgz = root / "owner.tgz", zip = root / "owner.zip";
        const auto vendor = filesystem_fixture(true);
        archive_fixture(tgz,
                        {{"ota/second", second},
                         {"ota/qnx", "raw"},
                         {"ota/first", first},
                         {"ota/vendor", vendor}},
                        false);
        archive_fixture(zip, {{"update.tgz", contents(tgz)}}, true);
        const Json owner = {{"bytes", std::filesystem::file_size(zip)},
                            {"sha256", sha256_file(zip)},
                            {"inner",
                             {{"file", "update.tgz"},
                              {"bytes", std::filesystem::file_size(tgz)},
                              {"sha256", sha256_file(tgz)}}}};
        const Json scatter = {{"bytes", raw.size()},
                              {"sha256", sha256_bytes(raw)},
                              {"segments", Json::array({{{"member", "ota/first"},
                                                         {"offset", 0u},
                                                         {"bytes", first.size()},
                                                         {"sha256", sha256_bytes(first)}},
                                                        {{"member", "ota/second"},
                                                         {"offset", 4096u},
                                                         {"bytes", second.size()},
                                                         {"sha256", sha256_bytes(second)}}})}};
        Json local = {{"schema", 1},
                      {"status", "incomplete"},
                      {"android", image},
                      {"original",
                       {{"own",
                         {{"file", "framework/old.jar"},
                          {"bytes", 6u},
                          {"sha256", sha256_bytes("native")},
                          {"acquisition", {{"image", "system"}, {"path", "/system/own"}}}}}}},
                      {"ownerUpdate", owner},
                      {"acquisition",
                       {{"format", "pinned-zip-tgz-raw-scatter"},
                        {"diff", false},
                        {"implemented", false},
                        {"qnxOriginals", Json::array({"role.img"})},
                        {"system", scatter}}}};
        const Json qnx = {
                {"schema", 1},
                {"originals",
                 {{"role.img",
                   {{"file", "role.img"},
                    {"bytes", 3u},
                    {"sha256", sha256_bytes("raw")},
                    {"acquisition", {{"kind", "raw-tar-member"}, {"member", "ota/qnx"}}}}}}},
                {"update",
                 {{"container", "zip-stored-tgz"},
                  {"sha256", owner.at("sha256")},
                  {"nested_member", "update.tgz"},
                  {"nested_sha256", owner.at("inner").at("sha256")}}}};
        const std::string passion = "test-passion";
        auto vendor_definition = local;
        vendor_definition["platform"] = "passion";
        vendor_definition["android"]["package"] = "system-images;android-30;default;arm64-v8a";
        vendor_definition["acquisition"]["vendor"] = scatter;
        vendor_definition["original"]["LY_Car"] = {
                {"file", "LY_Car.apk"},
                {"bytes", 6u},
                {"sha256", sha256_bytes("native")},
                {"source", {{"package", "com.voyah.car"}}},
                {"acquisition", {{"image", "vendor"}, {"path", "/vendor/app/LY_Car/LY_Car.apk"}}}};

        for (unsigned mode = 0; mode < 9; ++mode) {
            auto requested = vendor_definition;

            if (mode == 0) {
                requested["android"]["package"] = "system-images;android-28;default;arm64-v8a";
            }

            if (mode == 1) {
                requested["original"]["LY_Car"]["acquisition"]["image"] = "unknown";
            }

            if (mode == 2) {
                requested["original"]["LY_Car"]["acquisition"]["path"] =
                        "/vendor/../app/LY_Car/LY_Car.apk";
            }

            if (mode == 3) {
                requested["original"]["LY_Car"]["source"] = {
                        {"path", "/vendor/app/LY_Car/LY_Car.apk"}};
            }

            if (mode == 4) {
                requested["acquisition"]["vendor"]["sha256"] = std::string(64, 'f');
            }

            if (mode == 5) {
                requested["platform"] = "qinggan11";
            }

            if (mode == 6) {
                requested["acquisition"].erase("qnxOriginals");
            }

            // A vendor library is declared by its own path.
            if (mode == 7) {
                requested["original"]["MessageCenterRpc"] = {
                        {"file", "message-center/libmrpc.so"},
                        {"bytes", 6u},
                        {"sha256", sha256_bytes("native")},
                        {"source", {{"package", "com.voyah.car"}}},
                        {"acquisition",
                         {{"image", "vendor"}, {"path", "/vendor/lib64/libmrpc.so"}}}};
            }

            if (mode == 8) {
                requested["original"]["LY_Car"]["acquisition"]["path"] =
                        "/vendor/app/LY_Other/LY_Car.apk";
            }

            write_private_json(root / "profiles" / passion / "profile.json", requested);
            write_private_json(root / "profiles" / passion / "profile-qnx.json", qnx);
            bool denied = false;
            try {
                import_owner_profile_inputs(root, passion, zip, 0);
            } catch (...) {
                denied = true;
            }

            check(denied && !std::filesystem::exists(root / ".local/profiles" / passion),
                  "finite vendor acquisition rejects foreign application directories, libraries without their path and other invalid inputs before publication");
        }

        auto vendor_apps = vendor_definition;
        vendor_apps["acquisition"]["vendor"] = {
                {"bytes", vendor.size()},
                {"sha256", sha256_bytes(vendor)},
                {"segments", Json::array({{{"member", "ota/vendor"},
                                           {"offset", 0u},
                                           {"bytes", vendor.size()},
                                           {"sha256", sha256_bytes(vendor)}}})}};
        vendor_apps["original"].erase("LY_Car");
        vendor_apps["original"]["LY_Multimedia"] = {
                {"file", "LY_Multimedia.apk"},
                {"bytes", 5u},
                {"sha256", sha256_bytes("music")},
                {"source", {{"package", "com.voyah.multimedia"}}},
                {"acquisition",
                 {{"image", "vendor"}, {"path", "/vendor/app/LY_Multimedia/LY_Multimedia.apk"}}}};
        vendor_apps["original"]["Native"] = {
                {"file", "native"},
                {"bytes", 6u},
                {"sha256", sha256_bytes("native")},
                {"source", {{"path", "/vendor/native"}}},
                {"acquisition", {{"image", "vendor"}, {"path", "/vendor/native"}}}};
        const auto vendor_profile = root / "profiles/test-passion-vendor";
        write_private_json(vendor_profile / "profile.json", vendor_apps);
        write_private_json(vendor_profile / "profile-qnx.json", qnx);
        const auto vendor_observed = import_owner_profile_inputs(root, "test-passion-vendor", zip,
                                                                 0);
        const auto vendor_destination = root / ".local/profiles/test-passion-vendor/originals";
        check(vendor_observed.at("originals").at("verified") == true &&
                      contents(vendor_destination / "LY_Multimedia.apk") == "music" &&
                      contents(vendor_destination / "native") == "native",
              "vendor library and launcher APK batches publish one verified acquisition");

        auto media_definition = local;
        media_definition["platform"] = "passion";
        media_definition["android"]["package"] = "system-images;android-30;default;arm64-v8a";
        media_definition["original"]["LY_Camera"] = {
                {"file", "LY_Camera.apk"},
                {"bytes", 111142678u},
                {"sha256", "e0e57f7cd9099136541c3ed35e1042fba1762a13640bea7f6a2ac3415f426bf0"},
                {"source", {{"package", "com.voyah.camera"}}},
                {"acquisition",
                 {{"image", "system"}, {"path", "/system/app/LY_Camera/LY_Camera.apk"}}}};

        for (unsigned mode = 0; mode < 7; ++mode) {
            auto requested = media_definition;

            if (mode == 0) {
                requested["android"]["package"] = "system-images;android-28;default;arm64-v8a";
            }

            if (mode == 1) {
                requested["original"]["LY_Camera"]["sha256"] = std::string(64, 'f');
            }

            if (mode == 2) {
                requested["original"]["LY_Camera"]["acquisition"]["path"] =
                        "/system/app/../LY_Camera.apk";
            }

            if (mode == 3) {
                requested["original"]["LY_Camera"]["source"]["package"] = "foreign.package";
            }

            if (mode == 4) {
                requested["original"]["LY_Camera"]["bytes"] = 1u;
            }

            if (mode == 5) {
                requested["original"]["LY_Camera"]["acquisition"]["image"] = "vendor";
            }

            if (mode == 6) {
                requested["platform"] = "qinggan11";
            }

            write_private_json(root / "profiles" / passion / "profile.json", requested);
            write_private_json(root / "profiles" / passion / "profile-qnx.json", qnx);
            bool denied = false;
            try {
                import_owner_profile_inputs(root, passion, zip, 0);
            } catch (...) {
                denied = true;
            }

            check(denied && !std::filesystem::exists(root / ".local/profiles" / passion),
                  "finite media role rejects foreign API, pin, path, package, extent, partition and platform without publication");
        }

        auto screen_definition = local;
        screen_definition["platform"] = "passion";
        screen_definition["android"]["package"] = "system-images;android-30;default;arm64-v8a";
        const auto screen_roles = Json::parse(
                R"CSV({"screen-control-screen0_off_change":{"file":"screen0_off_change.csv","bytes":6111,"sha256":"7e82e683f773e0e300fe7e1f2c097381f0f94ff784d9705d350523f870081881","source":{"path":"/system/etc/screen-control/screen0_off_change.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen0_off_change.csv"}},"screen-control-screen0_off_keep":{"file":"screen0_off_keep.csv","bytes":6111,"sha256":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","source":{"path":"/system/etc/screen-control/screen0_off_keep.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen0_off_keep.csv"}},"screen-control-screen0_on_change":{"file":"screen0_on_change.csv","bytes":6111,"sha256":"dbfe5e0802173415484a1640ed3024a181843ad40d895320952db3a4d8a7bfff","source":{"path":"/system/etc/screen-control/screen0_on_change.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen0_on_change.csv"}},"screen-control-screen0_on_keep":{"file":"screen0_on_keep.csv","bytes":6111,"sha256":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","source":{"path":"/system/etc/screen-control/screen0_on_keep.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen0_on_keep.csv"}},"screen-control-screen1_off_change":{"file":"screen1_off_change.csv","bytes":6111,"sha256":"3aee3f501728d48de7a4c2a189fec04b1c9ddfb7898cd0dcc636129faa908ac0","source":{"path":"/system/etc/screen-control/screen1_off_change.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen1_off_change.csv"}},"screen-control-screen1_off_keep":{"file":"screen1_off_keep.csv","bytes":6111,"sha256":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","source":{"path":"/system/etc/screen-control/screen1_off_keep.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen1_off_keep.csv"}},"screen-control-screen1_on_change":{"file":"screen1_on_change.csv","bytes":6111,"sha256":"e2a2f3a83123cf347c7f0ec8cba58fa077e402b9a3317b36bec2225cbfb65f82","source":{"path":"/system/etc/screen-control/screen1_on_change.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen1_on_change.csv"}},"screen-control-screen1_on_keep":{"file":"screen1_on_keep.csv","bytes":6111,"sha256":"826ff8847dd688819344780bb67dea7cf6287622752ed02cd56d286ae28bf33f","source":{"path":"/system/etc/screen-control/screen1_on_keep.csv"},"acquisition":{"image":"system","path":"/system/etc/screen-control/screen1_on_keep.csv"}}})CSV");

        for (auto it = screen_roles.begin(); it != screen_roles.end(); ++it) {
            screen_definition["original"][it.key()] = it.value();
        }

        for (unsigned mode = 0; mode < 9; ++mode) {
            auto requested = screen_definition;
            const std::string key = "screen-control-screen0_off_change";

            if (mode == 0) {
                requested["android"]["package"] = "system-images;android-28;default;arm64-v8a";
            }

            if (mode == 1) {
                requested["original"].erase(key);
            }

            if (mode == 2) {
                requested["original"][key]["sha256"] = std::string(64, 'f');
            }

            if (mode == 3) {
                requested["original"][key]["bytes"] = 6110u;
            }

            if (mode == 4) {
                requested["original"][key]["acquisition"]["path"] =
                        "/system/etc/screen-control/../screen0_off_change.csv";
            }

            if (mode == 5) {
                requested["original"][key]["source"]["path"] = "/system/etc/foreign.csv";
            }

            if (mode == 6) {
                requested["original"][key]["file"] = "foreign.csv";
            }

            if (mode == 7) {
                requested["original"]["screen-control-foreign"] = requested["original"][key];
                requested["original"]["screen-control-foreign"]["file"] = "extra.csv";
            }

            if (mode == 8) {
                requested["platform"] = "qinggan11";
            }

            write_private_json(root / "profiles" / passion / "profile.json", requested);
            bool denied = false;
            try {
                import_owner_profile_inputs(root, passion, zip, 0);
            } catch (const std::exception &error) {
                denied = std::string_view(error.what()).find("screen-control") !=
                                 std::string_view::npos ||
                         mode == 4;

                if (!denied) {
                    std::cerr << "CSV_MODE " << mode << " ERROR " << error.what() << '\n';
                }
            }

            check(denied && !std::filesystem::exists(root / ".local/profiles" / passion),
                  "finite eight CSV role rejects API, partial group, pin, extent, traversal, source, name, extra role and platform before publication");
        }

        const auto selected = root / "profiles/archive-fixture";
        write_private_json(selected / "profile.json", local);
        write_private_json(selected / "profile-qnx.json", qnx);
        write_private_json(selected / "capture.json", {{"never", "device/Java must not run"}});
        const auto destination = root / ".local/profiles/archive-fixture";
        const auto host_inventory = [&] {
            Json inventory = Json::object();
            const auto tools = root / ".local/toolchains";

            if (std::filesystem::exists(tools)) {
                for (const auto &entry : std::filesystem::recursive_directory_iterator(tools)) {
                    check(!entry.is_symlink(), "ordinary host dependency fixture required");
                    const auto name = entry.path().lexically_relative(tools).generic_string();
                    inventory[name] =
                            entry.is_regular_file()
                                    ? Json{{"kind", "file"},
                                           {"sha256", sha256_file(entry.path())},
                                           {"identity", cache_file_identity(entry.path())}}
                                    : Json{{"kind", "directory"}};
                }
            }

            return inventory;
        };
        const auto host_before_import = host_inventory();
        // The import shows the system image it unpacks, the files extracted from it and the saved
        // originals with the QNX images.
        std::ostringstream console;
        auto *prior = std::cerr.rdbuf(console.rdbuf());
        progress::console(cli::Language::english, false);
        Json imported;
        try {
            imported = import_owner_profile_inputs(root, "archive-fixture", zip, 0);
        } catch (...) {
            std::cerr.rdbuf(prior);
            throw;
        }

        std::cerr.rdbuf(prior);
        const auto lines = console.str();
        const auto image_line = lines.find("\n\nAndroid system image ("),
                   extracted_line = lines.find("\n  Files extracted: ", image_line),
                   saved_line = lines.find("\n\nOriginals saved: ", extracted_line);
        check(image_line != std::string::npos && extracted_line != std::string::npos &&
                      saved_line != std::string::npos &&
                      lines.find(" QNX images in ", saved_line) != std::string::npos,
              ("owner archive import lines differ: " + lines).c_str());
        check(!imported.contains("profile_sha256") && !imported.contains("qnx_profile_sha256"),
              "owner input history must not pin authoring profiles");
        check(imported.at("native") == true && imported.at("frame_verified") == false &&
                      contents(destination / "originals/framework/old.jar") == "native" &&
                      contents(destination / "qnx/role.img") == "raw" &&
                      host_inventory() == host_before_import,
              "native archive/ext4 exact inputs without Java/device");
        const auto original_identity =
                           cache_file_identity(destination / "originals/framework/old.jar"),
                   source_identity = cache_file_identity(zip);
        check(import_owner_profile_inputs(root, "archive-fixture", zip, 0).at("cached") == true,
              "exact acquisition cache reused");
        bool next_offline = false;
        try {
            fetch_native_inputs(root, "archive-fixture", true, "", 0, {}, zip);
        } catch (const std::exception &error) {
            next_offline = std::string_view(error.what()).starts_with("DOWNLOAD_OFFLINE:");
        }

        check(next_offline && !std::filesystem::exists(destination / "native-inputs.json") &&
                      host_inventory() == host_before_import &&
                      cache_file_identity(zip) == source_identity &&
                      cache_file_identity(destination / "originals/framework/old.jar") ==
                              original_identity,
              "ordinary update fetch continues offline base stage without capture or mutation");
        auto metadata = local;
        metadata["install"] = Json::array({"own-adapter"});
        metadata["compatibility"] = {{"guest_boot_verified", false}};
        auto qnx_metadata = qnx;
        qnx_metadata["hardware_adapter"] = "source-only-fixture";
        qnx_metadata["remaining"] = Json::array({"actual-guest-proof"});
        write_private_json(selected / "profile.json", metadata);
        write_private_json(selected / "profile-qnx.json", qnx_metadata);
        check(import_owner_profile_inputs(root, "archive-fixture", zip, 0).at("cached") == true &&
                      cache_file_identity(destination / "originals/framework/old.jar") ==
                              original_identity,
              "metadata-only adapter/profile changes reuse pinned acquisition unchanged");
        auto extended = metadata;
        extended["original"]["frameworkBase"] = {
                {"file", "framework/framework.jar"},
                {"bytes", 5u},
                {"sha256", sha256_bytes("extra")},
                {"source", {{"path", "/system/framework/framework.jar"}}},
                {"acquisition",
                 {{"image", "system"}, {"path", "/system/framework/framework.jar"}}}};
        write_private_json(destination / "native-inputs.json",
                           {{"schema", 1},
                            {"profile", "archive-fixture"},
                            {"native", true},
                            {"frame_verified", false},
                            {"preparation_ready", false},
                            {"owner_inputs_sha256", sha256_file(destination / "owner-inputs.json")},
                            {"android_archive", {{"sha256", sha256_bytes("retained-base")}}}});
        const auto old_cache = root / "retained-subset";
        std::filesystem::copy(destination, old_cache, std::filesystem::copy_options::recursive);

        for (unsigned fault = 0; fault < 7; ++fault) {
            const auto id = "startup-parent-" + std::to_string(fault);
            const auto dir = root / ".local/profiles" / id, profile_dir = root / "profiles" / id;
            std::filesystem::copy(old_cache, dir, std::filesystem::copy_options::recursive);
            auto old_owner = read_private_json(dir / "owner-inputs.json");
            old_owner["profile"] = id;
            write_private_json(dir / "owner-inputs.json", old_owner);
            std::filesystem::remove(dir / "native-inputs.json");
            auto requested = metadata;
            requested["original"]["BootAnimation"] = {
                    {"file", "media/bootanimation.zip"},
                    {"bytes", 5u},
                    {"sha256", sha256_bytes("extra")},
                    {"acquisition",
                     {{"image", "system"}, {"path", "/system/media/bootanimation.zip"}}}};

            if (fault == 6) {
                requested["original"]["BootAnimation"]["file"] = "media/../bootanimation.zip";
            }

            write_private_json(profile_dir / "profile.json", requested);
            write_private_json(profile_dir / "profile-qnx.json", qnx_metadata);
            const auto before_owner = contents(dir / "owner-inputs.json"),
                       before_ext4 = contents(dir / "ext4-extraction.json");
            const auto old_id = cache_file_identity(dir / "originals/framework/old.jar");
            const auto parent = dir / "originals/media";

            if (fault == 2) {
                std::filesystem::create_directory(parent);
            }

            if (fault == 3) {
                std::ofstream out(parent);
                out << "foreign";
            }

            if (fault == 4) {
                std::filesystem::create_directory(dir / "originals/Media");
            }

            if (fault == 5) {
                std::filesystem::create_directory_symlink(dir / "originals/framework", parent);
            }

            const auto blocked = dir / "owner-inputs.json";

            if (fault == 1) {
                check(::chflags(blocked.c_str(), UF_IMMUTABLE) == 0,
                      "startup receipt failure fixture");
            }

            bool rejected = false;
            try {
                import_owner_profile_inputs(root, id, zip, 0);
            } catch (...) {
                rejected = true;
            }

            if (fault == 1) {
                check(::chflags(blocked.c_str(), 0) == 0, "clear startup receipt fixture");
            }

            check(fault == 0 ? !rejected && contents(parent / "bootanimation.zip") == "extra"
                             : rejected,
                  "startup extension creates declared missing parent only after retained verification");
            check(cache_file_identity(dir / "originals/framework/old.jar") == old_id,
                  "startup extension preserves retained binary incarnation");

            if (fault) {
                check(contents(dir / "owner-inputs.json") == before_owner &&
                              contents(dir / "ext4-extraction.json") == before_ext4,
                      "startup rollback restores attempted receipts");
            }

            if (fault == 1 || fault == 6) {
                check(!std::filesystem::exists(parent),
                      "startup rollback removes owned empty parent");
            }

            if (fault == 2) {
                check(std::filesystem::is_directory(parent), "foreign empty parent preserved");
            }

            if (fault == 3) {
                check(contents(parent) == "foreign", "foreign file parent preserved");
            }

            if (fault == 4) {
                check(std::filesystem::is_directory(dir / "originals/Media"),
                      "case collision preserved");
            }

            if (fault == 5) {
                check(std::filesystem::is_symlink(parent), "foreign symlink parent preserved");
            }
        }

        for (unsigned fault = 0; fault < 7; ++fault) {
            const auto id = "extension-negative-" + std::to_string(fault);
            const auto dir = root / ".local/profiles" / id, profile_dir = root / "profiles" / id;
            std::filesystem::copy(old_cache, dir, std::filesystem::copy_options::recursive);
            auto old_owner = read_private_json(dir / "owner-inputs.json");
            old_owner["profile"] = id;
            write_private_json(dir / "owner-inputs.json", old_owner);
            auto normal = read_private_json(dir / "native-inputs.json");
            normal["profile"] = id;
            normal["owner_inputs_sha256"] = sha256_file(dir / "owner-inputs.json");
            write_private_json(dir / "native-inputs.json", normal);
            auto requested = extended;

            if (fault == 5) {
                requested["acquisition"]["system"]["segments"][0]["sha256"] = std::string(64, 'f');
            }

            if (fault == 6) {
                requested["original"]["another"] = requested["original"]["frameworkBase"];
                requested["original"]["another"]["file"] = "another.jar";
            }

            write_private_json(profile_dir / "profile.json", requested);
            write_private_json(profile_dir / "profile-qnx.json", qnx_metadata);
            const auto old_file_id = cache_file_identity(dir / "originals/framework/old.jar"),
                       raw_id = cache_file_identity(dir / "qnx/role.img");
            const auto old_owner_bytes = contents(dir / "owner-inputs.json"),
                       old_ext4_bytes = contents(dir / "ext4-extraction.json"),
                       old_normal_bytes = contents(dir / "native-inputs.json");
            std::filesystem::path blocked;

            if (fault < 3) {
                blocked = dir / (fault == 0   ? "ext4-extraction.json"
                                 : fault == 1 ? "owner-inputs.json"
                                              : "native-inputs.json");
            } else if (fault == 3) {
                blocked = dir / "originals/framework";
            }

            struct Clear {
                std::filesystem::path path;

                ~Clear() {
                    if (!path.empty()) {
                        ::chflags(path.c_str(), 0);
                    }
                }
            } clear{blocked};

            if (!blocked.empty()) {
                check(::chflags(blocked.c_str(), UF_IMMUTABLE) == 0,
                      "immutable publication failure fixture");
            }

            if (fault == 4) {
                std::ofstream out(dir / "originals/framework/framework.jar");
                out << "foreign";
            }

            bool denied = false;
            try {
                import_owner_profile_inputs(root, id, zip, 0);
            } catch (...) {
                denied = true;
            }

            if (!blocked.empty()) {
                check(::chflags(blocked.c_str(), 0) == 0, "clear own immutable fixture");
                clear.path.clear();
            }

            check(denied &&
                          cache_file_identity(dir / "originals/framework/old.jar") == old_file_id &&
                          cache_file_identity(dir / "qnx/role.img") == raw_id &&
                          contents(dir / "owner-inputs.json") == old_owner_bytes &&
                          contents(dir / "ext4-extraction.json") == old_ext4_bytes &&
                          contents(dir / "native-inputs.json") == old_normal_bytes,
                  "failed extension preserves old binary incarnations and rolls back every attempted receipt");
            check(fault == 4 ? contents(dir / "originals/framework/framework.jar") == "foreign"
                             : !std::filesystem::exists(dir / "originals/framework/framework.jar"),
                  "failed extension removes only its own new file, preserves foreign file");
        }

        write_private_json(selected / "profile.json", extended);
        const auto qnx_identity = cache_file_identity(destination / "qnx/role.img"),
                   owner_update_identity = cache_file_identity(destination / "owner-update.json");
        try {
            const auto added = import_owner_profile_inputs(root, "archive-fixture", zip, 0);
            check(!added.contains("profile_sha256") && !added.contains("qnx_profile_sha256"),
                  "extended owner input history must not pin authoring profiles");
            check(added.at("originals").at("files").size() == 2 &&
                          contents(destination / "originals/framework/framework.jar") == "extra" &&
                          cache_file_identity(destination / "originals/framework/old.jar") ==
                                  original_identity &&
                          cache_file_identity(destination / "qnx/role.img") == qnx_identity &&
                          cache_file_identity(destination / "owner-update.json") ==
                                  owner_update_identity,
                  "framework extension preserves every old input incarnation");
        } catch (const std::exception &error) {
            throw std::runtime_error(
                    std::string("FETCH_FRAMEWORK_EXTENSION: old owned subset could not extend: ") +
                    error.what());
        }

        check(import_owner_profile_inputs(root, "archive-fixture", zip, 0).at("cached") == true,
              "extended acquisition cache reused");
        const auto normal_extended = read_private_json(destination / "native-inputs.json");
        check(normal_extended.at("owner_inputs_sha256") ==
                              sha256_file(destination / "owner-inputs.json") &&
                      normal_extended.at("originals").at("files") == 2 &&
                      normal_extended.at("originals").at("bytes") == 11 &&
                      normal_extended.at("android_archive").at("sha256") ==
                              sha256_bytes("retained-base") &&
                      read_private_json(destination / "ext4-extraction.json").at("files").size() ==
                              2,
              "three receipts advance together while retaining base verification");
        auto apps = extended;
        apps["original"]["LY_Multimedia"] = {
                {"file", "LY_Multimedia.apk"},
                {"bytes", 5u},
                {"sha256", sha256_bytes("music")},
                {"source", {{"package", "com.voyah.multimedia"}}},
                {"acquisition",
                 {{"image", "system"}, {"path", "/system/app/LY_Multimedia/LY_Multimedia.apk"}}}};
        apps["original"]["LY_BtPhone"] = {
                {"file", "LY_BtPhone.apk"},
                {"bytes", 5u},
                {"sha256", sha256_bytes("phone")},
                {"source", {{"package", "com.voyah.btphone"}}},
                {"acquisition",
                 {{"image", "system"}, {"path", "/system/priv-app/LY_BtPhone/LY_BtPhone.apk"}}}};
        const auto app_cache = root / "retained-framework-subset";
        std::filesystem::copy(destination, app_cache, std::filesystem::copy_options::recursive);

        for (unsigned fault = 0; fault < 10; ++fault) {
            const auto id = "music-phone-negative-" + std::to_string(fault);
            const auto dir = root / ".local/profiles" / id, profile_dir = root / "profiles" / id;
            std::filesystem::copy(app_cache, dir, std::filesystem::copy_options::recursive);
            auto old_owner = read_private_json(dir / "owner-inputs.json");
            old_owner["profile"] = id;
            write_private_json(dir / "owner-inputs.json", old_owner);
            auto normal = read_private_json(dir / "native-inputs.json");
            normal["profile"] = id;
            normal["owner_inputs_sha256"] = sha256_file(dir / "owner-inputs.json");
            write_private_json(dir / "native-inputs.json", normal);
            auto requested = apps;

            if (fault == 4) {
                requested["original"].erase("LY_BtPhone");
            }

            if (fault == 5) {
                requested["original"]["LY_BtPhone"]["sha256"] = sha256_bytes("wrong");
            }

            if (fault == 6) {
                requested["original"]["own"]["sha256"] = sha256_bytes("changed-old");
            }

            if (fault == 7) {
                requested["acquisition"]["system"]["segments"][0]["sha256"] = std::string(64, 'f');
            }

            if (fault == 8) {
                requested["original"]["third"] = requested["original"]["LY_Multimedia"];
                requested["original"]["third"]["file"] = "third.apk";
            }

            if (fault == 9) {
                requested["original"]["LY_BtPhone"]["source"]["package"] = "foreign.package";
            }

            write_private_json(profile_dir / "profile.json", requested);
            write_private_json(profile_dir / "profile-qnx.json", qnx_metadata);
            std::map<std::filesystem::path, Json> identities;

            for (const auto &entry : std::filesystem::recursive_directory_iterator(dir)) {
                if (entry.is_regular_file()) {
                    identities.emplace(entry.path(), cache_file_identity(entry.path()));
                }
            }

            const auto old_owner_bytes = contents(dir / "owner-inputs.json"),
                       old_ext4_bytes = contents(dir / "ext4-extraction.json"),
                       old_normal_bytes = contents(dir / "native-inputs.json");
            const auto blocked = fault < 3 ? dir / (fault == 0   ? "ext4-extraction.json"
                                                    : fault == 1 ? "owner-inputs.json"
                                                                 : "native-inputs.json")
                                           : std::filesystem::path{};
            struct Clear {
                std::filesystem::path path;

                ~Clear() {
                    if (!path.empty()) {
                        ::chflags(path.c_str(), 0);
                    }
                }
            } clear{blocked};

            if (!blocked.empty()) {
                check(::chflags(blocked.c_str(), UF_IMMUTABLE) == 0,
                      "immutable Music/Phone receipt fixture");
            }

            if (fault == 3) {
                std::ofstream out(dir / "originals/LY_BtPhone.apk");
                out << "foreign";
            }

            bool denied = false;
            try {
                import_owner_profile_inputs(root, id, zip, 0);
            } catch (...) {
                denied = true;
            }

            if (!blocked.empty()) {
                check(::chflags(blocked.c_str(), 0) == 0, "clear Music/Phone receipt fixture");
                clear.path.clear();
            }

            check(denied && contents(dir / "owner-inputs.json") == old_owner_bytes &&
                          contents(dir / "ext4-extraction.json") == old_ext4_bytes &&
                          contents(dir / "native-inputs.json") == old_normal_bytes,
                  "Music/Phone failure rolls back all three receipts");

            for (const auto &[path, identity] : identities) {
                if (path.filename() != "owner-inputs.json" &&
                    path.filename() != "ext4-extraction.json" &&
                    path.filename() != "native-inputs.json") {
                    check(cache_file_identity(path) == identity,
                          "Music/Phone refusal changed retained original/QNX/source receipt incarnation");
                }
            }

            check(!std::filesystem::exists(dir / "originals/LY_Multimedia.apk") &&
                          (fault == 3 ? contents(dir / "originals/LY_BtPhone.apk") == "foreign"
                                      : !std::filesystem::exists(dir / "originals/LY_BtPhone.apk")),
                  "Music/Phone rollback removes own APKs and preserves foreign destination");
        }

        std::map<std::filesystem::path, Json> retained_ids;

        for (const auto &entry : std::filesystem::recursive_directory_iterator(destination)) {
            if (entry.is_regular_file() && entry.path().filename() != "owner-inputs.json" &&
                entry.path().filename() != "ext4-extraction.json" &&
                entry.path().filename() != "native-inputs.json") {
                retained_ids.emplace(entry.path(), cache_file_identity(entry.path()));
            }
        }

        write_private_json(selected / "profile.json", apps);
        const auto app_result = import_owner_profile_inputs(root, "archive-fixture", zip, 0);
        check(app_result.at("extended") == true &&
                      app_result.at("extension").at("kind") == "MusicPhone" &&
                      contents(destination / "originals/LY_Multimedia.apk") == "music" &&
                      contents(destination / "originals/LY_BtPhone.apk") == "phone",
              "exact two-role Music/Phone extension required");

        for (const auto &[path, identity] : retained_ids) {
            check(cache_file_identity(path) == identity,
                  "successful Music/Phone extension changed retained binary or source receipt incarnation");
        }

        check(read_private_json(destination / "owner-inputs.json")
                                      .at("originals")
                                      .at("files")
                                      .size() == 4 &&
                      read_private_json(destination / "native-inputs.json")
                                      .at("originals")
                                      .at("files") == 4 &&
                      read_private_json(destination / "ext4-extraction.json").at("files").size() ==
                              4 &&
                      read_private_json(destination / "native-inputs.json")
                                      .at("owner_inputs_sha256") ==
                              sha256_file(destination / "owner-inputs.json"),
              "Music/Phone three receipt alignment");
        check(import_owner_profile_inputs(root, "archive-fixture", zip, 0).at("cached") == true &&
                      cache_file_identity(zip) == source_identity,
              "Music/Phone cached rerun preserves owner archive");
        extended = apps;
        metadata = extended;
        auto changed_recipe = metadata;
        changed_recipe["acquisition"]["system"]["segments"][0]["sha256"] = std::string(64, 'f');
        write_private_json(selected / "profile.json", changed_recipe);
        bool changed = false;
        try {
            import_owner_profile_inputs(root, "archive-fixture", zip, 0);
        } catch (...) {
            changed = true;
        }

        check(changed && cache_file_identity(destination / "originals/framework/old.jar") ==
                                 original_identity,
              "changed acquisition recipe preserves/refuses retained inputs");
        write_private_json(selected / "profile.json", metadata);
        {
            std::ofstream extra(destination / "foreign");
            extra << "foreign";
        }
        bool foreign = false;
        try {
            import_owner_profile_inputs(root, "archive-fixture", zip, 0);
        } catch (...) {
            foreign = true;
        }

        check(foreign && contents(destination / "foreign") == "foreign" &&
                      cache_file_identity(destination / "originals/framework/old.jar") ==
                              original_identity,
              "foreign retained file preserved/refused");
        std::filesystem::remove(destination / "foreign");
        {
            std::ofstream corrupt(destination / "originals/framework/old.jar");
            corrupt << "broken";
        }
        bool mismatch = false;
        try {
            import_owner_profile_inputs(root, "archive-fixture", zip, 0);
        } catch (...) {
            mismatch = true;
        }

        check(mismatch && contents(destination / "originals/framework/old.jar") == "broken",
              "mismatched retained original preserved/refused");
        local["original"]["own"]["sha256"] = sha256_bytes("wrong");
        write_private_json(root / "profiles/rejected/profile.json", local);
        write_private_json(root / "profiles/rejected/profile-qnx.json", qnx);
        bool rollback = false;
        try {
            import_owner_profile_inputs(root, "rejected", zip, 0);
        } catch (...) {
            rollback = true;
        }

        check(rollback && !std::filesystem::exists(root / ".local/profiles/rejected"),
              "original mismatch rolls back provisional acquisition");

        for (const auto &entry : std::filesystem::directory_iterator(root / ".local/build/tmp")) {
            check(!entry.path().filename().string().starts_with("owner-fetch-"),
                  "owned provisional staging cleaned");
        }
#endif
        auto incomplete = definition;
        incomplete["status"] = "incomplete";
        write_private_json(source, incomplete);
        write_private_json(source.parent_path() / "capture.json", {{"schema", 1}});
        bool retained_offline = false;
        try {
            fetch_native_inputs(root, "fixture", true, "", 0);
        } catch (const std::exception &error) {
            retained_offline = std::string_view(error.what()).starts_with("DOWNLOAD_OFFLINE:");
        }

        check(retained_offline && read_private_json(source).at("status") == "incomplete" &&
                      !std::filesystem::exists(root / ".local/profiles/fixture/native-inputs.json"),
              "retained pinned incomplete offline profile bypasses physical capture without ready claim");
        std::filesystem::remove(originals / "framework/one.jar");

        for (const bool offline : {false, true}) {
            bool missing = false;
            try {
                fetch_native_inputs(root, "fixture", offline, "", 0);
            } catch (const std::exception &error) {
                missing = std::string_view(error.what()).starts_with("FETCH_MISSING:");
            }

            check(missing,
                  "incomplete profile without a source rejects missing input before capture or publication");
        }

        {
            std::ofstream out(originals / "framework/one.jar");
            out << "one";
        }
        auto empty = incomplete;
        empty["original"] = Json::object();
        write_private_json(source, empty);
        bool no_imports = false;
        try {
            fetch_native_inputs(root, "fixture", true, "", 0);
        } catch (const std::exception &error) {
            no_imports = std::string_view(error.what()).starts_with("FETCH_MISSING:");
        }

        check(no_imports, "incomplete offline empty inputs cannot request physical capture");
        write_private_json(source, incomplete);
        {
            std::ofstream out(originals / "app.apk");
            out << "bad";
        }
        bool corrupt = false;
        try {
            verify_original_inputs(root, "fixture", inputs);
        } catch (const std::exception &error) {
            corrupt = std::string_view(error.what()).starts_with("FETCH_SHA:");
        }

        check(corrupt, "corrupt retained input fails SHA rather than refetching implicitly");
        bool fetch_corrupt = false;
        try {
            fetch_native_inputs(root, "fixture", true, "", 0);
        } catch (const std::exception &error) {
            fetch_corrupt = std::string_view(error.what()).starts_with("FETCH_SHA:");
        }

        check(fetch_corrupt,
              "incomplete offline corrupt pin rejects before capture or publication");
        // A development kernel is the CI-built release asset; fetch downloads and verifies it and
        // builds no kernel when the asset is missing or differs from its pin.
        {
            const std::string kernel = "development kernel image";
            const Json descriptor = {{"url", "https://github.com/voyemu/voyemu/releases/download/"
                                             "kernel-qinggan-11-" +
                                                     sha256_bytes(kernel).substr(0, 8) + "/Image"},
                                     {"sha256", sha256_bytes(kernel)}};
            const auto installed = root / ".local/toolchains/downloads/development-kernel" /
                                   (sha256_bytes(kernel) + ".blob");
            const DownloadTransport missing = [](const DownloadPin &, const DownloadSink &) {
                throw os::HttpsFailure(os::HttpsFailure::Kind::status, 404, "fixture");
            };
            const auto failure = [&](bool offline_mode, const DownloadTransport &transport) {
                try {
                    install_development_kernel(root, descriptor, offline_mode, 0, transport);
                } catch (const std::runtime_error &error) {
                    return std::string(error.what());
                }

                return std::string();
            };
            check(failure(false, missing).starts_with("DEVELOPMENT_KERNEL_ASSET_MISSING:") &&
                          !std::filesystem::exists(installed),
                  "missing kernel asset is an error");
            // Without a network the console names the unreachable host, not a missing asset.
            check(failure(false,
                          [](const DownloadPin &, const DownloadSink &) {
                              throw os::HttpsFailure(os::HttpsFailure::Kind::unreachable, 0,
                                                     "fixture");
                          }).starts_with("DOWNLOAD_HTTP:") &&
                          !std::filesystem::exists(installed),
                  "unreachable kernel host reported as a missing asset");
            check(failure(true, {}).starts_with("DOWNLOAD_OFFLINE:"),
                  "offline fetch without the kernel asset is an error");
            check(failure(false,
                          [](const DownloadPin &, const DownloadSink &sink) {
                              sink("tampered");
                          }).starts_with("DOWNLOAD_SHA:") &&
                          !std::filesystem::exists(installed),
                  "kernel asset that differs from the pin rejected");
            check(install_development_kernel(root, descriptor, false, 0,
                                             [&](const DownloadPin &, const DownloadSink &sink) {
                                                 sink(kernel);
                                             }) == installed &&
                          sha256_file(installed) == sha256_bytes(kernel),
                  "published kernel asset downloaded");
            check(install_development_kernel(root, descriptor, true, 0) == installed,
                  "installed kernel verified offline");
        }

        if (argc == 2) {
#ifdef _WIN32
            const auto installed = root / "voyemu.exe";
#else
            const auto installed = root / "voyemu";
#endif
            ensure_private_directory(root / ".local/machines");
            std::filesystem::copy_file(std::filesystem::canonical(argv[1]), installed);
            ProcessSpec command;
            command.executable = installed;
            command.arguments = {"fetch", "fixture", "--offline"};
            command.directory = root;
            command.output = root / "fetch.log";
            const auto reply = execute(command, 10000);
            check(reply.exit_code != 0 && reply.output.find("FETCH_SHA") != std::string::npos,
                  "native CLI dispatches fetch before any guest startup");
        }

        std::cout
                << "native fetch source planning, 487 pinned originals, offline and corruption guards passed\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
