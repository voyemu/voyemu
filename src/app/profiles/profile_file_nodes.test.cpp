#include "profile_file_nodes.hpp"
#include "init_patch.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "selinux_patch.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
using namespace voyemu;

// The bundled Android 9 profile on the 8155 board, read from the catalog.
static const std::string &qinggan09_profile() {
    static const auto id =
            embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);

    return id;
}

namespace {
void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

void put(const std::filesystem::path &path, const std::string &bytes) {
    ensure_private_directory(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    stream << bytes;
    check(bool(stream), "fixture write failed");
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 5 && std::string(argv[1]) == "--codec-wrapper") {
            // A local copy of A9 named by argv[3] plans the current A9 codec node.
            auto nodes = plan_profile_codec_file_node(std::filesystem::canonical(argv[2]), argv[3],
                                                      std::filesystem::canonical(argv[4]));
            check(nodes.patches.size() == 1 &&
                          nodes.patches.front().output_sha256 ==
                                  "11d1e2cb76995985aa319e08fca8a6286bc7c701ecb71ed5a7822b4816bce86f",
                  "copied stable wrapper codec differs");
            const auto output = prepare_file_patches(nodes.patches);
            check(output.size() == 1 &&
                          sha256_bytes(output.front()) == nodes.patches.front().output_sha256,
                  "copied stable wrapper dispatch differs");
            std::cout << "copied stable wrapper uses current codec\n";

            return 0;
        }

        if (argc == 5 && std::string(argv[1]) == "--codec-publish") {
            auto nodes = plan_profile_codec_file_node(std::filesystem::canonical(argv[2]),
                                                      qinggan09_profile(),
                                                      std::filesystem::canonical(argv[3]));
            check(nodes.patches.size() == 1 && nodes.patches.front().id == "ccodec-allocation-a9",
                  "codec-only publication must not replace existing Java file nodes");
            publish_file_patches(nodes.patches, std::filesystem::path(argv[4]));
            auto receipt = read_private_json(std::filesystem::path(argv[4]) / "receipt.json",
                                             128 * 1024);
            receipt["profile_provenance"] = nodes.provenance;
            write_private_json(std::filesystem::path(argv[4]) / "receipt.json", receipt);
            nodes.revalidate();
            check(sha256_file(std::filesystem::path(argv[4]) / "ccodec-allocation-a9.output") ==
                          "11d1e2cb76995985aa319e08fca8a6286bc7c701ecb71ed5a7822b4816bce86f",
                  "codec published output differs");
            std::cout << receipt.dump() << '\n';

            return 0;
        }

        if (argc == 7 && std::string(argv[1]) == "--plan-publish") {
            const auto nodes = plan_profile_file_nodes(std::filesystem::canonical(argv[2]), argv[3],
                                                       std::filesystem::canonical(argv[4]),
                                                       std::filesystem::canonical(argv[5]));
            publish_file_patches(nodes.patches, std::filesystem::path(argv[6]));
            auto receipt = read_private_json(std::filesystem::path(argv[6]) / "receipt.json",
                                             128 * 1024);
            receipt["profile_provenance"] = nodes.provenance;
            write_private_json(std::filesystem::path(argv[6]) / "receipt.json", receipt);
            nodes.revalidate();
            std::cout << receipt.dump() << '\n';

            return 0;
        }

        if (argc == 6 && std::string(argv[1]) == "--plan") {
            const auto nodes = plan_profile_file_nodes(std::filesystem::canonical(argv[2]), argv[3],
                                                       std::filesystem::canonical(argv[4]),
                                                       std::filesystem::canonical(argv[5]));
            nodes.revalidate();
            std::cout << nodes.provenance.dump() << '\n';

            return 0;
        }

        const auto codec_input = argc == 3 && std::string(argv[1]) == "--codec-input"
                                         ? std::filesystem::canonical(argv[2])
                                         : std::filesystem::path{};
        check(argc == 1 || !codec_input.empty(),
              "usage: --codec-input PINNED_CODEC | --codec-publish ROOT SYSTEM DEST | --plan ROOT PROFILE SYSTEM_EXTRACTION VENDOR_EXTRACTION");
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-file-nodes-" + random_token());
        ensure_private_directory(root);
        struct Cleanup {
            std::filesystem::path p;

            ~Cleanup() {
                std::error_code e;
                std::filesystem::remove_all(p, e);
            }
        } cleanup{root};
        const auto repository = std::filesystem::path(__FILE__)
                                        .parent_path()
                                        .parent_path()
                                        .parent_path()
                                        .parent_path();
        const std::string profile = qinggan09_profile();
        const auto directory = root / "profiles" / profile, system = root / "system-extraction",
                   vendor = root / "vendor-extraction";
        ensure_private_directory(directory / "patches");
        ensure_private_directory(system);
        ensure_private_directory(vendor);
        {
            const auto &catalog = embedded_profile_catalog();
            const auto targeted =
                    std::find_if(catalog.begin(), catalog.end(), [](const auto &entry) {
                        return entry.at("definition").contains("targets") &&
                               profile_platform(entry.at("definition")) == ProfilePlatform::passion;
                    });
            check(targeted != catalog.end(), "registered Passion target fixture missing");
            const std::string id = "test-file-node-target";
            auto definition = targeted->at("definition");
            definition["id"] = id;
            const auto first = api30_file_recipes_for_profile(definition).front().id;
            definition["patches"][first]["input"] = "android:/system/foreign";
            // The fixture target declares the kernel of its ABI, which the published one lacks.
            auto kernel = definition.at("android").at("development_kernel");
            kernel["abi"] = "x86_64";
            definition["targets"]["x86"]["developmentKernel"] = kernel;
            write_private_json(root / "profiles" / id / "profile.json", definition);
            const auto base_name =
                    definition.at("targets").at("x86").at("androidBase").get<std::string>();
            const auto relative = std::filesystem::path("profiles/common/android-bases") /
                                  (base_name + ".json");
            const auto base = read_private_json(repository / relative);
            write_private_json(root / relative, base);
            const auto &clean = base.at("clean_base");
            const auto &partitions = clean.at("logical_partitions");
            write_private_json(system / "receipt.json",
                               {{"schema", 1},
                                {"native", true},
                                {"filesystem_mounted", false},
                                {"image_sha256", clean.at("images").at("system.img")},
                                {"logical_partition", "system"},
                                {"lp_metadata_sha256", partitions.at("metadata_sha256")},
                                {"partition_offset", partitions.at("system").at("offset")},
                                {"logical_partition_bytes", partitions.at("system").at("bytes")}});
            const auto rejects_at = [&](std::string_view target, std::string_view message) {
                try {
                    (void)plan_profile_file_nodes(root, id, system, vendor, target);
                } catch (const VoyemuError &error) {
                    return std::string_view(error.what()).find(message) != std::string_view::npos;
                }

                return false;
            };
            check(rejects_at("arm", "API30 logical platform extraction receipt required") &&
                          rejects_at("x86", "API30 native node declaration differs"),
                  "only the selected x86 descriptor accepts the x86 extraction receipt");
        }
        auto definition = read_private_json(repository / "profiles" / profile / "profile.json",
                                            512 * 1024);
        const Json java_shutdown = {{"type", "file"},
                                    {"input", "android:/vendor/etc/init/hw/init.ranchu.rc"},
                                    {"steps", Json::array({"shutdown-router-a9.json"})}},
                   java_shutdown_install = {{"artifact", "patched:shutdown-router-a9"},
                                            {"type", "file"},
                                            {"target", "/vendor/etc/init/hw/init.ranchu.rc"},
                                            {"mode", "0644"}};
        check(definition.at("patches").at("shutdown-router-a9") == java_shutdown,
              "exact Java-owned shutdown route fixture contract");
        definition["patches"].erase("shutdown-router-a9");
        Json native_install = Json::array();
        unsigned removed = 0;

        for (const auto &row : definition.at("install")) {
            if (row == java_shutdown_install) {
                ++removed;
            } else {
                native_install.push_back(row);
            }
        }

        check(removed == 1, "one Java-owned shutdown install outside native fixture");
        definition["install"] = std::move(native_install);
        const std::string plat = "(allow su present (file (read)))\n",
                          vendor_policy = "(allow su_28_0 present_28_0 (dir (search)))\n";
        definition["original"]["PlatSepolicy"]["sha256"] = sha256_bytes(plat);
        definition["original"]["VendorSepolicy"]["sha256"] = sha256_bytes(vendor_policy);
        put(root / ".local/profiles" / profile / "originals/policy/plat_sepolicy.cil", plat);
        put(root / ".local/profiles" / profile / "originals/policy/vendor_sepolicy.cil",
            vendor_policy);
        write_private_json(directory / "profile.json", definition);
        Json system_receipt = {{"schema", 1},
                               {"native", true},
                               {"filesystem_mounted", false},
                               {"image_sha256",
                                "1d38dd537caa931441dc92949098b0f61b112587769877266f79f6e826822009"},
                               {"files", Json::object()}},
             vendor_receipt = system_receipt;
        vendor_receipt["image_sha256"] =
                "44fdea85db085010dc5554d17661a2273c47fa540f9188dbebf14a4cfc52f173";

        for (auto it = definition.at("patches").begin(); it != definition.at("patches").end();
             ++it) {
            if (it.value().at("type") != "file") {
                continue;
            }

            const auto name = it.key();

            for (const auto &step : it.value().at("steps")) {
                const auto value = step.get<std::string>();
                const auto target = directory / "patches" / value;

                if (!std::filesystem::exists(target)) {
                    std::filesystem::copy_file(
                            repository / "profiles" / profile / "patches" / value, target);
                }
            }

            const auto input = it.value().at("input").get<std::string>().substr(8);
            const bool is_vendor = input.starts_with("/vendor/");
            const auto relative = is_vendor ? input.substr(8) : input.substr(1);
            std::string bytes = "old\n";

            if (name == "ccodec-allocation-a9" && !codec_input.empty()) {
                std::ifstream input(codec_input, std::ios::binary);
                bytes.assign(std::istreambuf_iterator<char>(input), {});
                check(sha256_bytes(bytes) ==
                              "2262964922a876a51c3b5186f094afb136ce9daae0678f9820f11e86e058e353",
                      "exact extracted codec fixture required");
            }

            if (name == "selinux-canbus-a9") {
                bytes = "(type su)\n(type present)\n(typepermissive su)\n";
            }

            if (name == "selinux-hash-a9") {
                bytes = std::string(64, '0') + "\n";
            }

            for (const auto &recipe : init_patch_recipes()) {
                if (recipe.id == name) {
                    bytes.clear();

                    for (unsigned n = 1; n < recipe.insert_line; ++n) {
                        bytes += "fixture line\n";
                    }

                    bytes += "tail\n";
                }
            }

            const auto extraction = is_vendor ? vendor : system;
            put(extraction / relative, bytes);
            auto &receipt = is_vendor ? vendor_receipt : system_receipt;
            receipt["files"][relative] = {{"bytes", bytes.size()}, {"sha256", sha256_bytes(bytes)}};
        }

        write_private_json(system / "receipt.json", system_receipt);
        write_private_json(vendor / "receipt.json", vendor_receipt);
        check(api30_file_recipes_for("qinggan11")[0].id == "keymanager-contexts-api30" &&
                      api30_file_recipes_for("api30-fixture")[1].id ==
                              "selinux-service-contexts-api30" &&
                      api30_file_recipes_for("passion")[1].id == "passion-service-contexts",
              "Free wheel context must not widen generic/Passion context transforms");
        check(api30_file_recipes_for("api30-fixture").size() == 3 &&
                      api30_file_recipes_for("qinggan11").size() == 8 &&
                      api30_file_recipes_for("passion").size() == 6,
              "profile-specific API30 graph inventories preserved");
        const auto observer_recipes = api30_file_recipes_for("qinggan11", true, true);
        check(observer_recipes.size() == 9 &&
                      observer_recipes[6].output_sha256 == qinggan11_ui_observer_policy_sha256 &&
                      observer_recipes[8].output_sha256 ==
                              qinggan11_ui_observer_policy_hash_file_sha256,
              "observer policy and digest are selected together");

        for (const auto platform : {"qinggan09", "passion", "api30-fixture"}) {
            bool rejected = false;
            try {
                (void)api30_file_recipes_for(platform, true, true);
            } catch (const VoyemuError &error) {
                rejected = error.code() == "SELINUX_PATCH_SCOPE";
            }

            check(rejected, "observer variant rejects an unrelated platform");
        }

        bool missing_baseline = false;
        try {
            (void)api30_file_recipes_for("qinggan11", false, true);
        } catch (const VoyemuError &error) {
            missing_baseline = error.code() == "SELINUX_PATCH_SCOPE";
        }

        check(missing_baseline, "observer variant rejects another policy baseline");
        const auto original_recipes = api30_file_recipes_for("qinggan11", true);

        check(original_recipes.size() == 9 && original_recipes[2].id == "original-navi-selinux" &&
                      original_recipes[8].id == "selinux-hash-api30" &&
                      original_recipes[6].id == "can-early-policy-api30",
              "only original Navi graph gets MAC and keeps policy-hash dependency order");
        // The feature alone decides the early policy and its hash; no profile id takes part.
        check(api30_file_recipes_for("qinggan11")[5].id == "can-early-policy-api30" &&
                      api30_file_recipes_for("qinggan11")[5].output_sha256 ==
                              "50e7563396d73b053a36a9022d31807121731ecc0ce51b695df65ec7d6838db6" &&
                      api30_file_recipes_for("qinggan11")[7].output_sha256 ==
                              "2f158789774a59073cf85bf2c91272416b0da948eea037f9e13586187338f2c9" &&
                      original_recipes[6].output_sha256 ==
                              "e8f3b8cb54b3ec09280cf5c630f495b3202f1c9994e796c5a1cf707a5dcd6cf6" &&
                      original_recipes[8].output_sha256 ==
                              "7293ab8b5ff6f3890a7f60b158e6bf28c882896c755edf1e996c9231519c37de",
              "qinggan11 early policy follows the original_navi feature");
        bool wrong_original = false;
        try {
            (void)api30_file_recipes_for("api30-fixture", true);
        } catch (const VoyemuError &error) {
            wrong_original = error.code() == "QINGGAN11_ORIGINAL_NAVI";
        }

        check(wrong_original, "original Navi SELinux graph rejects another platform");
        bool old_navi_rejected = false;
        try {
            (void)api30_file_recipes_for("passion", true);
        } catch (const VoyemuError &error) {
            old_navi_rejected = error.code() == "QINGGAN11_ORIGINAL_NAVI";
        }

        check(old_navi_rejected, "Passion graph rejects the original Navi");
        const auto free_profile =
                embedded_profile_names(ProfilePlatform::qinggan11, ProfileBoard::sa8155).at(0);
        const auto free_dir = root / "profiles" / free_profile;
        ensure_private_directory(free_dir);
        const auto complete_free = read_private_json(
                repository / "profiles" / free_profile / "profile.json", 512 * 1024);

        for (bool empty : {false, true}) {
            auto incomplete = complete_free;

            if (empty) {
                incomplete["patches"] = Json::object();
            } else {
                incomplete["patches"].erase("public-qg-runtime-api30");
            }

            write_private_json(free_dir / "profile.json", incomplete);
            bool rejected = false;
            try {
                plan_profile_file_nodes(root, free_profile, system, vendor);
            } catch (const std::exception &error) {
                rejected = std::string(error.what()).find("native file graph") != std::string::npos;
            }

            check(rejected,
                  "current qinggan11 profile must reject missing/all-removed public native graph before extraction");
        }

        auto missing_property = complete_free;
        missing_property["patches"].erase("can-early-property-contexts-api30");
        write_private_json(free_dir / "profile.json", missing_property);
        bool property_rejected = false;
        try {
            plan_profile_file_nodes(root, free_profile, system, vendor);
        } catch (const std::exception &error) {
            property_rejected = std::string(error.what()).find("native file graph") !=
                                std::string::npos;
        }

        check(property_rejected,
              "current qinggan11 profile must reject missing can early property context before extraction");
        auto unsupported_java = definition;
        unsupported_java["patches"]["shutdown-router-a9"] = java_shutdown;
        unsupported_java["install"].push_back(java_shutdown_install);
        write_private_json(directory / "profile.json", unsupported_java);
        bool java_node_rejected = false;
        try {
            plan_profile_file_nodes(root, profile, system, vendor);
        } catch (const std::exception &e) {
            java_node_rejected = std::string(e.what()).find("unsupported non-APK profile node") !=
                                 std::string::npos;
        }

        check(java_node_rejected,
              "Java-owned shutdown route must not be promoted into the twelve-node native file planner");
        auto missing_codec = definition;
        missing_codec["patches"].erase("ccodec-allocation-a9");
        write_private_json(directory / "profile.json", missing_codec);
        bool codec_missing_rejected = false;
        try {
            plan_profile_file_nodes(root, profile, system, vendor);
        } catch (...) {
            codec_missing_rejected = true;
        }

        check(codec_missing_rejected, "A9 native graph must reject missing codec node");
        write_private_json(directory / "profile.json", definition);

        if (codec_input.empty()) {
            bool invalid_codec_rejected = false;
            try {
                plan_profile_file_nodes(root, profile, system, vendor);
            } catch (const std::exception &e) {
                const auto reason = std::string(e.what());
                invalid_codec_rejected = reason.find("ANDROID_CODEC_TIMING") != std::string::npos ||
                                         (reason.find("SELINUX_PATCH_MISMATCH") == 0 &&
                                          reason.find("contexts required") != std::string::npos);
            }

            check(invalid_codec_rejected,
                  "synthetic extraction cannot pass exact native pinned-input guards");
            std::cout
                    << "profile/API30 and missing/unregistered A9 native input guards passed; --codec-input exercises complete A9 graph\n";

            return 0;
        }

        auto codec_only = plan_profile_codec_file_node(root, profile, system);
        check(codec_only.patches.size() == 1 &&
                      codec_only.provenance.at("native_scope") == "api28-codec-only" &&
                      codec_only.provenance.at("nodes").size() == 1,
              "native handoff must contain only codec, not old eleven Java transforms");
        const auto nodes = plan_profile_file_nodes(root, profile, system, vendor);
        check(nodes.patches.size() == 12 && nodes.patches.back().id == "selinux-hash-a9" &&
                      nodes.provenance.at("machine_ready") == false,
              "all file nodes/order/scope mismatch");
        nodes.revalidate();
        put(system / "system/etc/init/incidentd.rc", "changed");
        bool refused = false;
        try {
            nodes.revalidate();
        } catch (...) {
            refused = true;
        }

        check(refused, "extracted input mutation accepted");
        refused = false;
        try {
            plan_profile_file_nodes(root, profile, system, vendor);
        } catch (...) {
            refused = true;
        }

        check(refused, "extraction receipt mismatch accepted");
        vendor_receipt["image_sha256"] = std::string(64, '0');
        write_private_json(vendor / "receipt.json", vendor_receipt);
        refused = false;
        try {
            plan_profile_file_nodes(root, profile, system, vendor);
        } catch (const std::exception &e) {
            refused = std::string(e.what()).find("receipt required") != std::string::npos;
        }

        check(refused, "unregistered vendor image accepted");
        std::cout << "all profile file nodes extraction/source/dependency binding guards passed\n";

        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';

        return 1;
    }
}
