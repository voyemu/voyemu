#include "passion_power_prepared.hpp"
#include "passion_signed_guest.test.hpp"
#include <cassert>
#include <exception>
#include <fstream>
#include <iostream>
using namespace voyemu;

template <class F> void rejects(F f) {
    bool bad = false;

    try {
        f();
    } catch (...) {
        bad = true;
    }

    assert(bad);
}

int main() try {
    Json definition = {
            {"id", "test-passion"},
            {"platform", "passion"},
            {"board", "8155"},
            {"android",
             {{"package", "system-images;android-30;default;arm64-v8a"},
              {"sha256", std::string(64, 'b')}}},
            {"patches",
             {{"MegaNexusService", {{"steps", Json::array({"passion-api30-nexus-power.json"})}}},
              {"passion-api30-secondary-navigation",
               {{"steps", Json::array({"passion-api30-display-power.json"})}}}}}};
    Json candidate = {{"schema", 1},
                      {"kind", "android-candidate"},
                      {"profile", definition["id"]},
                      {"profile_sha256", std::string(64, 'c')},
                      {"clean_base_archive_sha256", std::string(64, 'b')},
                      {"artifact_result_sha256", std::string(64, 'd')},
                      {"prepared_VM", true},
                      {"stopped", true},
                      {"cold_boot_verified", true},
                      {"android",
                       {{"images",
                         {{"system.img",
                           {{"file", "android/system.img"},
                            {"sha256", std::string(64, 'a')},
                            {"bytes", 42}}}}}}},
                      {"installed", Json::array()},
                      {"checks", Json::array()}};

    for (const auto &pair : std::vector<std::pair<std::string, std::string>>{
                 {"boot", "1"}, {"api", "30"}, {"abi", "arm64-v8a"}, {"selinux", "Enforcing"}}) {
        candidate["checks"].push_back({{"id", pair.first},
                                       {"actual", pair.second},
                                       {"expected", pair.second},
                                       {"passed", true}});
    }

    Json pins = Json::object();
    const auto targets = passion_power_targets(), csv = passion_power_csv();

    for (auto it = targets.begin(); it != targets.end(); ++it) {
        const auto pin = csv.contains(it.key().substr(1))
                                 ? csv.at(it.key().substr(1)).get<std::string>()
                                 : std::string(64, 'e');
        pins[it.key()] = pin;
        candidate["installed"].push_back({{"artifact", it.value()},
                                          {"target", it.key()},
                                          {"sha256", pin},
                                          {"mutable", false}});
        candidate["checks"].push_back(
                {{"id", "artifact:" + it.value().get<std::string>() + ":" + it.key()},
                 {"expected", pin},
                 {"actual", pin},
                 {"passed", true}});
    }

    Json helpers = Json::object();

    for (const auto &target :
         {std::string("/system/framework/services.jar"),
          std::string("/system/priv-app/MegaNexusService/MegaNexusService.apk")}) {
        const bool sdk = target == "/system/framework/services.jar";
        helpers[target] = {{"contract", "passion-display-power-helper-v1"},
                           {"artifact", targets.at(target)},
                           {"archive_sha256", pins.at(target)},
                           {"entry", sdk ? "classes3.dex" : "classes2.dex"},
                           {"sha256", std::string(64, 'f')},
                           {"bytes", std::uint64_t{128}}};
    }

    candidate["display_power"] = passion_power_contract(definition, candidate, pins, helpers);

    for (int mode = 0; mode < 8; ++mode) {
        auto bad = helpers;
        auto &helper = bad["/system/framework/services.jar"];

        if (mode == 0) {
            helper["artifact"] = "patched:MegaNexusService";
        }

        if (mode == 1) {
            helper["archive_sha256"] = std::string(64, '0');
        }

        if (mode == 2) {
            helper["entry"] = "classes2.dex";
        }

        if (mode == 3) {
            helper["contract"] = "foreign";
        }

        if (mode == 4) {
            helper.erase("sha256");
        }

        if (mode == 5) {
            helper["bytes"] = std::uint64_t{0};
        }

        if (mode == 6) {
            helper["extra"] = true;
        }

        if (mode == 7) {
            bad.erase("/system/priv-app/MegaNexusService/MegaNexusService.apk");
        }

        rejects([&] {
            passion_power_contract(definition, candidate, pins, bad);
        });
    }

    // The exact same archive verifier gates the extra metadata in upgrade artifact descriptors.
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-power-contract-" + random_token());
    ensure_private_directory(root / ".local");
    struct Cleanup {
        std::filesystem::path path;

        ~Cleanup() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    } cleanup{root};
    const auto archive = root / ".local/helper.jar";
    const std::string hex =
            "504b03041400000000000000000079841f6219000000190000000c000000636c6173736573332e646578"
            "73796e74686574696320636f6d70696c65642068656c706572504b01021400140000000000000000007984"
            "1f6219000000190000000c0000000000000000000000000000000000636c6173736573332e646578504b"
            "050600000000010001003a000000430000000000";
    {
        std::ofstream out(archive, std::ios::binary);

        for (std::size_t i = 0; i < hex.size(); i += 2) {
            out.put(static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        }

        assert(bool(out));
    }
    Json descriptor = {{"file", archive.string()},
                       {"sha256", sha256_file(archive)},
                       {"bytes", std::filesystem::file_size(archive)},
                       {"power_helper",
                        {{"contract", "passion-display-power-helper-v1"},
                         {"artifact", "patched:passion-api30-secondary-navigation"},
                         {"archive_sha256", sha256_file(archive)},
                         {"entry", "classes3.dex"},
                         {"sha256", sha256_bytes("synthetic compiled helper")},
                         {"bytes", std::uint64_t{25}}}}};
    const std::string reference = "patched:passion-api30-secondary-navigation";
    passion_power_helper_artifact(root, reference, descriptor);
    rejects([&] {
        passion_power_helper_artifact(root, "patched:unrelated", descriptor);
    });

    for (int mode = 0; mode < 8; ++mode) {
        auto bad = descriptor;

        if (mode == 0) {
            bad["power_helper"]["sha256"] = std::string(64, '0');
        }

        if (mode == 1) {
            bad["power_helper"]["bytes"] = std::uint64_t{26};
        }

        if (mode == 2) {
            bad["power_helper"]["archive_sha256"] = std::string(64, '0');
        }

        if (mode == 3) {
            bad["power_helper"]["entry"] = "classes.dex";
        }

        if (mode == 4) {
            bad["power_helper"].erase("contract");
        }

        if (mode == 5) {
            bad["sha256"] = std::string(64, '0');
        }

        if (mode == 6) {
            bad["bytes"] = std::uint64_t{0};
        }

        if (mode == 7) {
            bad["extra"] = true;
        }

        rejects([&] {
            passion_power_helper_artifact(root, reference, bad);
        });
    }

    const auto images = candidate["android"]["images"];
    assert(validate_passion_power_candidate(definition, candidate, images, std::string(64, 'c')) ==
           media::PassionPowerOwner::capability());

    for (int mode = 0; mode < 10; mode++) {
        auto bad = candidate;

        if (mode == 0) {
            bad["checks"].erase(bad["checks"].begin() + 4);
        }

        if (mode == 1) {
            bad["checks"][4]["actual"] = std::string(64, '0');
        }

        if (mode == 2) {
            bad["checks"][4]["passed"] = false;
        }

        if (mode == 3) {
            bad["installed"][0]["mutable"] = true;
        }

        if (mode == 4) {
            bad["display_power"]["sdk_hook_dex_sha256"] = std::string(64, '0');
        }

        if (mode == 5) {
            bad["stopped"] = false;
        }

        if (mode == 6) {
            bad["checks"].push_back(bad["checks"][4]);
        }

        if (mode == 7) {
            bad["profile_sha256"] = std::string(64, '0');
        }

        if (mode == 8) {
            bad["android"]["images"]["system.img"]["sha256"] = std::string(64, '0');
        }

        if (mode == 9) {
            bad["checks"][1]["actual"] = "28";
        }

        rejects([&] {
            validate_passion_power_candidate(definition, bad, images, std::string(64, 'c'));
        });
    }

    auto composed = definition;
    composed["patches"]["passion-api30-secondary-navigation"]["steps"] =
            Json::array({"passion-api30-secondary-navigation.json",
                         "passion-api30-display-power.json", "passion-api30-startup-volume.json"});
    auto current = candidate;
    current["display_power"] = passion_power_contract(composed, current, pins, helpers);
    assert(current["display_power"]["sdk_hook_dex_sha256"] ==
           "b8d882888bd7575d78db9797a9b8f81e1897f786b0687d59ac79dffb40eba558");
    assert(validate_passion_power_candidate(composed, current, images, std::string(64, 'c')) ==
           media::PassionPowerOwner::capability());
    rejects([&] {
        validate_passion_power_candidate(definition, current, images, std::string(64, 'c'));
    });
    rejects([&] {
        validate_passion_power_candidate(composed, candidate, images, std::string(64, 'c'));
    });

    for (int mode = 0; mode < 2; ++mode) {
        auto bad = composed;
        auto &steps = bad["patches"]["passion-api30-secondary-navigation"]["steps"];

        if (mode == 0) {
            std::swap(steps[1], steps[2]);
        } else {
            steps.push_back("passion-api30-startup-volume.json");
        }

        rejects([&] {
            passion_power_contract(bad, current, pins, helpers);
        });
    }

    auto x86_definition = composed;
    auto x86_candidate = current;
    test::use_signed_x86_guest(x86_definition, x86_candidate);
    x86_candidate["display_power"] = passion_power_contract(x86_definition, x86_candidate, pins,
                                                            helpers);
    const auto signed_images = x86_candidate.at("android").at("images");
    assert(validate_passion_power_candidate(x86_definition, x86_candidate, signed_images,
                                            std::string(64, 'c')) ==
           media::PassionPowerOwner::capability());

    auto repeated_boot = x86_candidate;
    repeated_boot["signed_android"]["cold_boot_id"] =
            repeated_boot["signed_android"]["first_boot_id"];
    rejects([&] {
        validate_passion_power_candidate(x86_definition, repeated_boot, signed_images,
                                         std::string(64, 'c'));
    });
    auto unsigned_candidate = x86_candidate;
    unsigned_candidate["signed_android"].erase("system_root_sha256");
    rejects([&] {
        validate_passion_power_candidate(x86_definition, unsigned_candidate, signed_images,
                                         std::string(64, 'c'));
    });
    auto wrong_cold_abi = x86_candidate;
    wrong_cold_abi["checks"][2]["expected"] = wrong_cold_abi["checks"][2]["actual"] = "arm64-v8a";
    rejects([&] {
        validate_passion_power_candidate(x86_definition, wrong_cold_abi, signed_images,
                                         std::string(64, 'c'));
    });

    auto old = definition;
    old["patches"]["MegaNexusService"]["steps"] = Json::array();
    old["patches"]["passion-api30-secondary-navigation"]["steps"] = Json::array();
    assert(!passion_power_requested(old));
    old["patches"]["MegaNexusService"]["steps"].push_back("passion-api30-nexus-power.json");
    rejects([&] {
        passion_power_requested(old);
    });
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
