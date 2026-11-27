#include "passion_mcu_prepared.hpp"
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
#ifdef NDEBUG
    throw std::runtime_error("assertions required");
#endif
    Json definition = {
            {"id", "test-passion"},
            {"platform", "passion"},
            {"board", "8155"},
            {"android",
             {{"package", "system-images;android-30;default;arm64-v8a"},
              {"sha256", std::string(64, 'b')}}},
            {"patches",
             {{"MonzaCarService",
               {{"input", "original:MonzaCarService"},
                {"type", "apk"},
                {"steps", Json::array({"framework-libraries.json", "passion-api30-diagnostics.json",
                                       "passion-api30-mcu-property.json"})}}}}}};
    const std::string apk(64, 'a'), profile(64, 'c');
    Json images = {
            {"system.img",
             {{"sha256", std::string(64, 'd')}, {"file", "android/system.img"}, {"bytes", 42}}}};
    Json candidate = {
            {"schema", 1},
            {"kind", "android-candidate"},
            {"profile", definition.at("id")},
            {"profile_sha256", profile},
            {"clean_base_archive_sha256", std::string(64, 'b')},
            {"artifact_result_sha256", std::string(64, 'e')},
            {"prepared_VM", true},
            {"stopped", true},
            {"cold_boot_verified", true},
            {"installed",
             Json::array({Json{{"artifact", "patched:MonzaCarService"},
                               {"target", "/system/priv-app/MonzaCarService/MonzaCarService.apk"},
                               {"sha256", apk},
                               {"mutable", false}}})},
            {"checks", Json::array()},
            {"android", {{"images", images}}}};

    for (const auto &pair : std::vector<std::pair<std::string, std::string>>{
                 {"boot", "1"},
                 {"api", "30"},
                 {"abi", "arm64-v8a"},
                 {"selinux", "Enforcing"},
                 {"artifact:patched:MonzaCarService:/system/priv-app/MonzaCarService/MonzaCarService.apk",
                  apk}}) {
        candidate["checks"].push_back({{"id", pair.first},
                                       {"expected", pair.second},
                                       {"actual", pair.second},
                                       {"passed", true}});
    }

    const auto root = std::filesystem::current_path();
    const auto work = root / ".local/build/jobs" / ("passion-mcu-output-" + random_token());
    ensure_private_directory(work);
    struct Cleanup {
        std::filesystem::path path;

        ~Cleanup() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    } cleanup{work};
    const auto archive = work / "Monza.apk";
    const std::string hex =
            "504b03041400000000000000000079841f6219000000190000000d000000"
            "636c617373657331382e64657873796e74686574696320636f6d70696c65642068656c706572"
            "504b010214001400000000000000000079841f6219000000190000000d000000"
            "0000000000000000000000000000636c617373657331382e646578"
            "504b050600000000010001003b000000440000000000";
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
                       {"mcu_helper",
                        {{"contract", "passion-mcu-property-helper-v1"},
                         {"artifact", "patched:MonzaCarService"},
                         {"archive_sha256", sha256_file(archive)},
                         {"entry", "classes18.dex"},
                         {"sha256", sha256_bytes("synthetic compiled helper")},
                         {"bytes", std::uint64_t{25}}}}};
    const Json artifacts = {{"patched:MonzaCarService", descriptor}};
    passion_mcu_helper_graph(root, definition, artifacts);

    for (const auto *field :
         {"contract", "artifact", "archive_sha256", "entry", "sha256", "bytes"}) {
        auto bad = artifacts;
        bad["patched:MonzaCarService"]["mcu_helper"].erase(field);
        rejects([&] {
            passion_mcu_helper_graph(root, definition, bad);
        });
    }

    for (int mode = 0; mode < 5; ++mode) {
        auto bad = artifacts;

        if (mode == 0) {
            bad["patched:MonzaCarService"]["mcu_helper"]["sha256"] = std::string(64, '0');
        }

        if (mode == 1) {
            bad["patched:MonzaCarService"]["mcu_helper"]["bytes"] = std::uint64_t{24};
        }

        if (mode == 2) {
            bad["patched:MonzaCarService"]["sha256"] = std::string(64, '0');
        }

        if (mode == 3) {
            bad["patched:MonzaCarService"]["bytes"] = std::uint64_t{1};
        }

        if (mode == 4) {
            bad["foreign"] = bad["patched:MonzaCarService"];
            bad.erase("patched:MonzaCarService");
        }

        rejects([&] {
            passion_mcu_helper_graph(root, definition, bad);
        });
    }

    auto foreign = definition;
    foreign["platform"] = "qinggan11";
    rejects([&] {
        passion_mcu_helper_graph(root, foreign, artifacts);
    });
    rejects([&] {
        passion_mcu_helper_graph(root, definition, Json::object());
    });

    candidate["mcu_property"] =
            passion_mcu_contract(definition, candidate, apk,
                                 {{"contract", "passion-mcu-property-helper-v1"},
                                  {"artifact", "patched:MonzaCarService"},
                                  {"archive_sha256", apk},
                                  {"entry", "classes18.dex"},
                                  {"sha256", std::string(64, 'f')},
                                  {"bytes", std::uint64_t{25}}});
    assert(validate_passion_mcu_candidate(definition, candidate, images, profile) ==
           passion_mcu_capability());
    // The machine keeps cold evidence beyond 128 KiB up to the 1 MiB that start reads.
    auto large = candidate;
    large["events"] = Json::array({std::string(200 * 1024, 'e')});
    assert(export_passion_mcu(definition, large, work / "large-evidence", profile)
                   .at("bytes")
                   .get<std::uint64_t>() > 128 * 1024);

    for (int mode = 0; mode < 17; mode++) {
        auto bad = candidate;

        if (mode == 0) {
            bad["stopped"] = false;
        }

        if (mode == 1) {
            bad["cold_boot_verified"] = false;
        }

        if (mode == 2) {
            bad["checks"].erase(bad["checks"].begin() + 4);
        }

        if (mode == 3) {
            bad["checks"][4]["actual"] = std::string(64, '0');
        }

        if (mode == 4) {
            bad["installed"][0]["mutable"] = true;
        }

        if (mode == 5) {
            bad["profile_sha256"] = std::string(64, '0');
        }

        if (mode == 6) {
            bad["android"]["images"]["system.img"]["sha256"] = std::string(64, '0');
        }

        if (mode == 7) {
            bad["mcu_property"]["capability"]["supported_fields"].push_back("target");
        }

        if (mode == 8) {
            bad["checks"].push_back(bad["checks"][4]);
        }

        if (mode == 9) {
            bad["mcu_property"]["helper"]["archive_sha256"] = std::string(64, '0');
        }

        if (mode == 10) {
            bad["checks"][1]["actual"] = "29";
        }

        if (mode == 11) {
            bad["mcu_property"]["helper"]["entry"] = "classes17.dex";
        }

        if (mode == 12) {
            bad["mcu_property"]["helper"]["artifact"] = "patched:Other";
        }

        if (mode == 13) {
            bad["mcu_property"]["helper"]["bytes"] = std::uint64_t{0};
        }

        if (mode == 14) {
            bad["mcu_property"]["helper"]["sha256"] = "invalid";
        }

        if (mode == 15) {
            bad["mcu_property"]["helper"]["contract"] = "foreign";
        }

        if (mode == 16) {
            bad["mcu_property"]["helper"]["bytes"] = std::uint64_t{(64ULL << 20) + 1};
        }

        rejects([&] {
            validate_passion_mcu_candidate(definition, bad, images, profile);
        });
    }

    auto x86_definition = definition;
    auto x86_candidate = candidate;
    test::use_signed_x86_guest(x86_definition, x86_candidate);
    x86_candidate["mcu_property"] = passion_mcu_contract(x86_definition, x86_candidate, apk,
                                                         candidate.at("mcu_property").at("helper"));
    const auto signed_images = x86_candidate.at("android").at("images");
    assert(validate_passion_mcu_candidate(x86_definition, x86_candidate, signed_images, profile) ==
           passion_mcu_capability());

    auto unsigned_candidate = x86_candidate;
    unsigned_candidate.erase("signed_android");
    rejects([&] {
        validate_passion_mcu_candidate(x86_definition, unsigned_candidate, signed_images, profile);
    });
    auto wrong_abi = x86_candidate;
    wrong_abi["android"]["abi"] = "arm64-v8a";
    rejects([&] {
        validate_passion_mcu_candidate(x86_definition, wrong_abi, signed_images, profile);
    });
    auto wrong_base = x86_definition;
    wrong_base["android"]["package"] = "system-images;android-29;default;x86_64";
    rejects([&] {
        validate_passion_mcu_candidate(wrong_base, x86_candidate, signed_images, profile);
    });
    auto absent_verity = x86_candidate;
    absent_verity["checks"].erase(absent_verity["checks"].end() - 1);
    rejects([&] {
        validate_passion_mcu_candidate(x86_definition, absent_verity, signed_images, profile);
    });
    auto extra_check = x86_candidate;
    extra_check["checks"].push_back(extra_check["checks"].back());
    rejects([&] {
        validate_passion_mcu_candidate(x86_definition, extra_check, signed_images, profile);
    });
    auto wrong_image = x86_candidate;
    wrong_image["signed_android"]["files"]["vendor.img"]["sha256"] = std::string(64, '9');
    rejects([&] {
        validate_passion_mcu_candidate(x86_definition, wrong_image, signed_images, profile);
    });

    auto old = definition;
    old["patches"]["MonzaCarService"]["steps"].erase(
            old["patches"]["MonzaCarService"]["steps"].begin() + 2);
    assert(!passion_mcu_requested(old));
    auto wrong = definition;
    wrong["patches"]["MonzaCarService"]["steps"].push_back("foreign.json");
    rejects([&] {
        passion_mcu_requested(wrong);
    });
    std::cout
            << "PASS partial capability cold guest/artifact/image/profile proof and old-graph disabled\n";
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
