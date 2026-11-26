#include "base_image.hpp"
#include "download.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include <fstream>
#include <iostream>
using namespace voyemu;

int main(int argc, char **argv) {
    try {
        const auto qinggan09 =
                embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);
        const auto descriptor = embedded_profile(qinggan09).at("definition").at("android");

        if (native_base_api(descriptor) != 28) {
            throw std::runtime_error("A9 clean base API differs");
        }

        const auto api30 =
                embedded_profile("free-11-chinese-20260731-7.3.1").at("definition").at("android");

        if (argc == 3 && (std::string_view(argv[1]) == "--verify-api30-cache" ||
                          std::string_view(argv[1]) == "--verify-api28-cache")) {
            const auto result = verify_native_base_image(
                    std::string_view(argv[1]) == "--verify-api30-cache" ? api30 : descriptor,
                    std::filesystem::canonical(argv[2]));
            std::cout << Json{{"valid", true},
                              {"archive_required", false},
                              {"files", result.at("files").size()},
                              {"bytes", result.at("bytes")}}
                                 .dump()
                      << '\n';

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--fetch-api30") {
            const auto root = std::filesystem::canonical(argv[2]);
            const auto result = download_pinned({api30.at("url").get<std::string>(),
                                                 api30.at("sha256").get<std::string>(), 548363615},
                                                root / ".local/toolchains/downloads/native", false,
                                                24ULL << 30);
            std::cout << Json{{"file", result.file.string()},
                              {"bytes", result.bytes},
                              {"sha256", sha256_file(result.file)},
                              {"cached", result.cached},
                              {"native_https", true}}
                                 .dump()
                      << '\n';

            return 0;
        }

        if (argc == 4 && std::string_view(argv[1]) == "--prepare-api30") {
            std::cout << prepare_native_base_image(api30, std::filesystem::canonical(argv[2]),
                                                   std::filesystem::path(argv[3]), 24ULL << 30)
                                 .dump(2)
                      << '\n';

            return 0;
        }

        auto x86 = api30;
        x86["package"] = "system-images;android-30;default;x86_64";
        x86["url"] = "https://dl.google.com/android/repository/sys-img/android/x86_64-30_r11.zip";

        if (native_base_identity(x86).abi != "x86_64" || native_base_api(x86) != 30 ||
            native_base_identity(api30).abi != "arm64-v8a") {
            throw std::runtime_error("clean Android API/ABI mismatch");
        }

        const auto accelerated = [](const Json &image, const Json &acceleration) {
            return Json{{"android", image}, {"emulator", {{"acceleration", acceleration}}}};
        };

        if (android_acceleration_required({{"android", api30}}) ||
            !android_acceleration_required(accelerated(api30, "required")) ||
            !android_acceleration_required(accelerated(x86, "required")) ||
            android_guest_abi({{"android", x86}}) != "x86_64" ||
            android_guest_abi(Json::object()) != "arm64-v8a") {
            throw std::runtime_error("guest ABI or acceleration contract differs");
        }

        bool refused = false;
        try {
            (void)android_acceleration_required(accelerated(x86, "kvm"));
        } catch (const VoyemuError &) {
            refused = true;
        }

        if (!refused) {
            throw std::runtime_error("host-specific acceleration value accepted");
        }

        // Acceleration follows the guest ABI, never a host or target name.
        if (!android_hardware_acceleration(os::host_android_abi) ||
            android_hardware_acceleration("unknown-abi")) {
            throw std::runtime_error("hardware acceleration differs from the host ABI");
        }

        if (native_base_api(api30) != 30) {
            throw std::runtime_error("registered API30 descriptor rejected");
        }

        for (const auto &package : {"system-images;android-29;default;arm64-v8a",
                                    "system-images;android-30;default;x86_64",
                                    "system-images;android-30;default;armeabi-v7a"}) {
            auto wrong = api30;
            wrong["package"] = package;
            bool rejected = false;
            try {
                native_base_api(wrong);
            } catch (...) {
                rejected = true;
            }

            if (!rejected) {
                throw std::runtime_error("wrong clean base API/ABI accepted");
            }
        }

        // The contents of the clean base are pinned only in the clean_base object of profile.json.
        if (api30.at("clean_base").at("images").at("system.img") !=
                    native_base_pin(api30, "images", "system.img") ||
            native_clean_base(descriptor).boot_files.size() != 4 ||
            native_clean_base(api30).boot_files.size() != 6) {
            throw std::runtime_error("clean base pins differ from profile.json");
        }

        auto unpinned = api30;
        unpinned.erase("clean_base");
        auto malformed = api30;
        malformed["clean_base"]["boot_files"]["kernel-ranchu"] = "wrong";

        for (const auto &value : {unpinned, malformed}) {
            bool rejected = false;
            try {
                native_clean_base(value);
            } catch (const std::exception &error) {
                rejected = std::string_view(error.what()).starts_with("BASE_DESCRIPTOR:");
            }

            if (!rejected || native_base_api(value) != 30) {
                throw std::runtime_error("missing or malformed clean base pins accepted");
            }
        }

        bool unknown_rejected = false;
        try {
            native_base_pin(api30, "images", "userdata.img");
        } catch (const std::exception &error) {
            unknown_rejected = std::string_view(error.what()).starts_with("BASE_DESCRIPTOR:");
        }

        if (!unknown_rejected) {
            throw std::runtime_error("clean base file without a pin accepted");
        }

        for (const auto &field : {"package", "revision", "url", "sha256"}) {
            auto wrong = api30;
            wrong[field] = "wrong";
            bool rejected = false;
            try {
                native_base_api(wrong);
            } catch (...) {
                rejected = true;
            }

            if (!rejected) {
                throw std::runtime_error("mixed API30 descriptor accepted");
            }
        }

        if (argc == 4 && std::string_view(argv[1]) == "--prepare") {
            std::cout << prepare_native_base_image(descriptor, std::filesystem::canonical(argv[2]),
                                                   std::filesystem::path(argv[3]))
                                 .dump(2)
                      << '\n';

            return 0;
        }

        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-base-" + random_token());
        ensure_private_directory(root);
        struct Cleanup {
            std::filesystem::path path;

            ~Cleanup() {
                std::filesystem::remove_all(path);
            }
        } cleanup{root};

        for (unsigned mode = 0; mode < 3; ++mode) {
            auto value = descriptor;

            if (mode == 0) {
                value["package"] = "system-images;android-29;default;arm64-v8a";
            }

            if (mode == 1) {
                value["revision"] = "latest";
            }

            if (mode == 2) {
                value["sha256"] = "missing";
            }

            bool rejected = false;
            try {
                prepare_native_base_image(value, root / "missing.zip", root / "base", 0);
            } catch (const std::exception &error) {
                rejected = std::string_view(error.what()).starts_with("BASE_DESCRIPTOR:");
            }

            if (!rejected || std::filesystem::exists(root / "base")) {
                throw std::runtime_error("unsupported or unpinned base created output");
            }
        }

        const auto receipt_fixture = std::filesystem::path(__FILE__).parent_path() /
                                     "fixtures/api30-base-receipt.json";
        const auto receipt = read_private_json(receipt_fixture, 512 * 1024);

        for (unsigned mode = 0; mode < 4; ++mode) {
            const auto cache = root / ("cached-" + std::to_string(mode));
            ensure_private_directory(cache);

            if (mode) {
                std::filesystem::copy_file(receipt_fixture, cache / "base.json");

                if (mode == 2) {
                    const auto first = receipt.at("files").begin();
                    const auto file = cache / first.key();
                    ensure_private_directory(file.parent_path());
                    std::ofstream bad(file, std::ios::binary);
                    const std::string bytes(first.value().at("bytes").get<std::size_t>(), '\0');
                    bad.write(bytes.data(), bytes.size());
                }

                if (mode == 3) {
                    auto forged = receipt;
                    forged["files"]["system.img"]["sha256"] = std::string(64, '0');
                    write_private_json(cache / "base.json", forged);
                }
            }

            bool rejected = false;
            try {
                verify_native_base_image(api30, cache);
            } catch (const std::exception &e) {
                rejected = std::string_view(e.what()).starts_with("BASE_CACHE:");
            }

            if (!rejected) {
                throw std::runtime_error("missing, corrupt or forged extracted base accepted");
            }

            if (std::filesystem::exists(cache / "archive.zip")) {
                throw std::runtime_error("cache validation invented an archive");
            }
        }

        // A cache extracted from another archive or with another receipt than profile.json pins.
        auto wrong_cache_pin = api30;
        wrong_cache_pin["sha256"] = std::string(64, '0');
        auto wrong_receipt_pin = api30;
        wrong_receipt_pin["clean_base"]["receipt_sha256"] = std::string(64, '0');

        for (const auto &[value, reason] :
             {std::pair{wrong_cache_pin, "BASE_CACHE: registered extraction identity differs"},
              std::pair{wrong_receipt_pin, "BASE_CACHE: registered extraction receipt differs"}}) {
            std::string error;
            try {
                verify_native_base_image(value, root / "cached-1");
            } catch (const std::exception &e) {
                error = e.what();
            }

            if (error != reason) {
                throw std::runtime_error("unregistered cached base identity accepted");
            }
        }

        std::cout << "native clean base descriptor guards passed\n";

        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }
}
