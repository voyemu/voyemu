#include "native_bridge.hpp"
#include "process.hpp"
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace voyemu;

namespace {
void check(bool value, const char *message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

bool rejected(const std::function<void()> &call, std::string_view message) {
    try {
        call();
    } catch (const std::exception &error) {
        const std::string_view text = error.what();

        return text.starts_with("NATIVE_BRIDGE: ") && text.find(message) != std::string::npos;
    }

    return false;
}

Json descriptor() {
    return {{"schema", 1},
            {"archive",
             {{"url", "https://dl.google.com/android/repository/sys-img/google_apis/x86_64.zip"},
              {"sha256", std::string(64, 'a')},
              {"member", "x86_64/system.img"},
              {"systemImageSha256", std::string(64, 'b')}}},
            {"files", {{"/system/lib64/libndk_translation.so", std::string(64, 'c')}}},
            {"propertyFiles",
             {{"/vendor/default.prop",
               {{"inputSha256", std::string(64, 'd')},
                {"outputSha256", std::string(64, 'e')},
                {"values", {{"ro.dalvik.vm.native.bridge", "libndk_translation.so"}}}}}}}};
}
} // namespace

int main(int argc, char **argv) {
    try {
        // A present key keeps its line; missing keys follow in key order after trailing blanks.
        const Json values = {
                {"ro.product.cpu.abilist", "x86_64,arm64-v8a"}, {"ro.b", "2"}, {"ro.a", "1"}};
        check(merge_android_properties("# base\nro.product.cpu.abilist=x86_64\nro.z=9\n\n\n",
                                       values) ==
                      "# base\nro.product.cpu.abilist=x86_64,arm64-v8a\nro.z=9\nro.a=1\nro.b=2\n",
              "merged properties differ");
        check(merge_android_properties("ro.a=0", {{"ro.a", "1"}}) == "ro.a=1\n",
              "a property file without a final newline merges differently");
        check(rejected(
                      [&] {
                          (void)merge_android_properties("ro.a=0\nro.a=1\n", {{"ro.a", "2"}});
                      },
                      "repeated property key: ro.a"),
              "a repeated key was merged");

        // The base names its bridge; a profile without one has none.
        const std::filesystem::path scratch = argc > 1 ? argv[1] : ".";
        const auto root = scratch / ("native-bridge-" + random_token());
        ensure_private_directory(root / "profiles/common/native-bridges");
        write_private_json(root / "profiles/common/native-bridges/fixture.json", descriptor());
        check(native_bridge_descriptor(root, {{"android", {{"package", "p"}}}}).is_null(),
              "a base without a bridge declared one");
        check(native_bridge_descriptor(root, {{"android", {{"native_bridge", "fixture"}}}}) ==
                      descriptor(),
              "the declared bridge descriptor differs");
        check(rejected(
                      [&] {
                          (void)native_bridge_descriptor(
                                  root, {{"android", {{"native_bridge", "missing"}}}});
                      },
                      "native bridge descriptor missing"),
              "a missing descriptor was accepted");

        for (const auto &[pointer, value] : std::vector<std::pair<std::string, Json>>{
                     {"/archive/url", "https://example.com/donor.zip"},
                     {"/files", Json::object()},
                     {"/propertyFiles/~1vendor~1default.prop/values/ro.dalvik.vm.native.bridge",
                      "a\nb"}}) {
            auto changed = descriptor();
            changed[Json::json_pointer(pointer)] = value;
            write_private_json(root / "profiles/common/native-bridges/changed.json", changed);
            check(rejected(
                          [&] {
                              (void)native_bridge_descriptor(
                                      root, {{"android", {{"native_bridge", "changed"}}}});
                          },
                          ""),
                  "an invalid bridge descriptor was accepted");
        }

        // The extracted tree must match its descriptor before it is installed.
        const auto tree = root / ".local/profiles/common/native-bridge" / std::string(64, 'a');
        ensure_private_directory(tree / "files/system/lib64");
        write_private_json(tree / "native-bridge.json", {{"schema", 1},
                                                         {"archive_sha256", std::string(64, 'a')},
                                                         {"files",
                                                          {{"/system/lib64/libndk_translation.so",
                                                            {{"sha256", sha256_bytes("bridge")},
                                                             {"bytes", 6},
                                                             {"mode", 0644},
                                                             {"uid", 0},
                                                             {"gid", 0}}}}}});
        {
            std::ofstream out(tree / "files/system/lib64/libndk_translation.so", std::ios::binary);
            out << "bridge";
        }
        auto pinned = descriptor();
        pinned["files"]["/system/lib64/libndk_translation.so"] = sha256_bytes("bridge");
        check(verify_native_bridge({pinned, tree / "files"}).at("files").size() == 1,
              "an exact bridge tree was rejected");
        check(rejected(
                      [&] {
                          (void)verify_native_bridge({descriptor(), tree / "files"});
                      },
                      "native bridge receipt entry differs"),
              "a bridge tree of other bytes was accepted");
        std::filesystem::remove_all(root);
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';

        return 1;
    }

    return 0;
}
