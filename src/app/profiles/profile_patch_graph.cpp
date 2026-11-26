#include "profile_patch_graph.hpp"
#include "check.hpp"
#include "dex_instruction_patch.hpp"
#include "dex_method_redirect.hpp"
#include "error.hpp"
#include "file_patch.hpp"
#include "ordinary_path.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_file_nodes.hpp"
#include "profile_identity.hpp"
#include "quickboot.hpp"
#include <functional>
#include <map>
#include <set>
namespace voyemu {
namespace {
constexpr Check need{"PATCH_GRAPH"};

struct Recipe {
    const char *kind;
    const char *node;
    const char *entry;
    const char *source;
    const char *output;
};

const std::map<std::string, Recipe> &registered() {
    static const std::map<std::string, Recipe> value = {
            {"add-qg-runtime.json", {"qg-runtime", "", "lib/arm64-v8a/libqg_runtime.so", "", ""}},
            {"aiqiyi-netutil-ethernet-guard.json",
             {"launcher-ethernet", "Launcher", "classes3.dex",
              "458351aa5f7512e2920b2c4ad57adf0153c25f250fe3848c691876fd7fa89705",
              "844aa4798d771d7bd62c0850ecfe0d4d1e9b2ebd83afa348bd8c38087e4e2ff5"}},
            {"media-card-music-fix.json",
             {"launcher-media-redirect", "Launcher", "classes2.dex", launcher_media_source_sha256,
              launcher_media_output_sha256}},
            {"navi-gles-msaa.json",
             {"navi-msaa", "PateoNavi", "classes.dex",
              "f24e35ff5987ca00155badfe6ee83d1ea5b3aad2098549997aabc76763428b0c",
              "a43bed8ccbab8e9e980004ca38d30133381845a7f81fe97c0c7fcdce38be5efe"}}};

    return value;
}

const std::map<std::string, std::string> &file_node_inputs() {
    static const std::map<std::string, std::string> value = {
            {"can-early-policy-a9", "/system/etc/selinux/plat_sepolicy.cil"},
            {"can-early-file-contexts-a9", "/system/etc/selinux/plat_file_contexts"},
            {"can-early-property-contexts-a9", "/system/etc/selinux/plat_property_contexts"},
            {"can-simulator-policy-a9", "/system/etc/selinux/plat_sepolicy.cil"},
            {"can-simulator-contexts-a9", "/system/etc/selinux/plat_file_contexts"},
            {"ccodec-allocation-a9", "/system/lib64/libstagefright_ccodec.so"},
            {"disable-broadcastradio-a9",
             "/vendor/etc/init/android.hardware.broadcastradio@1.1-service.rc"},
            {"disable-incidentd-a9", "/system/etc/init/incidentd.rc"},
            {"disable-mediametrics-a9", "/system/etc/init/mediametrics.rc"},
            {"disable-perfprofd-a9", "/system/etc/init/perfprofd.rc"},
            {"disable-rild-a9", "/vendor/etc/init/rild.rc"},
            {"disable-statsd-a9", "/system/etc/init/statsd.rc"},
            {"selinux-canbus-a9", "/system/etc/selinux/plat_sepolicy.cil"},
            {"selinux-hash-a9", "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256"},
            {"selinux-property-contexts-a9", "/system/etc/selinux/plat_property_contexts"},
            {"selinux-service-contexts-a9", "/system/etc/selinux/plat_service_contexts"}};

    return value;
}

std::string category(const std::string &s) {
    if (s == "can-early-policy-a9.json" || s == "can-early-file-contexts-a9.json" ||
        s == "can-early-property-contexts-a9.json" || s == "can-simulator-policy-a9.json" ||
        s == "can-simulator-contexts-a9.json" || s == "ccodec-allocation-a9.json" ||
        s.starts_with("disable-") || s.starts_with("selinux-")) {
        return "native-file";
    }

    if (s == "music-arm64-libs.json" || s == "qgime-arm64-natives.json" ||
        s == "add-qg-runtime.json") {
        return "native-binary";
    }

    if (s == "systemservice-framework.json") {
        return "manifest-framework";
    }

    if (s == "ivoka-silent-foreground.json" || s == "navi-silent-foreground.json" ||
        s == "network-ap-host-stub.json" || s == "setting-framework-gaps.json" ||
        s == "settingnetwork-framework-gaps.json") {
        return "dex-control-flow";
    }

    return "dex-injection-or-rewrite";
}

void safe_relative(const std::string &s) {
    need(!s.empty() && s.size() <= 1024 && s.find_first_of("\\:\r\n\t") == std::string::npos,
         "safe relative source path");
    const std::filesystem::path p(s);
    need(!p.is_absolute() && p.lexically_normal() == p, "normalized source path");

    for (const auto &part : p) {
        need(part != ".." && part != ".", "source traversal");
    }
}

void ordinary(const std::filesystem::path &p) {
    ordinary_path(p, need, PathForm::Canonical, "canonical input required",
                  "linked source rejected");
}

std::string file_pin(const std::filesystem::path &p, std::size_t bound) {
    ordinary(p);
    need(std::filesystem::is_regular_file(p) && std::filesystem::hard_link_count(p) == 1 &&
                 std::filesystem::file_size(p) <= bound,
         "ordinary bounded source required");
    const auto epoch = cache_file_identity(p);
    const auto pin = sha256_file(p);
    need(cache_file_identity(p) == epoch, "source changed during hash");

    return pin;
}
} // namespace

Json plan_profile_patch_graph(const std::filesystem::path &root, std::string_view profile) {
    ordinary(root);
    need(valid_profile_name(profile), "safe profile name required");
    const auto directory = authoring_directory(root, profile);
    const auto checked_definition = [&] {
        return authoring_profile_bytes(root, profile, [&](const auto &path) {
            const auto pin = file_pin(path, 512 * 1024);
            const auto bytes = read_private_json_bytes(path, 512 * 1024);
            need(pin == sha256_bytes(bytes), "profile changed during read");

            return bytes;
        });
    };
    const auto definition_bytes = checked_definition();
    const auto definition = Json::parse(definition_bytes);
    need(definition.at("schema") == 1 && definition.at("patches").is_object() &&
                 definition.at("patches").size() <= 256,
         "bounded patch map required");
    const auto &patches = definition.at("patches");
    std::map<std::string, std::vector<std::string>> dependencies;
    std::map<std::string, int> colors;
    std::vector<std::string> order;

    for (auto it = patches.begin(); it != patches.end(); ++it) {
        need(valid_profile_name(it.key()), "safe node name");
        const auto &recipe = it.value();
        need(recipe.at("steps").is_array() && recipe.at("steps").size() <= 64,
             "bounded ordered steps required");
        need(recipe.at("type") == "apk" || recipe.at("type") == "file",
             "supported declaration type");
        std::vector<std::string> refs = {recipe.at("input").get<std::string>()};

        for (const auto &ref : recipe.value("uses", Json::array())) {
            refs.push_back(ref.get<std::string>());
        }

        for (const auto &ref : refs) {
            const auto colon = ref.find(':');
            need(colon != std::string::npos, "artifact reference required");
            const auto type = ref.substr(0, colon), name = ref.substr(colon + 1);

            if (type == "patched") {
                need(patches.contains(name), "missing patched dependency");
                dependencies[it.key()].push_back(name);
            } else if (type == "original") {
                need(definition.at("original").contains(name), "missing original dependency");
            } else if (type == "component") {
                need(definition.at("components").contains(name), "missing component dependency");
            } else {
                need(type == "android" && name.starts_with('/'), "unsupported artifact reference");
            }
        }
    }

    std::function<void(const std::string &)> visit = [&](const auto &name) {
        need(colors[name] != 1, "patch dependency cycle");

        if (colors[name] == 2) {
            return;
        }

        colors[name] = 1;

        for (const auto &dependency : dependencies[name]) {
            visit(dependency);
        }

        colors[name] = 2;
        order.push_back(name);
    };

    for (auto it = patches.begin(); it != patches.end(); ++it) {
        visit(it.key());
    }

    // The A9 CAN file recipes belong to qinggan09 on the 8155 board.
    const bool qinggan09 = record_declares(definition, ProfilePlatform::qinggan09,
                                           ProfileBoard::sa8155);
    Json nodes = Json::array(), missing_nodes = Json::array(), missing_steps = Json::array();
    std::map<std::string, bool> ready;
    std::size_t implemented_count = 0;
    Json all_source_pins = Json::object();

    for (const auto &name : order) {
        const auto &declaration = patches.at(name);
        Json steps = Json::array();
        bool complete = true, unknown_dex = false;
        std::map<std::string, std::string> entry_state;
        const auto input = declaration.at("input").get<std::string>();
        Json original_pin = nullptr;

        if (input.starts_with("original:")) {
            const auto &original = definition.at("original").at(input.substr(9));
            original_pin = original.at("sha256");
        }

        for (const auto &value : declaration.at("steps")) {
            const auto step = value.get<std::string>();
            safe_relative(step);
            const auto actual_pin = file_pin(directory / "patches" / step, 1024 * 1024);
            all_source_pins[step] = actual_pin;
            Json record = {{"name", step},
                           {"category", category(step)},
                           {"implemented", false},
                           {"composable", false}};
            const auto found = registered().find(step);

            if (declaration.at("type") == "file") {
                const auto node_input = file_node_inputs().find(name);
                const auto native_steps = native_file_patch_steps(name);
                Json expected = {{"type", "file"},
                                 {"input", node_input == file_node_inputs().end()
                                                   ? std::string{}
                                                   : "android:" + node_input->second},
                                 {"steps", native_steps}};

                if (name == "selinux-canbus-a9" || name == "can-simulator-policy-a9" ||
                    name == "can-early-policy-a9") {
                    expected["uses"] =
                            Json::array({"original:PlatSepolicy", "original:VendorSepolicy"});
                }

                if (name == "selinux-hash-a9") {
                    expected["uses"] = Json::array({patches.contains("can-early-policy-a9")
                                                            ? "patched:can-early-policy-a9"
                                                    : patches.contains("can-simulator-policy-a9")
                                                            ? "patched:can-simulator-policy-a9"
                                                            : "patched:selinux-canbus-a9"});
                }

                const bool base = definition.at("android").at("package") ==
                                  "system-images;android-28;default;arm64-v8a";
                const bool family =
                        name == "can-early-policy-a9"
                                ? (qinggan09 && !patches.contains("selinux-canbus-a9") &&
                                   !patches.contains("can-simulator-policy-a9"))
                        : name == "can-early-file-contexts-a9"
                                ? (qinggan09 && !patches.contains("can-simulator-contexts-a9"))
                        : name == "can-early-property-contexts-a9"
                                ? (qinggan09 && !patches.contains("selinux-property-contexts-a9"))
                        : name == "can-simulator-contexts-a9" ? qinggan09
                        : name == "can-simulator-policy-a9"
                                ? (qinggan09 && !patches.contains("selinux-canbus-a9"))
                                : true;
                const bool bound = base && family && node_input != file_node_inputs().end() &&
                                   file_steps().contains(step) && !native_steps.empty() &&
                                   declaration == expected;
                record["implemented"] = bound;
                record["composable"] = bound;
                record["dispatch"] = "native-file";
                record["recipe"] = name;
                record["step_index"] = steps.size();
                record["requires"] =
                        "validated native ext4 extraction receipts; OEM plat and vendor policy donors and patched CIL dependency where declared";

                if (bound) {
                    ++implemented_count;
                } else {
                    record["reason"] =
                            "file node declaration, base or source revision is not implemented";
                }
            } else if (found != registered().end()) {
                const auto &r = found->second;
                bool bound = declaration.at("type") == "apk" &&
                             declaration.value("sign", std::string{}) == "platform" &&
                             input == "original:" + name &&
                             (std::string(r.node).empty() || name == r.node);

                if (std::string(r.kind) == "qg-runtime") {
                    bool uses_runtime = false;

                    for (const auto &use : declaration.value("uses", Json::array())) {
                        uses_runtime = uses_runtime || use == "component:qg-runtime";
                    }

                    bound = bound && uses_runtime;
                }

                record["implemented"] = bound;
                record["dispatch"] = r.kind;
                record["entry"] = r.entry;

                if (!std::string(r.source).empty()) {
                    record["input_sha256"] = r.source;
                    record["output_sha256"] = r.output;
                    const auto previous = entry_state.find(r.entry);
                    const bool composition = !unknown_dex && (previous == entry_state.end() ||
                                                              previous->second == r.source);
                    record["composable"] = bound && composition;

                    if (bound && composition) {
                        entry_state[r.entry] = r.output;
                    } else {
                        record["reason"] =
                                "original DEX recipe cannot follow an unknown or incompatible preceding edit";
                    }
                } else {
                    record["composable"] = bound;
                    record["requires"] =
                            "validated native qg-runtime producer receipt and output pin";
                }

                if (!bound) {
                    record["reason"] =
                            "recipe source revision or profile binding is not implemented";
                }

                if (bound) {
                    ++implemented_count;
                }
            } else {
                record["reason"] = "native implementation missing";
            }

            if (!record.at("implemented").get<bool>() || !record.at("composable").get<bool>()) {
                complete = false;
                missing_steps.push_back({{"node", name},
                                         {"step", step},
                                         {"reason", record.value("reason", std::string{})}});
            }

            if (!record.at("implemented").get<bool>() && category(step).starts_with("dex-")) {
                unknown_dex = true;
            }

            steps.push_back(std::move(record));
        }

        for (const auto &dependency : dependencies[name]) {
            if (!ready[dependency]) {
                complete = false;
            }
        }

        ready[name] = complete;

        if (!complete) {
            missing_nodes.push_back(name);
        }

        nodes.push_back({{"name", name},
                         {"type", declaration.at("type")},
                         {"input", input},
                         {"original_sha256", original_pin},
                         {"dependencies", dependencies[name]},
                         {"steps", steps},
                         {"supported", complete}});
    }

    need(checked_definition() == definition_bytes, "profile changed during planning");

    for (auto it = all_source_pins.begin(); it != all_source_pins.end(); ++it) {
        need(file_pin(directory / "patches" / it.key(), 1024 * 1024) ==
                     it.value().get<std::string>(),
             "patch source changed during planning");
    }

    return {{"schema", 1},
            {"profile", profile},
            {"nodes", nodes},
            {"implemented_step_occurrences", implemented_count},
            {"missing_nodes", missing_nodes},
            {"missing_steps", missing_steps},
            {"patches_supported", missing_nodes.empty()},
            {"machine_ready", false},
            {"remaining_stages",
             Json::array({"component producers", "APK/DEX/framework missing steps",
                          "install/configure/verify", "QNX preparation",
                          "portable machine publication"})},
            {"host_java_required", false},
            {"host_node_required", false}};
}
} // namespace voyemu
