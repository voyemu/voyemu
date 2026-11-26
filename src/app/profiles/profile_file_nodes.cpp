#include "profile_file_nodes.hpp"
#include "apk_base.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "codec_timing.hpp"
#include "error.hpp"
#include "init_patch.hpp"
#include "ordinary_path.hpp"
#include "original_navi_candidate.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_identity.hpp"
#include "profile_originals.hpp"
#include "quickboot.hpp"
#include "selinux_patch.hpp"
#include <fstream>
#include <map>
#include <set>
namespace voyemu {
namespace {
constexpr Check need{"PROFILE_FILE"};
constexpr ProfileScope qinggan09_scope{ProfilePlatform::qinggan09, ProfileBoard::sa8155};

void ordinary(const std::filesystem::path &path) {
    ordinary_path(path, need, PathForm::Canonical, "canonical input required",
                  "linked ancestor rejected");
}

const std::map<std::string, std::string> &input_paths() {
    static const std::map<std::string, std::string> value = {
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
} // namespace

const std::set<std::string> &file_steps() {
    static const std::set<std::string> value = {"can-early-policy-a9.json",
                                                "can-early-file-contexts-a9.json",
                                                "can-early-property-contexts-a9.json",
                                                "can-simulator-policy-a9.json",
                                                "can-simulator-contexts-a9.json",
                                                "ccodec-allocation-a9.json",
                                                "disable-broadcastradio-a9.json",
                                                "disable-incidentd-a9.json",
                                                "disable-mediametrics-a9.json",
                                                "disable-perfprofd-a9.json",
                                                "disable-rild-a9.json",
                                                "disable-statsd-a9.json",
                                                "selinux-bounded-su-a9.json",
                                                "selinux-canbus-a9.json",
                                                "selinux-hash.json",
                                                "selinux-property-contexts-a9.json",
                                                "selinux-service-contexts-a9.json"};

    return value;
}

ProfileFileNodes plan_profile_codec_file_node(const std::filesystem::path &root,
                                              std::string_view profile,
                                              const std::filesystem::path &system) {
    ordinary(root);
    ordinary(system);
    std::map<std::filesystem::path, std::pair<Json, std::string>> tracked;
    auto read = [&](const std::filesystem::path &path, std::uint64_t maximum) {
        ordinary(path);
        need(std::filesystem::is_regular_file(path) &&
                     std::filesystem::hard_link_count(path) == 1 &&
                     std::filesystem::file_size(path) <= maximum,
             "ordinary bounded codec source required");
        const auto epoch = cache_file_identity(path);
        std::ifstream input(path, std::ios::binary);
        std::string bytes((std::istreambuf_iterator<char>(input)), {});
        need(bytes.size() <= maximum && sha256_file(path) == sha256_bytes(bytes) &&
                     cache_file_identity(path) == epoch,
             "codec source changed during read");
        tracked[path] = {epoch, sha256_bytes(bytes)};

        return bytes;
    };
    const auto definition =
            Json::parse(authoring_profile_bytes(root, profile, [&](const auto &path) {
                return read(path, 512 * 1024);
            }));
    const auto directory = authoring_directory(root, profile);
    need(profile_scope(definition) == qinggan09_scope && definition.at("schema") == 1 &&
                 native_base_api(definition.at("android")) == 28,
         "registered clean A9 codec base required");
    const std::string id = "ccodec-allocation-a9",
                      target = "/system/lib64/libstagefright_ccodec.so", step = id + ".json";
    need(definition.at("patches").at(id) == Json({{"type", "file"},
                                                  {"input", "android:" + target},
                                                  {"steps", Json::array({step})}}),
         "exact codec node declaration required");
    unsigned installed = 0;

    for (const auto &entry : definition.at("install")) {
        if (entry.value("artifact", std::string{}) == "patched:" + id) {
            need(entry == Json({{"artifact", "patched:" + id},
                                {"type", "file"},
                                {"target", target},
                                {"mode", "0644"}}),
                 "exact codec install required");
            ++installed;
        }
    }

    need(installed == 1, "one codec install required");
    need(file_steps().contains(step), "codec step not registered");
    (void)read(directory / "patches" / step, 128 * 1024);
    const auto receipt_bytes = read(system / "receipt.json", 128 * 1024);
    const auto receipt = Json::parse(receipt_bytes);
    need(receipt.at("schema") == 1 && receipt.at("native") == true &&
                 receipt.at("filesystem_mounted") == false &&
                 receipt.at("image_sha256") ==
                         native_base_pin(definition.at("android"), "images", "system.img") &&
                 receipt.at("files").is_object() && receipt.at("files").size() <= 256,
         "native pinned A9 codec extraction required");
    const auto input = system / "system/lib64/libstagefright_ccodec.so";
    const auto bytes = read(input, 632488);
    const auto input_pin = sha256_bytes(bytes);
    const auto &extracted = receipt.at("files").at("system/lib64/libstagefright_ccodec.so");
    need(extracted.at("sha256") == input_pin && extracted.at("bytes") == bytes.size(),
         "codec extraction entry differs");
    const auto transformed = android_codec_timing_patch(bytes);
    PinnedFilePatch patch{id, 28, input, input_pin, sha256_bytes(transformed.bytes)};
    patch.profile = runtime_profile_reference(definition, profile);
    patch.scope = profile_scope(definition);
    ProfileFileNodes result;
    result.patches.push_back(std::move(patch));
    result.provenance = {{"schema", 1},
                         {"profile", profile},
                         {"native", true},
                         {"native_scope", "api28-codec-only"},
                         {"machine_ready", false},
                         {"system_image_sha256", receipt.at("image_sha256")},
                         {"extraction_receipt_sha256", sha256_bytes(receipt_bytes)},
                         {"nodes",
                          {{id,
                            {{"input_sha256", input_pin},
                             {"output_sha256", result.patches.front().output_sha256},
                             {"target", target}}}}}};
    result.revalidate = [tracked] {
        for (const auto &[path, value] : tracked) {
            need(cache_file_identity(path) == value.first && sha256_file(path) == value.second,
                 "bound codec input changed");
        }
    };
    result.revalidate();

    return result;
}

ProfileFileNodes plan_profile_file_nodes(const std::filesystem::path &root,
                                         std::string_view profile,
                                         const std::filesystem::path &system,
                                         const std::filesystem::path &vendor,
                                         std::string_view build_target) {
    ordinary(root);
    need(valid_profile_name(profile), "safe profile name required");
    ordinary(system);
    std::map<std::filesystem::path, std::pair<Json, std::string>> tracked;
    auto read = [&](const std::filesystem::path &path, std::uint64_t maximum) {
        ordinary(path);
        need(std::filesystem::is_regular_file(path) &&
                     std::filesystem::hard_link_count(path) == 1 &&
                     std::filesystem::file_size(path) <= maximum,
             "ordinary bounded input required");
        const auto epoch = cache_file_identity(path);
        std::ifstream stream(path, std::ios::binary);
        std::string bytes((std::istreambuf_iterator<char>(stream)), {});
        need(bytes.size() <= maximum && sha256_file(path) == sha256_bytes(bytes) &&
                     cache_file_identity(path) == epoch,
             "input changed during read");
        tracked[path] = {epoch, sha256_bytes(bytes)};

        return bytes;
    };
    const auto definition = Json::parse(authoring_profile_bytes(
            root, profile,
            [&](const auto &path) {
                return read(path, 512 * 1024);
            },
            build_target));
    const auto directory = authoring_directory(root, profile);
    const bool rooted_observer = qinggan11_ui_observer_policy_requested(definition);

    if (native_base_api(definition.at("android")) == 30) {
        const bool passion = record_declares(definition, ProfilePlatform::passion,
                                             ProfileBoard::sa8155),
                   qinggan11 = record_declares(definition, ProfilePlatform::qinggan11,
                                               ProfileBoard::sa8155);
        const auto recipes = api30_file_recipes_for_profile(definition);
        std::size_t policy_index = passion ? 0U : 1U;

        for (std::size_t i = 0; i < recipes.size(); ++i) {
            if (std::string_view(recipes[i].id) == "can-early-policy-api30") {
                policy_index = i;
            }
        }

        need(!(passion || qinggan11) || definition.at("id") == profile,
             "Scoped API30 source profile identity differs");
        std::size_t files = 0;

        for (const auto &node : definition.at("patches")) {
            if (node.at("type") == "file") {
                ++files;
            }
        }

        need((!passion && !qinggan11 && files == 1) || files == recipes.size(),
             "API30 native file graph must be exact NVRAM or cockpit policy set");
        const auto receipt_bytes = read(system / "receipt.json", 128 * 1024);
        const auto receipt = Json::parse(receipt_bytes);
        const auto clean = native_clean_base(definition.at("android"));
        need(receipt.at("schema") == 1 && receipt.at("native") == true &&
                     receipt.at("filesystem_mounted") == false &&
                     receipt.at("image_sha256") == clean.pin("images", "system.img") &&
                     receipt.at("logical_partition") == "system" &&
                     receipt.at("lp_metadata_sha256") == clean.metadata_sha256 &&
                     receipt.at("partition_offset") == clean.system.offset &&
                     receipt.at("logical_partition_bytes") == clean.system.bytes,
             "API30 logical platform extraction receipt required");
        ProfileFileNodes result;
        Json nodes = Json::object();

        for (std::size_t i = 0; i < files; ++i) {
            const auto &spec = recipes[i];
            const std::string name(spec.id), step = name + ".json", target(spec.target),
                                             member = target.substr(1);
            Json expected = {{"type", "file"},
                             {"input", "android:" + target},
                             {"steps", Json(native_file_patch_steps(name))}};

            const bool bounded = qinggan11 && (name == "can-simulator-policy-api30" ||
                                               name == "can-early-policy-api30");

            if (name == recipes.back().id) {
                expected["uses"] = Json::array({"patched:" + std::string(recipes[policy_index].id),
                                                "android:/system/etc/selinux/mapping/30.0.cil"});
            }

            if (bounded) {
                expected["uses"] =
                        Json::array({"original:SystemExtSepolicy", "original:VendorSepolicy"});
            }

            need(definition.at("patches").at(name) == expected,
                 "API30 native node declaration differs");
            const auto step_bytes = read(directory / "patches" / step, 128 * 1024);
            const bool observer_node = rooted_observer && (name == "can-early-policy-api30" ||
                                                           name == "selinux-hash-api30");

            if (observer_node) {
                const auto recipe = Json::parse(step_bytes);
                need(recipe.at("schema") == 1 && recipe.at("api") == 30 &&
                             recipe.at("native") == true &&
                             recipe.at("output_sha256") == spec.output_sha256,
                     "rooted UI observer recipe output pin differs");
            }

            const auto input = read(system / member, 4ULL << 20);
            need(sha256_bytes(input) == spec.input_sha256 &&
                         receipt.at("files").at(member).at("sha256") == spec.input_sha256 &&
                         receipt.at("files").at(member).at("bytes") == input.size(),
                 "API30 platform native input differs");
            const bool intermediate = name == "can-simulator-contexts-api30" ||
                                      name == "can-simulator-policy-api30";
            bool installed = false;

            for (const auto &install : definition.at("install")) {
                if (install.value("artifact", std::string{}) == "patched:" + name) {
                    need(!installed && install == Json({{"artifact", "patched:" + name},
                                                        {"type", "file"},
                                                        {"target", target},
                                                        {"mode", "0644"}}),
                         "API30 native install differs");
                    installed = true;
                }
            }

            need(installed || intermediate, "API30 native install missing");
            PinnedFilePatch patch{name, 30, system / member, std::string(spec.input_sha256),
                                  std::string(spec.output_sha256)};
            patch.original_navi = original_navi_requested(definition);
            patch.ui_observer_root_accessibility = observer_node;

            if (bounded) {
                auto donor = [&](const char *role, const char *file) {
                    const auto &original = definition.at("original").at(role);
                    need(original.at("file") == file, "OEM policy path");
                    const auto path = profile_originals_directory(root, profile) / file;
                    const auto hash = sha256_bytes(read(path, 32ULL << 20));
                    need(original.at("sha256") == hash, "OEM policy pin mismatch");

                    return PinnedFileDependency{path, hash};
                };
                patch.donor = donor("SystemExtSepolicy", "policy/system_ext_sepolicy.cil");
                patch.vendor_donor = donor("VendorSepolicy", "policy/vendor_sepolicy.cil");
            }

            if (name == "original-navi-selinux") {
                original_navi_preflight(definition, 30);
                const auto apk = profile_originals_directory(root, profile) / "Navi.apk";
                ordinary(apk);
                const auto epoch = cache_file_identity(apk);
                const auto cert = pinned_apk_v2_certificate(apk, std::string(original_navi_sha));
                need(sha256_bytes(cert) == original_navi_cert, "original Navi certificate differs");
                tracked[apk] = {epoch, std::string(original_navi_sha)};
                patch.certificate_apk = PinnedFileDependency{apk, std::string(original_navi_sha)};
            }

            if (name == recipes.back().id) {
                const std::string mapping = "system/etc/selinux/mapping/30.0.cil",
                                  mapping_pin = native_base_pin(definition.at("android"), "files",
                                                                "/" + mapping);
                const auto bytes = read(system / mapping, 1024 * 1024);
                need(sha256_bytes(bytes) == mapping_pin &&
                             receipt.at("files").at(mapping).at("sha256") == mapping_pin &&
                             receipt.at("files").at(mapping).at("bytes") == bytes.size(),
                     "API30 mapping input differs");
                patch.donor = PinnedFileDependency{system / mapping, mapping_pin};
                patch.patched_dependency = std::string(recipes[policy_index].id);
                patch.dependency_sha256 = std::string(recipes[policy_index].output_sha256);
            }

            if (passion ||
                (qinggan11 &&
                 (name == "selinux-hash-api30" || name == "can-simulator-contexts-api30" ||
                  name == "can-early-file-contexts-api30" || name == "can-simulator-policy-api30" ||
                  name == "can-early-policy-api30" || name == "can-early-property-contexts-api30" ||
                  name == "selinux-services-api30")) ||
                name == "public-qg-runtime-api30" || name == "property-contexts-api30" ||
                name == "keymanager-contexts-api30" || name == "original-navi-selinux") {
                patch.profile = runtime_profile_reference(definition, profile);
                patch.scope = profile_scope(definition);
            }

            result.patches.push_back(std::move(patch));
            nodes[name] = {{"input_sha256", spec.input_sha256},
                           {"output_sha256", spec.output_sha256},
                           {"target", target}};
        }

        const auto outputs = prepare_file_patches(result.patches);
        need(outputs.size() == files, "API30 native output count differs");
        result.provenance = {{"schema", 1},
                             {"profile", profile},
                             {"native", true},
                             {"file_nodes_supported", true},
                             {"machine_ready", false},
                             {"system_image_sha256", receipt.at("image_sha256")},
                             {"extraction_receipt_sha256", sha256_bytes(receipt_bytes)},
                             {"nodes", nodes}};
        result.revalidate = [tracked] {
            for (const auto &[path, value] : tracked) {
                need(cache_file_identity(path) == value.first && sha256_file(path) == value.second,
                     "bound API30 file input changed");
            }
        };
        result.revalidate();

        return result;
    }

    ordinary(vendor);
    need(definition.at("schema") == 1 && native_base_api(definition.at("android")) == 28,
         "registered clean A9 base required");
    const auto system_receipt = Json::parse(read(system / "receipt.json", 128 * 1024)),
               vendor_receipt = Json::parse(read(vendor / "receipt.json", 128 * 1024));
    auto receipt = [&](const Json &value, const std::string &hash) {
        need(value.at("schema") == 1 && value.at("native") == true &&
                     value.at("filesystem_mounted") == false && value.at("image_sha256") == hash &&
                     value.at("files").is_object() && value.at("files").size() <= 256,
             "native pinned ext4 extraction receipt required");
    };
    receipt(system_receipt, native_base_pin(definition.at("android"), "images", "system.img"));
    receipt(vendor_receipt, native_base_pin(definition.at("android"), "images", "vendor.img"));
    ProfileFileNodes result;
    Json inputs = Json::object();
    std::map<std::string, std::string> candidates;
    std::size_t observed = 0;
    auto selected_input_paths = input_paths();

    if (definition.at("patches").contains("can-early-file-contexts-a9")) {
        need(profile_scope(definition) == qinggan09_scope,
             "early file contexts require A9 reference family");
        need(!definition.at("patches").contains("can-simulator-contexts-a9"),
             "early contexts replace existing context node");
        selected_input_paths.emplace("can-early-file-contexts-a9",
                                     "/system/etc/selinux/plat_file_contexts");
    }

    if (definition.at("patches").contains("can-simulator-contexts-a9")) {
        need(profile_scope(definition) == qinggan09_scope,
             "simulator contexts require A9 reference family");
        selected_input_paths.emplace("can-simulator-contexts-a9",
                                     "/system/etc/selinux/plat_file_contexts");
    }

    if (definition.at("patches").contains("can-early-property-contexts-a9")) {
        need(profile_scope(definition) == qinggan09_scope,
             "early property requires A9 reference family");
        need(!definition.at("patches").contains("selinux-property-contexts-a9"),
             "early property replaces stock property node");
        selected_input_paths.erase("selinux-property-contexts-a9");
        selected_input_paths.emplace("can-early-property-contexts-a9",
                                     "/system/etc/selinux/plat_property_contexts");
    }

    if (definition.at("patches").contains("can-early-policy-a9")) {
        need(profile_scope(definition) == qinggan09_scope,
             "early policy requires A9 reference family");
        need(!definition.at("patches").contains("selinux-canbus-a9") &&
                     !definition.at("patches").contains("can-simulator-policy-a9"),
             "early policy replaces existing policy node");
        selected_input_paths.erase("selinux-canbus-a9");
        selected_input_paths.emplace("can-early-policy-a9",
                                     "/system/etc/selinux/plat_sepolicy.cil");
    }

    if (definition.at("patches").contains("can-simulator-policy-a9")) {
        need(profile_scope(definition) == qinggan09_scope,
             "simulator policy requires A9 reference family");
        need(!definition.at("patches").contains("selinux-canbus-a9"),
             "simulator policy replaces stock policy node");
        selected_input_paths.erase("selinux-canbus-a9");
        selected_input_paths.emplace("can-simulator-policy-a9",
                                     "/system/etc/selinux/plat_sepolicy.cil");
    }

    std::vector<std::string> order;

    for (const auto &[name, path] : selected_input_paths) {
        if (name != "selinux-hash-a9") {
            order.push_back(name);
        }
    }

    order.push_back("selinux-hash-a9");

    for (auto it = definition.at("patches").begin(); it != definition.at("patches").end(); ++it) {
        if (it.value().at("type") == "file") {
            need(selected_input_paths.contains(it.key()), "unsupported non-APK profile node");
            ++observed;
        }
    }

    need(observed == selected_input_paths.size(), "all registered non-APK nodes required");

    for (const auto &name : order) {
        const auto &node = definition.at("patches").at(name);
        const auto &path = selected_input_paths.at(name);
        const auto expected_steps = native_file_patch_steps(name);
        need(!expected_steps.empty(), "native recipe missing");
        Json expected = {{"type", "file"}, {"input", "android:" + path}, {"steps", expected_steps}};

        if (name == "selinux-canbus-a9" || name == "can-simulator-policy-a9" ||
            name == "can-early-policy-a9") {
            expected["uses"] = Json::array({"original:PlatSepolicy", "original:VendorSepolicy"});
        }

        if (name == "selinux-hash-a9") {
            expected["uses"] =
                    Json::array({selected_input_paths.contains("can-early-policy-a9")
                                         ? "patched:can-early-policy-a9"
                                 : selected_input_paths.contains("can-simulator-policy-a9")
                                         ? "patched:can-simulator-policy-a9"
                                         : "patched:selinux-canbus-a9"});
        }

        need(node == expected, "file node declaration differs from native recipe");

        for (const auto &step : expected_steps) {
            need(file_steps().contains(step), "step not registered");
            (void)read(directory / "patches" / step, 128 * 1024);
        }

        const bool vendor_path = path.starts_with("/vendor/");
        const auto &extraction = vendor_path ? vendor : system;
        const auto &extraction_receipt = vendor_path ? vendor_receipt : system_receipt;
        // System image is system-as-root; vendor image has /etc at its filesystem root.
        const auto relative = vendor_path ? path.substr(8) : path.substr(1);
        const auto &entry = extraction_receipt.at("files").at(relative);
        const auto bytes = read(extraction / relative, 32ULL << 20);
        const auto hash = sha256_bytes(bytes);
        need(entry.at("sha256") == hash && entry.at("bytes") == bytes.size(),
             "extracted file differs from receipt");
        PinnedFilePatch patch{name, 28, extraction / relative, hash, {}};
        std::string output;

        if (name == "can-early-file-contexts-a9") {
            patch.profile = runtime_profile_reference(definition, profile);
            patch.scope = profile_scope(definition);
            output = apply_can_early_file_context_patch(
                    *patch.scope, 28, apply_can_simulator_context_patch(*patch.scope, 28, bytes));
        } else if (name == "can-early-property-contexts-a9") {
            patch.profile = runtime_profile_reference(definition, profile);
            patch.scope = profile_scope(definition);
            output = apply_can_early_property_patch(
                    *patch.scope, 28,
                    apply_selinux_context_patch("selinux-property-contexts-a9", 28, bytes));
        } else if (name == "can-simulator-contexts-a9") {
            patch.profile = runtime_profile_reference(definition, profile);
            patch.scope = profile_scope(definition);
            output = apply_can_simulator_context_patch(*patch.scope, 28, bytes);
        } else if (name == "ccodec-allocation-a9") {
            patch.profile = runtime_profile_reference(definition, profile);
            patch.scope = profile_scope(definition);
            need(profile_scope(definition) == qinggan09_scope, "exact A9 codec profile required");
            output = android_codec_timing_patch(bytes).bytes;
        } else if (name == "selinux-canbus-a9" || name == "can-simulator-policy-a9" ||
                   name == "can-early-policy-a9") {
            auto donor = [&](const char *role, const char *file) {
                const auto &original = definition.at("original").at(role);
                need(original.at("file") == file, "OEM policy path");
                const auto path = profile_originals_directory(root, profile) / file;
                auto content = read(path, 32ULL << 20);
                const auto hash = sha256_bytes(content);
                need(original.at("sha256") == hash, "OEM policy pin mismatch");

                return std::pair{PinnedFileDependency{path, hash}, std::move(content)};
            };
            auto [plat, plat_bytes] = donor("PlatSepolicy", "policy/plat_sepolicy.cil");
            auto [oem_vendor, vendor_bytes] = donor("VendorSepolicy", "policy/vendor_sepolicy.cil");
            patch.donor = std::move(plat);
            patch.vendor_donor = std::move(oem_vendor);
            output = apply_bounded_canbus_policy(28, bytes, plat_bytes, vendor_bytes).cil;

            if (name != "selinux-canbus-a9") {
                patch.profile = runtime_profile_reference(definition, profile);
                patch.scope = profile_scope(definition);
                output = apply_can_simulator_policy_patch(*patch.scope, 28, output);

                if (name == "can-early-policy-a9") {
                    output = apply_can_early_policy_patch(*patch.scope, 28, output);
                }
            }
        } else if (name == "selinux-hash-a9") {
            patch.patched_dependency = selected_input_paths.contains("can-early-policy-a9")
                                               ? "can-early-policy-a9"
                                       : selected_input_paths.contains("can-simulator-policy-a9")
                                               ? "can-simulator-policy-a9"
                                               : "selinux-canbus-a9";
            patch.dependency_sha256 = sha256_bytes(candidates.at(patch.patched_dependency));
            output = apply_selinux_context_patch(name, 28, candidates.at(patch.patched_dependency));
        } else {
            output = name.starts_with("disable-") ? apply_init_patch(name, 28, bytes)
                                                  : apply_selinux_context_patch(name, 28, bytes);
        }

        patch.output_sha256 = sha256_bytes(output);
        candidates[name] = std::move(output);
        inputs[name] = {
                {"input_sha256", hash}, {"output_sha256", patch.output_sha256}, {"target", path}};
        result.patches.push_back(std::move(patch));
        bool installed = false;

        for (const auto &install : definition.at("install")) {
            if (install.value("artifact", std::string{}) == "patched:" + name) {
                need(!installed && install == Json({{"artifact", "patched:" + name},
                                                    {"type", "file"},
                                                    {"target", path},
                                                    {"mode", "0644"}}),
                     "file install declaration mismatch");
                installed = true;
            }
        }

        need(installed, "file install declaration missing");
    }

    const auto verified = prepare_file_patches(result.patches);

    for (std::size_t i = 0; i < result.patches.size(); ++i) {
        need(sha256_bytes(verified[i]) == result.patches[i].output_sha256,
             "native graph output differs");
    }

    result.provenance = {{"schema", 1},
                         {"profile", profile},
                         {"nodes", inputs},
                         {"native", true},
                         {"file_nodes_supported", true},
                         {"machine_ready", false},
                         {"system_image_sha256", system_receipt.at("image_sha256")},
                         {"vendor_image_sha256", vendor_receipt.at("image_sha256")}};
    result.revalidate = [tracked] {
        for (const auto &[path, value] : tracked) {
            need(cache_file_identity(path) == value.first && sha256_file(path) == value.second,
                 "bound file input changed");
        }
    };
    result.revalidate();

    return result;
}
} // namespace voyemu
