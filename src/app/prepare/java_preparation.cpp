#include "java_preparation.hpp"
#include "apk_base.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "error.hpp"
#include "java_toolchain.hpp"
#include "native_component.hpp"
#include "original_navi_candidate.hpp"
#include "os/fs.hpp"
#include "os/platform.hpp"
#include "passion_generated_helper.hpp"
#include "process.hpp"
#include "profile_build.hpp"
#include "profile_catalog.hpp"
#include "profile_file_nodes.hpp"
#include "profile_identity.hpp"
#include "project_files.hpp"
#include "quickboot.hpp"
#include "selinux_patch.hpp"
#include "zip_archive.hpp"
#include <fstream>
#include <regex>
#include <set>
namespace voyemu {
namespace {
constexpr Check need{"JAVA_PREPARATION"};

void path(const std::filesystem::path &p) {
    need(p.is_absolute() && p.lexically_normal() == p && !p.filename().empty(),
         "normalized absolute path required");

    need(!os::linked_ancestor(p), "linked path rejected");
}

bool inside(const std::filesystem::path &child, const std::filesystem::path &parent) {
    auto c = child.begin();

    for (auto p = parent.begin(); p != parent.end(); ++p, ++c) {
        if (c == child.end() || *c != *p) {
            return false;
        }
    }

    return true;
}

void relative(const std::string &name) {
    std::filesystem::path p(name);

    need(!name.empty() && name.size() <= 512 && !p.is_absolute() &&
                 name.find('\\') == std::string::npos && name.find(':') == std::string::npos,
         "relative input path required");

    for (const auto &c : p) {
        need(c != "." && c != ".." && !c.empty(), "confined relative path required");
    }
}

void pinned(const std::filesystem::path &p, const std::string &hash,
            std::uint64_t maximum = 4ULL << 30) {
    path(p);
    need(sha256_text(hash) && std::filesystem::is_regular_file(p) &&
                 std::filesystem::file_size(p) <= maximum,
         "bounded pinned file required");
    const auto epoch = cache_file_identity(p);
    need(sha256_file(p) == hash && cache_file_identity(p) == epoch, "input SHA/epoch mismatch");
}

// The profile with its selected build target resolved, as the request pins it.
std::string pinned_profile_bytes(const std::filesystem::path &root,
                                 const JavaPreparationRequest &request) {
    auto bytes = authoring_profile_bytes(root, request.profile, request.target);

    need(sha256_bytes(bytes) == request.profile_sha256, "authoring profile changed");

    return bytes;
}

Json pinned_profile(const std::filesystem::path &root, const JavaPreparationRequest &request) {
    return Json::parse(pinned_profile_bytes(root, request));
}

std::set<std::string> keys(const Json &obj) {
    need(obj.is_object() && obj.size() <= 4096, "bounded object required");
    std::set<std::string> out;

    for (auto it = obj.begin(); it != obj.end(); ++it) {
        out.insert(it.key());
    }

    return out;
}

void write_log(const std::filesystem::path &file, const std::string &bytes) {
    need(bytes.size() <= 1ULL << 20 && !std::filesystem::exists(file),
         "fresh bounded log required");
    std::ofstream out(file, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    out.close();
    need(bool(out), "log write failed");
}

std::string classpath(const std::filesystem::path &root, const JavaPreparationRuntime &runtime) {
    pinned(runtime.helper, runtime.helper_sha256, 128ULL << 20);
    pinned(runtime.receipt, runtime.receipt_sha256, 256 * 1024);
    need(runtime.receipt.parent_path() == runtime.helper.parent_path(),
         "helper receipt directory mismatch");
    const auto receipt = read_private_json(runtime.receipt, 256 * 1024);
    need(receipt.value("schema", 0) == 1 &&
                 receipt.value("kind", std::string{}) == "java-preparation-helper" &&
                 receipt.value("java_release", 0) == 25 &&
                 receipt.at("sha256") == runtime.helper_sha256 &&
                 receipt.at("jar") == runtime.helper.filename().string(),
         "helper build receipt mismatch");
    // The published helper is an immutable source cut. Later authoring edits belong to a new cut.
    const auto owner_file = runtime.helper.parent_path() / "toolchain-receipt.json";
    path(owner_file);
    const auto owner = read_private_json(owner_file, 512 * 1024);
    const auto &fingerprint = runtime.helper_cache_key;
    need(owner.value("schema", 0) == 1 &&
                 owner.value("kind", std::string{}) == "java-preparation-toolchain" &&
                 sha256_text(fingerprint) && owner.at("fingerprint") == fingerprint &&
                 runtime.helper.parent_path() ==
                         root / ".local/toolchains/java-helper" / fingerprint &&
                 owner.at("helper_sha256") == runtime.helper_sha256 &&
                 owner.at("build_receipt_sha256") == runtime.receipt_sha256,
         "helper ownership mismatch");
    std::map<std::string, std::string> expected_libraries;
    const auto specs = project_file_json(root, "src/prepare/libraries.json", 256 * 1024);
    need(specs.is_array() && specs.size() <= 64, "library specification array required");

    for (const auto &spec : specs) {
        const auto name = "lib/" + spec.at("filename").get<std::string>();
        relative(name);
        need(expected_libraries.emplace(name, spec.at("sha256").get<std::string>()).second,
             "duplicate library specification");
    }

    const auto tools = project_file_json(root, "src/prepare/toolchain.json", 256 * 1024);

    for (const auto &name : {"d8", "apksigner"}) {
        need(expected_libraries
                     .emplace(std::string("lib/") + name + ".jar",
                              tools.at("libraries").at(name).at("sha256").get<std::string>())
                     .second,
             "duplicate SDK library specification");
    }

    bool main = false;

    for (const auto &e : pinned_zip_inventory(runtime.helper, runtime.helper_sha256)) {
        if (e.name == "com/voyemu/prepare/PreparationMain.class" && !e.directory) {
            main = true;
        }
    }

    need(main, "PreparationMain class missing");
    const char separator = os::path_list_separator;
    std::string result = runtime.helper.string();
    need(receipt.at("dependencies").is_array() && receipt.at("dependencies").size() <= 64,
         "bounded helper dependencies");
    std::set<std::string> libraries;

    for (const auto &d : receipt.at("dependencies")) {
        const auto name = d.at("file").get<std::string>();
        relative(name);
        need(name.starts_with("lib/") && name.ends_with(".jar") && libraries.insert(name).second,
             "unique helper library required");
        need(expected_libraries.contains(name) && d.at("sha256") == expected_libraries.at(name),
             "helper library differs from dependency specification");
        const auto file = runtime.helper.parent_path() / name;
        pinned(file, d.at("sha256").get<std::string>(), 256ULL << 20);
        need(d.at("bytes") == std::filesystem::file_size(file), "helper library extent mismatch");
        result += separator;
        result += file.string();
    }

    need(libraries.size() == expected_libraries.size() && !libraries.empty(),
         "helper library coverage mismatch");

    return result;
}

void response(const std::filesystem::path &root, const JavaPreparationRequest &request,
              const Json &result) {
    const auto operation = request.operation == JavaPreparationOperation::plan ? "plan"
                                                                               : "build-artifacts";

    need(result.is_object() && result.value("schema", 0) == 1 &&
                 result.value("operation", std::string{}) == operation &&
                 result.value("profile", std::string{}) == request.profile &&
                 result.contains("machine_ready") && result.at("machine_ready") == false &&
                 result.contains("guest_started") && result.at("guest_started") == false,
         "helper response identity/state mismatch");
    const auto profile = pinned_profile(root, request);
    need(result.value("target", Json{}) == profile_target_identity(profile),
         "helper response target, ABI or base pin differs");
    auto names = [](const Json &v) {
        need(v.is_array() && v.size() <= 4096, "bounded result list");
        std::set<std::string> s;

        for (const auto &n : v) {
            auto name = n.get<std::string>();
            need(s.insert(name).second, "duplicate result node");
        }

        return s;
    };
    need(names(result.at("components")) == keys(profile.at("components")) &&
                 names(result.at("patch_nodes")) == keys(profile.at("patches")),
         "helper response source/node mismatch");

    if (request.operation == JavaPreparationOperation::plan) {
        need(!result.contains("artifacts") && !result.value("artifacts_built", false),
             "plan unexpectedly built artifacts");

        return;
    }

    need(result.value("artifacts_built", false) && result.at("artifacts").is_object() &&
                 result.at("artifacts").size() <= 4096,
         "build result artifacts required");
    passion_generated_helper_graph(root, profile, result.at("artifacts"));

    if (request.build) {
        for (const auto &[id, item] : request.build->native_components) {
            const auto proof = read_private_json(item.receipt, 1 << 20);
            const auto reference = "component:" + id;
            need(result.at("artifacts").contains(reference),
                 "native component output missing from artifact result");
            const auto &output = result.at("artifacts").at(reference);
            need(output.at("file") == (item.receipt.parent_path() /
                                       proof.at("output").get<std::string>())
                                              .string() &&
                         output.at("sha256") == proof.at("sha256") &&
                         output.at("bytes") == proof.at("bytes"),
                 "native component artifact output differs from receipt");
        }
    }

    for (auto artifact = result.at("artifacts").begin(); artifact != result.at("artifacts").end();
         ++artifact) {
        const auto &item = artifact.value();
        need(item.is_object(), "artifact object");

        if (item.contains("file")) {
            const std::filesystem::path file = item.at("file").get<std::string>();

            if (!inside(file, root / ".local")) {
                need(artifact.key().starts_with("files:") && profile.contains("files") &&
                             profile.at("files").contains(artifact.key().substr(6)),
                     "artifact outside project data");
                const auto &declared = profile.at("files").at(artifact.key().substr(6));
                const auto name = declared.at("file").get<std::string>();
                relative(name);
                need(file == authoring_directory(root, request.profile) / "files" / name,
                     "artifact outside declared profile files");

                if (declared.contains("sha256")) {
                    need(declared.at("sha256") == item.at("sha256"), "profile file SHA mismatch");
                }
            }

            pinned(file, item.at("sha256").get<std::string>());
            need(item.at("bytes") == std::filesystem::file_size(file), "artifact extent mismatch");
        } else {
            const std::filesystem::path directory = item.at("directory").get<std::string>();
            path(directory);
            need(inside(directory, root / ".local") && std::filesystem::is_directory(directory) &&
                         item.at("files").is_object() && item.at("files").size() <= 65536,
                 "bounded artifact directory");
            std::set<std::string> declared;

            for (auto it = item.at("files").begin(); it != item.at("files").end(); ++it) {
                relative(it.key());
                const auto file = directory / it.key();
                pinned(file, it.value().at("sha256").get<std::string>());
                need(it.value().at("bytes") == std::filesystem::file_size(file),
                     "directory artifact extent mismatch");
                declared.insert(it.key());
            }

            std::set<std::string> actual;

            for (const auto &e : std::filesystem::recursive_directory_iterator(directory)) {
                need(!e.is_symlink() && (e.is_directory() || e.is_regular_file()),
                     "ordinary artifact tree");

                if (e.is_regular_file()) {
                    actual.insert(e.path().lexically_relative(directory).generic_string());
                }
            }

            need(actual == declared, "directory artifact inventory mismatch");
        }
    }
}
} // namespace

void validate_java_preparation_response(const std::filesystem::path &root,
                                        const JavaPreparationRequest &request, const Json &result) {
    (void)pinned_profile(root, request);

    if (!request.source_snapshot.empty()) {
        need(sha256_text(request.source_snapshot) &&
                     current_profile_revision(root, request.profile) == request.source_snapshot,
             "profile source changed during operation");
    }

    response(root, request, result);
}

Json java_preparation_native_files(const std::filesystem::path &root,
                                   const JavaPreparationRequest &request) {
    const auto profile = pinned_profile(root, request);
    const auto guest_api = native_base_api(profile.at("android"));
    const auto &b = request.build.value();
    Json result;
    const bool codec = guest_api == 28 && profile.at("patches").contains("ccodec-allocation-a9");

    if (codec) {
        need(record_declares(profile, ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
                     !b.native_files_receipt.empty() &&
                     inside(b.native_files_receipt, root / ".local"),
             "exact API28 codec handoff required");
        const auto &extraction = b.android_inputs.at("/system/lib64/libstagefright_ccodec.so");
        auto expected = plan_profile_codec_file_node(root, request.profile,
                                                     extraction.receipt.parent_path());
        need(expected.patches.size() == 1, "one planned codec output required");
        const auto &patch = expected.patches.front();
        pinned(b.native_files_receipt, b.native_files_receipt_sha256, 128 * 1024);
        const auto receipt = read_private_json(b.native_files_receipt, 128 * 1024);
        need(receipt.at("schema") == 1 && receipt.at("kind") == "native-file-draft" &&
                     receipt.at("files").size() == 1 &&
                     receipt.at("profile_provenance") == expected.provenance &&
                     expected.provenance.at("extraction_receipt_sha256") ==
                             extraction.receipt_sha256,
             "codec native receipt provenance differs");
        const auto &output = receipt.at("files")[0];
        need(output == Json({{"id", patch.id},
                             {"api", 28},
                             {"input", patch.input.string()},
                             {"input_sha256", patch.input_sha256},
                             {"output", patch.id + ".output"},
                             {"output_sha256", patch.output_sha256},
                             {"profile", patch.profile}}),
             "codec native output binding differs");
        pinned(b.native_files_receipt.parent_path() / (patch.id + ".output"), patch.output_sha256,
               632488);
        expected.revalidate();
        result = {{"receipt", b.native_files_receipt.string()},
                  {"receipt_sha256", b.native_files_receipt_sha256}};
    }

    const bool passion = record_declares(profile, ProfilePlatform::passion, ProfileBoard::sa8155);
    const auto recipes = api30_file_recipes_for_profile(profile);
    std::size_t native_nodes = 0;

    if (guest_api == 30) {
        for (const auto &node : profile.at("patches")) {
            if (node.at("type") == "file") {
                ++native_nodes;
            }
        }
    }

    need((record_declares(profile, ProfilePlatform::qinggan11, ProfileBoard::sa8155)
                  ? native_nodes == recipes.size()
                  : (native_nodes == 0 || (!passion && native_nodes == 1) ||
                     native_nodes == recipes.size())) &&
                 (native_nodes == 0 || !b.native_files_receipt.empty()),
         "API30 native file receipt required");

    if (!codec && !b.native_files_receipt.empty()) {
        need(guest_api == 30 && native_nodes > 0 && inside(b.native_files_receipt, root / ".local"),
             "native file handoff scope differs");
        pinned(b.native_files_receipt, b.native_files_receipt_sha256, 128 * 1024);
        const auto receipt = read_private_json(b.native_files_receipt, 128 * 1024);
        // The draft must be what profile preparation plans for these inputs: the same nodes with
        // their declared uses, recipes, outputs and dependencies. API30 file nodes read only the
        // system extraction.
        const auto &extraction = b.android_inputs.at(std::string(recipes.front().target));
        auto expected = plan_profile_file_nodes(
                root, request.profile, extraction.receipt.parent_path(), {}, request.target);
        need(receipt.at("schema") == 1 && receipt.at("kind") == "native-file-draft" &&
                     receipt.at("files").size() == native_nodes &&
                     expected.patches.size() == native_nodes &&
                     receipt.at("profile_provenance") == expected.provenance &&
                     expected.provenance.at("extraction_receipt_sha256") ==
                             extraction.receipt_sha256,
             "native file profile provenance differs");

        for (std::size_t i = 0; i < native_nodes; ++i) {
            const auto &patch = expected.patches[i];
            need(b.android_inputs.at(std::string(recipes[i].target)).receipt_sha256 ==
                         extraction.receipt_sha256,
                 "native file extraction binding differs");
            need(receipt.at("files").at(i) == file_patch_receipt_entry(patch),
                 "native file output recipe differs");
            pinned(b.native_files_receipt.parent_path() / (patch.id + ".output"),
                   patch.output_sha256, 4ULL << 20);
        }

        need(b.android_inputs.at("/system/etc/selinux/mapping/30.0.cil").receipt_sha256 ==
                     extraction.receipt_sha256,
             "native mapping extraction differs");
        expected.revalidate();
        result = {{"receipt", b.native_files_receipt.string()},
                  {"receipt_sha256", b.native_files_receipt_sha256}};
    } else if (!codec) {
        need(b.native_files_receipt_sha256.empty(), "native file SHA without receipt");
    }

    return result;
}

static Json request_document(const std::filesystem::path &root,
                             const JavaPreparationRequest &request, bool require_fresh) {
    path(root);
    need(std::filesystem::is_directory(root) && valid_profile_name(request.profile),
         "project/profile required");
    // The helper builds the profile from these exact bytes and never resolves a target itself.
    auto bytes = pinned_profile_bytes(root, request);
    const auto profile = Json::parse(bytes);
    need(profile.at("schema") == 1, "profile schema");
    Json result = {{"schema", 1},
                   {"root", root.string()},
                   {"profile", request.profile},
                   {"profile_sha256", request.profile_sha256},
                   {"resolved_profile", std::move(bytes)}};

    if (request.operation == JavaPreparationOperation::plan) {
        need(!request.build, "plan may not contain build inputs");
        result["operation"] = "plan";

        return result;
    }

    need(request.operation == JavaPreparationOperation::build_artifacts &&
                 request.build.has_value(),
         "typed build operation/inputs required");
    result["operation"] = "build-artifacts";
    need(!profile.contains("targets"), "artifact preparation requires a selected build target");
    const auto &b = request.build.value();
    path(b.sdk);
    path(b.work);
    need(inside(b.sdk, root / ".local") && std::filesystem::is_directory(b.sdk) &&
                 inside(b.work, root / ".local") && b.work != root / ".local" &&
                 (!require_fresh || !std::filesystem::exists(b.work)),
         "owned SDK/fresh work required");
    pinned(b.patch_data, b.patch_data_sha256, 4 << 20);
    need(sha256_text(b.tool_manifest_sha256) &&
                 project_file_sha256(root, "src/app/toolchain.json", 1 << 20) ==
                         b.tool_manifest_sha256,
         "tool manifest changed during invocation");
    pinned(b.key, b.key_sha256, 65536);
    pinned(b.certificate, b.certificate_sha256, 65536);
    need(b.tool_files.size() <= 256 && !b.tool_files.empty(), "bounded SDK tool pins required");
    Json files = Json::object();

    for (const auto &[name, hash] : b.tool_files) {
        relative(name);
        pinned(b.sdk / name, hash);
        files[name] = hash;
    }

    const auto manifest = project_file_json(root, "src/app/toolchain.json", 1 << 20);
    const auto version = manifest.at("sdk").at("buildTools").get<std::string>();
    const auto api = manifest.at("sdk").at("compileSdk").get<unsigned>();
    need(std::regex_match(version, std::regex("[0-9]+\\.[0-9]+\\.[0-9]+")) && api >= 28 &&
                 api <= 100,
         "SDK selector bounds");
    const std::string exe(os::executable_suffix);

    for (const auto &required : {"build-tools/" + version + "/aapt2" + exe,
                                 "build-tools/" + version + "/zipalign" + exe}) {
        need(files.contains(required), "required SDK tool pin missing");
    }

    Json platform = Json::object();

    if (!b.platform.empty()) {
        need(inside(b.platform, root / ".local") && b.platform.filename() == "android.jar",
             "owned public Android platform JAR required");
        pinned(b.platform, b.platform_sha256, 128ULL << 20);
        platform = {{"file", b.platform.string()}, {"sha256", b.platform_sha256}};
    } else {
        need(b.platform_sha256.empty(), "platform SHA without override path");
        need(files.contains("platforms/android-" + std::to_string(api) + "/android.jar"),
             "required SDK platform pin missing");
    }

    const auto guest_api = native_base_api(profile.at("android"));
    Json android = Json::object();
    need(b.android_inputs.size() <= 512, "Android input count");

    for (const auto &[logical, input] : b.android_inputs) {
        const bool extension = logical.starts_with("/system_ext/");
        need(logical.starts_with("/system/") || logical.starts_with("/vendor/") ||
                     (guest_api == 30 && extension),
             "registered system/vendor/system_ext logical path required");
        const auto relative_name = logical.starts_with("/vendor/") ? logical.substr(8)
                                   : extension                     ? logical.substr(12)
                                                                   : logical.substr(1);
        relative(relative_name);
        pinned(input.receipt, input.receipt_sha256, 128 * 1024);
        const auto receipt = read_private_json(input.receipt);
        const bool vendor = logical.starts_with("/vendor/");
        const auto image = native_base_pin(profile.at("android"), "images",
                                           vendor ? "vendor.img" : "system.img");
        need(receipt.value("schema", 0) == 1 && receipt.value("native", false) &&
                     !receipt.value("filesystem_mounted", true) &&
                     receipt.value("image_sha256", std::string{}) == image,
             "native registered-base extraction receipt required");

        if (guest_api == 30 && !vendor) {
            const auto clean = native_clean_base(profile.at("android"));
            const auto &partition = extension ? clean.system_ext : clean.system;
            need(receipt.value("logical_partition", std::string{}) ==
                                 (extension ? "system_ext" : "system") &&
                         clean.metadata_sha256 ==
                                 receipt.value("lp_metadata_sha256", std::string{}) &&
                         partition.offset == receipt.value("partition_offset", 0ULL) &&
                         partition.bytes == receipt.value("logical_partition_bytes", 0ULL),
                 "API30 pinned logical-system/system_ext view required");
        }

        const auto file = input.receipt.parent_path() / relative_name;
        const auto spec = receipt.at("files").at(relative_name);
        pinned(file, spec.at("sha256").get<std::string>());
        need(spec.at("bytes") == std::filesystem::file_size(file),
             "extracted file extent mismatch");
        android[logical] = {{"receipt", input.receipt.string()},
                            {"receipt_sha256", input.receipt_sha256}};
    }

    if (auto native = java_preparation_native_files(root, request); !native.is_null()) {
        result["native_files"] = std::move(native);
    }

    Json components = Json::object();

    for (auto it = profile.at("components").begin(); it != profile.at("components").end(); ++it) {
        const auto relative_name = it.value().get<std::string>();
        relative(relative_name);
        const auto source = authoring_directory(root, request.profile) / relative_name;
        const auto definition = read_private_json(source / "component.json");

        if (definition.value("type", std::string{}) != "native") {
            continue;
        }

        const auto output_type = definition.value("outputType", std::string("shared-library"));
        need(output_type == "shared-library" || output_type == "executable",
             "unknown native output type");
        const auto id = it.key();
        relative(id);
        const auto recipe_api = definition.at("minSdk").get<int>();
        need((output_type == "executable" ? guest_api == static_cast<unsigned>(recipe_api)
                                          : guest_api >= static_cast<unsigned>(recipe_api)) &&
                     (recipe_api == 28 || recipe_api == 30) && b.native_components.contains(id),
             "declared API28/API30 native component receipt required");
        const auto &item = b.native_components.at(id);
        need(inside(item.receipt, root / ".local/build"),
             "owned native component receipt required");
        pinned(item.receipt, item.receipt_sha256);
        const auto proof = read_private_json(item.receipt, 1 << 20);
        const auto key = native_component_pin(request.profile, id, definition);
        const auto origin = native_component_origin(manifest.at("androidNativeComponents"), key,
                                                    definition);
        const auto abi = native_component_abi(definition,
                                              native_base_identity(profile.at("android")).abi);
        const bool matching_origin =
                origin.contains("asset")
                        ? !proof.contains("source") &&
                                  proof.value("asset", Json{}) == origin.at("asset")
                        : !proof.contains("asset") &&
                                  proof.value("source", std::string{}) == "recipe";
        need(proof.at("schema") == 1 && proof.at("type") == "native" &&
                     proof.at("output_type") == output_type && proof.at("api") == recipe_api &&
                     proof.at("abi") == abi && proof.at("output") == definition.at("output") &&
                     proof.at("sha256") == origin.at("sha256") && matching_origin,
             "native component receipt differs from its pin");
        pinned(item.receipt.parent_path() / proof.at("output").get<std::string>(),
               proof.at("sha256").get<std::string>());
        components[id] = {{"receipt", item.receipt.string()},
                          {"receipt_sha256", item.receipt_sha256},
                          {"output_type", output_type},
                          {"abi", abi},
                          {"output", proof.at("output")},
                          {"sha256", proof.at("sha256")}};
    }

    need(components.size() == b.native_components.size(), "undeclared native component rejected");

    if (!components.empty()) {
        result["native_components"] = components;
    }

    result["patch_data"] = b.patch_data.string();
    result["patch_data_sha256"] = b.patch_data_sha256;
    result["work"] = b.work.string();
    result["android_inputs"] = android;
    // The helper takes the toolchain manifest from the request and never reads src/.
    result["tools"] = {{"sdk", b.sdk.string()},
                       {"manifest", project_file_bytes(root, "src/app/toolchain.json", 1 << 20)},
                       {"manifest_sha256", b.tool_manifest_sha256},
                       {"files", files},
                       {"signing",
                        {{"key", b.key.string()},
                         {"key_sha256", b.key_sha256},
                         {"certificate", b.certificate.string()},
                         {"certificate_sha256", b.certificate_sha256}}}};

    if (!platform.empty()) {
        result["tools"]["platform"] = platform;
    }

    if (!b.guest_java.empty()) {
        need(inside(b.guest_java, root / ".local/toolchains/android-java") &&
                     b.guest_java.filename() == "android-java.zip",
             "installed android-java asset required");
        pinned(b.guest_java, b.guest_java_sha256, 256ULL << 20);
        result["tools"]["guest_java"] = {{"file", b.guest_java.string()},
                                         {"sha256", b.guest_java_sha256}};
    }

    need(result.dump().size() <= 2ULL << 20, "request byte budget");

    return result;
}

Json java_preparation_request(const std::filesystem::path &root,
                              const JavaPreparationRequest &request) {
    return request_document(root, request, true);
}

// One artifact budget for every profile: the helper runs the same graph for all of them, and the
// work grows with the graph, not with the profile name. API 30 profiles validate each patch step
// on the original classes before applying it (Artifacts.applySteps), and their framework guards
// serialize the whole framework dex for each check, which took most of a Passion run; API 28
// profiles apply once but build the most components (47 for Free A9 6.0.3). On KLG a Passion run
// did not finish within 20 minutes and a Free A9 6.0.3 run took 41 minutes, so the hour bounds a
// hung helper on a slow host instead of cutting a working one.
int java_preparation_timeout_ms(const JavaPreparationRequest &request) {
    return request.operation == JavaPreparationOperation::build_artifacts ? 3600000 : 300000;
}

Json prepare_java_artifacts(const std::filesystem::path &root,
                            const JavaPreparationRuntime &runtime,
                            const JavaPreparationRequest &request,
                            const std::filesystem::path &destination, int timeout) {
    need(timeout >= 1000 && timeout <= java_preparation_timeout_ms(request),
         "bounded timeout required");
    auto invocation = request;
    invocation.source_snapshot = current_profile_revision(root, request.profile);
    const auto document = java_preparation_request(root, request);
    path(runtime.jdk);
    const std::string exe(os::executable_suffix);
    const auto java = runtime.jdk / "bin" / ("java" + exe),
               javac = runtime.jdk / "bin" / ("javac" + exe);
    pinned(java, runtime.java_sha256, 256ULL << 20);
    path(javac);

    // Without the CI-built guest Java the helper compiles it, which needs javac.
    if (request.build && request.build->guest_java.empty() &&
        !std::filesystem::is_regular_file(javac)) {
        throw VoyemuError("ANDROID_JAVA_ASSET_MISSING",
                          "the android-java asset cannot be downloaded and the Java runtime has no "
                          "javac to compile the guest Java; build with --jdk");
    }

    const auto cp = classpath(root, runtime);
    path(destination);
    need(inside(destination, root / ".local") && destination != root / ".local" &&
                 !std::filesystem::exists(destination),
         "fresh owned preparation transport directory required");

    if (request.build) {
        need(!inside(destination, request.build->work),
             "transport directory may not be inside artifact work");
    }

    ensure_private_directory(destination.parent_path());
    need(std::filesystem::create_directory(destination), "exclusive transport directory");
    ensure_private_directory(destination);
    write_private_json(destination / "request.json", document, 2 << 20);
    ProcessSpec command;
    command.executable = java;
    command.directory = root;
    command.environment = {{"PYTHONDONTWRITEBYTECODE", "1"},
                           {"JAVA_TOOL_OPTIONS", ""},
                           {"JDK_JAVA_OPTIONS", ""},
                           {"_JAVA_OPTIONS", ""},
                           {"CLASSPATH", ""},
                           {"TMPDIR", destination.string()},
                           {"TMP", destination.string()},
                           {"TEMP", destination.string()}};
    command.arguments = {"--version"};
    const auto version = execute(command, 10000, 16 * 1024);
    write_log(destination / "java-version.log", version.output);
    std::smatch match;
    need(!version.timed_out && version.exit_code == 0 &&
                 std::regex_search(version.output, match,
                                   std::regex(R"((?:openjdk|java) ([0-9]+)(?:\.|\s))")) &&
                 std::stoul(match[1].str()) >= 17,
         "Java version probe failed");
    command.arguments = {"-Xmx1g",
                         "-Djava.io.tmpdir=" + destination.string(),
                         "-cp",
                         cp,
                         "com.voyemu.prepare.PreparationMain",
                         (destination / "request.json").string()};
    const auto run = timeout > 600000 ? execute_artifact_preparation(command, timeout, 1 << 20)
                                      : execute(command, timeout, 1 << 20);
    write_log(destination / "helper.log", run.output);
    write_private_json(destination / "helper-process.json", {{"schema", 1},
                                                             {"timeout_ms", timeout},
                                                             {"timed_out", run.timed_out},
                                                             {"exit_code", run.exit_code}});
    need(!run.timed_out && run.exit_code == 0, "PreparationMain failed; see helper.log");
    auto end = run.output.find_last_not_of("\r\n \t");
    need(end != std::string::npos, "helper returned no JSON");
    const auto begin = run.output.rfind('\n', end);
    const auto line = run.output.substr(begin == std::string::npos ? 0 : begin + 1,
                                        end - (begin == std::string::npos ? 0 : begin + 1) + 1);
    const auto result = Json::parse(line);
    validate_java_preparation_response(root, invocation, result);
    need(current_profile_revision(root, request.profile) == invocation.source_snapshot &&
                 request_document(root, request, false) == document &&
                 classpath(root, runtime) == cp,
         "inputs/helper changed during preparation");
    pinned(java, runtime.java_sha256, 256ULL << 20);
    write_private_json(destination / "result.json", result);
    write_private_json(destination / "receipt.json",
                       {{"schema", 1},
                        {"kind", "java-preparation-invocation"},
                        {"java_sha256", runtime.java_sha256},
                        {"helper_sha256", runtime.helper_sha256},
                        {"helper_receipt_sha256", runtime.receipt_sha256},
                        {"request_sha256", sha256_file(destination / "request.json")},
                        {"result_sha256", sha256_file(destination / "result.json")},
                        {"operation", document.at("operation")},
                        {"profile", request.profile},
                        {"guest_started", false}});

    return result;
}

std::string java_preparation_classpath(const std::filesystem::path &root,
                                       const JavaPreparationRuntime &runtime) {
    return classpath(root, runtime);
}
} // namespace voyemu
