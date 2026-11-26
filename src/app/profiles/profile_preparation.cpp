#include "profile_preparation.hpp"
#include "android_java.hpp"
#include "apk_base.hpp"
#include "apk_identity.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "cli_messages.hpp"
#include "deps.hpp"
#include "error.hpp"
#include "ext4_image.hpp"
#include "fetch.hpp"
#include "java_toolchain.hpp"
#include "machine_preparation.hpp"
#include "native_component.hpp"
#include "ordinary_path.hpp"
#include "os/fs.hpp"
#include "os/platform.hpp"
#include "owner_lock.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "profile_file_nodes.hpp"
#include "profile_identity.hpp"
#include "progress.hpp"
#include "project_files.hpp"
#include "qnx_link_interface.hpp"
#include "quickboot.hpp"
#include "toolchain_manifest.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
namespace voyemu {
namespace {
constexpr Check need{"PROFILE_PREPARATION"};

void ordinary(const std::filesystem::path &p) {
    ordinary_path(p, need, PathForm::Normalized, "normalized absolute path required",
                  "linked path rejected");
}

void relative(const std::string &name) {
    const std::filesystem::path path(name);

    need(!name.empty() && name.size() <= 1024 && !path.is_absolute() &&
                 path.lexically_normal() == path &&
                 name.find_first_of("\\:\r\n") == std::string::npos,
         "safe relative file path required");

    for (const auto &part : path) {
        need(part != ".." && part != ".", "traversal rejected");
    }
}

std::string hash(const std::filesystem::path &file, std::uint64_t maximum = 4ULL << 30) {
    ordinary(file);

    if (!(std::filesystem::is_regular_file(file) && std::filesystem::hard_link_count(file) == 1 &&
          std::filesystem::file_size(file) <= maximum)) {
        throw VoyemuError("PROFILE_PREPARATION",
                          "ordinary bounded file required: " + file.string());
    }

    const auto epoch = cache_file_identity(file);
    const auto pin = sha256_file(file);
    need(cache_file_identity(file) == epoch, "input changed during hashing");

    return pin;
}

Json profile_definition(const std::filesystem::path &root, std::string_view name,
                        std::string_view target = {}) {
    ordinary(root);
    need(std::filesystem::is_directory(root) && std::filesystem::canonical(root) == root &&
                 valid_profile_name(name),
         "canonical project root and safe profile required");
    const auto file = root / "profiles" / std::string(name) / "profile.json";
    hash(file, 512 * 1024);
    auto profile = authoring_profile(root, name, target);
    need(profile.at("schema") == 1, "registered profile schema required");
    native_base_api(profile.at("android"));

    return profile;
}

Json verify_base(const std::filesystem::path &base, const Json &descriptor) {
    return verify_native_base_image(descriptor, base);
}

Json verify_extraction(const std::filesystem::path &directory, const std::string &image_pin,
                       const std::vector<std::string> &paths) {
    ordinary(directory);
    const auto receipt_file = directory / "receipt.json";
    const auto receipt_pin = hash(receipt_file, 128 * 1024);
    const auto receipt = read_private_json(receipt_file, 128 * 1024);
    need(receipt.at("schema") == 1 && receipt.at("native") == true &&
                 receipt.at("filesystem_mounted") == false &&
                 receipt.at("image_sha256") == image_pin && receipt.at("files").is_object() &&
                 receipt.at("files").size() == paths.size(),
         "native extraction receipt mismatch");
    std::set<std::string> expected = {"receipt.json"};

    for (const auto &path : paths) {
        need(path.starts_with('/'), "absolute guest path required");
        const auto name = path.substr(1);
        relative(name);
        const auto spec = receipt.at("files").at(name);
        const auto file = directory / name;
        need(hash(file, 256ULL << 20) == spec.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(file) == spec.at("bytes"),
             "extracted file differs from receipt");
        expected.insert(name);
    }

    std::set<std::string> actual;

    for (const auto &e : std::filesystem::recursive_directory_iterator(directory)) {
        need(!e.is_symlink() && (e.is_directory() || e.is_regular_file()),
             "ordinary extraction tree");

        if (e.is_regular_file()) {
            actual.insert(e.path().lexically_relative(directory).generic_string());
        }
    }

    need(actual == expected, "extraction inventory differs from receipt");
    need(hash(receipt_file, 128 * 1024) == receipt_pin,
         "extraction receipt changed during verification");

    return receipt;
}
} // namespace

std::filesystem::path cached_native_android_inputs(const std::filesystem::path &cache,
                                                   const std::string &image_pin,
                                                   const std::vector<std::string> &paths,
                                                   std::string_view logical_partition) {
    ordinary(cache);
    need(sha256_text(image_pin) && !paths.empty() && paths.size() <= 256,
         "bounded pinned cache lookup required");

    for (const auto &path : paths) {
        need(path.starts_with('/'), "absolute guest path required");
        relative(path.substr(1));
    }

    need(std::is_sorted(paths.begin(), paths.end()) &&
                 std::adjacent_find(paths.begin(), paths.end()) == paths.end(),
         "sorted distinct extraction paths required");
    Json identity = {{"image_sha256", image_pin}, {"paths", paths}};

    if (!logical_partition.empty()) {
        identity["logical_partition"] = logical_partition;
    }

    const auto exact = cache / sha256_bytes(identity.dump());

    if (std::filesystem::exists(exact) || std::filesystem::is_symlink(exact)) {
        const auto receipt = verify_extraction(exact, image_pin, paths);
        need(logical_partition.empty()
                     ? !receipt.contains("logical_partition")
                     : receipt.value("logical_partition", std::string()) == logical_partition,
             "logical partition extraction receipt mismatch");

        return exact;
    }

    if (!std::filesystem::exists(cache)) {
        return {};
    }

    std::vector<std::filesystem::path> candidates;

    for (const auto &entry : std::filesystem::directory_iterator(cache)) {
        const auto name = entry.path().filename().string();

        if (!sha256_text(name)) {
            continue;
        }

        need(!entry.is_symlink() && entry.is_directory(),
             "ordinary extraction cache directory required");
        candidates.push_back(entry.path());
    }

    std::sort(candidates.begin(), candidates.end());
    std::filesystem::path selected;
    std::size_t selected_count = 0;

    for (const auto &directory : candidates) {
        ordinary(directory);
        const auto file = directory / "receipt.json";

        if (!std::filesystem::exists(file) && !std::filesystem::is_symlink(file)) {
            continue;
        }

        const auto receipt_pin = hash(file, 128 * 1024);
        const auto receipt = read_private_json(file, 128 * 1024);

        if (receipt.value("image_sha256", std::string()) != image_pin ||
            (logical_partition.empty()
                     ? receipt.contains("logical_partition")
                     : receipt.value("logical_partition", std::string()) != logical_partition)) {
            continue;
        }

        const auto &files = receipt.at("files");
        need(files.is_object() && !files.empty() && files.size() <= 256,
             "bounded original extraction inventory required");
        bool contains = true;

        for (const auto &path : paths) {
            if (!files.contains(path.substr(1))) {
                contains = false;
            }
        }

        if (!contains) {
            continue;
        }

        std::vector<std::string> full_paths;

        for (auto it = files.begin(); it != files.end(); ++it) {
            relative(it.key());
            full_paths.push_back("/" + it.key());
        }

        auto original_identity = identity;
        original_identity["paths"] = full_paths;
        need(directory.filename() == sha256_bytes(original_identity.dump()),
             "original extraction cache identity differs");
        (void)verify_extraction(directory, image_pin, full_paths);
        need(hash(file, 128 * 1024) == receipt_pin,
             "original extraction receipt changed during selection");

        if (selected.empty() || full_paths.size() < selected_count) {
            selected = directory;
            selected_count = full_paths.size();
        }
    }

    return selected;
}

std::vector<std::string> native_profile_android_inputs(const std::filesystem::path &root,
                                                       std::string_view name) {
    const auto profile = profile_definition(root, name);
    std::set<std::string> paths;

    for (const auto &patch : profile.at("patches")) {
        const auto input = patch.at("input").get<std::string>();

        if (input.starts_with("android:")) {
            paths.insert(input.substr(8));
        }

        for (const auto &dependency : patch.value("uses", Json::array())) {
            const auto value = dependency.get<std::string>();

            if (value.starts_with("android:")) {
                paths.insert(value.substr(8));
            }
        }
    }

    for (auto it = profile.at("components").begin(); it != profile.at("components").end(); ++it) {
        const auto relative_name = it.value().get<std::string>();
        relative(relative_name);
        const auto file = authoring_directory(root, name) / relative_name / "component.json";
        hash(file, 512 * 1024);
        const auto component = read_private_json(file, 512 * 1024);

        for (const auto &lib : component.value("guestLibs", Json::array())) {
            paths.insert(lib.get<std::string>());
        }

        // The C and C++ runtime libraries that a native component with guest libraries also
        // imports from; a jar component lists only framework files as guest libraries.
        if (component.value("type", std::string{}) == "native" && component.contains("guestLibs")) {
            for (const auto *lib : {"/system/lib64/libc.so", "/system/lib64/libm.so",
                                    "/system/lib64/libdl.so", "/system/lib64/libc++.so"}) {
                paths.insert(lib);
            }
        }

        if (component.contains("frameworkBase")) {
            const auto &base = component.at("frameworkBase");
            need(base.is_object(), "framework base metadata required");

            for (const char *key : {"jar", "oat", "vdex"}) {
                const auto input = base.at(key).get<std::string>();
                need(input.starts_with("/system/framework/"),
                     "framework base input must belong to system framework");
                paths.insert(input);
            }
        }
    }

    paths.insert("/system/framework/framework-res.apk");
    need(paths.size() <= 512, "Android input count bound");

    for (const auto &path : paths) {
        need(path.starts_with("/system/") || path.starts_with("/vendor/") ||
                     (native_base_api(profile.at("android")) == 30 &&
                      path.starts_with("/system_ext/")),
             "registered system/vendor/system_ext input required");
        relative(path.substr(1));
    }

    return {paths.begin(), paths.end()};
}

Json profile_patch_metadata(const std::filesystem::path &root, std::string_view name) {
    const auto definition = profile_definition(root, name);
    Json result = Json::object();
    const auto directory = authoring_directory(root, name) / "patches";

    for (const auto &node : definition.at("patches")) {
        for (const auto &item : node.at("steps")) {
            const auto step = item.get<std::string>();
            relative(step);
            need(step.ends_with(".json"), "JSON recipe required");
            const auto file = directory / step;
            const auto pin = hash(file, 1 << 20);
            auto data = read_private_json(file, 1 << 20);
            need(data.at("schema") == 1 &&
                         data.at("api") == native_base_api(definition.at("android")) &&
                         !data.contains("sourceSha256"),
                 "canonical JSON recipe required");
            data["sourceSha256"] = pin;
            result[step] = data;
        }
    }

    return result;
}

std::uint64_t native_profile_android_input_reserve(const Json &profile) {
    if (!record_declares(profile, ProfilePlatform::qinggan09, ProfileBoard::nxp)) {
        return 20ULL << 30;
    }

    need(native_base_api(profile.at("android")) == 28, "exact NXP API28 extraction base required");

    return 8ULL << 30;
}

std::uint64_t native_profile_executable_reserve(const Json &profile, std::string_view name) {
    const auto android = profile.value("android", Json::object());

    if (embedded_profile_declares(runtime_profile_reference(profile, name),
                                  ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
        android.value("package", std::string{}) == "system-images;android-28;default;arm64-v8a") {
        return android_candidate_reserve_bytes(profile, name);
    }

    if (!profile_feature(profile, "measured_disk_reserve") ||
        profile.value("id", std::string{}) != name) {
        return 20ULL << 30;
    }

    return android_candidate_reserve_bytes(profile, name);
}

ProfilePreparationArtifacts prepare_profile_artifacts(const std::filesystem::path &root,
                                                      std::string_view name, bool offline,
                                                      const std::filesystem::path &requested_jdk,
                                                      std::string_view target) {
    const auto profile = profile_definition(root, name, target);
    const auto jdk = profile_preparation_jdk(
            root, requested_jdk, embedded_toolchain_manifest().at("javaHelper"), !target.empty());
    const auto profile_pin = sha256_bytes(authoring_profile_bytes(root, name, target));
    const auto logical = native_profile_android_inputs(root, name);

    ensure_private_directory(root / ".local/build");
    const auto lock =
            owner_lock(root / ".local/build" / ("prepare-" + std::string(name) + ".lock"));

    if (!lock->held()) {
        throw cli::LocalizedError("PROFILE_PREPARATION", "error.preparation_running",
                                  {{"profile", std::string(name)}});
    }

    const auto dependencies = install_native_dependencies(root, offline);
    const auto fetched = fetch_native_inputs(root, name, offline, "", 20ULL << 30, {}, {}, target);
    const auto tools = ensure_java_preparation_tools(
            root, jdk, offline, android_candidate_reserve_bytes(profile, name));
    ProfilePreparationArtifacts output;
    output.sdk = tools.sdk;
    const auto archive_pin = profile.at("android").at("sha256").get<std::string>();
    output.base = root / ".local/profiles/common/android-base" / archive_pin;
    ensure_private_directory(output.base.parent_path());

    if (fetched.contains("android_base")) {
        const auto &existing = fetched.at("android_base");
        need(existing.at("directory") == output.base.string() &&
                     existing.at("archive_sha256") == archive_pin &&
                     existing.at("receipt_sha256") == hash(output.base / "base.json", 512 * 1024),
             "cached clean base receipt differs");
    } else {
        const auto archive =
                std::filesystem::path(fetched.at("android_archive").at("file").get<std::string>());
        need(hash(archive, 8ULL << 30) == archive_pin, "clean AOSP archive pin mismatch");

        if (!std::filesystem::exists(output.base) && !std::filesystem::is_symlink(output.base)) {
            prepare_native_base_image(profile.at("android"), archive, output.base);
        }
    }

    const auto base = verify_base(output.base, profile.at("android"));
    JavaPreparationBuildInputs inputs;
    inputs.sdk = tools.sdk;
    inputs.platform = tools.platform;
    inputs.platform_sha256 = tools.platform_sha256;

    if (jdk.empty()) {
        inputs.guest_java =
                install_android_java(root, embedded_toolchain_manifest().at("androidJava"), offline,
                                     android_candidate_reserve_bytes(profile, name));

        if (!inputs.guest_java.empty()) {
            inputs.guest_java_sha256 = sha256_file(inputs.guest_java);
        }
    }

    bool extracting = false;

    for (const auto *image : {"system", "vendor", "system_ext"}) {
        const auto image_name = std::string(image) == "system_ext" ? std::string("system.img")
                                                                   : std::string(image) + ".img";
        const auto image_pin = base.at("files").at(image_name).at("sha256").get<std::string>();
        std::vector<std::string> selected;
        std::map<std::string, std::string> logical_by_member;

        for (const auto &path : logical) {
            if (path.starts_with(std::string("/") + image + "/")) {
                const auto member = std::string(image) == "vendor"       ? path.substr(7)
                                    : std::string(image) == "system_ext" ? path.substr(11)
                                                                         : path;
                selected.push_back(member);
                logical_by_member.emplace(member, path);
            }
        }

        if (selected.empty()) {
            continue;
        }

        const std::string logical_partition = native_base_api(profile.at("android")) == 30 &&
                                                              std::string(image) != "vendor"
                                                      ? image
                                                      : "";
        Json extraction_identity = {{"image_sha256", image_pin}, {"paths", selected}};

        if (!logical_partition.empty()) {
            extraction_identity["logical_partition"] = logical_partition;
        }

        const auto extraction_key = sha256_bytes(extraction_identity.dump());
        const auto cache = root / ".local/profiles/common/android-extracted";
        ensure_private_directory(cache);
        auto directory = cached_native_android_inputs(cache, image_pin, selected,
                                                      logical_partition);

        if (directory.empty()) {
            if (!extracting) {
                progress::report("build_extract");
                extracting = true;
            }

            directory = cache / extraction_key;
            extract_pinned_ext4_files(output.base / image_name, image_pin, selected, directory,
                                      native_profile_android_input_reserve(profile),
                                      logical_partition);
        }

        std::vector<std::string> extracted_paths;
        const auto original_receipt = read_private_json(directory / "receipt.json", 128 * 1024);

        for (auto it = original_receipt.at("files").begin();
             it != original_receipt.at("files").end(); ++it) {
            extracted_paths.push_back("/" + it.key());
        }

        const auto extraction = verify_extraction(directory, image_pin, extracted_paths);

        for (const auto &path : selected) {
            need(extraction.at("files").contains(path.substr(1)),
                 "requested extraction input missing");
        }

        need(logical_partition.empty()
                     ? !extraction.contains("logical_partition")
                     : extraction.value("logical_partition", std::string()) == logical_partition,
             "logical partition extraction receipt mismatch");
        const auto receipt = directory / "receipt.json";
        const auto receipt_pin = hash(receipt, 128 * 1024);

        for (const auto &[member, path] : logical_by_member) {
            (void)member;
            inputs.android_inputs[path] = {receipt, receipt_pin};
        }

        if (std::string(image) == "system") {
            output.system_inputs = directory;
        } else if (std::string(image) == "vendor") {
            output.vendor_inputs = directory;
        }
    }

    ensure_private_directory(root / ".local/build/tmp");
    inputs.patch_data = root / ".local/build/tmp" / ("patch-data-" + random_token() + ".json");
    write_private_json(inputs.patch_data, profile_patch_metadata(root, name));
    inputs.patch_data_sha256 = hash(inputs.patch_data, 4ULL << 20);
    inputs.tool_manifest_sha256 = project_file_sha256(root, "src/app/toolchain.json", 1 << 20);
    inputs.key = fetched.at("signing").at("key").at("file").get<std::string>();
    inputs.key_sha256 = fetched.at("signing").at("key").at("sha256").get<std::string>();
    inputs.certificate = fetched.at("signing").at("cert").at("file").get<std::string>();
    inputs.certificate_sha256 = fetched.at("signing").at("cert").at("sha256").get<std::string>();
    const auto framework_receipt = read_private_json(
            inputs.android_inputs.at("/system/framework/framework-res.apk").receipt);
    const auto framework = output.system_inputs / "system/framework/framework-res.apk";
    const auto framework_pin = framework_receipt.at("files")
                                       .at("system/framework/framework-res.apk")
                                       .at("sha256")
                                       .get<std::string>();
    const auto base_cert = sha256_bytes(pinned_apk_v2_certificate(framework, framework_pin));
    load_pinned_apk_identity(inputs.key, inputs.key_sha256, inputs.certificate,
                             inputs.certificate_sha256, base_cert);
    const std::string exe(os::executable_suffix);
    const auto manifest = project_file_json(root, "src/app/toolchain.json", 128 * 1024);
    const auto build_version = manifest.at("sdk").at("buildTools").get<std::string>();

    for (const auto &file : {"build-tools/" + build_version + "/aapt2" + exe,
                             "build-tools/" + build_version + "/zipalign" + exe}) {
        inputs.tool_files[file] = hash(tools.sdk / file);
    }

    std::optional<ProfileFileNodes> native_files;

    if (native_base_api(profile.at("android")) == 28 &&
        profile.at("patches").contains("ccodec-allocation-a9")) {
        native_files = plan_profile_codec_file_node(root, name, output.system_inputs);
    }

    if (native_base_api(profile.at("android")) == 30) {
        bool has_files = false;

        for (const auto &node : profile.at("patches")) {
            if (node.at("type") == "file") {
                has_files = true;
            }
        }

        if (has_files) {
            native_files = plan_profile_file_nodes(root, name, output.system_inputs,
                                                   output.vendor_inputs, target);
        }
    }

    if (native_files) {
        const auto directory = root / ".local/build" /
                               ("native-files-" + std::string(name) + "-" + random_token());
        publish_file_patches(native_files->patches, directory);
        auto receipt = read_private_json(directory / "receipt.json", 128 * 1024);
        receipt["profile_provenance"] = native_files->provenance;
        write_private_json(directory / "receipt.json", receipt);
        native_files->revalidate();
        inputs.native_files_receipt = directory / "receipt.json";
        inputs.native_files_receipt_sha256 = hash(inputs.native_files_receipt, 128 * 1024);
    }

    for (auto it = profile.at("components").begin(); it != profile.at("components").end(); ++it) {
        const auto relative_name = it.value().get<std::string>();
        relative(relative_name);
        relative(it.key());
        const auto component_source = authoring_directory(root, name) / relative_name;
        const auto definition = read_private_json(component_source / "component.json");

        if (definition.value("type", std::string{}) != "native") {
            continue;
        }

        const auto output_type = definition.value("outputType", std::string("shared-library"));
        need(output_type == "shared-library" || output_type == "executable",
             "unknown native output type");
        need(native_base_api(profile.at("android")) == 28 ||
                     native_base_api(profile.at("android")) == 30,
             "API28/API30 native component required");
        // Native components are CI-built release assets; nothing is compiled here.
        const auto receipt = install_native_component(
                root, std::string(name), it.key(),
                embedded_toolchain_manifest().at("androidNativeComponents"), offline, {}, {},
                native_base_identity(profile.at("android")).abi);
        const auto module = read_private_json(receipt, 1 << 20);
        const auto file = receipt.parent_path() / module.at("output").get<std::string>();

        // The imports of the guest libraries stay undefined; the libraries of the image export
        // them.
        if (definition.contains("guestLibs")) {
            std::vector<std::string> libraries;

            for (const auto &lib : definition.at("guestLibs")) {
                libraries.push_back(lib.get<std::string>());
            }

            libraries.insert(libraries.end(),
                             {"/system/lib64/libc.so", "/system/lib64/libm.so",
                              "/system/lib64/libdl.so", "/system/lib64/libc++.so"});
            const auto slurp = [](const std::filesystem::path &path) {
                need(std::filesystem::file_size(path) <= (64ULL << 20), "bounded ELF required");
                std::ifstream in(path, std::ios::binary);

                return std::string((std::istreambuf_iterator<char>(in)), {});
            };
            std::vector<std::string> payloads;

            for (const auto &lib : libraries) {
                payloads.push_back(slurp(output.system_inputs / lib.substr(1)));
            }

            std::vector<std::pair<std::string, std::string_view>> exporters;

            for (std::size_t i = 0; i < libraries.size(); ++i) {
                exporters.emplace_back(std::filesystem::path(libraries[i]).filename().string(),
                                       payloads[i]);
            }

            verify_link_exports(slurp(file), exporters);
        }

        inputs.native_components[it.key()] = {receipt, hash(receipt, 1 << 20)};
    }

    const auto token = random_token();
    output.work = root / ".local/build" / ("artifacts-" + std::string(name) + "-" + token);
    output.transport = root / ".local/build/tmp" / ("artifact-transport-" + token);
    inputs.work = output.work;
    JavaPreparationRequest request;
    request.profile = name;
    request.target = target;
    request.profile_sha256 = profile_pin;
    request.operation = JavaPreparationOperation::build_artifacts;
    request.build = inputs;
    need(sha256_bytes(authoring_profile_bytes(root, name, target)) == profile_pin,
         "profile changed before artifact preparation");
    progress::report("build_components",
                     {{"count", std::to_string(profile.at("components").size())}});
    output.result = prepare_java_artifacts(root, tools.runtime, request, output.transport,
                                           java_preparation_timeout_ms(request));

    if (native_files) {
        native_files->revalidate();
    }

    need(output.result.at("machine_ready") == false && output.result.at("guest_started") == false,
         "artifact helper exceeded scope");
    output.receipt = {{"schema", 1},
                      {"kind", "native-profile-artifacts"},
                      {"profile", name},
                      {"base", output.base.string()},
                      {"base_receipt_sha256", hash(output.base / "base.json", 512 * 1024)},
                      {"sdk", output.sdk.string()},
                      {"native_dependencies_sha256", sha256_bytes(dependencies.dump())},
                      {"java_tools", tools.receipt},
                      {"base_certificate_sha256", base_cert},
                      {"android_inputs", logical},
                      {"work", output.work.string()},
                      {"transport", output.transport.string()},
                      {"result_sha256", hash(output.transport / "result.json", 4ULL << 20)},
                      {"invocation_sha256", hash(output.transport / "receipt.json", 128 * 1024)},
                      {"request_sha256", hash(output.transport / "request.json", 2ULL << 20)},
                      {"machine_ready", false},
                      {"guest_started", false}};

    if (!target.empty()) {
        output.receipt["target"] = profile_target_identity(profile);
    }

    if (native_files) {
        output.receipt["native_files"] = {{"receipt", inputs.native_files_receipt.string()},
                                          {"receipt_sha256", inputs.native_files_receipt_sha256},
                                          {"provenance", native_files->provenance}};
    }

    write_private_json(output.transport / "profile-artifacts.json", output.receipt);

    return output;
}
} // namespace voyemu
