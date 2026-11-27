#include "profile_build_internal.hpp"
#include "profile_catalog.hpp"
#include "project_files.hpp"

// Validates built Android candidates and the artifacts that a resumed build reuses.
namespace voyemu {
using namespace profile_build_detail;
namespace profile_build_detail {
void validate_accepted_android_profile(const std::filesystem::path &android, const Json &candidate,
                                       std::string_view profile, const Json &definition) {
    need(candidate.at("profile") == profile &&
                 candidate.value("profile_file", std::string()) == "profile.json",
         "accepted candidate profile snapshot required");
    const auto file = android / "profile.json";
    ordinary(file);
    need(std::filesystem::hard_link_count(file) == 1, "unaliased accepted profile required");
    const auto bytes = read_private_json_bytes(file, 1 << 20);
    need(sha256_bytes(bytes) == candidate.at("profile_sha256").get<std::string>(),
         "accepted profile output checksum differs");
    need(portable_profile_json(bytes) == definition,
         "authoring configuration differs from cold accepted profile");
}

bool qinggan11_camera_delivery_required(const Json &definition) {
    if (!qinggan11_package_delivery(definition)) {
        return false;
    }

    const auto steps = definition.value("patches", Json::object())
                               .value("Camera", Json::object())
                               .value("steps", Json::array());

    return steps.is_array() &&
           std::find(steps.begin(), steps.end(), Json("api30-camera-virtual.json")) != steps.end();
}

bool qinggan11_navi_delivery_required(const Json &definition) {
    if (!qinggan11_package_delivery(definition)) {
        return false;
    }

    const auto steps = definition.value("patches", Json::object())
                               .value("Navi", Json::object())
                               .value("steps", Json::array());

    return steps.is_array() &&
           std::find(steps.begin(), steps.end(), Json("api30-navi-vin.json")) != steps.end();
}
} // namespace profile_build_detail

static Json validate_plain_android_system_candidate(const std::filesystem::path &root,
                                                    std::string_view profile,
                                                    const std::filesystem::path &android,
                                                    const std::string &receipt_pin,
                                                    bool require_package) {
    root_profile(root, profile);
    ordinary(android);
    inside(root / ".local", android);
    const auto receipt = android / "receipt.json";
    need(hash(receipt, 1 << 20) == receipt_pin, "Android system candidate receipt pin differs");
    const auto candidate = read_private_json(receipt, 1 << 20);
    const auto target = candidate.value("target", Json::object()).value("name", std::string{});
    const auto definition = authoring_profile(root, profile, target);
    need(profile_feature(definition, "system_upgrade"),
         "system-only upgrade requires a supported profile");
    api30_framework_boot::verify(definition);
    need(native_base_api(definition.at("android")) == 30, "API30 system recipe required");
    need(candidate.at("schema") == 1 && candidate.at("kind") == "android-candidate" &&
                 candidate.at("profile") == profile && candidate.at("stopped") == true &&
                 candidate.at("cold_boot_verified") == true &&
                 candidate.at("prepared_VM") == true &&
                 candidate.at("old_machine_modified") == false,
         "source-matched stopped cold Android system candidate required");
    validate_accepted_android_profile(android, candidate, profile, definition);
    need(candidate.at("clean_base_archive_sha256") == definition.at("android").at("sha256") &&
                 candidate.at("android").at("abi") ==
                         native_base_identity(definition.at("android")).abi &&
                 candidate.value("target", Json{}) == profile_target_identity(definition),
         "system candidate base/ABI differs");

    if (const auto development = portable_development_kernel(definition); !development.is_null()) {
        need(candidate.contains("development_kernel") &&
                     candidate.at("development_kernel") == development,
             "candidate development kernel differs from cold boot");
    } else {
        need(!candidate.contains("development_kernel"), "unexpected candidate development kernel");
    }

    validate_android_candidate_checks(definition, candidate.value("checks", Json()));
    const bool original_navi = original_navi_requested(definition) ||
                               candidate.contains("original_navi_system");
    std::set<std::string> compiled;
    unsigned bridge = 0;

    for (const auto &entry : candidate.at("installed")) {
        if ((!original_navi && entry.at("artifact") == "component:view-observation") ||
            (original_navi && entry.at("target") == "/system/framework/framework.jar")) {
            need(entry.at("target") == "/system/framework/framework.jar" &&
                         entry.at("mode") == "0644" && !entry.at("mutable").get<bool>(),
                 "installed system bridge differs");
            ++bridge;
        }

        if (entry.at("artifact") == "compiled-boot-image") {
            need(compiled.insert(entry.at("target").get<std::string>()).second,
                 "duplicate compiled boot image");
        }
    }

    const auto paths = api30_framework_boot::paths(definition);
    need(bridge == 1 && compiled == std::set<std::string>(paths.begin(), paths.end()),
         "complete API30 bridge and boot extension required");
    need(api30_framework_boot::compiled(definition, candidate.at("events")),
         "complete verified API30 boot compilation required");

    if (require_package || candidate.contains("owned_package")) {
        const auto &package = candidate.at("owned_package");
        android_owned_package_descriptor(package, true);
        const auto package_file = android / package.at("file").get<std::string>();
        need(hash(package_file, 16ULL << 20) == package.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(package_file) ==
                             package.at("bytes").get<std::uint64_t>(),
             "candidate owned provider APK differs");
        unsigned providers = 0;

        for (const auto &item : candidate.at("installed")) {
            if (item.at("artifact") == "component:wheel-input") {
                need(item.at("package") == package.at("package") &&
                             item.at("sha256") == package.at("sha256") &&
                             item.at("target").get<std::string>().starts_with("/data/app/"),
                     "candidate cold provider package differs");
                ++providers;
            }
        }

        need(providers == 1, "one cold verified provider package required");
    }

    if (original_navi) {
        const auto proof = read_private_json(android / "artifact-origin.json", 8192);
        need(proof.size() == 6 && proof.at("schema") == 1 &&
                     proof.at("kind") == "android-artifact-origin" &&
                     proof.at("profile") == profile &&
                     proof.at("candidate_receipt_sha256") == receipt_pin,
             "original Navi artifact origin differs");
        const std::filesystem::path origin = proof.at("artifact_receipt").get<std::string>();
        const auto artifact_lease = artifact_reader(
                root, origin, proof.at("artifact_receipt_sha256").get<std::string>());
        const auto verified = validate_profile_artifact_resume(
                root, profile, origin, proof.at("artifact_receipt_sha256").get<std::string>());
        need(verified.at("result_sha256") == candidate.at("artifact_result_sha256"),
             "original Navi artifact epoch differs");
        const auto result = read_private_json(
                std::filesystem::path(verified.at("transport").get<std::string>()) / "result.json",
                16 << 20);
        const auto &native = verified.at("native_files");
        const std::filesystem::path native_receipt = native.at("receipt").get<std::string>();
        inside(root / ".local", native_receipt);
        need(hash(native_receipt, 128 * 1024) == native.at("receipt_sha256").get<std::string>(),
             "Navi SELinux native receipt pin differs");
        const auto native_proof = read_private_json(native_receipt, 128 * 1024);
        unsigned mac_sources = 0;

        for (const auto &row : native_proof.at("files")) {
            if (row.value("id", std::string{}) == "original-navi-selinux") {
                const auto &cert = row.at("certificate_source");
                need(cert.at("source") == "certificate-from-original:Navi" &&
                             cert.at("apk") ==
                                     result.at("artifacts").at("original:Navi").at("file") &&
                             cert.at("apk_sha256") == original_navi_sha &&
                             cert.at("certificate_sha256") == original_navi_cert &&
                             row.at("output_sha256") ==
                                     "c5c361ff9623c3c3798f60210684ae10b5eec48bed7e9e43a3b275f2b36db392" &&
                             !row.contains("donor"),
                     "Navi SELinux certificate origin differs");
                ++mac_sources;
            }
        }

        need(mac_sources == 1, "one native Navi SELinux provenance required");
        const auto &artifact = result.at("artifacts").at("original:Navi");
        const std::filesystem::path file = artifact.at("file").get<std::string>();
        need(hash(file, 512ULL << 20) == original_navi_sha &&
                     std::filesystem::file_size(file) == 226402144,
             "original Navi APK bytes differ");
        const auto certificate =
                sha256_bytes(pinned_apk_v2_certificate(file, std::string(original_navi_sha)));
        original_navi_candidate(definition, native_base_api(definition.at("android")), candidate,
                                result.at("artifacts"), certificate);
    }

    if (qinggan11_navi_delivery_required(definition) && !original_navi) {
        need(candidate.contains("prepared_packages"),
             "current Free A11 Navi recipe requires cold prepared packages");
    }

    if (qinggan11_camera_delivery_required(definition)) {
        need(candidate.contains("camera_package") || candidate.contains("prepared_packages"),
             "current Free A11 Camera recipe requires cold Camera package");
    }

    if (candidate.contains("prepared_packages")) {
        need(qinggan11_package_delivery(definition) && !candidate.contains("camera_package"),
             "exact Free A11 prepared list required");
        const auto &packages = candidate.at("prepared_packages");
        android_prepared_packages_descriptor(packages, true);

        // A profile without a Navi patch exports only its Camera.
        need(definition.at("patches").contains("Navi") || packages.size() == 1,
             "a profile without a Navi patch exports only Camera");

        for (unsigned i = 0; i < packages.size(); ++i) {
            const auto &package = packages.at(i);
            const auto file = android / package.at("file").get<std::string>();
            need(hash(file, 512ULL << 20) == package.at("sha256").get<std::string>() &&
                         std::filesystem::file_size(file) ==
                                 package.at("bytes").get<std::uint64_t>(),
                 "candidate prepared APK differs");
            const std::string artifact = i == 0 ? std::string("patched:Camera") : "patched:Navi";
            unsigned matches = 0;

            for (const auto &item : candidate.at("installed")) {
                if (item.at("artifact") == artifact) {
                    need(item.at("package") == package.at("package") &&
                                 item.at("sha256") == package.at("sha256") &&
                                 item.at("target").get<std::string>().starts_with("/data/app/") &&
                                 !item.at("mutable").get<bool>(),
                         "candidate cold prepared APK differs");
                    ++matches;
                }
            }

            need(matches == 1, "one cold verified prepared APK required");
        }
    }

    if (candidate.contains("camera_package")) {
        need(qinggan11_package_delivery(definition),
             "Camera candidate requires exact Free A11 profile");
        const auto &package = candidate.at("camera_package");
        android_camera_package_descriptor(package, true);
        const auto file = android / package.at("file").get<std::string>();
        need(hash(file, 128ULL << 20) == package.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(file) == package.at("bytes").get<std::uint64_t>(),
             "candidate Camera APK differs");
        unsigned matches = 0;

        for (const auto &item : candidate.at("installed")) {
            if (item.at("artifact") == "patched:Camera") {
                need(item.at("package") == package.at("package") &&
                             item.at("sha256") == package.at("sha256") &&
                             item.at("target").get<std::string>().starts_with("/data/app/") &&
                             !item.at("mutable").get<bool>(),
                     "candidate cold Camera differs");
                ++matches;
            }
        }

        need(matches == 1, "one cold verified Camera required");
    }

    const auto image = candidate.at("android").at("images").at("system.img");
    need(image.is_object() && image.size() == 3 && image.at("file") == "android/system.img",
         "fixed candidate system descriptor required");
    const auto source = android / "android/system.img";
    need(hash(source) == image.at("sha256").get<std::string>() &&
                 std::filesystem::file_size(source) == image.at("bytes").get<std::uint64_t>(),
         "candidate system image differs");
    need(hash(receipt, 1 << 20) == receipt_pin, "candidate receipt changed during validation");

    return image;
}

namespace profile_build_detail {
Json upgrade_pinned_json(const std::filesystem::path &root, const Json &descriptor,
                         std::uint64_t bound) {
    need(descriptor.is_object() && descriptor.size() == 2, "exact proof file/SHA required");
    const std::filesystem::path file = descriptor.at("file").get<std::string>();
    inside(root / ".local", file);
    need(hash(file, bound) == descriptor.at("sha256").get<std::string>(),
         "upgrade proof file pin differs");

    return read_private_json(file, bound);
}
} // namespace profile_build_detail

std::string current_profile_revision(const std::filesystem::path &root, std::string_view profile) {
    const auto directory = authoring_directory(root, profile);
    Json files = Json::object();
    std::uint64_t total = 0;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        ordinary(entry.path());

        if (entry.is_regular_file()) {
            const auto bytes = std::filesystem::file_size(entry.path());
            need(bytes <= 32ULL << 20 && total <= 128ULL << 20 && bytes <= (128ULL << 20) - total,
                 "bounded profile source closure required");
            total += bytes;
            files[entry.path().lexically_relative(directory).generic_string()] = hash(entry.path(),
                                                                                      32ULL << 20);
        }
    }

    return sha256_bytes(files.dump());
}

static void validate_upgrade_artifact(const std::filesystem::path &root, const Json &descriptor,
                                      const std::string &reference);

static void validate_qinggan09_equipment_artifact(const std::filesystem::path &root,
                                                  std::string_view profile,
                                                  const std::filesystem::path &work,
                                                  const Json &artifact) {
    const auto directory = authoring_directory(root, profile);
    const auto definition = authoring_profile(root, profile);

    need(record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
                 definition.at("android").at("package") ==
                         "system-images;android-28;default;arm64-v8a",
         "equipment simulation requires API28 A9 reference family");
    const auto &files = definition.at("files");
    const auto &raw = files.at("hybrid-nvram");
    const auto &simulation = raw.at("simulation");
    need(raw.size() == 2 && simulation.size() == 3 &&
                 simulation.at("kind") == "qinggan09-equipment-item51-v1" &&
                 simulation.at("otherOptions") ==
                         "Preserved synthetic item51 options; not a physical vehicle capture" &&
                 raw.at("file") == files.at("nvram").at("file"),
         "exact explicit equipment simulation and shared JNI seed required");
    const auto powertrain = simulation.at("powertrain").get<std::string>();
    need(powertrain == "hybrid" || powertrain == "ev", "explicit equipment powertrain required");
    const auto seed = directory / "files" / raw.at("file").get<std::string>();
    inside(directory / "files", seed);
    hash(seed, 65536);
    std::ifstream seed_input(seed, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(seed_input)), {});
    std::string value;
    bool found = false;
    std::istringstream lines(text);

    for (std::string line; std::getline(lines, line);) {
        if (line.starts_with("51=")) {
            need(!found, "duplicate equipment item51");
            found = true;
            value = line.substr(3);
        }
    }

    need(found && value.size() >= 26 && value.size() <= 30 && value.size() % 2 == 0 &&
                 std::all_of(value.begin(), value.end(),
                             [](unsigned char c) {
                                 return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                        (c >= 'A' && c <= 'F');
                             }),
         "bounded even ASCII hex equipment required");
    need((std::stoul(value.substr(0, 2), nullptr, 16) & 3) == (powertrain == "hybrid" ? 1U : 0U),
         "equipment seed contradicts powertrain");
    std::string expected(4 * 1024 * 1024, char(0));
    expected[0] = 1;
    expected.replace(0x860, value.size(), value);
    expected.replace(0x20860, value.size(), value);
    const std::filesystem::path output = artifact.at("file").get<std::string>();
    need(output == work / "qinggan09-equipment-nvram.img" &&
                 artifact.at("bytes") == expected.size() &&
                 artifact.at("sha256") == sha256_bytes(expected) &&
                 hash(output, expected.size()) == sha256_bytes(expected) &&
                 std::filesystem::file_size(output) == expected.size(),
         "derived equipment output differs from exact simulation seed/layout");
}

Json validate_profile_artifact_resume(const std::filesystem::path &root, std::string_view profile,
                                      const std::filesystem::path &file, const std::string &pin,
                                      std::string_view target) {
    root_profile(root, profile);
    const auto definition = authoring_profile(root, profile, target);
    const auto identity = profile_target_identity(definition);
    const auto artifact_lease = artifact_reader(root, file, pin);
    ordinary(file);
    inside(root / ".local", file);
    need(file.filename() == "profile-artifacts.json" && hash(file, 1 << 20) == pin,
         "pinned production artifact receipt required");
    const auto receipt = read_private_json(file, 1 << 20);
    need(receipt.at("schema") == 1 && receipt.at("kind") == "native-profile-artifacts" &&
                 receipt.at("profile") == profile && receipt.at("machine_ready") == false &&
                 receipt.at("guest_started") == false &&
                 receipt.value("target", Json{}) == identity,
         "artifact preparation epoch differs");
    const std::filesystem::path transport = receipt.at("transport").get<std::string>(),
                                base = receipt.at("base").get<std::string>(),
                                sdk = receipt.at("sdk").get<std::string>(),
                                work = receipt.at("work").get<std::string>();

    for (const auto &directory : {transport, base, sdk, work}) {
        ordinary(directory);
        inside(root / ".local", directory);
    }

    need(transport == file.parent_path() && sdk == root / ".local/toolchains/native-sdk" &&
                 hash(base / "base.json", 512 * 1024) ==
                         receipt.at("base_receipt_sha256").get<std::string>() &&
                 hash(transport / "result.json", 4ULL << 20) ==
                         receipt.at("result_sha256").get<std::string>(),
         "prepared base/result receipt changed");
    const auto result = read_private_json(transport / "result.json", 4ULL << 20);
    need(result.at("schema") == 1 && result.at("operation") == "build-artifacts" &&
                 result.at("artifacts_built") == true && result.at("machine_ready") == false &&
                 result.at("guest_started") == false && result.at("artifacts").is_object() &&
                 result.at("profile") == profile && result.value("target", Json{}) == identity,
         "prepared artifact profile source closure changed");

    if (!target.empty()) {
        const auto base_pin = identity.at("base_sha256").get<std::string>();
        const auto base_receipt = read_private_json(base / "base.json", 512 * 1024);
        need(receipt.contains("android_inputs") &&
                     base == root / ".local/profiles/common/android-base" / base_pin &&
                     base_receipt.at("archive_sha256") == base_pin &&
                     base_receipt.at("package") == definition.at("android").at("package"),
             "prepared base does not match selected target");
    }

    if (receipt.contains("android_inputs")) {
        need(receipt.contains("invocation_sha256") == receipt.contains("request_sha256"),
             "incomplete invocation pins");

        if (receipt.contains("invocation_sha256")) {
            need(hash(transport / "receipt.json", 128 * 1024) ==
                                 receipt.at("invocation_sha256").get<std::string>() &&
                         hash(transport / "request.json", 2 << 20) ==
                                 receipt.at("request_sha256").get<std::string>(),
                 "prepared invocation pin changed");
        }

        const auto invocation = read_private_json(transport / "receipt.json", 128 * 1024);
        need(invocation.at("schema") == 1 &&
                     invocation.at("kind") == "java-preparation-invocation" &&
                     invocation.at("profile") == profile &&
                     invocation.at("operation") == "build-artifacts" &&
                     invocation.at("guest_started") == false &&
                     invocation.at("result_sha256") == receipt.at("result_sha256") &&
                     invocation.at("helper_sha256") ==
                             receipt.at("java_tools").at("helper_sha256") &&
                     invocation.at("helper_receipt_sha256") ==
                             receipt.at("java_tools").at("helper_receipt_sha256") &&
                     hash(transport / "request.json", 2 << 20) ==
                             invocation.at("request_sha256").get<std::string>(),
             "prepared invocation/request differs");
        const auto request = read_private_json(transport / "request.json", 2 << 20);
        need(request.at("profile") == profile && request.at("root") == root.string() &&
                     request.at("work") == work.string() &&
                     request.at("android_inputs").is_object() &&
                     receipt.at("android_inputs").is_array(),
             "prepared request identity differs");

        if (!target.empty()) {
            const auto bytes = authoring_profile_bytes(root, profile, target);
            need(request.at("resolved_profile") == bytes &&
                         request.at("profile_sha256") == sha256_bytes(bytes),
                 "prepared request target or pinned Android base differs");
        }

        std::set<std::string> selected;

        for (const auto &item : receipt.at("android_inputs")) {
            need(selected.insert(item.get<std::string>()).second, "duplicate Android input");
        }

        need(selected.size() == request.at("android_inputs").size(),
             "prepared Android input coverage differs");
        const std::filesystem::path patch_data = request.at("patch_data").get<std::string>();
        inside(root / ".local", patch_data);
        need(hash(patch_data, 4 << 20) == request.at("patch_data_sha256").get<std::string>(),
             "patch metadata changed");
        const auto &selected_tools = request.at("tools");
        const auto manifest = selected_tools.at("manifest").get<std::string>();
        need(selected_tools.at("sdk") == sdk.string() &&
                     selected_tools.at("manifest_sha256") == sha256_bytes(manifest) &&
                     Json::parse(manifest) ==
                             project_file_json(root, "src/app/toolchain.json", 1 << 20),
             "prepared SDK manifest differs");
        const auto &signing = selected_tools.at("signing");

        for (const auto &[field, pin_field] : std::array<std::pair<std::string, std::string>, 2>{
                     {{"key", "key_sha256"}, {"certificate", "certificate_sha256"}}}) {
            const std::filesystem::path selected_file = signing.at(field).get<std::string>();
            inside(root / ".local", selected_file);
            need(hash(selected_file, 65536) == signing.at(pin_field).get<std::string>(),
                 "signing input changed");
        }

        for (auto at = selected_tools.at("files").begin(); at != selected_tools.at("files").end();
             ++at) {
            const auto selected_file = sdk / at.key();
            inside(sdk, selected_file);
            need(hash(selected_file) == at.value().get<std::string>(), "SDK tool changed");
        }

        if (selected_tools.contains("platform")) {
            const auto &platform = selected_tools.at("platform");
            const std::filesystem::path selected_file = platform.at("file").get<std::string>();
            inside(root / ".local", selected_file);
            need(hash(selected_file) == platform.at("sha256").get<std::string>(),
                 "platform input changed");
        }

        if (request.contains("native_components")) {
            for (const auto &component : request.at("native_components")) {
                const std::filesystem::path proof_file = component.at("receipt").get<std::string>();
                inside(root / ".local", proof_file);
                need(hash(proof_file, 1 << 20) == component.at("receipt_sha256").get<std::string>(),
                     "native component receipt changed");
                const auto proof = read_private_json(proof_file, 1 << 20);
                const auto output = proof_file.parent_path() /
                                    component.at("output").get<std::string>();
                inside(proof_file.parent_path(), output);
                need(proof.at("sha256") == component.at("sha256") &&
                             hash(output) == component.at("sha256").get<std::string>(),
                     "native component changed");
            }
        }

        for (auto at = request.at("android_inputs").begin();
             at != request.at("android_inputs").end(); ++at) {
            const auto logical = at.key();
            need(selected.contains(logical) &&
                         (logical.starts_with("/system/") || logical.starts_with("/vendor/") ||
                          logical.starts_with("/system_ext/")),
                 "unregistered prepared Android input");
            const std::filesystem::path extracted = at.value().at("receipt").get<std::string>();
            inside(root / ".local", extracted);
            need(hash(extracted, 128 * 1024) == at.value().at("receipt_sha256").get<std::string>(),
                 "extraction receipt changed");
            const auto proof = read_private_json(extracted, 128 * 1024);
            const auto name = logical.starts_with("/vendor/")       ? logical.substr(8)
                              : logical.starts_with("/system_ext/") ? logical.substr(12)
                                                                    : logical.substr(1);
            const auto input = extracted.parent_path() / name;
            inside(extracted.parent_path(), input);
            const auto &entry = proof.at("files").at(name);
            need(hash(input) == entry.at("sha256").get<std::string>() &&
                         std::filesystem::file_size(input) ==
                                 entry.at("bytes").get<std::uint64_t>(),
                 "extracted Android input changed");
        }

        if (receipt.contains("native_files")) {
            const auto &handoff = receipt.at("native_files");
            need(request.at("native_files").at("receipt") == handoff.at("receipt") &&
                         request.at("native_files").at("receipt_sha256") ==
                                 handoff.at("receipt_sha256"),
                 "native file request differs");
            const std::filesystem::path native = handoff.at("receipt").get<std::string>();
            inside(root / ".local", native);
            need(hash(native, 128 * 1024) == handoff.at("receipt_sha256").get<std::string>(),
                 "native file receipt changed");
            const auto proof = read_private_json(native, 128 * 1024);
            need(proof.at("profile_provenance") == handoff.at("provenance") &&
                         proof.at("files").is_array() && proof.at("files").size() <= 512,
                 "native file provenance differs");

            for (const auto &entry : proof.at("files")) {
                const std::filesystem::path input = entry.at("input").get<std::string>(),
                                            output = native.parent_path() /
                                                     entry.at("output").get<std::string>();
                inside(root / ".local", input);
                inside(native.parent_path(), output);
                need(hash(input) == entry.at("input_sha256").get<std::string>() &&
                             hash(output) == entry.at("output_sha256").get<std::string>(),
                     "native file input/output changed");
            }
        }
    }

    passion_mcu_helper_graph(root, definition, result.at("artifacts"));

    passion_generated_helper_graph(root, definition, result.at("artifacts"));

    for (auto at = result.at("artifacts").begin(); at != result.at("artifacts").end(); ++at) {
        const auto &artifact = at.value();

        if (artifact.contains("file") && at.key().starts_with("files:")) {
            if (at.key() == "files:hybrid-nvram" && definition.contains("files") &&
                definition.at("files").contains("hybrid-nvram") &&
                definition.at("files").at("hybrid-nvram").contains("simulation")) {
                validate_qinggan09_equipment_artifact(root, profile, work, artifact);
            } else {
                const std::filesystem::path source = artifact.at("file").get<std::string>();
                inside(authoring_directory(root, profile) / "files", source);
                need(hash(source) == artifact.at("sha256").get<std::string>() &&
                             std::filesystem::file_size(source) ==
                                     artifact.at("bytes").get<std::uint64_t>(),
                     "prepared profile artifact changed");
            }
        } else {
            validate_upgrade_artifact(root, artifact, at.key());
        }
    }

    const auto &tools = receipt.at("java_tools");
    const std::filesystem::path helper = tools.at("helper").get<std::string>();
    ordinary(helper);
    inside(root / ".local/toolchains/java-helper", helper);
    need(hash(helper, 16ULL << 20) == tools.at("helper_sha256").get<std::string>() &&
                 hash(helper.parent_path() / "build-receipt.json", 1 << 20) ==
                         tools.at("helper_receipt_sha256").get<std::string>(),
         "prepared Java producer receipt changed");
    const auto owner = read_private_json(helper.parent_path() / "toolchain-receipt.json",
                                         512 * 1024);
    const auto fingerprint = tools.at("fingerprint").get<std::string>();
    need(owner.at("schema") == 1 && owner.at("kind") == "java-preparation-toolchain" &&
                 sha256_text(fingerprint) && owner.at("fingerprint") == fingerprint &&
                 owner.at("fingerprint") == helper.parent_path().filename().string() &&
                 owner.at("helper_sha256") == tools.at("helper_sha256") &&
                 owner.at("build_receipt_sha256") == tools.at("helper_receipt_sha256"),
         "prepared producer ownership fingerprint differs");
    const auto producer = read_private_json(helper.parent_path() / "build-receipt.json", 1 << 20);

    need(producer.at("dependencies").is_array() && producer.at("dependencies").size() <= 64 &&
                 !producer.at("dependencies").empty(),
         "prepared producer dependencies required");
    const auto expected_dependencies = java_helper_source_inputs(root, false).at("dependencies");
    std::set<std::string> dependencies;

    for (const auto &dependency : producer.at("dependencies")) {
        const auto name = dependency.at("file").get<std::string>();
        need(name.starts_with("lib/") && dependencies.insert(name).second &&
                     expected_dependencies.contains(name) &&
                     dependency.at("sha256") == expected_dependencies.at(name),
             "prepared producer dependency name differs");
        const auto path = helper.parent_path() / name;
        inside(helper.parent_path() / "lib", path);
        need(hash(path, 256ULL << 20) == dependency.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(path) ==
                             dependency.at("bytes").get<std::uint64_t>(),
             "prepared producer dependency changed");
    }

    need(dependencies.size() == expected_dependencies.size(),
         "prepared producer dependency coverage differs");

    need(hash(file, 1 << 20) == pin, "artifact receipt changed during validation");

    return receipt;
}

static void validate_upgrade_artifact(const std::filesystem::path &root, const Json &descriptor,
                                      const std::string &reference) {
    if (descriptor.contains("file")) {
        if (descriptor.contains("mcu_helper")) {
            passion_mcu_helper_artifact(root, reference, descriptor);

            return;
        }

        if (descriptor.contains("generated_helper")) {
            passion_generated_helper_artifact(root, reference, descriptor);

            return;
        }

        if (descriptor.contains("power_helper")) {
            passion_power_helper_artifact(root, reference, descriptor);

            return;
        }

        need(descriptor.size() == 3, "exact artifact file descriptor required");
        const std::filesystem::path file = descriptor.at("file").get<std::string>();
        inside(root / ".local", file);
        need(hash(file) == descriptor.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(file) ==
                             descriptor.at("bytes").get<std::uint64_t>(),
             "upgrade artifact file changed");

        return;
    }

    need(descriptor.is_object() && descriptor.size() == 2 && descriptor.contains("directory") &&
                 descriptor.at("files").is_object(),
         "exact artifact tree descriptor required");
    const std::filesystem::path directory = descriptor.at("directory").get<std::string>();
    inside(root / ".local", directory);
    ordinary(directory);
    Json actual = Json::object();

    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        ordinary(entry.path());

        if (entry.is_regular_file()) {
            actual[entry.path().lexically_relative(directory).generic_string()] = {
                    {"sha256", hash(entry.path())},
                    {"bytes", std::filesystem::file_size(entry.path())}};
        }
    }

    need(actual == descriptor.at("files"), "upgrade artifact tree changed");
}

static void validate_owned_package_session_proof(const std::filesystem::path &root,
                                                 const Json &proof, std::string_view profile,
                                                 const std::string &base_pin,
                                                 const std::string &result_pin,
                                                 const std::string &package_pin) {
    need(proof.at("schema") == 1 && proof.at("kind") == "qinggan11-owned-package-session-proof" &&
                 proof.at("profile") == profile && proof.at("base_receipt_sha256") == base_pin &&
                 proof.at("artifact_result_sha256") == result_pin &&
                 proof.at("installed_package_sha256") == package_pin,
         "actual owned Session proof lineage differs");
    need(proof.at("full_audio_startup_acceptance") == true &&
                 proof.at("positive_control_restored") == true &&
                 proof.at("same_boot_sdk_restore") == true,
         "complete actual cold/audio/restore proof required");
    const auto &seed = proof.at("seed");
    const auto &resume = proof.at("resume");
    const auto session = seed.at("session_id").get<std::string>(),
               boot = seed.at("boot_id").get<std::string>();
    need(hex_text(session, 32) && android_boot_id_valid(boot) && resume.at("boot_id") == boot &&
                 seed.at("quickboot").at("mode") == "cold" &&
                 resume.at("quickboot").at("mode") == "restored",
         "actual cold and same-boot restore identity required");
    const auto &saved = proof.at("saved_checkpoint").at("presave");
    const auto &direct = saved.at("receipt");
    const auto challenge = direct.at("save_nonce").get<std::string>();
    need(saved.at("host_session_id") == session && saved.at("guest_boot_id") == boot &&
                 direct.at("schema") == 1 && direct.at("status") == "presave-ready" &&
                 direct.at("session_id") == session && direct.at("boot_id") == boot &&
                 direct.at("sequence") == saved.at("input_sequence") &&
                 direct.at("acoustic_zero") == true && hex_text(challenge, 32),
         "direct operation-bound preSAVE receipt required");
    need(proof.at("seed_stop").at("stopped") == true &&
                 proof.at("resume_stop").at("stopped") == true,
         "owned proof sessions must be stopped");

    for (const char *key : {"seed_zero_streams", "resume_zero_streams"}) {
        const auto &streams = proof.at(key);
        need(streams.is_array() && streams.size() == 12,
             "all twelve actual audio streams required");
        std::set<unsigned> indices;

        for (const auto &stream : streams) {
            const auto index = stream.at("stream_index").get<unsigned>();
            const auto &values = stream.at("current_indices");
            need(index < 12 && indices.insert(index).second && values.is_array() &&
                         !values.empty() && values.size() <= 64,
                 "complete unambiguous audio readback required");

            for (const auto &value : values) {
                need(value.is_number_integer() && value == 0,
                     "actual restored stream remains audible");
            }
        }
    }

    auto count = [&](const Json &value, const char *key, std::uint64_t maximum) {
        need(value.at(key).is_number_integer(), "integer audio measurement required");
        const auto number = value.at(key).get<std::uint64_t>();
        need(number > 0 && number <= maximum, "bounded positive audio measurement required");

        return number;
    };

    for (const char *key : {"startup_quiet_pcm", "resume_entire_startup_pcm"}) {
        const auto &pcm = proof.at(key);
        const auto bytes = count(pcm, "bytes", 1ULL << 30),
                   samples = count(pcm, "samples", 1ULL << 29);
        need(bytes >= samples * 2 && pcm.at("nonzero_samples").is_number_integer() &&
                     pcm.at("nonzero_samples") == 0 && pcm.at("peak").is_number_integer() &&
                     pcm.at("peak") == 0 && pcm.at("seconds").is_number() &&
                     pcm.at("seconds").get<double>() > 0 && pcm.at("seconds").get<double>() <= 3600,
             "measured whole startup silence required");
    }

    const auto &positive = proof.at("positive_pcm");
    const auto samples = count(positive, "samples", 1ULL << 29),
               nonzero = count(positive, "nonzero_samples", 1ULL << 29),
               peak = count(positive, "peak", 32768);
    need(nonzero <= samples && peak > 0, "measured positive route control required");
    const auto &links = proof.at("evidence_links");
    need(links.is_array() && links.size() >= 6 && links.size() <= 128,
         "bounded actual Session/QB/WAV evidence links required");
    std::set<std::string> files;

    for (const auto &link : links) {
        need(link.is_object() && link.size() == 2, "exact evidence file/SHA required");
        const std::filesystem::path file = link.at("file").get<std::string>();
        inside(root / ".local", file);
        need(files.insert(file.string()).second &&
                     hash(file, 1ULL << 30) == link.at("sha256").get<std::string>(),
             "actual Session evidence changed");
    }
}

static Json validate_android_package_upgrade(const std::filesystem::path &root,
                                             std::string_view profile,
                                             const std::filesystem::path &capsule,
                                             const std::string &receipt_pin) {
    root_profile(root, profile);
    need(qinggan11_wheel_provider(authoring_profile(root, profile)),
         "owned package lineage requires the qinggan11 wheel provider");
    ordinary(capsule);
    inside(root / ".local", capsule);
    need(hash(capsule / "receipt.json", 1 << 20) == receipt_pin,
         "package upgrade capsule pin differs");
    const auto lineage = read_private_json(capsule / "receipt.json", 1 << 20);
    need(lineage.is_object() && lineage.size() == 9 && lineage.at("schema") == 1 &&
                 lineage.at("kind") == "android-owned-package-upgrade" &&
                 lineage.at("profile") == profile,
         "exact current owned package capsule required");
    const auto &base = lineage.at("base_candidate");
    need(base.is_object() && base.size() == 2, "exact base candidate directory/pin required");
    const std::filesystem::path directory = base.at("directory").get<std::string>();
    ordinary(directory);
    inside(root / ".local", directory);
    need(directory != capsule, "distinct immutable base candidate required");
    const auto base_pin = base.at("receipt_sha256").get<std::string>();
    const auto image = validate_plain_android_system_candidate(root, profile, directory, base_pin,
                                                               false),
               candidate = read_private_json(directory / "receipt.json", 1 << 20);
    need(candidate.at("kind") == "android-candidate",
         "lineage base must be a direct cold candidate");
    const auto &images = candidate.at("android").at("images");
    need(images.is_object() && images.size() == 5,
         "exact five immutable base image roles required");

    for (const auto *name :
         {"system.img", "vendor.img", "userdata-qemu.img", "encryptionkey.img", "cache.img"}) {
        const auto &role = images.at(name);
        need(role.size() == 3 && role.at("file") == std::string("android/") + name,
             "fixed base image path required");
        const auto file = directory / role.at("file").get<std::string>();
        need(hash(file) == role.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(file) == role.at("bytes").get<std::uint64_t>(),
             "immutable base image changed");
    }

    const auto parent = upgrade_pinned_json(root, lineage.at("parent_artifacts"), 16 << 20),
               result = upgrade_pinned_json(root, lineage.at("artifacts"), 16 << 20);
    need(candidate.at("artifact_result_sha256") == lineage.at("parent_artifacts").at("sha256") &&
                 parent.at("profile") == profile && result.at("profile") == profile &&
                 result.at("schema") == 1 && result.at("artifacts_built") == true &&
                 result.at("guest_started") == false && result.at("machine_ready") == false,
         "base and current artifact source epochs differ");
    const auto &before = parent.at("artifacts");
    const auto &after = result.at("artifacts");
    need(before.is_object() && before.size() == 56 && after.is_object() && after.size() == 56,
         "exact original 56 artifact closure required");
    unsigned unchanged = 0;

    for (auto it = before.begin(); it != before.end(); ++it) {
        need(after.contains(it.key()), "reused artifact role missing");

        if (it.key() != "component:wheel-input") {
            need(after.at(it.key()) == it.value(), "unrelated reused artifact differs");
            ++unchanged;
        }

        validate_upgrade_artifact(root, after.at(it.key()), it.key());
    }

    need(unchanged == 55 && before.at("component:wheel-input") != after.at("component:wheel-input"),
         "exact one-provider artifact derivation required");
    const auto &package = lineage.at("owned_package");
    android_owned_package_descriptor(package, true);
    const auto &artifact = after.at("component:wheel-input");
    need(artifact.at("sha256") == package.at("sha256") &&
                 artifact.at("bytes") == package.at("bytes"),
         "derived provider APK differs");
    const auto proof = upgrade_pinned_json(root, lineage.at("session_proof"), 1 << 20);
    validate_owned_package_session_proof(root, proof, profile, base_pin,
                                         lineage.at("artifacts").at("sha256").get<std::string>(),
                                         package.at("sha256").get<std::string>());
    need(hash(capsule / "receipt.json", 1 << 20) == receipt_pin,
         "package upgrade capsule changed during validation");

    return image;
}

Json validate_profile_android_system_candidate(const std::filesystem::path &root,
                                               std::string_view profile,
                                               const std::filesystem::path &android,
                                               const std::string &receipt_pin) {
    root_profile(root, profile);
    ordinary(android);
    inside(root / ".local", android);
    need(hash(android / "receipt.json", 1 << 20) == receipt_pin, "candidate receipt pin differs");
    const auto receipt = read_private_json(android / "receipt.json", 1 << 20);

    if (receipt.value("kind", std::string{}) == "android-owned-package-upgrade") {
        return validate_android_package_upgrade(root, profile, android, receipt_pin);
    }

    return validate_plain_android_system_candidate(
            root, profile, android, receipt_pin,
            !record_declares(authoring_profile(root, profile), ProfilePlatform::passion,
                             ProfileBoard::sa8155));
}

namespace profile_build_detail {
// QGMedia is installed in the immutable system image. This validates its source
// provenance only; it never exports or installs a second APK over user data.
Json source_system_media_artifact(const std::filesystem::path &root, std::string_view profile,
                                  const std::filesystem::path &android,
                                  const std::string &receipt_pin,
                                  const std::filesystem::path &artifact_receipt,
                                  const std::string &artifact_receipt_pin) {
    const auto candidate = read_private_json(android / "receipt.json", 1 << 20);
    Json media = Json();
    std::filesystem::path media_origin = artifact_receipt;
    std::string media_origin_pin = artifact_receipt_pin;
    const auto source_definition = authoring_profile(root, profile);
    const auto media_steps = source_definition.value("patches", Json::object())
                                     .value("QGMedia", Json::object())
                                     .value("steps", Json::array());
    const bool has_media_recipe = qinggan11_package_delivery(source_definition) &&
                                  std::find(media_steps.begin(), media_steps.end(),
                                            Json("api30-usb-player.json")) != media_steps.end();

    if (has_media_recipe) {
        if (media_origin.empty()) {
            const auto origin = read_private_json(android / "artifact-origin.json", 8192);
            need(origin.size() == 6 && origin.at("schema") == 1 &&
                         origin.at("kind") == "android-artifact-origin" &&
                         origin.at("profile") == profile &&
                         origin.at("candidate_receipt_sha256") == receipt_pin,
                 "exact cold candidate artifact origin required");
            media_origin = origin.at("artifact_receipt").get<std::string>();
            media_origin_pin = origin.at("artifact_receipt_sha256").get<std::string>();
        }

        const auto artifact_lease = artifact_reader(root, media_origin, media_origin_pin);
        const auto verified = validate_profile_artifact_resume(root, profile, media_origin,
                                                               media_origin_pin);
        need(verified.at("result_sha256") == candidate.at("artifact_result_sha256"),
             "media artifact epoch differs from cold candidate");
        const auto artifact_result_file =
                std::filesystem::path(verified.at("transport").get<std::string>()) / "result.json";
        const auto values = read_private_json(artifact_result_file, 16 << 20);
        media = values.at("artifacts").at("patched:QGMedia");
        need(candidate.value("schema", 0) == 1 &&
                     candidate.value("kind", std::string{}) == "android-candidate" &&
                     candidate.at("profile") == profile && candidate.value("stopped", false) &&
                     candidate.value("cold_boot_verified", false) &&
                     candidate.value("prepared_VM", false) &&
                     candidate.contains("old_machine_modified") &&
                     candidate.at("old_machine_modified") == false &&
                     candidate.at("installed").is_array(),
             "stopped source-built Free A11 7.3.1 system candidate required");
        need(media.is_object() && media.size() == 3 && media.contains("file") &&
                     media.contains("sha256") && media.contains("bytes"),
             "exact prepared QGMedia artifact required");
        unsigned matches = 0;

        for (const auto &row : candidate.at("installed")) {
            if (row.at("artifact") == "patched:QGMedia") {
                need(row.at("package") == "com.qinggan.media" &&
                             row.at("sha256") == media.at("sha256") && row.at("mode") == "0644" &&
                             row.contains("mutable") && row.at("mutable") == false &&
                             row.at("target") ==
                                     "/system/priv-app/qgmedia-release-signed/qgmedia-release-signed.apk",
                     "QGMedia must be the exact immutable privileged system APK");
                ++matches;
            }
        }

        need(matches == 1, "exactly one system QGMedia installation required");
        const std::filesystem::path file = media.at("file").get<std::string>();
        ordinary(file);
        inside(root / ".local", file);
        need(hash(file, 64ULL << 20) == media.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(file) == media.at("bytes").get<std::uint64_t>(),
             "source media APK differs");
    }

    return media;
}
} // namespace profile_build_detail

Json validate_profile_android_media_source(const std::filesystem::path &root,
                                           std::string_view profile,
                                           const std::filesystem::path &android,
                                           const std::string &receipt_pin,
                                           const std::filesystem::path &artifact_receipt,
                                           const std::string &artifact_receipt_pin) {
    root_profile(root, profile);
    ordinary(android);
    inside(root / ".local", android);
    need(hash(android / "receipt.json", 1 << 20) == receipt_pin,
         "pinned cold media candidate required");

    return source_system_media_artifact(root, profile, android, receipt_pin, artifact_receipt,
                                        artifact_receipt_pin);
}

namespace profile_build_detail {
Json source_camera_artifact(const std::filesystem::path &root, std::string_view profile,
                            const std::filesystem::path &android, const std::string &receipt_pin,
                            const std::filesystem::path &artifact_receipt,
                            const std::string &artifact_receipt_pin) {
    const auto candidate = read_private_json(android / "receipt.json", 1 << 20);

    if (!candidate.contains("camera_package") && !candidate.contains("prepared_packages")) {
        return Json();
    }

    need(qinggan11_package_delivery(authoring_profile(root, profile)) &&
                 candidate.at("kind") == "android-candidate",
         "Camera artifact requires exact cold Free A11 candidate");
    auto origin = artifact_receipt;
    auto origin_pin = artifact_receipt_pin;

    if (origin.empty()) {
        const auto proof = read_private_json(android / "artifact-origin.json", 8192);
        need(proof.size() == 6 && proof.at("schema") == 1 &&
                     proof.at("kind") == "android-artifact-origin" &&
                     proof.at("profile") == profile &&
                     proof.at("candidate_receipt_sha256") == receipt_pin,
             "Camera artifact origin differs");
        origin = proof.at("artifact_receipt").get<std::string>();
        origin_pin = proof.at("artifact_receipt_sha256").get<std::string>();
    }

    const auto artifact_lease = artifact_reader(root, origin, origin_pin);
    const auto verified = validate_profile_artifact_resume(root, profile, origin, origin_pin);
    need(verified.at("result_sha256") == candidate.at("artifact_result_sha256"),
         "Camera artifact epoch differs");
    const auto result = read_private_json(
            std::filesystem::path(verified.at("transport").get<std::string>()) / "result.json",
            16 << 20);
    const auto artifact = result.at("artifacts").at("patched:Camera");
    const auto &package = candidate.contains("prepared_packages")
                                  ? candidate.at("prepared_packages").at(0)
                                  : candidate.at("camera_package");
    android_camera_package_descriptor(package, true);
    need(artifact.is_object() && artifact.size() == 3 &&
                 artifact.at("sha256") == package.at("sha256") &&
                 artifact.at("bytes") == package.at("bytes"),
         "Camera prepared artifact differs from cold package");
    const std::filesystem::path file = artifact.at("file").get<std::string>();
    ordinary(file);
    inside(root / ".local", file);
    need(hash(file, 128ULL << 20) == artifact.at("sha256").get<std::string>() &&
                 std::filesystem::file_size(file) == artifact.at("bytes").get<std::uint64_t>(),
         "prepared Camera artifact changed");

    return artifact;
}

Json source_navi_artifact(const std::filesystem::path &root, std::string_view profile,
                          const std::filesystem::path &android, const std::string &receipt_pin,
                          const std::filesystem::path &artifact_receipt,
                          const std::string &artifact_receipt_pin) {
    const auto candidate = read_private_json(android / "receipt.json", 1 << 20);

    const auto definition = authoring_profile(root, profile);

    // Only a profile with a Navi patch prepares a Navi package.
    if (!candidate.contains("prepared_packages") || !definition.at("patches").contains("Navi")) {
        return Json();
    }

    need(qinggan11_package_delivery(definition) && candidate.at("kind") == "android-candidate",
         "Navi artifact requires exact cold Free A11 candidate");
    auto origin = artifact_receipt;
    auto origin_pin = artifact_receipt_pin;

    if (origin.empty()) {
        const auto proof = read_private_json(android / "artifact-origin.json", 8192);
        need(proof.size() == 6 && proof.at("schema") == 1 &&
                     proof.at("kind") == "android-artifact-origin" &&
                     proof.at("profile") == profile &&
                     proof.at("candidate_receipt_sha256") == receipt_pin,
             "Navi artifact origin differs");
        origin = proof.at("artifact_receipt").get<std::string>();
        origin_pin = proof.at("artifact_receipt_sha256").get<std::string>();
    }

    const auto artifact_lease = artifact_reader(root, origin, origin_pin);
    const auto verified = validate_profile_artifact_resume(root, profile, origin, origin_pin);
    need(verified.at("result_sha256") == candidate.at("artifact_result_sha256"),
         "Navi artifact epoch differs");
    const auto result = read_private_json(
            std::filesystem::path(verified.at("transport").get<std::string>()) / "result.json",
            16 << 20);
    const auto artifact = result.at("artifacts").at("patched:Navi");
    const auto &packages = candidate.at("prepared_packages");
    android_prepared_packages_descriptor(packages, true);
    const auto &package = packages.at(1);
    need(artifact.is_object() && artifact.size() == 3 &&
                 artifact.at("sha256") == package.at("sha256") &&
                 artifact.at("bytes") == package.at("bytes"),
         "Navi prepared artifact differs from cold package");
    const std::filesystem::path file = artifact.at("file").get<std::string>();
    ordinary(file);
    inside(root / ".local", file);
    need(hash(file, 512ULL << 20) == artifact.at("sha256").get<std::string>() &&
                 std::filesystem::file_size(file) == artifact.at("bytes").get<std::uint64_t>(),
         "prepared Navi artifact changed");

    return artifact;
}
} // namespace profile_build_detail

Json validate_profile_android_navi_source(const std::filesystem::path &root,
                                          std::string_view profile,
                                          const std::filesystem::path &android,
                                          const std::string &receipt_pin,
                                          const std::filesystem::path &artifact_receipt,
                                          const std::string &artifact_receipt_pin) {
    root_profile(root, profile);
    ordinary(android);
    inside(root / ".local", android);
    need(hash(android / "receipt.json", 1 << 20) == receipt_pin,
         "pinned cold Navi candidate required");

    return source_navi_artifact(root, profile, android, receipt_pin, artifact_receipt,
                                artifact_receipt_pin);
}

Json validate_profile_android_camera_source(const std::filesystem::path &root,
                                            std::string_view profile,
                                            const std::filesystem::path &android,
                                            const std::string &receipt_pin,
                                            const std::filesystem::path &artifact_receipt,
                                            const std::string &artifact_receipt_pin) {
    root_profile(root, profile);
    ordinary(android);
    inside(root / ".local", android);
    need(hash(android / "receipt.json", 1 << 20) == receipt_pin,
         "pinned cold Camera candidate required");

    return source_camera_artifact(root, profile, android, receipt_pin, artifact_receipt,
                                  artifact_receipt_pin);
}
} // namespace voyemu
