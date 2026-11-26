#pragma once
#include "base_image.hpp"
#include "check.hpp"
#include "deps.hpp"
#include "model.hpp"
#include "profile_catalog.hpp"
#include <functional>
#include <map>
#include <set>
#include <vector>
namespace voyemu {
struct MachineIdentity;

// Versioned system generations retain every writable application disk in place.
inline std::string portable_system_image_file(const Json &descriptor, unsigned api) {
    const auto file = descriptor.at("file").get<std::string>();
    const auto sha = descriptor.at("sha256").get<std::string>();

    if (file == "android/system.img") {
        return file;
    }

    if (api != 30 || !sha256_text(sha) ||
        file != "android/system-versions/" + sha + "/system.img") {
        throw VoyemuError("PORTABLE_RUNTIME", "exact versioned API30 system image required");
    }

    return file;
}

// A bundled API30 profile that declares the view-observation component takes the UI observer
// bound to it.
inline bool portable_api30_ui_observer_profile(std::string_view profile) {
    for (const auto &record : embedded_profile_catalog()) {
        if (record.at("id") == profile) {
            const auto &definition = record.at("definition");

            return definition.value("components", Json::object()).contains("view-observation") &&
                   native_base_api(definition.at("android")) == 30;
        }
    }

    return false;
}

inline bool portable_ui_observer_binding(const Json &value, std::string_view profile) {
    if (!value.is_object() || !value.contains("dex") || !value.at("dex").is_string() ||
        !value.contains("sha256") || !value.at("sha256").is_string()) {
        return false;
    }

    return value.size() == 2 || (value.size() == 3 && portable_api30_ui_observer_profile(profile) &&
                                 value.contains("profile") && value.at("profile") == profile);
}

struct PortableRuntimeHostBindings {
    std::filesystem::path sdk, clean_base;
    std::filesystem::path
            seed; // Optional explicit portable machine source; never copied into machines/.
    std::map<std::string, std::string> pins; // Absolute locally verified host file -> SHA256.
    unsigned android_port = 5574;
    Json ui_observer =
            Json::object();         // Optional owned observer DEX path/SHA and exact API30 profile.
    Json frontend = Json::object(); // Optional pinned native frontend; SDK control remains
                                    // available without it.
    std::filesystem::path qnx_qemu, graphics, angle;
    unsigned qmp_port = 45995;
    Json refresh_source =
            nullptr; // Exact already validated portable-host snapshot for explicit refresh CAS.
    bool refresh_host = false; // Caller must hold the stopped, owned profile supervisor lock.
                               // Observer/root frontend pins only.
    bool require_cluster =
            true; // Explicit false permits Android-only activation; true requires a QNX seed.
};
// Copies pinned guest image bytes with exclusive creation and sparse zero ranges.
void copy_portable_image(const std::filesystem::path &source, const std::string &sha256,
                         const std::filesystem::path &target,
                         std::uint64_t reserve_bytes = 20ULL << 30);
// Read-only host pin guard; only the exact configured canonical QNX engine may be installed outside
// the project.
std::string verify_portable_host_tool(const std::filesystem::path &,
                                      const PortableRuntimeHostBindings &,
                                      const std::filesystem::path &,
                                      bool allow_installed_qnx = false);

// Reject ambiguous JSON only for profiles opting into the development kernel.
inline Json portable_profile_json(const std::string &bytes) {
    auto profile = Json::parse(bytes);
    std::vector<std::set<std::string>> keys;
    bool duplicate = false, has_development = false;
    auto callback = [&](int, Json::parse_event_t event, Json &value) {
        if (event == Json::parse_event_t::object_start) {
            keys.emplace_back();
        } else if (event == Json::parse_event_t::key) {
            const auto key = value.get<std::string>();

            if (key == "development_kernel") {
                has_development = true;
            }

            if (keys.empty() || !keys.back().insert(key).second) {
                duplicate = true;
            }
        } else if (event == Json::parse_event_t::object_end) {
            keys.pop_back();
        }

        return true;
    };

    (void)Json::parse(bytes, callback);

    if (has_development && duplicate) {
        throw VoyemuError("PORTABLE_RUNTIME", "duplicate development profile key");
    }

    return profile;
}

// Development kernels are CI-built release assets <releaseBase>kernel-<name>-<sha8>/Image; the
// base is optionalTools.kernelBuild.releaseBase in toolchain.json.
inline std::string development_kernel_release_base() {
    return embedded_toolchain_manifest()
            .at("optionalTools")
            .at("kernelBuild")
            .at("releaseBase")
            .get<std::string>();
}

// fetch stores the Image here; prepared machines keep the declaration and their own kernel.
inline std::filesystem::path portable_development_kernel_file(const std::filesystem::path &root,
                                                              const Json &descriptor) {
    return root / ".local/toolchains/downloads/development-kernel" /
           (descriptor.at("sha256").get<std::string>() + ".blob");
}

inline Json portable_development_kernel(const Json &definition) {
    if (!definition.contains("android")) {
        return Json();
    }

    const auto &android = definition.at("android");

    if (!android.contains("development_kernel")) {
        return Json();
    }

    const auto &d = android.at("development_kernel");

    if (!d.is_object() || d.size() != 4 || !d.contains("url") || !d.at("url").is_string() ||
        !d.contains("sha256") || !d.at("sha256").is_string() || !d.contains("abi") ||
        d.at("abi") != android_package_identity(android.value("package", std::string{})).abi ||
        !d.contains("provenance") || !d.at("provenance").is_object() ||
        d.at("provenance").empty()) {
        throw VoyemuError("PORTABLE_RUNTIME", "invalid development kernel descriptor");
    }

    const auto &provenance = d.at("provenance");
    const auto valid_sha = [](const Json &value) {
        if (!value.is_string()) {
            return false;
        }

        const auto text = value.get<std::string>();

        return sha256_text(text);
    };

    for (const auto *key : {"source_revision", "toolchain"}) {
        if (!provenance.contains(key) || !provenance.at(key).is_string() ||
            provenance.at(key).get<std::string>().empty()) {
            throw VoyemuError("PORTABLE_RUNTIME", "development kernel provenance missing");
        }
    }

    for (const auto *key : {"source_content_sha256", "normalized_config_sha256"}) {
        if (!provenance.contains(key) || !valid_sha(provenance.at(key))) {
            throw VoyemuError("PORTABLE_RUNTIME", "development kernel provenance pin invalid");
        }
    }

    if (!provenance.contains("configuration_deviations") ||
        !provenance.at("configuration_deviations").is_array()) {
        throw VoyemuError("PORTABLE_RUNTIME", "development kernel build provenance required");
    }

    for (const auto &deviation : provenance.at("configuration_deviations")) {
        if (!deviation.is_string() || deviation.get<std::string>().empty()) {
            throw VoyemuError("PORTABLE_RUNTIME", "development kernel deviation invalid");
        }
    }

    const auto sha = d.at("sha256").get<std::string>();
    const auto url = d.at("url").get<std::string>();
    const auto suffix = "-" + sha.substr(0, 8) + "/Image";

    // Prepared machines can carry the original release URL in their verified manifest.
    const bool release_url =
            url.starts_with(development_kernel_release_base() + "kernel-") ||
            url.starts_with("https://github.com/voyemu/voyemu/releases/download/kernel-");

    if (!sha256_text(sha) || !release_url || !url.ends_with(suffix) ||
        url.find_first_not_of("abcdefghijklmnopqrstuvwxyzI0123456789-./:") != std::string::npos) {
        throw VoyemuError("PORTABLE_RUNTIME", "invalid development kernel URL or pin");
    }

    return d;
}

// The clean boot files of the image that android, the android object of profile.json, pins in
// clean_base.boot_files, with their SHA-256.
std::map<std::string, std::string> portable_clean_boot_pins(const Json &android);
Json portable_qnx_diagnostic_launch(Json launch, const Json &binding);
bool portable_qnx_diagnostic_current(const Json &launch, const Json &binding);
Json portable_sdk_control_binding(const std::filesystem::path &,
                                  const PortableRuntimeHostBindings &);
// Shared launch assembly; caller supplies already verified immutable pins and owned writable disks.
// Does not publish acceptance, copy images, or start a guest.
// A scoped owned Passion WAV diagnostic run is authorized by one private record inside the
// configured machine directory (schema 1, route "wav", exact profile). Absent that record ordinary
// launches never carry a diagnostic audio field; capture is never a permanent profile policy.
Json audio_diagnostic_activation(const std::filesystem::path &configured_machine_directory);
Json portable_android_launch(const std::filesystem::path &, const PortableRuntimeHostBindings &,
                             const std::filesystem::path &machine,
                             const std::filesystem::path &base, const std::filesystem::path &config,
                             const std::string &avd, Json pins,
                             Json profile_definition = Json::object(),
                             const Json &audio_diagnostic = Json::object(),
                             std::string_view verified_profile = {});
bool portable_runtime_available(const std::filesystem::path &, std::string_view profile,
                                const MachineIdentity &machine,
                                const std::filesystem::path &seed = {});
// Prepared machines use only their own manifest-pinned profile snapshot.
Json portable_profile_definition(const std::filesystem::path &, std::string_view profile,
                                 const MachineIdentity &machine,
                                 const std::filesystem::path &seed = {});
Json inspect_portable_runtime(const std::filesystem::path &, std::string_view profile,
                              const MachineIdentity &machine,
                              const std::filesystem::path &seed = {});
// A host-specific path stored in a shared checkout can name the exact same
// file or directory through Wine's Unix drive mapping.
bool same_wine_host_path(std::string_view recorded, const std::filesystem::path &local);
bool portable_configuration_from_other_host(const Json &record, const std::filesystem::path &root,
                                            std::string_view profile,
                                            const MachineIdentity &machine,
                                            const std::filesystem::path &seed,
                                            std::string_view manifest_sha);
// Configuration-only first binding of an external portable machine. Uses installed
// host dependencies and tiny writable overlays; never copies or SHA-audits guest images.
std::filesystem::path bind_machine_configuration(const std::filesystem::path &root,
                                                 std::string_view profile,
                                                 const MachineIdentity &machine,
                                                 const std::filesystem::path &seed,
                                                 const std::filesystem::path &current_program,
                                                 bool multimedia = true, bool cluster = true);
// Stopped observer publication; payload-only builds do not require private activation.
// Acquires both supervisor locks before preparation; start never reads source observers.
Json refresh_machine_ui_observer(const std::filesystem::path &root, std::string_view profile,
                                 const MachineIdentity &machine, const std::filesystem::path &seed,
                                 const std::function<Json()> &prepare,
                                 bool refresh_configuration = true);
Json publish_machine_android_system(
        const std::filesystem::path &root, std::string_view profile, const MachineIdentity &machine,
        const std::string &expected_manifest_sha, const std::filesystem::path &source,
        const std::string &source_sha, std::uint64_t source_bytes,
        const std::function<void()> &verify_source, const Json &disk_tool,
        const Json &owned_package = Json(), std::uint64_t reserve_bytes = 20ULL << 30,
        const Json &source_evidence = Json(), const Json &camera_package = Json(),
        const Json &prepared_packages = Json());
// Stopped nonpersistent Free A11 QNX replacement; reject changed/unknown old guest files.
Json publish_machine_qnx(const std::filesystem::path &root, std::string_view profile,
                         const MachineIdentity &machine, const std::string &expected_manifest_sha,
                         const std::filesystem::path &accepted_source, const Json &replacement,
                         const std::function<void()> &verify_source);
// Stopped Free A9 boot-only update; keep Android and mutable QNX files unchanged.
Json publish_machine_qnx_boot(const std::filesystem::path &root, std::string_view profile,
                              const MachineIdentity &machine,
                              const std::string &expected_manifest_sha,
                              const std::filesystem::path &accepted_source, const Json &replacement,
                              const std::function<void()> &verify_source);
// Same stopped boot-only transaction for an explicit canonical portable machine directory.
Json publish_machine_qnx_boot_at(const std::filesystem::path &root, std::string_view profile,
                                 const std::filesystem::path &seed,
                                 const std::string &expected_manifest_sha,
                                 const std::filesystem::path &accepted_source,
                                 const Json &replacement,
                                 const std::function<void()> &verify_source);
// Existing build/start calls this on discovery; no new user command or VM launch.
// Publishes scoped local bindings and a private writable AVD without replacing existing files.
Json activate_portable_runtime(const std::filesystem::path &, std::string_view profile,
                               const MachineIdentity &machine, const PortableRuntimeHostBindings &,
                               std::uint64_t reserve_bytes = 20ULL << 30);
} // namespace voyemu
