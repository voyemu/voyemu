#pragma once
#include "android_adb.hpp"
#include "model.hpp"
#include "process.hpp"
#include "zip_archive.hpp"
#include <functional>
#include <map>
namespace voyemu {
struct AndroidCandidateRequest {
    std::string profile, profile_sha256, artifact_result_sha256, clean_receipt_sha256;
    std::filesystem::path artifact_result, clean_base, sdk;
    // The extracted Native Bridge of the Android base, or none.
    std::filesystem::path native_bridge;
    Json native_bridge_descriptor;
    std::map<std::string, std::string> tool_pins; // Absolute host file -> SHA256.
    unsigned port = 5580;
    // The candidate steps other than the boots of the emulator, which have no time limit.
    int overall_timeout_ms = 1800000;
    std::function<bool()> cancelled;
    bool capture_frames = false;
    std::string target;
};
// Internal preparation cleanup helper, also exercised by retained fake-SDK host fixtures.
Json capture_android_candidate_failure(ChildProcess &, const std::filesystem::path &adb,
                                       const std::filesystem::path &stage, unsigned port,
                                       const std::string &avd, const std::string &nonce,
                                       const AndroidOwnedAdb *binding = nullptr,
                                       ChildProcess *server = nullptr) noexcept;
// Failure-only best-effort sync with an independent 10s budget and retained private ownership.
Json sync_android_candidate_failure(ChildProcess &, const std::filesystem::path &adb,
                                    const std::filesystem::path &stage, unsigned port,
                                    const std::string &avd, const std::string &nonce,
                                    const AndroidOwnedAdb *binding, ChildProcess *server) noexcept;
Json android_candidate_failure_log_frame(const ProcessResult &, std::string_view frame,
                                         std::string_view nonce,
                                         const std::vector<std::string> &secrets);
// Fixed SDK bootstrap operation; caller supplies its remaining preparation budget.
void android_candidate_start_multidisplay(ChildProcess &, const std::filesystem::path &adb,
                                          const std::filesystem::path &stage, unsigned port,
                                          int remaining_ms,
                                          const AndroidOwnedAdb *binding = nullptr,
                                          ChildProcess *server = nullptr);
// Pure install ordering: system/framework/policy first, data seeds next, APKs last.
// Returns only a registered clean ARM64 base API; it does not validate OEM compatibility.
unsigned android_candidate_api(const Json &profile);
// System APKs with extractNativeLibs need sibling libraries of each native ABI of the guest, such
// as lib/arm64-v8a; data APKs use PackageManager.
std::vector<ZipEntry>
android_candidate_system_native_libraries(const Json &entry, const std::vector<ZipEntry> &inventory,
                                          std::string_view manifest,
                                          std::string_view abi = "arm64-v8a");
// The guest file with each line of source that it lacks added after its last line.
std::string android_candidate_merged_lines(std::string_view guest, std::string_view source);
// The ABIs whose libraries a system APK provides to a guest of guest_abi, primary first.
std::vector<std::string> android_guest_native_abis(std::string_view guest_abi);

std::string android_candidate_cpu_config(const Json &profile);
// Actual finite Passion system payload plus directory headroom and F2FS reserve.
void android_candidate_require_unused_root_image(const std::filesystem::path &image);
// Stopped unpublished candidate only; failure aborts preparation before reboot/export.
void android_candidate_promote_labelled_system(const std::filesystem::path &machine,
                                               const std::filesystem::path &raw,
                                               const std::string &raw_sha,
                                               const std::string &base_sha,
                                               const std::string &overlay_sha,
                                               std::uint64_t reserve_bytes);
bool android_candidate_api30_root_layout(const Json &profile);
std::uint64_t android_candidate_overlay_scratch_bytes(const Json &profile,
                                                      std::uint64_t payload_bytes);
// Bind launcher environment to the explicitly selected SDK, never executable ancestry.
std::map<std::string, std::string>
android_candidate_sdk_environment(const std::filesystem::path &sdk, bool windows,
                                  std::string_view inherited_path);
std::vector<std::string> android_candidate_capture_arguments(const Json &profile, bool capture,
                                                             unsigned port);
std::vector<std::vector<std::string>> android_candidate_start_commands(const Json &profile);
// Typed settings-put commands for the configure phase; the late set omits the
// global device_name family that OEM boot processes reset during the boot window.
std::vector<std::vector<std::string>> android_candidate_configure_settings(const Json &settings,
                                                                           bool late);
void android_candidate_configure_properties(
        const Json &profile,
        const std::function<std::string(const std::vector<std::string> &)> &shell);
// Apply persistent profile properties before the first boot with installed OEM system APKs.
void android_candidate_home_reboot_checkpoints(unsigned api, bool has_home,
                                               const std::function<void()> &establish,
                                               const std::function<void()> &verify,
                                               const std::function<void()> &cold_boot);
// Cold SELinux label contract for offline_selinux_labels: file labels plus
// option-specific device labels; throws on an unknown label request.
void android_candidate_cold_label_plan(
        const std::string &option, std::vector<std::pair<std::string, std::string>> &file_labels,
        std::vector<std::pair<std::string, std::string>> &device_labels);
// Installed metadata of a file entry with a context as `stat -c '%a %u:%g'` and `ls -Zd` report
// it, for example "660 1000:1000 u:object_r:system_app_data_file:s0".
std::string android_candidate_file_metadata(const Json &entry);
// Failed push: target, remote adb reason, diagnostic shell identity and parent label.
// The shell identity does not identify the adbd sync writer.
std::string android_candidate_write_failure(const std::string &target, const std::string &error,
                                            const std::string &shell_identity,
                                            const std::string &parent);
// Require the same real ext4 root mount before and after the A9 read-only transition.
// The API30 early policy pin follows the platform and the original_navi feature of profile.
void android_candidate_offline_policy_pin(const std::string &artifact, const std::string &expected,
                                          const Json &profile = Json::object());
void android_candidate_first_oem_boot(
        const Json &profile,
        const std::function<std::string(const std::vector<std::string> &)> &shell,
        const std::function<void()> &reboot, const std::function<void()> &prepare_files = {});
std::vector<std::string> android_candidate_art_verify_packages(const Json &profile);
// Classify typed guest argv only; host ADB routing and shell strings are never parsed.
std::string android_candidate_command_log(const std::vector<std::string> &arguments);
bool android_candidate_package_settings_flushed(
        const std::string &xml, const Json &configure,
        const std::optional<std::string> &home_query = std::nullopt);
Json android_candidate_can_check(std::string_view reply, std::string_view boot);
// Retain exact service-list status and missing names; readiness requires a successful full probe.
Json android_candidate_binder_probe(const Json &required, const ProcessResult &probe);
Json android_candidate_vehicle_observer_policy(const Json &profile);
void validate_android_candidate_checks(const Json &profile, const Json &checks);
// Internal rich UI capture contract; optional metadata and partial coverage remain explicit.
Json android_candidate_ui_request(int timeout_ms);
Json android_candidate_ui_observation(Json response, unsigned secondary_display);
Json save_android_candidate_ui_observation(const std::filesystem::path &, const Json &,
                                           unsigned secondary_display);
std::optional<unsigned> android_candidate_secondary_provider(const Json &profile,
                                                             const std::string &displays);
std::optional<unsigned> android_candidate_secondary_display_ready(const Json &profile,
                                                                  const std::string &displays,
                                                                  const std::string &windows);
// A stopped candidate exports the formatted cache, never a host-specific mkfs recipe.
void validate_android_candidate_cache_image(std::string_view header, std::uint64_t bytes);
// Read back real PackageManager privilege and effective APK topology; never infer flags from UID.
Json android_candidate_privileged_apk_check(const Json &entry, const std::string &package,
                                            const std::string &effective, const std::string &dump);
bool android_candidate_home_priorities_ready(const Json &wanted, const std::string &query);
Json android_candidate_install_plan(const Json &profile, const Json &artifacts);
// Reuse the producer manifest boundary before consuming artifact files.
void validate_android_candidate_artifacts(const std::filesystem::path &root,
                                          const AndroidCandidateRequest &, const Json &result);
std::vector<std::string> android_candidate_boot_cache_paths(const Json &profile);
std::vector<std::string> android_candidate_boot_image_command(const Json &profile);
// API30 compiler diagnostics preserve its exact argv/status before owned VM cleanup.
std::vector<std::string>
android_candidate_boot_compile_diagnostic_command(const Json &, const std::string &nonce,
                                                  const std::string &isa = "arm64");
std::vector<std::string> android_candidate_boot_relocation_command(const Json &profile);
std::vector<std::vector<std::string>> android_candidate_system_server_commands(const Json &profile);
std::string android_candidate_boot_properties(std::string_view source, const Json &values);
// Actual remaining writes after the clean base copy: profile scratch preseed
// (its formula also carries the install payload), the grown RAW re-export of
// the copied base images, and a measured fixed guest data/qcow/log allowance.
std::uint64_t android_candidate_peak_extra_bytes(const Json &profile, std::uint64_t base_bytes,
                                                 std::uint64_t payload_bytes,
                                                 std::string_view requested_profile = {});
struct AndroidCandidateBudget {
    std::uint64_t reserve_bytes, peak_extra_bytes;
};
// Exact registered bases retain an 8GiB floor. A9 requires the verified request identity; raw
// profiles need no id.
std::uint64_t android_candidate_reserve_bytes(const Json &profile,
                                              std::string_view requested_profile = {});
AndroidCandidateBudget android_candidate_build_budget(const Json &profile, std::uint64_t base_bytes,
                                                      std::uint64_t payload_bytes,
                                                      std::string_view requested_profile = {});
// Copy the clean base before admitting the remaining candidate/export budget.
void prepare_android_candidate_base(const std::filesystem::path &source, const Json &files,
                                    const std::filesystem::path &destination,
                                    std::uint64_t reserve_bytes, std::uint64_t peak_extra_bytes,
                                    std::function<std::uint64_t()> available = {},
                                    const std::filesystem::path &development_kernel = {},
                                    const std::string &development_sha = {});
// Export only the cold-verified owned Free A11 provider APK; unrelated installed app data stays
// private.
Json export_android_candidate_camera_package(const Json &profile, const Json &artifacts,
                                             const Json &installed,
                                             const std::filesystem::path &destination,
                                             std::uint64_t reserve_bytes = 20ULL << 30);
Json export_android_candidate_owned_package(const Json &profile, const Json &artifacts,
                                            const Json &installed,
                                            const std::filesystem::path &destination,
                                            std::uint64_t reserve_bytes = 20ULL << 30);
// Builds only a NEW owned candidate, never promotes/replaces an existing machine.
// Success requires install, persisted reboot and separate cold boot checks, then stop.
// Exports five relative RAW Android images including the formatted cache; no host snapshots or peer
// userdata. peak_extra_bytes: measured remaining candidate/export write peak for this profile
// (android_candidate_peak_extra_bytes); callers may raise it, never lower below it.
Json build_android_candidate(const std::filesystem::path &root, const AndroidCandidateRequest &,
                             const std::filesystem::path &destination,
                             std::uint64_t reserve_bytes = 20ULL << 30,
                             std::uint64_t peak_extra_bytes = 12ULL << 30);
} // namespace voyemu
