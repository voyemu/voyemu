#pragma once
#include "model.hpp"
#include <functional>
#include <map>
namespace voyemu {
struct MachineIdentity;
// Source-build acceptance uses the actual unified executor without changing saved host bindings.
Json profile_source_graphics_bindings(const std::filesystem::path &root, const Json &bindings,
                                      const std::filesystem::path &current_program);
// Public boot dependencies for an imported prepared guest; no owner originals required.
Json prepare_portable_base(const std::filesystem::path &root, std::string_view profile,
                           bool offline = false, std::uint64_t reserve = 20ULL << 30,
                           std::string_view target = {});
// Read-only genuine accepted QNX closure reuse; original acceptance remains immutable.
Json validate_accepted_qnx_reuse(const std::filesystem::path &root, std::string_view profile,
                                 const std::filesystem::path &receipt, const std::string &sha256,
                                 const std::filesystem::path &payload_source = {});
// Complete source build and bounded guest checks; a machine target preserves the canonical seed.
Json build_profile(const std::filesystem::path &root, std::string_view profile,
                   const MachineIdentity &machine, bool offline = false,
                   const std::filesystem::path &jdk = {}, std::function<bool()> cancelled = {},
                   bool cluster = true, bool multimedia = true,
                   const std::filesystem::path &current_program = {},
                   const std::filesystem::path &reuse_qnx = {},
                   const std::string &reuse_qnx_sha256 = {},
                   const std::filesystem::path &reuse_qnx_source = {},
                   std::string_view target = {});
// Read-only validation of a pinned stopped artifact preparation epoch.
std::string current_profile_revision(const std::filesystem::path &root, std::string_view profile);
Json validate_profile_artifact_resume(const std::filesystem::path &root, std::string_view profile,
                                      const std::filesystem::path &receipt,
                                      const std::string &receipt_sha256,
                                      std::string_view target = {});
// Android preparation stage only; never publishes an Android-only final profile.
Json build_profile_android(const std::filesystem::path &root, std::string_view profile,
                           const MachineIdentity &machine, bool offline = false,
                           const std::filesystem::path &jdk = {},
                           std::function<bool()> cancelled = {},
                           const std::filesystem::path &artifact_receipt = {},
                           const std::string &artifact_receipt_sha256 = {},
                           std::string_view target = {});
// Finalizer consumes an already stopped/cold-verified Android candidate and an
// explicit accepted QNX seed receipt. It never reruns Android or replaces a profile.
// Upgrade stopped QNX boot files; preserve Android and existing Free A9 persistent storage.
Json upgrade_profile_qnx(const std::filesystem::path &root, std::string_view profile,
                         const MachineIdentity &machine, const std::filesystem::path &accepted_qnx,
                         const std::string &acceptance_sha256,
                         const std::filesystem::path &payload_source = {});
Json upgrade_profile_qnx_at(const std::filesystem::path &root, std::string_view profile,
                            const std::filesystem::path &seed,
                            const std::filesystem::path &accepted_qnx,
                            const std::string &acceptance_sha256,
                            const std::filesystem::path &payload_source = {});
Json finalize_profile_build(const std::filesystem::path &root, std::string_view profile,
                            const MachineIdentity &machine,
                            const std::filesystem::path &android_candidate,
                            const std::filesystem::path &qnx_acceptance,
                            const std::string &qnx_acceptance_sha256, bool reuse_qnx = false,
                            const std::filesystem::path &reuse_qnx_source = {},
                            const std::filesystem::path &jdk = {});
// Publisher garbage collection of closed candidate VM working disks after successful publication.
void purge_android_candidate_working_disks(const std::filesystem::path &root,
                                           const std::filesystem::path &android_candidate,
                                           const std::filesystem::path &qemu_img_tool);
// After a one-step build published `publication`, releases the payloads of the generation it
// created: the closed candidate, its fresh artifact work and the given QNX source and accepted
// directories. Keeps evidence, payloads that differ from their receipt and directories another
// consumer leases; reports them in `build_outputs` and never throws.
Json release_build_generation(const std::filesystem::path &root, Json publication,
                              const std::filesystem::path &android_candidate,
                              const std::filesystem::path &qnx_source = {},
                              const std::filesystem::path &qnx_accepted = {});
// Explicit Android-only publication; never claims full QNX acceptance.
Json finalize_android_profile_build(const std::filesystem::path &root, std::string_view profile,
                                    const MachineIdentity &machine,
                                    const std::filesystem::path &android_candidate,
                                    const std::string &candidate_receipt_sha256,
                                    const std::filesystem::path &jdk = {});
// Exact stopped source candidate validation of a system_upgrade profile; exports only its system
// image descriptor.
Json validate_profile_android_system_candidate(const std::filesystem::path &root,
                                               std::string_view profile,
                                               const std::filesystem::path &candidate,
                                               const std::string &receipt_sha256);
// Read-only binding of a stopped source candidate to the exact prepared OEM APK.
Json validate_profile_android_navi_source(const std::filesystem::path &root,
                                          std::string_view profile,
                                          const std::filesystem::path &candidate,
                                          const std::string &receipt_sha256,
                                          const std::filesystem::path &artifact_receipt = {},
                                          const std::string &artifact_receipt_sha256 = {});
Json validate_profile_android_camera_source(const std::filesystem::path &root,
                                            std::string_view profile,
                                            const std::filesystem::path &candidate,
                                            const std::string &receipt_sha256,
                                            const std::filesystem::path &artifact_receipt = {},
                                            const std::string &artifact_receipt_sha256 = {});
Json validate_profile_android_media_source(const std::filesystem::path &root,
                                           std::string_view profile,
                                           const std::filesystem::path &candidate,
                                           const std::string &receipt_sha256,
                                           const std::filesystem::path &artifact_receipt = {},
                                           const std::string &artifact_receipt_sha256 = {});
// Existing machine upgrade retains every persistent app disk and portable snapshot.
Json upgrade_profile_android_system(const std::filesystem::path &root, std::string_view profile,
                                    const MachineIdentity &machine,
                                    const std::filesystem::path &candidate,
                                    const std::string &receipt_sha256,
                                    const std::filesystem::path &artifact_receipt = {},
                                    const std::string &artifact_receipt_sha256 = {});
// Normal built application uses its own pinned program and profile wheel assets.
Json profile_built_frontend_bindings(const std::filesystem::path &, std::string_view,
                                     const MachineIdentity &machine,
                                     std::map<std::string, std::string> &,
                                     const std::filesystem::path &seed = {});
// Read-only frontend schema/pin validation; updates host pins only after complete validation.
Json profile_frontend_bindings(const std::filesystem::path &root, std::string_view profile,
                               const Json &frontend, std::map<std::string, std::string> &host_pins);
// Activates only a complete published portable profile using canonical native SDK
// and explicit private QNX host bindings; never falls back to another profile/peer.
// Validates ready source-matched DEX receipts without discovering or executing a JVM.
Json cached_profile_ui_observer(const std::filesystem::path &);
Json prepare_profile_ui_observer(const std::filesystem::path &root,
                                 const std::filesystem::path &jdk = {});
// Host-only source observer preparation and stopped configuration CAS; never starts a guest.
Json refresh_built_profile_ui_observer(const std::filesystem::path &root, std::string_view profile,
                                       const MachineIdentity &machine,
                                       const std::filesystem::path &seed);
Json activate_built_profile(const std::filesystem::path &root, std::string_view profile,
                            const MachineIdentity &machine, bool require_cluster = true,
                            bool refresh_host = false, const std::filesystem::path &seed = {},
                            bool root_program_only = false);
} // namespace voyemu
