#pragma once
#include "model.hpp"
#include "profile_identity.hpp"
#include <functional>
namespace voyemu {
// Exact profile bytes for preparation and publication. A selected build target resolves its
// pinned Android base before any consumer computes the profile digest.
std::string authoring_profile_bytes(const std::filesystem::path &root, std::string_view profile,
                                    std::string_view target = {});
// Planners bind every physical input (recipe and SDK descriptor) to their existing guards.
std::string
authoring_profile_bytes(const std::filesystem::path &root, std::string_view profile,
                        const std::function<std::string(const std::filesystem::path &)> &read,
                        std::string_view target = {});
Json authoring_profile(const std::filesystem::path &root, std::string_view profile,
                       std::string_view target = {});
// The build target that deps and build prepare. name is empty for a profile without targets;
// translated tells a guest ABI that the host runs in software translation; preferred tells the
// only target whose guest ABI is the host ABI.
struct ProfileTargetSelection {
    std::string name;
    bool translated = false, preferred = false;
};
// Without a requested name, the only target whose guestAbi is host_abi; any declared target when
// requested. Neither, or several matching targets, stop with PROFILE_TARGET and the target list.
ProfileTargetSelection select_profile_target(const Json &definition, std::string_view requested,
                                             std::string_view host_abi);
// The default machine of a profile is machines/PROFILE, also for its preferred build target;
// another target names machines/PROFILE-TARGET. CLI and Voyemu API share this rule.
std::string profile_target_machine_name(std::string_view profile,
                                        const ProfileTargetSelection &selection);
Json profile_target_identity(const Json &definition);
// The authoring directory profiles/PROFILE of a valid profile id.
std::filesystem::path authoring_directory(const std::filesystem::path &root,
                                          std::string_view profile);
// Every bundled definition declares a valid platform, board and title.
const Json &embedded_profile_catalog();
const Json &embedded_profile(std::string_view id);
std::vector<std::string> embedded_profile_names();
// The bundled profiles that declare this platform and board, in catalog order.
std::vector<std::string> embedded_profile_names(ProfilePlatform platform, ProfileBoard board);
// Whether the bundled profile declares this platform and board; an id outside the catalog, such as
// a local copy, declares none.
bool embedded_profile_declares(std::string_view id, ProfilePlatform platform, ProfileBoard board);
// Whether a profile definition or a machine launch record declares this platform and board; a
// record without a platform declares none.
bool record_declares(const Json &record, ProfilePlatform platform, ProfileBoard board);
// Declared patch dependencies only; component build recipes are a separate graph.
Json declared_patch_plan(const Json &definition);
} // namespace voyemu
