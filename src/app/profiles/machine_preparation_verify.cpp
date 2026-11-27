#include "machine_preparation_internal.hpp"
#include "profile_catalog.hpp"
#include "selinux_patch.hpp"

// Verifies a prepared candidate by a cold boot, captures its frames and exports its images.
namespace voyemu {
using namespace machine_preparation_detail;
namespace {
void verify_qinggan09_can_feedback(Candidate &c, Json &checks) {
    Json observed;
    bool ready = false;
    const auto boot = c.shell({"cat", "/proc/sys/kernel/random/boot_id"});

    for (int attempt = 0; attempt < 10; ++attempt) {
        observed = parse_can_observation(parse_android_provider_reply(
                c.shell({"content", "call", "--uri", "content://com.voyemu.output.vehicle",
                         "--method", "observe", "--arg", R"({"schema":1})"})));

        if (observed.value("status", std::string()) == "ready" &&
            observed.value("boot_id", std::string()) == boot) {
            const auto &values = observed.at("values");
            ready = values.at("vehicle_state.IVI_SOC_MODESET").at("status") == "observed" &&
                    values.at("vehicle_state.HUM_VSP_FUNCTION_SW").at("status") == "observed";
        }

        if (ready) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    need(ready, "cold CAN model feedback unavailable");
    checks.push_back({{"id", "can-model-feedback"}, {"passed", true}, {"observation", observed}});
}

Json export_candidate_image(Candidate &c, const std::string &name,
                            const std::filesystem::path &destination, std::uint64_t reserve,
                            bool require_overlay = false) {
    need(!c.process.alive(), "cannot export live guest images");
    ensure_private_directory(destination / "android");
    std::filesystem::path source;

    for (const auto &file :
         {c.machine / (name + ".qcow2"), c.machine / name, c.machine / "base" / name}) {
        if (std::filesystem::is_regular_file(file)) {
            source = file;
            break;
        }
    }

    need(!source.empty() && (!require_overlay || source == c.machine / (name + ".qcow2")),
         "required guest image/overlay unavailable");
    ordinary(source);
    const auto chain = Json::parse(
            c.host(c.qemu_img, {"info", "--backing-chain", "--output=json", source.string()})
                    .output);
    need(chain.is_array() && chain.size() >= 1 && chain.size() <= 4,
         "bounded guest backing chain required");

    for (const auto &image : chain) {
        const std::filesystem::path file = image.at("filename").get<std::string>();
        ordinary(file);
        need(inside(file, c.machine), "guest image backing leaves owned candidate");

        if (image.contains("full-backing-filename")) {
            const std::filesystem::path backing =
                    image.at("full-backing-filename").get<std::string>();
            ordinary(backing);
            need(inside(backing, c.machine), "foreign guest backing image rejected");
        }
    }

    need(std::filesystem::space(destination).available >= reserve,
         "disk reserve before image export");
    const auto target = destination / "android" / name;
    need(!std::filesystem::exists(target), "fresh image export required");
    c.host(c.qemu_img, {"convert", "-O", "raw", "-S", "4096", source.string(), target.string()},
           300000);
    const auto info =
            Json::parse(c.host(c.qemu_img, {"info", "--output=json", target.string()}).output);
    need(info.at("format") == "raw" && !info.contains("backing-filename") &&
                 std::filesystem::file_size(target) > 0 &&
                 std::filesystem::file_size(target) <= 8ULL << 30,
         "portable RAW image required");
    ordinary(target);
    need(std::filesystem::hard_link_count(target) == 1, "unaliased exported RAW image required");
    const auto epoch = cache_file_identity(target);
    const auto bytes = std::filesystem::file_size(target);
    need(info.at("virtual-size") == bytes, "exported virtual extent differs");

    if (name == "cache.img") {
        std::array<char, 1082> header{};
        std::ifstream input(target, std::ios::binary);
        input.read(header.data(), header.size());
        need(input.gcount() == static_cast<std::streamsize>(header.size()),
             "exported cache header unavailable");
        validate_android_candidate_cache_image(std::string_view(header.data(), header.size()),
                                               bytes);
    }

    const auto sha = sha256_file(target);
    need(cache_file_identity(target) == epoch, "exported RAW image changed during verification");

    return {{"file", "android/" + name}, {"bytes", bytes}, {"sha256", sha}};
}
} // namespace

namespace machine_preparation_detail {
bool CandidateAvbConsole::rejected(const std::filesystem::path &log) {
    std::error_code error;
    const auto size = std::filesystem::file_size(log, error);

    if (error || size <= offset) {
        return false;
    }

    std::ifstream stream(log, std::ios::binary);
    stream.seekg(static_cast<std::streamoff>(offset));
    std::string bytes(std::min<std::uintmax_t>(size - offset, 256 * 1024), '\0');
    stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<std::size_t>(stream.gcount()));
    offset += bytes.size();
    incomplete += bytes;
    std::size_t start = 0;

    for (;;) {
        const auto end = incomplete.find('\n', start);

        if (end == std::string::npos) {
            break;
        }

        std::string_view line(incomplete.data() + start, end - start);
        start = end + 1;

        if (!line.starts_with("[")) {
            continue;
        }

        if (line.find("] Linux version ") != std::string_view::npos) {
            stage = 0;
        } else if (line.find("] init: [libfs_avb]vbmeta digest mismatch") !=
                   std::string_view::npos) {
            stage = 1;
        } else if (stage == 1 && line.find("] init: [libfs_avb]VerifyVbmetaImages failed") !=
                                         std::string_view::npos) {
            stage = 2;
        } else if (stage == 2 &&
                   line.find("] init: InitFatalReboot: signal ") != std::string_view::npos) {
            return true;
        }
    }

    incomplete.erase(0, start);

    if (incomplete.size() > 4096) {
        incomplete.clear();
    }

    return false;
}

void record_cold_check(Json &checks, const std::string &id, const std::string &actual,
                       const std::string &expected) {
    checks.push_back({{"id", id},
                      {"expected", expected},
                      {"actual", actual},
                      {"passed", actual == expected}});
    need(actual == expected, "cold check failed: " + id);
}

bool cold_policy_file(const Json &profile, const Installed &item) {
    if (item.mutable_seed || !item.package.empty() || item.sha256.empty() || item.mode != "0644" ||
        !item.artifact.starts_with("patched:") || !profile.contains("patches")) {
        return false;
    }

    const auto path = std::filesystem::path(item.target);

    const auto parent = path.parent_path().generic_string();

    if (parent != "/system/etc/selinux" && parent != "/system_ext/etc/selinux" &&
        parent != "/product/etc/selinux" && parent != "/vendor/etc/selinux" &&
        parent != "/odm/etc/selinux") {
        return false;
    }

    const auto &patches = profile.at("patches");
    const auto patch = patches.find(item.artifact.substr(8));

    if (patch == patches.end() || patch->value("type", std::string{}) != "file" ||
        patch->value("input", std::string{}) != "android:" + item.target) {
        return false;
    }

    const auto &entries = profile.at("install");

    return std::count_if(entries.begin(), entries.end(), [&](const auto &entry) {
               return entry.value("type", std::string{}) == "file" &&
                      entry.value("artifact", std::string{}) == item.artifact &&
                      entry.value("target", std::string{}) == item.target &&
                      entry.value("mode", std::string("0644")) == "0644" &&
                      entry.value("uid", 0U) == 0 && entry.value("gid", 0U) == 0 &&
                      !entry.value("mutable", false);
           }) == 1;
}

void read_cold_artifact_file(
        const Json &profile, const Installed &item, const std::string &target, Json &checks,
        const std::function<std::string(const std::vector<std::string> &)> &shell) {
    const auto output = shell({"sha256sum", target});

    record_cold_check(checks, "artifact:" + item.artifact + ":" + target, output.substr(0, 64),
                      item.sha256);

    if (original_navi_requested(profile) && item.artifact == "patched:original-navi-selinux") {
        const auto label = shell({"ls", "-Zd", target});
        need(std::regex_search(label,
                               std::regex(R"((?:^|\s)u:object_r:mac_perms_file:s0(?:\s|$))")),
             "Navi policy file SELinux label differs");
        record_cold_check(checks, "navi-mac-label", "u:object_r:mac_perms_file:s0",
                          "u:object_r:mac_perms_file:s0");
    }

    if (!item.mode.empty()) {
        record_cold_check(checks, "mode:" + target, shell({"stat", "-c", "%a", target}),
                          item.mode.substr(1));
    }
}

void verify_cold_policy_files(
        const Json &profile, const std::vector<Installed> &installed, Json &checks,
        const std::function<std::string(const std::vector<std::string> &)> &shell,
        const std::function<void()> &root_for_policy) {
    const auto boot_id = shell({"cat", "/proc/sys/kernel/random/boot_id"});

    need(!boot_id.empty(), "cold policy reader boot identity required");

    const auto verify = [&](const Installed &item) {
        const auto first = checks.size();
        const auto &entries = profile.at("install");
        const auto entry = std::find_if(entries.begin(), entries.end(), [&](const auto &value) {
            return value.value("artifact", std::string{}) == item.artifact &&
                   value.value("target", std::string{}) == item.target;
        });
        need(entry != entries.end(), "cold policy declaration required");

        if (entry->contains("context")) {
            record_cold_check(checks, "metadata:" + item.target,
                              guest_file_metadata(item.target, shell),
                              android_candidate_file_metadata(*entry));
        }

        read_cold_artifact_file(profile, item, item.target, checks, shell);

        for (auto index = first; index < checks.size(); ++index) {
            checks.at(index)["boot_id"] = boot_id;
            checks.at(index)["path"] = item.target;
            checks.at(index)["artifact"] = item.artifact;
        }
    };

    const auto passion = record_declares(profile, ProfilePlatform::passion, ProfileBoard::sa8155);
    std::vector<const Installed *> restricted;

    for (const auto &item : installed) {
        if (!cold_policy_file(profile, item)) {
            continue;
        }

        // The SDK's stock shell can read the other patch targets, but not hwservice contexts.
        const bool passion_hwservice = passion &&
                                       item.artifact == "patched:passion-hwservice-contexts" &&
                                       item.target == "/system/etc/selinux/plat_hwservice_contexts";

        if (item.artifact == "patched:original-navi-selinux" || passion_hwservice) {
            need(std::none_of(restricted.begin(), restricted.end(),
                              [&](const Installed *previous) {
                                  return previous->target == item.target;
                              }),
                 "duplicate restricted cold SELinux artifact");
            restricted.push_back(&item);
        } else {
            verify(item);
        }
    }

    if (restricted.empty()) {
        return;
    }

    need(static_cast<bool>(root_for_policy), "root proof required to read restricted cold policy");
    root_for_policy();
    need(shell({"cat", "/proc/sys/kernel/random/boot_id"}) == boot_id,
         "cold policy reader boot identity changed");

    for (const auto *policy : restricted) {
        verify(*policy);
    }
}

bool cold_policy_verified(const Json &profile, const Installed &item, const Json &checks,
                          const std::string &boot_id) {
    if (!cold_policy_file(profile, item) || boot_id.empty()) {
        return false;
    }

    std::vector<std::pair<std::string, std::string>> expected = {
            {"artifact:" + item.artifact + ":" + item.target, item.sha256},
            {"mode:" + item.target, item.mode.substr(1)}};

    for (const auto &entry : profile.at("install")) {
        if (entry.value("artifact", std::string{}) == item.artifact &&
            entry.value("target", std::string{}) == item.target && entry.contains("context")) {
            expected.emplace_back("metadata:" + item.target,
                                  android_candidate_file_metadata(entry));
        }
    }

    if (original_navi_requested(profile) && item.artifact == "patched:original-navi-selinux") {
        expected.emplace_back("navi-mac-label", "u:object_r:mac_perms_file:s0");
    }

    auto bound = [&](const auto &check) {
        return check.value("artifact", std::string{}) == item.artifact &&
               check.value("path", std::string{}) == item.target &&
               check.value("boot_id", std::string{}) == boot_id;
    };

    if (std::count_if(checks.begin(), checks.end(), bound) !=
        static_cast<std::ptrdiff_t>(expected.size())) {
        return false;
    }

    return std::all_of(expected.begin(), expected.end(), [&](const auto &value) {
        return std::count_if(checks.begin(), checks.end(), [&](const auto &check) {
                   return bound(check) && check.value("id", std::string{}) == value.first &&
                          check.value("passed", false) &&
                          check.value("expected", std::string{}) == value.second &&
                          check.value("actual", std::string{}) == value.second;
               }) == 1;
    });
}

void verify_cold_installed_file(
        const Json &profile, const Installed &item, const std::string &target, Json &checks,
        const std::string &boot_id,
        const std::function<std::string(const std::vector<std::string> &)> &shell) {
    if (cold_policy_file(profile, item)) {
        need(target == item.target && cold_policy_verified(profile, item, checks, boot_id),
             "complete current cold policy verification required: " + item.target);

        return;
    }

    read_cold_artifact_file(profile, item, target, checks, shell);
}

void verify_cold_original_navi(Candidate &c, Json &checks) {
    const auto start = c.shell(
            {"am", "start", "-W", "-n", "com.baidu.naviauto/com.baidu.naviauto.NaviAutoActivity"},
            60000);

    need(start.find("Error:") == std::string::npos && start.find("Status: ok") != std::string::npos,
         "original Navi launch not confirmed");
    const auto pid = c.shell({"pidof", "com.baidu.naviauto"});
    need(std::regex_match(pid, std::regex("[1-9][0-9]{0,9}")), "one Navi process PID required");

    // Stock shell is the authorized process-label reader. NAME uses the process argv[0].
    const auto ps = c.shell({"ps", "-p", pid, "-o", "LABEL,PID,NAME", "-w"});
    write(c.stage / "cold-navi-process.txt", ps + "\n");
    const auto context = original_navi_process_context(ps, pid);
    need(!context.empty(), "actual Navi platform_app process missing");
    checks.push_back({{"id", "original-navi-security"},
                      {"passed", true},
                      {"package", "com.baidu.naviauto"},
                      {"policy_seinfo", "platform"},
                      {"policy_seinfo_source", "pinned-mac-policy"},
                      {"process_context", context},
                      {"pid", pid}});
}

void verify_cold(Candidate &c, const Json &profile, const std::vector<Installed> &installed,
                 Json &checks) {
    const auto cold_boot_id = c.shell({"cat", "/proc/sys/kernel/random/boot_id"});
    auto equal = [&](const std::string &id, const std::string &actual,
                     const std::string &expected) {
        record_cold_check(checks, id, actual, expected);
    };

    equal("boot", c.shell({"getprop", "sys.boot_completed"}), "1");
    equal("api", c.shell({"getprop", "ro.build.version.sdk"}),
          std::to_string(android_candidate_api(profile)));
    equal("abi", c.shell({"getprop", "ro.product.cpu.abi"}),
          std::string(native_base_identity(profile.at("android")).abi));
    equal("selinux", c.shell({"getenforce"}), "Enforcing");

    if (qinggan11_ui_observer_policy_requested(profile)) {
        equal("ui-observer-root-uid", c.shell({"id", "-u"}), "0");
        equal("ui-observer-root-context", c.shell({"id", "-Z"}), "u:r:su:s0");
        equal("ui-observer-accessibility", c.shell({"service", "check", "accessibility"}),
              "Service accessibility: found");
        equal("ui-observer-accessibility-boot", c.shell({"cat", "/proc/sys/kernel/random/boot_id"}),
              cold_boot_id);
    }

    if (profile.at("android").contains("offline_selinux_labels")) {
        const auto cold_option =
                profile.at("android").at("offline_selinux_labels").get<std::string>();
        std::vector<std::pair<std::string, std::string>> cold_files, cold_devices;
        android_candidate_cold_label_plan(cold_option, cold_files, cold_devices);

        for (const auto &[path, context] : cold_files) {
            const auto label = c.shell({"ls", "-Zd", path});
            need(std::regex_search(
                         label, std::regex(R"((?:^|\s))" + regex_escape(context) + R"((?:\s|$))")),
                 "cold SELinux label differs: " + path);
            equal("label:" + path, context, context);
        }

        equal("early-ready", c.shell({"getprop", "sys.voyemu.early.ready"}), "1");
        equal("can-simulator", c.shell({"getprop", "init.svc.can-simulator"}), "running");

        if (cold_option == "qinggan09-can-early-v1") {
            verify_qinggan09_can_feedback(c, checks);
        }

        for (const auto &[path, context] : cold_devices) {
            const auto label = c.shell({"ls", "-Zd", path});
            need(std::regex_search(
                         label, std::regex(R"((?:^|\s))" + regex_escape(context) + R"((?:\s|$))")),
                 "cold device label differs: " + path);
            equal("label:" + path, context, context);
        }
    }

    // A mutable seed keeps no content hash, but its mode, owner and label survive the cold boot.
    for (const auto &entry : profile.at("install")) {
        if (entry.value("type", std::string{}) == "file" && entry.contains("context")) {
            const auto target = entry.at("target").get<std::string>();
            const auto item =
                    std::find_if(installed.begin(), installed.end(), [&](const auto &value) {
                        return value.artifact == entry.at("artifact").get<std::string>() &&
                               value.target == target;
                    });

            if (item != installed.end() && cold_policy_file(profile, *item)) {
                need(cold_policy_verified(profile, *item, checks, cold_boot_id),
                     "complete cold policy metadata verification required: " + target);
                continue;
            }

            equal("metadata:" + target, guest_file_metadata(c, target),
                  android_candidate_file_metadata(entry));
        }
    }

    for (const auto &item : installed) {
        if (item.mutable_seed || item.sha256.empty()) {
            continue;
        }

        std::string target = item.target;

        if (!item.package.empty()) {
            const auto result = lines(c.shell({"pm", "path", item.package}));
            need(result.size() == 1 && result[0].starts_with("package:/"),
                 "cold package topology differs");
            target = result[0].substr(8);
        }

        if (!item.package.empty() && item.target.starts_with("/system/priv-app/")) {
            equal("privileged-base:" + item.target,
                  c.shell({"sha256sum", item.target},
                          android_candidate_cold_command_timeout({"sha256sum", item.target}))
                          .substr(0, 64),
                  item.sha256);
            const auto parent = std::filesystem::path(item.target).parent_path().generic_string();
            equal("privileged-owner:" + item.target, c.shell({"stat", "-c", "%u:%g", item.target}),
                  "0:0");
            equal("privileged-parent-mode:" + parent, c.shell({"stat", "-c", "%a", parent}), "755");
            equal("privileged-parent-owner:" + parent, c.shell({"stat", "-c", "%u:%g", parent}),
                  "0:0");

            for (const auto &path : {parent, item.target}) {
                const auto label = c.shell({"ls", "-Zd", path});
                need(std::regex_search(label,
                                       std::regex(R"((?:^|\s)u:object_r:system_file:s0(?:\s|$))")),
                     "privileged APK SELinux label differs");
                equal("privileged-label:" + path, "u:object_r:system_file:s0",
                      "u:object_r:system_file:s0");
            }

            const auto dump = c.shell({"dumpsys", "package", item.package});
            write(c.stage / ("privileged-package-" + sha256_bytes(item.package).substr(0, 16) +
                             ".txt"),
                  dump);
            checks.push_back(android_candidate_privileged_apk_check(
                    {{"target", item.target}, {"package", item.package}}, item.package, target,
                    dump));

            if (original_navi_requested(profile) && item.artifact == "component:canbus") {
                const std::regex provider(
                        R"(\[com\.voyemu\.free731\.identity\]:\s*\n\s*Provider\{[^\n]*com\.qinggan\.canbus\.service/\.VinIdentityProvider\})");
                need(std::regex_search(dump, provider), "original Navi provider authority missing");
                checks.push_back({{"id", "provider:com.voyemu.free731.identity"},
                                  {"passed", true},
                                  {"package", item.package},
                                  {"class", "com.qinggan.canbus.service.VinIdentityProvider"},
                                  {"artifact_sha256", item.sha256}});
            }
        }

        verify_cold_installed_file(
                profile, item, target, checks, cold_boot_id, [&](const auto &command) {
                    return c.shell(command, android_candidate_cold_command_timeout(command));
                });
    }

    const auto config = profile.value("configure", Json::object());
    const auto settings = config.value("settings", Json::object());

    for (auto space = settings.begin(); space != settings.end(); ++space) {
        for (auto value = space.value().begin(); value != space.value().end(); ++value) {
            equal("setting:" + space.key() + ":" + value.key(),
                  c.shell({"settings", "get", space.key(), value.key()}),
                  value.value().get<std::string>());
        }
    }

    for (const auto &group : {"properties", "bootProperties"}) {
        const auto values = config.value(group, Json::object());

        for (auto value = values.begin(); value != values.end(); ++value) {
            equal("property:" + value.key(), c.shell({"getprop", value.key()}),
                  value.value().get<std::string>());
        }
    }

    persisted(c, profile, installed);
    const auto wanted_priorities =
            profile.value("verify", Json::object()).value("homePriorities", Json::object());

    if (!wanted_priorities.empty()) {
        const auto priorities =
                c.shell({"cmd", "package", "query-activities", "--brief", "--user", "0", "-a",
                         "android.intent.action.MAIN", "-c", "android.intent.category.HOME", "-p",
                         config.at("home").get<std::string>()});
        write(c.stage / "cold-home-priorities.txt", priorities);
        const bool passed = android_candidate_home_priorities_ready(wanted_priorities, priorities);
        checks.push_back(
                {{"id", "home-priorities"}, {"passed", passed}, {"expected", wanted_priorities}});
        need(passed, "original HOME activity priorities differ");
    }

    for (const auto &overlay : config.value("overlays", Json::array())) {
        need(c.shell({"cmd", "overlay", "list", "--user", "0"})
                             .find("[x] " + overlay.get<std::string>()) != std::string::npos,
             "overlay not enabled after cold boot");
    }

    const auto verify = profile.value("verify", Json::object());
    ProcessResult binder_probe{-1, {}, false};
    bool binder_attempted = false;
    try {
        c.wait(
                [&] {
                    c.identity();
                    binder_attempted = true;
                    c.host(c.adb,
                           {"-s", "emulator-" + std::to_string(c.port), "shell",
                            shell_line({"service", "list"})},
                           10000, &binder_probe);
                    const auto observed = android_candidate_binder_probe(
                            verify.value("services", Json::array()), binder_probe);
                    need(observed.at("ready").get<bool>(),
                         "missing Binder services: " + observed.at("missing").dump());

                    return true;
                },
                60000, "profile Binder services");
    } catch (...) {
        auto observed = android_candidate_binder_probe(verify.value("services", Json::array()),
                                                       binder_probe);
        observed["probe_attempted"] = binder_attempted;
        write_private_json(c.stage / "cold-services-failure.json", observed);
        throw;
    }

    c.wait(
            [&] {
                const auto windows = c.shell({"dumpsys", "window", "windows"}),
                           displays = c.shell({"dumpsys", "display"});
                const auto second = android_candidate_secondary_display_ready(profile, displays,
                                                                              windows);

                for (const auto &activity : verify.value("activities", Json::array())) {
                    const auto logical = activity.at("display").get<unsigned>();

                    if (logical > 1 || (logical && !second) ||
                        !visible(windows, activity.at("component").get<std::string>(),
                                 logical ? *second : 0)) {
                        return false;
                    }
                }

                return true;
            },
            60000, "profile activities");
    const auto services = c.shell({"service", "list"});

    for (const auto &name : verify.value("services", Json::array())) {
        const bool ready = std::regex_search(
                services, std::regex("(?:^|\\n)\\s*\\d+\\s+" +
                                     regex_escape(name.get<std::string>()) + ":\\s*\\["));
        checks.push_back({{"id", "service:" + name.get<std::string>()}, {"passed", ready}});
        need(ready, "cold service missing: " + name.get<std::string>());
    }

    const auto windows = c.shell({"dumpsys", "window", "windows"}),
               displays = c.shell({"dumpsys", "display"});
    write(c.stage / "cold-windows.txt", windows);
    write(c.stage / "cold-displays.txt", displays);
    write(c.stage / "cold-services.txt", services);
    const auto second = android_candidate_secondary_display_ready(profile, displays, windows);
    // The multimedia screens; the provider numbers a rear screen on its own, see RearScreen.
    const auto screens = android_screens(profile.at("displays"));
    const auto multimedia = std::min<std::size_t>(screens.size(), 2);
    need(multimedia == 1 || second.has_value(), "cold secondary display/Home not ready");

    for (unsigned logical = 0; logical < multimedia; ++logical) {
        const auto actual = logical ? *second : 0;
        const auto &wanted = screens.at(logical);
        bool matched = false;
        std::size_t at = 0;

        while (at < displays.size()) {
            auto next = displays.find("DisplayInfo{", at + 1);
            const auto block = displays.substr(at, next == std::string::npos ? std::string::npos
                                                                             : next - at);
            const auto width = std::to_string(wanted.width), height = std::to_string(wanted.height),
                       density = std::to_string(wanted.density);

            if (std::regex_search(block, std::regex("(?:mDisplayId|displayId)[ =]+" +
                                                    std::to_string(actual) + "(?:\\D|$)")) &&
                std::regex_search(block, std::regex("(?:real |logicalWidth=)?" + width +
                                                    "(?: x |,? logicalHeight=)" + height)) &&
                std::regex_search(block, std::regex("(?:density |logicalDensityDpi=)" + density +
                                                    "(?:\\D|$)"))) {
                matched = true;
            }

            if (next == std::string::npos) {
                break;
            }

            at = next;
        }

        checks.push_back({{"id", "display:" + std::to_string(logical)},
                          {"actual_display", actual},
                          {"passed", matched}});
        need(matched, "cold display dimensions/density differ");
    }

    for (const auto &activity : verify.value("activities", Json::array())) {
        const auto logical = activity.at("display").get<unsigned>();
        need(logical <= 1, "registered logical display required");
        const auto actual = logical ? *second : 0;
        const bool ready = visible(windows, activity.at("component").get<std::string>(), actual);
        checks.push_back({{"id", "activity:" + activity.at("component").get<std::string>()},
                          {"display", actual},
                          {"passed", ready}});
        need(ready, "cold activity not visible on expected display");
    }

    if (verify.contains("windows")) {
        const auto declared = verify.at("windows");
        const auto observed = blocks(windows);

        for (const auto &group : {"required", "optional"}) {
            const auto rules = declared.value(group, Json::object());

            for (auto title = rules.begin(); title != rules.end(); ++title) {
                std::vector<unsigned> found;

                for (const auto &block : observed) {
                    std::smatch header, id;

                    if (std::regex_search(
                                block, header,
                                std::regex(
                                        R"((?:^|\n)\s*Window #\d+ Window\{\S+ u\d+ (.*?)\}:)")) &&
                        header[1].str() == title.key() &&
                        block.find(declared.at("package").get<std::string>() + " ") !=
                                std::string::npos &&
                        std::regex_search(block, id, std::regex(R"(mDisplayId=(\d+))"))) {
                        found.push_back(static_cast<unsigned>(std::stoul(id[1].str())));
                    }
                }

                const auto logical = title.value().get<unsigned>();
                need(logical <= 1, "window display role");
                const auto actual = logical ? *second : 0;
                const bool passed = (found.empty() && std::string(group) == "optional") ||
                                    (found.size() == 1 && found[0] == actual);
                checks.push_back({{"id", "window:" + title.key()}, {"passed", passed}});
                need(passed, "cold OEM window routing failed: " + title.key());
            }
        }
    }

    for (const auto &component : verify.value("bindings", Json::array())) {
        const auto name = component.get<std::string>();
        c.wait(
                [&] {
                    return binding_ready(c.shell({"dumpsys", "activity", "services", name}), name);
                },
                60000, "active service binding");
        checks.push_back({{"id", "binding:" + name}, {"passed", true}});
    }

    const auto usage = c.shell({"content"});
    need(usage.find("usage: adb shell content [subcommand] [options]") != std::string::npos,
         "cold content entrypoint unavailable");
    checks.push_back({{"id", "cli:content:entrypoint"}, {"passed", true}});
    const auto observer = android_candidate_vehicle_observer_policy(profile);

    if (!observer.at("supported").get<bool>()) {
        checks.push_back(observer);
    } else {
        const Json can_query = {{"schema", 1},
                                {"states", Json::array({"IVI_SOC_MODESET", "HUM_VSP_FUNCTION_SW"})},
                                {"limit", 1}};
        c.wait(
                [&] {
                    const auto boot = c.shell({"cat", "/proc/sys/kernel/random/boot_id"});
                    const auto response = c.shell(
                            {"content", "call", "--uri", "content://com.voyemu.output.vehicle",
                             "--method", "observe", "--arg", can_query.dump()});
                    const auto proof = android_candidate_can_check(response, boot);
                    need(c.shell({"cat", "/proc/sys/kernel/random/boot_id"}) == boot,
                         "cold CAN check crossed guest boot");
                    checks.push_back(proof);

                    return true;
                },
                30000, "content CLI read-only CAN proof");
    }
}

Json capture_candidate_frames(Candidate &c, const Json &profile) {
    c.identity();
    const auto boot = c.shell({"cat", "/proc/sys/kernel/random/boot_id"});
    const auto windows = c.shell({"dumpsys", "window", "windows"}),
               displays = c.shell({"dumpsys", "display"});
    const auto second = android_candidate_secondary_display_ready(profile, displays, windows);
    need(second.has_value(), "secondary window/display must remain ready for native capture");
    const auto os_root = std::getenv(std::string(os::sdk_discovery_root_variable).c_str());
    const auto registration = sdk_registration_directory(os_root ? os_root : "",
                                                         c.stage / "emulator-home");
    const auto grpc = c.port + 30000;
    std::optional<media::Connection> connection;
    ensure_private_directory(c.stage / "sdk-metadata");
    c.wait(
            [&] {
                c.identity();

                need(c.process.owns_tcp_listener(grpc), "owned SDK gRPC listener is not ready");

                const auto found =
                        sdk_discovery(c.stage / ("emulator-" + std::to_string(c.boots) + ".log"),
                                      registration, static_cast<unsigned>(c.process.pid()), false,
                                      SdkAdvertisementWindow::startup);
                need(found.has_value(), "owned SDK startup advertisement is not ready");

                const auto copied =
                        import_sdk_descriptor(*found, c.stage / "sdk-metadata" / found->filename(),
                                              static_cast<unsigned>(c.process.pid()), c.port, grpc);

                need(copied.has_value(), "owned SDK discovery descriptor is not ready");

                const auto record = c.stage / "media-connection.json";
                write_private_json(record, {{"schema", 1},
                                            {"session_id", c.token},
                                            {"vm_pid", c.process.pid()},
                                            {"discovery", copied->string()},
                                            {"grpc_port", grpc},
                                            {"serial_port", c.port}});
                connection = media::read_connection(record, c.token);

                return true;
            },
            30000, "owned authenticated SDK native-frame endpoint");
    const auto screens = profile_screens(profile.at("displays"));
    Json frames = Json::array();

    for (unsigned logical = 0; logical < 2; ++logical) {
        c.identity();
        need(c.process.owns_tcp_listener(grpc), "owned SDK frame endpoint disappeared");
        const auto &declared = screens.at(logical);
        const auto frame = media::capture_image(
                connection.value(), {logical, declared.width, declared.height}, c.remaining(10000));
        need(frame.display == logical && frame.width == declared.width &&
                     frame.height == declared.height,
             "SDK native frame dimensions differ; scaling forbidden");
        const auto bytes = output::png_frame(frame.pixels(), frame.width, frame.height);
        need(!bytes.empty() && bytes.size() <= 16ULL << 20, "bounded complete native PNG required");
        const auto name = "screen-" + std::to_string(logical) + ".png";
        output::write_artifact(c.stage / name, bytes);
        frames.push_back({{"file", name},
                          {"bytes", bytes.size()},
                          {"sha256", sha256_bytes({reinterpret_cast<const char *>(bytes.data()),
                                                   bytes.size()})},
                          {"width", frame.width},
                          {"height", frame.height},
                          {"sdk_display", logical},
                          {"android_display", logical ? second.value() : 0},
                          {"sequence", frame.sequence},
                          {"timestamp_us", frame.timestamp_us},
                          {"source", "owned-SDK-getScreenshot"}});
        c.identity();
    }

    need(c.shell({"cat", "/proc/sys/kernel/random/boot_id"}) == boot,
         "native frame pair crossed guest boot");
    need(android_candidate_secondary_display_ready(profile, c.shell({"dumpsys", "display"}),
                                                   c.shell({"dumpsys", "window", "windows"})) ==
                 second,
         "secondary routing changed during native frame pair");
    c.events.push_back(
            {{"phase", "native-frames-captured"}, {"frames", 2}, {"same_guest_boot", true}});

    return frames;
}

std::string avd_config(const Json &profile, const std::filesystem::path &base,
                       const std::string &avd) {
    const auto emulator = profile.at("emulator");
    const auto screens = android_screens(profile.at("displays"));
    const auto abi = android_guest_abi(profile);
    std::map<std::string, std::string> values = {
            {"AvdId", avd},
            {"avd.ini.displayname", "Voyemu preparation"},
            {"image.sysdir.1",
             base.string() + std::string(1, std::filesystem::path::preferred_separator)},
            {"abi.type", std::string(abi)},
            {"tag.id", "default"},
            {"hw.cpu.arch", std::string(android_avd_cpu_arch(abi))},
            {"hw.ramSize", std::to_string(emulator.value("memory", 4096U))},
            {"hw.gpu.enabled", "yes"},
            {"hw.gpu.mode", emulator.value("gpuMode", std::string("auto"))},
            {"disk.dataPartition.size", "6G"},
            {"fastboot.forceColdBoot", "yes"},
            {"fastboot.forceFastBoot", "no"},
            {"hw.multi_display_window", "false"},
            {"hw.hotplug_multi_display", "false"}};

    passion_camera_config(profile, values);

    // Each Android screen is an emulator display; the others belong to QNX.
    add_avd_screens(values, screens, -1);

    std::string out;

    for (const auto &[key, value] : values) {
        need(value.find_first_of("\r\n\0", 0, 3) == std::string::npos, "AVD config control byte");
        out += key + "=" + value + "\n";
    }

    out += android_candidate_cpu_config(profile);

    return out;
}

void base_features(const std::filesystem::path &file, const Json &features) {
    auto original = text(file);
    auto list = lines(original);

    for (auto it = features.begin(); it != features.end(); ++it) {
        need(std::regex_match(it.key(), std::regex("[A-Za-z0-9_]+")) &&
                     (it.value() == "on" || it.value() == "off"),
             "registered Android feature selector");
        const auto prefix = it.key() + " =";
        bool found = false;

        for (auto &line : list) {
            if (line.starts_with(prefix)) {
                need(!found, "duplicate base feature");
                line = prefix + " " + it.value().get<std::string>();
                found = true;
            }
        }

        if (!found) {
            list.push_back(prefix + " " + it.value().get<std::string>());
        }
    }

    std::string out;

    for (const auto &line : list) {
        if (!line.empty()) {
            out += line + "\n";
        }
    }

    std::ofstream stream(file, std::ios::binary | std::ios::trunc);
    stream << out;
    stream.close();
    need(bool(stream), "private base feature write");
}

// The helper is needed only while producing the explicitly opted-in A9 candidate.
void prepare_api30_root_layout(Candidate &c, const Json &profile, const std::string &image_pin,
                               std::uint64_t reserve) {
    need(android_candidate_api30_root_layout(profile), "exact API30 root layout profile required");
    need(c.boots == 0 && !c.process.alive() && !c.adb_server.alive(),
         "root layout requires unbooted stopped candidate");
    const auto image = c.machine / "base/system.img";
    ordinary(image);
    need(inside(image, c.stage) && std::filesystem::is_regular_file(image) &&
                 std::filesystem::hard_link_count(image) == 1,
         "private unaliased system image required");
    auto no_holders = [&] {
        android_candidate_require_unused_root_image(image);
    };
    no_holders();
    const auto before = read_lp_partition(image, image_pin, "system");
    need(before.offset == 3145728 && before.bytes == 789696512,
         "exact API30 system extent required");
    const auto helper =
            install_e2fs_helper(c.root, embedded_toolchain_manifest().at("e2fsprogs").at("helpers"),
                                "api30-root-layout", false, reserve);
    no_holders();
    read_lp_partition(image, image_pin, "system");
    c.host(helper,
           {image.string(), image_pin, std::to_string(before.offset), std::to_string(before.bytes)},
           300000, nullptr, "api30-root-layout.log");
    no_holders();
    const auto after_pin = sha256_file(image);
    const auto after = read_lp_partition(image, after_pin, "system");
    need(after.offset == before.offset && after.bytes == before.bytes &&
                 after.metadata_sha256 == before.metadata_sha256,
         "root layout changed LP metadata");
    c.events.push_back({{"phase", "api30-root-layout"},
                        {"source_image_sha256", image_pin},
                        {"image_sha256", after_pin},
                        {"outside_partition_unchanged", true}});
}

void repair_a9_offline_labels(Candidate &c, const Json &profile, const Json &artifacts,
                              const std::vector<Installed> &installed, std::uint64_t reserve) {
    const auto option = profile.at("android").value("offline_selinux_labels", std::string{});

    need(option == "qinggan09-can-early-v1" && android_candidate_api(profile) == 28,
         "unknown offline SELinux label request");
#if (defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))) || defined(_WIN32)
    std::map<std::string, std::string> hashes;

    for (const auto &[artifact, target, mode] :
         std::array<std::tuple<std::string, std::string, std::string>, 5>{
                 {{"component:early-inputs", "/system/bin/voyemu-early-inputs", "0755"},
                  {"component:can-simulator", "/system/bin/voyemu-can-model", "0755"},
                  {"files:can-simulator-fixture", "/system/etc/voyemu/can-model.fixture", "0644"},
                  {"files:qg-settings-guest", "/system/etc/voyemu/qg-settings-guest.db", "0444"},
                  {"files:hybrid-nvram", "/system/etc/voyemu/hybrid-nvram.img", "0444"}}}) {
        unsigned declarations = 0, matches = 0;

        for (const auto &entry : profile.at("install")) {
            if (entry.value("artifact", std::string{}) == artifact) {
                need(entry.value("type", std::string{}) == "file" &&
                             entry.value("target", std::string{}) == target &&
                             entry.value("mode", std::string{}) == mode &&
                             entry.value("uid", 0U) == 0 && entry.value("gid", 0U) == 0 &&
                             !entry.value("mutable", false),
                     "offline label install declaration differs");
                ++declarations;
            }
        }

        for (const auto &item : installed) {
            if (item.artifact == artifact) {
                need(item.target == target && item.mode == mode && !item.mutable_seed &&
                             sha256_text(item.sha256),
                     "offline label installed artifact differs");
                hashes[artifact] = item.sha256;
                ++matches;
            }
        }

        need(declarations == 1 && matches == 1, "exact offline label targets required");
    }

    for (const auto &[artifact, target] : std::array<std::pair<std::string, std::string>, 2>{
                 {{"patched:can-early-policy-a9", "/system/etc/selinux/plat_sepolicy.cil"},
                  {"patched:can-early-file-contexts-a9",
                   "/system/etc/selinux/plat_file_contexts"}}}) {
        unsigned declarations = 0, matches = 0;
        const auto &descriptor = artifacts.at(artifact);
        const auto expected = descriptor.at("sha256").get<std::string>();
        const std::filesystem::path source_file = descriptor.at("file").get<std::string>();
        check_file(source_file, expected, 4ULL << 20);

        for (const auto &entry : profile.at("install")) {
            if (entry.value("artifact", std::string{}) == artifact) {
                need(entry.value("type", std::string{}) == "file" &&
                             entry.value("target", std::string{}) == target &&
                             entry.value("mode", std::string{}) == "0644",
                     "offline policy declaration differs");
                ++declarations;
            }
        }

        for (const auto &item : installed) {
            if (item.artifact == artifact) {
                need(item.target == target && item.sha256 == expected && item.mode == "0644" &&
                             !item.mutable_seed,
                     "installed offline policy differs");
                ++matches;
            }
        }

        need(declarations == 1 && matches == 1, "exact installed policy and contexts required");
        android_candidate_offline_policy_pin(artifact, expected);
    }

    const auto &helpers = embedded_toolchain_manifest().at("e2fsprogs").at("helpers");
    const auto helper = install_e2fs_helper(c.root, helpers, "a9-offline-labels", false, reserve);
    const auto helper_sha =
            helpers.at(e2fs_helper_host()).at("a9-offline-labels").at("sha256").get<std::string>();
    c.identity();
    c.root_adbd();
    c.shell({"sync"});
    c.stop();
    need(!c.process.alive() && !c.adb_server.alive(), "offline label candidate must be stopped");
    const auto overlay = c.machine / "system.img.qcow2";
    ordinary(overlay);
    need(std::filesystem::is_regular_file(overlay) &&
                 std::filesystem::hard_link_count(overlay) == 1,
         "private system overlay required");
    const auto overlay_epoch = cache_file_identity(overlay);
    const auto overlay_sha = sha256_file(overlay);
    const auto overlay_info =
            Json::parse(c.host(c.qemu_img, {"info", "--output=json", overlay.string()}).output);
    const auto virtual_bytes = overlay_info.at("virtual-size").get<std::uint64_t>();
    need(overlay_info.at("format") == "qcow2" && virtual_bytes > 0 && virtual_bytes <= 4ULL << 30,
         "bounded A9 overlay virtual size required");
    const auto conversion_room = virtual_bytes + (512ULL << 20);
    need(reserve <= std::numeric_limits<std::uint64_t>::max() - conversion_room &&
                 std::filesystem::space(c.stage).available >= reserve + conversion_room,
         "disk reserve for offline image conversion unavailable");
    const auto scratch = c.stage / "offline-selinux-labels";
    need(!std::filesystem::exists(scratch) && !std::filesystem::is_symlink(scratch),
         "fresh offline label stage required");
    need(std::filesystem::create_directory(scratch), "exclusive offline label stage required");
    const auto stage_owner = random_token();
    write_private_json(scratch / ".owner.json", {{"token", stage_owner}});
    struct CleanupOfflineStage {
        std::filesystem::path path;
        std::string owner;

        ~CleanupOfflineStage() {
            try {
                if (read_private_json(path / ".owner.json").at("token") == owner) {
                    std::filesystem::remove_all(path);
                }
            } catch (...) { /* Ignored: owned scratch cleanup must not escape its destructor. */
            }
        }
    } cleanup{scratch, stage_owner};
    const auto exported = export_candidate_image(c, "system.img", scratch, reserve, true);
    const auto raw = scratch / exported.at("file").get<std::string>();
    const auto raw_sha = exported.at("sha256").get<std::string>();
    check_file(raw, raw_sha);
    check_file(helper, helper_sha, 32ULL << 20);
    std::vector<std::string> label_args = {raw.string(),
                                           raw_sha,
                                           hashes.at("component:early-inputs"),
                                           hashes.at("component:can-simulator"),
                                           hashes.at("files:can-simulator-fixture"),
                                           hashes.at("files:qg-settings-guest"),
                                           hashes.at("files:hybrid-nvram")};
    auto inspect_args = label_args;
    inspect_args.push_back("--check-before-fsck");
    const auto before_fsck = c.host(helper, inspect_args, 300000).output;
    std::smatch geometry;
    need(std::regex_match(
                 before_fsck, geometry,
                 std::regex("offset=([0-9]+) bytes=([0-9]+) outside_sha256=([0-9a-f]{64})\n")),
         "validated offline filesystem geometry required");
    // e2fsck of the pinned emulator archive of the host.
#ifdef _WIN32
    const std::string fsck_file = "emulator/bin64/e2fsck.exe", no_config = "NUL";
#else
    const std::string fsck_file = "emulator/bin64/e2fsck", no_config = "/dev/null";
#endif
    const auto fsck = c.sdk / fsck_file;
    const auto fsck_sha = native_runtime_file_pin(native_dependency_host(), fsck_file);
    check_file(fsck, fsck_sha, 32ULL << 20);
    // The first Android install replaces mapped ART files. After stopping the VM,
    // preen its private export to reclaim unlinked inodes before changing labels.
    ProcessSpec fsck_command;
    fsck_command.executable = fsck;
    fsck_command.arguments = {"-f", "-p", raw.string() + "?offset=" + geometry[1].str()};
    fsck_command.directory = c.stage;
    fsck_command.environment = {
            {"LC_ALL", "C"}, {"E2FSCK_CONFIG", no_config}, {"TMPDIR", c.stage.string()}};
    const auto repaired = execute(fsck_command, c.remaining(300000), 1 << 20);
    write(c.stage / "offline-fsck.log", repaired.output);
    need(!repaired.timed_out && (repaired.exit_code == 0 || repaired.exit_code == 1),
         "private system filesystem preen failed: " + repaired.output.substr(0, 4096));
    check_file(fsck, fsck_sha, 32ULL << 20);
    fsck_command.arguments[1] = "-n";
    const auto verified = execute(fsck_command, c.remaining(300000), 1 << 20);
    write(c.stage / "offline-fsck-verify.log", verified.output);
    need(!verified.timed_out && verified.exit_code == 0,
         "private system filesystem verification failed: " + verified.output.substr(0, 4096));
    label_args[1] = sha256_file(raw);
    inspect_args = label_args;
    inspect_args.push_back("--check-before-fsck");
    need(c.host(helper, inspect_args, 300000).output == before_fsck,
         "offline filesystem bounds or GPT changed during preen");
    c.host(helper, label_args, 300000, nullptr, "offline-labels.log");
    check_file(fsck, fsck_sha, 32ULL << 20);
    check_file(helper, helper_sha, 32ULL << 20);
    ordinary(raw);
    need(std::filesystem::is_regular_file(raw) && std::filesystem::hard_link_count(raw) == 1,
         "offline label output must remain private");
    const auto patched_sha = sha256_file(raw);
    const auto patched_epoch = cache_file_identity(raw);
    need(cache_file_identity(raw) == patched_epoch && sha256_file(raw) == patched_sha &&
                 cache_file_identity(overlay) == overlay_epoch &&
                 sha256_file(overlay) == overlay_sha,
         "offline label images changed during verification");
    const auto base = c.machine / "base/system.img";
    ordinary(base);
    const auto base_sha = sha256_file(base);
    need(std::filesystem::file_size(base) == virtual_bytes &&
                 std::filesystem::file_size(raw) == virtual_bytes,
         "offline RAW/base virtual extent differs");
    android_candidate_promote_labelled_system(c.machine, raw, patched_sha, base_sha, overlay_sha,
                                              reserve);
    need(read_private_json(scratch / ".owner.json").at("token") == stage_owner,
         "offline stage owner changed");
    std::filesystem::remove_all(scratch);
    c.events.push_back({{"phase", "offline-selinux-labels"},
                        {"profile_opt_in", option},
                        {"source_image_sha256", raw_sha},
                        {"patched_image_sha256", patched_sha},
                        {"helper_sha256", helper_sha},
                        {"fsck_sha256", fsck_sha},
                        {"fsck_exit_code", repaired.exit_code},
                        {"stopped", true},
                        {"outside_partition_unchanged", true}});
    c.boot(profile);
#else
    (void)c;
    (void)artifacts;
    (void)installed;
    (void)reserve;
    need(false,
         "offline SELinux label preparation requires macOS arm64 or Windows x64; prepared machine launch is unaffected");
#endif
}

// API30 policy/contexts are installed as pinned system files before the first OEM boot;
// the new label definitions load with that boot, so the A11 opt-in only fences the
// resulting on-disk labels through an in-guest restorecon before the cold verification.
void repair_a11_offline_labels(Candidate &c, const Json &profile, const Json &artifacts) {
    const auto option = profile.at("android").value("offline_selinux_labels", std::string{});

    need(option == "qinggan11-can-early-v1" && android_candidate_api(profile) == 30,
         "unknown offline SELinux label request");

    for (const auto &[artifact, target] : std::array<std::pair<std::string, std::string>, 3>{
                 {{"patched:can-early-policy-api30", "/system/etc/selinux/plat_sepolicy.cil"},
                  {"patched:can-early-file-contexts-api30",
                   "/system/etc/selinux/plat_file_contexts"},
                  {"patched:can-early-property-contexts-api30",
                   "/system/etc/selinux/plat_property_contexts"}}}) {
        unsigned declarations = 0;

        for (const auto &entry : profile.at("install")) {
            if (entry.value("artifact", std::string{}) == artifact) {
                need(entry.value("type", std::string{}) == "file" &&
                             entry.value("target", std::string{}) == target &&
                             entry.value("mode", std::string{}) == "0644" &&
                             entry.value("uid", 0U) == 0 && entry.value("gid", 0U) == 0 &&
                             !entry.value("mutable", false),
                     "offline policy install declaration differs");
                ++declarations;
            }
        }

        const auto descriptor = artifacts.at(artifact);
        const auto expected = descriptor.at("sha256").get<std::string>();
        check_file(descriptor.at("file").get<std::string>(), expected, 4ULL << 20);
        android_candidate_offline_policy_pin(artifact, expected, profile);
        need(declarations == 1, "exact installed API30 offline policy required");
    }

    c.identity();
    c.root_adbd();
    c.shell({"sync"});

    for (const auto &[artifact, target, mode] :
         std::array<std::tuple<std::string, std::string, std::string>, 5>{
                 {{"component:early-inputs", "/system/bin/voyemu-early-inputs", "0755"},
                  {"component:can-simulator", "/system/bin/voyemu-can-model", "0755"},
                  {"files:can-simulator-fixture", "/system/etc/voyemu/can-model.fixture", "0644"},
                  {"files:qg-settings-guest", "/system/etc/voyemu/qg-settings-guest.db", "0444"},
                  {"files:hybrid-nvram", "/system/etc/voyemu/hybrid-nvram.img", "0444"}}}) {
        unsigned declarations = 0;

        for (const auto &entry : profile.at("install")) {
            if (entry.value("artifact", std::string{}) == artifact) {
                need(entry.value("type", std::string{}) == "file" &&
                             entry.value("target", std::string{}) == target &&
                             entry.value("mode", std::string{}) == mode,
                     "offline label install declaration differs");
                ++declarations;
            }
        }

        need(declarations == 1, "exact offline label targets required");
        need(c.shell({"sha256sum", target}).size() >= 65,
             "offline label target missing: " + target);
        c.shell({"restorecon", target});
    }

    c.events.push_back({{"phase", "offline-selinux-labels"},
                        {"profile_opt_in", option},
                        {"scope", "api30 in-guest fence"}});
    c.reboot();
}

Json export_images(Candidate &c, const std::filesystem::path &destination, std::uint64_t reserve) {
    Json images = Json::object();

    for (const auto *name :
         {"system.img", "vendor.img", "userdata-qemu.img", "encryptionkey.img", "cache.img"}) {
        images[name] = export_candidate_image(c, name, destination, reserve);
    }

    return images;
}
} // namespace machine_preparation_detail
} // namespace voyemu
