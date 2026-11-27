#include "machine_preparation_internal.hpp"
#include "selinux_patch.hpp"

namespace voyemu {
using namespace machine_preparation_detail;
namespace {
const std::string &art_diagnostic_script() {
    // Separate bounded streams and the exact child PID survive a nonzero compiler
    // status. No log buffer is cleared and the original compiler argv is untouched.
    static const std::string script =
            R"ART(nonce=$1; parent=$2; shift 2; )ART"
            R"ART(umask 077; )ART"
            R"ART(dir="$parent/voyemu-art-$nonce"; )ART"
            R"ART(mkdir "$dir" || exit 125; )ART"
            R"ART(trap 'rm -f "$dir/stdout" "$dir/stderr"; rmdir "$dir"' EXIT; )ART"
            R"ART(begin=unknown; read begin ignored < /proc/uptime 2>/dev/null || begin=unknown; )ART"
            R"ART("$@" >"$dir/stdout" 2>"$dir/stderr" & )ART"
            R"ART(pid=$!; )ART"
            R"ART(printf 'VOYEMU_ART_BEGIN %s %s %s\n' "$nonce" "$pid" "$begin"; )ART"
            R"ART(wait "$pid"; status=$?; )ART"
            R"ART(end=unknown; read end ignored < /proc/uptime 2>/dev/null || end=unknown; )ART"
            R"ART(printf 'VOYEMU_ART_END %s %s %s %s\n' "$nonce" "$pid" "$end" "$status"; )ART"
            R"ART(printf 'VOYEMU_ART_STDOUT_BEGIN\n'; head -c 65536 "$dir/stdout"; printf '\nVOYEMU_ART_STDOUT_END\n'; )ART"
            R"ART(printf 'VOYEMU_ART_STDERR_BEGIN\n'; head -c 65536 "$dir/stderr"; printf '\nVOYEMU_ART_STDERR_END\n'; )ART"
            R"ART(printf 'VOYEMU_ART_LOGCAT_BEGIN\n'; )ART"
            R"ART(logcat -d -b all --pid="$pid" -v threadtime,monotonic -t 200 2>&1 | head -c 65536; )ART"
            R"ART(printf '\nVOYEMU_ART_LOGCAT_END\n'; )ART"
            R"ART(exit "$status")ART";

    return script;
}

bool passion_platform(const Json &profile) {
    return record_declares(profile, ProfilePlatform::passion, ProfileBoard::sa8155);
}

bool qinggan11_platform(const Json &profile) {
    return record_declares(profile, ProfilePlatform::qinggan11, ProfileBoard::sa8155);
}

// The reviewed qinggan11 source Launchers whose second launcher activity owns the secondary
// display.
bool qinggan11_reviewed_launcher(const Json &profile) {
    const auto &pin = profile.at("original").at("Launcher").at("sha256");

    return pin == "48665cf9d6bb50b49b3aa0b1aa73bdb0ac5d9d7071240c46c7f13d07d4114d7e" ||
           pin == "94007beb0eed82807d3f20429435f2bbd585d9d52e6125b2a40779fc8cd2683c" ||
           pin == "b3287150827e7fa51072bcbcba257539101cda8433c5f9d3a95f4ca905abd567";
}
} // namespace

Json android_candidate_ui_request(int timeout_ms) {
    need(timeout_ms >= 1 && timeout_ms <= 30000, "bounded rich UI request required");

    return {{"op", "ui"},
            {"surfaces", Json::array({"media_primary", "media_secondary"})},
            {"scope", {{"windows", "all_attached"}}},
            {"timeout_ms", timeout_ms}};
}

Json android_candidate_ui_observation(Json response, unsigned secondary_display) {
    need(secondary_display > 0, "actual secondary UI display required");
    auto result = runtime::normalize_ui_observation(std::move(response));

    for (const auto &screen : result.at("screens")) {
        const unsigned expected = screen.at("screen") == "primary" ? 0 : secondary_display;
        need(screen.at("display_id") == expected, "rich UI display differs from provider");
        need(screen.value("scope", std::string{}) == "all_attached" && screen.contains("nodes") &&
                     !screen.at("nodes").empty(),
             "actual attached UI nodes required on each display");

        for (const auto *key : {"complete", "metadata_complete", "enumeration_complete"}) {
            need(screen.contains(key) && screen.at(key).is_boolean(),
                 "explicit rich UI coverage required");
        }

        need(screen.contains("unavailable_windows") && screen.at("unavailable_windows").is_array(),
             "explicit unavailable UI windows required");
        const bool complete = screen.at("complete").get<bool>();
        need(!complete || (screen.at("metadata_complete") == true &&
                           screen.at("enumeration_complete") == true &&
                           screen.at("unavailable_windows").empty()),
             "rich UI completeness contradicts coverage");
        need(screen.at("status") == (complete ? "ok" : "partial"),
             "rich UI status contradicts completeness");

        for (const auto &node : screen.at("nodes")) {
            need(node.value("bridge_version", Json()) == 1 && node.contains("privacy") &&
                         node.at("privacy").is_object(),
                 "actual bridge-v1 UI metadata required");

            for (const auto *key : {"sensitive", "editable", "password"}) {
                need(node.at("privacy").contains(key) && node.at("privacy").at(key).is_boolean(),
                     "known rich UI privacy verdict required");
            }

            need(node.at("privacy").contains("input_type") &&
                         (node.at("privacy").at("input_type").is_null() ||
                          node.at("privacy").at("input_type").is_number_integer()),
                 "explicit rich UI input type or unknown required");
            const auto status = node.value("text_status", std::string{});
            need(status == "available" || status == "redacted" || status == "none",
                 "known rich UI text status required");
        }
    }

    return result;
}

Json save_android_candidate_ui_observation(const std::filesystem::path &directory, const Json &raw,
                                           unsigned secondary_display) {
    write_private_json(directory / "ui-observation-raw.json", raw, 6 * 1024 * 1024);
    const auto normalized = android_candidate_ui_observation(raw, secondary_display);
    // Two screens: at most 24000 nodes and 128 windows, two rectangles each.
    // Each array-to-object rectangle adds less than 64 bytes; 6MiB + that
    // expansion and bounded top-level normalization stays below 10MiB.
    write_private_json(directory / "ui-observation.json", normalized, 10 * 1024 * 1024);

    return normalized;
}

bool android_candidate_package_settings_flushed(const std::string &xml, const Json &config,
                                                const std::optional<std::string> &home_query) {
    for (const auto &name : config.value("disabled", Json::array())) {
        if (!std::regex_search(xml, std::regex("name=\"" + regex_escape(name.get<std::string>()) +
                                               "\"[^>]*enabled=\"3\""))) {
            return false;
        }
    }

    for (const auto &name : config.value("uninstalled", Json::array())) {
        if (!std::regex_search(xml, std::regex("name=\"" + regex_escape(name.get<std::string>()) +
                                               "\"[^>]*inst=\"false\""))) {
            return false;
        }
    }

    if (!config.contains("homeActivity")) {
        return true;
    }

    const auto wanted = expanded(config.at("homeActivity").get<std::string>());
    const auto begin = xml.find("<preferred-activities>"),
               end = xml.find("</preferred-activities>", begin);

    if (begin == std::string::npos || end == std::string::npos) {
        return false;
    }

    std::size_t at = begin;

    while ((at = xml.find("<item ", at)) != std::string::npos && at < end) {
        const auto header_end = xml.find('>', at), item_end = xml.find("</item>", header_end);

        if (header_end == std::string::npos || item_end == std::string::npos || item_end > end) {
            return false;
        }

        const auto header = xml.substr(at, header_end - at + 1);
        std::smatch name;

        if (std::regex_search(header, name, std::regex(R"xml(\sname="([^"]+)")xml")) &&
            expanded(name[1].str()) == wanted) {
            const auto filter = xml.find("<filter", header_end),
                       filter_end = xml.find("</filter>", filter);

            if (filter != std::string::npos && filter_end != std::string::npos &&
                filter < item_end && filter_end < item_end &&
                std::string_view(" >\t\r\n").find(xml[filter + 7]) != std::string_view::npos) {
                const auto body = xml.substr(filter, filter_end - filter);

                if (std::regex_search(
                            body,
                            std::regex(
                                    R"xml(<action\b[^>]*\sname="android\.intent\.action\.MAIN"[^>]*/?>)xml")) &&
                    std::regex_search(
                            body,
                            std::regex(
                                    R"xml(<cat\b[^>]*\sname="android\.intent\.category\.HOME"[^>]*/?>)xml"))) {
                    if (!home_query) {
                        return true;
                    }

                    std::smatch always;

                    if (std::regex_search(header, always,
                                          std::regex(R"xml(\salways="([^"]*)")xml")) &&
                        !std::regex_match(always[1].str(), std::regex("true", std::regex::icase))) {
                        return false;
                    }

                    std::smatch count;

                    if (!std::regex_search(header, count,
                                           std::regex(R"xml(\sset="([0-9]+)")xml"))) {
                        return false;
                    }

                    const auto entries = xml.substr(header_end + 1, filter - header_end - 1);
                    const std::regex set_tag(R"xml(<set\b[^>]*\sname="([^"]+)"[^>]*/?>)xml");
                    std::vector<std::string> saved;

                    for (auto it = std::sregex_iterator(entries.begin(), entries.end(), set_tag);
                         it != std::sregex_iterator(); ++it) {
                        saved.push_back(expanded((*it)[1].str()));
                    }

                    if (saved.empty()) {
                        return false;
                    }

                    try {
                        if (std::stoull(count[1].str()) != saved.size()) {
                            return false;
                        }
                    } catch (...) {
                        return false;
                    }

                    std::vector<std::string> current;

                    for (const auto &value : lines(*home_query)) {
                        if (std::regex_match(value,
                                             std::regex("[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+"))) {
                            current.push_back(expanded(value));
                        }
                    }

                    if (current.size() != saved.size()) {
                        return false;
                    }

                    for (const auto &value : current) {
                        if (std::find(saved.begin(), saved.end(), value) == saved.end()) {
                            return false;
                        }
                    }

                    return true;
                }
            }
        }

        at = item_end + 7;
    }

    return false;
}

std::map<std::string, std::string>
android_candidate_sdk_environment(const std::filesystem::path &sdk, bool windows,
                                  std::string_view inherited_path) {
    need(sdk.is_absolute() && sdk.lexically_normal() == sdk,
         "explicit normalized absolute SDK root required");
    auto environment = android_sdk_environment(sdk, windows, inherited_path);
    environment["ANDROID_HOME"] = sdk.string();
    environment["ANDROID_SDK_ROOT"] = sdk.string();

    return environment;
}

std::vector<std::string> android_candidate_art_verify_packages(const Json &profile) {
    if (!passion_platform(profile) || !profile.contains("android") ||
        native_base_identity(profile.at("android")).api != 30 || !profile.contains("original") ||
        !profile.at("original").contains("LY_Car")) {
        return {};
    }

    std::vector<std::string> packages{"com.voyah.car"};

    if (profile.at("original").contains("LY_Launcher") && profile.contains("patches") &&
        profile.at("patches").contains("LY_Launcher")) {
        for (const auto &step :
             profile.at("patches").at("LY_Launcher").value("steps", Json::array())) {
            if (step == "passion-api30-launcher-audio.json") {
                packages.push_back("com.voyah.os.carlauncher");
                break;
            }
        }
    }

    if (profile.contains("patches") && profile.at("patches").contains("LY_AVM")) {
        const auto &patch = profile.at("patches").at("LY_AVM");
        const auto steps = patch.value("steps", Json::array());

        if (std::find(steps.begin(), steps.end(), Json("passion-api30-avm-nexus.json")) !=
            steps.end()) {
            need(profile.at("original").contains("LY_AVM"),
                 "AVM ART verification requires original APK");
            const auto &original = profile.at("original").at("LY_AVM");
            need(original.value("sha256", std::string{}) ==
                                 "ca78d415246c5be5c892d93a1b90c9dc19a638024af3ec61877c309cee7b8ecb" &&
                         original.value("source", Json::object()).value("package", std::string{}) ==
                                 "com.voyah.avm" &&
                         patch.value("input", std::string{}) == "original:LY_AVM" &&
                         patch.value("type", std::string{}) == "apk" &&
                         steps == Json::array({"passion-api30-media-libraries.json",
                                               "passion-api30-avm-nexus.json"}),
                 "exact guarded AVM ART package contract required");
            const auto installs = profile.value("install", Json::array());
            need(std::count(installs.begin(), installs.end(),
                            Json{{"artifact", "patched:LY_AVM"},
                                 {"type", "file"},
                                 {"target", "/system/priv-app/LY_AVM/LY_AVM.apk"},
                                 {"mode", "0644"}}) == 1,
                 "guarded AVM ART verification requires exactly one installed APK");
            packages.push_back("com.voyah.avm");
        }
    }

    return packages;
}

std::string android_candidate_command_log(const std::vector<std::string> &arguments) {
    if (arguments.empty()) {
        return {};
    }

    std::size_t command = 0;

    if (arguments.front() == "sh") {
        if (arguments.size() < 7 || arguments[1] != "-c" ||
            arguments[2] != art_diagnostic_script() || arguments[3] != "voyemu-art" ||
            !hex_text(arguments[4], 32) || arguments[5] != "/data/local/tmp") {
            return {};
        }

        command = 6;
    } else if (arguments.front() == "/system/bin/env") {
        if (arguments.size() < 4 || arguments[1] != "ANDROID_ROOT=/system" ||
            arguments[2] != "ANDROID_DATA=/system/framework/arm64" ||
            arguments[3] != "/system/bin/patchoat") {
            return {};
        }

        command = 3;
    }

    if (arguments[command] == "/system/bin/patchoat") {
        return "boot-image-relocation.log";
    }

    if (arguments[command] != "/system/bin/dex2oat" &&
        arguments[command] != "/apex/com.android.art/bin/dex2oat64" &&
        arguments[command] != "/apex/com.android.art/bin/dex2oat32") {
        return {};
    }

    for (std::size_t i = command + 1; i < arguments.size(); ++i) {
        if (arguments[i].starts_with("--image=") && arguments[i].size() > 8) {
            return arguments[command] == "/apex/com.android.art/bin/dex2oat32"
                           ? "boot-image-compile-x86.log"
                           : "boot-image-compile.log";
        }
    }

    return "system-server-" +
           sha256_bytes(Json(std::vector<std::string>(arguments.begin() + command, arguments.end()))
                                .dump())
                   .substr(0, 16) +
           ".log";
}

std::vector<std::string> android_candidate_boot_compile_diagnostic_command(const Json &profile,
                                                                           const std::string &nonce,
                                                                           const std::string &isa) {
    need(android_candidate_api(profile) == 30 && hex_text(nonce, 32),
         "exact API30 compiler diagnostic owner required");
    const auto command = api30_framework_boot::command(profile, isa);
    std::vector<std::string> result = {"sh",         "-c",  art_diagnostic_script(),
                                       "voyemu-art", nonce, "/data/local/tmp"};
    result.insert(result.end(), command.begin(), command.end());

    return result;
}

std::vector<std::vector<std::string>> android_candidate_start_commands(const Json &profile) {
    const auto config = profile.value("configure", Json::object());

    need(config.is_object(), "configure object required");
    const auto starts = config.value("start", Json::array());
    need(starts.is_array() && starts.size() <= 64, "bounded service start array required");
    std::vector<std::vector<std::string>> result;

    for (const auto &entry : starts) {
        std::string component, mode = "foreground-service";

        if (entry.is_string()) {
            component = entry.get<std::string>();
        } else {
            need(entry.is_object() && entry.size() == 2 && entry.contains("component") &&
                         entry.contains("mode") && entry.at("component").is_string() &&
                         entry.at("mode").is_string(),
                 "exact service start object required");
            component = entry.at("component").get<std::string>();
            mode = entry.at("mode").get<std::string>();
        }

        need(component.size() <= 512 &&
                     std::regex_match(
                             component,
                             std::regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+/[A-Za-z0-9_.$]+")),
             "service component invalid");
        need(mode == "service" || mode == "foreground-service", "unsupported service start mode");
        result.push_back({"am", mode == "service" ? "start-service" : "start-foreground-service",
                          "-n", component});
    }

    return result;
}

Json android_candidate_binder_probe(const Json &required, const ProcessResult &probe) {
    Json missing = Json::array();

    for (const auto &name : required) {
        if (!std::regex_search(probe.output,
                               std::regex("(?:^|\\n)\\s*\\d+\\s+" +
                                          regex_escape(name.get<std::string>()) + ":\\s*\\["))) {
            missing.push_back(name);
        }
    }

    return {{"ready", probe.exit_code == 0 && !probe.timed_out && missing.empty()},
            {"missing", missing},
            {"exit_code", probe.exit_code},
            {"timed_out", probe.timed_out},
            {"output", probe.output.substr(0, 512 * 1024)},
            {"output_truncated", probe.output.size() > 512 * 1024}};
}

Json android_candidate_vehicle_observer_policy(const Json &profile) {
    if (record_declares(profile, ProfilePlatform::qinggan09, ProfileBoard::nxp)) {
        need(android_candidate_api(profile) == 28,
             "NXP vehicle observation requires an API28 source profile");

        return {{"id", "vehicle-observer"},
                {"status", "unsupported"},
                {"supported", false},
                {"reason", "NXP profile has no source-backed vehicle observer"}};
    }

    if (!passion_platform(profile)) {
        return {{"supported", true}};
    }

    need(android_candidate_api(profile) == 30,
         "Passion vehicle observation requires an API30 developer profile");

    return {{"id", "vehicle-observer"},
            {"status", "unsupported"},
            {"supported", false},
            {"reason", "Passion developer profile has no source-backed vehicle observer"}};
}

void validate_android_candidate_checks(const Json &profile, const Json &checks) {
    const auto fail = [](const std::string &reason) {
        throw VoyemuError("ANDROID_CANDIDATE_CHECKS", reason);
    };

    if (!checks.is_array() || checks.empty() || checks.size() > 8192) {
        fail("bounded nonempty cold check array required");
    }

    const bool passion = passion_platform(profile);
    const auto unsupported = passion ? android_candidate_vehicle_observer_policy(profile) : Json();
    unsigned declarations = 0;

    for (std::size_t index = 0; index < checks.size(); ++index) {
        const auto &row = checks.at(index);
        const auto location = "checks[" + std::to_string(index) + "]";

        if (!row.is_object() || !row.contains("id") || !row.at("id").is_string()) {
            fail(location + ": check object with string id required");
        }

        const auto id = row.at("id").get<std::string>();

        if (id.empty() || id.size() > 512 || id.find_first_of("\r\n") != std::string::npos) {
            fail(location + ": bounded check id required");
        }

        const auto context = location + " (" + id + ")";
        const bool declaration = (passion && id == "vehicle-observer") ||
                                 (row.contains("supported") && (!row.at("supported").is_boolean() ||
                                                                row.at("supported") == false)) ||
                                 (row.contains("status") && row.at("status") == "unsupported");

        if (declaration) {
            if (!passion || row != unsupported) {
                fail(context +
                     ": exact source-declared unsupported Passion vehicle observer required");
            }

            if (++declarations != 1) {
                fail(context + ": duplicate unsupported vehicle observer declaration");
            }

            continue;
        }

        if (!row.contains("passed") || !row.at("passed").is_boolean() || row.at("passed") != true) {
            fail(context + ": executed cold check requires explicit passed=true");
        }
    }

    if (passion && declarations != 1) {
        fail("exact unsupported Passion vehicle observer declaration missing");
    }
}

std::optional<unsigned> android_candidate_secondary_provider(const Json &profile,
                                                             const std::string &displays) {
    const bool passion = passion_platform(profile);

    need(passion || qinggan11_platform(profile),
         "API30 source-owned secondary provider scope required");
    need(android_candidate_api(profile) == 30,
         "API30 display readiness requires a supported source profile");
    const auto android = android_screens(profile.at("displays"));
    need(android.size() >= 2 &&
                 (passion ? profile.at("original").at("LY_Launcher").at("sha256") ==
                                    "4032f14c0fc49fd52514737309d2af67c9d4ff9340dd534874f46cbe2e748c00"
                          : qinggan11_reviewed_launcher(profile)),
         "two-display source Launcher contract required");
    const auto width = android.at(1).width, height = android.at(1).height;
    need(width >= 64 && width <= 8192 && height >= 64 && height <= 8192,
         "bounded developer display dimensions required");

    if (displays.size() > 128 * 1024) {
        return std::nullopt;
    }

    const std::regex header(R"((?:^|\n)\s*Display (\d+):)"),
            provider(
                    R"((?:^|\n)\s*mPrimaryDisplayDevice=(?:Emulator2D|Emulator 2D Display)\r?(?:\n|$))");
    std::vector<std::pair<std::size_t, unsigned>> ids;

    for (auto it = std::sregex_iterator(displays.begin(), displays.end(), header);
         it != std::sregex_iterator(); ++it) {
        ids.emplace_back(static_cast<std::size_t>(it->position()),
                         static_cast<unsigned>(std::stoul((*it)[1])));
    }

    std::optional<unsigned> secondary;

    for (std::size_t i = 0; i < ids.size(); ++i) {
        const auto end = i + 1 < ids.size() ? ids[i + 1].first : displays.size();
        const auto block = displays.substr(ids[i].first, end - ids[i].first);

        if (!ids[i].second || !std::regex_search(block, provider) ||
            block.find("real " + std::to_string(width) + " x " + std::to_string(height)) ==
                    std::string::npos ||
            block.find("state ON") == std::string::npos) {
            continue;
        }

        if (secondary) {
            return std::nullopt;
        }

        secondary = ids[i].second;
    }

    return secondary;
}

std::optional<unsigned> android_candidate_secondary_display_ready(const Json &profile,
                                                                  const std::string &displays,
                                                                  const std::string &windows) {
    const bool passion = passion_platform(profile);

    if (!passion && !qinggan11_platform(profile)) {
        return secondary_display_ready(displays, windows);
    }

    if (windows.size() > 128 * 1024) {
        return std::nullopt;
    }

    const auto secondary = android_candidate_secondary_provider(profile, displays);
    const auto component =
            passion ? "com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond"
                    : "com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity";

    if (!secondary || !visible(windows, component, *secondary)) {
        return std::nullopt;
    }

    return secondary;
}

std::vector<std::string> android_candidate_capture_arguments(const Json &profile, bool capture,
                                                             unsigned port) {
    if (!capture) {
        return {};
    }

    const bool nxp = record_declares(profile, ProfilePlatform::qinggan09, ProfileBoard::nxp) &&
                     android_candidate_api(profile) == 28,
               qinggan11 = qinggan11_platform(profile);
    need(nxp || ((passion_platform(profile) || qinggan11) && android_candidate_api(profile) == 30),
         "frame capture requires an exact supported source profile");

    if (qinggan11 && profile.at("original").contains("Launcher")) {
        need(qinggan11_reviewed_launcher(profile), "exact qinggan11 capture inputs required");
    }

    need(port >= 5554 && port <= 5682 && port % 2 == 0, "bounded candidate capture port required");
    const auto android = android_screens(profile.at("displays"));
    need(android.size() >= 2, "two developer displays required");

    // The native capture covers the multimedia screens.
    for (std::size_t i = 0; i < 2; ++i) {
        need(android[i].width == 1920 && android[i].height == 720,
             "native SDK capture requires declared1920x720 without scaling");
    }

    return {"-grpc", std::to_string(port + 30000), "-grpc-use-token"};
}

std::string android_candidate_cpu_config(const Json &profile) {
    const auto emulator = profile.value("emulator", Json::object());

    if (!emulator.contains("cores")) {
        return {};
    }

    const auto value = emulator.at("cores");
    need(value.is_number_integer() && value >= 1 && value <= 8,
         "candidate CPU cores must be an integer in1..8");

    return "hw.cpu.ncore=" + std::to_string(value.get<unsigned>()) + "\n";
}

void android_candidate_require_unused_root_image(const std::filesystem::path &image) {
    ordinary(image);
    const auto use = os::file_use(image);
    need(use != os::FileUse::unknown, "root layout holder check unavailable");
    need(use == os::FileUse::unused, "root layout image has live holder");
}

void android_candidate_promote_labelled_system(const std::filesystem::path &machine,
                                               const std::filesystem::path &raw,
                                               const std::string &raw_sha,
                                               const std::string &base_sha,
                                               const std::string &overlay_sha,
                                               std::uint64_t reserve) {
    ordinary(machine);
    ordinary(raw);
    need(machine.filename() == "machine" &&
                 raw == machine.parent_path() / "offline-selinux-labels/android/system.img",
         "exact private offline image roles required");
    const auto base = machine / "base/system.img", overlay = machine / "system.img.qcow2";
    check_file(raw, raw_sha, 4ULL << 30);
    check_file(base, base_sha, 4ULL << 30);
    check_file(overlay, overlay_sha, 8ULL << 30);
    need(std::filesystem::file_size(raw) > 0 &&
                 std::filesystem::file_size(raw) == std::filesystem::file_size(base),
         "labelled base extent differs");

    for (const auto &file : {raw, base, overlay}) {
        android_candidate_require_unused_root_image(file);
    }

    require_disk_space("MACHINE_PREPARATION", machine, 0, reserve);
    // Both paths are in the unpublished owned candidate. A failure after rename
    // aborts that candidate; no running or published machine can observe it.
    std::filesystem::rename(raw, base);
    check_file(base, raw_sha, 4ULL << 30);
    check_file(overlay, overlay_sha, 8ULL << 30);
    android_candidate_require_unused_root_image(overlay);
    need(std::filesystem::remove(overlay), "old offline overlay removal failed");
    need(!std::filesystem::exists(overlay) && std::filesystem::space(machine).available >= reserve,
         "labelled base promotion incomplete");
}

bool android_candidate_api30_root_layout(const Json &profile) {
    if (!qinggan11_platform(profile)) {
        return false;
    }

    need(android_candidate_api(profile) == 30 &&
                 profile.at("android").value("offline_selinux_labels", std::string{}) ==
                         "qinggan11-can-early-v1",
         "exact API30 root layout profile required");
    need(profile.at("android").value("package", std::string{}) ==
                 "system-images;android-30;default;arm64-v8a",
         "exact qinggan11 API30 SDK required");

    return true;
}

std::uint64_t android_candidate_overlay_scratch_bytes(const Json &profile, std::uint64_t payload) {
    const bool original_navi = original_navi_requested(profile);

    if (original_navi) {
        original_navi_preflight(profile, android_candidate_api(profile));
    }

    const bool qinggan11 = qinggan11_platform(profile);

    if (qinggan11) {
        need(android_candidate_api30_root_layout(profile),
             "exact qinggan11 scratch profile required");
    }

    if (!original_navi && !qinggan11) {
        if (!passion_platform(profile)) {
            return 0;
        }

        const auto originals = profile.value("original", Json::object());

        if (!originals.contains("LY_Camera") && !originals.contains("LY_Video") &&
            !originals.contains("LY_AVM")) {
            return 0;
        }

        need(originals.contains("LY_Camera") && originals.contains("LY_Video") &&
                     originals.contains("LY_AVM") && android_candidate_api(profile) == 30,
             "complete finite Passion API30 media scratch required");
    }

    need(payload > 0 && payload <= 2ULL << 30, "bounded system install payload required");
    constexpr std::uint64_t quantum = 256ULL << 20;
    const auto required = (payload + (384ULL << 20)) * 5 / 4;
    const auto bytes = (required + quantum - 1) / quantum * quantum;
    need(bytes <= 2ULL << 30, "finite scratch payload exceeds2GiB");

    return bytes;
}

std::vector<ZipEntry>
android_candidate_system_native_libraries(const Json &entry, const std::vector<ZipEntry> &inventory,
                                          std::string_view manifest, std::string_view abi) {
    if (!entry.contains("target")) {
        return {};
    }

    const auto target = entry.at("target").get<std::string>();
    guest_path(target);
    need(std::regex_match(
                 target,
                 std::regex(
                         R"(/system/(?:system_ext/)?(?:priv-app|app)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.apk)")),
         "confined system APK native target required");
    bool extract = true;
    unsigned declarations = 0;
    std::istringstream xml{std::string(manifest)};

    for (std::string line; std::getline(xml, line);) {
        if (line.find("extractNativeLibs(") != std::string::npos) {
            need(++declarations == 1, "duplicate native extraction attribute");
            const auto at = line.find('=');
            need(at != std::string::npos, "native extraction attribute value required");
            const auto value = trim(line.substr(at + 1));
            need(value == "true" || value == "false" || value == "(type 0x12)0xffffffff" ||
                         value == "(type 0x12)0x0",
                 "native extraction boolean required");
            extract = value == "true" || value == "(type 0x12)0xffffffff";
        }
    }

    if (!extract) {
        return {};
    }

    std::vector<ZipEntry> out;
    std::set<std::string> names;
    std::uint64_t bytes = 0;
    const auto folder = "lib/" + std::string(abi) + "/";
    need(abi == "arm64-v8a" || abi == "x86_64" || abi == "x86", "native library ABI unsupported");

    for (const auto &file : inventory) {
        if (!file.directory && file.name.starts_with(folder)) {
            need(std::regex_match(file.name.substr(folder.size()),
                                  std::regex(R"(lib[A-Za-z0-9_.+-]+\.so)")),
                 "ordinary shared library required");
            auto basename = std::filesystem::path(file.name).filename().generic_string();

            for (char &c : basename) {
                if (c >= 'A' && c <= 'Z') {
                    c += 32;
                }
            }

            need(file.bytes > 0 && file.bytes <= 64ULL << 20 &&
                         file.bytes <= (512ULL << 20) - bytes && names.insert(basename).second &&
                         out.size() < 512,
                 "bounded portable unique shared libraries required");
            bytes += file.bytes;
            out.push_back(file);
        }
    }

    return out;
}

std::string android_candidate_merged_lines(std::string_view guest, std::string_view source) {
    std::string merged(guest);
    const auto existing = lines(merged);

    for (const auto &line : lines(source)) {
        if (std::find(existing.begin(), existing.end(), line) == existing.end()) {
            if (!merged.empty() && !merged.ends_with('\n')) {
                merged += '\n';
            }

            merged += line + "\n";
        }
    }

    return merged;
}

std::vector<std::string> android_guest_native_abis(std::string_view guest_abi) {
    // An x86_64 guest runs 64-bit and 32-bit x86 processes natively; ARM code of other APKs runs
    // through its Native Bridge.
    if (guest_abi == "x86_64") {
        return {"x86_64", "x86"};
    }

    return {"arm64-v8a"};
}

unsigned android_candidate_api(const Json &profile) {
    return native_base_api(profile.at("android"));
}

void validate_android_candidate_cache_image(std::string_view header, std::uint64_t bytes) {
    need(bytes == 69206016 && header.size() == 1082,
         "registered formatted Android cache extent required");
    need(static_cast<unsigned char>(header[1080]) == 0x53 &&
                 static_cast<unsigned char>(header[1081]) == 0xef,
         "exported Android cache ext4 magic required");
}

Json android_candidate_privileged_apk_check(const Json &entry, const std::string &package,
                                            const std::string &effective, const std::string &dump) {
    const auto target = privileged_apk_target(entry);

    need(package == entry.at("package").get<std::string>(), "privileged package identity differs");
    guest_path(effective);
    need(dump.size() <= 4ULL << 20, "bounded package state required");
    const auto section = dump.find("Packages:\n");
    need(section != std::string::npos &&
                 dump.find("Packages:\n", section + 10) == std::string::npos,
         "unique active Packages section required");
    auto section_end = dump.find("\nHidden system packages:", section);
    const auto shared = dump.find("\nShared users:", section);

    if (shared != std::string::npos && (section_end == std::string::npos || shared < section_end)) {
        section_end = shared;
    }

    const auto active = dump.substr(
            section, section_end == std::string::npos ? std::string::npos : section_end - section);
    const auto marker = "  Package [" + package + "] (";
    const auto begin = active.find(marker);
    need(begin != std::string::npos &&
                 active.find(marker, begin + marker.size()) == std::string::npos,
         "unique active package state required");
    const auto end = active.find("\n  Package [", begin + marker.size());
    const auto block = active.substr(begin,
                                     end == std::string::npos ? std::string::npos : end - begin);
    std::smatch flags, private_flags, code;
    need(std::regex_search(block, flags, std::regex(R"((?:^|\n)\s*flags=\[([^\]]*)\])")) &&
                 std::regex_search(block, private_flags,
                                   std::regex(R"((?:^|\n)\s*privateFlags=\[([^\]]*)\])")) &&
                 std::regex_search(block, code, std::regex(R"((?:^|\n)\s*codePath=([^\r\n]+))")),
         "actual package flags/codePath missing");
    const auto has = [](const std::string &value, const char *token) {
        return std::regex_search(value, std::regex(std::string(R"(\b)") + token + R"(\b)"));
    };
    need(has(flags[1].str(), "SYSTEM") && has(private_flags[1].str(), "PRIVILEGED"),
         "APK is not actually system/privileged");
    const bool updated = has(flags[1].str(), "UPDATED_SYSTEM_APP");
    need(trim(code[1].str()) == std::filesystem::path(effective).parent_path().generic_string(),
         "effective package codePath differs");
    need(effective == target || (updated && effective.starts_with("/data/app/") &&
                                 effective.ends_with("/base.apk")),
         "effective APK is neither its system base nor a real updated system package");

    return {{"id", "privileged-apk:" + package},
            {"passed", true},
            {"system_base", target},
            {"effective_apk", effective},
            {"updated_system_app", updated},
            {"privileged", true}};
}

bool android_candidate_home_priorities_ready(const Json &wanted, const std::string &query) {
    if (!wanted.is_object() || wanted.empty() || wanted.size() > 16 || query.size() > 128 * 1024) {
        return false;
    }

    std::map<std::string, int> expected, actual;

    for (auto it = wanted.begin(); it != wanted.end(); ++it) {
        if (!std::regex_match(it.key(), std::regex("[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+")) ||
            !it.value().is_number_integer()) {
            return false;
        }

        const auto priority = it.value().get<std::int64_t>();

        if (priority < -1000 || priority > 1000 ||
            !expected.emplace(expanded(it.key()), static_cast<int>(priority)).second) {
            return false;
        }
    }

    std::optional<int> priority;

    for (const auto &line : lines(query)) {
        std::smatch found;

        if (std::regex_search(line, found, std::regex(R"(^priority=(-?[0-9]+)\b)"))) {
            const auto number = found[1].str();

            if (priority || number.size() > 5) {
                return false;
            }

            const int value = std::stoi(number);

            if (value < -1000 || value > 1000) {
                return false;
            }

            priority = value;
        } else if (std::regex_match(line, std::regex("[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+"))) {
            if (!priority || !actual.emplace(expanded(line), *priority).second) {
                return false;
            }

            priority.reset();
        }
    }

    return !priority && actual == expected;
}

Json android_candidate_install_plan(const Json &profile, const Json &artifacts) {
    need(profile.at("install").is_array() && profile.at("install").size() <= 4096 &&
                 artifacts.is_object(),
         "bounded install graph required");
    Json system = Json::array(), data = Json::array(), apks = Json::array();
    std::set<std::string> targets;

    for (const auto &entry : profile.at("install")) {
        const auto ref = entry.at("artifact").get<std::string>(),
                   type = entry.at("type").get<std::string>();
        need(!ref.empty() && (type == "directory" || artifacts.contains(ref)),
             "install artifact missing: " + ref);
        const auto &artifact = type == "directory" ? Json::object() : artifacts.at(ref);

        if (type == "apk") {
            need(artifact.contains("file"), "APK file/topology required");

            if (entry.contains("target")) {
                const auto target = privileged_apk_target(entry);
                need(targets.insert(target).second, "duplicate install target");
                system.push_back(entry);
            } else {
                apks.push_back(entry);
            }

            continue;
        }

        need(type == "file" || type == "tree" || type == "directory",
             "registered install type required");
        const auto target = entry.at("target").get<std::string>();
        guest_path(target);
        need(targets.insert(target).second, "duplicate install target");
        need(type == "file" ? artifact.contains("file")
                            : type == "directory" ||
                                      artifact.contains("directory") && artifact.contains("files"),
             "artifact file/tree shape differs");
        (target.starts_with("/data/") ? data : system).push_back(entry);
    }

    for (const auto &apk : system) {
        if (apk.at("type") == "apk") {
            const auto target = apk.at("target").get<std::string>();

            for (const auto &entry : profile.at("install")) {
                if (entry.at("type") == "tree") {
                    need(!target.starts_with(entry.at("target").get<std::string>() + "/"),
                         "privileged APK overlaps an installed tree");
                }
            }
        }
    }

    return {{"system", system}, {"data", data}, {"apks", apks}};
}

std::vector<std::string> android_candidate_boot_cache_paths(const Json &profile) {
    std::set<std::string> installed;

    for (const auto &entry : profile.at("install")) {
        if (entry.value("type", std::string{}) == "file") {
            installed.insert(entry.at("target").get<std::string>());
        }
    }

    if (!installed.contains("/system/framework/framework.jar")) {
        return {};
    }

    if (android_candidate_api(profile) == 30) {
        return api30_framework_boot::paths(profile);
    }

    std::vector<std::string> paths;

    for (const char *stem :
         {"core-oj", "core-libart", "conscrypt", "okhttp", "bouncycastle", "apache-xml", "ext",
          "framework", "telephony-common", "voip-common", "ims-common",
          "android.hidl.base-V1.0-java", "android.hidl.manager-V1.0-java",
          "framework-oahl-backward-compatibility", "android.test.base"}) {
        const std::string name = stem;
        need(installed.contains("/system/framework/" + name + ".jar"),
             "full bootclasspath replacement required before ART invalidation");
        const auto boot = name == "core-oj" ? std::string("boot") : "boot-" + name;

        for (const char *arch : {"", "arm/", "arm64/"}) {
            for (const char *extension : {".art", ".oat", ".vdex", ".art.rel"}) {
                paths.push_back("/system/framework/" + std::string(arch) + boot + extension);
            }
        }
    }

    return paths;
}

std::vector<std::string> android_candidate_boot_image_command(const Json &profile) {
    if (android_candidate_boot_cache_paths(profile).empty()) {
        return {};
    }

    if (android_candidate_api(profile) == 30) {
        return api30_framework_boot::command(
                profile, api30_framework_boot::instruction_sets(profile).back());
    }

    std::vector<std::string> args = {"/system/bin/dex2oat",
                                     "--image=/system/framework/arm64/boot.art",
                                     "--oat-file=/system/framework/arm64/boot.oat",
                                     "--oat-location=/system/framework/arm64/boot.oat",
                                     "--multi-image",
                                     "--instruction-set=arm64",
                                     "--instruction-set-variant=generic",
                                     "--instruction-set-features=default",
                                     "--compact-dex-level=fast",
                                     "--copy-dex-files=always",
                                     "--compiler-filter=speed",
                                     "--base=0x70000000",
                                     "--android-root=/system",
                                     "--runtime-arg",
                                     "-Xnorelocate",
                                     "--runtime-arg",
                                     "-Xms64m",
                                     "--runtime-arg",
                                     "-Xmx512m",
                                     "--compile-pic",
                                     "--no-inline-from=core-oj.jar",
                                     "--abort-on-hard-verifier-error",
                                     "--abort-on-soft-verifier-error"};

    for (const char *name :
         {"core-oj", "core-libart", "conscrypt", "okhttp", "bouncycastle", "apache-xml", "ext",
          "framework", "telephony-common", "voip-common", "ims-common",
          "android.hidl.base-V1.0-java", "android.hidl.manager-V1.0-java",
          "framework-oahl-backward-compatibility", "android.test.base"}) {
        const auto path = "/system/framework/" + std::string(name) + ".jar";
        args.push_back("--dex-file=" + path);
        args.push_back("--dex-location=" + path);
    }

    return args;
}

std::vector<std::string> android_candidate_boot_relocation_command(const Json &profile) {
    if (android_candidate_boot_cache_paths(profile).empty()) {
        return {};
    }

    if (android_candidate_api(profile) == 30) {
        return {};
    }

    return {"/system/bin/env",
            "ANDROID_ROOT=/system",
            "ANDROID_DATA=/system/framework/arm64",
            "/system/bin/patchoat",
            "--input-image-location=/system/framework/boot.art",
            "--output-image-relocation-directory=/system/framework/arm64",
            "--instruction-set=arm64",
            "--base-offset-delta=0x10000000"};
}

std::vector<std::vector<std::string>>
android_candidate_system_server_commands(const Json &profile) {
    const auto configured = profile.value("configure", Json::object())
                                    .value("systemServerClasspath", Json::array());

    if (configured.empty()) {
        return {};
    }

    need(android_candidate_api(profile) == 28,
         "API30 system server recipe requires verified classpath inputs");
    const Json expected =
            Json::array({"/system/framework/services.jar", "/system/framework/ethernet-service.jar",
                         "/system/framework/wifi-service.jar",
                         "/system/framework/com.android.location.provider.jar"});
    need(configured == expected, "registered ordered system server classpath required");
    std::set<std::string> installed;

    for (const auto &entry : profile.at("install")) {
        if (entry.value("type", std::string{}) == "file") {
            installed.insert(entry.at("target").get<std::string>());
        }
    }

    std::vector<std::vector<std::string>> commands;

    for (const auto &item : configured) {
        const auto path = item.get<std::string>();
        need(installed.contains(path), "source-built system server jar missing");
        const auto target = "/system/framework/oat/arm64/" +
                            std::filesystem::path(path).stem().string() + ".odex";
        commands.push_back(
                {"/system/bin/dex2oat",
                 "--dex-file=" + path,
                 "--dex-location=" + path,
                 "--oat-file=" + target,
                 "--oat-location=" + target,
                 "--instruction-set=arm64",
                 "--instruction-set-variant=generic",
                 "--instruction-set-features=default",
                 "--compiler-filter=speed",
                 "--compact-dex-level=fast",
                 "--copy-dex-files=always",
                 "--class-loader-context=&",
                 "--runtime-arg",
                 "-Xnorelocate",
                 "--runtime-arg",
                 "-Xms64m",
                 "--runtime-arg",
                 "-Xmx512m",
                 "--abort-on-hard-verifier-error",
                 "--compile-pic",
                 "--force-determinism",
                 "--no-inline-from=core-oj.jar",
                 "--app-image-file=" +
                         std::filesystem::path(target).replace_extension(".art").string(),
                 "--image-format=lz4"});
    }

    return commands;
}

void android_candidate_configure_properties(
        const Json &profile,
        const std::function<std::string(const std::vector<std::string> &)> &shell) {
    const auto properties =
            profile.value("configure", Json::object()).value("properties", Json::object());

    need(properties.is_object(), "profile properties must be an object");

    for (auto value = properties.begin(); value != properties.end(); ++value) {
        need(std::regex_match(value.key(), std::regex("[A-Za-z0-9_.-]+")) &&
                     value.value().is_string() &&
                     value.value().get<std::string>().find('\0') == std::string::npos,
             "profile property key/value invalid");
    }

    for (auto value = properties.begin(); value != properties.end(); ++value) {
        const auto expected = value.value().get<std::string>();

        if (shell({"getprop", value.key()}) == expected) {
            continue;
        }

        shell({"setprop", value.key(), expected});
        need(shell({"getprop", value.key()}) == expected,
             "profile property readback differs: " + value.key());
    }
}

std::vector<std::vector<std::string>> android_candidate_configure_settings(const Json &settings,
                                                                           bool late) {
    std::vector<std::vector<std::string>> commands;

    for (auto space = settings.begin(); space != settings.end(); ++space) {
        need((space.key() == "global" || space.key() == "secure" || space.key() == "system") &&
                     space.value().is_object(),
             "settings namespace");

        for (auto value = space.value().begin(); value != space.value().end(); ++value) {
            if (!value.value().is_string()) {
                throw VoyemuError("MACHINE_PREPARATION", "settings value");
            }

            if (late && !(space.key() == "global" &&
                          (value.key() == "device_name" || value.key() == "device_name_suffix"))) {
                continue;
            }

            commands.push_back({"settings", "put", space.key(), value.key(),
                                value.value().get<std::string>()});
        }
    }

    return commands;
}

// Configure writes all profile settings right after the settings service is up;
// OEM boot processes in the first ~15s after boot_completed then reset the global
// device_name family to its default through SettingsProvider, so it is re-applied
// late, immediately before the persist reboot, where the boot window has expired.
void android_candidate_home_reboot_checkpoints(unsigned api, bool has_home,
                                               const std::function<void()> &establish,
                                               const std::function<void()> &verify,
                                               const std::function<void()> &cold_boot) {
    if (api == 28 && has_home) {
        establish();
    }

    verify();
    cold_boot();

    if (api == 28) {
        verify();
    }
}

void android_candidate_offline_policy_pin(const std::string &artifact, const std::string &expected,
                                          const Json &profile) {
    if (artifact == "patched:can-early-policy-a9") {
        need(expected == "2879712e7a6a12f262ab346fbe61b7f5b992e652e10d93edf8eb44a6c7b84a77",
             "offline policy output pin differs");
    } else if (artifact == "patched:can-early-file-contexts-a9") {
        need(expected == "8bd8062c3b8108bdc34573f78d403691e747298a986a3464ace94721b02ad1d7",
             "offline contexts output pin differs");
    } else if (artifact == "patched:can-early-policy-api30") {
        const bool qinggan11 = qinggan11_platform(profile),
                   original_navi = qinggan11 && original_navi_requested(profile),
                   shared = qinggan11 && !original_navi;
        need((original_navi &&
              expected ==
                      (qinggan11_ui_observer_policy_requested(profile)
                               ? qinggan11_ui_observer_policy_sha256
                               : "e8f3b8cb54b3ec09280cf5c630f495b3202f1c9994e796c5a1cf707a5dcd6cf6")) ||
                     (shared &&
                      expected ==
                              "50e7563396d73b053a36a9022d31807121731ecc0ce51b695df65ec7d6838db6"),
             "offline API30 policy output pin differs");
    } else if (artifact == "patched:can-early-file-contexts-api30") {
        need(expected == "873da6472b242a86d657900bdd90d4fa458dbde615c75ea406c6806f06ce8ecc",
             "offline API30 contexts output pin differs");
    } else if (artifact == "patched:can-early-property-contexts-api30") {
        need(expected == "6618819c1a2cf856486d66e270459aeccfe03d8d7837c9cc946940cd5a104493",
             "offline API30 property contexts output pin differs");
    } else {
        need(false, "unknown offline policy artifact");
    }
}

void android_candidate_first_oem_boot(
        const Json &profile,
        const std::function<std::string(const std::vector<std::string> &)> &shell,
        const std::function<void()> &reboot, const std::function<void()> &prepare_files) {
    if (prepare_files) {
        prepare_files();
    }

    android_candidate_configure_properties(profile, shell);
    const auto config = profile.value("configure", Json::object());

    if (!config.value("properties", Json::object()).empty() ||
        (prepare_files && !config.value("bootProperties", Json::object()).empty())) {
        shell({"sync"});
    }

    reboot();
}

std::string android_candidate_boot_properties(std::string_view source, const Json &values) {
    need(source.size() <= 1ULL << 20 && source.find('\0') == std::string_view::npos &&
                 values.is_object() && values.size() <= 7,
         "bounded boot property input required");
    const std::set<std::string> allowed = {"ro.product.board",      "ro.build.product_3rdparty",
                                           "ro.build.product",      "ro.product.device",
                                           "ro.product.locale",     "ro.qg.voice_vendor",
                                           "SpeechResc_init_state", "ro.qg.presentation"};

    for (auto it = values.begin(); it != values.end(); ++it) {
        need(allowed.contains(it.key()) && it.value().is_string() &&
                     (it.key() != "ro.qg.voice_vendor" || it.value() == "speech_voicecloud") &&
                     (it.key() != "SpeechResc_init_state" || it.value() == "1") &&
                     (it.key() != "ro.qg.presentation" || it.value() == "VirtualDisplay") &&
                     std::regex_match(it.value().get<std::string>(),
                                      std::regex("[A-Za-z0-9._-]{1,91}")),
             "OEM boot identity whitelist");
    }

    std::istringstream input{std::string(source)};
    std::string output;
    std::set<std::string> found;

    for (std::string line; std::getline(input, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        std::smatch property;

        if (std::regex_search(line, property, std::regex(R"(^\s*([^#\s=]+)\s*=)")) &&
            values.contains(property[1].str())) {
            const auto key = property[1].str();
            need(found.insert(key).second, "duplicate OEM boot property");
            line = key + "=" + values.at(key).get<std::string>();
        }

        output += line + "\n";
    }

    while (output.ends_with("\n\n")) {
        output.pop_back();
    }

    for (auto it = values.begin(); it != values.end(); ++it) {
        if (!found.contains(it.key())) {
            output += it.key() + "=" + it.value().get<std::string>() + "\n";
        }
    }

    return output;
}

Json android_candidate_can_check(std::string_view reply, std::string_view boot) {
    need(std::regex_match(
                 std::string(boot),
                 std::regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
         "complete cold CAN boot identity required");
    const auto observed = parse_can_observation(parse_android_provider_reply(std::string(reply)));
    need(observed.at("status") == "ready" && observed.at("boot_id") == boot,
         "cold CAN source must be ready in the current boot");

    for (const auto *name :
         {"vehicle_state.IVI_SOC_MODESET", "vehicle_state.HUM_VSP_FUNCTION_SW"}) {
        need(observed.at("values").contains(name), "cold CAN required state missing");
    }

    need(observed.at("history").at("gap").is_null() &&
                 !observed.at("history").at("has_more").get<bool>() &&
                 observed.at("events").empty(),
         "cold CAN baseline must be complete");

    return {{"id", "cli:content:can-observe"},
            {"passed", true},
            {"schema", 1},
            {"source", observed.at("source")},
            {"boot_id", observed.at("boot_id")},
            {"source_instance", observed.at("source_instance")},
            {"pid", observed.at("pid")},
            {"revision", observed.at("revision")},
            {"transport", observed.at("transport")},
            {"values", observed.at("values")}};
}
} // namespace voyemu
