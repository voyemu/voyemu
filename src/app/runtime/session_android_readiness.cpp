#include "error.hpp"
#include "session_internal.hpp"

namespace voyemu {
using namespace session_detail;

static std::optional<unsigned>
secondary_display_for(const std::string &displays, const std::string &windows,
                      std::string_view component, bool provider_only = false,
                      std::string_view state = "ON", bool canonical = false) {
    if (displays.size() > 128 * 1024 || windows.size() > 128 * 1024) {
        return std::nullopt;
    }

    static const std::regex display_header(R"((?:^|\n)\s*Display (\d+):)");
    std::vector<std::pair<std::size_t, unsigned>> ids;

    for (auto it = std::sregex_iterator(displays.begin(), displays.end(), display_header);
         it != std::sregex_iterator(); ++it) {
        ids.emplace_back(static_cast<std::size_t>(it->position()),
                         static_cast<unsigned>(std::stoul((*it)[1])));
    }

    std::optional<unsigned> secondary;

    for (std::size_t i = 0; i < ids.size(); ++i) {
        const auto end = i + 1 < ids.size() ? ids[i + 1].first : displays.size();
        const auto block = displays.substr(ids[i].first, end - ids[i].first);

        if (ids[i].second == 0 ||
            !std::regex_search(
                    block,
                    std::regex(
                            R"((?:^|\n)\s*mPrimaryDisplayDevice=(?:Emulator2D|Emulator 2D Display)\r?(?:\n|$))"))) {
            continue;
        }

        if (canonical) {
            if (ids[i].second != 1 || block.find("real 1920 x 720,") == std::string::npos) {
                return std::nullopt;
            }

            static const std::regex unique(R"id(uniqueId "([^"]+)")id");
            bool found = false;

            for (auto it = std::sregex_iterator(block.begin(), block.end(), unique);
                 it != std::sregex_iterator(); ++it) {
                found = true;

                if ((*it)[1] != "virtual:com.android.emulator.multidisplay:1234562") {
                    return std::nullopt;
                }
            }

            if (!found) {
                return std::nullopt;
            }

            static const std::regex geometry(R"(real (\d+) x (\d+),)"),
                    power(R"(state ([A-Z_]+),)");
            bool sized = false, powered = false;

            for (auto it = std::sregex_iterator(block.begin(), block.end(), geometry);
                 it != std::sregex_iterator(); ++it) {
                sized = true;

                if ((*it)[1] != "1920" || (*it)[2] != "720") {
                    return std::nullopt;
                }
            }

            if (!state.empty()) {
                for (auto it = std::sregex_iterator(block.begin(), block.end(), power);
                     it != std::sregex_iterator(); ++it) {
                    powered = true;

                    if ((*it)[1].str() != state) {
                        return std::nullopt;
                    }
                }
            }

            if (!sized || (!state.empty() && !powered)) {
                return std::nullopt;
            }
        }

        if (block.find("real 1920 x 720") == std::string::npos ||
            (!state.empty() && block.find("state " + std::string(state)) == std::string::npos)) {
            continue;
        }

        if (secondary) {
            return std::nullopt;
        }

        secondary = ids[i].second;
    }

    if (!secondary) {
        return std::nullopt;
    }

    if (provider_only) {
        return secondary;
    }

    static const std::regex window_header(R"((?:^|\n)\s*Window #\d+)");
    std::vector<std::size_t> positions;

    for (auto it = std::sregex_iterator(windows.begin(), windows.end(), window_header);
         it != std::sregex_iterator(); ++it) {
        positions.push_back(static_cast<std::size_t>(it->position()));
    }

    const std::regex matching_id("mDisplayId=" + std::to_string(*secondary) + R"((?:\D|$))");

    for (std::size_t i = 0; i < positions.size(); ++i) {
        const auto end = i + 1 < positions.size() ? positions[i + 1] : windows.size();
        const auto block = windows.substr(positions[i], end - positions[i]);

        if (block.find(component) != std::string::npos &&
            block.find("isOnScreen=true") != std::string::npos &&
            std::regex_search(block, matching_id)) {
            return secondary;
        }
    }

    return std::nullopt;
}

std::optional<unsigned> secondary_display_ready(const std::string &displays,
                                                const std::string &windows) {
    return secondary_display_for(
            displays, windows,
            "com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity");
}

std::optional<unsigned> passion_secondary_display_ready(const std::string &displays,
                                                        const std::string &windows) {
    const auto id = secondary_display_for(displays, windows, passion_secondary);

    return id && *id == 1 ? id : std::nullopt;
}

bool passion_secondary_provider_ready(const std::string &displays) {
    const auto id = secondary_display_for(displays, "", passion_secondary, true);

    return id && *id == 1;
}

bool passion_secondary_provider_preserves_readiness(const std::string &displays,
                                                    const std::string &established_boot,
                                                    const std::string &current_boot) {
    // LogicalDisplay applies WindowManager geometry overrides, but its power state comes from the
    // base device. Availability therefore checks physical identity/geometry only; the fresh power
    // watch owns ON/OFF admission.
    return android_boot_id_valid(current_boot) && established_boot == current_boot &&
           secondary_display_for(displays, "", passion_secondary, true, "", true) == 1;
}

Json passion_display_readiness_diagnostic(const std::string &displays,
                                          const std::string &established_boot,
                                          const std::string &current_boot) {
    auto result = host_lifecycle_receipt();
    const bool valid = android_boot_id_valid(current_boot),
               match = valid && established_boot == current_boot;
    const bool on = secondary_display_for(displays, "", passion_secondary, true, "ON", true) == 1,
               off = secondary_display_for(displays, "", passion_secondary, true, "OFF", true) == 1;
    const bool physical = secondary_display_for(displays, "", passion_secondary, true, "", true) ==
                          1;
    static const std::regex header(R"((?:^|\n)[ \t]*Display 1:\r?(?:\n|$))"),
            next(R"(\n(?:[ \t]*Display \d+:|[A-Z][^\n]*))");
    std::smatch found, following;
    std::string block;

    if (std::regex_search(displays, found, header)) {
        const auto begin = static_cast<std::size_t>(found.position());
        const auto tail = displays.substr(begin + found.length());
        const auto length = found.length() +
                            (std::regex_search(tail, following, next)
                                     ? static_cast<std::size_t>(following.position())
                                     : tail.size());
        block = displays.substr(begin, length);
    }

    result.update({{"schema", 1},
                   {"reason", !valid                     ? "invalid_current_boot"
                              : established_boot.empty() ? "missing_established_boot"
                              : !match                   ? "boot_changed"
                              : block.empty()            ? "secondary_missing"
                              : !physical                ? "canonical_provider_rejected"
                                                         : "accepted"},
                   {"fresh_observation", true},
                   {"current_boot_id", current_boot},
                   {"established_boot_id", established_boot},
                   {"current_boot_valid", valid},
                   {"boot_match", match},
                   {"canonical_on", on},
                   {"canonical_off", off},
                   {"canonical_physical", physical},
                   {"logical_display_1_present", !block.empty()},
                   {"full_observation_bytes", displays.size()},
                   {"logical_block_bytes", block.size()},
                   {"raw", block.substr(0, 4096)},
                   {"raw_maximum_bytes", 4096},
                   {"raw_truncated", block.size() > 4096}});

    return result;
}

bool oem_status_bars_ready(std::string_view windows, unsigned secondary_display_id) {
    if (!secondary_display_id || windows.size() > 128 * 1024) {
        return false;
    }

    const std::string text(windows);
    const std::regex header(R"((?:^|\n)\s*Window #\d+[^\n]*StatusBar([12])\}?:[^\n]*\n)");
    std::array<bool, 2> ready{};
    const std::regex any_window(R"((?:^|\n)\s*Window #\d+)");

    for (auto it = std::sregex_iterator(text.begin(), text.end(), header);
         it != std::sregex_iterator(); ++it) {
        auto slot = std::stoul((*it)[1].str()) - 1;
        auto begin = std::size_t(it->position());
        auto tail = text.substr(begin + it->length());
        std::smatch next;
        auto block = text.substr(begin, it->length() + (std::regex_search(tail, next, any_window)
                                                                ? std::size_t(next.position())
                                                                : tail.size()));
        const std::regex id("mDisplayId=" + std::to_string(slot ? secondary_display_id : 0) +
                            R"((?:\D|$))");
        ready[slot] = block.find("package=com.qinggan.systemui ") != std::string::npos &&
                      block.find("isOnScreen=true") != std::string::npos &&
                      block.find("mFrame=[0,0][1920,50]") != std::string::npos &&
                      std::regex_search(block, id);
    }

    return ready[0] && ready[1];
}

bool multimedia_canvas_ready(const Json &record) {
    if (!record.is_object() || record.value("schema", 0) != 1 ||
        record.value("source", std::string{}) != "own-window-instrumentation" ||
        record.value("bundle_identifier", std::string{}) != "com.voyemu.emulator") {
        return false;
    }

    const auto scale = record.value("backing_scale", 0.0);

    if (!std::isfinite(scale) || scale <= 0 || scale > 4) {
        return false;
    }

    auto dimensions = [&](const Json &rect, std::size_t width, std::size_t height) {
        return rect.is_array() && rect.size() > height && rect[width].is_number() &&
               rect[height].is_number() &&
               std::abs(rect[width].get<double>() * scale - 3840) < .5 &&
               std::abs(rect[height].get<double>() * scale - 720) < .5;
    };

    if (!record.contains("content_points") || !dimensions(record.at("content_points"), 0, 1) ||
        !record.contains("content_subviews") || !record.at("content_subviews").is_array()) {
        return false;
    }

    unsigned matched = 0;

    for (const auto &child : record.at("content_subviews")) {
        if (child.is_object() && child.value("class", std::string{}) == "EmuGLViewWithMetal") {
            auto full_rect = [&](const Json &rect) {
                return rect.is_array() && rect.size() == 4 && rect[0].is_number() &&
                       rect[1].is_number() && std::abs(rect[0].get<double>() * scale) < .5 &&
                       std::abs(rect[1].get<double>() * scale) < .5 && dimensions(rect, 2, 3);
            };

            if (!child.contains("frame_points") || !child.contains("bounds_points") ||
                !full_rect(child.at("frame_points")) || !full_rect(child.at("bounds_points"))) {
                return false;
            }

            ++matched;
        }
    }

    return matched == 1;
}

std::optional<std::string> resolved_home_component(std::string_view response,
                                                   std::string_view package) {
    if (response.size() > 8192 || package.empty()) {
        return std::nullopt;
    }

    static const std::regex shape(R"(^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$)");
    std::istringstream lines{std::string(response)};
    std::string line;
    std::optional<std::string> found;

    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (!std::regex_match(line, shape)) {
            continue;
        }

        if (found || !line.starts_with(std::string(package) + "/")) {
            return std::nullopt;
        }

        const auto slash = line.find('/');

        if (line[slash + 1] == '.') {
            line.insert(slash + 1, package);
        }

        found = line;
    }

    return found;
}

bool primary_home_visible(std::string_view windows, std::string_view component) {
    if (windows.size() > 128 * 1024 || component.empty()) {
        return false;
    }

    const std::string text(windows);
    const std::regex header(R"((?:^|\n)\s*Window #\d+)");
    std::vector<std::size_t> starts;

    for (auto it = std::sregex_iterator(text.begin(), text.end(), header);
         it != std::sregex_iterator(); ++it) {
        starts.push_back(it->position());
    }

    static const std::regex primary(R"(mDisplayId=0(?:\D|$))");

    for (std::size_t i = 0; i < starts.size(); ++i) {
        auto block = text.substr(starts[i],
                                 (i + 1 < starts.size() ? starts[i + 1] : text.size()) - starts[i]);

        if (block.find(component) != std::string::npos &&
            block.find("isOnScreen=true") != std::string::npos &&
            std::regex_search(block, primary)) {
            return true;
        }
    }

    return false;
}

bool home_component_declared(std::string_view candidates, std::string_view component,
                             std::string_view package) {
    const auto requested = resolved_home_component(component, package);

    if (candidates.size() > 65536 || !requested) {
        return false;
    }

    std::istringstream lines{std::string(candidates)};
    std::string line;

    while (std::getline(lines, line)) {
        const auto first = line.find_first_not_of(" \t");

        if (first != std::string::npos &&
            resolved_home_component(std::string_view(line).substr(first), package) == requested) {
            return true;
        }
    }

    return false;
}

std::vector<std::string> primary_home_start_command(const std::string &component) {
    // The OEM package declares two HOME activities. Select the already verified
    // primary component and its HOME stack; am start adds NEW_TASK itself.
    // Do not set --display: Android 9 can select a STANDARD fullscreen stack
    // before checking the HOME type. HOME naturally targets the default display.
    return {"shell",
            "am",
            "start",
            "--user",
            "0",
            "--activityType",
            "2",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.HOME",
            "-n",
            component};
}

Json home_start_result(const ProcessResult &result, const std::vector<std::string> &secrets) {
    const auto text = std::string_view(result.output).substr(0, 8192);
    std::string category = "none";

    for (const auto &entry : std::vector<std::pair<std::string_view, std::string_view>>{
                 {"SecurityException", "security"},
                 {"Permission Denial", "permission"},
                 {"Error type 3", "activity_missing"},
                 {"Error: Activity not started", "activity_not_started"},
                 {"Error:", "activity_error"},
                 {"Exception", "exception"},
                 {"Error", "unknown_error"}}) {
        if (text.find(entry.first) != std::string_view::npos) {
            category = entry.second;
            break;
        }
    }

    std::string exception_class = "none", failure_category = "none";

    if (text.find("Exception") != std::string_view::npos) {
        exception_class = "unknown";

        for (const char *name :
             {"SecurityException", "IllegalArgumentException", "IllegalStateException",
              "NullPointerException", "RemoteException", "DeadObjectException",
              "ActivityNotFoundException", "RuntimeException"}) {
            if (text.find(name) != std::string_view::npos) {
                exception_class = name;
                break;
            }
        }
    }

    if (text.find("Permission Denial") != std::string_view::npos ||
        exception_class == "SecurityException") {
        failure_category = "permission_denial";
    } else if (text.find("Error type 3") != std::string_view::npos ||
               text.find("does not exist") != std::string_view::npos ||
               text.find("unable to resolve Intent") != std::string_view::npos ||
               exception_class == "ActivityNotFoundException") {
        failure_category = "activity_not_found";
    } else if (text.find("Invalid display") != std::string_view::npos ||
               text.find("invalid display") != std::string_view::npos ||
               text.find("does not have a valid display") != std::string_view::npos ||
               text.find("Display does not exist") != std::string_view::npos) {
        failure_category = "unknown_display";
    } else if (text.find("Activity manager has not been initialized") != std::string_view::npos ||
               text.find("Can't find service: activity") != std::string_view::npos ||
               text.find("System not ready") != std::string_view::npos ||
               exception_class == "DeadObjectException") {
        failure_category = "service_not_ready";
    }

    std::string exception_detail;

    if (exception_class != "none" && exception_class != "unknown") {
        std::istringstream lines{std::string(text)};
        std::string line;

        while (std::getline(lines, line)) {
            const auto name = line.find(exception_class);

            if (name == std::string::npos) {
                continue;
            }

            const auto end = name + exception_class.size();

            if (end >= line.size() || line[end] != ':') {
                continue;
            }

            auto detail = line.substr(end + 1);
            auto cut = detail.size();

            for (const char *marker : {"Intent", "extras", "\tat ", " at android.", " at com."}) {
                const auto pos = detail.find(marker);

                if (pos != std::string::npos) {
                    cut = std::min(cut, pos);
                }
            }

            detail = redact_diagnostic_text(detail.substr(0, cut), secrets);

            for (char &ch : detail) {
                if (static_cast<unsigned char>(ch) < 32 || static_cast<unsigned char>(ch) > 126) {
                    ch = ' ';
                }
            }

            const auto first = detail.find_first_not_of(' ');

            if (first != std::string::npos) {
                exception_detail = detail.substr(first, 192);
            }

            break;
        }
    }

    Json exception_frames = Json::array();

    if (exception_class != "none" && exception_class != "unknown") {
        // A finite Java frame projection, never a raw stack trace or pathname.
        static const std::regex frame(
                R"(^[ \t]*at ((?:android|com\.android|java|javax|dalvik)\.[A-Za-z_$][A-Za-z0-9_.$]*\.[A-Za-z_$<>][A-Za-z0-9_$<>]*)\(([A-Za-z_$][A-Za-z0-9_$]*\.java):([0-9]{1,7})\)[ \t]*$)");
        std::istringstream lines{std::string(text)};
        std::string line;
        std::smatch match;

        while (exception_frames.size() < 8 && std::getline(lines, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.size() > 512 || !std::regex_match(line, match, frame)) {
                continue;
            }

            const auto method = match[1].str(), source = match[2].str();

            if (redact_diagnostic_text(method, secrets) != method ||
                redact_diagnostic_text(source, secrets) != source) {
                continue;
            }

            exception_frames.push_back(
                    {{"method", method}, {"source", source}, {"line", std::stoul(match[3].str())}});
        }
    }

    if (category == "none" && result.output.find("Error") != std::string::npos) {
        category = "unknown_error";
    }

    const auto reason = result.timed_out     ? "timeout"
                        : result.exit_code   ? "command_exit"
                        : category != "none" ? "activity_error"
                                             : "accepted";

    return {{"reason", reason},
            {"exit_code", result.exit_code},
            {"timed_out", result.timed_out},
            {"activity_manager", category},
            {"exception_class", exception_class},
            {"failure_category", failure_category},
            {"exception_detail", exception_detail},
            {"exception_frames", exception_frames}};
}

void record_home_start(Json &android, const ProcessResult &result,
                       const std::vector<std::string> &secrets) {
    const auto receipt = home_start_result(result, secrets);

    android["home_start"] = receipt;

    if (receipt.at("reason") != "accepted" && !android.contains("home_start_failure")) {
        android["home_start_failure"] = receipt;
    }
}

void clear_android_camera_delivery(Json &android) {
    android.erase("camera_package");
    android.erase("prepared_packages");
}

void clear_android_home_delivery(Json &android) {
    for (const char *key : {"home", "ui_observer", "home_start", "home_start_failure"}) {
        android.erase(key);
    }
}

bool Session::ensure_android_home() {
    if (primary_home_ready_ || !android_spec_.contains("home")) {
        return true;
    }

    const auto &home = android_spec_["home"];
    auto package = home.at("package").get<std::string>();
    std::vector<std::string> intent{"shell",
                                    "cmd",
                                    "package",
                                    "resolve-activity",
                                    "--brief",
                                    "--user",
                                    "0",
                                    "-a",
                                    "android.intent.action.MAIN",
                                    "-c",
                                    "android.intent.category.HOME"};
    auto scoped = intent;
    scoped.insert(scoped.end(), {"-p", package});
    auto qualified = adb(scoped, 2500);
    auto component = qualified.exit_code || qualified.timed_out
                             ? std::nullopt
                             : resolved_home_component(qualified.output, package);

    if (home.contains("component")) {
        const auto requested = resolved_home_component(home.at("component").get<std::string>(),
                                                       package);

        if (!requested) {
            throw VoyemuError("HOME_MISSING", "invalid configured primary component");
        }

        if (component != requested) {
            auto query = scoped;
            query[3] = "query-activities";
            const auto declared = adb(query, 2500);

            if (declared.timed_out || declared.exit_code ||
                !home_component_declared(declared.output, *requested, package)) {
                throw VoyemuError("HOME_MISSING",
                                  "configured primary is not a declared HOME activity");
            }

            component = requested;
        }
    }

    if (!component) {
        throw VoyemuError("HOME_MISSING", "configured primary does not resolve in its package");
    }

    auto current = adb(intent, 2500);

    if (current.exit_code || current.timed_out ||
        resolved_home_component(current.output, package) != component) {
        auto set = adb({"shell", "cmd", "package", "set-home-activity", "--user", "0", *component},
                       2500);
        current = adb(intent, 2500);

        if (set.exit_code || set.timed_out || current.exit_code || current.timed_out ||
            resolved_home_component(current.output, package) != component) {
            throw VoyemuError("HOME_NOT_PERSISTED", "primary restoration failed");
        }
    }

    auto windows = adb({"shell", "dumpsys", "window", "windows"}, 2500);

    if (windows.exit_code || windows.timed_out) {
        throw VoyemuError("HOME_WINDOW", "primary observation unavailable");
    }

    if (!primary_home_visible(windows.output, *component)) {
        auto start = adb(primary_home_start_command(*component), 2500);
        record_home_start(deliveries_["android"], start, {session_id_, android_boot_nonce_});

        if (deliveries_["android"]["home_start"].at("reason") != "accepted") {
            throw VoyemuError("HOME_START", "configured primary did not start " +
                                                    deliveries_["android"]["home_start"].dump());
        }

        return false;
    }

    primary_home_ready_ = true;
    deliveries_["android"]["home"] = {
            {"status", "visible_on_primary"}, {"component", *component}, {"display_id", 0}};

    return true;
}

void Session::prepare_android_displays() {
    const bool multiple = android_spec_.contains("features") &&
                          android_spec_["features"].value("MultiDisplay", std::string{}) == "on";

    if ((primary_home_ready_ || !android_spec_.contains("home")) && !multiple) {
        return;
    }

    // State and wheel delivery keep their own cadence; only expensive display observations wait.
    if (android_displays_ready_ && std::chrono::steady_clock::now() < next_display_observation_) {
        return;
    }

    auto pending = [&] {
        if (android_displays_ready_) {
            android_display_activated_ = false;
            android_canvas_refreshed_ = false;
        }

        android_displays_ready_ = false;
        deliveries_["android"].erase("displays");
        deliveries_["android"].erase("host_canvas");
        deliveries_["android"].erase("systemui");
    };

    if (!android_boot_completed_) {
        const auto boot = adb({"shell", "getprop", "sys.boot_completed"}, 1500);

        if (boot.exit_code || boot.timed_out || boot.output.find('1') == std::string::npos) {
            pending();

            return;
        }

        android_boot_completed_ = true;
    }

    const bool passion = passion_presentation(android_spec_);

    if (passion && multiple) {
        const auto provider = adb({"shell", "dumpsys", "display"}, 2500);

        if (provider.exit_code || provider.timed_out) {
            throw VoyemuError("ANDROID_DISPLAY", "Passion provider observation unavailable");
        }

        // Initial bootstrap proves visible presentation; later foreground and power changes do not
        // remove the device. Keep established readiness on this first fresh sameboot physical
        // observation, before any window recheck.
        if (android_displays_ready_) {
            const auto established_boot = deliveries_["android"]
                                                  .value("displays", Json::object())
                                                  .value("boot_id", std::string{});

            if (!passion_secondary_provider_preserves_readiness(provider.output, established_boot,
                                                                android_transport_boot_)) {
                try {
                    deliveries_["android"]["display_readiness_rejection"] =
                            passion_display_readiness_diagnostic(provider.output, established_boot,
                                                                 android_transport_boot_);
                } catch (...) { /* Ignored: retain existing rejection behavior if diagnostics are
                                   unavailable. */
                }

                pending();

                return;
            }

            next_display_observation_ = std::chrono::steady_clock::now() + std::chrono::seconds(3);

            return;
        }

        if (!passion_secondary_provider_ready(provider.output)) {
            pending();

            if (std::chrono::steady_clock::now() >= next_display_activation_) {
                next_display_activation_ = std::chrono::steady_clock::now() +
                                           std::chrono::seconds(2);
                const auto wake =
                        adb({"shell", "am", "broadcast", "--user", "0", "--receiver-foreground",
                             "-a", "com.android.emulator.multidisplay.START", "-n",
                             "com.android.emulator.multidisplay/.MultiDisplayServiceReceiver"},
                            30000);

                if (wake.exit_code || wake.timed_out ||
                    wake.output.find("Broadcast completed: result=") == std::string::npos) {
                    throw VoyemuError("ANDROID_DISPLAY",
                                      "Passion SDK provider wake unacknowledged");
                }
            }

            return;
        }
    }

    if (passion && deliveries_["android"]
                                   .value("startup_services", Json::object())
                                   .value("boot_id", std::string{}) != android_boot_nonce_) {
        for (const auto *component :
             {"com.android.car/com.voyemu.oem.car.CarAvailabilityService",
              "com.mega.nexus.server/.BootService", "com.mega.car/.MegaCarService",
              "com.voyah.coreservice/.CoreService"}) {
            const auto started = adb({"shell", "am", "startservice", "-n", component}, 10000);

            if (started.exit_code || started.timed_out ||
                started.output.find("Error") != std::string::npos) {
                throw VoyemuError("PASSION_STARTUP", "source-defined ordinary service failed");
            }
        }

        deliveries_["android"]["startup_services"] = {
                {"status", "submitted"}, {"boot_id", android_boot_nonce_}, {"mode", "service"}};
    }

    if (!ensure_android_home() || !multiple) {
        return;
    }

    if (android_spec_.contains("systemui_adapter") &&
        android_spec_["systemui_adapter"].at("component").get<std::string>() !=
                "com.qinggan.systemui/.SystemUIService") {
        throw VoyemuError("ANDROID_SYSTEMUI", "invalid owned component");
    }

    // Observe before activating: restored guests and a late host canvas may already be ready.
    const auto display = adb({"shell", "dumpsys", "display"}, 2500);
    const auto windows = adb({"shell", "dumpsys", "window", "windows"}, 2500);

    if (display.exit_code || display.timed_out || windows.exit_code || windows.timed_out) {
        throw VoyemuError("ANDROID_DISPLAY", "secondary verification unavailable");
    }

    const auto display_id = passion ? passion_secondary_display_ready(display.output,
                                                                      windows.output)
                                    : secondary_display_ready(display.output, windows.output);

    if (!display_id || (android_spec_.contains("systemui_adapter") &&
                        !oem_status_bars_ready(windows.output, *display_id))) {
        pending();
        const auto now = std::chrono::steady_clock::now();

        if (!android_display_activated_ && now >= next_display_activation_) {
            next_display_activation_ = now + std::chrono::seconds(2);
            const auto wake =
                    passion ? ProcessResult{}
                            : adb({"shell", "am", "broadcast", "--user", "0", "-a",
                                   "com.android.emulator.multidisplay.START", "-n",
                                   "com.android.emulator.multidisplay/.MultiDisplayServiceReceiver"},
                                  2500);

            if (wake.exit_code || wake.timed_out) {
                throw VoyemuError("ANDROID_DISPLAY", "secondary provider wake failed");
            }

            const auto service = adb({"shell", "am", "startservice", "-n",
                                      "com.voyemu/com.voyemu.output.SecondScreenService"},
                                     2500);

            if (service.exit_code || service.timed_out ||
                service.output.find("Error") != std::string::npos) {
                throw VoyemuError("ANDROID_DISPLAY", "secondary launcher bootstrap failed");
            }

            if (android_spec_.contains("systemui_adapter")) {
                const auto bar = adb({"shell", "am", "startservice", "-n",
                                      "com.qinggan.systemui/.SystemUIService"},
                                     2500);

                if (bar.exit_code || bar.timed_out ||
                    bar.output.find("Error") != std::string::npos) {
                    throw VoyemuError("ANDROID_SYSTEMUI", "OEM service start failed");
                }
            }

            android_display_activated_ = true;
        }

        return;
    }

    if (android_spec_.contains("systemui_adapter")) {
        deliveries_["android"]["systemui"] = {
                {"status", "both_OEM_bars_visible"},
                {"primary_display_id", 0},
                {"secondary_display_id", *display_id},
                {"bar_size", Json::array({1920, 50})},
                {"source", "com.qinggan.systemui; exact visible windows"}};
    }

    if (!android_host_canvas_ready(pending)) {
        return;
    }

    // Three seconds separates watchdog observations; scheduling below wakes at this independent
    // deadline.
    next_display_observation_ = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    android_displays_ready_ = true;
    deliveries_["android"]["displays"] = {
            {"status", "both_guest_displays_ready"},
            {"secondary_display_id", *display_id},
            {"size", Json::array({3840, 720})},
            {"source", "matching visible secondary launcher and display geometry"}};

    if (passion &&
        secondary_display_for(display.output, "", passion_secondary, true, "", true) == 1) {
        deliveries_["android"]["displays"]["boot_id"] = android_transport_boot_;
    }
}
} // namespace voyemu
