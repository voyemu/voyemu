#include "machine_preparation.hpp"
#include "a9_precompiled_policy.hpp"
#include "android_adb.hpp"
#include "android_engine.hpp"
#include "api30_framework_boot.hpp"
#include "machine_preparation_internal.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "session.hpp"
#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <regex>
#include <set>
#include <source_location>
#include <stdexcept>
#include <thread>
#ifndef _WIN32
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <windows.h>
#endif
#include "profile_build.hpp"
#include "profile_runtime.hpp"
using namespace voyemu;

// The bundled Android 9 profile on the 8155 board, read from the catalog.
static const std::string &qinggan09_profile() {
    static const auto id =
            embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);

    return id;
}

namespace {
void check(bool value, const std::source_location where = std::source_location::current()) {
    if (!value) {
        throw std::runtime_error("machine preparation check failed at " +
                                 std::to_string(where.line()) + ":" +
                                 std::to_string(where.column()));
    }
}

void verify_failed_cold_check_retains_observation() {
    Json checks = Json::array();

    machine_preparation_detail::record_cold_check(checks, "boot", "1", "1");
    bool rejected = false;
    try {
        machine_preparation_detail::record_cold_check(checks, "setting:global:policy_control",
                                                      "null", "immersive.status=*");
    } catch (const VoyemuError &error) {
        rejected = std::string(error.what()) ==
                   "MACHINE_PREPARATION: cold check failed: setting:global:policy_control";
    }

    check(rejected && checks.size() == 2 && checks[0].at("passed") == true);
    check(checks[1] == Json{{"id", "setting:global:policy_control"},
                            {"actual", "null"},
                            {"expected", "immersive.status=*"},
                            {"passed", false}});
    checks = Json::array();
    machine_preparation_detail::record_cold_check(checks, "setting:global:policy_control",
                                                  "immersive.status=*", "immersive.status=*");
    check(checks.size() == 1 && checks[0].at("passed") == true);
}

void verify_candidate_profile_artifact_boundary() {
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("candidate-profile-files-" + random_token());
    const auto source = root / "profiles/fixture/files/declared.xml";

    ensure_private_directory(source.parent_path());
    {
        std::ofstream out(source);
        out << "declared profile input";
    }
    const auto pin = sha256_file(source);
    Json profile = {{"components", Json::object()},
                    {"patches", Json::object()},
                    {"files", {{"declared", {{"file", "declared.xml"}, {"sha256", pin}}}}},
                    {"install", Json::array({{{"artifact", "files:declared"},
                                              {"type", "file"},
                                              {"target", "/system/etc/declared.xml"}}})}};
    write_private_json(root / "profiles/fixture/profile.json", profile);
    AndroidCandidateRequest request;
    request.profile = "fixture";
    request.profile_sha256 = sha256_file(root / "profiles/fixture/profile.json");
    Json result = {{"schema", 1},
                   {"operation", "build-artifacts"},
                   {"profile", "fixture"},
                   {"revision", current_profile_revision(root, "fixture")},
                   {"components", Json::array()},
                   {"patch_nodes", Json::array()},
                   {"step_source_pins", Json::object()},
                   {"machine_ready", false},
                   {"guest_started", false},
                   {"artifacts_built", true},
                   {"artifacts",
                    {{"files:declared",
                      {{"file", source.string()},
                       {"sha256", pin},
                       {"bytes", std::filesystem::file_size(source)}}}}}};
    validate_android_candidate_artifacts(root, request, result);
    auto reject = [&](const Json &value) {
        bool failed = false;
        try {
            validate_android_candidate_artifacts(root, request, value);
        } catch (...) {
            failed = true;
        }

        check(failed);
    };
    auto changed = result;
    changed["artifacts"]["files:unknown"] = changed["artifacts"]["files:declared"];
    reject(changed);
    changed = result;
    changed["artifacts"]["files:declared"]["file"] =
            (source.parent_path() / "../files/declared.xml").string();
    reject(changed);
    changed = result;
    changed["artifacts"]["files:declared"]["sha256"] = std::string(64, '0');
    reject(changed);
    changed = result;
    changed["artifacts"]["files:declared"]["bytes"] = 0;
    reject(changed);
    std::filesystem::remove_all(root);
}

void verify_candidate_ui_retry() {
    const Json connection = {{"boot_id", "boot"}, {"observer_pid", 42}};
    const Json observed = {{"schema", 1}, {"ok", true}, {"boot_id", "boot"}, {"observer_pid", 42}};
    const Json window_changed = {{"schema", 1}, {"ok", false}, {"reason", "window_changed"}};
    const Json snapshot_busy = {{"schema", 1}, {"ok", false}, {"reason", "snapshot_busy"}};
    const auto observe = [&](const std::vector<std::pair<std::string_view, Json>> &replies,
                             std::string_view expected_error = {}) {
        std::size_t calls = 0;
        bool failed = false;
        try {
            const auto raw = machine_preparation_detail::read_candidate_ui(
                    connection, 35000, [&](const Json &message, int timeout) {
                        check(calls < replies.size());
                        const auto &[operation, response] = replies[calls++];
                        check(message.at("op") == operation);
                        check(timeout > 0 && timeout <= 35000);

                        if (operation == "ui") {
                            const int guest_timeout = message.at("timeout_ms").get<int>();
                            check(guest_timeout > 0 && guest_timeout <= std::min(timeout, 30000));
                            check(message.at("surfaces") ==
                                  Json::array({"media_primary", "media_secondary"}));
                            check(message.at("scope").at("windows") == "all_attached");
                        } else {
                            check(operation == "hello" && timeout <= 2000 && message.size() == 1);
                        }

                        return response;
                    });
            check(raw == observed);
        } catch (const VoyemuError &error) {
            failed = true;
            check(!expected_error.empty() &&
                  std::string_view(error.what()).find(expected_error) != std::string_view::npos);
        }

        check(failed == !expected_error.empty() && calls == replies.size());
    };

    observe({{"ui", observed}});
    observe({{"ui", window_changed},
             {"hello", observed},
             {"ui", snapshot_busy},
             {"hello", observed},
             {"ui", observed}});
    auto other_boot = observed;
    other_boot["boot_id"] = "other-boot";
    observe({{"ui", window_changed}, {"hello", other_boot}}, "rich UI observer lifetime changed");
    auto other_observer = observed;
    other_observer["observer_pid"] = 43;
    observe({{"ui", snapshot_busy}, {"hello", other_observer}},
            "rich UI observer lifetime changed");
    observe({{"ui", other_observer}}, "rich UI observer lifetime changed");
    auto rejected = window_changed;
    rejected["reason"] = "wm_display_conflict";
    observe({{"ui", rejected}}, "observer rejected observation; reason=wm_display_conflict");
    observe({{"ui", window_changed}, {"hello", rejected}},
            "observer handshake rejected; reason=wm_display_conflict");
    auto malformed = window_changed;
    malformed["schema"] = 2;
    observe({{"ui", malformed}}, "invalid rich UI observer response");
}

void verify_candidate_rich_ui() {
    const auto check_shell = [&](bool root, bool wrong_context, bool service_ready) {
        std::vector<std::vector<std::string>> calls;
        bool accepted = false, denied = false;
        try {
            accepted = machine_preparation_detail::android_candidate_ui_shell_ready(
                    [&](const std::vector<std::string> &cmd) -> std::string {
                        calls.push_back(cmd);

                        if (cmd == std::vector<std::string>{"id", "-u"}) {
                            return root ? "0" : "2000";
                        }

                        if (cmd == std::vector<std::string>{"id", "-Z"}) {
                            return wrong_context ? "u:r:su:s0" : "u:r:shell:s0";
                        }

                        check(cmd == std::vector<std::string>{"service", "check", "accessibility"});

                        return service_ready ? "Service accessibility: found"
                                             : "Service accessibility: not found";
                    });
        } catch (const VoyemuError &) {
            denied = true;
        }

        check(denied == (root || wrong_context) &&
              accepted == (!root && !wrong_context && service_ready));
        check(calls.size() == (root ? 1 : wrong_context ? 2 : 3));
        check(calls[0] == std::vector<std::string>{"id", "-u"});

        if (!root) {
            check(calls[1] == std::vector<std::string>{"id", "-Z"});
        }
    };

    check_shell(false, false, true);
    check_shell(false, false, false);
    check_shell(true, false, true);
    check_shell(false, true, true);

    for (unsigned variant = 0; variant < 4; ++variant) {
        unsigned probes = 0, dispatches = 0, broadcasts = 0;
        bool failed = false;
        try {
            machine_preparation_detail::start_qinggan11_secondary_service(
                    [&](const std::vector<std::string> &command, int timeout) -> std::string {
                        if (command.front() == "dumpsys") {
                            check(command == std::vector<std::string>{"dumpsys", "-t", "3",
                                                                      "activity", "services",
                                                                      "com.voyemu"});
                            check(timeout == 5000 && dispatches == 0);
                            ++probes;

                            if (variant == 1 || (variant == 0 && probes == 1)) {
                                return "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
                                       "*** SERVICE 'activity' DUMP TIMEOUT (3s) ***";
                            }

                            return "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
                                   "  (nothing)";
                        }

                        ++dispatches;
                        check(command ==
                              std::vector<std::string>{
                                      "am", "startservice", "-n",
                                      "com.voyemu/com.voyemu.output.SecondScreenService"});
                        check(timeout == 30000 && broadcasts == 0);

                        if (variant == 2) {
                            throw VoyemuError("MACHINE_PREPARATION", "host command timed out");
                        }

                        const std::string output =
                                "Starting service: Intent { cmp=com.voyemu/.output.SecondScreenService }";

                        return variant == 3 ? output + "\nError: rejected" : output;
                    },
                    [&](const std::function<bool()> &ready, int timeout, const std::string &) {
                        check(timeout == 30000 && probes == 0 && dispatches == 0);

                        if (!ready() && !ready()) {
                            throw VoyemuError("MACHINE_PREPARATION", "readiness timed out");
                        }
                    },
                    [&] {
                        check(variant == 0 && probes == 2 && dispatches == 1);
                        ++broadcasts;
                    });
        } catch (const VoyemuError &) {
            failed = true;
        }

        check(failed == (variant != 0));
        check(probes == (variant < 2 ? 2 : 1) && dispatches == (variant == 1 ? 0 : 1));
        check(broadcasts == (variant == 0 ? 1 : 0));
    }

    const auto request = android_candidate_ui_request(12000);

    check(request == Json({{"op", "ui"},
                           {"surfaces", Json::array({"media_primary", "media_secondary"})},
                           {"scope", {{"windows", "all_attached"}}},
                           {"timeout_ms", 12000}}));

    for (const int timeout : {0, 30001}) {
        bool failed = false;
        try {
            android_candidate_ui_request(timeout);
        } catch (...) {
            failed = true;
        }

        check(failed);
    }

    Json response = {{"schema", 1},
                     {"ok", true},
                     {"boot_id", "boot"},
                     {"observer_epoch", "epoch"},
                     {"observation_id", "observation"},
                     {"surfaces", Json::array()}};

    for (unsigned slot = 0; slot < 2; ++slot) {
        const Json node = {{"bridge_version", 1},
                           {"privacy",
                            {{"sensitive", false},
                             {"editable", false},
                             {"password", false},
                             {"input_type", nullptr}}},
                           {"text_status", "none"},
                           {"text", ""},
                           {"description", ""},
                           {"text_redacted", false},
                           {"bounds", nullptr},
                           {"layout", {{"params_type", "none"}, {"min_width", nullptr}}},
                           {"text_style", {{"text_size_px", nullptr}}},
                           {"image", {{"scale_type", nullptr}}}};
        response["surfaces"].push_back(
                {{"surface", slot ? "media_secondary" : "media_primary"},
                 {"display_id", slot ? 7 : 0},
                 {"sdk_display_id", slot},
                 {"width", 1920},
                 {"height", 720},
                 {"scope", "all_attached"},
                 {"status", slot ? "ok" : "partial"},
                 {"complete", slot != 0},
                 {"metadata_complete", true},
                 {"enumeration_complete", slot != 0},
                 {"windows", Json::array()},
                 {"unavailable_windows", slot ? Json::array() : Json::array({"wallpaper"})},
                 {"nodes", Json::array({node})}});
    }

    auto observed = android_candidate_ui_observation(response, 7);
    check(observed.at("format") == "voyemu.ui.v1" && observed.at("status") == "partial" &&
          observed.at("complete") == false);
    check(observed.at("screens")[0].at("display_id") == 0 &&
          observed.at("screens")[1].at("display_id") == 7 &&
          observed.at("screens")[1].at("sdk_display_id") == 1);
    check(observed.at("screens")[0].at("unavailable_windows") == Json::array({"wallpaper"}));
    check(observed.at("screens")[1].at("metadata_complete") == true &&
          observed.at("screens")[1].at("nodes")[0].at("text_style").at("text_size_px").is_null());
    auto safe = response;
    safe["surfaces"][1]["nodes"][0]["privacy"]["input_type"] = 1;
    safe["surfaces"][1]["nodes"][0]["text_status"] = "available";
    safe["surfaces"][1]["nodes"][0]["text"] = "Media";
    check(android_candidate_ui_observation(safe, 7).at("screens")[1].at("nodes")[0].at("text") ==
          "Media");
    auto secret = response;
    secret["surfaces"][0]["nodes"][0]["privacy"]["sensitive"] = true;
    secret["surfaces"][0]["nodes"][0]["text_status"] = "redacted";
    secret["surfaces"][0]["nodes"][0]["text_redacted"] = true;
    check(android_candidate_ui_observation(secret, 7).at("screens")[0].at("nodes")[0].at("text") ==
          "");
    auto partial = response;
    partial["surfaces"][0]["metadata_complete"] = false;
    partial["surfaces"][0]["window_read_failures"] =
            Json::array({{{"window_id", 19}, {"reason", "wallpaper_without_view_root"}}});
    const auto preserved = android_candidate_ui_observation(partial, 7);
    check(preserved.at("screens")[0].at("metadata_complete") == false &&
          preserved.at("screens")[0].at("window_read_failures") ==
                  partial.at("surfaces")[0].at("window_read_failures"));
    auto reject = [](const Json &value, unsigned id = 7) {
        bool failed = false;
        try {
            android_candidate_ui_observation(value, id);
        } catch (...) {
            failed = true;
        }

        check(failed);
    };
    auto bad = response;
    bad["surfaces"][1]["nodes"] = Json::array();
    reject(bad);
    bad = response;
    bad["surfaces"][1]["nodes"][0]["bridge_version"] = nullptr;
    reject(bad);
    bad = response;
    bad["surfaces"][0]["nodes"][0]["privacy"]["password"] = nullptr;
    reject(bad);
    bad = response;
    bad["surfaces"][0]["nodes"][0]["privacy"].erase("input_type");
    reject(bad);
    bad = response;
    bad["surfaces"][0]["nodes"][0]["text_status"] = "unknown";
    reject(bad);
    bad = secret;
    bad["surfaces"][0]["nodes"][0]["text"] = "secret";
    reject(bad);
    bad = response;
    bad["surfaces"][0]["complete"] = true;
    bad["surfaces"][0]["status"] = "ok";
    reject(bad);
    bad = response;
    bad["surfaces"][1]["scope"] = "api30_default_display";
    reject(bad);
    reject(response, 1);
    reject(response, 0);
    const auto directory = std::filesystem::path(__FILE__)
                                   .parent_path()
                                   .parent_path()
                                   .parent_path()
                                   .parent_path() /
                           ".local/build/tmp" / ("rich-ui-extent-" + random_token());
    ensure_private_directory(directory);
    struct Cleanup {
        std::filesystem::path p;

        ~Cleanup() {
            std::error_code error;
            std::filesystem::remove_all(p, error);
        }
    } cleanup{directory};
    auto large = safe;
    large["surfaces"][1]["nodes"][0]["text"] = std::string(150 * 1024, 'x');
    check(large.dump().size() > 128 * 1024);
    const auto saved = save_android_candidate_ui_observation(directory, large, 7);
    check(read_private_json(directory / "ui-observation-raw.json", 6 * 1024 * 1024) == large);
    check(read_private_json(directory / "ui-observation.json", 10 * 1024 * 1024) == saved &&
          saved.at("screens")[1].at("nodes")[0].at("text").get_ref<const std::string &>().size() ==
                  150 * 1024);
    auto oversized = large;
    oversized["surfaces"][1]["nodes"][0]["text"] = std::string(6 * 1024 * 1024, 'x');
    bool extent_rejected = false;
    try {
        save_android_candidate_ui_observation(directory, oversized, 7);
    } catch (const std::exception &error) {
        extent_rejected = std::string_view(error.what()).starts_with("STATE_EXTENT:");
    }

    check(extent_rejected);
    check(read_private_json(directory / "ui-observation-raw.json", 6 * 1024 * 1024) == large &&
          read_private_json(directory / "ui-observation.json", 10 * 1024 * 1024) == saved);
}

volatile std::sig_atomic_t candidate_cancelled = 0;

void cancel_candidate(int) {
    candidate_cancelled = 1;
}

Json run_owned_candidate(const std::filesystem::path &root, AndroidCandidateRequest request,
                         const std::filesystem::path &destination) {
    request.cancelled = [] {
        return candidate_cancelled != 0;
    };

    if (request.cancelled()) {
        throw std::runtime_error("test-entry candidate cancelled before dispatch");
    }

    return build_android_candidate(root, request, destination, 20ULL << 30, 12ULL << 30);
}

void verify_candidate_peak_formula() {
    // Non-media profiles need no scratch: peak = RAW re-export of base+payload+guest growth.
    check(android_candidate_peak_extra_bytes(Json{{"id", qinggan09_profile()}}, 0, 0) ==
          2ULL << 30);
    check(android_candidate_peak_extra_bytes(Json{{"id", qinggan09_profile()}}, 1ULL << 30,
                                             512ULL << 20) ==
          (2ULL << 30) + (1ULL << 30) + (512ULL << 20));
    // Passion media covers the scratch, raw export and growth of both disk copies.
    Json passion_media = {
            {"id", "test-passion"},
            {"platform", "passion"},
            {"board", "8155"},
            {"status", "incomplete"},
            {"android",
             {{"package", "system-images;android-30;default;arm64-v8a"},
              {"revision", "1"},
              {"url",
               "https://dl.google.com/android/repository/sys-img/android/arm64-v8a-30_r02.zip"},
              {"sha256", "cb50112cf2dd234a71e2a29b0241c23dbb37dd5fc3156c68cc9c49d0f58ad304"}}}};

    for (const auto *name : {"LY_Camera", "LY_Video", "LY_AVM"}) {
        passion_media["original"][name] = Json::object();
    }

    check(android_candidate_peak_extra_bytes(passion_media, 3ULL << 30, 1ULL << 30) ==
          (1792ULL << 20) + (3ULL << 30) + (1ULL << 30) + (2ULL << 30) + (512ULL << 20));
    auto x86_media = passion_media;
    x86_media["android"]["package"] = "system-images;android-30;default;x86_64";
    x86_media["android"]["url"] =
            "https://dl.google.com/android/repository/sys-img/android/x86_64-30_r11.zip";
    const auto x86_payload = 1272150162ULL;
    check(android_candidate_overlay_scratch_bytes(x86_media, x86_payload) == 2ULL << 30);
    check(android_candidate_peak_extra_bytes(x86_media, 3ULL << 30, x86_payload) ==
          (2ULL << 30) + (3ULL << 30) + x86_payload + (2ULL << 30) + (1ULL << 30));
    // Measured Passion build remains below the replaced flat12GiB term.
    check(android_candidate_peak_extra_bytes(passion_media, 3ULL << 30, 1ULL << 30) < 12ULL << 30);

    // Overflow/invalid extents must be rejected by checked arithmetic.
    for (const auto bad :
         {std::pair<std::uint64_t, std::uint64_t>{std::numeric_limits<std::uint64_t>::max(), 1},
          std::pair<std::uint64_t, std::uint64_t>{5ULL << 30, 0},
          std::pair<std::uint64_t, std::uint64_t>{0, 3ULL << 30}}) {
        bool refused = false;
        try {
            android_candidate_peak_extra_bytes(passion_media, bad.first, bad.second);
        } catch (...) {
            refused = true;
        }

        check(refused);
    }
}

void verify_offline_policy_pins() {
    const std::string policy = "2879712e7a6a12f262ab346fbe61b7f5b992e652e10d93edf8eb44a6c7b84a77",
                      contexts = "8bd8062c3b8108bdc34573f78d403691e747298a986a3464ace94721b02ad1d7",
                      api30_policy =
                              "e8f3b8cb54b3ec09280cf5c630f495b3202f1c9994e796c5a1cf707a5dcd6cf6",
                      api30_contexts =
                              "873da6472b242a86d657900bdd90d4fa458dbde615c75ea406c6806f06ce8ecc",
                      api30_properties =
                              "6618819c1a2cf856486d66e270459aeccfe03d8d7837c9cc946940cd5a104493";

    android_candidate_offline_policy_pin("patched:can-early-policy-a9", policy);
    android_candidate_offline_policy_pin("patched:can-early-file-contexts-a9", contexts);
    android_candidate_offline_policy_pin("patched:can-early-policy-api30", api30_policy,
                                         Json{{"platform", "qinggan11"},
                                              {"board", "8155"},
                                              {"features", {{"original_navi", true}}}});
    android_candidate_offline_policy_pin("patched:can-early-file-contexts-api30", api30_contexts);
    android_candidate_offline_policy_pin("patched:can-early-property-contexts-api30",
                                         api30_properties);

    for (const auto &[artifact, hash] : std::vector<std::pair<std::string, std::string>>{
                 {"patched:can-early-policy-a9",
                  "d49353119542aea94026886c0301806b73c42949f66cfd6124edb7952b1e34a1"},
                 {"patched:can-early-policy-a9", contexts},
                 {"patched:can-early-file-contexts-a9", policy},
                 {"patched:can-early-policy-api30", api30_contexts},
                 {"patched:can-early-file-contexts-api30", api30_policy},
                 {"patched:can-early-property-contexts-api30", policy},
                 {"other", policy}}) {
        bool refused = false;
        try {
            android_candidate_offline_policy_pin(artifact, hash);
        } catch (const std::exception &) {
            refused = true;
        }

        check(refused);
    }
}

void verify_labelled_base_promotion() {
#ifdef __APPLE__
    const auto root =
            std::filesystem::absolute(".local/build/tmp/label-promotion-" + random_token());
    ensure_private_directory(root);
    struct Cleanup {
        std::filesystem::path path;

        ~Cleanup() {
            std::filesystem::remove_all(path);
        }
    } cleanup{root};

    for (unsigned mode = 0; mode < 9; ++mode) {
        const auto stage = root / std::to_string(mode), machine = stage / "machine",
                   base = machine / "base/system.img", overlay = machine / "system.img.qcow2",
                   raw = stage / "offline-selinux-labels/android/system.img";
        ensure_private_directory(base.parent_path());
        ensure_private_directory(raw.parent_path());
        auto write = [](const auto &path, const std::string &value) {
            std::ofstream out(path, std::ios::binary);
            out << value;
            check(bool(out));
        };
        write(base, "old base");
        write(overlay, "old overlay");
        write(raw, "new base");
        const auto old_sha = sha256_file(base), overlay_sha = sha256_file(overlay),
                   raw_sha = sha256_file(raw);
        const auto external = root / ("shared-" + std::to_string(mode));
        write(external, "shared input");
        const auto external_sha = sha256_file(external);
        auto input = raw;
        int held = -1;

        if (mode == 1) {
            write(raw, "bad base");
        }

        if (mode == 2) {
            std::filesystem::create_hard_link(raw, stage / "raw-alias");
        }

        if (mode == 3) {
            input = stage / "foreign.img";
            write(input, "new base");
        }

        if (mode == 4) {
            held = ::open(overlay.c_str(), O_RDONLY);
        }

        if (mode == 5) {
            std::filesystem::remove(base);
            std::filesystem::create_symlink(external, base);
        }

        if (mode == 7) {
            write(raw, "new extent");
        }

        if (mode == 8) {
            std::filesystem::permissions(machine, std::filesystem::perms::owner_read |
                                                          std::filesystem::perms::owner_exec);
        }

        bool refused = false;
        try {
            android_candidate_promote_labelled_system(
                    machine, input, mode == 7 ? sha256_file(raw) : raw_sha, old_sha, overlay_sha,
                    mode == 6 ? UINT64_MAX : 0);
        } catch (...) {
            refused = true;
        }

        if (mode == 8) {
            std::filesystem::permissions(machine, std::filesystem::perms::owner_all);
        }

        if (held >= 0) {
            ::close(held);
        }

        check(refused == (mode != 0));
        check(sha256_file(external) == external_sha);

        if (mode == 0) {
            check(!std::filesystem::exists(raw) && !std::filesystem::exists(overlay));
            check(sha256_file(base) == raw_sha && std::filesystem::hard_link_count(base) == 1);
        } else {
            check(std::filesystem::exists(overlay) && sha256_file(overlay) == overlay_sha);

            if (mode != 5) {
                check(sha256_file(base) == (mode == 8 ? raw_sha : old_sha));
            }

            if (mode == 8) {
                check(!std::filesystem::exists(raw));
            }
        }
    }
#endif
}

void verify_candidate_storage() {
    verify_offline_policy_pins();
    verify_labelled_base_promotion();
    const auto source_root =
            std::filesystem::path(__FILE__).parent_path().parent_path().parent_path().parent_path();
    const auto a9 = read_private_json(
            source_root / "profiles" / qinggan09_profile() / "profile.json", 1 << 20);
    check(!a9.contains("id"));
    const std::uint64_t qinggan09_base = 2810564557ULL, qinggan09_payload = 152342979ULL;
    const auto qinggan09_budget = android_candidate_build_budget(
            a9, qinggan09_base, qinggan09_payload, qinggan09_profile());
    auto clone = a9;
    clone["id"] = "custom-qinggan09-development";
    clone["capture"] = {{"profile", "custom-qinggan09-development"},
                        {"referenceProfile", qinggan09_profile()}};
    const auto clone_budget = android_candidate_build_budget(
            clone, qinggan09_base, qinggan09_payload, "custom-qinggan09-development");
    check(clone_budget.reserve_bytes == qinggan09_budget.reserve_bytes &&
          clone_budget.peak_extra_bytes == qinggan09_budget.peak_extra_bytes);
    clone["capture"]["profile"] = "other";
    check(android_candidate_build_budget(clone, qinggan09_base, qinggan09_payload,
                                         "custom-qinggan09-development")
                  .reserve_bytes == 20ULL << 30);
    check(qinggan09_budget.reserve_bytes == 8ULL << 30);
    check(qinggan09_budget.peak_extra_bytes ==
          qinggan09_base + (6ULL << 30) + 2 * qinggan09_payload + (2ULL << 30) + (4ULL << 30));
    // The failed real build had 25GiB after copying the base: old 20+12 failed.
    check((25ULL << 30) < (20ULL << 30) + (12ULL << 30));
    check((25ULL << 30) >= qinggan09_budget.reserve_bytes + qinggan09_budget.peak_extra_bytes);
    check((40ULL << 30) >= qinggan09_budget.reserve_bytes + qinggan09_budget.peak_extra_bytes);

    for (unsigned mode = 0; mode < 4; ++mode) {
        auto bad = a9;

        if (mode == 0) {
            bad["android"]["sha256"] = "not-a-pin";
        }

        if (mode == 1) {
            bad["android"]["revision"] = "r2";
        }

        if (mode == 2) {
            bad["id"] = "unrelated";
        }

        bool refused = false;
        try {
            android_candidate_build_budget(bad, mode == 3 ? UINT64_MAX : qinggan09_base,
                                           qinggan09_payload, qinggan09_profile());
        } catch (...) {
            refused = true;
        }

        check(refused);
    }

    check(android_candidate_build_budget(a9, qinggan09_base, qinggan09_payload, "unregistered")
                  .reserve_bytes == 20ULL << 30);

    const Json nxp = {
            {"id", "test-nxp"},
            {"platform", "qinggan09"},
            {"board", "nxp"},
            {"android",
             {{"package", "system-images;android-28;default;arm64-v8a"},
              {"url",
               "https://dl.google.com/android/repository/sys-img/android/arm64-v8a-28_r02.zip"},
              {"revision", "1"},
              {"sha256", "86844d2edf6ba7c7f11261f6be3fb37788c985cfcf3b8924cfe9f57a1ccbc0a9"}}}};
    const auto budget = android_candidate_build_budget(nxp, 3ULL << 30, 64ULL << 20);
    check(budget.reserve_bytes == 8ULL << 30 &&
          budget.peak_extra_bytes ==
                  android_candidate_peak_extra_bytes(nxp, 3ULL << 30, 64ULL << 20));

    for (const auto *id : {qinggan09_profile().c_str(), "other"}) {
        const auto old = android_candidate_build_budget(Json{{"id", id}}, 0, 0);
        check(old.reserve_bytes == 20ULL << 30 && old.peak_extra_bytes == 12ULL << 30);
    }

    auto wrong = nxp;
    wrong["android"]["package"] = "system-images;android-30;default;arm64-v8a";
    bool wrong_refused = false;
    try {
        android_candidate_build_budget(wrong, 0, 0);
    } catch (...) {
        wrong_refused = true;
    }

    check(wrong_refused);
    Json passion = {
            {"id", "test-passion"},
            {"platform", "passion"},
            {"board", "8155"},
            {"android",
             {{"package", "system-images;android-30;default;arm64-v8a"},
              {"url",
               "https://dl.google.com/android/repository/sys-img/android/arm64-v8a-30_r02.zip"},
              {"revision", "1"},
              {"sha256", "cb50112cf2dd234a71e2a29b0241c23dbb37dd5fc3156c68cc9c49d0f58ad304"}}}};

    for (const auto *name : {"LY_Camera", "LY_Video", "LY_AVM"}) {
        passion["original"][name] = Json::object();
    }

    const auto passion_budget = android_candidate_build_budget(passion, 3ULL << 30, 1ULL << 30);
    auto qinggan11 = passion;
    qinggan11["id"] = "test-qinggan11";
    qinggan11["platform"] = "qinggan11";
    qinggan11["android"]["offline_selinux_labels"] = "qinggan11-can-early-v1";
    const auto qinggan11_budget = android_candidate_build_budget(qinggan11, 3ULL << 30, 1ULL << 30);
    check(qinggan11_budget.reserve_bytes == 8ULL << 30 &&
          qinggan11_budget.peak_extra_bytes ==
                  android_candidate_peak_extra_bytes(qinggan11, 3ULL << 30, 1ULL << 30));

    for (unsigned mode = 0; mode < 3; ++mode) {
        auto bad = qinggan11;

        if (mode == 0) {
            bad["android"]["package"] = "system-images;android-28;default;arm64-v8a";
        }

        if (mode == 1) {
            bad["android"]["revision"] = "r2";
        }

        if (mode == 2) {
            bad["android"]["sha256"] = "not-a-pin";
        }

        bool denied = false;
        try {
            android_candidate_build_budget(bad, 3ULL << 30, 1ULL << 30);
        } catch (...) {
            denied = true;
        }

        check(denied);
    }

    check(passion_budget.reserve_bytes == 8ULL << 30 &&
          passion_budget.peak_extra_bytes ==
                  android_candidate_peak_extra_bytes(passion, 3ULL << 30, 1ULL << 30));

    for (unsigned mode = 0; mode < 4; ++mode) {
        auto bad = passion;

        if (mode == 0) {
            bad["android"]["package"] = "system-images;android-28;default;arm64-v8a";
        }

        if (mode == 1) {
            bad["android"]["revision"] = "r2";
        }

        if (mode == 2) {
            bad["android"]["sha256"] = "not-a-pin";
        }

        bool denied = false;
        try {
            android_candidate_build_budget(bad, mode == 3 ? UINT64_MAX : 3ULL << 30, 1ULL << 30);
        } catch (...) {
            denied = true;
        }

        check(denied);
    }

    const auto qinggan11_611 = read_private_json(
            source_root / "profiles/free-11-chinese-20250710-6.11.1/profile.json");
    const auto qinggan11_611_budget = android_candidate_build_budget(
            qinggan11_611, 3ULL << 30, 512ULL << 20, "free-11-chinese-20250710-6.11.1");
    check(qinggan11_611_budget.reserve_bytes == 8ULL << 30 &&
          qinggan11_611_budget.peak_extra_bytes ==
                  android_candidate_peak_extra_bytes(qinggan11_611, 3ULL << 30, 512ULL << 20,
                                                     "free-11-chinese-20250710-6.11.1"));

    // The image pins live only in profile.json; the measured reserve follows the image package,
    // the labels and the OEM system image.
    for (unsigned mode = 0; mode < 3; ++mode) {
        auto bad = qinggan11_611;

        if (mode == 0) {
            bad["android"]["package"] = "other";
        }

        if (mode == 1) {
            bad["android"]["offline_selinux_labels"] = "other";
        }

        if (mode == 2) {
            bad["acquisition"]["images"]["system"]["sha256"] = std::string(64, '0');
        }

        check(android_candidate_reserve_bytes(bad, "free-11-chinese-20250710-6.11.1") ==
              20ULL << 30);
    }

    for (const auto *reference : {"free-11-chinese-20260731-7.3.1", qinggan09_profile().c_str()}) {
        auto cross = qinggan11_611;
        cross["capture"] = {{"profile", "free-11-chinese-20250710-6.11.1"},
                            {"referenceProfile", reference}};
        check(android_candidate_reserve_bytes(cross, "free-11-chinese-20250710-6.11.1") ==
              20ULL << 30);
    }

    // The measured budget follows the data of the profile, not its id.
    auto foreign611 = qinggan11_611;
    foreign611["id"] = "test-qinggan11";
    foreign611["platform"] = "qinggan11";
    check(android_candidate_reserve_bytes(foreign611, "test-qinggan11") == 8ULL << 30);
    const auto directory =
            std::filesystem::absolute(".local/build/tmp/candidate-storage-test-" + random_token());
    ensure_private_directory(directory);
    const auto source = directory / "clean";
    ensure_private_directory(source);
    const auto input = source / "system.img";
    {
        std::ofstream out(input, std::ios::binary);
        out << std::string(4 << 20, 'D');
        check(bool(out));
    }
    const auto pin = sha256_file(input);
    const Json files = {{"system.img", {{"sha256", pin}}}};
    const std::uint64_t reserve = 1ULL << 20, peak_extra = 12ULL << 30,
                        before = reserve + peak_extra + (1ULL << 20),
                        dense_bytes = std::filesystem::file_size(input);
    auto attempt = [&](const std::string &name, std::uint64_t first, std::uint64_t after,
                       bool pass) {
        const auto target = directory / name;
        unsigned reads = 0;
        bool published = false, failed = false;
        try {
            prepare_android_candidate_base(source, files, target, reserve, peak_extra, [&] {
                return reads++ == 0 ? first : after;
            });
            published = true;
        } catch (const std::exception &) {
            failed = true;
        }

        check(pass ? published && !failed : failed && !published);

        if (pass) {
            check(sha256_file(target / "machine/base/system.img") == pin);
            check(std::filesystem::hard_link_count(target / "machine/base/system.img") == 1);
            std::filesystem::remove_all(target);
        } else {
            check(!std::filesystem::exists(target));
        }

        check(sha256_file(input) == pin);
    };
    // Identical logical inputs; only the observed post-copy free space differs.
    attempt("clone", before, before, true);
    attempt("dense", before, before - dense_bytes, false);
    attempt("floor-before", reserve - 1, reserve - 1, false);
    attempt("floor-copy", before, reserve - 1, false);
    // Exact measured-peak boundary: one byte below denies, exactly at peak accepts.
    attempt("peak-boundary", before, reserve + peak_extra, true);
    attempt("peak-one-short", before, reserve + peak_extra - 1, false);
    // Short space names the free and required space and the installation root.
    {
        const auto target = directory / "short-space";
        std::string failure;
        try {
            prepare_android_candidate_base(source, files, target, reserve, peak_extra, [&] {
                return reserve - 1;
            });
        } catch (const std::exception &error) {
            failure = error.what();
        }

        check(failure.starts_with("MACHINE_PREPARATION: not enough disk space: ") &&
              !std::filesystem::exists(target));
    }
    // An injected measurement stands for the disk: a reserve beyond any real disk still publishes
    // when the measurement admits it, so the budget checks below do not depend on this host.
    {
        const std::uint64_t beyond_disk = 1ULL << 50;
        const auto target = directory / "injected-measurement";
        prepare_android_candidate_base(source, files, target, beyond_disk, peak_extra, [&] {
            return beyond_disk + peak_extra;
        });
        check(sha256_file(target / "machine/base/system.img") == pin);
        std::filesystem::remove_all(target);
    }

    for (const bool exact : {false, true}) {
        const auto target = directory /
                            (exact ? "qinggan09-budget-boundary" : "qinggan09-budget-one-short");
        bool passed = false;
        try {
            prepare_android_candidate_base(source, files, target, qinggan09_budget.reserve_bytes,
                                           qinggan09_budget.peak_extra_bytes, [&] {
                                               return qinggan09_budget.reserve_bytes +
                                                      qinggan09_budget.peak_extra_bytes -
                                                      (exact ? 0 : 1);
                                           });
            passed = true;
        } catch (...) { /* Ignored: the expected rejection is asserted afterwards. */
        }

        check(passed == exact);

        if (exact) {
            std::filesystem::remove_all(target);
        } else {
            check(!std::filesystem::exists(target));
        }
    }

    for (const bool exact : {false, true}) {
        const auto target = directory / (exact ? "nxp-budget-boundary" : "nxp-budget-one-short");
        bool passed = false;
        try {
            prepare_android_candidate_base(
                    source, files, target, budget.reserve_bytes, budget.peak_extra_bytes, [&] {
                        return budget.reserve_bytes + budget.peak_extra_bytes - (exact ? 0 : 1);
                    });
            passed = true;
        } catch (...) { /* Ignored: the expected rejection is asserted afterwards. */
        }

        check(passed == exact);

        if (exact) {
            std::filesystem::remove_all(target);
        } else {
            check(!std::filesystem::exists(target));
        }
    }

    for (const bool exact : {false, true}) {
        const auto target = directory /
                            (exact ? "passion-budget-boundary" : "passion-budget-one-short");
        bool passed = false;
        try {
            prepare_android_candidate_base(source, files, target, passion_budget.reserve_bytes,
                                           passion_budget.peak_extra_bytes, [&] {
                                               return passion_budget.reserve_bytes +
                                                      passion_budget.peak_extra_bytes -
                                                      (exact ? 0 : 1);
                                           });
            passed = true;
        } catch (...) { /* Ignored: the expected rejection is asserted afterwards. */
        }

        check(passed == exact);

        if (exact) {
            std::filesystem::remove_all(target);
        } else {
            check(!std::filesystem::exists(target));
        }
    }

    for (const bool exact : {false, true}) {
        const auto target = directory /
                            (exact ? "qinggan11-budget-boundary" : "qinggan11-budget-one-short");
        bool passed = false;
        try {
            prepare_android_candidate_base(source, files, target, qinggan11_budget.reserve_bytes,
                                           qinggan11_budget.peak_extra_bytes, [&] {
                                               return qinggan11_budget.reserve_bytes +
                                                      qinggan11_budget.peak_extra_bytes -
                                                      (exact ? 0 : 1);
                                           });
            passed = true;
        } catch (...) { /* Ignored: the expected rejection is asserted afterwards. */
        }

        check(passed == exact);

        if (exact) {
            std::filesystem::remove_all(target);
        } else {
            check(!std::filesystem::exists(target));
        }
    }

    for (const bool exact : {false, true}) {
        const auto target = directory / (exact ? "qinggan11-611-budget-boundary"
                                               : "qinggan11-611-budget-one-short");
        bool passed = false;
        try {
            prepare_android_candidate_base(source, files, target,
                                           qinggan11_611_budget.reserve_bytes,
                                           qinggan11_611_budget.peak_extra_bytes, [&] {
                                               return qinggan11_611_budget.reserve_bytes +
                                                      qinggan11_611_budget.peak_extra_bytes -
                                                      (exact ? 0 : 1);
                                           });
            passed = true;
        } catch (...) { /* Ignored: the expected rejection is asserted afterwards. */
        }

        check(passed == exact);

        if (exact) {
            std::filesystem::remove_all(target);
        } else {
            check(!std::filesystem::exists(target));
        }
    }

    const auto overflow = directory / "overflow";
    bool rejected = false;
    try {
        prepare_android_candidate_base(source, files, overflow,
                                       std::numeric_limits<std::uint64_t>::max(),
                                       std::numeric_limits<std::uint64_t>::max(), [] {
                                           return std::numeric_limits<std::uint64_t>::max();
                                       });
    } catch (...) {
        rejected = true;
    }

    check(rejected && !std::filesystem::exists(overflow));
    const auto bad_input = source / "zz-bad.img";
    {
        std::ofstream out(bad_input);
        out << "original";
    }
    auto bad_files = files;
    bad_files["zz-bad.img"] = {{"sha256", std::string(64, '0')}};
    const auto partial = directory / "copy-failure";
    unsigned copy_reads = 0;
    rejected = false;
    try {
        prepare_android_candidate_base(source, bad_files, partial, reserve, peak_extra, [&] {
            ++copy_reads;

            return before;
        });
    } catch (...) {
        rejected = true;
    }

    check(rejected && copy_reads >= 2 && !std::filesystem::exists(partial) &&
          sha256_file(input) == pin);
    {
        const auto stock = source / "kernel-ranchu", development = directory / "development-Image";
        {
            std::ofstream out(stock);
            out << "stock kernel";
        }
        {
            std::ofstream out(development);
            out << "development kernel";
        }
        const auto stock_sha = sha256_file(stock), development_sha = sha256_file(development);
        auto boot_files = files;
        boot_files["kernel-ranchu"] = {{"sha256", stock_sha}};
        const auto selected = directory / "development-base";
        prepare_android_candidate_base(
                source, boot_files, selected, reserve, peak_extra,
                [&] {
                    return before;
                },
                development, development_sha);
        check(sha256_file(selected / "machine/base/kernel-ranchu") == development_sha &&
              sha256_file(stock) == stock_sha);
        std::filesystem::remove_all(selected);
        const auto unchanged = directory / "stock-base";
        prepare_android_candidate_base(source, boot_files, unchanged, reserve, peak_extra, [&] {
            return before;
        });
        check(sha256_file(unchanged / "machine/base/kernel-ranchu") == stock_sha);
        std::filesystem::remove_all(unchanged);
        bool denied = false;
        try {
            prepare_android_candidate_base(
                    source, boot_files, directory / "bad-kernel-base", reserve, peak_extra,
                    [&] {
                        return before;
                    },
                    development, std::string(64, '0'));
        } catch (...) {
            denied = true;
        }

        check(denied && !std::filesystem::exists(directory / "bad-kernel-base") &&
              sha256_file(stock) == stock_sha);
    }
    const auto existing = directory / "existing";
    ensure_private_directory(existing);
    {
        std::ofstream out(existing / "keep");
        out << "keep";
    }
    rejected = false;
    try {
        prepare_android_candidate_base(source, files, existing, reserve, peak_extra, [&] {
            return before;
        });
    } catch (...) {
        rejected = true;
    }

    check(rejected && std::filesystem::exists(existing / "keep"));
    std::filesystem::remove_all(directory);
}

void verify_candidate_cancellation() {
    for (const int signal : {SIGTERM, SIGINT}) {
        candidate_cancelled = 0;
        const auto previous = std::signal(signal, cancel_candidate);
        std::raise(signal);
        check(candidate_cancelled == 1);
        bool refused = false;
        try {
            run_owned_candidate("relative", AndroidCandidateRequest{}, "relative");
        } catch (const std::exception &error) {
            refused = std::string(error.what()) == "test-entry candidate cancelled before dispatch";
        }

        std::signal(signal, previous);
        candidate_cancelled = 0;
        check(refused);
    }
}

std::map<std::string, std::string> candidate_route_environment(const AndroidOwnedAdb &binding) {
    auto environment = android_owned_adb_sdk_environment(binding);

    // Keep the scanner's exact disconnected-port retry worker alive, while its
    // initial scan range remains empty (5555..1). No USB/mDNS discovery.
    environment.at("ADB_EMU") = "1";
    check(environment.at("ADB_LOCAL_TRANSPORT_MAX_PORT") == "1");

    return environment;
}

Json candidate_route(const std::filesystem::path &file) {
    const auto spec = read_private_json(file, 128 * 1024);
    const auto binding = android_owned_adb(5580, 35580, spec.at("owner").get<std::string>(), 25580);

    check(spec.at("schema") == 1 && spec.at("server_port") == 25580 &&
          spec.at("console_port") == 5580 && spec.at("grpc_port") == 35580);
    check(spec.at("environment") == Json(candidate_route_environment(binding)) &&
          spec.at("server_arguments") == Json(android_owned_adb_server_arguments(binding)));

    return spec;
}

void check_candidate_route_environment(const Json &spec) {
    for (auto item = spec.at("environment").begin(); item != spec.at("environment").end(); ++item) {
        const auto *value = std::getenv(item.key().c_str());
        check(value && std::string(value) == item.value().get<std::string>());
    }
}
} // namespace
#ifndef _WIN32
static int failure_sdk_child(unsigned port, int seconds = 15) {
    std::vector<int> sockets;

    for (unsigned value : {port, port + 1}) {
        const auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(value);

        if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof address) ||
            ::listen(fd, 2)) {
            return 3;
        }

        sockets.push_back(fd);
    }

    std::this_thread::sleep_for(std::chrono::seconds(seconds));

    for (auto fd : sockets) {
        ::close(fd);
    }

    return 0;
}

static int failure_adb_child(int argc, char **argv) {
    std::string server;

    if (argc >= 6 && std::string(argv[1]) == "-H") {
        if (std::string(argv[2]) != "127.0.0.1" || std::string(argv[3]) != "-P" ||
            std::string(argv[4]) == "5037") {
            return 3;
        }

        server = argv[4];
        argc -= 4;
        argv += 4;
    }

    if (argc < 4 || std::string(argv[1]) != "-s") {
        return 3;
    }

    const auto settings = read_private_json(std::filesystem::current_path() / "fake-adb.json",
                                            4096);
    const auto mode = settings.at("mode").get<std::string>();
    std::ofstream(std::filesystem::current_path() / "probe-call", std::ios::app) << "1";

    if (settings.contains("private_server")) {
        if (server != settings.at("private_server").get<std::string>()) {
            return 3;
        }

        const auto *route = std::getenv("ADB_SERVER_SOCKET");
        const auto *scan = std::getenv("ADB_LOCAL_TRANSPORT_MAX_PORT");
        const auto *input = std::getenv("ADB_USB");

        if (!route || std::string(route) != "tcp:127.0.0.1:" + server || !scan ||
            std::string(scan) != "1" || !input || std::string(input) != "0") {
            return 3;
        }
    }

    if (mode.starts_with("root-")) {
        const auto state = std::filesystem::current_path() / "root-step";
        unsigned step = 0;
        std::ifstream(state) >> step;
        const auto operation = std::string(argv[3]);
        const auto script = argc > 4 ? std::string(argv[4]) : std::string{};

        if (operation == "root") {
            std::ofstream(std::filesystem::current_path() / "root-requests", std::ios::app) << "1";

            if (mode == "root-request-failed") {
                std::cout << "permission denied\n";

                return 7;
            }

            if (mode == "root-request-denied") {
                std::cout << "adbd cannot run as root in production builds\n";

                return 0;
            }

            if (mode == "root-quiet") {
                std::ofstream(state) << 1;
                std::cout.flush();

                return 0;
            }

            if (mode == "root-offline" || mode == "root-offline-nochange" ||
                mode == "root-offline-wrong-nonce") {
                std::ofstream(state) << 1;
                std::cout << "adb: device offline\n";

                return 1;
            }

            if (mode == "root-closed" || mode == "root-device-missing" ||
                mode == "root-foreign-serial") {
                std::ofstream(state) << 1;
                std::cout << "adb: unable to connect for root: closed\n";

                return 1;
            }

            std::ofstream(state) << 1;

            std::cout << "restarting adbd as root\n";

            return 0;
        }

        if (operation == "shell" && script == "getprop") {
            std::cout << settings.at("nonce").get<std::string>() << '\n';

            return 0;
        }

        if (operation == "shell" && script == "'id' '-u'") {
            std::cout << "0\n";

            return 0;
        }

        if (operation == "shell" && script == "'configure-barrier'") {
            if (step < 3) {
                std::cout << "configure dispatched before replacement adbd\n";

                return 7;
            }

            return 0;
        }

        if (operation == "shell" && script.find("VOYEMU_ADBD_LIFETIME") != std::string::npos) {
            if (step == 1 && mode == "root-offline") {
                std::ofstream(state) << 2;
                std::cout << "adb: device offline\n";

                return 1;
            }

            if (step == 1 && (mode == "root-device-missing" || mode == "root-foreign-serial")) {
                std::ofstream(state) << 2;
                std::cout << "adb: device '"
                          << (mode == "root-device-missing" ? argv[2] : "emulator-0")
                          << "' not found\n";

                return 1;
            }

            if (step == 2 && mode != "root-nochange") {
                std::ofstream(state) << 3;
                std::cout << "error: device offline\n";

                return 1;
            }

            std::ofstream(std::filesystem::current_path() / "snapshots", std::ios::app) << "1";

            if (step != 0 && mode == "root-permission") {
                std::cout << "cat: /proc/33/stat: Permission denied\n";

                return 7;
            }

            if (step != 0 && mode == "root-protocol") {
                std::cout << "invalid lifetime protocol\n";

                return 0;
            }

            const auto pid = step >= 3 && mode != "root-start-change" ? "44" : "33";
            const auto start = step >= 3 && mode == "root-start-change" ? "101" : "100";

            const auto nonce = step != 0 && (mode == "root-wrong-nonce" ||
                                             mode == "root-offline-wrong-nonce")
                                       ? std::string(32, 'c')
                                       : settings.at("nonce").get<std::string>();

            const std::string boot = step != 0 && mode == "root-changed-boot"
                                             ? "12345678-1234-1234-1234-123456789abd"
                                             : "12345678-1234-1234-1234-123456789abc";

            std::cout << "VOYEMU_ADBD_LIFETIME\n"
                      << nonce << '\n'
                      << boot << '\n'
                      << pid << '\n'
                      << start << '\n'
                      << (step == 0 && mode != "root-already" ? "2000" : "0") << '\n'
                      << pid << '\n'
                      << (step != 0 && mode == "root-inconsistent" ? "101" : start) << '\n'
                      << boot << '\n'
                      << nonce << '\n';

            if (step == 1 && mode != "root-nochange" && mode != "root-offline-nochange") {
                std::ofstream(state) << 2;
            }

            return 0;
        }
    }

    if (std::string(argv[3]) == "emu") {
        if (argc != 6 || std::string(argv[4]) != "avd" || std::string(argv[5]) != "name") {
            return 3;
        }

        std::cout << ((mode == "foreign-avd" || mode == "sync-foreign-avd")
                              ? "foreign-avd"
                              : settings.at("avd").get<std::string>())
                  << "\nOK\n";

        return 0;
    }

    if (argc != 5 || std::string(argv[3]) != "shell") {
        return 3;
    }

    const std::string script = argv[4];

    if (mode.starts_with("broadcast-")) {
        if (script !=
            "'am' 'broadcast' '--receiver-foreground' '--user' '0' '-a' 'com.android.emulator.multidisplay.START' '-n' 'com.android.emulator.multidisplay/.MultiDisplayServiceReceiver'") {
            return 3;
        }

        std::cout << "Broadcasting: SDK bootstrap\n" << std::flush;

        if (mode == "broadcast-slow") {
            std::this_thread::sleep_for(std::chrono::seconds(11));
        }

        if (mode == "broadcast-failed") {
            return 7;
        }

        if (mode != "broadcast-noack") {
            std::cout << "Broadcast completed: result=0\n";
        }

        return 0;
    }

    if (mode.starts_with("sync-")) {
        const bool mutation = script.find("'sync'") != std::string::npos;
        const bool probe = script.find("'true'") != std::string::npos;

        if (!mutation && !probe) {
            return 3;
        }

        const auto at = script.find("VOYEMU_STARTUP_");

        if (at == std::string::npos) {
            return 3;
        }

        const auto marker = script.substr(at, 15 + 32);
        const std::string boot = "12345678-1234-1234-1234-123456789abc",
                          other = "12345678-1234-1234-1234-123456789abd";
        const auto nonce = mode == "sync-wrong-nonce" ? std::string(32, 'c')
                                                      : settings.at("nonce").get<std::string>();

        if (mutation) {
            if (script.find("[ \"$b\" = '" + boot + "' ] || exit 79;") == std::string::npos ||
                script.find("[ \"$n\" = '" + settings.at("nonce").get<std::string>() +
                            "' ] || exit 79;") == std::string::npos) {
                return 3;
            }

            if (mode == "sync-new-boot") {
                return 79;
            }

            if (mode == "sync-nonzero") {
                return 7;
            }

            if (mode == "sync-slow") {
                std::this_thread::sleep_for(std::chrono::seconds(12));
            }

            std::ofstream(std::filesystem::current_path() / "persisted")
                    << "synthetic dirty guest buffer flushed";
            std::filesystem::remove(std::filesystem::current_path() / "dirty");
        }

        const auto after = mode == "sync-changed-boot" ? other : boot;
        std::cout << marker << ":b1:" << boot << '\n'
                  << marker << ":n1:" << nonce << '\n'
                  << marker << ":body\n\n"
                  << marker << ":exit:0\n"
                  << marker << ":n2:" << nonce << '\n'
                  << marker << ":b2:" << after << '\n'
                  << marker << ":utc:1700000000\n";

        return 0;
    }

    if (script.find("'-t' '200'") != std::string::npos) {
        return 3; // The final200 unrelated log rows must not hide the earlier startup failure.
    }

    const bool audio = script.find("'dumpsys' 'audio'") != std::string::npos,
               notification = script.find("'dumpsys' 'notification'") != std::string::npos;
    const bool probe = script.find("'sed'") != std::string::npos ||
                       script.find("'true'") != std::string::npos ||
                       script.find("'resolve-activity'") != std::string::npos ||
                       script.find("'query-activities'") != std::string::npos ||
                       script.find("'dumpsys' 'package'") != std::string::npos ||
                       script.find("'pm' 'list'") != std::string::npos ||
                       script.find("'dumpsys' 'activity'") != std::string::npos;

    if (mode == "logcat-overflow" && !audio && !notification && !probe) {
        std::cout << std::string(600000, 'x');

        return 0;
    }

    if (!audio && !notification && !probe) {
        for (const auto tag : {"QGRuntime:E", "System.err:W", "main", "system", "crash", "events",
                               "notification_alert:I", "PackageManager:I", "AppMain:D"}) {
            if (script.find(tag) == std::string::npos) {
                return 3;
            }
        }
    }

    const auto at = script.find("VOYEMU_STARTUP_");

    if (at == std::string::npos) {
        return 3;
    }

    const auto marker = script.substr(at, 15 + 32);

    if (audio && mode == "audio-command-failed") {
        return 7;
    }

    const auto nonce = (mode == "wrong-nonce" || (audio && mode == "audio-wrong-nonce"))
                               ? std::string(32, 'c')
                               : settings.at("nonce").get<std::string>();
    const std::string boot = audio && mode == "audio-other-boot"
                                     ? "12345678-1234-1234-1234-123456789abd"
                                     : "12345678-1234-1234-1234-123456789abc",
                      after = mode == "changed-boot" ? "12345678-1234-1234-1234-123456789abd"
                                                     : boot;

    if (mode == "slow") {
        std::this_thread::sleep_for(std::chrono::seconds(8));
    }

    std::cout << marker << ":b1:" << boot << '\n'
              << marker << ":n1:" << nonce << '\n'
              << marker << ":body\n"
              << (audio ? "AudioPlaybackConfiguration uid=10142 usage=USAGE_NOTIFICATION"
                  : notification
                          ? "NotificationChannel sound=content://settings/system/notification_sound"
                          : "QGRuntime: token=secret-value failed ")
              << nonce << '\n'
              << marker << ":exit:0\n"
              << marker << ":n2:" << nonce << '\n'
              << marker << ":b2:" << after << '\n'
              << marker << ":utc:1700000000\n";

    return 0;
}

static void root_transition_fixture(const std::filesystem::path &self,
                                    const std::filesystem::path &parent) {
    const auto stage = parent / ("root-transition-" + random_token());

    ensure_private_directory(stage);
    unsigned port = 46000;

    while (port < 46500 && (!tcp_port_free(port) || !tcp_port_free(port + 1))) {
        port += 2;
    }

    unsigned server_port = 46500;

    while (server_port < 47000 && !tcp_port_free(server_port)) {
        server_port += 2;
    }

    check(port < 46500 && server_port < 47000);
    auto launch = [&](unsigned value, const char *name) {
        ProcessSpec spec;
        spec.executable = self;
        spec.arguments = {"--broadcast-sdk", std::to_string(value)};
        spec.directory = stage;
        spec.output = stage / name;

        return ChildProcess::launch(spec);
    };
    auto child = launch(port, "sdk.log"), server = launch(server_port, "adb.log");
    const auto ready = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < ready &&
           (!child.owns_tcp_listener(port) || !child.owns_tcp_listener(port + 1) ||
            !server.owns_tcp_listener(server_port))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    check(child.alive() && child.owns_tcp_listener(port) && child.owns_tcp_listener(port + 1) &&
          server.alive() && server.owns_tcp_listener(server_port));
    machine_preparation_detail::Candidate candidate(stage, stage, stage, self, self, self, port,
                                                    10000, {});
    candidate.avd = "root-transition-fixture";
    candidate.token = random_token();
    candidate.adb_binding = {port, 35580, server_port, random_token()};
    candidate.process = std::move(child);
    candidate.adb_server = std::move(server);
    // A boot has no time limit and leaves the deadline of the other steps untouched: it outlasts
    // that deadline while its checks still run bounded commands.
    {
        const auto saved = candidate.deadline;
        candidate.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        const auto booting = std::chrono::steady_clock::now();
        candidate.wait_boot(
                [&] {
                    (void)candidate.remaining(1000);

                    return std::chrono::steady_clock::now() - booting >
                           std::chrono::milliseconds(800);
                },
                "fixture boot");
        check(candidate.remaining(1000) > 100);
        candidate.deadline = saved;
    }

    for (const auto *mode : {"root-transition",
                             "root-start-change",
                             "root-quiet",
                             "root-closed",
                             "root-offline",
                             "root-offline-nochange",
                             "root-offline-wrong-nonce",
                             "root-device-missing",
                             "root-foreign-serial",
                             "root-already",
                             "root-nochange",
                             "root-wrong-nonce",
                             "root-changed-boot",
                             "root-protocol",
                             "root-permission",
                             "root-request-denied",
                             "root-request-failed",
                             "root-inconsistent",
                             "root-cancelled",
                             "root-owner-lost"}) {
        for (const auto *file : {"root-step", "root-requests", "snapshots"}) {
            std::filesystem::remove(stage / file);
        }

        candidate.cancelled = [&] {
            return std::string_view(mode) == "root-cancelled" &&
                   std::filesystem::exists(stage / "root-requests");
        };
        const bool nochange = std::string_view(mode) == "root-nochange" ||
                              std::string_view(mode) == "root-offline-nochange";

        candidate.deadline = std::chrono::steady_clock::now() +
                             std::chrono::milliseconds(nochange ? 900 : 10000);
        write_private_json(stage / "fake-adb.json",
                           {{"mode", mode},
                            {"avd", candidate.avd},
                            {"nonce", candidate.token},
                            {"private_server", std::to_string(server_port)}});

        if (std::string_view(mode) == "root-owner-lost") {
            candidate.adb_server.terminate(1000);
        }

        std::string failure;
        const auto begin = std::chrono::steady_clock::now();
        try {
            candidate.root_adbd();
        } catch (const VoyemuError &error) {
            failure = error.what();
        }

        const bool success = std::string_view(mode) == "root-transition" ||
                             std::string_view(mode) == "root-start-change" ||
                             std::string_view(mode) == "root-quiet" ||
                             std::string_view(mode) == "root-closed" ||
                             std::string_view(mode) == "root-offline" ||
                             std::string_view(mode) == "root-device-missing" ||
                             std::string_view(mode) == "root-already";
        check(success == failure.empty());

        if (std::string_view(mode) == "root-transition" ||
            std::string_view(mode) == "root-start-change" ||
            std::string_view(mode) == "root-offline" ||
            std::string_view(mode) == "root-device-missing") {
            candidate.shell({"configure-barrier"});
        }

        if (std::string_view(mode) == "root-already" ||
            std::string_view(mode) == "root-owner-lost") {
            check(!std::filesystem::exists(stage / "root-requests"));
        } else {
            check(machine_preparation_detail::text(stage / "root-requests") == "1");
        }

        if (!success && !nochange && std::string_view(mode) != "root-owner-lost") {
            check(machine_preparation_detail::text(stage / "snapshots").size() <= 2);
        }

        if (nochange) {
            check(std::chrono::steady_clock::now() - begin < std::chrono::seconds(2));
        }

        if (std::string_view(mode) == "root-offline-nochange") {
            check(failure.find("timeout rooted adbd lifetime transition") != std::string::npos);
        }

        if (std::string_view(mode) == "root-foreign-serial") {
            check(failure.find("adb: device 'emulator-0' not found") != std::string::npos);
        }

        if (std::string_view(mode) == "root-offline-wrong-nonce") {
            check(failure.find("guest nonce differs") != std::string::npos);
        }

        std::cout << mode << ": " << (success ? "passed" : failure) << '\n';
    }

    candidate.process.terminate(1000);
    candidate.adb_server.terminate(1000);
    std::cout << "root transition barrier passed: " << stage.string() << '\n';
}

static void broadcast_fixture(const std::filesystem::path &self,
                              const std::filesystem::path &parent) {
    const auto stage = parent / ("candidate-broadcast-fixture-" + random_token());

    ensure_private_directory(stage);
    unsigned port = 49500;

    while (port < 49900 && (!tcp_port_free(port) || !tcp_port_free(port + 1))) {
        port += 2;
    }

    check(port < 49900);
    ProcessSpec sdk;
    sdk.executable = self;
    sdk.arguments = {"--broadcast-sdk", std::to_string(port)};
    sdk.directory = stage;
    sdk.output = stage / "sdk.log";
    auto child = ChildProcess::launch(sdk);
    const auto ready = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < ready &&
           (!child.owns_tcp_listener(port) || !child.owns_tcp_listener(port + 1))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    check(child.alive() && child.owns_tcp_listener(port) && child.owns_tcp_listener(port + 1));
    auto mode = [&](const std::string &value) {
        write_private_json(stage / "fake-adb.json", {{"mode", value}});
    };
    mode("broadcast-slow");
    ProcessSpec old;
    old.executable = self;
    old.directory = stage;
    old.arguments = {
            "-s", "emulator-" + std::to_string(port), "shell",
            "'am' 'broadcast' '--receiver-foreground' '--user' '0' '-a' 'com.android.emulator.multidisplay.START' '-n' 'com.android.emulator.multidisplay/.MultiDisplayServiceReceiver'"};
    const auto red = execute(old, 10000, 65536);
    check(red.timed_out && red.output.find("Broadcasting:") != std::string::npos && child.alive());
    const auto begin = std::chrono::steady_clock::now();
    android_candidate_start_multidisplay(child, self, stage, port, 30000);
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    check(elapsed >= std::chrono::seconds(11) && elapsed < std::chrono::seconds(15));
    auto rejected = [&](ChildProcess &owner, int budget) {
        bool failed = false;
        try {
            android_candidate_start_multidisplay(owner, self, stage, port, budget);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed);
    };
    unsigned server_port = 48000;

    while (server_port < 48900 &&
           (!tcp_port_free(server_port) || !tcp_port_free(server_port + 1))) {
        server_port += 2;
    }

    check(server_port < 48900);
    ProcessSpec private_spec;
    private_spec.executable = self;
    private_spec.arguments = {"--broadcast-sdk", std::to_string(server_port)};
    private_spec.directory = stage;
    private_spec.output = stage / "private-server.log";
    auto private_server = ChildProcess::launch(private_spec);
    const auto private_ready = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < private_ready &&
           !private_server.owns_tcp_listener(server_port)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    check(private_server.alive() && private_server.owns_tcp_listener(server_port));
    // Synthetic high console ports avoid real emulator transports; production uses
    // android_owned_adb validation.
    const AndroidOwnedAdb private_binding{port, 35580, server_port, random_token()};
    write_private_json(stage / "fake-adb.json", {{"mode", "broadcast-private"},
                                                 {"private_server", std::to_string(server_port)}});
    android_candidate_start_multidisplay(child, self, stage, port, 30000, &private_binding,
                                         &private_server);
    private_server.terminate(1000);
    bool lost_rejected = false;
    try {
        android_candidate_start_multidisplay(child, self, stage, port, 30000, &private_binding,
                                             &private_server);
    } catch (...) {
        lost_rejected = true;
    }

    check(lost_rejected && child.alive() && tcp_port_free(server_port));
    const auto binding = android_owned_adb(5580, 35580, random_token());
    bool private_rejected = false;
    try {
        android_candidate_start_multidisplay(child, self, stage, port, 30000, &binding, nullptr);
    } catch (...) {
        private_rejected = true;
    }

    check(private_rejected && child.alive());
    rejected(child, 0);
    rejected(child, 30001);
    mode("broadcast-noack");
    rejected(child, 30000);
    mode("broadcast-failed");
    rejected(child, 30000);
    ChildProcess foreign;
    rejected(foreign, 30000);
    check(child.alive() && child.owns_tcp_listener(port));
    child.terminate(1000);
    check(!child.alive() && tcp_port_free(port) && tcp_port_free(port + 1));
    write_private_json(stage / "receipt.json",
                       {{"schema", 1},
                        {"synthetic_fixture", true},
                        {"real_guest", false},
                        {"old10000ms_delayed_broadcast", "RED-timeout"},
                        {"caller_remaining_delayed_broadcast", "GREEN-completion-ACK"},
                        {"negative_cases", 7},
                        {"private_route_verified", true},
                        {"private_server_loss_rejected", true},
                        {"owned_fake_adb_stopped", true},
                        {"owned_fake_sdk_stopped", true}});
    std::cout << stage.string() << '\n';
}

static void failure_collector_fixture(const std::filesystem::path &self,
                                      const std::filesystem::path &parent) {
    check(parent.is_absolute() && parent.lexically_normal() == parent &&
          std::filesystem::is_directory(parent));
    const auto root = parent / ("candidate-failure-fixture-" + random_token());
    ensure_private_directory(root);
    unsigned port = 49000;

    while (port < 49500 && (!tcp_port_free(port) || !tcp_port_free(port + 1))) {
        port += 2;
    }

    check(port < 49500);
    ProcessSpec sdk;
    sdk.executable = self;
    sdk.arguments = {"--failure-sdk", std::to_string(port)};
    sdk.directory = root;
    sdk.output = root / "fake-sdk.log";
    auto child = ChildProcess::launch(sdk);
    const auto ready = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < ready &&
           (!child.owns_tcp_listener(port) || !child.owns_tcp_listener(port + 1))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    check(child.alive() && child.owns_tcp_listener(port) && child.owns_tcp_listener(port + 1));
    const std::string nonce(32, 'b'), avd = "own-failure-fixture";

    for (const auto mode :
         {"valid", "wrong-nonce", "changed-boot", "foreign-avd", "slow", "audio-wrong-nonce",
          "audio-other-boot", "audio-command-failed", "logcat-overflow"}) {
        const auto stage = root / mode;
        ensure_private_directory(stage);
        write_private_json(stage / "fake-adb.json",
                           {{"mode", mode}, {"avd", avd}, {"nonce", nonce}});
        const auto original_deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1),
                   start = std::chrono::steady_clock::now();
        check(start > original_deadline);
        const auto report = capture_android_candidate_failure(child, self, stage, port, avd, nonce);
        const auto elapsed = std::chrono::steady_clock::now() - start;
        check(elapsed < std::chrono::seconds(6));

        if (std::string(mode) == "valid") {
            check(report.at("status") == "captured" &&
                  std::filesystem::is_regular_file(stage / "failure-startup-logcat.txt"));
            std::ifstream input(stage / "failure-startup-logcat.txt");
            std::string text((std::istreambuf_iterator<char>(input)), {});
            check(text.find("QGRuntime") != std::string::npos &&
                  text.find(nonce) == std::string::npos &&
                  text.find("secret-value") == std::string::npos);

            for (const auto *kind : {"audio", "notification"}) {
                check(report.at("supplementary").at(kind).at("status") == "captured");
                const auto evidence = stage / (std::string("failure-") + kind + ".txt");
                check(std::filesystem::is_regular_file(evidence) &&
                      std::filesystem::file_size(evidence) <= 128 * 1024);
                std::ifstream extra(evidence);
                const std::string body((std::istreambuf_iterator<char>(extra)), {});
                check(body.find(nonce) == std::string::npos &&
                      body.find(kind == std::string("audio")
                                        ? "USAGE_NOTIFICATION"
                                        : "NotificationChannel") != std::string::npos);
            }

            for (const auto *kind : {"home-resolve", "home-query", "package-preferred",
                                     "package-preferred-xml", "packages", "focus"}) {
                check(report.at("supplementary").at(kind).at("status") == "captured");
                check(std::filesystem::is_regular_file(stage /
                                                       (std::string("failure-") + kind + ".txt")));
            }

            check(report.at("maximum_total_bytes") == 1152 * 1024);
        } else if (std::string(mode) == "logcat-overflow") {
            check(report.at("status") == "partial" &&
                  report.at("supplementary").at("home-resolve").at("status") == "captured" &&
                  report.at("supplementary").at("startup-logcat").at("status") == "unavailable" &&
                  !std::filesystem::exists(stage / "failure-startup-logcat.txt"));
        } else if (std::string(mode).starts_with("audio-")) {
            check(report.at("status") == "captured" &&
                  report.at("supplementary").at("audio").at("status") == "unavailable" &&
                  report.at("supplementary").at("notification").at("status") == "captured" &&
                  !std::filesystem::exists(stage / "failure-audio.txt") &&
                  std::filesystem::is_regular_file(stage / "failure-startup-logcat.txt"));
        } else {
            check(report.at("status") == "unavailable" &&
                  !std::filesystem::exists(stage / "failure-startup-logcat.txt"));
        }
    }

    ChildProcess unowned;
    const auto foreign = root / "foreign-owner";
    ensure_private_directory(foreign);
    check(capture_android_candidate_failure(unowned, self, foreign, port, avd, nonce)
                          .at("status") == "unavailable" &&
          child.alive() && child.owns_tcp_listener(port) &&
          !std::filesystem::exists(foreign / "failure-startup-logcat.txt"));
    const auto lost = root / "lost-private-owner";
    ensure_private_directory(lost);
    write_private_json(lost / "fake-adb.json", {{"mode", "valid"}, {"avd", avd}, {"nonce", nonce}});
    const AndroidOwnedAdb binding{port, 35580, 48001, random_token()};
    ChildProcess absent_server;
    check(capture_android_candidate_failure(child, self, lost, port, avd, nonce, &binding,
                                            &absent_server)
                          .at("status") == "unavailable" &&
          !std::filesystem::exists(lost / "probe-call") && child.alive());
    child.terminate(1000);
    check(!child.alive() && tcp_port_free(port) && tcp_port_free(port + 1));
    const auto stopped = root / "stopped";
    ensure_private_directory(stopped);
    check(capture_android_candidate_failure(child, self, stopped, port, avd, nonce).at("status") ==
          "unavailable");
    write_private_json(root / "receipt.json", {{"schema", 1},
                                               {"synthetic_fixture", true},
                                               {"real_guest", false},
                                               {"cases", 12},
                                               {"supplementary_negative_cases", 3},
                                               {"shared_maximum_ms", 5000},
                                               {"expired_preparation_deadline", true},
                                               {"owned_fake_sdk_stopped", true}});
    std::cout << root.string() << '\n';
}

static void failure_sync_fixture(const std::filesystem::path &self,
                                 const std::filesystem::path &parent) {
    const auto root = parent / ("candidate-failure-sync-" + random_token());

    ensure_private_directory(root);
    unsigned port = 47000;

    while (port < 47500 && (!tcp_port_free(port) || !tcp_port_free(port + 1))) {
        port += 2;
    }

    check(port < 47500);
    unsigned server_port = 47500;

    while (server_port < 48000 &&
           (!tcp_port_free(server_port) || !tcp_port_free(server_port + 1))) {
        server_port += 2;
    }

    check(server_port < 48000);
    auto launch = [&](unsigned value, const char *name) {
        ProcessSpec spec;
        spec.executable = self;
        spec.arguments = {"--broadcast-sdk", std::to_string(value)};
        spec.directory = root;
        spec.output = root / name;

        return ChildProcess::launch(spec);
    };
    auto child = launch(port, "sdk.log"), server = launch(server_port, "private-adb.log");
    const auto ready = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < ready &&
           (!child.owns_tcp_listener(port) || !child.owns_tcp_listener(port + 1) ||
            !server.owns_tcp_listener(server_port))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    check(child.alive() && child.owns_tcp_listener(port) && child.owns_tcp_listener(port + 1) &&
          server.alive() && server.owns_tcp_listener(server_port));
    const std::string nonce(32, 'b'), avd = "owned-sync-fixture";
    const AndroidOwnedAdb binding{port, 35580, server_port, random_token()};
    unsigned cases = 0;

    for (const auto *mode : {"sync-valid", "sync-wrong-nonce", "sync-changed-boot", "sync-new-boot",
                             "sync-foreign-avd", "sync-nonzero", "sync-slow"}) {
        const auto stage = root / mode;
        ensure_private_directory(stage);
        write_private_json(stage / "fake-adb.json",
                           {{"mode", mode},
                            {"private_server", std::to_string(server_port)},
                            {"avd", avd},
                            {"nonce", nonce}});
        std::ofstream(stage / "dirty") << "synthetic dirty buffer";
        const Json original = {{"host_exit_code", 23},
                               {"native_status", 71},
                               {"message", "original ART compile failure"}};
        write_private_json(stage / "boot-image-process.json", original);
        const auto original_pin = sha256_file(stage / "boot-image-process.json");
        const auto expired = std::chrono::steady_clock::now() - std::chrono::seconds(1),
                   begin = std::chrono::steady_clock::now();
        check(begin > expired);
        const auto report = sync_android_candidate_failure(child, self, stage, port, avd, nonce,
                                                           &binding, &server);
        const auto elapsed = std::chrono::steady_clock::now() - begin;
        check(elapsed < std::chrono::seconds(11) && report.at("maximum_ms") == 10000 &&
              report.at("pid") == child.pid());

        if (std::string_view(mode) == "sync-valid") {
            check(report.at("status") == "synced" &&
                  report.at("boot_id") == "12345678-1234-1234-1234-123456789abc" &&
                  std::filesystem::exists(stage / "persisted") &&
                  !std::filesystem::exists(stage / "dirty"));
        } else {
            check(report.at("status") == "unavailable" &&
                  !std::filesystem::exists(stage / "persisted") &&
                  std::filesystem::exists(stage / "dirty"));
        }

        check(child.alive() && server.alive() &&
              sha256_file(stage / "boot-image-process.json") == original_pin);
        ++cases;
    }

    const auto stage = root / "sync-valid";
    ChildProcess foreign;

    for (const auto *absent : {"owner", "binding", "server"}) {
        const auto report = sync_android_candidate_failure(
                std::string_view(absent) == "owner" ? foreign : child, self, stage, port, avd,
                nonce, std::string_view(absent) == "binding" ? nullptr : &binding,
                std::string_view(absent) == "server" ? nullptr : &server);
        check(report.at("status") == "unavailable" && child.alive() && server.alive());
        ++cases;
    }

    server.terminate(1000);
    check(sync_android_candidate_failure(child, self, stage, port, avd, nonce, &binding, &server)
                          .at("status") == "unavailable" &&
          child.alive());
    ++cases;
    child.terminate(1000);
    check(tcp_port_free(port) && tcp_port_free(port + 1) && tcp_port_free(server_port));
    write_private_json(root / "receipt.json", {{"schema", 1},
                                               {"synthetic_fixture", true},
                                               {"real_guest", false},
                                               {"real_f2fs_verified", false},
                                               {"cases", cases},
                                               {"expired_preparation_deadline", true},
                                               {"private_route_verified", true},
                                               {"maximum_cleanup_ms", 10000},
                                               {"original_art_status_preserved", true},
                                               {"owned_fake_processes_stopped", true}});
    std::cout << root.string() << '\n';
}
#endif

static void owned_package_export_fixture() {
    const auto root = std::filesystem::current_path() / ".local/build/tmp" /
                      ("owned-package-export-" + random_token());

    ensure_private_directory(root);
    struct Cleanup {
        std::filesystem::path p;

        ~Cleanup() {
            std::error_code e;
            std::filesystem::remove_all(p, e);
        }
    } cleanup{root};
    const auto apk = root / "normally-built.apk";
    std::ofstream(apk) << "cold verified owned APK";
    const auto sha = sha256_file(apk);
    const Json profile = {{"id", "test-qinggan11"},
                          {"platform", "qinggan11"},
                          {"board", "8155"},
                          {"features", {{"system_upgrade", true}}},
                          {"wheel", {{"provider", "com.voyemu.input.wheel"}}},
                          {"install", Json::array({{{"artifact", "component:wheel-input"},
                                                    {"type", "apk"}}})}},
               artifacts = {{"component:wheel-input",
                             {{"file", apk.string()},
                              {"sha256", sha},
                              {"bytes", std::filesystem::file_size(apk)}}}};
    const Json installed = Json::array({{{"artifact", "component:wheel-input"},
                                         {"package", "com.voyemu.input.wheel"},
                                         {"target", "/data/app/owned/base.apk"},
                                         {"sha256", sha},
                                         {"mutable", false}}});
    auto camera_artifacts = artifacts;
    camera_artifacts["patched:Camera"] = camera_artifacts.at("component:wheel-input");
    auto camera_installed = installed;
    camera_installed[0]["artifact"] = "patched:Camera";
    camera_installed[0]["package"] = "com.qinggan.camera";
    const auto camera = export_android_candidate_camera_package(
            profile, camera_artifacts, camera_installed, root / "camera", 0);
    check(camera.at("package") == "com.qinggan.camera" &&
          sha256_file(root / "camera" / camera.at("file").get<std::string>()) == sha);
    auto bad_camera = camera_installed;
    bad_camera[0]["package"] = "foreign.package";
    bool camera_denied = false;
    try {
        export_android_candidate_camera_package(profile, camera_artifacts, bad_camera,
                                                root / "bad-camera", 0);
    } catch (...) {
        camera_denied = true;
    }

    check(camera_denied);
    auto denied = [&](const Json &selected, const Json &values) {
        bool failed = false;
        try {
            export_android_candidate_owned_package(profile, selected, values,
                                                   root / ("rejected-" + random_token()));
        } catch (...) {
            failed = true;
        }

        check(failed);
    };
    auto wrong = installed;
    wrong[0]["package"] = "foreign.package";
    denied(artifacts, wrong);
    wrong = installed;
    wrong[0]["sha256"] = std::string(64, '0');
    denied(artifacts, wrong);
    auto bad = artifacts;
    bad["component:wheel-input"]["file"] = (root / "missing.apk").string();
    denied(bad, installed);
    bad = artifacts;
    bad["component:wheel-input"]["sha256"] = std::string(64, '0');
    denied(bad, installed);
    bool reserve_rejected = false;
    try {
        export_android_candidate_owned_package(profile, artifacts, installed,
                                               root / "unavailable-reserve",
                                               std::numeric_limits<std::uint64_t>::max());
    } catch (...) {
        reserve_rejected = true;
    }

    check(reserve_rejected);
    const auto result = export_android_candidate_owned_package(profile, artifacts, installed,
                                                               root / "candidate", 0);
    check(result.at("file") == "android/packages/" + sha + ".apk" &&
          sha256_file(root / "candidate" / result.at("file").get<std::string>()) == sha &&
          std::filesystem::hard_link_count(apk) == 1);
    auto other = profile;
    other["platform"] = "passion";
    check(export_android_candidate_owned_package(other, Json::object(), Json::array(),
                                                 root / "untouched")
                  .empty() &&
          !std::filesystem::exists(root / "untouched"));
}

void verify_candidate_avb_console(const std::filesystem::path &log) {
    const std::string mismatch = "[  7.68] init: [libfs_avb]vbmeta digest mismatch\n",
                      failed = "[  7.69] init: [libfs_avb]VerifyVbmetaImages failed\n",
                      fatal = "[  7.70] init: InitFatalReboot: signal 6\n";

    std::ofstream(log) << mismatch << failed << fatal;
    machine_preparation_detail::CandidateAvbConsole console;
    console.offset = std::filesystem::file_size(log);
    check(!console.rejected(log));
    std::ofstream(log, std::ios::app)
            << failed << fatal << mismatch << failed << "[  0.0] Linux version 5.4\n"
            << fatal;
    check(!console.rejected(log));
    std::ofstream(log, std::ios::app) << mismatch << failed << fatal.substr(0, 21);
    check(!console.rejected(log));
    std::ofstream(log, std::ios::app) << fatal.substr(21);
    check(console.rejected(log));
}

void verify_retained_candidate_version_marker() {
    const auto root = std::filesystem::current_path() / ".local/build/tmp" /
                      ("candidate-retained-marker-" + random_token());

    ensure_private_directory(root / "base");
    struct Cleanup {
        std::filesystem::path p;

        ~Cleanup() {
            std::error_code e;
            std::filesystem::remove_all(p, e);
        }
    } cleanup{root};
    verify_candidate_avb_console(root / "test-console.log");
    const auto properties = root / "base/build.prop", marker = root / "version_num.cache";
    std::ofstream(properties) << "ro.build.version.incremental=9767327\n";
    std::map<std::string, std::string> pins;

    for (const auto *name : {"userdata-qemu.img.qcow2", "encryptionkey.img.qcow2",
                             "system.img.qcow2", "vendor.img.qcow2"}) {
        std::ofstream(root / name) << "retained installed APK and disk changes: " << name;
        pins[name] = sha256_file(root / name);
    }

    // The actual first candidate run supplied no marker and its SDK reset all four
    // copied overlays. This host fixture checks the shared prelaunch remedy without
    // invoking an SDK or claiming a second guest acceptance.
    check(!std::filesystem::exists(marker));
    prepare_android_avd_version_marker(root, properties, true);
    {
        std::ifstream input(marker);
        std::string version;
        std::getline(input, version);
        check(version == "9767327");
    }

    for (const auto &[name, sha] : pins) {
        check(sha256_file(root / name) == sha);
    }

    const auto marker_sha = sha256_file(marker);
    prepare_android_avd_version_marker(root, properties, true);
    check(sha256_file(marker) == marker_sha);

    for (const auto *invalid :
         {"ro.build.version.incremental=not-a-number\n",
          "ro.build.version.incremental=9767327\nro.build.version.incremental=2\n",
          "ro.build.version.incremental=-1\n", "ro.build.version.incremental=2147483648\n",
          "unrelated=true\n"}) {
        std::ofstream(properties, std::ios::trunc) << invalid;
        bool refused = false;
        try {
            prepare_android_avd_version_marker(root, properties, true);
        } catch (...) {
            refused = true;
        }

        check(refused && sha256_file(marker) == marker_sha);

        for (const auto &[name, sha] : pins) {
            check(sha256_file(root / name) == sha);
        }
    }

    std::ofstream(properties, std::ios::trunc) << "ro.build.version.incremental=9767327\r\n";
    prepare_android_avd_version_marker(root, properties, true);
    check(sha256_file(marker) == marker_sha);
    std::ofstream(properties, std::ios::trunc) << std::string(65537, 'x');
    bool oversized = false;
    try {
        prepare_android_avd_version_marker(root, properties, true);
    } catch (...) {
        oversized = true;
    }

    check(oversized && sha256_file(marker) == marker_sha);
    std::filesystem::remove(properties);
    bool refused = false;
    try {
        prepare_android_avd_version_marker(root, properties, true);
    } catch (...) {
        refused = true;
    }

    check(refused);
    prepare_android_avd_version_marker(root, properties, false);
    check(sha256_file(marker) == marker_sha);
}

static void qinggan09_home_checkpoint_fixture() {
    const std::vector<std::pair<std::string, int>> candidates = {
            {"com.qinggan.app.launcher/.activity.MainActivity", 0},
            {"com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity", 0}};
    const std::string resolver = "android/com.android.internal.app.ResolverActivity";
    std::string selected = resolver;
    bool flushed = false, invalidate_cold = false;
    unsigned establishes = 0, verifies = 0, boots = 0;
    auto establish = [&] {
        ++establishes;
        check(candidates.size() == 2 && candidates[0].second == 0 && candidates[1].second == 0);
        selected = candidates.front().first;
        flushed = true;
    };
    auto verify = [&] {
        ++verifies;

        if (selected != candidates.front().first) {
            throw std::runtime_error("HOME resolver differs");
        }
    };
    auto cold = [&] {
        ++boots;
        check(flushed);

        if (invalidate_cold) {
            selected = resolver;
        }
    };

    android_candidate_home_reboot_checkpoints(28, true, establish, verify, cold);
    check(establishes == 1 && verifies == 2 && boots == 1 && selected == candidates.front().first);
    selected = resolver;
    flushed = false;
    invalidate_cold = true;
    establishes = verifies = boots = 0;
    bool failed = false;
    try {
        android_candidate_home_reboot_checkpoints(28, true, establish, verify, cold);
    } catch (const std::exception &) {
        failed = true;
    }

    check(failed && establishes == 1 && verifies == 2 && boots == 1 && selected == resolver);
    selected = candidates.front().first;
    flushed = true;
    invalidate_cold = false;
    establishes = verifies = boots = 0;
    android_candidate_home_reboot_checkpoints(30, true, establish, verify, cold);
    check(establishes == 0 && verifies == 1 && boots == 1);
}

// The OEM HOME set of Free A9 6.0.3 as the Mac candidate queried it, with the Launcher placed
// by the profile: PackageManager clamps the HOME priorities of a non-privileged package to 0,
// so resolution then depends on the preferred activity, and ActivityManager clears the
// preferred activities of a HOME process without FLAG_SYSTEM when it crashes.
static void qinggan09_home_launcher_crash_fixture() {
    const auto root =
            std::filesystem::path(__FILE__).parent_path().parent_path().parent_path().parent_path();
    const auto profile = read_private_json(root / "profiles" / qinggan09_profile() / "profile.json",
                                           4 << 20);
    Json artifacts = Json::object();

    for (const auto &entry : profile.at("install")) {
        artifacts[entry.at("artifact").get<std::string>()] =
                entry.at("type") == "tree"
                        ? Json({{"directory", "/fixture/theme"}, {"files", Json::object()}})
                        : Json({{"file", "/fixture/file"}});
    }

    const auto plan = android_candidate_install_plan(profile, artifacts);
    const auto &configure = profile.at("configure");
    const auto launcher = configure.at("home").get<std::string>();
    bool system_launcher = false;

    for (const auto &entry : plan.at("system")) {
        if (entry.at("type") == "apk" && entry.at("package") == launcher) {
            system_launcher =
                    entry.at("target").get<std::string>().starts_with("/system/priv-app/");
        }
    }

    const auto &wanted = profile.at("verify").at("homePriorities");
    const std::string
            main = "com.qinggan.app.launcher/.activity.MainActivity",
            second =
                    "com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity",
            resolver = "android/com.android.internal.app.ResolverActivity";
    check(configure.at("homeActivity") == "com.qinggan.app.launcher/.activity.MainActivity");
    const auto priority = [&](const std::string &component) {
        return system_launcher ? wanted.at(*resolved_home_component(component, launcher)).get<int>()
                               : 0;
    };
    const std::vector<std::pair<std::string, int>> candidates = {
            {main, priority(main)},
            {second, priority(second)},
            {"com.qinggan.app.login/.RootActivity", 0},
            {"com.android.settings/.FallbackHome", -1000}};
    std::optional<std::string> preferred;
    // PackageManager.chooseBestActivity: a unique top priority wins, otherwise the preferred
    // activity of the full set, otherwise the chooser.
    const auto resolve = [&] {
        auto sorted = candidates;
        std::stable_sort(sorted.begin(), sorted.end(), [](const auto &a, const auto &b) {
            return a.second > b.second;
        });
        const auto chosen = sorted[0].second != sorted[1].second ? sorted[0].first
                            : preferred                          ? *preferred
                                                                 : resolver;

        return "priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n" +
               chosen;
    };
    const auto launcher_crash = [&] {
        if (!system_launcher) {
            preferred.reset();
        }
    };
    unsigned crashes = 0;
    auto establish = [&] {
        preferred = main;
        check(resolved_home_component(resolve(), launcher) ==
              resolved_home_component(main, launcher));
        // The crash after the HOME preference was flushed, as on the Mac candidate.
        launcher_crash();
        ++crashes;
    };
    auto verify = [&] {
        if (resolved_home_component(resolve(), launcher) !=
            resolved_home_component(main, launcher)) {
            throw std::runtime_error("HOME resolver differs");
        }
    };
    auto cold = [&] {
        launcher_crash();
        ++crashes;
    };

    android_candidate_home_reboot_checkpoints(android_candidate_api(profile), true, establish,
                                              verify, cold);
    check(system_launcher && crashes == 2);
    std::string declared;

    for (const auto &[component, value] : candidates) {
        if (component.starts_with(launcher + "/")) {
            declared += "  priority=" + std::to_string(value) +
                        " preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n  " +
                        component + "\n";
        }
    }

    check(android_candidate_home_priorities_ready(wanted, declared));
}

// A guest of API 30 that keeps HOME in two stores: PackageManager persists the preferred HOME
// activity, RoleManager the HOME role holder, each asynchronously. A reboot restores both from
// disk, and the first default role grant after it, which a package change starts, sets the
// preferred activity to the role holder. Each guest command is one tick of the guest clock.
struct HomeRoleGuest {
    std::string preferred = "com.android.launcher3", preferred_disk = "com.android.launcher3",
                role = "com.android.launcher3", role_disk = "com.android.launcher3";
    // Ticks after set-home-activity until the request reaches RoleManager (negative: never),
    // and ticks until RoleManager writes roles.xml after its holder changes (negative: never).
    int role_lag = 2, disk_lag = 4;
    bool add_effective = true;
    unsigned tick = 0, adds = 0;
    std::optional<unsigned> role_at, disk_at;
    std::string requested;

    void advance() {
        ++tick;

        if (role_at && tick >= *role_at) {
            role = requested;
            role_at.reset();

            if (disk_lag >= 0) {
                disk_at = tick + static_cast<unsigned>(disk_lag);
            }
        }

        if (disk_at && tick >= *disk_at) {
            role_disk = role;
            disk_at.reset();
        }

        preferred_disk = preferred;
    }

    std::string shell(const std::vector<std::string> &command) {
        advance();

        if (command.size() == 6 && command[2] == "set-home-activity") {
            preferred = command[5].substr(0, command[5].find('/'));
            requested = preferred;

            if (role_lag >= 0) {
                role_at = tick + static_cast<unsigned>(role_lag);
            }

            return "Success";
        }

        if (command == std::vector<std::string>{"dumpsys", "role"}) {
            return "ROLE MANAGER STATE (dumpsys role)\n  user_states={\n    user_id=0\n    "
                   "roles={\n      {\n        name=android.app.role.ASSISTANT\n      }\n      "
                   "{\n        name=android.app.role.HOME\n        holders=" +
                   role + "\n      }\n    }\n  }\n";
        }

        if (command.size() == 7 && command[1] == "role" && command[2] == "add-role-holder") {
            ++adds;

            if (add_effective) {
                requested = command[6];
                role_at = tick;
                advance();
            }

            return {};
        }

        if (command.size() == 2 && command[0] == "cat") {
            return "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<roles version=\"-1\" "
                   "packagesHash=\"00\">\n  <role name=\"android.app.role.ASSISTANT\" />\n  "
                   "<role name=\"android.app.role.HOME\">\n    <holder name=\"" +
                   role_disk + "\" />\n  </role>\n</roles>\n";
        }

        throw std::runtime_error("unexpected guest command");
    }

    // Reboot, then the first default role grant of the new boot.
    void reboot_and_grant() {
        preferred = preferred_disk;
        role = role_disk;
        role_at.reset();
        disk_at.reset();
        preferred = preferred_disk = role;
    }
};

static void home_role_fixture() {
    const std::string launcher = "com.voyah.os.carlauncher",
                      component = launcher + "/com.voyah.os.carlauncher.LauncherActivityMain";

    check(android_home_role_holders("        name=android.app.role.HOME\n        holders=a.b, c.d\n"
                                    "      }\n        name=android.app.role.SMS\n"
                                    "        holders=e.f\n") ==
                  std::vector<std::string>{"a.b", "c.d"} &&
          android_home_role_holders("        name=android.app.role.HOME\n      }\n").empty() &&
          android_home_role_holders("name=android.app.role.HOME_EXTRA\nholders=a.b\n").empty());
    check(android_persisted_home_role_holders("<role name=\"android.app.role.HOME\" />") ==
                  std::vector<std::string>{} &&
          !android_persisted_home_role_holders("<role name=\"android.app.role.SMS\" />") &&
          android_persisted_home_role_holders(
                  "<role name=\"android.app.role.HOME\">\n<holder name=\"a.b\" />\n</role>") ==
                  std::vector<std::string>{"a.b"});

    // Preparation as it runs: set HOME, wait for its holder, then for both persisted stores,
    // reboot.
    const auto prepare = [&](HomeRoleGuest &guest, unsigned api) {
        const auto shell = [&](const std::vector<std::string> &command) {
            return guest.shell(command);
        };
        const AndroidCandidatePoll poll = [&](const std::function<bool()> &ready, int timeout) {
            for (int i = 0; i < timeout / 250; ++i) {
                if (ready()) {
                    return true;
                }

                guest.advance();
            }

            return false;
        };
        shell({"cmd", "package", "set-home-activity", "--user", "0", component});
        android_candidate_home_role(api, launcher, shell, poll);
        check(poll(
                [&] {
                    return guest.preferred_disk == launcher;
                },
                120000));
        android_candidate_home_role_persisted(api, launcher, shell, poll);
        guest.reboot_and_grant();
    };
    const auto rejected = [&](HomeRoleGuest &guest, const std::string &text) {
        try {
            prepare(guest, 30);
        } catch (const std::exception &error) {
            return std::string(error.what()) == "HOME_NOT_PERSISTED: " + text;
        }

        return false;
    };

    // The KLG failure: RoleManager writes roles.xml long after PackageManager writes the preferred
    // activity, so a reboot right after the preferred activity keeps the old holder on disk.
    for (const int disk_lag : {0, 4, 40, 200}) {
        HomeRoleGuest guest;
        guest.disk_lag = disk_lag;
        prepare(guest, 30);
        check(guest.preferred == launcher && guest.role == launcher && guest.adds == 0);
    }

    // A set-home-activity request that never reaches RoleManager gets one idempotent add.
    HomeRoleGuest lost;
    lost.role_lag = -1;
    prepare(lost, 30);
    check(lost.preferred == launcher && lost.adds == 1);

    HomeRoleGuest refused;
    refused.role_lag = -1;
    refused.add_effective = false;
    check(rejected(refused, "HOME role holder differs: com.android.launcher3") &&
          refused.adds == 1);

    HomeRoleGuest unwritten;
    unwritten.disk_lag = -1;
    check(rejected(unwritten, "persisted HOME role holder differs: com.android.launcher3"));

    // API 28 has no RoleManager; the HOME steps send no guest command there.
    unsigned commands = 0;
    android_candidate_home_role(
            28, launcher,
            [&](const std::vector<std::string> &) {
                ++commands;

                return std::string{};
            },
            [](const std::function<bool()> &, int) {
                return false;
            });
    android_candidate_home_role_persisted(
            28, launcher,
            [&](const std::vector<std::string> &) {
                ++commands;

                return std::string{};
            },
            [](const std::function<bool()> &, int) {
                return false;
            });
    check(commands == 0);
}

static void configure_settings_fixture() {
    const Json settings = {{"global",
                            {{"device_name", "Voyemu"},
                             {"device_name_suffix", "NXP"},
                             {"policy_control", "immersive.status=*"}}},
                           {"secure", {{"default_input_method", "pkg/.IME"}}},
                           {"system", Json::object()}};
    const auto early = android_candidate_configure_settings(settings, false);

    check(early == std::vector<std::vector<std::string>>{
                           {"settings", "put", "global", "device_name", "Voyemu"},
                           {"settings", "put", "global", "device_name_suffix", "NXP"},
                           {"settings", "put", "global", "policy_control", "immersive.status=*"},
                           {"settings", "put", "secure", "default_input_method", "pkg/.IME"}});
    const auto late = android_candidate_configure_settings(settings, true);
    check(late == std::vector<std::vector<std::string>>{
                          {"settings", "put", "global", "device_name", "Voyemu"},
                          {"settings", "put", "global", "device_name_suffix", "NXP"}});
    check(android_candidate_configure_settings(Json::object(), false).empty() &&
          android_candidate_configure_settings(Json::object(), true).empty());

    for (const auto &bad :
         Json::array({Json{{"unknown", Json::object()}}, Json{{"global", Json::array()}},
                      Json{{"global", {{"value", 42}}}}})) {
        bool denied = false;
        try {
            android_candidate_configure_settings(bad, true);
        } catch (...) {
            denied = true;
        }

        check(denied);
    }
}

static void home_settings_fixture() {
    const Json config = {{"homeActivity", "pkg/.Main"}};
    const std::string query = "pkg/.Main\npkg/.Second\nlogin/.Root\nsettings/.Fallback\n";
    const std::string item =
            "<item name=\"pkg/.Main\" always=\"true\" set=\"4\"><set name=\"pkg/.Main\"/><set name=\"pkg/.Second\"/><set name=\"login/.Root\"/><set name=\"settings/.Fallback\"/><filter><action name=\"android.intent.action.MAIN\"/><cat name=\"android.intent.category.HOME\"/></filter></item>";
    auto xml = [&](std::string body) {
        return "<preferred-activities>" + body + "</preferred-activities>";
    };

    check(android_candidate_package_settings_flushed(xml(item), config, query));
    auto last = item;
    last.replace(last.find("always=\"true\""), 13, "always=\"false\"");
    check(!android_candidate_package_settings_flushed(xml(last), config, query));
    auto implicit = item;
    implicit.erase(implicit.find("always=\"true\""), 13);
    check(android_candidate_package_settings_flushed(xml(implicit), config, query));
    auto upper = item;
    upper.replace(upper.find("always=\"true\""), 13, "always=\"TRUE\"");
    check(android_candidate_package_settings_flushed(xml(upper), config, query));
    auto empty_always = item;
    empty_always.replace(empty_always.find("always=\"true\""), 13, "always=\"\"");
    check(!android_candidate_package_settings_flushed(xml(empty_always), config, query));
    check(!android_candidate_package_settings_flushed(xml(item), config, query + "new/.Home\n"));
    check(!android_candidate_package_settings_flushed(xml(item), config, std::string{}));
    auto changed = item;
    changed.replace(changed.find("settings/.Fallback"), 18, "settings/.Other");
    check(!android_candidate_package_settings_flushed(xml(changed), config, query));
}

int main(int argc, char **argv) {
    try {
        verify_failed_cold_check_retains_observation();

        if (argc == 2 && std::string_view(argv[1]) == "--cold-check-failure") {
            return 0;
        }

        verify_candidate_ui_retry();

        if (argc == 2 && std::string_view(argv[1]) == "--candidate-ui-retry") {
            return 0;
        }

        check(a9_policy_identity("platform", "mapping") == sha256_bytes("platformmapping") + "\n");
        check(a9_policy_identity("platform", "mapping") !=
              a9_policy_identity("platform", "other mapping"));
        {
            std::string policy(32, char(0));
            const auto word = [&](unsigned at, unsigned value) {
                for (unsigned i = 0; i < 4; ++i) {
                    policy[at + i] = static_cast<char>(value >> (i * 8));
                }
            };
            word(0, 0xf97cff8c);
            word(4, 8);
            policy.replace(8, 8, "SE Linux");
            word(16, 30);
            a9_policy_binary(policy, 30);
            bool symbols_rejected = false;
            try {
                a9_policy_required_names(policy);
            } catch (...) {
                symbols_rejected = true;
            }

            check(symbols_rejected);
            bool rejected = false;
            try {
                a9_policy_binary(policy, 31);
            } catch (...) {
                rejected = true;
            }

            check(rejected);
            rejected = false;
            try {
                a9_policy_binary(policy.substr(0, 16), 30);
            } catch (...) {
                rejected = true;
            }

            check(rejected);
            word(0, 0);
            rejected = false;
            try {
                a9_policy_binary(policy, 30);
            } catch (...) {
                rejected = true;
            }

            check(rejected);
        }

        if (argc == 2 && std::string_view(argv[1]) == "--nvram-seed") {
            const auto source_root = std::filesystem::path(__FILE__)
                                             .parent_path()
                                             .parent_path()
                                             .parent_path()
                                             .parent_path();

            // Each profile with an NVRAM seed installs it read-only into the system image, with
            // the mode, owner and label that the install and cold verifications read back; the
            // data partition receives no file from preparation.
            for (const auto *name :
                 {"free-09-chinese-20260106-6.0.3", "free-11-chinese-20250710-6.11.1",
                  "free-11-chinese-20260731-7.3.1"}) {
                const auto profile = read_private_json(
                        source_root / "profiles" / name / "profile.json", 4 << 20);
                unsigned seeds = 0;

                for (const auto &entry : profile.at("install")) {
                    check(!entry.value("target", std::string{}).starts_with("/data/"));

                    if (entry.at("artifact") == "files:nvram") {
                        check(entry.at("type") == "file" && !entry.value("mutable", false) &&
                              entry.at("target") == "/system/etc/nvram" &&
                              android_candidate_file_metadata(entry) ==
                                      "644 0:0 u:object_r:system_file:s0");
                        ++seeds;
                    }
                }

                check(seeds == 1);
            }

            check(android_candidate_file_metadata(
                          Json{{"mode", "0000"}, {"context", "u:object_r:x_file:s0"}}) ==
                  "0 0:0 u:object_r:x_file:s0");

            for (const auto &bad :
                 {Json{{"mode", "0660"}, {"context", "system_app_data_file"}},
                  Json{{"mode", "660"}, {"context", "u:object_r:system_app_data_file:s0"}},
                  Json{{"mode", "0660"}, {"uid", 70000}, {"context", "u:object_r:x:s0"}},
                  Json{{"mode", "0660"}}}) {
                bool rejected = false;
                try {
                    android_candidate_file_metadata(bad);
                } catch (...) {
                    rejected = true;
                }

                check(rejected);
            }

            // The push of the Mac candidate whose su could not create /data/nvram.
            const std::string refused =
                    "host command failed: adb -H 127.0.0.1 -P 25572 -s emulator-5572 push "
                    "/example/project/profiles/free-11-chinese-20250710-6.11.1/files/nvram.txt "
                    "/data/nvram: /example/project/profiles/free-11-chinese-20250710-6.11.1/"
                    "files/nvram.txt: 1 file pushed, 0 skipped. 0.4 MB/s (36 bytes in 0.000s)\n"
                    "adb: error: failed to copy '/example/project/profiles/"
                    "free-11-chinese-20250710-6.11.1/files/nvram.txt' to '/data/nvram': remote "
                    "couldn't create file: Permission denied\n";
            check(android_candidate_write_failure(
                          "/data/nvram", refused,
                          "uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0",
                          "u:object_r:system_data_root_file:s0 /data") ==
                  "guest file write failed: /data/nvram: remote couldn't create file: "
                  "Permission denied; diagnostic shell uid=0(root) gid=0(root) "
                  "groups=0(root) "
                  "context=u:r:su:s0; parent u:object_r:system_data_root_file:s0 "
                  "/data");
            check(android_candidate_write_failure("/data/nvram", "emulator exited", "w", "p") ==
                  "guest file write failed: /data/nvram: emulator exited; diagnostic "
                  "shell w; parent p");
            std::cout << "NVRAM seed metadata and failed write text passed\n";

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--cold-label-plan") {
            std::vector<std::pair<std::string, std::string>> files, devices;
            android_candidate_cold_label_plan("qinggan09-can-early-v1", files, devices);
            check(files.size() == 5 && files[0].first == "/system/bin/voyemu-early-inputs" &&
                  files[1].first == "/system/bin/voyemu-can-model" &&
                  files[2].first == "/system/etc/voyemu/can-model.fixture" &&
                  files[3].first == "/system/etc/voyemu/qg-settings-guest.db" &&
                  files[4].first == "/system/etc/voyemu/hybrid-nvram.img");
            check(files[0].second == "u:object_r:can_early_inputs_exec:s0" &&
                  files[1].second == "u:object_r:can_simulator_exec:s0" &&
                  files[2].second == "u:object_r:can_simulator_fixture:s0" &&
                  files[3].second == "u:object_r:can_early_input_file:s0" &&
                  files[4].second == "u:object_r:can_early_input_file:s0");
            check(devices.size() == 2 && devices[0].first == "/dev/cis_can" &&
                  devices[0].second == "u:object_r:can_device:s0" &&
                  devices[1].first == "/dev/block/vdh" &&
                  devices[1].second == "u:object_r:vdh_device:s0");
            files.clear();
            devices.clear();
            android_candidate_cold_label_plan("qinggan11-can-early-v1", files, devices);
            check(files.size() == 6 &&
                  files[0] == std::make_pair(std::string("/system/bin/voyemu-early-inputs"),
                                             std::string("u:object_r:can_early_inputs_exec:s0")) &&
                  files[4].first == "/system/etc/voyemu/hybrid-nvram.img" &&
                  files[5] == std::make_pair(std::string("/vendor/overlay"),
                                             std::string("u:object_r:vendor_overlay_file:s0")));
            check(devices.size() == 3 && devices[0].first == "/dev/cis_can_model" &&
                  devices[0].second == "u:object_r:can_simulator_device:s0" &&
                  devices[1].first == "/dev/socket/voyemu_can_model" &&
                  devices[1].second == "u:object_r:can_simulator_socket:s0" &&
                  devices[2].first == "/dev/socket/voyemu_can_observe" &&
                  devices[2].second == "u:object_r:can_simulator_observe_socket:s0");
            bool refused = false;
            try {
                android_candidate_cold_label_plan("a10-can-early-v1", files, devices);
            } catch (...) {
                refused = true;
            }

            check(refused);
            std::cout << "a9/a11 cold label plan and unknown-option rejection passed\n";

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--home-settings") {
            home_settings_fixture();

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--configure-settings") {
            configure_settings_fixture();

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--home-role") {
            home_role_fixture();

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--qinggan09-home-checkpoints") {
            qinggan09_home_checkpoint_fixture();
            qinggan09_home_launcher_crash_fixture();

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--system-native-libraries") {
            const auto source_root = std::filesystem::path(__FILE__)
                                             .parent_path()
                                             .parent_path()
                                             .parent_path()
                                             .parent_path();
            const auto original_profile = read_private_json(
                    source_root / "profiles/free-11-chinese-20260731-7.3.1/profile.json");
            check(android_candidate_overlay_scratch_bytes(original_profile, 512ULL << 20) >=
                  1280ULL << 20);
            check(android_candidate_api30_root_layout(original_profile));
            auto older = read_private_json(source_root /
                                           "profiles/free-11-chinese-20250710-6.11.1/profile.json");
            older["android"]["offline_selinux_labels"] = "qinggan11-can-early-v1";
            check(android_candidate_api30_root_layout(older));
            check(android_candidate_overlay_scratch_bytes(older, 512ULL << 20) >= 1280ULL << 20);
            const auto older_budget = android_candidate_build_budget(
                    older, 3ULL << 30, 512ULL << 20, "free-11-chinese-20250710-6.11.1");
            check(older_budget.reserve_bytes == 8ULL << 30 &&
                  older_budget.peak_extra_bytes ==
                          android_candidate_peak_extra_bytes(older, 3ULL << 30, 512ULL << 20,
                                                             "free-11-chinese-20250710-6.11.1"));
            auto wrong_sdk = older;
            wrong_sdk["android"]["sha256"] = "not-a-pin";
            bool sdk_rejected = false;
            try {
                android_candidate_api30_root_layout(wrong_sdk);
            } catch (...) {
                sdk_rejected = true;
            }

            check(sdk_rejected);
            auto wrong_older_labels = older;
            wrong_older_labels["android"]["offline_selinux_labels"] = "other";
            bool older_labels_rejected = false;
            try {
                android_candidate_overlay_scratch_bytes(wrong_older_labels, 512ULL << 20);
            } catch (...) {
                older_labels_rejected = true;
            }

            check(older_labels_rejected);
            auto foreign = original_profile;
            foreign["platform"] = "passion";
            check(!android_candidate_api30_root_layout(foreign));
            const auto russian_profile = read_private_json(
                    source_root / "profiles/free-11-russian-20260318-rc1/profile.json");
            check(android_candidate_api30_root_layout(russian_profile));
            check(android_candidate_overlay_scratch_bytes(russian_profile, 512ULL << 20) >=
                  1280ULL << 20);
            auto bad_labels = original_profile;
            bad_labels["android"]["offline_selinux_labels"] = "other";
            bool bad_label_rejected = false;
            try {
                android_candidate_api30_root_layout(bad_labels);
            } catch (...) {
                bad_label_rejected = true;
            }

            check(bad_label_rejected);
#ifdef __APPLE__
            const auto held_file =
                    std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                    ("root-layout-holder-" + random_token());
            {
                std::ofstream out(held_file);
                out << "fixture";
            }
            android_candidate_require_unused_root_image(held_file);
            const int held = ::open(held_file.c_str(), O_RDONLY);
            check(held >= 0);
            bool holder_rejected = false;
            try {
                android_candidate_require_unused_root_image(held_file);
            } catch (...) {
                holder_rejected = true;
            }

            ::close(held);
            check(holder_rejected);
            android_candidate_require_unused_root_image(held_file);
            std::filesystem::remove(held_file);
#endif

            const Json system = {{"artifact", "original:Navi"},
                                 {"type", "apk"},
                                 {"package", "com.baidu.naviauto"},
                                 {"target", "/system/priv-app/dueros/Navi.apk"}};
            const std::vector<ZipEntry> inventory = {{"classes.dex", 16, false},
                                                     {"lib/arm64-v8a/libxcrash.so", 76176, false},
                                                     {"lib/armeabi-v7a/libother.so", 32, false}};
            auto selected = android_candidate_system_native_libraries(
                    system, inventory, "A: android:extractNativeLibs(0x010104ea)=true\n");
            check(selected.size() == 1 && selected[0].name == "lib/arm64-v8a/libxcrash.so" &&
                  selected[0].bytes == 76176);
            check(android_candidate_system_native_libraries(system, inventory, "").size() == 1);
            auto engine = inventory;
            engine[1] = {"lib/arm64-v8a/libBaiduMapAutoEngine.so", 41362008, false};
            check(android_candidate_system_native_libraries(system, engine, "").size() == 1);

            check(android_candidate_system_native_libraries(
                          system, inventory, "A: android:extractNativeLibs(0x010104ea)=false\n")
                          .empty());
            auto data = system;
            data.erase("target");
            check(android_candidate_system_native_libraries(data, inventory, "").empty());
            // An x86_64 guest takes the libraries of its own ABIs; ARM code stays in the APK.
            check(android_guest_native_abis("x86_64") ==
                          std::vector<std::string>{"x86_64", "x86"} &&
                  android_guest_native_abis("arm64-v8a") == std::vector<std::string>{"arm64-v8a"});
            const std::vector<ZipEntry> mixed = {{"lib/arm64-v8a/libpag.so", 64, false},
                                                 {"lib/x86_64/libmain.so", 48, false},
                                                 {"lib/x86/libmain.so", 40, false}};
            const auto x86_64 = android_candidate_system_native_libraries(system, mixed, "",
                                                                          "x86_64");
            check(x86_64.size() == 1 && x86_64[0].name == "lib/x86_64/libmain.so" &&
                  android_candidate_system_native_libraries(system, mixed, "", "x86").size() == 1);
            // A merged file keeps the guest bytes and adds only the lines it lacks.
            check(android_candidate_merged_lines("a b\nc d\n", "c d\nusb rule\n") ==
                          "a b\nc d\nusb rule\n" &&
                  android_candidate_merged_lines("a b", "usb rule\n") == "a b\nusb rule\n" &&
                  android_candidate_merged_lines("a b\nusb rule\n", "usb rule\n") ==
                          "a b\nusb rule\n");
            auto rejects = [&](const Json &entry, const std::vector<ZipEntry> &files,
                               std::string_view xml) {
                bool refused = false;
                try {
                    android_candidate_system_native_libraries(entry, files, xml);
                } catch (...) {
                    refused = true;
                }

                check(refused);
            };
            auto bad = system;
            bad["target"] = "/data/app/unsafe.apk";
            rejects(bad, inventory, "");

            for (const auto *name :
                 {"lib/arm64-v8a/../escape.so", "lib/arm64-v8a/nested/libbad.so"}) {
                auto files = inventory;
                files[1].name = name;
                rejects(system, files, "");
            }

            auto files = inventory;
            files[1].bytes = 0;
            rejects(system, files, "");
            files = inventory;
            files[1].bytes = 65ULL << 20;
            rejects(system, files, "");
            files = inventory;
            files.push_back(files[1]);
            rejects(system, files, "");
            files = inventory;
            files.push_back({"lib/arm64-v8a/libXcrash.so", 76176, false});
            rejects(system, files, "");
            rejects(system, inventory,
                    "A: android:extractNativeLibs(0x010104ea)=true\nA: android:extractNativeLibs(0x010104ea)=false\n");
            std::cout
                    << "System native extraction/default, direct APK mmap, A9 PackageManager preservation and seven inverse guards passed\n";

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--retained-marker-fixture") {
            verify_retained_candidate_version_marker();

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--storage-only") {
            verify_candidate_storage();
            std::cout
                    << "A9 exact identity, budget boundaries and retained legacy/profile floors passed\n";

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--owned-package-export-fixture") {
            owned_package_export_fixture();
            std::cout
                    << "cold owned APK export, wrong package/missing/tamper rejection and unrelated profile preservation passed\n";

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--cancel-entry-fixture") {
            verify_candidate_cancellation();
            std::cout
                    << "SIGTERM/SIGINT cancelled before production dispatch; no VM/tool executed\n";

            return 0;
        }

        if (argc == 4 && std::string_view(argv[1]) == "--adb-route-spec") {
            const auto root = std::filesystem::canonical(argv[2]),
                       directory = std::filesystem::absolute(argv[3]);
            check(directory.lexically_normal() == directory &&
                  directory.lexically_relative(root).generic_string().starts_with(".local/"));
            ensure_private_directory(directory);
            const auto binding = android_owned_adb(5580, 35580, random_token(), 25580);
            const auto adb = root / ".local/toolchains/native-sdk/platform-tools/adb";
            write_private_json(directory / "route.json",
                               {{"schema", 1},
                                {"owner", binding.owner},
                                {"console_port", binding.console},
                                {"grpc_port", binding.grpc},
                                {"server_port", binding.server},
                                {"environment", candidate_route_environment(binding)},
                                {"server_arguments", android_owned_adb_server_arguments(binding)},
                                {"adb", adb.string()},
                                {"adb_sha256", sha256_file(adb)}});
            std::cout << "private owned ADB route prepared; no process launched\n";

            return 0;
        }

        if (argc == 3 && (std::string_view(argv[1]) == "--adb-route-inheritance-fixture" ||
                          std::string_view(argv[1]) == "--adb-route-leaf-check")) {
            const auto spec = candidate_route(argv[2]);
            check_candidate_route_environment(spec);

            if (std::string_view(argv[1]) == "--adb-route-inheritance-fixture") {
                ProcessSpec child;
                child.executable = std::filesystem::canonical(argv[0]);
                child.arguments = {"--adb-route-leaf-check", argv[2]};
                child.directory = std::filesystem::path(argv[2]).parent_path();
                child.environment = {{"TMPDIR", child.directory.string()}};
                const auto result = execute(child, 5000, 16384);
                check(!result.timed_out && result.exit_code == 0);
            }

            std::cout
                    << "owned ADB environment inherited without global fallback; no ADB client executed\n";

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--adb-route-cancel-wait-fixture") {
            check_candidate_route_environment(candidate_route(argv[2]));
            std::signal(SIGTERM, cancel_candidate);
            std::signal(SIGINT, cancel_candidate);
            write_private_json(std::filesystem::path(argv[2]).parent_path() /
                                       "cancel-wait-ready.json",
                               {{"schema", 1}, {"armed", true}});
            const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);

            while (!candidate_cancelled && std::chrono::steady_clock::now() < end) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            check(candidate_cancelled != 0);
            bool refused = false;
            try {
                run_owned_candidate("relative", AndroidCandidateRequest{}, "relative");
            } catch (const std::exception &error) {
                refused = std::string(error.what()) ==
                          "test-entry candidate cancelled before dispatch";
            }

            check(refused);
            std::cout << "server loss cancelled before production dispatch; no VM/tool executed\n";

            return 0;
        }

#ifndef _WIN32
        if (argc == 3 && std::string_view(argv[1]) == "--broadcast-sdk") {
            return failure_sdk_child(static_cast<unsigned>(std::stoul(argv[2])), 45);
        }

        if (argc == 3 && std::string_view(argv[1]) == "--root-transition-fixture") {
            root_transition_fixture(std::filesystem::canonical(argv[0]),
                                    std::filesystem::canonical(argv[2]));

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--broadcast-fixture") {
            broadcast_fixture(std::filesystem::canonical(argv[0]), std::filesystem::path(argv[2]));

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--failure-sdk") {
            return failure_sdk_child(static_cast<unsigned>(std::stoul(argv[2])));
        }

        if (argc >= 2 && (std::string_view(argv[1]) == "-s" || std::string_view(argv[1]) == "-H")) {
            return failure_adb_child(argc, argv);
        }

        if (argc == 3 && std::string_view(argv[1]) == "--failure-sync-fixture") {
            failure_sync_fixture(std::filesystem::canonical(argv[0]),
                                 std::filesystem::canonical(argv[2]));

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--failure-collector-fixture") {
            failure_collector_fixture(std::filesystem::canonical(argv[0]),
                                      std::filesystem::path(argv[2]));

            return 0;
        }
#endif

        {
            const std::string frame(32, 'a'), nonce(32, 'b'),
                    boot = "12345678-1234-1234-1234-123456789abc",
                    marker = "VOYEMU_STARTUP_" + frame;
            auto captured = [&](std::string first, std::string last, std::string n,
                                std::string text) {
                return ProcessResult{0,
                                     marker + ":b1:" + first + "\n" + marker + ":n1:" + n + "\n" +
                                             marker + ":body\n" + text + "\n" + marker +
                                             ":exit:0\n" + marker + ":n2:" + n + "\n" + marker +
                                             ":b2:" + last + "\n" + marker + ":utc:1700000000\n",
                                     false};
            };
            const auto report = android_candidate_failure_log_frame(
                    captured(boot, boot, nonce, "token=secret-value " + nonce), frame, nonce,
                    {nonce});
            check(report.at("status") == "captured" && report.at("boot_id") == boot &&
                  report.at("text").get<std::string>().find(nonce) == std::string::npos &&
                  report.at("text").get<std::string>().find("secret-value") == std::string::npos);

            for (const auto value :
                 {captured(boot, "12345678-1234-1234-1234-123456789abd", nonce, "x"),
                  captured(boot, boot, std::string(32, 'c'), "x"),
                  ProcessResult{0, "partial", false}, ProcessResult{0, "", true},
                  captured(boot, boot, nonce, std::string(512 * 1024, 'x'))}) {
                bool denied = false;
                try {
                    android_candidate_failure_log_frame(value, frame, nonce, {nonce});
                } catch (...) {
                    denied = true;
                }

                check(denied);
            }
        }
        {
            const Json wanted = Json::array({"qg.canbus", "qg.setting", "qg.display_manager",
                                             "multidisplay", "multiwindow"});
            const std::string live =
                    "Found 5 services:\n131\tqg.canbus: [com.qinggan.canbus.ICanBusService]\n132\tqg.setting: []\n133\tqg.display_manager: [com.qinggan.navi.IDisplayManagerService]\n134\tmultidisplay: [com.qinggan.multidisplay.IMultiDisplayService]\n135\tmultiwindow: [com.qinggan.system.IMultiWindowService]\n";
            auto report = android_candidate_binder_probe(wanted, {0, live, false});
            check(report.at("ready") == true && report.at("missing").empty() &&
                  report.at("output") == live && report.at("exit_code") == 0 &&
                  report.at("timed_out") == false);
            auto missing = live;
            missing.replace(missing.find("qg.setting:"), 11, "qgXsetting:");
            report = android_candidate_binder_probe(wanted, {0, missing, false});
            check(report.at("ready") == false &&
                  report.at("missing") == Json::array({"qg.setting"}));
            check(android_candidate_binder_probe(wanted, {7, live, false}).at("ready") == false &&
                  android_candidate_binder_probe(wanted, {0, live, true}).at("ready") == false);
            report = android_candidate_binder_probe(wanted, {-1, {}, true});
            check(report.at("missing") == wanted && report.at("exit_code") == -1 &&
                  report.at("timed_out") == true);
            report = android_candidate_binder_probe(Json::array(),
                                                    {0, std::string(512 * 1024 + 1, 'x'), false});
            check(report.at("output").get<std::string>().size() == 512 * 1024 &&
                  report.at("output_truncated") == true);
        }
        check(android_candidate_cpu_config(Json::object()).empty());
        check(android_candidate_cpu_config(Json{{"emulator", {{"cores", 4}}}}) ==
              "hw.cpu.ncore=4\n");

        for (const auto &bad : Json::array({0, 9, -1, 4.5, "4", nullptr, true})) {
            bool denied = false;
            try {
                android_candidate_cpu_config(Json{{"emulator", {{"cores", bad}}}});
            } catch (...) {
                denied = true;
            }

            check(denied);
        }

        const auto sdk_root = std::filesystem::absolute("candidate-sdk").lexically_normal();
        const auto win_program = android_sdk_program(sdk_root, true),
                   mac_program = android_sdk_program(sdk_root, false);
        check(win_program == sdk_root / "emulator/qemu/windows-x86_64/qemu-system-aarch64.exe" &&
              win_program.parent_path().parent_path() != sdk_root);
        check(mac_program == sdk_root / "emulator/emulator" &&
              mac_program.parent_path().parent_path() == sdk_root);

        for (const bool windows : {false, true}) {
            const auto environment = android_candidate_sdk_environment(sdk_root, windows,
                                                                       "inherited-PATH");
            check(environment.at("ANDROID_HOME") == sdk_root.string() &&
                  environment.at("ANDROID_SDK_ROOT") == sdk_root.string());

            if (windows) {
                check(environment.at("ANDROID_EMULATOR_LAUNCHER_DIR") ==
                      (sdk_root / "emulator").string());
                check(environment.at("PATH") ==
                      android_sdk_environment(sdk_root, true, "inherited-PATH").at("PATH"));
            } else {
                check(environment.size() == 2);
            }
        }

        for (const auto &wrong : {std::filesystem::path{}, std::filesystem::path("relative-sdk"),
                                  sdk_root / ".." / "different"}) {
            bool denied = false;
            try {
                android_candidate_sdk_environment(wrong, true, "");
            } catch (...) {
                denied = true;
            }

            check(denied);
        }

        check(android_candidate_vehicle_observer_policy(Json{{"id", qinggan09_profile()}}) ==
              Json({{"supported", true}}));
        Json passion = {
                {"id", "test-passion"},
                {"platform", "passion"},
                {"board", "8155"},
                {"status", "incomplete"},
                {"android",
                 {{"package", "system-images;android-30;default;arm64-v8a"},
                  {"revision", "1"},
                  {"url",
                   "https://dl.google.com/android/repository/sys-img/android/arm64-v8a-30_r02.zip"},
                  {"sha256", "cb50112cf2dd234a71e2a29b0241c23dbb37dd5fc3156c68cc9c49d0f58ad304"}}}};
        check(android_candidate_overlay_scratch_bytes(Json::object(), 1) == 0 &&
              android_candidate_overlay_scratch_bytes(passion, 1) == 0);
        auto passion_media = passion;

        for (const auto *name : {"LY_Camera", "LY_Video", "LY_AVM"}) {
            passion_media["original"][name] = Json::object();
        }

        check(android_candidate_overlay_scratch_bytes(passion_media, 1ULL << 30) == 1792ULL << 20);
        auto ready_media = passion_media;
        ready_media["status"] = "ready";
        check(android_candidate_overlay_scratch_bytes(ready_media, 1ULL << 30) == 1792ULL << 20);
        auto other_media = passion_media;
        other_media["platform"] = "qinggan09";
        check(android_candidate_overlay_scratch_bytes(other_media, 1ULL << 30) == 0);

        for (unsigned mode = 0; mode < 5; ++mode) {
            auto bad = passion_media;
            std::uint64_t payload = 1ULL << 30;

            if (mode == 0) {
                bad["original"].erase("LY_AVM");
            }

            if (mode == 1) {
                bad["android"]["package"] = "system-images;android-28;default;arm64-v8a";
            }

            if (mode == 2) {
                payload = 0;
            }

            if (mode == 3) {
                payload = UINT64_MAX;
            }

            if (mode == 4) {
                payload = 2ULL << 30;
            }

            bool denied = false;
            try {
                android_candidate_overlay_scratch_bytes(bad, payload);
            } catch (...) {
                denied = true;
            }

            check(denied);
        }

        passion["displays"] = Json::array({Json{{"role", "primary"},
                                                {"guest", "android"},
                                                {"width", 1280},
                                                {"height", 720},
                                                {"density", 160}},
                                           Json{{"role", "secondary"},
                                                {"guest", "android"},
                                                {"width", 1280},
                                                {"height", 720},
                                                {"density", 160}}});
        passion["original"] = {
                {"LY_Launcher",
                 {{"sha256", "4032f14c0fc49fd52514737309d2af67c9d4ff9340dd534874f46cbe2e748c00"}}}};
        const std::string
                passion_display =
                        "Display 17:\n mPrimaryDisplayDevice=Emulator2D\n real 1280 x 720, state ON\n",
                passion_window =
                        "Window #0 Window{abc u0 com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond}:\n mDisplayId=17 isOnScreen=true\n";
        check(android_candidate_secondary_provider(passion, passion_display) == 17);
        check(!android_candidate_secondary_provider(passion, ""));
        check(!android_candidate_secondary_display_ready(passion, passion_display, ""));

        for (const auto bad :
             {std::string("Display 1:\n mPrimaryDisplayDevice=Other\n real 1280 x 720, state ON\n"),
              std::string(
                      "Display 1:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state ON\n"),
              std::string(
                      "Display 1:\n mPrimaryDisplayDevice=Emulator2D\n real 1280 x 720, state OFF\n"),
              passion_display + passion_display}) {
            check(!android_candidate_secondary_provider(passion, bad));
        }

        check(android_candidate_secondary_display_ready(passion, passion_display, passion_window) ==
              17);
        check(!android_candidate_secondary_display_ready(
                passion,
                passion_display +
                        "Display 19:\n mPrimaryDisplayDevice=Emulator2D\n real 1280 x 720, state ON\n",
                passion_window));

        for (const auto bad :
             {std::string("Window #0 unrelated\n mDisplayId=17 isOnScreen=true\n"),
              std::string(
                      "Window #0 Window{abc u0 com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond}:\n mDisplayId=2 isOnScreen=true\n"),
              std::string(
                      "Window #0 Window{abc u0 com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond}:\n mDisplayId=17 isOnScreen=false\n")}) {
            check(!android_candidate_secondary_display_ready(passion, passion_display, bad));
        }

        check(!android_candidate_secondary_display_ready(
                passion,
                "Display 17:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state ON\n",
                passion_window));
        check(!android_candidate_secondary_display_ready(
                passion,
                "Display 17:\n mPrimaryDisplayDevice=Emulator2D\n real 1280 x 720, state OFF\n",
                passion_window));
        check(!android_candidate_secondary_display_ready(Json{{"id", qinggan09_profile()}},
                                                         passion_display, passion_window));
        auto qinggan11_731 = passion;
        qinggan11_731["id"] = "test-qinggan11";
        qinggan11_731["platform"] = "qinggan11";
        qinggan11_731["original"] = {
                {"Launcher",
                 {{"sha256", "b3287150827e7fa51072bcbcba257539101cda8433c5f9d3a95f4ca905abd567"}}}};
        qinggan11_731["displays"] = Json::array({Json{{"role", "primary"},
                                                      {"guest", "android"},
                                                      {"width", 1920},
                                                      {"height", 720},
                                                      {"density", 160}},
                                                 Json{{"role", "secondary"},
                                                      {"guest", "android"},
                                                      {"width", 1920},
                                                      {"height", 720},
                                                      {"density", 160}}});
        const std::string
                free_display =
                        "Display 19:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1920 x 720, state ON\n",
                free_window =
                        "Window #0 Window{abc u0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity}:\n mDisplayId=19 isOnScreen=true\n";
        check(android_candidate_secondary_display_ready(qinggan11_731, free_display, free_window) ==
              19);
        auto qinggan11_611 = qinggan11_731;
        qinggan11_611["id"] = "test-qinggan11-older";
        qinggan11_611["original"]["Launcher"]["sha256"] =
                "48665cf9d6bb50b49b3aa0b1aa73bdb0ac5d9d7071240c46c7f13d07d4114d7e";
        check(android_candidate_secondary_provider(qinggan11_611, free_display) == 19 &&
              android_candidate_secondary_display_ready(qinggan11_611, free_display, free_window) ==
                      19);
        check(android_candidate_capture_arguments(qinggan11_611, true, 5572) ==
              std::vector<std::string>{"-grpc", "35572", "-grpc-use-token"});
        // The rear provider display has its own size and never counts as the secondary one.
        auto qinggan11_rear = qinggan11_611;
        qinggan11_rear["displays"].push_back({{"role", "rear"},
                                              {"guest", "android"},
                                              {"width", 1902},
                                              {"height", 540},
                                              {"density", 160}});
        check(android_candidate_secondary_provider(
                      qinggan11_rear,
                      free_display + "Display 20:\n mPrimaryDisplayDevice=Emulator 2D Display\n "
                                     "real 1902 x 540, state ON\n") == 19 &&
              android_candidate_capture_arguments(qinggan11_rear, true, 5572) ==
                      std::vector<std::string>{"-grpc", "35572", "-grpc-use-token"});

        // profile.json alone pins the Android image; preparation verifies it against
        // android.clean_base, and capture admits only the supported image package.
        for (unsigned mode = 0; mode < 3; ++mode) {
            auto bad = qinggan11_611;

            if (mode == 0) {
                bad["original"]["Launcher"]["sha256"] = std::string(64, '0');
            }

            if (mode == 1) {
                bad["android"]["package"] = "system-images;android-28;default;arm64-v8a";
            }

            if (mode == 2) {
                bad["android"]["sha256"] = "not-a-pin";
            }

            bool denied = false;
            try {
                android_candidate_capture_arguments(bad, true, 5572);
            } catch (...) {
                denied = true;
            }

            check(denied);
        }

        {
            auto ready = qinggan11_731;
            ready["status"] = "ready";
            check(android_candidate_secondary_provider(ready, free_display) == 19 &&
                  android_candidate_secondary_display_ready(ready, free_display, free_window) ==
                          19);
        }
        check(android_candidate_secondary_display_ready(
                      passion,
                      "Display 17:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1280 x 720, state ON\n",
                      passion_window) == 17);
        check(android_candidate_secondary_display_ready(
                      qinggan11_731,
                      "Display 19:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state ON\n",
                      free_window) == 19);

        for (const auto bad :
             {std::string(
                      "Display 19:\n mPrimaryDisplayDevice=Emulator 2D Display Extra\n real 1920 x 720, state ON\n"),
              std::string(
                      "Display 19:\n mPrimaryDisplayDevice=FakeEmulator2D\n real 1920 x 720, state ON\n"),
              std::string(
                      "Display 19:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1280 x 720, state ON\n"),
              std::string(
                      "Display 19:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1920 x 720, state OFF\n"),
              free_display +
                      "Display 20:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state ON\n"}) {
            check(!android_candidate_secondary_display_ready(qinggan11_731, bad, free_window));
        }

        check(!android_candidate_secondary_display_ready(
                qinggan11_731, free_display,
                "Window #0 Window{abc u0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity}:\n mDisplayId=2 isOnScreen=true\n"));
        const std::string actual_pending_window =
                "Window #0 Window{fixture u0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity}:\n mDisplayId=19\n Surface: shown=false\n mDrawState=DRAW_PENDING\n isOnScreen=false\n isVisible=true\n";
        check(!android_candidate_secondary_display_ready(qinggan11_731, free_display,
                                                         actual_pending_window));
        const std::string actual_drawn_window =
                free_window + " Surface: shown=true\n mDrawState=HAS_DRAWN\n isVisible=true\n";
        check(android_candidate_secondary_display_ready(qinggan11_731, free_display,
                                                        actual_drawn_window) == 19);

        for (const auto &fields : {" mDrawState=DRAW_PENDING\n", " Surface: shown=false\n"}) {
            check(!android_candidate_secondary_display_ready(qinggan11_731, free_display,
                                                             free_window + fields));
        }

        const auto crash_window = [](const std::string &package, unsigned display) {
            return "  Window #1 Window{fixture u0 Application Error: " + package +
                   "}:\n mDisplayId=" + std::to_string(display) +
                   "\n mAttrs={ty=SYSTEM_ERROR}\n isOnScreen=true\n isVisible=true\n";
        };
        check(!android_candidate_secondary_display_ready(
                qinggan11_731, free_display,
                actual_drawn_window + crash_window("com.qinggan.app.launcher", 19)));
        check(android_candidate_secondary_display_ready(
                      qinggan11_731, free_display,
                      actual_drawn_window + crash_window("com.qinggan.app.launcher", 20)) == 19);
        check(android_candidate_secondary_display_ready(
                      qinggan11_731, free_display,
                      actual_drawn_window + crash_window("com.qinggan.app.launcher.other", 19)) ==
              19);
        check(android_candidate_secondary_display_ready(Json{{"id", qinggan09_profile()}},
                                                        free_display, free_window) == 19);
        const auto unsupported = android_candidate_vehicle_observer_policy(passion);
        check(unsupported.at("status") == "unsupported" && unsupported.at("supported") == false &&
              !unsupported.contains("passed") && unsupported.contains("reason"));
        {
            const auto observed =
                    Json::array({Json{{"id", "boot"}, {"passed", true}}, unsupported});
            const auto original = observed;
            validate_android_candidate_checks(passion, observed);
            check(observed == original && !observed.back().contains("passed"));
            auto reject_checks = [&](const Json &profile, const Json &rows,
                                     const std::string &context) {
                bool denied = false;
                try {
                    validate_android_candidate_checks(profile, rows);
                } catch (const std::exception &error) {
                    const std::string message = error.what();
                    denied = message.starts_with("ANDROID_CANDIDATE_CHECKS:") &&
                             message.find(context) != std::string::npos;
                }

                check(denied);
            };

            for (unsigned mode = 0; mode < 13; ++mode) {
                auto bad = observed;

                if (mode == 0) {
                    bad[0].erase("passed");
                }

                if (mode == 1) {
                    bad[0]["passed"] = false;
                }

                if (mode == 2) {
                    bad[0]["passed"] = "true";
                }

                if (mode == 3) {
                    bad[1]["reason"] = "invented reason";
                }

                if (mode == 4) {
                    bad.push_back(unsupported);
                }

                if (mode == 5) {
                    bad[1]["id"] = "unknown-capability";
                }

                if (mode == 6) {
                    bad[1]["passed"] = true;
                }

                if (mode == 7) {
                    bad[1]["supported"] = "false";
                }

                if (mode == 8) {
                    bad[1].erase("supported");
                }

                if (mode == 9) {
                    bad[0].erase("id");
                }

                if (mode == 10) {
                    bad[0]["id"] = 5;
                }

                if (mode == 11) {
                    bad[0]["passed"] = 1;
                }

                if (mode == 12) {
                    bad[0]["supported"] = false;
                }

                reject_checks(passion, bad, "checks[");
            }

            reject_checks(passion, Json::array({observed[0]}), "declaration missing");
            reject_checks(passion, Json(), "bounded");
            reject_checks(passion, Json::object(), "bounded");
            reject_checks(Json{{"id", qinggan09_profile()}}, observed, "vehicle-observer");
            validate_android_candidate_checks(Json{{"id", qinggan09_profile()}},
                                              Json::array({observed[0]}));
        }
        auto wrong_api = passion;
        wrong_api["android"]["package"] = "system-images;android-28;default;arm64-v8a";
        bool wrong_denied = false;
        try {
            android_candidate_vehicle_observer_policy(wrong_api);
        } catch (...) {
            wrong_denied = true;
        }

        check(wrong_denied);
        check(!AndroidCandidateRequest{}.capture_frames &&
              android_candidate_capture_arguments(Json::object(), false, 0).empty());
        {
            auto capture_nxp = read_private_json(
                    std::filesystem::path(__FILE__)
                                    .parent_path()
                                    .parent_path()
                                    .parent_path()
                                    .parent_path() /
                            "profiles/free-09-chinese-20221230-nxp-rc45/profile.json",
                    1 << 20);
            const auto nxp_start = android_candidate_start_commands(capture_nxp);
            check(std::find(nxp_start.begin(), nxp_start.end(),
                            std::vector<std::string>{"am", "start-service", "-n",
                                                     "com.voyemu.oem/.RegistrationService"}) !=
                  nxp_start.end());
            check(!android_candidate_vehicle_observer_policy(capture_nxp)
                           .at("supported")
                           .get<bool>());
            check(android_candidate_capture_arguments(capture_nxp, true, 5580) ==
                  std::vector<std::string>{"-grpc", "35580", "-grpc-use-token"});

            for (unsigned variant = 0; variant < 3; ++variant) {
                auto bad = capture_nxp;

                if (variant == 0) {
                    bad["board"] = "8155";
                }

                if (variant == 1) {
                    bad["android"]["package"] = "system-images;android-30;default;arm64-v8a";
                }

                if (variant == 2) {
                    bad["android"]["sha256"] = "not-a-pin";
                }

                bool denied = false;
                try {
                    android_candidate_capture_arguments(bad, true, 5580);
                } catch (...) {
                    denied = true;
                }

                check(denied);
            }
        }
        auto capture_profile = passion;

        for (auto &display : capture_profile["displays"]) {
            display["width"] = 1920;
        }

        check(android_candidate_capture_arguments(capture_profile, true, 5580) ==
              std::vector<std::string>{"-grpc", "35580", "-grpc-use-token"});
        auto capture_free = capture_profile;
        capture_free["id"] = "test-qinggan11";
        capture_free["platform"] = "qinggan11";
        check(android_candidate_capture_arguments(capture_free, true, 5580) ==
              std::vector<std::string>{"-grpc", "35580", "-grpc-use-token"});
        {
            auto ready = capture_free;
            ready["status"] = "ready";
            check(android_candidate_capture_arguments(ready, true, 5580) ==
                  std::vector<std::string>{"-grpc", "35580", "-grpc-use-token"});
        }

        for (unsigned variant = 0; variant < 5; ++variant) {
            auto bad = capture_profile;
            unsigned port = 5580;

            if (variant == 0) {
                bad["platform"] = "qinggan09";
            }

            if (variant == 1) {
                bad["android"]["package"] = "system-images;android-28;default;arm64-v8a";
            }

            if (variant == 2) {
                bad["displays"][1]["width"] = 1280;
            }

            if (variant == 3) {
                port = 65535;
            }

            if (variant == 4) {
                bad["android"]["revision"] = "r2";
            }

            bool denied = false;
            try {
                android_candidate_capture_arguments(bad, true, port);
            } catch (...) {
                denied = true;
            }

            check(denied);
        }

        {
            const Json first_oem = {
                    {"configure", {{"properties", {{"persist.app.kuwo.support", "false"}}}}}};
            std::vector<std::vector<std::string>> trace;
            auto shell = [&](const std::vector<std::string> &command) {
                trace.push_back(command);

                return command.front() == "getprop" ? std::string("false") : std::string{};
            };
            auto reboot = [&] {
                trace.push_back({"reboot"});
            };
            android_candidate_first_oem_boot(first_oem, shell, reboot);
            check(trace == std::vector<std::vector<std::string>>{
                                   {"getprop", "persist.app.kuwo.support"}, {"sync"}, {"reboot"}});
            trace.clear();
            android_candidate_configure_properties(first_oem, shell);
            check(trace ==
                  std::vector<std::vector<std::string>>{{"getprop", "persist.app.kuwo.support"}});

            for (const auto &profile :
                 {Json::object(), Json{{"configure", {{"properties", Json::object()}}}}}) {
                trace.clear();
                android_candidate_first_oem_boot(profile, shell, reboot);
                check(trace == std::vector<std::vector<std::string>>{{"reboot"}});
            }

            for (bool failed_write : {false, true}) {
                trace.clear();
                bool denied = false;
                try {
                    android_candidate_first_oem_boot(
                            first_oem,
                            [&](const std::vector<std::string> &command) {
                                trace.push_back(command);

                                if (failed_write && command.front() == "setprop") {
                                    throw std::runtime_error("setprop failed");
                                }

                                return std::string("true");
                            },
                            reboot);
                } catch (...) {
                    denied = true;
                }

                const std::vector<std::vector<std::string>> expected =
                        failed_write
                                ? std::vector<
                                          std::vector<std::string>>{{"getprop",
                                                                     "persist.app.kuwo.support"},
                                                                    {"setprop",
                                                                     "persist.app.kuwo.support",
                                                                     "false"}}
                                : std::vector<std::vector<std::string>>{
                                          {"getprop", "persist.app.kuwo.support"},
                                          {"setprop", "persist.app.kuwo.support", "false"},
                                          {"getprop", "persist.app.kuwo.support"}};
                check(denied && trace == expected);
            }

            for (const auto &failure : std::vector<std::string>{"getprop", "sync"}) {
                trace.clear();
                bool denied = false;
                try {
                    android_candidate_first_oem_boot(
                            first_oem,
                            [&](const std::vector<std::string> &command) {
                                trace.push_back(command);

                                if (command.front() == failure) {
                                    throw std::runtime_error("guest command failed");
                                }

                                return command.front() == "getprop" ? std::string("false")
                                                                    : std::string{};
                            },
                            reboot);
                } catch (...) {
                    denied = true;
                }

                check(denied && std::none_of(trace.begin(), trace.end(), [](const auto &command) {
                          return command.front() == "reboot";
                      }));
            }

            for (const auto &invalid :
                 Json::array({nullptr, 42, Json::array(),
                              Json{{"persist.valid", "false"}, {"persist.zbad", false}},
                              Json{{"persist.valid", "false"}, {"persist.zbad key", "false"}},
                              Json{{"persist.valid", "false"},
                                   {"persist.zbad", std::string("a\0b", 3)}}})) {
                trace.clear();
                bool denied = false;
                try {
                    android_candidate_first_oem_boot(Json{{"configure", {{"properties", invalid}}}},
                                                     shell, reboot);
                } catch (...) {
                    denied = true;
                }

                check(denied && trace.empty());
            }
        }
        check(android_candidate_start_commands(Json::object()).empty());
        const Json legacy = {{"configure", {{"start", Json::array({"com.example/.Service"})}}}};
        check(android_candidate_start_commands(legacy) ==
              std::vector<std::vector<std::string>>{
                      {"am", "start-foreground-service", "-n", "com.example/.Service"}});
        const Json modes = {{"configure",
                             {{"start", Json::array({Json{{"component", "com.example/.Service"},
                                                          {"mode", "service"}},
                                                     Json{{"component", "com.example/.Foreground"},
                                                          {"mode", "foreground-service"}}})}}}};
        check(android_candidate_start_commands(modes) ==
              std::vector<std::vector<std::string>>{
                      {"am", "start-service", "-n", "com.example/.Service"},
                      {"am", "start-foreground-service", "-n", "com.example/.Foreground"}});

        for (const auto &bad :
             Json::array({42, "bad component",
                          Json{{"component", "com.example/.Service"}, {"mode", "unknown"}},
                          Json{{"component", "com.example/.Service"},
                               {"mode", "service"},
                               {"extra", true}},
                          Json{{"component", 42}, {"mode", "service"}},
                          Json{{"component", "com.example/.Service"}}})) {
            bool denied = false;
            try {
                android_candidate_start_commands(
                        Json{{"configure", {{"start", Json::array({bad})}}}});
            } catch (...) {
                denied = true;
            }

            check(denied);
        }

        // API30 PackageManager serializes the preferred HOME as a short ComponentName.
        const Json flushed_home = {
                {"homeActivity",
                 "com.example.launcher/com.example.launcher.activity.MainActivity"}};
        const std::string home_filter =
                R"xml(<filter><action name="android.intent.action.MAIN"/><cat name="android.intent.category.HOME"/></filter>)xml";
        const auto preferred_xml = [&](const std::string &name, const std::string &content) {
            return "<package-restrictions><preferred-activities><item name=\"" + name +
                   "\" always=\"true\">" + content +
                   "</item></preferred-activities></package-restrictions>";
        };
        check(android_candidate_package_settings_flushed(
                preferred_xml("com.example.launcher/.activity.MainActivity", home_filter),
                flushed_home));
        check(android_candidate_package_settings_flushed(
                preferred_xml("com.example.launcher/com.example.launcher.activity.MainActivity",
                              home_filter),
                flushed_home));
        check(!android_candidate_package_settings_flushed(
                preferred_xml(
                        "com.other/.MainActivity",
                        "<set name=\"com.example.launcher/com.example.launcher.activity.MainActivity\"/>" +
                                home_filter),
                flushed_home));
        check(!android_candidate_package_settings_flushed(
                preferred_xml("com.example.launcher/.activity.Other", home_filter), flushed_home));
        check(!android_candidate_package_settings_flushed(
                preferred_xml("com.example.launcher/.activity.MainActivity",
                              "<filter><cat name=\"android.intent.category.HOME\"/></filter>"),
                flushed_home));
        check(!android_candidate_package_settings_flushed(
                preferred_xml("com.example.launcher/.activity.MainActivity",
                              "<filter><action name=\"android.intent.action.MAIN\"/></filter>"),
                flushed_home));
        check(!android_candidate_package_settings_flushed(
                "<package-restrictions><set name=\"com.example.launcher/com.example.launcher.activity.MainActivity\"/></package-restrictions>",
                flushed_home));
        check(android_candidate_package_settings_flushed("<package-restrictions/>",
                                                         Json::object()));
        const Json package_states = {{"disabled", Json::array({"com.example.disabled"})},
                                     {"uninstalled", Json::array({"com.example.removed"})}};
        check(android_candidate_package_settings_flushed(
                "<package-restrictions><pkg name=\"com.example.disabled\" enabled=\"3\"/><pkg name=\"com.example.removed\" inst=\"false\"/></package-restrictions>",
                package_states));
        check(!android_candidate_package_settings_flushed(
                "<package-restrictions><pkg name=\"com.example.disabled\" enabled=\"1\"/><pkg name=\"com.example.removed\" inst=\"false\"/></package-restrictions>",
                package_states));
        check(!android_candidate_package_settings_flushed(
                "<package-restrictions><pkg name=\"com.example.disabled\" enabled=\"3\"/><pkg name=\"com.example.removed\" inst=\"true\"/></package-restrictions>",
                package_states));

        if (argc == 7 && std::string(argv[1]) == "--run") {
            std::signal(SIGTERM, cancel_candidate);
            std::signal(SIGINT, cancel_candidate);
            const auto *route_file = std::getenv("VOYEMU_CANDIDATE_ADB_ROUTE");
            check(route_file && *route_file);
            check_candidate_route_environment(candidate_route(route_file));
            const auto root = std::filesystem::absolute(argv[2]);
            AndroidCandidateRequest request;
            request.profile = argv[3];
            check(valid_profile_name(request.profile));
            request.profile_sha256 =
                    sha256_file(root / "profiles" / request.profile / "profile.json");
            request.artifact_result = std::filesystem::absolute(argv[4]);
            request.artifact_result_sha256 = sha256_file(request.artifact_result);
            request.clean_base = std::filesystem::absolute(argv[5]);
            request.clean_receipt_sha256 = sha256_file(request.clean_base / "base.json");
            request.sdk = root / ".local/toolchains/native-sdk";
            request.port = 5580;
#ifdef _WIN32
            const std::string exe = ".exe", host = "windows-x86_64";
#elif defined(__aarch64__) || defined(__arm64__)
            const std::string exe, host = "darwin-aarch64";
#else
            const std::string exe, host = "darwin-x86_64";
#endif

            for (const auto &file :
                 {request.sdk / ("emulator/emulator" + exe),
                  request.sdk / ("platform-tools/adb" + exe),
                  request.sdk / ("build-tools/36.1.0/aapt2" + exe),
                  request.sdk / ("emulator/qemu-img" + exe),
                  request.sdk / "emulator/qemu" / host / ("qemu-system-aarch64" + exe)}) {
                request.tool_pins[file.string()] = sha256_file(file);
            }

            const auto result = run_owned_candidate(root, request,
                                                    std::filesystem::absolute(argv[6]));
            std::cout << result.dump() << '\n';

            return 0;
        }

        if (argc == 4 && std::string(argv[1]) == "--plan") {
            const auto root = std::filesystem::absolute(argv[2]);
            const auto profile = read_private_json(
                               root / "profiles" / qinggan09_profile() / "profile.json", 4 << 20),
                       artifacts = read_private_json(std::filesystem::absolute(argv[3]), 16 << 20);
            std::cout << android_candidate_install_plan(profile, artifacts.at("artifacts")).dump()
                      << '\n';

            return 0;
        }

        check(argc == 1);
        verify_candidate_profile_artifact_boundary();
        const auto root = std::filesystem::path(__FILE__)
                                  .parent_path()
                                  .parent_path()
                                  .parent_path()
                                  .parent_path();
        const auto profile = read_private_json(
                root / "profiles" / qinggan09_profile() / "profile.json", 4 << 20);
        Json artifacts = Json::object();

        for (const auto &entry : profile.at("install")) {
            const auto ref = entry.at("artifact").get<std::string>();
            artifacts[ref] = entry.at("type") == "tree" ? Json({{"directory", "/fixture/theme"},
                                                                {"files", Json::object()}})
                                                        : Json({{"file", "/fixture/file"}});
        }

        const auto plan = android_candidate_install_plan(profile, artifacts);
        check(plan.at("system").at(0).at("artifact") == "files:early-inputs-init" &&
              plan.at("data").empty() && plan.at("apks").at(0).at("artifact") == "patched:QGIME");
        check(plan.at("system").size() + plan.at("data").size() + plan.at("apks").size() ==
              profile.at("install").size());

        {
            const auto actual = read_private_json(
                    root / "profiles/free-09-chinese-20221230-nxp-rc45/profile.json", 4 << 20);
            Json inputs = Json::object();
            Json immutable = Json::array(), mutable_seeds = Json::array();

            for (const auto &entry : actual.at("install")) {
                const auto type = entry.at("type").get<std::string>();
                inputs[entry.at("artifact").get<std::string>()] =
                        type == "tree"
                                ? Json{{"directory", "/fixture/tree"}, {"files", Json::object()}}
                                : Json{{"file", "/fixture/file"}};

                if (type != "apk" && entry.at("target").get<std::string>().starts_with("/data/")) {
                    (entry.value("mutable", false) ? mutable_seeds : immutable).push_back(entry);
                }
            }

            const auto phases = android_candidate_install_plan(actual, inputs);
            const auto [early_data, late_data] =
                    machine_preparation_detail::data_install_phases(phases.at("data"));
            check(early_data == immutable);
            check(late_data == mutable_seeds);
            check(phases.at("data").size() == immutable.size() + mutable_seeds.size());
            bool oem_booted = false;
            std::size_t filesystem_installs = 0, package_installs = 0;
            android_candidate_first_oem_boot(
                    actual,
                    [&](const std::vector<std::string> &command) {
                        return command.front() == "getprop" ? actual.at("configure")
                                                                      .at("properties")
                                                                      .at(command.at(1))
                                                                      .get<std::string>()
                                                            : std::string{};
                    },
                    [&] {
                        oem_booted = true;
                    },
                    [&] {
                        for (const auto &entry : early_data) {
                            check(!oem_booted && !entry.value("mutable", false));
                            ++filesystem_installs;
                        }
                    });

            for (const auto &entry : late_data) {
                check(oem_booted && entry.value("mutable", false));
                ++filesystem_installs;
            }

            for (const auto &entry : phases.at("apks")) {
                check(oem_booted && entry.at("type") == "apk");
                ++package_installs;
            }

            check(filesystem_installs == immutable.size() + mutable_seeds.size());
            check(package_installs == phases.at("apks").size() && package_installs > 0);
            check(immutable.size() == 266 && mutable_seeds.empty());
        }

        {
            using namespace machine_preparation_detail;
            auto policy_profile = read_private_json(
                    root / "profiles/free-09-chinese-20221230-nxp-rc45/profile.json", 4 << 20);
            const Installed policy{"patched:selinux-canbus-nxp",
                                   "/system/etc/selinux/plat_sepolicy.cil",
                                   std::string(64, 'a'),
                                   {},
                                   "0644",
                                   false};

            for (auto &entry : policy_profile["install"]) {
                if (entry.value("target", std::string{}) == policy.target) {
                    entry["context"] = "u:object_r:sepolicy_file:s0";
                }
            }

            const Json partial_proof =
                    Json::array({{{"id", "artifact:" + policy.artifact + ":" + policy.target},
                                  {"expected", policy.sha256},
                                  {"actual", policy.sha256},
                                  {"passed", true},
                                  {"boot_id", "cold-boot"},
                                  {"path", policy.target},
                                  {"artifact", policy.artifact}}});
            check(!cold_policy_verified(policy_profile, policy, partial_proof, "cold-boot"));

            for (unsigned outcome = 0; outcome < 8; ++outcome) {
                Json checks = Json::array();
                bool refused = false;
                std::size_t root_reads = 0;
                auto root_reader = [&](const std::vector<std::string> &) -> std::string {
                    ++root_reads;
                    throw std::runtime_error("root cannot read policy files");
                };
                auto shell = [&](const std::vector<std::string> &command) {
                    if (command.front() == "cat") {
                        return std::string("cold-boot");
                    }

                    check(command.back() == policy.target);

                    if (command.front() == "ls") {
                        return std::string(outcome == 6 ? "u:object_r:system_file:s0 "
                                                        : "u:object_r:sepolicy_file:s0 ") +
                               policy.target;
                    }

                    if (command.front() == "stat" && command.at(2) == "%a %u:%g") {
                        if (outcome == 7) {
                            throw std::runtime_error("normal metadata read failed");
                        }

                        return std::string(outcome == 4   ? "644 1:0"
                                           : outcome == 5 ? "644 0:1"
                                                          : "644 0:0");
                    }

                    if (command.front() == "stat" && command.at(2) == "%a") {
                        return std::string(outcome == 3 ? "600" : "644");
                    }

                    check(command.front() == "sha256sum");

                    if (outcome == 2) {
                        throw std::runtime_error("normal content read failed");
                    }

                    return std::string(64, outcome == 1 ? 'b' : 'a') + "  " + policy.target;
                };
                try {
                    verify_cold_policy_files(policy_profile, {policy}, checks, shell);
                    verify_cold_installed_file(policy_profile, policy, policy.target, checks,
                                               "cold-boot", root_reader);
                } catch (...) {
                    refused = true;
                }

                check(refused == (outcome != 0) && root_reads == 0);
                check(cold_policy_verified(policy_profile, policy, checks, "cold-boot") ==
                      (outcome == 0));

                if (outcome != 0) {
                    bool rejected = false;
                    try {
                        verify_cold_installed_file(policy_profile, policy, policy.target, checks,
                                                   "cold-boot", root_reader);
                    } catch (...) {
                        rejected = true;
                    }

                    check(rejected && root_reads == 0);
                    continue;
                }

                check(checks.size() == 3);
                check(!cold_policy_verified(policy_profile, policy, checks, "other-boot"));

                for (const auto *id : {"mode:", "metadata:"}) {
                    auto missing = checks;
                    missing.erase(
                            std::remove_if(missing.begin(), missing.end(),
                                           [&](const auto &row) {
                                               return row.at("id").template get<std::string>() ==
                                                      std::string(id) + policy.target;
                                           }),
                            missing.end());
                    check(!cold_policy_verified(policy_profile, policy, missing, "cold-boot"));
                }

                for (const auto *field :
                     {"passed", "actual", "expected", "artifact", "path", "boot_id"}) {
                    auto changed = checks;
                    changed.at(0)[field] = std::string(field) == "passed" ? Json(false)
                                                                          : Json("wrong");
                    check(!cold_policy_verified(policy_profile, policy, changed, "cold-boot"));
                }

                auto duplicate = checks;
                duplicate.push_back(checks.at(0));
                check(!cold_policy_verified(policy_profile, policy, duplicate, "cold-boot"));
                auto changed_policy = policy;
                changed_policy.sha256 = std::string(64, 'b');
                check(!cold_policy_verified(policy_profile, changed_policy, checks, "cold-boot"));
                auto changed_profile = policy_profile;

                for (auto &entry : changed_profile["install"]) {
                    if (entry.value("target", std::string{}) == policy.target) {
                        entry["context"] = "u:object_r:system_file:s0";
                    }
                }

                check(!cold_policy_verified(changed_profile, policy, checks, "cold-boot"));
            }

            Json regular_checks = Json::array();
            const Installed regular{"fixture:regular",
                                    "/data/local/fixture",
                                    std::string(64, 'a'),
                                    {},
                                    "0644",
                                    false};
            std::size_t regular_reads = 0;
            verify_cold_installed_file(policy_profile, regular, regular.target, regular_checks,
                                       "cold-boot", [&](const std::vector<std::string> &command) {
                                           ++regular_reads;
                                           check(command.back() == regular.target);

                                           return command.front() == "sha256sum"
                                                          ? regular.sha256 + "  " + regular.target
                                                          : std::string("644");
                                       });
            check(regular_reads == 2 && regular_checks.size() == 2);
        }

        for (const auto &[name, expected_count] :
             {std::pair{"free-09-chinese-20260106-6.0.3", 5U},
              std::pair{"free-09-chinese-20221230-nxp-rc45", 3U},
              std::pair{"free-11-chinese-20250710-6.11.1", 5U},
              std::pair{"free-11-chinese-20260731-7.3.1", 6U},
              std::pair{"passion-11-russian-20260403-2.1.4.80", 6U}}) {
            const auto actual = read_private_json(root / "profiles" / name / "profile.json",
                                                  4 << 20);
            std::vector<machine_preparation_detail::Installed> policies;

            for (const auto &entry : actual.at("install")) {
                if (entry.at("type") == "file" &&
                    std::filesystem::path(entry.at("target").get<std::string>())
                                    .parent_path()
                                    .filename() == "selinux") {
                    policies.push_back({entry.at("artifact").get<std::string>(),
                                        entry.at("target").get<std::string>(),
                                        std::string(64, 'a'),
                                        {},
                                        "0644",
                                        false});
                }
            }

            check(policies.size() == expected_count);
            Json checks = Json::array();
            std::size_t contents = 0, modes = 0, labels = 0, roots = 0;
            bool changed_boot = false;
            const auto passion = actual.at("platform") == "passion";
            const auto read_policy = [&](const std::vector<std::string> &command) {
                if (command.front() == "cat") {
                    return std::string(roots && changed_boot ? "different-boot" : "sibling-cold");
                }

                const auto policy = std::find_if(policies.begin(), policies.end(),
                                                 [&](const auto &item) {
                                                     return item.target == command.back();
                                                 });
                check(policy != policies.end());
                const bool restricted =
                        policy->artifact == "patched:original-navi-selinux" ||
                        (passion &&
                         policy->target == "/system/etc/selinux/plat_hwservice_contexts");
                check((roots == 1) == restricted);

                if (command.front() == "sha256sum") {
                    ++contents;

                    return policy->sha256 + "  " + policy->target;
                }

                if (command.front() == "stat") {
                    check(command.at(2) == "%a");
                    ++modes;

                    return std::string("644");
                }

                check(command.front() == "ls" &&
                      policy->artifact == "patched:original-navi-selinux");
                ++labels;

                return std::string("u:object_r:mac_perms_file:s0 ") + policy->target;
            };
            const auto rooted_adb = [&] {
                ++roots;
            };
            machine_preparation_detail::verify_cold_policy_files(actual, policies, checks,
                                                                 read_policy, rooted_adb);
            check(contents == expected_count && modes == expected_count);
            check(labels == (original_navi_requested(actual) ? 1U : 0U));
            check(roots == (passion || original_navi_requested(actual) ? 1U : 0U));

            if (roots) {
                roots = 0;
                contents = 0;
                changed_boot = true;
                Json new_boot_checks = Json::array();
                bool rejected = false;
                try {
                    machine_preparation_detail::verify_cold_policy_files(
                            actual, policies, new_boot_checks, read_policy, rooted_adb);
                } catch (const std::runtime_error &error) {
                    rejected = std::string_view(error.what())
                                       .ends_with("cold policy reader boot identity changed");
                }

                check(rejected && roots == 1 && contents == expected_count - 1);
            }

            check(checks.size() == 2 * static_cast<std::size_t>(expected_count) + labels);

            for (const auto &policy : policies) {
                check(machine_preparation_detail::cold_policy_verified(actual, policy, checks,
                                                                       "sibling-cold"));
                machine_preparation_detail::verify_cold_installed_file(
                        actual, policy, policy.target, checks, "sibling-cold",
                        [&](const std::vector<std::string> &) -> std::string {
                            throw std::runtime_error("root policy read forbidden");
                        });
            }

            if (labels) {
                auto bad_label = checks;

                for (auto &row : bad_label) {
                    if (row.at("id") == "navi-mac-label") {
                        row["actual"] = "u:object_r:system_file:s0";
                    }
                }

                const auto mac =
                        std::find_if(policies.begin(), policies.end(), [](const auto &item) {
                            return item.artifact == "patched:original-navi-selinux";
                        });
                check(mac != policies.end());
                check(!machine_preparation_detail::cold_policy_verified(actual, *mac, bad_label,
                                                                        "sibling-cold"));
            }
        }

        {
            using namespace machine_preparation_detail;
            const Json system_file = {{"artifact", "fixture:system"},
                                      {"type", "file"},
                                      {"target", "/system/etc/fixture.prop"},
                                      {"mode", "0644"}};
            const Json directory = {{"artifact", "directory:fixture"},
                                    {"type", "directory"},
                                    {"target", "/data/vendor/fixture"},
                                    {"mode", "0755"},
                                    {"uid", 1000},
                                    {"gid", 1000}};
            const Json file = {{"artifact", "fixture:file"},
                               {"type", "file"},
                               {"target", "/data/vendor/fixture/config"},
                               {"mode", "0644"},
                               {"uid", 1000},
                               {"gid", 1000}};
            const Json tree = {{"artifact", "fixture:tree"},
                               {"type", "tree"},
                               {"target", "/data/vendor/fixture/tree"},
                               {"mode", "0644"},
                               {"uid", 1000},
                               {"gid", 1000}};
            const Json mutable_file = {{"artifact", "fixture:state"},
                                       {"type", "file"},
                                       {"target", "/data/local/fixture-state"},
                                       {"mode", "0666"},
                                       {"uid", 1000},
                                       {"gid", 1000},
                                       {"mutable", true}};
            const Json apk = {{"artifact", "fixture:apk"}, {"type", "apk"}};
            const Json local_profile = {
                    {"install",
                     Json::array({system_file, directory, file, tree, mutable_file, apk})},
                    {"configure",
                     {{"bootProperties", {{"ro.qg.presentation", "VirtualDisplay"}}},
                      {"properties", {{"persist.fixture.mode", "ready"}}}}}};
            const Json inputs = {
                    {"fixture:system", {{"file", "/fixture/system"}}},
                    {"fixture:file", {{"file", "/fixture/config"}}},
                    {"fixture:tree", {{"directory", "/fixture/tree"}, {"files", Json::object()}}},
                    {"fixture:state", {{"file", "/fixture/state"}}},
                    {"fixture:apk", {{"file", "/fixture/application.apk"}}}};
            const auto phases = android_candidate_install_plan(local_profile, inputs);
            const auto [early_data, late_data] = data_install_phases(phases.at("data"));
            check(phases.at("data") == Json::array({directory, file, tree, mutable_file}));
            check(early_data == Json::array({directory, file, tree}));
            check(late_data == Json::array({mutable_file}));
            check(phases.at("apks") == Json::array({apk}) &&
                  phases.at("system") == Json::array({system_file}));
            std::vector<std::string> installed;
            std::string property, boot_properties;
            bool oem_booted = false;
            android_candidate_first_oem_boot(
                    local_profile,
                    [&](const std::vector<std::string> &command) {
                        if (command.front() == "setprop") {
                            property = command.at(2);
                        }

                        return command.front() == "getprop" ? property : std::string{};
                    },
                    [&] {
                        check(installed == std::vector<std::string>{"directory:fixture",
                                                                    "fixture:file",
                                                                    "fixture:tree"});
                        check(boot_properties == "ro.qg.presentation=VirtualDisplay\n");
                        oem_booted = true;
                    },
                    [&] {
                        for (const auto &entry : early_data) {
                            check(!oem_booted);
                            installed.push_back(entry.at("artifact").get<std::string>());
                        }

                        boot_properties = android_candidate_boot_properties(
                                "", local_profile.at("configure").at("bootProperties"));
                    });

            for (const auto &entry : late_data) {
                check(oem_booted && entry.at("mutable") == true);
                installed.push_back(entry.at("artifact").get<std::string>());
            }

            for (const auto &entry : phases.at("apks")) {
                check(oem_booted && entry.at("type") == "apk");
                installed.push_back(entry.at("artifact").get<std::string>());
            }

            check(installed == std::vector<std::string>{"directory:fixture", "fixture:file",
                                                        "fixture:tree", "fixture:state",
                                                        "fixture:apk"});
        }

        std::set<std::string> oem_privileged;

        for (const auto &entry : plan.at("system")) {
            check(!entry.at("target").get<std::string>().starts_with("/data/"));

            if (entry.at("type") == "apk") {
                oem_privileged.insert(entry.at("package").get<std::string>());
            }
        }

        // The OEM services and Launcher keep their system placement; the CAN adapter is privileged.
        check(oem_privileged ==
              std::set<std::string>{"com.qinggan.QGBus", "com.qinggan.app.launcher",
                                    "com.qinggan.canbus.service", "com.qinggan.systempolicy"});
        // The Launcher HOME declarations of the Mac candidate that installed it as a data APK.
        check(!android_candidate_home_priorities_ready(
                profile.at("verify").at("homePriorities"),
                "2 activities found:\n  Activity #0:\n    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n    com.qinggan.app.launcher/.activity.MainActivity\n  Activity #1:\n    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n    com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity"));

        std::string cache_header(1082, char{});
        cache_header[1080] = 0x53;
        cache_header[1081] = static_cast<char>(0xef);
        validate_android_candidate_cache_image(cache_header, 69206016);

        for (unsigned mode = 0; mode < 5; ++mode) {
            auto header = cache_header;
            std::uint64_t extent = 69206016;

            if (mode == 0) {
                --extent;
            }

            if (mode == 1) {
                ++extent;
            }

            if (mode == 2) {
                header.resize(1081);
            }

            if (mode == 3) {
                header[1080] = 0;
            }

            if (mode == 4) {
                header[1081] = 0;
                header[1079] = static_cast<char>(0xef);
            }

            bool refused = false;
            try {
                validate_android_candidate_cache_image(header, extent);
            } catch (...) {
                refused = true;
            }

            check(refused);
        }

        check(android_candidate_command_log(
                      std::vector<std::string>{"sha256sum", "/apex/com.android.art/bin/dex2oat64"})
                      .empty());
        check(android_candidate_command_log(std::vector<std::string>{
                      "/system/bin/env", "ANDROID_ROOT=/system",
                      "ANDROID_DATA=/system/framework/arm64", "/system/bin/patchoat",
                      "--input-image-location=/system/framework/boot.art"}) ==
              "boot-image-relocation.log");
        check(android_candidate_command_log(std::vector<std::string>{
                      "/system/bin/dex2oat", "--image=/system/framework/arm64/boot.art"}) ==
              "boot-image-compile.log");
        const std::vector<std::string> server_log_command = {
                "/system/bin/dex2oat", "--oat-file=/system/framework/oat/arm64/services.odex"};
        check(android_candidate_command_log(server_log_command) ==
              "system-server-" + sha256_bytes(Json(server_log_command).dump()).substr(0, 16) +
                      ".log");
        const std::vector<std::string> collided = {
                "-H",    "127.0.0.1",
                "-P",    "25580",
                "-s",    "emulator-5580",
                "shell", "'sha256sum' '/apex/com.android.art/bin/dex2oat64'"};
        std::string joined;

        for (const auto &arg : collided) {
            if (!joined.empty()) {
                joined += ' ';
            }

            joined += arg;
        }

        check("system-server-" + sha256_bytes(joined).substr(0, 16) + ".log" ==
              "system-server-6c47adbaef8caf1f.log");
        check(android_candidate_command_log(collided).empty());

        for (const auto &args : std::vector<std::vector<std::string>>{
                     {},
                     {"cat", "/system/bin/dex2oat"},
                     {"echo",
                      "/apex/com.android.art/bin/dex2oat64 --image=/system/framework/arm64/boot.art"},
                     {"/system/bin/patchoat-extra"},
                     {"shell",
                      "'/system/bin/dex2oat' '--image=/system/framework/arm64/boot.art'"}}) {
            check(android_candidate_command_log(args).empty());
        }

        check(android_candidate_command_log(
                      std::vector<std::string>{"/system/bin/dex2oat",
                                               "--dex-file=contains--image=embedded"})
                      .starts_with("system-server-"));
        Json art_profile = {
                {"id", "test-passion"},
                {"platform", "passion"},
                {"board", "8155"},
                {"android",
                 {{"package", "system-images;android-30;default;arm64-v8a"},
                  {"revision", "1"},
                  {"url",
                   "https://dl.google.com/android/repository/sys-img/android/arm64-v8a-30_r01.zip"},
                  {"sha256", std::string(64, 'a')}}},
                {"original", {{"LY_Car", Json::object()}, {"LY_Launcher", Json::object()}}}};
        art_profile["patches"]["LY_Launcher"]["steps"] = Json::array(
                {"framework-libraries.json", "passion-api30-sidebars.json",
                 "passion-api30-bluetooth-volume.json", "passion-api30-launcher-audio.json"});
        check(android_candidate_art_verify_packages(art_profile) ==
              std::vector<std::string>({"com.voyah.car", "com.voyah.os.carlauncher"}));
        auto art_old = art_profile;
        art_old["patches"]["LY_Launcher"]["steps"] = Json::array({"passion-api30-sidebars.json"});
        check(android_candidate_art_verify_packages(art_old) ==
              std::vector<std::string>({"com.voyah.car"}));
        auto art_foreign = art_profile;
        art_foreign["id"] = "test-qinggan11";
        art_foreign["platform"] = "qinggan11";
        check(android_candidate_art_verify_packages(art_foreign).empty());
        auto art_api28 = art_profile;
        art_api28["android"]["package"] = "system-images;android-28;default;arm64-v8a";
        check(android_candidate_art_verify_packages(art_api28).empty());
        auto art_partial = art_profile;
        art_partial["original"].erase("LY_Car");
        check(android_candidate_art_verify_packages(art_partial).empty());
        const auto art_avm = read_private_json(
                root / "profiles/passion-11-russian-20260403-2.1.4.80/profile.json", 4 << 20);
        const auto art_avm_packages = android_candidate_art_verify_packages(art_avm);
        check(art_avm_packages ==
              std::vector<std::string>(
                      {"com.voyah.car", "com.voyah.os.carlauncher", "com.voyah.avm"}));
        auto art_avm_legacy = art_avm;
        art_avm_legacy["patches"]["LY_AVM"]["steps"] =
                Json::array({"passion-api30-media-libraries.json"});
        check(android_candidate_art_verify_packages(art_avm_legacy) ==
              std::vector<std::string>({"com.voyah.car", "com.voyah.os.carlauncher"}));

        for (unsigned mode = 0; mode < 7; ++mode) {
            auto bad = art_avm;

            if (mode == 0) {
                bad["original"].erase("LY_AVM");
            }

            if (mode == 1) {
                bad["original"]["LY_AVM"]["sha256"] = std::string(64, '0');
            }

            if (mode == 2) {
                bad["original"]["LY_AVM"]["source"]["package"] = "foreign.avm";
            }

            if (mode == 3) {
                bad["patches"]["LY_AVM"]["input"] = "original:LY_Car";
            }

            if (mode == 4) {
                bad["patches"]["LY_AVM"]["steps"].push_back("foreign.json");
            }

            if (mode == 5) {
                bad["install"].erase(std::remove_if(bad["install"].begin(), bad["install"].end(),
                                                    [](const auto &item) {
                                                        return item.value("artifact",
                                                                          std::string{}) ==
                                                               "patched:LY_AVM";
                                                    }),
                                     bad["install"].end());
            }

            if (mode == 6) {
                for (auto &item : bad["install"]) {
                    if (item.value("artifact", std::string{}) == "patched:LY_AVM") {
                        item["target"] = "/system/app/foreign.apk";
                    }
                }
            }

            bool rejected = false;
            try {
                (void)android_candidate_art_verify_packages(bad);
            } catch (const std::exception &) {
                rejected = true;
            }

            check(rejected);
        }

        const auto avm_original =
                root / ".local/profiles/passion-11-russian-20260403-2.1.4.80/originals/LY_AVM.apk";
#ifdef _WIN32
        const auto avm_aapt = root / ".local/toolchains/native-sdk/build-tools/36.1.0/aapt2.exe";
#else
        const auto avm_aapt = root / ".local/toolchains/native-sdk/build-tools/36.1.0/aapt2";
#endif

        if (std::filesystem::is_regular_file(avm_original) &&
            std::filesystem::is_regular_file(avm_aapt)) {
            check(sha256_file(avm_original) ==
                  art_avm.at("original").at("LY_AVM").at("sha256").get<std::string>());
            ProcessSpec spec;
            spec.executable = avm_aapt;
            spec.directory = root;
            spec.arguments = {"dump", "badging", avm_original.string()};
            const auto actual = execute(spec, 10000, 1 << 20);
            check(!actual.timed_out && actual.exit_code == 0);
            std::smatch package;
            check(std::regex_search(actual.output, package, std::regex("package: name='([^']+)'")));
            check(std::count(art_avm_packages.begin(), art_avm_packages.end(), package[1].str()) ==
                  1);
            std::cout
                    << "Actual owner-pinned AVM APK package selected for ART exactly once; no guest compiler executed\n";
        }

        check(android_candidate_command_log(
                      std::vector<std::string>{"getprop", "sys.boot_completed"})
                      .empty());
        check(int(android_candidate_api(profile)) == 28);
        check(int(android_candidate_api(read_private_json(
                      root / "profiles/passion-11-russian-20260403-2.1.4.80/profile.json",
                      4 << 20))) == 30);
        auto api30 = read_private_json(
                root / "profiles/free-11-chinese-20250710-6.11.1/profile.json", 4 << 20);
        api30["android"]["revision"] = "1";
        const auto actual_qinggan11 = read_private_json(
                root / "profiles/free-11-chinese-20260731-7.3.1/profile.json", 4 << 20);
        check((actual_qinggan11.at("status") == "incomplete" ||
               actual_qinggan11.at("status") == "ready") &&
              int(android_candidate_api(actual_qinggan11)) == 30);
        check(android_candidate_boot_cache_paths(actual_qinggan11).size() == 18 &&
              !android_candidate_boot_image_command(actual_qinggan11).empty() &&
              android_candidate_boot_relocation_command(actual_qinggan11).empty() &&
              android_candidate_system_server_commands(actual_qinggan11).empty());
        check(int(android_candidate_api(api30)) == 30);
        api30["install"] = Json::array();
        check(android_candidate_boot_cache_paths(api30).empty() &&
              android_candidate_boot_image_command(api30).empty() &&
              android_candidate_boot_relocation_command(api30).empty() &&
              android_candidate_system_server_commands(api30).empty());
        const auto acquired_api30 = read_private_json(
                root / "profiles/free-11-chinese-20260731-7.3.1/profile.json", 4 << 20);
        check((acquired_api30.at("status") == "incomplete" ||
               acquired_api30.at("status") == "ready") &&
              int(android_candidate_api(acquired_api30)) == 30);
        // Reproduce a version-0 CanBus DATA install remaining outside the regenerated SYSTEM image.
        const Json old_canbus = {
                {"package", "com.qinggan.canbus.service"}, {"version_code", 0}, {"system", false}};
        check(old_canbus.at("package") == "com.qinggan.canbus.service" &&
              old_canbus.at("version_code") == 0 && old_canbus.at("system") == false);
        const Json canbus_artifact = {{"component:canbus", {{"file", "verified-canbus.apk"}}}};
        const auto old_canbus_plan = android_candidate_install_plan(
                {{"install",
                  Json::array({Json{{"artifact", "component:canbus"}, {"type", "apk"}}})}},
                canbus_artifact);
        check(old_canbus_plan.at("system").empty() && old_canbus_plan.at("apks").size() == 1);
        const Json expected_canbus = {{"artifact", "component:canbus"},
                                      {"type", "apk"},
                                      {"target", "/system/priv-app/VoyemuCanBus/VoyemuCanBus.apk"},
                                      {"package", "com.qinggan.canbus.service"},
                                      {"mode", "0644"}};
        Json canbus_entry;
        unsigned canbus_entries = 0;
        std::size_t canbus_index = 0;

        for (std::size_t index = 0; index < acquired_api30.at("install").size(); ++index) {
            const auto &entry = acquired_api30.at("install").at(index);

            if (entry.at("artifact") == "component:canbus") {
                ++canbus_entries;
                check(entry == expected_canbus);
                canbus_entry = entry;
                canbus_index = index;
            }
        }

        check(canbus_entries == 1);
        check(canbus_index > 0 && canbus_index + 1 < acquired_api30.at("install").size());
        check(acquired_api30.at("install").at(canbus_index - 1) ==
              Json({{"artifact", "original:theme"},
                    {"type", "tree"},
                    {"target", "/system/resc/defaulttheme"}}));
        check(acquired_api30.at("install").at(canbus_index + 1) ==
              Json({{"artifact", "component:bootstrap"}, {"type", "apk"}}));
        const auto new_canbus_plan = android_candidate_install_plan(
                {{"install", Json::array({canbus_entry})}}, canbus_artifact);
        check(new_canbus_plan.at("system") == Json::array({expected_canbus}) &&
              new_canbus_plan.at("apks").empty() && new_canbus_plan.at("data").empty());
        std::ifstream canbus_manifest_file(
                root /
                "profiles/free-11-chinese-20260731-7.3.1/components/canbus/AndroidManifest.xml");
        const std::string canbus_manifest((std::istreambuf_iterator<char>(canbus_manifest_file)),
                                          std::istreambuf_iterator<char>());
        std::smatch canbus_version;
        check(std::regex_search(canbus_manifest, canbus_version,
                                std::regex("android:versionCode=\"([0-9]+)\"")) &&
              std::stoi(canbus_version[1].str()) > old_canbus.at("version_code").get<int>());
        check(android_candidate_boot_cache_paths(acquired_api30).size() == 18 &&
              !android_candidate_boot_image_command(acquired_api30).empty() &&
              android_candidate_boot_relocation_command(acquired_api30).empty() &&
              android_candidate_system_server_commands(acquired_api30).empty());
        check(acquired_api30.at("configure").at("properties").at("persist.app.kuwo.support") ==
              "false");

        for (const auto &actual : {acquired_api30, profile}) {
            std::map<std::string, std::string> values;
            std::vector<std::vector<std::string>> trace;
            bool rebooted = false;
            auto shell = [&](const std::vector<std::string> &command) {
                check(!rebooted);
                trace.push_back(command);

                if (command.front() == "setprop") {
                    values[command.at(1)] = command.at(2);

                    return std::string{};
                }

                if (command.front() == "getprop") {
                    return values[command.at(1)];
                }

                check(command == std::vector<std::string>{"sync"});

                return std::string{};
            };
            android_candidate_first_oem_boot(actual, shell, [&] {
                rebooted = true;
            });
            check(rebooted);
            const auto expected = actual.at("configure").value("properties", Json::object());
            check(values.size() == expected.size());

            for (auto item = expected.begin(); item != expected.end(); ++item) {
                check(values.at(item.key()) == item.value().get<std::string>());
            }

            trace.clear();
            rebooted = false;
            android_candidate_configure_properties(actual, shell);
            std::vector<std::vector<std::string>> expected_trace;

            for (auto item = expected.begin(); item != expected.end(); ++item) {
                expected_trace.push_back({"getprop", item.key()});
            }

            check(trace == expected_trace);
        }

        for (const auto *name :
             {"free-11-chinese-20250710-6.11.1", "free-11-chinese-20260731-7.3.1",
              "free-09-chinese-20260106-6.0.3", "free-09-chinese-20221230-nxp-rc45"}) {
            const auto actual = read_private_json(root / "profiles" / name / "profile.json",
                                                  4 << 20);
            const auto boot = actual.at("configure").at("bootProperties");
            std::string disk = "untouched.key=preserve\n";
            bool oem_booted = false, prepared = false;
            android_candidate_first_oem_boot(
                    actual,
                    [&](const std::vector<std::string> &command) {
                        return command.front() == "getprop" ? actual.at("configure")
                                                                      .at("properties")
                                                                      .at(command.at(1))
                                                                      .get<std::string>()
                                                            : std::string{};
                    },
                    [&] {
                        check(prepared);
                        check(disk ==
                              android_candidate_boot_properties("untouched.key=preserve\n", boot));
                        oem_booted = true;
                    },
                    [&] {
                        check(!oem_booted);
                        disk = android_candidate_boot_properties(disk, boot);
                        prepared = true;
                    });
            check(oem_booted && prepared);
            std::map<std::string, std::string> retained;
            const auto properties = actual.at("configure").value("properties", Json::object());

            for (auto value = properties.begin(); value != properties.end(); ++value) {
                retained[value.key()] = value.value().get<std::string>();
            }

            std::size_t reads = 0;
            android_candidate_configure_properties(actual, [&](const auto &command) {
                check(command.front() == "getprop");
                ++reads;

                return retained.at(command.at(1));
            });
            check(reads == properties.size());
        }

        const auto acquired_identity = acquired_api30.at("configure").at("bootProperties");
        // The OEM build.prop of Free A11 selects the cluster presentation over qg.cluster.service.
        check(acquired_identity == Json({{"ro.build.product", "msmnile_gvmq"},
                                         {"ro.build.product_3rdparty", "f6802h"},
                                         {"ro.qg.presentation", "VirtualDisplay"}}));
        check(read_private_json(root / "profiles/free-11-chinese-20250710-6.11.1/profile.json",
                                4 << 20)
                      .at("configure")
                      .at("bootProperties") == Json({{"ro.qg.presentation", "VirtualDisplay"}}));
        const std::string identity_source =
                "ro.build.product=emulator_arm64\nuntouched.key=preserve\n";
        const auto identity_output = android_candidate_boot_properties(identity_source,
                                                                       acquired_identity);
        check(identity_output ==
              "ro.build.product=msmnile_gvmq\nuntouched.key=preserve\nro.build.product_3rdparty=f6802h\nro.qg.presentation=VirtualDisplay\n");

        for (const Json bad_identity :
             {Json({{"ro.build.product_3rdparty", "f6802h\nunsafe=1"}}),
              Json({{"ro.qg.presentation", "Integration"}}),
              Json({{"ro.product.unsupported", "f6802h"}}), Json({{"ro.build.product", 42}})}) {
            bool rejected = false;
            try {
                android_candidate_boot_properties(identity_source, bad_identity);
            } catch (...) {
                rejected = true;
            }

            check(rejected);
        }

        bool duplicate_identity = false;
        try {
            android_candidate_boot_properties("ro.build.product=one\nro.build.product=two\n",
                                              acquired_identity);
        } catch (...) {
            duplicate_identity = true;
        }

        check(duplicate_identity);
        Json acquired_artifacts = Json::object();

        for (const auto &entry : acquired_api30.at("install")) {
            const auto ref = entry.at("artifact").get<std::string>();
            acquired_artifacts[ref] =
                    entry.at("type") == "tree"
                            ? Json({{"directory", "/fixture/a11theme"}, {"files", Json::object()}})
                            : Json({{"file", "/fixture/a11file"}});
        }

        const auto acquired_plan = android_candidate_install_plan(acquired_api30,
                                                                  acquired_artifacts);
        check(acquired_plan.at("apks").size() == 18 && acquired_plan.at("data").empty() &&
              acquired_plan.at("system").size() == 45);
        std::set<std::string> acquired_apks;

        for (const auto &entry : acquired_plan.at("apks")) {
            check(acquired_apks.insert(entry.at("artifact").get<std::string>()).second);
        }

        check(acquired_apks ==
              std::set<std::string>({"component:wheel-input", "patched:QGSettingProvider",
                                     "patched:SystemService", "patched:SystemUI",
                                     "patched:MusicConcate", "patched:VehicleAir",
                                     "patched:VehicleSetting", "patched:Gallery", "patched:Video",
                                     "patched:Dvr", "patched:CloudApp", "patched:WecarFlow",
                                     "patched:HiCar", "patched:Bill", "patched:UserCenter",
                                     "patched:Ivoka", "patched:Camera", "component:bootstrap"}));
        check(acquired_plan.at("system").size() + acquired_plan.at("data").size() +
                      acquired_plan.at("apks").size() ==
              63);
        const Json expected_vendor_overlay = {{"artifact", "files:vendor-overlay"},
                                              {"type", "directory"},
                                              {"target", "/vendor/overlay"},
                                              {"mode", "0755"},
                                              {"context", "u:object_r:vendor_overlay_file:s0"}};
        check(std::count(acquired_plan.at("system").begin(), acquired_plan.at("system").end(),
                         expected_vendor_overlay) == 1);
        std::set<std::string> acquired_system;

        for (const auto &entry : acquired_plan.at("system")) {
            check(acquired_system.insert(entry.at("artifact").get<std::string>()).second);
        }

        check(acquired_system == std::set<std::string>({"component:canbus",
                                                        "patched:original-navi-framework",
                                                        "patched:original-navi-services",
                                                        "patched:QGAPI",
                                                        "component:bluetooth",
                                                        "patched:BluetoothPhone",
                                                        "original:QGMOD",
                                                        "original:android.car",
                                                        "patched:original-navi-vehicle",
                                                        "patched:can-early-file-contexts-api30",
                                                        "component:qg-runtime",
                                                        "patched:public-qg-runtime-api30",
                                                        "files:qinggan-framework",
                                                        "files:secondary-display-feature",
                                                        "component:wheel-platform",
                                                        "patched:KeyManagerService",
                                                        "files:launcher-privapp",
                                                        "patched:Launcher",
                                                        "patched:Setting",
                                                        "original:theme",
                                                        "patched:can-early-policy-api30",
                                                        "patched:keymanager-contexts-api30",
                                                        "patched:can-early-property-contexts-api30",
                                                        "patched:selinux-hash-api30",
                                                        "patched:Hiboard",
                                                        "patched:ThirdScreen",
                                                        "patched:QGMedia",
                                                        "patched:AudioPolicy",
                                                        "component:oem-power",
                                                        "patched:api30-stock-statusbar",
                                                        "original:Navi",
                                                        "patched:original-navi-selinux",
                                                        "component:can-model-observer",
                                                        "files:can-simulator-fixture",
                                                        "files:can-simulator-init",
                                                        "component:can-simulator",
                                                        "files:hybrid-nvram",
                                                        "files:nvram",
                                                        "files:qg-settings-guest",
                                                        "component:early-inputs",
                                                        "files:early-inputs-init",
                                                        "files:usb-drive-fstab",
                                                        "files:vendor-overlay",
                                                        "patched:QGBus",
                                                        "patched:SystemPolicy"}));
        const Json expected_stock_statusbar = {
                {"artifact", "patched:api30-stock-statusbar"},
                {"type", "file"},
                {"target", "/system/system_ext/priv-app/SystemUI/SystemUI.apk"},
                {"mode", "0644"}};
        check(std::count(acquired_plan.at("system").begin(), acquired_plan.at("system").end(),
                         expected_stock_statusbar) == 1);
        const Json expected_phone = {
                {"artifact", "patched:BluetoothPhone"},
                {"type", "apk"},
                {"target",
                 "/system/priv-app/BluetoothPhone-release-signed/BluetoothPhone-release-signed.apk"},
                {"package", "com.qinggan.bluetoothphone"},
                {"mode", "0644"}};
        check(std::count(acquired_plan.at("system").begin(), acquired_plan.at("system").end(),
                         expected_phone) == 1 &&
              acquired_apks.count("patched:BluetoothPhone") == 0);
        // System-only publication retains userdata: a PM-only candidate APK would not reach the
        // accepted machine.
        {
            auto old_delivery = acquired_api30;

            for (auto &entry : old_delivery["install"]) {
                if (entry.at("artifact") == "patched:BluetoothPhone") {
                    entry = {{"artifact", "patched:BluetoothPhone"}, {"type", "apk"}};
                }
            }

            const auto old_plan = android_candidate_install_plan(old_delivery, acquired_artifacts);
            check(std::count(old_plan.at("apks").begin(), old_plan.at("apks").end(),
                             Json({{"artifact", "patched:BluetoothPhone"}, {"type", "apk"}})) == 1);
            check(std::none_of(old_plan.at("system").begin(), old_plan.at("system").end(),
                               [](const auto &entry) {
                                   return entry.at("artifact") == "patched:BluetoothPhone";
                               }));
        }
        // Actual preserved DATA version1 must be replaced through the regenerated SYSTEM graph.
        const Json expected_setting = {
                {"artifact", "patched:Setting"},
                {"type", "apk"},
                {"target", "/system/priv-app/Setting-release-signed/Setting-release-signed.apk"},
                {"package", "com.qinggan.app.setting"},
                {"mode", "0644"}};
        check(std::count(acquired_plan.at("system").begin(), acquired_plan.at("system").end(),
                         expected_setting) == 1);
        check(std::none_of(acquired_plan.at("apks").begin(), acquired_plan.at("apks").end(),
                           [](const auto &e) {
                               return e.at("artifact") == "patched:Setting";
                           }));
        {
            auto old_setting = acquired_api30;

            for (auto &e : old_setting["install"]) {
                if (e.at("artifact") == "patched:Setting") {
                    e = {{"artifact", "patched:Setting"}, {"type", "apk"}};
                }
            }

            const auto old_plan = android_candidate_install_plan(old_setting, acquired_artifacts);
            check(std::none_of(old_plan.at("system").begin(), old_plan.at("system").end(),
                               [](const auto &e) {
                                   return e.at("artifact") == "patched:Setting";
                               }));
            check(std::count(old_plan.at("apks").begin(), old_plan.at("apks").end(),
                             Json({{"artifact", "patched:Setting"}, {"type", "apk"}})) == 1);
        }
        const Json expected_media = {
                {"artifact", "patched:QGMedia"},
                {"type", "apk"},
                {"target", "/system/priv-app/qgmedia-release-signed/qgmedia-release-signed.apk"},
                {"package", "com.qinggan.media"}};
        check(std::count(acquired_plan.at("system").begin(), acquired_plan.at("system").end(),
                         expected_media) == 1);
        check(acquired_api30.at("original").at("QGMedia").at("sha256") ==
                      "533a0b0dc5ccbe91a42847fac20c5735bd8d78a28bbb980a6bf365dd5ed0fba0" &&
              acquired_api30.at("original").at("QGMedia").at("source").at("package") ==
                      "com.qinggan.media");
        check(acquired_api30.at("patches").at("QGMedia") ==
              Json({{"input", "original:QGMedia"},
                    {"type", "apk"},
                    {"steps",
                     Json::array({"api30-media-runtime.json", "api30-media-cloud-availability.json",
                                  "api30-media-notification-actions.json",
                                  "api30-usb-player.json"})}}));
        check(std::ranges::count(acquired_plan.at("system"),
                                 Json({{"artifact", "files:nvram"},
                                       {"type", "file"},
                                       {"target", "/system/etc/nvram"},
                                       {"mode", "0644"},
                                       {"context", "u:object_r:system_file:s0"}})) == 1);
        const auto launcher_policy_file =
                root / "profiles/free-11-chinese-20260731-7.3.1/files" /
                acquired_api30.at("files").at("launcher-privapp").at("file").get<std::string>();
        const std::string expected_privapp = R"xml(<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.qinggan.app.launcher">
        <permission name="android.permission.BIND_APPWIDGET"/>
    </privapp-permissions>
    <privapp-permissions package="com.qinggan.app.hiboard">
        <permission name="android.permission.BIND_APPWIDGET"/>
    </privapp-permissions>
    <privapp-permissions package="com.qinggan.audiopolicy.service">
        <permission name="android.permission.READ_LOGS"/>
        <permission name="android.permission.BATTERY_STATS"/>
    </privapp-permissions>
    <privapp-permissions package="com.qinggan.bluetoothphone">
        <permission name="android.permission.CHANGE_CONFIGURATION"/>
        <permission name="android.permission.MOUNT_UNMOUNT_FILESYSTEMS"/>
        <permission name="android.permission.READ_LOGS"/>
    </privapp-permissions>
    <privapp-permissions package="com.qinggan.app.setting">
        <permission name="android.permission.ACCESS_CACHE_FILESYSTEM"/>
        <permission name="android.permission.DELETE_CACHE_FILES"/>
        <permission name="android.permission.INTERACT_ACROSS_USERS"/>
        <permission name="android.permission.OVERRIDE_WIFI_CONFIG"/>
        <permission name="android.permission.READ_LOGS"/>
        <permission name="android.permission.REBOOT"/>
    </privapp-permissions>
    <privapp-permissions package="com.baidu.naviauto">
        <permission name="android.permission.READ_LOGS"/>
        <permission name="android.permission.MOUNT_UNMOUNT_FILESYSTEMS"/>
        <permission name="android.permission.INTERACT_ACROSS_USERS"/>
        <permission name="android.permission.WRITE_MEDIA_STORAGE"/>
    </privapp-permissions>
    <privapp-permissions package="com.qinggan.systempolicy">
        <permission name="android.permission.SET_TIME"/>
        <permission name="android.permission.SET_TIME_ZONE"/>
    </privapp-permissions>
    <privapp-permissions package="com.qinggan.QGBus">
        <permission name="android.permission.MANAGE_USERS"/>
    </privapp-permissions>
</permissions>
)xml";
        std::ifstream launcher_policy_source(launcher_policy_file);
        const std::string launcher_policy((std::istreambuf_iterator<char>(launcher_policy_source)),
                                          {});
        const auto expected_privapp_metadata = Json{
                {"file", "files/voyemu-privapp.xml"},
                {"packages",
                 Json{{"com.baidu.naviauto",
                       Json::array({"android.permission.READ_LOGS",
                                    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                                    "android.permission.INTERACT_ACROSS_USERS",
                                    "android.permission.WRITE_MEDIA_STORAGE"})},
                      {"com.qinggan.systempolicy",
                       Json::array({"android.permission.SET_TIME",
                                    "android.permission.SET_TIME_ZONE"})},
                      {"com.qinggan.QGBus", Json::array({"android.permission.MANAGE_USERS"})},
                      {"com.qinggan.app.launcher",
                       Json::array({"android.permission.BIND_APPWIDGET"})},
                      {"com.qinggan.app.hiboard",
                       Json::array({"android.permission.BIND_APPWIDGET"})},
                      {"com.qinggan.audiopolicy.service",
                       Json::array({"android.permission.READ_LOGS",
                                    "android.permission.BATTERY_STATS"})},
                      {"com.qinggan.bluetoothphone",
                       Json::array({"android.permission.CHANGE_CONFIGURATION",
                                    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                                    "android.permission.READ_LOGS"})},
                      {"com.qinggan.app.setting",
                       Json::array({"android.permission.ACCESS_CACHE_FILESYSTEM",
                                    "android.permission.DELETE_CACHE_FILES",
                                    "android.permission.INTERACT_ACROSS_USERS",
                                    "android.permission.OVERRIDE_WIFI_CONFIG",
                                    "android.permission.READ_LOGS",
                                    "android.permission.REBOOT"})}}},
                {"scope",
                 "exact manifest-requested BIND_APPWIDGET for Launcher/Hiboard and READ_LOGS/BATTERY_STATS for original AudioPolicy and CHANGE_CONFIGURATION/MOUNT_UNMOUNT_FILESYSTEMS/READ_LOGS for original BluetoothPhone and exact six manifest-requested API30 signature|privileged permissions for original Setting; privileged permission enforcement remains enabled; original signed Navi retains exactly its four manifest-requested privileged capabilities already requested by the accepted platform-signed Navi and original SystemPolicy and QGBus retain exactly their manifest-requested SET_TIME/SET_TIME_ZONE and MANAGE_USERS"}};
        const auto finite_privapp = [&](const Json &definition, const std::string &xml) {
            return definition.at("compatibility").contains("privapp_whitelist") &&
                   definition.at("compatibility").at("privapp_whitelist") ==
                           expected_privapp_metadata &&
                   xml == expected_privapp;
        };
        // API30 stops system_server when an installed privileged APK lacks a requested privileged
        // permission.
        check(finite_privapp(acquired_api30, launcher_policy));
        check(acquired_api30.at("original").at("Hiboard").at("sha256") ==
              "902562587355d9e48d3878773da7955cd5a793c03e5ba6e5b595a317c7ec0f39");
        check(!finite_privapp(acquired_api30, ""));
        auto foreign_privapp = launcher_policy;
        foreign_privapp.replace(foreign_privapp.find("com.qinggan.app.hiboard"),
                                std::string("com.qinggan.app.hiboard").size(),
                                "com.qinggan.app.foreign");
        check(!finite_privapp(acquired_api30, foreign_privapp));
        auto extra_privapp = launcher_policy;
        extra_privapp.insert(extra_privapp.find("    </privapp-permissions>"),
                             "        <permission name=\"android.permission.REBOOT\"/>\n");
        check(!finite_privapp(acquired_api30, extra_privapp));
        auto missing_hiboard_permission = launcher_policy;
        const auto hiboard_begin = missing_hiboard_permission.find(
                "    <privapp-permissions package=\"com.qinggan.app.hiboard\">");
        missing_hiboard_permission.erase(
                hiboard_begin,
                missing_hiboard_permission.find("    </privapp-permissions>\n", hiboard_begin) +
                        std::string("    </privapp-permissions>\n").size() - hiboard_begin);
        check(!finite_privapp(acquired_api30, missing_hiboard_permission));
        auto missing_audio_policy = launcher_policy;
        const auto audio_begin = missing_audio_policy.find(
                "    <privapp-permissions package=\"com.qinggan.audiopolicy.service\">");
        missing_audio_policy.erase(
                audio_begin,
                missing_audio_policy.find("    </privapp-permissions>\n", audio_begin) +
                        std::string("    </privapp-permissions>\n").size() - audio_begin);
        check(!finite_privapp(acquired_api30, missing_audio_policy));

        for (const auto *permission :
             {"android.permission.READ_LOGS", "android.permission.BATTERY_STATS"}) {
            auto missing_permission = launcher_policy;
            const std::string row = "        <permission name=\"" + std::string(permission) +
                                    "\"/>\n";
            const auto at = missing_permission.find(row);
            check(at != std::string::npos);
            missing_permission.erase(at, row.size());
            check(!finite_privapp(acquired_api30, missing_permission));
        }

        // Reproduce the exact three Phone grants rejected by API30
        // PermissionManagerService.systemReady.
        for (const auto *permission :
             {"android.permission.CHANGE_CONFIGURATION",
              "android.permission.MOUNT_UNMOUNT_FILESYSTEMS", "android.permission.READ_LOGS"}) {
            auto missing_phone = launcher_policy;
            const auto begin = missing_phone.find(
                    "    <privapp-permissions package=\"com.qinggan.bluetoothphone\">");
            check(begin != std::string::npos);
            const std::string row = "        <permission name=\"" + std::string(permission) +
                                    "\"/>\n";
            const auto at = missing_phone.find(row, begin);
            check(at != std::string::npos);
            missing_phone.erase(at, row.size());
            check(!finite_privapp(acquired_api30, missing_phone));
        }

        for (const auto &permission :
             expected_privapp_metadata.at("packages").at("com.qinggan.app.setting")) {
            auto missing_setting = launcher_policy;
            const auto begin = missing_setting.find(
                    "    <privapp-permissions package=\"com.qinggan.app.setting\">");
            check(begin != std::string::npos);
            const std::string row = "        <permission name=\"" + permission.get<std::string>() +
                                    "\"/>\n";
            const auto at = missing_setting.find(row, begin);
            check(at != std::string::npos);
            missing_setting.erase(at, row.size());
            check(!finite_privapp(acquired_api30, missing_setting));
        }

        auto wrong_privapp_pin = acquired_api30;
        wrong_privapp_pin["compatibility"]["privapp_whitelist"]["sha256"] = std::string(64, '0');
        check(!finite_privapp(wrong_privapp_pin, launcher_policy));
        {
            auto missing_policy = acquired_artifacts;
            missing_policy.erase("files:launcher-privapp");
            bool refused = false;
            try {
                android_candidate_install_plan(acquired_api30, missing_policy);
            } catch (...) {
                refused = true;
            }

            check(refused);
        }
        unsigned launcher_policy_count = 0;
        std::size_t launcher_policy_index = 0, launcher_system_index = 0;

        for (std::size_t i = 0; i < acquired_plan.at("system").size(); ++i) {
            const auto &entry = acquired_plan.at("system").at(i);

            if (entry.at("artifact") == "files:launcher-privapp") {
                ++launcher_policy_count;
                launcher_policy_index = i;
                check(entry == Json({{"artifact", "files:launcher-privapp"},
                                     {"type", "file"},
                                     {"target", "/system/etc/permissions/voyemu-privapp.xml"},
                                     {"mode", "0644"}}));
            }

            if (entry.at("artifact") == "patched:Launcher") {
                launcher_system_index = i;
            }
        }

        check(launcher_policy_count == 1 && launcher_policy_index < launcher_system_index);

        for (std::size_t i = 0; i < acquired_plan.at("system").size(); ++i) {
            if (acquired_plan.at("system").at(i).at("artifact") == "patched:Hiboard") {
                check(launcher_policy_index < i);
            }
        }

        Json privileged, keymanager, hiboard;
        unsigned privileged_count = 0;

        for (const auto &entry : acquired_plan.at("system")) {
            if (entry.at("type") == "apk") {
                ++privileged_count;

                if (entry.at("artifact") == "patched:Launcher") {
                    check(privileged.is_null());
                    privileged = entry;
                } else if (entry.at("artifact") == "patched:KeyManagerService") {
                    check(keymanager.is_null());
                    keymanager = entry;
                } else if (entry.at("artifact") == "patched:QGMedia") {
                    check(entry == expected_media);
                } else if (entry.at("artifact") == "patched:AudioPolicy") {
                    check(entry ==
                          Json({{"artifact", "patched:AudioPolicy"},
                                {"type", "apk"},
                                {"target",
                                 "/system/priv-app/AudioPolicy-release/AudioPolicy-release.apk"},
                                {"package", "com.qinggan.audiopolicy.service"}}));
                } else if (entry.at("artifact") == "component:oem-power") {
                    check(entry ==
                          Json({{"artifact", "component:oem-power"},
                                {"type", "apk"},
                                {"target", "/system/priv-app/VoyemuOemPower/VoyemuOemPower.apk"},
                                {"package", "com.voyemu.oem"}}));
                } else if (entry.at("artifact") == "patched:BluetoothPhone") {
                    check(entry == expected_phone);
                } else if (entry.at("artifact") == "component:canbus") {
                    check(entry == expected_canbus);
                } else if (entry.at("artifact") == "patched:Setting") {
                    check(entry == expected_setting);
                } else if (entry.at("artifact") == "original:Navi") {
                    check(entry ==
                          Json({{"artifact", "original:Navi"},
                                {"type", "apk"},
                                {"target", "/system/priv-app/dueros/Dueros-h97c-signed.apk"},
                                {"package", "com.baidu.naviauto"}}));
                } else if (entry.at("artifact") == "patched:ThirdScreen") {
                    check(entry ==
                          Json({{"artifact", "patched:ThirdScreen"},
                                {"type", "apk"},
                                {"target",
                                 "/system/priv-app/ThirdScreen-release-signed/ThirdScreen-release-signed.apk"},
                                {"package", "com.qinggan.app.thirdscreen"}}));
                } else if (entry.at("artifact") == "patched:SystemPolicy") {
                    check(entry ==
                          Json({{"artifact", "patched:SystemPolicy"},
                                {"type", "apk"},
                                {"target",
                                 "/system/priv-app/SystemPolicy-release/SystemPolicy-release.apk"},
                                {"package", "com.qinggan.systempolicy"}}));
                } else if (entry.at("artifact") == "patched:QGBus") {
                    check(entry ==
                          Json({{"artifact", "patched:QGBus"},
                                {"type", "apk"},
                                {"target", "/system/priv-app/QGBus-release/QGBus-release.apk"},
                                {"package", "com.qinggan.QGBus"}}));
                } else {
                    check(entry.at("artifact") == "patched:Hiboard" && hiboard.is_null());
                    hiboard = entry;
                }
            }
        }

        check(privileged_count == 13 && privileged.at("package") == "com.qinggan.app.launcher" &&
              privileged.at("target") ==
                      "/system/priv-app/Launcher-release-signed/Launcher-release-signed.apk");
        check(keymanager ==
                      Json({{"artifact", "patched:KeyManagerService"},
                            {"type", "apk"},
                            {"target",
                             "/system/priv-app/KeyManagerService-release/KeyManagerService-release.apk"},
                            {"package", "com.qinggan.keymanager.service"}}) &&
              keymanager.value("mode", std::string("0644")) == "0644");
        check(hiboard ==
                      Json({{"artifact", "patched:Hiboard"},
                            {"type", "apk"},
                            {"target",
                             "/system/priv-app/Hiboard-release-signed/Hiboard-release-signed.apk"},
                            {"package", "com.qinggan.app.hiboard"}}) &&
              hiboard.value("mode", std::string("0644")) == "0644");
        {
            auto missing_hiboard = acquired_artifacts;
            missing_hiboard.erase("patched:Hiboard");
            bool refused = false;
            try {
                android_candidate_install_plan(acquired_api30, missing_hiboard);
            } catch (...) {
                refused = true;
            }

            check(refused);
        }
        unsigned platform_count = 0;

        for (const auto &entry : acquired_plan.at("system")) {
            if (entry.at("artifact") == "component:wheel-platform") {
                ++platform_count;
                check(entry == Json({{"artifact", "component:wheel-platform"},
                                     {"type", "file"},
                                     {"target", "/system/framework/voyemu-free-wheel.jar"},
                                     {"mode", "0644"}}));
            }
        }

        check(platform_count == 1);
        auto bad_privileged = [&](Json entry) {
            auto value = acquired_api30;

            for (auto &install : value["install"]) {
                if (install.at("artifact") == "patched:Launcher") {
                    install = entry;
                }
            }

            bool refused = false;
            try {
                android_candidate_install_plan(value, acquired_artifacts);
            } catch (...) {
                refused = true;
            }

            check(refused);
        };

        for (const auto &target :
             {"/data/app/Launcher.apk", "/system/app/Launcher/Launcher.apk",
              "/system/priv-app/../Launcher.apk", "/system/priv-app/Launcher.jar",
              "/system/priv-app/Launcher/file.jar", "/system/priv-app/Launcher/nested/file.apk"}) {
            auto bad = privileged;
            bad["target"] = target;
            bad_privileged(bad);
        }

        for (const auto &mode : {"0777", "0755", "0600"}) {
            auto bad = privileged;
            bad["mode"] = mode;
            bad_privileged(bad);
        }

        for (const auto *owner : {"uid", "gid"}) {
            auto bad = privileged;
            bad[owner] = 1000;
            bad_privileged(bad);
        }

        {
            auto bad = privileged;
            bad["mutable"] = true;
            bad_privileged(bad);
            bad = privileged;
            bad.erase("package");
            bad_privileged(bad);
            bad = privileged;
            bad["package"] = "not/a/package";
            bad_privileged(bad);
        }
        {
            auto duplicate = acquired_api30;
            duplicate["install"].push_back(privileged);
            bool refused = false;
            try {
                android_candidate_install_plan(duplicate, acquired_artifacts);
            } catch (...) {
                refused = true;
            }

            check(refused);
        }

        for (const auto &tree_target :
             {"/system/priv-app", "/system/priv-app/Launcher-release-signed"}) {
            auto overlap = acquired_api30;
            auto tree_artifacts = acquired_artifacts;
            overlap["install"].push_back(
                    {{"artifact", "fixture:tree"}, {"type", "tree"}, {"target", tree_target}});
            tree_artifacts["fixture:tree"] = {{"directory", "/fixture/tree"},
                                              {"files", Json::object()}};
            bool refused = false;
            try {
                android_candidate_install_plan(overlap, tree_artifacts);
            } catch (...) {
                refused = true;
            }

            check(refused);
        }

        const std::string privileged_package = "com.qinggan.app.launcher",
                          privileged_target = privileged.at("target").get<std::string>();
        const auto package_state = [&](std::string code, std::string flags,
                                       std::string private_flags) {
            return "Packages:\n  Package [" + privileged_package +
                   "] (fixture):\n    codePath=" + code + "\n    flags=[ " + flags +
                   " ]\n    privateFlags=[ " + private_flags + " ]\nShared users:\n";
        };
        const auto system_state = package_state(
                std::filesystem::path(privileged_target).parent_path().generic_string(),
                "SYSTEM HAS_CODE",
                "PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION PRIVILEGED PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING");
        check(android_candidate_privileged_apk_check(privileged, privileged_package,
                                                     privileged_target, system_state)
                      .at("passed") == true);
        const std::string updated_target = "/data/app/fixture/com.qinggan.app.launcher/base.apk";
        const auto updated_state = package_state(
                std::filesystem::path(updated_target).parent_path().generic_string(),
                "SYSTEM UPDATED_SYSTEM_APP HAS_CODE",
                "PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION PRIVILEGED PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING");
        check(android_candidate_privileged_apk_check(privileged, privileged_package, updated_target,
                                                     updated_state)
                      .at("updated_system_app") == true);
        const auto refuse_state = [&](const std::string &effective, const std::string &dump) {
            bool refused = false;
            try {
                android_candidate_privileged_apk_check(privileged, privileged_package, effective,
                                                       dump);
            } catch (...) {
                refused = true;
            }

            check(refused);
        };
        refuse_state(
                privileged_target,
                package_state(
                        std::filesystem::path(privileged_target).parent_path().generic_string(),
                        "HAS_CODE",
                        "PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION PRIVILEGED PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING"));
        refuse_state(
                privileged_target,
                package_state(
                        std::filesystem::path(privileged_target).parent_path().generic_string(),
                        "SYSTEM HAS_CODE", ""));
        refuse_state(
                updated_target,
                package_state(
                        std::filesystem::path(updated_target).parent_path().generic_string(),
                        "SYSTEM HAS_CODE",
                        "PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION PRIVILEGED PRIVATE_FLAG_ALLOW_NATIVE_HEAP_POINTER_TAGGING"));
        refuse_state(updated_target, system_state);
        refuse_state(privileged_target, system_state + system_state);
        refuse_state(
                privileged_target,
                package_state(
                        std::filesystem::path(privileged_target).parent_path().generic_string(),
                        "SYSTEM HAS_CODE", "PRIVATE_FLAG_PRIVILEGED"));
        const auto hidden =
                "\nHidden system packages:\n  Package [" + privileged_package +
                "] (base):\n    codePath=" +
                std::filesystem::path(privileged_target).parent_path().generic_string() +
                "\n    flags=[ SYSTEM ]\n    privateFlags=[ PRIVILEGED ]\n";
        auto active_updated = updated_state;
        active_updated.resize(active_updated.find("Shared users:"));
        check(android_candidate_privileged_apk_check(privileged, privileged_package, updated_target,
                                                     active_updated + hidden)
                      .at("updated_system_app") == true);
        refuse_state(
                updated_target,
                package_state(std::filesystem::path(updated_target).parent_path().generic_string(),
                              "HAS_CODE", "") +
                        hidden);
        refuse_state(
                privileged_target,
                "Packages:\n  Package [other.package] (fixture):\n    codePath=/system/priv-app/Other\n    flags=[ SYSTEM ]\n    privateFlags=[ PRIVATE_FLAG_PRIVILEGED ]\n");
        const Json home_priorities = {
                {"com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity", 100},
                {"com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity",
                 10}};
        check(acquired_api30.at("verify").at("homePriorities") == home_priorities);
        const std::string priorities =
                "2 activities found:\n  Activity #0:\n    priority=100 preferredOrder=0 match=0x108000 isDefault=true\n    com.qinggan.app.launcher/.activity.MainActivity\n  Activity #1:\n    priority=10 preferredOrder=0 match=0x108000 isDefault=true\n    com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n";
        check(android_candidate_home_priorities_ready(home_priorities, priorities));
        auto clamped = priorities;
        clamped.replace(clamped.find("priority=100"), 12, "priority=0");
        check(!android_candidate_home_priorities_ready(home_priorities, clamped));
        check(!android_candidate_home_priorities_ready(
                home_priorities,
                priorities +
                        "priority=100\ncom.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity\n"));
        check(!android_candidate_home_priorities_ready(
                home_priorities,
                "priority=100\ncom.qinggan.app.launcher/.activity.MainActivity\n"));
        check(!android_candidate_home_priorities_ready(
                home_priorities, priorities + "priority=0\nother.package/.Home\n"));
        auto ambiguous = home_priorities;
        ambiguous["com.qinggan.app.launcher/.activity.MainActivity"] = 100;
        check(!android_candidate_home_priorities_ready(ambiguous, priorities));
        check(!android_candidate_home_priorities_ready(
                home_priorities, "com.qinggan.app.launcher/.activity.MainActivity\n"));
        check(!android_candidate_home_priorities_ready(home_priorities,
                                                       "priority=0\n" + priorities));
        std::set<std::string> native_policies;
        unsigned keymanager_contexts = 0;

        for (const auto &entry : acquired_plan.at("system")) {
            const auto ref = entry.at("artifact").get<std::string>();

            if (ref.starts_with("patched:selinux-")) {
                check(native_policies.insert(ref).second);
            }

            if (ref == "patched:keymanager-contexts-api30") {
                ++keymanager_contexts;
                check(entry.at("type") == "file" &&
                      entry.at("target") == "/system/etc/selinux/plat_service_contexts");
            }
        }

        check(native_policies == std::set<std::string>({"patched:selinux-hash-api30"}) &&
              keymanager_contexts == 1);

        for (const auto &field : {"package", "revision", "url", "sha256"}) {
            auto invalid_api = api30;
            invalid_api["android"][field] = "unregistered";
            bool refused = false;
            try {
                android_candidate_api(invalid_api);
            } catch (...) {
                refused = true;
            }

            check(refused);
        }

        const auto api30_boot_paths = android_candidate_boot_cache_paths(acquired_api30);
        check(api30_boot_paths.size() == 18);

        for (const auto &path : api30_boot_paths) {
            check(path.starts_with("/system/framework/arm64/boot-") &&
                  !path.ends_with(".art.rel") && path.find("/apex/") == std::string::npos);
        }

        {
            const Json multilib = {
                    {"id", "test-x86-vehicle"},
                    {"platform", "passion"},
                    {"android", {{"package", "system-images;android-30;default;x86_64"}}},
                    {"components", {{"view-observation", "components/view-observation"}}},
                    {"install", Json::array({{{"artifact", "component:view-observation"},
                                              {"type", "file"},
                                              {"target", "/system/framework/framework.jar"},
                                              {"mode", "0644"}}})}};
            const auto paths = api30_framework_boot::paths(multilib);
            check(paths.size() == 36 &&
                  std::set<std::string>(paths.begin(), paths.end()).size() == paths.size());
            Json events = Json::array();

            for (const std::string isa : {"x86", "x86_64"}) {
                const auto command = api30_framework_boot::command(multilib, isa);
                check(command.front() == (isa == "x86" ? "/apex/com.android.art/bin/dex2oat32"
                                                       : "/apex/com.android.art/bin/dex2oat64"));
                check(std::count(command.begin(), command.end(), "--instruction-set=" + isa) == 1);
                check(std::count(paths.begin(), paths.end(),
                                 "/system/framework/" + isa + "/boot-framework.art") == 1);
                check(std::count(command.begin(), command.end(),
                                 "--image=/system/framework/" + isa + "/boot.art") == 1);
                check(android_candidate_command_log(command) ==
                      (isa == "x86" ? "boot-image-compile-x86.log" : "boot-image-compile.log"));
                events.push_back(
                        {{"phase", "boot-art-compiled"}, {"files", 18}, {"command", command}});
            }

            check(api30_framework_boot::compiled(multilib, events));
            events[0] = events[1];
            check(!api30_framework_boot::compiled(multilib, events));
            events.erase(events.begin());
            check(!api30_framework_boot::compiled(multilib, events));
        }

        const auto api30_boot_command = android_candidate_boot_image_command(acquired_api30);
        check(api30_boot_command.front() == "/apex/com.android.art/bin/dex2oat64");
        check(std::count(api30_boot_command.begin(), api30_boot_command.end(),
                         "--boot-image=/apex/com.android.art/javalib/boot.art") == 1);
        check(std::count(api30_boot_command.begin(), api30_boot_command.end(),
                         "--image=/system/framework/arm64/boot.art") == 1);
        check(std::count(api30_boot_command.begin(), api30_boot_command.end(),
                         "-Xbootclasspath:" + api30_framework_boot::classpath()) == 1);
        check(std::count(api30_boot_command.begin(), api30_boot_command.end(),
                         "-Xbootclasspath-locations:" + api30_framework_boot::classpath()) == 1);
        check(std::count_if(api30_boot_command.begin(), api30_boot_command.end(),
                            [](const auto &arg) {
                                return arg.starts_with("--dex-file=");
                            }) == 6);
        check(android_candidate_boot_relocation_command(acquired_api30).empty());
        check(android_candidate_command_log(api30_boot_command) == "boot-image-compile.log");
        {
            const auto original = android_candidate_boot_image_command(acquired_api30);
            const std::string nonce(32, 'a');
            auto diagnostic = android_candidate_boot_compile_diagnostic_command(acquired_api30,
                                                                                nonce);
            check(diagnostic.size() == original.size() + 6 &&
                  std::vector<std::string>(diagnostic.begin() + 6, diagnostic.end()) == original);

            for (const auto &argument : diagnostic) {
                check(!android_shell_quote(argument)
                               .empty()); // Same quote boundary as Candidate::shell.
            }

            check(android_candidate_command_log(diagnostic) == "boot-image-compile.log");
            check(android_candidate_command_log(
                          std::vector<std::string>{
                                  "shell",
                                  std::string(2048, 'x') +
                                          " /apex/com.android.art/bin/dex2oat64 --image=/system/framework/arm64/boot.art"})
                          .empty());

            for (unsigned mode = 0; mode < 6; ++mode) {
                auto malformed = diagnostic;

                if (mode == 0) {
                    malformed[2] += " ";
                }

                if (mode == 1) {
                    malformed[3] = "foreign";
                }

                if (mode == 2) {
                    malformed[4] = "../foreign";
                }

                if (mode == 3) {
                    malformed[5] = "/foreign";
                }

                if (mode == 4) {
                    malformed[6] = "sha256sum";
                }

                if (mode == 5) {
                    malformed.resize(6);
                }

                check(android_candidate_command_log(malformed).empty());
            }

            check(diagnostic[2].find("--pid=\"$pid\"") != std::string::npos &&
                  diagnostic[2].find("-t 200") != std::string::npos &&
                  diagnostic[2].find("head -c 65536") != std::string::npos);
            check(diagnostic[2].find("/proc/uptime") != std::string::npos &&
                  diagnostic[2].find("exit \"$status\"") != std::string::npos);
            bool refused = false;
            try {
                android_candidate_boot_compile_diagnostic_command(acquired_api30, "../foreign");
            } catch (...) {
                refused = true;
            }

            check(refused);
#ifndef _WIN32
            const auto fixture = root / ".local/build/tmp" /
                                 ("art-diagnostic-test-" + random_token());
            ensure_private_directory(fixture);
            struct Cleanup {
                std::filesystem::path p;

                ~Cleanup() {
                    std::error_code error;
                    std::filesystem::remove_all(p, error);
                }
            } cleanup{fixture};
            const auto logcat = fixture / "logcat", args = fixture / "logcat.args";
            {
                std::ofstream file(logcat);
                file << "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$ART_LOGCAT_ARGS\"\nprintf 'PID-scoped-fixture-log\\n'\n";
            }
            std::filesystem::permissions(logcat, std::filesystem::perms::owner_all);

            for (const int status : {17, 0}) {
                auto command = diagnostic;
                command[5] = fixture.string();
                command.resize(6);
                command.insert(command.end(), {"/bin/sh", "-c",
                                               "printf deliberate-compiler-stderr >&2; exit " +
                                                       std::to_string(status)});
                std::string line;

                for (const auto &argument : command) {
                    if (!line.empty()) {
                        line += ' ';
                    }

                    line += android_shell_quote(argument);
                }

                ProcessSpec spec;
                spec.executable = "/bin/sh";
                spec.arguments = {"-c", line};
                spec.directory = fixture;
                spec.environment = {{"PATH", fixture.string() + ":/usr/bin:/bin"},
                                    {"ART_LOGCAT_ARGS", args.string()}};
                const auto result = execute(spec, 5000, 256 * 1024);
                check(!result.timed_out && result.exit_code == status &&
                      result.output.find("deliberate-compiler-stderr") != std::string::npos &&
                      result.output.find("PID-scoped-fixture-log") != std::string::npos);
                std::smatch marker;
                check(std::regex_search(result.output, marker,
                                        std::regex("VOYEMU_ART_END " + nonce + " ([0-9]+) [^ ]+ " +
                                                   std::to_string(status))));
                std::ifstream file(args);
                const std::string captured{std::istreambuf_iterator<char>(file), {}};
                check(captured.find("--pid=" + marker[1].str() + "\n") != std::string::npos &&
                      captured.find("-t\n200\n") != std::string::npos);
            }
#endif
        }

        for (const auto *field : {"platform", "components", "install"}) {
            auto wrong_boot = acquired_api30;
            wrong_boot[field] = field == std::string("platform")     ? Json("qinggan09")
                                : field == std::string("components") ? Json::object()
                                                                     : Json::array();
            bool refused = false;
            try {
                android_candidate_boot_cache_paths(wrong_boot);
            } catch (...) {
                refused = true;
            }

            if (field == std::string("install")) {
                check(!refused && android_candidate_boot_cache_paths(wrong_boot).empty());
            } else {
                check(refused);
            }
        }

        auto wrong_art = profile;
        wrong_art["android"] = api30["android"];
        bool api30_art_refused = false;
        try {
            android_candidate_boot_cache_paths(wrong_art);
        } catch (...) {
            api30_art_refused = true;
        }

        check(api30_art_refused);
        auto wrong_server = api30;
        wrong_server["configure"]["systemServerClasspath"] =
                Json::array({"/system/framework/services.jar"});
        bool api30_server_refused = false;
        try {
            android_candidate_system_server_commands(wrong_server);
        } catch (...) {
            api30_server_refused = true;
        }

        check(api30_server_refused);
        const auto boot_cache = android_candidate_boot_cache_paths(profile);
        check(boot_cache.size() == 180);
        std::set<std::string> cache_unique(boot_cache.begin(), boot_cache.end());
        check(cache_unique.size() == 180 &&
              cache_unique.contains("/system/framework/arm64/boot-framework.oat") &&
              cache_unique.contains("/system/framework/boot.vdex") &&
              cache_unique.contains("/system/framework/arm64/boot.art.rel") &&
              cache_unique.contains("/system/framework/arm/boot-framework.art.rel") &&
              cache_unique.contains("/system/framework/boot-core-libart.art.rel"));
        auto partial_boot = profile;

        for (auto it = partial_boot["install"].begin(); it != partial_boot["install"].end(); ++it) {
            if (it->value("target", std::string{}) == "/system/framework/core-oj.jar") {
                partial_boot["install"].erase(it);
                break;
            }
        }

        bool partial_refused = false;
        try {
            android_candidate_boot_cache_paths(partial_boot);
        } catch (...) {
            partial_refused = true;
        }

        check(partial_refused);
        check(android_candidate_boot_cache_paths(Json{{"install", Json::array()}}).empty());
        const auto boot_command = android_candidate_boot_image_command(profile);
        check(boot_command.front() == "/system/bin/dex2oat");
        check(std::count(boot_command.begin(), boot_command.end(), "--compact-dex-level=fast") ==
              1);
        check(std::count(boot_command.begin(), boot_command.end(), "--base=0x70000000") == 1);
        check(boot_command.size() == 53);
        check(std::count(boot_command.begin(), boot_command.end(), "--copy-dex-files=always") == 1);
        check(boot_command[23] == "--dex-file=/system/framework/core-oj.jar" &&
              boot_command[51] == "--dex-file=/system/framework/android.test.base.jar");

        for (const auto &arg : boot_command) {
            check(arg.find("verify:none") == std::string::npos);
        }

        check(android_candidate_boot_image_command(Json{{"install", Json::array()}}).empty());
        const auto relocation_command = android_candidate_boot_relocation_command(profile);
        check(relocation_command ==
              std::vector<std::string>{
                      "/system/bin/env", "ANDROID_ROOT=/system",
                      "ANDROID_DATA=/system/framework/arm64", "/system/bin/patchoat",
                      "--input-image-location=/system/framework/boot.art",
                      "--output-image-relocation-directory=/system/framework/arm64",
                      "--instruction-set=arm64", "--base-offset-delta=0x10000000"});
        check(android_candidate_boot_relocation_command(Json{{"install", Json::array()}}).empty());
        auto server_profile = profile;
        server_profile["configure"]["systemServerClasspath"] = Json::array(
                {"/system/framework/services.jar", "/system/framework/ethernet-service.jar",
                 "/system/framework/wifi-service.jar",
                 "/system/framework/com.android.location.provider.jar"});

        for (const auto &path : server_profile["configure"]["systemServerClasspath"]) {
            server_profile["install"].push_back({{"type", "file"}, {"target", path}});
        }

        const auto server_commands = android_candidate_system_server_commands(server_profile);
        check(server_commands.size() == 4 && server_commands[0][11] == "--class-loader-context=&" &&
              server_commands[1][11] == "--class-loader-context=&");
        check(server_commands[3][3] ==
              "--oat-file=/system/framework/oat/arm64/com.android.location.provider.odex");

        for (const auto &command : server_commands) {
            check(std::count(command.begin(), command.end(), "--abort-on-hard-verifier-error") ==
                  1);
            check(std::count(command.begin(), command.end(), "--abort-on-soft-verifier-error") ==
                  0);
            check(std::count(command.begin(), command.end(), "--image-format=lz4") == 1);
        }

        check(server_commands[0][1] == "--dex-file=/system/framework/services.jar");
        auto bad_server = server_profile;
        std::swap(bad_server["configure"]["systemServerClasspath"][0],
                  bad_server["configure"]["systemServerClasspath"][1]);
        bool bad_server_refused = false;
        try {
            android_candidate_system_server_commands(bad_server);
        } catch (...) {
            bad_server_refused = true;
        }

        check(bad_server_refused);
        check(android_candidate_system_server_commands(Json{{"install", Json::array()}}).empty());
        Json can_state = {
                {"schema", 1},
                {"source", "android:qg.canbus"},
                {"status", "ready"},
                {"boot_id", "boot"},
                {"source_instance", "service"},
                {"pid", 123},
                {"revision", "2"},
                {"service_started_elapsed_ns", "1"},
                {"clock", {{"domain", "android.elapsedRealtimeNanos"}, {"sampled_ns", "3"}}},
                {"values",
                 {{"vehicle_state.IVI_SOC_MODESET", {{"status", "observed"}, {"raw", 0}}}}},
                {"acc", {{"status", "observed"}, {"raw", 0}}},
                {"history",
                 {{"oldest_seq", "1"},
                  {"latest_seq", "2"},
                  {"dropped_count", "0"},
                  {"next_cursor", {{"source_instance", "service"}, {"after_seq", "2"}}},
                  {"has_more", false},
                  {"gap", nullptr}}},
                {"events", Json::array()},
                {"transport",
                 {{"registration", "registered"},
                  {"binder_alive", true},
                  {"client_manager_cache", "not_observed"}}}};
        const std::string can_boot = "aaaaaaaa-1111-2222-3333-444444444444";
        can_state["boot_id"] = can_boot;
        can_state["values"]["vehicle_state.HUM_VSP_FUNCTION_SW"] = {{"status", "observed"},
                                                                    {"raw", 2}};
        auto can_reply = [](const Json &value) {
            return "Bundle[{json=" + value.dump() + "}]";
        };
        const auto can_proof = android_candidate_can_check(can_reply(can_state), can_boot);
        check(can_proof.at("passed") == true &&
              can_proof.at("values").at("vehicle_state.IVI_SOC_MODESET").at("raw") == 0);
        auto reject_can = [&](const Json &value, const std::string &boot) {
            bool refused = false;
            try {
                android_candidate_can_check(can_reply(value), boot);
            } catch (...) {
                refused = true;
            }

            check(refused);
        };
        auto bad_can = can_state;
        bad_can["schema"] = 2;
        reject_can(bad_can, can_boot);
        bad_can = can_state;
        bad_can["status"] = "not-ready";
        reject_can(bad_can, can_boot);
        bad_can = can_state;
        bad_can["transport"]["binder_alive"] = false;
        reject_can(bad_can, can_boot);
        bad_can = can_state;
        bad_can["values"].erase("vehicle_state.HUM_VSP_FUNCTION_SW");
        reject_can(bad_can, can_boot);
        bad_can = can_state;
        bad_can["history"]["gap"] = "overflow";
        reject_can(bad_can, can_boot);
        bad_can = can_state;
        bad_can["history"]["has_more"] = true;
        reject_can(bad_can, can_boot);
        reject_can(can_state, "bbbbbbbb-1111-2222-3333-444444444444");
        reject_can(can_state, "boot");
        bool invalid_can_reply = false;
        try {
            android_candidate_can_check("Bundle[{error=authentication}]", can_boot);
        } catch (...) {
            invalid_can_reply = true;
        }

        check(invalid_can_reply);
        unsigned content_installs = 0;

        for (const auto &entry : profile.at("install")) {
            if (entry.value("target", std::string{}) == "/system/framework/content.jar") {
                ++content_installs;
                check(entry.at("artifact") == "component:base-content");
            }
        }

        check(content_installs == 1);

        const std::set<std::string> sdk28_cli = {
                "content", "input",       "am", "bmgr", "bu",          "dpm",
                "monkey",  "requestsync", "sm", "svc",  "uiautomator", "android.test.runner"};
        Json cli_definitions = Json::object();

        for (const auto *name :
             {"free-09-chinese-20260106-6.0.3", "free-09-chinese-20221230-nxp-rc45"}) {
            const auto actual = read_private_json(root / "profiles" / name / "profile.json",
                                                  4 << 20);
            Json inputs = Json::object();

            for (const auto &entry : actual.at("install")) {
                inputs[entry.at("artifact").get<std::string>()] =
                        entry.at("type") == "tree"
                                ? Json{{"directory", "/fixture/tree"}, {"files", Json::object()}}
                                : Json{{"file", "/fixture/file"}};
            }

            const auto delivery = android_candidate_install_plan(actual, inputs);
            auto without_cli = actual;

            for (const auto &stem : sdk28_cli) {
                const auto artifact = "component:base-" + stem;
                const auto target = "/system/framework/" + stem + ".jar";
                const auto definition = read_private_json(
                        root / "profiles" / name /
                        actual.at("components").at("base-" + stem).get<std::string>() /
                        "component.json");
                check(definition.at("type") == "jar" && definition.at("minSdk") == 28 &&
                      definition.at("output") == stem + ".jar");
                const auto &base = definition.at("frameworkBase");
                check(base.at("jar") == target &&
                      base.at("oat") == "/system/framework/oat/arm64/" + stem + ".odex" &&
                      base.at("vdex") == "/system/framework/oat/arm64/" + stem + ".vdex");

                for (const auto *pin : {"oat_sha256", "vdex_sha256"}) {
                    check(std::regex_match(base.at(pin).get<std::string>(),
                                           std::regex("[0-9a-f]{64}")));
                }

                if (cli_definitions.contains(stem)) {
                    check(cli_definitions.at(stem) == definition);
                } else {
                    cli_definitions[stem] = definition;
                }

                unsigned installs = 0;

                for (const auto &entry : delivery.at("system")) {
                    if (entry.value("target", std::string{}) == target) {
                        ++installs;
                        check(entry.at("artifact") == artifact && entry.at("type") == "file" &&
                              entry.value("mode", std::string("0644")) == "0644");
                    }
                }

                check(installs == 1);
                auto &entries = without_cli["install"];
                entries.erase(std::remove_if(entries.begin(), entries.end(),
                                             [&](const auto &entry) {
                                                 return entry.value("artifact", std::string{}) ==
                                                        artifact;
                                             }),
                              entries.end());
            }

            check(actual.at("install").size() - without_cli.at("install").size() ==
                  sdk28_cli.size());
            check(android_candidate_boot_cache_paths(actual) ==
                  android_candidate_boot_cache_paths(without_cli));
            check(android_candidate_boot_image_command(actual) ==
                  android_candidate_boot_image_command(without_cli));
            check(android_candidate_boot_relocation_command(actual) ==
                  android_candidate_boot_relocation_command(without_cli));
            check(android_candidate_system_server_commands(actual) ==
                  android_candidate_system_server_commands(without_cli));
        }

        for (const auto *name :
             {"free-11-chinese-20250710-6.11.1", "free-11-chinese-20260731-7.3.1",
              "passion-11-russian-20260403-2.1.4.80"}) {
            const auto actual = read_private_json(root / "profiles" / name / "profile.json",
                                                  4 << 20);

            for (const auto &stem : sdk28_cli) {
                check(!actual.at("components").contains("base-" + stem));

                for (const auto &entry : actual.at("install")) {
                    check(entry.value("artifact", std::string{}) != "component:base-" + stem);
                }
            }
        }

        auto rejects = [&](const Json &p, const Json &a) {
            bool failed = false;
            try {
                android_candidate_install_plan(p, a);
            } catch (const std::exception &) {
                failed = true;
            }

            check(failed);
        };
        auto missing = artifacts;
        missing.erase("patched:QGIME");
        rejects(profile, missing);
        auto invalid = profile;
        invalid["install"][0]["type"] = "unknown";
        rejects(invalid, artifacts);
        invalid = profile;
        invalid["install"][2]["target"] = "/system/../data/unsafe";
        rejects(invalid, artifacts);
        invalid = profile;
        invalid["install"][2]["target"] = "/outside/unsafe";
        rejects(invalid, artifacts);
        invalid = profile;

        for (auto &entry : invalid["install"]) {
            if (entry.value("artifact", std::string{}) == "patched:QGIME") {
                entry["target"] = "/data/app/forced.apk";
            }
        }

        rejects(invalid, artifacts);
        const auto properties = android_candidate_boot_properties(
                "# preserve\r\nro.hardware=ranchu\r\nro.product.board=old\r\n",
                {{"ro.product.board", "sa8155"}, {"ro.product.locale", "zh-CN"}});
        check(properties ==
              "# preserve\nro.hardware=ranchu\nro.product.board=sa8155\nro.product.locale=zh-CN\n");

        for (const auto &bad : std::vector<Json>{{{"ro.hardware", "unsafe"}},
                                                 {{"ro.product.board", "has spaces"}},
                                                 {{"ro.product.board", 1}}}) {
            bool failed = false;
            try {
                android_candidate_boot_properties("original\n", bad);
            } catch (const std::exception &) {
                failed = true;
            }

            check(failed);
        }

        bool failed = false;
        try {
            android_candidate_boot_properties("ro.product.board=a\nro.product.board=b\n",
                                              {{"ro.product.board", "c"}});
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed);
        const auto nxp_voice_profile =
                read_private_json(std::filesystem::path(__FILE__)
                                                  .parent_path()
                                                  .parent_path()
                                                  .parent_path()
                                                  .parent_path() /
                                          "profiles/free-09-chinese-20221230-nxp-rc45/profile.json",
                                  1 << 20);
        const auto nxp_voice_properties = nxp_voice_profile.at("configure").at("bootProperties");
        check(nxp_voice_properties.size() == 7 &&
              nxp_voice_properties.at("ro.qg.voice_vendor") == "speech_voicecloud" &&
              nxp_voice_properties.at("SpeechResc_init_state") == "1");
        const auto nxp_volatile_properties = nxp_voice_profile.at("configure").at("properties");
        check(!nxp_volatile_properties.contains("SpeechResc_init_state") &&
              nxp_volatile_properties.size() == 2);
        const auto nxp_voice_output = android_candidate_boot_properties(
                "# preserve\nro.hardware=ranchu\nro.qg.voice_vendor=old\n", nxp_voice_properties);
        check(nxp_voice_output.starts_with("# preserve\nro.hardware=ranchu\n") &&
              nxp_voice_output.find("ro.qg.voice_vendor=old") == std::string::npos &&
              nxp_voice_output.find("SpeechResc_init_state=1\n") != std::string::npos);

        for (auto property = nxp_voice_properties.begin(); property != nxp_voice_properties.end();
             ++property) {
            const auto line = property.key() + "=" + property.value().get<std::string>() + "\n";
            const auto at = nxp_voice_output.find(line);
            check(at != std::string::npos &&
                  nxp_voice_output.find(line, at + line.size()) == std::string::npos);
        }

        auto reject_voice_boot = [&](const Json &values, const std::string &source = "original\n") {
            bool rejected = false;
            try {
                android_candidate_boot_properties(source, values);
            } catch (...) {
                rejected = true;
            }

            check(rejected);
        };
        auto invalid_voice_boot = nxp_voice_properties;
        invalid_voice_boot["ro.product.extra"] = "unknown";
        reject_voice_boot(invalid_voice_boot);
        invalid_voice_boot = nxp_voice_properties;
        invalid_voice_boot.erase("ro.product.locale");
        invalid_voice_boot["ro.product.extra"] = "unknown";
        check(invalid_voice_boot.size() == 7);
        reject_voice_boot(invalid_voice_boot);

        for (const Json bad_rescue :
             {Json("0"), Json("2"), Json("1\nunsafe=1"), Json(42), Json("")}) {
            invalid_voice_boot = nxp_voice_properties;
            invalid_voice_boot["SpeechResc_init_state"] = bad_rescue;
            reject_voice_boot(invalid_voice_boot);
        }

        for (const Json bad_vendor :
             {Json("nuance_voicecloud"), Json("speech_voicecloud\nunsafe=1"), Json(42), Json("")}) {
            invalid_voice_boot = nxp_voice_properties;
            invalid_voice_boot["ro.qg.voice_vendor"] = bad_vendor;
            reject_voice_boot(invalid_voice_boot);
        }

        reject_voice_boot(nxp_voice_properties, "ro.qg.voice_vendor=one\nro.qg.voice_vendor=two\n");
        reject_voice_boot(nxp_voice_properties, std::string((1 << 20) + 1, 'a'));
        reject_voice_boot(nxp_voice_properties, std::string("unsafe\0property", 15));
        const std::string choices =
                "com.qinggan.app.launcher/.activity.MainActivity\ncom.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n";
        check(home_component_declared(choices, "com.qinggan.app.launcher/.activity.MainActivity",
                                      "com.qinggan.app.launcher"));
        check(!home_component_declared(choices, "com.qinggan.app.launcher/.Missing",
                                       "com.qinggan.app.launcher"));
        verify_candidate_peak_formula();
        verify_candidate_rich_ui();
        verify_retained_candidate_version_marker();
        verify_candidate_storage();
        verify_candidate_cancellation();
        AndroidCandidateRequest request;
        request.profile = qinggan09_profile();
        request.profile_sha256 = sha256_file(root / "profiles" / request.profile / "profile.json");
        failed = false;
        try {
            build_android_candidate(root, request, "relative", 0, 0);
        } catch (const std::exception &) {
            failed = true;
        }

        check(failed);
        std::cout
                << "actual install ordering, OEM boot property and two-HOME guards passed; no VM/tool executed\n";

        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';

        return 1;
    }
}
