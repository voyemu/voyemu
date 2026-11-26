#include "media_capture.hpp"
#include "media_readiness.hpp"
#include "qinggan11_startup.hpp"
#include <cassert>
#include <chrono>
#include <exception>
#include <future>
#include <iostream>
using namespace std::chrono_literals;
using voyemu::media::CaptureDemand;

int main() try {
    using voyemu::Json;
    namespace media = voyemu::media;
    const std::string epoch = "0123456789abcdef0123456789abcdef";
    const auto generic = media::readiness_owner(epoch, Json::object());
    const auto oem = media::readiness_owner(
            epoch,
            {{"systemui_adapter", {{"component", "com.qinggan.systemui/.SystemUIService"}}}});
    assert(!media::require_oem_systemui(generic, epoch) && media::require_oem_systemui(oem, epoch));
    // The window reads the screens of the machine from the owner record of its session.
    const Json displays = Json::array({{{"role", "primary"},
                                        {"guest", "android"},
                                        {"width", 1920},
                                        {"height", 720},
                                        {"density", 160}},
                                       {{"role", "rear"},
                                        {"guest", "android"},
                                        {"width", 1902},
                                        {"height", 540},
                                        {"density", 160}}});
    const auto screens =
            media::owner_screens(media::readiness_owner(epoch, {{"screens", displays}}), epoch);
    assert(screens.size() == 2 && screens[1].role == "rear" && screens[1].android_display == 1u);
    bool unlisted = false;

    try {
        (void)media::owner_screens(generic, epoch);
    } catch (const std::runtime_error &) {
        unlisted = true;
    }

    assert(unlisted);
    Json android = {{"status", "guest_acknowledged"},
                    {"guest_acknowledged", true},
                    {"home", {{"status", "visible_on_primary"}}},
                    {"displays", {{"status", "both_guest_displays_ready"}}}};
    assert(media::presentation_ready(android, false) && !media::presentation_ready(android, true));
    android["systemui"] = {{"status", "both_OEM_bars_visible"}};
    assert(media::presentation_ready(android, true));

    for (const char *key : {"status", "home", "displays"}) {
        auto pending = android;
        pending.erase(key);
        assert(!media::presentation_ready(pending, false) &&
               !media::presentation_ready(pending, true));
    }

    for (const Json &invalid :
         Json::array({Json::object(),
                      {{"schema", 1}, {"session_id", epoch}},
                      {{"schema", 1}, {"session_id", "other"}, {"require_oem_systemui", false}},
                      {{"schema", 2}, {"session_id", epoch}, {"require_oem_systemui", false}},
                      {{"schema", true}, {"session_id", epoch}, {"require_oem_systemui", false}},
                      {{"schema", 1}, {"session_id", epoch}, {"require_oem_systemui", 0}},
                      {{"schema", 1}, {"session_id", epoch}, {"require_oem_systemui", "false"}},
                      {{"schema", 1}, {"session_id", epoch}, {"require_oem_systemui", nullptr}}})) {
        bool rejected = false;
        try {
            (void)media::require_oem_systemui(invalid, epoch);
        } catch (const std::runtime_error &) {
            rejected = true;
        }

        assert(rejected);
    }

    // The wheel provider of profile.json, not the profile id, selects these startup values.
    const Json free_source = {
            {"schema", 1},
            {"id", "api30-fixture"},
            {"platform", "qinggan11"},
            {"wheel", {{"provider", "com.voyemu.input.wheel"}}},
            {"status", "incomplete"},
            {"android", {{"package", "system-images;android-30;default;arm64-v8a"}}},
            {"configure",
             {{"home", "com.qinggan.app.launcher"},
              {"homeActivity",
               "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}}}};
    assert(voyemu::qinggan11_startup_values(free_source).empty());
    {
        auto ready = free_source;
        ready["status"] = "ready";
        assert(voyemu::qinggan11_startup_values(ready).empty());
        ready["initial_state"] = {{"speed", 37}, {"gear", 2}};
        assert(voyemu::qinggan11_startup_values(ready) == ready.at("initial_state"));
    }
    const Json free_presentation = {
            {"reference_profile", "free-11-chinese-20260731-7.3.1"},
            {"api", 30},
            {"home",
             {{"package", "com.qinggan.app.launcher"},
              {"component",
               "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}}}};
    assert(voyemu::qinggan11_presentation(free_presentation));

    for (const auto &update :
         Json::array({{{"reference_profile", "free-09-chinese-20260106-6.0.3"}},
                      {{"reference_profile", "test-passion"}},
                      {{"api", 28}},
                      {{"home",
                        {{"package", "com.qinggan.app.launcher"},
                         {"component", "com.qinggan.app.launcher/.activity.MainActivity"}}}},
                      {{"home", {{"package", "other"}, {"component", "other/.Main"}}}}})) {
        auto invalid = free_presentation;
        invalid.update(update);
        assert(!voyemu::qinggan11_presentation(invalid));
    }

    {
        auto explicit_values = free_source;
        explicit_values["initial_state"] = {{"speed", 37}, {"gear", 2}};
        assert(voyemu::qinggan11_startup_values(explicit_values) ==
               explicit_values.at("initial_state"));
    }

    for (const auto *field : {"schema", "platform", "wheel", "status", "android", "configure"}) {
        auto invalid = free_source;
        invalid.erase(field);
        bool denied = false;
        try {
            voyemu::qinggan11_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    for (const auto &value : Json::array({nullptr, Json::array(), 7, "wrong"})) {
        auto invalid = free_source;
        invalid["initial_state"] = value;
        bool denied = false;
        try {
            voyemu::qinggan11_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    for (const auto &update :
         Json::array({{{"platform", "qinggan09"}},
                      {{"wheel", {{"provider", "other"}}}},
                      {{"status", "prepared"}},
                      {{"android", {{"package", "system-images;android-28;default;arm64-v8a"}}}},
                      {{"configure",
                        {{"home", "other.package"}, {"homeActivity", "other.package/.Main"}}}}})) {
        auto invalid = free_source;
        invalid.update(update);
        bool denied = false;
        try {
            voyemu::qinggan11_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    const Json passion_source = {
            {"schema", 1},
            {"id", "synthetic-passion"},
            {"platform", "passion"},
            {"board", "8155"},
            {"status", "incomplete"},
            {"android", {{"package", "system-images;android-30;default;arm64-v8a"}}}};
    assert(voyemu::passion_startup_values(passion_source).empty());
    auto ready_passion = passion_source;
    ready_passion["status"] = "ready";
    assert(voyemu::passion_startup_values(ready_passion).empty());

    for (const auto *field : {"schema", "platform", "status", "android"}) {
        auto invalid = passion_source;
        invalid.erase(field);
        bool denied = false;
        try {
            voyemu::passion_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    {
        auto invalid = passion_source;
        invalid["status"] = "unknown";
        bool denied = false;
        try {
            voyemu::passion_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }
    {
        auto invalid = passion_source;
        invalid["android"]["package"] = "system-images;android-28;default;arm64-v8a";
        bool denied = false;
        try {
            voyemu::passion_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }
    {
        auto invalid = passion_source;
        invalid["initial_state"] = {{"speed", 123}};
        bool denied = false;
        try {
            voyemu::passion_startup_values(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }
    Json passion_spec = {
            {"api", 30},
            {"reference_profile", "synthetic-passion"},
            {"platform", "passion"},
            {"board", "8155"},
            {"home",
             {{"package", "com.voyah.os.carlauncher"}, {"component", voyemu::passion_home}}},
            {"presentation_adapter", voyemu::passion_presentation_contract("synthetic-passion")}};
    assert(voyemu::passion_presentation(passion_spec) && !voyemu::nxp_presentation(passion_spec));
    const auto passion_owner = media::readiness_owner(epoch, passion_spec);
    assert(passion_owner.at("presentation_family") == "passion");
    assert(media::presentation_only(passion_owner, epoch) &&
           !media::presentation_only(generic, epoch));

    // The presentation adapter belongs to the reference profile of its own launch.
    for (const bool adapter : {false, true}) {
        auto foreign = passion_spec;
        (adapter ? foreign["presentation_adapter"]["family"]
                 : foreign["reference_profile"]) = "synthetic-other";
        bool denied = false;
        try {
            voyemu::passion_presentation(foreign);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    {
        auto other = passion_spec;
        other["platform"] = "qinggan11";
        assert(!voyemu::passion_presentation(other) && !voyemu::nxp_presentation(other));
    }

    auto presentation = android;
    presentation["status"] = "presentation_ready";
    presentation["presentation_family"] = "passion";
    presentation["guest_acknowledged"] = false;
    assert(media::presentation_ready(presentation, false, true) &&
           !media::presentation_ready(presentation, false));
    assert(!media::presentation_ready(android, false, true));
    assert(media::android_public_ready(presentation));
    assert(media::android_public_ready(android));
    {
        auto claimed = android;
        claimed["presentation_family"] = "passion";
        assert(!media::android_public_ready(claimed));
    }
    {
        auto failed = presentation;
        failed["last_error"] = "identity unavailable";
        assert(!media::android_public_ready(failed));
    }

    for (const auto *key : {"home", "displays", "presentation_family"}) {
        auto invalid = presentation;
        invalid.erase(key);
        assert(!media::presentation_ready(invalid, false, true));
    }

    {
        auto invalid = presentation;
        invalid["guest_acknowledged"] = true;
        assert(!media::presentation_ready(invalid, false, true));
    }
    {
        auto invalid = passion_owner;
        invalid["presentation_family"] = "other";
        bool denied = false;
        try {
            media::presentation_only(invalid, epoch);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    assert(voyemu::nxp_clock_service_ready(true, 0, false, "Service alarm: found\n"));
    assert(!voyemu::nxp_clock_service_ready(false, 0, false, "Service alarm: found\n"));
    assert(!voyemu::nxp_clock_service_ready(true, 0, false, "Service alarm: not found\n"));
    assert(!voyemu::nxp_clock_service_ready(true, 1, false, "Service alarm: found\n"));
    assert(!voyemu::nxp_clock_service_ready(true, 0, true, "Service alarm: found\n"));
    assert(voyemu::nxp_key_manager_service_ready(0, false, "Service qg.key_manager: found\n"));
    assert(!voyemu::nxp_key_manager_service_ready(0, false, "Service qg.key_manager: not found\n"));
    assert(!voyemu::nxp_key_manager_service_ready(1, false, "Service qg.key_manager: found\n"));
    assert(!voyemu::nxp_key_manager_service_ready(0, true, "Service qg.key_manager: found\n"));
    Json nxp_spec = {
            {"api", 28},
            {"reference_profile", "synthetic-nxp"},
            {"platform", "qinggan09"},
            {"board", "nxp"},
            {"home", {{"package", "com.qinggan.app.launcher"}, {"component", voyemu::nxp_home}}},
            {"presentation_adapter", voyemu::nxp_presentation_contract("synthetic-nxp")}};
    assert(voyemu::nxp_presentation(nxp_spec) && !voyemu::passion_presentation(nxp_spec));
    const auto nxp_owner = media::readiness_owner(epoch, nxp_spec);
    assert(nxp_owner.at("presentation_family") == "nxp");
    assert(media::presentation_only(nxp_owner, epoch));
    {
        auto foreign = nxp_spec;
        foreign["presentation_adapter"]["family"] = "synthetic-other";
        bool denied = false;
        try {
            voyemu::nxp_presentation(foreign);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    auto nxp_delivery = presentation;
    nxp_delivery["presentation_family"] = "nxp";
    assert(media::android_public_ready(nxp_delivery));

    for (const auto *key : {"home", "displays"}) {
        auto invalid = nxp_delivery;
        invalid.erase(key);
        assert(!media::android_public_ready(invalid));
    }

    {
        auto wheel = nxp_spec;
        wheel["wheel_adapter"] = voyemu::nxp_wheel_adapter();
        assert(voyemu::nxp_presentation(wheel));
        assert(wheel["wheel_adapter"]["routes"]["photo"] == 142);
        wheel["wheel_adapter"]["routes"]["photo"] = 173;
        bool denied = false;
        try {
            voyemu::nxp_presentation(wheel);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    for (const auto *key : {"vehicle_adapter", "wheel_adapter", "systemui_adapter"}) {
        auto invalid = nxp_spec;
        invalid[key] = Json::object();
        bool denied = false;
        try {
            voyemu::nxp_presentation(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    {
        auto invalid = nxp_spec;
        invalid["api"] = 30;
        bool denied = false;
        try {
            voyemu::nxp_presentation(invalid);
        } catch (...) {
            denied = true;
        }

        assert(denied);
    }

    voyemu::media::PresentationFrames<std::shared_ptr<int>> frames;
    frames.put(1, std::make_shared<int>(10)); // The secondary display can finish first during boot.
    assert(!frames.complete() && !frames.snapshot()[1]);
    assert(frames.set_ready(true));
    frames.put(0, std::make_shared<int>(11));
    assert(!frames.complete() && !frames.snapshot()[0]); // Keep the entire Android row masked until
                                                         // both fresh frames arrive.
    frames.put(1, std::make_shared<int>(12));
    assert(frames.complete());
    assert(*frames.snapshot()[0] == 11 && *frames.snapshot()[1] == 12);
    assert(!frames.set_ready(true) &&
           frames.complete()); // A regular poll must not discard live frames.
    assert(frames.set_ready(false) && !frames.complete() && !frames.snapshot()[0] &&
           !frames.snapshot()[1]);
    frames.put(0,
               std::make_shared<int>(13)); // Late pre-ready frame must not survive a guest reboot.
    assert(frames.set_ready(true) && !frames.complete());
    frames.put(1, std::make_shared<int>(14));
    assert(!frames.complete());
    frames.put(0, std::make_shared<int>(15));
    assert(frames.complete());
    assert(*frames.snapshot()[0] == 15 && *frames.snapshot()[1] == 14);
    // A rear screen frame is shown once it arrives but never holds back the multimedia screens.
    media::PresentationFrames<std::shared_ptr<int>> rear(3, 2);
    assert(rear.set_ready(true));
    rear.put(2, std::make_shared<int>(20));
    assert(!rear.complete() && rear.snapshot().size() == 3 && !rear.snapshot()[2]);
    rear.put(0, std::make_shared<int>(21));
    rear.put(1, std::make_shared<int>(22));
    assert(rear.complete() && *rear.snapshot()[2] == 20);
    assert(rear.set_ready(false) && rear.set_ready(true));
    rear.put(0, std::make_shared<int>(23));
    rear.put(1, std::make_shared<int>(24));
    assert(rear.complete() && !rear.snapshot()[2]);
    // A change-driven stream emits one initial image, then remains static until reconnected.
    media::PresentationFrames<std::shared_ptr<int>> static_frames;
    CaptureDemand static_demand;
    auto deliver = [&](const CaptureDemand::Cancellation &attempt, unsigned display, int value) {
        if (!attempt->load()) {
            static_frames.put(display, std::make_shared<int>(value));
        }
    };
    auto boot_left = static_demand.wait(), boot_right = static_demand.wait();
    deliver(boot_left, 0, 100);
    deliver(boot_right, 1, 101);
    assert(!static_frames.complete() && !static_frames.snapshot()[0] &&
           !static_frames.snapshot()[1]);
    assert(media::set_presentation_ready(static_frames, static_demand, true));
    assert(boot_left->load() &&
           boot_right->load()); // Readiness must reconnect both static streams.
    deliver(boot_left, 0, 102);
    deliver(boot_right, 1, 103);
    assert(!static_frames.complete()); // Late boot callbacks cannot satisfy the new epoch.
    auto fresh_left = static_demand.wait(), fresh_right = static_demand.wait();
    assert(!fresh_left->load() && !fresh_right->load());
    deliver(fresh_left, 0, 200);
    assert(!static_frames.complete());
    deliver(fresh_right, 1, 201);
    assert(static_frames.complete());
    assert(*static_frames.snapshot()[0] == 200 && *static_frames.snapshot()[1] == 201);
    assert(!media::set_presentation_ready(static_frames, static_demand, true) &&
           static_frames.complete() && !fresh_left->load() && !fresh_right->load());
    assert(media::set_presentation_ready(static_frames, static_demand, false) &&
           fresh_left->load() && fresh_right->load() && !static_frames.complete());
    auto reboot_left = static_demand.wait(), reboot_right = static_demand.wait();
    deliver(reboot_left, 0, 300);
    deliver(reboot_right, 1, 301);
    assert(!static_frames.complete());
    assert(media::set_presentation_ready(static_frames, static_demand, true) &&
           reboot_left->load() && reboot_right->load());
    deliver(reboot_left, 0, 302);
    deliver(reboot_right, 1, 303);
    assert(!static_frames.complete());
    auto next_left = static_demand.wait(), next_right = static_demand.wait();
    deliver(next_left, 0, 400);
    deliver(next_right, 1, 401);
    assert(static_frames.complete());
    assert(*static_frames.snapshot()[0] == 400 && *static_frames.snapshot()[1] == 401);
    static_demand.stop();
    assert(next_left->load() && next_right->load());
    CaptureDemand paused;
    paused.set_wanted(false);
    paused.refresh();
    std::promise<void> pause_entered;
    auto pause_ready = pause_entered.get_future();
    auto waiting = std::async(std::launch::async, [&] {
        pause_entered.set_value();

        return paused.wait();
    });
    pause_ready.wait();
    assert(waiting.wait_for(30ms) == std::future_status::timeout);
    paused.stop();
    assert(waiting.wait_for(1s) == std::future_status::ready &&
           !waiting.get()); // Refresh never resumes an explicitly paused or stopped owner.

    CaptureDemand demand;
    auto left = demand.wait(), right = demand.wait();
    assert(left && right && !left->load() && !right->load());
    assert(demand.set_wanted(false));
    assert(left->load() && right->load());
    std::promise<void> entered;
    auto ready = entered.get_future();
    auto pending = std::async(std::launch::async, [&] {
        entered.set_value();

        return demand.wait();
    });
    ready.wait();
    assert(pending.wait_for(30ms) == std::future_status::timeout);
    assert(demand.set_wanted(true));
    assert(pending.wait_for(1s) == std::future_status::ready);
    auto resumed = pending.get();
    assert(resumed && !resumed->load());
    assert(left->load() && right->load()); // Resuming cannot revive a cancelled in-flight transfer.
    assert(!demand.set_wanted(true));
    demand.set_wanted(false);
    auto blocked = std::async(std::launch::async, [&] {
        return demand.wait();
    });
    assert(blocked.wait_for(30ms) == std::future_status::timeout);
    demand.stop();
    assert(resumed->load());
    assert(blocked.wait_for(1s) == std::future_status::ready && !blocked.get());
    assert(!demand.set_wanted(true) && !demand.wait());
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
