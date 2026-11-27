#ifdef NDEBUG
#undef NDEBUG
#endif
#include "api.hpp"
#include "guest_android_fake.hpp"
#include "profile_catalog.hpp"
#include <cassert>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
using namespace voyemu;
namespace {
struct Owned {
    std::filesystem::path root;
    std::string profile =
            embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);
    std::string id = random_token(), owner = random_token();

    explicit Owned(const std::filesystem::path &base)
        : root(base / ("guest-android-" + random_token())) {
        const auto directory = root / ".local/machines" / profile / "sessions" / id;
        ensure_private_directory(directory);
        write_private_json(root / ".local/machines" / profile / "active" / (profile + ".json"),
                           {{"schema", 1},
                            {"session_id", id},
                            {"directory", directory.string()},
                            {"endpoint", "owned-guest-android-fixture"}});
        write_private_json(directory / "automation-owner.json",
                           {{"schema", 1}, {"session_id", id}, {"ownership_id", owner}});
    }

    Json request(const char *op) const {
        return {{"schema", 1},
                {"request_id", random_token()},
                {"op", op},
                {"profile", profile},
                {"session", {{"id", id}, {"ownership_id", owner}}}};
    }
};

std::string code(const Json &response) {
    return response.at("error").at("code").get<std::string>();
}

void lifecycle(const std::filesystem::path &base) {
    const Owned owned(base);
    auto android = std::make_shared<api::FakeGuestAndroid>();
    api::Transports transports;

    transports.android = android;
    transports.control = [](const auto &, const Json &, int) -> Json {
        throw std::runtime_error("IPC_CONNECT: fixture has no supervisor");
    };
    api::Api instance(owned.root, "unused", transports);

    auto launch = owned.request("multimedia.launch");
    launch["package"] = "com.android.settings";
    launch["boot_id"] = android->boot_id;
    const auto launched = instance.call(launch);
    assert(launched.at("ok") == true && launched.at("result").at("screen") == "primary" &&
           launched.at("result").at("android_pid") == android->pid);

    auto reboot = owned.request("multimedia.reboot");
    reboot["mode"] = "sideways";
    assert(code(instance.call(reboot)) == "TEST_ARGUMENT" && android->calls.size() == 1);
    reboot["request_id"] = random_token();
    reboot["mode"] = "warm";
    const auto rebooted = instance.call(reboot);
    assert(rebooted.at("ok") == true && android->generation == 2 &&
           rebooted.at("result").at("boot_id") == android->boot_id &&
           android->calls.back() == "reboot_warm");

    // The previous boot identity no longer authorizes a launch.
    launch["request_id"] = random_token();
    assert(code(instance.call(launch)) == "APP_STALE");
    launch["request_id"] = random_token();
    launch["boot_id"] = android->boot_id;
    launch["screen"] = "secondary";
    launch["component"] = "com.android.settings/.Settings";
    assert(instance.call(launch).at("result").at("screen") == "secondary");
    launch["request_id"] = random_token();
    launch["package"] = "com.example.absent";
    launch.erase("component");
    assert(code(instance.call(launch)) == "APP_RESOLVE");
    launch["request_id"] = random_token();
    launch["intent"] = "android.intent.action.VIEW";
    const auto calls = android->calls.size();
    assert(code(instance.call(launch)) == "TEST_ARGUMENT" && android->calls.size() == calls);

    auto off = owned.request("multimedia.power");
    off["enabled"] = false;
    const auto stopped = instance.call(off);
    assert(stopped.at("ok") == true && !android->powered &&
           stopped.at("result").at("shutdown").at("ports_released") == true &&
           !stopped.at("result").contains("ok"));
    launch["request_id"] = random_token();
    launch["package"] = "com.android.settings";
    launch.erase("intent");
    assert(code(instance.call(launch)) == "APP_UNAVAILABLE");
    auto on = owned.request("multimedia.power");
    on["enabled"] = true;
    const auto started = instance.call(on);
    assert(started.at("ok") == true && android->powered && android->generation == 3 &&
           started.at("result").at("changed") == true);

    auto foreign = owned.request("multimedia.reboot");
    foreign["mode"] = "cold";
    foreign["session"]["ownership_id"] = random_token();
    const auto before = android->calls.size();
    assert(code(instance.call(foreign)) == "TEST_OWNERSHIP" && android->calls.size() == before);
    std::filesystem::remove_all(owned.root);
}

// The API verifies the supervisor's power receipt; an incomplete one is an uncertain outcome.
void power_receipt(const std::filesystem::path &base) {
    struct Incomplete final : api::FakeGuestAndroid {
        Json power(const Json &request, bool enabled, int) override {
            return {{"ok", true},
                    {"session_id", request.at("session").at("id")},
                    {"enabled", enabled},
                    {"process_alive", !enabled}};
        }
    };
    const Owned owned(base);
    api::Transports transports;

    transports.android = std::make_shared<Incomplete>();
    api::Api instance(owned.root, "unused", transports);
    auto on = owned.request("multimedia.power");
    on["enabled"] = true;
    const auto failure = instance.call(on).at("error");
    assert(failure.at("code") == "ANDROID_POWER_UNKNOWN" && failure.at("outcome") == "unknown");
    std::filesystem::remove_all(owned.root);
}

// Android UI tree, frame, system, phone and log reads go through GuestAndroid; the supervisor only
// reports session status.
struct Observed {
    Owned owned;
    std::shared_ptr<api::FakeGuestAndroid> android;
    api::Api instance;

    Observed(const std::filesystem::path &base, std::shared_ptr<api::FakeGuestAndroid> guest)
        : owned(base), android(std::move(guest)), instance(owned.root, "unused", transports()) {}

    api::Transports transports() {
        api::Transports result;
        result.android = android;
        result.control = [this](const auto &, const Json &operation, int) -> Json {
            assert(operation.at("op") == "status");

            return {{"ok", true},       {"session_id", owned.id},
                    {"stopped", false}, {"android_pid", android->pid},
                    {"qnx_pid", 0},     {"revision", 3}};
        };

        return result;
    }

    ~Observed() {
        std::filesystem::remove_all(owned.root);
    }
};

void tree(const std::filesystem::path &base) {
    Observed fixture(base, std::make_shared<api::FakeGuestAndroid>());
    auto &android = *fixture.android;
    const auto read = [&](Json screens) {
        auto request = fixture.owned.request("session.ui");
        request["screens"] = std::move(screens);
        request["timeout_ms"] = 2000;
        const auto response = fixture.instance.call(request);
        assert(response.at("ok") == true);

        return response.at("result").at("multimedia");
    };
    const auto primary = read({"primary"}).at(0);

    assert(primary.at("status") == "ok" && primary.at("boot_id") == android.boot_id &&
           primary.at("android_pid") == android.pid &&
           primary.at("nodes").at(0).at("text") == "Settings" &&
           primary.at("nodes").at(0).at("bounds").at("width") == 100);
    assert((android.calls == std::vector<std::string>{"ui_observer", "ui_ui", "ui_hello"}));
    const auto both = read({"primary", "secondary"});
    assert(both.at(0).at("status") == "ok" && both.at(1).at("status") == "unsupported");
    android.nodes[0]["clipped_bounds"] = {0, 0, 5000, 40};
    assert(read({"primary"}).at(0).at("error").at("code") == "TREE_PROTOCOL");
    android.powered = false;
    assert(read({"primary"}).at(0).at("error").at("code") == "TREE_STALE");
}

void frame(const std::filesystem::path &base) {
    Observed fixture(base, std::make_shared<api::FakeGuestAndroid>());
    auto &android = *fixture.android;
    const auto capture = [&] {
        auto request = fixture.owned.request("session.screenshot");
        request["screens"] = {"primary"};
        request["artifact_dir"] =
                (fixture.owned.root / ".local/build/tmp" / random_token()).string();

        return fixture.instance.call(request);
    };
    const auto captured = capture().at("result");

    assert(captured.at("accepted") == true && captured.at("android_boot_id") == android.boot_id &&
           captured.at("frames").at(0).at("screen") == "primary" &&
           captured.at("frames").at(0).at("sdk_display_id") == 0);
    assert((android.calls == std::vector<std::string>{"boot_identity", "frame", "boot_identity"}));
    android.frame_width = 1280;
    assert(code(capture()) == "TEST_FRAME");
    android.powered = false;
    assert(code(capture()) == "TEST_BOOT_UNAVAILABLE");
}

void system_phone_logs(const std::filesystem::path &base) {
    struct Stateless final : api::FakeGuestAndroid {
        Json system(const Json &request, int) override {
            return {{"ok", true}, {"session_id", request.at("session").at("id")}};
        }
    };
    Observed fixture(base, std::make_shared<api::FakeGuestAndroid>());
    auto &android = *fixture.android;
    auto &instance = fixture.instance;
    const auto &owned = fixture.owned;

    assert(instance.call(owned.request("multimedia.system")).at("result") == android.system_state);
    android.failure = "IPC_TIMEOUT_UNKNOWN: supervisor reply deadline";
    const auto timeout = instance.call(owned.request("multimedia.system")).at("error");
    assert(timeout.at("code") == "IPC_TIMEOUT_UNKNOWN" && timeout.at("outcome") == "unknown");
    Observed stateless(base, std::make_shared<Stateless>());
    assert(code(stateless.instance.call(stateless.owned.request("multimedia.system"))) ==
           "TEST_ARGUMENT");

    assert(instance.call(owned.request("multimedia.phone.state")).at("result").at("state") ==
           android.phone_state);
    const auto connected = instance.call(owned.request("multimedia.phone.connect"));
    assert(connected.at("ok") == true &&
           connected.at("result").at("state").at("connected") == true &&
           android.calls.back() == "phone_connect");
    android.failure = "PHONE_PROVIDER_UNKNOWN: provider restarted after dispatch";
    assert(instance.call(owned.request("multimedia.phone.disconnect")).at("error").at("outcome") ==
           "unknown");
    auto unexpected = owned.request("multimedia.phone.state");
    unexpected["payload"] = {{"number", "+70000000000"}};
    const auto calls = android.calls.size();
    assert(code(instance.call(unexpected)) == "TEST_ARGUMENT" && android.calls.size() == calls);

    auto logs = owned.request("session.logs");
    logs["source"] = "android";
    assert(instance.call(logs).at("result").at("source") == "android");
    android.logs_source = "native";
    logs["request_id"] = random_token();
    assert(code(instance.call(logs)) == "TEST_LOGS_PROTOCOL");

    android.powered = false;
    logs["request_id"] = random_token();
    assert(code(instance.call(logs)) == "TEST_LOGS_UNAVAILABLE");
    const auto off = instance.call(owned.request("multimedia.phone.state")).at("error");
    assert(off.at("code") == "PHONE_PROVIDER_UNAVAILABLE" && off.at("outcome") == "not_started");
}

void incident_logs(const std::filesystem::path &base) {
    struct IncidentGuest final : api::FakeGuestAndroid {
        bool wrong_system = false;

        Json logs(const Json &request, const Json &query, int timeout) override {
            assert(timeout >= 500);
            assert(query.at("system") == "multimedia" && query.at("timeout_ms") == 0 &&
                   query.at("limit") == 2);

            return {{"ok", true},
                    {"session_id", request.at("session").at("id")},
                    {"logs",
                     {{"source", "incidents"},
                      {"system", wrong_system ? "cluster" : "multimedia"},
                      {"status", "unavailable"},
                      {"entries", Json::array()},
                      {"cursor", query.at("cursor")}}}};
        }
    };
    auto android = std::make_shared<IncidentGuest>();
    Observed fixture(base, android);
    auto read = fixture.owned.request("session.logs");

    read["session"].erase("ownership_id");
    read["source"] = "incidents";
    read["timeout_ms"] = 0;
    read["limit"] = 2;

    assert(code(fixture.instance.call(read)) == "TEST_ARGUMENT");
    read["system"] = "cluster";
    assert(code(fixture.instance.call(read)) == "TEST_UNSUPPORTED");
    read["system"] = "unrecognized";
    assert(code(fixture.instance.call(read)) == "TEST_ARGUMENT");
    read["system"] = "multimedia";
    read["cursor"] = {{"session_id", read.at("session").at("id")},
                      {"system", "multimedia"},
                      {"stream_id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                      {"after_seq", "5"}};
    const auto result = fixture.instance.call(read);
    assert(result.at("ok") == true && result.at("result").at("cursor") == read.at("cursor") &&
           result.at("result").at("status") == "unavailable");
    android->wrong_system = true;
    assert(code(fixture.instance.call(read)) == "TEST_LOGS_PROTOCOL");

    read["subsystem"] = "multimedia";
    assert(code(fixture.instance.call(read)) == "TEST_ARGUMENT");
    read.erase("subsystem");
    read["source"] = "android_incidents";
    assert(code(fixture.instance.call(read)) == "TEST_ARGUMENT");
}

void usb_drive(const std::filesystem::path &base) {
    struct Unconfirmed final : api::FakeGuestAndroid {
        Json usb_drive(const Json &request, bool, int) override {
            return {{"ok", true}, {"session_id", request.at("session").at("id")}};
        }
    };
    Observed fixture(base, std::make_shared<api::FakeGuestAndroid>());
    auto &android = *fixture.android;
    auto &instance = fixture.instance;
    const auto &owned = fixture.owned;

    const auto attached = instance.call(owned.request("multimedia.usb.attach"));

    assert(attached.at("ok") == true && attached.at("result").at("attached") == true &&
           attached.at("result").at("changed") == true &&
           attached.at("result").at("volume").at("state") == "mounted" &&
           !attached.at("result").contains("ok") && android.calls.back() == "usb_attach");
    const auto again = instance.call(owned.request("multimedia.usb.attach"));
    assert(again.at("result").at("changed") == false);
    const auto detached = instance.call(owned.request("multimedia.usb.detach"));
    assert(detached.at("result").at("attached") == false &&
           detached.at("result").at("volume").is_null() && android.calls.back() == "usb_detach");

    auto bounded = owned.request("multimedia.usb.attach");
    bounded["timeout_ms"] = 25001;
    auto extra = owned.request("multimedia.usb.attach");
    extra["image"] = "/tmp/other.img";
    auto foreign = owned.request("multimedia.usb.detach");
    foreign["session"].erase("ownership_id");
    const auto calls = android.calls.size();
    assert(code(instance.call(bounded)) == "TEST_ARGUMENT" &&
           code(instance.call(extra)) == "TEST_ARGUMENT" &&
           code(instance.call(foreign)) == "TEST_OWNERSHIP" && android.calls.size() == calls);

    android.failure = "USB_DRIVE_UNKNOWN: QMP channel lost: IPC_READ_UNKNOWN: incomplete message";
    const auto lost = instance.call(owned.request("multimedia.usb.attach")).at("error");
    assert(lost.at("code") == "USB_DRIVE_UNKNOWN" && lost.at("outcome") == "unknown");
    android.powered = false;
    const auto off = instance.call(owned.request("multimedia.usb.attach")).at("error");
    assert(off.at("code") == "USB_DRIVE" && off.at("outcome") == "not_started");

    Observed unconfirmed(base, std::make_shared<Unconfirmed>());
    assert(code(unconfirmed.instance.call(unconfirmed.owned.request("multimedia.usb.attach"))) ==
           "USB_DRIVE_UNKNOWN");
}
} // namespace

int main(int argc, char **argv) try {
    assert(argc == 2);
    const std::filesystem::path base = argv[1];
    ensure_private_directory(base);
    lifecycle(base);
    power_receipt(base);
    tree(base);
    frame(base);
    system_phone_logs(base);
    incident_logs(base);
    usb_drive(base);
    std::cout << "Android multimedia API lifecycle and observations dispatch through "
                 "GuestAndroid\n";
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
