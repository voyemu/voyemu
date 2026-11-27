#ifdef NDEBUG
#undef NDEBUG
#endif
#include "android_incidents.hpp"

#include <cassert>
#include <string_view>

using voyemu::runtime::AndroidIncidents;
using voyemu::runtime::IncidentSource;

namespace {
constexpr auto first_boot = "d5a59b88-6a46-43f7-a381-a382d92d9f09";
constexpr auto second_boot = "9f53379a-0e2c-4f6e-94d8-6bd332814a49";

void word(std::string &out, unsigned n, unsigned width = 4) {
    while (width--) {
        out += static_cast<char>(n & 255);
        n >>= 8;
    }
}

std::string frame(unsigned buffer, unsigned pid, unsigned tid, std::string_view payload,
                  unsigned seconds = 1795766868) {
    std::string result;

    word(result, static_cast<unsigned>(payload.size()), 2);
    word(result, 28, 2);
    word(result, pid);
    word(result, tid);
    word(result, seconds);
    word(result, 196000000);
    word(result, buffer);
    word(result, 1000);
    result += payload;

    return result;
}

std::string text(std::string_view tag, std::string_view message, unsigned pid = 25007,
                 unsigned tid = 25007, unsigned seconds = 1795766868) {
    std::string payload(1, '\6');

    payload += tag;
    payload += '\0';
    payload += message;
    payload += '\0';

    return frame(4, pid, tid, payload, seconds);
}

std::string java_fatal() {
    return text("AndroidRuntime", "FATAL EXCEPTION: main\nProcess: com.test.app, PID: 25007\n"
                                  "java.lang.IllegalStateException: password=unknown-secret\n"
                                  "\tat com.test.app.Activity.crash(Activity.java:20)");
}

std::string activity_report(bool anr) {
    std::string fields;

    word(fields, anr ? 30008 : 30039);
    const auto integer = [&](unsigned value) {
        fields += '\0';
        word(fields, value);
    };
    const auto string = [&](std::string_view value) {
        fields += '\2';
        word(fields, static_cast<unsigned>(value.size()));
        fields += value;
    };
    fields += '\3';
    fields += anr ? '\5' : '\10';
    // Actual Android 9 am_crash writer emits PID, user despite the event-log-tags labels.
    // am_anr emits user, PID.
    integer(anr ? 0 : 25007);
    integer(anr ? 25007 : 0);
    string("com.test.app");
    integer(0);

    if (anr) {
        string("Input dispatching timed out (unbounded details)");
    } else {
        string("java.lang.IllegalStateException");
        string("password=unknown-secret");
        string("Activity.java");
        integer(20);
    }

    return frame(2, 1399, 1404, fields);
}

void fresh_only_and_updates() {
    AndroidIncidents monitor("test-session", "test-stream");

    monitor.observe_boot(first_boot, 7);
    const auto retained = java_fatal();
    assert(monitor.ingest(IncidentSource::text, retained.substr(0, 13), 100));
    assert(monitor.ingest(IncidentSource::text, retained.substr(13), 100));
    assert(monitor.ingest(IncidentSource::events, activity_report(false), 100));
    monitor.flush(500);
    assert(monitor.read({}, 16, 0).at("entries").empty());

    assert(monitor.ingest(IncidentSource::text, java_fatal(), 501));
    monitor.flush(800);
    const auto first = monitor.read({}, 16, 0);
    assert(first.at("entries").size() == 1);
    const auto one = first.at("entries").at(0).at("incident");
    assert(one.at("kind") == "java_fatal" && one.at("boot_id") == first_boot &&
           one.at("process").at("pid") == 25007 && one.at("stack").at("frames").size() == 1);
    assert(first.dump().find("unknown-secret") == std::string::npos);
    assert(first.dump().find("password") == std::string::npos);

    assert(monitor.ingest(IncidentSource::events, activity_report(false), 815));
    monitor.flush(850);
    const auto update = monitor.read(first.at("cursor"), 16, 0);
    const auto entry = update.at("entries").at(0);
    assert(entry.at("change") == "enriched");
    assert(entry.at("incident").at("id") == one.at("id") &&
           entry.at("incident").at("revision") == 2);
    assert(monitor.read(first.at("cursor"), 16, 0).at("entries") == update.at("entries"));

    assert(monitor.ingest(IncidentSource::text, java_fatal(), 900));
    assert(monitor.ingest(IncidentSource::events, activity_report(true), 910));
    monitor.flush(1500);
    const auto page = monitor.read(update.at("cursor"), 1, 0);
    assert(page.at("entries").at(0).at("incident").at("id") != one.at("id") &&
           page.at("has_more") == true);
    const auto anr = monitor.read(page.at("cursor"), 16, 0).at("entries").at(0).at("incident");
    assert(anr.at("kind") == "am_anr" && anr.at("process").at("pid") == 25007 &&
           anr.at("reason").at("summary") == "Input dispatching timed out");
}

void native_boundaries_and_retention() {
    AndroidIncidents monitor("test-session", "test-stream", 3);

    monitor.observe_boot(first_boot, 7);
    assert(monitor.ingest(IncidentSource::text, text("unrelated", "old"), 0));
    const auto previous = monitor.read({}, 16, 0).at("cursor");
    const auto signal = text("libc",
                             "Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 43 "
                             "(app), pid 42 (app)",
                             42, 43);
    const auto dump = text("DEBUG",
                           "pid: 42, tid: 43, name: app >>> com.test.native <<<\n"
                           "signal 6 (SIGABRT), code -1 (SI_QUEUE), fault addr --------\n"
                           "    #00 pc 0000000000005678  /system/lib64/libc.so (abort+24)",
                           88, 88);
    assert(monitor.ingest(IncidentSource::text, signal + dump, 500));
    monitor.flush(1000);
    const auto crash = monitor.read(previous, 16, 0);
    const auto native = crash.at("entries").at(0).at("incident");
    assert(native.at("kind") == "native_fatal" && native.at("process").at("pid") == 42 &&
           native.at("evidence").size() == 2 && native.at("stack").at("frames").size() == 1);

    monitor.lost(IncidentSource::text, "transport_lost");
    assert(monitor.ingest(IncidentSource::text, signal, 1010));
    monitor.flush(1200);
    monitor.observe_boot(second_boot, 8);
    assert(monitor.ingest(IncidentSource::text, java_fatal(), 1300));
    assert(monitor.ingest(IncidentSource::text, java_fatal(), 1310));
    monitor.flush(1600);
    const auto resumed = monitor.read(previous, 16, 0).at("entries");
    assert(resumed.at(0).at("type") == "gap" && resumed.at(0).at("reason") == "journal_evicted");
    const auto new_crash = resumed.back().at("incident");
    assert(new_crash.at("boot_id") == second_boot && new_crash.at("id") != native.at("id"));
}
} // namespace

int main() {
    fresh_only_and_updates();
    native_boundaries_and_retention();
}
