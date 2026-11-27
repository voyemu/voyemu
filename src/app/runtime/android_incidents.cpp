#include "android_incidents.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <regex>

namespace voyemu::runtime {
namespace {
using namespace std::chrono_literals;
constexpr std::size_t max_record = 4096;
constexpr std::size_t max_pending = 256 * 1024;
constexpr std::size_t max_entries_bytes = 2 * 1024 * 1024;
constexpr std::size_t max_batch_bytes = 60 * 1024;
constexpr std::size_t max_candidates = 64;
constexpr auto name_text = "logcat_text";
constexpr auto name_events = "logcat_events";

std::size_t index(IncidentSource source) {
    return source == IncidentSource::text ? 0 : 1;
}

const char *name(IncidentSource source) {
    return source == IncidentSource::text ? name_text : name_events;
}

std::uint32_t word(std::string_view bytes, std::size_t at, unsigned count = 4) {
    std::uint32_t result = 0;

    for (unsigned i = 0; i < count; ++i) {
        result |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[at + i])) << (8 * i);
    }

    return result;
}

std::optional<std::uint64_t> decimal(std::string_view digits) {
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);

    if (digits.empty() || (digits.size() > 1 && digits.front() == '0') ||
        parsed.ec != std::errc() || parsed.ptr != digits.data() + digits.size()) {
        return std::nullopt;
    }

    return value;
}

std::string_view trim(std::string_view row) {
    const auto first = row.find_first_not_of(" \t\r");

    return first == std::string_view::npos
                   ? std::string_view{}
                   : row.substr(first, row.find_last_not_of(" \t\r") - first + 1);
}

// Names and frames retain program identifiers. Arbitrary exception, ANR and dump text stays in
// Android. No labels, intent arguments, addresses or absolute file paths enter the journal.
std::string identifier(std::string_view text, std::size_t limit = 161) {
    if (text.empty() || text.size() > limit ||
        text.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:$-") !=
                std::string_view::npos) {
        return {};
    }

    return std::string(text);
}

Json nullable(const std::string &value) {
    return value.empty() ? Json() : Json(value);
}

struct LogRecord {
    std::uint32_t pid, tid, seconds, nanoseconds, buffer;
    std::string_view payload;

    Json time() const {
        const bool usable = seconds != 0 && nanoseconds < 1000000000;

        return {{"clock", "android.realtime"},
                {"unix_ns",
                 usable ? Json(std::to_string(std::uint64_t(seconds) * 1000000000 + nanoseconds))
                        : Json()},
                {"quality", usable         ? "reported"
                            : seconds == 0 ? "unset"
                                           : "unknown"}};
    }
};

struct Candidate {
    std::string kind, process, code, summary, id;
    std::uint32_t pid = 0, tid = 0, producer_pid = 0, producer_tid = 0;
    std::int64_t started = 0, updated = 0;
    unsigned revision = 0;
    Json time, evidence = Json::array(), frames = Json::array();
    bool dirty = true, truncated = false;
};

void evidence(Candidate &c, const char *source, const char *buffer, std::string_view tag,
              const char *match) {
    c.evidence.push_back({{"source", source}, {"buffer", buffer}, {"tag", tag}, {"match", match}});
    c.dirty = true;
}

Candidate candidate(std::string_view kind, const LogRecord &r, std::int64_t now) {
    Candidate c;

    c.kind = kind;
    c.producer_pid = c.pid = r.pid;
    c.producer_tid = c.tid = r.tid;
    c.time = r.time();
    c.started = c.updated = now;

    return c;
}

void frame(Candidate &c, std::string row) {
    if (c.frames.size() < 10 && c.frames.dump().size() + row.size() < 1100) {
        c.frames.push_back(std::move(row));
    } else {
        c.truncated = true;
    }

    c.dirty = true;
}

struct ActivityReport {
    std::uint32_t pid;
    std::string process, code;
    bool anr;
};

std::optional<ActivityReport> activity_report(std::string_view p, bool anr) {
    // The producer PID in the logger_entry header identifies system_server. Android's
    // am_crash writer emits PID then user, contrary to its event-log-tags label order.
    // The am_anr writer emits user then PID.
    constexpr std::array<int, 8> crash_types{0, 0, 2, 0, 2, 2, 2, 0};
    constexpr std::array<int, 5> anr_types{0, 0, 2, 0, 2};
    const std::span<const int> types = anr ? std::span<const int>(anr_types)
                                           : std::span<const int>(crash_types);

    if (p.size() < 2 || p[0] != 3 || static_cast<unsigned char>(p[1]) != types.size()) {
        return {};
    }

    p.remove_prefix(2);
    ActivityReport report{0, {}, {}, anr};

    for (std::size_t i = 0; i < types.size(); ++i) {
        if (p.size() < 5 || p.front() != types[i]) {
            return {};
        }

        const auto value = word(p, 1);
        p.remove_prefix(5);

        if (types[i] == 0) {
            if (i == (anr ? 1u : 0u) && value > 0 && value <= INT32_MAX) {
                report.pid = value;
            }

            continue;
        }

        if (value > p.size()) {
            return {};
        }

        const auto string = p.substr(0, value);

        if (i == 2) {
            report.process = identifier(string);
        } else if (i == 4) {
            if (!anr) {
                report.code = identifier(string);
            } else if (string.starts_with("Input dispatching timed out")) {
                report.code = "Input dispatching timed out";
            } else if (string.starts_with("Broadcast of Intent")) {
                report.code = "Broadcast timed out";
            } else if (string.starts_with("executing service")) {
                report.code = "Service execution timed out";
            } else {
                report.code = "Application not responding";
            }
        }

        p.remove_prefix(value);
    }

    if (!report.pid || (p != "\n" && !p.empty())) {
        return {};
    }

    return report;
}
} // namespace

struct AndroidIncidents::Impl {
    struct Reader {
        std::string pending, reason = "waiting_for_boot";
        bool armed = false;
    };

    struct Entry {
        std::uint64_t seq;
        std::size_t bytes;
        Json value;
    };

    std::mutex mutex;
    std::condition_variable changed;
    std::string session, stream, boot, last_boot;
    std::uint64_t generation = 0, seq = 0, state = 0;
    std::size_t capacity, bytes = 0;
    bool closed = false;
    std::array<Reader, 2> readers;
    std::deque<Entry> entries;
    std::deque<Candidate> candidates;

    Impl(std::string session_, std::string stream_, std::size_t capacity_)
        : session(std::move(session_)), stream(std::move(stream_)), capacity(capacity_) {}

    void notify() {
        ++state;
        changed.notify_all();
    }

    void append(Json value) {
        value["seq"] = std::to_string(++seq);
        const auto size = value.dump().size();
        entries.push_back({seq, size, std::move(value)});
        bytes += size;

        while (entries.size() > capacity || bytes > max_entries_bytes) {
            bytes -= entries.front().bytes;
            entries.pop_front();
        }

        notify();
    }

    void gap(std::string_view why, Json sources, Json before, Json after = nullptr) {
        append({{"type", "gap"},
                {"reason", why},
                {"sources", std::move(sources)},
                {"boot_before", std::move(before)},
                {"boot_after", std::move(after)},
                {"lost_records", nullptr}});
    }

    bool reset_reader(IncidentSource source, std::string_view reason) {
        auto &reader = readers[index(source)];

        if (!reader.armed && reader.reason == reason && reader.pending.empty()) {
            return false;
        }

        const bool had_baseline = reader.armed;
        reader = {{}, std::string(reason), false};
        notify();

        return had_baseline;
    }

    void lose(IncidentSource source, std::string_view reason) {
        if (reset_reader(source, reason)) {
            // Candidates may contain facts from both readers. Discard them at the gap so an
            // unrelated report after reconnect cannot enrich an old incident.
            candidates.clear();
            gap(reason, Json::array({name(source)}), boot);
        }
    }

    Candidate &add(Candidate value) {
        if (candidates.size() >= max_candidates) {
            gap("assembly_overflow", Json::array({name_text, name_events}), boot);
            candidates.pop_front();
        }

        candidates.push_back(std::move(value));

        return candidates.back();
    }

    void publish(Candidate &c) {
        if (c.id.empty()) {
            c.id = stream + ":" + std::to_string(seq + 1);
        }

        const auto change = c.revision == 0 ? "opened" : "enriched";
        ++c.revision;
        Json incident{{"id", c.id},
                      {"revision", c.revision},
                      {"boot_id", boot},
                      {"android_generation", std::to_string(generation)},
                      {"kind", c.kind},
                      {"process",
                       {{"pid", c.pid ? Json(c.pid) : Json()},
                        {"name", nullable(c.process)},
                        {"tid", c.tid ? Json(c.tid) : Json()}}},
                      {"guest_time", c.time},
                      {"reason", {{"code", nullable(c.code)}, {"summary", nullable(c.summary)}}},
                      {"stack", {{"frames", c.frames}, {"truncated", c.truncated}}},
                      {"evidence", c.evidence}};

        if (c.kind == "am_crash") {
            incident["correlation"] = "unresolved";
        }

        append({{"type", "incident"}, {"change", change}, {"incident", std::move(incident)}});
        c.dirty = false;
    }

    void expire(std::int64_t now) {
        for (auto &c : candidates) {
            const auto settle = c.kind == "am_crash" ? 400 : 150;

            if (c.dirty && (now - c.updated >= settle || now - c.started >= 1000)) {
                publish(c);
            }
        }

        std::erase_if(candidates, [&](const auto &c) {
            return now - c.started >= 2400;
        });
    }

    void am(const LogRecord &r, std::int64_t now) {
        if (r.payload.size() < 4) {
            return;
        }

        const auto tag = word(r.payload, 0);

        if (tag != 30008 && tag != 30039) {
            return;
        }

        const auto report = activity_report(r.payload.substr(4), tag == 30008);

        if (!report) {
            gap("unknown_event_format", Json::array({name_events}), boot);

            return;
        }

        Candidate *match = nullptr;

        if (!report->anr && !report->code.empty() && !report->process.empty()) {
            for (auto &c : candidates) {
                if (c.kind == "java_fatal" && c.pid == report->pid &&
                    c.process == report->process && c.code == report->code &&
                    now - c.started < 1000 &&
                    std::none_of(
                            c.evidence.begin(), c.evidence.end(),
                            [](const auto &item) {
                                return item.at("tag") == "am_crash";
                            })) {
                    if (match) {
                        match = nullptr;
                        break;
                    }

                    match = &c;
                }
            }
        }

        if (match) {
            evidence(*match, name_events, "events", "am_crash", "correlated");

            return;
        }

        auto value = candidate(report->anr ? "am_anr" : "am_crash", r, now);
        value.pid = report->pid;
        value.tid = 0;
        value.process = report->process;

        if (report->anr) {
            value.summary = report->code;
        } else {
            value.code = report->code;
        }

        evidence(value, name_events, "events", report->anr ? "am_anr" : "am_crash", "anchor");
        add(std::move(value));
    }

    void correlate_pending(Candidate &java, std::int64_t now) {
        Candidate *report = nullptr;

        for (auto &c : candidates) {
            if (c.pid != java.pid || c.process != java.process || c.code != java.code ||
                now - c.started >= 1000) {
                continue;
            }

            if (c.kind == "java_fatal" && &c != &java) {
                return;
            }

            if (c.kind == "am_crash" && c.revision == 0) {
                if (report) {
                    return;
                }

                report = &c;
            }
        }

        if (report) {
            // Keep the candidate's slot until expiry since deque erasure invalidates references.
            report->dirty = false;
            report->kind.clear();
            evidence(java, name_events, "events", "am_crash", "correlated");
        }
    }

    void java(const LogRecord &r, std::string_view row, std::int64_t now, const char *buffer) {
        static const std::regex process(R"(^Process: ([A-Za-z0-9_.:$-]+), PID: ([0-9]+)$)");
        static const std::regex stack(R"(^at ([A-Za-z0-9_.$]+)[(]([A-Za-z0-9_.:$ -]+)[)]$)");
        static const std::regex jni(
                R"(^[A-Za-z0-9_.]+: No implementation found for [A-Za-z0-9_.\[\]]+ ([A-Za-z0-9_.$]+[(][A-Za-z0-9_., \[\]]*[)]).*)");
        std::match_results<std::string_view::const_iterator> m;

        if (row.starts_with("FATAL EXCEPTION:")) {
            auto c = candidate("java_fatal", r, now);
            evidence(c, name_text, buffer, "AndroidRuntime", "anchor");
            add(std::move(c));

            return;
        }

        for (auto it = candidates.rbegin(); it != candidates.rend(); ++it) {
            if (it->kind != "java_fatal" || it->producer_pid != r.pid ||
                it->producer_tid != r.tid || now - it->started >= 1000) {
                continue;
            }

            if (std::regex_match(row.begin(), row.end(), m, process)) {
                const auto pid = decimal(m[2].str());

                if (pid == r.pid) {
                    it->process = identifier(m[1].str());
                }
            } else if (std::regex_match(row.begin(), row.end(), m, stack)) {
                const auto location = m[2].str();

                if (location == "Native Method" || location == "Unknown Source" ||
                    (location.find(' ') == std::string::npos &&
                     location.find(".java:") != std::string::npos)) {
                    frame(*it, m[1].str() + " (" + location + ")");
                }
            } else if (it->code.empty()) {
                auto code = identifier(row.substr(0, row.find(':')));

                if (code.find('.') == std::string::npos) {
                    return;
                }

                it->code = std::move(code);

                if (it->code == "java.lang.UnsatisfiedLinkError" &&
                    std::regex_match(row.begin(), row.end(), m, jni)) {
                    if (m[1].length() <= 150) {
                        it->summary = "No JNI implementation for " + m[1].str();
                    }
                }

                if (!it->process.empty()) {
                    correlate_pending(*it, now);
                }
            } else {
                return;
            }

            it->dirty = true;
            it->updated = now;

            return;
        }
    }

    void native(const LogRecord &r, std::string_view tag, std::string_view row, std::int64_t now,
                const char *buffer) {
        static const std::regex libc_signal(
                R"(^Fatal signal ([0-9]+) \((SIG[A-Z0-9]+)\).* in tid ([0-9]+) \([^)]*\)(?:, pid ([0-9]+) \([^)]*\))?.*$)");
        static const std::regex header(
                R"(^pid: ([0-9]+), tid: ([0-9]+), name: [^>]* >>> ([A-Za-z0-9_.:$-]+) <<<$)");
        static const std::regex signal(R"(^signal [0-9]+ \((SIG[A-Z0-9]+)\).*$)");
        static const std::regex backtrace(
                R"(^#[0-9]+ pc ([0-9a-fA-F]+)\s+(?:[^ ]*/)?([A-Za-z0-9_.+-]+)(?:\s+\(([^)]*)\))?.*$)");
        std::match_results<std::string_view::const_iterator> m;

        if (tag == "libc") {
            if (!std::regex_match(row.begin(), row.end(), m, libc_signal) ||
                decimal(m[3].str()) != r.tid || (m[4].matched && decimal(m[4].str()) != r.pid)) {
                return;
            }

            auto c = candidate("native_fatal", r, now);
            c.code = m[2].str();
            evidence(c, name_text, buffer, "libc", "anchor");
            add(std::move(c));

            return;
        }

        if (std::regex_match(row.begin(), row.end(), m, header)) {
            const auto pid = decimal(m[1].str()), tid = decimal(m[2].str());

            if (!pid || !tid || *pid == 0 || *tid == 0 || *pid > INT32_MAX || *tid > INT32_MAX) {
                return;
            }

            // Link the section after the signal line confirms the same native failure.
            auto c = candidate("debuggerd", r, now);
            c.pid = static_cast<std::uint32_t>(*pid);
            c.tid = static_cast<std::uint32_t>(*tid);
            c.process = identifier(m[3].str());
            add(std::move(c)).dirty = false;

            return;
        }

        if (std::regex_match(row.begin(), row.end(), m, signal)) {
            for (auto next = candidates.rbegin(); next != candidates.rend(); ++next) {
                if (next->kind != "debuggerd" || next->producer_pid != r.pid ||
                    next->producer_tid != r.tid || now - next->started >= 1000) {
                    continue;
                }

                Candidate *match = nullptr;

                for (auto &c : candidates) {
                    if (c.kind == "native_fatal" && c.pid == next->pid && c.tid == next->tid &&
                        c.code == m[1].str() && now - c.started < 1000 && c.producer_pid == c.pid) {
                        if (match) {
                            match = nullptr;
                            break;
                        }

                        match = &c;
                    }
                }

                if (match) {
                    match->process = next->process;
                    match->producer_pid = r.pid;
                    match->producer_tid = r.tid;
                    match->updated = now;
                    next->kind.clear();
                    evidence(*match, name_text, buffer, "DEBUG", "correlated");
                } else {
                    next->kind = "native_fatal";
                    next->code = m[1].str();
                    next->updated = now;
                    evidence(*next, name_text, buffer, "DEBUG", "anchor");
                }

                return;
            }
        } else if (std::regex_match(row.begin(), row.end(), m, backtrace)) {
            for (auto it = candidates.rbegin(); it != candidates.rend(); ++it) {
                if (it->kind == "native_fatal" && it->producer_pid == r.pid &&
                    it->producer_tid == r.tid && now - it->started < 1000) {
                    frame(*it, m[2].str() + " +0x" + m[1].str());
                    it->updated = now;

                    return;
                }
            }
        }
    }

    void text(const LogRecord &r, std::int64_t now) {
        if (r.payload.size() < 3 || (r.buffer != 0 && r.buffer != 3 && r.buffer != 4)) {
            return;
        }

        const auto tag_end = r.payload.find('\0', 1);

        if (tag_end == std::string_view::npos) {
            return;
        }

        const auto tag = r.payload.substr(1, tag_end - 1);

        if (tag != "AndroidRuntime" && tag != "libc" && tag != "DEBUG") {
            return;
        }

        const char *buffer = r.buffer == 4 ? "crash" : r.buffer == 3 ? "system" : "main";
        auto message = r.payload.substr(tag_end + 1);
        message = message.substr(0, message.find('\0'));

        while (!message.empty()) {
            const auto end = message.find('\n');
            const auto row = trim(message.substr(0, end));

            if (tag == "AndroidRuntime" && r.buffer == 4) {
                java(r, row, now, buffer);
            } else if (tag != "AndroidRuntime") {
                native(r, tag, row, now, buffer);
            }

            if (end == std::string_view::npos) {
                break;
            }

            message.remove_prefix(end + 1);
        }
    }

    Json cursor(std::uint64_t after) const {
        return {{"session_id", session},
                {"system", "multimedia"},
                {"stream_id", stream},
                {"after_seq", std::to_string(after)}};
    }
};

AndroidIncidents::AndroidIncidents(std::string session, std::string stream, std::size_t capacity)
    : impl_(std::make_unique<Impl>(std::move(session), std::move(stream), capacity)) {}

AndroidIncidents::~AndroidIncidents() = default;

void AndroidIncidents::observe_boot(std::string_view id, std::uint64_t generation) {
    auto &s = *impl_;
    std::lock_guard lock(s.mutex);

    if (s.closed || (s.boot == id && s.generation == generation)) {
        return;
    }

    const bool changed = !s.last_boot.empty() && (s.last_boot != id || s.generation != generation);

    if (changed) {
        s.gap("boot_changed", Json::array({name_text, name_events}), s.last_boot, id);
    }

    s.boot = s.last_boot = id;
    s.generation = generation;
    s.readers.fill({{}, "baseline_pending", false});
    s.candidates.clear();
    s.notify();
}

void AndroidIncidents::boot_unavailable(std::string_view reason) {
    auto &s = *impl_;
    std::lock_guard lock(s.mutex);

    if (!s.boot.empty()) {
        s.gap(reason, Json::array({name_text, name_events}), s.boot);
        s.boot.clear();
        s.candidates.clear();
    }

    s.reset_reader(IncidentSource::text, reason);
    s.reset_reader(IncidentSource::events, reason);
}

void AndroidIncidents::lost(IncidentSource source, std::string_view reason) {
    std::lock_guard lock(impl_->mutex);

    impl_->lose(source, reason);
}

void AndroidIncidents::close() {
    auto &s = *impl_;
    std::lock_guard lock(s.mutex);

    s.closed = true;
    s.boot.clear();
    s.candidates.clear();
    s.readers.fill({{}, "session_closed", false});
    s.notify();
}

bool AndroidIncidents::ingest(IncidentSource source, std::string_view bytes, std::int64_t now) {
    auto &s = *impl_;
    std::lock_guard lock(s.mutex);

    if (s.closed || s.boot.empty()) {
        return false;
    }

    auto &reader = s.readers[index(source)];

    if (bytes.size() > max_pending - reader.pending.size()) {
        s.lose(source, "transport_overflow");

        return false;
    }

    reader.pending += bytes;
    std::string_view remaining = reader.pending;

    while (remaining.size() >= 4) {
        const auto size = word(remaining, 0, 2);
        const auto header = word(remaining, 2, 2);

        if (size == 0 || size > max_record || header != 28) {
            s.lose(source, "unsupported_logcat_frame");

            return false;
        }

        if (remaining.size() < size + header) {
            break;
        }

        const LogRecord r{word(remaining, 4),  word(remaining, 8),  word(remaining, 12),
                          word(remaining, 16), word(remaining, 20), remaining.substr(header, size)};

        if ((source == IncidentSource::events) != (r.buffer == 2)) {
            s.lose(source, "unexpected_logcat_buffer");

            return false;
        }

        if (!reader.armed) {
            // Discard the one record allowed to precede this logd connection's live tail.
            reader.armed = true;
            reader.reason.clear();
            s.notify();
        } else if (source == IncidentSource::events) {
            s.am(r, now);
        } else {
            s.text(r, now);
        }

        remaining.remove_prefix(size + header);
    }

    reader.pending.erase(0, reader.pending.size() - remaining.size());

    return true;
}

void AndroidIncidents::flush(std::int64_t now) {
    std::lock_guard lock(impl_->mutex);

    impl_->expire(now);
}

Json AndroidIncidents::read(const Json &requested, std::size_t limit, int timeout_ms) {
    auto &s = *impl_;

    if (timeout_ms < 0 || timeout_ms > 60000 || limit == 0 || limit > 32) {
        throw VoyemuError("TEST_ARGUMENT", "invalid incident read bounds");
    }

    std::unique_lock lock(s.mutex);
    std::uint64_t after = 0;
    bool reset = false;

    if (!requested.is_null()) {
        if (!requested.is_object() || requested.size() != 4 || !requested.contains("session_id") ||
            requested.at("session_id") != s.session || !requested.contains("system") ||
            requested.at("system") != "multimedia" || !requested.contains("stream_id") ||
            !requested.at("stream_id").is_string() || !requested.contains("after_seq") ||
            !requested.at("after_seq").is_string()) {
            throw VoyemuError("TEST_ARGUMENT", "invalid incident cursor scope");
        }

        const auto sequence = decimal(requested.at("after_seq").get_ref<const std::string &>());

        if (!sequence || requested.at("stream_id").get_ref<const std::string &>().empty() ||
            requested.at("stream_id").get_ref<const std::string &>().size() > 64) {
            throw VoyemuError("TEST_ARGUMENT", "invalid incident cursor");
        }

        reset = requested.at("stream_id") != s.stream;
        after = reset ? (s.entries.empty() ? s.seq : s.entries.front().seq - 1) : *sequence;

        if (after > s.seq) {
            throw VoyemuError("TEST_ARGUMENT", "incident cursor is ahead of the journal");
        }
    }

    bool timed_out = false;

    if (timeout_ms && !reset) {
        const auto state = s.state;
        timed_out = !s.changed.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
            return s.closed || s.seq > after || s.state != state;
        });
    }

    Json page = Json::array();
    std::size_t bytes = 0;

    if (!reset && !s.entries.empty() && after < s.entries.front().seq - 1) {
        const auto floor = s.entries.front().seq - 1;

        page.push_back({{"type", "gap"},
                        {"reason", "journal_evicted"},
                        {"from_seq", std::to_string(after + 1)},
                        {"through_seq", std::to_string(floor)},
                        {"lost_records", std::to_string(floor - after)}});
        after = floor;
        bytes = page.back().dump().size();
    }

    if (!reset) {
        for (const auto &entry : s.entries) {
            if (entry.seq > after) {
                if (page.size() >= limit || bytes + entry.bytes > max_batch_bytes) {
                    break;
                }

                page.push_back(entry.value);
                after = entry.seq;
                bytes += entry.bytes;
            }
        }
    }

    auto source_status = [](const Impl::Reader &reader) {
        return Json{{"status", reader.armed ? "ready" : "unavailable"},
                    {"baseline", reader.armed ? "armed" : "pending"},
                    {"reason", reader.armed ? Json() : Json(reader.reason)},
                    {"coverage", "best_effort"}};
    };
    const auto &text = s.readers[0], &events = s.readers[1];

    return {{"source", "incidents"},
            {"system", "multimedia"},
            {"status", s.closed || !(text.armed || events.armed) ? "unavailable"
                       : text.armed && events.armed              ? "ready"
                                                                 : "partial"},
            {"boot", s.boot.empty()
                             ? Json()
                             : Json{{"id", s.boot}, {"generation", std::to_string(s.generation)}}},
            {"sources", {{name_text, source_status(text)}, {name_events, source_status(events)}}},
            {"cursor", s.cursor(after)},
            {"head_cursor", s.cursor(s.seq)},
            {"cursor_reset", reset},
            {"has_more", after < s.seq},
            {"timed_out", timed_out},
            {"entries", std::move(page)}};
}
} // namespace voyemu::runtime
