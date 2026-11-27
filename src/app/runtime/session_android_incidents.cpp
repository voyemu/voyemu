#include "adb_host.hpp"
#include "session_internal.hpp"

#include <string_view>

namespace voyemu {
namespace {
using namespace std::chrono_literals;
using runtime::IncidentSource;

constexpr std::array sources{IncidentSource::text, IncidentSource::events};
constexpr std::string_view boot_prefix = "VOYEMU_INCIDENT_BOOT ";

std::vector<std::string> incident_shell(IncidentSource source) {
    std::string command = "set -e; boot=$(cat /proc/sys/kernel/random/boot_id); "
                          "printf 'VOYEMU_INCIDENT_BOOT %s\\n' \"$boot\"; ";

    command += source == IncidentSource::text ? "exec logcat -B -T 1 -b main -b system -b crash"
                                              : "exec logcat -B -T 1 -b events";

    return {"shell", std::move(command)};
}
} // namespace

std::shared_ptr<runtime::AndroidIncidents> Session::android_incident_journal() {
    if (!android_incidents_) {
        android_incidents_ = std::make_shared<runtime::AndroidIncidents>(session_id_,
                                                                         random_token());

        if (stopped_) {
            android_incidents_->close();
        }
    }

    return android_incidents_;
}

void Session::retire_android_incidents(std::string_view reason, bool close) {
    if (!android_incidents_) {
        return;
    }

    for (auto &reader : android_incident_readers_) {
        reader = {};
    }

    android_incident_boot_.clear();

    if (close) {
        android_incidents_->close();
    } else {
        android_incidents_->boot_unavailable(reason);
    }
}

void Session::poll_android_incidents() {
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now();

    if (now < next_incident_poll_) {
        return;
    }

    next_incident_poll_ = now + 100ms;

    if (stopped_ || test_services_closed_ || android_spec_.empty() || !android_powered_ ||
        !android_identity_ || android_identity_mismatch_ || !android_transport_ready_ ||
        !android_boot_id_valid(android_transport_boot_)) {
        if (!android_incident_boot_.empty()) {
            retire_android_incidents("boot_unverified");
        }

        return;
    }

    const auto pid = android_.pid();
    const auto generation = android_generation_;
    const auto boot = android_transport_boot_;
    auto monitor = android_incident_journal();

    if (android_incident_boot_ != boot || android_incident_generation_ != generation ||
        android_incident_sdk_pid_ != pid) {
        for (auto &reader : android_incident_readers_) {
            reader = {};
        }

        monitor->observe_boot(boot, generation);
        android_incident_boot_ = boot;
        android_incident_generation_ = generation;
        android_incident_sdk_pid_ = pid;
    }

    std::shared_ptr<AndroidEmbeddedAdb> transport;
    try {
        transport = owned_android_adb(android_spec_, pid, generation);
    } catch (const VoyemuError &) {
        retire_android_incidents("ownership_unverified");

        return;
    }

    const auto now_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    for (std::size_t i = 0; i < sources.size(); ++i) {
        const auto source = sources[i];
        auto &reader = android_incident_readers_[i];
        const auto lost = [&](std::string_view reason) {
            reader = {};
            reader.next_open = now + 1s;
            monitor->lost(source, reason);
        };

        if (!reader.stream && now >= reader.next_open) {
            const auto lease = transport->lease();

            if (!transport->current(lease)) {
                lost("adb_offline");
                continue;
            }

            try {
                reader.stream = transport->open_shell(incident_shell(source), 0, 256 * 1024, lease,
                                                      true);
                reader.stream.close_stdin();
                reader.lease = lease;
                reader.opening_deadline = now + 5s;
            } catch (const VoyemuError &) {
                lost("logcat_open_failed");
                continue;
            }
        }

        if (!reader.stream || !reader.lease) {
            continue;
        }

        const auto update = reader.stream.poll();

        if (!transport->current(*reader.lease)) {
            lost("transport_lost");
            continue;
        }

        if (!update.error_output.empty() || update.terminal) {
            const auto reason = !update.error_output.empty()            ? "logcat_unavailable"
                                : update.status == ADB_STATUS_TRUNCATED ? "transport_overflow"
                                                                        : "stream_ended";
            lost(reason);
            continue;
        }

        if (!reader.verified) {
            reader.prefix += update.output;
            const auto end = reader.prefix.find('\n');

            if (end == std::string::npos) {
                if (reader.prefix.size() > boot_prefix.size() + 36 ||
                    now >= reader.opening_deadline) {
                    lost("boot_proof_missing");
                }

                continue;
            }

            const auto header = std::string_view(reader.prefix).substr(0, end);

            if (!header.starts_with(boot_prefix) || header.substr(boot_prefix.size()) != boot) {
                lost("boot_proof_mismatch");
                continue;
            }

            reader.verified = true;

            if (!monitor->ingest(source, std::string_view(reader.prefix).substr(end + 1), now_ms)) {
                lost("logcat_frame_rejected");
            }

            reader.prefix.clear();
        } else if (!monitor->ingest(source, update.output, now_ms)) {
            lost("logcat_frame_rejected");
        }
    }

    monitor->flush(now_ms);
}
} // namespace voyemu
