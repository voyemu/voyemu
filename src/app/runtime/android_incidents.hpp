#pragma once

#include "model.hpp"
#include <memory>

namespace voyemu::runtime {
enum class IncidentSource {
    text,
    events
};

class AndroidIncidents {
public:
    AndroidIncidents(std::string session, std::string stream, std::size_t capacity = 512);
    ~AndroidIncidents();

    void observe_boot(std::string_view id, std::uint64_t generation);
    void lost(IncidentSource source, std::string_view reason);
    void boot_unavailable(std::string_view reason);
    void close();

    // A boot-fenced, bounded logcat -B stream that returns at most one retained frame first.
    bool ingest(IncidentSource source, std::string_view bytes, std::int64_t now_ms);
    void flush(std::int64_t now_ms);
    Json read(const Json &cursor, std::size_t limit, int timeout_ms);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace voyemu::runtime
