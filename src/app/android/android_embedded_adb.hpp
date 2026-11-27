#pragma once

#include "process.hpp"
#include <stop_token>

namespace voyemu {
// One owned emulator transport per supervisor process.
class AndroidEmbeddedAdb {
    struct Impl;
    struct Operation;

public:
    class Lease {
        friend class AndroidEmbeddedAdb;

        Lease(std::weak_ptr<Impl> owner, std::uint64_t attachment, std::uint64_t generation)
            : owner_(std::move(owner)), attachment_(attachment), generation_(generation) {}

        std::weak_ptr<Impl> owner_;
        std::uint64_t attachment_;
        std::uint64_t generation_;
    };

    class Stream {
    public:
        struct Poll {
            bool opened = false;
            std::string output;
            std::optional<ProcessResult> terminal;
            int status = 0;
            std::string error_output;
        };

        Stream() = default;
        ~Stream();
        Stream(Stream &&) noexcept;
        Stream &operator=(Stream &&) noexcept;
        Stream(const Stream &) = delete;
        Stream &operator=(const Stream &) = delete;

        explicit operator bool() const noexcept {
            return operation_ != nullptr;
        }
        Poll poll();
        std::size_t write(std::string_view bytes);
        void close_stdin();
        void cancel() noexcept;

    private:
        friend class AndroidEmbeddedAdb;
        Stream(std::shared_ptr<Impl>, std::shared_ptr<Operation>);
        std::shared_ptr<Impl> owner_;
        std::shared_ptr<Operation> operation_;
    };

    explicit AndroidEmbeddedAdb(unsigned console_port);
    ~AndroidEmbeddedAdb();
    AndroidEmbeddedAdb(const AndroidEmbeddedAdb &) = delete;
    AndroidEmbeddedAdb &operator=(const AndroidEmbeddedAdb &) = delete;

    void attach(std::function<bool()> fence);
    void detach();
    void cancel_all() noexcept;
    bool shutdown() noexcept;
    // Capture while the caller holds its Session ownership fence.
    Lease lease() const;
    bool current(const Lease &lease) const;
    ProcessResult run(const std::vector<std::string> &arguments, int timeout_ms,
                      std::size_t output_limit, std::stop_token cancellation = {},
                      std::optional<Lease> expected = {});
    // A zero timeout retains this shell until the stream's owner cancels it.
    Stream open_shell(const std::vector<std::string> &arguments, int timeout_ms,
                      std::size_t pending_limit = 128 * 1024,
                      const std::optional<Lease> &expected = {}, bool separate_stderr = false);
    Stream open_root(int timeout_ms, std::size_t pending_limit);
    Stream open_observer(std::string_view observer_id, int timeout_ms);

private:
    Stream open(std::uint32_t service, std::string_view command, int timeout_ms,
                std::size_t pending_limit, const std::optional<Lease> &expected = {},
                bool separate_stderr = false);
    std::shared_ptr<Impl> impl_;
};
} // namespace voyemu
