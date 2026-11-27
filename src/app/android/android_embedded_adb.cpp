#include "android_embedded_adb.hpp"
#include "adb_host.hpp"
#include "check.hpp"
#include "error.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace voyemu {
namespace {
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
constexpr std::size_t maximum_capture = 1024 * 1024;
constexpr std::size_t observer_pending = 6 * 1024 * 1024 + 2;
constexpr std::size_t aggregate_pending = 24 * 1024 * 1024;
constexpr std::size_t sync_chunk = 64 * 1024;
constexpr std::uint64_t maximum_transfer = 1024ULL * 1024 * 1024;

AdbBytes bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

std::string_view view(AdbBytes data) {
    if (!data.size) {
        return {};
    }

    return {reinterpret_cast<const char *>(data.data), data.size};
}

ProcessResult failed(int status) {
    return {1, std::string("ANDROID_ADB_SERVICE ") + std::to_string(status),
            status == ADB_STATUS_TIMEOUT};
}

std::string command_line(const std::vector<std::string> &arguments, bool exec) {
    if (arguments.size() < 2 || arguments[1].empty() || (!exec && arguments[1].starts_with("-"))) {
        throw VoyemuError("ANDROID_ADB_COMMAND", "fixed noninteractive shell command required");
    }

    auto result = arguments[1];

    for (std::size_t i = 2; i < arguments.size(); ++i) {
        result += ' ';
        // adb shell joins the caller's shell text. adb exec-out escapes trailing argv.
        result += exec ? android_shell_quote(arguments[i]) : arguments[i];
    }

    return result;
}

int time_left(Clock::time_point deadline) {
    return static_cast<int>(
            std::max(0ms, std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()))
                    .count());
}

struct SyncFailure : std::exception {
    explicit SyncFailure(ProcessResult value) : result(std::move(value)) {}

    ProcessResult result;
};

std::string sync_packet(std::string_view id, std::uint32_t value, std::string_view payload = {}) {
    std::string packet(id);

    for (unsigned shift = 0; shift != 32; shift += 8) {
        packet += static_cast<char>((value >> shift) & 0xff);
    }

    packet += payload;

    return packet;
}

class SyncConnection {
public:
    SyncConnection(AndroidEmbeddedAdb::Stream stream, Clock::time_point deadline,
                   std::stop_token stop)
        : stream_(std::move(stream)), deadline_(deadline), stop_(stop) {
        while (!receive()) {
            require_live();
            pause();
        }
    }

    void send(std::string_view data) {
        while (!data.empty()) {
            receive();
            require_live();
            const auto count = stream_.write(data);
            data.remove_prefix(count);

            if (!count) {
                pause();
            }
        }
    }

    std::string read(std::size_t size) {
        while (pending_.size() < size) {
            receive();

            if (pending_.size() < size) {
                require_live();
                pause();
            }
        }

        auto part = pending_.substr(0, size);
        pending_.erase(0, size);

        return part;
    }

    std::pair<std::string, std::uint32_t> header() {
        const auto data = read(8);
        std::uint32_t value = 0;

        for (unsigned i = 0; i != 4; ++i) {
            value |= static_cast<std::uint32_t>(static_cast<unsigned char>(data[4 + i])) << (8 * i);
        }

        auto id = data.substr(0, 4);

        if (id == "FAIL") {
            if (value > 4096) {
                throw SyncFailure{failed(ADB_STATUS_PROTOCOL_ERROR)};
            }

            throw SyncFailure{{1, read(value), false}};
        }

        return {std::move(id), value};
    }

    void finish() {
        if (!pending_.empty()) {
            throw SyncFailure{failed(ADB_STATUS_PROTOCOL_ERROR)};
        }

        if (!terminal_) {
            send(sync_packet("QUIT", 0));
        }

        while (!terminal_) {
            pause();
            receive();

            if (!pending_.empty()) {
                throw SyncFailure{failed(ADB_STATUS_PROTOCOL_ERROR)};
            }
        }
    }

private:
    void pause() const {
        std::this_thread::sleep_for(std::chrono::milliseconds(std::min(5, time_left(deadline_))));
    }

    void require_live() const {
        if (terminal_) {
            throw SyncFailure{failed(ADB_STATUS_PROTOCOL_ERROR)};
        }
    }

    bool receive() {
        if (stop_.stop_requested()) {
            throw SyncFailure{failed(ADB_STATUS_CANCELLED)};
        }

        if (!time_left(deadline_)) {
            throw SyncFailure{failed(ADB_STATUS_TIMEOUT)};
        }

        auto update = stream_.poll();

        if (update.output.size() > 4 * sync_chunk - pending_.size()) {
            throw SyncFailure{failed(ADB_STATUS_TRUNCATED)};
        }

        pending_ += update.output;

        if (update.terminal) {
            if (update.terminal->exit_code || update.terminal->timed_out) {
                throw SyncFailure{std::move(*update.terminal)};
            }

            terminal_ = true;
        }

        return update.opened;
    }

    AndroidEmbeddedAdb::Stream stream_;
    Clock::time_point deadline_;
    std::stop_token stop_;
    std::string pending_;
    bool terminal_ = false;
};

ProcessResult sync_file(AndroidEmbeddedAdb::Stream stream, bool push, const std::string &remote,
                        const std::filesystem::path &local, Clock::time_point deadline,
                        std::size_t limit, std::stop_token stop) {
    if (remote.empty() || remote.front() != '/' || remote.ends_with('/') || remote.size() > 1024 ||
        remote.find('\0') != std::string::npos) {
        throw VoyemuError("ANDROID_ADB_SYNC", "exact absolute guest file path required");
    }

    try {
        if (push) {
            if (!std::filesystem::is_regular_file(local) ||
                std::filesystem::file_size(local) > maximum_transfer) {
                throw VoyemuError("ANDROID_ADB_SYNC", "bounded regular source file required");
            }

            std::ifstream input(local, std::ios::binary);

            if (!input) {
                throw VoyemuError("ANDROID_ADB_SYNC", "source file unavailable");
            }

            SyncConnection connection(std::move(stream), deadline, stop);
            constexpr unsigned file_type = 0100000;
            const auto mode = static_cast<unsigned>(std::filesystem::status(local).permissions()) &
                              0777;
            const auto target = remote + "," + std::to_string(file_type | mode);

            if (target.size() > 1024) {
                throw VoyemuError("ANDROID_ADB_SYNC", "guest path exceeds SEND bound");
            }

            connection.send(sync_packet("SEND", static_cast<std::uint32_t>(target.size()), target));
            std::array<char, sync_chunk> buffer{};
            std::uint64_t total = 0;

            while (input.read(buffer.data(), buffer.size()) || input.gcount()) {
                const auto count = static_cast<std::uint32_t>(input.gcount());
                total += count;

                if (total > maximum_transfer) {
                    throw SyncFailure{failed(ADB_STATUS_TRUNCATED)};
                }

                connection.send(sync_packet("DATA", count, {buffer.data(), count}));
            }

            if (!input.eof() || input.bad()) {
                throw SyncFailure{failed(ADB_STATUS_IO_ERROR)};
            }

            const auto seconds =
                    std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::file_clock::to_sys(std::filesystem::last_write_time(local))
                                    .time_since_epoch())
                            .count();
            const auto mtime =
                    static_cast<std::uint32_t>(std::clamp<std::int64_t>(seconds, 0, UINT32_MAX));
            connection.send(sync_packet("DONE", mtime));

            if (connection.header() != std::pair<std::string, std::uint32_t>{"OKAY", 0}) {
                throw SyncFailure{failed(ADB_STATUS_PROTOCOL_ERROR)};
            }

            connection.finish();

            return {0, {}, false};
        }

        struct TemporaryFile {
            std::filesystem::path path;

            ~TemporaryFile() {
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
            }
        } temporary{local.parent_path() / (".voyemu-adb-" + random_token())};
        std::ofstream output(temporary.path, std::ios::binary | std::ios::trunc);

        if (!output) {
            throw VoyemuError("ANDROID_ADB_SYNC", "destination file unavailable");
        }

        SyncConnection connection(std::move(stream), deadline, stop);
        connection.send(sync_packet("RECV", static_cast<std::uint32_t>(remote.size()), remote));
        std::uint64_t total = 0;

        for (;;) {
            const auto [id, count] = connection.header();

            if (id == "DONE" && !count) {
                break;
            }

            if (id != "DATA" || !count || count > sync_chunk) {
                throw SyncFailure{failed(ADB_STATUS_PROTOCOL_ERROR)};
            }

            total += count;

            if (total > maximum_transfer) {
                throw SyncFailure{failed(ADB_STATUS_TRUNCATED)};
            }

            const auto data = connection.read(count);

            if (!output.write(data.data(), data.size())) {
                throw SyncFailure{failed(ADB_STATUS_IO_ERROR)};
            }
        }

        connection.finish();
        output.close();

        if (!output) {
            throw SyncFailure{failed(ADB_STATUS_IO_ERROR)};
        }

        if (stop.stop_requested()) {
            throw SyncFailure{failed(ADB_STATUS_CANCELLED)};
        }

        if (!time_left(deadline)) {
            throw SyncFailure{failed(ADB_STATUS_TIMEOUT)};
        }

        std::filesystem::rename(temporary.path, local);

        return {0, {}, false};
    } catch (SyncFailure &failure) {
        if (failure.result.output.size() > limit) {
            throw VoyemuError("PROCESS_EXTENT", "capture exceeded bound");
        }

        return std::move(failure.result);
    }
}
} // namespace

struct AndroidEmbeddedAdb::Operation {
    AdbOperationId id = 0;
    std::uint64_t generation = 0;
    std::size_t limit = 0;
    std::uint32_t service = 0;
    int status = ADB_STATUS_OK;
    bool opened = false;
    bool separate_stderr = false;
    std::string output, error_output;
    std::string control_prefix;
    std::optional<ProcessResult> terminal;
};

struct AndroidEmbeddedAdb::Impl {
    explicit Impl(unsigned port) : console(port), serial("emulator-" + std::to_string(port)) {}

    const unsigned console;
    const std::string serial;
    AdbHost *host = nullptr;
    std::mutex lifecycle;
    std::mutex mutex;
    std::condition_variable_any changed;
    std::map<AdbOperationId, std::shared_ptr<Operation>> operations;
    std::thread pump;
    struct Fence {
        std::mutex mutex;
        std::function<bool()> check;
    };
    std::unique_ptr<Fence> fence = std::make_unique<Fence>();
    std::uint64_t generation = 0;
    std::uint64_t retired_generation = 0;
    std::uint64_t attachment = 0;
    std::size_t reserved_pending = 0;
    bool attached = false;
    bool stopping = false;
    bool shutdown_complete = false;

    static std::int32_t connect_allowed(void *context) noexcept {
        auto &fence = *static_cast<Fence *>(context);
        std::lock_guard lock(fence.mutex);
        try {
            return fence.check && fence.check() ? 1 : 0;
        } catch (...) {
            return 0;
        }
    }

    void stop_operation(Operation &operation, int status) {
        if (operation.terminal) {
            return;
        }

        operation.status = status;
        operation.terminal = failed(status);

        if (operation.id) {
            adb_host_cancel(host, operation.id);
            reserved_pending -= operation.limit;
            operations.erase(operation.id);
        }
    }

    void cancel_all() {
        while (!operations.empty()) {
            auto operation = operations.begin()->second;
            stop_operation(*operation, ADB_STATUS_CANCELLED);
        }

        changed.notify_all();
    }

    void dispatch(const AdbEvent &event) {
        if (event.type == ADB_EVENT_DEVICE && view(event.serial) == serial) {
            if (!attached) {
                return;
            }

            if (event.device_state == ADB_DEVICE_ONLINE) {
                if (event.device_generation > retired_generation) {
                    generation = event.device_generation;
                }
            } else if (generation == event.device_generation) {
                generation = 0;
            }

            return;
        }

        const auto found = operations.find(event.operation);

        if (found == operations.end()) {
            return;
        }

        auto operation = found->second;

        if (event.device_generation != operation->generation) {
            stop_operation(*operation, ADB_STATUS_STALE_DEVICE);
        } else if (event.type == ADB_EVENT_OPENED) {
            operation->opened = true;
        } else if (event.type == ADB_EVENT_STDOUT || event.type == ADB_EVENT_STDERR) {
            if (event.payload.size >
                operation->limit - operation->output.size() - operation->error_output.size()) {
                stop_operation(*operation, ADB_STATUS_TRUNCATED);
            } else {
                const auto data = view(event.payload);
                auto &target = event.type == ADB_EVENT_STDERR && operation->separate_stderr
                                       ? operation->error_output
                                       : operation->output;
                target.append(data);

                if (operation->service == ADB_SERVICE_ROOT ||
                    operation->service == ADB_SERVICE_REBOOT) {
                    operation->control_prefix.append(
                            data.substr(0, 32 - operation->control_prefix.size()));
                }
            }
        } else if (event.type == ADB_EVENT_TERMINAL) {
            operation->status = event.status;
            operation->terminal =
                    event.status == ADB_STATUS_OK
                            ? ProcessResult{event.has_remote_exit_code ? event.remote_exit_code : 0,
                                            {},
                                            false}
                            : failed(event.status);
            const bool reboot_rejected = operation->service == ADB_SERVICE_REBOOT &&
                                         !operation->control_prefix.empty();

            if (reboot_rejected ||
                (operation->service == ADB_SERVICE_ROOT &&
                 operation->control_prefix.starts_with("adbd cannot run as root"))) {
                operation->terminal->exit_code = 1;
            }

            // Once a restart was accepted, never satisfy a subsequent wait from the old adbd.
            if (operation->opened && event.status == ADB_STATUS_OK &&
                ((operation->service == ADB_SERVICE_REBOOT && !reboot_rejected) ||
                 (operation->service == ADB_SERVICE_ROOT &&
                  operation->control_prefix.starts_with("restarting adbd as root")))) {
                retired_generation = std::max(retired_generation, operation->generation);

                if (generation == operation->generation) {
                    generation = 0;
                }
            }

            reserved_pending -= operation->limit;
            operations.erase(found);
        }
    }

    void consume() {
        for (;;) {
            std::uint64_t receipt_attachment;
            {
                std::lock_guard lock(mutex);

                if (stopping) {
                    return;
                }

                receipt_attachment = attachment;
            }
            AdbEvent event{};

            if (adb_host_next_event(host, 25, &event) != ADB_STATUS_OK) {
                continue;
            }

            bool refresh = false;
            {
                std::lock_guard lock(mutex);

                if (!stopping) {
                    refresh = event.type == ADB_EVENT_DEVICE && receipt_attachment != attachment;

                    if (!refresh) {
                        dispatch(event);
                    }
                }

                adb_host_event_release(&event);
                changed.notify_all();
            }

            // A DEVICE fetched across reattachment can describe the retired
            // listener. Ask the looper to republish its current selection.
            if (refresh) {
                adb_host_scan(host);
            }
        }
    }
};

AndroidEmbeddedAdb::Stream::Stream(std::shared_ptr<Impl> owner,
                                   std::shared_ptr<Operation> operation)
    : owner_(std::move(owner)), operation_(std::move(operation)) {}

AndroidEmbeddedAdb::Stream::~Stream() {
    cancel();
}

AndroidEmbeddedAdb::Stream::Stream(Stream &&) noexcept = default;
AndroidEmbeddedAdb::Stream &AndroidEmbeddedAdb::Stream::operator=(Stream &&other) noexcept {
    if (this != &other) {
        cancel();
        owner_ = std::move(other.owner_);
        operation_ = std::move(other.operation_);
    }

    return *this;
}

AndroidEmbeddedAdb::Stream::Poll AndroidEmbeddedAdb::Stream::poll() {
    if (!operation_) {
        return {false, {}, failed(ADB_STATUS_INVALID), ADB_STATUS_INVALID, {}};
    }

    std::lock_guard lock(owner_->mutex);
    auto output = std::exchange(operation_->output, {});

    if (operation_->service == ADB_SERVICE_SYNC && !output.empty() && !operation_->terminal) {
        adb_host_grant_sync_output(owner_->host, operation_->id, output.size());
    }

    return {operation_->opened, std::move(output), operation_->terminal, operation_->status,
            std::exchange(operation_->error_output, {})};
}

std::size_t AndroidEmbeddedAdb::Stream::write(std::string_view data) {
    if (!operation_) {
        return 0;
    }

    std::lock_guard lock(owner_->mutex);

    if (operation_->terminal || !operation_->opened) {
        return 0;
    }

    std::size_t count = 0;
    const auto status = adb_host_write(owner_->host, operation_->id, bytes(data), &count);

    if (status == ADB_STATUS_OK) {
        return count;
    }

    // A stream may have retired in the ABI before its terminal event was dispatched.
    if (status != ADB_STATUS_WOULD_BLOCK && status != ADB_STATUS_INVALID) {
        owner_->stop_operation(*operation_, status);
    }

    return 0;
}

void AndroidEmbeddedAdb::Stream::close_stdin() {
    if (!operation_) {
        return;
    }

    std::lock_guard lock(owner_->mutex);

    if (!operation_->terminal && operation_->service == ADB_SERVICE_SHELL_V2_RAW) {
        adb_host_close_stdin(owner_->host, operation_->id);
    }
}

void AndroidEmbeddedAdb::Stream::cancel() noexcept {
    if (!operation_) {
        return;
    }

    std::lock_guard lock(owner_->mutex);
    owner_->stop_operation(*operation_, ADB_STATUS_CANCELLED);
    owner_->changed.notify_all();
}

AndroidEmbeddedAdb::AndroidEmbeddedAdb(unsigned port) : impl_(std::make_shared<Impl>(port)) {
    if (port < 1024 || port > 65534 || port % 2) {
        throw VoyemuError("ANDROID_ADB_BINDING", "canonical emulator console port required");
    }

    const AdbHostConfig config{0, 16 * 1024 * 1024};
    // Library messages may contain guest data and cannot share the supervisor JSON log.
    static std::once_flag adb_logger;
    std::call_once(adb_logger, [] {
        adb_host_set_log_callback(nullptr);
    });

    if (const auto status = adb_host_create(&config, &impl_->host); status != ADB_STATUS_OK) {
        throw VoyemuError("ANDROID_ADB_HOST", "create failed " + std::to_string(status));
    }

    try {
        impl_->pump = std::thread([owner = impl_.get()] {
            owner->consume();
        });
    } catch (...) {
        shutdown();
        throw;
    }
}

AndroidEmbeddedAdb::~AndroidEmbeddedAdb() {
    shutdown();
}

void AndroidEmbeddedAdb::attach(std::function<bool()> fence) {
    std::lock_guard lifecycle(impl_->lifecycle);
    std::lock_guard lock(impl_->mutex);

    if (impl_->attached || impl_->stopping || !fence) {
        throw VoyemuError("ANDROID_ADB_OWNER", "invalid attachment lifetime");
    }

    impl_->fence->check = std::move(fence);
    const auto status = adb_host_attach_owned_emulator(impl_->host, impl_->console,
                                                       &Impl::connect_allowed, impl_->fence.get());

    if (status != ADB_STATUS_OK) {
        impl_->fence->check = {};
        throw VoyemuError("ANDROID_ADB_OWNER", "attachment failed " + std::to_string(status));
    }

    ++impl_->attachment;
    impl_->attached = true;
}

void AndroidEmbeddedAdb::detach() {
    std::lock_guard lifecycle(impl_->lifecycle);
    {
        std::lock_guard lock(impl_->mutex);

        if (!impl_->attached) {
            return;
        }

        impl_->retired_generation = std::max(impl_->retired_generation, impl_->generation);
        impl_->generation = 0;
        impl_->attached = false;
        impl_->cancel_all();
    }
    const auto status = adb_host_detach_emulator(impl_->host);

    if (status != ADB_STATUS_OK) {
        throw VoyemuError("ANDROID_ADB_OWNER", "detach failed " + std::to_string(status));
    }

    impl_->fence->check = {};
}

void AndroidEmbeddedAdb::cancel_all() noexcept {
    std::lock_guard lock(impl_->mutex);

    impl_->cancel_all();
}

bool AndroidEmbeddedAdb::shutdown() noexcept {
    std::lock_guard lifecycle(impl_->lifecycle);
    {
        std::lock_guard lock(impl_->mutex);

        if (impl_->stopping) {
            return impl_->shutdown_complete;
        }

        impl_->stopping = true;
        impl_->attached = false;
        impl_->cancel_all();
    }
    {
        std::lock_guard lock(impl_->fence->mutex);
        impl_->fence->check = {};
    }

    if (impl_->pump.joinable()) {
        impl_->pump.join();
    }

    auto *host = std::exchange(impl_->host, nullptr);

    if (adb_host_shutdown(host, 1000) == ADB_STATUS_OK) {
        adb_host_destroy(host);
        impl_->shutdown_complete = true;

        return true;
    }

    // The ABI retains this context until the connector joins. Its callback can no
    // longer reach Session. Finish cleanup without extending the caller's deadline.
    auto *fence = impl_->fence.release();
    try {
        std::thread([host, fence] {
            if (adb_host_shutdown(host, 3600000) == ADB_STATUS_OK) {
                adb_host_destroy(host);
                delete fence;
            }
        }).detach();
    } catch (...) {
        // Ignored: the process still owns the context while the ABI cleanup runs.
    }

    return false;
}

AndroidEmbeddedAdb::Lease AndroidEmbeddedAdb::lease() const {
    std::lock_guard lock(impl_->mutex);

    return Lease(impl_, impl_->attachment, impl_->generation);
}

bool AndroidEmbeddedAdb::current(const Lease &expected) const {
    std::lock_guard lock(impl_->mutex);

    return impl_->attached && impl_->generation && expected.owner_.lock() == impl_ &&
           expected.attachment_ == impl_->attachment && expected.generation_ == impl_->generation;
}

AndroidEmbeddedAdb::Stream AndroidEmbeddedAdb::open(std::uint32_t service, std::string_view command,
                                                    int timeout_ms, std::size_t pending_limit,
                                                    const std::optional<Lease> &expected,
                                                    bool separate_stderr) {
    if (timeout_ms < 0 || timeout_ms > 3600000 || pending_limit > observer_pending ||
        (!timeout_ms && service != ADB_SERVICE_SHELL_V2_RAW)) {
        throw VoyemuError("ANDROID_ADB_SERVICE", "invalid stream bounds");
    }

    auto operation = std::make_shared<Operation>();
    operation->limit = pending_limit;
    operation->service = service;
    operation->separate_stderr = separate_stderr;
    std::lock_guard lock(impl_->mutex);
    operation->generation = impl_->generation;

    if (expected &&
        (expected->owner_.lock() != impl_ || expected->attachment_ != impl_->attachment ||
         expected->generation_ != impl_->generation)) {
        operation->status = ADB_STATUS_STALE_DEVICE;
        operation->terminal = failed(operation->status);
    } else if (!impl_->attached || !operation->generation) {
        operation->status = ADB_STATUS_OFFLINE;
        operation->terminal = failed(operation->status);
    } else if (pending_limit > aggregate_pending - impl_->reserved_pending) {
        operation->status = ADB_STATUS_BUSY;
        operation->terminal = failed(operation->status);
    } else {
        const auto status = adb_host_open(impl_->host, bytes(impl_->serial), operation->generation,
                                          service, bytes(command), timeout_ms, &operation->id);

        if (status == ADB_STATUS_OK) {
            impl_->operations.emplace(operation->id, operation);
            impl_->reserved_pending += pending_limit;
        } else {
            operation->status = status;
            operation->terminal = failed(status);
        }
    }

    return Stream(impl_, std::move(operation));
}

AndroidEmbeddedAdb::Stream AndroidEmbeddedAdb::open_shell(const std::vector<std::string> &arguments,
                                                          int timeout_ms, std::size_t pending_limit,
                                                          const std::optional<Lease> &expected,
                                                          bool separate_stderr) {
    if (arguments.empty() || arguments[0] != "shell") {
        throw VoyemuError("ANDROID_ADB_COMMAND", "shell required");
    }

    return open(ADB_SERVICE_SHELL_V2_RAW, command_line(arguments, false), timeout_ms, pending_limit,
                expected, separate_stderr);
}

AndroidEmbeddedAdb::Stream AndroidEmbeddedAdb::open_root(int timeout_ms,
                                                         std::size_t pending_limit) {
    return open(ADB_SERVICE_ROOT, {}, timeout_ms, pending_limit);
}

AndroidEmbeddedAdb::Stream AndroidEmbeddedAdb::open_observer(std::string_view id, int timeout_ms) {
    if (!hex_text(id, 32)) {
        throw VoyemuError("ANDROID_ADB_COMMAND", "owned observer socket ID required");
    }

    return open(ADB_SERVICE_OBSERVER, id, timeout_ms, observer_pending);
}

ProcessResult AndroidEmbeddedAdb::run(const std::vector<std::string> &arguments, int timeout_ms,
                                      std::size_t limit, std::stop_token cancellation,
                                      std::optional<Lease> expected) {
    if (timeout_ms < 1 || timeout_ms > 600000 || limit > maximum_capture) {
        throw VoyemuError("PROCESS_BOUNDS", "invalid ADB capture bounds");
    }

    if (arguments.empty()) {
        throw VoyemuError("ANDROID_ADB_COMMAND", "guest operation required");
    }

    if (cancellation.stop_requested()) {
        return failed(ADB_STATUS_CANCELLED);
    }

    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    const auto &action = arguments.front();

    if (action == "wait-for-device" && arguments.size() == 1) {
        std::unique_lock lock(impl_->mutex);
        const auto attachment = impl_->attachment;

        if (expected && (expected->owner_.lock() != impl_ || expected->attachment_ != attachment)) {
            return failed(ADB_STATUS_STALE_DEVICE);
        }

        const auto ready = impl_->changed.wait_until(lock, cancellation, deadline, [&] {
            return impl_->generation || !impl_->attached || impl_->attachment != attachment;
        });

        if (cancellation.stop_requested()) {
            return failed(ADB_STATUS_CANCELLED);
        }

        if (!ready) {
            return failed(ADB_STATUS_TIMEOUT);
        }

        if (impl_->attachment != attachment) {
            return failed(ADB_STATUS_STALE_DEVICE);
        }

        return impl_->generation ? ProcessResult{0, {}, false} : failed(ADB_STATUS_OFFLINE);
    }

    if ((action == "push" || action == "pull") && arguments.size() == 3) {
        const bool push = action == "push";
        const auto &filename = arguments[push ? 1 : 2];
        const auto path = std::filesystem::path(std::u8string_view(
                reinterpret_cast<const char8_t *>(filename.data()), filename.size()));

        return sync_file(open(ADB_SERVICE_SYNC, {}, timeout_ms, 2 * sync_chunk, expected), push,
                         arguments[push ? 2 : 1], path, deadline, limit, cancellation);
    }

    auto stream = [&] {
        if (action == "shell") {
            return open(ADB_SERVICE_SHELL_V2_RAW, command_line(arguments, false), timeout_ms, limit,
                        expected);
        }

        if (action == "exec-out") {
            return open(ADB_SERVICE_EXEC_RAW, command_line(arguments, true), timeout_ms, limit,
                        expected);
        }

        if (arguments.size() == 1) {
            if (action == "root") {
                return open(ADB_SERVICE_ROOT, {}, timeout_ms, limit, expected);
            }

            if (action == "remount") {
                return open(ADB_SERVICE_REMOUNT, {}, timeout_ms, limit, expected);
            }

            if (action == "reboot") {
                return open(ADB_SERVICE_REBOOT, {}, timeout_ms, limit, expected);
            }
        }

        throw VoyemuError("ANDROID_ADB_COMMAND", "unsupported guest operation");
    }();

    if (action == "shell") {
        stream.close_stdin();
    }

    std::string output;

    for (;;) {
        std::unique_lock lock(impl_->mutex);
        const auto &operation = *stream.operation_;
        impl_->changed.wait_until(lock, cancellation, deadline, [&] {
            return !operation.output.empty() || operation.terminal;
        });
        lock.unlock();

        if (cancellation.stop_requested()) {
            return failed(ADB_STATUS_CANCELLED);
        }

        auto update = stream.poll();

        if (update.output.size() > limit - output.size()) {
            throw VoyemuError("PROCESS_EXTENT", "capture exceeded bound");
        }

        output += update.output;

        if (update.terminal) {
            auto result = std::move(*update.terminal);

            if (update.status == ADB_STATUS_TRUNCATED) {
                throw VoyemuError("PROCESS_EXTENT", "capture exceeded bound");
            }

            if (!output.empty()) {
                result.output = std::move(output);
            }

            return result;
        }

        if (!time_left(deadline)) {
            return {1, std::move(output), true};
        }
    }
}
} // namespace voyemu
