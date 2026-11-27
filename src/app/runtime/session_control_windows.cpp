#include "android_port_lease.hpp"
#include "error.hpp"
#include "session_windows.hpp"

namespace voyemu {
using namespace session_detail;
namespace session_detail {
std::wstring pipe_name(const std::filesystem::path &endpoint) {
    auto name = endpoint.wstring();

    if (!name.starts_with(L"\\\\.\\pipe\\voyemu-")) {
        throw VoyemuError("IPC_PATH", "private Voyemu named pipe required");
    }

    return name;
}

HANDLE pipe_connect(const std::filesystem::path &endpoint, int timeout) {
    const auto name = pipe_name(endpoint);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);

    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();

        if (WaitNamedPipeW(name.c_str(),
                           static_cast<DWORD>(std::clamp<std::int64_t>(remaining, 1, 50)))) {
            HANDLE pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                      OPEN_EXISTING, 0, nullptr);

            if (pipe != INVALID_HANDLE_VALUE) {
                return pipe;
            }
        }

        const auto error = GetLastError();

        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY &&
            error != ERROR_SEM_TIMEOUT && error != ERROR_HANDLES_CLOSED) {
            throw VoyemuError("IPC_CONNECT",
                              "named pipe unavailable (" + std::to_string(error) + ")");
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    throw VoyemuError("IPC_CONNECT", "named pipe connection timeout");
}

void pipe_write(HANDLE pipe, const std::string &text) {
    DWORD count = 0;

    if (!WriteFile(pipe, text.data(), static_cast<DWORD>(text.size()), &count, nullptr) ||
        count != text.size()) {
        throw VoyemuError("IPC_WRITE_UNKNOWN", "named pipe failed");
    }
}

void pipe_write_response(HANDLE pipe, const std::string &text, ClusterDeadline deadline) {
    for (std::size_t offset = 0; offset < text.size();) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "named pipe write timeout");
        }

        DWORD count = 0;
        const auto requested =
                static_cast<DWORD>(std::min<std::size_t>(text.size() - offset, 16384));

        if (!WriteFile(pipe, text.data() + offset, requested, &count, nullptr)) {
            throw VoyemuError("IPC_WRITE_UNKNOWN", "named pipe failed");
        }

        if (count == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        offset += count;
    }
}

std::string pipe_read(HANDLE pipe, int timeout, std::size_t limit) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    std::string output;

    while (output.size() < limit) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "named pipe timeout");
        }

        DWORD available = 0;

        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            throw VoyemuError("IPC_READ_UNKNOWN", "pipe closed");
        }

        if (!available) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }

        char buffer[4096];
        DWORD count = 0;
        const auto offset = output.size();
        const auto requested = static_cast<DWORD>(
                std::min<std::size_t>({available, sizeof buffer, limit - offset}));

        if (!ReadFile(pipe, buffer, requested, &count, nullptr)) {
            throw VoyemuError("IPC_READ_UNKNOWN", "named pipe failed");
        }

        output.append(buffer, count);
        const auto end = output.find('\n', offset);

        if (end != std::string::npos) {
            return output.substr(0, end);
        }
    }

    throw VoyemuError("IPC_EXTENT", "named pipe input too large");
}
} // namespace session_detail

std::filesystem::path host_lease_directory() {
    return std::filesystem::canonical(std::filesystem::temp_directory_path()) / "voyemu";
}

std::filesystem::path private_control_endpoint(const std::string &name) {
    return std::filesystem::path("\\\\.\\pipe\\voyemu-" + name);
}

namespace session_detail {
std::filesystem::path session_control_endpoint(const std::filesystem::path &,
                                               const std::string &session_id) {
    return private_control_endpoint(session_id);
}

std::filesystem::path session_runtime_root() {
    throw VoyemuError("IPC_PATH", "Unix runtime socket path is unavailable on Windows");
}

namespace {
class SocketQmpStream final : public QmpStream {
public:
    SocketQmpStream() {
        WSADATA data{};

        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw VoyemuError("IPC_SOCKET", "Winsock unavailable");
        }

        socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (socket_ == INVALID_SOCKET) {
            WSACleanup();
            throw VoyemuError("IPC_SOCKET", "cannot create channel");
        }
    }

    ~SocketQmpStream() override {
        ::closesocket(socket_);
        WSACleanup();
    }

    SocketQmpStream(const SocketQmpStream &) = delete;
    SocketQmpStream &operator=(const SocketQmpStream &) = delete;

    void connect(unsigned port, int timeout_ms) {
        u_long nonblocking = 1;

        ioctlsocket(socket_, FIONBIO, &nonblocking);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(static_cast<unsigned short>(port));

        if (::connect(socket_, reinterpret_cast<sockaddr *>(&address), sizeof address) == 0) {
            return;
        }

        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            throw VoyemuError("IPC_CONNECT", "service unavailable");
        }

        wait(true, timeout_ms);
        int error = 0, length = sizeof error;
        getsockopt(socket_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &length);

        if (error) {
            throw VoyemuError("IPC_CONNECT", "service unavailable");
        }
    }

    void write(const std::string &text, int timeout_ms) override {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        std::size_t offset = 0;

        while (offset < text.size()) {
            wait(true, remaining(deadline));
            const auto count = ::send(socket_, text.data() + offset,
                                      static_cast<int>(text.size() - offset), 0);

            if (count <= 0) {
                throw VoyemuError("IPC_WRITE_UNKNOWN", "local channel failed");
            }

            offset += static_cast<std::size_t>(count);
        }
    }

    std::string read_line(int timeout_ms) override {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);

        while (remainder_.size() < 64 * 1024) {
            if (const auto end = remainder_.find('\n'); end != std::string::npos) {
                auto line = remainder_.substr(0, end);
                remainder_.erase(0, end + 1);

                return line;
            }

            wait(false, remaining(deadline));
            char bytes[4096];
            const auto count = ::recv(socket_, bytes, sizeof bytes, 0);

            if (count <= 0) {
                throw VoyemuError("IPC_READ_UNKNOWN", "incomplete message");
            }

            remainder_.append(bytes, static_cast<std::size_t>(count));
        }

        throw VoyemuError("IPC_EXTENT", "input too large");
    }

private:
    static int remaining(std::chrono::steady_clock::time_point deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  deadline - std::chrono::steady_clock::now())
                                  .count();

        if (left <= 0) {
            throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "local channel deadline");
        }

        return static_cast<int>(left);
    }

    void wait(bool write, int timeout_ms) {
        fd_set selected;

        FD_ZERO(&selected);
        FD_SET(socket_, &selected);
        timeval timeout{timeout_ms / 1000, (timeout_ms % 1000) * 1000};

        if (::select(0, write ? nullptr : &selected, write ? &selected : nullptr, nullptr,
                     &timeout) <= 0) {
            throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "local channel unavailable");
        }
    }

    SOCKET socket_ = INVALID_SOCKET;
    std::string remainder_;
};
} // namespace

std::unique_ptr<QmpStream> qmp_connect(const Json &endpoint, int timeout_ms) {
    const auto port = endpoint.at("port").get<unsigned>();

    if (endpoint.at("host") != "127.0.0.1" || port < 1024 || port > 65535) {
        throw VoyemuError("IPC_OWNER", "owned loopback QMP port required");
    }

    auto stream = std::make_unique<SocketQmpStream>();
    stream->connect(port, timeout_ms);

    return stream;
}

Json android_qmp_endpoint(const std::string &, unsigned console_port) {
    for (unsigned port = console_port + 2; port < 65535; ++port) {
        if (tcp_port_free(port)) {
            return {{"host", "127.0.0.1"}, {"port", port}};
        }
    }

    throw VoyemuError("USB_DRIVE", "no free loopback QMP port");
}

Json control_exchange(const std::filesystem::path &endpoint, const std::string &text,
                      const Json &operation, const ControlTimeout &timeout) {
    HANDLE pipe = pipe_connect(endpoint, timeout.remaining());

    try {
        pipe_write(pipe, text);
        auto response =
                timeout.parse(pipe_read(pipe, timeout.remaining(), response_limit(operation)));
        pipe_write(pipe, "received\n");
        CloseHandle(pipe);

        return response;
    } catch (...) {
        CloseHandle(pipe);
        throw;
    }
}
} // namespace session_detail

struct ControlServer::Impl {
    std::filesystem::path endpoint;
    Handler handler;
    Tick tick;
};

ControlServer::ControlServer(std::filesystem::path endpoint, Handler handler, Tick tick)
    : impl_(std::make_unique<Impl>()) {
    impl_->endpoint = std::move(endpoint);
    impl_->handler = std::move(handler);
    impl_->tick = std::move(tick);
}

ControlServer::~ControlServer() = default;

void ControlServer::serve(std::atomic<bool> &stop) {
    struct Job {
        std::thread thread;
        std::atomic<bool> done{true};
        HANDLE pipe = INVALID_HANDLE_VALUE;
    };
    std::array<Job, 16> jobs;
    std::mutex jobs_mutex;
    std::atomic<unsigned> watch_readers{0};
    auto finish = [&](bool abort) {
        if (abort) {
            std::lock_guard lock(jobs_mutex);

            for (auto &job : jobs) {
                if (job.pipe != INVALID_HANDLE_VALUE) {
                    DisconnectNamedPipe(job.pipe);
                }
            }
        }

        for (auto &job : jobs) {
            if (job.thread.joinable()) {
                job.thread.join();
            }
        }
    };
    auto next_tick = std::chrono::steady_clock::time_point::min();
    auto tick = [&]() {
        const auto now = std::chrono::steady_clock::now();

        if (impl_->tick && now >= next_tick) {
            impl_->tick();
            next_tick = now + std::chrono::milliseconds(20);
            const auto tick_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - now)
                                         .count();

            // The tick shares the session lock with request handlers; a long wait stalls accept.
            if (tick_ms > 250) {
                try {
                    logging::write(logging::Level::debug, "control", "pipe.tick_slow",
                                   {{"elapsed_ms", tick_ms}});
                } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                }
            }
        }
    };
    bool serve_announced = false;

    try {
        while (!stop.load()) {
            // No listening instance exists until CreateNamedPipe; clients then fail IPC_CONNECT.
            const auto instance_absent = std::chrono::steady_clock::now();
            tick();

            if (!serve_announced) {
                serve_announced = true;
                try {
                    logging::write(logging::Level::debug, "control", "pipe.serve_started",
                                   {{"endpoint", impl_->endpoint}});
                } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                }
            }

            for (auto &job : jobs) {
                if (job.done.load() && job.thread.joinable()) {
                    job.thread.join();
                }
            }

            auto name = pipe_name(impl_->endpoint);
            HANDLE pipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
                                           PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT |
                                                   PIPE_REJECT_REMOTE_CLIENTS,
                                           17, static_cast<DWORD>(maximum_message),
                                           static_cast<DWORD>(maximum_message), 0, nullptr);

            if (pipe == INVALID_HANDLE_VALUE) {
                throw VoyemuError("IPC_BIND", "named pipe failed");
            }

            const auto absent_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::steady_clock::now() - instance_absent)
                                           .count();

            if (absent_ms > 250) {
                try {
                    logging::write(logging::Level::debug, "control", "pipe.instance_gap",
                                   {{"elapsed_ms", absent_ms}});
                } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                }
            }

            bool connected = false;
            // A fresh session is occasionally born with a control pipe that refuses every client
            // while the session itself stays healthy. The accept path reported nothing, so the
            // reason was unobservable: a listening instance that never signals a connection and a
            // saturated slot table look identical from the client (only IPC_CONNECT).
            const auto listen_started = std::chrono::steady_clock::now();
            auto listen_reported = listen_started;

            while (!stop.load()) {
                tick();

                if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
                    connected = true;
                    break;
                }

                const auto listen_error = GetLastError();

                if (listen_error != ERROR_PIPE_LISTENING && listen_error != ERROR_NO_DATA) {
                    CloseHandle(pipe);
                    throw VoyemuError("IPC_ACCEPT", "named pipe failed");
                }

                // Under PIPE_NOWAIT an instance whose client connected and vanished reports
                // ERROR_NO_DATA for every later ConnectNamedPipe, so this loop spins forever on a
                // dead instance while the session itself stays healthy, logging pipe.listen
                // error=232 with no accepted connection while every client request fails with
                // IPC_CONNECT. Rebuild the instance instead of spinning on it.
                if (listen_error == ERROR_NO_DATA) {
                    try {
                        logging::write(logging::Level::debug, "control", "pipe.recreated",
                                       {{"elapsed_ms",
                                         std::chrono::duration_cast<std::chrono::milliseconds>(
                                                 std::chrono::steady_clock::now() - listen_started)
                                                 .count()}});
                    } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                    }

                    break;
                }

                const auto listen_now = std::chrono::steady_clock::now();

                if (listen_now - listen_reported >= std::chrono::seconds(2)) {
                    listen_reported = listen_now;
                    try {
                        logging::write(logging::Level::debug, "control", "pipe.listen",
                                       {{"error", static_cast<int>(listen_error)},
                                        {"elapsed_ms",
                                         std::chrono::duration_cast<std::chrono::milliseconds>(
                                                 listen_now - listen_started)
                                                 .count()}});
                    } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            const auto listen_elapsed_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - listen_started)
                            .count();

            if (connected && listen_elapsed_ms > 1000) {
                try {
                    logging::write(logging::Level::debug, "control", "pipe.accepted",
                                   {{"elapsed_ms", listen_elapsed_ms}});
                } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                }
            }

            if (!connected) {
                CloseHandle(pipe);
                continue;
            }

            auto slot = std::find_if(jobs.begin(), jobs.end(), [](const Job &job) {
                return job.done.load() && !job.thread.joinable();
            });

            if (slot == jobs.end()) {
                try {
                    logging::write(logging::Level::debug, "control", "pipe.saturated",
                                   {{"slots", static_cast<int>(jobs.size())}});
                } catch (...) { /* Ignored: diagnostics must not change accept behavior. */
                }

                try {
                    (void)pipe_read(pipe, 100);
                    pipe_write(pipe, bounded_message(
                                             Json{{"ok", false},
                                                  {"error", "IPC_BUSY: active connection limit"}}));

                    if (pipe_read(pipe, 100) != "received") {
                        throw VoyemuError("IPC_ACK", "response receipt required");
                    }
                } catch (...) { /* Ignored: a busy reply cannot change the served session. */
                }

                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                continue;
            }

            auto &job = *slot;
            job.pipe = pipe;
            job.done = false;
            try {
                job.thread = std::thread([&, selected = &job]() {
                    const auto channel = selected->pipe;
                    bool watching = false;
                    try {
                        Json response;
                        auto limit = maximum_message;
                        auto cluster_deadline = ClusterDeadline::max();
                        try {
                            const auto input = Json::parse(pipe_read(channel, 2000));
                            limit = response_limit(input);

                            if (input.value("op", std::string{}) == "test_cluster_ui") {
                                cluster_deadline =
                                        std::chrono::steady_clock::now() +
                                        std::chrono::milliseconds(cluster_ui_timeout(input));
                            }

                            if (input.value("op", std::string{}) == "test_watch_read" ||
                                (input.value("op", std::string{}) == "test_output_logs" &&
                                 input.value("source", std::string{}) == "incidents" &&
                                 input.value("timeout_ms", 1000) > 0)) {
                                auto count = watch_readers.load();

                                while (count < 4 &&
                                       !watch_readers.compare_exchange_weak(count, count + 1)) {}

                                if (count >= 4) {
                                    throw VoyemuError("IPC_BUSY", "watch reader limit");
                                }

                                watching = true;
                            }

                            // A cluster capture never returned and every later request went
                            // unanswered too, so the accept loop alone cannot show whether
                            // the handler or the slot table is at fault. job.begin/job.end
                            // bracket the handler per slot.
                            const auto started = std::chrono::steady_clock::now();
                            const auto job_op = input.value("op", std::string{});
                            const auto job_slot = static_cast<int>(selected - jobs.data());
                            try {
                                logging::write(logging::Level::debug, "control", "job.begin",
                                               {{"op", job_op}, {"slot", job_slot}});
                            } catch (...) { /* Ignored: diagnostics must not change accept
                                             * behavior.
                                             */
                            }

                            response = impl_->handler(input);
                            try {
                                logging::write(
                                        logging::Level::debug, "control", "job.end",
                                        {{"op", job_op},
                                         {"slot", job_slot},
                                         {"ok", response.value("ok", false)},
                                         {"elapsed_ms",
                                          std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  std::chrono::steady_clock::now() - started)
                                                  .count()}});
                            } catch (...) { /* Ignored: diagnostics must not change accept
                                             * behavior.
                                             */
                            }
                        } catch (const std::exception &error) {
                            response = Json{{"ok", false}, {"error", error.what()}};
                        }

                        // DisconnectNamedPipe discards unread response bytes; require the
                        // bounded client receipt.
                        const auto text = cluster_deadline == ClusterDeadline::max()
                                                  ? bounded_message(response, limit)
                                                  : encode_qnx_kanzi_ui_json(response, limit,
                                                                             cluster_deadline);

                        if (text.size() > maximum_message ||
                            cluster_deadline != ClusterDeadline::max()) {
                            pipe_write_response(channel, text,
                                                cluster_deadline == ClusterDeadline::max()
                                                        ? std::chrono::steady_clock::now() +
                                                                  std::chrono::seconds(2)
                                                        : cluster_deadline);
                        } else {
                            pipe_write(channel, text);
                        }

                        if (pipe_read(channel, cluster_deadline == ClusterDeadline::max()
                                                       ? 2000
                                                       : cluster_remaining(cluster_deadline)) !=
                            "received") {
                            throw VoyemuError("IPC_ACK", "response receipt required");
                        }
                    } catch (...) { /* Ignored: diagnostics are best-effort. */
                    }

                    if (watching) {
                        --watch_readers;
                    }

                    {
                        std::lock_guard lock(jobs_mutex);
                        DisconnectNamedPipe(channel);
                        CloseHandle(channel);
                        selected->pipe = INVALID_HANDLE_VALUE;
                    }
                    selected->done = true;
                });
            } catch (...) {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                job.pipe = INVALID_HANDLE_VALUE;
                job.done = true;
                throw;
            }
        }
    } catch (...) {
        finish(true);
        throw;
    }

    // A stop handler can publish stopped before its response is serialized.
    // Drain bounded accepted requests so normal shutdown cannot truncate that reply.
    finish(false);
}
} // namespace voyemu
