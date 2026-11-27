#include "android_port_lease.hpp"
#include "error.hpp"
#include "session_posix.hpp"

namespace voyemu {
using namespace session_detail;
namespace session_detail {
void wait_fd(int fd, short events, int timeout) {
    pollfd item{fd, events, 0};
    int result;

    do {
        result = ::poll(&item, 1, timeout);
    } while (result < 0 && errno == EINTR);

    // Linux reports POLLERR beside queued bytes when the peer closed with unread
    // input; the queued reply is still delivered before the error.
    if (result <= 0 || (item.revents & (POLLERR | POLLNVAL) && !(item.revents & events))) {
        throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "local channel unavailable");
    }
}

void send_text(int fd, const std::string &text, int timeout) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    std::size_t offset = 0;

    while (offset < text.size()) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 deadline - std::chrono::steady_clock::now())
                                 .count();

        if (remaining <= 0) {
            throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "local write deadline");
        }

        wait_fd(fd, POLLOUT, static_cast<int>(remaining));
        auto count = os::send_without_sigpipe(fd, text.data() + offset, text.size() - offset);

        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }

        if (count <= 0) {
            throw VoyemuError("IPC_WRITE_UNKNOWN", "local channel failed");
        }

        offset += static_cast<std::size_t>(count);
    }
}

std::string receive_line(int fd, int timeout, std::string *remainder, std::size_t limit) {
    std::string output;

    if (remainder) {
        output.swap(*remainder);
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    std::size_t scan = 0;

    while (scan < limit) {
        const auto line = output.find('\n', scan);

        if (line != std::string::npos) {
            if (line >= limit) {
                break;
            }

            if (remainder) {
                *remainder = output.substr(line + 1);
            }

            return output.substr(0, line);
        }

        scan = output.size();

        if (scan >= limit) {
            break;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();

        if (remaining <= 0) {
            throw VoyemuError("IPC_TIMEOUT_UNKNOWN", "incomplete message");
        }

        wait_fd(fd, POLLIN, static_cast<int>(remaining));
        char buffer[4096];
        const auto count = ::recv(fd, buffer, std::min(sizeof buffer, limit - scan), 0);

        if (count < 0 && errno == EINTR) {
            continue;
        }

        if (count <= 0) {
            throw VoyemuError("IPC_READ_UNKNOWN", "incomplete message");
        }

        output.append(buffer, static_cast<std::size_t>(count));
    }

    throw VoyemuError("IPC_EXTENT", "input too large");
}

int unix_connect(const std::filesystem::path &endpoint, int timeout, bool owned) {
    auto text = endpoint.string();
    sockaddr_un address{};

    address.sun_family = AF_UNIX;

    if (text.size() >= sizeof address.sun_path) {
        throw VoyemuError("IPC_PATH", "socket path too long");
    }

    if (owned) {
        struct stat status{};

        if (::lstat(endpoint.c_str(), &status) != 0 || !S_ISSOCK(status.st_mode) ||
            status.st_uid != ::geteuid() || (status.st_mode & 0077)) {
            throw VoyemuError("IPC_OWNER", "private owned socket required");
        }
    }

    std::memcpy(address.sun_path, text.c_str(), text.size() + 1);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        throw VoyemuError("IPC_SOCKET", "cannot create channel");
    }

    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    os::disable_socket_sigpipe(fd);
    ::fcntl(fd, F_SETFL, O_NONBLOCK);
    int result = ::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof address);

    if (result < 0 && errno != EINPROGRESS) {
        ::close(fd);
        throw VoyemuError("IPC_CONNECT", "service unavailable");
    }

    try {
        if (result < 0) {
            wait_fd(fd, POLLOUT, timeout);
            int error = 0;
            socklen_t length = sizeof error;
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length);

            if (error) {
                throw VoyemuError("IPC_CONNECT", "service unavailable");
            }
        }
    } catch (...) {
        ::close(fd);
        throw;
    }

    return fd;
}
} // namespace session_detail

std::filesystem::path native_socket_root() {
    // The sockets of a session never live under the machine root, whose length is unbounded,
    // but in the first private directory of the user that leaves room in sun_path for the
    // longest name, <session id>-media-qmp.sock: the temporary directory, the user runtime
    // directory, then /tmp, the default temporary directory, which POSIX keeps short. The directory
    // exists before QEMU or a control server binds there.
    const auto user = "voyemu-" + std::to_string(::geteuid());

    for (const auto &root :
         {std::filesystem::canonical(std::filesystem::temp_directory_path()) / user,
          os::user_socket_directory(), std::filesystem::canonical("/tmp") / user}) {
        if (root.is_absolute() &&
            (root / (std::string(32, '0') + "-media-qmp.sock")).string().size() <
                    sizeof(sockaddr_un{}.sun_path)) {
            ensure_private_directory(root);

            return root;
        }
    }

    throw VoyemuError("IPC_PATH", "no private directory short enough for native sockets");
}

std::filesystem::path host_lease_directory() {
    return std::filesystem::canonical(std::filesystem::temp_directory_path()) /
           ("voyemu-" + std::to_string(::geteuid()));
}

std::filesystem::path private_control_endpoint(const std::string &name) {
    return native_socket_root() / (name + ".sock");
}

namespace session_detail {
std::filesystem::path session_control_endpoint(const std::filesystem::path &directory,
                                               const std::string &session_id) {
    auto endpoint = directory / "control.sock";

    if (endpoint.string().size() >= 104) {
        endpoint = private_control_endpoint(session_id);
    }

    return endpoint;
}

std::filesystem::path session_runtime_root() {
    return native_socket_root();
}

namespace {
class SocketQmpStream final : public QmpStream {
public:
    explicit SocketQmpStream(int fd) : fd_(fd) {}

    void write(const std::string &text, int timeout_ms) override {
        send_text(fd_.value, text, timeout_ms);
    }

    std::string read_line(int timeout_ms) override {
        return receive_line(fd_.value, timeout_ms, &remainder_, 64 * 1024);
    }

private:
    Fd fd_;
    std::string remainder_;
};
} // namespace

std::unique_ptr<QmpStream> qmp_connect(const Json &endpoint, int timeout_ms) {
    const std::filesystem::path path = endpoint.get<std::string>();
    struct stat status{};

    // QEMU creates the socket with the process umask inside the private runtime directory.
    if (path.parent_path() != native_socket_root() || ::lstat(path.c_str(), &status) != 0 ||
        !S_ISSOCK(status.st_mode) || status.st_uid != ::geteuid()) {
        throw VoyemuError("IPC_OWNER", "owned QMP socket required");
    }

    return std::make_unique<SocketQmpStream>(unix_connect(path, timeout_ms, false));
}

Json android_qmp_endpoint(const std::string &session_id, unsigned) {
    return (native_socket_root() / (session_id + "-media-qmp.sock")).string();
}

Json control_exchange(const std::filesystem::path &endpoint, const std::string &text,
                      const Json &operation, const ControlTimeout &timeout) {
    Fd fd(unix_connect(endpoint, timeout.remaining(), true));
    const auto write_deadline = timeout.cluster
                                        ? timeout.deadline
                                        : std::chrono::steady_clock::now() +
                                                  std::chrono::milliseconds(timeout.timeout_ms);

    try {
        send_text(fd.value, text, timeout.remaining());
    } catch (...) {
        const auto failure = std::current_exception();
        // Admission can reject and close before consuming the request. Only its
        // exact negative reply is meaningful after a failed write; never replay.
        try {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           write_deadline - std::chrono::steady_clock::now())
                                           .count();

            if (remaining > 0) {
                const auto response =
                        Json::parse(receive_line(fd.value, static_cast<int>(remaining)));

                if (response ==
                    Json{{"ok", false}, {"error", "IPC_BUSY: active connection limit"}}) {
                    return response;
                }
            }
        } catch (...) { /* Ignored: the original failure is rethrown below. */
        }

        std::rethrow_exception(failure);
    }

    return timeout.parse(
            receive_line(fd.value, timeout.remaining(), nullptr, response_limit(operation)));
}
} // namespace session_detail

struct ControlServer::Impl {
    std::filesystem::path endpoint;
    Handler handler;
    Tick tick;
    int socket = -1;
    std::uint64_t inode = 0;
};

ControlServer::ControlServer(std::filesystem::path endpoint, Handler handler, Tick tick)
    : impl_(std::make_unique<Impl>()) {
    impl_->endpoint = std::move(endpoint);
    impl_->handler = std::move(handler);
    impl_->tick = std::move(tick);
    ensure_private_directory(impl_->endpoint.parent_path());

    if (std::filesystem::exists(impl_->endpoint) || std::filesystem::is_symlink(impl_->endpoint)) {
        throw VoyemuError("IPC_BUSY", "endpoint already exists");
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    auto text = impl_->endpoint.string();

    if (text.size() >= sizeof address.sun_path) {
        throw VoyemuError("IPC_PATH", "socket path too long");
    }

    std::memcpy(address.sun_path, text.c_str(), text.size() + 1);
    impl_->socket = ::socket(AF_UNIX, SOCK_STREAM, 0);

    if (impl_->socket < 0) {
        throw VoyemuError("IPC_SOCKET", "create failed");
    }

    ::fcntl(impl_->socket, F_SETFD, FD_CLOEXEC);

    if (::bind(impl_->socket, reinterpret_cast<sockaddr *>(&address), sizeof address) != 0 ||
        ::chmod(impl_->endpoint.c_str(), 0600) != 0 || ::listen(impl_->socket, 17) != 0) {
        ::close(impl_->socket);
        impl_->socket = -1;
        throw VoyemuError("IPC_BIND", "cannot bind private endpoint");
    }

    struct stat status{};
    ::lstat(impl_->endpoint.c_str(), &status);
    impl_->inode = status.st_ino;
}

ControlServer::~ControlServer() {
    if (impl_->socket >= 0) {
        ::close(impl_->socket);
    }

    struct stat status{};

    if (::lstat(impl_->endpoint.c_str(), &status) == 0 && status.st_ino == impl_->inode &&
        S_ISSOCK(status.st_mode) && status.st_uid == ::geteuid()) {
        ::unlink(impl_->endpoint.c_str());
    }
}

void ControlServer::serve(std::atomic<bool> &stop) {
    auto next_tick = std::chrono::steady_clock::time_point::min();
    auto tick = [&]() {
        const auto now = std::chrono::steady_clock::now();

        if (impl_->tick && now >= next_tick) {
            impl_->tick();
            next_tick = now + std::chrono::milliseconds(20);
        }
    };
    // Fixed slots bound both live connections and retained thread handles.
    struct Job {
        std::thread thread;
        std::atomic<bool> done{true};
        int fd = -1;
    };
    std::array<Job, 16> jobs;
    std::mutex jobs_mutex;
    std::atomic<unsigned> watch_readers{0};
    auto finish = [&](bool abort) {
        if (abort) {
            std::lock_guard lock(jobs_mutex);

            for (auto &job : jobs) {
                if (job.fd >= 0) {
                    ::shutdown(job.fd, SHUT_RDWR);
                }
            }
        }

        for (auto &job : jobs) {
            if (job.thread.joinable()) {
                job.thread.join();
            }
        }
    };
    bool serve_announced = false;

    try {
        while (!stop.load()) {
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

            pollfd item{impl_->socket, POLLIN, 0};
            auto available = ::poll(&item, 1, 20);

            if (available < 0 && errno == EINTR) {
                continue;
            }

            if (available < 0) {
                throw VoyemuError("IPC_ACCEPT", "socket failed");
            }

            if (available == 0) {
                continue;
            }

            Fd client(::accept(impl_->socket, nullptr, nullptr));

            if (client.value < 0) {
                continue;
            }

            ::fcntl(client.value, F_SETFD, FD_CLOEXEC);
            ::fcntl(client.value, F_SETFL, O_NONBLOCK);
            os::disable_socket_sigpipe(client.value);

            if (!os::unix_peer_is_current_user(client.value)) {
                continue;
            }

            auto slot = std::find_if(jobs.begin(), jobs.end(), [](const Job &job) {
                return job.done.load() && !job.thread.joinable();
            });

            if (slot == jobs.end()) {
                // A single nonblocking write keeps overload handling off the accept
                // deadline.
                const auto busy = bounded_message(
                        Json{{"ok", false}, {"error", "IPC_BUSY: active connection limit"}});
                os::send_without_sigpipe(client.value, busy.data(), busy.size());
                continue;
            }

            auto &job = *slot;
            job.fd = client.value;
            client.value = -1;
            job.done = false;
            try {
                job.thread = std::thread([&, selected = &job]() {
                    const int fd = selected->fd;
                    bool watching = false;
                    try {
                        Json response;
                        auto limit = maximum_message;
                        auto cluster_deadline = ClusterDeadline::max();
                        try {
                            const auto input = Json::parse(receive_line(fd, 2000));
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

                            response = impl_->handler(input);
                        } catch (const std::exception &error) {
                            response = Json{{"ok", false}, {"error", error.what()}};
                        }

                        if (cluster_deadline == ClusterDeadline::max()) {
                            send_text(fd, bounded_message(response, limit), 2000);
                        } else {
                            const auto text = encode_qnx_kanzi_ui_json(response, limit,
                                                                       cluster_deadline);
                            send_text(fd, text, cluster_remaining(cluster_deadline));
                        }
                    } catch (...) { /* Ignored: a failed reply cannot change the served
                                       session. */
                    }

                    if (watching) {
                        --watch_readers;
                    }

                    {
                        std::lock_guard lock(jobs_mutex);
                        ::close(fd);
                        selected->fd = -1;
                    }
                    selected->done = true;
                });
            } catch (...) {
                ::close(job.fd);
                job.fd = -1;
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
