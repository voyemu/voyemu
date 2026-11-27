#include "android_embedded_adb.hpp"
#include "adb_host.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;

namespace {
void require(bool value, const char *reason) {
    if (!value) {
        throw std::runtime_error(reason);
    }
}

std::string copy(AdbBytes value) {
    return value.size ? std::string(reinterpret_cast<const char *>(value.data), value.size) : "";
}

struct Event {
    AdbEvent value{};
    std::string serial;
    std::string payload;
};

std::string packet(std::string_view id, std::uint32_t length, std::string_view data = {}) {
    std::string result(id);

    for (unsigned shift = 0; shift < 32; shift += 8) {
        result += static_cast<char>(length >> shift);
    }

    result += data;

    return result;
}

constexpr std::string_view binary{"a\0\r\n\xff", 5};
} // namespace

struct AdbHost {
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<Event> events;
    struct Operation {
        std::uint32_t service;
        std::string command;
        std::string input;
    };
    std::map<AdbOperationId, Operation> operations;
    AdbOperationId last = 0;
    std::uint64_t generation = 1;
};

namespace {
AdbHost *fixture = nullptr;
bool private_logger_installed = false;

void emit(AdbHost *host, std::uint32_t type, AdbOperationId id = 0, std::string payload = {},
          int exit = -1) {
    Event event;

    event.value.type = type;
    event.value.operation = id;
    event.value.device_generation = host->generation;
    event.value.remote_exit_code = exit;
    event.value.has_remote_exit_code = exit >= 0;
    event.payload = std::move(payload);

    if (type == ADB_EVENT_DEVICE) {
        event.serial = "emulator-2048";
        event.value.device_state = ADB_DEVICE_ONLINE;
    }

    host->events.push_back(std::move(event));
    host->changed.notify_all();
}
} // namespace

void adb_host_set_log_callback(AdbLogCallback callback) {
    require(!callback && !fixture, "ADB logs must be suppressed before host creation");
    private_logger_installed = true;
}

int32_t adb_host_create(const AdbHostConfig *config, AdbHost **host) {
    require(private_logger_installed, "ADB logger was not installed");
    require(config->maximum_queued_output_bytes == 16 * 1024 * 1024, "runtime host scope");
    *host = fixture = new AdbHost;

    return ADB_STATUS_OK;
}

int32_t adb_host_attach_owned_emulator(AdbHost *host, uint32_t port, AdbEmulatorFence fence,
                                       void *context) {
    require(port == 2048 && fence(context), "attachment fence");
    std::lock_guard lock(host->mutex);
    emit(host, ADB_EVENT_DEVICE);

    return ADB_STATUS_OK;
}

int32_t adb_host_scan(AdbHost *host) {
    std::lock_guard lock(host->mutex);

    emit(host, ADB_EVENT_DEVICE);

    return ADB_STATUS_OK;
}

int32_t adb_host_detach_emulator(AdbHost *host) {
    std::lock_guard lock(host->mutex);

    ++host->generation;

    return ADB_STATUS_OK;
}

int32_t adb_host_shutdown(AdbHost *, uint64_t) {
    return ADB_STATUS_OK;
}

void adb_host_destroy(AdbHost *host) {
    delete host;
    fixture = nullptr;
}

int32_t adb_host_next_event(AdbHost *host, uint64_t timeout, AdbEvent *out) {
    std::unique_lock lock(host->mutex);

    if (!host->changed.wait_for(lock, std::chrono::milliseconds(timeout), [&] {
            return !host->events.empty();
        })) {
        return ADB_STATUS_TIMEOUT;
    }

    auto *event = new Event(std::move(host->events.front()));
    host->events.pop_front();
    event->value.private_event = event;
    event->value.serial = {reinterpret_cast<const uint8_t *>(event->serial.data()),
                           event->serial.size()};
    event->value.payload = {reinterpret_cast<const uint8_t *>(event->payload.data()),
                            event->payload.size()};
    *out = event->value;

    return ADB_STATUS_OK;
}

void adb_host_event_release(AdbEvent *event) {
    delete static_cast<Event *>(event->private_event);
}

int32_t adb_host_open(AdbHost *host, AdbBytes serial, uint64_t generation, uint32_t service,
                      AdbBytes command, uint64_t, AdbOperationId *out) {
    std::lock_guard lock(host->mutex);

    if (copy(serial) != "emulator-2048" || generation != host->generation) {
        return ADB_STATUS_STALE_DEVICE;
    }

    const auto id = *out = ++host->last;
    host->operations[id] = {service, copy(command), {}};
    emit(host, ADB_EVENT_OPENED, id);

    if (service == ADB_SERVICE_EXEC_RAW) {
        require(copy(command) == "cat 'a b'", "exec-out argv escaping");
        emit(host, ADB_EVENT_STDOUT, id, std::string(binary));
        emit(host, ADB_EVENT_TERMINAL, id);
    }

    return ADB_STATUS_OK;
}

int32_t adb_host_close_stdin(AdbHost *host, AdbOperationId id) {
    std::lock_guard lock(host->mutex);
    const auto &operation = host->operations.at(id);

    require(operation.service == ADB_SERVICE_SHELL_V2_RAW, "stdin only on shell v2");

    if (operation.command == "slow") {
        return ADB_STATUS_OK;
    }

    require(operation.command == "printf '%s' ready", "shell command text");
    emit(host, ADB_EVENT_STDOUT, id, "ok");
    emit(host, ADB_EVENT_STDERR, id, "err");
    emit(host, ADB_EVENT_TERMINAL, id, {}, 37);

    return ADB_STATUS_OK;
}

int32_t adb_host_cancel(AdbHost *host, AdbOperationId id) {
    std::lock_guard lock(host->mutex);

    host->operations.erase(id);

    return ADB_STATUS_OK;
}

int32_t adb_host_grant_sync_output(AdbHost *, AdbOperationId, size_t) {
    return ADB_STATUS_OK;
}

int32_t adb_host_write(AdbHost *host, AdbOperationId id, AdbBytes data, size_t *accepted) {
    std::lock_guard lock(host->mutex);
    auto &operation = host->operations.at(id);
    const auto chunk = copy(data);

    *accepted = chunk.size();
    operation.input += chunk;

    if (operation.service == ADB_SERVICE_OBSERVER) {
        require(operation.command == "0123456789abcdef0123456789abcdef", "exact observer socket");
        emit(host, ADB_EVENT_STDOUT, id, operation.input);
    } else {
        require(operation.service == ADB_SERVICE_SYNC, "write only to raw duplex");

        if (chunk.starts_with("RECV")) {
            require(chunk == packet("RECV", 11, "/data/input"), "sync pull path");
            const auto reply = packet("DATA", binary.size(), binary) + packet("DONE", 0);
            emit(host, ADB_EVENT_STDOUT, id, reply.substr(0, 3));
            emit(host, ADB_EVENT_STDOUT, id, reply.substr(3));
        } else if (chunk.starts_with("SEND")) {
            require(chunk.substr(8).starts_with("/data/output,"), "sync push path and mode");
        } else if (chunk.starts_with("DATA")) {
            require(chunk == packet("DATA", binary.size(), binary), "sync push binary data");
        } else if (chunk.starts_with("DONE")) {
            emit(host, ADB_EVENT_STDOUT, id, packet("OKAY", 0));
        } else if (chunk == packet("QUIT", 0)) {
            emit(host, ADB_EVENT_TERMINAL, id);
        } else {
            throw std::runtime_error("unexpected sync request");
        }
    }

    return ADB_STATUS_OK;
}

int main(int argc, char **argv) try {
    require(argc == 2, "test output path");
    const std::filesystem::path folder(argv[1]);
    std::filesystem::create_directories(folder);
    voyemu::AndroidEmbeddedAdb client(2048);
    client.attach([] {
        return true;
    });
    require(!client.run({"wait-for-device"}, 1000, 128).exit_code, "device online");

    const auto shell = client.run({"shell", "printf", "'%s'", "ready"}, 1000, 128);
    require(shell.output == "okerr" && shell.exit_code == 37, "shell v2 streams and exit code");
    const auto lease = client.lease();
    auto separated = client.open_shell({"shell", "printf", "'%s'", "ready"}, 1000, 128, lease,
                                       true);
    require(client.current(lease), "capture belongs to the active device lease");
    separated.close_stdin();
    std::string stdout_bytes, stderr_bytes;

    for (const auto end = std::chrono::steady_clock::now() + 1s;;
         std::this_thread::sleep_for(1ms)) {
        require(std::chrono::steady_clock::now() < end, "lease-bound shell did not finish");
        const auto update = separated.poll();
        stdout_bytes += update.output;
        stderr_bytes += update.error_output;

        if (update.terminal) {
            require(update.terminal->exit_code == 37 && stdout_bytes == "ok" &&
                            stderr_bytes == "err",
                    "binary shell keeps stderr separate");
            break;
        }
    }

    const auto exec = client.run({"exec-out", "cat", "a b"}, 1000, 128);
    require(!exec.exit_code && exec.output == binary, "binary exec-out");
    require(client.run({"shell", "slow"}, 20, 128).timed_out, "bounded shell deadline");
    std::stop_source stop;
    std::jthread canceller([&] {
        std::this_thread::sleep_for(20ms);
        stop.request_stop();
    });
    const auto cancelled = client.run({"shell", "slow"}, 1000, 128, stop.get_token());
    require(cancelled.exit_code && !cancelled.timed_out, "cancel shell only");
    auto observer = client.open_observer("0123456789abcdef0123456789abcdef", 1000);

    for (auto end = std::chrono::steady_clock::now() + 1s;; std::this_thread::sleep_for(1ms)) {
        require(std::chrono::steady_clock::now() < end, "observer did not open");

        if (observer.poll().opened) {
            break;
        }
    }

    require(observer.write(binary) == binary.size(), "observer write");

    for (auto end = std::chrono::steady_clock::now() + 1s;; std::this_thread::sleep_for(1ms)) {
        require(std::chrono::steady_clock::now() < end, "observer did not respond");
        const auto update = observer.poll();

        if (update.output.empty()) {
            continue;
        }

        require(update.output == binary && !update.terminal, "observer binary response");
        break;
    }

    observer.cancel();

    const auto local = folder / "file";
    const auto local_u8 = local.u8string();
    const std::string local_arg(reinterpret_cast<const char *>(local_u8.data()), local_u8.size());
    require(!client.run({"pull", "/data/input", local_arg}, 1000, 128).exit_code, "sync pull");
    std::ifstream input(local, std::ios::binary);
    require(std::string(std::istreambuf_iterator<char>(input), {}) == binary,
            "pull preserved bytes");
    input.close();
    require(!client.run({"push", local_arg, "/data/output"}, 1000, 128).exit_code, "sync push");
    std::filesystem::remove(local);

    const auto before_root = client.lease();
    auto root = client.open_root(1000, 128);
    {
        std::lock_guard lock(fixture->mutex);
        emit(fixture, ADB_EVENT_STDOUT, fixture->last, "restarting adbd as root\n");
    }

    for (auto end = std::chrono::steady_clock::now() + 1s;; std::this_thread::sleep_for(1ms)) {
        require(std::chrono::steady_clock::now() < end, "root response missing");

        if (!root.poll().output.empty()) {
            break;
        }
    }

    {
        std::lock_guard lock(fixture->mutex);
        emit(fixture, ADB_EVENT_TERMINAL, fixture->last);
    }

    for (auto end = std::chrono::steady_clock::now() + 1s;; std::this_thread::sleep_for(1ms)) {
        require(std::chrono::steady_clock::now() < end, "root terminal missing");

        if (root.poll().terminal) {
            break;
        }
    }

    require(client.run({"wait-for-device"}, 20, 128).timed_out, "retired root generation reused");
    {
        std::lock_guard lock(fixture->mutex);
        ++fixture->generation;
        emit(fixture, ADB_EVENT_DEVICE);
    }
    require(!client.run({"wait-for-device"}, 1000, 128, {}, before_root).exit_code,
            "new root generation");
    const auto before_detach = client.lease();
    const auto last_open = fixture->last;
    require(client.run({"root"}, 1000, 128, {}, before_root).exit_code,
            "stale root generation reused");
    require(fixture->last == last_open, "stale raw lease opened a new operation");
    client.detach();
    require(client.run({"wait-for-device"}, 100, 128).exit_code, "detached device");
    client.attach([] {
        return true;
    });
    require(!client.run({"wait-for-device"}, 1000, 128).exit_code, "same port reattach");
    require(client.run({"root"}, 1000, 128, {}, before_detach).exit_code,
            "stale attachment accepted mutation");
    require(client.run({"wait-for-device"}, 1000, 128, {}, before_detach).exit_code,
            "stale attachment accepted wait");
    require(fixture->last == last_open, "stale attachment lease opened a new operation");
    require(client.shutdown(), "bounded shutdown");

    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
