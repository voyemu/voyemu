#include "session_windows.hpp"
#include "error.hpp"
#include "os/current_user_windows.hpp"
#include "os/private_state_security.hpp"

// The parts of Session that differ on Windows, where Android runs through framed transactions of
// the embedded ADB and QNX through loopback TCP; session_posix.cpp holds the macOS and Linux parts.
namespace voyemu {
using namespace session_detail;
namespace session_detail {
// Voyemu creates every file it later claims with the token user as an explicit owner through
// detail::PrivateStateSecurity, so the token default owner, Administrators under an elevated
// token, never qualifies.
bool owned_windows_file(HANDLE file) {
    return os::owned_by_current_user(file);
}

std::filesystem::path session_sdk_registration_directory(const std::filesystem::path &directory,
                                                         bool diagnostic_native) {
    const auto home = directory / "emulator-home";

    if (diagnostic_native) {
        return home / "Library/Caches/TemporaryItems/avd/running";
    }

    return sdk_registration_directory(home, home);
}

bool qmp_continue_windows(const Json &qmp, bool checkpoint,
                          const std::function<void()> &verify_owner,
                          std::optional<bool> persistence_paused) {
    if (!qmp.is_object() || qmp.value("host", std::string("127.0.0.1")) != "127.0.0.1") {
        throw VoyemuError("QMP_OWNER", "Windows QMP must bind loopback");
    }

    auto port = qmp.at("port").get<unsigned>();

    if (port < 1024 || port > 65535) {
        throw VoyemuError("QMP_PORT", "invalid port");
    }

    WSADATA data{};

    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        throw VoyemuError("QMP_SOCKET", "Winsock unavailable");
    }

    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket == INVALID_SOCKET) {
        WSACleanup();
        throw VoyemuError("QMP_SOCKET", "socket creation failed");
    }

    try {
        u_long nonblocking = 1;
        ioctlsocket(socket, FIONBIO, &nonblocking);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(static_cast<unsigned short>(port));
        int connected = ::connect(socket, reinterpret_cast<sockaddr *>(&address), sizeof address);

        if (connected != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
            throw VoyemuError("QMP_CONNECT", "unavailable");
        }

        auto ready = [&](bool write) {
            fd_set selected;
            FD_ZERO(&selected);
            FD_SET(socket, &selected);
            timeval timeout{0, 300000};

            if (::select(0, write ? nullptr : &selected, write ? &selected : nullptr, nullptr,
                         &timeout) <= 0) {
                throw VoyemuError("QMP_TIMEOUT", "bounded I/O timeout");
            }
        };

        if (connected != 0) {
            ready(true);
            int error = 0;
            int length = sizeof error;
            getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &length);

            if (error) {
                throw VoyemuError("QMP_CONNECT", "refused");
            }
        }

        std::string carry;
        auto line = [&]() {
            while (carry.size() < 65536) {
                auto end = carry.find('\n');

                if (end != std::string::npos) {
                    auto output = carry.substr(0, end);
                    carry.erase(0, end + 1);

                    return Json::parse(output);
                }

                ready(false);
                char bytes[4096];
                auto count = ::recv(socket, bytes, sizeof bytes, 0);

                if (count <= 0) {
                    throw VoyemuError("QMP_READ", "incomplete reply");
                }

                carry.append(bytes, count);
            }

            throw VoyemuError("QMP_EXTENT", "oversized reply");
        };
        auto send = [&](const Json &value) {
            auto text = value.dump() + "\n";
            std::size_t offset = 0;

            while (offset < text.size()) {
                ready(true);
                auto count = ::send(socket, text.data() + offset,
                                    static_cast<int>(text.size() - offset), 0);

                if (count <= 0) {
                    throw VoyemuError("QMP_WRITE", "failed");
                }

                offset += count;
            }
        };

        if (verify_owner) {
            verify_owner();
        }

        if (!line().contains("QMP")) {
            throw VoyemuError("QMP_GREETING", "invalid server");
        }

        send({{"execute", "qmp_capabilities"}});

        if (!line().contains("return")) {
            throw VoyemuError("QMP_CAPABILITIES", "rejected");
        }

        auto query = [&](const char *command, Json arguments = Json{}) {
            const std::string id = std::string("qnx-") + command;
            Json request{{"execute", command}, {"id", id}};

            if (!arguments.is_null()) {
                request["arguments"] = std::move(arguments);
            }

            send(request);

            for (unsigned i = 0; i < 8; ++i) {
                auto reply = line();

                if (reply.value("id", std::string{}) == id) {
                    if (reply.contains("error")) {
                        throw VoyemuError("QMP_QUERY", "owned query rejected");
                    }

                    return reply.at("return");
                }
            }

            throw VoyemuError("QMP_QUERY", "missing owned query reply");
        };

        if (persistence_paused) {
            if (verify_owner) {
                verify_owner();
            }

            query(*persistence_paused ? "stop" : "cont");
            const auto status = query("query-status");

            if (!status.contains("running") || !status.at("running").is_boolean() ||
                status.at("running").get<bool>() == *persistence_paused) {
                throw VoyemuError("QNX_PERSISTENCE", "QMP pause state unverified");
            }

            if (verify_owner) {
                verify_owner();
            }

            closesocket(socket);
            WSACleanup();

            return true;
        }

        if (checkpoint) {
            const auto migration = query("query-migrate"), status = query("query-status");

            if (!qnx_checkpoint_migration_ready(migration, status)) {
                closesocket(socket);
                WSACleanup();

                return false;
            }
        }

        send({{"execute", "cont"}});
        bool done = false;

        for (unsigned i = 0; i < 4; ++i) {
            auto reply = line();

            if (reply.contains("return")) {
                done = true;
                break;
            }

            if (reply.contains("error")) {
                throw VoyemuError("QMP_CONT", "rejected");
            }
        }

        if (!done) {
            throw VoyemuError("QMP_CONT", "missing reply");
        }
    } catch (...) {
        closesocket(socket);
        WSACleanup();
        throw;
    }

    closesocket(socket);
    WSACleanup();

    return true;
}

bool android_windows_renderer(const Json &specification, bool diagnostic_native) {
    return !diagnostic_native && windows_android_renderer_policy(specification);
}

// The native diagnostic runs the macOS engine, so the backend of this PE host does not apply.
os::EmulatorAudioOutput android_emulator_audio_output(bool diagnostic_native) {
    return diagnostic_native ? os::EmulatorAudioOutput{.driver = "coreaudio"}
                             : os::emulator_audio_output();
}

int android_stop_sync_budget() {
    return 60000; // The same finite stop request deadline still clamps this framed flush.
}

void check_restart_can_boundary(bool with_can) {
    if (with_can) {
        throw VoyemuError("CAN_BOUNDARY_UNAVAILABLE", "native owned Android backend required");
    }
}

void require_short_pair_transport() {
    throw VoyemuError("TEST_UNSUPPORTED", "Windows short-pair transport is unavailable");
}

std::chrono::milliseconds source_collector_budget(const std::string &id) {
    // Each serial system read has its own framed Windows transaction and AVD fences.
    return id == "system" ? std::chrono::seconds(10) : std::chrono::milliseconds(1500);
}

std::string native_backend_path(const std::filesystem::path &path, bool diagnostic_native) {
    return diagnostic_native ? wine_native_unix_path(path) : path.string();
}

std::string native_backend_avd_config(std::string text, bool diagnostic_native,
                                      const std::filesystem::path &base) {
    if (!diagnostic_native) {
        return text;
    }

    const std::string key = "image.sysdir.1=";
    const auto offset = text.find(key);

    if (offset == std::string::npos || (offset && text[offset - 1] != '\n')) {
        throw VoyemuError("WINE_NATIVE_DIAGNOSTIC", "AVD sysdir missing");
    }

    const auto end = text.find('\n', offset);
    text.replace(offset, end - offset, key + wine_native_unix_path(base) + "/");

    return text;
}

bool native_backend_same_file(const std::filesystem::path &a, const std::filesystem::path &b) {
    // Under the Wine diagnostic mapping the content directory and the portable machine live on
    // different Windows drive letters of one shared host file system: hard links share the file
    // index, but std::filesystem::equivalent also compares the volume serial, which Wine derives
    // per drive mapping.
    struct Identity {
        LARGE_INTEGER index;
        DWORD links;
    } left{}, right{};
    const auto describe = [&](const std::filesystem::path &file, Identity &identity) {
        const HANDLE handle = CreateFileW(
                file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

        if (handle == INVALID_HANDLE_VALUE || !handle) {
            return false;
        }

        BY_HANDLE_FILE_INFORMATION information{};
        const bool read = GetFileInformationByHandle(handle, &information) != FALSE;
        CloseHandle(handle);

        if (!read) {
            return false;
        }

        identity.index.HighPart = information.nFileIndexHigh;
        identity.index.LowPart = information.nFileIndexLow;
        identity.links = information.nNumberOfLinks;

        return true;
    };

    if (!describe(a, left) || !describe(b, right)) {
        return false;
    }

    constexpr DWORD final_flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const auto resolved = [&](const std::filesystem::path &file) {
        const HANDLE handle = CreateFileW(
                file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

        if (handle == INVALID_HANDLE_VALUE) {
            return std::wstring{};
        }

        wchar_t buffer[32768]{};
        const DWORD length = GetFinalPathNameByHandleW(handle, buffer, 32768, final_flags);
        CloseHandle(handle);

        if (!length || length >= 32768) {
            return std::wstring{};
        }

        return std::wstring(buffer, length);
    };
    const auto left_final = resolved(a), right_final = resolved(b);

    if (!left_final.empty() && left_final == right_final) {
        return true;
    }

    // A hard link under the diagnostic mapping shares the file index and
    // the link count, but each name resolves through its own drive letter.
    return left.index.QuadPart != 0 && left.index.QuadPart == right.index.QuadPart &&
           left.links == right.links && right.links >= 2;
}

bool owned_symlink(const std::filesystem::path &alias) {
    const HANDLE handle = CreateFileW(
            alias.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    const bool owned = owned_windows_file(handle);
    CloseHandle(handle);

    return owned;
}

void link_overlay(const std::filesystem::path &disk, const std::filesystem::path &alias) {
    std::error_code link_error;

    std::filesystem::create_hard_link(disk, alias, link_error);

    if (!link_error) {
        return;
    }

    if (!CreateSymbolicLinkW(alias.c_str(), disk.c_str(), 0x2)) {
        throw VoyemuError("ANDROID_AVD_STORAGE",
                          "persistent overlay link requires same volume or Windows Developer Mode");
    }

    // owned_symlink later claims the link, which CreateSymbolicLinkW gives the token default owner.
    const HANDLE handle = CreateFileW(
            alias.c_str(), WRITE_OWNER | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    const bool owned = handle != INVALID_HANDLE_VALUE &&
                       detail::PrivateStateSecurity().assign(handle);

    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }

    if (!owned) {
        DeleteFileW(alias.c_str());
        throw VoyemuError("ANDROID_AVD_STORAGE", "persistent overlay link owner unavailable");
    }
}

OwnedRamReader owned_ram_reader(const std::filesystem::path &ram, std::uint64_t bytes) {
    const auto file = std::shared_ptr<void>(
            CreateFileW(ram.c_str(), GENERIC_READ | READ_CONTROL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr),
            [](HANDLE value) {
                if (value != INVALID_HANDLE_VALUE) {
                    CloseHandle(value);
                }
            });
    BY_HANDLE_FILE_INFORMATION info{};

    if (file.get() == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(file.get(), &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        info.nNumberOfLinks != 1 ||
        ((std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow) != bytes ||
        !owned_windows_file(file.get())) {
        return {};
    }

    return [file](std::uint64_t offset, std::span<std::byte> output) {
        LARGE_INTEGER position{};

        position.QuadPart = static_cast<LONGLONG>(offset);
        DWORD got = 0;

        return SetFilePointerEx(file.get(), position, nullptr, FILE_BEGIN) &&
               ReadFile(file.get(), output.data(), static_cast<DWORD>(output.size()), &got,
                        nullptr) &&
               got == output.size();
    };
}

void write_handoff_file(const std::filesystem::path &path, const std::string &text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        throw VoyemuError("QNX_HANDOFF", "exclusive creation failed");
    }

    DWORD count = 0;
    bool written = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &count, nullptr) &&
                   count == text.size() && FlushFileBuffers(file);
    CloseHandle(file);

    if (!written) {
        throw VoyemuError("QNX_HANDOFF", "durable write failed; RAM retained");
    }
}

struct OwnedRamBacking::Handle {
    HANDLE file = INVALID_HANDLE_VALUE;

    ~Handle() {
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
    }
};

OwnedRamBacking::OwnedRamBacking(const std::filesystem::path &path, bool exists,
                                 std::uint64_t bytes)
    : path_(path), handle_(std::make_unique<Handle>()) {
    if (!exists) {
        return;
    }

    handle_->file = CreateFileW(path.c_str(), GENERIC_READ | DELETE | READ_CONTROL, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

    if (handle_->file == INVALID_HANDLE_VALUE) {
        throw VoyemuError("QNX_CLEANUP_RAM", "cannot claim terminal backing");
    }

    BY_HANDLE_FILE_INFORMATION identity{};

    if (!GetFileInformationByHandle(handle_->file, &identity) ||
        (identity.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        identity.nNumberOfLinks != 1 ||
        ((std::uint64_t(identity.nFileSizeHigh) << 32) | identity.nFileSizeLow) != bytes ||
        !owned_windows_file(handle_->file)) {
        throw VoyemuError("QNX_CLEANUP_RAM", "foreign or invalid backing");
    }
}

OwnedRamBacking::~OwnedRamBacking() = default;

void OwnedRamBacking::remove() {
    FILE_DISPOSITION_INFO disposition{};

    disposition.DeleteFile = TRUE;

    if (!SetFileInformationByHandle(handle_->file, FileDispositionInfo, &disposition,
                                    sizeof disposition)) {
        throw VoyemuError("QNX_CLEANUP_REMOVE", "terminal backing removal failed");
    }

    CloseHandle(handle_->file);
    handle_->file = INVALID_HANDLE_VALUE;
}

std::tm local_time(std::time_t time) {
    std::tm local{};

    localtime_s(&local, &time);

    return local;
}
} // namespace session_detail

void Session::advance_android(bool guest_possible, std::chrono::steady_clock::time_point now) {
    if (guest_possible && now >= next_android_) {
        try {
            advance_windows_android_transaction();
        } catch (const std::exception &error) {
            deliveries_["android"]["last_error"] = error.what();
        }

        next_android_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    }
}

Session::IoLockLoan Session::lend_android_request_io(std::unique_lock<std::recursive_mutex> &lock) {
    return {android_io_state_lock_, lock};
}

void Session::cancel_android_identity_probe() {
    android_identity_probe_.cancel();
}

void Session::add_interguest_delivery(Json &android) const {
    if (interguest_link_ && android_spec_.contains("interguest_network")) {
        const auto link = interguest_link_->status();
        android["interguest_network"] = {{"port", link.port},
                                         {"connected", link.connected},
                                         {"received_frames", link.received},
                                         {"sent_frames", link.sent},
                                         {"reconnects", link.reconnects},
                                         {"fault", link.fault}};
    }
}

void Session::reset_android_transaction() {
    reset_windows_android_transaction();
}

void Session::configure_android_native_backend(ProcessSpec &spec, const Json &specification,
                                               unsigned port, std::uint64_t generation) {
    if (specification.contains("diagnostic_native")) {
        const auto &native = specification.at("diagnostic_native");

        if (native.at("schema") != 1 || native.at("executable") != spec.executable.string()) {
            throw VoyemuError("WINE_NATIVE_DIAGNOSTIC", "host binding differs");
        }

        spec.wine_native_diagnostic = WineNativeDiagnostic{
                native.at("launcher").get<std::string>(),
                directory_ / ("native-backend-g" + std::to_string(generation)),
                {port, port + 1, specification.at("sdk_control").at("grpc_port").get<unsigned>()},
                3600000};
        spec.environment["ANDROID_HOME"] = native.at("sdk_root").get<std::string>();
        spec.environment["ANDROID_SDK_ROOT"] = native.at("sdk_root").get<std::string>();
    }
}

std::optional<ProcessResult> Session::execute_android_transaction(
        const Json &specification, const std::vector<std::string> &arguments, int &timeout_ms,
        std::size_t limit, std::int64_t expected_pid, std::uint64_t expected_generation) {
    {
        std::lock_guard state(mutex_);

        if (android_request_deadline_ != std::chrono::steady_clock::time_point{}) {
            const auto remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            android_request_deadline_ - std::chrono::steady_clock::now())
                            .count();

            if (remaining < 1) {
                return ProcessResult{1, {}, true};
            }

            timeout_ms = static_cast<int>(std::min<std::int64_t>(timeout_ms, remaining));
        }
    }

    if (!arguments.empty() && arguments.front() == "shell") {
        return execute_windows_android_operation(specification, arguments, timeout_ms, limit,
                                                 expected_pid, expected_generation);
    }

    return std::nullopt;
}

void Session::assert_android_identity() {
    assert_windows_android_identity();
}

void Session::assert_android_identity_until(std::chrono::steady_clock::time_point deadline) {
    assert_windows_android_identity(deadline);
}

bool Session::android_ports_released_after_kill(unsigned port, bool wrapper_alive,
                                                const std::function<bool()> &) {
    TcpPortProbe console_probe, adb_probe;
    const bool console_released = tcp_port_free(port, &console_probe),
               adb_released = tcp_port_free(port + 1, &adb_probe);
    const bool ports_released = console_released && adb_released;

    if (wrapper_alive || !ports_released) {
        try {
            auto probe = [](const TcpPortProbe &value) {
                return Json{{"port", value.port},
                            {"family", value.family},
                            {"stage", value.stage},
                            {"platform_error", value.error},
                            {"listener_pid", value.listener_pid},
                            {"listener_address", value.listener_address.data()}};
            };
            logging::write(logging::Level::error, "android", "stop.host_only_failed",
                           {{"session_id", session_id_},
                            {"generation", android_generation_},
                            {"sdk_pid", android_.pid()},
                            {"wrapper_alive", wrapper_alive},
                            {"wrapper_exit_code", android_.exit_code()},
                            {"ports_released", ports_released},
                            {"console_probe", probe(console_probe)},
                            {"adb_probe", probe(adb_probe)}});
        } catch (...) { /* Ignored: diagnostics do not change the strict release guard. */
        }
    }

    return ports_released;
}

bool Session::android_ports_released_at_stop(unsigned port, const std::function<bool()> &) {
    TcpPortProbe final_probe;
    const bool final_released = tcp_port_free(port, &final_probe) &&
                                tcp_port_free(port + 1, &final_probe);

    if (!final_released) {
        try {
            logging::write(logging::Level::error, "android", "stop.port_probe_failed",
                           {{"session_id", session_id_},
                            {"generation", android_generation_},
                            {"sdk_pid", android_.pid()},
                            {"port", final_probe.port},
                            {"family", final_probe.family},
                            {"stage", final_probe.stage},
                            {"platform_error", final_probe.error},
                            {"listener_pid", final_probe.listener_pid},
                            {"listener_address", final_probe.listener_address.data()}});
        } catch (...) { /* Ignored: diagnostics do not change the strict release guard. */
        }
    }

    return final_released;
}

Json android_launch_identity(std::int64_t) {
    // The job object retained by the launch identifies the SDK; it ends with its supervisor.
    return Json::object();
}

std::optional<std::string> Session::android_boot_id() {
    return windows_android_.boot;
}

void Session::prevalidate_android_reboot() {}

std::optional<std::string>
Session::await_android_reboot(std::unique_lock<std::recursive_mutex> &lock,
                              const std::string &before, const std::function<std::string()> &) {
    const auto deadline = std::min(std::chrono::steady_clock::now() + std::chrono::seconds(60),
                                   android_request_deadline_);
    const auto specification = android_spec_;
    const auto port = specification.at("port").get<unsigned>();
    const auto nonce = android_resume_ ? android_boot_nonce_ : session_id_;
    const WindowsAndroidOwner owner{session_id_, android_generation_, android_.pid(),
                                    sha256_bytes(specification.at("owned_adb").dump() + ":" +
                                                 specification.at("avd_name").get<std::string>() +
                                                 ":" + nonce)};
    std::string frame;
    auto retry = std::chrono::steady_clock::now();
    auto owned = [&] {
        (void)owned_android_adb(specification, owner.sdk_pid, owner.generation, false);

        if (!android_.alive()) {
            throw VoyemuError("ANDROID_ADB_OWNER", "reboot monitor SDK exited");
        }

        return android_.owns_tcp_listener(port) && android_.owns_tcp_listener(port + 1);
    };
    auto avd = [&] {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();

        if (remaining < 1) {
            throw VoyemuError("ANDROID_REBOOT_WAIT", "finite boot monitor deadline");
        }

        const auto result = adb({"emu", "avd", "name"},
                                static_cast<int>(std::min<std::int64_t>(1500, remaining)));

        if (!owned() || result.exit_code || result.timed_out ||
            result.output.substr(0, result.output.find_first_of("\r\n")) !=
                    specification.at("avd_name").get<std::string>()) {
            throw VoyemuError("ANDROID_REBOOT_WAIT", "current SDK AVD unavailable");
        }
    };

    try {
        while (std::chrono::steady_clock::now() < deadline) {
            if (owned()) {
                if (!android_identity_probe_.pending() &&
                    std::chrono::steady_clock::now() >= retry) {
                    avd();
                    frame = random_token();
                    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                   deadline - std::chrono::steady_clock::now()) -
                                           std::chrono::milliseconds(1500);

                    if (remaining < std::chrono::milliseconds(1)) {
                        break;
                    }

                    const auto budget = std::min(remaining, std::chrono::milliseconds(60000));
                    const auto launched = RetainedAndroidAction::Clock::now();
                    auto stream = owned_android_adb(specification, owner.sdk_pid, owner.generation)
                                          ->open_shell({"shell",
                                                        windows_startup_command(
                                                                {"cat",
                                                                 "/proc/sys/kernel/random/boot_id"},
                                                                frame, nonce, {}, false)},
                                                       static_cast<int>(budget.count()), 4096);
                    stream.close_stdin();
                    android_identity_probe_.launch(owner, std::move(stream), launched, budget,
                                                   4096);
                }

                if (android_identity_probe_.pending()) {
                    const auto result = android_identity_probe_.poll(owner);

                    if (result) {
                        avd();
                        android_identity_probe_.cancel();

                        if (!result->timed_out) {
                            const auto pending = parse_windows_reboot_frame(*result, frame, nonce);

                            if (!pending) {
                                retry = std::chrono::steady_clock::now() +
                                        std::chrono::milliseconds(500);
                                continue;
                            }

                            const auto &observed = *pending;

                            if (!observed.boot_changed && observed.result.exit_code == 0 &&
                                android_reboot_changed(before, observed.boot_id)) {
                                windows_android_.owner = owner;
                                windows_android_.reboot_confirmed = true;
                                windows_android_.boot = observed.boot_id;
                                windows_android_.nonce = observed.nonce;
                                windows_android_.started = std::chrono::steady_clock::now();
                                android_transport_boot_ = observed.boot_id;
                                android_boot_nonce_ = observed.nonce;
                                android_identity_ = false;
                                android_identity_proof_operation_ = 0;
                                deliveries_["android"]["reboot"]["status"] = "completed";
                                deliveries_["android"]["reboot"]["boot_id"] = observed.boot_id;
                                deliveries_["android"]["status"] = "booting";
                                record_android_processes(false);

                                return observed.boot_id;
                            }
                        }

                        retry = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
                    }
                }
            }

            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            lock.lock();
        }

        android_identity_probe_.cancel();
    } catch (...) {
        android_identity_probe_.cancel();
        throw;
    }

    return std::nullopt;
}

void Session::configure_qnx_event_monitor(ProcessSpec &qemu, const std::string &ram_backend) {
    // A second owned monitor mirrors the macOS event channel over the same loopback TCP primitive.
    qnx_shutdown_monitor_.reset();
    qnx_events_port_ = 0;

    if (qnx_persistent_storage_ && cluster_spec_.at("qmp").is_object() &&
        cluster_spec_.at("qmp").value("host", std::string{}) == "127.0.0.1" &&
        cluster_spec_.at("qmp").contains("port") &&
        std::find(qemu.arguments.begin(), qemu.arguments.end(), "-no-reboot") !=
                qemu.arguments.end() &&
        std::find(qemu.arguments.begin(), qemu.arguments.end(), "-S") != qemu.arguments.end()) {
        const auto base = cluster_spec_.at("qmp").at("port").get<unsigned>();

        for (unsigned port = base + 1; port < 65535; ++port) {
            if (tcp_port_free(port)) {
                qnx_events_port_ = port;
                break;
            }
        }

        if (!qnx_events_port_) {
            throw VoyemuError("QMP_EVENTS", "no owned loopback event port available");
        }

        qnx_shutdown_monitor_ = std::make_unique<QnxShutdownMonitor>(
                Json{{"host", "127.0.0.1"}, {"port", qnx_events_port_}}, cluster_generation_ + 1);
        qemu.arguments.insert(qemu.arguments.end(),
                              {"-qmp", "tcp:127.0.0.1:" + std::to_string(qnx_events_port_) +
                                               ",server=on,wait=off"});
    }

    if (cluster_boot_spec_.contains("diagnostic_native")) {
        const auto &native = cluster_boot_spec_.at("diagnostic_native");

        if (native.at("schema") != 1 || native.at("executable") != qemu.executable.string() ||
            ram_backend != "file" || !cluster_boot_spec_.at("qmp").is_object()) {
            throw VoyemuError("QNX_NATIVE_DIAGNOSTIC",
                              "exact native engine/file RAM/TCP binding required");
        }

        std::vector<unsigned> native_ports{native.at("qmp_port").get<unsigned>()};

        if (qnx_events_port_) {
            native_ports.push_back(qnx_events_port_);
        }

        qemu.wine_native_diagnostic = WineNativeDiagnostic{native.at("launcher").get<std::string>(),
                                                           directory_ / "native-qnx-backend",
                                                           std::move(native_ports), 3600000};
    }
}

bool Session::continue_qnx_guest() {
    if (qnx_shutdown_monitor_) {
        if (!qnx_.owns_tcp_listener(qnx_events_port_)) {
            return false;
        }

        qnx_shutdown_monitor_->connect_owned(qnx_.pid(), [this] {
            if (!qnx_.alive() || !qnx_.owns_tcp_listener(qnx_events_port_)) {
                throw VoyemuError("QNX_SHUTDOWN_MONITOR", "owned QMP events listener required");
            }
        });
    }

    const auto &qmp = cluster_spec_.at("qmp");

    if (!qmp.is_object() || !qmp.contains("port")) {
        throw VoyemuError("QMP_OWNER", "owned Windows loopback listener required");
    }

    const auto port = qmp.at("port").get<unsigned>();

    if (port < 1024 || port > 65535) {
        throw VoyemuError("QMP_PORT", "invalid port");
    }

    if (!qnx_.owns_tcp_listener(port)) {
        return false;
    }

    qmp_cont_ = qmp_continue_windows(qmp, qnx_checkpoint_.resume);

    return qmp_cont_;
}

void Session::start_qnx_ring_collector(const std::filesystem::path &, std::uint64_t, std::size_t,
                                       std::uint64_t) {}

void Session::add_retained_qnx_producers(
        std::vector<std::uint64_t> &,
        std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> &,
        const std::function<void(std::uint64_t, const char *)> &) {}

void Session::configure_graphics_environment(ProcessSpec &spec, const Json &graphics) {
    if (cluster_boot_spec_.contains("diagnostic_native")) {
        spec.environment["ANGLE_DEFAULT_PLATFORM"] = "vulkan";
        spec.environment["VOYEMU_RPC_PROFILE"] = "1";
    }

    const auto icd = std::filesystem::path(graphics.at("angle").get<std::string>()) /
                     "vk_swiftshader_icd.json";
    spec.environment["VK_DRIVER_FILES"] = icd.string();
    spec.environment["VK_ICD_FILENAMES"] = icd.string();
}

void Session::set_qnx_persistence_paused(bool paused) {
    const auto &qmp = cluster_spec_.at("qmp");

    if (!qmp.is_object() || !qmp.contains("port") || !qmp.at("port").is_number_unsigned()) {
        throw VoyemuError("QNX_PERSISTENCE", "owned QMP endpoint required");
    }

    const auto port = qmp.at("port").get<unsigned>();

    if (port < 1024 || port > 65535) {
        throw VoyemuError("QNX_PERSISTENCE", "invalid QMP port");
    }

    auto owned = [&] {
        if (!qnx_.alive() || !qnx_.owns_tcp_listener(port)) {
            throw VoyemuError("QNX_PERSISTENCE", "QMP listener is not owned QEMU");
        }
    };
    owned();

    if (paused) {
        qnx_persistence_paused_ = true;
    }

    qmp_continue_windows(qmp, false, owned, paused);
    qnx_persistence_paused_ = paused;
}

void Session::stop_qnx_ready_collector() {}

void Session::remove_qmp_socket(Json &) {}

void Session::require_unborrowed_state_lock() const {}

Json Session::observe_can_boundary(const std::function<Json(const std::string &)> &unavailable,
                                   std::unique_lock<std::recursive_mutex> &,
                                   std::chrono::steady_clock::time_point, int) {
    return unavailable("native owned Android backend required");
}

void Session::prepare_android_media_input() {
    if (!windows_android_.ever_ready ||
        !windows_android_.observation_current(std::chrono::steady_clock::now()) ||
        !android_clock_observed_ || !android_boot_completed_) {
        throw VoyemuError("TEST_BUSY",
                          "fresh complete Windows guest observation required before input");
    }

    assert_android_identity();
    guard_windows_android_transaction();
}

void Session::bound_android_request(const Json &operation,
                                    std::chrono::steady_clock::time_point received) {
    const auto op = operation.value("op", std::string{});

    // Cluster observations already validate and enforce their own deadline.
    if (op == "test_cluster_ui" || op == "test_cluster_system") {
        return;
    }

    if (operation.contains("timeout_ms")) {
        if (!operation.at("timeout_ms").is_number_integer()) {
            throw VoyemuError("IPC_BOUNDS", "integer control timeout required");
        }

        const auto timeout = operation.at("timeout_ms").get<std::int64_t>();

        // A request that closes the cluster may carry its full bound, which the guest sync of the
        // TCG engine extends beyond 180 s.
        if (timeout < 0 || timeout > std::max(180000, request_timeout_limit_ms(op))) {
            throw VoyemuError("IPC_BOUNDS", "control timeout out of range");
        }

        // The framed Windows transaction reserves one AVD identity fence before and one after
        // every guest action, so a caller bound below that floor can never complete: the floor
        // is the effective bound of the request, exactly as it is of the single guest
        // operation.
        android_request_deadline_ =
                std::min(android_request_deadline_,
                         received + std::chrono::milliseconds(windows_guest_operation_timeout(
                                            static_cast<int>(timeout),
                                            android_spec_.contains("diagnostic_native"))));
    }
}

void Session::request_frontend_stop() {
    if (frontend_.alive()) {
        try {
            write_private_json(directory_ / "media-view-stop.json",
                               {{"schema", 1},
                                {"session_id", session_id_},
                                {"frontend_pid", frontend_.pid()}});
        } catch (const std::exception &error) {
            logging::write(logging::Level::error, "frontend", "window.stop_request_failed",
                           {{"error", error.what()}});
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);

        while (frontend_.alive() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
}

int Session::android_provider_budget() const {
    // Exact stop scope, bounded by its existing request deadline.
    return android_identity_stopping_ ? 60000 : 2500;
}

void Session::retire_android_transaction_for_flush(bool android_stopping) {
    if (android_stopping) {
        reset_windows_android_transaction();
    } else {
        retire_windows_wheel_pair_for_flush();
    }
}

void Session::reset_android_identity_for_new_boot() {
    android_identity_probe_.cancel();
    android_identity_proof_operation_ = 0;
    android_identity_mismatch_ = false;
    android_identity_ = false;
}

bool Session::android_host_canvas_ready(const std::function<void()> &) {
    return true;
}

ChildProcess launch_session_child(const ProcessSpec &spec, const std::filesystem::path &,
                                  const std::string &, std::uint64_t) {
    return ChildProcess::launch(spec);
}

// Windows keeps no launch identity record: the job object of ChildProcess owns the Android child.
void advance_android_launch_generation(const std::filesystem::path &, const std::string &,
                                       std::int64_t, std::uint64_t) {}

// The named pipe of a Windows session derives from its id, so no endpoint record is kept.
void record_session_endpoint(const std::filesystem::path &, const std::string &,
                             const std::filesystem::path &) {}
} // namespace voyemu
