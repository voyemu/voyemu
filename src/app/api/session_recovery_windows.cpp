#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>

#include "session_recovery.hpp"
#include <iphlpapi.h>
namespace voyemu::api {
namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;

    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
};
} // namespace

StoppedAndroidLease::StoppedAndroidLease(const std::filesystem::path &root,
                                         const std::string &profile,
                                         const MachineIdentity &machine_scope,
                                         const std::string &id, const std::string &ownership)
    : root_(root), profile_(profile), id_(id), ownership_(ownership) {
    check_epoch(profile, machine_scope, id, ownership);
    ordinary_path(root);
    const auto active_directory = native_current_active_directory(root, profile, machine_scope);
    launch_lock_ = std::make_unique<FileLock>(active_directory / (profile + ".launch.lock"));
    supervisor_lock_ =
            std::make_unique<FileLock>(active_directory / (profile + ".supervisor.lock"));
    active_path_ = active_directory / (profile + ".json");
    active_ = read_private_json(active_path_, 4096);
    directory_ = native_session_directory(root, profile, machine_scope, id);
    require(active_.at("session_id") == id && active_.at("profile") == profile &&
                    path(active_, "directory") == directory_,
            "active epoch/path differs");
    require(active_.at("endpoint") == "\\\\.\\pipe\\voyemu-" + id, "private endpoint differs");
    owner_ = read_private_json(directory_ / "automation-owner.json", 4096);
    require(owner_.at("session_id") == id && owner_.at("profile") == profile &&
                    owner_.at("ownership_id") == ownership,
            "automation owner differs");
    supervisor_ = read_private_json(directory_ / "session-owner.json", 16384);
    require(supervisor_.at("schema") == 1 && supervisor_.at("session_id") == id &&
                    path(supervisor_, "directory") == directory_ &&
                    supervisor_.at("origin") == "voyemu-native-supervisor",
            "supervisor owner differs");
    runtime_ = read_private_json(directory_ / "runtime.json");
    require(runtime_.at("session_id") == id && runtime_.at("endpoint") == active_.at("endpoint"),
            "runtime epoch differs");
    const auto &qnx = runtime_.at("deliveries").at("qnx");
    const auto qnx_status = qnx.value("status", std::string{});
    require(runtime_.value("qnx_pid", std::int64_t{}) == 0 &&
                    (qnx_status == "not_started" || (qnx_status == "stopped" && qnx.size() == 1)) &&
                    !supervisor_.contains("qnx_pid"),
            "QNX ownership cannot be recovered as Android-only");
    auto machine = machine_scope;

    if (std::filesystem::exists(directory_ / "machine-selection.json")) {
        selection_ = read_private_json(directory_ / "machine-selection.json", 4096);
        const auto selector = selection_.at("machine").get<std::string>();
        const auto selected = inspect_machine_path(path(selection_, "seed"));
        require((selector.empty() || valid_profile_name(selector)) && selected.profile == profile &&
                        machine_selector_matches(root, selected, selector),
                "machine selection differs");
        machine = machine_identity(profile, selector);
    }

    require(machine_scope.name == machine.name, "requested machine differs from owned session");
    scoped_ = profile_launch_directory(root, profile, machine);
    activation_ = read_private_json(scoped_ / "activation.json");
    launch_ = read_private_json(scoped_ / "android-launch.json");
    launch_sha_ = sha256_file(scoped_ / "android-launch.json");
    const bool configured = activation_.value("kind", std::string{}) == "runtime-configuration";
    const auto processes = supervisor_.value("android_processes", Json::object());
    require(launch_.value("adb_transport", std::string{}) == "direct",
            "direct Android transport required");
    require(activation_.at("profile") == profile, "activation profile differs");

    if (!configured) {
        require(activation_.at("android_launch_sha256") == launch_sha_,
                "activation launch differs");
    }

    const auto manifest_sha = activation_.at("manifest_sha256").get<std::string>();
    require(sha256_text(manifest_sha), "source manifest pin required");

    if (configured) {
        require(activation_.size() == 7 && activation_.at("schema") == 1 &&
                        canonical_machine_name(profile,
                                               activation_.at("machine").get<std::string>()) ==
                                machine.name &&
                        activation_.at("integrity_audited") == false,
                "runtime configuration identity differs");
        const auto seed = selection_.is_null() ? root / "machines" / profile
                                               : path(selection_, "seed");
        ordinary_path(seed);
        ordinary_path(path(activation_, "seed"));
        require(std::filesystem::equivalent(path(activation_, "seed"), seed),
                "runtime configuration seed differs");
        const auto manifest_file = seed / "runtime.json";
        ordinary_path(manifest_file);
        require(ordinary_native_launch_file(manifest_file) &&
                        std::filesystem::hard_link_count(manifest_file) == 1 &&
                        std::filesystem::file_size(manifest_file) < 128 * 1024,
                "bounded ordinary seed manifest required");
        const auto manifest = read_private_json(manifest_file, 128 * 1024);
        require(sha256_file(manifest_file) == manifest_sha && manifest.at("schema") == 1 &&
                        manifest.at("kind") == "portable-guest-runtime" &&
                        manifest.at("profile") == profile,
                "seed manifest identity differs");
        const auto &android = manifest.at("android");
        const auto api = android.at("api").get<unsigned>();
        const auto archive = android.at("base_archive_sha256").get<std::string>();
        require((api == 28 || api == 30) &&
                        (android.at("abi") == "arm64-v8a" || android.at("abi") == "x86_64") &&
                        sha256_text(archive),
                "registered Android base identity required");
        ordinary_path(path(launch_, "machine"));
        ordinary_path(path(launch_, "base"));
        require(std::filesystem::equivalent(path(launch_, "machine"), seed / "android") &&
                        std::filesystem::equivalent(path(launch_, "base"), seed / "android"),
                "configured Android paths differ");
        const auto sdk = path(launch_, "android_sdk_root");
        require(std::filesystem::equivalent(
                        path(launch_, "executable"),
                        android_sdk_program(sdk, true, android.at("abi").get<std::string>())),
                "configured SDK paths differ");
    } else {
        const auto runtime_parent = root / ".local/machines" / machine.name / "portable";
        const auto runtime_root = runtime_parent / ("portable-" + manifest_sha);
        require(path(activation_, "runtime") == runtime_root &&
                        path(launch_, "machine") == runtime_root / "android-machine" &&
                        path(launch_, "base") == runtime_root / "android-machine/base",
                "source runtime paths differ");
        ordinary_path(runtime_root / "android-machine/base");
    }

    if (machine.selected) {
        require(canonical_machine_name(profile, activation_.at("machine").get<std::string>()) ==
                                machine.name &&
                        activation_.at("manifest_sha256") == selection_.at("manifest_sha256"),
                "activation selection differs");
    }

    const unsigned console = launch_.at("port").get<unsigned>(),
                   grpc = launch_.at("sdk_control").at("grpc_port").get<unsigned>();
    require(console >= 1024 && console <= 65534 && console % 2 == 0 && grpc >= 1024 &&
                    grpc <= 65535,
            "bounded SDK ports required");
    ports_ = {console, console + 1, grpc};

    require(std::set<unsigned>(ports_.begin(), ports_.end()).size() == ports_.size(),
            "distinct owned ports required");
    pids_.insert(pid(supervisor_, "creator_pid", true));
    pids_.insert(pid(runtime_, "android_pid", false));
    const auto &android = runtime_.at("deliveries").at("android");
    pids_.insert(pid(android, "pid", false));

    if (android.contains("wrapper")) {
        pids_.insert(pid(android.at("wrapper"), "pid", false));
    }

    if (runtime_.at("deliveries").contains("frontend")) {
        pids_.insert(pid(runtime_.at("deliveries").at("frontend"), "pid", false));
    }

    if (supervisor_.contains("android_processes")) {
        require(processes.at("phase") == "recorded" &&
                        processes.at("generation") ==
                                runtime_.at("deliveries").at("android").at("generation"),
                "incomplete/stale process launch");
        require(processes.at("console_port") == console && processes.at("grpc_port") == grpc,
                "process ports differ");

        require(processes.at("adbd_port") == console + 1 && !processes.contains("adb_pid") &&
                        !processes.contains("adb_server_port"),
                "direct adbd receipt differs");

        for (const auto *key : {"sdk_pid", "frontend_pid"}) {
            pids_.insert(pid(processes, key, false));
        }

        require(processes.at("sdk_pid") == runtime_.at("android_pid"),
                "SDK process receipt differs");
    }

    frontend_image_ = path(launch_.at("frontend"), "executable");
    const auto backend = android_sdk_program(path(launch_, "android_sdk_root"), true,
                                             launch_.value("guest_arch", std::string("arm64-v8a")));
    std::vector<std::filesystem::path> images{path(launch_, "executable"), backend,
                                              frontend_image_};

    for (const auto &file : images) {
        const auto relative = file.lexically_relative(root);
        require(file.is_absolute() && !relative.empty() && !relative.is_absolute(),
                "owned executable must be inside project");

        for (const auto &part : relative) {
            require(part != ".." && part != ".", "executable path escapes project");
        }

        ordinary_path(file);
        require(ordinary_native_launch_file(file) && std::filesystem::hard_link_count(file) == 1,
                "ordinary unaliased owned executable required");
        images_.insert(file);
    }

    if (!configured) {
        for (const auto &file : images_) {
            if (file != frontend_image_) {
                unsigned count = 0;

                for (const auto &item : launch_.at("pins")) {
                    if (path(item, "path") == file) {
                        require(sha256_file(file) == item.at("sha256").get<std::string>(),
                                "SDK/ADB pin differs");
                        ++count;
                    }
                }

                require(count == 1, "exact SDK/ADB pin required");
            }
        }
    }

    if (std::filesystem::exists(directory_ / "media-connection.json")) {
        media_ = read_private_json(directory_ / "media-connection.json", 16384);
        require(media_.at("session_id") == id &&
                        media_.at("vm_pid") == runtime_.at("android_pid") &&
                        media_.at("grpc_port") == grpc && media_.at("serial_port") == console,
                "media SDK process/ports differ");
        pids_.insert(pid(media_, "vm_pid", true));
    }

    verify_processes();
    endpoint_dead();
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "socket initialization failed");
    wsa_ = true;
    try {
        for (const auto port : ports_) {
            require(tcp_port_free(port), "existing listener table entry remains");

            for (const int family : {AF_INET, AF_INET6}) {
                hold(port, family);
            }
        }

        verify();
    } catch (...) {
        release_sockets();
        throw;
    }
}

StoppedAndroidLease::~StoppedAndroidLease() {
    release_sockets();
}

bool StoppedAndroidLease::endpoint_absent(const std::filesystem::path &endpoint) {
    if (WaitNamedPipeW(endpoint.c_str(), 1)) {
        return false;
    }

    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

void StoppedAndroidLease::verify_host_absence() const {
    verify_owner_records();
    verify_processes();
    endpoint_dead();
    verify_listeners();
}

void StoppedAndroidLease::verify() const {
    verify_host_absence();
    require(read_private_json(scoped_ / "activation.json") == activation_ &&
                    sha256_file(scoped_ / "android-launch.json") == launch_sha_,
            "activation changed during recovery");
}

void StoppedAndroidLease::verify_owner_records() const {
    require(read_private_json(active_path_, 4096) == active_ &&
                    read_private_json(directory_ / "automation-owner.json", 4096) == owner_ &&
                    read_private_json(directory_ / "session-owner.json", 16384) == supervisor_ &&
                    read_private_json(directory_ / "runtime.json") == runtime_,
            "owned records changed during recovery");
    require(std::filesystem::exists(directory_ / "machine-selection.json") == !selection_.is_null(),
            "machine selection presence changed during recovery");

    if (!selection_.is_null()) {
        require(read_private_json(directory_ / "machine-selection.json", 4096) == selection_,
                "machine selection changed during recovery");
    }

    require(std::filesystem::exists(directory_ / "media-connection.json") == !media_.is_null(),
            "media binding presence changed during recovery");

    if (!media_.is_null()) {
        require(read_private_json(directory_ / "media-connection.json", 16384) == media_,
                "media binding changed during recovery");
    }
}

void StoppedAndroidLease::ordinary_path(const std::filesystem::path &file) {
    require(file.is_absolute() && file.lexically_normal() == file,
            "absolute ordinary path required");

    for (const auto &at : os::ancestors(file)) {
        const auto attributes = GetFileAttributesW(at.c_str());
        require(attributes != INVALID_FILE_ATTRIBUTES &&
                        !(attributes & FILE_ATTRIBUTE_REPARSE_POINT),
                "missing or reparse owned path");
    }
}

void StoppedAndroidLease::endpoint_dead() const {
    const auto endpoint = path(active_, "endpoint");

    if (WaitNamedPipeW(endpoint.c_str(), 1)) {
        require(false, "supervisor endpoint remains");
    }

    require(GetLastError() == ERROR_FILE_NOT_FOUND, "supervisor endpoint absence not proven");
}

void StoppedAndroidLease::verify_processes() const {
    for (const auto &image : images_) {
        ordinary_path(image);
    }

    for (const auto value : pids_) {
        if (value) {
            Handle process;
            process.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                        static_cast<DWORD>(value));

            if (!process.value) {
                require(GetLastError() == ERROR_INVALID_PARAMETER,
                        "recorded process absence not proven");
                continue;
            }

            require(WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0,
                    "recorded process remains or PID was reused");
        }
    }

    Handle snapshot;
    snapshot.value = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    require(snapshot.value != INVALID_HANDLE_VALUE, "complete process enumeration failed");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    BOOL more = Process32FirstW(snapshot.value, &entry);
    require(more || GetLastError() == ERROR_NO_MORE_FILES, "process enumeration failed");

    while (more) {
        bool candidate = false;

        for (const auto &image : images_) {
            if (CompareStringOrdinal(entry.szExeFile, -1, image.filename().c_str(), -1, TRUE) ==
                CSTR_EQUAL) {
                candidate = true;
            }
        }

        if (candidate) {
            Handle process;
            process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                        entry.th32ProcessID);

            if (!process.value) {
                require(GetLastError() == ERROR_INVALID_PARAMETER,
                        "matching process image identity unavailable");
            } else {
                std::wstring image(32768, L'\0');
                DWORD count = static_cast<DWORD>(image.size());
                require(QueryFullProcessImageNameW(process.value, 0, image.data(), &count) &&
                                count > 0 && count < image.size(),
                        "matching process image identity unavailable");
                image.resize(count);
                const std::filesystem::path actual(image);

                // Foreign paths are only inspected through their ordinary final-file handle;
                // aliases to an owned image still match its identity.
                for (const auto &expected : images_) {
                    const auto same_spelling =
                            CompareStringOrdinal(actual.lexically_normal().c_str(), -1,
                                                 expected.lexically_normal().c_str(), -1,
                                                 TRUE) == CSTR_EQUAL;
                    const auto same_identity = file_identity(actual) == file_identity(expected);

                    if (same_spelling) {
                        require(same_identity, "matching image identity changed");
                    }

                    if (same_spelling || same_identity) {
                        require(entry.th32ProcessID == GetCurrentProcessId() &&
                                        expected == frontend_image_,
                                "owned executable process remains");
                    }
                }
            }
        }

        more = Process32NextW(snapshot.value, &entry);
    }

    require(GetLastError() == ERROR_NO_MORE_FILES, "incomplete process enumeration");
}

std::array<unsigned long, 3> StoppedAndroidLease::file_identity(const std::filesystem::path &file) {
    Handle handle;

    handle.value = CreateFileW(file.c_str(), FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    require(handle.value != INVALID_HANDLE_VALUE && GetFileType(handle.value) == FILE_TYPE_DISK &&
                    GetFileInformationByHandle(handle.value, &info) &&
                    !(info.dwFileAttributes &
                      (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
                    info.nNumberOfLinks == 1,
            "ordinary process image identity unavailable");

    return {info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow};
}

void StoppedAndroidLease::verify_listeners() const {
    for (const auto family : {AF_INET, AF_INET6}) {
        DWORD bytes = 0;
        auto result = GetExtendedTcpTable(nullptr, &bytes, FALSE, family,
                                          TCP_TABLE_OWNER_PID_LISTENER, 0);
        require(result == ERROR_INSUFFICIENT_BUFFER && bytes > 0 && bytes < 16 * 1024 * 1024,
                "listener ownership table unavailable");
        std::vector<unsigned char> table(bytes);
        require(GetExtendedTcpTable(table.data(), &bytes, FALSE, family,
                                    TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR,
                "listener ownership table read failed");
        std::set<unsigned> found;
        auto inspect = [&](DWORD network, DWORD owner) {
            const auto port = ntohs(static_cast<u_short>(network));

            if (std::find(ports_.begin(), ports_.end(), port) != ports_.end()) {
                require(owner == GetCurrentProcessId(),
                        "foreign listener appeared during recovery");
                found.insert(port);
            }
        };

        if (family == AF_INET) {
            const auto *value = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(table.data());

            for (DWORD i = 0; i < value->dwNumEntries; ++i) {
                inspect(value->table[i].dwLocalPort, value->table[i].dwOwningPid);
            }
        } else {
            const auto *value = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID *>(table.data());

            for (DWORD i = 0; i < value->dwNumEntries; ++i) {
                inspect(value->table[i].dwLocalPort, value->table[i].dwOwningPid);
            }
        }

        require(found.size() == ports_.size(), "held listeners missing from ownership table");
    }
}

void StoppedAndroidLease::hold(unsigned port, int family) {
    require(port >= 1024 && port <= 65535, "bounded listener port required");
    const auto socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    require(socket != INVALID_SOCKET, "listener fence unavailable");
    sockets_.push_back(socket);
    BOOL yes = TRUE;
    require(setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char *>(&yes), sizeof(yes)) == 0,
            "exclusive listener fence unavailable");

    if (family == AF_INET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<u_short>(port));
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        require(::bind(socket, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0,
                "IPv4 listener remains");
    } else {
        require(setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&yes),
                           sizeof(yes)) == 0,
                "IPv6-only listener fence unavailable");
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(static_cast<u_short>(port));
        address.sin6_addr = in6addr_any;
        require(::bind(socket, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0,
                "IPv6 listener remains");
    }

    require(::listen(socket, 1) == 0, "held listener fence unavailable");
}

void StoppedAndroidLease::release_sockets() {
    for (const auto socket : sockets_) {
        closesocket(socket);
    }

    sockets_.clear();

    if (wsa_) {
        WSACleanup();
        wsa_ = false;
    }
}

std::optional<Json> recover_stopped_supervisor(const std::filesystem::path &root,
                                               const std::string &profile,
                                               const MachineIdentity &machine, const Json &record,
                                               const std::string &ownership,
                                               const std::filesystem::path &active_directory,
                                               bool failed_stop) {
    (void)active_directory;
    (void)failed_stop;

    if (!StoppedAndroidLease::endpoint_absent(record.at("endpoint").get<std::string>())) {
        return std::nullopt;
    }

    StoppedAndroidLease lease(root, profile, machine, record.at("session_id").get<std::string>(),
                              ownership);

    return lease.publish_terminal();
}
} // namespace voyemu::api
