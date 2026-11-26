#include "core/process.hpp"
#include "os/socket.hpp"
#include <windows.h>
#include <cstring>
#include <iphlpapi.h>
#include <vector>

namespace voyemu::os {
namespace {
SOCKET native(SocketHandle socket) {
    return static_cast<SOCKET>(socket);
}

// Whether a listener table row holds port in the LISTEN state, recording it in diagnostic.
template <typename Row, typename Address>
bool listening(const Row &row, int family, unsigned port, const Address &address,
               TcpPortProbe *diagnostic) {
    if (row.dwState != MIB_TCP_STATE_LISTEN ||
        ntohs(static_cast<u_short>(row.dwLocalPort)) != port) {
        return false;
    }

    if (diagnostic) {
        diagnostic->listener_pid = row.dwOwningPid;
        ::inet_ntop(family, &address, diagnostic->listener_address.data(),
                    diagnostic->listener_address.size());
    }

    return true;
}

// The IPv4 TCP table of kind with owning processes: absent when the host has no rows.
LoopbackHolder tcp_table(TCP_TABLE_CLASS kind, std::vector<unsigned char> &data) {
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        ULONG bytes = 0;
        const auto first = GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET, kind, 0);

        if (first == ERROR_NO_DATA) {
            return LoopbackHolder::absent;
        }

        if ((first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR) || bytes < sizeof(DWORD) ||
            bytes > 1024 * 1024) {
            return LoopbackHolder::table_unavailable;
        }

        data.resize(bytes);
        const auto result = GetExtendedTcpTable(data.data(), &bytes, FALSE, AF_INET, kind, 0);

        if (result == ERROR_INSUFFICIENT_BUFFER) {
            continue;
        }

        if (result == ERROR_NO_DATA) {
            return LoopbackHolder::absent;
        }

        if (result != NO_ERROR) {
            return LoopbackHolder::table_read_failed;
        }

        if (bytes > data.size() || bytes < sizeof(DWORD)) {
            return LoopbackHolder::table_extent_invalid;
        }

        const auto *table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(data.data());

        if (table->dwNumEntries > (bytes - sizeof(DWORD)) / sizeof(MIB_TCPROW_OWNER_PID)) {
            return LoopbackHolder::table_count_invalid;
        }

        return LoopbackHolder::owner;
    }

    return LoopbackHolder::absent;
}
} // namespace

SocketLibrary::SocketLibrary() {
    WSADATA data{};

    error_ = static_cast<unsigned>(WSAStartup(MAKEWORD(2, 2), &data));
}

SocketLibrary::~SocketLibrary() {
    if (!error_) {
        WSACleanup();
    }
}

unsigned socket_error() {
    return static_cast<unsigned>(WSAGetLastError());
}

bool socket_interrupted() {
    return WSAGetLastError() == WSAEINTR;
}

bool socket_would_block() {
    return WSAGetLastError() == WSAEWOULDBLOCK;
}

bool socket_connecting() {
    return WSAGetLastError() == WSAEWOULDBLOCK;
}

bool socket_reset() {
    return WSAGetLastError() == WSAECONNRESET;
}

SocketHandle open_stream_socket(int family) {
    const SOCKET socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);

    return socket == INVALID_SOCKET ? no_socket : static_cast<SocketHandle>(socket);
}

SocketHandle open_unix_listener(std::string_view, int) {
    return no_socket;
}

bool unix_socket_listening(std::string_view) {
    return false;
}

SocketHandle open_private_tcp_socket() {
    const SOCKET socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                     WSA_FLAG_NO_HANDLE_INHERIT);
    u_long nonblocking = 1;

    if (socket == INVALID_SOCKET) {
        return no_socket;
    }

    if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0) {
        closesocket(socket);

        return no_socket;
    }

    return static_cast<SocketHandle>(socket);
}

void close_socket(SocketHandle socket) {
    closesocket(native(socket));
}

bool make_private_socket(SocketHandle socket) {
    u_long nonblocking = 1;

    return ::ioctlsocket(native(socket), FIONBIO, &nonblocking) == 0 &&
           ::SetHandleInformation(reinterpret_cast<HANDLE>(native(socket)), HANDLE_FLAG_INHERIT, 0);
}

SocketHandle accept_socket(SocketHandle socket) {
    const SOCKET peer = ::accept(native(socket), nullptr, nullptr);

    return peer == INVALID_SOCKET ? no_socket : static_cast<SocketHandle>(peer);
}

int poll_socket(SocketHandle socket, bool writing, int timeout_ms) {
    fd_set read{}, write{};

    FD_SET(native(socket), &read);

    if (writing) {
        FD_SET(native(socket), &write);
    }

    timeval budget{0, static_cast<long>(timeout_ms) * 1000};

    return ::select(0, &read, writing ? &write : nullptr, nullptr, &budget);
}

bool bind_socket(SocketHandle socket, const sockaddr *address, SocketLength size) {
    return ::bind(native(socket), address, size) == 0;
}

bool connect_socket(SocketHandle socket, const sockaddr *address, SocketLength size) {
    return ::connect(native(socket), address, size) == 0;
}

bool socket_name(SocketHandle socket, sockaddr *address, SocketLength *size) {
    return ::getsockname(native(socket), address, size) == 0;
}

int pending_socket_error(SocketHandle socket) {
    int error = 0;
    int size = sizeof(error);

    return ::getsockopt(native(socket), SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error),
                        &size)
                   ? -1
                   : error;
}

long long send_socket(SocketHandle socket, const char *data, std::size_t size) {
    return ::send(native(socket), data, static_cast<int>(size), 0);
}

long long receive_socket(SocketHandle socket, char *data, std::size_t size) {
    return ::recv(native(socket), data, static_cast<int>(size), 0);
}

bool listen_socket(SocketHandle socket, int backlog) {
    return ::listen(native(socket), backlog) == 0;
}

bool shutdown_socket(SocketHandle socket, bool receiving) {
    return ::shutdown(native(socket), receiving ? SD_BOTH : SD_SEND) == 0;
}

bool set_socket_buffer(SocketHandle socket, bool sending, int bytes) {
    return ::setsockopt(native(socket), SOL_SOCKET, sending ? SO_SNDBUF : SO_RCVBUF,
                        reinterpret_cast<const char *>(&bytes), sizeof(bytes)) == 0;
}

bool reuse_address(SocketHandle) {
    return true;
}

bool exclusive_address(SocketHandle socket) {
    int exclusive = 1;

    return setsockopt(native(socket), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                      reinterpret_cast<const char *>(&exclusive), sizeof(exclusive)) == 0;
}

int wait_socket(SocketHandle socket, bool writing, long long timeout_us) {
    fd_set selected, failed;

    FD_ZERO(&selected);
    FD_SET(native(socket), &selected);
    FD_ZERO(&failed);
    FD_SET(native(socket), &failed);
    timeval budget{static_cast<long>(timeout_us / 1000000),
                   static_cast<long>(timeout_us % 1000000)};
    const int result = ::select(0, writing ? nullptr : &selected, writing ? &selected : nullptr,
                                &failed, &budget);

    if (result > 0) {
        return FD_ISSET(native(socket), &failed) ? -2 : 1;
    }

    return result;
}

std::optional<SocketRefusal> loopback_listener(int family, const sockaddr *, SocketLength,
                                               unsigned port, TcpPortProbe *diagnostic) {
    // Wine and Windows reusable sockets may allow overlapping binds; inspect live listeners first.
    ULONG bytes = 0;
    auto table_result = GetExtendedTcpTable(nullptr, &bytes, FALSE, family,
                                            TCP_TABLE_OWNER_PID_LISTENER, 0);

    if (table_result != ERROR_INSUFFICIENT_BUFFER || bytes > 1024 * 1024) {
        return SocketRefusal{"table_size", static_cast<unsigned>(table_result)};
    }

    std::vector<unsigned char> table_bytes(bytes);
    const auto table_read = GetExtendedTcpTable(table_bytes.data(), &bytes, FALSE, family,
                                                TCP_TABLE_OWNER_PID_LISTENER, 0);

    if (table_read != NO_ERROR) {
        return SocketRefusal{"table_read", static_cast<unsigned>(table_read)};
    }

    if (family == AF_INET) {
        const auto table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(table_bytes.data());

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            in_addr local{};
            local.s_addr = table->table[i].dwLocalAddr;

            if (listening(table->table[i], family, port, local, diagnostic)) {
                return SocketRefusal{"listener", 0};
            }
        }
    } else {
        const auto table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID *>(table_bytes.data());

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            IN6_ADDR local{};
            std::memcpy(&local, table->table[i].ucLocalAddr, sizeof local);

            if (listening(table->table[i], family, port, local, diagnostic)) {
                return SocketRefusal{"listener", 0};
            }
        }
    }

    return std::nullopt;
}

bool peer_name(SocketHandle socket, sockaddr *address, SocketLength *size) {
    return ::getpeername(native(socket), address, size) == 0;
}

bool set_nonblocking_socket(SocketHandle socket) {
    u_long one = 1;

    return ::ioctlsocket(native(socket), FIONBIO, &one) == 0;
}

bool suppress_socket_signal(SocketHandle) {
    return true;
}

LoopbackHolder loopback_listener_holder(std::uint64_t pid, unsigned port) {
    std::vector<unsigned char> data;

    if (const auto read = tcp_table(TCP_TABLE_OWNER_PID_LISTENER, data);
        read != LoopbackHolder::owner) {
        return read;
    }

    const auto *table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(data.data());
    auto holder = LoopbackHolder::absent;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];

        if (ntohs(static_cast<u_short>(row.dwLocalPort)) != port) {
            continue;
        }

        if (row.dwOwningPid != pid || row.dwLocalAddr != htonl(INADDR_LOOPBACK)) {
            return LoopbackHolder::foreign;
        }

        holder = LoopbackHolder::owner;
    }

    return holder;
}

LoopbackHolder loopback_connection_holder(std::uint64_t pid, unsigned local_port,
                                          unsigned remote_port) {
    std::vector<unsigned char> data;

    if (const auto read = tcp_table(TCP_TABLE_OWNER_PID_CONNECTIONS, data);
        read != LoopbackHolder::owner) {
        return read;
    }

    const auto *table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(data.data());

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];

        // A row in transition may have no owning process yet.
        if (row.dwLocalAddr != htonl(INADDR_LOOPBACK) ||
            row.dwRemoteAddr != htonl(INADDR_LOOPBACK) || row.dwState != MIB_TCP_STATE_ESTAB ||
            ntohs(static_cast<u_short>(row.dwLocalPort)) != local_port ||
            ntohs(static_cast<u_short>(row.dwRemotePort)) != remote_port || !row.dwOwningPid) {
            continue;
        }

        return row.dwOwningPid == pid ? LoopbackHolder::owner : LoopbackHolder::foreign;
    }

    return LoopbackHolder::absent;
}
} // namespace voyemu::os
