#include "os/audio.hpp"
#include "os/socket.hpp"
#include <cstdlib>
#include <filesystem>
#include <string_view>
#include <system_error>

namespace voyemu::os {
// PulseAudio or pipewire-pulse on the local socket of PULSE_SERVER, or else on the desktop socket;
// only the full SDK engine links libpulse.
EmulatorAudioOutput emulator_audio_output() {
    const char *server = std::getenv("PULSE_SERVER");
    std::string socket;

    if (server && *server) {
        const std::string_view address(server);
        constexpr std::string_view prefix = "unix:";
        socket = address.starts_with(prefix) ? address.substr(prefix.size()) : address;
        std::error_code error;
        const auto status = std::filesystem::status(socket, error);

        // A TCP address, a server list, a relative path or another file is no local socket.
        if (!socket.starts_with('/') || address.find_first_of(" \t\n\r\f\v") != address.npos ||
            (std::filesystem::exists(status) && !std::filesystem::is_socket(status))) {
            return {.driver = "none", .unavailable = "unsupported_server", .detail = server};
        }
    } else if (const char *runtime = std::getenv("XDG_RUNTIME_DIR"); runtime && *runtime) {
        socket = (std::filesystem::path(runtime) / "pulse/native").string();
    }

    if (!socket.starts_with('/') || socket.find_first_of(" \t\n\r\f\v") != socket.npos ||
        !unix_socket_listening(socket)) {
        return {.driver = "none", .unavailable = "no_server", .detail = socket};
    }

    return {.driver = "pa",
            .environment = {{"PULSE_SERVER", "unix:" + socket}, {"QEMU_AUDIO_ADC_VOICES", "0"}},
            .full_engine = true,
            .detail = socket};
}
} // namespace voyemu::os
