#pragma once
#include <map>
#include <string>

namespace voyemu::os {
// The playback route of the QEMU of the Android Emulator on this host. driver is a QEMU audio
// driver and environment carries its settings; full_engine asks for the SDK engine with a window
// because its headless engine lacks the driver. unavailable is empty when the host can play, and
// otherwise "no_server" or "unsupported_server"; detail names the socket or value that decided.
struct EmulatorAudioOutput {
    std::string driver;
    std::map<std::string, std::string> environment;
    bool full_engine{};
    std::string unavailable;
    std::string detail;
};

EmulatorAudioOutput emulator_audio_output();
} // namespace voyemu::os
