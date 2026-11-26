#include "android_audio.hpp"
#include "android_audio_test_host.hpp"
#include "os/fs.hpp"
#include "wine_native_backend_windows.hpp"
#include <stdexcept>

void wine_volume_root_case(const std::filesystem::path &directory) {
    using namespace voyemu;

    if (os::reparse_point("Z:\\")) {
        const auto mapped =
                std::filesystem::path("Z:") /
                std::filesystem::path(wine_native_unix_path(directory)).make_preferred();
        ProcessSpec mapped_capture;
        configure_android_audio(mapped_capture, true, os::EmulatorAudioOutput{.driver = "dsound"},
                                "wav", mapped, 7);

        if (mapped_capture.environment.at("QEMU_WAV_PATH") !=
            (mapped / "android-audio-g7.wav").string()) {
            throw std::runtime_error("volume root reparse point rejected an owned session");
        }
    }
}
