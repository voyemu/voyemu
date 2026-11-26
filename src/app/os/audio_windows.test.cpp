#include "os/audio.hpp"
#include <iostream>

int main() {
    const auto output = voyemu::os::emulator_audio_output();

    // DirectSound plays in the headless engine and needs no settings.
    if (output.driver != "dsound" || output.full_engine || !output.unavailable.empty() ||
        !output.environment.empty()) {
        std::cerr << "Windows playback route differs\n";

        return 1;
    }

    std::cout << "Windows playback route passed\n";

    return 0;
}
