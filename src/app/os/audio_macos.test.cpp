#include "os/audio.hpp"
#include <iostream>

int main() {
    const auto output = voyemu::os::emulator_audio_output();

    // Core Audio plays in the headless engine and needs no settings.
    if (output.driver != "coreaudio" || output.full_engine || !output.unavailable.empty() ||
        !output.environment.empty()) {
        std::cerr << "macOS playback route differs\n";

        return 1;
    }

    std::cout << "macOS playback route passed\n";

    return 0;
}
