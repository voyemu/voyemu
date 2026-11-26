#include "os/audio.hpp"

namespace voyemu::os {
EmulatorAudioOutput emulator_audio_output() {
    return {.driver = "coreaudio"};
}
} // namespace voyemu::os
