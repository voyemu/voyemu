#include "os/audio.hpp"

namespace voyemu::os {
EmulatorAudioOutput emulator_audio_output() {
    return {.driver = "dsound"};
}
} // namespace voyemu::os
