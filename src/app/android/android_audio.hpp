#pragma once
#include "check.hpp"
#include "model.hpp"
#include "os/audio.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include <algorithm>
#include <stdexcept>
namespace voyemu {
// playing reaches the host, unavailable keeps the guest device on the none driver, disabled has no
// guest audio device and diagnostic writes the session WAV.
enum class AndroidAudioState {
    playing,
    unavailable,
    disabled,
    diagnostic
};

// The output that configure_android_audio set up: the QEMU driver, whether the SDK engine needs
// its window for it, and for unavailable output the reason and detail of the host backend.
struct AndroidAudioRoute {
    AndroidAudioState state{};
    std::string driver;
    bool full_engine{};
    std::string reason, detail;
};

inline bool android_audio_output_enabled(const Json &specification) {
    if (specification.contains("audioOutput") && !specification.at("audioOutput").is_boolean()) {
        throw VoyemuError("ANDROID_AUDIO_MODE", "boolean audioOutput required");
    }

    return specification.value("audioOutput", false);
}

// The caller validates its owned directory before selecting these private files.
inline void configure_android_wav_audio(ProcessSpec &process, const std::filesystem::path &wave,
                                        const std::filesystem::path &input) {
    const auto reject = [](bool accepted, const char *why) {
        if (!accepted) {
            throw VoyemuError("ANDROID_AUDIO_DIAGNOSTIC", why);
        }
    };

    reject(std::none_of(process.arguments.begin(), process.arguments.end(),
                        [](const auto &arg) {
                            return arg == "-audio" || arg == "-no-audio" || arg == "-noaudio" ||
                                   arg == "-no_audio" || arg == "-allow-host-audio" ||
                                   arg == "-allow_host_audio";
                        }),
           "incoming audio override rejected");
    reject(wave.is_absolute() && input.is_absolute() && wave != input,
           "distinct absolute WAV paths required");

    for (const auto &file : {wave, input}) {
        reject(!std::filesystem::exists(file) && !std::filesystem::is_symlink(file),
               "fresh private WAV paths required");
    }

    process.environment["QEMU_AUDIO_DRV"] = "wav";
    process.environment["QEMU_AUDIO_OUT_DRV"] = "wav";
    process.environment["QEMU_AUDIO_IN_DRV"] = "none";
    process.environment["QEMU_AUDIO_ADC_VOICES"] = "0";
    process.environment["QEMU_WAV_PATH"] = wave.string();
    process.environment["QEMU_WAV_IN_PATH"] = input.string();
    process.environment["QEMU_WAV_FREQUENCY"] = "44100";
    process.environment["QEMU_WAV_FORMAT"] = "S16";
    process.environment["QEMU_WAV_DAC_FIXED_CHANNELS"] = "2";
    process.arguments.insert(process.arguments.end(), {"-audio", "wav"});
}

// Applies the output of the guest: the host route, the none driver when the host cannot play, or
// the WAV diagnostic. Never reads the environment and never changes the window arguments.
inline AndroidAudioRoute configure_android_audio(ProcessSpec &process, bool output,
                                                 const os::EmulatorAudioOutput &host,
                                                 const Json &diagnostic = nullptr,
                                                 const std::filesystem::path &session = {},
                                                 unsigned generation = 0) {
    if (!diagnostic.is_null()) {
        const auto reject = [](bool accepted, const char *why) {
            if (!accepted) {
                throw VoyemuError("ANDROID_AUDIO_DIAGNOSTIC", why);
            }
        };
        reject(output && diagnostic.is_string() && diagnostic == "wav",
               "exact enabled WAV opt-in required");
        reject(std::none_of(process.arguments.begin(), process.arguments.end(),
                            [](const auto &arg) {
                                return arg == "-audio" || arg == "-no-audio" || arg == "-noaudio" ||
                                       arg == "-no_audio" || arg == "-allow-host-audio" ||
                                       arg == "-allow_host_audio";
                            }),
               "incoming audio override rejected");
        const auto id = session.filename().string();
        reject(generation > 0 && session.is_absolute() && session.lexically_normal() == session &&
                       std::filesystem::canonical(session) == session &&
                       std::filesystem::is_directory(session) && hex_text(id, 32) &&
                       session.parent_path().filename() == "sessions",
               "owned canonical session directory required");

        for (const auto &path : os::ancestors(session)) {
            reject(!os::reparse_point(path), "session reparse path rejected");
            reject(!std::filesystem::is_symlink(std::filesystem::symlink_status(path)),
                   "session symlink path rejected");
        }

        const auto wave = session / ("android-audio-g" + std::to_string(generation) + ".wav"),
                   input = session / ("android-no-input-g" + std::to_string(generation) + ".wav");
        configure_android_wav_audio(process, wave, input);

        return {AndroidAudioState::diagnostic, "wav"};
    }

    if (!output) {
        process.arguments.push_back("-no-audio");

        return {AndroidAudioState::disabled};
    }

    // An unavailable host keeps the guest audio device and its snapshot on the none driver.
    AndroidAudioRoute route{AndroidAudioState::unavailable, "none", false, host.unavailable,
                            host.detail};

    if (host.unavailable.empty()) {
        route = {AndroidAudioState::playing, host.driver, host.full_engine, {}, host.detail};

        for (const auto &[key, value] : host.environment) {
            process.environment[key] = value;
        }
    }

    // SDK documents directional backends. Never open a host recording device.
    process.environment["QEMU_AUDIO_DRV"] = route.driver;
    process.environment["QEMU_AUDIO_OUT_DRV"] = route.driver;
    process.environment["QEMU_AUDIO_IN_DRV"] = "none";

    // -allow-host-audio is deliberately absent; guest input remains silent.
    return route;
}

// The audio delivery of the session status: deliveries.android.audio.
inline Json android_audio_delivery(const AndroidAudioRoute &route) {
    static constexpr const char *states[] = {"playing", "unavailable", "disabled", "diagnostic"};

    return {{"state", states[static_cast<int>(route.state)]},
            {"driver", route.driver},
            {"reason", route.reason},
            {"detail", route.detail}};
}
} // namespace voyemu
