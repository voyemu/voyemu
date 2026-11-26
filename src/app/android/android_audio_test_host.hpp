#pragma once
// The host part of android_audio.test.cpp: android_audio_posix.test.cpp and
// android_audio_windows.test.cpp.
#include <filesystem>

// Wine reports its Z:\ drive root as a reparse point; a session directory reached through that
// drive is still an ordinary owned path below the volume root. Nothing to check on POSIX.
void wine_volume_root_case(const std::filesystem::path &directory);
