#include "core/process.hpp"
#include "model.hpp"
#include "os/audio.hpp"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
using namespace voyemu;
namespace fs = std::filesystem;

static void check(bool ok, const char *message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}

// Unavailable playback is a route to the none driver with a reason, never an error.
static void expect_unavailable(const char *reason, const std::string &detail, const char *message) {
    const auto output = os::emulator_audio_output();

    check(output.driver == "none" && output.unavailable == reason && output.detail == detail &&
                  output.environment.empty() && !output.full_engine,
          message);
}

int main() try {
    // sun_path holds about 100 bytes, so the socket lives below the short system temporary
    // directory rather than below the build tree.
    const auto fixture = fs::temp_directory_path() /
                         ("voyemu-pulse-" + random_token().substr(0, 8));

    ensure_private_directory(fixture / "pulse");
    struct Cleanup {
        fs::path fixture;
        int fd = -1;

        ~Cleanup() {
            if (fd >= 0) {
                ::close(fd);
            }

            std::error_code error;
            fs::remove_all(fixture, error);
        }
    } cleanup{fixture};
    const auto pathname = (fixture / "pulse/native").string();
    const auto server = "unix:" + pathname;
    check(::unsetenv("PULSE_SERVER") == 0 && ::unsetenv("XDG_RUNTIME_DIR") == 0,
          "clear the PulseAudio environment");
    expect_unavailable("no_server", "", "no desktop runtime directory selected a socket");
    check(::setenv("XDG_RUNTIME_DIR", fixture.c_str(), 1) == 0, "set desktop runtime fixture");
    expect_unavailable("no_server", pathname, "a missing desktop socket played");
    check(::setenv("PULSE_SERVER", server.c_str(), 1) == 0, "select missing explicit socket");
    expect_unavailable("no_server", pathname, "a missing explicit socket played");

    for (const auto *value : {"tcp:127.0.0.1:4713", "relative/native", "unix:relative/native",
                              "{id}unix:/run/pulse/native", "unix:/a/native unix:/b/native"}) {
        check(::setenv("PULSE_SERVER", value, 1) == 0, "set unsupported PulseAudio address");
        expect_unavailable("unsupported_server", value,
                           "a nonlocal or ambiguous PulseAudio address played");
    }

    const auto nonsocket = fixture / "not-a-socket";
    std::ofstream(nonsocket) << "ordinary file";
    const auto file_server = "unix:" + nonsocket.string();
    check(::setenv("PULSE_SERVER", file_server.c_str(), 1) == 0, "select an ordinary file");
    expect_unavailable("unsupported_server", file_server, "an ordinary file played");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    check(pathname.size() < sizeof(address.sun_path), "PulseAudio fixture path too long");
    std::memcpy(address.sun_path, pathname.c_str(), pathname.size() + 1);
    cleanup.fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    check(cleanup.fd >= 0 && ::bind(cleanup.fd, reinterpret_cast<const sockaddr *>(&address),
                                    sizeof(address)) == 0,
          "bind fixture PulseAudio socket without listening");
    check(::setenv("PULSE_SERVER", server.c_str(), 1) == 0, "select stale explicit socket");
    expect_unavailable("no_server", pathname, "a stale explicit socket played");
    check(::unsetenv("PULSE_SERVER") == 0, "select stale desktop socket");
    expect_unavailable("no_server", pathname, "a stale desktop socket played");
    check(::listen(cleanup.fd, 4) == 0, "listen on fixture PulseAudio socket");

    for (const auto &value : {std::string{}, server, pathname}) {
        if (value.empty()) {
            check(::unsetenv("PULSE_SERVER") == 0, "select the desktop socket");
        } else {
            check(::setenv("PULSE_SERVER", value.c_str(), 1) == 0, "select the explicit socket");
        }

        const auto output = os::emulator_audio_output();
        check(output.driver == "pa" && output.unavailable.empty() && output.full_engine &&
                      output.detail == pathname &&
                      output.environment ==
                              std::map<std::string, std::string>{{"PULSE_SERVER", server},
                                                                 {"QEMU_AUDIO_ADC_VOICES", "0"}},
              "a listening socket plays through PulseAudio on the full engine without capture");
    }

    check(::unsetenv("PULSE_SERVER") == 0, "clear explicit PulseAudio fixture");
    std::cout << "Linux PulseAudio route passed\n";

    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
