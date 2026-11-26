#include "media_discovery.hpp"
#include "model.hpp"
#include "os/platform.hpp"
#include "process.hpp"
#include "session_internal.hpp"
#include <cassert>
#include <exception>
#include <iostream>
#include <sys/stat.h>
using namespace voyemu;

static std::ofstream descriptor_output(const std::filesystem::path &path) {
    // Windows can assign the token default owner instead of the current user.
    if (os::host_windows && !std::filesystem::exists(path)) {
        assert(os::create_private_file(path));
    }

    return std::ofstream(path);
}

static void warm_sdk_descriptor_binding() {
    const auto root = std::filesystem::current_path() / ".local/build/tmp" /
                      ("voyemu-sdk-warm-" + random_token());

    ensure_private_directory(root);
    const auto saved = root / "private";
    ensure_private_directory(saved);
    const auto log = root / "android.log", source = root / "pid_987.ini",
               target = saved / source.filename();
    const std::string descriptor =
            "grpc.port=45992\nport.serial=5566\ngrpc.token=private-fixture-token\n";
    {
        descriptor_output(source) << descriptor;
        std::ofstream(log) << "Advertising in: " << source.string() << '\n';
    }
    SdkDescriptorCache cache;
    assert(!cache.authenticated() && cache.bearer().empty());
    assert(cache.resolve(log, root, saved, 987, 5566, 45992, false) == target &&
           cache.authenticated() && cache.bearer() == "private-fixture-token");
    { std::ofstream(log, std::ios::app) << std::string(600000, 'x') << '\n'; }
    assert(std::filesystem::file_size(log) > 512 * 1024 && !sdk_discovery(log, root, 987));
    assert(sdk_discovery(log, root, 987, false, SdkAdvertisementWindow::startup) == source);
    assert(!sdk_discovery(log, root, 988, false, SdkAdvertisementWindow::startup));
    assert(!sdk_discovery(log, saved, 987, false, SdkAdvertisementWindow::startup));
    const auto truncated = root / "truncated.log";
    const std::string advertisement = "Advertising in: " + source.string();
    {
        std::ofstream output(truncated);
        output << std::string(512 * 1024 - advertisement.size(), 'x') << advertisement << 'x'
               << '\n';
    }
    assert(!sdk_discovery(truncated, root, 987, false, SdkAdvertisementWindow::startup));

    // A guest warm reboot keeps this SDK launch, but its nonce must be verified again.
    assert(!cache.resolve(log, root, saved, 987, 5566, 45992, false));
    assert(cache.resolve(log, root, saved, 987, 5566, 45992, true) == target);
    auto rejected = [&](unsigned pid, unsigned serial, unsigned grpc) {
        bool blocked = false;
        try {
            cache.resolve(log, root, saved, pid, serial, grpc, true);
        } catch (const std::exception &) {
            blocked = true;
        }

        assert(blocked);
    };
    rejected(988, 5566, 45992);
    rejected(987, 5568, 45992);
    rejected(987, 5566, 45993);
    // Replacing the original source cannot replace the already authenticated token.
    std::filesystem::rename(source, root / "original");
    {
        auto changed = descriptor;
        changed.replace(changed.find("private-fixture-token"), 21, "changed-fixture-token");
        descriptor_output(source) << changed;
    }
    rejected(987, 5566, 45992);
    assert(cache.bearer() == "private-fixture-token");
    std::filesystem::remove(source);
    std::filesystem::rename(root / "original", source);
    assert(cache.resolve(log, root, saved, 987, 5566, 45992, true) == target);
    std::filesystem::create_hard_link(source, root / "alias");
    rejected(987, 5566, 45992);
    std::filesystem::remove(root / "alias");

    // Windows guards the descriptor with ACLs, and links need a privilege there.
    if (!voyemu::os::host_windows) {
        std::filesystem::rename(source, root / "original");
        std::filesystem::create_symlink(root / "original", source);
        assert(!cache.resolve(log, root, saved, 987, 5566, 45992, true));
        std::filesystem::remove(source);
        std::filesystem::rename(root / "original", source);
        std::filesystem::permissions(target, std::filesystem::perms::owner_read |
                                                     std::filesystem::perms::owner_write |
                                                     std::filesystem::perms::group_read |
                                                     std::filesystem::perms::others_read);
        rejected(987, 5566, 45992);
        std::filesystem::permissions(target, std::filesystem::perms::owner_read |
                                                     std::filesystem::perms::owner_write);
    }

    std::filesystem::create_hard_link(target, saved / "alias");
    rejected(987, 5566, 45992);
    std::filesystem::remove(saved / "alias");
    // Cold SDK launches, including PID reuse, cannot adopt a private copy without discovery.
    cache.reset();
    assert(!cache.authenticated() && cache.bearer().empty());
    assert(!cache.resolve(log, root, saved, 987, 5566, 45992, true) && !cache.authenticated());
    { std::ofstream(log) << "Advertising in: " << source.string() << '\n'; }
    assert(cache.resolve(log, root, saved, 987, 5566, 45992, false) == target);
    std::filesystem::remove(target);
    rejected(987, 5566, 45992);
    assert(!std::filesystem::exists(target));
    std::filesystem::remove_all(root);
}

int main() try {
    warm_sdk_descriptor_binding();

    {
        // The session looks for the registration where its SDK child writes it.
        const auto session = std::filesystem::absolute("isolated-session");
        ProcessSpec sdk;
        android_session_environment(sdk, session);
        const std::filesystem::path root =
                sdk.environment.at(std::string(os::sdk_discovery_root_variable));
        assert(session_detail::session_sdk_registration_directory(session, false) ==
               root / (os::platform_name == "macOS" ? "Library/Caches/TemporaryItems/avd/running"
                       : os::host_windows           ? "Temp/avd/running"
                                                    : "avd/running"));
        assert(os::platform_name != "Linux" || root == session / "tmp");
    }

    const auto os_root = std::filesystem::absolute("sdk-user"),
               home = std::filesystem::absolute("project/emulator-home");
    assert(sdk_registration_directory(os_root, home) ==
           os_root / (voyemu::os::platform_name == "macOS"
                              ? "Library/Caches/TemporaryItems/avd/running"
                      : voyemu::os::host_windows ? "Temp/avd/running"
                                                 : "avd/running"));
    assert(sdk_registration_directory({}, home) == home / "avd/running");
    bool relative_rejected = false;
    try {
        sdk_registration_directory("relative", home);
    } catch (...) {
        relative_rejected = true;
    }

    assert(relative_rejected);
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-sdk-discovery-" + random_token());
    ensure_private_directory(root);
    auto log = root / "android.log", descriptor = root / "pid_123.ini";
    { descriptor_output(descriptor) << "grpc.port=45992\n"; }
    auto advertise = [&](const std::filesystem::path &path) {
        std::ofstream(log) << "INFO | Advertising in: " << path.string() << '\n';
    };
    advertise(descriptor);
    assert(sdk_discovery(log, root, 123) == descriptor);
    assert(!sdk_discovery(log, root, 124));
    advertise(root / "../pid_123.ini");
    assert(!sdk_discovery(log, root, 123));
    {
        std::ofstream(log) << std::string(600000, 'x')
                           << "\nAdvertising in: " << descriptor.string() << '\n';
    }
    assert(sdk_discovery(log, root, 123) == descriptor);
    auto other = root / "other";
    ensure_private_directory(other);
    {
        descriptor_output(other / "pid_123.ini") << "grpc.port=45992\n";
        std::ofstream(log) << "Advertising in: " << descriptor.string()
                           << "\nAdvertising in: " << (other / "pid_123.ini").string() << '\n';
    }
    assert(!sdk_discovery(log, root, 123));
    advertise(descriptor);
    std::filesystem::resize_file(descriptor, 32769);
    assert(!sdk_discovery(log, root, 123));
    std::filesystem::resize_file(descriptor, 0);
    assert(!sdk_discovery(log, root, 123));
    { descriptor_output(descriptor) << "fixture"; }
    std::filesystem::create_hard_link(descriptor, root / "alias");
    assert(!sdk_discovery(log, root, 123));
    std::filesystem::remove(root / "alias");

    // Creating a symbolic link needs a privilege on Windows.
    if (!voyemu::os::host_windows) {
        std::filesystem::remove(descriptor);
        std::filesystem::create_symlink(other / "pid_123.ini", descriptor);
        assert(!sdk_discovery(log, root, 123));
    }

    auto source = root / "pid_987.ini", target = other / "pid_987.ini";
    {
        descriptor_output(source)
                << "grpc.port=45992\nport.serial=5566\ngrpc.token=private-fixture-token\n";
    }
    assert(import_sdk_descriptor(source, target, 987, 5566, 45992) == target);
    assert(std::filesystem::exists(source));
    assert(import_sdk_descriptor(source, target, 987, 5566, 45992) ==
           target); // Guest reboot keeps the same SDK process and descriptor.
    {
        descriptor_output(source)
                << "grpc.port=45992\nport.serial=5566\ngrpc.token=changed-private-fixture-token\n";
    }
    bool blocked = false;
    try {
        import_sdk_descriptor(source, target, 987, 5566, 45992);
    } catch (const std::exception &) {
        blocked = true;
    }

    assert(blocked);
    {
        descriptor_output(source)
                << "grpc.port=45992\nport.serial=5566\ngrpc.token=private-fixture-token\n";
    }

    // Windows guards the descriptor with ACLs, not mode bits.
    if (!voyemu::os::host_windows) {
        std::filesystem::permissions(target, std::filesystem::perms::owner_read |
                                                     std::filesystem::perms::owner_write |
                                                     std::filesystem::perms::group_read |
                                                     std::filesystem::perms::others_read);
        blocked = false;
        try {
            import_sdk_descriptor(source, target, 987, 5566, 45992);
        } catch (const std::exception &) {
            blocked = true;
        }

        assert(blocked);
        std::filesystem::permissions(target, std::filesystem::perms::owner_read |
                                                     std::filesystem::perms::owner_write);
    }

    std::filesystem::create_hard_link(target, other / "descriptor-alias");
    blocked = false;
    try {
        import_sdk_descriptor(source, target, 987, 5566, 45992);
    } catch (const std::exception &) {
        blocked = true;
    }

    assert(blocked);
    std::filesystem::remove(other / "descriptor-alias");
    std::filesystem::remove(target);
    blocked = false;
    try {
        import_sdk_descriptor(source, target, 987, 5566, 45993);
    } catch (const std::exception &) {
        blocked = true;
    }

    assert(blocked && !std::filesystem::exists(target));
    { descriptor_output(source) << "grpc.port=45992\nport.serial=5566\n"; }
    assert(!import_sdk_descriptor(source, target, 987, 5566, 45992));

    // Windows guards the descriptor with ACLs, not mode bits.
    if (!voyemu::os::host_windows) {
        {
            descriptor_output(source)
                    << "grpc.port=45992\nport.serial=5566\ngrpc.token=private-fixture-token\n";
        }
        assert(import_sdk_descriptor(source, target, 987, 5566, 45992));
        assert((std::filesystem::status(target).permissions() &
                (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
               std::filesystem::perms::none);
    }

    std::filesystem::remove_all(root);
    std::cout
            << "SDK discovery retained PID/project boundary/tail extent/alias/ambiguity guards passed\n";
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
