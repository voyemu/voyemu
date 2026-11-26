#include "cli_arguments.hpp"
#include "help.hpp"
#include "os/platform.hpp"
#include "os/process.hpp"
#include <cassert>
#include <cstdlib>
#include <exception>
#include <iostream>
using namespace voyemu;

int main(int argc, char **argv) try {
    assert(argc == 2);
    const auto root = std::filesystem::canonical(argv[1]) / ".local/build/tmp" /
                      ("cli-arguments-" + random_token());
    // Parsing never reads profiles/, so a synthetic identifier stands for any profile.
    const std::string profile = "synthetic-profile";
    ensure_private_directory(root / ".local/machines");
    const auto machine = root / "machines" / profile;
    ensure_private_directory(machine);
    write_private_json(machine / "runtime.json",
                       {{"schema", 1}, {"kind", "portable-guest-runtime"}, {"profile", profile}});
    const auto variant = root / "machines/variant";
    ensure_private_directory(variant);
    write_private_json(variant / "runtime.json", read_private_json(machine / "runtime.json"));
    const auto executable = root / ("voyemu" + std::string(voyemu::os::executable_suffix));
    auto parse = [&](std::vector<std::string> words) {
        words.insert(words.begin(), executable.string());
        std::vector<char *> pointers;

        for (auto &word : words) {
            pointers.push_back(word.data());
        }

        return cli::parse(static_cast<int>(pointers.size()), pointers.data(), executable);
    };
    auto reject = [&](std::vector<std::string> words, const char *code) {
        bool failed = false;
        try {
            parse(std::move(words));
        } catch (const std::exception &error) {
            failed = std::string(error.what()).starts_with(code);
        }

        assert(failed);
    };

    for (const auto *command : {"start", "restart", "status", "stop", "check", "patch"}) {
        std::vector<std::string> words{command, machine.string()};

        if (std::string(command) == "patch") {
            words.insert(words.end(), {"--values", "{\"speed\":80}"});
        }

        const auto result = parse(words);
        assert(result.command == command && result.profile == profile &&
               result.machine.name == profile && result.machine.selected &&
               result.machine_path == machine && result.root == root);
        reject({command}, "MACHINE_PATH:");
        reject({command, machine.string(), variant.string()}, "MACHINE_PATH:");

        for (const auto *flag : {"--profile", "--machine", "--root"}) {
            reject({command, machine.string(), flag, "other"}, "CLI_ARGUMENT:");
        }
    }

    const auto external = root / "outside machines/arbitrary-seed";
    ensure_private_directory(external);
    write_private_json(external / "runtime.json", read_private_json(machine / "runtime.json"));
    const auto relative = parse(
            {"status", external.lexically_relative(std::filesystem::current_path()).string()});
    assert(relative.machine_path == external &&
           relative.machine.name == external.filename().string());
    const MachinePathSelection canonical{machine, profile}, other{variant, profile};
    assert(machine_selector_matches(root, canonical, "") &&
           machine_selector_matches(root, canonical, profile) &&
           !machine_selector_matches(root, canonical, "foreign"));
    const Json canonical_api{{"machine", profile}, {"machine_seed", machine.string()}};
    assert(machine_session_matches(root, canonical, canonical_api) &&
           machine_session_matches(root, canonical, Json::object()) &&
           !machine_session_matches(root, other, canonical_api) &&
           !machine_session_matches(root, other, Json::object()));
    assert(!machine_session_matches(root, canonical, Json{{"machine", profile}}));
    assert(!parse({"start", machine.string()}).verbose);
    assert(parse({"start", machine.string(), "--verbose"}).verbose);
    reject({"start", machine.string(), "--verbose", "--verbose"}, "CLI_ARGUMENT:");
    reject({"status", machine.string(), "--verbose"}, "CLI_ARGUMENT:");
    reject({"stop", machine.string(), "--verbose"}, "CLI_ARGUMENT:");
    assert(parse({"restart", machine.string(), "--verbose"}).verbose);
    assert(parse({"deps", "--verbose"}).verbose);
    assert(parse({"fetch", profile, "--verbose"}).verbose);
    assert(parse({"build", profile, "--verbose"}).verbose);
    const auto signed_release = root / "signed release";
    const auto trusted_key = root / "trusted-public.pem";
    const std::string trusted_spki(64, 'a');
    const std::vector<std::string> signed_options{
            "--signed-android",   signed_release.string(),       "--android-public-key",
            trusted_key.string(), "--android-public-key-sha256", trusted_spki};
    std::vector<std::string> signed_build{"build", profile, "--cluster=off"};
    signed_build.insert(signed_build.end(), signed_options.begin(), signed_options.end());
    const auto signed_result = parse(signed_build);

    if (signed_result.command != "build" ||
        signed_result.signed_android.release != signed_release ||
        signed_result.signed_android.public_key != trusted_key ||
        signed_result.signed_android.spki_sha256 != trusted_spki) {
        throw std::runtime_error("signed Android build options were not accepted");
    }

    reject({"build", profile, "--cluster=off", "--signed-android", signed_release.string()},
           "CLI_ARGUMENT:");
    auto other_command = std::vector<std::string>{"fetch", profile};
    other_command.insert(other_command.end(), signed_options.begin(), signed_options.end());
    reject(other_command, "CLI_ARGUMENT:");
    auto cluster_build = signed_build;
    cluster_build[2] = "--cluster=on";
    reject(cluster_build, "CLI_ARGUMENT:");
    auto invalid_pin = signed_build;
    invalid_pin.back() = "bad";
    reject(invalid_pin, "CLI_ARGUMENT:");
    const auto selected = parse({"start", variant.string(), "--cluster=on", "--multimedia=off"});
    assert(selected.machine.name == "variant" && selected.cluster && !selected.multimedia);
    const auto media = parse({"restart", machine.string(), "--cluster=off", "--multimedia=on"});
    assert(!media.cluster && media.multimedia);
    reject({"start", machine.string(), "--cluster=off", "--multimedia=off"}, "CLI_ARGUMENT:");

    for (const auto *flag :
         {"--cluster=maybe", "--multimedia=false", "--with-cluster", "--no-cluster"}) {
        reject({"start", machine.string(), flag}, "CLI_ARGUMENT:");
    }

    reject({"start", machine.string(), "--cluster=on", "--cluster=off"}, "CLI_ARGUMENT:");
    reject({"status", machine.string(), "--background"}, "CLI_ARGUMENT:");
    reject({"check", machine.string(), "--seconds", "2"}, "CLI_ARGUMENT:");
    assert(!parse({"start", machine.string()}).network);
    assert(parse({"start", machine.string(), "--network=yes"}).network);
    reject({"start", machine.string(), "--network=maybe"}, "CLI_ARGUMENT:");
    reject({"start", machine.string(), "--network="}, "CLI_ARGUMENT:");
    reject({"start", machine.string(), "--network", "yes"}, "CLI_ARGUMENT:");
    reject({"status", machine.string(), "--network=no"}, "CLI_ARGUMENT:");
    const auto off = parse({"start", machine.string(), "--network=no"});
    assert(off.network_explicit);
    reject({"start", machine.string(), "--network=yes", "--network=no"}, "CLI_ARGUMENT:");

    for (const auto *command : {"fetch", "build"}) {
        const auto result = parse({command, profile, "--offline"});
        assert(result.profile == profile && result.profile_explicit && result.offline);
        reject({command}, "PROFILE_NAME:");
        reject({command, profile, "machines/nested/second"}, "CLI_ARGUMENT:");
    }

    const auto archive = root / "owner update.zip";
    const auto source = "--source=" + archive.string();
    const auto retained = parse({"fetch", profile});
    assert(retained.update.empty() && retained.serial.empty());
    const auto local = parse({"fetch", profile, source, "--offline"});
    assert(local.update == archive && local.serial.empty() && local.offline);
    const auto device = parse({"fetch", profile, "--serial", "vehicle-123", "--source=adb"});
    assert(device.update.empty() && device.serial == "vehicle-123");
    // A relative path starts at the current directory, ~/ at the home directory, and links
    // resolve, so the archive reaches fetch as its real absolute path.
    const auto fetched = [&](const std::string &value) {
        return parse({"fetch", profile, "--source=" + value}).update;
    };
    const auto saved_directory = std::filesystem::current_path();
    ensure_private_directory(root / "downloads");
    std::filesystem::current_path(root / "downloads");
    assert(fetched("owner update.zip") == root / "downloads/owner update.zip");
    assert(fetched("../owner update.zip") == archive);
    assert(fetched("nested/../owner.zip") == root / "downloads/owner.zip");
    const auto relative_tools =
            parse({"build", "free-11-chinese-20260731-7.3.1", "--reuse-qnx", "../acceptance.json",
                   "--reuse-qnx-sha256", std::string(64, 'a'), "--jdk", "jdk"});
    assert(relative_tools.reuse_qnx == root / "acceptance.json" &&
           relative_tools.jdk == root / "downloads/jdk");
    assert(parse({"start", machine.string(), "--provider", "provider.json"}).providers ==
           std::vector<std::filesystem::path>{root / "downloads/provider.json"});
    assert(parse({"test", "--request", "request.json"}).request_file ==
                   root / "downloads/request.json" &&
           parse({"test", "--request", "-"}).request_file == "-");
    std::filesystem::current_path(saved_directory);
    const char *home_variable = voyemu::os::host_windows ? "USERPROFILE" : "HOME";
    const auto *saved_home = std::getenv(home_variable);
    const std::string previous_home = saved_home ? saved_home : "";
    const auto set_home = [&](const std::string &value) {
        voyemu::os::set_environment_variable(home_variable, value);
    };
    set_home(root.string());
    assert(fetched("~/owner update.zip") == archive);
    set_home("relative-home");
    reject({"fetch", profile, "--source=~/owner update.zip"}, "USER_HOME:");
    set_home(previous_home);
    const auto real = root / "real";
    ensure_private_directory(real);
    write_private_json(real / "owner.zip", Json::object());
    std::filesystem::create_directory_symlink(real, root / "linked");
    assert(fetched((root / "linked/owner.zip").string()) == real / "owner.zip");
    assert(fetched((root / "linked/absent.zip").string()) == real / "absent.zip");

    // Creating a file symbolic link needs a privilege on Windows.
    if (!voyemu::os::host_windows) {
        std::filesystem::create_symlink(real / "owner.zip", root / "linked.zip");
        assert(fetched((root / "linked.zip").string()) == real / "owner.zip");
    }

    for (const auto &options : std::vector<std::vector<std::string>>{
                 {"fetch", profile, "--source=adb"},
                 {"fetch", profile, "--source=adb", "--serial", ""},
                 {"fetch", profile, "--source="},
                 {"fetch", profile, "--source", "adb"},
                 {"fetch", profile, "--serial", "vehicle-123"},
                 {"fetch", profile, source, "--serial", "vehicle-123"},
                 {"fetch", profile, source, "--source=adb", "--serial", "vehicle-123"},
                 {"fetch", profile, "--source=adb", "--serial", "vehicle-123", "--serial", "other"},
                 {"fetch", profile, "--update", archive.string()},
                 {"deps", profile, source},
                 {"deps", profile, "--source=adb", "--serial", "vehicle-123"},
         }) {
        reject(options, "CLI_ARGUMENT:");
    }

    const auto destination = root / "machines/second-build";

    for (const auto &path : {std::string("machines/second-build"), destination.string()}) {
        const auto result = parse({"build", profile, path, "--cluster=off", "--offline"});
        assert(result.profile == profile && result.machine.name == "second-build" &&
               result.machine_path.empty() && !result.cluster && result.offline);
    }

    const auto unnamed_build = parse({"build", profile});
    assert(unnamed_build.machine.name == profile && !unnamed_build.machine.selected &&
           unnamed_build.machine.selector().empty());
    assert(parse({"build", profile, "--target=x86"}).build_target == "x86");
    assert(parse({"build", "--target=arm", profile, "machines/second-build"}).build_target ==
           "arm");
    // Any name the profile declares selects a target; the profile decides which exist.
    assert(parse({"deps", profile, "--target=synthetic-target"}).build_target ==
           "synthetic-target");
    reject({"build", profile, "--target="}, "CLI_ARGUMENT:");
    reject({"build", profile, "--target=../escape"}, "CLI_ARGUMENT:");
    reject({"build", profile, "--target=x86", "--target=arm"}, "CLI_ARGUMENT:");
    reject({"fetch", profile, "--target=x86"}, "CLI_ARGUMENT:");

    for (const auto &path : {machine.string(), variant.string(), (root / "outside-new").string(),
                             std::string("machines/nested/new"), std::string("machines/../escape"),
                             std::string("machines/second-build/")}) {
        reject({"build", profile, path}, "CLI_ARGUMENT:");
    }

    // An existing machine is named as such; only build --force selects it.
    reject({"build", profile, variant.string()},
           ("CLI_ARGUMENT: machine " + progress::path_text(variant) + " already exists.").c_str());
    const auto update = parse({"build", profile, variant.string(), "--force", "--cluster=off"});
    assert(update.force_existing && update.machine.name == "variant" &&
           !parse({"build", profile}).force_existing);
    reject({"start", machine.string(), "--force"}, "CLI_ARGUMENT:");
    reject({"build", profile, destination.string(), "machines/third-build"}, "CLI_ARGUMENT:");
    reject({"build", profile, destination.string(), "--machine", "second-build"}, "CLI_ARGUMENT:");
    const auto linked_destination = root / "machines/linked-build";
    std::filesystem::create_directory_symlink(external, linked_destination);
    reject({"build", profile, linked_destination.string()}, "CLI_ARGUMENT:");
    std::filesystem::remove(linked_destination);
    const auto saved_machines = root / "saved-machines";
    std::filesystem::rename(root / "machines", saved_machines);
    std::filesystem::create_directory_symlink(external, root / "machines");
    reject({"build", profile, "machines/second-build"}, "CLI_ARGUMENT:");
    std::filesystem::remove(root / "machines");
    std::filesystem::rename(saved_machines, root / "machines");
    assert(cli_help().find("build PROFILE [MACHINE_PATH]") != std::string_view::npos);
    assert(cli_help().find("build-finalize") == std::string_view::npos);
    // No profile is a default: deps without one installs only the tools, and the internal
    // commands require theirs.
    const auto tools = parse({"deps"});
    assert(tools.command == "deps" && tools.profile.empty() && !tools.profile_explicit);
    assert(parse({"deps", profile}).profile == profile);
    assert(parse({"help"}).profile.empty() && parse({"list"}).profile.empty());
    reject({"_start", "--root", root.string(), "--exclusive", "--ownership-id",
            std::string(32, 'a')},
           "PROFILE_NAME:");
    reject({"_supervise", "--root", root.string()}, "PROFILE_NAME:");
    const auto providers =
            parse({"start", machine.string(), "--provider", (root / "provider-a.json").string(),
                   "--provider", (root / "provider-b.json").string()});
    assert(providers.providers.size() == 2);
    reject({"start", machine.string(), "--cluster=off", "--seconds", "2"}, "CLI_ARGUMENT:");
    reject({"patch", machine.string(), "--values", "[]"}, "CLI_ARGUMENT:");
    reject({"patch", machine.string(), "--values", "{"}, "CLI_ARGUMENT:");
    reject({"build-finalize", "passion-11-russian-20260403-2.1.4.80"}, "CLI_COMMAND:");

    for (const auto *option : {"--android-only", "--candidate", "--candidate-sha256"}) {
        reject({"build", "passion-11-russian-20260403-2.1.4.80", option}, "CLI_ARGUMENT:");
    }

    const auto full_build = parse({"build", "free-11-chinese-20260731-7.3.1"});
    assert(full_build.cluster && full_build.multimedia);
    const auto android_build =
            parse({"build", "free-11-chinese-20260731-7.3.1", "--cluster=off", "--multimedia=on"});
    assert(!android_build.cluster && android_build.multimedia);
    const auto qnx_build =
            parse({"build", "passion-11-russian-20260403-2.1.4.80", "--multimedia=off"});
    assert(qnx_build.cluster && !qnx_build.multimedia);
    reject({"build", profile, "--cluster=off", "--multimedia=off"}, "CLI_ARGUMENT:");
    reject({"build", profile, "--background"}, "CLI_ARGUMENT:");
    reject({"build", profile, "--seconds", "1"}, "CLI_ARGUMENT:");
    const auto accepted = root / ".local/build/accepted/acceptance.json";
    const std::string accepted_pin(64, 'a');
    const auto reuse = parse({"build", "free-11-chinese-20260731-7.3.1", "--reuse-qnx",
                              accepted.string(), "--reuse-qnx-sha256", accepted_pin});
    assert(reuse.reuse_qnx == accepted && reuse.reuse_qnx_sha256 == accepted_pin && reuse.cluster &&
           reuse.multimedia);
    reject({"build", profile, "--reuse-qnx", accepted.string()}, "CLI_ARGUMENT:");
    reject({"build", profile, "--reuse-qnx-sha256", accepted_pin}, "CLI_ARGUMENT:");
    reject({"build", profile, "--cluster=off", "--reuse-qnx", accepted.string(),
            "--reuse-qnx-sha256", accepted_pin},
           "CLI_ARGUMENT:");
    reject({"build", profile, "--reuse-qnx", accepted.string(), "--reuse-qnx-sha256", "wrong"},
           "CLI_ARGUMENT:");
    const auto source_reuse =
            parse({"build", "free-11-chinese-20260731-7.3.1", "--reuse-qnx", accepted.string(),
                   "--reuse-qnx-sha256", accepted_pin, "--reuse-qnx-source", machine.string()});
    assert(source_reuse.reuse_qnx_source == machine);
    reject({"build", profile, "--reuse-qnx-source", machine.string()}, "CLI_ARGUMENT:");
    const auto private_start =
            parse({"_start", "--root", root.string(), "--profile", profile, "--machine", "variant",
                   "--exclusive", "--ownership-id", std::string(32, 'a'), "--with-cluster"});
    assert(private_start.private_start && private_start.machine.name == "variant" &&
           private_start.machine.selected && private_start.cluster);
    // The default machine and the machine named like the profile reach one canonical name at the
    // CLI boundary; only the selection differs.
    auto private_machine = [&](std::vector<std::string> extra) {
        std::vector<std::string> words{
                "_start", "--root",      root.string(),    "--profile",
                profile,  "--exclusive", "--ownership-id", std::string(32, 'a')};
        words.insert(words.end(), extra.begin(), extra.end());

        return parse(words).machine;
    };
    const auto unnamed = private_machine({}), named = private_machine({"--machine", profile});
    assert(unnamed.name == profile && !unnamed.selected && unnamed.selector().empty());
    assert(named.name == unnamed.name && named.selected && named.selector() == profile);
    assert(parse({"status", machine.string()}).machine.name == named.name);
    reject({"start", machine.string(), "--exclusive"}, "CLI_ARGUMENT:");
    reject({"strat"}, "CLI_COMMAND:");
    assert(parse({"--version"}).command == "--version");
    reject({"patch", machine.string()}, "CLI_ARGUMENT:");
    const auto help = cli_help();
    assert(help.find("--version") != std::string_view::npos);
    assert(help.find("start MACHINE_PATH") != std::string_view::npos &&
           help.find("--cluster=on|off") != std::string_view::npos &&
           help.find("--multimedia=on|off") != std::string_view::npos &&
           help.find("--network=yes|no") != std::string_view::npos);
    std::filesystem::remove_all(root);
    std::cout
            << "Public machine paths, preparation profiles, role flags and private bridge passed\n";
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
