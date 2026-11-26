#pragma once
#include "cli_messages.hpp"
#include "profile_catalog.hpp"
#include <string>
#include <string_view>
namespace voyemu {
// Command and option syntax stays untranslated; descriptions come from the message catalog.
inline std::string cli_help(cli::Language language = cli::Language::english) {
    struct Row {
        std::string_view syntax, key;
        cli::MessageArguments arguments;
    };
    std::string out;
    const auto text = [&](std::string_view key, const cli::MessageArguments &arguments = {}) {
        return cli::message(language, key, arguments);
    };
    const auto note = [&](std::string_view key, std::string_view indent) {
        const auto value = text(key);
        out += indent;

        for (const auto c : value) {
            out += c;

            if (c == '\n') {
                out += indent;
            }
        }

        out += '\n';
    };
    const auto heading = [&](std::string_view key) {
        out += '\n' + text(key) + '\n';
    };
    const auto entries = [&](std::initializer_list<Row> list) {
        for (const auto &row : list) {
            constexpr std::size_t column = 23;
            out += "  ";
            out += row.syntax;
            out += row.syntax.size() < column - 1 ? std::string(column - row.syntax.size(), ' ')
                                                  : '\n' + std::string(column + 2, ' ');
            out += text(row.key, row.arguments) + '\n';
        }
    };

    out += text("help.usage", {{"syntax", "voyemu COMMAND [OPTIONS]"}}) + '\n';
    heading("help.run");
    entries({{"start MACHINE_PATH", "help.start", {}},
             {"restart MACHINE_PATH", "help.restart", {}},
             {"status MACHINE_PATH", "help.status", {}},
             {"stop MACHINE_PATH", "help.stop", {}},
             {"check MACHINE_PATH", "help.check", {}},
             {"patch MACHINE_PATH --values JSON",
              "help.patch",
              {{"example", R"('{"speed":80}')"}}}});
    heading("help.prepare");
    entries({{"list", "help.list", {}},
             {"deps [PROFILE]", "help.deps", {}},
             {"fetch PROFILE", "help.fetch", {}},
             {"fetch PROFILE --source=FILE", "help.fetch_archive", {}},
             {"fetch PROFILE --source=adb --serial SERIAL", "help.fetch_adb", {}},
             {"build PROFILE [MACHINE_PATH] [--target=TARGET]",
              "help.build",
              {{"default", "machines/PROFILE"}, {"other", "machines/PROFILE-TARGET"}}}});
    heading("help.subsystems");
    entries({{"--cluster=on|off", "help.cluster", {}},
             {"--multimedia=on|off", "help.multimedia", {}}});
    note("help.subsystems_note", "  ");
    heading("help.launch");
    entries({{"--network=yes|no", "help.network", {}},
             {"--verbose", "help.verbose", {}},
             {"--background", "help.background", {}},
             {"--resume", "help.resume", {}},
             {"--seconds 1..3600", "help.seconds", {}},
             {"--provider FILE", "help.provider", {}}});
    note("help.launch_note", "  ");
    heading("help.preparation");
    note("help.preparation_note", "  ");
    entries({{"--reuse-qnx FILE --reuse-qnx-sha256 SHA256", "help.reuse_qnx", {}},
             {"--reuse-qnx-source PATH", "help.reuse_qnx_source", {}},
             {"--force", "help.force", {}},
             {"--offline", "help.offline", {}},
             {"--jdk PATH", "help.jdk", {}}});
    heading("help.global");
    entries({{"--lang=en|ru|zh", "help.lang", {}}, {"--version", "help.version", {}}});
    heading("help.automation");
    entries({{"test [--request FILE]", "help.test", {}}});
    note("help.automation_note", "  ");
    out += '\n';
    note("help.machine_path_note", "");
    heading("help.examples");

    // The examples name bundled profiles: an Android 9 one with a cluster and an Android 11 one.
    const auto machine =
            embedded_profile_names(ProfilePlatform::qinggan09, ProfileBoard::sa8155).at(0);
    const auto profile =
            embedded_profile_names(ProfilePlatform::qinggan11, ProfileBoard::sa8155).at(0);

    for (const auto &example :
         {"start machines/" + machine, "start machines/" + machine + " --cluster=off",
          "start machines/" + machine + " --multimedia=off", "status machines/" + machine,
          "build " + profile + " --cluster=off",
          "build " + profile + " machines/" + profile + "-new --cluster=off",
          "fetch " + profile + " --source=update.zip",
          "fetch " + profile + " --source=adb --serial SERIAL",
          std::string("test --request request.json")}) {
        out += "  voyemu " + example + '\n';
    }

    out += "  voyemu help            " + text("help.help") + '\n';

    return out;
}
} // namespace voyemu
