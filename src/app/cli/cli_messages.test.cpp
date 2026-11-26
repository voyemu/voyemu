#include "cli_messages.hpp"
#include "cli_arguments.hpp"
#include "help.hpp"
#include "human_output.hpp"
#include "process.hpp"
#include "supervisor_failure.hpp"
#include <algorithm>
#include <exception>
#include <fstream>
#include <iostream>
#include <set>
using namespace voyemu;
using cli::Language;
namespace {
int failures = 0;

void check(bool condition, const std::string &what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << '\n';
        ++failures;
    }
}

const char *tag(Language language) {
    return ui::language_tag(language);
}

// Placeholder names in order; nullopt when a brace does not open a {name} placeholder.
std::optional<std::multiset<std::string>> placeholders(const std::string &text) {
    std::multiset<std::string> names;

    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '}') {
            return std::nullopt;
        }

        if (text[i] != '{') {
            continue;
        }

        const auto end = text.find('}', i);

        if (end == std::string::npos || end == i + 1) {
            return std::nullopt;
        }

        const auto name = text.substr(i + 1, end - i - 1);

        if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyz_") != std::string::npos) {
            return std::nullopt;
        }

        names.insert(name);
        i = end;
    }

    return names;
}

cli::EnvironmentLookup environment(std::map<std::string, std::string> values) {
    return [values = std::move(values)](const char *name) -> const char * {
        const auto found = values.find(name);

        return found == values.end() ? nullptr : found->second.c_str();
    };
}

cli::InterfaceLanguage interface(std::string value) {
    return [value = std::move(value)] {
        return value;
    };
}

cli::Arguments parse_command(std::vector<std::string> words) {
    words.insert(words.begin(), "voyemu");
    std::vector<char *> argv;

    for (auto &word : words) {
        argv.push_back(word.data());
    }

    return cli::parse(static_cast<int>(argv.size()), argv.data(),
                      std::filesystem::current_path() / "voyemu");
}

std::string parse_error(std::vector<std::string> words, Language language) {
    try {
        parse_command(std::move(words));
    } catch (const std::exception &error) {
        return human_cli_error(std::current_exception(), language);
    }

    return {};
}

void catalogs() {
    const auto english = Json::parse(cli::message_catalog(Language::english), nullptr, false);

    check(english.is_object() && !english.empty(), "English catalog is a non-empty object");

    for (const auto language : cli::languages) {
        const auto catalog = Json::parse(cli::message_catalog(language), nullptr, false);
        check(catalog.is_object(), std::string(tag(language)) + " catalog is an object");

        for (const auto &[key, text] : english.items()) {
            if (!catalog.contains(key)) {
                check(false, std::string(tag(language)) + " misses " + key);
                continue;
            }

            const auto &value = catalog.at(key);
            check(value.is_string() && !value.get<std::string>().empty(),
                  std::string(tag(language)) + " has text for " + key);

            if (!value.is_string()) {
                continue;
            }

            const auto source = placeholders(text.get<std::string>());
            const auto translated = placeholders(value.get<std::string>());
            check(source && translated && *source == *translated,
                  std::string(tag(language)) + " keeps placeholders of " + key);
        }

        for (const auto &[key, text] : catalog.items()) {
            check(english.contains(key), std::string(tag(language)) + " adds unknown " + key);
        }
    }

    check(cli::message(Language::russian, "output.session_active", {{"machine", "car"}}) ==
                  "Сессия активна: car",
          "message substitutes arguments");
    bool missing = false;
    try {
        cli::message(Language::english, "output.session_active");
    } catch (const std::logic_error &) {
        missing = true;
    }

    check(missing, "missing argument is rejected");
    missing = false;
    try {
        cli::message(Language::chinese, "absent.key");
    } catch (const std::logic_error &) {
        missing = true;
    }

    check(missing, "missing key is rejected instead of falling back");
}

void resolution() {
    const auto none = environment({});
    const auto resolve = [](std::optional<std::string_view> option,
                            const cli::EnvironmentLookup &variables, const std::string &host) {
        return cli::resolve_language(option, variables, interface(host));
    };

    check(resolve(std::nullopt, none, "") == Language::english, "default is English");
    check(resolve("zh", environment({{"LC_ALL", "ru_RU.UTF-8"}}), "ru-RU") == Language::chinese,
          "--lang wins over the environment and the host");
    check(resolve("de", environment({{"LANG", "ru_RU.UTF-8"}}), "") == Language::russian,
          "an invalid --lang is not a match");
    check(resolve(std::nullopt,
                  environment({{"LC_ALL", "zh_CN.UTF-8"},
                               {"LC_MESSAGES", "ru_RU.UTF-8"},
                               {"LANG", "en_US.UTF-8"}}),
                  "") == Language::chinese,
          "LC_ALL wins over LC_MESSAGES and LANG");
    check(resolve(std::nullopt,
                  environment({{"LC_ALL", ""}, {"LC_MESSAGES", "ru_RU"}, {"LANG", "zh_CN"}}),
                  "") == Language::russian,
          "an empty LC_ALL is unset and LC_MESSAGES wins over LANG");
    check(resolve(std::nullopt, environment({{"LANG", "zh_Hans"}}), "ru-RU") == Language::chinese,
          "LANG wins over the host UI language");
    check(resolve(std::nullopt, environment({{"LANG", "C"}}), "ru-RU") == Language::english,
          "C means English and ends the search");
    check(resolve(std::nullopt, environment({{"LC_ALL", "POSIX"}}), "zh-CN") == Language::english,
          "POSIX means English");
    check(resolve(std::nullopt, environment({{"LANG", "fr_FR.UTF-8"}}), "ru-RU") ==
                  Language::english,
          "an unknown locale means English");
    check(resolve(std::nullopt, none, "ru-RU") == Language::russian,
          "the host UI language follows the environment");
    check(resolve(std::nullopt, none, "zh-CN") == Language::chinese, "Chinese host UI language");
    check(resolve(std::nullopt, none, "de-DE") == Language::english,
          "unknown host UI language means English");
    std::vector<std::string> words{"voyemu", "status", "--lang=ru", "machines/car", "--lang=zh"};
    std::vector<char *> argv;

    for (auto &word : words) {
        argv.push_back(word.data());
    }

    check(cli::select_language(static_cast<int>(argv.size()), argv.data(),
                               environment({{"LANG", "zh_CN.UTF-8"}}),
                               interface("zh-CN")) == Language::russian,
          "the first --lang on the command line overrides the environment");
    check(cli::select_language(2, argv.data(), environment({{"LANG", "zh_CN.UTF-8"}}),
                               interface("ru-RU")) == Language::chinese,
          "without --lang the environment selects the language");
}

void help() {
    std::set<std::string> rendered;

    for (const auto language : cli::languages) {
        const auto text = cli_help(language);
        rendered.insert(text);

        for (const auto *syntax :
             {"start MACHINE_PATH", "build PROFILE [MACHINE_PATH] [--target=TARGET]",
              "--cluster=on|off", "--multimedia=on|off", "--network=yes|no", "--lang=en|ru|zh",
              "fetch PROFILE --source=adb --serial SERIAL", R"('{"speed":80}')",
              "voyemu test --request request.json"}) {
            check(text.find(syntax) != std::string::npos,
                  std::string(tag(language)) + " help keeps " + syntax);
        }

        check(text.find(cli::message(language, "help.run")) != std::string::npos &&
                      text.find(cli::message(language, "help.lang")) != std::string::npos,
              std::string(tag(language)) + " help uses its catalog");
        check(text.back() == '\n' && text.find(" \n") == std::string::npos,
              std::string(tag(language)) + " help has no trailing spaces");
    }

    check(rendered.size() == cli::languages.size(), "each language renders distinct help");
    const auto english = cli_help();
    check(english.starts_with("Usage: voyemu COMMAND [OPTIONS]\n\nRun and control a prepared "
                              "machine\n  start MACHINE_PATH     Launch the selected machine "
                              "directory\n"),
          "English help keeps its layout");
    check(english.find("  build PROFILE [MACHINE_PATH] [--target=TARGET]\n"
                       "                         Prepare a new machine. The default path is "
                       "machines/PROFILE; a build target for another processor than that of this "
                       "host uses machines/PROFILE-TARGET.\n") != std::string::npos,
          "long syntax moves its description to the next line");
    const auto names = embedded_profile_names();
    check(std::any_of(names.begin(), names.end(),
                      [&](const std::string &name) {
                          return english.find("  voyemu start machines/" + name + '\n') !=
                                 std::string::npos;
                      }) &&
                  std::any_of(names.begin(), names.end(),
                              [&](const std::string &name) {
                                  return english.find("  voyemu build " + name +
                                                      " --cluster=off\n") != std::string::npos;
                              }),
          "help examples name bundled profiles");
    check(cli_help(Language::russian).starts_with("Использование: voyemu COMMAND [OPTIONS]\n"),
          "Russian help heading");
    check(cli_help(Language::chinese).starts_with("用法：voyemu COMMAND [OPTIONS]\n"),
          "Chinese help heading");
}

void errors() {
    const cli::LocalizedError error("CLI_ARGUMENT", "error.unknown_option", {{"option", "--x"}});

    check(std::string(error.what()) == "CLI_ARGUMENT: unknown --x",
          "what() keeps the English JSON message");
    check(human_cli_error(std::make_exception_ptr(error), Language::russian) ==
                  "Voyemu: CLI_ARGUMENT: неизвестный параметр --x\n",
          "human error renders the selected language with its code");
    check(human_cli_error(
                  std::make_exception_ptr(std::runtime_error("PIN_PATH: retained input missing")),
                  Language::chinese) == "Voyemu: PIN_PATH: retained input missing\n",
          "uncatalogued errors keep English");
    // With the log file of the command, a catalog error names it, and an uncatalogued error shows
    // only its code and points to the log, which keeps its English text.
    const std::filesystem::path log = "/root/.local/build/logs/build-20261120-101512.log";
    check(human_cli_error(std::make_exception_ptr(error), Language::russian, log) ==
                  "Voyemu: CLI_ARGUMENT: неизвестный параметр --x\nЛог: " + log.string() + "\n",
          "a catalog error names the log");
    check(human_cli_error(
                  std::make_exception_ptr(std::runtime_error("PIN_PATH: retained input missing")),
                  Language::english,
                  log) == "Voyemu: PIN_PATH: the operation failed.\nDetails are in the log: " +
                                  log.string() +
                                  ". If the error persists, attach the log to a problem report.\n",
          "an uncatalogued error keeps its code and names the log");
    const auto unaccelerated = std::make_exception_ptr(
            VoyemuError("ANDROID_ACCELERATION", "private technical detail"));

    for (const auto language : cli::languages) {
        const auto visible = human_cli_error(unaccelerated, language, log);
        check(visible.find("ANDROID_ACCELERATION: " +
                           cli::message(language, "error.android_acceleration")) !=
                              std::string::npos &&
                      visible.find("private technical detail") == std::string::npos,
              "missing acceleration names its remedy in the selected language");
    }

    const auto rejected = std::make_exception_ptr(
            VoyemuError("ANDROID_VERIFIED_BOOT", "private technical detail"));

    for (const auto language : cli::languages) {
        const auto visible = human_cli_error(rejected, language, log);
        check(visible.find("ANDROID_VERIFIED_BOOT: " +
                           cli::message(language, "error.android_verified_boot")) !=
                              std::string::npos &&
                      visible.find(log.string()) != std::string::npos &&
                      visible.find("private technical detail") == std::string::npos,
              "verified boot rejection retains its diagnostic and log in the selected language");
    }

    // An exception without a code shows its kind and its cause, then the log.
    const auto denied = std::make_error_code(std::errc::permission_denied);
    const std::filesystem::path machine = "/machines/car";
    check(human_cli_error(std::make_exception_ptr(std::filesystem::filesystem_error(
                                  "resize_file", machine / "qnx-ram.bin", denied)),
                          Language::russian, log) ==
                  "Voyemu: FILESYSTEM: файловая операция не выполнена: resize_file " +
                          (machine / "qnx-ram.bin").string() + ": " + denied.message() +
                          ".\nПроверьте путь, права доступа и свободное место на томе, затем "
                          "повторите команду.\nЛог: " +
                          log.string() + "\n",
          "a filesystem error names its operation, path and reason");
    // A Windows system message ends with a period and a line break that the sentence drops.
    std::error_code missing;
    std::filesystem::rename(machine / "absent-source", machine / "absent-target", missing);
    try {
        std::filesystem::rename(machine / "absent-source", machine / "absent-target");
        check(false, "a missing rename source throws");
    } catch (const std::filesystem::filesystem_error &error) {
        check(human_cli_error(std::current_exception(), Language::english) ==
                      "Voyemu: FILESYSTEM: a file operation failed: rename " +
                              (machine / "absent-source").string() + ", " +
                              (machine / "absent-target").string() + ": " +
                              failure_reason(missing.message()) +
                              ".\nCheck the path, its permissions and the free space on its "
                              "volume, then repeat the command.\n",
              "a thrown filesystem error names its operation and both paths");
    }

    const std::system_error refused(std::make_error_code(std::errc::connection_refused), "connect");
    check(human_cli_error(std::make_exception_ptr(refused), Language::english, log) ==
                  "Voyemu: SYSTEM: a system operation failed: " + std::string(refused.what()) +
                          ".\nIf the error persists, attach the log to a problem report.\nLog: " +
                          log.string() + "\n",
          "a system error shows its reason");
    try {
        static_cast<void>(Json::parse("{\"schema\": }"));
        check(false, "malformed JSON throws");
    } catch (const Json::exception &error) {
        const std::string text = error.what();
        const auto rendered = human_cli_error(std::current_exception(), Language::chinese);
        check(rendered.starts_with("Voyemu: JSON: 无法读取 JSON 数据：parse error at line 1") &&
                      rendered.find("[json.exception.") == std::string::npos &&
                      rendered.ends_with("。\n如果错误再次出现，请在问题报告中附上日志。\n"),
              "a JSON error shows its parse position without the library prefix: " + rendered +
                      " from " + text);
    }

    check(human_cli_error(std::make_exception_ptr(std::logic_error("vector index out of range.")),
                          Language::russian, log) ==
                  "Voyemu: INTERNAL_ERROR: непредвиденный сбой: vector index out of range.\nЕсли "
                  "ошибка повторится, приложите лог к сообщению о проблеме.\nЛог: " +
                          log.string() + "\n",
          "another error without a code shows its text with INTERNAL_ERROR");
    check(human_cli_error(
                  std::make_exception_ptr(cli::LocalizedError("INTERRUPTED", "error.interrupted")),
                  Language::chinese,
                  log) == "Voyemu: INTERRUPTED: 命令已中断。\n日志：" + log.string() + "\n",
          "an interruption names the log");
    // A start whose supervisor exited names the cause from its log, or its exit status, and the
    // session log.
    const auto directory = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                           ("voyemu-start-failed-" + random_token());
    ensure_private_directory(directory);
    const auto supervisor = directory / "supervisor.log";
    std::ofstream(supervisor)
            << "{\"ok\":false,\"error\":\"LAUNCH_PIN: immutable input mismatch\"}\n";
    const auto exited = supervisor_exit_error(supervisor, 4);
    check(exited.code() == "SUPERVISOR_EXITED" &&
                  exited.render(Language::russian) ==
                          "SUPERVISOR_EXITED: сеанс завершился при запуске (LAUNCH_PIN).\nЛог сеанса: " +
                                  supervisor.string(),
          "an exited start names its cause and session log");
    check(supervisor_exit_error(directory / "absent.log", 3).render(Language::english) ==
                  "SUPERVISOR_EXITED: the session exited during start (exit 3).\nSession log: " +
                          (directory / "absent.log").string(),
          "an exited start without a logged code names its exit status");
    std::filesystem::remove_all(directory);
    check(parse_error({"strat"}, Language::chinese) ==
                  "Voyemu: CLI_COMMAND: 未知命令“strat”；请运行 voyemu help\n",
          "unknown command renders in Chinese");
    check(parse_error({"start"}, Language::russian) ==
                  "Voyemu: MACHINE_PATH: start требует каталог машины; запустите voyemu help\n",
          "missing machine renders in Russian");
    check(parse_error({"list", "--lang=fr"}, Language::english) ==
                  "Voyemu: CLI_ARGUMENT: --lang requires en, ru or zh\n",
          "an unsupported --lang is rejected");
    check(parse_error({"list", "--lang=ru", "--lang=ru"}, Language::english) ==
                  "Voyemu: CLI_ARGUMENT: duplicate --lang\n",
          "a repeated --lang is rejected");
    const auto global = parse_command({"--lang=zh", "list"});
    check(global.command == "list" && global.language == "zh",
          "--lang before the command keeps the command position");
    check(parse_command({"--lang=ru"}).command == "help", "--lang alone shows help");
    check(parse_command({"help", "--lang=en"}).language == "en", "--lang after the command");
}

void output() {
    const Json status{{"stopped", false},
                      {"deliveries",
                       {{"android", {{"status", "guest_acknowledged"}}},
                        {"qnx", {{"status", "not_started"}}}}}};

    check(human_cli_output("status", status, "profile", "car", false, Language::russian) ==
                  "Машина: car\nСостояние" + std::string(5, ' ') + "Мультимедиа" +
                          std::string(11, ' ') + "Приборка\nработает" + std::string(6, ' ') +
                          "готова" + std::string(16, ' ') + "выкл\n",
          "Russian status table aligns by columns");
    check(human_cli_output("status", status, "profile", "car", false, Language::chinese) ==
                  "机器：car\n状态" + std::string(10, ' ') + "多媒体" + std::string(16, ' ') +
                          "仪表\n运行中" + std::string(8, ' ') + "就绪" + std::string(18, ' ') +
                          "关\n",
          "Chinese status table counts ideographs as two columns");
    check(human_cli_output("list", Json::array({"a"}), "a", {}, false, Language::chinese) ==
                  "配置文件\n  a\n",
          "Chinese list heading");
    check(human_cli_output("stop", {{"ok", true}}, "p", "car", false, Language::english) ==
                  "Session stopped: car\n",
          "English stop summary");
}
} // namespace

int main() try {
    catalogs();
    resolution();
    help();
    errors();
    output();

    if (failures != 0) {
        return 1;
    }

    std::cout << "CLI catalogs, language resolution, help and errors passed in every language\n";

    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
