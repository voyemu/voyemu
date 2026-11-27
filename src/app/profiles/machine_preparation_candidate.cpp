#include "check.hpp"
#include "machine_preparation_internal.hpp"
#include "ordinary_path.hpp"
#include "ui_observer_diagnostics.hpp"
#include <cstdio>

// Drives a booted Android candidate: installs files and packages, configures and wakes its
// displays.
namespace voyemu {
using namespace machine_preparation_detail;
namespace {
Installed install_file(Candidate &c, const Json &entry, const std::filesystem::path &source,
                       const std::string &sha, const std::string &target) {
    guest_path(target);
    check_file(source, sha);
    const auto mode = entry.value("mode", std::string("0644"));
    need(std::regex_match(mode, std::regex("0[0-7]{3}")), "guest mode required");
    const auto uid = entry.value("uid", 0U), gid = entry.value("gid", 0U);
    need(uid <= 65535 && gid <= 65535, "guest owner bounds");
    const auto metadata = entry.contains("context") ? android_candidate_file_metadata(entry)
                                                    : std::string{};
    const auto parent = std::filesystem::path(target).parent_path().generic_string();
    c.shell({"mkdir", "-p", parent});

    if (entry.value("mutable", false)) {
        c.shell({"rm", "-f", target});
    }

    try {
        c.adbd({"push", source.string(), target}, 180000);
    } catch (const VoyemuError &e) {
        throw VoyemuError("MACHINE_PREPARATION",
                          android_candidate_write_failure(target, e.what(), c.shell({"id"}),
                                                          c.shell({"ls", "-Zd", parent})));
    }

    c.shell({"chmod", mode, target});
    c.shell({"chown", std::to_string(uid) + ":" + std::to_string(gid), target});
    c.shell({"restorecon", target});
    need(c.shell({"sha256sum", target}).starts_with(sha + " "),
         "installed file hash differs: " + target);

    if (!metadata.empty()) {
        const auto actual = guest_file_metadata(c, target);
        need(actual == metadata, "installed file metadata differs: " + target + ": " + actual);
    }

    return {entry.at("artifact").get<std::string>(),
            target,
            sha,
            {},
            mode,
            entry.value("mutable", false)};
}

Installed install_directory(Candidate &c, const Json &entry) {
    const auto target = entry.at("target").get<std::string>();

    guest_path(target);
    const auto mode = entry.value("mode", std::string("0755"));
    need(std::regex_match(mode, std::regex("0[0-7]{3}")), "guest directory mode required");
    const auto uid = entry.value("uid", 0U), gid = entry.value("gid", 0U);
    need(uid <= 65535 && gid <= 65535, "guest owner bounds");

    if (entry.contains("context")) {
        need(std::regex_match(entry.at("context").get<std::string>(),
                              std::regex("u:object_r:[a-z0-9_]+:s0")),
             "guest directory SELinux context required");
    }

    c.shell({"mkdir", "-p", target});
    const auto parent = std::filesystem::path(target).parent_path().generic_string();

    for (const auto &path : {parent, target}) {
        c.shell({"test", "!", "-L", path});
    }

    c.shell({"chmod", mode, target});
    c.shell({"chown", std::to_string(uid) + ":" + std::to_string(gid), target});
    c.shell({"restorecon", target});
    const auto label = c.shell({"ls", "-Zd", target});

    if (entry.contains("context")) {
        need(std::regex_search(label,
                               std::regex(R"((?:^|\s))" +
                                          regex_escape(entry.at("context").get<std::string>()) +
                                          R"((?:\s|$))")),
             "installed directory SELinux label differs: " + target);
    }

    return {entry.at("artifact").get<std::string>(),
            target,
            std::string{},
            std::string{},
            mode,
            false};
}

Installed install_apk(Candidate &c, const Json &entry, const Json &artifact,
                      const std::filesystem::path &aapt2) {
    const std::filesystem::path source = artifact.at("file").get<std::string>();
    const auto info = c.host(aapt2, {"dump", "badging", source.string()}).output;
    std::smatch package;

    need(std::regex_search(info, package, std::regex(R"(package: name='([A-Za-z0-9_.]+)')")),
         "APK package metadata missing");
    const auto name = package[1].str();

    if (entry.contains("target")) {
        const auto target = privileged_apk_target(entry),
                   parent = std::filesystem::path(target).parent_path().generic_string();
        need(name == entry.at("package").get<std::string>(),
             "privileged APK package metadata differs");

        for (const auto &path : {std::string("/system/priv-app"), parent, target}) {
            c.shell({"test", "!", "-L", path});
        }

        c.shell({"mkdir", "-p", parent});
        c.shell({"chmod", "0755", parent});
        c.shell({"chown", "0:0", parent});
        c.shell({"restorecon", parent});
        auto installed = install_file(c, entry, source, artifact.at("sha256").get<std::string>(),
                                      target);
        installed.package = name;

        return installed;
    }

    const auto installed = c.adbd({"install", "--no-incremental", "-r", source.string()}, 180000);
    need(std::regex_search(installed, std::regex("(?:^|\\n)Success(?:\\r?\\n|$)")),
         "APK installation failed: " + name);
    const auto paths = lines(c.shell({"pm", "path", name}));
    need(paths.size() == 1 && paths[0].starts_with("package:/"),
         "ambiguous installed package topology: " + name);
    const auto target = paths[0].substr(8), sha = artifact.at("sha256").get<std::string>();
    need(c.shell({"sha256sum", target}).starts_with(sha + " "),
         "installed APK hash differs: " + name);

    return {entry.at("artifact").get<std::string>(), target, sha, name, {}, false};
}

// The ELF class and machine of the libraries of an APK ABI, and its instruction set directory.
struct NativeAbi {
    unsigned elf_class, machine;
    std::string isa;
};

NativeAbi native_abi(std::string_view abi) {
    if (abi == "x86_64") {
        return {2, 62, "x86_64"};
    }

    if (abi == "x86") {
        return {1, 3, "x86"};
    }

    return {2, 183, "arm64"};
}

void install_system_native_library(Candidate &c, const Json &entry,
                                   const std::filesystem::path &source, const std::string &sha,
                                   const ZipEntry &file, const NativeAbi &elf,
                                   const std::string &folder, std::vector<Installed> &installed) {
    const auto bytes = read_pinned_zip_entry(source, sha, file.name, 64U << 20,
                                             ZipNamePolicy::exact);

    need(bytes.size() == file.bytes && bytes.size() >= 20 &&
                 bytes.substr(0, 4) == std::string("\x7f"
                                                   "ELF",
                                                   4) &&
                 static_cast<unsigned char>(bytes[4]) == elf.elf_class &&
                 static_cast<unsigned char>(bytes[5]) == 1 &&
                 static_cast<unsigned char>(bytes[18]) == elf.machine && bytes[19] == 0,
         "native APK entry must be an ELF of its ABI: " + file.name);
    const auto pin = sha256_bytes(bytes),
               target = folder + std::filesystem::path(file.name).filename().generic_string();
    c.shell({"test", "!", "-e", target});
    const auto unpacked = c.stage / "apk-native" / (pin + ".so");

    if (!std::filesystem::exists(unpacked)) {
        ensure_private_directory(unpacked.parent_path());
        std::ofstream output(unpacked, std::ios::binary);
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.close();
        need(bool(output), "native APK entry write failed");
    } else {
        check_file(unpacked, pin);
    }

    installed.push_back(install_file(
            c,
            {{"artifact", "native:" + entry.at("artifact").get<std::string>()}, {"mode", "0644"}},
            unpacked, pin, target));
}

void install_system_native_libraries(Candidate &c, const Json &entry, const Json &artifact,
                                     const std::filesystem::path &aapt2,
                                     std::vector<Installed> &installed) {
    const std::filesystem::path source = artifact.at("file").get<std::string>();
    const auto sha = artifact.at("sha256").get<std::string>();
    const auto inventory = pinned_zip_inventory(source, sha, ZipNamePolicy::exact);

    for (const auto &abi : android_guest_native_abis(android_guest_abi(c.boot_profile))) {
        if (std::none_of(inventory.begin(), inventory.end(), [&](const auto &e) {
                return !e.directory && e.name.starts_with("lib/" + abi + "/");
            })) {
            continue;
        }

        const auto manifest =
                c.host(aapt2, {"dump", "xmltree", "--file", "AndroidManifest.xml", source.string()})
                        .output;
        const auto selected = android_candidate_system_native_libraries(entry, inventory, manifest,
                                                                        abi);

        if (selected.empty()) {
            continue;
        }

        const auto elf = native_abi(abi);
        const auto parent = std::filesystem::path(entry.at("target").get<std::string>())
                                    .parent_path()
                                    .generic_string();

        for (const auto &folder : {parent + "/lib", parent + "/lib/" + elf.isa}) {
            c.shell({"test", "!", "-L", folder});
            c.shell({"mkdir", "-p", folder});
            c.shell({"chmod", "0755", folder});
            c.shell({"chown", "0:0", folder});
            c.shell({"restorecon", folder});
        }

        for (const auto &file : selected) {
            install_system_native_library(c, entry, source, sha, file, elf,
                                          parent + "/lib/" + elf.isa + "/", installed);
        }
    }
}

void big(std::string &out, std::uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        out += static_cast<char>(value >> (i * 8));
    }
}

std::uint32_t crc(std::string_view bytes) {
    std::uint32_t value = 0xffffffff;

    for (unsigned char c : bytes) {
        value ^= c;

        for (unsigned i = 0; i < 8; ++i) {
            value = (value >> 1) ^ ((value & 1) ? 0xedb88320 : 0);
        }
    }

    return ~value;
}

void chunk(std::string &png, std::string_view type, const std::string &value) {
    big(png, static_cast<std::uint32_t>(value.size()));
    std::string bytes(type);
    bytes += value;
    png += bytes;
    big(png, crc(bytes));
}

std::string black_png(unsigned width, unsigned height) {
    need(width > 0 && height > 0 && width <= 4096 && height <= 4096 &&
                 static_cast<std::uint64_t>(width) * height <= 4 * 1024 * 1024,
         "wallpaper dimension bounds");
    std::string raw;
    raw.reserve(static_cast<std::size_t>(width * 4 + 1) * height);

    for (unsigned y = 0; y < height; ++y) {
        raw += char(0);

        for (unsigned x = 0; x < width; ++x) {
            raw.append("\0\0\0\xff", 4);
        }
    }

    std::string compressed = "\x78\x01";

    for (std::size_t at = 0; at < raw.size();) {
        const auto count = static_cast<unsigned>(std::min<std::size_t>(65535, raw.size() - at));
        compressed += static_cast<char>(at + count == raw.size() ? 1 : 0);
        compressed += static_cast<char>(count);
        compressed += static_cast<char>(count >> 8);
        compressed += static_cast<char>(~count);
        compressed += static_cast<char>((~count) >> 8);
        compressed.append(raw, at, count);
        at += count;
    }

    std::uint32_t a = 1, b = 0;

    for (unsigned char c : raw) {
        a = (a + c) % 65521;
        b = (b + a) % 65521;
    }

    big(compressed, (b << 16) | a);
    std::string png("\x89PNG\r\n\x1a\n", 8), header;
    big(header, width);
    big(header, height);
    header.append("\x08\x06\0\0\0", 5);
    chunk(png, "IHDR", header);
    chunk(png, "IDAT", compressed);
    chunk(png, "IEND", {});

    return png;
}
} // namespace

namespace machine_preparation_detail {
void ordinary(const std::filesystem::path &p) {
    ordinary_path(p, need, PathForm::Normalized, "normalized absolute path required",
                  "linked path rejected", PathLinks::Reparse);
}

bool inside(const std::filesystem::path &p, const std::filesystem::path &root) {
    auto a = p.begin();

    for (auto b = root.begin(); b != root.end(); ++b, ++a) {
        if (a == p.end() || *a != *b) {
            return false;
        }
    }

    return true;
}

void relative(const std::string &s) {
    std::filesystem::path p(s);

    need(!s.empty() && s.size() <= 512 && !p.is_absolute() && s.find('\\') == std::string::npos &&
                 s.find(':') == std::string::npos,
         "confined relative path required");

    for (const auto &c : p) {
        need(c != ".." && c != "." && !c.empty(), "relative traversal");
    }
}

void guest_path(const std::string &p) {
    need(p.starts_with("/system/") || p.starts_with("/vendor/") || p.starts_with("/data/"),
         "system/vendor/data guest target required");
    relative(p.substr(1));
    need(p.find_first_of("\r\n\0", 0, 3) == std::string::npos, "guest target control byte");
}

void check_file(const std::filesystem::path &p, const std::string &expected,
                std::uint64_t maximum) {
    ordinary(p);
    need(sha256_text(expected) && std::filesystem::is_regular_file(p) &&
                 std::filesystem::hard_link_count(p) == 1 &&
                 std::filesystem::file_size(p) <= maximum,
         "bounded unaliased pinned file required");
    const auto epoch = cache_file_identity(p);
    need(sha256_file(p) == expected && cache_file_identity(p) == epoch,
         "file pin/epoch differs: " + p.filename().string());
}

std::string text(const std::filesystem::path &p, std::uint64_t maximum) {
    ordinary(p);
    need(std::filesystem::is_regular_file(p) && std::filesystem::file_size(p) <= maximum,
         "bounded text input");
    std::ifstream in(p, std::ios::binary);
    need(bool(in), "text open");
    std::string bytes((std::istreambuf_iterator<char>(in)), {});
    need(!in.bad() && bytes.size() <= maximum, "text read");

    return bytes;
}

void write(const std::filesystem::path &p, const std::string &value) {
    need(!std::filesystem::exists(p) && value.size() <= 16ULL << 20,
         "fresh bounded output required");
    ensure_private_directory(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out.write(value.data(), static_cast<std::streamsize>(value.size()));
    out.close();
    need(bool(out), "output write");
}

std::string trim(std::string s) {
    const auto end = s.find_last_not_of("\r\n \t");

    if (end == std::string::npos) {
        return {};
    }

    s.resize(end + 1);
    const auto start = s.find_first_not_of("\r\n \t");

    return s.substr(start);
}

std::vector<std::string> lines(std::string_view value) {
    std::istringstream in{std::string(value)};
    std::vector<std::string> out;

    for (std::string s; std::getline(in, s);) {
        out.push_back(trim(s));
    }

    return out;
}

std::string regex_escape(const std::string &s) {
    std::string out;

    for (char c : s) {
        if (std::string_view(".^$|()[]{}*+?\\").find(c) != std::string_view::npos) {
            out += '\\';
        }

        out += c;
    }

    return out;
}

std::string expanded(std::string component) {
    auto at = component.find("/.");

    if (at != std::string::npos) {
        component.replace(at + 1, 1, component.substr(0, at) + ".");
    }

    return component;
}

std::string shell_line(const std::vector<std::string> &args) {
    std::string line;

    for (const auto &arg : args) {
        if (!line.empty()) {
            line += ' ';
        }

        line += android_shell_quote(arg);
    }

    return line;
}

std::string guest_file_metadata(Candidate &c, const std::string &path) {
    return guest_file_metadata(path, [&](const auto &command) {
        return c.shell(command);
    });
}

std::string
guest_file_metadata(const std::string &path,
                    const std::function<std::string(const std::vector<std::string> &)> &shell) {
    const auto label = shell({"ls", "-Zd", path});

    return shell({"stat", "-c", "%a %u:%g", path}) + " " + label.substr(0, label.find(' '));
}

std::vector<std::string> blocks(const std::string &dump) {
    std::vector<std::string> out;
    std::size_t begin = 0;

    while (begin < dump.size()) {
        auto next = dump.find("  Window #", begin + 1);
        out.push_back(
                dump.substr(begin, next == std::string::npos ? std::string::npos : next - begin));

        if (next == std::string::npos) {
            break;
        }

        begin = next;
    }

    return out;
}

bool visible(const std::string &dump, const std::string &component, unsigned display) {
    const auto full = expanded(component), package = component.substr(0, component.find('/'));
    const auto windows = blocks(dump);
    const std::regex same_display("(?:mDisplayId|displayId)=" + std::to_string(display) +
                                  "(?:\\D|$)"),
            on_screen(R"(\bisOnScreen=true\b)"),
            error("Application Error: " + regex_escape(package) + R"((?:[}\s]|$))");

    for (const auto &b : windows) {
        if (std::regex_search(b, same_display) && std::regex_search(b, on_screen) &&
            std::regex_search(b, error)) {
            return false;
        }
    }

    for (const auto &b : windows) {
        if ((b.find(full) == std::string::npos && b.find(component) == std::string::npos) ||
            !std::regex_search(b, same_display) || !std::regex_search(b, on_screen)) {
            continue;
        }

        if (b.find("mDrawState=") != std::string::npos &&
            !std::regex_search(b, std::regex(R"(\bmDrawState=HAS_DRAWN\b)"))) {
            continue;
        }

        if (b.find("Surface: shown=") != std::string::npos &&
            !std::regex_search(b, std::regex(R"(Surface: shown=true\b)"))) {
            continue;
        }

        return true;
    }

    return false;
}

bool android_candidate_ui_shell_ready(
        const std::function<std::string(const std::vector<std::string> &)> &shell) {
    need(shell({"id", "-u"}) == "2000" && shell({"id", "-Z"}) == "u:r:shell:s0",
         "rich UI observer requires the stock Android shell");

    return shell({"service", "check", "accessibility"}) == "Service accessibility: found";
}

Json read_candidate_ui(const Json &connection, int timeout_ms,
                       const std::function<Json(const Json &, int)> &exchange) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    const auto remaining = [&](int limit) {
        const auto left =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                        .count();
        need(left > 0, "rich UI observation deadline elapsed");

        return static_cast<int>(std::min<std::int64_t>(left, limit));
    };
    const auto verify_lifetime = [&](const Json &reply) {
        need(reply.value("boot_id", Json()) == connection.at("boot_id") &&
                     reply.value("observer_pid", Json()).is_number_integer() &&
                     reply.at("observer_pid") == connection.at("observer_pid"),
             "rich UI observer lifetime changed");
    };
    const auto valid_reply = [](const Json &reply) {
        return reply.is_object() && reply.value("schema", Json()).is_number_integer() &&
               reply.at("schema") == 1 && reply.value("ok", Json()).is_boolean();
    };

    for (;;) {
        const auto left = remaining(35000);
        auto raw = exchange(android_candidate_ui_request(std::min(left, 30000)), left);
        need(valid_reply(raw), "invalid rich UI observer response");
        need(raw.dump().size() <= 6 * 1024 * 1024, "bounded rich UI response required");

        if (raw.at("ok") == true) {
            verify_lifetime(raw);

            return raw;
        }

        const auto reason = raw.value("reason", Json());
        const auto diagnostic = observer_failure_summary(raw);
        need(reason == "window_changed" || reason == "snapshot_busy",
             "rich UI observer rejected observation; " + diagnostic);
        logging::write(logging::Level::debug, "prepare", "rich UI observation rejected",
                       {{"failure", diagnostic}});
        const auto hello = exchange({{"op", "hello"}}, remaining(2000));
        need(valid_reply(hello), "invalid rich UI observer handshake");
        need(hello.at("ok") == true,
             "rich UI observer handshake rejected; " + observer_failure_summary(hello));
        verify_lifetime(hello);
    }
}

Json capture_candidate_ui(Candidate &c, const Json &profile) {
    auto definition = cached_profile_ui_observer(c.root);

    need(!definition.empty(), "source-matched rich UI observer required");
    definition["profile"] = profile.at("id");
    const auto secondary = android_candidate_secondary_provider(profile,
                                                                c.shell({"dumpsys", "display"}));
    need(secondary.has_value(), "rich UI secondary provider unavailable");
    const auto server_pid = c.adb_server.pid(), sdk_pid = c.process.pid();
    const Json specification = {{"adb", c.adb.string()},
                                {"android_sdk_root", c.sdk.string()},
                                {"port", c.port},
                                {"ui_observer", definition},
                                {"owned_adb",
                                 {{"schema", 1},
                                  {"server_pid", server_pid},
                                  {"server_port", c.adb_binding.server},
                                  {"grpc_port", c.adb_binding.grpc},
                                  {"owner", c.adb_binding.owner}}}};
    const auto budget = [&](int maximum) {
        const int left = c.remaining(600000) - 15000;
        need(left > 0, "rich UI shutdown reserve exhausted");

        return std::min(left, maximum);
    };
    const auto fence = [&] {
        need(c.process.pid() == sdk_pid && c.process.alive() &&
                     c.process.owns_tcp_listener(c.port) && c.process.owns_tcp_listener(c.port + 1),
             "rich UI SDK owner changed");
        need(c.adb_server.pid() == server_pid && c.adb_server.alive() &&
                     c.adb_server.owns_tcp_listener(c.adb_binding.server),
             "rich UI private ADB owner changed");
        const auto names = lines(c.raw({"emu", "avd", "name"}, budget(2000)));
        need(!names.empty() && names.front() == c.avd, "rich UI AVD identity changed");
        need(c.raw({"shell", "getprop", "qemu.voyemu.token"}, budget(2000)) == c.token,
             "rich UI guest nonce changed");
    };
    const UiObserver::Adb adb = [&](const std::vector<std::string> &args, int timeout) {
        fence();
        const auto output = c.raw(args, budget(timeout));
        fence();

        return ProcessResult{0, output, false};
    };
    CandidateUiObserverTransport transport(c.stage, specification, adb);
    UiObserver observer(
            c.stage, c.token, specification, adb,
            [&](const auto &args) {
                fence();

                return transport.shell(args);
            },
            [&](std::string_view id, int timeout) {
                fence();

                return transport.observer(id, timeout);
            });
    Json summary;
    std::exception_ptr failure;
    try {
        fence();
        const auto connection = observer.connection(budget(30000));
        const auto raw =
                read_candidate_ui(connection, budget(35000), [&](const Json &message, int timeout) {
                    auto reply = observer.exchange(connection, message, budget(timeout));
                    fence();

                    return reply;
                });
        const auto normalized = save_android_candidate_ui_observation(c.stage, raw,
                                                                      secondary.value());
        Json screens = Json::array();

        for (const auto &screen : normalized.at("screens")) {
            screens.push_back({{"screen", screen.at("screen")},
                               {"display_id", screen.at("display_id")},
                               {"sdk_display_id", screen.at("sdk_display_id")},
                               {"node_count", screen.at("nodes").size()},
                               {"status", screen.at("status")},
                               {"complete", screen.at("complete")},
                               {"metadata_complete", screen.at("metadata_complete")},
                               {"unavailable_windows", screen.at("unavailable_windows")}});
        }

        summary = {{"id", "rich-ui-observation"},
                   {"passed", true},
                   {"format", "voyemu.ui.v1"},
                   {"observer_sha256", definition.at("sha256")},
                   {"raw",
                    {{"file", "ui-observation-raw.json"},
                     {"sha256", sha256_file(c.stage / "ui-observation-raw.json")}}},
                   {"observation",
                    {{"file", "ui-observation.json"},
                     {"sha256", sha256_file(c.stage / "ui-observation.json")}}},
                   {"status", normalized.at("status")},
                   {"complete", normalized.at("complete")},
                   {"screens", screens}};
    } catch (...) {
        failure = std::current_exception();
    }

    bool stopped = false;
    try {
        stopped = observer.stop();
    } catch (...) {
        if (!failure) {
            failure = std::current_exception();
        }
    }

    try {
        write_private_json(c.stage / "ui-observer-shutdown.json", observer.shutdown_status());
    } catch (...) {
        if (!failure) {
            failure = std::current_exception();
        }
    }

    if (failure) {
        std::rethrow_exception(failure);
    }

    need(stopped, "rich UI observer shutdown unverified");
    c.remaining(1);
    write_private_json(c.stage / "ui-observation-summary.json", summary);

    return summary;
}

std::string tool(const AndroidCandidateRequest &request, const std::filesystem::path &path) {
    const auto it = request.tool_pins.find(path.string());

    need(it != request.tool_pins.end(), "host tool pin missing: " + path.filename().string());
    check_file(path, it->second, 512ULL << 20);

    return it->second;
}

void artifact_files(const Json &artifact) {
    if (artifact.contains("file")) {
        const std::filesystem::path file = artifact.at("file").get<std::string>();
        check_file(file, artifact.at("sha256").get<std::string>());
        need(artifact.at("bytes") == std::filesystem::file_size(file), "artifact bytes differ");

        return;
    }

    const std::filesystem::path folder = artifact.at("directory").get<std::string>();
    ordinary(folder);
    need(std::filesystem::is_directory(folder) && artifact.at("files").is_object() &&
                 artifact.at("files").size() <= 65536,
         "artifact tree bounds");
    std::set<std::string> expected;

    for (auto it = artifact.at("files").begin(); it != artifact.at("files").end(); ++it) {
        relative(it.key());
        check_file(folder / it.key(), it.value().at("sha256").get<std::string>());
        need(it.value().at("bytes") == std::filesystem::file_size(folder / it.key()),
             "tree bytes differ");
        expected.insert(it.key());
    }

    std::set<std::string> actual;

    for (const auto &e : std::filesystem::recursive_directory_iterator(folder)) {
        need(!e.is_symlink() && (e.is_directory() || e.is_regular_file()),
             "ordinary artifact tree");

        if (e.is_regular_file()) {
            actual.insert(e.path().lexically_relative(folder).generic_string());
        }
    }

    need(expected == actual, "tree inventory differs");
}

std::string privileged_apk_target(const Json &entry) {
    const auto target = entry.at("target").get<std::string>();

    guest_path(target);
    need(std::regex_match(target,
                          std::regex(R"(/system/priv-app/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.apk)")),
         "privileged APK target must be a confined system/priv-app APK");
    need(entry.value("mode", std::string("0644")) == "0644" && entry.value("uid", 0U) == 0 &&
                 entry.value("gid", 0U) == 0 && !entry.value("mutable", false),
         "privileged APK permissions must be root:root/0644 and immutable");
    need(entry.contains("package") && entry.at("package").is_string() &&
                 std::regex_match(entry.at("package").get<std::string>(),
                                  std::regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")),
         "privileged APK requires its declared package");

    return target;
}

std::pair<Json, Json> data_install_phases(const Json &entries) {
    Json immutable = Json::array(), mutable_seeds = Json::array();

    for (const auto &entry : entries) {
        (entry.value("mutable", false) ? mutable_seeds : immutable).push_back(entry);
    }

    return {immutable, mutable_seeds};
}

namespace {
// The ELF machine of the bytes of an ELF header, or 0 for another file.
unsigned elf_machine(std::string_view header) {
    if (header.size() < 20 || header.substr(0, 4) != std::string_view("\x7f"
                                                                      "ELF",
                                                                      4)) {
        return 0;
    }

    return static_cast<unsigned char>(header[18]) |
           static_cast<unsigned>(static_cast<unsigned char>(header[19])) << 8;
}

unsigned guest_elf_machine(std::string_view abi) {
    return abi == "x86_64" ? 62 : 183;
}

// The ELF machine of a guest file, or 0 when it is absent or another file.
unsigned guest_file_elf_machine(Candidate &c, const std::string &target) {
    const auto bytes =
            c.shell({"sh", "-c", "[ ! -f \"$1\" ] || od -A n -t u1 -N 20 \"$1\"", "sh", target});
    std::istringstream values(bytes);
    std::string header;

    for (unsigned value = 0; values >> value;) {
        need(value < 256 && header.size() < 20, "guest ELF header read differs");
        header += static_cast<char>(value);
    }

    return elf_machine(header);
}

// A file whose source is ELF code of another instruction set than the guest leaves the guest file
// of the same path in place when that one is ELF code of the guest, such as a vendor shell of an
// x86_64 base; the replacement could not run before the Native Bridge starts.
bool keeps_guest_elf(Candidate &c, const std::filesystem::path &source, const std::string &target) {
    std::ifstream input(source, std::ios::binary);
    std::string header(20, '\0');

    input.read(header.data(), static_cast<std::streamsize>(header.size()));
    header.resize(static_cast<std::size_t>(input.gcount()));
    const auto guest = guest_elf_machine(android_guest_abi(c.boot_profile));
    const auto machine = elf_machine(header);

    if (!machine || machine == guest || guest_file_elf_machine(c, target) != guest) {
        return false;
    }

    c.events.push_back(
            {{"phase", "guest-elf-kept"}, {"target", target}, {"source_machine", machine}});

    return true;
}

// A line merge adds each line of the source that the guest file lacks, after its last line.
std::filesystem::path merged_lines(Candidate &c, const Json &entry,
                                   const std::filesystem::path &source) {
    need(entry.at("merge") == "lines", "registered install merge required");
    const auto target = entry.at("target").get<std::string>();
    const auto pulled = c.stage / ("merge-" + random_token());
    c.adbd({"pull", target, pulled.string()});
    const auto merged = android_candidate_merged_lines(text(pulled, 1U << 20),
                                                       text(source, 1U << 20));
    std::filesystem::remove(pulled);
    const auto output = c.stage / ("merged-" + random_token());
    write(output, merged);

    return output;
}
} // namespace

void install_entries(Candidate &c, const Json &entries, const Json &artifacts,
                     const std::filesystem::path &aapt2, std::vector<Installed> &installed,
                     progress::Meter *meter) {
    for (const auto &entry : entries) {
        const auto &artifact = entry.at("type") == "directory"
                                       ? Json::object()
                                       : artifacts.at(entry.at("artifact").get<std::string>());
        // The bytes of the entry count once it is installed.
        std::uint64_t bytes = 0;

        if (artifact.contains("file")) {
            bytes = std::filesystem::file_size(artifact.at("file").get<std::string>());
        } else if (artifact.contains("files")) {
            for (auto it = artifact.at("files").begin(); it != artifact.at("files").end(); ++it) {
                bytes += std::filesystem::file_size(
                        std::filesystem::path(artifact.at("directory").get<std::string>()) /
                        it.key());
            }
        }

        if (entry.at("type") == "apk") {
            auto item = install_apk(c, entry, artifact, aapt2);

            for (const auto &existing : installed) {
                need(existing.package.empty() || existing.package != item.package,
                     "duplicate installed package");
            }

            installed.push_back(std::move(item));

            if (entry.contains("target")) {
                install_system_native_libraries(c, entry, artifact, aapt2, installed);
            }
        } else if (entry.at("type") == "directory") {
            installed.push_back(install_directory(c, entry));
        } else if (entry.at("type") == "file") {
            const std::filesystem::path source = artifact.at("file").get<std::string>();
            const auto target = entry.at("target").get<std::string>();

            if (entry.contains("merge")) {
                check_file(source, artifact.at("sha256").get<std::string>());
                const auto merged = merged_lines(c, entry, source);
                installed.push_back(install_file(c, entry, merged, sha256_file(merged), target));
            } else if (!keeps_guest_elf(c, source, target)) {
                installed.push_back(install_file(c, entry, source,
                                                 artifact.at("sha256").get<std::string>(), target));
            }

            if (entry.at("target").get<std::string>().ends_with(".apk")) {
                install_system_native_libraries(c, entry, artifact, aapt2, installed);
            }
        } else {
            const std::filesystem::path folder = artifact.at("directory").get<std::string>();

            for (auto it = artifact.at("files").begin(); it != artifact.at("files").end(); ++it) {
                installed.push_back(install_file(
                        c, entry, folder / it.key(), it.value().at("sha256").get<std::string>(),
                        entry.at("target").get<std::string>() + "/" + it.key()));
            }
        }

        if (meter) {
            meter->advance(bytes);
        }
    }
}

void install_native_bridge(Candidate &c, const NativeBridge &bridge,
                           std::vector<Installed> &installed) {
    const auto receipt = verify_native_bridge(bridge);
    const auto &files = bridge.descriptor.at("files");
    std::vector<std::string> present = {
            "sh", "-c", "for f in \"$@\"; do [ ! -e \"$f\" ] || echo \"$f\"; done", "sh"};
    std::set<std::string> folders;

    for (const auto &[target, pin] : files.items()) {
        (void)pin;
        present.push_back(target);

        for (auto folder = std::filesystem::path(target).parent_path();
             folder.generic_string().size() > std::string_view("/system").size();
             folder = folder.parent_path()) {
            folders.insert(folder.generic_string());
        }
    }

    need(c.shell(present, 60000).empty(), "Native Bridge files already present in the base");
    std::vector<std::string> existing = {
            "sh", "-c", "for f in \"$@\"; do [ ! -d \"$f\" ] || echo \"$f\"; done", "sh"};
    existing.insert(existing.end(), folders.begin(), folders.end());
    const auto kept = lines(c.shell(existing, 60000));

    // Folders sort before their contents; each new one gets the owner and mode of system folders.
    for (const auto &folder : folders) {
        if (std::find(kept.begin(), kept.end(), folder) == kept.end()) {
            c.shell({"mkdir", folder});
            c.shell({"chmod", "0755", folder});
            c.shell({"chown", "0:0", folder});
            c.shell({"restorecon", folder});
        }
    }

    // The donated files take their mode and owner from the donor image and their labels from
    // the file contexts of the guest; the shell steps run once for all of them.
    std::map<std::string, std::vector<std::string>> modes, owners;
    std::vector<std::string> targets;

    for (const auto &[target, pin] : files.items()) {
        const auto &inode = receipt.at("files").at(target);
        const auto source = bridge.directory / target.substr(1);
        check_file(source, pin.get<std::string>(), 256ULL << 20);
        c.adbd({"push", source.string(), target}, 180000);
        char mode[8];
        std::snprintf(mode, sizeof mode, "0%03o", inode.at("mode").get<unsigned>() & 0777U);
        modes[mode].push_back(target);
        owners[std::to_string(inode.at("uid").get<unsigned>()) + ":" +
               std::to_string(inode.at("gid").get<unsigned>())]
                .push_back(target);
        targets.push_back(target);
    }

    for (const auto &[command, groups] :
         {std::pair{"chmod", &modes}, std::pair{"chown", &owners}}) {
        for (const auto &[value, paths] : *groups) {
            std::vector<std::string> arguments = {command, value};
            arguments.insert(arguments.end(), paths.begin(), paths.end());
            c.shell(arguments, 60000);
        }
    }

    std::vector<std::string> label = {"restorecon"};
    label.insert(label.end(), targets.begin(), targets.end());
    c.shell(label, 60000);
    need(native_bridge_files_pinned(c, bridge), "installed Native Bridge files differ from pins");

    for (const auto &[target, file] : bridge.descriptor.at("propertyFiles").items()) {
        const auto pulled = c.stage / ("native-bridge-" + random_token() + ".prop");
        c.adbd({"pull", target, pulled.string()});
        need(sha256_file(pulled) == file.at("inputSha256").get<std::string>(),
             "base property file differs from the Native Bridge pin: " + target);
        const auto merged = merge_android_properties(text(pulled), file.at("values"));
        need(sha256_bytes(merged) == file.at("outputSha256").get<std::string>(),
             "merged Native Bridge property file differs from its pin: " + target);
        const auto output = c.stage / ("native-bridge-" + random_token() + ".merged");
        write(output, merged);
        std::istringstream fields(c.shell({"stat", "-c", "%a %u %g", target}));
        std::vector<std::string> owner(3);
        need(bool(fields >> owner[0] >> owner[1] >> owner[2]),
             "guest property file owner required: " + target);
        installed.push_back(install_file(c,
                                         {{"artifact", "native-bridge"},
                                          {"mode", "0" + owner[0]},
                                          {"uid", std::stoul(owner[1])},
                                          {"gid", std::stoul(owner[2])}},
                                         output, sha256_bytes(merged), target));
    }

    c.events.push_back({{"phase", "native-bridge"},
                        {"files", files.size()},
                        {"property_files", bridge.descriptor.at("propertyFiles").size()}});
}

bool native_bridge_files_pinned(Candidate &c, const NativeBridge &bridge) {
    std::vector<std::string> sums = {"sha256sum"};
    const auto &files = bridge.descriptor.at("files");

    for (const auto &[target, pin] : files.items()) {
        (void)pin;
        sums.push_back(target);
    }

    std::size_t matched = 0;

    for (const auto &line : lines(c.shell(sums, 120000))) {
        const auto space = line.find("  ");

        if (space != std::string::npos && files.contains(line.substr(space + 2)) &&
            files.at(line.substr(space + 2)) == line.substr(0, space)) {
            ++matched;
        }
    }

    return matched == files.size();
}

void verify_cold_native_bridge(Candidate &c, const NativeBridge &bridge, Json &checks) {
    record_cold_check(checks, "native-bridge-files",
                      native_bridge_files_pinned(c, bridge) ? "pinned" : "differ", "pinned");

    for (const auto &[target, file] : bridge.descriptor.at("propertyFiles").items()) {
        (void)target;

        for (const auto &[key, value] : file.at("values").items()) {
            record_cold_check(checks, "native-bridge-property:" + key, c.shell({"getprop", key}),
                              value.get<std::string>());
        }
    }
}

std::string home_component(Candidate &c, const Json &config, bool establish) {
    const auto package = config.at("home").get<std::string>();

    need(std::regex_match(package, std::regex("[A-Za-z0-9_.]+")), "HOME package invalid");
    std::vector<std::string> query = {"cmd",
                                      "package",
                                      "query-activities",
                                      "--brief",
                                      "--user",
                                      "0",
                                      "-a",
                                      "android.intent.action.MAIN",
                                      "-c",
                                      "android.intent.category.HOME",
                                      "-p",
                                      package};
    const auto declared = c.shell(query);
    std::string component = config.value("homeActivity", std::string{});

    if (component.empty()) {
        const auto list = lines(declared);
        std::vector<std::string> candidates;

        for (const auto &line : list) {
            if (std::regex_match(line, std::regex("[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+"))) {
                candidates.push_back(line);
            }
        }

        need(candidates.size() == 1, "ambiguous HOME requires profile homeActivity");
        component = candidates[0];
    }

    need(home_component_declared(declared, component, package),
         "configured HOME not among declared activities");

    if (establish) {
        c.shell({"cmd", "package", "set-home-activity", "--user", "0", component});
    }

    std::string current;
    try {
        c.wait(
                [&] {
                    current = c.shell({"cmd", "package", "resolve-activity", "--brief", "--user",
                                       "0", "-a", "android.intent.action.MAIN", "-c",
                                       "android.intent.category.HOME"});
                    const auto resolved = resolved_home_component(current, package);

                    return resolved && expanded(*resolved) == expanded(component);
                },
                60000, "configured HOME ready");
    } catch (...) {
        try {
            Json report = {{"expected", component},
                           {"resolved", current},
                           {"declared", declared},
                           {"global_declared", nullptr},
                           {"global_declared_status", "unavailable"},
                           {"establish", establish},
                           {"boot", c.boots}};
            try {
                report["global_declared"] = c.shell(
                        {"cmd", "package", "query-activities", "--brief", "--user", "0", "-a",
                         "android.intent.action.MAIN", "-c", "android.intent.category.HOME"},
                        2000);
                report["global_declared_status"] = "captured";
            } catch (...) { /* Ignored: the failure report records only available evidence. */
            }

            try {
                report["role_holders"] =
                        android_home_role_holders(c.shell({"dumpsys", "role"}, 5000));
            } catch (...) { /* Ignored: the failure report records only available evidence. */
            }

            write_private_json(c.stage / "home-failure.json", report);
        } catch (...) { /* Ignored: the failure report must not replace the original failure. */
        }

        throw;
    }

    return component;
}

void prepare_a9_precompiled_policy(Candidate &c, const Json &profile,
                                   std::vector<Installed> &installed) {
    if (profile.at("android").value("offline_selinux_labels", std::string{}) !=
        "qinggan09-can-early-v1") {
        return;
    }

    need(android_candidate_api(profile) == 28, "API28 precompiled policy required");
    c.phase("selinux-precompiled");
    const auto folder = c.stage / "selinux-precompiled";
    ensure_private_directory(folder);
    const std::vector<std::pair<std::string, std::string>> inputs{
            {"compiler", "/system/bin/secilc"},
            {"init", "/init"},
            {"platform", "/system/etc/selinux/plat_sepolicy.cil"},
            {"mapping", "/system/etc/selinux/mapping/28.0.cil"},
            {"public", "/vendor/etc/selinux/plat_pub_versioned.cil"},
            {"vendor", "/vendor/etc/selinux/vendor_sepolicy.cil"}};
    need(c.shell({"cat", "/vendor/etc/selinux/plat_sepolicy_vers.txt"}) == "28.0",
         "API28 mapping version differs");
    need(c.shell({"sh", "-c",
                  "test ! -e /odm/etc/selinux/odm_sepolicy.cil && test ! -e /odm/etc/selinux/precompiled_sepolicy"}) ==
                 "",
         "unexpected ODM policy");
    Json pins = Json::object();

    for (const auto &[name, path] : inputs) {
        c.adbd({"pull", path, (folder / name).string()});
        need(std::filesystem::file_size(folder / name) > 0 &&
                     std::filesystem::file_size(folder / name) <= 16ULL << 20,
             "bounded policy input required");
        pins[path] = sha256_file(folder / name);
    }

    need(pins.at("/system/bin/secilc") ==
                         native_base_pin(profile.at("android"), "files", "/system/bin/secilc") &&
                 pins.at("/init") == native_base_pin(profile.at("android"), "files", "/init"),
         "pinned API28 compiler/init required");
    const auto version_text = c.shell({"cat", "/sys/fs/selinux/policyvers"});
    need(std::regex_match(version_text, std::regex("3[0-3]")),
         "supported kernel policy version required");
    const auto version = static_cast<unsigned>(std::stoul(version_text));
    const auto guest = "/data/local/tmp/voyemu-policy-" + c.token;
    c.shell({"mkdir", "-m", "0700", guest});
    c.shell({"/system/bin/secilc", "/system/etc/selinux/plat_sepolicy.cil", "-m", "-M", "true",
             "-G", "-N", "-c", version_text, "/system/etc/selinux/mapping/28.0.cil", "-o",
             guest + "/policy", "-f", "/sys/fs/selinux/null",
             "/vendor/etc/selinux/plat_pub_versioned.cil",
             "/vendor/etc/selinux/vendor_sepolicy.cil"},
            120000);
    c.adbd({"pull", guest + "/policy", (folder / "policy").string()});
    a9_policy_binary(text(folder / "policy"), version);
    a9_policy_required_names(text(folder / "policy"));

    for (const auto &[name, path] : inputs) {
        need(c.shell({"sha256sum", path}).substr(0, 64) == pins.at(path).get<std::string>(),
             "policy input changed during compilation");
    }

    write(folder / "identity", a9_policy_identity(text(folder / "platform", 16ULL << 20),
                                                  text(folder / "mapping", 16ULL << 20)));
    const std::vector<std::pair<std::string, std::string>> outputs{
            {"policy", "/vendor/etc/selinux/precompiled_sepolicy"},
            {"identity", "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256"},
            {"identity", "/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256"}};

    for (const auto &[name, target] : outputs) {
        const auto temporary = target + ".voyemu-pending";
        c.adbd({"push", (folder / name).string(), temporary});
        c.shell({"chmod", "0644", temporary});
        c.shell({"chown", "0:0", temporary});
        c.shell({"mv", temporary, target});
        c.shell({"restorecon", target});
        const auto hash = sha256_file(folder / name);
        need(c.shell({"sha256sum", target}).substr(0, 64) == hash,
             "published policy output differs");
        installed.erase(std::remove_if(installed.begin(), installed.end(),
                                       [&](const Installed &item) {
                                           return item.target == target;
                                       }),
                        installed.end());
        installed.push_back({"compiled-selinux-" + name, target, hash, {}, "0644", false});
    }

    c.shell({"rm", "-r", guest});
    write_private_json(folder / "receipt.json",
                       {{"schema", 1},
                        {"kernel_policy_version", version},
                        {"inputs", pins},
                        {"binary_sha256", sha256_file(folder / "policy")},
                        {"platform_mapping_identity", trim(text(folder / "identity"))}});
    c.events.push_back({{"phase", "selinux-precompiled"},
                        {"receipt_sha256", sha256_file(folder / "receipt.json")},
                        {"candidate_only", true}});
}

void verify_a9_precompiled_policy(Candidate &c, const Json &profile) {
    if (profile.at("android").value("offline_selinux_labels", std::string{}) !=
        "qinggan09-can-early-v1") {
        return;
    }

    const auto folder = c.stage / "selinux-precompiled";
    const auto receipt = read_private_json(folder / "receipt.json", 16384);
    write_private_json(folder / "policy-reader.json",
                       {{"identity", c.shell({"id"})},
                        {"context", c.shell({"id", "-Z"})},
                        {"policy", c.shell({"ls", "-lZ", "/sys/fs/selinux/policy"})}});
    c.adbd({"pull", "/sys/fs/selinux/policy", (folder / "kernel-policy").string()});
    c.root_adbd();
    need(c.shell({"getenforce"}) == "Enforcing", "compiled policy cold boot must remain enforcing");
    need(c.shell({"sha256sum", "/vendor/etc/selinux/precompiled_sepolicy"}).substr(0, 64) ==
                 receipt.at("binary_sha256").get<std::string>(),
         "cold precompiled policy differs");
    const auto identity = receipt.at("platform_mapping_identity").get<std::string>();
    need(c.shell({"cat", "/system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256"}) == identity &&
                 c.shell({"cat",
                          "/vendor/etc/selinux/precompiled_sepolicy.plat_and_mapping.sha256"}) ==
                         identity,
         "cold policy sidecars differ");
    a9_policy_binary(text(folder / "kernel-policy"),
                     receipt.at("kernel_policy_version").get<unsigned>());
    a9_policy_required_names(text(folder / "kernel-policy"));
    c.events.push_back({{"phase", "selinux-precompiled-cold-verified"},
                        {"kernel_policy_sha256", sha256_file(folder / "kernel-policy")},
                        {"enforcing", true}});
}

void configure_settings(Candidate &c, const Json &settings, bool late) {
    for (const auto &command : android_candidate_configure_settings(settings, late)) {
        c.shell(command);
    }
}

void configure_boot_properties(Candidate &c, const Json &profile,
                               std::vector<Installed> &installed) {
    const auto config = profile.value("configure", Json::object());
    const auto boot = config.value("bootProperties", Json::object());

    const bool prepared = std::any_of(installed.begin(), installed.end(), [](const auto &file) {
        return file.artifact == "oem-boot-properties";
    });

    if (!boot.empty() && !prepared) {
        c.writable();
        const auto pulled = c.stage / "system-build.prop";
        c.adbd({"pull", "/system/build.prop", pulled.string()});
        const auto modified = android_candidate_boot_properties(text(pulled), boot);
        const auto target = c.stage / "oem-build.prop";
        write(target, modified);
        std::erase_if(installed, [](const Installed &file) {
            return file.target == "/system/build.prop";
        });
        installed.push_back(install_file(c, {{"artifact", "oem-boot-properties"}, {"mode", "0644"}},
                                         target, sha256_file(target), "/system/build.prop"));
    }
}

void configure(Candidate &c, const Json &profile, std::vector<Installed> &installed) {
    const auto config = profile.value("configure", Json::object());

    configure_boot_properties(c, profile, installed);
    c.root_adbd();
    const auto primary = profile_screens(profile.at("displays")).at(0);
    const auto width = primary.width, height = primary.height;
    const auto wallpaper = c.stage / "wallpaper.png", info = c.stage / "wallpaper_info.xml";
    write(wallpaper, black_png(width, height));
    write(info, "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<wp id=\"1\" width=\"" +
                        std::to_string(width) + "\" height=\"" + std::to_string(height) +
                        "\" cropLeft=\"0\" cropTop=\"0\" cropRight=\"" + std::to_string(width) +
                        "\" cropBottom=\"" + std::to_string(height) +
                        "\" name=\"\" backup=\"true\" />\n");
    c.adbd({"push", wallpaper.string(), "/data/local/tmp/voyemu-wallpaper"});
    c.adbd({"push", info.string(), "/data/local/tmp/voyemu-wallpaper-info.xml"});
    c.shell({"mkdir", "-p", "/data/system/users/0"});
    c.shell({"cp", "/data/local/tmp/voyemu-wallpaper", "/data/system/users/0/wallpaper"});
    c.shell({"cp", "/data/local/tmp/voyemu-wallpaper-info.xml",
             "/data/system/users/0/wallpaper_info.xml"});

    for (const auto &file :
         {"/data/system/users/0/wallpaper", "/data/system/users/0/wallpaper_info.xml"}) {
        c.shell({"chown", "system:system", file});
        c.shell({"chmod", "0600", file});
        c.shell({"restorecon", file});
    }

    const auto settings = config.value("settings", Json::object());

    if (!settings.empty()) {
        c.wait(
                [&] {
                    return std::regex_search(c.shell({"service", "list"}),
                                             std::regex(R"((?:^|\n)\s*\d+\s+settings:\s*\[)"));
                },
                60000, "settings service");
        configure_settings(c, settings, false);
    }

    android_candidate_configure_properties(profile, [&](const auto &command) {
        return c.shell(command);
    });

    for (const auto &value : config.value("disabled", Json::array())) {
        c.shell({"pm", "disable-user", "--user", "0", value.get<std::string>()});
    }

    for (const auto &value : config.value("uninstalled", Json::array())) {
        const auto result = c.shell({"pm", "uninstall", "--user", "0", value.get<std::string>()});
        need(result.find("Success") != std::string::npos, "profile package uninstall failed");
    }

    if (config.contains("home")) {
        home_component(c, config, true);
        android_candidate_home_role(
                android_candidate_api(profile), config.at("home").get<std::string>(),
                [&](const auto &command) {
                    return c.shell(command);
                },
                c.home_role_poll("HOME role holder"));
    }

    for (const auto &value : config.value("overlays", Json::array())) {
        c.shell({"cmd", "overlay", "enable", "--user", "0", value.get<std::string>()});
    }

    for (const auto &command : android_candidate_start_commands(profile)) {
        c.shell(command);
    }
}

void start_qinggan11_secondary_service(
        const std::function<std::string(const std::vector<std::string> &, int)> &shell,
        const std::function<void(const std::function<bool()> &, int, const std::string &)> &wait,
        const std::function<void()> &activate_multidisplay) {
    constexpr int activity_probe_deadline_ms = 30000;
    constexpr int service_dispatch_deadline_ms = 30000;

    wait(
            [&] {
                const auto dump =
                        shell({"dumpsys", "-t", "3", "activity", "services", "com.voyemu"}, 5000);

                return dump.starts_with("ACTIVITY MANAGER SERVICES (dumpsys activity services)") &&
                       dump.find("DUMP TIMEOUT") == std::string::npos;
            },
            activity_probe_deadline_ms, "ActivityManager service dispatch readiness");

    const auto dispatch =
            shell({"am", "startservice", "-n", "com.voyemu/com.voyemu.output.SecondScreenService"},
                  service_dispatch_deadline_ms);
    need(dispatch.starts_with("Starting service: Intent {") &&
                 dispatch.find("Error:") == std::string::npos,
         "secondary screen service dispatch rejected: " + dispatch.substr(0, 1024));
    // The SDK receiver can block ActivityManager service dispatch when it starts first.
    // The bootstrap waits for the SDK display after its start request has been accepted.
    activate_multidisplay();
}

void wake_displays(Candidate &c, const Json &profile) {
    if (android_screens(profile.at("displays")).size() < 2) {
        return;
    }

    const auto features = profile.at("android").value("features", Json::object());

    if (features.value("MultiDisplay", std::string{}) != "on") {
        return;
    }

    need(c.shell({"pm", "list", "packages", "com.android.emulator.multidisplay"})
                         .find("package:com.android.emulator.multidisplay") != std::string::npos,
         "multidisplay provider missing");
    const bool bootstrap_first = original_navi_requested(profile);
    const auto activate_multidisplay = [&] {
        c.identity();
        android_candidate_start_multidisplay(c.process, c.adb, c.stage, c.port, c.remaining(30000),
                                             &c.adb_binding, &c.adb_server);
        c.identity();
    };

    if (!bootstrap_first) {
        activate_multidisplay();
    }

    if (record_declares(profile, ProfilePlatform::passion, ProfileBoard::sa8155)) {
        c.wait(
                [&] {
                    return android_candidate_secondary_provider(
                                   profile, c.shell({"dumpsys", "display"})) == 1;
                },
                30000, "actual SDK secondary display1 before OEM HOME");
    }

    // The filter of pm list packages matches substrings, so com.voyemu.oem would also match.
    const auto packages = lines(c.shell({"pm", "list", "packages", "com.voyemu"}));
    need(std::ranges::find(packages, "package:com.voyemu") != packages.end(),
         "bootstrap service missing");

    if (bootstrap_first) {
        start_qinggan11_secondary_service(
                [&](const auto &command, int timeout) {
                    return c.shell(command, timeout);
                },
                [&](const auto &ready, int timeout, const auto &message) {
                    c.wait(ready, timeout, message);
                },
                activate_multidisplay);
    } else {
        c.shell({"am", "startservice", "-n", "com.voyemu/com.voyemu.output.SecondScreenService"});
    }

    const auto config = profile.value("configure", Json::object());

    if (config.contains("home")) {
        const auto home = home_component(c, config, false);
        c.shell({"am", "start", "--user", "0", "--display", "0", "-a", "android.intent.action.MAIN",
                 "-c", "android.intent.category.HOME", "-n", home});
    }

    c.wait(
            [&] {
                return android_candidate_secondary_display_ready(
                               profile, c.shell({"dumpsys", "display"}),
                               c.shell({"dumpsys", "window", "windows"}))
                        .has_value();
            },
            120000, "owned secondary display/Home");
}

void persisted(Candidate &c, const Json &profile, const std::vector<Installed> &installed) {
    for (const auto &item : installed) {
        if (!item.package.empty()) {
            const auto result = lines(c.shell({"pm", "path", item.package}));
            need(result.size() == 1 && result[0].starts_with("package:/"),
                 "package did not survive reboot: " + item.package);
        }
    }

    const auto config = profile.value("configure", Json::object());
    const auto disabled = lines(c.shell({"pm", "list", "packages", "-d"})),
               packages = lines(c.shell({"pm", "list", "packages", "--user", "0"}));

    for (const auto &name : config.value("disabled", Json::array())) {
        need(std::find(disabled.begin(), disabled.end(), "package:" + name.get<std::string>()) !=
                     disabled.end(),
             "disabled package not persisted");
    }

    for (const auto &name : config.value("uninstalled", Json::array())) {
        need(std::find(packages.begin(), packages.end(), "package:" + name.get<std::string>()) ==
                     packages.end(),
             "uninstalled package returned");
    }

    if (config.contains("home")) {
        home_component(c, config, false);
    }
}

bool binding_ready(const std::string &dump, const std::string &component) {
    const auto start = dump.find("User 0 active services:");

    if (start == std::string::npos) {
        return false;
    }

    const auto live = dump.substr(start);
    const auto full = expanded(component);
    std::size_t at = 0;

    while (at < live.size()) {
        auto next = live.find("* ServiceRecord{", at + 1);
        const auto block = live.substr(at,
                                       next == std::string::npos ? std::string::npos : next - at);
        std::smatch name;

        if (std::regex_search(block, name, std::regex(R"(\* ServiceRecord\{\S+ u0 (\S+)\})")) &&
            expanded(name[1].str()) == full &&
            std::regex_search(block, std::regex(R"((?:^|\n)\s*app=ProcessRecord\{)")) &&
            std::regex_search(block, std::regex(R"((?:^|\n)\s*binder=(?!null(?:\s|$))\S+)")) &&
            std::regex_search(
                    block,
                    std::regex(R"((?:^|\n)\s*requested=true received=true hasBound=true\b)"))) {
            return true;
        }

        if (next == std::string::npos) {
            break;
        }

        at = next;
    }

    return false;
}
} // namespace machine_preparation_detail

void android_candidate_cold_label_plan(
        const std::string &option, std::vector<std::pair<std::string, std::string>> &file_labels,
        std::vector<std::pair<std::string, std::string>> &device_labels) {
    need(option == "qinggan09-can-early-v1" || option == "qinggan11-can-early-v1",
         "unknown cold label request");
    file_labels = {
            {"/system/bin/voyemu-early-inputs", "u:object_r:can_early_inputs_exec:s0"},
            {"/system/bin/voyemu-can-model", "u:object_r:can_simulator_exec:s0"},
            {"/system/etc/voyemu/can-model.fixture", "u:object_r:can_simulator_fixture:s0"},
            {"/system/etc/voyemu/qg-settings-guest.db", "u:object_r:can_early_input_file:s0"},
            {"/system/etc/voyemu/hybrid-nvram.img", "u:object_r:can_early_input_file:s0"}};

    if (option == "qinggan09-can-early-v1") {
        device_labels = {{"/dev/cis_can", "u:object_r:can_device:s0"},
                         {"/dev/block/vdh", "u:object_r:vdh_device:s0"}};
    } else {
        file_labels.push_back({"/vendor/overlay", "u:object_r:vendor_overlay_file:s0"});
        device_labels = {
                {"/dev/cis_can_model", "u:object_r:can_simulator_device:s0"},
                {"/dev/socket/voyemu_can_model", "u:object_r:can_simulator_socket:s0"},
                {"/dev/socket/voyemu_can_observe", "u:object_r:can_simulator_observe_socket:s0"}};
    }
}

std::string android_candidate_file_metadata(const Json &entry) {
    const auto mode = entry.value("mode", std::string("0644")),
               context = entry.at("context").get<std::string>();

    need(std::regex_match(mode, std::regex("0[0-7]{3}")), "guest mode required");
    need(std::regex_match(context, std::regex("u:object_r:[a-z0-9_]+:s0")),
         "guest file SELinux context required");
    const auto uid = entry.value("uid", 0U), gid = entry.value("gid", 0U);
    need(uid <= 65535 && gid <= 65535, "guest owner bounds");
    const auto octal = mode.substr(std::min(mode.find_first_not_of('0'), mode.size() - 1));

    return octal + " " + std::to_string(uid) + ":" + std::to_string(gid) + " " + context;
}

std::string android_candidate_write_failure(const std::string &target, const std::string &error,
                                            const std::string &shell_identity,
                                            const std::string &parent) {
    const auto at = error.rfind("': remote ");
    const auto reason =
            at == std::string::npos ? error : error.substr(at + 3, error.find('\n', at) - at - 3);

    return "guest file write failed: " + target + ": " + reason + "; diagnostic shell " +
           shell_identity + "; parent " + parent;
}
} // namespace voyemu
