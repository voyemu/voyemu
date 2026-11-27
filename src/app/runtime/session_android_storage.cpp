#include "check.hpp"
#include "error.hpp"
#include "session_internal.hpp"

namespace voyemu {
using namespace session_detail;
namespace session_detail {
constexpr std::array<const char *, 8> android_disk_files{
        {"userdata-qemu.img", "cache.img", "encryptionkey.img", "userdata-qemu.img.qcow2",
         "cache.img.qcow2", "encryptionkey.img.qcow2", "system.img.qcow2", "vendor.img.qcow2"}};

void android_regular_input(const std::filesystem::path &path) {
    if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path))) {
        throw VoyemuError("ANDROID_AVD_IMAGE", "prepared regular file required");
    }

    if (os::foreign_owner(path)) {
        throw VoyemuError("ANDROID_AVD_OWNER", "foreign input");
    }
}
} // namespace session_detail

void normalize_android_disk_backings(const std::filesystem::path &machine,
                                     const std::filesystem::path &qemu_img, const Json &binding) {
    Json system_spec = {{"machine", machine.string()}, {"api", 30}};

    if (!binding.is_null()) {
        system_spec["system_binding"] = binding;
    }

    const auto system = android_system_binding(system_spec);

    if (!binding.is_null()) {
        for (const auto &path : {system.raw, system.overlay}) {
            if (std::filesystem::canonical(path) != path) {
                throw VoyemuError("ANDROID_SYSTEM_BINDING", "linked system version rejected");
            }
        }
    }

    // The SDK rewrites system/vendor QCOW backing names to absolute host paths.
    // Only the four declared same-machine raw partitions may be made relative.
    for (const char *name :
         {"userdata-qemu.img", "encryptionkey.img", "system.img", "vendor.img"}) {
        const bool selected = std::string_view(name) == "system.img" && !binding.is_null();
        const auto overlay = selected ? system.overlay : machine / (std::string(name) + ".qcow2");
        android_regular_input(overlay);
        std::ifstream file(overlay, std::ios::binary);
        std::array<unsigned char, 24> header{};
        file.read(reinterpret_cast<char *>(header.data()), header.size());

        if (file.gcount() != static_cast<std::streamsize>(header.size()) || header[0] != 'Q' ||
            header[1] != 'F' || header[2] != 'I' || header[3] != 0xfb) {
            continue;
        }

        std::uint64_t offset = 0;
        std::uint32_t length = 0;

        for (unsigned i = 8; i < 16; ++i) {
            offset = (offset << 8) | header[i];
        }

        for (unsigned i = 16; i < 20; ++i) {
            length = (length << 8) | header[i];
        }

        if (!length) {
            continue;
        }

        if (length > 4096 || offset < 24 || offset > 65536) {
            throw VoyemuError("ANDROID_DISK_BACKING", "bounded QCOW backing path required");
        }

        std::string backing(length, '\0');
        file.seekg(static_cast<std::streamoff>(offset));
        file.read(backing.data(), length);

        if (!file || backing.find('\0') != std::string::npos) {
            throw VoyemuError("ANDROID_DISK_BACKING", "unreadable QCOW backing path");
        }

        file.close();
        auto raw = selected ? system.raw : machine / name;

        if (!std::filesystem::exists(raw)) {
            raw = machine / "base" / name;
        }

        android_regular_input(raw);
        const auto relative = raw.lexically_relative(overlay.parent_path()).generic_string();

        if (backing == relative) {
            continue;
        }

        const auto previous = std::filesystem::path(backing);

        if ((selected && previous != raw) ||
            (!selected && (previous.filename() != name ||
                           (!previous.is_absolute() && backing != std::string("base/") + name)))) {
            throw VoyemuError("ANDROID_DISK_BACKING",
                              "backing differs from declared machine partition");
        }

        ProcessSpec command;
        command.executable = qemu_img;
        command.arguments = {"rebase", "-u", "-f",     "qcow2",         "-F",
                             "raw",    "-b", relative, overlay.string()};
        command.directory = overlay.parent_path();
        const auto result = execute(command, 5000, 16384);

        if (result.timed_out || result.exit_code) {
            throw VoyemuError("ANDROID_DISK_BACKING", "portable backing normalization failed");
        }
    }
}

void prepare_android_emulator_home(const std::filesystem::path &project,
                                   const std::filesystem::path &home) {
    auto fail = []() {
        throw VoyemuError("ANDROID_EMULATOR_HOME",
                          "canonical project-owned ordinary directory required");
    };

    if (!project.is_absolute() || std::filesystem::canonical(project) != project ||
        !home.is_absolute() || home.lexically_normal() != home) {
        fail();
    }

    const auto relative = home.lexically_relative(project / ".local");

    if (relative.empty() || relative == "." || relative.is_absolute()) {
        fail();
    }

    for (const auto &part : relative) {
        if (part == "..") {
            fail();
        }
    }

    auto guard = [&] {
        for (const auto &at : os::ancestors(home)) {
            std::error_code error;
            const auto status = std::filesystem::symlink_status(at, error);

            if (error && error != std::errc::no_such_file_or_directory) {
                fail();
            }

            if (std::filesystem::is_symlink(status) ||
                (std::filesystem::exists(status) && !std::filesystem::is_directory(status))) {
                fail();
            }

            if (os::reparse_point(at)) {
                fail();
            }
        }
    };
    guard();
    ensure_private_directory(home);
    guard();

    if (std::filesystem::canonical(home) != home) {
        fail();
    }
}

void prepare_android_avd_version_marker(const std::filesystem::path &content,
                                        const std::filesystem::path &build_properties,
                                        bool required) {
    if (std::filesystem::exists(build_properties)) {
        android_regular_input(build_properties);

        if (std::filesystem::file_size(build_properties) > 65536) {
            throw VoyemuError("ANDROID_AVD_VERSION", "bounded build properties required");
        }

        std::ifstream properties(build_properties);
        std::string line;
        int incremental = -1;
        bool found = false;
        constexpr std::string_view key = "ro.build.version.incremental=";

        while (std::getline(properties, line)) {
            if (line.starts_with(key)) {
                if (found) {
                    throw VoyemuError("ANDROID_AVD_VERSION", "duplicate incremental version");
                }

                found = true;
                auto value = line.substr(key.size());

                if (!value.empty() && value.back() == '\r') {
                    value.pop_back();
                }

                const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(),
                                                          incremental);

                if (error != std::errc{} || end != value.data() + value.size() || incremental < 0) {
                    throw VoyemuError("ANDROID_AVD_VERSION",
                                      "numeric system-image incremental version required");
                }
            }
        }

        if (!found || properties.bad()) {
            throw VoyemuError("ANDROID_AVD_VERSION", "system-image incremental version missing");
        }

        const auto marker = content / "version_num.cache";

        if (std::filesystem::exists(marker) || std::filesystem::is_symlink(marker)) {
            android_regular_input(marker);

            if (std::filesystem::hard_link_count(marker) != 1) {
                throw VoyemuError("ANDROID_AVD_VERSION", "linked runtime marker rejected");
            }
        }

        const auto pending_version = content / ("version_num.cache." + random_token() + ".pending");
        std::ofstream version(pending_version, std::ios::binary);
        version << incremental << '\n';
        version.close();

        if (!version) {
            throw VoyemuError("ANDROID_AVD_VERSION", "runtime marker write failed");
        }

        std::filesystem::rename(pending_version, marker);
    } else if (required) {
        throw VoyemuError("ANDROID_AVD_VERSION", "selected sysdir build properties missing");
    }
}

std::filesystem::path session_detail::prepare_android_avd_impl(
        const std::filesystem::path &home, const std::filesystem::path &machine,
        const std::string &avd, const std::filesystem::path &source,
        const std::string &config_sha256, const std::filesystem::path &base, bool machine_start,
        unsigned api, bool diagnostic_native, const std::filesystem::path &runtime,
        const Json &binding, const std::filesystem::path &previous_machine) {
    if (api != 28 && api != 30) {
        throw VoyemuError("ANDROID_AVD", "supported API28/API30 required");
    }

    if (!home.is_absolute() || !machine.is_absolute() || avd.empty() ||
        !std::all_of(avd.begin(), avd.end(),
                     [](unsigned char c) {
                         return std::isalnum(c) || c == '_' || c == '-' || c == '.';
                     }) ||
        avd == "." || avd == "..") {
        throw VoyemuError("ANDROID_AVD", "invalid private locator");
    }

    android_regular_input(source);

    if (std::filesystem::file_size(source) > 65536 ||
        (!machine_start && (config_sha256.size() != 64 || sha256_file(source) != config_sha256))) {
        throw VoyemuError("LAUNCH_PIN", "immutable AVD template mismatch");
    }

    Json system_spec = {{"machine", machine.string()},
                        {"base", (base.empty() ? machine / "base" : base).string()},
                        {"api", api}};

    if (!binding.is_null()) {
        system_spec["system_binding"] = binding;
    }

    const auto system = android_system_binding(system_spec);

    if (!binding.is_null()) {
        for (const auto &path : {system.raw, system.overlay}) {
            if (std::filesystem::canonical(path) != path) {
                throw VoyemuError("ANDROID_SYSTEM_BINDING", "linked system version rejected");
            }
        }
    }

    for (auto name : android_disk_files) {
        if (std::string_view(name) != "cache.img" && std::string_view(name) != "cache.img.qcow2") {
            android_regular_input(std::string_view(name) == "system.img.qcow2" ? system.overlay
                                                                               : machine / name);
        }
    }

    for (const char *name : {"system.img", "vendor.img"}) {
        android_regular_input(std::string_view(name) == "system.img"
                                      ? system.raw
                                      : (base.empty() ? machine / "base" : base) / name);
    }

    const auto content = runtime.empty() ? home / "content" : runtime;
    auto config = content / "config.ini";

    if (source == config ||
        (std::filesystem::exists(config) && std::filesystem::equivalent(source, config))) {
        throw VoyemuError("ANDROID_AVD", "template must be independent of SDK config");
    }

    ensure_private_directory(home);
    auto locator = home / (avd + ".ini");

    if (std::filesystem::exists(locator)) {
        throw VoyemuError("ANDROID_AVD", "fresh session locator required");
    }

    auto pending = content / "config.ini.voyemu-pending";

    if (std::filesystem::exists(pending)) {
        throw VoyemuError("ANDROID_AVD", "prepared config write in progress");
    }

    ensure_private_directory(content);
    std::ifstream input(source, std::ios::binary);

    if (!input) {
        throw VoyemuError("ANDROID_AVD", "prepared config read failed");
    }

    auto text = android_quickboot_config(std::string{std::istreambuf_iterator<char>(input), {}});
    text = native_backend_avd_config(std::move(text), diagnostic_native,
                                     base.empty() ? machine / "base" : base);
    const auto locator_machine = native_backend_path(content, diagnostic_native);
    os::ExclusiveFile file(pending);

    if (!file.open()) {
        throw VoyemuError("ANDROID_AVD", "exclusive runtime config failed");
    }

    const bool complete = file.write(text.data(), text.size()) && file.sync();
    file.close();

    if (!complete) {
        std::filesystem::remove(pending);
        throw VoyemuError("ANDROID_AVD", "runtime config write failed");
    }

    if (!os::replace_file(pending, config)) {
        throw VoyemuError("ANDROID_AVD", "runtime config replacement failed");
    }

    prepare_android_avd_version_marker(
            content, (base.empty() ? machine / "base" : base) / "build.prop", machine_start);
    // The SDK always opens system/vendor overlays beside the AVD configuration.
    // AvdInfo also needs the encryption raw image here to select the correct boot-device MMIO
    // index. Link required disks to the portable machine; never copy them.
    const auto same_storage = [=](const std::filesystem::path &a, const std::filesystem::path &b) {
        if (std::filesystem::equivalent(a, b)) {
            return true;
        }

        return diagnostic_native && native_backend_same_file(a, b);
    };

    for (const char *name : {"system.img.qcow2", "vendor.img.qcow2", "system.img", "vendor.img",
                             "encryptionkey.img"}) {
        const bool selected = !binding.is_null() && (std::string_view(name) == "system.img" ||
                                                     std::string_view(name) == "system.img.qcow2");
        auto disk = selected
                            ? (std::string_view(name) == "system.img" ? system.raw : system.overlay)
                            : machine / name;
        const auto alias = content / name;

        if (!std::filesystem::exists(disk)) {
            disk = (base.empty() ? machine / "base" : base) / name;
        }

        android_regular_input(disk);
        auto status = std::filesystem::symlink_status(alias);

        if (!previous_machine.empty() && std::filesystem::is_symlink(status) &&
            !std::filesystem::exists(alias)) {
            const auto reject = []() {
                throw VoyemuError("ANDROID_AVD_RELOCATION",
                                  "exact owned dangling prior-machine alias required");
            };

            if (!previous_machine.is_absolute() ||
                previous_machine.lexically_normal() != previous_machine ||
                previous_machine == machine || previous_machine.filename() != machine.filename() ||
                previous_machine.parent_path().filename() != machine.parent_path().filename()) {
                reject();
            }

            terminal_path_guard(previous_machine);
            terminal_path_guard(content);

            if (std::filesystem::exists(previous_machine.parent_path())) {
                reject();
            }

            const auto relative = disk.lexically_relative(machine);

            if (relative.empty() || relative.is_absolute()) {
                reject();
            }

            for (const auto &part : relative) {
                if (part == "..") {
                    reject();
                }
            }

            if (std::filesystem::read_symlink(alias) != previous_machine / relative) {
                reject();
            }

            if (!owned_symlink(alias)) {
                reject();
            }

            if (!std::filesystem::remove(alias)) {
                reject();
            }

            status = std::filesystem::symlink_status(alias);
        }

        if (selected && (std::filesystem::exists(status) || std::filesystem::is_symlink(status)) &&
            !same_storage(disk, alias)) {
            const auto owned = [&](const std::filesystem::path &candidate) {
                return std::filesystem::is_regular_file(
                               std::filesystem::symlink_status(candidate)) &&
                       std::filesystem::canonical(candidate) == candidate &&
                       same_storage(candidate, alias);
            };
            bool previous = owned(machine / name) ||
                            owned((base.empty() ? machine / "base" : base) / name);
            const auto versions = machine / "system-versions";

            if (!previous && std::filesystem::is_directory(versions) &&
                std::filesystem::canonical(versions) == versions) {
                unsigned count = 0;

                for (const auto &entry : std::filesystem::directory_iterator(versions)) {
                    if (++count > 128) {
                        throw VoyemuError("ANDROID_AVD_STORAGE",
                                          "version inventory bound exceeded");
                    }

                    const auto sha = entry.path().filename().string();

                    if (sha256_text(sha) && owned(entry.path() / name)) {
                        previous = true;
                        break;
                    }
                }
            }

            if (!previous) {
                throw VoyemuError("ANDROID_AVD_STORAGE", "foreign system alias retained");
            }

            std::filesystem::remove(alias);
            status = std::filesystem::symlink_status(alias);
        }

        if (std::filesystem::exists(status) || std::filesystem::is_symlink(status)) {
            if (!same_storage(disk, alias)) {
                throw VoyemuError("ANDROID_AVD_STORAGE", "runtime overlay alias differs");
            }
        } else {
            link_overlay(disk, alias);
        }

        if (!same_storage(disk, alias)) {
            throw VoyemuError("ANDROID_AVD_STORAGE", "persistent overlay alias unavailable");
        }
    }

    // SDK configuration, locks and snapshots are session-local; image arguments retain installed
    // data.
    {
        std::ofstream file(locator, std::ios::binary);
        file << "avd.ini.encoding=UTF-8\npath=" << locator_machine << "\ntarget=android-" << api
             << '\n';

        if (!file) {
            throw VoyemuError("ANDROID_AVD", "locator write failed");
        }
    }
    write_private_json(home / "prepared-inputs.json",
                       {{"schema", 1},
                        {"source_machine", machine.string()},
                        {"content", content.string()},
                        {"config_template", source.string()},
                        {"template_sha256", config_sha256},
                        {"userdata_path", (machine / "userdata-qemu.img").string()},
                        {"disk_paths", android_disk_files},
                        {"system_specification", system_spec}});

    return content;
}

std::filesystem::path
prepare_android_avd(const std::filesystem::path &home, const std::filesystem::path &machine,
                    const std::string &avd, const std::filesystem::path &source,
                    const std::string &config_sha256, const std::filesystem::path &base,
                    unsigned api, const Json &binding,
                    const std::filesystem::path &previous_machine) {
    return prepare_android_avd_impl(home, machine, avd, source, config_sha256, base, false, api,
                                    false, {}, binding, previous_machine);
}

void session_detail::verify_android_avd_storage_impl(const std::filesystem::path &home,
                                                     const std::filesystem::path &machine,
                                                     const std::string &avd, bool machine_start,
                                                     bool diagnostic_native,
                                                     const Json &specification) {
    auto inputs = read_private_json(home / "prepared-inputs.json", 4096);

    if (inputs.at("source_machine").get<std::string>() != machine.string() ||
        (!machine_start && sha256_file(inputs.at("config_template").get<std::string>()) !=
                                   inputs.at("template_sha256").get<std::string>())) {
        throw VoyemuError("ANDROID_AVD_STORAGE", "immutable prepared template changed");
    }

    if (!specification.is_null() &&
        inputs.at("system_specification").value("system_binding", Json()) !=
                specification.value("system_binding", Json())) {
        throw VoyemuError("ANDROID_AVD_STORAGE", "selected system binding changed");
    }

    const auto locator_machine = native_backend_path(inputs.at("content").get<std::string>(),
                                                     diagnostic_native);
    std::ifstream locator(home / (avd + ".ini"));
    std::string text{std::istreambuf_iterator<char>(locator), {}};

    if (text.find("path=" + locator_machine + "\n") == std::string::npos) {
        throw VoyemuError("ANDROID_AVD_STORAGE", "prepared machine locator changed");
    }

    const auto system = android_system_binding(
            inputs.value("system_specification", Json{{"machine", machine.string()}}));

    for (auto name : android_disk_files) {
        if (std::string_view(name) != "cache.img" && std::string_view(name) != "cache.img.qcow2") {
            android_regular_input(std::string_view(name) == "system.img.qcow2" ? system.overlay
                                                                               : machine / name);
        }
    }
}

void verify_android_avd_storage(const std::filesystem::path &home,
                                const std::filesystem::path &machine, const std::string &avd) {
    verify_android_avd_storage_impl(home, machine, avd, false);
}
} // namespace voyemu
