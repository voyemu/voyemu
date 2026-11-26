#include "native_component.hpp"
#include "base_image.hpp"
#include "check.hpp"
#include "deps.hpp"
#include "download.hpp"
#include "error.hpp"
#include "logging.hpp"
#include "ordinary_path.hpp"
#include "os/fs.hpp"
#include "process.hpp"
#include "profile_catalog.hpp"
#include "quickboot.hpp"
#include "source_edits.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <map>
#include <regex>
#include <set>
namespace voyemu {
namespace {
void ordinary(const std::filesystem::path &path) {
    ordinary_path(path, Check{"COMPONENT_PATH"}, PathForm::Canonical,
                  "canonical ordinary input required", "linked ancestor rejected");
}

Json source_inventory(const std::filesystem::path &source) {
    ordinary(source);

    if (!std::filesystem::is_directory(source)) {
        throw VoyemuError("COMPONENT_SOURCE", "source directory required");
    }

    Json files = Json::array();
    std::uint64_t total = 0;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(source)) {
        if (entry.is_symlink() || (!entry.is_directory() && !entry.is_regular_file())) {
            throw VoyemuError("COMPONENT_SOURCE", "ordinary source tree required");
        }

        if (entry.is_directory()) {
            continue;
        }

        const auto size = entry.file_size();

        if (files.size() >= 4096 || size > (32ULL << 20) - total ||
            std::filesystem::hard_link_count(entry.path()) != 1) {
            throw VoyemuError("COMPONENT_BOUND", "source tree outside bounds");
        }

        total += size;
        const auto epoch = cache_file_identity(entry.path());
        const auto hash = sha256_file(entry.path());

        if (cache_file_identity(entry.path()) != epoch) {
            throw VoyemuError("COMPONENT_CHANGED", "source changed during hashing");
        }

        files.push_back({{"path", entry.path().lexically_relative(source).generic_string()},
                         {"sha256", hash},
                         {"bytes", size}});
    }

    std::sort(files.begin(), files.end(), [](const Json &a, const Json &b) {
        return a.at("path").get<std::string>() < b.at("path").get<std::string>();
    });

    return files;
}

void valid_output_name(const std::string &output, bool executable) {
    if (executable ? (!std::regex_match(output, std::regex(R"(^[A-Za-z0-9_][A-Za-z0-9_-]*$)")))
                   : (!std::regex_match(output, std::regex(R"(^lib[A-Za-z0-9_]+\.so$)")))) {
        throw VoyemuError("COMPONENT_OUTPUT", "invalid native output name");
    }
}

void elf(const std::filesystem::path &file, std::string_view abi, bool executable) {
    if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(file)) ||
        std::filesystem::file_size(file) < 64 || std::filesystem::file_size(file) > 128ULL << 20) {
        throw VoyemuError("COMPONENT_ELF", "bounded output required");
    }

    std::ifstream input(file, std::ios::binary);
    unsigned char h[64]{};
    input.read(reinterpret_cast<char *>(h), sizeof h);

    if (!input || h[0] != 127 || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' || h[4] != 2 ||
        h[5] != 1 || h[16] != 3 || h[17] != 0 || h[18] != (abi == "x86_64" ? 62 : 183) ||
        h[19] != 0) {
        throw VoyemuError("COMPONENT_ELF", std::string(abi) + " ELF required");
    }

    if (executable) {
        auto field = [](const unsigned char *data, int at, int bytes) {
            std::uint64_t value = 0;

            for (int i = bytes - 1; i >= 0; --i) {
                value = (value << 8) | data[at + i];
            }

            return value;
        };
        const auto entry = field(h, 24, 8), offset = field(h, 32, 8), size = field(h, 54, 2),
                   count = field(h, 56, 2);
        const auto length = std::filesystem::file_size(file);

        if (h[6] != 1 || field(h, 20, 4) != 1 || field(h, 52, 2) != 64 || size != 56 || !count ||
            offset > length || count > (length - offset) / size) {
            throw VoyemuError("COMPONENT_ELF", "invalid executable header");
        }

        struct Segment {
            std::uint64_t type, flags, offset, address, filesz, memsz, align;
        };
        std::vector<Segment> segments;

        for (std::uint64_t i = 0; i < count; ++i) {
            unsigned char ph[56]{};
            input.seekg(offset + i * size);
            input.read(reinterpret_cast<char *>(ph), sizeof ph);

            if (!input) {
                throw VoyemuError("COMPONENT_ELF", "invalid program headers");
            }

            Segment p{field(ph, 0, 4),  field(ph, 4, 4),  field(ph, 8, 8), field(ph, 16, 8),
                      field(ph, 32, 8), field(ph, 40, 8), field(ph, 48, 8)};

            if (p.type == 1 && (p.filesz > p.memsz || p.offset > length ||
                                p.filesz > length - p.offset || p.memsz > UINT64_MAX - p.address ||
                                (p.align > 1 && ((p.align & (p.align - 1)) ||
                                                 p.offset % p.align != p.address % p.align)))) {
                throw VoyemuError("COMPONENT_ELF", "invalid load segment");
            }

            segments.push_back(p);
        }

        auto mapped = [&](const Segment &p) {
            for (const auto &load : segments) {
                if (load.type == 1 && p.offset >= load.offset && p.address >= load.address &&
                    p.offset - load.offset == p.address - load.address &&
                    p.offset - load.offset <= load.filesz &&
                    p.filesz <= load.filesz - (p.offset - load.offset)) {
                    return true;
                }
            }

            return false;
        };
        bool entry_mapped = false, interpreter = false, pie = false, dynamic_seen = false;

        for (const auto &p : segments) {
            if (p.type == 1 && (p.flags & 1) && entry >= p.address &&
                entry - p.address < p.filesz) {
                entry_mapped = true;
            }

            if (p.type == 2) {
                if (dynamic_seen || !mapped(p) || !p.filesz || p.filesz % 16) {
                    throw VoyemuError("COMPONENT_ELF", "invalid dynamic segment");
                }

                dynamic_seen = true;
                bool terminated = false;

                for (std::uint64_t at = 0; at < p.filesz; at += 16) {
                    unsigned char d[16]{};
                    input.seekg(p.offset + at);
                    input.read(reinterpret_cast<char *>(d), 16);

                    if (!input) {
                        throw VoyemuError("COMPONENT_ELF", "invalid dynamic segment");
                    }

                    const auto tag = field(d, 0, 8), value = field(d, 8, 8);

                    if (!tag) {
                        terminated = true;
                        break;
                    }

                    if (tag == 0x6ffffffb && (value & 0x08000000)) {
                        pie = true;
                    }
                }

                if (!terminated) {
                    throw VoyemuError("COMPONENT_ELF", "unterminated dynamic segment");
                }
            }

            if (p.type == 3) {
                if (interpreter || !mapped(p)) {
                    throw VoyemuError("COMPONENT_ELF", "invalid interpreter segment");
                }

                interpreter = true;
                const std::string expected = "/system/bin/linker64";

                if (p.filesz != expected.size() + 1) {
                    throw VoyemuError("COMPONENT_ELF", "Android ARM64 interpreter required");
                }

                std::string actual(p.filesz, '\0');
                input.seekg(p.offset);
                input.read(actual.data(), p.filesz);

                if (!input || actual != expected + std::string(1, '\0')) {
                    throw VoyemuError("COMPONENT_ELF", "Android ARM64 interpreter required");
                }
            }
        }

        if (!entry_mapped || !interpreter || !dynamic_seen || !pie) {
            throw VoyemuError("COMPONENT_ELF", "Android PIE executable required");
        }
    }
}
} // namespace

std::filesystem::path native_component_sources(const std::filesystem::path &root,
                                               const std::filesystem::path &component,
                                               const std::filesystem::path &work) {
    const auto definition = read_private_json(component / "component.json");

    if (!definition.contains("sourceFiles")) {
        return component;
    }

    const auto &shared = definition.at("sourceFiles");

    if (!shared.is_object() || shared.empty() || shared.size() > 64 ||
        definition.contains("externalSources") || definition.contains("upstreamEdits")) {
        throw VoyemuError("COMPONENT_RECIPE", "bounded shared sources without external edits");
    }

    if (std::filesystem::exists(std::filesystem::symlink_status(work))) {
        throw VoyemuError("COMPONENT_OUTPUT", "fresh shared source directory required");
    }

    std::filesystem::create_directories(work);

    for (const auto &entry : source_inventory(component)) {
        const auto relative = entry.at("path").get<std::string>();
        std::filesystem::create_directories((work / relative).parent_path());
        std::filesystem::copy_file(component / relative, work / relative);
    }

    // The same resource names as the sourceFiles of an APK component, confined to common sources.
    const std::regex name(R"(src/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.c)"),
            resource(R"(voyemu/profiles/common/components/[a-z0-9][a-z0-9._-]{0,127}/src/)"
                     R"([A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.c)");

    for (auto it = shared.begin(); it != shared.end(); ++it) {
        const auto value = it.value().is_string() ? it.value().get<std::string>() : std::string{};

        if (!std::regex_match(it.key(), name) || !std::regex_match(value, resource)) {
            throw VoyemuError("COMPONENT_PATH", "confined common component source required");
        }

        const auto source = root / value.substr(std::string("voyemu/").size());
        ordinary(source);
        const auto target = work / it.key();

        if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(source)) ||
            std::filesystem::hard_link_count(source) != 1) {
            throw VoyemuError("COMPONENT_SOURCE", "ordinary common source required");
        }

        if (std::filesystem::exists(std::filesystem::symlink_status(target))) {
            throw VoyemuError("COMPONENT_SOURCE", "shared source would overwrite local source");
        }

        std::filesystem::create_directories(target.parent_path());
        std::filesystem::copy_file(source, target);
    }

    return work;
}

Json build_native_component(const std::filesystem::path &source,
                            const std::filesystem::path &compiler, const std::string &compiler_pin,
                            const std::filesystem::path &destination, std::uint64_t reserve,
                            std::function<std::uint64_t()> available_space,
                            std::string_view guest_abi) {
    const auto sources = source_inventory(source);
    const auto definition = read_private_json(source / "component.json");
    const auto recipe_api = definition.at("minSdk").get<int>();

    if (definition.at("type") != "native" || (recipe_api != 28 && recipe_api != 30)) {
        throw VoyemuError("COMPONENT_RECIPE", "native API28/API30 recipe required");
    }

    const auto abi = native_component_abi(definition, guest_abi);
    const auto target = "--target=" + std::string(abi == "x86_64" ? "x86_64" : "aarch64") +
                        "-linux-android" + std::to_string(recipe_api);
    Json materialized = Json::object();
    std::set<std::string> guest_sonames;

    if (definition.contains("externalSources") || definition.contains("upstreamEdits") ||
        definition.contains("guestLibs")) {
        if (!std::filesystem::is_regular_file(
                    std::filesystem::symlink_status(source / "native-sources.json"))) {
            throw VoyemuError(
                    "COMPONENT_RECIPE",
                    "external source edits and guest libraries require materialized native inputs");
        }

        materialized = read_private_json(source / "native-sources.json");
        Json files = Json::object();

        for (const auto &entry : sources) {
            const auto name = entry.at("path").get<std::string>();

            if (name != "native-sources.json") {
                files[name] = {{"bytes", entry.at("bytes")}, {"sha256", entry.at("sha256")}};
            }
        }

        if (materialized.value("schema", 0) != 1 || !materialized.value("native", false) ||
            materialized.at("files") != files.size() ||
            materialized.at("definition_sha256") != sha256_file(source / "component.json") ||
            materialized.at("source_tree_sha256") != sha256_bytes(files.dump())) {
            throw VoyemuError("COMPONENT_INPUTS",
                              "materialized source receipt differs from source tree");
        }
    }

    const auto declared_guests = definition.value("guestLibs", Json::array());

    if (!declared_guests.is_array() || declared_guests.size() > 32) {
        throw VoyemuError("COMPONENT_INPUTS", "bounded guest library list required");
    }

    // Guest libraries link as stubs that carry only their soname: the imports stay undefined for
    // the Android linker, and preparation checks that the libraries of the image export them.
    for (const auto &value : declared_guests) {
        const auto name = value.get<std::string>();

        if (!std::regex_match(name, std::regex(R"(^/system/lib64/lib[A-Za-z0-9_.]+\.so$)")) ||
            !guest_sonames.insert(std::filesystem::path(name).filename().string()).second) {
            throw VoyemuError("COMPONENT_INPUTS",
                              "unique 64-bit system shared library path required");
        }
    }

    const auto output_type = definition.value("outputType", std::string("shared-library"));

    if (output_type != "shared-library" && output_type != "executable") {
        throw VoyemuError("COMPONENT_RECIPE", "unknown native output type");
    }

    const bool executable = output_type == "executable";
    const auto output = definition.at("output").get<std::string>();

    valid_output_name(output, executable);

    ordinary(compiler);

    if (!std::filesystem::is_regular_file(compiler) || compiler_pin.size() != 64 ||
        sha256_file(compiler) != compiler_pin) {
        throw VoyemuError("COMPONENT_TOOL", "pinned native compiler required");
    }

    const auto compiler_epoch = cache_file_identity(compiler);

    if (!destination.is_absolute() || destination.lexically_normal() != destination ||
        std::filesystem::exists(destination) || std::filesystem::is_symlink(destination)) {
        throw VoyemuError("COMPONENT_OUTPUT", "fresh absolute destination required");
    }

    auto existing = destination.parent_path();

    while (!std::filesystem::exists(existing)) {
        existing = existing.parent_path();
    }

    constexpr std::uint64_t allowance = 256ULL << 20;

    if (reserve > std::numeric_limits<std::uint64_t>::max() - allowance) {
        throw VoyemuError("COMPONENT_SPACE", "reserve overflow");
    }

    if ((available_space ? available_space() : std::filesystem::space(existing).available) <
        reserve + allowance) {
        throw VoyemuError("COMPONENT_SPACE", "reserve plus bounded build required");
    }

    std::vector<std::string> translation_units;
    bool cxx = false, c_units = false;
    std::set<std::filesystem::path> includes;

    for (const auto &entry : sources) {
        const std::filesystem::path relative = entry.at("path").get<std::string>();
        const auto extension = relative.extension();

        if (relative.generic_string().starts_with("src/") &&
            (extension == ".c" || extension == ".cc" || extension == ".cpp" ||
             extension == ".cxx")) {
            translation_units.push_back((source / relative).string());
            cxx = cxx || extension != ".c";
            c_units = c_units || extension == ".c";
        }

        if (relative.generic_string().starts_with("include/")) {
            includes.insert(source / "include");
            const auto tail = relative.lexically_relative("include");

            if (tail.has_parent_path()) {
                includes.insert(source / "include" / *tail.begin());
            }
        }
    }

    if (translation_units.empty()) {
        throw VoyemuError("COMPONENT_SOURCE", "native translation units missing");
    }

    if (cxx && c_units) {
        throw VoyemuError("COMPONENT_RECIPE",
                          "mixed C/C++ units require separate translation commands");
    }

    ensure_private_directory(destination.parent_path());

    if (!std::filesystem::create_directory(destination)) {
        throw VoyemuError("COMPONENT_OUTPUT", "exclusive stage required");
    }

    const auto token = random_token();
    write_private_json(destination / ".owner.json", {{"token", token}});
    struct Cleanup {
        std::filesystem::path path;
        std::string token;
        bool published = false;

        ~Cleanup() {
            if (published) {
                return;
            }

            try {
                if (read_private_json(path / ".owner.json").at("token") == token) {
                    std::filesystem::remove_all(path);
                }
            } catch (...) { /* Ignored: cleanup of owned temporary state is best-effort. */
            }
        }
    } cleanup{destination, token};
    ProcessSpec command;
    command.executable = compiler;
    command.directory = destination;
    command.output = destination / "build.log";
    command.environment = {{"JAVA_HOME", "/nonexistent"},
                           {"NODE_PATH", "/nonexistent"},
                           {"TMPDIR", destination.string()},
                           {"TMP", destination.string()},
                           {"TEMP", destination.string()}};
    command.arguments = {
            target, executable ? "-pie" : "-shared", executable ? "-fPIE" : "-fPIC",  "-O2",
            "-g0",  cxx ? "-std=c++17" : "-std=c11", "-I" + (source / "src").string()};

    if (guest_sonames.empty()) {
        command.arguments.insert(command.arguments.end() - 1, "-Wl,--no-undefined");
    }

    if (!executable) {
        command.arguments.insert(command.arguments.end() - 1, "-Wl,-soname," + output);
    }

    if (cxx) {
        command.arguments.insert(command.arguments.end(),
                                 {"-DANDROID", "-static-libstdc++", "-fno-rtti",
                                  "-Wno-invalid-specialization", "-Wno-unused-parameter",
                                  "-Wno-deprecated-literal-operator",
                                  "-Wno-inconsistent-missing-override"});
    }

    for (const auto &include : includes) {
        command.arguments.push_back("-I" + include.string());
    }

    command.arguments.insert(command.arguments.end(), translation_units.begin(),
                             translation_units.end());

    for (const auto &name : definition.value("libs", Json::array())) {
        const auto library = name.get<std::string>();

        if (!std::regex_match(library, std::regex("[a-z][a-z0-9_]*"))) {
            throw VoyemuError("COMPONENT_RECIPE", "ordinary SDK library name required");
        }

        command.arguments.push_back("-l" + library);
    }

    if (!guest_sonames.empty()) {
        const auto stubs = destination / "guest-stubs";
        ensure_private_directory(stubs);
        std::ofstream(stubs / "stub.c").close();

        for (const auto &soname : guest_sonames) {
            ProcessSpec stub = command;
            stub.arguments = {target,
                              "-shared",
                              "-nostdlib",
                              "-Wl,-soname," + soname,
                              (stubs / "stub.c").string(),
                              "-o",
                              (stubs / soname).string()};
            const auto linked = execute(stub, 300000, 128 * 1024);

            if (linked.exit_code || linked.timed_out) {
                throw VoyemuError("COMPONENT_COMPILE", "guest library stub failed");
            }
        }

        command.arguments.push_back("-L" + stubs.string());

        for (const auto &soname : guest_sonames) {
            command.arguments.push_back("-l:" + soname);
        }
    }

    // The .comment section would keep the identity strings of the host builds of clang and LLD,
    // which differ between the Linux, macOS and Windows NDK; without it every host links the same
    // bytes.
    const auto script = destination / "reproducible.ld";
    {
        std::ofstream(script)
                << "SECTIONS {\n  /DISCARD/ : { *(.comment) }\n}\nINSERT AFTER .text;\n";
    }
    command.arguments.insert(command.arguments.end(), {"-Xlinker", "--script=" + script.string(),
                                                       "-o", (destination / output).string()});
    const auto compiled = execute(command, 300000, 128 * 1024);

    if (compiled.exit_code || compiled.timed_out) {
        throw VoyemuError("COMPONENT_COMPILE", "native clang compilation failed");
    }

    elf(destination / output, abi, executable);
    std::filesystem::remove_all(destination / "guest-stubs");
    std::filesystem::remove(script);

    if (source_inventory(source) != sources || cache_file_identity(compiler) != compiler_epoch ||
        sha256_file(compiler) != compiler_pin) {
        throw VoyemuError("COMPONENT_CHANGED", "source or compiler changed during build");
    }

    materialized.erase("definition_sha256");
    materialized.erase("source_tree_sha256");
    Json result = {{"schema", 1},
                   {"type", "native"},
                   {"api", recipe_api},
                   {"abi", abi},
                   {"output", output},
                   {"bytes", std::filesystem::file_size(destination / output)},
                   {"sha256", sha256_file(destination / output)},
                   {"compiler_sha256", compiler_pin},
                   {"language", cxx ? "c++17" : "c11"},
                   {"guest_sonames", guest_sonames},
                   {"materialized_source", materialized},
                   {"command", command.arguments},
                   {"host_java_required", false},
                   {"host_node_required", false},
                   {"host_python_required", false}};

    if (executable) {
        result["output_type"] = "executable";
    }

    write_private_json(destination / "receipt.json", result);
    std::filesystem::remove(destination / ".owner.json");
    cleanup.published = true;

    return result;
}

std::string native_component_pin(const std::string &profile, const std::string &component,
                                 const Json &definition) {
    return definition.value("pin", profile + "/" + component);
}

std::string native_component_abi(const Json &definition, std::string_view guest) {
    const auto abi = definition.value("abi", std::string(guest));
    // Native Bridge translates only shared libraries of ARM64 OEM processes in an x86_64 guest.
    const bool bridged = guest == "x86_64" && abi == "arm64-v8a" &&
                         definition.value("outputType", std::string("shared-library")) ==
                                 "shared-library";

    if ((abi != "arm64-v8a" && abi != "x86_64") || (abi != guest && !bridged)) {
        throw VoyemuError("COMPONENT_RECIPE", "unsupported native component ABI for this guest");
    }

    return abi;
}

Json native_component_origin(const Json &pins, const std::string &key, const Json &definition) {
    const bool local = definition.contains("sourceBuildSha256");

    if (local && (definition.contains("pin") || pins.contains(key))) {
        throw VoyemuError("COMPONENT_PIN", "ambiguous native component source");
    }

    if (!local && !pins.contains(key)) {
        throw VoyemuError("COMPONENT_PIN", "missing native component pin: " + key);
    }

    auto origin = local ? Json{{"source", "recipe"}, {"sha256", definition.at("sourceBuildSha256")}}
                        : Json{{"asset", pins.at(key).at("url")},
                               {"sha256", pins.at(key).at("sha256")}};

    if (!origin.at("sha256").is_string() || !sha256_text(origin.at("sha256").get<std::string>())) {
        throw VoyemuError("COMPONENT_PIN", "invalid native component SHA-256: " + key);
    }

    return origin;
}

namespace {
std::string_view profile_guest_abi(const std::filesystem::path &root, const std::string &profile) {
    const auto definition = authoring_profile(root, profile);

    if (!definition.contains("android")) {
        return "arm64-v8a";
    }

    return android_package_identity(definition.at("android").value("package", std::string{})).abi;
}

// The declared native component source of a profile and its definition.
std::pair<std::filesystem::path, Json> profile_native_component(const std::filesystem::path &root,
                                                                const std::string &profile,
                                                                const std::string &component) {
    const auto relative =
            authoring_profile(root, profile).at("components").at(component).get<std::string>();
    const std::filesystem::path path = relative;

    if (path.is_absolute() || path.lexically_normal() != path || *path.begin() == "..") {
        throw VoyemuError("COMPONENT_PATH", "profile-relative component required");
    }

    const auto source = authoring_directory(root, profile) / path;
    const auto definition = read_private_json(source / "component.json");

    if (definition.value("type", std::string{}) != "native") {
        throw VoyemuError("COMPONENT_RECIPE", "native component required");
    }

    return {source, definition};
}

// Builds one native component of a profile into work/<component> and returns its output.
std::filesystem::path
build_profile_native_component(const std::filesystem::path &root, const std::string &profile,
                               const std::string &component, const std::filesystem::path &compiler,
                               const std::string &compiler_pin, const std::filesystem::path &work,
                               bool offline) {
    auto [source, definition] = profile_native_component(root, profile, component);
    source = native_component_sources(root, source, work / (component + "-shared"));

    if (definition.contains("externalSources") || definition.contains("upstreamEdits")) {
        // The pinned AOSP sources, kept decoded by SHA-256; gitiles serves ?format=TEXT as base64.
        const auto cache = root / ".local/toolchains/downloads/sources";
        ensure_private_directory(cache);

        const auto external = definition.value("externalSources", Json::object());

        for (auto it = external.begin(); it != external.end(); ++it) {
            const auto url = it.value().at("url").get<std::string>(),
                       sha = it.value().at("sha256").get<std::string>();

            if (std::filesystem::exists(std::filesystem::symlink_status(cache / sha))) {
                continue;
            }

            const auto blob =
                    download_pinned({url, sha, 1ULL << 20,
                                     url.ends_with("?format=TEXT") ? DownloadEncoding::base64
                                                                   : DownloadEncoding::raw},
                                    cache, offline)
                            .file;
            std::filesystem::copy_file(blob, cache / sha);
        }

        materialize_native_component_sources(source, cache, work / (component + "-sources"));
        source = work / (component + "-sources");
    }

    build_native_component(source, compiler, compiler_pin, work / component, 0, {},
                           profile_guest_abi(root, profile));

    return work / component / definition.at("output").get<std::string>();
}
} // namespace

Json build_native_component_recipe(const std::filesystem::path &root,
                                   const std::filesystem::path &compiler,
                                   const std::string &compiler_pin,
                                   const std::filesystem::path &output, bool offline) {
    ordinary(root);
    ensure_private_directory(output);
    const auto work = output / ".work";

    if (std::filesystem::exists(work)) {
        throw VoyemuError("COMPONENT_OUTPUT", "fresh recipe output required");
    }

    ensure_private_directory(work);
    Json files = Json::object();
    std::set<std::filesystem::path> profiles;

    for (const auto &entry : std::filesystem::directory_iterator(root / "profiles")) {
        if (std::filesystem::is_regular_file(entry.path() / "profile.json")) {
            profiles.insert(entry.path());
        }
    }

    for (const auto &directory : profiles) {
        const auto profile = directory.filename().string();
        const auto definition = read_private_json(directory / "profile.json", 4 << 20);

        if (definition.value("local", false)) {
            continue;
        }

        const auto components = definition.value("components", Json::object());

        for (auto it = components.begin(); it != components.end(); ++it) {
            const auto definition_file = directory / it.value().get<std::string>() /
                                         "component.json";

            if (!std::filesystem::is_regular_file(definition_file)) {
                continue;
            }

            const auto component = read_private_json(definition_file);

            // A component that names a pin of another profile publishes no asset of its own.
            if (component.value("type", std::string{}) != "native" || component.contains("pin") ||
                component.contains("sourceBuildSha256")) {
                continue;
            }

            const auto built = build_profile_native_component(
                    root, profile, it.key(), compiler, compiler_pin, work / profile, offline);
            const auto asset = profile + "-" + it.key() + "-" + built.filename().string();
            std::filesystem::copy_file(built, output / asset);
            files[profile + "/" + it.key()] = {{"asset", asset}, {"sha256", sha256_file(built)}};
        }
    }

    std::filesystem::remove_all(work);

    return files;
}

std::filesystem::path
install_native_component(const std::filesystem::path &root, const std::string &profile,
                         const std::string &component, const Json &pins, bool offline,
                         const DownloadTransport &transport,
                         const std::function<void(const std::filesystem::path &)> &build,
                         std::string_view guest_abi) {
    const std::regex keys(R"(^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9-]*$)");

    if (!std::regex_match(profile + "/" + component, keys)) {
        throw VoyemuError("COMPONENT_PATH", "invalid native component key");
    }

    const auto [source, definition] = profile_native_component(root, profile, component);
    const auto key = native_component_pin(profile, component, definition);

    if (!std::regex_match(key, keys)) {
        throw VoyemuError("COMPONENT_PIN", "invalid native component pin");
    }

    const auto output = definition.at("output").get<std::string>();
    const auto api = definition.at("minSdk").get<int>();
    const auto output_type = definition.value("outputType", std::string("shared-library"));
    valid_output_name(output, output_type == "executable");
    const auto origin = native_component_origin(pins, key, definition);
    const auto sha = origin.at("sha256").get<std::string>(),
               url = origin.value("asset", std::string{});
    const auto abi = native_component_abi(
            definition, guest_abi.empty() ? profile_guest_abi(root, profile) : guest_abi);

    auto asset = key;
    asset[key.find('/')] = '-';

    if (origin.contains("asset") && !url.ends_with("/" + asset + "-" + output)) {
        throw VoyemuError("COMPONENT_PIN", "asset name differs from the component");
    }

    const auto folder = root / ".local/toolchains/android-native" / sha;
    const auto installed = folder / output;
    const auto pinned = [&](const std::filesystem::path &file) {
        return std::filesystem::is_regular_file(std::filesystem::symlink_status(file)) &&
               std::filesystem::hard_link_count(file) == 1 && sha256_file(file) == sha;
    };

    if (!std::filesystem::exists(std::filesystem::symlink_status(installed))) {
        ensure_private_directory(folder);
        const auto temporary = folder / (".part-" + random_token());

        bool from_recipe = origin.contains("source");

        if (!from_recipe) {
            try {
                const auto blob =
                        download_pinned({url, sha, 64ULL << 20},
                                        root / ".local/toolchains/downloads/android-native",
                                        offline, 0, transport)
                                .file;
                std::filesystem::copy_file(blob, temporary);
                logging::write(logging::Level::debug, "prepare", "native component downloaded",
                               {{"component", key}, {"sha256", sha}});
            } catch (const std::runtime_error &) {
                if (offline || !download_unpublished(std::current_exception())) {
                    throw;
                }

                from_recipe = true;
            }
        }

        if (from_recipe) {
            const auto job = root / ".local/build/jobs" / ("native-component-" + random_token());
            struct Job {
                std::filesystem::path path;

                ~Job() {
                    std::error_code ignored;
                    std::filesystem::remove_all(path, ignored);
                }
            } owned{job};
            ensure_private_directory(job);
            std::filesystem::path built;

            if (build) {
                build(job);
                built = job / output;
            } else {
                // Bionic headers and libraries come only with the NDK, so no recipe runs without
                // it.
                const auto ndk = native_ndk_directory(root);
                const auto clang = ndk / native_ndk_tool("clang");

                if (!std::filesystem::exists(clang)) {
                    throw VoyemuError("ANDROID_NATIVE_ASSET_MISSING",
                                      "building " + key + " requires the pinned developer NDK");
                }

                logging::write(logging::Level::info, "prepare",
                               "native component built from the recipe",
                               {{"component", key}, {"abi", abi}});
                const auto compiler = std::filesystem::canonical(clang);
                built = build_profile_native_component(root, profile, component, compiler,
                                                       sha256_file(compiler), job, offline);
            }

            std::filesystem::copy_file(built, temporary);
        }

        if (!pinned(temporary)) {
            std::filesystem::remove(temporary);

            throw VoyemuError("COMPONENT_PIN", "native component differs from its pin: " + key);
        }

        try {
            elf(temporary, abi, output_type == "executable");
            std::filesystem::rename(temporary, installed);
        } catch (...) {
            std::filesystem::remove(temporary);
            throw;
        }
    }

    if (!pinned(installed)) {
        throw VoyemuError("COMPONENT_PIN",
                          "installed native component differs from its pin: " + installed.string());
    }

    elf(installed, abi, output_type == "executable");
    const auto handoff = root / ".local/build" / ("native-component-" + random_token());
    ensure_private_directory(handoff);
    std::filesystem::copy_file(installed, handoff / output);

    if (output_type == "executable") {
        std::filesystem::permissions(handoff / output, std::filesystem::perms::owner_exec,
                                     std::filesystem::perm_options::add);
    }

    Json receipt = {{"schema", 1},
                    {"type", "native"},
                    {"output_type", output_type},
                    {"api", api},
                    {"abi", abi},
                    {"output", output},
                    {"bytes", std::filesystem::file_size(handoff / output)},
                    {"sha256", sha}};
    receipt.update(origin);
    write_private_json(handoff / "receipt.json", receipt);

    return handoff / "receipt.json";
}
} // namespace voyemu
