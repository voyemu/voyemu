#include "qnx_host_windows.hpp"
#include "check.hpp"
#include "download.hpp"
#include "error.hpp"
#include "process.hpp"
#include "qnx_host.hpp"
#include "qnx_host_build_diagnostics.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <functional>
#include <set>
#include <string_view>
#include <thread>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
namespace voyemu {
#ifdef _WIN32
namespace {
constexpr Check require{"QNX_HOST"};

void save(const std::filesystem::path &path, const std::string &bytes) {
    std::ofstream file(path, std::ios::binary);

    file << bytes;
    file.close();
    require(bool(file), "cannot write build input: " + path.string());
}

std::string shell(std::string_view value) {
    std::string result = "'";

    for (char c : value) {
        if (c == '\'') {
            result += "'\\''";
        } else {
            result += c;
        }
    }

    return result + "'";
}

std::string posix(const std::filesystem::path &path) {
    auto s = path.generic_string();

    require(s.size() > 2 && s[1] == ':' && s[2] == '/', "local Windows drive path required");
    s[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[0])));

    return "/" + s.substr(0, 1) + s.substr(2);
}

Json inventory(const std::filesystem::path &directory) {
    Json files = Json::object();

    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        require(!entry.is_symlink(), "linked build payload rejected");

        if (entry.is_directory()) {
            continue;
        }

        if (entry.path().filename() == "qnx-host.json") {
            continue;
        }

        require(entry.is_regular_file(), "ordinary build payload required");
        files[entry.path().lexically_relative(directory).generic_string()] = {
                {"bytes", entry.file_size()}, {"sha256", sha256_file(entry.path())}};
    }

    return files;
}
} // namespace
#endif

Json install_qnx_host_windows_source(const std::filesystem::path &root, bool offline,
                                     std::uint64_t reserve) {
    // Host-independent refusal: a non-canonical root is rejected on every supported host before any
    // catalog lookup, download or publication can begin.
    if (!(root.is_absolute() && std::filesystem::canonical(root) == root)) {
        throw VoyemuError("QNX_HOST", "canonical project root required");
    }

#ifndef _WIN32
    (void)offline;
    (void)reserve;
    throw VoyemuError("QNX_HOST", "Windows source builder requires Windows x64");
#else
    const auto &recipe = qnx_host_catalog().at("windows_file_backend");
    const auto pin = sha256_bytes(recipe.dump());
    const auto parent = root / ".local/toolchains",
               target = parent / ("qnx-host-windows-source-11.1.2-" + pin.substr(0, 12));
    auto result = [&](bool cached) {
        const auto exe = target / "qemu-system-aarch64.exe";
        require(std::filesystem::is_regular_file(std::filesystem::symlink_status(exe)) &&
                        std::filesystem::hard_link_count(exe) == 1,
                "published source engine missing");

        return Json{{"schema", 1},
                    {"ready", true},
                    {"cached", cached},
                    {"version", "11.1.2"},
                    {"directory", target.string()},
                    {"executable", exe.string()},
                    {"guest_verified", false},
                    {"qnx_file_backend",
                     {{"schema", 1}, {"version", "11.1.2"}, {"engine_sha256", sha256_file(exe)}}}};
    };

    if (std::filesystem::exists(target)) {
        validate_installed_windows_source(target, root, recipe);

        return result(true);
    }

    ensure_private_directory(parent);
    const auto lock = parent / "qnx-host.lock";
    require(std::filesystem::create_directory(lock), "installation already owned");
    struct Unlock {
        std::filesystem::path path;

        ~Unlock() {
            std::error_code error;
            std::filesystem::remove(path, error);
        }
    } unlock{lock};
    require(std::filesystem::space(root).available >= reserve + (4ULL << 30),
            "insufficient source build disk reserve");
    const auto token = random_token();
    // The pinned QEMU tar contains nested ROM paths up to 180 characters long.
    const auto stage = root / ".local/build/tmp" / ("qw-" + token);
    ensure_private_directory(stage);
    QnxHostBuildStage cleanup{stage, root / ".local/build" / ("qnx-windows-source-" + token)};
    const auto cache = root / ".local/toolchains/downloads/qnx-host";
    ensure_private_directory(cache);
    auto get = [&](const Json &spec) {
        const auto url = spec.at("url").get<std::string>();

        try {
            return download_pinned({url, spec.at("sha256").get<std::string>(), 512ULL << 20}, cache,
                                   offline, reserve)
                    .file;
        } catch (const VoyemuError &error) {
            const auto code = std::string(error.code());
            throw VoyemuError(code.c_str(),
                              url + ": " + std::string(error.what()).substr(code.size() + 2));
        }
    };
    const auto source = get(recipe.at("source")), dtc = get(recipe.at("dtc")),
               base = get(recipe.at("build_shell")),
               zigarchive = get(recipe.at("compiler").at("windows_x64")),
               msi = get(qnx_host_catalog().at("windows_x64").at("extractor"));
    std::map<std::string, std::filesystem::path> tools, deps;

    for (const auto &[name, spec] : recipe.at("build_tools").items()) {
        tools[name] = get(spec);
    }

    for (const auto &[name, spec] : recipe.at("dependencies").items()) {
        deps[name] = get(spec);
    }

    std::vector<std::filesystem::path> wheels;

    for (const auto &spec : recipe.at("python_wheels")) {
        wheels.push_back(get(spec));
    }

    const auto patch = root / recipe.at("patch").at("file").get<std::string>();
    require(std::filesystem::is_regular_file(patch), "source patch missing");
    const auto boot = parent / ("qnx-windows-build-" + pin.substr(0, 12));
    extract_qnx_unpacker(msi, stage / "unpacker");
    unsigned step = 0;
    auto run = [&](const std::filesystem::path &exe, std::vector<std::string> args,
                   const std::filesystem::path &cwd, std::map<std::string, std::string> env = {},
                   int timeout = 120000, std::size_t output_limit = 256 * 1024) {
        ProcessSpec spec;
        spec.executable = exe;
        spec.arguments = std::move(args);
        spec.directory = cwd;
        spec.environment = std::move(env);
        spec.output = stage / (std::to_string(++step) + ".log");

        if (timeout <= 300000 && output_limit <= 1024 * 1024) {
            const auto response = execute(spec, timeout, output_limit);
            save(spec.output, response.output);
            require(!response.timed_out && response.exit_code == 0,
                    "source step " + std::to_string(step) +
                            " failed; diagnostics: " + cleanup.logs().string());

            return response.output;
        }

        auto child = ChildProcess::launch(spec);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);

        while (child.alive()) {
            require(std::chrono::steady_clock::now() < deadline, "source build deadline exceeded");
            require(std::filesystem::space(root).available >= reserve,
                    "source build disk reserve reached");
            require(!std::filesystem::exists(spec.output) ||
                            std::filesystem::file_size(spec.output) <
                                    (output_limit > 1024 * 1024 ? output_limit : 16ULL << 20),
                    "source build output exceeds bound");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        require(child.exit_code() == 0,
                "source build failed; diagnostics: " + cleanup.logs().string());

        if (output_limit > 1024 * 1024) {
            require(std::filesystem::file_size(spec.output) < output_limit,
                    "source listing exceeds bound");
            std::ifstream file(spec.output, std::ios::binary);
            std::string text((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
            require(file.eof() || bool(file), "source listing unreadable");

            return text;
        }

        return std::string{};
    };
    const auto unpacker = stage / "unpacker/7z.exe";
    auto unpack = [&](const std::filesystem::path &archive,
                      const std::filesystem::path &destination,
                      bool compressed) -> std::filesystem::path {
        ensure_private_directory(destination);

        if (!compressed) {
            run(unpacker, {"x", "-y", "-o" + destination.string(), archive.string()}, stage);

            return {};
        }

        const auto intermediate = stage / ("archive-" + std::to_string(++step));
        ensure_private_directory(intermediate);
        run(unpacker, {"x", "-y", "-o" + intermediate.string(), archive.string()}, stage);
        std::filesystem::path tar;

        for (const auto &entry : std::filesystem::directory_iterator(intermediate)) {
            require(tar.empty() && entry.is_regular_file() && !entry.is_symlink() &&
                            entry.file_size() < (2ULL << 30),
                    "single bounded tar required");
            tar = entry.path();
        }

        require(!tar.empty(), "archive did not yield tar");
        run(unpacker, {"x", "-y", "-o" + destination.string(), tar.string()}, stage);
        std::filesystem::remove_all(intermediate);

        return tar;
    };
    auto unpack_recorded = [&](const std::filesystem::path &archive,
                               const std::filesystem::path &destination,
                               const std::string &prefix = "",
                               bool omit_unused_qemu_links = false) -> std::filesystem::path {
        ensure_private_directory(destination);
        const auto intermediate = stage / ("archive-" + std::to_string(++step));
        ensure_private_directory(intermediate);
        run(unpacker, {"x", "-y", "-o" + intermediate.string(), archive.string()}, stage);
        std::filesystem::path tar;

        for (const auto &entry : std::filesystem::directory_iterator(intermediate)) {
            require(tar.empty() && entry.is_regular_file() && !entry.is_symlink() &&
                            entry.file_size() < (2ULL << 30),
                    "single bounded tar required");
            tar = entry.path();
        }

        require(!tar.empty(), "archive did not yield tar");
        const auto records = destination / "msys_recorded_symlinks";
        require(!std::filesystem::exists(records), "symlink record destination differs");
        const auto produced = destination / "msys_recorded_symlinks.produced";
        require(!std::filesystem::exists(produced), "symlink record producer destination differs");
        const auto listing = run(unpacker, {"l", "-slt", "-ba", "-sccUTF-8", tar.string()}, stage,
                                 {}, 120000, 32ULL << 20);
        require(listing.size() < (32ULL << 20), "archive listing exceeds bound");
        const auto excluded = record_msys_archive_links(listing, produced, prefix,
                                                        omit_unused_qemu_links);
        std::filesystem::rename(produced, records);
        std::vector<std::string> args{"x", "-y", "-spd", "-o" + destination.string(), tar.string()};

        if (!excluded.empty()) {
            const auto omitted = intermediate / "links.txt";
            std::string names;

            for (const auto &name : excluded) {
                names += name + "\n";
            }

            save(omitted, names);
            args.push_back("-scsUTF-8");
            args.push_back("-x@" + omitted.string());
        }

        run(unpacker, std::move(args), stage);
        std::filesystem::remove_all(intermediate);

        return records;
    };

    if (std::filesystem::exists(boot)) {
        const auto receipt = read_private_json(boot / "qnx-host.json", 16 << 20);
        require(receipt.at("component_sha256") == pin, "build tools recipe differs");

        for (const auto &[relative, pinned] : receipt.at("files").items()) {
            const auto file = boot / relative;
            require(std::filesystem::is_regular_file(std::filesystem::symlink_status(file)) &&
                            std::filesystem::file_size(file) ==
                                    pinned.at("bytes").get<std::uint64_t>() &&
                            sha256_file(file) == pinned.at("sha256").get<std::string>(),
                    "installed build payload differs: " + relative);
        }
    } else {
        const auto payload = stage / "bootstrap";
        ensure_private_directory(payload);
        const auto base_extraction = unpack_recorded(base, payload, "msys64");
        const auto msys = payload / "msys64";
        require(std::filesystem::exists(msys / "usr/bin/bash.exe"), "MSYS shell missing");
        restore_msys_symlinks(msys, base_extraction);

        for (const auto &[name, file] : tools) {
            const auto extraction = unpack_recorded(file, msys);
            restore_msys_symlinks(msys, extraction);
        }

        for (const auto &[name, file] : deps) {
            const auto extraction = unpack_recorded(file, msys);
            restore_msys_symlinks(msys, extraction);
        }

        unpack(zigarchive, payload, false);
        require(!std::filesystem::exists(boot), "build tools destination appeared");
        write_private_json(
                payload / "qnx-host.json",
                {{"schema", 1}, {"component_sha256", pin}, {"files", inventory(payload)}},
                16 << 20);
        std::filesystem::rename(payload, boot);
    }

    const auto source_key =
            sha256_bytes(recipe.at("source").dump() + recipe.at("patched_sources").dump());
    const auto msys = boot / "msys64", bash = msys / "usr/bin/bash.exe",
               zig = boot / "zig-x86_64-windows-0.15.2/zig.exe",
               sources = cache / ("win-src-" + source_key.substr(0, 12));
    // Zig keeps its cache in the build stage instead of the user profile.
    const auto zig_cache = (stage / "zig-cache").string();
    std::map<std::string, std::string> env{{"MSYSTEM", "MSYS"},
                                           {"MSYS2_PATH_TYPE", "strict"},
                                           {"CHERE_INVOKING", "1"},
                                           {"PIP_NO_INDEX", "1"},
                                           {"PYTHONHASHSEED", "0"},
                                           {"PYTHONDONTWRITEBYTECODE", "1"},
                                           {"MSYS2_ARG_CONV_EXCL", "*"},
                                           {"ZIG_GLOBAL_CACHE_DIR", zig_cache},
                                           {"ZIG_LOCAL_CACHE_DIR", zig_cache}};
    auto script = [&](const std::string &bytes, const std::filesystem::path &cwd,
                      int timeout = 120000) {
        const auto file = stage / ("command-" + std::to_string(step) + ".sh");
        save(file, "#!/bin/sh\nset -eu\nexport PATH=" + shell(posix(msys / "usr/bin")) +
                           ":/usr/bin:/bin\n" + bytes + "\n");

        return run(bash, {"--noprofile", "--norc", posix(file)}, cwd, env, timeout);
    };
    script("python3 -c 'import venv,ensurepip,pyexpat; import sys; assert sys.version_info >= (3,9)'\nninja --version\npkgconf --version\npatch --version",
           stage);

    if (!std::filesystem::exists(sources)) {
        const auto extract = stage / "sources";
        const auto omitted = unpack_recorded(source, extract, "qemu-11.1.2", true);
        std::filesystem::remove(omitted);
        const auto tree = extract / "qemu-11.1.2";

        for (const auto &[file, sha] : recipe.at("patched_sources").items()) {
            require(sha256_file(tree / file) == sha.at("before").get<std::string>(),
                    "source before pin differs: " + file);
        }

        script("cd " + shell(posix(tree)) + "\npatch --batch -p1 -i " + shell(posix(patch)), stage);

        for (const auto &[file, sha] : recipe.at("patched_sources").items()) {
            require(sha256_file(tree / file) == sha.at("after").get<std::string>(),
                    "source after pin differs: " + file);
        }

        std::filesystem::rename(tree, sources);
    } else {
        for (const auto &[file, sha] : recipe.at("patched_sources").items()) {
            require(sha256_file(sources / file) == sha.at("after").get<std::string>(),
                    "cached source pin differs: " + file);
        }
    }

    const auto build = stage / "build", wrappers = stage / "wrappers", python = stage / "python",
               fdt = stage / "dtc";
    ensure_private_directory(build);
    ensure_private_directory(wrappers);
    ensure_private_directory(python);
    unpack(dtc, fdt, true);

    for (const auto &wheel : wheels) {
        script("python3 -m zipfile -e " + shell(posix(wheel)) + " " + shell(posix(python)) +
                       "\nfind " + shell(posix(python)) +
                       " -name '__pycache__' -type d -prune -exec rm -rf {} +",
               stage);
    }

    const auto zigroot = zig.parent_path();
    const auto z = shell(posix(zig));
    auto wrapper = [&](const std::string &name, const std::string &args) {
        const std::filesystem::path file = wrappers / name;
        save(file, "#!/bin/sh\n" + args + "\n");
        std::error_code error;
        std::filesystem::permissions(
                file,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                        std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
                        std::filesystem::perms::group_exec | std::filesystem::perms::others_exec,
                std::filesystem::perm_options::replace, error);
        require(!error &&
                        (std::filesystem::status(file).permissions() &
                         std::filesystem::perms::owner_exec) == std::filesystem::perms::owner_exec,
                "build wrapper exec bit failed: " + name);
    };
    // MSYS Python and Ninja need POSIX paths. Convert arguments only at the native Zig boundary.
    const auto zig_command = "MSYS2_ARG_CONV_EXCL='' exec " + z;
    wrapper("cc", zig_command + " cc -target x86_64-windows-gnu -UNDEBUG \"$@\"");
    wrapper("cxx", zig_command + " c++ -target x86_64-windows-gnu -UNDEBUG \"$@\"");
    wrapper("ar", zig_command + " ar \"$@\"");
    // The rc adapter answers the meson windres detection
    // probe (single '/?' argument) so configure detects a windows resource compiler.
    wrapper("rc",
            "if [ \"$#\" = 1 ] && [ \"$1\" = '/?' ]; then echo 'LLVM Resource Converter interface adapter using Zig rc'; exit 0; fi\n"
            "MSYS2_ARG_CONV_EXCL='/nologo;/fo' exec " +
                    z + " rc -:output-format coff -:target x86_64 -i " +
                    shell(posix(zigroot / "lib/libc/include/any-windows-any")) + " \"$@\"");
    const auto fdtsrc = fdt / "dtc-1.8.1/libfdt", fdtdst = stage / "fdt-prefix";
    ensure_private_directory(fdtdst / "lib/pkgconfig");
    ensure_private_directory(fdtdst / "include");
    std::string fdtcmd = "cd " + shell(posix(fdtsrc)) + "\n";

    for (const auto &name :
         {"fdt.c", "fdt_ro.c", "fdt_wip.c", "fdt_sw.c", "fdt_rw.c", "fdt_strerror.c",
          "fdt_empty_tree.c", "fdt_addresses.c", "fdt_overlay.c", "fdt_check.c"}) {
        fdtcmd += shell(posix(wrappers / "cc")) + " -O2 -I. -c " + name + " -o " +
                  shell(posix(fdtdst / "lib" / (std::string(name) + ".o"))) + "\n";
    }

    fdtcmd += shell(posix(wrappers / "ar")) + " rcs " + shell(posix(fdtdst / "lib/libfdt.a")) +
              " " + shell(posix(fdtdst / "lib")) + "/*.o\n";
    script(fdtcmd, stage, 300000);

    for (const auto &name : {"libfdt.h", "libfdt_env.h", "fdt.h"}) {
        std::filesystem::copy_file(fdtsrc / name, fdtdst / "include" / name);
    }

    save(fdtdst / "lib/pkgconfig/libfdt.pc",
         "prefix=" + fdtdst.generic_string() +
                 "\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\nName: libfdt\nDescription: pinned device tree library\nVersion: 1.8.1\nLibs: -L${libdir} -lfdt\nCflags: -I${includedir}\n");
    std::string configure =
            "export PYTHONPATH=" + shell(posix(python)) + "\nexport PKG_CONFIG_LIBDIR=" +
            shell(posix(fdtdst / "lib/pkgconfig") + ":" + posix(msys / "ucrt64/lib/pkgconfig")) +
            "\nexport PKG_CONFIG=" + shell(posix(msys / "usr/bin/pkgconf.exe")) +
            "\nexport AR=" + shell(posix(wrappers / "ar")) +
            "\nexport WINDRES=" + shell(posix(wrappers / "rc")) +
            "\nunset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS\ncd " + shell(posix(build)) + "\n" +
            shell(posix(sources / "configure"));

    for (const auto &arg : recipe.at("configure")) {
        configure += " " + shell(arg.get<std::string>());
    }

    configure += " --cross-prefix=x86_64-w64-mingw32- --cc=" + shell(posix(wrappers / "cc")) +
                 " --cxx=" + shell(posix(wrappers / "cxx")) +
                 " --python=" + shell(posix(msys / "usr/bin/python3.exe")) +
                 " --extra-cflags=" + shell("-I" + (msys / "ucrt64/include").generic_string()) +
                 " --extra-ldflags=" + shell("-L" + (msys / "ucrt64/lib").generic_string());
    script(configure, build, 300000);
    script("cd " + shell(posix(build)) + "\nninja -j3 qemu-system-aarch64.exe", build, 3600000);
    const auto exe = build / "qemu-system-aarch64.exe", payload = stage / "payload";
    ensure_private_directory(payload);
    require(std::filesystem::is_regular_file(exe) && std::filesystem::hard_link_count(exe) == 1,
            "source engine product missing");
    std::filesystem::copy_file(exe, payload / exe.filename());
    // Independent expected closure from the recipe; the inventory of the assembled payload must
    // equal it without either side being derived from the other.
    const auto &runtime_files_spec = recipe.at("verified_runtime").at("files");
    Json expected = Json::object();

    for (const auto &[relative, pinned] : runtime_files_spec.items()) {
        expected[relative] = pinned;
    }

    for (const auto &[relative, spec] : runtime_files_spec.items()) {
        if (relative == "qemu-system-aarch64.exe" || relative == "licenses/qemu/COPYING") {
            continue;
        }

        const auto from = qnx_windows_source_file(msys, relative);
        require(std::filesystem::is_regular_file(std::filesystem::symlink_status(from)) &&
                        sha256_file(from) == spec.at("sha256").get<std::string>() &&
                        std::filesystem::file_size(from) == spec.at("bytes").get<std::uint64_t>(),
                "runtime dependency pin differs: " + relative);
        const auto destination = payload / relative;
        ensure_private_directory(destination.parent_path());
        require(!std::filesystem::exists(destination), "payload destination differs");
        std::filesystem::copy_file(from, destination);
    }

    // licenses/qemu/COPYING is the QEMU source tree's own license (the MSYS packages do not ship
    // it)
    {
        const auto &spec = runtime_files_spec.at("licenses/qemu/COPYING");
        const auto destination = payload / "licenses/qemu/COPYING";
        require(std::filesystem::is_regular_file(
                        std::filesystem::symlink_status(sources / "COPYING")) &&
                        sha256_file(sources / "COPYING") == spec.at("sha256").get<std::string>() &&
                        std::filesystem::file_size(sources / "COPYING") ==
                                spec.at("bytes").get<std::uint64_t>(),
                "QEMU source license pin differs");
        ensure_private_directory(destination.parent_path());
        require(!std::filesystem::exists(destination), "payload license destination differs");
        std::filesystem::copy_file(sources / "COPYING", destination);
    }
    expected["qemu-system-aarch64.exe"] = {
            {"bytes", std::filesystem::file_size(payload / exe.filename())},
            {"sha256", sha256_file(payload / exe.filename())}};
    require(run(payload / exe.filename(), {"--version"}, payload)
                            .find("QEMU emulator version 11.1.2") != std::string::npos,
            "source engine version probe failed");
    require(run(payload / exe.filename(), {"-object", "help"}, payload)
                            .find("memory-backend-file") != std::string::npos,
            "source file backend probe failed");
    const auto actual = inventory(payload);
    require(actual.size() == expected.size() && actual == expected,
            "published payload differs from pinned runtime closure");
    write_private_json(payload / "qnx-host.json",
                       {{"schema", 1},
                        {"component_sha256", pin},
                        {"recipe", recipe},
                        {"files", actual},
                        {"executable_sha256", sha256_file(payload / exe.filename())},
                        {"guest_verified", false}});
    require(!std::filesystem::exists(target), "source engine destination appeared");
    std::filesystem::rename(payload, target);
    validate_installed_windows_source(target, root, recipe);

    return result(false);
#endif
}
} // namespace voyemu
