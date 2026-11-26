#include "check.hpp"
#include "os/platform.hpp"
#include "portable_runtime_internal.hpp"
#include "signed_android.hpp"

namespace voyemu {
using namespace portable_detail;
namespace {
void image_group(const std::filesystem::path &seed, const Json &files,
                 const std::set<std::string> &expected, const std::string &prefix,
                 unsigned api = 28, const std::set<std::string> &mutable_roles = {},
                 const std::filesystem::path &avd_content = {}) {
    need(files.is_object() && files.size() == expected.size(),
         ("exact " + prefix +
          " guest image roles required: expected=" + std::to_string(expected.size()) +
          " actual=" + std::to_string(files.is_object() ? files.size() : 0))
                 .c_str());

    for (auto at = files.begin(); at != files.end(); ++at) {
        need(expected.contains(at.key()) && at.value().is_object(), "unknown guest role");
        const auto relative = prefix == "android" && at.key() == "system.img"
                                      ? portable_system_image_file(at.value(), api)
                                      : prefix + "/" + at.key();
        need(at.value().size() == 3 && at.value().at("file") == relative,
             "fixed relative file/bytes/SHA required");
        const auto size = at.value().at("bytes").get<std::uint64_t>();
        need(size > 0 && size <= (8ULL << 30), "guest byte bound");
        const auto file = seed / relative;

        if (mutable_roles.contains(at.key())) {
            ordinary(file);
            need(sha256_text(at.value().at("sha256").get<std::string>()) &&
                         std::filesystem::is_regular_file(file) &&
                         std::filesystem::hard_link_count(file) == 1,
                 "ordinary private mutable guest image required");
        } else {
            const bool linked_role = at.key() == "system.img" || at.key() == "vendor.img" ||
                                     at.key() == "encryptionkey.img";
            const auto alias = !avd_content.empty() && linked_role ? avd_content / at.key()
                                                                   : std::filesystem::path{};
            checked_file(file, at.value().at("sha256").get<std::string>(), 8ULL << 30, alias);
        }

        need(std::filesystem::file_size(file) == size, "guest image extent differs");
    }
}
} // namespace

namespace portable_detail {
void ordinary(const std::filesystem::path &path, [[maybe_unused]] bool allow_windows_spelling) {
    const auto message = "canonical path required: " + path.string();

    need(path.is_absolute() && path.lexically_normal() == path, message.c_str());
    auto canonical = std::filesystem::canonical(path);
    bool matches = canonical == path;
#ifdef _WIN32
    if (!matches && allow_windows_spelling) {
        auto spelling = path;
        matches = CompareStringOrdinal(canonical.make_preferred().c_str(), -1,
                                       spelling.make_preferred().c_str(), -1, TRUE) == CSTR_EQUAL;
    }
#endif
    need(matches, message.c_str());

    // The volume root is not inspected, so a reparse point anywhere below it still rejects the
    // path.
    for (const auto &at : os::ancestors(path)) {
        need(!std::filesystem::is_symlink(std::filesystem::symlink_status(at)),
             ("linked path: " + at.string()).c_str());
#ifdef _WIN32
        const auto attributes = GetFileAttributesW(os::win32_file_path(at).c_str());

        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            throw VoyemuError("PORTABLE_RUNTIME",
                              "invalid or reparse path: " + at.string() +
                                      " attributes=" + std::to_string(attributes) +
                                      " error=" + std::to_string(GetLastError()));
        }
#endif
    }
}

void inside(const std::filesystem::path &root, const std::filesystem::path &path) {
    const auto relative = path.lexically_relative(root);

    need(!relative.empty() && relative != "." && !relative.is_absolute(),
         "path must be inside selected project");

    for (const auto &part : relative) {
        need(part != "..", "path leaves project");
    }
}

Json checked_file(const std::filesystem::path &file, const std::string &sha, std::uint64_t maximum,
                  const std::filesystem::path &android_alias) {
    need(sha256_text(sha), "lowercase SHA256 required");
    ordinary(file);
    const auto links = std::filesystem::hard_link_count(file);
    const auto known_links = [&] {
        if (links == 1) {
            return true;
        }

        // The Windows SDK needs these aliases beside its AVD config. Only the
        // exact owned runtime alias can account for an additional hard link.
        if (links != 2 || android_alias.empty()) {
            return false;
        }

        ordinary(android_alias);

        return std::filesystem::is_regular_file(android_alias) &&
               std::filesystem::equivalent(file, android_alias);
    };
    need(std::filesystem::is_regular_file(file) && known_links() &&
                 std::filesystem::file_size(file) <= maximum,
         "bounded unaliased ordinary file required");
    const auto identity = cache_file_identity(file, links);
    need(sha256_file(file) == sha && cache_file_identity(file, links) == identity && known_links(),
         "input pin differs");

    return identity;
}

std::filesystem::path seed_directory(const std::filesystem::path &root, std::string_view profile,
                                     const MachineIdentity &machine,
                                     const std::filesystem::path &explicit_seed) {
    need(machine.valid_for(profile), "invalid profile or machine name");

    if (!explicit_seed.empty()) {
        ordinary(explicit_seed);
        need(std::filesystem::is_directory(explicit_seed), "machine directory required");

        return explicit_seed;
    }

    return root / "machines" / machine.name;
}

void rename_exclusive(const std::filesystem::path &from, const std::filesystem::path &to) {
    need(os::rename_exclusive(from, to), "exclusive directory publication failed");
}

OwnedDirectory owned_directory(const std::filesystem::path &path) {
    need(!std::filesystem::exists(path) && !std::filesystem::is_symlink(path),
         "fresh owned directory required");
    need(std::filesystem::create_directory(path), "exclusive directory creation failed");
    ensure_private_directory(path);
    const auto token = random_token();
    write_private_json(path / ".owner.json", {{"token", token}, {"kind", "portable-runtime"}});

    return {path, token};
}

void copy_sparse(const std::filesystem::path &source, const std::string &sha,
                 const std::filesystem::path &target, std::uint64_t reserve) {
    const auto identity = checked_file(source, sha);
    const auto size = std::filesystem::file_size(source);

    ensure_private_directory(target.parent_path());
#ifdef __APPLE__
    need(std::filesystem::space(target.parent_path()).available >= reserve,
         "disk reserve reached before image clone");

    if (clone_image(source, target)) {
        const int fd = ::open(target.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        need(fd >= 0, "cloned image open failed");
        struct CloneFile {
            int value;

            ~CloneFile() {
                ::close(value);
            }
        } close{fd};
        need(::fchmod(fd, 0600) == 0 && ::fsync(fd) == 0, "cloned image mode/sync failed");
        need(std::filesystem::hard_link_count(target) == 1 &&
                     cache_file_identity(target) != identity &&
                     std::filesystem::file_size(target) == size,
             "independent cloned image required");
        need(cache_file_identity(source) == identity && sha256_file(source) == sha &&
                     sha256_file(target) == sha,
             "image clone/source changed");
        need(std::filesystem::space(target.parent_path()).available >= reserve,
             "disk reserve reached after image clone");

        return;
    }
#endif
    std::ifstream input(source, std::ios::binary);
    need(bool(input), "seed open failed");
#ifdef _WIN32
    detail::PrivateStateSecurity security;
    HANDLE fd = CreateFileW(os::win32_file_path(target).c_str(), GENERIC_WRITE, 0,
                            &security.attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (fd == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        throw VoyemuError("PORTABLE_RUNTIME",
                          "exclusive image output failed; win32=" + std::to_string(error));
    }

    struct File {
        HANDLE value;

        ~File() {
            if (value != INVALID_HANDLE_VALUE) {
                CloseHandle(value);
            }
        }
    } close{fd};
    DWORD returned = 0;
    need(DeviceIoControl(fd, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr) != 0,
         "sparse filesystem required");
#else
    const int fd = ::open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          0600);
    need(fd >= 0, "exclusive image output failed");
    struct File {
        int value;

        ~File() {
            ::close(value);
        }
    } close{fd};
#endif
    std::array<char, 65536> buffer{};
    std::uint64_t offset = 0;

    while (offset < size) {
        const auto count =
                static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), size - offset));
        input.read(buffer.data(), static_cast<std::streamsize>(count));
        need(static_cast<std::size_t>(input.gcount()) == count, "short seed read");

        if (!std::all_of(buffer.begin(), buffer.begin() + count, [](char c) {
                return c == 0;
            })) {
            const auto available = std::filesystem::space(target.parent_path()).available;
            need(available >= reserve && available - reserve >= count,
                 "disk reserve reached before image write");
#ifdef _WIN32
            LARGE_INTEGER position;
            position.QuadPart = static_cast<LONGLONG>(offset);
            need(SetFilePointerEx(fd, position, nullptr, FILE_BEGIN) != 0, "image seek failed");
            DWORD done = 0;
            need(WriteFile(fd, buffer.data(), static_cast<DWORD>(count), &done, nullptr) &&
                         done == count,
                 "image write failed");
#else
            std::size_t done = 0;

            while (done < count) {
                const auto wrote = ::pwrite(fd, buffer.data() + done, count - done,
                                            static_cast<off_t>(offset + done));
                need(wrote > 0, "image write failed");
                done += static_cast<std::size_t>(wrote);
            }
#endif
        }

        offset += count;
        need(std::filesystem::space(target.parent_path()).available >= reserve,
             "disk reserve reached");
    }

#ifdef _WIN32
    LARGE_INTEGER end;
    end.QuadPart = static_cast<LONGLONG>(size);
    need(SetFilePointerEx(fd, end, nullptr, FILE_BEGIN) && SetEndOfFile(fd) && FlushFileBuffers(fd),
         "image extent/sync failed");
    CloseHandle(close.value);
    close.value = INVALID_HANDLE_VALUE;
#else
    need(::ftruncate(fd, static_cast<off_t>(size)) == 0 && ::fsync(fd) == 0,
         "image extent/sync failed");
#endif
    need(cache_file_identity(source) == identity && sha256_file(source) == sha &&
                 sha256_file(target) == sha,
         "image copy/source changed");
}

void private_text(const std::filesystem::path &path, const std::string &text) {
    need(!std::filesystem::exists(path) && text.size() < 65536, "fresh bounded text required");
    std::ofstream file(path, std::ios::binary);
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    file.close();
    need(bool(file), "text write failed");
}

std::string bounded_text(const std::filesystem::path &path) {
    ordinary(path);
    need(std::filesystem::is_regular_file(path) && std::filesystem::hard_link_count(path) == 1 &&
                 std::filesystem::file_size(path) < 65536,
         "bounded unaliased configuration text required");
    const auto epoch = cache_file_identity(path);
    std::ifstream file(path, std::ios::binary);
    std::string bytes{std::istreambuf_iterator<char>(file), {}};
    need(!file.bad() && bytes.size() == std::filesystem::file_size(path) &&
                 cache_file_identity(path) == epoch,
         "configuration text changed");

    return bytes;
}

std::string tool_pin(const std::filesystem::path &root, const PortableRuntimeHostBindings &host,
                     const std::filesystem::path &file, bool allow_installed_qnx) {
    if (allow_installed_qnx) {
#ifdef _WIN32
        const std::string engine = "qemu-system-aarch64.exe";
#else
        const std::string engine = "qemu-system-aarch64";
#endif
        need(file == host.qnx_qemu && file.filename() == engine,
             "only the explicitly configured installed QNX engine may leave project");
        ordinary(file);
    } else {
        inside(root, file);
    }

    const auto found = host.pins.find(file.string());
    need(found != host.pins.end(), "host dependency/build pin missing");
    checked_file(file, found->second, 512 * mib);

    return found->second;
}

Json portable_observer_descriptor(const std::filesystem::path &seed, const Json &manifest) {
    need(valid_profile_name(manifest.at("profile").get<std::string>()) &&
                 (manifest.at("android").at("api") == 28 || manifest.at("android").at("api") == 30),
         "portable observer requires supported Android profile");
    need(manifest.contains("ui_observer"),
         "prepared Free 7.3.1 UI observer missing; rebuild the profile before start");
    const auto &descriptor = manifest.at("ui_observer");
    need(descriptor.is_object() && descriptor.size() == 3 &&
                 descriptor.at("file") == "observer/classes.dex",
         "exact portable observer descriptor required");
    const auto bytes = descriptor.at("bytes").get<std::uint64_t>();
    need(bytes > 0 && bytes <= (8ULL << 20), "portable observer byte bound");
    const auto source = seed / "observer/classes.dex";
    checked_file(source, descriptor.at("sha256").get<std::string>(), 8 * mib);
    need(std::filesystem::file_size(source) == bytes, "portable observer extent differs");

    return descriptor;
}

void add_pin(Json &pins, const std::filesystem::path &file, const std::string &sha) {
    pins.push_back({{"path", file.string()}, {"sha256", sha}});
}

Json refresh_observer(const std::filesystem::path &root, const std::filesystem::path &scoped,
                      const PortableRuntimeHostBindings &host, const Json &record) {
#ifdef _WIN32
    [[maybe_unused]] const std::string executable_suffix = ".exe", library_suffix = ".dll";
#else
    [[maybe_unused]] const std::string executable_suffix, library_suffix = ".dylib";
#endif
    need(host.refresh_host,
         "existing observer binding differs; explicit host launch migration required");
    auto lock = owned_directory(scoped.parent_path() /
                                (scoped.filename().string() + ".activation.lock"));
    need(read_private_json(scoped / "activation.json") == record,
         "activation changed during refresh");
    std::map<std::filesystem::path, Json> identities;
    auto capture = [&](const std::filesystem::path &file) {
        ordinary(file);
        const auto identity = cache_file_identity(file);
        const auto bytes = read_private_json_bytes(file);
        need(cache_file_identity(file) == identity && sha256_file(file) == sha256_bytes(bytes),
             "host source changed during snapshot");
        identities[file] = identity;

        return bytes;
    };
    const auto launch_before = capture(scoped / "android-launch.json"),
               activation_before = capture(scoped / "activation.json");
    const auto original = Json::parse(launch_before);
    need(Json::parse(activation_before) == record, "activation changed during refresh");
    need(sha256_bytes(launch_before) == record.at("android_launch_sha256").get<std::string>(),
         "launch changed during refresh");
    auto updated = original;
    normalize_ready_android_adb(updated);
    const bool observer_changed = !host.ui_observer.empty() &&
                                  original.value("ui_observer", Json::object()) != host.ui_observer;
    std::filesystem::path old_dex, dex, program;
    std::string old_sha, new_sha, old_program_sha, new_program_sha;

    if (observer_changed) {
        need(portable_ui_observer_binding(host.ui_observer,
                                          record.at("profile").get<std::string>()),
             "exact new observer binding required");

        need(original.contains("ui_observer") &&
                     portable_ui_observer_binding(original.at("ui_observer"),
                                                  record.at("profile").get<std::string>()),
             "existing exact observer binding required");
        old_dex = original.at("ui_observer").at("dex").get<std::string>();
        old_sha = original.at("ui_observer").at("sha256").get<std::string>();
        inside(root, old_dex);
        checked_file(old_dex, old_sha, 8 * mib);

        dex = host.ui_observer.at("dex").get<std::string>();
        new_sha = host.ui_observer.at("sha256").get<std::string>();
        need(tool_pin(root, host, dex) == new_sha, "new observer pin mismatch");
        updated["ui_observer"] = host.ui_observer;
    }

    bool frontend_changed = false;
#if defined(_WIN32) || defined(__APPLE__)
    frontend_changed = !host.frontend.empty() &&
                       original.value("frontend", Json::object()) != host.frontend;

    if (frontend_changed) {
        need(original.contains("frontend") && original.at("frontend").is_object(),
             "existing frontend binding required");
        auto before = original.at("frontend"), after = host.frontend;
        const auto old_pins = before.at("pins"), new_pins = after.at("pins");
        before.erase("pins");
        after.erase("pins");
        need(before == after && old_pins.is_array() && new_pins.is_array() &&
                     old_pins.size() == new_pins.size(),
             "frontend refresh may only change the root program SHA");
        program = root / ("voyemu" + executable_suffix);
        need(std::filesystem::path(before.at("executable").get<std::string>()) == program,
             "exact root frontend program required");
        unsigned replacements = 0;
        std::set<std::filesystem::path> unique;

        for (std::size_t i = 0; i < old_pins.size(); ++i) {
            const auto &prior = old_pins[i];
            const auto &next = new_pins[i];
            need(prior.is_object() && next.is_object() && prior.size() == 2 && next.size() == 2,
                 "exact frontend pin required");
            const std::filesystem::path file = prior.at("path").get<std::string>();
            inside(root, file);
            need(next.at("path") == prior.at("path") && unique.insert(file).second,
                 "frontend asset inventory differs");

            if (file == program) {
                old_program_sha = prior.at("sha256").get<std::string>();
                new_program_sha = next.at("sha256").get<std::string>();
                need(sha256_text(old_program_sha) && old_program_sha != new_program_sha &&
                             tool_pin(root, host, file) == new_program_sha,
                     "explicit current frontend program pin required");
                ++replacements;
            } else {
                need(next == prior, "frontend asset pin changed");
                checked_file(file, prior.at("sha256").get<std::string>());
            }
        }

        need(replacements == 1, "exactly one frontend program pin required");
        updated["frontend"] = host.frontend;
    }
#endif
    HostRefreshRecord cluster;
    Json cluster_pins = Json::array();
    bool graphics_changed = false;
#if defined(_WIN32) || defined(__APPLE__)
    if (!frontend_changed && record.contains("cluster_launch_sha256") && !host.frontend.empty()) {
        program = root / ("voyemu" + executable_suffix);
        need(host.frontend.at("executable") == program.string() &&
                     original.at("frontend") == host.frontend,
             "exact current root frontend required");
        new_program_sha = tool_pin(root, host, program);
        unsigned roots = 0;

        for (const auto &item : host.frontend.at("pins")) {
            const std::filesystem::path file = item.at("path").get<std::string>();
            inside(root, file);
            checked_file(file, item.at("sha256").get<std::string>());

            if (file == program) {
                need(item.at("sha256") == new_program_sha, "current frontend root pin differs");
                ++roots;
            }
        }

        need(roots == 1, "exact current frontend root pin required");
        const auto prior = read_private_json(scoped / "cluster-launch.json");

        for (const auto &item : prior.at("pins")) {
            if (item.at("path") == program.string()) {
                graphics_changed = graphics_changed || item.at("sha256") != new_program_sha;
            }
        }
    }
#endif

    if ((frontend_changed || graphics_changed) && record.contains("cluster_launch_sha256")) {
        const auto bytes = capture(scoped / "cluster-launch.json");
        need(sha256_bytes(bytes) == record.at("cluster_launch_sha256").get<std::string>(),
             "cluster launch changed during refresh");
        auto updated_cluster = Json::parse(bytes);
        need(updated_cluster.value("schema", 0) == 1 &&
                     updated_cluster.at("graphics").at("executable") == program.string() &&
                     host.graphics == program,
             "exact shared root graphics program required");
        need(updated_cluster.at("qemu").at("executable") == host.qnx_qemu.string() &&
                     updated_cluster.at("graphics").at("angle") == host.angle.string(),
             "cluster host dependencies differ");
        need(updated_cluster.at("pins").is_array(), "cluster pins required");
        unsigned replacements = 0;
        std::set<std::filesystem::path> unique;

        for (auto &item : updated_cluster["pins"]) {
            need(item.is_object() && item.size() == 2, "exact cluster pin required");
            const std::filesystem::path file = item.at("path").get<std::string>();
            const auto sha = item.at("sha256").get<std::string>();
            need(unique.insert(file).second, "duplicate cluster pin");

            if (file == program) {
                if (frontend_changed) {
                    need(sha == old_program_sha, "old graphics program pin differs");
                } else {
                    need(sha256_text(sha) && sha != new_program_sha,
                         "old graphics program pin required");
                    old_program_sha = sha;
                }

                item["sha256"] = new_program_sha;
                ++replacements;
            } else {
                if (file == host.qnx_qemu) {
                    need(tool_pin(root, host, file, true) == sha, "QNX engine pin differs");
                } else {
                    inside(root, file);
                    checked_file(file, sha);
                }
            }
        }

        need(replacements == 1 && unique.contains(host.qnx_qemu) &&
                     unique.contains(host.angle / ("libEGL" + library_suffix)) &&
                     unique.contains(host.angle / ("libGLESv2" + library_suffix)),
             "exact cluster host pins required");
        cluster_pins = updated_cluster.at("pins");
        cluster = {scoped / "cluster-launch.json", bytes, updated_cluster.dump() + "\n"};
    }

    need(observer_changed || frontend_changed || graphics_changed,
         "explicit host binding change required");
    need(original.at("pins").is_array(), "existing launch pins required");
    unsigned observer_pins = 0;

    for (auto &item : updated["pins"]) {
        need(item.is_object() && item.size() == 2, "exact existing launch pin required");
        const std::filesystem::path file = item.at("path").get<std::string>();
        const auto sha = item.at("sha256").get<std::string>();
        inside(root, file);

        if (frontend_changed && file == program) {
            need(sha == old_program_sha, "old program launch pin differs");
            item["sha256"] = new_program_sha;
        } else {
            checked_file(file, sha);

            if (observer_changed && file == old_dex) {
                need(sha == old_sha, "old observer launch pin differs");
                ++observer_pins;
                item = {{"path", dex.string()}, {"sha256", new_sha}};
            } else if (observer_changed) {
                need(file != dex, "new observer already has unrelated pin");
            }
        }
    }

    need(!observer_changed || observer_pins == 1u, "exactly one old observer pin required");

    auto disk_inventory = [&] {
        Json result = Json::object();

        if (!frontend_changed && !graphics_changed) {
            return result;
        }

        const std::filesystem::path machine = original.at("machine").get<std::string>(),
                                    runtime = record.at("runtime").get<std::string>();
        inside(root, runtime);
        ordinary(runtime);
        inside(runtime, machine);
        ordinary(machine);
        unsigned count = 0;

        for (const auto &entry : std::filesystem::recursive_directory_iterator(machine)) {
            ordinary(entry.path());

            if (entry.is_directory()) {
                continue;
            }

            if (entry.path().extension() != ".img" && entry.path().extension() != ".qcow2") {
                continue;
            }

            need(++count <= 64 && entry.is_regular_file() &&
                         std::filesystem::hard_link_count(entry.path()) == 1 &&
                         entry.file_size() <= (8ULL << 30),
                 "bounded writable image inventory required");
            const auto identity = cache_file_identity(entry.path());
            const auto sha = sha256_file(entry.path());
            need(cache_file_identity(entry.path()) == identity,
                 "writable image changed during refresh");
            result[entry.path().string()] = {{"identity", identity}, {"sha256", sha}};
        }

        need(count > 0, "existing writable images required");

        for (const auto &item : cluster_pins) {
            const std::filesystem::path file = item.at("path").get<std::string>();
            const auto sha = item.at("sha256").get<std::string>();
            result[file.string()] = {{"identity", checked_file(file, sha)}, {"sha256", sha}};
        }

        return result;
    };
    const auto disks = disk_inventory();
    const auto pending = scoped / (".host-refresh-" + random_token() + ".json");
    write_private_json(pending, updated);
    auto replacement = record;
    replacement["android_launch_sha256"] = sha256_file(pending);

    if (replacement.contains("host_file_pins")) {
        replacement["host_file_pins"].erase("adb");
    }

    if (!cluster.path.empty()) {
        replacement["cluster_launch_sha256"] = sha256_bytes(cluster.after);
    }

    try {
        need(read_private_json(scoped / "activation.json") == record &&
                     sha256_file(scoped / "android-launch.json") ==
                             record.at("android_launch_sha256").get<std::string>(),
             "activation/images changed before refresh publication");
        HostRefreshRecord binding;
        const auto binding_file = qnx_host_bindings_path(root);

        if ((frontend_changed || graphics_changed) && std::filesystem::exists(binding_file)) {
            // The CAS subject is the whole shared document, while the working keys are read and
            // edited on its platform view: the "windows" section on Windows, the flat document
            // elsewhere.
            const auto bytes = capture(binding_file);
            const auto document = Json::parse(bytes);
            const auto before = qnx_host_binding_view(root, document);
            need(before == host.refresh_source && before.at("schema") == 1,
                 "explicit frontend host source differs");

            if (before.contains("frontend")) {
                need(before.at("frontend") == original.at("frontend"),
                     "explicit frontend host source differs");
            }

            auto after = before;

            if (before.contains("frontend")) {
                after["frontend"] = host.frontend;
            }

            if (!cluster.path.empty()) {
                need(before.at("graphics") == program.string() &&
                             before.at("qnx_qemu") == host.qnx_qemu.string() &&
                             before.at("angle") == host.angle.string() &&
                             after.at("pins").is_array(),
                     "explicit shared graphics host source differs");
                unsigned replacements = 0;
                std::set<std::filesystem::path> unique;

                for (auto &item : after["pins"]) {
                    need(item.is_object() && item.size() == 2, "exact graphics host pin required");
                    const std::filesystem::path file = item.at("path").get<std::string>();
                    need(unique.insert(file).second, "duplicate graphics host pin");
                    const auto sha = item.at("sha256").get<std::string>();

                    if (file == program) {
                        need(sha == old_program_sha, "old graphics host pin differs");
                        item["sha256"] = new_program_sha;
                        ++replacements;
                    } else {
                        need(tool_pin(root, host, file, file == host.qnx_qemu) == sha,
                             "graphics host dependency pin differs");
                    }
                }

                need(replacements == 1 && unique.contains(host.qnx_qemu) &&
                             unique.contains(host.angle / ("libEGL" + library_suffix)) &&
                             unique.contains(host.angle / ("libGLESv2" + library_suffix)),
                     "exact graphics host dependency inventory required");
            }

            // The updated view is merged back into the whole document, so the rest of the shared
            // file is never dropped or rewritten.
            auto published = after;
#ifdef _WIN32
            published = document;
            published["windows"] = after;
#endif
            binding = {binding_file, bytes, published.dump() + "\n"};
        }

        const auto read = [&](const auto &file) {
            const auto bytes = read_private_json_bytes(file);
            need(cache_file_identity(file) == identities.at(file) &&
                         sha256_file(file) == sha256_bytes(bytes),
                 "host source identity/bytes changed");

            return bytes;
        };
        const auto write = [&](const auto &file, const auto &bytes) {
            write_private_json_bytes(file, bytes);
            identities[file] = cache_file_identity(file);
        };
        const auto validate = [&] {
            need(disk_inventory() == disks, "writable images changed during refresh publication");
        };

        if (cluster.path.empty()) {
            publish_host_refresh(
                    std::array<HostRefreshRecord, 3>{
                            {{scoped / "android-launch.json", launch_before, updated.dump() + "\n"},
                             {scoped / "activation.json", activation_before,
                              replacement.dump() + "\n"},
                             binding}},
                    read, write, validate);
        } else {
            need(!binding.path.empty(), "explicit full cluster host source required");
            publish_host_refresh(
                    std::array<HostRefreshRecord, 4>{
                            {{scoped / "android-launch.json", launch_before, updated.dump() + "\n"},
                             cluster,
                             {scoped / "activation.json", activation_before,
                              replacement.dump() + "\n"},
                             binding}},
                    read, write, validate);
        }

        std::filesystem::remove(pending);
    } catch (...) {
        std::error_code error;
        std::filesystem::remove(pending, error);
        throw;
    }

    replacement["cached"] = true;
    replacement["host_refreshed"] = true;
    replacement["cluster_requested"] = host.require_cluster;

    return replacement;
}

std::string image_sha(const Json &files, const std::string &name) {
    return files.at(name).at("sha256").get<std::string>();
}

std::string runtime_avd_config(const Json &definition, const std::filesystem::path &base,
                               const std::string &avd) {
    const auto emulator = definition.value("emulator", Json::object());
    const auto screens =
            android_screens(definition.value("displays", Json::array({{{"role", "primary"},
                                                                       {"guest", "android"},
                                                                       {"width", 1920},
                                                                       {"height", 720},
                                                                       {"density", 160}},
                                                                      {{"role", "secondary"},
                                                                       {"guest", "android"},
                                                                       {"width", 1920},
                                                                       {"height", 720},
                                                                       {"density", 160},
                                                                       {"xOffset", 1920},
                                                                       {"yOffset", 0},
                                                                       {"flag", 0}}})));
    const auto memory = emulator.value("memory", 4096u), cores = emulator.value("cores", 4u);

    need(memory >= 512 && memory <= 16384 && cores >= 1 && cores <= 8,
         "bounded profile memory/CPU configuration required");
    const auto abi = android_guest_abi(definition);
    std::map<std::string, std::string> values{
            {"AvdId", avd},
            {"avd.ini.displayname", definition.value("id", std::string("Voyemu"))},
            {"image.sysdir.1", base.string() + "/"},
            {"abi.type", std::string(abi)},
            {"tag.id", "default"},
            {"hw.cpu.arch", std::string(android_avd_cpu_arch(abi))},
            {"hw.ramSize", std::to_string(memory)},
            {"hw.cpu.ncore", std::to_string(cores)},
            {"hw.gpu.enabled", "yes"},
            {"hw.gpu.mode", emulator.value("gpuMode", std::string("auto"))},
            {"disk.dataPartition.size", "6G"},
            {"hw.multi_display_window", "false"},
            {"hw.hotplug_multi_display", "false"},
            {"fastboot.forceColdBoot", "yes"},
            {"fastboot.forceFastBoot", "no"}};
    passion_camera_config(definition, values);

    // Each Android screen is an emulator display; the others belong to QNX.
    add_avd_screens(values, screens, 0);

    // Supported prepared image roles contain no external SD image. Do not let
    // SDK -datadir discovery attach system.img as an implicit removable disk.
    values["hw.sdCard"] = "no";
    std::string result;

    for (const auto &[key, value] : values) {
        need(value.find_first_of("\r\n\0", 0, 3) == std::string::npos,
             "AVD configuration control byte");
        result += key + "=" + value + "\n";
    }

    return result;
}
} // namespace portable_detail

void copy_portable_image(const std::filesystem::path &source, const std::string &sha256,
                         const std::filesystem::path &target, std::uint64_t reserve_bytes) {
    copy_sparse(source, sha256, target, reserve_bytes);
}

std::map<std::string, std::string> portable_clean_boot_pins(const Json &android) {
    return native_clean_base(android).boot_files;
}

namespace portable_detail {
Json wine_native_diagnostic_binding() {
#ifdef _WIN32
    const char *selected = std::getenv("VOYEMU_WINE_NATIVE_DIAGNOSTIC");

    if (!selected) {
        return Json::object();
    }

    const std::filesystem::path file = std::filesystem::u8path(selected);
    need(file.is_absolute(), "diagnostic native binding requires an absolute file");
    ordinary(file);
    need(std::filesystem::is_regular_file(file) && std::filesystem::hard_link_count(file) == 1 &&
                 std::filesystem::file_size(file) <= 16384,
         "bounded diagnostic native binding required");
    auto value = read_private_json(file, 16384);
    need(value.is_object() &&
                 (value.size() == 9 || (value.size() == 10 && value.contains("qnx"))) &&
                 value.at("schema") == 1,
         "diagnostic native binding schema differs");
    const std::filesystem::path sdk = value.at("sdk_root").get<std::string>(),
                                launcher = value.at("launcher").get<std::string>(),
                                discovery = value.at("discovery_root").get<std::string>();
    need(sdk.is_absolute() && launcher.is_absolute() && discovery.is_absolute(),
         "absolute diagnostic native host paths required");
    ordinary(sdk);
    ordinary(launcher);
    wchar_t profile_home[MAX_PATH]{};
    need(SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, SHGFP_TYPE_CURRENT,
                                    profile_home)),
         "Windows console home unavailable");
    const std::filesystem::path home = value.at("home").get<std::string>();
    ordinary(home);
    need(home == std::filesystem::path(profile_home) &&
                 discovery == home / "Library/Caches/TemporaryItems/avd/running",
         "diagnostic console home or discovery root differs");
    const std::filesystem::path base = value.at("base_root").get<std::string>();
    ordinary(base);
    need(base.parent_path().filename() == "android-base",
         "diagnostic clean base confinement differs");
    const auto &disk_tools = value.at("disk_tools");
    need(disk_tools.is_object() && disk_tools.size() == 2, "diagnostic disk tool pins required");
    checked_file(sdk / "emulator/qemu-img", disk_tools.at("qemu-img").get<std::string>(), 64 * mib);
    checked_file(sdk / "emulator/bin64/mkfs.ext4", disk_tools.at("mkfs.ext4").get<std::string>(),
                 64 * mib);

    if (value.contains("qnx")) {
        const auto &qnx = value.at("qnx");
        need(qnx.is_object() && qnx.size() == 2, "QNX native binding exact fields required");
        const std::filesystem::path engine = qnx.at("executable").get<std::string>();
        checked_file(engine, qnx.at("sha256").get<std::string>(), 512 * mib);
        std::ifstream image(engine, std::ios::binary);
        unsigned char header[8]{};
        image.read(reinterpret_cast<char *>(header), 8);
        need(image.gcount() == 8 && header[0] == 0xcf && header[1] == 0xfa && header[2] == 0xed &&
                     header[3] == 0xfe && header[4] == 12 && header[5] == 0 && header[6] == 0 &&
                     header[7] == 1,
             "QNX diagnostic engine must be pinned native Mach-O ARM64, not PE/proxy");
    }

    const auto executable = sdk / "emulator/emulator";
    checked_file(executable, value.at("sdk_sha256").get<std::string>(), 512 * mib);
    checked_file(launcher, value.at("launcher_sha256").get<std::string>(), 512 * mib);
    value["executable"] = executable.string();

    return value;
#else
    return Json::object();
#endif
}
} // namespace portable_detail

Json portable_qnx_diagnostic_launch(Json launch, const Json &binding) {
    if (binding.empty() || !binding.contains("qnx")) {
        return launch;
    }

    need(binding.at("schema") == 1 && binding.contains("launcher"),
         "QNX native diagnostic launcher capability required");
    const auto &native = binding.at("qnx");
    need(native.is_object() && native.size() == 2, "exact QNX native executable/pin required");
    const auto executable = native.at("executable").get<std::string>(),
               pin = native.at("sha256").get<std::string>();
    need(!executable.empty() && !executable.ends_with(".exe") && sha256_text(pin),
         "Mac QNX binary and exact pin required");
    need(launch.at("qmp").is_object() &&
                 launch.at("qmp").value("host", std::string{}) == "127.0.0.1",
         "QNX native diagnostic requires owned loopback TCP QMP");
    auto &args = launch.at("qemu").at("args");
    need(args.is_array(), "QNX argument array required");
    const bool persistent = launch.contains("persistent_storage");
    need(launch.value("ram_backend", std::string{}) == "file",
         "QNX diagnostic selection requires the exact original RAM backend");

    if (persistent) {
        const auto &storage = launch.at("persistent_storage");
        need(storage.is_object() && storage.size() == 3 &&
                     storage.at("schema").is_number_integer() && storage.at("schema") == 1 &&
                     storage.at("system").is_string() && storage.at("userdata").is_string(),
             "QNX diagnostic persistent storage exact fields required");
    }

    for (std::size_t i = 0; i < args.size();) {
        if (args[i] == "-icount") {
            need(i + 1 < args.size() && args[i + 1].is_string() &&
                         !args[i + 1].get<std::string>().starts_with("-"),
                 "QNX native diagnostic requires an explicit icount value");
            args.erase(args.begin() + i, args.begin() + i + 2);
        } else {
            ++i;
        }
    }

    const unsigned memory_mib =
            launch.value("hardware_adapter", std::string{}) == "sa8155-passion-21480" ? 11713
                                                                                      : 8192;

    if (memory_mib == 11713) {
        unsigned matches = 0;

        for (std::size_t i = 0; i + 1 < args.size(); ++i) {
            if (args[i] == "-m") {
                need(args[i + 1] == "11713", "Passion diagnostic memory extent differs");
                ++matches;
            }
        }

        need(!persistent && matches == 1, "exact nonpersistent Passion memory extent required");
    }

    const auto ram =
            persistent ? qnx_persistent_ram_launch(
                                 QnxEngine::hvf,
                                 launch.at("persistent_storage").at("system").get<std::string>(),
                                 launch.at("persistent_storage").at("userdata").get<std::string>())
                       : qnx_ram_launch(QnxEngine::hvf, memory_mib);

    if (persistent) {
        unsigned objects = 0, nodes = 0;

        for (const auto &arg : args) {
            if (arg == "-object") {
                ++objects;
            }

            if (arg == "-numa") {
                ++nodes;
            }
        }

        need(objects == 5 && nodes == 5,
             "QNX diagnostic requires exactly five persistent NUMA backends");
    }

    // The HVF engine maps the same RAM file and disks as the original launch.
    for (std::size_t i = 0; i < ram.options.size(); i += 2) {
        unsigned matches = 0;

        for (std::size_t j = 0; j + 1 < args.size(); ++j) {
            if (args[j] == ram.options[i] && args[j + 1] == ram.options[i + 1]) {
                ++matches;
            }
        }

        need(matches == 1, "QNX diagnostic RAM mapping differs");
    }

    bool machine = false, accel = false, cpu = false;

    for (std::size_t i = 0; i + 1 < args.size(); ++i) {
        const auto option = args[i].get<std::string>();

        if (option == "-machine") {
            args[++i] = ram.machine;
            machine = true;
        } else if (option == "-accel") {
            args[++i] = ram.accelerator;
            accel = true;
        } else if (option == "-cpu") {
            args[++i] = "host";
            cpu = true;
        }
    }

    need(machine && accel && cpu, "QNX native launch must carry explicit machine/accel/CPU");

    launch["qemu"]["executable"] = executable;
    launch["diagnostic_native"] = {{"schema", 1},
                                   {"executable", executable},
                                   {"launcher", binding.at("launcher")},
                                   {"qmp_port", launch.at("qmp").at("port")}};

    if (persistent) {
        launch["diagnostic_native"]["persistent_backend"] = "macos-file-numa-v1";
        launch["diagnostic_native"]["engine_sha256"] = pin;
    }

    add_pin(launch["pins"], executable, pin);

    return launch;
}

bool portable_qnx_diagnostic_current(const Json &launch, const Json &binding) {
    const auto actual = launch.value("diagnostic_native", Json::object());

    if (binding.empty() || !binding.contains("qnx")) {
        return actual.empty();
    }

    const auto &qnx = binding.at("qnx");
    Json expected = {{"schema", 1},
                     {"executable", qnx.at("executable")},
                     {"launcher", binding.at("launcher")},
                     {"qmp_port", launch.at("qmp").at("port")}};

    if (launch.contains("persistent_storage")) {
        expected["persistent_backend"] = "macos-file-numa-v1";
        expected["engine_sha256"] = qnx.at("sha256");
    }

    if (actual != expected || launch.value("ram_backend", std::string{}) != "file" ||
        launch.at("qemu").at("executable") != qnx.at("executable")) {
        return false;
    }

    unsigned matching = 0;

    for (const auto &pin : launch.value("pins", Json::array())) {
        if (pin.value("path", std::string{}) == qnx.at("executable").get<std::string>()) {
            if (pin.value("sha256", std::string{}) != qnx.at("sha256").get<std::string>()) {
                return false;
            }

            ++matching;
        }
    }

    return matching == 1;
}

Json portable_sdk_control_binding(const std::filesystem::path &root,
                                  const PortableRuntimeHostBindings &host) {
    need(root.is_absolute() && host.android_port >= 5554 && host.android_port <= 5682 &&
                 host.android_port % 2 == 0,
         "SDK binding requires an absolute project and valid Android port");
    const bool frontend = !host.frontend.empty();
    const auto grpc = frontend ? host.frontend.at("grpc_port").get<unsigned>()
                               : host.android_port + 30000;
    const auto os_root = std::getenv(std::string(os::sdk_discovery_root_variable).c_str());
    const auto diagnostic = wine_native_diagnostic_binding();
    const auto discovery =
            diagnostic.empty()
                    ? sdk_registration_directory(os_root ? os_root : "",
                                                 root / ".local/build/sdk-registration")
                    : std::filesystem::path(diagnostic.at("discovery_root").get<std::string>());
    need(grpc >= 1024 && grpc <= 65535 && grpc != host.android_port &&
                 grpc != host.android_port + 1 && discovery.is_absolute(),
         "isolated SDK control port and absolute discovery root required");

    return {{"grpc_port", grpc}, {"discovery_root", discovery.string()}};
}

namespace portable_detail {
// A system generation retains the accepted machine snapshot and application disks.
// Its cold proof belongs to its own source snapshot and five fresh candidate images.
Json passion_system_evidence(const std::filesystem::path &seed, const Json &manifest,
                             const std::filesystem::path &staged) {
    const auto &android = manifest.at("android");
    const auto &lineage = android.at("system_upgrade");

    need(lineage.is_object() && lineage.size() == 4 && lineage.at("schema") == 1,
         "exact Passion system lineage required");
    const auto prefix = "android/system-versions/" +
                        android.at("images").at("system.img").at("sha256").get<std::string>() + "/";
    auto read = [&](const char *role, const char *name, std::uint64_t limit) {
        const auto &descriptor = lineage.at(role);
        need(descriptor.is_object() && descriptor.size() == 3 &&
                     descriptor.at("file") == prefix + name &&
                     descriptor.at("bytes").is_number_unsigned() &&
                     descriptor.at("bytes").get<std::uint64_t>() <= limit,
             "fixed bounded system proof required");
        const auto file = staged.empty() ? seed / descriptor.at("file").get<std::string>()
                                         : staged / name;
        checked_file(file, descriptor.at("sha256").get<std::string>(), limit);
        need(std::filesystem::file_size(file) == descriptor.at("bytes").get<std::uint64_t>(),
             "system proof extent differs");

        return read_private_json(file, limit);
    };
    const auto definition = read("source_profile", "source-profile.json", 1 << 20),
               candidate = read("candidate", "cold-candidate.json", 1 << 20),
               parent = read("parent_manifest", "parent-manifest.json", 128 * 1024);
    api30_framework_boot::verify(definition);
    need(candidate.at("schema") == 1 && candidate.at("kind") == "android-candidate" &&
                 candidate.at("profile") == manifest.at("profile") &&
                 definition.at("id") == manifest.at("profile") &&
                 record_declares(definition, ProfilePlatform::passion, ProfileBoard::sa8155) &&
                 candidate.at("profile_sha256") == lineage.at("source_profile").at("sha256") &&
                 candidate.at("stopped") == true && candidate.at("cold_boot_verified") == true &&
                 candidate.at("prepared_VM") == true &&
                 candidate.at("old_machine_modified") == false,
         "actual stopped Passion cold candidate required");
    need(candidate.at("clean_base_archive_sha256") == android.at("base_archive_sha256") &&
                 definition.at("android").at("sha256") == android.at("base_archive_sha256") &&
                 candidate.at("android").at("abi") ==
                         native_base_identity(definition.at("android")).abi,
         "system proof clean base differs");
    const auto paths = api30_framework_boot::paths(definition);
    std::set<std::string> compiled;
    unsigned bridge = 0;

    for (const auto &row : candidate.at("installed")) {
        if (row.at("artifact") == "component:view-observation") {
            need(row.at("target") == "/system/framework/framework.jar" &&
                         row.at("mode") == "0644" && !row.at("mutable").get<bool>(),
                 "cold bridge installation differs");
            ++bridge;
        }

        if (row.at("artifact") == "compiled-boot-image") {
            need(compiled.insert(row.at("target").get<std::string>()).second,
                 "duplicate cold boot image");
        }
    }

    need(bridge == 1 && api30_framework_boot::compiled(definition, candidate.at("events")) &&
                 compiled == std::set<std::string>(paths.begin(), paths.end()),
         "complete cold bridge boot extension required");
    const auto &fresh = candidate.at("android").at("images");
    need(fresh.is_object() && fresh.size() == 5, "complete cold candidate image set required");

    for (const auto *role :
         {"system.img", "vendor.img", "userdata-qemu.img", "encryptionkey.img", "cache.img"}) {
        need(fresh.at(role).at("file") == std::string("android/") + role &&
                     sha256_text(fresh.at(role).at("sha256").get<std::string>()),
             "fixed cold image descriptor required");
    }

    const auto &vendor = android.at("images").at("vendor.img");
    need(fresh.at("vendor.img").at("sha256") == vendor.at("sha256") &&
                 fresh.at("vendor.img").at("bytes") == vendor.at("bytes"),
         "cold vendor differs from retained vendor");
    const auto &system = android.at("images").at("system.img");
    need(system.at("file") == prefix + "system.img" &&
                 fresh.at("system.img").at("sha256") == system.at("sha256") &&
                 fresh.at("system.img").at("bytes") == system.at("bytes"),
         "cold proof system binding differs");
    auto retained = manifest;
    retained["android"]["images"]["system.img"] =
            parent.at("android").at("images").at("system.img");
    retained["android"].erase("system_upgrade");

    for (const auto *key : {"display_power", "mcu_property"}) {
        if (parent.at("android").contains(key)) {
            retained["android"][key] = parent.at("android").at(key);
        } else {
            retained["android"].erase(key);
        }
    }

    if (parent.at("android").contains("system_upgrade")) {
        retained["android"]["system_upgrade"] = parent.at("android").at("system_upgrade");
    }

    // Observer payloads have an independent stopped-machine publication transaction.
    // Verify their current physical descriptor, then compare the immutable system/disk
    // lineage with its original observer descriptor; no other component may drift.
    if (manifest.contains("ui_observer")) {
        (void)portable_observer_descriptor(seed, manifest);

        if (parent.contains("ui_observer")) {
            retained["ui_observer"] = parent.at("ui_observer");
        } else {
            retained.erase("ui_observer");
        }
    }

    need(retained == parent, "system lineage changed accepted machine identity or retained disks");
    validate_android_candidate_checks(definition, candidate.value("checks", Json()));

    return {{"profile", definition}, {"candidate", candidate}};
}
} // namespace portable_detail

// A host-only wheel addition may retain the original cold guest producer identity.
// Reconstruct its exact source bytes; provenance alone never relaxes the cold guards.
static std::pair<Json, std::string> passion_wheel_guest_source(const std::filesystem::path &seed,
                                                               const Json &manifest,
                                                               const Json &definition,
                                                               const Json &candidate) {
    const auto current = manifest.at("profile_sha256").get<std::string>();

    if (candidate.at("profile_sha256") == current) {
        return {definition, current};
    }

    need(definition.at("id") == manifest.at("profile") &&
                 record_declares(definition, ProfilePlatform::passion, ProfileBoard::sa8155) &&
                 !manifest.at("android").contains("system_upgrade"),
         "wheel provenance requires base Passion generation");
    const auto &descriptor = manifest.at("resources").at("ui/cockpit-provenance.json");
    need(descriptor.is_object() && descriptor.size() == 3 &&
                 descriptor.at("file") == "ui/cockpit-provenance.json" &&
                 descriptor.at("bytes").is_number_unsigned() &&
                 descriptor.at("bytes").get<std::uint64_t>() > 0 &&
                 descriptor.at("bytes").get<std::uint64_t>() <= 64 * 1024,
         "bounded exact wheel provenance descriptor required");
    const auto file = seed / "ui/cockpit-provenance.json";
    checked_file(file, descriptor.at("sha256").get<std::string>(), 64 * 1024);
    const auto bytes = read_private_json_bytes(file, 64 * 1024);
    need(bytes.size() == descriptor.at("bytes").get<std::uint64_t>() &&
                 sha256_bytes(bytes) == descriptor.at("sha256").get<std::string>(),
         "wheel provenance extent or pin differs");
    const auto provenance = Json::parse(bytes);
    need(provenance.is_object() && provenance.size() == 6 && provenance.at("schema") == 1 &&
                 provenance.at("kind") == "host-wheel-resource-refresh" &&
                 provenance.at("ui_profile_sha256") == current &&
                 provenance.at("guest_images_rebuilt") == false,
         "host-only wheel provenance required");
    const auto producer = provenance.at("guest_producer_profile_sha256").get<std::string>();
    need(sha256_text(producer) && candidate.at("profile_sha256") == producer,
         "wheel guest producer differs");
    const auto profile = seed / "profile.json";
    checked_file(profile, current, 1 << 20);
    const auto profile_bytes = read_private_json_bytes(profile, 1 << 20);
    need(sha256_bytes(profile_bytes) == current, "wheel current profile differs");
    auto original = nlohmann::ordered_json::parse(profile_bytes);
    need(Json(original) == definition && original.is_object() && original.contains("wheel"),
         "wheel current source differs");
    const auto &wheel = original.at("wheel");
    need(wheel.is_object() && wheel.size() == 3 &&
                 wheel.at("assets") == "profiles/common/wheels/passion-2024" &&
                 wheel.at("provenance").is_string() &&
                 Json(wheel.at("artwork")) == provenance.at("artwork"),
         "exact host wheel artwork required");
    original.erase("wheel");
    need(sha256_bytes(original.dump(2) + "\n") == producer, "wheel refresh changed guest source");
    need(manifest.at("candidate_receipt_sha256") ==
                         manifest.at("android").at("display_power").at("sha256") &&
                 manifest.at("candidate_receipt_sha256") ==
                         manifest.at("android").at("mcu_property").at("sha256"),
         "wheel cold candidate receipt differs");

    return {Json(original), producer};
}

namespace portable_detail {
Json portable_passion_power(const std::filesystem::path &seed, const Json &manifest,
                            const Json &definition) {
    if (manifest.at("android").contains("system_upgrade")) {
        const auto evidence = passion_system_evidence(seed, manifest);
        const auto &candidate = evidence.at("candidate");
        const auto &descriptor = manifest.at("android").at("display_power");
        const auto &proof = manifest.at("android").at("system_upgrade").at("candidate");
        need(descriptor.is_object() && descriptor.size() == 5 && descriptor.at("schema") == 1 &&
                     descriptor.at("file") == proof.at("file") &&
                     descriptor.at("sha256") == proof.at("sha256") &&
                     descriptor.at("bytes") == proof.at("bytes"),
             "system generation capability descriptor differs");
        const auto cap = validate_passion_power_candidate(
                evidence.at("profile"), candidate, candidate.at("android").at("images"),
                candidate.at("profile_sha256").get<std::string>());
        need(cap == descriptor.at("capability"), "system generation capability differs");

        return cap;
    }

    const auto &descriptor = manifest.at("android").at("display_power");
    need(descriptor.is_object() && descriptor.size() == 5 && descriptor.at("schema") == 1 &&
                 descriptor.at("file") == "display-power/candidate.json" &&
                 descriptor.at("bytes").is_number_unsigned() &&
                 descriptor.at("bytes").get<std::uint64_t>() <= 1ULL << 20,
         "bounded exact power evidence descriptor required");
    const auto file = seed / "display-power/candidate.json";
    checked_file(file, descriptor.at("sha256").get<std::string>(), 1 << 20);
    need(std::filesystem::file_size(file) == descriptor.at("bytes").get<std::uint64_t>(),
         "power evidence extent differs");
    const auto candidate = read_private_json(file, 1 << 20);
    const auto source = passion_wheel_guest_source(seed, manifest, definition, candidate);
    const auto cap = validate_passion_power_candidate(
            source.first, candidate, manifest.at("android").at("images"), source.second);
    need(cap == descriptor.at("capability"), "power capability differs from stopped cold evidence");

    return cap;
}

Json portable_passion_mcu(const std::filesystem::path &seed, const Json &manifest,
                          const Json &definition) {
    if (manifest.at("android").contains("system_upgrade")) {
        const auto evidence = passion_system_evidence(seed, manifest);
        const auto &candidate = evidence.at("candidate");
        const auto &descriptor = manifest.at("android").at("mcu_property");
        const auto &proof = manifest.at("android").at("system_upgrade").at("candidate");
        need(descriptor.is_object() && descriptor.size() == 5 && descriptor.at("schema") == 1 &&
                     descriptor.at("file") == proof.at("file") &&
                     descriptor.at("sha256") == proof.at("sha256") &&
                     descriptor.at("bytes") == proof.at("bytes"),
             "system generation capability descriptor differs");
        const auto cap = validate_passion_mcu_candidate(
                evidence.at("profile"), candidate, candidate.at("android").at("images"),
                candidate.at("profile_sha256").get<std::string>());
        need(cap == descriptor.at("capability"), "system generation capability differs");

        return cap;
    }

    const auto &descriptor = manifest.at("android").at("mcu_property");
    need(descriptor.is_object() && descriptor.size() == 5 && descriptor.at("schema") == 1 &&
                 descriptor.at("file") == "mcu-property/candidate.json" &&
                 descriptor.at("bytes").is_number_unsigned() &&
                 descriptor.at("bytes").get<std::uint64_t>() <= 1ULL << 20,
         "bounded exact MCU evidence descriptor required");
    const auto file = seed / "mcu-property/candidate.json";
    checked_file(file, descriptor.at("sha256").get<std::string>(), 1 << 20);
    need(std::filesystem::file_size(file) == descriptor.at("bytes").get<std::uint64_t>(),
         "MCU evidence extent differs");
    const auto candidate = read_private_json(file, 1 << 20);
    const auto source = passion_wheel_guest_source(seed, manifest, definition, candidate);
    const auto cap = validate_passion_mcu_candidate(
            source.first, candidate, manifest.at("android").at("images"), source.second);
    need(cap == descriptor.at("capability"), "MCU capability differs from stopped cold evidence");

    return cap;
}
} // namespace portable_detail

Json portable_android_launch(const std::filesystem::path &root,
                             const PortableRuntimeHostBindings &host,
                             const std::filesystem::path &machine,
                             const std::filesystem::path &base, const std::filesystem::path &config,
                             const std::string &avd, Json pins, Json definition,
                             const Json &audio_diagnostic, std::string_view verified_profile) {
    need(root.is_absolute() && machine.is_absolute() && base.is_absolute() &&
                 config.is_absolute() && !avd.empty() && pins.is_array(),
         "absolute Android launch paths and pins required");
    const bool frontend = !host.frontend.empty();
    const std::string suffix(os::executable_suffix);
    const auto machine_name = avd.starts_with("voyemu-") ? avd.substr(7) : avd;
    // Without a verified profile or an id the runtime directory is named by the machine alone.
    const auto profile_name = verified_profile.empty() ? definition.value("id", machine_name)
                                                       : std::string(verified_profile);
    const auto identity = machine_identity(profile_name, machine_name);
    const auto runtime = native_machine_directory(root, profile_name, identity);
    Json android = {
            {"schema", 1},
            {"executable", android_sdk_program(host.sdk, !suffix.empty()).string()},
            {"adb_transport", "direct"},
            {"avd_name", avd},
            {"machine", machine.string()},
            {"base", base.string()},
            {"port", host.android_port},
            {"android_sdk_root", host.sdk.string()},
            {"pins", pins},
            {"config_template", config.string()},
            {"features", {{"MultiDisplay", "on"}, {"VirtioInput", "on"}, {"VirtioTablet", "off"}}},
            {"gpuMode", "host"},
            {"audioOutput", true},
            {"home",
             {{"package", "com.qinggan.app.launcher"},
              {"component", "com.qinggan.app.launcher/.activity.MainActivity"}}},
            {"vehicle_adapter", {{"authority", "com.voyemu.output.vehicle"}}},
            {"systemui_adapter", {{"component", "com.qinggan.systemui/.SystemUIService"}}},
            {"headless", frontend},
            {"env",
             {{"TMPDIR", (runtime / "tmp").string()},
              {"ANDROID_TMP", (runtime / "tmp").string()},
              {"ANDROID_EMULATOR_HOME", (runtime / "emulator-home").string()}}}};
    const auto reference = runtime_profile_reference(definition, verified_profile);

    if (!reference.empty()) {
        android["reference_profile"] = reference;
    }

    // The launch record carries the platform and board of its profile for the runtime.
    if (definition.contains("platform")) {
        android["platform"] = definition.at("platform");
        android["board"] = definition.at("board");
    }

    const auto phone_adapter = phone_adapter_for_profile(definition, verified_profile);

    if (!phone_adapter.empty()) {
        android["phone_adapter"] = phone_adapter;
    }

    const auto diagnostic_native = wine_native_diagnostic_binding();

    if (!diagnostic_native.empty()) {
        android["diagnostic_native"] = diagnostic_native;
        android["executable"] = diagnostic_native.at("executable");
        add_pin(android["pins"], diagnostic_native.at("executable").get<std::string>(),
                diagnostic_native.at("sdk_sha256").get<std::string>());
        add_pin(android["pins"], diagnostic_native.at("launcher").get<std::string>(),
                diagnostic_native.at("launcher_sha256").get<std::string>());
    }

    // The window names the machine by the title of its profile, such as "Voyemu Free 7.3.1".
    android["profile_title"] = profile_title(definition);
    const auto base_identity = definition.contains("android")
                                       ? native_base_identity(definition.at("android"))
                                       : AndroidBaseIdentity{28, "arm64-v8a"};
    const bool x86 = base_identity.abi == "x86_64";
    const bool accelerated = android_hardware_acceleration(base_identity.abi) ||
                             !diagnostic_native.empty();
    android["api"] = base_identity.api;

    if (x86) {
        android["guest_arch"] = base_identity.abi;
    }

    // The session confirms acceleration with the emulator before it starts such a guest.
    if (accelerated && android_acceleration_required(definition)) {
        android["acceleration"] = "required";
    }

    if (android.at("api") == 30) {
        need(definition.contains("configure") && definition.at("configure").contains("home") &&
                     definition.at("configure").contains("homeActivity"),
             "API30 profile HOME package and activity metadata required");
    }

    if (definition.contains("android")) {
        android["features"] = definition.at("android").value("features", Json::object());
    }

    // The window, frames and screenshots take the screens of the machine from its profile.
    if (definition.contains("displays")) {
        (void)profile_screens(definition.at("displays"));
        android["screens"] = definition.at("displays");
    }

    if (definition.contains("emulator")) {
        const auto &emulator = definition.at("emulator");
        android["gpuMode"] = emulator.value("gpuMode", std::string("host"));
        android["audioOutput"] = android_launch_audio_output(emulator, x86);
    }

    if (definition.contains("configure")) {
        const auto &configured = definition.at("configure");

        if (configured.contains("home")) {
            android["home"] = {{"package", configured.at("home")}};

            if (configured.contains("homeActivity")) {
                android["home"]["component"] = configured.at("homeActivity");
            }
        }
    }

    // Production policy never routes ordinary sound into a diagnostic WAV; a permanent
    // configure.diagnosticAudio field fails closed. Prepared seed snapshots may predate its
    // removal, so an owned host refresh rebuilds the launch specification from the current
    // canonical profile while every other acceptance field stays pinned to the seed snapshot.
    const auto diagnostic_profile = verified_profile.empty() ? definition.value("id", std::string{})
                                                             : std::string(verified_profile);

    if (!audio_diagnostic.empty() && definition.contains("id")) {
        need(definition.at("id") == diagnostic_profile,
             "audio diagnostic verified profile differs from selected definition");
    }

    if (definition.contains("configure") &&
        definition.at("configure").contains("diagnosticAudio") && !audio_diagnostic.empty() &&
        diagnostic_profile == audio_diagnostic.value("profile", std::string{})) {
        definition["configure"].erase("diagnosticAudio");
    }

    if (definition.contains("configure") &&
        definition.at("configure").contains("diagnosticAudio")) {
        throw VoyemuError(
                "ANDROID_AUDIO_DIAGNOSTIC",
                "permanent profile diagnosticAudio policy rejected; use a scoped owned run");
    }

    if (!audio_diagnostic.empty()) {
        need(!diagnostic_profile.empty() &&
                     audio_diagnostic.value("profile", std::string{}) == diagnostic_profile,
             "audio diagnostic profile differs from selected definition");
        need(android.at("api") == 30 ||
                     ((record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::nxp) ||
                       record_declares(definition, ProfilePlatform::qinggan09,
                                       ProfileBoard::sa8155)) &&
                      android.at("api") == 28),
             "audio diagnostic requires the selected pinned runtime");
        android["diagnostic_audio"] = "wav";
    }

    const bool passion = record_declares(definition, ProfilePlatform::passion,
                                         ProfileBoard::sa8155);
    const bool nxp = record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::nxp);

    if (passion) {
#ifdef _WIN32
        throw VoyemuError("PASSION_PRESENTATION",
                          "Windows presentation startup is not yet supported");
#endif
        need(android.at("api") == 30 && android.at("home").at("component") == passion_home,
             "exact Passion API30 HOME required");
        const auto screens = android_screens(definition.at("displays"));
        need(screens.size() == 2 && definition.at("emulator").at("cores") == 4,
             "Passion developer two-display/four-core contract required");

        for (const auto &screen : screens) {
            need(screen.width == 1920 && screen.height == 720 && screen.density == 160,
                 "Passion developer display geometry differs");
        }

        android.erase("vehicle_adapter");
        android.erase("systemui_adapter");
        android["presentation_adapter"] = passion_presentation_contract(reference);
        need(passion_presentation(android), "Passion presentation contract required");
    } else {
        need(android.at("home").at("package") == "com.qinggan.app.launcher",
             "selected HOME family requires its own native vehicle/display adapter; Free/Dreamer bindings cannot be reused");
    }

    if (os::host_windows && diagnostic_native.empty()) {
        android["rendererPolicy"] = "windows-angle-36.3.10";
    }

    android["args"] = Json::array({"-accel", accelerated ? "on" : "off"});
    const char *inherited_path = std::getenv("PATH");

    for (const auto &[key, value] :
         android_sdk_environment(host.sdk, !suffix.empty() && diagnostic_native.empty(),
                                 inherited_path ? inherited_path : "")) {
        android["env"][key] = value;
    }

    if (!host.ui_observer.empty()) {
        need(portable_ui_observer_binding(host.ui_observer, definition.value("id", std::string{})),
             "exact observer binding required");
        const std::filesystem::path dex = host.ui_observer.at("dex").get<std::string>();
        const auto pin = tool_pin(root, host, dex);
        need(host.ui_observer.at("sha256").get<std::string>() == pin, "observer pin mismatch");
        android["ui_observer"] = host.ui_observer;
        add_pin(android["pins"], dex, pin);
    }

    android["sdk_control"] = portable_sdk_control_binding(root, host);
    const auto grpc = android.at("sdk_control").at("grpc_port").get<unsigned>();
    android["args"].push_back("-grpc");
    android["args"].push_back(std::to_string(grpc));
    android["args"].push_back("-grpc-use-token");

    if (frontend) {
        android["frontend"] = host.frontend;
        android["args"].push_back("-no-window");
    }

    if (nxp) {
        need(android.at("api") == 28 && android.at("home").at("component") == nxp_home,
             "exact NXP API28 HOME required");
        android.erase("vehicle_adapter");
        android.erase("systemui_adapter");
        android["presentation_adapter"] = nxp_presentation_contract(reference);
        need(nxp_presentation(android), "NXP presentation contract required");

        if (!definition.value("components", Json::object()).contains("wheel")) {
            return android;
        }
    }

    if (passion) {
        android["wheel_capability"] = passion_wheel_capability(definition);

        if (android.at("wheel_capability").at("supported") == true) {
            android["wheel_adapter"] = {{"authority", "com.voyemu.input.wheel"},
                                        {"routes", passion_wheel_routes()}};
        }

        android["presentation_adapter"] = passion_presentation_contract(
                reference, false, passion_wheel_partial(android.at("wheel_capability")));

        return android;
    }

    if (qinggan11_wheel_provider(definition)) {
        android["wheel_capability"] = qinggan11_wheel_capability(definition);

        if (android.at("wheel_capability").at("supported") == true) {
            android["wheel_adapter"] = qinggan11_wheel_adapter();
        }

        (void)qinggan11_wheel_unsupported(android);

        return android;
    }

    const auto route_file = definition.value("wheel", Json::object())
                                    .value("androidRoutes",
                                           std::string("src/app/android-wheel-routes.json"));
    const std::filesystem::path route_relative = route_file;
    need(!route_relative.is_absolute(), "relative wheel route metadata required");
    inside(root, root / route_relative);
    const auto route_metadata =
            !host.seed.empty()
                    ? read_private_json(portable_resource_path(host.seed, "ui/wheel-routes.json"))
            : route_file.starts_with("src/") ? project_file_json(root, route_file, 128 * 1024)
                                             : read_private_json(root / route_relative);
    Json routes = Json::object();

    for (const auto &row : route_metadata.at("routes")) {
        routes[row.at("id").get<std::string>()] = row.value("qg_code", Json{});
    }

    if (nxp) {
        need(route_metadata.value("profile", std::string{}) == reference &&
                     routes == nxp_wheel_routes(),
             "exact NXP wheel metadata required");
    }

    android["wheel_adapter"] = {
            {"authority", "com.voyemu.input.wheel"},
            {"component", "com.voyemu.oem/.RegistrationService"},
            {"action", "com.voyemu.input.action.WHEEL_INPUT_V1"},
            {"receipt_path", "/data/user/0/com.voyemu.oem/files/wheel-receipt.json"},
            {"routes", routes}};

    return android;
}

std::string verify_portable_host_tool(const std::filesystem::path &root,
                                      const PortableRuntimeHostBindings &host,
                                      const std::filesystem::path &file, bool installed) {
    return tool_pin(root, host, file, installed);
}

bool portable_runtime_available(const std::filesystem::path &root, std::string_view profile,
                                const MachineIdentity &machine,
                                const std::filesystem::path &explicit_seed) {
    const auto seed = seed_directory(root, profile, machine, explicit_seed);

    for (const auto &path : {explicit_seed.empty() ? root / "machines" : seed, seed}) {
        if (std::filesystem::is_symlink(path)) {
            return false;
        }
    }

    return ordinary_native_launch_file(seed / "runtime.json");
}

Json portable_profile_definition(const std::filesystem::path &root, std::string_view profile,
                                 const MachineIdentity &machine,
                                 const std::filesystem::path &explicit_seed) {
    if (!portable_runtime_available(root, profile, machine, explicit_seed)) {
        return authoring_profile(root, profile);
    }

    const auto seed = seed_directory(root, profile, machine, explicit_seed);
    ordinary(seed);
    const auto file = seed / "runtime.json";
    ordinary(file);
    need(std::filesystem::hard_link_count(file) == 1 &&
                 std::filesystem::file_size(file) < 128 * 1024,
         "bounded seed manifest required");
    const auto manifest = portable_profile_json(read_private_json_bytes(file, 128 * 1024));
    need(manifest.is_object() && manifest.value("schema", 0) == 1 &&
                 manifest.at("profile") == profile &&
                 manifest.at("kind") == "portable-guest-runtime",
         "manifest identity");
    const auto definition_file = seed / "profile.json";
    need(std::filesystem::exists(definition_file),
         "machine profile snapshot missing; prepared machines never use a shared build profile");
    checked_file(definition_file, manifest.at("profile_sha256").get<std::string>(), 1024 * 1024);

    if (manifest.at("android").contains("system_upgrade")) {
        return passion_system_evidence(seed, manifest).at("profile");
    }

    return portable_profile_json(read_private_json_bytes(definition_file, 1024 * 1024));
}

namespace portable_detail {
void check_android_guest_identity(const Json &definition, const Json &manifest) {
    need(definition.contains("android"), "profile declares no Android base");
    const auto &android = manifest.at("android");
    const auto identity = native_base_identity(definition.at("android"));

    (void)android_acceleration_required(definition);
    need(android.at("abi") == identity.abi && android.at("api") == identity.api &&
                 android.at("base_archive_sha256") == definition.at("android").at("sha256"),
         "registered clean base/API/ABI required");

    if (definition.contains("target") || android.contains("target")) {
        const auto target = definition.value("target", Json::object());
        const auto name = target.value("name", std::string{});
        need(valid_profile_name(name) && target.value("guestAbi", std::string{}) == identity.abi &&
                     android.value("target", std::string{}) == name,
             "portable Android target differs from its profile snapshot");
    }
}

std::string checked_can_model_receipt(const std::filesystem::path &seed, const Json &manifest) {
    const auto &android = manifest.at("android");

    if (!android.contains("can_model_receipt")) {
        return {};
    }

    const auto &d = android.at("can_model_receipt");
    need(d.is_object() && d.size() == 3 && d.at("file") == "can-model/candidate.json" &&
                 d.at("bytes").is_number_unsigned() &&
                 d.at("bytes").get<std::uint64_t>() <= (1ULL << 20),
         "CAN receipt descriptor invalid");
    const auto file = seed / "can-model/candidate.json";
    const auto sha = d.at("sha256").get<std::string>();
    checked_file(file, sha, 1 << 20);
    need(std::filesystem::file_size(file) == d.at("bytes").get<std::uint64_t>(),
         "CAN receipt extent differs");

    if (manifest.contains("scope")) {
        need(manifest.at("candidate_receipt_sha256") == sha, "CAN receipt scope differs");
    }

    return can_model_candidate_hash(
            read_private_json(file, 1 << 20), manifest.at("profile").get<std::string>(),
            manifest.at("profile_sha256").get<std::string>(),
            android.at("images").at("system.img").at("sha256").get<std::string>());
}

Json checked_development_kernel(const std::filesystem::path &seed, const Json &definition,
                                const Json &manifest) {
    const auto development = portable_development_kernel(definition);
    const auto &android = manifest.at("android");

    need(android.contains("development_kernel") == !development.is_null(),
         "development kernel declaration differs");

    if (development.is_null()) {
        return development;
    }

    need(android.at("development_kernel") == development && android.contains("boot_files"),
         "development kernel manifest differs");
    const auto &image = android.at("boot_files").at("kernel-ranchu");
    need(image.is_object() && image.size() == 3 && image.at("file") == "android/kernel-ranchu" &&
                 image.at("sha256") == development.at("sha256"),
         "development kernel image differs");
    const auto kernel = seed / "android/kernel-ranchu";
    checked_file(kernel, development.at("sha256").get<std::string>(), 64 * mib);
    need(image.at("bytes") == std::filesystem::file_size(kernel),
         "development kernel extent differs");

    return development;
}
} // namespace portable_detail

static Json inspect_portable_runtime_impl(const std::filesystem::path &root,
                                          std::string_view profile, const MachineIdentity &machine,
                                          const std::filesystem::path &explicit_seed) {
    ordinary(root);
    need(portable_runtime_available(root, profile, machine, explicit_seed),
         "portable seed missing");
    const auto seed = seed_directory(root, profile, machine, explicit_seed);
    ordinary(seed);
    const auto file = seed / "runtime.json";
    ordinary(file);
    need(std::filesystem::hard_link_count(file) == 1 &&
                 std::filesystem::file_size(file) < 128 * 1024,
         "bounded seed manifest required");
    const auto epoch = cache_file_identity(file);
    const auto sha = sha256_file(file);
    const auto manifest = portable_profile_json(read_private_json_bytes(file, 128 * 1024));
    need(manifest.is_object() && manifest.value("schema", 0) == 1 &&
                 manifest.at("profile") == profile &&
                 manifest.at("kind") == "portable-guest-runtime",
         "manifest identity");
    const auto definition = portable_profile_definition(root, profile, machine, seed);
    const auto family = runtime_profile_reference(definition, profile);
    check_android_guest_identity(definition, manifest);
    const auto boot_pins = checked_signed_android_boot_pins(seed, definition, manifest);
    const auto api = manifest.at("android").at("api").get<unsigned>();
    const bool android_only = manifest.contains("scope");

    if (android_only) {
        need(manifest.at("scope") == "android" && manifest.at("cluster_available") == false &&
                     !manifest.contains("qnx") &&
                     sha256_text(manifest.at("candidate_receipt_sha256").get<std::string>()),
             "invalid Android-only scope");
    }

    need(manifest.size() == (android_only ? 8 : (manifest.contains("qnx") ? 6 : 5)) +
                                    (manifest.contains("ui_observer") ? 1 : 0) +
                                    (manifest.contains("resources") ? 1 : 0) &&
                 manifest.at("android").size() ==
                         4 + (manifest.at("android").contains("target") ? 1 : 0) +
                                 (manifest.at("android").contains("display_power") ? 1 : 0) +
                                 (manifest.at("android").contains("mcu_property") ? 1 : 0) +
                                 (manifest.at("android").contains("owned_package") ? 1 : 0) +
                                 (manifest.at("android").contains("camera_package") ? 1 : 0) +
                                 (manifest.at("android").contains("prepared_packages") ? 1 : 0) +
                                 (manifest.at("android").contains("system_upgrade") ? 1 : 0) +
                                 (manifest.at("android").contains("qinggan09_owned_packages") ? 1
                                                                                              : 0) +
                                 (manifest.at("android").contains("qinggan09_phone_package") ? 1
                                                                                             : 0) +
                                 (manifest.at("android").contains("boot_files") ? 1 : 0) +
                                 (manifest.at("android").contains("development_kernel") ? 1 : 0) +
                                 (manifest.at("android").contains("signed_android") ? 1 : 0) +
                                 (manifest.at("android").contains("can_model_receipt") ? 1 : 0),
         "unknown portable fields");
    (void)checked_development_kernel(seed, definition, manifest);
    (void)checked_can_model_receipt(seed, manifest);

    if (manifest.at("android").contains("boot_files")) {
        const auto &boot = manifest.at("android").at("boot_files");
        need(boot.is_object() && boot.size() == boot_pins.size(), "machine boot file roles differ");

        for (const auto &[name, expected] : boot_pins) {
            const auto &descriptor = boot.at(name);
            const auto relative = std::string("android/") + name;
            need(descriptor.is_object() && descriptor.size() == 3 &&
                         descriptor.at("file") == relative,
                 "machine boot path differs");
            const auto path = seed / relative;
            checked_file(path, descriptor.at("sha256").get<std::string>(), 64 * mib);
            need(descriptor.at("bytes") == std::filesystem::file_size(path),
                 "machine boot extent differs");
        }
    }

    if (manifest.at("android").contains("system_upgrade")) {
        (void)passion_system_evidence(seed, manifest);
    }

    if (manifest.at("android").contains("owned_package")) {
        need(embedded_profile_declares(family, ProfilePlatform::qinggan11, ProfileBoard::sa8155) &&
                     api == 30,
             "owned package requires exact Free A11 profile");
        const auto &package = manifest.at("android").at("owned_package");
        android_owned_package_descriptor(package, true);
        const auto apk = seed / package.at("file").get<std::string>();
        checked_file(apk, package.at("sha256").get<std::string>(), 16 * mib);
        need(std::filesystem::file_size(apk) == package.at("bytes").get<std::uint64_t>(),
             "owned package extent differs");
    }

    if (manifest.at("android").contains("camera_package")) {
        need(embedded_profile_declares(family, ProfilePlatform::qinggan11, ProfileBoard::sa8155) &&
                     api == 30,
             "Camera package requires exact Free A11 profile");
        const auto &package = manifest.at("android").at("camera_package");
        android_camera_package_descriptor(package, true);
        const auto apk = seed / package.at("file").get<std::string>();
        checked_file(apk, package.at("sha256").get<std::string>(), 128 * mib);
        need(std::filesystem::file_size(apk) == package.at("bytes").get<std::uint64_t>(),
             "Camera package extent differs");
    }

    if (manifest.at("android").contains("prepared_packages")) {
        need(embedded_profile_declares(family, ProfilePlatform::qinggan11, ProfileBoard::sa8155) &&
                     api == 30 && !manifest.at("android").contains("camera_package"),
             "exact Free A11 prepared package list required");
        const auto &packages = manifest.at("android").at("prepared_packages");
        android_prepared_packages_descriptor(packages, true);

        for (const auto &package : packages) {
            const auto apk = seed / package.at("file").get<std::string>();
            checked_file(apk, package.at("sha256").get<std::string>(), 512 * mib);
            need(std::filesystem::file_size(apk) == package.at("bytes").get<std::uint64_t>(),
                 "prepared package extent differs");
        }
    }

    if (manifest.at("android").contains("qinggan09_owned_packages")) {
        need(record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
                     api == 28,
             "A9 packages require exact API28 profile");
        const auto &packages = manifest.at("android").at("qinggan09_owned_packages");
        qinggan09_owned_packages_descriptor(packages, true);

        for (const auto &package : qinggan09_owned_packages_payloads(packages)) {
            const auto apk = seed / package.at("file").get<std::string>();
            checked_file(apk, package.at("sha256").get<std::string>(), 16 * mib);
            need(std::filesystem::file_size(apk) == package.at("bytes").get<std::uint64_t>(),
                 "A9 package extent differs");
        }
    }

    if (manifest.at("android").contains("qinggan09_phone_package")) {
        need(record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::sa8155) &&
                     api == 28,
             "A9 Phone package requires exact API28 profile");
        const auto &descriptor = manifest.at("android").at("qinggan09_phone_package");
        qinggan09_phone_package_descriptor(descriptor, true);
        const auto &package = descriptor.at("package");
        const auto apk = seed / package.at("file").get<std::string>();
        checked_file(apk, package.at("sha256").get<std::string>(), 128 * mib);
        need(std::filesystem::file_size(apk) == package.at("bytes").get<std::uint64_t>(),
             "A9 Phone package extent differs");
    }

    if (manifest.at("android").contains("display_power")) {
        (void)portable_passion_power(seed, manifest, definition);
    }

    need(passion_mcu_requested(definition) == manifest.at("android").contains("mcu_property"),
         "partial MCU graph requires matching cold evidence");

    if (manifest.at("android").contains("mcu_property")) {
        (void)portable_passion_mcu(seed, manifest, definition);
    }

    auto roles = std::set<std::string>(android_names.begin(), android_names.end());
    roles.insert("cache.img");
    image_group(seed, manifest.at("android").at("images"), roles, "android", api, {},
                native_machine_directory(root, profile, machine) / "android");
    {
        const auto cache = seed / "android/cache.img";
        need(std::filesystem::file_size(cache) == 69206016, "prepared cache extent differs");
        std::ifstream input(cache, std::ios::binary);
        input.seekg(1080);
        std::array<unsigned char, 2> magic{};
        input.read(reinterpret_cast<char *>(magic.data()), magic.size());
        need(bool(input) && magic == std::array<unsigned char, 2>{0x53, 0xef},
             "prepared cache ext4 magic differs");
    }

    if (manifest.contains("qnx")) {
        const auto &qnx = manifest.at("qnx");
        const auto layout = qnx_portable_layout(family, qnx);
        image_group(seed, qnx.at("images"), qnx_image_roles(layout), "qnx", api,
                    layout.persistence.is_null() ? std::set<std::string>{}
                                                 : std::set<std::string>{"sysla-gpt-ramdisk-v3.img",
                                                                         "userdata-qnx6.img"});
    }

    if (manifest.contains("resources")) {
        for (auto item = manifest.at("resources").begin(); item != manifest.at("resources").end();
             ++item) {
            (void)portable_resource_path(seed, item.key());
        }
    }

    if (manifest.contains("ui_observer")) {
        (void)portable_observer_descriptor(seed, manifest);
    }

    need(cache_file_identity(file) == epoch && sha256_file(file) == sha, "manifest changed");

    return manifest;
}

Json inspect_portable_runtime(const std::filesystem::path &root, std::string_view profile,
                              const MachineIdentity &machine, const std::filesystem::path &seed) {
    return inspect_portable_runtime_impl(root, profile, machine, seed);
}
} // namespace voyemu
