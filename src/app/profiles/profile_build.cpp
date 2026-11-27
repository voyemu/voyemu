#include "java_toolchain.hpp"
#include "native_bridge.hpp"
#include "ordinary_path.hpp"
#include "profile_build_internal.hpp"
#include "profile_catalog.hpp"
#include "qnx_guest_build.hpp"

namespace voyemu {
using namespace profile_build_detail;
namespace {
// A consumer of a build generation directory holds this file shared; release takes it exclusively.
constexpr const char *build_output_lock = "build-output.lock";

// Cold candidates keep their origin across invocations; a live file lock alone cannot protect
// those consumers. Published candidates have finished consuming their artifact generation.
bool candidate_uses_artifacts(const std::filesystem::path &root,
                              const std::filesystem::path &own_candidate,
                              const std::filesystem::path &work) {
    for (const auto &entry : std::filesystem::directory_iterator(root / ".local/build")) {
        const auto candidate = entry.path();

        if (candidate == own_candidate || entry.is_symlink() || !entry.is_directory() ||
            !candidate.filename().string().starts_with("candidate-")) {
            continue;
        }

        try {
            ordinary(candidate);
            const auto origin = read_private_json(candidate / "artifact-origin.json", 8192);
            const auto receipt_pin = hash(candidate / "receipt.json", 1 << 20);

            if (origin.at("candidate_receipt_sha256") != receipt_pin) {
                continue;
            }

            const auto published_file = candidate / "build-publication.json";

            if (std::filesystem::exists(published_file) &&
                read_private_json(published_file, 128 * 1024).at("candidate_receipt_sha256") ==
                        receipt_pin) {
                continue;
            }

            const std::filesystem::path receipt = origin.at("artifact_receipt").get<std::string>();
            ordinary(receipt);
            inside(root / ".local", receipt);

            if (hash(receipt, 1 << 20) == origin.at("artifact_receipt_sha256").get<std::string>() &&
                read_private_json(receipt, 1 << 20).at("work") == work.string()) {
                return true;
            }
        } catch (const std::exception &) {
            // Ignored: missing or stale origin evidence does not establish an artifact consumer.
        }
    }

    return false;
}

// Receipts, logs, frames, signing authority and source patches outlive their generation.
bool build_evidence(const std::filesystem::path &file) {
    static const std::set<std::string> kept = {".json",     ".log",   ".txt", ".png",
                                               ".pem",      ".pk8",   ".jks", ".p12",
                                               ".keystore", ".patch", ".diff"};

    return kept.contains(file.extension().string()) || file.filename() == build_output_lock;
}

// Collects {file, sha256} and {directory, files} descriptors of a receipt; relative files belong
// to base. A path declared with two digests maps to an empty digest and is never released.
void declared_payloads(const Json &value, const std::filesystem::path &base,
                       std::map<std::filesystem::path, std::string> &payloads) {
    const auto add = [&](const std::filesystem::path &file, const std::string &sha256) {
        const auto path = (file.is_absolute() ? file : base / file).lexically_normal();

        if (const auto [at, added] = payloads.emplace(path, sha256);
            !added && at->second != sha256) {
            at->second.clear();
        }
    };

    if (value.is_object()) {
        if (value.contains("file") && value.at("file").is_string() && value.contains("sha256") &&
            value.at("sha256").is_string()) {
            add(value.at("file").get<std::string>(), value.at("sha256").get<std::string>());
        }

        if (value.contains("directory") && value.at("directory").is_string() &&
            value.contains("files") && value.at("files").is_object()) {
            const std::filesystem::path directory = value.at("directory").get<std::string>();

            for (const auto &[name, item] : value.at("files").items()) {
                if (item.is_object() && item.contains("sha256") && item.at("sha256").is_string()) {
                    add(directory / name, item.at("sha256").get<std::string>());
                }
            }
        }
    }

    if (value.is_structured()) {
        for (const auto &item : value) {
            declared_payloads(item, base, payloads);
        }
    }
}

// Removes declared payloads whose bytes still match their receipt and, with scratch, every other
// non-evidence file; then empty subdirectories. Returns the released bytes.
std::uint64_t
release_generation_directory(const std::filesystem::path &directory,
                             const std::map<std::filesystem::path, std::string> &payloads,
                             bool scratch, Json &retained) {
    std::vector<std::filesystem::path> files, directories;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_symlink()) {
            continue;
        }

        if (entry.is_directory()) {
            directories.push_back(entry.path());
        } else if (entry.is_regular_file() && !build_evidence(entry.path())) {
            files.push_back(entry.path());
        }
    }

    std::uint64_t released = 0;

    for (const auto &file : files) {
        const auto declared = payloads.find(file.lexically_normal());

        if (declared == payloads.end() ? !scratch : declared->second != sha256_file(file)) {
            if (declared != payloads.end()) {
                retained.push_back({{"path", file.string()}, {"reason", "payload changed"}});
            }

            continue;
        }

        const auto bytes = std::filesystem::file_size(file);
        need(std::filesystem::remove(file), "build output release failed: " + file.string());
        released += bytes;
    }

    for (auto at = directories.rbegin(); at != directories.rend(); ++at) {
        std::error_code error;

        if (std::filesystem::is_empty(*at, error)) {
            std::filesystem::remove(*at, error);
        }
    }

    return released;
}
} // namespace

namespace profile_build_detail {
std::function<void()> capture_authoring_inputs(const std::filesystem::path &root,
                                               std::string_view profile) {
    const auto definition_file = authoring_definition(root, profile),
               qnx_file = authoring_directory(root, profile) / "profile-qnx.json";
    const auto name = std::string(profile);
    const auto definition_epoch = cache_file_identity(definition_file),
               qnx_epoch = cache_file_identity(qnx_file);
    const auto profile_pin = sha256_bytes(authoring_profile_bytes(root, name)),
               qnx_pin = hash(qnx_file, 128 * 1024);
    const auto validate = [=] {
        need(cache_file_identity(definition_file) == definition_epoch &&
                     cache_file_identity(qnx_file) == qnx_epoch &&
                     sha256_bytes(authoring_profile_bytes(root, name)) == profile_pin &&
                     hash(qnx_file, 128 * 1024) == qnx_pin,
             "authoring files changed during build");
    };

    validate();

    return validate;
}

void inside(const std::filesystem::path &root, const std::filesystem::path &path) {
    const auto relative = path.lexically_relative(root);

    need(!relative.empty() && relative != "." && !relative.is_absolute(),
         "path must be inside project");

    for (const auto &part : relative) {
        need(part != "..", "path leaves project");
    }
}

void ordinary(const std::filesystem::path &p) {
    ordinary_path(p, need, PathForm::Normalized, "absolute normalized input required",
                  "linked path rejected");
}

std::string hash(const std::filesystem::path &file, std::uint64_t bound) {
    ordinary(file);
    need(std::filesystem::is_regular_file(file),
         "ordinary bounded file required (not regular): " + file.string());
    need(std::filesystem::hard_link_count(file) == 1,
         "ordinary bounded file required (link count): " + file.string());
    need(std::filesystem::file_size(file) <= bound,
         "ordinary bounded file required (size limit): " + file.string());
    const auto epoch = cache_file_identity(file);
    const auto pin = sha256_file(file);
    need(cache_file_identity(file) == epoch, "file changed while hashing");

    return pin;
}

// The authoring profile.json, which build reads and pins directly from profiles/.
std::filesystem::path authoring_definition(const std::filesystem::path &root,
                                           std::string_view profile) {
    return root / "profiles" / std::string(profile) / "profile.json";
}

void root_profile(const std::filesystem::path &root, std::string_view profile) {
    ordinary(root);
    need(std::filesystem::is_directory(root) && std::filesystem::canonical(root) == root &&
                 valid_profile_name(profile),
         "canonical root/profile required");
    const auto definition = authoring_definition(root, profile);

    // An unknown profile fails as in fetch.
    if (!std::filesystem::exists(definition) && !std::filesystem::is_symlink(definition)) {
        (void)embedded_profile(profile);
    }

    hash(definition, 1 << 20);
    const auto status = portable_profile_json(read_private_json_bytes(definition, 1 << 20))
                                .value("status", std::string("ready"));
    need(status == "ready" || status == "incomplete", "invalid profile source status");
}

std::string exe() {
    return std::string(os::executable_suffix);
}

std::string backend_host() {
    return std::string(os::emulator_host);
}

std::filesystem::path build_target(const std::filesystem::path &root, std::string_view profile,
                                   const MachineIdentity &machine) {
    need(machine.valid_for(profile), "valid machine child name required");

    return root / "machines" / machine.name;
}

std::map<std::string, std::string> host_pins(const std::filesystem::path &sdk,
                                             const Json &definition) {
    std::map<std::string, std::string> pins;

    for (const auto &file :
         {sdk / "emulator" / ("emulator" + exe()), sdk / "platform-tools" / ("adb" + exe()),
          sdk / "build-tools/36.1.0" / ("aapt2" + exe()), sdk / "emulator" / ("qemu-img" + exe()),
          sdk / "emulator" / "qemu" / backend_host() /
                  ("qemu-system-" + std::string(android_qemu_arch(android_guest_abi(definition))) +
                   exe())}) {
        pins[file.string()] = hash(file, 512ULL << 20);
    }

    if (android_guest_abi(definition) == "x86_64") {
        const auto headless = android_sdk_headless_engine(sdk / "emulator/qemu" / backend_host());
        pins[headless.string()] = hash(headless, 512ULL << 20);
    }

    return pins;
}

void publish(const std::filesystem::path &from, const std::filesystem::path &to) {
    need(os::rename_exclusive(from, to), "exclusive profile publication failed");
}

Json copy_images(const std::filesystem::path &root, const std::filesystem::path &source,
                 const Json &images, const std::filesystem::path &stage, const std::string &group,
                 const std::set<std::string> &roles, std::uint64_t reserve,
                 progress::Meter *meter) {
    need(images.is_object() && images.size() == roles.size(),
         "exact portable guest roles required");
    Json output = Json::object();

    for (auto it = images.begin(); it != images.end(); ++it) {
        need(roles.contains(it.key()), "unknown portable role");
        const std::filesystem::path relative = it.value().at("file").get<std::string>();
        need(relative == std::filesystem::path(group) / it.key(),
             "fixed guest image path required");
        const auto file = source / relative;
        inside(root / ".local", file);
        const auto pin = hash(file);
        need(it.value().at("sha256") == pin &&
                     it.value().at("bytes") == std::filesystem::file_size(file),
             "guest image pin/extent mismatch");

        if (group == "android" && it.key() == "cache.img") {
            std::ifstream input(file, std::ios::binary);
            std::string header(1082, '\0');
            input.read(header.data(), header.size());
            need(bool(input), "prepared cache header required");
            validate_android_candidate_cache_image(header, std::filesystem::file_size(file));
        }

        const auto destination = stage / relative;
        ensure_private_directory(destination.parent_path());
        copy_portable_image(file, pin, destination, reserve);
        need(hash(destination) == pin && hash(file) == pin, "copied image differs");
        output[it.key()] = it.value();

        if (meter) {
            meter->advance(it.value().at("bytes").get<std::uint64_t>());
        }
    }

    return output;
}

std::uint64_t image_bytes(const Json &images) {
    std::uint64_t bytes = 0;

    for (const auto &image : images) {
        bytes += image.at("bytes").get<std::uint64_t>();
    }

    return bytes;
}

Json export_portable_boot_files(const std::filesystem::path &root, const Json &definition,
                                const std::filesystem::path &stage, std::uint64_t reserve,
                                const std::filesystem::path &verified_boot_parameters,
                                const std::string &verified_boot_sha256) {
    const auto source = root / ".local/profiles/common/android-base" /
                        definition.at("android").at("sha256").get<std::string>();
    Json files = Json::object();

    for (const auto &[name, expected] : portable_clean_boot_pins(definition.at("android"))) {
        (void)expected;
        const auto development = portable_development_kernel(definition);
        auto input = source / name;
        const auto target = stage / "android" / name;

        if (!development.is_null() && name == "kernel-ranchu") {
            input = portable_development_kernel_file(root, development);
        }

        const bool machine_parameters = !verified_boot_parameters.empty() &&
                                        name == "VerifiedBootParams.textproto";

        if (machine_parameters) {
            input = verified_boot_parameters;
        }

        const auto pin = hash(input, 64ULL << 20);

        if (machine_parameters) {
            need(pin == verified_boot_sha256, "candidate boot parameters changed");
        }

        if (!development.is_null() && name == "kernel-ranchu") {
            need(pin == development.at("sha256").get<std::string>(),
                 "development kernel input pin differs");
        }

        ensure_private_directory(target.parent_path());
        copy_portable_image(input, pin, target, reserve);
        need(hash(target, 64ULL << 20) == pin, "portable boot export differs");
        files[name] = {{"file", std::string("android/") + name},
                       {"sha256", pin},
                       {"bytes", std::filesystem::file_size(target)}};
    }

    return files;
}
} // namespace profile_build_detail

// Collect a closed candidate's private working tree before publication, after exported
// images have been copied to the pending stage. A partial removal is irreversible; retain
// any remainder for inspection and refuse further publication until it is addressed.
// Exported candidate images and receipts remain available for a later finalize retry.
void purge_android_candidate_working_disks(const std::filesystem::path &root,
                                           const std::filesystem::path &android,
                                           const std::filesystem::path &disk_tool) {
    const auto fail = [](const char *reason) {
        throw VoyemuError("PROFILE_BUILD", reason);
    };
    const auto absolute = [&](const std::filesystem::path &p) {
        if (!(p.is_absolute() && p.lexically_normal() == p)) {
            fail("absolute normalized input required");
        }

        for (const auto &at : os::ancestors(p)) {
            if (std::filesystem::is_symlink(std::filesystem::symlink_status(at))) {
                fail("linked path rejected");
            }
        }
    };

    absolute(root);
    absolute(android);
    {
        const auto relative = android.lexically_relative(root / ".local");

        if (relative.empty() || relative == "." || relative.is_absolute()) {
            fail("candidate inside project required");
        }

        for (const auto &part : relative) {
            if (part == "..") {
                fail("candidate leaves project");
            }
        }
    }
    const auto receipt_file = android / "receipt.json";

    if (!std::filesystem::is_regular_file(receipt_file)) {
        fail("candidate receipt required");
    }

    const auto candidate = read_private_json(receipt_file, 1 << 20);

    if (!(candidate.at("schema") == 1 && candidate.at("kind") == "android-candidate" &&
          candidate.at("stopped") == true && candidate.at("cold_boot_verified") == true)) {
        fail("closed stopped candidate required for working-disk GC");
    }

    for (const auto &entry : std::filesystem::directory_iterator(android)) {
        if (entry.path().filename().string().starts_with("machine.gc-pending-")) {
            fail("pending working-disk release requires inspection");
        }
    }

    const std::filesystem::path working = android / "machine";

    if (!std::filesystem::exists(working)) {
        return;
    }

    if (!std::filesystem::is_directory(working)) {
        fail("candidate working directory must be an ordinary directory");
    }

    // Ordinary, unaliased private files only; collect qcow2 overlays for backing-chain audit.
    std::vector<std::filesystem::path> overlays;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(working)) {
        const auto &file = entry.path();

        if (std::filesystem::is_symlink(std::filesystem::symlink_status(file))) {
            fail("working-disk tree must be ordinary");
        }

        if (entry.is_directory()) {
            continue;
        }

        if (!(entry.is_regular_file() && std::filesystem::hard_link_count(file) == 1)) {
            fail("unaliased closed working disk required");
        }

        if (file.extension() == ".qcow2") {
            overlays.push_back(file);
        }
    }

    // QCOW backing chains must never reference images outside the released tree; otherwise some
    // other (canonical or active) disk is aliased through backing and the purge refuses.
    if (!overlays.empty()) {
        if (!std::filesystem::is_regular_file(disk_tool) || !disk_tool.is_absolute()) {
            fail("native qemu-img required for backing audit");
        }

        for (const auto &overlay : overlays) {
            ProcessSpec command;
            command.executable = disk_tool;
            command.arguments = {"info", "--backing-chain", "--output=json", overlay.string()};
            command.directory = root;
            const auto result = execute(command, 60000, 1 << 20);

            if (result.timed_out || result.exit_code != 0) {
                fail((std::string("qcow2 overlay audit failed: exit=") +
                      std::to_string(result.exit_code) + " output=" + result.output.substr(0, 400))
                             .c_str());
            }

            const auto chain = Json::parse(result.output);

            if (!(chain.is_array() && chain.size() >= 1 && chain.size() <= 4)) {
                fail("bounded guest backing chain required");
            }

            for (const auto &image : chain) {
                if (!image.contains("filename")) {
                    fail("backing chain entry required");
                }

                const std::filesystem::path backing = image.at("filename").get<std::string>();
                absolute(backing);
                const auto inside = backing.lexically_relative(working);

                if (inside.empty() || inside == "." || inside.is_absolute()) {
                    fail("working-disk backing leaves the released tree");
                }

                for (const auto &part : inside) {
                    if (part == "..") {
                        fail("working-disk backing escapes the released tree");
                    }
                }
            }
        }
    }

    // Signed extent audit of every file is implicit in the release rename: total bytes recorded.
    std::uint64_t freed = 0;

    for (const auto &entry : std::filesystem::recursive_directory_iterator(working)) {
        if (entry.is_regular_file()) {
#ifdef __APPLE__
            struct ::stat info{};

            if (::lstat(entry.path().c_str(), &info) == 0) {
                freed += static_cast<std::uint64_t>(info.st_blocks) * 512;
            } else {
                freed += std::filesystem::file_size(entry.path());
            }
#else
            freed += std::filesystem::file_size(entry.path());
#endif
        }
    }

    // Rename separates the working tree from its original path; removal may be partial.
    const auto receipt_pin = sha256_file(receipt_file);
    const std::filesystem::path pending = android / ("machine.gc-pending-" + random_token());

    if (!os::rename_exclusive(working, pending)) {
        fail("atomic working-disk release failed");
    }

    // Record the pre-removal inventory; the pending stage has not been published yet.
    Json inventory = Json::array();

    for (const auto &entry : std::filesystem::recursive_directory_iterator(pending)) {
        if (entry.is_regular_file()) {
            const auto rel = entry.path().lexically_relative(pending).generic_string();

            if (rel.size() <= 128) {
                inventory.push_back(
                        {{"file", rel}, {"bytes", std::filesystem::file_size(entry.path())}});
            }
        }
    }

    std::error_code error;
    std::filesystem::remove_all(pending, error);
    const bool removed = !error && !std::filesystem::exists(pending);

    if (sha256_file(receipt_file) != receipt_pin) {
        fail("receipt damaged during working-disk release");
    }

    if (!removed) {
        write_private_json(
                android / "gc.json",
                {{"schema", 1},
                 {"kind", "android-candidate-working-disk-gc"},
                 {"removed_directory", "machine"},
                 {"pending_recovery", pending.filename().string()},
                 {"recovered", false},
                 {"freed_bytes", std::uint64_t(0)},
                 {"note",
                  "working-disk release kept in pending directory; deleted files are unrecoverable; inspect the remainder before removing it and retrying from exported candidate images"},
                 {"released_inventory", inventory}});
        fail("working-disk removal failed; recovery directory retained");
    }

    write_private_json(
            android / "gc.json",
            {{"schema", 1},
             {"kind", "android-candidate-working-disk-gc"},
             {"removed_directory", "machine"},
             {"preserved", Json::array({"receipt.json", "artifact-origin.json", "android/",
                                        "failure.json", "logs", "artwork"})},
             {"freed_bytes", freed},
             {"freed_bytes_basis",
              "physical_blocks: st_blocks*512; APFS clone/encoded extents may free fewer host bytes"},
             {"released_inventory", inventory}});
}

namespace profile_build_detail {
std::unique_ptr<os::FileLock> artifact_reader(const std::filesystem::path &root,
                                              const std::filesystem::path &receipt,
                                              const std::string &pin) {
    ordinary(receipt);
    inside(root / ".local", receipt);
    need(hash(receipt, 1 << 20) == pin, "artifact reader receipt changed");
    const std::filesystem::path work =
            read_private_json(receipt, 1 << 20).at("work").get<std::string>();
    ordinary(work);
    inside(root / ".local", work);
    auto lease = std::make_unique<os::FileLock>(work / build_output_lock, false);
    need(lease->held(), "artifact input is being released");
    need(hash(receipt, 1 << 20) == pin, "artifact reader receipt changed");

    return lease;
}

std::unique_ptr<os::FileLock> candidate_artifact_reader(const std::filesystem::path &root,
                                                        const std::filesystem::path &candidate) {
    const auto origin_file = candidate / "artifact-origin.json";

    if (!std::filesystem::exists(origin_file)) {
        return {};
    }

    const auto origin = read_private_json(origin_file, 8192);

    return artifact_reader(root, origin.at("artifact_receipt").get<std::string>(),
                           origin.at("artifact_receipt_sha256").get<std::string>());
}
} // namespace profile_build_detail

Json release_build_generation(const std::filesystem::path &root, Json publication,
                              const std::filesystem::path &android,
                              const std::filesystem::path &qnx_source,
                              const std::filesystem::path &qnx_accepted) {
    Json retained = Json::array();
    std::uint64_t released = 0;
    const auto retain = [&](const std::filesystem::path &path, const std::string &reason) {
        retained.push_back({{"path", path.string()}, {"reason", reason}});
    };

    try {
        const std::filesystem::path runtime = publication.at("runtime").get<std::string>();
        ordinary(runtime);
        inside(root / "machines", runtime);
        need(hash(runtime, 128 * 1024) == publication.at("runtime_sha256").get<std::string>(),
             "published runtime differs from the build result");
        ordinary(android);
        inside(root / ".local/build", android);
        write_private_json(android / "build-publication.json",
                           {{"candidate_receipt_sha256", hash(android / "receipt.json", 1 << 20)},
                            {"runtime", runtime.string()},
                            {"runtime_sha256", publication.at("runtime_sha256")}});
        std::map<std::filesystem::path, std::string> payloads;
        std::vector<std::pair<std::filesystem::path, bool>> owned{{android, false}};
        declared_payloads(read_private_json(android / "receipt.json", 1 << 20), android, payloads);
        const auto origin = read_private_json(android / "artifact-origin.json", 8192);
        const std::filesystem::path artifact_receipt =
                origin.at("artifact_receipt").get<std::string>();

        if (hash(artifact_receipt, 1 << 20) ==
            origin.at("artifact_receipt_sha256").get<std::string>()) {
            const auto artifacts = read_private_json(artifact_receipt, 1 << 20);
            const std::filesystem::path
                    work = artifacts.at("work").get<std::string>(),
                    result = std::filesystem::path(artifacts.at("transport").get<std::string>()) /
                             "result.json";

            if (hash(result, 16 << 20) == artifacts.at("result_sha256").get<std::string>()) {
                declared_payloads(read_private_json(result, 16 << 20), work, payloads);
                owned.emplace_back(work, true);
            } else {
                retain(work, "artifact result changed");
            }
        } else {
            retain(artifact_receipt, "artifact receipt changed");
        }

        for (const auto &[directory, receipt] :
             {std::pair{qnx_source, "build.json"}, std::pair{qnx_accepted, "acceptance.json"}}) {
            if (!directory.empty()) {
                declared_payloads(read_private_json(directory / receipt, 1 << 20), directory,
                                  payloads);
                owned.emplace_back(directory, false);
            }
        }

        for (const auto &[directory, scratch] : owned) {
            try {
                ordinary(directory);
                inside(root / ".local/build", directory);
                const os::FileLock lease(directory / build_output_lock, true);

                if (!lease.held()) {
                    retain(directory, "leased by another consumer");
                    continue;
                }

                if (scratch && candidate_uses_artifacts(root, android, directory)) {
                    retain(directory, "referenced by another candidate");
                    continue;
                }

                if (directory == android) {
                    purge_android_candidate_working_disks(
                            root, android,
                            root / ".local/toolchains/native-sdk/emulator" / ("qemu-img" + exe()));
                }

                released += release_generation_directory(directory, payloads, scratch, retained);
            } catch (const std::exception &error) {
                retain(directory, error.what());
            }
        }
    } catch (const std::exception &error) {
        retain(android, error.what());
    }

    for (const auto &item : retained) {
        logging::write(logging::Level::error, "build", "build output retained", item);
    }

    logging::write(logging::Level::info, "build", "build outputs released",
                   {{"released_bytes", released}, {"retained", retained.size()}});

    if (released) {
        progress::block();
        progress::report("build_released",
                         {{"size", progress::size_text(released, progress::language())}});
    }

    publication["build_outputs"] = {{"released_bytes", released}, {"retained", retained}};

    return publication;
}

Json profile_source_graphics_bindings(const std::filesystem::path &root, const Json &bindings,
                                      const std::filesystem::path &program) {
    if (program.empty()) {
        return bindings;
    }

    ordinary(program);
    inside(root, program);
    const auto current_pin = hash(program, 512ULL << 20);
    const std::filesystem::path previous = bindings.at("graphics").get<std::string>();
    ordinary(previous);
    inside(root, previous);
    const auto previous_pin = hash(previous, 512ULL << 20);
    auto result = bindings;
    unsigned selected = 0;

    for (auto &item : result.at("pins")) {
        const std::filesystem::path file = item.at("path").get<std::string>();

        if (file == previous) {
            need(program == previous || item.at("sha256") == previous_pin,
                 "configured graphics pin differs");
            item["path"] = program.string();
            item["sha256"] = current_pin;
            ++selected;
        } else {
            need(file != program, "current graphics pin conflicts with another binding");
        }
    }

    need(selected == 1, "exactly one configured graphics pin required");
    result["graphics"] = program.string();

    return result;
}

Json prepare_portable_base(const std::filesystem::path &root, std::string_view profile,
                           bool offline, std::uint64_t reserve, std::string_view selected) {
    root_profile(root, profile);
    const auto definition = authoring_profile(root, profile, selected),
               descriptor = definition.at("android");
    const auto pin = descriptor.at("sha256").get<std::string>();
    const auto base = root / ".local/profiles/common/android-base" / pin;

    if (!std::filesystem::exists(base)) {
        const auto archive =
                download_pinned({descriptor.at("url").get<std::string>(), pin, 3ULL << 30},
                                root / ".local/toolchains/downloads/native", offline, reserve)
                        .file;
        prepare_native_base_image(descriptor, archive, base);
    }

    ordinary(base);
    const auto receipt = read_private_json(base / "base.json", 512 * 1024);
    need(receipt.at("schema") == 1 && receipt.at("archive_sha256") == pin &&
                 receipt.at("prepared_VM") == false,
         "public AOSP boot provenance differs");

    for (const auto &[name, expected] : portable_clean_boot_pins(descriptor)) {
        need(hash(base / name, 64ULL << 20) == expected, "public AOSP boot file differs");
    }

    return {{"schema", 1},
            {"base", base.string()},
            {"archive_sha256", pin},
            {"boot_files_verified", true},
            {"owner_inputs_required", false},
            {"guest_started", false}};
}

namespace profile_build_detail {
Json validate_accepted_qnx_closure(const std::filesystem::path &root, std::string_view profile,
                                   const std::filesystem::path &file, const std::string &expected,
                                   const std::filesystem::path &payload_source, bool persistent) {
    root_profile(root, profile);
    const auto qnx_file = root / "profiles" / std::string(profile) / "profile-qnx.json";
    const auto qnx_definition = read_private_json(qnx_file, 128 * 1024);
    // A complete profile-qnx.json whose storage contract matches the requested closure.
    need(qnx_definition.value("status", std::string("ready")) != "incomplete" &&
                 qnx_definition.contains("persistence") == persistent,
         "QNX closure reuse requires a complete QNX profile with this storage contract");
    inside(root / ".local", file);
    need(hash(file, 1 << 20) == expected, "accepted QNX receipt pin differs");
    const auto accepted = read_private_json(file, 1 << 20);
    need(accepted.at("schema") == 1 && accepted.at("kind") == "accepted-qnx-portable-seed" &&
                 accepted.at("profile") == profile && accepted.at("source_built") == true &&
                 accepted.at("cold_boot_verified") == true && accepted.at("stopped") == true,
         "stopped genuine accepted QNX seed required");
    auto proof = [&](const char *key) {
        const auto &entry = accepted.at(key);
        const std::filesystem::path path = entry.at("file").get<std::string>();
        inside(root / ".local", path);
        need(hash(path, 16ULL << 20) == entry.at("sha256").get<std::string>(),
             "accepted QNX proof pin differs");

        return read_private_json(path, 16ULL << 20);
    };
    const auto source = proof("source_receipt"), evidence = proof("cold_boot_evidence");
    need(source.at("schema") == 1 && source.at("kind") == "raw-qnx-source-build" &&
                 source.at("profile") == profile && source.at("source_generated") == true &&
                 source.at("prepared_baseline_input") == false,
         "genuine original QNX source receipt required");
    need(evidence.at("source_receipt_sha256") == accepted.at("source_receipt").at("sha256") &&
                 evidence.at("cold_boot_verified") == true &&
                 evidence.at("actual_exported_frame") == true && evidence.at("guest_ack") == true,
         "actual accepted QNX cold proof required");
    const auto definition = authoring_profile(root, profile);
    need(definition.value("initial_state", Json::object()) ==
                 evidence.value("startup_profile_values", Json::object()),
         "QNX effective startup state changed");
    const auto layout = qnx_runtime_layout(profile, source);

    if (persistent) {
        need(!layout.persistence.is_null() &&
                     qnx_runtime_layout(profile, accepted).persistence == layout.persistence &&
                     qnx_definition.at("persistence") == layout.persistence,
             "persistent QNX closure contract differs");
    }

    need(qnx_definition.at("hardware_adapter") == layout.adapter &&
                 qnx_runtime_layout(profile, accepted).adapter == layout.adapter,
         "QNX adapter changed");
    need(source.at("guest_build").at("hardware_adapter") == layout.adapter &&
                 source.at("guest_build").at("mcu_projection") == layout.projection,
         "QNX guest variant changed");
    const auto &originals = qnx_definition.at("originals");
    need(source.at("originals").size() == layout.originals.size() &&
                 originals.size() == layout.originals.size(),
         "exact QNX OEM original roles required");

    for (const auto &name : layout.originals) {
        const auto pin = source.at("originals").at(name).at("sha256").get<std::string>();
        need(originals.at(name).at("file") == name && originals.at(name).at("sha256") == pin &&
                     hash(root / ".local/profiles" / std::string(profile) / "qnx" / name,
                          4ULL << 30) == pin,
             "QNX OEM original changed");
    }

    need(source.at("guest_build").at("modules_digest") == qnx_guest_modules_digest(layout.adapter),
         "QNX guest modules changed");
    need(accepted.at("source_bundle_sha256") == source.at("guest_build").at("bundle_sha256"),
         "QNX source bundle differs");
    const std::filesystem::path directory =
            payload_source.empty()
                    ? std::filesystem::path(accepted.at("directory").get<std::string>())
                    : payload_source;
    ordinary(directory);

    if (directory != root / "machines" / std::string(profile)) {
        inside(root / ".local", directory);
    }

    const auto roles = qnx_image_roles(layout);
    need(accepted.at("images").size() == roles.size(), "exact accepted QNX image roles required");

    for (const auto &name : roles) {
        const auto &image = accepted.at("images").at(name);
        const std::filesystem::path relative = image.at("file").get<std::string>();
        need(relative == std::filesystem::path("qnx") / name,
             "fixed accepted QNX image path required");
        const auto path = directory / relative;
        need(hash(path) == image.at("sha256").get<std::string>() &&
                     std::filesystem::file_size(path) == image.at("bytes").get<std::uint64_t>(),
             "accepted QNX image changed");
    }

    need(hash(file, 1 << 20) == expected, "accepted QNX receipt changed during validation");

    return {{"kind", "reused-unchanged-accepted-qnx-closure"},
            {"acceptance_sha256", expected},
            {"cold_boot_evidence_sha256", accepted.at("cold_boot_evidence").at("sha256")}};
}
} // namespace profile_build_detail

Json validate_accepted_qnx_reuse(const std::filesystem::path &root, std::string_view profile,
                                 const std::filesystem::path &file, const std::string &expected,
                                 const std::filesystem::path &payload_source) {
    return validate_accepted_qnx_closure(root, profile, file, expected, payload_source, false);
}

Json build_profile(const std::filesystem::path &root, std::string_view profile,
                   const MachineIdentity &machine, bool offline,
                   const std::filesystem::path &requested_jdk, std::function<bool()> cancelled,
                   bool cluster, bool multimedia, const std::filesystem::path &current_program,
                   const std::filesystem::path &reuse_qnx, const std::string &reuse_qnx_pin,
                   const std::filesystem::path &reuse_qnx_source, std::string_view selected) {
    need(reuse_qnx_source.empty() || !reuse_qnx.empty(),
         "QNX payload source requires pinned accepted receipt");
    need(reuse_qnx.empty() == reuse_qnx_pin.empty(), "paired QNX reuse receipt and pin required");
    root_profile(root, profile);

    const auto definition = authoring_profile(root, profile, selected);
    const auto jdk = profile_preparation_jdk(
            root, requested_jdk, embedded_toolchain_manifest().at("javaHelper"), !selected.empty());

    if (std::filesystem::exists(build_target(root, profile, machine)) &&
        profile_feature(definition, "system_upgrade") && !cluster) {
        need(multimedia, "system upgrade requires Android subsystem");
        const auto candidate = build_profile_android(root, profile, machine, offline, jdk,
                                                     std::move(cancelled), {}, {}, selected);
        const std::filesystem::path android = candidate.at("candidate").get<std::string>();

        return release_build_generation(
                root,
                upgrade_profile_android_system(
                        root, profile, machine, android,
                        candidate.at("candidate_receipt_sha256").get<std::string>()),
                android);
    }

    if (!reuse_qnx.empty()) {
        need(cluster && multimedia, "QNX reuse requires combined build");
        // Another build's generation stays leased while this build reads it.
        std::vector<std::unique_ptr<os::FileLock>> leases;

        for (const auto &directory : {reuse_qnx.parent_path(), reuse_qnx_source}) {
            const auto relative = directory.lexically_relative(root / ".local/build");

            if (!directory.empty() && !relative.empty() && *relative.begin() != ".." &&
                std::filesystem::is_directory(directory)) {
                leases.push_back(
                        std::make_unique<os::FileLock>(directory / build_output_lock, false));
                need(leases.back()->held(), "QNX reuse input is being released");
            }
        }

        validate_accepted_qnx_reuse(root, profile, reuse_qnx, reuse_qnx_pin, reuse_qnx_source);
        const auto android = build_profile_android(root, profile, machine, offline, jdk,
                                                   std::move(cancelled), {}, {}, selected);
        const std::filesystem::path candidate = android.at("candidate").get<std::string>();

        return release_build_generation(root,
                                        finalize_profile_build(root, profile, machine, candidate,
                                                               reuse_qnx, reuse_qnx_pin, true,
                                                               reuse_qnx_source, jdk),
                                        candidate);
    }

    need(cluster || multimedia, "at least one subsystem must be selected");
    need(multimedia, "cluster-only source publication is not implemented");

    if (!cluster) {
        const auto android = build_profile_android(root, profile, machine, offline, jdk,
                                                   std::move(cancelled), {}, {}, selected);

        const std::filesystem::path candidate = android.at("candidate").get<std::string>();

        return release_build_generation(
                root,
                finalize_android_profile_build(
                        root, profile, machine, candidate,
                        android.at("candidate_receipt_sha256").get<std::string>(), jdk),
                candidate);
    }

    root_profile(root, profile);
    const auto target = build_target(root, profile, machine);

    if ((std::filesystem::exists(target) &&
         !qinggan11_package_delivery(authoring_profile(root, profile))) ||
        std::filesystem::is_symlink(target)) {
        throw cli::LocalizedError("PROFILE_BUILD", "error.machine_exists",
                                  {{"machine", progress::path_text(target)}});
    }

    progress::Phase checking("build_check");
    // Check the configured local host before spending time preparing or booting Android.
    const auto binding_file = qnx_host_bindings_path(root);
    const auto bindings = profile_source_graphics_bindings(
            root, ensure_qnx_host_bindings(root, offline), current_program);
    hash(binding_file, 128 * 1024);
    need(bindings.at("schema") == 1, "portable host binding schema required");
    const std::filesystem::path qemu = bindings.at("qnx_qemu").get<std::string>(),
                                graphics = bindings.at("graphics").get<std::string>(),
                                angle = bindings.at("angle").get<std::string>();
    inside(root, graphics);
    inside(root, angle);
    std::map<std::string, std::string> pins;

    for (const auto &item : bindings.at("pins")) {
        const std::filesystem::path file = item.at("path").get<std::string>();

        if (file != qemu) {
            inside(root, file);
        }

        const auto pin = hash(file, 512ULL << 20);
        need(item.at("sha256") == pin && pins.emplace(file.string(), pin).second,
             "local QNX host pin mismatch");
    }

    need(pins.contains(qemu.string()) && pins.contains(graphics.string()),
         "local QNX executable pins missing");
    install_native_dependencies(root, offline);
    materialize_qnx_originals(root, profile, jdk, offline);
    checking.done();
    const auto authoring_unchanged = capture_authoring_inputs(root, profile);
    const auto token = random_token(), name = std::string(profile);
    const auto qnx_source = root / ".local/build" / ("qnx-source-" + name + "-" + token);
    progress::Phase building("build_qnx_images");
    const auto source = prepare_qnx_images(root, profile, qnx_source, offline);
    building.done();
    authoring_unchanged();

    if (cancelled && cancelled()) {
        throw VoyemuError("PROFILE_BUILD", "cancelled after QNX source build");
    }

    const auto temporary = root / ".local/build/tmp";
    ensure_private_directory(temporary);
#ifdef _WIN32
    for (const auto *name : {L"TMPDIR", L"TMP", L"TEMP"}) {
        need(SetEnvironmentVariableW(name, temporary.c_str()) != 0,
             "project temporary directory setup failed");
    }
#else
    need(::setenv("TMPDIR", temporary.c_str(), 1) == 0, "project temporary directory setup failed");
#endif
    Json images = Json::object(), libraries = Json::object();

    for (auto it = source.at("images").begin(); it != source.at("images").end(); ++it) {
        images[it.key()] = {{"file", (qnx_source / it.key()).string()},
                            {"sha256", it.value().at("sha256")}};
    }

    for (const auto *name : {"libEGL", "libGLESv2"}) {
        const auto library = name + std::string(os::shared_library_suffix);
        const auto file = angle / library;
        need(pins.contains(file.string()), "local ANGLE pin missing");
        libraries[library] = pins.at(file.string());
    }

    const auto request_file = temporary / ("qnx-source-acceptance-" + token + ".json"),
               accepted = root / ".local/build" / ("qnx-accepted-" + name + "-" + token);
    write_private_json(
            request_file,
            {{"schema", 1},
             {"profile", name},
             {"source_receipt",
              {{"file", (qnx_source / "build.json").string()},
               {"sha256", hash(qnx_source / "build.json", 1 << 20)}}},
             {"images", images},
             {"tools",
              {{"qemu", {{"file", qemu.string()}, {"sha256", pins.at(qemu.string())}}},
               {"graphics", {{"file", graphics.string()}, {"sha256", pins.at(graphics.string())}}},
               {"angle", angle.string()},
               {"libraries", libraries}}}});

    if (bindings.contains("qnx_file_backend")) {
        auto request = read_private_json(request_file, 128 * 1024);
        request["tools"]["qemu"]["qnx_file_backend"] = bindings.at("qnx_file_backend");
        write_private_json(request_file, request);
    }

    if (!current_program.empty()) {
        auto request = read_private_json(request_file, 128 * 1024);
        request["tools"]["graphics"]["backend"] = "voyemu";
        write_private_json(request_file, request);
    }

    accept_qnx_images(root, name, request_file, accepted, cancelled);
    authoring_unchanged();

    if (cancelled && cancelled()) {
        throw VoyemuError("PROFILE_BUILD", "cancelled after QNX acceptance");
    }

    const auto android = build_profile_android(root, profile, machine, offline, jdk,
                                               std::move(cancelled), {}, {}, selected);
    authoring_unchanged();
    const std::filesystem::path candidate = android.at("candidate").get<std::string>();

    return release_build_generation(
            root,
            finalize_profile_build(root, profile, machine, candidate, accepted / "acceptance.json",
                                   hash(accepted / "acceptance.json", 1 << 20), false, {}, jdk),
            candidate, qnx_source, accepted);
}

Json build_profile_android(const std::filesystem::path &root, std::string_view profile,
                           const MachineIdentity &machine, bool offline,
                           const std::filesystem::path &jdk, std::function<bool()> cancelled,
                           const std::filesystem::path &artifact_receipt,
                           const std::string &artifact_receipt_pin, std::string_view selected) {
    root_profile(root, profile);
    const auto definition = authoring_profile(root, profile, selected);
    const auto target = build_target(root, profile, machine);

    if (std::filesystem::is_symlink(target) ||
        (std::filesystem::exists(target) && !profile_feature(definition, "system_upgrade"))) {
        throw cli::LocalizedError("PROFILE_BUILD", "error.machine_exists",
                                  {{"machine", progress::path_text(target)}});
    }

    if (std::filesystem::exists(target)) {
        (void)inspect_portable_runtime(root, profile, machine);
    }

    progress::Phase phase("build_android");
    (void)prepare_profile_ui_observer(root, jdk);
    auto artifact_lease = artifact_receipt.empty()
                                  ? std::unique_ptr<os::FileLock>()
                                  : artifact_reader(root, artifact_receipt, artifact_receipt_pin);
    const auto artifacts = [&] {
        if (artifact_receipt.empty()) {
            need(artifact_receipt_pin.empty(), "artifact receipt pin requires receipt");

            return prepare_profile_artifacts(root, profile, offline, jdk, selected);
        }

        const auto receipt = validate_profile_artifact_resume(root, profile, artifact_receipt,
                                                              artifact_receipt_pin, selected);
        ProfilePreparationArtifacts prepared;
        prepared.receipt = receipt;
        prepared.base = receipt.at("base").get<std::string>();
        prepared.sdk = receipt.at("sdk").get<std::string>();
        prepared.work = receipt.at("work").get<std::string>();
        prepared.transport = receipt.at("transport").get<std::string>();

        for (const auto &directory :
             {prepared.base, prepared.sdk, prepared.work, prepared.transport}) {
            ordinary(directory);
            inside(root / ".local", directory);
        }

        need(prepared.transport == artifact_receipt.parent_path() &&
                     hash(prepared.base / "base.json", 512 * 1024) ==
                             receipt.at("base_receipt_sha256").get<std::string>() &&
                     hash(prepared.transport / "result.json", 4ULL << 20) ==
                             receipt.at("result_sha256").get<std::string>(),
             "prepared base/result receipt changed");
        prepared.result = read_private_json(prepared.transport / "result.json", 4ULL << 20);

        return prepared;
    }();

    if (!artifact_lease) {
        artifact_lease =
                artifact_reader(root, artifacts.transport / "profile-artifacts.json",
                                hash(artifacts.transport / "profile-artifacts.json", 1 << 20));
    }

    // The x86_64 guest of an Android base with a Native Bridge runs the ARM code of the profile.
    const auto bridge_descriptor = native_bridge_descriptor(root, definition);
    const auto bridge =
            bridge_descriptor.is_null()
                    ? NativeBridge{}
                    : prepare_native_bridge(root, bridge_descriptor,
                                            root / ".local/toolchains/downloads/native", offline,
                                            android_candidate_reserve_bytes(definition, profile));
    phase.done();
    AndroidCandidateRequest request;
    request.profile = profile;
    request.target = selected;
    request.profile_sha256 = sha256_bytes(authoring_profile_bytes(root, profile, selected));
    request.artifact_result = artifacts.transport / "result.json";
    request.artifact_result_sha256 = hash(request.artifact_result, 16 << 20);
    request.clean_base = artifacts.base;
    request.clean_receipt_sha256 = hash(artifacts.base / "base.json", 128 * 1024);
    request.sdk = artifacts.sdk;
    request.cancelled = std::move(cancelled);
    request.port = 0;

    request.tool_pins = host_pins(artifacts.sdk, definition);

    if (!bridge_descriptor.is_null()) {
        request.native_bridge = bridge.directory;
        request.native_bridge_descriptor = bridge_descriptor;
    }

    // A profile may pin the port of its source candidate in emulator.candidatePort.
    if (const auto fixed = definition.value("emulator", Json::object()).value("candidatePort", 0U);
        fixed != 0) {
        const auto port = fixed;

        if (tcp_port_free(port) && tcp_port_free(port + 1) && tcp_port_free(port + 20000) &&
            tcp_port_free(port + 30000)) {
            request.port = port;
        }
    } else {
        for (unsigned port = 5580; port <= 5682; port += 2) {
            if (tcp_port_free(port) && tcp_port_free(port + 1) && tcp_port_free(port + 30000)) {
                request.port = port;
                break;
            }
        }
    }

    need(request.port != 0, "no free owned SDK port triple available");

    if (native_base_api(definition.at("android")) == 30) {
        request.overall_timeout_ms = 600000;
        request.capture_frames = true;
    }

    // The donated files, their checks and the boot image of the second x86 instruction set take
    // their own time.
    if (!request.native_bridge.empty()) {
        request.overall_timeout_ms += 300000;
    }

    if (record_declares(definition, ProfilePlatform::qinggan09, ProfileBoard::nxp)) {
        request.capture_frames = true;
    }

#ifdef _WIN32
    need(!passion_mcu_requested(definition),
         "PASSION_MCU: Windows partial projection is unsupported");
#endif
    const auto candidate = root / ".local/build" /
                           ("candidate-" + std::string(profile) + "-" + random_token());
    auto receipt = [&] {
        const auto family = runtime_profile_reference(definition, profile);

        // A bundled profile builds its measured candidate; a local copy builds the generic one.
        const auto bundled = embedded_profile_names();

        if (std::ranges::find(bundled, family) == bundled.end()) {
            return build_android_candidate(root, request, candidate);
        }

        const auto clean = read_private_json(request.clean_base / "base.json", 512 * 1024),
                   produced = read_private_json(request.artifact_result, 16 << 20).at("artifacts");
        std::uint64_t base_bytes = 0, payload_bytes = 0;

        for (const auto &file : clean.at("files")) {
            const auto bytes = file.at("bytes").get<std::uint64_t>();
            need(bytes <= 4ULL << 30 && base_bytes <= (4ULL << 30) - bytes,
                 "bounded measured clean base extent required");
            base_bytes += bytes;
        }

        const auto plan = android_candidate_install_plan(definition, produced);
        const auto add_payload = [&](const std::filesystem::path &file) {
            const auto bytes = std::filesystem::file_size(file);
            need(bytes <= 2ULL << 30 && payload_bytes <= (2ULL << 30) - bytes,
                 "bounded measured system payload required");
            payload_bytes += bytes;
        };

        for (const auto &item : plan.at("system")) {
            if (item.at("type") == "directory") {
                continue;
            }

            const auto &artifact = produced.at(item.at("artifact").get<std::string>());

            if (artifact.contains("file")) {
                add_payload(artifact.at("file").get<std::string>());
            } else {
                for (auto file = artifact.at("files").begin(); file != artifact.at("files").end();
                     ++file) {
                    add_payload(std::filesystem::path(artifact.at("directory").get<std::string>()) /
                                file.key());
                }
            }
        }

        if (!request.native_bridge.empty()) {
            for (const auto &[path, pin] : request.native_bridge_descriptor.at("files").items()) {
                (void)pin;
                add_payload(request.native_bridge / path.substr(1));
            }
        }

        const auto budget = android_candidate_build_budget(definition, base_bytes, payload_bytes,
                                                           profile);

        return build_android_candidate(root, request, candidate, budget.reserve_bytes,
                                       budget.peak_extra_bytes);
    }();

    if (passion_power_requested(definition)) {
        need(hash(request.artifact_result, 16 << 20) == request.artifact_result_sha256 &&
                     sha256_bytes(authoring_profile_bytes(root, profile, selected)) ==
                             request.profile_sha256,
             "power artifact/profile epoch changed after cold verification");
        receipt["display_power"] = build_passion_power_proof(
                root, definition,
                read_private_json(request.artifact_result, 16 << 20).at("artifacts"), receipt);
        write_private_json(candidate / "receipt.json", receipt, 1 << 20);
    }

    if (passion_mcu_requested(definition)) {
        need(hash(request.artifact_result, 16 << 20) == request.artifact_result_sha256 &&
                     sha256_bytes(authoring_profile_bytes(root, profile, selected)) ==
                             request.profile_sha256,
             "MCU artifact/profile epoch changed after cold verification");
        receipt["mcu_property"] = build_passion_mcu_proof(
                root, definition,
                read_private_json(request.artifact_result, 16 << 20).at("artifacts"), receipt);
        write_private_json(candidate / "receipt.json", receipt, 1 << 20);
    }

    const auto origin_file = artifacts.transport / "profile-artifacts.json";
    const auto origin_pin = hash(origin_file, 1 << 20);
    write_private_json(candidate / "artifact-origin.json",
                       {{"schema", 1},
                        {"kind", "android-artifact-origin"},
                        {"profile", profile},
                        {"candidate_receipt_sha256", hash(candidate / "receipt.json", 1 << 20)},
                        {"artifact_receipt", origin_file.string()},
                        {"artifact_receipt_sha256", origin_pin}});

    return {{"schema", 1},
            {"profile", profile},
            {"android_ready", true},
            {"profile_ready", false},
            {"machine_ready", false},
            {"candidate", candidate.string()},
            {"candidate_receipt_sha256", hash(candidate / "receipt.json", 1 << 20)},
            {"cold_boot_verified", receipt.at("cold_boot_verified")},
            {"stopped", receipt.at("stopped")},
            {"missing", Json::array({"accepted source-built QNX portable seed"})},
            {"old_machine_modified", false}};
}
} // namespace voyemu
