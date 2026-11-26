#include "java_toolchain.hpp"
#include "check.hpp"
#include "disk_space.hpp"
#include "e2fs_helper.hpp"
#include "error.hpp"
#include "interruption.hpp"
#include "java_runtime.hpp"
#include "java_toolchain_identity.hpp"
#include "ordinary_path.hpp"
#include "os/fs.hpp"
#include "os/platform.hpp"
#include "owner_lock.hpp"
#include "process.hpp"
#include "project_files.hpp"
#include "quickboot.hpp"
#include "toolchain_manifest.hpp"
#include "zip_archive.hpp"
#include <chrono>
#include <fstream>
#include <limits>
#include <regex>
#include <set>
#include <thread>
namespace voyemu {
namespace {
constexpr Check need{"JAVA_TOOLCHAIN"};

void ordinary(const std::filesystem::path &p) {
    ordinary_path(p, need, PathForm::Normalized, "normalized absolute path required",
                  "linked input rejected");
}

void relative(const std::string &name) {
    std::filesystem::path p(name);

    need(!name.empty() && name.size() <= 512 && !p.is_absolute() &&
                 name.find('\\') == std::string::npos && name.find(':') == std::string::npos,
         "confined relative path required");

    for (const auto &c : p) {
        need(c != "." && c != ".." && !c.empty(), "relative traversal");
    }
}

std::string bytes(const std::filesystem::path &p, std::uint64_t maximum) {
    ordinary(p);
    need(std::filesystem::is_regular_file(p) && std::filesystem::file_size(p) <= maximum,
         "bounded ordinary file required");
    std::ifstream in(p, std::ios::binary);
    need(bool(in), "input open");
    std::string result((std::istreambuf_iterator<char>(in)), {});
    need(!in.bad() && result.size() <= maximum, "input read");

    return result;
}

std::string hash(const std::filesystem::path &p, std::uint64_t maximum = 256ULL << 20) {
    ordinary(p);
    need(std::filesystem::is_regular_file(p) && std::filesystem::file_size(p) <= maximum,
         "bounded file required");
    const auto epoch = cache_file_identity(p);
    auto result = sha256_file(p);
    need(cache_file_identity(p) == epoch, "file changed during hashing");

    return result;
}

// Shared SDK/library inputs are immutable by exact SHA pin, not exclusive mutable cache files.
Json input_identity(const std::filesystem::path &path) {
    ordinary(path);

    return immutable_input_identity(path);
}

void write(const std::filesystem::path &p, const std::string &data) {
    need(!std::filesystem::exists(p) && data.size() <= 1ULL << 20,
         "fresh bounded build file required");
    std::ofstream out(p, std::ios::binary);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    need(bool(out), "build file write failed");
}

// Waits while another process builds the same helper; the OS releases the lock of a process that
// exits or is killed.
class HelperLock {
public:
    explicit HelperLock(const std::filesystem::path &path) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);

        for (lock_ = owner_lock(path); !lock_->held(); lock_ = owner_lock(path)) {
            interruption::check();
            need(std::chrono::steady_clock::now() < deadline, "helper build lock unavailable");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

private:
    std::unique_ptr<os::FileLock> lock_;
};

std::map<std::string, std::string> environment(const std::filesystem::path &temporary) {
    return {{"JAVA_TOOL_OPTIONS", ""},      {"JDK_JAVA_OPTIONS", ""},
            {"_JAVA_OPTIONS", ""},          {"CLASSPATH", ""},
            {"TMPDIR", temporary.string()}, {"TMP", temporary.string()},
            {"TEMP", temporary.string()}};
}

using os::executable_suffix;

struct Jdk {
    std::filesystem::path home, java, javac;
    std::string java_sha256, javac_sha256, release_sha256, version;
};

Jdk installed_jdk(const std::filesystem::path &root, const std::filesystem::path &requested) {
    need(requested.is_absolute(), "configured JDK must be absolute");
    const auto configured = std::filesystem::canonical(requested);
    const auto java = configured / "bin" / ("java" + std::string(executable_suffix));

    ordinary(java);
    need(std::filesystem::is_regular_file(java), "configured Java executable missing");
    ensure_private_directory(root / ".local/build/tmp");
    ProcessSpec spec;
    spec.executable = java;
    spec.arguments = {"-XshowSettings:properties", "-version"};
    spec.directory = root;
    spec.environment = environment(root / ".local/build/tmp");
    const auto result = execute(spec, 10000, 64 * 1024);
    std::smatch home, version;
    need(!result.timed_out && result.exit_code == 0 &&
                 std::regex_search(result.output, home,
                                   std::regex(R"(java\.home\s*=\s*([^\r\n]+))")) &&
                 std::regex_search(result.output, version,
                                   std::regex(R"(java\.version\s*=\s*([0-9]+[^\s\r\n]*))")),
         "JDK version/home probe failed");
    std::string home_text = home[1].str();

    while (!home_text.empty() && (home_text.back() == ' ' || home_text.back() == '\t')) {
        home_text.pop_back();
    }

    auto actual = std::filesystem::canonical(std::filesystem::path(home_text));
    ordinary(actual);
    need(actual == configured, "configured JDK differs from java.home");
    const auto feature = std::stoul(version[1].str());
    need(feature >= 25, "JDK25 or newer required");
    Jdk selected;
    selected.home = actual;
    selected.java = actual / "bin" / ("java" + std::string(executable_suffix));
    selected.javac = actual / "bin" / ("javac" + std::string(executable_suffix));
    selected.java_sha256 = java_toolchain_input_sha256(selected.java);
    selected.javac_sha256 = java_toolchain_input_sha256(selected.javac);
    selected.release_sha256 = java_toolchain_input_sha256(actual / "release", 1 << 20);
    selected.version = version[1].str();

    return selected;
}

Jdk refreshed(const Jdk &jdk) {
    auto result = jdk;

    result.java_sha256 = java_toolchain_input_sha256(jdk.java);
    result.javac_sha256 = java_toolchain_input_sha256(jdk.javac);
    result.release_sha256 = java_toolchain_input_sha256(jdk.home / "release", 1 << 20);

    return result;
}

// Freeze exactly the sources passed to javac. An edit during capture is rejected;
// edits after capture affect the next helper cut, not this build.
void capture_helper_sources(const std::filesystem::path &root,
                            const std::filesystem::path &snapshot, const Json &inputs) {
    const auto &sources = inputs.at("sources");

    need(sources.is_object() && sources.size() <= 256, "bounded source snapshot required");

    for (auto at = sources.begin(); at != sources.end(); ++at) {
        const auto name = at.key();
        relative(name);
        need(name.starts_with("src/prepare/java/") ||
                     name == "src/prepare/test/fixtures/com/voyemu/prepare/fixture/BuildMarker.java",
             "unexpected captured source");
        const auto input = root / name, output = snapshot / name;
        ordinary(input);
        const auto before = cache_file_identity(input);
        const auto content = bytes(input, 1 << 20);
        need(sha256_bytes(content) == at.value().get<std::string>() &&
                     cache_file_identity(input) == before,
             "Java source changed during capture");
        ensure_private_directory(output.parent_path());
        write(output, content);
        need(hash(output, 1 << 20) == at.value().get<std::string>(),
             "captured Java source differs");
    }
}

std::map<std::string, std::string> library_pins(const std::filesystem::path &root);

void verify_helper_tool_inputs(const std::filesystem::path &root, const Json &inputs) {
    need(Json(library_pins(root)) == inputs.at("dependencies"),
         "helper tool pins changed during preparation");

    const auto resources = inputs.value("resource_snapshot", Json::object());

    for (auto at = resources.begin(); at != resources.end(); ++at) {
        const auto name = at.key();
        need(name.starts_with("voyemu/"), "helper resource path");
        relative(name);
        need(project_file_sha256(root, name.substr(7), 1 << 20) == at.value().get<std::string>(),
             "helper guest resource changed during preparation");
    }
}

std::map<std::string, std::string> library_pins(const std::filesystem::path &root) {
    std::map<std::string, std::string> result;
    const auto specs = project_file_json(root, "src/prepare/libraries.json", 256 * 1024);

    need(specs.is_array() && specs.size() <= 64, "bounded library specification");

    for (const auto &spec : specs) {
        const auto filename = spec.at("filename").get<std::string>();
        relative(filename);
        need(filename.ends_with(".jar") &&
                     result.emplace("lib/" + filename, spec.at("sha256").get<std::string>()).second,
             "unique library file required");
    }

    const auto tools = project_file_json(root, "src/prepare/toolchain.json", 256 * 1024);

    for (const auto &name : {"d8", "apksigner"}) {
        need(result.emplace(std::string("lib/") + name + ".jar",
                            tools.at("libraries").at(name).at("sha256").get<std::string>())
                     .second,
             "unique SDK library");
    }

    for (const auto &[file, p] : result) {
        (void)file;
        need(sha256_text(p), "library SHA256 required");
    }

    return result;
}

Json verify_helper(const std::filesystem::path &root, const std::filesystem::path &folder) {
    ordinary(folder);
    const auto receipt = read_private_json(folder / "build-receipt.json", 256 * 1024);
    need(receipt.value("schema", 0) == 1 &&
                 receipt.value("kind", std::string{}) == "java-preparation-helper" &&
                 receipt.value("java_release", 0) == 25 &&
                 receipt.at("jar") == "voyemu-java-helper.jar",
         "helper build receipt identity differs");
    const auto jar = folder / "voyemu-java-helper.jar";
    const auto jar_pin = receipt.at("sha256").get<std::string>();
    need(sha256_text(jar_pin) && hash(jar, 128ULL << 20) == jar_pin &&
                 receipt.at("bytes") == std::filesystem::file_size(jar),
         "helper JAR differs from receipt");
    const auto expected = library_pins(root);
    std::set<std::string> actual;
    need(receipt.at("dependencies").is_array() &&
                 receipt.at("dependencies").size() == expected.size(),
         "helper library coverage");

    for (const auto &d : receipt.at("dependencies")) {
        const auto file = d.at("file").get<std::string>();
        relative(file);
        need(actual.insert(file).second && expected.contains(file) &&
                     d.at("sha256") == expected.at(file) &&
                     java_toolchain_input_sha256(folder / file) == expected.at(file) &&
                     d.at("bytes") == std::filesystem::file_size(folder / file),
             "helper library differs from pin");
    }

    bool entry = false;

    for (const auto &e : pinned_zip_inventory(jar, jar_pin)) {
        if (!e.directory && e.name == "com/voyemu/prepare/PreparationMain.class") {
            entry = true;
        }
    }

    need(entry, "PreparationMain class missing");

    return receipt;
}

// Puts one JAR of the pinned Android SDK archive product into the Java SDK of the project unless it
// is there; a catalog label with its version names the archive on the console instead.
void install_sdk_jar(const std::filesystem::path &root, const Json &archive,
                     const std::string &product, const std::string &label,
                     const std::string &version, const std::string &entry, bool exact_name,
                     const std::filesystem::path &target, const std::string &sha256, bool offline,
                     std::uint64_t reserve, const DownloadTransport &transport) {
    if (std::filesystem::exists(std::filesystem::symlink_status(target))) {
        need(java_toolchain_input_sha256(target) == sha256, "existing Java SDK JAR differs");

        return;
    }

    const auto archive_sha = archive.at("sha256").get<std::string>();
    const auto file = download_pinned({archive.at("url").get<std::string>(), archive_sha,
                                       3ULL << 30, DownloadEncoding::raw, product, label, version},
                                      root / ".local/toolchains/downloads/native", offline, reserve,
                                      transport)
                              .file;
    std::string selected;
    std::uint64_t bytes = 0;

    for (const auto &e : pinned_zip_inventory(file, archive_sha, ZipNamePolicy::exact)) {
        if (!e.directory && (exact_name ? e.name == entry : e.name.ends_with("/" + entry))) {
            need(selected.empty(), "ambiguous Java SDK JAR entry");
            selected = e.name;
            bytes = e.bytes;
        }
    }

    need(!selected.empty() && bytes <= 128ULL << 20, "Java SDK JAR entry missing");
    ensure_private_directory(target.parent_path());
    const auto part = target.parent_path() /
                      ("." + target.filename().string() + ".part-" + random_token());

    try {
        extract_pinned_zip_tree(file, archive_sha, {{selected, part, bytes}}, reserve,
                                ZipNamePolicy::exact);
        need(sha256_file(part) == sha256, "extracted Java SDK JAR differs from its pin");
        std::filesystem::rename(part, target);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(part, ignored);
        throw;
    }
}

// d8.jar and apksigner.jar of the pinned build tools and android.jar of the pinned platform in
// .local/toolchains/java-sdk, extracted from the archives that deps downloads for the native SDK.
void install_java_sdk(const std::filesystem::path &root, bool offline, std::uint64_t reserve,
                      const DownloadTransport &transport) {
    const auto manifest = project_file_json(root, "src/app/toolchain.json", 256 * 1024),
               tools = project_file_json(root, "src/prepare/toolchain.json", 256 * 1024);
    const auto &sdk = manifest.at("sdk");

    need(sdk.at("compileSdk") == 34 && sdk.at("buildTools") == "36.1.0",
         "registered Java SDK34 required");
    const std::string host = e2fs_helper_host();
    const auto &archives = sdk.at("archives").at(host.substr(0, host.find('-')));
    const auto java_sdk = root / ".local/toolchains/java-sdk";

    for (const auto &name : {"d8", "apksigner"}) {
        install_sdk_jar(root, archives.at("buildTools"), "Android SDK Build-Tools 36.1.0", {}, {},
                        std::string("lib/") + name + ".jar", false,
                        java_sdk / "build-tools/36.1.0/lib" / (std::string(name) + ".jar"),
                        tools.at("libraries").at(name).at("sha256").get<std::string>(), offline,
                        reserve, transport);
    }

    const auto platform = java_sdk / "platforms/android-34/android.jar";
    install_sdk_jar(root, archives.at("platform"), "Android SDK Platform 34", "java_platform", "34",
                    "android-34/android.jar", true, platform,
                    sdk.at("platformJar").at("sha256").get<std::string>(), offline, reserve,
                    transport);
    need(sdk.at("platformJar").at("bytes") == std::filesystem::file_size(platform),
         "platform JAR extent differs");
}

// Extracts the java-helper asset into the fresh folder output and adds the SDK JARs of the
// project, which the asset leaves out.
void extract_java_helper(const std::filesystem::path &root, const std::filesystem::path &asset,
                         const std::string &sha256, const std::filesystem::path &output,
                         std::uint64_t reserve) {
    const auto expected = library_pins(root);
    std::vector<ZipTreeEntry> members;

    for (const auto &e : pinned_zip_inventory(asset, sha256)) {
        need(!e.directory &&
                     (e.name == "voyemu-java-helper.jar" || e.name == "build-receipt.json" ||
                      (expected.contains(e.name) && e.name != "lib/d8.jar" &&
                       e.name != "lib/apksigner.jar")) &&
                     members.size() < expected.size(),
             "unexpected java-helper asset entry");
        members.push_back({e.name, output / e.name, e.bytes});
    }

    ensure_private_directory(output / "lib");
    extract_pinned_zip_tree(asset, sha256, members, reserve);

    for (const auto &name : {"d8", "apksigner"}) {
        const auto file = std::string("lib/") + name + ".jar";
        const auto source = root / ".local/toolchains/java-sdk/build-tools/36.1.0" / file;
        need(java_toolchain_input_sha256(source) == expected.at(file), "Java SDK JAR differs");
        std::filesystem::copy_file(source, output / file);
    }
}
} // namespace

std::string java_toolchain_input_sha256(const std::filesystem::path &p, std::uint64_t maximum,
                                        const std::function<void()> &before_verify) {
    ordinary(p);
    need(std::filesystem::is_regular_file(p) && std::filesystem::file_size(p) <= maximum,
         "bounded file required");
    const auto epoch = input_identity(p);
    auto result = sha256_file(p);

    if (before_verify) {
        before_verify();
    }

    ordinary(p);
    need(input_identity(p) == epoch, "file changed during hashing");

    return result;
}

Json java_helper_source_inputs(const std::filesystem::path &root, bool from_sources) {
    // An installation has no sources; the javaHelper pin of the launcher identifies its helper.
    if (!from_sources || !project_source_checkout(root)) {
        return {{"schema", 1},
                {"asset_sha256", embedded_toolchain_manifest().at("javaHelper").at("sha256")},
                {"dependencies", library_pins(root)}};
    }

    const auto builder = java_helper_builder_source(
            project_file_bytes(root, "src/prepare/JavaHelperBuild.java", 256 * 1024));
    Json sources = Json::object();

    for (const auto &e : std::filesystem::recursive_directory_iterator(root / "src/prepare/java")) {
        need(!e.is_symlink() && (e.is_directory() || e.is_regular_file()),
             "ordinary Java source tree required");
    }

    for (const auto &file : project_directory_files(root, "src/prepare/java", true)) {
        need(file.name.ends_with(".java") && sources.size() < 256, "Java source count/kind");
        sources[file.name] = project_file_sha256(root, file.name, 1 << 20);
    }

    const std::string fixture =
            "src/prepare/test/fixtures/com/voyemu/prepare/fixture/BuildMarker.java";
    sources[fixture] = project_file_sha256(root, fixture, 1 << 20);
    need(sources.contains("src/prepare/java/com/voyemu/prepare/PreparationMain.java"),
         "PreparationMain source missing");
    Json guest = Json::object();

    for (const auto *name : {"src/guest/android/oem/audio/OemAudioPolicy.java",
                             "src/guest/android/oem/audio/OemAudioPolicyUnavailable.java"}) {
        guest[std::string("voyemu/") + name] = project_file_sha256(root, name, 1 << 20);
    }

    return {{"schema", 1},
            {"resource_snapshot", guest},
            {"sources", sources},
            {"builder_sha256", sha256_bytes(builder)},
            {"dependencies", library_pins(root)}};
}

std::string java_helper_builder_source(std::string_view source) {
    need(!source.empty() && source.size() <= 256 * 1024 &&
                 source.find('\0') == std::string_view::npos,
         "bounded Java source required");
    std::string result;

    for (std::size_t i = 0; i < source.size(); ++i) {
        if (source[i] == '\r') {
            need(i + 1 < source.size() && source[i + 1] == '\n', "lone carriage return");
            continue;
        }

        result += source[i];
    }

    need(result.starts_with("package com.voyemu.prepare;\n") &&
                 result.find("public final class JavaHelperBuild") != std::string::npos &&
                 result.ends_with("}\n"),
         "registered Java helper builder required");

    return result;
}

void publish_java_helper_directory(const std::filesystem::path &stage,
                                   const std::filesystem::path &destination, const Json &owner,
                                   const std::function<void()> &before_publish) {
    ordinary(stage);
    ordinary(destination);
    need(std::filesystem::is_directory(stage) && !std::filesystem::exists(destination),
         "fresh helper publication required");
    need(owner.at("helper_sha256") == hash(stage / "voyemu-java-helper.jar", 128ULL << 20) &&
                 owner.at("build_receipt_sha256") == hash(stage / "build-receipt.json", 256 * 1024),
         "publication payload differs");
    need(!std::filesystem::exists(stage / "toolchain-receipt.json"),
         "fresh helper ownership receipt required");
    write_private_json(stage / "toolchain-receipt.json", owner);
    need(read_private_json(stage / "toolchain-receipt.json", 512 * 1024) == owner,
         "helper ownership receipt differs");
    need(!std::filesystem::exists(destination), "helper publication destination appeared");

    if (before_publish) {
        before_publish();
    }

    need(os::rename_exclusive(stage, destination), "exclusive helper publication failed");
}

namespace {
// The recipe: JavaHelperBuild compiled and run on jdk builds the helper of the sources captured in
// stage into output.
void build_java_helper(const std::filesystem::path &root, const Jdk &jdk, bool offline,
                       const Json &inputs, const std::filesystem::path &stage,
                       const std::filesystem::path &output) {
    const auto snapshot = stage / "sources";

    capture_helper_sources(root, snapshot, inputs);
    const auto builder = java_helper_builder_source(
            bytes(root / "src/prepare/JavaHelperBuild.java", 256 * 1024));
    need(sha256_bytes(builder) == inputs.at("builder_sha256").get<std::string>(),
         "shared builder changed");
    write(stage / "JavaHelperBuild.java", builder);
    ProcessSpec command;
    command.executable = jdk.javac;
    command.directory = root;
    command.environment = environment(stage);
    command.arguments = {"-J-Djava.io.tmpdir=" + stage.string(),
                         "--release",
                         "25",
                         "-encoding",
                         "UTF-8",
                         "-d",
                         (stage / "bootstrap").string(),
                         (snapshot / "src/prepare/java/com/voyemu/prepare/Json.java").string(),
                         (stage / "JavaHelperBuild.java").string()};
    auto compile = execute(command, 120000, 1 << 20);
    write(stage / "javac.log", compile.output);
    need(!compile.timed_out && compile.exit_code == 0,
         "shared builder javac failed; see project .local/build/tmp stage");
    command.executable = jdk.java;
    command.arguments = {"-Xmx512m",
                         "-Djava.io.tmpdir=" + stage.string(),
                         "-cp",
                         (stage / "bootstrap").string(),
                         "com.voyemu.prepare.JavaHelperBuild",
                         root.string(),
                         (root / ".local/toolchains/java/libraries").string(),
                         (root / ".local/toolchains/native-sdk").string(),
                         output.string(),
                         "-",
                         offline ? "offline" : "fetch",
                         (root / ".local/toolchains/downloads/sdk").string(),
                         snapshot.string()};
    const auto run = execute(command, 300000, 1 << 20);
    write(stage / "builder.log", run.output);
    need(!run.timed_out && run.exit_code == 0,
         "Java helper build/fetch failed; see project .local/build/tmp stage");
    const auto current = refreshed(jdk);
    need(current.java_sha256 == jdk.java_sha256 && current.javac_sha256 == jdk.javac_sha256 &&
                 current.release_sha256 == jdk.release_sha256,
         "JDK changed during helper preparation");
}

Json helper_owner(const std::filesystem::path &folder, const Json &inputs) {
    return {{"schema", 1},
            {"kind", "java-preparation-toolchain"},
            {"fingerprint", sha256_bytes(inputs.dump())},
            {"helper_sha256", hash(folder / "voyemu-java-helper.jar", 128ULL << 20)},
            {"build_receipt_sha256", hash(folder / "build-receipt.json", 256 * 1024)}};
}

// Cache selection supplies the expected key; the receipt cannot select its own identity.
void verify_published_helper(const std::filesystem::path &root, const std::filesystem::path &folder,
                             const Json &inputs) {
    ordinary(folder);
    const auto fingerprint = sha256_bytes(inputs.dump());

    need(std::filesystem::exists(folder / "toolchain-receipt.json"),
         "incomplete helper ownership; retained without adoption");

    const auto owner = read_private_json(folder / "toolchain-receipt.json", 512 * 1024);
    need(owner.value("schema", 0) == 1 &&
                 owner.value("kind", std::string{}) == "java-preparation-toolchain" &&
                 owner.at("fingerprint") == fingerprint,
         "immutable helper ownership/cache key mismatch");
    const auto built = verify_helper(root, folder);
    need(owner.at("helper_sha256") == built.at("sha256") &&
                 owner.at("build_receipt_sha256") ==
                         hash(folder / "build-receipt.json", 256 * 1024),
         "immutable helper receipt mismatch");
}
} // namespace

std::filesystem::path install_java_helper(
        const std::filesystem::path &root, const Json &pin, bool offline, std::uint64_t reserve,
        const DownloadTransport &transport,
        const std::function<void(const std::filesystem::path &, const std::filesystem::path &)>
                &build,
        bool from_sources) {
    ordinary(root);
    const auto inputs = java_helper_source_inputs(root, from_sources);
    const auto fingerprint = sha256_bytes(inputs.dump());
    const auto cache = root / ".local/toolchains/java-helper", folder = cache / fingerprint;

    if (std::filesystem::exists(folder)) {
        verify_published_helper(root, folder, inputs);

        return folder;
    }

    ensure_private_directory(cache);
    HelperLock build_guard(cache / (fingerprint + ".lock"));

    if (std::filesystem::exists(folder)) {
        verify_published_helper(root, folder, inputs);

        return folder;
    }

    const auto stage = root / ".local/build/tmp" / ("java-toolchain-" + random_token());
    ensure_private_directory(stage);
    const auto token = random_token();
    write_private_json(stage / ".owner.json", {{"token", token}});
    const auto output = stage / "helper";
    const auto sha = pin.at("sha256").get<std::string>();

    try {
        bool downloaded = false;

        if (!inputs.contains("sources")) {
            try {
                const auto asset = download_pinned({pin.at("url").get<std::string>(),
                                                    sha,
                                                    128ULL << 20,
                                                    DownloadEncoding::raw,
                                                    {},
                                                    "java_helper"},
                                                   root / ".local/toolchains/downloads/java-helper",
                                                   offline, reserve, transport)
                                           .file;
                extract_java_helper(root, asset, sha, output, reserve);
                downloaded = true;
            } catch (const std::runtime_error &error) {
                const std::string message = error.what();

                // Only an asset that is not published or not cached offline is missing; a network
                // failure stays an error.
                if (!download_unpublished(std::current_exception()) &&
                    !message.starts_with("DOWNLOAD_OFFLINE:")) {
                    throw;
                }

                throw VoyemuError("JAVA_HELPER_ASSET_MISSING",
                                  project_source_checkout(root)
                                          ? "the pinned helper asset is unavailable; use --jdk to "
                                            "build the developer source recipe"
                                          : "the pinned helper asset is unavailable");
            }
        }

        if (!downloaded) {
            build(stage, output);
        }

        verify_helper(root, output);
        verify_helper_tool_inputs(root, inputs);
        publish_java_helper_directory(output, folder, helper_owner(output, inputs));
    } catch (const std::exception &error) {
        write_private_json(stage / "failure.json", {{"schema", 1},
                                                    {"kind", "java-toolchain-failure"},
                                                    {"fingerprint", fingerprint},
                                                    {"logs_retained", true}});
        throw std::runtime_error(std::string(error.what()) + "; diagnostics: " + stage.string());
    }

    if (read_private_json(stage / ".owner.json").at("token") == token) {
        std::filesystem::remove_all(stage);
    }

    return folder;
}

std::filesystem::path java_helper_recipe_jdk(const std::filesystem::path &root,
                                             const std::filesystem::path &jdk) {
    if (!project_source_checkout(root)) {
        throw VoyemuError("JAVA_HELPER_ASSET_MISSING",
                          "the java-helper asset of these sources cannot be downloaded and this "
                          "installation has no project sources for its recipe");
    }

    if (!jdk.empty()) {
        return jdk;
    }

    const auto home = java_developer_jdk(root);

    if (!std::filesystem::is_regular_file(home / "bin" /
                                          ("javac" + std::string(executable_suffix)))) {
        throw VoyemuError("JAVA_HELPER_ASSET_MISSING",
                          "the java-helper asset of these sources cannot be downloaded and the "
                          "pinned JDK of the developer tools that builds it is not installed: " +
                                  home.string());
    }

    return home;
}

std::filesystem::path profile_preparation_jdk(const std::filesystem::path &root,
                                              const std::filesystem::path &requested,
                                              const Json &helper_pin, bool target) {
    if (!target || helper_pin.value("profileTargetSchema", Json{}) == 1) {
        return requested;
    }

    if (!project_source_checkout(root)) {
        throw VoyemuError("JAVA_HELPER_ASSET_MISSING",
                          "the pinned release helper does not support profile build targets; build "
                          "the machine from the Voyemu source checkout with its developer JDK");
    }

    return java_helper_recipe_jdk(root, requested);
}

std::filesystem::path java_preparation_java(const std::filesystem::path &root,
                                            const std::filesystem::path &jdk, const Json &runtime,
                                            bool offline, std::uint64_t reserve,
                                            const DownloadTransport &transport) {
    if (!jdk.empty()) {
        return installed_jdk(root, jdk).java;
    }

    return install_java_runtime(root, runtime, offline, reserve, transport);
}

JavaPreparationToolchain ensure_java_preparation_tools(const std::filesystem::path &root,
                                                       const std::filesystem::path &requested,
                                                       bool offline, std::uint64_t reserve) {
    ordinary(root);
    need(std::filesystem::is_directory(root), "project root required");
    const auto java = java_preparation_java(
            root, requested, embedded_toolchain_manifest().at("javaRuntime"), offline, reserve);
    const auto home = java.parent_path().parent_path();
    const auto java_sha256 = java_toolchain_input_sha256(java);
    const bool from_sources = !requested.empty();
    const auto inputs = java_helper_source_inputs(root, from_sources);
    const auto fingerprint = sha256_bytes(inputs.dump());
    const bool reused =
            std::filesystem::exists(root / ".local/toolchains/java-helper" / fingerprint);

    if (!reused) {
        require_disk_space("JAVA_TOOLCHAIN", root, 512ULL << 20, reserve);
    }

    install_java_sdk(root, offline, reserve, {});
    const auto folder = install_java_helper(
            root, embedded_toolchain_manifest().at("javaHelper"), offline, reserve, {},
            [&](const std::filesystem::path &stage, const std::filesystem::path &output) {
                build_java_helper(root,
                                  installed_jdk(root, java_helper_recipe_jdk(root, requested)),
                                  offline, inputs, stage, output);
            },
            from_sources);
    need(folder.filename() == fingerprint, "helper sources changed during preparation");
    need(java_toolchain_input_sha256(java) == java_sha256, "Java changed during preparation");
    const auto built = verify_helper(root, folder);
    JavaPreparationToolchain result;
    result.runtime.jdk = home;
    result.runtime.java_sha256 = java_sha256;
    result.runtime.helper = folder / "voyemu-java-helper.jar";
    result.runtime.helper_sha256 = built.at("sha256").get<std::string>();
    result.runtime.receipt = folder / "build-receipt.json";
    result.runtime.receipt_sha256 = hash(result.runtime.receipt, 256 * 1024);
    result.runtime.helper_cache_key = fingerprint;
    result.sdk = root / ".local/toolchains/native-sdk";
    result.platform = root / ".local/toolchains/java-sdk/platforms/android-34/android.jar";
    result.platform_sha256 = java_toolchain_input_sha256(result.platform);
    result.reused = reused;
    result.receipt = {{"schema", 1},
                      {"kind", "java-preparation-tools"},
                      {"fingerprint", fingerprint},
                      {"helper", result.runtime.helper.string()},
                      {"helper_sha256", result.runtime.helper_sha256},
                      {"helper_receipt_sha256", result.runtime.receipt_sha256},
                      {"runtime", requested.empty() ? "java-runtime" : "jdk"},
                      {"jdk", home.string()},
                      {"java_sha256", java_sha256},
                      {"sdk", result.sdk.string()},
                      {"platform", result.platform.string()},
                      {"platform_sha256", result.platform_sha256},
                      {"reused", reused},
                      {"jdk_downloaded", false},
                      {"shell_required", false},
                      {"node_required", false},
                      {"python_required", false},
                      {"native_sdk_modified", false},
                      {"native_sdk_installed", std::filesystem::is_directory(result.sdk)}};

    return result;
}
} // namespace voyemu
