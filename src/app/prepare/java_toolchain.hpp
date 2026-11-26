#pragma once
#include "download.hpp"
#include "java_preparation.hpp"
#include <functional>
namespace voyemu {
struct JavaPreparationToolchain {
    JavaPreparationRuntime runtime;
    std::filesystem::path sdk, platform;
    std::string platform_sha256;
    Json receipt;
    bool reused = false;
};
// Hashes owned or installed root-owned regular immutable inputs, including shared hard links,
// without modifying them.
std::string java_toolchain_input_sha256(const std::filesystem::path &path,
                                        std::uint64_t maximum = 256ULL << 20,
                                        const std::function<void()> &before_verify = {});
// Validates the bounded Java builder source; compilation uses installed javac.
std::string java_helper_builder_source(std::string_view script);
// Local build-cache inputs only; source maps are never published in artifact receipts. Without
// from_sources, select the pinned asset even inside a source checkout.
Json java_helper_source_inputs(const std::filesystem::path &root, bool from_sources = true);
// Publishes an already validated helper with its ownership receipt in one directory rename.
void publish_java_helper_directory(const std::filesystem::path &stage,
                                   const std::filesystem::path &destination, const Json &owner,
                                   const std::function<void()> &before_publish = {});
// Installs the Java helper of the current sources into .local/toolchains/java-helper/<fingerprint>/
// and returns that folder. from_sources selects the developer recipe when sources exist;
// otherwise the pinned java-helper.zip is used. Both paths verify the real artifact and external
// dependencies. A final cache missing ownership is retained and rejected.
std::filesystem::path install_java_helper(
        const std::filesystem::path &root, const Json &pin, bool offline, std::uint64_t reserve,
        const DownloadTransport &transport,
        const std::function<void(const std::filesystem::path &, const std::filesystem::path &)>
                &build,
        bool from_sources = true);
// The JDK home that builds a helper without a published asset: jdk when given, otherwise the pinned
// JDK of the developer tools; without either it stops with JAVA_HELPER_ASSET_MISSING.
std::filesystem::path java_helper_recipe_jdk(const std::filesystem::path &root,
                                             const std::filesystem::path &jdk);
// A selected build target needs a helper that declares profileTargetSchema; otherwise a source
// checkout builds the helper with its developer JDK.
std::filesystem::path profile_preparation_jdk(const std::filesystem::path &root,
                                              const std::filesystem::path &requested,
                                              const Json &helper_pin, bool target);
// The java that runs the helper: that of the JDK25+ jdk when given, otherwise that of the Java
// runtime of this host which install_java_runtime installs from runtime (javaRuntime pins).
std::filesystem::path java_preparation_java(const std::filesystem::path &root,
                                            const std::filesystem::path &jdk, const Json &runtime,
                                            bool offline, std::uint64_t reserve,
                                            const DownloadTransport &transport = {});
// The Java runtime of preparation, or the JDK25+ jdk as a developer override, runs the helper; the
// Java SDK JARs come from the pinned SDK archives and the helper from install_java_helper, whose
// recipe runs on java_helper_recipe_jdk. offline forbids downloads.
// Native SDK is never installed, copied or modified by this function.
JavaPreparationToolchain ensure_java_preparation_tools(const std::filesystem::path &root,
                                                       const std::filesystem::path &jdk = {},
                                                       bool offline = false,
                                                       std::uint64_t reserve_bytes = 20ULL << 30);
} // namespace voyemu
