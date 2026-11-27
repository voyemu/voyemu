#include "quickboot.hpp"
#include "android_audio_startup.hpp"
#include "android_engine.hpp"
#include "android_system_binding.hpp"
#include "check.hpp"
#include "error.hpp"
#include "os/platform.hpp"
#include "passion_wheel.hpp"
#include "process.hpp"
#include "qinggan11_startup.hpp"
#include "qnx_interguest_contract.hpp"
#include "quickboot_stamp.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>

namespace voyemu {
namespace {
bool nonce(const std::string &value) {
    return hex_text(value, 32);
}

Json stamp(const std::filesystem::path &path, std::uintmax_t expected_links = 1) {
    if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path))) {
        throw VoyemuError("QUICKBOOT_FILE", "owned regular file required");
    }

    return file_stamp(path, expected_links);
}
} // namespace

bool android_presave_required(const Json &specification) {
    const auto capability = specification.value("wheel_capability", Json());

    return qinggan11_partial_wheel_capability_matches(capability) ||
           passion_wheel_partial(capability);
}

namespace {
bool guest_boot_valid(const std::string &value) {
    if (value.size() != 36) {
        return false;
    }

    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') {
                return false;
            }
        } else if (std::string_view("0123456789abcdef").find(value[i]) == std::string_view::npos) {
            return false;
        }
    }

    return true;
}

bool presave_matches(const Json &receipt, const std::string &session, const std::string &guest_boot,
                     std::uint32_t sequence, const std::string &challenge) {
    try {
        return nonce(session) && guest_boot_valid(guest_boot) && nonce(challenge) &&
               receipt.at("schema").is_number_integer() && receipt.at("schema") == 1 &&
               receipt.at("status") == "presave-ready" && receipt.at("session_id") == session &&
               receipt.at("boot_id") == guest_boot && receipt.at("sequence").is_number_integer() &&
               receipt.at("sequence") == sequence && receipt.at("save_nonce") == challenge &&
               receipt.at("acoustic_zero").is_boolean() && receipt.at("acoustic_zero") == true;
    } catch (...) {
        return false;
    }
}

bool saved_presave_valid(const Json &saved) {
    if (!android_presave_required(saved.at("key").at("prepared"))) {
        return true;
    }

    const auto &binding = saved.at("presave");
    const auto &receipt = binding.at("receipt");

    if (!binding.at("input_sequence").is_number_integer() || binding.at("input_sequence") < 0 ||
        binding.at("input_sequence") > UINT32_MAX) {
        return false;
    }

    return binding.at("host_boot_nonce") == saved.at("boot_nonce") &&
           nonce(binding.at("host_boot_nonce").get<std::string>()) &&
           presave_matches(receipt, binding.at("host_session_id").get<std::string>(),
                           binding.at("guest_boot_id").get<std::string>(),
                           binding.at("input_sequence").get<std::uint32_t>(),
                           receipt.at("save_nonce").get<std::string>());
}
} // namespace

std::optional<Json>
android_presave_snapshot(const std::string &session, const std::string &guest_boot,
                         std::uint32_t sequence,
                         const std::function<Json(const std::string &)> &presave,
                         const std::function<bool()> &save) {
    try {
        const auto challenge = random_token();
        auto receipt = presave(challenge);

        if (!presave_matches(receipt, session, guest_boot, sequence, challenge) || !save()) {
            return std::nullopt;
        }

        return receipt;
    } catch (...) {
        return std::nullopt;
    }
}

Json cache_file_identity(const std::filesystem::path &path, std::uintmax_t expected_links) {
    return stamp(path, expected_links);
}

bool same_file_object(const Json &first, const Json &second) {
    auto a = first, b = second;

    // The size and time fields of both identity forms that stamp writes.
    for (const char *key :
         {"size", "size_high", "size_low", "mtime_seconds", "mtime_ns", "mtime_high", "mtime_low",
          "ctime_seconds", "ctime_ns", "change_time"}) {
        a.erase(key);
        b.erase(key);
    }

    return a == b;
}

static void normalize_checkpoint_prepared(Json &prepared) {
    prepared.erase("owned_adb");
    prepared.erase("frontend");

    if (prepared.value("adb_transport", std::string{}) == "direct") {
        prepared.erase("adb_transport");
    }
}

Json android_quickboot_key(const Json &specification) {
    auto prepared = specification;

    normalize_checkpoint_prepared(prepared);

    // Native presentation records have fresh session paths and do not change guest hardware.
    if (prepared.contains("env")) {
        for (const char *name : {"VOYEMU_HOST_WINDOW_RECORD", "VOYEMU_MEDIA_WINDOW_RECORD"}) {
            prepared["env"].erase(name);
        }
    }

    Json key{{"protocol", 2},
             {"wheel_protocol", 1},
             {"vehicle_protocol", 1},
             {"vehicle_maps", Json::array({qinggan09_map_sha256, qinggan11_map_sha256})},
             {"prepared", prepared},
             // The USB controller of the multimedia guest is part of the device state.
             {"usb_controller", "usb-ehci-v1"}};

    if (specification.contains("interguest_network")) {
        validate_qnx_interguest_contract(specification.at("interguest_network"));
        key["network_topology"] = specification.at("interguest_network");
        key["interguest_nic"] = "virtio-net-pci-v1";
    }

    if (specification.contains("network")) {
        validate_android_network_contract(specification.at("network"));
        key["outbound_network_topology"] = android_network_contract();
        key["outbound_nic"] = "virtio-net-pci-nat-v1";
    }

    if (android_presave_required(specification)) {
        key["presave_protocol"] = 1;
    }

    if (android_audio_startup_required(specification)) {
        key["audio_startup_protocol"] = 1;
    }

    // Timer/accelerator state is part of the SDK snapshot migration format on Windows.
    if (os::host_windows) {
        key["backend_arguments"] = android_sdk_machine_arguments(true);
    }

    return key;
}

std::string android_quickboot_config(std::string config) {
    std::istringstream input(config);
    std::string line, result;

    while (std::getline(input, line)) {
        auto at = line.find('=');
        auto name = line.substr(0, at);
        name.erase(std::remove_if(name.begin(), name.end(),
                                  [](unsigned char c) {
                                      return std::isspace(c);
                                  }),
                   name.end());

        if (name == "fastboot.forceColdBoot" || name == "fastboot.forceFastBoot") {
            continue;
        }

        result += line + '\n';
    }

    return result + "fastboot.forceColdBoot=no\nfastboot.forceFastBoot=yes\n";
}

AndroidQuickBoot::AndroidQuickBoot(std::filesystem::path machine, Json key,
                                   std::filesystem::path runtime)
    : machine_(std::move(machine)), runtime_(runtime.empty() ? machine_ : std::move(runtime)),
      record_(runtime_ / "voyemu-quickboot.json"), key_(std::move(key)) {}

Json AndroidQuickBoot::disks() const {
    Json result = Json::object();
    auto prepared = key_.value("prepared", Json::object());

    if (!prepared.contains("machine")) {
        prepared["machine"] = machine_.string();
    }

    const auto system = android_system_binding(prepared);
    const auto avd_disk_stamp = [&](const std::filesystem::path &disk, const char *name) {
        const auto alias = runtime_ / name;

        // Windows normally publishes these SDK aliases as hard links. Accept
        // a second link only when both known paths identify the same file.
        if (os::host_windows && runtime_ != machine_ &&
            std::filesystem::is_regular_file(std::filesystem::symlink_status(alias)) &&
            std::filesystem::equivalent(disk, alias) && disk != alias) {
            const auto identity = stamp(disk, 2);

            if (stamp(alias, 2) != identity) {
                throw VoyemuError("QUICKBOOT_FILE", "AVD disk alias identity changed");
            }

            return identity;
        }

        return stamp(disk);
    };

    for (const char *name :
         {"userdata-qemu.img", "userdata-qemu.img.qcow2", "encryptionkey.img.qcow2"}) {
        result[name] = stamp(machine_ / name);
    }

    for (const char *name : {"cache.img", "cache.img.qcow2"}) {
        result[name] = stamp(runtime_ / name);
    }

    result["encryptionkey.img"] = avd_disk_stamp(machine_ / "encryptionkey.img",
                                                 "encryptionkey.img");
    result["system.img.qcow2"] = avd_disk_stamp(system.overlay, "system.img.qcow2");
    result["vendor.img.qcow2"] = avd_disk_stamp(machine_ / "vendor.img.qcow2", "vendor.img.qcow2");

    const auto base =
            key_.value("prepared", Json::object()).value("base", (machine_ / "base").string());
    result["base/system.img"] = avd_disk_stamp(system.raw, "system.img");
    result["base/vendor.img"] = avd_disk_stamp(std::filesystem::path(base) / "vendor.img",
                                               "vendor.img");

    return result;
}

Json AndroidQuickBoot::snapshot() const {
    Json result = Json::object();
    const auto directory = runtime_ / "snapshots" / snapshot_name;

    if (!std::filesystem::is_directory(directory) || std::filesystem::is_symlink(directory)) {
        throw VoyemuError("QUICKBOOT_FILE", "snapshot directory required");
    }

    std::size_t count = 0;

    for (const auto &item : std::filesystem::recursive_directory_iterator(directory)) {
        if (++count > 128) {
            throw VoyemuError("QUICKBOOT_FILE", "snapshot extent exceeded");
        }

        const auto status = item.symlink_status();

        if (std::filesystem::is_symlink(status)) {
            throw VoyemuError("QUICKBOOT_FILE", "linked snapshot rejected");
        }

        if (std::filesystem::is_directory(status)) {
            continue;
        }

        result[item.path().lexically_relative(directory).generic_string()] = stamp(item.path());
    }

    for (const char *name : {"snapshot.pb", "ram.bin", "hardware.ini"}) {
        if (!result.contains(name) || std::filesystem::file_size(directory / name) == 0) {
            throw VoyemuError("QUICKBOOT_FILE", "incomplete snapshot");
        }
    }

    return result;
}

QuickBootRestore AndroidQuickBoot::runtime_checkpoint() const {
    if (!std::filesystem::exists(record_)) {
        return {false, {}, "cache_missing"};
    }

    try {
        const auto saved = read_private_json(record_, 32768);

        if (saved.value("schema", 0) != 1 || saved.value("state", std::string{}) != "clean" ||
            saved.value("name", std::string{}) != snapshot_name) {
            return {false, {}, "unclean_or_incompatible"};
        }

        auto saved_key = saved.at("key");

        if (saved_key.contains("prepared")) {
            normalize_checkpoint_prepared(saved_key["prepared"]);
        }

        if (saved_key != key_) {
            return {false, {}, "prepared_inputs_changed"};
        }

        if (!saved_presave_valid(saved)) {
            return {false, {}, "presave_receipt_invalid"};
        }

        const auto boot = saved.at("boot_nonce").get<std::string>();

        if (!nonce(boot)) {
            return {false, {}, "boot_nonce_invalid"};
        }

        if (saved.at("disks") != disks()) {
            return {false, {}, "guest_storage_changed"};
        }

        return {true, boot, "prepared_checkpoint"};
    } catch (const std::exception &) {
        return {false, {}, "cache_rejected"};
    }
}

QuickBootRestore AndroidQuickBoot::inspect() const {
    if (!std::filesystem::exists(record_) && !std::filesystem::is_symlink(record_)) {
        return {false, {}, "cache_missing"};
    }

    try {
        stamp(record_);
        const auto saved = read_private_json(record_, 32768);

        if (saved.value("schema", 0) != 1 || saved.value("state", std::string{}) != "clean" ||
            saved.value("name", std::string{}) != snapshot_name) {
            return {false, {}, "unclean_or_incompatible"};
        }

        auto saved_key = saved.at("key");

        if (saved_key.contains("prepared")) {
            normalize_checkpoint_prepared(saved_key["prepared"]);
        }

        if (saved_key != key_) {
            return {false, {}, "prepared_inputs_changed"};
        }

        if (!saved_presave_valid(saved)) {
            return {false, {}, "presave_receipt_invalid"};
        }

        const auto boot = saved.at("boot_nonce").get<std::string>();

        if (!nonce(boot)) {
            return {false, {}, "boot_nonce_invalid"};
        }

        // Earlier macOS checkpoints named the volume by device number.
        for (const auto &item : saved.at("disks").items()) {
            if (os::platform_name == "macOS" && item.value().contains("device") &&
                !item.value().contains("volume_uuid")) {
                return {false, {}, "storage_identity_format_changed"};
            }
        }

        if (saved.at("disks") != disks()) {
            return {false, {}, "guest_storage_changed"};
        }

        if (saved.at("snapshot") != snapshot()) {
            return {false, {}, "snapshot_changed"};
        }

        return {true, boot, "clean_checkpoint"};
    } catch (const std::exception &) {
        return {false, {}, "cache_rejected"};
    }
}

Json AndroidQuickBoot::snapshot_save_budget(std::optional<std::uint64_t> available) const {
    constexpr std::uint64_t reserve = 512ULL * 1024 * 1024;
    Json budget{{"allowed", false},
                {"available_bytes", available ? Json(*available) : Json()},
                {"reserve_bytes", reserve},
                {"reason", "disk_space_unknown"}};

    if (!available) {
        return budget;
    }

    try {
        const auto &prepared = key_.at("prepared");
        const auto path = std::filesystem::path(prepared.at("config_template").get<std::string>());
        const auto config_identity = stamp(path);

        if (std::filesystem::file_size(path) > 65536) {
            throw VoyemuError("QUICKBOOT_CONFIG", "extent");
        }

        std::string pin;

        for (const auto &item : prepared.at("pins")) {
            if (item.at("path") == path.string()) {
                pin = item.at("sha256").get<std::string>();
            }
        }

        if (pin.empty() || sha256_file(path) != pin) {
            throw VoyemuError("QUICKBOOT_CONFIG", "pin changed");
        }

        std::ifstream config(path);
        std::string line;
        std::uint64_t memory_mib = 0;
        bool seen = false;
        auto trim = [](std::string value) {
            const auto first = value.find_first_not_of(" \t\r");

            if (first == std::string::npos) {
                return std::string{};
            }

            return value.substr(first, value.find_last_not_of(" \t\r") - first + 1);
        };

        while (std::getline(config, line)) {
            const auto at = line.find('=');

            if (at == std::string::npos || trim(line.substr(0, at)) != "hw.ramSize") {
                continue;
            }

            if (seen) {
                throw VoyemuError("QUICKBOOT_CONFIG", "duplicate RAM");
            }

            seen = true;
            const auto value = trim(line.substr(at + 1));
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(),
                                                      memory_mib);

            if (error != std::errc{} || end != value.data() + value.size() || memory_mib < 1 ||
                memory_mib > 65536) {
                throw VoyemuError("QUICKBOOT_CONFIG", "RAM extent");
            }
        }

        if (!seen || config.bad() || stamp(path) != config_identity) {
            throw VoyemuError("QUICKBOOT_CONFIG", "RAM unavailable or changed");
        }

        std::uint64_t previous = 0;
        std::size_t count = 0;
        const auto directory = runtime_ / "snapshots" / snapshot_name;

        if (std::filesystem::is_symlink(directory)) {
            throw VoyemuError("QUICKBOOT_FILE", "linked snapshot");
        }

        if (std::filesystem::exists(directory)) {
            for (const auto &item : std::filesystem::recursive_directory_iterator(directory)) {
                if (++count > 128 || item.is_symlink()) {
                    throw VoyemuError("QUICKBOOT_FILE", "snapshot extent");
                }

                if (item.is_directory()) {
                    continue;
                }

                stamp(item.path());
                const auto size = std::filesystem::file_size(item.path());

                if (size > std::numeric_limits<std::uint64_t>::max() - previous) {
                    throw VoyemuError("QUICKBOOT_FILE", "snapshot size overflow");
                }

                previous += size;
            }
        }

        const auto memory = memory_mib * 1024 * 1024, replacement = std::max(memory, previous);

        if (replacement > std::numeric_limits<std::uint64_t>::max() - reserve) {
            throw VoyemuError("QUICKBOOT_FILE", "reserve overflow");
        }

        const auto required = replacement + reserve;
        const bool allowed = *available >= required;
        budget.update({{"allowed", allowed},
                       {"required_bytes", required},
                       {"configured_ram_bytes", memory},
                       {"previous_snapshot_bytes", previous},
                       {"reason", allowed ? "space_available" : "insufficient_disk_space"}});
    } catch (const std::exception &) {
        budget["reason"] = "snapshot_space_unknown";
    }

    return budget;
}

void AndroidQuickBoot::begin() {
    ensure_private_directory(runtime_);

    if (std::filesystem::exists(record_) || std::filesystem::is_symlink(record_)) {
        stamp(record_);
    }

    auto pending = record_;
    pending += ".pending";

    if (std::filesystem::exists(pending) || std::filesystem::is_symlink(pending)) {
        stamp(pending);

        if (std::filesystem::file_size(pending) > 128 * 1024) {
            throw VoyemuError("QUICKBOOT_PENDING", "invalid stale write");
        }

        std::filesystem::remove(pending);
    }

    ensure_private_directory(runtime_ / "snapshots");
    ensure_private_directory(runtime_ / "snapshots" / snapshot_name);
    generation_ = random_token();
    write_private_json(record_, {{"schema", 1},
                                 {"state", "in_use"},
                                 {"key", key_},
                                 {"name", snapshot_name},
                                 {"generation", generation_}});
}

void AndroidQuickBoot::commit(const std::string &boot_nonce, const std::string &session,
                              const Json &presave, const std::string &guest_boot,
                              std::uint32_t input_sequence) {
    if (!nonce(boot_nonce)) {
        throw VoyemuError("QUICKBOOT_NONCE", "invalid immutable boot identity");
    }

    const auto current = read_private_json(record_, 32768);

    if (generation_.empty() || current.value("generation", std::string{}) != generation_ ||
        current.value("state", std::string{}) != "in_use" || current.at("key") != key_) {
        throw VoyemuError("QUICKBOOT_OWNER", "checkpoint generation changed");
    }

    Json saved = {{"schema", 1},           {"state", "clean"},         {"name", snapshot_name},
                  {"key", key_},           {"boot_nonce", boot_nonce}, {"disks", disks()},
                  {"snapshot", snapshot()}};

    if (android_presave_required(key_.at("prepared"))) {
        saved["presave"] = {{"host_session_id", session},
                            {"host_boot_nonce", boot_nonce},
                            {"guest_boot_id", guest_boot},
                            {"input_sequence", input_sequence},
                            {"receipt", presave}};

        if (!saved_presave_valid(saved)) {
            throw VoyemuError("QUICKBOOT_PRESAVE", "verified receipt required");
        }
    }

    write_private_json(record_, saved);
}
} // namespace voyemu
