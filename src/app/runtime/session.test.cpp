#include "session.hpp"
#include "android_adb_route.hpp"
#include "nxp_presentation.hpp"
#include "os/fs.hpp"
#include "os/held_file.hpp"
#include "os/platform.hpp"
#include "os/socket.hpp"
#include "passion_display_cache.hpp"
#include "passion_presentation.hpp"
#include "passion_wheel.hpp"
#include "program_modes.hpp"
#include "qinggan11_startup.hpp"
#include "qnx_interguest_contract.hpp"
#include "qnx_mcu_projection.hpp"
#include "qnx_persistent_storage.hpp"
#include "qnx_shutdown_monitor.hpp"
#include "session_internal.hpp"
#include "session_test_host.hpp"
#include "shutdown_fixture.hpp"
#include "ui_observer.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <tuple>
using namespace voyemu;
// Bound of a wait for an event that a passing run sees within milliseconds; loaded hosts get time.
constexpr auto event_wait = std::chrono::seconds(30);

static void rejects(const std::function<void()> &action) {
    bool threw = false;

    try {
        action();
    } catch (...) {
        threw = true;
    }

    assert(threw);
}

static std::string rejection(const std::function<void()> &action) {
    try {
        action();
    } catch (const std::exception &error) {
        return error.what();
    }

    assert(false);

    return {};
}

// Writes or reads exactly bytes at offset of an existing file.
static void write_at(const std::filesystem::path &path, std::uint64_t offset, const void *data,
                     std::size_t bytes) {
    os::PositionalFile file(path, true);

    assert(file.open() && file.write(offset, static_cast<const char *>(data), bytes));
}

static void read_at(const std::filesystem::path &path, std::uint64_t offset, void *data,
                    std::size_t bytes) {
    const os::PositionalFile file(path, false);

    assert(file.open() && file.read(offset, static_cast<char *>(data), bytes));
}

// Creates a new private file of bytes, sparse where the filesystem allows.
static void create_private_extent(const std::filesystem::path &path, std::uint64_t bytes) {
    assert(os::create_private_file(path));
    os::resize_file(path, bytes);
}

static unsigned reserve_loopback_port() {
    const os::SocketLibrary library;

    assert(!library.error());
    const auto fd = os::open_stream_socket(AF_INET);
    assert(fd != os::no_socket);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(os::bind_socket(fd, reinterpret_cast<sockaddr *>(&address), sizeof address));
    os::SocketLength extent = sizeof address;
    assert(os::socket_name(fd, reinterpret_cast<sockaddr *>(&address), &extent));
    const unsigned port = ntohs(address.sin_port);
    os::close_socket(fd);
    assert(port >= 1024 && port <= 65535);

    return port;
}

namespace voyemu {
struct SessionPersistenceFixture {
    static void screen_stream_handoff(const std::filesystem::path &executable) {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-screen-stream-" + random_token());
        ensure_private_directory(root);
        {
            Session session(root, random_token());
            session.cluster_generation_ = 2;
            constexpr std::uint64_t animation = 0x50001000, live = 0x50002000;
            const auto frame = root / "frame.bgra", claim = root / "frame-owner.json";
            const auto candidate = root / "producer-50002000";
            ensure_private_directory(candidate);
            frames::Writer animation_frames(frame), live_frames(candidate / "frame.bgra");
            frames::Reader visible(frame);
            std::vector<std::byte> pixels(frames::pixel_bytes, std::byte{11});
            animation_frames.publish(pixels, 4, 10);
            write_private_json(claim, {{"schema", 1},
                                       {"source", "original-OEM-Screen-BMP"},
                                       {"producer_address", animation}});
            const auto initial_frame = visible.read_latest();
            assert(initial_frame && initial_frame->bgra.front() == std::byte{11});

            ProcessSpec child;
            child.executable = executable;
            child.arguments = {"--screen-stream-worker-fixture"};
            child.output = root / "worker.log";
            session.graphics_.push_back(ChildProcess::launch(child));
            session.graphics_owners_.push_back({41, 42, 43});
            session.producers_.push_back(live);
            const Json receipt{{"schema", 1},
                               {"session_id", session.session_id_},
                               {"generation", 2},
                               {"producer_address", live},
                               {"worker_pid", session.graphics_[0].pid()},
                               {"nonce", 41},
                               {"guest_pid", 42},
                               {"producer_incarnation", 43}};
            std::array<std::uint64_t, 2> identity{42, 43};
            auto ram = [&](std::uint64_t address, std::span<std::byte> out) -> std::size_t {
                const std::array<std::uint32_t, 2> header{0x58464751, 3};

                if (address == live && out.size() == sizeof(header)) {
                    std::memcpy(out.data(), header.data(), sizeof(header));

                    return sizeof(header);
                }

                if (address == live + 240 && out.size() == sizeof(identity)) {
                    std::memcpy(out.data(), identity.data(), sizeof(identity));

                    return sizeof(identity);
                }

                return 0;
            };
            auto still_animation = [&] {
                session.promote_live_screen(ram);
                assert(read_private_json(claim).at("producer_address") == animation);
            };
            const auto proof = candidate / "screen-stream.json";
            std::fill(pixels.begin(), pixels.end(), std::byte{22});
            live_frames.publish(pixels, 1, 20);
            still_animation(); // A per-window writer with no stream receipt cannot take over.
            write_private_json(proof, receipt);
            still_animation(); // Do not reset a reader's sequence during the handoff.
            live_frames.publish(pixels, 5, 30);
            auto stale = receipt;
            stale["generation"] = 1;
            write_private_json(proof, stale);
            still_animation();
            auto unrelated = receipt;
            unrelated["producer_address"] = live + 4096;
            write_private_json(proof, unrelated);
            still_animation();
            write_private_json(proof, receipt);
            identity[1] = 44;
            still_animation();
            identity[1] = 43;
            session.promote_live_screen(ram);
            const auto stream = read_private_json(claim);
            assert(stream.at("producer_address") == live && stream.at("screen_stream") == true);
            const auto new_frame = visible.read_latest(4);
            assert(new_frame && new_frame->sequence == 5 &&
                   new_frame->bgra.front() == std::byte{22});
            live_frames.publish(pixels, 6, 40);
            animation_frames.publish(pixels, 100, 50); // Lost owner cannot update canonical path.
            const auto newest_frame = visible.read_latest(5);
            assert(newest_frame && newest_frame->sequence == 6);
            session.graphics_[0].terminate(1000);
            assert(!session.graphics_[0].alive());
        }
        std::filesystem::remove_all(root);
    }

    // The MCU receiver of a generation dies (Screen ESRCH retirement): the vehicle delivery
    // reports the unavailable receiver with the last receipt instead of an endless queue, a
    // successor owes a receipt of its own and no receipt of the dead receiver is accepted.
    static void vehicle_receiver_lifecycle() {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-vehicle-receiver-" + random_token());
        ensure_private_directory(root);
        {
            Session session(root, random_token());
            constexpr std::uint64_t dead = 0x9de0f000, successor = 0x9de10000;
            session.cluster_requested_ = true;
            session.cluster_generation_ = 2;
            session.cluster_boot_spec_ = {{"hardware_adapter", "sa8155-qinggan09"}};
            session.deliveries_["qnx"] = {
                    {"status", "graphics_running"},
                    {"presentation", {{"status", "awaiting_vehicle_ack"}, {"generation", 2}}}};
            auto own = [&](std::uint64_t address, Session::GraphicsOwner owner) {
                session.graphics_.emplace_back();
                session.producers_.push_back(address);
                session.graphics_owners_.push_back(owner);
                // The worker creates its producer directory before it claims the controls.
                std::ostringstream producer;
                producer << "producer-" << std::hex << address;
                ensure_private_directory(root / producer.str());
                write_private_json(root / "control-owner.json", {{"schema", 1},
                                                                 {"source", "original-MCU-input"},
                                                                 {"producer_address", address}});
            };
            auto receipt = [&](std::uint64_t address, Session::GraphicsOwner owner,
                               std::uint64_t generation) {
                write_private_json(root / "vehicle-ack.json",
                                   {{"schema", 1u},
                                    {"sequence", session.body_.state().at("sequence")},
                                    {"producer_address", address},
                                    {"generation", generation},
                                    {"worker_nonce", owner.nonce},
                                    {"guest_pid", owner.pid},
                                    {"producer_incarnation", owner.incarnation},
                                    {"guest_acknowledged", true},
                                    {"host_monotonic_ns", 1u}});
            };
            auto revise = [&](unsigned value) {
                session.model_.patch({{"sound_enable", value}});
                session.body_.update(session.model_.state(), std::chrono::steady_clock::now());
                session.deliveries_["qnx"]["vehicle"] = session.qnx_vehicle_pending();
            };
            const Session::GraphicsOwner first{11, 978978, 0x91}, second{12, 1011, 0x92};
            own(dead, first);
            revise(1);
            receipt(dead, first, 2);
            session.observe_qnx_vehicle();
            const auto acknowledged = session.body_.state().at("sequence");
            assert(session.deliveries_["qnx"]["vehicle"]["status"] == "guest_acknowledged");
            session.retire_graphics_worker(0, true, "guest_pid_esrch", false);
            const auto &lost = session.deliveries_["qnx"]["vehicle"];
            assert(lost["status"] == "unavailable" && lost["reason"] == "receiver_retired" &&
                   lost["receiver"]["producer_address"] == dead &&
                   lost["receiver"]["guest_pid"] == 978978 &&
                   lost["receiver"]["producer_incarnation"] == 0x91 &&
                   lost["receiver"]["generation"] == 2 &&
                   lost["receiver"]["retirement"] == "guest_pid_esrch" &&
                   lost["last_acknowledged"]["sequence"] == acknowledged &&
                   lost["last_acknowledged"]["producer_address"] == dead);
            assert(!std::filesystem::exists(root / "control-owner.json") &&
                   !std::filesystem::exists(root / "vehicle-ack.json"));
            // A new revision without a receiver stays unavailable, also across polls.
            revise(0);
            session.observe_qnx_vehicle();
            assert(session.deliveries_["qnx"]["vehicle"]["status"] == "unavailable" &&
                   session.deliveries_["qnx"]["vehicle"]["sequence"] ==
                           session.model_.state().at("sequence"));
            // The receipt of the dead receiver for the old revision is replayed under the
            // successor: the successor is queued and nothing old is accepted.
            own(successor, second);
            const auto current = session.body_.state().at("sequence");
            write_private_json(root / "vehicle-ack.json",
                               {{"schema", 1u},
                                {"sequence", acknowledged},
                                {"producer_address", dead},
                                {"generation", 2u},
                                {"worker_nonce", first.nonce},
                                {"guest_pid", first.pid},
                                {"producer_incarnation", first.incarnation},
                                {"guest_acknowledged", true}});
            session.observe_qnx_vehicle();
            assert(session.deliveries_["qnx"]["vehicle"]["status"] == "queued" &&
                   session.qnx_retired_receiver_.is_null());
            receipt(successor, second, 1);
            session.observe_qnx_vehicle();
            assert(session.deliveries_["qnx"]["vehicle"]["status"] == "queued");
            receipt(successor, first, 2);
            session.observe_qnx_vehicle();
            assert(session.deliveries_["qnx"]["vehicle"]["status"] == "queued");
            receipt(successor, second, 2);
            session.observe_qnx_vehicle();
            const auto &fresh = session.deliveries_["qnx"]["vehicle"];
            assert(fresh["status"] == "guest_acknowledged" && fresh["sequence"] == current &&
                   fresh["source_sequence"] == session.model_.state().at("sequence") &&
                   session.deliveries_["qnx"]["presentation"]["vehicle_revision"] ==
                           session.model_.state().at("sequence"));
        }
        std::filesystem::remove_all(root);
    }

    // The cluster language command carries the ivi_languageSet of the model, which a qinggan11
    // guest also receives in its MCU word: every writer of the model field reaches both, and a
    // started cluster receives the current value again.
    static void cluster_language_single_source() {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-cluster-language-" + random_token());
        ensure_private_directory(root);
        {
            Session session(root, random_token());
            auto command = [&] {
                return read_private_json(root / "language-command.json");
            };
            session.queue_cluster_language();
            assert(!std::filesystem::exists(root / "language-command.json"));
            session.cluster_requested_ = true;
            session.model_.patch({{"ivi_languageSet", 1}});
            session.queue_cluster_language();
            assert(command() ==
                           Json({{"value", 1u}, {"source", "IPP_LANGUAGE_SET"}, {"seq", 1u}}) &&
                   session.deliveries_["qnx"]["language"]["value"] == 1);
            session.queue_cluster_language();
            assert(command()["seq"] == 1);
            session.model_.patch({{"ivi_languageSet", 0}});
            session.queue_cluster_language();
            assert(command()["seq"] == 2 && command()["value"] == 0);
            // A value without a command leaves the last command.
            session.model_.patch({{"ivi_languageSet", 2}});
            session.queue_cluster_language();
            assert(command()["seq"] == 2);
            session.model_.patch({{"ivi_languageSet", 0}});
            session.cluster_language_.reset();
            session.queue_cluster_language();
            assert(command()["seq"] == 3 && command()["value"] == 0);
        }
        std::filesystem::remove_all(root);
    }

    static void wheel_pair_flush_run() {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-wheel-flush-" + random_token());
        ensure_private_directory(root);
        auto pair = [](Session &session) {
            const auto down = session.events_.submit("volume_down", "down", "fixture-owner"),
                       up = session.events_.submit("volume_down", "up", "fixture-owner");
            session.android_events_ = {down, up};
            session.android_possible_pressed_[down.id] = down.owner;
            auto &t = session.windows_android_;
            t.phase = WindowsStartupPhase::event_submit;
            t.wheel_pair_up_sequence = up.sequence;
            t.wheel_pair_hold_ms = 150;

            return down.sequence;
        };
        {
            Session session(root / "undispatched", random_token());
            pair(session);
            session.close_cluster(false, "wheel-fixture");
            assert(session.android_events_.empty() && session.android_possible_pressed_.empty() &&
                   session.windows_android_.wheel_pair_up_sequence == 0 &&
                   session.windows_android_.phase == WindowsStartupPhase::ready);
        }
        {
            Session session(root / "pending", random_token());
            const auto down = pair(session);
            auto &t = session.windows_android_;
            t.attempted_mutations.insert("wheel-event:" + std::to_string(down));
            const WindowsAndroidOwner owner{session.session_id_, 1, 123, "fixture-route"};
            session.android_identity_probe_.launch(owner, {},
                                                   Session::RetainedAndroidAction::Clock::now(),
                                                   std::chrono::seconds(30), 4096);
            const auto up = t.wheel_pair_up_sequence;
            session.android_request_deadline_ = std::chrono::steady_clock::now() -
                                                std::chrono::milliseconds(1);
            bool deferred = false;
            try {
                session.close_cluster(false, "wheel-fixture");
            } catch (const std::exception &error) {
                deferred = std::string(error.what()).starts_with("ANDROID_IDENTITY_NOT_READY:");
            }

            assert(deferred && session.android_events_.size() == 2 &&
                   session.android_events_.front().sequence == down &&
                   session.android_events_[1].sequence == up);
            assert(t.wheel_pair_up_sequence == up && t.phase != WindowsStartupPhase::failed &&
                   t.attempted_mutations.count("wheel-event:" + std::to_string(down)) == 1);
            assert(session.android_identity_probe_.pending() &&
                   session.android_identity_probe_.owner() == owner);
            session.android_request_deadline_ = {};
            session.android_identity_probe_.cancel();
            session.android_events_.clear();
            session.android_possible_pressed_.clear();
            session.windows_android_ = WindowsAndroidTransaction{};
        }
        std::filesystem::remove_all(root);
    }

    // Windows pauses the persistence of the owned QEMU over QMP on loopback TCP and rejects a
    // foreign QMP peer and a wrong run state.
    static void qmp_pause_run(const std::filesystem::path &executable) {
        const auto root = std::filesystem::current_path() / ".local/build" /
                          ("qnx-win-pause-" + random_token());
        const auto id = random_token();
        ensure_private_directory(root);
        auto wait = [&](const std::filesystem::path &ready) {
            const auto deadline = std::chrono::steady_clock::now() + event_wait;

            while (!std::filesystem::exists(ready) && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }

            assert(std::filesystem::exists(ready));
            unsigned port = 0;
            std::ifstream(ready) >> port;
            assert(port >= 1024 && port <= 65535);

            return port;
        };
        const auto log = root / "qmp.log", foreign_log = root / "foreign.log";
        ProcessSpec child;
        child.executable = executable;
        child.arguments = {"--qnx-persistence-win-qmp-fixture", log.string()};
        child.output = root / "child.log";
        {
            Session session(root, id);
            session.qnx_ = ChildProcess::launch(child);
            const auto port = wait(log.string() + ".ready");
            session.cluster_spec_["qmp"] = {{"host", "127.0.0.1"}, {"port", port}};
            auto other = child;
            other.arguments = {"--qnx-persistence-win-qmp-fixture", foreign_log.string()};
            other.output = root / "foreign-child.log";
            auto foreign = ChildProcess::launch(other);
            const auto foreign_port = wait(foreign_log.string() + ".ready");
            session.cluster_spec_["qmp"]["port"] = foreign_port;
            rejects([&] {
                session.set_qnx_persistence_paused(true);
            });
            assert(!session.qnx_persistence_paused_ && !std::filesystem::exists(foreign_log));
            session.cluster_spec_["qmp"]["port"] = port;
            session.set_qnx_persistence_paused(true);
            assert(session.qnx_persistence_paused_ && session.qnx_.alive());
            session.set_qnx_persistence_paused(false);
            assert(!session.qnx_persistence_paused_);
            {
                std::ofstream invalid(log.string() + ".badstate");
                invalid << "wrong status";
            }
            rejects([&] {
                session.set_qnx_persistence_paused(true);
            });
            assert(session.qnx_persistence_paused_ && session.qnx_.alive());
            std::filesystem::remove(log.string() + ".badstate");
            session.set_qnx_persistence_paused(false);
            assert(!session.qnx_persistence_paused_);
            std::ifstream input(log);
            const std::string commands{std::istreambuf_iterator<char>(input), {}};
            assert(commands ==
                   "qmp_capabilities\nstop\nquery-status\nqmp_capabilities\ncont\nquery-status\nqmp_capabilities\nstop\nquery-status\nqmp_capabilities\ncont\nquery-status\n");
            session.qnx_.terminate(1000);
            foreign.terminate(1000);
            assert(!session.qnx_.alive() && !foreign.alive());
        }
        std::filesystem::remove_all(root);
    }

    static void uart_ready_run() {
        for (const bool passion : {true, false}) {
            const auto root = std::filesystem::current_path() / ".local/build" /
                              ("passion-session-ready-" + random_token());
            ensure_private_directory(root);
            const auto ram = root / "qnx-ram.bin";
            {
                std::ofstream file(ram);
                file << 'x';
            }
            os::resize_file(ram, passion ? 11713ULL << 20 : 8ULL << 30);
            const auto worker = root / "graphics-fixture", arguments = root / "graphics-argv";
            {
                std::ofstream script(worker);
                script << "#!/bin/sh\nprintf '%s\\n' \"$@\" > graphics-argv.tmp\nmv graphics-argv.tmp graphics-argv\nexec /bin/sleep 30\n";
            }
            std::filesystem::permissions(worker, std::filesystem::perms::owner_all);
            constexpr std::uint64_t page = 0x40003000;
            const std::array<std::uint32_t, 2> identity{0x58464751, 3};
            write_at(ram, page - 0x40000000, identity.data(), sizeof(identity));
            {
                std::ofstream serial(root / "qnx-serial.log");
                serial << "QG3 READY paddr=0x40003000 length=4096\n";
            }
            std::filesystem::permissions(root / "qnx-serial.log",
                                         std::filesystem::perms::owner_read |
                                                 std::filesystem::perms::owner_write);
            {
                Session session(root, random_token());
                session.cluster_finalized_ = true;
                session.qmp_cont_ = true;
                session.cluster_generation_ = 1;
                session.cluster_spec_ = {
                        {"profile", "passion-11-russian-20260403-2.1.4.80"},
                        {"hardware_adapter", "sa8155-passion-21480-developer"},
                        {"interguest_network", qnx_interguest_contract()},
                        {"interguest_ram", qnx_passion_interguest_ram_contract()},
                        {"ram_backend", "file"},
                        {"ram", "${SESSION}/qnx-ram.bin"},
                        {"qemu",
                         {{"args",
                           Json::array(
                                   {"-machine",
                                    "virt-11.0,gic-version=3,virtualization=on,secure=off,memory-backend=qnxmem",
                                    "-m", "11713", "-object",
                                    "memory-backend-file,id=qnxmem,size=11713M,mem-path=${SESSION}/qnx-ram.bin,share=on",
                                    "-serial", "file:${SESSION}/qnx-serial.log"})}}}};
                session.cluster_spec_["qemu"]["arguments"] = session.cluster_spec_["qemu"]["args"];

                if (!passion) {
                    session.cluster_spec_["hardware_adapter"] = "sa8155-qinggan11-731";
                    session.cluster_spec_.erase("profile");
                    session.cluster_spec_.erase("interguest_ram");
                    session.cluster_spec_["mcu_projection"] =
                            qnx_mcu_projection(QnxGuestAdapter::sa8155_qinggan11_731);
                }

                session.cluster_boot_spec_ = session.cluster_spec_;
                session.cluster_boot_spec_["graphics"] = {{"executable", worker.string()},
                                                          {"angle", "unused"}};
                ProcessSpec child;
                child.executable = "/bin/sleep";
                child.arguments = {"30"};
                child.output = root / "fixture.log";
                session.qnx_ = ChildProcess::launch(child);
                session.cluster_boot_spec_["hardware_adapter"] = "sa8155-qinggan11-731";
                session.cluster_boot_spec_.erase("mcu_projection");
                rejects([&] {
                    session.poll_qnx();
                });
                session.cluster_boot_spec_ = session.cluster_spec_;
                session.cluster_boot_spec_["graphics"] = {{"executable", worker.string()},
                                                          {"angle", "unused"}};
                const auto until = std::chrono::steady_clock::now() + event_wait;

                while (session.producers_.empty() && std::chrono::steady_clock::now() < until) {
                    session.poll_qnx();
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }

                if (session.producers_ != std::vector<std::uint64_t>{page}) {
                    throw std::runtime_error("Passion Session lost UART READY without legacy ring");
                }

                while (!std::filesystem::exists(arguments) &&
                       std::chrono::steady_clock::now() < until) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }

                std::ifstream captured(arguments);
                std::vector<std::string> argv;

                for (std::string arg; std::getline(captured, arg);) {
                    argv.push_back(arg);
                }

                std::vector<std::string> expected{
                        "--ram",       ram.string(),
                        "--ram-bytes", std::to_string(passion ? 11713ULL << 20 : 8ULL << 30),
                        "--address",   std::to_string(page),
                        "--session",   root.string(),
                        "--angle",     "unused"};

                // A qinggan11 worker names the adapter of the MCU layout it serves.
                if (!passion) {
                    expected.insert(expected.end(), {"--mcu-adapter", "sa8155-qinggan11-731"});
                }

                expected.insert(expected.end(),
                                {"--session-id", session.session_id_, "--generation", "1",
                                 "--worker-nonce",
                                 std::to_string(session.graphics_owners_.at(0).nonce),
                                 "--guest-pid", "0", "--producer-incarnation", "0"});

                if (argv != expected) {
                    throw std::runtime_error("Session graphics argv RAM extent mismatch");
                }

                // A typed terminal worker is isolated while its sibling and QEMU survive.
                ProcessSpec survivor;
                survivor.executable = "/bin/sleep";
                survivor.arguments = {"30"};
                survivor.output = root / "survivor.log";
                session.graphics_.push_back(ChildProcess::launch(survivor));
                session.producers_.push_back(page + 4096);
                session.graphics_owners_.push_back({42, 0, 0});
                session.graphics_[0].terminate(1000);
                ProcessSpec failed;
                failed.executable = "/bin/sh";
                failed.arguments = {"-c", "exit 70"};
                failed.output = root / "failed.log";
                session.graphics_[0] = ChildProcess::launch(failed);
                const auto owner = session.graphics_owners_[0];
                write_private_json(
                        root / ("worker-disposition-" + std::to_string(owner.nonce) + ".json"),
                        {{"schema", 1},
                         {"reason", "rpc_channel_invalidated"},
                         {"producer_address", page},
                         {"worker_pid", session.graphics_[0].pid()},
                         {"generation", 1},
                         {"nonce", owner.nonce},
                         {"session_id", session.session_id_},
                         {"guest_pid", 0},
                         {"producer_incarnation", 0}});

                while (session.graphics_[0].alive()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }

                session.poll_qnx();
                assert(session.qnx_.alive() && session.graphics_.size() == 1 &&
                       session.graphics_[0].alive() &&
                       session.producers_ == std::vector<std::uint64_t>{page + 4096});
                session.poll_qnx();
                assert(session.graphics_.size() ==
                       1); // The retained legacy READY cannot resurrect its retired address.
                // More than eight lifetime incarnations may reuse one address while only two
                // workers are active.
                constexpr std::uint64_t fresh_page = page + 8192;

                for (std::uint64_t incarnation = 1; incarnation <= 9; ++incarnation) {
                    const std::array<std::uint64_t, 2> identity_owner{123, incarnation};
                    write_at(ram, fresh_page - 0x40000000, identity.data(), sizeof(identity));
                    write_at(ram, fresh_page - 0x40000000 + 240, identity_owner.data(),
                             sizeof(identity_owner));
                    {
                        std::ofstream serial(root / "qnx-serial.log", std::ios::app);
                        serial << "QG3 READY paddr=0x" << std::hex << fresh_page
                               << " length=4096 pid=123 incarnation=0x" << incarnation << "\n";
                    }
                    const auto deadline = std::chrono::steady_clock::now() + event_wait;

                    while (session.producers_.size() < 2 &&
                           std::chrono::steady_clock::now() < deadline) {
                        session.poll_qnx();
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }

                    assert(session.producers_.size() == 2 && session.producers_[1] == fresh_page &&
                           session.graphics_owners_[1].incarnation == incarnation);
                    session.graphics_[1].terminate(1000);
                    session.graphics_[1] = ChildProcess::launch(failed);
                    const auto next_owner = session.graphics_owners_[1];
                    write_private_json(root / ("worker-disposition-" +
                                               std::to_string(next_owner.nonce) + ".json"),
                                       {{"schema", 1},
                                        {"reason", "rpc_channel_invalidated"},
                                        {"producer_address", fresh_page},
                                        {"worker_pid", session.graphics_[1].pid()},
                                        {"generation", 1},
                                        {"nonce", next_owner.nonce},
                                        {"session_id", session.session_id_},
                                        {"guest_pid", 123},
                                        {"producer_incarnation", incarnation}});

                    while (session.graphics_[1].alive()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }

                    session.poll_qnx();
                    assert(session.qnx_.alive() &&
                           session.producers_ == std::vector<std::uint64_t>{page + 4096});
                    const std::array<std::byte, 256> zero{};
                    write_at(ram, fresh_page - 0x40000000, zero.data(), zero.size());
                    session.poll_qnx();
                    assert(session.qnx_.alive() &&
                           session.producers_ ==
                                   std::vector<std::uint64_t>{
                                           page + 4096}); // Old enhanced READY cannot become an
                                                          // unbound legacy worker.
                }

                // Guest SIGKILL may leave all page identity bytes valid: reclaim exact dead PIDs at
                // the active limit.
                write_private_json(root / "frame-owner.json",
                                   {{"schema", 1},
                                    {"source", "original-OEM-Screen-BMP"},
                                    {"producer_address", page + 4096}});

                for (unsigned i = 0; i < 7; ++i) {
                    const auto address = page + 0x10000 + static_cast<std::uint64_t>(i) * 4096;
                    const std::array<std::uint64_t, 2> retained{500 + i, 100 + i};
                    write_at(ram, address - 0x40000000, identity.data(), sizeof(identity));
                    write_at(ram, address - 0x40000000 + 240, retained.data(), sizeof(retained));
                    auto child = survivor;
                    child.output = root / ("retained-" + std::to_string(i) + ".log");
                    session.graphics_.push_back(ChildProcess::launch(child));
                    session.producers_.push_back(address);
                    session.graphics_owners_.push_back({1000 + i, 500 + i, 100 + i});
                }

                session.publish_graphics_owners();
                assert(session.graphics_.size() == 8);
                auto death = [&](std::size_t i) {
                    const auto owner = session.graphics_owners_.at(i);

                    return Json{{"schema", 1},
                                {"session_id", session.session_id_},
                                {"generation", 1},
                                {"challenge", session.graphics_owner_challenge_},
                                {"nonce", owner.nonce},
                                {"producer_address", session.producers_[i]},
                                {"worker_pid", session.graphics_[i].pid()},
                                {"guest_pid", owner.pid},
                                {"producer_incarnation", owner.incarnation},
                                {"result", -1},
                                {"errno", 3},
                                {"observer_producer_address", page + 4096},
                                {"observer_worker_pid", session.graphics_[0].pid()},
                                {"observer_guest_pid", 0},
                                {"observer_producer_incarnation", 0},
                                {"observer_nonce", 42}};
                };
                const auto proof = death(1);
                const auto proof_path = root / "owner-death-1000.json";

                for (const auto *field :
                     {"generation", "nonce", "worker_pid", "guest_pid", "producer_incarnation",
                      "observer_nonce", "observer_worker_pid", "observer_producer_address",
                      "producer_address", "errno"}) {
                    auto wrong = proof;
                    wrong[field] = 999;
                    write_private_json(proof_path, wrong);
                    session.poll_qnx();
                    assert(session.graphics_.size() == 8 && session.graphics_[1].alive() &&
                           session.qnx_.alive());
                }

                auto stale = proof;
                stale["challenge"] = 0;
                write_private_json(proof_path, stale);
                session.poll_qnx();
                assert(session.graphics_.size() == 8 && !std::filesystem::exists(proof_path));
                auto legacy = death(0);
                write_private_json(root / "owner-death-42.json", legacy);
                session.poll_qnx();
                assert(session.graphics_.size() == 8 && session.graphics_[0].alive());
                std::filesystem::remove(root / "owner-death-42.json");
                // Even an exact receipt cannot reap a page now belonging to another incarnation.
                auto changed_identity = std::array<std::uint64_t, 2>{500, 999};
                const auto retained_address = session.producers_[1];
                write_at(ram, retained_address - 0x40000000 + 240, changed_identity.data(),
                         sizeof(changed_identity));
                write_private_json(proof_path, proof);
                session.poll_qnx();
                assert(session.graphics_.size() == 8 && session.graphics_[1].alive());
                changed_identity[1] = 100;
                write_at(ram, retained_address - 0x40000000 + 240, changed_identity.data(),
                         sizeof(changed_identity));

                for (std::size_t i = 1; i <= 3; ++i) {
                    write_private_json(root / ("owner-death-" +
                                               std::to_string(session.graphics_owners_[i].nonce) +
                                               ".json"),
                                       death(i));
                }

                session.poll_qnx();
                assert(session.graphics_.size() == 5 && session.qnx_.alive());
                const auto old_challenge = proof.at("challenge");
                assert(session.graphics_owner_challenge_ != old_challenge);
                write_private_json(proof_path, proof);
                session.poll_qnx();
                assert(session.graphics_.size() == 5); // Replayed retired tuple is inert.
                std::array<std::uint32_t, 2> unchanged{};
                read_at(ram, retained_address - 0x40000000, unchanged.data(), sizeof(unchanged));
                assert(unchanged == identity);

                for (unsigned i = 0; i < 3; ++i) {
                    const auto address = page + 0x20000 + static_cast<std::uint64_t>(i) * 4096;
                    const std::array<std::uint64_t, 2> next{900 + i, 300 + i};
                    write_at(ram, address - 0x40000000, identity.data(), sizeof(identity));
                    write_at(ram, address - 0x40000000 + 240, next.data(), sizeof(next));
                    std::ofstream serial(root / "qnx-serial.log", std::ios::app);
                    serial << "QG3 READY paddr=0x" << std::hex << address
                           << " length=4096 pid=" << std::dec << 900 + i << " incarnation=0x"
                           << std::hex << 300 + i << "\n";
                }

                const auto rebound = std::chrono::steady_clock::now() + event_wait;

                while (session.graphics_.size() < 8 && std::chrono::steady_clock::now() < rebound) {
                    session.poll_qnx();
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }

                assert(session.graphics_.size() == 8 && session.qnx_.alive());
                session.graphics_[0].terminate(1000);

                if (passion) {
                    session.graphics_[0] = ChildProcess::launch(failed);
                    write_private_json(root / "worker-disposition-42.json",
                                       {{"schema", 1},
                                        {"reason", "rpc_channel_invalidated"},
                                        {"producer_address", page + 4096},
                                        {"worker_pid", session.graphics_[0].pid()},
                                        {"generation", 2},
                                        {"nonce", 42},
                                        {"session_id", session.session_id_},
                                        {"guest_pid", 0},
                                        {"producer_incarnation", 0}});

                    while (session.graphics_[0].alive()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                }

                session.poll_qnx();
                assert(!session.qnx_.alive() &&
                       session.deliveries_["qnx"]["status"] == "graphics_worker_exited");
                session.stop();
            }
            std::filesystem::remove_all(root);
        }

        std::cout
                << "Passion/Free Session UART READY, exact Free projection guard and graphics RAM argv GREEN\n";
    }

    static void run(const std::filesystem::path &executable) {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-persistent-stop-" + random_token());
        const auto id = random_token();
        const auto directory = root / ".local/machines/test-profile/sessions" / id;
        ensure_private_directory(directory);
        const auto socket = native_socket_root() / (id + "-qmp.sock"), log = directory / "qmp.log",
                   ram = directory / "qnx-ram.bin";
        const auto system = root / "system.img", userdata = root / "userdata.img";

        for (const auto &entry :
             {std::pair{system, 1025ULL << 20}, std::pair{userdata, 32ULL << 20},
              std::pair{ram, 0x200000000ULL}}) {
            create_private_extent(entry.first, entry.second);
        }

        os::HeldFile mapped;
        assert(mapped.open(ram, true) == os::HeldFile::Opening::opened &&
               mapped.map(0, 8192) == os::HeldFile::Mapping::mapped);
        auto *w = reinterpret_cast<std::uint32_t *>(static_cast<unsigned char *>(mapped.view()) +
                                                    4096);
        w[0] = 0x54454e51;
        w[1] = 1;
        std::array<std::uint32_t, 8> ring{0xbeefeeee, 16352};
        const std::string marker = "QNET READY pid=42 paddr=0x40001000 length=4096 version=1\n";
        ring[2] = marker.size();
        write_at(ram, 0x10010000, ring.data(), 32);
        write_at(ram, 0x10010020, marker.data(), marker.size());
        auto wait = [&](const std::function<bool()> &condition) {
            const auto until = std::chrono::steady_clock::now() + event_wait;

            while (!condition() && std::chrono::steady_clock::now() < until) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            assert(condition());
        };
        {
            Session session(directory, id);
            Json spec{
                    {"persistent_storage",
                     {{"schema", 1}, {"system", system.string()}, {"userdata", userdata.string()}}},
                    {"qmp", socket.string()},
                    {"ram", ram.string()},
                    {"qemu",
                     {{"args", qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                         userdata.string())
                                       .options}}}};
            session.cluster_spec_ = spec;
            session.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            session.interguest_link_ = std::make_unique<InterguestLink>();
            session.interguest_link_->start(directory, id);
            session.interguest_link_->bind_ram(ram);
            wait([&] {
                return session.interguest_link_->status().ready;
            });
            const auto epoch = session.interguest_link_->status().utc_expected;
            w[15] = epoch;
            __atomic_store_n(&w[13], 1, __ATOMIC_RELEASE);
            wait([&] {
                return session.interguest_link_->status().utc_complete;
            });
            ProcessSpec process;
            process.executable = executable;
            process.arguments = {"--qnx-persistence-qmp-fixture", socket.string(), log.string()};
            process.output = directory / "fixture.log";
            session.qnx_ = ChildProcess::launch(process);
            wait([&] {
                return std::filesystem::exists(log.string() + ".ready");
            });
            session.cluster_requested_ = true;
            // Only the synthetic process/mailbox are owned here; no VM cleanup obligation.
            session.cluster_finalized_ = true;
            // Reject an unsafe private parent before connecting, without weakening global IPC.
            session.cluster_spec_["qmp"] = (directory / "qmp.sock").string();
            std::filesystem::permissions(directory, std::filesystem::perms::owner_all |
                                                            std::filesystem::perms::group_all);
            bool unsafe = false;
            try {
                session.set_qnx_persistence_paused(true);
            } catch (const std::exception &error) {
                unsafe = std::string(error.what()).find("private owned QMP directory") !=
                         std::string::npos;
            }

            assert(unsafe && session.qnx_.alive() && !std::filesystem::exists(log));
            std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
            session.cluster_spec_["qmp"] = socket.string();
            // The connected owner replaces its pathname before greeting: reject the changed inode
            // before commands.
            auto original = std::move(session.qnx_);
            std::filesystem::rename(socket, socket.string() + ".original");
            auto swapping = process;
            swapping.arguments = {"--qnx-persistence-qmp-fixture", socket.string(),
                                  (directory / "swap.log").string()};
            swapping.output = directory / "swap-fixture.log";
            session.qnx_ = ChildProcess::launch(swapping);
            wait([&] {
                return std::filesystem::exists(directory / "swap.log.ready");
            });
            bool changed = false;
            try {
                session.set_qnx_persistence_paused(true);
            } catch (const std::exception &error) {
                changed = std::string(error.what()).find("QMP pathname identity changed") !=
                          std::string::npos;
            }

            assert(changed && session.qnx_.alive() && original.alive() &&
                   !std::filesystem::exists(directory / "swap.log"));
            session.qnx_.terminate(1000);
            std::filesystem::remove(socket);
            std::filesystem::remove(socket.string() + ".retained");
            std::filesystem::rename(socket.string() + ".original", socket);
            session.qnx_ = std::move(original);
            auto acknowledge = [&](unsigned sequence, int status) {
                return std::thread([&, sequence, status] {
                    wait([&] {
                        return __atomic_load_n(&w[784], __ATOMIC_ACQUIRE) == sequence;
                    });
                    w[786] = static_cast<std::uint32_t>(status);
                    __atomic_store_n(&w[785], sequence, __ATOMIC_RELEASE);
                });
            };
            // The expected pathname is insufficient: an unrelated live QMP peer is rejected.
            auto foreign = std::move(session.qnx_);
            ProcessSpec decoy;
            decoy.executable = "/bin/sleep";
            decoy.arguments = {"60"};
            decoy.output = directory / "decoy.log";
            session.qnx_ = ChildProcess::launch(decoy);
            auto mismatch = acknowledge(1, 0);
            rejects([&] {
                session.stop();
            });
            mismatch.join();
            assert(session.qnx_.alive() && foreign.alive() && !std::filesystem::exists(log) &&
                   w[6] == 0);
            session.qnx_.terminate(1000);
            session.qnx_ = std::move(foreign);
            auto failed = acknowledge(2, -2);
            // Stop already closed test services and the guest may have remounted: not not_started.
            const auto failure = rejection([&] {
                session.stop();
            });
            assert(failure.starts_with("SESSION_STOP_UNKNOWN: INTERGUEST_FLUSH_UNKNOWN:"));
            failed.join();
            assert(session.qnx_.alive() && !session.stopped() && !std::filesystem::exists(log) &&
                   w[6] == 0);
            // A replaced disk fails only after QMP pause and keeps the retained child alive.
            std::filesystem::rename(userdata, root / "retained-userdata");
            {
                std::ofstream replacement(userdata);
                replacement << "foreign replacement";
            }
            auto paused = acknowledge(3, 0);
            rejects([&] {
                session.stop();
            });
            paused.join();
            assert(session.qnx_.alive() && session.qnx_persistence_paused_ && !session.stopped() &&
                   w[6] == 0);
            assert(session.deliveries_["qnx"]["persistence"]["status"] ==
                   "flush_failed_runtime_retained_paused");
            std::filesystem::remove(userdata);
            std::filesystem::rename(root / "retained-userdata", userdata);
            // Exercise an actual fsync syscall failure after quiescence/pause, then restore the
            // retained capability.
            with_failing_disk_flushes(
                    session.qnx_persistent_storage_->disks_[0].native_handle(), [&] {
                        auto io_failed = acknowledge(4, 0);
                        rejects([&] {
                            session.stop();
                        });
                        io_failed.join();
                        assert(session.qnx_.alive() && session.qnx_persistence_paused_ &&
                               !session.stopped() && std::filesystem::exists(system) &&
                               std::filesystem::exists(userdata));
                        assert(session.deliveries_["qnx"]["persistence"]["error"]
                                       .get<std::string>()
                                       .find("durable disk flush failed") != std::string::npos);
                    });
            auto retry = acknowledge(5, 0);
            session.stop();
            retry.join();
            assert(!session.qnx_.alive() && session.stopped() && w[784] == 5 && w[785] == 5);
            std::ifstream input(log);
            const std::string commands{std::istreambuf_iterator<char>(input), {}};
            assert(commands ==
                   "qmp_capabilities\nstop\nquery-status\nqmp_capabilities\ncont\nquery-status\nqmp_capabilities\nstop\nquery-status\nqmp_capabilities\ncont\nquery-status\nqmp_capabilities\nstop\nquery-status\n");
        }
        {
            Session terminal(directory, id);
            Json spec{{"persistent_storage",
                       {{"schema", 1},
                        {"system", system.string()},
                        {"userdata", userdata.string()}}}};
            spec["qemu"]["args"] = qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                             userdata.string())
                                           .options;
            terminal.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            terminal.cluster_requested_ = true;
            terminal.cluster_finalized_ = false;
            terminal.cluster_generation_ = 1;
            terminal.cluster_spec_ = {{"qmp", socket.string()}, {"ram", ram.string()}};
            ProcessSpec process;
            process.executable = "/bin/sh";
            process.arguments = {
                    "-c",
                    R"(printf guest-data | dd of="$1" bs=1 seek=4096 conv=notrunc 2>/dev/null; exit 0)",
                    "fixture", userdata.string()};
            process.output = directory / "terminal-fixture.log";
            terminal.qnx_ = ChildProcess::launch(process);
            wait([&] {
                return !terminal.qnx_.alive();
            });
            assert(terminal.qnx_.exit_code() == 0);
            auto owner = read_private_json(directory / "session-owner.json");
            owner["qnx_pid"] = terminal.qnx_.pid();
            owner["ram_absent_before_owned_qemu"] = true;
            write_private_json(directory / "session-owner.json", owner);
            // A clean owned exit still cannot authorize a replaced disk or failed durable flush.
            std::filesystem::rename(userdata, root / "retained-userdata");
            {
                std::ofstream replacement(userdata);
                replacement << "foreign replacement";
            }
            rejects([&] {
                terminal.close_cluster(false, "restart");
            });
            assert(terminal.cluster_requested_ && std::filesystem::exists(ram));
            std::filesystem::remove(userdata);
            std::filesystem::rename(root / "retained-userdata", userdata);
            with_failing_disk_flushes(
                    terminal.qnx_persistent_storage_->disks_[0].native_handle(), [&] {
                        rejects([&] {
                            terminal.close_cluster(false, "restart");
                        });
                        assert(terminal.cluster_requested_ && std::filesystem::exists(ram));
                    });
            terminal.close_cluster(false, "restart");
            assert(!terminal.cluster_requested_ && !terminal.qnx_.alive() &&
                   terminal.cluster_finalized_ && !std::filesystem::exists(ram));
            const auto receipt = terminal.deliveries_["qnx"]["persistence"];
            assert(receipt["status"] == "owned_qemu_exited_host_flushed" &&
                   receipt["guest_sync_acknowledged"] == false && receipt["qemu_exit_code"] == 0);
            std::ifstream persisted(userdata, std::ios::binary);
            persisted.seekg(4096);
            char data[10]{};
            persisted.read(data, 10);
            assert(std::string(data, 10) == "guest-data");
            // Exercise the actual fresh-generation attach after durable flush and RAM cleanup.
            spec["schema"] = 1;
            // Pins name a regular file; /bin/sh is a symlink on some Linux hosts.
            const auto shell = std::filesystem::canonical("/bin/sh").string();
            spec["pins"] = Json::array({{{"path", shell}, {"sha256", sha256_file(shell)}}});
            spec["ram"] = ram.string();
            spec["qmp"] = socket.string();
            spec["interguest_network"] = {{"schema", 1},
                                          {"transport", "tap-ram-v1"},
                                          {"address", "172.16.100.22"},
                                          {"peer_address", "172.16.100.21"},
                                          {"prefix", 24},
                                          {"qconn_port", 8000}};
            auto args = std::vector<std::string>{
                    "-c", R"(dd if="$1" of="$2" bs=1 skip=4096 count=10 2>/dev/null)", "fixture",
                    userdata.string(), (directory / "reboot-readback").string()};
            const auto mappings = qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                            userdata.string())
                                          .options;
            args.insert(args.end(), mappings.begin(), mappings.end());
            spec["qemu"]["executable"] = shell;
            spec["qemu"]["args"] = args;
            const auto ignition = [&] {
                return terminal.model_.state().at("raw_oem").at("ign").get<unsigned>();
            };
            assert(ignition() == 1);
            const auto started_state = terminal.model_.state();
            terminal.attach_cluster(spec, std::nullopt, true);
            assert(terminal.cluster_generation_ == 2 && std::filesystem::exists(ram));
            assert(terminal.model_.state() == started_state);
            wait([&] {
                return !terminal.qnx_.alive();
            });
            assert(terminal.qnx_.exit_code() == 0);
            std::ifstream rebooted(directory / "reboot-readback", std::ios::binary);
            const std::string readback{std::istreambuf_iterator<char>(rebooted), {}};
            assert(readback == "guest-data");
            terminal.close_cluster(false, "qemu_exit");
            assert(terminal.cluster_finalized_ && !std::filesystem::exists(ram));
            assert(terminal.model_.state() == started_state);
            terminal.attach_cluster(spec, std::nullopt, true);
            assert(terminal.cluster_generation_ == 3 && terminal.model_.state() == started_state);
            wait([&] {
                return !terminal.qnx_.alive();
            });
            terminal.close_cluster(false, "qemu_exit");
            assert(terminal.cluster_finalized_ && !std::filesystem::exists(ram) && ignition() == 1);
            terminal.stop();
        }
        {
            const auto abnormal_id = random_token();
            const auto abnormal_directory = root / ".local/machines/test-profile/sessions" /
                                            abnormal_id;
            ensure_private_directory(abnormal_directory);
            const auto abnormal_ram = abnormal_directory / "qnx-ram.bin";
            create_private_extent(abnormal_ram, 0x200000000ULL);
            Session abnormal(abnormal_directory, abnormal_id);
            Json spec{{"persistent_storage",
                       {{"schema", 1},
                        {"system", system.string()},
                        {"userdata", userdata.string()}}}};
            spec["qemu"]["args"] = qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                             userdata.string())
                                           .options;
            abnormal.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            abnormal.cluster_requested_ = true;
            abnormal.cluster_finalized_ = true;
            rejects([&] {
                abnormal.close_cluster(false, "restart");
            });
            assert(abnormal.cluster_requested_ && std::filesystem::exists(abnormal_ram));
            ProcessSpec process;
            process.executable = "/bin/sh";
            process.arguments = {"-c", "exit 7"};
            process.output = abnormal_directory / "abnormal-fixture.log";
            abnormal.qnx_ = ChildProcess::launch(process);
            wait([&] {
                return !abnormal.qnx_.alive();
            });
            rejects([&] {
                abnormal.close_cluster(false, "restart");
            });
            assert(abnormal.qnx_.exit_code() == 7 && abnormal.cluster_requested_ &&
                   std::filesystem::exists(abnormal_ram));
            abnormal.cluster_requested_ = false;
            abnormal.stop();
        }
        mapped.unmap();
        mapped.close();
        std::filesystem::remove(socket);
        std::filesystem::remove_all(root);
    }

    static void spontaneous_android_exit_closes_frontend() {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("session-spontaneous-exit-" + random_token());
        const auto machine = root / "machine", source = machine / "config-template.ini";
        ensure_private_directory(machine / "base");
        { std::ofstream(source) << "hw.display1.flag=0\n"; }

        for (const char *name :
             {"userdata-qemu.img", "cache.img", "encryptionkey.img", "userdata-qemu.img.qcow2",
              "cache.img.qcow2", "encryptionkey.img.qcow2", "system.img.qcow2", "vendor.img.qcow2",
              "base/system.img", "base/vendor.img"}) {
            std::ofstream(machine / name) << "fixture";
        }

        const auto id = random_token();
        const auto directory = root / id, home = directory / "emulator-home";
        {
            Session session(directory, id);
            prepare_android_avd(home, machine, "test", source, sha256_file(source));
            unsigned port = 45000;

            for (; port < 45100; port += 2) {
                if (tcp_port_free(port) && tcp_port_free(port + 1)) {
                    break;
                }
            }

            assert(port < 45100);
            session.android_spec_ = {
                    {"port", port}, {"machine", machine.string()}, {"avd_name", "test"}};
            session.android_home_ = home;
            session.android_powered_ = true;
            session.android_seen_guest_ = true;
            ProcessSpec frontend;
            frontend.executable = "/bin/sleep";
            frontend.arguments = {"30"};
            frontend.directory = directory;
            frontend.output = directory / "native-window.log";
            session.frontend_ = ChildProcess::launch(frontend);
            session.deliveries_["frontend"] = {{"status", "started"}};
            session.tick();
            const auto terminal = read_private_json(directory / "runtime.json");
            const bool closed = !session.frontend_.alive() && terminal.value("stopped", false) &&
                                terminal.at("deliveries").at("frontend").at("status") == "stopped";
            session.frontend_.terminate(1000);
            session.android_spec_.clear();
            session.android_powered_ = false;
            assert(closed);
        }
        std::filesystem::remove_all(root);
    }

    static void unbounded_restart_preflight() {
        const auto project = std::filesystem::path(__FILE__)
                                     .parent_path()
                                     .parent_path()
                                     .parent_path()
                                     .parent_path();
        const auto root = project / ".local/build/jobs" /
                          ("test-unbounded-restart-" + random_token());
        const auto id = random_token(), owner = random_token(), action = random_token();
        const auto directory = root / ".local/machines/test-profile/sessions" / id;
        {
            Session session(directory, id);
            write_private_json(directory / "automation-owner.json",
                               {{"schema", 1}, {"session_id", id}, {"ownership_id", owner}});
            ProcessSpec child;
            child.executable = "/bin/sleep";
            child.arguments = {"30"};
            child.output = directory / "fixture.log";
            session.android_ = ChildProcess::launch(child);
            session.qnx_ = ChildProcess::launch(child);
            session.android_spec_ = {{"schema", 1}};
            session.android_powered_ = true;
            session.cluster_spec_ = {{"interguest_network", Json::object()}};
            session.cluster_requested_ = true;
            session.cluster_finalized_ = true;
            session.cluster_generation_ = 1;
            session.interguest_link_ = std::make_unique<InterguestLink>();
            const auto reply =
                    session.handle({{"op", "machine_restart"},
                                    {"session_id", id},
                                    {"ownership_id", owner},
                                    {"operation_id", action},
                                    {"timeout_ms", 1000},
                                    {"expected_boot",
                                     {{"android", "11111111-1111-4111-8111-111111111111"},
                                      {"qnx_generation", "1"},
                                      {"qnx_pid", session.qnx_.pid()}}}});
            const auto stale = session.handle({{"op", "cluster_restart"},
                                               {"session_id", id},
                                               {"ownership_id", owner},
                                               {"expected_generation", 0u}});
            const bool untouched =
                    session.android_.alive() && session.qnx_.alive() &&
                    !std::filesystem::exists(directory / ("full-restart-" + action + ".json"));
            session.android_spec_.clear();
            session.android_powered_ = false;
            session.stop();
            assert(reply.at("ok") == false &&
                   reply.at("error") ==
                           "SESSION_RESTART_UNAVAILABLE: current QNX guest acknowledgement is not established");
            assert(stale.at("ok") == false &&
                   stale.at("error") == "TEST_GENERATION: stale QNX generation" && untouched);
        }
        std::filesystem::remove_all(root);
    }

    // A bounded cluster whose guest never reached the relay holds no unflushed guest state.
    // close_cluster must pause the owned QEMU, flush the host mappings and terminate it instead
    // of retaining; a relay fault or a startup marker is guest evidence and must still retain.
    static void never_attached_close_run(const std::filesystem::path &executable) {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-never-attached-" + random_token());
        ensure_private_directory(root);
        const auto id = random_token();
        const auto directory = root / ".local/machines/test-profile/sessions" / id;
        ensure_private_directory(directory);
        const auto socket = native_socket_root() / (id + "-qmp.sock"), log = directory / "qmp.log",
                   ram = directory / "qnx-ram.bin", system = root / "system.img",
                   userdata = root / "userdata.img";

        for (const auto &entry :
             {std::pair{system, 1025ULL << 20}, std::pair{userdata, 32ULL << 20}}) {
            create_private_extent(entry.first, entry.second);
        }

        const auto spec_for = [&] {
            return Json{
                    {"persistent_storage",
                     {{"schema", 1}, {"system", system.string()}, {"userdata", userdata.string()}}},
                    {"qmp", socket.string()},
                    {"ram", ram.string()},
                    {"qemu",
                     {{"args", qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                         userdata.string())
                                       .options}}}};
        };
        auto wait = [&](const std::function<bool()> &condition) {
            const auto until = std::chrono::steady_clock::now() + event_wait;

            while (!condition() && std::chrono::steady_clock::now() < until) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            assert(condition());
        };
        auto launch_qmp = [&](Session &session) {
            ProcessSpec fixture;
            fixture.executable = executable;
            fixture.arguments = {"--qnx-persistence-qmp-fixture", socket.string(), log.string()};
            fixture.output = directory / "fixture.log";
            session.qnx_ = ChildProcess::launch(fixture);
            wait([&] {
                return std::filesystem::exists(log.string() + ".ready");
            });
            std::filesystem::remove(log);
        };
        auto launch_sleep = [&](Session &session, const char *name) {
            ProcessSpec child;
            child.executable = "/bin/sleep";
            child.arguments = {"30"};
            child.output = directory / name;
            session.qnx_ = ChildProcess::launch(child);
        };
        {
            // Positive proof of no guest state: relay not ready, fault empty, no startup markers.
            Session session(directory, id);
            const auto spec = spec_for();
            session.cluster_spec_ = spec;
            session.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            session.interguest_link_ = std::make_unique<InterguestLink>();
            session.cluster_requested_ = true;
            session.cluster_seconds_ = 30;
            session.cluster_finalized_ = true;
            launch_qmp(session);
            const auto relay = session.interguest_link_->status();
            assert(!relay.ready && relay.fault.empty() && session.startup_markers_.empty() &&
                   session.qnx_.alive());
            session.stop();
            assert(!session.qnx_.alive() && session.stopped());
            assert(session.deliveries_["qnx"]["persistence"]["status"] ==
                   "guest_never_attached_qemu_paused_host_flushed");
            std::ifstream input(log);
            const std::string commands{std::istreambuf_iterator<char>(input), {}};
            assert(commands == "qmp_capabilities\nstop\nquery-status\n");
        }
        {
            // A relay fault is guest-adjacent evidence: retain the owned QEMU exactly as before.
            Session session(directory, id);
            const auto spec = spec_for();
            session.cluster_spec_ = spec;
            session.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            session.interguest_link_ = std::make_unique<InterguestLink>();
            session.interguest_link_->start(directory, id);
            {
                create_private_extent(ram, 0x200000000ULL);
                const std::array<std::uint32_t, 2> bad{0xbeefeeee, 1};
                write_at(ram, 0x10010000, bad.data(), sizeof bad);
            }
            session.interguest_link_->bind_ram(ram);
            wait([&] {
                return !session.interguest_link_->status().fault.empty();
            });
            session.cluster_requested_ = true;
            session.cluster_seconds_ = 30;
            session.cluster_finalized_ = true;
            launch_sleep(session, "retained-fault.log");
            assert(rejection([&] {
                       session.stop();
                   }).starts_with("SESSION_STOP_UNKNOWN: INTERGUEST_FLUSH:"));
            assert(session.qnx_.alive() && !session.stopped() &&
                   session.deliveries_["qnx"]["persistence"]["status"] ==
                           "flush_failed_runtime_retained");
            session.cluster_requested_ = false;
            session.stop();
            assert(!session.qnx_.alive() && session.stopped());
        }
        {
            // A recorded startup marker is evidence of guest execution: retain as before.
            Session session(directory, id);
            const auto spec = spec_for();
            session.cluster_spec_ = spec;
            session.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            session.interguest_link_ = std::make_unique<InterguestLink>();
            session.startup_markers_.insert("QIP 1");
            session.cluster_requested_ = true;
            session.cluster_seconds_ = 30;
            session.cluster_finalized_ = true;
            launch_sleep(session, "retained-marker.log");
            rejects([&] {
                session.stop();
            });
            assert(session.qnx_.alive() && !session.stopped() &&
                   session.deliveries_["qnx"]["persistence"]["status"] ==
                           "flush_failed_runtime_retained");
            session.cluster_requested_ = false;
            session.stop();
            assert(!session.qnx_.alive() && session.stopped());
        }
        std::filesystem::remove(socket);
        std::filesystem::remove_all(root);
        std::cout
                << "QNX never-attached close pauses, flushes host and terminates; relay fault and startup markers retain\n";
    }

    // Source acceptance images are disposable: after a failed guest sync or a lapsed budget,
    // discard ends the owned QEMU and graphics children and removes the owned RAM. A session of
    // other images keeps the retained runtime of a failed stop, and no foreign process is touched.
    static void acceptance_discard_run() {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-acceptance-discard-" + random_token());
        ensure_private_directory(root);
        const auto system = root / "system.img", userdata = root / "userdata.img";

        for (const auto &entry :
             {std::pair{system, 1025ULL << 20}, std::pair{userdata, 32ULL << 20}}) {
            create_private_extent(entry.first, entry.second);
        }

        ProcessSpec sleeper;
        sleeper.executable = "/bin/sleep";
        sleeper.arguments = {"60"};
        sleeper.output = root / "foreign.log";
        auto foreign = ChildProcess::launch(sleeper);
        const auto scenario = [&](bool acceptance, bool stop_first) {
            const auto id = random_token();
            const auto directory = root / ".local/machines/test-profile/sessions" / id;
            ensure_private_directory(directory);
            const auto ram = directory / "qnx-ram.bin";
            create_private_extent(ram, 0x200000000ULL);
            Session session(directory, id);
            Json spec{
                    {"persistent_storage",
                     {{"schema", 1}, {"system", system.string()}, {"userdata", userdata.string()}}},
                    {"qmp", (directory / "qmp.sock").string()},
                    {"ram", ram.string()},
                    {"qemu",
                     {{"args", qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                         userdata.string())
                                       .options}}}};

            if (acceptance) {
                spec["source_acceptance"] = true;
            }

            session.cluster_spec_ = spec;
            session.qnx_persistent_storage_ = std::make_unique<QnxPersistentStorage>(spec);
            // The guest ran, and the relay that would carry its sync is gone.
            session.interguest_link_ = std::make_unique<InterguestLink>();
            session.startup_markers_.insert("QMC BEGIN raw-OEM-QNX6-readonly");
            sleeper.output = directory / "children.log";
            session.qnx_ = ChildProcess::launch(sleeper);

            for (std::uint64_t producer : {0x9c93d000ULL, 0x9cfd2000ULL}) {
                session.graphics_.push_back(ChildProcess::launch(sleeper));
                session.producers_.push_back(producer);
            }

            const std::vector<std::int64_t> children{session.qnx_.pid(), session.graphics_[0].pid(),
                                                     session.graphics_[1].pid()};
            auto owner = read_private_json(directory / "session-owner.json");
            owner["qnx_pid"] = session.qnx_.pid();
            owner["ram_absent_before_owned_qemu"] = true;
            write_private_json(directory / "session-owner.json", owner);
            session.cluster_requested_ = true;
            session.cluster_finalized_ = false;
            session.cluster_generation_ = 1;

            if (stop_first) {
                assert(rejection([&] {
                           session.stop();
                       }).starts_with("SESSION_STOP_UNKNOWN: INTERGUEST_FLUSH"));
                assert(session.qnx_.alive() && session.graphics_.size() == 2 &&
                       session.graphics_[0].alive() && session.graphics_[1].alive() &&
                       std::filesystem::exists(ram) && !session.stopped());
            }

            if (!acceptance) {
                assert(rejection([&] {
                           session.discard();
                       }).starts_with("SESSION_DISCARD:"));
                assert(session.qnx_.alive() && session.graphics_[0].alive() &&
                       session.graphics_[1].alive() && std::filesystem::exists(ram) &&
                       !session.stopped());
                session.cluster_requested_ = false;
                session.cluster_finalized_ = true;
                session.qnx_.terminate(1000);

                for (auto &process : session.graphics_) {
                    process.terminate(1000);
                }

                session.stop();
                std::filesystem::remove(ram);

                return;
            }

            session.discard();
            assert(session.stopped() && !session.qnx_.alive() && session.graphics_.empty() &&
                   !std::filesystem::exists(ram));

            for (const auto pid : children) {
                assert(process_gone(pid));
            }

            const auto qnx = session.deliveries_["qnx"];
            assert(qnx["persistence"]["status"] == "disposable_images_discarded" &&
                   qnx["persistence"]["guest_sync_acknowledged"] == false &&
                   qnx["cleanup"]["status"] == "removed_after_handoff" &&
                   qnx["cleanup"]["ram_removed"] == true);
        };
        // An unknown stop inside acceptance, then the budget lapsing without any stop.
        scenario(true, true);
        scenario(true, false);
        // Other images keep the retained runtime of a failed stop and refuse a discard.
        scenario(false, true);
        assert(foreign.alive() && std::filesystem::exists(system) &&
               std::filesystem::exists(userdata));
        foreign.terminate(1000);
        std::filesystem::remove_all(root);
        std::cout << "QNX source acceptance discard ends owned QEMU and graphics, removes RAM\n";
    }

    static void reboot_run(const std::filesystem::path &executable) {
        // The long macOS TMPDIR leaves no room for the Unix socket paths of the fixture.
        const auto temp = os::platform_name == "macOS" ? std::filesystem::path("/tmp")
                                                       : std::filesystem::temp_directory_path();
        const auto root = std::filesystem::canonical(temp) /
                          ("qnx-auto-" + random_token().substr(0, 12));
        ensure_private_directory(root);
        const auto executable_sha = sha256_file(executable);
        const auto read = [](const std::filesystem::path &path) {
            std::ifstream in(path, std::ios::binary);

            return std::string(std::istreambuf_iterator<char>(in), {});
        };
        auto make_disk = [&](const std::filesystem::path &path, std::uint64_t bytes) {
            assert(os::create_private_file(path));
            os::resize_file(path, bytes);
        };
        auto disk_identity = [&](const std::filesystem::path &path) {
            const auto object = os::PositionalFile(path, false).object();
            assert(object);

            return std::pair<std::uint64_t, std::uint64_t>{object->volume, object->index};
        };
        std::vector<std::string> names{
                "positive", "repeat",       "guest-shutdown", "host-signal",
                "none",     "exit7",        "disk-failure",   "cleanup-failure",
                "expired",  "explicit-off", "explicit-stop"};

        // POSIX fd replacement only; no Windows analogue here.
        if (!os::host_windows) {
            names.insert(names.begin() + 7, "fsync-failure");
        }

        for (const auto &name : names) {
            const std::string test = name;
            const auto project = root / test;
            const auto id = random_token();
            const auto directory = project / ".local/machines/test-profile/sessions" / id;
            const auto state = project / "state", system = project / "system",
                       userdata = project / "userdata", ram = directory / "qnx-ram.bin";
            ensure_private_directory(state);

            for (const auto &disk :
                 {std::pair{system, 1025ULL << 20}, std::pair{userdata, 32ULL << 20}}) {
                make_disk(disk.first, disk.second);
            }

            const auto disk_before = disk_identity(userdata);
            std::string scenario = "guest-reset";

            if (test == "positive") {
                scenario = "fragmented";
            } else if (test == "repeat" || test == "guest-shutdown" || test == "host-signal" ||
                       test == "none" || test == "exit7") {
                scenario = test;
            }

            {
                Session session(directory, id);
                std::filesystem::path primary;
                std::string primary_argument, qmp_argument;
                Json qmp_endpoint;

                // Windows serves QMP on loopback TCP, POSIX on a Unix socket.
                if (os::host_windows) {
                    const unsigned primary_port = reserve_loopback_port();
                    primary_argument = std::to_string(primary_port);
                    qmp_argument = "tcp:127.0.0.1:" + std::to_string(primary_port) +
                                   ",server=on,wait=off";
                    qmp_endpoint = {{"host", "127.0.0.1"}, {"port", primary_port}};
                } else {
                    primary = native_socket_root() / (id + "-qmp.sock");
                    primary_argument = primary.string();
                    qmp_argument = "unix:" + primary.string() + ",server=on,wait=off";
                    qmp_endpoint = primary.string();
                }

                auto args = std::vector<std::string>{"--qnx-shutdown-fixture",
                                                     scenario,
                                                     state.string(),
                                                     primary_argument,
                                                     userdata.string(),
                                                     "auto",
                                                     ram.string(),
                                                     "-no-reboot",
                                                     "-S",
                                                     "-qmp",
                                                     qmp_argument};
                const auto mapping = qnx_persistent_ram_launch(host_qnx_engine, system.string(),
                                                               userdata.string(), os::host_windows)
                                             .options;
                args.insert(args.end(), mapping.begin(), mapping.end());
                Json spec{{"schema", 1},
                          {"pins", Json::array({{{"path", executable.string()},
                                                 {"sha256", executable_sha}}})},
                          {"ram", ram.string()},
                          {"qmp", qmp_endpoint},
                          {"guest_arch", "aarch64"},
                          {"persistent_storage",
                           {{"schema", 1},
                            {"system", system.string()},
                            {"userdata", userdata.string()}}},
                          {"interguest_network", qnx_interguest_contract()},
                          {"qemu", {{"executable", executable.string()}, {"args", args}}}};

                // The TCG engine of Windows maps RAM through its verified file backend.
                if (os::host_windows) {
                    spec["qnx_file_backend"] = {{"schema", 1},
                                                {"version", "11.1.2"},
                                                {"engine_sha256", executable_sha}};
                }

                session.attach_cluster(spec, 30);
                const auto original_deadline = session.qnx_deadline_;
                const auto until = [&](const auto &predicate) {
                    const auto deadline = std::chrono::steady_clock::now() + event_wait;
                    std::string first, last;

                    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
                        try {
                            if (session.cluster_requested_) {
                                session.poll_qnx();
                            }
                        } catch (const std::exception &error) {
                            last = error.what();

                            if (first.empty()) {
                                first = last;
                            }
                        }

                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }

                    if (!predicate()) {
                        throw std::runtime_error(
                                "automatic reboot fixture " + test + ": " + last +
                                "; first poll error: " + first + "; QEMU exit " +
                                std::to_string(session.qnx_.exit_code()) +
                                "; console: " + read(directory / "qnx-console.log"));
                    }
                };
                until([&] {
                    return session.qmp_cont_ && session.interguest_link_->status().utc_complete;
                });
                const auto first_port = session.interguest_link_->status().port;
                const auto first_link_generation = session.interguest_link_->status().generation;
                assert(first_port && session.qnx_shutdown_monitor_ &&
                       session.qnx_shutdown_monitor_->evidence()["subscribed"] == true);
                {
                    std::ofstream release(state / "release-1");
                    release << "release";
                }
                const auto terminal_deadline = std::chrono::steady_clock::now() + event_wait;

                while (session.qnx_.alive() &&
                       std::chrono::steady_clock::now() < terminal_deadline) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }

                assert(!session.qnx_.alive());

                if (test == "exit7") {
                    rejects([&] {
                        session.poll_qnx();
                    });
                    assert(session.cluster_generation_ == 1 && session.cluster_requested_ &&
                           std::filesystem::exists(ram));
                    session.cluster_requested_ = false;
                    session.stop();
                } else if (test == "cleanup-failure") {
                    {
                        std::ofstream blocked(project / "plans");
                        blocked << "do not replace";
                    }
                    rejects([&] {
                        session.poll_qnx();
                    });
                    assert(session.cluster_generation_ == 1 && !session.cluster_requested_ &&
                           !session.cluster_finalized_ && std::filesystem::exists(ram));
                    session.stop();
                } else if (test == "expired") {
                    session.qnx_deadline_ = std::chrono::steady_clock::now() -
                                            std::chrono::seconds(1);
                    session.poll_qnx();
                    assert(session.cluster_generation_ == 1 && !session.cluster_requested_ &&
                           !std::filesystem::exists(ram));
                    session.stop();
                } else if (test == "explicit-off" || test == "explicit-stop") {
                    if (test == "explicit-off") {
                        const auto reply = session.handle(
                                {{"op", "cluster_power"}, {"enabled", false}, {"session_id", id}});
                        assert(reply["ok"] == true &&
                               reply["deliveries"]["qnx"]["status"] == "off");
                    } else {
                        session.stop();
                    }

                    assert(session.cluster_generation_ == 1 && !session.cluster_requested_ &&
                           !std::filesystem::exists(ram));
                    session.stop();
                } else if (test == "guest-shutdown" || test == "host-signal" || test == "none") {
                    session.poll_qnx();
                    assert(session.cluster_generation_ == 1 && !session.cluster_requested_ &&
                           !std::filesystem::exists(ram));
                    session.stop();
                } else {
                    if (test == "disk-failure") {
                        std::filesystem::rename(userdata, project / "retained-userdata");
                        {
                            std::ofstream replacement(userdata);
                            replacement << "foreign";
                        }
                        rejects([&] {
                            session.poll_qnx();
                        });
                        assert(session.cluster_generation_ == 1 && session.cluster_requested_ &&
                               std::filesystem::exists(ram) && read(state / "boots") == "1");
                        std::filesystem::remove(userdata);
                        std::filesystem::rename(project / "retained-userdata", userdata);
                    }

                    if (test == "fsync-failure") {
                        with_failing_disk_flushes(
                                session.qnx_persistent_storage_->disks_[0].native_handle(), [&] {
                                    rejects([&] {
                                        session.poll_qnx();
                                    });
                                    assert(session.cluster_generation_ == 1 &&
                                           session.cluster_requested_ &&
                                           std::filesystem::exists(ram) &&
                                           read(state / "boots") == "1");
                                });
                    }

                    until([&] {
                        return session.cluster_generation_ == 2 && session.qmp_cont_ &&
                               session.interguest_link_->status().utc_complete;
                    });
                    assert(session.qnx_deadline_ == original_deadline &&
                           read(state / "disk-readback-2") == "guest-data" &&
                           read(state / "fresh-ram-2") == "fresh");
                    const auto link = session.interguest_link_->status();

                    if (!(link.port == first_port && link.generation == first_link_generation + 2 &&
                          link.ready && link.fault.empty())) {
                        throw std::runtime_error("fixture link port " + std::to_string(link.port) +
                                                 " first " + std::to_string(first_port) +
                                                 " generation " + std::to_string(link.generation) +
                                                 " ready " + std::to_string(link.ready) +
                                                 " fault " + link.fault);
                    }

                    assert(session.deliveries_["qnx"]["reboot"]["shutdown"]["reason"] ==
                           "guest-reset");
                    assert(disk_identity(userdata) == disk_before);

                    if (test == "repeat") {
                        {
                            std::ofstream release(state / "release-2");
                            release << "release";
                        }
                        until([&] {
                            return session.cluster_generation_ == 3 && session.qmp_cont_ &&
                                   session.interguest_link_->status().utc_complete;
                        });
                        assert(session.qnx_deadline_ == original_deadline &&
                               read(state / "disk-readback-3") == "guest-data" &&
                               read(state / "fresh-ram-3") == "fresh");
                    }

                    const auto generation = session.cluster_generation_;
                    const auto off = session.handle(
                            {{"op", "cluster_power"}, {"enabled", false}, {"session_id", id}});
                    assert(off["ok"] == true && off["deliveries"]["qnx"]["status"] == "off" &&
                           session.cluster_generation_ == generation &&
                           !session.cluster_requested_ && !std::filesystem::exists(ram));
                    session.stop();
                }

                // Windows tears the TCP events listener down with the generation, POSIX removes
                // the Unix sockets.
                if (os::host_windows) {
                    assert(!session.qnx_shutdown_monitor_);
                } else {
                    assert(!std::filesystem::exists(native_socket_root() / (id + "-evt.sock")) &&
                           !std::filesystem::exists(primary));
                }
            }

            // Bound the per-scenario disk footprint on Windows.
            if (os::host_windows) {
                std::filesystem::remove_all(project);
            }
        }

        std::filesystem::remove_all(root);
        std::cout
                << "automatic QNX guest-reset generations, durable data/fresh RAM, network UTC, shutdown causes, explicit off/stop and persistence failure retention passed\n";
    }
};
} // namespace voyemu

static void qnx_ready_survives_blocked_android() {
    const auto root = std::filesystem::current_path() / ".local/build" /
                      ("qnx-ready-" + random_token());

    ensure_private_directory(root);
    const auto ram = root / "ram";
    {
        std::ofstream file(ram);
        file << 'x';
    }
    std::filesystem::resize_file(ram, 0x10000);
    constexpr std::uint64_t ring = 0x40001000, page = 0x40003000;
    auto write = [&](std::uint64_t address, const void *data, std::size_t bytes) {
        write_at(ram, address - 0x40000000, data, bytes);
    };
    auto publish = [&](const std::string &text) {
        std::array<char, 4096> bytes{};
        std::array<std::uint32_t, 3> header{0xbeefeeee, 4096 - 32, 0};
        std::memcpy(bytes.data(), header.data(), sizeof(header));
        assert(text.size() < 4096 - 32);
        std::memcpy(bytes.data() + 32, text.data(), text.size());
        write(ring, bytes.data(), bytes.size());
    };
    const std::array<std::uint32_t, 2> identity{0x58464751, 3};
    write(page, identity.data(), sizeof(identity));
    publish("QG3 READY paddr=0x40003000 length=4096\n");
    {
        QnxReadyCollector collector(ram, ring, 4096);
        const auto deadline = std::chrono::steady_clock::now() + event_wait;

        while (collector.addresses().empty() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        assert(collector.addresses() == std::vector<std::uint64_t>{page});
        // Reproduce the actual 5.793-second synchronous Android interval. During
        // it the guest overwrites every byte of the old one-shot advertisement.
        publish(std::string(4096 - 33, 'x'));
        std::this_thread::sleep_for(std::chrono::milliseconds(5800));
        std::array<char, 4096> latest{};
        read_at(ram, 0x1000, latest.data(), latest.size());
        assert(std::string_view(latest.data(), latest.size()).find("QG3 READY") ==
               std::string_view::npos); // Old polling loses it.
        assert(collector.addresses() == std::vector<std::uint64_t>{page});
        publish("QG3 READY paddr=0x40003000 length=4096\nQG3 READY paddr=0x40003000 length=4096\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        assert(collector.addresses().size() == 1);
        collector.stop();
    }
    // A new generation cannot inherit a page discovered in the old RAM file.
    std::filesystem::remove(ram);
    {
        std::ofstream file(ram);
        file << 'x';
    }
    std::filesystem::resize_file(ram, 0x10000);
    publish("new generation without READY");
    {
        QnxReadyCollector next(ram, ring, 4096);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        assert(next.addresses().empty());
    }
    publish("QG3 READY paddr=0x40003000 length=4096\n");
    {
        QnxReadyCollector invalid(ram, ring, 4096);
        bool rejected = false;
        const auto end = std::chrono::steady_clock::now() + event_wait;

        while (!rejected && std::chrono::steady_clock::now() < end) {
            try {
                assert(invalid.addresses().empty());
            } catch (const std::exception &error) {
                rejected = std::string(error.what()).find("page identity") != std::string::npos;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        assert(rejected);
    }
    std::string excessive;

    for (unsigned i = 0; i < 9; ++i) {
        const auto address = page + static_cast<std::uint64_t>(i) * 4096;
        write(address, identity.data(), sizeof(identity));
        std::ostringstream line;
        line << "QG3 READY paddr=0x" << std::hex << address << " length=4096\n";
        excessive += line.str();
    }

    publish(excessive);
    {
        QnxReadyCollector limited(ram, ring, 4096);
        bool rejected = false;
        const auto end = std::chrono::steady_clock::now() + event_wait;

        while (!rejected && std::chrono::steady_clock::now() < end) {
            try {
                limited.addresses();
            } catch (const std::exception &error) {
                rejected = std::string(error.what()).find("eight bounded workers") !=
                           std::string::npos;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        assert(rejected);
    }
    publish("no READY");
    {
        QnxReadyCollector replaced(ram, ring, 4096);
        std::filesystem::rename(ram, root / "retained-ram");
        {
            std::ofstream file(ram);
            file << 'x';
        }
        bool rejected = false;
        const auto end = std::chrono::steady_clock::now() + event_wait;

        while (!rejected && std::chrono::steady_clock::now() < end) {
            try {
                replaced.addresses();
            } catch (const std::exception &error) {
                rejected = std::string(error.what()).find("incarnation") != std::string::npos;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        assert(rejected);
    }
    std::filesystem::remove_all(root);
}

static void observer_metadata_after_exchanged_shutdown() {
    // Test fixtures stay inside the project, including when ctest uses its build directory.
    const auto directory = std::filesystem::current_path() / ".local/build" /
                           ("voyemu-observer-metadata-" + random_token());

    ensure_private_directory(directory);
    const auto session = random_token(), foreign = random_token();
    unsigned adb_calls = 0;
    {
        UiObserver observer(directory, session, Json::object(),
                            [&](const auto &, int) {
                                ++adb_calls;

                                return ProcessResult{};
                            },
                            {}, {});
        const std::string before = "1cfcc625-9d42-40e8-ac0c-f2f8dc789b85",
                          after = "76045be3-57f5-4b04-bccd-40ff21a6d6ec";
        rejects([&] {
            observer.retire_for_boot(before, before);
        });
        rejects([&] {
            observer.retire_for_boot("", after);
        });
        rejects([&] {
            observer.retire_for_boot(before, "unknown");
        });
        observer.retire_for_boot(before, after);
    }
    assert(adb_calls == 0); // Empty/preparation-only observer never addresses any guest.
    const auto file = directory / "ui-observer.json", sibling = directory / "other-lease.json";
    write_private_json(file, {{"schema", 1}, {"session_id", session}, {"android_pid", 100}});
    write_private_json(sibling, {{"schema", 1}, {"session_id", foreign}});
    // reboot_android exchanges the live pointer before stop_android is invoked.
    auto observer = std::make_shared<int>(1);
    auto stopped = std::exchange(observer, {});
    assert(!observer && stopped);
    clear_ui_observer_metadata(directory, session);
    assert(!std::filesystem::exists(file) && std::filesystem::exists(sibling));
    clear_ui_observer_metadata(directory, session);
    write_private_json(file, {{"schema", 1}, {"session_id", foreign}});
    rejects([&] {
        clear_ui_observer_metadata(directory, session);
    });
    assert(read_private_json(file).at("session_id") == foreign);
    write_private_json(file, {{"schema", 2}, {"session_id", session}});
    rejects([&] {
        clear_ui_observer_metadata(directory, session);
    });
    assert(std::filesystem::exists(file));
    std::filesystem::remove_all(directory);
}

static void android_nonce_authority() {
    assert(android_nonce_matches("current", "current", "current", false));
    assert(android_nonce_matches("retained", "current", "retained", true));
    assert(!android_nonce_matches("retained", "current", "retained", false));
    assert(!android_nonce_matches("foreign", "current", "retained", true));
    assert(!android_nonce_matches("previous-checkpoint", "current", "retained", true));
    // SDK cold fallback is admitted even if restoration was requested.
    assert(android_nonce_matches("current", "current", "retained", true));
}

static void cleanup_guards() {
    auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                ("voyemu-owned-qnx-cleanup-test-" + random_token());
    auto created = std::filesystem::create_directory(root);

    assert(created);

    if (!created) {
        throw std::runtime_error("test directory unexpectedly exists");
    }

    auto make = [&](bool ram = true) {
        auto id = random_token();
        auto directory = root / ".local/machines/test-profile/sessions" / id;
        ensure_private_directory(directory);
        write_private_json(directory / "session-owner.json",
                           {{"schema", 1},
                            {"session_id", id},
                            {"directory", directory.string()},
                            {"origin", "voyemu-native-supervisor"},
                            {"ram_absent_before_owned_qemu", true},
                            {"qnx_pid", 99}});

        // The session precreates the backing on Windows with the explicit user owner.
        if (ram) {
            create_qnx_ram(directory / "qnx-ram.bin", 8ULL << 30);
        }

        return directory;
    };
    Json terminal{{"children_terminal", true},
                  {"qemu", {{"pid", 99}, {"alive", false}, {"exit_code", 0}}},
                  {"graphics", Json::array({{{"pid", 100}, {"alive", false}, {"exit_code", 0}}})}};
    auto invalid = make();
    auto path = invalid / "qnx-ram.bin";
    auto id = invalid.filename().string();
    auto live = terminal;
    live["qemu"]["alive"] = true;
    rejects([&] {
        finalize_owned_qnx_session(invalid, id, path, live);
    });
    assert(std::filesystem::exists(path));
    auto graphics_live = terminal;
    graphics_live["graphics"][0]["alive"] = true;
    rejects([&] {
        finalize_owned_qnx_session(invalid, id, path, graphics_live);
    });
    assert(std::filesystem::exists(path));
    rejects([&] {
        finalize_owned_qnx_session(invalid, random_token(), path, terminal);
    });
    assert(std::filesystem::exists(path));
    const auto original_owner = read_private_json(invalid / "session-owner.json");
    auto relative_owner = original_owner;
    relative_owner["directory"] = "relative-session";
    write_private_json(invalid / "session-owner.json", relative_owner);
    rejects([&] {
        finalize_owned_qnx_session(invalid, id, path, terminal);
    });
    assert(std::filesystem::exists(path));
    write_private_json(invalid / "session-owner.json", original_owner);
    rejects([&] {
        finalize_owned_qnx_session(invalid, id, root / "foreign-ram.bin", terminal);
    });
    assert(std::filesystem::exists(path));
    auto size = make();
    std::filesystem::resize_file(size / "qnx-ram.bin", 64);
    rejects([&] {
        finalize_owned_qnx_session(size, size.filename().string(), size / "qnx-ram.bin", terminal);
    });
    assert(std::filesystem::file_size(size / "qnx-ram.bin") == 64);

    // The linked backings are POSIX fixtures: a symbolic link needs a privilege on Windows.
    if (!os::host_windows) {
        auto linked = make(false);
        std::filesystem::create_symlink(path, linked / "qnx-ram.bin");
        rejects([&] {
            finalize_owned_qnx_session(linked, linked.filename().string(), linked / "qnx-ram.bin",
                                       terminal);
        });
        assert(std::filesystem::exists(path));
        auto hard = make(false);
        std::filesystem::create_hard_link(path, hard / "qnx-ram.bin");
        rejects([&] {
            finalize_owned_qnx_session(hard, hard.filename().string(), hard / "qnx-ram.bin",
                                       terminal);
        });
        assert(std::filesystem::exists(path));
        std::filesystem::remove(hard / "qnx-ram.bin");
    }

    std::filesystem::path valid;

    // Under an elevated Windows token a backing that only inherits the token default owner stays
    // foreign, while the explicit user owner of the session backing passes.
    if (os::host_windows) {
        auto previous_owner = elevated_default_owner();
        auto defaulted = make(false);
        { std::ofstream(defaulted / "qnx-ram.bin", std::ios::binary) << "defaulted"; }
        os::resize_file(defaulted / "qnx-ram.bin", 8ULL << 30);
        valid = make();
        restore_default_owner(previous_owner);

        if (previous_owner.empty()) {
            std::cout << "SKIP elevated default owner: token keeps its default owner\n";
        } else {
            rejects([&] {
                finalize_owned_qnx_session(defaulted, defaulted.filename().string(),
                                           defaulted / "qnx-ram.bin", terminal);
            });
            assert(std::filesystem::exists(defaulted / "qnx-ram.bin"));
        }
    } else {
        valid = make();
    }

    {
        std::ofstream(valid / "qnx-console.log") << "preserved";
        std::ofstream(valid / "OEM-input.bin") << "preserved";
    }
    auto finalized = finalize_owned_qnx_session(valid, valid.filename().string(),
                                                valid / "qnx-ram.bin", terminal);
    assert(finalized["ram_removed"] == true && !std::filesystem::exists(valid / "qnx-ram.bin"));
    assert(std::filesystem::exists(valid / "qnx-console.log") &&
           std::filesystem::exists(valid / "OEM-input.bin"));
    auto handoff = std::filesystem::path(finalized.at("handoff").get<std::string>());
    assert(std::filesystem::exists(handoff) &&
           sha256_file(handoff) == finalized.at("handoff_sha256").get<std::string>());
    std::ifstream input(handoff);
    std::string text{std::istreambuf_iterator<char>(input), {}};
    // Windows neither renames the plans directory nor unlinks the handoff while it is open.
    input.close();
    assert(text.find("\"frame_count\": 0") != std::string::npos &&
           text.find("guest poll acknowledgement only") != std::string::npos);
    auto passion = make();
    auto passion_owner = read_private_json(passion / "session-owner.json");
    passion_owner["ram_geometry"] = "Passion11713MiB";
    write_private_json(passion / "session-owner.json", passion_owner);
    os::resize_file(passion / "qnx-ram.bin", 11713ULL * 1024 * 1024);
    auto passion_removed = finalize_owned_qnx_session(passion, passion.filename().string(),
                                                      passion / "qnx-ram.bin", terminal);
    assert(passion_removed["ram_removed"] == true &&
           !std::filesystem::exists(passion / "qnx-ram.bin"));
    auto unclaimed_passion = make();
    os::resize_file(unclaimed_passion / "qnx-ram.bin", 11713ULL * 1024 * 1024);
    rejects([&] {
        finalize_owned_qnx_session(unclaimed_passion, unclaimed_passion.filename().string(),
                                   unclaimed_passion / "qnx-ram.bin", terminal);
    });
    assert(std::filesystem::exists(unclaimed_passion / "qnx-ram.bin"));
    auto wrong_geometry = make();
    auto wrong_owner = read_private_json(wrong_geometry / "session-owner.json");
    wrong_owner["ram_geometry"] = "Passion11713MiB";
    write_private_json(wrong_geometry / "session-owner.json", wrong_owner);
    rejects([&] {
        finalize_owned_qnx_session(wrong_geometry, wrong_geometry.filename().string(),
                                   wrong_geometry / "qnx-ram.bin", terminal);
    });
    assert(std::filesystem::exists(wrong_geometry / "qnx-ram.bin"));
    wrong_owner["ram_geometry"] = "unvalidated";
    write_private_json(wrong_geometry / "session-owner.json", wrong_owner);
    rejects([&] {
        finalize_owned_qnx_session(wrong_geometry, wrong_geometry.filename().string(),
                                   wrong_geometry / "qnx-ram.bin", terminal);
    });
    assert(std::filesystem::exists(wrong_geometry / "qnx-ram.bin"));
    auto absent = make(false);
    auto no_ram = finalize_owned_qnx_session(absent, absent.filename().string(),
                                             absent / "qnx-ram.bin", terminal);
    assert(no_ram["status"] == "ram_not_created" && std::filesystem::exists(handoff));

    // Only macOS clones the RAM backing before QEMU starts.
    if (os::platform_name == "macOS") {
        auto prelaunch = make();
        auto clone_path = prelaunch / "qnx-ram.bin";
        auto clone_owner = read_private_json(prelaunch / "session-owner.json");
        clone_owner["qnx_pid"] = 0;
        clone_owner["ram_clone_identity"] = cache_file_identity(clone_path);
        write_private_json(prelaunch / "session-owner.json", clone_owner);
        Json no_child{
                {"children_terminal", true},
                {"qemu", {{"pid", 0}, {"alive", false}, {"started", false}, {"exit_code", -1}}},
                {"graphics", Json::array()},
                {"qemu_launch_failed_before_child", true},
                {"ram_clone_identity", clone_owner["ram_clone_identity"]}};
        auto wrong = no_child;
        wrong.erase("qemu_launch_failed_before_child");
        rejects([&] {
            finalize_owned_qnx_session(prelaunch, prelaunch.filename().string(), clone_path, wrong);
        });
        assert(std::filesystem::exists(clone_path));
        wrong = no_child;
        wrong["ram_clone_identity"]["inode"] = 0;
        rejects([&] {
            finalize_owned_qnx_session(prelaunch, prelaunch.filename().string(), clone_path, wrong);
        });
        assert(std::filesystem::exists(clone_path));
        wrong = no_child;
        wrong["qemu"]["exit_code"] = 0;
        rejects([&] {
            finalize_owned_qnx_session(prelaunch, prelaunch.filename().string(), clone_path, wrong);
        });
        assert(std::filesystem::exists(clone_path));
        wrong = no_child;
        wrong["qemu"]["started"] = true;
        wrong["qemu"]["exit_code"] = 0;
        rejects([&] {
            finalize_owned_qnx_session(prelaunch, prelaunch.filename().string(), clone_path, wrong);
        });
        assert(std::filesystem::exists(clone_path));
        auto removed = finalize_owned_qnx_session(prelaunch, prelaunch.filename().string(),
                                                  clone_path, no_child);
        assert(removed["ram_removed"] == true && !std::filesystem::exists(clone_path));
        std::ifstream no_child_record(removed["handoff"].get<std::string>());
        std::string no_child_text{std::istreambuf_iterator<char>(no_child_record), {}};
        assert(no_child_text.find("\"started\": false") != std::string::npos &&
               no_child_text.find("\"exit_code\": -1") != std::string::npos);
    }

    auto blocked = make();
    std::filesystem::rename(root / "plans", root / "preserved-plans");
    { std::ofstream(root / "plans") << "block handoff parent"; }
    rejects([&] {
        finalize_owned_qnx_session(blocked, blocked.filename().string(), blocked / "qnx-ram.bin",
                                   terminal);
    });
    assert(std::filesystem::exists(blocked / "qnx-ram.bin") &&
           std::filesystem::exists(root / "preserved-plans" /
                                   handoff.lexically_relative(root / "plans")));
    std::filesystem::remove_all(root);
}

static void configured_cluster_without_launch() {
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-off-cluster-test-" + random_token());
    const auto id = random_token();
    const auto directory = root / ".local/machines/test-profile/sessions" / id;

    ensure_private_directory(directory);
    Session session(directory, id);
    session.configure_cluster({{"schema", 1},
                               {"pins", Json::array()},
                               {"ram", "${SESSION}/qnx-ram.bin"},
                               {"qmp", "${RUNTIME}/${TOKEN}-qmp.sock"}},
                              10);
    const auto owner = read_private_json(directory / "session-owner.json");
    assert(!owner.contains("qnx_pid") && !std::filesystem::exists(directory / "qnx-ram.bin"));
    session.stop();
    const auto terminal = session.handle({{"op", "status"}});
    assert(terminal.at("stopped") == true && terminal.at("qnx_pid") == 0);
    assert(!terminal.at("deliveries").at("qnx").value("cleanup", Json::object()).contains("error"));
    assert(read_private_json(directory / "session-owner.json") == owner &&
           !std::filesystem::exists(root / "plans"));
    std::filesystem::remove_all(root);
}

static bool android_emulator_home_guards() {
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-emulator-home-" + random_token());

    ensure_private_directory(root);
    struct Cleanup {
        std::filesystem::path path;

        ~Cleanup() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    } cleanup{root};
    const auto home = root / ".local/machines/test-machine/emulator-home";
    prepare_android_emulator_home(root, home);

    if (!std::filesystem::is_directory(home)) {
        std::cerr << "fresh configured emulator home was not prepared before SDK startup\n";

        return false;
    }

    const auto marker = home / "preserved";
    { std::ofstream(marker) << "owned cached settings"; }
    const auto marker_sha = sha256_file(marker);
    prepare_android_emulator_home(root, home);
    assert(sha256_file(marker) == marker_sha);
    const auto file = root / ".local/machines/test-machine/file";
    { std::ofstream(file) << "preserved file"; }
    const auto file_sha = sha256_file(file);
    rejects([&] {
        prepare_android_emulator_home(root, file);
    });
    assert(sha256_file(file) == file_sha);
    const auto outside = root / "foreign";
    ensure_private_directory(outside);
    rejects([&] {
        prepare_android_emulator_home(root, outside / "emulator-home");
    });
    assert(!std::filesystem::exists(outside / "emulator-home"));
    rejects([&] {
        prepare_android_emulator_home(root, root / ".local/machines/test-machine/../escaped");
    });
    rejects([&] {
        prepare_android_emulator_home(root, "relative-home");
    });
    const auto linked = root / ".local/machines/test-machine/linked";
    std::filesystem::create_directory_symlink(outside, linked);
    rejects([&] {
        prepare_android_emulator_home(root, linked);
    });
    rejects([&] {
        prepare_android_emulator_home(root, linked / "child");
    });
    assert(!std::filesystem::exists(outside / "child"));

    return true;
}

static void android_avd_config_guards() {
    auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                ("voyemu-avd-config-test-" + random_token());

    ensure_private_directory(root);
    auto machine = root / "machine";
    ensure_private_directory(machine);
    ensure_private_directory(machine / "base");
    auto source = machine / "config-template.ini";
    {
        std::ofstream(source) << "hw.display1.flag=0\n";
        std::ofstream(machine / "config.ini") << "hw.display1.flag=1737\n";
    }
    const std::array<const char *, 8> names{"userdata-qemu.img", "cache.img",
                                            "encryptionkey.img", "userdata-qemu.img.qcow2",
                                            "cache.img.qcow2",   "encryptionkey.img.qcow2",
                                            "system.img.qcow2",  "vendor.img.qcow2"};

    for (auto name : names) {
        std::ofstream(machine / name) << name;
    }

    for (const char *name : {"system.img", "vendor.img"}) {
        std::ofstream(machine / "base" / name) << name;
    }

    { std::ofstream(machine / "base/build.prop") << "ro.build.version.incremental=9767327\n"; }
    const auto backing_fixture = machine / "system.img.qcow2";
    const auto original_overlay = sha256_file(backing_fixture);
    const auto fake_backing = [&](const std::string &backing) {
        std::array<unsigned char, 24> header{};
        header[0] = 'Q';
        header[1] = 'F';
        header[2] = 'I';
        header[3] = 0xfb;
        header[15] = 24;
        header[19] = static_cast<unsigned char>(backing.size());
        std::ofstream file(backing_fixture, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char *>(header.data()), header.size());
        file << backing;
    };
    fake_backing("../other/system.img");
    rejects([&] {
        normalize_android_disk_backings(machine, root / "never-executed");
    });
    fake_backing("foreign.img");
    rejects([&] {
        normalize_android_disk_backings(machine, root / "never-executed");
    });
    { std::ofstream(backing_fixture) << "system.img.qcow2"; }
    assert(sha256_file(backing_fixture) == original_overlay);

    // Creating a symbolic link needs a privilege on Windows.
    if (!os::host_windows) {
        const auto guarded = root / "marker-link/avd-home";
        ensure_private_directory(guarded / "content");
        const auto input = machine / "userdata-qemu.img",
                   marker = guarded / "content/version_num.cache";
        const auto before = sha256_file(input);
        std::filesystem::create_symlink(input, marker);
        rejects([&] {
            prepare_android_avd(guarded, machine, "marker", source, sha256_file(source));
        });
        assert(sha256_file(input) == before);
        std::filesystem::remove(marker);
        std::filesystem::create_hard_link(input, marker);
        rejects([&] {
            prepare_android_avd(guarded, machine, "marker", source, sha256_file(source));
        });
        assert(sha256_file(input) == before);
        std::filesystem::remove(marker);
    }

    auto expected = sha256_file(source);
    auto home = root / "session" / "avd-home";
    // A pre-existing alias that is a foreign regular file must be rejected without
    // touching the machine overlay; a hard-linked storage alias is accepted
    // because it is the same physical disk (Wine maps it across drive letters).
    {
        const auto guarded = root / "overlay-alias/avd-home";
        ensure_private_directory(guarded / "content");
        const auto fake = guarded / "content/system.img.qcow2";
        { std::ofstream(fake) << "foreign overlay bytes"; }
        rejects([&] {
            prepare_android_avd(guarded, machine, "aliastest", source, sha256_file(source));
        });
        assert(std::filesystem::exists(fake));
        std::filesystem::remove(fake);
        const auto disk = machine / "system.img.qcow2",
                   alias = guarded / "content/system.img.qcow2";
        std::error_code link_error;
        std::filesystem::create_hard_link(disk, alias, link_error);

        if (link_error) {
            std::cout << "SKIP shared-storage alias fixture: " << link_error.message() << '\n';
        } else {
            prepare_android_avd(guarded, machine, "aliastest", source, sha256_file(source));
            assert(std::filesystem::exists(alias));
            std::filesystem::remove(alias);
        }
    }
    rejects([&] {
        prepare_android_avd(home, machine, "../outside", source, expected);
    });
    rejects([&] {
        prepare_android_avd(home, machine, "test", source, std::string(64, '0'));
    });
    assert(!std::filesystem::exists(home));

    for (auto name : names) {
        if (std::string_view(name).starts_with("cache.img")) {
            continue;
        }

        std::filesystem::rename(machine / name, machine / "absent.saved");
        rejects([&] {
            prepare_android_avd(home, machine, "test", source, expected);
        });
        assert(!std::filesystem::exists(home));
        std::filesystem::rename(machine / "absent.saved", machine / name);
    }

    // Creating a symbolic link needs a privilege on Windows.
    if (!os::host_windows) {
        ensure_private_directory(home / "content");
        auto pending = home / "content/config.ini.voyemu-pending",
             foreign = root / "foreign-config.ini";
        std::filesystem::create_symlink(foreign, pending);
        rejects([&] {
            prepare_android_avd(home, machine, "test", source, expected);
        });
        assert(!std::filesystem::exists(foreign));
        std::filesystem::remove(pending);
        { std::ofstream(foreign) << "must remain unchanged"; }
        auto foreign_hash = sha256_file(foreign);
        std::filesystem::create_hard_link(foreign, pending);
        rejects([&] {
            prepare_android_avd(home, machine, "test", source, expected);
        });
        assert(sha256_file(foreign) == foreign_hash);
        std::filesystem::remove(pending);
    }

    std::map<std::filesystem::path, std::string> disks;

    for (auto name : names) {
        disks[machine / name] = sha256_file(machine / name);
    }

    auto assert_disks = [&] {
        for (const auto &[path, hash] : disks) {
            assert(sha256_file(path) == hash);
        }
    };
    auto runtime = prepare_android_avd(home, machine, "test", source, expected);
    assert(runtime == home / "content");
    assert(std::filesystem::equivalent(runtime / "encryptionkey.img",
                                       machine / "encryptionkey.img"));
    assert(!std::filesystem::exists(runtime / "encryptionkey.img.qcow2"));
    {
        std::ifstream version(runtime / "version_num.cache");
        std::string value;
        std::getline(version, value);
        assert(value == "9767327");
    }
    assert(sha256_file(runtime / "config.ini") != expected);
    assert_disks();
    std::ifstream locator(home / "test.ini");
    std::string text{std::istreambuf_iterator<char>(locator), {}};
    locator.close();
    assert(text.find("path=" + runtime.string() + "\n") != std::string::npos);
    { std::ofstream(runtime / "config.ini") << "hw.display1.flag = 1737\n"; }
    assert(sha256_file(source) == expected);
    verify_android_avd_storage(home, machine, "test");
    assert_disks();
    rejects([&] {
        prepare_android_avd(home, machine, "test", source, expected);
    });
    auto second = prepare_android_avd(root / "restart" / "avd-home", machine, "test", source,
                                      expected);
    assert(second == root / "restart/avd-home/content" &&
           sha256_file(second / "config.ini") != expected);
    verify_android_avd_storage(root / "restart" / "avd-home", machine, "test");
    assert_disks();
    const auto separate_base = root / "separate-base";
    std::filesystem::rename(machine / "base", separate_base);
    // A launch already carries an explicit project-owned sysdir; AVD validation must use it.
    auto third = prepare_android_avd(root / "separate-session/avd-home", machine, "test", source,
                                     expected, separate_base);
    assert(third == root / "separate-session/avd-home/content");
    verify_android_avd_storage(root / "separate-session/avd-home", machine, "test");
    assert_disks();
    std::filesystem::rename(separate_base, machine / "base");
    const auto api30_home = root / "api30-session/avd-home";
    prepare_android_avd(api30_home, machine, "api30", source, expected, {}, 30);
    std::ifstream api30_locator(api30_home / "api30.ini");
    const std::string locator_text{std::istreambuf_iterator<char>(api30_locator), {}};
    api30_locator.close();
    assert(locator_text.find("target=android-30\n") != std::string::npos);
    assert_disks();
    rejects([&] {
        prepare_android_avd(root / "invalid-api", machine, "bad", source, expected, {}, 29);
    });
    assert(!std::filesystem::exists(root / "invalid-api"));
    const std::string version_sha(64, 'a');
    const auto version_dir = machine / "system-versions" / version_sha;
    ensure_private_directory(version_dir);
    {
        std::ofstream(version_dir / "system.img") << "new system raw";
        std::ofstream(version_dir / "system.img.qcow2") << "new system overlay";
    }
    const Json version_binding = {{"raw", (version_dir / "system.img").string()},
                                  {"overlay", (version_dir / "system.img.qcow2").string()},
                                  {"sha256", version_sha}};
    const auto selected_backing = [&](const std::string &backing) {
        std::array<unsigned char, 24> header{};
        header[0] = 'Q';
        header[1] = 'F';
        header[2] = 'I';
        header[3] = 0xfb;
        header[15] = 24;
        header[19] = static_cast<unsigned char>(backing.size());
        std::ofstream file(version_dir / "system.img.qcow2", std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char *>(header.data()), header.size());
        file << backing;
    };
    selected_backing("system.img");
    normalize_android_disk_backings(machine, root / "never-executed", version_binding);
    selected_backing("../other/system.img");
    rejects([&] {
        normalize_android_disk_backings(machine, root / "never-executed", version_binding);
    });
    { std::ofstream(version_dir / "system.img.qcow2") << "new system overlay"; }
    const auto version_home = root / "version-system/avd-home";
    ensure_private_directory(version_home / "content");
    std::filesystem::create_symlink(machine / "base/system.img",
                                    version_home / "content/system.img");
    std::filesystem::create_hard_link(machine / "system.img.qcow2",
                                      version_home / "content/system.img.qcow2");
    const auto version_content = prepare_android_avd(version_home, machine, "versioned", source,
                                                     expected, {}, 30, version_binding);
    assert(std::filesystem::equivalent(version_content / "system.img",
                                       version_dir / "system.img") &&
           std::filesystem::equivalent(version_content / "system.img.qcow2",
                                       version_dir / "system.img.qcow2"));
    verify_android_avd_storage(version_home, machine, "versioned");
    assert_disks();
    auto invalid_binding = version_binding;
    invalid_binding["raw"] = (version_dir / "../system.img").string();
    rejects([&] {
        prepare_android_avd(root / "bad-system", machine, "bad", source, expected, {}, 30,
                            invalid_binding);
    });
    assert(!std::filesystem::exists(root / "bad-system"));
    const auto foreign_home = root / "foreign-system/avd-home";
    ensure_private_directory(foreign_home / "content");
    const auto foreign_system = root / "foreign-system.img";
    { std::ofstream(foreign_system) << "foreign system"; }
    std::filesystem::create_symlink(foreign_system, foreign_home / "content/system.img");
    rejects([&] {
        prepare_android_avd(foreign_home, machine, "foreign", source, expected, {}, 30,
                            version_binding);
    });
    assert(std::filesystem::equivalent(foreign_home / "content/system.img", foreign_system));
    assert_disks();
    // A failed prepared-input check never publishes an Android lifetime or verifies an uncreated
    // AVD on stop.
    const auto engine = root / "unused-engine";
    { std::ofstream(engine) << "not executed"; }
    write_private_json(machine / "machine.json", {{"schema", 1}});
    const auto id = random_token();
    const auto directory = root / ".local/machines/test-profile/sessions" / id;
    ensure_private_directory(directory);
    const Json spec = {
            {"schema", 1},
            {"executable", engine.string()},
            {"machine", machine.string()},
            {"base", (machine / "base").string()},
            {"config_template", source.string()},
            {"port", 5608},
            {"avd_name", "test"},
            {"android_sdk_root", (root / "unused-sdk").string()},
            {"pins", Json::array({{{"path", engine.string()}, {"sha256", sha256_file(engine)}},
                                  {{"path", source.string()}, {"sha256", expected}}})}};

    // Windows attaches Android through its startup transaction, covered by its own fixtures.
    if (!os::host_windows) {
        {
            const auto passion_id = random_token();
            const auto passion_dir = root / ".local/machines/passion-test/sessions" / passion_id;
            ensure_private_directory(passion_dir);
            Session passion(passion_dir, passion_id);
            auto presentation = spec;
            presentation["api"] = 30;
            presentation["home"] = {{"package", "com.voyah.os.carlauncher"},
                                    {"component", passion_home}};
            presentation["reference_profile"] = "synthetic-passion";
            presentation["platform"] = "passion";
            presentation["board"] = "8155";
            presentation["presentation_adapter"] =
                    passion_presentation_contract("synthetic-passion");
            presentation["gpuMode"] = "invalid-before-child";
            bool before_child = false;
            try {
                passion.attach_android(presentation, true);
            } catch (const std::exception &e) {
                before_child = std::string(e.what()).starts_with("ANDROID_GPU:");
            }

            assert(before_child);
            const auto before = passion.handle({{"op", "status"}});
            assert(before.at("android_pid") == 0 && before.at("wheel_routes").is_null());
            const auto state_sha = sha256_file(passion_dir / "vehicle-state.json");

            for (const Json &command :
                 Json::array({{{"op", "patch"}, {"values", {{"ivi_languageSet", 1}}}},
                              {{"op", "wheel"},
                               {"id", "voice"},
                               {"phase", "down"},
                               {"owner", "test"}}})) {
                const auto rejected = passion.handle(command);
                assert(rejected.at("ok") == false);
                const auto after = passion.handle({{"op", "status"}});
                assert(after.at("revision") == before.at("revision") &&
                       after.at("held_buttons") == 0 &&
                       sha256_file(passion_dir / "vehicle-state.json") == state_sha);
            }

            passion.stop();
        }
        {
            const auto nxp_id = random_token();
            const auto nxp_dir = root / ".local/machines/nxp-test/sessions" / nxp_id;
            ensure_private_directory(nxp_dir);
            Session nxp(nxp_dir, nxp_id);
            auto presentation = spec;
            presentation["api"] = 28;
            presentation["home"] = {{"package", "com.qinggan.app.launcher"},
                                    {"component", nxp_home}};
            presentation["reference_profile"] = "synthetic-nxp";
            presentation["platform"] = "qinggan09";
            presentation["board"] = "nxp";
            presentation["presentation_adapter"] = nxp_presentation_contract("synthetic-nxp");
            presentation["gpuMode"] = "invalid-before-child";
            bool before_child = false;
            try {
                nxp.attach_android(presentation, true);
            } catch (const std::exception &e) {
                before_child = std::string(e.what()).starts_with("ANDROID_GPU:");
            }

            assert(before_child);
            const auto before = nxp.handle({{"op", "status"}});
            assert(before.at("android_pid") == 0 && before.at("wheel_routes").is_null());
            const auto state_sha = sha256_file(nxp_dir / "vehicle-state.json");

            for (const Json &command :
                 Json::array({{{"op", "patch"}, {"values", {{"ivi_languageSet", 1}}}},
                              {{"op", "wheel"},
                               {"id", "voice"},
                               {"phase", "down"},
                               {"owner", "test"}}})) {
                const auto rejected = nxp.handle(command);
                assert(rejected.at("ok") == false);
                const auto after = nxp.handle({{"op", "status"}});
                assert(after.at("revision") == before.at("revision") &&
                       after.at("held_buttons") == 0 &&
                       sha256_file(nxp_dir / "vehicle-state.json") == state_sha);
            }

            nxp.stop();
        }
        {
            const auto nxp_id = random_token();
            const auto nxp_dir = root / ".local/machines/nxp-wheel-test/sessions" / nxp_id;
            ensure_private_directory(nxp_dir);
            Session nxp(nxp_dir, nxp_id);
            auto presentation = spec;
            presentation["api"] = 28;
            presentation["home"] = {{"package", "com.qinggan.app.launcher"},
                                    {"component", nxp_home}};
            presentation["reference_profile"] = "synthetic-nxp";
            presentation["platform"] = "qinggan09";
            presentation["board"] = "nxp";
            presentation["presentation_adapter"] = nxp_presentation_contract("synthetic-nxp");
            presentation["wheel_adapter"] = nxp_wheel_adapter();
            presentation["gpuMode"] = "invalid-before-child";
            bool before_child = false;
            try {
                nxp.attach_android(presentation, true);
            } catch (const std::exception &e) {
                before_child = std::string(e.what()).starts_with("ANDROID_GPU:");
            }

            assert(before_child);
            const auto before = nxp.handle({{"op", "status"}});
            assert(before.at("wheel_routes").at("photo").at("android").at("key_code") == 142);
            assert(!before.at("wheel_routes").at("ica").contains("ecu"));
            const auto state_sha = sha256_file(nxp_dir / "vehicle-state.json");

            for (const char *phase : {"down", "up"}) {
                const auto receipt = nxp.handle(
                        {{"op", "wheel"}, {"id", "ica"}, {"phase", phase}, {"owner", "test"}});
                assert(receipt.at("ok") == true &&
                       receipt.at("deliveries").at("android") == "unmapped" &&
                       receipt.at("deliveries").at("adas_ecu") == "not_a_consumer");
            }

            const auto after = nxp.handle({{"op", "status"}});
            assert(after.at("revision") == before.at("revision") && after.at("held_buttons") == 0 &&
                   sha256_file(nxp_dir / "vehicle-state.json") == state_sha);
            nxp.stop();
        }
    }

    {
        const auto free_id = random_token();
        const auto free_dir = root / ".local/machines/free-test/sessions" / free_id;
        ensure_private_directory(free_dir);
        Session free(free_dir, free_id);
        auto unsupported = spec;
        unsupported["api"] = 30;
        unsupported["home"] = {
                {"package", "com.qinggan.app.launcher"},
                {"component",
                 "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}};
        unsupported["reference_profile"] = "free-11-chinese-20260731-7.3.1";
        unsupported["vehicle_adapter"] = {{"authority", "com.voyemu.output.vehicle"}};
        unsupported["wheel_capability"] = {{"schema", 1},
                                           {"profile", "free-11-chinese-20260731-7.3.1"},
                                           {"status", "unsupported"},
                                           {"supported", false},
                                           {"reason", "provider_not_installed"},
                                           {"authority", "com.voyemu.input.wheel"}};
        unsupported["gpuMode"] = "invalid-before-child";
        bool before_child = false;
        try {
            free.attach_android(unsupported, true);
        } catch (const std::exception &e) {
            before_child = std::string(e.what()).starts_with("ANDROID_GPU:");
        }

        assert(before_child);
        const auto before = free.handle({{"op", "status"}});
        assert(before.at("android_pid") == 0);

        for (const auto &[key, route] : before.at("wheel_routes").items()) {
            assert(route.at("android") == "unsupported");
        }

        const auto state_sha = sha256_file(free_dir / "vehicle-state.json");
        const auto rejected = free.handle(
                {{"op", "wheel"}, {"id", "menu"}, {"phase", "down"}, {"owner", "test"}});
        assert(!rejected.at("ok").get<bool>());
        const auto after = free.handle({{"op", "status"}});
        assert(after.at("revision") == before.at("revision") && after.at("held_buttons") == 0 &&
               sha256_file(free_dir / "vehicle-state.json") == state_sha);
        free.stop();
    }
    {
        const auto partial_id = random_token();
        const auto partial_dir = root / ".local/machines/free-partial-test/sessions" / partial_id;
        ensure_private_directory(partial_dir);
        Session partial(partial_dir, partial_id);
        auto prepared = spec;
        prepared["api"] = 30;
        prepared["home"] = {
                {"package", "com.qinggan.app.launcher"},
                {"component",
                 "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}};
        prepared["vehicle_adapter"] = {{"authority", "com.voyemu.output.vehicle"}};
        prepared["reference_profile"] = "free-11-chinese-20260731-7.3.1";
        prepared["wheel_adapter"] = qinggan11_wheel_adapter();
        prepared["wheel_capability"] =
                qinggan11_partial_wheel_capability("free-11-chinese-20260731-7.3.1");
        prepared["gpuMode"] = "invalid-before-child";
        bool before_child = false;
        try {
            partial.attach_android(prepared, true);
        } catch (const std::exception &error) {
            before_child = std::string(error.what()).starts_with("ANDROID_GPU:");
        }

        assert(before_child);
        const auto before = partial.handle({{"op", "status"}});
        const auto state_sha = sha256_file(partial_dir / "vehicle-state.json");

        for (const auto &[button, route] : before.at("wheel_routes").items()) {
            const Json supported = {{"volume_up", 2}, {"volume_down", 1}, {"next", 3},
                                    {"previous", 4},  {"ok", 6},          {"photo", 173},
                                    {"voice", 130},   {"phone", 128}};

            if (supported.contains(button)) {
                assert(route.at("android").at("key_code") == supported.at(button));
                continue;
            }

            assert(route.at("android") == "unsupported");
            const auto rejected = partial.handle(
                    {{"op", "wheel"}, {"id", button}, {"phase", "down"}, {"owner", "test"}});
            assert(!rejected.at("ok").get<bool>());
            const auto after = partial.handle({{"op", "status"}});
            assert(after.at("held_buttons") == 0 && after.at("revision") == before.at("revision") &&
                   sha256_file(partial_dir / "vehicle-state.json") == state_sha);
        }

        for (const char *button :
             {"volume_up", "volume_down", "next", "previous", "ok", "photo", "voice", "phone"}) {
            assert(partial.handle({{"op", "wheel"},
                                   {"id", button},
                                   {"phase", "down"},
                                   {"owner", "test"}})
                           .at("accepted"));
            assert(partial.handle({{"op", "wheel"},
                                   {"id", button},
                                   {"phase", "cancel"},
                                   {"owner", "other"}})
                           .at("ok") == false);
            assert(partial.handle({{"op", "wheel"},
                                   {"id", button},
                                   {"phase", "cancel"},
                                   {"owner", "test"}})
                           .at("accepted"));
        }

        for (const char *button : {"next", "previous", "ok", "photo", "voice", "phone"}) {
            const auto rejected = partial.handle(
                    {{"op", "wheel_pair"}, {"id", button}, {"owner", "test"}, {"hold_ms", 100}});
            assert(!rejected.at("ok").get<bool>() &&
                   partial.handle({{"op", "status"}}).at("held_buttons") == 0);
        }

        for (const auto &hold : Json::array({0, 201, 1300, 100.5})) {
            const auto rejected = partial.handle({{"op", "wheel_pair"},
                                                  {"id", "volume_down"},
                                                  {"owner", "test"},
                                                  {"hold_ms", hold}});
            assert(!rejected.at("ok").get<bool>() &&
                   partial.handle({{"op", "status"}}).at("held_buttons") == 0);
        }

        // Windows pairs wheel events through its Android startup transaction: wheel_pair_flush_run.
        if (!os::host_windows) {
            const auto paired = partial.handle({{"op", "wheel_pair"},
                                                {"id", "volume_down"},
                                                {"owner", "test"},
                                                {"hold_ms", 100}});
            assert(paired.at("ok") == true && paired.at("session_id") == partial_id &&
                   paired.at("released") == true && paired.at("guest_acknowledged") == false &&
                   paired.at("up").at("event_sequence").get<unsigned>() ==
                           paired.at("down").at("event_sequence").get<unsigned>() + 1 &&
                   partial.handle({{"op", "status"}}).at("held_buttons") == 0);
        }

        partial.stop();
    }
    {
        const auto external_id = random_token();
        const auto external_dir = root / ".local/machines/external-network-test/sessions" /
                                  external_id;
        ensure_private_directory(external_dir);
        Session external(external_dir, external_id);
        auto networked = spec;
        networked["gpuMode"] = "invalid-before-child";
        networked["network"] = android_network_contract();
        bool before_child = false;
        try {
            external.attach_android(networked, true);
        } catch (const std::exception &e) {
            before_child = std::string(e.what()).starts_with("ANDROID_GPU:");
        }

        assert(before_child);

        for (const Json &invalid : Json::array({Json::object(),
                                                {{"schema", 1}, {"transport", "tap-ram-v1"}},
                                                {{"schema", 2}, {"transport", "slirp-user-nat-v1"}},
                                                {{"schema", 1},
                                                 {"transport", "slirp-user-nat-v1"},
                                                 {"address", "10.0.2.15"}}})) {
            auto broken = networked;
            broken["network"] = invalid;
            bool rejected = false;
            try {
                external.attach_android(broken, true);
            } catch (const std::exception &e) {
                rejected = std::string(e.what()).starts_with("ANDROID_NETWORK_CONTRACT:");
            }

            assert(rejected);
        }

        external.stop();
    }
    {
        Session failed(directory, id);
        std::filesystem::rename(machine / "userdata-qemu.img", machine / "userdata.saved");
        bool input_failure = false;
        try {
            failed.attach_android(spec, true);
        } catch (const std::exception &error) {
            input_failure = std::string(error.what()).starts_with("ANDROID_AVD_IMAGE:");
        }

        std::filesystem::rename(machine / "userdata.saved", machine / "userdata-qemu.img");
        assert(input_failure && !std::filesystem::exists(directory / "avd-home"));
        failed.stop();
        const auto terminal = failed.handle({{"op", "status"}});
        assert(terminal.at("stopped") == true && terminal.at("android_pid") == 0);
    }
    // Ordinary start consumes configuration independently of historical binary and
    // payload digests. Missing storage must still fail before any engine starts.
    auto historical = spec;
    historical["pins"][0]["sha256"] = std::string(64, '0');
    historical["pins"].push_back({{"path", (root / "absent-large-image.img").string()},
                                  {"sha256", std::string(64, 'a')}});
    {
        Session audited(directory, id);
        bool mismatch = false;
        try {
            audited.attach_android(historical, true);
        } catch (const std::exception &error) {
            mismatch = std::string(error.what()).starts_with("LAUNCH_PIN:");
        }

        assert(mismatch);
        audited.stop();
    }
    {
        const auto normal_id = random_token();
        const auto normal_dir = root / ".local/machines/test-profile/sessions" / normal_id;
        ensure_private_directory(normal_dir);
        auto normal = Session::for_machine_start(normal_dir, normal_id);
        std::filesystem::rename(machine / "userdata-qemu.img", machine / "userdata.saved");
        bool storage = false;
        try {
            normal->attach_android(historical, true);
        } catch (const std::exception &error) {
            storage = std::string(error.what()).starts_with("ANDROID_AVD_IMAGE:");
        }

        std::filesystem::rename(machine / "userdata.saved", machine / "userdata-qemu.img");
        assert(storage && !std::filesystem::exists(normal_dir / "avd-home"));
        normal->stop();
    }
    { std::ofstream(source) << "corrupt-template"; }
    rejects([&] {
        verify_android_avd_storage(home, machine, "test");
    });
    std::filesystem::remove_all(root);
}

static void android_avd_relocation_guards() {
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-avd-relocation-" + random_token());

    ensure_private_directory(root);
    struct Cleanup {
        std::filesystem::path path;

        ~Cleanup() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }
    } cleanup{root};
    const auto old_seed = root / "original/car", new_seed = root / "relocated/car",
               old_machine = old_seed / "android", machine = new_seed / "android",
               home = root / "runtime/avd-home", source = root / "source.ini";
    ensure_private_directory(old_machine);
    ensure_private_directory(new_seed.parent_path());

    for (const char *name :
         {"system.img", "vendor.img", "userdata-qemu.img", "cache.img", "encryptionkey.img",
          "system.img.qcow2", "vendor.img.qcow2", "userdata-qemu.img.qcow2", "cache.img.qcow2",
          "encryptionkey.img.qcow2"}) {
        std::ofstream(old_machine / name) << name;
    }

    {
        std::ofstream(old_machine / "build.prop") << "ro.build.version.incremental=9767327\n";
        std::ofstream(source) << "AvdId=relocation\nhw.ramSize=1\nhw.sdCard=no\n";
    }
    const auto pin = sha256_file(source);
    const auto content = prepare_android_avd(home, old_machine, "relocation", source, pin,
                                             old_machine);

    // Windows links an overlay by a hard link where it can, POSIX always by a symbolic link.
    if (!os::host_windows) {
        assert(std::filesystem::read_symlink(content / "system.img") == old_machine / "system.img");
    }

    std::map<std::string, std::string> disks;

    for (const auto &entry : std::filesystem::directory_iterator(old_machine)) {
        if (entry.is_regular_file()) {
            disks[entry.path().filename().string()] = sha256_file(entry.path());
        }
    }

    std::filesystem::rename(old_seed, new_seed);
    std::filesystem::remove(home / "relocation.ini");
    prepare_android_avd(home, machine, "relocation", source, pin, machine, 28, Json(), old_machine);

    for (const char *name : {"system.img.qcow2", "vendor.img.qcow2", "system.img", "vendor.img",
                             "encryptionkey.img"}) {
        assert(std::filesystem::equivalent(content / name, machine / name));
    }

    for (const auto &[name, sha] : disks) {
        assert(sha256_file(machine / name) == sha);
    }

    auto old_spec = Json{{"machine", old_machine.string()}, {"base", old_machine.string()}},
         new_spec = Json{{"machine", machine.string()}, {"base", machine.string()}};
    assert(android_quickboot_key(old_spec) != android_quickboot_key(new_spec));

    // Creating a symbolic link needs a privilege on Windows.
    if (!os::host_windows) {
        std::filesystem::remove(home / "relocation.ini");
        const auto alias = content / "system.img";
        std::filesystem::remove(alias);
        std::filesystem::create_symlink(old_machine / "system.img", alias);
        const auto retained = std::filesystem::read_symlink(alias);
        rejects([&] {
            prepare_android_avd(home, machine, "relocation", source, pin, machine);
        });
        assert(std::filesystem::read_symlink(alias) == retained);
        rejects([&] {
            prepare_android_avd(home, machine, "relocation", source, pin, machine, 28, Json(),
                                root / "unrelated/car/android");
        });
        assert(std::filesystem::read_symlink(alias) == retained);
        ensure_private_directory(old_machine);
        rejects([&] {
            prepare_android_avd(home, machine, "relocation", source, pin, machine, 28, Json(),
                                old_machine);
        });
        assert(std::filesystem::read_symlink(alias) == retained);
        std::filesystem::remove_all(old_seed);
        std::filesystem::remove(alias);
        const auto foreign = root / "foreign-missing-system.img";
        std::filesystem::create_symlink(foreign, alias);
        rejects([&] {
            prepare_android_avd(home, machine, "relocation", source, pin, machine, 28, Json(),
                                old_machine);
        });
        assert(std::filesystem::read_symlink(alias) == foreign);
        std::filesystem::remove(alias);
        std::filesystem::create_symlink(old_machine / "system.img", alias);
        prepare_android_avd(home, machine, "relocation", source, pin, machine, 28, Json(),
                            old_machine);
        // Once aliases match, a later reuse of the old directory must not break this machine.
        std::filesystem::remove(home / "relocation.ini");
        ensure_private_directory(old_machine);
        prepare_android_avd(home, machine, "relocation", source, pin, machine, 28, Json(),
                            old_machine);
        std::filesystem::remove_all(old_seed);
        std::filesystem::remove(home / "relocation.ini");
        std::filesystem::rename(new_seed, old_seed);
        prepare_android_avd(home, old_machine, "relocation", source, pin, old_machine, 28, Json(),
                            machine);

        for (const char *name : {"system.img.qcow2", "vendor.img.qcow2", "system.img", "vendor.img",
                                 "encryptionkey.img"}) {
            assert(std::filesystem::equivalent(content / name, old_machine / name));
        }

        for (const auto &[name, sha] : disks) {
            assert(sha256_file(old_machine / name) == sha);
        }
    }
}

static void android_startup_stage_isolation() {
    for (unsigned failures = 0; failures < 8; ++failures) {
        std::vector<std::string> calls;
        auto stage = [&](const char *name, unsigned bit) {
            calls.push_back(name);

            if (failures & bit) {
                throw std::runtime_error(std::string(name) + " failed");
            }
        };
        auto errors = run_android_startup_stages(
                [&] {
                    stage("guard", 1);
                },
                [&] {
                    stage("vehicle", 2);
                },
                [&] {
                    stage("display", 4);
                });

        if (failures & 1) {
            assert(calls == std::vector<std::string>{"guard"});
            assert(errors.size() == 1 && errors["guard"] == "guard failed");
        } else {
            assert((calls == std::vector<std::string>{"guard", "vehicle", "display"}));
            assert(errors.contains("vehicle") == bool(failures & 2));
            assert(errors.contains("display") == bool(failures & 4));
            assert(errors.size() == unsigned(bool(failures & 2)) + unsigned(bool(failures & 4)));
        }
    }

    auto errors = run_android_startup_stages([] {},
                                             [] {
                                                 throw std::runtime_error(std::string(4096, 'x'));
                                             },
                                             [] {});
    assert(errors["vehicle"].get<std::string>().size() == 2048);
    assert(run_android_startup_stages([] {}, [] {}, [] {}).empty());
}

static void android_short_pair_guards() {
    const WheelEvent down{41, "volume_down", "down", "pair-owner", 0, 1},
            up{42, "volume_down", "up", "pair-owner", 0, 0};

    assert(android_wheel_release_reuses_identity(down, up));
    auto cancel = up;
    cancel.phase = "cancel";
    assert(android_wheel_release_reuses_identity(down, cancel));

    for (auto changed : {WheelEvent{43, "volume_down", "up", "pair-owner", 0, 0},
                         WheelEvent{42, "volume_down", "up", "foreign", 0, 0},
                         WheelEvent{42, "volume_up", "up", "pair-owner", 0, 0},
                         WheelEvent{42, "volume_down", "down", "pair-owner", 0, 0}}) {
        assert(!android_wheel_release_reuses_identity(down, changed));
    }

    for (int hold : {0, 201, 1300}) {
        bool refused = false;
        try {
            (void)android_short_wheel_pair_command("pair-session", std::string(32, 'a'),
                                                   "pair-boot", down, up, hold);
        } catch (const std::exception &) {
            refused = true;
        }

        assert(refused);
    }

    for (auto wrong : {WheelEvent{43, "volume_down", "up", "pair-owner", 0, 0},
                       WheelEvent{42, "volume_down", "up", "foreign", 0, 0},
                       WheelEvent{42, "volume_up", "up", "pair-owner", 0, 0},
                       WheelEvent{42, "volume_down", "cancel", "pair-owner", 0, 0}}) {
        bool refused = false;
        try {
            (void)android_short_wheel_pair_command("pair-session", std::string(32, 'a'),
                                                   "pair-boot", down, wrong, 1);
        } catch (const std::exception &) {
            refused = true;
        }

        assert(refused);
    }

    // The pair command runs under /bin/sh.
    if (!os::host_windows) {
        const std::string expected =
                R"(Result: Bundle[{json={"schema":1,"session_id":"pair-session","boot_id":"pair-boot","sequence":41,"button":"volume_down","phase":"down","status":"terminal-requested","oem_handled":null,"visible_effect_verified":false,"submission_confirmed":true,"key_code":1,"action":4096,"flags":0,"scope":"OEM transaction7 completed; callbacks/effects not inferred"}}])";
        auto run = [&](const std::string &reply) {
            ProcessSpec shell;
            shell.executable = "/bin/sh";
            shell.arguments = {
                    "-c",
                    "content() { case \"$*\" in *phase:s:down*) printf '%s\\n' " +
                            android_shell_quote(reply) +
                            ";; *phase:s:up*) printf '%s\\n' RELEASE_SENT;; *) return 9;; esac; };\n" +
                            android_short_wheel_pair_command("pair-session", std::string(32, 'a'),
                                                             "pair-boot", down, up, 1)};

            return execute(shell, 2000);
        };
        const auto good = run(expected);
        assert(good.exit_code == 0 && good.output.find("VOYEMU_DOWN\n") == 0 &&
               good.output.find("VOYEMU_UP\nRELEASE_SENT\n") != std::string::npos);

        for (const auto &replacement : std::vector<std::pair<std::string, std::string>>{
                     {"pair-boot", "foreign-boot"},
                     {"terminal-requested", "terminal-unavailable"},
                     {"\"submission_confirmed\":true", "\"submission_confirmed\":false"},
                     {"\"sequence\":41", "\"sequence\":40"},
                     {"\"key_code\":1", "\"key_code\":2"}}) {
            auto bad = expected;
            const auto position = bad.find(replacement.first);
            assert(position != std::string::npos);
            bad.replace(position, replacement.first.size(), replacement.second);
            const auto rejected = run(bad);
            assert(rejected.exit_code == 24 &&
                   rejected.output.find("RELEASE_SENT") == std::string::npos);
        }
    }
}

static void android_wheel_terminal_receipts() {
    const std::string session = "wheel-receipt-session";
    const WheelEvent event{17, "custom", "up", "owner", 0, 0};
    Json receipt{{"schema", 1},        {"session_id", session}, {"sequence", 17},
                 {"button", "custom"}, {"phase", "up"},         {"status", "callbacks"}};

    for (const char *status :
         {"callbacks", "terminal-requested", "no-consumer", "restricted", "terminal-unavailable"}) {
        receipt["status"] = status;
        receipt["terminal_failure"] = "src-mode-blocked";
        auto delivery = android_wheel_delivery_receipt(receipt, session, event);
        assert(delivery && delivery->at("status") == status &&
               delivery->at("guest_acknowledged") == true);
        assert(delivery->at("visible_effect_verified") == false &&
               delivery->at("receipt") == receipt);
    }

    receipt["status"] = "callbacks";

    for (const auto &patch :
         {Json{{"schema", 1.0}}, Json{{"schema", 2}}, Json{{"sequence", 17.0}},
          Json{{"sequence", -1}}, Json{{"sequence", 0x100000011ULL}}, Json{{"session_id", "stale"}},
          Json{{"button", "menu"}}, Json{{"phase", "down"}}, Json{{"status", "unknown"}},
          Json{{"status", true}}}) {
        auto malformed = receipt;
        malformed.update(patch);
        assert(!android_wheel_delivery_receipt(malformed, session, event));
    }

    for (const char *key : {"schema", "session_id", "sequence", "button", "phase", "status"}) {
        auto absent = receipt;
        absent.erase(key);
        assert(!android_wheel_delivery_receipt(absent, session, event));
    }

    assert(!android_wheel_delivery_receipt(Json::array(), session, event));
}

static void qnx_vehicle_receipts() {
    const QnxVehicleReceiver receiver{0x9de10000, 2, 12, 1011, 0x92};
    const Json ack{{"schema", 1u},
                   {"sequence", 3u},
                   {"producer_address", receiver.producer_address},
                   {"generation", 2u},
                   {"worker_nonce", 12u},
                   {"guest_pid", 1011u},
                   {"producer_incarnation", 0x92u},
                   {"guest_acknowledged", true},
                   {"host_monotonic_ns", 1u}};

    assert(qnx_vehicle_receipt(ack, receiver, 3) == ack);
    // The receipt of revision 2 never confirms the queued revision 3.
    assert(!qnx_vehicle_receipt(ack, receiver, 4) && !qnx_vehicle_receipt(ack, receiver, 0));

    for (const char *key : {"producer_address", "generation", "worker_nonce", "guest_pid",
                            "producer_incarnation", "sequence"}) {
        auto other = ack;
        other[key] = other.at(key).get<std::uint64_t>() + 1;
        assert(!qnx_vehicle_receipt(other, receiver, 3));
        auto absent = ack;
        absent.erase(key);
        assert(!qnx_vehicle_receipt(absent, receiver, 3));
    }

    for (const auto &patch :
         {Json{{"schema", 2u}}, Json{{"guest_acknowledged", false}},
          Json{{"guest_acknowledged", 1}}, Json{{"sequence", 3.0}}, Json{{"sequence", "3"}},
          Json{{"generation", -2}}, Json{{"producer_address", nullptr}}}) {
        auto damaged = ack;
        damaged.update(patch);
        assert(!qnx_vehicle_receipt(damaged, receiver, 3));
    }

    assert(!qnx_vehicle_receipt(Json(), receiver, 3) &&
           !qnx_vehicle_receipt(Json::array(), receiver, 3));
}

static void theme_consumer_acknowledgements() {
    const auto directory = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                           ("voyemu-theme-ack-test-" + random_token());

    ensure_private_directory(directory);
    const std::uint64_t mcu = 0x40001000, theme = 0x40002000, foreign = 0x40003000;
    write_private_json(
            directory / "control-owner.json",
            {{"schema", 1}, {"source", "original-MCU-input"}, {"producer_address", mcu}});
    auto path = [&](std::uint64_t address) {
        std::ostringstream name;
        name << "producer-" << std::hex << address;
        ensure_private_directory(directory / name.str());

        return directory / name.str() / "theme-ack.json";
    };
    auto receipt = [&](std::uint64_t address) {
        return Json{{"schema", 1},
                    {"sequence", 2u},
                    {"producer_address", address},
                    {"guest_acknowledged", true},
                    {"host_monotonic_ns", 1u}};
    };
    const auto theme_path = path(theme);
    write_private_json(theme_path, receipt(theme));
    assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2, 1001));
    assert(find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2).value().at("producer_address") ==
           theme);
    assert(!find_qnx_theme_receipt(directory, {mcu}, 2, 2));
    assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 0, 2));
    assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 3, 2));
    write_private_json(path(foreign), receipt(foreign));
    write_private_json(theme_path, receipt(foreign));
    assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2));

    for (const auto &patch : {Json{{"sequence", 0x100000002ULL}}, Json{{"sequence", 2.0}},
                              Json{{"guest_acknowledged", false}}, Json{{"schema", 2}}}) {
        auto bad = receipt(theme);
        bad.update(patch);
        write_private_json(theme_path, bad);
        assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2));
    }

    write_private_json(theme_path, receipt(theme));
    auto acknowledged = find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2);
    assert(acknowledged.value().at("producer_address") == theme &&
           acknowledged.value().at("status") == "guest_acknowledged" &&
           acknowledged.value().at("guest_acknowledged") == true);
    std::filesystem::remove(theme_path);
    const auto observation_path = theme_path.parent_path() / "theme-observed.json";
    Json observation{{"schema", 1},
                     {"sequence", 2u},
                     {"producer_address", theme},
                     {"source", "original-setting-getter"},
                     {"theme_id", 2u},
                     {"observed_display_theme", 2u},
                     {"request_suppressed", true}};
    observation["observed_display_theme"] = 5u;
    write_private_json(observation_path, observation);
    auto selected = find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2);
    assert(selected.value().at("status") == "already_selected" &&
           selected.value().at("guest_acknowledged") == false &&
           !selected.value().at("visible_effect_verified").get<bool>());

    for (const auto &patch :
         {Json{{"request_suppressed", false}}, Json{{"observed_display_theme", 4u}},
          Json{{"theme_id", 4u}}, Json{{"source", "unknown"}}}) {
        auto bad = observation;
        bad.update(patch);
        write_private_json(observation_path, bad);
        assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2));
    }

    write_private_json(observation_path, observation);
    write_private_json(theme_path, receipt(theme));
    assert(find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2).value().at("guest_acknowledged") ==
           true);
    std::filesystem::remove(observation_path);
    auto modern = receipt(theme);
    modern.update({{"contract", "qinggan11-611-theme-v1"},
                   {"theme_id", 4u},
                   {"theme_skin", 3002u},
                   {"observed_requested_theme", 4u},
                   {"observed_skin", 3002u}});
    write_private_json(theme_path, modern);
    assert(find_qnx_theme_receipt(directory, {mcu, theme}, 2, 4, 3002)
                   .value()
                   .at("guest_acknowledged") == true);
    assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 2, 4, 3001));
    assert(!find_qnx_theme_receipt(directory, {mcu}, 2, 4, 3002));
    assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 3, 4, 3002));

    for (const auto &patch :
         {Json{{"contract", "foreign"}}, Json{{"theme_skin", 3001u}},
          Json{{"observed_requested_theme", 6u}}, Json{{"observed_skin", 3001u}},
          Json{{"observed_skin", 4294970298ULL}}, Json{{"observed_skin", 3002.0}},
          Json{{"guest_acknowledged", false}}}) {
        auto bad = modern;
        bad.update(patch);
        write_private_json(theme_path, bad);
        assert(!find_qnx_theme_receipt(directory, {mcu, theme}, 2, 4, 3002));
    }

    std::filesystem::remove(theme_path);
    auto modern_observed = modern;
    modern_observed.erase("guest_acknowledged");
    modern_observed.update({{"source", "original-requested-theme-and-skin-getters"},
                            {"request_suppressed", false},
                            {"native_attempt_sequence", 2u},
                            {"native_outcome", "skin_ipc_failed"}});
    write_private_json(observation_path, modern_observed);
    auto partial = find_qnx_theme_receipt(directory, {mcu, theme}, 2, 4, 3002);
    assert(partial.value().at("status") == "partial_failure" &&
           !partial.value().at("guest_acknowledged").get<bool>());
    modern_observed.update({{"native_outcome", "complete"}, {"request_suppressed", true}});
    write_private_json(observation_path, modern_observed);
    auto already = find_qnx_theme_receipt(directory, {mcu, theme}, 2, 4, 3002);
    assert(already.value().at("status") == "already_selected" &&
           !already.value().at("guest_acknowledged").get<bool>());
    std::filesystem::remove(observation_path);
    write_private_json(theme_path, receipt(theme));

    // Creating a symbolic link needs a privilege on Windows.
    if (!os::host_windows) {
        std::filesystem::rename(theme_path, theme_path.string() + ".saved");
        std::filesystem::create_symlink(theme_path.filename().string() + ".saved", theme_path);
        rejects([&] {
            find_qnx_theme_receipt(directory, {mcu, theme}, 2, 2);
        });
    }

    auto language_path = [&](std::uint64_t address) {
        std::ostringstream name;
        name << "producer-" << std::hex << address;

        return directory / name.str() / "language-ack.json";
    };
    auto language_receipt = [&](std::uint64_t address) {
        return Json{{"schema", 1},
                    {"sequence", 5u},
                    {"producer_address", address},
                    {"language", 0u},
                    {"native_request_issued", true},
                    {"observed_language", 0u}};
    };
    write_private_json(language_path(theme), language_receipt(theme));
    assert(find_qnx_language_receipt(directory, {mcu, theme}, 5, 0)
                   .value()
                   .at("guest_acknowledged") == true);
    assert(find_qnx_language_receipt(directory, {mcu, theme}, 5, 0)
                   .value()
                   .at("visible_effect_verified") == true);
    assert(!find_qnx_language_receipt(directory, {mcu}, 5, 0));
    assert(!find_qnx_language_receipt(directory, {mcu, theme}, 5, 1));
    assert(!find_qnx_language_receipt(directory, {mcu, theme}, 4, 0));
    // Without a proven OEM getter observation a submission is never an observed effect.
    {
        auto bad = language_receipt(theme);
        bad["observed_language"] = 1u;
        write_private_json(language_path(theme), bad);
        const auto r = find_qnx_language_receipt(directory, {mcu, theme}, 5, 0);
        assert(r && r->at("status") == "request_issued" && r->at("guest_acknowledged") == false &&
               r->at("visible_effect_verified") == false);
    }
    {
        auto bad = language_receipt(theme);
        bad.erase("observed_language");
        write_private_json(language_path(theme), bad);
        const auto r = find_qnx_language_receipt(directory, {mcu, theme}, 5, 0);
        assert(r && r->at("status") == "request_issued");
    }
    {
        auto bad = language_receipt(theme);
        bad["native_request_issued"] = false;
        bad.erase("observed_language");
        write_private_json(language_path(theme), bad);
        assert(!find_qnx_language_receipt(directory, {mcu, theme}, 5, 0));
    }
    {
        auto bad = language_receipt(theme);
        bad["schema"] = 2;
        write_private_json(language_path(theme), bad);
        assert(!find_qnx_language_receipt(directory, {mcu, theme}, 5, 0));
    }
    std::filesystem::remove_all(directory);
}

static void lifecycle_ipc_deadlines() {
    std::atomic<bool> stopped = false;
    const auto endpoint = private_control_endpoint(random_token() + "-vld");
    {
        ControlServer server(endpoint, [](const Json &input) {
            return Json{{"op", input.at("op")}, {"payload", std::string(65536, 'x')}};
        });
        std::thread worker([&] {
            // WaitNamedPipe returns FILE_NOT_FOUND before the first instance is created.
            if (os::host_windows) {
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
            }

            server.serve(stopped);
        });
        try {
            for (const char *op : {"stop", "media_power", "test_media_power", "media_restart",
                                   "cluster_power", "cluster_restart"}) {
                assert(request(endpoint, {{"op", op}}, 90000).at("op") == op);
            }

            const auto response = request(endpoint, {{"op", "status"}}, 30000);
            assert(response.at("op") == "status" &&
                   response.at("payload") == std::string(65536, 'x'));
            rejects([&] {
                request(endpoint, {{"op", "status"}}, 30001);
            });
            rejects([&] {
                request(endpoint, {{"op", "cluster_restart"}},
                        request_timeout_limit_ms("cluster_restart") + 1);
            });

            // A request that closes a cluster also waits for the guest sync of the engine.
            for (const char *op : {"stop", "cluster_power", "cluster_restart"}) {
                assert(request_timeout_limit_ms(op) ==
                       90000 + qnx_guest_sync().count() - qnx_guest_sync(QnxEngine::hvf).count());
            }

            assert(request_timeout_limit_ms("media_power") == 90000 &&
                   request_timeout_limit_ms("machine_restart") == 180000 &&
                   request_timeout_limit_ms("status") == 30000);
        } catch (...) {
            stopped = true;
            worker.join();
            throw;
        }

        stopped = true;
        worker.join();
    }
}

static void control_server_stop_reply() {
    const auto endpoint = private_control_endpoint(random_token() + "-vsr");

    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        std::atomic<bool> stopped = false;
        ControlServer server(endpoint, [&](const Json &) {
            stopped = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(120));

            return Json{{"ok", true}, {"payload", std::string(65536, 'x')}};
        });
        std::thread serving([&] {
            server.serve(stopped);
        });
        Json response;
        try {
            response = request(endpoint, {{"op", "stop"}}, 2000);
        } catch (...) {
            stopped = true;
            serving.join();
            throw;
        }

        serving.join();
        assert(response.at("ok") == true && response.at("payload") == std::string(65536, 'x'));
    }

    control_server_idle_clients(endpoint);
}

namespace voyemu {
struct SessionInterguestSnapshotFixture {
    static void run() {
        const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                          ("voyemu-network-snapshot-" + random_token());
        const auto id = random_token();
        const auto directory = root / id;
        ensure_private_directory(directory);
        {
            Session session(directory, id);
            session.android_spec_ = {{"interguest_network", Json::object()}};
            session.interguest_link_ = std::make_unique<InterguestLink>();
            const auto port = session.interguest_link_->start(directory, id);
            const auto original = session.deliveries_;
            const auto before = session.snapshot();
            const auto network = before.at("deliveries").at("android").at("interguest_network");
            assert(network.at("port") == port && !network.at("connected").get<bool>() &&
                   network.at("fault") == "" && network.contains("received_frames") &&
                   network.contains("sent_frames") && network.contains("reconnects") &&
                   before.at("qnx_pid") == 0 && session.deliveries_ == original);
            const auto ram = directory / "qnx-ram.bin";
            create_qnx_ram(ram, 8ULL << 30);
            const std::array<std::uint32_t, 8> invalid{0xbeefeeee, 1};
            write_at(ram, 0x10010000, invalid.data(), sizeof invalid);
            session.interguest_link_->bind_ram(ram);
            const auto end = std::chrono::steady_clock::now() + event_wait;

            while (session.interguest_link_->status().fault.empty()) {
                assert(std::chrono::steady_clock::now() < end);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            const auto fault = session.snapshot()
                                       .at("deliveries")
                                       .at("android")
                                       .at("interguest_network")
                                       .at("fault")
                                       .get<std::string>();
            assert(fault.starts_with("INTERGUEST_RING:") && session.deliveries_ == original);
            session.interguest_link_->stop();
            session.interguest_link_.reset();
        }
        std::filesystem::remove_all(root);
    }
};
struct SessionRequestIoFixture {
    static bool run() {
        const auto directory = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                               ("voyemu-request-io-" + random_token());
        ensure_private_directory(directory);
        bool clean_a = false, clean_b = false, isolated_a = false, isolated_b = false,
             nested = false;
        {
            Session session(directory, random_token());
            std::mutex gate;
            std::condition_variable changed;
            unsigned phase = 0;
            auto wait = [&](unsigned n) {
                std::unique_lock lock(gate);
                assert(changed.wait_for(lock, std::chrono::seconds(5), [&] {
                    return phase >= n;
                }));
            };
            auto mark = [&](unsigned n) {
                {
                    std::lock_guard lock(gate);
                    phase = n;
                }
                changed.notify_all();
            };
            std::recursive_mutex state;
            const auto first = std::chrono::steady_clock::time_point(std::chrono::seconds(11)),
                       second = first + std::chrono::seconds(22);
            std::thread a([&] {
                std::unique_lock owner(state, std::defer_lock);
                clean_a = session.android_io_state_lock_ == nullptr &&
                          session.android_request_deadline_ ==
                                  std::chrono::steady_clock::time_point{};
                auto *old = session.android_io_state_lock_;
                auto deadline = session.android_request_deadline_;
                session.android_io_state_lock_ = &owner;
                session.android_request_deadline_ = first;
                mark(1);
                wait(2);
                isolated_a = session.android_io_state_lock_ == &owner &&
                             session.android_request_deadline_ == first;
                session.android_io_state_lock_ = old;
                session.android_request_deadline_ = deadline;
                mark(3);
            });
            std::thread b([&] {
                wait(1);
                std::unique_lock owner(state, std::defer_lock);
                clean_b = session.android_io_state_lock_ == nullptr &&
                          session.android_request_deadline_ ==
                                  std::chrono::steady_clock::time_point{};
                auto *old = session.android_io_state_lock_;
                auto deadline = session.android_request_deadline_;
                session.android_io_state_lock_ = &owner;
                session.android_request_deadline_ = second;
                {
                    std::unique_lock inner(state, std::defer_lock);
                    auto *outer = session.android_io_state_lock_;
                    auto outer_deadline = session.android_request_deadline_;
                    session.android_io_state_lock_ = &inner;
                    session.android_request_deadline_ = first;
                    session.android_io_state_lock_ = outer;
                    session.android_request_deadline_ = outer_deadline;
                    nested = session.android_io_state_lock_ == &owner &&
                             session.android_request_deadline_ == second;
                }
                mark(2);
                wait(3);
                isolated_b = session.android_io_state_lock_ == &owner &&
                             session.android_request_deadline_ == second;
                session.android_io_state_lock_ = old;
                session.android_request_deadline_ = deadline;
            });
            a.join();
            b.join();
            session.android_io_state_lock_ = nullptr;
            session.android_request_deadline_ = {};
        }
        std::filesystem::remove_all(directory);

        return clean_a && clean_b && isolated_a && isolated_b && nested;
    }
};
} // namespace voyemu

static void control_server_concurrency() {
    const auto endpoint = private_control_endpoint(random_token() + "-vcc");
    std::atomic<bool> stopped = false;
    std::mutex mutex;
    std::condition_variable changed;
    unsigned entered = 0;
    bool released = false;
    auto handler = [&](const Json &input) {
        if (input.at("op") == "test_watch_read" || input.at("op") == "blocked") {
            std::unique_lock lock(mutex);
            ++entered;
            changed.notify_all();
            changed.wait(lock, [&] {
                return released;
            });
        }

        return Json{{"ok", true}};
    };
    {
        ControlServer server(endpoint, handler);
        std::thread serving([&] {
            server.serve(stopped);
        });
        std::vector<std::future<Json>> readers;
        readers.push_back(std::async(std::launch::async, [&] {
            return request(endpoint, {{"op", "test_watch_read"}}, 5000);
        }));
        bool first = false;
        {
            std::unique_lock lock(mutex);
            first = changed.wait_for(lock, std::chrono::seconds(2), [&] {
                return entered == 1;
            });
        }
        auto quick = std::async(std::launch::async, [&] {
            return request(endpoint, {{"op", "status"}}, 2000);
        });
        const bool independent = quick.wait_for(std::chrono::seconds(1)) ==
                                 std::future_status::ready;

        if (first && independent) {
            assert(quick.get().at("ok") == true);

            for (unsigned i = 1; i < 4; ++i) {
                readers.push_back(std::async(std::launch::async, [&] {
                    return request(endpoint, {{"op", "test_watch_read"}}, 5000);
                }));
            }

            bool full = false;
            {
                std::unique_lock lock(mutex);
                full = changed.wait_for(lock, std::chrono::seconds(2), [&] {
                    return entered == 4;
                });
            }
            assert(full);
            const auto excess = request(endpoint, {{"op", "test_watch_read"}}, 2000);
            assert(excess.at("ok") == false && excess.at("error").get<std::string>().find(
                                                       "watch reader limit") != std::string::npos);
            assert(request(endpoint, {{"op", "status"}}, 2000).at("ok") == true);

            for (unsigned i = 4; i < 16; ++i) {
                readers.push_back(std::async(std::launch::async, [&] {
                    return request(endpoint, {{"op", "blocked"}}, 5000);
                }));
                std::unique_lock lock(mutex);
                assert(changed.wait_for(lock, std::chrono::seconds(2), [&] {
                    return entered == i + 1;
                }));
            }

            bool capped = false;
            {
                std::unique_lock lock(mutex);
                capped = changed.wait_for(lock, std::chrono::seconds(2), [&] {
                    return entered == 16;
                });
            }
            assert(capped);
            const auto busy = request(endpoint, {{"op", "status"}}, 2000);
            assert(busy.at("ok") == false &&
                   busy.at("error").get<std::string>().find("active connection limit") !=
                           std::string::npos);
        }

        {
            std::lock_guard lock(mutex);
            released = true;
        }
        changed.notify_all();

        for (auto &reader : readers) {
            assert(reader.get().at("ok") == true);
        }

        if (!independent) {
            try {
                quick.get();
            } catch (...) { /* Ignored: the quick request may fail when it is not independent. */
            }
        }

        stopped = true;
        serving.join();
        assert(first && independent);
    }
}

static void boot_local_android_network_tests() {
    const std::string boot = "12345678-1234-4abc-8abc-1234567890ab";
    const std::string next = "12345678-1234-4abc-8abc-1234567890ac";

    using Command = std::vector<std::string>;
    const Command fence = {"shell", "cat", "/proc/sys/kernel/random/boot_id"};
    const Command links = {
            "shell",
            R"SH(for file in /sys/class/net/*/address; do interface=${file%/address}; interface=${interface##*/}; IFS= read -r mac < "$file" || continue; printf '%s %s\n' "$interface" "$mac"; done)SH"};
    const Command address = {"shell", "ip", "-o", "-4", "addr", "show", "dev", "eth1"};
    const Command network = {"shell", "ip", "-4", "route", "show", "table", "98"};
    const Command system = {"shell", "ip", "-4", "route", "show", "table", "99"};
    const Command all = {"shell", "ip", "-4", "route", "show", "table", "all"};
    const std::vector<std::pair<Command, ProcessResult>> good = {
            {fence, {0, boot + "\n", false}},
            {links,
             {0,
              "eth0 52:54:00:76:6f:20\n"
              "eth1 52:54:00:76:6f:21\n",
              false}},
            {address, {0, "3: eth1 inet 172.16.100.21/24 scope global eth1\n", false}},
            {network, {0, "172.16.100.0/24 dev eth1 scope link\n", false}},
            {system, {0, "172.16.100.0/24 dev eth1 scope link\n", false}},
            {all, {0, "default via 10.0.2.2 dev wlan0 table 1003\n", false}},
            {fence, {0, boot + "\n", false}}};
    auto verify = [&](const auto &rows) {
        std::size_t offset = 0;

        return verify_boot_local_android_network(boot, [&](const auto &command, int timeout) {
            assert(offset < rows.size() && command == rows[offset].first && timeout == 1500);

            return rows[offset++].second;
        });
    };

    const auto proof = verify(good);
    assert(proof.at("boot_id") == boot && proof.at("interface") == "eth1" &&
           proof.at("legacy_route_tables") == Json::array({98, 99}));

    const std::vector<std::pair<std::size_t, ProcessResult>> invalid = {
            {1,
             {0,
              "eth1 52:54:00:76:6f:21\n"
              "eth2 52:54:00:76:6f:21\n",
              false}},
            {2, {0, "3: eth1 inet 172.16.100.21/32 scope global eth1\n", false}},
            {3, {0, "", true}},
            {4, {0, "172.16.100.0/24 dev eth10 scope link\n", false}},
            {5, {0, "default via 172.16.100.22 dev eth1 table 1004\n", false}},
            {6, {0, next + "\n", false}}};

    for (const auto &[index, wrong] : invalid) {
        auto rows = good;
        rows[index].second = wrong;
        bool rejected = false;

        try {
            (void)verify(rows);
        } catch (const VoyemuError &) {
            rejected = true;
        }

        assert(rejected);
    }
}

static void owned_android_network_recovery_tests() {
    const std::string first = "11111111-1111-4111-8111-111111111111",
                      second = "22222222-2222-4222-8222-222222222222", payload = "source-dex",
                      pin = sha256_bytes(payload);
    const Json inputs{{"dex_sha256", pin}, {"network", qnx_passion_interguest_contract()}};
    struct Artifact {
        std::string inode = "1234", hash;
        bool symlink = false;
        std::string owner_mode = "0:0:700", payload_mode = "0:0:600";
        std::size_t bytes = 10;
        bool regular = true;
    };
    struct Fixture {
        std::map<std::string, Artifact> files;
        std::vector<std::string> created, removed;
        std::string boot, pin,
                report =
                        "\"local_route_requested\":true,\"interface\":\"eth1\",\"network_ids\":[65000]";
        int cleanup_failures = 0, nonce_count = 0, setup_count = 0, command_count = 0;
        bool fail_setup = false, reboot_setup = false, reboot_cleanup = false,
             uncertain_mkdir = false, partial_push = false, fail_chmod = false;

        ProcessResult run(const std::vector<std::string> &args, int timeout) {
            assert(timeout > 0 && timeout <= 10000);
            ++command_count;

            if (args ==
                std::vector<std::string>{"shell", "cat", "/proc/sys/kernel/random/boot_id"}) {
                return {0, boot + "\n", false};
            }

            if (args[0] == "push") {
                auto &file = files.at(args.at(2).substr(0, args.at(2).rfind('/')));
                file.hash = partial_push ? sha256_bytes("sour") : pin;
                file.bytes = partial_push ? 4 : 10;
                file.payload_mode = "0:0:644";

                return partial_push ? ProcessResult{1, "partial push\n", false}
                                    : ProcessResult{0, "1 file pushed\n", false};
            }

            if (args.size() == 4 && args[1] == "chmod") {
                if (fail_chmod) {
                    return {1, "chmod denied\n", false};
                }

                files.at(args.at(3).substr(0, args.at(3).rfind('/'))).payload_mode = "0:0:600";

                return {0, "", false};
            }

            if (args.size() == 3 && args[1] == "sha256sum") {
                return {0, pin + "  " + args[2] + "\n", false};
            }

            assert(args.size() == 2 && args[0] == "shell");
            const auto &script = args[1];

            if (script.starts_with("umask 077; mkdir '")) {
                const auto begin = script.find('\'') + 1, end = script.find('\'', begin);
                const auto path = script.substr(begin, end - begin);

                if (files.contains(path)) {
                    return {1, "mkdir: File exists\n", false};
                }

                files.emplace(path, Artifact{"1234", {}, false});
                created.push_back(path);

                if (uncertain_mkdir) {
                    return {-1, "", true};
                }

                return {0, "0:0:700:1234\n", false};
            }

            if (script.starts_with("d='")) {
                const auto path = script.substr(3, script.find('\'', 3) - 3);
                assert(script.find("[ ! -L \"$d\" ]") != std::string::npos &&
                       script.find("stat -c '%u:%g:%a:%i'") != std::string::npos);
                assert(script.find("find \"$d\" -type l -print") != std::string::npos &&
                       script.find("find \"$d\" ! -user root -print") != std::string::npos);

                if (script.find("rm -rf") == std::string::npos) {
                    if (!files.contains(path)) {
                        return {0, "ABSENT\n", false};
                    }

                    const auto &file = files.at(path);

                    if (file.symlink || !file.regular || file.owner_mode != "0:0:700" ||
                        script.find("0:0:700:" + file.inode + "'") == std::string::npos) {
                        return {71, "identity rejected\n", false};
                    }

                    return file.hash.empty() ? ProcessResult{0, "EMPTY\n", false}
                                             : ProcessResult{0,
                                                             file.payload_mode + ":" +
                                                                     std::to_string(file.bytes) +
                                                                     ":5678\n" + file.hash + "  " +
                                                                     path + "/classes.dex\n",
                                                             false};
                }

                if (cleanup_failures-- > 0) {
                    return {1, "rm: Permission denied\n", false};
                }

                if (files.contains(path)) {
                    const auto &file = files.at(path);

                    if (file.symlink || file.owner_mode != "0:0:700" ||
                        script.find("0:0:700:" + file.inode + "'") == std::string::npos ||
                        (!file.hash.empty() &&
                         (script.find(file.hash) == std::string::npos ||
                          script.find(file.payload_mode) == std::string::npos))) {
                        return {73, "identity rejected\n", false};
                    }

                    files.erase(path);
                    removed.push_back(path);
                }

                if (reboot_cleanup) {
                    boot = "33333333-3333-4333-8333-333333333333";
                }

                return {0, "", false};
            }

            assert(script.find("com.voyemu.api.NetworkSetup 172.30.100.3") != std::string::npos);
            ++setup_count;

            if (reboot_setup) {
                boot = "33333333-3333-4333-8333-333333333333";
            }

            if (fail_setup) {
                return {9, "original helper failure\n", false};
            }

            return {0,
                    "VOYEMU_NETWORK_V1 {\"schema\":1,\"ok\":true,\"address\":\"172.30.100.3\",\"prefix\":24," +
                            report + "}\n",
                    false};
        }

        std::string nonce() {
            return std::string(31, '0') + char('0' + (++nonce_count));
        }
    };
    auto configure = [&](Fixture &f, const std::string &boot, Json &android,
                         std::vector<AndroidNetworkArtifact> &pending, const Json &manifest) {
        configure_owned_android_network(
                boot, "/prepared/classes.dex", pin, payload, manifest, android, pending,
                [&](const auto &args, int timeout) {
                    return f.run(args, timeout);
                },
                [&] {
                    return f.nonce();
                });
    };
    {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        configure(f, first, android, pending, inputs);
        assert(pending.empty() && f.setup_count == 1 && f.files.empty());
        const auto commands = f.command_count;
        configure(f, first, android, pending, inputs);
        assert(f.command_count == commands + 2 &&
               f.nonce_count == 1); // Boot fences only; no periodic redeployment.
        auto changed = inputs;
        changed["dex_sha256"] = std::string(64, 'b');
        configure(f, first, android, pending, changed);
        assert(f.setup_count == 2);
        f.boot = second;
        configure(f, second, android, pending, inputs);
        assert(f.setup_count == 3 && android["interguest_network"]["boot_id"] == second &&
               f.created[0] != f.created[2]);
        f.boot = first;
        rejects([&] {
            configure(f, second, android, pending, inputs);
        });
        assert(!android.contains("interguest_network") && f.setup_count == 3 && f.nonce_count == 3);
    }

    // The OEM EthernetService owns eth0: the report verifies the address and requests no route.
    for (const auto &[report, accepted] : std::vector<std::pair<std::string, bool>>{
                 {"\"local_route_requested\":false,\"interface\":\"eth0\",\"network_ids\":[]",
                  true},
                 {"\"local_route_requested\":true,\"interface\":\"eth0\",\"network_ids\":[]",
                  false},
                 {"\"local_route_requested\":false,\"interface\":\"eth1\",\"network_ids\":[65000]",
                  false}}) {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.report = report;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        bool configured = true;
        try {
            configure(f, first, android, pending, inputs);
        } catch (const std::exception &) {
            configured = false;
        }

        assert(configured == accepted && f.setup_count == 1 && f.files.empty());
        assert(!accepted || (android["interguest_network"]["interface"] == "eth0" &&
                             android["interguest_network"]["network_ids"].empty()));
    }

    {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.fail_setup = true;
        f.cleanup_failures = 10;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        std::string error;
        try {
            configure(f, first, android, pending, inputs);
        } catch (const std::exception &e) {
            error = e.what();
        }

        assert(error == "INTERGUEST_ANDROID: owned startup command failed" && pending.size() == 1 &&
               android["interguest_network_failure"]["exit_code"] == 9 &&
               android["interguest_network_failure"]["output"] == "original helper failure\n");
        assert(android["interguest_network_cleanup"]["exit_code"] == 1 &&
               android["interguest_network_cleanup"]["timed_out"] == false);
        android["interguest_network"] = {
                {"boot_id", first}, {"inputs", inputs}, {"status", "configured"}};
        f.boot = second;
        rejects([&] {
            configure(f, second, android, pending, inputs);
        });
        assert(!android.contains("interguest_network") && pending.size() == 1 &&
               f.nonce_count == 1); // Pending failure is fail-closed.
        f.cleanup_failures = 0;
        f.fail_setup = false;
        configure(f, second, android, pending, inputs);
        assert(pending.empty() && f.created.size() == 2 && f.removed.size() == 2 &&
               f.created[0] != f.created[1] && android["interguest_network"]["boot_id"] == second);
        assert(!android.contains("interguest_network_failure") &&
               android["interguest_network_last_failure"]["exit_code"] == 9 &&
               android["interguest_network_last_failure"]["boot_id"] == first &&
               android["interguest_network_cleanup"]["status"] == "recovered");
    }
    {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.fail_setup = true;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(android["interguest_network_failure"]["boot_id"] == first);
        f.boot = second;
        rejects([&] {
            configure(f, second, android, pending, inputs);
        });
        assert(android["interguest_network_failure"]["boot_id"] == second &&
               android["interguest_network_last_failure"]["boot_id"] == first);
        f.fail_setup = false;
        configure(f, second, android, pending, inputs);
        assert(!android.contains("interguest_network_failure") &&
               android["interguest_network_last_failure"]["boot_id"] == second &&
               android["interguest_network_last_failure"]["status"] == "recovered");
        android["interguest_network_failure"] = {{"exit_code", 136}, {"boot_id", second}};
        configure(f, second, android, pending, inputs);
        assert(!android.contains("interguest_network_failure") &&
               android["interguest_network_last_failure"]["boot_id"] == second &&
               android["interguest_network_last_failure"]["status"] == "recovered");
        android["interguest_network_failure"] = {{"exit_code", 136},
                                                 {"output", "old unscoped failure"}};
        configure(f, second, android, pending, inputs);
        assert(!android.contains("interguest_network_failure") &&
               android["interguest_network_last_failure"]["exit_code"] == 136 &&
               !android["interguest_network_last_failure"].contains("boot_id"));
    }

    for (const auto &corruption :
         {std::string{"inode"}, std::string{"hash"}, std::string{"symlink"},
          std::string{"owner-mode"}, std::string{"payload-mode"}}) {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.fail_setup = true;
        f.cleanup_failures = 10;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        auto &file = f.files.at(pending.front().path);

        if (corruption == "inode") {
            file.inode = "9999";
        } else if (corruption == "hash") {
            file.hash = std::string(64, 'b');
        } else if (corruption == "symlink") {
            file.symlink = true;
        } else if (corruption == "owner-mode") {
            file.owner_mode = "2000:2000:755";
        } else {
            file.payload_mode = "0:0:644";
        }

        f.cleanup_failures = 0;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(f.removed.empty() && pending.size() == 1 && f.nonce_count == 1);
    }

    {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        const auto unknown = "/data/local/tmp/voyemu-network-" + std::string(31, '0') + '1';
        f.files.emplace(unknown, Artifact{"2222", "foreign", false});
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(pending.empty() && f.removed.empty() && f.files.at(unknown).hash == "foreign");
        configure(f, first, android, pending, inputs);
        assert(f.files.contains(unknown) &&
               f.created.size() == 1); // Fresh nonce does not touch unknown legacy path.
    }

    for (bool cleanup_reboot : {false, true}) {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.reboot_setup = !cleanup_reboot;
        f.reboot_cleanup = cleanup_reboot;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(!android.contains("interguest_network") &&
               pending.size() == (cleanup_reboot ? 0 : 1));
        f.reboot_setup = false;
        f.reboot_cleanup = false;
        const auto observed_boot = f.boot;
        configure(f, observed_boot, android, pending, inputs);
        assert(pending.empty() && android["interguest_network"]["boot_id"] == observed_boot);
    }

    {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.reboot_cleanup = true;
        const auto path = "/data/local/tmp/voyemu-network-" + std::string(32, 'a');
        f.files.emplace(path, Artifact{"1234", pin, false});
        Json android{{"interguest_network",
                      {{"boot_id", first}, {"inputs", inputs}, {"status", "configured"}}}};
        std::vector<AndroidNetworkArtifact> pending{{path, "1234", pin, payload, true}};
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(!android.contains("interguest_network") && pending.empty() && f.setup_count == 0 &&
               f.nonce_count == 0);
    }

    for (bool partial_push : {false, true}) {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.partial_push = partial_push;
        f.fail_chmod = !partial_push;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(pending.empty() &&
               f.removed.size() ==
                       1); // Exact pinned prefix/full transfer, before execution, is removable.
        f.partial_push = false;
        f.fail_chmod = false;
        configure(f, first, android, pending, inputs);
        assert(pending.empty() && f.setup_count == 1);
    }

    for (unsigned corruption = 0; corruption < 6; ++corruption) {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        const auto path = "/data/local/tmp/voyemu-network-" + std::string(32, 'a');
        Artifact file{"1234", sha256_bytes("sour"), false, "0:0:700", "0:0:644", 4};

        if (corruption == 0) {
            file.hash = sha256_bytes("soux");
        }

        if (corruption == 1) {
            file.hash = std::string(64, 'b');
        }

        if (corruption == 2) {
            file.bytes = 11;
        }

        if (corruption == 3) {
            file.symlink = true;
        }

        if (corruption == 4) {
            file.payload_mode = "0:0:666";
        }

        if (corruption == 5) {
            file.regular = false;
        }

        f.files.emplace(path, file);
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending{{path, "1234", pin, payload, false}};
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(pending.size() == 1 && f.removed.empty() && f.nonce_count == 0);
    }

    {
        Fixture f;
        f.boot = first;
        f.pin = pin;
        f.uncertain_mkdir = true;
        Json android = Json::object();
        std::vector<AndroidNetworkArtifact> pending;
        rejects([&] {
            configure(f, first, android, pending, inputs);
        });
        assert(f.removed.empty() && pending.empty() && f.files.size() == 1 &&
               android["interguest_network_failure"]["timed_out"] == true);
    }
}

static void owned_adbd_bootstrap_tests() {
    std::string retained;
    const std::string first = "11111111-1111-4111-8111-111111111111",
                      second = "22222222-2222-4222-8222-222222222222";

    assert(!observe_android_boot(retained, first));
    bool attempted = true, ready = true;
    auto observe = [&](const std::string &boot) {
        if (observe_android_boot(retained, boot)) {
            attempted = false;
            ready = false;
        }
    };
    observe(first);
    assert(attempted && ready); // Same-boot adbd UID drop must not reset startup privileges.
    observe(second);
    assert(!attempted && !ready);
    attempted = true;
    ready = true;
    observe(second);
    assert(attempted && ready);
    rejects([&] {
        observe("invalid");
    });
    assert(retained == second && attempted && ready);

    std::vector<std::vector<std::string>> calls;
    bool root = false;
    bool ownership = true;
    int identities = 0;
    bool enforcing = true;
    auto run = [&](const std::vector<std::string> &args, int timeout) {
        assert(timeout > 0 && timeout <= 1000);
        calls.push_back(args);
        ProcessResult r{};
        r.exit_code = 0;

        if (args == std::vector<std::string>{"shell", "id", "-u"}) {
            r.output = root ? "0\n" : "2000\n";
        } else if (args == std::vector<std::string>{"root"}) {
            root = true;
        } else if (args == std::vector<std::string>{"shell", "getenforce"}) {
            r.output = enforcing ? "Enforcing\n" : "Permissive\n";
        } else {
            assert(args == std::vector<std::string>{"wait-for-device"});
        }

        return r;
    };
    auto owned = [&]() {
        return ownership;
    };
    auto identity = [&](int timeout) {
        assert(timeout > 0);
        ++identities;
    };
    bootstrap_owned_adbd(run, owned, identity, 1000);
    assert(root && identities == 4);
    assert(std::count(calls.begin(), calls.end(), std::vector<std::string>{"root"}) == 1);
    assert(std::count(calls.begin(), calls.end(), std::vector<std::string>{"wait-for-device"}) ==
           1);
    calls.clear();
    identities = 0;
    bootstrap_owned_adbd(run, owned, identity, 1000);
    assert(identities == 2 && calls.size() == 2);
    calls.clear();
    ownership = false;
    rejects([&] {
        bootstrap_owned_adbd(run, owned, identity, 1000);
    });
    assert(calls.empty());
    ownership = true;
    calls.clear();
    rejects([&] {
        bootstrap_owned_adbd(
                run, owned,
                [](int) {
                    throw std::runtime_error("nonce mismatch");
                },
                1000);
    });
    assert(calls.empty());
    enforcing = false;
    rejects([&] {
        bootstrap_owned_adbd(run, owned, identity, 1000);
    });
    enforcing = true;
    root = false;
    calls.clear();
    auto fails_root = [&](const std::vector<std::string> &args, int timeout) {
        if (args == std::vector<std::string>{"root"}) {
            ProcessResult r{};
            r.exit_code = 1;

            return r;
        }

        return run(args, timeout);
    };
    rejects([&] {
        bootstrap_owned_adbd(fails_root, owned, identity, 1000);
    });
    assert(std::count(calls.begin(), calls.end(), std::vector<std::string>{"wait-for-device"}) ==
           0);
    root = false;
    calls.clear();
    auto stays_shell = [&](const std::vector<std::string> &args, int timeout) {
        auto r = run(args, timeout);

        if (args == std::vector<std::string>{"root"}) {
            root = false;
        }

        return r;
    };
    rejects([&] {
        bootstrap_owned_adbd(stays_shell, owned, identity, 1000);
    });
    // Installer adbd restarts can interrupt observation without changing the guest.
    root = false;
    calls.clear();
    int unavailable = 2;
    auto delayed_identity = [&](int timeout) {
        if (unavailable-- > 0) {
            throw std::runtime_error("ANDROID_IDENTITY_NOT_READY: transport restarting");
        }

        identity(timeout);
    };
    int read_failures = 2;
    auto delayed_read = [&](const std::vector<std::string> &args, int timeout) {
        if (args == std::vector<std::string>{"shell", "id", "-u"} && read_failures-- > 0) {
            ProcessResult r{};
            r.exit_code = 1;

            return r;
        }

        return run(args, timeout);
    };
    bootstrap_owned_adbd(delayed_read, owned, delayed_identity, 1000);
    assert(root && std::count(calls.begin(), calls.end(), std::vector<std::string>{"root"}) == 1);
    root = false;
    calls.clear();
    int after_root_failures = 2;
    auto after_root_identity = [&](int timeout) {
        if (root && after_root_failures-- > 0) {
            throw std::runtime_error(
                    "ANDROID_IDENTITY_NOT_READY: boot read temporarily unavailable");
        }

        identity(timeout);
    };
    bootstrap_owned_adbd(run, owned, after_root_identity, 1000);
    assert(root && std::count(calls.begin(), calls.end(), std::vector<std::string>{"root"}) == 1);
    root = false;
    calls.clear();
    auto rebooted_identity = [&](int timeout) {
        if (root) {
            throw std::runtime_error(
                    "ANDROID_IDENTITY_MISMATCH: guest rebooted during SDK bootstrap");
        }

        identity(timeout);
    };
    rejects([&] {
        bootstrap_owned_adbd(run, owned, rebooted_identity, 1000);
    });
    assert(std::count(calls.begin(), calls.end(), std::vector<std::string>{"root"}) == 1);
    root = false;
    calls.clear();
    int root_submissions = 0;
    auto ambiguous_root = [&](const std::vector<std::string> &args, int timeout) {
        if (args == std::vector<std::string>{"root"}) {
            ++root_submissions;
            ProcessResult r{};
            r.timed_out = true;

            return r;
        }

        return run(args, timeout);
    };
    rejects([&] {
        bootstrap_owned_adbd(ambiguous_root, owned, identity, 1000);
    });
    assert(root_submissions == 1);
    calls.clear();
    int missing_identity = 0;
    rejects([&] {
        bootstrap_owned_adbd(
                run, owned,
                [&](int) {
                    ++missing_identity;
                    throw std::runtime_error("ANDROID_IDENTITY_NOT_READY: unavailable");
                },
                40);
    });
    assert(missing_identity > 0 && calls.empty());
    root = false;
    calls.clear();
    auto loses_owner = [&](const std::vector<std::string> &args, int timeout) {
        auto r = run(args, timeout);

        if (args == std::vector<std::string>{"root"}) {
            ownership = false;
        }

        return r;
    };
    rejects([&] {
        bootstrap_owned_adbd(loses_owner, owned, identity, 1000);
    });
    ownership = true;
}

static void app_launch_guards() {
    const std::string boot = "01234567-89ab-cdef-0123-456789abcdef";
    unsigned calls = 0, fences = 0;
    std::vector<std::vector<std::string>> commands;
    auto fence = [&]() {
        ++fences;

        return boot;
    };
    auto run = [&](const std::vector<std::string> &args, int) {
        ++calls;
        commands.push_back(args);

        return ProcessResult{0,
                             calls % 2 ? "org.example.app/.Main\n"
                                       : "Starting: Intent { cmp=org.example.app/.Main }\n",
                             false};
    };

    for (const auto &package : {"org.example;id", "org.example$HOME", "-n", "org..app",
                                "org.example/app", "org.example\napp"}) {
        rejects([&] {
            launch_android_app(package, "primary", boot, "", 0, fence, run);
        });
    }

    assert(calls == 0);
    rejects([&] {
        launch_android_app("org.example.app", "cluster", boot, "", 0, fence, run);
    });
    rejects([&] {
        launch_android_app("org.example.app", "primary", "stale", "", 0, fence, run);
    });
    rejects([&] {
        launch_android_app("org.example.app", "secondary", boot, "", 0, fence, run);
    });
    rejects([&] {
        launch_android_app("org.example.app", "primary", boot, "foreign.app/.Main", 0, fence, run);
    });
    assert(calls == 0);
    auto result = launch_android_app("org.example.app", "secondary", boot, "org.example.app/.Main",
                                     7, fence, run);
    assert(result.at("display_id") == 7 && result.at("accepted") == true &&
           result.at("visible_effect_verified") == false && calls == 2 && fences >= 3);
    assert(commands[0][commands[0].size() - 2] == "-n" && commands[1][6] == "7");

    for (const auto &requested : {std::string{}, std::string("org.example.app/.Main")}) {
        unsigned brief_calls = 0;
        auto brief = [&](const auto &, int) {
            return ++brief_calls == 1
                           ? ProcessResult{0,
                                           "priority=0 preferredOrder=0 match=0x0 specificIndex=-1 isDefault=false\norg.example.app/.Main\n",
                                           false}
                           : ProcessResult{0, "Starting: Intent { cmp=org.example.app/.Main }\n",
                                           false};
        };
        auto brief_result = launch_android_app("org.example.app", "primary", boot, requested, 0,
                                               fence, brief);
        assert(brief_calls == 2 &&
               brief_result.at("component") == "org.example.app/org.example.app.Main");
    }

    unsigned mismatch_calls = 0;
    auto mismatch = [&](const auto &, int) {
        ++mismatch_calls;

        return ProcessResult{0, "priority=0\norg.example.app/.Other\n", false};
    };
    rejects([&] {
        launch_android_app("org.example.app", "primary", boot, "org.example.app/.Main", 0, fence,
                           mismatch);
    });
    assert(mismatch_calls == 1);
    calls = 0;
    unsigned boundary = 0;
    auto changed = [&]() {
        return ++boundary == 1 ? boot : std::string("fedcba98-7654-3210-fedc-ba9876543210");
    };
    rejects([&] {
        launch_android_app("org.example.app", "primary", boot, "", 0, changed, run);
    });
    assert(calls == 1);
    calls = 0;
    auto foreign = [&]() {
        return std::string("fedcba98-7654-3210-fedc-ba9876543210");
    };
    rejects([&] {
        launch_android_app("org.example.app", "primary", boot, "", 0, foreign, run);
    });
    assert(calls == 0);

    for (const auto &response :
         {"No activity found\n", "foreign.app/.Main\n", "org.example.app/.Main;id\n",
          "org.example.app/.Main\norg.example.app/.Other\n"}) {
        unsigned count = 0;
        auto unresolved = [&](const auto &, int) {
            ++count;

            return ProcessResult{0, response, false};
        };
        rejects([&] {
            launch_android_app("org.example.app", "primary", boot, "", 0, fence, unresolved);
        });
        assert(count == 1);
    }

    unsigned count = 0;
    auto timeout = [&](const auto &, int) {
        ++count;

        return count == 1 ? ProcessResult{0, "org.example.app/.Main\n", false}
                          : ProcessResult{-1, "", true};
    };
    try {
        launch_android_app("org.example.app", "primary", boot, "", 0, fence, timeout);
        assert(false);
    } catch (const std::exception &e) {
        assert(std::string(e.what()).starts_with("APP_LAUNCH_UNKNOWN:"));
    }

    assert(count == 2);
}

static void qnx_owned_ram_read_guards() {
    const auto directory = std::filesystem::current_path() / ".local/build" /
                           ("voyemu-owned-ram-read-" + random_token());

    ensure_private_directory(directory);
    {
        Session session(directory, random_token());
        std::array<std::byte, 8> bytes{};
        assert(!session.read_owned_qnx_ram(0x40000000, bytes));
        rejects([&] {
            session.read_owned_qnx_ram(0x3fffffff, bytes);
        });
        rejects([&] {
            session.read_owned_qnx_ram(0x240000000ULL, bytes);
        });
        rejects([&] {
            session.read_owned_qnx_ram(0x23ffffffcULL, bytes);
        });
        rejects([&] {
            session.read_owned_qnx_ram(UINT64_MAX, bytes);
        });
        rejects([&] {
            session.read_owned_qnx_ram(0x40000000, {});
        });
        std::vector<std::byte> excessive(0x40001);
        rejects([&] {
            session.read_owned_qnx_ram(0x40000000, excessive);
        });
        session.stop();
        assert(!session.read_owned_qnx_ram(0x40000000, bytes));
    }
    std::filesystem::remove_all(directory);
}

static void owned_adb_route_contract() {
    Json spec = {{"adb", "fixture-adb"}, {"port", 5574}};

    rejects([&] {
        android_adb_process(spec, {"shell", "true"});
    });
    spec["owned_adb"] = {{"schema", 1},
                         {"owner", std::string(32, 'a')},
                         {"server_pid", 123},
                         {"server_port", 25574},
                         {"grpc_port", 35574}};
    assert(android_adb_serial(spec) == "emulator-5574");
    const auto command = android_adb_process(spec, {"shell", "true"});
    assert(command.arguments == std::vector<std::string>({"-H", "127.0.0.1", "-P", "25574", "-s",
                                                          "emulator-5574", "shell", "true"}));
    assert(command.environment.at("ADB_MDNS") == "0");
    spec["owned_adb"]["server_pid"] = 0;
    rejects([&] {
        android_adb_process(spec, {"shell", "true"});
    });
    spec.erase("adb");
    spec["owned_adb"] = {{"schema", 1},
                         {"owner", std::string(32, 'a')},
                         {"console_port", 5574},
                         {"adbd_port", 5575}};
    assert(android_adb_serial(spec) == "emulator-5574");
    spec["owned_adb"]["adbd_port"] = 5037;
    rejects([&] {
        android_adb_serial(spec);
    });
}

static void qnx_startup_diagnostics_retained() {
    std::set<std::string> seen;
    std::string console =
            "QMC CHILD exit=userdata-data code=0\nQSTORE FAIL supervisor-config step=initialize-flags errno=22\nQSTORE READY root=ro userdata=persistent\nunknown guest bytes\nQSTOREX rejected\n";
    const auto retained = qnx_startup_markers(console, seen);

    console.clear();
    assert(retained ==
           std::vector<std::string>({"QMC CHILD exit=userdata-data code=0",
                                     "QSTORE FAIL supervisor-config step=initialize-flags errno=22",
                                     "QSTORE READY root=ro userdata=persistent"}));
    assert(qnx_startup_markers(retained[1] + "\n", seen).empty());
    assert(qnx_startup_markers("QSTORE " + std::string(250, 'x') + "\n", seen).empty());
    assert(qnx_startup_markers("QIP old\nQC1 old\n", seen).size() == 2);

    while (seen.size() < 512) {
        seen.insert("retained-" + std::to_string(seen.size()));
    }

    assert(qnx_startup_markers("QSTORE FAIL supervisor-config step=authority errno=13\n", seen)
                   .empty());
}

// The console ring of the live TCG run of free-09-chinese-20260106-6.0.3 on Linux: the hypervisor
// writes its lines in pieces between complete CRLF lines of the guest runtime.
static void qnx_startup_markers_interleaved() {
    std::set<std::string> seen;
    const std::string ring = "QMC WAIT initial_sleep before\r\n"
                             "[tid=3]process_a_cmd:396 SpawnQMC WAIT initial_sleep after\r\n"
                             "eQMC WAIT ram_driver before\r\n"
                             "d \"mq\", piQMC RAM driver-ready=1\r\n"
                             "40981QMC RAM begin raw-system-offset=32768 readonly\r\n"
                             "[tid=3]process_gptlink:69 FaQMC RAM parent-alive=49171\r\n"
                             "r(/dev/disk/uda0dumping 4096 bytes of memory at 0x3f04580000\r\n"
                             "QMC CHILD begin=animation-ready\r\n"
                             "QMC \r\nQIP\r\nQMC CHILD\x01 begin=files\r\nQSTOREX rejected\r\n"
                             "QIP IPC service-ready=rpc";

    assert(qnx_startup_markers(ring, seen) ==
           std::vector<std::string>(
                   {"QMC WAIT initial_sleep before", "QMC WAIT initial_sleep after",
                    "QMC WAIT ram_driver before", "QMC RAM driver-ready=1",
                    "QMC RAM begin raw-system-offset=32768 readonly", "QMC RAM parent-alive=49171",
                    "QMC CHILD begin=animation-ready"}));
    // The last line is complete once its LF arrives; the earlier lines are not repeated.
    assert(qnx_startup_markers(ring + "d\r\n", seen) ==
           std::vector<std::string>({"QIP IPC service-ready=rpcd"}));
}

// A pinned graphics launch names the ANGLE libraries of the Emulator of this host.
static void graphics_launch_angle_pins() {
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-angle-pins-" + random_token());
    const auto angle = root / "angle";

    ensure_private_directory(root);
    ensure_private_directory(angle);
    const auto worker = root / "worker";
    { std::ofstream(worker) << "worker"; }
    Json spec{{"schema", 1},
              {"pins", Json::array({{{"path", worker.string()}, {"sha256", sha256_file(worker)}}})},
              {"graphics", {{"executable", worker.string()}, {"angle", angle.string()}}}};

    for (const auto *name : {"libEGL", "libGLESv2"}) {
        const auto library = angle / (name + std::string(os::shared_library_suffix));
        { std::ofstream(library) << name; }
        spec["pins"].push_back({{"path", library.string()}, {"sha256", sha256_file(library)}});
    }

    session_detail::validate_pins(spec);
    spec["pins"].erase(spec["pins"].size() - 1);
    rejects([&] {
        session_detail::validate_pins(spec);
    });
    std::filesystem::remove_all(root);
}

// A session of a qinggan11 machine works on the 736 fields of the qinggan11 catalogue: status,
// patch and the power state read and write its fields, and qinggan09 fields are unknown.
static void qinggan11_vehicle_catalog() {
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("voyemu-qinggan11-catalog-" + random_token());

    ensure_private_directory(root);
    {
        Session session(root, random_token(), {}, VehicleCatalog::qinggan11);
        auto status = session.handle({{"op", "status"}});
        assert(status["catalog"].size() == 736 &&
               status["state"]["map_sha256"] == qinggan11_map_sha256 &&
               status["state"]["raw_oem"]["vcu_ready"] == 1);
        auto patched = session.handle({{"op", "patch"}, {"values", {{"ADCU_TargetType_1", 3}}}});
        assert(patched["ok"] == true && patched["state"]["raw_oem"]["ADCU_TargetType_1"] == 3);
        auto foreign = session.handle({{"op", "patch"}, {"values", {{"mrr_vSetDis", 1}}}});
        assert(foreign["ok"] == false);
        // The power state ON clears ready_lamp and with it the READY flag of the VCU.
        auto on = session.handle({{"op", "patch"}, {"values", {{"power", "on"}}}});
        assert(on["ok"] == true && on["state"]["raw_oem"]["ready_lamp"] == 0 &&
               on["state"]["raw_oem"]["vcu_ready"] == 0 && on["state"]["raw_oem"]["ign"] == 1);
        auto ready = session.handle({{"op", "patch"}, {"values", {{"power", "ready"}}}});
        assert(ready["state"]["raw_oem"]["vcu_ready"] == 1);
    }
    std::filesystem::remove_all(root);
}

int main(int argc, char **argv) try {
    if (argc == 2 && std::string_view(argv[1]) == "--screen-stream-worker-fixture") {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        return 0;
    }

    if (argc == 1) {
        SessionPersistenceFixture::screen_stream_handoff(std::filesystem::canonical(argv[0]));
    }

    if (const auto code = persistence_qmp_fixture(argc, argv)) {
        return *code;
    }

    // The wheel pair flush belongs to the Android startup transaction of Windows.
    if (os::host_windows) {
        if (argc == 2 && std::string_view(argv[1]) == "--windows-wheel-pair-flush-only") {
            SessionPersistenceFixture::wheel_pair_flush_run();

            return 0;
        }

        if (argc == 1) {
            SessionPersistenceFixture::wheel_pair_flush_run();
        }
    }

    if (argc == 2 && std::string_view(argv[1]) == "--socket-root-only") {
        project_socket_root_guard();

        return 0;
    }

    qnx_startup_diagnostics_retained();
    qnx_startup_markers_interleaved();
    graphics_launch_angle_pins();
    qnx_vehicle_receipts();
    qinggan11_vehicle_catalog();
    SessionPersistenceFixture::vehicle_receiver_lifecycle();
    SessionPersistenceFixture::cluster_language_single_source();

    if (argc == 2 && std::string_view(argv[1]) == "--qnx-vehicle-receiver-only") {
        return 0;
    }

    if (argc == 2 && std::string_view(argv[1]) == "--qnx-startup-diagnostics-only") {
        return 0;
    }

    if (argc == 2 && std::string_view(argv[1]) == "--avd-relocation-only") {
        android_avd_relocation_guards();

        return 0;
    }

    // The automatic reboot fixture covers the QNX engines of macOS and Windows.
    const bool reboot_fixture = os::platform_name != "Linux";

    if (reboot_fixture) {
        if (argc >= 8 && std::string_view(argv[1]) == "--qnx-shutdown-fixture") {
            return shutdown_fixture::run(argc, argv);
        }

        if (argc == 2 && std::string_view(argv[1]) == "--qnx-reboot-only") {
            SessionPersistenceFixture::reboot_run(std::filesystem::canonical(argv[0]));

            return 0;
        }
    }

    // QMP over loopback TCP pauses the persistence of Windows; the POSIX fixtures drive Unix
    // sockets, descriptors and /bin/sh children.
    if (os::host_windows) {
        SessionPersistenceFixture::qmp_pause_run(std::filesystem::canonical(argv[0]));
    } else {
        if (argc == 2 && std::string_view(argv[1]) == "--qnx-uart-ready-only") {
            SessionPersistenceFixture::uart_ready_run();

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--qnx-never-attached-only") {
            SessionPersistenceFixture::never_attached_close_run(
                    std::filesystem::canonical(argv[0]));

            return 0;
        }

        if (argc == 2 && std::string_view(argv[1]) == "--qnx-acceptance-discard-only") {
            SessionPersistenceFixture::acceptance_discard_run();

            return 0;
        }

        SessionPersistenceFixture::spontaneous_android_exit_closes_frontend();
        SessionPersistenceFixture::unbounded_restart_preflight();
        SessionPersistenceFixture::uart_ready_run();
        SessionPersistenceFixture::run(std::filesystem::canonical(argv[0]));
        SessionPersistenceFixture::never_attached_close_run(std::filesystem::canonical(argv[0]));
        SessionPersistenceFixture::acceptance_discard_run();
    }

    if (reboot_fixture) {
        SessionPersistenceFixture::reboot_run(std::filesystem::canonical(argv[0]));
    }

    if (argc == 2 && std::string(argv[1]) == "--qnx-persistence-only") {
        return 0;
    }

    // The fixture replaces the RAM file under an open collector, which POSIX allows.
    if (!os::host_windows) {
        qnx_ready_survives_blocked_android();
    }

    {
        std::vector<std::string> renamed{"--fixture"};
        program_mode("/tmp/renamed-voyemu", "_window", renamed, true);
        assert(renamed == std::vector<std::string>({"_window", "--fixture"}));
        std::vector<std::string> custom{"--fixture"};
        program_mode("/tmp/custom-backend", "_graphics", custom);
        assert(custom == std::vector<std::string>({"--fixture"}));
        assert(builtin_program_name("/previous/location/voyemu") &&
               !builtin_program_name("/tmp/custom-backend"));
    }

    if (!android_emulator_home_guards()) {
        return 1;
    }

    owned_adb_route_contract();
    qnx_owned_ram_read_guards();
    android_nonce_authority();
    observer_metadata_after_exchanged_shutdown();
    owned_adbd_bootstrap_tests();
    boot_local_android_network_tests();
    owned_android_network_recovery_tests();
    control_server_stop_reply();
    control_server_early_busy_reply();

    // The request I/O state and interguest snapshot fixtures are acceptance of the Windows host.
    if (os::host_windows) {
        assert(SessionRequestIoFixture::run());
        SessionInterguestSnapshotFixture::run();
    }

    control_server_concurrency();
    lifecycle_ipc_deadlines();
    project_socket_root_guard();
    android_avd_config_guards();
    android_avd_relocation_guards();
    const std::string display =
            "Display 0:\n mPrimaryDisplayDevice=Built-in Screen\nDisplay 4:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state ON\n";
    const std::string visible =
            "Window #0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n mDisplayId=4 isOnScreen=true\n";
    assert(secondary_display_ready(display, visible) == 4);
    // API28 OEM secondary HOME: wake_displays() uses the GENERIC parser for this profile id, so
    // these rows only prove the parser's own admission rules on a hand-written fixture:
    //  * it accepts a hand-written Display 1 block carrying the emulator provider identity,
    //  * it yields no display when only local:0 is present (the shape observed in this guest),
    //  * it keeps waiting when the OEM secondary window is absent or off-display.
    // This does NOT establish that a real API28 `dumpsys display` emits this block, nor that the
    // OEM SecondMainActivity ever reaches it; runtime both-display acceptance stays open.
    const std::string api28_display =
            "Display 0:\n mDisplayId=0\n mPrimaryDisplayDevice=Built-in Screen\n mUniqueId=local:0\n"
            "Display 1:\n mDisplayId=1\n mLayerStack=1\n mPrimaryDisplayDevice=Emulator2D\n"
            " mUniqueId=virtual:com.android.emulator.multidisplay:1234562\n isVirtual=true\n state ON\n"
            " real 1920 x 720, modeId 1, defaultModeId 1\n";
    const std::string api28_window =
            "Window #3 Window{a1b2c3d u0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity}:\n"
            " mDisplayId=1\n mDrawState=HAS_DRAWN\n Surface: shown=true\n isOnScreen=true\n";
    const std::string primary_only_window =
            "Window #1 Window{9f8e7d6 u0 com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity}:\n"
            " mDisplayId=0\n mDrawState=HAS_DRAWN\n Surface: shown=true\n isOnScreen=true\n";
    assert(secondary_display_ready(api28_display, api28_window) == 1);
    assert(!secondary_display_ready(
            "Display 0:\n mDisplayId=0\n mPrimaryDisplayDevice=Built-in Screen\n mUniqueId=local:0\n",
            api28_window));
    assert(!secondary_display_ready(api28_display,
                                    "")); // a foreground app may hide SecondMainActivity
    // Wake admission: the generic parser must keep waiting for the OEM window itself. Production
    // waits up to 120s on exactly this (wake_displays, machine_preparation.cpp:190), and its ACK
    // matcher is an inline exact-row test at :585, not a named helper, so it is not called here.
    assert(!secondary_display_ready(api28_display, primary_only_window));
    const std::string passion_display =
            "Display 1:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1920 x 720, state ON\n";
    const std::string passion_window =
            "Window #0 com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond\n mDisplayId=1 isOnScreen=true\n";
    // Actual normal14 DMS provider remains present while LauncherSecond is off-screen.
    const std::string passion_off = R"dms(  Display 1:
    mDisplayId=1
    mLayerStack=1
    mHasContent=true
    mDesiredDisplayModeSpecs={baseModeId=2 primaryRefreshRateRange=[0 60] appRequestRefreshRateRange=[0 Infinity]}
    mRequestedColorMode=0
    mDisplayOffset=(0, 0)
    mDisplayScalingDisabled=false
    mPrimaryDisplayDevice=Emulator 2D Display
    mBaseDisplayInfo=DisplayInfo{"Emulator 2D Display", displayId 1, FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS, FLAG_TRUSTED, real 1920 x 720, largest app 1920 x 720, smallest app 1920 x 720, appVsyncOff 0, presDeadline 16666666, mode 2, defaultMode 2, modes [{id=2, width=1920, height=720, fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported false, rotation 0, state OFF, type VIRTUAL, uniqueId "virtual:com.android.emulator.multidisplay:1234562", app 1920 x 720, density 160 (160.0 x 160.0) dpi, layerStack 1, colorMode 0, supportedColorModes [0], deviceProductInfo null, owner com.android.emulator.multidisplay (uid 1000), removeMode 0}
    mOverrideDisplayInfo=DisplayInfo{"Emulator 2D Display", displayId 1, FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS, FLAG_TRUSTED, real 1920 x 720, largest app 1920 x 1920, smallest app 720 x 720, appVsyncOff 0, presDeadline 16666666, mode 2, defaultMode 2, modes [{id=2, width=1920, height=720, fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported false, rotation 0, state OFF, type VIRTUAL, uniqueId "virtual:com.android.emulator.multidisplay:1234562", app 1920 x 720, density 160 (160.0 x 160.0) dpi, layerStack 1, colorMode 0, supportedColorModes [0], deviceProductInfo null, owner com.android.emulator.multidisplay (uid 1000), removeMode 0}
    mRequestedMinimalPostProcessing=false)dms";
    const std::string display_boot = "12345678-1234-1234-1234-123456789abc";
    assert(!passion_secondary_provider_ready(passion_off));
    assert(!passion_secondary_display_ready(
            passion_off,
            "Window #0 com.voyah.os.carlauncher/com.voyah.os.carlauncher.second.LauncherActivityMainSecond\n mDisplayId=1 isOnScreen=false\n"));
    assert(passion_secondary_provider_preserves_readiness(passion_off, display_boot, display_boot));
    assert(!passion_secondary_provider_preserves_readiness(passion_off, "", display_boot));
    assert(!passion_secondary_provider_preserves_readiness(passion_off, display_boot,
                                                           "22345678-1234-1234-1234-123456789abc"));
    assert(!passion_secondary_provider_preserves_readiness(passion_off, display_boot, ""));

    for (const auto &invalid : {std::string{}, passion_display, passion_off + "\n" + passion_off}) {
        assert(!passion_secondary_provider_preserves_readiness(invalid, display_boot,
                                                               display_boot));
    }

    for (const auto &[from, to] : std::vector<std::pair<std::string, std::string>>{
                 {"1234562", "1234563"},
                 {"1920 x 720", "1280 x 720"},
                 {"Display 1:", "Display 2:"},
                 {"Emulator 2D Display", "FakeEmulator2D"}}) {
        auto invalid = passion_off;
        std::size_t pos = 0;

        while ((pos = invalid.find(from, pos)) != std::string::npos) {
            invalid.replace(pos, from.size(), to);
            pos += to.size();
        }

        assert(!passion_secondary_provider_preserves_readiness(invalid, display_boot,
                                                               display_boot));
    }

    // Saved v6: the first provider observation was ON; later OFF/window-hidden verification started
    // SecondScreenService. An established physical provider must stop that visibility recheck
    // before ON->OFF can race it.
    auto passion_on = passion_off;

    for (std::size_t pos = 0; (pos = passion_on.find("state OFF,", pos)) != std::string::npos;
         pos += 9) {
        passion_on.replace(pos, 10, "state ON,");
    }

    assert(!passion_secondary_display_ready(passion_on,
                                            "")); // A foreground app may hide LauncherSecond.

    for (const auto &observation : {passion_on, passion_off, passion_on}) {
        assert(passion_secondary_provider_preserves_readiness(observation, display_boot,
                                                              display_boot));
    }

    assert(!passion_secondary_provider_preserves_readiness(passion_on, "", display_boot));
    assert(!passion_secondary_provider_preserves_readiness(passion_on, display_boot,
                                                           "22345678-1234-1234-1234-123456789abc"));
    // Actual v8 rejection: base device OFF and WindowManager override ON, with identical physical
    // identity/geometry.
    const std::string passion_mixed_power = R"dms(
  Display 1:
    mDisplayId=1
    mLayerStack=1
    mHasContent=true
    mDesiredDisplayModeSpecs={baseModeId=2 primaryRefreshRateRange=[0 60] appRequestRefreshRateRange=[0 Infinity]}
    mRequestedColorMode=0
    mDisplayOffset=(0, 0)
    mDisplayScalingDisabled=false
    mPrimaryDisplayDevice=Emulator 2D Display
    mBaseDisplayInfo=DisplayInfo{"Emulator 2D Display", displayId 1, FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS, FLAG_TRUSTED, real 1920 x 720, largest app 1920 x 720, smallest app 1920 x 720, appVsyncOff 0, presDeadline 16666666, mode 2, defaultMode 2, modes [{id=2, width=1920, height=720, fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported false, rotation 0, state OFF, type VIRTUAL, uniqueId "virtual:com.android.emulator.multidisplay:1234562", app 1920 x 720, density 160 (160.0 x 160.0) dpi, layerStack 1, colorMode 0, supportedColorModes [0], deviceProductInfo null, owner com.android.emulator.multidisplay (uid 1000), removeMode 0}
    mOverrideDisplayInfo=DisplayInfo{"Emulator 2D Display", displayId 1, FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS, FLAG_TRUSTED, real 1920 x 720, largest app 1920 x 1920, smallest app 720 x 720, appVsyncOff 0, presDeadline 16666666, mode 2, defaultMode 2, modes [{id=2, width=1920, height=720, fps=60.0}], hdrCapabilities null, minimalPostProcessingSupported false, rotation 0, state ON, type VIRTUAL, uniqueId "virtual:com.android.emulator.multidisplay:1234562", app 1920 x 720, density 160 (160.0 x 160.0) dpi, layerStack 1, colorMode 0, supportedColorModes [0], deviceProductInfo null, owner com.android.emulator.multidisplay (uid 1000), removeMode 0}
    mRequestedMinimalPostProcessing=false
)dms";
    // Initial bootstrap still needs the visible launcher; its physical identity can then be pinned
    // across mixed power metadata.
    assert(passion_secondary_display_ready(passion_mixed_power, passion_window) == 1);
    assert(!passion_secondary_display_ready(passion_mixed_power, ""));
    assert(passion_secondary_provider_preserves_readiness(passion_mixed_power, display_boot,
                                                          display_boot));

    for (const auto &next_observation : {passion_mixed_power, passion_off, passion_on}) {
        assert(passion_secondary_provider_preserves_readiness(next_observation, display_boot,
                                                              display_boot));
    }

    assert(!passion_secondary_provider_preserves_readiness(passion_mixed_power, "", display_boot));
    assert(!passion_secondary_provider_preserves_readiness(passion_mixed_power, display_boot,
                                                           "22345678-1234-1234-1234-123456789abc"));
    auto unknown_power = passion_mixed_power;

    for (const auto &state : {std::string("state OFF,"), std::string("state ON,")}) {
        for (std::size_t pos = 0; (pos = unknown_power.find(state, pos)) != std::string::npos;
             pos += 14) {
            unknown_power.replace(pos, state.size(), "state UNKNOWN,");
        }
    }

    assert(passion_secondary_provider_preserves_readiness(unknown_power, display_boot,
                                                          display_boot));
    const auto unknown_power_record =
            passion_display_readiness_diagnostic(unknown_power, display_boot, display_boot);
    assert(unknown_power_record.at("canonical_physical") == true &&
           unknown_power_record.at("canonical_on") == false &&
           unknown_power_record.at("canonical_off") == false &&
           !unknown_power_record.contains("states"));
    media::PassionDisplayCache unknown_watch({true, "session", "boot", "watch"});
    const Json unknown_event = {
            {"schema", 1},
            {"kind", "display_state_event"},
            {"session_id", "session"},
            {"watch_id", "watch"},
            {"boot_id", "boot"},
            {"sequence", 1},
            {"states",
             Json::array({{{"display", 1},
                           {"unique_id", "virtual:com.android.emulator.multidisplay:1234562"},
                           {"state", 0},
                           {"kind", "observed"},
                           {"request", 0},
                           {"transaction", 0},
                           {"observed_ms", 1000},
                           {"order", 1}}})}};
    assert(!unknown_watch.accept(unknown_event, 100, 1000) &&
           !unknown_watch.get(1, 100)); // Physical presence cannot admit an unknown power proof.

    // Every base/override geometry and identity must still agree; power metadata does not prove
    // availability.
    for (const auto &[from, to] : std::vector<std::pair<std::string, std::string>>{
                 {"real 1920 x 720,", "real 1280 x 720,"},
                 {"1234562", "1234563"},
                 {"mPrimaryDisplayDevice=Emulator 2D Display",
                  "mPrimaryDisplayDevice=FakeEmulator2D"}}) {
        auto invalid = passion_mixed_power;
        invalid.replace(invalid.rfind(from), from.size(), to);
        assert(!passion_secondary_provider_preserves_readiness(invalid, display_boot,
                                                               display_boot));
    }

    const auto rejected_display = passion_display_readiness_diagnostic(passion_off, display_boot,
                                                                       display_boot);
    assert(rejected_display.at("canonical_off") == true &&
           rejected_display.at("canonical_on") == false &&
           rejected_display.at("boot_match") == true);
    assert(rejected_display.at("reason") == "accepted" &&
           rejected_display.at("raw_truncated") == false &&
           rejected_display.at("host_monotonic_us").get<std::int64_t>() > 0 &&
           rejected_display.at("host_wall_ms").get<std::int64_t>() > 0);
    assert(rejected_display.at("raw").get<std::string>().find("Display 1:") != std::string::npos);
    auto large_display = passion_off + "\n    metadata=" + std::string(6000, 'x') +
                         "\nDisplayModeDirector\n unrelated raw";
    const auto bounded_display = passion_display_readiness_diagnostic(large_display, display_boot,
                                                                      display_boot);
    assert(bounded_display.at("raw").get<std::string>().size() == 4096 &&
           bounded_display.at("raw_truncated") == true &&
           bounded_display.at("logical_block_bytes").get<std::size_t>() > 4096);
    assert(bounded_display.at("full_observation_bytes") == large_display.size());
    assert(bounded_display.at("raw").get<std::string>().find("DisplayModeDirector") ==
           std::string::npos);
    assert(passion_display_readiness_diagnostic(display, display_boot, display_boot).at("reason") ==
           "secondary_missing");
    assert(passion_display_readiness_diagnostic(passion_off, "", display_boot).at("reason") ==
           "missing_established_boot");
    assert(passion_display_readiness_diagnostic(passion_off, display_boot, "").at("reason") ==
           "invalid_current_boot");
    assert(passion_display_readiness_diagnostic(passion_off, display_boot,
                                                "22345678-1234-1234-1234-123456789abc")
                   .at("reason") == "boot_changed");
    assert(passion_secondary_provider_ready(passion_display));
    assert(!passion_secondary_display_ready(passion_display, ""));
    assert(passion_secondary_display_ready(passion_display, passion_window) == 1);
    assert(!passion_secondary_display_ready(passion_display, visible));
    assert(!passion_secondary_display_ready(display, passion_window));
    assert(!passion_secondary_provider_ready(display));
    assert(!passion_secondary_provider_ready(passion_display + display));

    for (const auto &invalid :
         {std::string{},
          std::string(
                  "Display 1:\n mPrimaryDisplayDevice=FakeEmulator2D\n real 1920 x 720, state ON\n"),
          std::string(
                  "Display 1:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state OFF\n"),
          std::string(
                  "Display 1:\n mPrimaryDisplayDevice=Emulator2D\n real 1280 x 720, state ON\n")}) {
        assert(!passion_secondary_provider_ready(invalid));
    }

    const std::string spaced_display =
            "Display 4:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1920 x 720, state ON\n";
    assert(secondary_display_ready(spaced_display, visible) == 4);

    for (const auto name : {"FakeEmulator2D", "Emulator2D Extra", "Emulator 2D Display Extra"}) {
        assert(!secondary_display_ready("Display 4:\n mPrimaryDisplayDevice=" + std::string(name) +
                                                "\n real 1920 x 720, state ON\n",
                                        visible));
    }

    assert(!secondary_display_ready(
            spaced_display +
                    "Display 5:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 720, state ON\n",
            visible));
    assert(!secondary_display_ready(
            "Display 4:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1920 x 1080, state ON\n",
            visible));
    assert(!secondary_display_ready(
            "Display 4:\n mPrimaryDisplayDevice=Emulator 2D Display\n real 1920 x 720, state OFF\n",
            visible));
    assert(!secondary_display_ready(
            spaced_display,
            "Window #0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n mDisplayId=1 isOnScreen=true\n"));

    assert(!secondary_display_ready(
            display,
            "Window #0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n mDisplayId=1 isOnScreen=true\n"));
    assert(!secondary_display_ready(
            display,
            "Window #0 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n mDisplayId=4 isOnScreen=false\n"));
    assert(!secondary_display_ready(
            display,
            "Window #0 unrelated\n mDisplayId=4 isOnScreen=true\nWindow #1 com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n mDisplayId=1 isOnScreen=true\n"));
    assert(!secondary_display_ready(
            "Display 4:\n mPrimaryDisplayDevice=Emulator2D\n real 1920 x 1080, state ON\n",
            visible));

    {
        ProcessResult result;
        result.exit_code = 0;
        result.timed_out = false;
        result.output = "Starting: Intent";
        assert(home_start_result(result).at("reason") == "accepted");
        Json delivery = {{"home", {{"status", "visible_on_primary"}}},
                         {"ui_observer", {{"boot_id", "old"}}}};
        result.timed_out = true;
        record_home_start(delivery, result);
        assert(delivery.at("home_start").at("reason") == "timeout");
        assert(delivery.at("home_start").at("timed_out") == true);
        result.timed_out = false;
        result.exit_code = 255;
        record_home_start(delivery, result);
        assert(delivery.at("home_start").at("reason") == "command_exit");
        assert(delivery.at("home_start_failure").at("reason") == "timeout");
        result.exit_code = 0;

        for (const auto &[text, category] : std::vector<std::pair<std::string, std::string>>{
                     {"SecurityException: private data", "security"},
                     {"Permission Denial: private", "permission"},
                     {"Error type 3", "activity_missing"},
                     {"Error: Activity not started", "activity_not_started"},
                     {"Error: arbitrary secret", "activity_error"},
                     {"Exception private", "exception"},
                     {"Error private", "unknown_error"}}) {
            result.output = text;
            const auto receipt = home_start_result(result);
            assert(receipt.at("reason") == "activity_error");
            assert(receipt.at("activity_manager") == category);
            assert(receipt.at("activity_manager").get<std::string>().find("private") ==
                   std::string::npos);
        }

        for (const auto &[text, exception, category] :
             std::vector<std::tuple<std::string, std::string, std::string>>{
                     {"Exception occurred while executing:\njava.lang.SecurityException: Permission Denial: secret",
                      "SecurityException", "permission_denial"},
                     {"java.lang.IllegalArgumentException: Invalid display 9",
                      "IllegalArgumentException", "unknown_display"},
                     {"Error type 3\nError: Activity class {secret} does not exist.", "none",
                      "activity_not_found"},
                     {"Error: Activity not started, unable to resolve Intent {secret}", "none",
                      "activity_not_found"},
                     {"java.lang.IllegalStateException: Activity manager has not been initialized",
                      "IllegalStateException", "service_not_ready"},
                     {"android.os.DeadObjectException: secret", "DeadObjectException",
                      "service_not_ready"},
                     {"Error: Can't find service: activity", "none", "service_not_ready"},
                     {"java.lang.NullPointerException: secret", "NullPointerException", "none"},
                     {"android.os.RemoteException: secret", "RemoteException", "none"},
                     {"android.content.ActivityNotFoundException: secret",
                      "ActivityNotFoundException", "activity_not_found"},
                     {"java.lang.RuntimeException: secret", "RuntimeException", "none"},
                     {"vendor.secret.CustomException: secret", "unknown", "none"}}) {
            result.output = text;
            result.exit_code = 255;
            const auto receipt = home_start_result(result);
            assert(receipt.at("exception_class") == exception);
            assert(receipt.at("failure_category") == category);
            assert(receipt.at("reason") == "command_exit");
            assert(receipt.at("exception_class").get<std::string>().find("secret") ==
                   std::string::npos);
        }

        result.output =
                "Exception occurred while executing:\njava.lang.IllegalStateException: User 0 is stopped\n\tat android.app.Secret.method(Secret.java:1)";
        assert(home_start_result(result).at("exception_detail") == "User 0 is stopped");
        result.output =
                "java.lang.IllegalStateException: token=abc password=xyz authorization=Bearer qwerty Intent { extras secretpayload }";
        const auto sanitized = home_start_result(result).at("exception_detail").get<std::string>();

        for (const char *secret : {"abc", "xyz", "qwerty", "Intent", "secretpayload"}) {
            assert(sanitized.find(secret) == std::string::npos);
        }

        result.output = "java.lang.IllegalStateException: sid-value nonce-value owner-value";
        assert(home_start_result(result, {"sid-value", "nonce-value", "owner-value"})
                       .at("exception_detail") == "[redacted] [redacted] [redacted]");
        result.output =
                "java.lang.IllegalStateException: conflict\n"
                "\tat android.app.WindowConfiguration.setActivityType(WindowConfiguration.java:268)\n"
                "\tat android.content.res.Configuration.updateFrom(Configuration.java:1250)\n"
                "\tat com.android.server.am.ActivityStack.onConfigurationChanged(ActivityStack.java:801)\n"
                "\tat vendor.secret.Token.run(Token.java:1)\n"
                "\tat android.app.Secret.run(/private/path/Secret.java:1)\n"
                "\tat android.app.Secret.run(Secret.java:1) password=hidden\n";
        const auto frames = home_start_result(result).at("exception_frames");
        assert(frames.size() == 3);
        assert(frames[0].at("method") == "android.app.WindowConfiguration.setActivityType");
        assert(frames[0].at("source") == "WindowConfiguration.java" && frames[0].at("line") == 268);
        assert(frames.dump().find("secret") == std::string::npos &&
               frames.dump().find("private") == std::string::npos);
        assert(home_start_result(result, {"WindowConfiguration"}).at("exception_frames").size() ==
               2);
        result.output = "java.lang.IllegalStateException: conflict\n";

        for (unsigned i = 0; i < 12; ++i) {
            result.output += "\tat android.app.Example.run(Example.java:1)\n";
        }

        assert(home_start_result(result).at("exception_frames").size() == 8);
        result.output = "vendor.CustomException: never expose this";
        assert(home_start_result(result).at("exception_detail") == "");
        result.output = "java.lang.IllegalStateException: " + std::string(300, 'x');
        assert(home_start_result(result).at("exception_detail").get<std::string>().size() == 192);
        result.output = "java.lang.IllegalStateException: reason extras hidden";
        assert(home_start_result(result).at("exception_detail") == "reason ");
        result.exit_code = 0;
        result.output = "Starting: Intent";
        record_home_start(delivery, result);
        assert(delivery.at("home_start_failure").at("reason") == "timeout");
        clear_android_home_delivery(delivery);
        assert(delivery.empty());
        delivery["camera_package"] = {{"status", "current"}};
        delivery["prepared_packages"] = Json::array({{{"status", "current"}}});
        delivery["unrelated"] = true;
        clear_android_camera_delivery(delivery);
        assert(!delivery.contains("camera_package") && !delivery.contains("prepared_packages") &&
               delivery.at("unrelated") == true);
    }
    const std::string home =
            "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity";
    // Both OEM activities declare HOME; dispatch the verified primary into a
    // HOME stack rather than accepting ambiguous package resolution.
    const auto home_start = primary_home_start_command(home);
    assert(home_start ==
           std::vector<std::string>({"shell", "am", "start", "--user", "0", "--activityType", "2",
                                     "-a", "android.intent.action.MAIN", "-c",
                                     "android.intent.category.HOME", "-n", home}));
    assert(std::find(home_start.begin(), home_start.end(), "--display") == home_start.end());

    assert(resolved_home_component(
                   "priority=100\ncom.qinggan.app.launcher/.activity.MainActivity\n",
                   "com.qinggan.app.launcher") == home);
    assert(!resolved_home_component("android/com.android.internal.app.ResolverActivity",
                                    "com.qinggan.app.launcher"));
    assert(!resolved_home_component("No activity found", "com.qinggan.app.launcher"));
    const std::string candidates =
            "2 activities found:\n  Activity #0:\n    priority=0\n    com.qinggan.app.launcher/.activity.MainActivity\n  Activity #1:\n    com.qinggan.app.launcher/com.qinggan.secondlauncher.activity.SecondMainActivity\n";
    assert(home_component_declared(candidates, home, "com.qinggan.app.launcher"));
    assert(!home_component_declared(candidates, "com.qinggan.app.launcher/.Missing",
                                    "com.qinggan.app.launcher"));
    assert(!home_component_declared("other/.activity.MainActivity", home,
                                    "com.qinggan.app.launcher"));
    assert(!home_component_declared(std::string(65537, 'x'), home, "com.qinggan.app.launcher"));
    assert(!resolved_home_component(home + "\n" + home, "com.qinggan.app.launcher"));
    assert(primary_home_visible("Window #0 " + home + "\n mDisplayId=0 isOnScreen=true\n", home));
    assert(!primary_home_visible("Window #0 " + home + "\n mDisplayId=1 isOnScreen=true\n", home));
    assert(!primary_home_visible("Window #0 " + home + "\n mDisplayId=0 isOnScreen=false\n", home));

    const std::string bars =
            "Window #0 Window{a u0 StatusBar1}:\n mDisplayId=0 package=com.qinggan.systemui appop=NONE\n mFrame=[0,0][1920,50] isOnScreen=true\nWindow #1 Window{b u0 StatusBar2}:\n mDisplayId=4 package=com.qinggan.systemui appop=NONE\n mFrame=[0,0][1920,50] isOnScreen=true\n";
    assert(oem_status_bars_ready(bars, 4));
    assert(!oem_status_bars_ready(bars, 1));
    assert(!oem_status_bars_ready(bars, 0));
    auto wrong = bars;
    wrong.replace(wrong.find("mDisplayId=4"), 12, "mDisplayId=0");
    assert(!oem_status_bars_ready(wrong, 4));
    wrong = bars;
    wrong.replace(wrong.rfind("isOnScreen=true"), 15, "isOnScreen=false");
    assert(!oem_status_bars_ready(wrong, 4));
    wrong = bars;
    wrong.replace(wrong.rfind("package=com.qinggan.systemui"), 27, "package=com.android.systemui");
    assert(!oem_status_bars_ready(wrong, 4));

    std::string token(32, 'a');
    std::filesystem::path long_session =
            std::filesystem::canonical(std::filesystem::temp_directory_path()) /
            std::string(160, 'x');
    assert(expand_session_path("${SESSION}/${TOKEN}", long_session, token) ==
           long_session.string() + "/" + token);

    // Windows has no ${RUNTIME} socket directory: its control endpoints are named pipes;
    // project_socket_root_guard expands it on POSIX.
    if (os::host_windows) {
        rejects([&] {
            expand_session_path("${RUNTIME}/${TOKEN}-qmp.sock", long_session, token);
        });
    }

    assert(passion_qnx_wheel_index("volume_up") == 325 &&
           passion_qnx_wheel_index("volume_down") == 326);
    assert(passion_qnx_wheel_index("menu") == 323 && passion_qnx_wheel_index("voice") == 331 &&
           passion_qnx_wheel_index("phone") == 330);
    assert(!passion_qnx_wheel_index("photo") && !passion_qnx_wheel_index("night_vision") &&
           !passion_qnx_wheel_index("unknown"));
    // Lower Night Vision sends the real OEM momentary switch, not an ADAS action.
    const auto nvs_field = std::find_if(catalog(VehicleCatalog::qinggan09).begin(),
                                        catalog(VehicleCatalog::qinggan09).end(),
                                        [](const Field &field) {
                                            return field.index == 329;
                                        });
    assert(nvs_field != catalog(VehicleCatalog::qinggan09).end() &&
           nvs_field->name == "swm_nvsSwitch" && nvs_field->width == 1);
    EventQueue nvs_events;
    auto nvs_down = nvs_events.submit("night_vision", "down", "nvs-owner");
    auto nvs_up = nvs_events.submit("night_vision", "up", "nvs-owner");
    assert(nvs_down.qnx_index == 329 && nvs_down.value == 1 && nvs_up.qnx_index == 329 &&
           nvs_up.value == 0);
    EventQueue events;
    auto down = events.submit("menu", "down", "ui-a");
    assert(down.qnx_index == 323 && down.value == 1 && events.held() == 1);
    rejects([&] {
        events.submit("menu", "down", "ui-a");
    });
    rejects([&] {
        events.submit("menu", "up", "ui-b");
    });
    auto up = events.submit("menu", "up", "ui-a");
    assert(up.sequence == down.sequence + 1 && up.value == 0 && events.held() == 0);
    assert(events.pop().value().phase == "down" && events.pop().value().phase == "up" &&
           !events.pop());
    events.submit("ok", "down", "ui-a");
    events.submit("voice", "down", "ui-a");
    events.release("ui-a");
    assert(events.held() == 0);
    assert(events.pop().value().phase == "down");
    assert(events.pop().value().phase == "down");
    assert(events.pop().value().phase == "cancel");
    assert(events.pop().value().phase == "cancel");
    events.submit("phone", "down", "ui-b");
    events.submit("photo", "down", "ui-a");
    events.release_all();
    assert(events.held() == 0);

    while (events.pop()) {}

    auto forced = events.force_release("menu", "ui-a");
    assert(forced.phase == "cancel" && forced.value == 0);
    events.submit("menu", "down", "ui-b");
    rejects([&] {
        events.force_release("menu", "ui-a");
    });
    events.release_all();

    while (events.pop()) {}

    assert(EventQueue::routes().size() == 17);
    auto all_routes = EventQueue::routes();

    for (const auto &[id, route] : all_routes.items()) {
        auto press = events.submit(id, "down", "ui-a");
        auto release = events.submit(id, "up", "ui-a");
        assert(press.sequence + 1 == release.sequence);
    }

    rejects([&] {
        events.submit("horn", "down", "ui-a");
    });
    rejects([&] {
        events.submit("menu", "down", "bad owner");
    });
    const Json free_graph = {
            {"schema", 1},
            {"id", "api30-fixture"},
            {"platform", "qinggan11"},
            {"wheel", {{"provider", "com.voyemu.input.wheel"}}},
            {"status", "incomplete"},
            {"android", {{"package", "system-images;android-30;default;arm64-v8a"}}},
            {"configure",
             {{"home", "com.qinggan.app.launcher"},
              {"homeActivity",
               "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}}},
            {"components",
             {{"canbus", "components/canbus"},
              {"qg-runtime", "components/qg-runtime"},
              {"bootstrap", "components/bootstrap"}}},
            {"install", Json::array({{{"artifact", "component:canbus"}, {"type", "apk"}},
                                     {{"artifact", "component:qg-runtime"}, {"type", "file"}},
                                     {{"artifact", "component:bootstrap"}, {"type", "apk"}}})}};
    const auto free_capability = qinggan11_wheel_capability(free_graph);
    const Json free_android = {
            {"reference_profile", "free-11-chinese-20260731-7.3.1"},
            {"api", 30},
            {"home",
             {{"package", "com.qinggan.app.launcher"},
              {"component",
               "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}}},
            {"vehicle_adapter", {{"authority", "com.voyemu.output.vehicle"}}},
            {"wheel_capability", free_capability}};
    assert(qinggan11_wheel_unsupported(free_android) && free_capability.at("supported") == false);
    assert(!qinggan11_wheel_unsupported(
            Json{{"wheel_adapter",
                  {{"authority",
                    "com.voyemu.input.wheel"}}}})); // A9 remains mandatory protected bootstrap.

    for (const char *field : {"components", "install", "configure", "android"}) {
        auto bad = free_graph;
        bad.erase(field);
        rejects([&] {
            qinggan11_wheel_capability(bad);
        });
    }

    {
        auto bad = free_graph;
        bad["components"]["oem-services"] = "components/oem-services";
        rejects([&] {
            qinggan11_wheel_capability(bad);
        });
    }
    {
        auto bad = free_graph;
        bad["install"].erase(0);
        rejects([&] {
            qinggan11_wheel_capability(bad);
        });
    }
    {
        auto bad = free_graph;
        bad["install"].push_back(bad["install"][0]);
        rejects([&] {
            qinggan11_wheel_capability(bad);
        });
    }

    for (const char *field : {"vehicle_adapter", "home"}) {
        auto bad = free_android;
        bad.erase(field);
        rejects([&] {
            qinggan11_wheel_unsupported(bad);
        });
    }

    {
        auto bad = free_android;
        bad["wheel_adapter"] = {{"authority", "com.voyemu.input.wheel"}};
        rejects([&] {
            qinggan11_wheel_unsupported(bad);
        });
    }
    {
        auto bad = free_android;
        bad["wheel_capability"]["supported"] = true;
        rejects([&] {
            qinggan11_wheel_unsupported(bad);
        });
    }
    {
        auto bad = free_android;
        bad["api"] = 28;
        rejects([&] {
            qinggan11_wheel_unsupported(bad);
        });
    }
    auto bootstrap = parse_android_provider_reply(
            R"(Result: Bundle[{json={"schema":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"session-ready"}}])");
    assert(bootstrap["status"] == "session-ready");
    Json nested{
            {"schema", 1},
            {"sequence", 3},
            {"actions", Json::array({Json{{"note", std::string("brace } { quote \" slash \\")}}})}};
    assert(parse_android_provider_reply("Result: Bundle[{json=" + nested.dump() + "}]\n") ==
           nested);
    const Json phone_diagnostics{
            {"schema", 1},
            {"authority", true},
            {"wanted", true},
            {"bound", false},
            {"readers", 2},
            {"events",
             {{"HFP_REGISTER_PHONE", 1}, {"HFP_DELIVER_PHONE", 3}, {"CALLBACK_ACCEPT", 2}}},
            {"hfp_listeners", 1},
            {"hfp_last_state", 128}};
    const Json phone_provider{{"schema", 1},
                              {"session", "private-session"},
                              {"sequence", 3},
                              {"provider_pid", 10651},
                              {"data",
                               {{"ok", true},
                                {"hfp_connected", true},
                                {"pbap_connected", false},
                                {"diagnostics", phone_diagnostics}}}};
    auto phone_projected =
            parse_android_provider_reply("Result: Bundle[{json=" + phone_provider.dump() + "}]\n");
    assert(phone_projected == phone_provider);
    // Session::phone_control projects only the outer ownership fields.
    phone_projected.erase("session");
    phone_projected["session_id"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    phone_projected["synthetic"] = true;
    phone_projected["visible_effect_verified"] = false;
    assert(!phone_projected.contains("session") &&
           phone_projected.at("session_id") == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
           phone_projected.at("synthetic") == true &&
           phone_projected.at("visible_effect_verified") == false);
    assert(phone_projected.at("data") == phone_provider.at("data") &&
           phone_projected.at("data").at("diagnostics") == phone_diagnostics);
    assert(phone_projected.at("data")
                   .at("diagnostics")
                   .at("events")
                   .at("HFP_DELIVER_PHONE")
                   .is_number_integer() &&
           phone_projected.at("data").at("hfp_connected").is_boolean() &&
           phone_projected.at("data").at("pbap_connected") == false);
    rejects([&] {
        parse_android_provider_reply("Result: Bundle[mParcelledData.dataSize=24]");
    });
    rejects([&] {
        parse_android_provider_reply("SecurityException: permission denied");
    });
    rejects([&] {
        parse_android_provider_reply("Result: Bundle[{error=authentication}]");
    });
    {
        bool exact = false;
        try {
            parse_android_provider_reply("Result: Bundle[{error=storage-or-submission}]");
        } catch (const std::exception &e) {
            exact = std::string(e.what()) == "ANDROID_PROVIDER_ERROR: storage-or-submission";
        }

        assert(exact);
    }
    rejects([&] {
        parse_android_provider_reply("Result: Bundle[{json={\"schema\":1}");
    });
    rejects([&] {
        parse_android_provider_reply("Result: Bundle[{json={\"schema\":1}}] unexpected");
    });
    rejects([&] {
        parse_android_provider_reply("Result: Bundle[{json=[]}]");
    });
    assert(binder_integer("Result: Parcel(00000000 000003ea   '....')") == 1002);
    rejects([&] {
        binder_integer("Result: Parcel(ffffffff 00000001 '....')");
    });
    assert(host_light_theme("default") == false && host_light_theme("simple") == true);
    assert(host_light_theme("simple\r\n") == true);

    for (const auto title : {"", "golden", "day", "night", "Simple", "simple extra"}) {
        assert(!host_light_theme(title).has_value());
    }

    assert(oem_language_setting("Row: 0 value=0\n") == 0u &&
           oem_language_setting("Row: 0 value=1\r\n") == 1u);

    for (const auto query : {"", "No result found.", "SecurityException", "Row: 0 value=2",
                             "Row: 0 value=-1", "Row: 0 value=10", "Row: 1 value=1",
                             "Row: 0 value=1\nRow: 1 value=0", "Row: 0 value=1 extra"}) {
        assert(!oem_language_setting(query));
    }

    assert(oem_language_change(std::nullopt, 1) == Json({{"ivi_languageSet", 1}}));
    assert(oem_language_change(1u, 0) == Json({{"ivi_languageSet", 0}}));
    assert(!oem_language_change(1u, 1));
    assert(oem_language_command(std::nullopt, 1) ==
           Json({{"value", 1u}, {"source", "IPP_LANGUAGE_SET"}}));
    assert(oem_language_command(1u, 0) == Json({{"value", 0u}, {"source", "IPP_LANGUAGE_SET"}}));
    assert(!oem_language_command(1u, 1));
    rejects([&] {
        oem_language_command(std::nullopt, 2);
    });
    // Initial sync: a nullopt previous must emit so a preexisting equal MCU word cannot
    // suppress the first cluster command; an unchanged value must not re-emit.
    assert(oem_language_change(std::nullopt, 1) && oem_language_command(std::nullopt, 1));
    assert(oem_language_change(std::nullopt, 0) && oem_language_command(std::nullopt, 0));
    assert(!oem_language_change(1u, 1) && !oem_language_command(1u, 1));
    rejects([&] {
        oem_language_change(std::nullopt, 2);
    });
    rejects([&] {
        oem_language_change(2u, 0);
    });
    const Json android611 = {
            {"reference_profile", "free-11-chinese-20250710-6.11.1"},
            {"api", 30},
            {"home",
             {{"package", "com.qinggan.app.launcher"},
              {"component",
               "com.qinggan.app.launcher/com.qinggan.app.launcher.activity.MainActivity"}}}};
    const std::vector<std::vector<std::string>> cluster_query{{"shell", "service", "call",
                                                               "qg.cluster.service", "7", "i32",
                                                               "1", "i32", "27", "i32", "28"}};
    auto android731 = android611;
    android731["reference_profile"] = "free-11-chinese-20260731-7.3.1";

    // Both firmwares read the cluster skin and queue the same command with it on every host.
    for (const auto &presentation : {android611, android731}) {
        assert(qinggan11_presentation(presentation));
        assert(oem_theme_queries(presentation) == cluster_query);
        assert(oem_theme_state(presentation, {"Result: Parcel(00000000 00000bba   '........')"}) ==
               std::optional<ThemeState>({4, 3002}));
        assert(oem_theme_command(presentation, std::nullopt, {4, 3002}).value() ==
               Json({{"theme_id", 4},
                     {"theme_skin", 3002},
                     {"source", "qg.cluster.service/SKIN"}}));
        assert(!oem_theme_command(presentation, ThemeState{4, 3002}, {4, 3002}));

        for (const auto *reply : {"Result: Parcel(ffffffff 00000bba   '........')", "missing",
                                  "Result: Parcel(00000000 000003ea   '........')"}) {
            assert(!oem_theme_state(presentation, {reply}));
        }
    }

    auto foreign611 = android611;
    foreign611["api"] = 28;
    assert(!qinggan11_presentation(foreign611));
    foreign611 = android611;
    foreign611["reference_profile"] = "free-09-chinese-20260106-6.0.3";
    assert(!qinggan11_presentation(foreign611));
    assert(oem_theme_queries(foreign611) ==
           std::vector<std::vector<std::string>>({{"shell", "service", "call", "qg.canbus", "57",
                                                   "i32", "1", "i32", "599", "i32", "818"},
                                                  {"shell", "service", "call", "qg.canbus", "57",
                                                   "i32", "1", "i32", "978", "i32", "1195"}}));
    assert(oem_theme_state(foreign611, {"Result: Parcel(00000000 00000002   '........')",
                                        "Result: Parcel(00000000 000003e9   '........')"}) ==
           std::optional<ThemeState>({2, 1001}));
    assert(oem_theme_command(foreign611, std::nullopt, {2, 1001})->at("source") ==
           "IPK_THEME_SKIN");

    for (int skin : {1, 1001, 3001, 3002, 3003}) {
        auto value = qinggan11_theme_change(std::nullopt, {(skin + 999) / 1000, skin});
        assert(value->at("theme_id") == (skin + 999) / 1000 && value->at("theme_skin") == skin);
    }

    for (int skin : {0, 1002, 2999, 3004, 6000}) {
        rejects([&] {
            qinggan11_theme_change(std::nullopt, {(skin + 999) / 1000, skin});
        });
    }

    rejects([&] {
        qinggan11_theme_change(std::nullopt, {2, 3001});
    });
    assert(!qinggan11_theme_change(ThemeState{4, 3002}, {4, 3002}));
    assert(qinggan11_theme_change(ThemeState{4, 3001}, {4, 3002})->at("theme_skin") == 3002);
    assert(qinggan11_theme_change(ThemeState{2, 1001}, {4, 3003})->at("theme_skin") == 3003);
    assert(qinggan11_cluster_skin_theme("Result: Parcel(00000000 00000001   '........')") ==
           std::optional<ThemeState>({1, 1}));
    assert(qinggan11_cluster_skin_theme("Result: Parcel(00000000 000003e9   '........')") ==
           std::optional<ThemeState>({2, 1001}));
    assert(!qinggan11_cluster_skin_theme(""));
    assert(!qinggan11_cluster_skin_theme("Result: Parcel(00000000 00000fa1   '........')"));
    auto boot = theme_change(std::nullopt, {2, 1001});
    assert((*boot)["theme_id"] == 2);
    auto changed = theme_change(ThemeState{2, 1001}, {2, 4000});
    assert((*changed)["theme_id"] == 4 && (*changed)["source"] == "IPK_THEME_SKIN");
    auto mode = theme_change(ThemeState{2, 4000}, {1, 4000});
    assert((*mode)["theme_id"] == 1 && (*mode)["source"] == "IPK_THEM_MODE");
    assert(!theme_change(ThemeState{2, 4000}, {2, 4000}));
    rejects([&] {
        theme_change(std::nullopt, {2, 6001});
    });
    auto source = initial_state(VehicleCatalog::qinggan09);
    Json receipt{{"schema", 1},
                 {"status", "applied"},
                 {"map_sha256", qinggan09_map_sha256},
                 {"field_count", 579},
                 {"sequence", source["sequence"]},
                 {"raw_oem", source["raw_oem"]}};
    assert(android_vehicle_receipt_matches(receipt, source));
    auto stale = receipt;
    stale["sequence"] = 2;
    assert(!android_vehicle_receipt_matches(stale, source));
    auto different = receipt;
    different["raw_oem"]["odo"] = 1;
    assert(!android_vehicle_receipt_matches(different, source));
    auto fractional = receipt;
    fractional["sequence"] = 1.0;
    assert(!android_vehicle_receipt_matches(fractional, source));
    auto malformed = receipt;
    malformed["raw_oem"]["speed"] = 0.0;
    assert(!android_vehicle_receipt_matches(malformed, source));
    auto incomplete = receipt;
    incomplete["raw_oem"].erase("cfg_acc");
    assert(!android_vehicle_receipt_matches(incomplete, source));
    auto submitted = source;
    submitted["sequence"] = source.at("sequence").get<std::uint32_t>() + 1;
    assert(android_vehicle_receipt_pending(receipt, submitted));
    assert(!android_vehicle_receipt_matches(receipt, submitted));
    assert(android_vehicle_receipt_pending(Json{{"schema", 1}, {"status", "not-ready"}},
                                           submitted));
    auto foreign_receipt = receipt;
    foreign_receipt["map_sha256"] = std::string(64, 'f');
    assert(!android_vehicle_receipt_pending(foreign_receipt, submitted));
    assert(!android_vehicle_receipt_pending(malformed, submitted));
    assert(!android_vehicle_receipt_pending(receipt, source));
    auto directory = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                     ("vst-" + random_token().substr(0, 16));
    ensure_private_directory(directory);
    Session session(directory, random_token());
    auto result = session.handle(
            {{"schema", 1}, {"op", "patch"}, {"values", {{"speed", 88}, {"soc", 61}}}});
    assert(result["ok"] && result["state"]["raw_oem"]["speed10x"] == 880);
    assert(!session.handle({{"op", "patch"}, {"values", {{"swm_menu", 1}}}})["ok"]);
    assert(!session.handle({{"op", "status"}, {"session_id", "stale"}})["ok"]);
    assert(!session.handle({{"op", "shell"}, {"command", "unavailable"}})["ok"]);
    const auto fenced_before = session.handle({{"op", "status"}});
    auto stale_revision = session.handle(
            {{"op", "patch"}, {"expected_revision", std::uint64_t{0}}, {"values", {{"speed", 3}}}});
    assert(!stale_revision["ok"] &&
           stale_revision["error"].get<std::string>().starts_with("TEST_REVISION:"));
    auto stale_generation = session.handle({{"op", "patch"},
                                            {"expected_generation", std::uint64_t{1}},
                                            {"values", {{"speed", 3}}}});
    assert(!stale_generation["ok"] &&
           stale_generation["error"].get<std::string>().starts_with("TEST_GENERATION:"));
    assert(session.handle({{"op", "status"}})["state"] == fenced_before["state"]);
    auto atomic_patch = session.handle({{"op", "patch"},
                                        {"expected_revision", fenced_before["revision"]},
                                        {"values", {{"speed", 88}}}});
    assert(atomic_patch["ok"] &&
           atomic_patch["revision"] == fenced_before["revision"].get<std::uint32_t>() + 1);
    assert(!session.handle(
            {{"op", "media_input"}, {"input", {{"kind", "key"}, {"key", "HOME"}}}})["ok"]);
    const auto race_before = session.handle({{"op", "status"}});
    Json patch_a, patch_b;
    const Json raced{{"op", "patch"},
                     {"expected_revision", race_before["revision"]},
                     {"values", {{"speed", 88}}}};
    std::thread first_patch([&] {
        patch_a = session.handle(raced);
    }),
            second_patch([&] {
                patch_b = session.handle(raced);
            });
    first_patch.join();
    second_patch.join();
    assert(patch_a["ok"].get<bool>() != patch_b["ok"].get<bool>());
    assert(session.handle({{"op", "status"}})["revision"] ==
           race_before["revision"].get<std::uint32_t>() + 1);

    auto ready = session.handle(
            {{"op", "patch"}, {"values", {{"speed", 80}, {"gear", 3}, {"gear_valid", 1}}}});
    assert(ready["ok"]);
    assert(session.handle({{"op", "status"}})["wheel_routes"]["acc"]["ecu"]["consumer"] ==
           "voyemu.adas-ecu");
    auto act = [&](const char *id) {
        auto down = session.handle(
                {{"op", "wheel"}, {"id", id}, {"phase", "down"}, {"owner", "adas-test"}});
        assert(down["accepted"] && down["deliveries"]["adas_ecu"] == "queued");
        auto up = session.handle(
                {{"op", "wheel"}, {"id", id}, {"phase", "up"}, {"owner", "adas-test"}});
        assert(up["accepted"]);
        session.tick();
        auto result = session.handle({{"op", "status"}});
        assert(result["deliveries"]["adas_ecu"]["event_sequence"] == up["event_sequence"]);

        return result;
    };
    auto engaged = act("acc");
    assert(engaged["state"]["raw_oem"]["acc_mode"] == 3 &&
           engaged["state"]["raw_oem"]["mrr_vSetDis"] == 160);
    auto increment = act("cruise_up");
    assert(increment["state"]["raw_oem"]["mrr_vSetDis"] == 162 &&
           increment["state"]["raw_oem"]["speed"] == 80);
    auto persisted = read_private_json(directory / "vehicle-state.json");
    assert(persisted == increment["state"]);
    auto braking = session.handle({{"op", "patch"}, {"values", {{"vcu_brakePedalPressed", 1}}}});
    assert(braking["state"]["raw_oem"]["acc_mode"] == 2 &&
           braking["state"]["sequence"].get<unsigned>() ==
                   increment["state"]["sequence"].get<unsigned>() + 1);
    assert(session.handle({{"op", "wheel"},
                           {"id", "ica"},
                           {"phase", "down"},
                           {"owner", "adas-test"}})["accepted"]);
    session.tick();
    session.handle({{"op", "release_owner"}, {"owner", "adas-test"}});
    session.tick();
    auto cancel = session.handle({{"op", "status"}});
    assert(cancel["deliveries"]["adas_ecu"]["outcome"] == "cancelled" &&
           cancel["state"] == braking["state"]);
    std::atomic<bool> stopped = false;
    assert(session.endpoint().string().size() < 104);
    {
        ControlServer server(session.endpoint(), [&](const Json &input) {
            return session.handle(input);
        });
        std::thread thread([&] {
            server.serve(stopped);
        });
        auto status = request(session.endpoint(), {{"op", "status"}, {"request_id", "check"}});
        assert(status["ok"] && status["request_id"] == "check" && status["catalog"].size() == 579);
        auto press =
                request(session.endpoint(),
                        {{"op", "wheel"}, {"id", "menu"}, {"phase", "down"}, {"owner", "ui-a"}});
        assert(press["accepted"]);
        auto released = request(session.endpoint(), {{"op", "release_owner"}, {"owner", "ui-a"}});
        assert(released["held_buttons"] == 0);
        stopped = true;
        thread.join();
    }
    assert(!std::filesystem::exists(session.endpoint()));
    // Source services never fabricate guest state when this Session has no Android.
    const auto session_token =
            session.handle({{"op", "status"}}).at("session_id").get<std::string>();
    assert(!session.handle({{"op", "test_output_state"}})["ok"]);
    assert(!session.handle({{"op", "test_output_state"}, {"session_id", "foreign"}})["ok"]);
    auto absent_sources = session.handle(
            {{"op", "test_output_state"}, {"session_id", session_token}, {"timeout_ms", 1000}});
    assert(absent_sources["ok"] && !absent_sources["state"]["complete"].get<bool>());
    assert(absent_sources["state"]["sources"]["can"]["status"] == "unavailable");
    assert(absent_sources["state"]["sources"]["system"]["value"].is_null());
    auto absent_watch =
            session.handle({{"op", "test_watch_start"},
                            {"session_id", session_token},
                            {"timeout_ms", 1000},
                            {"lease_ms", 1000},
                            {"condition", {{"op", "present"}, {"path", "/sources/can/value"}}}});
    assert(absent_watch["ok"] && absent_watch["status"] == "unavailable" &&
           absent_watch["watch_id"] == "");
    auto stale_watch = session.handle({{"op", "test_watch_read"},
                                       {"session_id", session_token},
                                       {"watch_id", "1"},
                                       {"epoch", "stale"},
                                       {"cursor", "0"},
                                       {"timeout_ms", 0}});
    assert(!stale_watch["ok"] &&
           stale_watch["error"].get<std::string>().starts_with("TEST_WATCH_EPOCH:"));
    std::ostringstream stop_trace;
    auto *original_stderr = std::cerr.rdbuf(stop_trace.rdbuf());
    const auto stopped_reply = session.handle({{"op", "stop"}});
    std::cerr.rdbuf(original_stderr);
    assert(stopped_reply.at("stopped") == true && session.stopped());
    std::vector<std::string> stop_phases;
    std::istringstream stop_lines(stop_trace.str());
    std::string stop_line;
    std::int64_t previous_stop_us = 0;

    while (std::getline(stop_lines, stop_line)) {
        const auto event = Json::parse(stop_line);

        if (event.value("message", std::string{}) != "session.stop") {
            continue;
        }

        const auto &fields = event.at("fields");
        assert(fields.at("session_id") == session_token);
        const auto receipt_us = fields.at("host_monotonic_us").get<std::int64_t>();
        assert(receipt_us >= previous_stop_us && fields.at("host_wall_ms").get<std::int64_t>() > 0);
        previous_stop_us = receipt_us;
        stop_phases.push_back(fields.at("phase").get<std::string>());
    }

    assert((stop_phases ==
            std::vector<std::string>{"request_received", "entry", "source_collectors_closed",
                                     "observer_closed", "lifecycle_acquired", "frontend_begin",
                                     "frontend_closed", "cluster_closed", "android_begin",
                                     "android_closed", "complete"}));
    auto final_record = read_private_json(directory / "runtime.json");
    assert(final_record["stopped"] == true &&
           final_record["deliveries"]["android"]["status"] == "stopped");
    std::filesystem::remove_all(directory);
    Json canvas = {{"schema", 1},
                   {"source", "own-window-instrumentation"},
                   {"bundle_identifier", "com.voyemu.emulator"},
                   {"backing_scale", 2},
                   {"content_points", {1920, 360}},
                   {"content_subviews", Json::array({{{"class", "EmuGLViewWithMetal"},
                                                      {"frame_points", {0, 0, 1920, 360}},
                                                      {"bounds_points", {0, 0, 1920, 360}}}})}};
    assert(multimedia_canvas_ready(canvas));
    auto cropped = canvas;
    cropped["content_subviews"][0]["frame_points"][2] = 960;
    cropped["content_subviews"][0]["bounds_points"][2] = 960;
    assert(!multimedia_canvas_ready(cropped));
    auto too_tall = canvas;
    too_tall["content_points"][1] = 453;
    assert(!multimedia_canvas_ready(too_tall));
    auto tall_canvas = canvas;
    tall_canvas["content_points"][1] = 453;
    tall_canvas["content_subviews"][0]["frame_points"][3] = 453;
    tall_canvas["content_subviews"][0]["bounds_points"][3] = 453;
    assert(!multimedia_canvas_ready(tall_canvas));
    auto shifted = canvas;
    shifted["content_subviews"][0]["frame_points"][0] = 960;
    assert(!multimedia_canvas_ready(shifted));
    auto scrolled = canvas;
    scrolled["content_subviews"][0]["bounds_points"][1] = 93;
    assert(!multimedia_canvas_ready(scrolled));
    auto wrong_layer = canvas;
    wrong_layer["content_subviews"][0]["class"] = "NSView";
    assert(!multimedia_canvas_ready(wrong_layer));
    auto bounds_only = canvas;
    bounds_only["content_subviews"][0]["bounds_points"][3] = 453;
    assert(!multimedia_canvas_ready(bounds_only));
    auto duplicate = canvas;
    duplicate["content_subviews"].push_back(canvas["content_subviews"][0]);
    assert(!multimedia_canvas_ready(duplicate));
    auto foreign = canvas;
    foreign["bundle_identifier"] = "other.app";
    assert(!multimedia_canvas_ready(foreign));
    app_launch_guards();
    android_startup_stage_isolation();
    android_short_pair_guards();
    android_wheel_terminal_receipts();
    theme_consumer_acknowledgements();
    cleanup_guards();
    configured_cluster_without_launch();
    std::cout << "wheel ownership, native IPC, OEM theme decoding and terminal cleanup passed\n";
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';

    return 1;
}
