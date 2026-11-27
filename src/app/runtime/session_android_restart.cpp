#include "error.hpp"
#include "session_internal.hpp"

namespace voyemu {
using namespace session_detail;

Json Session::restart_machine(const Json &operation) {
    const auto expected = operation.at("expected_boot");

    validate_restart_expected(expected);
    const auto timeout = operation.at("timeout_ms").get<int>();
    const auto action = operation.at("operation_id").get<std::string>();

    if (!hex_text(action, 32)) {
        throw VoyemuError("TEST_ARGUMENT", "durable restart action required");
    }

    const auto receipt_path = directory_ / ("full-restart-" + action + ".json");
    const auto expected_can = operation.value("expected_can", Json());
    const bool with_can = !expected_can.is_null();

    if (with_can) {
        validate_can_boundary_expected(expected_can);
    }

    std::lock_guard stop_lock(test_stop_mutex_);

    if (std::filesystem::exists(receipt_path) || std::filesystem::is_symlink(receipt_path)) {
        throw VoyemuError("SESSION_RESTART_UNKNOWN",
                          "restart action already dispatched; query operation.get");
    }

    check_restart_can_boundary(with_can);

    auto boot = [&] {
        assert_android_identity();
        auto value = android_boot_id();

        if (!value) {
            throw VoyemuError("SESSION_RESTART_BOOT", "Linux boot observation failed");
        }

        if (!android_boot_id_valid(*value)) {
            throw VoyemuError("SESSION_RESTART_BOOT", "complete Linux boot identity required");
        }

        return *value;
    };
    auto before_identity = [&] {
        if (stopped_ || android_spec_.empty() || !android_powered_ || !android_.alive() ||
            !cluster_requested_ || !qnx_.alive() || !interguest_link_ ||
            !cluster_spec_.contains("interguest_network")) {
            throw VoyemuError("SESSION_RESTART_UNAVAILABLE",
                              "live owned Android and QNX with interguest handshake are required");
        }

        const auto link = interguest_link_->status();

        if (!restart_qnx_ack(link, 0, cluster_generation_, interguest_qnx_generation_)) {
            throw VoyemuError("SESSION_RESTART_UNAVAILABLE",
                              "current QNX guest acknowledgement is not established");
        }

        const bool cold = deliveries_["qnx"]
                                  .value("quickboot", Json::object())
                                  .value("mode", std::string{}) == "cold";
        auto identity = restart_boot_identity(boot(), cluster_generation_, qnx_.pid(), cold);
        identity["android_pid"] = android_.pid();
        validate_restart_before(expected, identity);

        return identity;
    };
    std::shared_ptr<voyemu::runtime::SourceCoordinator> sources;
    {
        std::lock_guard lock(mutex_);

        if (test_services_closed_) {
            throw VoyemuError("SESSION_RESTART_UNAVAILABLE", "observation services are closing");
        }

        const auto current = before_identity();

        if (active_can_boundary_) {
            throw VoyemuError("CAN_BOUNDARY_FROZEN", "previous fence cleanup requires owned stop");
        }

        if (with_can) {
            const auto &anchor = expected_can.at("anchor");

            if (!android_spec_.contains("can_model_observer_sha256") ||
                anchor.at("session_id") != session_id_ ||
                anchor.at("boot_uuid") != current.at("android_boot_id") ||
                anchor.at("owned_android_pid") != current.at("android_pid") ||
                std::find(can_history_anchors_.begin(), can_history_anchors_.end(), anchor) ==
                        can_history_anchors_.end()) {
                throw VoyemuError("CAN_BOUNDARY_STALE",
                                  "current owned CAN history anchor required");
            }
        }

        test_services_closed_ = true;

        if (test_watch_) {
            test_watch_->close();
        }

        if (test_can_watch_) {
            test_can_watch_->close();
        }

        for (const auto &[selection, projection] : test_source_watches_) {
            projection->close();
        }

        sources = test_sources_;
    }
    struct Reopen {
        bool &closed;
        std::recursive_mutex &state;

        ~Reopen() {
            std::lock_guard lock(state);
            closed = false;
        }
    } reopen{test_services_closed_, mutex_};

    if (sources) {
        sources->stop();
    }

    {
        std::lock_guard lock(mutex_);
        test_sources_.reset();
        test_watch_.reset();
        test_can_watch_.reset();
        test_source_watches_.clear();
        test_can_cursor_ = nullptr;
        test_can_generation_ = 0;
        test_demand_until_ = 0;
        test_ui_connection_ = Json();
        test_ui_subscription_ = Json();
        test_ui_sample_ = {};
        test_ui_sampled_ms_ = 0;
    }
    std::shared_ptr<UiObserver> observer;
    {
        std::lock_guard lock(mutex_);
        observer = std::exchange(ui_observer_, {});
    }

    if (observer && !observer->stop()) {
        std::lock_guard lock(mutex_);
        ui_observer_ = observer;
        test_services_closed_ = false;
        throw VoyemuError("SESSION_RESTART_OBSERVER", "old observer shutdown is unverified");
    }

    clear_ui_observer_metadata(directory_, session_id_);
    std::unique_lock lifecycle(lifecycle_mutex_);
    std::unique_lock lock(mutex_);
    AndroidIdentityScope identity_scope(android_identity_scope_depth_, android_identity_operation_);
    const auto restart_io = lend_android_request_io(lock);
    const Restore restart_deadline(android_request_deadline_,
                                   std::chrono::steady_clock::now() +
                                           std::chrono::milliseconds(timeout));
    test_sources_.reset();
    test_watch_.reset();
    test_can_watch_.reset();
    test_source_watches_.clear();
    test_can_cursor_ = nullptr;
    test_can_generation_ = 0;
    test_demand_until_ = 0;
    test_ui_connection_ = Json();
    test_ui_subscription_ = Json();
    test_ui_sample_ = {};
    test_ui_sampled_ms_ = 0;
    const auto before = before_identity();
    const auto prior_link_generation = interguest_link_->status().generation;
    machine_restart_active_ = true;
    struct RestoreRestart {
        bool &active;

        ~RestoreRestart() {
            active = false;
        }
    } restore_restart{machine_restart_active_};
    const auto android = android_spec_, qnx = cluster_spec_;
    const auto seconds = cluster_seconds_;
    const auto selection_path = directory_ / "machine-selection.json";
    const bool selected = std::filesystem::exists(selection_path) ||
                          std::filesystem::is_symlink(selection_path);
    const auto selection = selected ? read_private_json(selection_path, 4096)
                                    : Json{{"android_storage", android_spec_.at("machine")}};
    Json can_proof, can_token;
    bool seal_attempted = false;
    const auto old_boot = before.at("android_boot_id").get<std::string>();
    const auto old_android_pid = android_.pid();
    const auto old_android_generation = android_generation_;

    if (with_can) {
        can_proof = expected_can;
        can_proof["old_kernel_stopped"] = false;
        std::uint64_t nonce = 0;
        (void)std::from_chars(action.data(), action.data() + 16, nonce, 16);
        const auto &anchor = expected_can.at("anchor");
        can_token = {{"session", anchor.at("session")},
                     {"epoch", anchor.at("epoch")},
                     {"nonce", std::to_string(nonce)},
                     {"ttl_ms", 180000}};
        validate_can_boundary_token(can_token);
    }

    auto can_observe = [&](const std::string &method, const std::string &identity_boot) {
        if (!android_spec_.contains("can_model_observer_sha256")) {
            throw VoyemuError("CAN_BOUNDARY_UNAVAILABLE", "sealed helper absent");
        }

        const CanGuestIdentity identity{session_id_,
                                        android_spec_.at("avd_name").get<std::string>(),
                                        android_boot_nonce_, android_resume_};
        const auto pid = android_.pid();
        const auto generation = android_generation_;
        auto value = collect_can_boundary(
                method, can_token, identity,
                android_spec_.at("can_model_observer_sha256").get<std::string>(), identity_boot,
                15000, [&](const auto &args, int limit) {
                    return adb(args, limit);
                });

        if (android_.pid() != pid || android_generation_ != generation || !android_.alive() ||
            boot() != identity_boot) {
            throw VoyemuError("CAN_BOUNDARY_STALE",
                              "owned Android changed during fence observation");
        }

        return value;
    };
    auto can_seal = [&] {
        const auto live = can_observe("boundary", old_boot);
        validate_can_boundary_overlap(live, expected_can, old_boot);

        if (live.at("stage") != "none" && live.at("stage") != "aborted") {
            throw VoyemuError("CAN_BOUNDARY_FROZEN", "existing fence on owned Android");
        }

        if (live.at("raw_queued") != "0" || live.at("raw_inflight_seq") != "0" ||
            live.at("semantic_queue") != "0") {
            throw VoyemuError("CAN_BOUNDARY_UNVERIFIED",
                              "pending CAN writers after the native anchor");
        }

        seal_attempted = true;
        active_can_boundary_ = true;
        auto sealed = can_boundary_dispatch("prepare-restart", [&](const auto &method) {
            return can_observe(method, old_boot);
        });
        validate_can_boundary_frozen(sealed, can_token, old_boot);
        validate_can_boundary_overlap(sealed, expected_can, old_boot);
        can_proof["prepared"] = std::move(sealed);
    };
    auto can_before_stop = [&](const char *phase, const char *previous) {
        auto now = can_observe("restart-status", old_boot);
        validate_can_boundary_unchanged(now, can_proof.at(previous), can_token, old_boot);
        can_proof[phase] = std::move(now);
    };
    auto can_recover = [&] {
        if (!seal_attempted || !active_can_boundary_) {
            return;
        }

        try {
            if (!android_.alive() || android_.pid() != old_android_pid ||
                android_generation_ != old_android_generation) {
                throw VoyemuError("CAN_BOUNDARY_STALE",
                                  "old Android unavailable for fence recovery");
            }

            const auto live = can_observe("boundary", old_boot);
            validate_can_boundary_source(live, old_boot);

            if (live.at("nonce") == can_token.at("nonce")) {
                auto aborted = can_boundary_dispatch("abort-restart", [&](const auto &method) {
                    return can_observe(method, old_boot);
                });
                validate_can_boundary_aborted(aborted, can_token, old_boot);
                can_proof["cleanup"] = {{"status", "aborted"}, {"witness", std::move(aborted)}};
            } else {
                if (live.at("stage") != "none" && live.at("stage") != "aborted") {
                    throw VoyemuError("CAN_BOUNDARY_FROZEN", "another fence is active");
                }

                can_proof["cleanup"] = {{"status", "fence_not_installed"}, {"witness", live}};
            }

            active_can_boundary_ = false;
        } catch (const std::exception &failure) {
            can_proof["cleanup"] = {{"status", "unverified"}, {"reason", failure.what()}};
        }
    };
    FullRestartActions actions;
    actions.now_ms = [] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
    };
    actions.publish = [&](const Json &receipt) {
        const auto status = receipt.value("status", std::string{});

        if (status == "unknown") {
            can_recover();
        }

        if (status == "completed") {
            const auto owner = read_private_json(directory_ / "automation-owner.json", 4096);

            if (owner.value("session_id", std::string{}) != session_id_ ||
                owner.at("ownership_id") != operation.at("ownership_id")) {
                throw VoyemuError("TEST_OWNERSHIP", "authority changed during full restart");
            }

            if (selected && read_private_json(selection_path, 4096) != selection) {
                throw VoyemuError("TEST_SESSION",
                                  "concrete machine selection changed during full restart");
            }
        }

        auto retained = receipt;

        if (with_can) {
            retained["can_boundary"] = can_proof;
        }

        retained["observed_processes"] = {{"android_pid", android_.pid()},
                                          {"android_alive", android_.alive()},
                                          {"qnx_pid", qnx_.pid()},
                                          {"qnx_alive", qnx_.alive()},
                                          {"qnx_generation", std::to_string(cluster_generation_)},
                                          {"current_qnx_finalized", cluster_finalized_}};
        write_private_json(receipt_path, retained);
        deliveries_["machine_restart"] = retained;
    };
    actions.stop_qnx = [&] {
        if (with_can) {
            can_seal();
            can_before_stop("before_qnx_stop", "prepared");
        }

        close_cluster(false, "owned_full_restart");

        if (qnx_.alive() || !cluster_finalized_ ||
            !deliveries_["qnx"].value("cleanup", Json::object()).value("processed", false)) {
            throw VoyemuError("SESSION_RESTART_CLEANUP",
                              "old QNX incarnation is not cleanly finalized");
        }
    };
    actions.stop_android = [&] {
        if (with_can) {
            can_before_stop("before_android_stop", "before_qnx_stop");
        }

        stop_android(lock, false);
        flush_android_releases(true);

        if (android_.alive() || !deliveries_["android"]
                                         .value("shutdown", Json::object())
                                         .value("ports_released", false)) {
            throw VoyemuError("SESSION_RESTART_CLEANUP", "old Android incarnation is not stopped");
        }

        android_powered_ = false;
        android_identity_ = false;
        media_connection_written_ = false;

        if (with_can) {
            can_proof["old_kernel_stopped"] = true;
            active_can_boundary_ = false;
        }

        can_history_anchors_.clear();
        std::filesystem::remove(directory_ / "media-connection.json");
    };
    actions.start_android = [&] {
        attach_android(android, true);
    };
    actions.start_qnx = [&] {
        attach_cluster(qnx, seconds, true);
    };
    actions.observe = [&] {
        // Let the existing startup pipeline establish real guest handshakes; old source services
        // remain retired.
        lock.unlock();
        try {
            tick();
        } catch (...) {
            lock.lock();
            throw;
        }

        lock.lock();

        if (stopped_ || test_stop_requested_ || !android_.alive() || !qnx_.alive()) {
            throw VoyemuError("SESSION_RESTART_GUEST",
                              "a restarted guest exited or shutdown was requested");
        }

        if (!android_identity_) {
            return Json{{"guest_acknowledged", false}};
        }

        const auto link = interguest_link_->status();
        const bool cold = deliveries_["qnx"]
                                  .value("quickboot", Json::object())
                                  .value("mode", std::string{}) == "cold";
        bool ack = restart_qnx_ack(link, prior_link_generation, cluster_generation_,
                                   interguest_qnx_generation_);
        auto identity = restart_boot_identity(boot(), cluster_generation_, qnx_.pid(), cold);
        identity["android_pid"] = android_.pid();
        identity["qnx"]["guest_link_generation"] = std::to_string(link.generation);
        identity["qnx"]["guest_utc_ack"] = {{"request", 1},
                                            {"expected", std::to_string(link.utc_expected)},
                                            {"actual", std::to_string(link.utc_actual)},
                                            {"status", link.utc_status},
                                            {"complete", link.utc_complete}};

        if (with_can && ack) {
            Json fresh;
            try {
                fresh = can_observe("boundary", identity.at("android_boot_id").get<std::string>());
            } catch (const std::exception &) {
                return Json{{"boot", identity}, {"guest_acknowledged", false}};
            }

            const auto fresh_boot = identity.at("android_boot_id").get<std::string>();
            validate_can_history(fresh, fresh_boot);
            validate_can_boundary_new_boot(fresh, fresh_boot);
            can_proof["after"] = fresh;
        }

        return Json{{"boot", identity}, {"guest_acknowledged", ack}};
    };
    actions.wait = [&] {
        lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        lock.lock();
    };
    auto result = run_full_restart(
            expected, before,
            {{"schema", 1},
             {"ok", true},
             {"session_id", session_id_},
             {"machine_identity", selection},
             {"operation_id", action},
             {"request_id", operation.at("request_id")},
             {"guest_ack_source", "fresh_owned_QNX_interguest_mailbox_after_cold_start"}},
            timeout, actions);

    if (with_can) {
        result["can_boundary"] = can_proof;
    }

    return result;
}

Json Session::reboot_android(const std::string &mode) {
    validate_android_reboot_mode(mode);
    std::lock_guard stop_lock(test_stop_mutex_);
    std::shared_ptr<voyemu::runtime::SourceCoordinator> sources;
    {
        std::lock_guard lock(mutex_);

        if (stopped_ || test_services_closed_ || android_spec_.empty() || !android_powered_) {
            throw VoyemuError("ANDROID_REBOOT_UNAVAILABLE", "owned Android guest is not running");
        }

        prevalidate_android_reboot();
        test_services_closed_ = true;
        cancel_android_identity_probe();
        android_identity_proof_operation_ = 0;

        if (test_watch_) {
            test_watch_->close();
        }

        if (test_can_watch_) {
            test_can_watch_->close();
        }

        for (const auto &[selection, projection] : test_source_watches_) {
            projection->close();
        }

        sources = test_sources_;
    }

    // Collectors may need both locks to finish their identity fences.
    if (sources) {
        sources->stop();
    }

    std::shared_ptr<UiObserver> observer;
    {
        std::lock_guard lock(mutex_);
        observer = std::exchange(ui_observer_, {});
    }

    if (observer && !observer->stop()) {
        const auto diagnostic = observer->shutdown_status();
        std::lock_guard lock(mutex_);
        ui_observer_ = observer;
        test_services_closed_ = false;
        throw VoyemuError("ANDROID_REBOOT_OBSERVER",
                          "old observer shutdown is unverified " + diagnostic.dump());
    }

    // The observer pointer was exchanged above, so stop_android cannot clear this lease.
    clear_ui_observer_metadata(directory_, session_id_);
    std::unique_lock lifecycle(lifecycle_mutex_);
    std::unique_lock lock(mutex_);
    AndroidIdentityScope identity_scope(android_identity_scope_depth_, android_identity_operation_);
    const auto reboot_io = lend_android_request_io(lock);
    const Restore reboot_deadline(
            android_request_deadline_,
            tighter_deadline(android_request_deadline_,
                             std::chrono::steady_clock::now() + std::chrono::seconds(180)));
    const Restore identity_shutdown(android_identity_stopping_, true);
    test_sources_.reset();
    test_watch_.reset();
    test_can_watch_.reset();
    test_source_watches_.clear();
    test_can_cursor_ = nullptr;
    test_can_generation_ = 0;
    test_demand_until_ = 0;
    test_ui_connection_ = Json();
    test_ui_subscription_ = Json();
    test_ui_sample_ = {};
    test_ui_sampled_ms_ = 0;
    struct Reopen {
        bool &closed;

        ~Reopen() {
            closed = false;
        }
    } reopen{test_services_closed_};

    if (stopped_ || !android_powered_) {
        throw VoyemuError("ANDROID_REBOOT_UNAVAILABLE", "Android stopped before reboot");
    }

    assert_android_identity();
    auto boot = [&] {
        const auto value = android_boot_id();

        if (!value || !android_boot_id_valid(*value)) {
            throw VoyemuError("ANDROID_REBOOT_BOOT", "complete Linux boot identity required");
        }

        return *value;
    };
    const auto before = boot();
    const auto old_generation = android_generation_;
    const auto old_pid = android_.pid();
    try {
        if (mode == "cold") {
            stop_android(lock, false);
            flush_android_releases(true);
            android_powered_ = false;
            android_identity_ = false;
            media_connection_written_ = false;
            std::filesystem::remove(directory_ / "media-connection.json");
            const auto specification = android_spec_;
            attach_android(specification, true);
        } else {
            if (ui_observer_) {
                if (!ui_observer_->stop()) {
                    throw VoyemuError("ANDROID_REBOOT_OBSERVER",
                                      "old observer shutdown is unverified " +
                                              ui_observer_->shutdown_status().dump());
                }

                ui_observer_.reset();
                std::filesystem::remove(directory_ / "ui-observer.json");
            }

            flush_android_releases(false);

            while (!android_events_.empty()) {
                deliver_android_event(android_events_.front());
                android_events_.pop_front();
            }

            // The command is fixed, never a shell fragment or caller-supplied executable.
            const auto submitted = adb({"reboot"}, 5000);

            if (submitted.exit_code || submitted.timed_out) {
                throw VoyemuError("ANDROID_REBOOT_UNKNOWN", "SDK reboot may have been submitted");
            }

            // A warm reboot retains the SDK process. Advance its authenticated launch
            // record before the completion probe checks the new generation.
            advance_android_launch_generation(directory_, session_id_, old_pid, old_generation);
            ++android_generation_;
            deliveries_["android"]["generation"] = android_generation_;
            reset_android_transaction();
            android_identity_mismatch_ = false;
            android_identity_ = false;
            android_clock_observed_ = false;
            android_clock_correction_attempted_ = false;
            android_clock_exit_code_ = -1;
            android_clock_arrival_ = {};
            android_transport_ready_ = false;
            android_transport_attempted_ = false;
            android_transport_boot_.clear();
            wheel_provisioned_ = false;
            android_revision_ = 0;
            android_boot_completed_ = false;
            android_displays_ready_ = false;
            android_display_activated_ = false;
            android_canvas_refreshed_ = false;
            primary_home_ready_ = false;
            clear_android_home_delivery(deliveries_["android"]);
            clear_android_camera_delivery(deliveries_["android"]);
            theme_.reset();
            oem_language_.reset();
            next_android_ = {};
            next_oem_settings_ = {};
            next_display_observation_ = {};
            next_display_activation_ = {};
            media_connection_written_ = false;
            std::filesystem::remove(directory_ / "media-connection.json");
        }

        deliveries_["android"]["status"] = "rebooting";
        deliveries_["android"]["reboot"] = {{"mode", mode},
                                            {"status", "pending"},
                                            {"boot_id_before", before},
                                            {"generation_before", old_generation},
                                            {"generation", android_generation_}};

        if (const auto after = await_android_reboot(lock, before, boot)) {
            return {{"ok", true},
                    {"session_id", session_id_},
                    {"mode", mode},
                    {"status", "completed"},
                    {"scope", "guest_boot_changed"},
                    {"boot_id_before", before},
                    {"boot_id", *after},
                    {"generation_before", old_generation},
                    {"generation", android_generation_},
                    {"android_pid_before", old_pid},
                    {"android_pid", android_.pid()},
                    {"application_ready", false}};
        }

        deliveries_["android"]["reboot"]["status"] = "unknown";
        throw VoyemuError("ANDROID_REBOOT_UNKNOWN",
                          "new Linux boot identity not verified before deadline");
    } catch (const std::exception &error) {
        deliveries_["android"]["reboot"]["status"] = "unknown";
        throw VoyemuError("ANDROID_REBOOT_UNKNOWN", error.what());
    }
}
} // namespace voyemu
