#include "api_internal.hpp"
#include "error.hpp"

namespace voyemu::api {
using namespace detail;

Json Api::dispatch_observe(const std::string &op, const Json &request, Clock::time_point deadline) {
    if (op == "session.observe") {
        const auto timeout = number(request, "timeout_ms", 1000, 0, 60000);
        Json operation{{"op", "test_output_state"}, {"timeout_ms", timeout}};
        validate_sources(request);

        if (request.contains("sources")) {
            operation["sources"] = request.at("sources");
        }

        return control(request, operation, false, static_cast<int>(timeout + 500)).at("state");
    }

    if (op == "session.watch.start" || op == "session.watch.read" || op == "session.watch.stop") {
        Json operation{{"op", op == "session.watch.start"  ? "test_watch_start"
                              : op == "session.watch.read" ? "test_watch_read"
                                                           : "test_watch_stop"}};
        const auto timeout = number(request, "timeout_ms", op == "session.watch.stop" ? 0 : 1000, 0,
                                    60000);
        operation["timeout_ms"] = timeout;

        if (op == "session.watch.start") {
            validate_sources(request);
            voyemu::runtime::validate_condition(request.at("condition"));
            operation["condition"] = request.at("condition");
            operation["lease_ms"] = number(request, "lease_ms", 30000, 1, 60000);

            if (request.contains("sources")) {
                operation["sources"] = request.at("sources");
            }
        } else {
            operation["watch_id"] = text(request, "watch_id");
            operation["epoch"] = text(request, "epoch");

            if (op == "session.watch.read") {
                operation["cursor"] = text(request, "cursor");
                operation["limit"] = number(request, "limit", 1, 1, 32);
            }
        }

        return control(request, operation, false, static_cast<int>(timeout + 500));
    }

    if (op == "session.wait" && request.contains("condition")) {
        validate_sources(request);
        voyemu::runtime::validate_condition(request.at("condition"));
        const auto timeout = number(request, "timeout_ms", 10000, 1, 60000);
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeout);
        Json start{{"op", "test_watch_start"},
                   {"condition", request.at("condition")},
                   {"lease_ms", std::min<std::uint64_t>(60000, timeout + 1000)},
                   {"timeout_ms", std::min<std::uint64_t>(1000, timeout)}};

        if (request.contains("sources")) {
            start["sources"] = request.at("sources");
        }

        auto ready = control(request, start, false,
                             static_cast<int>(std::min<std::uint64_t>(1000, timeout) + 500));

        if (ready.value("status", std::string{}) != "ready") {
            return ready;
        }

        Json identity{{"watch_id", ready.at("watch_id")}, {"epoch", ready.at("epoch")}};
        auto finish = [&] {
            auto close = identity;
            close["op"] = "test_watch_stop";
            close["timeout_ms"] = 0;

            return control(request, close, false, 500);
        };
        Json observed = ready;
        try {
            while (observed.value("result", Json::object())
                           .value("status", std::string("pending")) == "pending") {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               deadline - Clock::now())
                                               .count();

                if (remaining <= 0) {
                    observed["timed_out"] = true;
                    break;
                }

                auto read = identity;
                read["op"] = "test_watch_read";
                read["cursor"] = observed.at("cursor");
                read["limit"] = 1;
                read["timeout_ms"] = std::min<std::int64_t>(1000, remaining);
                observed = control(request, read, false,
                                   static_cast<int>(std::min<std::int64_t>(1000, remaining) + 500));

                if (observed.value("status", std::string{}) == "ended" ||
                    observed.value("gap", false)) {
                    break;
                }
            }

            observed["cleanup"] = finish();

            return observed;
        } catch (...) {
            try {
                finish();
            } catch (...) { /* Ignored: cleanup must not replace the original failure. */
            }

            throw;
        }
    }

    if (op == "session.wait") {
        const auto predicate = text(request, "predicate");

        if ((predicate == "android.delivery" || predicate == "qnx.delivery") &&
            !request.contains("revision")) {
            throw VoyemuError("TEST_ARGUMENT", "delivery wait requires revision");
        }

        const auto timeout = number(request, "timeout_ms", 10000, 1, 60000);
        const auto start = Clock::now(), deadline = start + std::chrono::milliseconds(timeout);
        Json observed = observation(Json::object(), predicate, request);
        unsigned attempts = 0, failures = 0;
        std::string last_error;
        auto metadata = [&] {
            observed["elapsed_ms"] =
                    std::chrono::duration<double, std::milli>(Clock::now() - start).count();
            observed["status_rpc_attempts"] = attempts;
            observed["transport_failures"] = failures;

            if (!last_error.empty()) {
                observed["last_transport_error"] = last_error;
            }
        };

        do {
            const auto remaining = std::max<std::int64_t>(
                    1,
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                            .count());
            ++attempts;
            try {
                const auto status =
                        control(request, {{"op", "status"}}, false,
                                static_cast<int>(std::min<std::int64_t>(1000, remaining)));
                session_record(request, false);
                observed = observation(status, predicate, request);
                observed["observation_status"] = "observed";
                metadata();

                if (status.value("stopped", false)) {
                    observed["ready"] = false;
                    observed["accepted"] = false;
                    observed["terminal"] = true;
                    observed["pending_reason"] = "source session stopped";

                    return observed;
                }

                if (Clock::now() >= deadline) {
                    break;
                }

                if (observed.at("ready").get<bool>()) {
                    return observed;
                }
            } catch (const std::exception &) {
                const auto code = error(std::current_exception()).at("code").get<std::string>();

                if (code != "IPC_TIMEOUT_UNKNOWN" && code != "IPC_CONNECT" &&
                    code != "IPC_READ_UNKNOWN" && code != "IPC_WRITE_UNKNOWN") {
                    throw;
                }

                // Only status is retried. A changed active epoch or ownership path
                // remains fatal even when the transport failed before replying.
                session_record(request, false);
                ++failures;
                last_error = code;
                observed["ready"] = false;
                observed["observation_status"] = "unavailable";
                metadata();
            }

            const auto pause =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                            .count();

            if (pause > 0) {
                std::this_thread::sleep_for(
                        std::chrono::milliseconds(std::min<std::int64_t>(25, pause)));
            }
        } while (Clock::now() < deadline);

        metadata();
        observed["ready"] = false;
        observed["timed_out"] = true;

        if (observed.value("observation_status", std::string{}) == "unavailable") {
            observed["outcome"] = "unknown";
        }

        observed["pending_reason"] =
                observed.value("observation_status", std::string{}) == "unavailable"
                        ? "status transport remains unavailable; predicate unverified"
                        : "named predicate remains unverified before deadline";

        return observed;
    }

    if (op == "vehicle.can.get") {
        Json query{{"schema", 1}};

        for (const char *key : {"states", "cursor", "limit"}) {
            if (request.contains(key)) {
                query[key] = request.at(key);
            }
        }

        validate_can_request(query);
        const auto timeout = number(request, "timeout_ms", 5000, 1, 10000);

        return control(request,
                       {{"op", "test_can_observation"}, {"query", query}, {"timeout_ms", timeout}},
                       false, static_cast<int>(timeout + 250))
                .at("observation");
    }

    if (op == "cluster.ipk.history") {
        Json query{{"schema", 1}};

        for (const auto &[key, value] : request.items()) {
            if (key == "cursor" || key == "limit") {
                query[key] = value;
            } else if (key != "schema" && key != "request_id" && key != "operation_id" &&
                       key != "op" && key != "profile" && key != "session" && key != "machine" &&
                       key != "timeout_ms") {
                throw VoyemuError("TEST_ARGUMENT",
                                  "IPK history inspection is read-only and closed");
            }
        }

        validate_ipk_request(query);
        const auto timeout = number(request, "timeout_ms", 5000, 1, 10000);

        return control(request,
                       {{"op", "test_ipk_history"}, {"query", query}, {"timeout_ms", timeout}},
                       false, static_cast<int>(timeout + 250))
                .at("observation");
    }

    if (op == "vehicle.mode.history") {
        Json query{{"schema", 1}};

        for (const auto &[key, value] : request.items()) {
            if (key == "cursor" || key == "limit") {
                query[key] = value;
            } else if (key != "schema" && key != "request_id" && key != "operation_id" &&
                       key != "op" && key != "profile" && key != "session" && key != "machine" &&
                       key != "timeout_ms") {
                throw VoyemuError("TEST_ARGUMENT",
                                  "mode history inspection is read-only and closed");
            }
        }

        validate_mode_request(query);
        const auto timeout = number(request, "timeout_ms", 5000, 1, 10000);

        return control(request,
                       {{"op", "test_mode_history"}, {"query", query}, {"timeout_ms", timeout}},
                       false, static_cast<int>(timeout + 250))
                .at("observation");
    }

    if (op == "vehicle.can.history") {
        for (const auto &[key, value] : request.items()) {
            (void)value;

            if (key != "schema" && key != "request_id" && key != "operation_id" && key != "op" &&
                key != "profile" && key != "session" && key != "machine" && key != "timeout_ms") {
                throw VoyemuError("TEST_ARGUMENT",
                                  "CAN history inspection is read-only and closed");
            }
        }

        const auto timeout = number(request, "timeout_ms", 5000, 1, 15000);
        const auto observed = control(request,
                                      {{"op", "test_can_history"}, {"timeout_ms", timeout}}, false,
                                      static_cast<int>(timeout + 500))
                                      .at("observation");

        if (observed.at("session_id") != request.at("session").at("id")) {
            throw VoyemuError("CAN_BOUNDARY_STALE", "CAN history belongs to another session");
        }

        if (observed.at("status") == "unavailable") {
            if (observed.size() != 6 || observed.at("schema") != 1 ||
                observed.at("producer") != "closed_ecu_boundary" ||
                observed.at("capability") != "closed_ecu_boundary_v1" ||
                !observed.at("reason").is_string()) {
                throw VoyemuError("CAN_BOUNDARY_PROTOCOL", "invalid unavailable history result");
            }
        } else {
            validate_can_history_observation(observed);
        }

        return observed;
    }

    if (op == "vehicle.can.model") {
        Json query{{"schema", 1}};

        for (const char *key : {"mode", "cursor", "limit"}) {
            if (request.contains(key)) {
                query[key] = request.at(key);
            }
        }

        validate_can_model_request(query);
        const auto timeout = number(request, "timeout_ms", 5000, 1, 10000);

        return control(request,
                       {{"op", "test_can_model_observation"},
                        {"query", query},
                        {"timeout_ms", timeout}},
                       false, static_cast<int>(timeout + 250))
                .at("observation");
    }

    if (op == "session.screenshot") {
        return capture(request);
    }

    if (op == "session.ui") {
        return session_ui(request, deadline);
    }

    if (op == "session.logs") {
        if (request.contains("details") && !request.at("details").is_boolean()) {
            throw VoyemuError("TEST_ARGUMENT", "log details must be boolean");
        }

        const auto source = request.value("source", std::string("supervisor"));

        if (source == "incidents") {
            const auto system = text(request, "system");

            if (system == "cluster") {
                throw VoyemuError("TEST_UNSUPPORTED", "cluster incident logging is unavailable");
            }

            if (system != "multimedia") {
                throw VoyemuError("TEST_ARGUMENT", "unknown incident log system");
            }

            const auto timeout = number(request, "timeout_ms", 1000, 0, 60000);
            auto logs = transports_.android
                                ->logs(request,
                                       {{"source", source},
                                        {"system", system},
                                        {"timeout_ms", timeout},
                                        {"limit", number(request, "limit", 16, 1, 32)},
                                        {"cursor", request.value("cursor", Json())}},
                                       static_cast<int>(timeout + 500))
                                .at("logs");

            if (!logs.is_object() || logs.value("source", std::string{}) != source ||
                logs.value("system", std::string{}) != system) {
                throw VoyemuError("TEST_LOGS_PROTOCOL", "incident source or system mismatch");
            }

            return logs;
        }

        if (source == "anr" || source == "native") {
            if (request.contains("details") || request.contains("cursor")) {
                throw VoyemuError("TEST_ARGUMENT",
                                  "ANR/native snapshots have no details option or cursor");
            }

            return anr(request);
        }

        if (source == "android") {
            if (source == "anr" && request.contains("details")) {
                throw VoyemuError("TEST_ARGUMENT",
                                  "ANR source already includes bounded diagnostic details");
            }

            if (request.contains("cursor")) {
                throw VoyemuError("TEST_UNSUPPORTED",
                                  "Android diagnostic snapshots have no lossless cursor");
            }

            const auto timeout = number(request, "timeout_ms", 5000, 1, 10000);
            auto logs = transports_.android
                                ->logs(request,
                                       {{"source", source},
                                        {"timeout_ms", timeout},
                                        {"details", request.value("details", false)}},
                                       static_cast<int>(timeout + 500))
                                .at("logs");

            if (!logs.is_object() || logs.value("source", std::string{}) != source) {
                throw VoyemuError(
                        "TEST_LOGS_PROTOCOL",
                        "diagnostic source mismatch; running supervisor does not support this source");
            }

            return logs;
        }

        if (request.contains("details")) {
            throw VoyemuError("TEST_ARGUMENT", "log details require Android source");
        }

        if (source != "supervisor") {
            throw VoyemuError("TEST_ARGUMENT",
                              "log source must be supervisor, android, anr, native or incidents");
        }

        const auto record = session_record(request, false);

        return read_logs(std::filesystem::path(record.at("directory").get<std::string>()) /
                                 "supervisor.log",
                         request);
    }

    if (op == "operation.get") {
        std::string id;
        std::optional<AdmissionResult> admitted;
        const auto admissions = root_ / ".local/build/automation/admissions";

        if (request.contains("lookup_request_id")) {
            if (std::filesystem::exists(admissions)) {
                admitted = AdmissionStore(admissions)
                                   .lookup(admission_scope(request),
                                           text(request, "lookup_request_id"));
            }

            if (!admitted) {
                throw VoyemuError("TEST_OPERATION_NOT_FOUND",
                                  "no admission for this request and scope");
            }

            id = admitted->operation_id;
        } else {
            id = text(request, "id");
        }

        if (!token(id)) {
            throw VoyemuError("TEST_ARGUMENT", "valid operation ID required");
        }

        const auto path = root_ / ".local/build/automation/operations" / (id + ".json");

        if (admitted && !std::filesystem::exists(path) && !std::filesystem::is_symlink(path)) {
            Json record{{"operation_id", id}, {"status", admitted->status}};

            if (admitted->response) {
                record["response"] = *admitted->response;

                if (record.at("status") == "terminal") {
                    record["outcome"] = terminal_outcome(record.at("response"));
                }
            }

            return record;
        }

        // Durable action responses are bounded at8MiB; allow the small mirror envelope too.
        auto record = read_private_json(path, 8 * 1024 * 1024 + 32768);

        if (admitted) {
            if (admitted->response) {
                record["response"] = *admitted->response;
                record["status"] = admitted->status;
            } else if (record.value("status", std::string{}) != "terminal") {
                record["status"] = admitted->status;
            } else {
                record["admission_status"] = admitted->status;
            }
        }

        if (record.value("status", std::string{}) == "terminal" && record.contains("response")) {
            record["outcome"] = terminal_outcome(record.at("response"));
        }

        if (record.value("op", std::string{}) == "session.restart") {
            // Lookup observes the durable runtime action, never dispatches or replays a restart.
            const auto session = session_record(request, true);

            if (record.value("session_id", std::string{}) !=
                        session.at("session_id").get<std::string>() ||
                record.value("scope", std::string{}) !=
                        "session:" + session.at("session_id").get<std::string>() ||
                record.value("ownership_sha256", std::string{}) !=
                        sha256_bytes(text(request.at("session"), "ownership_id"))) {
                throw VoyemuError("TEST_SESSION", "restart action belongs to another session");
            }

            const auto file = std::filesystem::path(session.at("directory").get<std::string>()) /
                              ("full-restart-" + id + ".json");

            if (ordinary_native_launch_file(file)) {
                const auto receipt = read_private_json(file, 32768);

                if (receipt.value("session_id", Json()) != session.at("session_id") ||
                    receipt.value("operation_id", Json()) != id ||
                    receipt.value("request_id", Json()) != record.at("request_id")) {
                    throw VoyemuError("TEST_SESSION", "retained restart receipt identity differs");
                }

                if (receipt.value("status", std::string{}) == "completed") {
                    validate_restart_complete(receipt, record.at("expected_boot"));
                }

                if (record.contains("expected_can") &&
                    receipt.value("status", std::string{}) == "completed") {
                    validate_can_restart_receipt(receipt, record.at("expected_boot"),
                                                 record.at("expected_can"));
                }

                const auto selection =
                        std::filesystem::path(session.at("directory").get<std::string>()) /
                        "machine-selection.json";

                if (ordinary_native_launch_file(selection) &&
                    receipt.value("machine_identity", Json()) !=
                            read_private_json(selection, 4096)) {
                    throw VoyemuError("TEST_SESSION", "restart concrete machine selection differs");
                }

                record["runtime_receipt"] = receipt;
                record["runtime_outcome"] = receipt.value("status", std::string{}) == "completed"
                                                    ? "completed"
                                                    : "unknown";
            }
        }

        if ((record.value("op", std::string{}) == "session.start" ||
             record.value("op", std::string{}) == "test.run") &&
            record.contains("profile") && record.contains("ownership_id")) {
            const auto name = profile(record);
            const auto machine = machine_identity(name, record.value("machine", std::string{}));
            const auto active_path = session_active_directory(root_, name, machine) /
                                     (name + ".json");

            if (ordinary_native_launch_file(active_path)) {
                auto active = read_private_json(active_path, 4096);
                const auto active_id = active.at("session_id").get<std::string>();

                if (token(active_id)) {
                    const auto directory = native_session_directory(root_, name, machine,
                                                                    active_id);

                    if (ordinary_native_launch_file(directory / "automation-owner.json")) {
                        auto owner = read_private_json(directory / "automation-owner.json", 4096);

                        if (owner.value("ownership_id", std::string{}) ==
                            record.value("ownership_id", std::string{})) {
                            record["owned_session_observed"] = {
                                    {"id", active.at("session_id")},
                                    {"ownership_id", owner.at("ownership_id")}};
                        }
                    }
                }
            }
        }

        return record;
    }

    return unhandled_operation();
}

Json Api::anr(const Json &request) {
    const auto source = request.at("source").get<std::string>();

    if (source == "native" &&
        (request.contains("tags") || request.contains("buffers") || request.contains("command"))) {
        throw VoyemuError("TEST_ARGUMENT", "native diagnostic tags, buffers and command are fixed");
    }

    const auto tombstone = diagnostic_tombstone(request, source);
    const auto timeout = number(request, "timeout_ms", 5000, 1, 10000);
    const auto started = Clock::now(), deadline = started + std::chrono::milliseconds(timeout);
    auto remaining = [&]() {
        const auto value =
                std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();

        if (value < 1) {
            throw VoyemuError("TEST_LOGS_TIMEOUT", "ANR read deadline expired");
        }

        return static_cast<int>(value);
    };
    const auto record = session_record(request, false),
               before = control(request, {{"op", "status"}}, false, remaining());

    if (before.value("stopped", true) || before.value("android_pid", 0) < 2) {
        throw VoyemuError("TEST_LOGS_STALE", "live owned Android required");
    }

    const auto directory = std::filesystem::path(record.at("directory").get<std::string>()),
               connection_path = directory / "media-connection.json";
    const auto connection_record = read_private_json(connection_path, 4096);
    const auto session = record.at("session_id").get<std::string>();
    const auto connection = media::read_connection(connection_path, session);

    if (connection_record.at("vm_pid") != before.at("android_pid")) {
        throw VoyemuError("TEST_LOGS_STALE", "SDK descriptor PID differs");
    }

    const auto selection_path = directory / "machine-selection.json";
    const auto selection = ordinary_native_launch_file(selection_path)
                                   ? read_private_json(selection_path, 4096)
                                   : Json(nullptr);
    const auto machine = diagnostic_machine_name(before, selection);
    const auto launch_path =
            profile_launch_directory(root_, profile(request),
                                     voyemu::machine_identity(profile(request), machine)) /
            "android-launch.json";
    const auto launch_hash = sha256_file(launch_path);
    const auto launch = read_private_json(launch_path);

    if (connection_record.at("serial_port") != launch.at("port")) {
        throw VoyemuError("TEST_LOGS_STALE", "owned launch SDK binding differs");
    }

    const auto boot_before = transports_.android->boot_identity(request, remaining());

    if (boot_before.at("android_pid") != before.at("android_pid")) {
        throw VoyemuError("TEST_LOGS_STALE", "Android changed before ANR read");
    }

    const auto budget = remaining();
    Json query = {{"source", source},
                  {"timeout_ms", budget},
                  {"android_pid", before.at("android_pid")},
                  {"boot_id", boot_before.at("boot_id")}};

    if (!tombstone.empty()) {
        query["tombstone"] = tombstone;
    }

    auto result = transports_.android->logs(request, query, budget).at("logs");

    if (!result.is_object() || result.value("source", std::string{}) != source ||
        result.value("session_id", std::string{}) != session) {
        throw VoyemuError(
                "TEST_LOGS_PROTOCOL",
                "diagnostic source mismatch; running supervisor does not support this source");
    }

    if (result.at("android_pid") != before.at("android_pid") ||
        result.at("boot_id") != boot_before.at("boot_id")) {
        throw VoyemuError("TEST_LOGS_STALE", "diagnostic epoch differs");
    }

    const auto boot_after = transports_.android->boot_identity(request, remaining()),
               after = control(request, {{"op", "status"}}, false, remaining());
    const auto final_connection = media::read_connection(connection_path, session);
    const auto final_selection = ordinary_native_launch_file(selection_path)
                                         ? read_private_json(selection_path, 4096)
                                         : Json(nullptr);

    if (diagnostic_machine_name(after, final_selection) != machine ||
        sha256_file(launch_path) != launch_hash) {
        throw VoyemuError("TEST_LOGS_STALE", "selected launch configuration changed");
    }

    if (after.value("stopped", true) || after.at("android_pid") != before.at("android_pid") ||
        boot_after != boot_before || final_connection.port != connection.port ||
        final_connection.bearer != connection.bearer) {
        throw VoyemuError("TEST_LOGS_STALE", "Android identity changed during ANR read");
    }

    result["elapsed_ms"] =
            std::chrono::duration<double, std::milli>(Clock::now() - started).count();

    return result;
}

Json Api::capture(const Json &request) {
    const auto screens = requested_screens(request);
    const bool wants_android = std::any_of(screens.begin(), screens.end(), [](const Json &screen) {
        return screen != "cluster";
    });
    const bool wants_cluster = std::find(screens.begin(), screens.end(), "cluster") !=
                               screens.end();

    if (request.contains("rect") && screens.size() != 1) {
        throw VoyemuError("TEST_ARGUMENT", "rect requires exactly one screen");
    }

    auto rect = requested_rect(request);
    const auto after_sequence = number(request, "after_sequence", 0, 0, UINT64_MAX);

    if (wants_android && after_sequence > 0) {
        throw VoyemuError("TEST_UNSUPPORTED",
                          "positive after_sequence is unavailable for Android unary capture");
    }

    const auto max_age = request.contains("max_age_ms") ? number(request, "max_age_ms", 0, 1, 10000)
                                                        : 0;

    if (max_age && wants_cluster) {
        throw VoyemuError("TEST_UNSUPPORTED", "max_age_ms currently requires Android screens");
    }

    const bool selected = request.contains("selector");

    if (selected && (screens.size() != 1 || wants_cluster || request.contains("rect"))) {
        throw VoyemuError("TEST_ARGUMENT", "selector requires one Android screen without rect");
    }

    const auto timeout = number(request, "timeout_ms", 5000, 1, 10000),
               skew = number(request, "max_skew_ms", 500, 1, 10000);
    const auto start = Clock::now(), deadline = start + std::chrono::milliseconds(timeout);
    const auto remaining = [&]() {
        const auto value =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
                        .count();

        if (value < 1) {
            throw VoyemuError("TEST_FRAME_TIMEOUT", "frame capture deadline elapsed");
        }

        return static_cast<int>(value);
    };
    const auto record = session_record(request, false);
    const auto directory = std::filesystem::path(record.at("directory").get<std::string>());
    const auto before = control(request, {{"op", "status"}}, false, remaining());

    if (before.value("stopped", true)) {
        throw VoyemuError("TEST_SESSION", "capture needs a live session");
    }

    const bool cluster_on = before.value("qnx_pid", 0) > 0;

    if (wants_cluster && !cluster_on) {
        throw VoyemuError("TEST_UNSUPPORTED", "requested cluster screen is unavailable");
    }

    // Each requested Android screen at the size of its profile screen; the HUD has no guest frames.
    const auto machine = status_screens(before);
    std::map<std::string, media::GuestDisplay> displays;

    for (const auto &screen : screens) {
        if (screen != "cluster") {
            displays[screen.get<std::string>()] = android_screen(machine,
                                                                 screen.get<std::string>());
        }
    }

    const auto qnx_generation = before.value("deliveries", Json::object())
                                        .value("qnx", Json::object())
                                        .value("generation", 0ULL);
    Json manifest{{"schema", 1},
                  {"session_id", record.at("session_id")},
                  {"android_pid", before.at("android_pid")},
                  {"screens", screens},
                  {"capture_mode", "parallel_fenced"},
                  {"cluster_powered", cluster_on},
                  {"visible_effect_verified", false},
                  {"process_provenance_available", false},
                  {"launcher_generation_verified", false},
                  {"consistency_scope", Json::array({"session", "requested_source_generation",
                                                     "host_skew_upper_bound"})},
                  {"frames", Json::array()}};

    if (wants_cluster) {
        manifest["qnx_generation"] = std::to_string(qnx_generation);
    }

    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> encoded;
    std::uint64_t first = 0, last = 0;
    std::mutex collected;
    Json boot_before;

    if (wants_android) {
        boot_before = transports_.android->boot_identity(request, remaining());
        manifest["android_boot_id"] = boot_before.at("boot_id");
        manifest["android_boot_identity_verified"] = true;
    }

    Json geometry_before;
    auto read_geometry = [&]() {
        auto read = request;
        read.erase("selector");
        read.erase("expected");
        read.erase("rect");
        read["timeout_ms"] = remaining();

        if (request.value("scope", std::string{}) != "interactive") {
            if (screens.at(0) == "primary") {
                read.erase("scope");
            } else {
                read["scope"] = "all_attached";
            }
        }

        auto geometry_request = request;
        geometry_request["screens"] = screens;

        return capture_geometry(geometry_request, tree(read));
    };

    if (selected) {
        geometry_before = read_geometry();

        if (geometry_before.at("boot_id") != boot_before.at("boot_id")) {
            throw VoyemuError("TEST_CAPTURE_STALE", "ROI boot changed before capture");
        }

        const auto &b = geometry_before.at("rect");
        rect = {b.at("x").get<std::int64_t>(), b.at("y").get<std::int64_t>(),
                b.at("width").get<std::int64_t>(), b.at("height").get<std::int64_t>()};
    }

    auto append = [&](std::string_view screen, std::span<const std::uint8_t> pixels,
                      std::size_t width, std::size_t height, bool bgra, std::uint64_t sequence,
                      std::uint64_t source_timestamp, std::string_view clock, std::uint64_t begin,
                      std::uint64_t end, std::uint64_t age_upper_us = 0) {
        auto cropped = crop_frame(pixels, width, height, width * 4, rect, bgra);
        auto png = voyemu::output::png_frame(cropped.pixels, cropped.rect.width,
                                             cropped.rect.height, bgra);
        Json frame{
                {"screen", screen},
                {"source", screen == "cluster" ? "qnx" : "android_sdk"},
                {"width", cropped.rect.width},
                {"height", cropped.rect.height},
                {"source_width", width},
                {"source_height", height},
                {"rect", rect_json(cropped.rect)},
                {"sequence", std::to_string(sequence)},
                {"source_timestamp_ns", std::to_string(source_timestamp)},
                {"source_clock_domain", clock},
                {"host_interval",
                 {{"clock_domain", "host.steady"},
                  {"clock_id", record.at("session_id")},
                  {"start_ns", std::to_string(begin * 1000)},
                  {"end_ns", std::to_string(end * 1000)}}},
                {"sha256", sha256_bytes({reinterpret_cast<const char *>(png.data()), png.size()})},
                {"file", std::string(screen) + ".png"},
                {"derived", request.contains("rect") || selected},
                {"freshness",
                 {{"source_clock_mapped", false},
                  {"newer_guest_frame_proven", screen == "cluster" && after_sequence > 0}}}};

        if (max_age) {
            frame["freshness"] = {{"source_clock_mapped", true},
                                  {"basis", "sdk_frame_generation_estimate"},
                                  {"age_upper_bound_ms", age_upper_us / 1000.0},
                                  {"max_age_ms", max_age},
                                  {"within_limit", true},
                                  {"newer_guest_frame_proven", false}};
        }

        if (screen != "cluster") {
            frame["sdk_display_id"] = displays.at(std::string(screen)).id;
            frame["display_id"] = nullptr;
            frame["display_identity_basis"] = "SDK slot; guest display mapping not observed";
        }

        std::lock_guard lock(collected);
        manifest["frames"].push_back(std::move(frame));
        encoded.emplace_back(std::string(screen) + ".png", std::move(png));
        first = first ? std::min(first, begin) : begin;
        last = std::max(last, end);
    };
    auto android = [&](const std::string &screen) {
        const auto display = displays.at(screen);
        const auto sample = []() {
            return CaptureClock{static_cast<std::uint64_t>(
                                        std::chrono::duration_cast<std::chrono::microseconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count()),
                                monotonic_us()};
        };
        const auto clock_before = sample();
        const auto begin = clock_before.steady_us;
        auto image = transports_.android->frame(
                directory, record.at("session_id").get<std::string>(), display, remaining());
        const auto clock_after = sample();
        const auto end = clock_after.steady_us;
        const auto age_upper_us =
                max_age ? capture_age_upper_us(image.timestamp_us, clock_before, clock_after) : 0;

        if (max_age && age_upper_us > max_age * 1000) {
            throw VoyemuError("TEST_FRAME_STALE",
                              "SDK frame generation estimate exceeds max_age_ms");
        }

        if (image.display != display.id || image.width != display.width ||
            image.height != display.height || image.pixel_offset > image.storage.size() ||
            image.storage.size() - image.pixel_offset < image.pixels().size()) {
            throw VoyemuError("TEST_FRAME", "wrong SDK slot or incomplete pixels");
        }

        if (image.timestamp_us > UINT64_MAX / 1000) {
            throw VoyemuError("TEST_FRAME", "source timestamp overflows nanoseconds");
        }

        append(screen, image.pixels(), image.width, image.height, false, image.sequence,
               image.timestamp_us * 1000, "host.unix.sdk_frame_estimate", begin, end, age_upper_us);
    };
    auto cluster = [&]() {
        const auto begin = monotonic_us();
        const auto frame = transports_.qnx->frame(directory, after_sequence, remaining());

        if (!frame) {
            throw VoyemuError("TEST_FRAME_TIMEOUT", "frame capture deadline elapsed");
        }

        const auto end = monotonic_us();

        if (frame->width != 1920 || frame->height != 720 ||
            frame->bgra.size() != frames::pixel_bytes) {
            throw VoyemuError("TEST_FRAME", "incomplete QNX frame");
        }

        append("cluster",
               {reinterpret_cast<const std::uint8_t *>(frame->bgra.data()), frame->bgra.size()},
               frame->width, frame->height, true, frame->sequence, frame->timestamp_ns,
               "qnx.frame_transport", begin, end);
    };
    {
        std::latch gate(1);
        std::vector<std::future<void>> jobs;
        try {
            for (const auto &selected : screens) {
                const auto screen = selected.get<std::string>();
                jobs.push_back(std::async(std::launch::async, [&, screen] {
                    gate.wait();

                    if (screen == "cluster") {
                        cluster();
                    } else {
                        android(screen);
                    }
                }));
            }
        } catch (...) {
            gate.count_down();
            throw;
        }

        gate.count_down();

        for (auto &job : jobs) {
            job.get();
        }

        std::sort(manifest["frames"].begin(), manifest["frames"].end(),
                  [](const Json &left, const Json &right) {
                      return left.at("screen").get<std::string>() <
                             right.at("screen").get<std::string>();
                  });
    }

    if (selected) {
        const auto geometry_after = read_geometry();
        verify_capture_geometry(geometry_before, geometry_after);
        manifest["roi"] = {{"selector", request.at("selector")},
                           {"before", geometry_before},
                           {"after", geometry_after},
                           {"geometry_verified", true},
                           {"atomic", false},
                           {"pixels_match_node", false},
                           {"occlusion_basis", "known_window_bounds_and_layer"}};
    }

    Json boot_after;

    if (wants_android) {
        boot_after = transports_.android->boot_identity(request, remaining());
    }

    const auto after = control(request, {{"op", "status"}}, false, remaining());
    const bool android_changed = wants_android &&
                                 (boot_after.at("boot_id") != boot_before.at("boot_id") ||
                                  boot_before.at("android_pid") != before.at("android_pid") ||
                                  boot_after.at("android_pid") != after.at("android_pid") ||
                                  after.at("android_pid") != before.at("android_pid"));
    const bool qnx_changed = wants_cluster &&
                             (after.value("qnx_pid", 0) != before.value("qnx_pid", 0) ||
                              after.value("deliveries", Json::object())
                                              .value("qnx", Json::object())
                                              .value("generation", 0ULL) != qnx_generation);
    const bool epoch_changed = after.value("stopped", true) || android_changed || qnx_changed;
    manifest["host_interval"] = {{"clock_domain", "host.steady"},
                                 {"clock_id", record.at("session_id")},
                                 {"start_ns", std::to_string(first * 1000)},
                                 {"end_ns", std::to_string(last * 1000)}};
    manifest["skew_upper_bound_ms"] = (last - first) / 1000.;
    const bool excessive_skew = last - first > skew * 1000;
    manifest["accepted"] = !epoch_changed && !excessive_skew;
    manifest["frames_consistent"] = !epoch_changed && !excessive_skew;
    manifest["atomic"] = false;
    manifest["exported_frame_verified"] = wants_cluster;
    manifest["android_frames_verified"] = wants_android;
    manifest["qnx_frame_verified"] = wants_cluster;

    if (epoch_changed || excessive_skew) {
        manifest["validation_error"] = {
                {"code", epoch_changed ? "TEST_FRAME_EPOCH" : "TEST_FRAME_SKEW"},
                {"message",
                 epoch_changed
                         ? "Requested source changed during capture; artifacts are rejected evidence"
                         : "Screen bundle exceeds requested host skew bound; artifacts are rejected evidence"}};
    }

    const auto output = artifacts(root_, request);

    for (const auto &[name, bytes] : encoded) {
        voyemu::output::write_artifact(output / name, bytes);
    }

    new_json(output / "manifest.json", manifest);
    manifest["artifact_dir"] = output.string();
    manifest["manifest"] = (output / "manifest.json").string();
    manifest["elapsed_ms"] =
            std::chrono::duration<double, std::milli>(Clock::now() - start).count();

    return manifest;
}
} // namespace voyemu::api
