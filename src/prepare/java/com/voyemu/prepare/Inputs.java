package com.voyemu.prepare;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Owner inputs and receipts only. Embedded definitions are never rewritten. */
final class Inputs {
    record Checked(boolean ok, Map<String, Object> pins, List<Object> checks) {}

    /** Selected owner source of one fetch and the names it acquired. */
    private record Acquisition(
            Arguments args,
            Path imported,
            Toolchains tools,
            String serial,
            java.util.function.Consumer<String> log,
            List<String> fetched) {}

    static Map<String, Object> definitions(ProfileRegistry.Profile profile) {
        return Json.obj(profile.data(), "original");
    }

    static String originalsProfile(ProfileRegistry.Profile profile, Storage storage) {
        return Files.isDirectory(storage.originals(profile.id()))
                ? profile.id()
                : profile.referenceProfile();
    }

    static Path originals(ProfileRegistry.Profile profile, Storage storage) {
        return storage.originals(originalsProfile(profile, storage));
    }

    static Map<String, Object> receiptPins(ProfileRegistry.Profile profile, Storage storage)
            throws Exception {
        Path path =
                Storage.confined(
                        storage.data(),
                        "profiles/" + originalsProfile(profile, storage) + "/receipt.json");

        if (!Files.exists(path)) {
            return Map.of();
        }

        Failure.require(
                Files.isRegularFile(path) && !Files.isSymbolicLink(path),
                "INPUT_RECEIPT_INVALID",
                "Input receipt must be an ordinary file",
                3);
        Map<String, Object> receipt = Json.object(Json.parse(Files.readString(path)));
        Failure.require(
                Json.integer(receipt, "schema") == 1
                        && originalsProfile(profile, storage).equals(Json.str(receipt, "profile")),
                "INPUT_RECEIPT_INVALID",
                "Input receipt belongs to another profile",
                3);

        return Json.obj(receipt, "pins");
    }

    static Checked check(ProfileRegistry.Profile profile, Storage storage) throws Exception {
        Map<String, Object> actualPins = new LinkedHashMap<>();
        List<Object> checks = new ArrayList<>();
        Map<String, Object> overrides = receiptPins(profile, storage);
        boolean ok = true;

        for (var entry : definitions(profile).entrySet()) {
            Map<String, Object> definition = Json.object(entry.getValue());
            Path source =
                    Storage.confined(originals(profile, storage), Json.str(definition, "file"));
            Object expected =
                    overrides.containsKey(entry.getKey())
                            ? overrides.get(entry.getKey())
                            : definition.get("sha256");
            boolean valid = false;

            if (Files.exists(source)) {
                Object actual = hashes(source, definition);
                actualPins.put(entry.getKey(), actual);
                valid = actual.equals(expected);
            }

            ok &= valid;
            checks.add(
                    Map.of(
                            "id",
                            entry.getKey(),
                            "status",
                            valid ? "pass" : "fail",
                            "source",
                            Files.exists(source) ? "local" : "missing"));
        }

        return new Checked(ok, actualPins, checks);
    }

    static Map<String, Object> fetch(
            ProfileRegistry.Profile profile,
            Storage storage,
            Arguments args,
            Toolchains tools,
            java.util.function.Consumer<String> log)
            throws Exception {
        Checked previous = check(profile, storage);

        if (previous.ok() && !args.flag("--force")) {
            return Map.of("changed", false, "verified", previous.pins().keySet());
        }

        String selected = args.value("--input");
        Path imported = selected == null ? null : Path.of(selected).toAbsolutePath().normalize();
        Map<String, Object> definitions = definitions(profile);
        requireAcquisitionSources(definitions, previous, args, tools, imported);
        Map<String, Object> overrides = receiptPins(profile, storage);
        Path parent = storage.data().resolve("profiles/" + profile.id());
        Storage.directory(parent);
        Path stage = parent.resolve(".fetch-" + UUID.randomUUID());
        Storage.directory(stage);
        Path candidate = stage.resolve("originals");
        Storage.directory(candidate);
        Map<String, Object> pins = new LinkedHashMap<>();
        List<String> fetched = new ArrayList<>();
        String serial = imported == null ? selectDevice(tools, args.value("--serial")) : null;
        var acquisition = new Acquisition(args, imported, tools, serial, log, fetched);
        boolean cleanStage = true;

        try {
            for (var entry : definitions.entrySet()) {
                String name = entry.getKey();
                Map<String, Object> definition = Json.object(entry.getValue());
                String relative = Json.str(definition, "file");
                Path destination = Storage.confined(candidate, relative);
                Storage.directory(destination.getParent());
                Path existing = Storage.confined(originals(profile, storage), relative);
                pins.put(
                        name,
                        stageOriginal(
                                acquisition,
                                name,
                                definition,
                                relative,
                                existing,
                                destination,
                                overrides));
            }

            String inputRevision =
                    NativeCore.hash(
                            Json.write(pins).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Path receiptCandidate = stage.resolve("receipt.json");
            writeReceipt(receiptCandidate, profile, inputRevision, pins, imported);
            Path root = storage.originals(profile.id());
            Path receiptTarget = parent.resolve("receipt.json");
            Path backup = stage.resolve("previous-originals");
            Path receiptBackup = stage.resolve("previous-receipt.json");
            boolean oldRoot = Files.exists(root), oldReceipt = Files.exists(receiptTarget);
            boolean rootBackedUp = false, receiptBackedUp = false, published = false;

            try {
                if (oldRoot) {
                    Files.move(root, backup, StandardCopyOption.ATOMIC_MOVE);
                    rootBackedUp = true;
                }

                if (oldReceipt) {
                    Files.move(receiptTarget, receiptBackup, StandardCopyOption.ATOMIC_MOVE);
                    receiptBackedUp = true;
                }

                Files.move(candidate, root, StandardCopyOption.ATOMIC_MOVE);
                published = true;
                Files.move(receiptCandidate, receiptTarget, StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception failure) {
                // checkstyle-allow IllegalCatch: rollback, then rethrow unchanged
                try {
                    rollbackPublish(
                            stage, root, receiptTarget, published, rootBackedUp, receiptBackedUp);
                } catch (Exception rollbackFailure) {
                    // checkstyle-allow IllegalCatch: rollback failure is attached to the original
                    cleanStage = false;
                    failure.addSuppressed(rollbackFailure);
                }

                throw failure;
            }

            return Map.of(
                    "changed",
                    true,
                    "downloaded",
                    fetched,
                    "revision",
                    inputRevision,
                    "verified",
                    pins.keySet());
        } finally {
            if (cleanStage) {
                FilesSupport.removeOwnedTree(stage);
            }
        }
    }

    private static void requireAcquisitionSources(
            Map<String, Object> definitions,
            Checked previous,
            Arguments args,
            Toolchains tools,
            Path imported) {
        if (imported == null) {
            for (var entry : definitions.entrySet()) {
                Map<String, Object> definition = Json.object(entry.getValue());

                if (!previous.pins().containsKey(entry.getKey()) || args.flag("--force")) {
                    Failure.require(
                            definition.containsKey("source"),
                            "ORIGINAL_SOURCE_MISSING",
                            "No device acquisition recipe for "
                                    + entry.getKey()
                                    + "; import an owner input directory with fetch --input",
                            2);
                }
            }

            Failure.require(
                    tools != null && Files.isRegularFile(tools.adb()),
                    "TOOL_MISSING",
                    "Run voyemu deps to prepare ADB",
                    3);
        } else {
            Failure.require(
                    Files.isDirectory(imported) && !Files.isSymbolicLink(imported),
                    "INPUT_DIRECTORY_INVALID",
                    "--input must name an ordinary owner input directory",
                    2);
        }
    }

    private static Object stageOriginal(
            Acquisition acquisition,
            String name,
            Map<String, Object> definition,
            String relative,
            Path existing,
            Path destination,
            Map<String, Object> overrides)
            throws Exception {
        Object expected =
                overrides.containsKey(name) ? overrides.get(name) : definition.get("sha256");
        boolean reuse =
                !acquisition.args().flag("--force")
                        && Files.exists(existing)
                        && hashes(existing, definition).equals(expected);

        if (reuse) {
            copy(existing, destination, definition);
        } else if (acquisition.imported() != null) {
            acquisition.log().accept("Importing owner input " + name);
            Path source = Storage.confined(acquisition.imported(), relative);
            Failure.require(
                    Files.exists(source), "ORIGINAL_MISSING", "Owner input is missing: " + name, 3);
            copy(source, destination, definition);
            acquisition.fetched().add(name);
        } else {
            acquisition.log().accept("Fetching declared owner input " + name);
            pull(acquisition.tools(), acquisition.serial(), definition, destination);
            acquisition.fetched().add(name);
        }

        Object actual = hashes(destination, definition);
        Failure.require(
                acquisition.args().flag("--force") || actual.equals(expected),
                "ORIGINAL_HASH_MISMATCH",
                "Owner input differs from the selected profile: "
                        + name
                        + "; --force is required to record a new local input revision",
                3);

        return actual;
    }

    private static void writeReceipt(
            Path receiptCandidate,
            ProfileRegistry.Profile profile,
            String inputRevision,
            Map<String, Object> pins,
            Path imported)
            throws Exception {
        Map<String, Object> receipt = new LinkedHashMap<>();

        receipt.put("schema", 1);
        receipt.put("profile", profile.id());
        receipt.put("recipeRevision", profile.revision());
        receipt.put("revision", inputRevision);
        receipt.put("pins", pins);
        receipt.put("acquired", Instant.now().toString());
        receipt.put("source", imported == null ? "selected-device" : "owner-directory");
        Files.writeString(receiptCandidate, Json.write(receipt) + "\n");
    }

    /** Restores the previous originals and receipt from the fetch stage after a failed swap. */
    private static void rollbackPublish(
            Path stage,
            Path root,
            Path receiptTarget,
            boolean published,
            boolean rootBackedUp,
            boolean receiptBackedUp)
            throws Exception {
        Path candidate = stage.resolve("originals");
        Path backup = stage.resolve("previous-originals");
        Path receiptBackup = stage.resolve("previous-receipt.json");

        if (published) {
            Files.move(root, candidate, StandardCopyOption.ATOMIC_MOVE);
        }

        if (rootBackedUp) {
            Files.move(backup, root, StandardCopyOption.ATOMIC_MOVE);
        }

        if (receiptBackedUp) {
            Files.move(receiptBackup, receiptTarget, StandardCopyOption.ATOMIC_MOVE);
        }
    }

    private static Object hashes(Path source, Map<String, Object> definition) throws Exception {
        if (!Json.str(definition, "type", "file").equals("tree")) {
            return FilesSupport.hash(source);
        }

        Map<String, Object> result = new LinkedHashMap<>();

        for (var entry : FilesSupport.tree(source).entrySet()) {
            result.put(entry.getKey(), FilesSupport.hash(entry.getValue()));
        }

        return result;
    }

    private static void copy(Path source, Path target, Map<String, Object> definition)
            throws Exception {
        if (Json.str(definition, "type", "file").equals("tree")) {
            FilesSupport.copyTree(source, target);
        } else {
            Failure.require(
                    Files.isRegularFile(source) && !Files.isSymbolicLink(source),
                    "ORIGINAL_INVALID",
                    "Owner input must be an ordinary file",
                    3);
            Files.copy(source, target);
        }
    }

    private static String selectDevice(Toolchains tools, String explicit) throws Exception {
        if (explicit != null) {
            Failure.require(
                    explicit.matches("[A-Za-z0-9][A-Za-z0-9_.:-]*"),
                    "ARGUMENT_INVALID",
                    "Invalid ADB serial",
                    2);

            return explicit;
        }

        Processes.Result result =
                Processes.run(tools.adb(), List.of("devices"), null, Duration.ofSeconds(15), false);
        List<String> devices = new ArrayList<>();

        for (String line : result.stdout().lines().toList()) {
            String[] fields = line.trim().split("\\s+", -1);

            if (fields.length == 2
                    && fields[1].equals("device")
                    && !fields[0].startsWith("emulator-")) {
                devices.add(fields[0]);
            }
        }

        Failure.require(
                devices.size() == 1,
                "DEVICE_SELECTION_REQUIRED",
                "Select exactly one owner device with fetch --serial",
                3);

        return devices.get(0);
    }

    private static void pull(
            Toolchains tools, String serial, Map<String, Object> definition, Path destination)
            throws Exception {
        Map<String, Object> source = Json.obj(definition, "source");
        String remote;

        if (source.containsKey("package")) {
            String name = Json.str(source, "package");
            Failure.require(
                    name.matches("[A-Za-z0-9_.]+"),
                    "ORIGINAL_SOURCE_INVALID",
                    "Invalid package source",
                    2);
            String output = device(tools, serial, List.of("shell", "pm", "path", name)).stdout();
            List<String> paths =
                    output.lines()
                            .filter(line -> line.startsWith("package:"))
                            .map(line -> line.substring(8))
                            .toList();
            Failure.require(
                    paths.size() == 1,
                    "ORIGINAL_PACKAGE_INVALID",
                    "Expected one nonsplit APK for " + name,
                    3);
            remote = paths.get(0);
        } else {
            remote = Json.str(source, "path");
        }

        Failure.require(
                remote.matches("/[A-Za-z0-9_./-]+") && !remote.contains(".."),
                "ORIGINAL_SOURCE_INVALID",
                "Invalid device path",
                2);

        if (Json.str(definition, "type", "file").equals("tree")) {
            Storage.directory(destination);

            for (String relative : Json.object(definition.get("sha256")).keySet()) {
                Path target = Storage.confined(destination, relative);
                Storage.directory(target.getParent());
                device(tools, serial, List.of("pull", remote + "/" + relative, target.toString()));
            }
        } else {
            device(tools, serial, List.of("pull", remote, destination.toString()));
        }
    }

    private static Processes.Result device(Toolchains tools, String serial, List<String> args)
            throws Exception {
        List<String> command = new ArrayList<>(List.of("-s", serial));

        command.addAll(args);

        return Processes.run(tools.adb(), command, null, Duration.ofMinutes(5), false);
    }
}
