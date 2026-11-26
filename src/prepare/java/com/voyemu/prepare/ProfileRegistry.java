package com.voyemu.prepare;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Immutable compiled-in definitions; mutable owner receipts live in Storage. */
final class ProfileRegistry {
    record Profile(
            String id,
            String revision,
            Map<String, Object> data,
            String resourcePrefix,
            Path sourceRoot) {
        private static final Set<String> PLATFORMS = Set.of("qinggan09", "qinggan11", "passion");
        private static final Set<String> BOARDS = Set.of("8155", "nxp");

        /** A definition that declares platform or board declares both valid; a title is valid. */
        Profile {
            if (data.containsKey("platform") || data.containsKey("board")) {
                declared(data, "platform", PLATFORMS);
                declared(data, "board", BOARDS);
            }

            if (data.containsKey("title")) {
                title(data);
            }
        }

        Profile(String id, String revision, Map<String, Object> data, String resourcePrefix) {
            this(id, revision, data, resourcePrefix, null);
        }

        /** qinggan09, qinggan11 or passion; behavior follows it, not the id. */
        String platform() {
            return declared(data, "platform", PLATFORMS);
        }

        /** 8155 for the Qualcomm SA8155 board or nxp for the NXP i.MX 8QuadMax board. */
        String board() {
            return declared(data, "board", BOARDS);
        }

        /** Whether the profile declares the original_navi feature: the stock navigation app. */
        boolean originalNavi() {
            return data.get("features") instanceof Map<?, ?> features
                    && Boolean.TRUE.equals(features.get("original_navi"));
        }

        /** The name of the profile in human text, such as "Free 7.3.1". */
        String title() {
            return title(data);
        }

        // The compact constructor validates its parameter before the fields are assigned.
        private static String title(Map<String, Object> data) {
            Failure.require(
                    data.get("title") instanceof String text && !text.isEmpty(),
                    "PROFILE_INVALID",
                    "Profile title must be a nonempty string",
                    2);

            return (String) data.get("title");
        }

        private static String declared(Map<String, Object> data, String field, Set<String> values) {
            Failure.require(
                    data.get(field) instanceof String value && values.contains(value),
                    "PROFILE_INVALID",
                    "Profile " + field + " must be one of " + new java.util.TreeSet<>(values),
                    2);

            return (String) data.get(field);
        }

        String referenceProfile() {
            Failure.require(
                    !data.containsKey("id") || id.equals(data.get("id")),
                    "PROFILE_INVALID",
                    "Logical profile identity differs",
                    2);

            if (!(data.get("capture") instanceof Map<?, ?>)) {
                return id;
            }

            var capture = Json.obj(data, "capture");

            if (!capture.containsKey("referenceProfile")) {
                return id;
            }

            Failure.require(
                    id.equals(capture.get("profile"))
                            && capture.get("referenceProfile") instanceof String,
                    "PROFILE_INVALID",
                    "Reference profile must belong to the selected logical profile",
                    2);
            String reference = Json.str(capture, "referenceProfile");
            validId(reference);

            return reference;
        }
    }

    private final Map<String, Profile> profiles = new LinkedHashMap<>();
    private final Map<String, Map<String, String>> sourcePins = new LinkedHashMap<>();
    private final Path projectRoot;

    /** Explicit current source profiles; no Node-generated embedded resource index required. */
    ProfileRegistry(Path root) throws Exception {
        this(root, null);
    }

    /**
     * Host source preparation only: exposes one explicitly selected incomplete definition, never
     * changes status.
     */
    ProfileRegistry(Path root, String preparationProfile) throws Exception {
        this(root, preparationProfile, null);
    }

    ProfileRegistry(Path root, String preparationProfile, String target) throws Exception {
        if (preparationProfile != null) {
            validId(preparationProfile);
        }

        Failure.require(
                root.isAbsolute() && root.toRealPath().equals(root.normalize()),
                "PROFILE_ROOT_INVALID",
                "Canonical project root required",
                2);
        Storage.confined(root, ".");
        projectRoot = root;
        Path folder = Storage.confined(root, "profiles");

        try (var entries = Files.list(folder)) {
            for (Path directory : entries.sorted().toList()) {
                if (preparationProfile != null
                        && !directory.getFileName().toString().equals(preparationProfile)) {
                    continue;
                }

                Failure.require(
                        Files.isDirectory(directory) && !Files.isSymbolicLink(directory),
                        "PROFILE_INVALID",
                        "Ordinary profile directory required",
                        2);
                String id = directory.getFileName().toString();
                validId(id);
                Path definition = directory.resolve("profile.json");

                if (!Files.exists(definition)) {
                    continue;
                } // Draft profiles have no executable definition.

                Map<String, Object> source = readDefinition(definition);
                Map<String, Object> data =
                        target == null ? source : resolveTarget(root, id, source, target);
                String status = (String) data.getOrDefault("status", "ready");

                if (!"ready".equals(status)
                        && !(id.equals(preparationProfile) && "incomplete".equals(status))) {
                    continue;
                }

                Failure.require(
                        Json.integer(data, "schema") == 1,
                        "PROFILE_INVALID",
                        "Unsupported source profile schema",
                        2);
                Map<String, String> pins = inventory(root, id, data);
                String revision =
                        NativeCore.hash(Json.write(pins).getBytes(StandardCharsets.UTF_8));
                profiles.put(
                        id, new Profile(id, revision, data, "voyemu/profiles/" + id + "/", root));
                sourcePins.put(id, Map.copyOf(pins));
            }
        }

        Failure.require(
                !profiles.isEmpty(), "PROFILE_MISSING", "No executable source profiles found", 2);
    }

    private static Map<String, Object> readDefinition(Path file) throws Exception {
        Failure.require(
                Files.isRegularFile(file)
                        && !Files.isSymbolicLink(file)
                        && Files.size(file) <= 1024 * 1024,
                "PROFILE_RESOURCE_LIMIT",
                "Bounded regular source definition required",
                2);

        return Json.object(Json.parse(Files.readString(file)));
    }

    private static Path androidBase(Path root, Map<String, Object> selection) throws Exception {
        String name = Json.str(selection, "androidBase");

        validId(name);

        return Storage.confined(root, "profiles/common/android-bases/" + name + ".json");
    }

    private static boolean variantEmulator(Map<String, Object> emulator) {
        var allowed = Set.of("acceleration", "gpuMode", "memory", "audioOutput");

        return allowed.containsAll(emulator.keySet())
                && "kvm".equals(emulator.get("acceleration"))
                && "host".equals(emulator.get("gpuMode"))
                && emulator.getOrDefault("audioOutput", false) instanceof Boolean
                && (!emulator.containsKey("memory")
                        || (emulator.get("memory") instanceof Long
                                && Json.integer(emulator, "memory") >= 512
                                && Json.integer(emulator, "memory") <= 16384));
    }

    private static Map<String, Object> resolveTarget(
            Path root, String id, Map<String, Object> source, String name) throws Exception {
        var catalogue = Json.obj(source, "targets");
        var android = Json.obj(source, "android");
        boolean x86 = "x86".equals(name);
        String abi = x86 ? "x86_64" : "arm64-v8a";
        String preparation = x86 ? "signed-offline" : "sdk";

        Failure.require(
                id.equals(source.get("id"))
                        && !source.containsKey("target")
                        && catalogue.keySet().equals(Set.of("arm", "x86"))
                        && catalogue.containsKey(name)
                        && "system-images;android-30;default;arm64-v8a"
                                .equals(android.get("package")),
                "PROFILE_TARGET",
                "Invalid Android target catalogue",
                2);
        var entry = Json.obj(catalogue, name);
        Failure.require(
                entry.keySet()
                                .equals(
                                        x86
                                                ? Set.of(
                                                        "guestAbi",
                                                        "preparation",
                                                        "androidBase",
                                                        "emulator")
                                                : Set.of("guestAbi", "preparation"))
                        && abi.equals(entry.get("guestAbi"))
                        && preparation.equals(entry.get("preparation")),
                "PROFILE_TARGET",
                "Target ABI or preparation differs",
                2);
        var resolved = new LinkedHashMap<>(source);
        var target =
                new LinkedHashMap<String, Object>(
                        Map.of("name", name, "guestAbi", abi, "preparation", preparation));

        if (x86) {
            var base = readDefinition(androidBase(root, entry));
            var emulator = Json.obj(entry, "emulator");
            Failure.require(
                    variantEmulator(emulator)
                            && "system-images;android-30;default;x86_64".equals(base.get("package"))
                            && base.containsKey("clean_base")
                            && !base.containsKey("development_kernel"),
                    "PROFILE_TARGET",
                    "X86 target requires a pinned API30 SDK base and KVM settings",
                    2);
            var features = Json.object(android.getOrDefault("features", Map.of()));

            if (!features.isEmpty()) {
                var combined =
                        new LinkedHashMap<>(Json.object(base.getOrDefault("features", Map.of())));
                combined.putAll(features);
                base.put("features", combined);
            }

            resolved.put("android", base);
            var settings = new LinkedHashMap<>(Json.obj(source, "emulator"));
            settings.putAll(emulator);
            resolved.put("emulator", settings);
            target.put("androidBase", Json.str(entry, "androidBase"));
        }

        resolved.remove("targets");
        resolved.put("target", target);

        return resolved;
    }

    private static Map<String, String> inventory(Path root, String id, Map<String, Object> data)
            throws Exception {
        Map<String, String> pins = new java.util.TreeMap<>();
        long total = 0;

        for (var entry : FilesSupport.tree(Storage.confined(root, "profiles/" + id)).entrySet()) {
            long size = Files.size(entry.getValue());
            total += size;
            Failure.require(
                    size <= 32L * 1024 * 1024 && total <= 128L * 1024 * 1024,
                    "PROFILE_RESOURCE_LIMIT",
                    "Source profile exceeds bounds",
                    2);
            pins.put(entry.getKey(), FilesSupport.hash(entry.getValue()));
        }

        var selection = Json.object(data.getOrDefault("target", Map.of()));

        if (selection.containsKey("androidBase")) {
            Path file = androidBase(root, selection);
            pins.put("common/android-bases/" + file.getFileName(), FilesSupport.hash(file));
        }

        return pins;
    }

    void verifySource(Profile profile) throws Exception {
        if (projectRoot == null) {
            return;
        }

        Map<String, String> actual = inventory(projectRoot, profile.id(), profile.data());

        Failure.require(
                actual.equals(sourcePins.get(profile.id())),
                "PROFILE_RESOURCE_MODIFIED",
                "Source profile changed during preparation",
                3);
    }

    ProfileRegistry() throws Exception {
        projectRoot = null;
        Map<String, Object> index = Json.object(Json.parse(text("voyemu/profile-index.json")));
        Failure.require(
                Json.integer(index, "schema") == 1,
                "PROFILE_INVALID",
                "Unsupported embedded catalog schema",
                2);

        for (Object item : Json.list(index.get("profiles"))) {
            Map<String, Object> entry = Json.object(item);
            String id = Json.str(entry, "id");
            validId(id);
            String prefix = "voyemu/profiles/" + id + "/";
            Map<String, Object> data = Json.object(Json.parse(text(prefix + "profile.json")));
            Failure.require(
                    Json.integer(data, "schema") == 1,
                    "PROFILE_INVALID",
                    "Unsupported profile schema",
                    2);
            Failure.require(
                    !profiles.containsKey(id), "PROFILE_INVALID", "Duplicate embedded profile", 2);
            profiles.put(id, new Profile(id, Json.str(entry, "revision"), data, prefix));
        }
    }

    static void validId(String id) {
        Failure.require(
                id.matches("[a-z0-9][a-z0-9._-]{0,127}") && !id.equals(".") && !id.equals(".."),
                "PROFILE_INVALID",
                "Invalid profile ID",
                2);
    }

    List<Profile> list() {
        return List.copyOf(profiles.values());
    }

    Profile get(String id) {
        Profile profile = profiles.get(id);

        Failure.require(
                profile != null, "PROFILE_MISSING", "Profile is not in this release: " + id, 2);

        return profile;
    }

    Path sourceDirectory(Profile profile) throws Exception {
        Failure.require(
                projectRoot != null && projectRoot.equals(profile.sourceRoot()),
                "PROFILE_ROOT_INVALID",
                "Preparation requires an explicit source profile",
                2);
        verifySource(profile);

        return Storage.confined(projectRoot, "profiles/" + profile.id());
    }

    static Map<String, Object> patchMetadata(Profile profile) throws Exception {
        var imageApi =
                java.util.regex.Pattern.compile("(?:^|;)android-(28|30)(?:;|$)")
                        .matcher(Json.str(Json.obj(profile.data(), "android"), "package"));

        Failure.require(imageApi.find(), "PATCH_SOURCE", "Supported exact Android API required", 3);
        int api = Integer.parseInt(imageApi.group(1));

        Map<String, Object> result = new java.util.TreeMap<>();

        for (Object node : Json.obj(profile.data(), "patches").values()) {
            for (Object item : Json.list(Json.object(node).get("steps"))) {
                String step = (String) item;
                Failure.require(step.endsWith(".json"), "PATCH_SOURCE", "JSON recipe required", 3);
                byte[] source = bytes(profile, profile.resourcePrefix() + "patches/" + step);
                Map<String, Object> data =
                        Json.object(Json.parse(new String(source, StandardCharsets.UTF_8)));
                Failure.require(
                        Json.integer(data, "schema") == 1
                                && Json.integer(data, "api") == api
                                && !data.containsKey("sourceSha256"),
                        "PATCH_SOURCE",
                        "Canonical JSON recipe required",
                        3);
                data.put("sourceSha256", NativeCore.hash(source));
                result.put(step, data);
            }
        }

        return result;
    }

    static byte[] bytes(Profile profile, String name) throws Exception {
        Path root = profile.sourceRoot();

        // Other project resources, such as the AudioPolicy helper sources, are embedded in the
        // helper JAR, so preparation never reads src/.
        if (root != null
                && (name.startsWith("voyemu/profiles/") || name.equals("voyemu/LICENSE"))) {
            String relative = name.substring("voyemu/".length());

            Path file = Storage.confined(root, relative);
            Failure.require(
                    Files.isRegularFile(file) && Files.size(file) <= 32L * 1024 * 1024,
                    "RESOURCE_MISSING",
                    "Missing bounded explicit project resource: " + relative,
                    3);

            return Files.readAllBytes(file);
        }

        return bytes(name);
    }

    static byte[] bytes(String name) throws Exception {
        try (InputStream stream =
                ProfileRegistry.class.getClassLoader().getResourceAsStream(name)) {
            Failure.require(
                    stream != null, "RESOURCE_MISSING", "Missing embedded resource: " + name, 3);

            return stream.readAllBytes();
        }
    }

    static String text(String name) throws Exception {
        return new String(bytes(name), StandardCharsets.UTF_8);
    }
}
