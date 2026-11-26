package com.voyemu.prepare;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Profile DAG adapter. Android files come only from the owned clean-base guest. */
final class Artifacts {
    interface AndroidFiles {
        Path read(String path) throws Exception;
    }

    private final ProfileRegistry.Profile profile;
    private final Storage storage;
    private final Toolchains tools;
    private final Path recipe, work;
    private final AndroidFiles android;
    private final java.util.function.Consumer<String> log;
    private final Map<String, Path> produced = new LinkedHashMap<>();
    private final Set<String> visiting = new java.util.HashSet<>();
    private final Map<String, Object> patches;
    private Path frameworkClasspath;
    final int api;
    final String abi;

    Artifacts(
            ProfileRegistry.Profile profile,
            Storage storage,
            Toolchains tools,
            Path recipe,
            Path work,
            AndroidFiles android,
            java.util.function.Consumer<String> log)
            throws Exception {
        this(
                new PatchedProfile(profile, ProfileRegistry.patchMetadata(profile)),
                storage,
                tools,
                recipe,
                work,
                android,
                log);
    }

    /** A profile with the recipe metadata of its patch steps. */
    record PatchedProfile(ProfileRegistry.Profile profile, Map<String, Object> patchData) {}

    Artifacts(
            PatchedProfile patched,
            Storage storage,
            Toolchains tools,
            Path recipe,
            Path work,
            AndroidFiles android,
            java.util.function.Consumer<String> log)
            throws Exception {
        ProfileRegistry.Profile profile = patched.profile();
        Map<String, Object> patchData = patched.patchData();

        this.profile = profile;
        this.storage = storage;
        this.tools = tools;
        this.recipe = recipe;
        this.work = work;
        this.android = android;
        this.log = log;
        String image = Json.str(Json.obj(profile.data(), "android"), "package");
        var version = java.util.regex.Pattern.compile("android-([0-9]+)").matcher(image);
        Failure.require(version.find(), "PROFILE_INVALID", "Android API is missing", 2);
        api = Integer.parseInt(version.group(1));
        abi = image.substring(image.lastIndexOf(';') + 1);
        patches = Map.copyOf(patchData);
        Storage.directory(work);
    }

    void useNativeFile(String reference, Path file) throws Exception {
        if (Api28CodecNativeFile.accepts(profile, api, reference, file)) {
            Failure.require(
                    produced.putIfAbsent(reference, file) == null,
                    "PREPARATION_NATIVE_FILE",
                    "Duplicate codec native output",
                    3);

            return;
        }

        var spec =
                Api30NativeFiles.forProfile(profile).stream()
                        .filter(value -> reference.equals("patched:" + value.id()))
                        .findFirst();
        Failure.require(
                api == 30
                        && spec.isPresent()
                        && Files.isRegularFile(file)
                        && !Files.isSymbolicLink(file)
                        && FilesSupport.hash(file).equals(spec.get().outputPin())
                        && produced.putIfAbsent(reference, file) == null,
                "PREPARATION_NATIVE_FILE",
                "Exact native API30 output required",
                3);
    }

    void useNativeComponent(String reference, Path file) throws Exception {
        Failure.require(
                reference.startsWith("component:")
                        && Files.isRegularFile(file)
                        && !Files.isSymbolicLink(file),
                "PREPARATION_NATIVE_COMPONENT",
                "Declared native component required",
                3);
        String id = reference.substring("component:".length());
        Object selected = Json.obj(profile.data(), "components").get(id);
        Failure.require(
                selected instanceof String,
                "PREPARATION_NATIVE_COMPONENT",
                "Unknown native component",
                3);
        Path source = Storage.confined(recipe, (String) selected);
        Map<String, Object> definition =
                Json.object(Json.parse(Files.readString(source.resolve("component.json"))));
        long recipeApi = Json.integer(definition, "minSdk");
        Failure.require(
                "native".equals(definition.get("type"))
                        && (recipeApi == 28 || recipeApi == 30)
                        && ("executable".equals(definition.get("outputType"))
                                ? api == recipeApi
                                : api >= recipeApi)
                        && file.getFileName().toString().equals(Json.str(definition, "output"))
                        && produced.putIfAbsent(reference, file) == null,
                "PREPARATION_NATIVE_COMPONENT",
                "Native component override differs from component",
                3);
    }

    Map<String, Path> build() throws Exception {
        Failure.require(
                Inputs.check(profile, storage).ok(),
                "ORIGINAL_HASH_MISMATCH",
                "Verify owner originals before building",
                3);

        for (Object item : Json.list(profile.data().get("install"))) {
            if (!"directory".equals(Json.object(item).get("type"))) {
                resolve(Json.str(Json.object(item), "artifact"));
            }
        }

        return Map.copyOf(produced);
    }

    Path resolve(String ref) throws Exception {
        if (produced.containsKey(ref)) {
            return produced.get(ref);
        }

        Failure.require(
                visiting.add(ref), "ARTIFACT_CYCLE", "Artifact dependency cycle: " + ref, 2);

        try {
            int split = ref.indexOf(':');
            Failure.require(split > 0, "ARTIFACT_INVALID", "Invalid artifact reference", 2);
            String kind = ref.substring(0, split), name = ref.substring(split + 1);
            Path output;

            switch (kind) {
                case "original" -> {
                    Map<String, Object> definition =
                            Json.object(Json.obj(profile.data(), "original").get(name));
                    output =
                            Storage.confined(
                                    Inputs.originals(profile, storage),
                                    Json.str(definition, "file"));
                }
                case "android" -> {
                    Failure.require(
                            name.startsWith("/") && !name.contains(".."),
                            "ARTIFACT_INVALID",
                            "Invalid Android file",
                            2);
                    output = android.read(name);
                }
                case "files" -> {
                    Map<String, Object> definition =
                            Json.object(Json.obj(profile.data(), "files").get(name));
                    output =
                            Storage.confined(recipe.resolve("files"), Json.str(definition, "file"));

                    if (definition.containsKey("simulation")) {
                        var simulation = Json.obj(definition, "simulation");
                        Failure.require(
                                api == 28
                                        && name.equals("hybrid-nvram")
                                        && "qinggan09-equipment-item51-v1"
                                                .equals(simulation.get("kind"))
                                        && Json.str(definition, "file")
                                                .equals(
                                                        Json.str(
                                                                Json.obj(
                                                                        Json.obj(
                                                                                profile.data(),
                                                                                "files"),
                                                                        "nvram"),
                                                                "file")),
                                "EQUIPMENT_SIMULATION_INVALID",
                                "A9 equipment must use the same seed as JNI NVRAM",
                                2);
                        byte[] image =
                                Qinggan09EquipmentNvram.create(
                                        Files.readString(output),
                                        Json.str(simulation, "powertrain"));
                        output = work.resolve("qinggan09-equipment-nvram.img");
                        Files.write(output, image);
                    }
                }
                case "component" -> output = component(name);
                case "patched" -> output = patched(name);
                default ->
                        throw new Failure("ARTIFACT_INVALID", "Unknown artifact kind: " + kind, 2);
            }

            Failure.require(
                    Files.exists(output) && !Files.isSymbolicLink(output),
                    "ARTIFACT_OUTPUT_MISSING",
                    "Artifact was not produced: " + ref,
                    5);
            produced.put(ref, output);

            return output;
        } finally {
            visiting.remove(ref);
        }
    }

    // The component source with its shared, external and edited files, as every build compiles it.
    private record Materialized(Map<String, Object> definition, Path source, Path dir) {}

    private Path componentSource(String name) throws Exception {
        Object selected = Json.obj(profile.data(), "components").get(name);

        Failure.require(
                selected instanceof String, "ARTIFACT_MISSING", "Unknown component: " + name, 2);

        return Storage.confined(recipe, (String) selected);
    }

    private Materialized materialize(String name) throws Exception {
        Path original = componentSource(name);
        Path dir = work.resolve("component-" + name);

        Storage.directory(dir);
        Path source = dir.resolve("source");
        FilesSupport.copyTree(original, source);
        Map<String, Object> definition =
                Json.object(Json.parse(Files.readString(source.resolve("component.json"))));

        if (definition.containsKey("sourceFiles")) {
            ComponentSources.copy(
                    Json.obj(definition, "sourceFiles"),
                    source,
                    resource -> ProfileRegistry.bytes(profile, resource));
        }

        if (definition.containsKey("externalSources")) {
            copyExternalSources(definition, source);
        }

        ComponentSources.editDeclared(definition, source);

        if (definition.containsKey("upstreamEdits")) {
            SourceEdits.upstream(
                    source, Storage.confined(source, Json.str(definition, "upstreamEdits")));
        }

        return new Materialized(definition, source, dir);
    }

    /**
     * The units of the android-java recipe for this profile: the own sources of its components,
     * every src or *-src directory of its patch steps and the AudioPolicy and Phone provider
     * helpers, each compiled for its minimum API.
     */
    List<GuestJava.Unit> guestJavaUnits() throws Exception {
        List<GuestJava.Unit> units = new ArrayList<>();

        for (String name : new TreeSet<>(Json.obj(profile.data(), "components").keySet())) {
            Path config = Storage.confined(componentSource(name), "component.json");
            Map<String, Object> definition = Json.object(Json.parse(Files.readString(config)));
            String type = Json.str(definition, "type");

            if (!type.equals("jar")
                    && !type.equals("apk")
                    && !definition.containsKey("api30ViewObservation")) {
                continue;
            }

            Materialized materialized = materialize(name);
            Path source = materialized.source(), own = source.resolve("src");
            int minimum =
                    definition.containsKey("minSdk")
                            ? Math.toIntExact(Json.integer(definition, "minSdk"))
                            : api;

            boolean compiled =
                    !definition.containsKey("frameworkBase")
                            && !definition.containsKey("frameworkOriginal")
                            && Files.isDirectory(own)
                            && !FilesSupport.tree(own).isEmpty();

            if (definition.containsKey("api30ViewObservation")) {
                units.add(
                        new GuestJava.Unit(
                                Api30ViewObservation.source(profile, definition), minimum));
            } else if (compiled && type.equals("jar")) {
                units.add(
                        new GuestJava.Unit(
                                own,
                                definition.containsKey("compileOnly")
                                        ? "stub-cls"
                                        : GuestJava.COMPILE_ONLY,
                                null,
                                minimum));
            } else if (compiled) {
                linkComponentResources(
                        tools.buildTool("aapt2"),
                        tools.platform(),
                        source,
                        materialized.dir(),
                        minimum,
                        Math.toIntExact(Json.integer(definition, "targetSdk")));
                units.add(
                        new GuestJava.Unit(
                                own,
                                GuestJava.COMPILE_ONLY,
                                materialized.dir().resolve("generated"),
                                minimum));
            }
        }

        Path patchRoot = recipe.resolve("patches");

        if (Files.isDirectory(patchRoot)) {
            try (var walk = Files.walk(patchRoot)) {
                for (Path dir :
                        walk.filter(Files::isDirectory)
                                .filter(p ->
                                        p.getFileName().toString().equals("src")
                                                || p.getFileName().toString().endsWith("-src"))
                                .sorted()
                                .toList()) {
                    if (units.stream().noneMatch(u -> dir.startsWith(u.root()))) {
                        units.add(new GuestJava.Unit(dir, api));
                    }
                }
            }
        }

        for (GuestJava.Unit helper : helperUnits()) {
            if (!units.contains(helper)) {
                units.add(helper);
            }
        }

        return units;
    }

    // The AudioPolicy and Phone provider helpers of the guard steps of this profile.
    private List<GuestJava.Unit> helperUnits() throws Exception {
        List<GuestJava.Unit> helpers = new ArrayList<>();

        if (patches.containsKey("api30-audio-policy.json")) {
            helpers.add(new GuestJava.Unit(AudioPolicyGuard.helperSource(), api));
        }

        if (patches.containsKey(PhoneProviderGuard.NAME + ".json")) {
            var constants =
                    Json.obj(
                            Json.object(patches.get(PhoneProviderGuard.NAME + ".json")),
                            "constants");
            helpers.add(new GuestJava.Unit(PhoneProviderGuard.source(profile, constants), 30));
        }

        return helpers;
    }

    private Path component(String name) throws Exception {
        Materialized materialized = materialize(name);
        Map<String, Object> definition = materialized.definition();
        Path source = materialized.source(), dir = materialized.dir();

        if (definition.get("type").equals("native-library-archive")) {
            Failure.require(
                    name.endsWith("-arm64-libraries"),
                    "COMPONENT_TYPE_INVALID",
                    "Registered ARM64 library archive component required",
                    3);

            return GalleryArm64Libraries.build(api, abi, source, dir);
        }

        int minimum = Math.toIntExact(Json.integer(definition, "minSdk"));
        Failure.require(
                minimum <= api, "COMPONENT_API_MISMATCH", "Component requires a newer guest", 2);
        log.accept("Building component " + name);

        if (definition.containsKey("api30ViewObservation")) {
            return api30ViewObservationComponent(definition, dir, minimum);
        }

        if (definition.containsKey("frameworkBase")) {
            return frameworkBaseComponent(definition, dir);
        }

        if (definition.containsKey("frameworkOriginal")) {
            return frameworkOriginalComponent(definition, dir);
        }

        String type = Json.str(definition, "type");

        if (type.equals("native")) {
            return nativeComponent(definition);
        }

        if (type.equals("jar")) {
            return jarComponent(name, definition, source, dir, minimum);
        }

        Failure.require(type.equals("apk"), "COMPONENT_TYPE_INVALID", "Unknown component type", 2);

        return apkComponent(definition, source, dir, minimum);
    }

    private void copyExternalSources(Map<String, Object> definition, Path source) throws Exception {
        for (var entry : Json.obj(definition, "externalSources").entrySet()) {
            Map<String, Object> pin = Json.object(entry.getValue());
            String url = Json.str(pin, "url");
            Path data =
                    Downloads.cached(
                            pin,
                            storage.cache().resolve("sources"),
                            16 * 1024 * 1024,
                            url.contains("android.googlesource.com")
                                    && url.contains("format=TEXT"));
            Path target = Storage.confined(source, entry.getKey());
            Failure.require(
                    !Files.exists(target),
                    "SOURCE_TARGET_EXISTS",
                    "External source would overwrite own source",
                    3);
            Storage.directory(target.getParent());
            Files.copy(data, target);
        }
    }

    private Path api30ViewObservationComponent(
            Map<String, Object> definition, Path dir, int minimum) throws Exception {
        Failure.require(
                api == 30,
                "API30_VIEW_OBSERVATION_CONTRACT",
                "Exact registered Android30 observation component required",
                3);
        Path bridgeSource = Api30ViewObservation.source(profile, definition);
        Path dex =
                GuestJava.dex(
                        new GuestJava.Unit(bridgeSource, minimum),
                        tools.platform(),
                        dir.resolve("java"));
        Failure.require(
                Api30ViewObservation.source(profile, definition).equals(bridgeSource),
                "API30_VIEW_OBSERVATION_CONTRACT",
                "Pinned shared bridge source changed during compilation",
                3);
        Path helper = dir.resolve("bridge.jar");
        NativeCore.zip(helper, bytes(dex), false);

        return Api30ViewObservation.build(
                profile.referenceProfile(),
                api,
                android.read("/system/framework/framework.jar"),
                helper,
                dir.resolve(Json.str(definition, "output")));
    }

    private Path frameworkBaseComponent(Map<String, Object> definition, Path dir) throws Exception {
        Failure.require(
                api == 28, "FRAMEWORK_API_UNSUPPORTED", "Pinned Android28 base required", 3);
        Map<String, Object> base = Json.obj(definition, "frameworkBase");
        Path oat = android.read(Json.str(base, "oat"));
        Path vdex = android.read(Json.str(base, "vdex"));
        var restored =
                FrameworkDexMaterializer.materialize(
                        NativeCore.pinned(oat, Json.str(base, "oat_sha256")),
                                Json.str(base, "oat_sha256"),
                        NativeCore.pinned(vdex, Json.str(base, "vdex_sha256")),
                                Json.str(base, "vdex_sha256"));
        List<byte[]> dexFiles = new ArrayList<>(restored.dexFiles());

        if (base.containsKey("startupAudioZero")) {
            Failure.require(
                    Boolean.TRUE.equals(base.get("startupAudioZero")) && dexFiles.size() == 1,
                    "NXP_STARTUP_AUDIO_CONTRACT",
                    "Exact pinned API28 single-DEX startup audio component required",
                    3);
            dexFiles.set(
                    0,
                    NxpStartupVolumeGuard.apply(profile.referenceProfile(), api, dexFiles.get(0)));
        }

        for (byte[] data : dexFiles) {
            for (String descriptor :
                    NativeCore.classes(
                            new org.jf.dexlib2.dexbacked.DexBackedDexFile(
                                    org.jf.dexlib2.Opcodes.forApi(api), data))) {
                Failure.require(
                        !descriptor.equals(ViewDumpPatch.HELPER)
                                && !descriptor.startsWith(
                                        ViewDumpPatch.HELPER.substring(
                                                        0, ViewDumpPatch.HELPER.length() - 1)
                                                + "$"),
                        "FRAMEWORK_BRIDGE_COLLISION",
                        "Bridge namespace already exists in original boot classpath",
                        5);
            }
        }

        if (base.containsKey("bridge")) {
            Path helper = resolve(Json.str(base, "bridge"));
            Map<String, byte[]> helperEntries = NativeCore.entries(helper);
            Failure.require(
                    helperEntries.keySet().equals(Set.of("classes.dex")) && dexFiles.size() == 3,
                    "FRAMEWORK_BRIDGE_LAYOUT",
                    "Single helper DEX and exact framework multidex required",
                    5);
            byte[] originalDex = dexFiles.get(1),
                    helperDex =
                            FrameworkBridgeVerifier.jumboHelper(helperEntries.get("classes.dex"));
            byte[] patchedDex =
                    ViewDumpPatch.patch(
                            originalDex,
                            NativeCore.hash(originalDex),
                            helperDex,
                            NativeCore.hash(helperDex));
            FrameworkBridgeVerifier.verify(originalDex, helperDex, patchedDex);
            dexFiles.set(1, patchedDex);
        }

        Set<String> descriptors = new TreeSet<>();
        Map<String, byte[]> jar =
                new TreeMap<>(NativeCore.entries(android.read(Json.str(base, "jar"))));
        jar.keySet().removeIf(entry -> entry.matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex"));

        for (int index = 0; index < dexFiles.size(); index++) {
            byte[] data = dexFiles.get(index);

            for (String descriptor :
                    NativeCore.classes(
                            new org.jf.dexlib2.dexbacked.DexBackedDexFile(
                                    org.jf.dexlib2.Opcodes.forApi(api), data))) {
                Failure.require(
                        descriptors.add(descriptor),
                        "FRAMEWORK_DUPLICATE_CLASS",
                        "Cross-DEX framework class collision",
                        5);
            }

            jar.put(index == 0 ? "classes.dex" : "classes" + (index + 1) + ".dex", data);
        }

        Path output = dir.resolve(Json.str(definition, "output"));
        NativeCore.zip(output, jar, true);
        Files.writeString(
                dir.resolve("materialization.json"),
                Json.write(
                                Map.of(
                                        "schema",
                                        1,
                                        "oat_sha256",
                                        Json.str(base, "oat_sha256"),
                                        "vdex_sha256",
                                        Json.str(base, "vdex_sha256"),
                                        "semantic_sha256",
                                        restored.semanticSha256(),
                                        "classes",
                                        descriptors.size(),
                                        "jar_sha256",
                                        FilesSupport.hash(output),
                                        "bridge",
                                        base.containsKey("bridge")))
                        + "\n");

        return output;
    }

    private Path frameworkOriginalComponent(Map<String, Object> definition, Path dir)
            throws Exception {
        Failure.require(
                api == 28,
                "FRAMEWORK_API_UNSUPPORTED",
                "Framework restoration requires a proved format adapter",
                3);
        Path root = resolve("original:" + Json.str(definition, "frameworkOriginal"));

        if (frameworkClasspath == null) {
            frameworkClasspath = work.resolve("framework-classpath");
            Storage.directory(frameworkClasspath);

            for (var entry : FilesSupport.tree(root).entrySet()) {
                String file = entry.getValue().getFileName().toString();

                if (!NativeCore.BOOT.matcher(file).matches()) {
                    continue;
                }

                if (entry.getKey().startsWith("arm64/") && file.endsWith(".oat")) {
                    Files.copy(entry.getValue(), frameworkClasspath.resolve(file));
                }

                if (!entry.getKey().contains("/") && file.endsWith(".vdex")) {
                    Files.write(
                            frameworkClasspath.resolve(file),
                            BootVdex.decode(Files.readAllBytes(entry.getValue())));
                }
            }
        }

        String filename = Json.str(definition, "output"),
                base = filename.replaceFirst("\\.jar$", "");
        NativeCore.framework(frameworkClasspath, Storage.confined(root, filename), base, dir);

        return dir.resolve(filename);
    }

    private Path jarComponent(
            String name, Map<String, Object> definition, Path source, Path dir, int minimum)
            throws Exception {
        if (definition.containsKey("qinggan11PhonePeer")) {
            return BluetoothPeerComponent.build(
                    profile,
                    api,
                    name,
                    definition,
                    source,
                    new BluetoothPeerComponent.CompileInputs(
                            resolve("original:QGAPI"),
                            resolve("original:BluetoothPhone"),
                            tools.platform()),
                    dir);
        }

        if (definition.containsKey("donorDex")) {
            Map<String, Object> spec = Json.obj(definition, "donorDex");

            return DexOperations.donorJar(
                    resolve("original:" + Json.str(spec, "original")),
                    spec,
                    source.resolve("src"),
                    tools.platform(),
                    dir.resolve("library"),
                    Json.str(definition, "output"),
                    new DexOperations.DonorTarget(
                            api,
                            profile.referenceProfile(),
                            definition.containsKey("compatibilityAdapter")
                                    ? Json.str(definition, "compatibilityAdapter")
                                    : ""));
        }

        String compileOnly = GuestJava.COMPILE_ONLY;

        if (definition.containsKey("compileOnly")) {
            Failure.require(
                    name.equals("bluetooth")
                            && api == 28
                            && minimum == 28
                            && Json.str(definition, "output").equals("Ivt8BluetoothAdapter.jar")
                            && Json.str(definition, "compileOnly").equals("src/stub-cls"),
                    "COMPONENT_COMPILE_ONLY",
                    "Exact API28 Free Bluetooth compile-only ABI required",
                    5);
            Storage.confined(source, "src/stub-cls");
            compileOnly = "stub-cls";
        }

        Path dex =
                GuestJava.dex(
                        new GuestJava.Unit(source.resolve("src"), compileOnly, null, minimum),
                        tools.platform(),
                        dir.resolve("java"));
        Path output = dir.resolve(Json.str(definition, "output"));
        NativeCore.zip(output, bytes(dex), false);

        return output;
    }

    private Path apkComponent(Map<String, Object> definition, Path source, Path dir, int minimum)
            throws Exception {
        Path manifest = source.resolve("AndroidManifest.xml");
        String xml = Files.readString(manifest);

        Failure.require(
                !xml.matches("(?is).*(?:<!DOCTYPE|<!ENTITY).*"),
                "MANIFEST_INVALID",
                "External entities are forbidden",
                2);
        Path generated = dir.resolve("generated");
        Path resourceApk =
                linkComponentResources(
                        tools.buildTool("aapt2"),
                        tools.platform(),
                        source,
                        dir,
                        minimum,
                        Math.toIntExact(Json.integer(definition, "targetSdk")));
        Map<String, byte[]> entries = new TreeMap<>(NativeCore.entries(resourceApk));
        DexOperations.Donor donor = null;

        if (definition.containsKey("donorDex")) {
            Map<String, Object> spec = Json.obj(definition, "donorDex");
            boolean powerDonor =
                    api == 30
                            && new java.util.HashSet<>(Json.list(spec.get("classes")))
                                    .equals(
                                            Set.of(
                                                    "com.qinggan.power.IPowerManagerListener",
                                                    "com.qinggan.system.IPowerManagerService"));
            Path original = resolve("original:" + Json.str(spec, "original"));
            Failure.require(
                    !powerDonor
                            || FilesSupport.hash(original)
                                    .equals(
                                            Json.str(
                                                    Json.object(
                                                            Json.obj(profile.data(), "original")
                                                                    .get(
                                                                            Json.str(
                                                                                    spec,
                                                                                    "original"))),
                                                    "sha256")),
                    "DONOR_PIN_MISMATCH",
                    "Exact profile-bound OEM power ABI required",
                    5);
            donor = DexOperations.donor(original, spec, dir.resolve("donor"), api, "");
            entries.put("classes.dex", Files.readAllBytes(donor.dex()));
        }

        Set<String> donated = new TreeSet<>(donor == null ? Set.of() : donor.descriptors());
        String ownDex = donor == null ? "classes.dex" : "classes2.dex";

        // A second OEM donor fills the next DEX slot; its classes may not repeat the first donor.
        if (definition.containsKey("secondDonorDex")) {
            Failure.require(
                    donor != null,
                    "DONOR_SPEC_INVALID",
                    "Second donor requires the first donor",
                    2);
            Map<String, Object> spec = Json.obj(definition, "secondDonorDex");
            DexOperations.Donor second =
                    DexOperations.donor(
                            resolve("original:" + Json.str(spec, "original")),
                            spec,
                            dir.resolve("second-donor"),
                            api,
                            "");

            for (String descriptor : second.descriptors()) {
                Failure.require(
                        donated.add(descriptor), "DEX_CLASS_COLLISION", "Donor classes collide", 5);
            }

            entries.put(ownDex, Files.readAllBytes(second.dex()));
            ownDex = "classes3.dex";
        }

        Path own = source.resolve("src");

        if (Files.isDirectory(own) && !FilesSupport.tree(own).isEmpty()) {
            Path dex =
                    GuestJava.dex(
                            new GuestJava.Unit(own, GuestJava.COMPILE_ONLY, generated, minimum),
                            tools.platform(),
                            dir.resolve("java"));
            Map<String, byte[]> compiled = bytes(dex);
            Failure.require(
                    donor == null || !compiled.containsKey("classes2.dex"),
                    "DEX_SLOT_COLLISION",
                    "Own multidex conflicts with donor layout",
                    5);
            Set<String> descriptors = new TreeSet<>();

            for (Path file : FilesSupport.tree(dex).values()) {
                Set<String> classes =
                        NativeCore.classes(
                                org.jf.dexlib2.DexFileFactory.loadDexFile(
                                        file.toFile(), org.jf.dexlib2.Opcodes.forApi(api)));

                for (String descriptor : classes) {
                    Failure.require(
                            descriptors.add(descriptor) && !donated.contains(descriptor),
                            "DEX_CLASS_COLLISION",
                            "Own and donor classes collide",
                            5);
                }
            }

            for (var entry : compiled.entrySet()) {
                entries.put(
                        entry.getKey().equals("classes.dex") ? ownDex : entry.getKey(),
                        entry.getValue());
            }
        }

        return signed(entries, dir, minimum);
    }

    // Native components are CI-built release assets that the C++ side hands over before build().
    private static Path nativeComponent(Map<String, Object> definition) {
        throw new Failure(
                "PREPARATION_NATIVE_COMPONENT",
                "CI-built native component handoff required for " + Json.str(definition, "output"),
                3);
    }

    static void verifyPinnedNativeEntry(Map<String, byte[]> entries, String name, String pin)
            throws Exception {
        Failure.require(
                entries.containsKey(name) && NativeCore.hash(entries.get(name)).equals(pin),
                "PATCH_ENTRY_HASH_MISMATCH",
                "Pinned native entry differs or is absent",
                5);
    }

    private Path patched(String name) throws Exception {
        Map<String, Object> definition = Json.object(Json.obj(profile.data(), "patches").get(name));

        Failure.require(
                !Boolean.TRUE.equals(definition.get("resources")),
                "PATCH_RESOURCES_UNSUPPORTED",
                "Code-only backend cannot rebuild OEM resources",
                3);
        Path input = resolve(Json.str(definition, "input")), dir = work.resolve("patched-" + name);
        Storage.directory(dir);
        Map<String, Path> uses = new LinkedHashMap<>();

        if (definition.containsKey("uses")) {
            for (Object value : Json.list(definition.get("uses"))) {
                uses.put((String) value, resolve((String) value));
            }
        }

        String type = Json.str(definition, "type");
        Path decoded = dir.resolve("decoded");
        Storage.directory(decoded);
        Map<String, byte[]> entries =
                type.equals("file") ? new TreeMap<>() : new TreeMap<>(NativeCore.entries(input));
        Map<String, Set<String>> classSets = new LinkedHashMap<>();
        List<String> dexNames =
                entries.keySet().stream()
                        .filter(file -> file.matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex"))
                        .sorted()
                        .toList();

        DexClasses dex = null;

        if (type.equals("file")) {
            Files.copy(input, decoded.resolve("output"));
        } else if (api != 30) {
            dex = new DexClasses(entries, dexNames, api);

            for (String dexName : dexNames) {
                classSets.put(dexName, dex.classes(dexName));
            }
        }

        List<Path> added = new ArrayList<>();
        Map<String, byte[]> donorSlots = new LinkedHashMap<>();
        var patch =
                new PatchTarget.Patch(
                        profile,
                        api,
                        abi,
                        tools,
                        type,
                        Json.str(definition, "input"),
                        input,
                        dir,
                        decoded,
                        uses,
                        entries,
                        dex,
                        classSets,
                        added,
                        donorSlots);
        applySteps(name, definition, patch);

        if (type.equals("file")) {
            return decoded.resolve("output");
        }

        if (dex != null) {
            dex.write(entries);
        }

        appendDexSlots(dexNames, classSets, donorSlots, added, dir, entries);
        entries.keySet()
                .removeIf(entry ->
                        DexOperations.signatureEntry(entry)
                                && !(type.equals("jar")
                                        && (name.equals(SecondaryNavigationGuard.NAME)
                                                || name.equals(
                                                        PassionSecondaryNavigationGuard.NAME))
                                        && entry.equals("META-INF/MANIFEST.MF")));
        Path output;

        if (type.equals("apk")) {
            output = signed(entries, dir, api);
        } else {
            output = dir.resolve("patched.jar");
            NativeCore.zip(output, entries, false);
        }

        FilesSupport.removeOwnedTree(decoded);

        return output;
    }

    private void applySteps(String name, Map<String, Object> definition, PatchTarget.Patch patch)
            throws Exception {
        for (int pass = api == 30 ? 0 : 1; pass < 2; pass++) {
            for (Object value : Json.list(definition.get("steps"))) {
                String step = (String) value;
                Failure.require(
                        step.endsWith(".json"),
                        "PATCH_STEP_UNSUPPORTED",
                        "Native patch step must have a registered handler",
                        2);
                Path stepRoot = Storage.confined(recipe.resolve("patches"), step).getParent();
                Map<String, Object> metadata = Json.object(patches.get(step));
                Recipes.Target target =
                        new PatchTarget(
                                patch,
                                stepRoot,
                                metadata.get("constants") instanceof Map<?, ?>
                                        ? Json.obj(metadata, "constants")
                                        : Map.of(),
                                pass == 0);
                log.accept("Applying patch " + name + ": " + step);

                if (pass == 0) {
                    Recipes.validateApi30(step, metadata, target);
                } else {
                    Recipes.apply(step, metadata, target);
                }
            }
        }
    }

    private void appendDexSlots(
            List<String> dexNames,
            Map<String, Set<String>> classSets,
            Map<String, byte[]> donorSlots,
            List<Path> added,
            Path dir,
            Map<String, byte[]> entries)
            throws Exception {
        Set<String> classes = new TreeSet<>();

        for (Set<String> set : classSets.values()) {
            for (String descriptor : set) {
                Failure.require(
                        classes.add(descriptor),
                        "DEX_CLASS_COLLISION",
                        "Original APK has duplicate classes",
                        5);
            }
        }

        int slot =
                dexNames.stream()
                                .mapToInt(file ->
                                        file.equals("classes.dex")
                                                ? 1
                                                : Integer.parseInt(
                                                        file.substring(7, file.length() - 4)))
                                .max()
                                .orElse(0)
                        + 1;
        // Embedded donor definitions share the application classloader, including native-library
        // lookup.
        // The donor JARs are build inputs only: no uses-library declaration may shadow these
        // definitions.
        // Only the NXP SystemUI steps declare donor slots; NxpSettingsLibrary.slot checks each.
        List<String> order =
                List.of(
                        "component:media-callbacks",
                        "component:settings-runtime",
                        "component:settings-managers",
                        "component:systemui-runtime-a",
                        "component:systemui-runtime-b",
                        "component:systemui-runtime-c");
        Failure.require(
                donorSlots.keySet().stream().allMatch(order::contains)
                        && order.stream().filter(donorSlots::containsKey).count()
                                == donorSlots.size(),
                "PATCH_DEPENDENCY_MISSING",
                "Unknown or unordered donor slot",
                5);

        for (String reference : order) {
            if (donorSlots.containsKey(reference)) {
                byte[] payload = donorSlots.get(reference);
                Path verify = dir.resolve("slot-verify-" + slot + ".dex");
                Files.write(verify, payload);

                for (String descriptor :
                        NativeCore.classes(
                                org.jf.dexlib2.DexFileFactory.loadDexFile(
                                        verify.toFile(), org.jf.dexlib2.Opcodes.forApi(api)))) {
                    Failure.require(
                            classes.add(descriptor),
                            "DEX_CLASS_COLLISION",
                            "Donor slot class collides with an existing class",
                            5);
                }

                entries.put("classes" + slot++ + ".dex", payload);
            }
        }

        for (Path dex : added) {
            for (String descriptor :
                    NativeCore.classes(
                            org.jf.dexlib2.DexFileFactory.loadDexFile(
                                    dex.toFile(), org.jf.dexlib2.Opcodes.forApi(api)))) {
                Failure.require(
                        classes.add(descriptor),
                        "DEX_CLASS_COLLISION",
                        "Helper class collision",
                        5);
            }

            entries.put("classes" + slot++ + ".dex", Files.readAllBytes(dex));
        }
    }

    static Path linkComponentResources(
            Path aapt2, Path platform, Path source, Path dir, int minimum, int target)
            throws Exception {
        Path resourceApk = dir.resolve("resources.apk"), generated = dir.resolve("generated");

        Storage.directory(generated);
        List<String> link =
                new ArrayList<>(
                        List.of(
                                "link",
                                "-o",
                                resourceApk.toString(),
                                "--manifest",
                                source.resolve("AndroidManifest.xml").toString(),
                                "-I",
                                platform.toString(),
                                "--min-sdk-version",
                                String.valueOf(minimum),
                                "--target-sdk-version",
                                String.valueOf(target),
                                "--java",
                                generated.toString()));

        if (Files.isDirectory(source.resolve("res"))
                && !FilesSupport.tree(source.resolve("res")).isEmpty()) {
            Path compiled = dir.resolve("compiled.zip");
            Processes.run(
                    aapt2,
                    List.of(
                            "compile",
                            "--dir",
                            source.resolve("res").toString(),
                            "-o",
                            compiled.toString()),
                    dir,
                    Duration.ofMinutes(3),
                    false);
            // First resource table of a new APK, exactly as the source TS builder: not -R overlay
            // merging.
            link.add(compiled.toString());
        }

        if (Files.isDirectory(source.resolve("assets"))) {
            link.addAll(List.of("-A", source.resolve("assets").toString()));
        }

        Processes.run(aapt2, link, dir, Duration.ofMinutes(3), false);

        return resourceApk;
    }

    /**
     * Replaces or adds selected classes of the primary DEX with the definitions of an adapter
     * component; selection maps each class name to "replace" or "add".
     */
    static void mergeAdapterClasses(
            DexClasses dex,
            Path adapter,
            Map<String, Object> selection,
            Map<String, Set<String>> classSets,
            int api)
            throws Exception {
        Failure.require(
                !selection.isEmpty() && selection.size() <= 1024,
                "PATCH_CLASS_INVALID",
                "Explicit bounded class selection required",
                5);
        var container =
                org.jf.dexlib2.DexFileFactory.loadDexContainer(
                        adapter.toFile(), org.jf.dexlib2.Opcodes.forApi(api));
        Map<String, List<org.jf.dexlib2.iface.ClassDef>> compiled = new TreeMap<>();

        for (String name : container.getDexEntryNames()) {
            for (var type : container.getEntry(name).getDexFile().getClasses()) {
                compiled.computeIfAbsent(
                                type.getType().toLowerCase(java.util.Locale.ROOT),
                                key -> new ArrayList<>())
                        .add(type);
            }
        }

        Map<String, String> original = new TreeMap<>();

        for (var classes : classSets.values()) {
            for (String type : classes) {
                original.merge(type.toLowerCase(java.util.Locale.ROOT), type, (a, b) -> "");
            }
        }

        Set<String> aliases = new TreeSet<>();
        List<org.jf.dexlib2.iface.ClassDef> replacements = new ArrayList<>(),
                additions = new ArrayList<>();

        for (var selected : selection.entrySet()) {
            String name = selected.getKey();
            Object mode = selected.getValue();
            Failure.require(
                    name.matches("[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)+")
                            && aliases.add(name.toLowerCase(java.util.Locale.ROOT))
                            && ("replace".equals(mode) || "add".equals(mode)),
                    "PATCH_CLASS_INVALID",
                    "Invalid class selection",
                    5);
            String descriptor = "L" + name.replace('.', '/') + ";",
                    alias = descriptor.toLowerCase(java.util.Locale.ROOT);
            List<org.jf.dexlib2.iface.ClassDef> after = compiled.getOrDefault(alias, List.of());
            Failure.require(
                    after.size() == 1
                            && after.get(0).getType().equals(descriptor)
                            && ("replace".equals(mode)
                                    ? descriptor.equals(original.get(alias))
                                    : !original.containsKey(alias)),
                    "PATCH_CLASS_MISMATCH",
                    "Expected exact original and adapter class definitions",
                    5);

            if ("add".equals(mode)) {
                Failure.require(
                        classSets.containsKey("classes.dex"),
                        "PATCH_CLASS_MISMATCH",
                        "Primary DEX missing",
                        5);
                additions.add(after.get(0));
            } else {
                replacements.add(after.get(0));
            }
        }

        // Validate the entire selection before changing the original classes.
        for (var type : replacements) {
            dex.replace(type);
        }

        for (var type : additions) {
            dex.add("classes.dex", type);
            classSets.get("classes.dex").add(type.getType());
        }
    }

    private Path signed(Map<String, byte[]> entries, Path dir, int minimum) throws Exception {
        Path unsigned = dir.resolve("unsigned.apk");

        NativeCore.zip(unsigned, entries, true);
        byte[] key = Files.readAllBytes(tools.key("key")),
                certificate = Files.readAllBytes(tools.key("cert"));
        Path signed =
                DexOperations.sign(unsigned, dir.resolve("signed.apk"), key, certificate, minimum);
        Files.delete(unsigned);

        return signed;
    }

    private static Map<String, byte[]> bytes(Path directory) throws Exception {
        Map<String, byte[]> result = new TreeMap<>();

        for (var entry : FilesSupport.tree(directory).entrySet()) {
            result.put(entry.getKey(), Files.readAllBytes(entry.getValue()));
        }

        return result;
    }

    static void elf(Path path, String abi) throws Exception {
        byte[] header;

        try (var input = Files.newInputStream(path)) {
            header = input.readNBytes(64);
        }

        Failure.require(
                header.length >= 20
                        && header[0] == 0x7f
                        && header[1] == 'E'
                        && header[2] == 'L'
                        && header[3] == 'F'
                        && header[5] == 1,
                "NATIVE_ABI_INVALID",
                "Invalid ELF header",
                5);
        int machine = Byte.toUnsignedInt(header[18]) | Byte.toUnsignedInt(header[19]) << 8;
        int expected =
                switch (abi) {
                    case "arm64-v8a" -> 183;
                    case "armeabi-v7a" -> 40;
                    case "x86_64" -> 62;
                    case "x86" -> 3;
                    default -> -1;
                };
        Failure.require(
                machine == expected
                        && header[4] == (abi.equals("arm64-v8a") || abi.equals("x86_64") ? 2 : 1),
                "NATIVE_ABI_INVALID",
                "ELF does not match guest ABI",
                5);
    }
}
