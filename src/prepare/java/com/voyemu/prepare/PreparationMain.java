package com.voyemu.prepare;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Host-only source preparation entry. Never launches or installs a guest machine. */
public final class PreparationMain {
    /** Verifies a bounded preparation input against its SHA-256 pin and returns the same path. */
    interface PinnedInput {
        Path verify(Path path, String sha256);
    }

    // The vehicle definition pins the SDK archive and the clean image contents.
    private static boolean registeredApi30Base(Map<String, Object> base) {
        boolean api30 =
                "system-images;android-30;default;arm64-v8a".equals(base.get("package"))
                        || "system-images;android-30;default;x86_64".equals(base.get("package"));

        Failure.require(
                (api30 || "system-images;android-28;default;arm64-v8a".equals(base.get("package")))
                        && base.get("sha256") instanceof String sha
                        && sha.matches("[0-9a-f]{64}"),
                api30 ? "PREPARATION_ANDROID_BASE" : "PREPARATION_BASE",
                api30 ? "Pinned API30 base descriptor required" : "Registered base required",
                3);

        return api30;
    }

    /** The SHA-256 that clean_base of the android object of profile.json pins for name in group. */
    static String cleanBasePin(Map<String, Object> base, String group, String name) {
        Object pins = base.get("clean_base") instanceof Map<?, ?> clean ? clean.get(group) : null;
        Object pin = pins instanceof Map<?, ?> map ? map.get(name) : null;

        Failure.require(
                pin instanceof String value && value.matches("[0-9a-f]{64}"),
                "PREPARATION_ANDROID_BASE",
                "Clean base pin required: " + group + " " + name,
                3);

        return (String) pin;
    }

    // Mirrored transport guard with native java_preparation.cpp; both read profile.json pins.
    static void validateAndroidReceipt(
            Map<String, Object> base, String logical, Map<String, Object> receipt) {
        boolean vendor = logical.startsWith("/vendor/"),
                extension = logical.startsWith("/system_ext/");
        boolean api30 = registeredApi30Base(base);

        Failure.require(
                logical.startsWith("/system/") || vendor || (api30 && extension),
                "PREPARATION_ANDROID_PATH",
                "Registered system/vendor/system_ext path required",
                2);
        String image = cleanBasePin(base, "images", vendor ? "vendor.img" : "system.img");
        Failure.require(
                Json.integer(receipt, "schema") == 1
                        && Boolean.TRUE.equals(receipt.get("native"))
                        && Boolean.FALSE.equals(receipt.get("filesystem_mounted"))
                        && image.equals(Json.str(receipt, "image_sha256")),
                "PREPARATION_ANDROID_RECEIPT",
                "Pinned registered-base extraction receipt required",
                3);

        if (api30 && !vendor) {
            Map<String, Object>
                    partitions = Json.obj(Json.obj(base, "clean_base"), "logical_partitions"),
                    partition = Json.obj(partitions, extension ? "system_ext" : "system");
            Failure.require(
                    (extension ? "system_ext" : "system").equals(receipt.get("logical_partition"))
                            && Json.str(partitions, "metadata_sha256")
                                    .equals(receipt.get("lp_metadata_sha256"))
                            && Json.integer(receipt, "partition_offset")
                                    == Json.integer(partition, "offset")
                            && Json.integer(receipt, "logical_partition_bytes")
                                    == Json.integer(partition, "bytes"),
                    "PREPARATION_ANDROID_RECEIPT",
                    "Pinned API30 logical-system/system_ext view required",
                    3);
        }
    }

    // The policy node that the last native file node uses besides the mapping.
    private static int nativePolicyIndex(List<Api30NativeFiles.Spec> specs, boolean passion) {
        int policyIndex = passion ? 0 : 1;

        for (int i = 0; i < specs.size(); i++) {
            if (specs.get(i).id().equals("can-early-policy-api30")) {
                policyIndex = i;
            }
        }

        return policyIndex;
    }

    // The registered patch node of native file spec i.
    private static Map<String, Object> expectedNativeNode(
            List<Api30NativeFiles.Spec> specs, int policyIndex, int i, boolean bounded) {
        var spec = specs.get(i);
        Map<String, Object> expected =
                new java.util.LinkedHashMap<>(
                        Map.of(
                                "type",
                                "file",
                                "input",
                                "android:" + spec.target(),
                                "steps",
                                Api30NativeFiles.nodeSteps(spec.id())));

        if (i == specs.size() - 1) {
            expected.put(
                    "uses",
                    List.of(
                            "patched:" + specs.get(policyIndex).id(),
                            "android:" + Api30NativeFiles.MAPPING));
        }

        if (bounded) {
            expected.put("uses", List.of("original:SystemExtSepolicy", "original:VendorSepolicy"));
        }

        return expected;
    }

    // Only the original Navi SELinux output names its certificate source.
    private static void requireNativeCertificate(
            Map<String, Object> request,
            ProfileRegistry.Profile profile,
            PinnedInput pinned,
            String id,
            Map<String, Object> output)
            throws Exception {
        if (id.equals("original-navi-selinux")) {
            requireNaviCertificate(request, profile, pinned, output);
        } else {
            Failure.require(
                    !output.containsKey("certificate_source"),
                    "PREPARATION_NATIVE_FILE",
                    "Unexpected certificate provenance",
                    3);
        }
    }

    static Map<String, Path> nativeFileOutputs(
            Map<String, Object> request,
            ProfileRegistry.Profile profile,
            Map<String, Object> sourcePins,
            Map<String, Path> android,
            PinnedInput pinned)
            throws Exception {
        if (Api28CodecNativeFile.selected(profile)) {
            return Api28CodecNativeFile.outputs(request, profile, sourcePins, android, pinned);
        }

        boolean passion = "passion".equals(profile.data().get("platform")),
                qinggan11 = "qinggan11".equals(profile.data().get("platform"));
        var specs = Api30NativeFiles.forProfile(profile);
        int policyIndex = nativePolicyIndex(specs, passion);
        long fileNodes =
                Json.obj(profile.data(), "patches").values().stream()
                        .filter(v -> "file".equals(Json.object(v).get("type")))
                        .count();
        Failure.require(
                !qinggan11 || fileNodes == specs.size(),
                "PREPARATION_NATIVE_FILE",
                "Free API30 requires public native visibility and the complete registered native"
                        + " file graph",
                3);

        if (!request.containsKey("native_files")) {
            Failure.require(
                    !registeredApi30Base(Json.obj(profile.data(), "android")) || fileNodes == 0,
                    "PREPARATION_NATIVE_FILE",
                    "Native API30 file receipt missing",
                    3);

            return Map.of();
        }

        requireNativeHandoff(profile, specs.size(), fileNodes, passion, qinggan11);
        Map<String, Object> input = Json.obj(request, "native_files");
        Path receiptFile =
                pinned.verify(
                        absolute(Json.str(input, "receipt")), Json.str(input, "receipt_sha256"));
        Failure.require(
                receiptFile.startsWith(absolute(Json.str(request, "root")).resolve(".local"))
                        && Files.size(receiptFile) <= 128 * 1024,
                "PREPARATION_NATIVE_FILE",
                "Bounded project native receipt required",
                3);
        Map<String, Object> receipt = Json.object(Json.parse(Files.readString(receiptFile))),
                provenance = Json.obj(receipt, "profile_provenance");
        requireNativeProvenance(profile, receipt, provenance, fileNodes);
        Map<String, Object> nodes = new java.util.LinkedHashMap<>();
        Map<String, Path> outputs = new java.util.LinkedHashMap<>();
        String extractionPin = null;

        for (int i = 0; i < fileNodes; ++i) {
            var spec = specs.get(i);
            String id = spec.id(), target = spec.target();
            boolean bounded =
                    qinggan11
                            && (id.equals("can-simulator-policy-api30")
                                    || id.equals("can-early-policy-api30"));
            Failure.require(
                    Json.object(Json.obj(profile.data(), "patches").get(id))
                                    .equals(expectedNativeNode(specs, policyIndex, i, bounded))
                            && sourcePins.containsKey(spec.step()),
                    "PREPARATION_NATIVE_FILE",
                    "Native node/source differs",
                    3);
            nodes.put(
                    id,
                    Map.of(
                            "input_sha256",
                            spec.inputPin(),
                            "output_sha256",
                            spec.outputPin(),
                            "target",
                            target));
            var extraction = Json.object(Json.obj(request, "android_inputs").get(target));
            String selected = Json.str(extraction, "receipt_sha256");

            if (extractionPin == null) {
                extractionPin = selected;
            }

            Failure.require(
                    extractionPin.equals(selected),
                    "PREPARATION_NATIVE_FILE",
                    "Native extraction binding differs",
                    3);
            var output = Json.object(Json.list(receipt.get("files")).get(i));
            requireNativeOutputProfile(profile, id, output, passion, qinggan11);
            Path source = android.get(target);
            requireNativeFileBinding(spec, id, source, output);
            pinned.verify(source, spec.inputPin());
            Path file =
                    pinned.verify(
                            Storage.confined(receiptFile.getParent(), id + ".output"),
                            spec.outputPin());
            Failure.require(
                    Files.size(file) <= 4L * 1024 * 1024,
                    "PREPARATION_NATIVE_FILE",
                    "Bounded native output required",
                    3);

            if (id.equals(specs.get(specs.size() - 1).id())) {
                requireNativeMapping(
                        request, android, pinned, specs.get(policyIndex), extractionPin, output);
            } else if (bounded) {
                requireNativePolicyDonors(request, profile, pinned, output);
            } else {
                Failure.require(
                        !output.containsKey("donor")
                                && !output.containsKey("vendor_donor")
                                && !output.containsKey("patched_dependency"),
                        "PREPARATION_NATIVE_FILE",
                        "Unexpected native dependency",
                        3);
            }

            requireNativeCertificate(request, profile, pinned, id, output);
            outputs.put("patched:" + id, file);
        }

        Failure.require(
                extractionPin.equals(provenance.get("extraction_receipt_sha256"))
                        && Json.obj(provenance, "nodes").equals(nodes),
                "PREPARATION_NATIVE_FILE",
                "Native extraction/recipe provenance differs",
                3);

        return outputs;
    }

    private static void requireNativeHandoff(
            ProfileRegistry.Profile profile,
            int specCount,
            long fileNodes,
            boolean passion,
            boolean qinggan11) {
        Failure.require(
                registeredApi30Base(Json.obj(profile.data(), "android"))
                        && ((!passion && !qinggan11 && fileNodes == 1) || fileNodes == specCount),
                "PREPARATION_NATIVE_FILE",
                "Native file handoff is exact API30-only",
                3);
    }

    private static void requireNativeProvenance(
            ProfileRegistry.Profile profile,
            Map<String, Object> receipt,
            Map<String, Object> provenance,
            long fileNodes) {
        Failure.require(
                Json.integer(receipt, "schema") == 1
                        && "native-file-draft".equals(receipt.get("kind"))
                        && Json.list(receipt.get("files")).size() == fileNodes
                        && profile.id().equals(provenance.get("profile"))
                        && Boolean.TRUE.equals(provenance.get("native"))
                        && Boolean.FALSE.equals(provenance.get("machine_ready"))
                        && cleanBasePin(Json.obj(profile.data(), "android"), "images", "system.img")
                                .equals(provenance.get("system_image_sha256")),
                "PREPARATION_NATIVE_FILE",
                "Native profile provenance differs",
                3);
    }

    private static void requireNativeFileBinding(
            Api30NativeFiles.Spec spec, String id, Path source, Map<String, Object> output) {
        Failure.require(
                source != null
                        && source.toString().equals(output.get("input"))
                        && spec.inputPin().equals(output.get("input_sha256"))
                        && spec.outputPin().equals(output.get("output_sha256"))
                        && id.equals(output.get("id"))
                        && Json.integer(output, "api") == 30
                        && (id + ".output").equals(output.get("output")),
                "PREPARATION_NATIVE_FILE",
                "Native file input/output binding differs",
                3);
    }

    private static void requireNativeOutputProfile(
            ProfileRegistry.Profile profile,
            String id,
            Map<String, Object> output,
            boolean passion,
            boolean qinggan11) {
        Failure.require(
                (passion
                                || (qinggan11
                                        && (id.equals("selinux-services-api30")
                                                || id.equals("selinux-hash-api30")
                                                || id.equals("can-simulator-contexts-api30")
                                                || id.equals("can-early-file-contexts-api30")
                                                || id.equals("can-simulator-policy-api30")
                                                || id.equals("can-early-policy-api30")
                                                || id.equals("can-early-property-contexts-api30")))
                                || id.equals("public-qg-runtime-api30")
                                || id.equals("property-contexts-api30")
                                || id.equals("keymanager-contexts-api30")
                                || id.equals("original-navi-selinux"))
                        ? profile.referenceProfile().equals(output.get("profile"))
                        : !output.containsKey("profile"),
                "PREPARATION_NATIVE_FILE",
                "Native output profile differs",
                3);
    }

    private static void requireNativeMapping(
            Map<String, Object> request,
            Map<String, Path> android,
            PinnedInput pinned,
            Api30NativeFiles.Spec policy,
            String extractionPin,
            Map<String, Object> output) {
        Path mapping = android.get(Api30NativeFiles.MAPPING);

        Failure.require(
                mapping != null, "PREPARATION_NATIVE_FILE", "Native mapping input missing", 3);
        pinned.verify(mapping, Api30NativeFiles.MAPPING_PIN);
        var mappingExtraction =
                Json.object(Json.obj(request, "android_inputs").get(Api30NativeFiles.MAPPING));
        Failure.require(
                extractionPin.equals(Json.str(mappingExtraction, "receipt_sha256"))
                        && Json.obj(output, "donor")
                                .equals(
                                        Map.of(
                                                "input",
                                                mapping.toString(),
                                                "sha256",
                                                Api30NativeFiles.MAPPING_PIN))
                        && Json.obj(output, "patched_dependency")
                                .equals(Map.of("id", policy.id(), "sha256", policy.outputPin())),
                "PREPARATION_NATIVE_FILE",
                "Native policy/mapping dependency differs",
                3);
    }

    // The bounded su of the Free A11 policy comes from the OEM system_ext and vendor policies.
    private static void requireNativePolicyDonors(
            Map<String, Object> request,
            ProfileRegistry.Profile profile,
            PinnedInput pinned,
            Map<String, Object> output)
            throws Exception {
        Path originals =
                absolute(Json.str(request, "root"))
                        .resolve(".local/profiles")
                        .resolve(profile.id())
                        .resolve("originals");
        Map<String, Object> declared = Json.obj(profile.data(), "original");

        for (var donor :
                List.of(
                        List.of("donor", "SystemExtSepolicy"),
                        List.of("vendor_donor", "VendorSepolicy"))) {
            var original = Json.object(declared.get(donor.get(1)));
            Path file = originals.resolve(Json.str(original, "file"));
            String pin = Json.str(original, "sha256");
            Failure.require(
                    Json.obj(output, donor.get(0))
                                    .equals(Map.of("input", file.toString(), "sha256", pin))
                            && !output.containsKey("patched_dependency"),
                    "PREPARATION_NATIVE_FILE",
                    "Native OEM policy donor differs",
                    3);
            pinned.verify(file, pin);
        }
    }

    private static void requireNaviCertificate(
            Map<String, Object> request,
            ProfileRegistry.Profile profile,
            PinnedInput pinned,
            Map<String, Object> output)
            throws Exception {
        Failure.require(
                profile.originalNavi(),
                "PREPARATION_NATIVE_FILE",
                "Original Navi policy requires the original_navi feature",
                3);
        String pin = Json.str(Json.obj(Json.obj(profile.data(), "original"), "Navi"), "sha256");
        Path apk =
                absolute(Json.str(request, "root"))
                        .resolve(".local/profiles")
                        .resolve(profile.id())
                        .resolve("originals/Navi.apk");

        Failure.require(
                Json.obj(output, "certificate_source")
                        .equals(
                                Map.of(
                                        "source",
                                        "certificate-from-original:Navi",
                                        "apk",
                                        apk.toString(),
                                        "apk_sha256",
                                        pin,
                                        "certificate_sha256",
                                        "b2e962ed163aed0831d6d08ee41ca9406ae970032aa4df8a4c3b41d222b201d3")),
                "PREPARATION_NATIVE_FILE",
                "Original Navi certificate provenance differs",
                3);
        pinned.verify(apk, pin);
    }

    static Map<String, Path> nativeComponentOutputs(
            Map<String, Object> request,
            ProfileRegistry.Profile profile,
            Path root,
            PinnedInput pinned)
            throws Exception {
        Map<String, Object> declared = Json.obj(profile.data(), "components"),
                inputs =
                        request.containsKey("native_components")
                                ? Json.obj(request, "native_components")
                                : Map.of();
        Map<String, Path> result = new TreeMap<>();

        for (var entry : declared.entrySet()) {
            String id = entry.getKey();
            Path source =
                    Storage.confined(
                            root.resolve("profiles").resolve(profile.id()),
                            (String) entry.getValue());
            Map<String, Object> definition =
                    Json.object(Json.parse(Files.readString(source.resolve("component.json"))));

            if (!"native".equals(definition.get("type"))) {
                continue;
            }

            String type = (String) definition.getOrDefault("outputType", "shared-library");
            Failure.require(
                    type.equals("shared-library") || type.equals("executable"),
                    "PREPARATION_NATIVE_COMPONENT",
                    "Unknown native output type",
                    3);
            long recipeApi = Json.integer(definition, "minSdk");
            Failure.require(
                    inputs.containsKey(id) && (recipeApi == 28 || recipeApi == 30),
                    "PREPARATION_NATIVE_COMPONENT",
                    "Declared API28/API30 native component receipt required",
                    3);
            Map<String, Object> item = Json.object(inputs.get(id));
            String name = Json.str(definition, "output"), hash = Json.str(item, "sha256");
            Failure.require(
                    name.matches(
                                    type.equals("executable")
                                            ? "[A-Za-z0-9_][A-Za-z0-9_-]*"
                                            : "lib[A-Za-z0-9_]+\\.so")
                            && name.equals(item.get("output")),
                    "PREPARATION_NATIVE_COMPONENT",
                    "Native component identity differs",
                    3);
            Path receipt =
                    pinned.verify(
                            absolute(Json.str(item, "receipt")), Json.str(item, "receipt_sha256"));
            Failure.require(
                    receipt.startsWith(root.resolve(".local/build"))
                            && Files.size(receipt) <= 1024 * 1024,
                    "PREPARATION_NATIVE_COMPONENT",
                    "Owned receipt required",
                    3);
            Map<String, Object> proof = Json.object(Json.parse(Files.readString(receipt)));
            // The launcher decides the ABI of each component and passes it with the receipt.
            String abi = Json.str(item, "abi");
            Failure.require(
                    Json.integer(proof, "schema") == 1
                            && "native".equals(proof.get("type"))
                            && type.equals(proof.get("output_type"))
                            && Json.integer(proof, "api") == recipeApi
                            && abi.equals(proof.get("abi"))
                            && name.equals(proof.get("output"))
                            && hash.equals(proof.get("sha256")),
                    "PREPARATION_NATIVE_COMPONENT",
                    "Native component receipt differs",
                    3);

            if (definition.containsKey("sourceBuildSha256")) {
                Failure.require(
                        "recipe".equals(proof.get("source"))
                                && hash.equals(Json.str(definition, "sourceBuildSha256")),
                        "PREPARATION_NATIVE_COMPONENT",
                        "Native source build differs from its declared recipe pin",
                        3);
            }

            Path output = pinned.verify(Storage.confined(receipt.getParent(), name), hash);
            Failure.require(
                    Files.size(output) == Json.integer(proof, "bytes"),
                    "PREPARATION_NATIVE_COMPONENT",
                    "Native component extent differs",
                    3);
            Artifacts.elf(output, abi);
            result.put("component:" + id, output);
        }

        Failure.require(
                result.size() == inputs.size(),
                "PREPARATION_NATIVE_COMPONENT",
                "Undeclared native component receipt rejected",
                3);

        return result;
    }

    private static Path absolute(String text) throws Exception {
        Path path = Path.of(text);

        Failure.require(
                path.isAbsolute() && path.normalize().equals(path),
                "PREPARATION_PATH",
                "Normalized absolute path required",
                2);
        Storage.confined(path, ".");

        return path;
    }

    /** The definition the launcher resolved and pinned; the helper never resolves a target. */
    private static Map<String, Object> requestedProfile(Map<String, Object> request)
            throws Exception {
        byte[] bytes = Json.str(request, "resolved_profile").getBytes(StandardCharsets.UTF_8);

        Failure.require(
                bytes.length <= 1024 * 1024
                        && NativeCore.hash(bytes).equals(Json.str(request, "profile_sha256")),
                "PREPARATION_PROFILE_PIN",
                "Profile differs from request pin",
                3);

        return Json.object(Json.parse(new String(bytes, StandardCharsets.UTF_8)));
    }

    private static Map<String, Object> targetIdentity(ProfileRegistry.Profile profile) {
        var target = Json.obj(profile.data(), "target");

        return Map.of(
                "name", Json.str(target, "name"),
                "abi", Json.str(target, "guestAbi"),
                "base_sha256", Json.str(Json.obj(profile.data(), "android"), "sha256"));
    }

    static Map<String, Object> run(Map<String, Object> request) throws Exception {
        Failure.require(
                Json.integer(request, "schema") == 1,
                "PREPARATION_SCHEMA",
                "Request schema 1 required",
                2);
        String operation = Json.str(request, "operation");
        Failure.require(
                operation.equals("plan") || operation.equals("build-artifacts"),
                "PREPARATION_OPERATION",
                "Expected plan or build-artifacts",
                2);
        Path root = absolute(Json.str(request, "root"));
        ProfileRegistry registry =
                new ProfileRegistry(root, Json.str(request, "profile"), requestedProfile(request));
        ProfileRegistry.Profile profile = registry.get(Json.str(request, "profile"));
        Map<String, Object> plan = new LinkedHashMap<>();
        plan.put("schema", 1);
        plan.put("operation", operation);
        plan.put("profile", profile.id());

        if (profile.data().containsKey("target")) {
            plan.put("target", targetIdentity(profile));
        }

        plan.put(
                "components",
                Json.obj(profile.data(), "components").keySet().stream().sorted().toList());
        plan.put(
                "patch_nodes",
                Json.obj(profile.data(), "patches").keySet().stream().sorted().toList());
        Map<String, Object> sourcePins = stepSourcePins(root, profile);
        plan.put("machine_ready", false);
        plan.put("guest_started", false);

        if (operation.equals("plan")) {
            registry.verifySource(profile);

            return plan;
        }

        registeredApi30Base(Json.obj(profile.data(), "android"));
        Map<Path, String> tracked = new LinkedHashMap<>();
        PinnedInput pinned =
                (path, hash) -> {
                    try {
                        Failure.require(
                                hash.matches("[a-f0-9]{64}")
                                        && Files.isRegularFile(path)
                                        && !Files.isSymbolicLink(path)
                                        && FilesSupport.hash(path).equals(hash),
                                "PREPARATION_INPUT_PIN",
                                "Bounded preparation input differs from pin",
                                3);
                        Storage.confined(path, ".");
                        tracked.put(path, hash);

                        return path;
                    } catch (IOException | NoSuchAlgorithmException error) {
                        throw new Failure(
                                "PREPARATION_INPUT", "Could not verify preparation input", 3);
                    }
                };
        Path metadataFile =
                pinned.verify(
                        absolute(Json.str(request, "patch_data")),
                        Json.str(request, "patch_data_sha256"));
        Failure.require(
                Files.size(metadataFile) <= 4L * 1024 * 1024,
                "PREPARATION_METADATA",
                "Patch metadata exceeds bound",
                2);
        Map<String, Object> metadata = Json.object(Json.parse(Files.readString(metadataFile)));
        verifyPatchMetadata(metadata, sourcePins);
        Path local = root.resolve(".local");
        Storage storage =
                new Storage(
                        local,
                        local.resolve("toolchains"),
                        local.resolve("toolchains/downloads"),
                        local.resolve("build"),
                        local.resolve("build/tmp"),
                        local.resolve("build/logs"));
        Inputs.Checked checked = Inputs.check(profile, storage);
        Failure.require(
                checked.ok(),
                "PREPARATION_ORIGINALS",
                "All owner originals must match profile pins",
                3);

        for (var entry : Inputs.definitions(profile).entrySet()) {
            Failure.require(
                    Json.object(entry.getValue())
                            .get("sha256")
                            .equals(checked.pins().get(entry.getKey())),
                    "PREPARATION_ORIGINALS",
                    "Local override cannot replace selected profile originals",
                    3);
        }

        Toolchains selectedTools = selectedTools(request, storage, tracked, pinned);
        Map<String, Path> android = androidInputs(request, profile, pinned);
        Map<String, Path> nativeOutputs =
                nativeFileOutputs(request, profile, sourcePins, android, pinned);
        Map<String, Path> nativeComponents = nativeComponentOutputs(request, profile, root, pinned);
        // Existing source builder may consume cache entries, but never acquire them during build.
        pinComponentSources(root, profile, storage, pinned);
        Path work = absolute(Json.str(request, "work"));
        Failure.require(
                work.startsWith(local) && !Files.exists(work),
                "PREPARATION_WORK",
                "Fresh work directory inside project .local required",
                2);
        Path recipe = registry.sourceDirectory(profile);
        Artifacts builder =
                new Artifacts(
                        new Artifacts.PatchedProfile(profile, metadata),
                        storage,
                        selectedTools,
                        recipe,
                        work,
                        logical -> {
                            Path file = android.get(logical);
                            Failure.require(
                                    file != null,
                                    "PREPARATION_ANDROID_MISSING",
                                    "Extracted Android input missing: " + logical,
                                    3);

                            return file;
                        },
                        System.err::println);

        for (var entry : nativeOutputs.entrySet()) {
            builder.useNativeFile(entry.getKey(), entry.getValue());
        }

        for (var entry : nativeComponents.entrySet()) {
            builder.useNativeComponent(entry.getKey(), entry.getValue());
        }

        boolean powerHelpers =
                PassionPowerHelperContract.requested(Json.obj(profile.data(), "patches"));
        Map<String, Path> artifacts = builder.build();
        registry.verifySource(profile);
        requireUnchanged(tracked, profile, storage, checked);
        Map<String, Object> outputs =
                artifactOutputs(
                        artifacts,
                        powerHelpers,
                        PassionGeneratedHelperContract.requested(
                                Json.obj(profile.data(), "patches")),
                        PassionMcuHelperContract.requested(Json.obj(profile.data(), "patches")));
        plan.put("artifacts", outputs);
        plan.put("artifacts_built", true);

        return plan;
    }

    // Every pinned input and original still matches the pins observed before the build.
    private static void requireUnchanged(
            Map<Path, String> tracked,
            ProfileRegistry.Profile profile,
            Storage storage,
            Inputs.Checked checked)
            throws Exception {
        for (var entry : tracked.entrySet()) {
            Failure.require(
                    FilesSupport.hash(entry.getKey()).equals(entry.getValue()),
                    "PREPARATION_INPUT_CHANGED",
                    "Preparation input changed during build",
                    3);
        }

        Failure.require(
                Inputs.check(profile, storage).pins().equals(checked.pins()),
                "PREPARATION_ORIGINALS_CHANGED",
                "Original inputs changed during build",
                3);
    }

    private static Map<String, Object> stepSourcePins(Path root, ProfileRegistry.Profile profile)
            throws Exception {
        Map<String, Object> sourcePins = new TreeMap<>();

        // Preserve each actual source step pin; canonical declarative metadata is an explicit build
        // input.
        for (Object value : Json.obj(profile.data(), "patches").values()) {
            for (Object step : Json.list(Json.object(value).get("steps"))) {
                String name = (String) step;
                sourcePins.put(
                        name,
                        FilesSupport.hash(
                                Storage.confined(
                                        root.resolve("profiles/" + profile.id() + "/patches"),
                                        name)));
            }
        }

        return sourcePins;
    }

    private static void verifyPatchMetadata(
            Map<String, Object> metadata, Map<String, Object> sourcePins) {
        for (var entry : sourcePins.entrySet()) {
            Map<String, Object> data = Json.object(metadata.get(entry.getKey()));
            Failure.require(
                    Json.integer(data, "schema") == 1
                            && entry.getValue().equals(Json.str(data, "sourceSha256")),
                    "PREPARATION_METADATA",
                    "Declarative recipe is not bound to current source",
                    3);
        }
    }

    private static Toolchains selectedTools(
            Map<String, Object> request,
            Storage storage,
            Map<Path, String> tracked,
            PinnedInput pinned)
            throws Exception {
        Map<String, Object> tools = Json.obj(request, "tools");
        Path sdk = absolute(Json.str(tools, "sdk"));
        // The launcher passes the toolchain manifest it embeds, so preparation never reads src/.
        String manifest = Json.str(tools, "manifest");

        Failure.require(
                NativeCore.hash(manifest.getBytes(StandardCharsets.UTF_8))
                        .equals(Json.str(tools, "manifest_sha256")),
                "PREPARATION_TOOLS",
                "Toolchain manifest differs from its SHA-256",
                3);
        Map<String, Object> toolchain = Json.object(Json.parse(manifest));

        for (var entry : Json.obj(tools, "files").entrySet()) {
            pinned.verify(Storage.confined(sdk, entry.getKey()), (String) entry.getValue());
        }

        Map<String, Object> signing = Json.obj(tools, "signing");
        Path key =
                pinned.verify(absolute(Json.str(signing, "key")), Json.str(signing, "key_sha256"));
        Path certificate =
                pinned.verify(
                        absolute(Json.str(signing, "certificate")),
                        Json.str(signing, "certificate_sha256"));
        Path platformOverride = null;

        if (tools.containsKey("platform")) {
            Map<String, Object> platform = Json.obj(tools, "platform");
            platformOverride =
                    pinned.verify(
                            absolute(Json.str(platform, "file")), Json.str(platform, "sha256"));
        }

        // The CI-built guest Java of the android-java asset; without it the helper compiles on a
        // JDK.
        if (tools.containsKey("guest_java")) {
            Map<String, Object> guestJava = Json.obj(tools, "guest_java");
            GuestJava.use(
                    pinned.verify(
                            absolute(Json.str(guestJava, "file")), Json.str(guestJava, "sha256")));
        }

        Toolchains selectedTools =
                new Toolchains(storage, toolchain, sdk, key, certificate, platformOverride);
        List<Path> requiredTools =
                new ArrayList<>(
                        List.of(
                                selectedTools.platform(),
                                selectedTools.buildTool("aapt2"),
                                selectedTools.buildTool("zipalign")));

        for (Path required : requiredTools) {
            Failure.require(
                    tracked.containsKey(required),
                    "PREPARATION_TOOL_PIN",
                    "Required tool file pin missing: " + sdk.relativize(required),
                    3);
        }

        return selectedTools;
    }

    private static Map<String, Path> androidInputs(
            Map<String, Object> request, ProfileRegistry.Profile profile, PinnedInput pinned)
            throws Exception {
        Map<String, Path> android = new TreeMap<>();

        for (var entry : Json.obj(request, "android_inputs").entrySet()) {
            String logical = entry.getKey();
            Failure.require(
                    logical.startsWith("/system/")
                            || logical.startsWith("/vendor/")
                            || logical.startsWith("/system_ext/"),
                    "PREPARATION_ANDROID_PATH",
                    "Extracted system/vendor/system_ext path required",
                    2);
            Map<String, Object> input = Json.object(entry.getValue());
            Path receiptFile =
                    pinned.verify(
                            absolute(Json.str(input, "receipt")),
                            Json.str(input, "receipt_sha256"));
            Failure.require(
                    Files.size(receiptFile) <= 128 * 1024,
                    "PREPARATION_ANDROID_RECEIPT",
                    "Extraction receipt exceeds bound",
                    3);
            Map<String, Object> receipt = Json.object(Json.parse(Files.readString(receiptFile)));
            validateAndroidReceipt(Json.obj(profile.data(), "android"), logical, receipt);
            String relative =
                    logical.startsWith("/vendor/")
                            ? logical.substring(8)
                            : logical.startsWith("/system_ext/")
                                    ? logical.substring(12)
                                    : logical.substring(1);
            Path file = Storage.confined(receiptFile.getParent(), relative);
            Map<String, Object> filePin = Json.object(Json.obj(receipt, "files").get(relative));
            pinned.verify(file, Json.str(filePin, "sha256"));
            Failure.require(
                    Files.size(file) == Json.integer(filePin, "bytes"),
                    "PREPARATION_ANDROID_RECEIPT",
                    "Extracted file extent differs",
                    3);
            android.put(logical, file);
        }

        return android;
    }

    private static void pinComponentSources(
            Path root, ProfileRegistry.Profile profile, Storage storage, PinnedInput pinned)
            throws Exception {
        for (Object value : Json.obj(profile.data(), "components").values()) {
            Map<String, Object> component =
                    Json.object(
                            Json.parse(
                                    Files.readString(
                                            Storage.confined(
                                                    root.resolve("profiles/" + profile.id()),
                                                    value + "/component.json"))));

            if (component.containsKey("externalSources")) {
                for (Object external : Json.obj(component, "externalSources").values()) {
                    String hash = Json.str(Json.object(external), "sha256");
                    pinned.verify(storage.cache().resolve("sources/" + hash), hash);
                }
            }
        }
    }

    static Map<String, Object> artifactOutputs(Map<String, Path> artifacts, boolean powerHelpers)
            throws Exception {
        return artifactOutputs(artifacts, powerHelpers, Set.of());
    }

    static Map<String, Object> artifactOutputs(
            Map<String, Path> artifacts, boolean powerHelpers, Set<String> generatedHelpers)
            throws Exception {
        return artifactOutputs(artifacts, powerHelpers, generatedHelpers, false);
    }

    static Map<String, Object> artifactOutputs(
            Map<String, Path> artifacts,
            boolean powerHelpers,
            Set<String> generatedHelpers,
            boolean mcuHelper)
            throws Exception {
        if (mcuHelper) {
            Failure.require(
                    artifacts.containsKey(PassionMcuHelperContract.ARTIFACT),
                    "PASSION_MCU",
                    "Declared MCU helper artifact missing",
                    5);
        }

        for (String artifact : generatedHelpers) {
            PassionGeneratedHelperContract.slot(artifact);
            Failure.require(
                    artifacts.containsKey(artifact) && Files.isRegularFile(artifacts.get(artifact)),
                    "PASSION_GENERATED_HELPER",
                    "Declared helper artifact missing",
                    5);
        }

        Map<String, Object> outputs = new TreeMap<>();

        for (var entry : artifacts.entrySet()) {
            if (Files.isRegularFile(entry.getValue())) {
                Map<String, Object> output = new TreeMap<>();
                output.put("file", entry.getValue().toString());
                output.put("sha256", FilesSupport.hash(entry.getValue()));
                output.put("bytes", Files.size(entry.getValue()));

                if (powerHelpers
                        && (entry.getKey().equals(PassionPowerHelperContract.SDK)
                                || entry.getKey().equals(PassionPowerHelperContract.OEM))) {
                    output.put(
                            "power_helper",
                            PassionPowerHelperContract.receipt(entry.getKey(), entry.getValue()));
                }

                if (mcuHelper && entry.getKey().equals(PassionMcuHelperContract.ARTIFACT)) {
                    output.put("mcu_helper", PassionMcuHelperContract.receipt(entry.getValue()));
                }

                if (generatedHelpers.contains(entry.getKey())) {
                    output.put(
                            "generated_helper",
                            PassionGeneratedHelperContract.receipt(
                                    entry.getKey(), entry.getValue()));
                }

                outputs.put(entry.getKey(), output);
            }
        }

        for (var entry : artifacts.entrySet()) {
            if (Files.isDirectory(entry.getValue())) {
                Map<String, Object> files = new TreeMap<>();

                for (var file : FilesSupport.tree(entry.getValue()).entrySet()) {
                    files.put(
                            file.getKey(),
                            Map.of(
                                    "sha256",
                                    FilesSupport.hash(file.getValue()),
                                    "bytes",
                                    Files.size(file.getValue())));
                }

                outputs.put(
                        entry.getKey(),
                        Map.of("directory", entry.getValue().toString(), "files", files));
            }
        }

        return outputs;
    }

    static void diagnostic(Throwable error, java.io.PrintStream output) {
        // Exception messages may contain arbitrary tool/input data. Emit only bounded code
        // locations.
        output.println(error.getClass().getName());
        StackTraceElement[] frames = error.getStackTrace();

        for (int i = 0; i < Math.min(frames.length, 24); i++) {
            output.println("  at " + frames[i]);
        }

        if (frames.length > 24) {
            output.println("  ... truncated");
        }
    }

    public static void main(String[] args) {
        try {
            Failure.require(
                    args.length == 1, "PREPARATION_USAGE", "PreparationMain REQUEST.json", 2);
            Path request = absolute(args[0]);
            Failure.require(
                    Files.size(request) <= 2L * 1024 * 1024,
                    "PREPARATION_REQUEST",
                    "Request exceeds bound",
                    2);
            System.out.println(Json.write(run(Json.object(Json.parse(Files.readString(request))))));
        } catch (Failure error) {
            System.err.println(error.code + ": " + error.getMessage());
            System.exit(error.exitCode);
        } catch (Throwable error) {
            // checkstyle-allow IllegalCatch: process boundary reports every failure
            diagnostic(error, System.err);
            System.exit(1);
        }
    }
}
