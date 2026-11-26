#include "selinux_patch.hpp"
#include "model.hpp"
#include "process.hpp"
#include <fstream>
#include <iostream>
#include <regex>
using namespace voyemu;

constexpr ProfileScope qinggan09_scope{ProfilePlatform::qinggan09, ProfileBoard::sa8155},
        nxp_scope{ProfilePlatform::qinggan09, ProfileBoard::nxp},
        qinggan11_scope{ProfilePlatform::qinggan11, ProfileBoard::sa8155},
        passion_scope{ProfilePlatform::passion, ProfileBoard::sa8155};

static void check(bool ok, const char *text) {
    if (!ok) {
        throw std::runtime_error(text);
    }
}

static bool rejects(std::string_view id, unsigned api, std::string_view input) {
    try {
        apply_selinux_context_patch(id, api, input);

        return false;
    } catch (...) {
        return true;
    }
}

int main(int argc, char **argv) {
    try {
        if (argc == 3 && std::string_view(argv[1]) == "--can-simulator-contexts") {
            std::ifstream source(argv[2], std::ios::binary);
            check(bool(source), "API28 context input required");
            const std::string input{std::istreambuf_iterator<char>(source), {}};
            const auto output = apply_can_simulator_context_patch(qinggan09_scope, 28, input);
            check(output.starts_with(input) &&
                          sha256_bytes(output) ==
                                  "b140f7f850f0279e8935053b948784708c9c62de4aeb59019a7c07ef0d9f5813",
                  "exact stock context bytes and scoped simulator labels");

            for (const auto bad : {nxp_scope, qinggan11_scope}) {
                bool rejected = false;
                try {
                    apply_can_simulator_context_patch(bad, 28, input);
                } catch (...) {
                    rejected = true;
                }

                check(rejected, "wrong profile rejected");
            }

            for (const auto &bad : {input + " ", output}) {
                bool rejected = false;
                try {
                    apply_can_simulator_context_patch(qinggan09_scope, 28, bad);
                } catch (...) {
                    rejected = true;
                }

                check(rejected, "wrong source and reapply rejected");
            }

            bool wrong_api = false;
            try {
                apply_can_simulator_context_patch(qinggan09_scope, 30, input);
            } catch (...) {
                wrong_api = true;
            }

            check(wrong_api, "wrong API rejected");
            std::cout << "simulator context source/profile/output guards passed\n";

            return 0;
        }

        if (argc == 5 && std::string_view(argv[1]) == "--can-simulator-policy") {
            auto read = [](const char *path) {
                std::ifstream f(path, std::ios::binary);
                check(bool(f), "pinned policy input required");

                return std::string{std::istreambuf_iterator<char>(f), {}};
            };
            auto input = read(argv[2]), plat = read(argv[3]), vendor = read(argv[4]);
            auto base = apply_bounded_canbus_policy(28, input, plat, vendor).cil;
            auto output = apply_can_simulator_policy_patch(qinggan09_scope, 28, base);
            check(output.starts_with(base) &&
                          sha256_bytes(output) ==
                                  "ea017c277007b5ba8401ab214b2d607d72ddd39b7a303db05eb5281cb405fd22",
                  "simulator policy preserves bounded su and exact candidate");
            const auto early = apply_can_early_policy_patch(qinggan09_scope, 28, output);
            check(early.starts_with(output) &&
                          sha256_bytes(early) ==
                                  "2879712e7a6a12f262ab346fbe61b7f5b992e652e10d93edf8eb44a6c7b84a77",
                  "early policy exact pin");
            bool reapply = false;
            try {
                apply_can_early_policy_patch(qinggan09_scope, 28, early);
            } catch (...) {
                reapply = true;
            }

            check(reapply, "early policy reapply rejected");

            for (int i = 0; i < 4; ++i) {
                bool denied = false;
                try {
                    apply_can_simulator_policy_patch(i == 0 ? nxp_scope : qinggan09_scope,
                                                     i == 1 ? 30 : 28,
                                                     i == 2   ? base + " "
                                                     : i == 3 ? output
                                                              : base);
                } catch (...) {
                    denied = true;
                }

                check(denied, "policy profile/API/pin/reapply");
            }

            std::cout << "simulator policy guards passed\n";

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--can-early-property") {
            std::ifstream f(argv[2], std::ios::binary);
            check(bool(f), "property source required");
            const std::string source{std::istreambuf_iterator<char>(f), {}};
            const auto base = apply_selinux_context_patch("selinux-property-contexts-a9", 28,
                                                          source);
            const auto output = apply_can_early_property_patch(qinggan09_scope, 28, base);
            check(sha256_bytes(output) ==
                          "bd2a3eafde0f3d98966d590dcc70047f9fa38e9812f3660a0326182e0f43540d",
                  "exact property output");

            for (int i = 0; i < 3; ++i) {
                bool denied = false;
                try {
                    apply_can_early_property_patch(i == 0 ? nxp_scope : qinggan09_scope,
                                                   i == 1 ? 30 : 28, i == 2 ? output : base);
                } catch (...) {
                    denied = true;
                }

                check(denied, "property profile/API/reapply guard");
            }

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--can-early-contexts") {
            std::ifstream f(argv[2], std::ios::binary);
            check(bool(f), "file context source required");
            const std::string source{std::istreambuf_iterator<char>(f), {}};
            const auto base = apply_can_simulator_context_patch(qinggan09_scope, 28, source);
            const auto output = apply_can_early_file_context_patch(qinggan09_scope, 28, base);
            check(sha256_bytes(output) ==
                          "8bd8062c3b8108bdc34573f78d403691e747298a986a3464ace94721b02ad1d7",
                  "exact early contexts output");

            for (int i = 0; i < 3; ++i) {
                bool denied = false;
                try {
                    apply_can_early_file_context_patch(i == 0 ? nxp_scope : qinggan09_scope,
                                                       i == 1 ? 30 : 28, i == 2 ? output : base);
                } catch (...) {
                    denied = true;
                }

                check(denied, "early contexts profile/API/reapply guard");
            }

            return 0;
        }

        if (argc == 3 && std::string_view(argv[1]) == "--api30-early-property") {
            // The real extracted API30 plat_property_contexts of the Free A11 base drives the
            // pinned chain: the cluster/Hiboard step output feeds the early property step.
            std::ifstream f(argv[2], std::ios::binary);
            check(bool(f), "API30 property context input required");
            const std::string source{std::istreambuf_iterator<char>(f), {}};
            check(sha256_bytes(source) ==
                          "a49213f01ea1f8ec19b41311116bc9324c682af1482297e4bbbc05265dfd623e",
                  "exact clean API30 platform property contexts required");
            const auto after_cluster =
                    source + "persist.clusterCardInfo u:object_r:system_prop:s0 exact string\n"
                             "ignoreActivation u:object_r:system_prop:s0 exact bool\n";
            check(sha256_bytes(after_cluster) ==
                          "50c13ef43f195b1b94c5e1ed85f3a33578220e6074d9d244414ae73c9837d2db",
                  "cluster and Hiboard step output remains exact");
            const auto output = apply_qinggan11_can_early_property_patch(qinggan11_scope, 30,
                                                                         after_cluster);
            check(output.substr(0, after_cluster.size()) == after_cluster &&
                          output.substr(after_cluster.size()) ==
                                  "qinggan.thirdscreen.standby u:object_r:system_prop:s0 exact bool\n"
                                  "sys.voyemu.early.ready u:object_r:can_early_ready_prop:s0 exact string\n"
                                  "sys.voyemu.early.probe u:object_r:exported3_system_prop:s0 exact string\n" &&
                          sha256_bytes(output) ==
                                  "3ba593c9e010284511a1433a599c345e89c115122059238cd3aa9842fb33cbcd",
                  "all platform bytes preserved with the exact rear-screen standby and early properties");

            for (int i = 0; i < 5; ++i) {
                bool denied = false;
                try {
                    const auto bytes =
                            i == 0   ? source
                            : i == 1 ? after_cluster + "qinggan.thirdscreen.standby "
                                                       "u:object_r:system_prop:s0 exact bool\n"
                            : i == 2 ? after_cluster + "qinggan.thirdscreen.standby "
                                                       "u:object_r:default_prop:s0 exact bool\n"
                            : i == 3 ? after_cluster + "qinggan.thirdscreen.standby "
                                                       "u:object_r:system_prop:s0 exact string\n"
                                     : after_cluster;
                    apply_qinggan11_can_early_property_patch(i == 4 ? passion_scope
                                                                    : qinggan11_scope,
                                                             30, i == 4 ? after_cluster : bytes);
                } catch (...) {
                    denied = true;
                }

                check(denied, "standby baseline/duplicate/label/type/scope guards");
            }

            std::cout
                    << "actual API30 early property contexts with the rear-screen standby passed\n";

            return 0;
        }

        bool passion_unpinned = false;
        try {
            apply_passion_selinux_patch(passion_scope, 30, "services", "unverified fixture");
        } catch (...) {
            passion_unpinned = true;
        }

        check(passion_unpinned, "Passion cannot accept arbitrary platform policy bytes");

        if (argc == 8 && std::string_view(argv[1]) == "--passion-api30-policy") {
            auto read = [](const char *path) {
                std::ifstream source(path, std::ios::binary);
                check(bool(source), "Passion policy input required");

                return std::string{std::istreambuf_iterator<char>(source), {}};
            };
            constexpr auto profile = passion_scope;
            auto denied = [](ProfileScope p, unsigned api, std::string_view id,
                             std::string_view input) {
                try {
                    apply_passion_selinux_patch(p, api, id, input);

                    return false;
                } catch (...) {
                    return true;
                }
            };
            const auto input = read(argv[2]), contexts = read(argv[3]), mapping = read(argv[4]),
                       properties = read(argv[5]), hwservices = read(argv[6]),
                       files = read(argv[7]);
            const auto output = apply_passion_selinux_patch(profile, 30, "services", input),
                       mapped = apply_passion_selinux_patch(profile, 30, "service-contexts",
                                                            contexts);
            check(output.starts_with(input) &&
                          mapped ==
                                  contexts +
                                          "car_service u:object_r:voyemu_car_service:s0\ncom.mega.NexusService u:object_r:voyemu_nexus_service:s0\ncom.mega.car.CarService u:object_r:voyemu_mega_car_service:s0\n",
                  "Passion append preserves original policy/context bytes");
            const auto property = apply_passion_selinux_patch(profile, 30, "property-contexts",
                                                              properties);
            check(property == properties +
                                          "boot.car_service_created u:object_r:system_prop:s0 exact bool\n" &&
                          denied(profile, 30, "property-contexts", property) &&
                          denied(profile, 30, "property-contexts", properties + " ") &&
                          denied(profile, 28, "property-contexts", properties),
                  "exact property scope/source/reapply guards");
            const auto hwservice = apply_passion_selinux_patch(profile, 30, "hwservice-contexts",
                                                               hwservices);
            check(hwservice == hwservices + "vendor.mega.message_center::IMessageCenter "
                                            "u:object_r:message_center_hwservice:s0\n" &&
                          denied(profile, 30, "hwservice-contexts", hwservice) &&
                          denied(profile, 28, "hwservice-contexts", hwservices),
                  "exact message center hwservice label");
            const auto labels = apply_passion_selinux_patch(profile, 30, "file-contexts", files);
            check(labels.starts_with(files) &&
                          labels.find("\n/vendor/bin/someipd -- u:object_r:someipd_exec:s0\n") !=
                                  std::string::npos &&
                          labels.find("/vendor/bin/config_vlan\\.sh "
                                      "u:object_r:vendor_qti_init_shell_exec:s0\n") !=
                                  std::string::npos &&
                          labels.find("/vendor/bin/oem-eth0\\.sh "
                                      "u:object_r:goldfish_setup_exec:s0\n") != std::string::npos &&
                          labels.find("\n/log/android(/.*)? u:object_r:android_data_file:s0\n") !=
                                  std::string::npos &&
                          labels.find("vehicle@2\\.0-mega-service "
                                      "u:object_r:hal_vehicle_default_exec:s0\n") !=
                                  std::string::npos &&
                          denied(profile, 30, "file-contexts", labels) &&
                          denied(profile, 28, "file-contexts", files),
                  "exact OEM network, message center, VHAL and /log file labels");
            const auto own = output.substr(input.size());
            check(own.find("(allow system_app voyemu_car_service (service_manager (add find)))") !=
                                  std::string::npos &&
                          own.find("(allow message_center_default message_center_hwservice "
                                   "(hwservice_manager (add find)))") != std::string::npos &&
                          own.find("(allow system_app message_center_hwservice "
                                   "(hwservice_manager (find)))") != std::string::npos &&
                          own.find("(typetransition init someipd_exec process someipd)") !=
                                  std::string::npos &&
                          own.find("(typetransition init vendor_qti_init_shell_exec process "
                                   "vendor_qti_init_shell)") != std::string::npos &&
                          own.find("_30_0") == std::string::npos &&
                          own.find("default_android_hwservice") == std::string::npos &&
                          own.find("default_service") == std::string::npos &&
                          own.find("permissive") == std::string::npos &&
                          own.find("su ") == std::string::npos,
                  "own service permissions and the OEM vendor domains mapped onto the platform");
            check(apply_passion_selinux_patch(profile, 30, "policy-hash", output + mapping) ==
                          "9a666d2c89e4adbe1d3e46d126ec1c32be94e708150c0e7937d1395b604eaef7\n",
                  "Passion hash binds patched CIL and unchanged mapping");

            for (const auto id : {"services", "service-contexts", "policy-hash"}) {
                const auto &original = std::string_view(id) == "services" ? input
                                       : std::string_view(id) == "service-contexts"
                                               ? contexts
                                               : output + mapping;
                check(denied(qinggan11_scope, 30, id, original) &&
                              denied(profile, 28, id, original) &&
                              denied(profile, 30, id, original + " "),
                      "wrong profile/API/source rejected");
            }

            check(denied(profile, 30, "services", output) &&
                          denied(profile, 30, "service-contexts", mapped) &&
                          denied(profile, 30, "policy-hash", input + mapping) &&
                          denied(profile, 30, "policy-hash", output) &&
                          denied(profile, 30, "unknown", input),
                  "reapply/conflict/unpatched/missing mapping/unknown operation rejected");
            check(rejects("services", 30, input), "Passion does not widen Free recipe dispatch");
            std::cout
                    << "exact Passion API30 policy/context/hash guards passed; guest compile unverified\n";

            return 0;
        }

        if (argc == 5 && std::string_view(argv[1]) == "--api30-policy") {
            auto read = [](const char *path) {
                std::ifstream source(path, std::ios::binary);
                check(bool(source), "API30 policy input required");

                return std::string{std::istreambuf_iterator<char>(source), {}};
            };
            const auto input = read(argv[2]), contexts = read(argv[3]);
            const auto generic = apply_selinux_context_patch("selinux-services-api30", 30, input);
            const auto output = apply_selinux_context_patch("selinux-services-api30", 30, input,
                                                            true);
            check(generic.find(
                          "(allow platform_app voyemu_cockpit_service (service_manager (find)))") ==
                          std::string::npos,
                  "generic policy remains unchanged");
            const auto mapped = apply_selinux_context_patch("selinux-service-contexts-api30", 30,
                                                            contexts);
            check(output.starts_with(input) && mapped.starts_with(contexts),
                  "API30 append preserves all original policy/context bytes");
            check(output.find(
                          "(allow platform_app voyemu_cockpit_service (service_manager (find)))") !=
                          std::string::npos,
                  "Navi platform application can discover real cockpit services");
            check(output.find("(allow platform_app voyemu_cockpit_service (service_manager (add") ==
                          std::string::npos,
                  "Navi cannot publish cockpit services");

            for (const std::string name :
                 {"qg.canbus", "qg.setting", "qg.display_manager", "multidisplay", "multiwindow"}) {
                check(mapped.find(name + " u:object_r:voyemu_cockpit_service:s0\n") !=
                              std::string::npos,
                      "each proven published service mapped");
            }

            const auto keymapped = apply_selinux_context_patch("keymanager-contexts-api30", 30,
                                                               contexts);
            check(keymapped ==
                          mapped +
                                  "qg.key_manager u:object_r:voyemu_cockpit_service:s0\nqg.power_manager u:object_r:voyemu_cockpit_service:s0\nqg.cluster.service u:object_r:voyemu_cockpit_service:s0\nqg.system_policy u:object_r:voyemu_cockpit_service:s0\nqg.qgbus_service u:object_r:voyemu_cockpit_service:s0\nqg.carsignal u:object_r:voyemu_cockpit_service:s0\nqg.audio_policy u:object_r:voyemu_cockpit_service:s0\n",
                  "Free adds only genuine KeyManager, PowerManager, SystemPolicy, QGBus, car signal and"
                  " AudioPolicy service names");
            check(mapped.find("qg.key_manager") == std::string::npos &&
                          rejects("keymanager-contexts-api30", 28, contexts) &&
                          rejects("keymanager-contexts-api30", 30, keymapped) &&
                          rejects("keymanager-contexts-api30", 30, contexts + " "),
                  "generic context unchanged; wrong API/source/reapply rejected");
            check(output.find(
                          "(allow system_app voyemu_cockpit_service (service_manager (add find)))") !=
                          std::string::npos,
                  "only current shared system UID can publish/find own type");
            check(output.substr(input.size()).find("su ") == std::string::npos &&
                          output.substr(input.size()).find("default_android_service") ==
                                  std::string::npos,
                  "no A9 su/default service carveouts");
            check(rejects("selinux-services-api30", 30, output) &&
                          rejects("selinux-service-contexts-api30", 30, mapped) &&
                          rejects("selinux-services-api30", 28, input) &&
                          rejects("selinux-service-contexts-api30", 28, contexts),
                  "API30 repeat and cross API reject");
            check(rejects("selinux-services-api30", 30, input + " ") &&
                          rejects("selinux-service-contexts-api30", 30, contexts + " "),
                  "API30 whole source pins required");
            const auto mapping = read(argv[4]);
            const auto hash = apply_selinux_context_patch("selinux-hash-api30", 30,
                                                          output + mapping, true);
            check(hash == "d312218f439e3f970934791cdfa572078b5d78b21a3d5eeddff3f2a1c5b6e364\n",
                  "API30 hash includes actual unchanged mapping");
            check(rejects("selinux-hash-api30", 30, output) &&
                          rejects("selinux-hash-api30", 30, input + mapping) &&
                          rejects("selinux-hash-api30", 30, output + mapping + " ") &&
                          rejects("selinux-hash-api30", 28, output + mapping),
                  "missing mapping/unpatched CIL/corrupt mapping/wrong API hash rejected");
            std::cout
                    << "exact API30 native service policy/context guards passed; guest compile unverified\n";

            return 0;
        }

        check(argc == 2, "profile steps required");

        for (const std::string kind : {"service", "property"}) {
            const auto id = "selinux-" + kind + "-contexts-a9";
            std::ifstream source(std::filesystem::path(argv[1]) / (id + ".json"));
            check(bool(source), "reference recipe exists");
            Json data;
            source >> data;
            check(data.at("api") == 28, "reference API guard preserved");
            std::string expected = "original\n";

            for (const auto &entry : data.at("constants").at("ENTRIES")) {
                expected += entry.get<std::string>() + "\n";
            }

            check(apply_selinux_context_patch(id, 28, "original\n\n") == expected,
                  "native entries exactly match profile and normalize trailing LF");
            check(rejects(id, 28, expected), "repeat application rejected");
            check(rejects(id, 30, "original"), "Android 11 cannot use Android 9 contexts");
        }

        check(rejects("selinux-property-contexts-a9", 28,
                      "  persist.app.\tu:object_r:other_prop:s0\n"),
              "duplicate property prefix rejected even with another label and whitespace");
        check(rejects("selinux-nvram-contexts-a9", 28, "old") &&
                      rejects("selinux-nvram-contexts-api30", 30, "old"),
              "the NVRAM store needs no file context recipe");
        check(apply_selinux_context_patch("selinux-hash-a9", 28, "abc") ==
                      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
              "policy hash derives from dependency bytes with final newline");
        const std::string cil =
                "(type su)\n(type present)\n(typealias alias)\n(typeattribute service_manager_type)\n(typepermissive su)\n";
        const std::string map =
                "; private fixture, no OEM bytes\n(allow su present (file (read)))\n(allow su alias (file (read)))\n(allow su service_manager_type (service_manager (find)))\n(allow su absent_oem_type (file (write)))\n";
        const std::string vendor =
                "; private fixture, no OEM bytes\n(allow su_28_0 present_28_0 (dir (search)))\n(allow su_28_0 service_manager_type (service_manager (add)))\n(allow su_28_0 self (process (execmem)))\n(allow su_28_0 vendor_only (file (read)))\n(allow su_28_0 absent_oem_type_28_0 (file (write)))\n(allow su present_28_0 (file (write)))\n(allow vendor_domain present_28_0 (file (write)))\n";
        auto bounded = apply_bounded_canbus_policy(28, cil, map, vendor);
        check(bounded.applied == 6 && bounded.skipped == 3,
              "filter recognizes types aliases attributes self and skips unknown OEM types");
        check(bounded.cil.find("(typepermissive su)") == std::string::npos &&
                      bounded.cil.find("absent_oem_type") == std::string::npos &&
                      bounded.cil.find("vendor_only") == std::string::npos &&
                      bounded.cil.find("_28_0") == std::string::npos &&
                      bounded.cil.find("vendor_domain") == std::string::npos,
              "permissive removed and absent OEM types not imported");
        check(bounded.cil.find("(allow su alias (file (read)))\n(allow su service_manager_type "
                               "(service_manager (find)))\n(allow su present (dir (search)))\n"
                               "(allow su service_manager_type (service_manager (add)))\n"
                               "(allow su self (process (execmem)))\n") != std::string::npos,
              "plat rules then vendor rules read through the 28.0 mapping");

        for (const std::string name : {"selinux-canbus-a9.json", "selinux-bounded-su-a9.json"}) {
            std::ifstream file(std::filesystem::path(argv[1]) / name);
            check(bool(file), "reference policy recipe exists");
            Json data;
            file >> data;
            const auto &rules = data.at("constants")
                                        .at(name == "selinux-canbus-a9.json" ? "RULES"
                                                                             : "CARVEOUT");
            std::size_t position = 0;

            for (const auto &rule : rules) {
                const auto text = rule.get<std::string>();
                const auto found = bounded.cil.find(text, position);
                check(found != std::string::npos,
                      "native policy preserves independent source rule order and contents");
                position = found + text.size();
            }

            check(rules.size() == (name == "selinux-canbus-a9.json" ? 8u : 5u),
                  "all expected profile policy rules checked");
        }

        bool repeated = false;
        try {
            apply_bounded_canbus_policy(28, bounded.cil, map, vendor);
        } catch (...) {
            repeated = true;
        }

        check(repeated, "policy repetition rejected");
        // API 30 reads the vendor rules through the 30.0 mapping and adds no A9 canbus services.
        const auto bounded30 = apply_bounded_canbus_policy(
                30, "(type su)\n(type present)\n(typepermissive su)\n",
                "(allow su present (file (read)))\n(allow su absent (file (read)))\n",
                "(allow su_30_0 present_30_0 (dir (search)))\n(allow su_30_0 self (process "
                "(execmem)))\n(allow su_28_0 present_28_0 (file (write)))\n");
        check(bounded30.applied == 3 && bounded30.skipped == 1 &&
                      bounded30.cil.find("(typepermissive su)") == std::string::npos &&
                      bounded30.cil.find("canbus") == std::string::npos &&
                      bounded30.cil.find("_28_0") == std::string::npos &&
                      bounded30.cil.find("; voyemu API30 bounded su\n(allow su present (file "
                                         "(read)))\n(allow su present (dir (search)))\n(allow su "
                                         "self (process (execmem)))\n(allow su system_data_file "
                                         "(file (relabelfrom)))\n") != std::string::npos,
              "API30 bounded su takes platform rules then vendor rules of the 30.0 mapping");
        // The NVRAM store needs no su right: su stays limited to the OEM rules in /data.
        check(bounded30.cil.find("system_data_root_file") == std::string::npos,
              "API30 bounded su gains no /data rule");
        bool wrong_api = false;
        try {
            apply_bounded_canbus_policy(29, cil, map, vendor);
        } catch (...) {
            wrong_api = true;
        }

        check(wrong_api, "only API 28 and 30 policies can be bounded");
        check(rejects("unknown", 28, ""), "unknown policy transform rejected");
        std::cout << "five native SELinux file recipes passed\n";

        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';

        return 1;
    }
}
