import { test } from "node:test";
import assert from "node:assert/strict";
import { linkLibraries, resolversFor, basename, type LibDescriptor } from "../src/core/analysis/link";
import { scoreMrpc, MRPC_STR, mrpcVerdict, structuralMrpcRole } from "../src/core/analysis/mrpc";

const d = (o: Partial<LibDescriptor> & { soname: string }): LibDescriptor => ({
  name: o.name ?? o.soname, soname: o.soname, arch: o.arch ?? "arm64",
  exports: o.exports ?? [], imports: o.imports ?? [], needed: o.needed ?? [],
  refStrings: o.refStrings ?? [], dynLoader: o.dynLoader ?? false, detStrings: o.detStrings ?? [],
});

test("Link: symbol resolution, NEEDED, dlopen edges and shared detections", () => {
  const libs = [
    d({ soname: "libUE4.so", imports: ["ACE_Init", "GetEmulatorName", "memcpy"], needed: ["libanogs.so", "libc.so"], refStrings: ["libtersafe.so"], dynLoader: true, detStrings: ["IsEmulator", "ro.product.model"] }),
    d({ soname: "libanogs.so", exports: ["ACE_Init", "ACE_Report"], imports: ["memcpy"], detStrings: ["IsEmulator", "/proc/self/maps"] }),
    d({ soname: "libtersafe.so", exports: ["ts_scan"], imports: ["ptrace"], detStrings: ["ro.product.model"] }),
  ];
  const g = linkLibraries(libs);
  const sym = g.edges.find((e) => e.via === "symbol" && e.from === "libUE4.so" && e.to === "libanogs.so");
  assert.ok(sym, "libUE4 must resolve ACE_Init from libanogs");
  assert.deepEqual(sym!.symbols, ["ACE_Init"]);
  // memcpy is not exported by any loaded lib → unresolved, not an edge.
  assert.ok(!g.edges.some((e) => e.symbols.includes("memcpy")));
  assert.ok(g.unresolved.find((u) => u.lib === "libUE4.so")!.sample.includes("memcpy"));
  // DT_NEEDED naming a loaded lib is an edge; libc.so (not loaded) is not.
  assert.ok(g.edges.some((e) => e.via === "needed" && e.from === "libUE4.so" && e.to === "libanogs.so"));
  assert.ok(!g.edges.some((e) => e.to === "libc.so"));
  // dlopen: libUE4 names libtersafe as a string and imports dlopen → strong edge.
  const dl = g.edges.find((e) => e.via === "dlopen" && e.to === "libtersafe.so");
  assert.ok(dl && dl.count === 2, JSON.stringify(dl));
  // Shared detections: "IsEmulator" in UE4+anogs, "ro.product.model" in UE4+tersafe.
  assert.deepEqual(g.sharedDetections.find((s) => s.value === "IsEmulator")!.libs.sort(), ["libUE4.so", "libanogs.so"]);
  assert.ok(g.sharedDetections.some((s) => s.value === "ro.product.model"));
  // resolversFor: focused lib's imports mapped to their provider.
  const r = resolversFor("libUE4.so", libs);
  assert.equal(r.get("ACE_Init"), "libanogs.so");
  assert.equal(r.get("memcpy"), undefined);
  assert.equal(basename("C:\\x\\y\\libUE4.so"), "libUE4.so");
});

test("Link: a self-export never resolves its own import, no self-edges", () => {
  const libs = [d({ soname: "a.so", exports: ["f"], imports: ["f"] })];
  const g = linkLibraries(libs);
  assert.equal(g.edges.length, 0);
  assert.equal(g.unresolved[0].sample[0], "f"); // undefined-and-defined in the same lib is still an unmet cross-lib import
});

test("MRPC: scorer needs an anchor plus a mechanism; classifies roles and neutralisation", () => {
  // Lone config string is not an engine.
  assert.equal(scoreMrpc({ strings: ["config"], imports: [], callees: [], hasLoop: false, branches: 0, stores: 0, indirectCalls: 0 }), null);
  // No rule vocabulary at all → null.
  assert.equal(scoreMrpc({ strings: ["hello", "world"], imports: ["curl_easy_perform"], callees: [], hasLoop: true, branches: 5, stores: 3, indirectCalls: 0 }), null);
  // Downloader: rule strings + network.
  const dl = scoreMrpc({ strings: ["cloud_control rule download", "https://api.example/v1/rule"], imports: ["curl_easy_perform", "SSL_read"], callees: [], hasLoop: true, branches: 3, stores: 2, indirectCalls: 0 });
  assert.ok(dl && dl.role === "downloader" && dl.legs.includes("download:network"), JSON.stringify(dl));
  assert.match(dl!.how, /Starve it/);
  // Parser: rule strings + json parse, no network/file.
  const ps = scoreMrpc({ strings: ["ruleset", "rule.json"], imports: [], callees: ["cJSON_Parse", "nlohmann_parse"], hasLoop: true, branches: 4, stores: 2, indirectCalls: 0 });
  assert.ok(ps && (ps.role === "downloader" || ps.role === "parser"), JSON.stringify(ps)); // rule.json triggers file leg → downloader; both acceptable
  // Dispatcher: rule id + many indirect calls.
  const dp = scoreMrpc({ strings: ["rule_id handler", "policy"], imports: [], callees: [], hasLoop: true, branches: 6, stores: 2, indirectCalls: 4 });
  assert.ok(dp && dp.role === "dispatcher" && dp.legs.some((l) => l.startsWith("dispatch:")), JSON.stringify(dp));
  // Proof level scales with legs.
  const strong = scoreMrpc({ strings: ["cloud rule blacklist", "https://x/rule.json"], imports: ["curl_easy_perform", "cJSON_Parse", "SHA256"], callees: ["apply_rule"], hasLoop: true, branches: 5, stores: 3, indirectCalls: 0 });
  assert.ok(strong && strong.proofLevel === "proven", JSON.stringify(strong));
  // Anchor vocabulary matches the real PUBGM-style tells and rejects innocents.
  for (const s of ["cloud_control", "ruleset version", "blacklist", "规则下发", "灰度", "config.json", "feature_toggle", "hotupdate"]) assert.ok(MRPC_STR.test(s), `missed: ${s}`);
  // The literal ACE/anogs MRPCS subsystem vocabulary + snake_case rules (the libanogs miss).
  for (const s of ["mrpcs_download_data_thread_start_failed!", "MRPCS_ANDROID", "mrpcs_lib", "SetDownloadConfig", "rule_exe_fail", "rule_op_is_change", "cloud_feature.xml", "XCLOUD_VERSION_ACE_7.7", "REMOTECONFIG"]) assert.ok(MRPC_STR.test(s), `missed mrpcs vocab: ${s}`);
  for (const s of ["configure the camera", "moleculer", "capture", "PlayerController", "vmprotect", "ruler"]) assert.ok(!MRPC_STR.test(s), `false MRPC hit: ${s}`);
  // Strong-anchor lead: a specific mrpcs string alone (obfuscated code, no mechanism leg) still surfaces, with role inferred from the string.
  const leadDl = scoreMrpc({ strings: ["mrpcs_download_data_thread_start_failed!"], imports: [], callees: [], hasLoop: false, branches: 0, stores: 0, indirectCalls: 0 });
  assert.ok(leadDl && leadDl.proofLevel === "lead" && leadDl.role === "downloader", JSON.stringify(leadDl));
  const leadPs = scoreMrpc({ strings: ["mrpcs_data_crc_error", "mrpcs_data_len_error"], imports: [], callees: [], hasLoop: false, branches: 0, stores: 0, indirectCalls: 0 });
  assert.ok(leadPs && leadPs.role === "parser", JSON.stringify(leadPs));
  const leadAp = scoreMrpc({ strings: ["rule_exe_fail", "rule_op_is_change"], imports: [], callees: [], hasLoop: false, branches: 0, stores: 0, indirectCalls: 0 });
  assert.ok(leadAp && leadAp.role === "applier", JSON.stringify(leadAp));
  // A generic non-specific anchor with no mechanism is still rejected (no strong anchor).
  assert.equal(scoreMrpc({ strings: ["feature_toggle"], imports: [], callees: [], hasLoop: false, branches: 0, stores: 0, indirectCalls: 0 }), null);
  // Orchestrator: no own anchor, but drives ≥2 mrpcs helpers → dispatcher.
  const orch = scoreMrpc({ strings: ["mrpcs_download_data_thread_start_failed!", "mrpcs_data_crc_error"], imports: ["memset"], callees: [], hasLoop: true, branches: 40, stores: 30, indirectCalls: 4, helperCalls: 3 });
  assert.ok(orch && orch.role === "dispatcher" && orch.legs.some((l) => l.startsWith("orchestrates:")), JSON.stringify(orch));
  // Verdicts.
  assert.match(mrpcVerdict([], false), /No downloaded-rule engine/);
  assert.match(mrpcVerdict([{ addr: 0x1000, name: "sub_1000", role: "downloader", confidence: 0.8, proofLevel: "proven", legs: ["download:network"], strings: ["cloud rule"], imports: [], how: "x" }], true), /SERVER-FED.*starve/s);
});

test("MRPC: structural scorer finds string-less parser/dispatcher/applier (no hasLoop requirement — flattened code)", () => {
  const base = { hasLoop: false, loadCount: 0, storeCount: 0, branchCount: 0, callCount: 0, size: 800 };
  // Parser: dense byte-extraction + compares + loads, no loop (flattened), no strings.
  const p = structuralMrpcRole({ ...base, mnemonicHist: { ldrb: 6, ubfx: 2, cmp: 5 }, loadCount: 40 });
  assert.ok(p && p.role === "parser", JSON.stringify(p));
  // Dispatcher: heavy indirect calls (rule id → handler pointer).
  const d = structuralMrpcRole({ ...base, mnemonicHist: { blr: 4, cmp: 2 }, loadCount: 10 });
  assert.ok(d && d.role === "dispatcher", JSON.stringify(d));
  // Applier: many stores behind many branches.
  const a = structuralMrpcRole({ ...base, mnemonicHist: { cmp: 5 }, storeCount: 14, branchCount: 10, loadCount: 12 });
  assert.ok(a && a.role === "applier", JSON.stringify(a));
  // A plain accessor is not a rule-engine shape.
  assert.equal(structuralMrpcRole({ ...base, mnemonicHist: { ldr: 2, ret: 1 }, loadCount: 2 }), null);
});
