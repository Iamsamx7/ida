import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, type FunctionContext } from "../src/core/analysis/semantic/rules";
import { DETECTION_LABELS } from "../src/core/analysis/semantic/securityRules";
import { parseIntent } from "../src/ai/retrieval";

function context(calls: string[] = [], strings: string[] = []): FunctionContext {
  return { addr: 0x1000, name: "sub_1000", size: 128, calleeNames: calls, callerNames: [], importsAll: new Set(),
    stringValues: strings.map((value, i) => ({ addr: 0x2000 + i * 256, value, category: "generic" })),
    features: { mnemonicHist: { ret: 1 }, constants: [], stringRefs: [], callees: [], importCalls: calls, branchCount: 0, callCount: calls.length, loadCount: 0, storeCount: 0, memAccessOffsets: [], hasLoop: false, fingerprint: "test" } };
}
const result = (ctx: FunctionContext, label: string) => classify(ctx).find((c) => c.label === label);
const cases: [string, string[], string[]][] = [
  ["debugger-detection", ["fopen", "fgets"], ["/proc/self/status", "TracerPid:"]],
  ["root-detection", ["access"], ["/system/xbin/su"]],
  ["emulator-detection", ["__system_property_get"], ["ro.kernel.qemu"]],
  ["instrumentation-detection", ["strstr", "dl_iterate_phdr"], ["frida-agent"]],
  ["process-inspection", ["openat"], ["/proc/self/maps"]],
  ["tls-verification", ["SSL_get_verify_result"], []],
  ["certificate-pinning", ["CRYPTO_memcmp"], ["certificate pinning"]],
  ["signature-verification", ["EVP_DigestVerifyFinal"], []],
  ["memory-permission-change", ["mprotect"], []],
  ["secure-random", ["getrandom"], []],
  ["secure-erasure", ["explicit_bzero"], []],
  ["native-registration", ["RegisterNatives"], []],
];
for (const [label, calls, strings] of cases) test(`Detections: ${label} reports function-local evidence`, () => {
  const hit = result(context(calls, strings), label);
  assert.ok(hit, `${label} missing`); assert.ok(hit.confidence >= 0.55);
  assert.ok(hit.evidence.length > 0); assert.ok(hit.evidence.every((e) => e.address !== undefined));
});
test("Detections: catalog covers every positive case", () => {
  assert.deepEqual(new Set(cases.map(([label]) => label)), new Set(DETECTION_LABELS));
});
test("Detections: repeated xrefs, duplicate imports and symbol versions do not inflate confidence", () => {
  const one = result(context(["strstr"], ["frida-agent"]), "instrumentation-detection")!;
  const repeated = result(context(["strstr@plt", "strstr@GLIBC_2.17", "strstr"], Array(20).fill("frida-agent")), "instrumentation-detection")!;
  assert.equal(one.confidence, repeated.confidence);
  assert.equal(result(context(["SSL_get_verify_result@OPENSSL_3.0.0"]), "tls-verification")?.confidence, result(context(["SSL_get_verify_result"]), "tls-verification")?.confidence);
});
test("Detections: markers alone are leads and unrelated global imports cannot corroborate them", () => {
  for (const [label, calls, strings] of cases.filter(([, , s]) => s.length)) {
    const ctx = context([], strings); ctx.importsAll = new Set(calls);
    const hit = result(ctx, label)!;
    assert.ok(hit); assert.ok(hit.confidence < 0.35); assert.match(hit.evidence[0].text, /String-only lead/);
  }
});
test("Detections: generic Android properties, root UI names, GLib loops and ordinary TLS are not specific checks", () => {
  const ctx = context(["__system_property_get", "fopen", "strstr", "SSL_connect", "memcmp", "memset", "rand"], ["ro.product.model", "RootComponent", "root directory", "VolumeMultiplier", "WorldPlayer", "gmain", "https://example.com", "certificate chain", "signature banner"]);
  assert.deepEqual(classify(ctx).filter((c) => (DETECTION_LABELS as readonly string[]).includes(c.label)), []);
});
test("Detections: marker boundaries and API boundaries exclude look-alike symbols", () => {
  assert.equal(result(context(["access"], ["/system/xbin/sushi"]), "root-detection"), undefined);
  assert.equal(result(context(["SSL_get_verify_result_logger"]), "tls-verification"), undefined);
  assert.equal(result(context(["my_mprotect_wrapper"]), "memory-permission-change"), undefined);
  assert.equal(result(context(["open"], ["/proc/self/maps_backup"]), "process-inspection"), undefined);
});
test("Detections: broad classifications cannot displace specific findings", () => {
  const ctx = context(["malloc", "free", "memcpy", "memset", "fopen", "fclose", "printf", "puts", "socket", "send", "SHA256", "HMAC", "getrandom"]);
  const hits = classify(ctx);
  assert.ok(hits.length > 5); assert.ok(hits.find((h) => h.label === "secure-random"));
});
test("Detections: API observations do not claim enabled TLS, executable memory or successful verification", () => {
  assert.match(result(context(["mprotect"]), "memory-permission-change")!.evidence[0].text, /not inferred/);
  assert.match(result(context(["SSL_set_verify"]), "tls-verification")!.evidence[0].text, /does not prove/);
  assert.match(result(context(["RSA_verify"]), "signature-verification")!.evidence[0].text, /handling still needs inspection/);
});
test("Detections: AI routes focused detector queries and keeps current-function explanations", () => {
  assert.deepEqual(parseIntent("find root detection"), { kind: "semantic-search", query: "root-detection" });
  assert.deepEqual(parseIntent("show me certificate pinning"), { kind: "semantic-search", query: "certificate-pinning" });
  assert.equal(parseIntent("explain this root detection function").kind, "explain");
});
