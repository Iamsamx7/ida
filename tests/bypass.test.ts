import { test } from "node:test";
import assert from "node:assert/strict";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { extractFeatures } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { planBypass, planWorkspace, stepSurface, huntVerdictBranches, huntConsumerTrap, prologuePatchLib, branchFlipLib, fridaHook, fridaSpoof, isHeartbeat, selfInspectionHit, flipBranchWord, prologueWords, emulatorVerdict, type BypassStep } from "../src/core/analysis/bypass";
import { analyzePasted, parsePatchLines } from "../src/core/analysis/verify";
import { EMU_MARKER_RE, EMU_VERDICT_RE } from "../src/core/analysis/intel";
import { ANTI_TAMPER_STR, BAN_STR } from "../src/core/analysis/semantic/rules";
import { buildMrpcReport } from "../src/core/analysis/mrpc";
import { libDescriptor, linkLibraries, type LibDescriptor } from "../src/core/analysis/link";
import { buildSampleSo } from "./fixtures/elfBuilder";

const sample = buildSampleSo();
function setup() {
  const elf = parseElf(sample.bytes);
  const arch = getArchitecture(elf.header.arch)!;
  const db = new AnalysisDatabase(elf, sample.bytes, arch, "libsample.so");
  db.setStrings(toRecords(elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0).flatMap((s) => scanStrings(sample.bytes, s.offset, s.addr, s.size))));
  const chunks = db.space.codeRanges().map((r, i) => scanCodeChunk(arch, sample.bytes, r.offset, r.vaddr, r.size, true, i, true));
  const r = discoverFunctions(db, chunks);
  db.setFunctions(r.functions); db.memAccess = r.memAccess; db.immediates = r.immediates; db.setXrefs(r.xrefs);
  const importsAll = new Set(elf.imports.map((i) => i.name));
  for (const f of db.functions) {
    f.features = extractFeatures(db, f);
    f.classes = classify({ addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: f.features.callees.map((c) => db.nameFor(c).name), callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)!).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll });
  }
  return { db };
}

test("Bypass: verdict hunt skips loop back-edges and names the dirty side", () => {
  const { db } = setup();
  const hb = huntVerdictBranches(db, sample.addrs.hash_buffer);
  // hash_buffer: forward `cbz x1` (length check) is a verdict candidate; the `b.ne loop` back-edge never is.
  assert.ok(hb.every((b) => !b.text.startsWith("b.ne")), `loop guard listed as verdict: ${hb.map((b) => b.text).join(" | ")}`);
  assert.ok(hb.some((b) => b.text.startsWith("cbz")), hb.map((b) => b.text).join(" | "));
  // net_send: `cmp x0,#0; b.ge skip` — the fall-through loads the error string, so that is the dirty side.
  const ns = huntVerdictBranches(db, sample.addrs.net_send);
  assert.equal(ns.length, 1, JSON.stringify(ns));
  assert.equal(ns[0].dirtySide, "fallthrough");
  assert.match(ns[0].why, /fed by cmp .* 1 insn\(s\) earlier/);
  assert.match(ns[0].why, /error: world state/);
  assert.match(ns[0].flipHint, /fall-through \(punish\) path is skipped/);
  // lib_init calls hash_buffer and never judges the result — no consumer trap.
  assert.equal(huntConsumerTrap(db, sample.addrs.lib_init, sample.addrs.hash_buffer), null);
});

test("Bypass: prologue patch keeps a BTI landing pad on PAC/BTI entries; flips refuse B.AL", () => {
  const { db } = setup();
  const pac = prologuePatchLib(db, sample.addrs.lib_init); // entry is paciasp
  assert.ok(pac.ok && pac.landingKept, JSON.stringify(pac));
  assert.match(pac.line, /"9F 24 03 D5 00 00 80 D2 C0 03 5F D6"/);
  assert.match(pac.altLine, /9F 24 03 D5 20 00 80 D2 C0 03 5F D6/);
  assert.equal(pac.origWords.length, 3);
  const plain = prologuePatchLib(db, sample.addrs.world_state_reader); // entry is adrp
  assert.ok(plain.ok && !plain.landingKept);
  assert.match(plain.line, /"00 00 80 D2 C0 03 5F D6"/);
  assert.deepEqual(plain.words, [0xd2800000, 0xd65f03c0]);
  // net_send's b.ge flips to b.lt; a non-branch word is refused with its encoding named.
  const brAddr = huntVerdictBranches(db, sample.addrs.net_send)[0].addr;
  const flip = branchFlipLib(db, brAddr);
  assert.ok(flip.ok && flip.origWord !== null && flip.flippedWord === (flip.origWord ^ 1));
  const notBranch = branchFlipLib(db, sample.addrs.hash_buffer);
  assert.ok(!notBranch.ok && /not a flippable/.test(notBranch.note));
  assert.equal(isHeartbeat({ hasLoop: true }, ["strftime", "localtime"]), false);
  assert.equal(isHeartbeat({ hasLoop: true }, ["clock_gettime"]), true);
  assert.equal(selfInspectionHit(["message.text"], ["fopen"]), null);
  assert.match(selfInspectionHit(["/proc/self/maps"], ["fopen"]) ?? "", /fopen/);
});

test("Bypass: plan is self-consistent — unique ids, no self-requires, real Frida, its own lines pass the analyzer", async () => {
  const { db } = setup();
  const plan = await planBypass(db, undefined, { includeGameRevive: true });
  assert.ok(plan.steps.length >= 2, `expected steps for hash_buffer, got ${plan.steps.length}`);
  const ids = plan.steps.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate step ids");
  for (const s of plan.steps) {
    assert.ok(!s.requires.some((r) => r.startsWith(s.id)), `${s.id} requires itself: ${s.requires.join(" | ")}`);
    assert.doesNotMatch(s.frida, /findBasePoint|Module\.findBaseAddress|Module\.findExportByName\(/);
  }
  for (const s of plan.steps.filter((x) => x.action === "hook-entry")) assert.match(s.frida, /Process\.findModuleByName\("libsample\.so"\)/);
  for (const s of plan.steps.filter((x) => x.action === "patch-prologue-ret" && x.safety !== "BLOCKED")) {
    assert.match(s.frida, /Memory\.patchCode\(addr, (8|12)/);
    assert.ok(s.patchLibAlt && /20 00 80 D2/.test(s.patchLibAlt), "alt (return 1) line missing");
  }
  for (const s of plan.steps.filter((x) => x.action === "patch-branch" && x.safety === "SAFE")) assert.match(s.frida, /Memory\.patchCode\(addr, 4/);
  // Every PATCH_LIB / HOOK_LIB the planner emits must survive its own analyzer.
  const lines = plan.steps.flatMap((s) => [s.patchLib, s.patchLibAlt ?? "", ...(s.hookLib ? s.hookLib.split("\n").filter((l) => /^HOOK_LIB/.test(l)) : [])]).filter((l) => l && !l.startsWith("//"));
  assert.ok(lines.length > 0);
  const rep = analyzePasted(db, lines.join("\n"));
  const unsafe = rep.items.filter((v) => v.status === "UNSAFE");
  assert.equal(unsafe.length, 0, unsafe.map((u) => `${u.item.raw}: ${u.checks.filter((c) => !c.pass).map((c) => c.detail).join(" | ")}`).join("\n"));
  // Snippets are block-scoped, so concatenating them is valid JS.
  const joined = plan.steps.map((s) => s.frida).join("\n") + fridaSpoof([["ro.product.model", "Pixel 8"]], ["/dev/qemu_pipe"]) + fridaHook("libsample.so", "x", 0x10, "0");
  assert.doesNotThrow(() => new Function(joined));
});

test("Verify: parses mod-menu formats, catches mid-function hooks, PC-relative bytes, overlaps, collisions and lost landing pads", () => {
  const { db } = setup();
  const hb = sample.addrs.hash_buffer, li = sample.addrs.lib_init;
  const text = [
    `MemoryPatch::createWithHex("libsample.so", 0x${hb.toString(16)}, "00 00 80 D2 C0 03 5F D6");`,
    `PATCH_SWITCH("libsample.so","0x${hb.toString(16)}","C0 03 5F D6");`,
    `{"0x${li.toString(16)}", "1F 20 03 D5"},`,
    `HOOK_LIB("libsample.so","0x${(li + 8).toString(16)}",(void *)hook_x,(void **)&orig_x);`,
    `HOOK_LIB("libsample.so","0x${li.toString(16)}",(void *)hook_y,(void **)&orig_y);`,
  ].join("\n");
  const { items, errors } = parsePatchLines(text);
  assert.deepEqual(errors, []);
  assert.deepEqual(items.map((i) => i.format), ["KittyMemory", "PATCH_SWITCH", "pair", "HOOK_LIB", "HOOK_LIB"]);
  assert.equal(items[3].hookName, "hook_x");
  const rep = analyzePasted(db, text);
  const failed = (v: (typeof rep.items)[number], label: string) => v.checks.find((c) => c.label === label && !c.pass);
  // two patches on hash_buffer's entry overlap
  assert.ok(failed(rep.items[0], "Overlap") && failed(rep.items[1], "Overlap"));
  assert.match(rep.items[0].checks.find((c) => c.label === "Bytes mean")!.detail, /MOV X0,#0; RET/);
  // NOP over paciasp at lib_init's entry drops the landing pad; the hook on the same entry collides with it
  assert.ok(failed(rep.items[2], "Landing pad"));
  assert.ok(failed(rep.items[2], "Collision") && failed(rep.items[4], "Collision"));
  // mid-function hook
  assert.equal(rep.items[3].status, "RISKY");
  assert.match(failed(rep.items[3], "Hook point")!.detail, /mid-function/);
  // PC-relative bytes copied blindly: B +4 at a non-branch site
  const rel = analyzePasted(db, `PATCH_LIB("libsample.so","0x${hb.toString(16)}","01 00 00 14");`);
  assert.ok(failed(rel.items[0], "Position"));
  assert.equal(rel.items[0].status, "RISKY");
  // the planner's computed flip is PC-relative by nature and must NOT be flagged
  const brAddr = huntVerdictBranches(db, sample.addrs.net_send)[0].addr;
  const flipLine = branchFlipLib(db, brAddr).line;
  const ok = analyzePasted(db, flipLine);
  assert.ok(!failed(ok.items[0], "Position") && !failed(ok.items[0], "Branch flip"), JSON.stringify(ok.items[0].checks));
  // wrong library and unmapped offset are UNSAFE
  const bad = analyzePasted(db, `PATCH_LIB("libanogs.so","0x1000","C0 03 5F D6");\nPATCH_LIB("libsample.so","0xDEAD0000","C0 03 5F D6");`);
  assert.deepEqual(bad.items.map((v) => v.status), ["UNSAFE", "UNSAFE"]);
  assert.equal(bad.overall, "UNSAFE");
});

test("Bypass: ARM32 templates, emulator vocabulary boundaries, emulator verdict text", () => {
  // ARM (A32) B<cond> flips toggle bit 28: BEQ (0x0a……) ↔ BNE (0x1a……); B (AL) and non-branches are refused.
  assert.deepEqual(flipBranchWord("arm32", 0x0a000005), { flipped: 0x1a000005, note: "" });
  assert.deepEqual(flipBranchWord("arm32", 0xba000005), { flipped: 0xaa000005, note: "" }); // BLT ↔ BGE
  assert.equal(flipBranchWord("arm32", 0xea000005).flipped, null);
  assert.equal(flipBranchWord("arm32", 0xe3a00000).flipped, null);
  assert.equal(flipBranchWord("arm32", 0x0b000005).flipped, null); // BL<cond> is a call, not a verdict
  assert.deepEqual(prologueWords("arm32", false, 0), { words: [0xe3a00000, 0xe12fff1e], asm: "MOV R0,#0; BX LR" });
  assert.deepEqual(prologueWords("arm64", true, 1)?.words, [0xd503249f, 0xd2800020, 0xd65f03c0]);
  assert.equal(prologueWords("x86-64", false, 0), null);
  assert.equal(flipBranchWord("arm64", 0x54000000).flipped, 0x54000001); // B.EQ → B.NE
  assert.equal(flipBranchWord("arm64", 0x5400000e).flipped, null); // B.AL
  // UE4 names that used to be "emulator tells" and "anti-tamper" vocabulary.
  for (const s of ["AudioComponent.VolumeMultiplierMin", "MaxDynamicLoadingWorldPlayer", "OldPlayerState", "TimeMultiplier", "res_spelowmemui_"]) assert.ok(!EMU_MARKER_RE.test(s), `false emulator tell: ${s}`);
  for (const s of ["IsEmulator", "ro.product.model", "/dev/qemu_pipe", "/system/lib/libhoudini.so", "ro.dalvik.vm.native.bridge", "Indentify is running on game simulator", "MEmu"]) assert.ok(EMU_MARKER_RE.test(s), `missed emulator tell: ${s}`);
  for (const s of ["IsEmulator[ReturnValue:%d]", "GetEmulatorName() emulatorName = NoEmulator", "IsEmulatorWhenInit"]) assert.ok(EMU_VERDICT_RE.test(s), `missed verdict name: ${s}`);
  for (const s of ["RootComponent", "AntiAliasing", "Subsystem", "USTExtraPlayerController", "SimulatePhysics", "ro.product.model"]) assert.ok(!ANTI_TAMPER_STR.test(s) || s === "ro.product.model", `false anti-tamper hit: ${s}`);
  for (const s of ["/proc/self/maps", "TracerPid:", "su", "root detected", "anti-cheat init", "/proc/1234/maps"]) assert.ok(ANTI_TAMPER_STR.test(s), `missed anti-tamper: ${s}`);
  for (const s of ["SetBannerVisible", "Urban", "Bandwidth", "Abandon"]) assert.ok(!BAN_STR.test(s), `false ban hit: ${s}`);
  for (const s of ["You have been banned", "account banned", "ban reason"]) assert.ok(BAN_STR.test(s), `missed ban: ${s}`);
  // Verdict text covers all three situations.
  assert.match(emulatorVerdict({ markers: 0, sample: [], readers: [], propReaders: 0, consumers: [], spoofSteps: 0, consumerSteps: 0, verdict: "" }), /No emulator tells/);
  assert.match(emulatorVerdict({ markers: 5, sample: ["ro.product.model"], readers: [], propReaders: 0, consumers: [{ addr: 0x1000, name: "IsEmulator", strings: ["IsEmulator[ReturnValue:%d]"] }], spoofSteps: 0, consumerSteps: 1, verdict: "" }), /CONSUMES a verdict.*IsEmulator@0x1000/);
  assert.match(emulatorVerdict({ markers: 5, sample: ["ro.product.model"], readers: [], propReaders: 0, consumers: [], spoofSteps: 1, consumerSteps: 0, verdict: "" }), /floating.*catch-all prop spoof/s);
});

test("Bypass: the plan always carries an emulator report", async () => {
  const { db } = setup();
  const plan = await planBypass(db);
  assert.ok(plan.emulator);
  assert.equal(plan.emulator.markers, 0);
  assert.match(plan.emulator.verdict, /No emulator tells/);
  assert.ok(plan.thinking.some((t) => /^EMULATOR:/.test(t)));
});

test("Bypass: the plan carries an MRPC report; the sample has no rule engine", async () => {
  const { db } = setup();
  const rep = buildMrpcReport(db, 12);
  assert.equal(rep.count, 0);
  assert.match(rep.verdict, /No downloaded-rule engine/);
  const plan = await planBypass(db);
  assert.ok(plan.mrpc);
  assert.equal(plan.mrpc.count, 0);
  assert.ok(plan.thinking.some((t) => /^MRPC:/.test(t)));
  assert.ok(!plan.steps.some((s) => s.identity.startsWith("mrpc ·")));
});

test("Bypass: a workspace produces a cross-lib report; siblings resolve each other", async () => {
  const { db } = setup();
  const me = libDescriptor(db); // libsample.so
  // Synthetic sibling that exports one of libsample's imports (if any) and a security symbol it 'needs'.
  const sibling: LibDescriptor = {
    name: "libanogs.so", soname: "libanogs.so", arch: "arm64",
    exports: [...me.imports.slice(0, 1), "ACE_ScanTick"], imports: [], needed: [],
    refStrings: [], dynLoader: false, detStrings: me.detStrings.slice(0, 1),
  };
  const descriptors = [me, sibling];
  const link = linkLibraries(descriptors);
  const plan = await planBypass(db, undefined, { workspace: { descriptors, link } });
  assert.ok(plan.crossLib, "workspace plan must carry crossLib");
  assert.equal(plan.crossLib!.self, me.soname);
  assert.match(plan.crossLib!.note, /workspace/);
  // If libsample imports anything the sibling now exports, the dependency shows up.
  if (me.imports.length) assert.ok(plan.crossLib!.dependsOn.some((x) => x.lib === "libanogs.so"), JSON.stringify(plan.crossLib!.dependsOn));
  // Single-lib plans carry no crossLib.
  const solo = await planBypass(db);
  assert.equal(solo.crossLib, undefined);
});

test("Bypass: section scope filters hook surfaces; every step is stamped with its section", async () => {
  const { db } = setup();
  const auto = await planBypass(db);
  assert.ok(auto.steps.length > 0 && auto.steps.every((s) => typeof s.section === "string"), "every step must carry a section");
  // stepSurface mapping.
  const mk = (action: BypassStep["action"]) => ({ action }) as BypassStep;
  assert.equal(stepSurface(mk("hook-import")), "got");
  assert.equal(stepSurface(mk("patch-global")), "data");
  assert.equal(stepSurface(mk("hook-entry")), "text");
  assert.equal(stepSurface(mk("patch-branch")), "text");
  // .text-only keeps only text-surface steps.
  const textOnly = await planBypass(db, undefined, { scope: { text: true, got: false, data: false } });
  assert.ok(textOnly.steps.length > 0 && textOnly.steps.every((s) => stepSurface(s) === "text"));
  // .got-only drops the code steps (the sample has no .got security imports → fewer steps) and notes the scoping.
  const gotOnly = await planBypass(db, undefined, { scope: { text: false, got: true, data: false } });
  assert.ok(gotOnly.steps.every((s) => stepSurface(s) === "got"));
  assert.ok(gotOnly.steps.length < textOnly.steps.length, "restricting to .got must drop the .text steps");
  assert.ok(gotOnly.thinking.some((t) => /^SCOPE:/.test(t)));
});

test("Bypass: planWorkspace plans every lib and emits an apply order", async () => {
  const { db } = setup();
  const { db: db2 } = setup();
  db2.elf.soname = "libsibling.so"; // distinct identity so both appear in the workspace
  const ws = await planWorkspace([{ name: "libsample.so", db }, { name: "libsibling.so", db: db2 }]);
  assert.equal(ws.perLib.length, 2);
  assert.equal(ws.summary.libs, 2);
  assert.ok(ws.summary.steps > 0, "workspace should aggregate steps from both libs");
  assert.ok(ws.order.length > 0, "workspace must emit an apply order");
  assert.ok(ws.perLib.every((l) => !!l.plan.mrpc), "each per-lib plan carries its MRPC report");
  // No cross-imports between two copies of the sample → no chains, but plumbing holds.
  assert.equal(ws.chains.length, 0);
  assert.equal(ws.summary.providersMissing, 0);
});
