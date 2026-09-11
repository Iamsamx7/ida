/**
 * Real-binary smoke run: parse + full single-thread analysis over one or more
 * ELF files given on the command line, printing counts, warnings and timings.
 * Throws (non-zero exit) if any stage raises.
 *   npx tsx tests/real.ts path/to/lib.so [more.so ...]
 */
import { readFileSync } from "node:fs";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { extractFeatures } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { collectGlobals, inferStructures } from "../src/core/analysis/structures";
import { generatePseudocode } from "../src/core/analysis/pseudocode";
import { search } from "../src/core/search/engine";
import { buildIntel } from "../src/core/analysis/intel";
import { planBypass } from "../src/core/analysis/bypass";
import { analyzePasted } from "../src/core/analysis/verify";
import { LocalAssistant } from "../src/ai/assistant";
import { buildLlmContext } from "../src/ai/context";

async function main() {
for (const path of process.argv.slice(2)) {
  const bytes = new Uint8Array(readFileSync(path));
  const t0 = performance.now();
  const elf = parseElf(bytes);
  const t1 = performance.now();
  const arch = getArchitecture(elf.header.arch);
  console.log(`\n== ${path} (${(bytes.length / 1048576).toFixed(1)} MB) ${elf.header.machineName} ELF${elf.header.elfClass} ${elf.header.littleEndian ? "LE" : "BE"}`);
  console.log(`   parse ${(t1 - t0).toFixed(0)} ms · ${elf.sections.length} sections · ${elf.segments.length} segments · ${elf.symbols.length} symbols · ${elf.imports.length} imports · ${elf.exports.length} exports · ${elf.relocations.length} relocs (${elf.relocations.filter((r) => r.typeName === "RELR_RELATIVE").length} RELR) · gnuhash=${elf.hasGnuHash} sysv=${elf.hasSysvHash} · init=${elf.initArray.length} · stripped=${elf.stripped}`);
  for (const w of elf.warnings.slice(0, 10)) console.log(`   [${w.level}] ${w.message}`);
  if (!arch) continue;
  const db = new AnalysisDatabase(elf, bytes, arch, path);
  console.log(`   plt stubs named: ${db.pltNames.size}`);
  const strRanges = elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0);
  const raw = strRanges.flatMap((s) => scanStrings(bytes, s.offset, s.addr, s.size));
  db.setStrings(toRecords(raw));
  const t2 = performance.now();
  const chunks: ReturnType<typeof scanCodeChunk>[] = [];
  let i = 0;
  for (const r of db.space.codeRanges()) {
    const CH = 512 * 1024;
    for (let o = 0; o < r.size; o += CH) chunks.push(scanCodeChunk(arch, bytes, r.offset + o, r.vaddr + o, Math.min(CH, r.size - o), elf.header.littleEndian, i++, o === 0));
  }
  const t3 = performance.now();
  const res = discoverFunctions(db, chunks);
  db.setFunctions(res.functions);
  db.memAccess = res.memAccess;
  db.immediates = res.immediates;
  db.setXrefs(res.xrefs);
  const t4 = performance.now();
  const insns = chunks.reduce((a, c) => a + c.insnCount, 0);
  const unknown = chunks.reduce((a, c) => a + c.unknownCount, 0);
  console.log(`   scan ${(t3 - t2).toFixed(0)} ms (${insns} insns, ${unknown} unknown = ${((unknown / Math.max(1, insns)) * 100).toFixed(2)}%) · discovery ${(t4 - t3).toFixed(0)} ms · ${db.functions.length} functions (${db.functions.filter((f) => f.sources.includes("symbol")).length} sym) · ${db.xrefs.count} xrefs · ${db.strings.length} strings`);
  const importsAll = new Set(elf.imports.map((x) => x.name));
  let classified = 0;
  const t5 = performance.now();
  for (const f of db.functions.slice(0, 3000)) {
    if (f.isImportStub) continue;
    f.features = extractFeatures(db, f);
    f.classes = classify({ addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: f.features.callees.map((c) => db.nameFor(c).name), callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)!).filter(Boolean).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll });
    if (f.classes.length) classified++;
  }
  const t6 = performance.now();
  const structs = inferStructures(db);
  const globals = collectGlobals(db);
  let pseudoLines = 0;
  for (const f of db.functions.slice(0, 500)) pseudoLines += generatePseudocode(db, f).length;
  const hits = search(db, "init");
  console.log(`   semantic(3000) ${(t6 - t5).toFixed(0)} ms · ${classified} classified · ${structs.length} structs · ${globals.length} globals · pseudocode(500) ${pseudoLines} lines · search 'init' ${hits.length} hits`);
  const sample = db.functions.filter((f) => !f.isImportStub).slice(0, 3);
  for (const f of sample) console.log(`   ${f.name} @0x${f.addr.toString(16)} size=${f.size} conf=${f.confidence.toFixed(2)} [${f.sources.join(",")}] ${f.classes?.[0] ? f.classes[0].label + " " + f.classes[0].level : ""}`);
  // ---- AI layer on the real binary: intel proof bar, assistant routing, LLM context size.
  const t7 = performance.now();
  const intel = buildIntel(db, 12);
  const byLevel = (l: string) => intel.findings.filter((f) => f.proofLevel === l).length;
  console.log(`   intel ${(performance.now() - t7).toFixed(0)} ms: ${intel.findings.length} findings — ${byLevel("proven")} proven · ${byLevel("corroborated")} corroborated · ${byLevel("lead")} lead${intel.packedSuspect ? " · PACKED SUSPECT" : ""}`);
  for (const f of intel.findings.slice(0, 5)) console.log(`     ${f.proofLevel.toUpperCase().padEnd(12)} ${f.kind.padEnd(11)} ${f.name}@0x${f.addr.toString(16)} ${Math.round(f.confidence * 100)}% legs=${f.legs.join(" + ")}`);
  const t8 = performance.now();
  buildIntel(db, 6);
  console.log(`   intel cached view ${(performance.now() - t8).toFixed(1)} ms`);
  const index = new Map<number, string>();
  for (const f of db.functions) if (f.features) index.set(f.addr, [f.name, ...(f.classes ?? []).map((c) => c.label), ...f.features.importCalls, ...f.features.stringRefs.slice(0, 8).map((a) => db.stringAt(a)?.value.slice(0, 40) ?? "")].join(" ").toLowerCase());
  const ai = new LocalAssistant(db, index);
  const target = db.functions.find((f) => !f.isImportStub && f.features && f.size > 64)?.addr ?? null;
  const t9 = performance.now();
  const qs: [string, number | null][] = [["Where is anticheat?", null], ["Where is memcpy used?", null], ["What does this function do?", target], ["show me where the player state is read", null], ["what does this hash function do?", target], ["recon", null]];
  for (const [q, at] of qs) {
    const a = ai.answer(q, at);
    console.log(`   ai “${q}” → ${a.intent} · ${a.verdict ?? "-"} · ${a.evidence.length} evidence · ${a.related.length} related${a.actions ? ` · ${a.actions.length} actions` : ""}`);
  }
  const explain = ai.answer("What does this function do?", target);
  const ctx = buildLlmContext(db, explain, target);
  console.log(`   assistant ${qs.length + 1} questions in ${(performance.now() - t9).toFixed(0)} ms · LLM context ${ctx.length} chars`);
  // ---- Bypass planner + its own autopsy: the plan's PATCH/HOOK lines must pass the analyzer.
  const t10 = performance.now();
  const plan = await planBypass(db);
  const planLines = plan.steps.flatMap((s) => [s.patchLib, ...(s.hookLib ? s.hookLib.split("\n").filter((l) => /^HOOK_LIB/.test(l)) : [])]).filter((l) => l && !l.startsWith("//"));
  const self = planLines.length ? analyzePasted(db, planLines.join("\n")) : null;
  const cnt = (st: string) => plan.steps.filter((s) => s.safety === st).length;
  console.log(`   bypass plan ${(performance.now() - t10).toFixed(0)} ms: ${plan.steps.length} steps (${cnt("SAFE")} SAFE · ${cnt("RISKY")} RISKY) · ${plan.blocked.length} blocked · ${plan.coverage.branches} branch flips · ${plan.coverage.consumers} consumer traps${self ? ` · self-check ${self.items.length} lines: ${self.items.filter((v) => v.status === "UNSAFE").length} UNSAFE · ${self.items.filter((v) => v.status === "RISKY").length} RISKY` : ""}`);
  console.log(`   MRPC: ${plan.mrpc.count} rule-engine routine(s)${plan.mrpc.count ? ` (${plan.mrpc.networkBacked ? "server-fed" : "bundled"}) · ${plan.steps.filter((s) => s.identity.startsWith("mrpc ·")).length} neutralise step(s) → ${plan.mrpc.findings.slice(0, 3).map((f) => `${f.role} ${f.name}@0x${f.addr.toString(16)}`).join(", ")}` : " — none"}`);
  for (const v of self?.items.filter((x) => x.status === "UNSAFE").slice(0, 3) ?? []) console.log(`     UNSAFE ${v.item.raw.slice(0, 70)} — ${v.checks.filter((c) => !c.pass).map((c) => c.detail.slice(0, 80)).join(" | ")}`);
  for (const s of plan.steps.filter((x) => x.action === "patch-branch").slice(0, 3)) console.log(`     branch ${s.safety} ${s.targetName}@0x${s.address.toString(16)} :: ${s.detail.replace(/\s+/g, " ").slice(0, 200)}`);
  for (const s of plan.steps.filter((x) => x.action === "patch-consumer").slice(0, 2)) console.log(`     consumer ${s.safety} ${s.title.slice(0, 80)} :: ${s.origBytes}`);
  for (const b of plan.blocked.slice(0, 3)) console.log(`     blocked ${b.target}@0x${b.addr.toString(16)} — ${b.reason.slice(0, 100)}`);
}
}
main().catch((e) => { console.error(e); process.exit(1); });
