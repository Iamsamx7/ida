// Multi-library workspace + MRPC diagnostic. Fully analyzes each lib, links them,
// and plans the FIRST one inside the workspace so cross-lib annotations appear.
//   NODE_OPTIONS=--max-old-space-size=12288 npx tsx tests/diag-workspace.ts a.so b.so c.so
import { readFileSync } from "node:fs";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { extractFeatures } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { buildMrpcReport } from "../src/core/analysis/mrpc";
import { libDescriptor, linkLibraries } from "../src/core/analysis/link";
import { planBypass } from "../src/core/analysis/bypass";
import { analyzePasted } from "../src/core/analysis/verify";

const hex = (n: number) => "0x" + n.toString(16);
function analyze(path: string): AnalysisDatabase {
  const bytes = new Uint8Array(readFileSync(path));
  const elf = parseElf(bytes);
  const arch = getArchitecture(elf.header.arch)!;
  const db = new AnalysisDatabase(elf, bytes, arch, path.split(/[\\/]/).pop()!);
  db.setStrings(toRecords(elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0).flatMap((s) => scanStrings(bytes, s.offset, s.addr, s.size))));
  const chunks: ReturnType<typeof scanCodeChunk>[] = [];
  let ci = 0; const CH = 512 * 1024;
  for (const r of db.space.codeRanges()) for (let o = 0; o < r.size; o += CH) chunks.push(scanCodeChunk(arch, bytes, r.offset + o, r.vaddr + o, Math.min(CH, r.size - o), elf.header.littleEndian, ci++, o === 0));
  const res = discoverFunctions(db, chunks);
  db.setFunctions(res.functions); db.memAccess = res.memAccess; db.immediates = res.immediates; db.setXrefs(res.xrefs);
  db.insnTotal = chunks.reduce((a, c) => a + c.insnCount, 0); db.unknownTotal = chunks.reduce((a, c) => a + c.unknownCount, 0);
  const importsAll = new Set(elf.imports.map((x) => x.name));
  const lim = db.functions.length > 30000 ? 1200 : 3000;
  for (const f of db.functions) {
    if (f.isImportStub) { f.classes = []; continue; }
    try {
      const ins = db.decodeFunction(f, lim);
      f.insnCount = ins.length;
      f.features = extractFeatures(db, f, ins);
      f.classes = classify({ addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: [...f.features.callees.map((c) => db.nameFor(c).name), ...f.features.importCalls], callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)).filter((s): s is NonNullable<typeof s> => !!s).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll });
    } catch { f.classes = []; }
  }
  return db;
}

async function main() {
  const paths = process.argv.slice(2);
  const T0 = performance.now();
  const dbs = paths.map((p) => { const t = performance.now(); const db = analyze(p); console.log(`analyzed ${db.fileName}: ${db.functions.length} fns, ${db.elf.exports.length} exp, ${db.elf.imports.length} imp, soname=${db.elf.soname} in ${((performance.now() - t) / 1000).toFixed(1)}s`); return db; });
  const descriptors = dbs.map(libDescriptor);
  const link = linkLibraries(descriptors);
  console.log(`\n=== LINK GRAPH (${link.nodes.length} nodes, ${link.edges.length} edges) ===`);
  for (const e of link.edges.slice(0, 30)) console.log(`   ${e.from} → ${e.to} [${e.via}] ${e.via === "symbol" ? `${e.count} sym: ${e.symbols.slice(0, 6).join(", ")}` : ""}`);
  console.log(`shared detections: ${link.sharedDetections.length}${link.sharedDetections.length ? " → " + link.sharedDetections.slice(0, 6).map((s) => `"${s.value.slice(0, 24)}"×${s.libs.length}`).join(", ") : ""}`);
  for (const u of link.unresolved) console.log(`   unresolved ${u.lib}: ${u.count} (${u.sample.slice(0, 4).join(", ")})`);

  console.log(`\n=== MRPC per lib ===`);
  for (const db of dbs) { const m = buildMrpcReport(db, 8); console.log(`   ${db.fileName}: ${m.count} rule-engine routine(s)${m.count ? ` (${m.networkBacked ? "server-fed" : "bundled"}) → ${m.findings.slice(0, 4).map((f) => `${f.role} ${f.name}@${hex(f.addr)} [${f.legs.filter((l) => !l.startsWith("rule-strings")).join("+")}]`).join(", ")}` : ""}`); }

  console.log(`\n=== PLAN for ${dbs[0].fileName} (in workspace) ===`);
  const plan = await planBypass(dbs[0], undefined, { workspace: { descriptors, link } });
  const cnt = (st: string) => plan.steps.filter((s) => s.safety === st).length;
  const mrpcSteps = plan.steps.filter((s) => s.identity.startsWith("mrpc ·"));
  console.log(`plan: ${plan.steps.length} steps (${cnt("SAFE")} SAFE · ${cnt("RISKY")} RISKY) · ${plan.blocked.length} blocked · mrpc steps ${mrpcSteps.length}`);
  const lines = plan.steps.flatMap((s) => [s.patchLib, ...(s.hookLib ? s.hookLib.split("\n").filter((l) => /^HOOK_LIB/.test(l)) : [])]).filter((l) => l && !l.startsWith("//"));
  const self = lines.length ? analyzePasted(dbs[0], lines.join("\n")) : null;
  console.log(`self-check: ${self ? `${self.items.length} lines · ${self.items.filter((v) => v.status === "UNSAFE").length} UNSAFE` : "n/a"}`);
  for (const s of mrpcSteps.slice(0, 4)) console.log(`   MRPC step ${s.safety} ${s.title} :: ${s.detail.replace(/\s+/g, " ").slice(0, 160)}`);
  console.log(`MRPC verdict: ${plan.mrpc.verdict.slice(0, 260)}`);
  if (plan.crossLib) {
    console.log(`crossLib: depends on [${plan.crossLib.dependsOn.map((x) => `${x.lib}(${x.via.join("/")}${x.symbols ? "," + x.symbols : ""})`).join(", ")}] · used by [${plan.crossLib.dependedBy.map((x) => x.lib).join(", ")}]`);
    console.log(`  security resolved elsewhere: ${plan.crossLib.securityResolvedElsewhere.slice(0, 10).map((r) => `${r.symbol}→${r.lib}`).join(", ") || "none"}`);
    console.log(`  ${plan.crossLib.note.slice(0, 300)}`);
    for (const s of plan.steps.filter((x) => x.crossLib?.length).slice(0, 5)) console.log(`   step ${s.targetName}@${hex(s.address)} → ${s.crossLib!.map((c) => `${c.symbol}@${c.lib}`).join(", ")}`);
  }
  console.log(`\ntotal ${((performance.now() - T0) / 1000).toFixed(1)}s`);
}
main().catch((e) => { console.error(e); process.exit(1); });
