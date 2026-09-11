// Real workspace-plan (unified all-libs) diagnostic — exercises cross-lib chains.
import { readFileSync } from "node:fs";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { extractFeatures } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { planWorkspace } from "../src/core/analysis/bypass";

const hex = (n: number) => "0x" + n.toString(16);
function analyze(path: string): AnalysisDatabase {
  const bytes = new Uint8Array(readFileSync(path));
  const elf = parseElf(bytes);
  const arch = getArchitecture(elf.header.arch)!;
  const db = new AnalysisDatabase(elf, bytes, arch, path.split(/[\/]/).pop()!);
  db.setStrings(toRecords(elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0).flatMap((s) => scanStrings(bytes, s.offset, s.addr, s.size))));
  const chunks: ReturnType<typeof scanCodeChunk>[] = []; let ci = 0; const CH = 512 * 1024;
  for (const r of db.space.codeRanges()) for (let o = 0; o < r.size; o += CH) chunks.push(scanCodeChunk(arch, bytes, r.offset + o, r.vaddr + o, Math.min(CH, r.size - o), elf.header.littleEndian, ci++, o === 0));
  const res = discoverFunctions(db, chunks);
  db.setFunctions(res.functions); db.memAccess = res.memAccess; db.immediates = res.immediates; db.setXrefs(res.xrefs);
  db.insnTotal = chunks.reduce((a, c) => a + c.insnCount, 0); db.unknownTotal = chunks.reduce((a, c) => a + c.unknownCount, 0);
  const importsAll = new Set(elf.imports.map((x) => x.name));
  const lim = db.functions.length > 30000 ? 900 : 3000;
  for (const f of db.functions) {
    if (f.isImportStub) { f.classes = []; continue; }
    try { const ins = db.decodeFunction(f, lim); f.insnCount = ins.length; f.features = extractFeatures(db, f, ins); f.classes = classify({ addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: [...f.features.callees.map((c) => db.nameFor(c).name), ...f.features.importCalls], callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)).filter((s): s is NonNullable<typeof s> => !!s).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll }); } catch { f.classes = []; }
  }
  return db;
}
async function main() {
  const T0 = performance.now();
  const libs = process.argv.slice(2).map((p) => { const t = performance.now(); const db = analyze(p); console.log(`analyzed ${db.fileName}: ${db.functions.length} fns in ${((performance.now() - t) / 1000).toFixed(1)}s`); return { name: db.fileName, db }; });
  const ws = await planWorkspace(libs, (p) => { if (p.progress === 0) console.log(`  [${p.pass}]`); });
  console.log(`\n=== WORKSPACE PLAN (${((performance.now() - T0) / 1000).toFixed(1)}s) ===`);
  console.log(`libs ${ws.summary.libs} · steps ${ws.summary.steps} (${ws.summary.safeSteps} SAFE) · chains ${ws.summary.chains} (${ws.summary.providersMissing} missing provider) · mrpc ${ws.summary.mrpc}`);
  for (const l of ws.perLib) console.log(`   ${l.soname}: ${l.plan.steps.length} steps, mrpc ${l.plan.mrpc.count}, crossLib ${l.plan.crossLib?.securityResolvedElsewhere.length ?? 0} sec-elsewhere`);
  console.log(`\n=== CHAINS (${ws.chains.length}, showing 12) ===`);
  for (const c of ws.chains.slice(0, 12)) console.log(`   [${c.symbol}] ${c.hasProviderStep ? "✓provider" : "✗no-provider"}: ${c.steps.map((s) => `${s.lib}::${s.role}@${hex(s.addr)}`).join(" → ")}`);
  console.log(`\n=== APPLY ORDER (first 14 of ${ws.order.length}) ===`);
  for (const o of ws.order.slice(0, 14)) console.log(`   ${o.lib} :: ${o.title.slice(0, 70)}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
