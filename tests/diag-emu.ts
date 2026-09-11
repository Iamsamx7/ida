// Diagnostic: how the emulator story flows through strings → xrefs → readers → intel → plan for one binary.
//   NODE_OPTIONS=--max-old-space-size=12288 npx tsx tests/diag-emu.ts path/to/lib.so
import { readFileSync } from "node:fs";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { extractFeatures } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { buildIntel, EMU_MARKER_RE, emuMarkersOf, emuRelevantAnticheat, emuSweep } from "../src/core/analysis/intel";
import { planBypass } from "../src/core/analysis/bypass";
import { analyzePasted } from "../src/core/analysis/verify";

const hex = (n: number) => "0x" + n.toString(16);
const path = process.argv[2];
const t = (label: string, t0: number) => console.log(`[${((performance.now() - t0) / 1000).toFixed(1)}s] ${label}`);

async function main() {
  const T0 = performance.now();
  const bytes = new Uint8Array(readFileSync(path));
  const elf = parseElf(bytes);
  const arch = getArchitecture(elf.header.arch)!;
  console.log(`${path}: ${(bytes.length / 1048576).toFixed(1)} MB ${elf.header.machineName} · ${elf.sections.length} sections · ${elf.symbols.length} symbols · ${elf.imports.length} imports · ${elf.exports.length} exports · stripped=${elf.stripped} · soname=${elf.soname} · needed=${elf.needed.join(",")}`);
  for (const w of elf.warnings.slice(0, 5)) console.log(`  [${w.level}] ${w.message}`);
  const db = new AnalysisDatabase(elf, bytes, arch, path);
  const strRanges = elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0);
  db.setStrings(toRecords(strRanges.flatMap((s) => scanStrings(bytes, s.offset, s.addr, s.size))));
  t(`strings: ${db.strings.length}`, T0);

  // 1. Emulator marker strings, regardless of who reads them.
  const markers = db.strings.filter((s) => s.value.length <= 160 && EMU_MARKER_RE.test(s.value));
  console.log(`emulator marker strings: ${markers.length}`);
  for (const s of markers.slice(0, 40)) console.log(`   ${hex(s.addr)} [${s.category}] "${s.value.slice(0, 90).replace(/\n/g, "\\n")}"`);

  // 2. Full pipeline so readers/classes/intel exist.
  const chunks: ReturnType<typeof scanCodeChunk>[] = [];
  let ci = 0;
  const CH = 512 * 1024;
  for (const r of db.space.codeRanges()) for (let o = 0; o < r.size; o += CH) chunks.push(scanCodeChunk(arch, bytes, r.offset + o, r.vaddr + o, Math.min(CH, r.size - o), elf.header.littleEndian, ci++, o === 0));
  t(`code scan: ${chunks.reduce((a, c) => a + c.insnCount, 0)} insns (${chunks.reduce((a, c) => a + c.unknownCount, 0)} unknown)`, T0);
  const res = discoverFunctions(db, chunks);
  db.setFunctions(res.functions); db.memAccess = res.memAccess; db.immediates = res.immediates; db.setXrefs(res.xrefs);
  db.insnTotal = chunks.reduce((a, c) => a + c.insnCount, 0); db.unknownTotal = chunks.reduce((a, c) => a + c.unknownCount, 0);
  let k7 = 0;
  for (let i = 0; i < db.xrefs.count; i++) if (db.xrefs.kind[i] === 7) k7++;
  t(`discovery: ${db.functions.length} functions · ${db.xrefs.count} xrefs · ${k7} string xrefs (kind 7)`, T0);
  const importsAll = new Set(elf.imports.map((x) => x.name));
  const decodeLim = db.functions.length > 30000 ? 1200 : 3000;
  let n = 0;
  for (const f of db.functions) {
    if (f.isImportStub) { f.classes = []; continue; }
    try {
      const insns = db.decodeFunction(f, decodeLim);
      f.insnCount = insns.length;
      f.features = extractFeatures(db, f, insns);
      f.classes = classify({ addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: [...f.features.callees.map((c) => db.nameFor(c).name), ...f.features.importCalls], callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)).filter((s): s is NonNullable<typeof s> => !!s).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll });
    } catch { f.classes = []; }
    if (++n % 100000 === 0) t(`classified ${n}`, T0);
  }
  t(`semantic: ${db.functions.filter((f) => f.classes?.length).length} classified`, T0);

  // 3. Who reads the marker strings, and how are those readers labelled?
  const readers = new Map<number, { fn: string; markers: string[]; classes: string; imports: string[] }>();
  for (const s of markers) {
    for (const x of db.xrefs.refsTo(s.addr, 50)) {
      const fn = db.functionAt(x.from);
      if (!fn) continue;
      const r = readers.get(fn.addr) ?? { fn: db.nameFor(fn.addr).name, markers: [], classes: (fn.classes ?? []).slice(0, 3).map((c) => `${c.label}@${Math.round(c.confidence * 100)}`).join(" "), imports: db.importCallsOf(fn).slice(0, 6) };
      if (r.markers.length < 6) r.markers.push(s.value.slice(0, 40));
      readers.set(fn.addr, r);
    }
  }
  console.log(`functions referencing marker strings: ${readers.size}`);
  for (const [addr, r] of [...readers.entries()].slice(0, 25)) console.log(`   ${r.fn}@${hex(addr)} classes=[${r.classes || "none"}] imports=[${r.imports.join(",")}] markers=${JSON.stringify(r.markers)}`);
  const propReaders = db.functions.filter((f) => (f.features?.importCalls ?? []).some((i) => /__system_property_get|__system_property_read|__system_property_find|property_get/.test(i)));
  console.log(`functions calling __system_property_get/property_get: ${propReaders.length}`);

  // 4. What the planner's own emulator machinery sees.
  console.log(`emuSweep: ${JSON.stringify(emuSweep(db))}`);
  const em = emuMarkersOf(db);
  console.log(`emuMarkersOf: markers=${em.markers.length} functions=${em.functions.length} floating=${em.floating.length} :: ${em.markers.slice(0, 6).map((m) => `${m.via}:${m.key.slice(0, 30)}→${m.phoneValue.slice(0, 24)}`).join(" | ")}`);
  const era = emuRelevantAnticheat(db, 12);
  console.log(`emuRelevantAnticheat: ${era.length} → ${era.slice(0, 8).map((f) => `${f.name}@${hex(f.addr)}:${f.proofLevel}`).join(", ")}`);
  const intel = buildIntel(db, 15);
  console.log(`intel: ${intel.findings.length} findings (${intel.counts.anticheat} anticheat · ${intel.counts["hash-check"]} hash · ${intel.counts["ban-check"]} ban · ${intel.counts["game-revive"]} revive) proven=${intel.provenCount} packed=${intel.packedSuspect}`);
  for (const f of intel.findings.filter((x) => x.kind === "anticheat").slice(0, 8)) console.log(`   ${f.proofLevel.toUpperCase()} ${f.name}@${hex(f.addr)} ${Math.round(f.confidence * 100)}% legs=${f.legs.join(" + ")} :: ${f.connectedTo.filter((c) => c.role === "string").slice(0, 3).map((c) => c.name).join(" ")}`);
  const plan = await planBypass(db);
  const spoof = plan.steps.filter((s) => s.action === "spoof-props");
  console.log(`plan: ${plan.steps.length} steps · spoof steps: ${spoof.length}`);
  for (const s of spoof) console.log(`   ${s.safety} ${s.title} :: ${s.detail.replace(/\s+/g, " ").slice(0, 240)}`);
  for (const th of plan.thinking.filter((x) => /emu|spoof/i.test(x))) console.log(`   thinking: ${th.slice(0, 260)}`);
  console.log(`emulator report: ${JSON.stringify({ ...plan.emulator, verdict: undefined })}`);
  console.log(`verdict: ${plan.emulator.verdict}`);
  for (const s of plan.steps.filter((x) => x.identity.startsWith("emu-verdict consumer") || x.id.startsWith("emu-consumer-")).slice(0, 6)) console.log(`   consumer ${s.safety} ${s.title.slice(0, 100)}`);
  for (const s of plan.steps.filter((x) => x.action === "patch-branch" && x.safety === "SAFE").slice(0, 3)) console.log(`   branch ${s.targetName}@${hex(s.address)} ${s.patchLib} :: ${s.detail.replace(/\s+/g, " ").slice(0, 160)}`);
  const planLines = plan.steps.flatMap((s) => [s.patchLib, ...(s.hookLib ? s.hookLib.split("\n").filter((l) => /^HOOK_LIB/.test(l)) : [])]).filter((l) => l && !l.startsWith("//"));
  const self = planLines.length ? analyzePasted(db, planLines.join("\n")) : null;
  console.log(`self-check: ${self ? `${self.items.length} lines · ${self.items.filter((v) => v.status === "UNSAFE").length} UNSAFE · ${self.items.filter((v) => v.status === "RISKY").length} RISKY` : "n/a"}`);
  for (const v of self?.items.filter((x) => x.status === "UNSAFE").slice(0, 4) ?? []) console.log(`   UNSAFE ${v.item.raw.slice(0, 70)} — ${v.checks.filter((c) => !c.pass).map((c) => c.detail.slice(0, 90)).join(" | ")}`);
  const cnt = (st: string) => plan.steps.filter((s) => s.safety === st).length;
  console.log(`plan safety: ${cnt("SAFE")} SAFE · ${cnt("RISKY")} RISKY · ${plan.blocked.length} blocked · patch lines: ${plan.steps.filter((s) => s.patchLib && !s.patchLib.startsWith("//")).length}`);
  t("done", T0);
}
main().catch((e) => { console.error(e); process.exit(1); });
