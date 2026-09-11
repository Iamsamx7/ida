/**
 * Benchmarks: ELF parse, code scan (single-thread), string scan, function
 * discovery/xref merge, and search latency.
 * Run: npx tsx tests/bench.ts [path/to/binary.so]
 */
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { search } from "../src/core/search/engine";
import { compilePattern, scanPattern } from "../src/core/signatures/pattern";
import { buildSampleSo } from "./fixtures/elfBuilder";

const arg = process.argv[2];
let bytes: Uint8Array;
let name: string;
if (arg && existsSync(arg)) {
  bytes = new Uint8Array(readFileSync(arg));
  name = arg;
} else {
  // 32 MB synthetic ARM64 text for a meaningful measurement
  bytes = buildSampleSo({ hugeText: 32 << 20 }).bytes;
  name = "synthetic-arm64-32MB";
  mkdirSync("tests/out", { recursive: true });
}
const mem0 = process.memoryUsage().heapUsed;
const t = (label: string, fn: () => unknown) => {
  const t0 = performance.now();
  const r = fn();
  const ms = performance.now() - t0;
  console.log(`${label.padEnd(34)} ${ms.toFixed(1).padStart(9)} ms`);
  return r;
};
console.log(`Benchmark: ${name} (${(bytes.length / 1048576).toFixed(1)} MB)`);
const elf = t("ELF parse", () => parseElf(bytes)) as ReturnType<typeof parseElf>;
const arch = getArchitecture(elf.header.arch)!;
const db = t("Database + PLT resolve", () => new AnalysisDatabase(elf, bytes, arch, name)) as AnalysisDatabase;
const strRanges = elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0);
const raw = t("String scan", () => strRanges.flatMap((s) => scanStrings(bytes, s.offset, s.addr, s.size))) as ReturnType<typeof scanStrings>;
db.setStrings(toRecords(raw));
const chunks = t("Code scan (1 thread)", () => {
  const out = [];
  let i = 0;
  for (const r of db.space.codeRanges()) {
    const CH = 512 * 1024;
    for (let o = 0; o < r.size; o += CH) out.push(scanCodeChunk(arch, bytes, r.offset + o, r.vaddr + o, Math.min(CH, r.size - o), elf.header.littleEndian, i++, o === 0));
  }
  return out;
}) as ReturnType<typeof scanCodeChunk>[];
const insns = chunks.reduce((a, c) => a + c.insnCount, 0);
const res = t("Function discovery + XREF merge", () => discoverFunctions(db, chunks)) as ReturnType<typeof discoverFunctions>;
db.setFunctions(res.functions);
db.memAccess = res.memAccess;
db.immediates = res.immediates;
t("XREF counts", () => db.setXrefs(res.xrefs));
t("Search 'init' (text)", () => search(db, "init"));
t("Search byte pattern", () => scanPattern(bytes, compilePattern("FD 7B ?? A9 ?? ?? ?? 91")));
t("Search address", () => search(db, "0x1000"));
const mem1 = process.memoryUsage().heapUsed;
console.log(`\nInstructions decoded: ${insns.toLocaleString()} (${(insns / 1e6).toFixed(2)} M) · functions: ${db.functions.length.toLocaleString()} · xrefs: ${db.xrefs.count.toLocaleString()} · strings: ${db.strings.length.toLocaleString()}`);
console.log(`Heap delta: ${((mem1 - mem0) / 1048576).toFixed(1)} MB`);
if (!arg) writeFileSync("tests/out/bench-last.json", JSON.stringify({ name, insns, functions: db.functions.length, xrefs: db.xrefs.count }, null, 2));
