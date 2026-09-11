import type { AnalysisDatabase } from "./database";
import type { GlobalRecord, StructureRecord } from "./types";
import { regName } from "./codeScan";

/**
 * Infer possible structures from recurring base+offset access patterns and
 * collect global data objects from data xrefs. Everything produced here is
 * marked as INFERENCE — fields are "possible", never "certain" unless a
 * symbol confirms them.
 */
export function inferStructures(db: AnalysisDatabase, maxStructures = 400): StructureRecord[] {
  const mem = db.memAccess;
  if (!mem.length || !db.arch) return [];
  // Group by (function, baseReg)
  type Acc = { fn: number; reg: number; fields: Map<number, { size: number; reads: number; writes: number; at: number }> };
  const groups = new Map<string, Acc>();
  for (let i = 0; i < mem.length; i += 4) {
    const va = mem[i], disp = mem[i + 1], reg = mem[i + 2], flags = mem[i + 3];
    if (disp < 0 || disp > 0x4000) continue;
    const fn = db.functionAt(va);
    if (!fn) continue;
    const key = `${fn.addr}:${reg}`;
    let g = groups.get(key);
    if (!g) {
      g = { fn: fn.addr, reg, fields: new Map() };
      groups.set(key, g);
    }
    const f = g.fields.get(disp) ?? { size: flags >> 1, reads: 0, writes: 0, at: va };
    if (flags & 1) f.writes++;
    else f.reads++;
    f.size = Math.max(f.size, flags >> 1);
    g.fields.set(disp, f);
  }
  // Merge groups with identical offset signatures across functions (same layout seen from several places).
  const bySig = new Map<string, { accs: Acc[]; sig: number[] }>();
  for (const g of groups.values()) {
    if (g.fields.size < 3) continue;
    const sig = [...g.fields.keys()].sort((a, b) => a - b);
    const key = sig.join(",");
    const e = bySig.get(key) ?? { accs: [], sig };
    e.accs.push(g);
    bySig.set(key, e);
  }
  const out: StructureRecord[] = [];
  const ranked = [...bySig.values()].sort((a, b) => b.accs.length * b.sig.length - a.accs.length * a.sig.length);
  let n = 0;
  for (const e of ranked) {
    if (n++ >= maxStructures) break;
    const first = e.accs[0];
    const fields = e.sig.map((off) => {
      const f = first.fields.get(off)!;
      const kinds: ("read" | "write")[] = [];
      if (f.reads) kinds.push("read");
      if (f.writes) kinds.push("write");
      return { offset: off, name: off === 0 && f.size === 8 ? "vtable?" : `field_${off.toString(16)}`, size: f.size, type: guessType(f.size), certain: false, accessKinds: kinds };
    });
    const fnNames = e.accs.slice(0, 4).map((a) => db.nameFor(a.fn).name);
    const reg = regName(db.arch.bits, db.arch.id, first.reg);
    const conf = Math.min(0.9, 0.3 + 0.1 * e.accs.length + 0.03 * e.sig.length);
    out.push({
      id: `struct_${first.fn.toString(16)}_${reg}`,
      name: `struct_${reg}_${first.fn.toString(16)}`,
      origin: "inferred",
      fields,
      confidence: conf,
      functions: e.accs.map((a) => a.fn),
      evidence: [
        { text: `${e.sig.length} distinct offsets accessed from ${reg} in ${e.accs.length} function(s): ${fnNames.join(", ")}`, certainty: "inference", address: first.fn },
        ...e.accs.slice(0, 3).map((a) => ({ text: `access pattern in ${db.nameFor(a.fn).name}`, certainty: "inference" as const, address: a.fn })),
      ],
    });
  }
  return out;
}

function guessType(size: number) {
  switch (size) {
    case 1: return "uint8_t";
    case 2: return "uint16_t";
    case 4: return "uint32_t/float";
    case 8: return "uint64_t/pointer";
    case 16: return "uint128/vector";
    default: return "unknown";
  }
}

/** Collect referenced global data objects (from data xrefs + object symbols). */
export function collectGlobals(db: AnalysisDatabase, max = 50_000): GlobalRecord[] {
  const map = new Map<number, GlobalRecord>();
  const secName = (addr: number) => db.space.sectionAt(addr)?.name ?? "?";
  for (const s of db.elf.symbols) {
    if (s.kind === "object" && s.defined && s.value && !map.has(s.value)) {
      map.set(s.value, { addr: s.value, name: s.name, nameSource: "symbol", size: s.size, section: secName(s.value), readers: 0, writers: 0 });
    }
  }
  const { from, to, kind, count } = db.xrefs;
  for (let i = 0; i < count && map.size < max; i++) {
    const k = kind[i];
    if (k !== 3 && k !== 4 && k !== 5) continue;
    const addr = to[i];
    if (db.space.isExec(addr) || db.stringAt(addr)) continue;
    let g = map.get(addr);
    if (!g) {
      const n = db.nameFor(addr); // user name, symbol, or GOT slot name when known
      g = { addr, name: n.source === "inferred" ? `g_${secName(addr).replace(/^\./, "")}_${addr.toString(16)}` : n.name, nameSource: n.source, size: 0, section: secName(addr), readers: 0, writers: 0 };
      map.set(addr, g);
    }
    if (k === 4) g.writers++;
    else g.readers++;
    void from;
  }
  return [...map.values()].sort((a, b) => b.readers + b.writers - (a.readers + a.writers));
}
