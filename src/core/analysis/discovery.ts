import type { AnalysisDatabase } from "./database";
import type { ChunkScanResult, FunctionRecord, Xref } from "./types";
import { XrefIndex } from "./xrefIndex";

interface Candidate {
  addr: number;
  sources: Map<string, number>; // source -> confidence
}

/**
 * Merge chunk scan results into function records + xref index.
 * Evidence-based: every candidate carries its sources and a combined
 * confidence, and low-evidence candidates that fall inside a known
 * function are discarded.
 */
export function discoverFunctions(db: AnalysisDatabase, chunks: ChunkScanResult[]): { functions: FunctionRecord[]; xrefs: XrefIndex; memAccess: Float64Array; immediates: Float64Array; droppedCandidates: number } {
  const space = db.space;
  const align = db.arch?.alignment ?? 1;
  const candidates = new Map<number, Candidate>();
  const add = (addr: number, source: string, conf: number) => {
    if (!Number.isFinite(addr) || addr <= 0) return;
    if (align > 1 && addr % align !== 0) return;
    if (!space.isExec(addr)) return;
    let c = candidates.get(addr);
    if (!c) {
      c = { addr, sources: new Map() };
      candidates.set(addr, c);
    }
    const prev = c.sources.get(source) ?? 0;
    if (conf > prev) c.sources.set(source, conf);
  };

  // 1. Symbols (facts)
  const symSizes = new Map<number, number>();
  for (const s of db.elf.symbols) {
    if (s.kind === "func" && s.defined && s.value) {
      add(s.value, "symbol", 1);
      if (s.size) symSizes.set(s.value, Math.max(symSizes.get(s.value) ?? 0, s.size));
    }
  }
  for (const e of db.elf.exports) if (e.kind === "func" || (e.kind === "notype" && space.isExec(e.value))) add(e.value, "export", 1);
  if (db.elf.header.entry) add(db.elf.header.entry, "entry", 0.95);
  for (const a of db.elf.initArray) add(a, "init-array", 0.95);
  for (const a of db.elf.finiArray) add(a, "fini-array", 0.95);
  for (const [addr] of db.pltNames) add(addr, "plt", 1);

  // 2. Relocations pointing into code (vtables, function pointer tables)
  const dataToCode: Xref[] = [];
  const definedSymByName = new Map<string, number>();
  for (const s of db.elf.symbols) if (s.defined && s.name && !definedSymByName.has(s.name)) definedSymByName.set(s.name, s.value);
  let relocPtrCount = 0;
  for (const r of db.elf.relocations) {
    if (relocPtrCount > 500_000) break;
    let target: number | null = null;
    if (/RELATIVE/.test(r.typeName)) {
      target = r.addend || db.readPointer(r.offset);
      if (r.typeName === "RELR_RELATIVE" || (!r.addend && r.section.startsWith(".rel"))) target = db.readPointer(r.offset);
    } else if (/ABS64|ABS32|R_X86_64_64|R_386_32/.test(r.typeName) && r.symName) {
      const v = definedSymByName.get(r.symName);
      target = v !== undefined ? v + r.addend : null;
    }
    if (target !== null && space.isExec(target) && (align === 1 || target % align === 0)) {
      add(target, "relocation", 0.7);
      dataToCode.push({ from: r.offset, to: target, kind: 6 });
      relocPtrCount++;
    }
  }

  // 3. Code scan evidence
  const xrefFrom: number[] = [], xrefTo: number[] = [], xrefKind: number[] = [];
  let memTotal = 0, immTotal = 0;
  const codeRanges = space.codeRanges();
  const inCode = (a: number) => codeRanges.some((r) => a >= r.vaddr && a < r.vaddr + r.size);
  for (const ch of chunks) {
    const c = ch.calls;
    for (let i = 0; i < c.length; i += 2) {
      add(c[i + 1], "call-target", 0.9);
      xrefFrom.push(c[i]); xrefTo.push(c[i + 1]); xrefKind.push(1);
    }
    const j = ch.jumps;
    for (let i = 0; i < j.length; i += 2) { xrefFrom.push(j[i]); xrefTo.push(j[i + 1]); xrefKind.push(2); }
    const cj = ch.condJumps;
    for (let i = 0; i < cj.length; i += 2) { xrefFrom.push(cj[i]); xrefTo.push(cj[i + 1]); xrefKind.push(2); }
    const d = ch.dataRefs;
    for (let i = 0; i < d.length; i += 3) {
      const to = d[i + 1];
      if (!space.isMapped(to)) continue;
      let kind = d[i + 2];
      if (db.stringAt(to)) kind = 7;
      xrefFrom.push(d[i]); xrefTo.push(to); xrefKind.push(kind);
      // Address-taken code (function pointers loaded via adrp/add)
      if (kind === 5 && inCode(to) && (align === 1 || to % align === 0)) add(to, "address-taken", 0.6);
    }
    const p = ch.prologues;
    for (let i = 0; i < p.length; i += 2) {
      const score = p[i + 1] / 255;
      add(p[i], "prologue", 0.35 + 0.55 * score);
    }
    memTotal += ch.memAccess.length;
    immTotal += ch.immediates.length;
  }
  for (const x of dataToCode) { xrefFrom.push(x.from); xrefTo.push(x.to); xrefKind.push(6); }

  // Tail-call jump targets from outside any function body are also candidates (resolved after first pass).

  // 4. Combine evidence
  let prelim: FunctionRecord[] = [];
  for (const c of candidates.values()) {
    let notP = 1;
    for (const conf of c.sources.values()) notP *= 1 - conf;
    const confidence = 1 - notP;
    prelim.push({
      addr: c.addr,
      size: 0,
      name: "",
      nameSource: "inferred",
      confidence,
      sources: [...c.sources.keys()],
      insnCount: 0,
      callerCount: 0,
      calleeCount: 0,
      isImportStub: c.sources.has("plt"),
    });
  }
  prelim.sort((a, b) => a.addr - b.addr);

  // 5. Prune: prologue-only candidates inside a symbol'd function body are not functions;
  //    weak prologue-only candidates below threshold are dropped.
  const strong = prelim.filter((f) => f.sources.some((s) => s !== "prologue"));
  const strongAddrs = strong.map((f) => f.addr);
  const insideKnown = (addr: number) => {
    // binary search greatest strong start <= addr
    let lo = 0, hi = strongAddrs.length - 1, k = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (strongAddrs[m] <= addr) { k = m; lo = m + 1; } else hi = m - 1; }
    if (k < 0) return false;
    const start = strongAddrs[k];
    const size = symSizes.get(start) ?? 0;
    return size > 0 && addr < start + size;
  };
  prelim = prelim.filter((f) => {
    if (f.sources.length === 1 && f.sources[0] === "prologue") {
      if (f.confidence < 0.55) return false;
      if (insideKnown(f.addr)) return false;
    }
    return true;
  });
  // Also drop candidates that are jump targets from inside an immediately preceding function *and* have weak evidence
  const weakSet = new Set(prelim.filter((f) => f.confidence < 0.7).map((f) => f.addr));
  if (weakSet.size) {
    const jumpTargets = new Set<number>();
    for (let i = 0; i < xrefKind.length; i++) if (xrefKind[i] === 2) jumpTargets.add(xrefTo[i]);
    prelim = prelim.filter((f) => !(weakSet.has(f.addr) && jumpTargets.has(f.addr) && !f.sources.includes("call-target")));
  }

  // 5b. Mass valve: garbage-dense inputs (packed/encrypted code decodes into
  // millions of phantom call-targets/prologues). Past this point the list is
  // unusable and downstream stages never finish — keep every strong candidate
  // and fill up to the cap by confidence. Small binaries never reach this.
  let droppedCandidates = 0;
  const MASS_LIMIT = 400_000;
  if (prelim.length > MASS_LIMIT) {
    prelim.sort((a, b) => b.confidence - a.confidence || a.addr - b.addr);
    const strong = prelim.filter((f) => f.confidence >= 0.7);
    const rest = prelim.filter((f) => f.confidence < 0.7).slice(0, Math.max(0, MASS_LIMIT - strong.length));
    droppedCandidates = prelim.length - strong.length - rest.length;
    prelim = [...strong, ...rest].sort((a, b) => a.addr - b.addr);
  }

  // 6. Sizes: symbol size if known, otherwise up to next function start or end of code range.
  for (let i = 0; i < prelim.length; i++) {
    const f = prelim[i];
    const range = codeRanges.find((r) => f.addr >= r.vaddr && f.addr < r.vaddr + r.size);
    const rangeEnd = range ? range.vaddr + range.size : f.addr + 4;
    const next = i + 1 < prelim.length ? prelim[i + 1].addr : rangeEnd;
    const sym = symSizes.get(f.addr);
    f.size = Math.max(align, Math.min(sym && sym > 0 ? sym : next - f.addr, rangeEnd - f.addr, next - f.addr));
    if (sym && sym > 0 && sym <= next - f.addr) f.size = sym;
  }

  // Collect memAccess & immediates into flat arrays
  const mem = new Float64Array(memTotal);
  const imm = new Float64Array(immTotal);
  let mo = 0, io = 0;
  for (const ch of chunks) { mem.set(ch.memAccess, mo); mo += ch.memAccess.length; imm.set(ch.immediates, io); io += ch.immediates.length; }

  const xrefs = new XrefIndex(Float64Array.from(xrefFrom), Float64Array.from(xrefTo), Uint8Array.from(xrefKind));
  return { functions: prelim, xrefs, memAccess: mem, immediates: imm, droppedCandidates };
}
