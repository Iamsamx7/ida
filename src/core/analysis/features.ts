import type { ArchitectureProvider, Instruction } from "../architecture/types";
import { decodeRange } from "../architecture/registry";
import type { AnalysisDatabase } from "./database";
import type { FunctionFeatures, FunctionRecord } from "./types";

/** Pure per-function code summary: no database access, worker-safe. */
export interface CodeSummary {
  hist: Record<string, number>;
  constants: number[];
  offsets: number[];
  branchCount: number;
  callCount: number;
  loadCount: number;
  storeCount: number;
  hasLoop: boolean;
  fingerprint: string;
  insnCount: number;
}

/**
 * Summarize decoded instructions. Pure function of the instruction stream —
 * runs identically on workers and the main thread.
 */
export function summarizeCode(code: Instruction[], stackPointer: string | null, fnAddr: number): CodeSummary {
  const hist: Record<string, number> = {};
  const constants = new Set<number>();
  const offsets = new Set<number>();
  let branchCount = 0, callCount = 0, loadCount = 0, storeCount = 0, hasLoop = false;
  const norm: string[] = [];
  const regVals = new Map<string, number>(); // movz/movk composition
  for (const ins of code) {
    if ((ins.mnemonic === "mov" || ins.mnemonic === "movz") && ins.operands[1]?.imm !== undefined && ins.operands[0].reg) {
      regVals.set(ins.operands[0].reg.replace(/^w/, "x"), ins.operands[1].imm);
    } else if (ins.mnemonic === "movk" && ins.operands[1]?.imm !== undefined && ins.operands[0].reg) {
      const r = ins.operands[0].reg.replace(/^w/, "x");
      const sh = ins.operands[2]?.text.match(/#(\d+)/);
      const shift = sh ? +sh[1] : 0;
      const prev = regVals.get(r) ?? 0;
      const composed = prev + ins.operands[1].imm * 2 ** shift;
      regVals.set(r, composed);
      if (constants.size < 64) constants.add(composed);
    } else if (ins.operands[0]?.reg && ins.kind !== "store" && ins.kind !== "compare") regVals.delete(ins.operands[0].reg.replace(/^w/, "x"));
    hist[ins.mnemonic] = (hist[ins.mnemonic] ?? 0) + 1;
    const k = ins.kind;
    if (k === "jump" || k === "condjump") {
      branchCount++;
      if (ins.target !== undefined && ins.target <= ins.address && ins.target >= fnAddr) hasLoop = true;
    } else if (k === "call" || k === "indirect-call") callCount++;
    else if (k === "load") loadCount++;
    else if (k === "store") storeCount++;
    for (const o of ins.operands) {
      if (o.imm !== undefined && k !== "call" && k !== "jump" && k !== "condjump" && k !== "adr" && Math.abs(o.imm) >= 0x10 && constants.size < 64) constants.add(o.imm);
      if (o.memBase && o.memDisp !== undefined && o.memBase !== stackPointer && o.memBase !== "x29" && o.memBase !== "rbp" && o.memBase !== "rip") offsets.add(o.memDisp);
    }
    // Normalised instruction: mnemonic + operand shape (registers abstracted)
    norm.push(ins.mnemonic + ":" + ins.operands.map((o) => (o.memBase ? "M" : o.reg ? "R" : o.imm !== undefined ? "I" : "T")).join(""));
  }
  return {
    hist,
    constants: [...constants].slice(0, 64),
    offsets: [...offsets].sort((a, b) => a - b).slice(0, 64),
    branchCount, callCount, loadCount, storeCount, hasLoop,
    fingerprint: fnv1a(norm.join("|")),
    insnCount: code.length,
  };
}

/** Database-backed call/string resolution for one function (main thread; cheap map lookups). */
export function resolveCalls(db: AnalysisDatabase, fn: FunctionRecord): { stringRefs: number[]; callees: number[]; importCalls: string[] } {
  const refs = db.xrefs.refsFromRange(fn.addr, fn.addr + fn.size);
  const stringRefs: number[] = [];
  const callees: number[] = [];
  const importCalls: string[] = [];
  for (const r of refs) {
    if (r.kind === 7) stringRefs.push(r.to);
    else if (r.kind === 1) {
      callees.push(r.to);
      const n = db.nameFor(r.to);
      if (db.pltNames.has(r.to) || n.source === "symbol") importCalls.push(n.name.replace(/@plt$/, ""));
    } else if (r.kind === 2 && !db.contains(fn, r.to)) {
      // tail call
      callees.push(r.to);
      const n = db.nameFor(r.to);
      if (db.pltNames.has(r.to)) importCalls.push(n.name.replace(/@plt$/, ""));
    } else if (r.kind === 3 && db.gotNames.has(r.to)) {
      // Import used through its GOT slot (adrp + ldr + blr, the usual ARM64 pattern): counts as calling the import.
      callees.push(r.to);
      importCalls.push(db.gotNames.get(r.to)!);
    }
  }
  return {
    stringRefs: [...new Set(stringRefs)].slice(0, 64),
    callees: [...new Set(callees)].slice(0, 128),
    importCalls: [...new Set(importCalls)].slice(0, 64),
  };
}

/**
 * Extract a compact feature vector from a function. Used by the semantic
 * rule engine, the similarity engine and the AI retrieval layer.
 */
export function extractFeatures(db: AnalysisDatabase, fn: FunctionRecord, insns?: Instruction[]): FunctionFeatures {
  const code = insns ?? db.decodeFunction(fn, 4000);
  const s = summarizeCode(code, db.arch?.stackPointer ?? null, fn.addr);
  const r = resolveCalls(db, fn);
  return {
    mnemonicHist: s.hist,
    constants: s.constants,
    stringRefs: r.stringRefs,
    callees: r.callees,
    importCalls: r.importCalls,
    branchCount: s.branchCount,
    callCount: s.callCount,
    loadCount: s.loadCount,
    storeCount: s.storeCount,
    memAccessOffsets: s.offsets,
    hasLoop: s.hasLoop,
    fingerprint: s.fingerprint,
  };
}

export interface FeaturizeItem {
  addr: number;
  summary: CodeSummary;
}

/**
 * Decode a byte slice once and summarize every function inside it. Runs in
 * workers (and as the inline fallback). Pure decode + summarize — name and
 * xref resolution stays on the main thread via resolveCalls().
 */
export function featurizeSlice(
  arch: ArchitectureProvider,
  bytes: Uint8Array,
  va: number,
  littleEndian: boolean,
  funcs: { addr: number; size: number }[],
  cap: number,
): FeaturizeItem[] {
  const sorted = [...funcs].sort((a, b) => a.addr - b.addr);
  const insns = decodeRange(arch, bytes, 0, va, bytes.length, littleEndian, sorted.length * cap);
  const out: FeaturizeItem[] = [];
  let k = 0;
  const sp = arch.stackPointer;
  for (const f of sorted) {
    const end = f.addr + Math.max(f.size, 4);
    while (k < insns.length && insns[k].address < f.addr) k++;
    const slice: Instruction[] = [];
    for (let j = k; j < insns.length && insns[j].address < end && slice.length < cap; j++) slice.push(insns[j]);
    out.push({ addr: f.addr, summary: summarizeCode(slice, sp, f.addr) });
  }
  return out;
}

export function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Cosine-like similarity of two feature vectors, weighted across several signals. */
export function similarity(a: FunctionFeatures, b: FunctionFeatures, sizeA: number, sizeB: number): number {
  const hist = cosine(a.mnemonicHist, b.mnemonicHist);
  const consts = jaccard(a.constants, b.constants);
  const strs = jaccard(a.stringRefs, b.stringRefs);
  const imports = jaccard(a.importCalls, b.importCalls);
  const callees = jaccard(a.callees, b.callees);
  const offs = jaccard(a.memAccessOffsets, b.memAccessOffsets);
  const sizeRatio = Math.min(sizeA, sizeB) / Math.max(sizeA, sizeB, 1);
  const fp = a.fingerprint === b.fingerprint ? 1 : 0;
  const structural = Math.abs(a.branchCount - b.branchCount) <= Math.max(2, 0.2 * Math.max(a.branchCount, b.branchCount)) ? 1 : 0;
  const hasExtra = a.constants.length + a.stringRefs.length + a.importCalls.length > 0;
  const base = hist * 0.35 + sizeRatio * 0.15 + structural * 0.1 + fp * 0.15;
  const extra = hasExtra ? (consts * 0.25 + strs * 0.3 + imports * 0.25 + callees * 0.1 + offs * 0.1) / 1.0 : hist * 0.25;
  return Math.min(1, base + extra * 0.4 + (fp ? 0.1 : 0));
}

function cosine(a: Record<string, number>, b: Record<string, number>) {
  let dot = 0, na = 0, nb = 0;
  for (const k in a) { na += a[k] * a[k]; if (k in b) dot += a[k] * b[k]; }
  for (const k in b) nb += b[k] * b[k];
  if (!na || !nb) return 0;
  return dot / Math.sqrt(na * nb);
}
function jaccard<T>(a: T[], b: T[]) {
  if (!a.length && !b.length) return 0;
  const sa = new Set(a), sb = new Set(b);
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  return inter / (sa.size + sb.size - inter);
}
