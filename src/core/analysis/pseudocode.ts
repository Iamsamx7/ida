import type { Instruction } from "../architecture/types";
import type { AnalysisDatabase } from "./database";
import type { FunctionRecord } from "./types";

export interface PseudoLine {
  text: string;
  address?: number;
  indent: number;
  kind: "code" | "label" | "comment" | "header";
}

/**
 * Reconstruct C-like pseudocode from a decoded function.
 *
 * This is an *inference*: a symbolic linear pass over the instruction stream
 * with register forwarding inside basic blocks. It is labelled as
 * reconstructed everywhere it is shown; it is not the original source.
 * Currently tuned for AArch64 (the primary target); other architectures get
 * a generic statement-per-instruction rendering.
 */
export function generatePseudocode(db: AnalysisDatabase, fn: FunctionRecord, insns?: Instruction[]): PseudoLine[] {
  const code = insns ?? db.decodeFunction(fn, 6000);
  const lines: PseudoLine[] = [];
  const name = db.nameFor(fn.addr).name;
  const isArm64 = db.arch?.id === "arm64";
  lines.push({ text: `// Reconstructed pseudocode (inferred, not original source) — ${name} @ 0x${fn.addr.toString(16)}`, indent: 0, kind: "comment" });

  // Labels needed
  const targets = new Set<number>();
  for (const i of code) if ((i.kind === "jump" || i.kind === "condjump") && i.target !== undefined && db.contains(fn, i.target)) targets.add(i.target);

  // Argument count heuristic: highest x0..x7 read before being written.
  // Only value-producing instructions write their first operand; stores, compares, branches (cbz x1) and calls (blr x8) read it.
  const argRegs = db.arch?.argumentRegisters ?? [];
  const writesFirst = (k: Instruction["kind"]) => k === "arith" || k === "logic" || k === "move" || k === "load" || k === "adr" || k === "simd";
  const written = new Set<string>();
  let maxArg = -1;
  for (const i of code.slice(0, 60)) {
    const ops = i.operands;
    const dest = ops[0]?.reg;
    for (let k = writesFirst(i.kind) ? 1 : 0; k < ops.length; k++) {
      const r = ops[k].reg ?? ops[k].memBase;
      if (!r) continue;
      const idx = argIndex(r, argRegs);
      if (idx >= 0 && !written.has(canon(r))) maxArg = Math.max(maxArg, idx);
    }
    if (dest && writesFirst(i.kind)) written.add(canon(dest));
  }
  const params = Array.from({ length: maxArg + 1 }, (_, i) => `${typeName(argRegs[i])} a${i + 1}`);
  const retType = code.some((i) => i.kind === "ret") ? "int64_t" : "void";
  lines.push({ text: `${retType} ${name}(${params.join(", ") || "void"})`, indent: 0, kind: "header", address: fn.addr });
  lines.push({ text: "{", indent: 0, kind: "code" });

  // Symbolic state
  const importNames = new Set(db.gotNames.values());
  let regs = new Map<string, string>();
  const reset = () => { regs = new Map(); };
  const val = (r?: string): string => {
    if (!r) return "?";
    const c = canon(r);
    if (c === "xzr" || c === "wzr") return "0";
    if (c === "sp") return "sp";
    const idx = argIndex(c, argRegs);
    if (regs.has(c)) return regs.get(c)!;
    if (idx >= 0 && idx <= maxArg) return `a${idx + 1}`;
    return c;
  };
  /** Longest symbolic expression kept in a register before it is materialised as a statement. */
  const MAX_EXPR = 160;
  const wordRx = new Map<string, RegExp>();
  const mentions = (expr: string, reg: string) => {
    let rx = wordRx.get(reg);
    if (!rx) { rx = new RegExp(`\\b${reg}\\b`); wordRx.set(reg, rx); }
    return rx.test(expr);
  };
  let curAddr = fn.addr;
  const set = (r: string, expr: string) => {
    const c = canon(r);
    // Invalidate expressions depending on this register (conservative: only direct self-dependency matters for readability).
    for (const [k, v] of regs) if (k !== c && mentions(v, c)) regs.delete(k);
    // Expressions that fold into themselves (loop bodies, hash mixes) grow exponentially; emit them as a statement instead.
    if (expr.length > MAX_EXPR) {
      push(`${c} = ${expr}`, curAddr);
      regs.set(c, c);
      return;
    }
    regs.set(c, expr);
  };
  const symbolic = (addr: number) => {
    const s = db.stringAt(addr);
    if (s) return JSON.stringify(s.value.slice(0, 60));
    const f = db.functionByAddr(addr);
    if (f) return db.nameFor(addr).name;
    const n = db.nameFor(addr);
    return n.source === "inferred" ? `&g_${addr.toString(16)}` : `&${n.name}`;
  };
  let pendingCmp: { a: string; b: string } | null = null;
  let pageRegs = new Map<string, number>();
  let indent = 1;
  const emit = (text: string, address?: number) => lines.push({ text, address, indent, kind: "code" });
  const push = (text: string, address: number) => emit(text + ";", address);
  /** Display name of a register: argument registers read as a1.. while they still hold the argument. */
  const regLabel = (c: string) => {
    const a = argIndex(c, argRegs);
    return a >= 0 && a <= maxArg ? `a${a + 1}` : c;
  };
  /**
   * End of a basic block: every register still holding a symbolic expression is
   * written out as an assignment (otherwise loop-carried updates such as
   * `x8 = hash(x8, byte)` would silently vanish), then the state is cleared.
   */
  const flush = (addr: number) => {
    for (const [k, v] of regs) if (!k.startsWith("local_") && v !== k && v !== regLabel(k)) push(`${regLabel(k)} = ${v}`, addr);
    reset();
  };

  let prevAddr = fn.addr;
  for (let idx = 0; idx < code.length; idx++) {
    const i = code[idx];
    curAddr = i.address;
    const blockEnd = prevAddr;
    prevAddr = i.address;
    if (targets.has(i.address)) {
      flush(blockEnd);
      lines.push({ text: `loc_${i.address.toString(16)}:`, indent: 0, kind: "label", address: i.address });
      pageRegs = new Map();
      // pendingCmp is kept: the fall-through predecessor's compare is the best available reading of the flags here.
    }
    const m = i.mnemonic;
    const o = i.operands;
    const d = o[0]?.reg ?? "";
    const c = db.comments.get(i.address);
    if (c) lines.push({ text: `// ${c}`, indent, kind: "comment", address: i.address });

    if (!isArm64) {
      // Generic rendering for secondary architectures
      if (i.kind === "call") push(`${symbolic(i.target ?? 0)}()`, i.address);
      else if (i.kind === "ret") push("return", i.address);
      else if (i.kind === "condjump") push(`if (${m}) goto loc_${(i.target ?? 0).toString(16)}`, i.address);
      else if (i.kind === "jump") push(`goto ${i.target !== undefined && db.contains(fn, i.target) ? `loc_${i.target.toString(16)}` : symbolic(i.target ?? 0)}`, i.address);
      else if (i.kind !== "nop" && i.kind !== "system") push(`${m} ${i.opText}`, i.address);
      continue;
    }

    // ---- Prologue / epilogue noise
    if ((m === "stp" || m === "ldp") && /\bsp\b/.test(o[2]?.text ?? "") && /x29|x30|x19|x2[0-8]/.test(d)) continue;
    if ((m === "str" || m === "ldr") && /\[sp/.test(o[1]?.text ?? "") && /x29|x30|x19|x2[0-8]/.test(d)) continue;
    if ((m === "sub" || m === "add") && d === "sp") continue;
    if (m === "mov" && d === "x29") continue;
    if (m === "paciasp" || m === "autiasp" || m === "bti" || m === "nop" || m === "hint" || m === "pacibsp" || m === "autibsp") continue;

    if (m === "adrp" && i.pageValue !== undefined) { pageRegs.set(d, i.pageValue); set(d, `0x${i.pageValue.toString(16)}`); continue; }
    if (m === "adr" && i.target !== undefined) { set(d, symbolic(i.target)); continue; }
    if (m === "add" && o.length === 3 && o[2].imm !== undefined && o[1].reg && pageRegs.has(o[1].reg)) {
      const addr = pageRegs.get(o[1].reg)! + o[2].imm;
      pageRegs.delete(o[1].reg);
      set(d, symbolic(addr));
      continue;
    }
    if (m === "mov" || m === "movz" || m === "movn") { set(d, o[1].imm !== undefined ? fmtImm(o[1].imm) : val(o[1].reg)); continue; }
    if (m === "movk" && o[1].imm !== undefined) {
      const sh = o[2]?.text.match(/#(\d+)/);
      const shift = sh ? +sh[1] : 0;
      const cur = val(d);
      const lit = parseLiteral(cur);
      if (lit !== null) {
        // movz/movk chains with known pieces fold into one constant (e.g. 0x811c9dc5 rather than (0x9dc5 | 0x811c0000)).
        const v = ((lit & ~(0xffffn << BigInt(shift))) | (BigInt(o[1].imm) << BigInt(shift))) & ((1n << 64n) - 1n);
        set(d, fmtBig(v));
      } else set(d, `(${cur} | ${fmtImm(o[1].imm * 2 ** shift)})`);
      continue;
    }
    const bin: Record<string, string> = { add: "+", sub: "-", mul: "*", and: "&", orr: "|", eor: "^", lsl: "<<", lsr: ">>", asr: ">>", udiv: "/", sdiv: "/", bic: "& ~", orn: "| ~", ror: ">>>" };
    if (bin[m] && o.length >= 3) {
      const rhs = o[2].imm !== undefined ? fmtImm(o[2].imm) : val(o[2].reg);
      const extra = o[3]?.text ? ` ${o[3].text}` : "";
      set(d, `(${val(o[1].reg)} ${bin[m]} ${rhs}${extra})`);
      continue;
    }
    if ((m === "adds" || m === "subs" || m === "ands") && o.length >= 3) {
      const rhs = o[2].imm !== undefined ? fmtImm(o[2].imm) : val(o[2].reg);
      const op = m === "adds" ? "+" : m === "subs" ? "-" : "&";
      const expr = `(${val(o[1].reg)} ${op} ${rhs})`;
      set(d, expr);
      pendingCmp = { a: expr, b: "0" };
      continue;
    }
    if (m === "madd" || m === "msub") { set(d, `(${val(o[3].reg)} ${m === "madd" ? "+" : "-"} ${val(o[1].reg)} * ${val(o[2].reg)})`); continue; }
    if (m === "neg") { set(d, `-${val(o[1].reg)}`); continue; }
    if (m === "mvn") { set(d, `~${val(o[1].reg)}`); continue; }
    if (/^(sxtw|sxth|sxtb|uxth|uxtb)$/.test(m)) { set(d, `(${{ sxtw: "int64_t)(int32_t", sxth: "int16_t", sxtb: "int8_t", uxth: "uint16_t", uxtb: "uint8_t" }[m]})${val(o[1].reg)}`); continue; }
    if (m === "ubfx" || m === "sbfx") { set(d, `((${val(o[1].reg)} >> ${o[2].imm}) & ${fmtImm(2 ** (o[3].imm ?? 1) - 1)})`); continue; }
    if (m === "cmp" || m === "cmn" || m === "tst") {
      const b = o[1].imm !== undefined ? fmtImm(o[1].imm) : val(o[1].reg);
      pendingCmp = m === "tst" ? { a: `(${val(o[0].reg)} & ${b})`, b: "0" } : { a: val(o[0].reg), b: m === "cmn" ? `-${b}` : b };
      continue;
    }
    if (m === "cset" || m === "csetm") { set(d, `(${condExpr(o[1].text, pendingCmp)})`); continue; }
    if (m === "csel" || m === "csinc" || m === "csinv" || m === "csneg" || m === "cinc" || m === "cneg" || m === "cinv") {
      const cond = condExpr(o[o.length - 1].text, pendingCmp);
      const a = val(o[1].reg), b = o.length === 4 ? val(o[2].reg) : val(o[1].reg);
      const alt = m === "csinc" ? `${b} + 1` : m === "csinv" ? `~${b}` : m === "csneg" ? `-${b}` : m === "cinc" ? `${a} + 1` : m === "cneg" ? `-${a}` : m === "cinv" ? `~${a}` : b;
      set(d, m.startsWith("ci") || m === "cneg" ? `(${cond} ? ${alt} : ${a})` : `(${cond} ? ${a} : ${alt})`);
      continue;
    }
    if (i.kind === "load" && o.length >= 2) {
      const mem = o[o.length - 1];
      if (i.targetIsData && i.target !== undefined) { set(d, `*(int64_t*)${symbolic(i.target)}`); continue; }
      if (mem.memBase && pageRegs.has(mem.memBase) && mem.memDisp !== undefined && !mem.text.includes("!")) {
        const addr = pageRegs.get(mem.memBase)! + mem.memDisp;
        // A load from a GOT slot yields the imported function/object itself.
        set(d, db.gotNames.get(addr) ?? globalName(db, addr));
        if (m === "ldp") set(o[1].reg!, db.gotNames.get(addr + 8) ?? globalName(db, addr + 8));
        continue;
      }
      const base = val(mem.memBase);
      const ty = loadType(m, d);
      const disp = mem.memDisp ?? 0;
      const expr = mem.memBase ? `*(${ty}*)(${base}${disp ? ` + 0x${disp.toString(16)}` : ""})` : `*(${ty}*)${mem.text}`;
      if (mem.memBase === "sp") set(d, `local_${(disp).toString(16)}`);
      else {
        // Materialise loads as statements when the value is complex, else keep symbolic.
        if (m === "ldp") { push(`${d} = ${expr}`, i.address); push(`${o[1].reg} = *(${ty}*)(${base} + 0x${(disp + 8).toString(16)})`, i.address); regs.delete(canon(d)); regs.delete(canon(o[1].reg!)); }
        else set(d, expr);
      }
      if (mem.text.includes("!") || mem.text.includes("], ")) set(mem.memBase!, `(${base} + ${disp})`);
      continue;
    }
    if (i.kind === "store" && o.length >= 2) {
      const mem = o[o.length - 1];
      const src = val(o[0].reg);
      const disp = mem.memDisp ?? 0;
      if (mem.memBase && pageRegs.has(mem.memBase) && !mem.text.includes("!")) {
        push(`${globalName(db, pageRegs.get(mem.memBase)! + disp)} = ${src}`, i.address);
        continue;
      }
      const base = val(mem.memBase);
      const ty = loadType(m, o[0].reg ?? "");
      if (mem.memBase === "sp") { set(`local_${disp.toString(16)}`, src); push(`local_${disp.toString(16)} = ${src}`, i.address); }
      else {
        push(`*(${ty}*)(${base}${disp ? ` + 0x${disp.toString(16)}` : ""}) = ${src}`, i.address);
        if (m === "stp") push(`*(${ty}*)(${base} + 0x${(disp + (ty.includes("64") ? 8 : 4)).toString(16)}) = ${val(o[1].reg)}`, i.address);
      }
      if (mem.text.includes("!") || mem.text.includes("], ")) set(mem.memBase!, `(${base} + ${disp})`);
      continue;
    }
    if (i.kind === "call" || i.kind === "indirect-call") {
      const viaReg = val(o[0]?.reg);
      const callee = i.kind === "call" && i.target !== undefined ? symbolic(i.target) : importNames.has(viaReg) ? viaReg : `(*${viaReg})`;
      const args: string[] = [];
      for (let k = 0; k < argRegs.length; k++) {
        const r = argRegs[k];
        if (regs.has(r) || regs.has(r.replace("x", "w"))) args.push(val(r));
        else if (k <= maxArg && args.length === k) args.push(`a${k + 1}`);
        else break;
      }
      push(`x0 = ${callee}(${args.join(", ")})`, i.address);
      // calls clobber caller-saved registers
      for (const k of [...regs.keys()]) if (/^[xw]([0-9]|1[0-8])$/.test(k) || k.startsWith("d") || k.startsWith("s")) regs.delete(k);
      regs.set("x0", "x0");
      pageRegs = new Map();
      pendingCmp = null;
      continue;
    }
    if (i.kind === "condjump") {
      const tgt = i.target ?? 0;
      const label = db.contains(fn, tgt) ? `loc_${tgt.toString(16)}` : symbolic(tgt);
      let cond: string;
      if (m === "cbz") cond = `${val(o[0].reg)} == 0`;
      else if (m === "cbnz") cond = `${val(o[0].reg)} != 0`;
      else if (m === "tbz") cond = `(${val(o[0].reg)} & ${fmtImm(2 ** (o[1].imm ?? 0))}) == 0`;
      else if (m === "tbnz") cond = `(${val(o[0].reg)} & ${fmtImm(2 ** (o[1].imm ?? 0))}) != 0`;
      else cond = condExpr(m.slice(2), pendingCmp);
      // The condition was built from the pre-flush expressions; pending assignments must precede the branch.
      flush(i.address);
      emit(`if (${cond}) goto ${label};`, i.address);
      continue;
    }
    if (i.kind === "jump") {
      const tgt = i.target ?? 0;
      if (db.contains(fn, tgt)) {
        flush(i.address);
        push(`goto loc_${tgt.toString(16)}`, i.address);
      } else {
        const args = argRegs.slice(0, Math.max(1, maxArg + 1)).map(val).join(", ");
        flush(i.address);
        push(`return ${symbolic(tgt)}(${args}) /* tail call */`, i.address);
      }
      continue;
    }
    if (i.kind === "indirect-jump") { const target = val(o[0].reg); flush(i.address); push(`goto *${target}`, i.address); continue; }
    if (i.kind === "ret") {
      const r = regs.has("x0") || regs.has("w0") ? val("x0") : maxArg >= 0 ? "x0" : "x0";
      push(retType === "void" ? "return" : `return ${r}`, i.address);
      reset();
      continue;
    }
    if (m === "brk") { push(`__builtin_trap() /* brk ${o[0]?.text ?? ""} */`, i.address); continue; }
    if (m === "svc") { push(`syscall(x8)`, i.address); continue; }
    if (m === "mrs") { set(d, o[1].text === "tpidr_el0" ? "__thread_pointer()" : `__mrs(${o[1].text})`); continue; }
    if (i.kind === "simd" || i.kind === "unknown") { push(`/* ${m} ${i.opText} */`, i.address); continue; }
    if (i.kind === "arith" || i.kind === "logic" || i.kind === "move") { if (d) set(d, `${m}(${o.slice(1).map((x) => x.imm !== undefined ? fmtImm(x.imm) : val(x.reg) || x.text).join(", ")})`); continue; }
    push(`/* ${m} ${i.opText} */`, i.address);
  }
  lines.push({ text: "}", indent: 0, kind: "code" });
  return lines;
}

function canon(r: string) {
  if (/^w\d+$/.test(r)) return "x" + r.slice(1);
  if (r === "wzr") return "xzr";
  if (r === "wsp") return "sp";
  return r;
}
function argIndex(r: string, argRegs: string[]) {
  const c = canon(r);
  return argRegs.indexOf(c);
}
function typeName(reg: string) {
  return reg?.startsWith("x") || reg?.startsWith("r") ? "int64_t" : "int64_t";
}
function fmtImm(v: number) {
  if (!Number.isFinite(v)) return "?";
  if (Math.abs(v) < 10) return String(v);
  return (v < 0 ? "-" : "") + "0x" + Math.abs(v).toString(16);
}
function fmtBig(v: bigint) {
  return v < 10n ? v.toString() : "0x" + v.toString(16);
}
/** Parse an expression produced by fmtImm/fmtBig back into a (non-negative) integer, or null if it is not a plain literal. */
function parseLiteral(expr: string): bigint | null {
  const m = expr.match(/^(0x[0-9a-f]+|\d+)$/i);
  if (!m) return null;
  try {
    return BigInt(m[1]);
  } catch {
    return null;
  }
}
function loadType(m: string, reg: string) {
  if (m.endsWith("b") || m.endsWith("sb")) return m.includes("s") && m !== "strb" ? "int8_t" : "uint8_t";
  if (m.endsWith("h") || m.endsWith("sh")) return m.includes("s") && m !== "strh" ? "int16_t" : "uint16_t";
  if (m === "ldrsw") return "int32_t";
  if (reg.startsWith("w")) return "uint32_t";
  if (reg.startsWith("s")) return "float";
  if (reg.startsWith("d")) return "double";
  if (reg.startsWith("q")) return "uint128_t";
  return "int64_t";
}
function condExpr(cond: string, cmp: { a: string; b: string } | null) {
  const c = cond.trim();
  const a = cmp?.a ?? "flags", b = cmp?.b ?? "0";
  const map: Record<string, string> = { eq: "==", ne: "!=", cs: ">=", hs: ">=", cc: "<", lo: "<", mi: "<", pl: ">=", vs: "overflow", vc: "!overflow", hi: ">", ls: "<=", ge: ">=", lt: "<", gt: ">", le: "<=", al: "true", nv: "false" };
  const op = map[c] ?? c;
  if (op === "true" || op === "false") return op;
  if (op.includes("overflow")) return `${op}(${a} - ${b})`;
  const unsigned = c === "cs" || c === "hs" || c === "cc" || c === "lo" || c === "hi" || c === "ls";
  return `${unsigned ? "(uint64_t)" : ""}${a} ${op} ${b}`;
}
function globalName(db: AnalysisDatabase, addr: number) {
  const s = db.stringAt(addr);
  if (s) return JSON.stringify(s.value.slice(0, 60));
  const n = db.nameFor(addr);
  return n.source === "inferred" ? `g_${addr.toString(16)}` : n.name;
}
