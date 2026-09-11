import type { ArchitectureProvider, InsnKind, Instruction, Operand } from "../types";

// ---------------------------------------------------------------------------
// AArch64 (A64) instruction decoder
// Covers the base integer ISA (data processing, branches, loads/stores,
// system), pointer-authentication hints, atomics and the commonly used scalar
// FP conversions. Everything else is decoded as an opaque SIMD/FP or unknown
// word so analysis can continue safely across it (all A64 encodings are 4 bytes).
// ---------------------------------------------------------------------------

const bits = (x: number, hi: number, lo: number) => (x >>> lo) & ((1 << (hi - lo + 1)) - 1 >>> 0);
const bit = (x: number, b: number) => (x >>> b) & 1;
const sext = (v: number, w: number) => (v & (1 << (w - 1)) ? v - 2 ** w : v);

const COND = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];
const invCond = (c: number) => COND[c ^ 1];
const SHIFT = ["lsl", "lsr", "asr", "ror"];
const EXTEND = ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"];

function xr(n: number, sp = false) {
  return n === 31 ? (sp ? "sp" : "xzr") : `x${n}`;
}
function wr(n: number, sp = false) {
  return n === 31 ? (sp ? "wsp" : "wzr") : `w${n}`;
}
const gr = (sf: number, n: number, sp = false) => (sf ? xr(n, sp) : wr(n, sp));
const fr = (t: string, n: number) => `${t}${n}`;

function immText(v: number) {
  if (v < 0) return `#-0x${(-v).toString(16)}`;
  return v < 10 ? `#${v}` : `#0x${v.toString(16)}`;
}
const R = (reg: string): Operand => ({ text: reg, reg });
const I = (v: number): Operand => ({ text: immText(v), imm: v });
const D = (v: number): Operand => ({ text: `#${v}`, imm: v });
const T = (text: string): Operand => ({ text });
const MEM = (base: string, disp: number, mode: "off" | "pre" | "post" = "off"): Operand => {
  let text: string;
  if (mode === "post") text = `[${base}], ${immText(disp)}`;
  else if (mode === "pre") text = `[${base}, ${immText(disp)}]!`;
  else text = disp === 0 ? `[${base}]` : `[${base}, ${immText(disp)}]`;
  return { text, memBase: base, memDisp: disp };
};

function ones(n: number): bigint {
  return (1n << BigInt(n)) - 1n;
}
function ror(v: bigint, r: number, size: number): bigint {
  if (r === 0) return v;
  const m = ones(size);
  return ((v >> BigInt(r)) | (v << BigInt(size - r))) & m;
}
/** DecodeBitMasks (logical immediates). Returns null for reserved encodings. */
function decodeBitMasks(N: number, imms: number, immr: number, sf: number): bigint | null {
  const datasize = sf ? 64 : 32;
  const v = (N << 6) | ((~imms) & 0x3f);
  let len = -1;
  for (let i = 6; i >= 0; i--) if (v & (1 << i)) { len = i; break; }
  if (len < 1) return null;
  const levels = (1 << len) - 1;
  const S = imms & levels;
  const Rr = immr & levels;
  if (S === levels) return null;
  const esize = 1 << len;
  const welem = ones(S + 1);
  let elem = ror(welem, Rr, esize);
  let wmask = 0n;
  for (let i = 0; i < datasize; i += esize) wmask |= elem << BigInt(i);
  wmask &= ones(datasize);
  return wmask;
}
function bigImmText(v: bigint) {
  return v < 10n ? `#${v}` : `#0x${v.toString(16)}`;
}

interface Dec {
  mnemonic: string;
  ops: Operand[];
  kind?: InsnKind;
  target?: number;
  targetIsData?: boolean;
  destReg?: string;
  pageValue?: number;
  fallsThrough?: boolean;
  prologue?: boolean;
}

function decodeWord(w: number, pc: number): Dec {
  const op0 = bits(w, 28, 25);
  // ---------------- Data processing (immediate) ----------------
  if ((op0 & 0b1110) === 0b1000) {
    const sf = bit(w, 31);
    const rd = bits(w, 4, 0);
    const rn = bits(w, 9, 5);
    const grp = bits(w, 25, 23);
    if ((grp & 0b110) === 0b000) {
      // PC-rel
      const immlo = bits(w, 30, 29);
      const immhi = bits(w, 23, 5);
      const imm = sext((immhi << 2) | immlo, 21);
      if (bit(w, 31)) {
        const page = (pc - (pc % 4096)) + imm * 4096;
        return { mnemonic: "adrp", ops: [R(xr(rd)), { text: `0x${page.toString(16)}`, imm: page }], kind: "adr", destReg: xr(rd), pageValue: page, target: page, targetIsData: true };
      }
      const tgt = pc + imm;
      return { mnemonic: "adr", ops: [R(xr(rd)), { text: `0x${tgt.toString(16)}`, imm: tgt }], kind: "adr", destReg: xr(rd), target: tgt, targetIsData: true };
    }
    if (grp === 0b010) {
      const op = bit(w, 30), S = bit(w, 29), sh = bit(w, 22);
      let imm = bits(w, 21, 10);
      if (sh) imm <<= 12;
      const name = op ? (S ? "subs" : "sub") : S ? "adds" : "add";
      if (!S && !op && !sh && imm === 0 && (rd === 31 || rn === 31)) {
        return { mnemonic: "mov", ops: [R(gr(sf, rd, true)), R(gr(sf, rn, true))], kind: "move" };
      }
      if (S && rd === 31) return { mnemonic: op ? "cmp" : "cmn", ops: [R(gr(sf, rn, true)), I(imm)], kind: "compare" };
      const dec: Dec = { mnemonic: name, ops: [R(gr(sf, rd, !S)), R(gr(sf, rn, true)), I(imm)], kind: "arith" };
      if (op && !S && rd === 31 && rn === 31 && sf) dec.prologue = true; // sub sp, sp, #N
      return dec;
    }
    if (grp === 0b100) {
      const opc = bits(w, 30, 29), N = bit(w, 22), immr = bits(w, 21, 16), imms = bits(w, 15, 10);
      const mask = decodeBitMasks(N, imms, immr, sf);
      if (mask === null || (!sf && N)) return { mnemonic: ".word", ops: [T(`0x${w.toString(16).padStart(8, "0")}`)], kind: "unknown" };
      const immOp: Operand = { text: bigImmText(mask), imm: Number(mask) };
      const names = ["and", "orr", "eor", "ands"];
      if (opc === 1 && rn === 31) return { mnemonic: "mov", ops: [R(gr(sf, rd, true)), immOp], kind: "move" };
      if (opc === 3 && rd === 31) return { mnemonic: "tst", ops: [R(gr(sf, rn)), immOp], kind: "compare" };
      return { mnemonic: names[opc], ops: [R(gr(sf, rd, opc !== 3)), R(gr(sf, rn)), immOp], kind: "logic" };
    }
    if (grp === 0b101) {
      const opc = bits(w, 30, 29), hw = bits(w, 22, 21), imm16 = bits(w, 20, 5);
      const shift = hw * 16;
      if (opc === 1 || (!sf && hw > 1)) return { mnemonic: ".word", ops: [T(`0x${w.toString(16)}`)], kind: "unknown" };
      const name = opc === 0 ? "movn" : opc === 2 ? "movz" : "movk";
      const ops: Operand[] = [R(gr(sf, rd)), I(imm16)];
      if (opc !== 3 && !(opc === 0 && imm16 === 0 && shift !== 0)) {
        // MOV alias with full value
        let big = BigInt(imm16) << BigInt(shift);
        if (opc === 0) big = sf ? ~big & ones(64) : ~big & ones(32);
        return { mnemonic: "mov", ops: [R(gr(sf, rd)), { text: `#0x${big.toString(16)}`, imm: Number(big) }], kind: "move", destReg: gr(sf, rd) };
      }
      if (shift) ops.push(T(`lsl #${shift}`));
      return { mnemonic: name, ops, kind: "move" };
    }
    if (grp === 0b110) {
      const opc = bits(w, 30, 29), immr = bits(w, 21, 16), imms = bits(w, 15, 10);
      const ds = sf ? 64 : 32;
      const Rd = R(gr(sf, rd)), Rn = R(gr(sf, rn));
      if (opc === 2) {
        if (imms !== ds - 1 && imms + 1 === immr) return { mnemonic: "lsl", ops: [Rd, Rn, D(ds - 1 - imms)], kind: "arith" };
        if (imms === ds - 1) return { mnemonic: "lsr", ops: [Rd, Rn, D(immr)], kind: "arith" };
        if (immr === 0 && imms === 7) return { mnemonic: "uxtb", ops: [Rd, R(wr(rn))], kind: "arith" };
        if (immr === 0 && imms === 15) return { mnemonic: "uxth", ops: [Rd, R(wr(rn))], kind: "arith" };
        if (imms >= immr) return { mnemonic: "ubfx", ops: [Rd, Rn, D(immr), D(imms - immr + 1)], kind: "arith" };
        return { mnemonic: "ubfiz", ops: [Rd, Rn, D((ds - immr) % ds), D(imms + 1)], kind: "arith" };
      }
      if (opc === 0) {
        if (imms === ds - 1) return { mnemonic: "asr", ops: [Rd, Rn, D(immr)], kind: "arith" };
        if (immr === 0 && imms === 7) return { mnemonic: "sxtb", ops: [Rd, R(wr(rn))], kind: "arith" };
        if (immr === 0 && imms === 15) return { mnemonic: "sxth", ops: [Rd, R(wr(rn))], kind: "arith" };
        if (immr === 0 && imms === 31 && sf) return { mnemonic: "sxtw", ops: [Rd, R(wr(rn))], kind: "arith" };
        if (imms >= immr) return { mnemonic: "sbfx", ops: [Rd, Rn, D(immr), D(imms - immr + 1)], kind: "arith" };
        return { mnemonic: "sbfiz", ops: [Rd, Rn, D((ds - immr) % ds), D(imms + 1)], kind: "arith" };
      }
      if (opc === 1) {
        if (imms >= immr) return { mnemonic: "bfxil", ops: [Rd, Rn, D(immr), D(imms - immr + 1)], kind: "arith" };
        if (rn === 31) return { mnemonic: "bfc", ops: [Rd, D((ds - immr) % ds), D(imms + 1)], kind: "arith" };
        return { mnemonic: "bfi", ops: [Rd, Rn, D((ds - immr) % ds), D(imms + 1)], kind: "arith" };
      }
    }
    if (grp === 0b111) {
      const rm = bits(w, 20, 16), imms = bits(w, 15, 10);
      if (rn === rm) return { mnemonic: "ror", ops: [R(gr(sf, rd)), R(gr(sf, rn)), D(imms)], kind: "arith" };
      return { mnemonic: "extr", ops: [R(gr(sf, rd)), R(gr(sf, rn)), R(gr(sf, rm)), D(imms)], kind: "arith" };
    }
    return unknown(w);
  }

  // ---------------- Branches, exceptions, system ----------------
  if ((op0 & 0b1110) === 0b1010) {
    const top6 = bits(w, 31, 26);
    if (top6 === 0b000101 || top6 === 0b100101) {
      const tgt = pc + sext(bits(w, 25, 0), 26) * 4;
      const isCall = top6 === 0b100101;
      return { mnemonic: isCall ? "bl" : "b", ops: [{ text: `0x${tgt.toString(16)}`, imm: tgt }], kind: isCall ? "call" : "jump", target: tgt, fallsThrough: isCall };
    }
    if (bits(w, 31, 24) === 0b01010100 && bit(w, 4) === 0) {
      const tgt = pc + sext(bits(w, 23, 5), 19) * 4;
      return { mnemonic: `b.${COND[bits(w, 3, 0)]}`, ops: [{ text: `0x${tgt.toString(16)}`, imm: tgt }], kind: "condjump", target: tgt };
    }
    if (bits(w, 30, 25) === 0b011010) {
      const tgt = pc + sext(bits(w, 23, 5), 19) * 4;
      return { mnemonic: bit(w, 24) ? "cbnz" : "cbz", ops: [R(gr(bit(w, 31), bits(w, 4, 0))), { text: `0x${tgt.toString(16)}`, imm: tgt }], kind: "condjump", target: tgt };
    }
    if (bits(w, 30, 25) === 0b011011) {
      const tgt = pc + sext(bits(w, 18, 5), 14) * 4;
      const bitno = (bit(w, 31) << 5) | bits(w, 23, 19);
      return { mnemonic: bit(w, 24) ? "tbnz" : "tbz", ops: [R(gr(bit(w, 31), bits(w, 4, 0))), D(bitno), { text: `0x${tgt.toString(16)}`, imm: tgt }], kind: "condjump", target: tgt };
    }
    if (bits(w, 31, 25) === 0b1101011) {
      const opc = bits(w, 24, 21), op3 = bits(w, 15, 10), rn = bits(w, 9, 5), op4 = bits(w, 4, 0);
      const auth = op3 === 0b000010 || op3 === 0b000011;
      const sfx = auth ? (op3 & 1 ? "ab" : "aa") : "";
      if (opc === 0) return { mnemonic: auth ? `bra${sfx}z` : "br", ops: [R(xr(rn))], kind: "indirect-jump", fallsThrough: false };
      if (opc === 1) return { mnemonic: auth ? `blra${sfx}z` : "blr", ops: [R(xr(rn))], kind: "indirect-call" };
      if (opc === 2) return { mnemonic: auth ? `reta${sfx}` : "ret", ops: rn === 30 || auth ? [] : [R(xr(rn))], kind: "ret", fallsThrough: false };
      if (opc === 4) return { mnemonic: "eret", ops: [], kind: "ret", fallsThrough: false };
      if (opc === 5) return { mnemonic: "drps", ops: [], kind: "system", fallsThrough: false };
      if (opc === 8) return { mnemonic: `bra${sfx}`, ops: [R(xr(rn)), R(xr(op4, true))], kind: "indirect-jump", fallsThrough: false };
      if (opc === 9) return { mnemonic: `blra${sfx}`, ops: [R(xr(rn)), R(xr(op4, true))], kind: "indirect-call" };
      return unknown(w);
    }
    if (bits(w, 31, 24) === 0b11010100) {
      const opc = bits(w, 23, 21), imm = bits(w, 20, 5), ll = bits(w, 1, 0);
      if (opc === 0 && ll === 1) return { mnemonic: "svc", ops: [I(imm)], kind: "system" };
      if (opc === 0 && ll === 2) return { mnemonic: "hvc", ops: [I(imm)], kind: "system" };
      if (opc === 0 && ll === 3) return { mnemonic: "smc", ops: [I(imm)], kind: "system" };
      if (opc === 1 && ll === 0) return { mnemonic: "brk", ops: [I(imm)], kind: "trap", fallsThrough: false };
      if (opc === 2 && ll === 0) return { mnemonic: "hlt", ops: [I(imm)], kind: "trap", fallsThrough: false };
      return unknown(w);
    }
    if (bits(w, 31, 22) === 0b1101010100) {
      const L = bit(w, 21), o0 = bits(w, 20, 19), op1 = bits(w, 18, 16), crn = bits(w, 15, 12), crm = bits(w, 11, 8), op2 = bits(w, 7, 5), rt = bits(w, 4, 0);
      if (o0 === 0 && crn === 2 && rt === 31 && L === 0) {
        if (crm === 0) {
          const h = ["nop", "yield", "wfe", "wfi", "sev", "sevl", "dgh", "xpaclri"][op2];
          return { mnemonic: h ?? "hint", ops: h ? [] : [I((crm << 3) | op2)], kind: h === "nop" ? "nop" : "system" };
        }
        if (crm === 3) {
          const h = ["paciaz", "paciasp", "pacibz", "pacibsp", "autiaz", "autiasp", "autibz", "autibsp"][op2];
          return { mnemonic: h, ops: [], kind: "system", prologue: op2 === 1 || op2 === 3 };
        }
        if (crm === 4 && (op2 & 1) === 0) {
          const t = ["", "c", "j", "jc"][op2 >> 1];
          return { mnemonic: "bti", ops: t ? [T(t)] : [], kind: "system", prologue: true };
        }
        if (crm === 2 && op2 === 0) return { mnemonic: "esb", ops: [], kind: "system" };
        if (crm === 2 && op2 === 1) return { mnemonic: "psb csync", ops: [], kind: "system" };
        return { mnemonic: "hint", ops: [I((crm << 3) | op2)], kind: "system" };
      }
      if (o0 === 0 && crn === 3 && L === 0) {
        const bar: Record<number, string> = { 2: "clrex", 4: "dsb", 5: "dmb", 6: "isb", 7: "sb" };
        const opt: Record<number, string> = { 15: "sy", 14: "st", 13: "ld", 11: "ish", 10: "ishst", 9: "ishld", 7: "nsh", 6: "nshst", 5: "nshld", 3: "osh", 2: "oshst", 1: "oshld" };
        const m = bar[op2];
        if (m) return { mnemonic: m, ops: m === "isb" || m === "clrex" || m === "sb" ? [] : [T(opt[crm] ?? `#${crm}`)], kind: "system" };
      }
      if (o0 === 0 && crn === 4 && L === 0) {
        const ps: Record<number, string> = { 3: "uao", 4: "pan", 5: "spsel", 6: "daifset", 7: "daifclr", 25: "dit" };
        return { mnemonic: "msr", ops: [T(ps[(op1 << 3) | op2] ?? `pstate_${op1}_${op2}`), I(crm)], kind: "system" };
      }
      if (o0 === 1 && L === 0) {
        return { mnemonic: "sys", ops: [I(op1), T(`c${crn}`), T(`c${crm}`), I(op2), R(xr(rt))], kind: "system" };
      }
      if (o0 === 1 && L === 1) return { mnemonic: "sysl", ops: [R(xr(rt)), I(op1), T(`c${crn}`), T(`c${crm}`), I(op2)], kind: "system" };
      // MRS / MSR (register)
      const key = `${2 + (o0 & 1)}_${op1}_${crn}_${crm}_${op2}`;
      const known: Record<string, string> = {
        "3_3_13_0_2": "tpidr_el0", "3_3_13_0_3": "tpidrro_el0", "3_3_4_2_0": "nzcv", "3_3_4_4_0": "fpcr", "3_3_4_4_1": "fpsr",
        "3_3_0_0_1": "ctr_el0", "3_3_0_0_7": "dczid_el0", "3_3_14_0_2": "cntvct_el0", "3_3_14_0_0": "cntfrq_el0", "3_3_14_0_1": "cntpct_el0",
        "3_0_0_0_0": "midr_el1", "3_0_13_0_4": "tpidr_el1", "3_3_4_2_1": "daif", "3_3_14_3_0": "cntv_tval_el0", "3_3_14_3_1": "cntv_ctl_el0", "3_3_14_3_2": "cntv_cval_el0",
      };
      const reg = known[key] ?? `s${2 + (o0 & 1)}_${op1}_c${crn}_c${crm}_${op2}`;
      return L ? { mnemonic: "mrs", ops: [R(xr(rt)), T(reg)], kind: "system" } : { mnemonic: "msr", ops: [T(reg), R(xr(rt))], kind: "system" };
    }
    return unknown(w);
  }

  // ---------------- Loads and stores ----------------
  if ((op0 & 0b0101) === 0b0100) {
    const size = bits(w, 31, 30), V = bit(w, 26), rt = bits(w, 4, 0), rn = bits(w, 9, 5);
    const b29_27 = bits(w, 29, 27);
    const Rn = xr(rn, true);
    // Load/store register pair
    if (b29_27 === 0b101) {
      const variant = bits(w, 24, 23), L = bit(w, 22), imm7 = sext(bits(w, 21, 15), 7), rt2 = bits(w, 14, 10), opc = size;
      let regName: (n: number) => string;
      let scale: number;
      let mnem = L ? "ldp" : "stp";
      if (V) {
        const t = ["s", "d", "q"][opc];
        if (!t) return unknown(w);
        regName = (n) => fr(t, n);
        scale = 4 << opc;
      } else if (opc === 0) { regName = (n) => wr(n); scale = 4; }
      else if (opc === 1) { if (!L) return unknown(w); regName = (n) => xr(n); scale = 4; mnem = "ldpsw"; }
      else if (opc === 2) { regName = (n) => xr(n); scale = 8; }
      else return unknown(w);
      if (variant === 0) mnem = L ? "ldnp" : "stnp";
      const disp = imm7 * scale;
      const mode = variant === 1 ? "post" : variant === 3 ? "pre" : "off";
      const dec: Dec = { mnemonic: mnem, ops: [R(regName(rt)), R(regName(rt2)), MEM(Rn, disp, mode)], kind: L ? "load" : "store" };
      if (!L && !V && rn === 31 && (rt === 29 || rt2 === 30) && (mode === "pre" || (mode === "off" && disp >= 0))) dec.prologue = true;
      return dec;
    }
    // Load/store literal
    if (b29_27 === 0b011 && bit(w, 24) === 0) {
      const opc = size;
      const tgt = pc + sext(bits(w, 23, 5), 19) * 4;
      const lbl: Operand = { text: `=0x${tgt.toString(16)}`, imm: tgt };
      if (V) {
        const t = ["s", "d", "q"][opc];
        if (!t) return unknown(w);
        return { mnemonic: "ldr", ops: [R(fr(t, rt)), lbl], kind: "load", target: tgt, targetIsData: true, destReg: fr(t, rt) };
      }
      if (opc === 0) return { mnemonic: "ldr", ops: [R(wr(rt)), lbl], kind: "load", target: tgt, targetIsData: true, destReg: wr(rt) };
      if (opc === 1) return { mnemonic: "ldr", ops: [R(xr(rt)), lbl], kind: "load", target: tgt, targetIsData: true, destReg: xr(rt) };
      if (opc === 2) return { mnemonic: "ldrsw", ops: [R(xr(rt)), lbl], kind: "load", target: tgt, targetIsData: true, destReg: xr(rt) };
      return { mnemonic: "prfm", ops: [I(rt), lbl], kind: "load", target: tgt, targetIsData: true };
    }
    // Load/store exclusive / acquire-release / CAS
    if (bits(w, 29, 24) === 0b001000) {
      const o2 = bit(w, 23), L = bit(w, 22), o1 = bit(w, 21), rs = bits(w, 20, 16), o0 = bit(w, 15), rt2 = bits(w, 14, 10);
      const sfx = ["b", "h", "", ""][size];
      const reg = size === 3 ? xr : wr;
      const MemN = MEM(Rn, 0);
      if (o1 && o2 === 1 && rt2 === 31) {
        // CAS: size 001000 1 L 1 Rs o0 11111 Rn Rt
        const acq = L ? "a" : "", rel = o0 ? "l" : "";
        return { mnemonic: `cas${acq}${rel}${sfx}`, ops: [R(reg(rs)), R(reg(rt)), MemN], kind: "store" };
      }
      if (o1 && o2 === 0 && size < 2 && rt2 === 31) {
        // CASP: 0 sz 001000 0 L 1 Rs o0 11111 Rn Rt
        const acq = L ? "a" : "", rel = o0 ? "l" : "";
        const pr = size === 1 ? xr : wr;
        return { mnemonic: `casp${acq}${rel}`, ops: [R(pr(rs)), R(pr(rs + 1)), R(pr(rt)), R(pr(rt + 1)), MemN], kind: "store" };
      }
      if (o2 === 1 && o1 === 0) {
        // LDAR/STLR (o0=1) or LDLAR/STLLR
        const m = L ? (o0 ? "ldar" : "ldlar") : o0 ? "stlr" : "stllr";
        return { mnemonic: `${m}${sfx}`, ops: [R(reg(rt)), MemN], kind: L ? "load" : "store" };
      }
      if (o2 === 0 && o1 === 0) {
        const m = L ? (o0 ? "ldaxr" : "ldxr") : o0 ? "stlxr" : "stxr";
        const ops = L ? [R(reg(rt)), MemN] : [R(wr(rs)), R(reg(rt)), MemN];
        return { mnemonic: `${m}${sfx}`, ops, kind: L ? "load" : "store" };
      }
      if (o2 === 0 && o1 === 1 && size >= 2) {
        const m = L ? (o0 ? "ldaxp" : "ldxp") : o0 ? "stlxp" : "stxp";
        const ops = L ? [R(reg(rt)), R(reg(rt2)), MemN] : [R(wr(rs)), R(reg(rt)), R(reg(rt2)), MemN];
        return { mnemonic: m, ops, kind: L ? "load" : "store" };
      }
      return unknown(w);
    }
    if (b29_27 === 0b111) {
      const opc = bits(w, 23, 22);
      if (bit(w, 24) === 0 && bit(w, 21) === 1 && bits(w, 11, 10) === 0b00 && !V) {
        // Atomic memory operations (LSE)
        const A = bit(w, 23), Rl = bit(w, 22), o3 = bit(w, 15), opc3 = bits(w, 14, 12), rs = bits(w, 20, 16);
        const sfx = ["b", "h", "", ""][size];
        const reg2 = size === 3 ? xr : wr;
        const ord = `${A ? "a" : ""}${Rl ? "l" : ""}`;
        if (o3 === 1 && opc3 === 0) return { mnemonic: `swp${ord}${sfx}`, ops: [R(reg2(rs)), R(reg2(rt)), MEM(Rn, 0)], kind: "store" };
        if (o3 === 0) {
          const nm = ["add", "clr", "eor", "set", "smax", "smin", "umax", "umin"][opc3];
          if (rt === 31 && !A) return { mnemonic: `st${nm}${ord}${sfx}`, ops: [R(reg2(rs)), MEM(Rn, 0)], kind: "store" };
          return { mnemonic: `ld${nm}${ord}${sfx}`, ops: [R(reg2(rs)), R(reg2(rt)), MEM(Rn, 0)], kind: "store" };
        }
        return unknown(w);
      }
      // Determine register/mnemonic from size/V/opc
      let mnem: string, reg: string, scale = size, isLoad = true;
      if (V) {
        const q = (opc & 2) !== 0;
        if (q && size !== 0) return unknown(w);
        const t = q ? "q" : ["b", "h", "s", "d"][size];
        scale = q ? 4 : size;
        isLoad = (opc & 1) === 1;
        mnem = isLoad ? "ldr" : "str";
        reg = fr(t, rt);
      } else if (size === 3 && opc === 2) {
        mnem = "prfm"; reg = ""; isLoad = true;
      } else {
        const table: Record<number, (string | null)[]> = {
          0: ["strb", "ldrb", "ldrsb", "ldrsb"],
          1: ["strh", "ldrh", "ldrsh", "ldrsh"],
          2: ["str", "ldr", "ldrsw", null],
          3: ["str", "ldr", null, null],
        };
        const m = table[size][opc];
        if (!m) return unknown(w);
        mnem = m;
        isLoad = opc !== 0;
        const wide = (size === 3) || (opc === 2 && size !== 3) || (opc === 2 && size === 2);
        reg = wide ? xr(rt) : wr(rt);
        if (size === 2 && opc === 2) reg = xr(rt); // ldrsw
      }
      const RtOp: Operand = mnem === "prfm" ? I(rt) : R(reg);
      if (bit(w, 24) === 1) {
        const imm12 = bits(w, 21, 10) << scale;
        const dec: Dec = { mnemonic: mnem, ops: [RtOp, MEM(Rn, imm12)], kind: isLoad ? "load" : "store", destReg: isLoad ? reg : undefined };
        return dec;
      }
      if (bit(w, 21) === 0) {
        const imm9 = sext(bits(w, 20, 12), 9);
        const sub = bits(w, 11, 10);
        if (sub === 0) return { mnemonic: mnem.replace(/^(ld|st)r/, "$1ur").replace("prfm", "prfum"), ops: [RtOp, MEM(Rn, imm9)], kind: isLoad ? "load" : "store", destReg: isLoad ? reg : undefined };
        if (sub === 2) return { mnemonic: mnem.replace(/^(ld|st)r/, "$1tr"), ops: [RtOp, MEM(Rn, imm9)], kind: isLoad ? "load" : "store" };
        const dec: Dec = { mnemonic: mnem, ops: [RtOp, MEM(Rn, imm9, sub === 1 ? "post" : "pre")], kind: isLoad ? "load" : "store", destReg: isLoad ? reg : undefined };
        if (!isLoad && rn === 31 && sub === 3 && (rt === 29 || rt === 30)) dec.prologue = true;
        return dec;
      }
      if (bits(w, 11, 10) === 0b10) {
        const rm = bits(w, 20, 16), option = bits(w, 15, 13), S = bit(w, 12);
        const rmName = (option & 1) ? xr(rm) : wr(rm);
        let ext = "";
        if (option === 3) { if (S) ext = `, lsl #${scale}`; }
        else ext = `, ${EXTEND[option]}${S ? ` #${scale}` : ""}`;
        return { mnemonic: mnem, ops: [RtOp, { text: `[${Rn}, ${rmName}${ext}]`, memBase: Rn }], kind: isLoad ? "load" : "store" };
      }
      return unknown(w);
    }
    // Advanced SIMD load/store structures
    if (bits(w, 29, 27) === 0b011 && bit(w, 24) === 1) return { mnemonic: "simd.ldst", ops: [T(`0x${w.toString(16).padStart(8, "0")}`)], kind: "simd" };
    if (bits(w, 31, 30) === 0 && bits(w, 29, 26) === 0b0011 && bit(w, 24) === 0) {
      const L = bit(w, 22);
      return { mnemonic: L ? "ld1" : "st1", ops: [T(`{v${rt}}`), MEM(Rn, 0)], kind: "simd" };
    }
    return unknown(w);
  }

  // ---------------- Data processing (register) ----------------
  if ((op0 & 0b0111) === 0b0101) {
    const sf = bit(w, 31), rd = bits(w, 4, 0), rn = bits(w, 9, 5), rm = bits(w, 20, 16);
    const Rd = R(gr(sf, rd)), Rn = R(gr(sf, rn)), Rm = R(gr(sf, rm));
    if (bit(w, 28) === 0) {
      const shift = bits(w, 23, 22), imm6 = bits(w, 15, 10);
      const shOp = imm6 ? T(`${SHIFT[shift]} #${imm6}`) : null;
      const withShift = (ops: Operand[]) => (shOp ? [...ops, shOp] : ops);
      if (bit(w, 24) === 0) {
        const opc = bits(w, 30, 29), N = bit(w, 21);
        const names = [["and", "bic"], ["orr", "orn"], ["eor", "eon"], ["ands", "bics"]];
        if (opc === 1 && rn === 31 && !N && !imm6) return { mnemonic: "mov", ops: [Rd, Rm], kind: "move" };
        if (opc === 1 && rn === 31 && N) return { mnemonic: "mvn", ops: withShift([Rd, Rm]), kind: "logic" };
        if (opc === 3 && rd === 31) return { mnemonic: N ? "bics" : "tst", ops: withShift([Rn, Rm]), kind: "compare" };
        return { mnemonic: names[opc][N], ops: withShift([Rd, Rn, Rm]), kind: "logic" };
      }
      const op = bit(w, 30), S = bit(w, 29);
      if (bit(w, 21) === 0) {
        if (S && rd === 31) return { mnemonic: op ? "cmp" : "cmn", ops: withShift([Rn, Rm]), kind: "compare" };
        if (op && rn === 31) return { mnemonic: S ? "negs" : "neg", ops: withShift([Rd, Rm]), kind: "arith" };
        return { mnemonic: op ? (S ? "subs" : "sub") : S ? "adds" : "add", ops: withShift([Rd, Rn, Rm]), kind: "arith" };
      }
      const option = bits(w, 15, 13), imm3 = bits(w, 12, 10);
      const rmE = (option & 3) === 3 ? gr(sf, rm) : wr(rm);
      const extText = `${EXTEND[option]}${imm3 ? ` #${imm3}` : ""}`;
      const ops = [R(gr(sf, rd, !S)), R(gr(sf, rn, true)), R(rmE), T(extText)];
      if (S && rd === 31) return { mnemonic: op ? "cmp" : "cmn", ops: ops.slice(1), kind: "compare" };
      return { mnemonic: op ? (S ? "subs" : "sub") : S ? "adds" : "add", ops, kind: "arith" };
    }
    const op = bit(w, 30), S = bit(w, 29);
    const sub = bits(w, 24, 21);
    if (bit(w, 24) === 0) {
      if (sub === 0 && bits(w, 15, 10) === 0) return { mnemonic: op ? (S ? "sbcs" : "sbc") : S ? "adcs" : "adc", ops: [Rd, Rn, Rm], kind: "arith" };
      if (sub === 2 && S) {
        const cond = COND[bits(w, 15, 12)], nzcv = bits(w, 3, 0);
        const second = bit(w, 11) ? I(rm) : Rm;
        return { mnemonic: op ? "ccmp" : "ccmn", ops: [Rn, second, I(nzcv), T(cond)], kind: "compare" };
      }
      if (sub === 4 && !S) {
        const cond = bits(w, 15, 12), op2 = bits(w, 11, 10);
        const c = COND[cond];
        if (!op && op2 === 0) return { mnemonic: "csel", ops: [Rd, Rn, Rm, T(c)], kind: "move" };
        if (!op && op2 === 1) {
          if (rn === 31 && rm === 31 && cond < 14) return { mnemonic: "cset", ops: [Rd, T(invCond(cond))], kind: "move" };
          if (rn === rm && cond < 14) return { mnemonic: "cinc", ops: [Rd, Rn, T(invCond(cond))], kind: "move" };
          return { mnemonic: "csinc", ops: [Rd, Rn, Rm, T(c)], kind: "move" };
        }
        if (op && op2 === 0) {
          if (rn === 31 && rm === 31 && cond < 14) return { mnemonic: "csetm", ops: [Rd, T(invCond(cond))], kind: "move" };
          if (rn === rm && cond < 14) return { mnemonic: "cinv", ops: [Rd, Rn, T(invCond(cond))], kind: "move" };
          return { mnemonic: "csinv", ops: [Rd, Rn, Rm, T(c)], kind: "move" };
        }
        if (op && op2 === 1) {
          if (rn === rm && cond < 14) return { mnemonic: "cneg", ops: [Rd, Rn, T(invCond(cond))], kind: "move" };
          return { mnemonic: "csneg", ops: [Rd, Rn, Rm, T(c)], kind: "move" };
        }
      }
      if (sub === 6) {
        const opcode = bits(w, 15, 10);
        if (op === 0) {
          const two: Record<number, string> = { 2: "udiv", 3: "sdiv", 8: "lsl", 9: "lsr", 10: "asr", 11: "ror", 16: "crc32b", 17: "crc32h", 18: "crc32w", 19: "crc32x", 20: "crc32cb", 21: "crc32ch", 22: "crc32cw", 23: "crc32cx", 0: "subp", 4: "irg", 5: "gmi", 12: "pacga" };
          const m = two[opcode];
          if (m) return { mnemonic: m, ops: [Rd, Rn, Rm], kind: "arith" };
          return unknown(w);
        }
        if (bits(w, 20, 16) === 0) {
          const one: Record<number, string> = { 0: "rbit", 1: "rev16", 2: sf ? "rev32" : "rev", 3: "rev", 4: "clz", 5: "cls" };
          const m = one[opcode];
          if (m) return { mnemonic: m, ops: [Rd, Rn], kind: "arith" };
        }
        if (bits(w, 20, 16) === 1 && sf) {
          const pac = ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb", "paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd"][opcode];
          if (pac) return { mnemonic: pac, ops: opcode < 8 ? [Rd, R(xr(rn, true))] : [Rd], kind: "system" };
        }
        return unknown(w);
      }
      return unknown(w);
    }
    // 3-source
    const op31 = bits(w, 23, 21), o0 = bit(w, 15), ra = bits(w, 14, 10);
    const Ra = R(gr(sf, ra));
    if (op31 === 0) {
      if (ra === 31) return { mnemonic: o0 ? "mneg" : "mul", ops: [Rd, Rn, Rm], kind: "arith" };
      return { mnemonic: o0 ? "msub" : "madd", ops: [Rd, Rn, Rm, Ra], kind: "arith" };
    }
    if (sf) {
      const Wn = R(wr(rn)), Wm = R(wr(rm));
      if (op31 === 1) return ra === 31 ? { mnemonic: o0 ? "smnegl" : "smull", ops: [Rd, Wn, Wm], kind: "arith" } : { mnemonic: o0 ? "smsubl" : "smaddl", ops: [Rd, Wn, Wm, Ra], kind: "arith" };
      if (op31 === 2 && !o0) return { mnemonic: "smulh", ops: [Rd, Rn, Rm], kind: "arith" };
      if (op31 === 5) return ra === 31 ? { mnemonic: o0 ? "umnegl" : "umull", ops: [Rd, Wn, Wm], kind: "arith" } : { mnemonic: o0 ? "umsubl" : "umaddl", ops: [Rd, Wn, Wm, Ra], kind: "arith" };
      if (op31 === 6 && !o0) return { mnemonic: "umulh", ops: [Rd, Rn, Rm], kind: "arith" };
    }
    return unknown(w);
  }

  // ---------------- SIMD & FP ----------------
  if ((op0 & 0b0111) === 0b0111) {
    const rd = bits(w, 4, 0), rn = bits(w, 9, 5), rm = bits(w, 20, 16);
    // Scalar floating point (bits 28:24 = 11110, bit 21 = 1, bit 31=0, bit29 = 0)
    if (bits(w, 28, 24) === 0b11110 && bit(w, 21) === 1 && bit(w, 29) === 0) {
      const ptype = bits(w, 23, 22);
      const t = ["s", "d", "?", "h"][ptype];
      const sf = bit(w, 31);
      if (bit(w, 31) === 0 && bits(w, 11, 10) === 0b10 && bit(w, 21) === 1 && bits(w, 15, 12) <= 8) {
        // Data processing 2-source
        const m = ["fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"][bits(w, 15, 12)];
        return { mnemonic: m, ops: [R(fr(t, rd)), R(fr(t, rn)), R(fr(t, rm))], kind: "arith" };
      }
      if (bit(w, 31) === 0 && bits(w, 14, 10) === 0b10000) {
        const opcode = bits(w, 20, 15);
        const one: Record<number, string> = { 0: "fmov", 1: "fabs", 2: "fneg", 3: "fsqrt", 4: "fcvt", 5: "fcvt", 7: "fcvt", 8: "frintn", 9: "frintp", 10: "frintm", 11: "frintz", 12: "frinta", 14: "frintx", 15: "frinti" };
        const m = one[opcode];
        if (m) {
          const dt = m === "fcvt" ? ["s", "d", "?", "h"][opcode & 3] : t;
          return { mnemonic: m, ops: [R(fr(dt, rd)), R(fr(t, rn))], kind: "move" };
        }
      }
      if (bit(w, 31) === 0 && bits(w, 13, 10) === 0b1000 && bits(w, 15, 14) === 0) {
        const opc2 = bits(w, 4, 0);
        const e = opc2 & 0x10 ? "fcmpe" : "fcmp";
        return { mnemonic: e, ops: [R(fr(t, rn)), opc2 & 8 ? T("#0.0") : R(fr(t, rm))], kind: "compare" };
      }
      if (bit(w, 31) === 0 && bits(w, 12, 10) === 0b100 && bits(w, 9, 5) === 0) {
        const imm8 = bits(w, 20, 13);
        const value = fpImm8Value(imm8);
        return { mnemonic: "fmov", ops: [R(fr(t, rd)), { text: `#${Number.isInteger(value) ? value.toFixed(1) : value}`, imm: value }], kind: "move" };
      }
      if (bits(w, 11, 10) === 0b11 && bit(w, 31) === 0) {
        return { mnemonic: "fcsel", ops: [R(fr(t, rd)), R(fr(t, rn)), R(fr(t, rm)), T(COND[bits(w, 15, 12)])], kind: "move" };
      }
      if (bits(w, 15, 10) === 0) {
        const rmode = bits(w, 20, 19), opcode = bits(w, 18, 16);
        const G = R(gr(sf, rd)), Gn = R(gr(sf, rn));
        if (rmode === 0 && opcode === 2) return { mnemonic: "scvtf", ops: [R(fr(t, rd)), Gn], kind: "move" };
        if (rmode === 0 && opcode === 3) return { mnemonic: "ucvtf", ops: [R(fr(t, rd)), Gn], kind: "move" };
        if (rmode === 3 && opcode === 0) return { mnemonic: "fcvtzs", ops: [G, R(fr(t, rn))], kind: "move" };
        if (rmode === 3 && opcode === 1) return { mnemonic: "fcvtzu", ops: [G, R(fr(t, rn))], kind: "move" };
        if (rmode === 0 && opcode === 6) return { mnemonic: "fmov", ops: [G, R(fr(t, rn))], kind: "move" };
        if (rmode === 0 && opcode === 7) return { mnemonic: "fmov", ops: [R(fr(t, rd)), Gn], kind: "move" };
        if (rmode === 1 && opcode === 6 && sf) return { mnemonic: "fmov", ops: [G, T(`v${rn}.d[1]`)], kind: "move" };
        if (rmode === 1 && opcode === 7 && sf) return { mnemonic: "fmov", ops: [T(`v${rd}.d[1]`), Gn], kind: "move" };
        const rnd = ["n", "p", "m", "z"][rmode];
        if (opcode === 0) return { mnemonic: `fcvt${rnd}s`, ops: [G, R(fr(t, rn))], kind: "move" };
        if (opcode === 1) return { mnemonic: `fcvt${rnd}u`, ops: [G, R(fr(t, rn))], kind: "move" };
        if (opcode === 4) return { mnemonic: "fcvtas", ops: [G, R(fr(t, rn))], kind: "move" };
        if (opcode === 5) return { mnemonic: "fcvtau", ops: [G, R(fr(t, rn))], kind: "move" };
      }
    }
    // FP data-processing 3-source (fmadd etc.)
    if (bits(w, 28, 24) === 0b11111 && bit(w, 31) === 0 && bit(w, 29) === 0) {
      const t = ["s", "d", "?", "h"][bits(w, 23, 22)];
      const o1 = bit(w, 21), o0 = bit(w, 15), ra = bits(w, 14, 10);
      const m = [["fmadd", "fmsub"], ["fnmadd", "fnmsub"]][o1][o0];
      return { mnemonic: m, ops: [R(fr(t, rd)), R(fr(t, rn)), R(fr(t, rm)), R(fr(t, ra))], kind: "arith" };
    }
    // Common vector ops used by compilers: movi, eor v, orr v (mov), dup, ins, umov, cnt, addv, uaddlv
    if (bits(w, 31, 24) === 0b01001110 && bits(w, 23, 21) === 0b101 && bits(w, 15, 10) === 0b000111 && rn === rm) {
      return { mnemonic: "mov", ops: [T(`v${rd}.16b`), T(`v${rn}.16b`)], kind: "simd" };
    }
    if (bits(w, 31, 24) === 0b01101110 && bits(w, 23, 21) === 0b001 && bits(w, 15, 10) === 0b000111) {
      return { mnemonic: "eor", ops: [T(`v${rd}.16b`), T(`v${rn}.16b`), T(`v${rm}.16b`)], kind: "simd" };
    }
    if (bits(w, 30, 24) === 0b0001111 && bit(w, 31) === 0 && bits(w, 15, 10) === 0b000001 && bits(w, 20, 16) === 0) {
      return { mnemonic: "movi", ops: [T(`v${rd}.2d`), I(0)], kind: "simd" };
    }
    return { mnemonic: "simd", ops: [T(`0x${w.toString(16).padStart(8, "0")}`)], kind: "simd" };
  }
  return unknown(w);
}

/** VFPExpandImm for the 8-bit FMOV immediate: sign(7) exp(6:4) frac(3:0). */
function fpImm8Value(imm8: number): number {
  const sign = imm8 & 0x80 ? -1 : 1;
  const frac = imm8 & 0xf;
  const e3 = (imm8 >> 4) & 7;
  const e = (e3 ^ 4) - 3;
  return sign * (1 + frac / 16) * 2 ** e;
}

function unknown(w: number): Dec {
  return { mnemonic: ".word", ops: [T(`0x${w.toString(16).padStart(8, "0")}`)], kind: "unknown" };
}

export class Arm64Provider implements ArchitectureProvider {
  readonly id = "arm64" as const;
  readonly displayName = "ARM64 / AArch64";
  readonly bits = 64 as const;
  readonly insnSize = 4;
  readonly alignment = 4;
  readonly returnRegister = "x0";
  readonly argumentRegisters = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
  readonly stackPointer = "sp";
  readonly linkRegister = "x30";

  decode(bytes: Uint8Array, offset: number, address: number, littleEndian = true): Instruction {
    if (offset + 4 > bytes.length) {
      return { address, size: Math.max(1, bytes.length - offset), mnemonic: ".byte", operands: [], opText: "", kind: "unknown", fallsThrough: true, raw: 0 };
    }
    const w = littleEndian
      ? (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
      : ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
    let d: Dec;
    try {
      d = decodeWord(w, address);
    } catch {
      d = unknown(w);
    }
    const kind = d.kind ?? "unknown";
    const fallsThrough = d.fallsThrough ?? !(kind === "jump" || kind === "ret" || kind === "indirect-jump" || kind === "trap");
    return {
      address,
      size: 4,
      mnemonic: d.mnemonic,
      operands: d.ops,
      opText: d.ops.map((o) => o.text).join(", "),
      kind,
      target: d.target,
      targetIsData: d.targetIsData,
      destReg: d.destReg,
      pageValue: d.pageValue,
      fallsThrough,
      prologue: d.prologue,
      raw: w,
    };
  }

  prologueScore(insns: Instruction[]): number {
    if (!insns.length) return 0;
    const first = insns[0];
    let score = 0;
    const m = first.mnemonic;
    if (m === "paciasp" || m === "pacibsp" || m === "bti") score += 0.6;
    if (m === "stp" && first.prologue) score += 0.7;
    if (m === "sub" && first.prologue) score += 0.55;
    if (m === "str" && first.prologue) score += 0.5;
    // Secondary evidence in the first few instructions
    for (let i = 1; i < Math.min(insns.length, 4); i++) {
      const x = insns[i];
      if (x.mnemonic === "stp" && x.prologue) score += 0.25;
      if (x.mnemonic === "mov" && x.opText.startsWith("x29, sp")) score += 0.25;
      if (x.mnemonic === "add" && x.opText.startsWith("x29, sp")) score += 0.25;
    }
    // Leaf functions frequently begin with adrp/ldr/cbz/mov — weak evidence
    if (score === 0 && (m === "adrp" || m === "cbz" || m === "cbnz" || m === "mov" || m === "ldr" || m === "cmp")) score = 0.15;
    return Math.min(1, score);
  }

  fuseDataRefs(insns: Instruction[]) {
    const out: { from: number; to: number; kind: "read" | "write" | "address" }[] = [];
    const pages = new Map<string, { page: number; at: number }>();
    for (const ins of insns) {
      if (ins.mnemonic === "adrp" && ins.destReg && ins.pageValue !== undefined) {
        pages.set(ins.destReg, { page: ins.pageValue, at: ins.address });
        continue;
      }
      if (ins.mnemonic === "adr" && ins.target !== undefined) {
        out.push({ from: ins.address, to: ins.target, kind: "address" });
        if (ins.destReg) pages.delete(ins.destReg);
        continue;
      }
      if (ins.kind === "load" && ins.targetIsData && ins.target !== undefined) {
        out.push({ from: ins.address, to: ins.target, kind: "read" });
        if (ins.destReg) pages.delete(ins.destReg);
        continue;
      }
      if (pages.size) {
        const ops = ins.operands;
        if (ins.mnemonic === "add" && ops.length === 3 && ops[2].imm !== undefined && ops[1].reg && pages.has(ops[1].reg)) {
          const p = pages.get(ops[1].reg)!;
          out.push({ from: ins.address, to: p.page + ops[2].imm, kind: "address" });
          pages.delete(ops[1].reg);
          if (ops[0].reg) pages.delete(ops[0].reg);
          continue;
        }
        if ((ins.kind === "load" || ins.kind === "store") && ops.length >= 2) {
          const mem = ops[ops.length - 1];
          if (mem.memBase && pages.has(mem.memBase) && mem.memDisp !== undefined && !mem.text.includes("!") && !mem.text.includes("], ")) {
            const p = pages.get(mem.memBase)!;
            out.push({ from: ins.address, to: p.page + mem.memDisp, kind: ins.kind === "load" ? "read" : "write" });
          }
        }
        // Register overwrite invalidates pending pages
        if (ins.destReg && pages.has(ins.destReg)) pages.delete(ins.destReg);
        if (ops.length && ops[0].reg && pages.has(ops[0].reg) && ins.kind !== "store" && ins.kind !== "compare") pages.delete(ops[0].reg);
        if (ins.kind === "call" || ins.kind === "indirect-call") {
          for (let i = 0; i <= 18; i++) pages.delete(`x${i}`);
        }
      }
    }
    return out;
  }

  syntaxClass(m: string) {
    if (m === "bl" || m === "blr" || m.startsWith("blra")) return "call" as const;
    if (m === "ret" || m.startsWith("reta") || m === "eret") return "ret" as const;
    if (m === "b" || m.startsWith("b.") || m === "br" || m.startsWith("cb") || m.startsWith("tb") || m.startsWith("bra")) return "branch" as const;
    if (/^(ld|st|prf|swp|cas)/.test(m)) return "mem" as const;
    if (m === "cmp" || m === "cmn" || m === "tst" || m.startsWith("ccm") || m.startsWith("fcmp")) return "cmp" as const;
    if (m === "mov" || m === "movz" || m === "movk" || m === "movn" || m === "adrp" || m === "adr" || m.startsWith("cs") || m === "fmov") return "mov" as const;
    if (/^(nop|mrs|msr|svc|brk|hint|dmb|dsb|isb|bti|pac|aut|hlt|yield|wfe|wfi|sev)/.test(m)) return "sys" as const;
    return "arith" as const;
  }
}
