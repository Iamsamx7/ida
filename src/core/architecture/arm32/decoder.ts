import type { ArchitectureProvider, InsnKind, Instruction, Operand } from "../types";

// ---------------------------------------------------------------------------
// ARM (A32) decoder — secondary architecture.
// Decodes the common subset (branches, data processing, single/multiple
// loads/stores) needed for function discovery and cross references. Thumb
// code is not decoded yet; unknown words are emitted as `.word`.
// ---------------------------------------------------------------------------

const bits = (x: number, hi: number, lo: number) => (x >>> lo) & ((1 << (hi - lo + 1)) - 1 >>> 0);
const bit = (x: number, b: number) => (x >>> b) & 1;
const sext = (v: number, w: number) => (v & (1 << (w - 1)) ? v - 2 ** w : v);
const COND = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv"];
const REG = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"];
const DP = ["and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"];
const SH = ["lsl", "lsr", "asr", "ror"];
const R = (n: number): Operand => ({ text: REG[n], reg: REG[n] });
const I = (v: number): Operand => ({ text: v < 0 ? `#-0x${(-v).toString(16)}` : v < 10 ? `#${v}` : `#0x${v.toString(16)}`, imm: v });
const T = (text: string): Operand => ({ text });
const rotr32 = (v: number, r: number) => (((v >>> r) | (v << (32 - r))) >>> 0);

function regList(mask: number) {
  const r: string[] = [];
  for (let i = 0; i < 16; i++) if (mask & (1 << i)) r.push(REG[i]);
  return `{${r.join(", ")}}`;
}

function shiftedReg(w: number): Operand[] {
  const rm = bits(w, 3, 0);
  const type = bits(w, 6, 5);
  if (bit(w, 4)) return [R(rm), T(`${SH[type]} ${REG[bits(w, 11, 8)]}`)];
  const amt = bits(w, 11, 7);
  if (amt === 0 && type === 0) return [R(rm)];
  if (amt === 0 && type === 3) return [R(rm), T("rrx")];
  return [R(rm), T(`${SH[type]} #${amt === 0 ? 32 : amt}`)];
}

export class Arm32Provider implements ArchitectureProvider {
  readonly id = "arm32" as const;
  readonly displayName = "ARM32 (A32)";
  readonly bits = 32 as const;
  readonly insnSize = 4;
  readonly alignment = 4;
  readonly returnRegister = "r0";
  readonly argumentRegisters = ["r0", "r1", "r2", "r3"];
  readonly stackPointer = "sp";
  readonly linkRegister = "lr";

  decode(bytes: Uint8Array, offset: number, address: number, littleEndian = true): Instruction {
    if (offset + 4 > bytes.length) return { address, size: 1, mnemonic: ".byte", operands: [], opText: "", kind: "unknown", fallsThrough: true, raw: 0 };
    const w = littleEndian
      ? (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
      : ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
    let mnemonic = ".word";
    let ops: Operand[] = [T(`0x${w.toString(16).padStart(8, "0")}`)];
    let kind: InsnKind = "unknown";
    let target: number | undefined;
    let targetIsData: boolean | undefined;
    let fallsThrough = true;
    let prologue = false;
    /** For `ldr rX, [pc, #n]`: the register loaded and the literal word itself, so fusion can resolve `add rX, pc, rX` later. */
    let destReg: string | undefined;
    let pageValue: number | undefined;
    const cond = bits(w, 31, 28);
    const c = COND[cond];
    const pc = address + 8;
    try {
      if (cond === 15) {
        if (bits(w, 27, 25) === 0b101) {
          // BLX imm
          const imm = sext(bits(w, 23, 0), 24) * 4 + (bit(w, 24) << 1);
          target = ((pc + imm) & ~3) >>> 0; // keep unsigned above 0x80000000
          mnemonic = "blx"; ops = [{ text: `0x${target.toString(16)}`, imm: target }]; kind = "call";
        }
      } else if (bits(w, 27, 25) === 0b101) {
        const L = bit(w, 24);
        target = pc + sext(bits(w, 23, 0), 24) * 4;
        mnemonic = (L ? "bl" : "b") + c;
        ops = [{ text: `0x${target.toString(16)}`, imm: target }];
        kind = L ? "call" : cond === 14 ? "jump" : "condjump";
        fallsThrough = L === 1 || cond !== 14;
      } else if (bits(w, 27, 4) === 0b000100101111111111110001) {
        mnemonic = "bx" + c; ops = [R(bits(w, 3, 0))]; kind = bits(w, 3, 0) === 14 ? "ret" : "indirect-jump"; fallsThrough = cond !== 14;
      } else if (bits(w, 27, 4) === 0b000100101111111111110011) {
        mnemonic = "blx" + c; ops = [R(bits(w, 3, 0))]; kind = "indirect-call";
      } else if (bits(w, 27, 25) === 0b100) {
        const P = bit(w, 24), U = bit(w, 23), Wb = bit(w, 21), L = bit(w, 20), rn = bits(w, 19, 16), list = bits(w, 15, 0);
        const mode = ["da", "ia", "db", "ib"][(P << 1) | U];
        if (rn === 13 && Wb && L && P === 0 && U === 1) { mnemonic = "pop" + c; ops = [T(regList(list))]; kind = list & 0x8000 ? "ret" : "load"; fallsThrough = !(list & 0x8000) || cond !== 14; }
        else if (rn === 13 && Wb && !L && P === 1 && U === 0) { mnemonic = "push" + c; ops = [T(regList(list))]; kind = "store"; prologue = (list & 0x4000) !== 0; }
        else { mnemonic = (L ? "ldm" : "stm") + mode + c; ops = [{ text: REG[rn] + (Wb ? "!" : ""), reg: REG[rn] }, T(regList(list))]; kind = L ? "load" : "store"; if (L && list & 0x8000) { kind = "ret"; fallsThrough = cond !== 14; } }
      } else if (bits(w, 27, 26) === 0b01) {
        const Imm = bit(w, 25), P = bit(w, 24), U = bit(w, 23), B = bit(w, 22), Wb = bit(w, 21), L = bit(w, 20), rn = bits(w, 19, 16), rt = bits(w, 15, 12);
        mnemonic = (L ? "ldr" : "str") + (B ? "b" : "") + c;
        kind = L ? "load" : "store";
        let mem: Operand;
        if (!Imm) {
          const off = bits(w, 11, 0) * (U ? 1 : -1);
          if (P) mem = { text: off === 0 ? `[${REG[rn]}]` : `[${REG[rn]}, #${off < 0 ? "-" : ""}0x${Math.abs(off).toString(16)}]${Wb ? "!" : ""}`, memBase: REG[rn], memDisp: off };
          else mem = { text: `[${REG[rn]}], #${off < 0 ? "-" : ""}0x${Math.abs(off).toString(16)}`, memBase: REG[rn], memDisp: off };
          if (rn === 15 && P) {
            target = ((pc & ~3) >>> 0) + off; targetIsData = true; mem.text = `=0x${target.toString(16)}`;
            // Read the literal word now: the pool sits at the function's end, usually outside
            // any later fusion window, and `add rX, pc, rX` needs its value to name the string.
            if (L && !B && rt !== 15) {
              const lo = offset + (target - address);
              if (lo >= 0 && lo + 4 <= bytes.length) {
                destReg = REG[rt];
                pageValue = littleEndian
                  ? (bytes[lo] | (bytes[lo + 1] << 8) | (bytes[lo + 2] << 16) | (bytes[lo + 3] << 24)) >>> 0
                  : ((bytes[lo] << 24) | (bytes[lo + 1] << 16) | (bytes[lo + 2] << 8) | bytes[lo + 3]) >>> 0;
              }
            }
          }
        } else {
          const idx = shiftedReg(w).map((o) => o.text).join(", ");
          mem = { text: P ? `[${REG[rn]}, ${U ? "" : "-"}${idx}]${Wb ? "!" : ""}` : `[${REG[rn]}], ${U ? "" : "-"}${idx}`, memBase: REG[rn] };
        }
        ops = [R(rt), mem];
        if (L && rt === 15) { kind = "indirect-jump"; fallsThrough = cond !== 14; }
      } else if (bits(w, 27, 26) === 0b00) {
        const Imm = bit(w, 25), opc = bits(w, 24, 21), S = bit(w, 20), rn = bits(w, 19, 16), rd = bits(w, 15, 12);
        const isMul = !Imm && bits(w, 7, 4) === 0b1001;
        const isMisc = !Imm && bits(w, 24, 23) === 0b10 && !S && bit(w, 7) === 0;
        if (isMul && bits(w, 27, 24) === 0) {
          const A = bit(w, 21);
          mnemonic = (A ? "mla" : "mul") + (S ? "s" : "") + c;
          ops = A ? [R(rn), R(bits(w, 3, 0)), R(bits(w, 11, 8)), R(rd)] : [R(rn), R(bits(w, 3, 0)), R(bits(w, 11, 8))];
          kind = "arith";
        } else if (isMul && bits(w, 27, 23) === 1) {
          const U = bit(w, 22), A = bit(w, 21);
          mnemonic = (U ? "s" : "u") + (A ? "mlal" : "mull") + c;
          ops = [R(rd), R(rn), R(bits(w, 3, 0)), R(bits(w, 11, 8))];
          kind = "arith";
        } else if (!Imm && bit(w, 7) && bit(w, 4) && bits(w, 6, 5)) {
          // halfword/signed loads and stores
          const P = bit(w, 24), U = bit(w, 23), Iflag = bit(w, 22), Wb = bit(w, 21), L = bit(w, 20);
          const sh = bits(w, 6, 5);
          const nm = L ? ["", "h", "sb", "sh"][sh] : ["", "h", "d", "d"][sh];
          const ld = L || sh === 1 ? L : sh === 2;
          mnemonic = (ld ? "ldr" : "str") + nm + c;
          const off = Iflag ? ((bits(w, 11, 8) << 4) | bits(w, 3, 0)) * (U ? 1 : -1) : 0;
          const idx = Iflag ? (off === 0 ? "" : `, #${off < 0 ? "-" : ""}0x${Math.abs(off).toString(16)}`) : `, ${U ? "" : "-"}${REG[bits(w, 3, 0)]}`;
          ops = [R(rd), { text: P ? `[${REG[rn]}${idx}]${Wb ? "!" : ""}` : `[${REG[rn]}]${idx}`, memBase: REG[rn], memDisp: Iflag ? off : undefined }];
          kind = ld ? "load" : "store";
        } else if (isMisc && bits(w, 21, 20) === 0b10 && bits(w, 7, 4) === 0b0111) {
          mnemonic = "bkpt"; ops = [I((bits(w, 19, 8) << 4) | bits(w, 3, 0))]; kind = "trap"; fallsThrough = false;
        } else if (isMisc && bits(w, 27, 20) === 0b00010110 && bits(w, 7, 4) === 1) {
          mnemonic = "clz" + c; ops = [R(rd), R(bits(w, 3, 0))]; kind = "arith";
        } else if (isMisc && bit(w, 21) === 0 && bits(w, 7, 4) === 0) {
          mnemonic = "mrs" + c; ops = [R(rd), T(bit(w, 22) ? "spsr" : "cpsr")]; kind = "system";
        } else if (Imm && bits(w, 24, 20) === 0b10000) {
          mnemonic = "movw" + c; ops = [R(rd), I((rn << 12) | bits(w, 11, 0))]; kind = "move";
        } else if (Imm && bits(w, 24, 20) === 0b10100) {
          mnemonic = "movt" + c; ops = [R(rd), I((rn << 12) | bits(w, 11, 0))]; kind = "move";
        } else if (isMisc && bits(w, 21, 20) === 0b10 && bits(w, 7, 4) === 0) {
          mnemonic = "msr" + c; ops = [T(bit(w, 22) ? "spsr" : "cpsr"), R(bits(w, 3, 0))]; kind = "system";
        } else {
          const name = DP[opc];
          const op2: Operand[] = Imm ? [I(rotr32(bits(w, 7, 0), bits(w, 11, 8) * 2))] : shiftedReg(w);
          const isTest = opc >= 8 && opc <= 11;
          const isMov = opc === 13 || opc === 15;
          mnemonic = name + (S && !isTest ? "s" : "") + c;
          if (isTest) { ops = [R(rn), ...op2]; kind = "compare"; }
          else if (isMov) { ops = [R(rd), ...op2]; kind = "move"; if (w === 0xe1a00000) { mnemonic = "nop"; ops = []; kind = "nop"; } }
          else { ops = [R(rd), R(rn), ...op2]; kind = opc === 0 || opc === 1 || opc === 12 || opc === 14 ? "logic" : "arith"; }
          if (rd === 15 && !isTest) { kind = opc === 13 && !Imm && bits(w, 3, 0) === 14 ? "ret" : "indirect-jump"; fallsThrough = cond !== 14; }
          if (Imm && opc === 4 && rn === 15) { target = pc + rotr32(bits(w, 7, 0), bits(w, 11, 8) * 2); targetIsData = true; }
          if (Imm && opc === 2 && rn === 15) { target = pc - rotr32(bits(w, 7, 0), bits(w, 11, 8) * 2); targetIsData = true; }
        }
      } else if (bits(w, 27, 24) === 0b1111) {
        mnemonic = "svc" + c; ops = [I(bits(w, 23, 0))]; kind = "system";
      } else if (bits(w, 27, 24) >= 0b1100) {
        mnemonic = "vfp"; ops = [T(`0x${w.toString(16).padStart(8, "0")}`)]; kind = "simd";
      }
    } catch {
      /* fall back to .word */
    }
    return { address, size: 4, mnemonic, operands: ops, opText: ops.map((o) => o.text).join(", "), kind, target, targetIsData, fallsThrough, prologue, raw: w, destReg, pageValue };
  }

  prologueScore(insns: Instruction[]) {
    if (!insns.length) return 0;
    const m = insns[0].mnemonic;
    if (m.startsWith("push") && insns[0].prologue) return 0.75;
    if (m.startsWith("push")) return 0.5;
    if (m.startsWith("stmdb") || m.startsWith("stmfd")) return 0.5;
    if (m.startsWith("sub") && insns[0].opText.startsWith("sp, sp")) return 0.4;
    return 0.1;
  }
  /**
   * Data references: PC-relative literals/adr, MOVW+MOVT pairs (the usual way
   * A32 code materialises addresses) and PLT stub chains
   * (`add ip, pc, #a ; add ip, ip, #b ; ldr pc, [ip, #c]!` → GOT slot, emitted
   * from the stub's first instruction so callers can name the stub).
   */
  fuseDataRefs(insns: Instruction[]) {
    const out: { from: number; to: number; kind: "read" | "write" | "address" }[] = [];
    const movw = new Map<string, number>();
    /** reg → literal word loaded by `ldr reg, [pc, #n]` (PIC address materialisation). */
    const lit = new Map<string, number>();
    let plt: { ip: number; at: number } | null = null;
    for (const i of insns) {
      const m = i.mnemonic, o = i.operands;
      const dst = o[0]?.reg;
      if (m.startsWith("add") && dst === "r12" && o[1]?.reg === "pc" && o[2]?.imm !== undefined) { plt = { ip: (i.address + 8 + o[2].imm) >>> 0, at: i.address }; continue; }
      if (plt && m.startsWith("add") && dst === "r12" && o[1]?.reg === "r12" && o[2]?.imm !== undefined) { plt.ip = (plt.ip + o[2].imm) >>> 0; continue; }
      if (plt && m.startsWith("ldr") && dst === "pc" && o[1]?.memBase === "r12") { out.push({ from: plt.at, to: (plt.ip + (o[1].memDisp ?? 0)) >>> 0, kind: "read" }); plt = null; continue; }
      if (plt && dst === "r12") plt = null;
      if (i.target !== undefined && i.targetIsData) { out.push({ from: i.address, to: i.target, kind: i.kind === "load" ? "read" : "address" }); }
      // -fPIC ARM: `ldr rX, [pc, #n]` loads W = target - (add_pc + 8); `add rX, pc, rX` then
      // materialises the address. Strings, globals and vtables all arrive this way in
      // armeabi-v7a builds — without this fusion a UE4 library has no string xrefs at all.
      if (m.startsWith("ldr") && i.targetIsData && i.pageValue !== undefined && i.destReg) { lit.set(i.destReg, i.pageValue); continue; }
      if (m.startsWith("add") && dst && o.length === 3 && o[2]?.imm === undefined) {
        const src = o[1]?.reg === "pc" && o[2]?.reg && lit.has(o[2].reg) ? o[2].reg : o[2]?.reg === "pc" && o[1]?.reg && lit.has(o[1].reg) ? o[1].reg : null;
        if (src) {
          out.push({ from: i.address, to: (i.address + 8 + lit.get(src)!) >>> 0, kind: "address" });
          lit.delete(src);
          lit.delete(dst);
          movw.delete(dst);
          continue;
        }
      }
      // GOT-relative load: `ldr rX, [pc, rY]` with rY holding a literal → reads the slot at pc+8+W.
      if (m.startsWith("ldr") && dst && o[1]?.memBase === "pc" && !i.targetIsData) {
        const idx = o[1].text.match(/^\[pc, (r\d+|ip|lr)\]$/)?.[1];
        if (idx && lit.has(idx)) { out.push({ from: i.address, to: (i.address + 8 + lit.get(idx)!) >>> 0, kind: "read" }); lit.delete(idx); lit.delete(dst); continue; }
      }
      if (dst && i.kind !== "store" && i.kind !== "compare") lit.delete(dst);
      if (i.kind === "call" || i.kind === "indirect-call") for (const r of ["r0", "r1", "r2", "r3", "r12", "lr"]) lit.delete(r);
      if (m.startsWith("movw") && dst && o[1]?.imm !== undefined) { movw.set(dst, o[1].imm); continue; }
      if (m.startsWith("movt") && dst && o[1]?.imm !== undefined) {
        const lo = movw.get(dst);
        movw.delete(dst);
        if (lo !== undefined) out.push({ from: i.address, to: ((o[1].imm << 16) | lo) >>> 0, kind: "address" });
        continue;
      }
      if (dst && i.kind !== "store" && i.kind !== "compare") movw.delete(dst);
      if (i.kind === "call" || i.kind === "indirect-call") for (const r of ["r0", "r1", "r2", "r3", "r12", "lr"]) movw.delete(r);
    }
    return out;
  }
  syntaxClass(m: string) {
    if (m.startsWith("bl")) return "call" as const;
    if (m.startsWith("b")) return "branch" as const;
    if (/^(ldr|str|ldm|stm|push|pop)/.test(m)) return "mem" as const;
    if (/^(cmp|cmn|tst|teq)/.test(m)) return "cmp" as const;
    if (/^(mov|mvn|movw|movt)/.test(m)) return "mov" as const;
    if (/^(svc|mrs|msr|nop|bkpt)/.test(m)) return "sys" as const;
    return "arith" as const;
  }
}
