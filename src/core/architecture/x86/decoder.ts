import type { ArchitectureProvider, InsnKind, Instruction, Operand } from "../types";

// ---------------------------------------------------------------------------
// x86 / x86-64 decoder — secondary architecture.
// Length-accurate decoding of the general-purpose integer subset (prefixes,
// REX, ModRM/SIB, common 0F opcodes, SSE moves). Unknown opcodes decode as a
// single `.byte` so analysis can resynchronise. Intel syntax.
// ---------------------------------------------------------------------------

const R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"];
const R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"];
const R8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"];
const R8L = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];
const CC = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];
const ARITH = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const SHIFTS = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"];

const hexImm = (v: number) => (v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`);

class Cursor {
  pos: number;
  constructor(readonly b: Uint8Array, readonly start: number) {
    this.pos = start;
  }
  get ok() {
    return this.pos < this.b.length;
  }
  u8() {
    if (this.pos >= this.b.length) throw new Error("eof");
    return this.b[this.pos++];
  }
  i8() {
    const v = this.u8();
    return v & 0x80 ? v - 256 : v;
  }
  u16() {
    return this.u8() | (this.u8() << 8);
  }
  i32() {
    const v = (this.u8() | (this.u8() << 8) | (this.u8() << 16) | (this.u8() << 24)) | 0;
    return v;
  }
  u32() {
    return this.i32() >>> 0;
  }
  u64() {
    const lo = this.u32();
    const hi = this.u32();
    return hi * 0x100000000 + lo;
  }
}

interface ModRM {
  mod: number;
  reg: number;
  rm: number;
  text: string; // memory or register operand text
  isMem: boolean;
  ripTarget?: number;
  memBase?: string;
  memDisp?: number;
}

export class X86Provider implements ArchitectureProvider {
  readonly id;
  readonly displayName;
  readonly bits;
  readonly insnSize = 0;
  readonly alignment = 1;
  readonly returnRegister;
  readonly argumentRegisters;
  readonly stackPointer;
  readonly linkRegister = null;

  constructor(bitsMode: 32 | 64) {
    this.bits = bitsMode;
    this.id = bitsMode === 64 ? ("x86_64" as const) : ("x86" as const);
    this.displayName = bitsMode === 64 ? "x86-64" : "x86 (IA-32)";
    this.returnRegister = bitsMode === 64 ? "rax" : "eax";
    this.argumentRegisters = bitsMode === 64 ? ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] : [];
    this.stackPointer = bitsMode === 64 ? "rsp" : "esp";
  }

  decode(bytes: Uint8Array, offset: number, address: number): Instruction {
    const c = new Cursor(bytes, offset);
    const mk = (mnemonic: string, ops: Operand[], kind: InsnKind, extra: Partial<Instruction> = {}): Instruction => ({
      address,
      size: c.pos - offset,
      mnemonic,
      operands: ops,
      opText: ops.map((o) => o.text).join(", "),
      kind,
      fallsThrough: !(kind === "jump" || kind === "ret" || kind === "indirect-jump" || kind === "trap"),
      raw: bytes[offset],
      ...extra,
    });
    try {
      let opsize16 = false,
        rep: string | null = null,
        rex = 0,
        seg = "";
      // prefixes
      for (;;) {
        const p = bytes[c.pos];
        if (p === 0x66) { opsize16 = true; c.pos++; }
        else if (p === 0xf2) { rep = "repne"; c.pos++; }
        else if (p === 0xf3) { rep = "rep"; c.pos++; }
        else if (p === 0x2e || p === 0x36 || p === 0x3e || p === 0x26) { c.pos++; }
        else if (p === 0x64) { seg = "fs:"; c.pos++; }
        else if (p === 0x65) { seg = "gs:"; c.pos++; }
        else if (p === 0xf0) { rep = "lock"; c.pos++; }
        else break;
        if (c.pos - offset > 4) break;
      }
      if (this.bits === 64 && (bytes[c.pos] & 0xf0) === 0x40) rex = c.u8();
      const W = (rex & 8) !== 0, Rx = (rex & 4) ? 8 : 0, Xx = (rex & 2) ? 8 : 0, Bx = (rex & 1) ? 8 : 0;
      // 8-bit names: without a REX prefix indices 4..7 are ah/ch/dh/bh; with REX they are spl/bpl/sil/dil (+ r8b..r15b).
      const regName = (n: number, size: 8 | 16 | 32 | 64) => (size === 64 ? R64 : size === 32 ? R32 : size === 16 ? R16 : rex ? R8 : R8L)[n];
      const opSize: 16 | 32 | 64 = W ? 64 : opsize16 ? 16 : 32;
      /** Operand size of push/pop and indirect call/jmp (always the native width). */
      const stackSize: 32 | 64 = this.bits === 64 ? 64 : 32;
      const addrRegs = this.bits === 64 ? R64 : R32;
      const modrm = (): ModRM => {
        const m = c.u8();
        const mod = m >> 6, reg = ((m >> 3) & 7) | Rx, rm0 = m & 7;
        if (mod === 3) return { mod, reg, rm: rm0 | Bx, text: "", isMem: false };
        let base = "", index = "", scale = 1, disp = 0, ripRel = false;
        let rm = rm0 | Bx;
        if (rm0 === 4) {
          const sib = c.u8();
          scale = 1 << (sib >> 6);
          const idx = ((sib >> 3) & 7) | Xx;
          const b = (sib & 7) | Bx;
          if (idx !== 4) index = addrRegs[idx];
          if ((sib & 7) === 5 && mod === 0) { disp = c.i32(); }
          else base = addrRegs[b];
          rm = b;
        } else if (rm0 === 5 && mod === 0) {
          disp = c.i32();
          if (this.bits === 64) ripRel = true;
        } else base = addrRegs[rm];
        if (mod === 1) disp = c.i8();
        else if (mod === 2) disp = c.i32();
        let inner = ripRel ? "rip" : base;
        if (index) inner += (inner ? " + " : "") + index + (scale > 1 ? `*${scale}` : "");
        if (disp || !inner) inner += inner ? (disp < 0 ? ` - 0x${(-disp).toString(16)}` : ` + 0x${disp.toString(16)}`) : hexImm(disp);
        return { mod, reg, rm, text: `${seg}[${inner}]`, isMem: true, ripTarget: ripRel ? disp : undefined, memBase: ripRel ? "rip" : base || undefined, memDisp: disp };
      };
      const ptr = (s: number) => (s === 8 ? "byte ptr " : s === 16 ? "word ptr " : s === 32 ? "dword ptr " : s === 128 ? "xmmword ptr " : "qword ptr ");
      const rmOp = (m: ModRM, size: 8 | 16 | 32 | 64 | 128, withPtr = true): Operand => {
        if (!m.isMem) return size === 128 ? { text: `xmm${m.rm}`, reg: `xmm${m.rm}` } : { text: regName(m.rm, size), reg: regName(m.rm, size) };
        const o: Operand = { text: (withPtr ? ptr(size) : "") + m.text, memBase: m.memBase, memDisp: m.memDisp };
        return o;
      };
      const fixRip = (m: ModRM, ins: Instruction) => {
        if (m.ripTarget !== undefined) {
          const t = address + ins.size + m.ripTarget;
          ins.target = t;
          ins.targetIsData = true;
          for (const o of ins.operands) if (o.text.includes("[rip")) o.text = o.text.replace(/\[rip[^\]]*\]/, `[0x${t.toString(16)}]`);
          ins.opText = ins.operands.map((o) => o.text).join(", ");
        }
        return ins;
      };
      const regOp = (n: number, size: 8 | 16 | 32 | 64): Operand => ({ text: regName(n, size), reg: regName(n, size) });
      const immOp = (v: number): Operand => ({ text: hexImm(v), imm: v });
      const op = c.u8();

      if (op === 0x0f) {
        const op2 = c.u8();
        if (op2 >= 0x80 && op2 <= 0x8f) {
          const rel = c.i32();
          const t = address + (c.pos - offset) + rel;
          return mk(`j${CC[op2 - 0x80]}`, [{ text: hexImm(t), imm: t }], "condjump", { target: t });
        }
        if (op2 >= 0x40 && op2 <= 0x4f) { const m = modrm(); return fixRip(m, mk(`cmov${CC[op2 - 0x40]}`, [regOp(m.reg, opSize), rmOp(m, opSize)], "move")); }
        if (op2 >= 0x90 && op2 <= 0x9f) { const m = modrm(); return fixRip(m, mk(`set${CC[op2 - 0x90]}`, [rmOp(m, 8)], "move")); }
        if (op2 === 0x1f) { const m = modrm(); return fixRip(m, mk("nop", [rmOp(m, opSize)], "nop")); }
        if (op2 === 0x1e && bytes[c.pos] === 0xfa && rep === "rep") { c.pos++; return mk("endbr64", [], "system", { prologue: true }); }
        if (op2 === 0x05) return mk("syscall", [], "system");
        if (op2 === 0x0b) return mk("ud2", [], "trap");
        if (op2 === 0xa2) return mk("cpuid", [], "system");
        if (op2 === 0x31) return mk("rdtsc", [], "system");
        if (op2 === 0xb6 || op2 === 0xb7 || op2 === 0xbe || op2 === 0xbf) {
          const m = modrm();
          const src: 8 | 16 = op2 & 1 ? 16 : 8;
          return fixRip(m, mk(op2 < 0xb8 ? "movzx" : "movsx", [regOp(m.reg, opSize), rmOp(m, src)], "move"));
        }
        if (op2 === 0xaf) { const m = modrm(); return fixRip(m, mk("imul", [regOp(m.reg, opSize), rmOp(m, opSize)], "arith")); }
        if (op2 === 0xa3 || op2 === 0xab || op2 === 0xb3 || op2 === 0xbb) { const m = modrm(); return fixRip(m, mk(["bt", "bts", "btr", "btc"][(op2 >> 3) & 3], [rmOp(m, opSize), regOp(m.reg, opSize)], "logic")); }
        if (op2 === 0xba) { const m = modrm(); const imm = c.u8(); return fixRip(m, mk(["", "", "", "", "bt", "bts", "btr", "btc"][m.reg & 7] || "bt", [rmOp(m, opSize), immOp(imm)], "logic")); }
        if (op2 === 0xb1 || op2 === 0xb0) { const m = modrm(); return fixRip(m, mk("cmpxchg", [rmOp(m, op2 & 1 ? opSize : 8), regOp(m.reg, op2 & 1 ? opSize : 8)], "store")); }
        if (op2 === 0xc1 || op2 === 0xc0) { const m = modrm(); return fixRip(m, mk("xadd", [rmOp(m, op2 & 1 ? opSize : 8), regOp(m.reg, op2 & 1 ? opSize : 8)], "store")); }
        if (op2 === 0xbc || op2 === 0xbd) { const m = modrm(); return fixRip(m, mk(rep === "rep" ? (op2 === 0xbc ? "tzcnt" : "lzcnt") : op2 === 0xbc ? "bsf" : "bsr", [regOp(m.reg, opSize), rmOp(m, opSize)], "arith")); }
        if (op2 === 0xa4 || op2 === 0xac) { const m = modrm(); const imm = c.u8(); return fixRip(m, mk(op2 === 0xa4 ? "shld" : "shrd", [rmOp(m, opSize), regOp(m.reg, opSize), immOp(imm)], "arith")); }
        if (op2 === 0xa5 || op2 === 0xad) { const m = modrm(); return fixRip(m, mk(op2 === 0xa5 ? "shld" : "shrd", [rmOp(m, opSize), regOp(m.reg, opSize), { text: "cl", reg: "cl" }], "arith")); }
        if (op2 >= 0xc8 && op2 <= 0xcf) return mk("bswap", [regOp((op2 & 7) | Bx, opSize)], "arith");
        // SSE subset
        const sse: Record<number, string> = { 0x10: "movu", 0x11: "movu", 0x28: "mova", 0x29: "mova", 0x2e: "ucomis", 0x2f: "comis", 0x51: "sqrt", 0x54: "and", 0x57: "xor", 0x58: "add", 0x59: "mul", 0x5c: "sub", 0x5e: "div", 0x5d: "min", 0x5f: "max", 0x6f: "movdq", 0x7f: "movdq", 0xef: "pxor", 0xd6: "movq", 0x7e: "mov", 0x6e: "mov", 0x2a: "cvtsi2s", 0x2c: "cvtts2si", 0x2d: "cvts2si", 0x5a: "cvts2s", 0x14: "unpcklp", 0x16: "movhp", 0x12: "movlp", 0xc6: "shufp", 0x6c: "punpcklqdq", 0xd4: "paddq", 0xfe: "paddd", 0xfa: "psubd", 0x66: "pcmpgtd", 0x76: "pcmpeqd", 0xd7: "pmovmskb", 0x74: "pcmpeqb", 0xda: "pminub", 0xeb: "por", 0xdb: "pand", 0x70: "pshufd", 0x73: "psrldq", 0xe7: "movntdq", 0x2b: "movntp" };
        if (sse[op2] !== undefined) {
          const m = modrm();
          const sfx = rep === "rep" ? "ss" : rep === "repne" ? "sd" : opsize16 ? "pd" : "ps";
          let name = sse[op2];
          if (name === "movu" || name === "mova") name = (name === "movu" ? "movu" : "mova") + sfx;
          else if (name === "movdq") name = rep === "rep" ? "movdqu" : "movdqa";
          else if (name.endsWith("s") && !name.startsWith("p") && name !== "ucomis" && name !== "comis") name = name + (sfx === "pd" || sfx === "sd" ? "d" : "s");
          else if (name === "ucomis" || name === "comis") name = name + (opsize16 ? "d" : "s");
          else if (name === "cvtsi2s") name = rep === "repne" ? "cvtsi2sd" : "cvtsi2ss";
          else if (name === "cvtts2si") name = rep === "repne" ? "cvttsd2si" : "cvttss2si";
          else if (name === "cvts2si") name = rep === "repne" ? "cvtsd2si" : "cvtss2si";
          else if (name === "cvts2s") name = rep === "repne" ? "cvtsd2ss" : rep === "rep" ? "cvtss2sd" : opsize16 ? "cvtpd2ps" : "cvtps2pd";
          else if (name === "unpcklp" || name === "movhp" || name === "movlp" || name === "shufp" || name === "movntp") name = name + (opsize16 ? "d" : "s");
          const xmm = (n: number): Operand => ({ text: `xmm${n}`, reg: `xmm${n}` });
          const store = op2 === 0x11 || op2 === 0x29 || op2 === 0x7f || op2 === 0xd6 || op2 === 0x7e || op2 === 0xe7 || op2 === 0x2b;
          let ops: Operand[];
          if (op2 === 0x2a) ops = [xmm(m.reg), rmOp(m, W ? 64 : 32)];
          else if (op2 === 0x2c || op2 === 0x2d) ops = [regOp(m.reg, W ? 64 : 32), rmOp(m, 64)];
          else if (op2 === 0x6e) ops = [xmm(m.reg), rmOp(m, W ? 64 : 32)];
          else if (op2 === 0x7e && !rep) ops = [rmOp(m, W ? 64 : 32), xmm(m.reg)];
          else if (op2 === 0xd7) ops = [regOp(m.reg, 32), xmm(m.rm)];
          else if (store) ops = [rmOp(m, 128), xmm(m.reg)];
          else ops = [xmm(m.reg), rmOp(m, 128)];
          if (op2 === 0xc6 || op2 === 0x70 || op2 === 0x73) ops.push(immOp(c.u8()));
          return fixRip(m, mk(name, ops, store ? "store" : m.isMem ? "load" : "simd"));
        }
        if (op2 === 0x38 || op2 === 0x3a) { c.u8(); const m = modrm(); if (op2 === 0x3a) c.u8(); void m; return mk("sse4", [{ text: "..." }], "simd"); }
        c.pos = offset + 1;
        return mk(".byte", [{ text: `0x${bytes[offset].toString(16).padStart(2, "0")}` }], "unknown");
      }

      // one-byte opcodes
      if (op < 0x40 && (op & 7) < 6) {
        const opn = ARITH[op >> 3];
        const kind: InsnKind = opn === "cmp" ? "compare" : opn === "and" || opn === "or" || opn === "xor" ? "logic" : "arith";
        const dir = (op >> 1) & 1, wide = op & 1;
        const size = wide ? opSize : 8;
        if ((op & 7) < 4) {
          const m = modrm();
          const ops = dir ? [regOp(m.reg, size), rmOp(m, size)] : [rmOp(m, size), regOp(m.reg, size)];
          return fixRip(m, mk(opn, ops, kind));
        }
        const imm = wide ? (opSize === 16 ? c.u16() : c.i32()) : c.i8();
        return mk(opn, [regOp(0, size), immOp(imm)], kind);
      }
      if (op >= 0x50 && op <= 0x57) return mk("push", [regOp((op & 7) | Bx, stackSize)], "store", { prologue: (op & 7) === 5 && !Bx });
      if (op >= 0x58 && op <= 0x5f) return mk("pop", [regOp((op & 7) | Bx, stackSize)], "load");
      if (op === 0x63 && this.bits === 64) { const m = modrm(); return fixRip(m, mk("movsxd", [regOp(m.reg, opSize), rmOp(m, 32)], "move")); }
      if (op === 0x68) return mk("push", [immOp(c.i32())], "store");
      if (op === 0x6a) return mk("push", [immOp(c.i8())], "store");
      if (op === 0x69 || op === 0x6b) { const m = modrm(); const imm = op === 0x6b ? c.i8() : c.i32(); return fixRip(m, mk("imul", [regOp(m.reg, opSize), rmOp(m, opSize), immOp(imm)], "arith")); }
      if (op >= 0x70 && op <= 0x7f) { const rel = c.i8(); const t = address + (c.pos - offset) + rel; return mk(`j${CC[op - 0x70]}`, [{ text: hexImm(t), imm: t }], "condjump", { target: t }); }
      if (op >= 0x80 && op <= 0x83) {
        const m = modrm();
        const size = op & 1 ? opSize : 8;
        const imm = op === 0x81 ? (opSize === 16 ? c.u16() : c.i32()) : c.i8();
        const opn = ARITH[m.reg & 7];
        return fixRip(m, mk(opn, [rmOp(m, size), immOp(imm)], opn === "cmp" ? "compare" : "arith"));
      }
      if (op === 0x84 || op === 0x85) { const m = modrm(); return fixRip(m, mk("test", [rmOp(m, op & 1 ? opSize : 8), regOp(m.reg, op & 1 ? opSize : 8)], "compare")); }
      if (op === 0x86 || op === 0x87) { const m = modrm(); return fixRip(m, mk("xchg", [rmOp(m, op & 1 ? opSize : 8), regOp(m.reg, op & 1 ? opSize : 8)], "move")); }
      if (op >= 0x88 && op <= 0x8b) {
        const m = modrm();
        const size = op & 1 ? opSize : 8;
        const toReg = (op & 2) !== 0;
        const ops = toReg ? [regOp(m.reg, size), rmOp(m, size)] : [rmOp(m, size), regOp(m.reg, size)];
        const ins = mk("mov", ops, m.isMem ? (toReg ? "load" : "store") : "move");
        if (op === 0x89 && !m.isMem && m.rm === 5 && m.reg === 4 && this.bits === 64) ins.prologue = true; // mov rbp, rsp
        return fixRip(m, ins);
      }
      if (op === 0x8d) { const m = modrm(); return fixRip(m, mk("lea", [regOp(m.reg, opSize), { text: m.text, memBase: m.memBase, memDisp: m.memDisp }], "adr")); }
      if (op === 0x8f) { const m = modrm(); return fixRip(m, mk("pop", [rmOp(m, stackSize)], "load")); }
      if (op === 0x90) return mk(rep === "rep" ? "pause" : "nop", [], "nop");
      if (op > 0x90 && op <= 0x97) return mk("xchg", [regOp(0, opSize), regOp((op & 7) | Bx, opSize)], "move");
      if (op === 0x98) return mk(W ? "cdqe" : opsize16 ? "cbw" : "cwde", [], "move");
      if (op === 0x99) return mk(W ? "cqo" : opsize16 ? "cwd" : "cdq", [], "move");
      if (op === 0xa8) return mk("test", [regOp(0, 8), immOp(c.u8())], "compare");
      if (op === 0xa9) return mk("test", [regOp(0, opSize), immOp(opSize === 16 ? c.u16() : c.i32())], "compare");
      if (op >= 0xa4 && op <= 0xaf && op !== 0xa8 && op !== 0xa9) {
        const names: Record<number, string> = { 0xa4: "movsb", 0xa5: "movs", 0xa6: "cmpsb", 0xa7: "cmps", 0xaa: "stosb", 0xab: "stos", 0xac: "lodsb", 0xad: "lods", 0xae: "scasb", 0xaf: "scas" };
        let n = names[op];
        if (!n.endsWith("b")) n += opSize === 64 ? "q" : opSize === 16 ? "w" : "d";
        return mk((rep ? rep + " " : "") + n, [], "store");
      }
      if (op >= 0xb0 && op <= 0xb7) return mk("mov", [regOp((op & 7) | Bx, 8), immOp(c.u8())], "move");
      if (op >= 0xb8 && op <= 0xbf) {
        const imm = W ? c.u64() : opsize16 ? c.u16() : c.u32();
        return mk("mov", [regOp((op & 7) | Bx, opSize), immOp(imm)], "move");
      }
      if (op === 0xc0 || op === 0xc1 || (op >= 0xd0 && op <= 0xd3)) {
        const m = modrm();
        const size = op & 1 ? opSize : 8;
        const cnt: Operand = op <= 0xc1 ? immOp(c.u8()) : op >= 0xd2 ? { text: "cl", reg: "cl" } : immOp(1);
        return fixRip(m, mk(SHIFTS[m.reg & 7], [rmOp(m, size), cnt], "arith"));
      }
      if (op === 0xc2) return mk("ret", [immOp(c.u16())], "ret");
      if (op === 0xc3) return mk("ret", [], "ret");
      if (op === 0xc6 || op === 0xc7) {
        const m = modrm();
        const size = op & 1 ? opSize : 8;
        const imm = op === 0xc6 ? c.u8() : opSize === 16 ? c.u16() : c.i32();
        return fixRip(m, mk("mov", [rmOp(m, size), immOp(imm)], m.isMem ? "store" : "move"));
      }
      if (op === 0xc9) return mk("leave", [], "other");
      if (op === 0xcc) return mk("int3", [], "trap");
      if (op === 0xcd) return mk("int", [immOp(c.u8())], "system");
      if (op === 0xe8) { const rel = c.i32(); const t = address + (c.pos - offset) + rel; return mk("call", [{ text: hexImm(t), imm: t }], "call", { target: t }); }
      if (op === 0xe9) { const rel = c.i32(); const t = address + (c.pos - offset) + rel; return mk("jmp", [{ text: hexImm(t), imm: t }], "jump", { target: t }); }
      if (op === 0xeb) { const rel = c.i8(); const t = address + (c.pos - offset) + rel; return mk("jmp", [{ text: hexImm(t), imm: t }], "jump", { target: t }); }
      if (op === 0xf4) return mk("hlt", [], "trap");
      if (op === 0xf5) return mk("cmc", [], "other");
      if (op === 0xf8) return mk("clc", [], "other");
      if (op === 0xf9) return mk("stc", [], "other");
      if (op === 0xfc) return mk("cld", [], "other");
      if (op === 0xfd) return mk("std", [], "other");
      if (op === 0xf6 || op === 0xf7) {
        const m = modrm();
        const size = op & 1 ? opSize : 8;
        const sub = m.reg & 7;
        const names = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"];
        if (sub < 2) { const imm = op === 0xf6 ? c.u8() : opSize === 16 ? c.u16() : c.i32(); return fixRip(m, mk("test", [rmOp(m, size), immOp(imm)], "compare")); }
        return fixRip(m, mk(names[sub], [rmOp(m, size)], "arith"));
      }
      if (op === 0xfe || op === 0xff) {
        const m = modrm();
        const sub = m.reg & 7;
        const size = op & 1 ? opSize : 8;
        if (sub === 0) return fixRip(m, mk("inc", [rmOp(m, size)], "arith"));
        if (sub === 1) return fixRip(m, mk("dec", [rmOp(m, size)], "arith"));
        if (op === 0xff && sub === 2) return fixRip(m, mk("call", [rmOp(m, stackSize)], "indirect-call"));
        if (op === 0xff && sub === 4) return fixRip(m, mk("jmp", [rmOp(m, stackSize)], "indirect-jump"));
        if (op === 0xff && sub === 6) return fixRip(m, mk("push", [rmOp(m, stackSize)], "store"));
      }
      c.pos = offset + 1;
      return mk(".byte", [{ text: `0x${bytes[offset].toString(16).padStart(2, "0")}` }], "unknown");
    } catch {
      return { address, size: 1, mnemonic: ".byte", operands: [{ text: `0x${(bytes[offset] ?? 0).toString(16).padStart(2, "0")}` }], opText: "", kind: "unknown", fallsThrough: true, raw: bytes[offset] ?? 0 };
    }
  }

  prologueScore(insns: Instruction[]) {
    if (!insns.length) return 0;
    let s = 0;
    const m0 = insns[0];
    if (m0.mnemonic === "endbr64") s += 0.7;
    if (m0.mnemonic === "push" && m0.opText === "rbp") s += 0.6;
    if (m0.mnemonic === "push" && /^r(bx|1[2-5])$/.test(m0.opText)) s += 0.45;
    if (m0.mnemonic === "sub" && m0.opText.startsWith("rsp")) s += 0.5;
    for (let i = 1; i < Math.min(insns.length, 4); i++) {
      const x = insns[i];
      if (x.prologue) s += 0.3;
      if (x.mnemonic === "push") s += 0.15;
      if (x.mnemonic === "sub" && x.opText.startsWith("rsp")) s += 0.25;
    }
    return Math.min(1, s);
  }
  fuseDataRefs(insns: Instruction[]) {
    const out: { from: number; to: number; kind: "read" | "write" | "address" }[] = [];
    for (const i of insns) {
      if (i.target !== undefined && i.targetIsData) out.push({ from: i.address, to: i.target, kind: i.kind === "store" ? "write" : i.kind === "adr" ? "address" : "read" });
    }
    return out;
  }
  syntaxClass(m: string) {
    if (m === "call") return "call" as const;
    if (m === "ret") return "ret" as const;
    if (m.startsWith("j")) return "branch" as const;
    if (m === "cmp" || m === "test" || m.startsWith("ucomis") || m.startsWith("comis")) return "cmp" as const;
    if (m.startsWith("mov") || m === "lea" || m.startsWith("cmov") || m.startsWith("set")) return "mov" as const;
    if (m === "push" || m === "pop") return "mem" as const;
    if (/^(nop|syscall|int|hlt|cpuid|rdtsc|endbr64|ud2)/.test(m)) return "sys" as const;
    return "arith" as const;
  }
}
