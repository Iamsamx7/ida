import type { ArchitectureProvider, Instruction } from "../architecture/types";
import type { ChunkScanResult } from "./types";

/**
 * Scan a chunk of executable bytes and extract every fact function discovery
 * and the XREF engine need. This is pure and worker-safe: it only touches the
 * bytes it is given and returns flat typed arrays (transferable).
 */
export function scanCodeChunk(
  arch: ArchitectureProvider,
  bytes: Uint8Array,
  fileOffset: number,
  va: number,
  length: number,
  littleEndian: boolean,
  chunkIndex: number,
  /** True if this chunk starts at a code-range boundary. */
  rangeStart: boolean,
): ChunkScanResult {
  const calls: number[] = [];
  const jumps: number[] = [];
  const condJumps: number[] = [];
  const dataRefs: number[] = [];
  const prologues: number[] = [];
  const afterTerm: number[] = [];
  const memAccess: number[] = [];
  const immediates: number[] = [];
  const indirect: number[] = [];
  let insnCount = 0;
  let unknownCount = 0;

  // Sliding window of decoded instructions for fusion / prologue scoring.
  const window: Instruction[] = [];
  const WINDOW = 6;
  let off = 0;
  let prevTerminator = rangeStart;
  let prevWasPad = false;
  const isArm = arch.id === "arm64" || arch.id === "arm32";
  const sp = arch.stackPointer;
  const pushFused = (buf: Instruction[]) => {
    for (const r of arch.fuseDataRefs(buf)) dataRefs.push(r.from, r.to, r.kind === "read" ? 3 : r.kind === "write" ? 4 : 5);
  };

  // We decode twice logically: a running window for prologue scoring, and
  // periodic fusion over larger buffers to catch adrp/add (or movw/movt) pairs.
  const fusionBuf: Instruction[] = [];
  while (off < length) {
    const ins = arch.decode(bytes, fileOffset + off, va + off, littleEndian);
    insnCount++;
    if (ins.kind === "unknown") unknownCount++;
    const k = ins.kind;
    if (k === "call" && ins.target !== undefined) calls.push(ins.address, ins.target);
    else if (k === "jump" && ins.target !== undefined) jumps.push(ins.address, ins.target);
    else if (k === "condjump" && ins.target !== undefined) condJumps.push(ins.address, ins.target);
    else if (k === "indirect-call" || k === "indirect-jump") indirect.push(ins.address);

    // Memory access patterns (structure inference) — skip stack-relative accesses.
    if ((k === "load" || k === "store") && ins.operands.length >= 2) {
      const mem = ins.operands[ins.operands.length - 1];
      if (mem.memBase && mem.memDisp !== undefined && mem.memBase !== sp && mem.memBase !== "x29" && mem.memBase !== "rbp" && mem.memBase !== "rip" && mem.memBase !== "fp") {
        const regIdx = regIndex(mem.memBase);
        if (regIdx >= 0 && !mem.text.includes("!") && !mem.text.includes("], ")) {
          // The transferred register may be either operand (x86 stores put memory first).
          const regOp = ins.operands.find((o) => o !== mem && o.reg);
          const size = accessSize(ins.mnemonic, regOp?.reg ?? "", mem.text);
          memAccess.push(ins.address, mem.memDisp, regIdx, (k === "store" ? 1 : 0) | (size << 1));
        }
      }
    }
    // Interesting immediates (constants search) — anything >= 0x100 not a branch target
    if (k !== "call" && k !== "jump" && k !== "condjump" && k !== "adr") {
      for (const o of ins.operands) {
        if (o.imm !== undefined && Math.abs(o.imm) >= 0x100 && o.memBase === undefined) {
          immediates.push(ins.address, o.imm);
          break;
        }
      }
    }

    // Prologue candidates: after a terminator/padding, at range start, or strong prologue instructions.
    const strong = ins.prologue === true;
    if (prevTerminator || prevWasPad || strong) {
      window.length = 0;
      window.push(ins);
      // peek ahead a few instructions for scoring (does not advance main loop)
      let poff = off + ins.size;
      for (let i = 1; i < 4 && poff < length; i++) {
        const nx = arch.decode(bytes, fileOffset + poff, va + poff, littleEndian);
        window.push(nx);
        poff += Math.max(1, nx.size);
      }
      let score = arch.prologueScore(window);
      if (prevTerminator && score < 0.3 && k !== "unknown" && k !== "nop") score = Math.max(score, 0.25);
      if (score >= 0.25 && k !== "unknown" && k !== "nop") prologues.push(ins.address, Math.round(score * 255));
      if (prevTerminator) afterTerm.push(ins.address);
    }

    prevTerminator = !ins.fallsThrough;
    prevWasPad = k === "nop" || (isArm && k === "unknown" && ins.raw === 0);

    fusionBuf.push(ins);
    if (fusionBuf.length >= 512) {
      pushFused(fusionBuf);
      // Keep a short tail so pairs spanning the boundary are still fused; the overlap may re-emit a few refs, deduped below.
      const tail = fusionBuf.slice(-WINDOW);
      fusionBuf.length = 0;
      for (const t of tail) fusionBuf.push(t);
    }
    off += Math.max(1, ins.size);
  }
  if (fusionBuf.length) pushFused(fusionBuf);

  // Deduplicate dataRefs (tail overlap may double-emit)
  const dedup = dedupeTriples(dataRefs);

  return {
    chunkIndex,
    insnCount,
    unknownCount,
    calls: Float64Array.from(calls),
    jumps: Float64Array.from(jumps),
    condJumps: Float64Array.from(condJumps),
    dataRefs: dedup,
    prologues: Float64Array.from(prologues),
    afterTerminators: Float64Array.from(afterTerm),
    memAccess: Float64Array.from(memAccess),
    immediates: Float64Array.from(immediates),
    indirect: Float64Array.from(indirect),
  };
}

function dedupeTriples(arr: number[]): Float64Array {
  if (arr.length < 6) return Float64Array.from(arr);
  const seen = new Set<string>();
  const out: number[] = [];
  for (let i = 0; i < arr.length; i += 3) {
    const key = `${arr[i]}:${arr[i + 1]}:${arr[i + 2]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(arr[i], arr[i + 1], arr[i + 2]);
  }
  return Float64Array.from(out);
}

export function regIndex(reg: string): number {
  const m = reg.match(/^[xwr](\d+)$/);
  if (m) return parseInt(m[1], 10);
  const x64: Record<string, number> = { rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5, rsi: 6, rdi: 7, eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7 };
  if (reg in x64) return x64[reg];
  if (reg === "sp") return 31;
  if (reg === "lr") return 14;
  return -1;
}

export function regName(archBits: 32 | 64, archId: string, idx: number): string {
  if (archId === "arm64") return idx === 31 ? "sp" : `x${idx}`;
  if (archId === "arm32") return ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"][idx] ?? `r${idx}`;
  const x = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
  return archBits === 64 ? x[idx] ?? `r${idx}` : ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][idx] ?? `r${idx}`;
}

function accessSize(mnemonic: string, reg: string, memText = ""): number {
  // ARM: width is in the mnemonic suffix or the register class.
  if (/b$/.test(mnemonic) && /^(ld|st)/.test(mnemonic)) return 1;
  if (/h$/.test(mnemonic) && /^(ld|st)/.test(mnemonic)) return 2;
  if (mnemonic === "ldrsw") return 4;
  // x86: width is spelled out in the memory operand.
  if (memText.startsWith("byte ptr")) return 1;
  if (memText.startsWith("word ptr")) return 2;
  if (memText.startsWith("dword ptr")) return 4;
  if (memText.startsWith("qword ptr")) return 8;
  if (memText.startsWith("xmmword ptr")) return 16;
  if (reg.startsWith("w") || reg.startsWith("s") || reg.startsWith("e")) return 4;
  if (reg.startsWith("q")) return 16;
  if (reg.startsWith("x") || reg.startsWith("d") || reg.startsWith("r")) return 8;
  return 8;
}
