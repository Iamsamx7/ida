import type { ArchId } from "../elf/types";

export type InsnKind =
  | "call"
  | "jump"
  | "condjump"
  | "ret"
  | "indirect-call"
  | "indirect-jump"
  | "load"
  | "store"
  | "arith"
  | "logic"
  | "compare"
  | "move"
  | "adr"
  | "nop"
  | "system"
  | "trap"
  | "simd"
  /** Decoded but not otherwise categorised (flag ops, leave, ...). */
  | "other"
  | "unknown";

export interface Operand {
  text: string;
  /** Immediate value, if any (used by search / constants). */
  imm?: number;
  /** Register name if this operand is a register. */
  reg?: string;
  /** Memory base register and displacement for memory operands. */
  memBase?: string;
  memDisp?: number;
}

export interface Instruction {
  address: number;
  size: number;
  mnemonic: string;
  operands: Operand[];
  opText: string;
  kind: InsnKind;
  /** Direct branch target VA, or PC-relative data address (ADR/ADRP/LDR literal). */
  target?: number;
  /** Whether `target` refers to data rather than code. */
  targetIsData?: boolean;
  /** Destination register for ADRP/ADR/MOV to enable page+offset fusion. */
  destReg?: string;
  /** For ADRP: the page address written to destReg. */
  pageValue?: number;
  /** Whether this instruction ends a basic block / falls through. */
  fallsThrough: boolean;
  /** True if this is a recognized function prologue instruction. */
  prologue?: boolean;
  raw: number;
}

export interface Register {
  name: string;
  size: number;
}

export interface ArchitectureProvider {
  readonly id: ArchId;
  readonly displayName: string;
  readonly bits: 32 | 64;
  /** Fixed instruction size (0 = variable). */
  readonly insnSize: number;
  readonly alignment: number;
  readonly returnRegister: string;
  readonly argumentRegisters: string[];
  readonly stackPointer: string;
  readonly linkRegister: string | null;
  decode(bytes: Uint8Array, offset: number, address: number, littleEndian: boolean): Instruction;
  /** Whether the instruction sequence at this point looks like a function entry. Returns confidence 0..1. */
  prologueScore(insns: Instruction[]): number;
  /** Fuse PC-relative page + offset pairs (ADRP + ADD/LDR/STR) into data references. */
  fuseDataRefs(insns: Instruction[]): { from: number; to: number; kind: "read" | "write" | "address" }[];
  syntaxClass(mnemonic: string): "branch" | "call" | "ret" | "mem" | "arith" | "sys" | "cmp" | "mov" | "other";
}
