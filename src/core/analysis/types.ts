import type { ArchId } from "../elf/types";

export const ANALYSIS_VERSION = "1.1.0";

export type NameSource = "symbol" | "inferred" | "user" | "ai";
export type Certainty = "fact" | "inference" | "ai-hypothesis" | "user";

export interface FunctionRecord {
  addr: number;
  size: number;
  name: string;
  nameSource: NameSource;
  /** Discovery confidence 0..1 (1.0 for symbols). */
  confidence: number;
  /** Evidence sources: symbol, export, call-target, prologue, init-array, relocation, entry */
  sources: string[];
  insnCount: number;
  callerCount: number;
  calleeCount: number;
  isImportStub: boolean;
  /** Filled by semantic stage. */
  classes?: Classification[];
  features?: FunctionFeatures;
}

export interface Classification {
  label: string;
  confidence: number;
  level: "high" | "likely" | "possible" | "low";
  evidence: Evidence[];
}

export interface Evidence {
  text: string;
  address?: number;
  certainty: Certainty;
}

export interface FunctionFeatures {
  mnemonicHist: Record<string, number>;
  constants: number[];
  stringRefs: number[];
  callees: number[];
  importCalls: string[];
  branchCount: number;
  callCount: number;
  loadCount: number;
  storeCount: number;
  memAccessOffsets: number[];
  hasLoop: boolean;
  fingerprint: string;
}

export type XrefKind = 1 | 2 | 3 | 4 | 5 | 6 | 7;
export const XREF_KIND_NAMES: Record<XrefKind, string> = {
  1: "call",
  2: "jump",
  3: "read",
  4: "write",
  5: "address",
  6: "pointer", // data -> code (relocations, vtables)
  7: "string",
};

export interface Xref {
  from: number;
  to: number;
  kind: XrefKind;
}

export type StringEncoding = "ascii" | "utf8" | "utf16le" | "utf32le";
export type StringCategory =
  | "url"
  | "path"
  | "error"
  | "log"
  | "config"
  | "type-name"
  | "command"
  | "format"
  | "crypto"
  | "network"
  | "jni"
  | "anticheat"
  | "hash"
  | "game"
  | "generic";

export interface StringRecord {
  addr: number;
  length: number; // bytes
  encoding: StringEncoding;
  value: string;
  category: StringCategory;
  refCount: number;
}

export interface StructureField {
  offset: number;
  name: string;
  size: number;
  type?: string;
  certain: boolean;
  accessKinds?: ("read" | "write")[];
}

export interface StructureRecord {
  id: string;
  name: string;
  origin: "user" | "inferred" | "ai";
  fields: StructureField[];
  evidence: Evidence[];
  /** Functions in which the access pattern was observed. */
  functions: number[];
  confidence: number;
}

export interface GlobalRecord {
  addr: number;
  name: string;
  nameSource: NameSource;
  size: number;
  section: string;
  readers: number;
  writers: number;
}

export interface ChunkScanResult {
  chunkIndex: number;
  insnCount: number;
  unknownCount: number;
  /** [from, to] pairs */
  calls: Float64Array;
  jumps: Float64Array;
  condJumps: Float64Array;
  /** [from, to, kind(3 read/4 write/5 address)] triples */
  dataRefs: Float64Array;
  /** [va, score*255] pairs */
  prologues: Float64Array;
  /** addresses immediately following a block terminator (candidate function boundaries) */
  afterTerminators: Float64Array;
  /** [va, disp, baseRegIndex, flags(kind 0 read/1 write | size<<1)] quads for non-stack memory accesses */
  memAccess: Float64Array;
  /** [va, imm] pairs for large immediates (constant search) */
  immediates: Float64Array;
  /** addresses of indirect calls/jumps */
  indirect: Float64Array;
}

export interface StageState {
  id: string;
  label: string;
  status: "pending" | "running" | "complete" | "error" | "skipped";
  progress: number; // 0..1
  detail?: string;
  startedAt?: number;
  finishedAt?: number;
}

export interface BinaryIdentity {
  hash: string;
  fileName: string;
  size: number;
  arch: ArchId;
}

export interface BinarySummary {
  arch: string;
  size: number;
  sections: number;
  segments: number;
  functions: number;
  strings: number;
  imports: number;
  exports: number;
  relocations: number;
  xrefs: number;
  components: { label: string; count: number }[];
  interesting: { label: string; addr: number; reason: string }[];
}
