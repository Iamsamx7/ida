import type { ElfImage, ElfSymbol } from "../elf/types";
import { AddressSpace } from "../address/space";
import type { ArchitectureProvider, Instruction } from "../architecture/types";
import { decodeRange } from "../architecture/registry";
import type { ChunkScanResult, FunctionRecord, GlobalRecord, NameSource, StringRecord, StructureRecord, Xref, XrefKind } from "./types";
import { XrefIndex, floorIndex } from "./xrefIndex";

export interface Annotation {
  address: number;
  body: string;
}
export interface Bookmark {
  address: number;
  kind: "address" | "function" | "string" | "data";
  label: string;
  note: string;
}
export interface UserName {
  address: number;
  name: string;
  origin: "user" | "ai-accepted";
}

/**
 * In-memory analysis database for one binary. Holds the ELF image, the
 * address space, discovered functions / strings / xrefs and user annotations.
 * Large collections are kept in sorted arrays + typed arrays so lookups are
 * logarithmic and memory stays bounded.
 */
export class AnalysisDatabase {
  readonly elf: ElfImage;
  readonly space: AddressSpace;
  readonly bytes: Uint8Array;
  readonly arch: ArchitectureProvider | null;
  readonly fileName: string;
  hash = "";
  /** Bumped whenever functions / strings / xrefs / user names change — cache key for derived views (intel, sweeps). */
  revision = 0;

  functions: FunctionRecord[] = [];
  private fnAddrs: Float64Array = new Float64Array(0);
  private fnByAddr = new Map<number, number>();

  xrefs: XrefIndex = XrefIndex.empty();
  strings: StringRecord[] = [];
  private strAddrs: Float64Array = new Float64Array(0);
  private strByAddr = new Map<number, number>();
  globals: GlobalRecord[] = [];
  structures: StructureRecord[] = [];
  immediates: Float64Array = new Float64Array(0); // [va, imm] pairs sorted by va
  memAccess: Float64Array = new Float64Array(0); // quads

  // User / AI layers (never silently overwrite each other)
  userNames = new Map<number, UserName>();
  comments = new Map<number, string>();
  functionComments = new Map<number, string>();
  bookmarks = new Map<number, Bookmark>();
  tags = new Map<number, Set<string>>();
  symbolNames = new Map<number, ElfSymbol>();
  pltNames = new Map<number, string>();
  /** GOT slot address → imported symbol name (from JUMP_SLOT / GLOB_DAT relocations). */
  gotNames = new Map<number, string>();

  insnTotal = 0;
  unknownTotal = 0;

  constructor(elf: ElfImage, bytes: Uint8Array, arch: ArchitectureProvider | null, fileName: string) {
    this.elf = elf;
    this.bytes = bytes;
    this.arch = arch;
    this.fileName = fileName;
    this.space = new AddressSpace(elf);
    for (const s of elf.symbols) {
      if (!s.name || !s.defined || s.kind === "section" || s.kind === "file") continue;
      const prev = this.symbolNames.get(s.value);
      // prefer global > weak > local, func > object, and non-mangled-duplicate
      if (!prev || rank(s) > rank(prev)) this.symbolNames.set(s.value, s);
    }
    for (const r of elf.relocations) if (r.symName && /JUMP_SLOT|GLOB_DAT/.test(r.typeName) && !this.gotNames.has(r.offset)) this.gotNames.set(r.offset, r.symName);
    this.resolvePlt();
  }

  // ---------------------------------------------------------------- naming
  nameFor(addr: number): { name: string; source: NameSource } {
    const u = this.userNames.get(addr);
    if (u) return { name: u.name, source: u.origin === "user" ? "user" : "ai" };
    const s = this.symbolNames.get(addr);
    if (s) return { name: s.name, source: "symbol" };
    const p = this.pltNames.get(addr);
    if (p) return { name: p, source: "symbol" };
    const g = this.gotNames.get(addr);
    if (g) return { name: `${g}@got`, source: "symbol" };
    if (this.fnByAddr.has(addr)) return { name: `sub_${addr.toString(16)}`, source: "inferred" };
    const str = this.stringAt(addr);
    if (str) return { name: `a${sanitize(str.value).slice(0, 24)}`, source: "inferred" };
    return { name: `loc_${addr.toString(16)}`, source: "inferred" };
  }

  /** Display label for an address, using offsets into a containing function/string where applicable. */
  labelFor(addr: number): string {
    const f = this.functionAt(addr);
    if (f) {
      const n = this.nameFor(f.addr).name;
      return f.addr === addr ? n : `${n}+0x${(addr - f.addr).toString(16)}`;
    }
    return this.nameFor(addr).name;
  }

  setUserName(addr: number, name: string, origin: "user" | "ai-accepted" = "user") {
    const clean = name.trim();
    if (!clean) {
      this.userNames.delete(addr);
    } else this.userNames.set(addr, { address: addr, name: clean, origin });
    const f = this.functionAt(addr);
    if (f && f.addr === addr) {
      const n = this.nameFor(addr);
      f.name = n.name;
      f.nameSource = n.source;
    }
    this.revision++;
  }

  // ------------------------------------------------------------- functions
  setFunctions(fns: FunctionRecord[]) {
    fns.sort((a, b) => a.addr - b.addr);
    this.functions = fns;
    this.fnAddrs = Float64Array.from(fns.map((f) => f.addr));
    this.fnByAddr = new Map();
    fns.forEach((f, i) => this.fnByAddr.set(f.addr, i));
    for (const f of fns) {
      const n = this.nameFor(f.addr);
      f.name = n.name;
      f.nameSource = n.source;
    }
    this.revision++;
  }

  functionAt(addr: number): FunctionRecord | null {
    if (!this.functions.length) return null;
    const i = floorIndex(this.fnAddrs, addr);
    if (i < 0) return null;
    const f = this.functions[i];
    return addr < f.addr + Math.max(f.size, 4) ? f : null;
  }
  functionByAddr(addr: number): FunctionRecord | null {
    const i = this.fnByAddr.get(addr);
    return i === undefined ? null : this.functions[i];
  }
  functionIndex(addr: number) {
    return this.fnByAddr.get(addr) ?? -1;
  }

  // ------------------------------------------------------------- strings
  setStrings(strs: StringRecord[]) {
    strs.sort((a, b) => a.addr - b.addr);
    this.strings = strs;
    this.strAddrs = Float64Array.from(strs.map((s) => s.addr));
    this.strByAddr = new Map();
    strs.forEach((s, i) => this.strByAddr.set(s.addr, i));
    this.revision++;
  }
  stringAt(addr: number): StringRecord | null {
    const i = this.strByAddr.get(addr);
    if (i !== undefined) return this.strings[i];
    const j = floorIndex(this.strAddrs, addr);
    if (j < 0) return null;
    const s = this.strings[j];
    return addr < s.addr + s.length ? s : null;
  }

  // ------------------------------------------------------------- xrefs
  setXrefs(index: XrefIndex) {
    this.xrefs = index;
    // update string ref counts & function caller/callee counts
    for (const s of this.strings) s.refCount = 0;
    for (const f of this.functions) {
      f.callerCount = 0;
      f.calleeCount = 0;
    }
    const { from, to, kind } = index;
    for (let i = 0; i < index.count; i++) {
      const k = kind[i];
      if (k === 7 || k === 5 || k === 3) {
        const s = this.stringAt(to[i]);
        if (s) s.refCount++;
      }
      if (k === 1 || k === 6) {
        const callee = this.functionByAddr(to[i]);
        if (callee) callee.callerCount++;
        const caller = this.functionAt(from[i]);
        if (caller && k === 1) caller.calleeCount++;
      }
    }
    this.revision++;
  }

  callersOf(fn: FunctionRecord): { fn: FunctionRecord | null; from: number; kind: XrefKind }[] {
    return this.xrefs.refsToRange(fn.addr, fn.addr + 1).map((x) => ({ fn: this.functionAt(x.from), from: x.from, kind: x.kind }));
  }
  /**
   * Direct callees of a function. Besides BL targets (kind 1) this also
   * resolves the standard ARM64 import pattern `adrp + ldr [GOT] + blr`
   * (recorded as kind-3 reads of a GOT slot) so `memcpy`, `gettimeofday`
   * etc. show up as calls even in stripped binaries without PLT symbols.
   */
  calleesOf(fn: FunctionRecord): { fn: FunctionRecord | null; to: number; from: number; kind: XrefKind }[] {
    const out: { fn: FunctionRecord | null; to: number; from: number; kind: XrefKind }[] = [];
    for (const x of this.xrefs.refsFromRange(fn.addr, fn.addr + fn.size)) {
      if (x.kind === 1) out.push({ fn: this.functionByAddr(x.to), to: x.to, from: x.from, kind: x.kind });
      else if (x.kind === 2 && !this.contains(fn, x.to)) out.push({ fn: this.functionByAddr(x.to), to: x.to, from: x.from, kind: x.kind });
      else if (x.kind === 3 && this.gotNames.has(x.to)) out.push({ fn: null, to: x.to, from: x.from, kind: 1 });
    }
    return out;
  }
  /** Human-readable name for a callee target (resolves PLT stubs + GOT slots to `libc` names). */
  callNameFor(to: number): string {
    const p = this.pltNames.get(to);
    if (p) return p.replace(/@plt$/, "");
    const g = this.gotNames.get(to);
    if (g) return g.replace(/@.*$/, "");
    const s = this.symbolNames.get(to);
    if (s) return s.name;
    const f = this.functionByAddr(to);
    if (f) return this.nameFor(f.addr).name;
    return this.labelFor(to);
  }
  /** All import names used by a function (PLT + GOT + symbol calls), deduplicated. */
  importCallsOf(fn: FunctionRecord): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const c of this.calleesOf(fn)) {
      const n = this.callNameFor(c.to).replace(/@.*$/, "");
      if (!n || /^sub_|^loc_|^a[A-Za-z0-9_]{2,}$/.test(n)) continue;
      if (!seen.has(n)) { seen.add(n); out.push(n); }
    }
    // Belt & braces: features also track GOT imports found during scan.
    const feat = fn.features?.importCalls ?? [];
    for (const n of feat) {
      const clean = n.replace(/@.*$/, "");
      if (clean && !seen.has(clean)) { seen.add(clean); out.push(clean); }
    }
    return out.slice(0, 64);
  }
  /** Every function that references a given import (by GOT slot or PLT stub). */
  importUsers(importName: string, limit = 200): { fn: FunctionRecord; via: number }[] {
    const base = importName.replace(/@.*$/, "").toLowerCase();
    const gotAddrs = new Set<number>();
    for (const [addr, name] of this.gotNames) if (name.replace(/@.*$/, "").toLowerCase() === base) gotAddrs.add(addr);
    for (const [addr, name] of this.pltNames) if (name.replace(/@.*$/, "").toLowerCase() === base) gotAddrs.add(addr);
    for (const s of this.elf.imports) if (s.name.toLowerCase() === base) {
      // imports without a resolved slot: match by symbol call edges too
    }
    const out: { fn: FunctionRecord; via: number }[] = [];
    if (!gotAddrs.size) {
      // Fall back to feature-based matching (symbol-named callees).
      for (const f of this.functions) {
        if (f.features?.importCalls.some((n) => n.replace(/@.*$/, "").toLowerCase() === base)) {
          out.push({ fn: f, via: f.addr });
          if (out.length >= limit) break;
        }
      }
      return out;
    }
    const { from, to } = this.xrefs;
    for (let i = 0; i < this.xrefs.count && out.length < limit; i++) {
      if (!gotAddrs.has(to[i])) continue;
      const f = this.functionAt(from[i]);
      if (f && !out.some((o) => o.fn.addr === f.addr)) out.push({ fn: f, via: from[i] });
    }
    return out;
  }
  /** Most-used imports across the binary (for the Overview + AI library map). */
  topImports(limit = 25): { name: string; users: number; library: string }[] {
    const counts = new Map<string, number>();
    for (const f of this.functions) {
      if (!f.features) continue;
      for (const n of f.features.importCalls) {
        const clean = n.replace(/@.*$/, "");
        if (!clean) continue;
        counts.set(clean, (counts.get(clean) ?? 0) + 1);
      }
    }
    // Also count GOT-based edges for functions whose features are not built yet.
    const libOf = (n: string) => this.importLibraryOf(n);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([name, users]) => ({ name, users, library: libOf(name) }));
  }
  /** Best-effort library for an import: parses `name@LIB` versions, else guesses libc. */
  importLibraryOf(importName: string): string {
    const base = importName.replace(/@.*$/, "");
    for (const s of this.elf.imports) {
      if (s.name === base && s.version) return versionToLib(s.version);
    }
    for (const s of this.elf.symbols) {
      if (s.name === base && s.version) return versionToLib(s.version);
    }
    if (/^(memcpy|memset|memcmp|memmove|strlen|strcmp|malloc|free|open|read|write|mmap|pthread_|gettimeofday|clock_gettime|__android_log_|abort|exit|kill|ptrace|dlopen|dlsym|socket|send|recv|connect|fopen|fread|fwrite|inflate|deflate|SHA|MD5|AES_|EVP_)/.test(base)) return "libc/libsystem (inferred)";
    return this.elf.needed[0] ?? "unknown";
  }
  /** Needed libraries + how many imports plausibly come from each. */
  libraryMap(): { library: string; imports: string[] }[] {
    const groups = new Map<string, string[]>();
    for (const lib of this.elf.needed) groups.set(lib, []);
    const fallback = this.elf.needed[0] ?? "unknown";
    for (const s of this.elf.imports) {
      const lib = s.version ? versionToLib(s.version) : guessLibForImport(s.name, this.elf.needed) ?? fallback;
      if (!groups.has(lib)) groups.set(lib, []);
      groups.get(lib)!.push(s.version ? `${s.name}@${s.version}` : s.name);
    }
    return [...groups.entries()].map(([library, imports]) => ({ library, imports }));
  }
  dataRefsOf(fn: FunctionRecord): Xref[] {
    return this.xrefs.refsFromRange(fn.addr, fn.addr + fn.size).filter((x) => x.kind >= 3 && x.kind <= 5);
  }
  contains(fn: FunctionRecord, addr: number) {
    return addr >= fn.addr && addr < fn.addr + fn.size;
  }

  // ------------------------------------------------------------- decoding
  /** Decode instructions for a function (bounded). */
  decodeFunction(fn: FunctionRecord, limit = 20_000): Instruction[] {
    return this.decodeAt(fn.addr, fn.size, limit);
  }
  decodeAt(va: number, length: number, limit = 4096): Instruction[] {
    if (!this.arch) return [];
    const off = this.space.vaToOffset(va);
    if (off === null) return [];
    const range = this.space.rangeAt(va);
    const maxLen = range ? Math.min(length, range.vaddr + range.size - va) : length;
    return decodeRange(this.arch, this.bytes, off, va, Math.max(0, maxLen), this.elf.header.littleEndian, limit);
  }

  readBytes(va: number, len: number): Uint8Array {
    const off = this.space.vaToOffset(va);
    if (off === null) return new Uint8Array(0);
    return this.bytes.subarray(off, Math.min(this.bytes.length, off + len));
  }
  readPointer(va: number): number | null {
    const off = this.space.vaToOffset(va);
    if (off === null) return null;
    const is64 = this.elf.header.elfClass === 64;
    if (off + (is64 ? 8 : 4) > this.bytes.length) return null;
    const dv = new DataView(this.bytes.buffer, this.bytes.byteOffset + off, is64 ? 8 : 4);
    const le = this.elf.header.littleEndian;
    if (!is64) return dv.getUint32(0, le);
    const lo = dv.getUint32(le ? 0 : 4, le), hi = dv.getUint32(le ? 4 : 0, le);
    return hi * 0x100000000 + lo;
  }

  // ------------------------------------------------------------- PLT
  /**
   * Name PLT stubs by walking JUMP_SLOT / GLOB_DAT relocations and finding the
   * stubs that reference each GOT slot. Covers `.plt`, `.plt.sec` (x86-64 with
   * IBT, where the real jump stubs live) and `.plt.got`.
   */
  private resolvePlt() {
    if (!this.arch) return;
    const pltSections = this.elf.sections.filter((s) => s.exec && s.size > 0 && /^\.plt(\.sec|\.got)?$/.test(s.name));
    if (!pltSections.length) return;
    const slots = this.gotNames;
    if (!slots.size) return;
    // ARM64 and x86 stubs are 16 bytes and 16-byte aligned within the section (the ARM64 PLT0 header is 32 bytes,
    // so the alignment still holds). The A32 decoder emits the GOT reference from the stub's first instruction.
    const stubSize = 16;
    for (const plt of pltSections) {
      const insns = this.decodeAt(plt.addr, plt.size, 200_000);
      for (const r of this.arch.fuseDataRefs(insns)) {
        const name = slots.get(r.to);
        if (!name) continue;
        const stub = this.arch.id === "arm32" ? r.from : plt.addr + Math.floor((r.from - plt.addr) / stubSize) * stubSize;
        if (!this.pltNames.has(stub)) this.pltNames.set(stub, `${name}@plt`);
      }
    }
  }

  // ------------------------------------------------------------- stats
  stats() {
    return {
      functions: this.functions.length,
      strings: this.strings.length,
      xrefs: this.xrefs.count,
      imports: this.elf.imports.length,
      exports: this.elf.exports.length,
      relocations: this.elf.relocations.length,
      sections: this.elf.sections.length,
      segments: this.elf.segments.length,
      globals: this.globals.length,
      structures: this.structures.length,
    };
  }
}

function rank(s: ElfSymbol) {
  let r = 0;
  if (s.binding === "global") r += 3;
  else if (s.binding === "weak") r += 2;
  if (s.kind === "func") r += 2;
  else if (s.kind === "object") r += 1;
  if (s.table === "symtab") r += 0.5;
  return r;
}

/** Map an ELF symbol version (e.g. `LIBC`, `LIBC_N`, `GLIBC_2.17`) to a library name. */
export function versionToLib(version: string): string {
  const v = version.toUpperCase();
  if (v.includes("GLIBC") || v === "LIBC" || v.startsWith("LIBC_")) return "libc.so";
  if (v.includes("LIBM")) return "libm.so";
  if (v.includes("LIBDL")) return "libdl.so";
  if (v.includes("LIBPTHREAD") || v.includes("LIBC_N")) return "libpthread/libc (threads)";
  if (v.includes("LIBLOG") || v.includes("LIBANDROID")) return "liblog/libandroid";
  if (v.includes("LIBEGL") || v.includes("LIBGLES") || v.includes("LIBVULKAN")) return "libEGL/libGLESv2";
  if (v.includes("OPENSSL") || v.includes("LIBCRYPTO") || v.includes("LIBSSL")) return "libcrypto/libssl";
  if (v.includes("ZLIB")) return "libz";
  if (v.includes("CXXABI") || v.includes("GLIBCXX") || v.includes("LIBSTDC")) return "libc++/libstdc++";
  return version;
}

/** Heuristic owner library for well-known libc-style imports when no version is present. */
export function guessLibForImport(name: string, needed: string[]): string | null {
  if (/^(memcpy|memmove|memset|memcmp|strlen|strcmp|strncmp|strcpy|malloc|calloc|realloc|free|open|read|write|close|mmap|munmap|mprotect|pthread_|gettimeofday|clock_gettime|nanosleep|abort|exit|_exit|kill|raise|ptrace|dlopen|dlsym|dlclose|socket|send|recv|connect|bind|fopen|fread|fwrite|fclose|printf|snprintf|sscanf|atoi|strtol|toupper|__.*chk|__cxa_|_Znwm|_ZdlPv)/.test(name)) {
    const sys = needed.find((l) => /libc\.so|libc\+\+|libsystem/i.test(l)) ?? needed[0] ?? null;
    return sys;
  }
  if (/^(__android_log|ANativeWindow_|AHardwareBuffer_|AAsset|ASensor)/.test(name)) return needed.find((l) => /android|log/i.test(l)) ?? "libandroid/liblog";
  if (/^(gl|egl|vk|ANativeWindow)/.test(name)) return needed.find((l) => /EGL|GLES|vulkan/i.test(l)) ?? "libEGL/libGLESv2";
  if (/^(SSL_|EVP_|SHA|MD5|HMAC|RSA_|AES_|BN_|RAND_)/.test(name)) return needed.find((l) => /crypto|ssl/i.test(l)) ?? "libcrypto";
  if (/^(inflate|deflate|uncompress|compress)/.test(name)) return needed.find((l) => /z\.so|zip/i.test(l)) ?? "libz";
  if (/^(Java_|JNI_|FindClass|GetMethodID|NewStringUTF)/.test(name)) return "JNI (Java side)";
  return null;
}

export function sanitize(s: string) {
  return s.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "") || "str";
}

export type { ChunkScanResult };
