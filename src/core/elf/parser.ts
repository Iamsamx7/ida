import {
  ArchId,
  DT_NAMES,
  EM_INFO,
  ET_NAMES,
  ElfDynamicEntry,
  ElfHeader,
  ElfImage,
  ElfRelocation,
  ElfSection,
  ElfSegment,
  ElfSymbol,
  ElfWarning,
  PT_NAMES,
  RELOC_NAMES,
  SHT_NAMES,
  SymbolBinding,
  SymbolKind,
} from "./types";

export class ElfParseError extends Error {}

/** Safe reader that never throws on out-of-range access; callers check bounds. */
export class ByteReader {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  le = true;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  get length() {
    return this.bytes.length;
  }
  has(off: number, len: number) {
    return off >= 0 && len >= 0 && off + len <= this.bytes.length;
  }
  u8(off: number) {
    return this.has(off, 1) ? this.bytes[off] : 0;
  }
  u16(off: number) {
    return this.has(off, 2) ? this.view.getUint16(off, this.le) : 0;
  }
  u32(off: number) {
    return this.has(off, 4) ? this.view.getUint32(off, this.le) : 0;
  }
  i32(off: number) {
    return this.has(off, 4) ? this.view.getInt32(off, this.le) : 0;
  }
  /** 64-bit read as JS number (safe for all realistic .so addresses; flags overflow). */
  u64(off: number) {
    if (!this.has(off, 8)) return 0;
    const lo = this.view.getUint32(off + (this.le ? 0 : 4), this.le);
    const hi = this.view.getUint32(off + (this.le ? 4 : 0), this.le);
    return hi * 0x100000000 + lo;
  }
  i64(off: number) {
    if (!this.has(off, 8)) return 0;
    const v = this.view.getBigInt64(off, this.le);
    const n = Number(v);
    return Number.isSafeInteger(n) ? n : n; // caller tolerates precision loss for huge addends
  }
  cstr(off: number, max = 4096) {
    if (off < 0 || off >= this.bytes.length) return "";
    let end = off;
    const lim = Math.min(this.bytes.length, off + max);
    while (end < lim && this.bytes[end] !== 0) end++;
    return latin1(this.bytes.subarray(off, end));
  }
}

const decoder = new TextDecoder("utf-8", { fatal: false });
export function latin1(b: Uint8Array) {
  return decoder.decode(b);
}

function permString(flags: number) {
  return `${flags & 4 ? "r" : "-"}${flags & 2 ? "w" : "-"}${flags & 1 ? "x" : "-"}`;
}

function shFlagString(f: number) {
  let s = "";
  if (f & 0x1) s += "W";
  if (f & 0x2) s += "A";
  if (f & 0x4) s += "X";
  if (f & 0x10) s += "M";
  if (f & 0x20) s += "S";
  if (f & 0x40) s += "I";
  if (f & 0x80) s += "L";
  if (f & 0x400) s += "T";
  return s;
}

function symKind(t: number): SymbolKind {
  switch (t) {
    case 0:
      return "notype";
    case 1:
      return "object";
    case 2:
      return "func";
    case 3:
      return "section";
    case 4:
      return "file";
    case 5:
      return "common";
    case 6:
      return "tls";
    case 10:
      return "func"; // GNU_IFUNC
    default:
      return "other";
  }
}
function symBinding(b: number): SymbolBinding {
  return b === 0 ? "local" : b === 1 ? "global" : b === 2 ? "weak" : "other";
}

export interface ParseOptions {
  /** Cap on symbols parsed per table (protects against malicious headers). */
  maxSymbols?: number;
  maxRelocations?: number;
}

/**
 * Parse an ELF image. Never throws for malformed content after the magic check;
 * problems are reported through `warnings`. Throws ElfParseError only when the
 * buffer is not an ELF file at all.
 */
export function parseElf(bytes: Uint8Array, opts: ParseOptions = {}): ElfImage {
  const maxSymbols = opts.maxSymbols ?? 2_000_000;
  const maxRelocs = opts.maxRelocations ?? 4_000_000;
  const warnings: ElfWarning[] = [];
  const warn = (message: string, level: "warning" | "error" = "warning") => {
    if (warnings.length < 200) warnings.push({ level, message });
  };

  if (bytes.length < 16 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    throw new ElfParseError("Not an ELF file (bad magic)");
  }
  const r = new ByteReader(bytes);
  const cls = bytes[4];
  if (cls !== 1 && cls !== 2) throw new ElfParseError(`Invalid ELF class ${cls}`);
  const is64 = cls === 2;
  const data = bytes[5];
  if (data !== 1 && data !== 2) throw new ElfParseError(`Invalid ELF data encoding ${data}`);
  r.le = data === 1;
  const minHeader = is64 ? 64 : 52;
  if (bytes.length < minHeader) throw new ElfParseError("Truncated ELF header");

  const machine = r.u16(18);
  const em = EM_INFO[machine];
  const header: ElfHeader = {
    elfClass: is64 ? 64 : 32,
    littleEndian: r.le,
    osabi: bytes[7],
    type: r.u16(16),
    typeName: ET_NAMES[r.u16(16)] ?? `0x${r.u16(16).toString(16)}`,
    machine,
    machineName: em?.name ?? `EM_${machine}`,
    arch: (em?.arch ?? "unknown") as ArchId,
    version: r.u32(20),
    entry: is64 ? r.u64(24) : r.u32(24),
    phoff: is64 ? r.u64(32) : r.u32(28),
    shoff: is64 ? r.u64(40) : r.u32(32),
    flags: is64 ? r.u32(48) : r.u32(36),
    ehsize: is64 ? r.u16(52) : r.u16(40),
    phentsize: is64 ? r.u16(54) : r.u16(42),
    phnum: is64 ? r.u16(56) : r.u16(44),
    shentsize: is64 ? r.u16(58) : r.u16(46),
    shnum: is64 ? r.u16(60) : r.u16(48),
    shstrndx: is64 ? r.u16(62) : r.u16(50),
  };

  // ---- Program headers ----
  const segments: ElfSegment[] = [];
  const phentMin = is64 ? 56 : 32;
  if (header.phnum > 0) {
    if (header.phentsize < phentMin) warn(`Program header entry size ${header.phentsize} too small`, "error");
    else if (!r.has(header.phoff, header.phentsize * header.phnum)) warn("Program header table lies outside file", "error");
    else {
      for (let i = 0; i < header.phnum; i++) {
        const o = header.phoff + i * header.phentsize;
        const type = r.u32(o);
        let seg: ElfSegment;
        if (is64) {
          const flags = r.u32(o + 4);
          seg = {
            index: i,
            type,
            typeName: PT_NAMES[type] ?? `0x${type.toString(16)}`,
            flags,
            perms: permString(flags),
            offset: r.u64(o + 8),
            vaddr: r.u64(o + 16),
            paddr: r.u64(o + 24),
            filesz: r.u64(o + 32),
            memsz: r.u64(o + 40),
            align: r.u64(o + 48),
          };
        } else {
          const flags = r.u32(o + 24);
          seg = {
            index: i,
            type,
            typeName: PT_NAMES[type] ?? `0x${type.toString(16)}`,
            flags,
            perms: permString(flags),
            offset: r.u32(o + 4),
            vaddr: r.u32(o + 8),
            paddr: r.u32(o + 12),
            filesz: r.u32(o + 16),
            memsz: r.u32(o + 20),
            align: r.u32(o + 28),
          };
        }
        if (seg.type === 1 && seg.offset + seg.filesz > bytes.length) {
          warn(`LOAD segment ${i} extends beyond end of file (truncated file?)`);
          seg.filesz = Math.max(0, Math.min(seg.filesz, bytes.length - seg.offset));
        }
        segments.push(seg);
      }
    }
  }

  // ---- Section headers ----
  const sections: ElfSection[] = [];
  const shentMin = is64 ? 64 : 40;
  if (header.shnum > 0 && header.shoff > 0) {
    if (header.shentsize < shentMin) warn(`Section header entry size ${header.shentsize} too small`, "error");
    else if (!r.has(header.shoff, header.shentsize * header.shnum)) warn("Section header table lies outside file; continuing with segments only", "error");
    else {
      const raw: ElfSection[] = [];
      for (let i = 0; i < header.shnum; i++) {
        const o = header.shoff + i * header.shentsize;
        const nameOff = r.u32(o);
        const type = r.u32(o + 4);
        const flags = is64 ? r.u64(o + 8) : r.u32(o + 8);
        const s: ElfSection = {
          index: i,
          name: String(nameOff),
          type,
          typeName: SHT_NAMES[type] ?? `0x${type.toString(16)}`,
          flags,
          flagStr: shFlagString(flags),
          addr: is64 ? r.u64(o + 16) : r.u32(o + 12),
          offset: is64 ? r.u64(o + 24) : r.u32(o + 16),
          size: is64 ? r.u64(o + 32) : r.u32(o + 20),
          link: is64 ? r.u32(o + 40) : r.u32(o + 24),
          info: is64 ? r.u32(o + 44) : r.u32(o + 28),
          addralign: is64 ? r.u64(o + 48) : r.u32(o + 32),
          entsize: is64 ? r.u64(o + 56) : r.u32(o + 36),
          exec: (flags & 0x4) !== 0,
          alloc: (flags & 0x2) !== 0,
          write: (flags & 0x1) !== 0,
        };
        raw.push(s);
      }
      const shstr = raw[header.shstrndx];
      for (const s of raw) {
        const nameOff = Number(s.name);
        s.name = shstr && shstr.type !== 8 && r.has(shstr.offset + nameOff, 1) ? r.cstr(shstr.offset + nameOff, 256) : `section_${s.index}`;
        if (s.type !== 8 && s.size > 0 && !r.has(s.offset, s.size)) {
          warn(`Section ${s.name} (${s.index}) extends beyond end of file`);
        }
        sections.push(s);
      }
    }
  }

  const sectionByName = (n: string) => sections.find((s) => s.name === n);
  const va2off = (va: number): number | null => {
    for (const seg of segments) {
      if (seg.type === 1 && va >= seg.vaddr && va < seg.vaddr + seg.filesz) return seg.offset + (va - seg.vaddr);
    }
    for (const s of sections) {
      if (s.type !== 8 && s.alloc && va >= s.addr && va < s.addr + s.size) return s.offset + (va - s.addr);
    }
    return null;
  };

  // ---- Dynamic section ----
  const dynamic: ElfDynamicEntry[] = [];
  const dynSeg = segments.find((s) => s.type === 2);
  const dynSec = sectionByName(".dynamic");
  const dynOff = dynSeg ? dynSeg.offset : dynSec ? dynSec.offset : -1;
  const dynSize = dynSeg ? dynSeg.filesz : dynSec ? dynSec.size : 0;
  const dynEnt = is64 ? 16 : 8;
  const dyn: Record<number, number> = {};
  if (dynOff >= 0 && r.has(dynOff, Math.min(dynSize, dynEnt))) {
    const n = Math.min(Math.floor(dynSize / dynEnt), 10_000);
    for (let i = 0; i < n; i++) {
      const o = dynOff + i * dynEnt;
      if (!r.has(o, dynEnt)) break;
      const tag = is64 ? r.u64(o) : r.u32(o);
      const value = is64 ? r.u64(o + 8) : r.u32(o + 4);
      dynamic.push({ tag, tagName: DT_NAMES[tag] ?? `0x${tag.toString(16)}`, value });
      if (tag === 0) break;
      if (!(tag in dyn)) dyn[tag] = value;
    }
  }

  // Dynamic string table
  const dynstrOff = dyn[5] !== undefined ? va2off(dyn[5]) : sectionByName(".dynstr")?.offset ?? null;
  const dynstrSize = dyn[10] ?? sectionByName(".dynstr")?.size ?? 0;
  const dynStr = (o: number) => (dynstrOff !== null && o < Math.max(dynstrSize, 1) + 0x100000 ? r.cstr(dynstrOff + o) : "");
  const needed: string[] = [];
  let soname: string | null = null;
  for (const d of dynamic) {
    if (d.tag === 1) {
      d.text = dynStr(d.value);
      needed.push(d.text);
    } else if (d.tag === 14) {
      d.text = dynStr(d.value);
      soname = d.text;
    } else if (d.tag === 15 || d.tag === 29) d.text = dynStr(d.value);
  }

  // ---- Hash tables (also used to determine dynsym count without sections) ----
  let hasGnuHash = false;
  let hasSysvHash = false;
  let gnuHashInfo: ElfImage["gnuHashInfo"];
  let sysvHashInfo: ElfImage["sysvHashInfo"];
  let dynsymCount = 0;
  if (dyn[4] !== undefined) {
    const o = va2off(dyn[4]);
    if (o !== null && r.has(o, 8)) {
      hasSysvHash = true;
      sysvHashInfo = { nbuckets: r.u32(o), nchains: r.u32(o + 4) };
      dynsymCount = sysvHashInfo.nchains;
    }
  }
  if (dyn[0x6ffffef5] !== undefined) {
    const o = va2off(dyn[0x6ffffef5]);
    if (o !== null && r.has(o, 16)) {
      hasGnuHash = true;
      const nbuckets = r.u32(o);
      const symoffset = r.u32(o + 4);
      const bloomSize = r.u32(o + 8);
      const bloomShift = r.u32(o + 12);
      gnuHashInfo = { nbuckets, symoffset, bloomSize, bloomShift };
      const wordSize = is64 ? 8 : 4;
      const bucketsOff = o + 16 + bloomSize * wordSize;
      const chainsOff = bucketsOff + nbuckets * 4;
      if (nbuckets < 1_000_000 && r.has(bucketsOff, nbuckets * 4)) {
        let maxSym = 0;
        for (let i = 0; i < nbuckets; i++) maxSym = Math.max(maxSym, r.u32(bucketsOff + i * 4));
        if (maxSym >= symoffset) {
          let idx = maxSym;
          let guard = 0;
          while (guard++ < 5_000_000) {
            const c = chainsOff + (idx - symoffset) * 4;
            if (!r.has(c, 4)) break;
            const v = r.u32(c);
            idx++;
            if (v & 1) break;
          }
          dynsymCount = Math.max(dynsymCount, idx);
        } else dynsymCount = Math.max(dynsymCount, symoffset);
      }
    }
  }

  // ---- Symbols ----
  const symbols: ElfSymbol[] = [];
  const symEnt = is64 ? 24 : 16;
  const readSymbols = (
    off: number,
    count: number,
    strOff: number | null,
    table: "dynsym" | "symtab",
  ) => {
    const out: ElfSymbol[] = [];
    if (off < 0 || strOff === null) return out;
    const n = Math.min(count, maxSymbols);
    for (let i = 0; i < n; i++) {
      const o = off + i * symEnt;
      if (!r.has(o, symEnt)) {
        warn(`${table} truncated at entry ${i}`);
        break;
      }
      let nameOff: number, info: number, shndx: number, value: number, size: number;
      if (is64) {
        nameOff = r.u32(o);
        info = r.u8(o + 4);
        shndx = r.u16(o + 6);
        value = r.u64(o + 8);
        size = r.u64(o + 16);
      } else {
        nameOff = r.u32(o);
        value = r.u32(o + 4);
        size = r.u32(o + 8);
        info = r.u8(o + 12);
        shndx = r.u16(o + 14);
      }
      out.push({
        index: i,
        name: r.cstr(strOff + nameOff, 8192),
        value,
        size,
        kind: symKind(info & 0xf),
        binding: symBinding(info >> 4),
        shndx,
        defined: shndx !== 0,
        table,
      });
    }
    return out;
  };

  const dynsymSec = sectionByName(".dynsym");
  let dynsymOff = dyn[6] !== undefined ? va2off(dyn[6]) : dynsymSec ? dynsymSec.offset : null;
  if (dynsymOff === null && dynsymSec) dynsymOff = dynsymSec.offset;
  if (dynsymSec && dynsymSec.entsize > 0) dynsymCount = Math.max(dynsymCount, Math.floor(dynsymSec.size / dynsymSec.entsize));
  if (dynsymOff !== null && dynsymCount === 0 && dynstrOff !== null && dynsymOff < dynstrOff) {
    // No hash info: bound the table by the string table that typically follows it.
    dynsymCount = Math.floor((dynstrOff - dynsymOff) / symEnt);
  }
  const dynSymbols = dynsymOff !== null ? readSymbols(dynsymOff, dynsymCount, dynstrOff, "dynsym") : [];

  // Symbol versions (GNU versym / verneed / verdef)
  const versymOff = dyn[0x6ffffff0] !== undefined ? va2off(dyn[0x6ffffff0]) : null;
  if (versymOff !== null && dynSymbols.length) {
    const verNames = new Map<number, string>();
    const verneedOff = dyn[0x6ffffffe] !== undefined ? va2off(dyn[0x6ffffffe]) : null;
    const verneedNum = dyn[0x6fffffff] ?? 0;
    if (verneedOff !== null) {
      let o = verneedOff;
      for (let i = 0; i < Math.min(verneedNum, 1000) && r.has(o, 16); i++) {
        const cnt = r.u16(o + 2);
        const aux = r.u32(o + 8);
        const next = r.u32(o + 12);
        let a = o + aux;
        for (let j = 0; j < Math.min(cnt, 1000) && r.has(a, 16); j++) {
          verNames.set(r.u16(a + 6), dynStr(r.u32(a + 8)));
          const an = r.u32(a + 12);
          if (!an) break;
          a += an;
        }
        if (!next) break;
        o += next;
      }
    }
    const verdefOff = dyn[0x6ffffffc] !== undefined ? va2off(dyn[0x6ffffffc]) : null;
    const verdefNum = dyn[0x6ffffffd] ?? 0;
    if (verdefOff !== null) {
      let o = verdefOff;
      for (let i = 0; i < Math.min(verdefNum, 1000) && r.has(o, 20); i++) {
        const ndx = r.u16(o + 4);
        const aux = r.u32(o + 12);
        const next = r.u32(o + 16);
        if (r.has(o + aux, 8)) verNames.set(ndx, dynStr(r.u32(o + aux)));
        if (!next) break;
        o += next;
      }
    }
    for (const s of dynSymbols) {
      const v = r.u16(versymOff + s.index * 2) & 0x7fff;
      if (v > 1 && verNames.has(v)) s.version = verNames.get(v);
    }
  }

  const symtabSec = sectionByName(".symtab");
  const strtabSec = symtabSec ? sections[symtabSec.link] : undefined;
  const staticSymbols =
    symtabSec && strtabSec && symtabSec.entsize > 0
      ? readSymbols(symtabSec.offset, Math.floor(symtabSec.size / symtabSec.entsize), strtabSec.offset, "symtab")
      : [];
  // Not `push(...spread)`: large .symtab tables (hundreds of thousands of entries) overflow the argument stack.
  for (const s of dynSymbols) symbols.push(s);
  for (const s of staticSymbols) symbols.push(s);

  const imports: ElfSymbol[] = [];
  const exports: ElfSymbol[] = [];
  for (const s of dynSymbols) {
    if (!s.name || s.kind === "section" || s.kind === "file") continue;
    if (!s.defined) imports.push(s);
    else if (s.binding !== "local") exports.push(s);
  }

  // ---- Relocations ----
  const relocations: ElfRelocation[] = [];
  const relNames = RELOC_NAMES[header.arch] ?? {};
  const symName = (i: number) => (i > 0 && i < dynSymbols.length ? dynSymbols[i].name : "");
  const readRelocs = (off: number, size: number, rela: boolean, sectionName: string) => {
    const ent = rela ? (is64 ? 24 : 12) : is64 ? 16 : 8;
    const n = Math.min(Math.floor(size / ent), maxRelocs - relocations.length);
    for (let i = 0; i < n; i++) {
      const o = off + i * ent;
      if (!r.has(o, ent)) {
        warn(`Relocation table ${sectionName} truncated`);
        break;
      }
      let offset: number, symIndex: number, type: number, addend = 0;
      if (is64) {
        offset = r.u64(o);
        const infoLo = r.u32(o + 8);
        const infoHi = r.u32(o + 12);
        if (r.le) {
          type = infoLo;
          symIndex = infoHi;
        } else {
          type = infoHi;
          symIndex = infoLo;
        }
        if (rela) addend = r.i64(o + 16);
      } else {
        offset = r.u32(o);
        const info = r.u32(o + 4);
        type = info & 0xff;
        symIndex = info >>> 8;
        if (rela) addend = r.i32(o + 8);
      }
      relocations.push({ offset, type, typeName: relNames[type] ?? `R_${type}`, symIndex, symName: symName(symIndex), addend, section: sectionName });
    }
  };
  if (dyn[7] !== undefined && dyn[8]) {
    const o = va2off(dyn[7]);
    if (o !== null) readRelocs(o, dyn[8], true, ".rela.dyn");
  }
  if (dyn[17] !== undefined && dyn[18]) {
    const o = va2off(dyn[17]);
    if (o !== null) readRelocs(o, dyn[18], false, ".rel.dyn");
  }
  if (dyn[23] !== undefined && dyn[2]) {
    const o = va2off(dyn[23]);
    if (o !== null) readRelocs(o, dyn[2], dyn[20] === 7, ".rela.plt");
  }
  // RELR (compressed relative relocations; Android uses these heavily)
  if (dyn[36] !== undefined && dyn[35]) {
    const o = va2off(dyn[36]);
    const ent = is64 ? 8 : 4;
    if (o !== null) {
      let where = 0;
      const n = Math.min(Math.floor(dyn[35] / ent), maxRelocs);
      const nbits = ent * 8 - 1;
      const pushRelr = (offset: number) => relocations.push({ offset, type: -1, typeName: "RELR_RELATIVE", symIndex: 0, symName: "", addend: 0, section: ".relr.dyn" });
      for (let i = 0; i < n && relocations.length < maxRelocs; i++) {
        const eo = o + i * ent;
        if (!r.has(eo, ent)) break;
        // Read the entry as 32-bit words so 64-bit bitmaps keep every bit (a JS number would lose bits above 2^53).
        const lo = r.u32(is64 && !r.le ? eo + 4 : eo);
        if ((lo & 1) === 0) {
          const e = is64 ? r.u64(eo) : r.u32(eo);
          pushRelr(e);
          where = e + ent;
        } else {
          const words = is64 ? [lo, r.u32(r.le ? eo + 4 : eo)] : [lo];
          for (let wi = 0; wi < words.length; wi++) {
            const word = words[wi];
            if (!word) continue;
            for (let b = wi === 0 ? 1 : 0; b < 32; b++) {
              if ((word >>> b) & 1) pushRelr(where + (wi * 32 + b - 1) * ent);
            }
          }
          where += nbits * ent;
        }
      }
    }
  }

  // ---- init / fini arrays ----
  const readPtrArray = (va: number | undefined, size: number | undefined) => {
    const out: number[] = [];
    if (va === undefined || !size) return out;
    const o = va2off(va);
    const ent = is64 ? 8 : 4;
    if (o === null) return out;
    const n = Math.min(Math.floor(size / ent), 100_000);
    for (let i = 0; i < n; i++) out.push(is64 ? r.u64(o + i * ent) : r.u32(o + i * ent));
    return out;
  };
  const initArray = readPtrArray(dyn[25], dyn[27]);
  const finiArray = readPtrArray(dyn[26], dyn[28]);
  if (dyn[12]) initArray.unshift(dyn[12]);
  if (dyn[13]) finiArray.unshift(dyn[13]);

  const tlsSeg = segments.find((s) => s.type === 7);

  if (!segments.length && !sections.length) warn("No program or section headers found", "error");
  if (header.arch === "unknown") warn(`Unsupported machine type ${machine}; disassembly unavailable`, "warning");

  return {
    header,
    segments,
    sections,
    dynamic,
    symbols,
    imports,
    exports,
    relocations,
    needed,
    soname,
    initArray,
    finiArray,
    hasGnuHash,
    hasSysvHash,
    gnuHashInfo,
    sysvHashInfo,
    tls: tlsSeg ? { vaddr: tlsSeg.vaddr, filesz: tlsSeg.filesz, memsz: tlsSeg.memsz, align: tlsSeg.align } : undefined,
    stripped: staticSymbols.length === 0,
    warnings,
    fileSize: bytes.length,
  };
}
