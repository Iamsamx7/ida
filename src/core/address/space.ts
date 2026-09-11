import type { ElfImage, ElfSection, ElfSegment } from "../elf/types";

export interface MappedRange {
  vaddr: number;
  offset: number;
  size: number; // file-backed size
  memsz: number;
  exec: boolean;
  write: boolean;
  read: boolean;
  segmentIndex: number;
}

export interface AddressInfo {
  va: number;
  rva: number;
  fileOffset: number | null;
  segment: ElfSegment | null;
  segmentOffset: number | null;
  section: ElfSection | null;
  sectionOffset: number | null;
  exec: boolean;
  mapped: boolean;
}

export type GoToInput =
  | { kind: "va"; value: number }
  | { kind: "offset"; value: number }
  | { kind: "rva"; value: number }
  | { kind: "name"; value: string };

/**
 * Unified address model. All translations between VA, RVA, file offset and
 * section/segment-relative addressing go through here.
 */
export class AddressSpace {
  readonly ranges: MappedRange[];
  readonly imageBase: number;
  private sections: ElfSection[];

  constructor(elf: ElfImage) {
    const loads = elf.segments.filter((s) => s.type === 1);
    this.ranges = loads
      .map((s) => ({
        vaddr: s.vaddr,
        offset: s.offset,
        size: s.filesz,
        memsz: s.memsz,
        exec: (s.flags & 1) !== 0,
        write: (s.flags & 2) !== 0,
        read: (s.flags & 4) !== 0,
        segmentIndex: s.index,
      }))
      .sort((a, b) => a.vaddr - b.vaddr);
    // Fallback for object files / section-only images.
    if (!this.ranges.length) {
      for (const s of elf.sections) {
        if (s.alloc && s.type !== 8 && s.size > 0) {
          this.ranges.push({ vaddr: s.addr, offset: s.offset, size: s.size, memsz: s.size, exec: s.exec, write: s.write, read: true, segmentIndex: -1 });
        }
      }
      this.ranges.sort((a, b) => a.vaddr - b.vaddr);
    }
    this.imageBase = this.ranges.length ? this.ranges[0].vaddr - (this.ranges[0].vaddr % 0x1000) : 0;
    this.sections = elf.sections.filter((s) => s.alloc && s.size > 0).sort((a, b) => a.addr - b.addr);
    this.elfSegments = elf.segments;
  }
  private elfSegments: ElfSegment[];

  vaToOffset(va: number): number | null {
    for (const r of this.ranges) {
      if (va >= r.vaddr && va < r.vaddr + r.size) return r.offset + (va - r.vaddr);
    }
    return null;
  }

  offsetToVa(off: number): number | null {
    for (const r of this.ranges) {
      if (off >= r.offset && off < r.offset + r.size) return r.vaddr + (off - r.offset);
    }
    return null;
  }

  isMapped(va: number) {
    return this.ranges.some((r) => va >= r.vaddr && va < r.vaddr + r.memsz);
  }
  isExec(va: number) {
    return this.ranges.some((r) => r.exec && va >= r.vaddr && va < r.vaddr + r.size);
  }

  sectionAt(va: number): ElfSection | null {
    // binary search over sorted alloc sections
    let lo = 0,
      hi = this.sections.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const s = this.sections[mid];
      if (va < s.addr) hi = mid - 1;
      else if (va >= s.addr + s.size) lo = mid + 1;
      else return s;
    }
    return null;
  }

  rangeAt(va: number): MappedRange | null {
    for (const r of this.ranges) if (va >= r.vaddr && va < r.vaddr + r.memsz) return r;
    return null;
  }

  info(va: number): AddressInfo {
    const range = this.rangeAt(va);
    const section = this.sectionAt(va);
    const segment = range && range.segmentIndex >= 0 ? this.elfSegments[range.segmentIndex] : null;
    return {
      va,
      rva: va - this.imageBase,
      fileOffset: this.vaToOffset(va),
      segment,
      segmentOffset: segment ? va - segment.vaddr : null,
      section,
      sectionOffset: section ? va - section.addr : null,
      exec: range?.exec ?? false,
      mapped: !!range,
    };
  }

  /** Executable byte ranges (used by function discovery / disassembly). */
  execRanges(): MappedRange[] {
    return this.ranges.filter((r) => r.exec && r.size > 0);
  }

  /** Executable section ranges if sections are present (tighter than segments). */
  codeRanges(): { vaddr: number; offset: number; size: number; name: string }[] {
    const secs = this.sections.filter((s) => s.exec && s.type !== 8);
    if (secs.length) {
      return secs.map((s) => ({ vaddr: s.addr, offset: s.offset, size: s.size, name: s.name }));
    }
    return this.execRanges().map((r, i) => ({ vaddr: r.vaddr, offset: r.offset, size: r.size, name: `seg${i}` }));
  }

  /**
   * Parse user "Go To" input. Accepts hex (`0x1234`, `1234h`, or bare `1234` —
   * bare numbers are always hex, the RE-tool convention), `module+0x..`,
   * `off:`, `va:`, `rva:` prefixes, or a symbol name.
   */
  static parseGoTo(raw: string): GoToInput | null {
    const t = raw.trim();
    if (!t) return null;
    const m = t.match(/^(?:(module|base|image|rva)\s*\+\s*|(off|offset|file|va|rva)\s*:\s*)?(0x[0-9a-f]+|[0-9a-f]+h|[0-9a-f]+)$/i);
    if (m) {
      const numText = m[3];
      const value = /^0x/i.test(numText) ? parseInt(numText.slice(2), 16) : /h$/i.test(numText) ? parseInt(numText.slice(0, -1), 16) : parseInt(numText, 16);
      if (!Number.isFinite(value)) return null;
      const p = (m[1] ?? m[2] ?? "").toLowerCase();
      if (p === "module" || p === "base" || p === "image" || p === "rva") return { kind: "rva", value };
      if (p === "off" || p === "offset" || p === "file") return { kind: "offset", value };
      return { kind: "va", value };
    }
    return { kind: "name", value: t };
  }

  /** Resolve a numeric go-to into a VA, intelligently trying VA then offset then RVA. */
  resolve(input: GoToInput): { va: number; interpretedAs: string } | null {
    if (input.kind === "name") return null;
    if (input.kind === "rva") {
      const va = this.imageBase + input.value;
      return this.isMapped(va) ? { va, interpretedAs: "RVA" } : null;
    }
    if (input.kind === "offset") {
      const va = this.offsetToVa(input.value);
      return va !== null ? { va, interpretedAs: "file offset" } : null;
    }
    if (this.isMapped(input.value)) return { va: input.value, interpretedAs: "virtual address" };
    const fromOff = this.offsetToVa(input.value);
    if (fromOff !== null) return { va: fromOff, interpretedAs: "file offset" };
    const rva = this.imageBase + input.value;
    if (this.isMapped(rva)) return { va: rva, interpretedAs: "RVA" };
    return null;
  }
}

export function hex(n: number, pad = 0) {
  const s = Math.max(0, Math.floor(n)).toString(16);
  return "0x" + (pad ? s.padStart(pad, "0") : s);
}
