export type ArchId = "arm64" | "arm32" | "x86_64" | "x86" | "unknown";

export interface ElfHeader {
  elfClass: 32 | 64;
  littleEndian: boolean;
  osabi: number;
  type: number;
  typeName: string;
  machine: number;
  machineName: string;
  arch: ArchId;
  version: number;
  entry: number;
  phoff: number;
  shoff: number;
  flags: number;
  ehsize: number;
  phentsize: number;
  phnum: number;
  shentsize: number;
  shnum: number;
  shstrndx: number;
}

export interface ElfSegment {
  index: number;
  type: number;
  typeName: string;
  flags: number;
  perms: string; // e.g. "r-x"
  offset: number;
  vaddr: number;
  paddr: number;
  filesz: number;
  memsz: number;
  align: number;
}

export interface ElfSection {
  index: number;
  name: string;
  type: number;
  typeName: string;
  flags: number;
  flagStr: string;
  addr: number;
  offset: number;
  size: number;
  link: number;
  info: number;
  addralign: number;
  entsize: number;
  exec: boolean;
  alloc: boolean;
  write: boolean;
}

export type SymbolKind = "func" | "object" | "section" | "file" | "tls" | "notype" | "common" | "other";
export type SymbolBinding = "local" | "global" | "weak" | "other";

export interface ElfSymbol {
  index: number;
  name: string;
  value: number;
  size: number;
  kind: SymbolKind;
  binding: SymbolBinding;
  shndx: number;
  defined: boolean;
  table: "dynsym" | "symtab";
  version?: string;
}

export interface ElfRelocation {
  offset: number;
  type: number;
  typeName: string;
  symIndex: number;
  symName: string;
  addend: number;
  section: string;
}

export interface ElfDynamicEntry {
  tag: number;
  tagName: string;
  value: number;
  text?: string;
}

export interface ElfWarning {
  level: "warning" | "error";
  message: string;
}

export interface ElfImage {
  header: ElfHeader;
  segments: ElfSegment[];
  sections: ElfSection[];
  dynamic: ElfDynamicEntry[];
  symbols: ElfSymbol[];
  imports: ElfSymbol[];
  exports: ElfSymbol[];
  relocations: ElfRelocation[];
  needed: string[];
  soname: string | null;
  initArray: number[];
  finiArray: number[];
  hasGnuHash: boolean;
  hasSysvHash: boolean;
  gnuHashInfo?: { nbuckets: number; symoffset: number; bloomSize: number; bloomShift: number };
  sysvHashInfo?: { nbuckets: number; nchains: number };
  tls?: { vaddr: number; filesz: number; memsz: number; align: number };
  stripped: boolean;
  warnings: ElfWarning[];
  fileSize: number;
}

export const PT_NAMES: Record<number, string> = {
  0: "NULL",
  1: "LOAD",
  2: "DYNAMIC",
  3: "INTERP",
  4: "NOTE",
  5: "SHLIB",
  6: "PHDR",
  7: "TLS",
  0x6474e550: "GNU_EH_FRAME",
  0x6474e551: "GNU_STACK",
  0x6474e552: "GNU_RELRO",
  0x6474e553: "GNU_PROPERTY",
  0x70000001: "ARM_EXIDX",
};

export const SHT_NAMES: Record<number, string> = {
  0: "NULL",
  1: "PROGBITS",
  2: "SYMTAB",
  3: "STRTAB",
  4: "RELA",
  5: "HASH",
  6: "DYNAMIC",
  7: "NOTE",
  8: "NOBITS",
  9: "REL",
  10: "SHLIB",
  11: "DYNSYM",
  14: "INIT_ARRAY",
  15: "FINI_ARRAY",
  16: "PREINIT_ARRAY",
  17: "GROUP",
  18: "SYMTAB_SHNDX",
  19: "RELR",
  0x6ffffff5: "GNU_ATTRIBUTES",
  0x6ffffff6: "GNU_HASH",
  0x6ffffffd: "GNU_verdef",
  0x6ffffffe: "GNU_verneed",
  0x6fffffff: "GNU_versym",
  0x70000001: "ARM_EXIDX",
  0x70000003: "ARM_ATTRIBUTES",
};

export const DT_NAMES: Record<number, string> = {
  0: "NULL",
  1: "NEEDED",
  2: "PLTRELSZ",
  3: "PLTGOT",
  4: "HASH",
  5: "STRTAB",
  6: "SYMTAB",
  7: "RELA",
  8: "RELASZ",
  9: "RELAENT",
  10: "STRSZ",
  11: "SYMENT",
  12: "INIT",
  13: "FINI",
  14: "SONAME",
  15: "RPATH",
  16: "SYMBOLIC",
  17: "REL",
  18: "RELSZ",
  19: "RELENT",
  20: "PLTREL",
  21: "DEBUG",
  22: "TEXTREL",
  23: "JMPREL",
  24: "BIND_NOW",
  25: "INIT_ARRAY",
  26: "FINI_ARRAY",
  27: "INIT_ARRAYSZ",
  28: "FINI_ARRAYSZ",
  29: "RUNPATH",
  30: "FLAGS",
  32: "PREINIT_ARRAY",
  33: "PREINIT_ARRAYSZ",
  35: "RELRSZ",
  36: "RELR",
  37: "RELRENT",
  0x6ffffef5: "GNU_HASH",
  0x6ffffff0: "VERSYM",
  0x6ffffff9: "RELACOUNT",
  0x6ffffffa: "RELCOUNT",
  0x6ffffffb: "FLAGS_1",
  0x6ffffffc: "VERDEF",
  0x6ffffffd: "VERDEFNUM",
  0x6ffffffe: "VERNEED",
  0x6fffffff: "VERNEEDNUM",
  0x7ffffffd: "AUXILIARY",
  0x7fffffff: "FILTER",
};

export const ET_NAMES: Record<number, string> = {
  0: "NONE",
  1: "REL",
  2: "EXEC",
  3: "DYN (shared object)",
  4: "CORE",
};

export const EM_INFO: Record<number, { name: string; arch: ArchId }> = {
  3: { name: "Intel 80386", arch: "x86" },
  40: { name: "ARM", arch: "arm32" },
  62: { name: "AMD x86-64", arch: "x86_64" },
  183: { name: "AArch64", arch: "arm64" },
};

export const RELOC_NAMES: Record<ArchId, Record<number, string>> = {
  arm64: {
    0: "R_AARCH64_NONE",
    257: "R_AARCH64_ABS64",
    258: "R_AARCH64_ABS32",
    1024: "R_AARCH64_COPY",
    1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT",
    1027: "R_AARCH64_RELATIVE",
    1028: "R_AARCH64_TLS_DTPMOD64",
    1029: "R_AARCH64_TLS_DTPREL64",
    1030: "R_AARCH64_TLS_TPREL64",
    1031: "R_AARCH64_TLSDESC",
    1032: "R_AARCH64_IRELATIVE",
  },
  arm32: {
    0: "R_ARM_NONE",
    2: "R_ARM_ABS32",
    20: "R_ARM_COPY",
    21: "R_ARM_GLOB_DAT",
    22: "R_ARM_JUMP_SLOT",
    23: "R_ARM_RELATIVE",
    17: "R_ARM_TLS_DTPMOD32",
    18: "R_ARM_TLS_DTPOFF32",
    19: "R_ARM_TLS_TPOFF32",
    160: "R_ARM_IRELATIVE",
  },
  x86_64: {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    5: "R_X86_64_COPY",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE",
    16: "R_X86_64_DTPMOD64",
    17: "R_X86_64_DTPOFF64",
    18: "R_X86_64_TPOFF64",
    37: "R_X86_64_IRELATIVE",
  },
  x86: {
    0: "R_386_NONE",
    1: "R_386_32",
    2: "R_386_PC32",
    5: "R_386_COPY",
    6: "R_386_GLOB_DAT",
    7: "R_386_JUMP_SLOT",
    8: "R_386_RELATIVE",
    42: "R_386_IRELATIVE",
  },
  unknown: {},
};
