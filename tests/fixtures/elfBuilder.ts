/**
 * Builds a small but realistic AArch64 ELF shared object in memory:
 * exported + stripped functions, a global, GOT-based import calls, strings,
 * a hash loop, dynamic section, dynsym/dynstr, SysV hash and section headers.
 * Used by tests, the benchmark script and the in-app sample.
 */

// ---- tiny A64 assembler -----------------------------------------------------
export const A64 = {
  stpPre: (rt: number, rt2: number, rn: number, imm: number) => 0xa9800000 | (((imm / 8) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt,
  ldpPost: (rt: number, rt2: number, rn: number, imm: number) => 0xa8c00000 | (((imm / 8) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt,
  movSp: (rd: number, rn: number) => 0x91000000 | (rn << 5) | rd, // add rd, rn, #0
  adrp: (rd: number, pc: number, target: number) => {
    const imm = (target - (pc & ~0xfff)) / 4096;
    const immlo = imm & 3, immhi = (imm >> 2) & 0x7ffff;
    return (0x90000000 | (immlo << 29) | (immhi << 5) | rd) >>> 0;
  },
  addImm: (rd: number, rn: number, imm: number) => 0x91000000 | (imm << 10) | (rn << 5) | rd,
  subImm: (rd: number, rn: number, imm: number) => 0xd1000000 | (imm << 10) | (rn << 5) | rd,
  ldrX: (rt: number, rn: number, imm: number) => (0xf9400000 | ((imm / 8) << 10) | (rn << 5) | rt) >>> 0,
  ldrW: (rt: number, rn: number, imm: number) => (0xb9400000 | ((imm / 4) << 10) | (rn << 5) | rt) >>> 0,
  ldrbW: (rt: number, rn: number, imm: number) => (0x39400000 | (imm << 10) | (rn << 5) | rt) >>> 0,
  strX: (rt: number, rn: number, imm: number) => (0xf9000000 | ((imm / 8) << 10) | (rn << 5) | rt) >>> 0,
  bl: (pc: number, target: number) => (0x94000000 | (((target - pc) / 4) & 0x3ffffff)) >>> 0,
  b: (pc: number, target: number) => (0x14000000 | (((target - pc) / 4) & 0x3ffffff)) >>> 0,
  ret: () => 0xd65f03c0,
  cbz: (rt: number, pc: number, target: number) => (0xb4000000 | ((((target - pc) / 4) & 0x7ffff) << 5) | rt) >>> 0,
  cbnz: (rt: number, pc: number, target: number) => (0xb5000000 | ((((target - pc) / 4) & 0x7ffff) << 5) | rt) >>> 0,
  cmpImm: (rn: number, imm: number) => (0xf100001f | (imm << 10) | (rn << 5)) >>> 0,
  bcond: (cond: number, pc: number, target: number) => (0x54000000 | ((((target - pc) / 4) & 0x7ffff) << 5) | cond) >>> 0,
  movz: (rd: number, imm: number, shift = 0) => (0xd2800000 | ((shift / 16) << 21) | (imm << 5) | rd) >>> 0,
  movk: (rd: number, imm: number, shift = 0) => (0xf2800000 | ((shift / 16) << 21) | (imm << 5) | rd) >>> 0,
  movReg: (rd: number, rm: number) => (0xaa0003e0 | (rm << 16) | rd) >>> 0,
  eor: (rd: number, rn: number, rm: number) => (0xca000000 | (rm << 16) | (rn << 5) | rd) >>> 0,
  addReg: (rd: number, rn: number, rm: number) => (0x8b000000 | (rm << 16) | (rn << 5) | rd) >>> 0,
  ror: (rd: number, rn: number, imm: number) => (0x93c00000 | (rn << 16) | (imm << 10) | (rn << 5) | rd) >>> 0,
  blr: (rn: number) => (0xd63f0000 | (rn << 5)) >>> 0,
  nop: () => 0xd503201f,
  paciasp: () => 0xd503233f,
  autiasp: () => 0xd50323bf,
  subsImm: (rd: number, rn: number, imm: number) => (0xf1000000 | (imm << 10) | (rn << 5) | rd) >>> 0,
};

export interface BuiltSample {
  bytes: Uint8Array;
  addrs: Record<string, number>;
  strings: Record<string, number>;
}

export function buildSampleSo(opts: { hugeText?: number; /** Raw RELR entries (DT_RELR) to append, 64-bit words. */ relr?: bigint[] } = {}): BuiltSample {
  const TEXT = 0x1000, RODATA = 0x2000, DATA = 0x3000, GOT = 0x3100, DYNAMIC = 0x3800, DYNSYM = 0x100;
  const words: number[] = [];
  const addrs: Record<string, number> = {};
  const fixups: (() => void)[] = [];
  const pc = () => TEXT + words.length * 4;
  const emit = (w: number) => words.push(w >>> 0);
  const label = (n: string) => (addrs[n] = pc());
  const later = (fn: () => number) => { const at = words.length; emit(0); fixups.push(() => { words[at] = fn() >>> 0; }); };

  // strings in .rodata
  const strs: Record<string, number> = {};
  const roBytes: number[] = [];
  const addStr = (key: string, s: string) => { strs[key] = RODATA + roBytes.length; for (const ch of s) roBytes.push(ch.charCodeAt(0)); roBytes.push(0); };
  addStr("log", "libsample: init %s");
  addStr("url", "https://example.com/api/v1/session");
  addStr("err", "error: world state not initialized");
  addStr("path", "/data/local/tmp/config.json");
  addStr("cfg", "render.shadow_quality");

  const GLOBAL_WORLD = DATA + 0x0;
  const GOT_LOG = GOT + 0x0, GOT_SOCKET = GOT + 0x8, GOT_MALLOC = GOT + 0x10;

  // --- lib_init (exported): prologue, log string, calls hash + world reader, GOT call
  label("lib_init");
  emit(A64.paciasp());
  emit(A64.stpPre(29, 30, 31, -32));
  emit(A64.strX(19, 31, 16));
  emit(A64.movSp(29, 31));
  emit(A64.movReg(19, 0));
  later(() => A64.adrp(0, addrs.lib_init + 20, strs.log));
  emit(A64.addImm(0, 0, strs.log & 0xfff));
  emit(A64.movReg(1, 19));
  later(() => A64.adrp(8, addrs.lib_init + 32, GOT_LOG));
  emit(A64.ldrX(8, 8, GOT_LOG & 0xfff));
  emit(A64.blr(8));
  emit(A64.movz(0, 0x1234));
  emit(A64.movz(1, 32));
  later(() => A64.bl(addrs.lib_init + 52, addrs.hash_buffer));
  later(() => A64.bl(addrs.lib_init + 56, addrs.world_state_reader));
  emit(A64.ldrX(19, 31, 16));
  emit(A64.ldpPost(29, 30, 31, 32));
  emit(A64.autiasp());
  emit(A64.ret());

  // --- world_state_reader (stripped, no symbol): reads GlobalWorld, validates, returns world->state (+0x10)
  label("world_state_reader");
  later(() => A64.adrp(8, addrs.world_state_reader, GLOBAL_WORLD));
  emit(A64.ldrX(8, 8, GLOBAL_WORLD & 0xfff));
  later(() => A64.cbz(8, addrs.world_state_reader + 8, addrs.world_state_reader + 20));
  emit(A64.ldrX(0, 8, 0x10));
  emit(A64.ret());
  emit(A64.movz(0, 0)); // +20
  emit(A64.ret());

  // --- hash_buffer (stripped): FNV-like loop over (x0=ptr, x1=len)
  label("hash_buffer");
  emit(A64.movz(8, 0x9dc5));
  emit(A64.movk(8, 0x811c, 16));
  emit(A64.movz(9, 0x0193));
  emit(A64.movk(9, 0x0100, 16));
  emit(A64.cbz(1, pc(), pc() + 7 * 4)); // loop end
  const loop = pc();
  emit(A64.ldrbW(10, 0, 0));
  emit(A64.eor(8, 8, 10));
  emit(A64.ror(8, 8, 13));
  emit(A64.addReg(8, 8, 9));
  emit(A64.addImm(0, 0, 1));
  emit(A64.subsImm(1, 1, 1));
  emit(A64.bcond(1, pc(), loop)); // b.ne loop
  emit(A64.movReg(0, 8));
  emit(A64.ret());

  // --- net_send (exported): url string + socket via GOT
  label("net_send");
  emit(A64.stpPre(29, 30, 31, -16));
  emit(A64.movSp(29, 31));
  later(() => A64.adrp(0, addrs.net_send + 8, strs.url));
  emit(A64.addImm(0, 0, strs.url & 0xfff));
  later(() => A64.adrp(8, addrs.net_send + 16, GOT_SOCKET));
  emit(A64.ldrX(8, 8, GOT_SOCKET & 0xfff));
  emit(A64.blr(8));
  emit(A64.cmpImm(0, 0));
  emit(A64.bcond(10, pc(), pc() + 12)); // b.ge skip
  later(() => A64.adrp(0, addrs.net_send + 36, strs.err));
  emit(A64.addImm(0, 0, strs.err & 0xfff));
  emit(A64.ldpPost(29, 30, 31, 16));
  emit(A64.ret());

  // --- alloc_object (exported, memory): malloc via GOT, writes fields
  label("alloc_object");
  emit(A64.stpPre(29, 30, 31, -16));
  emit(A64.movSp(29, 31));
  emit(A64.movz(0, 0x40));
  later(() => A64.adrp(8, addrs.alloc_object + 12, GOT_MALLOC));
  emit(A64.ldrX(8, 8, GOT_MALLOC & 0xfff));
  emit(A64.blr(8));
  emit(A64.strX(31, 0, 0x8));
  emit(A64.strX(31, 0, 0x10));
  emit(A64.strX(31, 0, 0x20));
  emit(A64.ldpPost(29, 30, 31, 16));
  emit(A64.ret());

  // padding / bulk text for benchmarks: repeated copies of hash_buffer body
  if (opts.hugeText) {
    const copyStart = (addrs.hash_buffer - TEXT) / 4, copyLen = (addrs.net_send - addrs.hash_buffer) / 4;
    const body = words.slice(copyStart, copyStart + copyLen);
    while (words.length * 4 < opts.hugeText) {
      const base = pc();
      // rebase the loop's b.ne (relative, so identical) — body is position independent except nothing absolute
      for (const w of body) emit(w);
      void base;
    }
  }
  for (const f of fixups) f();

  // --- dynamic symbols
  const symNames = ["", "lib_init", "net_send", "alloc_object", "GlobalWorld", "__android_log_print", "socket", "malloc"];
  const dynstrBytes: number[] = [0];
  const strOff: Record<string, number> = { "": 0 };
  const addDynStr = (s: string) => { strOff[s] = dynstrBytes.length; for (const ch of s) dynstrBytes.push(ch.charCodeAt(0)); dynstrBytes.push(0); return strOff[s]; };
  for (const n of symNames.slice(1)) addDynStr(n);
  const soname = addDynStr("libsample.so");
  const needed = addDynStr("liblog.so");
  const needed2 = addDynStr("libc.so");
  const nsyms = symNames.length;
  const DYNSTR = DYNSYM + nsyms * 24;
  const HASH = align(DYNSTR + dynstrBytes.length, 8);
  const hashSize = 8 + 4 * 1 + 4 * nsyms;

  const textSize = words.length * 4;
  const fileSize = Math.max(0x4000, align(TEXT + textSize, 0x1000) + 0x3000);
  const TEXT_END = TEXT + textSize;
  const RODATA_ADDR = opts.hugeText ? align(TEXT_END, 0x1000) : RODATA;
  const DATA_ADDR = opts.hugeText ? RODATA_ADDR + 0x1000 : DATA;
  const GOT_ADDR = DATA_ADDR + 0x100, DYNAMIC_ADDR = DATA_ADDR + 0x800;
  // For hugeText mode we relocate rodata/data: fix strings and adrp fixups would be wrong, so hugeText mode keeps them in place (only used for perf).
  const roBase = opts.hugeText ? RODATA_ADDR : RODATA;
  const dataBase = opts.hugeText ? DATA_ADDR : DATA;

  const SHSTR_ADDR = DYNAMIC_ADDR + 0x200;
  const shNames = ["", ".dynsym", ".dynstr", ".hash", ".text", ".rodata", ".data", ".got", ".dynamic", ".shstrtab"];
  const shstrBytes: number[] = [0];
  const shOff: Record<string, number> = { "": 0 };
  for (const n of shNames.slice(1)) { shOff[n] = shstrBytes.length; for (const ch of n) shstrBytes.push(ch.charCodeAt(0)); shstrBytes.push(0); }
  const SHDR_OFF = align(SHSTR_ADDR + shstrBytes.length, 8);
  const total = Math.max(fileSize, SHDR_OFF + shNames.length * 64);
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  const w8 = (o: number, v: number) => (buf[o] = v);
  const w16 = (o: number, v: number) => dv.setUint16(o, v, true);
  const w32 = (o: number, v: number) => dv.setUint32(o, v >>> 0, true);
  const w64 = (o: number, v: number) => { dv.setUint32(o, v >>> 0, true); dv.setUint32(o + 4, Math.floor(v / 0x100000000), true); };

  // ELF header
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  w16(16, 3); w16(18, 183); w32(20, 1);
  w64(24, addrs.lib_init); w64(32, 64); w64(40, SHDR_OFF); w32(48, 0);
  w16(52, 64); w16(54, 56); w16(56, 3); w16(58, 64); w16(60, shNames.length); w16(62, shNames.length - 1);
  // Program headers
  const ph = (i: number, type: number, flags: number, off: number, va: number, filesz: number, memsz: number, alignv: number) => {
    const o = 64 + i * 56;
    w32(o, type); w32(o + 4, flags); w64(o + 8, off); w64(o + 16, va); w64(o + 24, va); w64(o + 32, filesz); w64(o + 40, memsz); w64(o + 48, alignv);
  };
  ph(0, 1, 5, 0, 0, dataBase, dataBase, 0x1000);
  ph(1, 1, 6, dataBase, dataBase, total - dataBase, total - dataBase, 0x1000);
  ph(2, 2, 6, DYNAMIC_ADDR, DYNAMIC_ADDR, 0x100, 0x100, 8);
  // dynsym
  const sym = (i: number, name: string, info: number, shndx: number, value: number, size: number) => {
    const o = DYNSYM + i * 24;
    w32(o, strOff[name]); w8(o + 4, info); w8(o + 5, 0); w16(o + 6, shndx); w64(o + 8, value); w64(o + 16, size);
  };
  sym(1, "lib_init", 0x12, 4, addrs.lib_init, addrs.world_state_reader - addrs.lib_init);
  sym(2, "net_send", 0x12, 4, addrs.net_send, addrs.alloc_object - addrs.net_send);
  sym(3, "alloc_object", 0x12, 4, addrs.alloc_object, 44);
  sym(4, "GlobalWorld", 0x11, 6, dataBase, 8);
  sym(5, "__android_log_print", 0x12, 0, 0, 0);
  sym(6, "socket", 0x12, 0, 0, 0);
  sym(7, "malloc", 0x22, 0, 0, 0);
  buf.set(dynstrBytes, DYNSTR);
  // sysv hash: nbucket=1, nchain=nsyms
  w32(HASH, 1); w32(HASH + 4, nsyms); w32(HASH + 8, 1);
  for (let i = 0; i < nsyms; i++) w32(HASH + 12 + i * 4, i + 1 < nsyms ? i + 1 : 0);
  // text
  for (let i = 0; i < words.length; i++) w32(TEXT + i * 4, words[i]);
  // rodata
  buf.set(roBytes, roBase);
  // data: GlobalWorld pointer → points at an object in .data (+0x40)
  w64(dataBase, dataBase + 0x40);
  w64(dataBase + 0x50, addrs.world_state_reader); // vtable-like function pointer
  // optional RELR table in .data (+0x600)
  const RELR_ADDR = dataBase + 0x600;
  if (opts.relr?.length) opts.relr.forEach((e, i) => dv.setBigUint64(RELR_ADDR + i * 8, e, true));
  // .rela.plt (+0x700): one R_AARCH64_JUMP_SLOT per GOT slot so the slots resolve to their import names
  const RELA_ADDR = dataBase + 0x700;
  const jumpSlots: [number, number][] = [[GOT_ADDR + 0x0, 5], [GOT_ADDR + 0x8, 6], [GOT_ADDR + 0x10, 7]]; // __android_log_print, socket, malloc
  jumpSlots.forEach(([slot, symIdx], i) => { const o = RELA_ADDR + i * 24; w64(o, slot); w32(o + 8, 1026); w32(o + 12, symIdx); w64(o + 16, 0); });
  // dynamic
  const dyn: [number, number][] = [
    [1, needed], [1, needed2], [14, soname], [4, HASH], [5, DYNSTR], [6, DYNSYM], [10, dynstrBytes.length], [11, 24],
    [23, RELA_ADDR], [2, jumpSlots.length * 24], [20, 7],
    ...(opts.relr?.length ? ([[36, RELR_ADDR], [35, opts.relr.length * 8], [37, 8]] as [number, number][]) : []),
    [0, 0],
  ];
  dyn.forEach(([t, v], i) => { w64(DYNAMIC_ADDR + i * 16, t); w64(DYNAMIC_ADDR + i * 16 + 8, v); });
  buf.set(shstrBytes, SHSTR_ADDR);
  // section headers
  const sh = (i: number, name: string, type: number, flags: number, addr: number, off: number, size: number, link: number, info: number, alignv: number, entsize: number) => {
    const o = SHDR_OFF + i * 64;
    w32(o, shOff[name]); w32(o + 4, type); w64(o + 8, flags); w64(o + 16, addr); w64(o + 24, off); w64(o + 32, size); w32(o + 40, link); w32(o + 44, info); w64(o + 48, alignv); w64(o + 56, entsize);
  };
  sh(1, ".dynsym", 11, 2, DYNSYM, DYNSYM, nsyms * 24, 2, 1, 8, 24);
  sh(2, ".dynstr", 3, 2, DYNSTR, DYNSTR, dynstrBytes.length, 0, 0, 1, 0);
  sh(3, ".hash", 5, 2, HASH, HASH, hashSize, 1, 0, 8, 4);
  sh(4, ".text", 1, 6, TEXT, TEXT, textSize, 0, 0, 4, 0);
  sh(5, ".rodata", 1, 2, roBase, roBase, roBytes.length, 0, 0, 1, 0);
  sh(6, ".data", 1, 3, dataBase, dataBase, 0x100, 0, 0, 8, 0);
  sh(7, ".got", 1, 3, GOT_ADDR, GOT_ADDR, 0x18, 0, 0, 8, 8);
  sh(8, ".dynamic", 6, 3, DYNAMIC_ADDR, DYNAMIC_ADDR, dyn.length * 16, 2, 0, 8, 16);
  sh(9, ".shstrtab", 3, 0, 0, SHSTR_ADDR, shstrBytes.length, 0, 0, 1, 0);

  return { bytes: buf, addrs: { ...addrs, GlobalWorld: dataBase, GOT_LOG, GOT_SOCKET, GOT_MALLOC }, strings: strs };
}

function align(v: number, a: number) {
  return Math.ceil(v / a) * a;
}
