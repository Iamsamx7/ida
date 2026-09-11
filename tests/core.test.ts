import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { parseElf, ElfParseError } from "../src/core/elf/parser";
import { AddressSpace } from "../src/core/address/space";
import { getArchitecture } from "../src/core/architecture/registry";
import { Arm64Provider } from "../src/core/architecture/arm64/decoder";
import { Arm32Provider } from "../src/core/architecture/arm32/decoder";
import { X86Provider } from "../src/core/architecture/x86/decoder";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords, categorize } from "../src/core/analysis/strings";
import { extractFeatures, similarity } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { generatePseudocode } from "../src/core/analysis/pseudocode";
import { inferStructures, collectGlobals } from "../src/core/analysis/structures";
import { search } from "../src/core/search/engine";
import { compilePattern, scanPattern } from "../src/core/signatures/pattern";
import { buildSampleSo } from "./fixtures/elfBuilder";

const sample = buildSampleSo();

function analyze(bytes: Uint8Array, name = "libsample.so") {
  const elf = parseElf(bytes);
  const arch = getArchitecture(elf.header.arch)!;
  const db = new AnalysisDatabase(elf, bytes, arch, name);
  // strings
  const ranges = elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0);
  const raw = ranges.flatMap((s) => scanStrings(bytes, s.offset, s.addr, s.size));
  db.setStrings(toRecords(raw));
  // code
  const chunks = db.space.codeRanges().map((r, i) => scanCodeChunk(arch, bytes, r.offset, r.vaddr, r.size, elf.header.littleEndian, i, true));
  const { functions, xrefs, memAccess, immediates } = discoverFunctions(db, chunks);
  db.setFunctions(functions);
  db.memAccess = memAccess;
  db.immediates = immediates;
  db.setXrefs(xrefs);
  return db;
}

// ---------------------------------------------------------------- ELF
test("ELF: parses synthetic AArch64 shared object", () => {
  const elf = parseElf(sample.bytes);
  assert.equal(elf.header.elfClass, 64);
  assert.equal(elf.header.arch, "arm64");
  assert.equal(elf.header.littleEndian, true);
  assert.equal(elf.header.typeName, "DYN (shared object)");
  assert.equal(elf.segments.filter((s) => s.type === 1).length, 2);
  assert.ok(elf.sections.some((s) => s.name === ".text" && s.exec));
  assert.equal(elf.soname, "libsample.so");
  assert.deepEqual(elf.needed, ["liblog.so", "libc.so"]);
  assert.ok(elf.hasSysvHash);
  assert.equal(elf.exports.map((e) => e.name).sort().join(","), "GlobalWorld,alloc_object,lib_init,net_send");
  assert.equal(elf.imports.map((e) => e.name).sort().join(","), "__android_log_print,malloc,socket");
  assert.equal(elf.imports.find((i) => i.name === "malloc")?.binding, "weak");
  assert.equal(elf.warnings.filter((w) => w.level === "error").length, 0);
});

test("ELF: rejects non-ELF and survives truncated / corrupted input", () => {
  assert.throws(() => parseElf(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])), ElfParseError);
  // truncated: cut in the middle of section headers
  const truncated = sample.bytes.slice(0, 0x1800);
  const elf = parseElf(truncated);
  assert.ok(elf.warnings.length > 0, "truncated file should produce warnings");
  assert.ok(elf.segments.length >= 1);
  // corrupted: absurd section count / offsets
  const bad = sample.bytes.slice();
  new DataView(bad.buffer).setUint16(60, 0xffff, true);
  new DataView(bad.buffer).setBigUint64(40, 0xffffffffn, true);
  const elf2 = parseElf(bad);
  assert.ok(elf2.warnings.some((w) => /Section header table/.test(w.message)));
  // garbage bytes never throw beyond magic check
  for (let seed = 0; seed < 20; seed++) {
    const g = sample.bytes.slice();
    let x = seed * 2654435761;
    for (let i = 16; i < g.length; i += 97) { x = (x * 1103515245 + 12345) >>> 0; g[i] = x & 0xff; }
    assert.doesNotThrow(() => parseElf(g));
  }
});

test("ELF: parses a real system x86-64 shared library if available", () => {
  const candidates = ["/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libc.so.6"];
  const p = candidates.find((c) => existsSync(c));
  if (!p) return;
  const bytes = new Uint8Array(readFileSync(p));
  const elf = parseElf(bytes);
  assert.equal(elf.header.arch, "x86_64");
  assert.ok(elf.exports.length > 10, "should find exports");
  assert.ok(elf.hasGnuHash || elf.hasSysvHash);
  assert.ok(elf.relocations.length > 0);
  const db = analyze(bytes, p);
  assert.ok(db.functions.length > 50, `expected functions, got ${db.functions.length}`);
  assert.ok(db.strings.length > 10);
});

// ---------------------------------------------------------------- Address space
test("AddressSpace: VA <-> offset <-> RVA and go-to parsing", () => {
  const elf = parseElf(sample.bytes);
  const sp = new AddressSpace(elf);
  assert.equal(sp.vaToOffset(0x1000), 0x1000);
  assert.equal(sp.offsetToVa(0x2000), 0x2000);
  assert.equal(sp.isExec(0x1000), true);
  assert.equal(sp.isExec(0x3000), false);
  assert.equal(sp.sectionAt(0x1004)?.name, ".text");
  assert.deepEqual(AddressSpace.parseGoTo("0x1234"), { kind: "va", value: 0x1234 });
  assert.deepEqual(AddressSpace.parseGoTo("module+0x10"), { kind: "rva", value: 0x10 });
  assert.deepEqual(AddressSpace.parseGoTo("off:2000"), { kind: "offset", value: 0x2000 });
  assert.deepEqual(AddressSpace.parseGoTo("lib_init"), { kind: "name", value: "lib_init" });
  assert.equal(sp.resolve({ kind: "va", value: 0x1010 })?.va, 0x1010);
  assert.equal(sp.resolve({ kind: "rva", value: 0x1010 })?.va, 0x1010);
  assert.equal(sp.resolve({ kind: "va", value: 0xffffffff }), null);
});

// ---------------------------------------------------------------- ARM64 decoder
test("ARM64: decodes representative instructions", () => {
  const arm = new Arm64Provider();
  const dec = (w: number, pc = 0x1000) => {
    const b = new Uint8Array([w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >>> 24) & 0xff]);
    const i = arm.decode(b, 0, pc, true);
    return `${i.mnemonic} ${i.opText}`.trim();
  };
  assert.equal(dec(0xa9bf7bfd), "stp x29, x30, [sp, #-0x10]!");
  assert.equal(dec(0xa8c17bfd), "ldp x29, x30, [sp], #0x10");
  assert.equal(dec(0x910003fd), "mov x29, sp");
  assert.equal(dec(0xf9400268), "ldr x8, [x19]");
  assert.equal(dec(0x91002108), "add x8, x8, #8");
  assert.equal(dec(0xd65f03c0), "ret");
  assert.equal(dec(0xd503201f), "nop");
  assert.equal(dec(0xd503233f), "paciasp");
  assert.equal(dec(0xd503245f), "bti c");
  assert.equal(dec(0x94012345, 0x1000), "bl 0x49d14");
  assert.equal(dec(0x17ffffff, 0x1000), "b 0xffc");
  assert.equal(dec(0x54000041, 0x1000), "b.ne 0x1008");
  assert.equal(dec(0xb4000048, 0x1000), "cbz x8, 0x1008");
  assert.equal(dec(0x36000048, 0x1000), "tbz w8, #0, 0x1008");
  assert.equal(dec(0xf100001f), "cmp x0, #0");
  assert.equal(dec(0xeb01001f), "cmp x0, x1");
  assert.equal(dec(0xd2802468), "mov x8, #0x123");
  assert.equal(dec(0xf2a02468), "movk x8, #0x123, lsl #16");
  assert.equal(dec(0x92800008), "mov x8, #0xffffffffffffffff");
  assert.equal(dec(0xaa0103e0), "mov x0, x1");
  assert.equal(dec(0x8b010000), "add x0, x0, x1");
  assert.equal(dec(0x8b010c00), "add x0, x0, x1, lsl #3");
  assert.equal(dec(0xca0a0108), "eor x8, x8, x10");
  assert.equal(dec(0x927df000), "and x0, x0, #0xfffffffffffffff8");
  assert.equal(dec(0x12000c00), "and w0, w0, #0xf");
  assert.equal(dec(0xb2400c00), "orr x0, x0, #0xf");
  assert.equal(dec(0x93c83508), "ror x8, x8, #13");
  assert.equal(dec(0xd37df000), "lsl x0, x0, #3");
  assert.equal(dec(0xd340fc00), "lsr x0, x0, #0");
  assert.equal(dec(0x53007c00), "lsr w0, w0, #0");
  assert.equal(dec(0x9b027c00), "mul x0, x0, x2");
  assert.equal(dec(0x9ac20800), "udiv x0, x0, x2");
  assert.equal(dec(0x9a9f17e0), "cset x0, eq");
  assert.equal(dec(0x9a821020), "csel x0, x1, x2, ne");
  assert.equal(dec(0x39400000), "ldrb w0, [x0]");
  assert.equal(dec(0x79400000), "ldrh w0, [x0]");
  assert.equal(dec(0xb9400000), "ldr w0, [x0]");
  assert.equal(dec(0xf8408400), "ldr x0, [x0], #8");
  assert.equal(dec(0xf81f0fe0), "str x0, [sp, #-0x10]!");
  assert.equal(dec(0xf8616800), "ldr x0, [x0, x1]");
  assert.equal(dec(0xf8617800), "ldr x0, [x0, x1, lsl #3]");
  assert.equal(dec(0xb8a17800), "ldrsw x0, [x0, x1, lsl #2]");
  assert.equal(dec(0x18000040, 0x1000), "ldr w0, =0x1008");
  assert.equal(dec(0x58000040, 0x1000), "ldr x0, =0x1008");
  assert.equal(dec(0x90000008, 0x1234), "adrp x8, 0x1000");
  assert.equal(dec(0xb0000008, 0x1234), "adrp x8, 0x2000");
  assert.equal(dec(0x10000040, 0x1000), "adr x0, 0x1008");
  assert.equal(dec(0xd63f0100), "blr x8");
  assert.equal(dec(0xd61f0100), "br x8");
  assert.equal(dec(0xd4000001), "svc #0");
  assert.equal(dec(0xd4200000), "brk #0");
  assert.equal(dec(0xd53bd048), "mrs x8, tpidr_el0");
  assert.equal(dec(0xd5033bbf), "dmb ish");
  assert.equal(dec(0x885f7c00), "ldxr w0, [x0]");
  assert.equal(dec(0xc8dffc00), "ldar x0, [x0]");
  assert.equal(dec(0xb8e00001), "ldaddal w0, w1, [x0]");
  assert.equal(dec(0xc8a07c00), "cas x0, x0, [x0]");
  assert.equal(dec(0x1e204000), "fmov s0, s0");
  assert.equal(dec(0x1e602820), "fadd d0, d1, d0");
  assert.equal(dec(0x9e620020), "scvtf d0, x1");
  assert.equal(dec(0x1e2e1000), "fmov s0, #1.0");
  assert.equal(dec(0x6e201c00), "eor v0.16b, v0.16b, v0.16b");
  // unknown/reserved words never throw
  for (const w of [0x00000000, 0xffffffff, 0x12345678, 0xdeadbeef]) assert.doesNotThrow(() => dec(w));
});

test("ARM64: prologue scoring and data-ref fusion", () => {
  const arm = new Arm64Provider();
  const words = [0xd503233f, 0xa9bf7bfd, 0x910003fd, 0xb0000008, 0xf9400508, 0x91002108, 0xd65f03c0];
  const b = new Uint8Array(words.length * 4);
  const dv = new DataView(b.buffer);
  words.forEach((w, i) => dv.setUint32(i * 4, w >>> 0, true));
  const insns = words.map((_, i) => arm.decode(b, i * 4, 0x1000 + i * 4, true));
  assert.ok(arm.prologueScore(insns) > 0.8);
  const refs = arm.fuseDataRefs(insns);
  assert.ok(refs.some((r) => r.to === 0x2008 && r.kind === "read"), JSON.stringify(refs));
});

// ---------------------------------------------------------------- Strings
test("Strings: extraction and categorisation", () => {
  const db = analyze(sample.bytes);
  const values = db.strings.map((s) => s.value);
  assert.ok(values.includes("https://example.com/api/v1/session"));
  assert.ok(values.includes("/data/local/tmp/config.json"));
  assert.equal(db.stringAt(sample.strings.url)?.category, "url");
  assert.equal(categorize("/data/local/tmp/config.json"), "path");
  assert.equal(categorize("error: world state not initialized"), "error");
  assert.equal(categorize("Java_com_example_Foo_bar"), "jni");
  // UTF-16
  const u16 = new Uint8Array("Hello16!".split("").flatMap((c) => [c.charCodeAt(0), 0]).concat([0, 0]));
  assert.equal(scanStrings(u16, 0, 0, u16.length)[0]?.encoding, "utf16le");
});

// ---------------------------------------------------------------- Functions / XREFs
test("Analysis: discovers symbol'd and stripped functions with evidence and sizes", () => {
  const db = analyze(sample.bytes);
  const names = db.functions.map((f) => f.name);
  assert.ok(names.includes("lib_init"));
  assert.ok(names.includes("net_send"));
  assert.ok(names.includes("alloc_object"));
  const wsr = db.functionByAddr(sample.addrs.world_state_reader);
  assert.ok(wsr, "stripped world_state_reader must be discovered");
  assert.ok(wsr!.sources.includes("call-target"));
  assert.ok(wsr!.sources.includes("relocation") || wsr!.confidence >= 0.9);
  assert.equal(wsr!.nameSource, "inferred");
  const hash = db.functionByAddr(sample.addrs.hash_buffer)!;
  assert.ok(hash, "hash_buffer must be discovered");
  assert.equal(hash.size, sample.addrs.net_send - sample.addrs.hash_buffer);
  // the loop label inside hash_buffer must NOT be a function
  assert.equal(db.functionByAddr(sample.addrs.hash_buffer + 20), null);
  // xrefs
  const callers = db.callersOf(wsr!);
  assert.ok(callers.some((c) => c.fn?.name === "lib_init"));
  const init = db.functionByAddr(sample.addrs.lib_init)!;
  assert.ok(db.calleesOf(init).some((c) => c.to === sample.addrs.hash_buffer));
  const strRefs = db.xrefs.refsTo(sample.strings.url);
  assert.equal(strRefs.length, 1);
  assert.equal(strRefs[0].kind, 7);
  assert.equal(db.stringAt(sample.strings.url)?.refCount, 1);
  const gw = db.xrefs.refsTo(sample.addrs.GlobalWorld);
  assert.ok(gw.some((x) => x.kind === 3 && x.from === sample.addrs.world_state_reader + 4));
  assert.ok(db.xrefs.refsTo(sample.addrs.GOT_SOCKET).length >= 1);
});

test("Semantic: rule engine classifies with evidence; pseudocode & structures", () => {
  const db = analyze(sample.bytes);
  const importsAll = new Set(db.elf.imports.map((i) => i.name));
  const ctxFor = (addr: number) => {
    const f = db.functionByAddr(addr)!;
    f.features = extractFeatures(db, f);
    return { addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: f.features.callees.map((c) => db.nameFor(c).name), callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)!).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll };
  };
  const hashCls = classify(ctxFor(sample.addrs.hash_buffer));
  assert.ok(hashCls.some((c) => c.label === "hashing"), JSON.stringify(hashCls));
  assert.ok(hashCls[0].evidence.length > 0);
  const netCls = classify(ctxFor(sample.addrs.net_send));
  assert.ok(netCls.some((c) => c.label === "networking"), JSON.stringify(netCls));
  const wsrCls = classify(ctxFor(sample.addrs.world_state_reader));
  assert.ok(wsrCls.some((c) => c.label === "state-access"), JSON.stringify(wsrCls));
  // pseudocode
  const wsr = db.functionByAddr(sample.addrs.world_state_reader)!;
  const pc = generatePseudocode(db, wsr).map((l) => l.text).join("\n");
  assert.match(pc, /GlobalWorld/);
  assert.match(pc, /== 0\) goto/);
  assert.match(pc, /return/);
  assert.match(pc, /Reconstructed/);
  // structures / globals
  const globals = collectGlobals(db);
  assert.ok(globals.some((g) => g.name === "GlobalWorld"));
  const structs = inferStructures(db);
  assert.ok(structs.some((s) => s.fields.length >= 3), "alloc_object writes 3 fields → structure candidate");
  // similarity: function vs itself = 1, vs different < 1
  const a = extractFeatures(db, db.functionByAddr(sample.addrs.hash_buffer)!);
  const b = extractFeatures(db, db.functionByAddr(sample.addrs.net_send)!);
  assert.ok(similarity(a, a, 10, 10) > 0.95);
  assert.ok(similarity(a, b, 10, 10) < similarity(a, a, 10, 10));
});

test("Search & patterns", () => {
  const db = analyze(sample.bytes);
  const r1 = search(db, "example.com");
  assert.ok(r1.some((h) => h.category === "strings"));
  const r2 = search(db, "lib_init");
  assert.ok(r2.some((h) => h.category === "functions" && h.address === sample.addrs.lib_init));
  const r3 = search(db, "0x1000");
  assert.ok(r3.some((h) => h.category === "addresses"));
  const r4 = search(db, "FD 7B BF A9");
  assert.ok(r4.some((h) => h.category === "bytes"), "byte pattern should hit stp prologue");
  const r5 = search(db, "re:^net_");
  assert.ok(r5.some((h) => h.title === "net_send"));
  const pat = compilePattern("FD 7B ?? A9 ?? ?? ?? 91");
  const offs = scanPattern(sample.bytes, pat);
  assert.ok(offs.includes(sample.addrs.net_send));
  // user rename never overwrites silently: name source flips to user, restore removes
  db.setUserName(sample.addrs.world_state_reader, "WorldStateReader");
  assert.equal(db.nameFor(sample.addrs.world_state_reader).source, "user");
  assert.ok(search(db, "WorldState").some((h) => h.address === sample.addrs.world_state_reader));
  db.setUserName(sample.addrs.world_state_reader, "");
  assert.equal(db.nameFor(sample.addrs.world_state_reader).source, "inferred");
});

// ---------------------------------------------------------------- Regression: secondary decoders
test("x86: 8-bit register names, native-width stack ops, flag ops", () => {
  const dec = (mode: 32 | 64, ...b: number[]) => { const i = new X86Provider(mode).decode(new Uint8Array(b), 0, 0x1000); return `${i.mnemonic} ${i.opText}`.trim(); };
  assert.equal(dec(64, 0x88, 0xc1), "mov cl, al");
  assert.equal(dec(64, 0xb0, 0x41), "mov al, 0x41");
  assert.equal(dec(64, 0x88, 0xe1), "mov cl, ah"); // no REX → ah, not spl
  assert.equal(dec(64, 0x40, 0x88, 0xe1), "mov cl, spl"); // REX → spl
  assert.equal(dec(64, 0x41, 0xb0, 0x07), "mov r8b, 0x7");
  assert.equal(dec(64, 0xff, 0xd0), "call rax");
  assert.equal(dec(32, 0xff, 0xd0), "call eax");
  assert.equal(dec(32, 0xff, 0x15, 0x10, 0x20, 0x30, 0x00), "call dword ptr [0x302010]");
  assert.equal(dec(64, 0xff, 0x35, 0x10, 0x00, 0x00, 0x00), "push qword ptr [0x1016]");
  assert.equal(dec(64, 0x0f, 0xc8), "bswap eax");
  assert.equal(dec(64, 0x48, 0x0f, 0xcb), "bswap rbx");
  const leave = new X86Provider(64).decode(new Uint8Array([0xc9]), 0, 0);
  assert.equal(leave.kind, "other");
  assert.equal(leave.fallsThrough, true);
});

test("ARM32: unsigned targets above 2 GB, MOVW/MOVT and PLT-stub fusion", () => {
  const arm = new Arm32Provider();
  const decodeWords = (words: number[], base: number) => {
    const b = new Uint8Array(words.length * 4);
    const dv = new DataView(b.buffer);
    words.forEach((w, i) => dv.setUint32(i * 4, w >>> 0, true));
    return words.map((_, i) => arm.decode(b, i * 4, base + i * 4, true));
  };
  const blx = decodeWords([0xfa000000], 0x80000000)[0]; // blx +0 (imm)
  assert.equal(blx.mnemonic, "blx");
  assert.ok(blx.target !== undefined && blx.target >= 0x80000000, `target must stay unsigned, got ${blx.target}`);
  const lit = decodeWords([0xe59f0004], 0x80000000)[0]; // ldr r0, [pc, #4]
  assert.equal(lit.target, 0x8000000c);
  // movw r0, #0x5678 ; movt r0, #0x1234 → address 0x12345678
  const mv = decodeWords([0xe3050678, 0xe3410234], 0x1000);
  assert.equal(`${mv[0].mnemonic} ${mv[0].opText}`, "movw r0, #0x5678");
  assert.equal(`${mv[1].mnemonic} ${mv[1].opText}`, "movt r0, #0x1234");
  assert.deepEqual(arm.fuseDataRefs(mv), [{ from: 0x1004, to: 0x12345678, kind: "address" }]);
  // add ip, pc, #0 ; add ip, ip, #0x10000 ; ldr pc, [ip, #8]! → GOT slot at pc+8+0x10000+8, reported from the stub start
  const plt = decodeWords([0xe28fc600, 0xe28cca10, 0xe5bcf008], 0x1000);
  assert.deepEqual(arm.fuseDataRefs(plt), [{ from: 0x1000, to: 0x11010, kind: "read" }]);
  // -fPIC string address: ldr r0, [pc, #4] (literal W at 0x100c) ; add r0, pc, r0 ; bx lr ; .word W
  // → the add materialises 0x1004 + 8 + W. This is how every armeabi-v7a build reaches its strings.
  const W = 0x2000;
  const pic = decodeWords([0xe59f0004, 0xe08f0000, 0xe12fff1e, W], 0x1000);
  assert.equal(pic[0].pageValue, W, "ldr literal must carry the pool word");
  assert.equal(pic[0].destReg, "r0");
  const refs = arm.fuseDataRefs(pic);
  assert.ok(refs.some((r) => r.from === 0x1004 && r.to === 0x1004 + 8 + W && r.kind === "address"), JSON.stringify(refs));
  // GOT-relative load: ldr r1, [pc, #4] ; ldr r1, [pc, r1] → reads slot at 0x1004 + 8 + W
  const got = decodeWords([0xe59f1004, 0xe79f1001, 0xe12fff1e, W], 0x1000);
  assert.ok(arm.fuseDataRefs(got).some((r) => r.from === 0x1004 && r.to === 0x1004 + 8 + W && r.kind === "read"), JSON.stringify(arm.fuseDataRefs(got)));
});

test("ELF: RELR bitmaps keep bits above 2^53", () => {
  const base = 0x3000;
  const relr = buildSampleSo({ relr: [BigInt(base + 0x40), 1n | (1n << 1n) | (1n << 63n), BigInt(base + 0x300)] });
  const elf = parseElf(relr.bytes);
  const offs = elf.relocations.filter((r) => r.typeName === "RELR_RELATIVE").map((r) => r.offset);
  assert.deepEqual(offs, [base + 0x40, base + 0x48, base + 0x48 + 62 * 8, base + 0x300]);
});

test("Pseudocode: self-folding expressions stay bounded", () => {
  const db = analyze(sample.bytes);
  const arm = new Arm64Provider();
  const words = [...Array.from({ length: 400 }, () => 0x8b080108), 0xaa0803e0, 0xd65f03c0]; // add x8,x8,x8 ×400 ; mov x0,x8 ; ret
  const b = new Uint8Array(words.length * 4);
  const dv = new DataView(b.buffer);
  words.forEach((w, i) => dv.setUint32(i * 4, w >>> 0, true));
  const insns = words.map((_, i) => arm.decode(b, i * 4, 0x1000 + i * 4, true));
  const fn = { addr: 0x1000, size: b.length, name: "fold", nameSource: "inferred" as const, confidence: 1, sources: ["test"], insnCount: insns.length, callerCount: 0, calleeCount: 0, isImportStub: false };
  const lines = generatePseudocode(db, fn, insns);
  assert.ok(lines.length > 3);
  for (const l of lines) assert.ok(l.text.length < 600, `line too long: ${l.text.length}`);
  assert.ok(lines.some((l) => /^x8 = /.test(l.text)), "long expressions must be materialised as statements");
});

test("Pseudocode: loop bodies are emitted and branch operands count as parameters", () => {
  const db = analyze(sample.bytes);
  const fn = db.functionByAddr(sample.addrs.hash_buffer)!;
  const pc = generatePseudocode(db, fn).map((l) => l.text).join("\n");
  assert.match(pc, /int64_t sub_1068\(int64_t a1, int64_t a2\)/, pc); // x1 is read by cbz → second parameter
  assert.match(pc, /if \(a2 == 0\) goto loc_1094/, pc);
  assert.match(pc, /x8 = \(.*\*\(uint8_t\*\)\(a1\).*\)/, pc); // loop-carried hash update survives the block boundary
  assert.match(pc, /a1 = \(a1 \+ 1\)/, pc);
  assert.match(pc, /if \(\(a2 - 1\) != 0\) goto loc_107c/, pc);
  assert.match(pc, /return x8/, pc);
});

test("GOT-slot imports: named, classified as API calls, and rendered as direct calls", () => {
  const db = analyze(sample.bytes);
  assert.equal(db.nameFor(sample.addrs.GOT_SOCKET).name, "socket@got");
  const fn = db.functionByAddr(sample.addrs.net_send)!;
  fn.features = extractFeatures(db, fn);
  assert.ok(fn.features.importCalls.includes("socket"), JSON.stringify(fn.features.importCalls));
  const cls = classify({ addr: fn.addr, name: fn.name, size: fn.size, features: fn.features, calleeNames: fn.features.callees.map((c) => db.nameFor(c).name), callerNames: [], stringValues: [], importsAll: new Set() });
  const net = cls.find((c) => c.label === "networking");
  assert.ok(net && net.evidence.some((e) => /calls socket/.test(e.text)), JSON.stringify(cls));
  const pc = generatePseudocode(db, fn).map((l) => l.text).join("\n");
  assert.match(pc, /x0 = socket\("https:\/\/example\.com/, pc);
});
