import type { AnalysisDatabase } from "./database";
import type { FunctionRecord } from "./types";

/**
 * Deobfuscation / XOR-decryptor detection. Obfuscated anticheat (anogs/ACE,
 * VMP-style) XOR-encrypts its strings, config keys and downloaded rules, then
 * decrypts them at runtime. Those functions carry NO plaintext strings, so
 * string-anchored detection is blind to them — but the decryptor itself has a
 * loud shape: a loop that loads a byte, XORs it with a key, stores it back.
 *
 * Finding the decryptor is the key to an XOR-hidden engine: hook it and dump
 * its output to reveal the plaintext strings/rules the rest of the tool can't
 * see statically.
 */
export interface XorScoreInput {
  mnemonicHist: Record<string, number>;
  hasLoop: boolean;
  size: number;
}

/** Pure: does this function look like an XOR-decrypt / byte-transform routine? */
export function scoreXorDecrypt(f: XorScoreInput): { score: number; eor: number; byteLS: number } | null {
  const h = f.mnemonicHist;
  const g = (...k: string[]) => k.reduce((a, x) => a + (h[x] ?? 0), 0);
  const eor = g("eor", "eon", "eor3", "xor"); // the XOR itself
  const byteLS = g("ldrb", "strb", "ldrh", "strh"); // byte/half stream in+out
  // XOR alone is common (register zeroing, hashing). The decryptor tell is XOR
  // together with a byte-level load/store stream: it transforms a buffer.
  if (eor < 2 || byteLS < 4) return null;
  if (eor < 3 && byteLS < 8) return null; // weak: needs either several XORs or a real byte stream
  const score = eor * 2 + Math.min(byteLS, 24) + (f.hasLoop ? 4 : 0);
  return { score, eor, byteLS };
}

export interface DecryptorFinding {
  addr: number;
  name: string;
  rva: number;
  eor: number;
  byteLS: number;
  loop: boolean;
  size: number;
  callers: number;
  score: number;
  /** How to reveal what it decrypts. */
  how: string;
  /** Frida snippet that dumps the plaintext this routine produces. */
  frida: string;
}

export interface DeobfReport {
  decryptors: DecryptorFinding[];
  count: number;
  note: string;
}

/** Find the XOR-decrypt / string-deobfuscation routines. Pure + deterministic. */
export function findDecryptors(db: AnalysisDatabase, limit = 12): DeobfReport {
  const rows: DecryptorFinding[] = [];
  const base = db.space.imageBase ?? 0;
  const lib = db.elf.soname ?? db.fileName;
  for (const fn of db.functions) {
    if (fn.isImportStub || !fn.features) continue;
    const sc = scoreXorDecrypt({ mnemonicHist: fn.features.mnemonicHist ?? {}, hasLoop: !!fn.features.hasLoop, size: fn.size });
    if (!sc) continue;
    const name = db.nameFor(fn.addr).name;
    const rva = fn.addr - base;
    rows.push({
      addr: fn.addr,
      name,
      rva,
      eor: sc.eor,
      byteLS: sc.byteLS,
      loop: !!fn.features.hasLoop,
      size: fn.size,
      callers: db.callersOf(fn).length,
      score: sc.score,
      how: `Hook this and DUMP its output — that is the plaintext (strings / config / rule blob) the static tool can't see. Don't force-return it (that breaks decryption); log the destination buffer on onLeave. Whoever calls it with the decrypted data is the hidden engine.`,
      frida: fridaDumpDecryptor(lib, name, rva),
    });
  }
  rows.sort((a, b) => b.score - a.score || a.addr - b.addr);
  const top = rows.slice(0, limit);
  return { decryptors: top, count: top.length, note: deobfNote(top) };
}

function deobfNote(rows: DecryptorFinding[]): string {
  if (!rows.length) return "No XOR/byte-transform decryptor routines stood out. Either strings are in the clear (see Strings), the deobfuscation is inlined/one-shot, or a different scheme (RC4/AES) is used — check the imports for EVP_/AES_ and the largest string-less byte-loops manually.";
  const strong = rows[0];
  return `Obfuscation present: ${rows.length} XOR/byte-transform routine(s) that decrypt hidden strings/config/rules at runtime — this is why the real parser/applier carry no plaintext strings. Strongest: ${strong.name} @ 0x${strong.addr.toString(16)} (${strong.eor} XORs, ${strong.byteLS} byte load/stores${strong.loop ? ", loop" : ""}). To reveal the hidden engine: hook a decryptor and dump its OUTPUT (the plaintext), then re-run the analysis on the dumped data / follow whoever consumes it. This finds what string-matching and structural exploration cannot — the XOR-hidden core.`;
}

/** Frida snippet: hook a decryptor, log its args, and dump the output buffer on return. */
export function fridaDumpDecryptor(lib: string, name: string, rva: number): string {
  return [
    `// ${name} — DUMP what it decrypts (reveal the XOR-hidden plaintext). Don't force the return — log the output.`,
    `{`,
    `  const mod = Process.findModuleByName("${lib}");`,
    `  if (!mod) throw new Error("${lib} not loaded — attach after it loads");`,
    `  const addr = mod.base.add(0x${rva.toString(16).toUpperCase()});`,
    `  Interceptor.attach(addr, {`,
    `    onEnter(args) { this.a = [args[0], args[1], args[2], args[3]]; /* dest,src,len,key vary by ABI — inspect */ },`,
    `    onLeave(retval) {`,
    `      // Try the return value and the first two args as the plaintext buffer:`,
    `      for (const p of [retval, this.a[0], this.a[1]]) {`,
    `        try { const s = p.readUtf8String(); if (s && /[ -~]{4,}/.test(s)) console.log("[${name}] str:", s); } catch (e) {}`,
    `        try { console.log("[${name}] hex:", hexdump(p, { length: 64, ansi: false })); } catch (e) {}`,
    `      }`,
    `    }`,
    `  });`,
    `}`,
    ``,
  ].join("\n");
}
