/**
 * Byte pattern / signature engine.
 * Pattern syntax: hex bytes separated by spaces, `??` or `?` = wildcard byte,
 * nibble wildcards like `4?` are supported. Example:
 *   "F? 03 00 AA ?? ?? ?? 94"
 */
export interface CompiledPattern {
  bytes: Uint8Array;
  mask: Uint8Array; // 0xff = must match, 0x00 = wildcard, 0xf0/0x0f nibble
  length: number;
  source: string;
}

export function compilePattern(src: string): CompiledPattern {
  const toks = src.trim().split(/\s+/).filter(Boolean);
  if (!toks.length) throw new Error("Empty pattern");
  const bytes = new Uint8Array(toks.length);
  const mask = new Uint8Array(toks.length);
  toks.forEach((t, i) => {
    const tok = t.toLowerCase().replace(/^0x/, "");
    if (tok === "?" || tok === "??" || tok === "*") { mask[i] = 0; return; }
    if (tok.length !== 2) throw new Error(`Bad token '${t}' at position ${i}`);
    let m = 0, b = 0;
    for (let n = 0; n < 2; n++) {
      const ch = tok[n];
      const shift = n === 0 ? 4 : 0;
      if (ch === "?") continue;
      const v = parseInt(ch, 16);
      if (Number.isNaN(v)) throw new Error(`Bad token '${t}' at position ${i}`);
      m |= 0xf << shift;
      b |= v << shift;
    }
    mask[i] = m;
    bytes[i] = b;
  });
  return { bytes, mask, length: toks.length, source: src };
}

/** Scan a byte range for a compiled pattern. Returns file offsets. */
export function scanPattern(hay: Uint8Array, pat: CompiledPattern, start = 0, end = hay.length, limit = 10_000): number[] {
  const out: number[] = [];
  const { bytes, mask, length } = pat;
  if (length === 0 || end - start < length) return out;
  // Find first fixed byte to use as an anchor for fast skipping
  let anchor = -1;
  for (let i = 0; i < length; i++) if (mask[i] === 0xff) { anchor = i; break; }
  const last = end - length;
  if (anchor >= 0) {
    const ab = bytes[anchor];
    let i = start + anchor;
    const stop = last + anchor;
    while (i <= stop) {
      const found = hay.indexOf(ab, i);
      if (found < 0 || found > stop) break;
      const base = found - anchor;
      let ok = true;
      for (let k = 0; k < length; k++) {
        const m = mask[k];
        if (m && (hay[base + k] & m) !== bytes[k]) { ok = false; break; }
      }
      if (ok) { out.push(base); if (out.length >= limit) break; }
      i = found + 1;
    }
    return out;
  }
  for (let base = start; base <= last; base++) {
    let ok = true;
    for (let k = 0; k < length; k++) {
      const m = mask[k];
      if (m && (hay[base + k] & m) !== bytes[k]) { ok = false; break; }
    }
    if (ok) { out.push(base); if (out.length >= limit) break; }
  }
  return out;
}

/** Build a unique signature for a byte range by wildcarding relocatable/immediate fields (ARM64: branch and page immediates). */
export function makeSignature(bytes: Uint8Array, offset: number, length: number, archId: string): string {
  const toks: string[] = [];
  for (let i = 0; i < length && offset + i < bytes.length; i++) {
    const b = bytes[offset + i];
    if (archId === "arm64" && i % 4 === 3) {
      // Wildcard BL/B (top 6 bits 100101/000101) and ADRP immediates conservatively
      const w = bytes[offset + i - 3] | (bytes[offset + i - 2] << 8) | (bytes[offset + i - 1] << 16) | (b << 24);
      const top = (w >>> 26) & 0x3f;
      if (top === 0b100101 || top === 0b000101) { toks.splice(toks.length - 3, 3, "??", "??", "??"); toks.push(b === 0x94 ? "94" : b === 0x97 ? "97" : b === 0x14 ? "14" : b === 0x17 ? "17" : "??"); continue; }
      if (((w >>> 24) & 0x9f) === 0x90) { toks.splice(toks.length - 3, 3, "??", "??", "??"); toks.push("??"); continue; }
    }
    toks.push(b.toString(16).padStart(2, "0"));
  }
  return toks.join(" ").toUpperCase();
}
