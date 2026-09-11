import type { AnalysisDatabase } from "../analysis/database";
import { AddressSpace } from "../address/space";
import { compilePattern, scanPattern } from "../signatures/pattern";

export type SearchCategory = "functions" | "strings" | "symbols" | "imports" | "exports" | "globals" | "references" | "constants" | "comments" | "semantic" | "addresses" | "bytes" | "instructions" | "tags" | "bookmarks";

export interface SearchHit {
  category: SearchCategory;
  address: number;
  title: string;
  subtitle?: string;
  score: number;
}

export interface SearchOptions {
  categories?: SearchCategory[];
  limitPerCategory?: number;
  regex?: boolean;
  /** Decode instructions for mnemonic/operand search (bounded, slower). */
  instructions?: boolean;
}

/**
 * Unified search across every indexed entity. Query grammar:
 *  - plain text          → fuzzy/substring over names, strings, symbols, comments, semantic labels
 *  - 0x1234 / 1234h      → address / offset / constant
 *  - "F? 03 ?? AA"        → byte pattern (auto-detected: ≥2 hex byte tokens with wildcards or spaces)
 *  - re:<regex>           → regular expression
 *  - tag:<name>, class:<label>, mn:<mnemonic>, imm:0x1234, xref:0xADDR
 */
export function search(db: AnalysisDatabase, rawQuery: string, opts: SearchOptions = {}): SearchHit[] {
  const q = rawQuery.trim();
  if (!q) return [];
  const limit = opts.limitPerCategory ?? 50;
  const hits: SearchHit[] = [];
  const want = (c: SearchCategory) => !opts.categories || opts.categories.includes(c);
  const lower = q.toLowerCase();
  let matcher: (s: string) => number;
  let mode: "text" | "regex" = opts.regex || lower.startsWith("re:") ? "regex" : "text";
  let text = lower.startsWith("re:") ? q.slice(3) : q;
  let prefix = "";
  const pm = text.match(/^(tag|class|mn|imm|xref|str|fn|sym):(.*)$/i);
  if (pm) { prefix = pm[1].toLowerCase(); text = pm[2].trim(); }
  if (mode === "regex") {
    let rx: RegExp;
    try { rx = new RegExp(text, "i"); } catch { return []; }
    matcher = (s) => (rx.test(s) ? 1 : 0);
  } else {
    const t = text.toLowerCase();
    matcher = (s) => {
      const l = s.toLowerCase();
      if (l === t) return 3;
      if (l.startsWith(t)) return 2;
      if (l.includes(t)) return 1;
      return 0;
    };
    mode = "text";
  }

  // Address / number
  const num = AddressSpace.parseGoTo(text);
  if (num && num.kind !== "name" && !prefix && want("addresses")) {
    const r = db.space.resolve(num);
    if (r) hits.push({ category: "addresses", address: r.va, title: `Go to 0x${r.va.toString(16)}`, subtitle: `interpreted as ${r.interpretedAs} · ${db.labelFor(r.va)}`, score: 100 });
    // also as constant / immediate
    if (want("constants") || prefix === "imm") {
      const imm = db.immediates;
      let n = 0;
      for (let i = 0; i < imm.length && n < limit; i += 2) {
        if (imm[i + 1] === num.value) {
          hits.push({ category: "constants", address: imm[i], title: `#0x${num.value.toString(16)} in ${db.labelFor(imm[i])}`, score: 50 });
          n++;
        }
      }
    }
  }
  if (prefix === "imm") {
    const v = parseInt(text, text.startsWith("0x") ? 16 : 10);
    const imm = db.immediates;
    let n = 0;
    for (let i = 0; i < imm.length && n < limit; i += 2) if (imm[i + 1] === v) { hits.push({ category: "constants", address: imm[i], title: `#0x${v.toString(16)} in ${db.labelFor(imm[i])}`, score: 50 }); n++; }
    return hits;
  }
  if (prefix === "xref") {
    const target = parseInt(text.replace(/^0x/, ""), 16);
    for (const x of db.xrefs.refsTo(target, limit)) hits.push({ category: "references", address: x.from, title: `${db.labelFor(x.from)} → 0x${target.toString(16)}`, subtitle: kindName(x.kind), score: 40 });
    return hits;
  }

  // Byte pattern
  const looksPattern = /^([0-9a-f?]{2}\s+){1,}[0-9a-f?]{2}$/i.test(text) || /^\?\?/.test(text);
  if (looksPattern && want("bytes") && !prefix) {
    try {
      const pat = compilePattern(text);
      let n = 0;
      for (const r of db.space.ranges) {
        for (const off of scanPattern(db.bytes, pat, r.offset, r.offset + r.size, limit)) {
          const va = r.vaddr + (off - r.offset);
          hits.push({ category: "bytes", address: va, title: `bytes at 0x${va.toString(16)}`, subtitle: db.labelFor(va), score: 60 });
          if (++n >= limit) break;
        }
        if (n >= limit) break;
      }
    } catch { /* not a pattern */ }
  }

  // Functions / symbols
  if ((want("functions") || prefix === "fn") && prefix !== "str" && prefix !== "tag" && prefix !== "class" && prefix !== "mn" && prefix !== "sym") {
    let n = 0;
    for (const f of db.functions) {
      const s = matcher(f.name);
      if (s) { hits.push({ category: "functions", address: f.addr, title: f.name, subtitle: `0x${f.addr.toString(16)} · ${f.size} bytes · ${f.nameSource}`, score: 30 + s * 5 + (f.nameSource === "user" ? 3 : 0) }); if (++n >= limit) break; }
    }
  }
  if ((want("symbols") || prefix === "sym") && !["str", "tag", "class", "mn", "fn"].includes(prefix)) {
    let n = 0;
    for (const s of db.elf.symbols) {
      if (!s.name) continue;
      const sc = matcher(s.name);
      if (sc) {
        const cat = !s.defined ? "imports" : s.binding !== "local" && s.table === "dynsym" ? "exports" : "symbols";
        if (want(cat)) { hits.push({ category: cat, address: s.value, title: s.name, subtitle: `${s.kind} · ${s.binding}${s.version ? " · " + s.version : ""}`, score: 20 + sc * 4 }); if (++n >= limit) break; }
      }
    }
  }
  if ((want("strings") || prefix === "str") && !["tag", "class", "mn", "fn", "sym"].includes(prefix)) {
    let n = 0;
    for (const s of db.strings) {
      const sc = matcher(s.value);
      if (sc) { hits.push({ category: "strings", address: s.addr, title: s.value.length > 100 ? s.value.slice(0, 100) + "…" : s.value, subtitle: `0x${s.addr.toString(16)} · ${s.encoding} · ${s.category} · ${s.refCount} refs`, score: 15 + sc * 4 + Math.min(5, s.refCount) }); if (++n >= limit) break; }
    }
  }
  if (want("globals") && !prefix) {
    let n = 0;
    for (const g of db.globals) { const sc = matcher(g.name); if (sc) { hits.push({ category: "globals", address: g.addr, title: g.name, subtitle: `${g.section} · ${g.readers}R/${g.writers}W`, score: 18 + sc * 3 }); if (++n >= limit) break; } }
  }
  if ((want("comments") || prefix === "str") && !prefix) {
    let n = 0;
    for (const [addr, body] of db.comments) { const sc = matcher(body); if (sc) { hits.push({ category: "comments", address: addr, title: body.slice(0, 100), subtitle: db.labelFor(addr), score: 25 + sc * 3 }); if (++n >= limit) break; } }
    for (const [addr, body] of db.functionComments) { const sc = matcher(body); if (sc) { hits.push({ category: "comments", address: addr, title: body.slice(0, 100), subtitle: db.labelFor(addr), score: 25 + sc * 3 }); if (++n >= limit) break; } }
  }
  if (want("bookmarks") && !prefix) {
    for (const b of db.bookmarks.values()) { const sc = Math.max(matcher(b.label), matcher(b.note)); if (sc) hits.push({ category: "bookmarks", address: b.address, title: b.label, subtitle: b.note || db.labelFor(b.address), score: 28 + sc * 3 }); }
  }
  if (want("tags") || prefix === "tag") {
    let n = 0;
    for (const [addr, set] of db.tags) for (const t of set) { const sc = matcher(t); if (sc) { hits.push({ category: "tags", address: addr, title: `#${t}`, subtitle: db.labelFor(addr), score: 26 + sc * 3 }); if (++n >= limit) break; } }
  }
  if ((want("semantic") || prefix === "class") && !["str", "tag", "mn", "fn", "sym"].includes(prefix)) {
    let n = 0;
    const words = text.toLowerCase().split(/[\s,]+/).filter(Boolean);
    for (const f of db.functions) {
      if (!f.classes?.length) continue;
      for (const c of f.classes) {
        const label = c.label.toLowerCase();
        const sc = matcher(c.label) || (mode === "text" && words.some((w) => label.includes(w) || SYNONYMS[w]?.some((s) => label.includes(s))) ? 1 : 0);
        if (sc) { hits.push({ category: "semantic", address: f.addr, title: f.name, subtitle: `${c.level} ${c.label} · ${Math.round(c.confidence * 100)}%`, score: 10 + c.confidence * 10 + sc }); n++; break; }
      }
      if (n >= limit) break;
    }
  }
  if ((prefix === "mn" || (opts.instructions && !prefix)) && want("instructions") && db.arch) {
    // bounded instruction search over functions (mnemonic or operand text)
    let n = 0;
    const budget = 400_000;
    let decoded = 0;
    for (const f of db.functions) {
      if (decoded > budget || n >= limit) break;
      const insns = db.decodeFunction(f, 2000);
      decoded += insns.length;
      for (const ins of insns) {
        const s = `${ins.mnemonic} ${ins.opText}`;
        const sc = prefix === "mn" ? (ins.mnemonic === text.toLowerCase() ? 3 : ins.mnemonic.startsWith(text.toLowerCase()) ? 1 : 0) : matcher(s);
        if (sc) { hits.push({ category: "instructions", address: ins.address, title: s, subtitle: db.labelFor(ins.address), score: 5 + sc }); if (++n >= limit) break; }
      }
    }
  }
  hits.sort((a, b) => b.score - a.score);
  return hits;
}

const SYNONYMS: Record<string, string[]> = {
  network: ["networking"], networking: ["networking"], net: ["networking"], socket: ["networking"], packet: ["networking", "serialization"],
  crypto: ["cryptography", "hashing"], encryption: ["cryptography"], hash: ["hashing"], checksum: ["hashing", "integrity"],
  render: ["rendering"], graphics: ["rendering"], gpu: ["rendering"], memory: ["memory-management", "memory-operations"], alloc: ["memory-management"],
  file: ["file-io"], io: ["file-io"], log: ["logging"], config: ["configuration"], init: ["initialization"], state: ["state-management", "state-access"], world: ["state"], player: ["state"],
  integrity: ["integrity-check", "validation"], antidebug: ["integrity-check"], anti: ["integrity-check"], tamper: ["integrity-check"], validate: ["validation"], check: ["validation", "integrity-check"],
  string: ["string-processing"], parse: ["serialization"], serialize: ["serialization"], thread: ["threading", "synchronization"], lock: ["synchronization"], jni: ["jni-bridge"], java: ["jni-bridge"],
  input: ["input-handling"], touch: ["input-handling"], compress: ["compression"], zip: ["compression"], error: ["error-handling"], exception: ["error-handling"], time: ["timing"],
};

function kindName(k: number) {
  return ["", "call", "jump", "read", "write", "address", "pointer", "string"][k] ?? "ref";
}

export function categoryCounts(hits: SearchHit[]) {
  const c: Partial<Record<SearchCategory, number>> = {};
  for (const h of hits) c[h.category] = (c[h.category] ?? 0) + 1;
  return c;
}
