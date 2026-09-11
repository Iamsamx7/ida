import type { AnalysisDatabase } from "./database";
import { ANTI_TAMPER_STR } from "./semantic/rules";
import { EMU_MARKER_RE } from "./intel";
import { MRPC_STR } from "./mrpc";

/**
 * Cross-library linkage. A workspace holds several .so files loaded together
 * (e.g. libUE4 + libanogs + libtersafe); this module answers "do they see each
 * other, and how" — which library resolves whose symbols, who dynamically loads
 * whom, and which detections they share — so a bypass plan for one library can
 * say when the real logic lives in a sibling.
 *
 * It operates on plain descriptors, not the heavy AnalysisDatabase, so it is
 * pure and trivially testable.
 */
export interface LibDescriptor {
  /** File name as loaded. */
  name: string;
  /** DT_SONAME if present, else the file basename — the identity other libs link against. */
  soname: string;
  arch: string;
  /** Defined dynamic symbols (what this lib offers to others). */
  exports: string[];
  /** Undefined dynamic symbols (what this lib needs from others). */
  imports: string[];
  /** DT_NEEDED entries. */
  needed: string[];
  /** `lib*.so` basenames referenced as strings — dlopen/dlsym candidates. */
  refStrings: string[];
  /** True if this lib imports dlopen/dlsym/android_dlopen_ext. */
  dynLoader: boolean;
  /** Security / anti-tamper / emulator / rule strings, for shared-detection matching. */
  detStrings: string[];
}

export interface LinkEdge {
  /** soname of the dependent / loader. */
  from: string;
  /** soname of the provider / loaded. */
  to: string;
  via: "symbol" | "needed" | "dlopen";
  /** Resolved symbol names (for `via: "symbol"`), capped for display; use `count` for the true total. */
  symbols: string[];
  count: number;
}

export interface LinkGraph {
  nodes: { name: string; soname: string; arch: string; exports: number; imports: number; needed: string[] }[];
  edges: LinkEdge[];
  /** Imports satisfied by NO loaded lib (system/external — libc, libm, …). Informational. */
  unresolved: { lib: string; count: number; sample: string[] }[];
  /** Detection strings that appear in ≥2 loaded libs — evidence they cooperate on the same checks. */
  sharedDetections: { value: string; libs: string[] }[];
}

export function basename(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}

const stripVer = (n: string) => n.replace(/@.*$/, "");

/** Build a descriptor from a loaded database (imports/exports/needed/strings). */
export function libDescriptor(db: AnalysisDatabase): LibDescriptor {
  const soname = db.elf.soname ?? basename(db.fileName);
  const exports = db.elf.exports
    .filter((s) => s.defined && (s.kind === "func" || s.kind === "object") && (s.binding === "global" || s.binding === "weak") && s.name)
    .map((s) => stripVer(s.name));
  const imports = db.elf.imports.map((s) => stripVer(s.name)).filter(Boolean);
  const dynLoader = imports.some((n) => /^(dlopen|dlsym|dlvsym|android_dlopen_ext|__loader_dlopen)$/.test(n));
  const refSeen = new Set<string>();
  const detSeen = new Set<string>();
  const refStrings: string[] = [];
  const detStrings: string[] = [];
  for (const s of db.strings) {
    const v = s.value;
    if (v.length <= 128) {
      const m = v.match(/(lib[\w.+-]+\.so)(\.\d+)?/i);
      if (m) { const b = m[1].toLowerCase(); if (!refSeen.has(b)) { refSeen.add(b); if (refStrings.length < 600) refStrings.push(b); } }
    }
    if (v.length <= 80 && (ANTI_TAMPER_STR.test(v) || EMU_MARKER_RE.test(v) || MRPC_STR.test(v))) {
      const key = v.slice(0, 60);
      if (!detSeen.has(key)) { detSeen.add(key); if (detStrings.length < 800) detStrings.push(key); }
    }
  }
  return { name: basename(db.fileName), soname, arch: db.arch?.id ?? "unknown", exports, imports, needed: db.elf.needed.slice(), refStrings, dynLoader, detStrings };
}

/** Pure: build the cross-library graph from a set of descriptors. */
export function linkLibraries(descs: LibDescriptor[]): LinkGraph {
  const nodes = descs.map((d) => ({ name: d.name, soname: d.soname, arch: d.arch, exports: d.exports.length, imports: d.imports.length, needed: d.needed }));
  // Which loaded libs export each symbol (a symbol can be exported by several).
  const exportIndex = new Map<string, Set<string>>();
  for (const d of descs) for (const e of d.exports) {
    let set = exportIndex.get(e);
    if (!set) exportIndex.set(e, (set = new Set()));
    set.add(d.soname);
  }
  // Loaded libs keyed by every name they might be referenced under.
  const loadedNames = new Map<string, string>(); // any-name → soname
  for (const d of descs) { loadedNames.set(d.soname.toLowerCase(), d.soname); loadedNames.set(basename(d.name).toLowerCase(), d.soname); }

  const edgeMap = new Map<string, LinkEdge>();
  const edge = (from: string, to: string, via: LinkEdge["via"]): LinkEdge => {
    const key = `${from}|${to}|${via}`;
    let e = edgeMap.get(key);
    if (!e) edgeMap.set(key, (e = { from, to, via, symbols: [], count: 0 }));
    return e;
  };

  const unresolved: LinkGraph["unresolved"] = [];
  for (const d of descs) {
    // Symbol resolution: each import satisfied by another loaded lib's export.
    const missing: string[] = [];
    for (const imp of d.imports) {
      const providers = exportIndex.get(imp);
      let resolvedHere = false;
      if (providers) for (const p of providers) {
        if (p === d.soname) continue;
        resolvedHere = true;
        const e = edge(d.soname, p, "symbol");
        e.count++;
        if (e.symbols.length < 16) e.symbols.push(imp);
      }
      if (!resolvedHere) missing.push(imp);
    }
    if (missing.length) unresolved.push({ lib: d.soname, count: missing.length, sample: missing.slice(0, 8) });

    // DT_NEEDED that names a loaded lib.
    for (const n of d.needed) {
      const to = loadedNames.get(n.toLowerCase()) ?? loadedNames.get(basename(n).toLowerCase());
      if (to && to !== d.soname) edge(d.soname, to, "needed").count++;
    }
    // dlopen/dlsym: this lib names another loaded lib as a string.
    for (const ref of d.refStrings) {
      const to = loadedNames.get(ref);
      if (to && to !== d.soname) { const e = edge(d.soname, to, "dlopen"); e.count = Math.max(e.count, d.dynLoader ? 2 : 1); }
    }
  }

  // Shared detections: the same security/rule/emulator string in ≥2 libs.
  const detIndex = new Map<string, Set<string>>();
  for (const d of descs) for (const s of d.detStrings) {
    let set = detIndex.get(s);
    if (!set) detIndex.set(s, (set = new Set()));
    set.add(d.soname);
  }
  const sharedDetections: LinkGraph["sharedDetections"] = [];
  for (const [value, libs] of detIndex) if (libs.size >= 2) sharedDetections.push({ value, libs: [...libs] });
  sharedDetections.sort((a, b) => b.libs.length - a.libs.length || a.value.localeCompare(b.value));

  return { nodes, edges: [...edgeMap.values()].sort((a, b) => b.count - a.count), unresolved, sharedDetections: sharedDetections.slice(0, 40) };
}

/**
 * For one focused lib: which of its imports are resolved by a sibling in the
 * workspace (name → providing soname). Lets a bypass plan flag "the real logic
 * is in libX; hooking the import here only blinds this library's use of it".
 */
export function resolversFor(self: string, descs: LibDescriptor[]): Map<string, string> {
  const out = new Map<string, string>();
  const me = descs.find((d) => d.soname === self || d.name === self);
  if (!me) return out;
  const exportIndex = new Map<string, string>();
  for (const d of descs) { if (d.soname === me.soname) continue; for (const e of d.exports) if (!exportIndex.has(e)) exportIndex.set(e, d.soname); }
  for (const imp of me.imports) { const p = exportIndex.get(imp); if (p) out.set(imp, p); }
  return out;
}
