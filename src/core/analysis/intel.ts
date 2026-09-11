import type { AnalysisDatabase } from "./database";
import type { FunctionRecord } from "./types";
import { ANTI_TAMPER_STR } from "./semantic/rules";

export type IntelKind = "hash-check" | "ban-check" | "anticheat" | "game-revive";

export interface IntelConnection {
  addr: number;
  name: string;
  role: "caller" | "callee" | "string" | "import" | "constant";
  note: string;
}

export interface IntelFinding {
  kind: IntelKind;
  addr: number;
  name: string;
  confidence: number;
  proofLevel: "proven" | "corroborated" | "lead";
  legs: string[];
  whatItIs: string;
  whatItDoes: string;
  connectedTo: IntelConnection[];
  hookImpact: string;
  patchImpact: string;
  howToVerify: string;
  evidence: { text: string; address?: number }[];
}

export interface IntelSummary {
  findings: IntelFinding[];
  counts: Record<IntelKind, number>;
  provenCount: number;
  packedSuspect: boolean;
}

const KIND_LABELS: Record<IntelKind, string[]> = {
  "hash-check": ["hash-check", "hashing", "cryptography"],
  "ban-check": ["ban-check"],
  anticheat: ["anticheat", "integrity-check"],
  "game-revive": ["game-revive"],
};

const hex = (n: number) => "0x" + n.toString(16);

const intelCache = new WeakMap<AnalysisDatabase, { sig: string; out: IntelSummary }>();
/** Every caller shares one computation at this per-kind depth; smaller limits are views of it. */
const FULL_LIMIT = 16;
const EMPTY_COUNTS = (): Record<IntelKind, number> => ({ "hash-check": 0, "ban-check": 0, anticheat: 0, "game-revive": 0 });

function intelSig(db: AnalysisDatabase, limit: number): string {
  // Classification progress is part of the key: functions/strings counts freeze
  // long before labels arrive, and labels are what the findings are built from.
  let classified = 0;
  for (const f of db.functions) if (f.classes?.length) classified++;
  return `${limit}:${db.functions.length}:${db.strings.length}:${db.xrefs.count}:${classified}:${db.revision}`;
}

/**
 * Build fully-traced, verified findings. Pure + deterministic. No guessing.
 *
 * Cached per database snapshot: the sweep is O(functions) with four sorts, and
 * the Overview, the assistant and the planner all ask for it — several times
 * per question and on every render tick during analysis. Returned arrays are
 * fresh copies, so callers may append/sort without poisoning the cache.
 */
export function buildIntel(db: AnalysisDatabase, limitPerKind = 12): IntelSummary {
  const L = Math.max(limitPerKind, FULL_LIMIT);
  const sig = intelSig(db, L);
  let full = intelCache.get(db);
  if (!full || full.sig !== sig) {
    full = { sig, out: computeIntel(db, L) };
    intelCache.set(db, full);
  }
  const taken = EMPTY_COUNTS();
  const findings = full.out.findings.filter((f) => taken[f.kind]++ < limitPerKind);
  const counts = EMPTY_COUNTS();
  for (const f of findings) counts[f.kind]++;
  return { findings, counts, provenCount: findings.filter((f) => f.proofLevel === "proven").length, packedSuspect: full.out.packedSuspect };
}

function computeIntel(db: AnalysisDatabase, limitPerKind: number): IntelSummary {
  const findings: IntelFinding[] = [];
  const packedSuspect = db.insnTotal > 1000 && db.unknownTotal / Math.max(1, db.insnTotal) > 0.25;
  for (const kind of Object.keys(KIND_LABELS) as IntelKind[]) {
    // The kind's own label qualifies at 30%; neighbouring labels (hashing/
    // cryptography → hash-check, integrity-check → anticheat) need 50% — a
    // 30% "cryptography" on a string-assign helper is not a hash check.
    const cands = db.functions
      .filter((f) => !f.isImportStub && f.classes?.some((c) => KIND_LABELS[kind].includes(c.label) && c.confidence >= (c.label === kind ? 0.3 : 0.5)))
      .sort((a, b) => (topConf(b, KIND_LABELS[kind]) - topConf(a, KIND_LABELS[kind])))
      .slice(0, limitPerKind * 2);
    for (const fn of cands) {
      const f = analyzeOne(db, kind, fn);
      if (f) findings.push(f);
      if (findings.filter((x) => x.kind === kind).length >= limitPerKind) break;
    }
  }
  findings.sort((a, b) => b.confidence - a.confidence);
  const counts = EMPTY_COUNTS();
  for (const f of findings) counts[f.kind]++;
  return { findings, counts, provenCount: findings.filter((f) => f.proofLevel === "proven").length, packedSuspect };
}

function topConf(f: FunctionRecord, labels: string[]): number {
  let best = 0;
  for (const c of f.classes ?? []) if (labels.includes(c.label)) best = Math.max(best, c.confidence);
  return best;
}

export function analyzeOne(db: AnalysisDatabase, kind: IntelKind, fn: FunctionRecord): IntelFinding | null {
  const name = db.nameFor(fn.addr).name;
  const cls = (fn.classes ?? []).filter((c) => KIND_LABELS[kind].includes(c.label));
  if (!cls.length) return null;
  const best = cls[0];

  // ---- legs (independent proof sources)
  const legs: string[] = [];
  const evidence: { text: string; address?: number }[] = [];
  const connected: IntelConnection[] = [];

  // Leg 1: classification
  legs.push(`rule-engine:${best.label}@${Math.round(best.confidence * 100)}%`);
  for (const e of best.evidence.slice(0, 3)) evidence.push({ text: e.text, address: e.address });

  // Leg 2: strings actually referenced by THIS function (not global search)
  const feat = fn.features;
  const strRefs = (feat?.stringRefs ?? []).map((a) => db.stringAt(a)).filter((s): s is NonNullable<typeof s> => !!s);
  // Anticheat vocabulary is shared with the rule engine (word-bounded: `root`
  // must not match RootComponent, `anti` must not match AntiAliasing) plus the
  // emulator tells and verdict names.
  const kindTest: (v: string) => boolean = kind === "hash-check" ? (v) => /(verify|checksum|integrity|signature|tamper|hash|md5|sha|crc)/i.test(v)
    : kind === "ban-check" ? (v) => /(\bban(ned|s)?\b|suspend|violation|punish|封号|制裁|account.{0,12}(blocked|frozen))/i.test(v)
    : kind === "anticheat" ? (v) => ANTI_TAMPER_STR.test(v) || EMU_MARKER_RE.test(v) || EMU_VERDICT_RE.test(v)
    : (v) => /(revive|respawn|resurrect|recall|knock|finish.?off|teammate|heal)/i.test(v);
  const hitStrs = strRefs.filter((s) => kindTest(s.value)).slice(0, 4);
  if (hitStrs.length) {
    legs.push(`strings:${hitStrs.length}-direct-ref`);
    for (const s of hitStrs) {
      evidence.push({ text: `"${s.value.slice(0, 60)}"`, address: s.addr });
      connected.push({ addr: s.addr, name: `"${s.value.slice(0, 40)}"`, role: "string", note: "read by this function" });
    }
  }

  // Leg 3: imports / syscalls used by THIS function.
  // Strong imports are witnesses on their own (ptrace, __system_property_get,
  // digest compares…). Weak ones are ordinary file/network/exit APIs that every
  // filesystem helper also calls — they only count when this function also
  // reads a kind-specific string. Without that gate, GCloud::CPath::RmDir
  // "corroborated" anticheat because it calls opendir + stat.
  const imports = db.importCallsOf(fn);
  const strongRe = kind === "hash-check" ? /(memcmp|bcmp|CRYPTO_memcmp|Verify|SHA|MD5|crc|mbedtls_|HMAC)/i
    : kind === "ban-check" ? /(SSL_write|curl_easy_perform|BIO_write|Http|Request|report)/i
    : kind === "anticheat" ? /(ptrace|process_vm_readv|process_vm_writev|__system_property_get|getprop|inotify_add_watch|getppid|tkill|tgkill|prctl|getauxval|syscall)/i
    : /(OnRevive|Respawn|Revive)/;
  const weakRe = kind === "hash-check" ? /(strcmp|strncmp)/i
    : kind === "ban-check" ? /(send|sendto|__android_log_print|exit|_exit|kill|abort)/i
    : kind === "anticheat" ? /(access|stat|fopen|open|openat|readlink|opendir|kill|exit)/i
    : /(write|send|Call|Set|Update|__android_log_print)/;
  const strongImp = imports.filter((n) => strongRe.test(n));
  const weakImp = hitStrs.length ? imports.filter((n) => weakRe.test(n) && !strongRe.test(n)) : [];
  const hitImp = [...strongImp, ...weakImp].slice(0, 5);
  if (hitImp.length) {
    legs.push(`imports:${hitImp.join("+")}${strongImp.length ? "" : " (weak, string-backed)"}`);
    const callees = db.calleesOf(fn);
    for (const n of hitImp) {
      const edge = callees.find((c) => db.callNameFor(c.to).replace(/@.*$/, "") === n);
      evidence.push({ text: `calls ${n}`, address: edge?.from ?? fn.addr });
      connected.push({ addr: edge?.to ?? fn.addr, name: n, role: "import", note: `called at ${hex(edge?.from ?? fn.addr)} · ${db.importLibraryOf(n)}` });
    }
  }

  // Leg 4: structural proof (loop / compare / constants observed in THIS function)
  const h = feat?.mnemonicHist ?? {};
  const total = Object.values(h).reduce((a, b) => a + b, 0);
  const cmp = (h["cmp"] ?? 0) + (h["cmn"] ?? 0) + (h["tst"] ?? 0) + (h["cbz"] ?? 0) + (h["cbnz"] ?? 0) + (h["test"] ?? 0);
  if (kind === "hash-check" && feat && total > 10 && cmp >= 1) {
    legs.push(`structure:${cmp}-compares${feat.hasLoop ? "+loop" : ""}`);
    evidence.push({ text: `${cmp} compare/test instruction(s)${feat.hasLoop ? " with loop" : ""} in ${total} insns`, address: fn.addr });
  } else if (cmp >= 2 && total > 15) {
    legs.push(`structure:${cmp}-branches`);
  }
  const consts = feat?.constants ?? [];
  if (kind === "hash-check" && consts.length) {
    legs.push(`constants:${consts.length}`);
    connected.push({ addr: fn.addr, name: `0x${(consts[0] >>> 0).toString(16)}`, role: "constant", note: "immediate used in this function" });
  }

  // Leg 5: trigger graph — who calls it, what it calls (real xref edges)
  const callers = db.callersOf(fn).slice(0, 8);
  const callees = db.calleesOf(fn).slice(0, 8);
  if (callers.length) {
    legs.push(`triggered-by:${callers.length}`);
    for (const c of callers.slice(0, 4)) {
      const cf = c.fn;
      connected.push({ addr: c.from, name: cf ? db.nameFor(cf.addr).name : db.labelFor(c.from), role: "caller", note: `calls in at ${hex(c.from)}` });
    }
  }
  for (const c of callees.slice(0, 4)) {
    if (connected.some((x) => x.addr === c.to && x.role !== "caller")) continue;
    connected.push({ addr: c.to, name: db.callNameFor(c.to), role: "callee", note: `called at ${hex(c.from)}` });
  }

  // ---- proof level: "proven" needs two independent SEMANTIC witnesses
  // (strings the function reads, imports it calls, algorithm constants it
  // uses). Compare-count shape and "has callers" are true of half the binary,
  // so they may corroborate but never convict on their own — otherwise every
  // classified routine with two compares and one caller shipped as PROVEN.
  const semanticLegs = legs.filter((l) => /^(strings|imports|constants):/.test(l)).length;
  const proofLevel: IntelFinding["proofLevel"] = semanticLegs >= 2 ? "proven" : semanticLegs === 1 ? "corroborated" : "lead";
  const legCount = legs.length;
  let confidence = best.confidence * (proofLevel === "proven" ? 1 : proofLevel === "corroborated" ? 0.85 : 0.6);
  confidence += Math.min(0.12, 0.04 * Math.max(0, legCount - 1));
  if (db.nameFor(fn.addr).source === "symbol") confidence = Math.min(0.98, confidence + 0.08);
  confidence = Math.max(0.2, Math.min(0.98, confidence));

  return {
    kind,
    addr: fn.addr,
    name,
    confidence,
    proofLevel,
    legs,
    whatItIs: whatItIs(kind, name, fn, hitStrs.map((s) => s.value), hitImp),
    whatItDoes: whatItDoes(db, kind, fn, hitStrs.map((s) => s.value), hitImp, cmp, total),
    connectedTo: connected.slice(0, 10),
    hookImpact: hookImpact(kind, name, fn, callers.length, hitImp),
    patchImpact: patchImpact(kind, name, fn, cmp),
    howToVerify: howToVerify(kind, fn.addr, hitStrs.map((s) => s.value).slice(0, 1), hitImp.slice(0, 1)),
    evidence: evidence.slice(0, 8),
  };
}

function whatItIs(kind: IntelKind, name: string, fn: FunctionRecord, strs: string[], imps: string[]): string {
  const sym = fn.nameSource === "symbol" ? `Known symbol ${name}` : `Inlined/unnamed routine ${name}`;
  switch (kind) {
    case "hash-check": return `${sym} — integrity/hash verification routine. It computes or compares a digest and branches on the result.${strs[0] ? ` Anchored on "${strs[0].slice(0, 50)}".` : ""}`;
    case "ban-check": return `${sym} — ban-enforcement routine. It reacts to a ban/violation state and reports or punishes.${strs[0] ? ` Anchored on "${strs[0].slice(0, 50)}".` : ""}`;
    case "anticheat": return `${sym} — anti-tamper/anti-cheat check. It probes the environment (debugger, emulator, root, hooks) and flags tampering.${imps[0] ? ` Built around ${imps[0]}.` : ""}`;
    case "game-revive": return `${sym} — revive/respawn game-logic handler. It transitions player state (knocked → revived) and notifies teammates.${strs[0] ? ` Anchored on "${strs[0].slice(0, 50)}".` : ""}`;
  }
}

function whatItDoes(db: AnalysisDatabase, kind: IntelKind, fn: FunctionRecord, strs: string[], imps: string[], cmp: number, total: number): string {
  const callers = db.callersOf(fn).length;
  const callees = db.calleesOf(fn).length;
  switch (kind) {
    case "hash-check": return `Reads the target bytes, runs a hash/compare loop (${total} insns, ${cmp} compare(s)), then takes or skips a branch. On mismatch it flows into the tamper path (log/kill/exit). Consumers: ${callers} caller(s); dependencies: ${callees} edge(s)${imps.length ? ` incl. ${imps.slice(0, 3).join(", ")}` : ""}.`;
    case "ban-check": return `Evaluates the ban/violation state${strs[0] ? ` ("${strs[0].slice(0, 40)}")` : ""}, then reports (network/log) and/or punishes (kick/exit/block). Triggered from ${callers} site(s); fans out to ${callees} edge(s)${imps.length ? ` incl. ${imps.slice(0, 3).join(", ")}` : ""}.`;
    case "anticheat": return `Probes runtime integrity${imps.length ? ` via ${imps.slice(0, 3).join(", ")}` : ""}${strs[0] ? `, keyed on "${strs[0].slice(0, 40)}"` : ""}. A positive detection forwards into logging/reporting or a kill path. Wired to ${callers} trigger(s), ${callees} downstream edge(s).`;
    case "game-revive": return `Mutates player/team state (HP, knocked flag, position) and emits the revive event to teammates/server. Entry from ${callers} trigger(s); ${callees} downstream edge(s)${imps.length ? ` incl. ${imps.slice(0, 3).join(", ")}` : ""}.`;
  }
}

function hookImpact(kind: IntelKind, name: string, fn: FunctionRecord, callerCount: number, imps: string[]): string {
  switch (kind) {
    case "hash-check": return `Hook ${name} entry and force-return the “match” value: every integrity verdict downstream flips to clean without touching callers. Hooking the inner ${imps[0] ?? "compare"} instead only blinds this one check — prefer the wrapper. ${callerCount} caller(s) inherit the spoof automatically.`;
    case "ban-check": return `Hook ${name} entry and return early: the report/punish path never fires, game continues. Lower noise than hooking send()/exit() globally. If it is server-authoritative, client hook only hides the local effect — the account stays flagged server-side.`;
    case "anticheat": return `Hook ${name} to return “clean”: all ${callerCount} trigger(s) see a clean device. Prefer this over hooking ptrace/getprop individually — one hook covers every probe inside. Watch for secondary checks that re-query the same APIs directly.`;
    case "game-revive": return `Hook ${name} to log/alter revive params (who, HP, position) or force success. Callers (${callerCount}) keep working; downstream state + server packets follow your values. Server may re-validate — treat as client-visual unless the server trusts it.`;
  }
}

function patchImpact(kind: IntelKind, name: string, fn: FunctionRecord, cmp: number): string {
  const at = "0x" + fn.addr.toString(16);
  switch (kind) {
    case "hash-check": return `Patch the verdict branch in ${name} (${at}, ${cmp} compare(s)): flip CBZ↔CBNZ / B.EQ↔B.NE so mismatch falls through to the clean path. 1-branch patch, survives updates worse than a hook. Re-sign/pack after patching.`;
    case "ban-check": return `Patch ${name} (${at}) prologue to RET immediately, or NOP the call into the punish block. Smallest diff = prologue RET. If the ban is server-driven, patching only removes the local kick — relog still blocked.`;
    case "anticheat": return `Patch ${name} (${at}) to RET 0 (clean) at the prologue: every probe inside is skipped in one edit. Alternative: NOP the kill/report call at the tail. Prologue-RET is the smallest, most portable patch.`;
    case "game-revive": return `Patch ${name} (${at}) to skip cooldown/cost checks (NOP the compare→branch pair) for instant revive. Keep the state-write + event-send intact or teammates/server desync.`;
  }
}

function howToVerify(kind: IntelKind, addr: number, strs: string[], imps: string[]): string {
  const a = "0x" + addr.toString(16);
  const s = strs[0] ? ` xref "${strs[0].slice(0, 30)}"` : " string xrefs";
  const c = imps[0] ? ` + ${imps[0]} call edge` : " + call edges";
  return `Go to ${a} → XREFs tab → confirm${s}${c} in the same function → set breakpoint at entry and watch the verdict branch fire.`;
}

/**
 * Any string that smells like an emulator probe (brand, build prop, pipe,
 * device ID, translation layer). Brand words carry word boundaries on purpose:
 * `memu` sits inside VolumeMultiplier and `ldplayer` inside WorldPlayer in
 * every UE4 build, and those are not emulator tells.
 */
export const EMU_MARKER_RE = /(isEmulator|getEmulator|checkEmu|isEmu\b|emu[_-]?detect|\b(mumu|memu|nox|noxplayer|leapdroid|genymotion|youwave|andyos|vbox|virtualbox|goldfish|ranchu|ttvm|qemu|bluestacks|ldplayer|gameloop|smartgaga|phoenixos|primeos|remixos|blissos|houdini|libhoudini|nativebridge|ndk_translation)\b|ro\.product\.(model|manufacturer|brand|device|board|cpu\.abi)|ro\.build\.(fingerprint|characteristics|product|host|tags|type|flavor)|ro\.hardware|ro\.kernel\.qemu|ro\.boot\.qemu|ro\.dalvik\.vm\.native\.bridge|dev\/qemu_pipe|dev\/socket\/qemud|qemu[-_]?props|ueventd\.(ranchu|goldfish|android_x86|vbox)|init\.(ranchu|goldfish)|fstab\.(ranchu|goldfish|android_x86)|000000000000000|1555521555\d?|310260000000000|sdk_gphone|google_sdk|Android SDK built for|android_x86|game\s*simulator|running on .{0,24}(emulator|simulator))/i;

/**
 * Strings that name an emulator VERDICT rather than a probe: the .so asks
 * someone else (Java GameActivity, the anticheat SDK) "is this an emulator?"
 * and reacts to the answer. UE4 games log these as `IsEmulator[ReturnValue:%d]`.
 */
export const EMU_VERDICT_RE = /(IsEmulator|GetEmulatorName|EmulatorName|EmulatorWhenInit|EmulatorDetect(ed)?|CheckEmulator|OnEmulator|bIsEmulator|IsSimulator|game\s*simulator|running on .{0,24}(emulator|simulator))/i;

export interface EmuMarker {
  key: string;
  addr: number;
  via: "prop" | "fingerprint" | "pipe" | "device-id" | "brand";
  /** What a real phone answers. Labeled examples — swap in a donor device. */
  phoneValue: string;
  /** How to feed the phone value: property spoof vs file hide. */
  how: "prop-spoof" | "file-hide";
}

/** Phone-side answers for well-known emulator tells (examples from a Pixel donor — replace with your own device). */const PHONE_PROPS: [RegExp, string, string][] = [
  [/ro\.product\.model/i, "ro.product.model", "Pixel 8"],
  [/ro\.product\.manufacturer/i, "ro.product.manufacturer", "Google"],
  [/ro\.product\.brand/i, "ro.product.brand", "google"],
  [/ro\.product\.device/i, "ro.product.device", "shiba"],
  [/ro\.product\.board/i, "ro.product.board", "shiba"],
  [/ro\.build\.fingerprint/i, "ro.build.fingerprint", "google/shiba/shiba:14/AP1A.240505.005/1219626:user/release-keys"],
  [/ro\.build\.characteristics/i, "ro.build.characteristics", "default"],
  [/ro\.hardware/i, "ro.hardware", "shiba"],
  [/ro\.kernel\.qemu|ro\.boot\.qemu/i, "ro.kernel.qemu", "0"],
];

/** Every emulator marker actually referenced by anticheat findings, with its phone-side answer. */
export function emuMarkersOf(db: AnalysisDatabase): { markers: EmuMarker[]; functions: { addr: number; name: string }[]; floating: EmuMarker[] } {
  // Readers come from the emulator-scored sweep over ALL anticheat-labelled
  // routines, not just the top-15 confidence window — in a UE4 binary the
  // libhoudini/ro.product probes sit far below hundreds of generic hits.
  const seenAddr = new Set<number>();
  const findings = [...buildIntel(db, 15).findings.filter((f) => f.kind === "anticheat"), ...emuRelevantAnticheat(db, 12)].filter((f) => (seenAddr.has(f.addr) ? false : (seenAddr.add(f.addr), true)));
  const seen = new Map<string, EmuMarker>();
  const fns: { addr: number; name: string }[] = [];
  /** Returns true when the string is a probe tell (verdict names are answers, not something a phone would say differently). */
  const eat = (value: string, addr: number): boolean => {
    if (!EMU_MARKER_RE.test(value) || EMU_VERDICT_RE.test(value)) return false;
    const v = value.slice(0, 80);
    let via: EmuMarker["via"] = "fingerprint";
    let phoneValue = "phone-side value (see table)";
    let how: EmuMarker["how"] = "prop-spoof";
    const prop = PHONE_PROPS.find(([re]) => re.test(value));
    if (prop) { via = "prop"; phoneValue = prop[2]; how = "prop-spoof"; }
    else if (/^\/|dev\/qemu|qemu[-_]?props|ueventd|fstab\.|sys\/qemu/i.test(value)) { via = "pipe"; phoneValue = "(absent on phones)"; how = "file-hide"; }
    else if (/000000000000000|1555521555|310260000000000/i.test(value)) { via = "device-id"; phoneValue = "donor IMEI/IMSI required — no universal safe value"; how = "prop-spoof"; }
    else if (/mumu|memu|nox|genymotion|vbox|virtualbox|goldfish|ranchu|qemu|bluestacks|ldplayer|gameloop|isEmulator|getEmulator/i.test(value)) { via = "brand"; phoneValue = "(must not appear at all)"; how = "prop-spoof"; }
    const key = `${via}:${v}`;
    if (!seen.has(key)) seen.set(key, { key: v, addr, via, phoneValue, how });
    return true;
  };
  for (const f of findings) {
    let touched = false;
    for (const c of f.connectedTo) {
      if (c.role !== "string") continue;
      const s = db.stringAt(c.addr);
      if (s && eat(s.value, s.addr)) touched = true;
    }
    // Also sweep the function's own string refs (connectedTo caps at 10).
    const fn = db.functionByAddr(f.addr);
    for (const a of fn?.features?.stringRefs ?? []) {
      const s = db.stringAt(a);
      if (s && eat(s.value, s.addr)) touched = true;
    }
    if (touched) fns.push({ addr: f.addr, name: db.nameFor(f.addr).name });
  }
  const owned = new Set([...seen.keys()]);
  // Floating tells: emulator markers sitting in the binary that no anticheat
  // finding references (dynamic keys, Java-side checks, unclassified readers).
  const floating: EmuMarker[] = [];
  for (const s of db.strings) {
    if (!EMU_MARKER_RE.test(s.value) || s.value.length > 120) continue;
    const probe = s.value.slice(0, 80);
    const already = [...owned].some((k) => k.endsWith(probe));
    if (already) continue;
    const before = seen.size;
    eat(s.value, s.addr);
    if (seen.size > before) {
      const added = [...seen.values()][seen.size - 1];
      if (floating.length < 10) floating.push(added);
    }
  }
  return { markers: [...seen.values()].slice(0, 20), functions: fns.slice(0, 12), floating };
}

export interface EmuSweep {
  /** Emulator marker strings anywhere in the binary. */
  markers: number;
  /** Sample marker values (up to 8). */
  sample: string[];
  /** Classified anticheat/integrity routines that read device props/files. */
  propReaders: number;
  /** Anticheat findings total (any evidence). */
  anticheatFindings: number;
}

const sweepCache = new WeakMap<AnalysisDatabase, { sig: string; out: EmuSweep }>();
/**
 * Cheap global emulator census: how many tells exist in this binary at all,
 * and how many classified checks read device state. Cached per database
 * snapshot — safe to call from render paths.
 */
export function emuSweep(db: AnalysisDatabase): EmuSweep {
  // Cache key includes classification progress so mid-analysis renders can't
  // go stale (functions/strings counts freeze long before labels arrive).
  let classified = 0;
  for (const f of db.functions) if (f.classes?.length) classified++;
  const sig = `${db.strings.length}:${db.functions.length}:${classified}`;
  const hit = sweepCache.get(db);
  if (hit && hit.sig === sig) return hit.out;
  let markers = 0;
  const sample: string[] = [];
  for (const s of db.strings) {
    if (s.value.length > 160) continue;
    if (EMU_MARKER_RE.test(s.value)) {
      markers++;
      if (sample.length < 8) sample.push(s.value.slice(0, 48));
    }
  }
  // Single pass builds both counts from the same filtered list, so the
  // display can never contradict itself (readers ⊆ findings, by construction).
  const ac = db.functions.filter((f) => (f.classes ?? []).some((c) => c.label === "anticheat" || c.label === "integrity-check"));
  const propReaders = ac.filter((f) => (f.features?.importCalls ?? []).some((n) => /__system_property_get|getprop|^open$|^openat$|^access$|^fopen$|^readlink$|^stat$/i.test(n))).length;
  const out: EmuSweep = { markers, sample, propReaders, anticheatFindings: ac.length };
  sweepCache.set(db, { sig, out });
  return out;
}

/**
 * Emulator-relevant anticheat, regardless of the planner's top-N window:
 * scores every classified anticheat routine on emulator markers + prop/file
 * reads so the ones that actually matter can't be crowded out by hundreds of
 * generic integrity hits.
 */
export function emuRelevantAnticheat(db: AnalysisDatabase, limit = 12): IntelFinding[] {
  const scored: { fn: FunctionRecord; score: number }[] = [];
  for (const fn of db.functions) {
    const cls = fn.classes ?? [];
    const best = cls.reduce((m, c) => (c.label === "anticheat" || c.label === "integrity-check" ? Math.max(m, c.confidence) : m), 0);
    if (best < 0.3) continue;
    let score = best;
    let emuHits = 0;
    for (const a of fn.features?.stringRefs ?? []) {
      const s = db.stringAt(a);
      if (s && s.value.length <= 120 && EMU_MARKER_RE.test(s.value)) emuHits++;
    }
    score += Math.min(1.5, emuHits * 0.5);
    const imps = fn.features?.importCalls ?? [];
    if (imps.some((n) => /__system_property_get|getprop/i.test(n))) score += 1;
    if (imps.some((n) => /^open$|^openat$|^access$|^fopen$|^readlink$|^stat$/i.test(n))) score += 0.5;
    if (emuHits > 0 || imps.some((n) => /__system_property_get|getprop/i.test(n))) scored.push({ fn, score });
  }
  scored.sort((a, b) => b.score - a.score);
  const out: IntelFinding[] = [];
  for (const { fn } of scored.slice(0, limit)) {
    const f = analyzeOne(db, "anticheat", fn);
    if (f) out.push(f);
  }
  return out;
}
