import type { AnalysisDatabase } from "./database";
import type { Instruction } from "../architecture/types";
import { buildIntel, EMU_MARKER_RE, EMU_VERDICT_RE, emuMarkersOf, emuSweep, emuRelevantAnticheat, type IntelFinding } from "./intel";
import { buildMrpcReport, type MrpcReport } from "./mrpc";
import { findDecryptors, type DeobfReport } from "./deobf";
import { libDescriptor, linkLibraries, resolversFor, type LibDescriptor, type LinkGraph } from "./link";

export type BypassSafety = "SAFE" | "RISKY" | "BLOCKED";
export type BypassAction = "hook-entry" | "patch-prologue-ret" | "patch-branch" | "patch-consumer" | "hook-import" | "spoof-props" | "patch-global";

/** Which hook surface(s) the plan may target. `undefined` = auto (all). */
export type SectionSurface = "text" | "got" | "data";
export interface SectionScope { text?: boolean; got?: boolean; data?: boolean }

export interface BypassStep {
  id: string;
  targetAddr: number;
  targetName: string;
  kind: IntelFinding["kind"] | "support";
  action: BypassAction;
  /** Function entry VA the step applies to. */
  address: number;
  /** RVA (module+offset) for Frida / patching, since ASLR moves the base. */
  rva: number;
  title: string;
  detail: string;
  safety: BypassSafety;
  safetyReasons: string[];
  /** Step ids that must also be applied for this step to hold. */
  requires: string[];
  /** What to check at runtime before trusting this step. */
  runtimeChecks: string[];
  frida: string;
  patchHex?: string;
  /** Why-this-step reasoning: the planner arguing with itself, in the open. */
  reasoning: string[];
  /** 0–100 strength: proof legs + precision + corroboration. Higher = harder to be wrong. */
  strength: number;
  /** Key imports this target actually calls (e.g. memcpy, gettimeofday) — the "which is which". */
  imports: string[];
  /** Intel proof level + legs behind this step. */
  proofLevel: "proven" | "corroborated" | "lead";
  legs: string[];
  /** One-line identity: kind + behaviour + key imports. */
  identity: string;
  /** Copy-paste mod-menu line, e.g. PATCH_LIB("libUE4.so","0x7FBAD78","00 00 80 D2 C0 03 5F D6"); */
  patchLib: string;
  /** Same patch returning 1 instead of 0 — for checks whose clean value is nonzero. */
  patchLibAlt?: string;
  /** Set when this target calls an imported symbol resolved from another loaded lib — the real logic lives there. */
  crossLib?: { symbol: string; lib: string }[];
  /** Section the target address lands in (".text", ".got", ".bss", …) — the hook surface. */
  section?: string;
  /** Copy-paste hook line, e.g. HOOK_LIB("libUE4.so","0x7FBAD78",(void*)hook_x,(void**)&orig_x); */
  hookLib: string;
  /** Original bytes at the patch site (file order) — always re-read live before writing. */
  origBytes: string;
}

/** How this .so relates to emulator detection — always written, even when the answer is "not here". */
export interface EmulatorReport {
  /** Emulator tell strings in the binary (word-bounded regex). */
  markers: number;
  sample: string[];
  /** Anticheat findings that read tell strings natively. */
  readers: { addr: number; name: string }[];
  /** Classified checks that call __system_property_get / getprop-style APIs. */
  propReaders: number;
  /** Functions that consume an emulator VERDICT produced elsewhere (IsEmulator / GetEmulatorName-style strings). */
  consumers: { addr: number; name: string; strings: string[] }[];
  spoofSteps: number;
  consumerSteps: number;
  /** One paragraph: what is (and isn't) here and what to do about it. */
  verdict: string;
}

/** Downloaded-rule (MRPC) situation for this .so. */
export interface CrossLibReport {
  self: string;
  /** Libs this one depends on (symbol/needed/dlopen edges). */
  dependsOn: { lib: string; via: string[]; symbols: number }[];
  /** Libs that depend on this one. */
  dependedBy: { lib: string; via: string[]; symbols: number }[];
  /** Security-relevant imports of THIS lib that a sibling resolves — the "logic is elsewhere" list. */
  securityResolvedElsewhere: { symbol: string; lib: string }[];
  /** Detection strings shared with sibling libs. */
  sharedDetections: { value: string; libs: string[] }[];
  note: string;
}

export interface BypassPlan {
  steps: BypassStep[];
  blocked: { target: string; addr: number; reason: string }[];
  warnings: string[];
  coverage: { findings: number; proven: number; covered: number; branches: number; consumers: number };
  passes: string[];
  /** Plan-level thinking log: what each pass concluded and what surprised it. */
  thinking: string[];
  emulator: EmulatorReport;
  /** Downloaded-rule engine detection + how to tick it out. */
  mrpc: MrpcReport;
  /** XOR/byte-transform decryptors — the routines that hide strings/rules. */
  deobf: DeobfReport;
  /** Present only when the plan ran inside a multi-library workspace. */
  crossLib?: CrossLibReport;
  durationMs: number;
}

/** One cross-library strike chain: a caller-lib step and the sibling step that owns the real check. */
export interface WorkspaceChain {
  symbol: string;
  reason: string;
  /** Ordered provider (sibling, the real check) → caller. */
  steps: { lib: string; stepId: string; title: string; addr: number; role: "provider" | "caller" }[];
  /** False when the sibling had no step at the export — hook the caller anyway / inspect the sibling. */
  hasProviderStep: boolean;
}

/** Unified plan across every loaded library, with cross-lib strike chains and one apply order. */
export interface WorkspacePlan {
  perLib: { name: string; soname: string; plan: BypassPlan }[];
  chains: WorkspaceChain[];
  /** Recommended apply order across libs: sibling real-checks before their callers. */
  order: { lib: string; stepId: string; title: string; addr: number }[];
  summary: { libs: number; steps: number; safeSteps: number; chains: number; mrpc: number; providersMissing: number };
  durationMs: number;
}

export interface BypassProgress {
  pass: string;
  passIndex: number;
  passTotal: number;
  progress: number;
  note: string;
  thought?: string;
}

const yieldToUI = () => new Promise<void>((r) => setTimeout(r, 0));
const hex = (n: number) => "0x" + n.toString(16);

/**
 * Safety-verified bypass PLAN generator (analysis aid, not an auto-pwner).
 *
 * Seven passes, each one reasoning in the open (see `thinking` on the plan
 * and `reasoning` on every step) — it tears the binary apart instead of
 * trusting the first hit:
 *  Pass 1 RESOLVE — each verified finding → hook + prologue-patch points.
 *  Pass 2 BRANCHES — disassemble each target and hunt the exact verdict
 *           branches (compare→conditional-branch pairs) for surgical patches.
 *  Pass 3 CONSUMERS — disassemble callers: whoever tests the check's return
 *           value is a second kill-point; hooking the check alone won't save you.
 *  Pass 4 SAFETY — blast-radius, dual-use, heartbeat/persistence and
 *           self-inspection (anti-hook tripwire) analysis; veto or downgrade.
 *  Pass 5 REDUNDANCY — full sweep for sibling checks, backup routines and
 *           byte-identical clones sharing strings+imports; required companions.
 *  Pass 6 ORDER — anticheat → hash → ban, precise-branch before prologue,
 *           hooks before file patches; wire requires-chains.
 *  Pass 7 REVIEW — final veto; single-leg leads can never ship as SAFE.
 *
 * Output is a plan with Frida/patch templates and runtime checks. Every step
 * must be validated in a lab (rooted test device / emulator snapshot) — static
 * analysis cannot see server-side verdicts, runtime-decrypted code, or integrity
 * checks that only exist in memory. Tampering with a live game account risks a
 * ban and may violate the game's Terms of Service.
 */
export async function planBypass(
  db: AnalysisDatabase,
  onProgress?: (p: BypassProgress) => void,
  opts: { includeGameRevive?: boolean; maxSteps?: number; workspace?: { descriptors: LibDescriptor[]; link: LinkGraph }; scope?: SectionScope } = {},
): Promise<BypassPlan> {
  const t0 = performance.now();
  const passes: string[] = [];
  const thinking: string[] = [];
  const report = (passIndex: number, passTotal: number, pass: string, progress: number, note: string, thought?: string) =>
    onProgress?.({ pass, passIndex, passTotal, progress, note, thought });
  const TOTAL = 7;
  const intel = buildIntel(db, 15);
  // Emulator priority: the top-N window crowds out relevant checks when a
  // binary has hundreds of generic integrity hits — force the emu-relevant
  // ones in (deduped by address) so spoof steps can't be starved out.
  try {
    const seen = new Set(intel.findings.map((f) => f.addr));
    const extra = emuRelevantAnticheat(db, 12).filter((f) => !seen.has(f.addr));
    if (extra.length) {
      for (const f of extra) intel.findings.push(f);
      thinking.push(`EMU-PRIORITY: window held none of the emulator-relevant checks among ${emuSweep(db).anticheatFindings} anticheat findings — pulled ${extra.length} in by marker/prop score so spoofing is on the table.`);
    }
  } catch {
    /* emu priority is best-effort; the plan stands without it */
  }
  const steps: BypassStep[] = [];
  const blocked: BypassPlan["blocked"] = [];
  const warnings: string[] = [];

  const base = db.space.imageBase ?? 0;
  const rvaOf = (va: number) => va - base;

  // ---------- Pass 1: RESOLVE ----------
  // One hook + one patch per unique address. A single function can carry
  // several findings (e.g. anticheat + hash-check) — those merge into one
  // step pair so step ids (used as React keys) stay unique.
  passes.push("RESOLVE");
  const candidates = intel.findings.filter((f) => (opts.includeGameRevive ? true : f.kind !== "game-revive"));
  const byAddr = new Map<number, IntelFinding[]>();
  for (const f of candidates) {
    const arr = byAddr.get(f.addr) ?? [];
    arr.push(f);
    byAddr.set(f.addr, arr);
  }
  const targets = [...byAddr.entries()];
  thinking.push(`RESOLVE: ${targets.length} unique target(s) from ${candidates.length} finding(s) — ${candidates.length - targets.length} merged as same-address multi-jobs. Refusing to emit two steps with one id; that class of bug ends here.`);
  let i = 0;
  for (const [addr, group] of targets) {
    const f = group.slice().sort((a, b) => b.confidence - a.confidence)[0];
    const extraKinds = group.map((g) => g.kind).filter((k) => k !== f.kind);
    const kindNote = extraKinds.length ? ` Also flagged ${extraKinds.join(" + ")} — one routine, several jobs.` : "";
    report(1, TOTAL, "RESOLVE", i / Math.max(1, targets.length), `${f.name} @ ${hex(addr)}`, `Resolving ${f.name}: entry hook plus a file-patch fallback — but entry points are blunt, so next I'll hunt the exact branches inside.`);
    await yieldToUI();
    const baseStrength = strengthOf(f);
    const idPack = identityFor(db, f.kind, f.addr, f);
    const pro = prologuePatchLib(db, f.addr);
    const entry: BypassStep = {
      id: `hook-${f.addr.toString(16)}`,
      targetAddr: f.addr,
      targetName: f.name,
      kind: f.kind,
      action: "hook-entry",
      address: f.addr,
      rva: rvaOf(f.addr),
      title: `Hook ${f.name} entry → force “clean”`,
      detail: f.hookImpact + kindNote,
      safety: "SAFE",
      safetyReasons: [],
      requires: [],
      runtimeChecks: [
        `Break at ${hex(f.addr)} and confirm it fires during the protected action (login, match start, scan tick).`,
        `Log its return value on a clean run first — your forced value must match the clean shape (0 vs pointer).`,
        ...f.connectedTo.slice(0, 2).map((c) => `Confirm neighbour ${c.name} @ ${hex(c.addr)} behaves as described (${c.note}).`),
      ],
      frida: fridaHook(libTag(db), f.name, rvaOf(f.addr), cleanReturnFor(f)),
      imports: idPack.imports,
      proofLevel: idPack.proofLevel,
      legs: idPack.legs,
      identity: idPack.identity,
      patchLib: "",
      hookLib: hookLibFor(db, f.addr, f.name).line,
      origBytes: "",
      reasoning: [
        `Chose entry-hook because ${f.name} is ${f.proofLevel} (${f.legs.join(" + ")}): intercepting at the door covers every internal path at once.`,
        `Kept the file-patch twin as fallback, but hooks are reversible and patches aren't — hook proves the theory first.`,
        extraKinds.length ? `Merged ${extraKinds.join(", ")} into this one target instead of emitting twin steps that would fight each other.` : `Single role (${f.kind}) — no merge needed.`,
      ],
      strength: baseStrength,
    };
    const patch: BypassStep = {
      id: `patch-${f.addr.toString(16)}`,
      targetAddr: f.addr,
      targetName: f.name,
      kind: f.kind,
      action: "patch-prologue-ret",
      address: f.addr,
      rva: rvaOf(f.addr),
      title: `Patch ${f.name} prologue → RET 0 (offline/modded-lib path)`,
      detail: f.patchImpact + kindNote + (pro.ok ? ` Original bytes: ${pro.orig}.${pro.landingKept ? " Entry starts with a BTI/PAC landing pad — a BTI JC is kept in front so indirect callers on BTI-enforcing builds don't SIGILL." : ""}${pro.note ? ` ${pro.note}.` : ""} If the clean value is nonzero use the return-1 variant.` : ` ${pro.note}.`),
      safety: pro.decodes === false ? "BLOCKED" : pro.ok ? "SAFE" : "RISKY",
      safetyReasons: pro.decodes === false ? [`Entry bytes (${pro.orig}) do not decode as ${db.arch?.displayName ?? "code"} — packed/encrypted or data; a file patch here writes into garbage.`] : pro.ok ? [] : [pro.note],
      requires: [],
      runtimeChecks: [
        `Read ${pro.words.length * 4 || 8} bytes at ${hex(f.addr)} at runtime and confirm they match the file bytes — packed/relocated code differs.`,
        `After patching, re-check the verdict branch still falls to the clean path (single-step once).`,
      ],
      frida: fridaPatch(libTag(db), f.name, rvaOf(f.addr), pro),
      patchHex: pro.ok ? `${pro.bytesHex} // ${pro.asm} — file byte order, ARM64 only, same bytes as the PATCH_LIB line; verify originals first` : undefined,
      imports: idPack.imports,
      proofLevel: idPack.proofLevel,
      legs: idPack.legs,
      identity: idPack.identity,
      patchLib: pro.line,
      patchLibAlt: pro.ok ? pro.altLine : undefined,
      hookLib: "",
      origBytes: pro.orig || (pro.ok ? "" : pro.note),
      reasoning: [
        `Prologue-RET is the blunt instrument: whole routine returns 0. Kept because when the exact branch (pass 2) turns out to sit in padding-obscured code, this still works.`,
        `Demoted below the branch patch in execution order — precision first, sledgehammer second.`,
      ],
      strength: Math.max(30, baseStrength - 10),
    };
    steps.push(entry, patch);
    // Emulator tells get a spoof step, not just a kill step: make the device
    // answer like a phone instead of silencing the question.
    if (f.kind === "anticheat") {
      const tells = collectEmuTells(db, f.addr);
      if (tells.length) pushSpoofStep(db, steps, f, idPack, baseStrength, tells, false);
      else if (idPack.imports.some((n) => /__system_property_get|getprop|^open$|^openat$|^access$|^fopen$|^readlink$|^stat$/i.test(n))) {
        // Blind spoof: reads device properties/files but the keys aren't
        // visible statically (built at runtime, or JNI-side). Spoof the
        // well-known emulator keys anyway and tell Sam to dump the live ones.
        pushSpoofStep(db, steps, f, idPack, baseStrength, [], true);
      }
    }
    i++;
  }
  // Global catch-all: emulator tells exist in the binary but no anticheat
  // routine references them directly (dynamic keys, Java-side checks, or
  // unclassified readers). One prop-spoof step anchored on the first reader.
  if (!steps.some((s) => s.action === "spoof-props")) {
    const global = collectGlobalEmuTells(db);
    if (global) {
      const anchorFn = db.functionByAddr(global.anchor);
      const anchorName = anchorFn ? db.nameFor(anchorFn.addr).name : db.labelFor(global.anchor);
      const propRows = global.tells.filter((t) => t[2] === "prop");
      const fileRows = global.tells.filter((t) => t[2] === "file");
      const table = global.tells.slice(0, 8).map(([k, v, how]) => `"${k}" → "${v}"${how === "file" ? " [hide file]" : ""}`).join("\n");
      const gImports = anchorFn ? db.importCallsOf(anchorFn).slice(0, 5) : [];
      steps.push({
        id: `spoof-global`,
        targetAddr: global.anchor,
        targetName: anchorName,
        kind: "anticheat",
        action: "spoof-props",
        address: global.anchor,
        rva: rvaOf(global.anchor),
        title: `Spoof device props globally (${global.tells.length} tells, no single owner)`,
        detail: `Nobody owns these tells — they float in the binary (dynamic keys or readers I couldn't classify). Spoof the well-known ones anyway; the real keys show up in a live getprop dump:\n${table}`,
        safety: "RISKY",
        safetyReasons: ["Catch-all, not tied to one proven check — dump live __system_property_get traffic first and confirm which keys actually get asked.", "Global identity change: use a donor ID you own, test account only."],
        requires: [],
        runtimeChecks: [
          `Hook __system_property_get and log every key for one full session — promote the observed ones into the table above.`,
          `Diff getprop output between emulator and donor phone; any key present only on emu joins the table.`,
        ],
        frida: fridaSpoof(propRows.map(([k, v]) => [k, v] as [string, string]), fileRows.map(([k]) => k)),
        patchLib: "",
        hookLib: "",
        origBytes: "",
        imports: [...new Set([...gImports, "__system_property_get"])].slice(0, 5),
        proofLevel: "corroborated",
        legs: ["emu-strings:global", "reader-link"],
        identity: `anticheat · spoofs ${global.tells.length} floating emu tells · CORROBORATED`,
        reasoning: [
          `No single classified routine owns these tells, so killing functions can't cover them — but a property hook covers all readers at once regardless of who asks. That's why this step exists.`,
          `Honestly weaker than a targeted spoof: the table is built from global strings, not one traced check. The live key-dump in runtime checks is what promotes it from lead to finding.`,
        ],
        strength: 62,
      });
    }
  }

  // ---------- Pass 1c: EMULATOR — how this .so relates to emulator detection ----------
  // Three situations, three different answers: the .so probes the device itself
  // (spoof the props — steps above), it merely CONSUMES a verdict produced by
  // Java/SDK code (hook the consumer; props won't help), or it has no emulator
  // story at all (say so and point at the process-wide getprop dump).
  const emu = buildEmulatorReport(db, steps, rvaOf, libTag(db));
  for (const st of emu.consumerSteps) steps.push(st);
  thinking.push(emu.report.consumers.length
    ? `EMULATOR: ${emu.report.consumers.length} function(s) consume an emulator VERDICT ("${emu.report.consumers[0].strings[0]}") produced outside this .so — hooking those beats spoofing props this library never reads.`
    : emu.report.markers ? `EMULATOR: ${emu.report.markers} tell(s) in strings · ${emu.report.readers.length} traced native reader(s) · ${emu.report.propReaders} prop-API reader(s) · ${emu.report.spoofSteps} spoof step(s).`
    : `EMULATOR: no tells in this .so at all — detection, if any, is Java/dex, another native lib, or server-side.`);

  // ---------- Pass 1d: MRPC — the downloaded-rule engine ("tick out the rules") ----------
  const mrpc = buildMrpcReport(db, 12);
  const mrpcSteps = buildMrpcSteps(db, mrpc, steps, rvaOf, libTag(db));
  for (const st of mrpcSteps) steps.push(st);
  thinking.push(mrpc.count
    ? `MRPC: ${mrpc.count} downloaded-rule routine(s) — ${mrpc.networkBacked ? "server-fed" : "bundled-config"}. Best single kill: ${mrpc.findings[0].name} @ ${hex(mrpc.findings[0].addr)} (${mrpc.findings[0].role}). Emitted ${mrpcSteps.length} neutralise step(s); with no rules loaded the whole downloaded ruleset is inert.`
    : `MRPC: no download-rules-and-apply engine in this .so — detection is baked-in (each check is its own step) or the engine lives in a sibling lib / Java. Load siblings and check the Links view.`);

  // ---------- Pass 1f: DEOBF — XOR/string decryptors (the real engine is often XOR-hidden) ----------
  const deobf = findDecryptors(db, 12);
  const deobfSteps = buildDeobfSteps(db, deobf, steps, rvaOf, libTag(db));
  for (const st of deobfSteps) steps.push(st);
  thinking.push(deobf.count
    ? `DEOBF: ${deobf.count} XOR/byte-transform decryptor(s) — the real parser/applier carry no plaintext strings because they're XOR-hidden. Strongest ${deobf.decryptors[0].name} @ ${hex(deobf.decryptors[0].addr)} (${deobf.decryptors[0].eor} XORs). Hook one and DUMP its output to reveal the hidden strings/rules — that beats string-matching entirely.`
    : `DEOBF: no standout XOR decryptor — strings may be in the clear, or the scheme is AES/RC4 (check EVP_/AES_ imports).`);

  // ---------- Pass 1e: SURFACES — .got import redirects & .bss/.data global flags ----------
  // Alternatives to code hooks: one GOT stomp blinds every caller of a security
  // import; forcing the flag a check reads skips it without touching code.
  const gotSteps = buildGotSteps(db, intel.findings, rvaOf, libTag(db));
  const dataSteps = buildGlobalSteps(db, intel.findings, rvaOf, libTag(db));
  for (const st of [...gotSteps, ...dataSteps]) steps.push(st);
  thinking.push(`SURFACES: ${gotSteps.length} .got import-redirect(s) (one stomp = every caller) + ${dataSteps.length} .bss/.data flag-flip(s). Pick the surface at the top of the plan — .text hooks the code, .got redirects the import, .bss/.data forces the flag.`);

  // ---------- Pass 2: BRANCHES — the exact verdict instructions ----------
  passes.push("BRANCHES");
  let branchTotal = 0;
  let b = 0;
  for (const [addr, group] of targets) {
    const f = group.slice().sort((a, b2) => b2.confidence - a.confidence)[0];
    report(2, TOTAL, "BRANCHES", b / Math.max(1, targets.length), `${f.name}`, `Disassembling ${f.name} looking for compare→branch pairs — the exact instructions where clean becomes dirty.`);
    await yieldToUI();
    const found = huntVerdictBranches(db, f.addr);
    // Only branches with a readable verdict shape ship as steps: a compare feeder
    // or a recognisable punish side. Loop back-edges were already excluded.
    const usable = found.filter((br) => br.feeder || br.dirtySide !== "unknown").slice(0, 3);
    if (!found.length) thinking.push(`BRANCHES/${f.name}: no forward conditional branch isolated — falling back to entry hook; the verdict may be computed across calls, so I won't pretend a branch address I can't see.`);
    else if (!usable.length) thinking.push(`BRANCHES/${f.name}: ${found.length} forward branch(es) but none with a compare feeder or a visible punish side — not listing them as verdicts; the entry hook covers this one.`);
    for (const br of usable) {
      branchTotal++;
      const brId = identityFor(db, f.kind, f.addr, f);
      const flip = branchFlipLib(db, br.addr);
      const sideKnown = br.dirtySide !== "unknown";
      steps.push({
        id: `branch-${br.addr.toString(16)}`,
        targetAddr: f.addr,
        targetName: f.name,
        kind: f.kind,
        action: "patch-branch",
        address: br.addr,
        rva: rvaOf(br.addr),
        title: `Flip verdict branch @ ${hex(br.addr)} (${br.text})`,
        detail: `Surgical alternative to the prologue patch: invert this conditional branch so the punish side becomes unreachable. ${br.why}. Bytes now: ${flip.orig || "unreadable"}.`,
        safety: flip.ok && sideKnown ? "SAFE" : "RISKY",
        safetyReasons: [
          ...(flip.ok
            ? [`Single-instruction change inside ${f.name}; rest of the routine (loops, logging, state writes) keeps running — smallest blast radius available.`]
            : [`Exact flip bytes could not be computed (${flip.note}) — confirm the encoding live before writing anything.`]),
          ...(sideKnown ? [] : [`Could not tell which side is the punish path from static reads — flipping the wrong way makes a clean device look dirty. Break here on a dirty run first.`]),
        ],
        requires: [`hook-${f.addr.toString(16)} (validate with hook first — only patch the file after the hook proves the theory)`],
        runtimeChecks: [
          `Break at ${hex(br.addr)} on a dirty run and watch it take the ${br.dirtySide === "target" ? "taken" : br.dirtySide === "fallthrough" ? "fall-through" : "punish"} path; then flip and re-run.`,
          `Confirm the bytes at ${hex(br.addr)} match the file before writing — packed/relocated code differs.`,
        ],
        frida: fridaBranch(f.name, libTag(db), rvaOf(br.addr), br.text, flip),
        patchHex: flip.ok ? `${flip.line.match(/"([0-9A-F ]+)"\);/)?.[1] ?? ""} // ${br.flipHint}` : br.flipHint,
        imports: brId.imports,
        proofLevel: brId.proofLevel,
        legs: brId.legs,
        identity: `${brId.identity} · branch ${br.text.slice(0, 28)}`,
        patchLib: flip.line,
        hookLib: "",
        origBytes: flip.orig || flip.note,
        reasoning: [
          `Found it by walking ${f.name}'s own instructions: ${br.why}. This is the decision point, not a guess about one.`,
          `Preferred over prologue-RET because everything else in the routine keeps behaving — fewer side effects to chase later.`,
          `Skipped ${found.length - usable.length} weaker forward branch(es) and every loop back-edge — flipping a loop guard rewrites the algorithm, not the verdict.`,
        ],
        strength: Math.min(98, baseStrengthOf(group) + (sideKnown ? 8 : 0)),
      });
    }
    b++;
  }
  thinking.push(`BRANCHES: isolated ${branchTotal} exact verdict branch(es) across ${targets.length} target(s). Every branch step names its instruction and its flip — no hand-waving.`);

  // ---------- Pass 3: CONSUMERS — whoever tests the return value ----------
  passes.push("CONSUMERS");
  let consumerTotal = 0;
  let c = 0;
  for (const [addr, group] of targets) {
    const f = group[0];
    const fn = db.functionByAddr(addr);
    const callers = fn ? db.callersOf(fn).slice(0, 6) : [];
    report(3, TOTAL, "CONSUMERS", c / Math.max(1, targets.length), `${f.name} (${callers.length} callers)`, `Checking who tests ${f.name}'s answer — a caller that branches on the return is a second kill-point. Hooking the check alone won't save you from it.`);
    if (c % 3 === 0) await yieldToUI();
    const seenCallers = new Set<number>();
    for (const caller of callers) {
      const cf = caller.fn;
      if (!cf || seenCallers.has(cf.addr)) continue;
      seenCallers.add(cf.addr);
      const trap = huntConsumerTrap(db, cf.addr, addr);
      if (!trap) continue;
      consumerTotal++;
      const cname = db.nameFor(cf.addr).name;
      const conId = identityFor(db, "support", cf.addr, { proofLevel: "corroborated", legs: [`tests-${f.name}`, "caller-disasm"] });
      const conFlip = branchFlipLib(db, trap.addr);
      steps.push({
        id: `consumer-${cf.addr.toString(16)}-${addr.toString(16)}`,
        targetAddr: cf.addr,
        targetName: cname,
        kind: "support",
        action: "patch-consumer",
        address: trap.addr,
        rva: rvaOf(trap.addr),
        title: `Caller trap: ${cname} tests ${f.name} @ ${hex(trap.addr)}`,
        detail: `${cname} calls ${f.name} then branches on the result (${trap.text}). Even with the check hooked, this consumer can re-arm the punish path — neuter it too or verify it goes clean. Bytes now: ${conFlip.orig || "unreadable"}.`,
        safety: "RISKY",
        safetyReasons: conFlip.ok
          ? [`Consumer routine does its own work beyond testing this check — patch only the branch, never prologue-RET the whole caller.`]
          : [`Consumer routine does its own work beyond testing this check — patch only the branch, never prologue-RET the whole caller.`, `Exact flip bytes not computable (${conFlip.note}) — confirm live.`],
        requires: [`hook-${addr.toString(16)} (hook the check first; this consumer step only matters if the punish path still fires)`],
        runtimeChecks: [
          `Break at ${hex(trap.addr)} after forcing ${f.name} clean — if it still takes the dirty path, this consumer needs the flip.`,
        ],
        frida: fridaBranch(`${cname} (consumer of ${f.name})`, libTag(db), rvaOf(trap.addr), trap.text, conFlip),
        patchHex: trap.flipHint,
        imports: conId.imports,
        proofLevel: conId.proofLevel,
        legs: conId.legs,
        identity: `tests ${f.name} · ${conId.imports.length ? "calls " + conId.imports.slice(0, 3).join(", ") : "caller logic"} · CORROBORATED`,
        patchLib: conFlip.line,
        hookLib: "",
        origBytes: conFlip.orig || conFlip.note,
        reasoning: [
          `Caught it by disassembling the caller: call to ${f.name} at ${hex(trap.callSite)}, then ${trap.text} at ${hex(trap.addr)}. That's the return value being judged.`,
          `Marked RISKY on purpose — callers are dual-use by nature. This is a scalpel step, not a sledgehammer.`,
        ],
        strength: 70,
      });
    }
    c++;
  }
  thinking.push(`CONSUMERS: found ${consumerTotal} caller-side trap(s). These are the steps amateurs miss — the check dies but the caller still punishes.`);

  // ---------- Pass 4: SAFETY (+ heartbeat + self-inspection) ----------
  passes.push("SAFETY");
  const callersOf = (addr: number) => {
    const fn = db.functionByAddr(addr);
    return fn ? db.callersOf(fn).length : 0;
  };
  let s = 0;
  for (const st of steps) {
    report(4, TOTAL, "SAFETY", s / Math.max(1, steps.length), `${st.targetName}`, `Stress-testing ${st.targetName}: blast radius, dual-use, does it re-fire on a timer, does it inspect its own hooks?`);
    if (s % 25 === 0) await yieldToUI();
    const callers = callersOf(st.targetAddr);
    const fn = db.functionByAddr(st.targetAddr);
    const imports = fn ? db.importCallsOf(fn) : [];
    // Discovery noise wearing a label: a 4-byte "function" from a relocation or
    // jump table is not a routine. Veto instead of dressing it up.
    if (fn && (fn.size < 8 || (fn.insnCount > 0 && fn.insnCount < 2))) {
      st.safety = "BLOCKED";
      st.safetyReasons.push(`${fn.size}-byte candidate discovered via ${fn.sources.join("+")} — a relocation/jump-table artefact, not a routine; nothing here to hook or patch.`);
      st.reasoning.push("Target is a few bytes wide. Real checks are not four bytes long — this is discovery noise that picked up a label, so I vetoed it.");
      s++;
      continue;
    }
    // Blast radius: heavily-called routines affect more than the target behaviour.
    if (callers >= 20) {
      st.safety = st.safety === "SAFE" ? "RISKY" : st.safety;
      st.safetyReasons.push(`${callers} callers — hooking/patching changes every one of them, not just the security path. Prefer hooking the narrower import inside instead.`);
      st.reasoning.push(`Counted ${callers} callers — that's a crowd. A blunt entry-RET would ripple everywhere, so I downgraded and pointed at the narrower import instead.`);
    }
    // Dual-use: routine does broad work beyond the security check.
    if (imports.length >= 8) {
      st.safety = st.safety === "SAFE" ? "RISKY" : st.safety;
      st.safetyReasons.push(`${imports.length} distinct imports — this routine does general work too; entry-RET may break legit features. Hook the inner security import instead.`);
      st.reasoning.push(`${imports.length} imports means this routine moonlights as general code. Killing the whole thing to stop one check is arson — narrowed the advice.`);
    }
    // Exported symbols are called cross-module; extra caution.
    if (fn && db.elf.exports.some((e) => e.value === fn.addr)) {
      st.safety = st.safety === "SAFE" ? "RISKY" : st.safety;
      st.safetyReasons.push(`Exported symbol — other libraries/processes may call it; test cross-module callers before patching the file.`);
      st.reasoning.push(`It's exported — strangers call it. File-patching an export without checking cross-module callers is how you break the whole process.`);
    }
    // Heartbeat: timing imports + loop = re-firing check. One-shot hooks die here.
    if (fn?.features && isHeartbeat(fn.features, imports)) {
      st.safety = st.safety === "SAFE" ? "RISKY" : st.safety;
      st.safetyReasons.push(`Heartbeat pattern (timing API + loop): this check re-fires on a timer. Your hook must stay resident (Frida, not one-shot patch-and-exit) and survive re-entry.`);
      st.runtimeChecks.push(`Leave the hook resident ≥10 minutes and watch for re-fire ticks; confirm no second timer thread re-arms it.`);
      st.reasoning.push(`Spotted timing calls plus a loop — this isn't a gate you pass once, it's a heartbeat. Planned for persistence, not a single flip.`);
    }
    // Self-inspection: reads its own maps/GOT/code = anti-hook tripwire.
    const strVals = (fn?.features?.stringRefs ?? []).map((a) => db.stringAt(a)?.value ?? "");
    const tripwire = selfInspectionHit(strVals, imports);
    if (tripwire) {
      st.safety = "RISKY";
      st.safetyReasons.push(`Self-inspection tripwire (${tripwire}): it looks at its own memory/maps. Hooking crudely (obvious trampolines, GOT stomps) can trip it — use stealthy hooks and hook this probe first.`);
      st.runtimeChecks.push(`After hooking, re-run the self-inspection path and confirm it still reports clean before touching anything else.`);
      st.reasoning.push(`It inspects itself (${tripwire}). That's a trap for hook tools — order matters: blind this probe before laying the rest, and keep hooks stealthy.`);
    }
    // Single-leg intel never ships as SAFE.
    const finding = intel.findings.find((f) => f.addr === st.targetAddr);
    if (finding?.proofLevel === "lead") {
      st.safety = "RISKY";
      st.safetyReasons.push(`Lead-grade intel only (${finding.legs.join(" + ")}) — confirm at runtime before trusting; do not ship as-is.`);
      st.reasoning.push(`Only one proof leg stands here. I refuse to stamp SAFE on a single witness — runtime must promote it, not me.`);
    }
    if (!st.safetyReasons.length) st.safetyReasons.push("Entry-point interception; original bytes restorable; no cross-module export; scoped to one routine.");
    if (!st.reasoning.length) st.reasoning.push("Clean bill: narrow routine, no crowd, no timer, no tripwire. Still verify live — static analysis is a map, not the territory.");
    st.strength = Math.max(20, Math.min(98, st.strength + (st.safety === "SAFE" ? 4 : st.safety === "RISKY" ? -12 : -30)));
    s++;
  }
  thinking.push(`SAFETY: interrogated ${steps.length} step(s) for crowd size, dual-use, heartbeats and self-inspection tripwires. Anything that smells got downgraded, not deleted — you see the doubt.`);

  // ---------- Pass 5: REDUNDANCY (+ byte-identical clones) ----------
  passes.push("REDUNDANCY");
  const byKind = new Map<string, IntelFinding[]>();
  for (const f of intel.findings) {
    const k = byKind.get(f.kind) ?? [];
    k.push(f);
    byKind.set(f.kind, k);
  }
  // Sibling sweep: every function referencing the same security strings/imports
  // as a finding is a potential backup check — scan ALL functions, in slices.
  const secStrings = new Set<number>();
  const secImports = new Set<string>();
  for (const f of intel.findings) {
    for (const c of f.connectedTo) {
      if (c.role === "string") secStrings.add(c.addr);
      if (c.role === "import") secImports.add(c.name.replace(/@.*$/, ""));
    }
  }
  const fns = db.functions;
  const SLICE = 400;
  let scanned = 0;
  const backupOf = new Map<number, number[]>(); // finding addr -> backup fn addrs
  for (let o = 0; o < fns.length; o += SLICE) {
    report(5, TOTAL, "REDUNDANCY", o / Math.max(1, fns.length), `scanning ${Math.min(o + SLICE, fns.length)}/${fns.length} functions for backup checks`, o === 0 ? "Now the paranoid sweep: every function in the binary, checking whether it shares the security strings AND imports. One shared marker is coincidence — both is a backup check." : undefined);
    await yieldToUI();
    const end = Math.min(fns.length, o + SLICE);
    for (let k = o; k < end; k++) {
      const fn = fns[k];
      if (fn.isImportStub || !fn.features) continue;
      let sharesString = false, sharesImport = false;
      for (const a of fn.features.stringRefs) if (secStrings.has(a)) { sharesString = true; break; }
      if (!sharesString) continue;
      for (const n of fn.features.importCalls) if (secImports.has(n.replace(/@.*$/, ""))) { sharesImport = true; break; }
      if (sharesString && sharesImport) {
        // Attribute to the finding(s) sharing those markers.
        for (const f of intel.findings) {
          const fStr = new Set(f.connectedTo.filter((c) => c.role === "string").map((c) => c.addr));
          const fImp = new Set(f.connectedTo.filter((c) => c.role === "import").map((c) => c.name.replace(/@.*$/, "")));
          const hitS = fn.features.stringRefs.some((a) => fStr.has(a));
          const hitI = fn.features.importCalls.some((n) => fImp.has(n.replace(/@.*$/, "")));
          if (hitS && hitI && fn.addr !== f.addr) {
            const arr = backupOf.get(f.addr) ?? [];
            if (!arr.includes(fn.addr)) arr.push(fn.addr);
            backupOf.set(f.addr, arr);
          }
        }
      }
    }
    scanned = end;
  }
  void scanned;
  // Clone hunt: byte-identical twins (same instruction fingerprint) are the
  // nastiest redundancy — same check compiled twice. Cheap exact-match pass.
  const fpOf = new Map<string, number[]>();
  for (const fn of fns) {
    if (!fn.features || fn.isImportStub) continue;
    const fp = fn.features.fingerprint;
    const arr = fpOf.get(fp) ?? [];
    if (arr.length < 8) arr.push(fn.addr);
    fpOf.set(fp, arr);
  }
  let cloneTotal = 0;
  for (const st of steps.filter((x) => x.action === "hook-entry")) {
    const fn = db.functionByAddr(st.targetAddr);
    const clones = fn?.features ? (fpOf.get(fn.features.fingerprint) ?? []).filter((a) => a !== st.targetAddr).slice(0, 3) : [];
    for (const c of clones) {
      cloneTotal++;
      st.safetyReasons.push(`Byte-identical clone ${db.nameFor(c).name} @ ${hex(c)} (same instruction fingerprint) — the same check twice. Hook it identically or it takes over.`);
    }
    if (clones.length) st.reasoning.push(`Fingerprint-matched ${clones.length} clone(s) — same bytes, same behaviour. Twins must die together.`);
  }
  thinking.push(`REDUNDANCY: sibling sweep + fingerprint clone hunt complete — ${cloneTotal} byte-identical twin(s) unmasked. Twins are the trap that survives a “working” bypass and kills you a week later.`);
  for (const st of steps.filter((x) => x.action === "hook-entry")) {
    const sibs = (byKind.get(st.kind as IntelFinding["kind"]) ?? []).filter((f) => f.addr !== st.targetAddr);
    const backups = (backupOf.get(st.targetAddr) ?? []).slice(0, 4);
    // A companion REQUIREMENT needs evidence of being the same check: shared
    // security strings AND imports (backupOf). Sharing only a kind is not a twin —
    // fifteen hash routines in one binary are fifteen jobs, not one job fifteen times.
    for (const b of backups) {
      const id = `hook-${b.toString(16)}`;
      const bf = db.functionByAddr(b);
      const nm = bf ? db.nameFor(bf.addr).name : hex(b);
      if (steps.some((x) => x.id === id)) {
        if (!st.requires.includes(id)) st.requires.push(id);
        st.safetyReasons.push(`Backup check ${nm} @ ${hex(b)} shares this check's security strings AND imports — neutering only one leaves the twin live; apply both.`);
      } else st.safetyReasons.push(`Possible backup check ${nm} @ ${hex(b)} shares security strings+imports but is not a verified finding — verify at runtime whether it re-fires after this hook; add a companion hook if it does.`);
    }
    if (sibs.length) st.safetyReasons.push(`${sibs.length} other ${st.kind} finding(s) exist (${sibs.slice(0, 3).map((f) => `${f.name}@${hex(f.addr)}`).join(", ")}${sibs.length > 3 ? ", …" : ""}) — independent checks with their own steps, not twins of this one.`);
    if (!sibs.length && !backups.length) st.safetyReasons.push("Redundancy sweep found no sibling check sharing both strings and imports — still re-test after each game update.");
  }

  // ---------- Pass 6: ORDER ----------
  passes.push("ORDER");
  report(6, TOTAL, "ORDER", 0.5, "anticheat → hash → ban, branch → prologue, hook → patch", "Ordering the strike: blind the watchers first, then the scales, then the executioner. Precise cuts before blunt ones, reversible before permanent.");
  await yieldToUI();
  const order = { anticheat: 0, "hash-check": 1, "ban-check": 2, "game-revive": 3, support: 4 } as Record<string, number>;
  const actionOrder = { "hook-entry": 0, "spoof-props": 1, "patch-branch": 2, "patch-consumer": 3, "patch-prologue-ret": 4, "hook-import": 5, "patch-global": 6 } as Record<string, number>;
  steps.sort((a, b) => order[a.kind] - order[b.kind] || (actionOrder[a.action] ?? 9) - (actionOrder[b.action] ?? 9) || a.targetAddr - b.targetAddr);
  // Hook before its own patch variant: hooking is reversible, patching is not.
  // Every patch step (prologue, branch, consumer) hangs off its target's entry
  // hook — derived from targetAddr, never from the step id, so a branch step
  // cannot end up requiring itself.
  for (const st of steps.filter((x) => x.action.startsWith("patch"))) {
    const hookId = `hook-${st.targetAddr.toString(16)}`;
    if (hookId !== st.id && steps.some((x) => x.id === hookId) && !st.requires.some((r) => r.startsWith(hookId))) st.requires.unshift(hookId + " (validate with hook first — only patch the file after the hook proves the theory)");
  }

  // ---------- Pass 7: REVIEW ----------
  passes.push("REVIEW");
  report(7, TOTAL, "REVIEW", 0.5, "final veto", "Last look with fresh eyes: anything I let through that I'd be embarrassed about? Single-leg leads can never be SAFE — demoting, not deleting, so you see the doubt.");
  await yieldToUI();
  // Section scope: stamp each step's surface, then keep only the selected ones.
  // undefined scope = auto = all surfaces.
  const wantText = opts.scope ? !!opts.scope.text : true;
  const wantGot = opts.scope ? !!opts.scope.got : true;
  const wantData = opts.scope ? !!opts.scope.data : true;
  const surfaceEnabled = (s: SectionSurface) => (s === "got" ? wantGot : s === "data" ? wantData : wantText);
  const kept: BypassStep[] = [];
  let scopedOut = 0;
  for (const st of steps) {
    st.section = st.section ?? (db.space.info(st.address).section?.name || "");
    if (st.safety === "BLOCKED") {
      blocked.push({ target: st.targetName, addr: st.address, reason: st.safetyReasons.join("; ") });
      continue;
    }
    if (!surfaceEnabled(stepSurface(st))) { scopedOut++; continue; }
    kept.push(st);
  }
  if (opts.scope && scopedOut) {
    const on = [wantText && ".text", wantGot && ".got", wantData && ".bss/.data"].filter(Boolean).join(", ") || "(none)";
    thinking.push(`SCOPE: you restricted hooks to ${on} — dropped ${scopedOut} step(s) on the other surfaces. Switch to Auto at the top to see them all.`);
  }
  if (intel.packedSuspect) warnings.push("Packed/encrypted code suspected — file addresses may not match runtime. Validate every RVA live (Frida Module.findBaseAddress) before patching the file; absence of findings proves nothing.");
  warnings.push("Server-side verdicts cannot be beaten client-side: a hook only hides the local effect. The account can stay flagged server-side — test on a throwaway account, never a main.");
  warnings.push("Tampering with a live game's protection risks an account ban and may violate the game's Terms of Service. Validate in a lab (emulator snapshot / test account) and keep originals restorable.");
  const covered = new Set(kept.filter((x) => x.action === "hook-entry").map((x) => x.targetAddr)).size;
  const branches = kept.filter((x) => x.action === "patch-branch").length;
  const consumers = kept.filter((x) => x.action === "patch-consumer").length;
  thinking.push(`REVIEW: ${kept.length} step(s) survive (${branches} surgical branch flips, ${consumers} caller traps), ${blocked.length} blocked. Average strength ${Math.round(kept.reduce((a, x) => a + x.strength, 0) / Math.max(1, kept.length))}/100. What remains is verified, ordered, and doubt-labelled — the rest is runtime's job.`);
  if (!kept.some((x) => x.action === "spoof-props")) {
    const sw = emuSweep(db);
    thinking.push(sw.markers === 0
      ? `No spoof step because the sweep found ZERO emulator tells in this binary's strings — nothing to spoof. The checks likely live in dex/Java or server-side; dump live __system_property_get traffic to confirm.`
      : `No spoof step although ${sw.markers} emulator tell(s) float in strings — none is referenced from a function I can anchor a step on (dynamic keys, Java-side readers, or dead strings). They're listed in the emulator review; confirm with a live getprop dump which keys actually get asked.`);
  }
  // ---------- Cross-library: who resolves this lib's security imports ----------
  let crossLib: CrossLibReport | undefined;
  if (opts.workspace && opts.workspace.descriptors.length > 1) {
    crossLib = buildCrossLibReport(kept, libTag(db), opts.workspace);
    if (crossLib.securityResolvedElsewhere.length) thinking.push(`CROSS-LIB: ${crossLib.securityResolvedElsewhere.length} security import(s) here resolve from ${[...new Set(crossLib.securityResolvedElsewhere.map((r) => r.lib))].join(", ")} — those steps are marked; the real logic lives in the sibling, so hook there for a full kill.`);
    else if (crossLib.dependsOn.length) thinking.push(`CROSS-LIB: linked to ${crossLib.dependsOn.length} sibling(s) but none resolves a security symbol used by a step — the checks in this lib are self-contained.`);
  }

  report(7, TOTAL, "REVIEW", 1, `${kept.length} steps, ${blocked.length} blocked`);
  const maxSteps = opts.maxSteps ?? 120;
  // The cap bounds the main code steps, but the curated support surfaces (MRPC
  // rule-engine, .got redirects, .bss/.data flags — all few and bounded) are
  // never starved off the tail: keep every one so the MRPC section is complete.
  const support = kept.filter((s) => s.kind === "support");
  const core = kept.filter((s) => s.kind !== "support");
  const finalSteps = [...core.slice(0, maxSteps), ...support];
  emu.report.spoofSteps = kept.filter((x) => x.action === "spoof-props").length;
  emu.report.consumerSteps = kept.filter((x) => x.id.startsWith("emu-consumer-") || x.identity.startsWith("emu-verdict consumer")).length;
  emu.report.verdict = emulatorVerdict(emu.report);
  return {
    steps: finalSteps,
    blocked,
    warnings,
    coverage: { findings: intel.findings.length, proven: intel.findings.filter((f) => f.proofLevel === "proven").length, covered, branches, consumers },
    passes,
    thinking,
    emulator: emu.report,
    mrpc,
    deobf,
    crossLib,
    durationMs: performance.now() - t0,
  };
}

/** Which hook surface a step targets — used by the section-scope filter. */
export function stepSurface(s: BypassStep): SectionSurface {
  if (s.action === "hook-import") return "got";
  if (s.action === "patch-global") return "data";
  return "text";
}

/** Security-relevant imports worth a whole-module GOT redirect. */
const GOT_SECURITY_IMP = /^(ptrace|process_vm_readv|process_vm_writev|__system_property_get|__system_property_read|inotify_add_watch|getppid|kill|tgkill|tkill|fork|vfork|mprotect|memcmp|bcmp|CRYPTO_memcmp|strcmp|strncmp|sendto|sendmsg|SSL_write|BIO_write|curl_easy_perform|dlopen|dlsym|android_dlopen_ext|fopen|open|openat|access|readlink|__android_log_print)$/;

/** What a redirected import should return, and why. Arg-agnostic (onLeave retval override). */
function gotRedirectHint(imp: string): { clean: string; why: string } {
  if (/ptrace/.test(imp)) return { clean: "0", why: "no debugger attached (PTRACE_TRACEME/ATTACH all succeed-as-clean)" };
  if (/process_vm_readv|process_vm_writev/.test(imp)) return { clean: "-1", why: "self-memory scan fails → nothing to compare" };
  if (/__system_property_get|__system_property_read/.test(imp)) return { clean: "0", why: "spoof device props — use the emulator spoof snippet instead of a blanket 0" };
  if (/inotify_add_watch/.test(imp)) return { clean: "-1", why: "file-watch never arms" };
  if (/getppid/.test(imp)) return { clean: "the real parent pid (don't fake to init)", why: "ppid-based debugger checks" };
  if (/kill|tgkill|tkill/.test(imp)) return { clean: "0", why: "swallow self-kill on detection" };
  if (/fork|vfork/.test(imp)) return { clean: "-1", why: "watchdog child never spawns" };
  if (/memcmp|bcmp|CRYPTO_memcmp/.test(imp)) return { clean: "0 (equal)", why: "force every integrity compare to 'match' — BROAD, breaks legit compares too" };
  if (/strcmp|strncmp/.test(imp)) return { clean: "0 (equal)", why: "force string compares equal — very broad, use only if scoped" };
  if (/sendto|sendmsg|SSL_write|BIO_write|curl_easy_perform/.test(imp)) return { clean: "the length (pretend sent)", why: "drop the detection report while faking success" };
  if (/dlopen|android_dlopen_ext/.test(imp)) return { clean: "0 / a decoy handle", why: "block loading a helper/anticheat module" };
  if (/dlsym/.test(imp)) return { clean: "0", why: "resolve-by-name of a probe returns null" };
  if (/fopen/.test(imp)) return { clean: "0 (NULL)", why: "tell files (/proc/…, maps) look absent" };
  if (/open|openat|access|readlink/.test(imp)) return { clean: "-1", why: "tell files look absent" };
  if (/__android_log_print/.test(imp)) return { clean: "0", why: "silence detection logging (cosmetic)" };
  return { clean: "0", why: "force the clean value" };
}

/**
 * .got surface: one redirect per security import used by findings. Redirecting
 * the GOT slot / import blinds EVERY caller in the module at once — broader than
 * per-function hooks, and the right tool when a check is inlined everywhere.
 */
function buildGotSteps(db: AnalysisDatabase, findings: IntelFinding[], rvaOf: (va: number) => number, lib: string): BypassStep[] {
  // import name → { gotAddr, users: finding names }
  const usedBy = new Map<string, Set<string>>();
  for (const f of findings) {
    const fn = db.functionByAddr(f.addr);
    if (!fn) continue;
    for (const imp of db.importCallsOf(fn)) {
      const base = imp.replace(/@.*$/, "");
      if (!GOT_SECURITY_IMP.test(base)) continue;
      const set = usedBy.get(base) ?? new Set<string>();
      set.add(f.name);
      usedBy.set(base, set);
    }
  }
  // GOT slot address per import (reverse of gotNames).
  const slotOf = new Map<string, number>();
  for (const [addr, name] of db.gotNames) { const base = name.replace(/@.*$/, ""); if (!slotOf.has(base)) slotOf.set(base, addr); }
  const out: BypassStep[] = [];
  const ranked = [...usedBy.entries()].sort((a, b) => b[1].size - a[1].size).slice(0, 12);
  for (const [imp, users] of ranked) {
    const slot = slotOf.get(imp);
    const addr = slot ?? db.functions.find((fn) => db.importCallsOf(fn).includes(imp))?.addr ?? 0;
    if (!addr) continue;
    const hint = gotRedirectHint(imp);
    const usersArr = [...users].slice(0, 6);
    out.push({
      id: `got-${imp}`,
      targetAddr: addr,
      targetName: `${imp}@got`,
      kind: "support",
      action: "hook-import",
      address: addr,
      rva: rvaOf(addr),
      title: `Redirect ${imp} (.got) → ${hint.clean}`,
      detail: `${users.size} check(s) call ${imp} (${usersArr.join(", ")}${users.size > usersArr.length ? ", …" : ""}). One GOT redirect makes ${imp} return ${hint.clean} for all of them — ${hint.why}.`,
      safety: "RISKY",
      safetyReasons: [
        `Module-wide: ${imp} is redirected for EVERY caller, not just the checks — legitimate uses change too. Scope it (check the return only in probe contexts) if that breaks the game.`,
        `GOT stomps are a classic self-inspection tripwire; some anticheat re-reads its own GOT. Prefer Interceptor.replace/attach (below) over a raw pointer overwrite.`,
      ],
      requires: [],
      runtimeChecks: [
        `Log ${imp}'s real return on a clean run before forcing ${hint.clean} — confirm the clean shape.`,
        slot ? `GOT slot at ${hex(slot)} (RVA ${rvaHex(rvaOf(slot))}); confirm it holds ${imp}'s resolved pointer at runtime before any manual stomp.` : `No GOT slot resolved statically — redirect via the export name at runtime instead.`,
      ],
      frida: fridaGotRedirect(lib, imp, hint.clean),
      imports: [imp],
      proofLevel: users.size >= 2 ? "corroborated" : "lead",
      legs: [`got-users:${users.size}`],
      identity: `support · .got redirect of ${imp} · ${users.size} caller-check(s)`,
      patchLib: "",
      hookLib: "",
      origBytes: "",
      section: ".got",
      reasoning: [
        `Chose the GOT surface because ${imp} is used by ${users.size} check(s) — one redirect covers them all, versus ${users.size} separate code hooks.`,
        `Kept it RISKY: module-wide redirects hit legitimate calls too, and self-GOT-inspection can catch a crude stomp.`,
      ],
      strength: Math.min(80, 48 + users.size * 6),
    });
  }
  return out;
}

/**
 * .bss/.data surface: force the flag a check reads. When a finding reads a
 * writable global and branches on it, writing the clean value skips the check
 * without touching code. .bss is zero-init (no file bytes) so this is a runtime
 * write, not a file patch.
 */
function buildGlobalSteps(db: AnalysisDatabase, findings: IntelFinding[], rvaOf: (va: number) => number, lib: string): BypassStep[] {
  const out: BypassStep[] = [];
  const seen = new Set<number>();
  for (const f of findings) {
    if (out.length >= 8) break;
    const fn = db.functionByAddr(f.addr);
    if (!fn || (fn.features?.branchCount ?? 0) < 1) continue;
    const reads = db.dataRefsOf(fn).filter((x) => (x.kind === 3 || x.kind === 5) && !db.stringAt(x.to) && db.space.isMapped(x.to) && !db.space.isExec(x.to));
    for (const r of reads) {
      if (seen.has(r.to)) continue;
      const sec = db.space.info(r.to).section?.name ?? "";
      if (!/\.(bss|data|data\.rel\.ro|got)/.test(sec) || sec === ".got") continue; // .got handled by buildGotSteps
      seen.add(r.to);
      const gname = db.nameFor(r.to).name;
      out.push({
        id: `global-${r.to.toString(16)}`,
        targetAddr: r.to,
        targetName: gname,
        kind: f.kind,
        action: "patch-global",
        address: r.to,
        rva: rvaOf(r.to),
        title: `Force global ${gname} (${sec}) → clean, read by ${f.name}`,
        detail: `${f.name} reads ${gname} @ ${hex(r.to)} (${sec}) and branches on it. Forcing this flag to the clean value skips the check with no code edit. ${sec.includes("bss") ? ".bss is zero-init — no file bytes to patch, so this is a runtime write." : ""}`,
        safety: "RISKY",
        safetyReasons: [
          `The clean value is a guess — read ${gname} on a clean run first; wrong value can fail closed (look guilty).`,
          `Only one reader (${f.name}) is confirmed; other code may write this global back — keep the write resident or hook the writer.`,
        ],
        requires: [],
        runtimeChecks: [
          `Break where ${f.name} reads ${hex(r.to)} on a clean device and record the value; that is the value to force.`,
          `Watch for writers to ${hex(r.to)} that re-set it after you write — if present, hook the writer instead.`,
        ],
        frida: fridaGlobalWrite(lib, gname, rvaOf(r.to)),
        imports: db.importCallsOf(fn).slice(0, 4),
        proofLevel: "lead",
        legs: [`global-read:${gname}`, `reader:${f.name}`],
        identity: `${f.kind} · forces ${sec} flag ${gname}`,
        patchLib: "",
        hookLib: "",
        origBytes: "",
        section: sec,
        reasoning: [
          `Chose the data surface because ${f.name} keys its verdict on ${gname}: flip the flag, skip the check, leave the code intact (survives code-integrity checks that don't cover .bss/.data).`,
          `Lead-only: the clean value isn't known statically, so this needs a live read before it's trustworthy.`,
        ],
        strength: 46,
      });
      break; // one global per finding
    }
  }
  return out;
}

const SECURITY_SYM_RE = /(anogs|anosdk|tersafe|tss|ace|shield|guard|protect|anti|cheat|scan|detect|ptrace|integrity|checksum|verify|tamper|report|ban|rule|policy|emulator|root|frida|xposed|magisk)/i;

/**
 * How this lib links to the rest of the workspace, and which of its own
 * security imports a sibling actually provides. Also stamps the affected steps
 * with `crossLib` so the UI can say "the real logic is in libX".
 */
function buildCrossLibReport(steps: BypassStep[], self: string, ws: { descriptors: LibDescriptor[]; link: LinkGraph }): CrossLibReport {
  const dependsOn = new Map<string, { via: Set<string>; symbols: number }>();
  const dependedBy = new Map<string, { via: Set<string>; symbols: number }>();
  for (const e of ws.link.edges) {
    if (e.from === self) { const g = dependsOn.get(e.to) ?? { via: new Set(), symbols: 0 }; g.via.add(e.via); g.symbols += e.via === "symbol" ? e.count : 0; dependsOn.set(e.to, g); }
    if (e.to === self) { const g = dependedBy.get(e.from) ?? { via: new Set(), symbols: 0 }; g.via.add(e.via); g.symbols += e.via === "symbol" ? e.count : 0; dependedBy.set(e.from, g); }
  }
  const resolvers = resolversFor(self, ws.descriptors);
  const securityResolvedElsewhere: { symbol: string; lib: string }[] = [];
  for (const [sym, lib] of resolvers) if (SECURITY_SYM_RE.test(sym)) securityResolvedElsewhere.push({ symbol: sym, lib });
  // Stamp steps whose target calls one of those cross-resolved security symbols.
  const resolvedSecuritySet = new Map(securityResolvedElsewhere.map((r) => [r.symbol, r.lib]));
  for (const st of steps) {
    const hits = st.imports.map((n) => n.replace(/@.*$/, "")).filter((n) => resolvedSecuritySet.has(n)).map((n) => ({ symbol: n, lib: resolvedSecuritySet.get(n)! }));
    if (hits.length) {
      st.crossLib = hits;
      st.reasoning.push(`Cross-lib: this routine calls ${hits.map((h) => `${h.symbol} → ${h.lib}`).join(", ")} — the actual work happens in the sibling. Hooking here blinds only this lib's use; for a full kill, add a step in ${hits[0].lib}.`);
      st.safetyReasons.push(`Real logic in ${[...new Set(hits.map((h) => h.lib))].join(", ")} (resolves ${hits.map((h) => h.symbol).join(", ")}) — partial without a companion step there.`);
    }
  }
  const shared = ws.link.sharedDetections.filter((s) => s.libs.includes(self)).slice(0, 20);
  const fmt = (m: Map<string, { via: Set<string>; symbols: number }>) => [...m.entries()].map(([lib, g]) => ({ lib, via: [...g.via], symbols: g.symbols })).sort((a, b) => b.symbols - a.symbols);
  const dOn = fmt(dependsOn), dBy = fmt(dependedBy);
  const note = `${self} in a ${ws.descriptors.length}-library workspace. Depends on: ${dOn.map((x) => `${x.lib} (${x.via.join("/")}${x.symbols ? `, ${x.symbols} sym` : ""})`).join(", ") || "nothing loaded"}. Depended on by: ${dBy.map((x) => `${x.lib} (${x.via.join("/")})`).join(", ") || "nothing loaded"}. ${securityResolvedElsewhere.length ? `${securityResolvedElsewhere.length} security symbol(s) resolve from a sibling — marked on the steps.` : "No security symbol crosses a library boundary — checks here are self-contained."} ${shared.length ? `${shared.length} detection string(s) shared with siblings (they cooperate on the same checks).` : ""}`;
  return { self, dependsOn: dOn, dependedBy: dBy, securityResolvedElsewhere, sharedDetections: shared, note };
}

/**
 * Turn XOR-decryptor findings into a hook + patch PAIR each, like normal
 * findings — but the HOOK dumps the plaintext (instrument, never force-return),
 * and the PATCH is a prologue-RET clearly flagged as breaking decryption.
 */
function buildDeobfSteps(db: AnalysisDatabase, deobf: DeobfReport, existing: BypassStep[], rvaOf: (va: number) => number, lib: string): BypassStep[] {
  const out: BypassStep[] = [];
  for (const d of deobf.decryptors.slice(0, 8)) {
    const prior = existing.find((s) => s.targetAddr === d.addr && s.action === "hook-entry");
    if (prior) { prior.title += " — also XOR decryptor"; prior.detail += ` Also an XOR/byte-transform decryptor (${d.eor} XOR ops) — hook it to DUMP the plaintext it produces.`; prior.reasoning.push(`DEOBF: ${d.eor} XOR ops over a ${d.byteLS}-op byte stream — deobfuscates hidden data.`); continue; }
    const fn = db.functionByAddr(d.addr);
    if (!fn) continue;
    const identity = `deobf · XOR decryptor · ${d.eor} XOR / ${d.byteLS} byte ld-st${d.loop ? " · loop" : ""}`;
    const imports = db.importCallsOf(fn).slice(0, 5);
    const strength = Math.min(80, 40 + d.eor * 2 + (d.loop ? 4 : 0));
    out.push({
      id: `hook-${d.addr.toString(16)}`,
      targetAddr: d.addr,
      targetName: d.name,
      kind: "support",
      action: "hook-entry",
      address: d.addr,
      rva: rvaOf(d.addr),
      title: `Dump plaintext from ${d.name} (XOR decryptor)`,
      detail: `XOR/byte-transform decryptor: ${d.eor} XOR ops over ${d.byteLS} byte load/stores${d.loop ? ", in a loop" : ""}. ${d.how}`,
      safety: "SAFE",
      safetyReasons: [
        "Instrumentation only — logs the decrypted output, does not change behaviour (fully reversible).",
        "Output location varies by ABI — the snippet dumps the return value and first args; point it at the real destination buffer once you see it.",
      ],
      requires: [],
      runtimeChecks: [
        `Break at ${hex(d.addr)}, run the protected action, and read the logged plaintext — those are the hidden strings/rules.`,
        `Follow the caller that consumes this output — that is the hidden (no-string) engine.`,
      ],
      frida: d.frida,
      imports,
      proofLevel: "lead",
      legs: [`xor:${d.eor}`, `byte-stream:${d.byteLS}`, ...(d.loop ? ["loop"] : [])],
      identity,
      patchLib: "",
      hookLib: hookLibFor(db, d.addr, d.name).line,
      origBytes: "",
      section: ".text",
      reasoning: [
        `XOR-decrypt shape (${d.eor} eor over a ${d.byteLS}-op byte stream${d.loop ? " + loop" : ""}) — this deobfuscates the hidden strings/rules the static passes can't read.`,
        `Hook to DUMP, not to force-return: forcing a clean value would feed ciphertext downstream and crash. The dump reveals what to attack next.`,
      ],
      strength,
    });
    const pro = prologuePatchLib(db, d.addr);
    out.push({
      id: `patch-${d.addr.toString(16)}`,
      targetAddr: d.addr,
      targetName: d.name,
      kind: "support",
      action: "patch-prologue-ret",
      address: d.addr,
      rva: rvaOf(d.addr),
      title: `Patch ${d.name} prologue → RET (⚠ breaks decryption)`,
      detail: `Prologue-RET here REMOVES the decryption — every caller then gets ciphertext and usually crashes. Only patch a decryptor if you're neutralising a check inlined inside it, not the decrypt itself. Prefer the dump hook above.${pro.ok ? ` Original bytes: ${pro.orig}.` : ` ${pro.note}.`}`,
      safety: pro.decodes === false ? "BLOCKED" : "RISKY",
      safetyReasons: pro.decodes === false
        ? [`Entry bytes (${pro.orig}) do not decode as ${db.arch?.displayName ?? "code"} — packed; a file patch writes garbage.`]
        : ["Removing a decryptor breaks everything downstream that needs the plaintext — high crash risk. Here for parity, not because it's the right move on a decryptor.", ...(pro.ok ? [] : [pro.note])],
      requires: [],
      runtimeChecks: [`Confirm nothing downstream needs this routine's plaintext before RET-ing it (it almost always does).`],
      frida: fridaPatch(lib, d.name, rvaOf(d.addr), pro),
      patchHex: pro.ok ? `${pro.bytesHex} // ${pro.asm} — verify originals first` : undefined,
      imports,
      proofLevel: "lead",
      legs: [`xor:${d.eor}`],
      identity,
      patchLib: pro.line,
      patchLibAlt: pro.ok ? pro.altLine : undefined,
      hookLib: "",
      origBytes: pro.orig || (pro.ok ? "" : pro.note),
      section: ".text",
      reasoning: [`Provided for parity with the other findings, but patching a decryptor deletes the decrypt step — use the dump hook unless you specifically mean to remove it.`],
      strength: Math.max(30, strength - 8),
    });
  }
  return out;
}

/**
 * Turn MRPC findings into a hook + patch PAIR each — the same treatment normal
 * findings get (RESOLVE pass): a reversible entry hook and a prologue-RET-0
 * file patch, each with its own SAFE/RISKY/BLOCKED verdict. Both make the
 * downloader/parser/applier return failure/empty so no rules load. Dedups
 * against an existing hook when the routine is already a normal finding.
 */
function buildMrpcSteps(db: AnalysisDatabase, report: MrpcReport, existing: BypassStep[], rvaOf: (va: number) => number, lib: string): BypassStep[] {
  const out: BypassStep[] = [];
  const serverCaveat = "Neutralises the LOCAL rule set only — rules the server also enforces survive; test on a throwaway account.";
  const shapeCaveat = "Confirm the clean/empty return shape on a clean run first (count vs list vs bool) — forcing the wrong one can fail closed.";
  for (const f of report.findings) {
    // Arm every surviving MRPC finding with hook + patch (like normal findings) —
    // even lead-level ones, because they only survive on a high-specificity anchor
    // (mrpcs_/rule_exe/SetDownloadConfig) or a real mechanism. The lead's weak
    // confidence shows in its strength + identity, not by hiding the hook/patch.
    const prior = existing.find((s) => s.targetAddr === f.addr && s.action === "hook-entry");
    if (prior) {
      prior.title += " — also MRPC rule engine";
      prior.detail += ` It is also part of the downloaded-rule engine (${f.role}): ${f.how}`;
      prior.reasoning.push(`MRPC: references ${f.strings.map((s) => `"${s}"`).join(", ")} — forcing "clean" here also empties the rule path.`);
      // Its patch twin (patch-<addr>) already exists from RESOLVE; nothing to add.
      continue;
    }
    const fn = db.functionByAddr(f.addr);
    if (!fn) continue;
    const legCount = f.legs.length;
    const strength = Math.min(90, 52 + legCount * 6);
    const anchorReason = `Anchored on rule/config vocabulary (${f.strings.map((s) => `"${s}"`).join(", ")}) plus a real mechanism (${f.legs.filter((l) => !l.startsWith("rule-strings")).join(", ")}) — not just a stray "config" string.`;
    const identity = `mrpc · ${f.role} · ${f.proofLevel.toUpperCase()} · ${f.legs.join(" + ")}`;
    // --- hook twin (reversible, start SAFE and let the safety passes decide, like normal findings)
    out.push({
      id: `hook-${f.addr.toString(16)}`,
      targetAddr: f.addr,
      targetName: f.name,
      kind: "support",
      action: "hook-entry",
      address: f.addr,
      rva: rvaOf(f.addr),
      title: `Tick out downloaded rules → hook ${f.name} (${f.role})`,
      detail: `Downloaded-rule engine ${f.role}. ${f.how}`,
      safety: "SAFE",
      safetyReasons: [serverCaveat, shapeCaveat],
      requires: [],
      runtimeChecks: [
        `Break at ${hex(f.addr)} and log what it returns / writes on a clean run — confirm empty == "no rules", not "fail closed".`,
        `Trace where the rule count/list is read after this, and confirm the downloaded checks stop firing once it is empty.`,
      ],
      frida: fridaHook(lib, f.name, rvaOf(f.addr), `0 /* ${f.role}: force no-rules / fetch-failure — confirm the empty shape first */`),
      imports: f.imports,
      proofLevel: f.proofLevel,
      legs: f.legs,
      identity,
      patchLib: "",
      hookLib: hookLibFor(db, f.addr, f.name).line,
      origBytes: "",
      section: ".text",
      reasoning: [
        anchorReason,
        `Chose the ${f.role} because killing one download/parse/apply point empties every rule at once — cheaper and more robust than patching each downloaded check.`,
        `Hook first: reversible, proves the theory before the file patch twin below.`,
      ],
      strength,
    });
    // --- patch twin (prologue → RET 0/1; SAFE/RISKY/BLOCKED from the real bytes, like normal findings)
    const pro = prologuePatchLib(db, f.addr);
    out.push({
      id: `patch-${f.addr.toString(16)}`,
      targetAddr: f.addr,
      targetName: f.name,
      kind: "support",
      action: "patch-prologue-ret",
      address: f.addr,
      rva: rvaOf(f.addr),
      title: `Patch ${f.name} prologue → RET 0 (${f.role}: no rules load)`,
      detail: `${f.how} A prologue RET makes ${f.name} return failure/empty for the offline/modded-lib path — every downloaded rule stays inert.${pro.ok ? ` Original bytes: ${pro.orig}.${pro.landingKept ? " BTI/PAC landing pad preserved." : ""}${pro.note ? ` ${pro.note}.` : ""} Use the return-1 variant if the clean value is nonzero.` : ` ${pro.note}.`}`,
      safety: pro.decodes === false ? "BLOCKED" : pro.ok ? "SAFE" : "RISKY",
      safetyReasons: pro.decodes === false
        ? [`Entry bytes (${pro.orig}) do not decode as ${db.arch?.displayName ?? "code"} — packed/encrypted; a file patch here writes garbage.`]
        : [serverCaveat, shapeCaveat, ...(pro.ok ? [] : [pro.note])],
      requires: [],
      runtimeChecks: [
        `Read ${pro.words.length * 4 || 8} bytes at ${hex(f.addr)} at runtime and confirm they match the file — packed/relocated code differs.`,
        `After patching, confirm the rule count/list downstream is empty and the downloaded checks stop firing.`,
      ],
      frida: fridaPatch(lib, f.name, rvaOf(f.addr), pro),
      patchHex: pro.ok ? `${pro.bytesHex} // ${pro.asm} — verify originals first` : undefined,
      imports: f.imports,
      proofLevel: f.proofLevel,
      legs: f.legs,
      identity,
      patchLib: pro.line,
      patchLibAlt: pro.ok ? pro.altLine : undefined,
      hookLib: "",
      origBytes: pro.orig || (pro.ok ? "" : pro.note),
      section: ".text",
      reasoning: [
        anchorReason,
        `Prologue-RET is the offline/modded-lib twin of the hook: one edit at the ${f.role}'s door starves the whole rule set. Survives updates worse than a hook, so validate with the hook first.`,
      ],
      strength: Math.max(40, strength - 4),
    });
  }
  return out;
}

/** Emulator situation report + hook steps for functions that consume an externally produced verdict. */
function buildEmulatorReport(db: AnalysisDatabase, steps: BypassStep[], rvaOf: (va: number) => number, lib: string): { report: EmulatorReport; consumerSteps: BypassStep[] } {
  const sw = emuSweep(db);
  const em = emuMarkersOf(db);
  const byFn = new Map<number, { addr: number; name: string; strings: string[] }>();
  for (const s of db.strings) {
    if (s.value.length > 120 || !EMU_VERDICT_RE.test(s.value)) continue;
    for (const x of db.xrefs.refsTo(s.addr, 20)) {
      const fn = db.functionAt(x.from);
      if (!fn || fn.isImportStub) continue;
      const c = byFn.get(fn.addr) ?? { addr: fn.addr, name: db.nameFor(fn.addr).name, strings: [] };
      const v = s.value.slice(0, 48);
      if (c.strings.length < 4 && !c.strings.includes(v)) c.strings.push(v);
      byFn.set(fn.addr, c);
    }
  }
  const consumers = [...byFn.values()].sort((a, b) => b.strings.length - a.strings.length || a.addr - b.addr).slice(0, 8);
  const consumerSteps: BypassStep[] = [];
  let covered = 0;
  for (const c of consumers) {
    const existing = steps.find((s) => s.targetAddr === c.addr && s.action === "hook-entry");
    if (existing) {
      // Already a finding with its own hook: mark it so the plan reads as the emulator step it is.
      covered++;
      existing.title += " — emulator-verdict consumer";
      existing.identity = `emu-verdict consumer · ${existing.identity}`;
      existing.detail += ` It also references ${c.strings.map((s) => `"${s}"`).join(", ")}: this is where the Java/SDK emulator verdict is consumed — forcing "clean" here hides the emulator reaction too, and no property spoof can reach a verdict formed elsewhere.`;
      existing.reasoning.push(`Emulator angle: "${c.strings[0]}" is a verdict name, not a probe. The question is asked in Java/the SDK; this routine only reacts to the answer.`);
      continue;
    }
    const fn = db.functionByAddr(c.addr);
    if (!fn) continue;
    consumerSteps.push({
      id: `emu-consumer-${c.addr.toString(16)}`,
      targetAddr: c.addr,
      targetName: c.name,
      kind: "anticheat",
      action: "hook-entry",
      address: c.addr,
      rva: rvaOf(c.addr),
      title: `Hook emulator-verdict consumer ${c.name} → answer "not an emulator"`,
      detail: `${c.name} references ${c.strings.map((s) => `"${s}"`).join(", ")}: this .so is not probing the device here — it asks Java / the anticheat SDK (via JNI) whether this is an emulator and reacts to the answer. Forcing this consumer's result (0 / "NoEmulator") blinds every native caller at once; spoofing ro.* props cannot change a verdict that was formed elsewhere.`,
      safety: "RISKY",
      safetyReasons: [
        "The verdict is produced outside this .so — hooking the consumer hides only the native reaction; the Java/SDK side may still report it server-side.",
        'Return shape unconfirmed: bool (0/1) vs FString ("NoEmulator") — log the clean value on a real phone first.',
      ],
      requires: [],
      runtimeChecks: [
        `Break at ${hex(c.addr)} on a phone and on the emulator; record both return values before forcing anything.`,
        "Find who produces the verdict: hook JNI CallStaticBooleanMethod / CallStaticObjectMethod and log method names around this call — that is the real check (Java) and the better place to lie.",
      ],
      frida: fridaHook(lib, c.name, rvaOf(c.addr), "0 /* not-emulator — confirm the clean shape first; FString-returning variants need a different hook */"),
      imports: db.importCallsOf(fn).slice(0, 5),
      proofLevel: "corroborated",
      legs: [`emu-verdict-strings:${c.strings.length}`, "xref-traced"],
      identity: `anticheat · consumes emulator verdict ("${c.strings[0].slice(0, 24)}") · CORROBORATED`,
      patchLib: "",
      hookLib: hookLibFor(db, c.addr, c.name).line,
      origBytes: "",
      reasoning: [
        `"${c.strings[0]}" is a verdict name, not a probe: no ro.* reads, no qemu paths, no __system_property_get in this routine — the question was asked elsewhere.`,
        "That is also why no spoof step covers it: props only matter to whoever reads them, and that is not this library.",
      ],
      strength: 58,
    });
    covered++;
  }
  const report: EmulatorReport = { markers: sw.markers, sample: sw.sample, readers: em.functions, propReaders: sw.propReaders, consumers, spoofSteps: steps.filter((s) => s.action === "spoof-props").length, consumerSteps: covered, verdict: "" };
  report.verdict = emulatorVerdict(report);
  return { report, consumerSteps };
}

export function emulatorVerdict(r: EmulatorReport): string {
  if (!r.markers && !r.consumers.length) return "No emulator tells in this .so's strings (brands, build props, qemu pipes, device IDs, translation layers) and no verdict names. Emulator detection, if any, lives in Java/dex, in another native library (libanogs/libtersafe-style) or server-side. Nothing to spoof here — hook __system_property_get process-wide and log which keys get asked to find the real reader.";
  const parts: string[] = [];
  const consumerList = r.consumers.slice(0, 4).map((c) => `${c.name}@${hex(c.addr)}`).join(", ");
  const readerList = r.readers.slice(0, 3).map((f) => `${f.name}@${hex(f.addr)}`).join(", ");
  if (r.consumers.length && r.readers.length) parts.push(`Two emulator stories in this .so. (1) It CONSUMES a verdict (${r.consumers.slice(0, 2).map((c) => `"${c.strings[0]}"`).join(", ")}) produced by Java/SDK code in ${r.consumers.length} function(s): ${consumerList} — props cannot change that verdict; hook them (${r.consumerSteps} hook step(s) marked "emu-verdict consumer") or the Java side. (2) It also PROBES natively in ${r.readers.length} routine(s): ${readerList} — ${r.spoofSteps} spoof/hide step(s) emitted for those.`);
  else if (r.consumers.length) parts.push(`This .so does not probe the device for emulators itself — it CONSUMES a verdict (${r.consumers.slice(0, 2).map((c) => `"${c.strings[0]}"`).join(", ")}) produced by Java/SDK code and reacts to it in ${r.consumers.length} function(s): ${consumerList}. Spoofing device props won't change that verdict; hook the consumer(s) (${r.consumerSteps} hook step(s) marked "emu-verdict consumer") or the Java side.`);
  else if (r.readers.length) parts.push(`${r.readers.length} routine(s) probe the device for emulator tells natively (${readerList}); ${r.spoofSteps} spoof/hide step(s) emitted for them.`);
  if (!r.readers.length && r.markers && !r.consumers.length) parts.push(`${r.markers} emulator tell(s) sit in the strings (e.g. ${r.sample.slice(0, 3).map((s) => `"${s}"`).join(", ")}) but no classified routine in this .so reads them — treated as floating. ${r.propReaders ? `${r.propReaders} routine(s) call __system_property_get, so some keys are built at runtime: dump them live.` : "Nothing here calls __system_property_get either, so the reader is outside this library."}`);
  else if (!r.readers.length && r.markers > r.consumers.length) parts.push(`Other tells in the strings (${r.markers} total) have no traced native reader — floating; a live getprop dump shows which ones actually get asked.`);
  if (r.spoofSteps && !r.readers.length) parts.push(`A catch-all prop spoof was emitted anyway (${r.spoofSteps} step(s)) — a property hook covers any reader in the process, this .so or not.`);
  return parts.join(" ");
}

/** Identity pack: the "which is which" — kind + key imports + behaviour in one line. */
export function identityFor(
  db: AnalysisDatabase,
  kind: IntelFinding["kind"] | "support",
  addr: number,
  proof: { proofLevel: "proven" | "corroborated" | "lead"; legs: string[] },
): { imports: string[]; proofLevel: "proven" | "corroborated" | "lead"; legs: string[]; identity: string } {
  const fn = db.functionByAddr(addr);
  const imports = fn ? db.importCallsOf(fn).slice(0, 5) : [];
  const h = fn?.features?.mnemonicHist ?? {};
  const cmp = (h["cmp"] ?? 0) + (h["cmn"] ?? 0) + (h["tst"] ?? 0) + (h["cbz"] ?? 0) + (h["cbnz"] ?? 0) + (h["test"] ?? 0);
  const loop = fn?.features?.hasLoop ? "+loop" : "";
  const kindWord = kind === "support" ? "caller-trap" : kind;
  const doesBit = imports.length ? `calls ${imports.slice(0, 3).join(", ")}` : kind === "hash-check" ? `${cmp} compares${loop}, digest logic` : kind === "anticheat" ? "env probes" : kind === "ban-check" ? "report/punish path" : "no direct imports";
  return { imports, proofLevel: proof.proofLevel, legs: proof.legs, identity: `${kindWord} · ${doesBit} · ${proof.proofLevel.toUpperCase()}` };
}
export function strengthOf(f: IntelFinding): number {
  let s = 40 + Math.round(f.confidence * 30);
  if (f.proofLevel === "proven") s += 12;
  else if (f.proofLevel === "corroborated") s += 4;
  else s -= 10;
  s += Math.min(8, f.legs.length * 2);
  if (f.legs.some((l) => l.startsWith("imports:"))) s += 4;
  return Math.max(20, Math.min(96, s));
}

/** Push one spoof-props step. Blind mode = prop/file APIs but no visible keys. */
function pushSpoofStep(
  db: AnalysisDatabase,
  steps: BypassStep[],
  f: { addr: number; name: string; kind: IntelFinding["kind"]; proofLevel: "proven" | "corroborated" | "lead" },
  idPack: { imports: string[]; proofLevel: "proven" | "corroborated" | "lead"; legs: string[] },
  baseStrength: number,
  tells: [string, string, "prop" | "file"][],
  blind: boolean,
) {
  const base = db.space.imageBase ?? 0;
  const rvaOf = (va: number) => va - base;
  const propRows = tells.filter((t) => t[2] === "prop");
  const fileRows = tells.filter((t) => t[2] === "file");
  const table = blind
    ? "No keys visible statically — table starts from the well-known emulator set; promote live-dumped keys into it."
    : tells.slice(0, 8).map(([k, v, how]) => `"${k}" → "${v}"${how === "file" ? " [hide file]" : ""}`).join("\n") + (tells.length > 8 ? `\n…+${tells.length - 8} more (see full finding)` : "");
  steps.push({
    id: `spoof-${f.addr.toString(16)}`,
    targetAddr: f.addr,
    targetName: f.name,
    kind: f.kind,
    action: "spoof-props",
    address: f.addr,
    rva: rvaOf(f.addr),
    title: blind ? `Spoof device props blind → dump live keys, look like a phone` : `Spoof device props → look like a phone (${tells.length} tells)`,
    detail: blind
      ? `This check reads device properties/files but builds its keys at runtime (or asks from JNI) — nothing to trace statically. Spoof the well-known emulator set, then dump live __system_property_get traffic and promote what you see:\n${table}`
      : `This check asks the device who it is. Answer like a phone instead of killing the question:\n${table}`,
    safety: "RISKY",
    safetyReasons: blind
      ? ["Blind table: keys unconfirmed until a live dump — do not ship the defaults.", "Global identity change: use a donor ID you own, test account only."]
      : ["Global identity change: every app on the device sees the spoofed props, and some games bind accounts to device IDs — use a donor ID you own, test account only."],
    requires: [],
    runtimeChecks: blind
      ? [`Hook __system_property_get and LOG every key for one full session (login → match → scan tick) before spoofing anything.`, `Diff getprop emulator vs donor phone; every emu-only key joins the table, then re-run ${f.name} for the clean path.`]
      : [
        `On the emulator AND a donor phone, dump the mapped keys (getprop each) and diff — your spoof table must match the donor exactly.`,
        `After spoofing, re-run ${f.name} and confirm it takes the clean path before touching anything else.`,
      ],
    frida: fridaSpoof(propRows.map(([k, v]) => [k, v] as [string, string]), fileRows.map(([k]) => k)),
    patchLib: "",
    hookLib: "",
    origBytes: "",
    imports: [...new Set([...idPack.imports, "__system_property_get"])].slice(0, 5),
    proofLevel: idPack.proofLevel,
    legs: blind ? [...idPack.legs, "emu-blind"] : [...idPack.legs, `emu-tells:${tells.length}`],
    identity: blind ? `anticheat · blind prop-spoof (keys hidden) · ${idPack.proofLevel.toUpperCase()}` : `anticheat · spoofs ${tells.length} emu tells · ${idPack.proofLevel.toUpperCase()}`,
    reasoning: blind
      ? [
        `It reads device state but I can't see the keys — built at runtime or asked from JNI. Guessing keys would be lying, so this step spoofs the known set and makes the live dump the actual plan.`,
        `Pair with the entry hook: spoof narrows what it can learn, hook guarantees the verdict. Dump first, trust second.`,
      ]
      : [
        `Counted ${tells.length} emulator tells feeding this check (${propRows.length} property reads, ${fileRows.length} file/path probes). Killing the check works, but spoofing removes the *reason* it fires — quieter and survives check-duplicates that share the same props.`,
        `Pair it with the entry hook, don't replace blindly: spoof first (clean identity), hook second (safety net). If the game binds accounts to device IDs, the spoof itself is the risky part — donor ID + test account.`,
      ],
    strength: blind ? Math.max(40, baseStrength - 8) : Math.min(96, baseStrength + 4),
  });
}

/** Global emulator tells: marker strings anywhere in the binary + first reader function. */
function collectGlobalEmuTells(db: AnalysisDatabase): { tells: [string, string, "prop" | "file"][]; anchor: number } | null {
  const seen = new Set<string>();
  const tells: [string, string, "prop" | "file"][] = [];
  let anchor = 0;
  for (const s of db.strings) {
    if (!EMU_MARKER_RE.test(s.value) || s.value.length > 120 || EMU_VERDICT_RE.test(s.value)) continue;
    const key = s.value.slice(0, 64);
    if (seen.has(key)) continue;
    seen.add(key);
    const how: "prop" | "file" = /^\/|dev\/qemu|qemu[-_]?props|ueventd|fstab\.|sys\/qemu/i.test(s.value) ? "file" : "prop";
    tells.push([key, how === "prop" ? phonePropFor(s.value.match(/ro\.[A-Za-z0-9_.]+/)?.[0] ?? s.value) : "(absent on phones — hide the file)", how]);
    if (!anchor) {
      const ref = db.xrefs.refsTo(s.addr, 1)[0];
      const fn = ref ? db.functionAt(ref.from) : null;
      if (fn) anchor = fn.addr;
    }
    if (tells.length >= 12) break;
  }
  if (!tells.length || !anchor) return null;
  return { tells, anchor };
}

/** Emulator tells actually read by one function: [observed, phoneValue, how]. */
export function collectEmuTells(db: AnalysisDatabase, fnAddr: number): [string, string, "prop" | "file"][] {
  const fn = db.functionByAddr(fnAddr);
  if (!fn?.features) return [];
  const out: [string, string, "prop" | "file"][] = [];
  const seen = new Set<string>();
  for (const a of fn.features.stringRefs) {
    const s = db.stringAt(a);
    if (!s || !EMU_MARKER_RE.test(s.value) || s.value.length > 120) continue;
    // Verdict names ("IsEmulator[ReturnValue:%d]") are answers, not probes — nothing to spoof.
    if (EMU_VERDICT_RE.test(s.value)) continue;
    const v = s.value;
    let phone = "";
    let how: "prop" | "file" = "prop";
    const prop = v.match(/ro\.[A-Za-z0-9_.]+/);
    if (prop) phone = phonePropFor(prop[0]);
    else if (/^\/|dev\/qemu|qemu[-_]?props|ueventd|fstab\.|sys\/qemu/i.test(v)) { phone = "(absent on phones — hide the file)"; how = "file"; }
    else if (/000000000000000|1555521555|310260000000000/i.test(v)) phone = "donor IMEI/IMSI required";
    else if (/sdk_gphone|google_sdk|Android SDK built for|android_x86/i.test(v)) phone = "phone fingerprint (see prop table)";
    else phone = "(must not appear — spoof the source prop)";
    const key = v.slice(0, 64);
    if (!seen.has(key)) { seen.add(key); out.push([key, phone, how]); }
    if (out.length >= 10) break;
  }
  return out;
}

function phonePropFor(key: string): string {
  const table: [RegExp, string][] = [
    [/ro\.product\.model/i, "Pixel 8"],
    [/ro\.product\.manufacturer/i, "Google"],
    [/ro\.product\.brand/i, "google"],
    [/ro\.product\.device/i, "shiba"],
    [/ro\.product\.board/i, "shiba"],
    [/ro\.build\.fingerprint/i, "google/shiba/shiba:14/AP1A.240505.005/1219626:user/release-keys"],
    [/ro\.build\.characteristics/i, "default"],
    [/ro\.hardware/i, "shiba"],
    [/ro\.kernel\.qemu|ro\.boot\.qemu/i, "0"],
  ];
  return table.find(([re]) => re.test(key))?.[1] ?? "donor value required";
}

/**
 * Emulator spoof: answer property reads like a phone and make file tells
 * vanish. Block-scoped and free of the static `Module.findExportByName`
 * (removed in Frida 17), so snippets can be concatenated and run on 16 or 17.
 */
export function fridaSpoof(props: [string, string][], files: string[]): string {
  const map = props.map(([k, v]) => `    "${k}": "${v}",`).join("\n");
  const fileList = files.slice(0, 12).map((f) => `"${f.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(", ");
  return [
    `// emu spoof — answer like a phone (LAB ONLY, donor values!). Frida 16/17 safe.`,
    `{`,
    `  const libc = Process.getModuleByName("libc.so");`,
    `  const exp = (m, n) => (typeof m.findExportByName === "function" ? m.findExportByName(n) : null) || (m.enumerateExports().find((e) => e.name === n) || {}).address || null;`,
    `  const PROP_MAP = {`,
    map || `    // (no ro.* keys observed — add donor pairs as getprop shows them)`,
    `  };`,
    `  const getprop = exp(libc, "__system_property_get");`,
    `  if (getprop) Interceptor.attach(getprop, {`,
    `    onEnter(args) { this.key = args[0].readCString(); this.out = args[1]; },`,
    `    onLeave(retval) { const v = PROP_MAP[this.key]; if (v !== undefined) { this.out.writeUtf8String(v); retval.replace(v.length); } }`,
    `  });`,
    `  const FILE_TELLS = [${fileList}];`,
    `  // Hide file tells: open/openat/access/fopen on a tell → "no such file". (stat is left alone — it needs errno + struct handling; add it if the check uses it.)`,
    `  if (FILE_TELLS.length) for (const fn of ["open", "openat", "access", "fopen"]) {`,
    `    const p = exp(libc, fn); if (!p) continue;`,
    `    Interceptor.attach(p, {`,
    `      onEnter(args) { const path = args[fn === "openat" ? 1 : 0].readCString(); this.hide = !!path && FILE_TELLS.some((t) => path.indexOf(t) !== -1); },`,
    `      onLeave(retval) { if (this.hide) retval.replace(fn === "fopen" ? ptr(0) : -1); }`,
    `    });`,
    `  }`,
    `}`,
    ``,
  ].join("\n");
}

/** Mod-menu plumbing: exact PATCH_LIB / HOOK_LIB lines, bytes computed from the binary. */
export function libTag(db: AnalysisDatabase): string {
  return db.elf.soname ?? db.fileName;
}
export function rvaHex(rva: number): string {
  return "0x" + rva.toString(16).toUpperCase();
}
export function symOf(db: AnalysisDatabase, addr: number): string {
  return db.nameFor(addr).name.replace(/[^A-Za-z0-9_]/g, "_").replace(/^[0-9]+/, "fn_$&") || "fn_unknown";
}
export function spaced(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0").toUpperCase()).join(" ");
}
export function readBytesAt(db: AnalysisDatabase, va: number, len: number): Uint8Array | null {
  const bytes = db.readBytes(va, len);
  return bytes.length === len ? bytes : null;
}
/** ARM64 words used by the templates (little-endian in the file). */
export const A64_WORD = {
  BTI_JC: 0xd503249f,
  MOV_X0_0: 0xd2800000,
  MOV_X0_1: 0xd2800020,
  RET: 0xd65f03c0,
} as const;
/** ARM (A32 mode) words: MOV R0,#0 / MOV R0,#1 / BX LR / NOP. Thumb is not covered — the decoder has no Thumb. */
export const A32_WORD = {
  MOV_R0_0: 0xe3a00000,
  MOV_R0_1: 0xe3a00001,
  BX_LR: 0xe12fff1e,
  NOP: 0xe320f000,
} as const;

/** Pure: the prologue-kill words for an architecture, or null when there is no trustworthy template. */
export function prologueWords(archId: string | undefined, landing: boolean, ret: 0 | 1): { words: number[]; asm: string } | null {
  if (archId === "arm64") return { words: [...(landing ? [A64_WORD.BTI_JC] : []), ret ? A64_WORD.MOV_X0_1 : A64_WORD.MOV_X0_0, A64_WORD.RET], asm: `${landing ? "BTI JC; " : ""}MOV X0,#${ret}; RET` };
  if (archId === "arm32") return { words: [ret ? A32_WORD.MOV_R0_1 : A32_WORD.MOV_R0_0, A32_WORD.BX_LR], asm: `MOV R0,#${ret}; BX LR` };
  return null;
}

/**
 * Pure: invert one conditional branch word. ARM64: CBZ↔CBNZ / TBZ↔TBNZ toggle
 * bit 24, B.cond toggles bit 0 (AL/NV excluded). ARM (A32): B<cond> toggles
 * bit 28 — EQ↔NE, CS↔CC, MI↔PL, VS↔VC, HI↔LS, GE↔LT, GT↔LE (AL excluded).
 */
export function flipBranchWord(archId: string | undefined, w: number): { flipped: number; note: "" } | { flipped: null; note: string } {
  const word = `word ${(w >>> 0).toString(16).toUpperCase()}`;
  if (archId === "arm64") {
    const top = w & 0x7f000000;
    if (top === 0x34000000 || top === 0x35000000) return { flipped: (w ^ 0x01000000) >>> 0, note: "" }; // CBZ<->CBNZ (bit 31 = sf, masked)
    if (top === 0x36000000 || top === 0x37000000) return { flipped: (w ^ 0x01000000) >>> 0, note: "" }; // TBZ<->TBNZ (bit 31 = b5, masked)
    if ((w & 0xff000010) === 0x54000000) return (w & 0xf) < 0xe ? { flipped: (w ^ 0x00000001) >>> 0, note: "" } : { flipped: null, note: "B.AL/B.NV is unconditional — nothing to flip" };
    return { flipped: null, note: `not a flippable branch encoding (${word})` };
  }
  if (archId === "arm32") {
    const cond = w >>> 28;
    const isB = ((w >>> 25) & 7) === 5 && ((w >>> 24) & 1) === 0; // B<cond>, not BL
    if (!isB) return { flipped: null, note: `not an ARM B<cond> encoding (${word}) — Thumb sites are not decoded` };
    if (cond >= 0xe) return { flipped: null, note: "B (AL) is unconditional — nothing to flip" };
    return { flipped: (w ^ 0x10000000) >>> 0, note: "" };
  }
  return { flipped: null, note: `no flip template for ${archId ?? "unknown arch"}` };
}

export interface ProloguePatch {
  /** PATCH_LIB line returning 0 (or a `//` explanation when no patch is emitted). */
  line: string;
  /** Same patch returning 1. */
  altLine: string;
  orig: string;
  ok: boolean;
  note: string;
  /** New words, in order. */
  words: number[];
  /** File words the new ones replace — the runtime pre-check compares against these. */
  origWords: number[];
  bytesHex: string;
  asm: string;
  /** Entry began with BTI/PACIASP/PACIBSP: a BTI JC landing pad is preserved in front. */
  landingKept: boolean;
  /** Entry bytes decode as instructions at all. */
  decodes: boolean;
}

export function le32(b: Uint8Array, o = 0): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}
export function wordsBytes(ws: readonly number[]): Uint8Array {
  return new Uint8Array(ws.flatMap((w) => [w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff]));
}
const hex32 = (w: number) => "0x" + (w >>> 0).toString(16).padStart(8, "0");

/**
 * Prologue kill: MOV X0,#0; RET — file byte order, ARM64 only. When the entry
 * starts with BTI or PACIASP/PACIBSP (both are BTI landing pads) a BTI JC is
 * kept in front: on BTI-enforcing builds an indirect call into a non-landing
 * instruction is SIGILL, and the patch would crash exactly the protected path.
 */
export function prologuePatchLib(db: AnalysisDatabase, addr: number): ProloguePatch {
  const lib = libTag(db);
  const off = rvaHex(addr - (db.space.imageBase ?? 0));
  const archId = db.arch?.id;
  const empty: ProloguePatch = { line: "", altLine: "", orig: "", ok: false, note: "", words: [], origWords: [], bytesHex: "", asm: "", landingKept: false, decodes: true };
  if (!prologueWords(archId, false, 0)) return { ...empty, line: `// ${lib} @ ${off}: ${archId ?? "unknown arch"} — no byte template; confirm the return sequence live and patch it there.`, note: `${archId ?? "unknown arch"} — byte template withheld rather than guessed` };
  const first = db.decodeAt(addr, 8, 2);
  const decodes = first.length >= 1 && first[0].kind !== "unknown";
  const landingKept = archId === "arm64" && decodes && /^(bti|paciasp|pacibsp)$/.test(first[0].mnemonic);
  const main = prologueWords(archId, landingKept, 0)!;
  const alt = prologueWords(archId, landingKept, 1)!;
  const origB = readBytesAt(db, addr, main.words.length * 4);
  if (!origB) return { ...empty, decodes, landingKept, words: main.words, line: `// ${lib} @ ${off}: original bytes unreadable (unmapped in file?) — resolve the address before patching.`, orig: "unreadable (unmapped?)", note: "original bytes unreadable" };
  const origWords: number[] = [];
  for (let i = 0; i < main.words.length; i++) origWords.push(le32(origB, i * 4));
  if (!decodes) return { ...empty, decodes, words: main.words, origWords, orig: spaced(origB), line: `// ${lib} @ ${off}: entry bytes ${spaced(origB)} do not decode — packed/encrypted or data; no patch emitted.`, note: `entry bytes do not decode as ${db.arch?.displayName ?? archId}` };
  const bytesHex = spaced(wordsBytes(main.words));
  return {
    line: `PATCH_LIB("${lib}","${off}","${bytesHex}");`,
    altLine: `PATCH_LIB("${lib}","${off}","${spaced(wordsBytes(alt.words))}"); // return 1 instead — use if the clean value is nonzero`,
    orig: spaced(origB),
    ok: true,
    note: archId === "arm32" ? "ARM mode assumed (no Thumb decode) — if the entry is Thumb the bytes differ, confirm live" : "",
    words: main.words,
    origWords,
    bytesHex,
    asm: main.asm,
    landingKept,
    decodes,
  };
}
/**
 * Exact branch flip, computed from the real 4 bytes — never guessed.
 * CBZ<->CBNZ, TBZ<->TBNZ: toggle bit 24. B.cond: invert cond (xor 1), except
 * AL/NV which are unconditional and cannot be flipped.
 */
export function branchFlipLib(db: AnalysisDatabase, addr: number): { line: string; orig: string; ok: boolean; note: string; origWord: number | null; flippedWord: number | null } {
  const lib = libTag(db);
  const off = rvaHex(addr - (db.space.imageBase ?? 0));
  const raw = readBytesAt(db, addr, 4);
  if (!raw) return { line: "", orig: "", ok: false, note: "bytes unreadable at branch site", origWord: null, flippedWord: null };
  const w = le32(raw);
  const r = flipBranchWord(db.arch?.id, w);
  if (r.flipped === null) return { line: "", orig: spaced(raw), ok: false, note: r.note, origWord: w, flippedWord: null };
  return { line: `PATCH_LIB("${lib}","${off}","${spaced(wordsBytes([r.flipped]))}");`, orig: spaced(raw), ok: true, note: "", origWord: w, flippedWord: r.flipped };
}
export function hookLibFor(db: AnalysisDatabase, addr: number, name: string): { line: string } {
  const lib = libTag(db);
  const off = rvaHex(addr - (db.space.imageBase ?? 0));
  const sym = symOf(db, addr);
  return {
    line: [
      `// ${name} — force clean. Match the real signature from pseudocode before compiling!`,
      `// void *orig_${sym} = nullptr;`,
      `// long hook_${sym}(/* same args as original */) { return 0; /* clean value — confirm on clean trace */ }`,
      `HOOK_LIB("${lib}","${off}",(void *)hook_${sym},(void **)&orig_${sym});`,
    ].join("\n"),
  };
}

export function baseStrengthOf(group: IntelFinding[]): number {
  return Math.max(...group.map(strengthOf));
}

/** Heartbeat: timing API + loop = a check that re-fires on a timer. Exact names — `strftime`/`localtime` are not timers. */
export function isHeartbeat(fn: { hasLoop: boolean }, imports: string[]): boolean {
  if (!fn.hasLoop) return false;
  return imports.some((n) => /^(clock_gettime|gettimeofday|nanosleep|usleep|sleep|time|clock|timer_create|timerfd_create|timerfd_settime|epoll_wait|poll|pthread_cond_timedwait|sem_timedwait|elapsedRealtime|uptimeMillis|QueryPerformanceCounter)$/.test(n.replace(/@.*$/, "")));
}

/** Self-inspection tripwire: the routine looks at its own memory/maps or hunts hook frameworks. */
export function selfInspectionHit(stringValues: string[], imports: string[]): string | null {
  const selfStr = stringValues.find((v) => /\/proc\/(self|\d+)\/(maps|mem|pagemap|status|task|fd)|\/proc\/self\/exe|tracerpid|got\.plt|\.got\b|(^|[\s"'/])\.text\s*$|libanogs|libtersafe|frida|substrate|xposed|inject/i.test(v));
  const imp = imports.find((n) => /^(ptrace|process_vm_readv|process_vm_writev|inotify_add_watch|__system_property_get|readlink|fopen|open|openat|mincore|mprotect)$/.test(n.replace(/@.*$/, "")));
  if (selfStr && imp) return `${imp} + "${selfStr.slice(0, 30)}"`;
  if (selfStr) return `"${selfStr.slice(0, 30)}" self-read`;
  return null;
}

export interface VerdictBranch {
  addr: number;
  text: string;
  why: string;
  flipHint: string;
  /** Which successor looks like the punish path — the side a flip must make unreachable. */
  dirtySide: "target" | "fallthrough" | "unknown";
  score: number;
  /** The compare (or self-testing CBZ/TBZ) that feeds the branch, if one is visible. */
  feeder: string | null;
}

/**
 * Calls that end a dirty path. Deliberately NOT here: `__stack_chk_fail`
 * (compiler stack-canary epilogue — flipping its guard crashes every clean
 * run), `__cxa_throw`/`terminate` (ordinary error handling), `write` (too
 * generic).
 */
const PUNISH_IMPORT_RE = /^(exit|_exit|abort|kill|tgkill|tkill|raise|__android_log_print|__android_log_write|__android_log_assert|android_set_abort_message|send|sendto|sendmsg|pthread_exit|syscall)$/;
/** Compiler/runtime guards whose branch is never a verdict. */
const GUARD_IMPORT_RE = /^(__stack_chk_fail|__stack_chk_fail_local|__ubsan_handle_\w+|__asan_\w+|__cxa_bad_cast|__cxa_bad_typeid|__cxa_pure_virtual|__cxa_deleted_virtual)$/;
const PUNISH_STRING_RE = /(ban|cheat|hack|tamper|detect|illegal|violat|kick|report|punish|fail|error|invalid|abnormal|forbid|reject|suspicious)/i;
const isCondBranch = (ins: Instruction) => ins.kind === "condjump" || /^(b\.|cbz|cbnz|tbz|tbnz)/.test(ins.mnemonic);
const isCompareInsn = (ins: Instruction) => ins.kind === "compare" || /^(cmp|cmn|tst|test|ccmp|ccmn|fcmp)$/.test(ins.mnemonic);

/**
 * What one successor path does in its first few instructions: a punish call
 * (exit/kill/log/report), a constant return, or nothing telling. Used to decide
 * which side of a verdict branch is the dirty one.
 */
export function classifyPath(db: AnalysisDatabase, insns: Instruction[], byAddr: Map<number, number>, start: number, maxInsns = 14): { punish: string | null; retConst: number | null; calls: string[]; guard: string | null } {
  const calls: string[] = [];
  let punish: string | null = null;
  let guard: string | null = null;
  let retConst: number | null = null;
  let pendingRet: number | null = null;
  const startIdx = byAddr.get(start);
  if (startIdx === undefined) return { punish, retConst, calls, guard };
  const endIdx = Math.min(insns.length - 1, startIdx + maxInsns);
  for (let k = startIdx; k <= endIdx; k++) {
    const ins = insns[k];
    if (ins.kind === "call" || ins.kind === "indirect-call") {
      let name: string | null = null;
      if (ins.target !== undefined) name = db.callNameFor(ins.target).replace(/@.*$/, "");
      else {
        // adrp + ldr [GOT] + blr: the GOT read xref sits a few instructions before the blr.
        const lo = insns[Math.max(startIdx, k - 4)].address;
        for (const x of db.xrefs.refsFromRange(lo, ins.address + 4)) {
          const g = db.gotNames.get(x.to);
          if (x.kind === 3 && g) { name = g.replace(/@.*$/, ""); break; }
        }
      }
      if (name) {
        calls.push(name);
        if (!guard && GUARD_IMPORT_RE.test(name)) guard = name;
        else if (!punish && PUNISH_IMPORT_RE.test(name)) punish = name;
      }
      pendingRet = null;
      continue;
    }
    if ((ins.kind === "move" || ins.mnemonic === "mov" || ins.mnemonic === "movz") && ins.operands[0]?.reg && /^[wx]0$/.test(ins.operands[0].reg) && ins.operands[1]?.imm !== undefined) pendingRet = ins.operands[1].imm;
    if (ins.kind === "trap") { punish = punish ?? ins.mnemonic; break; }
    if (ins.kind === "ret") { retConst = pendingRet; break; }
    if (ins.kind === "jump" || ins.kind === "indirect-jump") break;
    if (k > startIdx && isCondBranch(ins)) break; // another decision — stop describing this side
  }
  if (!punish && !guard) {
    for (const x of db.xrefs.refsFromRange(start, insns[endIdx].address + 4)) {
      if (x.kind !== 7) continue;
      const s = db.stringAt(x.to);
      if (s && PUNISH_STRING_RE.test(s.value)) { punish = `"${s.value.slice(0, 32)}"`; break; }
    }
  }
  return { punish, retConst, calls, guard };
}

/**
 * Hunt verdict branches inside one function: forward conditional branches with
 * a visible compare feeder and/or a recognisable punish side. Backward branches
 * are loop guards — flipping one rewrites the algorithm, never the verdict — so
 * they are excluded outright.
 */
export function huntVerdictBranches(db: AnalysisDatabase, fnAddr: number): VerdictBranch[] {
  const fn = db.functionByAddr(fnAddr);
  if (!fn || !db.arch) return [];
  const insns = db.decodeFunction(fn, 3000);
  const byAddr = new Map<number, number>();
  insns.forEach((i, idx) => byAddr.set(i.address, idx));
  const out: VerdictBranch[] = [];
  const describe = (label: string, s: ReturnType<typeof classifyPath> | null) =>
    !s ? `${label}: ?` : `${label}: ${s.punish ? `punish via ${s.punish}` : s.retConst !== null ? `returns ${s.retConst}` : s.calls.length ? `calls ${s.calls.slice(0, 2).join(", ")}` : "plain"}`;
  for (let idx = 0; idx < insns.length; idx++) {
    const ins = insns[idx];
    if (!isCondBranch(ins)) continue;
    const target = ins.target;
    if (target !== undefined && target <= ins.address) continue; // loop back-edge
    let feeder: string | null = null;
    let feederDistance = 0;
    if (/^(cbz|cbnz|tbz|tbnz)/.test(ins.mnemonic)) feeder = `${ins.mnemonic} ${ins.opText}`.trim();
    else {
      // Nearest compare feeding it, scanning backwards; a call or another branch in between breaks the chain.
      for (let j = idx - 1; j >= Math.max(0, idx - 8); j--) {
        if (isCompareInsn(insns[j])) { feeder = `${insns[j].mnemonic} ${insns[j].opText}`.trim(); feederDistance = idx - j; break; }
        if (isCondBranch(insns[j]) || insns[j].kind === "call" || insns[j].kind === "indirect-call") break;
      }
    }
    const sideT = target !== undefined ? classifyPath(db, insns, byAddr, target) : null;
    const fall = insns[idx + 1];
    const sideF = fall ? classifyPath(db, insns, byAddr, fall.address) : null;
    // Stack-canary / sanitizer guards: one side is `bl __stack_chk_fail`. Never a verdict — flipping it aborts every clean run.
    if (sideT?.guard || sideF?.guard) continue;
    let dirtySide: VerdictBranch["dirtySide"] = "unknown";
    if (sideT?.punish && !sideF?.punish) dirtySide = "target";
    else if (sideF?.punish && !sideT?.punish) dirtySide = "fallthrough";
    const hasRet = (s: ReturnType<typeof classifyPath> | null) => s !== null && s.retConst !== null;
    const score = (feeder ? 2 : 0) + (dirtySide !== "unknown" ? 4 : 0) + (hasRet(sideT) || hasRet(sideF) ? 1 : 0) + (feeder && /,\s*#0(x0)?\b|xzr|wzr|^cbn?z|^tbn?z/.test(feeder) ? 1 : 0);
    const text = `${ins.mnemonic} ${ins.opText}`.trim() + (target !== undefined ? ` → ${hex(target)}` : "");
    const why = `${feeder ? (feederDistance ? `fed by ${feeder} ${feederDistance} insn(s) earlier` : `self-testing ${feeder.split(" ")[0]}`) : "no compare within 8 insns — computed verdict, confirm live"}; ${describe("taken", sideT)}; ${describe("fall-through", sideF)}${dirtySide !== "unknown" ? ` ⇒ dirty side = ${dirtySide}` : " ⇒ dirty side unclear, confirm live"}`;
    out.push({ addr: ins.address, text, why, flipHint: flipHintFor(ins.mnemonic, dirtySide), dirtySide, score, feeder });
  }
  out.sort((a, b) => b.score - a.score || a.addr - b.addr);
  return out.slice(0, 6);
}

export function flipHintFor(mn: string, dirtySide: VerdictBranch["dirtySide"] = "unknown"): string {
  const side = dirtySide === "target" ? " — after the flip the taken (punish) path is unreachable" : dirtySide === "fallthrough" ? " — after the flip the fall-through (punish) path is skipped" : "";
  if (/^b\.eq$/i.test(mn) || /^cbz$/i.test(mn)) return `flip B.EQ/CBZ → B.NE/CBNZ${side} — confirm bytes live`;
  if (/^b\.ne$/i.test(mn) || /^cbnz$/i.test(mn)) return `flip B.NE/CBNZ → B.EQ/CBZ${side} — confirm bytes live`;
  if (/^tbz$/i.test(mn) || /^tbnz$/i.test(mn)) return `flip TBZ↔TBNZ${side} — confirm bytes live`;
  if (/^b\./i.test(mn)) return `invert ${mn} condition (e.g. B.LT↔B.GE)${side} — confirm bytes live`;
  return `invert branch condition so the punish path is skipped${side} — confirm bytes live`;
}

/**
 * Hunt a caller-side trap: call to target, then a compare/branch on the return
 * value. Anchors on the BRANCH (the flippable word); the compare is only its
 * feeder. Gives up when another call clobbers X0 before any judgement.
 */
export function huntConsumerTrap(db: AnalysisDatabase, callerAddr: number, targetAddr: number): { addr: number; text: string; callSite: number; flipHint: string; feeder: string | null } | null {
  const fn = db.functionByAddr(callerAddr);
  if (!fn || !db.arch) return null;
  const insns = db.decodeFunction(fn, 3000);
  for (let idx = 0; idx < insns.length; idx++) {
    const ins = insns[idx];
    if (!((ins.kind === "call" || ins.kind === "indirect-call") && ins.target === targetAddr)) continue;
    let feeder: string | null = null;
    for (let j = idx + 1; j < Math.min(insns.length, idx + 13); j++) {
      const c = insns[j];
      if (c.kind === "call" || c.kind === "indirect-call" || c.kind === "ret" || c.kind === "jump" || c.kind === "indirect-jump") break;
      if (isCompareInsn(c)) { feeder = `${c.mnemonic} ${c.opText}`.trim(); continue; }
      if (isCondBranch(c)) {
        const text = `${c.mnemonic} ${c.opText}`.trim() + (c.target !== undefined ? ` → ${hex(c.target)}` : "");
        return { addr: c.address, text: feeder ? `${text} (fed by ${feeder})` : text, callSite: ins.address, flipHint: flipHintFor(c.mnemonic), feeder };
      }
    }
  }
  return null;
}

export function cleanReturnFor(f: IntelFinding): string {
  switch (f.kind) {
    case "hash-check": return "0 /* match/clean — confirm against a clean trace first */";
    case "ban-check": return "0 /* no-ban — confirm the clean enum value first */";
    case "anticheat": return "0 /* clean — confirm the clean return shape first */";
    default: return "0 /* confirm clean value first */";
  }
}

/** .got redirect: force an import's return module-wide (arg-agnostic onLeave). Frida 16/17-safe export lookup. */
export function fridaGotRedirect(lib: string, imp: string, clean: string): string {
  const val = clean.split(" ")[0];
  const numeric = /^-?\d+$/.test(val);
  return [
    `// ${imp} — module-wide redirect (.got surface). Affects EVERY caller in ${lib}. Confirm the clean value first.`,
    `{`,
    `  const mod = Process.getModuleByName("${lib}");`,
    `  const p = (typeof mod.findExportByName === "function" ? mod.findExportByName("${imp}") : null) || Module.findExportByName("${lib}", "${imp}") || Module.findExportByName(null, "${imp}");`,
    `  if (!p) throw new Error("${imp} not found — it may be a GOT slot only; stomp the slot pointer instead");`,
    `  Interceptor.attach(p, { onEnter(a) { /* CLEAN RUN FIRST: log real return before forcing */ }, onLeave(r) { ${numeric ? `r.replace(${val});` : `/* non-trivial clean value (${clean}) — set r appropriately, e.g. r.replace(this.len) */`} } });`,
    `}`,
    ``,
  ].join("\n");
}

/** .bss/.data write: force a global flag to the clean value at runtime (no file bytes for .bss). */
export function fridaGlobalWrite(lib: string, name: string, rva: number): string {
  return [
    `// ${name} — force the flag a check reads (.bss/.data surface). Runtime write; read the clean value on a clean run first.`,
    `{`,
    ...moduleLines(lib, rva).map((l) => "  " + l),
    `  console.log("${name} @", addr, "currently", addr.readU32()); // CONFIRM the clean value before forcing`,
    `  addr.writeU32(0); // <-- clean value (guess); re-run to keep it set if a writer resets it`,
    `}`,
    ``,
  ].join("\n");
}

/** Module + address resolution shared by every snippet. `Process.findModuleByName` exists on Frida 12–17. */
function moduleLines(lib: string, rva: number): string[] {
  return [
    `const mod = Process.findModuleByName("${lib}");`,
    `if (!mod) throw new Error("${lib} not loaded yet — attach after it loads, or hook dlopen/android_dlopen_ext");`,
    `const addr = mod.base.add(0x${rva.toString(16).toUpperCase()});`,
  ];
}

/** Entry hook forcing the clean return. Block-scoped so several snippets can be pasted into one script. */
export function fridaHook(lib: string, name: string, rva: number, cleanRet: string): string {
  const cleanVal = cleanRet.split(" ")[0];
  return [
    `// ${name} — hook entry, force clean (validate on a clean trace first!)`,
    `{`,
    ...moduleLines(lib, rva).map((l) => "  " + l),
    `  Interceptor.attach(addr, {`,
    `    onEnter(args) { /* CLEAN RUN FIRST: console.log("${name}", args[0], args[1]); */ },`,
    `    onLeave(retval) { /* log retval.toInt32() on a clean run, then force: */ retval.replace(${cleanVal}); }`,
    `  });`,
    `}`,
    ``,
  ].join("\n");
}

/** In-memory prologue patch that verifies the original words before writing and refuses on mismatch. */
export function fridaPatch(lib: string, name: string, rva: number, pro: ProloguePatch): string {
  if (!pro.ok) return `// ${name} — prologue patch withheld: ${pro.note}. Resolve that first.\n`;
  return [
    `// ${name} — in-memory prologue patch (${pro.asm}). Verifies the original words first; refuses if they differ.`,
    `{`,
    ...moduleLines(lib, rva).map((l) => "  " + l),
    `  const expect = [${pro.origWords.map(hex32).join(", ")}]; // file words at ${lib}+0x${rva.toString(16).toUpperCase()}`,
    `  for (let i = 0; i < expect.length; i++) { const w = addr.add(i * 4).readU32(); if (w !== expect[i]) throw new Error("orig mismatch @+" + i * 4 + ": " + w.toString(16) + " != " + expect[i].toString(16) + " — packed/relocated/already patched, re-derive"); }`,
    `  Memory.patchCode(addr, ${pro.words.length * 4}, (code) => { ${pro.words.map((w, i) => `code.add(${i * 4}).writeU32(${hex32(w)});`).join(" ")} });`,
    `  console.log("patched ${name} @", addr, "→ ${pro.asm}");`,
    `}`,
    ``,
  ].join("\n");
}

/** In-memory branch flip: verifies the original word, writes the inverted one. Comment-only when the flip could not be computed. */
export function fridaBranch(name: string, lib: string, rva: number, insnText: string, flip: { ok: boolean; note: string; origWord: number | null; flippedWord: number | null }): string {
  const at = "0x" + rva.toString(16).toUpperCase();
  if (!flip.ok || flip.origWord === null || flip.flippedWord === null) {
    return [
      `// ${name} — flip branch @ RVA ${at} (${insnText}): exact bytes not computable (${flip.note}).`,
      `// Read the word live (addr.readU32()), invert the condition by hand, and only then Memory.patchCode(addr, 4, c => c.writeU32(flipped)).`,
      ``,
    ].join("\n");
  }
  return [
    `// ${name} — flip verdict branch @ RVA ${at} (${insnText}). Verifies the original word; refuses if it differs.`,
    `{`,
    ...moduleLines(lib, rva).map((l) => "  " + l),
    `  const w = addr.readU32();`,
    `  if (w !== ${hex32(flip.origWord)}) throw new Error("branch word mismatch: " + w.toString(16) + " != ${flip.origWord.toString(16)} — packed/relocated/already flipped, re-derive");`,
    `  Memory.patchCode(addr, 4, (code) => code.writeU32(${hex32(flip.flippedWord)}));`,
    `  console.log("flipped ${name} @", addr);`,
    `}`,
    ``,
  ].join("\n");
}

/** BFS from a sibling export over its callees (≤maxHops) to the nearest function that has a hook-entry step. */
function reachStepFrom(db: AnalysisDatabase, plan: BypassPlan, startAddr: number, maxHops: number): { step: BypassStep; hops: number } | null {
  const stepByAddr = new Map<number, BypassStep>();
  for (const s of plan.steps) if (s.action === "hook-entry" && !stepByAddr.has(s.targetAddr)) stepByAddr.set(s.targetAddr, s);
  if (!stepByAddr.size) return null;
  const start = db.functionByAddr(startAddr);
  if (!start) return null;
  let frontier = [start.addr];
  const seen = new Set<number>([start.addr]);
  for (let hop = 1; hop <= maxHops; hop++) {
    const next: number[] = [];
    for (const a of frontier) {
      const fn = db.functionByAddr(a);
      if (!fn) continue;
      for (const c of db.calleesOf(fn)) {
        const to = c.fn?.addr ?? c.to;
        if (seen.has(to)) continue;
        seen.add(to);
        const hit = stepByAddr.get(to);
        if (hit) return { step: hit, hops: hop };
        if (c.fn) next.push(to);
      }
    }
    if (seen.size > 4000) break;
    frontier = next;
  }
  return null;
}

/**
 * Plan the whole workspace: run the per-lib planner for every loaded library
 * (each sees the shared link graph), then stitch cross-lib strike chains — a
 * caller-lib step and the sibling step that owns the real check it calls into —
 * and emit one apply order that puts the sibling's real check before its caller.
 */
export async function planWorkspace(
  libs: { name: string; db: AnalysisDatabase }[],
  onProgress?: (p: BypassProgress) => void,
  opts: { includeGameRevive?: boolean; scope?: SectionScope } = {},
): Promise<WorkspacePlan> {
  const t0 = performance.now();
  const descriptors = libs.map((l) => libDescriptor(l.db));
  const link = linkLibraries(descriptors);
  const bySoname = new Map<string, { name: string; soname: string; db: AnalysisDatabase; plan: BypassPlan }>();
  const perLib: WorkspacePlan["perLib"] = [];
  for (let i = 0; i < libs.length; i++) {
    const l = libs[i];
    const soname = descriptors[i].soname;
    onProgress?.({ pass: `LIB ${i + 1}/${libs.length}`, passIndex: i + 1, passTotal: libs.length, progress: 0, note: `planning ${soname}` });
    const plan = await planBypass(l.db, (p) => onProgress?.({ ...p, pass: `${soname}: ${p.pass}`, passIndex: i + 1, passTotal: libs.length }), { ...opts, workspace: { descriptors, link } });
    const entry = { name: l.name, soname, db: l.db, plan };
    perLib.push({ name: l.name, soname, plan });
    bySoname.set(soname, entry);
  }

  // Stitch chains from the resolved-symbol map, NOT from caller steps: the
  // cross-lib value is highest exactly when the caller is a thin stub into the
  // SDK and has no step of its own (e.g. an encrypted UE4 hub that only calls
  // TssSDKInit). Provider (the sibling's real check) leads; a caller step is
  // attached when one exists.
  const chains: WorkspaceChain[] = [];
  const stripVer = (n: string) => n.replace(/@.*$/, "");
  const chainSeen = new Set<string>();
  for (const { soname, plan } of perLib) {
    for (const r of plan.crossLib?.securityResolvedElsewhere ?? []) {
      const sib = bySoname.get(r.lib);
      if (!sib) continue;
      const exp = sib.db.elf.exports.find((s) => stripVer(s.name) === r.symbol);
      const provFn = exp ? sib.db.functionAt(exp.value) ?? sib.db.functionByAddr(exp.value) : null;
      // Direct step at the export, else the nearest flagged check reachable from it
      // (the public SDK entry is a thin door; the real check is a hop or two in).
      let provStep = provFn ? sib.plan.steps.find((x) => x.targetAddr === provFn.addr && x.action === "hook-entry") ?? sib.plan.steps.find((x) => x.targetAddr === provFn.addr) : null;
      let hops = 0;
      if (!provStep && provFn) { const reached = reachStepFrom(sib.db, sib.plan, provFn.addr, 2); if (reached) { provStep = reached.step; hops = reached.hops; } }
      const provAddr = provStep?.address ?? provFn?.addr ?? exp?.value ?? 0;
      const key = `${soname}|${r.symbol}|${provAddr}`;
      if (chainSeen.has(key)) continue;
      chainSeen.add(key);
      const callerStep = plan.steps.find((s) => s.crossLib?.some((c) => c.symbol === r.symbol)) ?? plan.steps.find((s) => s.imports.map(stripVer).includes(r.symbol));
      const steps: WorkspaceChain["steps"] = [];
      if (provAddr) steps.push({ lib: r.lib, stepId: provStep?.id ?? "", title: provStep ? provStep.title : `${r.symbol} @ ${sib.db.nameFor(provAddr).name} (no flagged step — inspect)`, addr: provAddr, role: "provider" });
      if (callerStep) steps.push({ lib: soname, stepId: callerStep.id, title: callerStep.title, addr: callerStep.address, role: "caller" });
      if (!steps.length) continue;
      chains.push({
        symbol: r.symbol,
        reason: provStep
          ? `${soname} calls ${r.symbol} → the real check is ${provStep.title} in ${r.lib}${hops ? ` (${hops} hop(s) in from the ${r.symbol} entry)` : ""}. Apply the sibling step first${callerStep ? ", then the caller step here" : " (this hub only calls in — no local step needed)"}.`
          : `${soname} is a thin caller of ${r.symbol} → the real anti-cheat lives in ${r.lib} (entry at ${hex(provAddr)}), reached through internal/indirect dispatch that static tracing can't cross. Don't hook here — focus ${r.lib} and apply its own steps (front-loaded in the apply order below), or hook the ${r.symbol} import.`,
        steps,
        hasProviderStep: !!provStep,
      });
    }
  }
  chains.sort((a, b) => (b.hasProviderStep ? 1 : 0) - (a.hasProviderStep ? 1 : 0) || a.symbol.localeCompare(b.symbol));

  // Apply order: unique providers first (real checks), then callers, then the
  // rest of each lib's SAFE hook-entry steps.
  const order: WorkspacePlan["order"] = [];
  const seen = new Set<string>();
  const push = (lib: string, s: { stepId: string; title: string; addr: number }) => { const k = `${lib}::${s.stepId}`; if (!seen.has(k)) { seen.add(k); order.push({ lib, stepId: s.stepId, title: s.title, addr: s.addr }); } };
  for (const c of chains) for (const s of c.steps) if (s.role === "provider" && s.stepId) push(s.lib, s);
  for (const c of chains) for (const s of c.steps) if (s.role === "caller" && s.stepId) push(s.lib, s);
  for (const { soname, plan } of perLib) for (const s of plan.steps) if (s.action === "hook-entry" && s.safety === "SAFE") push(soname, { stepId: s.id, title: s.title, addr: s.address });

  const steps = perLib.reduce((a, l) => a + l.plan.steps.length, 0);
  const safeSteps = perLib.reduce((a, l) => a + l.plan.steps.filter((s) => s.safety === "SAFE").length, 0);
  const mrpc = perLib.reduce((a, l) => a + l.plan.mrpc.count, 0);
  return {
    perLib,
    chains,
    order,
    summary: { libs: libs.length, steps, safeSteps, chains: chains.length, mrpc, providersMissing: chains.filter((c) => !c.hasProviderStep).length },
    durationMs: performance.now() - t0,
  };
}
