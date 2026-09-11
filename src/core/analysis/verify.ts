import type { AnalysisDatabase } from "./database";
import type { Instruction } from "../architecture/types";
import { decodeRange } from "../architecture/registry";
import { buildIntel, type IntelSummary } from "./intel";
import { branchFlipLib, isHeartbeat, prologuePatchLib, selfInspectionHit } from "./bypass";

export interface PastedItem {
  raw: string;
  kind: "patch" | "hook";
  lib: string;
  rva: number;
  /** New bytes as upper-case hex without separators (patch) or "" (hook). */
  bytes: string;
  hookName?: string;
  /** Syntax the line used: PATCH_LIB, PATCH_SWITCH, KittyMemory, HOOK_LIB, pair, bare… */
  format: string;
}

export interface VerifyCheck {
  label: string;
  pass: boolean;
  detail: string;
}

export interface ItemVerdict {
  item: PastedItem;
  status: "SAFE" | "RISKY" | "UNSAFE";
  addr: number | null;
  funcName: string | null;
  funcKind: string | null;
  funcImports: string[];
  checks: VerifyCheck[];
  /** Concrete steps that would make this safe. */
  fixes: string[];
  /** Corrected line when the paste had a fixable mistake (wrong bytes/lib). */
  fixedLine: string | null;
}

export interface VerifyReport {
  items: ItemVerdict[];
  overall: "SAFE" | "RISKY" | "UNSAFE" | "EMPTY";
  warnings: string[];
}

const hex = (n: number) => "0x" + n.toString(16);
const spacedHex = (h: string) => (h.match(/../g) ?? []).join(" ");
const spaced = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0").toUpperCase()).join(" ");

/**
 * Accept the common mod-menu spellings:
 *   PATCH_LIB / PATCH_LIB_SWITCH / PATCH_SWITCH("lib","0xOFF","BYTES")
 *   MemoryPatch::createWithHex("lib", 0xOFF, "BYTES")            (KittyMemory)
 *   HOOK_LIB / HOOK_LIB_SWITCH("lib","0xOFF",(void*)hook,(void**)&orig)
 *   { "0xOFF", "BYTES" },                                          (table rows)
 *   0xOFF: BYTES                                                   (bare)
 */
export function parsePatchLines(text: string): { items: PastedItem[]; errors: string[] } {
  const items: PastedItem[] = [];
  const errors: string[] = [];
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("//") && !l.startsWith("#"));
  if (!lines.length) return { items, errors: ["Nothing to parse — paste PATCH_LIB / HOOK_LIB lines first."] };
  const pushPatch = (line: string, lib: string, off: string, bytesRaw: string, format: string) => {
    const rva = parseRva(off);
    if (rva === null) { errors.push(`Bad offset ${off} in: ${line.slice(0, 80)}`); return; }
    const bytes = bytesRaw.replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "").toUpperCase();
    if (!bytes.length || bytes.length % 2) { errors.push(`Bad hex bytes in: ${line.slice(0, 80)}`); return; }
    items.push({ raw: line, kind: "patch", lib, rva, bytes, format });
  };
  for (const line of lines) {
    const mPatch = line.match(/\b(PATCH_LIB_SWITCH|PATCH_LIB|PATCH_SWITCH|PATCH)\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"/i);
    if (mPatch) { pushPatch(line, mPatch[2], mPatch[3], mPatch[4], mPatch[1].toUpperCase()); continue; }
    const mKitty = line.match(/createWithHex\s*\(\s*"([^"]+)"\s*,\s*"?(0x[0-9a-fA-F]+|[0-9a-fA-F]+)"?\s*,\s*"([^"]+)"/i);
    if (mKitty) { pushPatch(line, mKitty[1], mKitty[2], mKitty[3], "KittyMemory"); continue; }
    const mHook = line.match(/\b(HOOK_LIB_SWITCH|HOOK_LIB|HOOK_SWITCH|HOOK)\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*(?:\(\s*void\s*\*\s*\)\s*)?&?\s*([A-Za-z_][A-Za-z0-9_]*)?/i);
    if (mHook) {
      const rva = parseRva(mHook[3]);
      if (rva === null) { errors.push(`Bad offset ${mHook[3]} in: ${line.slice(0, 80)}`); continue; }
      items.push({ raw: line, kind: "hook", lib: mHook[2], rva, bytes: "", hookName: mHook[4] || undefined, format: mHook[1].toUpperCase() });
      continue;
    }
    const mPair = line.match(/^\{?\s*"(0x[0-9a-fA-F]+|[0-9a-fA-F]{4,})"\s*,\s*"([0-9a-fA-F][0-9a-fA-F\s]*)"\s*\}?\s*,?$/);
    if (mPair) { pushPatch(line, "", mPair[1], mPair[2], "pair"); continue; }
    const mBare = line.match(/^(0x[0-9a-fA-F]+|[0-9a-fA-F]{4,})\s*[:\s]\s*([0-9a-fA-F][0-9a-fA-F\s]+)$/);
    if (mBare) { pushPatch(line, "", mBare[1], mBare[2], "bare"); continue; }
    errors.push(`Unrecognised line (want PATCH_LIB("lib.so","0xOFF","BYTES"), HOOK_LIB("lib.so","0xOFF",…), MemoryPatch::createWithHex("lib.so", 0xOFF, "BYTES") or 0xOFF: BYTES): ${line.slice(0, 80)}`);
  }
  return { items, errors };
}

function parseRva(s: string): number | null {
  const t = s.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{1,16}$/.test(t)) return null;
  const v = parseInt(t, 16);
  return Number.isSafeInteger(v) ? v : null;
}

/**
 * Autopsy for pasted hooks/patches: resolves every line against the loaded
 * binary, decodes the new bytes, checks arch/boundaries/landing pads, measures
 * blast radius, hunts the backup checks that would survive it, checks the
 * lines against each other (overlaps, hook/patch collisions) and prescribes
 * fixes. Deterministic — it reads the database, never guesses.
 */
export function analyzePasted(db: AnalysisDatabase, text: string): VerifyReport {
  const { items, errors } = parsePatchLines(text);
  const warnings = [...errors];
  if (!items.length) return { items: [], overall: "EMPTY", warnings };
  const intel = buildIntel(db, 15);
  const base = db.space.imageBase ?? 0;
  const ownLib = (db.elf.soname ?? db.fileName).toLowerCase();
  const verdicts = items.map((item) => autopsyOne(db, intel, item, base, ownLib));
  crossCheck(verdicts);
  const rank = { SAFE: 0, RISKY: 1, UNSAFE: 2 } as const;
  const worst = verdicts.reduce((a, v) => (rank[v.status] > rank[a] ? v.status : a), "SAFE" as ItemVerdict["status"]);
  if (intel.packedSuspect) warnings.push("Packed/encrypted code suspected — file bytes may not match runtime; re-read every site live before writing.");
  warnings.push("Lab-only verdicts: static checks can't see server-side state or runtime-decrypted code. Validate on a test account.");
  return { items: verdicts, overall: worst, warnings };
}

/** Known byte templates (upper-case hex, optional BTI JC prefix). */
const TEMPLATES: [RegExp, string][] = [
  [/^(9F2403D5)?000080D2C0035FD6$/, "MOV X0,#0; RET — return 0"],
  [/^(9F2403D5)?200080D2C0035FD6$/, "MOV X0,#1; RET — return 1"],
  [/^(9F2403D5)?00008052C0035FD6$/, "MOV W0,#0; RET — return 0 (32-bit)"],
  [/^(9F2403D5)?20008052C0035FD6$/, "MOV W0,#1; RET — return 1 (32-bit)"],
  [/^C0035FD6$/, "RET — return with X0 untouched"],
  [/^(1F2003D5)+$/, "NOP sled"],
  [/^0000A0E31EFF2FE1$/, "MOV R0,#0; BX LR — return 0 (ARM)"],
  [/^0100A0E31EFF2FE1$/, "MOV R0,#1; BX LR — return 1 (ARM)"],
  [/^1EFF2FE1$/, "BX LR — return with R0 untouched (ARM)"],
  [/^(00F020E3)+$/, "NOP sled (ARM)"],
];
/** Words that are valid BTI landing pads (LE hex): BTI JC / C / J / plain, PACIASP, PACIBSP. */
const LANDING_WORDS = /^(9F2403D5|5F2403D5|3F2403D5|1F2403D5|3F2303D5|7F2303D5)/;

function describeBytes(db: AnalysisDatabase, va: number, hexBytes: string): { asm: string; pcRelative: string[]; template: string | null; insns: Instruction[] } {
  const template = TEMPLATES.find(([re]) => re.test(hexBytes))?.[1] ?? null;
  if (!db.arch) return { asm: "", pcRelative: [], template, insns: [] };
  const bytes = new Uint8Array((hexBytes.match(/../g) ?? []).map((h) => parseInt(h, 16)));
  const insns = decodeRange(db.arch, bytes, 0, va, bytes.length, db.elf.header.littleEndian, 64);
  const asm = insns.map((i) => `${i.mnemonic} ${i.opText}`.trim()).join("; ");
  const pcRelative = insns.filter((i) => i.target !== undefined || i.kind === "adr").map((i) => `${i.mnemonic} ${i.opText}`.trim());
  return { asm, pcRelative, template, insns };
}

function autopsyOne(db: AnalysisDatabase, intel: IntelSummary, item: PastedItem, base: number, ownLib: string): ItemVerdict {
  const checks: VerifyCheck[] = [];
  const fixes: string[] = [];
  let status: ItemVerdict["status"] = "SAFE";
  const down = (to: ItemVerdict["status"]) => { if (to === "UNSAFE") status = "UNSAFE"; else if (status === "SAFE") status = "RISKY"; };
  // 1. library
  const libOk = !item.lib || ownLib.includes(item.lib.toLowerCase()) || item.lib.toLowerCase().includes(ownLib.split(".")[0]);
  checks.push({ label: "Library", pass: libOk, detail: item.lib ? (libOk ? `"${item.lib}" matches loaded ${db.elf.soname ?? db.fileName}` : `"${item.lib}" does NOT match loaded ${db.elf.soname ?? db.fileName} — offset means something else there`) : "no lib given — assumed loaded binary" });
  if (!libOk) { down("UNSAFE"); fixes.push(`Retarget to "${db.elf.soname ?? db.fileName}" or load the matching library first — as pasted it patches the wrong module.`); }
  // 2. mapping
  const va = base + item.rva;
  const mapped = db.space.isMapped(va);
  const exec = mapped && db.space.isExec(va);
  checks.push({ label: "Address", pass: mapped, detail: mapped ? `${hex(va)} is mapped${exec ? " (executable)" : " (NOT executable — data?)"}` : `${hex(va)} is not mapped in this binary — wrong base, wrong lib, or ASLR confusion (offsets here are base+0x${item.rva.toString(16).toUpperCase()})` });
  if (!mapped) { down("UNSAFE"); fixes.push(`Resolve the address first: base+0x${item.rva.toString(16).toUpperCase()} lands unmapped. Confirm the module base at runtime (Frida Process.findModuleByName(...).base) and re-derive the RVA.`); }
  if (mapped && !exec && item.kind === "patch") { down("RISKY"); fixes.push("Target isn't executable memory — if you meant code, the offset is wrong; if you meant data, say so and re-check what reads it."); }
  // 3. function context
  const fn = mapped ? db.functionAt(va) ?? db.functionByAddr(va) : null;
  const funcName = fn ? db.nameFor(fn.addr).name : null;
  const intelHit = fn ? intel.findings.find((f) => f.addr === fn.addr) : null;
  const funcKind = intelHit?.kind ?? fn?.classes?.[0]?.label ?? null;
  const funcImports = fn ? db.importCallsOf(fn).slice(0, 5) : [];
  checks.push({ label: "Function", pass: !!fn, detail: fn ? `inside ${funcName} @ ${hex(fn.addr)}${va !== fn.addr ? `+0x${(va - fn.addr).toString(16)}` : ""}${funcKind ? ` [${funcKind}]` : ""}${funcImports.length ? ` — calls ${funcImports.slice(0, 3).join(", ")}` : ""}` : "not inside any known function — mid-gap, padding, or data" });
  if (!fn && mapped) { down("RISKY"); fixes.push("No function owns this address — disassemble around it (Hex view) and confirm it's really code before writing."); }
  // 4. bytes / encoding (patches only)
  let fixedLine: string | null = null;
  if (item.kind === "patch" && mapped) {
    const nBytes = item.bytes.length / 2;
    const archId = db.arch?.id;
    if ((archId === "arm64" && nBytes % 4 !== 0) || (archId === "arm32" && nBytes % 2 !== 0)) {
      checks.push({ label: "Encoding", pass: false, detail: `${nBytes} bytes is not a multiple of ${archId === "arm64" ? 4 : 2} — ${archId === "arm64" ? "ARM64 instructions are 4 bytes" : "ARM/Thumb instructions are 4/2 bytes"}; this splits an instruction` });
      down("UNSAFE"); fixes.push(`Resize to whole instructions (multiples of ${archId === "arm64" ? 4 : 2}) or the CPU faults / slides into garbage.`);
    } else {
      if (archId === "arm32" && nBytes % 4 !== 0) checks.push({ label: "Encoding", pass: true, detail: `${nBytes} bytes — only valid for Thumb-2 (2/4-byte) code; this analyzer decodes ARM mode, so confirm the site really is Thumb` });
      const cover = coversWholeInstructions(db, va, nBytes);
      checks.push({ label: "Boundary", pass: cover.ok, detail: cover.detail });
      if (!cover.ok) { down("UNSAFE"); fixes.push(cover.fix); }
      // What the new bytes actually are.
      const desc = describeBytes(db, va, item.bytes);
      const decodable = desc.insns.length > 0 && !desc.insns.some((i) => i.kind === "unknown");
      checks.push({ label: "Bytes mean", pass: decodable, detail: desc.template ? `${desc.template} (${desc.asm})` : desc.asm ? (decodable ? `decodes as: ${desc.asm}` : `only partly decodes: ${desc.asm} — data patch, or wrong arch`) : "does not decode as instructions — data patch?" });
      // Branch-flip exactness for 4-byte patches on a branch site.
      let isComputedFlip = false;
      if (nBytes === 4 && (archId === "arm64" || archId === "arm32")) {
        const flip = branchFlipLib(db, va);
        if (flip.ok) {
          isComputedFlip = flip.line.includes(`"${spacedHex(item.bytes)}"`);
          checks.push({ label: "Branch flip", pass: isComputedFlip, detail: isComputedFlip ? `bytes exactly invert this branch (orig ${flip.orig}) — surgical` : `site is a flippable branch but your bytes differ from the computed flip; computed ${flip.line.match(/"([0-9A-F ]+)"\)/)?.[1] ?? "?"} from orig ${flip.orig}` });
          if (!isComputedFlip) { down("RISKY"); fixedLine = flip.line; fixes.push(`Use the computed flip instead: ${flip.line} — yours writes a different word to a live branch.`); }
        }
      }
      // PC-relative bytes copied from elsewhere encode the wrong offset here.
      if (desc.pcRelative.length && !isComputedFlip) {
        down("RISKY");
        checks.push({ label: "Position", pass: false, detail: `${desc.pcRelative.length} PC-relative instruction(s) in the new bytes (${desc.pcRelative.slice(0, 2).join("; ")}) — the encoded offset is relative to THIS address; bytes copied from another offset or build land somewhere else` });
        fixes.push("Re-encode the branch/ADRP for this exact address (or use the planner's computed flip line) instead of pasting bytes from elsewhere.");
      }
      // Original bytes: echo for live re-check, and catch no-op patches.
      const orig = db.readBytes(va, nBytes);
      if (orig.length) checks.push({ label: "Originals", pass: true, detail: `file bytes now: ${spaced(orig.subarray(0, 16))}${orig.length > 16 ? " …" : ""} — re-read live before writing` });
      if (orig.length === nBytes && spaced(orig) === spacedHex(item.bytes)) { down("RISKY"); checks.push({ label: "No-op", pass: false, detail: "new bytes equal the file bytes — this patch changes nothing (already-patched build, or wrong offset)" }); }
      // Landing pad: overwriting BTI/PACIASP at an entry breaks indirect callers on BTI-enforcing builds.
      if (fn && fn.addr === va && db.arch?.id === "arm64") {
        const first = db.decodeAt(va, 4, 1)[0];
        if (first && /^(bti|paciasp|pacibsp)$/.test(first.mnemonic) && !LANDING_WORDS.test(item.bytes)) {
          down("RISKY");
          checks.push({ label: "Landing pad", pass: false, detail: `entry starts with ${first.mnemonic} (a BTI/PAC landing pad); your bytes drop it — indirect callers SIGILL on BTI-enforcing builds` });
          const pro = prologuePatchLib(db, va);
          if (pro.ok && desc.template?.startsWith("MOV X0,#0")) { fixedLine = pro.line; fixes.push(`Keep the landing pad: ${pro.line}`); }
          else fixes.push("Start the patch with BTI JC (9F 24 03 D5) and shift your bytes by one word, or patch after the landing pad (+4).");
        }
      }
    }
  }
  // 5. hooks: entry vs mid-function, trampoline room, prologue relocation
  if (item.kind === "hook") {
    const atEntry = !!fn && fn.addr === va;
    checks.push({ label: "Hook point", pass: atEntry, detail: atEntry ? `entry of ${funcName} — reversible, original restorable` : fn ? `mid-function (${funcName}+0x${(va - fn.addr).toString(16)}) — inline hooks (HOOK_LIB/Dobby/Substrate) relocate the first instructions and expect a function entry; only Frida Interceptor.attach tolerates an instruction address` : "no function here — hooking mid-instruction/data crashes; move to a function entry" });
    if (!fn) down("UNSAFE");
    else if (!atEntry) { down("RISKY"); fixes.push(`Move the hook to the function entry ${hex(fn.addr)} (RVA 0x${(fn.addr - base).toString(16).toUpperCase()}), or use a branch patch at this exact instruction instead.`); }
    if (fn && atEntry && db.arch) {
      const head = db.decodeAt(fn.addr, 16, 4);
      const rel = head.filter((i) => i.target !== undefined || i.kind === "adr" || i.kind === "ret" || i.kind === "jump" || i.kind === "condjump");
      checks.push({ label: "Prologue", pass: true, detail: `${head.map((i) => i.mnemonic).join(" · ")}${rel.length ? ` — ${rel.length} PC-relative/flow insn(s) in the first 16 bytes: your hook framework must relocate them (Dobby/And64InlineHook do, raw trampolines don't)` : " — plain, trampoline-safe"}` });
      if (fn.size < 16) { down("RISKY"); checks.push({ label: "Room", pass: false, detail: `${funcName} is only ${fn.size} bytes — an inline trampoline needs ~16` }); fixes.push(`Hook the caller of ${funcName} or use Frida Interceptor (no trampoline) instead.`); }
    }
  }
  // 6. blast radius + behaviour (when inside a function)
  if (fn) {
    const callers = db.callersOf(fn).length;
    const imports = db.importCallsOf(fn);
    const hb = isHeartbeat({ hasLoop: !!fn.features?.hasLoop }, imports);
    checks.push({ label: "Blast radius", pass: callers < 20, detail: `${callers} caller(s)${imports.length ? `, ${imports.length} imports` : ""} — ${callers >= 20 ? "wide: change ripples everywhere" : "narrow"}` });
    if (callers >= 20) { down("RISKY"); fixes.push(`Narrow it: hook the inner security import instead of the whole ${funcName} entry — ${callers} callers inherit an entry hook.`); }
    if (hb) { down("RISKY"); checks.push({ label: "Heartbeat", pass: false, detail: "timing API + loop — re-fires on a timer; one-shot patches die" }); fixes.push("Keep the hook resident (Frida, always-on) and soak-test ≥10 minutes; a file patch alone gets re-checked."); }
    else checks.push({ label: "Heartbeat", pass: true, detail: "no timer pattern — one-shot interception can hold" });
    const strVals = (fn.features?.stringRefs ?? []).map((a) => db.stringAt(a)?.value ?? "");
    const trip = selfInspectionHit(strVals, imports);
    if (trip) { down("RISKY"); checks.push({ label: "Tripwire", pass: false, detail: `self-inspection (${trip}) — crude hooks/GOT stomps can trip it` }); fixes.push(`Blind the self-probe first (${trip}), keep hooks stealthy (no GOT stomps), and re-run the probe path after hooking.`); }
    else checks.push({ label: "Tripwire", pass: true, detail: "no self-inspection markers in this routine" });
    // 7. survivors: checks that share this routine's security strings, or its imports within the same kind.
    const myStrs = new Set(fn.features?.stringRefs ?? []);
    const myImps = new Set(imports.map((n) => n.replace(/@.*$/, "")));
    const sibs = intel.findings
      .filter((f) => f.addr !== fn.addr && (f.connectedTo.some((c) => c.role === "string" && myStrs.has(c.addr)) || (!!intelHit && f.kind === intelHit.kind && f.connectedTo.some((c) => c.role === "import" && myImps.has(c.name.replace(/@.*$/, ""))))))
      .slice(0, 3);
    if (sibs.length) {
      checks.push({ label: "Survivors", pass: false, detail: `${sibs.length} sibling check(s) share this routine's strings/imports: ${sibs.map((s) => `${s.name}@${hex(s.addr)}`).join(", ")}` });
      down("RISKY");
      fixes.push(`Alone this is NOT enough — companion-hook ${sibs.map((s) => `${s.name}@${hex(s.addr)}`).join(", ")}. One twin left live re-arms the whole thing.`);
    } else checks.push({ label: "Survivors", pass: true, detail: "no sibling sharing strings/imports found — still re-test after updates" });
    const callersTrap = db.callersOf(fn).slice(0, 6).map((c) => c.fn).filter((x): x is NonNullable<typeof x> => !!x).filter((cf) => (cf.features?.branchCount ?? 0) >= 2).slice(0, 2);
    if (callersTrap.length) {
      checks.push({ label: "Consumer traps", pass: false, detail: `${callersTrap.map((c) => db.nameFor(c.addr).name).join(", ")} branch heavily — may test this return value` });
      down("RISKY");
      fixes.push(`After applying, break on ${callersTrap.map((c) => db.nameFor(c.addr).name + "@" + hex(c.addr)).join(", ")} and confirm the dirty path stays dead — flip the consumer branch if it re-fires.`);
    } else checks.push({ label: "Consumer traps", pass: true, detail: "no branchy caller looks like a return-value judge" });
    if (intelHit) checks.push({ label: "Intel", pass: intelHit.proofLevel !== "lead", detail: `${intelHit.kind} · ${intelHit.proofLevel.toUpperCase()} · ${Math.round(intelHit.confidence * 100)}% (${intelHit.legs.join(" + ")})` });
  }
  return { item, status: mapped ? status : "UNSAFE", addr: mapped ? va : null, funcName, funcKind, funcImports, checks, fixes, fixedLine };
}

/** Lines against each other: overlapping writes, hook/patch collisions on one entry, duplicate hooks. */
function crossCheck(verdicts: ItemVerdict[]) {
  const down = (v: ItemVerdict) => { if (v.status === "SAFE") v.status = "RISKY"; };
  const patches = verdicts.filter((v) => v.item.kind === "patch" && v.addr !== null);
  for (let i = 0; i < patches.length; i++) {
    for (let j = i + 1; j < patches.length; j++) {
      const a = patches[i], b = patches[j];
      const aEnd = a.addr! + a.item.bytes.length / 2, bEnd = b.addr! + b.item.bytes.length / 2;
      if (a.addr! < bEnd && b.addr! < aEnd) {
        for (const v of [a, b]) {
          down(v);
          v.checks.push({ label: "Overlap", pass: false, detail: `overlaps another pasted patch (${(v === a ? b : a).item.raw.slice(0, 50)}) — whichever applies last wins, the other is silently undone` });
          v.fixes.push("Merge overlapping patches into one byte string, or drop one of them.");
        }
      }
    }
  }
  const hooks = verdicts.filter((v) => v.item.kind === "hook" && v.addr !== null);
  for (const h of hooks) {
    for (const p of patches) {
      if (p.addr! >= h.addr! && p.addr! < h.addr! + 16) {
        for (const v of [h, p]) {
          down(v);
          v.checks.push({ label: "Collision", pass: false, detail: `${v === h ? "a patch" : "a hook"} targets the same entry (${(v === h ? p : h).item.raw.slice(0, 50)}) — an inline hook writes a trampoline over the first ~16 bytes; a patch there fights it` });
          v.fixes.push("Pick one per entry: hook it OR patch it. The planner emits both as alternatives, not as a pair.");
        }
      }
    }
  }
  const seen = new Map<number, ItemVerdict>();
  for (const h of hooks) {
    if (seen.has(h.addr!)) { down(h); h.checks.push({ label: "Duplicate", pass: false, detail: "second hook on the same entry — stacked trampolines corrupt each other" }); h.fixes.push("Keep one hook per entry."); }
    else seen.set(h.addr!, h);
  }
}

function coversWholeInstructions(db: AnalysisDatabase, va: number, nBytes: number): { ok: boolean; detail: string; fix: string } {
  const fn = db.functionAt(va) ?? db.functionByAddr(va);
  if (!fn || !db.arch) return { ok: true, detail: "no decode context — boundary unchecked, confirm live", fix: "Disassemble the site and confirm the write covers whole instructions." };
  // Decode from the function start up to just past the write, however deep it sits.
  const insns = db.decodeAt(fn.addr, va + nBytes - fn.addr + 32, 200_000);
  let covered = 0;
  let first = true;
  for (const ins of insns) {
    if (ins.address + ins.size <= va) continue;
    if (ins.address > va && first) return { ok: false, detail: `write starts mid-instruction (nearest insn @ ${hex(ins.address)})`, fix: "Move the patch start to the instruction start or extend to cover whole instructions." };
    first = false;
    if (ins.address >= va + nBytes) break;
    if (ins.address < va || ins.address + ins.size > va + nBytes) return { ok: false, detail: `write clips ${ins.mnemonic} @ ${hex(ins.address)} (ends ${hex(ins.address + ins.size)}, write ends ${hex(va + nBytes)})`, fix: "Extend or shrink the byte string so every touched instruction is fully covered." };
    covered += ins.size;
    if (covered >= nBytes) break;
  }
  if (!covered) return { ok: false, detail: "no decodable instructions under the write — data or packed code?", fix: "Confirm the site really is code (disassemble + breakpoint) before writing." };
  return { ok: true, detail: `covers ${covered} byte(s) of whole instructions`, fix: "" };
}
