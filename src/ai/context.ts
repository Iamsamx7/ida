import type { AnalysisDatabase } from "../core/analysis/database";
import { buildIntel, emuSweep } from "../core/analysis/intel";
import { packFunction } from "./retrieval";
import type { AssistantAnswer } from "./assistant";
import { buildControlFlow } from "../core/analysis/controlFlow";

/**
 * Renders the structured context the LLM receives as compact plaintext —
 * chosen by what the question was about, not by what happens to be under the
 * cursor. A whole-binary question ("where is anticheat?") gets the verified
 * intel; a function question gets that function's pack; import/library
 * questions get the import map. The local engine's verification block always
 * rides along so the model stays grounded in checked claims.
 *
 * Plaintext beats JSON here: half the tokens, and truncation cuts whole lines
 * instead of leaving unbalanced braces.
 */
export const CONTEXT_CHAR_CAP = 48_000;

const SECURITY_INTENTS = new Set<AssistantAnswer["intent"]>(["anticheat", "ban", "hash", "bypass", "overview", "agent"]);
const LIBRARY_INTENTS = new Set<AssistantAnswer["intent"]>(["libraries", "imports"]);
const LIST_INTENTS = new Set<AssistantAnswer["intent"]>(["semantic-search", "search", "string-uses", "global-access", "similar"]);

interface Section {
  title: string;
  lines: string[];
  /** Lines may be dropped from the end when the whole context is over the cap. */
  shrinkable?: boolean;
}

const hex = (n: number) => "0x" + n.toString(16);

export function buildLlmContext(db: AnalysisDatabase, answer: AssistantAnswer, currentAddr: number | null, cap = CONTEXT_CHAR_CAP): string {
  const sections: Section[] = [];
  const st = db.stats();
  const packed = db.insnTotal > 1000 && db.unknownTotal / Math.max(1, db.insnTotal) > 0.25;
  sections.push({
    title: "BINARY",
    lines: [
      `${db.fileName} · ${db.arch?.displayName ?? db.elf.header.machineName} · ${st.functions} functions · ${st.strings} strings · ${st.imports} imports · ${st.exports} exports · ${st.xrefs} xrefs${db.elf.stripped ? " · stripped" : ""}${db.elf.soname ? ` · SONAME ${db.elf.soname}` : ""}`,
      `Needed libraries: ${db.elf.needed.join(", ") || "none"}`,
      ...(packed ? [`PACKED/ENCRYPTED SUSPECT: ${Math.round((db.unknownTotal / db.insnTotal) * 100)}% of executable bytes do not decode — file addresses may not match runtime; absence of findings proves nothing.`] : []),
    ],
  });

  // Function under discussion: the answer's target, else the cursor for function-ish intents.
  const targetAddr = answer.targetAddr ?? (currentAddr !== null && !SECURITY_INTENTS.has(answer.intent) && !LIBRARY_INTENTS.has(answer.intent) ? db.functionAt(currentAddr)?.addr : undefined);
  const fn = targetAddr !== undefined ? db.functionByAddr(targetAddr) : null;
  if (fn) {
    const p = packFunction(db, fn, 160);
    const flow = buildControlFlow(db.decodeFunction(fn, 12000));
    const head: string[] = [
      `${p.name} @ ${hex(p.addr)} · ${p.size} bytes · name source ${p.nameSource}${p.userName ? ` (user name ${p.userName})` : ""} · discovered via ${p.sources.join("+")} · discovery confidence ${Math.round(p.confidence * 100)}%`,
      `Summary: ${p.featuresSummary}`,
      `Static control flow (up to 12000 instructions): ${flow.blocks.length} basic blocks; ${flow.edges.length} edges; ${flow.unresolved} unresolved or external exits. Indirect jumps and unknown instructions are not resolved; static reachability is not proof of runtime reachability.`,
    ];
    if (p.tags.length) head.push(`Tags: ${p.tags.map((t) => "#" + t).join(" ")}`);
    if (p.comments.length) head.push(...p.comments.slice(0, 6).map((c) => `Comment @ ${hex(c.addr)}: ${c.body.slice(0, 200)}`));
    if (p.classes.length) {
      head.push("Classification (rule engine; label = hypothesis, evidence = facts/inferences):");
      for (const c of p.classes.slice(0, 4)) {
        head.push(`  ${c.label} ${Math.round(c.confidence * 100)}% (${c.level})`);
        for (const e of c.evidence.slice(0, 4)) head.push(`    - [${e.certainty}] ${e.text}${e.address !== undefined ? ` @ ${hex(e.address)}` : ""}`);
      }
    } else head.push("Classification: none fired.");
    const imports = db.importCallsOf(fn);
    if (imports.length) head.push(`Imports called (${imports.length}): ${imports.slice(0, 24).map((n) => `${n} [${db.importLibraryOf(n)}]`).join(", ")}`);
    head.push(`Callers (${p.callers.length}): ${p.callers.slice(0, 16).map((c) => `${c.name} @ ${hex(c.from)}`).join(", ") || "none found"}`);
    head.push(`Callees (${p.callees.length}): ${p.callees.slice(0, 16).map((c) => `${c.name} @ ${hex(c.addr)}`).join(", ") || "none (leaf or indirect only)"}`);
    if (p.strings.length) head.push(`Strings referenced (${p.strings.length}): ${p.strings.slice(0, 16).map((s) => `"${s.value.slice(0, 60)}" @ ${hex(s.addr)} [${s.category}]`).join(" · ")}`);
    if (p.globals.length) head.push(`Globals: ${p.globals.slice(0, 12).map((g) => `${g.name} (${g.kind}) @ ${hex(g.addr)}`).join(", ")}`);
    sections.push({ title: "FUNCTION", lines: head });
    sections.push({ title: "PSEUDOCODE (reconstructed, not source)", lines: p.pseudocode.slice(0, 120), shrinkable: true });
    sections.push({ title: `DISASSEMBLY (first ${Math.min(p.disassembly.length, 160)} of ${fn.insnCount || "?"} instructions)`, lines: p.disassembly.map((d) => `${hex(d.addr)}  ${d.text}`), shrinkable: true });
  }

  if (SECURITY_INTENTS.has(answer.intent) || (!fn && answer.intent === "general")) {
    const intel = buildIntel(db, 12);
    const lines: string[] = [`${intel.findings.length} finding(s), ${intel.provenCount} proven. PROVEN = two independent semantic witnesses (strings + imports/constants); CORROBORATED = one; LEAD = classification + shape only.`];
    for (const f of intel.findings.slice(0, 12)) {
      lines.push(`■ ${f.name} @ ${hex(f.addr)} · ${f.kind} · ${f.proofLevel.toUpperCase()} ${Math.round(f.confidence * 100)}% · legs: ${f.legs.join(" + ")}`);
      lines.push(`  is: ${f.whatItIs}`);
      lines.push(`  does: ${f.whatItDoes}`);
      const conns = f.connectedTo.slice(0, 6).map((c) => `[${c.role}] ${c.name} @ ${hex(c.addr)} (${c.note})`);
      if (conns.length) lines.push(`  connected: ${conns.join(" · ")}`);
      for (const e of f.evidence.slice(0, 4)) lines.push(`  - ${e.text}${e.address !== undefined ? ` @ ${hex(e.address)}` : ""}`);
    }
    const sw = emuSweep(db);
    lines.push(`Emulator sweep: ${sw.markers} marker string(s), ${sw.propReaders} classified prop/file reader(s), ${sw.anticheatFindings} anticheat-labelled function(s)${sw.sample.length ? ` · e.g. ${sw.sample.slice(0, 4).map((s) => `"${s}"`).join(", ")}` : ""}`);
    sections.push({ title: "VERIFIED INTEL (hash / ban / anticheat / revive)", lines, shrinkable: true });
  }

  if (LIBRARY_INTENTS.has(answer.intent) || answer.intent === "overview") {
    const lines: string[] = [];
    for (const g of db.libraryMap().slice(0, 12)) lines.push(`${g.library}: ${g.imports.length} imports — ${g.imports.slice(0, 14).join(", ")}${g.imports.length > 14 ? " …" : ""}`);
    const top = db.topImports(20);
    if (top.length) lines.push(`Most-used imports: ${top.map((t) => `${t.name} ×${t.users} [${t.library}]`).join(", ")}`);
    sections.push({ title: "IMPORT → LIBRARY MAP", lines, shrinkable: true });
  }

  if (LIST_INTENTS.has(answer.intent) || LIBRARY_INTENTS.has(answer.intent)) {
    const rel = answer.related.filter((r) => r.addr !== 0).slice(0, 40);
    if (rel.length) {
      sections.push({
        title: "RESULT SET (from the local engine)",
        lines: rel.map((r) => {
          const f = db.functionByAddr(r.addr);
          const cls = f?.classes?.[0];
          return `${r.name} @ ${hex(r.addr)}${r.note ? ` · ${r.note}` : ""}${f ? ` · ${f.size} bytes · ${f.callerCount} callers${cls ? ` · ${cls.label} ${Math.round(cls.confidence * 100)}%` : ""}` : ""}`;
        }),
        shrinkable: true,
      });
    }
  }

  // Always: what the deterministic engine concluded and how it checked itself.
  const ver: string[] = [`Verdict: ${answer.verdict ?? "n/a"} · confidence ${answer.confidence !== undefined ? Math.round(answer.confidence * 100) + "%" : "n/a"}`];
  for (const s of (answer.reasoning ?? []).slice(0, 14)) ver.push(`[${s.status}] ${s.label}: ${s.detail}`);
  if (answer.evidence.length) {
    ver.push("Evidence that survived the database cross-check:");
    for (const e of answer.evidence.slice(0, 24)) ver.push(`  - [${e.certainty}${e.verified ? ", verified" : ""}] ${e.text}${e.address !== undefined ? ` @ ${hex(e.address)}` : ""}`);
  }
  sections.push({ title: "LOCAL ENGINE VERIFICATION", lines: ver });

  return render(sections, cap);
}

function render(sections: Section[], cap: number): string {
  const text = () => sections.map((s) => `## ${s.title}\n${s.lines.join("\n")}`).join("\n\n");
  let out = text();
  // Over budget: halve the longest shrinkable section until it fits (or nothing is left to cut).
  for (let guard = 0; out.length > cap && guard < 40; guard++) {
    const victim = sections.filter((s) => s.shrinkable && s.lines.length > 12).sort((a, b) => b.lines.length - a.lines.length)[0];
    if (!victim) break;
    const keep = Math.max(12, Math.floor(victim.lines.length / 2));
    const dropped = victim.lines.length - keep;
    victim.lines = victim.lines.slice(0, keep);
    victim.lines.push(`… ${dropped} more line(s) omitted for size`);
    victim.shrinkable = keep > 12;
    out = text();
  }
  return out.length > cap ? out.slice(0, cap) + "\n… truncated" : out;
}
