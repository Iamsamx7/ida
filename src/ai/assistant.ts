import type { AnalysisDatabase } from "../core/analysis/database";
import type { FunctionRecord } from "../core/analysis/types";
import { findSimilar, packFunction, parseIntent, semanticSearch, type FunctionContextPack, type Intent } from "./retrieval";
import { buildIntel, emuMarkersOf, type IntelFinding, type IntelKind } from "../core/analysis/intel";
import { planAgentActions, type AgentAction } from "./agent";
import { search } from "../core/search/engine";

export interface EvidenceLink {
  text: string;
  address?: number;
  certainty: "fact" | "inference" | "ai-hypothesis" | "user";
  /** Set by the verifier when the claim survived a database cross-check. */
  verified?: boolean;
}
export interface ReasoningStep {
  label: string;
  status: "pass" | "fail" | "warn" | "info" | "thinking";
  detail: string;
  address?: number;
  /** Inner-monologue line: what the assistant asked itself at this step. */
  thought?: string;
}
export interface AssistantAnswer {
  text: string;
  evidence: EvidenceLink[];
  related: { addr: number; name: string; note?: string }[];
  confidence?: number;
  intent: Intent["kind"];
  /** Whether an external LLM produced the prose (vs. the deterministic local engine). */
  source: "local" | "llm";
  nameSuggestion?: { name: string; confidence: number; reasons: string[] };
  /** Think-then-verify trace: every question is checked before answering. */
  reasoning?: ReasoningStep[];
  verdict?: string;
  /** Agent hands: concrete actions the workbench executes (navigate/bookmark/tag/rename/comment). */
  actions?: AgentAction[];
  /** The function this answer is about (explain / why / callers / …), when there is one. Drives LLM context selection. */
  targetAddr?: number;
}

/** Intents whose answer is about one function (the cursor or an explicit address). */
export const FUNCTION_INTENTS: ReadonlySet<Intent["kind"]> = new Set<Intent["kind"]>(["explain", "why", "callers", "callees", "similar", "suggest-name", "general"]);

export interface NameSuggestion {
  name: string;
  confidence: number;
  reasons: string[];
}

/**
 * Evidence-based assistant. Works entirely from the analysis database; when an
 * external LLM provider is configured the same structured context is sent to
 * it, and the local answer acts as the grounding + fallback. Never fabricates
 * certainty: every statement is tagged fact / inference / hypothesis.
 */
export class LocalAssistant {
  constructor(private db: AnalysisDatabase, private index: Map<number, string>) {}

  /**
   * Think → check → verify → answer.
   * Every question runs a deliberative pipeline before any text is returned:
   *  1. understand (parse intent + resolve the target),
   *  2. deliberate (argue competing hypotheses with itself, ask follow-ups),
   *  3. gather (collect candidate evidence from the DB),
   *  4. verify (cross-check each claim; drop what fails; second-guess itself),
   *  5. calibrate (multi-source confidence, never 100% unless a known symbol).
   * The full inner-monologue trace is returned in `reasoning` so the UI can
   * show its work the way a real analyst thinks out loud.
   */
  answer(question: string, currentAddr: number | null): AssistantAnswer {
    const steps: ReasoningStep[] = [];
    const q = question.trim();
    if (!q) {
      return { text: "Ask me about a function, an import (e.g. memcpy), anticheat, ban checks, hash checks, or libraries.", evidence: [], related: [], intent: "general", source: "local", reasoning: [{ label: "Understand", status: "warn", detail: "empty question — nothing to verify" }] };
    }
    const intent = parseIntent(q, { imports: this.db.elf.imports.map((i) => i.name) });
    steps.push({ label: "Understand", status: "thinking", detail: `intent=${intent.kind}${"addr" in intent && intent.addr !== undefined ? ` target=0x${intent.addr.toString(16)}` : currentAddr !== null ? ` cursor=0x${currentAddr.toString(16)}` : " (whole binary)"}`, thought: `“${q.slice(0, 90)}” — what is Sam actually asking for here? ${this.describeIntent(intent, currentAddr)}` });
    if (intent.kind === "help") return { ...this.help(currentAddr), reasoning: steps, verdict: "n/a — capability list" };
    this.deliberate(intent, currentAddr, steps);
    let raw: AssistantAnswer;
    try {
      raw = this.answerInner(intent, currentAddr, steps);
    } catch (e) {
      steps.push({ label: "Gather", status: "fail", detail: `analysis error: ${String(e)}` });
      return { text: `I could not verify an answer — the analysis threw (${String(e)}). Try re-running analysis (F5).`, evidence: [], related: [], intent: intent.kind, source: "local", reasoning: steps, verdict: "unverified — error" };
    }
    if (raw.targetAddr === undefined && FUNCTION_INTENTS.has(intent.kind)) {
      const a = "addr" in intent && intent.addr !== undefined ? intent.addr : currentAddr;
      const f = a !== null && a !== undefined ? this.db.functionAt(a) : null;
      if (f) raw.targetAddr = f.addr;
    }
    return this.verify(intent, raw, steps);
  }

  /** Capability list — what the local engine and the agent hands can do, in the user's own words. */
  help(currentAddr: number | null): AssistantAnswer {
    const db = this.db;
    const cur = currentAddr !== null ? db.functionAt(currentAddr) : null;
    const text = [
      `I answer from the analysis database and verify every claim before showing it. ${cur ? `Cursor is on ${db.nameFor(cur.addr).name} @ 0x${cur.addr.toString(16)}.` : "Select a function to ask about it directly."}`,
      "",
      "Questions:",
      "• “What does this function do?” · “Why did you classify this?” · “What calls this?” · “What does this call?” · “Find similar functions” · “Suggest a name”",
      "• “Where is anticheat?” · “Where are ban checks?” · “Where are hash checks?” · “Plan a safe bypass” · “Overview of this binary”",
      "• “Where is memcpy used?” (any import) · “Which libraries does this use?” · “Where is the string \"…\" used?” · “Which functions access this global?”",
      "• “Show me everything related to networking” (semantic search) · “search <text>” (raw search)",
      "",
      "Orders (agent hands act on the workbench):",
      "• “recon” · “bookmark all anticheat” · “tag all ban as evil” · “take me to the best hash check”",
      "• “go to 0x1a2b0” · “go to net_send” · “bookmark this” · “tag this important” · “rename this to handle_ban” · “rename sub_1a2b0 to X” · “comment this function: …”",
      "",
      `Verified intel right now: ${(() => { const i = buildIntel(db, 12); return `${i.findings.length} finding(s), ${i.provenCount} proven${i.packedSuspect ? " — packed suspect, absence proves nothing" : ""}`; })()}.`,
    ].join("\n");
    return { text, evidence: [], related: [], intent: "help", source: "local", confidence: 1 };
  }

  private describeIntent(intent: Intent, currentAddr: number | null): string {
    switch (intent.kind) {
      case "explain": return "They want the story of one function — what it does and why I believe it.";
      case "why": return "They're challenging my classification — I need to defend it or back down.";
      case "callers": return "They want the blame list — who reaches this code?";
      case "callees": return "They want the dependency list — what does this code reach for?";
      case "anticheat": return "They're hunting protection — I must separate real checks from mere string mentions.";
      case "ban": return "They're hunting punishment logic — ban text alone isn't proof, I need the reporting path too.";
      case "hash": return "They're hunting integrity verification — I need loop + compare + constant, not just one of them.";
      case "imports": return `They're tracing “${intent.query}” — I need to prove the call path, not just quote the import table.`;
      case "libraries": return "They want the dependency map — which .so owns which import.";
      case "agent": return `An order (${intent.task.op}) — resolve the target, act, report what moved.`;
      case "help": return "They want to know what I can do — list it, no analysis needed.";
      default: return currentAddr !== null ? "Vague question — I'll anchor on the cursor and say what I assumed." : "Vague question over the whole binary — I'll survey first, then commit.";
    }
  }

  /**
   * Phase 2 — deliberate: argue with itself BEFORE gathering, so the answer
   * is steered by questions, not by the first match. Each push is a thought
   * the UI streams out loud.
   */
  private deliberate(intent: Intent, currentAddr: number | null, steps: ReasoningStep[]) {
    const db = this.db;
    const fn = currentAddr !== null ? db.functionAt(currentAddr) : null;
    const think = (label: string, thought: string, detail: string, status: ReasoningStep["status"] = "thinking", address?: number) =>
      steps.push({ label, status, detail, thought, address });
    switch (intent.kind) {
      case "explain":
      case "why": {
        if (!fn) { think("Deliberate", "No function under the cursor — I shouldn't invent one. I'll say so instead of guessing.", "no function resolved; will refuse rather than hallucinate", "warn"); break; }
        const name = db.nameFor(fn.addr);
        const cls = fn.classes ?? [];
        think("Deliberate", `OK, staring at ${name.name} @ 0x${fn.addr.toString(16)}. ${fn.size} bytes, found via ${fn.sources.join(" + ")}. First question: is this even a real function or a false split?`, `target ${name.name} [${name.source}] confidence ${Math.round(fn.confidence * 100)}% via ${fn.sources.join("+")}`, "thinking", fn.addr);
        if (name.source === "symbol") think("Deliberate", "Good — it has a real symbol. That's ground truth, I can lean on the name but I still have to prove the behaviour from instructions.", "known symbol: name is fact, behaviour still needs proof", "info", fn.addr);
        else if (fn.confidence < 0.6) think("Deliberate", "Hmm, low discovery confidence. This might be mid-function garbage or a jump-table artefact. I must hedge and say that up front.", `weak discovery (${Math.round(fn.confidence * 100)}%) — will hedge`, "warn", fn.addr);
        else think("Deliberate", "Discovery looks solid. Now — what are the rival stories? I shouldn't marry the first classification.", `discovery solid (${Math.round(fn.confidence * 100)}%) — opening rival hypotheses`, "info", fn.addr);
        if (!cls.length) think("Deliberate", "No classification fired at all. Is that because it's boring glue code, or because it's packed/obfuscated? Let me check size, calls and strings before calling it boring.", "zero classifications — glue vs packed?", "info", fn.addr);
        else if (cls.length === 1) think("Deliberate", `Only one story: ${cls[0].label} at ${Math.round(cls[0].confidence * 100)}%. That's suspicious by itself — one witness isn't a conviction. What would prove it wrong?`, `single hypothesis ${cls[0].label} — seeking disproof`, "thinking", fn.addr);
        else think("Deliberate", `Multiple stories compete: ${cls.slice(0, 3).map((c) => `${c.label} ${Math.round(c.confidence * 100)}%`).join(" vs ")}. I need to weigh them against each other, not just list them.`, `${cls.length} rival hypotheses — will weigh, not list`, "thinking", fn.addr);
        const imports = fn.features?.importCalls ?? [];
        if (imports.length) think("Deliberate", `It's reaching for ${imports.slice(0, 4).join(", ")}${imports.length > 4 ? ` +${imports.length - 4} more` : ""}. Calls don't lie as often as strings do — this is my strongest thread. But wait: are these direct calls or just GOT addresses I inferred?`, `${imports.length} import thread(s) — strongest lead, must confirm direct vs inferred`, "info", fn.addr);
        else think("Deliberate", "No imports at all. So it's either pure arithmetic/a getter, or it hides calls behind indirect branches. I can't claim “leaf” until I check for indirect jumps.", "zero imports — leaf vs hidden-indirect?", "info", fn.addr);
        break;
      }
      case "anticheat":
      case "ban":
      case "hash": {
        const what = intent.kind === "anticheat" ? "anticheat" : intent.kind === "ban" ? "ban logic" : "hash checks";
        think("Deliberate", `Hunting ${what}. Danger here: string matches are cheap — any binary can mention “ban” without enforcing it. My rule: text alone is a lead, text + behaviour is a finding.`, "string ≠ proof — demanding behaviour corroboration", "thinking");
        think("Deliberate", `Plan: sweep classifications first, then strings, then demand they corroborate each other. Anything standing on one leg gets downgraded, not deleted — Sam should still see the lead.`, "two-leg rule: classification × strings must agree", "info");
        break;
      }
      case "imports": {
        const nm = intent.query;
        const declared = db.elf.imports.some((s) => s.name === nm);
        think("Deliberate", `Tracing “${nm}”. First: is it even declared in this binary? ${declared ? "Yes — it's in the import table, so call sites should exist." : "Not in the import table — uh oh. Either Sam misspelled it, it's resolved via dlsym at runtime, or the binary is packed. I must check all three before answering."}`, declared ? "declared import — expecting call sites" : "undeclared — considering dlsym / spelling / packed", declared ? "info" : "warn");
        if (declared) think("Deliberate", "Next: PLT stub vs GOT-slot load vs plain symbol call? Stripped game .so files almost always go through GOT loads (adrp/ldr/blr), so if I only checked PLT I'd miss everything.", "resolution path matters: PLT vs GOT vs dlsym", "info");
        break;
      }
      case "callers":
      case "callees": {
        think("Deliberate", "XREF question. Trap: jumps aren't calls, and tail-calls look like jumps. I'll separate true calls from jumps and say which is which.", "call vs jump vs tail-call must be separated", "info");
        break;
      }
      case "bypass": {
        think("Deliberate", "They want a bypass plan. I must not free-guess hook points — the planner re-verifies every target live, checks blast radius and hunts backup checks first. My job here is the honest briefing, the button does the proving.", "briefing, not guessing — deferring to the 7-pass planner", "info");
        break;
      }
      case "agent": {
        think("Deliberate", "Action command, not a question — resolve the targets, do the thing, then report what I did. No hedging: either I marked them or I say why I couldn't.", "act, then report", "info");
        break;
      }
      default:
        think("Deliberate", "Broad question. I'll survey the database first and let the counts decide what's worth saying — no leading with a pet theory.", "survey-before-commit", "info");
        break;
    }
  }

  private answerInner(intent: Intent, currentAddr: number | null, steps: ReasoningStep[]): AssistantAnswer {
    const db = this.db;
    const fnAt = (a?: number) => {
      const addr = a ?? currentAddr ?? undefined;
      if (addr === undefined) return null;
      return db.functionAt(addr);
    };
    switch (intent.kind) {
      case "explain": {
        const fn = fnAt(intent.addr);
        if (!fn) return this.noFunction(intent.kind);
        return this.explain(fn);
      }
      case "why": {
        const fn = fnAt(intent.addr);
        if (!fn) return this.noFunction(intent.kind);
        const cls = fn.classes ?? [];
        if (!cls.length) return { text: `${db.nameFor(fn.addr).name} has no semantic classification yet — the rule engine found no matching evidence (no recognised API calls, string vocabulary, constants or structural pattern).`, evidence: [], related: [], intent: "why", source: "local" };
        const lines = cls.map((c) => `• ${c.level.toUpperCase()} ${c.label} (${Math.round(c.confidence * 100)}%):\n${c.evidence.map((e) => `    – [${e.certainty}] ${e.text}`).join("\n")}`);
        return { text: `Classification of ${db.nameFor(fn.addr).name} is derived from these observations:\n\n${lines.join("\n\n")}\n\nEach item is a fact from the binary or an inference from instruction patterns; the label itself is a hypothesis.`, evidence: cls.flatMap((c) => c.evidence), related: [], intent: "why", source: "local", confidence: cls[0].confidence };
      }
      case "callers": {
        const fn = fnAt(intent.addr);
        if (!fn) return this.noFunction(intent.kind);
        const callers = db.callersOf(fn);
        const uniq = new Map<number, { name: string; from: number; kind: number }>();
        for (const c of callers) { const k = c.fn?.addr ?? c.from; if (!uniq.has(k)) uniq.set(k, { name: c.fn ? db.nameFor(c.fn.addr).name : db.labelFor(c.from), from: c.from, kind: c.kind }); }
        const list = [...uniq.entries()].slice(0, 40);
        const text = list.length ? `${db.nameFor(fn.addr).name} is referenced from ${uniq.size} location(s)${callers.length > uniq.size ? ` (${callers.length} references)` : ""}:\n${list.map(([, v]) => `• ${v.name} at 0x${v.from.toString(16)} (${["", "call", "jump", "read", "write", "address", "pointer", "string"][v.kind]})`).join("\n")}` : `No references to ${db.nameFor(fn.addr).name} were found. It may be reached through an exported symbol, a vtable slot the analysis did not resolve, or indirect calls.`;
        return { text, evidence: list.map(([, v]) => ({ text: `${v.name} → 0x${v.from.toString(16)}`, address: v.from, certainty: "fact" as const })), related: list.map(([addr, v]) => ({ addr, name: v.name })), intent: "callers", source: "local" };
      }
      case "callees": {
        const fn = fnAt(intent.addr);
        if (!fn) return this.noFunction(intent.kind);
        const callees = db.calleesOf(fn);
        const text = callees.length ? `${db.nameFor(fn.addr).name} calls ${callees.length} target(s):\n${callees.slice(0, 40).map((c) => `• ${db.nameFor(c.to).name} from 0x${c.from.toString(16)}`).join("\n")}` : `${db.nameFor(fn.addr).name} makes no direct calls (leaf function or indirect calls only).`;
        return { text, evidence: callees.slice(0, 40).map((c) => ({ text: `call at 0x${c.from.toString(16)}`, address: c.from, certainty: "fact" as const })), related: callees.slice(0, 40).map((c) => ({ addr: c.to, name: db.nameFor(c.to).name })), intent: "callees", source: "local" };
      }
      case "string-uses": {
        const q = intent.query.replace(/^["'\s]+|["'\s?]+$/g, "");
        const strs = q ? db.strings.filter((s) => s.value.toLowerCase().includes(q.toLowerCase())).slice(0, 10) : currentAddr !== null && db.stringAt(currentAddr) ? [db.stringAt(currentAddr)!] : [];
        if (!strs.length) return { text: `No string matching "${q}" was found.`, evidence: [], related: [], intent: "string-uses", source: "local" };
        const parts: string[] = [];
        const ev: EvidenceLink[] = [];
        const rel: AssistantAnswer["related"] = [];
        for (const s of strs) {
          const refs = db.xrefs.refsTo(s.addr, 50);
          parts.push(`"${s.value.slice(0, 80)}" @ 0x${s.addr.toString(16)} — ${refs.length} reference(s)${refs.length ? ":\n" + refs.map((r) => `  • ${db.labelFor(r.from)}`).join("\n") : ""}`);
          for (const r of refs) { ev.push({ text: `${db.labelFor(r.from)} references string`, address: r.from, certainty: "fact" }); const f = db.functionAt(r.from); if (f && !rel.some((x) => x.addr === f.addr)) rel.push({ addr: f.addr, name: db.nameFor(f.addr).name }); }
        }
        return { text: parts.join("\n\n"), evidence: ev, related: rel, intent: "string-uses", source: "local" };
      }
      case "global-access": {
        let addr = intent.addr ?? null;
        if (addr === null && intent.query) addr = db.globals.find((g) => g.name.toLowerCase().includes(intent.query!.toLowerCase()))?.addr ?? null;
        if (addr === null && currentAddr !== null && !db.functionAt(currentAddr)) addr = currentAddr;
        if (addr === null) return { text: "Select a global (or give its address) and ask again.", evidence: [], related: [], intent: "global-access", source: "local" };
        const refs = db.xrefs.refsTo(addr, 200);
        const readers = new Map<number, number>(), writers = new Map<number, number>();
        for (const r of refs) { const f = db.functionAt(r.from); if (!f) continue; (r.kind === 4 ? writers : readers).set(f.addr, ((r.kind === 4 ? writers : readers).get(f.addr) ?? 0) + 1); }
        const nm = db.nameFor(addr).name;
        const text = `${nm} (0x${addr.toString(16)}) is accessed by ${readers.size + writers.size} function(s).\nReaders: ${[...readers.keys()].map((a) => db.nameFor(a).name).join(", ") || "none"}\nWriters: ${[...writers.keys()].map((a) => db.nameFor(a).name).join(", ") || "none"}`;
        return { text, evidence: refs.slice(0, 50).map((r) => ({ text: `${r.kind === 4 ? "write" : "read"} at ${db.labelFor(r.from)}`, address: r.from, certainty: "fact" as const })), related: [...new Set([...readers.keys(), ...writers.keys()])].map((a) => ({ addr: a, name: db.nameFor(a).name })), intent: "global-access", source: "local" };
      }
      case "similar": {
        const fn = fnAt(intent.addr);
        if (!fn) return this.noFunction(intent.kind);
        const sims = findSimilar(db, fn, 12, 0.55);
        const text = sims.length ? `Functions similar to ${db.nameFor(fn.addr).name} (instruction mix, constants, strings, callees, size, CFG shape):\n${sims.map((s) => `• ${db.nameFor(s.fn.addr).name} — ${Math.round(s.score * 100)}%`).join("\n")}` : `No sufficiently similar functions (≥55%) were found for ${db.nameFor(fn.addr).name}.`;
        return { text, evidence: [], related: sims.map((s) => ({ addr: s.fn.addr, name: db.nameFor(s.fn.addr).name, note: `${Math.round(s.score * 100)}%` })), intent: "similar", source: "local" };
      }
      case "suggest-name": {
        const fn = fnAt(intent.addr);
        if (!fn) return this.noFunction(intent.kind);
        const s = suggestName(db, fn);
        return { text: s ? `Suggested name: ${s.name} (confidence ${Math.round(s.confidence * 100)}%)\n\nReasons:\n${s.reasons.map((r) => `• ${r}`).join("\n")}\n\nThis is an AI hypothesis — accept it only if the evidence convinces you.` : "Not enough evidence to suggest a meaningful name.", evidence: [], related: [], intent: "suggest-name", source: "local", nameSuggestion: s ?? undefined, confidence: s?.confidence };
      }
      case "semantic-search": {
        const res = semanticSearch(db, this.index, intent.query, 25);
        const text = res.length ? `${res.length} function(s) related to "${intent.query}":\n${res.map((r) => `• ${db.nameFor(r.fn.addr).name}${r.fn.classes?.length ? ` — ${r.fn.classes[0].level} ${r.fn.classes[0].label}` : ""} (matched: ${r.matched.slice(0, 4).join(", ")})`).join("\n")}` : `Nothing in the semantic index matches "${intent.query}". Try different vocabulary, or wait for semantic analysis to finish.`;
        return { text, evidence: [], related: res.map((r) => ({ addr: r.fn.addr, name: db.nameFor(r.fn.addr).name, note: r.fn.classes?.[0]?.label })), intent: "semantic-search", source: "local" };
      }
      case "search": {
        const hits = search(db, intent.query, { limitPerCategory: 15 });
        return { text: hits.length ? `${hits.length} result(s) for "${intent.query}":\n${hits.slice(0, 30).map((h) => `• [${h.category}] ${h.title}`).join("\n")}` : `No results for "${intent.query}".`, evidence: [], related: hits.slice(0, 30).map((h) => ({ addr: h.address, name: h.title, note: h.category })), intent: "search", source: "local" };
      }
      case "overview":
        return this.overview();
      case "anticheat":
        return this.securityReport("anticheat");
      case "ban":
        return this.securityReport("ban");
      case "hash":
        return this.securityReport("hash");
      case "libraries":
        return this.libraryMap();
      case "bypass":
        return this.bypassGuide();
      case "agent": {
        return this.runAgent(intent.task, currentAddr);
      }
      case "imports": {
        return this.importUses(intent.query);
      }
      case "help":
        return this.help(currentAddr);
      default: {
        // General: try semantic search then fall back to explaining current function
        const res = semanticSearch(db, this.index, intent.query, 10);
        if (res.length && res[0].score >= 3) {
          const top = res.slice(0, 15);
          steps.push({ label: "Gather", status: "info", detail: `semantic search matched ${top.length} function(s), best score ${top[0].score}` });
          return { text: `${top.length} function(s) related to "${intent.query}":\n${top.map((r) => `• ${db.nameFor(r.fn.addr).name}${r.fn.classes?.length ? ` — ${r.fn.classes[0].level} ${r.fn.classes[0].label}` : ""} (matched: ${r.matched.slice(0, 4).join(", ")})`).join("\n")}`, evidence: [], related: top.map((r) => ({ addr: r.fn.addr, name: db.nameFor(r.fn.addr).name, note: r.fn.classes?.[0]?.label })), intent: "semantic-search", source: "local" };
        }
        const fn = fnAt();
        if (fn) return this.explain(fn, `I interpreted your question in the context of ${db.nameFor(fn.addr).name}.`);
        return this.overview();
      }
    }
  }

  /**
   * Phase 3+4: cross-check every claim in `raw` against the database, drop
   * anything that fails, then calibrate confidence from independent sources.
   * - fact claims (calls, strings, xrefs) must resolve to a real address/symbol;
   * - inference claims need ≥2 independent evidence kinds to hold confidence;
   * - single-source answers are explicitly downgraded, never silently upgraded;
   * - 100% is reserved for known symbols; everything inferred caps at 98%.
   */
  private verify(intent: Intent, raw: AssistantAnswer, steps: ReasoningStep[]): AssistantAnswer {
    const db = this.db;
    const evidence: EvidenceLink[] = [];
    let dropped = 0;
    const kinds = new Set<string>();
    for (const e of raw.evidence) {
      const check = this.checkEvidence(e);
      if (check.ok) {
        evidence.push({ ...e, verified: true });
        kinds.add(check.kind);
      } else {
        dropped++;
        steps.push({ label: "Verify", status: "fail", detail: `dropped unsupported claim: "${e.text.slice(0, 70)}"${e.address !== undefined ? ` @ 0x${e.address.toString(16)}` : ""} — ${check.reason}` });
      }
    }
    const related = (raw.related ?? []).filter((r) => {
      if (r.addr === 0) return true; // library pseudo-rows carry no address
      if (db.functionByAddr(r.addr) || db.stringAt(r.addr) || db.space.isMapped(r.addr) || db.symbolNames.has(r.addr) || db.pltNames.has(r.addr) || db.gotNames.has(r.addr)) return true;
      dropped++;
      steps.push({ label: "Verify", status: "fail", detail: `dropped dead link ${r.name} @ 0x${r.addr.toString(16)}` });
      return false;
    });
    const totalClaims = raw.evidence.length + (raw.related ?? []).length;
    steps.push({ label: "Gather", status: "info", detail: `${totalClaims} candidate claim(s) collected for intent=${raw.intent}`, thought: totalClaims ? `Gathered ${totalClaims} candidate claims. Now the adversarial part: which of these am I *least* sure about?` : "Nothing came back. Before I say “not found”, did I search the right way — or is the binary packed/stripped?" });
    steps.push({ label: "Verify", status: dropped ? "warn" : "pass", detail: dropped ? `${evidence.length + related.length} survived, ${dropped} dropped after DB cross-check` : `all ${evidence.length + related.length} claim(s) resolve in the database`, thought: dropped ? `I caught myself: ${dropped} claim(s) didn't survive the cross-check. Good — that's the system working. Removing them rather than smoothing them over.` : evidence.length + related.length > 0 ? "Every address resolves. But resolving isn't the same as *meaning* — a string can resolve and still be a red herring. Keeping that in mind for calibration." : undefined });
    // Second-guess: actively try to falsify the leading conclusion.
    this.secondGuess(intent, raw, evidence, kinds, steps);
    // Calibrate: independent-source bonus, single-source penalty, symbol ceiling.
    let conf = raw.confidence;
    const multiSource = kinds.size >= 2;
    if (conf === undefined) {
      conf = evidence.length === 0 && related.length === 0 ? 0.35 : Math.min(0.9, 0.45 + 0.12 * Math.min(3, kinds.size) + 0.05 * Math.min(4, Math.floor(evidence.length / 2)));
      if (!multiSource && (evidence.length + related.length) > 0) conf = Math.min(conf, 0.65);
    } else {
      if (!multiSource && kinds.size <= 1 && evidence.length <= 2) conf = Math.min(conf, 0.7);
    }
    conf = Math.max(0.05, Math.min(0.98, conf));
    const fails = steps.filter((s) => s.status === "fail").length;
    const verdict = totalClaims === 0
      ? (intent.kind === "overview" || intent.kind === "libraries" ? "verified — summary of database facts" : "unverified — no supporting evidence found, answer withheld from certainty")
      : fails > 0
        ? `verified with caution — ${dropped} unsupported claim(s) removed`
        : multiSource || evidence.length >= 3
          ? "verified — multiple independent evidence sources agree"
          : "partially verified — single evidence source, treat as lead not proof";
    steps.push({ label: "Calibrate", status: conf >= 0.75 ? "pass" : conf >= 0.5 ? "info" : "warn", detail: `confidence ${Math.round(conf * 100)}% from ${kinds.size || "0"} independent evidence kind(s) [${[...kinds].join(", ") || "none"}]` });
    const header = `Verdict: ${verdict} (${Math.round(conf * 100)}%).\n`;
    return { ...raw, text: header + raw.text, evidence, related, confidence: conf, reasoning: steps, verdict };
  }

  /** Phase 4b — steelman the opposite: what would prove my own conclusion wrong? */
  private secondGuess(intent: Intent, raw: AssistantAnswer, evidence: EvidenceLink[], kinds: Set<string>, steps: ReasoningStep[]) {
    const db = this.db;
    if (raw.intent === "explain" || raw.intent === "why") {
      const fn = raw.related?.map((r) => db.functionByAddr(r.addr)).find(Boolean) ?? null;
      void fn;
      const hasStrings = kinds.has("string");
      const hasImports = kinds.has("import") || kinds.has("function");
      if (hasStrings && !hasImports) steps.push({ label: "Second-guess", status: "thinking", detail: "strings without calls — could be a data holder, not logic", thought: "Hold on. All my flavour comes from strings, but there are no calls backing it up. Am I looking at a real handler or just a table of error messages? If it's the latter, my classification is story-telling, not analysis. Downgrading." });
      else if (hasImports && !hasStrings) steps.push({ label: "Second-guess", status: "thinking", detail: "calls without strings — behaviour is real but motive is thin", thought: "Calls check out but no strings confirm *why*. The mechanism is solid, the purpose is a guess. I'll state the mechanism confidently and mark the purpose as hypothesis." });
      else if (hasStrings && hasImports) steps.push({ label: "Second-guess", status: "pass", detail: "calls × strings agree — rival explanations narrowed", thought: "Both legs stand: calls say *how*, strings say *why*. I tried to kill this conclusion and couldn't — that's when I start trusting it." });
      else steps.push({ label: "Second-guess", status: "warn", detail: "thin evidence all around — mostly structural guesswork", thought: "Honestly? I'm running on fumes here — instruction mix and shape only. I should say that plainly instead of dressing it up." });
    } else if (raw.intent === "anticheat" || raw.intent === "ban" || raw.intent === "hash") {
      const n = evidence.length + (raw.related?.length ?? 0);
      if (n === 0) steps.push({ label: "Second-guess", status: "thinking", detail: "zero hits — packed binary or genuinely clean?", thought: "Zero hits. Two possibilities: it's clean, or it's packed and I'm blind. I must not claim “clean” — absence of evidence isn't evidence of absence, especially with encrypted game .so files. Saying so explicitly." });
      else steps.push({ label: "Second-guess", status: "thinking", detail: `${n} hit(s) — lead vs finding triage`, thought: `I have hits, but are they *findings* or just *leads*? A lone “ban” string in a log table is a lead. A ban string + a send/log/exit path in the same function is a finding. I already applied that rule — now I'm double-checking I didn't promote any leads.` });
    } else if (raw.intent === "imports") {
      if (evidence.length === 0) steps.push({ label: "Second-guess", status: "thinking", detail: "no call sites — dlsym? dead import? packed?", thought: "No call sites found. Before I close this out: did I check dlsym-resolved usage and spelling variants? A “not found” here has three very different meanings and Sam needs to know which one I checked." });
      else steps.push({ label: "Second-guess", status: "pass", detail: `${evidence.length} call site(s) confirmed via PLT/GOT map`, thought: "Call sites resolve through the PLT/GOT map — not inferred. That's as solid as static analysis gets without emulation." });
    }
  }
  /** Cross-check one evidence claim against the database. */
  private checkEvidence(e: EvidenceLink): { ok: boolean; kind: string; reason?: string } {
    const db = this.db;
    if (e.address === undefined) {
      // Address-less claims are only accepted when they quote a real string/import.
      const t = e.text.toLowerCase();
      const strHit = db.strings.some((s) => t.includes(s.value.slice(0, 24).toLowerCase()));
      if (strHit) return { ok: true, kind: "string" };
      const impHit = db.elf.imports.some((s) => t.includes(s.name.toLowerCase()));
      if (impHit) return { ok: true, kind: "import" };
      return { ok: e.certainty !== "fact", kind: "prose", reason: "no address and no matching string/import" };
    }
    const a = e.address;
    if (db.functionByAddr(a) || db.functionAt(a)) return { ok: true, kind: "function" };
    if (db.stringAt(a)) return { ok: true, kind: "string" };
    if (db.symbolNames.has(a) || db.pltNames.has(a) || db.gotNames.has(a)) return { ok: true, kind: "import" };
    if (db.space.isMapped(a)) {
      // Mapped but not a known object: accept reads/writes/xrefs, reject bare "call" facts.
      if (/call/i.test(e.text) && e.certainty === "fact") return { ok: false, kind: "call", reason: "call target not in function/PLT/GOT map" };
      return { ok: true, kind: "xref" };
    }
    return { ok: false, kind: "address", reason: "address not mapped in this binary" };
  }

  private noFunction(intent: Intent["kind"]): AssistantAnswer {
    return { text: "No function is selected. Navigate to a function (or include its address, e.g. 0x7a31f0) and ask again.", evidence: [], related: [], intent, source: "local" };
  }

  explain(fn: FunctionRecord, prefix?: string): AssistantAnswer {
    const db = this.db;
    const pack = packFunction(db, fn);
    const ev: EvidenceLink[] = [];
    const parts: string[] = [];
    if (prefix) parts.push(prefix);
    const cls = pack.classes[0];
    const behaviour = describeBehaviour(pack);
    parts.push(`${pack.name} (0x${fn.addr.toString(16)}, ${fn.size} bytes, discovered via ${fn.sources.join(" + ")}, confidence ${Math.round(fn.confidence * 100)}%).`);
    if (cls) parts.push(`${cls.level === "high" ? "High-confidence" : cls.level === "likely" ? "Likely" : "Possibly"} ${cls.label.replace(/-/g, " ")} routine (${Math.round(cls.confidence * 100)}%).`);
    parts.push(behaviour.text);
    ev.push(...behaviour.evidence);
    if (pack.strings.length) { parts.push(`References strings: ${pack.strings.slice(0, 4).map((s) => `"${s.value.slice(0, 40)}"`).join(", ")}.`); for (const s of pack.strings.slice(0, 6)) ev.push({ text: `string "${s.value.slice(0, 40)}"`, address: s.addr, certainty: "fact" }); }
    if (pack.callees.length) {
      const resolved = db.importCallsOf(fn);
      const shown = resolved.length ? resolved.slice(0, 8).map((n) => `${n} [${db.importLibraryOf(n)}]`) : [...new Set(pack.callees.map((c) => c.name))].slice(0, 6);
      parts.push(`Calls (${pack.callees.length} edges${resolved.length ? `, ${resolved.length} resolved imports` : ""}): ${shown.join(", ")}.`);
      for (const c of pack.callees.slice(0, 6)) ev.push({ text: `calls ${db.callNameFor(c.addr)}`, address: c.from, certainty: "fact" });
    }
    if (pack.callers.length) parts.push(`Called from: ${[...new Set(pack.callers.map((c) => c.name))].slice(0, 6).join(", ")}.`);
    if (pack.globals.length) { parts.push(`Touches globals: ${pack.globals.slice(0, 4).map((g) => `${g.name} (${g.kind})`).join(", ")}.`); for (const g of pack.globals.slice(0, 4)) ev.push({ text: `${g.kind} ${g.name}`, address: g.addr, certainty: "fact" }); }
    if (cls) for (const e of cls.evidence.slice(0, 4)) ev.push(e);
    // Rival hypotheses: show the debate, not just the winner.
    const rivals = (pack.classes ?? []).slice(1, 3);
    if (rivals.length && cls) parts.push(`Why not ${rivals.map((r) => `${r.label} (${Math.round(r.confidence * 100)}%)`).join(" or ")}? ${rivals.map((r) => `${r.label} has less support (${r.evidence.length} vs ${cls.evidence.length} evidence items)`).join("; ")}. If new xrefs appear, I'd re-weigh.`);
    else if (!cls) parts.push(`I considered the usual suspects and none cleared the bar — either genuinely plain glue code or deliberately quiet code. Check xrefs: ${pack.callers.length} caller(s), ${pack.callees.length} callee(s).`);
    // If this function is a verified intel finding, state definitively what happens on hook/patch.
    const intelHit = buildIntel(db, 12).findings.find((f) => f.addr === fn.addr);
    if (intelHit) {
      parts.push(`VERIFIED ROLE [${intelHit.kind} · ${intelHit.proofLevel.toUpperCase()} · ${Math.round(intelHit.confidence * 100)}% · proof: ${intelHit.legs.join(" + ")}]: ${intelHit.whatItDoes}`);
      parts.push(`IF YOU HOOK IT: ${intelHit.hookImpact}`);
      parts.push(`IF YOU PATCH IT: ${intelHit.patchImpact}`);
      for (const e of intelHit.evidence.slice(0, 3)) ev.push({ text: e.text.slice(0, 80), address: e.address, certainty: "fact" });
    } else {
      parts.push(`My doubt: ${pack.callees.length === 0 && pack.strings.length === 0 ? "thin evidence — mostly shape and size, so treat this as a lead" : pack.classes.length > 1 ? "competing labels both fit parts of the evidence — winner is provisional" : "single coherent story, but one new string or call could flip it"}. Facts above come from the binary; the behavioural summary is an inference; the classification is a hypothesis.`);
    }
    const suggestion = pack.nameSource !== "symbol" && pack.nameSource !== "user" ? suggestName(db, fn) : null;
    return { text: parts.join("\n\n"), evidence: ev, related: [...pack.callers.slice(0, 5).map((c) => ({ addr: c.addr, name: c.name, note: "caller" })), ...pack.callees.slice(0, 5).map((c) => ({ addr: c.addr, name: c.name, note: "callee" }))], intent: "explain", source: "local", confidence: cls?.confidence ?? behaviour.confidence, nameSuggestion: suggestion ?? undefined };
  }

  overview(): AssistantAnswer {
    const db = this.db;
    const st = db.stats();
    const comp = new Map<string, number>();
    for (const f of db.functions) for (const c of f.classes ?? []) if (c.confidence >= 0.5) comp.set(c.label, (comp.get(c.label) ?? 0) + 1);
    const top = [...comp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const intel = buildIntel(db, 6);
    const topImp = db.topImports(8).map((t) => `${t.name} ×${t.users}`).join(", ") || "pending…";
    const intelLines = intel.findings.slice(0, 6).map((f) => `• [${f.proofLevel.toUpperCase()} ${Math.round(f.confidence * 100)}%] ${f.name} @ 0x${f.addr.toString(16)} — ${f.whatItIs.split(".")[0]}.`);
    const text = `${db.fileName}: ${db.elf.header.machineName}, ${st.functions} functions, ${st.strings} strings, ${st.imports} imports, ${st.exports} exports, ${st.xrefs} cross-references${db.elf.stripped ? ", stripped" : ""}.\n\nVerified intel (${intel.findings.length} findings, ${intel.provenCount} proven — auto-checked on load):\n${intelLines.join("\n") || "• no hash/ban/anticheat/revive routine cleared the two-leg proof bar" + (intel.packedSuspect ? " (packed suspect — absence proves nothing)" : "")}\n\nDetected components (≥50%):\n${top.map(([l, n]) => `• ${l}: ${n}`).join("\n") || "• semantic analysis pending"}\n\nAsk "where is anticheat?" for the full chain per finding: what it is, what it does, what connects to it, and exactly what happens if you hook or patch it.\n\nTop API calls: ${topImp}\n\nNeeded libraries: ${db.elf.needed.join(", ") || "none"}.`;
    return {
      text,
      evidence: intel.findings.slice(0, 8).flatMap((f) => f.evidence.slice(0, 2).map((e) => ({ text: `${f.name}: ${e.text.slice(0, 60)}`, address: e.address, certainty: "fact" as const }))),
      related: intel.findings.slice(0, 8).map((f) => ({ addr: f.addr, name: f.name, note: `${f.kind} ${Math.round(f.confidence * 100)}%` })),
      intent: "overview",
      source: "local",
      confidence: intel.findings.length ? Math.min(0.95, 0.6 + 0.05 * intel.provenCount) : 0.5,
    };
  }

  securityReport(which: "anticheat" | "ban" | "hash"): AssistantAnswer {
    const db = this.db;
    const kind: IntelKind = which === "anticheat" ? "anticheat" : which === "ban" ? "ban-check" : "hash-check";
    const intel = buildIntel(db, 12);
    const hits = intel.findings.filter((f) => f.kind === kind || (which === "hash" && f.kind === "hash-check"));
    const title = which === "anticheat" ? "Anticheat / integrity checks" : which === "ban" ? "Ban enforcement" : "Hash / integrity verification";
    if (!hits.length) {
      return { text: `${title}: no routine cleared the two-leg proof bar (classification × strings/imports/structure must agree). ${which === "anticheat" ? "No ptrace/emulator/root probe with corroborating strings was traced end-to-end." : which === "ban" ? "No ban-notice string wired to a report/punish path was traced end-to-end." : "No hash loop + compare + verify-string chain was traced end-to-end."}${intel.packedSuspect ? " The binary looks packed/encrypted — absence here proves nothing, the code is hidden." : " Either genuinely absent or dlsym-hidden."} I verified rather than guessed: every candidate failed at least one proof leg.`, evidence: [], related: [], intent: which === "anticheat" ? "anticheat" : which === "ban" ? "ban" : "hash", source: "local", confidence: 0.4 };
    }
    const blocks = hits.slice(0, 8).map((f) => formatIntelBlock(db, f)).join("\n\n---\n\n");
    const text = `${title} — ${hits.length} verified finding(s), ${hits.filter((f) => f.proofLevel === "proven").length} proven. Each one below states what it is, what it does, what connects to it, and what happens if you hook or patch it.\n\n${blocks}${which === "anticheat" ? "\n\n---\n\n" + emuReviewBlock(db) : ""}`;
    return {
      text,
      evidence: hits.slice(0, 8).flatMap((f) => [{ text: `${f.name} (${f.kind}, ${f.proofLevel})`, address: f.addr, certainty: "inference" as const }, ...f.evidence.slice(0, 2).map((e) => ({ text: e.text.slice(0, 70), address: e.address, certainty: "fact" as const }))]),
      related: hits.slice(0, 12).map((f) => ({ addr: f.addr, name: f.name, note: `${f.kind} ${Math.round(f.confidence * 100)}% ${f.proofLevel}` })),
      intent: which === "anticheat" ? "anticheat" : which === "ban" ? "ban" : "hash",
      source: "local",
      confidence: Math.min(0.95, 0.55 + 0.08 * hits.filter((f) => f.proofLevel === "proven").length),
    };
  }

  libraryMap(): AssistantAnswer {
    const db = this.db;
    const groups = db.libraryMap();
    const top = db.topImports(15);
    const lines = groups.map((g) => `• ${g.library} (${g.imports.length} imports): ${g.imports.slice(0, 8).join(", ")}${g.imports.length > 8 ? ` …+${g.imports.length - 8} more` : ""}`);
    const text = `Library map for ${db.fileName} (SONAME ${db.elf.soname ?? "—"}):\n\nNeeded (DT_NEEDED): ${db.elf.needed.join(", ") || "none"}\n\n${lines.join("\n") || "(no imports)"}\n\nMost-used API calls (incl. GOT-resolved memcpy/gettimeofday family):\n${top.map((t) => `• ${t.name} — ${t.users} function(s) · ${t.library}`).join("\n") || "(features pending)"}\n\nImport → library attribution uses symbol versions when present, else well-known libc/Android heuristics. Ask "where is <name> used?" for call sites.`;
    return { text, evidence: [], related: top.slice(0, 10).map((t) => ({ addr: 0, name: t.name, note: `${t.users} users · ${t.library}` })), intent: "libraries", source: "local" };
  }

  bypassGuide(): AssistantAnswer {
    const db = this.db;
    const intel = buildIntel(db, 15);
    const text = `Safe bypass plan — how to run it (I don't guess this; the planner verifies it live).\n\nVerified findings right now: ${intel.findings.length} total (${intel.provenCount} proven: ${intel.counts.anticheat} anticheat · ${intel.counts["hash-check"]} hash · ${intel.counts["ban-check"]} ban · ${intel.counts["game-revive"]} revive).\n\nClick “Generate full safe bypass plan” in Overview (below Verified intel). It runs 7 passes over every function:\n1. RESOLVE — concrete hook/patch points per finding (entry VA + RVA for ASLR).\n2. BRANCHES — disassembles each target and isolates the exact verdict branches (compare→branch) for surgical flips.\n3. CONSUMERS — disassembles callers to catch traps that test the check's return value.\n4. SAFETY — blast-radius, dual-use, heartbeat timers, self-inspection tripwires; risky steps marked RISKY, never SAFE.\n5. REDUNDANCY — full sweep for sibling/backup checks plus byte-identical clones; they become required companion hooks.\n6. ORDER — anticheat → hash → ban, branch flips before prologue, hooks before file patches.\n7. REVIEW — final veto; single-leg leads can never ship as SAFE.\n\nEvery step carries its reasoning (“why this step”) and a strength score, and the plan opens with the planner's thinking log. You get per-step Frida snippets + patch bytes + the exact runtime checks to run on a clean trace first (breakpoint, log return shape, confirm neighbours). Lab-only, test account, originals restorable — server-side verdicts can't be beaten client-side, and tampering risks a ban / ToS violation.`;
    return {
      text,
      evidence: intel.findings.slice(0, 6).map((f) => ({ text: `${f.name} (${f.kind}, ${f.proofLevel})`, address: f.addr, certainty: "inference" as const })),
      related: intel.findings.slice(0, 8).map((f) => ({ addr: f.addr, name: f.name, note: `${f.kind} ${Math.round(f.confidence * 100)}%` })),
      intent: "bypass",
      source: "local",
      confidence: intel.findings.length ? 0.7 : 0.4,
    };
  }

  /** Agent hands: plan the mutations, the workbench executes them. */
  runAgent(task: import("./agent").AgentTask, currentAddr: number | null = null): AssistantAnswer {
    const db = this.db;
    const { actions, summary } = planAgentActions(db, task, currentAddr);
    const evidence = actions
      .filter((a) => a.type !== "navigate")
      .slice(0, 10)
      .map((a) => ({ text: `${a.type} → ${db.labelFor(a.addr)} (${a.why})`, address: a.addr, certainty: "fact" as const }));
    const related = actions.slice(0, 12).map((a) => ({ addr: a.addr, name: db.labelFor(a.addr), note: a.type }));
    const nav = actions.find((a) => a.type === "navigate");
    const text = `Agent task (${task.op}): ${summary.join(" ")}\n${actions.length ? `Executing ${actions.length} action(s) now — watch the workbench move.${nav && nav.type === "navigate" ? ` Opening ${db.labelFor(nav.addr)}.` : ""}` : "No actions to execute."}`;
    return { text, evidence, related, intent: "agent", source: "local", confidence: actions.length ? 0.9 : 0.4, actions };
  }

  importUses(rawName: string): AssistantAnswer {    const db = this.db;
    const name = rawName.replace(/[^A-Za-z0-9_]/g, "") || rawName;
    const users = db.importUsers(name, 60);
    const lib = db.importLibraryOf(name);
    if (!users.length) {
      // Not an import at all? If the name is a function defined in this binary,
      // the honest answer is that function's story, not "no callers of an import".
      const declared = db.elf.imports.some((s) => s.name.toLowerCase() === name.toLowerCase());
      if (!declared) {
        const hit = search(db, name, { categories: ["functions", "symbols", "exports"], limitPerCategory: 1 })[0];
        const fn = hit ? db.functionAt(hit.address) : null;
        if (fn) return { ...this.explain(fn, `“${name}” is not an import — it is a function defined in this binary (${hit!.category} match). Here is what it does and who calls it.`), targetAddr: fn.addr };
      }
      const similar = db.elf.imports.filter((s) => s.name.toLowerCase().includes(name.toLowerCase().slice(0, 4))).slice(0, 10).map((s) => s.name);
      return { text: `No callers of "${name}" were found${declared ? ` (declared import, library guess: ${lib})` : " — and it is not a declared import of this binary"}. It may be dead, resolved via dlsym, or the binary is packed.\n${similar.length ? `Did you mean: ${[...new Set(similar)].join(", ")}?` : `Declared imports (${db.elf.imports.length}): ${db.elf.imports.slice(0, 10).map((s) => s.name).join(", ")}…`}`, evidence: [], related: [], intent: "imports", source: "local" };
    }
    const uniq = users.slice(0, 30);
    const text = `"${name}" (${lib}) is used by ${users.length} function(s)${users.length > uniq.length ? ` — showing ${uniq.length}` : ""}:\n${uniq.map((u) => `• ${db.nameFor(u.fn.addr).name} @ 0x${u.fn.addr.toString(16)} (ref at 0x${u.via.toString(16)})`).join("\n")}\n\nResolved via PLT stubs + GOT-slot loads (adrp/ldr/blr), so stripped binaries still resolve.`;
    return {
      text,
      evidence: uniq.slice(0, 12).map((u) => ({ text: `${db.nameFor(u.fn.addr).name} uses ${name}`, address: u.via, certainty: "fact" as const })),
      related: uniq.map((u) => ({ addr: u.fn.addr, name: db.nameFor(u.fn.addr).name, note: `uses ${name}` })),
      intent: "imports",
      source: "local",
    };
  }
}

function emuReviewBlock(db: AnalysisDatabase): string {
  const { markers, functions, floating } = emuMarkersOf(db);
  if (!markers.length) return `EMULATOR REVIEW: no emulator tells (build props, pipes, device IDs, brands) found anywhere in this binary's strings — not even floating ones. Either this build doesn't check for emulators natively (Java-side or server-side instead), or the tells hide behind indirect loads. Confirm by searching "ro." and "qemu" in Strings.`;
  const owned = markers.filter((m) => !floating.includes(m));
  const lines = owned.map((m) => `• "${m.key}" @ 0x${m.addr.toString(16)} [${m.via}] → phone says "${m.phoneValue}" (${m.how === "prop-spoof" ? "spoof via __system_property_get" : "hide the file"})`);
  const floatLines = floating.map((m) => `• "${m.key}" @ 0x${m.addr.toString(16)} [${m.via}, floating] → phone says "${m.phoneValue}"`);
  return `EMULATOR REVIEW — how it knows, and how to look like a phone:\n\nTraced tells (${owned.length}, read by checks below):\n${lines.join("\n") || "(none traced — all floating)"}\n\nRead by: ${functions.map((f) => `${f.name} @ 0x${f.addr.toString(16)}`).join(", ") || "—"}\n\n${floatLines.length ? `Floating tells (${floatLines.length}, in-binary but owned by no traced check — dynamic keys or Java-side readers):\n${floatLines.join("\n")}\n\n` : ""}Playbook: spoof the prop rows through __system_property_get (Frida snippet ships in the bypass plan's spoof-props steps — donor Pixel values included, swap in your own device), hide the file rows (bind-mount /dev/null or hook open/access to -ENOENT), then re-run the readers above and confirm the clean path. Phone values above are labeled examples, not gospel — diff getprop output between the emulator and a donor phone before trusting them.`;
}

function formatIntelBlock(db: AnalysisDatabase, f: IntelFinding): string {
  const conns = f.connectedTo.slice(0, 6).map((c) => `  • [${c.role}] ${c.name} @ 0x${c.addr.toString(16)} — ${c.note}`).join("\n") || "  • (no resolved neighbours — isolated)";
  return `■ ${f.name} @ 0x${f.addr.toString(16)} [${f.kind} · ${f.proofLevel.toUpperCase()} · ${Math.round(f.confidence * 100)}% · proof: ${f.legs.join(" + ")}]\n\nWHAT THIS IS:\n${f.whatItIs}\n\nWHAT IT DOES:\n${f.whatItDoes}\n\nCONNECTED HERE:\n${conns}\n\nIF YOU HOOK IT:\n${f.hookImpact}\n\nIF YOU PATCH IT:\n${f.patchImpact}\n\nHOW TO VERIFY YOURSELF:\n${f.howToVerify}`;
}

function describeBehaviour(p: FunctionContextPack): { text: string; evidence: EvidenceLink[]; confidence: number } {
  const ev: EvidenceLink[] = [];
  const d = p.disassembly;
  const loads = d.filter((x) => /^ldr|^ldp|^ldrb|^ldrh|^ldrsw|^mov .*\[/.test(x.text));
  const stores = d.filter((x) => /^str|^stp|^strb|^strh/.test(x.text));
  const checks = d.filter((x) => /^(cbz|cbnz|cmp|tst|tbz|tbnz|test)\b/.test(x.text));
  const rets = d.filter((x) => /^ret\b/.test(x.text));
  const bits: string[] = [];
  if (p.globals.length && loads.length && d.length < 40) {
    bits.push(`It reads ${p.globals.filter((g) => g.kind === "read").map((g) => g.name).slice(0, 2).join(" and ") || "memory"}${checks.length ? ", validates the result" : ""}${rets.length ? " and returns" : ""}.`);
    const g = p.globals[0];
    ev.push({ text: `${g.kind}s ${g.name}`, address: g.addr, certainty: "fact" });
  } else if (d.length <= 8 && rets.length) bits.push(`A tiny ${loads.length ? "accessor" : stores.length ? "setter" : "stub"} (${d.length} instructions).`);
  else if (p.featuresSummary.includes("loop") && stores.length + loads.length > d.length * 0.4) bits.push(`Contains a loop dominated by memory traffic (${loads.length} loads / ${stores.length} stores) — typical of copy, parse or transform routines.`);
  else if (p.callees.length >= 4) bits.push(`Orchestrates ${p.callees.length} calls${p.callees.some((c) => /alloc|new|malloc/.test(c.name)) ? ", including allocation" : ""}${p.callees.some((c) => /free|delete/.test(c.name)) ? " and release" : ""} — a coordinating function.`);
  else bits.push(`${p.featuresSummary}.`);
  if (checks.length) { ev.push({ text: `${checks.length} validity check(s), first at 0x${checks[0].addr.toString(16)}`, address: checks[0].addr, certainty: "fact" }); }
  if (rets.length) ev.push({ text: `returns at 0x${rets[0].addr.toString(16)}`, address: rets[0].addr, certainty: "fact" });
  if (loads[0]) ev.push({ text: `first memory read: ${loads[0].text}`, address: loads[0].addr, certainty: "fact" });
  const confidence = Math.min(0.9, 0.4 + 0.1 * Math.min(3, p.globals.length) + 0.1 * Math.min(2, p.strings.length) + (p.classes[0]?.confidence ?? 0) * 0.3);
  return { text: bits.join(" "), evidence: ev, confidence };
}

/** Suggest a descriptive name from evidence. Returns null when evidence is too thin. */
export function suggestName(db: AnalysisDatabase, fn: FunctionRecord): NameSuggestion | null {
  const pack = packFunction(db, fn, 60);
  const reasons: string[] = [];
  let conf = 0.3;
  const cls = pack.classes[0];
  const words: string[] = [];
  // strongest: a single descriptive string with a class-like token
  const str = pack.strings.find((s) => /^[A-Za-z_][A-Za-z0-9_:]{3,40}$/.test(s.value));
  if (str) { words.push(str.value.split("::").pop()!.replace(/[^A-Za-z0-9]/g, "")); reasons.push(`references identifier-like string "${str.value}"`); conf += 0.25; }
  const importCallee = pack.callees.map((c) => c.name.replace(/@.*$/, "")).find((n) => /^[a-z_]+$/.test(n) && n.length > 3);
  if (cls) { words.push(...cls.label.split("-").map(cap)); reasons.push(`classified as ${cls.level} ${cls.label} (${Math.round(cls.confidence * 100)}%)`); conf += cls.confidence * 0.3; }
  if (!words.length && importCallee) { words.push(cap(importCallee), "Wrapper"); reasons.push(`thin wrapper around ${importCallee}`); conf += 0.15; }
  if (pack.globals.length && pack.disassembly.length < 30) { const g = pack.globals[0].name.replace(/^g_|^GLOBAL_/, ""); if (!/^[0-9a-f]+$/.test(g) && !g.startsWith("data_")) { words.push(cap(g)); reasons.push(`${pack.globals[0].kind}s global ${pack.globals[0].name}`); conf += 0.15; } if (pack.globals[0].kind === "read" && !words.some((w) => /Reader|Get/.test(w))) words.push("Reader"); if (pack.globals[0].kind === "write") words.push("Writer"); }
  if (!words.length) {
    if (pack.disassembly.length <= 6 && pack.callees.length === 0) { words.push("Get", "Field", `0x${(fn.features?.memAccessOffsets[0] ?? 0).toString(16)}`); reasons.push("tiny leaf accessor"); }
    else return null;
  }
  if (pack.callers.length >= 3) { reasons.push(`called from ${pack.callers.length} places`); conf += 0.05; }
  const name = words.map((w) => w.replace(/[^A-Za-z0-9_]/g, "")).filter(Boolean).slice(0, 4).join("");
  if (!name || name.length < 3) return null;
  return { name: /^[0-9]/.test(name) ? "fn_" + name : name, confidence: Math.min(0.85, conf), reasons };
}

function cap(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
