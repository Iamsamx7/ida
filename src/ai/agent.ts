import type { AnalysisDatabase } from "../core/analysis/database";
import { buildIntel, type IntelKind } from "../core/analysis/intel";
import { search } from "../core/search/engine";

export type AgentAction =
  | { type: "navigate"; addr: number; tab?: "disasm" | "pseudo" | "hex"; why: string }
  | { type: "bookmark"; addr: number; label: string; why: string }
  | { type: "tag"; addr: number; tag: string; why: string }
  | { type: "rename"; addr: number; name: string; why: string }
  | { type: "comment"; addr: number; body: string; scope: "line" | "function"; why: string };

/**
 * A parsed order. `addr` undefined + `target` undefined means "the function
 * under the cursor" — resolved by planAgentActions, which is the only place
 * that sees the database and the current selection.
 */
export type AgentTask =
  | { op: "bookmark-kind"; kind: IntelKind | "all" }
  | { op: "tag-kind"; kind: IntelKind | "all"; tag: string }
  | { op: "goto-kind"; kind: IntelKind }
  | { op: "goto"; addr?: number; name?: string }
  | { op: "recon" }
  | { op: "bookmark-here"; addr?: number; target?: string }
  | { op: "tag-here"; addr?: number; target?: string; tag: string }
  | { op: "rename"; addr?: number; target?: string; name: string }
  | { op: "comment"; addr?: number; target?: string; body: string; scope: "line" | "function" };

const KIND_WORDS: { re: RegExp; kind: IntelKind | "all" }[] = [
  { re: /anti[\s_-]?cheat|antidebug|integrity|emulator|tamper/, kind: "anticheat" },
  { re: /\bban(ned|s)?\b|punish|suspend/, kind: "ban-check" },
  { re: /\bhash(es|ing)?\b|checksum|digest/, kind: "hash-check" },
  { re: /revive|respawn|heal/, kind: "game-revive" },
];

const TAG_FILLER = new Set(["all", "every", "these", "those", "them", "findings", "finding", "checks", "check", "hits", "function", "functions", "this", "it", "here", "current", "selected", "the", "as", "with", "tag", "anticheat", "anti", "cheat", "ban", "hash", "revive", "integrity", "and", "to", "please"]);
const SELF_WORDS = /^(this|it|here|the|current|selected|function|routine|address|addr)$/i;
const IDENT = /^[A-Za-z_][A-Za-z0-9_:.@$]*$/;

/** Tag name from "tag … as X" / "tag … with #X" / "tag this X". */
export function parseTagName(q: string): string | null {
  const m = q.match(/\b(?:as|with|named|called)\s+[#"“'`]?([A-Za-z][A-Za-z0-9_-]{0,31})/i) ?? q.match(/#([A-Za-z][A-Za-z0-9_-]{0,31})/);
  if (m) return m[1];
  const words = q.trim().replace(/[.!?]+$/, "").split(/\s+/);
  const last = (words[words.length - 1] ?? "").replace(/[^A-Za-z0-9_-]/g, "");
  if (words.length >= 2 && last && !TAG_FILLER.has(last.toLowerCase()) && !/^0x/i.test(last)) return last;
  return null;
}

/** Parse an action command. Returns null when the text is a plain question. */
export function parseAgentTask(q: string): AgentTask | null {
  const raw = q.trim();
  const t = raw.toLowerCase();
  const addrM = t.match(/\b0x[0-9a-f]+\b/);
  const addr = addrM ? parseInt(addrM[0], 16) : undefined;
  const kindOf = (): IntelKind | "all" => {
    for (const k of KIND_WORDS) if (k.re.test(t)) return k.kind;
    return "all";
  };
  const many = /\b(all|every|these|those|findings|checks|hits)\b/.test(t);
  // Named target ("rename sub_1234 to …", "bookmark net_send") — never a self word or an address.
  const targetOf = (s: string | undefined): string | undefined => (s && !SELF_WORDS.test(s) && !/^0x/i.test(s) && IDENT.test(s) ? s : undefined);

  if (/^(bookmark|mark|save)\b/.test(t)) {
    if (many) return { op: "bookmark-kind", kind: kindOf() };
    const m = raw.match(/^(?:bookmark|mark|save)\s+(?:this|it|here|the current function|the|function\s+|address\s+)?\s*([A-Za-z_][A-Za-z0-9_:.@$]*|0x[0-9a-fA-F]+)?\s*[.!]*$/i);
    return { op: "bookmark-here", addr, target: targetOf(m?.[1]) };
  }
  if (/^tag\b/.test(t)) {
    const tag = parseTagName(raw) ?? "review";
    if (many) return { op: "tag-kind", kind: kindOf(), tag };
    const m = raw.match(/^tag\s+([A-Za-z_][A-Za-z0-9_:.@$]*|0x[0-9a-fA-F]+)\b/i);
    const target = targetOf(m?.[1]);
    return { op: "tag-here", addr, target: target && target.toLowerCase() !== tag.toLowerCase() ? target : undefined, tag };
  }
  if (/^(take me to|go ?to|jump to|navigate to|show me|open)\b/.test(t) && /\b(best|top|first|main|strongest)\b/.test(t)) {
    const k = kindOf();
    return { op: "goto-kind", kind: (k === "all" ? "anticheat" : k) as IntelKind };
  }
  const gm = raw.match(/^(?:take me to|go ?to|jump to|navigate to|open)\s+(.+?)\s*[.!?]*$/i);
  if (gm) {
    const target = gm[1].trim().replace(/^(?:the\s+)?(?:function|address|addr|symbol)\s+/i, "");
    const am = target.match(/^0x([0-9a-f]+)$/i) ?? target.match(/^([0-9a-f]{4,16})$/i);
    if (am) return { op: "goto", addr: parseInt(am[1], 16) };
    if (IDENT.test(target) && !/^(this|it|here)$/i.test(target)) return { op: "goto", name: target };
  }
  if (/^(recon|survey|hunt.*mark|fully? analy[sz]e|tear.*apart|map.*(for|and).*mark)/.test(t)) return { op: "recon" };
  if (/\brename\b/.test(t)) {
    const m = raw.match(/\brename\s+(?:(this|it|the|current|selected)\s+)?(?:(function|routine)\s+)?(0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_:.@$]*)?\s*(?:to|as|→|->|=)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[.!]*$/i);
    if (m) return { op: "rename", addr, target: targetOf(m[3]), name: m[4] };
  }
  if (/^(comment|note|annotate)\b/.test(t) || (addr !== undefined && /\bcomment\b/.test(t))) {
    const m = raw.match(/\b(?:comment|note|annotate)\s+(?:on\s+)?(?:(this function|the current function|this|it|here)|(0x[0-9a-fA-F]+)|([A-Za-z_][A-Za-z0-9_:.@$]*)(?=\s*[:\-–]))?\s*[:\-–]?\s*(.+)$/i);
    const body = m?.[4]?.trim().replace(/^["“]|["”]$/g, "");
    if (body) return { op: "comment", addr, target: targetOf(m?.[3]), body: body.slice(0, 500), scope: /\bfunction\b/i.test(t) ? "function" : "line" };
  }
  return null;
}

/**
 * The agent's hands: turns a task into concrete, bounded actions against the
 * database. The UI executes them (navigate/bookmark/tag/rename/comment) and
 * reports back. Read-only planning here — mutation happens in the workbench.
 */
export function planAgentActions(db: AnalysisDatabase, task: AgentTask, currentAddr: number | null = null): { actions: AgentAction[]; summary: string[] } {
  const hex = (n: number) => "0x" + n.toString(16);
  const actions: AgentAction[] = [];
  const summary: string[] = [];
  const cursorFn = currentAddr !== null ? db.functionAt(currentAddr) : null;
  /** Resolve an explicit address / name / the cursor to an address; `entry` snaps to the owning function's start. */
  const resolve = (addr: number | undefined, target: string | undefined, entry: boolean): { addr: number; how: string } | { error: string } => {
    if (addr !== undefined) {
      const f = db.functionAt(addr);
      if (entry && f) return { addr: f.addr, how: f.addr === addr ? "explicit address" : `inside ${db.nameFor(f.addr).name}` };
      if (db.space.isMapped(addr)) return { addr, how: "explicit address" };
      return { error: `${hex(addr)} is not mapped in this binary — check the base (offsets here are VA, use module+0x… in Go To for RVAs).` };
    }
    if (target) {
      const hit = search(db, target, { categories: ["functions", "symbols", "exports", "imports", "globals", "strings", "tags", "bookmarks"], limitPerCategory: 2 })[0];
      if (!hit) return { error: `Nothing named “${target}” in this binary (searched functions, symbols, imports, globals, strings).` };
      const f = db.functionAt(hit.address);
      return { addr: entry && f ? f.addr : hit.address, how: `${hit.category} “${hit.title}”` };
    }
    if (entry && cursorFn) return { addr: cursorFn.addr, how: "function under the cursor" };
    if (currentAddr !== null && db.space.isMapped(currentAddr)) return { addr: currentAddr, how: "cursor" };
    return { error: "Nothing is selected — click a function first, or name it (e.g. “rename sub_1a2b0 to handle_ban”)." };
  };
  const pick = (kind: IntelKind | "all") => {
    const list = buildIntel(db, 12).findings.filter((f) => kind === "all" || f.kind === kind);
    list.sort((a, b) => (b.proofLevel === "proven" ? 1 : 0) - (a.proofLevel === "proven" ? 1 : 0) || b.confidence - a.confidence);
    return list.slice(0, 10);
  };
  switch (task.op) {
    case "bookmark-kind": {
      const hits = pick(task.kind);
      if (!hits.length) return { actions, summary: [`Nothing worth bookmarking for ${task.kind} — nothing cleared the proof bar.`] };
      for (const f of hits) actions.push({ type: "bookmark", addr: f.addr, label: `${f.name} [${f.kind}]`, why: `${f.proofLevel} ${Math.round(f.confidence * 100)}%` });
      summary.push(`Marking ${hits.length} ${task.kind} finding(s) (${hits.filter((f) => f.proofLevel === "proven").length} proven) so you can walk them from Bookmarks.`);
      break;
    }
    case "tag-kind": {
      const hits = pick(task.kind);
      if (!hits.length) return { actions, summary: [`Nothing to tag for ${task.kind}.`] };
      for (const f of hits) actions.push({ type: "tag", addr: f.addr, tag: task.tag, why: f.kind });
      summary.push(`Tagging ${hits.length} ${task.kind} finding(s) with #${task.tag}.`);
      break;
    }
    case "goto-kind": {
      const hits = pick(task.kind);
      if (!hits.length) return { actions, summary: [`No ${task.kind} target to jump to — nothing cleared the proof bar.`] };
      const f = hits[0];
      actions.push({ type: "navigate", addr: f.addr, tab: "disasm", why: `best ${task.kind} hit: ${f.proofLevel} ${Math.round(f.confidence * 100)}%` });
      summary.push(`Taking you to ${f.name} @ ${hex(f.addr)} — best ${task.kind} hit (${f.proofLevel}, ${Math.round(f.confidence * 100)}%). ${hits.length - 1} more waiting; say “bookmark all ${task.kind}” to mark them.`);
      break;
    }
    case "goto": {
      const r = resolve(task.addr, task.name, false);
      if ("error" in r) return { actions, summary: [r.error] };
      const isCode = db.space.isExec(r.addr);
      actions.push({ type: "navigate", addr: r.addr, tab: isCode ? "disasm" : "hex", why: r.how });
      summary.push(`Opening ${db.labelFor(r.addr)} @ ${hex(r.addr)} (${r.how}) in ${isCode ? "disassembly" : "hex"}.`);
      break;
    }
    case "recon": {
      const intel = buildIntel(db, 12);
      const top = intel.findings.slice(0, 5);
      if (top.length) {
        actions.push({ type: "navigate", addr: top[0].addr, tab: "disasm", why: "recon anchor: strongest finding" });
        for (const f of intel.findings.filter((x) => x.proofLevel === "proven").slice(0, 6))
          actions.push({ type: "bookmark", addr: f.addr, label: `${f.name} [${f.kind}]`, why: "proven — recon sweep" });
      }
      summary.push(
        `Recon sweep: ${intel.findings.length} findings (${intel.provenCount} proven) across anticheat/hash/ban/revive.`,
        top.length ? `Anchored on ${top[0].name} @ ${hex(top[0].addr)} [${top[0].kind}, ${top[0].proofLevel}].` : "Nothing cleared the proof bar.",
        intel.provenCount ? `Proven hits bookmarked — walk them from Bookmarks, or say “plan a safe bypass” and I'll brief the strike order.` : `Nothing is proven yet (needs two semantic witnesses: strings + imports). Corroborated leads are listed in “where is anticheat?” — verify them live before trusting.`,
      );
      break;
    }
    case "bookmark-here": {
      const r = resolve(task.addr, task.target, true);
      if ("error" in r) return { actions, summary: [r.error] };
      actions.push({ type: "bookmark", addr: r.addr, label: db.labelFor(r.addr), why: r.how });
      summary.push(`Bookmarking ${db.labelFor(r.addr)} @ ${hex(r.addr)} (${r.how}).`);
      break;
    }
    case "tag-here": {
      const r = resolve(task.addr, task.target, true);
      if ("error" in r) return { actions, summary: [r.error] };
      actions.push({ type: "tag", addr: r.addr, tag: task.tag, why: r.how });
      summary.push(`Tagging ${db.labelFor(r.addr)} @ ${hex(r.addr)} with #${task.tag}.`);
      break;
    }
    case "rename": {
      const r = resolve(task.addr, task.target, true);
      if ("error" in r) return { actions, summary: [r.error] };
      const cur = db.nameFor(r.addr);
      if (cur.source === "symbol") summary.push(`Note: ${cur.name} is a real symbol — the rename is a display override, the export name stays ${cur.name}.`);
      actions.push({ type: "rename", addr: r.addr, name: task.name, why: `explicit rename (${cur.name} → ${task.name})` });
      summary.push(`Renaming ${cur.name} @ ${hex(r.addr)} → ${task.name}. Undo any time with F2 (empty name reverts).`);
      break;
    }
    case "comment": {
      const r = resolve(task.addr, task.target, task.scope === "function");
      if ("error" in r) return { actions, summary: [r.error] };
      actions.push({ type: "comment", addr: r.addr, body: task.body, scope: task.scope, why: "explicit note" });
      summary.push(`Noting @ ${hex(r.addr)} (${task.scope}): “${task.body.slice(0, 80)}”.`);
      break;
    }
  }
  return { actions, summary };
}
