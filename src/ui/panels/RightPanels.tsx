"use client";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useWorkbench, hex } from "../store";
import { Badge, Button, Input, PanelHeader, confidenceTone } from "../primitives";
import { XREF_KIND_NAMES, type XrefKind } from "@/core/analysis/types";
import type { AssistantAnswer } from "@/ai/assistant";
import { suggestName } from "@/ai/assistant";
import { buildLlmContext } from "@/ai/context";
import { parseChatEvent, sanitizeHistory, type ChatRequest } from "@/ai/chatProtocol";

const KV = ({ k, v }: { k: string; v: React.ReactNode }) => <div className="flex justify-between gap-3 border-b border-zinc-900 py-1 text-[12px]"><span className="text-zinc-500">{k}</span><span className="truncate text-right font-mono text-zinc-200">{v}</span></div>;

export function FunctionInfoPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const addr = wb.currentAddr;
  const fn = addr !== null ? db.functionAt(addr) : null;
  const info = addr !== null ? db.space.info(addr) : null;
  const [tagInput, setTagInput] = useState("");
  const suggestion = useMemo(() => (fn && fn.nameSource === "inferred" && fn.features ? suggestName(db, fn) : null), [db, fn, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  if (addr === null || !info) return <div className="p-3 text-[12px] text-zinc-500">Nothing selected.</div>;
  const name = db.nameFor(addr);
  const str = db.stringAt(addr);
  return (
    <div className="h-full overflow-auto p-3">
      <PanelHeader title="Address" />
      <KV k="Virtual address" v={hex(addr)} />
      <KV k="RVA (module+)" v={hex(info.rva)} />
      <KV k="File offset" v={info.fileOffset !== null ? hex(info.fileOffset) : "unmapped"} />
      <KV k="Section" v={info.section ? `${info.section.name} + ${hex(info.sectionOffset ?? 0)}` : "—"} />
      <KV k="Segment" v={info.segment ? `${info.segment.typeName} #${info.segment.index} (${info.segment.perms}) + ${hex(info.segmentOffset ?? 0)}` : "—"} />
      <KV k="Label" v={<span className={name.source === "user" ? "text-violet-300" : name.source === "symbol" ? "text-emerald-300" : name.source === "ai" ? "text-cyan-300" : "text-zinc-300"}>{db.labelFor(addr)}</span>} />
      {str && <KV k="String" v={<span className="text-emerald-200">&quot;{str.value.slice(0, 60)}&quot; ({str.encoding}, {str.category})</span>} />}
      {fn && (<>
        <PanelHeader title="Function" right={<><Button onClick={() => wb.setRenameTarget(fn.addr)}>Rename</Button><Button onClick={() => wb.setCommentTarget(-fn.addr)}>Comment</Button></>} />
        <div className="my-2 flex flex-wrap gap-1">
          <Badge tone={fn.nameSource === "user" ? "violet" : fn.nameSource === "symbol" ? "emerald" : fn.nameSource === "ai" ? "cyan" : "zinc"}>{fn.nameSource === "symbol" ? "known symbol" : fn.nameSource === "user" ? "user-renamed" : fn.nameSource === "ai" ? "ai-suggested (accepted)" : "inferred function"}</Badge>
          <Badge tone={confidenceTone(fn.confidence)} title={fn.sources.join(", ")}>confidence {Math.round(fn.confidence * 100)}%</Badge>
          <Badge tone="cyan" onClick={() => wb.setRightTab("xrefs")}>xref {fn.callerCount}</Badge>
          {fn.features?.hasLoop && <Badge>loop</Badge>}
          {fn.isImportStub && <Badge tone="amber">plt stub</Badge>}
          {[...(db.tags.get(fn.addr) ?? [])].map((t) => <Badge key={t} tone="violet" onClick={() => wb.removeTag(fn.addr, t)}>#{t} ✕</Badge>)}
        </div>
        <KV k="Start" v={hex(fn.addr)} />
        <KV k="Size" v={`${fn.size} bytes · ${fn.insnCount || Math.floor(fn.size / 4)} insns`} />
        <KV k="Discovery evidence" v={fn.sources.join(", ")} />
        <KV k="Callers / callees" v={`${fn.callerCount} / ${fn.calleeCount}`} />
        {fn.features && <KV k="Instruction mix" v={`${fn.features.branchCount} br · ${fn.features.callCount} call · ${fn.features.loadCount} ld · ${fn.features.storeCount} st`} />}
        {db.functionComments.get(fn.addr) && <div className="mt-2 rounded border border-emerald-900/50 bg-emerald-950/20 p-2 text-[12px] text-emerald-200">{db.functionComments.get(fn.addr)}</div>}
        <div className="mt-2 flex gap-1"><Input value={tagInput} onChange={(e) => setTagInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && tagInput) { wb.addTag(fn.addr, tagInput); setTagInput(""); } }} placeholder="add tag (Networking, Important, Investigate…)" className="w-full" /></div>

        <PanelHeader title="Semantic classification" />
        {!fn.classes?.length && <div className="py-2 text-[12px] text-zinc-500">{fn.classes ? "No classification — no matching evidence." : "Pending…"}</div>}
        {fn.classes?.map((c) => (
          <div key={c.label} className="mb-2 rounded border border-zinc-800 bg-zinc-900/40 p-2">
            <div className="flex items-center gap-2 text-[12px]"><Badge tone={confidenceTone(c.confidence)}>{c.level}</Badge><span className="font-medium text-zinc-100">{c.label}</span><span className="ml-auto text-zinc-500">{Math.round(c.confidence * 100)}%</span></div>
            <div className="mt-1 space-y-0.5">{c.evidence.map((e, i) => <div key={i} className="text-[11px] text-zinc-400">• <span className="text-zinc-600">[{e.certainty}]</span> {e.address !== undefined ? <button className="text-left text-sky-400 hover:underline" onClick={() => wb.navigate(e.address!)}>{e.text}</button> : e.text}</div>)}</div>
          </div>
        ))}
        {suggestion && (
          <div className="mt-2 rounded border border-cyan-900/60 bg-cyan-950/20 p-2 text-[12px]">
            <div className="flex items-center gap-2"><Badge tone="cyan">AI suggestion</Badge><span className="font-mono text-cyan-200">{suggestion.name}</span><span className="ml-auto text-zinc-500">{Math.round(suggestion.confidence * 100)}%</span></div>
            <div className="mt-1 text-[11px] text-zinc-400">{suggestion.reasons.map((r, i) => <div key={i}>• {r}</div>)}</div>
            <div className="mt-2 flex gap-1"><Button tone="emerald" onClick={() => { wb.rename(fn.addr, suggestion.name, "ai-accepted"); void wb.recordObservation({ address: fn.addr, kind: "name-suggestion", content: suggestion.name, confidence: suggestion.confidence, evidence: suggestion.reasons.map((r) => ({ text: r })) }).then((o) => wb.setVerdict(o, "accepted")); }}>Accept name</Button><Button onClick={() => wb.setRenameTarget(fn.addr)}>Edit…</Button></div>
          </div>
        )}
      </>)}
    </div>
  );
}

export function XrefsPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const addr = wb.currentAddr;
  const [kindFilter, setKindFilter] = useState<XrefKind | 0>(0);
  const data = useMemo(() => {
    if (addr === null) return null;
    const fn = db.functionAt(addr);
    const exact = db.xrefs.refsTo(addr, 5000);
    const toFn = fn && fn.addr !== addr ? db.xrefs.refsTo(fn.addr, 5000) : [];
    const from = fn ? db.xrefs.refsFromRange(fn.addr, fn.addr + fn.size, 5000) : [];
    return { fn, exact, toFn, from };
  }, [db, addr, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!data || addr === null) return <div className="p-3 text-[12px] text-zinc-500">Nothing selected.</div>;
  const Row = ({ a, b, k, dir }: { a: number; b: number; k: XrefKind; dir: "in" | "out" }) => {
    const target = dir === "in" ? a : b;
    const s = db.stringAt(target);
    const label = s ? `"${s.value.slice(0, 50)}"` : k === 3 && db.gotNames.has(target) ? `${db.callNameFor(target)} [import]` : db.labelFor(target);
    return (
      <button onClick={() => wb.navigate(target, { tab: s || (!db.space.isExec(target)) ? "hex" : "disasm" })} className="flex w-full items-center gap-2 px-2 py-[2px] text-left font-mono text-[12px] hover:bg-zinc-800/60">
        <Badge tone={k === 1 ? "sky" : k === 2 ? "amber" : k === 4 ? "rose" : k === 7 ? "emerald" : k === 6 ? "violet" : "zinc"}>{k === 3 && db.gotNames.has(target) ? "import" : XREF_KIND_NAMES[k]}</Badge>
        <span className="text-zinc-500">{target.toString(16)}</span>
        <span className="truncate text-zinc-200">{label}</span>
      </button>
    );
  };
  const filt = (xs: { from: number; to: number; kind: XrefKind }[]) => (kindFilter ? xs.filter((x) => x.kind === kindFilter) : xs);
  const callees = filt(data.from).filter((x) => x.kind === 1 || (x.kind === 2 && data.fn && !db.contains(data.fn, x.to)) || (x.kind === 3 && db.gotNames.has(x.to)));
  const reads = filt(data.from).filter((x) => x.kind === 3 || x.kind === 5 || x.kind === 7);
  const writes = filt(data.from).filter((x) => x.kind === 4);
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={`XREFs · ${db.labelFor(addr)}`} right={<select value={kindFilter} onChange={(e) => setKindFilter(Number(e.target.value) as XrefKind | 0)} className="h-6 rounded border border-zinc-700 bg-zinc-900 text-[11px] text-zinc-300"><option value={0}>all kinds</option>{Object.entries(XREF_KIND_NAMES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>} />
      <div className="flex-1 overflow-auto">
        <Group title={`References to this address (${filt(data.exact).length})`}>{filt(data.exact).map((x, i) => <Row key={i} a={x.from} b={x.to} k={x.kind} dir="in" />)}</Group>
        {data.fn && data.fn.addr !== addr && <Group title={`Callers of ${db.nameFor(data.fn.addr).name} (${filt(data.toFn).length})`}>{filt(data.toFn).map((x, i) => <Row key={i} a={x.from} b={x.to} k={x.kind} dir="in" />)}</Group>}
        {data.fn && (<>
          <Group title={`Callees (${callees.length})`}>{callees.map((x, i) => <Row key={i} a={x.from} b={x.to} k={x.kind} dir="out" />)}</Group>
          <Group title={`Reads / references (${reads.length})`}>{reads.map((x, i) => <Row key={i} a={x.from} b={x.to} k={x.kind} dir="out" />)}</Group>
          <Group title={`Writes (${writes.length})`}>{writes.map((x, i) => <Row key={i} a={x.from} b={x.to} k={x.kind} dir="out" />)}</Group>
        </>)}
      </div>
    </div>
  );
}
function Group({ title, children }: { title: string; children: React.ReactNode[] }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="border-b border-zinc-800">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-400 hover:text-zinc-200">{open ? "▾" : "▸"} <span className="ml-1">{title}</span></button>
      {open && (children.length ? children : <div className="px-2 pb-1 text-[11px] text-zinc-600">none</div>)}
    </div>
  );
}

interface Msg {
  id: number;
  role: "user" | "assistant";
  text: string;
  answer?: AssistantAnswer;
  /** LLM prose, grows while streaming. */
  llmText?: string;
  llmMeta?: { model?: string; servedBy?: string | null; refusal?: string; error?: string; streaming?: boolean };
  /** LLM request in flight. */
  pending?: boolean;
  revealed?: number;
  agentLog?: string[];
}

/** Delay between revealed reasoning steps — cosmetic; the LLM request is already running underneath. */
const REVEAL_MS = 120;

export function AIPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  const [agentOn, setAgentOn] = useState(true);
  const [thinkingId, setThinkingId] = useState<number | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(1);
  /** In-flight LLM requests by answer id, so Stop / unmount can abort them. */
  const inflight = useRef<Map<number, AbortController>>(new Map());
  useEffect(() => () => { for (const c of inflight.current.values()) c.abort(); }, []);
  // Messages are keyed by id (not array index) so concurrent questions patch the right bubble.
  const patchMsg = (id: number, f: (m: Msg) => Msg) => setMsgs((m) => m.map((x) => (x.id === id ? f(x) : x)));
  /** Agent hands: execute the assistant's proposed actions against the workbench. */
  const runAgentActions = (answerId: number, actions: NonNullable<AssistantAnswer["actions"]>) => {
    const log: string[] = [];
    for (const a of actions) {
      try {
        if (a.type === "navigate") { wb.navigate(a.addr, { tab: a.tab ?? "disasm" }); log.push(`→ opened ${db.labelFor(a.addr)} (${a.why})`); }
        else if (a.type === "bookmark") { wb.toggleBookmark(a.addr, a.label, "function"); log.push(`★ bookmarked ${db.labelFor(a.addr)}`); }
        else if (a.type === "tag") { wb.addTag(a.addr, a.tag); log.push(`#${a.tag} on ${db.labelFor(a.addr)}`); }
        else if (a.type === "rename") { wb.rename(a.addr, a.name, "ai-accepted"); log.push(`✎ renamed ${hex(a.addr)} → ${a.name}`); }
        else if (a.type === "comment") { wb.setComment(a.addr, a.body, a.scope); log.push(`✎ noted @ ${hex(a.addr)}`); }
      } catch (e) { log.push(`✗ ${a.type} failed: ${String(e)}`); }
    }
    patchMsg(answerId, (x) => ({ ...x, agentLog: [...(x.agentLog ?? []), ...log] }));
  };
  /** Stream the provider's answer into the bubble. Context is chosen by intent, history by what was actually said. */
  const askLLM = async (answerId: number, q: string, local: AssistantAnswer, prior: Msg[]) => {
    const ctrl = new AbortController();
    inflight.current.set(answerId, ctrl);
    const history = sanitizeHistory(prior.filter((m) => !m.pending).map((m) => ({ role: m.role, content: m.role === "assistant" ? m.llmText || m.text : m.text })));
    const req: ChatRequest = { question: q, contextText: buildLlmContext(db, local, wb.currentAddr), localAnswer: local.text, history };
    let acc = "";
    const fail = (error: string) => patchMsg(answerId, (m) => ({ ...m, pending: false, llmMeta: { ...m.llmMeta, streaming: false, error } }));
    try {
      const r = await fetch("/api/ai/chat", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(req), signal: ctrl.signal });
      if (!r.ok || !r.body) { fail(`HTTP ${r.status}`); return; }
      if (!(r.headers.get("content-type") ?? "").includes("ndjson")) {
        const j = (await r.json()) as { error?: string };
        fail(j.error ?? "provider not configured");
        return;
      }
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const ev = parseChatEvent(buf.slice(0, nl));
          buf = buf.slice(nl + 1);
          if (!ev) continue;
          if (ev.t === "start") patchMsg(answerId, (m) => ({ ...m, llmMeta: { ...m.llmMeta, model: ev.model, streaming: true } }));
          else if (ev.t === "delta") { acc += ev.text; const snap = acc; patchMsg(answerId, (m) => ({ ...m, llmText: snap })); }
          else if (ev.t === "done") { const finalText = ev.text || acc; patchMsg(answerId, (m) => ({ ...m, pending: false, llmText: finalText || m.llmText, llmMeta: { ...m.llmMeta, servedBy: ev.servedBy, streaming: false } })); }
          else if (ev.t === "refusal") patchMsg(answerId, (m) => ({ ...m, pending: false, llmMeta: { ...m.llmMeta, streaming: false, refusal: `The model declined this request${ev.category ? ` (${ev.category})` : ""}${ev.explanation ? `: ${ev.explanation}` : "."} The local evidence answer above still stands.` } }));
          else if (ev.t === "error") fail(ev.error);
        }
      }
      patchMsg(answerId, (m) => (m.pending ? { ...m, pending: false, llmMeta: { ...m.llmMeta, streaming: false, error: m.llmText ? undefined : "stream ended without a result" } } : m));
    } catch (e) {
      const aborted = e instanceof DOMException && e.name === "AbortError";
      patchMsg(answerId, (m) => ({ ...m, pending: false, llmMeta: { ...m.llmMeta, streaming: false, error: aborted ? (m.llmText ? "stopped" : "cancelled") : String(e) } }));
    } finally {
      inflight.current.delete(answerId);
    }
  };
  const ask = async (q: string) => {
    if (!wb.assistant || !q.trim()) return;
    const userId = nextId.current++;
    const answerId = nextId.current++;
    const prior = msgs;
    // 1. Show the question + a live "thinking…" bubble immediately.
    setMsgs((m) => [...m, { id: userId, role: "user", text: q }, { id: answerId, role: "assistant", text: "", revealed: 0 }]);
    setThinkingId(answerId);
    // 2. Verified local answer (fast). Orders and the help card never go to the LLM — nothing to add.
    const local = wb.assistant.answer(q, wb.currentAddr);
    const wantLLM = useLLM && !!wb.llm?.configured && local.intent !== "agent" && local.intent !== "help";
    // 3. Start the slow leg now; the step reveal below runs alongside it.
    if (wantLLM) { patchMsg(answerId, (m) => ({ ...m, pending: true })); void askLLM(answerId, q, local, prior); }
    const steps = local.reasoning ?? [];
    for (let i = 1; i <= steps.length; i++) {
      await new Promise((r) => setTimeout(r, REVEAL_MS));
      const snapshot = steps.slice(0, i);
      patchMsg(answerId, (m) => ({ ...m, answer: { ...local, reasoning: snapshot }, revealed: i }));
    }
    patchMsg(answerId, (m) => ({ ...m, text: local.text, answer: local, revealed: steps.length }));
    setThinkingId(null);
    // Agent hands: act on the workbench when the answer proposes actions.
    if (agentOn && local.actions?.length) runAgentActions(answerId, local.actions);
    if (local.nameSuggestion && wb.currentAddr !== null) void wb.recordObservation({ address: db.functionAt(wb.currentAddr)?.addr ?? wb.currentAddr, kind: "name-suggestion", content: local.nameSuggestion.name, confidence: local.nameSuggestion.confidence, evidence: local.nameSuggestion.reasons.map((r) => ({ text: r })) });
  };
  useEffect(() => {
    if (!wb.activeQuestion) return;
    const q = wb.activeQuestion;
    wb.clearActiveQuestion();
    void ask(q);
  }, [wb.activeQuestion]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { endRef.current?.scrollIntoView({ block: "end" }); }, [msgs]);
  const chips = ["⚡ Agent recon", "What does this function do?", "What calls this?", "Why did you classify this?", "Suggest a name", "Find similar functions", "Where is anticheat?", "Where are ban checks?", "Where are hash checks?", "Which libraries does this use?", "Where is memcpy used?", "Where is gettimeofday used?", "Plan a safe bypass", "Verify my patch", "Overview of this binary", "help"];
  const copy = (s: string) => void navigator.clipboard.writeText(s);
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title="AI assistant" right={<span className="flex items-center gap-2 text-[10px] text-zinc-500"><span className={`h-1.5 w-1.5 rounded-full ${wb.llm?.configured ? "bg-emerald-500" : "bg-amber-500"}`} />{wb.llm?.configured ? `${wb.llm.provider} · ${wb.llm.model}` : "local evidence engine (no LLM key)"}<label className="flex items-center gap-1" title="Agent hands: let the AI navigate, bookmark, tag, rename and comment directly"><input type="checkbox" checked={agentOn} onChange={(e) => setAgentOn(e.target.checked)} />agent</label>{wb.llm?.configured && <label className="flex items-center gap-1" title="Send the verified local answer + structured context to the configured LLM for a second opinion"><input type="checkbox" checked={useLLM} onChange={(e) => setUseLLM(e.target.checked)} />LLM</label>}</span>} />
      <div className="flex-1 overflow-auto p-3 text-[12px]">
        {!msgs.length && <div className="text-zinc-500">Ask about the current function or the whole binary — or give the agent orders (“recon”, “bookmark all anticheat”, “take me to the best hash check”, “tag all ban as evil”, “go to net_send”, “rename this to …”). With <span className="text-zinc-300">agent</span> on, it acts on the workbench, not just talks. Type <span className="text-zinc-300">help</span> for the full list.<div className="mt-3 flex flex-wrap gap-1">{chips.map((c) => <button key={c} onClick={() => { if (c === "⚡ Agent recon") void ask("recon"); else if (c === "Verify my patch") wb.setCenterTab("overview"); else void ask(c); }} className="rounded-full border border-zinc-700 px-2 py-0.5 text-[11px] text-zinc-300 hover:border-sky-600 hover:text-white">{c}</button>)}</div></div>}
        {msgs.map((m) => (
          <div key={m.id} className={`mb-3 ${m.role === "user" ? "text-right" : ""}`}>
            {m.role === "user" ? <span className="inline-block rounded-lg bg-sky-700/40 px-3 py-1.5 text-sky-100">{m.text}</span> : (
              <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
                <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-wider text-zinc-500"><span>{m.answer?.intent ?? (m.id === thinkingId ? "thinking" : "")}</span>{m.answer?.confidence !== undefined && <Badge tone={confidenceTone(m.answer.confidence)}>confidence {Math.round(m.answer.confidence * 100)}%</Badge>}{m.answer?.verdict && <Badge tone={m.answer.verdict.startsWith("verified — multiple") || m.answer.verdict.startsWith("verified — summary") ? "emerald" : m.answer.verdict.startsWith("verified") ? "sky" : m.answer.verdict.startsWith("partially") ? "amber" : m.answer.verdict.startsWith("n/a") ? "zinc" : "rose"}>{m.answer.verdict.split(" (")[0]}</Badge>}<Badge>evidence engine</Badge>{m.text && <button onClick={() => copy(m.text)} className="ml-auto text-zinc-500 hover:text-zinc-200" title="Copy the local answer">copy</button>}</div>
                {!!m.answer?.reasoning?.length && <Thinking steps={m.answer.reasoning} streaming={m.id === thinkingId} />}
                {!m.text && m.id === thinkingId && !m.answer?.reasoning?.length && <div className="animate-pulse text-[11px] text-zinc-500">Thinking… parsing the question.</div>}
                <pre className="whitespace-pre-wrap font-sans text-zinc-200"><Linkify text={m.text} /></pre>
                {(m.llmText || m.pending || m.llmMeta?.refusal || m.llmMeta?.error) && (
                  <div className="mt-2 border-t border-zinc-800 pt-2">
                    <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-wider text-zinc-500">
                      <Badge tone="cyan">{m.llmMeta?.servedBy ?? m.llmMeta?.model ?? wb.llm?.model ?? wb.llm?.provider ?? "llm"}</Badge>
                      <span>AI hypothesis{m.llmMeta?.servedBy && m.llmMeta.model && m.llmMeta.servedBy !== m.llmMeta.model ? ` · served by fallback ${m.llmMeta.servedBy}` : ""}</span>
                      {m.pending && <span className="animate-pulse normal-case tracking-normal">{m.llmMeta?.streaming ? "streaming…" : `waiting for ${wb.llm?.provider ?? "provider"}…`}</span>}
                      {m.pending && <button onClick={() => inflight.current.get(m.id)?.abort()} className="rounded border border-zinc-700 px-1.5 text-zinc-300 hover:border-rose-600 hover:text-white">stop</button>}
                      {m.llmText && !m.pending && <button onClick={() => copy(m.llmText!)} className="ml-auto text-zinc-500 hover:text-zinc-200" title="Copy the LLM answer">copy</button>}
                    </div>
                    {m.llmText && <Markdown text={m.llmText} />}
                    {m.llmMeta?.refusal && <div className="mt-1 rounded border border-amber-900/50 bg-amber-950/20 px-2 py-1 text-[11px] text-amber-200">{m.llmMeta.refusal}</div>}
                    {m.llmMeta?.error && <div className="mt-1 rounded border border-rose-900/50 bg-rose-950/20 px-2 py-1 text-[11px] text-rose-200">LLM: {m.llmMeta.error}</div>}
                  </div>
                )}
                {m.answer?.nameSuggestion && (
                  <div className="mt-2 flex items-center gap-2 rounded border border-cyan-900/60 bg-cyan-950/20 p-2"><Badge tone="cyan">suggested name</Badge><span className="font-mono text-cyan-200">{m.answer.nameSuggestion.name}</span><span className="text-zinc-500">{Math.round(m.answer.nameSuggestion.confidence * 100)}%</span>
                    <Button tone="emerald" className="ml-auto" onClick={() => { const fn = wb.currentAddr !== null ? db.functionAt(wb.currentAddr) : null; if (fn) { wb.rename(fn.addr, m.answer!.nameSuggestion!.name, "ai-accepted"); const o = wb.aiObservations.filter((x) => x.address === fn.addr && x.kind === "name-suggestion").pop(); if (o) wb.setVerdict(o, "accepted"); } }}>Accept</Button>
                    <Button onClick={() => { const fn = wb.currentAddr !== null ? db.functionAt(wb.currentAddr) : null; const o = fn ? wb.aiObservations.filter((x) => x.address === fn.addr && x.kind === "name-suggestion").pop() : null; if (o) wb.setVerdict(o, "rejected"); }}>Reject</Button></div>
                )}
                {!!m.answer?.evidence.length && <div className="mt-2"><div className="text-[10px] uppercase tracking-wider text-zinc-500">Evidence</div>{m.answer.evidence.slice(0, 12).map((e, k) => <div key={k} className="text-[11px] text-zinc-400">• <span className="text-zinc-600">[{e.certainty}]</span> {e.address !== undefined ? <button className="text-left text-sky-400 hover:underline" onClick={() => wb.navigate(e.address!)}>{e.text}</button> : e.text}</div>)}</div>}
                {!!m.answer?.related.length && <div className="mt-2 flex flex-wrap gap-1"><span className="text-[10px] uppercase tracking-wider text-zinc-500">Related</span>{m.answer.related.slice(0, 16).map((r, k) => <button key={k} onClick={() => wb.navigate(r.addr)} className="rounded border border-zinc-700 px-1.5 py-0.5 font-mono text-[11px] text-zinc-200 hover:border-sky-600">{r.name}{r.note ? <span className="text-zinc-500"> · {r.note}</span> : null}</button>)}</div>}
                {!!m.agentLog?.length && <div className="mt-2 rounded border border-violet-900/60 bg-violet-950/20 p-2"><div className="mb-1 text-[10px] uppercase tracking-wider text-violet-300">⚡ Agent did</div>{m.agentLog.map((l, k) => <div key={k} className="text-[11px] text-zinc-300">{l}</div>)}</div>}
              </div>
            )}
          </div>
        ))}
        <div ref={endRef} />
      </div>
      <div className="flex gap-1 border-t border-zinc-800 p-2">
        <Input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && input.trim()) { ask(input); setInput(""); } }} placeholder={wb.currentAddr !== null ? `Ask about ${db.labelFor(wb.currentAddr)}…` : "Ask about this binary…"} className="w-full" />
        <Button tone="sky" onClick={() => { if (input.trim()) { ask(input); setInput(""); } }}>Ask</Button>
      </div>
    </div>
  );
}

function Thinking({ steps, streaming }: { steps: NonNullable<AssistantAnswer["reasoning"]>; streaming?: boolean }) {
  const [open, setOpen] = useState(true);
  const pass = steps.filter((s) => s.status === "pass").length;
  const fail = steps.filter((s) => s.status === "fail").length;
  const icon = (s: string) => (s === "pass" ? "✓" : s === "fail" ? "✗" : s === "warn" ? "!" : s === "thinking" ? "◌" : s === "info" ? "·" : "▸");
  const tone = (s: string) => (s === "pass" ? "text-emerald-400" : s === "fail" ? "text-rose-400" : s === "warn" ? "text-amber-400" : s === "thinking" ? "text-sky-400" : "text-zinc-500");
  return (
    <div className="mb-2 rounded border border-zinc-800 bg-zinc-950/60">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 px-2 py-1 text-left text-[11px] text-zinc-400 hover:text-zinc-200">
        <span>{open ? "▾" : "▸"}</span><span className="font-semibold uppercase tracking-wider">{streaming ? "Thinking…" : "Thinking — checked before answering"}</span>
        <span className="ml-auto font-mono text-[10px] text-zinc-500">{pass}✓ {fail > 0 ? `${fail}✗ ` : ""}· {steps.length} steps</span>
      </button>
      {open && (
        <div className="border-t border-zinc-800 px-2 py-1">
          {steps.map((s, i) => (
            <div key={i} className="flex gap-2 py-[3px] text-[11px]">
              <span className={`w-4 shrink-0 font-mono ${tone(s.status)} ${s.status === "thinking" && i === steps.length - 1 ? "animate-pulse" : ""}`}>{icon(s.status)}</span>
              <div className="min-w-0">
                <div><span className="mr-2 uppercase tracking-wider text-zinc-500">{s.label}</span><span className="text-zinc-300">{s.detail}</span></div>
                {s.thought && <div className="mt-0.5 border-l-2 border-sky-900 pl-2 italic text-zinc-400">{s.thought}</div>}
              </div>
            </div>
          ))}
          {streaming && <div className="animate-pulse px-6 py-1 text-[11px] text-zinc-500">reasoning…</div>}
        </div>
      )}
    </div>
  );
}

function Linkify({ text }: { text: string }) {
  const wb = useWorkbench();
  const parts = text.split(/(0x[0-9a-fA-F]{3,})/g);
  return <>{parts.map((p, i) => (/^0x[0-9a-fA-F]{3,}$/.test(p) ? <button key={i} className="text-sky-400 hover:underline" onClick={() => wb.navigate(parseInt(p, 16))}>{p}</button> : <span key={i}>{p}</span>))}</>;
}

type MdBlock = { kind: "p" | "h"; text: string } | { kind: "li"; marker: string; text: string } | { kind: "code"; text: string };

/** Just enough markdown for LLM prose: headings, bullets, numbered lists, fenced code, **bold**, `code`, linked 0x addresses. */
export function splitMarkdown(text: string): MdBlock[] {
  const out: MdBlock[] = [];
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  let code: string[] | null = null;
  for (const raw of lines) {
    if (/^\s*```/.test(raw)) {
      if (code) { out.push({ kind: "code", text: code.join("\n") }); code = null; } else code = [];
      continue;
    }
    if (code) { code.push(raw); continue; }
    const line = raw.trimEnd();
    if (!line.trim()) continue;
    const h = line.match(/^\s*#{1,6}\s+(.*)$/);
    if (h) { out.push({ kind: "h", text: h[1].replace(/\s*#+\s*$/, "") }); continue; }
    const li = line.match(/^\s*(?:[-*•]|(\d+)[.)])\s+(.*)$/);
    if (li) { out.push({ kind: "li", marker: li[1] ? `${li[1]}.` : "•", text: li[2] }); continue; }
    out.push({ kind: "p", text: line.trim() });
  }
  if (code) out.push({ kind: "code", text: code.join("\n") });
  return out;
}

function Markdown({ text }: { text: string }) {
  const blocks = useMemo(() => splitMarkdown(text), [text]);
  return (
    <div className="space-y-1 text-zinc-200">
      {blocks.map((b, i) =>
        b.kind === "code" ? <pre key={i} className="overflow-auto rounded bg-black/40 p-2 font-mono text-[11px] text-emerald-200">{b.text}</pre>
        : b.kind === "h" ? <div key={i} className="mt-1.5 font-semibold text-zinc-100"><Inline text={b.text} /></div>
        : b.kind === "li" ? <div key={i} className="flex gap-1.5 pl-1"><span className="shrink-0 text-zinc-500">{b.marker}</span><span className="min-w-0"><Inline text={b.text} /></span></div>
        : <div key={i}><Inline text={b.text} /></div>,
      )}
    </div>
  );
}

function Inline({ text }: { text: string }) {
  const wb = useWorkbench();
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|0x[0-9a-fA-F]{3,})/g);
  return (
    <>
      {parts.map((p, i) => {
        if (/^\*\*[^*]+\*\*$/.test(p)) return <strong key={i} className="font-semibold text-zinc-100">{p.slice(2, -2)}</strong>;
        if (/^`[^`]+`$/.test(p)) return <code key={i} className="rounded bg-zinc-800 px-1 font-mono text-[11px] text-cyan-200">{p.slice(1, -1)}</code>;
        if (/^0x[0-9a-fA-F]{3,}$/.test(p)) return <button key={i} className="text-sky-400 hover:underline" onClick={() => wb.navigate(parseInt(p, 16))}>{p}</button>;
        return <span key={i}>{p}</span>;
      })}
    </>
  );
}

export function ConsolePanel() {
  const wb = useWorkbench();
  const [level, setLevel] = useState<"debug" | "info" | "warning" | "error">("info");
  const order = { debug: 0, info: 1, warning: 2, error: 3, critical: 4 };
  const logs = wb.logs.filter((l) => order[l.level] >= order[level]);
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { endRef.current?.scrollIntoView(); }, [logs.length]);
  const exportLogs = () => { const blob = new Blob([wb.logs.map((l) => `${new Date(l.ts).toISOString()} [${l.level.toUpperCase()}] ${l.source}: ${l.message}`).join("\n")], { type: "text/plain" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "analysis.log"; a.click(); };
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title="Console" right={<><select value={level} onChange={(e) => setLevel(e.target.value as typeof level)} className="h-6 rounded border border-zinc-700 bg-zinc-900 text-[11px] text-zinc-300"><option value="debug">debug</option><option value="info">info</option><option value="warning">warning</option><option value="error">error</option></select><Button onClick={exportLogs}>Export</Button></>} />
      <div className="flex-1 overflow-auto p-2 font-mono text-[11.5px]">
        {logs.map((l, i) => <div key={i} className={`${l.level === "error" || l.level === "critical" ? "text-rose-300" : l.level === "warning" ? "text-amber-300" : l.level === "debug" ? "text-zinc-600" : "text-zinc-300"}`}><span className="text-zinc-600">{new Date(l.ts).toLocaleTimeString()}</span> <span className="text-zinc-500">[{l.source}]</span> {l.message}</div>)}
        <div ref={endRef} />
      </div>
    </div>
  );
}
