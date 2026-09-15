"use client";
import React, { useMemo, useState } from "react";
import { useWorkbench, hex } from "../store";
import { Badge, Button, Input, confidenceTone } from "../primitives";
import { DETECTION_LABELS } from "@/core/analysis/semantic/securityRules";
import { downloadText } from "../download";

const labels = new Set<string>(DETECTION_LABELS);
export function DetectionsView() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [minimum, setMinimum] = useState(0);
  const [page, setPage] = useState(0);
  const all = useMemo(() => db.functions.flatMap((fn) => fn.isImportStub ? [] : (fn.classes ?? []).filter((c) => labels.has(c.label)).map((c) => ({ address: fn.addr, name: db.nameFor(fn.addr).name, ...c }))).sort((a, b) => b.confidence - a.confidence || a.address - b.address), [db, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const hit of all) map.set(hit.label, (map.get(hit.label) ?? 0) + 1);
    return map;
  }, [all]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all.filter((h) => (category === "all" || h.label === category) && h.confidence >= minimum && (!q || `${h.name} ${hex(h.address)} ${h.label} ${h.evidence.map((e) => e.text).join(" ")}`.toLowerCase().includes(q)));
  }, [all, category, minimum, query]);
  const lastPage = Math.max(0, Math.ceil(filtered.length / 50) - 1);
  const currentPage = Math.min(page, lastPage);
  const semantic = wb.stages.find((s) => s.id === "semantic");
  return <div className="flex h-full flex-col">
    <div className="border-b border-zinc-800 bg-gradient-to-r from-sky-950/40 to-violet-950/20 p-4">
      <div className="flex flex-wrap items-center gap-2"><h1 className="text-lg font-semibold text-zinc-100">Detections</h1><Badge tone="sky">{all.length} findings</Badge><Badge>{new Set(all.map((h) => h.address)).size} functions</Badge><Button className="ml-auto" disabled={!filtered.length} onClick={() => downloadText(`${db.fileName}.detections.json`, JSON.stringify({ file: db.fileName, sha256: db.hash, filters: { category, query, minimum }, findings: filtered }, null, 2), "application/json")}>Export results</Button></div>
      <p className="mt-2 text-[12px] text-zinc-400">12 focused detectors. Strings alone produce leads; APIs in the same function add support. Scores are rule weights, not measured probabilities or proof of enforcement.</p>
      <div className="mt-3 flex flex-wrap gap-2"><Input aria-label="Filter detections" value={query} onChange={(e) => { setQuery(e.target.value); setPage(0); }} placeholder="Filter by function, address or evidence…" className="min-w-48 flex-1" /><select aria-label="Detection confidence" value={minimum} onChange={(e) => { setMinimum(Number(e.target.value)); setPage(0); }} className="rounded border border-zinc-700 bg-zinc-900 px-2 text-[12px]"><option value={0}>All findings, including leads</option><option value={0.55}>Likely and high (≥55%)</option><option value={0.8}>High (≥80%)</option></select></div>
      <div className="mt-3 flex flex-wrap gap-1.5">{["all", ...DETECTION_LABELS].map((label) => <button key={label} onClick={() => { setCategory(label); setPage(0); }} className={`rounded-full border px-2.5 py-1 text-[11px] ${category === label ? "border-sky-500 bg-sky-800/30 text-sky-100" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{label === "all" ? "All" : label.replaceAll("-", " ")} <span className="ml-1 opacity-60">{label === "all" ? all.length : counts.get(label) ?? 0}</span></button>)}</div>
    </div>
    <div className="min-h-0 flex-1 overflow-auto p-4">
      {semantic?.status !== "complete" && <div className="mb-3 rounded border border-amber-900/60 p-3 text-[12px] text-amber-300">Semantic analysis {semantic?.status ?? "pending"}. Results may still be incomplete.</div>}
      {!filtered.length && <div className="rounded-lg border border-dashed border-zinc-700 p-8 text-center text-zinc-400">{all.length ? "No detections match these filters." : "No matching behavior found in the analyzed functions."}<p className="mt-2 text-[12px] text-zinc-500">Unresolved calls, encoded strings and analysis limits can hide behavior. No finding does not establish absence.</p></div>}
      <div className="space-y-3">{filtered.slice(currentPage * 50, (currentPage + 1) * 50).map((hit) => <article key={`${hit.address}:${hit.label}`} className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3">
        <div className="flex flex-wrap items-center gap-2"><Badge tone={confidenceTone(hit.confidence)}>{hit.level} · {Math.round(hit.confidence * 100)}%</Badge><span className="text-[12px] font-medium text-zinc-100">{hit.label.replaceAll("-", " ")}</span><button className="ml-auto truncate font-mono text-[12px] text-sky-300 hover:underline" onClick={() => wb.navigate(hit.address, { tab: "disasm" })}>{hit.name} · {hex(hit.address)} ↗</button></div>
        <ul className="mt-2 space-y-1 text-[12px] text-zinc-400">{hit.evidence.map((e, i) => <li key={i} className="flex items-start gap-2"><span className="mt-0.5 text-[10px] uppercase text-zinc-500">{e.certainty}</span><span className="min-w-0 break-words">{e.text}{e.address !== undefined && <button className="ml-2 font-mono text-sky-400 hover:underline" onClick={() => wb.navigate(e.address!, { tab: db.space.isExec(e.address!) ? "disasm" : "hex" })}>{hex(e.address)}</button>}</span></li>)}</ul>
      </article>)}</div>
    </div>
    <div className="flex items-center gap-2 border-t border-zinc-800 px-4 py-2 text-[11px] text-zinc-400"><span>{filtered.length} matching findings · page {currentPage + 1} / {lastPage + 1}</span><Button className="ml-auto" disabled={!currentPage} onClick={() => setPage(currentPage - 1)}>Previous</Button><Button disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)}>Next</Button></div>
  </div>;
}
