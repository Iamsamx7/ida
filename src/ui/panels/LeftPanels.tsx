"use client";
import React, { useMemo, useState } from "react";
import { useWorkbench, hex } from "../store";
import { Badge, ContextMenu, Input, PanelHeader, VirtualList, confidenceTone, useContextMenu, Button } from "../primitives";
import type { StringCategory } from "@/core/analysis/types";

const R = 22;

export function FunctionsPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<"addr" | "name" | "size" | "xref" | "conf">("addr");
  const [only, setOnly] = useState<"all" | "named" | "inferred" | "classified">("all");
  const menu = useContextMenu();
  const list = useMemo(() => {
    let fns = db.functions;
    if (only === "named") fns = fns.filter((f) => f.nameSource !== "inferred");
    else if (only === "inferred") fns = fns.filter((f) => f.nameSource === "inferred");
    else if (only === "classified") fns = fns.filter((f) => f.classes?.length);
    if (q) { const l = q.toLowerCase(); fns = fns.filter((f) => f.name.toLowerCase().includes(l) || f.addr.toString(16).includes(l) || f.classes?.some((c) => c.label.includes(l))); }
    if (sort !== "addr") fns = [...fns].sort((a, b) => sort === "name" ? a.name.localeCompare(b.name) : sort === "size" ? b.size - a.size : sort === "xref" ? b.callerCount - a.callerCount : b.confidence - a.confidence);
    return fns;
  }, [db, q, sort, only, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  const curIdx = wb.currentAddr !== null ? list.findIndex((f) => f === db.functionAt(wb.currentAddr!)) : -1;
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={`Functions · ${list.length.toLocaleString()}`} right={<select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)} className="h-6 rounded border border-zinc-700 bg-zinc-900 text-[11px] text-zinc-300"><option value="addr">address</option><option value="name">name</option><option value="size">size</option><option value="xref">xrefs</option><option value="conf">confidence</option></select>} />
      <div className="flex gap-1 border-b border-zinc-800 p-2"><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter (name, addr, class)" className="w-full" /><select value={only} onChange={(e) => setOnly(e.target.value as typeof only)} className="h-7 rounded border border-zinc-700 bg-zinc-900 text-[11px] text-zinc-300"><option value="all">all</option><option value="named">named</option><option value="inferred">inferred</option><option value="classified">classified</option></select></div>
      <VirtualList className="flex-1" count={list.length} rowHeight={R} scrollTo={curIdx >= 0 ? { index: curIdx, nonce: curIdx } : null} render={(i) => { const f = list[i]; const cur = i === curIdx; return (
        <div onClick={() => wb.navigate(f.addr)} onContextMenu={(e) => menu.open(e, [
          { label: "Rename…", shortcut: "F2", onClick: () => wb.setRenameTarget(f.addr) }, { label: "Function comment…", onClick: () => wb.setCommentTarget(-f.addr) }, { label: db.bookmarks.has(f.addr) ? "Remove bookmark" : "Bookmark", onClick: () => wb.toggleBookmark(f.addr, undefined, "function") },
          { label: "Add tag…", onClick: () => { const t = prompt("Tag"); if (t) wb.addTag(f.addr, t); } }, { separator: true, label: "" }, { label: "Show XREFs", onClick: () => { wb.navigate(f.addr); wb.setRightTab("xrefs"); } }, { label: "Call graph", onClick: () => wb.navigate(f.addr, { tab: "graph" }) }, { label: "Pseudocode", onClick: () => wb.navigate(f.addr, { tab: "pseudo" }) },
          { separator: true, label: "" }, { label: "AI: Explain", onClick: () => { wb.navigate(f.addr); wb.askAI(`What does this function do? (0x${f.addr.toString(16)})`); } }, { label: "AI: Find similar", onClick: () => { wb.navigate(f.addr); wb.askAI(`Find functions similar to 0x${f.addr.toString(16)}`); } }, { label: "Copy address", onClick: () => navigator.clipboard.writeText(hex(f.addr)) },
        ])} className={`flex h-[22px] cursor-pointer items-center gap-2 px-2 text-[12px] ${cur ? "bg-sky-500/20" : "hover:bg-zinc-800/60"}`}>
          <span className="w-[76px] shrink-0 font-mono text-zinc-500">{f.addr.toString(16)}</span>
          <span className={`truncate font-mono ${f.nameSource === "user" ? "text-violet-300" : f.nameSource === "symbol" ? "text-zinc-100" : f.nameSource === "ai" ? "text-cyan-300" : "text-zinc-400"}`}>{f.name}</span>
          <span className="ml-auto flex shrink-0 items-center gap-1">
            {f.classes?.[0] && <span className="rounded bg-zinc-800 px-1 text-[9px] uppercase text-zinc-400" title={`${f.classes[0].level} ${Math.round(f.classes[0].confidence * 100)}%`}>{f.classes[0].label.split("-")[0]}</span>}
            {f.callerCount > 0 && <span className="text-[10px] text-cyan-600">{f.callerCount}</span>}
            <span className={`h-1.5 w-1.5 rounded-full ${f.confidence >= 0.9 ? "bg-emerald-500" : f.confidence >= 0.6 ? "bg-sky-500" : "bg-amber-500"}`} title={`confidence ${Math.round(f.confidence * 100)}% (${f.sources.join(", ")})`} />
          </span>
        </div>
      ); }} />
      <ContextMenu menu={menu.menu} onClose={menu.close} />
    </div>
  );
}

export function StringsPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<StringCategory | "all">("all");
  const [refOnly, setRefOnly] = useState(false);
  const menu = useContextMenu();
  const list = useMemo(() => {
    let s = db.strings;
    if (cat !== "all") s = s.filter((x) => x.category === cat);
    if (refOnly) s = s.filter((x) => x.refCount > 0);
    if (q) { const l = q.toLowerCase(); s = s.filter((x) => x.value.toLowerCase().includes(l)); }
    return s;
  }, [db, q, cat, refOnly, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  const cats = useMemo(() => [...new Set(db.strings.map((s) => s.category))].sort(), [db, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={`Strings · ${list.length.toLocaleString()}`} right={<label className="flex items-center gap-1 text-[11px]"><input type="checkbox" checked={refOnly} onChange={(e) => setRefOnly(e.target.checked)} />referenced</label>} />
      <div className="flex gap-1 border-b border-zinc-800 p-2"><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter" className="w-full" /><select value={cat} onChange={(e) => setCat(e.target.value as typeof cat)} className="h-7 rounded border border-zinc-700 bg-zinc-900 text-[11px] text-zinc-300"><option value="all">all</option>{cats.map((c) => <option key={c} value={c}>{c}</option>)}</select></div>
      <VirtualList className="flex-1" count={list.length} rowHeight={R} render={(i) => { const s = list[i]; return (
        <div onClick={() => { wb.navigate(s.addr, { tab: "hex" }); wb.setRightTab("xrefs"); }} onDoubleClick={() => { const r = db.xrefs.refsTo(s.addr, 1)[0]; if (r) wb.navigate(r.from, { tab: "disasm" }); }} onContextMenu={(e) => menu.open(e, [
          { label: "Find references", onClick: () => { wb.navigate(s.addr, { tab: "hex" }); wb.setRightTab("xrefs"); } }, { label: "Go to first reference", disabled: !s.refCount, onClick: () => { const r = db.xrefs.refsTo(s.addr, 1)[0]; if (r) wb.navigate(r.from); } }, { label: "Go to (hex)", onClick: () => wb.navigate(s.addr, { tab: "hex" }) },
          { label: "AI: Where is this string used?", onClick: () => wb.askAI(`Where is the string "${s.value.slice(0, 60)}" used?`) }, { label: "Bookmark", onClick: () => wb.toggleBookmark(s.addr, s.value.slice(0, 40), "string") }, { label: "Rename associated object…", onClick: () => wb.setRenameTarget(s.addr) }, { label: "Copy string", onClick: () => navigator.clipboard.writeText(s.value) },
        ])} className={`flex h-[22px] cursor-pointer items-center gap-2 px-2 text-[12px] ${wb.currentAddr === s.addr ? "bg-sky-500/20" : "hover:bg-zinc-800/60"}`} title={s.value}>
          <span className="w-[68px] shrink-0 font-mono text-zinc-500">{s.addr.toString(16)}</span>
          <span className="truncate font-mono text-emerald-200/90">{s.value}</span>
          <span className="ml-auto flex shrink-0 gap-1">{s.category !== "generic" && <span className="rounded bg-zinc-800 px-1 text-[9px] text-zinc-400">{s.category}</span>}{s.encoding !== "ascii" && <span className="text-[9px] text-zinc-500">{s.encoding}</span>}{s.refCount > 0 && <span className="text-[10px] text-cyan-600">{s.refCount}</span>}</span>
        </div>
      ); }} />
      <ContextMenu menu={menu.menu} onClose={menu.close} />
    </div>
  );
}

const API_CATEGORY: [RegExp, string][] = [
  [/^(malloc|calloc|realloc|free|_Znwm|_Znam|_ZdlPv|_ZdaPv|mmap|munmap|mprotect|posix_memalign)$/, "memory"], [/^(mem(cpy|move|set|cmp|chr)|str|__str|wcs|snprintf|sprintf|vsnprintf|sscanf|atoi|strto)/, "string"], [/^(open|close|read|write|fopen|fclose|fread|fwrite|fseek|ftell|lseek|stat|fstat|lstat|access|mkdir|unlink|opendir|readdir|ioctl|fcntl|dup)/, "file"],
  [/^(socket|connect|bind|listen|accept|send|recv|getaddrinfo|inet_|setsockopt|getsockopt|poll|select|epoll|SSL_|BIO_|curl_)/, "network"], [/^pthread_|^sem_|^__cxa_guard|^futex/, "threading"], [/^__android_log|^syslog|^printf|^puts|^perror/, "logging"], [/^(dlopen|dlsym|dlclose|dladdr|android_dlopen_ext)$/, "loader"],
  [/^(AES_|EVP_|SHA|MD5|HMAC|RAND_|RSA_|EC_|BN_|mbedtls_|crypto_|sodium_)/, "crypto"], [/^(inflate|deflate|uncompress|compress|LZ4_|ZSTD_|lzma_|BZ2_)/, "compression"], [/^(gl[A-Z]|egl[A-Z]|vk[A-Z]|ANativeWindow|AHardwareBuffer)/, "graphics"], [/^(__cxa_|_Unwind|__gxx_personality|_ZSt9terminate|abort|__stack_chk|__assert)/, "runtime"],
  [/^(_ZN|_ZSt|_ZTV|_ZTI|_ZTS)/, "c++"], [/^(clock_gettime|gettimeofday|time|nanosleep|usleep|localtime)/, "time"], [/^(ptrace|prctl|getpid|getppid|kill|sigaction|signal|syscall|__system_property_get|getauxval)/, "system"], [/^(JNI_|Java_)/, "jni"],
];
export function apiCategory(name: string) {
  for (const [rx, c] of API_CATEGORY) if (rx.test(name)) return c;
  return "other";
}

export function SymbolsPanel({ kind }: { kind: "imports" | "exports" }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("all");
  const list = useMemo(() => {
    let s = kind === "imports" ? db.elf.imports : db.elf.exports;
    if (kind === "exports") s = [...s].sort((a, b) => a.value - b.value);
    if (cat !== "all") s = s.filter((x) => apiCategory(x.name) === cat);
    if (q) { const l = q.toLowerCase(); s = s.filter((x) => x.name.toLowerCase().includes(l)); }
    return s;
  }, [db, kind, q, cat]);
  const cats = useMemo(() => [...new Set((kind === "imports" ? db.elf.imports : db.elf.exports).map((s) => apiCategory(s.name)))].sort(), [db, kind]);
  const pltFor = (name: string) => { for (const [a, n] of db.pltNames) if (n === `${name}@plt`) return a; return null; };
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={`${kind} · ${list.length}`} />
      <div className="flex gap-1 border-b border-zinc-800 p-2"><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter" className="w-full" /><select value={cat} onChange={(e) => setCat(e.target.value)} className="h-7 rounded border border-zinc-700 bg-zinc-900 text-[11px] text-zinc-300"><option value="all">all</option>{cats.map((c) => <option key={c} value={c}>{c}</option>)}</select></div>
      <VirtualList className="flex-1" count={list.length} rowHeight={R} render={(i) => { const s = list[i]; const plt = kind === "imports" ? pltFor(s.name) : null; const target = kind === "exports" ? s.value : plt; return (
        <div onClick={() => { if (target) wb.navigate(target); if (plt) wb.setRightTab("xrefs"); }} className={`flex h-[22px] items-center gap-2 px-2 text-[12px] ${target ? "cursor-pointer hover:bg-zinc-800/60" : ""}`} title={`${s.kind} ${s.binding}${s.version ? " " + s.version : ""}`}>
          <span className="w-[68px] shrink-0 font-mono text-zinc-500">{kind === "exports" ? s.value.toString(16) : plt ? plt.toString(16) : ""}</span>
          <span className="truncate font-mono text-zinc-200">{s.name}</span>
          <span className="ml-auto flex shrink-0 gap-1">{s.binding === "weak" && <Badge tone="amber">weak</Badge>}<span className="rounded bg-zinc-800 px-1 text-[9px] text-zinc-400">{apiCategory(s.name)}</span>{plt && <span className="text-[10px] text-cyan-600">{db.xrefs.countTo(plt)}</span>}</span>
        </div>
      ); }} />
    </div>
  );
}

export function SectionsPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title="Sections & segments" right={<button className="text-sky-400 hover:underline" onClick={() => wb.setCenterTab("elf")}>ELF view</button>} />
      <div className="flex-1 overflow-auto">
        <div className="px-2 pt-2 text-[10px] uppercase tracking-wider text-zinc-500">Segments</div>
        {db.elf.segments.map((s) => <div key={s.index} onClick={() => s.type === 1 && wb.navigate(s.vaddr, { tab: "hex" })} className="flex cursor-pointer items-center gap-2 px-2 py-[2px] font-mono text-[12px] hover:bg-zinc-800/60"><span className="w-24 text-zinc-300">{s.typeName}</span><span className="text-zinc-500">{s.perms}</span><span className="text-zinc-400">{hex(s.vaddr)}</span><span className="ml-auto text-zinc-500">{hex(s.memsz)}</span></div>)}
        <div className="px-2 pt-3 text-[10px] uppercase tracking-wider text-zinc-500">Sections</div>
        {db.elf.sections.filter((s) => s.size > 0).map((s) => <div key={s.index} onClick={() => s.addr && wb.navigate(s.addr, { tab: s.exec ? "disasm" : "hex" })} className={`flex items-center gap-2 px-2 py-[2px] font-mono text-[12px] ${s.addr ? "cursor-pointer hover:bg-zinc-800/60" : "opacity-60"}`}><span className={`w-32 truncate ${s.exec ? "text-fuchsia-300" : s.write ? "text-amber-200" : "text-zinc-300"}`}>{s.name}</span><span className="text-zinc-500">{s.flagStr}</span><span className="text-zinc-400">{hex(s.addr)}</span><span className="ml-auto text-zinc-500">{hex(s.size)}</span></div>)}
      </div>
    </div>
  );
}

export function StructuresPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [sel, setSel] = useState(0);
  const s = db.structures[sel];
  const addUser = () => {
    const name = prompt("Structure name");
    if (!name) return;
    const fields = prompt("Fields as offset:name:size, comma-separated (e.g. 0:vtable:8,8:id:4)") ?? "";
    const parsed = fields.split(",").map((f) => f.trim().split(":")).filter((p) => p.length >= 2).map((p) => ({ offset: parseInt(p[0], 16), name: p[1], size: parseInt(p[2] ?? "8", 10), certain: true }));
    db.structures.unshift({ id: `user_${Date.now()}`, name, origin: "user", fields: parsed, evidence: [{ text: "user-defined", certainty: "user" }], functions: [], confidence: 1 });
    if (wb.projectHash) fetch(`/api/projects/${wb.projectHash}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "structure", op: "set", name, origin: "user", fields: parsed }) });
    wb.bump();
  };
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={`Structures · ${db.structures.length}`} right={<Button onClick={addUser}>+ define</Button>} />
      <div className="grid min-h-0 flex-1 grid-rows-2">
        <div className="overflow-auto border-b border-zinc-800">
          {db.structures.map((st, i) => <div key={st.id} onClick={() => setSel(i)} className={`flex cursor-pointer items-center gap-2 px-2 py-[3px] font-mono text-[12px] ${i === sel ? "bg-sky-500/20" : "hover:bg-zinc-800/60"}`}><span className="truncate text-zinc-200">{st.name}</span><Badge tone={st.origin === "user" ? "violet" : "amber"}>{st.origin}</Badge><span className="ml-auto text-zinc-500">{st.fields.length} fields</span></div>)}
          {!db.structures.length && <div className="p-3 text-[12px] text-zinc-500">No structures inferred yet (requires ≥3 distinct offsets from one base register).</div>}
        </div>
        <div className="overflow-auto p-2 font-mono text-[12px]">
          {s && (<>
            <div className="mb-1 text-zinc-300">{s.origin === "inferred" ? "Possible structure" : "Structure"} <span className="text-sky-300">{s.name}</span> {s.origin !== "user" && <Badge tone={confidenceTone(s.confidence)}>{Math.round(s.confidence * 100)}%</Badge>}</div>
            {s.fields.map((f) => <div key={f.offset} className="flex gap-3 text-zinc-300"><span className="w-14 text-zinc-500">+0x{f.offset.toString(16).padStart(2, "0")}</span><span className={f.certain ? "text-zinc-100" : "text-zinc-300"}>{f.name}{f.certain ? "" : "?"}</span><span className="text-zinc-500">{f.type ?? ""}</span><span className="ml-auto text-zinc-600">{f.accessKinds?.join("/")}</span></div>)}
            <div className="mt-2 text-[11px] text-zinc-500">Evidence</div>
            {s.evidence.map((e, i) => <div key={i} className="text-[11px] text-zinc-400">• <span className="text-zinc-600">[{e.certainty}]</span> {e.address !== undefined ? <button className="text-sky-400 hover:underline" onClick={() => wb.navigate(e.address!)}>{e.text}</button> : e.text}</div>)}
          </>)}
        </div>
      </div>
    </div>
  );
}

export function GlobalsPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [q, setQ] = useState("");
  const list = useMemo(() => (q ? db.globals.filter((g) => g.name.toLowerCase().includes(q.toLowerCase()) || g.addr.toString(16).includes(q)) : db.globals), [db, q, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={`Globals · ${list.length}`} />
      <div className="border-b border-zinc-800 p-2"><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter" className="w-full" /></div>
      <VirtualList className="flex-1" count={list.length} rowHeight={R} render={(i) => { const g = list[i]; const n = db.nameFor(g.addr); return (
        <div onClick={() => { wb.navigate(g.addr, { tab: "hex" }); wb.setRightTab("xrefs"); }} className="flex h-[22px] cursor-pointer items-center gap-2 px-2 font-mono text-[12px] hover:bg-zinc-800/60">
          <span className="w-[68px] shrink-0 text-zinc-500">{g.addr.toString(16)}</span><span className={`truncate ${n.source === "user" ? "text-violet-300" : n.source === "symbol" ? "text-zinc-100" : "text-zinc-400"}`}>{n.source === "inferred" ? g.name : n.name}</span>
          <span className="ml-auto flex shrink-0 gap-1 text-[10px]"><span className="text-zinc-500">{g.section}</span><span className="text-sky-500">{g.readers}R</span><span className="text-amber-500">{g.writers}W</span></span>
        </div>
      ); }} />
    </div>
  );
}

export function BookmarksPanel({ mode }: { mode: "bookmarks" | "tags" }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const bms = [...db.bookmarks.values()].sort((a, b) => a.address - b.address);
  const tagList = [...db.tags.entries()].flatMap(([addr, set]) => [...set].map((t) => ({ addr, tag: t }))).sort((a, b) => a.tag.localeCompare(b.tag));
  return (
    <div className="flex h-full flex-col">
      <PanelHeader title={mode === "bookmarks" ? `Bookmarks · ${bms.length}` : `Tags · ${tagList.length}`} />
      <div className="flex-1 overflow-auto">
        {mode === "bookmarks" && bms.map((b) => (
          <div key={b.address} className="group flex items-start gap-2 border-b border-zinc-900 px-2 py-1.5 text-[12px] hover:bg-zinc-800/60">
            <button onClick={() => wb.navigate(b.address, { tab: b.kind === "string" || b.kind === "data" ? "hex" : "disasm" })} className="min-w-0 flex-1 text-left"><div className="truncate font-mono text-amber-200">★ {b.label}</div><div className="font-mono text-[11px] text-zinc-500">{hex(b.address)} · {b.kind}{b.note ? ` · ${b.note}` : ""}</div></button>
            <button className="text-zinc-500 hover:text-zinc-200" title="Edit note" onClick={() => { const n = prompt("Bookmark note", b.note); if (n !== null) { wb.toggleBookmark(b.address, b.label, b.kind); db.bookmarks.get(b.address)!.note = n; wb.toggleBookmark(b.address, b.label, b.kind); } }}>✎</button>
            <button className="text-zinc-500 hover:text-rose-300" onClick={() => wb.toggleBookmark(b.address)}>✕</button>
          </div>
        ))}
        {mode === "bookmarks" && !bms.length && <div className="p-3 text-[12px] text-zinc-500">No bookmarks. Press F9 on any address.</div>}
        {mode === "tags" && tagList.map((t, i) => (
          <div key={i} className="flex items-center gap-2 border-b border-zinc-900 px-2 py-1 text-[12px] hover:bg-zinc-800/60">
            <Badge tone="violet" onClick={() => { wb.setSearchQuery(`tag:${t.tag}`); wb.setCenterTab("search"); }}>#{t.tag}</Badge>
            <button onClick={() => wb.navigate(t.addr)} className="truncate font-mono text-zinc-200 hover:underline">{db.labelFor(t.addr)}</button>
            <button className="ml-auto text-zinc-500 hover:text-rose-300" onClick={() => wb.removeTag(t.addr, t.tag)}>✕</button>
          </div>
        ))}
        {mode === "tags" && !tagList.length && <div className="p-3 text-[12px] text-zinc-500">No tags yet. Right-click a function → Add tag.</div>}
      </div>
    </div>
  );
}
