"use client";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useWorkbench, type CenterTab, type LeftTab, type RightTab, hex, fmtBytes } from "./store";
import { Badge, Button, Input, Modal, Progress } from "./primitives";
import { DisassemblyView } from "./views/DisassemblyView";
import { HexView, PseudocodeView } from "./views/HexAndPseudoViews";
import { CallGraphView, CompareView, ElfView, LinksView, OverviewView, SearchView } from "./views/OverviewElfGraph";
import { BookmarksPanel, FunctionsPanel, GlobalsPanel, SectionsPanel, StringsPanel, StructuresPanel, SymbolsPanel } from "./panels/LeftPanels";
import { AIPanel, ConsolePanel, FunctionInfoPanel, XrefsPanel } from "./panels/RightPanels";
import { AddressSpace } from "@/core/address/space";
import { search } from "@/core/search/engine";
import { generatePseudocode } from "@/core/analysis/pseudocode";
import { selectBackend } from "@/compute/backend";

interface Command { id: string; label: string; shortcut?: string; run: () => void; when?: () => boolean }

export function Workbench() {
  const wb = useWorkbench();
  const { db } = wb;
  const [left, setLeft] = useState(300);
  const [right, setRight] = useState(360);
  const [bottom, setBottom] = useState(170);
  const [showLeft, setShowLeft] = useState(true);
  const [showRight, setShowRight] = useState(true);
  const [showBottom, setShowBottom] = useState(true);
  const [bottomTab, setBottomTab] = useState<"console" | "progress">("progress");
  const [menuOpen, setMenuOpen] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [backendInfo, setBackendInfo] = useState<string>("");
  // The hidden file inputs are held in state (callback refs) so the command closures never read a ref during render.
  const [fileInput, setFileInput] = useState<HTMLInputElement | null>(null);
  const [compareInput, setCompareInput] = useState<HTMLInputElement | null>(null);
  const [workspaceInput, setWorkspaceInput] = useState<HTMLInputElement | null>(null);

  useEffect(() => { void selectBackend(undefined, { mode: wb.computeMode, gpuLoad: wb.gpuLoad, gpuMinBytes: 256 * 1024 }).then((r) => setBackendInfo(`${r.cpu} · ${r.gpu}`)); }, [wb.computeMode, wb.gpuLoad]);
  const pickFile = useCallback(() => fileInput?.click(), [fileInput]);
  const pickCompare = useCallback(() => compareInput?.click(), [compareInput]);
  const pickWorkspace = useCallback(() => workspaceInput?.click(), [workspaceInput]);

  const exportData = useCallback((what: "functions" | "strings" | "xrefs" | "disasm" | "pseudo" | "report", fmt: "json" | "csv" | "txt" | "html") => {
    if (!db) return;
    let content = "", name = `${db.fileName}.${what}.${fmt}`;
    const dl = () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type: fmt === "json" ? "application/json" : fmt === "html" ? "text/html" : "text/plain" })); a.download = name; a.click(); };
    const fnRows = db.functions.map((f) => ({ address: hex(f.addr), name: db.nameFor(f.addr).name, size: f.size, source: f.nameSource, confidence: +f.confidence.toFixed(2), evidence: f.sources.join("+"), classification: f.classes?.[0]?.label ?? "", classConfidence: f.classes?.[0] ? +f.classes[0].confidence.toFixed(2) : "", callers: f.callerCount }));
    const csv = (rows: Record<string, unknown>[]) => rows.length ? [Object.keys(rows[0]).join(","), ...rows.map((r) => Object.values(r).map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\n") : "";
    if (what === "functions") content = fmt === "json" ? JSON.stringify(fnRows, null, 1) : fmt === "csv" ? csv(fnRows) : fnRows.map((r) => `${r.address} ${r.name} ${r.size} ${r.classification}`).join("\n");
    else if (what === "strings") { const rows = db.strings.map((s) => ({ address: hex(s.addr), encoding: s.encoding, category: s.category, refs: s.refCount, value: s.value })); content = fmt === "json" ? JSON.stringify(rows, null, 1) : fmt === "csv" ? csv(rows) : rows.map((r) => `${r.address} ${r.value}`).join("\n"); }
    else if (what === "xrefs") { const rows: Record<string, unknown>[] = []; const x = db.xrefs; for (let i = 0; i < Math.min(x.count, 2_000_000); i++) rows.push({ from: hex(x.from[i]), to: hex(x.to[i]), kind: x.kind[i] }); content = fmt === "json" ? JSON.stringify(rows) : csv(rows); }
    else if (what === "disasm" || what === "pseudo") {
      const fn = wb.currentAddr !== null ? db.functionAt(wb.currentAddr) : null;
      if (!fn) return;
      content = what === "disasm" ? db.decodeFunction(fn).map((i) => `${i.address.toString(16).padStart(8, "0")}  ${[...db.readBytes(i.address, i.size)].map((b) => b.toString(16).padStart(2, "0")).join("")}  ${i.mnemonic} ${i.opText}${db.comments.has(i.address) ? "  ; " + db.comments.get(i.address) : ""}`).join("\n") : generatePseudocode(db, fn).map((l) => "  ".repeat(l.indent) + l.text).join("\n");
      name = `${db.nameFor(fn.addr).name}.${what}.txt`;
    } else {
      const comp = new Map<string, number>();
      for (const f of db.functions) for (const c of f.classes ?? []) if (c.confidence >= 0.5) comp.set(c.label, (comp.get(c.label) ?? 0) + 1);
      const report = { file: db.fileName, sha256: db.hash, header: db.elf.header, stats: db.stats(), components: Object.fromEntries(comp), needed: db.elf.needed, exports: db.elf.exports.map((e) => e.name), imports: db.elf.imports.map((e) => e.name), bookmarks: [...db.bookmarks.values()], userNames: [...db.userNames.values()], aiObservations: wb.aiObservations, timings: wb.coordinator?.timings };
      content = fmt === "html" ? `<html><body style="font-family:ui-monospace,monospace;background:#0b0f17;color:#e4e4e7;padding:24px"><h1>${db.fileName}</h1><pre>${JSON.stringify(report, null, 2).replace(/</g, "&lt;")}</pre></body></html>` : JSON.stringify(report, null, 2);
    }
    dl();
  }, [db, wb.currentAddr, wb.aiObservations, wb.coordinator]);

  const commands = useMemo<Command[]>(() => [
    { id: "open", label: "Open binary…", shortcut: "Ctrl+O", run: pickFile },
    { id: "sample", label: "Open sample libsample.so (ARM64)", run: () => void wb.openSample() },
    { id: "goto", label: "Go To Address / Offset", shortcut: "Ctrl+G", run: () => wb.setGotoOpen(true), when: () => !!db },
    { id: "search", label: "Search everything", shortcut: "Ctrl+Shift+F", run: () => wb.setCenterTab("search"), when: () => !!db },
    { id: "find", label: "Find in current view", shortcut: "Ctrl+F", run: () => wb.setCenterTab("search"), when: () => !!db },
    { id: "quick", label: "Quick open symbol / function", shortcut: "Ctrl+P", run: () => wb.setPaletteOpen(true), when: () => !!db },
    { id: "back", label: "Jump Back", shortcut: "Alt+←", run: () => wb.back(), when: () => wb.canBack },
    { id: "fwd", label: "Jump Forward", shortcut: "Alt+→", run: () => wb.forward(), when: () => wb.canForward },
    { id: "rename", label: "Rename Function / Address", shortcut: "F2", run: () => wb.currentAddr !== null && wb.setRenameTarget(db?.functionAt(wb.currentAddr)?.addr ?? wb.currentAddr), when: () => wb.currentAddr !== null },
    { id: "comment", label: "Add / Edit Comment", shortcut: ";", run: () => wb.currentAddr !== null && wb.setCommentTarget(wb.currentAddr), when: () => wb.currentAddr !== null },
    { id: "bookmark", label: "Toggle Bookmark", shortcut: "F9", run: () => wb.currentAddr !== null && wb.toggleBookmark(wb.currentAddr), when: () => wb.currentAddr !== null },
    { id: "xrefs", label: "Show XREFs", shortcut: "X", run: () => wb.setRightTab("xrefs"), when: () => !!db },
    { id: "callers", label: "Show Callers (AI)", run: () => wb.askAI("What calls this?"), when: () => wb.currentAddr !== null },
    { id: "callees", label: "Show Callees (AI)", run: () => wb.askAI("What does this call?"), when: () => wb.currentAddr !== null },
    { id: "explain", label: "AI: Explain Function", run: () => wb.askAI("What does this function do?"), when: () => wb.currentAddr !== null },
    { id: "why", label: "AI: Why this classification?", run: () => wb.askAI("Why did you classify this?"), when: () => wb.currentAddr !== null },
    { id: "anticheat", label: "AI: Where is anticheat?", run: () => wb.askAI("Where is anticheat?"), when: () => !!db },
    { id: "ban", label: "AI: Where are ban checks?", run: () => wb.askAI("Where are ban checks?"), when: () => !!db },
    { id: "hash", label: "AI: Where are hash checks?", run: () => wb.askAI("Where are hash checks?"), when: () => !!db },
    { id: "libs", label: "AI: Which libraries / lib map?", run: () => wb.askAI("Which libraries does this use?"), when: () => !!db },
    { id: "memcpy", label: "AI: Where is memcpy used?", run: () => wb.askAI("Where is memcpy used?"), when: () => !!db },
    { id: "time", label: "AI: Where is gettimeofday used?", run: () => wb.askAI("Where is gettimeofday used?"), when: () => !!db },
    { id: "bypass", label: "AI: Plan safe bypass (slow, thorough)", run: () => { wb.setCenterTab("overview"); wb.askAI("Plan a safe bypass"); }, when: () => !!db },
    { id: "verify", label: "Verify my patch/hook (analyzer)", run: () => { wb.setCenterTab("overview"); }, when: () => !!db },
    { id: "recon", label: "Agent: recon sweep (navigate + bookmark proven)", run: () => wb.askAI("recon"), when: () => !!db },
    { id: "similar", label: "Find Similar Functions", run: () => wb.askAI("Find functions similar to this one"), when: () => wb.currentAddr !== null },
    { id: "suggest", label: "AI: Suggest Name", run: () => wb.askAI("Suggest a name for this function"), when: () => wb.currentAddr !== null },
    { id: "analyze", label: "Re-run Analysis", shortcut: "F5", run: () => void wb.reanalyze(), when: () => !!db },
    { id: "disasm", label: "Open Disassembly", run: () => wb.setCenterTab("disasm"), when: () => !!db },
    { id: "pseudo", label: "Open Pseudocode", run: () => wb.setCenterTab("pseudo"), when: () => !!db },
    { id: "hex", label: "Open Hex View", run: () => wb.setCenterTab("hex"), when: () => !!db },
    { id: "graph", label: "Open Call Graph", run: () => wb.setCenterTab("graph"), when: () => !!db },
    { id: "elf", label: "Open ELF Structure", run: () => wb.setCenterTab("elf"), when: () => !!db },
    { id: "overview", label: "Open Library Overview", run: () => wb.setCenterTab("overview"), when: () => !!db },
    { id: "compare", label: "Compare Binary…", run: pickCompare, when: () => !!db },
    { id: "add-lib", label: "Add Library to Workspace…", run: pickWorkspace, when: () => !!db },
    { id: "links", label: "Open Links / Workspace", run: () => wb.setCenterTab("links"), when: () => !!db },
    { id: "sig", label: "Create Signature (copy 16 bytes at cursor)", run: () => { if (db && wb.currentAddr !== null) { wb.setSearchQuery([...db.readBytes(wb.currentAddr, 16)].map((b) => b.toString(16).padStart(2, "0")).join(" ")); wb.setCenterTab("search"); } }, when: () => wb.currentAddr !== null },
    { id: "exp-fn", label: "Export function list (JSON)", run: () => exportData("functions", "json"), when: () => !!db },
    { id: "exp-fn-csv", label: "Export function list (CSV)", run: () => exportData("functions", "csv"), when: () => !!db },
    { id: "exp-str", label: "Export strings (CSV)", run: () => exportData("strings", "csv"), when: () => !!db },
    { id: "exp-xref", label: "Export XREFs (CSV)", run: () => exportData("xrefs", "csv"), when: () => !!db },
    { id: "exp-dis", label: "Export current function disassembly (TXT)", run: () => exportData("disasm", "txt"), when: () => wb.currentAddr !== null },
    { id: "exp-pse", label: "Export current function pseudocode (TXT)", run: () => exportData("pseudo", "txt"), when: () => wb.currentAddr !== null },
    { id: "exp-rep", label: "Export analysis report (HTML)", run: () => exportData("report", "html"), when: () => !!db },
    { id: "exp-rep-json", label: "Export analysis report (JSON)", run: () => exportData("report", "json"), when: () => !!db },
    { id: "settings", label: "Settings (workers, compute backend)", run: () => setSettingsOpen(true) },
    { id: "toggle-left", label: "Toggle left dock", run: () => setShowLeft((v) => !v) },
    { id: "toggle-right", label: "Toggle right dock", run: () => setShowRight((v) => !v) },
    { id: "toggle-bottom", label: "Toggle bottom dock", run: () => setShowBottom((v) => !v) },
  ], [db, wb, exportData, pickFile, pickCompare, pickWorkspace]);

  // Global keyboard shortcuts
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      const typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
      const k = e.key.toLowerCase();
      if (e.ctrlKey && e.shiftKey && k === "p") { e.preventDefault(); wb.setPaletteOpen(true); return; }
      if (e.ctrlKey && !e.shiftKey && k === "p") { e.preventDefault(); wb.setPaletteOpen(true); return; }
      if (e.ctrlKey && k === "g") { e.preventDefault(); wb.setGotoOpen(true); return; }
      if (e.ctrlKey && k === "o") { e.preventDefault(); pickFile(); return; }
      if (e.ctrlKey && k === "f") { e.preventDefault(); wb.setCenterTab("search"); return; }
      if (e.altKey && e.key === "ArrowLeft") { e.preventDefault(); wb.back(); return; }
      if (e.altKey && e.key === "ArrowRight") { e.preventDefault(); wb.forward(); return; }
      if (typing) return;
      if (e.key === "F2" && wb.currentAddr !== null) { e.preventDefault(); wb.setRenameTarget(db?.functionAt(wb.currentAddr)?.addr ?? wb.currentAddr); }
      else if (e.key === "F5") { e.preventDefault(); void wb.reanalyze(); }
      else if (e.key === "F9" && wb.currentAddr !== null) { e.preventDefault(); wb.toggleBookmark(wb.currentAddr); }
      else if (e.key === "Escape") { if (wb.paletteOpen || wb.gotoOpen || wb.renameTarget !== null || wb.commentTarget !== null) { wb.setPaletteOpen(false); wb.setGotoOpen(false); wb.setRenameTarget(null); wb.setCommentTarget(null); } else if (wb.centerTab === "search") wb.setCenterTab("disasm"); else wb.back(); }
      else if (e.key === ";" && wb.currentAddr !== null) { e.preventDefault(); wb.setCommentTarget(wb.currentAddr); }
      else if (k === "x" && db) wb.setRightTab("xrefs");
      else if (k === "g" && !e.ctrlKey && db) { e.preventDefault(); wb.setGotoOpen(true); }
      else if (e.key === "Tab" && db && !e.ctrlKey) { e.preventDefault(); wb.setCenterTab(wb.centerTab === "disasm" ? "pseudo" : "disasm"); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [wb, db, pickFile]);

  const onDrop = (e: React.DragEvent) => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) void wb.openFile(f); };
  const menus: Record<string, Command[]> = {
    File: commands.filter((c) => ["open", "sample", "add-lib", "compare", "exp-fn", "exp-fn-csv", "exp-str", "exp-xref", "exp-dis", "exp-pse", "exp-rep", "exp-rep-json", "settings"].includes(c.id)),
    Edit: commands.filter((c) => ["rename", "comment", "bookmark", "sig"].includes(c.id)),
    View: commands.filter((c) => ["overview", "disasm", "pseudo", "hex", "graph", "elf", "links", "toggle-left", "toggle-right", "toggle-bottom"].includes(c.id)),
    Analysis: commands.filter((c) => ["analyze", "xrefs", "similar", "compare", "add-lib", "links"].includes(c.id)),
    Search: commands.filter((c) => ["goto", "search", "quick", "back", "fwd"].includes(c.id)),
    AI: commands.filter((c) => ["explain", "why", "suggest", "similar", "callers", "callees", "anticheat", "ban", "hash", "libs", "memcpy", "time", "bypass", "recon"].includes(c.id)),
    Tools: commands.filter((c) => ["sig", "compare", "settings"].includes(c.id)),
    Help: [{ id: "help", label: "Keyboard shortcuts: Ctrl+G go to · Ctrl+P / Ctrl+Shift+P palette · Ctrl+F search · Alt+←/→ history · F2 rename · ; comment · F9 bookmark · X xrefs · Tab asm/pseudo · Esc back", run: () => {} }],
  };

  const centerTabs: { id: CenterTab; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "disasm", label: "Disassembly" }, { id: "pseudo", label: "Pseudocode" }, { id: "hex", label: "Hex" }, { id: "elf", label: "ELF" }, { id: "graph", label: "Call graph" }, { id: "links", label: wb.libs.length > 1 ? `Links (${wb.libs.length})` : "Links" }, { id: "search", label: "Search" }, { id: "compare", label: "Compare" }];
  const leftTabs: { id: LeftTab; label: string }[] = [{ id: "functions", label: "Functions" }, { id: "sections", label: "Sections" }, { id: "imports", label: "Imports" }, { id: "exports", label: "Exports" }, { id: "strings", label: "Strings" }, { id: "structures", label: "Structs" }, { id: "globals", label: "Globals" }, { id: "bookmarks", label: "Bookmarks" }, { id: "tags", label: "Tags" }];
  const rightTabs: { id: RightTab; label: string }[] = [{ id: "info", label: "Info" }, { id: "xrefs", label: "XREFs" }, { id: "ai", label: "AI" }];
  const overall = wb.coordinator?.overallProgress ?? 0;
  const running = wb.stages.some((s) => s.status === "running");

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[#0b0f17] text-zinc-200" onDragOver={(e) => e.preventDefault()} onDrop={onDrop} onClick={() => setMenuOpen(null)}>
      <input ref={setFileInput} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) void wb.openFile(f); e.target.value = ""; }} />
      <input ref={setCompareInput} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) void wb.openCompare(f); e.target.value = ""; }} />
      <input ref={setWorkspaceInput} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) void wb.addLibrary(f); e.target.value = ""; }} />
      {/* Menu bar */}
      <div className="flex h-9 shrink-0 items-center gap-1 border-b border-zinc-800 bg-zinc-950 px-2 text-[12px]">
        <span className="mr-3 flex items-center gap-2 font-semibold tracking-tight text-zinc-100"><span className="inline-block h-4 w-4 rounded bg-gradient-to-br from-sky-400 to-violet-500" />soforge</span>
        {Object.keys(menus).map((m) => (
          <div key={m} className="relative" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => setMenuOpen(menuOpen === m ? null : m)} className={`rounded px-2 py-1 hover:bg-zinc-800 ${menuOpen === m ? "bg-zinc-800" : ""}`}>{m}</button>
            {menuOpen === m && <div className="absolute left-0 top-full z-50 mt-1 min-w-[280px] rounded-md border border-zinc-700 bg-zinc-900 py-1 shadow-2xl">{menus[m].map((c) => <button key={c.id} disabled={c.when ? !c.when() : false} onClick={() => { c.run(); setMenuOpen(null); }} className="flex w-full items-center justify-between px-3 py-1 text-left hover:bg-sky-600/30 disabled:opacity-40"><span>{c.label}</span>{c.shortcut && <span className="ml-6 text-[10px] text-zinc-500">{c.shortcut}</span>}</button>)}</div>}
          </div>
        ))}
        <div className="ml-4 flex items-center gap-1"><Button onClick={wb.back} disabled={!wb.canBack} title="Alt+←">←</Button><Button onClick={wb.forward} disabled={!wb.canForward} title="Alt+→">→</Button></div>
        <button onClick={() => wb.setPaletteOpen(true)} className="ml-3 flex h-7 w-[420px] items-center gap-2 rounded border border-zinc-800 bg-zinc-900 px-2 text-zinc-500 hover:border-zinc-600"><span>⌕</span><span>{db ? `Search ${db.fileName} — functions, strings, addresses, bytes… (Ctrl+P)` : "Open a .so to begin (Ctrl+O)"}</span></button>
        <div className="ml-auto flex items-center gap-3 text-[11px] text-zinc-400">
          {db && <span className="font-mono">{hex(wb.currentAddr)} · {wb.currentAddr !== null ? db.labelFor(wb.currentAddr) : ""}</span>}
          {db && running && <span className="flex items-center gap-2"><span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />Analysis {Math.round(overall * 100)}%</span>}
          {db && !running && <span className="text-emerald-400">● analysis complete</span>}
        </div>
      </div>
      {/* Body */}
      {!db && !wb.loading && <Landing />}
      {wb.loading && !db && <div className="flex flex-1 flex-col items-center justify-center gap-3 text-zinc-400"><div className="h-8 w-8 animate-spin rounded-full border-2 border-zinc-700 border-t-sky-400" /><div>Parsing {wb.fileName}…</div>{wb.error && <div className="text-rose-400">{wb.error}</div>}</div>}
      {db && (
        <div className="flex min-h-0 flex-1">
          {showLeft && (<>
            <div style={{ width: left }} className="flex shrink-0 flex-col border-r border-zinc-800 bg-zinc-950/60">
              <div className="flex shrink-0 flex-wrap border-b border-zinc-800 px-1">{leftTabs.map((t) => <button key={t.id} onClick={() => wb.setLeftTab(t.id)} className={`px-2 py-1.5 text-[11px] ${wb.leftTab === t.id ? "border-b-2 border-sky-500 text-white" : "text-zinc-400 hover:text-zinc-200"}`}>{t.label}</button>)}</div>
              <div className="min-h-0 flex-1">
                {wb.leftTab === "functions" && <FunctionsPanel />}{wb.leftTab === "sections" && <SectionsPanel />}{wb.leftTab === "imports" && <SymbolsPanel kind="imports" />}{wb.leftTab === "exports" && <SymbolsPanel kind="exports" />}{wb.leftTab === "strings" && <StringsPanel />}{wb.leftTab === "structures" && <StructuresPanel />}{wb.leftTab === "globals" && <GlobalsPanel />}{wb.leftTab === "bookmarks" && <BookmarksPanel mode="bookmarks" />}{wb.leftTab === "tags" && <BookmarksPanel mode="tags" />}
              </div>
            </div>
            <Splitter onDrag={(dx) => setLeft((w) => Math.max(200, Math.min(700, w + dx)))} />
          </>)}
          <div className="flex min-w-0 flex-1 flex-col">
            <div className="flex h-8 shrink-0 items-center border-b border-zinc-800 bg-zinc-950/60 px-1">{centerTabs.map((t) => <button key={t.id} onClick={() => wb.setCenterTab(t.id)} className={`px-3 py-1.5 text-[11px] ${wb.centerTab === t.id ? "border-b-2 border-sky-500 text-white" : "text-zinc-400 hover:text-zinc-200"}`}>{t.label}</button>)}<button onClick={() => setShowLeft((v) => !v)} className="ml-auto px-2 text-[11px] text-zinc-500 hover:text-zinc-200" title="Toggle left dock">◧</button><button onClick={() => setShowBottom((v) => !v)} className="px-2 text-[11px] text-zinc-500 hover:text-zinc-200" title="Toggle bottom dock">⬓</button><button onClick={() => setShowRight((v) => !v)} className="px-2 text-[11px] text-zinc-500 hover:text-zinc-200" title="Toggle right dock">◨</button></div>
            <div className="min-h-0 flex-1">
              {wb.centerTab === "overview" && <OverviewView />}{wb.centerTab === "disasm" && <DisassemblyView />}{wb.centerTab === "pseudo" && <PseudocodeView />}{wb.centerTab === "hex" && <HexView />}{wb.centerTab === "elf" && <ElfView />}{wb.centerTab === "graph" && <CallGraphView />}{wb.centerTab === "links" && <LinksView />}{wb.centerTab === "search" && <SearchView />}{wb.centerTab === "compare" && <CompareView />}
            </div>
            {showBottom && (<>
              <HSplitter onDrag={(dy) => setBottom((h) => Math.max(80, Math.min(500, h - dy)))} />
              <div style={{ height: bottom }} className="flex shrink-0 flex-col border-t border-zinc-800 bg-zinc-950/60">
                <div className="flex shrink-0 border-b border-zinc-800 px-1">{(["progress", "console"] as const).map((t) => <button key={t} onClick={() => setBottomTab(t)} className={`px-3 py-1 text-[11px] capitalize ${bottomTab === t ? "border-b-2 border-sky-500 text-white" : "text-zinc-400 hover:text-zinc-200"}`}>{t === "progress" ? "Analysis progress" : "Console / logs"}</button>)}<span className="ml-auto px-2 py-1 text-[10px] text-zinc-600">{backendInfo}</span></div>
                <div className="min-h-0 flex-1">{bottomTab === "console" ? <ConsolePanel /> : <ProgressPanel />}</div>
              </div>
            </>)}
          </div>
          {showRight && (<>
            <Splitter onDrag={(dx) => setRight((w) => Math.max(260, Math.min(800, w - dx)))} />
            <div style={{ width: right }} className="flex shrink-0 flex-col border-l border-zinc-800 bg-zinc-950/60">
              <div className="flex shrink-0 border-b border-zinc-800 px-1">{rightTabs.map((t) => <button key={t.id} onClick={() => wb.setRightTab(t.id)} className={`px-3 py-1.5 text-[11px] ${wb.rightTab === t.id ? "border-b-2 border-sky-500 text-white" : "text-zinc-400 hover:text-zinc-200"}`}>{t.label}</button>)}</div>
              <div className="min-h-0 flex-1">{wb.rightTab === "info" && <FunctionInfoPanel />}{wb.rightTab === "xrefs" && <XrefsPanel />}{wb.rightTab === "ai" && <AIPanel />}</div>
            </div>
          </>)}
        </div>
      )}
      {/* Status bar */}
      <div className="flex h-6 shrink-0 items-center gap-4 border-t border-zinc-800 bg-zinc-950 px-3 text-[11px] text-zinc-500">
        {db ? <><span>{db.arch?.displayName ?? db.elf.header.machineName}</span><span>{fmtBytes(db.bytes.length)}</span><span>{db.functions.length.toLocaleString()} functions</span><span>{db.strings.length.toLocaleString()} strings</span><span>{db.xrefs.count.toLocaleString()} xrefs</span><span>workers: {wb.workerCount}</span>{wb.projectHash && <span className="font-mono">project {wb.projectHash.slice(0, 12)}</span>}{wb.projectRestored && <span className="text-violet-400">restored {wb.projectRestored.names} names · {wb.projectRestored.comments} comments · {wb.projectRestored.bookmarks} bookmarks</span>}</> : <span>Ready — drop an ELF .so anywhere</span>}
        <span className="ml-auto">read-only · no code from the target is executed</span>
      </div>
      <CommandPalette commands={commands} />
      <GoToDialog />
      <RenameDialog />
      <CommentDialog />
      <Modal open={settingsOpen} onClose={() => setSettingsOpen(false)} width={520}>
        <div className="p-4 text-[12px]">
          <div className="mb-3 text-sm font-semibold text-zinc-100">Settings</div>
          <label className="mb-2 block text-zinc-400">Analysis workers (applies on next open) — {navigator.hardwareConcurrency || "?"} logical cores detected</label>
          <input type="range" min={1} max={16} value={wb.workerCount} onChange={(e) => wb.setWorkerCount(Number(e.target.value))} className="w-full" /><div className="font-mono text-zinc-200">{wb.workerCount} workers</div>
          <div className="mt-4 text-zinc-400">Compute backend (applies on next open)</div>
          <div className="mt-1 flex gap-1">{(["auto", "cpu", "gpu"] as const).map((m) => <button key={m} onClick={() => wb.setComputeMode(m)} className={`rounded border px-2 py-0.5 text-[11px] ${wb.computeMode === m ? "border-sky-600 bg-sky-950/40 text-white" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{m === "auto" ? "Auto (benchmark picks)" : m === "cpu" ? "CPU workers" : "GPU if faster"}</button>)}</div>
          <label className="mb-1 mt-3 block text-zinc-400">GPU load target — {Math.round(wb.gpuLoad * 100)}% (slice size + pacing between dispatches)</label>
          <input type="range" min={10} max={100} value={Math.round(wb.gpuLoad * 100)} onChange={(e) => wb.setGpuLoad(Number(e.target.value) / 100)} className="w-full" />
          <div className="text-zinc-200">{backendInfo || "detecting…"}</div>
          <div className="mt-1 text-zinc-500">GPU accelerates the bulk byte-filter stages (string pre-scan, pattern search) with CPU-verified identical output; decoding and classification stay on CPU workers — that&apos;s where the real time goes on big binaries. Auto mode benchmarks both on your machine and routes only when the GPU provably wins. 50% keeps the card responsive while you work.</div>
          <div className="mt-4 text-zinc-400">LLM provider</div><div className="text-zinc-200">{wb.llm?.configured ? `${wb.llm.provider} (${wb.llm.model})` : "none configured — set ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN), or OPENAI_API_KEY / AI_BASE_URL for any OpenAI-compatible server, in .env and restart; the local evidence engine is always active"}</div>
          <div className="mt-1 text-zinc-500">Optional: AI_PROVIDER=anthropic|openai to force one, AI_MODEL to override the model (default claude-opus-5), AI_EFFORT=low|medium|high|xhigh|max for Anthropic reasoning depth. Answers stream; the local verified answer never waits for the LLM.</div>
        </div>
      </Modal>
    </div>
  );
}

function Splitter({ onDrag }: { onDrag: (dx: number) => void }) {
  return <div className="w-1 shrink-0 cursor-col-resize bg-transparent hover:bg-sky-600/50" onMouseDown={(e) => { let x = e.clientX; const mv = (ev: MouseEvent) => { onDrag(ev.clientX - x); x = ev.clientX; }; const up = () => { window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); }; window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up); }} />;
}
function HSplitter({ onDrag }: { onDrag: (dy: number) => void }) {
  return <div className="h-1 shrink-0 cursor-row-resize bg-transparent hover:bg-sky-600/50" onMouseDown={(e) => { let y = e.clientY; const mv = (ev: MouseEvent) => { onDrag(ev.clientY - y); y = ev.clientY; }; const up = () => { window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); }; window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up); }} />;
}

function ProgressPanel() {
  const wb = useWorkbench();
  return (
    <div className="grid h-full grid-cols-4 gap-x-6 gap-y-1 overflow-auto p-3 text-[12px] lg:grid-cols-8">
      {wb.stages.map((s) => (
        <div key={s.id}>
          <div className="flex justify-between"><span className={s.status === "complete" ? "text-zinc-300" : s.status === "running" ? "text-sky-300" : s.status === "error" ? "text-rose-400" : "text-zinc-500"}>{s.label}</span><span className="text-zinc-500">{s.status === "complete" ? "✓" : s.status === "running" ? `${Math.round(s.progress * 100)}%` : s.status === "error" ? "✗" : "…"}</span></div>
          <Progress value={s.status === "complete" ? 1 : s.progress} className="my-1" />
          <div className="truncate text-[10px] text-zinc-500">{s.detail ?? ""}{s.finishedAt && s.startedAt ? ` · ${(s.finishedAt - s.startedAt).toFixed(0)} ms` : ""}</div>
        </div>
      ))}
    </div>
  );
}

function Landing() {
  const wb = useWorkbench();
  const [recent, setRecent] = useState<{ hash: string; fileName: string; size: number; arch: string; analysisState: string }[]>([]);
  useEffect(() => { fetch("/api/projects").then((r) => r.json()).then((j) => j.ok && setRecent(j.projects)).catch(() => {}); }, []);
  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <div className="max-w-3xl">
        <h1 className="text-3xl font-semibold tracking-tight text-zinc-100">Native binary workbench</h1>
        <p className="mt-2 text-zinc-400">Open an ELF shared library. Structure appears instantly; function discovery, cross references, strings, semantic classification and the AI index build in the background while you navigate. Analysis is read-only and runs locally in your browser; annotations are stored in the project database keyed by the binary&apos;s SHA-256.</p>
        <div className="mt-6 flex gap-3">
          <label className="cursor-pointer rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500">Open .so / ELF…<input type="file" className="hidden" onChange={(e) => e.target.files?.[0] && wb.openFile(e.target.files[0])} /></label>
          <Button onClick={() => void wb.openSample()} className="!h-auto px-4 py-2 text-sm">Open sample (ARM64 libsample.so)</Button>
        </div>
        <div className="mt-8 grid grid-cols-3 gap-3 text-[12px] text-zinc-400">
          {[["ELF engine", "ELF32/64, LE/BE, segments, sections, dynamic, symbols, relocations (RELA/REL/RELR), GNU/SysV hash, versions, TLS; stripped-safe"], ["Disassembly", "AArch64 decoder (primary), ARM32 and x86/x86-64 secondary; ADRP+ADD fusion, prologue scoring, branch arrows"], ["Analysis", "Evidence-based function discovery with confidence, XREF index, string categories, rule-based semantic classification, structure inference"], ["Navigation", "Go-To (VA / offset / module+RVA), history, command palette, bookmarks, comments, tags — all keyboard-first"], ["AI", "Evidence-grounded assistant with structured retrieval; optional LLM provider via server env; name suggestions you accept or reject"], ["Performance", "Worker pool scaled to your CPU, chunked scanning, typed-array indices, virtualized views; project cache for instant reopen"]].map(([t, d]) => <div key={t} className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"><div className="mb-1 font-semibold text-zinc-200">{t}</div>{d}</div>)}
        </div>
        {recent.length > 0 && <div className="mt-8"><div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Recent projects (re-open the same file to restore)</div>{recent.slice(0, 8).map((p) => <div key={p.hash} className="flex gap-3 py-0.5 font-mono text-[12px] text-zinc-400"><span className="text-zinc-200">{p.fileName}</span><span>{p.arch}</span><span>{fmtBytes(p.size)}</span><span>{p.analysisState}</span><span className="text-zinc-600">{p.hash.slice(0, 16)}</span></div>)}</div>}
        {wb.error && <div className="mt-4 rounded border border-rose-900 bg-rose-950/30 p-3 text-rose-200">{wb.error}</div>}
      </div>
    </div>
  );
}

// The dialogs below keep their input state in a body component that is only
// mounted while the dialog is open (Modal renders nothing when closed), so the
// state resets on every open without effects that call setState.

function CommandPalette({ commands }: { commands: Command[] }) {
  const wb = useWorkbench();
  return (
    <Modal open={wb.paletteOpen} onClose={() => wb.setPaletteOpen(false)} width={720}>
      <PaletteBody commands={commands} />
    </Modal>
  );
}

function PaletteBody({ commands }: { commands: Command[] }) {
  const wb = useWorkbench();
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const db = wb.db;
  const items = useMemo(() => {
    const t = q.trim();
    const cmdMode = t.startsWith(">") || !db;
    const text = cmdMode ? t.replace(/^>\s*/, "") : t;
    const cmds = commands.filter((c) => (!c.when || c.when()) && (!text || c.label.toLowerCase().includes(text.toLowerCase()))).map((c) => ({ kind: "cmd" as const, label: c.label, sub: c.shortcut ?? "", run: c.run }));
    if (cmdMode || !text) return cmds.slice(0, 40);
    const hits = search(db!, text, { limitPerCategory: 12 }).slice(0, 40).map((h) => ({ kind: "hit" as const, label: h.title, sub: `${h.category} · ${hex(h.address)}${h.subtitle ? " · " + h.subtitle : ""}`, run: () => wb.navigate(h.address, { tab: h.category === "bytes" || h.category === "globals" ? "hex" : "disasm" }) }));
    return [...hits, ...cmds.slice(0, 6)];
  }, [q, commands, db, wb]);
  return (
    <>
      <input autoFocus value={q} onChange={(e) => { setQ(e.target.value); setIdx(0); }} onKeyDown={(e) => { if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(items.length - 1, i + 1)); } else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); } else if (e.key === "Enter" && items[idx]) { items[idx].run(); wb.setPaletteOpen(false); } }} placeholder={db ? "Type to search functions, strings, addresses, bytes… or > for commands" : "> commands"} className="h-11 w-full border-b border-zinc-800 bg-transparent px-4 font-mono text-[13px] text-zinc-100 outline-none placeholder:text-zinc-600" />
      <div className="max-h-[50vh] overflow-auto py-1">
        {items.map((it, i) => <button key={i} onMouseEnter={() => setIdx(i)} onClick={() => { it.run(); wb.setPaletteOpen(false); }} className={`flex w-full items-center gap-3 px-4 py-1.5 text-left text-[12px] ${i === idx ? "bg-sky-600/30" : ""}`}><span className={`w-10 shrink-0 text-[9px] uppercase tracking-wider ${it.kind === "cmd" ? "text-violet-400" : "text-zinc-500"}`}>{it.kind === "cmd" ? "cmd" : ""}</span><span className="truncate font-mono text-zinc-100">{it.label}</span><span className="ml-auto truncate text-zinc-500">{it.sub}</span></button>)}
        {!items.length && <div className="px-4 py-3 text-[12px] text-zinc-500">No matches.</div>}
      </div>
    </>
  );
}

function GoToDialog() {
  const wb = useWorkbench();
  return (
    <Modal open={wb.gotoOpen} onClose={() => wb.setGotoOpen(false)} width={520}>
      <GoToBody />
    </Modal>
  );
}

function GoToBody() {
  const wb = useWorkbench();
  const [q, setQ] = useState("");
  const [err, setErr] = useState("");
  const db = wb.db;
  const go = () => {
    if (!db) return;
    const p = AddressSpace.parseGoTo(q);
    if (!p) return;
    if (p.kind === "name") {
      const hit = search(db, p.value, { categories: ["functions", "symbols", "exports", "imports", "globals", "strings"], limitPerCategory: 1 })[0];
      if (hit) { wb.navigate(hit.address); wb.setGotoOpen(false); } else setErr(`No symbol named "${p.value}"`);
      return;
    }
    const r = db.space.resolve(p);
    if (r) { wb.navigate(r.va, { tab: db.space.isExec(r.va) ? undefined : "hex" }); wb.log("info", "goto", `${q} → ${hex(r.va)} (${r.interpretedAs})`); wb.setGotoOpen(false); }
    else setErr("Address / offset not mapped in this binary");
  };
  return (
    <div className="p-4">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Go to address / offset / symbol</div>
      <Input autoFocus value={q} onChange={(e) => { setQ(e.target.value); setErr(""); }} onKeyDown={(e) => e.key === "Enter" && go()} placeholder="0x7A31F0 · 7A31F0 · module+0x1234 · off:0x1000 · rva:0x40 · lib_init" className="w-full font-mono" />
      <div className="mt-2 text-[11px] text-zinc-500">Plain numbers are hex. Interpreted as VA, then file offset, then RVA — whichever is mapped.</div>
      {err && <div className="mt-2 text-[12px] text-rose-300">{err}</div>}
    </div>
  );
}

function RenameDialog() {
  const wb = useWorkbench();
  const t = wb.renameTarget;
  if (t === null || !wb.db) return null;
  return <RenameBody key={t} addr={t} />;
}

function RenameBody({ addr: t }: { addr: number }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const cur = db.nameFor(t);
  const [v, setV] = useState(() => db.userNames.get(t)?.name ?? (cur.source === "inferred" ? "" : cur.name));
  return (
    <Modal open onClose={() => wb.setRenameTarget(null)} width={480}>
      <div className="p-4">
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Rename {hex(t)}</div>
        <div className="mb-2 text-[12px] text-zinc-500">Current: <span className="font-mono text-zinc-200">{cur.name}</span> <Badge tone={cur.source === "user" ? "violet" : cur.source === "symbol" ? "emerald" : cur.source === "ai" ? "cyan" : "zinc"}>{cur.source}</Badge></div>
        <Input autoFocus value={v} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { wb.rename(t, v); wb.setRenameTarget(null); } }} placeholder="New name (empty = revert to default)" className="w-full font-mono" />
        <div className="mt-3 flex justify-end gap-2"><Button onClick={() => wb.setRenameTarget(null)}>Cancel</Button><Button tone="sky" onClick={() => { wb.rename(t, v); wb.setRenameTarget(null); }}>Rename</Button></div>
      </div>
    </Modal>
  );
}

function CommentDialog() {
  const wb = useWorkbench();
  const raw = wb.commentTarget;
  if (raw === null || !wb.db) return null;
  // Negative targets denote a function-scoped comment (see FunctionsPanel / FunctionInfoPanel).
  const scope: "line" | "function" = raw < 0 ? "function" : "line";
  const t = Math.abs(raw);
  return <CommentBody key={`${scope}:${t}`} addr={t} scope={scope} />;
}

function CommentBody({ addr: t, scope }: { addr: number; scope: "line" | "function" }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const [v, setV] = useState(() => (scope === "function" ? db.functionComments : db.comments).get(t) ?? "");
  return (
    <Modal open onClose={() => wb.setCommentTarget(null)} width={560}>
      <div className="p-4">
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">{scope === "function" ? "Function comment" : "Comment"} @ {hex(t)} — {db.labelFor(t)}</div>
        <textarea autoFocus value={v} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { wb.setComment(t, v, scope); wb.setCommentTarget(null); } }} rows={4} className="w-full rounded border border-zinc-700 bg-zinc-900 p-2 font-mono text-[12px] text-zinc-100 outline-none focus:border-sky-600" />
        <div className="mt-2 flex justify-end gap-2"><span className="mr-auto text-[11px] text-zinc-500">Ctrl+Enter to save</span><Button onClick={() => wb.setCommentTarget(null)}>Cancel</Button><Button tone="sky" onClick={() => { wb.setComment(t, v, scope); wb.setCommentTarget(null); }}>Save</Button></div>
      </div>
    </Modal>
  );
}
