"use client";
import React, { useMemo, useState } from "react";
import { useWorkbench, hex } from "../store";
import { Badge, ContextMenu, VirtualList, confidenceTone, useContextMenu } from "../primitives";
import type { Instruction } from "@/core/architecture/types";
import { makeSignature } from "@/core/signatures/pattern";

const ROW = 20;

interface Row {
  kind: "header" | "insn" | "label";
  addr: number;
  insn?: Instruction;
}

/**
 * Function-scoped, virtualized disassembly with syntax highlighting, branch
 * arrows, XREF indicators, comments and inline navigation.
 */
export function DisassemblyView() {
  const wb = useWorkbench();
  const { db, currentAddr } = wb;
  const menu = useContextMenu();
  const [selected, setSelected] = useState<number | null>(null);

  const model = useMemo(() => {
    if (!db || currentAddr === null || !db.arch) return null;
    const fn = db.functionAt(currentAddr);
    const start = fn ? fn.addr : Math.max(currentAddr - 64 * 4, db.space.rangeAt(currentAddr)?.vaddr ?? currentAddr);
    const len = fn ? fn.size : 512 * 4;
    const insns = db.decodeAt(start, len, 60_000);
    const rows: Row[] = [];
    const targets = new Set<number>();
    for (const i of insns) if ((i.kind === "jump" || i.kind === "condjump") && i.target !== undefined && i.target >= start && i.target < start + len) targets.add(i.target);
    rows.push({ kind: "header", addr: start });
    const indexOf = new Map<number, number>();
    for (const i of insns) {
      if (targets.has(i.address) && i.address !== start) rows.push({ kind: "label", addr: i.address });
      indexOf.set(i.address, rows.length);
      rows.push({ kind: "insn", addr: i.address, insn: i });
    }
    // branch arrows: assign columns greedily
    const arrows: { from: number; to: number; col: number }[] = [];
    const cols: number[][] = [[], [], [], []];
    for (const i of insns) {
      if ((i.kind === "jump" || i.kind === "condjump") && i.target !== undefined && indexOf.has(i.target)) {
        const a = indexOf.get(i.address)!, b = indexOf.get(i.target)!;
        const lo = Math.min(a, b), hi = Math.max(a, b);
        let col = 0;
        for (; col < 4; col++) if (!cols[col].some((k) => k >= lo && k <= hi)) break;
        if (col === 4) col = 3;
        for (let k = lo; k <= hi; k++) cols[col].push(k);
        arrows.push({ from: a, to: b, col });
      }
    }
    return { fn, rows, indexOf, arrows, start, insns };
  }, [db, currentAddr, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps

  const scrollTo = useMemo(() => {
    if (!model || currentAddr === null) return null;
    const idx = model.indexOf.get(currentAddr) ?? 0;
    return { index: idx, nonce: currentAddr + (model.rows.length << 1) };
  }, [model, currentAddr]);

  if (!db) return null;
  if (!db.arch) return <div className="p-6 text-sm text-zinc-400">No disassembler for {db.elf.header.machineName}. Structure, strings and hex views remain available.</div>;
  if (!model || currentAddr === null) return <div className="p-6 text-sm text-zinc-500">Select a function to disassemble.</div>;
  const { fn, rows, arrows } = model;

  const rowMenu = (e: React.MouseEvent, row: Row) => {
    const i = row.insn;
    const items = [
      { label: `Copy address ${hex(row.addr)}`, onClick: () => navigator.clipboard.writeText(hex(row.addr)) },
      { label: "Copy file offset", onClick: () => navigator.clipboard.writeText(hex(db.space.vaToOffset(row.addr) ?? 0)) },
      { label: "Copy instruction", onClick: () => i && navigator.clipboard.writeText(`${i.mnemonic} ${i.opText}`) },
      { label: "Copy bytes", onClick: () => i && navigator.clipboard.writeText([...db.readBytes(i.address, i.size)].map((b) => b.toString(16).padStart(2, "0")).join(" ")) },
      { separator: true, label: "" },
      { label: "Rename…", shortcut: "F2", onClick: () => wb.setRenameTarget(fn?.addr ?? row.addr) },
      { label: "Comment…", shortcut: ";", onClick: () => wb.setCommentTarget(row.addr) },
      { label: db.bookmarks.has(row.addr) ? "Remove bookmark" : "Bookmark", shortcut: "F9", onClick: () => wb.toggleBookmark(row.addr) },
      { label: "Show XREFs to here", shortcut: "X", onClick: () => { wb.navigate(row.addr, { push: false }); wb.setRightTab("xrefs"); } },
      { separator: true, label: "" },
      { label: "Show in hex view", onClick: () => wb.navigate(row.addr, { tab: "hex" }) },
      { label: "Show pseudocode", onClick: () => wb.navigate(row.addr, { tab: "pseudo" }) },
      { label: "Call graph", onClick: () => wb.navigate(row.addr, { tab: "graph" }) },
      { label: "Create signature from here (16 bytes)", onClick: () => { const off = db.space.vaToOffset(row.addr); if (off !== null) { const sig = makeSignature(db.bytes, off, 16, db.arch!.id); navigator.clipboard.writeText(sig); wb.setSearchQuery(sig); wb.setCenterTab("search"); } } },
      { separator: true, label: "" },
      { label: "AI: Explain this function", onClick: () => wb.askAI(`What does this function do? (0x${(fn?.addr ?? row.addr).toString(16)})`) },
      { label: "AI: Suggest a name", onClick: () => wb.askAI(`Suggest a name for 0x${(fn?.addr ?? row.addr).toString(16)}`) },
      { label: "AI: Find similar functions", onClick: () => wb.askAI(`Find functions similar to 0x${(fn?.addr ?? row.addr).toString(16)}`) },
    ];
    if (i?.target !== undefined) items.splice(4, 0, { label: `Follow → ${db.labelFor(i.target)}`, shortcut: "Enter", onClick: () => wb.navigate(i.target!) });
    menu.open(e, items);
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (!model) return;
    const idx = selected !== null ? model.indexOf.get(selected) ?? 0 : 0;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      let n = idx + (e.key === "ArrowDown" ? 1 : -1);
      while (n >= 0 && n < rows.length && rows[n].kind !== "insn") n += e.key === "ArrowDown" ? 1 : -1;
      if (n >= 0 && n < rows.length) { setSelected(rows[n].addr); wb.navigate(rows[n].addr, { push: false }); }
    } else if (e.key === "Enter" && selected !== null) {
      const i = rows[idx].insn;
      if (i?.target !== undefined) wb.navigate(i.target);
    } else if (e.key === ";" && selected !== null) { e.preventDefault(); wb.setCommentTarget(selected); }
    else if (e.key.toLowerCase() === "x" && selected !== null) { wb.setRightTab("xrefs"); }
  };

  return (
    <div className="flex h-full flex-col" tabIndex={0} onKeyDown={onKey}>
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-zinc-800 px-3 text-[11px] text-zinc-400">
        <span className="font-mono text-zinc-200">{fn ? db.nameFor(fn.addr).name : hex(currentAddr)}</span>
        {fn && <span>{fn.size} bytes · {model.insns.length} insns · {db.space.sectionAt(fn.addr)?.name ?? "?"}</span>}
        {fn && <Badge tone={fn.nameSource === "user" ? "violet" : fn.nameSource === "symbol" ? "emerald" : fn.nameSource === "ai" ? "cyan" : "zinc"}>{fn.nameSource === "symbol" ? "known symbol" : fn.nameSource === "user" ? "user-renamed" : fn.nameSource === "ai" ? "ai-suggested" : "inferred"}</Badge>}
        {fn && <Badge tone={confidenceTone(fn.confidence)} title={`Sources: ${fn.sources.join(", ")}`}>confidence {Math.round(fn.confidence * 100)}%</Badge>}
        <span className="ml-auto text-zinc-500">← → history · Enter follow · F2 rename · ; comment · F9 bookmark</span>
      </div>
      <VirtualList
        className="flex-1 font-mono text-[12.5px] leading-5"
        count={rows.length}
        rowHeight={ROW}
        scrollTo={scrollTo}
        render={(idx) => {
          const row = rows[idx];
          if (row.kind === "header") return <FunctionHeader addr={row.addr} />;
          if (row.kind === "label") return <div className="pl-[232px] text-amber-300/90">loc_{row.addr.toString(16)}:</div>;
          const i = row.insn!;
          const isCur = i.address === currentAddr;
          const isSel = i.address === selected;
          const comment = db.comments.get(i.address);
          const xrefCount = db.xrefs.countTo(i.address);
          const bm = db.bookmarks.has(i.address);
          return (
            <div
              className={`group flex h-5 items-center whitespace-nowrap pr-3 ${isCur ? "bg-sky-500/15" : isSel ? "bg-zinc-800/60" : "hover:bg-zinc-800/40"}`}
              onClick={() => { setSelected(i.address); wb.navigate(i.address, { push: false }); }}
              onDoubleClick={() => i.target !== undefined && wb.navigate(i.target)}
              onContextMenu={(e) => rowMenu(e, row)}
            >
              <span className="w-4 text-center text-[10px] text-amber-400">{bm ? "★" : ""}</span>
              <span className="w-[100px] select-all text-zinc-500">{i.address.toString(16).padStart(8, "0")}</span>
              <span className="w-[88px] text-zinc-600">{[...db.readBytes(i.address, i.size)].map((b) => b.toString(16).padStart(2, "0")).join(" ").slice(0, 11)}</span>
              <Arrows idx={idx} arrows={arrows} />
              <Insn i={i} />
              <span className="ml-3 text-zinc-500">{xrefCount > 0 && <span className="cursor-pointer text-cyan-500/80 hover:underline" onClick={(e) => { e.stopPropagation(); wb.navigate(i.address, { push: false }); wb.setRightTab("xrefs"); }}>; XREF[{xrefCount}]</span>}</span>
              {comment && <span className="ml-3 text-emerald-400/90">; {comment}</span>}
            </div>
          );
        }}
      />
      <ContextMenu menu={menu.menu} onClose={menu.close} />
    </div>
  );
}

function Arrows({ idx, arrows }: { idx: number; arrows: { from: number; to: number; col: number }[] }) {
  const W = 40;
  const segs = arrows.filter((a) => idx >= Math.min(a.from, a.to) && idx <= Math.max(a.from, a.to));
  if (!segs.length) return <span style={{ width: W }} className="inline-block shrink-0" />;
  return (
    <svg width={W} height={ROW} className="shrink-0" style={{ overflow: "visible" }}>
      {segs.map((a, k) => {
        const x = W - 6 - a.col * 8;
        const isFrom = idx === a.from, isTo = idx === a.to;
        const up = a.to < a.from;
        const color = up ? "#f59e0b" : "#38bdf8";
        return (
          <g key={k} stroke={color} strokeWidth={1.2} fill="none">
            {!(isFrom || isTo) && <line x1={x} y1={0} x2={x} y2={ROW} />}
            {(isFrom || isTo) && <line x1={x} y1={isFrom === up ? ROW / 2 : 0} x2={x} y2={isFrom === up ? ROW : ROW / 2} />}
            {(isFrom || isTo) && <line x1={x} y1={ROW / 2} x2={W - 1} y2={ROW / 2} />}
            {isTo && <polygon points={`${W - 1},${ROW / 2} ${W - 5},${ROW / 2 - 3} ${W - 5},${ROW / 2 + 3}`} fill={color} stroke="none" />}
          </g>
        );
      })}
    </svg>
  );
}

function Insn({ i }: { i: Instruction }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const cls = db.arch!.syntaxClass(i.mnemonic);
  const mcolor = i.kind === "unknown" ? "text-zinc-600" : cls === "call" ? "text-fuchsia-400" : cls === "branch" ? "text-amber-300" : cls === "ret" ? "text-rose-400" : cls === "mem" ? "text-sky-300" : cls === "cmp" ? "text-orange-300" : cls === "mov" ? "text-teal-300" : cls === "sys" ? "text-zinc-400" : "text-lime-300";
  return (
    <span className="flex items-center">
      <span className={`w-[76px] ${mcolor}`}>{i.mnemonic}</span>
      <span className="text-zinc-200">
        {i.operands.map((o, k) => {
          const sep = k ? ", " : "";
          if (i.target !== undefined && (o.imm === i.target || o.text.includes(i.target.toString(16)))) {
            const label = db.labelFor(i.target);
            const str = db.stringAt(i.target);
            return (
              <span key={k}>{sep}<span className={`cursor-pointer underline decoration-dotted underline-offset-2 ${i.targetIsData ? "text-emerald-300" : "text-fuchsia-300"}`} onClick={(e) => { e.stopPropagation(); wb.navigate(i.target!); }}>{str ? `"${str.value.slice(0, 40)}"` : label}</span></span>
            );
          }
          if (o.reg) return <span key={k}>{sep}<span className="text-cyan-200">{o.text}</span></span>;
          if (o.imm !== undefined) return <span key={k}>{sep}<span className="text-violet-300">{o.text}</span></span>;
          if (o.memBase) return <span key={k}>{sep}<span className="text-sky-200">{o.text}</span></span>;
          return <span key={k}>{sep}{o.text}</span>;
        })}
      </span>
    </span>
  );
}

function FunctionHeader({ addr }: { addr: number }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const fn = db.functionByAddr(addr);
  const name = db.nameFor(addr).name;
  const cmt = db.functionComments.get(addr);
  const callers = fn ? db.xrefs.countTo(addr) : 0;
  return (
    <div className="flex h-5 items-center gap-2 border-t border-zinc-800 bg-zinc-900/40 pl-5 text-[12px]">
      <span className="text-zinc-500">{fn ? "function" : "region"}</span>
      <span className="font-semibold text-sky-300">{name}</span>
      {fn && <span className="text-zinc-500">({fn.sources.join(", ")})</span>}
      {fn && callers > 0 && <Badge tone="cyan" onClick={() => { wb.navigate(addr, { push: false }); wb.setRightTab("xrefs"); }}>xref {callers}</Badge>}
      {fn?.classes?.slice(0, 2).map((c) => <Badge key={c.label} tone={confidenceTone(c.confidence)} title={c.evidence.map((e) => e.text).join("\n")}>{c.level}: {c.label}</Badge>)}
      {[...(db.tags.get(addr) ?? [])].map((t) => <Badge key={t} tone="violet">#{t}</Badge>)}
      {cmt && <span className="text-emerald-400">; {cmt}</span>}
    </div>
  );
}
