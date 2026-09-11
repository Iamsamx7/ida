"use client";
import React, { useMemo, useState } from "react";
import { useWorkbench, hex } from "../store";
import { Badge, ContextMenu, VirtualList, useContextMenu, Input, Button } from "../primitives";
import { generatePseudocode } from "@/core/analysis/pseudocode";
import { compilePattern, scanPattern } from "@/core/signatures/pattern";

const BPR = 16;
const ROW = 20;

/** Professional hex viewer over the whole file (virtualized), synchronized with the current address. */
export function HexView() {
  const wb = useWorkbench();
  const { db, currentAddr, selection } = wb;
  const menu = useContextMenu();
  const [pattern, setPattern] = useState("");
  const [hits, setHits] = useState<number[]>([]);
  const [anchor, setAnchor] = useState<number | null>(null);
  if (!db) return null;
  const bytes = db.bytes;
  const rowCount = Math.ceil(bytes.length / BPR);
  const curOff = currentAddr !== null ? db.space.vaToOffset(currentAddr) : null;
  const scrollTo = curOff !== null ? { index: Math.floor(curOff / BPR), nonce: curOff } : null;
  const selStart = selection ? Math.min(selection.start, selection.end) : -1;
  const selEnd = selection ? Math.max(selection.start, selection.end) : -1;

  const clickByte = (off: number, e: React.MouseEvent) => {
    if (e.shiftKey && anchor !== null) wb.setSelection({ start: anchor, end: off });
    else { setAnchor(off); wb.setSelection({ start: off, end: off }); }
    const va = db.space.offsetToVa(off);
    if (va !== null) wb.navigate(va, { push: false, tab: "hex" });
  };
  const doSearch = () => {
    try {
      const pat = compilePattern(pattern);
      const res = scanPattern(bytes, pat, 0, bytes.length, 500);
      setHits(res);
      if (res.length) { const va = db.space.offsetToVa(res[0]); wb.setSelection({ start: res[0], end: res[0] + pat.length - 1 }); if (va !== null) wb.navigate(va, { tab: "hex" }); }
    } catch (e) { wb.log("warning", "hex", String(e)); }
  };
  const copySel = (asHex: boolean) => {
    if (selStart < 0) return;
    const s = bytes.subarray(selStart, selEnd + 1);
    navigator.clipboard.writeText(asHex ? [...s].map((b) => b.toString(16).padStart(2, "0")).join(" ") : new TextDecoder().decode(s));
  };
  const rowMenu = (e: React.MouseEvent, off: number) => {
    const va = db.space.offsetToVa(off);
    menu.open(e, [
      { label: `Copy offset ${hex(off)}`, onClick: () => navigator.clipboard.writeText(hex(off)) },
      { label: `Copy address ${va !== null ? hex(va) : "(unmapped)"}`, disabled: va === null, onClick: () => navigator.clipboard.writeText(hex(va ?? 0)) },
      { label: "Copy selected bytes (hex)", disabled: selStart < 0, onClick: () => copySel(true) },
      { label: "Copy selected bytes (text)", disabled: selStart < 0, onClick: () => copySel(false) },
      { separator: true, label: "" },
      { label: "Go to disassembly", disabled: va === null || !db.space.isExec(va), onClick: () => va !== null && wb.navigate(va, { tab: "disasm" }) },
      { label: "Bookmark", disabled: va === null, onClick: () => va !== null && wb.toggleBookmark(va, undefined, "data") },
      { label: "Comment…", disabled: va === null, onClick: () => va !== null && wb.setCommentTarget(va) },
      { label: "Use selection as search pattern", disabled: selStart < 0, onClick: () => setPattern([...bytes.subarray(selStart, selEnd + 1)].map((b) => b.toString(16).padStart(2, "0")).join(" ")) },
    ]);
  };
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-zinc-800 px-3 text-[11px] text-zinc-400">
        <span>offset {curOff !== null ? hex(curOff) : "-"} · va {hex(currentAddr)} · {db.space.sectionAt(currentAddr ?? -1)?.name ?? "unmapped"}</span>
        {selStart >= 0 && <Badge tone="sky">{selEnd - selStart + 1} bytes selected</Badge>}
        <div className="ml-auto flex items-center gap-1">
          <Input value={pattern} onChange={(e) => setPattern(e.target.value)} onKeyDown={(e) => e.key === "Enter" && doSearch()} placeholder="pattern: 7F 45 4C ?? 02" className="w-64 font-mono" />
          <Button onClick={doSearch}>Find</Button>
          {hits.length > 0 && <span>{hits.length} hit(s)</span>}
        </div>
      </div>
      <VirtualList className="flex-1 font-mono text-[12.5px] leading-5" count={rowCount} rowHeight={ROW} scrollTo={scrollTo} render={(r) => {
        const base = r * BPR;
        const va = db.space.offsetToVa(base);
        const cells: React.ReactNode[] = [];
        const ascii: React.ReactNode[] = [];
        for (let k = 0; k < BPR; k++) {
          const off = base + k;
          if (off >= bytes.length) { cells.push(<span key={k} className="inline-block w-[22px]" />); continue; }
          const b = bytes[off];
          const sel = off >= selStart && off <= selEnd;
          const cur = curOff !== null && off === curOff;
          const cls = `inline-block w-[22px] cursor-pointer text-center ${cur ? "bg-sky-500/40 text-white" : sel ? "bg-sky-800/50 text-sky-100" : b === 0 ? "text-zinc-700" : b >= 0x20 && b < 0x7f ? "text-zinc-200" : "text-zinc-400"}`;
          cells.push(<span key={k} className={cls} onMouseDown={(e) => clickByte(off, e)} onContextMenu={(e) => rowMenu(e, off)}>{b.toString(16).padStart(2, "0")}</span>);
          ascii.push(<span key={k} className={`${sel || cur ? "bg-sky-800/50 text-sky-100" : b >= 0x20 && b < 0x7f ? "text-emerald-200/90" : "text-zinc-700"}`} onMouseDown={(e) => clickByte(off, e)}>{b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."}</span>);
        }
        return (
          <div className="flex h-5 items-center whitespace-nowrap px-3">
            <span className="w-[90px] text-zinc-500">{base.toString(16).padStart(8, "0")}</span>
            <span className="w-[90px] text-zinc-600">{va !== null ? va.toString(16).padStart(8, "0") : ""}</span>
            <span className="mr-4">{cells}</span>
            <span className="border-l border-zinc-800 pl-3">{ascii}</span>
          </div>
        );
      }} />
      <ContextMenu menu={menu.menu} onClose={menu.close} />
    </div>
  );
}

/** Reconstructed pseudocode with optional side-by-side assembly. */
export function PseudocodeView() {
  const wb = useWorkbench();
  const { db, currentAddr } = wb;
  const [mode, setMode] = useState<"pseudo" | "both">("pseudo");
  const model = useMemo(() => {
    if (!db || currentAddr === null) return null;
    const fn = db.functionAt(currentAddr);
    if (!fn) return null;
    const insns = db.decodeFunction(fn, 6000);
    return { fn, lines: generatePseudocode(db, fn, insns), insns };
  }, [db, currentAddr, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!db) return null;
  if (!model) return <div className="p-6 text-sm text-zinc-500">Select a function to reconstruct pseudocode.</div>;
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-zinc-800 px-3 text-[11px] text-zinc-400">
        <span className="font-mono text-zinc-200">{db.nameFor(model.fn.addr).name}</span>
        <Badge tone="amber" title="Pseudocode is reconstructed from the instruction stream by symbolic forwarding. It is an inference, not the original source.">reconstructed / inferred</Badge>
        <div className="ml-auto flex gap-1">
          {(["pseudo", "both"] as const).map((m) => <button key={m} onClick={() => setMode(m)} className={`rounded px-2 py-0.5 ${mode === m ? "bg-zinc-700 text-white" : "hover:bg-zinc-800"}`}>{m === "pseudo" ? "Pseudocode" : "Both"}</button>)}
          <button onClick={() => wb.setCenterTab("disasm")} className="rounded px-2 py-0.5 hover:bg-zinc-800">Assembly</button>
        </div>
      </div>
      <div className={`grid min-h-0 flex-1 ${mode === "both" ? "grid-cols-2" : "grid-cols-1"} divide-x divide-zinc-800`}>
        <div className="overflow-auto p-3 font-mono text-[12.5px] leading-5">
          {model.lines.map((l, i) => (
            <div key={i} className={`flex ${l.address === currentAddr && l.kind === "code" ? "bg-sky-500/15" : "hover:bg-zinc-800/40"} ${l.kind === "comment" ? "text-zinc-500 italic" : l.kind === "label" ? "text-amber-300" : l.kind === "header" ? "text-sky-300" : "text-zinc-200"}`} onClick={() => l.address !== undefined && wb.navigate(l.address, { push: false })} onDoubleClick={() => l.address !== undefined && wb.navigate(l.address, { tab: "disasm" })}>
              <span className="w-[84px] shrink-0 select-none text-zinc-600">{l.address !== undefined ? l.address.toString(16) : ""}</span>
              <span style={{ paddingLeft: l.indent * 16 }}><Colorize text={l.text} /></span>
            </div>
          ))}
        </div>
        {mode === "both" && (
          <div className="overflow-auto p-3 font-mono text-[12.5px] leading-5">
            {model.insns.map((i, idx) => (
              <div key={`${i.address}:${idx}`} className={`flex ${i.address === currentAddr ? "bg-sky-500/15" : "hover:bg-zinc-800/40"}`} onClick={() => wb.navigate(i.address, { push: false })}>
                <span className="w-[84px] shrink-0 text-zinc-600">{i.address.toString(16)}</span>
                <span className="w-[72px] text-lime-300">{i.mnemonic}</span>
                <span className="text-zinc-200">{i.opText}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Colorize({ text }: { text: string }) {
  const wb = useWorkbench();
  const parts = text.split(/(\b(?:if|goto|return|void|int64_t|int32_t|uint8_t|uint16_t|uint32_t|int8_t|int16_t|float|double|syscall)\b|"[^"]*"|\b0x[0-9a-f]+\b|\bloc_[0-9a-f]+\b|\b(?:sub|g|a)_[0-9a-zA-Z_]+\b)/g);
  return (
    <>
      {parts.map((p, i) => {
        if (/^(if|goto|return|void|int64_t|int32_t|uint8_t|uint16_t|uint32_t|int8_t|int16_t|float|double|syscall)$/.test(p)) return <span key={i} className="text-fuchsia-300">{p}</span>;
        if (/^".*"$/.test(p)) return <span key={i} className="text-emerald-300">{p}</span>;
        if (/^0x[0-9a-f]+$/.test(p)) return <span key={i} className="text-violet-300">{p}</span>;
        if (/^loc_/.test(p)) return <span key={i} className="cursor-pointer text-amber-300 underline decoration-dotted" onClick={(e) => { e.stopPropagation(); wb.navigate(parseInt(p.slice(4), 16), { push: false }); }}>{p}</span>;
        if (/^sub_[0-9a-f]+$/.test(p)) return <span key={i} className="cursor-pointer text-sky-300 underline decoration-dotted" onClick={(e) => { e.stopPropagation(); wb.navigate(parseInt(p.slice(4), 16)); }}>{p}</span>;
        if (/^g_[0-9a-f]+$/.test(p)) return <span key={i} className="cursor-pointer text-teal-300 underline decoration-dotted" onClick={(e) => { e.stopPropagation(); wb.navigate(parseInt(p.slice(2), 16), { tab: "hex" }); }}>{p}</span>;
        return <span key={i}>{p}</span>;
      })}
    </>
  );
}
