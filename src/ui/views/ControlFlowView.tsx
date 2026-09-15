"use client";
import React, { useMemo } from "react";
import { useWorkbench, hex } from "../store";
import { Badge, Button } from "../primitives";
import { buildControlFlow } from "@/core/analysis/controlFlow";
import { downloadText } from "../download";

export function ControlFlowView() {
  const wb = useWorkbench();
  const { db, currentAddr } = wb;
  const fn = db && currentAddr !== null ? db.functionAt(currentAddr) : null;
  const model = useMemo(() => {
    if (!db || !fn) return null;
    const instructions = db.decodeFunction(fn, 12000);
    return { ...buildControlFlow(instructions), truncated: !!instructions.length && instructions[instructions.length - 1].address + instructions[instructions.length - 1].size < fn.addr + fn.size };
  }, [db, fn, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!db || !fn || !model) return <div className="p-6 text-sm text-zinc-400">Select a function to inspect its control flow.</div>;
  const jump = (address: number) => {
    wb.navigate(address, { tab: "flow" });
    document.getElementById(`block-${address}`)?.scrollIntoView({ block: "center", behavior: "smooth" });
  };
  return <div className="flex h-full flex-col">
    <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 p-3 text-[12px]">
      <span className="font-mono text-sky-200">{db.nameFor(fn.addr).name}</span>
      <Badge tone="sky">{model.blocks.length} blocks</Badge><Badge>{model.edges.length} edges</Badge>
      {!!model.unresolved && <Badge tone="amber">{model.unresolved} unresolved / external</Badge>}
      <Button className="ml-auto" onClick={() => downloadText(`${db.nameFor(fn.addr).name}.flow.json`, JSON.stringify({ file: db.fileName, sha256: db.hash, function: fn.addr, ...model }, null, 2), "application/json")}>Export flow</Button>
    </div>
    <div className="border-b border-zinc-800 bg-sky-950/15 px-3 py-2 text-[11px] text-zinc-400">Static flow from decoded instructions. Calls resume at the next instruction; indirect jumps and unknown instructions stop known flow. Unreached blocks may still be reached at runtime.{model.truncated && <span className="ml-1 text-amber-300">Limited to the first 12,000 instructions.</span>}</div>
    <div className="min-h-0 flex-1 overflow-auto p-4">
      {!model.blocks.length && <p className="text-zinc-500">No decoded instructions available.</p>}
      <div className="grid items-start gap-4 xl:grid-cols-2">
        {model.blocks.slice(0, 500).map((block, index) => {
          const active = currentAddr !== null && currentAddr >= block.address && currentAddr < block.end;
          return <section id={`block-${block.address}`} key={block.address} className={`overflow-hidden rounded-lg border ${active ? "border-sky-500 bg-sky-950/20 shadow-lg shadow-sky-950/30" : "border-zinc-700 bg-zinc-900/50"}`}>
            <div className="flex items-center gap-2 border-b border-zinc-800 px-3 py-2 text-[11px]"><Badge tone={index === 0 ? "emerald" : "zinc"}>{index === 0 ? "entry" : `block ${index + 1}`}</Badge><button className="font-mono text-sky-300 hover:underline" onClick={() => wb.navigate(block.address, { tab: "disasm" })}>{hex(block.address)} ↗</button><span className="ml-auto text-zinc-500">{block.instructions.length} insns</span>{!block.reachable && <Badge tone="amber">not reached statically</Badge>}</div>
            <div className="max-h-64 overflow-auto p-2 font-mono text-[12px]">
              {block.instructions.map((i) => <button key={i.address} onClick={() => wb.navigate(i.address, { tab: "disasm" })} className="flex w-full gap-3 rounded px-1 text-left hover:bg-sky-900/30"><span className="text-zinc-500">{i.address.toString(16)}</span><span className="min-w-16 text-lime-300">{i.mnemonic}</span><span className="text-zinc-300">{i.opText}</span></button>)}
            </div>
            <div className="flex flex-wrap gap-2 border-t border-zinc-800 px-3 py-2 text-[11px]">
              {!block.successors.length && <span className="text-zinc-500">{block.instructions.at(-1)?.kind === "ret" ? "Return" : "End of known flow"}</span>}
              {block.successors.map((edge, n) => <button key={n} disabled={edge.to === undefined} onClick={() => edge.to !== undefined && (edge.external ? wb.navigate(edge.to, { tab: "disasm" }) : jump(edge.to))} className={`rounded border px-2 py-1 disabled:opacity-60 ${edge.kind === "fallthrough" ? "border-emerald-900 text-emerald-300" : "border-amber-900 text-amber-300"}`}>{edge.kind === "fallthrough" ? "Next" : edge.kind === "indirect" ? "Unresolved" : "Branch"} → {edge.to === undefined ? "unknown" : hex(edge.to)}{edge.external && edge.to !== undefined ? " (outside decoded blocks)" : ""}</button>)}
            </div>
          </section>;
        })}
      </div>
      {model.blocks.length > 500 && <p className="mt-4 text-amber-300">Showing 500 blocks. Export flow for the full decoded graph.</p>}
    </div>
  </div>;
}
