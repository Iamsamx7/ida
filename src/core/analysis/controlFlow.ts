import type { Instruction } from "../architecture/types";

export interface FlowEdge {
  from: number;
  to?: number;
  kind: "branch" | "fallthrough" | "indirect";
  external: boolean;
}
export interface BasicBlock {
  address: number;
  end: number;
  instructions: Instruction[];
  successors: FlowEdge[];
  reachable: boolean;
}

/** Build a static CFG from decoded instructions. Calls return to the next instruction.
 * Unknown instructions terminate known flow; indirect destinations stay unresolved. */
export function buildControlFlow(instructions: Instruction[]) {
  const insns = [...instructions].sort((a, b) => a.address - b.address);
  if (!insns.length) return { blocks: [] as BasicBlock[], edges: [] as FlowEdge[], unresolved: 0 };
  const addresses = new Set(insns.map((i) => i.address));
  const leaders = new Set([insns[0].address]);
  const terminates = (i: Instruction) => !i.fallsThrough || ["jump", "condjump", "indirect-jump", "ret", "trap", "unknown"].includes(i.kind);
  for (let n = 0; n < insns.length; n++) {
    const i = insns[n], next = insns[n + 1];
    if ((i.kind === "jump" || i.kind === "condjump") && !i.targetIsData && i.target !== undefined && addresses.has(i.target)) leaders.add(i.target);
    if (next && (terminates(i) || next.address !== i.address + i.size)) leaders.add(next.address);
  }
  const blocks: BasicBlock[] = [];
  for (const i of insns) {
    if (leaders.has(i.address)) blocks.push({ address: i.address, end: i.address, instructions: [], successors: [], reachable: false });
    const block = blocks[blocks.length - 1];
    block.instructions.push(i);
    block.end = i.address + i.size;
  }
  const byAddress = new Map(blocks.map((b) => [b.address, b]));
  let unresolved = 0;
  for (const b of blocks) {
    const last = b.instructions[b.instructions.length - 1];
    const edge = (kind: FlowEdge["kind"], to?: number) => b.successors.push({ from: b.address, to, kind, external: to === undefined || !byAddress.has(to) });
    if (last.kind === "jump" || last.kind === "condjump") {
      const target = last.targetIsData ? undefined : last.target;
      edge("branch", target);
      if (target === undefined || !addresses.has(target)) unresolved++;
    }
    if (last.kind === "indirect-jump" || last.kind === "unknown") { edge("indirect"); unresolved++; }
    if (last.fallsThrough && !["jump", "indirect-jump", "ret", "trap", "unknown"].includes(last.kind)) {
      edge("fallthrough", b.end);
      if (!byAddress.has(b.end)) unresolved++;
    }
  }
  const queue = [blocks[0]];
  blocks[0].reachable = true;
  for (let n = 0; n < queue.length; n++) {
    for (const e of queue[n].successors) {
      const next = e.to === undefined ? undefined : byAddress.get(e.to);
      if (next && !next.reachable) { next.reachable = true; queue.push(next); }
    }
  }
  return { blocks, edges: blocks.flatMap((b) => b.successors), unresolved };
}
