/// <reference lib="webworker" />
import { getArchitecture } from "../core/architecture/registry";
import { scanCodeChunk } from "../core/analysis/codeScan";
import { scanStrings } from "../core/analysis/strings";
import { featurizeSlice } from "../core/analysis/features";
import { compilePattern, scanPattern } from "../core/signatures/pattern";
import type { ArchId } from "../core/elf/types";

/**
 * Stateless analysis worker. Each task carries the bytes it needs (a chunk),
 * so memory scales with chunk size × worker count rather than binary size ×
 * worker count. Results are returned as transferable typed arrays.
 */
export type WorkerTask =
  | { type: "scanCode"; id: number; bytes: Uint8Array; va: number; arch: ArchId; le: boolean; chunkIndex: number; rangeStart: boolean }
  | { type: "scanStrings"; id: number; bytes: Uint8Array; va: number; minLen: number }
  | { type: "pattern"; id: number; bytes: Uint8Array; va: number; pattern: string; limit: number }
  | { type: "featurize"; id: number; bytes: Uint8Array; va: number; arch: ArchId; le: boolean; funcs: { addr: number; size: number }[]; cap: number }
  | { type: "ping"; id: number };

export type WorkerResult = { id: number; ok: true; result: unknown; ms: number } | { id: number; ok: false; error: string };

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = (ev: MessageEvent<WorkerTask>) => {
  const task = ev.data;
  const t0 = performance.now();
  try {
    switch (task.type) {
      case "ping":
        ctx.postMessage({ id: task.id, ok: true, result: "pong", ms: 0 } satisfies WorkerResult);
        return;
      case "scanCode": {
        const arch = getArchitecture(task.arch);
        if (!arch) throw new Error(`Unsupported architecture ${task.arch}`);
        const r = scanCodeChunk(arch, task.bytes, 0, task.va, task.bytes.length, task.le, task.chunkIndex, task.rangeStart);
        const transfer = [r.calls, r.jumps, r.condJumps, r.dataRefs, r.prologues, r.afterTerminators, r.memAccess, r.immediates, r.indirect].map((a) => a.buffer);
        ctx.postMessage({ id: task.id, ok: true, result: r, ms: performance.now() - t0 } satisfies WorkerResult, transfer);
        return;
      }
      case "scanStrings": {
        const r = scanStrings(task.bytes, 0, task.va, task.bytes.length, task.minLen);
        ctx.postMessage({ id: task.id, ok: true, result: r, ms: performance.now() - t0 } satisfies WorkerResult);
        return;
      }
      case "pattern": {
        const pat = compilePattern(task.pattern);
        const offs = scanPattern(task.bytes, pat, 0, task.bytes.length, task.limit);
        ctx.postMessage({ id: task.id, ok: true, result: offs.map((o) => task.va + o), ms: performance.now() - t0 } satisfies WorkerResult);
        return;
      }
      case "featurize": {
        const arch = getArchitecture(task.arch);
        if (!arch) throw new Error(`Unsupported architecture ${task.arch}`);
        const r = featurizeSlice(arch, task.bytes, task.va, task.le, task.funcs, task.cap);
        ctx.postMessage({ id: task.id, ok: true, result: r, ms: performance.now() - t0 } satisfies WorkerResult);
        return;
      }
    }
  } catch (e) {
    ctx.postMessage({ id: (task as { id: number }).id, ok: false, error: e instanceof Error ? e.message : String(e) } satisfies WorkerResult);
  }
};
