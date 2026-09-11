import { parseElf } from "../elf/parser";
import { getArchitecture } from "../architecture/registry";
import { AnalysisDatabase } from "../analysis/database";
import { discoverFunctions } from "../analysis/discovery";
import { toRecords, type RawString } from "../analysis/strings";
import { extractFeatures, featurizeSlice, resolveCalls, type FeaturizeItem } from "../analysis/features";
import { classify, type FunctionContext } from "../analysis/semantic/rules";
import { collectGlobals, inferStructures } from "../analysis/structures";
import { scanCodeChunk } from "../analysis/codeScan";
import { scanStrings } from "../analysis/strings";
import { ANALYSIS_VERSION, type ChunkScanResult, type FunctionRecord, type StageState } from "../analysis/types";
import { buildIntel, type IntelSummary } from "../analysis/intel";
import { CPUBackend, selectBackend, DEFAULT_COMPUTE, type ComputeBackend, type ComputeSettings } from "../../compute/backend";
import { WorkerPool } from "./pool";
import type { WorkerTask } from "../../workers/analysis.worker";

export type LogLevel = "debug" | "info" | "warning" | "error" | "critical";
export interface LogEntry {
  ts: number;
  level: LogLevel;
  source: string;
  message: string;
}

export interface CoordinatorEvents {
  stages: (stages: StageState[]) => void;
  log: (entry: LogEntry) => void;
  update: (what: "elf" | "strings" | "functions" | "xrefs" | "semantic" | "structures" | "intel" | "index" | "hash") => void;
}

export interface AnalysisOptions {
  workers?: number;
  codeChunkSize?: number;
  stringChunkSize?: number;
  minStringLength?: number;
  /** Previously cached function list (from project DB) to show instantly. */
  cachedFunctions?: Partial<FunctionRecord>[] | null;
  compute?: ComputeSettings;
}

const STAGES: [string, string][] = [
  ["elf", "ELF parse"],
  ["hash", "Identity hash"],
  ["strings", "Strings"],
  ["functions", "Function discovery"],
  ["xrefs", "Cross references"],
  ["semantic", "Semantic analysis"],
  ["structures", "Structures & globals"],
  ["intel", "Verified intel"],
  ["index", "AI index"],
];

const yieldToUI = () => new Promise<void>((r) => setTimeout(r, 0));

/**
 * Drives the staged, asynchronous analysis pipeline. Heavy scanning runs in
 * the worker pool; merging and classification run on the main thread in
 * small cooperative slices so the UI never blocks.
 */
export class AnalysisCoordinator {
  db: AnalysisDatabase | null = null;
  stages: StageState[] = STAGES.map(([id, label]) => ({ id, label, status: "pending", progress: 0 }));
  logs: LogEntry[] = [];
  private listeners: { [K in keyof CoordinatorEvents]: Set<CoordinatorEvents[K]> } = { stages: new Set(), log: new Set(), update: new Set() };
  private pool: WorkerPool | null = null;
  private cancelled = false;
  timings: Record<string, number> = {};
  aiIndex: Map<number, string> = new Map();
  intel: IntelSummary | null = null;
  backend: ComputeBackend = new CPUBackend();

  on<K extends keyof CoordinatorEvents>(ev: K, fn: CoordinatorEvents[K]) {
    (this.listeners[ev] as Set<CoordinatorEvents[K]>).add(fn);
    return () => (this.listeners[ev] as Set<CoordinatorEvents[K]>).delete(fn);
  }
  private emit<K extends keyof CoordinatorEvents>(ev: K, ...args: Parameters<CoordinatorEvents[K]>) {
    for (const fn of this.listeners[ev]) (fn as (...a: unknown[]) => void)(...args);
  }
  log(level: LogLevel, source: string, message: string) {
    const e = { ts: Date.now(), level, source, message };
    this.logs.push(e);
    if (this.logs.length > 5000) this.logs.splice(0, 1000);
    this.emit("log", e);
  }
  private setStage(id: string, patch: Partial<StageState>) {
    const s = this.stages.find((x) => x.id === id);
    if (!s) return;
    Object.assign(s, patch);
    if (patch.status === "running" && !s.startedAt) s.startedAt = performance.now();
    if (patch.status === "complete" || patch.status === "error" || patch.status === "skipped") {
      s.finishedAt = performance.now();
      if (s.startedAt) this.timings[id] = s.finishedAt - s.startedAt;
    }
    this.emit("stages", this.stages);
  }

  cancel() {
    this.cancelled = true;
    this.pool?.terminate();
  }

  async open(bytes: Uint8Array, fileName: string, opts: AnalysisOptions = {}) {
    this.cancelled = false;
    const t0 = performance.now();
    // ---- Stage: ELF (synchronous, fast)
    this.setStage("elf", { status: "running" });
    let db: AnalysisDatabase;
    try {
      const elf = parseElf(bytes);
      const arch = getArchitecture(elf.header.arch);
      db = new AnalysisDatabase(elf, bytes, arch, fileName);
      this.db = db;
      for (const w of elf.warnings) this.log(w.level === "error" ? "error" : "warning", "elf", w.message);
      this.log("info", "elf", `${fileName}: ${elf.header.machineName}, ELF${elf.header.elfClass} ${elf.header.littleEndian ? "LE" : "BE"}, ${elf.sections.length} sections, ${elf.segments.length} segments, ${elf.symbols.length} symbols, ${elf.relocations.length} relocations${elf.stripped ? " (stripped)" : ""}`);
      if (!arch) this.log("warning", "arch", `No disassembler for ${elf.header.machineName}; showing structure only`);
      this.setStage("elf", { status: "complete", progress: 1, detail: `${(performance.now() - t0).toFixed(0)} ms` });
    } catch (e) {
      this.setStage("elf", { status: "error", detail: e instanceof Error ? e.message : String(e) });
      this.log("critical", "elf", e instanceof Error ? e.message : String(e));
      throw e;
    }
    this.emit("update", "elf");

    // Cached functions (project DB) → show instantly, verify in background.
    if (opts.cachedFunctions?.length) {
      const fns = opts.cachedFunctions.filter((f) => typeof f.addr === "number").map((f) => ({
        addr: f.addr!, size: f.size ?? 4, name: "", nameSource: "inferred" as const, confidence: f.confidence ?? 0.5, sources: f.sources ?? ["cache"], insnCount: 0, callerCount: 0, calleeCount: 0, isImportStub: false, classes: f.classes,
      }));
      db.setFunctions(fns);
      this.log("info", "cache", `Restored ${fns.length} functions from project database; re-verifying in background`);
      this.emit("update", "functions");
    }

    // ---- Worker pool
    this.pool = new WorkerPool(opts.workers);
    // The inline executor is always installed: it is the fallback when workers cannot be created, fail to load, or die.
    this.pool.setInlineExecutor(async (task: WorkerTask) => {
      await yieldToUI();
      if (task.type === "scanCode") return scanCodeChunk(db.arch!, task.bytes, 0, task.va, task.bytes.length, task.le, task.chunkIndex, task.rangeStart);
      if (task.type === "scanStrings") return scanStrings(task.bytes, 0, task.va, task.bytes.length, task.minLen);
      if (task.type === "featurize") return featurizeSlice(getArchitecture(task.arch)!, task.bytes, task.va, task.le, task.funcs, task.cap);
      return null;
    });
    if (!this.pool.usingWorkers) this.log("warning", "pool", "Web Workers unavailable; running analysis inline with cooperative yielding");
    else this.log("info", "pool", `Worker pool: ${this.pool.size} workers`);

    // ---- Stage: hash (native, async)
    this.setStage("hash", { status: "running" });
    const hashP = new CPUBackend().sha256(bytes).then((h) => {
      db.hash = h;
      this.setStage("hash", { status: "complete", progress: 1, detail: h.slice(0, 16) + "…" });
      this.emit("update", "hash");
    }).catch((e) => { this.setStage("hash", { status: "error", detail: String(e) }); });

    // ---- Stage: strings + code scan (parallel in pool)
    const stringsP = this.runStrings(db, opts);
    const codeP = db.arch ? this.runCodeScan(db, opts) : Promise.resolve([] as ChunkScanResult[]);
    await stringsP;
    if (this.cancelled) return db;
    const chunks = await codeP;
    if (this.cancelled) return db;

    // ---- Stage: functions + xrefs merge
    this.setStage("xrefs", { status: "running", progress: 0.2 });
    await yieldToUI();
    const t1 = performance.now();
    const { functions, xrefs, memAccess, immediates, droppedCandidates } = discoverFunctions(db, chunks);
    db.setFunctions(functions);
    db.memAccess = memAccess;
    db.immediates = immediates;
    db.setXrefs(xrefs);
    db.insnTotal = chunks.reduce((a, c) => a + c.insnCount, 0);
    db.unknownTotal = chunks.reduce((a, c) => a + c.unknownCount, 0);
    if (db.insnTotal > 1000 && db.unknownTotal / db.insnTotal > 0.25) {
      this.log("warning", "functions", `${Math.round((db.unknownTotal / db.insnTotal) * 100)}% of the executable bytes do not decode as ${db.arch?.displayName ?? "known"} instructions — the code is probably packed, encrypted or not code at all; function discovery and xrefs are unreliable for this binary`);
    }
    // Tail-call / jump-only functions: jumps whose target is not inside any function → promote if aligned & in code
    this.log("info", "functions", `${functions.length} functions (${functions.filter((f) => f.sources.includes("symbol")).length} from symbols, ${functions.filter((f) => !f.sources.includes("symbol")).length} inferred), ${xrefs.count} xrefs, ${db.insnTotal} instructions decoded (${db.unknownTotal} undecodable words) in ${(performance.now() - t1).toFixed(0)} ms merge`);
    if (droppedCandidates > 0) this.log("warning", "functions", `Mass valve: dropped ${droppedCandidates.toLocaleString()} weakest phantom candidates (packed/encrypted code); kept all strong evidence + top fill. Raise binary quality, not thresholds — the drops were sub-0.7 with no symbol/call support.`);
    this.setStage("functions", { status: "complete", progress: 1, detail: `${functions.length} functions` });
    this.setStage("xrefs", { status: "complete", progress: 1, detail: `${xrefs.count} references` });
    this.emit("update", "functions");
    this.emit("update", "xrefs");
    await hashP;

    // ---- Stage: semantic (cooperative main-thread slices)
    await this.runSemantic(db);
    if (this.cancelled) return db;

    // ---- Stage: structures & globals
    this.setStage("structures", { status: "running" });
    await yieldToUI();
    try {
      db.structures = inferStructures(db);
      db.globals = collectGlobals(db);
      this.setStage("structures", { status: "complete", progress: 1, detail: `${db.structures.length} structures · ${db.globals.length} globals` });
    } catch (e) {
      this.setStage("structures", { status: "error", detail: String(e) });
      this.log("error", "structures", String(e));
    }
    this.emit("update", "structures");

    // ---- Stage: verified intel (auto-verify hash/ban/anticheat on load)
    this.setStage("intel", { status: "running" });
    await yieldToUI();
    try {
      const tIntel = performance.now();
      this.intel = buildIntel(db);
      const s = this.intel;
      this.setStage("intel", { status: "complete", progress: 1, detail: `${s.findings.length} findings (${s.provenCount} proven)` });
      this.log("info", "intel", `Verified intel: ${s.counts["hash-check"]} hash-check · ${s.counts["ban-check"]} ban · ${s.counts.anticheat} anticheat · ${s.counts["game-revive"]} revive (${s.provenCount} proven, ${s.findings.length - s.provenCount} corroborated/lead) in ${(performance.now() - tIntel).toFixed(0)} ms${s.packedSuspect ? " · packed suspect: absence proves nothing" : ""}`);
    } catch (e) {
      this.setStage("intel", { status: "error", detail: String(e) });
      this.log("error", "intel", String(e));
    }
    this.emit("update", "intel");

    // ---- Stage: AI index (retrieval text per function)
    await this.runIndex(db);
    this.log("info", "pipeline", `Analysis complete in ${((performance.now() - t0) / 1000).toFixed(2)} s (worker CPU time ${(this.pool.totalWorkerMs / 1000).toFixed(2)} s over ${this.pool.tasksCompleted} tasks)`);
    return db;
  }

  private async runStrings(db: AnalysisDatabase, opts: AnalysisOptions) {
    this.setStage("strings", { status: "running" });
    const chunk = opts.stringChunkSize ?? 1 << 20;
    const overlap = 4096;
    const minLen = opts.minStringLength ?? 4;
    // Prefer non-executable alloc sections; fall back to all mapped ranges.
    let ranges = db.elf.sections.filter((s) => s.alloc && s.type !== 8 && !s.exec && s.size > 0 && !/^\.(rela?|relr|dynsym|hash|gnu\.hash|gnu\.version|eh_frame|eh_frame_hdr|init_array|fini_array|got|got\.plt|data\.rel\.ro)/.test(s.name)).map((s) => ({ offset: s.offset, va: s.addr, size: s.size }));
    if (!ranges.length) ranges = db.space.ranges.map((r) => ({ offset: r.offset, va: r.vaddr, size: r.size }));
    // Backend pick: GPU must win a live benchmark to take the stage.
    const compute = { ...DEFAULT_COMPUTE, ...(opts.compute ?? {}) };
    try {
      const sample = db.bytes.subarray(0, Math.min(db.bytes.length, 2 << 20));
      const rep = await selectBackend(sample, compute);
      this.backend = rep.selected;
      this.log("info", "compute", `String scan backend: ${rep.selected.describe()}${rep.benchmark ? ` (cpu ${rep.benchmark.cpuMs.toFixed(0)} ms${rep.benchmark.gpuMs !== undefined ? ` vs gpu ${rep.benchmark.gpuMs.toFixed(0)} ms` : ""})` : ""}`);
    } catch {
      this.backend = new CPUBackend();
    }
    // GPU path runs cooperatively on the main thread (workers can't reliably
    // touch WebGPU); CPU path fans out to the worker pool as before.
    if (this.backend.id === "webgpu") {
      await this.runStringsGpu(db, ranges, chunk, overlap, minLen);
      return;
    }
    const tasks: Promise<RawString[]>[] = [];
    let total = 0, done = 0;
    for (const r of ranges) for (let o = 0; o < r.size; o += chunk) total++;
    for (const r of ranges) {
      for (let o = 0; o < r.size; o += chunk) {
        const len = Math.min(chunk + overlap, r.size - o);
        const slice = db.bytes.slice(r.offset + o, r.offset + o + len);
        const va = r.va + o;
        tasks.push(this.pool!.run<RawString[]>({ type: "scanStrings", bytes: slice, va, minLen }, [slice.buffer]).then((res) => {
          done++;
          this.setStage("strings", { progress: done / total });
          // drop strings that begin in the overlap tail (they belong to the next chunk) unless this is the last chunk
          const limit = va + chunk;
          return o + chunk < r.size ? res.filter((s) => s.addr < limit) : res;
        }));
      }
    }
    try {
      const results = await Promise.all(tasks);
      const all = results.flat();
      const seen = new Set<number>();
      const uniq = all.filter((s) => (seen.has(s.addr) ? false : (seen.add(s.addr), true)));
      db.setStrings(toRecords(uniq));
      this.setStage("strings", { status: "complete", progress: 1, detail: `${uniq.length} strings` });
      this.log("info", "strings", `${uniq.length} strings from ${ranges.length} ranges`);
    } catch (e) {
      this.setStage("strings", { status: "error", detail: String(e) });
      this.log("error", "strings", String(e));
    }
    this.emit("update", "strings");
  }

  /** GPU string stage: prefilter on the card, exact verify on CPU — same output. */
  private async runStringsGpu(db: AnalysisDatabase, ranges: { offset: number; va: number; size: number }[], chunk: number, overlap: number, minLen: number) {
    try {
      const all: RawString[] = [];
      let done = 0;
      const total = ranges.reduce((a, r) => a + Math.ceil(r.size / chunk), 0);
      for (const r of ranges) {
        for (let o = 0; o < r.size; o += chunk) {
          if (this.cancelled) return;
          const len = Math.min(chunk + overlap, r.size - o);
          const slice = db.bytes.slice(r.offset + o, r.offset + o + len);
          const va = r.va + o;
          const found = await this.backend.scanStrings(slice, va, len, minLen, () => {
            this.setStage("strings", { progress: (done + 0.5) / Math.max(1, total) });
          });
          const limit = va + chunk;
          all.push(...(o + chunk < r.size ? found.filter((s) => s.addr < limit) : found));
          done++;
          this.setStage("strings", { progress: done / Math.max(1, total) });
          await yieldToUI();
        }
      }
      const seen = new Set<number>();
      const uniq = all.filter((s) => (seen.has(s.addr) ? false : (seen.add(s.addr), true)));
      db.setStrings(toRecords(uniq));
      this.setStage("strings", { status: "complete", progress: 1, detail: `${uniq.length} strings (GPU)` });
      this.log("info", "strings", `${uniq.length} strings from ${ranges.length} ranges (GPU prefilter + CPU verify)`);
    } catch (e) {
      this.log("warning", "compute", `GPU string scan failed mid-run (${String(e)}) — falling back to CPU workers`);
      this.backend = new CPUBackend();
      this.setStage("strings", { status: "running", progress: 0 });
      // Re-run the CPU worker path for the same ranges.
      const tasks: Promise<RawString[]>[] = [];
      let total = 0, done = 0;
      for (const r of ranges) for (let o = 0; o < r.size; o += chunk) total++;
      for (const r of ranges) {
        for (let o = 0; o < r.size; o += chunk) {
          const len = Math.min(chunk + overlap, r.size - o);
          const slice = db.bytes.slice(r.offset + o, r.offset + o + len);
          const va = r.va + o;
          tasks.push(this.pool!.run<RawString[]>({ type: "scanStrings", bytes: slice, va, minLen }, [slice.buffer]).then((res) => {
            done++;
            this.setStage("strings", { progress: done / total });
            const limit = va + chunk;
            return o + chunk < r.size ? res.filter((s) => s.addr < limit) : res;
          }));
        }
      }
      try {
        const results = await Promise.all(tasks);
        const seen = new Set<number>();
        const uniq = results.flat().filter((s) => (seen.has(s.addr) ? false : (seen.add(s.addr), true)));
        db.setStrings(toRecords(uniq));
        this.setStage("strings", { status: "complete", progress: 1, detail: `${uniq.length} strings` });
        this.log("info", "strings", `${uniq.length} strings from ${ranges.length} ranges (CPU fallback)`);
      } catch (e2) {
        this.setStage("strings", { status: "error", detail: String(e2) });
        this.log("error", "strings", String(e2));
      }
    }
    this.emit("update", "strings");
  }

  private async runCodeScan(db: AnalysisDatabase, opts: AnalysisOptions): Promise<ChunkScanResult[]> {
    this.setStage("functions", { status: "running" });
    const chunk = opts.codeChunkSize ?? 512 * 1024;
    const ranges = db.space.codeRanges();
    const tasks: Promise<ChunkScanResult>[] = [];
    let total = 0, done = 0, idx = 0;
    for (const r of ranges) for (let o = 0; o < r.size; o += chunk) total++;
    for (const r of ranges) {
      for (let o = 0; o < r.size; o += chunk) {
        const len = Math.min(chunk, r.size - o);
        const slice = db.bytes.slice(r.offset + o, r.offset + o + len);
        const chunkIndex = idx++;
        tasks.push(this.pool!.run<ChunkScanResult>({ type: "scanCode", bytes: slice, va: r.vaddr + o, arch: db.arch!.id, le: db.elf.header.littleEndian, chunkIndex, rangeStart: o === 0 }, [slice.buffer]).then((res) => {
          done++;
          this.setStage("functions", { progress: (done / total) * 0.9, detail: `${done}/${total} chunks` });
          return res;
        }));
      }
    }
    try {
      const res = await Promise.all(tasks);
      res.sort((a, b) => a.chunkIndex - b.chunkIndex);
      return res;
    } catch (e) {
      this.setStage("functions", { status: "error", detail: String(e) });
      this.log("error", "functions", String(e));
      return [];
    }
  }

  private classifyOne(db: AnalysisDatabase, f: FunctionRecord, importsAll: Set<string>) {
    try {
      const r = resolveCalls(db, f);
      if (!f.features) throw new Error("missing features");
      f.features.stringRefs = r.stringRefs;
      f.features.callees = r.callees;
      f.features.importCalls = r.importCalls;
      const ctx: FunctionContext = {
        addr: f.addr,
        name: f.name,
        size: f.size,
        features: f.features,
        calleeNames: [...f.features.callees.map((c) => db.nameFor(c).name), ...f.features.importCalls],
        callerNames: [],
        stringValues: f.features.stringRefs.map((a) => db.stringAt(a)).filter((s): s is NonNullable<typeof s> => !!s).map((s) => ({ addr: s.addr, value: s.value, category: s.category })),
        importsAll,
      };
      f.classes = classify(ctx);
    } catch (e) {
      f.classes = [];
      this.log("debug", "semantic", `classification failed at 0x${f.addr.toString(16)}: ${String(e)}`);
    }
  }

  private async runSemantic(db: AnalysisDatabase) {
    this.setStage("semantic", { status: "running" });
    const importsAll = new Set(db.elf.imports.map((i) => i.name));
    const fns = db.functions;
    // Adaptive decode budget: huge binaries (tens of thousands of functions)
    // decode fewer instructions per function for classification — the head of
    // each function carries almost all the signal. Honest trade, logged below.
    const decodeLim = fns.length > 30000 ? 1200 : fns.length > 10000 ? 2000 : 3000;
    if (decodeLim < 3000) this.log("info", "semantic", `Large binary (${fns.length} functions): classification decode capped at ${decodeLim} insns/function for speed; full decode still available per-function in disassembly`);
    // Weak-tail skip: past 100k functions, sub-0.5 candidates cost more than
    // they teach — decoding + classifying each is ~ms of main-thread time for
    // phantoms. Skipped entries keep their discovery evidence and stay
    // browsable; they just don't get rule labels.
    const skipWeak = fns.length > 100_000;
    let skipped = 0;
    const t0 = performance.now();
    // Eligible = everything that actually needs decode work.
    const eligible: FunctionRecord[] = [];
    for (const f of fns) {
      if (f.isImportStub) { f.classes = []; continue; }
      if (skipWeak && f.confidence < 0.5) { f.classes = []; f.insnCount = 0; skipped++; continue; }
      eligible.push(f);
    }
    if (!db.arch || !this.pool?.usingWorkers) {
      // Inline fallback (no workers): original main-thread path.
      if (db.arch) this.log("warning", "semantic", "Workers unavailable — classifying on the main thread; the UI may stutter on large binaries");
      const SLICE = 150;
      for (let i = 0; i < eligible.length; i += SLICE) {
        if (this.cancelled) return;
        const end = Math.min(eligible.length, i + SLICE);
        for (let k = i; k < end; k++) {
          const f = eligible[k];
          try {
            const insns = db.decodeFunction(f, decodeLim);
            f.insnCount = insns.length;
            f.features = extractFeatures(db, f, insns);
            this.classifyOne(db, f, importsAll);
          } catch (e) {
            f.classes = [];
            this.log("debug", "semantic", `classification failed at 0x${f.addr.toString(16)}: ${String(e)}`);
          }
        }
        this.setStage("semantic", { progress: end / Math.max(1, fns.length), detail: `${end}/${fns.length} functions` });
        if (end % (SLICE * 4) === 0) this.emit("update", "semantic");
        await yieldToUI();
      }
    } else {
      // Parallel path: decode + summarize in workers across all cores, then
      // resolve names + classify on the main thread (microseconds per fn, UI stays smooth).
      const byAddr = new Map<number, FunctionRecord>();
      for (const f of eligible) byAddr.set(f.addr, f);
      const batches: { funcs: { addr: number; size: number }[] }[] = [];
      const ranges = db.space.codeRanges();
      let cur: { funcs: { addr: number; size: number }[]; startOff: number; endOff: number } | null = null;
      const MAX_SPAN = 256 * 1024, MAX_FNS = 256;
      const flush = () => {
        if (cur && cur.funcs.length) {
          batches.push({ funcs: cur.funcs });
          cur = null;
        }
      };
      for (const f of eligible) {
        const range = ranges.find((r) => f.addr >= r.vaddr && f.addr < r.vaddr + r.size);
        if (!range) continue;
        const startOff = db.space.vaToOffset(f.addr);
        if (startOff === null) continue;
        const endOff = Math.min(startOff + Math.max(f.size, 4), range.offset + range.size);
        // New batch unless contiguous (≤4KB gap), same span budget and count budget.
        if (!cur || startOff > cur.endOff + 0x1000 || endOff - cur.startOff > MAX_SPAN || cur.funcs.length >= MAX_FNS) {
          flush();
          cur = { funcs: [], startOff, endOff };
        } else {
          cur.endOff = Math.max(cur.endOff, endOff);
        }
        cur.funcs.push({ addr: f.addr, size: f.size });
      }
      flush();
      // One byte slice per batch, anchored on VA.
      const jobs = batches.map((b) => {
        const va0 = b.funcs[0].addr;
        const off0 = db.space.vaToOffset(va0)!;
        const off1 = Math.max(...b.funcs.map((f) => db.space.vaToOffset(f.addr)! + Math.max(f.size, 4)));
        return { bytes: db.bytes.slice(off0, off1), va: va0, funcs: b.funcs };
      });
      this.log("info", "semantic", `Classifying ${eligible.length} functions: decode in ${jobs.length} batches across ${this.pool.size} workers, main thread only resolves + labels`);
      let done = 0;
      const CHUNK_LOG = Math.max(1, Math.floor(jobs.length / 20));
      await Promise.all(jobs.map((j) =>
        this.pool!.run<FeaturizeItem[]>({ type: "featurize", bytes: j.bytes, va: j.va, arch: db.arch!.id, le: db.elf.header.littleEndian, funcs: j.funcs, cap: decodeLim }, [j.bytes.buffer]).then((items) => {
          for (const it of items) {
            const f = byAddr.get(it.addr);
            if (!f) continue;
            f.insnCount = it.summary.insnCount;
            f.features = {
              mnemonicHist: it.summary.hist,
              constants: it.summary.constants,
              stringRefs: [],
              callees: [],
              importCalls: [],
              branchCount: it.summary.branchCount,
              callCount: it.summary.callCount,
              loadCount: it.summary.loadCount,
              storeCount: it.summary.storeCount,
              memAccessOffsets: it.summary.offsets,
              hasLoop: it.summary.hasLoop,
              fingerprint: it.summary.fingerprint,
            };
            this.classifyOne(db, f, importsAll);
          }
          done++;
          if (done % CHUNK_LOG === 0 || done === jobs.length) {
            this.setStage("semantic", { progress: done / Math.max(1, jobs.length), detail: `${done}/${jobs.length} batches` });
            this.emit("update", "semantic");
          }
        }),
      ));
      if (this.cancelled) return;
    }
    const classified = fns.filter((f) => f.classes && f.classes.length).length;
    this.setStage("semantic", { status: "complete", progress: 1, detail: `${classified} classified${skipped ? ` · ${skipped} weak skipped` : ""}` });
    this.log("info", "semantic", `${classified}/${fns.length} functions received a classification${skipped ? `, ${skipped} weak tail skipped (sub-0.5, still browsable)` : ""} in ${(performance.now() - t0).toFixed(0)} ms`);
    this.emit("update", "semantic");
  }

  private async runIndex(db: AnalysisDatabase) {
    this.setStage("index", { status: "running" });
    const fns = db.functions;
    // Huge binaries: indexing 1M+ anonymous stubs bloats memory and buys
    // nothing for search — index the interesting ones only.
    const selective = fns.length > 100_000;
    let indexed = 0;
    const SLICE = 400;
    for (let i = 0; i < fns.length; i += SLICE) {
      if (this.cancelled) return;
      const end = Math.min(fns.length, i + SLICE);
      for (let k = i; k < end; k++) {
        const f = fns[k];
        if (selective && !f.classes?.length && f.nameSource === "inferred" && f.confidence < 0.7) continue;
        const parts = [f.name];
        if (f.classes?.length) parts.push(...f.classes.map((c) => c.label));
        if (f.features) {
          parts.push(...f.features.importCalls);
          for (const a of f.features.stringRefs.slice(0, 8)) { const s = db.stringAt(a); if (s) parts.push(s.value.slice(0, 40)); }
        }
        this.aiIndex.set(f.addr, parts.join(" ").toLowerCase());
        indexed++;
      }
      this.setStage("index", { progress: end / Math.max(1, fns.length) });
      await yieldToUI();
    }
    this.setStage("index", { status: "complete", progress: 1, detail: `${this.aiIndex.size} entries${selective ? ` (selective of ${fns.length})` : ""}` });
    if (selective) this.log("info", "index", `Selective AI index: ${indexed} interesting entries of ${fns.length} functions (anonymous weak tail omitted)`);
    this.emit("update", "index");
  }

  get analysisVersion() {
    return ANALYSIS_VERSION;
  }
  get overallProgress() {
    const w = this.stages.filter((s) => s.status !== "skipped");
    return w.reduce((a, s) => a + (s.status === "complete" ? 1 : s.progress), 0) / Math.max(1, w.length);
  }
}
