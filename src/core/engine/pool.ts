import type { WorkerResult, WorkerTask } from "../../workers/analysis.worker";

type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;
export type TaskInput = DistributiveOmit<WorkerTask, "id">;

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; task: WorkerTask; transfer: Transferable[] };

/** How long the pool waits for at least one worker to answer the startup ping before giving up on workers. */
const READY_TIMEOUT_MS = 8000;

/**
 * Bounded worker pool with a FIFO task queue. Worker count is configurable
 * (defaults to cores-1, min 1, max 16). Falls back to an inline executor if
 * Web Workers cannot be created, fail to load, or die, so the app still works
 * everywhere.
 *
 * Every worker must answer a startup ping before it receives real tasks;
 * task payloads are transferred (not copied), so they are only handed to
 * workers that are known to be alive.
 */
export class WorkerPool {
  private workers: Worker[] = [];
  private idle: Worker[] = [];
  private ready = new Set<Worker>();
  private queue: Pending[] = [];
  private inflight = new Map<Worker, Pending>();
  private nextId = 1;
  private inline: ((task: WorkerTask) => Promise<unknown>) | null = null;
  private readyTimer: ReturnType<typeof setTimeout> | null = null;
  readonly size: number;
  tasksCompleted = 0;
  totalWorkerMs = 0;

  constructor(size?: number) {
    const cores = typeof navigator !== "undefined" ? navigator.hardwareConcurrency || 4 : 4;
    this.size = Math.max(1, Math.min(16, size ?? Math.max(1, cores - 1)));
    for (let i = 0; i < this.size; i++) {
      try {
        const w = new Worker(new URL("../../workers/analysis.worker.ts", import.meta.url));
        w.onmessage = (ev: MessageEvent<WorkerResult>) => {
          const r = ev.data;
          if (r.id === 0) {
            // startup ping answered → the worker script loaded and can take real work
            this.ready.add(w);
            this.pump();
            return;
          }
          this.onResult(w, r);
        };
        w.onerror = (ev) => this.onWorkerError(w, ev.message || "worker error");
        w.postMessage({ type: "ping", id: 0 } satisfies WorkerTask);
        this.workers.push(w);
        this.idle.push(w);
      } catch {
        break;
      }
    }
    if (this.workers.length) {
      this.readyTimer = setTimeout(() => {
        this.readyTimer = null;
        if (!this.ready.size) this.abandonWorkers("no worker answered the startup ping");
      }, READY_TIMEOUT_MS);
    }
  }

  get usingWorkers() {
    return this.workers.length > 0;
  }

  /** Provide an inline executor used when no workers could be created (or all of them died). */
  setInlineExecutor(fn: (task: WorkerTask) => Promise<unknown>) {
    this.inline = fn;
  }

  run<T>(task: TaskInput, transfer: Transferable[] = []): Promise<T> {
    const full = { ...task, id: this.nextId++ } as WorkerTask;
    if (!this.workers.length) return this.runInline<T>(full);
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ resolve: resolve as (v: unknown) => void, reject, task: full, transfer });
      this.pump();
    });
  }

  private runInline<T>(task: WorkerTask): Promise<T> {
    if (!this.inline) return Promise.reject(new Error("No workers and no inline executor"));
    return this.inline(task).then((r) => {
      this.tasksCompleted++;
      return r as T;
    });
  }

  private pump() {
    for (let i = 0; i < this.idle.length && this.queue.length; ) {
      const w = this.idle[i];
      if (!this.ready.has(w)) {
        i++;
        continue;
      }
      this.idle.splice(i, 1);
      const p = this.queue.shift()!;
      this.inflight.set(w, p);
      try {
        w.postMessage(p.task, p.transfer);
      } catch (e) {
        this.inflight.delete(w);
        this.idle.push(w);
        p.reject(e instanceof Error ? e : new Error(String(e)));
      }
    }
  }

  private onResult(w: Worker, r: WorkerResult) {
    const p = this.inflight.get(w);
    this.inflight.delete(w);
    if (!this.idle.includes(w)) this.idle.push(w);
    if (p) {
      this.tasksCompleted++;
      if (r.ok) {
        this.totalWorkerMs += r.ms;
        p.resolve(r.result);
      } else p.reject(new Error(r.error));
    }
    this.pump();
  }

  /** A worker failed to load or crashed: drop it, and re-run its task inline when the payload is still intact. */
  private onWorkerError(w: Worker, message: string) {
    const p = this.inflight.get(w);
    this.inflight.delete(w);
    this.ready.delete(w);
    this.workers = this.workers.filter((x) => x !== w);
    this.idle = this.idle.filter((x) => x !== w);
    try {
      w.terminate();
    } catch {
      /* already gone */
    }
    if (p) {
      const bytes = (p.task as { bytes?: Uint8Array }).bytes;
      const detached = !!bytes && bytes.byteLength === 0 && bytes.buffer.byteLength === 0;
      if (this.inline && !detached) this.runInline(p.task).then(p.resolve, p.reject);
      else p.reject(new Error(`worker error: ${message}`));
    }
    if (!this.workers.length) this.abandonWorkers(message);
    else this.pump();
  }

  /** Give up on workers entirely: everything queued (and future tasks) runs inline. */
  private abandonWorkers(reason: string) {
    if (this.readyTimer) {
      clearTimeout(this.readyTimer);
      this.readyTimer = null;
    }
    for (const w of this.workers) w.terminate();
    this.workers = [];
    this.idle = [];
    this.ready.clear();
    const queued = this.queue;
    this.queue = [];
    for (const p of queued) {
      if (this.inline) this.runInline(p.task).then(p.resolve, p.reject);
      else p.reject(new Error(`workers unavailable: ${reason}`));
    }
  }

  get pending() {
    return this.queue.length + this.inflight.size;
  }

  terminate() {
    if (this.readyTimer) {
      clearTimeout(this.readyTimer);
      this.readyTimer = null;
    }
    for (const w of this.workers) w.terminate();
    this.workers = [];
    this.idle = [];
    this.ready.clear();
    this.inflight.clear();
    for (const p of this.queue) p.reject(new Error("pool terminated"));
    this.queue = [];
  }
}
