import { scanPattern, type CompiledPattern } from "../core/signatures/pattern";
import { scanStrings, type RawString } from "../core/analysis/strings";
import { gpuDevice } from "./webgpu";

/**
 * Compute backend abstraction for embarrassingly-parallel byte workloads
 * (pattern scanning, hashing, bulk similarity). The CPU backend is always
 * available and is the reference implementation. A GPU backend is only
 * selected when it is (a) available and (b) benchmarks faster on this
 * machine for the given workload; otherwise we fall back transparently.
 */
export interface ComputeBackend {
  readonly id: "cpu" | "webgpu";
  readonly available: boolean;
  describe(): string;
  scanPattern(hay: Uint8Array, pattern: CompiledPattern, ranges: { start: number; end: number }[], limit?: number): Promise<number[]>;
  /** String scan with identical output to the CPU reference (GPU = prefilter + CPU verify). */
  scanStrings(bytes: Uint8Array, va: number, length: number, minLen: number, onProgress?: (done: number, total: number) => void): Promise<RawString[]>;
  sha256(data: Uint8Array): Promise<string>;
}

export type ComputePreference = "auto" | "cpu" | "gpu";

export interface ComputeSettings {
  mode: ComputePreference;
  /** 0.1..1 sustained GPU load target (slice size + pacing). 0.5 ≈ half the card. */
  gpuLoad: number;
  /** Below this range size the GPU isn't worth the transfer — stay on CPU. */
  gpuMinBytes: number;
}

export const DEFAULT_COMPUTE: ComputeSettings = { mode: "auto", gpuLoad: 0.5, gpuMinBytes: 256 * 1024 };

export class CPUBackend implements ComputeBackend {
  readonly id = "cpu" as const;
  readonly available = true;
  describe() {
    const n = typeof navigator !== "undefined" ? navigator.hardwareConcurrency ?? 1 : 1;
    return `CPU (${n} logical cores)`;
  }
  async scanPattern(hay: Uint8Array, pattern: CompiledPattern, ranges: { start: number; end: number }[], limit = 10_000) {
    const out: number[] = [];
    for (const r of ranges) {
      out.push(...scanPattern(hay, pattern, r.start, r.end, limit - out.length));
      if (out.length >= limit) break;
    }
    return out;
  }
  async scanStrings(bytes: Uint8Array, va: number, length: number, minLen: number) {
    return scanStrings(bytes, 0, va, length, minLen);
  }
  async sha256(data: Uint8Array): Promise<string> {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const buf = data.byteOffset === 0 && data.byteLength === data.buffer.byteLength ? data.buffer : data.slice().buffer;
      const digest = await crypto.subtle.digest("SHA-256", buf as ArrayBuffer);
      return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    // Node fallback
    const { createHash } = await import("crypto");
    return createHash("sha256").update(data).digest("hex");
  }
}

/**
 * WebGPU backend: data-parallel prefilter on the card, exact verification on
 * CPU — output is bit-for-bit identical to the reference. `available` is true
 * only after the device passes a kernel self-test against the CPU reference.
 */
export class WebGPUBackend implements ComputeBackend {
  readonly id = "webgpu" as const;
  available = false;
  adapterName = "";
  load = 0.5;
  minBytes = 256 * 1024;
  benchmarkMs: number | null = null;
  private cpu = new CPUBackend();
  async detect() {
    try {
      const ok = await gpuDevice.ensure();
      this.available = ok;
      this.adapterName = ok ? gpuDevice.adapterName : "";
      return ok;
    } catch {
      this.available = false;
      return false;
    }
  }
  describe() {
    if (!this.available) return "WebGPU unavailable (no adapter or self-test failed) — CPU";
    return `WebGPU (${this.adapterName || "adapter"}) · load target ${Math.round(this.load * 100)}%`;
  }
  private useGpu(n: number) {
    return this.available && n >= this.minBytes;
  }
  async scanPattern(hay: Uint8Array, pattern: CompiledPattern, ranges: { start: number; end: number }[], limit = 10_000) {
    try {
      // GPU kernel handles full-byte masks only; nibble wildcards stay on CPU for exactness.
      const byteMask = pattern.mask.every((m) => m === 0xff || m === 0x00);
      if (this.useGpu(hay.length) && byteMask && pattern.bytes.length <= 64) {
        const pat = Uint8Array.from(pattern.bytes);
        const mask = Uint8Array.from(pattern.mask, (m) => (m === 0xff ? 1 : 0));
        const out: number[] = [];
        for (const r of ranges) {
          const sub = hay.subarray(r.start, Math.min(hay.length, r.end));
          const hits = await gpuDevice.patternHits(sub, pat, mask, this.load, limit - out.length);
          for (const h of hits) out.push(r.start + h);
          if (out.length >= limit) break;
          await new Promise((res) => setTimeout(res, 0));
        }
        return out;
      }
    } catch {
      /* fall through to CPU */
    }
    return this.cpu.scanPattern(hay, pattern, ranges, limit);
  }
  async scanStrings(bytes: Uint8Array, va: number, length: number, minLen: number, onProgress?: (done: number, total: number) => void) {
    try {
      if (this.useGpu(length)) {
        const sub = bytes.subarray(0, length);
        const regions = await gpuDevice.stringRegions(sub, minLen, this.load, onProgress);
        // CPU verify on candidate regions only — identical output to a full scan.
        const out = new Map<number, RawString>();
        for (const r of regions) {
          const rs = scanStrings(sub, r.start, va + r.start, r.end - r.start, minLen);
          for (const s of rs) if (!out.has(s.addr)) out.set(s.addr, s);
          if (out.size > 2_000_000) break;
        }
        return [...out.values()].sort((a, b) => a.addr - b.addr);
      }
    } catch {
      /* fall through to CPU */
    }
    return scanStrings(bytes, 0, va, length, minLen);
  }
  sha256(data: Uint8Array) {
    return this.cpu.sha256(data);
  }
}

export interface BackendReport {
  selected: ComputeBackend;
  cpu: string;
  gpu: string;
  benchmark?: { cpuMs: number; gpuMs?: number };
}

/** Select the compute backend. In auto mode the GPU must beat the CPU on a real sample to win. */
export async function selectBackend(sample?: Uint8Array, prefs: ComputeSettings = DEFAULT_COMPUTE): Promise<BackendReport> {
  const cpu = new CPUBackend();
  const gpu = new WebGPUBackend();
  gpu.load = Math.min(1, Math.max(0.1, prefs.gpuLoad));
  await gpu.detect();
  let benchmark: BackendReport["benchmark"];
  if (prefs.mode === "cpu" || !gpu.available) return { selected: cpu, cpu: cpu.describe(), gpu: gpu.describe(), benchmark };
  if (sample && sample.length > 4096) {
    const sub = sample.subarray(0, Math.min(sample.length, 2 << 20));
    const t0 = performance.now();
    await cpu.scanStrings(sub, 0, sub.length, 4);
    const cpuMs = performance.now() - t0;
    let gpuMs: number | undefined;
    try {
      const t1 = performance.now();
      await gpu.scanStrings(sub, 0, sub.length, 4);
      gpuMs = performance.now() - t1;
    } catch {
      gpuMs = undefined;
    }
    benchmark = { cpuMs, gpuMs };
    if (prefs.mode === "gpu") return { selected: gpuMs !== undefined ? gpu : cpu, cpu: cpu.describe(), gpu: gpu.describe(), benchmark };
    // auto: GPU must prove itself
    if (gpuMs !== undefined && gpuMs < cpuMs) return { selected: gpu, cpu: cpu.describe(), gpu: gpu.describe(), benchmark };
    return { selected: cpu, cpu: cpu.describe(), gpu: gpu.describe() + " (CPU won benchmark)", benchmark };
  }
  // no sample to prove with: honour explicit gpu choice, else stay on CPU
  return { selected: prefs.mode === "gpu" && gpu.available ? gpu : cpu, cpu: cpu.describe(), gpu: gpu.describe(), benchmark };
}
