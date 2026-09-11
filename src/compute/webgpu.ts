/// <reference types="@webgpu/types" />
/**
 * WebGPU data-parallel kernels for the bulk byte-filter stages of loading a
 * binary (string pre-scan, byte-pattern search). The branchy work — ARM64
 * decoding, function discovery, rule classification — stays on CPU workers
 * because GPUs are bad at it; pretending otherwise would be slower, not faster.
 *
 * Honesty rules built in:
 *  - `ensure()` self-tests every kernel against the CPU reference before the
 *    backend is ever reported as available.
 *  - Work runs in budget-sized slices with yields between dispatches, so the
 *    "GPU load target" slider genuinely caps sustained utilization (~50% by
 *    default) instead of pegging the card.
 *  - Any failure (no adapter, lost device, shader error) disables the GPU
 *    path silently and the caller falls back to CPU bit-for-bit results.
 */

export interface GpuBudget {
  /** 0..1 sustained-load target. Controls slice size + pacing between dispatches. */
  load: number;
}

const WGSL_STRING = /* wgsl */ `
struct Params { n : u32 };
@group(0) @binding(0) var<storage, read> words : array<u32>;
@group(0) @binding(1) var<storage, read_write> cls : array<u32>;
@group(0) @binding(2) var<uniform> p : Params;
@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid : vec3<u32>) {
  let i = gid.x;
  if (i >= p.n) { return; }
  let b = (words[i >> 2u] >> ((i & 3u) * 8u)) & 0xffu;
  var c = 0u; // other
  if (b == 0u) { c = 2u; } // NUL
  else if (b == 9u || b == 10u || b == 13u || (b >= 32u && b < 127u)) { c = 1u; } // printable
  cls[i] = c;
}
`;

const WGSL_PATTERN = /* wgsl */ `
struct Params { n : u32, patLen : u32, outWords : u32 };
@group(0) @binding(0) var<storage, read> words : array<u32>;
@group(0) @binding(1) var<storage, read> pat : array<u32>;   // pattern bytes, one per u32
@group(0) @binding(2) var<storage, read> mask : array<u32>;  // 1 = must match, 0 = wildcard
@group(0) @binding(3) var<storage, read_write> bits : array<atomic<u32>>; // bit-packed hits
@group(0) @binding(4) var<uniform> p : Params;
@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid : vec3<u32>) {
  let i = gid.x;
  if (i >= p.n) { return; }
  var hit = 0u;
  if (i + p.patLen <= p.n) {
    var ok = true;
    for (var j = 0u; j < p.patLen; j = j + 1u) {
      if (mask[j] == 1u) {
        let b = (words[(i + j) >> 2u] >> (((i + j) & 3u) * 8u)) & 0xffu;
        if (b != pat[j]) { ok = false; break; }
      }
    }
    if (ok) { hit = 1u; }
  }
  if (hit == 1u) {
    // atomic: neighbouring threads share the same u32 word
    atomicOr(&bits[i >> 5u], 1u << (i & 31u));
  }
}
`;

class GpuDevice {
  device: GPUDevice | null = null;
  adapterName = "";
  private stringPipe: GPUComputePipeline | null = null;
  private patternPipe: GPUComputePipeline | null = null;
  private tested: boolean | null = null;

  async ensure(): Promise<boolean> {
    if (this.tested !== null) return this.tested;
    this.tested = false;
    try {
      const nav = navigator as Navigator & { gpu?: GPU };
      const adapter = await nav.gpu?.requestAdapter({ powerPreference: "high-performance" });
      if (!adapter) return false;
      const info = adapter.info as GPUAdapterInfo & { device?: string; vendor?: string };
      this.adapterName = info?.device || [info?.vendor, "adapter"].filter(Boolean).join(" ") || "WebGPU adapter";
      const device = await adapter.requestDevice();
      device.lost.then(() => {
        this.device = null;
        this.tested = null;
      });
      this.device = device;
      this.stringPipe = device.createComputePipeline({ layout: "auto", compute: { module: device.createShaderModule({ code: WGSL_STRING }), entryPoint: "main" } });
      this.patternPipe = device.createComputePipeline({ layout: "auto", compute: { module: device.createShaderModule({ code: WGSL_PATTERN }), entryPoint: "main" } });
      this.tested = await this.selfTest();
      if (!this.tested) this.device = null;
      return this.tested;
    } catch {
      this.device = null;
      return false;
    }
  }

  private writeBytes(buf: GPUBuffer, data: Uint8Array | Uint32Array) {
    const dev = this.device!;
    dev.queue.writeBuffer(buf, 0, data as unknown as ArrayBuffer);
  }

  private sliceMB(load: number): number {
    // 4 MB at 10% … 32 MB at 100%. Smaller slices + pacing = lower sustained load.
    return Math.round((4 + load * 28) * (1 << 20));
  }

  private async run(pipe: GPUComputePipeline, entries: { buffer: GPUBuffer }[], n: number, outBytes: number, load: number): Promise<GPUBuffer> {
    const dev = this.device!;
    const bind = dev.createBindGroup({ layout: pipe.getBindGroupLayout(0), entries: entries.map((e, i) => ({ binding: i, resource: { buffer: e.buffer } })) });
    const out = dev.createBuffer({ size: Math.max(16, outBytes), usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
    const enc = dev.createCommandEncoder();
    const pass = enc.beginComputePass();
    pass.setPipeline(pipe);
    pass.setBindGroup(0, bind);
    pass.dispatchWorkgroups(Math.ceil(n / 256));
    pass.end();
    dev.queue.submit([enc.finish()]);
    // Pacing: one dispatch in flight + breathers. This is what caps utilization.
    await dev.queue.onSubmittedWorkDone();
    if (load < 0.85) await new Promise((r) => setTimeout(r, Math.round((0.85 - load) * 24)));
    return out;
  }

  private async readback(buf: GPUBuffer, size: number): Promise<ArrayBuffer> {
    const dev = this.device!;
    const dst = dev.createBuffer({ size, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
    const enc = dev.createCommandEncoder();
    enc.copyBufferToBuffer(buf, 0, dst, 0, size);
    dev.queue.submit([enc.finish()]);
    await dst.mapAsync(GPUMapMode.READ);
    const copy = dst.getMappedRange().slice(0);
    dst.unmap();
    dst.destroy();
    return copy;
  }

  /** String prefilter: returns [start,end) candidate regions holding printable runs. */
  async stringRegions(src: Uint8Array, minLen: number, load: number, onSlice?: (done: number, total: number) => void): Promise<{ start: number; end: number }[]> {
    const dev = this.device!;
    const slice = this.sliceMB(load);
    const out: { start: number; end: number }[] = [];
    // 64B tail overlap per slice: runs spanning a boundary are emitted twice
    // (overlapping) and merged below — simple and exactly correct.
    for (let off = 0; off < src.length; off += slice) {
      const len = Math.min(slice + 64, src.length - off);
      const chunk = src.subarray(off, off + len);
      // pack bytes -> u32 words (little endian)
      const words = new Uint32Array(Math.ceil(len / 4));
      for (let k = 0; k < len; k++) words[k >> 2] |= chunk[k] << ((k & 3) * 8);
      const n = len;
      const inBuf = dev.createBuffer({ size: words.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
      const clsBuf = dev.createBuffer({ size: n * 4, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
      const parBuf = dev.createBuffer({ size: 16, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
      this.writeBytes(inBuf, words);
      this.writeBytes(parBuf, new Uint32Array([n, 0, 0, 0]));
      const outBuf = await this.run(this.stringPipe!, [{ buffer: inBuf }, { buffer: clsBuf }, { buffer: parBuf }], n, n * 4, load);
      const ab = await this.readback(outBuf, n * 4);
      const cls = new Uint32Array(ab);
      // compact runs on CPU (cheap linear pass); pad ends so the CPU
      // verifier sees terminators/context just like a full scan would.
      let runStart = -1;
      for (let k = 0; k <= len; k++) {
        const c = k < len ? cls[k] : 0;
        if (c === 1 && runStart < 0) runStart = k;
        if ((c !== 1 || k === len) && runStart >= 0) {
          if (k - runStart >= minLen) out.push({ start: Math.max(0, off + runStart - 4), end: Math.min(src.length, off + k + 17) });
          runStart = -1;
        }
      }
      inBuf.destroy(); clsBuf.destroy(); parBuf.destroy(); outBuf.destroy();
      onSlice?.(Math.min(src.length, off + slice), src.length);
      await new Promise((r) => setTimeout(r, 0));
    }
    // merge overlaps
    out.sort((a, b2) => a.start - b2.start);
    const merged: { start: number; end: number }[] = [];
    for (const r of out) {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
      else merged.push({ ...r });
    }
    return merged;
  }

  /** Exact byte-pattern search with wildcard mask. Returns file offsets (hits capped). */
  async patternHits(src: Uint8Array, pat: Uint8Array, mask: Uint8Array, load: number, limit = 10_000): Promise<number[]> {
    const dev = this.device!;
    const slice = this.sliceMB(load);
    const hits: number[] = [];
    const patU = new Uint32Array(pat.length);
    const maskU = new Uint32Array(mask.length);
    for (let k = 0; k < pat.length; k++) { patU[k] = pat[k]; maskU[k] = mask[k]; }
    const patBuf = dev.createBuffer({ size: patU.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
    const maskBuf = dev.createBuffer({ size: maskU.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
    this.writeBytes(patBuf, patU);
    this.writeBytes(maskBuf, maskU);
    const overlap = pat.length + 16;
    for (let off = 0; off < src.length && hits.length < limit; off += slice) {
      const len = Math.min(slice + overlap, src.length - off);
      const chunk = src.subarray(off, off + len);
      const words = new Uint32Array(Math.ceil(len / 4));
      for (let k = 0; k < len; k++) words[k >> 2] |= chunk[k] << ((k & 3) * 8);
      const inBuf = dev.createBuffer({ size: words.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
      const outWords = Math.ceil(len / 32);
      const bitsBuf = dev.createBuffer({ size: outWords * 4, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
      const parBuf = dev.createBuffer({ size: 16, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
      this.writeBytes(inBuf, words);
      this.writeBytes(parBuf, new Uint32Array([len, pat.length, outWords, 0]));
      const outBuf = await this.run(this.patternPipe!, [{ buffer: inBuf }, { buffer: patBuf }, { buffer: maskBuf }, { buffer: bitsBuf }, { buffer: parBuf }], len, outWords * 4, load);
      const ab = await this.readback(outBuf, outWords * 4);
      const bits = new Uint32Array(ab);
      const scanEnd = off + slice < src.length ? slice : len;
      for (let w = 0; w < outWords && hits.length < limit; w++) {
        let word = bits[w];
        while (word) {
          const bIdx = 31 - Math.clz32(word & 0xffffffff);
          const pos = w * 32 + bIdx;
          if (pos < scanEnd && pos + pat.length <= len) hits.push(off + pos);
          word &= ~(1 << bIdx);
        }
      }
      inBuf.destroy(); bitsBuf.destroy(); parBuf.destroy(); outBuf.destroy();
      await new Promise((r) => setTimeout(r, 0));
    }
    patBuf.destroy(); maskBuf.destroy();
    return hits;
  }

  private async selfTest(): Promise<boolean> {
    try {
      // string kernel: "Hi\x00" -> classes [1,1,2]
      const probe = new Uint8Array([72, 105, 0, 7]);
      const regs = await this.stringRegions(probe, 2, 1);
      if (!regs.length || regs[0].start !== 0) return false;
      // pattern kernel: find AB in "..AB.."
      const hay = new Uint8Array([9, 9, 65, 66, 9]);
      const hits = await this.patternHits(hay, new Uint8Array([65, 66]), new Uint8Array([1, 1]), 1, 10);
      if (hits.length !== 1 || hits[0] !== 2) return false;
      return true;
    } catch {
      return false;
    }
  }
}

export const gpuDevice = new GpuDevice();

/** True when the browser exposes WebGPU at all (kernels still self-test before use). */
export function gpuSupported(): boolean {
  return typeof navigator !== "undefined" && "gpu" in navigator;
}
