import type { Xref, XrefKind } from "./types";

/**
 * Compact cross-reference index. Struct-of-arrays with two sorted permutation
 * indices so caller/callee/reference queries are O(log n) without building a
 * Map per address. Handles millions of references.
 */
export class XrefIndex {
  from: Float64Array;
  to: Float64Array;
  kind: Uint8Array;
  private byTo: Uint32Array;
  private byFrom: Uint32Array;
  readonly count: number;

  constructor(from: Float64Array, to: Float64Array, kind: Uint8Array) {
    this.from = from;
    this.to = to;
    this.kind = kind;
    this.count = from.length;
    const idx = new Uint32Array(this.count);
    for (let i = 0; i < this.count; i++) idx[i] = i;
    this.byTo = idx.slice().sort((a, b) => to[a] - to[b] || from[a] - from[b]);
    this.byFrom = idx.sort((a, b) => from[a] - from[b] || to[a] - to[b]);
  }

  static empty() {
    return new XrefIndex(new Float64Array(0), new Float64Array(0), new Uint8Array(0));
  }

  static build(refs: Xref[]) {
    const n = refs.length;
    const from = new Float64Array(n), to = new Float64Array(n), kind = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      from[i] = refs[i].from;
      to[i] = refs[i].to;
      kind[i] = refs[i].kind;
    }
    return new XrefIndex(from, to, kind);
  }

  private lowerBound(perm: Uint32Array, key: Float64Array, value: number) {
    let lo = 0, hi = perm.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (key[perm[mid]] < value) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** All references whose target is exactly `addr`. */
  refsTo(addr: number, limit = 10_000): Xref[] {
    const out: Xref[] = [];
    let i = this.lowerBound(this.byTo, this.to, addr);
    while (i < this.byTo.length && this.to[this.byTo[i]] === addr && out.length < limit) {
      const j = this.byTo[i++];
      out.push({ from: this.from[j], to: this.to[j], kind: this.kind[j] as XrefKind });
    }
    return out;
  }

  /** All references whose target lies in [start, end). */
  refsToRange(start: number, end: number, limit = 10_000): Xref[] {
    const out: Xref[] = [];
    let i = this.lowerBound(this.byTo, this.to, start);
    while (i < this.byTo.length && this.to[this.byTo[i]] < end && out.length < limit) {
      const j = this.byTo[i++];
      out.push({ from: this.from[j], to: this.to[j], kind: this.kind[j] as XrefKind });
    }
    return out;
  }

  /** All references originating in [start, end). */
  refsFromRange(start: number, end: number, limit = 50_000): Xref[] {
    const out: Xref[] = [];
    let i = this.lowerBound(this.byFrom, this.from, start);
    while (i < this.byFrom.length && this.from[this.byFrom[i]] < end && out.length < limit) {
      const j = this.byFrom[i++];
      out.push({ from: this.from[j], to: this.to[j], kind: this.kind[j] as XrefKind });
    }
    return out;
  }

  countTo(addr: number) {
    let i = this.lowerBound(this.byTo, this.to, addr);
    let n = 0;
    while (i < this.byTo.length && this.to[this.byTo[i]] === addr) { n++; i++; }
    return n;
  }

  countToRange(start: number, end: number) {
    const a = this.lowerBound(this.byTo, this.to, start);
    const b = this.lowerBound(this.byTo, this.to, end);
    return b - a;
  }
}

/** Binary search helper: index of the greatest element <= value in a sorted Float64Array. */
export function floorIndex(sorted: ArrayLike<number>, value: number): number {
  let lo = 0, hi = sorted.length - 1, ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid] <= value) { ans = mid; lo = mid + 1; }
    else hi = mid - 1;
  }
  return ans;
}
