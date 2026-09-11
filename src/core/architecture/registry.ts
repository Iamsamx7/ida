import type { ArchId } from "../elf/types";
import type { ArchitectureProvider, Instruction } from "./types";
import { Arm64Provider } from "./arm64/decoder";
import { Arm32Provider } from "./arm32/decoder";
import { X86Provider } from "./x86/decoder";

/**
 * Architecture registry. New architectures plug in by implementing
 * ArchitectureProvider and calling registerArchitecture().
 */
const providers = new Map<ArchId, () => ArchitectureProvider>();
const instances = new Map<ArchId, ArchitectureProvider>();

export function registerArchitecture(id: ArchId, factory: () => ArchitectureProvider) {
  providers.set(id, factory);
}

export function getArchitecture(id: ArchId): ArchitectureProvider | null {
  if (instances.has(id)) return instances.get(id)!;
  const f = providers.get(id);
  if (!f) return null;
  const p = f();
  instances.set(id, p);
  return p;
}

export function listArchitectures() {
  return [...providers.keys()];
}

registerArchitecture("arm64", () => new Arm64Provider());
registerArchitecture("arm32", () => new Arm32Provider());
registerArchitecture("x86_64", () => new X86Provider(64));
registerArchitecture("x86", () => new X86Provider(32));

/** Decode a linear run of instructions from a byte range. */
export function decodeRange(
  arch: ArchitectureProvider,
  bytes: Uint8Array,
  fileOffset: number,
  va: number,
  length: number,
  littleEndian: boolean,
  limit = Infinity,
): Instruction[] {
  const out: Instruction[] = [];
  let off = 0;
  while (off < length && out.length < limit) {
    const ins = arch.decode(bytes, fileOffset + off, va + off, littleEndian);
    out.push(ins);
    off += Math.max(1, ins.size);
  }
  return out;
}
