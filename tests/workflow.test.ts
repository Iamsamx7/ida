import { test } from "node:test";
import assert from "node:assert/strict";
import { buildControlFlow } from "../src/core/analysis/controlFlow";
import type { Instruction, InsnKind } from "../src/core/architecture/types";
import { exportAnnotations, parseAnnotations, mergeAnnotations } from "../src/core/analysis/annotations";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { buildSampleSo } from "./fixtures/elfBuilder";

const insn = (address: number, kind: InsnKind = "arith", target?: number, size = 4): Instruction => ({ address, kind, target, size, mnemonic: kind, operands: [], opText: "", raw: 0, fallsThrough: !["jump", "ret", "indirect-jump", "trap"].includes(kind) });
test("CFG: empty input and single return", () => {
  assert.deepEqual(buildControlFlow([]).blocks, []);
  const flow = buildControlFlow([insn(0, "ret")]);
  assert.equal(flow.blocks.length, 1); assert.equal(flow.blocks[0].reachable, true); assert.equal(flow.edges.length, 0);
});
test("CFG: conditional branches split blocks, join and form loops", () => {
  const flow = buildControlFlow([insn(0), insn(4, "condjump", 16), insn(8), insn(12, "jump", 20), insn(16, "condjump", 0), insn(20, "ret")]);
  assert.deepEqual(flow.blocks.map((b) => b.address), [0, 8, 16, 20]);
  assert.deepEqual(flow.blocks[0].successors.map((e) => [e.kind, e.to]), [["branch", 16], ["fallthrough", 8]]);
  assert.equal(flow.blocks.every((b) => b.reachable), true); assert.equal(flow.unresolved, 0);
});
test("CFG: calls do not create callee blocks; indirect jumps preserve uncertainty", () => {
  const flow = buildControlFlow([insn(0, "call", 0x1000), insn(4, "indirect-jump"), insn(8, "ret")]);
  assert.equal(flow.blocks[0].instructions.length, 2);
  assert.equal(flow.blocks[1].reachable, false);
  assert.deepEqual(flow.edges, [{ from: 0, to: undefined, kind: "indirect", external: true }]);
});
test("CFG: variable-length instructions, gaps, invalid branch targets and unknown opcodes", () => {
  const flow = buildControlFlow([insn(0, "arith", undefined, 3), insn(3, "condjump", 1, 2), insn(5, "unknown", undefined, 1), insn(9, "ret", undefined, 1)]);
  assert.deepEqual(flow.blocks.map((b) => b.address), [0, 5, 9]);
  assert.equal(flow.edges[0].external, true); assert.equal(flow.blocks[2].reachable, false);
  assert.equal(flow.unresolved, 2);
});
test("CFG: truncated fallthrough is external, not a fabricated return", () => {
  const flow = buildControlFlow([insn(100)]);
  assert.deepEqual(flow.edges, [{ from: 100, to: 104, kind: "fallthrough", external: true }]);
});

function database() {
  const { bytes } = buildSampleSo();
  const elf = parseElf(bytes);
  const db = new AnalysisDatabase(elf, bytes, getArchitecture(elf.header.arch), "sample.so");
  db.hash = "a".repeat(64);
  return db;
}
test("Annotations: round trip all categories, unicode, address zero and both comment scopes", () => {
  const source = database();
  source.setUserName(0, "入口_α"); source.setUserName(4, "accepted", "ai-accepted");
  source.comments.set(0, "line\nsecond line"); source.functionComments.set(0, "function note");
  source.bookmarks.set(4, { address: 4, kind: "data", label: "", note: "bookmark note" });
  source.tags.set(4, new Set(["review", "解析"]));
  const backup = parseAnnotations(JSON.stringify(exportAnnotations(source)), source.hash);
  const target = database(); mergeAnnotations(target, backup);
  assert.deepEqual(exportAnnotations(target), exportAnnotations(source));
});
test("Annotations: merges preserve current values, keep origin, deduplicate tags and are idempotent", () => {
  const source = database(); source.setUserName(0, "backup"); source.comments.set(4, "backup comment"); source.tags.set(0, new Set(["old", "new"]));
  const target = database(); target.setUserName(0, "current"); target.comments.set(4, "current comment"); target.tags.set(0, new Set(["old"]));
  const backup = exportAnnotations(source);
  const added = mergeAnnotations(target, backup);
  assert.equal(target.nameFor(0).name, "current"); assert.equal(target.comments.get(4), "current comment");
  assert.equal(added.names.length, 0); assert.equal(added.tags.length, 1);
  assert.equal(mergeAnnotations(target, backup).tags.length, 0);
});
test("Annotations: reject wrong binary, unknown formats, malformed records and unsafe addresses atomically", () => {
  const db = database(); db.setUserName(0, "keep");
  const backup = exportAnnotations(db);
  for (const patch of [{ sha256: "b".repeat(64) }, { version: 2 }, { comments: null }, { tags: [{ address: -1, tag: "x" }] }, { names: [{ address: Number.MAX_SAFE_INTEGER + 1, name: "bad", origin: "user" }] }]) {
    assert.throws(() => parseAnnotations(JSON.stringify({ ...backup, ...patch }), db.hash));
  }
  const bad = { ...backup, names: [{ address: 4, name: "must not apply", origin: "user" as const }], tags: [{ address: NaN, tag: "bad" }] };
  assert.throws(() => mergeAnnotations(db, bad)); assert.equal(db.userNames.has(4), false); assert.equal(db.nameFor(0).name, "keep");
});
