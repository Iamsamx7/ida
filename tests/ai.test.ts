import { test } from "node:test";
import assert from "node:assert/strict";
import { parseElf } from "../src/core/elf/parser";
import { getArchitecture } from "../src/core/architecture/registry";
import { AnalysisDatabase } from "../src/core/analysis/database";
import { scanCodeChunk } from "../src/core/analysis/codeScan";
import { discoverFunctions } from "../src/core/analysis/discovery";
import { scanStrings, toRecords } from "../src/core/analysis/strings";
import { extractFeatures } from "../src/core/analysis/features";
import { classify } from "../src/core/analysis/semantic/rules";
import { LocalAssistant, suggestName } from "../src/ai/assistant";
import { parseIntent } from "../src/ai/retrieval";
import { parseAgentTask, parseTagName, planAgentActions } from "../src/ai/agent";
import { sanitizeHistory, parseChatEvent } from "../src/ai/chatProtocol";
import { buildLlmContext } from "../src/ai/context";
import { buildIntel } from "../src/core/analysis/intel";
import { huntVerdictBranches, fridaHook } from "../src/core/analysis/bypass";
import { providerStatus, anthropicCapabilities } from "../src/ai/providers";
import { buildSampleSo } from "./fixtures/elfBuilder";

const sample = buildSampleSo();
function setup() {
  const elf = parseElf(sample.bytes);
  const arch = getArchitecture(elf.header.arch)!;
  const db = new AnalysisDatabase(elf, sample.bytes, arch, "libsample.so");
  db.setStrings(toRecords(elf.sections.filter((s) => s.alloc && !s.exec && s.type !== 8 && s.size > 0).flatMap((s) => scanStrings(sample.bytes, s.offset, s.addr, s.size))));
  const chunks = db.space.codeRanges().map((r, i) => scanCodeChunk(arch, sample.bytes, r.offset, r.vaddr, r.size, true, i, true));
  const r = discoverFunctions(db, chunks);
  db.setFunctions(r.functions); db.memAccess = r.memAccess; db.immediates = r.immediates; db.setXrefs(r.xrefs);
  const importsAll = new Set(elf.imports.map((i) => i.name));
  const index = new Map<number, string>();
  for (const f of db.functions) {
    f.features = extractFeatures(db, f);
    f.classes = classify({ addr: f.addr, name: f.name, size: f.size, features: f.features, calleeNames: f.features.callees.map((c) => db.nameFor(c).name), callerNames: [], stringValues: f.features.stringRefs.map((a) => db.stringAt(a)!).map((s) => ({ addr: s.addr, value: s.value, category: s.category })), importsAll });
    index.set(f.addr, [f.name, ...(f.classes.map((c) => c.label)), ...f.features.importCalls, ...f.features.stringRefs.map((a) => db.stringAt(a)?.value ?? "")].join(" ").toLowerCase());
  }
  return { db, assistant: new LocalAssistant(db, index) };
}

test("AI: intent parsing", () => {
  assert.equal(parseIntent("What does this function do?").kind, "explain");
  assert.equal(parseIntent("What calls this?").kind, "callers");
  assert.equal(parseIntent('Where is the string "GWorld" used?').kind, "string-uses");
  assert.equal(parseIntent("Show me everything related to networking").kind, "semantic-search");
  assert.equal(parseIntent("Find functions similar to this one").kind, "similar");
  assert.equal(parseIntent("Why did you classify this as networking?").kind, "why");
  assert.equal(parseIntent("Which functions access this global?").kind, "global-access");
  assert.equal(parseIntent("Suggest a name").kind, "suggest-name");
});

test("AI: evidence-based answers reference real addresses and never fabricate", () => {
  const { db, assistant } = setup();
  const wsr = sample.addrs.world_state_reader;
  const a = assistant.answer("What does this function do?", wsr);
  assert.equal(a.intent, "explain");
  assert.match(a.text, /GlobalWorld/);
  assert.ok(a.evidence.length >= 2);
  for (const e of a.evidence) if (e.address !== undefined) assert.ok(db.space.isMapped(e.address), `evidence address ${e.address.toString(16)} must be mapped`);
  assert.match(a.text, /hypothesis|inference/i);
  const c = assistant.answer("What calls this?", wsr);
  assert.match(c.text, /lib_init/);
  const s = assistant.answer('Where is the string "example.com" used?', null);
  assert.match(s.text, /net_send/);
  const n = assistant.answer("Show me everything related to networking", null);
  assert.ok(n.related.some((r) => r.addr === sample.addrs.net_send), n.text);
  const g = assistant.answer(`Which functions access this global? 0x${sample.addrs.GlobalWorld.toString(16)}`, null);
  assert.match(g.text, /Readers: .*sub_/);
  const w = assistant.answer("Why did you classify this?", sample.addrs.hash_buffer);
  assert.match(w.text, /hashing/);
  const sug = suggestName(db, db.functionByAddr(wsr)!);
  assert.ok(sug && sug.name.length > 3 && sug.confidence <= 0.85, JSON.stringify(sug));
  // user names are never overwritten by AI acceptance path unless explicitly requested
  db.setUserName(wsr, "MyReader");
  db.setUserName(wsr, "AIName", "ai-accepted");
  assert.equal(db.nameFor(wsr).name, "AIName");
  assert.equal(db.nameFor(wsr).source, "ai");
});

test("AI: intent routing — real identifiers only for imports, explicit 'this' beats topic sweeps, orders parse", () => {
  const imports = ["__android_log_print", "socket", "malloc", "read"];
  // English verbs that happen to be libc names never hijack a question…
  assert.equal(parseIntent("show me where the player state is read", { imports }).kind, "semantic-search");
  // …unless the binary declares them AND the phrasing is call-like.
  assert.deepEqual(parseIntent("who calls read", { imports }), { kind: "imports", query: "read" });
  assert.deepEqual(parseIntent("who calls SSL_write"), { kind: "imports", query: "SSL_write" });
  assert.deepEqual(parseIntent("Where is gettimeofday used?", { imports }), { kind: "imports", query: "gettimeofday" });
  assert.equal(parseIntent('Where is the string "GWorld" used?').kind, "string-uses");
  assert.equal(parseIntent("Which functions access this global?").kind, "global-access");
  assert.equal(parseIntent("what does this hash function do?").kind, "explain");
  assert.equal(parseIntent("What does this call?").kind, "callees");
  assert.equal(parseIntent("What calls this?").kind, "callers");
  assert.equal(parseIntent("Where are hash checks?").kind, "hash");
  assert.equal(parseIntent("Where is anticheat?").kind, "anticheat");
  assert.equal(parseIntent("what does this binary do").kind, "overview");
  assert.equal(parseIntent("show me networking because packets").kind, "semantic-search");
  assert.equal(parseIntent("help").kind, "help");
  assert.equal(parseIntent("Plan a safe bypass").kind, "bypass");
  assert.equal(parseIntent("Which libraries does this use?").kind, "libraries");
  // Orders resolve against the cursor when no address is given.
  const ren = parseAgentTask("rename this to handle_ban");
  assert.ok(ren && ren.op === "rename" && ren.name === "handle_ban" && ren.addr === undefined && ren.target === undefined, JSON.stringify(ren));
  const renSym = parseAgentTask("rename sub_1000 to foo");
  assert.ok(renSym && renSym.op === "rename" && renSym.target === "sub_1000" && renSym.name === "foo", JSON.stringify(renSym));
  const renAddr = parseAgentTask("rename 0x1000 to foo");
  assert.ok(renAddr && renAddr.op === "rename" && renAddr.addr === 0x1000, JSON.stringify(renAddr));
  assert.deepEqual(parseAgentTask("tag all anticheat findings as suspicious"), { op: "tag-kind", kind: "anticheat", tag: "suspicious" });
  const tagHooked = parseAgentTask("tag these with #hooked");
  assert.ok(tagHooked && tagHooked.op === "tag-kind" && tagHooked.tag === "hooked", JSON.stringify(tagHooked));
  assert.equal(parseTagName("tag this important"), "important");
  assert.deepEqual(parseAgentTask("go to 0x1000"), { op: "goto", addr: 0x1000 });
  assert.deepEqual(parseAgentTask("go to net_send"), { op: "goto", name: "net_send" });
  assert.equal(parseAgentTask("bookmark this")?.op, "bookmark-here");
  assert.equal(parseAgentTask("show me everything related to networking"), null);
  assert.equal(parseAgentTask("What does this function do?"), null);
  const cm = parseAgentTask("comment this function: handles the revive path");
  assert.ok(cm && cm.op === "comment" && cm.scope === "function" && cm.body === "handles the revive path", JSON.stringify(cm));
});

test("AI: agent hands resolve the cursor and named targets; unmapped addresses are refused", () => {
  const { db, assistant } = setup();
  const wsr = sample.addrs.world_state_reader;
  const ren = planAgentActions(db, { op: "rename", name: "WorldReader" }, wsr);
  assert.deepEqual(ren.actions.map((a) => a.type), ["rename"]);
  assert.equal(ren.actions[0].addr, wsr);
  const go = planAgentActions(db, { op: "goto", name: "net_send" });
  assert.equal(go.actions[0]?.type, "navigate");
  assert.equal(go.actions[0]?.addr, sample.addrs.net_send);
  const bad = planAgentActions(db, { op: "goto", addr: 0xdead0000 });
  assert.equal(bad.actions.length, 0);
  assert.match(bad.summary[0], /not mapped/);
  const nothing = planAgentActions(db, { op: "bookmark-here" }, null);
  assert.equal(nothing.actions.length, 0);
  // End to end through the assistant: the order becomes actions, never a "suggest a name" answer.
  const a = assistant.answer("rename this to WorldReader", wsr);
  assert.equal(a.intent, "agent");
  assert.equal(a.actions?.[0]?.type, "rename");
  // "where is <defined function>" is not an import question — it explains the function instead of "no callers".
  const e = assistant.answer("where is net_send used", null);
  assert.match(e.text, /not an import/);
  assert.equal(e.targetAddr, sample.addrs.net_send);
  // Function questions carry their target so the LLM context can pick the right pack.
  assert.equal(assistant.answer("What does this function do?", wsr).targetAddr, wsr);
});

test("Intel: proof levels need semantic witnesses; buildIntel is cached, copy-safe and rename-aware", () => {
  const { db } = setup();
  const hb = sample.addrs.hash_buffer;
  const a = buildIntel(db);
  const hit = a.findings.find((f) => f.addr === hb);
  assert.ok(hit, "hash_buffer should be a hash-check finding");
  // Constants are its only semantic leg (no strings, no imports): corroborated, never proven.
  assert.equal(hit!.proofLevel, "corroborated");
  for (const f of a.findings) {
    const semantic = f.legs.filter((l) => /^(strings|imports|constants):/.test(l)).length;
    if (f.proofLevel === "proven") assert.ok(semantic >= 2, `${f.name} proven with ${semantic} semantic leg(s): ${f.legs.join("+")}`);
    if (f.proofLevel === "lead") assert.equal(semantic, 0);
  }
  // Mutating the returned array must not poison the cache.
  a.findings.push(a.findings[0]);
  const b = buildIntel(db);
  assert.equal(b.findings.length, a.findings.length - 1);
  // Smaller limits are views of the same computation.
  assert.ok(buildIntel(db, 1).findings.length <= 4);
  // Renames invalidate the snapshot (revision bump).
  db.setUserName(hb, "MyHash");
  assert.equal(buildIntel(db).findings.find((f) => f.addr === hb)?.name, "MyHash");
});

test("Bypass: verdict branch reports the real feeder distance; Frida snippets use a real API", () => {
  const { db } = setup();
  const br = huntVerdictBranches(db, sample.addrs.net_send);
  assert.ok(br.length >= 1);
  assert.match(br[0].why, /fed by cmp .* 1 insn\(s\) earlier/);
  const js = fridaHook("libsample.so", "x", 0x1000, "0");
  assert.match(js, /Process\.findModuleByName\("libsample\.so"\)/);
  assert.doesNotMatch(js, /findBasePoint|Module\.findBaseAddress/);
});

test("AI: chat protocol — history is provider-safe, events parse defensively, provider selection", () => {
  const h = sanitizeHistory([
    { role: "assistant", content: "stale leading assistant" },
    { role: "user", content: "q1" },
    { role: "assistant", content: "" },
    { role: "assistant", content: "a1" },
    { role: "user", content: "q2 (unanswered, in flight)" },
  ]);
  assert.deepEqual(h, [{ role: "user", content: "q1" }, { role: "assistant", content: "a1" }]);
  assert.equal(sanitizeHistory(undefined).length, 0);
  assert.equal(sanitizeHistory(Array.from({ length: 30 }, (_, i) => ({ role: i % 2 ? "assistant" : "user", content: `t${i}` })) as never).length, 8);
  assert.deepEqual(parseChatEvent('{"t":"delta","text":"hi"}'), { t: "delta", text: "hi" });
  assert.equal(parseChatEvent("   "), null);
  assert.equal(parseChatEvent("{not json")?.t, "error");
  assert.equal(providerStatus({}), null);
  assert.deepEqual(providerStatus({ ANTHROPIC_API_KEY: "k" }), { provider: "anthropic", model: "claude-opus-5", effort: "high" });
  assert.equal(providerStatus({ ANTHROPIC_AUTH_TOKEN: "t", AI_EFFORT: "xhigh" })?.effort, "xhigh");
  assert.equal(providerStatus({ ANTHROPIC_API_KEY: "k", AI_BASE_URL: "http://x", AI_PROVIDER: "openai" })?.provider, "openai-compatible");
  assert.deepEqual(anthropicCapabilities("claude-opus-5"), { adaptiveThinking: true, effort: true, fallbacks: true });
  assert.deepEqual(anthropicCapabilities("claude-haiku-4-5"), { adaptiveThinking: false, effort: false, fallbacks: false });
  assert.equal(anthropicCapabilities("claude-sonnet-4-6").fallbacks, false);
});

test("AI: LLM context follows the intent, is capped, and never sends the cursor pack for whole-binary questions", () => {
  const { db, assistant } = setup();
  const wsr = sample.addrs.world_state_reader;
  const fnCtx = buildLlmContext(db, assistant.answer("What does this function do?", wsr), wsr);
  assert.match(fnCtx, /## FUNCTION/);
  assert.match(fnCtx, /## DISASSEMBLY/);
  assert.match(fnCtx, /## LOCAL ENGINE VERIFICATION/);
  assert.match(fnCtx, new RegExp(`0x${wsr.toString(16)}`));
  const secCtx = buildLlmContext(db, assistant.answer("Where are hash checks?", wsr), wsr);
  assert.match(secCtx, /## VERIFIED INTEL/);
  assert.doesNotMatch(secCtx, /## DISASSEMBLY/);
  const tiny = buildLlmContext(db, assistant.answer("What does this function do?", wsr), wsr, 1500);
  assert.ok(tiny.length <= 1500 + 40, `capped context is ${tiny.length} chars`);
});
