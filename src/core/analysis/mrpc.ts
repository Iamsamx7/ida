import type { AnalysisDatabase } from "./database";

/**
 * MRPC = the anticheat's "download rules and apply" machinery. Modern mobile
 * anticheat (ACE/tersafe/anogs-style) doesn't ship every detection baked in —
 * it pulls a rule/config/policy blob from a server (or a bundled config file),
 * parses it, and applies the rules at runtime. Neutralising THAT one path
 * ("tick them out") is stronger than chasing each individual downloaded check,
 * because with no rules loaded, the whole downloaded ruleset is inert.
 *
 * This module finds those routines and says how to make the rule set empty.
 */

/**
 * Anchor vocabulary: a routine (or the helpers it drives) must reference at
 * least one of these to be an MRPC candidate. Includes the literal subsystem
 * name `mrpc(s)` (Tencent ACE's downloaded-rule engine, e.g. `mrpcs_download_…`,
 * `MRPCS_ANDROID`) and snake_case rule tokens (`rule_exe_fail`, `rule_op_…`).
 */
export const MRPC_STR = /(\bmrpcs?\b|mrpcs?[_-]|\brule[s]?\b|rule[_-]\w+|\bruleset\b|\bpolic(y|ies)\b|\bstrateg(y|ies)\b|blacklist|whitelist|\bcloud[_-]?(config|control|rule|ctrl|cmd|feature)\b|cloud[_-]?feature|remote[_-]?config|server[_-]?config|config[_-]?(center|server|update|download|version|sync|pull)|(get|set)[_-]?download[_-]?config|\bdownloadconfig\b|feature[_-]?(toggle|switch|flag|gate|config)|\bhotfix\b|hot[_-]?update|gray(scale)?[_-]?(rule|release|control|config)|\bxcloud|云控|规则|策略|下发|配置下发|黑名单|灰度|\/rule|rule\.(json|pb|dat|bin|conf)|config\.(json|pb|dat|bin|conf)|detect[_-]?(rule|config|policy)|anti[_-]?cheat[_-]?config)/i;
/** Apply/enable vocabulary — a second leg, never an anchor on its own ("apply" is everywhere). */
export const MRPC_APPLY_STR = /(update[_-]?rule|load[_-]?(rule|config|policy)|parse[_-]?(rule|config|policy)|apply[_-]?(rule|config|policy)|enable[_-]?(rule|feature)|rule[_-]?(apply|enable|effective|active|loaded)|生效|应用规则|启用|规则生效)/i;

const NET_IMP = /^(curl_easy_perform|curl_easy_setopt|SSL_read|SSL_write|BIO_read|BIO_write|recv|recvfrom|recvmsg|__sendto_chk|send|sendto|getaddrinfo|CFReadStream|HttpRequest|httpGet)$/;
const NET_HINT = /(https?:\/\/|curl|okhttp|cronet|HttpURLConnection|\.tencent\.|\/v\d\/|api\.|\.gz$|content-type|application\/json|application\/octet-stream)/i;
const FILE_IMP = /^(fopen|open|openat|read|pread|mmap|fread|__read_chk|access|stat)$/;
const PARSE_IMP = /(cJSON|json|rapidjson|nlohmann|ParseFrom|_pb_|pb_decode|protobuf|Unmarshal|Deserialize|Parse|base64|inflate|uncompress|AES_|EVP_Decrypt)/i;
const CRYPTO_IMP = /(MD5|SHA1|SHA256|CRYPTO_memcmp|HMAC|EVP_|RSA_verify|verify)/i;

export type MrpcRole = "downloader" | "parser" | "applier" | "dispatcher" | "rule-store";

export interface MrpcScore {
  legs: string[];
  role: MrpcRole;
  proofLevel: "proven" | "corroborated" | "lead";
  confidence: number;
  /** How to neutralise this specific routine. */
  how: string;
}

export interface MrpcScoreInput {
  strings: string[];
  imports: string[];
  /** callee names (resolved, incl. imports) — used for parse/net detection beyond the import table. */
  callees: string[];
  hasLoop: boolean;
  branches: number;
  stores: number;
  indirectCalls: number;
  /** Number of rule-string-bearing helper functions this routine calls (orchestrator signal). */
  helperCalls?: number;
}

/** Pure scorer — no DB, so it unit-tests without building an ELF. Returns null when it isn't MRPC. */
export function scoreMrpc(inp: MrpcScoreInput): MrpcScore | null {
  const anchors = inp.strings.filter((s) => MRPC_STR.test(s));
  if (!anchors.length) return null;
  const orchestrator = (inp.helperCalls ?? 0) >= 2;
  const all = [...inp.imports, ...inp.callees];
  const legs: string[] = [`rule-strings:${Math.min(anchors.length, 9)}${orchestrator ? "(via helpers)" : ""}`];
  if (orchestrator) legs.push(`orchestrates:${inp.helperCalls}-mrpc-helpers`);

  const net = all.some((n) => NET_IMP.test(n.replace(/@.*$/, ""))) || inp.strings.some((s) => NET_HINT.test(s));
  const file = all.some((n) => FILE_IMP.test(n.replace(/@.*$/, ""))) && inp.strings.some((s) => /\.(json|pb|dat|bin|conf|cfg)\b|\/rule|\/config|config\.|rule\./i.test(s));
  const parse = all.some((n) => PARSE_IMP.test(n));
  const crypto = all.some((n) => CRYPTO_IMP.test(n));
  const apply = inp.strings.some((s) => MRPC_APPLY_STR.test(s));
  const applyShape = inp.hasLoop && inp.branches >= 2 && inp.stores >= 1;
  const dispatch = inp.indirectCalls >= 2 && (apply || inp.strings.some((s) => /rule[_-]?(id|type|hit|match|handler)/i.test(s)));

  if (net) legs.push("download:network");
  if (file) legs.push("download:file");
  if (parse) legs.push("parse");
  if (crypto) legs.push("verify");
  if (apply) legs.push("apply-strings");
  else if (applyShape) legs.push("apply-shape");
  if (dispatch) legs.push(`dispatch:${inp.indirectCalls}-indirect`);

  // A generic "config" string alone is not a rule engine — need a 2nd mechanism
  // leg. But a HIGH-SPECIFICITY anchor (the literal mrpcs subsystem, rule_exe,
  // SetDownloadConfig, cloud_feature) is strong enough on its own to surface as
  // a lead — the core logic is often obfuscated (anogs strings barely xref), so
  // "this function touches the mrpcs rule subsystem" is worth showing.
  const strongAnchor = anchors.some((s) => /(mrpcs?[_-]|\bmrpcs?\b|rule[_-](exe|op|is_change|fail)|(get|set)[_-]?download[_-]?config|\bdownloadconfig\b|cloud[_-]?feature|\bxcloud)/i.test(s));
  if (legs.length < 2 && !strongAnchor) return null;
  if (legs.length < 2) legs.push("strong-anchor:mrpcs-vocab");

  let role: MrpcRole = "rule-store";
  if (orchestrator) role = "dispatcher";
  else if (dispatch) role = "dispatcher";
  else if (net || file) role = "downloader";
  else if (parse) role = "parser";
  else if (apply || applyShape) role = "applier";
  else {
    // No mechanism leg (strong-anchor lead in obfuscated code) — infer the role
    // from what the anchor strings describe.
    const blob = anchors.join(" ").toLowerCase();
    if (/download|fetch|scan|send|thread_start|http|\burl\b/.test(blob)) role = "downloader";
    else if (/crc|_len|parse|not_match|mode_name|decode|deserial|data_/.test(blob)) role = "parser";
    else if (/rule[_-](exe|op)|apply|effective|op_is_change|_exe_/.test(blob)) role = "applier";
  }

  const legCount = legs.length;
  const proofLevel = legCount >= 4 ? "proven" : legCount >= 3 ? "corroborated" : "lead";
  const confidence = Math.max(0.3, Math.min(0.95, 0.4 + 0.13 * (legCount - 1)));
  const how = orchestrator
    ? `This drives the whole downloaded-rule pipeline (${inp.helperCalls} rule helpers: fetch/parse/apply). Hook or RET-0 it and the entire pipeline no-ops — one cut, every downloaded rule inert. Cleaner than chasing each helper.`
    : neutralizeHow(role, { net, file, parse, apply: apply || applyShape, dispatch });
  return { legs, role, proofLevel, confidence, how };
}

function neutralizeHow(role: MrpcRole, f: { net: boolean; file: boolean; parse: boolean; apply: boolean; dispatch: boolean }): string {
  switch (role) {
    case "downloader": return `Starve it: hook this entry and return failure / empty (${f.net ? "network fetch → 0 bytes or error" : "config read → empty"}) so no rule blob ever arrives. With nothing downloaded, the applier falls back to an empty ruleset. Cleaner than patching each rule: one point, all downloaded rules gone.`;
    case "parser": return `Hook this parser to yield zero rules (return an empty list / count 0). Every downstream apply then iterates nothing. Confirm the return type on a clean trace first — a struct-returning parser needs the out-pointer zeroed, not the return value.`;
    case "applier": return `Hook this apply routine to a no-op (return early / force rule-count 0). The rules may still download and parse, but nothing gets enforced locally. Break here on a live run and log the rule count before forcing it.`;
    case "dispatcher": return `This routine dispatches rule handlers (indirect calls keyed by rule id). Hook it to swallow every dispatch (return before the call table). Safer than NOPping the table; keep the function returning "handled" so callers don't retry.`;
    case "rule-store": return `This holds/loads the rule set. Force the store empty (hook the getter to return count 0 / null list). Trace who reads it to confirm empty is treated as "no rules", not "fail closed".`;
  }
}

export interface MrpcFinding {
  addr: number;
  name: string;
  role: MrpcRole;
  confidence: number;
  proofLevel: MrpcScore["proofLevel"];
  legs: string[];
  strings: string[];
  imports: string[];
  how: string;
  /** True when found by call-graph exploration (no strings of its own) rather than a string anchor. */
  explored?: boolean;
}

/**
 * Structural shape of a string-less function — how the real parser/applier/
 * dispatcher are recognised without any strings to anchor on. Pure over the
 * mnemonic histogram + feature counts.
 */
export function structuralMrpcRole(f: {
  mnemonicHist: Record<string, number>;
  hasLoop: boolean;
  loadCount: number;
  storeCount: number;
  branchCount: number;
  callCount: number;
  size: number;
}): { role: MrpcRole; score: number; legs: string[] } | null {
  const h = f.mnemonicHist;
  const g = (...keys: string[]) => keys.reduce((a, k) => a + (h[k] ?? 0), 0);
  const byteExtract = g("ldrb", "ldrh", "ldrsb", "ldrsh", "ubfx", "sbfx", "bfxil"); // walking a byte/bitfield stream
  const cmp = g("cmp", "cmn", "subs", "tst", "ccmp");
  const indirect = g("blr") + Object.keys(h).filter((k) => k.startsWith("blra")).reduce((a, k) => a + h[k], 0);
  const tbl = g("br", "tbz", "tbnz"); // jump-table / switch dispatch
  // NOTE: no hasLoop gate — anogs/ACE is control-flow-flattened, so real parsers
  // report hasLoop=false (back-edges hidden behind a state-machine switch). The
  // density of byte-extraction + compares + loads is the reliable parser tell.
  const loopBonus = f.hasLoop ? 1 : 0;
  const legs: string[] = [];
  // Dispatcher: reads a value and INDIRECT-calls a handler (rule id → fn ptr), or a big jump table.
  if (indirect >= 3 || (indirect >= 2 && (cmp >= 2 || tbl >= 2)) || tbl >= 6) { legs.push(`structure:dispatch(${indirect} indirect${tbl ? `, ${tbl} table-branch` : ""})`); return { role: "dispatcher", score: 5 + indirect + loopBonus, legs }; }
  // Parser: dense byte/bitfield walk with bounds compares (loop optional under flattening).
  if (byteExtract >= 4 && cmp >= 4 && f.loadCount >= 16) { legs.push(`structure:parse(${byteExtract} byte-extract, ${cmp} cmp, ${f.loadCount} loads${f.hasLoop ? ", loop" : ""})`); return { role: "parser", score: 4 + Math.min(6, byteExtract) + loopBonus, legs }; }
  // Applier: writes lots of state behind many branches (sets flags from records).
  if (f.storeCount >= 10 && f.branchCount >= 8 && cmp >= 4) { legs.push(`structure:apply(${f.storeCount} stores, ${f.branchCount} branches, ${cmp} cmp)`); return { role: "applier", score: 3 + Math.min(5, Math.floor(f.storeCount / 6)) + loopBonus, legs }; }
  return null;
}

export interface MrpcReport {
  findings: MrpcFinding[];
  count: number;
  /** Whether the strongest finding is server-fed (network) vs a bundled config file. */
  networkBacked: boolean;
  verdict: string;
}

/** Scan a database for the downloaded-rule engine. Pure + deterministic. */
export function buildMrpcReport(db: AnalysisDatabase, limit = 12): MrpcReport {
  const findings: MrpcFinding[] = [];
  // Pass 1: functions that DIRECTLY reference MRPC anchor strings (the helpers).
  const ownAnchors = new Map<number, string[]>();
  for (const fn of db.functions) {
    if (fn.isImportStub || !fn.features) continue;
    const a = (fn.features.stringRefs ?? []).map((x) => db.stringAt(x)?.value ?? "").filter((v) => v && MRPC_STR.test(v));
    if (a.length) ownAnchors.set(fn.addr, a);
  }
  // Orchestrators: functions that call ≥2 anchor-bearing helpers but carry no
  // anchor string of their own (an mrpcs downloader/parser that only LOGS
  // through sub-helpers). Found by INVERTING the call graph over the few helper
  // functions — cheap (one callersOf per helper) and version-robust: it catches
  // whatever address the orchestrator sits at in this build.
  const orchestrators = new Map<number, { helpers: Set<number>; anchors: string[] }>();
  for (const [helperAddr, anchors] of ownAnchors) {
    const hf = db.functionByAddr(helperAddr);
    if (!hf) continue;
    for (const c of db.callersOf(hf)) {
      const ca = c.fn?.addr;
      if (ca === undefined || ca === helperAddr || ownAnchors.has(ca)) continue;
      const e = orchestrators.get(ca) ?? { helpers: new Set<number>(), anchors: [] };
      e.helpers.add(helperAddr);
      for (const s of anchors) if (e.anchors.length < 6 && !e.anchors.includes(s)) e.anchors.push(s);
      orchestrators.set(ca, e);
    }
  }
  // Pass 2: the helpers themselves, plus the orchestrators found above.
  for (const fn of db.functions) {
    if (fn.isImportStub || !fn.features) continue;
    const own = ownAnchors.get(fn.addr) ?? [];
    const orch = orchestrators.get(fn.addr);
    const helperCalls = orch && orch.helpers.size >= 2 ? orch.helpers.size : 0;
    const helperAnchors = helperCalls ? orch!.anchors : [];
    if (own.length === 0 && helperCalls < 2) continue;
    const anchorStrings = own.length ? own : helperAnchors;
    const imports = db.importCallsOf(fn);
    const callees = db.calleesOf(fn).map((c) => db.callNameFor(c.to));
    const h = fn.features.mnemonicHist ?? {};
    // Indirect calls (dispatch signal): ARM64 BLR/BLRAA…, ARM32 BLX reg, x86 `call r/m`.
    let indirect = 0;
    for (const [m, n] of Object.entries(h)) if (m === "blr" || m.startsWith("blra") || m === "blx" || m === "call*") indirect += n;
    const score = scoreMrpc({
      strings: anchorStrings,
      imports,
      callees,
      hasLoop: !!fn.features.hasLoop,
      branches: fn.features.branchCount ?? 0,
      stores: fn.features.storeCount ?? 0,
      indirectCalls: indirect,
      helperCalls,
    });
    if (!score) continue;
    findings.push({
      addr: fn.addr,
      name: db.nameFor(fn.addr).name,
      role: score.role,
      confidence: score.confidence,
      proofLevel: score.proofLevel,
      legs: score.legs,
      strings: anchorStrings.filter((s) => MRPC_STR.test(s)).slice(0, 4).map((s) => (own.length ? s : `via helper: ${s}`).slice(0, 56)),
      imports: imports.slice(0, 6),
      how: score.how,
    });
  }
  // Pass 3: EXPLORE. The real parser/applier/dispatcher often have NO strings —
  // they walk a downloaded binary blob and dispatch on rule ids. String-matching
  // can't see them; the call graph can. BFS out of the string-anchored seeds and
  // score each STRING-LESS callee by its structure (parse / dispatch / apply
  // loop). Proximity to a real MRPC anchor is what keeps this from flagging every
  // parser in the binary.
  const seeds = findings.map((f) => f.addr);
  if (seeds.length) {
    const anchored = new Set(seeds);
    const seen = new Set<number>(seeds);
    let frontier = seeds.map((a) => ({ addr: a, hop: 0, from: a }));
    let budget = 6000;
    const MAX_HOPS = 3;
    for (let hop = 1; hop <= MAX_HOPS && frontier.length && budget > 0; hop++) {
      const next: { addr: number; hop: number; from: number }[] = [];
      for (const node of frontier) {
        const nf = db.functionByAddr(node.addr);
        if (!nf) continue;
        for (const c of db.calleesOf(nf)) {
          if (budget-- <= 0) break;
          const to = c.to;
          if (seen.has(to)) continue;
          seen.add(to);
          const cf = db.functionByAddr(to);
          if (!cf || cf.isImportStub || !cf.features) continue;
          next.push({ addr: to, hop, from: node.from });
          if (ownAnchors.has(to) || anchored.has(to)) continue; // already a string finding
          if ((cf.features.stringRefs ?? []).some((x) => { const v = db.stringAt(x)?.value; return v && MRPC_STR.test(v); })) continue;
          const st = structuralMrpcRole({ mnemonicHist: cf.features.mnemonicHist ?? {}, hasLoop: !!cf.features.hasLoop, loadCount: cf.features.loadCount ?? 0, storeCount: cf.features.storeCount ?? 0, branchCount: cf.features.branchCount ?? 0, callCount: cf.features.callCount ?? 0, size: cf.size });
          if (!st) continue;
          const fromName = db.nameFor(node.from).name;
          findings.push({
            addr: to,
            name: db.nameFor(to).name,
            role: st.role,
            confidence: Math.max(0.28, Math.min(0.6, 0.3 + 0.05 * st.score - 0.05 * hop)),
            proofLevel: "lead",
            legs: [...st.legs, `explored:${hop}-hop(s)-from-${fromName}`, "no-strings"],
            strings: [],
            imports: db.importCallsOf(cf).slice(0, 6),
            how: `${neutralizeHow(st.role, { net: false, file: false, parse: st.role === "parser", apply: st.role === "applier", dispatch: st.role === "dispatcher" })} Found by EXPLORING ${hop} hop(s) from ${fromName} — it has no strings, so confirm on a live run (break here, check it runs while rules apply).`,
            explored: true,
          });
          anchored.add(to);
        }
        if (budget <= 0) break;
      }
      frontier = next;
    }
  }
  findings.sort((a, b) => b.confidence - a.confidence || a.addr - b.addr);
  const top = findings.slice(0, Math.max(limit, 20));
  const networkBacked = top.some((f) => f.legs.includes("download:network"));
  return { findings: top, count: top.length, networkBacked, verdict: mrpcVerdict(top, networkBacked) };
}

export function mrpcVerdict(findings: MrpcFinding[], networkBacked: boolean): string {
  if (!findings.length) return "No downloaded-rule engine (MRPC) found in this .so: no routine references rule/config/policy download vocabulary together with a fetch/parse/apply mechanism. Detection here is either fully baked-in (each check is its own finding above), or the rule engine lives in a sibling library (libanogs/libtersafe-style) or in Java — load those alongside and re-check the Links view.";
  const roles = new Map<MrpcRole, number>();
  for (const f of findings) roles.set(f.role, (roles.get(f.role) ?? 0) + 1);
  const roleStr = [...roles.entries()].map(([r, n]) => `${n} ${r}`).join(", ");
  const strong = findings.find((f) => f.role === "downloader") ?? findings.find((f) => f.role === "applier") ?? findings[0];
  const allLeads = findings.every((f) => f.proofLevel === "lead");
  const explored = findings.filter((f) => f.explored).length;
  const exploreNote = explored ? ` ${explored} of these have NO strings and were found by EXPLORING the call graph from the anchors (parse/dispatch/apply structure) — that is where the real rule parser/applier live; confirm them live.` : "";
  const obfNote = allLeads ? " These are LEAD-level — the anchor strings barely cross-reference (obfuscated/computed loads, typical of anogs/ACE), so the split is inferred from structure + strings; break at each on a live run to confirm the pipeline before trusting it." : "";
  return `Downloaded-rule engine (MRPC) present: ${findings.length} routine(s) (${roleStr}) fetch/parse/apply a rule set at runtime. ${networkBacked ? "It is SERVER-FED (pulls rules over the network) — the most effective single hit is to starve the download so no rules arrive." : "No network leg surfaced statically — hook the parser/applier to yield zero rules, or the downloader if it fetches via a helper."} Best single point: ${strong.name} @ 0x${strong.addr.toString(16)} (${strong.role}).${exploreNote}${obfNote} Caveat: rules the server also enforces server-side can't be killed from the client — this stops LOCAL application only.`;
}
