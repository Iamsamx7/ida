import type { AnalysisDatabase } from "../core/analysis/database";
import type { FunctionRecord, Evidence } from "../core/analysis/types";
import { extractFeatures, similarity } from "../core/analysis/features";
import { generatePseudocode } from "../core/analysis/pseudocode";
import { parseAgentTask, type AgentTask } from "./agent";
import { search } from "../core/search/engine";

/**
 * Structured retrieval for the AI assistant. The assistant never receives
 * pasted text blobs; it receives this typed context assembled from the
 * analysis database, and every item carries addresses so answers can link
 * back to evidence.
 */
export interface FunctionContextPack {
  addr: number;
  name: string;
  nameSource: string;
  size: number;
  confidence: number;
  sources: string[];
  classes: { label: string; confidence: number; level: string; evidence: Evidence[] }[];
  disassembly: { addr: number; text: string }[];
  pseudocode: string[];
  callers: { addr: number; name: string; from: number }[];
  callees: { addr: number; name: string; from: number }[];
  strings: { addr: number; value: string; category: string }[];
  globals: { addr: number; name: string; kind: string }[];
  comments: { addr: number; body: string }[];
  tags: string[];
  userName?: string;
  featuresSummary: string;
}

export type Intent =
  | { kind: "explain"; addr?: number }
  | { kind: "callers"; addr?: number }
  | { kind: "callees"; addr?: number }
  | { kind: "string-uses"; query: string }
  | { kind: "semantic-search"; query: string }
  | { kind: "global-access"; addr?: number; query?: string }
  | { kind: "similar"; addr?: number }
  | { kind: "why"; addr?: number }
  | { kind: "suggest-name"; addr?: number }
  | { kind: "search"; query: string }
  | { kind: "anticheat" }
  | { kind: "ban" }
  | { kind: "hash" }
  | { kind: "libraries" }
  | { kind: "imports"; query: string }
  | { kind: "bypass" }
  | { kind: "agent"; task: AgentTask }
  | { kind: "overview" }
  | { kind: "help" }
  | { kind: "general"; query: string };

export interface IntentOptions {
  /** Import names declared by the loaded binary — lets "where is X used" fire only for real imports. */
  imports?: Iterable<string>;
}

/** Question filler that can never be an import target. */
const Q_STOP = new Set(["where", "which", "what", "who", "whom", "how", "does", "do", "did", "is", "are", "was", "were", "be", "been", "find", "show", "list", "give", "tell", "me", "us", "the", "a", "an", "this", "that", "these", "those", "it", "its", "and", "or", "of", "to", "in", "on", "for", "with", "from", "by", "at", "into", "all", "any", "some", "every", "used", "use", "uses", "using", "usage", "call", "calls", "called", "calling", "caller", "callers", "callee", "callees", "import", "imports", "imported", "function", "functions", "routine", "routines", "code", "symbol", "symbols", "xref", "xrefs", "reference", "references", "here", "there", "please", "can", "you", "i", "we", "my", "our", "your", "get", "have", "has", "not", "no", "yes", "one", "ones", "thing", "things", "stuff", "player", "world", "state", "game", "data", "value", "values", "check", "checks", "logic", "handler", "handlers", "api", "apis", "library", "libraries", "lib", "libs", "binary", "file", "files", "string", "strings", "global", "globals"]);
/** Real libc names that are also ordinary English verbs — only accepted when the binary declares them AND the phrasing is call-like. */
const GENERIC_IMPORT_WORDS = new Set(["read", "write", "open", "close", "free", "send", "recv", "time", "kill", "exit", "access", "stat", "bind", "listen", "accept", "connect", "select", "poll", "signal", "raise", "system", "remove", "rename", "sleep", "abort", "socket", "link", "unlink", "wait", "pipe", "dup", "fork", "exec", "clone", "stop", "start", "seek", "lock", "unlock", "sync", "flush", "load", "save", "init", "set", "put", "add", "mark", "test", "match", "search", "sort", "copy", "move", "swap", "hash", "crypt", "log", "print", "printf", "exp", "pow", "abs", "div", "mod", "round", "floor", "random", "rand", "srand", "atoi", "index", "memory", "alloc"]);
const WELL_KNOWN_IMPORTS = new Set(["memcpy", "memmove", "memset", "memcmp", "memchr", "bzero", "gettimeofday", "clock_gettime", "nanosleep", "usleep", "malloc", "calloc", "realloc", "mmap", "munmap", "mprotect", "madvise", "ptrace", "dlopen", "dlsym", "dlclose", "dladdr", "sendto", "recvfrom", "sendmsg", "recvmsg", "getaddrinfo", "gethostbyname", "setsockopt", "__android_log_print", "__android_log_write", "__system_property_get", "strcmp", "strncmp", "strlen", "strcpy", "strncpy", "strstr", "strchr", "strcat", "strdup", "snprintf", "sprintf", "sscanf", "pthread_create", "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_join", "openat", "fopen", "fread", "fwrite", "fclose", "readlink", "opendir", "readdir", "inotify_add_watch", "getppid", "getpid", "gettid", "tgkill", "tkill", "prctl", "syscall", "inflate", "deflate", "uncompress", "sha1", "sha256", "sha512", "md5", "hmac", "aes_encrypt", "aes_decrypt", "evp_digestinit", "evp_encryptinit", "ssl_read", "ssl_write", "ssl_connect", "curl_easy_perform", "__stack_chk_fail", "__cxa_throw", "__cxa_begin_catch", "abort", "raise", "sigaction", "getauxval", "uname", "getenv", "setenv", "fstat", "lstat", "ioctl", "fcntl", "epoll_wait", "eventfd", "getrandom"]);

/**
 * The import a "where/who/which … X" question is really about, or null.
 * X must be a real identifier: declared by this binary, a well-known libc/
 * Android/OpenSSL name, or identifier-shaped (underscore, ALLCAPS prefix,
 * Itanium mangling). Plain English verbs that happen to be libc names (read,
 * write, open, free…) only count when the binary declares them and the
 * sentence treats them as a callee ("who calls open", "where is read() used").
 */
export function importTarget(q: string, opts?: IntentOptions): string | null {
  const unquoted = q.replace(/"[^"]*"|“[^”]*”|'[^']*'/g, " ");
  const t = unquoted.toLowerCase();
  if (!/\b(where|who|whom|which|what|find|show|list|uses?|calls?|callers?|imports?|xrefs?|references?|used|called)\b/.test(t)) return null;
  const declared = new Map<string, string>();
  for (const n of opts?.imports ?? []) declared.set(n.toLowerCase(), n);
  const toks = unquoted.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
  let best: string | null = null;
  for (const tok of toks) {
    const lower = tok.toLowerCase();
    if (Q_STOP.has(lower) || lower.length < 3) continue;
    const decl = declared.get(lower);
    const generic = GENERIC_IMPORT_WORDS.has(lower);
    const identLike = /_/.test(tok) || /^[A-Z]{2,}[A-Za-z0-9_]*$/.test(tok) || /^_Z/.test(tok) || /\d/.test(tok);
    const callLike = new RegExp(`\\b(?:calls?|uses?|import(?:s|ed)?|to|of|callers of|xrefs to)\\s+${tok}\\b|\\b${tok}\\s*(?:\\(|\\s+(?:is\\s+|are\\s+|gets?\\s+)?(?:used|called|imported|referenced|invoked))`, "i").test(unquoted);
    let ok = false;
    let name = tok;
    if (decl) { ok = !generic || callLike; name = decl; }
    else if (!generic) ok = WELL_KNOWN_IMPORTS.has(lower) || identLike;
    if (ok && (!best || name.length > best.length)) best = name;
  }
  return best;
}

export function parseIntent(q: string, opts?: IntentOptions): Intent {
  const t = q.trim().toLowerCase();
  const addrM = t.match(/\b0x[0-9a-f]+\b/);
  const addr = addrM ? parseInt(addrM[0], 16) : undefined;
  const agentTask = parseAgentTask(q);
  if (agentTask) return { kind: "agent", task: agentTask };
  if (/^(help|hi|hello|hey|yo|sup|what can you do|what do you do|commands?|\?)\s*[!?.]*$/.test(t)) return { kind: "help" };
  // XREF questions about the cursor come first — "what does this call?" is a
  // callee list, not an explanation.
  if (/what does (this|it) call|callees|calls what|which functions does (this|it) call/.test(t)) return { kind: "callees", addr };
  // Explicit "this function" questions win over topic sweeps: "what does this
  // hash function do?" is about the routine under the cursor, not a hash hunt.
  if (/^(what does|what is|what'?s|explain|describe|summari[sz]e|tell me about|walk me through|analy[sz]e)\s+(this|it|the (current|selected|highlighted) \w+|this \w+( function| routine| code)?)\b/.test(t) && !/\b(binary|library|module|file|whole)\b/.test(t)) return { kind: "explain", addr };
  if (/^(what does|explain|describe|analy[sz]e|tell me about)\s+(0x[0-9a-f]+|sub_[0-9a-f]+|loc_[0-9a-f]+)\b/.test(t)) return { kind: "explain", addr };
  if (/bypass|defeat.*(anticheat|anti.cheat|protection)|neutrali[sz]e.*check|auto.*(hook|patch)|full.*safe|kill.*anticheat/.test(t)) return { kind: "bypass" };
  const detector = DETECTOR_QUERIES.find(([pattern]) => pattern.test(t));
  if (detector) return { kind: "semantic-search", query: detector[1] };
  if (/anti[\s_-]?cheat|antidebug|emulator|root.detect|magisk|frida|xposed|debugger.detect|tamper.detect|integrity.check|where.*(cheat|hack|protect|guard|tss|anogs)/.test(t)) return { kind: "anticheat" };
  if (/\bban(ned)?\b|punish|suspend|violation|report.*cheat|where.*ban/.test(t)) return { kind: "ban" };
  if (/\bhash(check)?\b|checksum|crc.?32|murmur|fnv|xxhash|digest.?verif|verify.*(hash|signature|integrity)|where.*hash/.test(t)) return { kind: "hash" };
  if (/librar|which lib|what lib|dependencies|where.*\blib\b|lib.*map|what.*linked|imports.*from|what does it (need|link)/.test(t)) return { kind: "libraries" };
  if (/where is (this |the )?string|string .*used|uses? (this|the) string|references? (to )?(this |the )?string/.test(t)) return { kind: "string-uses", query: (q.match(/"([^"]+)"/)?.[1] ?? q.match(/“([^”]+)”/)?.[1] ?? q.replace(/.*string/i, "")).trim() };
  if (/which functions (access|read|write|use) (this|the) global|access(es)? this global|who (reads|writes)/.test(t)) return { kind: "global-access", addr, query: q.match(/"([^"]+)"/)?.[1] };
  const imp = importTarget(q, opts);
  if (imp) return { kind: "imports", query: imp };
  if (/^(what|which) (functions?|code) (calls?|references?|uses?) (this|it)/.test(t) || /^(who|what) calls/.test(t) || /callers/.test(t)) return { kind: "callers", addr };
  if (/what does (this|it) call|callees|calls what|which functions does/.test(t)) return { kind: "callees", addr };
  if (/similar/.test(t)) return { kind: "similar", addr };
  if (/^why\b|^how do you know|\bevidence (for|behind|of)\b|what('s| is) the evidence|classif/.test(t)) return { kind: "why", addr };
  if (/suggest.*name|name (for|this)|\brename\b|what should (i|we) call/.test(t)) return { kind: "suggest-name", addr };
  if (/show me|find|everything related|related to|functions that|look like|possible .* functions|where are .* handled/.test(t)) return { kind: "semantic-search", query: q.replace(/^(show me|find|list)\s+/i, "") };
  if (/overview|summar(y|ise|ize) (the|this) (binary|library|module)|what is this (binary|library|module|file)|what does this (binary|library|module) do/.test(t)) return { kind: "overview" };
  if (/what (does|is) (this|it)|explain|simple terms|purpose|do\?$/.test(t)) return { kind: "explain", addr };
  if (/^(search|grep|look for)\s/.test(t)) return { kind: "search", query: q.replace(/^(search|grep|look for)\s+/i, "") };
  return { kind: "general", query: q };
}

const DETECTOR_QUERIES: [RegExp, string][] = [
  [/debugger[\s_-]detection|anti[\s_-]debugging/, "debugger-detection"],
  [/root[\s_-]detection/, "root-detection"],
  [/emulator[\s_-]detection/, "emulator-detection"],
  [/instrumentation[\s_-]detection|frida[\s_-]detection/, "instrumentation-detection"],
  [/process[\s_-]inspection/, "process-inspection"],
  [/(?:tls|certificate)[\s_-]verification/, "tls-verification"],
  [/(?:certificate|public[\s_-]key)[\s_-]pinning/, "certificate-pinning"],
  [/signature[\s_-]verification/, "signature-verification"],
  [/memory[\s_-]permission[\s_-]changes?/, "memory-permission-change"],
  [/secure[\s_-]random/, "secure-random"],
  [/secure[\s_-]erasure/, "secure-erasure"],
  [/native[\s_-]registration/, "native-registration"],
];

export function packFunction(db: AnalysisDatabase, fn: FunctionRecord, maxInsns = 120): FunctionContextPack {
  const insns = db.decodeFunction(fn, Math.max(maxInsns, 400));
  if (!fn.features) fn.features = extractFeatures(db, fn, insns);
  const f = fn.features;
  const strings = f.stringRefs.map((a) => db.stringAt(a)).filter((s): s is NonNullable<typeof s> => !!s).map((s) => ({ addr: s.addr, value: s.value.slice(0, 120), category: s.category }));
  const globals = db.dataRefsOf(fn).filter((x) => !db.stringAt(x.to) && !db.space.isExec(x.to)).slice(0, 20).map((x) => ({ addr: x.to, name: db.nameFor(x.to).name, kind: x.kind === 4 ? "write" : x.kind === 3 ? "read" : "address" }));
  const comments = insns.filter((i) => db.comments.has(i.address)).map((i) => ({ addr: i.address, body: db.comments.get(i.address)! }));
  const fc = db.functionComments.get(fn.addr);
  if (fc) comments.unshift({ addr: fn.addr, body: fc });
  const total = Object.values(f.mnemonicHist).reduce((a, b) => a + b, 0);
  return {
    addr: fn.addr,
    name: db.nameFor(fn.addr).name,
    nameSource: db.nameFor(fn.addr).source,
    size: fn.size,
    confidence: fn.confidence,
    sources: fn.sources,
    classes: (fn.classes ?? []).map((c) => ({ label: c.label, confidence: c.confidence, level: c.level, evidence: c.evidence })),
    disassembly: insns.slice(0, maxInsns).map((i) => ({ addr: i.address, text: `${i.mnemonic} ${i.opText}`.trim() })),
    pseudocode: generatePseudocode(db, fn, insns).map((l) => "  ".repeat(l.indent) + l.text),
    callers: db.callersOf(fn).slice(0, 25).map((c) => ({ addr: c.fn?.addr ?? c.from, name: c.fn ? db.nameFor(c.fn.addr).name : db.labelFor(c.from), from: c.from })),
    callees: db.calleesOf(fn).slice(0, 25).map((c) => ({ addr: c.to, name: db.callNameFor(c.to), from: c.from })),
    strings,
    globals,
    comments,
    tags: [...(db.tags.get(fn.addr) ?? [])],
    userName: db.userNames.get(fn.addr)?.name,
    featuresSummary: `${total} instructions, ${f.branchCount} branches, ${f.callCount} calls, ${f.loadCount} loads, ${f.storeCount} stores${f.hasLoop ? ", contains loop(s)" : ""}; field offsets: ${f.memAccessOffsets.slice(0, 8).map((o) => "0x" + o.toString(16)).join(" ") || "none"}`,
  };
}

export function findSimilar(db: AnalysisDatabase, fn: FunctionRecord, limit = 10, minScore = 0.6) {
  if (!fn.features) fn.features = extractFeatures(db, fn);
  const out: { fn: FunctionRecord; score: number }[] = [];
  const sizeLo = fn.size * 0.4, sizeHi = fn.size * 2.5;
  // After the semantic stage every function already carries features; before it
  // each miss costs a full decode on the UI thread, so cap the cold work.
  let budget = 2000;
  for (const g of db.functions) {
    if (g.addr === fn.addr || g.isImportStub) continue;
    if (g.size < sizeLo || g.size > sizeHi) continue;
    if (!g.features) {
      if (budget-- <= 0) continue;
      g.features = extractFeatures(db, g);
    }
    const s = similarity(fn.features, g.features, fn.size, g.size);
    if (s >= minScore) out.push({ fn: g, score: s });
  }
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, limit);
}

export function semanticSearch(db: AnalysisDatabase, index: Map<number, string>, query: string, limit = 25) {
  const words = query.toLowerCase().replace(/[^a-z0-9 _-]/g, " ").split(/\s+/).filter((w) => w.length > 2 && !STOP.has(w));
  const expanded = new Set<string>();
  for (const w of words) {
    expanded.add(w);
    // "anti-cheat" / "anti_cheat" → "anticheat" so the synonym table and the index agree.
    const joined = w.replace(/[-_]/g, "");
    if (joined !== w && joined.length > 2) expanded.add(joined);
    for (const s of SYN[w] ?? SYN[joined] ?? []) expanded.add(s);
  }
  const scored: { fn: FunctionRecord; score: number; matched: string[] }[] = [];
  for (const f of db.functions) {
    const text = index.get(f.addr);
    if (!text) continue;
    const matched: string[] = [];
    let score = 0;
    for (const w of expanded) if (text.includes(w)) { matched.push(w); score += words.includes(w) ? 2 : 1; }
    if (score) {
      if (f.classes?.length) score += f.classes[0].confidence;
      scored.push({ fn: f, score, matched });
    }
  }
  scored.sort((a, b) => b.score - a.score);
  const results = scored.slice(0, limit);
  // fall back to generic search
  if (!results.length) {
    for (const h of search(db, query, { limitPerCategory: limit }).slice(0, limit)) {
      const f = db.functionAt(h.address);
      if (f && !results.some((r) => r.fn === f)) results.push({ fn: f, score: h.score / 10, matched: [h.category] });
    }
  }
  return results;
}

const STOP = new Set(["the", "this", "that", "with", "show", "find", "functions", "function", "code", "look", "like", "related", "possible", "are", "where", "which", "what", "for", "and", "all", "any", "everything"]);
const SYN: Record<string, string[]> = {
  network: ["networking", "socket", "http", "packet", "recv", "send"], networking: ["socket", "http", "packet"], packet: ["networking", "serialization", "parse"], parsing: ["serialization", "parse"], parser: ["serialization"],
  player: ["state-management", "state-access", "player", "actor"], world: ["state-management", "state-access", "world"], state: ["state-management", "state-access"],
  config: ["configuration", "setting", "option"], configuration: ["setting", "cfg"], crypto: ["cryptography", "hashing", "aes", "sha"], encryption: ["cryptography"], hash: ["hashing", "hash-check", "crc", "digest"],
  render: ["rendering", "shader", "texture", "draw"], rendering: ["shader", "gl"], memory: ["memory-management", "malloc", "free"], alloc: ["memory-management"], file: ["file-io", "fopen", "path"], files: ["file-io"],
  log: ["logging", "__android_log_print"], logging: ["log"], init: ["initialization"], integrity: ["integrity-check", "hash-check", "validation", "tamper"], antidebug: ["integrity-check", "anticheat", "ptrace"], debugger: ["integrity-check", "anticheat", "ptrace"],
  string: ["string-processing", "strlen", "strcmp"], thread: ["threading", "pthread"], lock: ["synchronization", "mutex"], jni: ["jni-bridge", "java"], java: ["jni-bridge"], input: ["input-handling", "touch"], compress: ["compression", "inflate"],
  error: ["error-handling", "abort"], exception: ["error-handling", "__cxa_throw"], time: ["timing", "clock"], serialization: ["serialize", "parse", "encode", "decode"],
  anticheat: ["anticheat", "integrity-check", "ptrace", "ban-check"], cheat: ["anticheat", "integrity-check"], hack: ["anticheat"], bypass: ["anticheat"], emulator: ["anticheat"], root: ["anticheat", "integrity-check"],
  frida: ["anticheat"], magisk: ["anticheat"], xposed: ["anticheat"], guard: ["anticheat"], protect: ["anticheat"],
  ban: ["ban-check", "anticheat"], banned: ["ban-check"], punish: ["ban-check"], suspend: ["ban-check"], violation: ["ban-check", "anticheat"],
  checksum: ["hash-check", "hashing"], verify: ["hash-check", "validation"], signature: ["hash-check", "cryptography"], tamper: ["anticheat", "integrity-check", "hash-check"],
  revive: ["game-revive", "state-management"], respawn: ["game-revive"], resurrect: ["game-revive"], recall: ["game-revive"], heal: ["game-revive", "state-management"],
  health: ["game-revive", "state-access"], teammate: ["game-revive"], knock: ["game-revive"],
  memcpy: ["memory-operations", "memcpy"], memset: ["memory-operations"], gettimeofday: ["timing"], clock: ["timing"],
};
