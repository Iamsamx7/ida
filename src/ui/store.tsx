"use client";
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AnalysisCoordinator, type LogEntry } from "@/core/engine/coordinator";
import type { AnalysisDatabase } from "@/core/analysis/database";
import { ANALYSIS_VERSION, type FunctionRecord, type StageState } from "@/core/analysis/types";
import { CPUBackend } from "@/compute/backend";
import { LocalAssistant } from "@/ai/assistant";
import { libDescriptor, linkLibraries, type LinkGraph } from "@/core/analysis/link";

export type CenterTab = "overview" | "disasm" | "pseudo" | "hex" | "elf" | "graph" | "search" | "compare" | "links";

/** One library in the workspace. The focused one is mirrored into `db`/`assistant`. */
export interface LoadedLib {
  name: string;
  hash: string;
  db: AnalysisDatabase;
  assistant: LocalAssistant;
  index: Map<number, string>;
}
export type LeftTab = "functions" | "sections" | "imports" | "exports" | "strings" | "structures" | "globals" | "bookmarks" | "tags";
export type RightTab = "info" | "xrefs" | "ai";

export interface AiObservation {
  id?: number;
  address: number;
  kind: string;
  content: string;
  confidence: number;
  evidence: { address?: number; text: string }[];
  verdict: "pending" | "accepted" | "rejected";
}

interface WorkbenchState {
  coordinator: AnalysisCoordinator | null;
  db: AnalysisDatabase | null;
  assistant: LocalAssistant | null;
  stages: StageState[];
  logs: LogEntry[];
  fileName: string | null;
  loading: boolean;
  error: string | null;
  currentAddr: number | null;
  selection: { start: number; end: number } | null;
  canBack: boolean;
  canForward: boolean;
  centerTab: CenterTab;
  leftTab: LeftTab;
  rightTab: RightTab;
  tick: number;
  workerCount: number;
  computeMode: "auto" | "cpu" | "gpu";
  gpuLoad: number;
  projectHash: string | null;
  projectRestored: { names: number; comments: number; bookmarks: number } | null;
  aiObservations: AiObservation[];
  llm: { configured: boolean; provider: string; model: string | null } | null;
  paletteOpen: boolean;
  gotoOpen: boolean;
  searchQuery: string;
  renameTarget: number | null;
  commentTarget: number | null;
  compareBinary: { name: string; db: AnalysisDatabase } | null;
  activeQuestion: string | null;
  /** Multi-library workspace; the focused lib is mirrored into `db`/`assistant`. */
  libs: LoadedLib[];
  link: LinkGraph | null;
  workspaceBusy: boolean;
}

interface WorkbenchApi extends WorkbenchState {
  openFile(file: File | { name: string; bytes: Uint8Array }): Promise<void>;
  openSample(): Promise<void>;
  openCompare(file: File): Promise<void>;
  navigate(addr: number, opts?: { tab?: CenterTab; push?: boolean }): void;
  back(): void;
  forward(): void;
  setCenterTab(t: CenterTab): void;
  setLeftTab(t: LeftTab): void;
  setRightTab(t: RightTab): void;
  setSelection(s: { start: number; end: number } | null): void;
  rename(addr: number, name: string, origin?: "user" | "ai-accepted"): void;
  setComment(addr: number, body: string, scope?: "line" | "function"): void;
  toggleBookmark(addr: number, label?: string, kind?: "address" | "function" | "string" | "data"): void;
  addTag(addr: number, tag: string): void;
  removeTag(addr: number, tag: string): void;
  recordObservation(o: Omit<AiObservation, "id" | "verdict">): Promise<AiObservation>;
  setVerdict(o: AiObservation, verdict: "accepted" | "rejected"): void;
  setWorkerCount(n: number): void;
  setComputeMode(m: "auto" | "cpu" | "gpu"): void;
  setGpuLoad(n: number): void;
  setPaletteOpen(b: boolean): void;
  setGotoOpen(b: boolean): void;
  setSearchQuery(q: string): void;
  setRenameTarget(a: number | null): void;
  setCommentTarget(a: number | null): void;
  askAI(question: string): void;
  /** Called by the AI panel once it has consumed `activeQuestion`, so the same question can be asked again later. */
  clearActiveQuestion(): void;
  /** Add another library to the workspace (fully analyzed) and recompute the cross-lib graph. */
  addLibrary(file: File): Promise<void>;
  /** Focus a loaded library — mirrors it into db/assistant so every panel follows. */
  focusLibrary(i: number): void;
  reanalyze(): Promise<void>;
  bump(): void;
  log(level: LogEntry["level"], source: string, message: string): void;
}

const Ctx = createContext<WorkbenchApi | null>(null);

export function useWorkbench() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useWorkbench outside provider");
  return c;
}

const api = {
  async json(url: string, init?: RequestInit) {
    try {
      const r = await fetch(url, { ...init, headers: { "content-type": "application/json", ...(init?.headers ?? {}) } });
      return await r.json();
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  },
};

/** Saved worker count, else cores-1 (the provider is client-only, so storage is available at first render). */
function initialWorkerCount() {
  if (typeof window === "undefined") return 0;
  const cores = navigator.hardwareConcurrency || 4;
  const saved = Number(localStorage.getItem("rw.workers") || 0);
  return saved || Math.max(1, cores - 1);
}

function initialCompute(): { mode: "auto" | "cpu" | "gpu"; load: number } {
  if (typeof window === "undefined") return { mode: "auto", load: 0.5 };
  const mode = localStorage.getItem("rw.compute") as "auto" | "cpu" | "gpu" | null;
  const load = Number(localStorage.getItem("rw.gpuload") || 0.5);
  return { mode: mode === "cpu" || mode === "gpu" ? mode : "auto", load: Math.min(1, Math.max(0.1, load || 0.5)) };
}

export function WorkbenchProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<WorkbenchState>(() => ({
    coordinator: null, db: null, assistant: null, stages: [], logs: [], fileName: null, loading: false, error: null, currentAddr: null, selection: null,
    canBack: false, canForward: false, centerTab: "overview", leftTab: "functions", rightTab: "info", tick: 0, workerCount: initialWorkerCount(), computeMode: initialCompute().mode, gpuLoad: initialCompute().load, projectHash: null, projectRestored: null,
    aiObservations: [], llm: null, paletteOpen: false, gotoOpen: false, searchQuery: "", renameTarget: null, commentTarget: null, compareBinary: null, activeQuestion: null,
    libs: [], link: null, workspaceBusy: false,
  }));
  const history = useRef<{ list: number[]; idx: number }>({ list: [], idx: -1 });
  const lastBytes = useRef<{ name: string; bytes: Uint8Array } | null>(null);
  const patch = useCallback((p: Partial<WorkbenchState> | ((s: WorkbenchState) => Partial<WorkbenchState>)) => setState((s) => ({ ...s, ...(typeof p === "function" ? p(s) : p) })), []);
  const bump = useCallback(() => setState((s) => ({ ...s, tick: s.tick + 1 })), []);

  useEffect(() => {
    let alive = true;
    api.json("/api/ai/chat").then((j) => { if (alive) patch({ llm: { configured: !!j.configured, provider: j.provider ?? "local", model: j.model ?? null } }); });
    return () => { alive = false; };
  }, [patch]);

  const log = useCallback((level: LogEntry["level"], source: string, message: string) => {
    setState((s) => ({ ...s, logs: [...s.logs.slice(-2000), { ts: Date.now(), level, source, message }] }));
  }, []);

  const persist = useCallback((hash: string | null, body: Record<string, unknown>) => {
    if (!hash) return;
    void api.json(`/api/projects/${hash}`, { method: "PUT", body: JSON.stringify(body) });
  }, []);

  const openBytes = useCallback(async (name: string, bytes: Uint8Array) => {
    state.coordinator?.cancel();
    lastBytes.current = { name, bytes };
    history.current = { list: [], idx: -1 };
    const coord = new AnalysisCoordinator();
    patch({ loading: true, error: null, fileName: name, coordinator: coord, db: null, assistant: null, stages: coord.stages, logs: [], currentAddr: null, selection: null, canBack: false, canForward: false, centerTab: "overview", projectHash: null, projectRestored: null, aiObservations: [], compareBinary: null, libs: [], link: null });
    coord.on("stages", (st) => patch({ stages: [...st.map((x) => ({ ...x }))] }));
    coord.on("log", (e) => setState((s) => ({ ...s, logs: [...s.logs.slice(-2000), e] })));
    coord.on("update", () => bump());
    try {
      // Identity first so cached results can be shown immediately.
      const hash = await new CPUBackend().sha256(bytes);
      const proj = await api.json(`/api/projects/${hash}`);
      if (!proj.ok) coord.log("warning", "project", `Project database unavailable (${proj.error ?? "request failed"}); names, comments and bookmarks will not be persisted`);
      let cached: Partial<FunctionRecord>[] | null = null;
      if (proj.ok && proj.project) {
        const snap = proj.snapshots?.find((s: { stage: string; analysisVersion: string }) => s.stage === "functions" && s.analysisVersion === ANALYSIS_VERSION);
        if (snap) {
          const sj = await api.json(`/api/projects/${hash}/snapshot?stage=functions`);
          if (sj.ok && sj.snapshot?.payload?.functions) cached = sj.snapshot.payload.functions;
          if (sj.snapshot && !sj.snapshot.complete) coord.log("warning", "cache", "Recovered incomplete analysis from a previous session; re-running remaining stages");
        }
      }
      const openP = coord.open(bytes, name, { workers: state.workerCount || undefined, cachedFunctions: cached, compute: { mode: state.computeMode, gpuLoad: state.gpuLoad, gpuMinBytes: 256 * 1024 } });
      // The ELF stage runs synchronously inside open(), so the db normally exists already; only wait for the
      // "elf" update if it does not (subscribing after the fact would otherwise miss the event and hang forever).
      const db = coord.db ?? await new Promise<AnalysisDatabase>((res, rej) => {
        const off = coord.on("update", (w) => { if (w === "elf" && coord.db) { off(); res(coord.db); } });
        openP.catch(rej);
      });
      db.hash = hash;
      const assistant = new LocalAssistant(db, coord.aiIndex);
      // restore annotations
      let restored: WorkbenchState["projectRestored"] = null;
      let observations: AiObservation[] = [];
      let persistOk = !!(proj.ok && proj.project);
      if (proj.ok && proj.project) {
        for (const n of proj.names ?? []) db.setUserName(Number(n.address), n.name, n.origin === "ai-accepted" ? "ai-accepted" : "user");
        for (const c of proj.comments ?? []) (c.scope === "function" ? db.functionComments : db.comments).set(Number(c.address), c.body);
        for (const b of proj.bookmarks ?? []) db.bookmarks.set(Number(b.address), { address: Number(b.address), kind: b.kind, label: b.label, note: b.note ?? "" });
        for (const t of proj.tags ?? []) { const s = db.tags.get(Number(t.address)) ?? new Set<string>(); s.add(t.tag); db.tags.set(Number(t.address), s); }
        for (const s of proj.structures ?? []) db.structures.push({ id: `user_${s.id}`, name: s.name, origin: s.origin, fields: s.fields, evidence: [{ text: "user-defined", certainty: "user" }], functions: [], confidence: 1 });
        observations = (proj.aiObservations ?? []).map((o: AiObservation & { address: string | number }) => ({ ...o, address: Number(o.address) }));
        restored = { names: (proj.names ?? []).length, comments: (proj.comments ?? []).length, bookmarks: (proj.bookmarks ?? []).length };
        coord.log("info", "project", `Restored project: ${restored.names} names, ${restored.comments} comments, ${restored.bookmarks} bookmarks, ${observations.length} AI observations`);
      } else {
        const created = await api.json("/api/projects", { method: "POST", body: JSON.stringify({ hash, fileName: name, size: bytes.length, arch: db.elf.header.arch, elfClass: db.elf.header.elfClass, endianness: db.elf.header.littleEndian ? "little" : "big", analysisVersion: ANALYSIS_VERSION }) });
        persistOk = !!created.ok;
      }
      const entry = db.elf.header.entry || db.functions[0]?.addr || db.space.ranges[0]?.vaddr || 0;
      history.current = { list: [entry], idx: 0 };
      patch({ db, assistant, loading: false, projectHash: hash, projectRestored: restored, aiObservations: observations, currentAddr: entry, libs: [{ name, hash, db, assistant, index: coord.aiIndex }], link: null });
      await openP;
      // checkpoint: functions snapshot + summary — only when the project DB exists (else skip silently, no 500 spam).
      if (persistOk) {
        const fns = db.functions.map((f) => ({ addr: f.addr, size: f.size, confidence: f.confidence, sources: f.sources, classes: (f.classes ?? []).slice(0, 2).map((c) => ({ ...c, evidence: c.evidence.slice(0, 3) })) }));
        const payload = { functions: fns };
        const json = JSON.stringify(payload);
        if (json.length < 40_000_000) await api.json(`/api/projects/${hash}/snapshot`, { method: "PUT", body: JSON.stringify({ stage: "functions", analysisVersion: ANALYSIS_VERSION, complete: true, payload }) });
        const comp = new Map<string, number>();
        for (const f of db.functions) for (const c of f.classes ?? []) if (c.confidence >= 0.5) comp.set(c.label, (comp.get(c.label) ?? 0) + 1);
        await api.json(`/api/projects/${hash}`, { method: "PATCH", body: JSON.stringify({ analysisState: "complete", analysisVersion: ANALYSIS_VERSION, summary: { ...db.stats(), components: Object.fromEntries(comp), timings: coord.timings } }) });
      }
      bump();
    } catch (e) {
      patch({ loading: false, error: e instanceof Error ? e.message : String(e) });
    }
  }, [bump, patch, state.coordinator, state.workerCount, state.computeMode, state.gpuLoad]);

  const openFile = useCallback(async (file: File | { name: string; bytes: Uint8Array }) => {
    if (file instanceof File) {
      const buf = await file.arrayBuffer();
      return openBytes(file.name, new Uint8Array(buf));
    }
    return openBytes(file.name, file.bytes);
  }, [openBytes]);

  const openSample = useCallback(async () => {
    const r = await fetch("/samples/libsample.so");
    const buf = await r.arrayBuffer();
    return openBytes("libsample.so", new Uint8Array(buf));
  }, [openBytes]);

  const openCompare = useCallback(async (file: File) => {
    const buf = new Uint8Array(await file.arrayBuffer());
    const coord = new AnalysisCoordinator();
    log("info", "compare", `Analyzing ${file.name} for comparison…`);
    try {
      const db = await coord.open(buf, file.name, { workers: state.workerCount || undefined, compute: { mode: state.computeMode, gpuLoad: state.gpuLoad, gpuMinBytes: 256 * 1024 } });
      patch({ compareBinary: { name: file.name, db }, centerTab: "compare" });
      log("info", "compare", `Comparison binary ready: ${db.functions.length} functions`);
    } catch (e) {
      log("error", "compare", String(e));
    }
  }, [log, patch, state.workerCount, state.computeMode, state.gpuLoad]);

  const navigate = useCallback((addr: number, opts?: { tab?: CenterTab; push?: boolean }) => {
    const h = history.current;
    if (opts?.push !== false && h.list[h.idx] !== addr) {
      h.list = h.list.slice(0, h.idx + 1);
      h.list.push(addr);
      if (h.list.length > 500) h.list.shift();
      h.idx = h.list.length - 1;
    }
    patch((s) => ({ currentAddr: addr, centerTab: opts?.tab ?? (s.centerTab === "overview" || s.centerTab === "search" || s.centerTab === "compare" ? "disasm" : s.centerTab), canBack: h.idx > 0, canForward: h.idx < h.list.length - 1 }));
  }, [patch]);
  const back = useCallback(() => { const h = history.current; if (h.idx > 0) { h.idx--; patch({ currentAddr: h.list[h.idx], canBack: h.idx > 0, canForward: true }); } }, [patch]);
  const forward = useCallback(() => { const h = history.current; if (h.idx < h.list.length - 1) { h.idx++; patch({ currentAddr: h.list[h.idx], canBack: true, canForward: h.idx < h.list.length - 1 }); } }, [patch]);

  const rename = useCallback((addr: number, name: string, origin: "user" | "ai-accepted" = "user") => {
    const db = state.db;
    if (!db) return;
    db.setUserName(addr, name, origin);
    persist(state.projectHash, name.trim() ? { type: "name", op: "set", address: addr, name: name.trim(), origin } : { type: "name", op: "delete", address: addr });
    bump();
  }, [bump, persist, state.db, state.projectHash]);

  const setComment = useCallback((addr: number, body: string, scope: "line" | "function" = "line") => {
    const db = state.db;
    if (!db) return;
    const map = scope === "function" ? db.functionComments : db.comments;
    if (body.trim()) map.set(addr, body.trim()); else map.delete(addr);
    persist(state.projectHash, { type: "comment", op: body.trim() ? "set" : "delete", address: addr, body, scope });
    bump();
  }, [bump, persist, state.db, state.projectHash]);

  const toggleBookmark = useCallback((addr: number, label?: string, kind: "address" | "function" | "string" | "data" = "address") => {
    const db = state.db;
    if (!db) return;
    if (db.bookmarks.has(addr) && label === undefined) {
      db.bookmarks.delete(addr);
      persist(state.projectHash, { type: "bookmark", op: "delete", address: addr });
    } else {
      const b = { address: addr, kind, label: label ?? db.labelFor(addr), note: db.bookmarks.get(addr)?.note ?? "" };
      db.bookmarks.set(addr, b);
      persist(state.projectHash, { type: "bookmark", op: "set", ...b });
    }
    bump();
  }, [bump, persist, state.db, state.projectHash]);

  const addTag = useCallback((addr: number, tag: string) => {
    const db = state.db;
    if (!db || !tag.trim()) return;
    const s = db.tags.get(addr) ?? new Set<string>();
    s.add(tag.trim());
    db.tags.set(addr, s);
    persist(state.projectHash, { type: "tag", op: "set", address: addr, tag: tag.trim() });
    bump();
  }, [bump, persist, state.db, state.projectHash]);
  const removeTag = useCallback((addr: number, tag: string) => {
    const db = state.db;
    if (!db) return;
    db.tags.get(addr)?.delete(tag);
    persist(state.projectHash, { type: "tag", op: "delete", address: addr, tag });
    bump();
  }, [bump, persist, state.db, state.projectHash]);

  const recordObservation = useCallback(async (o: Omit<AiObservation, "id" | "verdict">) => {
    const obs: AiObservation = { ...o, verdict: "pending" };
    if (state.projectHash) {
      const j = await api.json(`/api/projects/${state.projectHash}`, { method: "PUT", body: JSON.stringify({ type: "observation", op: "set", ...o }) });
      if (j.ok && j.observation) obs.id = j.observation.id;
    }
    patch((s) => ({ aiObservations: [...s.aiObservations, obs] }));
    return obs;
  }, [patch, state.projectHash]);

  const setVerdict = useCallback((o: AiObservation, verdict: "accepted" | "rejected") => {
    if (o.id && state.projectHash) persist(state.projectHash, { type: "observation", op: "verdict", id: o.id, verdict });
    patch((s) => ({ aiObservations: s.aiObservations.map((x) => (x === o || (x.id && x.id === o.id) ? { ...x, verdict } : x)) }));
  }, [patch, persist, state.projectHash]);

  const setWorkerCount = useCallback((n: number) => { localStorage.setItem("rw.workers", String(n)); patch({ workerCount: n }); }, [patch]);
  const setComputeMode = useCallback((m: "auto" | "cpu" | "gpu") => { localStorage.setItem("rw.compute", m); patch({ computeMode: m }); }, [patch]);
  const setGpuLoad = useCallback((n: number) => { const v = Math.min(1, Math.max(0.1, n)); localStorage.setItem("rw.gpuload", String(v)); patch({ gpuLoad: v }); }, [patch]);
  const reanalyze = useCallback(async () => { if (lastBytes.current) await openBytes(lastBytes.current.name, lastBytes.current.bytes); }, [openBytes]);

  const addLibrary = useCallback(async (file: File) => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const hash = await new CPUBackend().sha256(bytes);
    if (state.libs.some((l) => l.hash === hash)) { log("warning", "workspace", `${file.name} is already in the workspace`); return; }
    patch({ workspaceBusy: true });
    const coord = new AnalysisCoordinator();
    log("info", "workspace", `Analyzing ${file.name} for the workspace…`);
    try {
      const db = await coord.open(bytes, file.name, { workers: state.workerCount || undefined, compute: { mode: state.computeMode, gpuLoad: state.gpuLoad, gpuMinBytes: 256 * 1024 } });
      db.hash = hash;
      const lib: LoadedLib = { name: file.name, hash, db, assistant: new LocalAssistant(db, coord.aiIndex), index: coord.aiIndex };
      patch((s) => {
        const libs = s.libs.some((l) => l.hash === hash) ? s.libs : [...s.libs, lib];
        return { libs, link: libs.length > 1 ? linkLibraries(libs.map((l) => libDescriptor(l.db))) : null, workspaceBusy: false };
      });
      log("info", "workspace", `${file.name}: ${db.functions.length} functions, ${db.elf.exports.length} exports, ${db.elf.imports.length} imports — linked into the workspace`);
    } catch (e) {
      patch({ workspaceBusy: false });
      log("error", "workspace", `${file.name}: ${String(e)}`);
    }
  }, [log, patch, state.libs, state.workerCount, state.computeMode, state.gpuLoad]);

  const focusLibrary = useCallback((i: number) => {
    const lib = state.libs[i];
    if (!lib || lib.db === state.db) return;
    const entry = lib.db.elf.header.entry || lib.db.functions[0]?.addr || lib.db.space.ranges[0]?.vaddr || 0;
    history.current = { list: [entry], idx: 0 };
    patch({ db: lib.db, assistant: lib.assistant, fileName: lib.name, projectHash: lib.hash, currentAddr: entry, canBack: false, canForward: false, centerTab: "overview", rightTab: "info", leftTab: "functions" });
    log("info", "workspace", `Focused ${lib.name}`);
  }, [log, patch, state.libs, state.db]);

  const value = useMemo<WorkbenchApi>(() => ({
    ...state,
    openFile, openSample, openCompare, navigate, back, forward,
    setCenterTab: (t) => patch({ centerTab: t }),
    setLeftTab: (t) => patch({ leftTab: t }),
    setRightTab: (t) => patch({ rightTab: t }),
    setSelection: (s) => patch({ selection: s }),
    rename, setComment, toggleBookmark, addTag, removeTag, recordObservation, setVerdict, setWorkerCount, setComputeMode, setGpuLoad,
    setPaletteOpen: (b) => patch({ paletteOpen: b }),
    setGotoOpen: (b) => patch({ gotoOpen: b }),
    setSearchQuery: (q) => patch({ searchQuery: q }),
    setRenameTarget: (a) => patch({ renameTarget: a }),
    setCommentTarget: (a) => patch({ commentTarget: a }),
    askAI: (q) => patch({ activeQuestion: q, rightTab: "ai" }),
    clearActiveQuestion: () => patch({ activeQuestion: null }),
    addLibrary, focusLibrary,
    reanalyze, bump, log,
  }), [state, openFile, openSample, openCompare, navigate, back, forward, rename, setComment, toggleBookmark, addTag, removeTag, recordObservation, setVerdict, setWorkerCount, setComputeMode, setGpuLoad, addLibrary, focusLibrary, reanalyze, bump, log, patch]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const hex = (n: number | null | undefined, pad = 0) => (n === null || n === undefined ? "-" : "0x" + n.toString(16).padStart(pad, "0"));
export const fmtBytes = (n: number) => (n >= 1 << 30 ? (n / (1 << 30)).toFixed(2) + " GB" : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");
