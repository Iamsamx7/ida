"use client";
import React, { useMemo, useState } from "react";
import { useWorkbench, hex, fmtBytes } from "../store";
import { Badge, Progress, VirtualList, confidenceTone, Input, Button } from "../primitives";
import { COMPONENT_LABELS } from "@/core/analysis/semantic/rules";
import { buildIntel } from "@/core/analysis/intel";
import { planBypass, planWorkspace, type BypassPlan, type BypassProgress, type BypassStep, type WorkspacePlan } from "@/core/analysis/bypass";
import { libDescriptor } from "@/core/analysis/link";
import { emuSweep as emuSweepCount } from "@/core/analysis/intel";
import { analyzePasted, type VerifyReport } from "@/core/analysis/verify";
import { search, categoryCounts, type SearchCategory } from "@/core/search/engine";
import { extractFeatures, similarity } from "@/core/analysis/features";
import type { AnalysisDatabase } from "@/core/analysis/database";
import type { FunctionFeatures, FunctionRecord } from "@/core/analysis/types";

const Stat = ({ label, value, onClick }: { label: string; value: React.ReactNode; onClick?: () => void }) => (
  <button onClick={onClick} className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 text-left hover:border-zinc-600">
    <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
    <div className="mt-1 text-lg font-semibold text-zinc-100">{value}</div>
  </button>
);

/** Library overview dashboard — everything is clickable. */
export function OverviewView() {
  const wb = useWorkbench();
  const { db, stages, coordinator } = wb;
  const summary = useMemo(() => {
    if (!db) return null;
    const comp = new Map<string, number>();
    for (const f of db.functions) for (const c of f.classes ?? []) if (c.confidence >= 0.5) comp.set(c.label, (comp.get(c.label) ?? 0) + 1);
    const components = [...comp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14);
    const interesting: { label: string; addr: number; reason: string; tone: "amber" | "rose" | "sky" | "emerald" | "violet" | "cyan" }[] = [];
    const pick = (label: string, tone: "amber" | "rose" | "sky" | "emerald" | "violet" | "cyan", n = 3) => {
      const fns = db.functions.filter((f) => f.classes?.some((c) => c.label === label && c.confidence >= 0.4)).sort((a, b) => (b.classes![0].confidence) - (a.classes![0].confidence)).slice(0, n);
      for (const f of fns) interesting.push({ label: db.nameFor(f.addr).name, addr: f.addr, reason: label, tone });
    };
    pick("anticheat", "rose"); pick("ban-check", "rose", 2); pick("hash-check", "amber"); pick("integrity-check", "rose", 2); pick("game-revive", "emerald", 2); pick("networking", "sky", 2); pick("cryptography", "amber", 2); pick("jni-bridge", "sky", 2);
    const hot = [...db.functions].sort((a, b) => b.callerCount - a.callerCount).slice(0, 5);
    const strCats = new Map<string, number>();
    for (const s of db.strings) strCats.set(s.category, (strCats.get(s.category) ?? 0) + 1);
    let topImports: { name: string; users: number; library: string }[] = [];
    try { topImports = db.topImports(10); } catch { topImports = []; }
    const libMap = (() => { try { return db.libraryMap(); } catch { return []; } })();
    const intel = (() => { try { return buildIntel(db, 8); } catch { return null; } })();
    return { components, interesting, hot, strCats: [...strCats.entries()].sort((a, b) => b[1] - a[1]), topImports, libMap, intel };
  }, [db, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!db || !summary) return null;
  const st = db.stats();
  const h = db.elf.header;
  return (
    <div className="h-full overflow-auto p-5">
      <div className="mb-4 flex items-baseline gap-3">
        <h1 className="text-xl font-semibold text-zinc-100">{db.fileName}</h1>
        <span className="text-sm text-zinc-500">{db.elf.soname ?? ""}</span>
        {wb.projectRestored && <Badge tone="violet">project restored</Badge>}
        {db.elf.stripped && <Badge tone="amber">stripped</Badge>}
        <span className="ml-auto font-mono text-[11px] text-zinc-600">{db.hash ? `sha256 ${db.hash.slice(0, 20)}…` : ""}</span>
      </div>
      <div className="grid grid-cols-4 gap-3 lg:grid-cols-8">
        <Stat label="Architecture" value={<span className="text-base">{db.arch?.displayName ?? h.machineName}</span>} onClick={() => wb.setCenterTab("elf")} />
        <Stat label="Size" value={fmtBytes(db.bytes.length)} onClick={() => wb.setCenterTab("hex")} />
        <Stat label="Sections" value={st.sections} onClick={() => { wb.setLeftTab("sections"); wb.setCenterTab("elf"); }} />
        <Stat label="Functions" value={st.functions.toLocaleString()} onClick={() => wb.setLeftTab("functions")} />
        <Stat label="Strings" value={st.strings.toLocaleString()} onClick={() => wb.setLeftTab("strings")} />
        <Stat label="Imports" value={st.imports} onClick={() => wb.setLeftTab("imports")} />
        <Stat label="Exports" value={st.exports} onClick={() => wb.setLeftTab("exports")} />
        <Stat label="XREFs" value={st.xrefs.toLocaleString()} onClick={() => wb.setRightTab("xrefs")} />
      </div>
      <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
          <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Analysis</div>
          {stages.map((s) => (
            <div key={s.id} className="mb-2">
              <div className="flex justify-between text-[12px]"><span className={s.status === "complete" ? "text-zinc-300" : s.status === "running" ? "text-sky-300" : s.status === "error" ? "text-rose-400" : "text-zinc-500"}>{s.status === "complete" ? "✓ " : s.status === "running" ? "▸ " : s.status === "error" ? "✗ " : "· "}{s.label}</span><span className="text-zinc-500">{s.status === "complete" ? s.detail ?? "complete" : s.status === "running" ? `${Math.round(s.progress * 100)}%${s.detail ? " · " + s.detail : ""}` : s.status}</span></div>
              <Progress value={s.status === "complete" ? 1 : s.progress} className="mt-1" />
            </div>
          ))}
          {coordinator && <div className="mt-3 text-[11px] text-zinc-500">Overall {Math.round(coordinator.overallProgress * 100)}% · {db.insnTotal.toLocaleString()} instructions decoded{db.unknownTotal ? ` · ${db.unknownTotal.toLocaleString()} undecodable words` : ""}</div>}
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
          <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Detected components <span className="normal-case text-zinc-600">(functions with ≥50% classification — inference)</span></div>
          {summary.components.length === 0 && <div className="text-[12px] text-zinc-500">Semantic analysis pending…</div>}
          <div className="flex flex-wrap gap-1.5">
            {summary.components.map(([label, n]) => <Badge key={label} tone={COMPONENT_TONE[label] ?? "zinc"} onClick={() => { wb.setSearchQuery(`class:${label}`); wb.setCenterTab("search"); }}>{label} · {n}</Badge>)}
          </div>
          <div className="mt-4 mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">String categories</div>
          <div className="flex flex-wrap gap-1.5">{summary.strCats.slice(0, 10).map(([c, n]) => <Badge key={c} onClick={() => { wb.setLeftTab("strings"); wb.setSearchQuery(""); }}>{c} · {n}</Badge>)}</div>
          <div className="mt-4 mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Needed libraries</div>
          <div className="text-[12px] text-zinc-300">{db.elf.needed.join(", ") || "—"}</div>
          <div className="mt-2 space-y-1">
            {summary.libMap.slice(0, 6).map((g) => (
              <div key={g.library} className="text-[11px] text-zinc-500"><span className="text-zinc-300">{g.library}</span> · {g.imports.length} imports <span className="text-zinc-600">{g.imports.slice(0, 4).join(", ")}{g.imports.length > 4 ? "…" : ""}</span></div>
            ))}
          </div>
          <button onClick={() => wb.askAI("Which libraries does this use?")} className="mt-2 text-[11px] text-sky-400 hover:underline">Ask AI: full library map →</button>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
          <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Potentially interesting areas</div>
          {summary.interesting.length === 0 && <div className="text-[12px] text-zinc-500">Nothing flagged yet.</div>}
          {summary.interesting.map((i, k) => (
            <button key={k} onClick={() => wb.navigate(i.addr)} className="mb-1 flex w-full items-center gap-2 rounded px-2 py-1 text-left text-[12px] hover:bg-zinc-800">
              <Badge tone={i.tone}>{i.reason}</Badge><span className="font-mono text-zinc-200">{i.label}</span><span className="ml-auto font-mono text-zinc-600">{hex(i.addr)}</span>
            </button>
          ))}
          <div className="mt-4 mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Most referenced functions</div>
          {summary.hot.map((f) => (
            <button key={f.addr} onClick={() => wb.navigate(f.addr)} className="mb-1 flex w-full items-center gap-2 rounded px-2 py-1 text-left text-[12px] hover:bg-zinc-800">
              <span className="font-mono text-zinc-200">{db.nameFor(f.addr).name}</span><Badge tone="cyan">xref {f.callerCount}</Badge><span className="ml-auto font-mono text-zinc-600">{hex(f.addr)}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-rose-900/40 bg-rose-950/10 p-4">
          <div className="mb-3 flex items-center justify-between"><span className="text-[11px] font-semibold uppercase tracking-wider text-rose-300">Verified intel — auto-checked on load {summary.intel ? <span className="text-zinc-500">({summary.intel.findings.length} findings · {summary.intel.provenCount} proven)</span> : ""}</span><span className="flex gap-1">{[["anticheat", "where is anticheat?"], ["ban", "where are ban checks?"], ["hash", "where are hash checks?"]].map(([label, q]) => <button key={label} onClick={() => wb.askAI(q)} className="rounded border border-rose-900/60 px-1.5 py-0.5 text-[10px] text-rose-200 hover:bg-rose-900/30">{label}</button>)}</span></div>
          {!summary.intel && <div className="text-[12px] text-zinc-500">Intel stage still running…</div>}
          {summary.intel && !summary.intel.findings.length && <div className="text-[12px] text-zinc-500">No routine cleared the two-leg proof bar.{summary.intel.packedSuspect ? " Packed suspect — absence proves nothing." : ""}</div>}
          {summary.intel?.findings.slice(0, 6).map((f) => (
            <IntelCard key={`${f.addr}:${f.kind}`} f={f} />
          ))}
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
          <div className="mb-3 flex items-center justify-between"><span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Top API calls (memcpy / gettimeofday family, GOT-resolved)</span><button onClick={() => wb.askAI("Which libraries does this use?")} className="text-[10px] text-sky-400 hover:underline">library map →</button></div>
          {!summary.topImports.length && <div className="text-[12px] text-zinc-500">Import usage pending (semantic stage)…</div>}
          {summary.topImports.map((t) => (
            <button key={t.name} onClick={() => wb.askAI(`Where is ${t.name} used?`)} className="mb-1 flex w-full items-center gap-2 rounded px-2 py-1 text-left text-[12px] hover:bg-zinc-800" title={`Ask AI where ${t.name} is used`}>
              <span className="font-mono text-cyan-200">{t.name}</span><Badge>×{t.users}</Badge><span className="truncate text-zinc-500">{t.library}</span>
            </button>
          ))}
        </div>
      </div>
      <BypassPanel />
      <VerifyPanel />
      {db.elf.warnings.length > 0 && (
        <div className="mt-4 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[12px] text-amber-200">
          <div className="mb-1 font-semibold">Parser warnings ({db.elf.warnings.length})</div>
          {db.elf.warnings.slice(0, 8).map((w, i) => <div key={i}>• {w.message}</div>)}
        </div>
      )}
    </div>
  );
}

const COMPONENT_TONE: Record<string, "zinc" | "sky" | "emerald" | "amber" | "rose" | "violet" | "cyan"> = Object.fromEntries(COMPONENT_LABELS.map((l) => [l, l.includes("network") ? "sky" : l.includes("crypt") || l.includes("hash") ? "amber" : l.includes("integrity") || l.includes("error") ? "rose" : l.includes("render") || l.includes("input") ? "violet" : l.includes("state") ? "emerald" : l.includes("memory") || l.includes("string") ? "cyan" : "zinc"]));

function BypassPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [running, setRunning] = useState(false);
  const [prog, setProg] = useState<BypassProgress | null>(null);
  const [plan, setPlan] = useState<BypassPlan | null>(null);
  /** The planner's own PATCH_LIB / HOOK_LIB lines run back through the analyzer — a plan that fails its own autopsy is a bug, not a plan. */
  const [selfCheck, setSelfCheck] = useState<VerifyReport | null>(null);
  /** Hook-surface scope: auto (all), or any combination of .text / .got / .bss+.data. */
  const [scope, setScope] = useState({ auto: true, text: false, got: false, data: false });
  const [wsPlan, setWsPlan] = useState<WorkspacePlan | null>(null);
  const [wsRunning, setWsRunning] = useState(false);
  const [wsProg, setWsProg] = useState<BypassProgress | null>(null);
  const scopeOpts = () => (scope.auto ? {} : { scope: { text: scope.text, got: scope.got, data: scope.data } });
  const toggle = (k: "text" | "got" | "data") => setScope((s) => { const next = { ...s, auto: false, [k]: !s[k] }; if (!next.text && !next.got && !next.data) return { auto: true, text: false, got: false, data: false }; return next; });
  const run = async () => {
    if (running) return;
    setRunning(true);
    setPlan(null);
    setSelfCheck(null);
    setProg({ pass: "RESOLVE", passIndex: 1, passTotal: 7, progress: 0, note: "starting…" });
    try {
      const workspace = wb.libs.length > 1 && wb.link ? { workspace: { descriptors: wb.libs.map((l) => libDescriptor(l.db)), link: wb.link } } : {};
      const p = await planBypass(db, setProg, { ...workspace, ...scopeOpts() });
      setPlan(p);
      const lines = p.steps.flatMap((s) => [s.patchLib, ...(s.hookLib ? s.hookLib.split("\n").filter((l) => /^HOOK_LIB/.test(l)) : [])]).filter((l) => l && !l.startsWith("//"));
      setSelfCheck(lines.length ? analyzePasted(db, lines.join("\n")) : null);
    } finally {
      setRunning(false);
    }
  };
  const copyFrida = () => {
    if (!plan) return;
    const runnable = (s: BypassStep) => s.action === "hook-entry" || s.action === "spoof-props" || s.action === "patch-branch" || s.action === "patch-consumer";
    const active = plan.steps.filter((s) => s.safety === "SAFE" && runnable(s));
    const risky = plan.steps.filter((s) => s.safety === "RISKY" && runnable(s));
    const js = `// Safe-bypass plan for ${db.fileName} — LAB ONLY. Validate each hook on a clean trace first.\n// ${plan.coverage.covered}/${plan.coverage.findings} findings covered · ${active.length} SAFE step(s) armed · ${risky.length} RISKY step(s) below, commented out. Warnings:\n${plan.warnings.map((w) => `// - ${w}`).join("\n")}\n\n`
      + active.map((s) => s.frida).join("\n")
      + (risky.length ? `\n// ---- RISKY steps: read their safety notes in the plan first, then uncomment to arm ----\n` + risky.map((s) => s.frida.split("\n").map((l) => (l ? "// " + l : l)).join("\n")).join("\n") : "");
    void navigator.clipboard.writeText(js);
  };
  const copyPatchLib = () => {
    if (!plan) return;
    const lib = db.elf.soname ?? db.fileName;
    const lines = plan.steps.filter((s) => s.patchLib && !s.patchLib.startsWith("//")).map((s) => s.patchLib);
    const txt = `// ${lib} — paste into your mod menu (KittyMemory / LGL style).\n// ${plan.coverage.covered}/${plan.coverage.findings} findings covered. LAB ONLY — re-read bytes live before writing.\n// Warnings:\n${plan.warnings.map((w) => `// - ${w}`).join("\n")}\n\n` + lines.join("\n");
    void navigator.clipboard.writeText(txt);
  };
  const downloadJson = () => {
    if (!plan) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 1)], { type: "application/json" }));
    a.download = `${db.fileName}.bypass-plan.json`;
    a.click();
  };
  const runWorkspace = async () => {
    if (wsRunning || wb.libs.length < 2) return;
    setWsRunning(true);
    setWsPlan(null);
    setWsProg({ pass: "LIB 1", passIndex: 1, passTotal: wb.libs.length, progress: 0, note: "starting…" });
    try {
      const wp = await planWorkspace(wb.libs.map((l) => ({ name: l.name, db: l.db })), setWsProg, scopeOpts());
      setWsPlan(wp);
    } finally {
      setWsRunning(false);
    }
  };
  const focusByLib = (libName: string) => { const i = wb.libs.findIndex((l) => (l.db.elf.soname ?? l.name) === libName || l.name === libName); if (i >= 0) { wb.focusLibrary(i); } };
  const avgStrength = plan ? Math.round(plan.steps.reduce((a, x) => a + x.strength, 0) / Math.max(1, plan.steps.length)) : 0;
  const emu = (() => { try { return emuSweepCount(db); } catch { return null; } })();
  return (
    <div className="mt-4 rounded-lg border border-violet-900/50 bg-violet-950/10 p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-violet-300">Safe bypass plan — 7 passes, thinks out loud</span>
        {plan && <span className="text-[11px] text-zinc-500">{plan.coverage.covered}/{plan.coverage.findings} findings covered · {plan.coverage.proven} proven · {plan.coverage.branches} branch flips · {plan.coverage.consumers} caller traps · strength {avgStrength}/100 · {(plan.durationMs / 1000).toFixed(1)}s verification</span>}
        <span className="ml-auto flex gap-1">
          {plan && <><Button onClick={copyPatchLib}>Copy PATCH_LIB</Button><Button onClick={copyFrida}>Copy Frida JS</Button><Button onClick={downloadJson}>Download JSON</Button></>}
          {wb.libs.length > 1 && <Button tone={wsRunning ? undefined : "emerald"} onClick={runWorkspace} disabled={wsRunning || running}>{wsRunning ? "Planning all…" : `Plan all ${wb.libs.length} libraries`}</Button>}
          <Button tone={running ? undefined : "sky"} onClick={run} disabled={running || wsRunning}>{running ? "Verifying…" : plan ? "Re-run full verification" : "Generate full safe bypass plan"}</Button>
        </span>
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[11px]">
        <span className="uppercase tracking-wider text-zinc-500">Hook surface</span>
        <button onClick={() => setScope({ auto: true, text: false, got: false, data: false })} className={`rounded-full border px-2 py-0.5 ${scope.auto ? "border-sky-600 bg-sky-950/40 text-white" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>Auto</button>
        {(["text", "got", "data"] as const).map((k) => (
          <button key={k} onClick={() => toggle(k)} className={`rounded-full border px-2 py-0.5 ${!scope.auto && scope[k] ? "border-sky-600 bg-sky-950/40 text-white" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>{k === "text" ? ".text (code)" : k === "got" ? ".got (imports)" : ".bss/.data (globals)"}</button>
        ))}
        <span className="text-zinc-600">{scope.auto ? "all surfaces — code hooks, GOT redirects and global flags" : "generate only the selected surface(s); re-run to apply"}</span>
      </div>
      <div className="mb-2 text-[11px] text-zinc-500">7 passes over every function — resolve → exact branches → caller traps → safety (blast-radius, heartbeat timers, self-inspection tripwires) → redundancy + clone sweep → order → review. Every step shows its reasoning and a strength score. Lab-only: validate each step on a clean trace with a test account. Server-side verdicts can&apos;t be beaten client-side; tampering risks a ban and may violate the game&apos;s ToS.</div>
      {emu && (
        <div className="mb-2 rounded border border-zinc-800 bg-zinc-950/50 px-2 py-1 text-[11px] text-zinc-400">
          Emulator sweep: <span className="font-mono text-zinc-200">{emu.markers} tell(s)</span> in strings · <span className="font-mono text-zinc-200">{emu.propReaders}</span> classified prop/file reader(s) · {emu.anticheatFindings} anticheat finding(s)
          {emu.markers === 0 && <span className="text-zinc-500"> — no emulator tells in this .so; checks likely live in dex/Java or server-side</span>}
          {!!emu.sample.length && <span className="text-zinc-600"> · e.g. {emu.sample.slice(0, 3).join(", ")}</span>}
        </div>
      )}
      {wsRunning && wsProg && (
        <div className="mb-2">
          <div className="flex justify-between text-[11px]"><span className="text-violet-200">Workspace {wsProg.passIndex}/{wsProg.passTotal} · {wsProg.pass}</span><span className="text-zinc-500">{wsProg.note}</span></div>
          <Progress value={(wsProg.passIndex - 1 + wsProg.progress) / Math.max(1, wsProg.passTotal)} className="mt-1" />
        </div>
      )}
      {wsPlan && (
        <div className="mb-3 rounded-lg border border-violet-800/60 bg-violet-950/20 p-3 text-[11px]">
          <div className="mb-1 flex items-center gap-2"><span className="text-[12px] font-semibold uppercase tracking-wider text-violet-200">Unified plan — all {wsPlan.summary.libs} libraries</span><span className="text-zinc-500">{wsPlan.summary.steps} steps ({wsPlan.summary.safeSteps} SAFE) · {wsPlan.summary.chains} cross-lib chain(s) · {wsPlan.summary.mrpc} MRPC · {(wsPlan.durationMs / 1000).toFixed(1)}s</span><button onClick={() => setWsPlan(null)} className="ml-auto text-zinc-500 hover:text-zinc-200">✕</button></div>
          <div className="mb-2 flex flex-wrap gap-1">{wsPlan.perLib.map((l) => <button key={l.soname} onClick={() => focusByLib(l.soname)} className={`rounded border px-1.5 py-0.5 font-mono ${(db.elf.soname ?? db.fileName) === l.soname ? "border-sky-600 bg-sky-950/40 text-white" : "border-zinc-700 text-zinc-300 hover:border-violet-500"}`}>{l.soname} <span className="text-zinc-500">{l.plan.steps.length}st{l.plan.mrpc.count ? ` · ${l.plan.mrpc.count}rule` : ""}{l.plan.crossLib?.securityResolvedElsewhere.length ? ` · ${l.plan.crossLib.securityResolvedElsewhere.length}→sib` : ""}</span></button>)}</div>
          <div className="mb-1 font-semibold uppercase tracking-wider text-zinc-400">Cross-lib strike chains ({wsPlan.chains.length})</div>
          {!wsPlan.chains.length && <div className="text-zinc-500">No cross-lib chains — these libraries don&apos;t call each other&apos;s security symbols (independent modules). Each lib&apos;s own steps stand alone.</div>}
          <div className="space-y-1">
            {wsPlan.chains.slice(0, 40).map((c, i) => (
              <div key={i} className="rounded border border-zinc-800 bg-black/20 p-1.5">
                <div className="flex items-center gap-2"><Badge tone={c.hasProviderStep ? "emerald" : "amber"}>{c.symbol}</Badge>{c.steps.map((s, j) => <React.Fragment key={j}>{j > 0 && <span className="text-zinc-600">→</span>}<button onClick={() => { focusByLib(s.lib); if (s.addr) wb.navigate(s.addr); }} className="rounded border border-zinc-700 px-1 font-mono text-zinc-200 hover:border-violet-500"><span className={s.role === "provider" ? "text-emerald-300" : "text-sky-300"}>{s.role}</span> {s.lib.replace(/\.so$/, "")}@{hex(s.addr)}</button></React.Fragment>)}</div>
                <div className="mt-0.5 text-zinc-400">{c.reason}</div>
              </div>
            ))}
          </div>
          <div className="mt-2 mb-1 font-semibold uppercase tracking-wider text-zinc-400">Apply order (siblings first) — {wsPlan.order.length} steps</div>
          <ol className="ml-4 list-decimal space-y-0.5 text-zinc-300">{wsPlan.order.slice(0, 20).map((o, i) => <li key={i}><button onClick={() => { focusByLib(o.lib); if (o.addr) wb.navigate(o.addr); }} className="text-left hover:text-white"><span className="font-mono text-zinc-500">{o.lib.replace(/\.so$/, "")}</span> · {o.title}</button></li>)}{wsPlan.order.length > 20 && <li className="list-none text-zinc-600">…+{wsPlan.order.length - 20} more</li>}</ol>
        </div>
      )}
      {running && prog && (
        <div className="mb-2">
          <div className="flex justify-between text-[11px]"><span className="text-violet-200">Pass {prog.passIndex}/{prog.passTotal} · {prog.pass}</span><span className="text-zinc-500">{Math.round(prog.progress * 100)}% · {prog.note}</span></div>
          <Progress value={(prog.passIndex - 1 + prog.progress) / prog.passTotal} className="mt-1" />
          {prog.thought && <div className="mt-1 border-l-2 border-violet-800 pl-2 text-[11px] italic text-zinc-400">{prog.thought}</div>}
        </div>
      )}
      {plan && (
        <>
          {plan.warnings.map((w, i) => <div key={i} className="mb-1 rounded border border-amber-900/50 bg-amber-950/20 px-2 py-1 text-[11px] text-amber-200">⚠ {w}</div>)}
          {selfCheck && (() => {
            const n = (st: string) => selfCheck.items.filter((v) => v.status === st).length;
            const unsafe = selfCheck.items.filter((v) => v.status === "UNSAFE");
            return (
              <div className={`mb-1 rounded border px-2 py-1 text-[11px] ${unsafe.length ? "border-rose-900/60 bg-rose-950/20 text-rose-200" : "border-emerald-900/50 bg-emerald-950/20 text-emerald-200"}`}>
                Self-check — the plan&apos;s own {selfCheck.items.length} PATCH/HOOK line(s) through the analyzer: {n("SAFE")} SAFE · {n("RISKY")} RISKY · {n("UNSAFE")} UNSAFE{unsafe.length ? " — a plan that fails its own autopsy is a planner bug; do not apply these:" : " (RISKY here = hook+patch alternatives on one entry, expected)"}
                {unsafe.map((v, i) => <div key={i} className="mt-0.5 font-mono text-[10.5px]">{v.item.raw.slice(0, 90)} — {v.checks.filter((c) => !c.pass).map((c) => c.detail.slice(0, 90)).join(" | ")}</div>)}
              </div>
            );
          })()}
          {plan.emulator && (
            <div className="mb-2 rounded border border-cyan-900/50 bg-cyan-950/10 px-2 py-1.5 text-[11px]">
              <div className="mb-0.5 flex items-center gap-2 font-semibold uppercase tracking-wider text-cyan-300">Emulator — how this .so relates to emulator detection <span className="font-mono normal-case tracking-normal text-zinc-500">{plan.emulator.markers} tell(s) · {plan.emulator.readers.length} native reader(s) · {plan.emulator.consumers.length} verdict consumer(s) · {plan.emulator.spoofSteps} spoof · {plan.emulator.consumerSteps} consumer step(s)</span></div>
              <div className="text-zinc-300">{plan.emulator.verdict}</div>
              {!!plan.emulator.consumers.length && <div className="mt-1 flex flex-wrap gap-1">{plan.emulator.consumers.map((c) => <button key={c.addr} onClick={() => wb.navigate(c.addr)} title={c.strings.join(" · ")} className="rounded border border-cyan-900/60 bg-cyan-950/30 px-1.5 font-mono text-cyan-200 hover:border-cyan-500">{c.name} <span className="text-zinc-500">{hex(c.addr)}</span></button>)}</div>}
              {!!plan.emulator.readers.length && <div className="mt-1 flex flex-wrap gap-1"><span className="text-zinc-500">native readers:</span>{plan.emulator.readers.map((f) => <button key={f.addr} onClick={() => wb.navigate(f.addr)} className="rounded border border-zinc-700 px-1.5 font-mono text-zinc-200 hover:border-cyan-500">{f.name}</button>)}</div>}
            </div>
          )}
          {plan.deobf && !!plan.deobf.count && (() => {
            const deobfSteps = plan.steps.filter((s) => s.identity.startsWith("deobf ·"));
            return (
              <div className="mb-2 rounded border border-fuchsia-900/60 bg-fuchsia-950/15 px-2 py-1.5 text-[11px]">
                <div className="mb-0.5 flex items-center gap-2 font-semibold uppercase tracking-wider text-fuchsia-300">Obfuscation — XOR / string decryptors <span className="font-mono normal-case tracking-normal text-zinc-500">{plan.deobf.count} routine(s) · {deobfSteps.length} hook/patch step(s) · the hidden (no-string) engine lives here or in their callers</span></div>
                <div className="mb-1 text-zinc-300">{plan.deobf.note}</div>
                {/* Same expandable hook/patch rows as every finding — the hook DUMPS the plaintext, the patch is flagged as decryption-breaking. */}
                {deobfSteps.map((s) => <BypassStepRow key={s.id} s={s} plan={plan} />)}
              </div>
            );
          })()}
          {plan.mrpc && (() => {
            const mrpcSteps = plan.steps.filter((s) => s.identity.startsWith("mrpc ·"));
            const leadCount = plan.mrpc.findings.filter((f) => f.proofLevel === "lead").length;
            return (
              <div className={`mb-2 rounded border px-2 py-1.5 text-[11px] ${plan.mrpc.count ? "border-amber-900/60 bg-amber-950/15" : "border-zinc-800 bg-zinc-950/40"}`}>
                <div className="mb-0.5 flex items-center gap-2 font-semibold uppercase tracking-wider text-amber-300">MRPC — downloaded-rule engine (tick out the rules) <span className="font-mono normal-case tracking-normal text-zinc-500">{plan.mrpc.count} routine(s){plan.mrpc.count ? ` · ${plan.mrpc.networkBacked ? "server-fed" : "bundled config"} · ${mrpcSteps.length} hook/patch step(s)` : ""}</span></div>
                <div className="mb-1 text-zinc-300">{plan.mrpc.verdict}</div>
                {/* Same expandable step rows as every other finding — click for reason, requires, hook + patch. */}
                {mrpcSteps.map((s) => <BypassStepRow key={s.id} s={s} plan={plan} />)}
                {!!leadCount && <div className="mt-1 text-zinc-500">{leadCount} of these are LEAD-level (survived on a specific mrpcs/rule string but thin evidence — obfuscated code). Hook + patch are provided, but break on them live to confirm before trusting.</div>}
              </div>
            );
          })()}
          {plan.crossLib && (
            <div className="mb-2 rounded border border-indigo-900/50 bg-indigo-950/15 px-2 py-1.5 text-[11px]">
              <div className="mb-0.5 flex items-center gap-2 font-semibold uppercase tracking-wider text-indigo-300">Cross-library — how {plan.crossLib.self} links to the workspace</div>
              <div className="text-zinc-300">{plan.crossLib.note}</div>
              {!!plan.crossLib.securityResolvedElsewhere.length && (
                <div className="mt-1"><span className="text-rose-300">Security logic elsewhere:</span>{" "}
                  {plan.crossLib.securityResolvedElsewhere.slice(0, 12).map((r, i) => <span key={i} className="mr-2 font-mono text-zinc-300">{r.symbol}<span className="text-zinc-500">→{r.lib}</span></span>)}
                </div>
              )}
              <div className="mt-1 flex flex-wrap gap-2">
                {!!plan.crossLib.dependsOn.length && <span className="text-zinc-500">depends on: {plan.crossLib.dependsOn.map((x) => `${x.lib} (${x.via.join("/")}${x.symbols ? `,${x.symbols}` : ""})`).join(", ")}</span>}
                {!!plan.crossLib.dependedBy.length && <span className="text-zinc-500">used by: {plan.crossLib.dependedBy.map((x) => `${x.lib} (${x.via.join("/")})`).join(", ")}</span>}
              </div>
              {!!plan.crossLib.sharedDetections.length && <div className="mt-1 text-zinc-600">shared detections: {plan.crossLib.sharedDetections.slice(0, 6).map((s) => `"${s.value}" [${s.libs.length}]`).join(", ")}</div>}
            </div>
          )}
          <PlanThinking thinking={plan.thinking} />
          {!plan.steps.length && <div className="text-[12px] text-zinc-500">No actionable steps — nothing cleared the proof bar, or everything was vetoed. That itself is a result: don&apos;t patch blind.</div>}
          {plan.steps.filter((s) => !s.identity.startsWith("mrpc ·") && !s.identity.startsWith("deobf ·")).map((s) => <BypassStepRow key={s.id} s={s} plan={plan} />)}
          {!!plan.blocked.length && <div className="mt-2 text-[11px] text-zinc-500">Blocked: {plan.blocked.map((b) => `${b.target} (${b.reason.slice(0, 60)}…)`).join(" · ")}</div>}
        </>
      )}
    </div>
  );
}

function VerifyPanel() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [text, setText] = useState(`PATCH_LIB("${db.elf.soname ?? db.fileName}","0x0","00 00 80 D2 C0 03 5F D6");`);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const run = () => setReport(analyzePasted(db, text));
  const copyFixed = () => {
    if (!report) return;
    const lines = report.items.map((v) => v.fixedLine ?? v.item.raw);
    void navigator.clipboard.writeText(`// Autopsy-fixed set for ${db.fileName} — LAB ONLY, re-read bytes live before writing.\n` + lines.join("\n"));
  };
  const tone = report?.overall === "SAFE" ? "emerald" : report?.overall === "RISKY" ? "amber" : report?.overall === "UNSAFE" ? "rose" : "zinc";
  return (
    <div className="mt-4 rounded-lg border border-cyan-900/50 bg-cyan-950/10 p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-300">Patch / hook analyzer — paste yours, get an autopsy</span>
        {report && <Badge tone={tone}>{report.overall}</Badge>}
        <span className="ml-auto flex gap-1">
          {report && report.items.some((v) => v.fixedLine) && <Button onClick={copyFixed}>Copy fixed set</Button>}
          <Button tone="sky" onClick={run}>Analyze safety</Button>
        </span>
      </div>
      <div className="mb-2 text-[11px] text-zinc-500">Paste PATCH_LIB / HOOK_LIB lines (or <span className="font-mono">0xOFFSET bytes</span>). It resolves each line against the loaded binary — library, mapping, function, encoding, blast radius, heartbeats, tripwires, surviving siblings — and tells you how to make it safe.</div>
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3} spellCheck={false} placeholder='PATCH_LIB("lib.so","0x1D3AE4","00 00 80 D2 C0 03 5F D6");' className="w-full rounded border border-zinc-700 bg-zinc-950 p-2 font-mono text-[11.5px] text-zinc-100 outline-none focus:border-cyan-600" />
      {report && (
        <div className="mt-2">
          {report.warnings.map((w, i) => <div key={i} className="mb-1 rounded border border-amber-900/50 bg-amber-950/20 px-2 py-1 text-[11px] text-amber-200">⚠ {w}</div>)}
          {!report.items.length && <div className="text-[12px] text-zinc-500">Nothing parsed — check the format hint above.</div>}
          {report.items.map((v, i) => <VerifyRow key={i} v={v} />)}
        </div>
      )}
    </div>
  );
}

function VerifyRow({ v }: { v: VerifyReport["items"][number] }) {
  const wb = useWorkbench();
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-1.5 rounded border border-zinc-800 bg-zinc-950/50">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-[12px] hover:bg-zinc-800/40">
        <span>{open ? "▾" : "▸"}</span>
        <Badge tone={v.status === "SAFE" ? "emerald" : v.status === "RISKY" ? "amber" : "rose"}>{v.status}</Badge>
        <Badge tone="cyan">{v.item.kind}</Badge>
        <span className="truncate font-mono text-zinc-200">{v.item.raw.slice(0, 90)}</span>
        {v.funcName && <span className="ml-auto shrink-0 font-mono text-[11px] text-zinc-400">{v.funcName}{v.funcKind ? ` [${v.funcKind}]` : ""}</span>}
      </button>
      {open && (
        <div className="space-y-1 border-t border-zinc-800 px-2 py-2 text-[11px]">
          {v.addr !== null && v.funcName && <div><Button onClick={() => wb.navigate(v.addr!)}>Go to {v.funcName}</Button></div>}
          {v.checks.map((c, i) => <div key={i} className="flex gap-2"><span className={`w-4 shrink-0 font-mono ${c.pass ? "text-emerald-400" : "text-rose-400"}`}>{c.pass ? "✓" : "✗"}</span><span className="w-24 shrink-0 uppercase tracking-wider text-zinc-500">{c.label}</span><span className="text-zinc-300">{c.detail}</span></div>)}
          {!!v.fixes.length && <div className="rounded border border-emerald-900/50 bg-emerald-950/20 p-2"><div className="mb-1 font-semibold uppercase tracking-wider text-emerald-300">To make it safe</div>{v.fixes.map((f, i) => <div key={i} className="text-zinc-200">• {f}</div>)}</div>}
          {v.fixedLine && <div><div className="mb-1 font-semibold uppercase tracking-wider text-amber-300">Corrected line</div><pre className="overflow-auto rounded bg-black/40 p-2 font-mono text-[10.5px] text-amber-200">{v.fixedLine}</pre><Button onClick={() => void navigator.clipboard.writeText(v.fixedLine!)}>Copy corrected line</Button></div>}
        </div>
      )}
    </div>
  );
}

function PlanThinking({ thinking }: { thinking: string[] }) {  const [open, setOpen] = useState(false);
  if (!thinking.length) return null;
  return (
    <div className="mb-2 rounded border border-zinc-800 bg-zinc-950/60">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 px-2 py-1 text-left text-[11px] text-zinc-400 hover:text-zinc-200">
        <span>{open ? "▾" : "▸"}</span><span className="font-semibold uppercase tracking-wider">Planner thinking — why it decided what it did</span>
        <span className="ml-auto font-mono text-[10px] text-zinc-500">{thinking.length} notes</span>
      </button>
      {open && <div className="space-y-1 border-t border-zinc-800 px-2 py-1">{thinking.map((t, i) => <div key={i} className="border-l-2 border-violet-900 pl-2 text-[11px] italic text-zinc-400">{t}</div>)}</div>}
    </div>
  );
}

function BypassStepRow({ s, plan }: { s: BypassStep; plan: BypassPlan }) {
  const wb = useWorkbench();
  const [open, setOpen] = useState(false);
  const actionTone = s.action === "patch-branch" ? "amber" : s.action === "patch-consumer" ? "rose" : s.action === "spoof-props" ? "cyan" : "violet";
  const kindTone = s.kind === "ban-check" || s.kind === "anticheat" ? "rose" : s.kind === "hash-check" ? "amber" : s.kind === "game-revive" ? "emerald" : "zinc";
  return (
    <div className="mb-1.5 rounded border border-zinc-800 bg-zinc-950/50">
      <button onClick={() => setOpen(!open)} className="w-full px-2 py-1.5 text-left hover:bg-zinc-800/40">
        <span className="flex items-center gap-2 text-[12px]">
          <span>{open ? "▾" : "▸"}</span>
          <Badge tone={s.safety === "SAFE" ? "emerald" : s.safety === "RISKY" ? "amber" : "rose"}>{s.safety}</Badge>
          <Badge tone={actionTone}>{s.action}</Badge>
          {s.section && <Badge tone={s.section.includes("got") ? "sky" : /\.(bss|data)/.test(s.section) ? "violet" : "zinc"} title="Hook surface">{s.section}</Badge>}
          <Badge tone={kindTone}>{s.kind}</Badge>
          <span className="font-mono text-zinc-100">{s.targetName}</span>
          <span className="font-mono text-zinc-600">{hex(s.address)}</span>
          <span className="ml-auto font-mono text-[10px] text-zinc-500" title="Strength: proof legs + precision + corroboration">◈ {s.strength}</span>
          {s.requires.length > 0 && <span className="text-[10px] text-amber-400">+{s.requires.length} required</span>}
        </span>
        <span className="mt-0.5 flex flex-wrap items-center gap-1 pl-5 text-[10.5px]">
          <span className="text-zinc-500">{s.identity}</span>
          {s.imports.slice(0, 4).map((n) => (
            <span key={n} onClick={(e) => { e.stopPropagation(); wb.askAI(`Where is ${n} used?`); }} title={`Ask AI where ${n} is used`} className="cursor-pointer rounded border border-cyan-900/60 bg-cyan-950/30 px-1 font-mono text-cyan-300 hover:border-cyan-600">{n}</span>
          ))}
          {s.imports.length > 4 && <span className="text-zinc-600">+{s.imports.length - 4}</span>}
        </span>
      </button>
      {open && (
        <div className="space-y-1 border-t border-zinc-800 px-2 py-2 text-[11px]">
          <div className="text-zinc-300">{s.detail}</div>
          <div><span className="font-semibold uppercase tracking-wider text-violet-400">Why this step: </span></div>
          {s.reasoning.map((r, i) => <div key={i} className="border-l-2 border-violet-900 pl-2 italic text-zinc-400">{r}</div>)}
          <div><span className="font-semibold uppercase tracking-wider text-zinc-500">Safety: </span><span className="text-zinc-300">{s.safetyReasons.join(" ")}</span></div>
          {!!s.requires.length && <div><span className="font-semibold uppercase tracking-wider text-amber-400">Must also apply: </span><span className="text-zinc-300">{s.requires.join(" · ")}</span></div>}
          <div><span className="font-semibold uppercase tracking-wider text-zinc-500">Runtime checks: </span><span className="text-zinc-300">{s.runtimeChecks.join(" ")}</span></div>
          {!!s.patchLib && (
            <div>
              <div className="mb-1 flex items-center gap-1"><span className="font-semibold uppercase tracking-wider text-amber-400">PATCH_LIB: </span><Button onClick={() => void navigator.clipboard.writeText(s.patchLib)}>Copy line</Button><span className="text-zinc-600">orig: {s.origBytes || "—"}</span></div>
              <pre className="overflow-auto rounded bg-black/40 p-2 font-mono text-[10.5px] text-amber-200">{s.patchLib}</pre>
              {s.patchLibAlt && <pre className="mt-1 overflow-auto rounded bg-black/30 p-2 font-mono text-[10.5px] text-amber-200/70" title="Same patch returning 1 — for checks whose clean value is nonzero">{s.patchLibAlt}</pre>}
            </div>
          )}
          {!!s.hookLib && (
            <div>
              <div className="mb-1 flex items-center gap-1"><span className="font-semibold uppercase tracking-wider text-cyan-400">HOOK_LIB: </span><Button onClick={() => void navigator.clipboard.writeText(s.hookLib)}>Copy block</Button></div>
              <pre className="overflow-auto rounded bg-black/40 p-2 font-mono text-[10.5px] text-cyan-200">{s.hookLib}</pre>
            </div>
          )}
          <pre className="overflow-auto rounded bg-black/40 p-2 font-mono text-[10.5px] text-emerald-200">{s.frida}{s.patchHex ? `\n// patch bytes: ${s.patchHex}` : ""}</pre>
          <div className="flex gap-1">
            <Button onClick={() => wb.navigate(s.address)}>Go to function</Button>
            <Button onClick={() => void navigator.clipboard.writeText(s.frida)}>Copy snippet</Button>
          </div>
        </div>
      )}
    </div>
  );
}

function IntelCard({ f }: { f: import("@/core/analysis/intel").IntelFinding }) {
  const wb = useWorkbench();
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-2 rounded border border-zinc-800 bg-zinc-950/50">
      <button onClick={() => wb.navigate(f.addr)} className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-[12px] hover:bg-zinc-800/50" title="Go to function">
        <Badge tone={f.proofLevel === "proven" ? "emerald" : f.proofLevel === "corroborated" ? "sky" : "amber"}>{f.proofLevel}</Badge>
        <Badge tone={f.kind === "ban-check" || f.kind === "anticheat" ? "rose" : f.kind === "hash-check" ? "amber" : "emerald"}>{f.kind}</Badge>
        <span className="font-mono text-zinc-100">{f.name}</span>
        <span className="font-mono text-zinc-600">{hex(f.addr)}</span>
        <span className="ml-auto text-[10px] text-zinc-500">{Math.round(f.confidence * 100)}%</span>
      </button>
      <div className="px-2 pb-1 text-[11px] text-zinc-400">{f.whatItIs.split(".")[0]}.</div>
      <div className="flex gap-1 px-2 pb-2">
        <button onClick={() => setOpen(!open)} className="text-[10px] text-sky-400 hover:underline">{open ? "hide full chain ▾" : "what it does · connections · hook/patch ▸"}</button>
        <button onClick={() => wb.askAI(`What does ${f.name} do?`)} className="ml-auto text-[10px] text-zinc-500 hover:text-zinc-200">ask AI →</button>
      </div>
      {open && (
        <div className="space-y-1 border-t border-zinc-800 px-2 py-2 text-[11px]">
          <div><span className="font-semibold uppercase tracking-wider text-zinc-500">Does: </span><span className="text-zinc-300">{f.whatItDoes}</span></div>
          <div><span className="font-semibold uppercase tracking-wider text-zinc-500">Connected: </span><span className="text-zinc-300">{f.connectedTo.slice(0, 4).map((c) => `[${c.role}] ${c.name}`).join(" · ") || "isolated"}</span></div>
          <div><span className="font-semibold uppercase tracking-wider text-emerald-500">Hook: </span><span className="text-zinc-300">{f.hookImpact}</span></div>
          <div><span className="font-semibold uppercase tracking-wider text-amber-500">Patch: </span><span className="text-zinc-300">{f.patchImpact}</span></div>
        </div>
      )}
    </div>
  );
}

type ElfTabId = "header" | "segments" | "sections" | "dynamic" | "relocs" | "symbols" | "hash";
const ElfRow = ({ cells, onClick, mono = true }: { cells: React.ReactNode[]; onClick?: () => void; mono?: boolean }) => (
  <div onClick={onClick} className={`grid gap-2 border-b border-zinc-900 px-3 py-[3px] text-[12px] ${mono ? "font-mono" : ""} ${onClick ? "cursor-pointer hover:bg-zinc-800/50" : ""}`} style={{ gridTemplateColumns: `repeat(${cells.length}, minmax(0, 1fr))` }}>{cells.map((c, i) => <span key={i} className="truncate text-zinc-300">{c}</span>)}</div>
);
const ElfHead = ({ cols }: { cols: string[] }) => <div className="grid gap-2 border-b border-zinc-800 bg-zinc-900/60 px-3 py-1 text-[10px] uppercase tracking-wider text-zinc-500" style={{ gridTemplateColumns: `repeat(${cols.length}, minmax(0, 1fr))` }}>{cols.map((c) => <span key={c}>{c}</span>)}</div>;

/** ELF structure view: header, segments, sections, dynamic, relocations, symbol tables. */
export function ElfView() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [tab, setTab] = useState<ElfTabId>("sections");
  const e = db.elf;
  const h = e.header;
  const tabs: [ElfTabId, string][] = [["header", "Header"], ["segments", `Segments (${e.segments.length})`], ["sections", `Sections (${e.sections.length})`], ["dynamic", `Dynamic (${e.dynamic.length})`], ["relocs", `Relocations (${e.relocations.length})`], ["symbols", `Symbols (${e.symbols.length})`], ["hash", "Hash / Versions / TLS"]];
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 items-center border-b border-zinc-800 px-2">
        {tabs.map(([id, label]) => <button key={id} onClick={() => setTab(id)} className={`px-3 py-1 text-[11px] ${tab === id ? "border-b-2 border-sky-500 text-white" : "text-zinc-400 hover:text-zinc-200"}`}>{label}</button>)}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {tab === "header" && (
          <div className="grid grid-cols-2 gap-x-8 p-4 font-mono text-[12px] lg:grid-cols-3">
            {[["Class", `ELF${h.elfClass}`], ["Data", h.littleEndian ? "little-endian" : "big-endian"], ["OS/ABI", String(h.osabi)], ["Type", h.typeName], ["Machine", `${h.machineName} (${h.machine})`], ["Entry point", hex(h.entry)], ["Flags", hex(h.flags)], ["Program headers", `${h.phnum} × ${h.phentsize} @ ${hex(h.phoff)}`], ["Section headers", `${h.shnum} × ${h.shentsize} @ ${hex(h.shoff)}`], ["shstrndx", String(h.shstrndx)], ["Image base", hex(db.space.imageBase)], ["File size", `${db.bytes.length.toLocaleString()} bytes`], ["SONAME", e.soname ?? "—"], ["Stripped", e.stripped ? "yes (no .symtab)" : "no"], ["Init array", `${e.initArray.length} entries`], ["Fini array", `${e.finiArray.length} entries`]].map(([k, v]) => (
              <div key={k} className="flex justify-between border-b border-zinc-900 py-1"><span className="text-zinc-500">{k}</span><span className="text-zinc-200">{v}</span></div>
            ))}
            {e.initArray.length > 0 && <div className="col-span-full mt-3"><div className="mb-1 text-zinc-500">init_array</div>{e.initArray.slice(0, 50).map((a, i) => <button key={i} onClick={() => wb.navigate(a)} className="mr-2 text-sky-300 hover:underline">{db.labelFor(a)}</button>)}</div>}
          </div>
        )}
        {tab === "segments" && (<><ElfHead cols={["#", "Type", "Perms", "Offset", "VAddr", "FileSz", "MemSz", "Align"]} />{e.segments.map((s) => <ElfRow key={s.index} cells={[s.index, s.typeName, s.perms, hex(s.offset), hex(s.vaddr), hex(s.filesz), hex(s.memsz), hex(s.align)]} onClick={() => s.type === 1 && wb.navigate(s.vaddr, { tab: "hex" })} />)}</>)}
        {tab === "sections" && (<><ElfHead cols={["#", "Name", "Type", "Flags", "Addr", "Offset", "Size", "Align", "Entsize"]} />{e.sections.map((s) => <ElfRow key={s.index} cells={[s.index, s.name, s.typeName, s.flagStr, hex(s.addr), hex(s.offset), hex(s.size), String(s.addralign), String(s.entsize)]} onClick={() => s.addr && wb.navigate(s.addr, { tab: s.exec ? "disasm" : "hex" })} />)}</>)}
        {tab === "dynamic" && (<><ElfHead cols={["Tag", "Value", "Text"]} />{e.dynamic.map((d, i) => <ElfRow key={i} cells={[d.tagName, hex(d.value), d.text ?? ""]} onClick={() => db.space.isMapped(d.value) && wb.navigate(d.value, { tab: "hex" })} />)}</>)}
        {tab === "relocs" && (<><ElfHead cols={["Offset", "Type", "Symbol", "Addend", "Table"]} /><VirtualList count={e.relocations.length} rowHeight={22} className="h-[calc(100%-24px)]" render={(i) => { const r = e.relocations[i]; return <ElfRow cells={[hex(r.offset), r.typeName, r.symName, hex(r.addend), r.section]} onClick={() => wb.navigate(r.offset, { tab: "hex" })} />; }} /></>)}
        {tab === "symbols" && (<><ElfHead cols={["Value", "Size", "Kind", "Bind", "Table", "Name", "Version"]} /><VirtualList count={e.symbols.length} rowHeight={22} className="h-[calc(100%-24px)]" render={(i) => { const s = e.symbols[i]; return <ElfRow cells={[hex(s.value), String(s.size), s.kind, s.binding, s.table, s.name, s.version ?? ""]} onClick={() => s.value && wb.navigate(s.value)} />; }} /></>)}
        {tab === "hash" && (
          <div className="p-4 font-mono text-[12px] text-zinc-300">
            <div>GNU hash: {e.hasGnuHash ? `yes (buckets ${e.gnuHashInfo?.nbuckets}, symoffset ${e.gnuHashInfo?.symoffset}, bloom ${e.gnuHashInfo?.bloomSize} words, shift ${e.gnuHashInfo?.bloomShift})` : "no"}</div>
            <div>SysV hash: {e.hasSysvHash ? `yes (buckets ${e.sysvHashInfo?.nbuckets}, chains ${e.sysvHashInfo?.nchains})` : "no"}</div>
            <div className="mt-2">TLS: {e.tls ? `vaddr ${hex(e.tls.vaddr)}, filesz ${hex(e.tls.filesz)}, memsz ${hex(e.tls.memsz)}, align ${e.tls.align}` : "none"}</div>
            <div className="mt-2">Symbol versions: {e.symbols.filter((s) => s.version).length} versioned dynamic symbols</div>
            <div className="mt-2">Weak symbols: {e.symbols.filter((s) => s.binding === "weak").length}</div>
          </div>
        )}
      </div>
    </div>
  );
}

/** Interactive neighbourhood call graph (progressive: bounded per layer). */
export function CallGraphView() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [depth, setDepth] = useState(1);
  const [filter, setFilter] = useState("");
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [drag, setDrag] = useState<{ x: number; y: number; ox: number; oy: number } | null>(null);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const MAX = 24;
  const graph = useMemo(() => {
    const cur = wb.currentAddr !== null ? db.functionAt(wb.currentAddr) : null;
    if (!cur) return null;
    const layers: { addr: number; name: string; count: number }[][] = [];
    const expand = (seed: number[], dir: "callers" | "callees", d: number) => {
      const out: { addr: number; name: string; count: number }[][] = [];
      let frontier = seed;
      const seen = new Set<number>([cur.addr]);
      for (let i = 0; i < d; i++) {
        const next = new Map<number, number>();
        for (const a of frontier) {
          if (collapsed.has(a) && a !== cur.addr) continue;
          const f = db.functionByAddr(a);
          if (!f) continue;
          const rel = dir === "callers" ? db.callersOf(f).map((c) => c.fn?.addr).filter((x): x is number => x !== undefined) : db.calleesOf(f).map((c) => c.to);
          for (const r of rel) { if (!seen.has(r)) next.set(r, (next.get(r) ?? 0) + 1); }
        }
        const arr = [...next.entries()].map(([addr, count]) => ({ addr, name: db.nameFor(addr).name, count })).filter((n) => !filter || n.name.toLowerCase().includes(filter.toLowerCase()));
        arr.sort((a, b) => b.count - a.count);
        out.push(arr.slice(0, MAX));
        for (const n of arr) seen.add(n.addr);
        frontier = arr.slice(0, MAX).map((n) => n.addr);
        if (!frontier.length) break;
      }
      return out;
    };
    const callers = expand([cur.addr], "callers", depth).reverse();
    const callees = expand([cur.addr], "callees", depth);
    layers.push(...callers, [{ addr: cur.addr, name: db.nameFor(cur.addr).name, count: 0 }], ...callees);
    const edges: { a: number; b: number }[] = [];
    const pos = new Map<number, { x: number; y: number }>();
    const LX = 260, LY = 34;
    layers.forEach((layer, li) => layer.forEach((n, ni) => pos.set(n.addr, { x: li * LX + 20, y: ni * LY + 20 - (layer.length * LY) / 2 + 200 })));
    for (const layer of layers) for (const n of layer) {
      const f = db.functionByAddr(n.addr);
      if (!f) continue;
      for (const c of db.calleesOf(f)) if (pos.has(c.to) && !edges.some((e) => e.a === n.addr && e.b === c.to)) edges.push({ a: n.addr, b: c.to });
    }
    return { cur, layers, edges, pos };
  }, [db, wb.currentAddr, depth, filter, collapsed, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!graph) return <div className="p-6 text-sm text-zinc-500">Select a function to view its call graph.</div>;
  const centerIdx = graph.layers.findIndex((l) => l.length === 1 && l[0].addr === graph.cur.addr);
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-zinc-800 px-3 text-[11px] text-zinc-400">
        <span className="font-mono text-zinc-200">{db.nameFor(graph.cur.addr).name}</span>
        <span>depth</span>{[1, 2, 3].map((d) => <button key={d} onClick={() => setDepth(d)} className={`rounded px-2 ${depth === d ? "bg-zinc-700 text-white" : "hover:bg-zinc-800"}`}>{d}</button>)}
        <Input placeholder="filter nodes" value={filter} onChange={(e) => setFilter(e.target.value)} className="w-40" />
        <Button onClick={() => setView({ x: 0, y: 0, k: 1 })}>Reset view</Button>
        <span className="ml-auto">{graph.layers.reduce((a, l) => a + l.length, 0)} nodes · {graph.edges.length} edges · wheel = zoom · drag = pan · click = navigate · alt-click = collapse</span>
      </div>
      <svg className="flex-1 cursor-grab bg-[radial-gradient(#1f2937_1px,transparent_1px)] [background-size:20px_20px]" onWheel={(e) => { const k = Math.max(0.2, Math.min(3, view.k * (e.deltaY < 0 ? 1.1 : 0.9))); setView({ ...view, k }); }} onMouseDown={(e) => setDrag({ x: e.clientX, y: e.clientY, ox: view.x, oy: view.y })} onMouseMove={(e) => drag && setView({ ...view, x: drag.ox + (e.clientX - drag.x), y: drag.oy + (e.clientY - drag.y) })} onMouseUp={() => setDrag(null)} onMouseLeave={() => setDrag(null)}>
        <g transform={`translate(${view.x + 40},${view.y + 40}) scale(${view.k})`}>
          {graph.edges.map((e, i) => { const a = graph.pos.get(e.a)!, b = graph.pos.get(e.b)!; const x1 = a.x + 200, y1 = a.y + 12, x2 = b.x, y2 = b.y + 12; const isCur = e.a === graph.cur.addr || e.b === graph.cur.addr; return <path key={i} d={`M${x1},${y1} C${x1 + 60},${y1} ${x2 - 60},${y2} ${x2},${y2}`} fill="none" stroke={isCur ? (e.a === graph.cur.addr ? "#38bdf8" : "#f59e0b") : "#3f3f46"} strokeWidth={isCur ? 1.6 : 1} markerEnd="url(#arrow)" />; })}
          <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#71717a" /></marker></defs>
          {graph.layers.map((layer, li) => layer.map((n) => { const p = graph.pos.get(n.addr)!; const isCur = n.addr === graph.cur.addr; const f = db.functionByAddr(n.addr); const cls = f?.classes?.[0]; return (
            <g key={`${li}:${n.addr}`} transform={`translate(${p.x},${p.y})`} className="cursor-pointer" onClick={(e) => { e.stopPropagation(); if (e.altKey) { const s = new Set(collapsed); if (s.has(n.addr)) s.delete(n.addr); else s.add(n.addr); setCollapsed(s); } else wb.navigate(n.addr, { tab: "graph" }); }}>
              <rect width={200} height={24} rx={5} fill={isCur ? "#0c4a6e" : li < centerIdx ? "#1c1917" : "#111827"} stroke={isCur ? "#38bdf8" : collapsed.has(n.addr) ? "#a78bfa" : "#3f3f46"} />
              <text x={8} y={16} fontSize={11} fontFamily="ui-monospace, monospace" fill="#e4e4e7">{n.name.length > 24 ? n.name.slice(0, 23) + "…" : n.name}</text>
              {cls && <circle cx={190} cy={12} r={4} fill={cls.confidence > 0.7 ? "#22c55e" : cls.confidence > 0.5 ? "#38bdf8" : "#f59e0b"}><title>{cls.level} {cls.label}</title></circle>}
            </g>
          ); }))}
        </g>
      </svg>
    </div>
  );
}

/** Global search results with category filters. */
export function SearchView() {
  const wb = useWorkbench();
  const db = wb.db!;
  const [q, setQ] = useState(wb.searchQuery);
  const [cats, setCats] = useState<Set<SearchCategory>>(new Set());
  const [deep, setDeep] = useState(false);
  const query = wb.searchQuery;
  const results = useMemo(() => (query ? search(db, query, { limitPerCategory: 200, instructions: deep }) : []), [db, query, deep, wb.tick]); // eslint-disable-line react-hooks/exhaustive-deps
  const counts = categoryCounts(results);
  const shown = cats.size ? results.filter((r) => cats.has(r.category)) : results;
  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-zinc-800 px-3 py-2">
        <Input autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && wb.setSearchQuery(q)} placeholder="name, string, 0xaddr, bytes 'F? 03 ?? AA', re:regex, tag:, class:, mn:, imm:, xref:" className="w-[520px] font-mono" />
        <Button tone="sky" onClick={() => wb.setSearchQuery(q)}>Search</Button>
        <label className="flex items-center gap-1 text-[11px] text-zinc-400"><input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} /> instructions (slower)</label>
        <span className="ml-auto text-[11px] text-zinc-500">{results.length} results</span>
      </div>
      <div className="flex shrink-0 flex-wrap gap-1 border-b border-zinc-800 px-3 py-1.5">
        {(Object.keys(counts) as SearchCategory[]).map((c) => <Badge key={c} tone={cats.has(c) ? "sky" : "zinc"} onClick={() => { const s = new Set(cats); if (s.has(c)) s.delete(c); else s.add(c); setCats(s); }}>{c} — {counts[c]}</Badge>)}
      </div>
      <VirtualList className="flex-1" count={shown.length} rowHeight={26} render={(i) => { const r = shown[i]; return (
        <button onClick={() => wb.navigate(r.address, { tab: r.category === "bytes" || r.category === "globals" ? "hex" : "disasm" })} className="flex h-[26px] w-full items-center gap-3 px-3 text-left text-[12px] hover:bg-zinc-800/60">
          <span className="w-24 shrink-0 text-[10px] uppercase tracking-wider text-zinc-500">{r.category}</span>
          <span className="w-24 shrink-0 font-mono text-zinc-500">{hex(r.address)}</span>
          <span className="truncate font-mono text-zinc-100">{r.title}</span>
          <span className="ml-auto truncate text-zinc-500">{r.subtitle}</span>
        </button>
      ); }} />
    </div>
  );
}

const CompareSection = ({ title, items }: { title: string; items: React.ReactNode[] }) => <div className="rounded border border-zinc-800 bg-zinc-900/40 p-3"><div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">{title} ({items.length})</div><div className="max-h-64 overflow-auto font-mono text-[12px]">{items.length ? items : <span className="text-zinc-600">none</span>}</div></div>;

/** Binary comparison by function similarity. */
export function CompareView() {
  const wb = useWorkbench();
  const a = wb.db!;
  const b = wb.compareBinary?.db ?? null;
  const [minSim] = useState(0.7);
  const result = useMemo(() => {
    if (!b) return null;
    // Feature vectors are cached locally rather than written back onto the (shared) function records during render.
    const featA = new Map<number, FunctionFeatures>(), featB = new Map<number, FunctionFeatures>();
    const featOf = (db: AnalysisDatabase, f: FunctionRecord, cache: Map<number, FunctionFeatures>) => {
      let x = f.features ?? cache.get(f.addr);
      if (!x) { x = extractFeatures(db, f); cache.set(f.addr, x); }
      return x;
    };
    const byName = new Map<string, FunctionRecord>();
    for (const f of b.functions) if (f.nameSource === "symbol") byName.set(f.name, f);
    const matched: { a: number; b: number; score: number; changed: boolean }[] = [];
    const removed: number[] = [];
    const usedB = new Set<number>();
    let budget = 4000;
    for (const fa of a.functions) {
      if (fa.isImportStub) continue;
      let best: { f: FunctionRecord; s: number } | null = null;
      const byN = fa.nameSource === "symbol" ? byName.get(fa.name) : undefined;
      if (byN) best = { f: byN, s: 1 };
      else if (budget-- > 0) {
        const ffa = featOf(a, fa, featA);
        for (const fb of b.functions) {
          if (usedB.has(fb.addr) || fb.isImportStub || fb.size < fa.size * 0.5 || fb.size > fa.size * 2) continue;
          const s = similarity(ffa, featOf(b, fb, featB), fa.size, fb.size);
          if (s >= minSim && (!best || s > best.s)) best = { f: fb, s };
        }
      }
      if (best) {
        usedB.add(best.f.addr);
        const changed = best.s < 0.999 || fa.size !== best.f.size || featOf(a, fa, featA).fingerprint !== featOf(b, best.f, featB).fingerprint;
        matched.push({ a: fa.addr, b: best.f.addr, score: best.s, changed });
      } else removed.push(fa.addr);
    }
    const added = b.functions.filter((f) => !usedB.has(f.addr) && !f.isImportStub).map((f) => f.addr);
    const sa = new Set(a.strings.map((s) => s.value)), sb = new Set(b.strings.map((s) => s.value));
    const ia = new Set(a.elf.imports.map((s) => s.name)), ib = new Set(b.elf.imports.map((s) => s.name));
    const ea = new Set(a.elf.exports.map((s) => s.name)), eb = new Set(b.elf.exports.map((s) => s.name));
    const diff = <T,>(x: Set<T>, y: Set<T>) => [...x].filter((v) => !y.has(v));
    return { matched, removed, added, strAdded: diff(sb, sa), strRemoved: diff(sa, sb), impAdded: diff(ib, ia), impRemoved: diff(ia, ib), expAdded: diff(eb, ea), expRemoved: diff(ea, eb) };
  }, [a, b, minSim]);
  if (!b || !result) return (
    <div className="p-6 text-sm text-zinc-400">
      <p>Compare this binary against another version. Matching uses symbol names when available and function similarity (instruction mix, constants, strings, callees, size) otherwise.</p>
      <label className="mt-4 inline-block cursor-pointer rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-zinc-100 hover:bg-zinc-700">Choose binary B…<input type="file" className="hidden" onChange={(e) => e.target.files?.[0] && wb.openCompare(e.target.files[0])} /></label>
    </div>
  );
  const changed = result.matched.filter((m) => m.changed);
  return (
    <div className="h-full overflow-auto p-4">
      <div className="mb-3 text-[12px] text-zinc-400">A: <span className="text-zinc-200">{a.fileName}</span> ({a.functions.length} fns) vs B: <span className="text-zinc-200">{wb.compareBinary!.name}</span> ({b.functions.length} fns) · matched {result.matched.length} · changed {changed.length} · removed {result.removed.length} · added {result.added.length}</div>
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-3">
        <CompareSection title="Changed functions" items={changed.slice(0, 500).map((m) => <div key={m.a} className="flex gap-2"><button className="text-sky-300 hover:underline" onClick={() => wb.navigate(m.a)}>{a.nameFor(m.a).name}</button><span className="text-zinc-500">→ {b.nameFor(m.b).name}</span><Badge tone={confidenceTone(m.score)}>{Math.round(m.score * 100)}%</Badge></div>)} />
        <CompareSection title="Removed (only in A)" items={result.removed.slice(0, 500).map((x) => <button key={x} className="block text-rose-300 hover:underline" onClick={() => wb.navigate(x)}>{a.nameFor(x).name}</button>)} />
        <CompareSection title="Added (only in B)" items={result.added.slice(0, 500).map((x) => <div key={x} className="text-emerald-300">{b.nameFor(x).name} <span className="text-zinc-600">{hex(x)}</span></div>)} />
        <CompareSection title="Strings added" items={result.strAdded.slice(0, 300).map((s) => <div key={s} className="truncate text-emerald-300">{s}</div>)} />
        <CompareSection title="Strings removed" items={result.strRemoved.slice(0, 300).map((s) => <div key={s} className="truncate text-rose-300">{s}</div>)} />
        <CompareSection title="Imports / exports changed" items={[...result.impAdded.map((s) => <div key={"ia" + s} className="text-emerald-300">+ import {s}</div>), ...result.impRemoved.map((s) => <div key={"ir" + s} className="text-rose-300">− import {s}</div>), ...result.expAdded.map((s) => <div key={"ea" + s} className="text-emerald-300">+ export {s}</div>), ...result.expRemoved.map((s) => <div key={"er" + s} className="text-rose-300">− export {s}</div>)]} />
      </div>
    </div>
  );
}

/** Multi-library workspace: load several .so files and see how they connect. */
export function LinksView() {
  const wb = useWorkbench();
  const fileRef = React.useRef<HTMLInputElement>(null);
  const link = wb.link;
  const libs = wb.libs;
  const focused = wb.db;
  const edgeTone = (via: string): "sky" | "violet" | "amber" => (via === "symbol" ? "sky" : via === "needed" ? "violet" : "amber");
  return (
    <div className="h-full overflow-auto p-4 text-[12px]">
      <input ref={fileRef} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) void wb.addLibrary(f); e.target.value = ""; }} />
      <div className="mb-3 flex items-center gap-2">
        <span className="text-sm font-semibold text-zinc-100">Workspace — {libs.length} librar{libs.length === 1 ? "y" : "ies"}</span>
        {wb.workspaceBusy && <span className="flex items-center gap-1 text-[11px] text-sky-300"><span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />analyzing…</span>}
        <Button tone="sky" className="ml-auto" onClick={() => fileRef.current?.click()}>Add library…</Button>
      </div>
      <div className="mb-3 text-[11px] text-zinc-500">Load the game library, then add the ones it leans on (libanogs, libtersafe, libUE4…). Every lib is fully analyzed; the graph below shows which library resolves whose symbols, who dynamically loads whom, and which detections they share. In the bypass plan, steps whose real logic lives in a sibling get flagged.</div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-3">
        {libs.map((l) => {
          const isFocused = l.db === focused;
          return (
            <div key={l.hash} className={`rounded-lg border p-2 ${isFocused ? "border-sky-600 bg-sky-950/20" : "border-zinc-800 bg-zinc-900/40"}`}>
              <div className="flex items-center gap-2"><span className="truncate font-mono text-zinc-100">{l.db.elf.soname ?? l.name}</span>{isFocused && <Badge tone="sky">focused</Badge>}</div>
              <div className="mt-1 text-[11px] text-zinc-500">{l.db.arch?.displayName ?? l.db.elf.header.machineName} · {l.db.functions.length.toLocaleString()} fns · {l.db.elf.exports.length} exp · {l.db.elf.imports.length} imp</div>
              {!isFocused && <Button className="mt-1" onClick={() => { const i = libs.indexOf(l); if (i >= 0) wb.focusLibrary(i); }}>Focus</Button>}
            </div>
          );
        })}
      </div>

      {libs.length <= 1 && <div className="mt-4 rounded border border-zinc-800 bg-zinc-950/40 p-3 text-zinc-500">One library loaded. Add another to build the cross-library graph — e.g. load <span className="text-zinc-300">libUE4.so</span> then add <span className="text-zinc-300">libanogs.so</span> to see UE4 resolve the anticheat SDK&apos;s symbols.</div>}

      {link && (<>
        <div className="mt-4 mb-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Connections ({link.edges.length})</div>
        {!link.edges.length && <div className="text-zinc-500">No direct links found — these libraries don&apos;t import each other&apos;s symbols, name each other for dlopen, or DT_NEED each other. They may still cooperate through Java or a shared server.</div>}
        <div className="space-y-1">
          {link.edges.map((e, i) => (
            <div key={i} className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/30 px-2 py-1">
              <span className="font-mono text-zinc-200">{e.from}</span><span className="text-zinc-600">→</span><span className="font-mono text-zinc-200">{e.to}</span>
              <Badge tone={edgeTone(e.via)}>{e.via}</Badge>
              {e.via === "symbol" && <span className="text-zinc-500">{e.count} symbol{e.count === 1 ? "" : "s"}: {e.symbols.slice(0, 8).join(", ")}{e.count > e.symbols.length ? " …" : ""}</span>}
              {e.via === "dlopen" && <span className="text-zinc-500">{e.count === 2 ? "names it as a string and imports dlopen/dlsym" : "names it as a string"}</span>}
              {e.via === "needed" && <span className="text-zinc-500">DT_NEEDED</span>}
            </div>
          ))}
        </div>

        {!!link.sharedDetections.length && (<>
          <div className="mt-4 mb-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">Shared detections ({link.sharedDetections.length}) — the same check strings in several libs</div>
          <div className="flex flex-wrap gap-1">{link.sharedDetections.slice(0, 30).map((s, i) => <span key={i} className="rounded border border-rose-900/50 bg-rose-950/20 px-1.5 py-0.5 font-mono text-[11px] text-rose-200" title={s.libs.join(", ")}>&quot;{s.value.slice(0, 40)}&quot; <span className="text-zinc-500">×{s.libs.length}</span></span>)}</div>
        </>)}

        {!!link.unresolved.length && (
          <div className="mt-4 text-[11px] text-zinc-500">
            <span className="font-semibold uppercase tracking-wider">External imports</span> (resolved by system libs not loaded here): {link.unresolved.map((u) => `${u.lib} needs ${u.count} (${u.sample.slice(0, 3).join(", ")}…)`).join(" · ")}
          </div>
        )}
      </>)}
    </div>
  );
}
