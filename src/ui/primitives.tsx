"use client";
import React, { useEffect, useLayoutEffect, useRef, useState } from "react";

/** Fixed-row-height virtual list. Handles millions of rows without DOM bloat. */
export function VirtualList<T>({ count, rowHeight, render, scrollTo, className, overscan = 8, getKey }: {
  count: number;
  rowHeight: number;
  render: (index: number) => React.ReactNode;
  scrollTo?: { index: number; nonce: number } | null;
  className?: string;
  overscan?: number;
  getKey?: (index: number) => string | number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [range, setRange] = useState({ start: 0, end: Math.min(50, count) });
  const compute = () => {
    const el = ref.current;
    if (!el) return;
    const start = Math.max(0, Math.floor(el.scrollTop / rowHeight) - overscan);
    const end = Math.min(count, Math.ceil((el.scrollTop + el.clientHeight) / rowHeight) + overscan);
    setRange((r) => (r.start === start && r.end === end ? r : { start, end }));
  };
  useLayoutEffect(compute, [count, rowHeight]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    // Re-subscribe whenever the inputs change: an observer created once would keep the first render's
    // `count` (often 0) and blank the list on the next resize.
    const ro = new ResizeObserver(compute);
    ro.observe(el);
    return () => ro.disconnect();
  }, [count, rowHeight, overscan]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!scrollTo || !ref.current) return;
    const el = ref.current;
    const top = scrollTo.index * rowHeight;
    if (top < el.scrollTop + rowHeight * 2 || top > el.scrollTop + el.clientHeight - rowHeight * 3) {
      el.scrollTop = Math.max(0, top - el.clientHeight / 3);
    }
    compute();
  }, [scrollTo?.nonce]); // eslint-disable-line react-hooks/exhaustive-deps
  // The visible range is recomputed in a layout effect, so it can lag behind `count` for one render
  // (first mount, or the list shrinking): never ask for rows that no longer exist.
  const end = Math.min(range.end, count);
  const rows: React.ReactNode[] = [];
  for (let i = Math.min(range.start, end); i < end; i++) rows.push(<div key={getKey ? getKey(i) : i} style={{ position: "absolute", top: i * rowHeight, height: rowHeight, left: 0, right: 0 }}>{render(i)}</div>);
  return (
    <div ref={ref} onScroll={compute} className={`relative overflow-auto ${className ?? ""}`}>
      <div style={{ height: count * rowHeight, position: "relative" }}>{rows}</div>
    </div>
  );
}

export interface MenuItem {
  label: string;
  shortcut?: string;
  onClick?: () => void;
  disabled?: boolean;
  separator?: boolean;
}

export function ContextMenu({ menu, onClose }: { menu: { x: number; y: number; items: MenuItem[] } | null; onClose: () => void }) {
  useEffect(() => {
    if (!menu) return;
    const h = () => onClose();
    window.addEventListener("click", h);
    window.addEventListener("contextmenu", h);
    window.addEventListener("keydown", h);
    return () => { window.removeEventListener("click", h); window.removeEventListener("contextmenu", h); window.removeEventListener("keydown", h); };
  }, [menu, onClose]);
  if (!menu) return null;
  const x = Math.min(menu.x, window.innerWidth - 260), y = Math.min(menu.y, window.innerHeight - menu.items.length * 28 - 16);
  return (
    <div className="fixed z-[1000] min-w-[240px] rounded-md border border-zinc-700 bg-zinc-900/95 py-1 text-[12px] shadow-2xl backdrop-blur" style={{ left: x, top: y }} onClick={(e) => e.stopPropagation()}>
      {menu.items.map((it, i) =>
        it.separator ? <div key={i} className="my-1 border-t border-zinc-800" /> : (
          <button key={i} disabled={it.disabled} onClick={() => { it.onClick?.(); onClose(); }} className="flex w-full items-center justify-between px-3 py-1 text-left text-zinc-200 hover:bg-sky-600/30 disabled:opacity-40">
            <span>{it.label}</span>{it.shortcut && <span className="ml-6 text-[10px] text-zinc-500">{it.shortcut}</span>}
          </button>
        ),
      )}
    </div>
  );
}

export function useContextMenu() {
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null);
  const open = (e: React.MouseEvent, items: MenuItem[]) => { e.preventDefault(); e.stopPropagation(); setMenu({ x: e.clientX, y: e.clientY, items }); };
  return { menu, open, close: () => setMenu(null) };
}

export function Badge({ children, tone = "zinc", title, onClick }: { children: React.ReactNode; tone?: "zinc" | "sky" | "emerald" | "amber" | "rose" | "violet" | "cyan"; title?: string; onClick?: () => void }) {
  const tones: Record<string, string> = {
    zinc: "bg-zinc-800 text-zinc-300 border-zinc-700", sky: "bg-sky-900/40 text-sky-300 border-sky-800", emerald: "bg-emerald-900/40 text-emerald-300 border-emerald-800",
    amber: "bg-amber-900/40 text-amber-300 border-amber-800", rose: "bg-rose-900/40 text-rose-300 border-rose-800", violet: "bg-violet-900/40 text-violet-300 border-violet-800", cyan: "bg-cyan-900/40 text-cyan-300 border-cyan-800",
  };
  return <span title={title} onClick={onClick} className={`inline-flex items-center rounded border px-1.5 py-[1px] text-[10px] font-medium uppercase tracking-wide ${tones[tone]} ${onClick ? "cursor-pointer hover:brightness-125" : ""}`}>{children}</span>;
}

export function Progress({ value, className }: { value: number; className?: string }) {
  return <div className={`h-1.5 w-full overflow-hidden rounded bg-zinc-800 ${className ?? ""}`}><div className="h-full bg-sky-500 transition-all" style={{ width: `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%` }} /></div>;
}

export function PanelHeader({ title, right }: { title: React.ReactNode; right?: React.ReactNode }) {
  return <div className="flex h-8 shrink-0 items-center justify-between border-b border-zinc-800 px-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-400"><span>{title}</span><span className="flex items-center gap-2 normal-case tracking-normal">{right}</span></div>;
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`h-7 rounded border border-zinc-700 bg-zinc-900 px-2 text-[12px] text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-sky-600 ${props.className ?? ""}`} />;
}

export function Button({ children, tone = "zinc", ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { tone?: "zinc" | "sky" | "emerald" | "rose" }) {
  const t: Record<string, string> = { zinc: "border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200", sky: "border-sky-700 bg-sky-700/70 hover:bg-sky-600 text-white", emerald: "border-emerald-700 bg-emerald-700/70 hover:bg-emerald-600 text-white", rose: "border-rose-800 bg-rose-800/60 hover:bg-rose-700 text-white" };
  return <button {...rest} className={`h-7 rounded border px-2.5 text-[12px] font-medium disabled:opacity-40 ${t[tone]} ${rest.className ?? ""}`}>{children}</button>;
}

export function Modal({ open, onClose, children, width = 640 }: { open: boolean; onClose: () => void; children: React.ReactNode; width?: number }) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); onClose(); } };
    window.addEventListener("keydown", h, true);
    return () => window.removeEventListener("keydown", h, true);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[900] flex items-start justify-center bg-black/50 pt-[12vh]" onMouseDown={onClose}>
      <div className="max-h-[70vh] overflow-hidden rounded-lg border border-zinc-700 bg-zinc-950 shadow-2xl" style={{ width }} onMouseDown={(e) => e.stopPropagation()}>{children}</div>
    </div>
  );
}

export function confidenceTone(c: number): "emerald" | "sky" | "amber" | "rose" {
  return c >= 0.8 ? "emerald" : c >= 0.55 ? "sky" : c >= 0.35 ? "amber" : "rose";
}
