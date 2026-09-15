"use client";
import React, { useState } from "react";
import { useWorkbench } from "./store";
import { Button, Modal } from "./primitives";
import { exportAnnotations, parseAnnotations, type AnnotationBackup } from "@/core/analysis/annotations";
import { downloadText } from "./download";

export function AnnotationDialog({ onClose }: { onClose: () => void }) {
  const wb = useWorkbench();
  const db = wb.db!;
  const [backup, setBackup] = useState<AnnotationBackup | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const read = async (file: File) => {
    setError(""); setMessage(""); setBackup(null);
    try {
      if (file.size > 10_000_000) throw new Error("Annotation backup exceeds 10 MB.");
      setBackup(parseAnnotations(await file.text(), db.hash));
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return <Modal open onClose={busy ? () => {} : onClose} width={560}>
    <div className="space-y-4 p-5 text-[12px]">
      <h2 className="text-base font-semibold text-zinc-100">Annotation backups</h2>
      <p className="text-zinc-400">Save your names, line and function comments, bookmarks and tags to a portable file. Restore them into this exact binary later, even without a project database.</p>
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3"><div className="mb-2 truncate font-mono text-sky-200">{db.fileName}</div><Button onClick={() => {
        try { downloadText(`${db.fileName}.annotations.json`, JSON.stringify(exportAnnotations(db), null, 2), "application/json"); setMessage("Backup exported."); setError(""); }
        catch (e) { setError(String(e)); }
      }}>Export annotation backup</Button></div>
      <label className="block text-zinc-300">Choose a backup to restore<input disabled={busy} type="file" accept=".json,application/json" className="mt-2 block w-full text-zinc-400 file:mr-3 file:rounded file:border-0 file:bg-zinc-800 file:px-3 file:py-2 file:text-zinc-200" onChange={(e) => { const f = e.target.files?.[0]; if (f) void read(f); e.target.value = ""; }} /></label>
      {backup && <div className="rounded-lg border border-sky-900 bg-sky-950/20 p-3"><div className="text-sky-200">Binary fingerprint matches</div><p className="mt-1 text-zinc-400">{backup.names.length} names · {backup.comments.length} comments · {backup.bookmarks.length} bookmarks · {backup.tags.length} tags</p><p className="mt-2 text-zinc-500">Merge adds missing annotations. Your current values win any conflicts.</p><Button disabled={busy} tone="sky" className="mt-3" onClick={async () => {
        setBusy(true); setError("");
        try { const result = await wb.importAnnotations(backup); setMessage(result); setBackup(null); }
        catch (e) { setError(String(e)); }
        finally { setBusy(false); }
      }}>{busy ? "Merging…" : "Merge annotations"}</Button></div>}
      {message && <p role="status" className="text-emerald-300">{message}</p>}
      {error && <p role="alert" className="text-rose-300">{error}</p>}
      <div className="flex justify-end"><Button disabled={busy} onClick={onClose}>Close</Button></div>
    </div>
  </Modal>;
}
