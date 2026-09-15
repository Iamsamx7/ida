import type { AnalysisDatabase, Bookmark, UserName } from "./database";

export interface AnnotationBackup {
  format: "soforge-annotations";
  version: 1;
  sha256: string;
  fileName: string;
  names: UserName[];
  comments: { address: number; body: string; scope: "line" | "function" }[];
  bookmarks: Bookmark[];
  tags: { address: number; tag: string }[];
}

export function exportAnnotations(db: AnalysisDatabase): AnnotationBackup {
  if (!/^[a-f0-9]{64}$/.test(db.hash)) throw new Error("Binary identity is not ready yet.");
  return {
    format: "soforge-annotations", version: 1, sha256: db.hash, fileName: db.fileName,
    names: [...db.userNames.values()],
    comments: [...[...db.comments].map(([address, body]) => ({ address, body, scope: "line" as const })),
      ...[...db.functionComments].map(([address, body]) => ({ address, body, scope: "function" as const }))],
    bookmarks: [...db.bookmarks.values()],
    tags: [...db.tags].flatMap(([address, tags]) => [...tags].map((tag) => ({ address, tag }))),
  };
}

/** Validate the entire backup before any mutation; bind imports to the exact binary. */
export function parseAnnotations(text: string, hash: string): AnnotationBackup {
  if (text.length > 10_000_000) throw new Error("Annotation backup exceeds 10 MB.");
  const value: unknown = JSON.parse(text);
  const obj = (v: unknown): Record<string, unknown> => {
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("Invalid annotation record.");
    return v as Record<string, unknown>;
  };
  const data = obj(value);
  if (data.format !== "soforge-annotations" || data.version !== 1) throw new Error("Unsupported annotation backup format or version.");
  if (!/^[a-f0-9]{64}$/.test(hash) || data.sha256 !== hash) throw new Error("This backup belongs to a different binary. Open the matching file first.");
  const str = (v: unknown, limit: number, empty = false): string => {
    if (typeof v !== "string" || v.length > limit || (!empty && !v.trim())) throw new Error("Invalid or oversized annotation text.");
    return v;
  };
  const addr = (v: unknown): number => {
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new Error("Invalid annotation address.");
    return v;
  };
  const rows = (key: string) => {
    const list = data[key];
    if (!Array.isArray(list) || list.length > 100_000) throw new Error(`Invalid ${key} list.`);
    return list.map(obj);
  };
  return {
    format: "soforge-annotations", version: 1, sha256: hash, fileName: str(data.fileName, 4096),
    names: rows("names").map((r) => {
      if (r.origin !== "user" && r.origin !== "ai-accepted") throw new Error("Invalid name origin.");
      return { address: addr(r.address), name: str(r.name, 512), origin: r.origin };
    }),
    comments: rows("comments").map((r) => {
      if (r.scope !== "line" && r.scope !== "function") throw new Error("Invalid comment scope.");
      return { address: addr(r.address), body: str(r.body, 8192), scope: r.scope };
    }),
    bookmarks: rows("bookmarks").map((r) => {
      if (r.kind !== "address" && r.kind !== "function" && r.kind !== "string" && r.kind !== "data") throw new Error("Invalid bookmark kind.");
      return { address: addr(r.address), kind: r.kind, label: str(r.label, 256, true), note: str(r.note, 4096, true) };
    }),
    tags: rows("tags").map((r) => ({ address: addr(r.address), tag: str(r.tag, 64) })),
  };
}

/** Merge without replacing current work. Return only newly applied records for persistence. */
export function mergeAnnotations(db: AnalysisDatabase, backup: AnnotationBackup): AnnotationBackup {
  // Revalidate even when called outside the import dialog.
  const valid = parseAnnotations(JSON.stringify(backup), db.hash);
  const added: AnnotationBackup = { ...valid, names: [], comments: [], bookmarks: [], tags: [] };
  for (const n of valid.names) if (!db.userNames.has(n.address)) { db.setUserName(n.address, n.name, n.origin); added.names.push(n); }
  for (const c of valid.comments) {
    const map = c.scope === "function" ? db.functionComments : db.comments;
    if (!map.has(c.address)) { map.set(c.address, c.body); added.comments.push(c); }
  }
  for (const b of valid.bookmarks) if (!db.bookmarks.has(b.address)) { db.bookmarks.set(b.address, { ...b }); added.bookmarks.push(b); }
  for (const t of valid.tags) {
    const tags = db.tags.get(t.address) ?? new Set<string>();
    if (!tags.has(t.tag)) { tags.add(t.tag); db.tags.set(t.address, tags); added.tags.push(t); }
  }
  db.revision++;
  return added;
}
